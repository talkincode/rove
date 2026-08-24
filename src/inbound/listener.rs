//! TCP accept loop with an optional TLS wrap, then protocol dispatch.

use super::{http, sni, socks5, Ctx};
use crate::access_log::AccessLogger;
use crate::config::{Listener, SniGatewayConfig};
use crate::diagnostics::DiagnosticRegistry;
use crate::engine::Engine;
use crate::io::IoStream;
use crate::outbound::EgressContext;
use crate::stats::TrafficStats;
use crate::trace::ProbeTracer;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

pub struct BoundListener {
    cfg: Listener,
    acceptor: Option<TlsAcceptor>,
    proto: String,
    sni: Option<SniGatewayConfig>,
    listener: TcpListener,
}

impl BoundListener {
    pub async fn bind(cfg: Listener, stats: Arc<TrafficStats>) -> anyhow::Result<Self> {
        cfg.validate()?;
        let proto = cfg.protocol.trim().to_ascii_lowercase();
        let sni = if proto == "sni" {
            Some(cfg.sni_gateway_config()?)
        } else {
            None
        };
        let acceptor = match &cfg.tls {
            Some(t) => Some(crate::tls::server_acceptor_with_sni(t)?),
            None => None,
        };
        if proto != "http" && proto != "socks5" && proto != "sni" {
            anyhow::bail!("listener {}: unknown protocol {:?}", cfg.name, cfg.protocol);
        }

        let listener = TcpListener::bind(&cfg.listen)
            .await
            .map_err(|e| anyhow::anyhow!("listener {} bind {}: {e}", cfg.name, cfg.listen))?;
        stats.register_listener(&cfg.name);
        info!(
            listener = %cfg.name,
            protocol = %proto,
            tls = acceptor.is_some(),
            addr = %cfg.listen,
            "listening"
        );
        Ok(BoundListener {
            cfg,
            acceptor,
            proto,
            sni,
            listener,
        })
    }

    pub fn name(&self) -> &str {
        &self.cfg.name
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run_until(
        self,
        engine: Arc<Engine>,
        tracer: Option<Arc<ProbeTracer>>,
        diagnostics: Option<Arc<DiagnosticRegistry>>,
        access_log: Option<Arc<AccessLogger>>,
        stats: Arc<TrafficStats>,
        egress: EgressContext,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let BoundListener {
            cfg,
            acceptor,
            proto,
            sni,
            listener,
        } = self;
        let ctx = Arc::new(Ctx {
            engine,
            listener: cfg.name.clone(),
            sniff: cfg.sniff.clone(),
            tracer,
            diagnostics,
            access_log,
            stats,
            egress,
        });

        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = crate::lifecycle::shutdown_requested(&mut shutdown) => {
                    info!(listener = %cfg.name, active = connections.len(), "listener stopped accepting new connections");
                    break;
                }
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(v) => v,
                        Err(e) => {
                            warn!(listener = %cfg.name, error = %e, "accept failed");
                            continue;
                        }
                    };
                    let acceptor = acceptor.clone();
                    let proto = proto.clone();
                    let sni = sni.clone();
                    let ctx = ctx.clone();
                    connections.spawn(async move {
                        if let Err(e) = serve_conn(stream, acceptor, &proto, sni, ctx, peer).await {
                            debug!(peer = %peer, error = %e, "connection ended");
                        }
                    });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(e) = result {
                        debug!(listener = %cfg.name, error = %e, "connection task ended unexpectedly");
                    }
                }
            }
        }

        drop(listener);
        while let Some(result) = connections.join_next().await {
            if let Err(e) = result {
                debug!(listener = %cfg.name, error = %e, "connection task ended unexpectedly");
            }
        }
        info!(listener = %cfg.name, "listener connections drained");
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    cfg: Listener,
    engine: Arc<Engine>,
    tracer: Option<Arc<ProbeTracer>>,
    diagnostics: Option<Arc<DiagnosticRegistry>>,
    access_log: Option<Arc<AccessLogger>>,
    stats: Arc<TrafficStats>,
    egress: EgressContext,
) -> anyhow::Result<()> {
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    run_until(
        cfg,
        engine,
        tracer,
        diagnostics,
        access_log,
        stats,
        egress,
        shutdown_rx,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_until(
    cfg: Listener,
    engine: Arc<Engine>,
    tracer: Option<Arc<ProbeTracer>>,
    diagnostics: Option<Arc<DiagnosticRegistry>>,
    access_log: Option<Arc<AccessLogger>>,
    stats: Arc<TrafficStats>,
    egress: EgressContext,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    BoundListener::bind(cfg, stats.clone())
        .await?
        .run_until(
            engine,
            tracer,
            diagnostics,
            access_log,
            stats,
            egress,
            shutdown,
        )
        .await
}

async fn serve_conn(
    stream: TcpStream,
    acceptor: Option<TlsAcceptor>,
    proto: &str,
    sni: Option<SniGatewayConfig>,
    ctx: Arc<Ctx>,
    peer: SocketAddr,
) -> anyhow::Result<()> {
    let _ = stream.set_nodelay(true);
    let ingress = crate::ingress::metadata::take_tcp(peer);
    let client_peer = ingress
        .as_ref()
        .map(|metadata| metadata.client_addr)
        .unwrap_or(peer);
    // Captured before any TLS wrap so SOCKS5 UDP ASSOCIATE can advertise a BND
    // address on the same interface the client reached.
    let local = stream.local_addr().ok();
    crate::ingress::metadata::scope(ingress, async move {
        match acceptor {
            Some(acc) => {
                let tls = acc.accept(stream).await?;
                dispatch(tls, proto, sni, ctx, client_peer, local).await
            }
            None => dispatch(stream, proto, sni, ctx, client_peer, local).await,
        }
    })
    .await
}

async fn dispatch<S>(
    stream: S,
    proto: &str,
    sni: Option<SniGatewayConfig>,
    ctx: Arc<Ctx>,
    peer: SocketAddr,
    local: Option<SocketAddr>,
) -> anyhow::Result<()>
where
    S: IoStream,
{
    match proto {
        "http" => http::serve(stream, ctx, peer).await,
        "socks5" => socks5::serve(stream, ctx, peer, local).await,
        "sni" => {
            sni::serve(
                stream,
                ctx,
                peer,
                sni.expect("sni listener must have normalized gateway configuration"),
                local,
            )
            .await
        }
        other => {
            error!(protocol = other, "no handler");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn run_rejects_unknown_protocol_before_binding() {
        let cfg = Listener {
            name: "bad".to_string(),
            protocol: "trojan".to_string(),
            listen: "127.0.0.1:0".to_string(),
            tls: None,
            sniff: crate::config::SniffConfig::default(),
            identity: None,
            origins: Vec::new(),
        };

        let err = run(
            cfg,
            Engine::new(),
            None,
            None,
            None,
            crate::stats::TrafficStats::new(),
            EgressContext::default(),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("unknown protocol"));
    }

    #[tokio::test]
    async fn run_reports_bind_errors_for_invalid_address() {
        let cfg = Listener {
            name: "bad-bind".to_string(),
            protocol: "http".to_string(),
            listen: "not-an-address".to_string(),
            tls: None,
            sniff: crate::config::SniffConfig::default(),
            identity: None,
            origins: Vec::new(),
        };

        let err = run(
            cfg,
            Engine::new(),
            None,
            None,
            None,
            crate::stats::TrafficStats::new(),
            EgressContext::default(),
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("failed to lookup address information")
                || err.to_string().contains("invalid socket address")
                || err.to_string().contains("nodename nor servname")
        );
    }

    #[tokio::test]
    async fn run_accepts_and_dispatches_http_over_plain_tcp() {
        let port = free_port();
        let cfg = Listener {
            name: "it-http".to_string(),
            protocol: "http".to_string(),
            listen: format!("127.0.0.1:{port}"),
            tls: None,
            sniff: crate::config::SniffConfig::default(),
            identity: None,
            origins: Vec::new(),
        };
        let task = tokio::spawn(run(
            cfg,
            Engine::new(),
            None,
            None,
            None,
            crate::stats::TrafficStats::new(),
            EgressContext::default(),
        ));

        let mut stream = connect_with_retry(port).await;
        stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.starts_with("HTTP/1.1 405"));

        task.abort();
    }

    #[tokio::test]
    async fn run_accepts_and_dispatches_socks5_over_plain_tcp() {
        let port = free_port();
        let cfg = Listener {
            name: "it-socks5".to_string(),
            protocol: "socks5".to_string(),
            listen: format!("127.0.0.1:{port}"),
            tls: None,
            sniff: crate::config::SniffConfig::default(),
            identity: None,
            origins: Vec::new(),
        };
        let task = tokio::spawn(run(
            cfg,
            Engine::new(),
            None,
            None,
            None,
            crate::stats::TrafficStats::new(),
            EgressContext::default(),
        ));

        let mut stream = connect_with_retry(port).await;
        // Offer only "no auth" (0x00); the real socks5::serve requires 0x02
        // and replies 0xFF, proving the real accept loop reached it.
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, [0x05, 0xFF]);

        task.abort();
    }

    #[tokio::test]
    async fn run_accepts_and_dispatches_http_over_real_tls() {
        crate::tls::init_crypto();
        let cert_path = temp_path("listener-it.crt");
        let key_path = temp_path("listener-it.key");
        std::fs::write(&cert_path, crate::tls::tests::TEST_CERT).unwrap();
        std::fs::write(&key_path, crate::tls::tests::TEST_KEY).unwrap();

        let port = free_port();
        let cfg = Listener {
            name: "it-https".to_string(),
            protocol: "http".to_string(),
            listen: format!("127.0.0.1:{port}"),
            tls: Some(crate::config::TlsFiles {
                cert: cert_path.clone(),
                key: key_path.clone(),
                certificates: Vec::new(),
            }),
            sniff: crate::config::SniffConfig::default(),
            identity: None,
            origins: Vec::new(),
        };
        let task = tokio::spawn(run(
            cfg,
            Engine::new(),
            None,
            None,
            None,
            crate::stats::TrafficStats::new(),
            EgressContext::default(),
        ));

        let tcp = connect_with_retry(port).await;
        let connector = insecure_test_tls_connector();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(server_name, tcp).await.unwrap();

        tls.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut buf = [0u8; 64];
        let n = tls.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.starts_with("HTTP/1.1 405"));

        task.abort();
        let _ = std::fs::remove_file(cert_path);
        let _ = std::fs::remove_file(key_path);
    }

    /// Reserve then immediately release a loopback port so `run()` can bind
    /// to a known, free port instead of the test hardcoding one.
    fn free_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    /// `run()` binds asynchronously in the background; retry the client
    /// connect briefly instead of racing it with a fixed sleep.
    async fn connect_with_retry(port: u16) -> TcpStream {
        let addr = format!("127.0.0.1:{port}");
        for _ in 0..100 {
            if let Ok(stream) = TcpStream::connect(&addr).await {
                return stream;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("failed to connect to {addr} after retries");
    }

    fn temp_path(name: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("rove-listener-{nanos}-{name}"))
            .to_string_lossy()
            .into_owned()
    }

    /// Test-only rustls verifier that accepts any server certificate, so the
    /// TLS accept-loop test exercises a real handshake without depending on
    /// the fixture cert's specific hostname/validity window.
    #[derive(Debug)]
    struct AcceptAnyServerCert;

    impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    fn insecure_test_tls_connector() -> tokio_rustls::TlsConnector {
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            .with_no_client_auth();
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }
}
