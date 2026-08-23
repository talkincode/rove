//! Reverse-hop data plane: a QUIC transport that lets a hop node which the edge
//! cannot dial (NAT / firewall / private routing) instead dial *out* to the
//! edge and serve egress over multiplexed bidirectional streams.
//!
//! Topology and roles:
//!
//! * The **hop** is the QUIC client. It opens one long-lived, authenticated
//!   connection to each configured edge (see [`hop`]) and keeps it alive.
//! * The **edge** is the QUIC server. It accepts hop connections, authenticates
//!   the `REGISTER` frame, and tracks `hop_id -> connection` in a
//!   [`edge::ReverseHopManager`].
//! * For each policy-matched user connection the edge opens a fresh QUIC
//!   bidirectional stream, sends a `CONNECT` frame, and — on `OK` — splices the
//!   inbound client with that stream. The hop dials the real target and splices
//!   the target socket with its end of the same stream.
//!
//! The design fails closed: if there is no authenticated session for the
//! requested `hop_id`, or the stream/handshake fails, the request errors and is
//! never silently downgraded to direct routing.
//!
//! Auth in v1 is a shared token carried in the `REGISTER` frame over QUIC's
//! mandatory TLS 1.3 encryption. The hop may additionally skip edge-certificate
//! verification for self-signed / IP-only edge certs — an explicit opt-in,
//! mirroring the existing `skip_cert_verify` upstream knob, never a default.

pub mod edge;
pub mod frame;
pub mod hop;
pub mod udp;

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub use edge::{ReverseHopManager, ReverseListenerConfig};
pub use frame::ALPN;

/// Default cap on concurrent tunnels the edge will open on a single hop
/// connection. Conservative for v1; the hop enforces its own global/per-edge
/// caps independently.
pub const DEFAULT_MAX_STREAMS_PER_HOP: u32 = 256;

/// Default time the edge waits for a hop to acknowledge a `CONNECT` before
/// giving up on that tunnel (fails closed with stage `reverse_open`).
pub const DEFAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// QUIC keep-alive interval; well under common NAT UDP timeouts so the hop's
/// outbound mapping stays open with no user traffic.
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Idle timeout after which a silent connection is considered dead. Must exceed
/// [`KEEP_ALIVE_INTERVAL`] so keep-alives actually prevent teardown.
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(45);

/// Application close code used when tearing down a reverse connection cleanly.
pub const CLOSE_OK: u32 = 0;

/// Adapts quinn's split [`quinn::SendStream`] / [`quinn::RecvStream`] halves
/// into one duplex stream so a QUIC tunnel plugs straight into the shared
/// [`crate::io::splice`] / [`crate::io::IoStream`] path used by every other
/// egress.
pub struct QuicDuplex {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicDuplex {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        QuicDuplex { send, recv }
    }
}

impl AsyncRead for QuicDuplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicDuplex {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Disambiguate from quinn's inherent `SendStream::poll_write`, which
        // returns a `quinn::WriteError` rather than `io::Error`.
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// QUIC datagram buffer sizes (bytes of queued datagram payload) applied to
/// both endpoints. Sized for sustained real-time media (WebRTC / game traffic)
/// carried as one UDP packet per QUIC datagram: generous enough to absorb
/// bursts without stalling, bounded so a stalled peer cannot grow memory
/// without limit. Datagrams are lossy by design — overflow drops the oldest,
/// which is the correct behaviour for real-time UDP.
pub const DATAGRAM_RECV_BUFFER: usize = 8 * 1024 * 1024;
pub const DATAGRAM_SEND_BUFFER: usize = 2 * 1024 * 1024;

/// Shared transport tuning (keep-alive, idle timeout, per-hop stream cap,
/// datagram buffers) applied to both endpoints so NAT survival, back-pressure,
/// and UDP-relay behaviour are identical on each side.
///
/// `initial_mtu` pins the QUIC path MTU (max UDP-payload bytes) for a fixed or
/// already-compressed outer tunnel: quinn starts at that size and PMTUD is
/// capped so it never probes higher and never emits a datagram the carrier
/// silently drops. `None` keeps quinn's default (start at 1200, discover upward).
fn transport_config(max_streams: u32, initial_mtu: Option<u16>) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    if let Ok(timeout) = quinn::IdleTimeout::try_from(MAX_IDLE_TIMEOUT) {
        transport.max_idle_timeout(Some(timeout));
    }
    transport.max_concurrent_bidi_streams(max_streams.into());
    // Enable the QUIC unreliable datagram extension for reverse/2 UDP relay.
    transport.datagram_receive_buffer_size(Some(DATAGRAM_RECV_BUFFER));
    transport.datagram_send_buffer_size(DATAGRAM_SEND_BUFFER);
    apply_initial_mtu(&mut transport, initial_mtu);
    transport
}

/// Pin the QUIC path MTU to `mtu` (max UDP-payload bytes) when set: fix the
/// starting size and cap PMTUD to the same value so quinn never probes above a
/// known-compressed carrier's ceiling. A no-op when `None`.
pub(crate) fn apply_initial_mtu(transport: &mut quinn::TransportConfig, mtu: Option<u16>) {
    if let Some(v) = mtu {
        transport.initial_mtu(v);
        let mut discovery = quinn::MtuDiscoveryConfig::default();
        discovery.upper_bound(v);
        transport.mtu_discovery_config(Some(discovery));
    }
}

/// Build the edge-side (QUIC server) config from a PEM cert/key pair, with the
/// reverse-hop ALPN and shared transport tuning.
pub fn server_config(
    cert_path: &str,
    key_path: &str,
    max_streams: u32,
    initial_mtu: Option<u16>,
) -> anyhow::Result<quinn::ServerConfig> {
    let certs = crate::tls::load_cert_chain(cert_path)?;
    let key = crate::tls::load_private_key(key_path)?;
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("reverse-hop server TLS config: {e}"))?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .map_err(|e| anyhow::anyhow!("reverse-hop QUIC server crypto: {e}"))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    server.transport_config(Arc::new(transport_config(max_streams, initial_mtu)));
    Ok(server)
}

/// Build the hop-side (QUIC client) config. When `skip_cert_verify` is set the
/// hop still encrypts but accepts any edge certificate (self-signed / IP-only
/// edge certs); otherwise it verifies against the shared webpki + env root set.
pub fn client_config(
    skip_cert_verify: bool,
    max_streams: u32,
    initial_mtu: Option<u16>,
) -> anyhow::Result<quinn::ClientConfig> {
    let mut crypto = if skip_cert_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::AcceptAnyServerCert))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(crate::tls::root_store())
            .with_no_client_auth()
    };
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| anyhow::anyhow!("reverse-hop QUIC client crypto: {e}"))?;
    let mut client = quinn::ClientConfig::new(Arc::new(quic_crypto));
    client.transport_config(Arc::new(transport_config(max_streams, initial_mtu)));
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn configs_build_with_test_cert() {
        crate::tls::init_crypto();
        let dir = std::env::temp_dir();
        let cert = dir.join(format!("rev-{}.crt", std::process::id()));
        let key = dir.join(format!("rev-{}.key", std::process::id()));
        std::fs::write(&cert, crate::tls::tests::TEST_CERT).unwrap();
        std::fs::write(&key, crate::tls::tests::TEST_KEY).unwrap();

        assert!(server_config(cert.to_str().unwrap(), key.to_str().unwrap(), 64, None).is_ok());
        assert!(client_config(true, 64, None).is_ok());
        assert!(client_config(false, 64, None).is_ok());
        // Pinned MTU path (compressed tunnel) also builds.
        assert!(server_config(
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            64,
            Some(1332)
        )
        .is_ok());
        assert!(client_config(true, 64, Some(1332)).is_ok());

        let _ = std::fs::remove_file(cert);
        let _ = std::fs::remove_file(key);
    }

    #[tokio::test]
    async fn quic_duplex_forwards_reads_and_writes() {
        // Exercise the AsyncRead/AsyncWrite projection over a real in-memory
        // QUIC connection built from the two config builders above.
        crate::tls::init_crypto();
        let dir = std::env::temp_dir();
        let cert = dir.join(format!("rev-dup-{}.crt", std::process::id()));
        let key = dir.join(format!("rev-dup-{}.key", std::process::id()));
        std::fs::write(&cert, crate::tls::tests::TEST_CERT).unwrap();
        std::fs::write(&key, crate::tls::tests::TEST_KEY).unwrap();

        let server_cfg =
            server_config(cert.to_str().unwrap(), key.to_str().unwrap(), 64, None).unwrap();
        let server_endpoint =
            quinn::Endpoint::server(server_cfg, "127.0.0.1:0".parse().unwrap()).unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();

        let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config(true, 64, None).unwrap());

        let server_task = tokio::spawn(async move {
            let incoming = server_endpoint.accept().await.unwrap();
            let conn = incoming.accept().unwrap().await.unwrap();
            let (send, recv) = conn.accept_bi().await.unwrap();
            let mut duplex = QuicDuplex::new(send, recv);
            let mut buf = [0u8; 4];
            duplex.read_exact(&mut buf).await.unwrap();
            duplex.write_all(&buf).await.unwrap();
            duplex.flush().await.unwrap();
            // Keep the connection alive until the client has read the echo.
            conn.closed().await;
        });

        let conn = client_endpoint
            .connect(server_addr, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (send, recv) = conn.open_bi().await.unwrap();
        let mut duplex = QuicDuplex::new(send, recv);
        duplex.write_all(b"ping").await.unwrap();
        duplex.flush().await.unwrap();
        let mut echoed = [0u8; 4];
        duplex.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping");

        conn.close(CLOSE_OK.into(), b"done");
        drop(conn);
        client_endpoint.wait_idle().await;
        let _ = server_task.await;
        let _ = std::fs::remove_file(cert);
        let _ = std::fs::remove_file(key);
    }
}
