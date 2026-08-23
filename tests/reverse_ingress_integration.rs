mod common;

use common::{TEST_CERT, TEST_KEY};
use rove::config::{Listener, TlsFiles, TuicListener};
use rove::engine::Engine;
use rove::ingress::connector::{self, IngressListenerConfig, ReverseIngressConfig};
use rove::ingress::metadata;
use rove::ingress::relay::{RelayConfig, RelayServer};
use rove::ingress::{client_config, frame};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[tokio::test]
async fn relay_forwards_tcp_and_1200_byte_udp_with_client_metadata() {
    rove::tls::init_crypto();
    let files = TestFiles::new();
    let tcp_public_port = free_tcp_port();
    let udp_public_port = free_udp_port();
    let (tcp_local_addr, tcp_metadata) = start_tcp_echo().await;
    let (udp_local_addr, udp_metadata) = start_udp_echo().await;

    let relay_toml = format!(
        r#"
relay_id = "relay-test"
listen = "127.0.0.1:0"
public_bind = "127.0.0.1"
cert = {cert:?}
key = {key:?}
initial_mtu = 1452
lease_grace_secs = 5

[[nodes]]
node_id = "edge-nat-01"
token = "test-token"
max_leases = 4
max_tcp_connections = 16
max_udp_flows = 16

[[nodes.listeners]]
id = "tcp-public"
transport = "tcp"
ports = ["{tcp_public_port}"]

[[nodes.listeners]]
id = "udp-public"
transport = "udp"
ports = ["{udp_public_port}"]
"#,
        cert = files.cert,
        key = files.key,
    );
    std::fs::write(&files.config, relay_toml).unwrap();
    let relay = RelayServer::bind(RelayConfig::load(&files.config).unwrap()).unwrap();
    let relay_addr = relay.local_addr();
    let relay_task = tokio::spawn(relay.run());

    let reverse_ingress = ReverseIngressConfig {
        enable: true,
        relay: relay_addr.to_string(),
        server_name: String::new(),
        token: "test-token".into(),
        token_env: String::new(),
        skip_cert_verify: true,
        initial_mtu: Some(1452),
        max_streams: 64,
        max_udp_flows: 16,
        reconnect_min_secs: 1,
        reconnect_max_secs: 2,
        listeners: vec![
            IngressListenerConfig {
                id: "udp-public".into(),
                transport: "udp".into(),
                public_port: udp_public_port,
                local_listener: "tuic-local".into(),
                max_inner_datagram: 1200,
            },
            IngressListenerConfig {
                id: "tcp-public".into(),
                transport: "tcp".into(),
                public_port: tcp_public_port,
                local_listener: "tcp-local".into(),
                max_inner_datagram: 1200,
            },
        ],
    };
    let runtime = reverse_ingress
        .to_runtime(
            "edge-nat-01",
            &[Listener {
                name: "tcp-local".into(),
                protocol: "http".into(),
                listen: tcp_local_addr.to_string(),
                tls: None,
                sniff: rove::config::SniffConfig::default(),
            }],
            &[TuicListener {
                name: "tuic-local".into(),
                listen: udp_local_addr.to_string(),
                cert: "unused".into(),
                key: "unused".into(),
                alpn: vec!["h3".into()],
                initial_mtu: None,
                sniff: rove::config::SniffConfig::default(),
            }],
        )
        .unwrap()
        .unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let connector_task = tokio::spawn(connector::run_until(runtime, shutdown_rx));

    let mut tcp = connect_with_retry(tcp_public_port).await;
    let tcp_client_addr = tcp.local_addr().unwrap();
    tcp.write_all(b"reverse-ingress-tcp").await.unwrap();
    let mut echoed = [0u8; 19];
    tcp.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"reverse-ingress-tcp");
    let tcp_meta = tokio::time::timeout(Duration::from_secs(5), tcp_metadata)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tcp_meta.client_addr, tcp_client_addr);
    assert_eq!(tcp_meta.relay_instance_id, "relay-test");
    assert!(tcp_meta.ingress_id.is_some());

    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_client_addr = udp.local_addr().unwrap();
    let payload = vec![0x5a; 1200];
    let public_udp: SocketAddr = format!("127.0.0.1:{udp_public_port}").parse().unwrap();
    let mut received = vec![0u8; payload.len()];
    let len = loop {
        udp.send_to(&payload, public_udp).await.unwrap();
        match tokio::time::timeout(Duration::from_millis(300), udp.recv(&mut received)).await {
            Ok(Ok(len)) => break len,
            _ => continue,
        }
    };
    assert_eq!(len, payload.len());
    assert_eq!(received, payload);
    let udp_meta = tokio::time::timeout(Duration::from_secs(5), udp_metadata)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(udp_meta.client_addr, udp_client_addr);
    assert_eq!(udp_meta.relay_instance_id, "relay-test");
    assert!(udp_meta.flow_id.is_some());

    let _ = shutdown_tx.send(true);
    connector_task.abort();
    relay_task.abort();
}

#[tokio::test]
async fn relay_preserves_end_to_end_tls_termination_at_rove() {
    rove::tls::init_crypto();
    let files = TestFiles::new();
    let public_port = free_tcp_port();
    let local_port = free_tcp_port();
    let local_listener = Listener {
        name: "https-local".into(),
        protocol: "http".into(),
        listen: format!("127.0.0.1:{local_port}"),
        tls: Some(TlsFiles {
            cert: files.cert.clone(),
            key: files.key.clone(),
            certificates: Vec::new(),
        }),
        sniff: rove::config::SniffConfig::default(),
    };
    let (local_shutdown_tx, local_shutdown_rx) = tokio::sync::watch::channel(false);
    let local_task = tokio::spawn(rove::inbound::listener::run_until(
        local_listener.clone(),
        Engine::new(),
        None,
        None,
        None,
        rove::stats::TrafficStats::new(),
        rove::outbound::EgressContext::default(),
        local_shutdown_rx,
    ));

    let relay_toml = format!(
        r#"
relay_id = "relay-tls"
listen = "127.0.0.1:0"
public_bind = "127.0.0.1"
cert = {cert:?}
key = {key:?}
initial_mtu = 1452

[[nodes]]
node_id = "edge-tls"
token = "tls-token"

[[nodes.listeners]]
id = "https-public"
transport = "tcp"
ports = ["{public_port}"]
"#,
        cert = files.cert,
        key = files.key,
    );
    std::fs::write(&files.config, relay_toml).unwrap();
    let relay = RelayServer::bind(RelayConfig::load(&files.config).unwrap()).unwrap();
    let relay_addr = relay.local_addr();
    let relay_task = tokio::spawn(relay.run());

    let reverse_ingress = ReverseIngressConfig {
        enable: true,
        relay: relay_addr.to_string(),
        server_name: String::new(),
        token: "tls-token".into(),
        token_env: String::new(),
        skip_cert_verify: true,
        initial_mtu: Some(1452),
        max_streams: 64,
        max_udp_flows: 16,
        reconnect_min_secs: 1,
        reconnect_max_secs: 2,
        listeners: vec![IngressListenerConfig {
            id: "https-public".into(),
            transport: "tcp".into(),
            public_port,
            local_listener: "https-local".into(),
            max_inner_datagram: 1200,
        }],
    };
    let runtime = reverse_ingress
        .to_runtime("edge-tls", std::slice::from_ref(&local_listener), &[])
        .unwrap()
        .unwrap();
    let (connector_shutdown_tx, connector_shutdown_rx) = tokio::sync::watch::channel(false);
    let connector_task = tokio::spawn(connector::run_until(runtime, connector_shutdown_rx));

    let tcp = connect_with_retry(public_port).await;
    let connector = rove::tls::insecure_client_connector();
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();
    tls.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .unwrap();
    let mut response = [0u8; 128];
    let len = tls.read(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response[..len]).starts_with("HTTP/1.1 407"));

    let _ = connector_shutdown_tx.send(true);
    let _ = local_shutdown_tx.send(true);
    connector_task.abort();
    relay_task.abort();
    local_task.abort();
}

#[tokio::test]
async fn relay_rejects_bad_token_unknown_listener_and_unauthorized_port() {
    rove::tls::init_crypto();
    let files = TestFiles::new();
    let allowed_port = free_tcp_port();
    let relay_toml = format!(
        r#"
relay_id = "relay-auth"
listen = "127.0.0.1:0"
public_bind = "127.0.0.1"
cert = {cert:?}
key = {key:?}

[[nodes]]
node_id = "edge-auth"
token = "correct-token"

[[nodes.listeners]]
id = "https-public"
transport = "tcp"
ports = ["{allowed_port}"]
"#,
        cert = files.cert,
        key = files.key,
    );
    std::fs::write(&files.config, relay_toml).unwrap();
    let relay = RelayServer::bind(RelayConfig::load(&files.config).unwrap()).unwrap();
    let relay_addr = relay.local_addr();
    let relay_task = tokio::spawn(relay.run());

    let (_bad_endpoint, bad_connection) = connect_raw(relay_addr).await;
    let (mut send, mut recv) = bad_connection.open_bi().await.unwrap();
    let bad = frame::RegisterRequest {
        node_id: "edge-auth".into(),
        token: "wrong-token".into(),
    };
    frame::write_frame(&mut send, &bad.encode().unwrap())
        .await
        .unwrap();
    assert_eq!(
        frame::Reply::parse(&frame::read_frame(&mut recv).await.unwrap()).unwrap(),
        frame::Reply::Err(frame::codes::UNAUTHORIZED.into())
    );

    let (_endpoint, connection) = connect_raw(relay_addr).await;
    let (mut control_send, mut control_recv) = connection.open_bi().await.unwrap();
    let valid = frame::RegisterRequest {
        node_id: "edge-auth".into(),
        token: "correct-token".into(),
    };
    frame::write_frame(&mut control_send, &valid.encode().unwrap())
        .await
        .unwrap();
    assert!(matches!(
        frame::Reply::parse(&frame::read_frame(&mut control_recv).await.unwrap()).unwrap(),
        frame::Reply::Ok(_)
    ));

    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let unknown = frame::LeaseRequest {
        listener_id: "unknown".into(),
        transport: frame::Transport::Tcp,
        public_port: allowed_port,
    };
    frame::write_frame(&mut send, &unknown.encode().unwrap())
        .await
        .unwrap();
    assert_eq!(
        frame::Reply::parse(&frame::read_frame(&mut recv).await.unwrap()).unwrap(),
        frame::Reply::Err(frame::codes::FORBIDDEN.into())
    );

    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let unauthorized_port = frame::LeaseRequest {
        listener_id: "https-public".into(),
        transport: frame::Transport::Tcp,
        public_port: allowed_port.wrapping_add(1).max(1),
    };
    frame::write_frame(&mut send, &unauthorized_port.encode().unwrap())
        .await
        .unwrap();
    assert_eq!(
        frame::Reply::parse(&frame::read_frame(&mut recv).await.unwrap()).unwrap(),
        frame::Reply::Err(frame::codes::FORBIDDEN.into())
    );

    connection.close(0u32.into(), b"test complete");
    relay_task.abort();
}

#[tokio::test]
async fn relay_carries_a_real_tuic_quic_handshake_over_udp() {
    rove::tls::init_crypto();
    let files = TestFiles::new();
    let public_udp_port = free_udp_port();
    let public_tcp_port = free_tcp_port();
    let local_udp_port = free_udp_port();
    let tuic_listener = TuicListener {
        name: "tuic-local".into(),
        listen: format!("127.0.0.1:{local_udp_port}"),
        cert: files.cert.clone(),
        key: files.key.clone(),
        alpn: vec!["h3".into()],
        initial_mtu: Some(1200),
        sniff: rove::config::SniffConfig::default(),
    };
    let (tuic_shutdown_tx, tuic_shutdown_rx) = tokio::sync::watch::channel(false);
    let tuic_task = tokio::spawn(rove::inbound::tuic::run_until(
        tuic_listener.to_runtime(),
        Engine::new(),
        rove::stats::TrafficStats::new(),
        None,
        rove::outbound::EgressContext::default(),
        tuic_shutdown_rx,
    ));
    let (tcp_local_addr, _metadata) = start_tcp_echo().await;

    let relay_toml = format!(
        r#"
relay_id = "relay-tuic"
listen = "127.0.0.1:0"
public_bind = "127.0.0.1"
cert = {cert:?}
key = {key:?}
initial_mtu = 1452

[[nodes]]
node_id = "edge-tuic"
token = "tuic-token"

[[nodes.listeners]]
id = "tuic-public"
transport = "udp"
ports = ["{public_udp_port}"]

[[nodes.listeners]]
id = "ready"
transport = "tcp"
ports = ["{public_tcp_port}"]
"#,
        cert = files.cert,
        key = files.key,
    );
    std::fs::write(&files.config, relay_toml).unwrap();
    let relay = RelayServer::bind(RelayConfig::load(&files.config).unwrap()).unwrap();
    let relay_addr = relay.local_addr();
    let relay_task = tokio::spawn(relay.run());

    let reverse_ingress = ReverseIngressConfig {
        enable: true,
        relay: relay_addr.to_string(),
        server_name: String::new(),
        token: "tuic-token".into(),
        token_env: String::new(),
        skip_cert_verify: true,
        initial_mtu: Some(1452),
        max_streams: 64,
        max_udp_flows: 16,
        reconnect_min_secs: 1,
        reconnect_max_secs: 2,
        listeners: vec![
            IngressListenerConfig {
                id: "tuic-public".into(),
                transport: "udp".into(),
                public_port: public_udp_port,
                local_listener: "tuic-local".into(),
                max_inner_datagram: 1200,
            },
            IngressListenerConfig {
                id: "ready".into(),
                transport: "tcp".into(),
                public_port: public_tcp_port,
                local_listener: "ready-local".into(),
                max_inner_datagram: 1200,
            },
        ],
    };
    let runtime = reverse_ingress
        .to_runtime(
            "edge-tuic",
            &[Listener {
                name: "ready-local".into(),
                protocol: "http".into(),
                listen: tcp_local_addr.to_string(),
                tls: None,
                sniff: rove::config::SniffConfig::default(),
            }],
            std::slice::from_ref(&tuic_listener),
        )
        .unwrap()
        .unwrap();
    let (connector_shutdown_tx, connector_shutdown_rx) = tokio::sync::watch::channel(false);
    let connector_task = tokio::spawn(connector::run_until(runtime, connector_shutdown_rx));

    // The TCP lease is requested after the UDP lease; reaching it means the
    // public TUIC socket is already active.
    drop(connect_with_retry(public_tcp_port).await);
    tokio::time::sleep(Duration::from_millis(25)).await;

    let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let public_addr: SocketAddr = format!("127.0.0.1:{public_udp_port}").parse().unwrap();
    let connection = tokio::time::timeout(
        Duration::from_secs(5),
        endpoint
            .connect_with(insecure_quic_client(b"h3"), public_addr, "localhost")
            .unwrap(),
    )
    .await
    .expect("TUIC QUIC handshake timed out")
    .expect("TUIC QUIC handshake failed through relay");
    connection.close(0u32.into(), b"test complete");

    let _ = connector_shutdown_tx.send(true);
    let _ = tuic_shutdown_tx.send(true);
    connector_task.abort();
    relay_task.abort();
    tuic_task.abort();
}

#[tokio::test]
async fn dynamic_tcp_lease_restores_the_same_port_within_grace() {
    rove::tls::init_crypto();
    let files = TestFiles::new();
    let port_a = free_tcp_port();
    let mut port_b = free_tcp_port();
    while port_b == port_a {
        port_b = free_tcp_port();
    }
    let relay_toml = format!(
        r#"
relay_id = "relay-reconnect"
listen = "127.0.0.1:0"
public_bind = "127.0.0.1"
cert = {cert:?}
key = {key:?}
lease_grace_secs = 10

[[nodes]]
node_id = "edge-reconnect"
token = "reconnect-token"

[[nodes.listeners]]
id = "dynamic"
transport = "tcp"
ports = ["{port_a}", "{port_b}"]
"#,
        cert = files.cert,
        key = files.key,
    );
    std::fs::write(&files.config, relay_toml).unwrap();
    let relay = RelayServer::bind(RelayConfig::load(&files.config).unwrap()).unwrap();
    let relay_addr = relay.local_addr();
    let relay_task = tokio::spawn(relay.run());

    let reverse_ingress = ReverseIngressConfig {
        enable: true,
        relay: relay_addr.to_string(),
        server_name: String::new(),
        token: "reconnect-token".into(),
        token_env: String::new(),
        skip_cert_verify: true,
        initial_mtu: None,
        max_streams: 64,
        max_udp_flows: 16,
        reconnect_min_secs: 1,
        reconnect_max_secs: 2,
        listeners: vec![IngressListenerConfig {
            id: "dynamic".into(),
            transport: "tcp".into(),
            public_port: 0,
            local_listener: "local".into(),
            max_inner_datagram: 1200,
        }],
    };
    let runtime = reverse_ingress
        .to_runtime(
            "edge-reconnect",
            &[Listener {
                name: "local".into(),
                protocol: "http".into(),
                listen: "127.0.0.1:9".into(),
                tls: None,
                sniff: rove::config::SniffConfig::default(),
            }],
            &[],
        )
        .unwrap()
        .unwrap();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let first = tokio::spawn(connector::run_until(runtime.clone(), shutdown_rx));
    let assigned = discover_open_port(&[port_a, port_b]).await;
    let _ = shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_secs(5), first)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    wait_port_closed(assigned).await;

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let second = tokio::spawn(connector::run_until(runtime, shutdown_rx));
    let restored = discover_open_port(&[port_a, port_b]).await;
    assert_eq!(restored, assigned);
    let _ = shutdown_tx.send(true);
    second.abort();
    relay_task.abort();
}

async fn connect_raw(relay_addr: SocketAddr) -> (quinn::Endpoint, quinn::Connection) {
    let endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    let connection = endpoint
        .connect_with(
            client_config(true, 16, Some(1452)).unwrap(),
            relay_addr,
            "localhost",
        )
        .unwrap()
        .await
        .unwrap();
    (endpoint, connection)
}

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

fn insecure_quic_client(alpn: &[u8]) -> quinn::ClientConfig {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![alpn.to_vec()];
    let quic = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap();
    let mut client = quinn::ClientConfig::new(std::sync::Arc::new(quic));
    let mut transport = quinn::TransportConfig::default();
    transport.initial_mtu(1200);
    transport.datagram_receive_buffer_size(Some(1024 * 1024));
    client.transport_config(std::sync::Arc::new(transport));
    client
}

async fn start_tcp_echo() -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<metadata::IngressMetadata>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (metadata_tx, metadata_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, peer) = listener.accept().await.unwrap();
        let metadata = metadata::take_tcp(peer).expect("trusted TCP metadata registered");
        let _ = metadata_tx.send(metadata);
        let mut buffer = [0u8; 4096];
        loop {
            let len = match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(len) => len,
            };
            stream.write_all(&buffer[..len]).await.unwrap();
        }
    });
    (addr, metadata_rx)
}

async fn start_udp_echo() -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<metadata::IngressMetadata>,
) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (metadata_tx, metadata_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let metadata = metadata::lookup_udp(peer).expect("trusted UDP metadata registered");
        let _ = metadata_tx.send(metadata);
        socket.send_to(&buffer[..len], peer).await.unwrap();
    });
    (addr, metadata_rx)
}

async fn connect_with_retry(port: u16) -> TcpStream {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(stream) => return stream,
            Err(_) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }

            Err(error) => panic!("public relay TCP port did not become ready: {error}"),
        }
    }
}

async fn discover_open_port(ports: &[u16]) -> u16 {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        for port in ports {
            if TcpStream::connect(("127.0.0.1", *port)).await.is_ok() {
                return *port;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no dynamic relay port became ready"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_port_closed(port: u16) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).await.is_err() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "relay port stayed open after connector shutdown"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct TestFiles {
    cert: String,
    key: String,
    config: String,
}

impl TestFiles {
    fn new() -> Self {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let prefix =
            std::env::temp_dir().join(format!("rove-ingress-it-{}-{seq}", std::process::id()));
        let cert = prefix.with_extension("crt");
        let key = prefix.with_extension("key");
        let config = prefix.with_extension("toml");
        std::fs::write(&cert, TEST_CERT).unwrap();
        std::fs::write(&key, TEST_KEY).unwrap();
        TestFiles {
            cert: cert.to_string_lossy().into_owned(),
            key: key.to_string_lossy().into_owned(),
            config: config.to_string_lossy().into_owned(),
        }
    }
}

impl Drop for TestFiles {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.cert);
        let _ = std::fs::remove_file(&self.key);
        let _ = std::fs::remove_file(&self.config);
    }
}
