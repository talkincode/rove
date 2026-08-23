//! End-to-end TUIC v5 front-end integration tests. A raw QUIC client speaks the
//! real TUIC wire format against `inbound::tuic::run`: Authenticate (with a
//! genuine TLS keying-material token), Connect (TCP relay to an echo), and a
//! native-mode Packet routed through a real reverse hop to a UDP echo — proving
//! the front-end -> engine -> egress chain end to end.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rove::config::TuicListener;
use rove::engine::Engine;
use rove::model::{RawFrontendCred, RawSnapshot, RawUpstream, RawUser, Snapshot};
use rove::reverse::edge::{DuplicatePolicy, ReverseHopManager, ReverseListenerConfig};
use rove::reverse::hop::{ReverseEdgeConfig, ReverseHopClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::oneshot;

mod common;
use common::PolicySpec;

const TEST_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUAhO4y5A+Ol+O93RC/xCs0+kTRkkwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYzMDE2NTMzMloXDTI2MDcw
MTE2NTMzMlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA4czDicziIZKbupNwxPgbYa9jMAw1U9ypRAYUSlqcHG+5
shd/YkBxZ8fCZXDwr62GTVikRnyo99kzAeilgW22SgmlXzA8JKBpEzlN6YpZDhTh
yowwTtGts83z4mRWStXtHHzx1oomJTFpuwtvH6uNmvvVq8QGP9tRcPYXtJc80mZk
6qyFooKKxH8FinyqBpE0gLCnZoz9t/5CNTrZvkXt0kaZU9W5IwJGLw1ykktmzsC3
fl+vr24iHORg0HFI465tdFRN7fOhq9XMOdxxoEo9Fbe1J6AbwItkBMS6OJ8pMAMn
GOUqLDxvUxpICXUzvw6tRbfDjRjhRNAPJflJ5irmpQIDAQABo1MwUTAdBgNVHQ4E
FgQUTTYc3xMzdxugRyWHg9wY0SSWEXQwHwYDVR0jBBgwFoAUTTYc3xMzdxugRyWH
g9wY0SSWEXQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAvMhS
6sNjihQIHAMdZbQcxkBa1GsORK28flXAS1s41WI192gq6lCmP27mtig/vTzYEusY
qn0vMNhWaZXaAL1kUG5NMONrup5KA9N+vgdCClpGl9ffSrSMJciqvQZ/e3n/Eotn
fwJDlqASKGJ3ihQiEXfJx5oVpKA2VKSKxxlwKDmEPPUiwrbg3UH6iQlwFSed8Ypn
83niMaSI8VZf/Y2wtNldAOSW7K8jCvcfTCgO27qUepWAAnOl3Cy4NELtpZCTh6HH
ohVgaaT/RuT8aZbczsj7/5HH527DPpgJBmxKcOZ/e+jmdKtRsFnaoBziBr/CKwq4
IJsCUBadjBA5aZyBXg==
-----END CERTIFICATE-----";

const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDhzMOJzOIhkpu6
k3DE+Bthr2MwDDVT3KlEBhRKWpwcb7myF39iQHFnx8JlcPCvrYZNWKRGfKj32TMB
6KWBbbZKCaVfMDwkoGkTOU3pilkOFOHKjDBO0a2zzfPiZFZK1e0cfPHWiiYlMWm7
C28fq42a+9WrxAY/21Fw9he0lzzSZmTqrIWigorEfwWKfKoGkTSAsKdmjP23/kI1
Otm+Re3SRplT1bkjAkYvDXKSS2bOwLd+X6+vbiIc5GDQcUjjrm10VE3t86Gr1cw5
3HGgSj0Vt7UnoBvAi2QExLo4nykwAycY5SosPG9TGkgJdTO/Dq1Ft8ONGOFE0A8l
+UnmKualAgMBAAECggEAGQ0luJkhkYX5fxaykTfRmeHiiEcid35ozSI7iBBLd6Ax
ov+WY2kw68mu2KBSI7uFxfkKqMNV38GaNiEAk75/VfGCBnCMi6e8YKSf70QpIzXP
4y/wgB4lPmigIULui/j2CI4YKqxDFSdJSrY3CvV2jXZZO2hRJS6I95ZmBOQunE0I
laMoBeZrhI1yJGFu+KRM2759jRVFl5JAqsf8JRJQk9PIe2rB3mSaCRKyKS1gnDIK
iiddOdcxf3hJSoKaqF3z5h+qK1OxZNiteKNL5fuvX+2KmN/7rQcwttLQqbXGdnsw
vNOyyfnB5VpvxnKy5gbfFNI3fEovHtT7ELWhTIKAIQKBgQDx7O9GO05XnlUoGOTs
R7Ccrd+sqMDMWIo9cA7AD63z9Cy83PuOoOuAvmfHKGvCTDUPrVJ90X6nnbeCdLxX
NwWWQMTKwhq/vZaZ6eCVSFSXCdvbRRYVYFv5xxbIaoFnguiXEGhd24sKiGPuw9GN
HHSZxxiu+Ef6s6q5Cz+3M/9ffQKBgQDu76o/QqRb4tivbrh4+yT8PHbe8Ro53RUE
oNB0n4sjKXgsalhFuAv7fw6MDCFHSxHGBL2lTtV7mZ/VEgT3fB70j/929EsSteAx
dNHonxhZ+YSoHu+v8FU85F9XpPo5qEHY8vW3lsYHxHf9fOZSx0wM9Ok36aUEPz9k
5x7C9jMcSQKBgCevxaTQz85B1Bhq1QsJy6g4QcwyNsaO88aWXmUVbWTqtngZDE9e
iKOrGJ0sPVk3ZTD4LuMi/dMDZXpKKidoiEsYvu/AHeE8ebswCb6TigTpAh8bWz8Q
eqYkCdHA3w+bAwrdDzHudQW6UCJ4DyVF+L7NUXhKlIxE8wm+Faq5JfiFAoGADsEw
Ay4LVj1A4jx1Gctwcj8NnCDJXM9hL+L6XGlJv0cdS6jZgJyn6MTk0hMhrvRcyZyb
VWzz0+kdrJurQNkiVDncLa1SQXqHuKYdHD9O0qeM4JDgfj3aFaOIm7HtXcgdINeI
AulFm08vlbCzzGLQOHCbQj+kWAnL0WBQTvvDFjkCgYEA7LA+RcGSZQjXw7PYm0Z2
410OnmEWlGBiF5h+jWGrWLpSEH632KdAryjXnw5L2QGnzc/7bpsINX0Kvpstut1m
4yU5RFQ1CphRafbztDMLnv5dO0gkqHWHvxE97MTBV/W9UZl6c52RB+5a8H+/QSbZ
v6K3aPttpZErFvOSVbzWaCY=
-----END PRIVATE KEY-----";

fn write_test_cert() -> (String, String) {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir();
    let cert = dir.join(format!("rove-tuic-it-{nanos}.crt"));
    let key = dir.join(format!("rove-tuic-it-{nanos}.key"));
    std::fs::write(&cert, TEST_CERT).unwrap();
    std::fs::write(&key, TEST_KEY).unwrap();
    (
        cert.to_string_lossy().into_owned(),
        key.to_string_lossy().into_owned(),
    )
}

fn free_udp_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap().port()
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

fn client_endpoint() -> quinn::Endpoint {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    let qc = quinn::crypto::rustls::QuicClientConfig::try_from(crypto).unwrap();
    let mut cfg = quinn::ClientConfig::new(Arc::new(qc));
    let mut tr = quinn::TransportConfig::default();
    tr.datagram_receive_buffer_size(Some(1024 * 1024));
    tr.datagram_send_buffer_size(1024 * 1024);
    cfg.transport_config(Arc::new(tr));
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(cfg);
    ep
}

async fn connect_client(port: u16) -> quinn::Connection {
    let ep = client_endpoint();
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    for _ in 0..50 {
        if let Ok(connecting) = ep.connect(addr, "localhost") {
            if let Ok(Ok(conn)) = tokio::time::timeout(Duration::from_millis(500), connecting).await
            {
                return conn;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("client could not connect to tuic listener on {addr}");
}

fn engine_with(default_reverse_hop: Option<&str>) -> Arc<Engine> {
    rove::tls::init_crypto();
    let policy = PolicySpec {
        default_egress: default_reverse_hop.map(|hop| RawUpstream {
            kind: "reverse".to_string(),
            addr: hop.to_string(),
            username: None,
            password: None,
            tls: false,
            skip_cert_verify: false,
        }),
        ..Default::default()
    };
    engine_with_policy(policy)
}

fn engine_with_policy(policy: PolicySpec) -> Arc<Engine> {
    rove::tls::init_crypto();
    let (routing_policies, egresses) = policy.into_tables("g");
    let mut users = HashMap::new();
    users.insert(
        "alice".to_string(),
        RawUser {
            password: "login".to_string(),
            expire: None,
            up_rate: 0,
            down_rate: 0,
            max_connections: 0,
            policy: "g".to_string(),
            frontends: HashMap::from([(
                "tuic".to_string(),
                RawFrontendCred {
                    uuid: Some("01010101-0101-0101-0101-010101010101".to_string()),
                    password: Some("tp".to_string()),
                },
            )]),
        },
    );
    let raw = RawSnapshot {
        version: 1,
        users,
        routing_policies,
        egresses,
        ..Default::default()
    };
    let snap = Snapshot::compile(raw, "node").expect("compile");
    let engine = Engine::new();
    engine.replace(snap);
    engine
}

async fn start_tuic(engine: Arc<Engine>, reverse: Option<Arc<ReverseHopManager>>) -> u16 {
    let (cert, key) = write_test_cert();
    let port = free_udp_port();
    let cfg = TuicListener {
        name: "tuic-test".to_string(),
        listen: format!("127.0.0.1:{port}"),
        cert,
        key,
        alpn: vec!["h3".to_string()],
        initial_mtu: None,
        sniff: rove::config::SniffConfig::default(),
    }
    .to_runtime();
    let stats = rove::stats::TrafficStats::new();
    let egress = rove::outbound::EgressContext::new(reverse, None);
    tokio::spawn(rove::inbound::tuic::run(cfg, engine, stats, None, egress));
    tokio::time::sleep(Duration::from_millis(150)).await;
    port
}

async fn start_tuic_with_observe(
    engine: Arc<Engine>,
    access_log: Arc<rove::access_log::AccessLogger>,
    stats: Arc<rove::stats::TrafficStats>,
) -> u16 {
    let (cert, key) = write_test_cert();
    let port = free_udp_port();
    let cfg = TuicListener {
        name: "tuic-observe".to_string(),
        listen: format!("127.0.0.1:{port}"),
        cert,
        key,
        alpn: vec!["h3".to_string()],
        initial_mtu: None,
        sniff: rove::config::SniffConfig {
            enabled: true,
            ..rove::config::SniffConfig::default()
        },
    }
    .to_runtime();
    tokio::spawn(rove::inbound::tuic::run(
        cfg,
        engine,
        stats,
        Some(access_log),
        rove::outbound::EgressContext::default(),
    ));
    tokio::time::sleep(Duration::from_millis(150)).await;
    port
}

async fn start_tuic_with_route(
    engine: Arc<Engine>,
    access_log: Arc<rove::access_log::AccessLogger>,
    stats: Arc<rove::stats::TrafficStats>,
) -> u16 {
    let (cert, key) = write_test_cert();
    let port = free_udp_port();
    let cfg = TuicListener {
        name: "tuic-route".to_string(),
        listen: format!("127.0.0.1:{port}"),
        cert,
        key,
        alpn: vec!["h3".to_string()],
        initial_mtu: None,
        sniff: rove::config::SniffConfig {
            enabled: true,
            mode: rove::config::SniffMode::Route,
            ..rove::config::SniffConfig::default()
        },
    }
    .to_runtime();
    tokio::spawn(rove::inbound::tuic::run(
        cfg,
        engine,
        stats,
        Some(access_log),
        rove::outbound::EgressContext::default(),
    ));
    tokio::time::sleep(Duration::from_millis(150)).await;
    port
}

async fn authenticate(conn: &quinn::Connection) {
    let uuid = [1u8; 16];
    let mut token = [0u8; 32];
    conn.export_keying_material(&mut token, &uuid, b"tp")
        .expect("export keying material");
    let mut msg = vec![0x05u8, 0x00];
    msg.extend_from_slice(&uuid);
    msg.extend_from_slice(&token);
    let mut uni = conn.open_uni().await.unwrap();
    uni.write_all(&msg).await.unwrap();
    uni.finish().unwrap();
}

async fn start_tcp_echo() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

async fn start_http_connect_upstream() -> (String, oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let (target_tx, target_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let head = rove::util::read_http_head(&mut client, 8192).await.unwrap();
        let head = String::from_utf8(head).unwrap();
        let authority = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .expect("CONNECT authority")
            .to_string();
        let mut target = tokio::net::TcpStream::connect(&authority).await.unwrap();
        let _ = target_tx.send(authority);
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut target).await;
    });
    (address, target_rx)
}

async fn start_udp_echo() -> String {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match sock.recv_from(&mut buf).await {
                Ok((n, src)) => {
                    let _ = sock.send_to(&buf[..n], src).await;
                }
                Err(_) => return,
            }
        }
    });
    addr
}

fn start_edge() -> (Arc<ReverseHopManager>, String) {
    rove::tls::init_crypto();
    let (cert, key) = write_test_cert();
    let mut cfg = ReverseListenerConfig::new(
        "127.0.0.1:0",
        cert,
        key,
        vec!["tok".to_string()],
        "edge-test",
    );
    cfg.duplicate = DuplicatePolicy::Reject;
    cfg.open_timeout = Duration::from_secs(5);
    let m = ReverseHopManager::spawn(cfg).unwrap();
    let addr = m.local_addr().to_string();
    (m, addr)
}

async fn start_hop_and_wait(
    m: &Arc<ReverseHopManager>,
    edge_addr: &str,
    hop_id: &str,
    token: &str,
) {
    let config = ReverseHopClientConfig {
        edges: vec![ReverseEdgeConfig {
            edge_addr: edge_addr.to_string(),
            server_name: "localhost".to_string(),
            hop_id: hop_id.to_string(),
            token: token.to_string(),
            edge_id: Some("edge-test".to_string()),
            skip_cert_verify: true,
            max_streams: 64,
            initial_mtu: None,
        }],
        global_max_streams: 0,
        node_id: "hop-test".to_string(),
    };
    rove::reverse::hop::spawn(config, None, rove::stats::TrafficStats::new());
    for _ in 0..200 {
        if m.is_registered(hop_id) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("hop did not register");
}

fn v4_bytes(addr: &str) -> ([u8; 4], u16) {
    let sa: SocketAddr = addr.parse().unwrap();
    match sa {
        SocketAddr::V4(v4) => (v4.ip().octets(), v4.port()),
        _ => panic!("expected v4"),
    }
}

#[tokio::test]
async fn tuic_connect_tcp_relays_to_echo() {
    let engine = engine_with(None);
    let echo = start_tcp_echo().await;
    let port = start_tuic(engine, None).await;
    let conn = connect_client(port).await;
    authenticate(&conn).await;

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let (ip, p) = v4_bytes(&echo);
    let mut msg = vec![0x05u8, 0x01, 0x01]; // VER, CONNECT, ATYP v4
    msg.extend_from_slice(&ip);
    msg.extend_from_slice(&p.to_be_bytes());
    send.write_all(&msg).await.unwrap();
    send.write_all(b"hello-tuic").await.unwrap();

    let mut buf = [0u8; 10];
    tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut buf))
        .await
        .expect("tcp echo timed out")
        .expect("read echo");
    assert_eq!(&buf, b"hello-tuic");
}

#[tokio::test]
async fn tuic_connect_observe_sniff_records_host_without_changing_stream_bytes() {
    let engine = engine_with(None);
    let echo = start_tcp_echo().await;
    let (logger, mut records) = rove::access_log::AccessLogger::for_test();
    let stats = rove::stats::TrafficStats::new();
    let port = start_tuic_with_observe(engine, logger, stats.clone()).await;
    let conn = connect_client(port).await;
    authenticate(&conn).await;

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let (ip, target_port) = v4_bytes(&echo);
    let mut message = vec![0x05u8, 0x01, 0x01];
    message.extend_from_slice(&ip);
    message.extend_from_slice(&target_port.to_be_bytes());
    send.write_all(&message).await.unwrap();
    let payload = b"GET /quic HTTP/1.1\r\nHost: Quic.Example\r\n\r\n";
    send.write_all(payload).await.unwrap();

    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut echoed))
        .await
        .expect("tcp echo timed out")
        .expect("read echo");
    assert_eq!(echoed, payload);
    send.finish().unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1024))
        .await
        .expect("tuic stream close timed out")
        .expect("read stream close");

    let record = tokio::time::timeout(Duration::from_secs(5), records.recv())
        .await
        .expect("observe access record timed out")
        .expect("observe access record");
    assert_eq!(record.target_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(record.requested_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(record.sniffed_host.as_deref(), Some("quic.example"));
    assert_eq!(record.sniff_protocol, Some("http"));
    assert_eq!(record.sniff_outcome, Some("matched"));
    assert_eq!(stats.sniff_rows()[0].matched_total, 1);
}

#[tokio::test]
async fn tuic_route_sniffed_block_prevents_requested_ip_dial() {
    let engine = engine_with_policy(PolicySpec {
        blocked: vec!["blocked.example".to_string()],
        ..Default::default()
    });
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let (logger, mut records) = rove::access_log::AccessLogger::for_test();
    let stats = rove::stats::TrafficStats::new();
    let port = start_tuic_with_route(engine, logger, stats.clone()).await;
    let conn = connect_client(port).await;
    authenticate(&conn).await;

    let (mut send, _recv) = conn.open_bi().await.unwrap();
    let SocketAddr::V4(target_v4) = target_addr else {
        panic!("test target must be IPv4");
    };
    let mut message = vec![0x05u8, 0x01, 0x01];
    message.extend_from_slice(&target_v4.ip().octets());
    message.extend_from_slice(&target_v4.port().to_be_bytes());
    message.extend_from_slice(b"GET / HTTP/1.1\r\nHost: Blocked.Example\r\n\r\n");
    send.write_all(&message).await.unwrap();

    let record = tokio::time::timeout(Duration::from_secs(5), records.recv())
        .await
        .expect("route block access record timed out")
        .expect("route block access record");
    assert_eq!(record.target_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(record.requested_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(record.sniffed_host.as_deref(), Some("blocked.example"));
    assert_eq!(
        record.effective_policy_host.as_deref(),
        Some("blocked.example")
    );
    assert_eq!(record.decision.as_deref(), Some("block"));
    assert_eq!(record.failure_stage.as_deref(), Some("policy"));
    assert_eq!(record.snapshot_version, 1);
    assert_eq!(stats.sniff_rows()[0].matched_total, 1);
    assert!(
        tokio::time::timeout(Duration::from_millis(200), target.accept())
            .await
            .is_err(),
        "requested IP must not be dialed after sniffed block"
    );
}

#[tokio::test]
async fn tuic_route_unmatched_sniff_replays_captured_prefix_to_requested_ip() {
    let engine = engine_with(None);
    let echo = start_tcp_echo().await;
    let (logger, mut records) = rove::access_log::AccessLogger::for_test();
    let stats = rove::stats::TrafficStats::new();
    let port = start_tuic_with_route(engine, logger, stats.clone()).await;
    let conn = connect_client(port).await;
    authenticate(&conn).await;

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let (ip, target_port) = v4_bytes(&echo);
    let mut message = vec![0x05u8, 0x01, 0x01];
    message.extend_from_slice(&ip);
    message.extend_from_slice(&target_port.to_be_bytes());
    let payload = b"GET /route HTTP/1.1\r\nHost: Route.Example\r\n\r\nbody";
    message.extend_from_slice(payload);
    send.write_all(&message).await.unwrap();

    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut echoed))
        .await
        .expect("route echo timed out")
        .expect("read route echo");
    assert_eq!(echoed, payload);
    send.finish().unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1024))
        .await
        .expect("route stream close timed out")
        .expect("read route stream close");

    let record = tokio::time::timeout(Duration::from_secs(5), records.recv())
        .await
        .expect("route access record timed out")
        .expect("route access record");
    assert_eq!(record.requested_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(record.sniffed_host.as_deref(), Some("route.example"));
    assert_eq!(record.effective_policy_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(record.decision.as_deref(), Some("direct"));
    assert_eq!(record.result, "ok");
    assert_eq!(stats.sniff_rows()[0].matched_total, 1);
}

#[tokio::test]
async fn tuic_route_sniffed_proxy_selects_egress_but_dials_requested_ip() {
    let echo = start_tcp_echo().await;
    let (upstream, upstream_target) = start_http_connect_upstream().await;
    let engine = engine_with_policy(PolicySpec {
        egress: Some(RawUpstream {
            kind: "http".to_string(),
            addr: upstream.clone(),
            username: None,
            password: None,
            tls: false,
            skip_cert_verify: false,
        }),
        routed: vec!["route.example".to_string()],
        ..Default::default()
    });
    let (logger, mut records) = rove::access_log::AccessLogger::for_test();
    let stats = rove::stats::TrafficStats::new();
    let port = start_tuic_with_route(engine, logger, stats).await;
    let conn = connect_client(port).await;
    authenticate(&conn).await;

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    let (ip, target_port) = v4_bytes(&echo);
    let mut message = vec![0x05u8, 0x01, 0x01];
    message.extend_from_slice(&ip);
    message.extend_from_slice(&target_port.to_be_bytes());
    let payload = b"GET /proxy HTTP/1.1\r\nHost: Route.Example\r\n\r\n";
    message.extend_from_slice(payload);
    send.write_all(&message).await.unwrap();

    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), recv.read_exact(&mut echoed))
        .await
        .expect("proxied route echo timed out")
        .expect("read proxied route echo");
    assert_eq!(echoed, payload);
    let dialed = tokio::time::timeout(Duration::from_secs(5), upstream_target)
        .await
        .expect("upstream target capture timed out")
        .expect("upstream target capture");
    assert_eq!(dialed, echo);
    send.finish().unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(1024))
        .await
        .expect("proxied route stream close timed out")
        .expect("read proxied route stream close");

    let record = tokio::time::timeout(Duration::from_secs(5), records.recv())
        .await
        .expect("proxied route access record timed out")
        .expect("proxied route access record");
    assert_eq!(record.sniffed_host.as_deref(), Some("route.example"));
    assert_eq!(
        record.effective_policy_host.as_deref(),
        Some("route.example")
    );
    assert_eq!(
        record.decision.as_deref(),
        Some(format!("upstream:{upstream}").as_str())
    );
    assert_eq!(record.target_host.as_deref(), Some("127.0.0.1"));
    assert_eq!(record.snapshot_version, 1);
}

#[tokio::test]
async fn tuic_bad_token_closes_connection() {
    let engine = engine_with(None);
    let port = start_tuic(engine, None).await;
    let conn = connect_client(port).await;

    let uuid = [1u8; 16];
    let bad = [0u8; 32];
    let mut msg = vec![0x05u8, 0x00];
    msg.extend_from_slice(&uuid);
    msg.extend_from_slice(&bad);
    let mut uni = conn.open_uni().await.unwrap();
    uni.write_all(&msg).await.unwrap();
    uni.finish().unwrap();

    let closed = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
    assert!(closed.is_ok(), "connection must close after a bad token");
}

#[tokio::test]
async fn tuic_packet_relays_udp_through_reverse_hop() {
    let (manager, edge_addr) = start_edge();
    let echo = start_udp_echo().await;
    start_hop_and_wait(&manager, &edge_addr, "hop-tuic", "tok").await;

    let engine = engine_with(Some("hop-tuic"));
    let port = start_tuic(engine, Some(manager.clone())).await;
    let conn = connect_client(port).await;
    authenticate(&conn).await;

    let (ip, p) = v4_bytes(&echo);
    let payload = b"udp-hi";
    let mut dg = vec![0x05u8, 0x02]; // VER, PACKET
    dg.extend_from_slice(&1u16.to_be_bytes()); // assoc_id
    dg.extend_from_slice(&0u16.to_be_bytes()); // pkt_id
    dg.push(1); // frag_total
    dg.push(0); // frag_id
    dg.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    dg.push(0x01); // ATYP v4
    dg.extend_from_slice(&ip);
    dg.extend_from_slice(&p.to_be_bytes());
    dg.extend_from_slice(payload);
    conn.send_datagram(dg.into()).unwrap();

    let ret = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
        .await
        .expect("udp return timed out")
        .expect("read datagram");
    assert_eq!(ret[0], 0x05);
    assert_eq!(ret[1], 0x02);
    assert_eq!(u16::from_be_bytes([ret[2], ret[3]]), 1); // assoc_id echoed
    assert!(
        ret.windows(payload.len()).any(|w| w == payload),
        "return datagram must carry the echoed payload"
    );
}
