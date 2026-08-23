//! End-to-end reverse-hop QUIC integration tests: a real edge
//! [`ReverseHopManager`] and a real hop client (`reverse::hop::spawn`) talk over
//! loopback QUIC, tunnelling bytes through a local echo target. Also covers the
//! deterministic control-plane behaviours (auth reject, duplicate `hop_id`) via
//! a hand-rolled register handshake so they do not race the hop's reconnect
//! loop.

use std::sync::Arc;
use std::time::Duration;

use rove::reverse::client_config;
use rove::reverse::edge::{DuplicatePolicy, ReverseHopManager, ReverseListenerConfig};
use rove::reverse::frame::{self, codes, RegisterRequest, Reply};
use rove::reverse::hop::{ReverseEdgeConfig, ReverseHopClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// Self-signed localhost certificate (CN=localhost). Every test path below uses
// `skip_cert_verify`, so the fixture's validity window is irrelevant — the QUIC
// handshake only needs a syntactically valid TLS 1.3 certificate to present.
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
    // Wall-clock nanos alone collided when parallel tests hit the same clock
    // tick: one test's cleanup deleted the other's live cert. PID + a process
    // atomic counter makes the name unique regardless of clock resolution.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir();
    let cert = dir.join(format!("rove-rev-it-{pid}-{seq}.crt"));
    let key = dir.join(format!("rove-rev-it-{pid}-{seq}.key"));
    std::fs::write(&cert, TEST_CERT).unwrap();
    std::fs::write(&key, TEST_KEY).unwrap();
    (
        cert.to_string_lossy().into_owned(),
        key.to_string_lossy().into_owned(),
    )
}

/// Start an edge reverse-hop listener bound to an ephemeral loopback port.
fn start_edge(
    tokens: &[&str],
    duplicate: DuplicatePolicy,
) -> (Arc<ReverseHopManager>, String, String, String) {
    rove::tls::init_crypto();
    let (cert, key) = write_test_cert();
    let mut cfg = ReverseListenerConfig::new(
        "127.0.0.1:0",
        cert.clone(),
        key.clone(),
        tokens.iter().map(|t| t.to_string()).collect(),
        "edge-test",
    );
    cfg.duplicate = duplicate;
    cfg.open_timeout = Duration::from_secs(5);
    let manager = ReverseHopManager::spawn(cfg).expect("edge starts");
    let addr = manager.local_addr().to_string();
    (manager, addr, cert, key)
}

/// A loopback TCP echo server. Each accepted connection echoes until EOF.
async fn start_echo() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
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

/// Spawn the real hop client pointed at `edge_addr` and wait until it registers.
async fn start_hop_and_wait(
    manager: &Arc<ReverseHopManager>,
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
    wait_until(|| manager.is_registered(hop_id), Duration::from_secs(10)).await;
}

async fn wait_until(mut cond: impl FnMut() -> bool, timeout: Duration) {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("condition not met within {timeout:?}");
}

/// `Box<dyn IoStream>` is not `Debug`, so `Result::expect_err` cannot be used;
/// unwrap the error explicitly instead.
fn expect_open_error(
    result: rove::error::Result<Box<dyn rove::io::IoStream>>,
) -> rove::error::ProxyError {
    match result {
        Ok(_) => panic!("reverse open unexpectedly succeeded"),
        Err(e) => e,
    }
}

/// Manually perform the register handshake over a fresh QUIC connection,
/// returning the (kept-alive) connection and the edge's register reply. Used
/// for the deterministic auth / duplicate control-plane assertions.
async fn register_manually(
    edge_addr: &str,
    hop_id: &str,
    token: &str,
) -> (quinn::Connection, Reply) {
    let remote = tokio::net::lookup_host(edge_addr)
        .await
        .unwrap()
        .next()
        .unwrap();
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(client_config(true, 64, None).unwrap());
    let connection = endpoint
        .connect(remote, "localhost")
        .unwrap()
        .await
        .unwrap();
    let (mut send, mut recv) = connection.open_bi().await.unwrap();
    let request = RegisterRequest {
        hop_id: hop_id.to_string(),
        token: token.to_string(),
        edge_id: None,
        caps: vec![],
    };
    frame::write_frame(&mut send, &request.encode())
        .await
        .unwrap();
    let lines = frame::read_frame(&mut recv).await.unwrap();
    let reply = Reply::parse(&lines).unwrap();
    // Keep endpoint alive for the connection's lifetime.
    std::mem::forget(endpoint);
    (connection, reply)
}

#[tokio::test]
async fn reverse_tunnel_transfers_bytes_both_directions() {
    let (manager, edge_addr, cert, key) =
        start_edge(&["placeholder-token"], DuplicatePolicy::Reject);
    let echo = start_echo().await;
    start_hop_and_wait(&manager, &edge_addr, "hop-a", "placeholder-token").await;

    let (echo_host, echo_port) = echo.rsplit_once(':').unwrap();
    let mut tunnel = manager
        .open("hop-a", echo_host, echo_port.parse().unwrap())
        .await
        .expect("reverse tunnel opens");

    tunnel.write_all(b"hello-reverse").await.unwrap();
    let mut buf = [0u8; 13];
    tunnel.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello-reverse");

    // A second write/read on the same stream still round-trips.
    tunnel.write_all(b"again").await.unwrap();
    let mut buf2 = [0u8; 5];
    tunnel.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"again");

    let _ = std::fs::remove_file(cert);
    let _ = std::fs::remove_file(key);
}

#[tokio::test]
async fn concurrent_reverse_tunnels_do_not_block_each_other() {
    let (manager, edge_addr, cert, key) =
        start_edge(&["placeholder-token"], DuplicatePolicy::Reject);
    let echo = start_echo().await;
    start_hop_and_wait(&manager, &edge_addr, "hop-conc", "placeholder-token").await;
    let (echo_host, echo_port) = echo.rsplit_once(':').unwrap();
    let echo_port: u16 = echo_port.parse().unwrap();

    // Open several tunnels, then interleave: hold the first open while the
    // others complete, proving streams are independent on one QUIC connection.
    let mut tunnels = Vec::new();
    for _ in 0..5 {
        tunnels.push(
            manager
                .open("hop-conc", echo_host, echo_port)
                .await
                .expect("tunnel opens"),
        );
    }
    for (i, tunnel) in tunnels.iter_mut().enumerate() {
        let msg = format!("msg-{i}");
        tunnel.write_all(msg.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; msg.len()];
        tunnel.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, msg.as_bytes());
    }

    let _ = std::fs::remove_file(cert);
    let _ = std::fs::remove_file(key);
}

#[tokio::test]
async fn hop_target_connect_failure_is_isolated_to_one_stream() {
    let (manager, edge_addr, cert, key) =
        start_edge(&["placeholder-token"], DuplicatePolicy::Reject);
    let echo = start_echo().await;
    start_hop_and_wait(&manager, &edge_addr, "hop-iso", "placeholder-token").await;
    let (echo_host, echo_port) = echo.rsplit_once(':').unwrap();
    let echo_port: u16 = echo_port.parse().unwrap();

    // Reserve a port with a listener, capture it, then drop the listener so the
    // port is (almost certainly) closed — the hop's local dial should fail.
    let closed_port = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap().port()
    };

    let err = expect_open_error(manager.open("hop-iso", "127.0.0.1", closed_port).await);
    assert_eq!(err.failure_stage(), "hop_connect");

    // The QUIC connection is intact: a subsequent tunnel to the echo works.
    let mut tunnel = manager
        .open("hop-iso", echo_host, echo_port)
        .await
        .expect("connection still usable after one stream failure");
    tunnel.write_all(b"ok").await.unwrap();
    let mut buf = [0u8; 2];
    tunnel.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ok");

    let _ = std::fs::remove_file(cert);
    let _ = std::fs::remove_file(key);
}

#[tokio::test]
async fn open_without_registered_hop_fails_closed() {
    let (manager, _addr, cert, key) = start_edge(&["placeholder-token"], DuplicatePolicy::Reject);
    let err = expect_open_error(manager.open("nonexistent-hop", "example.com", 443).await);
    assert_eq!(err.failure_stage(), "reverse_lookup");
    let _ = std::fs::remove_file(cert);
    let _ = std::fs::remove_file(key);
}

#[tokio::test]
async fn registration_with_wrong_token_is_rejected() {
    let (manager, edge_addr, cert, key) = start_edge(&["good-token"], DuplicatePolicy::Reject);
    let (_conn, reply) = register_manually(&edge_addr, "hop-bad", "wrong-token").await;
    assert_eq!(reply, Reply::Err(codes::UNAUTHORIZED.to_string()));
    assert!(!manager.is_registered("hop-bad"));
    let _ = std::fs::remove_file(cert);
    let _ = std::fs::remove_file(key);
}

#[tokio::test]
async fn duplicate_hop_id_is_rejected_under_reject_policy() {
    let (manager, edge_addr, cert, key) = start_edge(&["good-token"], DuplicatePolicy::Reject);

    let (_first, first_reply) = register_manually(&edge_addr, "hop-dup", "good-token").await;
    assert_eq!(first_reply, Reply::Ok);
    wait_until(|| manager.is_registered("hop-dup"), Duration::from_secs(5)).await;

    let (_second, second_reply) = register_manually(&edge_addr, "hop-dup", "good-token").await;
    assert_eq!(
        second_reply,
        Reply::Err(codes::DUPLICATE_HOP_ID.to_string())
    );
    // The original session is retained; exactly one remains.
    assert_eq!(manager.session_count(), 1);

    let _ = std::fs::remove_file(cert);
    let _ = std::fs::remove_file(key);
}

#[tokio::test]
async fn replace_policy_swaps_in_the_new_session() {
    let (manager, edge_addr, cert, key) = start_edge(&["good-token"], DuplicatePolicy::Replace);

    let (_first, first_reply) = register_manually(&edge_addr, "hop-rep", "good-token").await;
    assert_eq!(first_reply, Reply::Ok);
    wait_until(|| manager.is_registered("hop-rep"), Duration::from_secs(5)).await;

    let (_second, second_reply) = register_manually(&edge_addr, "hop-rep", "good-token").await;
    assert_eq!(second_reply, Reply::Ok);
    // Still exactly one session for the hop_id (the newcomer replaced the old).
    wait_until(|| manager.session_count() == 1, Duration::from_secs(5)).await;
    assert!(manager.is_registered("hop-rep"));

    let _ = std::fs::remove_file(cert);
    let _ = std::fs::remove_file(key);
}

#[tokio::test]
async fn hop_access_log_records_reverse_decision_without_secrets() {
    let (manager, edge_addr, cert, key) =
        start_edge(&["super-secret-token"], DuplicatePolicy::Reject);
    let echo = start_echo().await;

    // Give the hop a real file-backed access log in a temp dir.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let log_dir = std::env::temp_dir().join(format!("rove-rev-log-{nanos}"));
    std::fs::create_dir_all(&log_dir).unwrap();
    let log_cfg = rove::config::AccessLogConfig {
        dir: log_dir.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let stats = rove::stats::TrafficStats::new();
    let access_log =
        rove::access_log::AccessLogger::spawn(&log_cfg, "hop-test".to_string(), stats.clone())
            .unwrap();

    let config = ReverseHopClientConfig {
        edges: vec![ReverseEdgeConfig {
            edge_addr: edge_addr.clone(),
            server_name: "localhost".to_string(),
            hop_id: "hop-log".to_string(),
            token: "super-secret-token".to_string(),
            edge_id: Some("edge-test".to_string()),
            skip_cert_verify: true,
            max_streams: 64,
            initial_mtu: None,
        }],
        global_max_streams: 0,
        node_id: "hop-test".to_string(),
    };
    rove::reverse::hop::spawn(config, Some(access_log), stats);
    wait_until(|| manager.is_registered("hop-log"), Duration::from_secs(10)).await;

    let (echo_host, echo_port) = echo.rsplit_once(':').unwrap();
    let mut tunnel = manager
        .open("hop-log", echo_host, echo_port.parse().unwrap())
        .await
        .unwrap();
    tunnel.write_all(b"payload").await.unwrap();
    let mut buf = [0u8; 7];
    tunnel.read_exact(&mut buf).await.unwrap();
    // Close the tunnel so the hop finishes the splice and writes its log line.
    drop(tunnel);

    // Read the rotated access-log file(s) and assert on their contents.
    let contents = wait_for_log(&log_dir).await;
    assert!(
        contents.contains("reverse:hop-log"),
        "access log should carry the reverse decision, got: {contents}"
    );
    assert!(
        !contents.contains("super-secret-token"),
        "access log must never contain the registration token"
    );

    let _ = std::fs::remove_file(cert);
    let _ = std::fs::remove_file(key);
    let _ = std::fs::remove_dir_all(log_dir);
}

async fn wait_for_log(dir: &std::path::Path) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Ok(entries) = std::fs::read_dir(dir) {
            let mut all = String::new();
            for entry in entries.flatten() {
                if let Ok(text) = std::fs::read_to_string(entry.path()) {
                    all.push_str(&text);
                }
            }
            if all.contains("reverse:hop-log") {
                return all;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Return whatever we have for a useful assertion message.
    let mut all = String::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(text) = std::fs::read_to_string(entry.path()) {
                all.push_str(&text);
            }
        }
    }
    all
}

// ===========================================================================
// reverse/2 UDP relay (client -> hop -> server), datagram data plane.
// ===========================================================================

/// A loopback UDP echo server: every datagram is sent straight back to its
/// source. Returns the bound `ip:port`.
async fn start_udp_echo() -> String {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
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

fn split_host_port(addr: &str) -> (String, u16) {
    let sa: std::net::SocketAddr = addr.parse().unwrap();
    (sa.ip().to_string(), sa.port())
}

#[tokio::test]
async fn udp_association_relays_through_hop_to_echo() {
    let (manager, edge_addr, _cert, _key) = start_edge(&["udp-token"], DuplicatePolicy::Reject);
    let echo = start_udp_echo().await;
    let (echo_host, echo_port) = split_host_port(&echo);
    start_hop_and_wait(&manager, &edge_addr, "hop-udp", "udp-token").await;

    let relay = manager
        .open_udp("hop-udp")
        .await
        .expect("open udp association");
    relay
        .send_to(b"ping-udp", &echo_host, echo_port)
        .await
        .expect("send_to");

    let (payload, rhost, rport) = tokio::time::timeout(Duration::from_secs(5), relay.recv_from())
        .await
        .expect("recv_from timed out")
        .expect("recv_from failed");
    assert_eq!(payload, b"ping-udp");
    // The reply is admitted only because its source is the address we sent to
    // (address-restricted filtering), and it is reported back verbatim.
    assert_eq!(rhost, echo_host);
    assert_eq!(rport, echo_port);
}

#[tokio::test]
async fn udp_open_fails_closed_for_hop_without_udp_cap() {
    let (manager, edge_addr, _cert, _key) = start_edge(&["nocap-token"], DuplicatePolicy::Reject);
    // register_manually advertises no capabilities (caps: vec![]), so the edge
    // records the hop as TCP-only and must refuse UDP association fail-closed.
    let (_conn, reply) = register_manually(&edge_addr, "hop-nocap", "nocap-token").await;
    assert_eq!(reply, Reply::Ok);
    wait_until(
        || manager.is_registered("hop-nocap"),
        Duration::from_secs(5),
    )
    .await;

    let err = match manager.open_udp("hop-nocap").await {
        Ok(_) => panic!("open_udp unexpectedly succeeded for a TCP-only hop"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("does not advertise udp"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn udp_open_fails_closed_without_reverse_plane() {
    // connect_udp must never fall back to direct when no reverse manager exists.
    use rove::model::{Decision, Upstream, UpstreamKind};
    let decision = Decision::Via(Upstream {
        kind: UpstreamKind::Reverse,
        addr: "hop-x".to_string(),
        tls: false,
        skip_cert_verify: false,
        username: None,
        password: None,
    });
    let err = rove::outbound::connect_udp(decision, &rove::outbound::EgressContext::default())
        .await
        .err()
        .expect("must fail closed");
    assert!(err
        .to_string()
        .contains("reverse data plane is not enabled"));
}

// ---------------------------------------------------------------------------
// Failover chains across the reverse data plane (issue #17)
// ---------------------------------------------------------------------------

fn chain_decision(
    members: Vec<(&str, u32, rove::model::UpstreamKind, String)>,
) -> rove::model::Decision {
    use rove::model::{Chain, ChainMember, Decision, Upstream};
    let mut members: Vec<ChainMember> = members
        .into_iter()
        .map(|(id, priority, kind, addr)| ChainMember {
            id: id.to_string(),
            priority,
            upstream: Upstream {
                kind,
                addr,
                username: None,
                password: None,
                tls: false,
                skip_cert_verify: false,
            },
        })
        .collect();
    members.sort_by_key(|m| m.priority);
    Decision::ViaChain(Arc::new(Chain {
        id: "jp-pop".to_string(),
        members,
    }))
}

/// Acceptance: a dead address-type primary fails over to a *real* reverse-hop
/// backup member during establishment, and the tunnel carries bytes.
#[tokio::test]
async fn chain_dead_address_primary_fails_over_to_reverse_member() {
    use rove::model::UpstreamKind;
    let (manager, edge_addr, cert, key) = start_edge(&["chain-token"], DuplicatePolicy::Reject);
    let echo = start_echo().await;
    start_hop_and_wait(&manager, &edge_addr, "hop-chain", "chain-token").await;

    // A dead HTTP upstream: bind + drop => connection refused.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        a.to_string()
    };
    let decision = chain_decision(vec![
        ("jp-http-1", 1, UpstreamKind::Http, dead),
        (
            "jp-reverse-2",
            2,
            UpstreamKind::Reverse,
            "hop-chain".to_string(),
        ),
    ]);

    let (echo_host, echo_port) = split_host_port(&echo);
    let egress_context = rove::outbound::EgressContext::new(Some(manager.clone()), None);
    let (mut tunnel, egress) =
        rove::outbound::connect(decision, &echo_host, echo_port, &egress_context)
            .await
            .expect("failover to the reverse member must succeed");
    assert_eq!(egress.chain_id.as_deref(), Some("jp-pop"));
    assert_eq!(egress.member_id.as_deref(), Some("jp-reverse-2"));
    assert_eq!(egress.attempts, 2);
    assert_eq!(egress.label, "reverse:hop-chain");

    tunnel.write_all(b"chain-over-reverse").await.unwrap();
    let mut buf = [0u8; 18];
    tunnel.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"chain-over-reverse");

    let _ = std::fs::remove_file(cert);
    let _ = std::fs::remove_file(key);
}

/// Acceptance: a mixed chain's UDP association skips the non-UDP-capable
/// socks5 primary, lands on the reverse member, and stays pinned to it.
#[tokio::test]
async fn chain_udp_association_uses_reverse_member_and_sticks() {
    use rove::model::UpstreamKind;
    let (manager, edge_addr, _cert, _key) =
        start_edge(&["chain-udp-token"], DuplicatePolicy::Reject);
    let echo = start_udp_echo().await;
    let (echo_host, echo_port) = split_host_port(&echo);
    start_hop_and_wait(&manager, &edge_addr, "hop-chain-udp", "chain-udp-token").await;

    let decision = chain_decision(vec![
        (
            "jp-socks-1",
            1,
            UpstreamKind::Socks5,
            "10.255.255.1:1080".to_string(),
        ),
        (
            "jp-reverse-2",
            2,
            UpstreamKind::Reverse,
            "hop-chain-udp".to_string(),
        ),
    ]);
    let egress_context = rove::outbound::EgressContext::new(Some(manager.clone()), None);
    let (relay, egress) = rove::outbound::connect_udp(decision, &egress_context)
        .await
        .expect("udp association must land on the reverse member");
    // Only the reverse member is UDP-eligible: exactly one attempt was made,
    // never a misuse of the socks5 primary.
    assert_eq!(egress.member_id.as_deref(), Some("jp-reverse-2"));
    assert_eq!(egress.attempts, 1);

    relay
        .send_to(b"chain-udp", &echo_host, echo_port)
        .await
        .expect("send_to");
    let (payload, _, _) = tokio::time::timeout(Duration::from_secs(5), relay.recv_from())
        .await
        .expect("recv_from timed out")
        .expect("recv_from failed");
    assert_eq!(payload, b"chain-udp");
}
