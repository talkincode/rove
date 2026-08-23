//! End-to-end SOCKS5 UDP ASSOCIATE integration test: a raw SOCKS5 client
//! authenticates, requests UDP ASSOCIATE, and relays a UDP datagram through a
//! real reverse hop to a UDP echo server, proving the client -> socks5 ->
//! connect_udp -> reverse edge -> hop -> echo -> client chain.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rove::engine::Engine;
use rove::inbound::{socks5, Ctx};
use rove::model::{RawGroup, RawSnapshot, RawUpstream, RawUser, Snapshot};
use rove::reverse::edge::{DuplicatePolicy, ReverseHopManager, ReverseListenerConfig};
use rove::reverse::hop::{ReverseEdgeConfig, ReverseHopClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

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
    let cert = dir.join(format!("rove-s5udp-it-{nanos}.crt"));
    let key = dir.join(format!("rove-s5udp-it-{nanos}.key"));
    std::fs::write(&cert, TEST_CERT).unwrap();
    std::fs::write(&key, TEST_KEY).unwrap();
    (
        cert.to_string_lossy().into_owned(),
        key.to_string_lossy().into_owned(),
    )
}

fn v4_bytes(addr: &str) -> ([u8; 4], u16) {
    match addr.parse::<SocketAddr>().unwrap() {
        SocketAddr::V4(v4) => (v4.ip().octets(), v4.port()),
        _ => panic!("expected v4"),
    }
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

/// Engine with a user (`alice`/`secret`) whose group routes every target to the
/// given reverse hop, so UDP egress goes through reverse/2.
fn engine_via_hop(hop_id: &str) -> Arc<Engine> {
    rove::tls::init_crypto();
    let mut groups = HashMap::new();
    groups.insert(
        "g".to_string(),
        RawGroup {
            upstream: None,
            default_upstream: Some(RawUpstream {
                kind: "reverse".to_string(),
                addr: hop_id.to_string(),
                username: None,
                password: None,
                tls: false,
                skip_cert_verify: false,
            }),
            proxy: vec![],
            block: vec![],
        },
    );
    let mut users = HashMap::new();
    users.insert(
        "alice".to_string(),
        RawUser {
            password: "secret".to_string(),
            expire: None,
            up_rate: 0,
            down_rate: 0,
            max_connections: 0,
            group: "g".to_string(),
            frontends: Default::default(),
        },
    );
    let raw = RawSnapshot {
        version: 1,
        users,
        groups,
        ..Default::default()
    };
    let snap = Snapshot::compile(raw, "node").expect("compile");
    let engine = Engine::new();
    engine.replace(snap);
    engine
}

/// Start a one-shot SOCKS5 server bound to an ephemeral loopback port.
async fn start_socks5(engine: Arc<Engine>, reverse: Arc<ReverseHopManager>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ctx = Arc::new(Ctx {
        engine,
        listener: "s5udp-test".to_string(),
        sniff: rove::config::SniffConfig::default(),
        tracer: None,
        diagnostics: None,
        access_log: None,
        stats: rove::stats::TrafficStats::new(),
        egress: rove::outbound::EgressContext::new(Some(reverse), None),
    });
    tokio::spawn(async move {
        if let Ok((server, peer)) = listener.accept().await {
            let local = server.local_addr().ok();
            let _ = socks5::serve(server, ctx, peer, local).await;
        }
    });
    addr
}

async fn socks5_auth(c: &mut TcpStream) {
    // method negotiation: offer user/pass (0x02)
    c.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
    let mut m = [0u8; 2];
    c.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [0x05, 0x02]);
    // RFC 1929 user/pass
    let (user, pass) = (b"alice", b"secret");
    let mut auth = vec![0x01, user.len() as u8];
    auth.extend_from_slice(user);
    auth.push(pass.len() as u8);
    auth.extend_from_slice(pass);
    c.write_all(&auth).await.unwrap();
    let mut ar = [0u8; 2];
    c.read_exact(&mut ar).await.unwrap();
    assert_eq!(ar, [0x01, 0x00]);
}

#[tokio::test]
async fn socks5_udp_associate_relays_through_hop_to_echo() {
    let (manager, edge_addr) = start_edge();
    let echo = start_udp_echo().await;
    start_hop_and_wait(&manager, &edge_addr, "hop-s5udp", "tok").await;
    let engine = engine_via_hop("hop-s5udp");
    let addr = start_socks5(engine, manager).await;

    // --- SOCKS5 control connection: auth + UDP ASSOCIATE ---
    let mut c = TcpStream::connect(addr).await.unwrap();
    socks5_auth(&mut c).await;
    // UDP ASSOCIATE: VER CMD=0x03 RSV ATYP=v4 0.0.0.0:0
    c.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0x00, "ASSOCIATE must succeed");
    assert_eq!(rep[3], 0x01, "BND must be v4");
    let bnd = SocketAddr::from((
        Ipv4Addr::new(rep[4], rep[5], rep[6], rep[7]),
        u16::from_be_bytes([rep[8], rep[9]]),
    ));

    // --- client UDP: send an encapsulated datagram to the echo via BND ---
    let cudp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (eip, eport) = v4_bytes(&echo);
    let payload = b"s5-udp-hi";
    let mut dg = vec![0x00, 0x00, 0x00, 0x01]; // RSV(2), FRAG=0, ATYP v4
    dg.extend_from_slice(&eip);
    dg.extend_from_slice(&eport.to_be_bytes());
    dg.extend_from_slice(payload);
    cudp.send_to(&dg, bnd).await.unwrap();

    let mut rbuf = vec![0u8; 65535];
    let (n, _from) = tokio::time::timeout(Duration::from_secs(5), cudp.recv_from(&mut rbuf))
        .await
        .expect("udp return timed out")
        .expect("recv_from");
    // The return datagram carries the SOCKS5 UDP header + the echoed payload.
    assert_eq!(rbuf[0], 0x00); // RSV
    assert_eq!(rbuf[2], 0x00); // FRAG
    assert!(
        rbuf[..n].windows(payload.len()).any(|w| w == payload),
        "return datagram must carry the echoed payload"
    );

    drop(c); // closing the control connection tears down the association
}
