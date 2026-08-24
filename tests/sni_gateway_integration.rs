#![cfg(unix)]

mod common;

use rove::engine::Engine;
use rove::inbound::listener;
use rove::model::{
    RawAction, RawEgress, RawRoute, RawRoutingPolicy, RawSnapshot, RawUpstream, RawUser, Snapshot,
};
use rove::util::read_http_head;
use rustls::pki_types::ServerName;
use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

#[derive(Clone, Copy)]
enum GatewayEgress {
    Http,
    Socks5,
    Direct,
    Block,
}

const RATE_LIMIT_BYTES_PER_SEC: u64 = 16 * 1024;
const RATE_LIMIT_TEST_BYTES: usize = 48 * 1024;

#[tokio::test]
async fn sni_gateway_transparently_tunnels_allowed_sni_through_selected_egress() {
    rove::tls::init_crypto();
    let (upstream_addr, target_rx, upstream_task) = start_tls_connect_upstream().await;
    let engine = engine_for_gateway(&upstream_addr, "alice", false, GatewayEgress::Http);
    let (port, gateway_task) = spawn_gateway(engine, "alice", vec!["LOCALHOST.".to_string()]);

    let tcp = connect_with_retry(port).await;
    let connector = rove::tls::insecure_client_connector();
    let name = ServerName::try_from("localhost").unwrap().to_owned();
    let mut client = connector
        .connect(name, tcp)
        .await
        .expect("TLS handshake through gateway");

    client.write_all(b"gateway-ping").await.unwrap();
    let mut echoed = [0u8; 12];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"gateway-ping");
    client.shutdown().await.unwrap();

    assert_eq!(target_rx.await.unwrap(), format!("localhost:{port}"));
    upstream_task.await.unwrap();
    gateway_task.abort();
}

#[tokio::test]
async fn sni_gateway_transparently_tunnels_allowed_sni_through_socks5_egress() {
    rove::tls::init_crypto();
    let (upstream_addr, target_rx, upstream_task) = start_tls_socks5_upstream().await;
    let engine = engine_for_gateway(&upstream_addr, "alice", false, GatewayEgress::Socks5);
    let (port, gateway_task) = spawn_gateway(engine, "alice", vec!["localhost".to_string()]);

    let tcp = connect_with_retry(port).await;
    let connector = rove::tls::insecure_client_connector();
    let name = ServerName::try_from("localhost").unwrap().to_owned();
    let mut client = connector
        .connect(name, tcp)
        .await
        .expect("TLS handshake through SOCKS5 egress");

    client.write_all(b"socks-ping").await.unwrap();
    let mut echoed = [0u8; 10];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"socks-ping");
    client.shutdown().await.unwrap();

    assert_eq!(target_rx.await.unwrap(), format!("localhost:{port}"));
    upstream_task.await.unwrap();
    gateway_task.abort();
}

#[tokio::test]
async fn sni_gateway_rejects_unlisted_sni_and_non_tls_before_dialing_egress() {
    rove::tls::init_crypto();
    let (upstream_addr, mut dial_rx) = start_dial_observer().await;
    let engine = engine_for_gateway(&upstream_addr, "alice", false, GatewayEgress::Http);
    let (port, gateway_task) = spawn_gateway(engine, "alice", vec!["localhost".to_string()]);

    let tcp = connect_with_retry(port).await;
    let connector = rove::tls::insecure_client_connector();
    let name = ServerName::try_from("unlisted.example").unwrap().to_owned();
    assert!(
        connector.connect(name, tcp).await.is_err(),
        "unlisted SNI must close"
    );

    let mut malformed = connect_with_retry(port).await;
    malformed.write_all(b"not a TLS ClientHello").await.unwrap();
    malformed.shutdown().await.unwrap();
    let mut response = [0u8; 1];
    assert_eq!(malformed.read(&mut response).await.unwrap(), 0);

    let tcp = connect_with_retry(port).await;
    let no_sni_name = ServerName::try_from("127.0.0.1").unwrap().to_owned();
    assert!(
        connector.connect(no_sni_name, tcp).await.is_err(),
        "a TLS ClientHello without SNI must close"
    );

    assert!(
        tokio::time::timeout(Duration::from_millis(250), &mut dial_rx)
            .await
            .is_err(),
        "rejected SNI or malformed traffic must not reach any egress"
    );
    gateway_task.abort();
}

#[tokio::test]
async fn sni_gateway_rejects_unknown_or_expired_bound_identity_before_dialing() {
    rove::tls::init_crypto();
    let (upstream_addr, mut dial_rx) = start_dial_observer().await;
    let engine = engine_for_gateway(&upstream_addr, "alice", true, GatewayEgress::Http);
    let (port, gateway_task) = spawn_gateway(engine, "alice", vec!["localhost".to_string()]);

    let tcp = connect_with_retry(port).await;
    let connector = rove::tls::insecure_client_connector();
    let name = ServerName::try_from("localhost").unwrap().to_owned();
    assert!(
        connector.connect(name, tcp).await.is_err(),
        "expired identity must close"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(250), &mut dial_rx)
            .await
            .is_err(),
        "an expired bound identity must not reach any egress"
    );
    gateway_task.abort();

    let unknown_engine =
        engine_for_gateway(&upstream_addr, "another-user", false, GatewayEgress::Http);
    let (unknown_port, unknown_gateway_task) =
        spawn_gateway(unknown_engine, "alice", vec!["localhost".to_string()]);
    let tcp = connect_with_retry(unknown_port).await;
    let name = ServerName::try_from("localhost").unwrap().to_owned();
    assert!(
        connector.connect(name, tcp).await.is_err(),
        "an identity missing from the snapshot must close"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(250), &mut dial_rx)
            .await
            .is_err(),
        "an unknown bound identity must not reach any egress"
    );
    unknown_gateway_task.abort();
}

#[tokio::test]
async fn sni_gateway_honors_a_block_policy_before_dialing_egress() {
    rove::tls::init_crypto();
    let (upstream_addr, mut dial_rx) = start_dial_observer().await;
    let engine = engine_for_gateway(&upstream_addr, "alice", false, GatewayEgress::Block);
    let (port, gateway_task) = spawn_gateway(engine, "alice", vec!["localhost".to_string()]);

    let tcp = connect_with_retry(port).await;
    let connector = rove::tls::insecure_client_connector();
    let name = ServerName::try_from("localhost").unwrap().to_owned();
    assert!(
        connector.connect(name, tcp).await.is_err(),
        "block policy must close"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(250), &mut dial_rx)
            .await
            .is_err(),
        "a block decision must not be followed by an egress dial"
    );
    gateway_task.abort();
}

#[tokio::test]
async fn sni_gateway_releases_a_connection_limit_after_the_tunnel_closes() {
    rove::tls::init_crypto();
    let (upstream_addr, first_ready, upstream_task) = start_two_tls_connect_upstream().await;
    let engine = engine_for_gateway_with_limits(
        &upstream_addr,
        "alice",
        false,
        GatewayEgress::Http,
        0,
        0,
        1,
    );
    let (port, gateway_task) = spawn_gateway(engine, "alice", vec!["localhost".to_string()]);
    let connector = rove::tls::insecure_client_connector();
    let name = ServerName::try_from("localhost").unwrap().to_owned();

    let first_tcp = connect_with_retry(port).await;
    let mut first = connector
        .connect(name.clone(), first_tcp)
        .await
        .expect("first TLS tunnel");
    first_ready.await.unwrap();

    let second_tcp = connect_with_retry(port).await;
    assert!(
        connector.connect(name.clone(), second_tcp).await.is_err(),
        "a second tunnel must be rejected while the bound identity is at its limit"
    );

    first.shutdown().await.unwrap();
    drop(first);

    let mut third = None;
    for _ in 0..100 {
        let tcp = connect_with_retry(port).await;
        if let Ok(client) = connector.connect(name.clone(), tcp).await {
            third = Some(client);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut third =
        third.expect("connection permit must be released after the first tunnel closes");
    third.write_all(b"limit").await.unwrap();
    let mut echoed = [0u8; 5];
    third.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"limit");
    third.shutdown().await.unwrap();

    upstream_task.await.unwrap();
    gateway_task.abort();
}

#[tokio::test]
async fn sni_gateway_applies_the_bound_identity_down_rate() {
    rove::tls::init_crypto();
    let (upstream_addr, upstream_task) =
        start_tls_sending_connect_upstream(RATE_LIMIT_TEST_BYTES).await;
    let engine = engine_for_gateway_with_limits(
        &upstream_addr,
        "alice",
        false,
        GatewayEgress::Http,
        0,
        RATE_LIMIT_BYTES_PER_SEC,
        4,
    );
    let (port, gateway_task) = spawn_gateway(engine, "alice", vec!["localhost".to_string()]);

    let tcp = connect_with_retry(port).await;
    let connector = rove::tls::insecure_client_connector();
    let name = ServerName::try_from("localhost").unwrap().to_owned();
    let mut client = connector.connect(name, tcp).await.expect("TLS tunnel");

    let started = Instant::now();
    let mut received = vec![0u8; RATE_LIMIT_TEST_BYTES];
    client.read_exact(&mut received).await.unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1400),
        "SNI down_rate completed too quickly: {elapsed:?}"
    );
    assert_eq!(received, vec![b'x'; RATE_LIMIT_TEST_BYTES]);
    client.shutdown().await.unwrap();

    upstream_task.await.unwrap();
    gateway_task.abort();
}

#[tokio::test]
async fn sni_gateway_transparently_tunnels_direct_egress_on_the_listener_port() {
    rove::tls::init_crypto();
    let Some((gateway_addr, origin_task)) = start_direct_tls_origin().await else {
        // A single-stack host cannot run a gateway and its direct origin on
        // separate local addresses sharing one port. Other environments still
        // exercise this invariant without depending on a fixed hosts ordering.
        eprintln!("skipping direct listener-port test: localhost is single-stack");
        return;
    };
    let port = gateway_addr.port();
    let engine = engine_for_gateway("127.0.0.1:9", "alice", false, GatewayEgress::Direct);
    let gateway_task = spawn_gateway_at(
        engine,
        "alice",
        vec!["localhost".to_string()],
        &gateway_addr.ip().to_string(),
        port,
    );

    let tcp = connect_with_retry_at(&gateway_addr.ip().to_string(), port).await;
    let connector = rove::tls::insecure_client_connector();
    let name = ServerName::try_from("localhost").unwrap().to_owned();
    let mut client = connector
        .connect(name, tcp)
        .await
        .expect("direct TLS handshake");
    client.write_all(b"direct-ping").await.unwrap();
    let mut echoed = [0u8; 11];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"direct-ping");
    client.shutdown().await.unwrap();

    origin_task.await.unwrap();
    gateway_task.abort();
}

fn engine_for_gateway(
    upstream_addr: &str,
    username: &str,
    expired: bool,
    route: GatewayEgress,
) -> Arc<Engine> {
    engine_for_gateway_with_limits(upstream_addr, username, expired, route, 0, 0, 4)
}

fn engine_for_gateway_with_limits(
    upstream_addr: &str,
    username: &str,
    expired: bool,
    route: GatewayEgress,
    up_rate: u64,
    down_rate: u64,
    max_connections: usize,
) -> Arc<Engine> {
    let engine = Engine::new();
    let raw = RawSnapshot {
        version: 1,
        users: HashMap::from([(
            username.to_string(),
            RawUser {
                password: "not-used-by-sni".to_string(),
                expire: expired.then(|| "2000-01-01".to_string()),
                up_rate,
                down_rate,
                max_connections,
                policy: "egress-policy".to_string(),
                frontends: HashMap::new(),
            },
        )]),
        routing_policies: HashMap::from([(
            "egress-policy".to_string(),
            RawRoutingPolicy {
                routes: vec![RawRoute {
                    selectors: vec!["full:localhost".to_string()],
                    action: match route {
                        GatewayEgress::Block => RawAction::Block,
                        GatewayEgress::Direct => RawAction::Direct,
                        GatewayEgress::Http | GatewayEgress::Socks5 => RawAction::Egress {
                            egress: "test-upstream".to_string(),
                        },
                    },
                }],
                default_action: Some(RawAction::Block),
            },
        )]),
        egresses: HashMap::from([(
            "test-upstream".to_string(),
            RawEgress::Upstream {
                backend: RawUpstream {
                    kind: match route {
                        GatewayEgress::Socks5 => "socks5",
                        GatewayEgress::Http | GatewayEgress::Direct | GatewayEgress::Block => {
                            "http"
                        }
                    }
                    .to_string(),
                    addr: upstream_addr.to_string(),
                    username: None,
                    password: None,
                    tls: false,
                    skip_cert_verify: false,
                },
            },
        )]),
        ..RawSnapshot::default()
    };
    engine.replace(Snapshot::compile(raw, "gateway-it").unwrap());
    engine
}

fn spawn_gateway(
    engine: Arc<Engine>,
    identity: &str,
    origins: Vec<String>,
) -> (u16, JoinHandle<anyhow::Result<()>>) {
    let port = free_port();
    let task = spawn_gateway_at(engine, identity, origins, "127.0.0.1", port);
    (port, task)
}

fn spawn_gateway_at(
    engine: Arc<Engine>,
    identity: &str,
    origins: Vec<String>,
    listen_host: &str,
    port: u16,
) -> JoinHandle<anyhow::Result<()>> {
    let cfg = rove::config::Listener {
        name: "sni-gateway-it".to_string(),
        protocol: "sni".to_string(),
        listen: listen_address(listen_host, port),
        tls: None,
        sniff: rove::config::SniffConfig::default(),
        identity: Some(identity.to_string()),
        origins,
    };
    tokio::spawn(listener::run(
        cfg,
        engine,
        None,
        None,
        None,
        rove::stats::TrafficStats::new(),
        rove::outbound::EgressContext::default(),
    ))
}

fn listen_address(host: &str, port: u16) -> String {
    host.parse::<std::net::IpAddr>()
        .map(|ip| SocketAddr::new(ip, port).to_string())
        .unwrap_or_else(|_| format!("{host}:{port}"))
}

async fn start_tls_connect_upstream() -> (String, oneshot::Receiver<String>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let acceptor = test_tls_acceptor();
    let (target_tx, target_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let head = String::from_utf8(read_http_head(&mut socket, 8192).await.unwrap()).unwrap();
        let target = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .expect("CONNECT authority")
            .to_string();
        target_tx.send(target).unwrap();
        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();

        let mut tls = acceptor.accept(socket).await.unwrap();
        let mut payload = [0u8; 12];
        tls.read_exact(&mut payload).await.unwrap();
        tls.write_all(&payload).await.unwrap();
        tls.shutdown().await.unwrap();
    });
    (address, target_rx, task)
}

async fn start_tls_socks5_upstream() -> (String, oneshot::Receiver<String>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let acceptor = test_tls_acceptor();
    let (target_tx, target_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut greeting = [0u8; 3];
        socket.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [0x05, 0x01, 0x00]);
        socket.write_all(&[0x05, 0x00]).await.unwrap();

        let mut request = [0u8; 5];
        socket.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[..4], &[0x05, 0x01, 0x00, 0x03]);
        let mut host = vec![0u8; request[4] as usize];
        socket.read_exact(&mut host).await.unwrap();
        let mut port = [0u8; 2];
        socket.read_exact(&mut port).await.unwrap();
        target_tx
            .send(format!(
                "{}:{}",
                String::from_utf8(host).unwrap(),
                u16::from_be_bytes(port)
            ))
            .unwrap();
        socket
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();

        let mut tls = acceptor.accept(socket).await.unwrap();
        let mut payload = [0u8; 10];
        tls.read_exact(&mut payload).await.unwrap();
        tls.write_all(&payload).await.unwrap();
        tls.shutdown().await.unwrap();
    });
    (address, target_rx, task)
}

async fn start_two_tls_connect_upstream() -> (String, oneshot::Receiver<()>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let acceptor = test_tls_acceptor();
    let (first_ready_tx, first_ready_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut first_ready_tx = Some(first_ready_tx);
        for attempt in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let head = String::from_utf8(read_http_head(&mut socket, 8192).await.unwrap()).unwrap();
            assert!(head.starts_with("CONNECT localhost:"));
            socket
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let mut tls = acceptor.accept(socket).await.unwrap();
            if attempt == 0 {
                first_ready_tx.take().unwrap().send(()).unwrap();
                let mut one = [0u8; 1];
                let _ = tls.read(&mut one).await.unwrap();
            } else {
                let mut payload = [0u8; 5];
                tls.read_exact(&mut payload).await.unwrap();
                tls.write_all(&payload).await.unwrap();
            }
            tls.shutdown().await.unwrap();
        }
    });
    (address, first_ready_rx, task)
}

async fn start_tls_sending_connect_upstream(bytes: usize) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let acceptor = test_tls_acceptor();
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let head = String::from_utf8(read_http_head(&mut socket, 8192).await.unwrap()).unwrap();
        assert!(head.starts_with("CONNECT localhost:"));
        socket
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let mut tls = acceptor.accept(socket).await.unwrap();
        tls.write_all(&vec![b'x'; bytes]).await.unwrap();
        tls.shutdown().await.unwrap();
    });
    (address, task)
}

async fn start_dial_observer() -> (String, oneshot::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let (dial_tx, dial_rx) = oneshot::channel();
    tokio::spawn(async move {
        if listener.accept().await.is_ok() {
            let _ = dial_tx.send(());
        }
    });
    (address, dial_rx)
}

async fn start_direct_tls_origin() -> Option<(SocketAddr, JoinHandle<()>)> {
    // Use the first address returned by the same system resolver Rove uses for
    // direct egress as the origin, and bind the gateway to a different local
    // address on that port. This proves the listener-port behavior without
    // assuming `localhost` prefers IPv6 or IPv4 on a particular CI host.
    let mut localhost = tokio::net::lookup_host(("localhost", 0)).await.ok()?;
    let origin_ip = localhost.next()?.ip();
    let gateway_ip = localhost
        .map(|address| address.ip())
        .find(|ip| *ip != origin_ip)?;
    let listener = TcpListener::bind(SocketAddr::new(origin_ip, 0))
        .await
        .ok()?;
    let gateway_addr = SocketAddr::new(gateway_ip, listener.local_addr().ok()?.port());
    let acceptor = test_tls_acceptor();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(socket).await.unwrap();
        let mut payload = [0u8; 11];
        tls.read_exact(&mut payload).await.unwrap();
        tls.write_all(&payload).await.unwrap();
        tls.shutdown().await.unwrap();
    });
    Some((gateway_addr, task))
}

fn test_tls_acceptor() -> tokio_rustls::TlsAcceptor {
    let suffix = format!("{}-{}", std::process::id(), unix_nanos());
    let cert = std::env::temp_dir().join(format!("rove-sni-gateway-{suffix}.crt"));
    let key = std::env::temp_dir().join(format!("rove-sni-gateway-{suffix}.key"));
    std::fs::write(&cert, common::TEST_CERT).unwrap();
    std::fs::write(&key, common::TEST_KEY).unwrap();
    let acceptor =
        rove::tls::server_acceptor(cert.to_str().unwrap(), key.to_str().unwrap()).unwrap();
    let _ = std::fs::remove_file(cert);
    let _ = std::fs::remove_file(key);
    acceptor
}

fn free_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn connect_with_retry(port: u16) -> TcpStream {
    connect_with_retry_at("127.0.0.1", port).await
}

async fn connect_with_retry_at(host: &str, port: u16) -> TcpStream {
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect((host, port)).await {
            return stream;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("gateway listener did not bind on {host}:{port}");
}

fn unix_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
