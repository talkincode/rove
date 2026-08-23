//! HTTP-over-Subnetra end to end through the real service layer.
//!
//! Proves the headline capability: a NAT'd spoke reaches Rove's HTTP proxy "over
//! the tunnel". Wiring:
//!
//! ```text
//! test client ──overlay TCP──▶ subnetra hub (Rove http::serve) ──direct TCP──▶ echo server
//! ```
//!
//! The hub is started exactly as `main.rs` starts it (`subnetra::service::start`
//! with a real `Engine`); the spoke side uses the public data-plane + netstack to
//! dial the hub's overlay proxy port and speak HTTP CONNECT.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use base64::Engine as _;
use rove::engine::Engine;
use rove::model::{RawGroup, RawSnapshot, RawUser, Snapshot};
use rove::subnetra::config::{PeerConfig, SubnetraConfig};
use rove::subnetra::{netstack, reactor, service};
use rove::util::read_http_head;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const EPOCH: u64 = 1_704_067_200_000_000_000;
const USERNAME: &str = "alice";
const PASSWORD: &str = "secret";

/// Permissive engine: user alice/secret in a group that egresses direct.
fn permissive_engine() -> Arc<Engine> {
    let mut users = HashMap::new();
    users.insert(
        USERNAME.to_string(),
        RawUser {
            password: PASSWORD.to_string(),
            expire: None,
            up_rate: 0,
            down_rate: 0,
            max_connections: 0,
            group: "default".to_string(),
            frontends: Default::default(),
        },
    );
    let mut groups = HashMap::new();
    groups.insert(
        "default".to_string(),
        RawGroup {
            upstream: None,
            default_upstream: None,
            proxy: Vec::new(),
            block: Vec::new(),
        },
    );
    let engine = Engine::new();
    let snapshot = Snapshot::compile(
        RawSnapshot {
            version: 1,
            users,
            groups,
            ..Default::default()
        },
        "hub-node",
    )
    .unwrap();
    engine.replace(snapshot);
    engine
}

async fn start_echo_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if socket.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, task)
}

#[tokio::test]
async fn http_connect_is_proxied_over_the_subnetra_overlay() {
    // A real target the hub will reach directly.
    let (echo_addr, _echo) = start_echo_server().await;

    // Start the hub exactly like main.rs would.
    let hub_cfg = SubnetraConfig {
        enable: true,
        mode: "hub".into(),
        local_id: 1,
        listen: "127.0.0.1:0".into(),
        overlay_cidr: "10.0.0.1/24".into(),
        obfuscate: true,
        keepalive_secs: 25,
        mtu: None,
        proxy_protocol: "http".into(),
        proxy_port: 8080,
        peers: vec![PeerConfig {
            id: 2,
            psk: "5a".repeat(32),
            allowed_src: "10.0.0.2/32".into(),
            endpoint: None,
            name: "spoke".into(),
        }],
    };
    let (_hub_egress, hub_udp) = service::start(
        &hub_cfg,
        permissive_engine(),
        rove::stats::TrafficStats::new(),
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();

    // Spoke side: data plane + egress-only netstack dialing the hub's overlay IP.
    let spoke_cfg = SubnetraConfig {
        enable: true,
        mode: "spoke".into(),
        local_id: 2,
        listen: "127.0.0.1:0".into(),
        overlay_cidr: "10.0.0.2/24".into(),
        obfuscate: true,
        keepalive_secs: 25,
        mtu: None,
        proxy_protocol: String::new(),
        proxy_port: 0,
        peers: vec![PeerConfig {
            id: 1,
            psk: "5a".repeat(32),
            allowed_src: "10.0.0.0/24".into(),
            endpoint: Some(hub_udp.to_string()),
            name: "hub".into(),
        }],
    }
    .to_runtime()
    .unwrap();
    let (dp, inbound) = reactor::spawn(spoke_cfg, EPOCH).await.unwrap();
    let (spoke_net, _accept) = netstack::spawn(
        dp,
        inbound,
        "10.0.0.2".parse::<Ipv4Addr>().unwrap(),
        24,
        None,
        rove::subnetra::INNER_MTU,
    );

    // Dial the hub's overlay proxy port (10.0.0.1:8080).
    let mut client = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        spoke_net.connect("10.0.0.1".parse().unwrap(), 8080),
    )
    .await
    .expect("overlay connect timed out")
    .expect("overlay connect failed");

    // Speak HTTP CONNECT to the echo server, authenticating as alice.
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{PASSWORD}"));
    let request = format!(
        "CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\nProxy-Authorization: Basic {token}\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();

    let head = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_http_head(&mut client, 8192),
    )
    .await
    .expect("proxy response timed out")
    .unwrap();
    assert!(
        String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"),
        "proxy CONNECT failed: {}",
        String::from_utf8_lossy(&head)
    );

    // Tunnel bytes through: client -> overlay -> hub -> direct -> echo -> back.
    client.write_all(b"subnetra carries http").await.unwrap();
    let mut echoed = vec![0u8; 21];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.read_exact(&mut echoed),
    )
    .await
    .expect("echo read timed out")
    .unwrap();
    assert_eq!(&echoed, b"subnetra carries http");
}
