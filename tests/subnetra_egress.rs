//! Spoke egress: a policy decision of `kind = "subnetra"` dials the target over
//! the overlay. Proves the outbound wiring end to end:
//!
//! ```text
//! outbound::connect(Via(Subnetra)) ─▶ explicit egress context ─▶ overlay ─▶ target service
//! ```
//!
//! The "target" is a raw overlay TCP echo server (standing in for a service in an
//! isolated network reachable only through the mesh). The spoke is brought up via
//! `service::start`, whose returned handle is installed in the egress context.

use std::net::Ipv4Addr;

use rove::model::{Decision, Upstream, UpstreamKind};
use rove::subnetra::config::{PeerConfig, SubnetraConfig};
use rove::subnetra::{netstack, reactor, service};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const EPOCH: u64 = 1_704_067_200_000_000_000;

/// Bring up a raw overlay TCP echo server on `10.0.0.1:port` (the "isolated
/// service"). Returns the data plane's bound UDP address.
async fn spawn_overlay_echo(port: u16) -> std::net::SocketAddr {
    let cfg = SubnetraConfig {
        enable: true,
        mode: "hub".into(),
        local_id: 1,
        listen: "127.0.0.1:0".into(),
        overlay_cidr: "10.0.0.1/24".into(),
        obfuscate: true,
        keepalive_secs: 25,
        mtu: None,
        proxy_protocol: "http".into(),
        proxy_port: port,
        peers: vec![PeerConfig {
            id: 2,
            psk: "5a".repeat(32),
            allowed_src: "10.0.0.2/32".into(),
            endpoint: None,
            name: "spoke".into(),
        }],
    }
    .to_runtime()
    .unwrap();

    let (dp, inbound) = reactor::spawn(cfg, EPOCH).await.unwrap();
    let udp = dp.local_addr();
    let (_net, mut accept_rx) = netstack::spawn(
        dp,
        inbound,
        "10.0.0.1".parse::<Ipv4Addr>().unwrap(),
        24,
        Some(port),
        rove::subnetra::INNER_MTU,
    );
    std::mem::forget(_net); // keep the netstack alive for the test
    tokio::spawn(async move {
        while let Some((mut stream, _)) = accept_rx.recv().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    udp
}

async fn start_spoke_egress(endpoint: std::net::SocketAddr) -> rove::outbound::EgressContext {
    let cfg = SubnetraConfig {
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
            endpoint: Some(endpoint.to_string()),
            name: "overlay-gw".into(),
        }],
    };
    let (egress_handle, _bound) = service::start(
        &cfg,
        rove::engine::Engine::new(),
        rove::stats::TrafficStats::new(),
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    rove::outbound::EgressContext::new(None, Some(egress_handle))
}

#[tokio::test]
async fn outbound_subnetra_upstream_dials_over_the_overlay() {
    let target_udp = spawn_overlay_echo(7000).await;
    let egress = start_spoke_egress(target_udp).await;

    // A policy Decision routing the client's target over the overlay.
    let decision = Decision::Via(Upstream {
        kind: UpstreamKind::Subnetra,
        addr: String::new(),
        username: None,
        password: None,
        tls: false,
        skip_cert_verify: false,
    });

    // outbound::connect dials 10.0.0.1:7000 over the overlay via the egress.
    let (mut stream, _egress) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rove::outbound::connect(decision, "10.0.0.1", 7000, &egress),
    )
    .await
    .expect("connect timed out")
    .expect("subnetra egress connect failed");

    stream.write_all(b"reach the isolated net").await.unwrap();
    let mut echoed = vec![0u8; 22];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_exact(&mut echoed),
    )
    .await
    .expect("echo read timed out")
    .unwrap();
    assert_eq!(&echoed, b"reach the isolated net");
}

#[tokio::test]
async fn outbound_subnetra_rejects_non_overlay_host_when_enabled() {
    let egress = start_spoke_egress("127.0.0.1:9".parse().unwrap()).await;
    let err = rove::outbound::connect(
        Decision::Via(Upstream {
            kind: UpstreamKind::Subnetra,
            addr: String::new(),
            username: None,
            password: None,
            tls: false,
            skip_cert_verify: false,
        }),
        "not-an-overlay-host.example",
        443,
        &egress,
    )
    .await;
    assert!(
        err.is_err(),
        "subnetra egress must fail closed, never fall back to direct"
    );
}
