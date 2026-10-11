//! Rootless 3-node Subnetra mesh integration tests using MemDevice.
//!
//! Verifies:
//! 1. Spoke A <-> Spoke B communication via Hub L3 relay (without hub kernel forwarding).
//! 2. Spoke <-> Hub communication when Hub runs TUN mode.
//! 3. Anti-spoofing drop: local host processes cannot spoof overlay source IPs.
//! 4. MTU and off-overlay packet filtering.
//! 5. Seamless relay when Hub runs userspace Netstack mode.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ipnet::Ipv4Net;
use rove::subnetra::config::{PeerConfig, SubnetraConfig, TunConfig};
use rove::subnetra::device::mem::{MemDevice, MemDevicePeer};
use rove::subnetra::device::{run_pump, PumpCounters, PumpPolicy};
use rove::subnetra::reactor;
use tokio::sync::watch;

const EPOCH: u64 = 1_704_067_200_000_000_000;

fn make_ipv4_packet(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + payload.len();
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    pkt[1] = 0;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = 1; // ICMP
    pkt[12..16].copy_from_slice(&src);
    pkt[16..20].copy_from_slice(&dst);
    pkt[20..].copy_from_slice(payload);
    pkt
}

struct TestNode {
    peer: MemDevicePeer,
    counters: Arc<PumpCounters>,
    bound: SocketAddr,
    _shutdown: watch::Sender<bool>,
}

async fn spawn_tun_node(
    mode: &str,
    local_id: u16,
    overlay_ip: &str,
    peers: Vec<PeerConfig>,
) -> TestNode {
    let cfg = SubnetraConfig {
        enable: true,
        mode: mode.into(),
        device: "tun".into(),
        tun: TunConfig::default(),
        local_id,
        listen: "127.0.0.1:0".into(),
        overlay_cidr: format!("{overlay_ip}/24"),
        obfuscate: true,
        keepalive_secs: 25,
        mtu: Some(1400),
        proxy_protocol: String::new(),
        proxy_port: 0,
        peers,
    }
    .to_runtime()
    .unwrap();

    let overlay_ip_addr = cfg.overlay_ip();
    let overlay_net: Ipv4Net = cfg.overlay;
    let mtu = cfg.mtu;

    let (dp, inbound_rx) = reactor::spawn(cfg, EPOCH).await.unwrap();
    let bound = dp.local_addr();

    let (dev, dev_peer) = MemDevice::pair(128);
    let counters = Arc::new(PumpCounters::default());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let policy = PumpPolicy {
        overlay_ip: overlay_ip_addr,
        overlay_net,
        mtu,
    };

    tokio::spawn(run_pump(
        dev,
        dp,
        inbound_rx,
        policy,
        counters.clone(),
        shutdown_rx,
    ));

    TestNode {
        peer: dev_peer,
        counters,
        bound,
        _shutdown: shutdown_tx,
    }
}

#[tokio::test]
async fn spoke_to_spoke_hub_relay_and_bidirectional_traffic() {
    let psk_a = "11".repeat(32);
    let psk_b = "22".repeat(32);

    // 1. Start Hub (TUN mode)
    let hub = spawn_tun_node(
        "hub",
        1,
        "10.0.0.1",
        vec![
            PeerConfig {
                id: 2,
                psk: psk_a.clone(),
                allowed_src: "10.0.0.2/32".into(),
                endpoint: None,
                name: "spoke-a".into(),
            },
            PeerConfig {
                id: 3,
                psk: psk_b.clone(),
                allowed_src: "10.0.0.3/32".into(),
                endpoint: None,
                name: "spoke-b".into(),
            },
        ],
    )
    .await;

    // 2. Start Spoke A (10.0.0.2)
    let mut spoke_a = spawn_tun_node(
        "spoke",
        2,
        "10.0.0.2",
        vec![PeerConfig {
            id: 1,
            psk: psk_a,
            allowed_src: "10.0.0.0/24".into(), // all overlay traffic routed to hub
            endpoint: Some(hub.bound.to_string()),
            name: "hub".into(),
        }],
    )
    .await;

    // 3. Start Spoke B (10.0.0.3)
    let mut spoke_b = spawn_tun_node(
        "spoke",
        3,
        "10.0.0.3",
        vec![PeerConfig {
            id: 1,
            psk: psk_b,
            allowed_src: "10.0.0.0/24".into(), // all overlay traffic routed to hub
            endpoint: Some(hub.bound.to_string()),
            name: "hub".into(),
        }],
    )
    .await;

    // Prime the hub: both spokes send a keepalive/hello packet so the hub learns their endpoints
    let prime_a = make_ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1], b"prime-a");
    spoke_a.peer.inject(&prime_a).await.unwrap();

    let prime_b = make_ipv4_packet([10, 0, 0, 3], [10, 0, 0, 1], b"prime-b");
    spoke_b.peer.inject(&prime_b).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Test A -> B: Spoke A injects packet destined to 10.0.0.3
    let pkt_a_to_b = make_ipv4_packet([10, 0, 0, 2], [10, 0, 0, 3], b"ping-from-a-to-b");
    spoke_a.peer.inject(&pkt_a_to_b).await.unwrap();

    let received_at_b = tokio::time::timeout(Duration::from_secs(2), spoke_b.peer.recv())
        .await
        .expect("spoke B timed out waiting for packet")
        .expect("spoke B channel closed");

    assert_eq!(received_at_b, pkt_a_to_b);

    // Test B -> A: Spoke B replies destined to 10.0.0.2
    let pkt_b_to_a = make_ipv4_packet([10, 0, 0, 3], [10, 0, 0, 2], b"pong-from-b-to-a");
    spoke_b.peer.inject(&pkt_b_to_a).await.unwrap();

    let received_at_a = tokio::time::timeout(Duration::from_secs(2), spoke_a.peer.recv())
        .await
        .expect("spoke A timed out waiting for reply")
        .expect("spoke A channel closed");

    assert_eq!(received_at_a, pkt_b_to_a);
}

#[tokio::test]
async fn hub_itself_reachable_when_running_tun_mode() {
    let psk = "33".repeat(32);

    let mut hub = spawn_tun_node(
        "hub",
        1,
        "10.0.0.1",
        vec![PeerConfig {
            id: 2,
            psk: psk.clone(),
            allowed_src: "10.0.0.2/32".into(),
            endpoint: None,
            name: "spoke-a".into(),
        }],
    )
    .await;

    let mut spoke = spawn_tun_node(
        "spoke",
        2,
        "10.0.0.2",
        vec![PeerConfig {
            id: 1,
            psk,
            allowed_src: "10.0.0.0/24".into(),
            endpoint: Some(hub.bound.to_string()),
            name: "hub".into(),
        }],
    )
    .await;

    // Spoke -> Hub OS interface
    let req = make_ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1], b"ssh-syn");
    spoke.peer.inject(&req).await.unwrap();

    let got_at_hub = tokio::time::timeout(Duration::from_secs(2), hub.peer.recv())
        .await
        .expect("hub timed out waiting for packet")
        .expect("hub channel closed");
    assert_eq!(got_at_hub, req);

    // Hub OS interface -> Spoke
    let resp = make_ipv4_packet([10, 0, 0, 1], [10, 0, 0, 2], b"ssh-syn-ack");
    hub.peer.inject(&resp).await.unwrap();

    let got_at_spoke = tokio::time::timeout(Duration::from_secs(2), spoke.peer.recv())
        .await
        .expect("spoke timed out waiting for packet")
        .expect("spoke channel closed");
    assert_eq!(got_at_spoke, resp);
}

#[tokio::test]
async fn anti_spoofing_drops_spoofed_source_ip() {
    let psk = "44".repeat(32);

    let mut hub = spawn_tun_node(
        "hub",
        1,
        "10.0.0.1",
        vec![PeerConfig {
            id: 2,
            psk: psk.clone(),
            allowed_src: "10.0.0.2/32".into(),
            endpoint: None,
            name: "spoke".into(),
        }],
    )
    .await;

    let spoke = spawn_tun_node(
        "spoke",
        2,
        "10.0.0.2",
        vec![PeerConfig {
            id: 1,
            psk,
            allowed_src: "10.0.0.0/24".into(),
            endpoint: Some(hub.bound.to_string()),
            name: "hub".into(),
        }],
    )
    .await;

    // Spoke tries to spoof source IP 10.0.0.99
    let spoofed = make_ipv4_packet([10, 0, 0, 99], [10, 0, 0, 1], b"attack");
    spoke.peer.inject(&spoofed).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Spoke counters: drop_spoofed_src must be 1
    let snap = spoke.counters.snapshot();
    assert_eq!(snap.drop_spoofed_src, 1);
    assert_eq!(snap.to_mesh, 0);

    // Hub must receive nothing
    assert!(hub.peer.try_recv().is_err());
}

#[tokio::test]
async fn drops_too_big_and_off_overlay() {
    let psk = "55".repeat(32);

    let hub = spawn_tun_node(
        "hub",
        1,
        "10.0.0.1",
        vec![PeerConfig {
            id: 2,
            psk: psk.clone(),
            allowed_src: "10.0.0.2/32".into(),
            endpoint: None,
            name: "spoke".into(),
        }],
    )
    .await;

    let spoke = spawn_tun_node(
        "spoke",
        2,
        "10.0.0.2",
        vec![PeerConfig {
            id: 1,
            psk,
            allowed_src: "10.0.0.0/24".into(),
            endpoint: Some(hub.bound.to_string()),
            name: "hub".into(),
        }],
    )
    .await;

    // 1. Oversized packet (> MTU 1400)
    let big = make_ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1], &vec![0u8; 1500]);
    spoke.peer.inject(&big).await.unwrap();

    // 2. Off-overlay destination (172.16.0.1 not in 10.0.0.0/24)
    let off = make_ipv4_packet([10, 0, 0, 2], [172, 16, 0, 1], b"off-net");
    spoke.peer.inject(&off).await.unwrap();

    // 3. Invalid IPv4 (IPv6 header nibble)
    let mut invalid = make_ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1], b"bad");
    invalid[0] = 0x60;
    spoke.peer.inject(&invalid).await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    let snap = spoke.counters.snapshot();
    assert_eq!(snap.drop_too_big, 1);
    assert_eq!(snap.drop_off_overlay, 1);
    assert_eq!(snap.drop_not_ipv4, 1);
    assert_eq!(snap.to_mesh, 0);
}

#[tokio::test]
async fn netstack_hub_relays_between_tun_spokes() {
    let psk_a = "66".repeat(32);
    let psk_b = "77".repeat(32);

    // Hub running netstack mode
    let hub_cfg = SubnetraConfig {
        enable: true,
        mode: "hub".into(),
        device: "netstack".into(),
        tun: TunConfig::default(),
        local_id: 1,
        listen: "127.0.0.1:0".into(),
        overlay_cidr: "10.0.0.1/24".into(),
        obfuscate: true,
        keepalive_secs: 25,
        mtu: Some(1400),
        proxy_protocol: "http".into(),
        proxy_port: 8080,
        peers: vec![
            PeerConfig {
                id: 2,
                psk: psk_a.clone(),
                allowed_src: "10.0.0.2/32".into(),
                endpoint: None,
                name: "spoke-a".into(),
            },
            PeerConfig {
                id: 3,
                psk: psk_b.clone(),
                allowed_src: "10.0.0.3/32".into(),
                endpoint: None,
                name: "spoke-b".into(),
            },
        ],
    }
    .to_runtime()
    .unwrap();

    let (hub_dp, _inbound) = reactor::spawn(hub_cfg, EPOCH).await.unwrap();
    let hub_bound = hub_dp.local_addr();

    // Spoke A (TUN mode)
    let spoke_a = spawn_tun_node(
        "spoke",
        2,
        "10.0.0.2",
        vec![PeerConfig {
            id: 1,
            psk: psk_a,
            allowed_src: "10.0.0.0/24".into(),
            endpoint: Some(hub_bound.to_string()),
            name: "hub".into(),
        }],
    )
    .await;

    // Spoke B (TUN mode)
    let mut spoke_b = spawn_tun_node(
        "spoke",
        3,
        "10.0.0.3",
        vec![PeerConfig {
            id: 1,
            psk: psk_b,
            allowed_src: "10.0.0.0/24".into(),
            endpoint: Some(hub_bound.to_string()),
            name: "hub".into(),
        }],
    )
    .await;

    // Prime hub endpoints
    spoke_a
        .peer
        .inject(&make_ipv4_packet([10, 0, 0, 2], [10, 0, 0, 1], b"init-a"))
        .await
        .unwrap();
    spoke_b
        .peer
        .inject(&make_ipv4_packet([10, 0, 0, 3], [10, 0, 0, 1], b"init-b"))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // A -> B relay across netstack hub
    let ping = make_ipv4_packet([10, 0, 0, 2], [10, 0, 0, 3], b"cross-netstack-hub");
    spoke_a.peer.inject(&ping).await.unwrap();

    let received = tokio::time::timeout(Duration::from_secs(2), spoke_b.peer.recv())
        .await
        .expect("spoke B timed out")
        .expect("spoke B closed");
    assert_eq!(received, ping);
}
