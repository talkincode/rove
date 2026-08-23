//! End-to-end integration of the subnetra userspace TCP stack over the real UDP
//! data plane. A hub node listens on its overlay IP; a spoke node dials it; bytes
//! flow both ways through smoltcp → reactor → UDP → reactor → smoltcp. This proves
//! the L3↔L4 bridge, endpoint learning, routing, and the async stream adapter all
//! work together, not just in isolation.

use std::net::Ipv4Addr;

use rove::subnetra::config::{PeerConfig, SubnetraConfig};
use rove::subnetra::netstack::{self, SubnetraStream};
use rove::subnetra::reactor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

const EPOCH: u64 = 1_704_067_200_000_000_000;

/// Bring up a hub node (reactor + listening netstack) and return its bound UDP
/// address plus the accept channel.
async fn spawn_hub(
    peer_id: u16,
    peer_allowed: &str,
    listen_port: u16,
) -> (
    std::net::SocketAddr,
    mpsc::Receiver<(SubnetraStream, std::net::SocketAddr)>,
) {
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
        proxy_port: 8080,
        peers: vec![PeerConfig {
            id: peer_id,
            psk: "5a".repeat(32),
            allowed_src: peer_allowed.into(),
            endpoint: None,
            name: "spoke".into(),
        }],
    }
    .to_runtime()
    .unwrap();

    let (dp, inbound) = reactor::spawn(cfg, EPOCH).await.unwrap();
    let udp = dp.local_addr();
    let (_net, accept_rx) = netstack::spawn(
        dp,
        inbound,
        "10.0.0.1".parse::<Ipv4Addr>().unwrap(),
        24,
        Some(listen_port),
        rove::subnetra::INNER_MTU,
    );
    // Keep the NetHandle alive for the duration of the test by leaking it into a
    // task that never finishes; the accept path does not need it.
    std::mem::forget(_net);
    (udp, accept_rx)
}

/// Bring up a spoke node (reactor + egress-only netstack) pointed at `hub_udp`.
async fn spawn_spoke(hub_udp: std::net::SocketAddr) -> netstack::NetHandle {
    let cfg = SubnetraConfig {
        enable: true,
        mode: "spoke".into(),
        local_id: 2,
        listen: "127.0.0.1:0".into(),
        overlay_cidr: "10.0.0.2/24".into(),
        obfuscate: true,
        keepalive_secs: 25,
        mtu: None,
        proxy_protocol: "http".into(),
        proxy_port: 8080,
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

    let (dp, inbound) = reactor::spawn(cfg, EPOCH).await.unwrap();
    let (net, _accept) = netstack::spawn(
        dp,
        inbound,
        "10.0.0.2".parse::<Ipv4Addr>().unwrap(),
        24,
        None,
        rove::subnetra::INNER_MTU,
    );
    net
}

#[tokio::test]
async fn tcp_stream_flows_both_ways_over_the_overlay() {
    let (hub_udp, mut accept_rx) = spawn_hub(2, "10.0.0.2/32", 8080).await;
    let spoke = spawn_spoke(hub_udp).await;

    // Spoke dials the hub's overlay IP; hub accepts.
    let connect = tokio::spawn(async move {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            spoke.connect("10.0.0.1".parse().unwrap(), 8080),
        )
        .await
        .expect("connect timed out")
        .expect("connect failed")
    });

    let (mut hub_stream, peer) =
        tokio::time::timeout(std::time::Duration::from_secs(5), accept_rx.recv())
            .await
            .expect("accept timed out")
            .expect("accept channel closed");
    assert_eq!(peer.ip().to_string(), "10.0.0.2");

    let mut spoke_stream = connect.await.unwrap();

    // Spoke -> hub.
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        spoke_stream.write_all(b"ping subnetra"),
    )
    .await
    .expect("write timed out")
    .unwrap();
    spoke_stream.flush().await.unwrap();
    let mut buf = [0u8; 13];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        hub_stream.read_exact(&mut buf),
    )
    .await
    .expect("hub read timed out")
    .unwrap();
    assert_eq!(&buf, b"ping subnetra");

    // Hub -> spoke (echo).
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        hub_stream.write_all(&buf),
    )
    .await
    .expect("echo write timed out")
    .unwrap();
    hub_stream.flush().await.unwrap();
    let mut echo = [0u8; 13];
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        spoke_stream.read_exact(&mut echo),
    )
    .await
    .expect("spoke read timed out")
    .unwrap();
    assert_eq!(&echo, b"ping subnetra");
}

#[tokio::test]
async fn concurrent_connect_burst_beyond_listen_backlog_succeeds() {
    let (hub_udp, mut accept_rx) = spawn_hub(2, "10.0.0.2/32", 7070).await;
    let spoke = spawn_spoke(hub_udp).await;

    // Hub side: accept every overlay connection and echo one byte back.
    tokio::spawn(async move {
        while let Some((mut s, _)) = accept_rx.recv().await {
            tokio::spawn(async move {
                let mut b = [0u8; 1];
                if s.read_exact(&mut b).await.is_ok() {
                    let _ = s.write_all(&b).await;
                    let _ = s.flush().await;
                }
            });
        }
    });

    // 32 simultaneous connects — four times the spare listener pool. Before the
    // pool was topped up on every service pass, SYNs arriving while all spare
    // listeners sat in SynReceived were answered with RST and these failed.
    const CONNS: usize = 32;
    let mut tasks = Vec::new();
    for i in 0..CONNS {
        let spoke = spoke.clone();
        tasks.push(tokio::spawn(async move {
            let mut s = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                spoke.connect("10.0.0.1".parse().unwrap(), 7070),
            )
            .await
            .expect("connect timed out")
            .expect("connect failed");
            let b = [i as u8];
            s.write_all(&b).await.unwrap();
            s.flush().await.unwrap();
            let mut echo = [0u8; 1];
            tokio::time::timeout(std::time::Duration::from_secs(5), s.read_exact(&mut echo))
                .await
                .expect("echo timed out")
                .unwrap();
            assert_eq!(echo, b);
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
}

#[tokio::test]
async fn bulk_transfer_survives_flow_control() {
    let (hub_udp, mut accept_rx) = spawn_hub(2, "10.0.0.2/32", 9090).await;
    let spoke = spawn_spoke(hub_udp).await;

    let connect = tokio::spawn(async move {
        spoke
            .connect("10.0.0.1".parse().unwrap(), 9090)
            .await
            .expect("connect failed")
    });
    let (mut hub_stream, _) = accept_rx.recv().await.expect("accept");
    let mut spoke_stream = connect.await.unwrap();

    // 256 KiB exercises windowing, segmentation, and both buffers.
    const N: usize = 256 * 1024;
    let payload: Vec<u8> = (0..N).map(|i| (i % 251) as u8).collect();

    let sender = {
        let payload = payload.clone();
        tokio::spawn(async move {
            spoke_stream.write_all(&payload).await.unwrap();
            spoke_stream.shutdown().await.unwrap();
        })
    };

    let mut received = Vec::with_capacity(N);
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            hub_stream.read(&mut buf),
        )
        .await
        .expect("read timed out")
        .unwrap();
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buf[..n]);
    }
    sender.await.unwrap();

    assert_eq!(received.len(), N);
    assert_eq!(received, payload);
}
