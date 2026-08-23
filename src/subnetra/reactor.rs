//! Subnetra UDP data-plane reactor.
//!
//! One Tokio task owns the UDP socket and the [`PeerTable`] and multiplexes three
//! sources with `select!` — inbound datagrams, local inner packets to send, and
//! (spoke only) a NAT-keepalive timer. Keeping all peer-state mutation on this
//! single task means no locking, faithfully mirroring the reference
//! implementation's single-reactor design while the rest of Rove runs elsewhere.
//!
//! The task is deliberately L3-only: it moves *inner IPv4 packets* between the
//! mesh and a local sink/source. Turning those packets into TCP streams for Rove's
//! proxy engine is the job of the userspace IP stack ([`super::netstack`]).

use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::config::{Mode, RuntimeConfig};
use super::peer::{ipv4_dst, Ingest, PeerTable};
use super::wire;

/// Channel depth for inner packets in either direction. Datagram semantics: if a
/// queue is full we drop (like a congested link) rather than stall the reactor.
const CHANNEL_DEPTH: usize = 1024;

/// Handle for the *local → mesh* direction plus the metadata the userspace IP
/// stack needs to configure itself.
#[derive(Clone)]
pub struct DataPlaneHandle {
    to_mesh: mpsc::Sender<Vec<u8>>,
    local_id: u16,
    overlay_ip: Ipv4Addr,
    local_addr: std::net::SocketAddr,
}

impl DataPlaneHandle {
    /// Queue one inner IPv4 packet to be routed, sealed, and sent to the mesh.
    /// Returns `Err` only if the reactor has stopped (channel closed).
    pub async fn send_inner(&self, packet: Vec<u8>) -> anyhow::Result<()> {
        self.to_mesh
            .send(packet)
            .await
            .map_err(|_| anyhow::anyhow!("subnetra reactor stopped"))
    }

    /// Non-blocking variant: drop the packet if the queue is momentarily full.
    pub fn try_send_inner(&self, packet: Vec<u8>) {
        if self.to_mesh.try_send(packet).is_err() {
            debug!("subnetra: local->mesh queue full or closed, dropping inner packet");
        }
    }

    pub fn local_id(&self) -> u16 {
        self.local_id
    }

    pub fn overlay_ip(&self) -> Ipv4Addr {
        self.overlay_ip
    }

    /// The actual bound UDP address (useful when `listen` used port 0).
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local_addr
    }
}

/// Spawn the reactor. Returns the local→mesh handle and the mesh→local receiver
/// carrying inner IPv4 packets destined to this node's overlay IP.
///
/// Binds the UDP socket up front and fails closed on a bind error, matching the
/// reverse-hop data plane: an operator who enabled subnetra should see a startup
/// error, not a silently dead mesh.
pub async fn spawn(
    cfg: RuntimeConfig,
    epoch: u64,
) -> anyhow::Result<(DataPlaneHandle, mpsc::Receiver<Vec<u8>>)> {
    let socket = UdpSocket::bind(cfg.listen)
        .await
        .map_err(|e| anyhow::anyhow!("subnetra: bind {} failed: {e}", cfg.listen))?;
    let local_addr = socket.local_addr().unwrap_or(cfg.listen);
    let socket = Arc::new(socket);

    let table = PeerTable::new(&cfg, epoch);
    let (to_mesh_tx, to_mesh_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);
    let (to_local_tx, to_local_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);

    let handle = DataPlaneHandle {
        to_mesh: to_mesh_tx,
        local_id: cfg.local_id,
        overlay_ip: cfg.overlay_ip(),
        local_addr,
    };

    info!(
        mode = ?cfg.mode,
        local_id = cfg.local_id,
        overlay = %cfg.overlay,
        listen = %local_addr,
        peers = cfg.peers.len(),
        obfuscate = cfg.obfuscate,
        "subnetra data plane started"
    );

    let reactor = Reactor {
        socket,
        table,
        mode: cfg.mode,
        overlay_ip: cfg.overlay_ip(),
        keepalive_secs: cfg.keepalive_secs,
        obfuscate: cfg.obfuscate,
        to_local: to_local_tx,
    };
    tokio::spawn(reactor.run(to_mesh_rx));

    Ok((handle, to_local_rx))
}

struct Reactor {
    socket: Arc<UdpSocket>,
    table: PeerTable,
    mode: Mode,
    overlay_ip: Ipv4Addr,
    keepalive_secs: u64,
    obfuscate: bool,
    to_local: mpsc::Sender<Vec<u8>>,
}

impl Reactor {
    async fn run(mut self, mut to_mesh_rx: mpsc::Receiver<Vec<u8>>) {
        // A 64 KiB scratch buffer covers any legal underlay datagram.
        let mut buf = vec![0u8; 65535];
        let is_spoke = self.mode == Mode::Spoke;

        // Keepalive timer (spoke only). The first tick fires immediately, which we
        // skip so we don't emit before any peer is reachable.
        let mut keepalive = tokio::time::interval(self.keepalive_interval());
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        keepalive.tick().await; // consume the immediate first tick

        loop {
            tokio::select! {
                recv = self.socket.recv_from(&mut buf) => {
                    match recv {
                        Ok((n, src)) => {
                            // recv_from only yields IPv4/IPv6 SocketAddrs; the mesh
                            // is UDP so any src is fine to pass through.
                            self.handle_inbound(&buf[..n], src).await;
                        }
                        Err(e) => {
                            warn!("subnetra: recv_from error: {e}");
                        }
                    }
                }
                maybe = to_mesh_rx.recv() => {
                    match maybe {
                        Some(packet) => self.handle_outbound(&packet).await,
                        // All handles dropped: the owner is shutting subnetra down.
                        None => {
                            info!("subnetra: local->mesh channel closed, reactor exiting");
                            return;
                        }
                    }
                }
                _ = keepalive.tick(), if is_spoke => {
                    self.send_keepalives().await;
                    // De-periodize the next interval under obfuscation (§3.4).
                    keepalive = tokio::time::interval(self.keepalive_interval());
                    keepalive.tick().await;
                }
            }
        }
    }

    /// Process one received datagram (§5) and act on the routing decision.
    async fn handle_inbound(&mut self, datagram: &[u8], src: std::net::SocketAddr) {
        match self.table.ingest(datagram, src) {
            Ingest::Data { peer_id, inner } => {
                let Some(dst) = ipv4_dst(&inner) else {
                    return; // not a well-formed inner IPv4 packet; drop
                };
                debug!(peer_id, %dst, overlay = %self.overlay_ip, len = inner.len(), "subnetra: inbound data");
                if dst == self.overlay_ip {
                    // Destined to us: hand up to the local userspace IP stack.
                    if self.to_local.try_send(inner).is_err() {
                        debug!("subnetra: mesh->local queue full, dropping inner packet");
                    }
                } else if self.mode == Mode::Hub {
                    self.relay(peer_id, dst, &inner).await;
                }
                // A spoke never relays; a non-local dst it can't place is dropped.
            }
            Ingest::Keepalive { peer_id } => {
                debug!(peer_id, "subnetra: keepalive from peer");
            }
            Ingest::Drop => {}
        }
    }

    /// Hub relay (§5.9): forward to the peer that owns `dst`, honouring the
    /// no-reflect guard (a hub MUST NOT bounce a packet back to its source peer).
    async fn relay(&mut self, from_peer: u16, dst: Ipv4Addr, inner: &[u8]) {
        let Some(to_peer) = self.table.route(dst) else {
            debug!(%dst, "subnetra: no route for relay target, dropping");
            return;
        };
        if to_peer == from_peer {
            debug!(peer = to_peer, "subnetra: no-reflect guard dropped relay");
            return;
        }
        if let Some((datagram, endpoint)) = self.table.seal_for(to_peer, 0, inner) {
            if let Err(e) = self.socket.send_to(&datagram, endpoint).await {
                warn!(peer = to_peer, %endpoint, "subnetra: relay send failed: {e}");
            }
        } else {
            debug!(
                peer = to_peer,
                "subnetra: relay target endpoint unknown, dropping"
            );
        }
    }

    /// Route a local inner packet to its owning peer, seal, and send (§4).
    async fn handle_outbound(&mut self, packet: &[u8]) {
        let Some(dst) = ipv4_dst(packet) else {
            debug!("subnetra: local packet is not IPv4, dropping");
            return;
        };
        let Some(to_peer) = self.table.route(dst) else {
            debug!(%dst, "subnetra: no route for local packet, dropping");
            return;
        };
        if let Some((datagram, endpoint)) = self.table.seal_for(to_peer, 0, packet) {
            debug!(%dst, peer = to_peer, %endpoint, len = packet.len(), "subnetra: egress send");
            if let Err(e) = self.socket.send_to(&datagram, endpoint).await {
                warn!(peer = to_peer, %endpoint, "subnetra: egress send failed: {e}");
            }
        } else {
            debug!(
                peer = to_peer, %dst,
                "subnetra: egress endpoint unknown, dropping"
            );
        }
    }

    /// Emit an empty keepalive to every peer with a known endpoint (§3.3).
    async fn send_keepalives(&mut self) {
        for peer_id in self.table.peers_with_endpoint() {
            if let Some((datagram, endpoint)) = self.table.seal_for(peer_id, wire::KEEPALIVE, &[]) {
                if let Err(e) = self.socket.send_to(&datagram, endpoint).await {
                    warn!(peer = peer_id, %endpoint, "subnetra: keepalive send failed: {e}");
                }
            }
        }
    }

    /// The next keepalive interval. With obfuscation on, randomize uniformly in
    /// `[k/2, k]` so an idle spoke's keepalive cadence is not a fixed-period
    /// signature (§3.4); otherwise fire at exactly `k`.
    fn keepalive_interval(&self) -> std::time::Duration {
        let k = self.keepalive_secs.max(1);
        if self.obfuscate {
            let half = k / 2;
            let jitter = if half > 0 {
                random_u64() % (k - half + 1)
            } else {
                0
            };
            std::time::Duration::from_secs(half + jitter)
        } else {
            std::time::Duration::from_secs(k)
        }
    }
}

/// A single cryptographically-random `u64`, used only for keepalive jitter.
/// Reuses the in-tree `ring` RNG so no new dependency is needed.
fn random_u64() -> u64 {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 8];
    // On the astronomically unlikely RNG failure, fall back to zero jitter —
    // de-periodization is a hardening measure, never a correctness requirement.
    let _ = ring::rand::SystemRandom::new().fill(&mut b);
    u64::from_le_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subnetra::config::{PeerConfig, SubnetraConfig};

    const EPOCH: u64 = 1_704_067_200_000_000_000;

    fn inner_packet(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p.extend_from_slice(payload);
        p
    }

    #[tokio::test]
    async fn spoke_egress_and_hub_delivery_over_udp() {
        // Bind the hub first so the spoke can be told its real port.
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
        }
        .to_runtime()
        .unwrap();
        let (hub_handle, mut hub_inbound) = spawn(hub_cfg, EPOCH).await.unwrap();
        let hub_addr = hub_handle.local_addr();

        let spoke_cfg = SubnetraConfig {
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
                allowed_src: "10.0.0.0/24".into(), // hub is the spoke's default route
                endpoint: Some(hub_addr.to_string()),
                name: "hub".into(),
            }],
        }
        .to_runtime()
        .unwrap();
        let (spoke_handle, mut spoke_inbound) = spawn(spoke_cfg, EPOCH).await.unwrap();

        // Spoke -> hub: an inner packet destined to the hub's overlay IP.
        let up = inner_packet([10, 0, 0, 2], [10, 0, 0, 1], b"hello-hub");
        spoke_handle.send_inner(up.clone()).await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), hub_inbound.recv())
            .await
            .expect("hub delivery timed out")
            .expect("hub inbound closed");
        assert_eq!(got, up);

        // Hub -> spoke: the hub learned the spoke's endpoint, so the reply flows.
        let down = inner_packet([10, 0, 0, 1], [10, 0, 0, 2], b"hello-spoke");
        hub_handle.send_inner(down.clone()).await.unwrap();
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), spoke_inbound.recv())
            .await
            .expect("spoke delivery timed out")
            .expect("spoke inbound closed");
        assert_eq!(got, down);
    }

    #[tokio::test]
    async fn garbage_datagram_is_ignored() {
        let cfg = SubnetraConfig {
            enable: true,
            mode: "hub".into(),
            local_id: 1,
            listen: "127.0.0.1:0".into(),
            overlay_cidr: "10.0.0.1/24".into(),
            obfuscate: false,
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
        }
        .to_runtime()
        .unwrap();
        let (handle, mut inbound) = spawn(cfg, EPOCH).await.unwrap();

        // Blast noise at the socket; the reactor must silently ignore it and stay
        // alive (no delivery, no panic).
        let noise = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        noise
            .send_to(&[0u8; 40], handle.local_addr())
            .await
            .unwrap();
        noise.send_to(b"short", handle.local_addr()).await.unwrap();

        let delivered =
            tokio::time::timeout(std::time::Duration::from_millis(300), inbound.recv()).await;
        assert!(delivered.is_err(), "no garbage should be delivered");
    }
}
