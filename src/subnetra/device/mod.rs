//! TUN and in-memory packet device abstraction and pump.
//!
//! Subnetra's data plane ([`reactor`](crate::subnetra::reactor)) routes raw
//! IPv4 datagrams over encrypted UDP tunnels. This module bridges those raw
//! datagrams to/from a host Layer-3 network device:
//!
//! - In production: a kernel TUN interface (e.g. `rove0` on Linux, `utunN` on macOS).
//! - In tests: an in-memory packet device ([`MemDevice`](mem::MemDevice)) allowing
//!   full rootless integration tests.

pub mod mem;
pub mod tun;

use std::future::Future;
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ipnet::Ipv4Net;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info};

use super::reactor::DataPlaneHandle;

/// One-packet-at-a-time Layer-3 device.
pub trait PacketIo: Send + Sync + 'static {
    /// Receive one raw IPv4 datagram from the device into `buf`.
    fn recv<'a>(&'a self, buf: &'a mut [u8])
        -> impl Future<Output = io::Result<usize>> + Send + 'a;

    /// Send one raw IPv4 datagram to the device.
    fn send<'a>(&'a self, pkt: &'a [u8]) -> impl Future<Output = io::Result<usize>> + Send + 'a;
}

/// Ingress policy enforced on packets flowing from the host device into the mesh.
#[derive(Debug, Clone)]
pub struct PumpPolicy {
    /// This node's overlay IP. Every packet sent from this host into the mesh
    /// MUST match this source address (anti-spoofing verdict).
    pub overlay_ip: Ipv4Addr,
    /// The overlay subnet. Packets with destinations outside this subnet are
    /// dropped immediately to avoid unroutable mesh traffic.
    pub overlay_net: Ipv4Net,
    /// Inner overlay MTU. Packets exceeding this size are dropped.
    pub mtu: usize,
}

/// Egress verdict returned by [`egress_verdict`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Forward packet to the mesh data plane.
    Forward,
    /// Dropped because the packet is not valid IPv4 or shorter than minimum header.
    DropNotIpv4,
    /// Dropped because the packet exceeds the configured MTU.
    DropTooBig,
    /// Dropped because the source IP does not match the node's overlay IP.
    DropSpoofedSrc,
    /// Dropped because the destination IP is not inside the overlay subnet.
    DropOffOverlay,
}

/// Inspect an outbound packet read from the host device before sealing into the mesh.
///
/// Enforces:
/// 1. IPv4 only (version == 4, valid header length).
/// 2. Packet length <= MTU.
/// 3. Source IP == overlay IP (anti-spoofing).
/// 4. Destination IP in overlay subnet.
pub fn egress_verdict(pkt: &[u8], policy: &PumpPolicy) -> Verdict {
    if pkt.len() < 20 {
        return Verdict::DropNotIpv4;
    }

    // IPv4 version (upper 4 bits of byte 0) must be 4.
    let version = pkt[0] >> 4;
    if version != 4 {
        return Verdict::DropNotIpv4;
    }

    // IHL (lower 4 bits of byte 0) in 32-bit words, min 5 (20 bytes).
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || ihl > pkt.len() {
        return Verdict::DropNotIpv4;
    }

    // Total length from IPv4 header (bytes 2-3).
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len < 20 || total_len > pkt.len() {
        return Verdict::DropNotIpv4;
    }

    // MTU enforcement.
    if pkt.len() > policy.mtu || total_len > policy.mtu {
        return Verdict::DropTooBig;
    }

    // Anti-spoofing: local processes must only source from this node's assigned overlay IP.
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    if src != policy.overlay_ip {
        return Verdict::DropSpoofedSrc;
    }

    // Destination check: must be inside overlay subnet.
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    if !policy.overlay_net.contains(&dst) {
        return Verdict::DropOffOverlay;
    }

    Verdict::Forward
}

/// Atomic counters tracking packet flow between host device and mesh reactor.
#[derive(Debug, Default)]
pub struct PumpCounters {
    pub to_mesh: AtomicU64,
    pub to_device: AtomicU64,
    pub drop_not_ipv4: AtomicU64,
    pub drop_too_big: AtomicU64,
    pub drop_spoofed_src: AtomicU64,
    pub drop_off_overlay: AtomicU64,
    pub device_errors: AtomicU64,
}

/// Immutable snapshot of [`PumpCounters`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PumpCountersSnapshot {
    pub to_mesh: u64,
    pub to_device: u64,
    pub drop_not_ipv4: u64,
    pub drop_too_big: u64,
    pub drop_spoofed_src: u64,
    pub drop_off_overlay: u64,
    pub device_errors: u64,
}

impl PumpCounters {
    pub fn snapshot(&self) -> PumpCountersSnapshot {
        PumpCountersSnapshot {
            to_mesh: self.to_mesh.load(Ordering::Relaxed),
            to_device: self.to_device.load(Ordering::Relaxed),
            drop_not_ipv4: self.drop_not_ipv4.load(Ordering::Relaxed),
            drop_too_big: self.drop_too_big.load(Ordering::Relaxed),
            drop_spoofed_src: self.drop_spoofed_src.load(Ordering::Relaxed),
            drop_off_overlay: self.drop_off_overlay.load(Ordering::Relaxed),
            device_errors: self.device_errors.load(Ordering::Relaxed),
        }
    }
}

/// Run full-duplex packet pump between device and mesh reactor until shutdown.
pub async fn run_pump<D: PacketIo>(
    dev: Arc<D>,
    dp: DataPlaneHandle,
    inbound: mpsc::Receiver<Vec<u8>>,
    policy: PumpPolicy,
    counters: Arc<PumpCounters>,
    mut shutdown: watch::Receiver<bool>,
) {
    let dev_rx = dev.clone();
    let dev_tx = dev;
    let dp_tx = dp;
    let counters_rx = counters.clone();
    let counters_tx = counters.clone();
    let policy_rx = policy.clone();

    // Outbound task: read from device -> egress_verdict -> dp.send_inner()
    let mut rx_shutdown = shutdown.clone();
    let rx_task = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            tokio::select! {
                biased;
                _ = crate::lifecycle::shutdown_requested(&mut rx_shutdown) => {
                    break;
                }
                res = dev_rx.recv(&mut buf) => {
                    match res {
                        Ok(n) => {
                            let pkt = &buf[..n];
                            match egress_verdict(pkt, &policy_rx) {
                                Verdict::Forward => {
                                    if let Err(e) = dp_tx.send_inner(pkt.to_vec()).await {
                                        debug!(error = %e, "reactor stopped, pump exiting");
                                        break;
                                    }
                                    counters_rx.to_mesh.fetch_add(1, Ordering::Relaxed);
                                }
                                Verdict::DropNotIpv4 => {
                                    counters_rx.drop_not_ipv4.fetch_add(1, Ordering::Relaxed);
                                }
                                Verdict::DropTooBig => {
                                    counters_rx.drop_too_big.fetch_add(1, Ordering::Relaxed);
                                }
                                Verdict::DropSpoofedSrc => {
                                    counters_rx.drop_spoofed_src.fetch_add(1, Ordering::Relaxed);
                                    debug!(
                                        expected = %policy_rx.overlay_ip,
                                        "dropped packet with spoofed source IP from device"
                                    );
                                }
                                Verdict::DropOffOverlay => {
                                    counters_rx.drop_off_overlay.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        Err(e) => {
                            counters_rx.device_errors.fetch_add(1, Ordering::Relaxed);
                            debug!(error = %e, "device read error");
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                    }
                }
            }
        }
    };

    // Inbound task: read from mesh inbound_rx -> dev.send()
    let mut tx_shutdown = shutdown.clone();
    let mut inbound_rx = inbound;
    let tx_task = async move {
        loop {
            tokio::select! {
                biased;
                _ = crate::lifecycle::shutdown_requested(&mut tx_shutdown) => {
                    break;
                }
                pkt = inbound_rx.recv() => {
                    let Some(pkt) = pkt else {
                        break;
                    };
                    if let Err(e) = dev_tx.send(&pkt).await {
                        counters_tx.device_errors.fetch_add(1, Ordering::Relaxed);
                        debug!(error = %e, "device write error");
                    } else {
                        counters_tx.to_device.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
    };

    // Periodic stats reporter
    let reporter = async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await; // skip initial immediate tick
        loop {
            tokio::select! {
                biased;
                _ = crate::lifecycle::shutdown_requested(&mut shutdown) => {
                    break;
                }
                _ = interval.tick() => {
                    let snap = counters.snapshot();
                    if snap.to_mesh > 0 || snap.to_device > 0 || snap.drop_spoofed_src > 0 {
                        info!(
                            to_mesh = snap.to_mesh,
                            to_device = snap.to_device,
                            drop_spoofed_src = snap.drop_spoofed_src,
                            drop_too_big = snap.drop_too_big,
                            drop_off_overlay = snap.drop_off_overlay,
                            drop_not_ipv4 = snap.drop_not_ipv4,
                            device_errors = snap.device_errors,
                            "subnetra tun pump traffic summary"
                        );
                    }
                }
            }
        }
    };

    tokio::join!(rx_task, tx_task, reporter);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn test_policy() -> PumpPolicy {
        PumpPolicy {
            overlay_ip: Ipv4Addr::new(10, 0, 0, 2),
            overlay_net: Ipv4Net::from_str("10.0.0.0/24").unwrap(),
            mtu: 1400,
        }
    }

    fn make_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload_len: usize) -> Vec<u8> {
        let total_len = 20 + payload_len;
        let mut pkt = vec![0u8; total_len];
        pkt[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        pkt[1] = 0;
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[8] = 64; // TTL
        pkt[9] = 1; // ICMP
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());
        pkt
    }

    #[test]
    fn verdict_valid_packet() {
        let policy = test_policy();
        let pkt = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3), 32);
        assert_eq!(egress_verdict(&pkt, &policy), Verdict::Forward);
    }

    #[test]
    fn verdict_drops_not_ipv4() {
        let policy = test_policy();
        assert_eq!(egress_verdict(&[0u8; 10], &policy), Verdict::DropNotIpv4);

        let mut pkt = make_ipv4_packet(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3), 10);
        pkt[0] = 0x60; // IPv6
        assert_eq!(egress_verdict(&pkt, &policy), Verdict::DropNotIpv4);
    }

    #[test]
    fn verdict_drops_too_big() {
        let policy = test_policy();
        let pkt = make_ipv4_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 3),
            1400, // total len 1420 > 1400 MTU
        );
        assert_eq!(egress_verdict(&pkt, &policy), Verdict::DropTooBig);
    }

    #[test]
    fn verdict_drops_spoofed_src() {
        let policy = test_policy();
        let pkt = make_ipv4_packet(
            Ipv4Addr::new(10, 0, 0, 9), // spoofed src
            Ipv4Addr::new(10, 0, 0, 3),
            20,
        );
        assert_eq!(egress_verdict(&pkt, &policy), Verdict::DropSpoofedSrc);
    }

    #[test]
    fn verdict_drops_off_overlay() {
        let policy = test_policy();
        let pkt = make_ipv4_packet(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(192, 168, 1, 1), // outside 10.0.0.0/24
            20,
        );
        assert_eq!(egress_verdict(&pkt, &policy), Verdict::DropOffOverlay);
    }
}
