//! A smoltcp [`Device`] backed by two in-memory queues, bridging the userspace IP
//! stack to the subnetra data-plane reactor.
//!
//! smoltcp is a synchronous, poll-driven stack, so this device does no I/O of its
//! own: the driver ([`super::Driver`]) pushes inbound inner packets in with
//! [`ChannelDevice::push_rx`] before each poll, and drains the packets smoltcp
//! emitted with [`ChannelDevice::drain_tx`] afterwards, forwarding them to the
//! reactor. The medium is [`Medium::Ip`] — the inner packets are bare IPv4, with
//! no Ethernet framing.

use std::collections::VecDeque;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;

use crate::subnetra::{INNER_MTU, MIN_INNER_MTU};

pub struct ChannelDevice {
    /// Inbound inner packets awaiting consumption by smoltcp (driver → stack).
    rx: VecDeque<Vec<u8>>,
    /// Outbound inner packets smoltcp produced, awaiting the driver (stack → mesh).
    tx: Vec<Vec<u8>>,
    mtu: usize,
}

impl ChannelDevice {
    pub fn new() -> Self {
        Self::with_mtu(INNER_MTU)
    }

    /// Build a device that advertises `mtu` as its inner MTU. smoltcp derives the
    /// TCP MSS it announces from this, so lowering it (e.g. when the mesh runs
    /// inside an already-compressed outer tunnel with a fixed 1360-byte path) keeps
    /// emitted inner segments small enough that the sealed outer UDP datagram still
    /// fits the carrier without fragmentation. The value is clamped to the protocol
    /// ceiling [`INNER_MTU`] — a larger request cannot be honoured because the
    /// crypto layer's plaintext is bounded there — and floored at the IPv4 minimum.
    pub fn with_mtu(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: Vec::new(),
            mtu: mtu.clamp(MIN_INNER_MTU, INNER_MTU),
        }
    }

    /// Queue one inbound inner IPv4 packet for smoltcp to process on the next poll.
    pub fn push_rx(&mut self, packet: Vec<u8>) {
        self.rx.push_back(packet);
    }

    /// Take the inner packets smoltcp emitted since the last drain, for the driver
    /// to hand to the reactor.
    pub fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.tx)
    }

    /// True if there is buffered inbound work, so the driver can decide whether a
    /// re-poll is warranted.
    pub fn has_rx(&self) -> bool {
        !self.rx.is_empty()
    }
}

impl Default for ChannelDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl Device for ChannelDevice {
    type RxToken<'a> = RxTokenImpl;
    type TxToken<'a> = TxTokenImpl<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Pop the next inbound packet (releasing the `rx` borrow), then hand the
        // remaining `tx` field to a paired tx token — smoltcp may emit a reply
        // (e.g. an ACK) while consuming a received segment.
        let buffer = self.rx.pop_front()?;
        Some((RxTokenImpl { buffer }, TxTokenImpl { tx: &mut self.tx }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTokenImpl { tx: &mut self.tx })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/// Owns a received packet; `consume` hands its bytes to smoltcp.
pub struct RxTokenImpl {
    buffer: Vec<u8>,
}

impl RxToken for RxTokenImpl {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.buffer)
    }
}

/// Borrows the device's tx queue; `consume` fills a fresh buffer that smoltcp
/// sizes, which is then pushed for the driver to forward.
pub struct TxTokenImpl<'a> {
    tx: &'a mut Vec<Vec<u8>>,
}

impl TxToken for TxTokenImpl<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.tx.push(buffer);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_buffers_are_captured_and_drained() {
        let mut dev = ChannelDevice::new();
        let now = Instant::now();
        let token = Device::transmit(&mut dev, now).unwrap();
        token.consume(4, |buf| {
            buf.copy_from_slice(&[1, 2, 3, 4]);
        });
        let drained = dev.drain_tx();
        assert_eq!(drained, vec![vec![1, 2, 3, 4]]);
        assert!(dev.drain_tx().is_empty());
    }

    #[test]
    fn rx_packets_are_consumed_in_order() {
        let mut dev = ChannelDevice::new();
        dev.push_rx(vec![0xaa]);
        dev.push_rx(vec![0xbb]);
        assert!(dev.has_rx());
        let now = Instant::now();

        let (rx, _tx) = Device::receive(&mut dev, now).unwrap();
        assert_eq!(rx.consume(|b| b.to_vec()), vec![0xaa]);
        let (rx, _tx) = Device::receive(&mut dev, now).unwrap();
        assert_eq!(rx.consume(|b| b.to_vec()), vec![0xbb]);
        assert!(Device::receive(&mut dev, now).is_none());
    }

    #[test]
    fn capabilities_are_ip_medium_with_inner_mtu() {
        let dev = ChannelDevice::new();
        let caps = dev.capabilities();
        assert_eq!(caps.medium, Medium::Ip);
        assert_eq!(caps.max_transmission_unit, INNER_MTU);
    }

    #[test]
    fn with_mtu_sets_transmission_unit() {
        let dev = ChannelDevice::with_mtu(1360);
        assert_eq!(dev.capabilities().max_transmission_unit, 1360);
    }

    #[test]
    fn with_mtu_clamps_out_of_range_values() {
        // Above the ceiling clamps down to INNER_MTU; below the floor clamps up.
        assert_eq!(
            ChannelDevice::with_mtu(INNER_MTU + 500)
                .capabilities()
                .max_transmission_unit,
            INNER_MTU
        );
        assert_eq!(
            ChannelDevice::with_mtu(1)
                .capabilities()
                .max_transmission_unit,
            MIN_INNER_MTU
        );
    }
}
