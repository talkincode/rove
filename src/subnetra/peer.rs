//! Subnetra peer table: identity selection, the security steps of §5 that are
//! *per-peer* (inner-source check, endpoint learning), and inner-destination
//! routing (§5.9).
//!
//! The reactor ([`super::reactor`]) owns exactly one [`PeerTable`] on a single
//! task, so every method takes `&mut self` and no locking is needed — this
//! mirrors the reference implementation's single-reactor design while leaving the
//! rest of Rove free to run on other Tokio tasks.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use ipnet::Ipv4Net;

use super::config::RuntimeConfig;
use super::crypto::{self, HEADER_LEN};
use super::session::{RxOutcome, RxSession, TxSession};
use super::wire::{self, Header, WIRE_VERSION};

/// A single mesh peer and its two directional sessions.
struct Peer {
    id: u16,
    name: String,
    /// Inner prefix this peer owns: the §5.7 inner-source filter and the §5.9
    /// routing key both use it.
    allowed_src: Ipv4Net,
    /// Current UDP endpoint — configured and/or learned from authenticated
    /// traffic (§5.8). `None` until first learned (hub side).
    endpoint: Option<SocketAddr>,
    /// `link_key(psk, peer_id, local_id)` raw bytes, kept for the obfuscation
    /// trial de-mask (§3.4) which needs the key before a session exists.
    rx_link_key: [u8; crypto::KEY_LEN],
    rx: RxSession,
    tx: TxSession,
}

/// The outcome of feeding one received datagram to the table.
#[derive(Debug, PartialEq, Eq)]
pub enum Ingest {
    /// Authenticated inner IPv4 data packet that passed the inner-source check.
    /// The reactor routes it by inner destination (deliver-local or hub-relay).
    Data { peer_id: u16, inner: Vec<u8> },
    /// Authenticated NAT keepalive (§3.3): the endpoint was learned, nothing is
    /// delivered.
    Keepalive { peer_id: u16 },
    /// Reject — the caller drops silently (§7).
    Drop,
}

pub struct PeerTable {
    local_id: u16,
    obfuscate: bool,
    peers: Vec<Peer>,
    by_id: HashMap<u16, usize>,
}

impl PeerTable {
    /// Build the table from validated config, sampling `local_epoch` once (the
    /// node's boot epoch, §2.3) for every transmit session.
    pub fn new(cfg: &RuntimeConfig, local_epoch: u64) -> Self {
        let mut peers = Vec::with_capacity(cfg.peers.len());
        let mut by_id = HashMap::new();
        for (i, p) in cfg.peers.iter().enumerate() {
            let rx_link_key = crypto::link_key(&p.psk, p.id, cfg.local_id);
            let tx_link_key = crypto::link_key(&p.psk, cfg.local_id, p.id);
            let rx = RxSession::new(rx_link_key);
            let tx = TxSession::new(tx_link_key, cfg.local_id, local_epoch, cfg.obfuscate);
            by_id.insert(p.id, i);
            peers.push(Peer {
                id: p.id,
                name: p.name.clone(),
                allowed_src: p.allowed_src,
                endpoint: p.endpoint,
                rx_link_key,
                rx,
                tx,
            });
        }
        Self {
            local_id: cfg.local_id,
            obfuscate: cfg.obfuscate,
            peers,
            by_id,
        }
    }

    /// Step 1–2: select the sending peer and recover its cleartext header. Under
    /// obfuscation the header is masked, so each peer's receive key is trialled
    /// (§3.4): recompute the pad from the cleartext tag, de-mask, and accept the
    /// candidate whose recovered header is self-consistent (`version == 1` and
    /// `key_id == peer.id`). Returns the peer index and validated header, or
    /// `None` to drop (unknown `key_id` / no trial match / invalid header).
    fn select(&self, datagram: &[u8], tag: &[u8; crypto::TAG_LEN]) -> Option<(usize, Header)> {
        if self.obfuscate {
            for (i, p) in self.peers.iter().enumerate() {
                let pad = crypto::obfuscation_pad(&p.rx_link_key, tag);
                let clear = wire::demask_header(&datagram[..HEADER_LEN], &pad);
                let header = Header::parse(&clear)?;
                if header.version == WIRE_VERSION && header.key_id == p.id && header.is_valid() {
                    return Some((i, header));
                }
            }
            None
        } else {
            let header = Header::parse(&datagram[..HEADER_LEN])?;
            let idx = *self.by_id.get(&header.key_id)?;
            if header.is_valid() {
                Some((idx, header))
            } else {
                None
            }
        }
    }

    /// Run the full receive path (§5) for one datagram arriving from `src`.
    pub fn ingest(&mut self, datagram: &[u8], src: SocketAddr) -> Ingest {
        // The tag is needed both to authenticate and (under obfuscation) to
        // select; if the datagram is too short to hold header + tag, drop (§5.2).
        let Some(tag) = wire::datagram_tag(datagram) else {
            return Ingest::Drop;
        };
        let Some((idx, header)) = self.select(datagram, &tag) else {
            return Ingest::Drop;
        };

        let body = &datagram[HEADER_LEN..];
        let inner = match self.peers[idx].rx.accept(&header, body) {
            RxOutcome::Accept(pt) => pt,
            RxOutcome::Drop => return Ingest::Drop,
        };
        let peer_id = self.peers[idx].id;

        // Step 6a: an authenticated keepalive learns the endpoint and stops — no
        // inner-source check, no routing, nothing delivered (§3.3, §5.6a).
        if header.is_keepalive() {
            self.peers[idx].endpoint = Some(src);
            return Ingest::Keepalive { peer_id };
        }

        // Step 7: the decrypted packet's inner source MUST fall in the peer's
        // allowed_src prefix (defeats inner-source spoofing by an authed peer).
        let Some(inner_src) = ipv4_src(&inner) else {
            return Ingest::Drop;
        };
        if !self.peers[idx].allowed_src.contains(&inner_src) {
            return Ingest::Drop;
        }

        // Step 8: only now — fully authenticated and inner-source-checked — learn
        // the endpoint, so a replayed/forged/spoofed datagram can never move it.
        self.peers[idx].endpoint = Some(src);

        Ingest::Data { peer_id, inner }
    }

    /// Route an inner destination to the peer that owns it (§5.9), by
    /// longest-prefix match over `allowed_src`. `None` = no route (drop).
    pub fn route(&self, dst: Ipv4Addr) -> Option<u16> {
        self.peers
            .iter()
            .filter(|p| p.allowed_src.contains(&dst))
            .max_by_key(|p| p.allowed_src.prefix_len())
            .map(|p| p.id)
    }

    /// Seal `inner` (or an empty keepalive) for `peer_id`, returning the wire
    /// datagram and the destination endpoint. `None` if the peer is unknown or
    /// its endpoint is not yet known (a hub that has never heard from a spoke
    /// cannot send to it — fail closed rather than blast to a guessed address).
    pub fn seal_for(
        &mut self,
        peer_id: u16,
        flags: u8,
        inner: &[u8],
    ) -> Option<(Vec<u8>, SocketAddr)> {
        let idx = *self.by_id.get(&peer_id)?;
        let endpoint = self.peers[idx].endpoint?;
        let datagram = self.peers[idx].tx.seal(flags, inner);
        Some((datagram, endpoint))
    }

    /// Peer ids that currently have a known endpoint (used by the spoke keepalive
    /// timer and diagnostics).
    pub fn peers_with_endpoint(&self) -> Vec<u16> {
        self.peers
            .iter()
            .filter(|p| p.endpoint.is_some())
            .map(|p| p.id)
            .collect()
    }

    /// All configured peer ids.
    pub fn peer_ids(&self) -> Vec<u16> {
        self.peers.iter().map(|p| p.id).collect()
    }

    /// This node's mesh id.
    pub fn local_id(&self) -> u16 {
        self.local_id
    }

    /// Look up a peer's label for logging.
    pub fn name_of(&self, peer_id: u16) -> Option<&str> {
        self.by_id
            .get(&peer_id)
            .map(|&i| self.peers[i].name.as_str())
    }
}

/// Extract the source IPv4 address of a complete inner IPv4 packet, or `None` if
/// it is not a well-formed IPv4 header (too short or wrong version nibble).
pub fn ipv4_src(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || (packet[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ))
}

/// Extract the destination IPv4 address of a complete inner IPv4 packet.
pub fn ipv4_dst(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || (packet[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subnetra::config::{PeerConfig, SubnetraConfig};

    const EPOCH: u64 = 1_704_067_200_000_000_000;

    fn hub_and_spoke(obfuscate: bool) -> (PeerTable, PeerTable) {
        // Hub = id 1 (10.0.0.1), spoke = id 2 (10.0.0.2), shared per-link psk.
        let psk = "5a".repeat(32);
        let hub_cfg = SubnetraConfig {
            enable: true,
            mode: "hub".into(),
            local_id: 1,
            listen: "0.0.0.0:18020".into(),
            overlay_cidr: "10.0.0.1/24".into(),
            obfuscate,
            keepalive_secs: 25,
            mtu: None,
            proxy_protocol: "http".into(),
            proxy_port: 8080,
            peers: vec![PeerConfig {
                id: 2,
                psk: psk.clone(),
                allowed_src: "10.0.0.2/32".into(),
                endpoint: None, // hub learns it
                name: "spoke".into(),
            }],
        }
        .to_runtime()
        .unwrap();
        let spoke_cfg = SubnetraConfig {
            enable: true,
            mode: "spoke".into(),
            local_id: 2,
            listen: "0.0.0.0:0".into(),
            overlay_cidr: "10.0.0.2/24".into(),
            obfuscate,
            keepalive_secs: 25,
            mtu: None,
            proxy_protocol: "http".into(),
            proxy_port: 8080,
            peers: vec![PeerConfig {
                id: 1,
                psk,
                allowed_src: "10.0.0.1/32".into(),
                endpoint: Some("203.0.113.1:18020".into()),
                name: "hub".into(),
            }],
        }
        .to_runtime()
        .unwrap();
        (
            PeerTable::new(&hub_cfg, EPOCH),
            PeerTable::new(&spoke_cfg, EPOCH),
        )
    }

    /// A minimal well-formed inner IPv4 packet from `src` to `dst`.
    fn inner_packet(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45; // v4, IHL 5
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    #[test]
    fn spoke_to_hub_roundtrip_learns_endpoint() {
        for obfuscate in [false, true] {
            let (mut hub, mut spoke) = hub_and_spoke(obfuscate);
            let spoke_src: SocketAddr = "198.51.100.9:40000".parse().unwrap();

            // Spoke seals a packet 10.0.0.2 -> 10.0.0.1 for the hub (id 1).
            let pkt = inner_packet([10, 0, 0, 2], [10, 0, 0, 1]);
            let (dg, dst) = spoke.seal_for(1, 0, &pkt).unwrap();
            assert_eq!(dst.to_string(), "203.0.113.1:18020");

            // Hub ingests it: authenticates, passes inner-source, learns endpoint.
            match hub.ingest(&dg, spoke_src) {
                Ingest::Data { peer_id, inner } => {
                    assert_eq!(peer_id, 2);
                    assert_eq!(inner, pkt);
                }
                other => panic!("expected Data, got {other:?}"),
            }
            // Now the hub can reach the spoke at the learned endpoint.
            let reply = inner_packet([10, 0, 0, 1], [10, 0, 0, 2]);
            let (_, learned) = hub.seal_for(2, 0, &reply).unwrap();
            assert_eq!(learned, spoke_src);
        }
    }

    #[test]
    fn inner_source_spoofing_is_dropped() {
        let (mut hub, mut spoke) = hub_and_spoke(false);
        // Spoke (allowed 10.0.0.2/32) forges a packet claiming source 10.0.0.9.
        let forged = inner_packet([10, 0, 0, 9], [10, 0, 0, 1]);
        let (dg, _) = spoke.seal_for(1, 0, &forged).unwrap();
        assert_eq!(
            hub.ingest(&dg, "198.51.100.9:1".parse().unwrap()),
            Ingest::Drop
        );
    }

    #[test]
    fn keepalive_learns_endpoint_without_delivery() {
        let (mut hub, mut spoke) = hub_and_spoke(true);
        let spoke_src: SocketAddr = "198.51.100.9:40000".parse().unwrap();
        let (dg, _) = spoke.seal_for(1, wire::KEEPALIVE, &[]).unwrap();
        assert_eq!(hub.ingest(&dg, spoke_src), Ingest::Keepalive { peer_id: 2 });
        // Endpoint learned even though nothing was delivered.
        let reply = inner_packet([10, 0, 0, 1], [10, 0, 0, 2]);
        let (_, learned) = hub.seal_for(2, 0, &reply).unwrap();
        assert_eq!(learned, spoke_src);
    }

    #[test]
    fn hub_cannot_send_to_unlearned_spoke() {
        let (mut hub, _spoke) = hub_and_spoke(false);
        let reply = inner_packet([10, 0, 0, 1], [10, 0, 0, 2]);
        // No traffic heard yet => no endpoint => fail closed.
        assert!(hub.seal_for(2, 0, &reply).is_none());
    }

    #[test]
    fn routing_prefers_longest_prefix() {
        let psk = "5a".repeat(32);
        let cfg = SubnetraConfig {
            enable: true,
            mode: "hub".into(),
            local_id: 1,
            listen: "0.0.0.0:18020".into(),
            overlay_cidr: "10.0.0.1/24".into(),
            obfuscate: false,
            keepalive_secs: 25,
            mtu: None,
            proxy_protocol: "http".into(),
            proxy_port: 8080,
            peers: vec![
                PeerConfig {
                    id: 2,
                    psk: psk.clone(),
                    allowed_src: "10.0.0.0/24".into(),
                    endpoint: None,
                    name: "wide".into(),
                },
                PeerConfig {
                    id: 3,
                    psk,
                    allowed_src: "10.0.0.5/32".into(),
                    endpoint: None,
                    name: "specific".into(),
                },
            ],
        }
        .to_runtime()
        .unwrap();
        let table = PeerTable::new(&cfg, EPOCH);
        assert_eq!(table.route("10.0.0.5".parse().unwrap()), Some(3)); // longest prefix
        assert_eq!(table.route("10.0.0.6".parse().unwrap()), Some(2)); // falls to /24
        assert_eq!(table.route("192.168.0.1".parse().unwrap()), None); // no route
    }

    #[test]
    fn cross_mesh_datagram_is_dropped() {
        // A datagram sealed under a different psk must not authenticate.
        let (mut hub, _) = hub_and_spoke(false);
        let other = {
            let cfg = SubnetraConfig {
                enable: true,
                mode: "spoke".into(),
                local_id: 2,
                listen: "0.0.0.0:0".into(),
                overlay_cidr: "10.0.0.2/24".into(),
                obfuscate: false,
                keepalive_secs: 25,
                mtu: None,
                proxy_protocol: "http".into(),
                proxy_port: 8080,
                peers: vec![PeerConfig {
                    id: 1,
                    psk: "ff".repeat(32), // wrong psk
                    allowed_src: "10.0.0.1/32".into(),
                    endpoint: Some("203.0.113.1:18020".into()),
                    name: "hub".into(),
                }],
            }
            .to_runtime()
            .unwrap();
            PeerTable::new(&cfg, EPOCH)
        };
        let mut other = other;
        let pkt = inner_packet([10, 0, 0, 2], [10, 0, 0, 1]);
        let (dg, _) = other.seal_for(1, 0, &pkt).unwrap();
        assert_eq!(
            hub.ingest(&dg, "198.51.100.9:1".parse().unwrap()),
            Ingest::Drop
        );
    }
}
