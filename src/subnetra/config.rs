//! Subnetra runtime configuration and its fail-closed validation.
//!
//! The file-format shape mirrors the reference implementation's `config.json`
//! (`local_id`, `obfuscate`, `peers[].{id,psk,allowed_src,endpoint}`) so an
//! operator who knows Subnetra finds it familiar, but it is expressed in Rove's
//! TOML and carries an explicit `mode` (`hub` vs `spoke`) because Rove mounts the
//! two roles onto different halves of its proxy engine.
//!
//! Every enabled config is validated up front and MUST fail closed: a
//! half-configured mesh (bad PSK length, missing spoke endpoint, id collision)
//! aborts startup rather than silently dropping every datagram at runtime.

use std::net::SocketAddr;

use ipnet::Ipv4Net;
use serde::Deserialize;

use super::crypto::KEY_LEN;
use super::{INNER_MTU, MIN_INNER_MTU};

/// The `[subnetra]` block in Rove's config file.
#[derive(Debug, Clone, Deserialize)]
pub struct SubnetraConfig {
    #[serde(default)]
    pub enable: bool,
    /// `hub` (accept spokes, terminate/relay) or `spoke` (dial a hub, egress).
    pub mode: String,
    /// This node's mesh id — the on-wire `key_id` selector. MUST be `0 < id`.
    pub local_id: u16,
    /// UDP `ip:port` the data plane binds to.
    pub listen: String,
    /// This node's own overlay address in CIDR form, e.g. `10.0.0.1/24`. The host
    /// bits are this node's inner IP; the prefix is the mesh's virtual subnet.
    pub overlay_cidr: String,
    /// Header obfuscation (§3.4). On by default; MUST match every mesh member.
    #[serde(default = "default_obfuscate")]
    pub obfuscate: bool,
    /// Spoke NAT-keepalive interval in seconds (§3.3). Ignored for a hub.
    #[serde(default = "default_keepalive_secs")]
    pub keepalive_secs: u64,
    /// Inner overlay MTU (bytes). Optional; defaults to the protocol ceiling
    /// [`INNER_MTU`](crate::subnetra::INNER_MTU) (1452). Lower it when the mesh
    /// rides inside an already-compressed outer tunnel with a smaller fixed path
    /// (e.g. a 1360-byte carrier): smoltcp then advertises a matching TCP MSS so
    /// the sealed outer UDP datagram still fits without fragmentation. MUST be in
    /// `[576, 1452]`; a larger value cannot be honoured (the crypto plaintext is
    /// bounded at the ceiling) and is rejected at startup.
    #[serde(default)]
    pub mtu: Option<usize>,
    /// Hub inbound proxy protocol served on the overlay: `http` or `socks5`.
    /// Required for `mode = "hub"`, ignored for a spoke.
    #[serde(default)]
    pub proxy_protocol: String,
    /// Hub inbound proxy port on the overlay IP. Required for `mode = "hub"`.
    #[serde(default)]
    pub proxy_port: u16,
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

/// One mesh peer (a directional pair of links share this entry).
#[derive(Debug, Clone, Deserialize)]
pub struct PeerConfig {
    /// Peer mesh id. MUST be non-zero, unique, and different from `local_id`.
    pub id: u16,
    /// Per-link 32-byte pre-shared key as 64 lowercase hex chars. MUST be unique
    /// per link (§2.1) — never reuse one PSK across peers.
    pub psk: String,
    /// The inner IPv4 prefix this peer may source from and that routes to it
    /// (§5.7 inner-source check + §5.9 routing), e.g. `10.0.0.2/32`.
    pub allowed_src: String,
    /// The peer's UDP endpoint. Optional for a hub (learned from authenticated
    /// traffic, §5.8); REQUIRED for a spoke (it must know where to dial).
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Human-friendly label for logs.
    #[serde(default)]
    pub name: String,
}

fn default_obfuscate() -> bool {
    true
}

fn default_keepalive_secs() -> u64 {
    25
}

/// The node role. Both roles run the identical data plane; the difference is
/// which side of Rove's proxy engine the userspace IP stack attaches to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Hub,
    Spoke,
}

impl Mode {
    fn parse(s: &str) -> anyhow::Result<Mode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "hub" => Ok(Mode::Hub),
            "spoke" => Ok(Mode::Spoke),
            other => anyhow::bail!("subnetra.mode must be \"hub\" or \"spoke\", got {other:?}"),
        }
    }
}

/// A validated, runtime-ready peer.
#[derive(Debug, Clone)]
pub struct RuntimePeer {
    pub id: u16,
    pub psk: [u8; KEY_LEN],
    pub allowed_src: Ipv4Net,
    pub endpoint: Option<SocketAddr>,
    pub name: String,
}

/// A validated, runtime-ready data-plane configuration.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub mode: Mode,
    pub local_id: u16,
    pub listen: SocketAddr,
    pub overlay: Ipv4Net,
    pub obfuscate: bool,
    pub keepalive_secs: u64,
    /// Validated inner overlay MTU, resolved to [`INNER_MTU`] when unset.
    pub mtu: usize,
    /// Hub inbound proxy: `(protocol, port)` served on the overlay IP. `None`
    /// for a spoke (egress-only).
    pub hub_proxy: Option<(String, u16)>,
    pub peers: Vec<RuntimePeer>,
}

impl RuntimeConfig {
    /// This node's own inner IPv4 address (the host part of `overlay_cidr`).
    pub fn overlay_ip(&self) -> std::net::Ipv4Addr {
        self.overlay.addr()
    }
}

/// Parse 64 hex chars into a 32-byte key. Rejects wrong length or non-hex.
fn parse_psk(s: &str) -> anyhow::Result<[u8; KEY_LEN]> {
    let s = s.trim();
    anyhow::ensure!(
        s.len() == KEY_LEN * 2,
        "psk must be {} hex chars (32 bytes), got {}",
        KEY_LEN * 2,
        s.len()
    );
    let mut key = [0u8; KEY_LEN];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow::anyhow!("psk contains non-hex characters"))?;
    }
    Ok(key)
}

impl SubnetraConfig {
    /// Validate and lower to a [`RuntimeConfig`]. Fails closed on any problem so a
    /// misconfigured mesh never starts (a running-but-broken mesh looks like a
    /// routing bug, which is far harder to diagnose than a startup error).
    pub fn to_runtime(&self) -> anyhow::Result<RuntimeConfig> {
        let mode = Mode::parse(&self.mode)?;

        anyhow::ensure!(
            self.local_id != 0,
            "subnetra.local_id must be non-zero (0 < id <= 65535)"
        );

        let listen: SocketAddr = self.listen.trim().parse().map_err(|e| {
            anyhow::anyhow!("subnetra.listen {:?} is not ip:port: {e}", self.listen)
        })?;

        let overlay: Ipv4Net = self.overlay_cidr.trim().parse().map_err(|e| {
            anyhow::anyhow!(
                "subnetra.overlay_cidr {:?} is not an IPv4 CIDR: {e}",
                self.overlay_cidr
            )
        })?;

        anyhow::ensure!(
            !self.peers.is_empty(),
            "subnetra requires at least one peer when enabled"
        );

        // Inner overlay MTU: default to the protocol ceiling, but let an operator
        // shrink it to fit an already-compressed outer tunnel. Reject values that
        // exceed the ceiling (the sealed plaintext cannot be larger) or fall below
        // the IPv4 minimum-reassembly floor.
        let mtu = match self.mtu {
            None => INNER_MTU,
            Some(v) => {
                anyhow::ensure!(
                    (MIN_INNER_MTU..=INNER_MTU).contains(&v),
                    "subnetra.mtu {v} out of range [{MIN_INNER_MTU}, {INNER_MTU}]"
                );
                v
            }
        };

        // A hub terminates overlay TCP into Rove's proxy, so it needs a protocol
        // and port; a spoke is egress-only and ignores these.
        let hub_proxy = if mode == Mode::Hub {
            let proto = self.proxy_protocol.trim().to_ascii_lowercase();
            anyhow::ensure!(
                proto == "http" || proto == "socks5",
                "subnetra hub requires proxy_protocol \"http\" or \"socks5\", got {:?}",
                self.proxy_protocol
            );
            anyhow::ensure!(
                self.proxy_port != 0,
                "subnetra hub requires a non-zero proxy_port"
            );
            Some((proto, self.proxy_port))
        } else {
            None
        };

        let mut peers = Vec::with_capacity(self.peers.len());
        let mut seen_ids = std::collections::HashSet::new();
        for p in &self.peers {
            anyhow::ensure!(p.id != 0, "peer id must be non-zero");
            anyhow::ensure!(
                p.id != self.local_id,
                "peer id {} collides with subnetra.local_id",
                p.id
            );
            anyhow::ensure!(
                seen_ids.insert(p.id),
                "duplicate peer id {} in subnetra.peers",
                p.id
            );

            let psk = parse_psk(&p.psk)
                .map_err(|e| anyhow::anyhow!("peer {} (id {}): {e}", p.name, p.id))?;

            let allowed_src: Ipv4Net = p.allowed_src.trim().parse().map_err(|e| {
                anyhow::anyhow!(
                    "peer {} (id {}) allowed_src {:?} is not an IPv4 CIDR: {e}",
                    p.name,
                    p.id,
                    p.allowed_src
                )
            })?;

            let endpoint = match &p.endpoint {
                Some(ep) => Some(ep.trim().parse::<SocketAddr>().map_err(|e| {
                    anyhow::anyhow!(
                        "peer {} (id {}) endpoint {:?} is not ip:port: {e}",
                        p.name,
                        p.id,
                        ep
                    )
                })?),
                None => None,
            };

            // A spoke dials its hub, so every peer it knows MUST have an endpoint.
            if mode == Mode::Spoke {
                anyhow::ensure!(
                    endpoint.is_some(),
                    "spoke peer {} (id {}) requires an endpoint to dial",
                    p.name,
                    p.id
                );
            }

            peers.push(RuntimePeer {
                id: p.id,
                psk,
                allowed_src,
                endpoint,
                name: p.name.clone(),
            });
        }

        Ok(RuntimeConfig {
            mode,
            local_id: self.local_id,
            listen,
            overlay,
            obfuscate: self.obfuscate,
            keepalive_secs: self.keepalive_secs,
            mtu,
            hub_proxy,
            peers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> SubnetraConfig {
        SubnetraConfig {
            enable: true,
            mode: "hub".into(),
            local_id: 1,
            listen: "0.0.0.0:18020".into(),
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
                endpoint: Some("203.0.113.2:18020".into()),
                name: "spoke-a".into(),
            }],
        }
    }

    #[test]
    fn valid_hub_config_lowers() {
        let rt = base().to_runtime().unwrap();
        assert_eq!(rt.mode, Mode::Hub);
        assert_eq!(rt.local_id, 1);
        assert_eq!(rt.overlay_ip().to_string(), "10.0.0.1");
        assert_eq!(rt.peers.len(), 1);
        assert_eq!(rt.peers[0].psk, [0x5a; 32]);
    }

    #[test]
    fn mtu_defaults_to_ceiling_when_unset() {
        let rt = base().to_runtime().unwrap();
        assert_eq!(rt.mtu, INNER_MTU);
    }

    #[test]
    fn mtu_accepts_value_in_range() {
        let mut c = base();
        c.mtu = Some(1360);
        assert_eq!(c.to_runtime().unwrap().mtu, 1360);
    }

    #[test]
    fn mtu_rejects_above_ceiling() {
        let mut c = base();
        c.mtu = Some(INNER_MTU + 1);
        assert!(c.to_runtime().is_err());
    }

    #[test]
    fn mtu_rejects_below_floor() {
        let mut c = base();
        c.mtu = Some(MIN_INNER_MTU - 1);
        assert!(c.to_runtime().is_err());
    }

    #[test]
    fn rejects_bad_psk_length() {
        let mut c = base();
        c.peers[0].psk = "5a".repeat(31); // 62 chars
        assert!(c.to_runtime().is_err());
    }

    #[test]
    fn rejects_non_hex_psk() {
        let mut c = base();
        c.peers[0].psk = "zz".repeat(32);
        assert!(c.to_runtime().is_err());
    }

    #[test]
    fn rejects_zero_and_colliding_ids() {
        let mut c = base();
        c.peers[0].id = 0;
        assert!(c.to_runtime().is_err());
        let mut c = base();
        c.peers[0].id = 1; // == local_id
        assert!(c.to_runtime().is_err());
    }

    #[test]
    fn rejects_duplicate_peer_ids() {
        let mut c = base();
        c.peers.push(c.peers[0].clone());
        assert!(c.to_runtime().is_err());
    }

    #[test]
    fn spoke_requires_peer_endpoint() {
        let mut c = base();
        c.mode = "spoke".into();
        c.peers[0].endpoint = None;
        assert!(c.to_runtime().is_err());
        // With an endpoint it lowers fine.
        c.peers[0].endpoint = Some("203.0.113.2:18020".into());
        assert_eq!(c.to_runtime().unwrap().mode, Mode::Spoke);
    }

    #[test]
    fn rejects_unknown_mode() {
        let mut c = base();
        c.mode = "relay".into();
        assert!(c.to_runtime().is_err());
    }
}
