//! Subnetra — an embedded, pure-Rust implementation of the Subnetra v1 wire
//! protocol, giving Rove a pluggable, lightweight Layer-3 mesh underlay.
//!
//! # Why it lives inside Rove
//!
//! Subnetra ([`jamiesun/subnetra`](https://github.com/jamiesun/subnetra)) is a
//! zero-dependency Layer-3 UDP tunnel. Running it as a separate daemon would
//! complicate Rove's deployment story, so instead Rove speaks the protocol
//! natively and exposes it as two mount points on the existing proxy engine:
//!
//! * **hub role (inbound)** — accept spokes (including the reference Zig
//!   implementation), terminate the overlay TCP in a userspace IP stack, and hand
//!   the stream to Rove's HTTP/SOCKS dispatch.
//! * **spoke role (outbound egress)** — dial another hub and carry proxied
//!   traffic out through an isolated network segment.
//!
//! Both roles are the *same* data plane; hub vs. spoke is a configuration
//! difference, not a different codec.
//!
//! # No TUN, all userspace
//!
//! PROTOCOL.md §1 explicitly permits "a kernel TUN device, a userspace IP stack,
//! or an application buffer" as the inner packet source. Rove uses a userspace IP
//! stack, so the integration needs no `NET_ADMIN`, no TUN device, and no kernel
//! routing changes.
//!
//! # Compatibility gate
//!
//! The wire format is frozen and mechanically verifiable: every primitive here is
//! pinned to the cross-implementation known-answer-test vectors in
//! `tests/subnetra_conformance.rs` (vendored from the reference repo). Any drift
//! from the Zig reference fails CI, which is what lets an existing Subnetra mesh
//! connect to Rove unchanged.

pub mod config;
pub mod crypto;
pub mod netstack;
pub mod peer;
pub mod reactor;
pub mod replay;
pub mod service;
pub mod session;
pub mod wire;

/// The minimum wall-clock boot epoch a conformant node may use: 2024-01-01T00:00Z
/// in nanoseconds (§2.3). A node whose clock cannot satisfy this MUST fail closed
/// rather than emit a low/zero epoch that peers would reject.
pub const MIN_EPOCH_NS: u64 = 1_704_067_200_000_000_000;

/// The v1 `raw_direct` inner tunnel MTU (§8): `1500 - 64` bytes of overhead,
/// rounded to the reference implementation's value. This is the protocol
/// *ceiling* on inner plaintext; an operator may configure a smaller device MTU
/// (see [`config::SubnetraConfig::mtu`]) when the mesh rides inside an
/// already-compressed outer tunnel, but never a larger one.
pub const INNER_MTU: usize = 1452;

/// The smallest inner MTU an operator may configure: the IPv4 minimum-reassembly
/// buffer (§ RFC 791). Below this, TCP/IP itself cannot make forward progress, so
/// a smaller request is a configuration error rather than a tighter tunnel.
pub const MIN_INNER_MTU: usize = 576;

/// Sample this node's boot epoch (§2.3): wall-clock nanoseconds since the Unix
/// epoch. Fails closed if the clock is before 2024-01-01 (or unreadable), because
/// a low/zero epoch would be rejected by every peer and a backward clock across a
/// restart re-emits a retired epoch — both are operational faults, not something
/// the handshake-free protocol can fix in-band.
pub fn sample_boot_epoch() -> anyhow::Result<u64> {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock is before the Unix epoch: {e}"))?
        .as_nanos();
    let epoch = u64::try_from(ns).map_err(|_| anyhow::anyhow!("boot epoch overflows u64"))?;
    anyhow::ensure!(
        epoch >= MIN_EPOCH_NS,
        "system clock ({epoch} ns) is before 2024-01-01; subnetra refuses to start with a low epoch (§2.3)"
    );
    Ok(epoch)
}
