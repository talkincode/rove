//! Subnetra v1 per-link session state (PROTOCOL.md §4, §5).
//!
//! * [`RxSession`] — one per (peer → us) directional link. Owns the forward-only
//!   epoch ordering, the cached session key, and the anti-replay window. Its
//!   [`RxSession::accept`] implements the security-critical ordering of §5:
//!   **authenticate before mutating any receive state**, and commit a newer epoch
//!   only *after* the datagram authenticates, so a forged higher `epoch` or wrong
//!   `key_id` can never poison the session.
//! * [`TxSession`] — one per (us → peer) directional link. Owns the monotonic
//!   sequence counter (starts at `1`) and seals datagrams.

use std::cmp::Ordering;

use super::crypto::{self, AeadKey, KEY_LEN};
use super::wire::{self, Header};

/// The result of feeding one datagram to an [`RxSession`].
#[derive(Debug)]
pub enum RxOutcome {
    /// Datagram authenticated and passed anti-replay; carries the recovered inner
    /// plaintext (empty for a keepalive). The caller still performs the
    /// inner-source check, endpoint learning, and routing (§5 steps 6a–9).
    Accept(Vec<u8>),
    /// Reject — the caller MUST drop silently with no observable response (§7).
    Drop,
}

/// Receive state for one directional link `(peer → local)`.
pub struct RxSession {
    /// `link_key(psk, peer_id, local_id)` — the receiver derives the same ordered
    /// pair the sender used (§2.1).
    rx_link_key: [u8; KEY_LEN],
    /// Highest epoch accepted on this link (`0` = none yet, §5.3).
    cur_epoch: u64,
    /// AEAD key for `cur_epoch`, cached so the common same-epoch path skips the
    /// KDF. `None` iff `cur_epoch == 0`.
    cur_key: Option<AeadKey>,
    replay: super::replay::ReplayWindow,
}

impl RxSession {
    pub fn new(rx_link_key: [u8; KEY_LEN]) -> Self {
        Self {
            rx_link_key,
            cur_epoch: 0,
            cur_key: None,
            replay: super::replay::ReplayWindow::new(),
        }
    }

    /// Construct a session that has already adopted `epoch` on this link, with a
    /// fresh replay window. `epoch == 0` is identical to [`RxSession::new`]. This
    /// models restored/persisted receive state and is the seam the receiver KAT's
    /// `init_epoch` drives (the `preloaded-session-rejects-stale-epoch` case).
    pub fn with_epoch(rx_link_key: [u8; KEY_LEN], epoch: u64) -> Self {
        let mut s = Self::new(rx_link_key);
        if epoch != 0 {
            s.cur_epoch = epoch;
            // `[u8; 32]` is `Copy`, so `rx_link_key` is still live after `new`.
            s.cur_key = Some(AeadKey::new(&crypto::session_key(&rx_link_key, epoch)));
        }
        s
    }

    /// Run §5 steps 3–6 for a datagram whose header has already been parsed and
    /// passed header validation (§5.2). `body` is `ciphertext || tag`.
    pub fn accept(&mut self, header: &Header, body: &[u8]) -> RxOutcome {
        match header.epoch.cmp(&self.cur_epoch) {
            // Retired session / cross-epoch replay — drop before spending crypto.
            Ordering::Less => RxOutcome::Drop,
            // Same epoch: use the cached key, then anti-replay.
            Ordering::Equal => {
                let Some(key) = self.cur_key.as_ref() else {
                    // cur_epoch == 0 here, which validation already excludes; be safe.
                    return RxOutcome::Drop;
                };
                let Some(pt) = key.open(header.seq, body) else {
                    return RxOutcome::Drop;
                };
                if self.replay.check_and_set(header.seq) {
                    RxOutcome::Accept(pt)
                } else {
                    RxOutcome::Drop
                }
            }
            // Newer epoch: derive a *candidate* key and authenticate BEFORE
            // committing any state (§5.4 → §5.5).
            Ordering::Greater => {
                let candidate = AeadKey::new(&crypto::session_key(&self.rx_link_key, header.epoch));
                let Some(pt) = candidate.open(header.seq, body) else {
                    // Forged higher epoch or wrong key: no state mutated, drop.
                    return RxOutcome::Drop;
                };
                // Authenticated: adopt the epoch and reset the replay window.
                self.cur_epoch = header.epoch;
                self.cur_key = Some(candidate);
                self.replay.reset();
                if self.replay.check_and_set(header.seq) {
                    RxOutcome::Accept(pt)
                } else {
                    RxOutcome::Drop
                }
            }
        }
    }

    /// The highest epoch currently accepted (for diagnostics/tests).
    pub fn current_epoch(&self) -> u64 {
        self.cur_epoch
    }
}

/// Transmit state for one directional link `(local → peer)`.
pub struct TxSession {
    /// `link_key(psk, local_id, peer_id)` (§2.1) — used to seal and to derive the
    /// obfuscation pad.
    tx_link_key: [u8; KEY_LEN],
    /// This node's boot epoch (§2.3), shared across all of its tx links.
    epoch: u64,
    /// AEAD key for `session_key(tx_link_key, epoch)`.
    key: AeadKey,
    /// This node's mesh id, emitted as the `key_id` selector.
    local_id: u16,
    /// Next sequence number; starts at `1`, strictly increasing, never repeats
    /// within an epoch (§4).
    next_seq: u64,
    obfuscate: bool,
}

impl TxSession {
    pub fn new(tx_link_key: [u8; KEY_LEN], local_id: u16, epoch: u64, obfuscate: bool) -> Self {
        let key = AeadKey::new(&crypto::session_key(&tx_link_key, epoch));
        Self {
            tx_link_key,
            epoch,
            key,
            local_id,
            next_seq: 1,
            obfuscate,
        }
    }

    /// Seal an inner packet into a wire datagram, consuming the next `seq`. Pass
    /// [`wire::KEEPALIVE`] with an empty `plaintext` for a NAT keepalive (§3.3).
    pub fn seal(&mut self, flags: u8, plaintext: &[u8]) -> Vec<u8> {
        let seq = self.next_seq;
        // Saturating guard: 2^64 datagrams per epoch is unreachable in practice,
        // but never wrap into a reused (key, nonce) pair — reuse is catastrophic.
        self.next_seq = self.next_seq.saturating_add(1);
        wire::seal_datagram(
            &self.tx_link_key,
            &self.key,
            self.local_id,
            self.epoch,
            seq,
            flags,
            plaintext,
            self.obfuscate,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a matched tx/rx pair for the link (from_id → to_id) under `psk`.
    fn pair(psk: &[u8; 32], from_id: u16, to_id: u16, epoch: u64) -> (TxSession, RxSession) {
        let tx_lk = crypto::link_key(psk, from_id, to_id);
        let rx_lk = crypto::link_key(psk, from_id, to_id); // receiver derives same ordered pair
        (
            TxSession::new(tx_lk, from_id, epoch, false),
            RxSession::new(rx_lk),
        )
    }

    fn open(rx: &mut RxSession, dg: &[u8]) -> RxOutcome {
        let (hdr, body) = wire::split(dg).unwrap();
        let header = Header::parse(hdr).unwrap();
        if !header.is_valid() {
            return RxOutcome::Drop;
        }
        rx.accept(&header, body)
    }

    #[test]
    fn roundtrip_accept() {
        let (mut tx, mut rx) = pair(&[0x5a; 32], 1, 2, 1_704_067_200_000_000_000);
        let dg = tx.seal(0, b"payload");
        match open(&mut rx, &dg) {
            RxOutcome::Accept(pt) => assert_eq!(pt, b"payload"),
            RxOutcome::Drop => panic!("should accept"),
        }
    }

    #[test]
    fn replay_is_dropped() {
        let (mut tx, mut rx) = pair(&[0x5a; 32], 1, 2, 1_704_067_200_000_000_000);
        let dg = tx.seal(0, b"x");
        assert!(matches!(open(&mut rx, &dg), RxOutcome::Accept(_)));
        assert!(matches!(open(&mut rx, &dg), RxOutcome::Drop));
    }

    #[test]
    fn stale_epoch_is_dropped_and_does_not_move_state() {
        let psk = [0x5a; 32];
        // First establish a high epoch.
        let (mut tx_hi, mut rx) = pair(&psk, 1, 2, 2_000_000_000_000_000_000);
        let hi = tx_hi.seal(0, b"new");
        assert!(matches!(open(&mut rx, &hi), RxOutcome::Accept(_)));
        assert_eq!(rx.current_epoch(), 2_000_000_000_000_000_000);
        // A lower-epoch datagram (crafted by a separate tx at an older epoch) drops.
        let tx_lo_lk = crypto::link_key(&psk, 1, 2);
        let mut tx_lo = TxSession::new(tx_lo_lk, 1, 1_704_067_200_000_000_000, false);
        let lo = tx_lo.seal(0, b"old");
        assert!(matches!(open(&mut rx, &lo), RxOutcome::Drop));
        assert_eq!(rx.current_epoch(), 2_000_000_000_000_000_000);
    }

    #[test]
    fn forged_higher_epoch_without_valid_key_does_not_commit() {
        let psk = [0x5a; 32];
        let (mut tx, mut rx) = pair(&psk, 1, 2, 1_704_067_200_000_000_000);
        let good = tx.seal(0, b"ok");
        assert!(matches!(open(&mut rx, &good), RxOutcome::Accept(_)));

        // Craft a datagram with a higher epoch but sealed under the WRONG psk, so
        // it cannot authenticate. It must drop AND leave cur_epoch unchanged.
        let wrong_lk = crypto::link_key(&[0xff; 32], 1, 2);
        let mut evil = TxSession::new(wrong_lk, 1, 9_000_000_000_000_000_000, false);
        let forged = evil.seal(0, b"evil");
        assert!(matches!(open(&mut rx, &forged), RxOutcome::Drop));
        assert_eq!(rx.current_epoch(), 1_704_067_200_000_000_000);

        // The genuine link still works and is not poisoned.
        let good2 = tx.seal(0, b"ok2");
        assert!(matches!(open(&mut rx, &good2), RxOutcome::Accept(_)));
    }

    #[test]
    fn newer_epoch_resets_replay_window() {
        let psk = [0x5a; 32];
        let (mut tx1, mut rx) = pair(&psk, 1, 2, 1_704_067_200_000_000_000);
        let a = tx1.seal(0, b"a"); // seq 1 at epoch1
        assert!(matches!(open(&mut rx, &a), RxOutcome::Accept(_)));

        // New epoch: seq restarts at 1 and must be accepted (window was reset).
        let tx2_lk = crypto::link_key(&psk, 1, 2);
        let mut tx2 = TxSession::new(tx2_lk, 1, 2_000_000_000_000_000_000, false);
        let b = tx2.seal(0, b"b"); // seq 1 at epoch2
        assert!(matches!(open(&mut rx, &b), RxOutcome::Accept(_)));
        assert_eq!(rx.current_epoch(), 2_000_000_000_000_000_000);
    }

    #[test]
    fn obfuscated_roundtrip_via_trial_demask() {
        let psk = [0x5a; 32];
        let epoch = 1_704_067_200_000_000_000;
        let tx_lk = crypto::link_key(&psk, 1, 2);
        let mut tx = TxSession::new(tx_lk, 1, epoch, true);
        let dg = tx.seal(0, b"secret");

        // Receiver trials its one peer key: recompute pad from the cleartext tag,
        // de-mask, check self-consistency, then authenticate.
        let rx_lk = crypto::link_key(&psk, 1, 2);
        let tag = wire::datagram_tag(&dg).unwrap();
        let pad = crypto::obfuscation_pad(&rx_lk, &tag);
        let clear = wire::demask_header(&dg[..20], &pad);
        let header = Header::parse(&clear).unwrap();
        assert!(header.is_valid() && header.key_id == 1);
        let mut rx = RxSession::new(rx_lk);
        let (_, body) = wire::split(&dg).unwrap();
        assert!(matches!(rx.accept(&header, body), RxOutcome::Accept(pt) if pt == b"secret"));
    }
}
