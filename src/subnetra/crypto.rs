//! Subnetra v1 cryptographic primitives (PROTOCOL.md §2).
//!
//! Two primitives, no negotiation, no handshake:
//!
//! * **KDF / keyed hash** — BLAKE2b-256 in *native keyed mode* (the key occupies
//!   the first BLAKE2 input block; this is **not** HMAC-BLAKE2b). All multi-byte
//!   integers fed into the KDF are **big-endian**; the label strings are ASCII
//!   with no NUL terminator.
//! * **AEAD** — ChaCha20-Poly1305 (IETF, 96-bit nonce), empty associated data,
//!   16-byte tag appended after the ciphertext.
//!
//! Every constant below (labels, their lengths, endianness) is pinned to the
//! cross-implementation KAT in `tests/subnetra_conformance.rs`; if the prose and
//! the vectors ever disagree, the vectors win.

use blake2::digest::{consts::U32, Mac};
use blake2::Blake2bMac;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

/// KDF label for per-link key derivation (§2.1). 16 bytes — note the PROTOCOL.md
/// prose comment says "15 bytes", but the KAT vectors prove it is 16.
const LABEL_LINK: &[u8] = b"subnetra-v1-link";
/// KDF label for per-session key derivation (§2.1).
const LABEL_SESSION: &[u8] = b"subnetra-v1-session";
/// KDF label for the header obfuscation pad (§3.4).
const LABEL_OBFS: &[u8] = b"subnetra-v1-obfs";

/// Fixed sizes (§2, §3).
pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const HEADER_LEN: usize = 20;
/// AEAD nonce width in bytes (96-bit IETF nonce).
const NONCE_LEN: usize = 12;

type Blake2bMac256 = Blake2bMac<U32>;

/// BLAKE2b-256 in keyed mode: `digest = BLAKE2b(key, msg)` with a 32-byte output.
///
/// The key length parameter equals the key's byte length, exactly as the spec
/// mandates. `new_from_slice` accepts any key of 1..=64 bytes (BLAKE2b's range);
/// all callers here pass a 32-byte key, so the error arm is unreachable in
/// practice but is surfaced rather than unwrapped for defence in depth.
fn blake2b_keyed(key: &[u8], parts: &[&[u8]]) -> [u8; KEY_LEN] {
    let mut mac = Blake2bMac256::new_from_slice(key)
        .expect("subnetra KDF key must be 1..=64 bytes (always 32 here)");
    for p in parts {
        mac.update(p);
    }
    let out = mac.finalize().into_bytes();
    let mut digest = [0u8; KEY_LEN];
    digest.copy_from_slice(&out);
    digest
}

/// `link_key(psk, from_id, to_id)` (§2.1).
///
/// Directional: the sender uses `link_key(psk, local_id, peer_id)` and the
/// receiver derives the match with `link_key(psk, peer_id, local_id)`. `psk` is a
/// per-link 32-byte pre-shared key and MUST NOT be reused across peers.
pub fn link_key(psk: &[u8; KEY_LEN], from_id: u16, to_id: u16) -> [u8; KEY_LEN] {
    // The ids are u16 on the wire (§3.1) but fed into the KDF as u32 big-endian.
    let from_be = (from_id as u32).to_be_bytes();
    let to_be = (to_id as u32).to_be_bytes();
    blake2b_keyed(psk, &[LABEL_LINK, &from_be, &to_be])
}

/// `session_key(link_key, epoch)` (§2.1). Epoch is fed in big-endian.
pub fn session_key(link_key: &[u8; KEY_LEN], epoch: u64) -> [u8; KEY_LEN] {
    blake2b_keyed(link_key, &[LABEL_SESSION, &epoch.to_be_bytes()])
}

/// Header obfuscation pad (§3.4): `BLAKE2b(link_key, "subnetra-v1-obfs" || tag)`
/// truncated to the 20-byte header length. The pad is keyed by the *link* key
/// (shared by both ends) and salted by the datagram's own 16-byte AEAD tag, which
/// travels in the clear, so a receiver can reproduce it before authenticating.
pub fn obfuscation_pad(link_key: &[u8; KEY_LEN], tag: &[u8; TAG_LEN]) -> [u8; HEADER_LEN] {
    let full = blake2b_keyed(link_key, &[LABEL_OBFS, tag]);
    let mut pad = [0u8; HEADER_LEN];
    pad.copy_from_slice(&full[..HEADER_LEN]);
    pad
}

/// The 96-bit AEAD nonce derived from the 64-bit sequence number (§2.2):
/// `nonce(seq) = u64_le(seq) || 0x00 0x00 0x00 0x00`.
fn nonce(seq: u64) -> Nonce {
    let mut raw = [0u8; NONCE_LEN];
    raw[..8].copy_from_slice(&seq.to_le_bytes());
    Nonce::assume_unique_for_key(raw)
}

/// A session AEAD key: ChaCha20-Poly1305 bound to one `session_key`. Constructing
/// it runs the key schedule once, so it is cached per epoch by the sessions.
pub struct AeadKey(LessSafeKey);

impl AeadKey {
    pub fn new(session_key: &[u8; KEY_LEN]) -> Self {
        let unbound = UnboundKey::new(&CHACHA20_POLY1305, session_key)
            .expect("32-byte ChaCha20-Poly1305 key is always valid");
        AeadKey(LessSafeKey::new(unbound))
    }

    /// Seal `plaintext` under `nonce(seq)` with empty AAD, returning
    /// `ciphertext || tag`. The `(session_key, nonce)` uniqueness invariant is the
    /// caller's responsibility (a fresh epoch re-keys the session, §2.3).
    pub fn seal(&self, seq: u64, plaintext: &[u8]) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        self.0
            .seal_in_place_append_tag(nonce(seq), Aad::empty(), &mut buf)
            .expect("ChaCha20-Poly1305 seal is infallible for in-memory buffers");
        buf
    }

    /// Open `ciphertext || tag` under `nonce(seq)` with empty AAD. Returns the
    /// recovered plaintext on success, or `None` on authentication failure or
    /// truncation — callers MUST treat `None` as a silent drop (§5, §7).
    pub fn open(&self, seq: u64, body: &[u8]) -> Option<Vec<u8>> {
        if body.len() < TAG_LEN {
            return None;
        }
        let mut buf = body.to_vec();
        match self.0.open_in_place(nonce(seq), Aad::empty(), &mut buf) {
            Ok(plaintext) => Some(plaintext.to_vec()),
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let sk = session_key(&link_key(&[0x5a; 32], 1, 2), 1_704_067_200_000_000_000);
        let key = AeadKey::new(&sk);
        let pt = b"the inner ip packet";
        let body = key.seal(7, pt);
        assert_eq!(body.len(), pt.len() + TAG_LEN);
        assert_eq!(key.open(7, &body).as_deref(), Some(&pt[..]));
        // Wrong seq => wrong nonce => auth failure => drop.
        assert!(key.open(8, &body).is_none());
    }

    #[test]
    fn tampered_body_fails_open() {
        let sk = session_key(&link_key(&[0x11; 32], 3, 4), 1_704_067_200_000_000_001);
        let key = AeadKey::new(&sk);
        let mut body = key.seal(1, b"x");
        let last = body.len() - 1;
        body[last] ^= 0x01;
        assert!(key.open(1, &body).is_none());
    }

    #[test]
    fn link_key_is_directional() {
        let psk = [0x5a; 32];
        assert_ne!(link_key(&psk, 1, 2), link_key(&psk, 2, 1));
    }
}
