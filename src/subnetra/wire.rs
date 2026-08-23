//! Subnetra v1 on-wire datagram format (PROTOCOL.md §3, §4).
//!
//! ```text
//! +------------------+---------------------------+----------------+
//! |  header (20 B)   |  ciphertext (len(inner))  |  tag (16 B)    |
//! +------------------+---------------------------+----------------+
//! ```
//!
//! The header fields `key_id`, `epoch`, and `seq` are **little-endian** on the
//! wire (§3.1) — a deliberate contrast with the **big-endian** integers fed into
//! the KDF (§2.1). This module owns serialization, header validation, and
//! sealing; the accept/drop decision and epoch/replay state live in
//! [`super::session`].

use super::crypto::{self, AeadKey, HEADER_LEN, KEY_LEN, TAG_LEN};

/// `flags` bit 0: a one-way spoke→hub NAT keepalive (§3.3). All other bits are
/// reserved and MUST be zero in v1.
pub const KEEPALIVE: u8 = 0x01;

/// The wire version carried in byte 0 of every datagram (§3.1).
pub const WIRE_VERSION: u8 = 1;

/// A parsed 20-byte header (§3.1). Field values are host-native; (de)serialization
/// handles the little-endian wire encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub flags: u8,
    pub key_id: u16,
    pub epoch: u64,
    pub seq: u64,
}

impl Header {
    /// Read a header from the first [`HEADER_LEN`] bytes. Field extraction is
    /// infallible (any 20 bytes decode to *some* header); semantic validity is a
    /// separate step ([`Header::is_valid`]) so a caller can reject with a single
    /// silent-drop path. Returns `None` only if the slice is too short (§5.2).
    pub fn parse(bytes: &[u8]) -> Option<Header> {
        if bytes.len() < HEADER_LEN {
            return None;
        }
        Some(Header {
            version: bytes[0],
            flags: bytes[1],
            key_id: u16::from_le_bytes([bytes[2], bytes[3]]),
            epoch: u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
            seq: u64::from_le_bytes(bytes[12..20].try_into().unwrap()),
        })
    }

    /// Serialize to the 20-byte wire header.
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = self.version;
        out[1] = self.flags;
        out[2..4].copy_from_slice(&self.key_id.to_le_bytes());
        out[4..12].copy_from_slice(&self.epoch.to_le_bytes());
        out[12..20].copy_from_slice(&self.seq.to_le_bytes());
        out
    }

    /// Header validation (§5 step 2): reject if `version != 1`, any reserved
    /// `flags` bit is set (bit 0 `KEEPALIVE` is permitted; all others MUST be 0),
    /// or `epoch == 0`. The length check is handled by [`Header::parse`].
    pub fn is_valid(&self) -> bool {
        self.version == WIRE_VERSION && (self.flags & !KEEPALIVE) == 0 && self.epoch != 0
    }

    /// True if this datagram is a NAT keepalive (§3.3): flagged and empty-bodied.
    pub fn is_keepalive(&self) -> bool {
        self.flags & KEEPALIVE != 0
    }
}

/// The tag is the last [`TAG_LEN`] bytes of the datagram (the body — and thus its
/// trailing tag — is never obfuscated, §3.4), so it is readable before any key is
/// known. Returns `None` if the datagram is shorter than `header + tag` (§5.2).
pub fn datagram_tag(datagram: &[u8]) -> Option<[u8; TAG_LEN]> {
    if datagram.len() < HEADER_LEN + TAG_LEN {
        return None;
    }
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&datagram[datagram.len() - TAG_LEN..]);
    Some(tag)
}

/// De-mask an obfuscated 20-byte header (§3.4) with a pad, returning the recovered
/// cleartext header bytes. XOR masking is symmetric, so this is its own inverse.
pub fn demask_header(masked: &[u8], pad: &[u8; HEADER_LEN]) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    for i in 0..HEADER_LEN {
        out[i] = masked[i] ^ pad[i];
    }
    out
}

/// Seal one datagram (§4 sender egress).
///
/// * `link_key` — the directional `link_key(psk, local_id, peer_id)`; needed only
///   to derive the obfuscation pad.
/// * `aead` — ChaCha20-Poly1305 bound to `session_key(link_key, epoch)`.
/// * `flags` — `0` for data, [`KEEPALIVE`] for a NAT keepalive (empty `plaintext`).
/// * `obfuscate` — XOR-mask the header (§3.4); MUST match the whole mesh's config.
///
/// The eight parameters are the irreducible sender inputs of §4; [`super::session::TxSession`]
/// is the ergonomic caller that carries the static ones (identity, epoch, obfuscate).
#[allow(clippy::too_many_arguments)]
pub fn seal_datagram(
    link_key: &[u8; KEY_LEN],
    aead: &AeadKey,
    local_id: u16,
    epoch: u64,
    seq: u64,
    flags: u8,
    plaintext: &[u8],
    obfuscate: bool,
) -> Vec<u8> {
    let header = Header {
        version: WIRE_VERSION,
        flags,
        key_id: local_id,
        epoch,
        seq,
    }
    .to_bytes();

    let body = aead.seal(seq, plaintext);
    let mut datagram = Vec::with_capacity(HEADER_LEN + body.len());
    datagram.extend_from_slice(&header);
    datagram.extend_from_slice(&body);

    if obfuscate {
        // `body` ends with the 16-byte tag; the pad is keyed off it (§3.4).
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&body[body.len() - TAG_LEN..]);
        let pad = crypto::obfuscation_pad(link_key, &tag);
        for i in 0..HEADER_LEN {
            datagram[i] ^= pad[i];
        }
    }
    datagram
}

/// Split a datagram into its (possibly still-masked) header slice and body slice
/// (`ciphertext || tag`). Returns `None` if too short to hold a header + tag.
pub fn split(datagram: &[u8]) -> Option<(&[u8], &[u8])> {
    if datagram.len() < HEADER_LEN + TAG_LEN {
        return None;
    }
    Some((&datagram[..HEADER_LEN], &datagram[HEADER_LEN..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip_is_little_endian() {
        let h = Header {
            version: 1,
            flags: 0,
            key_id: 0x0102,
            epoch: 0x1122_3344_5566_7788,
            seq: 0x00ff,
        };
        let bytes = h.to_bytes();
        // key_id LE.
        assert_eq!(&bytes[2..4], &[0x02, 0x01]);
        // epoch LE.
        assert_eq!(
            &bytes[4..12],
            &[0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
        );
        assert_eq!(Header::parse(&bytes), Some(h));
    }

    #[test]
    fn validation_rejects_bad_headers() {
        let base = Header {
            version: 1,
            flags: 0,
            key_id: 1,
            epoch: 1,
            seq: 1,
        };
        assert!(base.is_valid());
        assert!(!Header { version: 2, ..base }.is_valid());
        assert!(!Header { epoch: 0, ..base }.is_valid());
        assert!(!Header {
            flags: 0x02,
            ..base
        }
        .is_valid());
        // Keepalive bit alone is permitted.
        assert!(Header {
            flags: KEEPALIVE,
            ..base
        }
        .is_valid());
    }

    #[test]
    fn parse_rejects_short_slice() {
        assert!(Header::parse(&[0u8; 19]).is_none());
        assert!(datagram_tag(&[0u8; 35]).is_none());
        assert!(split(&[0u8; 35]).is_none());
    }

    #[test]
    fn seal_then_manual_open_plain() {
        let lk = crypto::link_key(&[0x5a; 32], 1, 2);
        let sk = crypto::session_key(&lk, 1_704_067_200_000_000_000);
        let aead = AeadKey::new(&sk);
        let dg = seal_datagram(
            &lk,
            &aead,
            1,
            1_704_067_200_000_000_000,
            5,
            0,
            b"hello",
            false,
        );
        let (hdr, body) = split(&dg).unwrap();
        let header = Header::parse(hdr).unwrap();
        assert!(header.is_valid());
        assert_eq!(header.key_id, 1);
        assert_eq!(aead.open(header.seq, body).as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn obfuscation_is_reversible() {
        let lk = crypto::link_key(&[0x5a; 32], 1, 2);
        let sk = crypto::session_key(&lk, 1_704_067_200_000_000_000);
        let aead = AeadKey::new(&sk);
        let dg = seal_datagram(&lk, &aead, 1, 1_704_067_200_000_000_000, 5, 0, b"hi", true);
        // The obfuscated header differs from the cleartext one on the wire.
        let plain = seal_datagram(&lk, &aead, 1, 1_704_067_200_000_000_000, 5, 0, b"hi", false);
        assert_ne!(&dg[..HEADER_LEN], &plain[..HEADER_LEN]);
        // De-masking with the right pad recovers the header.
        let tag = datagram_tag(&dg).unwrap();
        let pad = crypto::obfuscation_pad(&lk, &tag);
        let clear = demask_header(&dg[..HEADER_LEN], &pad);
        let header = Header::parse(&clear).unwrap();
        assert!(header.is_valid());
        assert_eq!(header.key_id, 1);
    }
}
