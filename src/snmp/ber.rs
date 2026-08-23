//! Minimal BER (X.690) codec for the SNMP agent.
//!
//! SNMP uses the Basic Encoding Rules with a small, fixed vocabulary of
//! universal types (INTEGER, OCTET STRING, NULL, OBJECT IDENTIFIER,
//! SEQUENCE), SNMP application types (IpAddress, Counter32, Gauge32,
//! TimeTicks, Counter64) and context-constructed PDU tags. Rather than pull
//! in a full ASN.1 framework we hand-roll exactly this subset: decoding is
//! defensive (all lengths bounds-checked, no recursion beyond caller-driven
//! nesting) because the agent parses datagrams from unauthenticated peers,
//! and encoding is definite-length only, as required for SNMP messages.

use std::fmt;

// Universal tags.
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OID: u8 = 0x06;
pub const TAG_SEQUENCE: u8 = 0x30;

// SNMP application tags (RFC 2578).
pub const TAG_IPADDRESS: u8 = 0x40;
pub const TAG_COUNTER32: u8 = 0x41;
pub const TAG_GAUGE32: u8 = 0x42;
pub const TAG_TIMETICKS: u8 = 0x43;
pub const TAG_COUNTER64: u8 = 0x46;

// varbind exception markers (RFC 3416, context tags in responses).
pub const TAG_NO_SUCH_OBJECT: u8 = 0x80;
pub const TAG_NO_SUCH_INSTANCE: u8 = 0x81;
pub const TAG_END_OF_MIB_VIEW: u8 = 0x82;

// PDU tags (context, constructed).
pub const TAG_GET_REQUEST: u8 = 0xA0;
pub const TAG_GET_NEXT_REQUEST: u8 = 0xA1;
pub const TAG_RESPONSE: u8 = 0xA2;
pub const TAG_SET_REQUEST: u8 = 0xA3;
pub const TAG_GET_BULK_REQUEST: u8 = 0xA5;
pub const TAG_REPORT: u8 = 0xA8;

/// Decode error. The agent treats every variant identically (silently drop
/// the packet and bump a counter), so this intentionally carries no detail
/// beyond a static description used in tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BerError(pub &'static str);

impl fmt::Display for BerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ber: {}", self.0)
    }
}

impl std::error::Error for BerError {}

/// An object identifier as a list of sub-identifiers.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Oid(pub Vec<u32>);

impl Oid {
    pub fn new(parts: &[u32]) -> Self {
        Oid(parts.to_vec())
    }

    /// Child OID: `self` with `suffix` appended.
    pub fn child(&self, suffix: &[u32]) -> Self {
        let mut v = self.0.clone();
        v.extend_from_slice(suffix);
        Oid(v)
    }

    pub fn starts_with(&self, prefix: &Oid) -> bool {
        self.0.len() >= prefix.0.len() && self.0[..prefix.0.len()] == prefix.0[..]
    }
}

impl fmt::Debug for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, part) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(f, "{part}")?;
        }
        Ok(())
    }
}

/// A decoded SNMP value (the ObjectSyntax subset the agent understands).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Integer(i64),
    OctetString(Vec<u8>),
    Null,
    Oid(Oid),
    IpAddress([u8; 4]),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Counter64(u64),
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

/// Streaming reader over a BER-encoded byte slice.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], BerError> {
        if self.buf.len() - self.pos < n {
            return Err(BerError("truncated"));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8, BerError> {
        Ok(self.take(1)?[0])
    }

    /// Peek the tag of the next TLV without consuming it.
    pub fn peek_tag(&self) -> Result<u8, BerError> {
        self.buf.get(self.pos).copied().ok_or(BerError("truncated"))
    }

    /// Read a TLV header, returning `(tag, content)` and consuming it.
    pub fn read_tlv(&mut self) -> Result<(u8, &'a [u8]), BerError> {
        let tag = self.byte()?;
        let len = self.read_length()?;
        Ok((tag, self.take(len)?))
    }

    fn read_length(&mut self) -> Result<usize, BerError> {
        let first = self.byte()?;
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }
        let n = (first & 0x7F) as usize;
        if n == 0 {
            // Indefinite length is forbidden in SNMP.
            return Err(BerError("indefinite length"));
        }
        if n > 4 {
            return Err(BerError("length too large"));
        }
        let mut len: usize = 0;
        for _ in 0..n {
            len = (len << 8) | self.byte()? as usize;
        }
        // Cap far above any real datagram to avoid pathological allocations.
        if len > 1 << 24 {
            return Err(BerError("length too large"));
        }
        Ok(len)
    }

    /// Read a TLV expecting `expected` as its tag.
    pub fn expect(&mut self, expected: u8) -> Result<&'a [u8], BerError> {
        let (tag, content) = self.read_tlv()?;
        if tag != expected {
            return Err(BerError("unexpected tag"));
        }
        Ok(content)
    }

    /// Read an INTEGER as i64 (two's complement, up to 8 content bytes).
    pub fn read_integer(&mut self) -> Result<i64, BerError> {
        let content = self.expect(TAG_INTEGER)?;
        decode_integer(content)
    }

    /// Read an OCTET STRING.
    pub fn read_octet_string(&mut self) -> Result<&'a [u8], BerError> {
        self.expect(TAG_OCTET_STRING)
    }

    /// Read an OBJECT IDENTIFIER.
    pub fn read_oid(&mut self) -> Result<Oid, BerError> {
        let content = self.expect(TAG_OID)?;
        decode_oid(content)
    }

    /// Read a SEQUENCE, returning a nested reader over its content.
    pub fn read_sequence(&mut self) -> Result<Reader<'a>, BerError> {
        Ok(Reader::new(self.expect(TAG_SEQUENCE)?))
    }

    /// Read any ObjectSyntax value (used for varbind values).
    pub fn read_value(&mut self) -> Result<Value, BerError> {
        let (tag, content) = self.read_tlv()?;
        Ok(match tag {
            TAG_INTEGER => Value::Integer(decode_integer(content)?),
            TAG_OCTET_STRING => Value::OctetString(content.to_vec()),
            TAG_NULL => {
                if !content.is_empty() {
                    return Err(BerError("null with content"));
                }
                Value::Null
            }
            TAG_OID => Value::Oid(decode_oid(content)?),
            TAG_IPADDRESS => {
                let arr: [u8; 4] = content.try_into().map_err(|_| BerError("bad ipaddress"))?;
                Value::IpAddress(arr)
            }
            TAG_COUNTER32 => Value::Counter32(decode_unsigned(content)? as u32),
            TAG_GAUGE32 => Value::Gauge32(decode_unsigned(content)? as u32),
            TAG_TIMETICKS => Value::TimeTicks(decode_unsigned(content)? as u32),
            TAG_COUNTER64 => Value::Counter64(decode_unsigned(content)?),
            TAG_NO_SUCH_OBJECT => Value::NoSuchObject,
            TAG_NO_SUCH_INSTANCE => Value::NoSuchInstance,
            TAG_END_OF_MIB_VIEW => Value::EndOfMibView,
            _ => return Err(BerError("unsupported value tag")),
        })
    }
}

fn decode_integer(content: &[u8]) -> Result<i64, BerError> {
    if content.is_empty() || content.len() > 8 {
        return Err(BerError("bad integer size"));
    }
    let mut v = if content[0] & 0x80 != 0 { -1i64 } else { 0 };
    for &b in content {
        v = (v << 8) | b as i64;
    }
    Ok(v)
}

fn decode_unsigned(content: &[u8]) -> Result<u64, BerError> {
    if content.is_empty() || content.len() > 9 {
        return Err(BerError("bad unsigned size"));
    }
    // A leading 0x00 pad byte is allowed (and required when the top bit of
    // the value is set); anything else >8 bytes cannot fit in u64.
    let bytes = if content.len() == 9 {
        if content[0] != 0 {
            return Err(BerError("bad unsigned size"));
        }
        &content[1..]
    } else {
        content
    };
    let mut v: u64 = 0;
    for &b in bytes {
        v = (v << 8) | b as u64;
    }
    Ok(v)
}

fn decode_oid(content: &[u8]) -> Result<Oid, BerError> {
    if content.is_empty() {
        return Err(BerError("empty oid"));
    }
    let mut parts = Vec::with_capacity(content.len() + 1);
    let first = content[0];
    parts.push((first / 40).min(2) as u32);
    if first / 40 >= 2 {
        parts.push(first as u32 - 80);
    } else {
        parts.push((first % 40) as u32);
    }
    let mut idx = 1;
    while idx < content.len() {
        let mut sub: u64 = 0;
        loop {
            let b = *content.get(idx).ok_or(BerError("truncated oid"))?;
            idx += 1;
            sub = (sub << 7) | (b & 0x7F) as u64;
            if sub > u32::MAX as u64 {
                return Err(BerError("oid subid overflow"));
            }
            if b & 0x80 == 0 {
                break;
            }
        }
        parts.push(sub as u32);
    }
    Ok(Oid(parts))
}

/// BER writer producing definite-length encodings.
///
/// Sequences of unknown length are written back-to-front friendly via
/// [`Writer::wrap`]: encode the content into a fresh writer, then wrap it in
/// a TLV. Message sizes here are tiny (< 64 KiB) so the copies are fine.
#[derive(Default)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer::default()
    }

    /// Wrap already-encoded bytes (used to concatenate TLV runs).
    pub fn from_bytes(out: Vec<u8>) -> Self {
        Writer { out }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    pub fn len(&self) -> usize {
        self.out.len()
    }

    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    fn push_tlv(&mut self, tag: u8, content: &[u8]) {
        self.out.push(tag);
        self.push_length(content.len());
        self.out.extend_from_slice(content);
    }

    fn push_length(&mut self, len: usize) {
        if len < 0x80 {
            self.out.push(len as u8);
        } else {
            let bytes = (len as u32).to_be_bytes();
            let skip = bytes.iter().take_while(|&&b| b == 0).count();
            self.out.push(0x80 | (4 - skip) as u8);
            self.out.extend_from_slice(&bytes[skip..]);
        }
    }

    pub fn write_integer(&mut self, v: i64) {
        let mut content = v.to_be_bytes().to_vec();
        // Trim redundant leading bytes while preserving the sign bit.
        while content.len() > 1 {
            let first = content[0];
            let second = content[1];
            let redundant =
                (first == 0x00 && second & 0x80 == 0) || (first == 0xFF && second & 0x80 != 0);
            if redundant {
                content.remove(0);
            } else {
                break;
            }
        }
        self.push_tlv(TAG_INTEGER, &content);
    }

    fn write_unsigned(&mut self, tag: u8, v: u64) {
        let mut content = v.to_be_bytes().to_vec();
        while content.len() > 1 && content[0] == 0 && content[1] & 0x80 == 0 {
            content.remove(0);
        }
        // Unsigned application types must not read as negative: prepend a pad
        // byte when the top bit survives trimming.
        if content[0] & 0x80 != 0 {
            content.insert(0, 0);
        }
        self.push_tlv(tag, &content);
    }

    pub fn write_octet_string(&mut self, v: &[u8]) {
        self.push_tlv(TAG_OCTET_STRING, v);
    }

    pub fn write_null(&mut self) {
        self.push_tlv(TAG_NULL, &[]);
    }

    pub fn write_oid(&mut self, oid: &Oid) {
        let mut content = Vec::with_capacity(oid.0.len() + 1);
        let (first, second) = match oid.0.len() {
            0 => (1, 3), // never produced by this agent; encode a harmless stub
            1 => (oid.0[0], 0),
            _ => (oid.0[0], oid.0[1]),
        };
        content.push((first * 40 + second) as u8);
        for &sub in oid.0.iter().skip(2) {
            let mut tmp = [0u8; 5];
            let mut i = 5;
            let mut v = sub;
            loop {
                i -= 1;
                tmp[i] = (v & 0x7F) as u8 | if i == 4 { 0 } else { 0x80 };
                v >>= 7;
                if v == 0 {
                    break;
                }
            }
            content.extend_from_slice(&tmp[i..]);
        }
        self.push_tlv(TAG_OID, &content);
    }

    pub fn write_value(&mut self, value: &Value) {
        match value {
            Value::Integer(v) => self.write_integer(*v),
            Value::OctetString(v) => self.write_octet_string(v),
            Value::Null => self.write_null(),
            Value::Oid(oid) => self.write_oid(oid),
            Value::IpAddress(v) => self.push_tlv(TAG_IPADDRESS, v),
            Value::Counter32(v) => self.write_unsigned(TAG_COUNTER32, *v as u64),
            Value::Gauge32(v) => self.write_unsigned(TAG_GAUGE32, *v as u64),
            Value::TimeTicks(v) => self.write_unsigned(TAG_TIMETICKS, *v as u64),
            Value::Counter64(v) => self.write_unsigned(TAG_COUNTER64, *v),
            Value::NoSuchObject => self.push_tlv(TAG_NO_SUCH_OBJECT, &[]),
            Value::NoSuchInstance => self.push_tlv(TAG_NO_SUCH_INSTANCE, &[]),
            Value::EndOfMibView => self.push_tlv(TAG_END_OF_MIB_VIEW, &[]),
        }
    }

    /// Wrap previously-encoded content in a constructed TLV with `tag`.
    pub fn wrap(tag: u8, content: Writer) -> Writer {
        let mut outer = Writer::new();
        outer.push_tlv(tag, &content.out);
        outer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- decoding ---

    #[test]
    fn decodes_integers_including_negatives_and_multibyte() {
        for (bytes, expected) in [
            (&[0x02, 0x01, 0x00][..], 0i64),
            (&[0x02, 0x01, 0x7F][..], 127),
            (&[0x02, 0x02, 0x00, 0x80][..], 128),
            (&[0x02, 0x01, 0x80][..], -128),
            (&[0x02, 0x02, 0xFF, 0x7F][..], -129),
            (&[0x02, 0x04, 0x7F, 0xFF, 0xFF, 0xFF][..], i32::MAX as i64),
        ] {
            let mut r = Reader::new(bytes);
            assert_eq!(r.read_integer().unwrap(), expected, "bytes {bytes:02X?}");
            assert!(r.is_empty());
        }
    }

    #[test]
    fn decodes_oid_with_multibyte_subids() {
        // 1.3.6.1.4.1.32473.61: 32473 = 0x81 0xFD 0x59 in base-128.
        let bytes = [
            0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xFD, 0x59, 0x3D,
        ];
        let mut r = Reader::new(&bytes);
        assert_eq!(
            r.read_oid().unwrap(),
            Oid::new(&[1, 3, 6, 1, 4, 1, 32473, 61])
        );
    }

    #[test]
    fn decodes_oid_with_first_byte_above_80() {
        // 2.100 encodes as single byte 2*40+100 = 180.
        let mut r = Reader::new(&[0x06, 0x01, 0xB4]);
        assert_eq!(r.read_oid().unwrap(), Oid::new(&[2, 100]));
    }

    #[test]
    fn decodes_long_form_lengths() {
        let mut payload = vec![0x04, 0x81, 0x80];
        payload.extend(std::iter::repeat_n(0xAB, 0x80));
        let mut r = Reader::new(&payload);
        assert_eq!(r.read_octet_string().unwrap().len(), 0x80);
    }

    #[test]
    fn rejects_truncated_and_malformed_input() {
        // Truncated content.
        assert!(Reader::new(&[0x02, 0x05, 0x01]).read_integer().is_err());
        // Indefinite length.
        assert!(Reader::new(&[0x30, 0x80, 0x00, 0x00])
            .read_sequence()
            .is_err());
        // Length-of-length too large.
        assert!(Reader::new(&[0x04, 0x85, 1, 1, 1, 1, 1])
            .read_octet_string()
            .is_err());
        // Wrong tag.
        assert!(Reader::new(&[0x04, 0x01, 0x00]).read_integer().is_err());
        // Empty integer.
        assert!(Reader::new(&[0x02, 0x00]).read_integer().is_err());
        // OID subid overflow (six 0xFF continuation bytes).
        assert!(
            Reader::new(&[0x06, 0x07, 0x2B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F])
                .read_oid()
                .is_err()
        );
        // Empty input.
        assert!(Reader::new(&[]).read_tlv().is_err());
    }

    #[test]
    fn reads_values_of_all_supported_application_types() {
        let cases: Vec<(Vec<u8>, Value)> = vec![
            (vec![0x41, 0x01, 0x2A], Value::Counter32(42)),
            (
                vec![0x42, 0x04, 0xFF, 0xFF, 0xFF, 0xFF],
                Value::Gauge32(u32::MAX),
            ),
            (vec![0x43, 0x02, 0x01, 0x00], Value::TimeTicks(256)),
            (
                vec![
                    0x46, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                ],
                Value::Counter64(u64::MAX),
            ),
            (
                vec![0x40, 0x04, 127, 0, 0, 1],
                Value::IpAddress([127, 0, 0, 1]),
            ),
            (vec![0x05, 0x00], Value::Null),
            (vec![0x80, 0x00], Value::NoSuchObject),
            (vec![0x81, 0x00], Value::NoSuchInstance),
            (vec![0x82, 0x00], Value::EndOfMibView),
        ];
        for (bytes, expected) in cases {
            let mut r = Reader::new(&bytes);
            assert_eq!(r.read_value().unwrap(), expected, "bytes {bytes:02X?}");
        }
    }

    // --- encoding ---

    #[test]
    fn encodes_integers_with_minimal_twos_complement() {
        let mut w = Writer::new();
        w.write_integer(0);
        w.write_integer(127);
        w.write_integer(128);
        w.write_integer(-128);
        w.write_integer(-129);
        assert_eq!(
            w.into_bytes(),
            vec![
                0x02, 0x01, 0x00, //
                0x02, 0x01, 0x7F, //
                0x02, 0x02, 0x00, 0x80, //
                0x02, 0x01, 0x80, //
                0x02, 0x02, 0xFF, 0x7F,
            ]
        );
    }

    #[test]
    fn encodes_unsigned_types_with_pad_byte_when_high_bit_set() {
        let mut w = Writer::new();
        w.write_value(&Value::Counter32(u32::MAX));
        w.write_value(&Value::Counter64(u64::MAX));
        w.write_value(&Value::Gauge32(1));
        w.write_value(&Value::TimeTicks(0));
        assert_eq!(
            w.into_bytes(),
            vec![
                0x41, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, //
                0x46, 0x09, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, //
                0x42, 0x01, 0x01, //
                0x43, 0x01, 0x00,
            ]
        );
    }

    #[test]
    fn encodes_oid_including_multibyte_subids() {
        let mut w = Writer::new();
        w.write_oid(&Oid::new(&[1, 3, 6, 1, 4, 1, 32473, 61]));
        assert_eq!(
            w.into_bytes(),
            vec![0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xFD, 0x59, 0x3D]
        );
    }

    #[test]
    fn encodes_long_form_length_for_large_content() {
        let mut w = Writer::new();
        w.write_octet_string(&vec![0x55; 300]);
        let bytes = w.into_bytes();
        assert_eq!(&bytes[..4], &[0x04, 0x82, 0x01, 0x2C]);
        assert_eq!(bytes.len(), 4 + 300);
    }

    #[test]
    fn wrap_produces_constructed_tlv() {
        let mut inner = Writer::new();
        inner.write_integer(1);
        let outer = Writer::wrap(TAG_SEQUENCE, inner);
        assert_eq!(outer.into_bytes(), vec![0x30, 0x03, 0x02, 0x01, 0x01]);
    }

    #[test]
    fn round_trips_all_value_variants() {
        let values = vec![
            Value::Integer(-1234567),
            Value::OctetString(b"rove".to_vec()),
            Value::Null,
            Value::Oid(Oid::new(&[1, 3, 6, 1, 2, 1, 1, 1, 0])),
            Value::IpAddress([10, 0, 0, 1]),
            Value::Counter32(4_000_000_000),
            Value::Gauge32(7),
            Value::TimeTicks(4_294_967_295),
            Value::Counter64(18_446_744_073_709_551_615),
            Value::NoSuchObject,
            Value::NoSuchInstance,
            Value::EndOfMibView,
        ];
        let mut w = Writer::new();
        for v in &values {
            w.write_value(v);
        }
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        for v in &values {
            assert_eq!(&r.read_value().unwrap(), v);
        }
        assert!(r.is_empty());
    }

    #[test]
    fn oid_display_and_helpers() {
        let base = Oid::new(&[1, 3, 6, 1]);
        let child = base.child(&[4, 1]);
        assert_eq!(child.to_string(), "1.3.6.1.4.1");
        assert!(child.starts_with(&base));
        assert!(!base.starts_with(&child));
    }
}
