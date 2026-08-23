//! `.rab` (Rove Address Book) v1 binary format: encoding, strict decoding and
//! integrity verification. The format is the stable protocol surface — see
//! `docs/addrbook-format.md` for the normative spec. Layout rules:
//!
//! * Little-endian, fixed-width records, offset-addressed sections.
//! * Section payloads are independently locatable via the section table, so a
//!   future reader can memory-map the file and query in place without any
//!   format change; the current loader decodes into typed vectors.
//! * The final 32 bytes are a SHA-256 digest over every preceding byte.
//!   Decoding verifies magic, version, checksum, bounds, sortedness and
//!   referential integrity, and rejects the file on any violation — a corrupt
//!   or truncated artifact must never partially load.

use anyhow::{bail, Context, Result};

pub const MAGIC: &[u8; 4] = b"RAB1";
pub const FORMAT_VERSION: u16 = 1;
pub const CHECKSUM_LEN: usize = 32;

/// Section kind tags (u32 on the wire). Unknown kinds are rejected: v1 readers
/// only accept v1 files, and the version field is bumped for any layout change.
const SEC_CATEGORIES: u32 = 1;
const SEC_CATSETS: u32 = 2;
const SEC_IP4: u32 = 3;
const SEC_IP6: u32 = 4;
const SEC_DOMAIN_EXACT: u32 = 5;
const SEC_DOMAIN_SUFFIX: u32 = 6;
const SEC_KEYWORD: u32 = 7;
const SECTION_COUNT: usize = 7;
const IPV4_MAPPED_START: u128 = 0xffffu128 << 32;
const IPV4_MAPPED_END: u128 = IPV4_MAPPED_START | u32::MAX as u128;

/// Hard caps so a malformed length field cannot drive huge allocations.
const MAX_CATEGORIES: usize = 100_000;
const MAX_ENTRIES: usize = 8_000_000;
const MAX_DECODED_HEAP_BYTES: usize = 256 * 1024 * 1024;
const PER_STRING_ALLOCATION_OVERHEAD: usize = 16;

/// One category: `name` is the full hierarchical path (e.g. `google/ads`),
/// `parent` is an index into the category table or `u32::MAX` for roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Category {
    pub name: String,
    pub parent: u32,
}

/// A string entry (domain / keyword) tagged with the id of the category set
/// that contains it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrEntry {
    pub text: String,
    pub catset: u32,
}

/// Decoded artifact payload: plain typed vectors, already validated. This is
/// the exchange type between the encoder (builder) and the query layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawBook {
    pub build_epoch: u64,
    /// Sorted by `name`.
    pub categories: Vec<Category>,
    /// Number of u64 words per category set; `categories.len()` bits rounded up.
    pub catset_words: u32,
    /// `catsets[i]` occupies words `i*catset_words .. (i+1)*catset_words`.
    pub catsets: Vec<u64>,
    /// Sorted by start; pairwise disjoint. `(start, end, catset)` inclusive.
    pub ip4: Vec<(u32, u32, u32)>,
    pub ip6: Vec<(u128, u128, u32)>,
    /// Sorted unique normalized names.
    pub domain_exact: Vec<StrEntry>,
    /// Sorted unique label-reversed normalized names (`google.com` → `com.google`).
    pub domain_suffix: Vec<StrEntry>,
    pub keywords: Vec<StrEntry>,
}

pub fn sha256(bytes: &[u8]) -> [u8; CHECKSUM_LEN] {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(digest.as_ref());
    out
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

struct SectionWriter {
    kind: u32,
    payload: Vec<u8>,
}

fn push_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn push_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}
fn push_u128(buf: &mut Vec<u8>, v: u128) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Encode string entries as `n | n * {pool_off u32, len u16, catset u32} | pool`.
fn encode_str_section(kind: u32, entries: &[StrEntry]) -> Result<SectionWriter> {
    let mut payload = Vec::new();
    push_u32(&mut payload, u32::try_from(entries.len())?);
    let mut pool = Vec::new();
    for e in entries {
        let off = u32::try_from(pool.len()).context("string pool exceeds u32")?;
        let len = u16::try_from(e.text.len()).context("string entry exceeds u16 length")?;
        push_u32(&mut payload, off);
        push_u16(&mut payload, len);
        push_u32(&mut payload, e.catset);
        pool.extend_from_slice(e.text.as_bytes());
    }
    push_u32(&mut payload, u32::try_from(pool.len())?);
    payload.extend_from_slice(&pool);
    Ok(SectionWriter { kind, payload })
}

/// Serialize a validated `RawBook` into `.rab` bytes. The caller (builder) is
/// responsible for producing sorted/deduplicated content; `encode` re-checks
/// the invariants via a decode round-trip in debug builds only implicitly
/// through tests — the release encoder trusts its single in-tree caller.
pub fn encode(book: &RawBook) -> Result<Vec<u8>> {
    validate(book)?;
    let mut sections: Vec<SectionWriter> = Vec::new();

    // CATEGORIES: n | n * {name_off u32, name_len u16, parent u32} | pool_len | pool
    {
        let mut payload = Vec::new();
        push_u32(&mut payload, u32::try_from(book.categories.len())?);
        let mut pool = Vec::new();
        for c in &book.categories {
            let off = u32::try_from(pool.len())?;
            let len = u16::try_from(c.name.len()).context("category name exceeds u16 length")?;
            push_u32(&mut payload, off);
            push_u16(&mut payload, len);
            push_u32(&mut payload, c.parent);
            pool.extend_from_slice(c.name.as_bytes());
        }
        push_u32(&mut payload, u32::try_from(pool.len())?);
        payload.extend_from_slice(&pool);
        sections.push(SectionWriter {
            kind: SEC_CATEGORIES,
            payload,
        });
    }

    // CATSETS: words u32 | n u32 | n * words * u64
    {
        let mut payload = Vec::new();
        push_u32(&mut payload, book.catset_words);
        let words = book.catset_words as usize;
        let n = book.catsets.len().checked_div(words).unwrap_or(0);
        push_u32(&mut payload, u32::try_from(n)?);
        for w in &book.catsets {
            push_u64(&mut payload, *w);
        }
        sections.push(SectionWriter {
            kind: SEC_CATSETS,
            payload,
        });
    }

    // IP4: n | n * {start u32, end u32, catset u32}
    {
        let mut payload = Vec::new();
        push_u32(&mut payload, u32::try_from(book.ip4.len())?);
        for (s, e, c) in &book.ip4 {
            push_u32(&mut payload, *s);
            push_u32(&mut payload, *e);
            push_u32(&mut payload, *c);
        }
        sections.push(SectionWriter {
            kind: SEC_IP4,
            payload,
        });
    }

    // IP6: n | n * {start u128, end u128, catset u32}
    {
        let mut payload = Vec::new();
        push_u32(&mut payload, u32::try_from(book.ip6.len())?);
        for (s, e, c) in &book.ip6 {
            push_u128(&mut payload, *s);
            push_u128(&mut payload, *e);
            push_u32(&mut payload, *c);
        }
        sections.push(SectionWriter {
            kind: SEC_IP6,
            payload,
        });
    }

    sections.push(encode_str_section(SEC_DOMAIN_EXACT, &book.domain_exact)?);
    sections.push(encode_str_section(SEC_DOMAIN_SUFFIX, &book.domain_suffix)?);
    sections.push(encode_str_section(SEC_KEYWORD, &book.keywords)?);

    // Header: magic | version u16 | reserved u16 | build_epoch u64 | n_sections u32
    // Section table: n * {kind u32, offset u64, len u64}; offsets are absolute.
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    push_u16(&mut out, FORMAT_VERSION);
    push_u16(&mut out, 0);
    push_u64(&mut out, book.build_epoch);
    push_u32(&mut out, u32::try_from(sections.len())?);
    let table_at = out.len();
    out.resize(out.len() + sections.len() * 20, 0);
    for (i, sec) in sections.iter().enumerate() {
        let off = out.len() as u64;
        out.extend_from_slice(&sec.payload);
        let entry = table_at + i * 20;
        out[entry..entry + 4].copy_from_slice(&sec.kind.to_le_bytes());
        out[entry + 4..entry + 12].copy_from_slice(&off.to_le_bytes());
        out[entry + 12..entry + 20].copy_from_slice(&(sec.payload.len() as u64).to_le_bytes());
    }
    let digest = sha256(&out);
    out.extend_from_slice(&digest);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Bounds-checked little-endian cursor. Every read is explicit; any overrun is
/// an error rather than a panic, so the decoder is total over arbitrary bytes.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.buf.len())
            .context("truncated section")?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn u128(&mut self) -> Result<u128> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into().unwrap()))
    }
    fn done(&self) -> Result<()> {
        if self.pos != self.buf.len() {
            bail!("trailing bytes in section");
        }
        Ok(())
    }
}

fn decode_str_section(
    payload: &[u8],
    what: &str,
    decoded_heap: &mut usize,
) -> Result<Vec<StrEntry>> {
    let mut cur = Cursor::new(payload);
    let n = cur.u32()? as usize;
    if n > MAX_ENTRIES {
        bail!("{what}: entry count {n} exceeds limit");
    }
    let min_len = 8usize
        .checked_add(n.checked_mul(10).context("string header size overflow")?)
        .context("string section size overflow")?;
    if payload.len() < min_len {
        bail!("{what}: declared entry count exceeds section length");
    }
    let per_entry = std::mem::size_of::<(usize, usize, u32)>()
        + std::mem::size_of::<StrEntry>()
        + PER_STRING_ALLOCATION_OVERHEAD;
    let estimated_heap = n
        .checked_mul(per_entry)
        .and_then(|size| size.checked_add(payload.len()))
        .context("string decode allocation size overflow")?;
    charge_decoded_heap(decoded_heap, estimated_heap, what)?;
    let mut heads = Vec::with_capacity(n);
    for _ in 0..n {
        let off = cur.u32()? as usize;
        let len = cur.u16()? as usize;
        let catset = cur.u32()?;
        heads.push((off, len, catset));
    }
    let pool_len = cur.u32()? as usize;
    let pool = cur.take(pool_len)?;
    cur.done()?;
    let mut out = Vec::with_capacity(n);
    let mut next_pool_offset = 0usize;
    for (off, len, catset) in heads {
        if off != next_pool_offset {
            bail!("{what}: noncanonical or overlapping string pool reference");
        }
        let end = off.checked_add(len).filter(|e| *e <= pool.len());
        let Some(end) = end else {
            bail!("{what}: string entry out of pool bounds");
        };
        let text = std::str::from_utf8(&pool[off..end])
            .with_context(|| format!("{what}: invalid utf-8"))?
            .to_string();
        out.push(StrEntry { text, catset });
        next_pool_offset = end;
    }
    if next_pool_offset != pool.len() {
        bail!("{what}: unreferenced bytes in string pool");
    }
    Ok(out)
}

/// Strictly decode and verify a `.rab` file. Any structural violation —
/// bad magic, unsupported version, checksum mismatch, truncation, unsorted or
/// overlapping ranges, dangling catset/category references — is a hard error.
pub fn decode(bytes: &[u8]) -> Result<RawBook> {
    if bytes.len() < 4 + 2 + 2 + 8 + 4 + CHECKSUM_LEN {
        bail!("file too small to be a .rab artifact");
    }
    let (body, checksum) = bytes.split_at(bytes.len() - CHECKSUM_LEN);
    if sha256(body) != *checksum {
        bail!("checksum mismatch: artifact is corrupt or truncated");
    }
    let mut cur = Cursor::new(body);
    if cur.take(4)? != MAGIC {
        bail!("bad magic: not a .rab artifact");
    }
    let version = cur.u16()?;
    if version != FORMAT_VERSION {
        bail!("unsupported .rab format version {version} (this build supports {FORMAT_VERSION})");
    }
    let reserved = cur.u16()?;
    if reserved != 0 {
        bail!("reserved header field must be zero");
    }
    let build_epoch = cur.u64()?;
    let n_sections = cur.u32()? as usize;
    if n_sections != SECTION_COUNT {
        bail!("v1 requires exactly {SECTION_COUNT} sections, found {n_sections}");
    }
    let mut sections: Vec<(u32, &[u8])> = Vec::with_capacity(n_sections);
    let mut table = Vec::with_capacity(n_sections);
    for _ in 0..n_sections {
        let kind = cur.u32()?;
        let off = usize::try_from(cur.u64()?).context("section offset exceeds address space")?;
        let len = usize::try_from(cur.u64()?).context("section length exceeds address space")?;
        table.push((kind, off, len));
    }
    let payload_start = cur.pos;
    let mut coverage = Vec::with_capacity(n_sections);
    for &(kind, off, len) in &table {
        let end = off.checked_add(len).filter(|e| *e <= body.len());
        let Some(end) = end else {
            bail!("section {kind} out of file bounds");
        };
        if off < payload_start {
            bail!("section {kind} overlaps the header or section table");
        }
        coverage.push((off, end, kind));
    }
    coverage.sort_unstable_by_key(|(off, _, _)| *off);
    let mut next = payload_start;
    for (off, end, kind) in coverage {
        if off < next {
            bail!("section {kind} overlaps another section");
        }
        if off > next {
            bail!("unreferenced bytes before section {kind}");
        }
        next = end;
    }
    if next != body.len() {
        bail!("unreferenced trailing bytes after final section");
    }
    for (kind, off, len) in table {
        let end = off + len;
        sections.push((kind, &body[off..end]));
    }

    let mut book = RawBook {
        build_epoch,
        ..Default::default()
    };
    let mut decoded_heap = 0usize;
    let mut seen = std::collections::HashSet::new();
    for (kind, payload) in sections {
        if !seen.insert(kind) {
            bail!("duplicate section kind {kind}");
        }
        match kind {
            SEC_CATEGORIES => {
                let mut cur = Cursor::new(payload);
                let n = cur.u32()? as usize;
                if n > MAX_CATEGORIES {
                    bail!("category count {n} exceeds limit");
                }
                let min_len = 8usize
                    .checked_add(n.checked_mul(10).context("category header size overflow")?)
                    .context("category section size overflow")?;
                if payload.len() < min_len {
                    bail!("declared category count exceeds section length");
                }
                let per_entry = std::mem::size_of::<(usize, usize, u32)>()
                    + std::mem::size_of::<Category>()
                    + PER_STRING_ALLOCATION_OVERHEAD;
                let estimated_heap = n
                    .checked_mul(per_entry)
                    .and_then(|size| size.checked_add(payload.len()))
                    .context("category decode allocation size overflow")?;
                charge_decoded_heap(&mut decoded_heap, estimated_heap, "categories")?;
                let mut heads = Vec::with_capacity(n);
                for _ in 0..n {
                    let off = cur.u32()? as usize;
                    let len = cur.u16()? as usize;
                    let parent = cur.u32()?;
                    heads.push((off, len, parent));
                }
                let pool_len = cur.u32()? as usize;
                let pool = cur.take(pool_len)?;
                cur.done()?;
                let mut next_pool_offset = 0usize;
                for (off, len, parent) in heads {
                    if off != next_pool_offset {
                        bail!("noncanonical or overlapping category name pool reference");
                    }
                    let end = off.checked_add(len).filter(|e| *e <= pool.len());
                    let Some(end) = end else {
                        bail!("category name out of pool bounds");
                    };
                    let name = std::str::from_utf8(&pool[off..end])
                        .context("category name invalid utf-8")?
                        .to_string();
                    book.categories.push(Category { name, parent });
                    next_pool_offset = end;
                }
                if next_pool_offset != pool.len() {
                    bail!("unreferenced bytes in category name pool");
                }
            }
            SEC_CATSETS => {
                let mut cur = Cursor::new(payload);
                let words = cur.u32()?;
                let n = cur.u32()? as usize;
                let total = (words as usize)
                    .checked_mul(n)
                    .context("catset size overflow")?;
                if total > MAX_ENTRIES {
                    bail!("catset table too large");
                }
                let expected_len = 8usize
                    .checked_add(total.checked_mul(8).context("catset byte size overflow")?)
                    .context("catset section size overflow")?;
                if payload.len() != expected_len {
                    bail!("declared catset count inconsistent with section length");
                }
                charge_decoded_heap(
                    &mut decoded_heap,
                    total
                        .checked_mul(std::mem::size_of::<u64>())
                        .context("catset allocation size overflow")?,
                    "catsets",
                )?;
                book.catset_words = words;
                book.catsets.reserve(total);
                for _ in 0..total {
                    book.catsets.push(cur.u64()?);
                }
                cur.done()?;
            }
            SEC_IP4 => {
                let mut cur = Cursor::new(payload);
                let n = cur.u32()? as usize;
                if n > MAX_ENTRIES {
                    bail!("ip4 count exceeds limit");
                }
                let expected_len = 4usize
                    .checked_add(n.checked_mul(12).context("ip4 byte size overflow")?)
                    .context("ip4 section size overflow")?;
                if payload.len() != expected_len {
                    bail!("declared ip4 count inconsistent with section length");
                }
                charge_decoded_heap(
                    &mut decoded_heap,
                    n.checked_mul(std::mem::size_of::<(u32, u32, u32)>())
                        .context("ip4 allocation size overflow")?,
                    "ip4",
                )?;
                book.ip4.reserve(n);
                for _ in 0..n {
                    let s = cur.u32()?;
                    let e = cur.u32()?;
                    let c = cur.u32()?;
                    book.ip4.push((s, e, c));
                }
                cur.done()?;
            }
            SEC_IP6 => {
                let mut cur = Cursor::new(payload);
                let n = cur.u32()? as usize;
                if n > MAX_ENTRIES {
                    bail!("ip6 count exceeds limit");
                }
                let expected_len = 4usize
                    .checked_add(n.checked_mul(36).context("ip6 byte size overflow")?)
                    .context("ip6 section size overflow")?;
                if payload.len() != expected_len {
                    bail!("declared ip6 count inconsistent with section length");
                }
                charge_decoded_heap(
                    &mut decoded_heap,
                    n.checked_mul(std::mem::size_of::<(u128, u128, u32)>())
                        .context("ip6 allocation size overflow")?,
                    "ip6",
                )?;
                book.ip6.reserve(n);
                for _ in 0..n {
                    let s = cur.u128()?;
                    let e = cur.u128()?;
                    let c = cur.u32()?;
                    book.ip6.push((s, e, c));
                }
                cur.done()?;
            }
            SEC_DOMAIN_EXACT => {
                book.domain_exact = decode_str_section(payload, "domain_exact", &mut decoded_heap)?
            }
            SEC_DOMAIN_SUFFIX => {
                book.domain_suffix =
                    decode_str_section(payload, "domain_suffix", &mut decoded_heap)?
            }
            SEC_KEYWORD => {
                book.keywords = decode_str_section(payload, "keyword", &mut decoded_heap)?
            }
            other => bail!("unknown section kind {other}"),
        }
    }

    validate(&book)?;
    Ok(book)
}

fn charge_decoded_heap(total: &mut usize, bytes: usize, what: &str) -> Result<()> {
    *total = total
        .checked_add(bytes)
        .context("decoded heap budget overflow")?;
    if *total > MAX_DECODED_HEAP_BYTES {
        bail!(
            "{what}: decoded heap budget exceeded: {} > {} bytes",
            *total,
            MAX_DECODED_HEAP_BYTES
        );
    }
    Ok(())
}

/// Structural invariants shared by decoder and tests. Kept separate so the
/// builder's output can be validated in unit tests without a byte round-trip.
pub fn validate(book: &RawBook) -> Result<()> {
    let n_cats = book.categories.len();
    if n_cats > MAX_CATEGORIES {
        bail!("category count {n_cats} exceeds limit");
    }
    let words = book.catset_words as usize;
    let expected_words = n_cats.div_ceil(64);
    if words != expected_words {
        bail!("catset_words {words} inconsistent with {n_cats} categories");
    }
    let n_sets = if words == 0 {
        if !book.catsets.is_empty() {
            bail!("catset data present with zero word count");
        }
        0
    } else {
        if !book.catsets.len().is_multiple_of(words) {
            bail!("catset table length not a multiple of word count");
        }
        book.catsets.len() / words
    };
    for w in book.categories.windows(2) {
        if w[0].name >= w[1].name {
            bail!("categories not sorted/unique");
        }
    }
    for (i, c) in book.categories.iter().enumerate() {
        if c.name.is_empty() {
            bail!("empty category name");
        }
        if c.name.split('/').any(|seg| {
            seg.is_empty()
                || !seg.chars().all(|ch| {
                    ch.is_ascii_lowercase()
                        || ch.is_ascii_digit()
                        || matches!(ch, '-' | '_' | '.' | '@' | '!')
                })
        }) {
            bail!("category {} has invalid path syntax", c.name);
        }
        match c.name.rsplit_once('/') {
            Some((expected_parent, _)) => {
                if c.parent == u32::MAX {
                    bail!("category {} is missing its parent", c.name);
                }
                let p = c.parent as usize;
                if p >= n_cats {
                    bail!("category {} has dangling parent", c.name);
                }
                if book.categories[p].name != expected_parent {
                    bail!(
                        "category {} parent mismatch: expected {}, found {}",
                        c.name,
                        expected_parent,
                        book.categories[p].name
                    );
                }
            }
            None if c.parent != u32::MAX => {
                bail!("root category {} must not have a parent", c.name);
            }
            None => {}
        }
        debug_assert!(c.parent == u32::MAX || (c.parent as usize) < i);
    }
    let remainder = n_cats % 64;
    if remainder != 0 {
        let valid_last_word = (1u64 << remainder) - 1;
        for (i, set) in book.catsets.chunks_exact(words).enumerate() {
            if set[words - 1] & !valid_last_word != 0 {
                bail!("catset {i} has bits outside the category table");
            }
        }
    }
    let check_catset = |cs: u32, what: &str| -> Result<()> {
        if (cs as usize) >= n_sets {
            bail!("{what}: dangling catset id {cs}");
        }
        Ok(())
    };
    let mut prev_end: Option<u32> = None;
    for (s, e, c) in &book.ip4 {
        if s > e {
            bail!("ip4 range start > end");
        }
        if let Some(pe) = prev_end {
            if *s <= pe {
                bail!("ip4 ranges unsorted or overlapping");
            }
        }
        prev_end = Some(*e);
        check_catset(*c, "ip4")?;
    }
    let mut prev_end6: Option<u128> = None;
    for (s, e, c) in &book.ip6 {
        if s > e {
            bail!("ip6 range start > end");
        }
        if *s <= IPV4_MAPPED_END && *e >= IPV4_MAPPED_START {
            bail!("ip6 range overlaps the IPv4-mapped region");
        }
        if let Some(pe) = prev_end6 {
            if *s <= pe {
                bail!("ip6 ranges unsorted or overlapping");
            }
        }
        prev_end6 = Some(*e);
        check_catset(*c, "ip6")?;
    }
    for (list, what) in [
        (&book.domain_exact, "domain_exact"),
        (&book.domain_suffix, "domain_suffix"),
    ] {
        for w in list.windows(2) {
            if w[0].text >= w[1].text {
                bail!("{what} not sorted/unique");
            }
        }
        for e in list.iter() {
            if e.text.is_empty() {
                bail!("{what}: empty entry");
            }
            if !is_normalized_match_text(&e.text) {
                bail!("{what}: noncanonical entry {:?}", e.text);
            }
            check_catset(e.catset, what)?;
        }
    }
    for w in book.keywords.windows(2) {
        if w[0].text >= w[1].text {
            bail!("keyword not sorted/unique");
        }
    }
    for e in &book.keywords {
        if e.text.is_empty() {
            bail!("keyword: empty entry");
        }
        if !is_normalized_match_text(&e.text) {
            bail!("keyword: noncanonical entry {:?}", e.text);
        }
        check_catset(e.catset, "keyword")?;
    }
    Ok(())
}

fn is_normalized_match_text(text: &str) -> bool {
    text == text.trim().trim_matches('.') && !text.bytes().any(|byte| byte.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RawBook {
        RawBook {
            build_epoch: 42,
            categories: vec![
                Category {
                    name: "google".into(),
                    parent: u32::MAX,
                },
                Category {
                    name: "google/ads".into(),
                    parent: 0,
                },
            ],
            catset_words: 1,
            // set 0 = {google}, set 1 = {google/ads}
            catsets: vec![0b01, 0b10],
            ip4: vec![(0x0100_0000, 0x0100_00FF, 0), (0x0200_0000, 0x0200_0000, 1)],
            ip6: vec![(1, 2, 0)],
            domain_exact: vec![StrEntry {
                text: "one.google.com".into(),
                catset: 0,
            }],
            domain_suffix: vec![StrEntry {
                text: "com.google".into(),
                catset: 0,
            }],
            keywords: vec![StrEntry {
                text: "googlevideo".into(),
                catset: 1,
            }],
        }
    }

    #[test]
    fn roundtrip_preserves_everything() {
        let book = sample();
        let bytes = encode(&book).unwrap();
        let decoded = decode(&bytes).unwrap();
        assert_eq!(decoded, book);
    }

    #[test]
    fn encoding_is_deterministic() {
        let a = encode(&sample()).unwrap();
        let b = encode(&sample()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_bad_magic_version_and_checksum() {
        let bytes = encode(&sample()).unwrap();

        let mut bad_magic = bytes.clone();
        bad_magic[0] = b'X';
        assert!(decode(&bad_magic).is_err());

        // Flip the version field and recompute the checksum so only the
        // version check can reject it.
        let mut bad_version = bytes.clone();
        bad_version[4] = 99;
        let body_len = bad_version.len() - CHECKSUM_LEN;
        let digest = sha256(&bad_version[..body_len]);
        bad_version[body_len..].copy_from_slice(&digest);
        let err = decode(&bad_version).unwrap_err().to_string();
        assert!(err.contains("unsupported"), "{err}");

        let mut corrupt = bytes.clone();
        let mid = corrupt.len() / 2;
        corrupt[mid] ^= 0xFF;
        let err = decode(&corrupt).unwrap_err().to_string();
        assert!(err.contains("checksum"), "{err}");

        assert!(decode(&bytes[..bytes.len() - 3]).is_err());
        assert!(decode(&[]).is_err());
    }

    fn resign(bytes: &mut [u8]) {
        let body_len = bytes.len() - CHECKSUM_LEN;
        let digest = sha256(&bytes[..body_len]);
        bytes[body_len..].copy_from_slice(&digest);
    }

    #[test]
    fn rejects_noncanonical_container_structure() {
        let bytes = encode(&sample()).unwrap();

        let mut reserved = bytes.clone();
        reserved[6] = 1;
        resign(&mut reserved);
        assert!(decode(&reserved)
            .unwrap_err()
            .to_string()
            .contains("reserved"));

        let mut missing_section = bytes.clone();
        missing_section[16..20].copy_from_slice(&6u32.to_le_bytes());
        resign(&mut missing_section);
        assert!(decode(&missing_section)
            .unwrap_err()
            .to_string()
            .contains("exactly 7"));

        // Make section 2 start at section 1's offset. The digest is valid, so
        // only the canonical non-overlap check can reject the container.
        let mut overlap = bytes.clone();
        let first_offset = overlap[24..32].to_vec();
        overlap[44..52].copy_from_slice(&first_offset);
        resign(&mut overlap);
        assert!(decode(&overlap)
            .unwrap_err()
            .to_string()
            .contains("overlaps"));
    }

    #[test]
    fn rejects_large_declared_counts_before_allocating() {
        let bytes = encode(&sample()).unwrap();

        let mut categories = bytes.clone();
        let category_offset = u64::from_le_bytes(categories[24..32].try_into().unwrap()) as usize;
        categories[category_offset..category_offset + 4]
            .copy_from_slice(&(MAX_CATEGORIES as u32).to_le_bytes());
        resign(&mut categories);
        assert!(decode(&categories)
            .unwrap_err()
            .to_string()
            .contains("section length"));

        let mut domains = bytes.clone();
        // DOMAIN_EXACT is section-table entry 4; its absolute offset starts at
        // header + 4*entry_size + kind_size = 20 + 4*20 + 4.
        let offset_field = 20 + 4 * 20 + 4;
        let domain_offset =
            u64::from_le_bytes(domains[offset_field..offset_field + 8].try_into().unwrap())
                as usize;
        domains[domain_offset..domain_offset + 4]
            .copy_from_slice(&(MAX_ENTRIES as u32).to_le_bytes());
        resign(&mut domains);
        assert!(decode(&domains)
            .unwrap_err()
            .to_string()
            .contains("section length"));
    }

    #[test]
    fn decoded_heap_budget_is_checked_before_allocation() {
        let mut total = MAX_DECODED_HEAP_BYTES;
        let err = charge_decoded_heap(&mut total, 1, "test").unwrap_err();
        assert!(err.to_string().contains("heap budget exceeded"), "{err}");
    }

    #[test]
    fn rejects_overlapping_string_pool_references() {
        let mut bytes = encode(&sample()).unwrap();
        let category_offset = u64::from_le_bytes(bytes[24..32].try_into().unwrap()) as usize;
        // Categories have two 10-byte headers. Redirect the second name to the
        // start of the first; without canonical pool checks this duplicates
        // allocations and permits extreme heap amplification.
        let second_name_offset = category_offset + 4 + 10;
        bytes[second_name_offset..second_name_offset + 4].copy_from_slice(&0u32.to_le_bytes());
        resign(&mut bytes);
        assert!(decode(&bytes)
            .unwrap_err()
            .to_string()
            .contains("overlapping"));
    }

    #[test]
    fn rejects_semantic_violations() {
        let mut overlapping = sample();
        overlapping.ip4 = vec![(10, 20, 0), (15, 30, 1)];
        assert!(validate(&overlapping).is_err());

        let mut unsorted = sample();
        unsorted.domain_exact = vec![
            StrEntry {
                text: "b".into(),
                catset: 0,
            },
            StrEntry {
                text: "a".into(),
                catset: 0,
            },
        ];
        assert!(validate(&unsorted).is_err());

        let mut dangling = sample();
        dangling.ip4 = vec![(1, 2, 99)];
        assert!(validate(&dangling).is_err());

        let mut bad_parent = sample();
        bad_parent.categories[1].parent = 7;
        assert!(validate(&bad_parent).is_err());

        let mut missing_parent = sample();
        missing_parent.categories[1].parent = u32::MAX;
        assert!(validate(&missing_parent).is_err());

        let mut invalid_category = sample();
        invalid_category.categories[1].name = "google//ads".into();
        assert!(validate(&invalid_category).is_err());

        let mut high_bit = sample();
        high_bit.catsets[0] |= 1 << 63;
        assert!(validate(&high_bit).is_err());

        let mut keywords = sample();
        keywords.keywords = vec![
            StrEntry {
                text: "z".into(),
                catset: 0,
            },
            StrEntry {
                text: "a".into(),
                catset: 0,
            },
        ];
        assert!(validate(&keywords).is_err());

        let mut uppercase = sample();
        uppercase.domain_exact[0].text = "One.Google.Com".into();
        assert!(validate(&uppercase).is_err());

        let mut mapped_in_ip6 = sample();
        mapped_in_ip6.ip6 = vec![(IPV4_MAPPED_START, IPV4_MAPPED_END, 0)];
        assert!(validate(&mapped_in_ip6).is_err());
    }

    #[test]
    fn decoder_never_panics_on_mutated_bytes() {
        // Deterministic cheap fuzz: single-byte mutations across the artifact
        // (checksum will reject most; structural checks the rest).
        let bytes = encode(&sample()).unwrap();
        for i in 0..bytes.len() {
            let mut m = bytes.clone();
            m[i] = m[i].wrapping_add(1);
            let _ = decode(&m);
        }
        // And arbitrary truncations.
        for cut in 0..bytes.len() {
            let _ = decode(&bytes[..cut]);
        }
    }
}
