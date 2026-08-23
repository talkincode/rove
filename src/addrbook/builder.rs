//! Deterministic `.rab` builder: accumulates categorized entries, merges IP
//! ranges with a boundary sweep, interns category sets and emits sorted,
//! validated sections. The same logical input always produces byte-identical
//! output (no wall clock, no hash-iteration order anywhere near the artifact),
//! which is what makes released artifacts diffable and reproducible.

use super::book::{normalize_domain, reverse_labels};
use super::format::{encode, validate, Category, RawBook, StrEntry};
use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;

/// Inclusive range with the *builder-local* category id it came from.
type RawRange = (u128, u128, u32);

/// A sweep boundary: `(is_infinity, position)`. `end + 1` of a range ending at
/// the numeric maximum becomes `(true, 0)`, which orders after every finite
/// position — no overflow special cases in the sweep itself.
type Boundary = (bool, u128);

pub struct BookBuilder {
    epoch: u64,
    /// All category paths, ancestors included.
    categories: BTreeSet<String>,
    ip4: Vec<(u128, u128, String)>,
    ip6: Vec<(u128, u128, String)>,
    exact: BTreeMap<String, BTreeSet<String>>,
    suffix: BTreeMap<String, BTreeSet<String>>,
    keywords: BTreeMap<String, BTreeSet<String>>,
}

impl BookBuilder {
    pub fn new(epoch: u64) -> Self {
        BookBuilder {
            epoch,
            categories: BTreeSet::new(),
            ip4: Vec::new(),
            ip6: Vec::new(),
            exact: BTreeMap::new(),
            suffix: BTreeMap::new(),
            keywords: BTreeMap::new(),
        }
    }

    /// Validate and register a category path (`google/ads`), including all
    /// ancestor paths. Returns the normalized path.
    pub fn add_category(&mut self, path: &str) -> Result<String> {
        let norm = path.trim().trim_matches('/').to_ascii_lowercase();
        if norm.is_empty() {
            bail!("empty category path");
        }
        for seg in norm.split('/') {
            if seg.is_empty() {
                bail!("category path {path:?} has an empty segment");
            }
            if !seg
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "-_.@!".contains(c))
            {
                bail!(
                    "category path {path:?} has invalid characters \
                     (allowed: a-z 0-9 - _ . @ ! /)"
                );
            }
        }
        let mut acc = String::new();
        for seg in norm.split('/') {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(seg);
            self.categories.insert(acc.clone());
        }
        Ok(norm)
    }

    /// Add one entry in Rove rule syntax: `full:host`, `keyword:frag`, an IP or
    /// CIDR, or a bare domain (suffix match). Mirrors `policy::RuleSet` parsing
    /// so the same source lines mean the same thing in both places.
    pub fn add_rule(&mut self, category: &str, rule: &str) -> Result<()> {
        let cat = self.add_category(category)?;
        let r = rule.trim();
        if r.is_empty() {
            bail!("empty rule");
        }
        if let Some(host) = r.strip_prefix("full:") {
            return self.add_domain_exact(&cat, host);
        }
        if let Some(frag) = r.strip_prefix("keyword:") {
            return self.add_keyword(&cat, frag);
        }
        if let Some(host) = r.strip_prefix("domain:") {
            return self.add_domain_suffix(&cat, host);
        }
        if let Some(ranges) = parse_ip_entries(r) {
            for (start, end, v4) in ranges {
                if v4 {
                    self.ip4.push((start, end, cat.clone()));
                } else {
                    self.ip6.push((start, end, cat.clone()));
                }
            }
            return Ok(());
        }
        // Match policy::DomainMatcher: an unknown `type:pattern` prefix falls
        // back to suffix matching the pattern rather than silently disabling
        // the rule. IPs are parsed first because IPv6 literals contain ':'.
        let pattern = r.split_once(':').map_or(r, |(_, pattern)| pattern);
        self.add_domain_suffix(&cat, pattern)
    }

    pub fn add_domain_suffix(&mut self, category: &str, host: &str) -> Result<()> {
        let cat = self.add_category(category)?;
        let name = normalize_domain(host);
        let name = name.strip_prefix("*.").unwrap_or(&name);
        if name.is_empty() {
            bail!("empty domain in category {category:?}");
        }
        self.suffix
            .entry(reverse_labels(name))
            .or_default()
            .insert(cat);
        Ok(())
    }

    pub fn add_domain_exact(&mut self, category: &str, host: &str) -> Result<()> {
        let cat = self.add_category(category)?;
        let name = normalize_domain(host);
        if name.is_empty() {
            bail!("empty domain in category {category:?}");
        }
        self.exact.entry(name).or_default().insert(cat);
        Ok(())
    }

    pub fn add_keyword(&mut self, category: &str, fragment: &str) -> Result<()> {
        let cat = self.add_category(category)?;
        let frag = normalize_domain(fragment);
        if frag.is_empty() {
            bail!("empty keyword in category {category:?}");
        }
        self.keywords.entry(frag).or_default().insert(cat);
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.ip4.is_empty()
            && self.ip6.is_empty()
            && self.exact.is_empty()
            && self.suffix.is_empty()
            && self.keywords.is_empty()
    }

    /// Produce the validated in-memory book.
    pub fn build(&self) -> Result<RawBook> {
        let cat_list: Vec<String> = self.categories.iter().cloned().collect();
        let cat_id: HashMap<&str, u32> = cat_list
            .iter()
            .enumerate()
            .map(|(i, name)| (name.as_str(), i as u32))
            .collect();
        let words = cat_list
            .len()
            .div_ceil(64)
            .max(usize::from(!cat_list.is_empty()));

        let categories: Vec<Category> = cat_list
            .iter()
            .map(|name| {
                let parent = match name.rfind('/') {
                    Some(i) => cat_id[&name[..i]],
                    None => u32::MAX,
                };
                Category {
                    name: name.clone(),
                    parent,
                }
            })
            .collect();

        let mask_of = |cats: &BTreeSet<String>| -> Vec<u64> {
            let mut m = vec![0u64; words];
            for c in cats {
                let id = cat_id[c.as_str()];
                m[(id / 64) as usize] |= 1u64 << (id % 64);
            }
            m
        };

        // Interning order is fixed (ip4, ip6, exact, suffix, keyword) and every
        // stream is already sorted, so catset ids are deterministic.
        let mut interner: HashMap<Vec<u64>, u32> = HashMap::new();
        let mut catsets: Vec<u64> = Vec::new();
        let mut intern = |mask: Vec<u64>| -> u32 {
            if let Some(&id) = interner.get(&mask) {
                return id;
            }
            let id = u32::try_from(interner.len()).expect("catset count fits u32");
            catsets.extend_from_slice(&mask);
            interner.insert(mask, id);
            id
        };

        let sweep4 = sweep(
            self.ip4
                .iter()
                .map(|(s, e, c)| (*s, *e, cat_id[c.as_str()]))
                .collect(),
            words,
        );
        let mut ip4 = Vec::with_capacity(sweep4.len());
        for (s, e, mask) in sweep4 {
            let s = u32::try_from(s).context("ip4 sweep out of range")?;
            let e = u32::try_from(e).context("ip4 sweep out of range")?;
            ip4.push((s, e, intern(mask)));
        }
        let sweep6 = sweep(
            self.ip6
                .iter()
                .map(|(s, e, c)| (*s, *e, cat_id[c.as_str()]))
                .collect(),
            words,
        );
        let mut ip6 = Vec::with_capacity(sweep6.len());
        for (s, e, mask) in sweep6 {
            ip6.push((s, e, intern(mask)));
        }

        let mut domain_exact = Vec::with_capacity(self.exact.len());
        for (text, cats) in &self.exact {
            domain_exact.push(StrEntry {
                text: text.clone(),
                catset: intern(mask_of(cats)),
            });
        }
        let mut domain_suffix = Vec::with_capacity(self.suffix.len());
        for (text, cats) in &self.suffix {
            domain_suffix.push(StrEntry {
                text: text.clone(),
                catset: intern(mask_of(cats)),
            });
        }
        let mut keywords = Vec::with_capacity(self.keywords.len());
        for (text, cats) in &self.keywords {
            keywords.push(StrEntry {
                text: text.clone(),
                catset: intern(mask_of(cats)),
            });
        }

        let book = RawBook {
            build_epoch: self.epoch,
            categories,
            catset_words: u32::try_from(words)?,
            catsets,
            ip4,
            ip6,
            domain_exact,
            domain_suffix,
            keywords,
        };
        validate(&book)?;
        Ok(book)
    }

    /// Build and serialize in one step.
    pub fn build_bytes(&self) -> Result<Vec<u8>> {
        encode(&self.build()?)
    }
}

const IPV4_MAPPED_START: u128 = 0xffffu128 << 32;
const IPV4_MAPPED_END: u128 = IPV4_MAPPED_START | u32::MAX as u128;

/// Parse an IP or CIDR entry into canonical inclusive numeric ranges.
/// IPv4-mapped portions of IPv6 ranges move into the IPv4 table; a broad range
/// such as `::/0` can therefore yield IPv6-before, IPv4, and IPv6-after pieces.
pub fn parse_ip_entries(s: &str) -> Option<Vec<(u128, u128, bool)>> {
    let t = s.trim();
    if let Ok(net) = t.parse::<ipnet::IpNet>() {
        let range = match net {
            ipnet::IpNet::V4(n) => (
                u128::from(u32::from(n.network())),
                u128::from(u32::from(n.broadcast())),
                true,
            ),
            ipnet::IpNet::V6(n) => (u128::from(n.network()), u128::from(n.broadcast()), false),
        };
        return Some(canonicalize_ip_range(range));
    }
    if let Ok(addr) = t.parse::<IpAddr>() {
        let range = match addr {
            IpAddr::V4(a) => {
                let v = u128::from(u32::from(a));
                (v, v, true)
            }
            IpAddr::V6(a) => {
                let v = u128::from(a);
                (v, v, false)
            }
        };
        return Some(canonicalize_ip_range(range));
    }
    None
}

fn canonicalize_ip_range((start, end, is_v4): (u128, u128, bool)) -> Vec<(u128, u128, bool)> {
    if is_v4 || end < IPV4_MAPPED_START || start > IPV4_MAPPED_END {
        return vec![(start, end, is_v4)];
    }
    let mut out = Vec::with_capacity(3);
    if start < IPV4_MAPPED_START {
        out.push((start, IPV4_MAPPED_START - 1, false));
    }
    let mapped_start = start.max(IPV4_MAPPED_START) - IPV4_MAPPED_START;
    let mapped_end = end.min(IPV4_MAPPED_END) - IPV4_MAPPED_START;
    out.push((mapped_start, mapped_end, true));
    if end > IPV4_MAPPED_END {
        out.push((IPV4_MAPPED_END + 1, end, false));
    }
    out
}

/// Boundary sweep: turn possibly-overlapping categorized ranges into sorted,
/// disjoint segments whose mask is the union of every covering range's
/// category bit. Adjacent segments with identical masks are merged.
fn sweep(ranges: Vec<RawRange>, words: usize) -> Vec<(u128, u128, Vec<u64>)> {
    if ranges.is_empty() {
        return Vec::new();
    }
    // events[boundary] = list of (cat_id, +1/-1)
    let mut events: BTreeMap<Boundary, Vec<(u32, i32)>> = BTreeMap::new();
    for (start, end, cat) in &ranges {
        events.entry((false, *start)).or_default().push((*cat, 1));
        let end_excl: Boundary = match end.checked_add(1) {
            Some(v) => (false, v),
            None => (true, 0),
        };
        events.entry(end_excl).or_default().push((*cat, -1));
    }
    let mut active: BTreeMap<u32, i64> = BTreeMap::new();
    let mut out: Vec<(u128, u128, Vec<u64>)> = Vec::new();
    let mut prev: Option<Boundary> = None;
    for (boundary, deltas) in events {
        if let Some((prev_inf, prev_pos)) = prev {
            if !active.is_empty() && !prev_inf {
                let seg_end = match boundary {
                    (false, pos) => pos - 1,
                    (true, _) => u128::MAX,
                };
                let mut mask = vec![0u64; words];
                for cat in active.keys() {
                    mask[(*cat / 64) as usize] |= 1u64 << (*cat % 64);
                }
                match out.last_mut() {
                    Some((_, last_end, last_mask))
                        if *last_mask == mask && last_end.checked_add(1) == Some(prev_pos) =>
                    {
                        *last_end = seg_end;
                    }
                    _ => out.push((prev_pos, seg_end, mask)),
                }
            }
        }
        for (cat, delta) in deltas {
            let counter = active.entry(cat).or_insert(0);
            *counter += i64::from(delta);
            if *counter <= 0 {
                active.remove(&cat);
            }
        }
        prev = Some(boundary);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::book::AddrBook;
    use super::super::format::decode;
    use super::*;

    #[test]
    fn build_is_deterministic_regardless_of_insertion_order() {
        let mut a = BookBuilder::new(1);
        a.add_rule("aws", "3.0.0.0/8").unwrap();
        a.add_rule("aws/ec2", "3.5.0.0/16").unwrap();
        a.add_rule("google", "google.com").unwrap();
        let mut b = BookBuilder::new(1);
        b.add_rule("google", "google.com").unwrap();
        b.add_rule("aws/ec2", "3.5.0.0/16").unwrap();
        b.add_rule("aws", "3.0.0.0/8").unwrap();
        assert_eq!(a.build_bytes().unwrap(), b.build_bytes().unwrap());
    }

    #[test]
    fn overlapping_ranges_become_disjoint_segments() {
        let mut b = BookBuilder::new(0);
        b.add_rule("a", "10.0.0.0/8").unwrap();
        b.add_rule("b", "10.1.0.0/16").unwrap();
        let raw = b.build().unwrap();
        // Segments: [10.0.0.0, 10.0.255.255] {a}, [10.1.0.0, 10.1.255.255]
        // {a,b}, [10.2.0.0, 10.255.255.255] {a} — sorted and disjoint.
        assert_eq!(raw.ip4.len(), 3);
        for w in raw.ip4.windows(2) {
            assert!(w[0].1 < w[1].0);
        }
        let book = AddrBook::from_raw(raw, [0u8; 32]);
        let a = book.resolve(&["a".into()]).unwrap();
        let bsel = book.resolve(&["b".into()]).unwrap();
        assert!(book.matches("10.1.2.3", &a));
        assert!(book.matches("10.1.2.3", &bsel));
        assert!(book.matches("10.2.0.1", &a));
        assert!(!book.matches("10.2.0.1", &bsel));
        assert!(!book.matches("11.0.0.1", &a));
    }

    #[test]
    fn adjacent_same_category_ranges_merge() {
        let mut b = BookBuilder::new(0);
        b.add_rule("a", "10.0.0.0/25").unwrap();
        b.add_rule("a", "10.0.0.128/25").unwrap();
        let raw = b.build().unwrap();
        assert_eq!(raw.ip4.len(), 1);
        assert_eq!(
            raw.ip4[0].0,
            u32::from(std::net::Ipv4Addr::new(10, 0, 0, 0))
        );
        assert_eq!(
            raw.ip4[0].1,
            u32::from(std::net::Ipv4Addr::new(10, 0, 0, 255))
        );
    }

    #[test]
    fn duplicate_entries_collapse() {
        let mut b = BookBuilder::new(0);
        b.add_rule("a", "example.com").unwrap();
        b.add_rule("a", "EXAMPLE.com.").unwrap();
        b.add_rule("a", "1.2.3.4").unwrap();
        b.add_rule("a", "1.2.3.4/32").unwrap();
        let raw = b.build().unwrap();
        assert_eq!(raw.domain_suffix.len(), 1);
        assert_eq!(raw.ip4.len(), 1);
    }

    #[test]
    fn unknown_domain_prefix_uses_runtime_fallback_semantics() {
        let mut b = BookBuilder::new(0);
        b.add_rule("x", "typo:example.com").unwrap();
        let book = AddrBook::from_raw(b.build().unwrap(), [0u8; 32]);
        let sel = book.resolve(&["x".into()]).unwrap();
        assert!(book.matches("www.example.com", &sel));
        assert!(!book.matches("typo:example.com", &sel));
    }

    #[test]
    fn full_range_v6_does_not_overflow() {
        let mut b = BookBuilder::new(0);
        b.add_rule("all", "::/0").unwrap();
        let raw = b.build().unwrap();
        assert_eq!(raw.ip4, vec![(0, u32::MAX, 0)]);
        assert_eq!(
            raw.ip6,
            vec![
                (0, IPV4_MAPPED_START - 1, 0),
                (IPV4_MAPPED_END + 1, u128::MAX, 0)
            ]
        );
        let book = AddrBook::from_raw(raw, [0u8; 32]);
        let sel = book.resolve(&["all".into()]).unwrap();
        assert!(book.matches("::1", &sel));
        assert!(book.matches("::ffff:192.0.2.1", &sel));
        assert!(book.matches("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &sel));
    }

    #[test]
    fn ipv4_mapped_ipv6_ranges_are_canonicalized_to_ipv4() {
        let mut b = BookBuilder::new(0);
        b.add_rule("mapped", "::ffff:192.0.2.0/120").unwrap();
        let raw = b.build().unwrap();
        assert_eq!(raw.ip4.len(), 1);
        assert!(raw.ip6.is_empty());
        let book = AddrBook::from_raw(raw, [0u8; 32]);
        let sel = book.resolve(&["mapped".into()]).unwrap();
        assert!(book.matches("192.0.2.7", &sel));
        assert!(book.matches("::ffff:192.0.2.7", &sel));
    }

    #[test]
    fn category_paths_are_validated() {
        let mut b = BookBuilder::new(0);
        assert!(b.add_category("Google/Ads").is_ok()); // lowercased
        assert!(b.add_category("google//ads").is_err());
        assert!(b.add_category("goo gle").is_err());
        assert!(b.add_category("").is_err());
        assert!(b.add_category("geosite@cn").is_ok());
        assert!(b.add_category("geosite/geolocation-!cn").is_ok());
    }

    #[test]
    fn built_bytes_decode_and_validate() {
        let mut b = BookBuilder::new(9);
        b.add_rule("x", "full:a.example").unwrap();
        b.add_rule("x", "keyword:tracker").unwrap();
        b.add_rule("y", "domain:b.example").unwrap();
        b.add_rule("y", "192.168.0.0/16").unwrap();
        let bytes = b.build_bytes().unwrap();
        let raw = decode(&bytes).unwrap();
        assert_eq!(raw.build_epoch, 9);
        assert_eq!(raw.domain_exact.len(), 1);
        assert_eq!(raw.domain_suffix.len(), 1);
        assert_eq!(raw.keywords.len(), 1);
        // Ancestors: categories are exactly x and y.
        assert_eq!(raw.categories.len(), 2);
    }

    #[test]
    fn empty_builder_builds_empty_book() {
        let b = BookBuilder::new(0);
        let raw = b.build().unwrap();
        let bytes = encode(&raw).unwrap();
        let book = AddrBook::from_bytes(&bytes).unwrap();
        assert_eq!(book.category_count(), 0);
        assert!(book.resolve(&["anything".into()]).is_err());
    }
}
