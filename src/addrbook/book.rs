//! Query layer over a decoded `.rab` artifact: category resolution and the
//! hot-path match primitives (IP binary search + domain exact/suffix/keyword).
//!
//! Consistency model: a compiled policy `Snapshot` pins the `Arc<AddrBook>` it
//! was compiled against together with the `Selector`s resolved from it, so a
//! selector is never evaluated against a different book than the one that
//! produced it. Hot-swapping a book therefore goes through a snapshot
//! recompile (see `sync::Syncer::adopt_addrbook`), never an in-place swap.

use super::format::{sha256, RawBook};
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, Weak};

const MAX_SELECTOR_CACHE_ENTRIES: usize = 20_000;

/// A resolved set of categories, as a bitmask over the book's category ids.
/// Only meaningful together with the `AddrBook` that resolved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    mask: Arc<[u64]>,
}

impl Selector {
    pub fn is_empty(&self) -> bool {
        self.mask.iter().all(|w| *w == 0)
    }

    pub(crate) fn allocation(&self) -> (usize, usize) {
        (
            self.mask.as_ptr() as usize,
            std::mem::size_of_val(&*self.mask),
        )
    }
}

pub struct AddrBook {
    raw: RawBook,
    /// Full category path → category id.
    name_index: HashMap<String, u32>,
    /// SHA-256 of the artifact bytes; identifies a build for logs/reload skips.
    checksum: [u8; 32],
    /// Exact normalized pattern combinations share one immutable selector
    /// bitmap across groups in a snapshot. Weak values avoid retaining old
    /// snapshot selectors for the lifetime of the book.
    selector_cache: Mutex<HashMap<Vec<String>, Weak<[u64]>>>,
}

/// Normalize a domain the same way `policy::domain` does: lowercase, trim
/// whitespace and leading/trailing dots.
pub fn normalize_domain(s: &str) -> String {
    s.trim().trim_matches('.').to_ascii_lowercase()
}

/// `mail.google.com` → `com.google.mail` (labels reversed, joined with '.').
pub fn reverse_labels(domain: &str) -> String {
    let mut labels: Vec<&str> = domain.split('.').collect();
    labels.reverse();
    labels.join(".")
}

fn normalize_category(s: &str) -> String {
    s.trim().trim_matches('/').to_ascii_lowercase()
}

impl AddrBook {
    /// Decode + verify artifact bytes into a queryable book.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let raw = super::format::decode(bytes)?;
        let checksum = sha256(bytes);
        Ok(Self::from_raw(raw, checksum))
    }

    pub(crate) fn from_raw(raw: RawBook, checksum: [u8; 32]) -> Self {
        let name_index = raw
            .categories
            .iter()
            .enumerate()
            .map(|(i, c)| (c.name.clone(), i as u32))
            .collect();
        AddrBook {
            raw,
            name_index,
            checksum,
            selector_cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn build_epoch(&self) -> u64 {
        self.raw.build_epoch
    }

    pub fn checksum(&self) -> &[u8; 32] {
        &self.checksum
    }

    pub fn checksum_hex(&self) -> String {
        self.checksum.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn category_count(&self) -> usize {
        self.raw.categories.len()
    }

    pub fn categories(&self) -> impl Iterator<Item = &str> {
        self.raw.categories.iter().map(|c| c.name.as_str())
    }

    pub fn entry_counts(&self) -> EntryCounts {
        let words = self.raw.catset_words as usize;
        EntryCounts {
            catsets: self.raw.catsets.len().checked_div(words).unwrap_or(0),
            ip4: self.raw.ip4.len(),
            ip6: self.raw.ip6.len(),
            domain_exact: self.raw.domain_exact.len(),
            domain_suffix: self.raw.domain_suffix.len(),
            keywords: self.raw.keywords.len(),
        }
    }

    pub(crate) fn prune_selector_cache(&self) {
        self.selector_cache
            .lock()
            .expect("addrbook selector cache poisoned")
            .retain(|_, value| value.strong_count() > 0);
    }

    /// Resolve category paths into a selector bitmask. A pattern selects the
    /// category itself plus every descendant (`google` covers `google/ads`).
    /// A pattern that names no known category (neither exact nor as a prefix)
    /// is a hard error: silently matching nothing would fail open when the
    /// rule is a block rule.
    pub fn resolve(&self, patterns: &[String]) -> Result<Selector> {
        let mut names = Vec::with_capacity(patterns.len());
        for pattern in patterns {
            let name = normalize_category(pattern);
            if name.is_empty() {
                bail!("empty addrbook category pattern");
            }
            names.push(name);
        }
        names.sort();
        names.dedup();
        if names.is_empty() {
            return Ok(Selector {
                mask: Arc::from([]),
            });
        }
        if let Some(mask) = self
            .selector_cache
            .lock()
            .expect("addrbook selector cache poisoned")
            .get(&names)
            .and_then(Weak::upgrade)
        {
            return Ok(Selector { mask });
        }

        let words = self.raw.catset_words as usize;
        let mut mask = vec![0u64; words];
        for name in &names {
            let mut hit = false;
            if let Some(&id) = self.name_index.get(name) {
                set_bit(&mut mask, id);
                hit = true;
            }
            // Descendants form a contiguous range in the sorted category
            // table: names >= "name/" and < "name0" ('0' = '/' + 1).
            let lo = format!("{name}/");
            let hi = format!("{name}0");
            let cats = &self.raw.categories;
            let start = cats.partition_point(|c| c.name.as_str() < lo.as_str());
            let end = cats.partition_point(|c| c.name.as_str() < hi.as_str());
            for id in start..end {
                set_bit(&mut mask, id as u32);
                hit = true;
            }
            if !hit {
                bail!("unknown addrbook category {name:?}");
            }
        }
        let mask: Arc<[u64]> = mask.into();
        let mut cache = self
            .selector_cache
            .lock()
            .expect("addrbook selector cache poisoned");
        if let Some(existing) = cache.get(&names).and_then(Weak::upgrade) {
            return Ok(Selector { mask: existing });
        }
        if cache.len() < MAX_SELECTOR_CACHE_ENTRIES {
            cache.insert(names, Arc::downgrade(&mask));
        }
        Ok(Selector { mask })
    }

    /// Does `host` (domain or IP literal) belong to any selected category?
    pub fn matches(&self, host: &str, sel: &Selector) -> bool {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.matches_ip(ip, sel);
        }
        self.matches_domain(host, sel)
    }

    pub fn matches_ip(&self, ip: IpAddr, sel: &Selector) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let key = u32::from(v4);
                self.lookup_range4(key)
                    .map(|cs| self.catset_intersects(cs, sel))
                    .unwrap_or(false)
            }
            IpAddr::V6(v6) => {
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return self
                        .lookup_range4(u32::from(v4))
                        .map(|cs| self.catset_intersects(cs, sel))
                        .unwrap_or(false);
                }
                let key = u128::from(v6);
                self.lookup_range6(key)
                    .map(|cs| self.catset_intersects(cs, sel))
                    .unwrap_or(false)
            }
        }
    }

    pub fn matches_domain(&self, host: &str, sel: &Selector) -> bool {
        let name = normalize_domain(host);
        if name.is_empty() {
            return false;
        }
        if let Ok(i) = self
            .raw
            .domain_exact
            .binary_search_by(|e| e.text.as_str().cmp(name.as_str()))
        {
            if self.catset_intersects(self.raw.domain_exact[i].catset, sel) {
                return true;
            }
        }
        let rev = reverse_labels(&name);
        // Test every label-boundary prefix of the reversed name: for
        // `com.google.mail` that is `com`, `com.google`, `com.google.mail`.
        let bytes = rev.as_bytes();
        let mut boundary = 0usize;
        loop {
            let end = match bytes[boundary..].iter().position(|b| *b == b'.') {
                Some(p) => boundary + p,
                None => bytes.len(),
            };
            let candidate = &rev[..end];
            if let Ok(i) = self
                .raw
                .domain_suffix
                .binary_search_by(|e| e.text.as_str().cmp(candidate))
            {
                if self.catset_intersects(self.raw.domain_suffix[i].catset, sel) {
                    return true;
                }
            }
            if end == bytes.len() {
                break;
            }
            boundary = end + 1;
        }
        self.raw
            .keywords
            .iter()
            .any(|k| name.contains(k.text.as_str()) && self.catset_intersects(k.catset, sel))
    }

    /// All category names `host` belongs to (tooling / `rove-abctl query`).
    pub fn lookup_categories(&self, host: &str) -> Vec<String> {
        let words = usize::max(self.raw.catset_words as usize, 1);
        let mut acc = vec![0u64; words];
        let add_set = |cs: u32, acc: &mut Vec<u64>| {
            let w = self.raw.catset_words as usize;
            let base = cs as usize * w;
            for (i, word) in self.raw.catsets[base..base + w].iter().enumerate() {
                acc[i] |= word;
            }
        };
        if let Ok(ip) = host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => {
                    if let Some(cs) = self.lookup_range4(u32::from(v4)) {
                        add_set(cs, &mut acc);
                    }
                }
                IpAddr::V6(v6) => {
                    let catset = match v6.to_ipv4_mapped() {
                        Some(v4) => self.lookup_range4(u32::from(v4)),
                        None => self.lookup_range6(u128::from(v6)),
                    };
                    if let Some(cs) = catset {
                        add_set(cs, &mut acc);
                    }
                }
            }
        } else {
            let name = normalize_domain(host);
            if name.is_empty() {
                return Vec::new();
            }
            if let Ok(i) = self
                .raw
                .domain_exact
                .binary_search_by(|e| e.text.as_str().cmp(name.as_str()))
            {
                add_set(self.raw.domain_exact[i].catset, &mut acc);
            }
            let rev = reverse_labels(&name);
            let bytes = rev.as_bytes();
            let mut boundary = 0usize;
            loop {
                let end = match bytes[boundary..].iter().position(|b| *b == b'.') {
                    Some(p) => boundary + p,
                    None => bytes.len(),
                };
                if let Ok(i) = self
                    .raw
                    .domain_suffix
                    .binary_search_by(|e| e.text.as_str().cmp(&rev[..end]))
                {
                    add_set(self.raw.domain_suffix[i].catset, &mut acc);
                }
                if end == bytes.len() {
                    break;
                }
                boundary = end + 1;
            }
            for k in &self.raw.keywords {
                if name.contains(k.text.as_str()) {
                    add_set(k.catset, &mut acc);
                }
            }
        }
        let mut out = Vec::new();
        for (id, c) in self.raw.categories.iter().enumerate() {
            if get_bit(&acc, id as u32) {
                out.push(c.name.clone());
            }
        }
        out
    }

    fn lookup_range4(&self, key: u32) -> Option<u32> {
        let idx = self.raw.ip4.partition_point(|(s, _, _)| *s <= key);
        if idx == 0 {
            return None;
        }
        let (_, end, catset) = self.raw.ip4[idx - 1];
        (key <= end).then_some(catset)
    }

    fn lookup_range6(&self, key: u128) -> Option<u32> {
        let idx = self.raw.ip6.partition_point(|(s, _, _)| *s <= key);
        if idx == 0 {
            return None;
        }
        let (_, end, catset) = self.raw.ip6[idx - 1];
        (key <= end).then_some(catset)
    }

    fn catset_intersects(&self, catset: u32, sel: &Selector) -> bool {
        let w = self.raw.catset_words as usize;
        if w == 0 {
            return false;
        }
        let base = catset as usize * w;
        self.raw.catsets[base..base + w]
            .iter()
            .zip(sel.mask.iter())
            .any(|(a, b)| a & b != 0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryCounts {
    pub catsets: usize,
    pub ip4: usize,
    pub ip6: usize,
    pub domain_exact: usize,
    pub domain_suffix: usize,
    pub keywords: usize,
}

fn set_bit(mask: &mut [u64], id: u32) {
    let w = (id / 64) as usize;
    if w < mask.len() {
        mask[w] |= 1u64 << (id % 64);
    }
}

fn get_bit(mask: &[u64], id: u32) -> bool {
    let w = (id / 64) as usize;
    w < mask.len() && mask[w] & (1u64 << (id % 64)) != 0
}

#[cfg(test)]
mod tests {
    use super::super::builder::BookBuilder;
    use super::*;

    fn book() -> AddrBook {
        let mut b = BookBuilder::new(7);
        b.add_rule("google", "google.com").unwrap();
        b.add_rule("google/ads", "doubleclick.net").unwrap();
        b.add_rule("google/ads", "*.wildcard.example").unwrap();
        b.add_rule("google/ads", "full:ads.g.example").unwrap();
        b.add_rule("google", "keyword:googlevideo").unwrap();
        b.add_rule("google", "8.8.8.0/24").unwrap();
        b.add_rule("google", "2001:4860::/32").unwrap();
        b.add_rule("microsoft", "microsoft.com").unwrap();
        b.add_rule("microsoft", "13.64.0.0/11").unwrap();
        let bytes = b.build_bytes().unwrap();
        AddrBook::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn resolve_expands_descendants() {
        let bk = book();
        let google = bk.resolve(&["google".into()]).unwrap();
        let ads = bk.resolve(&["google/ads".into()]).unwrap();
        // Parent selector covers child entries; child selector does not cover
        // parent-only entries.
        assert!(bk.matches("doubleclick.net", &google));
        assert!(bk.matches("doubleclick.net", &ads));
        assert!(bk.matches("google.com", &google));
        assert!(!bk.matches("google.com", &ads));
    }

    #[test]
    fn resolve_unknown_category_fails_closed() {
        let bk = book();
        assert!(bk.resolve(&["gooogle".into()]).is_err());
        assert!(bk.resolve(&["".into()]).is_err());
        // Sibling name that shares a prefix must not be swallowed by the
        // range scan ("google" vs "google2").
        assert!(bk.resolve(&["google2".into()]).is_err());
    }

    #[test]
    fn domain_matching_covers_exact_suffix_keyword() {
        let bk = book();
        let sel = bk.resolve(&["google".into()]).unwrap();
        assert!(bk.matches("google.com", &sel));
        assert!(bk.matches("mail.google.com", &sel));
        assert!(bk.matches("a.b.google.com", &sel));
        assert!(bk.matches("cdn.wildcard.example", &sel));
        assert!(!bk.matches("notgoogle.com", &sel));
        assert!(!bk.matches("google.com.evil.example", &sel));
        assert!(bk.matches("ads.g.example", &sel));
        assert!(!bk.matches("sub.ads.g.example", &sel)); // full: is exact only
        assert!(bk.matches("r1---sn.googlevideo.example", &sel)); // keyword
        assert!(bk.matches("GOOGLE.COM.", &sel)); // normalization
    }

    #[test]
    fn ip_matching_is_range_based_per_family() {
        let bk = book();
        let g = bk.resolve(&["google".into()]).unwrap();
        let m = bk.resolve(&["microsoft".into()]).unwrap();
        assert!(bk.matches("8.8.8.8", &g));
        assert!(!bk.matches("8.8.9.1", &g));
        assert!(!bk.matches("8.8.8.8", &m));
        assert!(bk.matches("13.85.36.104", &m));
        assert!(bk.matches("2001:4860:4860::8888", &g));
        assert!(bk.matches("::ffff:8.8.8.8", &g));
        assert!(!bk.matches("2001:4861::1", &g));
    }

    #[test]
    fn lookup_categories_reports_all_hits() {
        let bk = book();
        let cats = bk.lookup_categories("doubleclick.net");
        assert_eq!(cats, vec!["google/ads".to_string()]);
        let cats = bk.lookup_categories("8.8.8.8");
        assert_eq!(cats, vec!["google".to_string()]);
        let cats = bk.lookup_categories("::ffff:8.8.8.8");
        assert_eq!(cats, vec!["google".to_string()]);
        assert!(bk.lookup_categories("unrelated.example").is_empty());
    }

    #[test]
    fn reverse_labels_roundtrip() {
        assert_eq!(reverse_labels("mail.google.com"), "com.google.mail");
        assert_eq!(reverse_labels("com"), "com");
    }
}
