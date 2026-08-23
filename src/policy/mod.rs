pub mod domain;
pub mod ip;

use crate::addrbook::{AddrBook, Selector};
use domain::DomainMatcher;
use ip::IpMatcher;
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

/// Addrbook-backed part of a rule set: the pinned book plus the selector that
/// was resolved against exactly that book at snapshot-compile time. Pinning
/// both together means a selector can never be evaluated against a different
/// book than the one that produced it (book swaps go through a snapshot
/// recompile instead).
#[derive(Clone)]
struct BookRules {
    book: Arc<AddrBook>,
    selector: Selector,
}

/// A compiled set of routing rules (domains + IPs + addrbook categories) used
/// for an action class (e.g. "send via upstream" or "block").
#[derive(Default)]
pub struct RuleSet {
    domains: DomainMatcher,
    ips: IpMatcher,
    book: Option<BookRules>,
}

impl RuleSet {
    /// Build from raw rule strings. An entry that parses as an IP/CIDR becomes
    /// an IP rule; a `book:<category>` entry references addrbook categories;
    /// everything else is a domain rule (default = suffix match).
    ///
    /// Fails closed: `book:` rules when no addrbook is loaded, and `book:`
    /// patterns naming unknown categories, are hard errors — a block rule that
    /// silently stopped matching would fail open.
    pub fn from_rules(rules: &[String], book: Option<&Arc<AddrBook>>) -> anyhow::Result<Self> {
        let mut rs = RuleSet::default();
        let mut book_patterns: Vec<String> = Vec::new();
        for r in rules {
            let t = r.trim();
            if t.is_empty() {
                continue;
            }
            if let Some(pattern) = t.strip_prefix("book:") {
                let pattern = pattern.trim();
                if pattern.is_empty() {
                    anyhow::bail!("empty book: rule");
                }
                book_patterns.push(pattern.to_string());
                continue;
            }
            if !rs.ips.add(t) {
                rs.domains.add(t);
            }
        }
        if !book_patterns.is_empty() {
            let Some(book) = book else {
                anyhow::bail!(
                    "rules reference addrbook categories ({}) but no [addrbook] is configured",
                    book_patterns.join(", ")
                );
            };
            let selector = book.resolve(&book_patterns)?;
            rs.book = Some(BookRules {
                book: book.clone(),
                selector,
            });
        }
        Ok(rs)
    }

    pub fn matches(&self, host: &str) -> bool {
        if let Ok(addr) = host.parse::<IpAddr>() {
            if self.ips.matches(addr) {
                return true;
            }
        } else if self.domains.matches(host) {
            return true;
        }
        match &self.book {
            Some(b) => b.book.matches(host, &b.selector),
            None => false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty() && self.ips.is_empty() && self.book.is_none()
    }

    pub(crate) fn book_selector_allocation(&self) -> Option<(usize, usize)> {
        self.book.as_ref().map(|rules| rules.selector.allocation())
    }

    pub(crate) fn index_into(&self, route_idx: u32, index: &mut RouteIndex) {
        self.domains
            .contribute_full(|host| index.note_full(host, route_idx));
        self.domains
            .contribute_suffixes(|host| index.note_suffix(host, route_idx));
        self.domains
            .contribute_keywords(|keyword| index.note_keyword(keyword, route_idx));
        self.ips
            .contribute_exact(|addr| index.note_ip(addr, route_idx));
        self.ips
            .contribute_cidrs(|net| index.note_cidr(net, route_idx));
        if let Some(book) = &self.book {
            index.note_book(route_idx, book.clone());
        }
    }
}

/// Compiled first-match index for schema-v4 routes. Each selector stores the
/// smallest route index that contains it, so a query walks each matcher once
/// and still preserves declaration order.
#[derive(Default)]
pub(crate) struct RouteIndex {
    full: HashMap<String, u32>,
    suffix: IndexedSuffix,
    keywords: Vec<(String, u32)>,
    exact_ip: HashMap<IpAddr, u32>,
    cidrs: Vec<(IpNet, u32)>,
    books: Vec<(u32, BookRules)>,
}

impl RouteIndex {
    fn note_full(&mut self, host: &str, idx: u32) {
        note_min(&mut self.full, host.to_string(), idx);
    }

    fn note_suffix(&mut self, host: &str, idx: u32) {
        self.suffix.add(host, idx);
    }

    fn note_keyword(&mut self, keyword: &str, idx: u32) {
        self.keywords.push((keyword.to_string(), idx));
    }

    fn note_ip(&mut self, addr: IpAddr, idx: u32) {
        note_min(&mut self.exact_ip, addr, idx);
    }

    fn note_cidr(&mut self, net: IpNet, idx: u32) {
        self.cidrs.push((net, idx));
    }

    fn note_book(&mut self, idx: u32, book: BookRules) {
        self.books.push((idx, book));
    }

    /// Smallest matching route index, or `None` when no selector matches.
    pub(crate) fn first_match(&self, host: &str) -> Option<usize> {
        let mut best = u32::MAX;
        if let Ok(addr) = host.parse::<IpAddr>() {
            if let Some(&idx) = self.exact_ip.get(&addr) {
                best = best.min(idx);
            }
            for (net, idx) in &self.cidrs {
                if *idx < best && net.contains(&addr) {
                    best = *idx;
                    if best == 0 {
                        break;
                    }
                }
            }
        } else {
            let normalized = domain::normalize(host);
            if !normalized.is_empty() {
                if let Some(&idx) = self.full.get(&normalized) {
                    best = best.min(idx);
                }
                if let Some(idx) = self.suffix.best(&normalized) {
                    best = best.min(idx);
                }
                for (keyword, idx) in &self.keywords {
                    if *idx < best && normalized.contains(keyword.as_str()) {
                        best = *idx;
                        if best == 0 {
                            break;
                        }
                    }
                }
            }
        }
        for (idx, book) in &self.books {
            if *idx >= best {
                continue;
            }
            if book.book.matches(host, &book.selector) {
                best = *idx;
                if best == 0 {
                    break;
                }
            }
        }
        (best != u32::MAX).then_some(best as usize)
    }
}

fn note_min<K: Eq + std::hash::Hash>(map: &mut HashMap<K, u32>, key: K, idx: u32) {
    map.entry(key)
        .and_modify(|current| *current = (*current).min(idx))
        .or_insert(idx);
}

#[derive(Default)]
struct IndexedSuffix {
    root: IndexedNode,
}

#[derive(Default)]
struct IndexedNode {
    best: Option<u32>,
    children: HashMap<String, IndexedNode>,
}

impl IndexedSuffix {
    fn add(&mut self, domain: &str, idx: u32) {
        if domain.is_empty() {
            return;
        }
        let mut node = &mut self.root;
        for label in domain.split('.').rev() {
            node = node.children.entry(label.to_string()).or_default();
        }
        node.best = Some(node.best.map_or(idx, |best| best.min(idx)));
    }

    fn best(&self, domain: &str) -> Option<u32> {
        if domain.is_empty() {
            return None;
        }
        let mut node = &self.root;
        let mut best = None;
        for label in domain.split('.').rev() {
            match node.children.get(label) {
                Some(child) => {
                    if let Some(idx) = child.best {
                        best = Some(best.map_or(idx, |current: u32| current.min(idx)));
                    }
                    node = child;
                }
                None => break,
            }
        }
        best
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addrbook::BookBuilder;

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn test_book() -> Arc<AddrBook> {
        let mut b = BookBuilder::new(1);
        b.add_rule("google", "google.com").unwrap();
        b.add_rule("google", "8.8.8.0/24").unwrap();
        b.add_rule("blocked", "bad.example").unwrap();
        Arc::new(AddrBook::from_bytes(&b.build_bytes().unwrap()).unwrap())
    }

    #[test]
    fn explicit_rules_still_work_without_book() {
        let rs = RuleSet::from_rules(&strings(&["discord.dev", "10.0.0.0/8"]), None).unwrap();
        assert!(rs.matches("cdn.discord.dev"));
        assert!(rs.matches("10.1.2.3"));
        assert!(!rs.matches("example.com"));
        assert!(!rs.is_empty());
    }

    #[test]
    fn book_rules_match_domains_and_ips() {
        let book = test_book();
        let rs = RuleSet::from_rules(&strings(&["book:google"]), Some(&book)).unwrap();
        assert!(rs.matches("mail.google.com"));
        assert!(rs.matches("8.8.8.8"));
        assert!(!rs.matches("bad.example")); // other category not selected
        assert!(!rs.is_empty());
    }

    #[test]
    fn explicit_and_book_rules_combine() {
        let book = test_book();
        let rs = RuleSet::from_rules(&strings(&["special.example", "book:blocked"]), Some(&book))
            .unwrap();
        assert!(rs.matches("special.example"));
        assert!(rs.matches("sub.bad.example"));
        assert!(!rs.matches("mail.google.com"));
    }

    #[test]
    fn book_rule_without_book_fails_closed() {
        let err = RuleSet::from_rules(&strings(&["book:google"]), None)
            .err()
            .expect("must fail without book");
        assert!(err.to_string().contains("no [addrbook]"), "{err}");
    }

    #[test]
    fn unknown_category_fails_closed() {
        let book = test_book();
        let err = RuleSet::from_rules(&strings(&["book:nope"]), Some(&book))
            .err()
            .expect("unknown category must fail");
        assert!(
            err.to_string().contains("unknown addrbook category"),
            "{err}"
        );
        assert!(RuleSet::from_rules(&strings(&["book:"]), Some(&book)).is_err());
    }

    #[test]
    fn route_index_preserves_first_match_across_selector_kinds() {
        let book = test_book();
        let mut index = RouteIndex::default();
        let first = RuleSet::from_rules(&strings(&["example.com"]), None).unwrap();
        let second = RuleSet::from_rules(&strings(&["full:cdn.example.com"]), None).unwrap();
        let third = RuleSet::from_rules(&strings(&["book:google"]), Some(&book)).unwrap();
        first.index_into(0, &mut index);
        second.index_into(1, &mut index);
        third.index_into(2, &mut index);
        assert_eq!(index.first_match("cdn.example.com"), Some(0));
        assert_eq!(index.first_match("mail.google.com"), Some(2));
        assert_eq!(index.first_match("nomatch.tld"), None);
    }

    #[test]
    fn identical_book_patterns_share_selector_storage() {
        let book = test_book();
        let a = RuleSet::from_rules(&strings(&["book:google"]), Some(&book)).unwrap();
        let b = RuleSet::from_rules(&strings(&["book:google"]), Some(&book)).unwrap();
        assert_eq!(
            a.book_selector_allocation(),
            b.book_selector_allocation(),
            "identical selectors should share one bitmap allocation"
        );
    }
}
