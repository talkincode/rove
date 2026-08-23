//! Control-plane sidecar export: `.rab` → TeamsEdge `rove-addrbook.json`.
//!
//! The binary artifact is what Rove nodes load. Control planes that expand
//! `book:<category>` into PAC/Kard rules need a JSON projection with plain
//! domain strings and CIDR lists. This module is that projection; it is not
//! a second source of truth — always rebuild from the same `.rab` bytes.

use super::book::reverse_labels;
use super::format::RawBook;
use anyhow::{bail, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};

const SIDE_CAR_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
pub struct ControlPlaneCatalog {
    pub schema_version: u32,
    pub addrbook_epoch: u64,
    pub categories: Vec<String>,
    pub expansions: BTreeMap<String, CategoryExpansion>,
}

#[derive(Debug, Serialize)]
pub struct CategoryExpansion {
    pub domains: DomainExpansion,
    pub cidrs: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DomainExpansion {
    pub exact: Vec<String>,
    pub suffix: Vec<String>,
    pub keyword: Vec<String>,
}

fn catset_has(raw: &RawBook, catset: u32, category_id: u32) -> bool {
    let words = raw.catset_words as usize;
    if words == 0 {
        return false;
    }
    let base = catset as usize * words;
    let word = category_id as usize / 64;
    let bit = category_id as usize % 64;
    if base + word >= raw.catsets.len() {
        return false;
    }
    raw.catsets[base + word] & (1u64 << bit) != 0
}

fn categories_for_catset(raw: &RawBook, catset: u32) -> impl Iterator<Item = usize> + '_ {
    (0..raw.categories.len()).filter(move |&id| catset_has(raw, catset, id as u32))
}

/// Convert an inclusive IPv4 range into the minimal covering CIDR set.
pub fn ipv4_range_to_cidrs(mut start: u32, end: u32) -> Vec<String> {
    let mut out = Vec::new();
    if start > end {
        return out;
    }
    while start <= end {
        let mut host_bits = start.trailing_zeros().min(31);
        loop {
            let size = 1u64 << host_bits;
            let last = start as u64 + size - 1;
            if last <= end as u64 && (start as u64) & (size - 1) == 0 {
                break;
            }
            if host_bits == 0 {
                break;
            }
            host_bits -= 1;
        }
        let prefix = 32 - host_bits;
        out.push(format!("{}/{}", Ipv4Addr::from(start), prefix));
        let next = start as u64 + (1u64 << host_bits);
        if next > u32::MAX as u64 {
            break;
        }
        start = next as u32;
    }
    out
}

/// Convert an inclusive IPv6 range into the minimal covering CIDR set.
pub fn ipv6_range_to_cidrs(mut start: u128, end: u128) -> Vec<String> {
    let mut out = Vec::new();
    if start > end {
        return out;
    }
    while start <= end {
        let mut host_bits = start.trailing_zeros().min(127);
        loop {
            let size = 1u128 << host_bits;
            let last = start.saturating_add(size - 1);
            if last <= end && start & (size - 1) == 0 {
                break;
            }
            if host_bits == 0 {
                break;
            }
            host_bits -= 1;
        }
        let prefix = 128 - host_bits;
        out.push(format!("{}/{}", Ipv6Addr::from(start), prefix));
        let size = 1u128 << host_bits;
        match start.checked_add(size) {
            Some(next) if next > start => start = next,
            _ => break,
        }
    }
    out
}

/// Project a decoded book into the control-plane sidecar schema (v1).
///
/// Each category's expansion contains only entries tagged to that category
/// (via catset bits). Parent categories do not auto-inherit children — callers
/// that need descendant semantics must expand at rule compile time (Rove node)
/// or select leaf categories (PAC sidecar expand).
pub fn control_plane_catalog(raw: &RawBook) -> Result<ControlPlaneCatalog> {
    if raw.categories.is_empty() {
        bail!("addrbook has no categories");
    }

    let mut exact: Vec<BTreeSet<String>> = vec![BTreeSet::new(); raw.categories.len()];
    let mut suffix: Vec<BTreeSet<String>> = vec![BTreeSet::new(); raw.categories.len()];
    let mut keyword: Vec<BTreeSet<String>> = vec![BTreeSet::new(); raw.categories.len()];
    let mut cidrs: Vec<BTreeSet<String>> = vec![BTreeSet::new(); raw.categories.len()];

    for entry in &raw.domain_exact {
        for id in categories_for_catset(raw, entry.catset) {
            exact[id].insert(entry.text.clone());
        }
    }
    for entry in &raw.domain_suffix {
        // Stored label-reversed; restore wire-order domain for PAC.
        let domain = reverse_labels(&entry.text);
        for id in categories_for_catset(raw, entry.catset) {
            suffix[id].insert(domain.clone());
        }
    }
    for entry in &raw.keywords {
        for id in categories_for_catset(raw, entry.catset) {
            keyword[id].insert(entry.text.clone());
        }
    }
    for &(start, end, catset) in &raw.ip4 {
        let list = ipv4_range_to_cidrs(start, end);
        for id in categories_for_catset(raw, catset) {
            cidrs[id].extend(list.iter().cloned());
        }
    }
    for &(start, end, catset) in &raw.ip6 {
        let list = ipv6_range_to_cidrs(start, end);
        for id in categories_for_catset(raw, catset) {
            cidrs[id].extend(list.iter().cloned());
        }
    }

    let mut categories = Vec::with_capacity(raw.categories.len());
    let mut expansions = BTreeMap::new();
    for (i, cat) in raw.categories.iter().enumerate() {
        categories.push(cat.name.clone());
        expansions.insert(
            cat.name.clone(),
            CategoryExpansion {
                domains: DomainExpansion {
                    exact: exact[i].iter().cloned().collect(),
                    suffix: suffix[i].iter().cloned().collect(),
                    keyword: keyword[i].iter().cloned().collect(),
                },
                cidrs: cidrs[i].iter().cloned().collect(),
            },
        );
    }

    Ok(ControlPlaneCatalog {
        schema_version: SIDE_CAR_SCHEMA_VERSION,
        addrbook_epoch: raw.build_epoch,
        categories,
        expansions,
    })
}

pub fn control_plane_catalog_json(raw: &RawBook) -> Result<Vec<u8>> {
    let catalog = control_plane_catalog(raw)?;
    // Compact JSON keeps the sidecar smaller for 70k+ entry books.
    let mut bytes = serde_json::to_vec(&catalog)?;
    bytes.push(b'\n');
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addrbook::BookBuilder;

    #[test]
    fn ipv4_range_covers_single_and_power_of_two() {
        assert_eq!(
            ipv4_range_to_cidrs(0x0a000000, 0x0a000000),
            vec!["10.0.0.0/32"]
        );
        assert_eq!(
            ipv4_range_to_cidrs(0x0a000000, 0x0a0000ff),
            vec!["10.0.0.0/24"]
        );
        assert_eq!(
            ipv4_range_to_cidrs(0x0a000001, 0x0a000002),
            vec!["10.0.0.1/32", "10.0.0.2/32"]
        );
    }

    #[test]
    fn export_matches_control_plane_schema() {
        let mut b = BookBuilder::new(2026072402);
        b.add_rule("geosite/openai", "full:api.openai.com").unwrap();
        b.add_rule("geosite/openai", "openai.com").unwrap();
        b.add_rule("geosite/openai", "keyword:openai").unwrap();
        b.add_rule("geoip/private", "10.0.0.0/8").unwrap();
        let bytes = b.build_bytes().unwrap();
        let raw = crate::addrbook::format::decode(&bytes).unwrap();
        let catalog = control_plane_catalog(&raw).unwrap();
        assert_eq!(catalog.schema_version, 1);
        assert_eq!(catalog.addrbook_epoch, 2026072402);
        assert_eq!(
            catalog.categories,
            vec![
                "geoip".to_string(),
                "geoip/private".into(),
                "geosite".into(),
                "geosite/openai".into()
            ]
        );
        let openai = catalog.expansions.get("geosite/openai").unwrap();
        assert_eq!(openai.domains.exact, vec!["api.openai.com"]);
        assert_eq!(openai.domains.suffix, vec!["openai.com"]);
        assert_eq!(openai.domains.keyword, vec!["openai"]);
        let private = catalog.expansions.get("geoip/private").unwrap();
        assert_eq!(private.cidrs, vec!["10.0.0.0/8"]);
        // Parent buckets exist but stay empty unless entries were tagged there.
        assert!(catalog
            .expansions
            .get("geosite")
            .unwrap()
            .domains
            .exact
            .is_empty());
    }
}
