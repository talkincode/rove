//! Domain matcher ported from the Go `pkgs/matcher/domain` MixMatcher.
//! Default match type is `domain` (suffix / subdomain), matching the original
//! `NewDomainMixMatcher` which calls `SetDefaultMatcher(MatcherDomain)`.
//! Supported prefixes: `full:`, `domain:`, `keyword:` (regexp omitted — unused
//! by the dataset and avoids a regex dependency).

use std::collections::HashMap;

/// Lowercase, strip a leading/trailing dot. Mirrors Go `NormalizeDomain`
/// closely enough for proxy routing (fqdn- and case-insensitive).
pub(crate) fn normalize(s: &str) -> String {
    s.trim().trim_matches('.').to_ascii_lowercase()
}

#[derive(Default)]
struct LabelNode {
    terminal: bool,
    children: HashMap<String, LabelNode>,
}

/// Suffix matcher: an inserted `api.openai.com` matches `api.openai.com` and any
/// `*.api.openai.com`. Walks query labels from the TLD inward.
#[derive(Default)]
struct SubDomainMatcher {
    root: LabelNode,
    len: usize,
}

impl SubDomainMatcher {
    fn add(&mut self, s: &str) {
        let s = normalize(s);
        let s = s.strip_prefix("*.").unwrap_or(&s);
        if s.is_empty() {
            return;
        }
        let mut node = &mut self.root;
        for label in s.split('.').rev() {
            node = node.children.entry(label.to_string()).or_default();
        }
        if !node.terminal {
            node.terminal = true;
            self.len += 1;
        }
    }

    fn matches_normalized(&self, s: &str) -> bool {
        if s.is_empty() {
            return false;
        }
        let mut node = &self.root;
        let mut matched = false;
        for label in s.split('.').rev() {
            match node.children.get(label) {
                Some(child) => {
                    if child.terminal {
                        matched = true;
                    }
                    node = child;
                }
                None => break,
            }
        }
        matched
    }

    fn contribute_suffixes(&self, f: &mut impl FnMut(&str)) {
        fn walk(node: &LabelNode, labels: &mut Vec<String>, f: &mut impl FnMut(&str)) {
            if node.terminal && !labels.is_empty() {
                let domain = labels.iter().rev().cloned().collect::<Vec<_>>().join(".");
                f(&domain);
            }
            for (label, child) in &node.children {
                labels.push(label.clone());
                walk(child, labels, f);
                labels.pop();
            }
        }
        walk(&self.root, &mut Vec::new(), f);
    }
}

/// Mixed matcher: exact + suffix + keyword. `Match` checks them in order.
#[derive(Default)]
pub struct DomainMatcher {
    full: HashMap<String, ()>,
    domain: SubDomainMatcher,
    keyword: Vec<String>,
}

impl DomainMatcher {
    #[allow(dead_code)] // used in tests; kept as ergonomic constructor
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule. `type:pattern`; default type is `domain` (suffix).
    pub fn add(&mut self, rule: &str) {
        let (typ, pattern) = match rule.split_once(':') {
            Some((t, p)) => (t, p),
            None => ("domain", rule),
        };
        match typ {
            "full" => {
                self.full.insert(normalize(pattern), ());
            }
            "keyword" => {
                let k = normalize(pattern);
                if !k.is_empty() {
                    self.keyword.push(k);
                }
            }
            // "domain" and anything unknown fall back to suffix matching so an
            // operator typo never silently disables a rule.
            _ => self.domain.add(pattern),
        }
    }

    pub fn matches(&self, host: &str) -> bool {
        self.matches_normalized(&normalize(host))
    }

    pub(crate) fn matches_normalized(&self, n: &str) -> bool {
        if n.is_empty() {
            return false;
        }
        if self.full.contains_key(n) {
            return true;
        }
        if self.domain.matches_normalized(n) {
            return true;
        }
        self.keyword.iter().any(|k| n.contains(k.as_str()))
    }

    pub(crate) fn contribute_full(&self, mut f: impl FnMut(&str)) {
        for host in self.full.keys() {
            f(host);
        }
    }

    pub(crate) fn contribute_keywords(&self, mut f: impl FnMut(&str)) {
        for keyword in &self.keyword {
            f(keyword);
        }
    }

    pub(crate) fn contribute_suffixes(&self, mut f: impl FnMut(&str)) {
        self.domain.contribute_suffixes(&mut f);
    }

    pub fn is_empty(&self) -> bool {
        self.full.is_empty() && self.domain.len == 0 && self.keyword.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_matches_subdomains() {
        let mut m = DomainMatcher::new();
        m.add("api.openai.com");
        assert!(m.matches("api.openai.com"));
        assert!(m.matches("cdn.api.openai.com"));
        assert!(m.matches("a.b.api.openai.com"));
        assert!(!m.matches("notapi.openai.com"));
        assert!(!m.matches("api.openai.com.evil.com"));
    }

    #[test]
    fn full_and_keyword() {
        let mut m = DomainMatcher::new();
        m.add("full:gmail.com");
        m.add("keyword:openai");
        assert!(m.matches("gmail.com"));
        assert!(!m.matches("mail.gmail.com")); // full = exact only
        assert!(m.matches("api.openai.com"));
    }

    #[test]
    fn case_and_dot_insensitive() {
        let mut m = DomainMatcher::new();
        m.add("Api.OpenAI.Com.");
        assert!(m.matches("CDN.api.openai.com"));
    }

    #[test]
    fn wildcard_notation_is_a_suffix_alias() {
        let mut m = DomainMatcher::new();
        m.add("*.api.openai.com");
        assert!(m.matches("api.openai.com"));
        assert!(m.matches("cdn.api.openai.com"));
        assert!(!m.matches("notapi.openai.com"));
    }
}
