//! IP matcher ported from the Go `pkgs/ip_set` / `netlist`. A single address is
//! treated as a host route (`/32` or `/128`); CIDR strings are taken as-is.

use ipnet::IpNet;
use std::collections::HashSet;
use std::net::IpAddr;

#[derive(Default)]
pub struct IpMatcher {
    /// Host routes (`/32` / `/128` and bare addresses). O(1) lookup.
    exact: HashSet<IpAddr>,
    /// Real networks (prefix shorter than host route). OR-semantics.
    cidrs: Vec<IpNet>,
}

impl IpMatcher {
    #[allow(dead_code)] // used in tests; kept as ergonomic constructor
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry that is either a CIDR (`10.0.0.0/8`) or a bare IP.
    pub fn add(&mut self, entry: &str) -> bool {
        let s = entry.trim();
        if let Ok(net) = s.parse::<IpNet>() {
            self.insert_net(net);
            return true;
        }
        if let Ok(addr) = s.parse::<IpAddr>() {
            self.exact.insert(addr);
            return true;
        }
        false
    }

    fn insert_net(&mut self, net: IpNet) {
        if is_host_route(&net) {
            self.exact.insert(net.addr());
        } else {
            self.cidrs.push(net);
        }
    }

    pub fn matches(&self, addr: IpAddr) -> bool {
        self.exact.contains(&addr) || self.cidrs.iter().any(|n| n.contains(&addr))
    }

    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.cidrs.is_empty()
    }

    pub(crate) fn contribute_exact(&self, mut f: impl FnMut(IpAddr)) {
        for addr in &self.exact {
            f(*addr);
        }
    }

    pub(crate) fn contribute_cidrs(&self, mut f: impl FnMut(IpNet)) {
        for net in &self.cidrs {
            f(*net);
        }
    }
}

fn is_host_route(net: &IpNet) -> bool {
    match net {
        IpNet::V4(n) => n.prefix_len() == 32,
        IpNet::V6(n) => n.prefix_len() == 128,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_and_cidr() {
        let mut m = IpMatcher::new();
        assert!(m.add("1.1.1.1"));
        assert!(m.add("10.0.0.0/8"));
        assert!(m.matches("1.1.1.1".parse().unwrap()));
        assert!(!m.matches("1.1.1.2".parse().unwrap()));
        assert!(m.matches("10.2.3.4".parse().unwrap()));
        assert!(!m.matches("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn host_route_cidr_is_exact() {
        let mut m = IpMatcher::new();
        assert!(m.add("192.0.2.10/32"));
        assert!(m.add("2001:db8::1/128"));
        assert!(m.matches("192.0.2.10".parse().unwrap()));
        assert!(!m.matches("192.0.2.11".parse().unwrap()));
        assert!(m.matches("2001:db8::1".parse().unwrap()));
        assert!(!m.matches("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn many_exact_hosts_keep_or_semantics() {
        let mut m = IpMatcher::new();
        for i in 0..1000u32 {
            assert!(m.add(&format!("203.0.{}.{}", i / 256, i % 256)));
        }
        assert!(m.add("8.8.8.0/24"));
        assert!(m.matches("203.0.3.231".parse().unwrap()));
        assert!(!m.matches("203.1.0.0".parse().unwrap()));
        assert!(m.matches("8.8.8.8".parse().unwrap()));
        assert!(!m.matches("8.8.9.1".parse().unwrap()));
    }
}
