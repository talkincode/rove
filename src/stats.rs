//! Shared traffic counters for both the periodic access-log stats gauge and
//! the read-only SNMP agent (issue #61).
//!
//! Two bounded-cardinality dimensions are tracked:
//!
//! - **listener** — one row per configured inbound listener (fixed at process
//!   start), matching the pre-existing access-log `"stats"` gauge lines.
//! - **egress** — one row per egress decision key (`"direct"` or
//!   `"upstream:<addr>"`), bounded by the policy snapshot's upstream set.
//!   `"block"` and pre-decision failures are intentionally *not* an egress
//!   row: blocked connections never leave the node.
//!
//! Counting is always on (two relaxed atomic adds per finished connection and
//! one guard per accepted connection) so the SNMP agent keeps working when
//! the access log is disabled. Consumers take point-in-time snapshots; they
//! never lock the hot path.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Default)]
struct SniffCounterSet {
    matched_total: AtomicU64,
    unsupported_total: AtomicU64,
    timeout_total: AtomicU64,
    malformed_total: AtomicU64,
    limit_exceeded_total: AtomicU64,
    incomplete_total: AtomicU64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SniffStatsRow {
    pub listener: String,
    pub matched_total: u64,
    pub unsupported_total: u64,
    pub timeout_total: u64,
    pub malformed_total: u64,
    pub limit_exceeded_total: u64,
    pub incomplete_total: u64,
}

/// One dimension entry: current active tunnels plus cumulative byte totals.
/// `bytes_up` is client→target, `bytes_down` is target→client, mirroring the
/// access-log field names.
#[derive(Debug, Default)]
struct CounterSet {
    active: AtomicI64,
    bytes_up_total: AtomicU64,
    bytes_down_total: AtomicU64,
}

/// Decrements the owning entry's active gauge when dropped. Hold it for the
/// whole lifetime of a connection (listener dimension) or from successful
/// upstream establishment to teardown (egress dimension).
pub struct ActiveGuard {
    counters: Arc<CounterSet>,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.counters.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Point-in-time copy of one entry, sorted snapshots of which feed the SNMP
/// tables and the periodic access-log stats lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsRow {
    pub name: String,
    pub active: i64,
    pub bytes_up_total: u64,
    pub bytes_down_total: u64,
}

/// Process-wide traffic counter registry. Cheap to share (`Arc`); all methods
/// are lock-light: the per-entry fast path is a read of an already-populated
/// map plus relaxed atomic ops.
#[derive(Debug, Default)]
pub struct TrafficStats {
    listeners: Mutex<HashMap<String, Arc<CounterSet>>>,
    egress: Mutex<HashMap<String, Arc<CounterSet>>>,
    sniff: Mutex<HashMap<String, Arc<SniffCounterSet>>>,
}

impl TrafficStats {
    pub fn new() -> Arc<Self> {
        Arc::new(TrafficStats::default())
    }

    /// Marks one connection active on `listener` until the guard drops.
    pub fn track_listener(&self, listener: &str) -> ActiveGuard {
        Self::track(&self.listeners, listener)
    }

    /// Creates the listener row with zeroed counters if absent. Called at
    /// bind time so pollers (SNMP walkers, Cacti discovery) see every
    /// configured listener before its first connection.
    pub fn register_listener(&self, listener: &str) {
        Self::entry(&self.listeners, listener);
        Self::sniff_entry(&self.sniff, listener);
    }

    /// Marks one established upstream/direct tunnel active on `egress` until
    /// the guard drops. Call only after the outbound connection succeeded —
    /// the issue-#61 dimensional model counts egress `active` from the moment
    /// the decision materialised into a real connection.
    pub fn track_egress(&self, egress: &str) -> ActiveGuard {
        Self::track(&self.egress, egress)
    }

    /// Folds one finished connection's byte totals into the listener row.
    pub fn record_listener_bytes(&self, listener: &str, bytes_up: u64, bytes_down: u64) {
        Self::record(&self.listeners, listener, bytes_up, bytes_down);
    }

    /// Folds one finished connection's byte totals into the egress row.
    /// Callers skip `"block"` decisions (nothing egressed).
    pub fn record_egress_bytes(&self, egress: &str, bytes_up: u64, bytes_down: u64) {
        Self::record(&self.egress, egress, bytes_up, bytes_down);
    }

    /// Sorted point-in-time listener rows.
    pub fn listener_rows(&self) -> Vec<StatsRow> {
        Self::rows(&self.listeners)
    }

    /// Sorted point-in-time egress rows.
    pub fn egress_rows(&self) -> Vec<StatsRow> {
        Self::rows(&self.egress)
    }

    pub fn record_sniff(&self, listener: &str, outcome: crate::sniff::SniffOutcome) {
        let counters = Self::sniff_entry(&self.sniff, listener);
        let counter = match outcome {
            crate::sniff::SniffOutcome::Matched => &counters.matched_total,
            crate::sniff::SniffOutcome::Unsupported => &counters.unsupported_total,
            crate::sniff::SniffOutcome::Timeout => &counters.timeout_total,
            crate::sniff::SniffOutcome::Malformed => &counters.malformed_total,
            crate::sniff::SniffOutcome::LimitExceeded => &counters.limit_exceeded_total,
            crate::sniff::SniffOutcome::Incomplete => &counters.incomplete_total,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn sniff_rows(&self) -> Vec<SniffStatsRow> {
        let mut rows: Vec<SniffStatsRow> = {
            let map = self.sniff.lock().expect("sniff stats poisoned");
            map.iter()
                .map(|(listener, counters)| SniffStatsRow {
                    listener: listener.clone(),
                    matched_total: counters.matched_total.load(Ordering::Relaxed),
                    unsupported_total: counters.unsupported_total.load(Ordering::Relaxed),
                    timeout_total: counters.timeout_total.load(Ordering::Relaxed),
                    malformed_total: counters.malformed_total.load(Ordering::Relaxed),
                    limit_exceeded_total: counters.limit_exceeded_total.load(Ordering::Relaxed),
                    incomplete_total: counters.incomplete_total.load(Ordering::Relaxed),
                })
                .collect()
        };
        rows.sort_by(|left, right| left.listener.cmp(&right.listener));
        rows
    }

    fn track(map: &Mutex<HashMap<String, Arc<CounterSet>>>, name: &str) -> ActiveGuard {
        let counters = Self::entry(map, name);
        counters.active.fetch_add(1, Ordering::Relaxed);
        ActiveGuard { counters }
    }

    fn record(
        map: &Mutex<HashMap<String, Arc<CounterSet>>>,
        name: &str,
        bytes_up: u64,
        bytes_down: u64,
    ) {
        let counters = Self::entry(map, name);
        counters
            .bytes_up_total
            .fetch_add(bytes_up, Ordering::Relaxed);
        counters
            .bytes_down_total
            .fetch_add(bytes_down, Ordering::Relaxed);
    }

    /// Get-or-insert one entry. Reads under the lock first so the steady
    /// state allocates nothing; only the first touch of a name inserts.
    fn entry(map: &Mutex<HashMap<String, Arc<CounterSet>>>, name: &str) -> Arc<CounterSet> {
        {
            let map = map.lock().expect("traffic stats poisoned");
            if let Some(counters) = map.get(name) {
                return counters.clone();
            }
        }
        let mut map = map.lock().expect("traffic stats poisoned");
        map.entry(name.to_string()).or_default().clone()
    }

    fn sniff_entry(
        map: &Mutex<HashMap<String, Arc<SniffCounterSet>>>,
        listener: &str,
    ) -> Arc<SniffCounterSet> {
        {
            let map = map.lock().expect("sniff stats poisoned");
            if let Some(counters) = map.get(listener) {
                return counters.clone();
            }
        }
        let mut map = map.lock().expect("sniff stats poisoned");
        map.entry(listener.to_string()).or_default().clone()
    }

    fn rows(map: &Mutex<HashMap<String, Arc<CounterSet>>>) -> Vec<StatsRow> {
        let mut rows: Vec<StatsRow> = {
            let map = map.lock().expect("traffic stats poisoned");
            map.iter()
                .map(|(name, c)| StatsRow {
                    name: name.clone(),
                    active: c.active.load(Ordering::Relaxed),
                    bytes_up_total: c.bytes_up_total.load(Ordering::Relaxed),
                    bytes_down_total: c.bytes_down_total.load(Ordering::Relaxed),
                })
                .collect()
        };
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        rows
    }
}

/// Wall-clock-independent process uptime, shared by SNMP `sysUpTime` and the
/// v3 USM engine time. Constructed once at startup next to [`TrafficStats`].
#[derive(Debug, Clone, Copy)]
pub struct StartClock {
    started: Instant,
}

impl StartClock {
    pub fn now() -> Self {
        StartClock {
            started: Instant::now(),
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// SNMP TimeTicks are hundredths of a second, truncated to 32 bits with
    /// wraparound as the protocol prescribes.
    pub fn uptime_ticks(&self) -> u32 {
        (self.started.elapsed().as_millis() / 10) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row<'a>(rows: &'a [StatsRow], name: &str) -> &'a StatsRow {
        rows.iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("row {name} missing"))
    }

    #[test]
    fn register_listener_creates_zeroed_row_before_any_traffic() {
        let stats = TrafficStats::new();

        stats.register_listener("http-in");

        let rows = stats.listener_rows();
        let r = row(&rows, "http-in");
        assert_eq!(r.active, 0);
        assert_eq!(r.bytes_up_total, 0);
        assert_eq!(r.bytes_down_total, 0);
    }

    #[test]
    fn listener_guard_tracks_active_and_drop_decrements() {
        let stats = TrafficStats::new();

        let a = stats.track_listener("http-in");
        let b = stats.track_listener("http-in");
        let c = stats.track_listener("socks5-in");
        assert_eq!(row(&stats.listener_rows(), "http-in").active, 2);
        assert_eq!(row(&stats.listener_rows(), "socks5-in").active, 1);

        drop(a);
        drop(b);
        drop(c);
        assert_eq!(row(&stats.listener_rows(), "http-in").active, 0);
        assert_eq!(row(&stats.listener_rows(), "socks5-in").active, 0);
    }

    #[test]
    fn byte_totals_accumulate_per_dimension_independently() {
        let stats = TrafficStats::new();

        stats.record_listener_bytes("http-in", 100, 200);
        stats.record_listener_bytes("http-in", 1, 2);
        stats.record_egress_bytes("direct", 60, 120);
        stats.record_egress_bytes("upstream:10.0.0.5:1080", 41, 82);

        let l = stats.listener_rows();
        assert_eq!(row(&l, "http-in").bytes_up_total, 101);
        assert_eq!(row(&l, "http-in").bytes_down_total, 202);

        let e = stats.egress_rows();
        assert_eq!(row(&e, "direct").bytes_up_total, 60);
        assert_eq!(row(&e, "upstream:10.0.0.5:1080").bytes_up_total, 41);
        // The egress dimension never leaks into the listener table and
        // vice versa.
        assert!(l.iter().all(|r| r.name != "direct"));
        assert!(e.iter().all(|r| r.name != "http-in"));
    }

    #[test]
    fn rows_are_sorted_by_name_for_stable_snmp_walk_order() {
        let stats = TrafficStats::new();
        stats.record_egress_bytes("upstream:b", 1, 1);
        stats.record_egress_bytes("direct", 1, 1);
        stats.record_egress_bytes("upstream:a", 1, 1);

        let rows = stats.egress_rows();
        let names: Vec<&str> = rows.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, vec!["direct", "upstream:a", "upstream:b"]);
    }

    #[test]
    fn sniff_outcomes_are_counted_per_listener_without_domain_labels() {
        let stats = TrafficStats::new();
        stats.record_sniff("http-in", crate::sniff::SniffOutcome::Matched);
        stats.record_sniff("http-in", crate::sniff::SniffOutcome::Matched);
        stats.record_sniff("http-in", crate::sniff::SniffOutcome::Malformed);
        stats.record_sniff("socks-in", crate::sniff::SniffOutcome::Timeout);

        let rows = stats.sniff_rows();
        let http = rows.iter().find(|row| row.listener == "http-in").unwrap();
        assert_eq!(http.matched_total, 2);
        assert_eq!(http.malformed_total, 1);
        assert_eq!(http.timeout_total, 0);
        let socks = rows.iter().find(|row| row.listener == "socks-in").unwrap();
        assert_eq!(socks.timeout_total, 1);
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn egress_guard_tracks_established_tunnels() {
        let stats = TrafficStats::new();
        let g = stats.track_egress("direct");
        assert_eq!(row(&stats.egress_rows(), "direct").active, 1);
        drop(g);
        assert_eq!(row(&stats.egress_rows(), "direct").active, 0);
    }

    #[test]
    fn start_clock_reports_monotonic_uptime() {
        let clock = StartClock::now();
        let first = clock.uptime_ticks();
        std::thread::sleep(std::time::Duration::from_millis(25));
        assert!(clock.uptime_ticks() > first);
        // 25 ms sleep can't have crossed a full second boundary by more
        // than one tick of the seconds counter.
        assert!(clock.uptime_secs() <= 1);
    }
}
