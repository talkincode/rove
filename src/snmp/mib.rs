//! MIB view for the SNMP agent: a sorted snapshot of `(OID, value)` pairs.
//!
//! Every request builds a fresh snapshot from live counters (cheap: a few
//! dozen entries), then GET is a binary search and GETNEXT is "first entry
//! greater than". Sorting the flat vector by OID automatically yields the
//! column-major walk order SNMP requires for tables, and makes lexicographic
//! ordering bugs impossible regardless of how the source rows are sorted.
//!
//! Implemented subtrees:
//! - `system` group (1.3.6.1.2.1.1) — identity for generic pollers.
//! - `snmp` group subset (1.3.6.1.2.1.11) — agent packet counters.
//! - enterprise subtree (default 1.3.6.1.4.1.32473.61) — scalars,
//!   listener table, egress table. `32473` is the RFC 5612 documentation
//!   enterprise number used as a placeholder until a real PEN exists.
//! - with v3 enabled: `snmpEngine` (1.3.6.1.6.3.10.2.1) and `usmStats`
//!   (1.3.6.1.6.3.15.1.1) so USM discovery and error Reports are visible.

use super::ber::{Oid, Value};
use crate::stats::StatsRow;

/// Node role reported by `geNodeRole`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRole {
    Edge = 1,
    Hop = 2,
}

/// Agent-level packet counters (snapshot of the live atomics).
#[derive(Debug, Clone, Copy, Default)]
pub struct AgentCountersSnapshot {
    pub in_pkts: u32,
    pub in_bad_versions: u32,
    pub in_bad_community_names: u32,
    pub in_asn_parse_errs: u32,
}

/// SNMP-engine view for v3 (present only when USM is configured).
#[derive(Debug, Clone)]
pub struct EngineView {
    pub engine_id: Vec<u8>,
    pub boots: i64,
    pub time: i64,
    pub max_message_size: i64,
    /// usmStats counters 1..=6: unsupportedSecLevels, notInTimeWindows,
    /// unknownUserNames, unknownEngineIDs, wrongDigests, decryptionErrors.
    pub usm_stats: [u32; 6],
}

/// Everything needed to materialize one MIB snapshot.
pub struct MibInputs<'a> {
    pub base: &'a Oid,
    pub node_id: &'a str,
    pub node_role: NodeRole,
    pub version: &'a str,
    pub uptime_ticks: u32,
    pub listeners: &'a [StatsRow],
    pub egress: &'a [StatsRow],
    pub agent: AgentCountersSnapshot,
    pub engine: Option<&'a EngineView>,
}

/// An immutable, sorted MIB snapshot answering GET / GETNEXT.
pub struct MibView {
    entries: Vec<(Oid, Value)>,
}

const SYSTEM: &[u32] = &[1, 3, 6, 1, 2, 1, 1];
const SNMP_GROUP: &[u32] = &[1, 3, 6, 1, 2, 1, 11];
const SNMP_ENGINE: &[u32] = &[1, 3, 6, 1, 6, 3, 10, 2, 1];
const USM_STATS: &[u32] = &[1, 3, 6, 1, 6, 3, 15, 1, 1];

impl MibView {
    pub fn build(inputs: &MibInputs<'_>) -> Self {
        let mut entries: Vec<(Oid, Value)> =
            Vec::with_capacity(16 + 4 * (inputs.listeners.len() + inputs.egress.len()));
        let system = Oid::new(SYSTEM);
        let role_name = match inputs.node_role {
            NodeRole::Edge => "edge",
            NodeRole::Hop => "hop",
        };
        let descr = format!("Rove {} node, version {}", role_name, inputs.version);
        entries.push((
            system.child(&[1, 0]),
            Value::OctetString(descr.into_bytes()),
        ));
        entries.push((system.child(&[2, 0]), Value::Oid(inputs.base.clone())));
        entries.push((system.child(&[3, 0]), Value::TimeTicks(inputs.uptime_ticks)));
        entries.push((system.child(&[4, 0]), Value::OctetString(Vec::new())));
        entries.push((
            system.child(&[5, 0]),
            Value::OctetString(inputs.node_id.as_bytes().to_vec()),
        ));
        entries.push((system.child(&[6, 0]), Value::OctetString(Vec::new())));
        // sysServices 72 = transport (2^(4-1)) + application (2^(7-1)).
        entries.push((system.child(&[7, 0]), Value::Integer(72)));

        let snmp = Oid::new(SNMP_GROUP);
        entries.push((snmp.child(&[1, 0]), Value::Counter32(inputs.agent.in_pkts)));
        entries.push((
            snmp.child(&[3, 0]),
            Value::Counter32(inputs.agent.in_bad_versions),
        ));
        entries.push((
            snmp.child(&[4, 0]),
            Value::Counter32(inputs.agent.in_bad_community_names),
        ));
        entries.push((
            snmp.child(&[6, 0]),
            Value::Counter32(inputs.agent.in_asn_parse_errs),
        ));

        // Enterprise scalars: base.1.<n>.0
        entries.push((
            inputs.base.child(&[1, 1, 0]),
            Value::OctetString(inputs.node_id.as_bytes().to_vec()),
        ));
        entries.push((
            inputs.base.child(&[1, 2, 0]),
            Value::Integer(inputs.node_role as i64),
        ));
        entries.push((
            inputs.base.child(&[1, 3, 0]),
            Value::OctetString(inputs.version.as_bytes().to_vec()),
        ));

        // Tables: base.2 listeners, base.3 egress; entry node .1, columns
        // .1=name .2=active .3=bytesUp .4=bytesDown, string index.
        push_table(&mut entries, &inputs.base.child(&[2, 1]), inputs.listeners);
        push_table(&mut entries, &inputs.base.child(&[3, 1]), inputs.egress);

        if let Some(engine) = inputs.engine {
            let eng = Oid::new(SNMP_ENGINE);
            entries.push((
                eng.child(&[1, 0]),
                Value::OctetString(engine.engine_id.clone()),
            ));
            entries.push((eng.child(&[2, 0]), Value::Integer(engine.boots)));
            entries.push((eng.child(&[3, 0]), Value::Integer(engine.time)));
            entries.push((eng.child(&[4, 0]), Value::Integer(engine.max_message_size)));

            let usm = Oid::new(USM_STATS);
            for (i, count) in engine.usm_stats.iter().enumerate() {
                entries.push((usm.child(&[i as u32 + 1, 0]), Value::Counter32(*count)));
            }
        }

        entries.sort_by(|a, b| a.0.cmp(&b.0));
        MibView { entries }
    }

    /// Exact GET. Returns the varbind value, or the RFC 3416 exception.
    pub fn get(&self, oid: &Oid) -> Value {
        match self.entries.binary_search_by(|(o, _)| o.cmp(oid)) {
            Ok(idx) => self.entries[idx].1.clone(),
            Err(idx) => {
                // If some implemented instance lives below the queried OID,
                // the object exists but this instance does not.
                if self.entries[idx..]
                    .first()
                    .is_some_and(|(o, _)| o.starts_with(oid))
                {
                    Value::NoSuchInstance
                } else {
                    Value::NoSuchObject
                }
            }
        }
    }

    /// GETNEXT: first entry with an OID strictly greater than `oid`.
    pub fn next(&self, oid: &Oid) -> Option<(Oid, Value)> {
        let idx = match self.entries.binary_search_by(|(o, _)| o.cmp(oid)) {
            Ok(idx) => idx + 1,
            Err(idx) => idx,
        };
        self.entries.get(idx).cloned()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Length-prefixed string index, the standard OID encoding for string keys.
fn string_index(name: &str) -> Vec<u32> {
    let bytes = name.as_bytes();
    let mut idx = Vec::with_capacity(bytes.len() + 1);
    idx.push(bytes.len() as u32);
    idx.extend(bytes.iter().map(|&b| b as u32));
    idx
}

fn push_table(entries: &mut Vec<(Oid, Value)>, entry_node: &Oid, rows: &[StatsRow]) {
    for row in rows {
        let idx = string_index(&row.name);
        let mut col = |c: u32, v: Value| {
            let mut suffix = vec![c];
            suffix.extend_from_slice(&idx);
            entries.push((entry_node.child(&suffix), v));
        };
        col(1, Value::OctetString(row.name.as_bytes().to_vec()));
        col(
            2,
            Value::Gauge32(row.active.max(0).min(u32::MAX as i64) as u32),
        );
        col(3, Value::Counter64(row.bytes_up_total));
        col(4, Value::Counter64(row.bytes_down_total));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, active: i64, up: u64, down: u64) -> StatsRow {
        StatsRow {
            name: name.to_string(),
            active,
            bytes_up_total: up,
            bytes_down_total: down,
        }
    }

    fn base() -> Oid {
        Oid::new(&[1, 3, 6, 1, 4, 1, 32473, 61])
    }

    fn inputs<'a>(
        base: &'a Oid,
        listeners: &'a [StatsRow],
        egress: &'a [StatsRow],
        engine: Option<&'a EngineView>,
    ) -> MibInputs<'a> {
        MibInputs {
            base,
            node_id: "edge-1",
            node_role: NodeRole::Edge,
            version: "2.0.4",
            uptime_ticks: 4200,
            listeners,
            egress,
            agent: AgentCountersSnapshot {
                in_pkts: 10,
                in_bad_versions: 1,
                in_bad_community_names: 2,
                in_asn_parse_errs: 3,
            },
            engine,
        }
    }

    #[test]
    fn get_returns_identity_scalars_and_tables() {
        let base = base();
        let listeners = [row("web", 3, 100, 200)];
        let egress = [
            row("direct", 1, 60, 120),
            row("upstream:10.0.0.1:8443", 2, 40, 80),
        ];
        let view = MibView::build(&inputs(&base, &listeners, &egress, None));

        assert_eq!(
            view.get(&Oid::new(&[1, 3, 6, 1, 2, 1, 1, 5, 0])),
            Value::OctetString(b"edge-1".to_vec())
        );
        assert_eq!(
            view.get(&Oid::new(&[1, 3, 6, 1, 2, 1, 1, 3, 0])),
            Value::TimeTicks(4200)
        );
        assert_eq!(view.get(&base.child(&[1, 2, 0])), Value::Integer(1));
        // listenerTable: web -> index [3,119,101,98]
        let web = [3, 119, 101, 98];
        let mut name_oid = vec![2, 1, 1];
        name_oid.extend_from_slice(&web);
        assert_eq!(
            view.get(&base.child(&name_oid)),
            Value::OctetString(b"web".to_vec())
        );
        let mut active_oid = vec![2, 1, 2];
        active_oid.extend_from_slice(&web);
        assert_eq!(view.get(&base.child(&active_oid)), Value::Gauge32(3));
        let mut up_oid = vec![2, 1, 3];
        up_oid.extend_from_slice(&web);
        assert_eq!(view.get(&base.child(&up_oid)), Value::Counter64(100));
    }

    #[test]
    fn get_distinguishes_no_such_instance_from_no_such_object() {
        let base = base();
        let view = MibView::build(&inputs(&base, &[], &[], None));

        // sysDescr without the .0 instance: object exists, instance missing.
        assert_eq!(
            view.get(&Oid::new(&[1, 3, 6, 1, 2, 1, 1, 1])),
            Value::NoSuchInstance
        );
        // Entirely foreign subtree.
        assert_eq!(
            view.get(&Oid::new(&[1, 3, 6, 1, 4, 1, 99999, 1, 0])),
            Value::NoSuchObject
        );
    }

    #[test]
    fn next_walks_the_entire_view_in_sorted_order_and_terminates() {
        let base = base();
        let listeners = [row("web", 1, 1, 1), row("socks", 1, 1, 1)];
        let egress = [row("direct", 1, 1, 1)];
        let view = MibView::build(&inputs(&base, &listeners, &egress, None));

        let mut cursor = Oid::new(&[0]);
        let mut seen = Vec::new();
        while let Some((oid, _)) = view.next(&cursor) {
            assert!(oid > cursor, "walk must strictly advance");
            seen.push(oid.clone());
            cursor = oid;
        }
        assert_eq!(seen.len(), view.len());
        // First entry is sysDescr.0, last is in the egress table.
        assert_eq!(seen[0], Oid::new(&[1, 3, 6, 1, 2, 1, 1, 1, 0]));
        assert!(seen.last().unwrap().starts_with(&base.child(&[3, 1, 4])));
    }

    #[test]
    fn table_walk_order_is_column_major_with_length_prefixed_index() {
        // "b" (len 1) must sort before "aa" (len 2) within each column even
        // though lexicographically "aa" < "b".
        let base = base();
        let listeners = [row("aa", 1, 0, 0), row("b", 2, 0, 0)];
        let view = MibView::build(&inputs(&base, &listeners, &[], None));

        let table = base.child(&[2]);
        let mut cursor = table.clone();
        let mut names = Vec::new();
        while let Some((oid, value)) = view.next(&cursor) {
            if !oid.starts_with(&table) {
                break;
            }
            if oid.starts_with(&base.child(&[2, 1, 1])) {
                if let Value::OctetString(name) = &value {
                    names.push(String::from_utf8(name.clone()).unwrap());
                }
            }
            cursor = oid;
        }
        assert_eq!(names, vec!["b", "aa"]);

        // active column follows the same index order.
        let mut b_active = vec![2, 1, 2, 1, b'b' as u32];
        assert_eq!(view.get(&base.child(&b_active)), Value::Gauge32(2));
        b_active = vec![2, 1, 2, 2, b'a' as u32, b'a' as u32];
        assert_eq!(view.get(&base.child(&b_active)), Value::Gauge32(1));
    }

    #[test]
    fn engine_view_adds_snmp_engine_and_usm_stats_groups() {
        let base = base();
        let engine = EngineView {
            engine_id: vec![0x80, 0x00, 0x7E, 0xD9, 0x04, b'x'],
            boots: 7,
            time: 1234,
            max_message_size: 65507,
            usm_stats: [1, 2, 3, 4, 5, 6],
        };
        let view = MibView::build(&inputs(&base, &[], &[], Some(&engine)));

        assert_eq!(
            view.get(&Oid::new(&[1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0])),
            Value::OctetString(engine.engine_id.clone())
        );
        assert_eq!(
            view.get(&Oid::new(&[1, 3, 6, 1, 6, 3, 10, 2, 1, 2, 0])),
            Value::Integer(7)
        );
        assert_eq!(
            view.get(&Oid::new(&[1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0])),
            Value::Counter32(5)
        );

        // Without an engine, those subtrees are absent entirely.
        let bare = MibView::build(&inputs(&base, &[], &[], None));
        assert_eq!(
            bare.get(&Oid::new(&[1, 3, 6, 1, 6, 3, 10, 2, 1, 1, 0])),
            Value::NoSuchObject
        );
    }

    #[test]
    fn gauge_clamps_negative_active_counts_to_zero() {
        // A guard-drop race could transiently under-run; the SNMP view must
        // never encode a negative Gauge32.
        let base = base();
        let listeners = [row("web", -2, 0, 0)];
        let view = MibView::build(&inputs(&base, &listeners, &[], None));
        let oid = base.child(&[2, 1, 2, 3, 119, 101, 98]);
        assert_eq!(view.get(&oid), Value::Gauge32(0));
    }

    #[test]
    fn agent_counters_surface_in_snmp_group() {
        let base = base();
        let view = MibView::build(&inputs(&base, &[], &[], None));
        assert_eq!(
            view.get(&Oid::new(&[1, 3, 6, 1, 2, 1, 11, 1, 0])),
            Value::Counter32(10)
        );
        assert_eq!(
            view.get(&Oid::new(&[1, 3, 6, 1, 2, 1, 11, 4, 0])),
            Value::Counter32(2)
        );
    }
}
