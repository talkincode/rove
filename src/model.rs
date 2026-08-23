//! The data model synced from the control plane.
//!
//! Two layers:
//! * `Raw*` — the versioned JSON wire/cache formats. Schema v1-v3 use
//!   `users + groups`; schema v4 uses `users + routing_policies + egresses`.
//!   Both replace the old denormalized `userdata.json` shape.
//! * compiled `Snapshot` — users indexed by name (O(1) auth) and rule lists
//!   compiled into matchers, ready to serve.

use crate::policy::{RouteIndex, RuleSet};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

const MAX_SNAPSHOT_USERS: usize = 100_000;
const MAX_SNAPSHOT_GROUPS: usize = 10_000;
const MAX_SNAPSHOT_RULES: usize = 200_000;
const MAX_SNAPSHOT_NODE_OVERRIDES: usize = 10_000;
const MAX_SNAPSHOT_CHAINS: usize = 1_000;
const MAX_CHAIN_MEMBERS: usize = 16;
const MAX_ADDRBOOK_SELECTOR_BYTES: usize = 64 * 1024 * 1024;

/// Highest snapshot *wire schema* version this build understands. Distinct
/// from `RawSnapshot::version` (the content revision used for `?since=` /
/// 304): `schema_version` only changes when the JSON structure or semantics
/// change. v1 = the original single-upstream schema; v2 adds top-level
/// `chains` plus `kind = "chain"` upstream references; v3 adds the semantic
/// `book:<category>` rule scheme; v4 replaces the group/chain model with named
/// routing policies (ordered first-match routes) plus a separate named-egress
/// table. Snapshots declaring a higher schema are rejected so an older node
/// never misreads a new rule as a literal domain.
pub const MAX_SUPPORTED_SCHEMA_VERSION: u32 = 4;
const ADDRBOOK_RULE_SCHEMA_VERSION: u32 = 3;
/// The schema version of the routing-policy / named-egress document
/// ([`RawSnapshotV4`]).
pub const V4_SCHEMA_VERSION: u32 = 4;

/// Version guard seam: is `schema_version` within `1..=max_supported`?
///
/// Exposed (and tested) so a build pinned to an older `max_supported` provably
/// rejects a newer schema — e.g. `schema_version_supported(4, 3) == false`
/// proves a max-3 node rejects a schema-v4 snapshot — without hand-crafting a
/// snapshot for every guard case. The real compile paths call this with
/// [`MAX_SUPPORTED_SCHEMA_VERSION`].
pub fn schema_version_supported(schema_version: u32, max_supported: u32) -> bool {
    schema_version >= 1 && schema_version <= max_supported
}

// ---------------------------------------------------------------------------
// Wire / cache format
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawSnapshot {
    /// Wire-schema version; absent means `1` (the pre-chain schema). See
    /// [`MAX_SUPPORTED_SCHEMA_VERSION`]. Note this field alone cannot protect
    /// old nodes (they ignore unknown fields); the fail-closed sentinel for
    /// the v2 upgrade is the `kind = "chain"` upstream reference, which old
    /// nodes reject as an unsupported upstream kind.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    pub version: u64,
    #[serde(default)]
    pub users: HashMap<String, RawUser>,
    #[serde(default)]
    pub groups: HashMap<String, RawGroup>,
    /// Named priority-failover candidate sets (schema v2). A chain is a set
    /// of equivalent primary/backup backends for one logical egress — not a
    /// multi-hop A → B → target relay. Groups reference a chain through their
    /// existing upstream slots with `{ "kind": "chain", "addr": "<chain-id>" }`.
    #[serde(default)]
    pub chains: HashMap<String, RawChain>,
    /// Per-node group overrides, keyed by `node_id`. Lets the control plane
    /// ship one shared snapshot to every node (same `users`/`groups`) while
    /// still giving individual nodes (e.g. different edge locations with
    /// their own local hop) their own upstream or policy for specific
    /// groups, instead of requiring the control plane to compute a distinct
    /// response body per node.
    #[serde(default)]
    pub node_overrides: HashMap<String, NodeOverride>,
}

impl Default for RawSnapshot {
    fn default() -> Self {
        RawSnapshot {
            schema_version: default_schema_version(),
            version: 0,
            users: HashMap::new(),
            groups: HashMap::new(),
            chains: HashMap::new(),
            node_overrides: HashMap::new(),
        }
    }
}

fn default_schema_version() -> u32 {
    1
}

/// Group/chain overrides that apply only to the node whose `node_id` matches
/// the key in `RawSnapshot::node_overrides`. An override entry fully replaces
/// the base group or chain with the same id (or adds a node-only one); it is
/// never a field-level merge — a chain override replaces the whole member
/// list, not individual members.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeOverride {
    #[serde(default)]
    pub groups: HashMap<String, RawGroup>,
    #[serde(default)]
    pub chains: HashMap<String, RawChain>,
}

/// One named failover chain: an ordered-by-priority set of equivalent
/// backends for a single logical egress (e.g. one POP's primary + standby).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RawChain {
    #[serde(default)]
    pub members: Vec<RawChainMember>,
}

/// One chain member. `backend` reuses the existing upstream schema and
/// validation rules (`reverse.addr` is a `hop_id`, http/socks5 `addr` is
/// `host:port`); it must not itself be `kind = "chain"` (no recursion).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawChainMember {
    /// Stable member id, unique within the chain; surfaced in logs/metrics.
    pub id: String,
    /// Unique within the chain; lower number = tried first.
    pub priority: u32,
    pub backend: RawUpstream,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawUser {
    pub password: String,
    /// `YYYY-MM-DD`; empty/None = never expires.
    #[serde(default)]
    pub expire: Option<String>,
    /// Upload throttle in bytes/sec, 0 = unlimited.
    #[serde(default)]
    pub up_rate: u64,
    #[serde(default)]
    pub down_rate: u64,
    /// Maximum active tunnels for this user on this node, 0 = unlimited.
    #[serde(default)]
    pub max_connections: usize,
    pub group: String,
    /// Front-end protocol credentials, keyed by protocol name (e.g. `"tuic"`).
    /// Each protocol carries only the fields it needs (`uuid` and/or
    /// `password`). Deliberately independent of the login `password` so a leaked
    /// front-end credential never exposes the account, and independently
    /// rotatable/disable-able per protocol. Absent = the user has no front-end
    /// identity. Extensible: adding a protocol adds a map entry, not a new
    /// top-level field.
    #[serde(default)]
    pub frontends: HashMap<String, RawFrontendCred>,
}

/// One front-end protocol credential. Different protocols use different subsets:
/// TUIC uses `uuid` + `password`; a uuid-only protocol (e.g. VLESS) would set
/// just `uuid`; a password-only protocol (e.g. Trojan) just `password`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RawFrontendCred {
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawGroup {
    /// Secondary (upstream) proxy for targets matched by `proxy`. None = the
    /// group is direct-only.
    #[serde(default)]
    pub upstream: Option<RawUpstream>,
    /// Default secondary proxy for targets that do not match `proxy` or
    /// `block`. None = unmatched targets go direct.
    #[serde(default)]
    pub default_upstream: Option<RawUpstream>,
    /// Targets (domains or IP/CIDR) that must traverse the upstream proxy.
    #[serde(default)]
    pub proxy: Vec<String>,
    /// Targets that are denied outright.
    #[serde(default)]
    pub block: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawUpstream {
    /// "http", "socks5", or "reverse". For "reverse", `addr` is a `hop_id`
    /// (not a dialable host:port) — the edge must already hold an
    /// authenticated reverse-hop QUIC session for that id.
    pub kind: String,
    /// host:port of the upstream proxy, or the `hop_id` for reverse upstreams.
    pub addr: String,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// Speak to the upstream over TLS (https proxy / socks5-over-tls).
    #[serde(default)]
    pub tls: bool,
    /// Skip TLS certificate verification when dialing this upstream (self-
    /// signed / IP-only hop certs). Only meaningful when `tls` is true;
    /// ignored otherwise. Defaults to false — verification is on unless a
    /// group explicitly opts out for its own hop.
    #[serde(default)]
    pub skip_cert_verify: bool,
}

// ---------------------------------------------------------------------------
// Wire / cache format — schema v4 (routing policies + named egresses)
// ---------------------------------------------------------------------------

/// Schema-v4 top-level document. Replaces the denormalized group/chain model
/// with named *routing policies* (ordered first-match routes) plus a separate
/// named-*egress* table. Strict: unknown top-level fields — including the
/// legacy `groups` / `chains` — reject decode, so a v4 payload can never smuggle
/// legacy group semantics past a v4 reader.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSnapshotV4 {
    /// Must be [`V4_SCHEMA_VERSION`]; enforced at decode.
    pub schema_version: u32,
    pub version: u64,
    #[serde(default)]
    pub users: HashMap<String, RawUserV4>,
    /// Named routing policies keyed by policy id; users reference one by id.
    #[serde(default)]
    pub routing_policies: HashMap<String, RawRoutingPolicy>,
    /// Named egresses keyed by egress id; routes/policies reference these.
    #[serde(default)]
    pub egresses: HashMap<String, RawEgress>,
    /// Per-node egress overrides. Unlike v1-v3 node overrides (which can carry
    /// groups/chains), v4 node overrides only whole-replace an existing base
    /// egress — routing policies stay node-independent.
    #[serde(default)]
    pub node_overrides: HashMap<String, NodeOverrideV4>,
}

/// Schema-v4 user. References a non-empty `policy` (never the legacy `group`);
/// the auth / rate / front-end fields are unchanged. Strict: a `group` key (or
/// any other unknown field) rejects decode.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawUserV4 {
    pub password: String,
    #[serde(default)]
    pub expire: Option<String>,
    #[serde(default)]
    pub up_rate: u64,
    #[serde(default)]
    pub down_rate: u64,
    #[serde(default)]
    pub max_connections: usize,
    /// Routing policy id; required and non-empty (validated at compile).
    pub policy: String,
    #[serde(default)]
    pub frontends: HashMap<String, RawFrontendCred>,
}

/// One named routing policy: an ordered first-match route list plus an optional
/// default egress used when no route matches. An empty route list is legal (the
/// policy is then just its `default_egress`, or direct when that is absent).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RawRoutingPolicy {
    #[serde(default)]
    pub routes: Vec<RawRoute>,
    /// Egress id used when no route matches. Absent = direct. A dangling
    /// reference fails compilation (fail closed).
    #[serde(default)]
    pub default_egress: Option<String>,
}

/// One route: a non-empty selector list (domain / IP / CIDR / `book:` rules)
/// and exactly one action. A route matches if ANY selector matches; routes are
/// evaluated in declaration order and the first match wins (overlap is legal).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRoute {
    #[serde(default)]
    pub selectors: Vec<String>,
    pub action: RawAction,
}

/// Strict internally-tagged route action — exactly one of
/// `{"type":"egress","egress":"<id>"}`, `{"type":"direct"}`, `{"type":"block"}`.
///
/// Decoded through [`RawActionWire`] (serde's own `deny_unknown_fields` does not
/// apply to internally-tagged enums) so an unknown `type`, an unknown field, a
/// missing `egress`, or an `egress` on a `direct`/`block` action all reject
/// decode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawActionWire", into = "RawActionWire")]
pub enum RawAction {
    Egress { egress: String },
    Direct,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawActionWire {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    egress: Option<String>,
}

impl TryFrom<RawActionWire> for RawAction {
    type Error = String;
    fn try_from(w: RawActionWire) -> Result<Self, Self::Error> {
        match w.kind.as_str() {
            "egress" => {
                let egress = w.egress.ok_or_else(|| {
                    "route action type \"egress\" requires an \"egress\" id".to_string()
                })?;
                Ok(RawAction::Egress { egress })
            }
            "direct" => {
                if w.egress.is_some() {
                    return Err("route action type \"direct\" must not set \"egress\"".to_string());
                }
                Ok(RawAction::Direct)
            }
            "block" => {
                if w.egress.is_some() {
                    return Err("route action type \"block\" must not set \"egress\"".to_string());
                }
                Ok(RawAction::Block)
            }
            other => Err(format!("unknown route action type {other:?}")),
        }
    }
}

impl From<RawAction> for RawActionWire {
    fn from(a: RawAction) -> Self {
        match a {
            RawAction::Egress { egress } => RawActionWire {
                kind: "egress".to_string(),
                egress: Some(egress),
            },
            RawAction::Direct => RawActionWire {
                kind: "direct".to_string(),
                egress: None,
            },
            RawAction::Block => RawActionWire {
                kind: "block".to_string(),
                egress: None,
            },
        }
    }
}

/// Strict named-egress union — exactly one of
/// `{"type":"upstream","backend":<RawUpstream>}` (the backend must be a
/// concrete upstream, never `kind:"chain"`) or
/// `{"type":"chain","members":[<RawChainMember>...]}` (reusing the existing
/// chain validation/runtime). Decoded through [`RawEgressWire`] for strictness.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "RawEgressWire", into = "RawEgressWire")]
pub enum RawEgress {
    Upstream { backend: RawUpstream },
    Chain { members: Vec<RawChainMember> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEgressWire {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backend: Option<RawUpstream>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    members: Option<Vec<RawChainMember>>,
}

impl TryFrom<RawEgressWire> for RawEgress {
    type Error = String;
    fn try_from(w: RawEgressWire) -> Result<Self, Self::Error> {
        match w.kind.as_str() {
            "upstream" => {
                if w.members.is_some() {
                    return Err("egress type \"upstream\" must not set \"members\"".to_string());
                }
                let backend = w
                    .backend
                    .ok_or_else(|| "egress type \"upstream\" requires a \"backend\"".to_string())?;
                Ok(RawEgress::Upstream { backend })
            }
            "chain" => {
                if w.backend.is_some() {
                    return Err("egress type \"chain\" must not set \"backend\"".to_string());
                }
                let members = w
                    .members
                    .ok_or_else(|| "egress type \"chain\" requires \"members\"".to_string())?;
                Ok(RawEgress::Chain { members })
            }
            other => Err(format!("unknown egress type {other:?}")),
        }
    }
}

impl From<RawEgress> for RawEgressWire {
    fn from(e: RawEgress) -> Self {
        match e {
            RawEgress::Upstream { backend } => RawEgressWire {
                kind: "upstream".to_string(),
                backend: Some(backend),
                members: None,
            },
            RawEgress::Chain { members } => RawEgressWire {
                kind: "chain".to_string(),
                backend: None,
                members: Some(members),
            },
        }
    }
}

/// Per-node egress overrides for schema v4. Only `egresses` is allowed: a
/// matching entry whole-replaces an existing base egress with the same id.
/// Strict: a `groups` / `chains` key (or any other unknown field) rejects
/// decode, keeping v4 routing policies node-independent.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NodeOverrideV4 {
    #[serde(default)]
    pub egresses: HashMap<String, RawEgress>,
}

/// A decoded snapshot document: either a legacy (schema 1-3, or a converted
/// `userdata.json`) [`RawSnapshot`] or a schema-v4 [`RawSnapshotV4`]. Returned
/// by [`decode_snapshot`]; [`Snapshot::compile`] / [`Snapshot::compile_with_book`]
/// accept either via `Into<SnapshotDocument>`.
#[derive(Debug, Clone)]
pub enum SnapshotDocument {
    Legacy(RawSnapshot),
    V4(RawSnapshotV4),
}

impl SnapshotDocument {
    /// The content revision (`version`) regardless of schema.
    pub fn version(&self) -> u64 {
        match self {
            SnapshotDocument::Legacy(r) => r.version,
            SnapshotDocument::V4(r) => r.version,
        }
    }

    /// The declared wire-schema version.
    pub fn schema_version(&self) -> u32 {
        match self {
            SnapshotDocument::Legacy(r) => r.schema_version,
            SnapshotDocument::V4(r) => r.schema_version,
        }
    }

    /// Number of routing-policy definitions carried by the wire document.
    /// Legacy schemas expose each group as one policy definition.
    pub fn routing_policy_count(&self) -> usize {
        match self {
            SnapshotDocument::Legacy(r) => r.groups.len(),
            SnapshotDocument::V4(r) => r.routing_policies.len(),
        }
    }

    /// Number of egress definitions carried by the wire document. Schema v4
    /// has an explicit named table; legacy schemas count each concrete group
    /// slot plus each named chain.
    pub fn egress_definition_count(&self) -> usize {
        match self {
            SnapshotDocument::Legacy(r) => {
                r.chains.len()
                    + r.groups
                        .values()
                        .map(|group| {
                            usize::from(group.upstream.is_some())
                                + usize::from(group.default_upstream.is_some())
                        })
                        .sum::<usize>()
            }
            SnapshotDocument::V4(r) => r.egresses.len(),
        }
    }

    /// Extract the legacy [`RawSnapshot`], erroring for a v4 document. A
    /// convenience for call sites that are still legacy-only; the sync/cache
    /// path stores the whole [`SnapshotDocument`] and does not use this.
    pub fn into_legacy(self) -> anyhow::Result<RawSnapshot> {
        match self {
            SnapshotDocument::Legacy(r) => Ok(r),
            SnapshotDocument::V4(_) => {
                anyhow::bail!("expected a legacy snapshot but found a schema-v4 document")
            }
        }
    }

    /// Serialize back to canonical JSON bytes for the local cache. Whitespace
    /// and key ordering are not preserved, but the bytes round-trip through
    /// [`decode_snapshot`] to the same document (a v4 document re-decodes as v4,
    /// a legacy one as legacy) so a node can restart from cache unchanged.
    pub fn to_cache_bytes(&self) -> serde_json::Result<Vec<u8>> {
        match self {
            SnapshotDocument::Legacy(r) => serde_json::to_vec(r),
            SnapshotDocument::V4(r) => serde_json::to_vec(r),
        }
    }
}

impl From<RawSnapshot> for SnapshotDocument {
    fn from(r: RawSnapshot) -> Self {
        SnapshotDocument::Legacy(r)
    }
}

impl From<RawSnapshotV4> for SnapshotDocument {
    fn from(r: RawSnapshotV4) -> Self {
        SnapshotDocument::V4(r)
    }
}

#[derive(Debug, Deserialize)]
struct LegacyUserdata {
    #[serde(default)]
    timestamp: u64,
    #[serde(default)]
    user_list: Vec<LegacyUser>,
    #[serde(default)]
    address_list: Vec<LegacyAddress>,
    #[serde(default)]
    routings: Vec<LegacyRouting>,
}

#[derive(Debug, Deserialize)]
struct LegacyUser {
    username: String,
    password: String,
    #[serde(default)]
    expire: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    up_rate: Value,
    #[serde(default)]
    down_rate: Value,
}

#[derive(Debug, Deserialize)]
struct LegacyAddress {
    tag: String,
    address: String,
    #[serde(rename = "type")]
    #[serde(default)]
    _kind: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LegacyRouting {
    #[serde(default)]
    server_tag: Option<String>,
    #[serde(default)]
    server_addr: Option<String>,
    #[serde(default)]
    connector_type: Option<String>,
    #[serde(default)]
    dialer_type: Option<String>,
    #[serde(default)]
    use_auth: Option<String>,
    #[serde(default)]
    auth_user: Option<String>,
    #[serde(default)]
    auth_passwd: Option<String>,
    #[serde(default)]
    connector: Value,
    #[serde(default)]
    dialer: Value,
    #[serde(default)]
    default_hop_node: Value,
    #[serde(default)]
    users: Vec<String>,
    #[serde(default)]
    codes: Vec<String>,
    #[serde(default)]
    rules: Vec<LegacyRule>,
}

#[derive(Debug, Deserialize)]
struct LegacyRule {
    #[serde(default)]
    tag: String,
    #[serde(default)]
    action: String,
}

/// Parse a snapshot payload into a [`SnapshotDocument`]: a schema-v4
/// routing-policy document, a legacy (schema 1-3) `RawSnapshot`, or the old
/// `userdata.json` shape (converted for migration compatibility). The control
/// plane should prefer emitting `RawSnapshotV4` or `RawSnapshot` directly.
///
/// v4 is detected by its declared `schema_version` OR by the presence of a
/// v4-only top-level field (`routing_policies` / `egresses`), so such a field
/// carried under an older schema is still routed to the v4 branch and rejected
/// (below) instead of being silently dropped. Schema 1-3 payloads carrying any
/// v4-only field (`routing_policies`, `egresses`, `user.policy`,
/// `node_override.egresses`) are rejected — the two schemas never silently mix.
pub fn decode_snapshot(bytes: &[u8]) -> anyhow::Result<SnapshotDocument> {
    let value: Value = serde_json::from_slice(bytes)?;
    let declared_schema = value
        .get("schema_version")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| u64::from(default_schema_version()));

    if declared_schema == u64::from(V4_SCHEMA_VERSION)
        || value.get("routing_policies").is_some()
        || value.get("egresses").is_some()
    {
        let doc: RawSnapshotV4 = serde_json::from_value(value)?;
        anyhow::ensure!(
            doc.schema_version == V4_SCHEMA_VERSION,
            "schema-v4 fields (routing_policies/egresses) require schema_version \
             {V4_SCHEMA_VERSION} (found {})",
            doc.schema_version
        );
        return Ok(SnapshotDocument::V4(doc));
    }

    if looks_like_raw_snapshot(&value) {
        reject_v4_only_fields_in_legacy(&value)?;
        let raw: RawSnapshot = serde_json::from_value(value)?;
        return Ok(SnapshotDocument::Legacy(raw));
    }
    if looks_like_legacy_userdata(&value) {
        let legacy: LegacyUserdata = serde_json::from_value(value)?;
        return Ok(SnapshotDocument::Legacy(legacy_userdata_to_snapshot(
            legacy,
        )?));
    }
    anyhow::bail!(
        "snapshot payload is neither RawSnapshot nor legacy userdata.json (nor a schema-v4 document)"
    )
}

/// Reject a schema 1-3 payload that carries any schema-v4-only field, so the
/// control plane never accidentally mixes the two models (a v4 field silently
/// ignored under an old schema would fail open).
fn reject_v4_only_fields_in_legacy(value: &Value) -> anyhow::Result<()> {
    if value.get("routing_policies").is_some() {
        anyhow::bail!(
            "routing_policies is a schema-v4 field and is not allowed in a schema 1-3 snapshot"
        );
    }
    if value.get("egresses").is_some() {
        anyhow::bail!("egresses is a schema-v4 field and is not allowed in a schema 1-3 snapshot");
    }
    if let Some(users) = value.get("users").and_then(Value::as_object) {
        for (name, user) in users {
            if user.get("policy").is_some() {
                anyhow::bail!(
                    "user {name:?} sets schema-v4 field \"policy\"; schema 1-3 users use \"group\""
                );
            }
        }
    }
    if let Some(overrides) = value.get("node_overrides").and_then(Value::as_object) {
        for (node, override_value) in overrides {
            if override_value.get("egresses").is_some() {
                anyhow::bail!(
                    "node override {node:?} sets schema-v4 field \"egresses\"; not allowed in a \
                     schema 1-3 snapshot"
                );
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Compiled, serving format
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamKind {
    Http,
    Socks5,
    /// Reverse-hop QUIC data plane: `Upstream.addr` is a `hop_id`, resolved at
    /// connect time against the edge's authenticated reverse-hop sessions
    /// rather than dialed as a TCP address.
    Reverse,
    /// Subnetra overlay egress: the target is dialed as an IPv4 address over the
    /// embedded Subnetra mesh (see `src/subnetra/`) rather than the host network.
    /// `Upstream.addr` is unused — the destination comes from the client request.
    Subnetra,
}

#[derive(Debug, Clone)]
pub struct Upstream {
    pub kind: UpstreamKind,
    /// host:port for http/socks5 upstreams; `hop_id` for reverse upstreams.
    pub addr: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tls: bool,
    pub skip_cert_verify: bool,
}

/// Compiled chain member: a concrete upstream plus its stable identity.
#[derive(Debug, Clone)]
pub struct ChainMember {
    pub id: String,
    pub priority: u32,
    pub upstream: Upstream,
}

/// Compiled failover chain, members sorted by ascending priority (the try
/// order). Shared via `Arc` so `decide()` stays clone-cheap on the hot path.
#[derive(Debug)]
pub struct Chain {
    pub id: String,
    pub members: Vec<ChainMember>,
}

pub struct User {
    pub password: String,
    pub expire: Option<NaiveDate>,
    pub up_rate: u64,
    pub down_rate: u64,
    pub max_connections: usize,
    pub group: String,
    /// Front-end credentials by protocol name (see [`RawFrontendCred`]).
    pub frontends: HashMap<String, FrontendCred>,
}

/// Compiled front-end credential for one protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontendCred {
    pub uuid: Option<String>,
    pub password: Option<String>,
}

/// One egress slot of a compiled group: either a single upstream (schema v1
/// behaviour, unchanged) or a reference to a shared failover chain.
pub enum GroupEgress {
    Single(Upstream),
    Chain(std::sync::Arc<Chain>),
}

pub struct Group {
    pub upstream: Option<GroupEgress>,
    pub default_upstream: Option<GroupEgress>,
    pub proxy: RuleSet,
    pub block: RuleSet,
    proxy_rules: Vec<String>,
    block_rules: Vec<String>,
}

/// Compiled named egress (schema v4): a stable id plus its realization.
struct Egress {
    id: String,
    kind: EgressKind,
}

/// A named egress is realized either as a single concrete upstream or as a
/// shared failover chain (reusing the existing chain runtime semantics).
enum EgressKind {
    Upstream(Upstream),
    Chain(std::sync::Arc<Chain>),
}

impl Egress {
    fn decision(&self) -> Decision {
        match &self.kind {
            EgressKind::Upstream(up) => Decision::Via(up.clone()),
            EgressKind::Chain(chain) => Decision::ViaChain(chain.clone()),
        }
    }

    fn view(&self) -> EgressView {
        let upstream = match &self.kind {
            EgressKind::Upstream(up) => UpstreamView::from(up),
            EgressKind::Chain(chain) => UpstreamView::from_chain(chain),
        };
        EgressView {
            id: self.id.clone(),
            upstream,
        }
    }
}

/// Compiled route action (schema v4).
enum RouteAction {
    Egress(std::sync::Arc<Egress>),
    Direct,
    Block,
}

/// Compiled route (schema v4): a selector set plus one action. `selector_rules`
/// keeps the original strings for the credential-free MQTT/inspection view.
struct Route {
    selectors: RuleSet,
    selector_rules: Vec<String>,
    action: RouteAction,
}

/// Compiled routing policy (schema v4): ordered first-match routes plus an
/// optional default egress. Absent default = direct.
struct RoutingPolicy {
    routes: Vec<Route>,
    default_egress: Option<std::sync::Arc<Egress>>,
    index: RouteIndex,
}

impl RoutingPolicy {
    fn from_routes(routes: Vec<Route>, default_egress: Option<std::sync::Arc<Egress>>) -> Self {
        let mut index = RouteIndex::default();
        for (idx, route) in routes.iter().enumerate() {
            route.selectors.index_into(idx as u32, &mut index);
        }
        RoutingPolicy {
            routes,
            default_egress,
            index,
        }
    }

    /// First-match evaluation: the first route with ANY matching selector wins;
    /// `None` means no route matched.
    fn first_match(&self, host: &str) -> Option<&RouteAction> {
        self.index
            .first_match(host)
            .map(|idx| &self.routes[idx].action)
    }

    #[cfg(test)]
    fn first_match_naive(&self, host: &str) -> Option<&RouteAction> {
        self.routes
            .iter()
            .find(|route| route.selectors.matches(host))
            .map(|route| &route.action)
    }
}

/// Which routing model a compiled [`Snapshot`] serves. Set once at compile
/// time; a snapshot is never a mix of the two.
enum Routing {
    /// Schema 1-3: `groups` + `proxy`/`block`/`default_upstream`.
    Legacy,
    /// Schema 4: `policies` (ordered routes) + named `egresses`.
    V4,
}

/// What to do with a connection after auth.
#[derive(Debug)]
pub enum Decision {
    Direct,
    Via(Upstream),
    /// Try the chain's members in priority order during tunnel establishment
    /// only; fail closed when all members fail. See `outbound::connect`.
    ViaChain(std::sync::Arc<Chain>),
    Block,
}

#[derive(Debug)]
pub struct ResolvedDecision {
    pub decision: Decision,
    pub effective_policy_host: String,
    pub snapshot_version: u64,
}

pub struct Snapshot {
    pub version: u64,
    /// Wire-schema version the snapshot declared (1 when absent).
    pub schema_version: u32,
    /// Which routing model this snapshot serves (legacy groups vs v4 policies).
    routing: Routing,
    users: HashMap<String, User>,
    /// Schema 1-3 compiled groups (empty for a v4 snapshot).
    groups: HashMap<String, Group>,
    /// Schema-v4 routing policies keyed by policy id (empty for legacy).
    policies: HashMap<String, RoutingPolicy>,
    /// Front-end identity index: protocol -> (canonical-lowercase lookup key ->
    /// username). For uuid-based protocols the key is the uuid; built at compile
    /// time from each user's `frontends`.
    frontend_index: HashMap<String, HashMap<String, String>>,
}

impl Snapshot {
    pub fn empty() -> Self {
        Snapshot {
            version: 0,
            schema_version: 1,
            routing: Routing::Legacy,
            users: HashMap::new(),
            groups: HashMap::new(),
            policies: HashMap::new(),
            frontend_index: HashMap::new(),
        }
    }

    #[allow(dead_code)] // inspection surface
    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    #[allow(dead_code)] // inspection surface
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Compile a decoded snapshot into the serving form for a specific node.
    /// Accepts either a legacy [`RawSnapshot`] or a schema-v4 [`RawSnapshotV4`]
    /// (via `Into<SnapshotDocument>`). Invalid upstream kinds, dangling
    /// user/policy/egress/chain references, and unsupported schema versions are
    /// rejected so a bad control-plane push can't silently degrade routing or
    /// fail open.
    ///
    /// `node_id` selects this node's slice of `node_overrides`.
    pub fn compile(raw: impl Into<SnapshotDocument>, node_id: &str) -> anyhow::Result<Self> {
        Self::compile_with_book(raw, node_id, None)
    }

    /// Like [`Snapshot::compile`], but resolves `book:<category>` rules against
    /// `book`. The compiled rule sets pin that exact book, so a book swap
    /// requires a snapshot recompile — a snapshot is always internally
    /// consistent. `book: None` with `book:` rules present is a hard error
    /// (fail closed).
    pub fn compile_with_book(
        raw: impl Into<SnapshotDocument>,
        node_id: &str,
        book: Option<&std::sync::Arc<crate::addrbook::AddrBook>>,
    ) -> anyhow::Result<Self> {
        match raw.into() {
            SnapshotDocument::Legacy(raw) => Self::compile_legacy(raw, node_id, book),
            SnapshotDocument::V4(raw) => Self::compile_v4(raw, node_id, book),
        }
    }

    /// Compile a schema 1-3 snapshot. `node_id` selects this node's slice of
    /// `node_overrides`: matching chain entries replace (or add to) the shared
    /// `chains`, then matching group entries replace (or add to) the shared
    /// `groups`, before validation/compilation.
    fn compile_legacy(
        raw: RawSnapshot,
        node_id: &str,
        book: Option<&std::sync::Arc<crate::addrbook::AddrBook>>,
    ) -> anyhow::Result<Self> {
        let RawSnapshot {
            schema_version,
            version,
            users: raw_users,
            groups: mut raw_groups,
            chains: mut raw_chains,
            mut node_overrides,
        } = raw;

        if !schema_version_supported(schema_version, MAX_SUPPORTED_SCHEMA_VERSION) {
            anyhow::bail!(
                "unsupported snapshot schema_version {schema_version} (this node supports 1..={MAX_SUPPORTED_SCHEMA_VERSION})"
            );
        }

        if node_overrides.len() > MAX_SNAPSHOT_NODE_OVERRIDES {
            anyhow::bail!(
                "snapshot has too many node overrides: {} > {}",
                node_overrides.len(),
                MAX_SNAPSHOT_NODE_OVERRIDES
            );
        }

        if let Some(override_for_node) = node_overrides.remove(node_id) {
            // Chains first: group overrides may reference a chain that only
            // exists (or is replaced) on this node.
            for (chain_id, chain) in override_for_node.chains {
                if chain_id.trim().is_empty() {
                    anyhow::bail!("node override chain id is required");
                }
                raw_chains.insert(chain_id, chain);
            }
            for (group_id, group) in override_for_node.groups {
                if group_id.trim().is_empty() {
                    anyhow::bail!("node override group id is required");
                }
                raw_groups.insert(group_id, group);
            }
        }

        if raw_groups.values().any(|group| {
            group
                .proxy
                .iter()
                .chain(&group.block)
                .any(|rule| rule.trim().starts_with("book:"))
        }) && schema_version < ADDRBOOK_RULE_SCHEMA_VERSION
        {
            anyhow::bail!(
                "book: rules require snapshot schema_version \
                 {ADDRBOOK_RULE_SCHEMA_VERSION} (found {schema_version})"
            );
        }

        validate_snapshot_shape(&raw_users, &raw_groups)?;

        let chains = compile_chains(schema_version, raw_chains)?;
        if let Some(book) = book {
            book.prune_selector_cache();
        }

        let mut groups = HashMap::with_capacity(raw_groups.len());
        let mut selector_allocations = HashSet::new();
        let mut selector_bytes = 0usize;
        for (id, g) in raw_groups {
            let upstream = match g.upstream {
                Some(u) => Some(compile_group_egress(&id, "upstream", u, &chains)?),
                None => None,
            };
            let default_upstream = match g.default_upstream {
                Some(u) => Some(compile_group_egress(&id, "default_upstream", u, &chains)?),
                None => None,
            };
            let proxy = RuleSet::from_rules(&g.proxy, book)
                .map_err(|e| anyhow::anyhow!("group {id}: proxy rules: {e}"))?;
            let block = RuleSet::from_rules(&g.block, book)
                .map_err(|e| anyhow::anyhow!("group {id}: block rules: {e}"))?;
            account_book_selector(
                &proxy,
                &mut selector_allocations,
                &mut selector_bytes,
                MAX_ADDRBOOK_SELECTOR_BYTES,
            )
            .map_err(|e| anyhow::anyhow!("group {id}: proxy rules: {e}"))?;
            account_book_selector(
                &block,
                &mut selector_allocations,
                &mut selector_bytes,
                MAX_ADDRBOOK_SELECTOR_BYTES,
            )
            .map_err(|e| anyhow::anyhow!("group {id}: block rules: {e}"))?;
            groups.insert(
                id,
                Group {
                    upstream,
                    default_upstream,
                    proxy,
                    block,
                    proxy_rules: g.proxy,
                    block_rules: g.block,
                },
            );
        }

        let mut users = HashMap::with_capacity(raw_users.len());
        let mut frontend_index: HashMap<String, HashMap<String, String>> = HashMap::new();
        for (name, u) in raw_users {
            let user = compile_user(
                &name,
                u.password,
                u.expire,
                u.up_rate,
                u.down_rate,
                u.max_connections,
                u.group,
                u.frontends,
                &mut frontend_index,
            )?;
            users.insert(name, user);
        }

        Ok(Snapshot {
            version,
            schema_version,
            routing: Routing::Legacy,
            users,
            groups,
            policies: HashMap::new(),
            frontend_index,
        })
    }

    /// Compile a schema-v4 snapshot (routing policies + named egresses).
    ///
    /// `node_id` selects this node's slice of `node_overrides`: each entry
    /// whole-replaces an *existing* base egress of the same id (introducing a
    /// node-only egress is rejected — routing policies stay node-independent).
    /// Dangling user→policy, route→egress and default_egress references, and
    /// invalid egresses/chains all reject the snapshot (fail closed).
    fn compile_v4(
        raw: RawSnapshotV4,
        node_id: &str,
        book: Option<&std::sync::Arc<crate::addrbook::AddrBook>>,
    ) -> anyhow::Result<Self> {
        let RawSnapshotV4 {
            schema_version,
            version,
            users: raw_users,
            routing_policies: raw_policies,
            egresses: mut raw_egresses,
            mut node_overrides,
        } = raw;

        if !schema_version_supported(schema_version, MAX_SUPPORTED_SCHEMA_VERSION) {
            anyhow::bail!(
                "unsupported snapshot schema_version {schema_version} (this node supports 1..={MAX_SUPPORTED_SCHEMA_VERSION})"
            );
        }
        anyhow::ensure!(
            schema_version == V4_SCHEMA_VERSION,
            "routing-policy snapshot requires schema_version {V4_SCHEMA_VERSION} (found {schema_version})"
        );

        if raw_users.len() > MAX_SNAPSHOT_USERS {
            anyhow::bail!(
                "snapshot has too many users: {} > {}",
                raw_users.len(),
                MAX_SNAPSHOT_USERS
            );
        }
        if raw_policies.len() > MAX_SNAPSHOT_GROUPS {
            anyhow::bail!(
                "snapshot has too many routing policies: {} > {}",
                raw_policies.len(),
                MAX_SNAPSHOT_GROUPS
            );
        }
        if node_overrides.len() > MAX_SNAPSHOT_NODE_OVERRIDES {
            anyhow::bail!(
                "snapshot has too many node overrides: {} > {}",
                node_overrides.len(),
                MAX_SNAPSHOT_NODE_OVERRIDES
            );
        }

        // Node overrides only whole-replace an existing base egress.
        if let Some(override_for_node) = node_overrides.remove(node_id) {
            for (egress_id, egress) in override_for_node.egresses {
                if egress_id.trim().is_empty() {
                    anyhow::bail!("node override egress id is required");
                }
                anyhow::ensure!(
                    raw_egresses.contains_key(&egress_id),
                    "node override egress {egress_id:?} does not replace an existing base egress"
                );
                raw_egresses.insert(egress_id, egress);
            }
        }

        if raw_egresses.len() > MAX_SNAPSHOT_GROUPS {
            anyhow::bail!(
                "snapshot has too many egresses: {} > {}",
                raw_egresses.len(),
                MAX_SNAPSHOT_GROUPS
            );
        }

        // Compile egresses first: routes and policies reference them by id.
        let mut egresses: HashMap<String, std::sync::Arc<Egress>> =
            HashMap::with_capacity(raw_egresses.len());
        for (id, raw_egress) in raw_egresses {
            if id.trim().is_empty() {
                anyhow::bail!("egress id is required");
            }
            let egress = compile_egress(&id, raw_egress)?;
            egresses.insert(id, std::sync::Arc::new(egress));
        }

        if let Some(book) = book {
            book.prune_selector_cache();
        }

        let mut policies = HashMap::with_capacity(raw_policies.len());
        let mut selector_allocations = HashSet::new();
        let mut selector_bytes = 0usize;
        let mut total_rules = 0usize;
        for (id, raw_policy) in raw_policies {
            if id.trim().is_empty() {
                anyhow::bail!("routing policy id is required");
            }
            let default_egress = match raw_policy.default_egress {
                Some(egress_id) => {
                    let egress_id = egress_id.trim();
                    anyhow::ensure!(
                        !egress_id.is_empty(),
                        "policy {id}: default_egress id is required"
                    );
                    Some(egresses.get(egress_id).cloned().ok_or_else(|| {
                        anyhow::anyhow!(
                            "policy {id}: default_egress references unknown egress {egress_id:?}"
                        )
                    })?)
                }
                None => None,
            };

            let mut routes = Vec::with_capacity(raw_policy.routes.len());
            for (idx, raw_route) in raw_policy.routes.into_iter().enumerate() {
                let non_empty_selectors = raw_route
                    .selectors
                    .iter()
                    .filter(|s| !s.trim().is_empty())
                    .count();
                anyhow::ensure!(
                    non_empty_selectors > 0,
                    "policy {id} route {idx}: at least one selector is required"
                );
                total_rules = total_rules.saturating_add(non_empty_selectors);
                anyhow::ensure!(
                    total_rules <= MAX_SNAPSHOT_RULES,
                    "snapshot has too many policy rules: {total_rules} > {MAX_SNAPSHOT_RULES}"
                );
                let selectors = RuleSet::from_rules(&raw_route.selectors, book)
                    .map_err(|e| anyhow::anyhow!("policy {id} route {idx}: selectors: {e}"))?;
                account_book_selector(
                    &selectors,
                    &mut selector_allocations,
                    &mut selector_bytes,
                    MAX_ADDRBOOK_SELECTOR_BYTES,
                )
                .map_err(|e| anyhow::anyhow!("policy {id} route {idx}: selectors: {e}"))?;
                let action = match raw_route.action {
                    RawAction::Egress { egress } => {
                        let egress = egress.trim();
                        anyhow::ensure!(
                            !egress.is_empty(),
                            "policy {id} route {idx}: egress action requires an egress id"
                        );
                        RouteAction::Egress(egresses.get(egress).cloned().ok_or_else(|| {
                            anyhow::anyhow!(
                                "policy {id} route {idx}: references unknown egress {egress:?}"
                            )
                        })?)
                    }
                    RawAction::Direct => RouteAction::Direct,
                    RawAction::Block => RouteAction::Block,
                };
                routes.push(Route {
                    selectors,
                    selector_rules: raw_route.selectors,
                    action,
                });
            }
            policies.insert(id, RoutingPolicy::from_routes(routes, default_egress));
        }

        let mut users = HashMap::with_capacity(raw_users.len());
        let mut frontend_index: HashMap<String, HashMap<String, String>> = HashMap::new();
        for (name, u) in raw_users {
            anyhow::ensure!(
                !u.policy.trim().is_empty(),
                "user {name}: policy is required"
            );
            anyhow::ensure!(
                policies.contains_key(&u.policy),
                "user {name}: unknown policy {:?}",
                u.policy
            );
            let user = compile_user(
                &name,
                u.password,
                u.expire,
                u.up_rate,
                u.down_rate,
                u.max_connections,
                u.policy,
                u.frontends,
                &mut frontend_index,
            )?;
            users.insert(name, user);
        }

        Ok(Snapshot {
            version,
            schema_version,
            routing: Routing::V4,
            users,
            groups: HashMap::new(),
            policies,
            frontend_index,
        })
    }

    /// O(1) user lookup.
    pub fn user(&self, username: &str) -> Option<&User> {
        self.users.get(username)
    }

    /// Resolve a front-end `protocol` + lookup `key` (e.g. a uuid) to
    /// `(username, user)`. The user's credential for that protocol is in
    /// `user.frontends[protocol]`.
    pub fn frontend_user(&self, protocol: &str, key: &str) -> Option<(&str, &User)> {
        let name = self
            .frontend_index
            .get(protocol)?
            .get(&key.to_ascii_lowercase())?;
        self.users.get_key_value(name).map(|(k, v)| (k.as_str(), v))
    }

    /// Decide how to route `host` for an authenticated user. Block wins; a
    /// matching proxy rule can select a special upstream; otherwise an
    /// optional default upstream is used before falling back to direct.
    pub fn decide(&self, username: &str, host: &str) -> Decision {
        self.decide_with_sniff(username, host, None).decision
    }

    /// Decide against both the proxy-protocol target and a validated sniffed
    /// hostname. Either candidate may block. A sniffed proxy rule can select an
    /// egress only when the requested target is an IP; the dial target remains
    /// the requested host and is kept separate by the caller.
    pub fn decide_with_sniff(
        &self,
        username: &str,
        requested_host: &str,
        sniffed_host: Option<&str>,
    ) -> ResolvedDecision {
        match self.routing {
            Routing::Legacy => self.decide_legacy(username, requested_host, sniffed_host),
            Routing::V4 => self.decide_v4(username, requested_host, sniffed_host),
        }
    }

    fn decide_legacy(
        &self,
        username: &str,
        requested_host: &str,
        sniffed_host: Option<&str>,
    ) -> ResolvedDecision {
        let resolved = |decision, host: &str| ResolvedDecision {
            decision,
            effective_policy_host: host.to_string(),
            snapshot_version: self.version,
        };
        let Some(user) = self.users.get(username) else {
            return resolved(Decision::Block, requested_host);
        };
        let Some(group) = self.groups.get(&user.group) else {
            return resolved(Decision::Block, requested_host);
        };
        if !group.block.is_empty() && group.block.matches(requested_host) {
            return resolved(Decision::Block, requested_host);
        }
        if let Some(sniffed_host) = sniffed_host {
            if !group.block.is_empty() && group.block.matches(sniffed_host) {
                return resolved(Decision::Block, sniffed_host);
            }
        }
        if let Some(up) = &group.upstream {
            if requested_host.parse::<std::net::IpAddr>().is_ok() {
                if let Some(sniffed_host) = sniffed_host {
                    if group.proxy.matches(sniffed_host) {
                        return resolved(up.decision(), sniffed_host);
                    }
                }
            }
            if group.proxy.matches(requested_host) {
                return resolved(up.decision(), requested_host);
            }
        }
        if let Some(up) = &group.default_upstream {
            return resolved(up.decision(), requested_host);
        }
        resolved(Decision::Direct, requested_host)
    }

    /// Schema-v4 decision. Evaluates the user's policy first-match action for
    /// the requested host and, when present, the validated sniffed host:
    ///
    /// * A first-match `block` for EITHER host vetoes (requested checked first).
    /// * For a requested IP, a non-block sniffed action selects BEFORE the
    ///   requested-IP action (`effective_policy_host` = the sniffed host).
    /// * For a requested domain, the sniffed action is ignored for selection.
    /// * Otherwise the requested action applies, then the policy default egress,
    ///   then direct.
    ///
    /// The dial target is never rewritten; `effective_policy_host` only records
    /// which host selected the outcome.
    fn decide_v4(
        &self,
        username: &str,
        requested_host: &str,
        sniffed_host: Option<&str>,
    ) -> ResolvedDecision {
        let resolved = |decision, host: &str| ResolvedDecision {
            decision,
            effective_policy_host: host.to_string(),
            snapshot_version: self.version,
        };
        let Some(user) = self.users.get(username) else {
            return resolved(Decision::Block, requested_host);
        };
        let Some(policy) = self.policies.get(&user.group) else {
            return resolved(Decision::Block, requested_host);
        };

        let requested_action = policy.first_match(requested_host);
        let sniffed = sniffed_host.map(|host| (host, policy.first_match(host)));

        // Block veto: the requested host first, then the validated sniffed host.
        if matches!(requested_action, Some(RouteAction::Block)) {
            return resolved(Decision::Block, requested_host);
        }
        if let Some((host, Some(action))) = sniffed {
            if matches!(action, RouteAction::Block) {
                return resolved(Decision::Block, host);
            }
        }

        // For a requested IP, a non-block sniffed action wins over the
        // requested-IP action (the sniffed host is the more specific identity).
        if requested_host.parse::<std::net::IpAddr>().is_ok() {
            if let Some((host, Some(action))) = sniffed {
                return resolved(self.route_action_decision(action), host);
            }
        }

        if let Some(action) = requested_action {
            return resolved(self.route_action_decision(action), requested_host);
        }
        if let Some(default_egress) = &policy.default_egress {
            return resolved(default_egress.decision(), requested_host);
        }
        resolved(Decision::Direct, requested_host)
    }

    /// Map a compiled route action to a decision. `Block` is unreachable here —
    /// callers veto it before selection.
    fn route_action_decision(&self, action: &RouteAction) -> Decision {
        match action {
            RouteAction::Egress(egress) => egress.decision(),
            RouteAction::Direct => Decision::Direct,
            RouteAction::Block => Decision::Block,
        }
    }

    pub fn user_policy(&self, username: &str) -> Option<UserPolicyView> {
        let user = self.users.get(username)?;
        let (policy, routing_policy) = match self.routing {
            Routing::Legacy => (
                self.groups.get(&user.group).map(GroupPolicyView::from),
                None,
            ),
            Routing::V4 => (
                None,
                self.policies
                    .get(&user.group)
                    .map(|p| RoutingPolicyView::build(&user.group, p)),
            ),
        };
        Some(UserPolicyView {
            username: username.to_string(),
            expire: user.expire.map(|d| d.format("%Y-%m-%d").to_string()),
            group: user.group.clone(),
            up_rate: user.up_rate,
            down_rate: user.down_rate,
            max_connections: user.max_connections,
            policies: policy.iter().cloned().collect(),
            policy,
            routing_policy,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct UserPolicyView {
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire: Option<String>,
    pub group: String,
    pub up_rate: u64,
    pub down_rate: u64,
    pub max_connections: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<GroupPolicyView>,
    /// Same data as `policy`, wrapped in a 0-or-1-element array.
    ///
    /// The pre-rewrite Rove MQTT contract returned `policies: [...]`,
    /// one entry per matching route, because a user could be matched into
    /// several legacy routing rules at once. The v2 data model assigns each
    /// user exactly one `group`, so there is at most one entry here — but
    /// keeping the array field lets consumers still built against the old
    /// wire format (iterating `policies`) keep working instead of silently
    /// reading no data from the new singular `policy` field.
    pub policies: Vec<GroupPolicyView>,
    /// Schema-v4 routing policy (present only for a v4 snapshot). Kept as an
    /// additive field so a consumer built against the legacy `policy`/`policies`
    /// fields keeps working; a v4-aware consumer reads the ordered routes,
    /// per-route action types and credential-free named-egress realizations
    /// here. Absent for schema 1-3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_policy: Option<RoutingPolicyView>,
}

/// Credential-free view of a schema-v4 routing policy: its id, ordered routes
/// (each with its selectors, action type and — for an egress action — the
/// credential-free egress realization) and an optional default egress.
#[derive(Debug, Clone, Serialize)]
pub struct RoutingPolicyView {
    pub id: String,
    pub routes: Vec<RouteView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_egress: Option<EgressView>,
}

/// Credential-free view of one route: its selectors, action type
/// (`"egress"`/`"direct"`/`"block"`) and — for an egress action — the resolved
/// egress realization.
#[derive(Debug, Clone, Serialize)]
pub struct RouteView {
    pub selectors: Vec<String>,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressView>,
}

/// Credential-free view of a named egress: its id and the same credential-free
/// [`UpstreamView`] realization used for legacy groups (a single upstream, or a
/// chain with its member candidates — never passwords/tokens).
#[derive(Debug, Clone, Serialize)]
pub struct EgressView {
    pub id: String,
    pub upstream: UpstreamView,
}

impl RoutingPolicyView {
    fn build(id: &str, policy: &RoutingPolicy) -> Self {
        RoutingPolicyView {
            id: id.to_string(),
            routes: policy.routes.iter().map(RouteView::build).collect(),
            default_egress: policy.default_egress.as_ref().map(|e| e.view()),
        }
    }
}

impl RouteView {
    fn build(route: &Route) -> Self {
        let (action, egress) = match &route.action {
            RouteAction::Egress(egress) => ("egress".to_string(), Some(egress.view())),
            RouteAction::Direct => ("direct".to_string(), None),
            RouteAction::Block => ("block".to_string(), None),
        };
        RouteView {
            selectors: route.selector_rules.clone(),
            action,
            egress,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupPolicyView {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream: Option<UpstreamView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_upstream: Option<UpstreamView>,
    pub proxy: Vec<String>,
    pub block: Vec<String>,
}

/// Credential-free upstream summary for MQTT/inspection views. For a chain
/// reference `kind` is `"chain"`, `addr` is the chain id and `members` lists
/// the candidates (stable id, kind, addr, priority, `auth` flag) — never the
/// member passwords, tokens or auth headers.
#[derive(Debug, Clone, Serialize)]
pub struct UpstreamView {
    pub kind: String,
    pub addr: String,
    pub tls: bool,
    pub auth: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub members: Option<Vec<ChainMemberView>>,
}

/// Credential-free view of one chain member.
#[derive(Debug, Clone, Serialize)]
pub struct ChainMemberView {
    pub id: String,
    pub priority: u32,
    pub kind: String,
    pub addr: String,
    pub tls: bool,
    pub auth: bool,
}

impl From<&Group> for GroupPolicyView {
    fn from(group: &Group) -> Self {
        GroupPolicyView {
            upstream: group.upstream.as_ref().map(UpstreamView::from),
            default_upstream: group.default_upstream.as_ref().map(UpstreamView::from),
            proxy: group.proxy_rules.clone(),
            block: group.block_rules.clone(),
        }
    }
}

impl GroupEgress {
    fn decision(&self) -> Decision {
        match self {
            GroupEgress::Single(up) => Decision::Via(up.clone()),
            GroupEgress::Chain(chain) => Decision::ViaChain(chain.clone()),
        }
    }
}

pub fn upstream_kind_name(kind: UpstreamKind) -> &'static str {
    match kind {
        UpstreamKind::Http => "http",
        UpstreamKind::Socks5 => "socks5",
        UpstreamKind::Reverse => "reverse",
        UpstreamKind::Subnetra => "subnetra",
    }
}

impl From<&GroupEgress> for UpstreamView {
    fn from(egress: &GroupEgress) -> Self {
        match egress {
            GroupEgress::Single(up) => UpstreamView::from(up),
            GroupEgress::Chain(chain) => UpstreamView::from_chain(chain),
        }
    }
}

impl UpstreamView {
    /// Credential-free view of a failover chain: `kind = "chain"`, `addr` = the
    /// chain id, and `members` the candidates (id, kind, addr, priority, `auth`
    /// flag) — never member passwords/tokens.
    fn from_chain(chain: &Chain) -> Self {
        UpstreamView {
            kind: "chain".to_string(),
            addr: chain.id.clone(),
            tls: false,
            auth: false,
            members: Some(
                chain
                    .members
                    .iter()
                    .map(|m| ChainMemberView {
                        id: m.id.clone(),
                        priority: m.priority,
                        kind: upstream_kind_name(m.upstream.kind).to_string(),
                        addr: m.upstream.addr.clone(),
                        tls: m.upstream.tls,
                        auth: m.upstream.username.is_some() || m.upstream.password.is_some(),
                    })
                    .collect(),
            ),
        }
    }
}

impl From<&Upstream> for UpstreamView {
    fn from(upstream: &Upstream) -> Self {
        UpstreamView {
            kind: upstream_kind_name(upstream.kind).to_string(),
            addr: upstream.addr.clone(),
            tls: upstream.tls,
            auth: upstream.username.is_some() || upstream.password.is_some(),
            members: None,
        }
    }
}

fn looks_like_raw_snapshot(value: &Value) -> bool {
    value.get("version").is_some() || value.get("users").is_some() || value.get("groups").is_some()
}

fn looks_like_legacy_userdata(value: &Value) -> bool {
    value.get("user_list").is_some()
        || value.get("address_list").is_some()
        || value.get("routings").is_some()
}

fn legacy_userdata_to_snapshot(legacy: LegacyUserdata) -> anyhow::Result<RawSnapshot> {
    let addresses = legacy_address_map(&legacy.address_list);
    let mut groups = HashMap::new();
    groups.insert(
        "__legacy_direct".to_string(),
        RawGroup {
            upstream: None,
            default_upstream: None,
            proxy: Vec::new(),
            block: Vec::new(),
        },
    );

    for (idx, routing) in legacy.routings.iter().enumerate() {
        groups.insert(
            legacy_group_id(idx, routing),
            legacy_group(routing, &addresses)?,
        );
    }

    let routes = legacy.routings;
    let mut users = HashMap::with_capacity(legacy.user_list.len());
    for user in legacy.user_list {
        let group =
            legacy_user_group(&user, &routes).unwrap_or_else(|| "__legacy_direct".to_string());
        users.insert(
            user.username,
            RawUser {
                password: user.password,
                expire: user.expire,
                up_rate: value_to_u64(&user.up_rate),
                down_rate: value_to_u64(&user.down_rate),
                max_connections: 0,
                group,
                frontends: Default::default(),
            },
        );
    }

    Ok(RawSnapshot {
        schema_version: 1,
        version: legacy.timestamp.max(1),
        users,
        groups,
        chains: HashMap::new(),
        node_overrides: HashMap::new(),
    })
}

fn legacy_address_map(addresses: &[LegacyAddress]) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for address in addresses {
        let tag = address.tag.trim();
        let value = address.address.trim();
        if tag.is_empty() || value.is_empty() {
            continue;
        }
        map.entry(tag.to_string())
            .or_default()
            .push(value.to_string());
    }
    map
}

fn legacy_group(
    routing: &LegacyRouting,
    addresses: &HashMap<String, Vec<String>>,
) -> anyhow::Result<RawGroup> {
    let mut proxy = Vec::new();
    let mut block = Vec::new();
    for rule in &routing.rules {
        let entries = expand_legacy_rule(rule.tag.trim(), addresses);
        match rule.action.trim().to_ascii_lowercase().as_str() {
            "proxy" => proxy.extend(entries),
            "block" | "deny" => block.extend(entries),
            _ => {}
        }
    }
    dedup(&mut proxy);
    dedup(&mut block);

    let upstream = legacy_route_upstream(routing)?;
    let default_upstream = legacy_default_upstream(routing)?;
    if upstream.is_none() && default_upstream.is_none() {
        anyhow::bail!("legacy routing has no upstream addr");
    }

    Ok(RawGroup {
        upstream,
        default_upstream,
        proxy,
        block,
    })
}

fn legacy_route_upstream(routing: &LegacyRouting) -> anyhow::Result<Option<RawUpstream>> {
    let addr = routing
        .server_addr
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(str::trim)
        .map(str::to_string)
        .map(strip_proxy_scheme);
    let Some(addr) = addr else {
        return Ok(None);
    };

    let kind = routing
        .connector_type
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(str::trim)
        .map(str::to_string)
        .or_else(|| {
            routing
                .connector
                .get("type")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "http".to_string());

    let tls = kind.eq_ignore_ascii_case("https")
        || routing
            .dialer_type
            .as_deref()
            .map(|s| s.eq_ignore_ascii_case("tls"))
            .unwrap_or_else(|| {
                routing
                    .dialer
                    .get("type")
                    .and_then(Value::as_str)
                    .map(|s| s.eq_ignore_ascii_case("tls"))
                    .unwrap_or(false)
            });

    let use_auth = routing
        .use_auth
        .as_deref()
        .map(|s| s.eq_ignore_ascii_case("enabled") || s.eq_ignore_ascii_case("true"))
        .unwrap_or_else(|| {
            routing
                .auth_user
                .as_deref()
                .is_some_and(|s| !s.trim().is_empty())
                || routing
                    .connector
                    .get("auth")
                    .and_then(|a| a.get("username"))
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.trim().is_empty())
        });

    Ok(Some(RawUpstream {
        kind,
        addr,
        username: use_auth
            .then(|| {
                routing
                    .auth_user
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .or_else(|| {
                        routing
                            .connector
                            .get("auth")
                            .and_then(|a| a.get("username"))
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                    })
            })
            .flatten(),
        password: use_auth
            .then(|| {
                routing
                    .auth_passwd
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .or_else(|| {
                        routing
                            .connector
                            .get("auth")
                            .and_then(|a| a.get("password"))
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_string)
                    })
            })
            .flatten(),
        tls,
        skip_cert_verify: false,
    }))
}

fn legacy_default_upstream(routing: &LegacyRouting) -> anyhow::Result<Option<RawUpstream>> {
    let Some(addr) = routing
        .default_hop_node
        .get("addr")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .map(strip_proxy_scheme)
    else {
        return Ok(None);
    };

    let kind = routing
        .default_hop_node
        .get("connector")
        .and_then(|c| c.get("type"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| "http".to_string());

    let tls = kind.eq_ignore_ascii_case("https")
        || routing
            .default_hop_node
            .get("dialer")
            .and_then(|d| d.get("type"))
            .and_then(Value::as_str)
            .map(|s| s.eq_ignore_ascii_case("tls"))
            .unwrap_or(false);

    let username = routing
        .default_hop_node
        .get("connector")
        .and_then(|c| c.get("auth"))
        .and_then(|a| a.get("username"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let password = routing
        .default_hop_node
        .get("connector")
        .and_then(|c| c.get("auth"))
        .and_then(|a| a.get("password"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    Ok(Some(RawUpstream {
        kind,
        addr,
        username,
        password,
        tls,
        skip_cert_verify: false,
    }))
}

fn strip_proxy_scheme(addr: String) -> String {
    addr.trim()
        .strip_prefix("http://")
        .or_else(|| addr.trim().strip_prefix("https://"))
        .or_else(|| addr.trim().strip_prefix("socks5://"))
        .or_else(|| addr.trim().strip_prefix("socks://"))
        .unwrap_or_else(|| addr.trim())
        .to_string()
}

fn expand_legacy_rule(tag: &str, addresses: &HashMap<String, Vec<String>>) -> Vec<String> {
    if tag.is_empty() {
        return Vec::new();
    }
    addresses
        .get(tag)
        .filter(|entries| !entries.is_empty())
        .cloned()
        .unwrap_or_else(|| vec![tag.to_string()])
}

fn legacy_user_group(user: &LegacyUser, routes: &[LegacyRouting]) -> Option<String> {
    let username = user.username.trim();
    let code = user.code.as_deref().unwrap_or("").trim();
    for (idx, route) in routes.iter().enumerate() {
        if route.users.iter().any(|u| u.trim() == username)
            || (!code.is_empty() && route.codes.iter().any(|c| c.trim() == code))
        {
            return Some(legacy_group_id(idx, route));
        }
    }
    None
}

fn legacy_group_id(idx: usize, routing: &LegacyRouting) -> String {
    let tag = routing
        .server_tag
        .as_deref()
        .unwrap_or("route")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    if tag.is_empty() {
        format!("legacy-route-{idx}")
    } else {
        format!("legacy-route-{idx}-{tag}")
    }
}

fn value_to_u64(value: &Value) -> u64 {
    match value {
        Value::Number(n) => n.as_u64().unwrap_or(0),
        Value::String(s) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

fn dedup(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn validate_snapshot_shape(
    users: &HashMap<String, RawUser>,
    groups: &HashMap<String, RawGroup>,
) -> anyhow::Result<()> {
    if users.len() > MAX_SNAPSHOT_USERS {
        anyhow::bail!(
            "snapshot has too many users: {} > {}",
            users.len(),
            MAX_SNAPSHOT_USERS
        );
    }
    if groups.len() > MAX_SNAPSHOT_GROUPS {
        anyhow::bail!(
            "snapshot has too many groups: {} > {}",
            groups.len(),
            MAX_SNAPSHOT_GROUPS
        );
    }
    let mut rules = 0usize;
    for (group_id, group) in groups {
        rules = rules
            .saturating_add(group.proxy.len())
            .saturating_add(group.block.len());
        if rules > MAX_SNAPSHOT_RULES {
            anyhow::bail!("snapshot has too many policy rules: {rules} > {MAX_SNAPSHOT_RULES}");
        }
        if group_id.trim().is_empty() {
            anyhow::bail!("group id is required");
        }
    }
    for (name, user) in users {
        if user.group.trim().is_empty() {
            anyhow::bail!("user {name}: group is required");
        }
        if !groups.contains_key(&user.group) {
            anyhow::bail!("user {name}: unknown group {:?}", user.group);
        }
    }
    Ok(())
}

fn compile_upstream(context: &str, u: RawUpstream) -> anyhow::Result<Upstream> {
    let kind = match u.kind.to_ascii_lowercase().as_str() {
        "http" | "https" => UpstreamKind::Http,
        "socks5" | "socks" => UpstreamKind::Socks5,
        "reverse" => UpstreamKind::Reverse,
        "subnetra" => UpstreamKind::Subnetra,
        other => anyhow::bail!("{context}: unsupported upstream kind {other:?}"),
    };
    // Reverse upstreams are addressed by `hop_id`, not a dialable host:port,
    // and are authenticated by the hop's QUIC session token — never by
    // per-target credentials or a per-target TLS profile. Reject those fields
    // conservatively so a malformed reverse upstream fails at compile time
    // instead of silently ignoring operator intent.
    if kind == UpstreamKind::Reverse {
        let hop_id = u.addr.trim();
        anyhow::ensure!(
            !hop_id.is_empty(),
            "{context}: reverse upstream requires a non-empty hop_id in addr"
        );
        anyhow::ensure!(
            u.username.is_none() && u.password.is_none(),
            "{context}: reverse upstream must not set username/password (auth is the hop session token)"
        );
        anyhow::ensure!(
            !u.tls && !u.skip_cert_verify,
            "{context}: reverse upstream must not set tls/skip_cert_verify (QUIC transport already encrypts)"
        );
        return Ok(Upstream {
            kind,
            addr: hop_id.to_string(),
            username: None,
            password: None,
            tls: false,
            skip_cert_verify: false,
        });
    }
    // Subnetra upstreams dial the client's target over the overlay, so the
    // destination is the request target — `addr` is unused and per-target
    // credentials / TLS make no sense (the overlay AEAD already protects it).
    if kind == UpstreamKind::Subnetra {
        anyhow::ensure!(
            u.username.is_none() && u.password.is_none(),
            "{context}: subnetra upstream must not set username/password (the overlay is authenticated by per-link PSK)"
        );
        anyhow::ensure!(
            !u.tls && !u.skip_cert_verify,
            "{context}: subnetra upstream must not set tls/skip_cert_verify (the overlay already encrypts)"
        );
        return Ok(Upstream {
            kind,
            addr: u.addr,
            username: None,
            password: None,
            tls: false,
            skip_cert_verify: false,
        });
    }
    Ok(Upstream {
        kind,
        addr: u.addr,
        username: u.username,
        password: u.password,
        tls: u.tls,
        skip_cert_verify: u.skip_cert_verify,
    })
}

/// Validate and compile the (override-merged) chain table. Every structural
/// error rejects the whole snapshot so the node keeps its previous valid one:
/// unknown/empty ids, empty chains, duplicate member ids or priorities,
/// nested chain backends, or a chain present in a schema-v1 snapshot.
fn compile_chains(
    schema_version: u32,
    raw_chains: HashMap<String, RawChain>,
) -> anyhow::Result<HashMap<String, std::sync::Arc<Chain>>> {
    if raw_chains.is_empty() {
        return Ok(HashMap::new());
    }
    // The `kind = "chain"` reference is the fail-closed sentinel for old
    // nodes; requiring the schema declaration keeps the control plane honest
    // about which wire format it is emitting.
    anyhow::ensure!(
        schema_version >= 2,
        "snapshot defines chains but declares schema_version {schema_version}; chains require schema_version >= 2"
    );
    anyhow::ensure!(
        raw_chains.len() <= MAX_SNAPSHOT_CHAINS,
        "snapshot has too many chains: {} > {}",
        raw_chains.len(),
        MAX_SNAPSHOT_CHAINS
    );

    let mut chains = HashMap::with_capacity(raw_chains.len());
    for (id, raw) in raw_chains {
        let chain = compile_chain(&id, raw.members)?;
        chains.insert(id, std::sync::Arc::new(chain));
    }
    Ok(chains)
}

/// Validate and compile one failover chain from its members. Shared by the
/// legacy top-level `chains` table and schema-v4 `{"type":"chain"}` egresses so
/// both enforce identical structure: non-empty id, at least one member, member
/// count limit, unique member ids/priorities, no nested chain backend, and the
/// existing per-member upstream validation. Members are returned sorted by
/// ascending priority (the failover try order).
fn compile_chain(id: &str, raw_members: Vec<RawChainMember>) -> anyhow::Result<Chain> {
    anyhow::ensure!(!id.trim().is_empty(), "chain id is required");
    anyhow::ensure!(
        !raw_members.is_empty(),
        "chain {id}: must have at least one member"
    );
    anyhow::ensure!(
        raw_members.len() <= MAX_CHAIN_MEMBERS,
        "chain {id}: too many members: {} > {}",
        raw_members.len(),
        MAX_CHAIN_MEMBERS
    );
    let mut member_ids = HashSet::with_capacity(raw_members.len());
    let mut priorities = HashSet::with_capacity(raw_members.len());
    let mut members = Vec::with_capacity(raw_members.len());
    for m in raw_members {
        let member_id = m.id.trim().to_string();
        anyhow::ensure!(!member_id.is_empty(), "chain {id}: member id is required");
        anyhow::ensure!(
            member_ids.insert(member_id.clone()),
            "chain {id}: duplicate member id {member_id:?}"
        );
        anyhow::ensure!(
            priorities.insert(m.priority),
            "chain {id}: duplicate member priority {}",
            m.priority
        );
        // No recursion: a member is always a concrete backend.
        anyhow::ensure!(
            !m.backend.kind.eq_ignore_ascii_case("chain"),
            "chain {id}: member {member_id} backend must not be another chain"
        );
        let upstream = compile_upstream(&format!("chain {id} member {member_id}"), m.backend)?;
        members.push(ChainMember {
            id: member_id,
            priority: m.priority,
            upstream,
        });
    }
    // Ascending priority = the failover try order.
    members.sort_by_key(|m| m.priority);
    Ok(Chain {
        id: id.to_string(),
        members,
    })
}

/// Compile a schema-v4 named egress. `{"type":"upstream"}` reuses the existing
/// upstream validation (and forbids a `kind:"chain"` backend); `{"type":"chain"}`
/// reuses [`compile_chain`] so a named chain egress has identical structure and
/// runtime semantics to a legacy chain.
fn compile_egress(id: &str, raw: RawEgress) -> anyhow::Result<Egress> {
    let kind = match raw {
        RawEgress::Upstream { backend } => {
            anyhow::ensure!(
                !backend.kind.eq_ignore_ascii_case("chain"),
                "egress {id}: upstream backend must not be a chain (use \"type\":\"chain\")"
            );
            EgressKind::Upstream(compile_upstream(&format!("egress {id}"), backend)?)
        }
        RawEgress::Chain { members } => {
            EgressKind::Chain(std::sync::Arc::new(compile_chain(id, members)?))
        }
    };
    Ok(Egress {
        id: id.to_string(),
        kind,
    })
}

/// Compile one user (schema-independent): parse the expiry date and index each
/// front-end credential by uuid, failing compilation on a uuid claimed by two
/// users on the same protocol so front-end auth is never ambiguous.
/// `routing_key` is the user's group (schema 1-3) or policy (schema v4) id.
#[allow(clippy::too_many_arguments)]
fn compile_user(
    name: &str,
    password: String,
    expire: Option<String>,
    up_rate: u64,
    down_rate: u64,
    max_connections: usize,
    routing_key: String,
    raw_frontends: HashMap<String, RawFrontendCred>,
    frontend_index: &mut HashMap<String, HashMap<String, String>>,
) -> anyhow::Result<User> {
    let expire = match expire.as_deref() {
        Some(s) if !s.trim().is_empty() => Some(
            NaiveDate::parse_from_str(s.trim(), "%Y-%m-%d")
                .map_err(|e| anyhow::anyhow!("user {name}: bad expire {s:?}: {e}"))?,
        ),
        _ => None,
    };
    let mut frontends = HashMap::with_capacity(raw_frontends.len());
    for (proto, cred) in raw_frontends {
        if let Some(uuid) = cred.uuid.as_ref() {
            let key = uuid.trim().to_ascii_lowercase();
            if !key.is_empty() {
                let idx = frontend_index.entry(proto.clone()).or_default();
                if let Some(prev) = idx.insert(key.clone(), name.to_string()) {
                    anyhow::bail!("frontend {proto} uuid {key} claimed by both {prev} and {name}");
                }
            }
        }
        frontends.insert(
            proto,
            FrontendCred {
                uuid: cred.uuid,
                password: cred.password,
            },
        );
    }
    Ok(User {
        password,
        expire,
        up_rate,
        down_rate,
        max_connections,
        group: routing_key,
        frontends,
    })
}

fn account_book_selector(
    rules: &RuleSet,
    allocations: &mut HashSet<usize>,
    total_bytes: &mut usize,
    limit: usize,
) -> anyhow::Result<()> {
    let Some((allocation, bytes)) = rules.book_selector_allocation() else {
        return Ok(());
    };
    if !allocations.insert(allocation) {
        return Ok(());
    }
    *total_bytes = total_bytes
        .checked_add(bytes)
        .ok_or_else(|| anyhow::anyhow!("addrbook selector memory size overflow"))?;
    if *total_bytes > limit {
        anyhow::bail!(
            "addrbook selector memory budget exceeded: {} > {} bytes",
            *total_bytes,
            limit
        );
    }
    Ok(())
}

/// Compile one group upstream slot: `kind = "chain"` resolves `addr` as a
/// chain id against the override-merged chain table (dangling references
/// reject the snapshot); every other kind keeps the existing single-upstream
/// semantics.
fn compile_group_egress(
    group: &str,
    slot: &str,
    u: RawUpstream,
    chains: &HashMap<String, std::sync::Arc<Chain>>,
) -> anyhow::Result<GroupEgress> {
    if u.kind.eq_ignore_ascii_case("chain") {
        let chain_id = u.addr.trim();
        anyhow::ensure!(
            !chain_id.is_empty(),
            "group {group}: {slot} chain reference requires a chain id in addr"
        );
        // A chain reference carries no connection parameters of its own; the
        // members do. Reject conflicting fields instead of ignoring them.
        anyhow::ensure!(
            u.username.is_none() && u.password.is_none() && !u.tls && !u.skip_cert_verify,
            "group {group}: {slot} chain reference must not set username/password/tls/skip_cert_verify"
        );
        let chain = chains.get(chain_id).ok_or_else(|| {
            anyhow::anyhow!("group {group}: {slot} references unknown chain {chain_id:?}")
        })?;
        return Ok(GroupEgress::Chain(chain.clone()));
    }
    Ok(GroupEgress::Single(compile_upstream(
        &format!("group {group}"),
        u,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_budget_counts_unique_allocations_only() {
        let mut builder = crate::addrbook::BookBuilder::new(1);
        builder.add_rule("a", "a.example").unwrap();
        builder.add_rule("b", "b.example").unwrap();
        let book = std::sync::Arc::new(
            crate::addrbook::AddrBook::from_bytes(&builder.build_bytes().unwrap()).unwrap(),
        );
        let a1 =
            RuleSet::from_rules(&["book:a".to_string()], Some(&book)).expect("selector compiles");
        let a2 =
            RuleSet::from_rules(&["book:a".to_string()], Some(&book)).expect("selector compiles");
        let b =
            RuleSet::from_rules(&["book:b".to_string()], Some(&book)).expect("selector compiles");

        let mut allocations = HashSet::new();
        let mut bytes = 0;
        account_book_selector(&a1, &mut allocations, &mut bytes, 8).unwrap();
        account_book_selector(&a2, &mut allocations, &mut bytes, 8).unwrap();
        assert_eq!(bytes, 8, "shared selector must only count once");
        let err = account_book_selector(&b, &mut allocations, &mut bytes, 8).unwrap_err();
        assert!(err.to_string().contains("memory budget exceeded"), "{err}");
    }

    #[test]
    fn compile_upstream_accepts_reverse_with_hop_id() {
        let up = compile_upstream(
            "reverse-egress",
            RawUpstream {
                kind: "reverse".to_string(),
                addr: "hop-s604".to_string(),
                username: None,
                password: None,
                tls: false,
                skip_cert_verify: false,
            },
        )
        .expect("valid reverse upstream compiles");
        assert_eq!(up.kind, UpstreamKind::Reverse);
        assert_eq!(up.addr, "hop-s604");
        assert!(up.username.is_none() && up.password.is_none());
        assert!(!up.tls && !up.skip_cert_verify);
    }

    #[test]
    fn compile_upstream_rejects_reverse_without_hop_id() {
        let err = compile_upstream(
            "g",
            RawUpstream {
                kind: "reverse".to_string(),
                addr: "   ".to_string(),
                username: None,
                password: None,
                tls: false,
                skip_cert_verify: false,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("non-empty hop_id"));
    }

    #[test]
    fn compile_upstream_rejects_reverse_with_auth_or_tls() {
        let with_auth = compile_upstream(
            "g",
            RawUpstream {
                kind: "reverse".to_string(),
                addr: "hop-1".to_string(),
                username: Some("u".to_string()),
                password: None,
                tls: false,
                skip_cert_verify: false,
            },
        )
        .unwrap_err();
        assert!(with_auth
            .to_string()
            .contains("must not set username/password"));

        let with_tls = compile_upstream(
            "g",
            RawUpstream {
                kind: "reverse".to_string(),
                addr: "hop-1".to_string(),
                username: None,
                password: None,
                tls: true,
                skip_cert_verify: false,
            },
        )
        .unwrap_err();
        assert!(with_tls.to_string().contains("must not set tls"));
    }

    #[test]
    fn compile_upstream_still_rejects_unknown_kind() {
        let err = compile_upstream(
            "g",
            RawUpstream {
                kind: "wireguard".to_string(),
                addr: "x:1".to_string(),
                username: None,
                password: None,
                tls: false,
                skip_cert_verify: false,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("unsupported upstream kind"));
    }

    #[test]
    fn decide_returns_reverse_upstream_for_reverse_group() {
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            RawUser {
                password: "example".to_string(),
                expire: None,
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                group: "reverse-egress".to_string(),
                frontends: Default::default(),
            },
        );
        let mut groups = HashMap::new();
        groups.insert(
            "reverse-egress".to_string(),
            RawGroup {
                upstream: Some(RawUpstream {
                    kind: "reverse".to_string(),
                    addr: "hop-s604".to_string(),
                    username: None,
                    password: None,
                    tls: false,
                    skip_cert_verify: false,
                }),
                default_upstream: None,
                proxy: vec!["example.com".to_string()],
                block: Vec::new(),
            },
        );
        let raw = RawSnapshot {
            version: 1,
            users,
            groups,
            ..Default::default()
        };
        let snap = Snapshot::compile(raw, "edge-tokyo-01").expect("reverse snapshot compiles");
        match snap.decide("alice", "example.com") {
            Decision::Via(up) => {
                assert_eq!(up.kind, UpstreamKind::Reverse);
                assert_eq!(up.addr, "hop-s604");
            }
            other => panic!("expected reverse upstream, got {other:?}"),
        }
    }

    #[test]
    fn compile_builds_frontend_index_and_rejects_duplicate_uuid() {
        let group = || RawGroup {
            upstream: None,
            default_upstream: None,
            proxy: vec![],
            block: vec![],
        };
        let raw_user = |uuid: &str| RawUser {
            password: "login".to_string(),
            expire: None,
            up_rate: 0,
            down_rate: 0,
            max_connections: 0,
            group: "g".to_string(),
            frontends: HashMap::from([(
                "tuic".to_string(),
                RawFrontendCred {
                    uuid: Some(uuid.to_string()),
                    password: Some("tp".to_string()),
                },
            )]),
        };

        // Happy path: uuid resolves to the owning username (case-insensitive).
        let mut users = HashMap::new();
        users.insert(
            "bob".to_string(),
            raw_user("AAAAAAAA-0000-0000-0000-000000000001"),
        );
        let mut groups = HashMap::new();
        groups.insert("g".to_string(), group());
        let snap = Snapshot::compile(
            RawSnapshot {
                version: 1,
                users,
                groups,
                ..Default::default()
            },
            "n",
        )
        .expect("compiles");
        let (name, _u) = snap
            .frontend_user("tuic", "aaaaaaaa-0000-0000-0000-000000000001")
            .expect("uuid resolves");
        assert_eq!(name, "bob");
        assert!(snap.frontend_user("tuic", "no-such-uuid").is_none());

        // A uuid claimed by two users must fail compilation (ambiguous auth).
        let mut dup_users = HashMap::new();
        dup_users.insert("bob".to_string(), raw_user("dup-uuid"));
        dup_users.insert("carol".to_string(), raw_user("dup-uuid"));
        let mut dup_groups = HashMap::new();
        dup_groups.insert("g".to_string(), group());
        let err = match Snapshot::compile(
            RawSnapshot {
                version: 1,
                users: dup_users,
                groups: dup_groups,
                ..Default::default()
            },
            "n",
        ) {
            Ok(_) => panic!("duplicate tuic uuid must fail compilation"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("claimed by both"));
    }

    #[test]
    fn decode_snapshot_accepts_raw_snapshot_format() {
        let raw = decode_snapshot(
            br#"{
                "version": 9,
                "users": {
                    "alice": {
                        "password": "secret",
                        "group": "open",
                        "max_connections": 2
                    }
                },
                "groups": {
                    "open": {
                        "proxy": ["github.com"],
                        "block": []
                    }
                }
            }"#,
        )
        .unwrap()
        .into_legacy()
        .unwrap();

        assert_eq!(raw.version, 9);
        assert_eq!(raw.users["alice"].group, "open");
        assert_eq!(raw.users["alice"].max_connections, 2);
        assert!(raw.groups["open"].upstream.is_none());
    }

    #[test]
    fn decode_snapshot_converts_legacy_userdata() {
        let raw = decode_snapshot(
            br#"{
                "timestamp": 42,
                "user_list": [
                    {
                        "username": "alice",
                        "password": "secret",
                        "expire": "2099-12-31",
                        "code": "A",
                        "up_rate": "1024",
                        "down_rate": "2048"
                    },
                    {
                        "username": "bob",
                        "password": "hidden",
                        "expire": "",
                        "code": "B",
                        "up_rate": 0,
                        "down_rate": 0
                    }
                ],
                "address_list": [
                    {"tag": "GitHub", "address": "github.com", "type": "domain"},
                    {"tag": "GitHub", "address": "githubusercontent.com", "type": "domain"},
                    {"tag": "Office", "address": "100.117.0.0/16", "type": "ip"}
                ],
                "routings": [
                    {
                        "server_tag": "edge one",
                        "server_addr": "proxy.example.com:8443",
                        "connector_type": "http",
                        "dialer_type": "tls",
                        "use_auth": "enabled",
                        "auth_user": "up",
                        "auth_passwd": "pass",
                        "codes": ["A"],
                        "users": [],
                        "rules": [
                            {"tag": "GitHub", "action": "proxy"},
                            {"tag": "Office", "action": "block"}
                        ]
                    },
                    {
                        "server_tag": "edge two",
                        "server_addr": "socks.example.com:1080",
                        "connector_type": "socks5",
                        "dialer_type": "tcp",
                        "use_auth": "disabled",
                        "codes": ["A", "B"],
                        "users": [],
                        "rules": [
                            {"tag": "example.net", "action": "proxy"}
                        ]
                    }
                ]
            }"#,
        )
        .unwrap()
        .into_legacy()
        .unwrap();

        assert_eq!(raw.version, 42);
        assert_eq!(raw.users.len(), 2);
        assert_eq!(raw.users["alice"].up_rate, 1024);
        assert_eq!(raw.users["alice"].down_rate, 2048);
        assert_eq!(raw.users["alice"].group, "legacy-route-0-edge-one");
        assert_eq!(raw.users["bob"].group, "legacy-route-1-edge-two");

        let first = &raw.groups["legacy-route-0-edge-one"];
        assert_eq!(first.proxy, vec!["github.com", "githubusercontent.com"]);
        assert_eq!(first.block, vec!["100.117.0.0/16"]);
        let upstream = first.upstream.as_ref().unwrap();
        assert_eq!(upstream.kind, "http");
        assert_eq!(upstream.addr, "proxy.example.com:8443");
        assert!(upstream.tls);
        assert_eq!(upstream.username.as_deref(), Some("up"));
        assert_eq!(upstream.password.as_deref(), Some("pass"));

        let second = &raw.groups["legacy-route-1-edge-two"];
        let upstream = second.upstream.as_ref().unwrap();
        assert_eq!(upstream.kind, "socks5");
        assert_eq!(upstream.addr, "socks.example.com:1080");
        assert!(!upstream.tls);
        assert!(upstream.username.is_none());
    }

    #[test]
    fn decode_snapshot_converts_legacy_default_hop_to_default_upstream() {
        let raw = decode_snapshot(
            br#"{
                "timestamp": 43,
                "user_list": [
                    {
                        "username": "alice",
                        "password": "secret",
                        "code": "A",
                        "up_rate": 0,
                        "down_rate": 0
                    }
                ],
                "address_list": [
                    {"tag": "Special", "address": "special.example.com", "type": "domain"}
                ],
                "routings": [
                    {
                        "server_tag": "domestic special",
                        "server_addr": "socks5://domestic.example.com:1080",
                        "connector_type": "socks5",
                        "dialer_type": "tcp",
                        "default_hop_node": {
                            "name": "overseas default",
                            "addr": "overseas.example.com:8443",
                            "connector": {
                                "type": "http",
                                "auth": {
                                    "username": "default-user",
                                    "password": "default-pass"
                                }
                            },
                            "dialer": { "type": "tls" }
                        },
                        "codes": ["A"],
                        "users": [],
                        "rules": [
                            {"tag": "Special", "action": "proxy"}
                        ]
                    }
                ]
            }"#,
        )
        .unwrap()
        .into_legacy()
        .unwrap();

        let group = &raw.groups["legacy-route-0-domestic-special"];
        let special = group.upstream.as_ref().unwrap();
        assert_eq!(special.kind, "socks5");
        assert_eq!(special.addr, "domestic.example.com:1080");
        let default = group.default_upstream.as_ref().unwrap();
        assert_eq!(default.kind, "http");
        assert_eq!(default.addr, "overseas.example.com:8443");
        assert!(default.tls);
        assert_eq!(default.username.as_deref(), Some("default-user"));
        assert_eq!(default.password.as_deref(), Some("default-pass"));

        let snap = Snapshot::compile(raw, "node-1").unwrap();
        match snap.decide("alice", "special.example.com") {
            Decision::Via(up) => assert_eq!(up.addr, "domestic.example.com:1080"),
            other => panic!("expected special upstream, got {other:?}"),
        }
        match snap.decide("alice", "ordinary.example.com") {
            Decision::Via(up) => assert_eq!(up.addr, "overseas.example.com:8443"),
            other => panic!("expected default upstream, got {other:?}"),
        }
    }

    #[test]
    fn decode_snapshot_rejects_unknown_shape() {
        let err = decode_snapshot(br#"{"hello":"world"}"#).unwrap_err();
        assert!(err
            .to_string()
            .contains("neither RawSnapshot nor legacy userdata"));
    }

    #[test]
    fn compile_rejects_unknown_user_group() {
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            RawUser {
                password: "secret".to_string(),
                expire: None,
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                group: "missing".to_string(),
                frontends: Default::default(),
            },
        );

        let err = Snapshot::compile(
            RawSnapshot {
                version: 1,
                users,
                groups: HashMap::new(),
                ..Default::default()
            },
            "node-1",
        )
        .err()
        .expect("snapshot with unknown group should be rejected");

        assert!(err.to_string().contains("unknown group"));
    }

    #[test]
    fn compile_rejects_empty_user_group() {
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            RawUser {
                password: "secret".to_string(),
                expire: None,
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                group: "  ".to_string(),
                frontends: Default::default(),
            },
        );

        let err = Snapshot::compile(
            RawSnapshot {
                version: 1,
                users,
                groups: HashMap::new(),
                ..Default::default()
            },
            "node-1",
        )
        .err()
        .expect("snapshot with empty group should be rejected");

        assert!(err.to_string().contains("group is required"));
    }

    #[test]
    fn compile_rejects_empty_group_id() {
        let mut groups = HashMap::new();
        groups.insert(
            " ".to_string(),
            RawGroup {
                upstream: None,
                default_upstream: None,
                proxy: Vec::new(),
                block: Vec::new(),
            },
        );

        let err = Snapshot::compile(
            RawSnapshot {
                version: 1,
                users: HashMap::new(),
                groups,
                ..Default::default()
            },
            "node-1",
        )
        .err()
        .expect("snapshot with empty group id should be rejected");

        assert!(err.to_string().contains("group id is required"));
    }

    #[test]
    fn compile_applies_node_specific_override_for_matching_node_id() {
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            RawUser {
                password: "secret".to_string(),
                expire: None,
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                group: "via-hop".to_string(),
                frontends: Default::default(),
            },
        );
        let mut groups = HashMap::new();
        groups.insert(
            "via-hop".to_string(),
            RawGroup {
                upstream: Some(RawUpstream {
                    kind: "socks5".to_string(),
                    addr: "shared-hop.example.com:1080".to_string(),
                    username: None,
                    password: None,
                    tls: false,
                    skip_cert_verify: false,
                }),
                default_upstream: None,
                proxy: vec!["example.com".to_string()],
                block: Vec::new(),
            },
        );
        let mut override_groups = HashMap::new();
        override_groups.insert(
            "via-hop".to_string(),
            RawGroup {
                upstream: Some(RawUpstream {
                    kind: "socks5".to_string(),
                    addr: "127.0.0.1:1080".to_string(),
                    username: None,
                    password: None,
                    tls: false,
                    skip_cert_verify: false,
                }),
                default_upstream: None,
                proxy: vec!["example.com".to_string()],
                block: Vec::new(),
            },
        );
        let mut node_overrides = HashMap::new();
        node_overrides.insert(
            "edge-tokyo-01".to_string(),
            NodeOverride {
                groups: override_groups,
                chains: HashMap::new(),
            },
        );
        let raw = RawSnapshot {
            version: 1,
            users,
            groups,
            node_overrides,
            ..Default::default()
        };

        let overridden = Snapshot::compile(raw.clone(), "edge-tokyo-01").unwrap();
        match overridden.decide("alice", "example.com") {
            Decision::Via(up) => assert_eq!(up.addr, "127.0.0.1:1080"),
            other => panic!("expected overridden upstream, got {other:?}"),
        }

        let unmatched = Snapshot::compile(raw, "edge-hk-01").unwrap();
        match unmatched.decide("alice", "example.com") {
            Decision::Via(up) => assert_eq!(up.addr, "shared-hop.example.com:1080"),
            other => panic!("expected shared base upstream, got {other:?}"),
        }
    }

    #[test]
    fn compile_node_override_can_introduce_a_node_only_group() {
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            RawUser {
                password: "secret".to_string(),
                expire: None,
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                group: "node-only".to_string(),
                frontends: Default::default(),
            },
        );
        let mut override_groups = HashMap::new();
        override_groups.insert(
            "node-only".to_string(),
            RawGroup {
                upstream: None,
                default_upstream: None,
                proxy: Vec::new(),
                block: Vec::new(),
            },
        );
        let mut node_overrides = HashMap::new();
        node_overrides.insert(
            "edge-tokyo-01".to_string(),
            NodeOverride {
                groups: override_groups,
                chains: HashMap::new(),
            },
        );
        let raw = RawSnapshot {
            version: 1,
            users,
            groups: HashMap::new(),
            node_overrides,
            ..Default::default()
        };

        // The referencing node resolves fine because its override supplies
        // the group that "groups" alone does not define.
        Snapshot::compile(raw.clone(), "edge-tokyo-01")
            .expect("node with a matching override should compile");

        // A node without that override still fails closed instead of
        // silently treating the user as direct/open.
        let err = Snapshot::compile(raw, "edge-hk-01")
            .err()
            .expect("node without the override should reject the dangling group");
        assert!(err.to_string().contains("unknown group"));
    }

    #[test]
    fn decide_prefers_special_upstream_then_default_upstream() {
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            RawUser {
                password: "secret".to_string(),
                expire: None,
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                group: "split-exit".to_string(),
                frontends: Default::default(),
            },
        );
        let mut groups = HashMap::new();
        groups.insert(
            "split-exit".to_string(),
            RawGroup {
                upstream: Some(RawUpstream {
                    kind: "socks5".to_string(),
                    addr: "special-hop.example.com:1080".to_string(),
                    username: None,
                    password: None,
                    tls: false,
                    skip_cert_verify: false,
                }),
                default_upstream: Some(RawUpstream {
                    kind: "socks5".to_string(),
                    addr: "default-hop.example.com:1080".to_string(),
                    username: None,
                    password: None,
                    tls: false,
                    skip_cert_verify: false,
                }),
                proxy: vec!["special.example.com".to_string()],
                block: vec![
                    "blocked.example.com".to_string(),
                    "203.0.113.0/24".to_string(),
                ],
            },
        );
        let snap = Snapshot::compile(
            RawSnapshot {
                version: 1,
                users,
                groups,
                ..Default::default()
            },
            "node-1",
        )
        .unwrap();

        match snap.decide("alice", "special.example.com") {
            Decision::Via(up) => assert_eq!(up.addr, "special-hop.example.com:1080"),
            other => panic!("expected special upstream, got {other:?}"),
        }
        match snap.decide("alice", "ordinary.example.com") {
            Decision::Via(up) => assert_eq!(up.addr, "default-hop.example.com:1080"),
            other => panic!("expected default upstream, got {other:?}"),
        }
        assert!(matches!(
            snap.decide("alice", "blocked.example.com"),
            Decision::Block
        ));

        let sniffed_proxy =
            snap.decide_with_sniff("alice", "198.51.100.20", Some("special.example.com"));
        match sniffed_proxy.decision {
            Decision::Via(up) => assert_eq!(up.addr, "special-hop.example.com:1080"),
            other => panic!("expected sniffed special upstream, got {other:?}"),
        }
        assert_eq!(sniffed_proxy.effective_policy_host, "special.example.com");
        assert_eq!(sniffed_proxy.snapshot_version, 1);

        let sniffed_block =
            snap.decide_with_sniff("alice", "special.example.com", Some("blocked.example.com"));
        assert!(matches!(sniffed_block.decision, Decision::Block));
        assert_eq!(sniffed_block.effective_policy_host, "blocked.example.com");

        let requested_block =
            snap.decide_with_sniff("alice", "blocked.example.com", Some("special.example.com"));
        assert!(matches!(requested_block.decision, Decision::Block));
        assert_eq!(requested_block.effective_policy_host, "blocked.example.com");

        let requested_ip_block =
            snap.decide_with_sniff("alice", "203.0.113.9", Some("special.example.com"));
        assert!(matches!(requested_ip_block.decision, Decision::Block));
        assert_eq!(requested_ip_block.effective_policy_host, "203.0.113.9");

        let fallback =
            snap.decide_with_sniff("alice", "198.51.100.20", Some("ordinary.example.com"));
        match fallback.decision {
            Decision::Via(up) => assert_eq!(up.addr, "default-hop.example.com:1080"),
            other => panic!("expected default upstream, got {other:?}"),
        }
        assert_eq!(fallback.effective_policy_host, "198.51.100.20");

        let explicit_domain =
            snap.decide_with_sniff("alice", "ordinary.example.com", Some("special.example.com"));
        match explicit_domain.decision {
            Decision::Via(up) => assert_eq!(up.addr, "default-hop.example.com:1080"),
            other => panic!("explicit domain must keep default route, got {other:?}"),
        }
        assert_eq!(
            explicit_domain.effective_policy_host,
            "ordinary.example.com"
        );
    }

    #[test]
    fn compile_rejects_too_many_node_overrides() {
        let mut node_overrides = HashMap::new();
        for i in 0..=MAX_SNAPSHOT_NODE_OVERRIDES {
            node_overrides.insert(format!("node-{i}"), NodeOverride::default());
        }
        let raw = RawSnapshot {
            version: 1,
            users: HashMap::new(),
            groups: HashMap::new(),
            node_overrides,
            ..Default::default()
        };

        let err = Snapshot::compile(raw, "node-1")
            .err()
            .expect("snapshot with too many node overrides should be rejected");
        assert!(err.to_string().contains("too many node overrides"));
    }

    #[test]
    fn compile_rejects_empty_node_override_group_id() {
        let mut override_groups = HashMap::new();
        override_groups.insert(
            " ".to_string(),
            RawGroup {
                upstream: None,
                default_upstream: None,
                proxy: Vec::new(),
                block: Vec::new(),
            },
        );
        let mut node_overrides = HashMap::new();
        node_overrides.insert(
            "edge-tokyo-01".to_string(),
            NodeOverride {
                groups: override_groups,
                chains: HashMap::new(),
            },
        );
        let raw = RawSnapshot {
            version: 1,
            users: HashMap::new(),
            groups: HashMap::new(),
            node_overrides,
            ..Default::default()
        };

        let err = Snapshot::compile(raw, "edge-tokyo-01")
            .err()
            .expect("empty node override group id should be rejected");
        assert!(err.to_string().contains("group id is required"));
    }

    #[test]
    fn decide_blocks_when_user_or_group_is_missing() {
        let snap = Snapshot::empty();
        assert!(matches!(
            snap.decide("missing", "example.com"),
            Decision::Block
        ));

        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            User {
                password: "secret".to_string(),
                expire: None,
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                group: "missing".to_string(),
                frontends: Default::default(),
            },
        );
        let snap = Snapshot {
            version: 1,
            schema_version: 1,
            routing: Routing::Legacy,
            users,
            groups: HashMap::new(),
            policies: HashMap::new(),
            frontend_index: HashMap::new(),
        };

        assert!(matches!(
            snap.decide("alice", "example.com"),
            Decision::Block
        ));
    }

    #[test]
    fn user_policy_mirrors_policy_into_the_legacy_policies_array() {
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            User {
                password: "secret".to_string(),
                expire: None,
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                group: "g1".to_string(),
                frontends: Default::default(),
            },
        );
        let mut groups = HashMap::new();
        groups.insert(
            "g1".to_string(),
            Group {
                upstream: Some(GroupEgress::Single(Upstream {
                    kind: UpstreamKind::Socks5,
                    addr: "127.0.0.1:1080".to_string(),
                    username: None,
                    password: None,
                    tls: false,
                    skip_cert_verify: false,
                })),
                default_upstream: None,
                proxy: RuleSet::default(),
                block: RuleSet::default(),
                proxy_rules: vec!["example.com".to_string()],
                block_rules: vec![],
            },
        );
        let snap = Snapshot {
            version: 1,
            schema_version: 1,
            routing: Routing::Legacy,
            users,
            groups,
            policies: HashMap::new(),
            frontend_index: HashMap::new(),
        };

        let view = snap.user_policy("alice").expect("user must resolve");
        let policy = view.policy.clone().expect("group must resolve");
        assert_eq!(view.policies.len(), 1);
        assert_eq!(view.policies[0].proxy, policy.proxy);
        assert_eq!(view.policies[0].block, policy.block);

        // A user pointing at an unknown group still resolves (matches the
        // MQTT `not_found` semantics living one level up), but with no
        // policy data on either the singular or array field.
        let mut orphan_users = HashMap::new();
        orphan_users.insert(
            "bob".to_string(),
            User {
                password: "secret".to_string(),
                expire: None,
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                group: "missing".to_string(),
                frontends: Default::default(),
            },
        );
        let snap = Snapshot {
            version: 1,
            schema_version: 1,
            routing: Routing::Legacy,
            users: orphan_users,
            groups: HashMap::new(),
            policies: HashMap::new(),
            frontend_index: HashMap::new(),
        };
        let view = snap.user_policy("bob").expect("user must resolve");
        assert!(view.policy.is_none());
        assert!(view.policies.is_empty());

        assert!(snap.user_policy("missing").is_none());
    }

    // ---------------------------------------------------------------------
    // Failover chains (schema v2)
    // ---------------------------------------------------------------------

    fn raw_upstream(kind: &str, addr: &str) -> RawUpstream {
        RawUpstream {
            kind: kind.to_string(),
            addr: addr.to_string(),
            username: None,
            password: None,
            tls: false,
            skip_cert_verify: false,
        }
    }

    fn chain_member(id: &str, priority: u32, kind: &str, addr: &str) -> RawChainMember {
        RawChainMember {
            id: id.to_string(),
            priority,
            backend: raw_upstream(kind, addr),
        }
    }

    fn chain_user(group: &str) -> RawUser {
        RawUser {
            password: "secret".to_string(),
            expire: None,
            up_rate: 0,
            down_rate: 0,
            max_connections: 0,
            group: group.to_string(),
            frontends: Default::default(),
        }
    }

    /// A v2 snapshot with one `jp-pop` chain (reverse primary + socks5
    /// backup, deliberately inserted out of priority order) referenced from
    /// `rule-a.upstream`.
    fn chain_snapshot() -> RawSnapshot {
        let mut users = HashMap::new();
        users.insert("alice".to_string(), chain_user("rule-a"));
        let mut groups = HashMap::new();
        groups.insert(
            "rule-a".to_string(),
            RawGroup {
                upstream: Some(raw_upstream("chain", "jp-pop")),
                default_upstream: None,
                proxy: vec!["example.com".to_string()],
                block: Vec::new(),
            },
        );
        let mut chains = HashMap::new();
        chains.insert(
            "jp-pop".to_string(),
            RawChain {
                members: vec![
                    chain_member("jp-socks-2", 2, "socks5", "10.2.2.1:1080"),
                    chain_member("jp-reverse-1", 1, "reverse", "h1"),
                ],
            },
        );
        RawSnapshot {
            schema_version: 2,
            version: 13,
            users,
            groups,
            chains,
            node_overrides: HashMap::new(),
        }
    }

    #[test]
    fn compile_chain_snapshot_and_decide_returns_sorted_chain() {
        let snap = Snapshot::compile(chain_snapshot(), "edge-tokyo-01").expect("v2 compiles");
        assert_eq!(snap.schema_version, 2);
        match snap.decide("alice", "example.com") {
            Decision::ViaChain(chain) => {
                assert_eq!(chain.id, "jp-pop");
                let order: Vec<_> = chain.members.iter().map(|m| m.id.as_str()).collect();
                assert_eq!(order, ["jp-reverse-1", "jp-socks-2"]);
                assert_eq!(chain.members[0].upstream.kind, UpstreamKind::Reverse);
                assert_eq!(chain.members[1].upstream.addr, "10.2.2.1:1080");
            }
            other => panic!("expected chain decision, got {other:?}"),
        }
        // Unmatched targets stay direct: the chain applies only via the slot.
        assert!(matches!(
            snap.decide("alice", "other.example.net"),
            Decision::Direct
        ));
    }

    #[test]
    fn compile_supports_chain_in_default_upstream_slot() {
        let mut raw = chain_snapshot();
        let group = raw.groups.get_mut("rule-a").unwrap();
        group.default_upstream = group.upstream.take();
        let snap = Snapshot::compile(raw, "n").expect("compiles");
        assert!(matches!(
            snap.decide("alice", "anything.example.net"),
            Decision::ViaChain(_)
        ));
    }

    #[test]
    fn compile_rejects_unknown_chain_reference() {
        let mut raw = chain_snapshot();
        raw.groups.get_mut("rule-a").unwrap().upstream = Some(raw_upstream("chain", "no-such"));
        let err = Snapshot::compile(raw, "n")
            .err()
            .expect("snapshot must be rejected");
        assert!(err.to_string().contains("unknown chain"));
    }

    #[test]
    fn compile_rejects_empty_chain_and_empty_ids() {
        let mut raw = chain_snapshot();
        raw.chains
            .insert("empty".to_string(), RawChain { members: vec![] });
        let err = Snapshot::compile(raw, "n")
            .err()
            .expect("snapshot must be rejected");
        assert!(err.to_string().contains("at least one member"));

        let mut raw = chain_snapshot();
        raw.chains.get_mut("jp-pop").unwrap().members[0].id = "  ".to_string();
        let err = Snapshot::compile(raw, "n")
            .err()
            .expect("snapshot must be rejected");
        assert!(err.to_string().contains("member id is required"));

        let mut raw = chain_snapshot();
        let chain = raw.chains.remove("jp-pop").unwrap();
        raw.chains.insert(" ".to_string(), chain);
        let err = Snapshot::compile(raw, "n")
            .err()
            .expect("snapshot must be rejected");
        assert!(err.to_string().contains("chain id is required"));
    }

    #[test]
    fn compile_rejects_duplicate_member_ids_and_priorities() {
        let mut raw = chain_snapshot();
        raw.chains.get_mut("jp-pop").unwrap().members[0].id = "jp-reverse-1".to_string();
        let err = Snapshot::compile(raw, "n")
            .err()
            .expect("snapshot must be rejected");
        assert!(err.to_string().contains("duplicate member id"));

        let mut raw = chain_snapshot();
        raw.chains.get_mut("jp-pop").unwrap().members[0].priority = 1;
        let err = Snapshot::compile(raw, "n")
            .err()
            .expect("snapshot must be rejected");
        assert!(err.to_string().contains("duplicate member priority"));
    }

    #[test]
    fn compile_rejects_nested_chain_member_and_invalid_backend() {
        let mut raw = chain_snapshot();
        raw.chains.get_mut("jp-pop").unwrap().members[0].backend = raw_upstream("chain", "other");
        let err = Snapshot::compile(raw, "n")
            .err()
            .expect("snapshot must be rejected");
        assert!(err.to_string().contains("must not be another chain"));

        // Member backends reuse the existing upstream validation rules.
        let mut raw = chain_snapshot();
        raw.chains.get_mut("jp-pop").unwrap().members[1].backend.tls = true; // reverse + tls
        let err = Snapshot::compile(raw, "n")
            .err()
            .expect("snapshot must be rejected");
        assert!(err.to_string().contains("must not set tls"));
    }

    #[test]
    fn compile_rejects_chain_reference_with_conflicting_fields() {
        let mut raw = chain_snapshot();
        raw.groups.get_mut("rule-a").unwrap().upstream = Some(RawUpstream {
            username: Some("u".to_string()),
            ..raw_upstream("chain", "jp-pop")
        });
        let err = Snapshot::compile(raw, "n")
            .err()
            .expect("snapshot must be rejected");
        assert!(err
            .to_string()
            .contains("must not set username/password/tls/skip_cert_verify"));
    }

    #[test]
    fn compile_rejects_chains_in_schema_v1_and_unsupported_schema() {
        let mut raw = chain_snapshot();
        raw.schema_version = 1;
        let err = Snapshot::compile(raw, "n")
            .err()
            .expect("snapshot must be rejected");
        assert!(err.to_string().contains("require schema_version >= 2"));

        let mut raw = chain_snapshot();
        raw.schema_version = MAX_SUPPORTED_SCHEMA_VERSION + 1;
        let err = Snapshot::compile(raw, "n")
            .err()
            .expect("snapshot must be rejected");
        assert!(err
            .to_string()
            .contains("unsupported snapshot schema_version"));

        let mut raw = chain_snapshot();
        raw.schema_version = 0;
        let err = Snapshot::compile(raw, "n")
            .err()
            .expect("snapshot must be rejected");
        assert!(err
            .to_string()
            .contains("unsupported snapshot schema_version"));
    }

    #[test]
    fn compile_rejects_too_many_chains_and_members() {
        let mut raw = chain_snapshot();
        for i in 0..MAX_SNAPSHOT_CHAINS {
            raw.chains.insert(
                format!("bulk-{i}"),
                RawChain {
                    members: vec![chain_member("m1", 1, "socks5", "10.0.0.1:1080")],
                },
            );
        }
        let err = Snapshot::compile(raw, "n")
            .err()
            .expect("snapshot must be rejected");
        assert!(err.to_string().contains("too many chains"));

        let mut raw = chain_snapshot();
        raw.chains.get_mut("jp-pop").unwrap().members = (0..=MAX_CHAIN_MEMBERS as u32)
            .map(|i| chain_member(&format!("m{i}"), i, "socks5", "10.0.0.1:1080"))
            .collect();
        let err = Snapshot::compile(raw, "n")
            .err()
            .expect("snapshot must be rejected");
        assert!(err.to_string().contains("too many members"));
    }

    #[test]
    fn node_override_replaces_whole_chain_for_matching_node_only() {
        let mut raw = chain_snapshot();
        raw.node_overrides.insert(
            "edge-tokyo-01".to_string(),
            NodeOverride {
                groups: HashMap::new(),
                chains: HashMap::from([(
                    "jp-pop".to_string(),
                    RawChain {
                        members: vec![chain_member("local-1", 1, "socks5", "127.0.0.1:1080")],
                    },
                )]),
            },
        );

        // Matching node: the override fully replaces the member list.
        let snap = Snapshot::compile(raw.clone(), "edge-tokyo-01").unwrap();
        match snap.decide("alice", "example.com") {
            Decision::ViaChain(chain) => {
                assert_eq!(chain.members.len(), 1);
                assert_eq!(chain.members[0].id, "local-1");
            }
            other => panic!("expected chain, got {other:?}"),
        }

        // Other nodes keep the shared chain.
        let snap = Snapshot::compile(raw, "edge-hk-01").unwrap();
        match snap.decide("alice", "example.com") {
            Decision::ViaChain(chain) => assert_eq!(chain.members.len(), 2),
            other => panic!("expected chain, got {other:?}"),
        }
    }

    #[test]
    fn node_override_can_introduce_node_only_chain_and_empty_override_fails() {
        // A group override referencing a chain that only the override defines.
        let mut raw = chain_snapshot();
        raw.chains.clear();
        raw.node_overrides.insert(
            "edge-tokyo-01".to_string(),
            NodeOverride {
                groups: HashMap::new(),
                chains: HashMap::from([(
                    "jp-pop".to_string(),
                    RawChain {
                        members: vec![chain_member("local-1", 1, "socks5", "127.0.0.1:1080")],
                    },
                )]),
            },
        );
        Snapshot::compile(raw.clone(), "edge-tokyo-01").expect("override-supplied chain compiles");
        // A node without the override fails closed on the dangling reference.
        let err = Snapshot::compile(raw, "edge-hk-01")
            .err()
            .expect("snapshot must be rejected");
        assert!(err.to_string().contains("unknown chain"));

        // An override that empties the chain rejects the snapshot ("override
        // 后消失") instead of silently keeping the old members.
        let mut raw = chain_snapshot();
        raw.node_overrides.insert(
            "edge-tokyo-01".to_string(),
            NodeOverride {
                groups: HashMap::new(),
                chains: HashMap::from([("jp-pop".to_string(), RawChain { members: vec![] })]),
            },
        );
        let err = Snapshot::compile(raw, "edge-tokyo-01")
            .err()
            .expect("snapshot must be rejected");
        assert!(err.to_string().contains("at least one member"));
    }

    #[test]
    fn chain_snapshot_json_round_trip_preserves_chains_and_schema() {
        let raw = chain_snapshot();
        let bytes = serde_json::to_vec(&raw).unwrap();
        let restored = decode_snapshot(&bytes)
            .expect("round-trip decodes")
            .into_legacy()
            .expect("round-trip is legacy");
        assert_eq!(restored.schema_version, 2);
        assert_eq!(restored.version, 13);
        assert_eq!(restored.chains.len(), 1);
        assert_eq!(restored.chains["jp-pop"].members.len(), 2);
        assert_eq!(
            restored.groups["rule-a"].upstream.as_ref().unwrap().kind,
            "chain"
        );
        Snapshot::compile(restored, "n").expect("restored snapshot still compiles");
    }

    #[test]
    fn v1_snapshot_without_schema_version_still_compiles_as_schema_1() {
        let raw = decode_snapshot(
            br#"{
                "version": 9,
                "users": {"alice": {"password": "pw", "group": "open"}},
                "groups": {"open": {}}
            }"#,
        )
        .unwrap()
        .into_legacy()
        .unwrap();
        assert_eq!(raw.schema_version, 1);
        let snap = Snapshot::compile(raw, "n").unwrap();
        assert_eq!(snap.schema_version, 1);
        assert!(matches!(
            snap.decide("alice", "example.com"),
            Decision::Direct
        ));
    }

    #[test]
    fn user_policy_view_exposes_chain_without_credentials() {
        let mut raw = chain_snapshot();
        raw.chains.get_mut("jp-pop").unwrap().members[0]
            .backend
            .username = Some("u".to_string());
        raw.chains.get_mut("jp-pop").unwrap().members[0]
            .backend
            .password = Some("super-secret-pass".to_string());
        let snap = Snapshot::compile(raw, "n").unwrap();
        let view = snap.user_policy("alice").expect("resolves");
        let upstream = view.policy.as_ref().unwrap().upstream.as_ref().unwrap();
        assert_eq!(upstream.kind, "chain");
        assert_eq!(upstream.addr, "jp-pop");
        let members = upstream.members.as_ref().expect("members listed");
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].id, "jp-reverse-1");
        assert!(!members[0].auth);
        assert_eq!(members[1].id, "jp-socks-2");
        assert!(members[1].auth);

        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("super-secret-pass"));
        assert!(!json.contains("password"));
    }

    fn v4_user(policy: &str) -> RawUserV4 {
        RawUserV4 {
            password: "secret".to_string(),
            expire: None,
            up_rate: 0,
            down_rate: 0,
            max_connections: 0,
            policy: policy.to_string(),
            frontends: Default::default(),
        }
    }

    fn action_kind(action: Option<&RouteAction>) -> &'static str {
        match action {
            Some(RouteAction::Block) => "block",
            Some(RouteAction::Direct) => "direct",
            Some(RouteAction::Egress(_)) => "egress",
            None => "none",
        }
    }

    fn compile_v4_routes(routes: Vec<RawRoute>) -> Snapshot {
        let mut users = HashMap::new();
        users.insert("alice".to_string(), v4_user("edge"));
        let mut policies = HashMap::new();
        policies.insert(
            "edge".to_string(),
            RawRoutingPolicy {
                routes,
                default_egress: None,
            },
        );
        Snapshot::compile(
            RawSnapshotV4 {
                schema_version: 4,
                version: 1,
                users,
                routing_policies: policies,
                egresses: HashMap::new(),
                node_overrides: HashMap::new(),
            },
            "node-1",
        )
        .expect("v4 snapshot compiles")
    }

    #[test]
    fn v4_first_match_keeps_declaration_order_on_overlap() {
        let snap = compile_v4_routes(vec![
            RawRoute {
                selectors: vec!["example.com".into()],
                action: RawAction::Direct,
            },
            RawRoute {
                selectors: vec!["full:cdn.example.com".into()],
                action: RawAction::Block,
            },
        ]);
        assert!(matches!(
            snap.decide("alice", "cdn.example.com"),
            Decision::Direct
        ));
        assert!(matches!(
            snap.decide("alice", "other.tld"),
            Decision::Direct
        ));
    }

    #[test]
    fn v4_indexed_first_match_agrees_with_linear_scan() {
        let mut routes = Vec::new();
        for i in 0..80 {
            routes.push(RawRoute {
                selectors: vec![format!("full:filler-{i}.example")],
                action: RawAction::Block,
            });
        }
        routes.push(RawRoute {
            selectors: vec!["keyword:special".into()],
            action: RawAction::Direct,
        });
        routes.push(RawRoute {
            selectors: vec!["10.0.0.0/8".into(), "192.0.2.10".into()],
            action: RawAction::Block,
        });
        let snap = compile_v4_routes(routes);
        let policy = snap.policies.get("edge").expect("policy compiled");
        for host in [
            "filler-0.example",
            "filler-79.example",
            "host-with-special.tld",
            "10.1.2.3",
            "192.0.2.10",
            "192.0.2.11",
            "nomatch.other",
            "FILLER-10.EXAMPLE.",
        ] {
            assert_eq!(
                action_kind(policy.first_match(host)),
                action_kind(policy.first_match_naive(host)),
                "index/naive disagree for {host}"
            );
        }
    }

    #[test]
    fn v4_many_full_routes_miss_stays_sublinear() {
        let mut routes = Vec::new();
        for i in 0..2000 {
            routes.push(RawRoute {
                selectors: vec![format!("full:filler-{i}.example")],
                action: RawAction::Block,
            });
        }
        let snap = compile_v4_routes(routes);
        let started = std::time::Instant::now();
        for _ in 0..20_000 {
            assert!(matches!(
                snap.decide("alice", "nomatch.other"),
                Decision::Direct
            ));
        }
        let elapsed = started.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(80),
            "2000-route miss must stay indexed, took {elapsed:?}"
        );
    }
}
