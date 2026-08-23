//! The data model synced from the control plane.
//!
//! Two layers:
//! * `Raw*` — the JSON wire/cache format: `users + routing_policies + egresses`.
//!   There is exactly one schema (`schema_version: 1`); identity, policy and
//!   egress are separate tables, and a user names the policy it is bound to.
//! * compiled `Snapshot` — users indexed by name (O(1) auth) and selector lists
//!   compiled into matchers, ready to serve.

use crate::policy::{RouteIndex, RuleSet};
use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

const MAX_SNAPSHOT_USERS: usize = 100_000;
const MAX_SNAPSHOT_POLICIES: usize = 10_000;
const MAX_SNAPSHOT_EGRESSES: usize = 10_000;
const MAX_SNAPSHOT_RULES: usize = 200_000;
const MAX_SNAPSHOT_NODE_OVERRIDES: usize = 10_000;
const MAX_CHAIN_MEMBERS: usize = 16;
const MAX_ADDRBOOK_SELECTOR_BYTES: usize = 64 * 1024 * 1024;

/// The snapshot *wire schema* version. Distinct from [`RawSnapshot::version`]
/// (the content revision used for `?since=` / 304): `schema_version` only
/// changes when the JSON structure or its semantics change, and every wire
/// struct is `deny_unknown_fields`, so a document a node does not fully
/// understand is rejected whole rather than half-applied.
///
/// There is one schema. `schema_version: 1` is `users` + `routing_policies` +
/// `egresses`; a snapshot declaring anything else is rejected so a node never
/// misreads a newer selector or action as a literal domain.
pub const SCHEMA_VERSION: u32 = 1;

/// Highest schema version this build understands. Equal to [`SCHEMA_VERSION`]
/// today; kept separate because the guard below is what a future schema bump
/// widens.
pub const MAX_SUPPORTED_SCHEMA_VERSION: u32 = SCHEMA_VERSION;

/// Version guard seam: is `schema_version` within `1..=max_supported`?
///
/// Exposed (and tested) so a build pinned to an older `max_supported` provably
/// rejects a newer schema — e.g. `schema_version_supported(2, 1) == false`
/// proves a max-1 node rejects a future schema-v2 snapshot — without
/// hand-crafting a snapshot for every guard case. The real compile path calls
/// this with [`MAX_SUPPORTED_SCHEMA_VERSION`].
pub fn schema_version_supported(schema_version: u32, max_supported: u32) -> bool {
    schema_version >= 1 && schema_version <= max_supported
}

// ---------------------------------------------------------------------------
// Wire / cache format
// ---------------------------------------------------------------------------

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

/// One front-end protocol credential, namespaced per listener adapter so that
/// adding an adapter never widens an existing adapter's credential scope.
/// Different adapters use different subsets: TUIC uses `uuid` + `password`; a
/// token-style adapter may set only `uuid`; a secret-only adapter only
/// `password`. A new adapter must justify itself by an application-ingress
/// requirement and ship its own fail-closed auth path.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct RawFrontendCred {
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
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
// Wire / cache format
// ---------------------------------------------------------------------------

/// Top-level snapshot document: named *routing policies* (ordered first-match
/// routes) plus a separate named-*egress* table, so identity, policy and egress
/// stay independently addressable.
///
/// Strict by construction: unknown top-level fields reject decode, so a
/// malformed or foreign document is refused whole rather than silently
/// interpreted with missing routing intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawSnapshot {
    /// Must be [`SCHEMA_VERSION`]; enforced at decode.
    pub schema_version: u32,
    pub version: u64,
    #[serde(default)]
    pub users: HashMap<String, RawUser>,
    /// Named routing policies keyed by policy id; users reference one by id.
    #[serde(default)]
    pub routing_policies: HashMap<String, RawRoutingPolicy>,
    /// Named egresses keyed by egress id; routes/policies reference these.
    #[serde(default)]
    pub egresses: HashMap<String, RawEgress>,
    /// Per-node egress overrides. A node override only whole-replaces an
    /// existing base egress — routing policies stay node-independent.
    #[serde(default)]
    pub node_overrides: HashMap<String, NodeOverride>,
}

impl Default for RawSnapshot {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            version: 0,
            users: HashMap::new(),
            routing_policies: HashMap::new(),
            egresses: HashMap::new(),
            node_overrides: HashMap::new(),
        }
    }
}

/// One identity: login credential, limits, front-end credentials and the id of
/// the routing policy it is bound to. Strict: any unknown field rejects decode.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawUser {
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

/// Per-node egress overrides. Only `egresses` is allowed: a matching entry
/// whole-replaces an existing base egress with the same id. Strict: any
/// unknown field rejects decode, keeping routing policies node-independent.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NodeOverride {
    #[serde(default)]
    pub egresses: HashMap<String, RawEgress>,
}

/// Parse a snapshot payload into a [`RawSnapshot`].
///
/// Strict by construction: every wire struct is `deny_unknown_fields` and
/// `schema_version` is required, so a payload from a different producer shape —
/// or one carrying a field this build does not implement — is rejected here
/// rather than decoded into a partially-understood policy. The caller keeps its
/// previous valid snapshot (fail closed).
pub fn decode_snapshot(bytes: &[u8]) -> anyhow::Result<RawSnapshot> {
    let doc: RawSnapshot = serde_json::from_slice(bytes)?;
    anyhow::ensure!(
        schema_version_supported(doc.schema_version, MAX_SUPPORTED_SCHEMA_VERSION),
        "unsupported snapshot schema_version {} (this node supports 1..={MAX_SUPPORTED_SCHEMA_VERSION})",
        doc.schema_version
    );
    Ok(doc)
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
    /// Id of the routing policy this identity is bound to. Validated at compile
    /// time, so a dangling reference rejects the snapshot rather than leaving a
    /// user with no policy at request time.
    pub policy: String,
    /// Front-end credentials by protocol name (see [`RawFrontendCred`]).
    pub frontends: HashMap<String, FrontendCred>,
}

/// Compiled front-end credential for one protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontendCred {
    pub uuid: Option<String>,
    pub password: Option<String>,
}

/// Compiled named egress: a stable id plus its realization.
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

/// Compiled route action.
enum RouteAction {
    Egress(std::sync::Arc<Egress>),
    Direct,
    Block,
}

/// Compiled route: a selector set plus one action. `selector_rules`
/// keeps the original strings for the credential-free MQTT/inspection view.
struct Route {
    selectors: RuleSet,
    selector_rules: Vec<String>,
    action: RouteAction,
}

/// Compiled routing policy: ordered first-match routes plus an
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
    /// Wire-schema version the snapshot declared.
    pub schema_version: u32,
    users: HashMap<String, User>,
    /// Routing policies keyed by policy id.
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
            schema_version: SCHEMA_VERSION,
            users: HashMap::new(),
            policies: HashMap::new(),
            frontend_index: HashMap::new(),
        }
    }

    #[allow(dead_code)] // inspection surface
    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    #[allow(dead_code)] // inspection surface
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Compile a decoded snapshot into the serving form for a specific node.
    /// Invalid upstream kinds, dangling user/policy/egress/chain references, and
    /// unsupported schema versions are rejected so a bad control-plane push
    /// can't silently degrade routing or fail open.
    ///
    /// `node_id` selects this node's slice of `node_overrides`.
    pub fn compile(raw: RawSnapshot, node_id: &str) -> anyhow::Result<Self> {
        Self::compile_with_book(raw, node_id, None)
    }

    /// Like [`Snapshot::compile`], but resolves `book:<category>` rules against
    /// `book`. The compiled rule sets pin that exact book, so a book swap
    /// requires a snapshot recompile — a snapshot is always internally
    /// consistent. `book: None` with `book:` rules present is a hard error
    /// (fail closed).
    pub fn compile_with_book(
        raw: RawSnapshot,
        node_id: &str,
        book: Option<&std::sync::Arc<crate::addrbook::AddrBook>>,
    ) -> anyhow::Result<Self> {
        Self::compile_checked(raw, node_id, book)
    }

    /// Compile a snapshot (routing policies + named egresses).
    ///
    /// `node_id` selects this node's slice of `node_overrides`: each entry
    /// whole-replaces an *existing* base egress of the same id (introducing a
    /// node-only egress is rejected — routing policies stay node-independent).
    /// Dangling user→policy, route→egress and default_egress references, and
    /// invalid egresses/chains all reject the snapshot (fail closed).
    fn compile_checked(
        raw: RawSnapshot,
        node_id: &str,
        book: Option<&std::sync::Arc<crate::addrbook::AddrBook>>,
    ) -> anyhow::Result<Self> {
        let RawSnapshot {
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
            schema_version == SCHEMA_VERSION,
            "routing-policy snapshot requires schema_version {SCHEMA_VERSION} (found {schema_version})"
        );

        if raw_users.len() > MAX_SNAPSHOT_USERS {
            anyhow::bail!(
                "snapshot has too many users: {} > {}",
                raw_users.len(),
                MAX_SNAPSHOT_USERS
            );
        }
        if raw_policies.len() > MAX_SNAPSHOT_POLICIES {
            anyhow::bail!(
                "snapshot has too many routing policies: {} > {}",
                raw_policies.len(),
                MAX_SNAPSHOT_POLICIES
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

        if raw_egresses.len() > MAX_SNAPSHOT_EGRESSES {
            anyhow::bail!(
                "snapshot has too many egresses: {} > {}",
                raw_egresses.len(),
                MAX_SNAPSHOT_EGRESSES
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
            users,
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

    /// Decide how to route `host` for an authenticated user. A first-match
    /// route action wins; otherwise the policy's default egress applies, then
    /// direct.
    pub fn decide(&self, username: &str, host: &str) -> Decision {
        self.decide_with_sniff(username, host, None).decision
    }

    /// Decide against both the proxy-protocol target and a validated sniffed
    /// hostname. Either candidate may block. A sniffed route can select an
    /// egress only when the requested target is an IP; the dial target remains
    /// the requested host and is kept separate by the caller.
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
    pub fn decide_with_sniff(
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
        let Some(policy) = self.policies.get(&user.policy) else {
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
        let routing_policy = self
            .policies
            .get(&user.policy)
            .map(|p| RoutingPolicyView::build(&user.policy, p));
        Some(UserPolicyView {
            username: username.to_string(),
            expire: user.expire.map(|d| d.format("%Y-%m-%d").to_string()),
            policy: user.policy.clone(),
            up_rate: user.up_rate,
            down_rate: user.down_rate,
            max_connections: user.max_connections,
            routing_policy,
        })
    }
}

/// Credential-free view of one identity: its limits and the routing policy it
/// is bound to. Never carries the login password or any egress credential.
#[derive(Debug, Clone, Serialize)]
pub struct UserPolicyView {
    pub username: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire: Option<String>,
    /// Id of the routing policy this identity is bound to.
    pub policy: String,
    pub up_rate: u64,
    pub down_rate: u64,
    pub max_connections: usize,
    /// The resolved policy: ordered routes, per-route action types and
    /// credential-free named-egress realizations. Absent only if the snapshot
    /// no longer holds `policy` (compile-time validation makes that
    /// unreachable for a served snapshot).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_policy: Option<RoutingPolicyView>,
}

/// Credential-free view of a routing policy: its id, ordered routes (each with
/// its selectors, action type and — for an egress action — the credential-free
/// egress realization) and an optional default egress.
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

/// Credential-free view of a named egress: its id and its [`UpstreamView`]
/// realization (a single upstream, or a chain with its member candidates —
/// never passwords or tokens).
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

pub fn upstream_kind_name(kind: UpstreamKind) -> &'static str {
    match kind {
        UpstreamKind::Http => "http",
        UpstreamKind::Socks5 => "socks5",
        UpstreamKind::Reverse => "reverse",
        UpstreamKind::Subnetra => "subnetra",
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

/// Validate and compile one failover chain from its members: non-empty id, at
/// least one member, member count limit, unique member ids/priorities, no
/// nested chain backend, and the per-member upstream validation. Members are
/// returned sorted by ascending priority (the failover try order).
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

/// Compile a named egress. `{"type":"upstream"}` reuses the existing upstream
/// validation (and forbids a `kind:"chain"` backend); `{"type":"chain"}` reuses
/// [`compile_chain`] so a named chain egress has the same structure and runtime
/// semantics wherever it is referenced.
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
/// `policy` is the id of the routing policy the identity is bound to.
#[allow(clippy::too_many_arguments)]
fn compile_user(
    name: &str,
    password: String,
    expire: Option<String>,
    up_rate: u64,
    down_rate: u64,
    max_connections: usize,
    policy: String,
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
        policy,
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

#[cfg(test)]
#[allow(dead_code)]
pub(crate) mod test_support {
    use super::*;

    /// Test-only sugar for building a routing policy.
    ///
    /// The wire model is deliberately normalized (an ordered route list plus a
    /// separate named-egress table), which is verbose to spell out in a test that
    /// only cares about "these hosts take an egress, these are blocked". `PolicySpec`
    /// is the denormalized shorthand; [`PolicySpec::expand`] lowers it into the
    /// real `RawRoutingPolicy` + `RawEgress` pair the compiler consumes.
    ///
    /// Route order is block-first, matching the block-veto semantics of
    /// `Snapshot::decide_with_sniff`.
    #[derive(Debug, Clone, Default)]
    pub(crate) struct PolicySpec {
        /// Backend for hosts matched by `routed`. `None` = no egress route is emitted.
        pub(crate) egress: Option<RawUpstream>,
        /// Backend used when no route matches. `None` = direct.
        pub(crate) default_egress: Option<RawUpstream>,
        /// Selectors routed through `egress`.
        pub(crate) routed: Vec<String>,
        /// Selectors denied outright.
        pub(crate) blocked: Vec<String>,
    }

    impl PolicySpec {
        /// Lower into a routing policy plus the named egresses it references,
        /// using `id` to namespace the generated egress ids.
        pub(crate) fn expand(self, id: &str) -> (RawRoutingPolicy, HashMap<String, RawEgress>) {
            let mut egresses = HashMap::new();
            let mut routes = Vec::new();

            if !self.blocked.is_empty() {
                routes.push(RawRoute {
                    selectors: self.blocked,
                    action: RawAction::Block,
                });
            }
            // A routed selector with no egress would silently vanish from the
            // compiled policy, quietly making the test assert nothing.
            assert!(
                self.egress.is_some() || self.routed.is_empty(),
                "PolicySpec {id:?}: routed selectors require an egress"
            );
            if let Some(backend) = self.egress {
                let egress_id = format!("{id}-egress");
                egresses.insert(egress_id.clone(), RawEgress::Upstream { backend });
                if !self.routed.is_empty() {
                    routes.push(RawRoute {
                        selectors: self.routed,
                        action: RawAction::Egress { egress: egress_id },
                    });
                }
            }
            let default_egress = self.default_egress.map(|backend| {
                let egress_id = format!("{id}-default");
                egresses.insert(egress_id.clone(), RawEgress::Upstream { backend });
                egress_id
            });

            (
                RawRoutingPolicy {
                    routes,
                    default_egress,
                },
                egresses,
            )
        }

        /// Lower into the `routing_policies` / `egresses` tables of a snapshot.
        pub(crate) fn into_tables(
            self,
            id: &str,
        ) -> (
            HashMap<String, RawRoutingPolicy>,
            HashMap<String, RawEgress>,
        ) {
            let (policy, egresses) = self.expand(id);
            (HashMap::from([(id.to_string(), policy)]), egresses)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::PolicySpec;
    use super::*;

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

    fn user_bound_to(policy: &str) -> RawUser {
        RawUser {
            password: "secret".to_string(),
            expire: None,
            up_rate: 0,
            down_rate: 0,
            max_connections: 0,
            policy: policy.to_string(),
            frontends: Default::default(),
        }
    }

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
                policy: "reverse-egress".to_string(),
                frontends: Default::default(),
            },
        );
        let (routing_policies, egresses) = PolicySpec {
            egress: Some(RawUpstream {
                kind: "reverse".to_string(),
                addr: "hop-s604".to_string(),
                username: None,
                password: None,
                tls: false,
                skip_cert_verify: false,
            }),
            default_egress: None,
            routed: vec!["example.com".to_string()],
            blocked: Vec::new(),
        }
        .into_tables("reverse-egress");
        let raw = RawSnapshot {
            version: 1,
            users,
            routing_policies,
            egresses,
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
        let policies = || HashMap::from([("g".to_string(), RawRoutingPolicy::default())]);
        let raw_user = |uuid: &str| RawUser {
            password: "login".to_string(),
            expire: None,
            up_rate: 0,
            down_rate: 0,
            max_connections: 0,
            policy: "g".to_string(),
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
        let snap = Snapshot::compile(
            RawSnapshot {
                version: 1,
                users,
                routing_policies: policies(),
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
        let err = match Snapshot::compile(
            RawSnapshot {
                version: 1,
                users: dup_users,
                routing_policies: policies(),
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
    fn decode_snapshot_accepts_the_wire_format() {
        let raw = decode_snapshot(
            br#"{
                "schema_version": 1,
                "version": 9,
                "users": {
                    "alice": {
                        "password": "secret",
                        "policy": "open",
                        "max_connections": 2
                    }
                },
                "routing_policies": {
                    "open": {
                        "routes": [
                            {
                                "selectors": ["github.com"],
                                "action": {"type": "egress", "egress": "eu"}
                            }
                        ]
                    }
                },
                "egresses": {
                    "eu": {
                        "type": "upstream",
                        "backend": {"kind": "http", "addr": "eu.example.com:8443"}
                    }
                }
            }"#,
        )
        .unwrap();

        assert_eq!(raw.version, 9);
        assert_eq!(raw.schema_version, SCHEMA_VERSION);
        assert_eq!(raw.users["alice"].policy, "open");
        assert_eq!(raw.users["alice"].max_connections, 2);
        assert_eq!(raw.routing_policies["open"].routes.len(), 1);
        assert!(raw.egresses.contains_key("eu"));
    }

    /// A document from a foreign producer must be refused whole. Anything that
    /// is not exactly this schema — a different product's export, a hand-edited
    /// file, a payload carrying fields this build does not implement — is a
    /// decode error, so the caller keeps its previous valid snapshot instead of
    /// serving partially-understood routing intent.
    #[test]
    fn decode_snapshot_rejects_a_foreign_document_shape() {
        for payload in [
            &br#"{"hello":"world"}"#[..],
            // A denormalized group/chain shape: recognisable JSON, but its
            // routing intent lives in fields this schema does not define.
            &br#"{"schema_version":1,"version":1,"users":{},"groups":{}}"#[..],
            // A user carrying routing intent under an undefined key.
            &br#"{"schema_version":1,"version":1,"users":{"a":{"password":"p","group":"g"}}}"#[..],
        ] {
            let err = decode_snapshot(payload).unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("unknown field") || msg.contains("missing field"),
                "error was {msg}"
            );
        }
    }

    /// The schema-version guard is the forward-compatibility seam: a document
    /// produced by a newer control plane is rejected rather than reinterpreted
    /// under this build's field meanings.
    #[test]
    fn decode_snapshot_rejects_an_unsupported_schema_version() {
        let err = decode_snapshot(
            br#"{"schema_version": 99, "version": 1, "users": {}, "routing_policies": {}}"#,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported snapshot schema_version"),
            "error was {err}"
        );
    }

    #[test]
    fn compile_rejects_a_user_bound_to_an_unknown_policy() {
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            RawUser {
                password: "secret".to_string(),
                expire: None,
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                policy: "missing".to_string(),
                frontends: Default::default(),
            },
        );

        let err = Snapshot::compile(
            RawSnapshot {
                version: 1,
                users,
                ..Default::default()
            },
            "node-1",
        )
        .err()
        .expect("a user bound to an unknown policy must be rejected");

        assert!(
            err.to_string().contains("unknown policy"),
            "error was {err}"
        );
    }

    #[test]
    fn compile_rejects_a_user_with_an_empty_policy_id() {
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            RawUser {
                password: "secret".to_string(),
                expire: None,
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                policy: "  ".to_string(),
                frontends: Default::default(),
            },
        );

        let err = Snapshot::compile(
            RawSnapshot {
                version: 1,
                users,
                ..Default::default()
            },
            "node-1",
        )
        .err()
        .expect("a user with an empty policy id must be rejected");

        assert!(
            err.to_string().contains("policy is required"),
            "error was {err}"
        );
    }

    #[test]
    fn compile_rejects_an_empty_policy_id() {
        let (routing_policies, egresses) = PolicySpec {
            egress: None,
            default_egress: None,
            routed: Vec::new(),
            blocked: Vec::new(),
        }
        .into_tables(" ");

        let err = Snapshot::compile(
            RawSnapshot {
                version: 1,
                users: HashMap::new(),
                routing_policies,
                egresses,
                ..Default::default()
            },
            "node-1",
        )
        .err()
        .expect("an empty policy id must be rejected");

        assert!(
            err.to_string().contains("routing policy id is required"),
            "error was {err}"
        );
    }

    #[test]
    fn compile_applies_node_specific_egress_override_for_matching_node_id() {
        let users = HashMap::from([("alice".to_string(), user_bound_to("via-hop"))]);
        let (routing_policies, egresses) = PolicySpec {
            egress: Some(raw_upstream("socks5", "shared-hop.example.com:1080")),
            routed: vec!["example.com".to_string()],
            ..Default::default()
        }
        .into_tables("via-hop");
        let node_overrides = HashMap::from([(
            "edge-tokyo-01".to_string(),
            NodeOverride {
                egresses: HashMap::from([(
                    "via-hop-egress".to_string(),
                    RawEgress::Upstream {
                        backend: raw_upstream("socks5", "127.0.0.1:1080"),
                    },
                )]),
            },
        )]);
        let raw = RawSnapshot {
            version: 1,
            users,
            routing_policies,
            egresses,
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

    /// A node override may only whole-replace an *existing* base egress. If it
    /// could introduce a new id, the same snapshot would mean different things
    /// on different nodes and a typo would silently create a node-local egress
    /// no route references. Fail closed instead.
    #[test]
    fn compile_rejects_a_node_override_that_does_not_replace_a_base_egress() {
        let users = HashMap::from([("alice".to_string(), user_bound_to("via-hop"))]);
        let (routing_policies, egresses) = PolicySpec {
            egress: Some(raw_upstream("socks5", "shared-hop.example.com:1080")),
            routed: vec!["example.com".to_string()],
            ..Default::default()
        }
        .into_tables("via-hop");
        let node_overrides = HashMap::from([(
            "edge-tokyo-01".to_string(),
            NodeOverride {
                egresses: HashMap::from([(
                    "node-only".to_string(),
                    RawEgress::Upstream {
                        backend: raw_upstream("socks5", "127.0.0.1:1080"),
                    },
                )]),
            },
        )]);
        let raw = RawSnapshot {
            version: 1,
            users,
            routing_policies,
            egresses,
            node_overrides,
            ..Default::default()
        };

        // A node that does not carry the override is unaffected.
        Snapshot::compile(raw.clone(), "edge-hk-01").expect("base snapshot compiles");

        let err = Snapshot::compile(raw, "edge-tokyo-01")
            .err()
            .expect("an override introducing a new egress id must be rejected");
        assert!(
            err.to_string()
                .contains("does not replace an existing base egress"),
            "error was {err}"
        );
    }

    #[test]
    fn decide_prefers_a_matched_route_egress_over_the_default_egress() {
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            RawUser {
                password: "secret".to_string(),
                expire: None,
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                policy: "split-exit".to_string(),
                frontends: Default::default(),
            },
        );
        let (routing_policies, egresses) = PolicySpec {
            egress: Some(RawUpstream {
                kind: "socks5".to_string(),
                addr: "special-hop.example.com:1080".to_string(),
                username: None,
                password: None,
                tls: false,
                skip_cert_verify: false,
            }),
            default_egress: Some(RawUpstream {
                kind: "socks5".to_string(),
                addr: "default-hop.example.com:1080".to_string(),
                username: None,
                password: None,
                tls: false,
                skip_cert_verify: false,
            }),
            routed: vec!["special.example.com".to_string()],
            blocked: vec![
                "blocked.example.com".to_string(),
                "203.0.113.0/24".to_string(),
            ],
        }
        .into_tables("split-exit");
        let snap = Snapshot::compile(
            RawSnapshot {
                version: 1,
                users,
                routing_policies,
                egresses,
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
            node_overrides,
            ..Default::default()
        };

        let err = Snapshot::compile(raw, "node-1")
            .err()
            .expect("snapshot with too many node overrides should be rejected");
        assert!(err.to_string().contains("too many node overrides"));
    }

    #[test]
    fn compile_rejects_an_empty_node_override_egress_id() {
        let node_overrides = HashMap::from([(
            "edge-tokyo-01".to_string(),
            NodeOverride {
                egresses: HashMap::from([(
                    " ".to_string(),
                    RawEgress::Upstream {
                        backend: raw_upstream("socks5", "127.0.0.1:1080"),
                    },
                )]),
            },
        )]);
        let raw = RawSnapshot {
            version: 1,
            node_overrides,
            ..Default::default()
        };

        let err = Snapshot::compile(raw, "edge-tokyo-01")
            .err()
            .expect("an empty node override egress id must be rejected");
        assert!(
            err.to_string()
                .contains("node override egress id is required"),
            "error was {err}"
        );
    }

    /// An unknown identity and an identity bound to a policy the snapshot does
    /// not hold must both block. Neither may fall through to direct.
    #[test]
    fn decide_blocks_for_an_unknown_user_or_a_dangling_policy() {
        let snap = Snapshot::empty();
        assert!(matches!(
            snap.decide("missing", "example.com"),
            Decision::Block
        ));

        let snap = Snapshot {
            version: 1,
            schema_version: SCHEMA_VERSION,
            users: HashMap::from([("alice".to_string(), compiled_user("missing"))]),
            policies: HashMap::new(),
            frontend_index: HashMap::new(),
        };

        assert!(matches!(
            snap.decide("alice", "example.com"),
            Decision::Block
        ));
    }

    fn compiled_user(policy: &str) -> User {
        User {
            password: "secret".to_string(),
            expire: None,
            up_rate: 0,
            down_rate: 0,
            max_connections: 0,
            policy: policy.to_string(),
            frontends: Default::default(),
        }
    }

    /// The MQTT user view must name the bound policy and resolve it, and must
    /// still resolve the identity (with no policy data) when the binding is
    /// dangling — `not_found` semantics live one level up, in the MQTT layer.
    #[test]
    fn user_policy_exposes_the_bound_policy_and_tolerates_a_dangling_binding() {
        let snap = Snapshot::compile(
            RawSnapshot {
                version: 1,
                users: HashMap::from([("alice".to_string(), user_bound_to("g1"))]),
                routing_policies: HashMap::from([(
                    "g1".to_string(),
                    RawRoutingPolicy {
                        routes: vec![RawRoute {
                            selectors: vec!["example.com".to_string()],
                            action: RawAction::Egress {
                                egress: "hop".to_string(),
                            },
                        }],
                        default_egress: None,
                    },
                )]),
                egresses: HashMap::from([(
                    "hop".to_string(),
                    RawEgress::Upstream {
                        backend: raw_upstream("socks5", "127.0.0.1:1080"),
                    },
                )]),
                ..Default::default()
            },
            "n",
        )
        .expect("compiles");

        let view = snap.user_policy("alice").expect("user must resolve");
        assert_eq!(view.policy, "g1");
        let policy = view.routing_policy.as_ref().expect("policy must resolve");
        assert_eq!(policy.id, "g1");
        assert_eq!(policy.routes.len(), 1);
        assert_eq!(policy.routes[0].selectors, vec!["example.com".to_string()]);

        let snap = Snapshot {
            version: 1,
            schema_version: SCHEMA_VERSION,
            users: HashMap::from([("bob".to_string(), compiled_user("missing"))]),
            policies: HashMap::new(),
            frontend_index: HashMap::new(),
        };
        let view = snap.user_policy("bob").expect("user must resolve");
        assert_eq!(view.policy, "missing");
        assert!(view.routing_policy.is_none());

        assert!(snap.user_policy("missing").is_none());
    }

    // ---------------------------------------------------------------------
    // Failover chain egresses
    // ---------------------------------------------------------------------

    /// A snapshot whose `rule-a` policy routes `example.com` to the `jp-pop`
    /// chain egress (reverse primary + socks5 backup, deliberately declared out
    /// of priority order so the compile-time sort is actually exercised).
    fn chain_snapshot() -> RawSnapshot {
        RawSnapshot {
            version: 13,
            users: HashMap::from([("alice".to_string(), user_bound_to("rule-a"))]),
            routing_policies: HashMap::from([(
                "rule-a".to_string(),
                RawRoutingPolicy {
                    routes: vec![RawRoute {
                        selectors: vec!["example.com".to_string()],
                        action: RawAction::Egress {
                            egress: "jp-pop".to_string(),
                        },
                    }],
                    default_egress: None,
                },
            )]),
            egresses: HashMap::from([("jp-pop".to_string(), jp_pop_chain())]),
            ..Default::default()
        }
    }

    fn jp_pop_chain() -> RawEgress {
        RawEgress::Chain {
            members: vec![
                chain_member("jp-socks-2", 2, "socks5", "10.2.2.1:1080"),
                chain_member("jp-reverse-1", 1, "reverse", "h1"),
            ],
        }
    }

    /// Mutate the `jp-pop` chain members in place.
    fn with_jp_pop(raw: &mut RawSnapshot, f: impl FnOnce(&mut Vec<RawChainMember>)) {
        let RawEgress::Chain { members } = raw.egresses.get_mut("jp-pop").unwrap() else {
            panic!("jp-pop is not a chain egress");
        };
        f(members);
    }

    #[test]
    fn compile_chain_egress_and_decide_returns_members_in_priority_order() {
        let snap = Snapshot::compile(chain_snapshot(), "edge-tokyo-01").expect("compiles");
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
        // Unmatched targets stay direct: the chain applies only via its route.
        assert!(matches!(
            snap.decide("alice", "other.example.net"),
            Decision::Direct
        ));
    }

    #[test]
    fn compile_supports_a_chain_egress_as_the_policy_default() {
        let mut raw = chain_snapshot();
        let policy = raw.routing_policies.get_mut("rule-a").unwrap();
        policy.routes.clear();
        policy.default_egress = Some("jp-pop".to_string());
        let snap = Snapshot::compile(raw, "n").expect("compiles");
        assert!(matches!(
            snap.decide("alice", "anything.example.net"),
            Decision::ViaChain(_)
        ));
    }

    /// Every dangling egress reference — from a route or from a policy default
    /// — must fail compilation. A snapshot that compiled with a missing egress
    /// would silently downgrade controlled traffic to direct.
    #[test]
    fn compile_rejects_a_dangling_egress_reference() {
        let mut raw = chain_snapshot();
        raw.routing_policies.get_mut("rule-a").unwrap().routes[0].action = RawAction::Egress {
            egress: "no-such".to_string(),
        };
        let err = Snapshot::compile(raw, "n").err().expect("must be rejected");
        assert!(
            err.to_string().contains("references unknown egress"),
            "error was {err}"
        );

        let mut raw = chain_snapshot();
        raw.routing_policies
            .get_mut("rule-a")
            .unwrap()
            .default_egress = Some("no-such".to_string());
        let err = Snapshot::compile(raw, "n").err().expect("must be rejected");
        assert!(
            err.to_string()
                .contains("default_egress references unknown egress"),
            "error was {err}"
        );
    }

    #[test]
    fn compile_rejects_an_empty_chain_and_empty_ids() {
        let mut raw = chain_snapshot();
        raw.egresses
            .insert("empty".to_string(), RawEgress::Chain { members: vec![] });
        let err = Snapshot::compile(raw, "n").err().expect("must be rejected");
        assert!(err.to_string().contains("at least one member"));

        let mut raw = chain_snapshot();
        with_jp_pop(&mut raw, |m| m[0].id = "  ".to_string());
        let err = Snapshot::compile(raw, "n").err().expect("must be rejected");
        assert!(err.to_string().contains("member id is required"));

        let mut raw = chain_snapshot();
        let chain = raw.egresses.remove("jp-pop").unwrap();
        raw.egresses.insert(" ".to_string(), chain);
        let err = Snapshot::compile(raw, "n").err().expect("must be rejected");
        assert!(err.to_string().contains("egress id is required"));
    }

    #[test]
    fn compile_rejects_duplicate_member_ids_and_priorities() {
        let mut raw = chain_snapshot();
        with_jp_pop(&mut raw, |m| m[0].id = "jp-reverse-1".to_string());
        let err = Snapshot::compile(raw, "n").err().expect("must be rejected");
        assert!(err.to_string().contains("duplicate member id"));

        let mut raw = chain_snapshot();
        with_jp_pop(&mut raw, |m| m[0].priority = 1);
        let err = Snapshot::compile(raw, "n").err().expect("must be rejected");
        assert!(err.to_string().contains("duplicate member priority"));
    }

    #[test]
    fn compile_rejects_a_nested_chain_member_and_an_invalid_backend() {
        let mut raw = chain_snapshot();
        with_jp_pop(&mut raw, |m| m[0].backend = raw_upstream("chain", "other"));
        let err = Snapshot::compile(raw, "n").err().expect("must be rejected");
        assert!(err.to_string().contains("must not be another chain"));

        // Member backends reuse the existing upstream validation rules.
        let mut raw = chain_snapshot();
        with_jp_pop(&mut raw, |m| m[1].backend.tls = true); // reverse + tls
        let err = Snapshot::compile(raw, "n").err().expect("must be rejected");
        assert!(err.to_string().contains("must not set tls"));
    }

    /// A chain must be declared as `{"type":"chain"}`, never smuggled in as an
    /// upstream backend with `kind:"chain"` — that shape would bypass the chain
    /// validation entirely.
    #[test]
    fn compile_rejects_a_chain_kind_hidden_in_an_upstream_backend() {
        let mut raw = chain_snapshot();
        raw.egresses.insert(
            "jp-pop".to_string(),
            RawEgress::Upstream {
                backend: raw_upstream("chain", "jp-pop"),
            },
        );
        let err = Snapshot::compile(raw, "n").err().expect("must be rejected");
        assert!(
            err.to_string().contains("must not be a chain"),
            "error was {err}"
        );
    }

    #[test]
    fn compile_rejects_too_many_egresses_and_members() {
        let mut raw = chain_snapshot();
        for i in 0..MAX_SNAPSHOT_EGRESSES {
            raw.egresses.insert(
                format!("bulk-{i}"),
                RawEgress::Upstream {
                    backend: raw_upstream("socks5", "10.0.0.1:1080"),
                },
            );
        }
        let err = Snapshot::compile(raw, "n").err().expect("must be rejected");
        assert!(err.to_string().contains("too many egresses"));

        let mut raw = chain_snapshot();
        with_jp_pop(&mut raw, |m| {
            *m = (0..=MAX_CHAIN_MEMBERS as u32)
                .map(|i| chain_member(&format!("m{i}"), i, "socks5", "10.0.0.1:1080"))
                .collect();
        });
        let err = Snapshot::compile(raw, "n").err().expect("must be rejected");
        assert!(err.to_string().contains("too many members"));
    }

    #[test]
    fn node_override_replaces_a_whole_chain_for_the_matching_node_only() {
        let mut raw = chain_snapshot();
        raw.node_overrides.insert(
            "edge-tokyo-01".to_string(),
            NodeOverride {
                egresses: HashMap::from([(
                    "jp-pop".to_string(),
                    RawEgress::Chain {
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

    /// An override that empties a chain must reject the snapshot rather than
    /// silently keeping the base members — an operator who empties a chain gets
    /// an error, not a stale egress.
    #[test]
    fn node_override_with_an_empty_chain_rejects_the_snapshot() {
        let mut raw = chain_snapshot();
        raw.node_overrides.insert(
            "edge-tokyo-01".to_string(),
            NodeOverride {
                egresses: HashMap::from([(
                    "jp-pop".to_string(),
                    RawEgress::Chain { members: vec![] },
                )]),
            },
        );
        let err = Snapshot::compile(raw, "edge-tokyo-01")
            .err()
            .expect("must be rejected");
        assert!(err.to_string().contains("at least one member"));
    }

    #[test]
    fn snapshot_json_round_trip_preserves_chain_egresses() {
        let raw = chain_snapshot();
        let bytes = serde_json::to_vec(&raw).unwrap();
        let restored = decode_snapshot(&bytes).expect("round-trip decodes");
        assert_eq!(restored.schema_version, SCHEMA_VERSION);
        assert_eq!(restored.version, 13);
        let RawEgress::Chain { members } = &restored.egresses["jp-pop"] else {
            panic!("egress lost its chain shape");
        };
        assert_eq!(members.len(), 2);
        Snapshot::compile(restored, "n").expect("restored snapshot still compiles");
    }

    #[test]
    fn user_policy_view_exposes_a_chain_egress_without_credentials() {
        let mut raw = chain_snapshot();
        with_jp_pop(&mut raw, |m| {
            m[0].backend.username = Some("u".to_string());
            m[0].backend.password = Some("super-secret-pass".to_string());
        });
        let snap = Snapshot::compile(raw, "n").unwrap();
        let view = snap.user_policy("alice").expect("resolves");
        assert_eq!(view.policy, "rule-a");
        let policy = view.routing_policy.as_ref().expect("policy resolved");
        let egress = policy.routes[0].egress.as_ref().expect("egress realized");
        let upstream = &egress.upstream;
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

    fn action_kind(action: Option<&RouteAction>) -> &'static str {
        match action {
            Some(RouteAction::Block) => "block",
            Some(RouteAction::Direct) => "direct",
            Some(RouteAction::Egress(_)) => "egress",
            None => "none",
        }
    }

    fn compile_routes(routes: Vec<RawRoute>) -> Snapshot {
        let mut users = HashMap::new();
        users.insert("alice".to_string(), user_bound_to("edge"));
        let mut policies = HashMap::new();
        policies.insert(
            "edge".to_string(),
            RawRoutingPolicy {
                routes,
                default_egress: None,
            },
        );
        Snapshot::compile(
            RawSnapshot {
                version: 1,
                users,
                routing_policies: policies,
                ..Default::default()
            },
            "node-1",
        )
        .expect("routing snapshot compiles")
    }

    #[test]
    fn first_match_keeps_declaration_order_on_overlap() {
        let snap = compile_routes(vec![
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
    fn indexed_first_match_agrees_with_linear_scan() {
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
        let snap = compile_routes(routes);
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
    fn many_full_routes_miss_stays_sublinear() {
        let mut routes = Vec::new();
        for i in 0..2000 {
            routes.push(RawRoute {
                selectors: vec![format!("full:filler-{i}.example")],
                action: RawAction::Block,
            });
        }
        let snap = compile_routes(routes);
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
