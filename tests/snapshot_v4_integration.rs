//! Public integration coverage for the schema-v4 routing-policy slice.
//!
//! Everything here drives the crate through its *public* seam only —
//! `decode_snapshot` -> `Snapshot::compile` / `compile_with_book` ->
//! `decide` / `decide_with_sniff`, plus the credential-safe `user_policy`
//! JSON view — exactly the surface the control plane / MQTT layer consume.
//!
//! Fixtures live under `tests/fixtures/snapshot_v4/`. They are deterministic
//! JSON documents, hand-authored to pin one behaviour each.
//!
//! Note on the version guard: the valid v4 fixtures deliberately omit the
//! legacy `group` key on every user (they use `policy`). That means the same
//! bytes would *not* decode as a historical v3 snapshot — the two shapes never
//! silently mix. Tests below assert both directions without touching git.

use rove::addrbook::{AddrBook, BookBuilder};
use rove::model::{
    decode_snapshot, schema_version_supported, Decision, RawSnapshot, Snapshot,
    MAX_SUPPORTED_SCHEMA_VERSION,
};
use std::sync::Arc;

const FIXTURES: &str = "tests/fixtures/snapshot_v4";

fn read_fixture(name: &str) -> Vec<u8> {
    let path = format!("{FIXTURES}/{name}");
    std::fs::read(&path).unwrap_or_else(|e| panic!("fixture {path} must exist: {e}"))
}

/// decode -> compile for `node_id`, expecting success.
fn compile_fixture(name: &str, node_id: &str) -> Snapshot {
    let doc = decode_snapshot(&read_fixture(name))
        .unwrap_or_else(|e| panic!("fixture {name} must decode: {e:?}"));
    Snapshot::compile(doc, node_id).unwrap_or_else(|e| panic!("fixture {name} must compile: {e:?}"))
}

fn compile_main(node_id: &str) -> Snapshot {
    compile_fixture("policies.json", node_id)
}

fn via_addr(decision: &Decision) -> &str {
    match decision {
        Decision::Via(up) => up.addr.as_str(),
        other => panic!("expected Via(..), got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Version guard seam
// ---------------------------------------------------------------------------

#[test]
fn version_guard_seam_rejects_schema4_when_max_is_three() {
    // The testable seam proves a node that still caps support at schema 3
    // refuses a schema-4 document, while the real node (max = 4) accepts it.
    assert!(!schema_version_supported(4, 3));
    assert!(schema_version_supported(4, 4));
    assert!(schema_version_supported(3, 4));
    assert!(!schema_version_supported(5, 4));
    // The crate constant advanced to 4 as part of this slice.
    assert_eq!(MAX_SUPPORTED_SCHEMA_VERSION, 4);
    assert!(schema_version_supported(4, MAX_SUPPORTED_SCHEMA_VERSION));
}

#[test]
fn local_benchmark_snapshot_uses_current_v4_routing_contract() {
    let bytes = std::fs::read("docker/local/snapshot.json")
        .expect("local benchmark snapshot fixture must exist");
    let doc = decode_snapshot(&bytes).expect("local benchmark snapshot must decode");
    assert_eq!(doc.schema_version(), 4);

    let snap = Snapshot::compile(doc, "rove-local")
        .expect("local benchmark snapshot must compile for the benchmark node");
    assert!(matches!(
        snap.decide("bench-direct", "host.docker.internal"),
        Decision::Direct
    ));
    assert_eq!(
        via_addr(&snap.decide("bench-https", "host.docker.internal")),
        "hop-https.local:8443"
    );
    assert_eq!(
        via_addr(&snap.decide("bench-socks5", "host.docker.internal")),
        "hop-socks5:1080"
    );
    assert_eq!(
        via_addr(&snap.decide("bench-socks5tls", "host.docker.internal")),
        "hop-socks5tls.local:1081"
    );
    assert_eq!(
        via_addr(&snap.decide("bench-reverse", "host.docker.internal")),
        "local-reverse-hop"
    );
    assert!(matches!(
        snap.decide("blocked", "host.docker.internal"),
        Decision::Block
    ));
    assert!(matches!(
        snap.decide("bench-chain", "host.docker.internal"),
        Decision::ViaChain(_)
    ));
    assert!(matches!(
        snap.decide("bench-chain-failover", "host.docker.internal"),
        Decision::ViaChain(_)
    ));
}

#[test]
fn valid_v4_fixture_omits_legacy_group_so_v3_shape_would_reject() {
    // The fixture bytes carry `policy`, never `group`: a v4-only shape.
    let bytes = read_fixture("policies.json");
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("\"policy\""), "v4 users use `policy`");
    assert!(
        !text.contains("\"group\""),
        "v4 fixture must not carry the legacy `group` key"
    );
    // The historical decoder expected RawUser.group, so these exact bytes fail
    // before compilation instead of silently becoming a direct legacy policy.
    let legacy_error = serde_json::from_str::<RawSnapshot>(&text)
        .expect_err("the historical v3 wire shape must reject a valid v4 user");
    assert!(
        legacy_error.to_string().contains("group"),
        "unexpected historical-shape error: {legacy_error}"
    );

    // The v4 decoder and compiler accept the same bytes.
    let snap = compile_main("edge-0");
    assert_eq!(snap.schema_version, 4);
}

// ---------------------------------------------------------------------------
// Routing: egress A/B, upstream + chain, direct, block, defaults, order
// ---------------------------------------------------------------------------

#[test]
fn block_route_blocks_host_and_subdomains() {
    let snap = compile_main("edge-0");
    assert!(matches!(
        snap.decide("alice", "block.example.com"),
        Decision::Block
    ));
    assert!(matches!(
        snap.decide("alice", "sub.block.example.com"),
        Decision::Block
    ));
}

#[test]
fn full_selector_matches_exactly_and_routes_to_egress_a() {
    let snap = compile_main("edge-0");
    // Exact host -> egress-a (http upstream).
    assert_eq!(
        via_addr(&snap.decide("alice", "exact.example.com")),
        "proxy-a.example:8443"
    );
    // A different host under the same suffix is NOT matched by `full:` — it
    // falls through to the policy default egress (egress-b, socks5).
    assert_eq!(
        via_addr(&snap.decide("alice", "other.exact.example.com")),
        "proxy-b.example:1080"
    );
}

#[test]
fn keyword_selector_matches_substring_and_routes_to_egress_b() {
    let snap = compile_main("edge-0");
    assert_eq!(
        via_addr(&snap.decide("alice", "api.sockshost.net")),
        "proxy-b.example:1080"
    );
}

#[test]
fn egress_chain_action_yields_via_chain() {
    let snap = compile_main("edge-0");
    match snap.decide("alice", "chain.example.com") {
        Decision::ViaChain(chain) => assert_eq!(chain.members.len(), 2),
        other => panic!("expected ViaChain, got {other:?}"),
    }
}

#[test]
fn direct_action_returns_direct() {
    let snap = compile_main("edge-0");
    assert!(matches!(
        snap.decide("alice", "direct.example.com"),
        Decision::Direct
    ));
}

#[test]
fn ip_cidr_selector_routes_to_egress() {
    let snap = compile_main("edge-0");
    assert_eq!(
        via_addr(&snap.decide("alice", "10.1.2.3")),
        "proxy-a.example:8443"
    );
}

#[test]
fn overlapping_routes_resolve_in_declaration_order() {
    // Two routes select `overlap.example.com`: the first (egress-a) wins over
    // the later block route, proving ordered first-match with legal overlap.
    let snap = compile_main("edge-0");
    assert_eq!(
        via_addr(&snap.decide("alice", "overlap.example.com")),
        "proxy-a.example:8443"
    );
}

#[test]
fn default_egress_applies_when_no_route_matches() {
    let snap = compile_main("edge-0");
    assert_eq!(
        via_addr(&snap.decide("alice", "unmatched.example.org")),
        "proxy-b.example:1080"
    );
}

#[test]
fn policy_without_routes_or_default_is_direct() {
    let snap = compile_main("edge-0");
    // `dana` -> policy-direct-default (empty routes, no default_egress).
    assert!(matches!(
        snap.decide("dana", "anything.example.com"),
        Decision::Direct
    ));
    assert!(matches!(snap.decide("dana", "1.2.3.4"), Decision::Direct));
}

#[test]
fn policy_default_egress_only_covers_unmatched() {
    let snap = compile_main("edge-0");
    // `evan` -> policy-default-egress: a block route plus default egress-a.
    assert!(matches!(
        snap.decide("evan", "denied.example.com"),
        Decision::Block
    ));
    assert_eq!(
        via_addr(&snap.decide("evan", "elsewhere.example.com")),
        "proxy-a.example:8443"
    );
}

#[test]
fn unknown_user_fails_closed_to_block() {
    let snap = compile_main("edge-0");
    assert!(matches!(
        snap.decide("nobody", "example.com"),
        Decision::Block
    ));
}

// ---------------------------------------------------------------------------
// Node-specific egress override
// ---------------------------------------------------------------------------

#[test]
fn node_override_whole_replaces_egress_for_matching_node_only() {
    // The base egress-a points at proxy-a.example:8443 everywhere except on
    // node `edge-1`, where the override whole-replaces it.
    let base = compile_main("edge-0");
    assert_eq!(
        via_addr(&base.decide("alice", "exact.example.com")),
        "proxy-a.example:8443"
    );

    let overridden = compile_main("edge-1");
    assert_eq!(
        via_addr(&overridden.decide("alice", "exact.example.com")),
        "proxy-a-edge1.example:9000"
    );
    // egress-b is untouched by the override on either node.
    assert_eq!(
        via_addr(&overridden.decide("alice", "unmatched.example.org")),
        "proxy-b.example:1080"
    );
}

#[test]
fn node_override_introducing_new_egress_fails_closed() {
    let doc =
        decode_snapshot(&read_fixture("invalid/node_override_new_egress.json")).expect("decodes");
    // On the targeted node the node-only egress has no base to replace.
    let err = Snapshot::compile(doc.clone(), "edge-1").err().unwrap();
    assert!(
        err.to_string()
            .contains("does not replace an existing base egress"),
        "unexpected error: {err}"
    );
    // A node without that override compiles fine (the override is inert).
    Snapshot::compile(doc, "edge-0").expect("other nodes ignore the override");
}

// ---------------------------------------------------------------------------
// Runtime sniff semantics
// ---------------------------------------------------------------------------

#[test]
fn sniffed_block_vetoes_even_when_requested_host_would_route() {
    let snap = compile_main("edge-0");
    // Requested IP would route via egress-a; a sniffed host that blocks vetoes.
    let out = snap.decide_with_sniff("alice", "10.1.2.3", Some("block.example.com"));
    assert!(matches!(out.decision, Decision::Block));
    assert_eq!(out.effective_policy_host, "block.example.com");
}

#[test]
fn requested_block_vetoes_before_sniffed_host() {
    let snap = compile_main("edge-0");
    let out = snap.decide_with_sniff("alice", "block.example.com", Some("chain.example.com"));
    assert!(matches!(out.decision, Decision::Block));
    // Requested host is the vetoing identity.
    assert_eq!(out.effective_policy_host, "block.example.com");
}

#[test]
fn requested_ip_uses_non_block_sniffed_action_first() {
    let snap = compile_main("edge-0");
    // Requested IP matches egress-a; sniffed chain host is more specific and,
    // for an IP target, its non-block action selects instead.
    let out = snap.decide_with_sniff("alice", "10.1.2.3", Some("chain.example.com"));
    match out.decision {
        Decision::ViaChain(chain) => assert_eq!(chain.members.len(), 2),
        other => panic!("expected ViaChain from sniff, got {other:?}"),
    }
    assert_eq!(out.effective_policy_host, "chain.example.com");
}

#[test]
fn requested_ip_with_no_route_falls_back_to_default_egress() {
    let snap = compile_main("edge-0");
    let out = snap.decide_with_sniff("alice", "1.2.3.4", None);
    assert_eq!(via_addr(&out.decision), "proxy-b.example:1080");
    assert_eq!(out.effective_policy_host, "1.2.3.4");
}

#[test]
fn requested_domain_ignores_non_block_sniffed_action() {
    let snap = compile_main("edge-0");
    // Requested domain routes via egress-a; the sniffed chain host is a
    // non-block action and is ignored for a domain target.
    let out = snap.decide_with_sniff("alice", "exact.example.com", Some("chain.example.com"));
    assert_eq!(via_addr(&out.decision), "proxy-a.example:8443");
    assert_eq!(out.effective_policy_host, "exact.example.com");
}

// ---------------------------------------------------------------------------
// Addrbook (`book:`) category selectors
// ---------------------------------------------------------------------------

fn book_with_categories() -> Arc<AddrBook> {
    let mut b = BookBuilder::new(1);
    b.add_rule("blocked", "bad.example").unwrap();
    b.add_rule("viaproxy", "proxy.example").unwrap();
    Arc::new(AddrBook::from_bytes(&b.build_bytes().unwrap()).unwrap())
}

#[test]
fn book_category_route_matches_via_addrbook() {
    let book = book_with_categories();
    let doc = decode_snapshot(&read_fixture("book_policy.json")).expect("decodes");
    let snap = Snapshot::compile_with_book(doc, "edge-0", Some(&book)).expect("compiles with book");

    assert!(matches!(
        snap.decide("frank", "bad.example"),
        Decision::Block
    ));
    assert_eq!(
        via_addr(&snap.decide("frank", "proxy.example")),
        "proxy-a.example:8443"
    );
    // A host in neither category has no route and no default -> direct.
    assert!(matches!(
        snap.decide("frank", "neutral.example"),
        Decision::Direct
    ));
}

#[test]
fn book_route_without_book_fails_closed() {
    let doc = decode_snapshot(&read_fixture("book_policy.json")).expect("decodes");
    let err = Snapshot::compile(doc, "edge-0").err().unwrap();
    assert!(
        err.to_string().contains("addrbook"),
        "unexpected error: {err}"
    );
}

// ---------------------------------------------------------------------------
// Credential-safe MQTT view (`user_policy`)
// ---------------------------------------------------------------------------

#[test]
fn user_policy_view_exposes_v4_routing_without_secrets() {
    let snap = compile_main("edge-0");
    let view = snap.user_policy("alice").expect("alice resolves");

    let routing = view
        .routing_policy
        .as_ref()
        .expect("v4 snapshot exposes routing_policy");
    assert_eq!(routing.id, "policy-main");
    // Ordered routes are preserved with their action type strings.
    assert_eq!(routing.routes[0].action, "block");
    assert_eq!(routing.routes[1].action, "egress");
    assert_eq!(routing.routes[4].action, "direct");
    // The named egress id is surfaced for an egress action.
    let egress_view = routing.routes[1]
        .egress
        .as_ref()
        .expect("egress realization");
    assert_eq!(egress_view.id, "egress-a");
    // The default egress is surfaced too.
    assert_eq!(routing.default_egress.as_ref().unwrap().id, "egress-b");

    // The legacy `policy` / `policies` fields stay present (empty for v4).
    assert!(view.policy.is_none());
    assert!(view.policies.is_empty());

    // Serialization must never leak any credential — login, front-end, or
    // upstream/chain proxy secrets.
    let json = serde_json::to_string(&view).expect("view serializes");
    for secret in [
        "alice-login-secret",
        "alice-tuic-secret",
        "pw-a-secret",
        "pw-b-secret",
        "hop1-secret",
        "up-a",
        "up-b",
        "hop1-user",
    ] {
        assert!(
            !json.contains(secret),
            "credential {secret:?} leaked into user_policy JSON: {json}"
        );
    }
}

#[test]
fn user_policy_view_for_chain_egress_lists_members_without_secrets() {
    let snap = compile_main("edge-0");
    let view = snap.user_policy("alice").expect("alice resolves");
    let routing = view.routing_policy.expect("routing present");
    // Route 3 (index 3) is the chain egress.
    let chain_route = &routing.routes[3];
    assert_eq!(chain_route.action, "egress");
    let egress = chain_route
        .egress
        .as_ref()
        .expect("chain egress realization");
    assert_eq!(egress.id, "chain-x");
    let json = serde_json::to_string(&egress).expect("serializes");
    assert!(
        json.contains("hop1.example:8443"),
        "member addr should be visible"
    );
    assert!(
        !json.contains("hop1-secret"),
        "member password must not leak"
    );
}

// ---------------------------------------------------------------------------
// Legacy v1-v3 compatibility through the same seam
// ---------------------------------------------------------------------------

#[test]
fn legacy_schema2_snapshot_still_decodes_compiles_and_decides() {
    let snap = compile_fixture("legacy_v2_chain.json", "edge-0");
    assert_eq!(snap.schema_version, 2);
    // A proxied host resolves through the group's chain upstream.
    match snap.decide("carol", "proxied.example.com") {
        Decision::ViaChain(chain) => assert_eq!(chain.members.len(), 2),
        other => panic!("expected ViaChain, got {other:?}"),
    }
    assert!(matches!(
        snap.decide("carol", "blocked.example.com"),
        Decision::Block
    ));
    assert!(matches!(
        snap.decide("carol", "neutral.example.com"),
        Decision::Direct
    ));

    // The legacy view still populates `policy`/`policies` and no `routing_policy`.
    let view = snap.user_policy("carol").expect("carol resolves");
    assert!(view.routing_policy.is_none());
    let json = serde_json::to_string(&view).expect("serializes");
    assert!(
        !json.contains("carol-login-secret"),
        "login secret must not leak"
    );
}

// ---------------------------------------------------------------------------
// Strict decode / compile rejections (mixed / unknown / dangling)
// ---------------------------------------------------------------------------

#[test]
fn strict_rejections_fail_closed() {
    // Decode-time rejections (strict wire).
    for name in [
        "invalid/unknown_top_field.json",
        "invalid/user_group.json",
        "invalid/action_mixed.json",
        "invalid/action_unknown.json",
        "invalid/egress_both_variants.json",
        "invalid/schema_mismatch.json",
        "invalid/legacy_user_policy.json",
        "invalid/legacy_node_override_egresses.json",
    ] {
        assert!(
            decode_snapshot(&read_fixture(name)).is_err(),
            "fixture {name} must be rejected at decode"
        );
    }

    // Compile-time rejections (decode ok, semantics fail closed).
    for name in [
        "invalid/egress_chain_backend.json",
        "invalid/missing_policy.json",
        "invalid/missing_egress.json",
        "invalid/dangling_default_egress.json",
    ] {
        let doc = decode_snapshot(&read_fixture(name))
            .unwrap_or_else(|e| panic!("fixture {name} should decode: {e:?}"));
        assert!(
            Snapshot::compile(doc, "edge-0").is_err(),
            "fixture {name} must be rejected at compile"
        );
    }
}
