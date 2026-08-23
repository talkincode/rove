//! End-to-end coverage for rove-addrbook: the versioned `.rab` address dataset
//! and its `book:<category>` rule integration.
//!
//! Invariants pinned here (see docs/acceptance-matrix.md):
//! * happy path — a `book:` block rule blocks a CONNECT through the real HTTP
//!   proxy path; unselected categories don't leak into the decision;
//! * fail closed — a snapshot referencing an unknown category, or any `book:`
//!   rule with no addrbook configured, rejects the *whole* snapshot;
//! * rollback — a corrupt artifact at reload keeps the previous book serving,
//!   and an addrbook swap that breaks the active snapshot changes nothing;
//! * protocol stability — the checked-in golden vector must be byte-identical
//!   to a fresh deterministic build from the same fixture sources.

use base64::Engine as _;
use rove::addrbook::sources::{apply_manifest, Manifest};
use rove::addrbook::{AddrBook, AddrBookService, BookBuilder};
use rove::config::ControlPlane;
use rove::engine::Engine;
use rove::inbound::{http, Ctx};
use rove::model::{Decision, RawSnapshot, RawUser, Snapshot};
use rove::sync::Syncer;
use rove::util::read_http_head;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

mod common;
use common::PolicySpec;

const USERNAME: &str = "alice";
const PASSWORD: &str = "secret";

/// SHA-256 of the golden artifact. If an encoder change alters this, the
/// change is a format break: regenerate the vector deliberately with
/// `rove-abctl build --manifest tests/fixtures/addrbook/book.toml \
///  --out tests/vectors/addrbook_v1.rab` and document why.
const GOLDEN_SHA256: &str = "da8b261ac9652a1069ad7c88b83d0d0412409de90bc7d33e747e0a7c08a3e24d";

// ---------------------------------------------------------------------------
// Protocol stability: golden vector
// ---------------------------------------------------------------------------

#[test]
fn golden_vector_matches_deterministic_rebuild() {
    let manifest_path = Path::new("tests/fixtures/addrbook/book.toml");
    let (manifest, base) = Manifest::load(manifest_path).expect("fixture manifest loads");
    let mut builder = BookBuilder::new(manifest.epoch);
    apply_manifest(&mut builder, &manifest, &base).expect("fixture sources apply");
    let rebuilt = builder.build_bytes().expect("fixture book builds");

    let golden = std::fs::read("tests/vectors/addrbook_v1.rab").expect("golden vector exists");
    assert_eq!(
        rebuilt, golden,
        "freshly built artifact differs from tests/vectors/addrbook_v1.rab — \
         encoder output changed; treat as a format break"
    );

    let book = AddrBook::from_bytes(&golden).expect("golden vector decodes");
    assert_eq!(book.checksum_hex(), GOLDEN_SHA256);
    assert_eq!(book.build_epoch(), 20260101);
    assert_eq!(book.category_count(), 3);

    // Semantic anchors: hierarchical expansion, all three match kinds, IPs.
    let google = book.resolve(&["google".to_string()]).unwrap();
    assert!(book.matches("sub.doubleclick.net", &google)); // child category
    assert!(book.matches("ads.google.example", &google)); // full: exact
    assert!(book.matches("r1.adservice.test", &google)); // keyword
    assert!(book.matches("8.8.8.253", &google)); // ip4 range
    assert!(book.matches("2001:4860::1", &google)); // ip6 range
    assert!(!book.matches("microsoft.com", &google)); // sibling isolation
}

// ---------------------------------------------------------------------------
// Happy path: book:-rule routing through the real HTTP proxy path
// ---------------------------------------------------------------------------

fn loopback_book() -> Arc<AddrBook> {
    let mut b = BookBuilder::new(1);
    b.add_rule("blocked-nets", "127.0.0.0/8").unwrap();
    b.add_rule("blocked-nets", "bad.example").unwrap();
    b.add_rule("harmless", "203.0.113.0/24").unwrap();
    Arc::new(AddrBook::from_bytes(&b.build_bytes().unwrap()).unwrap())
}

fn snapshot_with_book(policy: PolicySpec, book: &Arc<AddrBook>) -> Snapshot {
    Snapshot::compile_with_book(raw_snapshot(policy), "node-1", Some(book)).expect("snapshot")
}

fn raw_snapshot(policy: PolicySpec) -> RawSnapshot {
    let mut users = HashMap::new();
    users.insert(
        USERNAME.to_string(),
        RawUser {
            password: PASSWORD.to_string(),
            expire: None,
            up_rate: 0,
            down_rate: 0,
            max_connections: 0,
            policy: "default".to_string(),
            frontends: Default::default(),
        },
    );
    let (routing_policies, egresses) = policy.into_tables("default");
    RawSnapshot {
        version: 1,
        users,
        routing_policies,
        egresses,
        ..Default::default()
    }
}

fn spawn_http_proxy(engine: Arc<Engine>) -> (DuplexStream, JoinHandle<anyhow::Result<()>>) {
    let (client, server) = tokio::io::duplex(8192);
    let ctx = Arc::new(Ctx {
        engine,
        listener: "test-http".to_string(),
        sniff: rove::config::SniffConfig::default(),
        tracer: None,
        diagnostics: None,
        access_log: None,
        stats: rove::stats::TrafficStats::new(),
        egress: rove::outbound::EgressContext::default(),
    });
    let peer: SocketAddr = "203.0.113.40:44444".parse().unwrap();
    let task = tokio::spawn(http::serve(server, ctx, peer));
    (client, task)
}

async fn start_echo_server() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        let mut buf = [0u8; 1024];
        while let Ok(n) = socket.read(&mut buf).await {
            if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    });
    (addr, task)
}

async fn connect_via_proxy(client: &mut DuplexStream, target: SocketAddr) -> String {
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{USERNAME}:{PASSWORD}"));
    let request = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic {token}\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    String::from_utf8(read_http_head(client, 8192).await.unwrap()).unwrap()
}

#[tokio::test]
async fn http_connect_to_book_blocked_category_is_rejected() {
    let book = loopback_book();
    let engine = Engine::new();
    engine.replace(snapshot_with_book(
        PolicySpec {
            blocked: vec!["book:blocked-nets".to_string()],
            ..Default::default()
        },
        &book,
    ));

    let (target_addr, _echo) = start_echo_server().await;
    let (mut client, proxy_task) = spawn_http_proxy(engine);
    let head = connect_via_proxy(&mut client, target_addr).await;
    assert!(
        head.starts_with("HTTP/1.1 403"),
        "book:blocked-nets must block loopback CONNECT, got {head:?}"
    );
    drop(client);
    let _ = proxy_task.await;
}

#[tokio::test]
async fn http_connect_passes_when_book_category_not_selected() {
    let book = loopback_book();
    let engine = Engine::new();
    // Only "harmless" (203.0.113.0/24) is selected; loopback must pass and the
    // tunnel must actually move bytes end to end.
    engine.replace(snapshot_with_book(
        PolicySpec {
            blocked: vec!["book:harmless".to_string()],
            ..Default::default()
        },
        &book,
    ));

    let (target_addr, echo_task) = start_echo_server().await;
    let (mut client, proxy_task) = spawn_http_proxy(engine);
    let head = connect_via_proxy(&mut client, target_addr).await;
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "expected tunnel, got {head:?}"
    );

    client.write_all(b"ping-through-book").await.unwrap();
    let mut buf = [0u8; 17];
    client.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping-through-book");

    drop(client);
    let _ = proxy_task.await;
    echo_task.abort();
}

#[test]
fn book_domain_block_applies_to_requested_host() {
    let book = loopback_book();
    let snap = snapshot_with_book(
        PolicySpec {
            blocked: vec!["book:blocked-nets".to_string()],
            ..Default::default()
        },
        &book,
    );
    assert!(matches!(
        snap.decide(USERNAME, "sub.bad.example"),
        Decision::Block
    ));
    assert!(matches!(
        snap.decide(USERNAME, "good.example"),
        Decision::Direct
    ));
}

// ---------------------------------------------------------------------------
// Fail closed: unresolvable book: rules reject the whole snapshot
// ---------------------------------------------------------------------------

#[test]
fn snapshot_with_unknown_book_category_is_rejected() {
    let book = loopback_book();
    let raw = raw_snapshot(PolicySpec {
        blocked: vec!["book:does-not-exist".to_string()],
        ..Default::default()
    });
    let err = Snapshot::compile_with_book(raw, "node-1", Some(&book))
        .err()
        .expect("unknown category must reject the snapshot");
    let msg = format!("{err:#}");
    assert!(msg.contains("does-not-exist"), "{msg}");
}

#[test]
fn snapshot_with_book_rules_but_no_book_is_rejected() {
    let raw = raw_snapshot(PolicySpec {
        blocked: vec!["book:google".to_string()],
        ..Default::default()
    });
    let err = Snapshot::compile(raw, "node-1")
        .err()
        .expect("book: rules without a configured addrbook must fail");
    let msg = format!("{err:#}");
    assert!(msg.contains("no [addrbook]"), "{msg}");
}

// ---------------------------------------------------------------------------
// Rollback: bad artifacts and bad swaps never take down the serving state
// ---------------------------------------------------------------------------

fn temp_path(name: &str) -> std::path::PathBuf {
    let unique = format!(
        "rove-abtest-{}-{}-{name}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    std::env::temp_dir().join(unique)
}

#[test]
fn corrupt_artifact_on_reload_keeps_previous_book() {
    let path = temp_path("book.rab");
    let mut b = BookBuilder::new(7);
    b.add_rule("streaming", "video.example").unwrap();
    std::fs::write(&path, b.build_bytes().unwrap()).unwrap();

    let service = AddrBookService::load(path.to_str().unwrap()).unwrap();
    let before = *service.current().checksum();

    // Corrupt the artifact in place: one flipped byte must fail the checksum.
    let mut bytes = std::fs::read(&path).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&path, &bytes).unwrap();

    let err = service
        .try_read_new()
        .err()
        .expect("corrupt artifact must fail");
    assert!(format!("{err:#}").contains("checksum"), "{err:#}");
    assert_eq!(
        *service.current().checksum(),
        before,
        "previous book must keep serving"
    );

    std::fs::remove_file(&path).unwrap();
    assert!(
        service.changed_stamp().is_err(),
        "a disappeared artifact must be reported, not silently ignored"
    );
}

#[test]
fn startup_with_unloadable_artifact_is_a_hard_error() {
    let path = temp_path("missing.rab");
    assert!(AddrBookService::load(path.to_str().unwrap()).is_err());

    let garbage = temp_path("garbage.rab");
    std::fs::write(&garbage, b"definitely not a rab artifact").unwrap();
    assert!(AddrBookService::load(garbage.to_str().unwrap()).is_err());
    let _ = std::fs::remove_file(&garbage);
}

fn test_syncer(engine: Arc<Engine>, service: Arc<AddrBookService>, cache: &Path) -> Arc<Syncer> {
    Arc::new(
        Syncer::new(
            ControlPlane {
                snapshot_url: "http://127.0.0.1:1/snapshot".to_string(),
                token: String::new(),
                poll_interval_secs: 60,
                cache_path: cache.to_string_lossy().into_owned(),
            },
            "node-1".to_string(),
            engine,
        )
        .unwrap()
        .with_addrbook(service),
    )
}

#[tokio::test]
async fn addrbook_swap_recompiles_snapshot_atomically_and_rejects_bad_books() {
    // v1 book: "streaming" covers old.example.
    let path = temp_path("swap.rab");
    let mut v1 = BookBuilder::new(1);
    v1.add_rule("streaming", "old.example").unwrap();
    std::fs::write(&path, v1.build_bytes().unwrap()).unwrap();
    let service = AddrBookService::load(path.to_str().unwrap()).unwrap();

    // Apply a snapshot whose block rules reference book:streaming, through the
    // syncer cache path so it also records last_raw for later recompiles.
    let engine = Engine::new();
    let cache = temp_path("swap-cache.json");
    let raw = raw_snapshot(PolicySpec {
        blocked: vec!["book:streaming".to_string()],
        ..Default::default()
    });
    std::fs::write(&cache, serde_json::to_vec(&raw).unwrap()).unwrap();
    let syncer = test_syncer(engine.clone(), service.clone(), &cache);
    let outcome = syncer.load_cache();
    assert!(outcome.success, "{}", outcome.message);
    assert!(matches!(
        engine.snapshot().decide(USERNAME, "old.example"),
        Decision::Block
    ));

    // v2 book still has "streaming" but now covering new.example: the adopt
    // must swap book + recompiled snapshot together.
    let mut v2 = BookBuilder::new(2);
    v2.add_rule("streaming", "new.example").unwrap();
    let v2 = Arc::new(AddrBook::from_bytes(&v2.build_bytes().unwrap()).unwrap());
    syncer.adopt_addrbook(v2).await.unwrap();
    let snap = engine.snapshot();
    assert!(matches!(
        snap.decide(USERNAME, "new.example"),
        Decision::Block
    ));
    assert!(matches!(
        snap.decide(USERNAME, "old.example"),
        Decision::Direct
    ));
    assert_eq!(service.current().build_epoch(), 2);

    // v3 book drops the category entirely: adoption must fail and change
    // nothing — neither the serving book nor the snapshot.
    let mut v3 = BookBuilder::new(3);
    v3.add_rule("other", "unrelated.example").unwrap();
    let v3_bytes = v3.build_bytes().unwrap();
    let v3 = Arc::new(AddrBook::from_bytes(&v3_bytes).unwrap());
    std::thread::sleep(std::time::Duration::from_millis(2));
    std::fs::write(&path, &v3_bytes).unwrap();
    let pending_stamp = service
        .changed_stamp()
        .unwrap()
        .expect("new file identity must be pending");
    let err = syncer
        .adopt_addrbook(v3.clone())
        .await
        .expect_err("must reject");
    assert!(format!("{err:#}").contains("streaming"), "{err:#}");
    assert_eq!(service.current().build_epoch(), 2, "book must not swap");
    assert!(matches!(
        engine.snapshot().decide(USERNAME, "new.example"),
        Decision::Block
    ));
    assert_eq!(
        service.changed_stamp().unwrap(),
        Some(pending_stamp),
        "a rejected candidate must remain pending for retry"
    );

    // Once policy no longer references the removed category, the unchanged v3
    // candidate can be retried and acknowledged.
    let compatible = raw_snapshot(PolicySpec::default());
    std::fs::write(&cache, serde_json::to_vec(&compatible).unwrap()).unwrap();
    assert!(syncer.load_cache().success);
    let (retry, retry_stamp) = service.try_read_new().unwrap();
    let retry = retry.expect("rejected candidate remains readable");
    syncer.adopt_addrbook(retry).await.unwrap();
    service.acknowledge_stamp(retry_stamp);
    assert_eq!(service.current().build_epoch(), 3);
    assert_eq!(service.changed_stamp().unwrap(), None);

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&cache);
}
