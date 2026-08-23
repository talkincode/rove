//! Control-plane sync: pull a compiled policy snapshot, cache it locally, and
//! hot-swap it into the engine. The same syncer backs periodic polling and
//! explicit MQTT sync commands.

use crate::addrbook::{AddrBook, AddrBookService};
use crate::config::ControlPlane;
use crate::engine::Engine;
use crate::model::{decode_snapshot, RawSnapshot, Snapshot};
use std::fs::OpenOptions;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{info, warn};

const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const MAX_POLL_BACKOFF_SECS: u64 = 300;

#[derive(Debug, Clone)]
pub struct SyncOutcome {
    pub success: bool,
    pub updated: bool,
    pub already_running: bool,
    pub message: String,
    pub version: u64,
    pub elapsed_ms: u128,
}

/// Credential-free control-plane reachability state consumed by `/readyz`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncHealth {
    pub last_attempt_unix_secs: Option<u64>,
    pub last_success_unix_secs: Option<u64>,
    pub failure_since_unix_secs: Option<u64>,
    pub consecutive_failures: u32,
}

#[derive(Clone)]
pub struct Syncer {
    cfg: ControlPlane,
    node_id: String,
    engine: Arc<Engine>,
    client: reqwest::Client,
    gate: Arc<Mutex<()>>,
    health: Arc<StdMutex<SyncHealth>>,
    addrbook: Option<Arc<AddrBookService>>,
    /// Last snapshot document that compiled successfully. Kept (as the decoded
    /// [`RawSnapshot`]) so an addrbook swap can trial-
    /// recompile the exact same policy against the new book.
    last_raw: Arc<StdMutex<Option<RawSnapshot>>>,
}

impl Syncer {
    pub fn new(cfg: ControlPlane, node_id: String, engine: Arc<Engine>) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()?;
        Ok(Syncer {
            cfg,
            node_id,
            engine,
            client,
            gate: Arc::new(Mutex::new(())),
            health: Arc::new(StdMutex::new(SyncHealth::default())),
            addrbook: None,
            last_raw: Arc::new(StdMutex::new(None)),
        })
    }

    /// Attach the addrbook service. Must happen before the first snapshot is
    /// applied so `book:` rules resolve from the start.
    pub fn with_addrbook(mut self, addrbook: Arc<AddrBookService>) -> Self {
        self.addrbook = Some(addrbook);
        self
    }

    fn current_book(&self) -> Option<Arc<AddrBook>> {
        self.addrbook.as_ref().map(|s| s.current())
    }

    /// Atomically adopt a new addrbook: trial-recompile the last applied raw
    /// snapshot against it and only if that succeeds swap book + snapshot
    /// together. On failure nothing changes (the old book keeps serving).
    pub async fn adopt_addrbook(&self, book: Arc<AddrBook>) -> anyhow::Result<()> {
        use anyhow::Context;
        let Some(service) = &self.addrbook else {
            anyhow::bail!("no addrbook service configured");
        };
        let _guard = self.gate.lock().await;
        let raw = self
            .last_raw
            .lock()
            .expect("sync last_raw state poisoned")
            .clone();
        match raw {
            Some(doc) => {
                let version = doc.version;
                let snapshot = Snapshot::compile_with_book(doc, &self.node_id, Some(&book))
                    .context("recompile snapshot against new addrbook")?;
                service.install(book);
                self.engine.replace(snapshot);
                info!(version, "snapshot recompiled against new addrbook");
            }
            None => service.install(book),
        }
        Ok(())
    }

    pub fn version(&self) -> u64 {
        self.engine.version()
    }

    pub fn schema_version(&self) -> u32 {
        self.engine.schema_version()
    }

    pub fn health(&self) -> SyncHealth {
        *self.health.lock().expect("sync health state poisoned")
    }

    pub fn load_cache(&self) -> SyncOutcome {
        let start = Instant::now();
        match load_cache(&self.cfg.cache_path) {
            Ok(Some(raw)) => self.apply(raw, "cache", start),
            Ok(None) => SyncOutcome {
                success: true,
                updated: false,
                already_running: false,
                message: "snapshot cache not found".to_string(),
                version: self.engine.version(),
                elapsed_ms: start.elapsed().as_millis(),
            },
            Err(e) => {
                warn!(error = %e, "load snapshot cache failed");
                SyncOutcome {
                    success: false,
                    updated: false,
                    already_running: false,
                    message: format!("load snapshot cache failed: {e}"),
                    version: self.engine.version(),
                    elapsed_ms: start.elapsed().as_millis(),
                }
            }
        }
    }

    pub async fn run_polling(self: Arc<Self>) {
        let interval = Duration::from_secs(self.cfg.poll_interval_secs.max(1));
        let mut failures = 0u32;
        loop {
            let outcome = self.sync_once("control-plane").await;
            if outcome.success {
                failures = 0;
            } else {
                failures = failures.saturating_add(1);
                warn!(message = %outcome.message, "control-plane sync failed");
            }
            tokio::time::sleep(next_poll_delay(interval, failures)).await;
        }
    }

    pub async fn sync_once(&self, source: &'static str) -> SyncOutcome {
        let _guard = self.gate.lock().await;
        self.sync_once_locked(source).await
    }

    pub async fn try_sync_once(&self, source: &'static str) -> SyncOutcome {
        let Ok(_guard) = self.gate.try_lock() else {
            return SyncOutcome {
                success: false,
                updated: false,
                already_running: true,
                message: "sync already running".to_string(),
                version: self.engine.version(),
                elapsed_ms: 0,
            };
        };
        self.sync_once_locked(source).await
    }

    async fn sync_once_locked(&self, source: &'static str) -> SyncOutcome {
        let start = Instant::now();
        let since = self.engine.version();
        let outcome = match fetch(&self.client, &self.cfg, since).await {
            Ok(Some(raw)) => self.apply_remote(raw, source, start),
            Ok(None) => SyncOutcome {
                success: true,
                updated: false,
                already_running: false,
                message: "no updates are required".to_string(),
                version: self.engine.version(),
                elapsed_ms: start.elapsed().as_millis(),
            },
            Err(e) => SyncOutcome {
                success: false,
                updated: false,
                already_running: false,
                message: format!("control-plane sync failed: {e}"),
                version: self.engine.version(),
                elapsed_ms: start.elapsed().as_millis(),
            },
        };
        self.record_health(&outcome);
        outcome
    }

    fn record_health(&self, outcome: &SyncOutcome) {
        let now = unix_timestamp_secs();
        let mut health = self.health.lock().expect("sync health state poisoned");
        health.last_attempt_unix_secs = Some(now);
        if outcome.success {
            health.last_success_unix_secs = Some(now);
            health.failure_since_unix_secs = None;
            health.consecutive_failures = 0;
        } else {
            health.failure_since_unix_secs.get_or_insert(now);
            health.consecutive_failures = health.consecutive_failures.saturating_add(1);
        }
    }

    fn apply_remote(&self, doc: RawSnapshot, source: &str, start: Instant) -> SyncOutcome {
        let doc_for_cache = doc.clone();
        let book = self.current_book();
        let (snapshot, meta) = match compile_snapshot(
            doc,
            source,
            start,
            self.engine.version(),
            &self.node_id,
            book.as_ref(),
        ) {
            Ok(compiled) => compiled,
            Err(outcome) => return outcome,
        };
        if let Err(e) = save_cache(&self.cfg.cache_path, &doc_for_cache) {
            warn!(error = %e, "persist snapshot cache failed");
        }
        self.remember_raw(doc_for_cache);
        self.replace_snapshot(snapshot, meta, source, start)
    }

    fn apply(&self, doc: RawSnapshot, source: &str, start: Instant) -> SyncOutcome {
        let book = self.current_book();
        let doc_to_remember = doc.clone();
        match compile_snapshot(
            doc,
            source,
            start,
            self.engine.version(),
            &self.node_id,
            book.as_ref(),
        ) {
            Ok((snapshot, meta)) => {
                self.remember_raw(doc_to_remember);
                self.replace_snapshot(snapshot, meta, source, start)
            }
            Err(outcome) => outcome,
        }
    }

    fn remember_raw(&self, doc: RawSnapshot) {
        *self.last_raw.lock().expect("sync last_raw state poisoned") = Some(doc);
    }

    fn replace_snapshot(
        &self,
        snapshot: Snapshot,
        meta: SnapshotMeta,
        source: &str,
        start: Instant,
    ) -> SyncOutcome {
        self.engine.replace(snapshot);
        info!(
            version = meta.version,
            users = meta.users,
            policies = meta.policies,
            source,
            "snapshot applied"
        );
        SyncOutcome {
            success: true,
            updated: true,
            already_running: false,
            message: "snapshot applied".to_string(),
            version: meta.version,
            elapsed_ms: start.elapsed().as_millis(),
        }
    }
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, Copy)]
struct SnapshotMeta {
    version: u64,
    users: usize,
    policies: usize,
}

fn compile_snapshot(
    doc: RawSnapshot,
    source: &str,
    start: Instant,
    current_version: u64,
    node_id: &str,
    book: Option<&Arc<AddrBook>>,
) -> Result<(Snapshot, SnapshotMeta), SyncOutcome> {
    let meta = SnapshotMeta {
        version: doc.version,
        users: doc.users.len(),
        policies: doc.routing_policies.len(),
    };
    match Snapshot::compile_with_book(doc, node_id, book) {
        Ok(snapshot) => Ok((snapshot, meta)),
        Err(e) => {
            warn!(error = %e, source, "compile snapshot failed");
            Err(SyncOutcome {
                success: false,
                updated: false,
                already_running: false,
                message: format!("compile snapshot failed: {e}"),
                version: current_version,
                elapsed_ms: start.elapsed().as_millis(),
            })
        }
    }
}

fn next_poll_delay(base: Duration, consecutive_failures: u32) -> Duration {
    if consecutive_failures == 0 {
        return base;
    }
    let base_secs = base.as_secs().max(1);
    let cap_secs = MAX_POLL_BACKOFF_SECS.max(base_secs);
    let multiplier = 1u64 << consecutive_failures.min(5);
    let secs = base_secs.saturating_mul(multiplier).min(cap_secs);
    Duration::from_secs(secs)
}

/// Fetches the shared snapshot. `cfg.snapshot_url` is used exactly as
/// configured — no path is hardcoded or appended, only a `since` query
/// parameter (added with `&` if the URL already has a query string). There
/// is no per-node URL or per-node response: every node hits the exact same
/// address and gets byte-identical JSON back. Per-node behavior (if any) is
/// resolved locally afterwards via the snapshot's `node_overrides`, keyed by
/// this node's own configured `node_id` — the control plane never needs to
/// know which node is asking.
async fn fetch(
    client: &reqwest::Client,
    cfg: &ControlPlane,
    since: u64,
) -> anyhow::Result<Option<RawSnapshot>> {
    let separator = if cfg.snapshot_url.contains('?') {
        '&'
    } else {
        '?'
    };
    let url = format!("{}{separator}since={since}", cfg.snapshot_url);
    let resp = client.get(&url).bearer_auth(&cfg.token).send().await?;
    if resp.status().as_u16() == 304 {
        return Ok(None);
    }
    if !resp.status().is_success() {
        anyhow::bail!("control-plane returned {}", resp.status());
    }
    let body = read_limited_response(resp, MAX_SNAPSHOT_BYTES).await?;
    let doc = decode_snapshot(&body)?;
    if doc.version <= since {
        return Ok(None);
    }
    Ok(Some(doc))
}

fn load_cache(path: &str) -> anyhow::Result<Option<RawSnapshot>> {
    let path = Path::new(path);
    if !path.exists() {
        return Ok(None);
    }
    let size = std::fs::metadata(path)?.len();
    if size > MAX_SNAPSHOT_BYTES as u64 {
        anyhow::bail!("snapshot cache is too large: {size} > {MAX_SNAPSHOT_BYTES} bytes");
    }
    let bytes = std::fs::read(path)?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        anyhow::bail!(
            "snapshot cache is too large: {} > {} bytes",
            bytes.len(),
            MAX_SNAPSHOT_BYTES
        );
    }
    let doc = decode_snapshot(&bytes)?;
    Ok(Some(doc))
}

async fn read_limited_response(mut resp: reqwest::Response, cap: usize) -> anyhow::Result<Vec<u8>> {
    if let Some(size) = resp.content_length() {
        if size > cap as u64 {
            anyhow::bail!("snapshot response is too large: {size} > {cap} bytes");
        }
    }

    let capacity = resp
        .content_length()
        .and_then(|size| usize::try_from(size).ok())
        .unwrap_or(0)
        .min(cap);
    let mut body = Vec::with_capacity(capacity);
    while let Some(chunk) = resp.chunk().await? {
        if body.len().saturating_add(chunk.len()) > cap {
            anyhow::bail!(
                "snapshot response is too large: {} > {} bytes",
                body.len().saturating_add(chunk.len()),
                cap
            );
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn save_cache(path: &str, doc: &RawSnapshot) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(doc)?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        anyhow::bail!(
            "snapshot cache payload is too large: {} > {} bytes",
            bytes.len(),
            MAX_SNAPSHOT_BYTES
        );
    }
    let path = Path::new(path);
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            std::fs::create_dir_all(dir)?;
        }
    }
    atomic_write_cache(path, &bytes)?;
    Ok(())
}

fn atomic_write_cache(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = temporary_cache_path(path)?;
    let result = write_cache_temp_then_rename(path, &tmp, bytes);
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

fn write_cache_temp_then_rename(path: &Path, tmp: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let mut file = options.open(tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    std::fs::rename(tmp, path)?;
    sync_parent_dir(path);
    Ok(())
}

fn temporary_cache_path(path: &Path) -> anyhow::Result<PathBuf> {
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("snapshot cache path must include a file name"))?
        .to_string_lossy();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    Ok(path.with_file_name(format!("{file_name}.tmp.{}.{nanos}", std::process::id())))
}

fn sync_parent_dir(path: &Path) {
    let Some(dir) = path.parent() else {
        return;
    };
    if dir.as_os_str().is_empty() {
        return;
    }
    if let Ok(dir_file) = OpenOptions::new().read(true).open(dir) {
        let _ = dir_file.sync_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RawSnapshot;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn load_cache_rejects_oversized_file() {
        let path = temp_path("oversized-snapshot.json");
        std::fs::write(&path, vec![b' '; MAX_SNAPSHOT_BYTES + 1]).unwrap();

        let err = load_cache(&path).unwrap_err();
        assert!(err.to_string().contains("snapshot cache is too large"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_cache_accepts_valid_snapshot() {
        let path = temp_path("valid-snapshot.json");
        std::fs::write(
            &path,
            br#"{"schema_version":1,"version":1,"users":{},"routing_policies":{}}"#,
        )
        .unwrap();

        let raw = load_cache(&path).unwrap().unwrap();
        assert_eq!(raw.version, 1);

        let _ = std::fs::remove_file(path);
    }

    /// A cache file written by a foreign producer (here: the pre-rewrite
    /// `userdata.json` shape) must be refused whole rather than decoded into a
    /// snapshot with no routing intent. Silently accepting it would leave the
    /// node serving users with an empty policy table.
    #[test]
    fn load_cache_rejects_a_foreign_document_shape() {
        let path = temp_path("foreign-shape.json");
        std::fs::write(
            &path,
            br#"{
                "timestamp": 5,
                "user_list": [{"username": "alice", "password": "secret"}],
                "routings": []
            }"#,
        )
        .unwrap();

        let err = load_cache(&path).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "error was {err}");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn save_cache_round_trips_valid_snapshot() {
        let path = temp_path("roundtrip-snapshot.json");
        let raw = RawSnapshot {
            version: 2,
            ..Default::default()
        };

        save_cache(&path, &raw).unwrap();
        let loaded = load_cache(&path).unwrap().unwrap();

        assert_eq!(loaded.version, 2);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn save_cache_round_trips_chain_egress_snapshot_with_overrides() {
        use crate::model::{NodeOverride, RawChainMember, RawEgress, RawUpstream};

        let path = temp_path("roundtrip-chain-snapshot.json");
        let member = |id: &str, priority: u32| RawChainMember {
            id: id.to_string(),
            priority,
            backend: RawUpstream {
                kind: "socks5".to_string(),
                addr: "10.2.2.1:1080".to_string(),
                username: None,
                password: None,
                tls: false,
                skip_cert_verify: false,
            },
        };
        let egresses = std::collections::HashMap::from([(
            "jp-pop".to_string(),
            RawEgress::Chain {
                members: vec![member("jp-1", 1), member("jp-2", 2)],
            },
        )]);
        let node_overrides = std::collections::HashMap::from([(
            "edge-tokyo-01".to_string(),
            NodeOverride {
                egresses: std::collections::HashMap::from([(
                    "jp-pop".to_string(),
                    RawEgress::Chain {
                        members: vec![member("local-1", 1)],
                    },
                )]),
            },
        )]);
        let raw = RawSnapshot {
            version: 13,
            egresses,
            node_overrides,
            ..Default::default()
        };

        save_cache(&path, &raw).unwrap();
        let loaded = load_cache(&path).unwrap().unwrap();
        // The cache round-trip must preserve chain members and per-node
        // override chains semantically — a node restarting from cache keeps
        // its failover configuration.
        assert_eq!(loaded.schema_version, crate::model::SCHEMA_VERSION);
        assert_eq!(loaded.version, 13);
        let RawEgress::Chain { members } = &loaded.egresses["jp-pop"] else {
            panic!("base egress lost its chain shape");
        };
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].id, "jp-1");
        let RawEgress::Chain { members } =
            &loaded.node_overrides["edge-tokyo-01"].egresses["jp-pop"]
        else {
            panic!("override egress lost its chain shape");
        };
        assert_eq!(members[0].id, "local-1");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_cache_with_unsupported_schema_keeps_current_snapshot() {
        let path = temp_path("future-schema-snapshot.json");
        std::fs::write(
            &path,
            br#"{"schema_version": 99, "version": 50, "users": {}, "routing_policies": {}}"#,
        )
        .unwrap();

        let engine = crate::engine::Engine::new();
        let syncer = Syncer::new(
            ControlPlane {
                snapshot_url: "http://127.0.0.1:1/snapshot".to_string(),
                token: String::new(),
                poll_interval_secs: 60,
                cache_path: path.clone(),
            },
            "node-test".to_string(),
            engine.clone(),
        )
        .unwrap();

        let outcome = syncer.load_cache();
        // The cache decodes but fails schema validation at compile time: the
        // node reports the failure and keeps serving its current snapshot.
        assert!(!outcome.success);
        assert!(outcome
            .message
            .contains("unsupported snapshot schema_version"));
        assert_eq!(engine.version(), 0);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn save_cache_writes_private_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path("private-snapshot.json");
        let raw = RawSnapshot {
            version: 2,
            ..Default::default()
        };

        save_cache(&path, &raw).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn save_cache_rejects_oversized_payload() {
        let path = temp_path("oversized-save-snapshot.json");
        let mut raw = RawSnapshot {
            version: 3,
            ..Default::default()
        };
        raw.users.insert(
            "alice".to_string(),
            crate::model::RawUser {
                password: "x".repeat(MAX_SNAPSHOT_BYTES + 1),
                expire: None,
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                policy: "open".to_string(),
                frontends: Default::default(),
            },
        );

        let err = save_cache(&path, &raw).unwrap_err();

        assert!(err
            .to_string()
            .contains("snapshot cache payload is too large"));
        assert!(!std::path::Path::new(&path).exists());
    }

    #[test]
    fn load_cache_reports_invalid_snapshot_compile_error() {
        let path = temp_path("invalid-compile-snapshot.json");
        std::fs::write(
            &path,
            br#"{
                "schema_version": 1,
                "version": 4,
                "users": {
                    "alice": {
                        "password": "secret",
                        "expire": null,
                        "up_rate": 0,
                        "down_rate": 0,
                        "max_connections": 0,
                        "policy": "missing"
                    }
                }
            }"#,
        )
        .unwrap();
        let engine = Engine::new();
        let syncer = Syncer::new(
            ControlPlane {
                snapshot_url: "http://127.0.0.1".to_string(),
                token: "token".to_string(),
                poll_interval_secs: 30,
                cache_path: path.clone(),
            },
            "node-1".to_string(),
            engine,
        )
        .unwrap();

        let outcome = syncer.load_cache();

        assert!(!outcome.success);
        assert!(outcome.message.contains("compile snapshot failed"));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn sync_once_applies_remote_snapshot_and_saves_cache() {
        let cache_path = temp_path("remote-cache.json");
        let body = br#"{"schema_version":1,"version":9,"users":{},"routing_policies":{}}"#.to_vec();
        let (snapshot_url, task) =
            start_snapshot_server(200, Some(body), Some("Bearer token")).await;
        let engine = Engine::new();
        let syncer = Syncer::new(
            ControlPlane {
                snapshot_url,
                token: "token".to_string(),
                poll_interval_secs: 30,
                cache_path: cache_path.clone(),
            },
            "node-1".to_string(),
            engine.clone(),
        )
        .unwrap();

        let outcome = syncer.sync_once("test").await;

        assert!(outcome.success);
        assert!(outcome.updated);
        assert_eq!(outcome.version, 9);
        assert_eq!(engine.version(), 9);
        assert!(std::fs::read_to_string(&cache_path)
            .unwrap()
            .contains("\"version\":9"));
        task.await.unwrap();
        let _ = std::fs::remove_file(cache_path);
    }

    #[tokio::test]
    async fn sync_once_applies_a_chain_egress_over_http_and_decides_via_chain() {
        let cache_path = temp_path("remote-chain-cache.json");
        let body = br#"{
            "schema_version": 1,
            "version": 13,
            "users": {"alice": {"password": "pw", "policy": "rule-a"}},
            "routing_policies": {"rule-a": {"routes": [
                {"selectors": ["example.com"], "action": {"type": "egress", "egress": "jp-pop"}}
            ]}},
            "egresses": {"jp-pop": {"type": "chain", "members": [
                {"id": "jp-reverse-1", "priority": 1, "backend": {"kind": "reverse", "addr": "h1"}},
                {"id": "jp-socks-2", "priority": 2, "backend": {"kind": "socks5", "addr": "10.2.2.1:1080"}}
            ]}}
        }"#
        .to_vec();
        let (snapshot_url, task) = start_snapshot_server(200, Some(body), None).await;
        let engine = Engine::new();
        let syncer = Syncer::new(
            ControlPlane {
                snapshot_url,
                token: "token".to_string(),
                poll_interval_secs: 30,
                cache_path: cache_path.clone(),
            },
            "node-1".to_string(),
            engine.clone(),
        )
        .unwrap();

        let outcome = syncer.sync_once("test").await;
        assert!(outcome.success && outcome.updated);
        assert_eq!(engine.version(), 13);
        assert_eq!(engine.schema_version(), crate::model::SCHEMA_VERSION);
        match engine.decide("alice", "example.com") {
            crate::model::Decision::ViaChain(chain) => {
                assert_eq!(chain.id, "jp-pop");
                assert_eq!(chain.members[0].id, "jp-reverse-1");
            }
            other => panic!("expected chain decision, got {other:?}"),
        }
        // The cache written from the HTTP body still carries the chain config.
        let cached = std::fs::read_to_string(&cache_path).unwrap();
        assert!(cached.contains("\"schema_version\":1"));
        assert!(cached.contains("jp-pop"));
        task.await.unwrap();
        let _ = std::fs::remove_file(cache_path);
    }

    #[tokio::test]
    async fn sync_once_applies_a_snapshot_persists_and_reloads_from_cache() {
        let cache_path = temp_path("remote-routing-cache.json");
        let body = br#"{
            "schema_version": 1,
            "version": 21,
            "egresses": {
                "e-a": {"type": "upstream", "backend": {"kind": "socks5", "addr": "10.9.9.9:1080"}}
            },
            "routing_policies": {
                "p": {"routes": [
                    {"selectors": ["blocked.example.com"], "action": {"type": "block"}},
                    {"selectors": ["example.com"], "action": {"type": "egress", "egress": "e-a"}}
                ]}
            },
            "users": {"alice": {"password": "pw", "policy": "p"}}
        }"#
        .to_vec();
        let (snapshot_url, task) = start_snapshot_server(200, Some(body), None).await;
        let engine = Engine::new();
        let syncer = Syncer::new(
            ControlPlane {
                snapshot_url,
                token: "token".to_string(),
                poll_interval_secs: 30,
                cache_path: cache_path.clone(),
            },
            "node-1".to_string(),
            engine.clone(),
        )
        .unwrap();

        // Remote apply: the document compiles, applies, and decides.
        let outcome = syncer.sync_once("test").await;
        assert!(outcome.success && outcome.updated);
        assert_eq!(engine.version(), 21);
        assert_eq!(engine.schema_version(), crate::model::SCHEMA_VERSION);
        match engine.decide("alice", "example.com") {
            crate::model::Decision::Via(up) => assert_eq!(up.addr, "10.9.9.9:1080"),
            other => panic!("expected an egress decision, got {other:?}"),
        }
        assert!(matches!(
            engine.decide("alice", "blocked.example.com"),
            crate::model::Decision::Block
        ));
        task.await.unwrap();

        // The persisted cache preserves the wire shape byte for byte.
        let cached = std::fs::read_to_string(&cache_path).unwrap();
        assert!(cached.contains("\"schema_version\":1"));
        assert!(cached.contains("routing_policies"));
        assert!(cached.contains("e-a"));

        // A fresh node restarting from that cache reloads the snapshot and
        // decides identically — no control plane involved.
        let reload_engine = Engine::new();
        let reload_syncer = Syncer::new(
            ControlPlane {
                snapshot_url: "http://127.0.0.1:1/snapshot".to_string(),
                token: String::new(),
                poll_interval_secs: 60,
                cache_path: cache_path.clone(),
            },
            "node-1".to_string(),
            reload_engine.clone(),
        )
        .unwrap();
        let reload = reload_syncer.load_cache();
        assert!(reload.success && reload.updated);
        assert_eq!(reload_engine.version(), 21);
        assert_eq!(reload_engine.schema_version(), crate::model::SCHEMA_VERSION);
        match reload_engine.decide("alice", "example.com") {
            crate::model::Decision::Via(up) => assert_eq!(up.addr, "10.9.9.9:1080"),
            other => panic!("expected an egress decision after reload, got {other:?}"),
        }

        let _ = std::fs::remove_file(cache_path);
    }

    #[tokio::test]
    async fn sync_once_rejects_missing_egress_refs_without_replacing_snapshot_or_cache() {
        let cache_path = temp_path("invalid-refs-preserve-cache.json");
        // Seed a valid cache and adopt it as the active snapshot.
        std::fs::write(
            &cache_path,
            br#"{"schema_version":1,"version":1,"users":{},"routing_policies":{}}"#,
        )
        .unwrap();
        // A remote whose route references an egress that does not exist:
        // decode succeeds but compile fails closed.
        let body = br#"{
            "schema_version": 1,
            "version": 2,
            "egresses": {},
            "routing_policies": {
                "p": {"routes": [
                    {"selectors": ["example.com"], "action": {"type": "egress", "egress": "ghost"}}
                ]}
            },
            "users": {"alice": {"password": "pw", "policy": "p"}}
        }"#
        .to_vec();
        let (snapshot_url, task) = start_snapshot_server_with_since(200, Some(body), None, 1).await;
        let engine = Engine::new();
        let syncer = Syncer::new(
            ControlPlane {
                snapshot_url,
                token: "token".to_string(),
                poll_interval_secs: 30,
                cache_path: cache_path.clone(),
            },
            "node-1".to_string(),
            engine.clone(),
        )
        .unwrap();

        let cache_outcome = syncer.load_cache();
        assert!(cache_outcome.success);
        assert_eq!(engine.version(), 1);

        let outcome = syncer.sync_once("test").await;

        // Compile fails; the active snapshot and the cache are both untouched.
        assert!(!outcome.success);
        assert!(outcome.message.contains("compile snapshot failed"));
        assert_eq!(engine.version(), 1);
        assert_eq!(engine.schema_version(), crate::model::SCHEMA_VERSION);
        let cached = std::fs::read_to_string(&cache_path).unwrap();
        assert!(cached.contains("\"version\":1"));
        assert!(!cached.contains("ghost"));
        task.await.unwrap();
        let _ = std::fs::remove_file(cache_path);
    }

    #[test]
    fn load_cache_applies_a_cached_snapshot_directly() {
        let path = temp_path("direct-cache.json");
        std::fs::write(
            &path,
            br#"{
                "schema_version": 1,
                "version": 8,
                "egresses": {
                    "e": {"type": "upstream", "backend": {"kind": "http", "addr": "p.example:8443"}}
                },
                "routing_policies": {
                    "p": {"routes": [], "default_action": {"type": "egress", "egress": "e"}}
                },
                "users": {"bob": {"password": "pw", "policy": "p"}}
            }"#,
        )
        .unwrap();
        let engine = Engine::new();
        let syncer = Syncer::new(
            ControlPlane {
                snapshot_url: "http://127.0.0.1:1/snapshot".to_string(),
                token: String::new(),
                poll_interval_secs: 60,
                cache_path: path.clone(),
            },
            "node-1".to_string(),
            engine.clone(),
        )
        .unwrap();

        let outcome = syncer.load_cache();
        assert!(outcome.success && outcome.updated);
        assert_eq!(engine.version(), 8);
        assert_eq!(engine.schema_version(), crate::model::SCHEMA_VERSION);
        // Every host falls back to the policy default egress.
        match engine.decide("bob", "anywhere.example.com") {
            crate::model::Decision::Via(up) => assert_eq!(up.addr, "p.example:8443"),
            other => panic!("expected default egress, got {other:?}"),
        }
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn sync_once_applies_node_specific_override_matching_configured_node_id() {
        let cache_path = temp_path("node-override-cache.json");
        let body = br#"{
            "schema_version": 1,
            "version": 9,
            "users": {
                "alice": {
                    "password": "secret",
                    "expire": null,
                    "up_rate": 0,
                    "down_rate": 0,
                    "max_connections": 0,
                    "policy": "via-hop"
                }
            },
            "routing_policies": {
                "via-hop": {"routes": [
                    {"selectors": ["example.com"], "action": {"type": "egress", "egress": "hop"}}
                ]}
            },
            "egresses": {
                "hop": {"type": "upstream", "backend": {"kind": "socks5", "addr": "shared.example.com:1080"}}
            },
            "node_overrides": {
                "node-1": {
                    "egresses": {
                        "hop": {"type": "upstream", "backend": {"kind": "socks5", "addr": "127.0.0.1:1080"}}
                    }
                },
                "node-2": {
                    "egresses": {
                        "hop": {"type": "upstream", "backend": {"kind": "socks5", "addr": "10.0.0.9:1080"}}
                    }
                }
            }
        }"#
        .to_vec();
        let (snapshot_url, task) =
            start_snapshot_server(200, Some(body), Some("Bearer token")).await;
        let engine = Engine::new();
        let syncer = Syncer::new(
            ControlPlane {
                snapshot_url,
                token: "token".to_string(),
                poll_interval_secs: 30,
                cache_path: cache_path.clone(),
            },
            "node-1".to_string(),
            engine.clone(),
        )
        .unwrap();

        let outcome = syncer.sync_once("test").await;

        assert!(outcome.success);
        assert!(outcome.updated);
        match engine.decide("alice", "example.com") {
            crate::model::Decision::Via(up) => assert_eq!(up.addr, "127.0.0.1:1080"),
            other => panic!("expected node-1 override upstream, got {other:?}"),
        }
        task.await.unwrap();
        let _ = std::fs::remove_file(cache_path);
    }

    #[tokio::test]
    async fn sync_once_rejects_invalid_remote_snapshot_without_overwriting_cache() {
        let cache_path = temp_path("invalid-remote-preserves-cache.json");
        std::fs::write(
            &cache_path,
            br#"{"schema_version":1,"version":1,"users":{},"routing_policies":{}}"#,
        )
        .unwrap();
        let body = br#"{
            "schema_version": 1,
            "version": 2,
            "users": {
                "alice": {
                    "password": "secret",
                    "expire": null,
                    "up_rate": 0,
                    "down_rate": 0,
                    "max_connections": 0,
                    "policy": "missing"
                }
            }
        }"#
        .to_vec();
        let (snapshot_url, task) =
            start_snapshot_server_with_since(200, Some(body), Some("Bearer token"), 1).await;
        let engine = Engine::new();
        let syncer = Syncer::new(
            ControlPlane {
                snapshot_url,
                token: "token".to_string(),
                poll_interval_secs: 30,
                cache_path: cache_path.clone(),
            },
            "node-1".to_string(),
            engine.clone(),
        )
        .unwrap();

        let cache_outcome = syncer.load_cache();
        assert!(cache_outcome.success);
        assert_eq!(engine.version(), 1);

        let outcome = syncer.sync_once("test").await;

        assert!(!outcome.success);
        assert!(outcome.message.contains("compile snapshot failed"));
        assert_eq!(engine.version(), 1);
        let cached = std::fs::read_to_string(&cache_path).unwrap();
        assert!(cached.contains("\"version\":1"));
        assert!(!cached.contains("\"version\":2"));
        task.await.unwrap();
        let _ = std::fs::remove_file(cache_path);
    }

    #[tokio::test]
    async fn sync_once_treats_304_and_stale_versions_as_no_update() {
        let cache_path = temp_path("not-modified-cache.json");
        let (snapshot_url, task) = start_snapshot_server(304, None, Some("Bearer token")).await;
        let engine = Engine::new();
        let syncer = Syncer::new(
            ControlPlane {
                snapshot_url,
                token: "token".to_string(),
                poll_interval_secs: 30,
                cache_path: cache_path.clone(),
            },
            "node-1".to_string(),
            engine.clone(),
        )
        .unwrap();

        let outcome = syncer.sync_once("test").await;

        assert!(outcome.success);
        assert!(!outcome.updated);
        assert_eq!(outcome.message, "no updates are required");
        assert_eq!(engine.version(), 0);
        task.await.unwrap();

        let body = br#"{"schema_version":1,"version":0,"users":{},"routing_policies":{}}"#.to_vec();
        let (snapshot_url, task) =
            start_snapshot_server(200, Some(body), Some("Bearer token")).await;
        let syncer = Syncer::new(
            ControlPlane {
                snapshot_url,
                token: "token".to_string(),
                poll_interval_secs: 30,
                cache_path: cache_path.clone(),
            },
            "node-1".to_string(),
            engine,
        )
        .unwrap();
        let stale = syncer.sync_once("test").await;
        assert!(stale.success);
        assert!(!stale.updated);
        task.await.unwrap();
        let _ = std::fs::remove_file(cache_path);
    }

    #[tokio::test]
    async fn sync_once_reports_http_and_body_errors() {
        let (snapshot_url, task) = start_snapshot_server(500, None, Some("Bearer token")).await;
        let engine = Engine::new();
        let syncer = Syncer::new(
            ControlPlane {
                snapshot_url,
                token: "token".to_string(),
                poll_interval_secs: 30,
                cache_path: temp_path("http-error-cache.json"),
            },
            "node-1".to_string(),
            engine.clone(),
        )
        .unwrap();

        let outcome = syncer.sync_once("test").await;

        assert!(!outcome.success);
        assert!(outcome.message.contains("control-plane returned"));
        task.await.unwrap();

        let (snapshot_url, task) =
            start_snapshot_server(200, Some(b"not json".to_vec()), Some("Bearer token")).await;
        let syncer = Syncer::new(
            ControlPlane {
                snapshot_url,
                token: "token".to_string(),
                poll_interval_secs: 30,
                cache_path: temp_path("bad-json-cache.json"),
            },
            "node-1".to_string(),
            engine,
        )
        .unwrap();
        let bad = syncer.sync_once("test").await;
        assert!(!bad.success);
        assert!(bad.message.contains("control-plane sync failed"));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn sync_once_rejected_token_fails_closed_without_touching_cache() {
        // Control plane rejecting the node token (401/403) must fail the
        // sync, keep serving the previously loaded snapshot, and leave the
        // cache file byte-identical — never degrade into an empty or
        // fallback policy state.
        for status in [401u16, 403] {
            let cache_path = temp_path(&format!("rejected-token-{status}.json"));
            std::fs::write(
                &cache_path,
                br#"{"schema_version":1,"version":1,"users":{},"routing_policies":{}}"#,
            )
            .unwrap();

            let (snapshot_url, task) =
                start_snapshot_server_with_since(status, None, None, 1).await;
            let engine = Engine::new();
            let syncer = Syncer::new(
                ControlPlane {
                    snapshot_url,
                    token: "wrong-token".to_string(),
                    poll_interval_secs: 30,
                    cache_path: cache_path.clone(),
                },
                "node-1".to_string(),
                engine.clone(),
            )
            .unwrap();

            let cache_outcome = syncer.load_cache();
            assert!(cache_outcome.success);
            assert_eq!(engine.version(), 1);
            let cached_before = std::fs::read_to_string(&cache_path).unwrap();

            let outcome = syncer.sync_once("test").await;

            assert!(!outcome.success, "{status} must not report success");
            assert!(!outcome.updated, "{status} must not report an update");
            assert!(
                outcome
                    .message
                    .contains(&format!("control-plane returned {status}")),
                "message must surface the {status} rejection, got: {}",
                outcome.message
            );
            assert_eq!(engine.version(), 1, "snapshot must stay hot-served");
            let cached_after = std::fs::read_to_string(&cache_path).unwrap();
            assert_eq!(cached_before, cached_after, "cache must stay untouched");
            task.await.unwrap();
            let _ = std::fs::remove_file(cache_path);
        }
    }

    #[tokio::test]
    async fn try_sync_once_reports_already_running() {
        let engine = Engine::new();
        let syncer = Syncer::new(
            ControlPlane {
                snapshot_url: "http://127.0.0.1".to_string(),
                token: "token".to_string(),
                poll_interval_secs: 30,
                cache_path: temp_path("gate-cache.json"),
            },
            "node-1".to_string(),
            engine,
        )
        .unwrap();
        let _guard = syncer.gate.lock().await;

        let outcome = syncer.try_sync_once("test").await;

        assert!(!outcome.success);
        assert!(outcome.already_running);
        assert_eq!(outcome.message, "sync already running");
    }

    #[test]
    fn next_poll_delay_uses_base_then_exponential_backoff_with_cap() {
        let base = Duration::from_secs(10);

        assert_eq!(next_poll_delay(base, 0), Duration::from_secs(10));
        assert_eq!(next_poll_delay(base, 1), Duration::from_secs(20));
        assert_eq!(next_poll_delay(base, 2), Duration::from_secs(40));
        assert_eq!(
            next_poll_delay(base, 10),
            Duration::from_secs(MAX_POLL_BACKOFF_SECS)
        );
    }

    fn temp_path(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("rove-{nanos}-{name}"))
            .to_string_lossy()
            .into_owned()
    }

    async fn start_snapshot_server(
        status: u16,
        body: Option<Vec<u8>>,
        expected_auth: Option<&'static str>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        start_snapshot_server_with_since(status, body, expected_auth, 0).await
    }

    async fn start_snapshot_server_with_since(
        status: u16,
        body: Option<Vec<u8>>,
        expected_auth: Option<&'static str>,
        expected_since: u64,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut data = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                data.extend_from_slice(&buf[..n]);
                if data.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&data);
            // Deliberately an arbitrary, non-"/api/v1/..." path: the client
            // must use `snapshot_url` verbatim and never hardcode a path.
            assert!(request.starts_with(&format!(
                "GET /whatever/the/control/plane/wants?since={expected_since} HTTP/1.1"
            )));
            if let Some(expected_auth) = expected_auth {
                assert!(
                    request.contains(&format!("authorization: {expected_auth}"))
                        || request.contains(&format!("Authorization: {expected_auth}"))
                );
            }
            let body = body.unwrap_or_default();
            let reason = match status {
                200 => "OK",
                304 => "Not Modified",
                500 => "Internal Server Error",
                _ => "Status",
            };
            socket
                .write_all(
                    format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            socket.write_all(&body).await.unwrap();
        });
        (
            format!("http://{addr}/whatever/the/control/plane/wants"),
            task,
        )
    }
}
