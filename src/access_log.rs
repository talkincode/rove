//! Structured, JSONL access log for completed proxy connections.
//!
//! This is the direct replacement for grepping GOST's legacy per-connection
//! traffic log: unlike `tracing` debug/info lines (see `inbound::http` and
//! `inbound::socks5`), every connection outcome — success or failure, at
//! every stage — is recorded here as one JSON line, independent of the
//! configured `log.level` and independent of MQTT.
//!
//! Design constraints:
//! - Never blocks the proxy hot path: [`AccessLogger::record`] does a
//!   non-blocking `try_send` and increments a dropped-event counter when the
//!   channel is saturated, mirroring `diagnostics::DiagnosticRegistry::record`.
//! - Never carries secrets: only the same redacted fields already exposed by
//!   [`crate::trace::TraceCandidate`] plus byte counters.
//! - Bounded memory: the channel capacity is fixed at construction.
//! - Rotation is in-process and time-based (daily, via `tracing-appender`);
//!   retention is enforced by deleting rotated files older than
//!   `retention_days`, based on the `YYYY-MM-DD` suffix in the filename (not
//!   file mtime), which keeps it deterministic and easy to test.
//! - Optional forwarding to a remote syslog collector (RFC 3164, UDP or TCP)
//!   happens from the same background writer task; syslog send failures never
//!   affect the local file write or the hot path. The RFC 3164 HOSTNAME field
//!   carries the node id (not the OS hostname), since that is what actually
//!   identifies a source across a fleet of edge nodes.
//! - Alongside per-connection records, the same writer emits a periodic
//!   per-listener stats gauge ([`AccessLogStatsRecord`]): active-connection
//!   count plus cumulative and since-last-tick byte totals. This is the
//!   cheap, bounded-cardinality alternative to a per-connection heartbeat --
//!   the closest match to the old Go Rove's `ObserverEvent` "stats" type
//!   -- and flows through the same file, rotation, retention and syslog
//!   forwarding as connection records, distinguished by `"kind":"stats"`.
//!   The counters themselves live in the shared [`crate::stats::TrafficStats`]
//!   registry (also feeding the SNMP agent), which this writer merely
//!   snapshots; a second `"kind":"egress_stats"` line series mirrors the
//!   egress dimension (`direct` / `upstream:<addr>`).

use crate::config::AccessLogConfig;
use crate::stats::TrafficStats;
use crate::trace::{TraceCandidate, TraceResult};
use chrono::{Local, NaiveDate, TimeZone};
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tracing::warn;

const RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(3600);
/// How often the background writer checks whether `dropped` grew, so a
/// saturated queue shows up as a warning within a minute instead of only
/// being visible through the in-process `dropped_count()` getter.
const DROP_CHECK_INTERVAL: Duration = Duration::from_secs(60);
/// How often the per-listener stats gauge (see module docs) is emitted.
const STATS_INTERVAL: Duration = Duration::from_secs(60);
/// RFC 3164 severity: this is an access log, not an alerting channel, so
/// every line ships as "informational" regardless of connection outcome.
const SYSLOG_SEVERITY_INFORMATIONAL: u8 = 6;
/// Ceiling on a single TCP syslog write. Matches the old Go Rove's
/// `remoteSyslogWriter` default (`3 * time.Second`). Without this, a
/// collector that accepts the TCP connection but stops reading (disk full,
/// overloaded, silently black-holed) would block this task's `write_all`
/// forever -- since the same task also drains the local JSONL file, that
/// would cascade into dropping local access-log records too, not just the
/// syslog forward.
const SYSLOG_TCP_WRITE_TIMEOUT: Duration = Duration::from_secs(3);

/// One JSONL access-log record. Field set mirrors [`TraceCandidate`] plus byte
/// counters; never includes passwords, tokens or upstream credentials.
#[derive(Debug, Clone, Serialize)]
pub struct AccessLogRecord {
    pub timestamp: u64,
    pub node_id: String,
    /// Always `"connection"`. Lets ops `grep`/`jq`-filter this shape apart
    /// from the periodic [`AccessLogStatsRecord`] `"stats"` lines sharing the
    /// same file.
    pub kind: &'static str,
    pub listener: String,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_addr_source: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flow_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniffed_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniff_protocol: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sniff_outcome: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effective_policy_host: Option<String>,
    /// Policy that owned the decision. Absent means routing was never reached
    /// (unknown user, or a user whose policy the snapshot does not define) --
    /// distinct from a policy that deliberately blocked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    /// Zero-based index of the matching route in that policy. Absent means no
    /// route matched and `default_action` decided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_route: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    /// Physical egress when it differs from `decision` (chain decisions): the
    /// winning member's credential-free outlet label, e.g. `reverse:h1`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress: Option<String>,
    /// Winning chain member id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_member: Option<String>,
    /// Chain establishment attempts (present on success and exhaustion).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u32>,
    pub result: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub snapshot_version: u64,
    pub duration_ms: u128,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

impl AccessLogRecord {
    pub fn from_candidate(
        node_id: &str,
        candidate: &TraceCandidate,
        bytes_up: u64,
        bytes_down: u64,
    ) -> Self {
        Self::from_candidate_with_ingress(
            node_id,
            candidate,
            bytes_up,
            bytes_down,
            crate::ingress::metadata::current().as_ref(),
        )
    }

    pub fn from_candidate_with_ingress(
        node_id: &str,
        candidate: &TraceCandidate,
        bytes_up: u64,
        bytes_down: u64,
        ingress: Option<&crate::ingress::metadata::IngressMetadata>,
    ) -> Self {
        let traffic = candidate.traffic.as_ref();
        let sniff = traffic.and_then(|identity| identity.sniff.as_ref());
        AccessLogRecord {
            timestamp: unix_ts(),
            node_id: node_id.to_string(),
            kind: "connection",
            listener: candidate.listener.clone(),
            protocol: candidate.protocol.clone(),
            client_addr: candidate.client_addr.clone(),
            client_addr_source: ingress.map(|_| "reverse_ingress"),
            relay_addr: ingress.map(|value| value.relay_addr.to_string()),
            relay_instance_id: ingress.map(|value| value.relay_instance_id.clone()),
            tunnel_session_id: ingress.map(|value| value.tunnel_session_id.clone()),
            ingress_id: ingress.and_then(|value| value.ingress_id.clone()),
            flow_id: ingress.and_then(|value| value.flow_id.clone()),
            username: candidate.username.clone(),
            target_host: traffic
                .map(|identity| identity.dial_host.clone())
                .or_else(|| candidate.target_host.clone()),
            target_port: traffic
                .map(|identity| identity.dial_port)
                .or(candidate.target_port),
            requested_host: traffic.map(|identity| identity.requested_host.clone()),
            requested_port: traffic.map(|identity| identity.requested_port),
            sniffed_host: sniff.and_then(|observation| observation.host.clone()),
            sniff_protocol: sniff.and_then(|observation| observation.protocol.map(|p| p.as_str())),
            sniff_outcome: sniff.map(|observation| observation.outcome.as_str()),
            effective_policy_host: traffic
                .map(|identity| identity.policy.effective_policy_host.clone()),
            policy_id: traffic.and_then(|identity| identity.policy.policy_id.clone()),
            matched_route: traffic.and_then(|identity| identity.policy.matched_route),
            decision: candidate.decision.clone(),
            egress: candidate.egress.clone(),
            chain_member: candidate.chain_member.clone(),
            attempts: candidate.attempts,
            result: match candidate.result {
                TraceResult::Ok => "ok",
                TraceResult::Error => "error",
            },
            failure_stage: candidate.failure_stage.clone(),
            message: candidate.message.clone(),
            snapshot_version: candidate.snapshot_version,
            duration_ms: candidate.duration_ms,
            bytes_up,
            bytes_down,
        }
    }

    fn to_json_line(&self) -> Vec<u8> {
        let mut line = serde_json::to_vec(self).unwrap_or_else(|_| b"{}".to_vec());
        line.push(b'\n');
        line
    }
}

/// One periodic per-listener gauge line: how many tunnels this listener is
/// handling right now, plus cumulative and since-last-tick byte totals.
/// Emitted every `STATS_INTERVAL` for every listener that has handled at
/// least one connection, independent of per-connection [`AccessLogRecord`]
/// lines -- see the module docs for why this exists instead of a
/// per-connection heartbeat.
#[derive(Debug, Clone, Serialize)]
pub struct AccessLogStatsRecord {
    pub timestamp: u64,
    pub node_id: String,
    /// Always `"stats"`.
    pub kind: &'static str,
    pub listener: String,
    pub active_connections: i64,
    pub bytes_up_total: u64,
    pub bytes_down_total: u64,
    pub bytes_up_delta: u64,
    pub bytes_down_delta: u64,
    pub sniff_matched_total: u64,
    pub sniff_unsupported_total: u64,
    pub sniff_timeout_total: u64,
    pub sniff_malformed_total: u64,
    pub sniff_limit_exceeded_total: u64,
    pub sniff_incomplete_total: u64,
}

impl AccessLogStatsRecord {
    fn to_json_line(&self) -> Vec<u8> {
        let mut line = serde_json::to_vec(self).unwrap_or_else(|_| b"{}".to_vec());
        line.push(b'\n');
        line
    }

    fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// The egress-dimension sibling of [`AccessLogStatsRecord`]: one line per
/// egress key (`"direct"` / `"upstream:<addr>"`) per stats tick, so byte
/// growth can be attributed to where traffic actually left the node. Shares
/// the file/syslog pipeline, distinguished by `"kind":"egress_stats"`.
#[derive(Debug, Clone, Serialize)]
pub struct EgressStatsRecord {
    pub timestamp: u64,
    pub node_id: String,
    /// Always `"egress_stats"`.
    pub kind: &'static str,
    pub egress: String,
    pub active_connections: i64,
    pub bytes_up_total: u64,
    pub bytes_down_total: u64,
    pub bytes_up_delta: u64,
    pub bytes_down_delta: u64,
}

impl EgressStatsRecord {
    fn to_json_line(&self) -> Vec<u8> {
        let mut line = serde_json::to_vec(self).unwrap_or_else(|_| b"{}".to_vec());
        line.push(b'\n');
        line
    }

    fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Advances a per-listener byte-total baseline and returns the delta since
/// the last call. Unlike `dropped_delta_since`, an unchanged (zero) delta is
/// still a meaningful stats-tick result (it confirms the listener is alive
/// and idle), so this always returns a value instead of `Option`.
fn bytes_delta_since(current: u64, last_seen: &mut u64) -> u64 {
    let delta = current.saturating_sub(*last_seen);
    *last_seen = current;
    delta
}

/// Non-blocking hot-path handle. Cheap to clone (wraps an `Arc` internally via
/// the caller holding `Arc<AccessLogger>`); safe to call from every inbound
/// protocol handler. Traffic *counters* live in the shared
/// [`TrafficStats`] registry, updated by the protocol handlers themselves;
/// this type only ships per-connection records to the writer task.
pub struct AccessLogger {
    node_id: String,
    tx: mpsc::Sender<AccessLogRecord>,
    dropped: Arc<AtomicU64>,
}

impl AccessLogger {
    /// Build the logger and spawn its background writer task. Validates the
    /// syslog transport/facility eagerly so a typo in config fails node
    /// startup instead of silently going nowhere at runtime. Must be called
    /// from within a Tokio runtime (spawns a background task). `stats` is
    /// the process-wide counter registry the periodic gauge lines snapshot.
    pub fn spawn(
        cfg: &AccessLogConfig,
        node_id: String,
        stats: Arc<TrafficStats>,
    ) -> anyhow::Result<Arc<AccessLogger>> {
        std::fs::create_dir_all(&cfg.dir)
            .map_err(|e| anyhow::anyhow!("access_log: create dir {:?}: {e}", cfg.dir))?;

        let syslog = if cfg.syslog.enable {
            Some(SyslogSink::new(&cfg.syslog, node_id.clone())?)
        } else {
            None
        };

        let capacity = cfg.channel_capacity.max(1);
        let (tx, rx) = mpsc::channel(capacity);
        let dropped = Arc::new(AtomicU64::new(0));

        let dir = cfg.dir.clone();
        let file_prefix = cfg.file_prefix.clone();
        let retention_days = cfg.retention_days;
        tokio::spawn(run_writer(
            rx,
            syslog,
            WriterConfig {
                dir,
                file_prefix,
                retention_days,
                node_id: node_id.clone(),
                dropped: dropped.clone(),
                stats,
            },
        ));

        Ok(Arc::new(AccessLogger {
            node_id,
            tx,
            dropped,
        }))
    }

    /// Non-blocking hot-path hook: never awaits, drops (and counts) the
    /// record when the writer's channel is saturated.
    pub fn record(&self, candidate: &TraceCandidate, bytes_up: u64, bytes_down: u64) {
        let record =
            AccessLogRecord::from_candidate(&self.node_id, candidate, bytes_up, bytes_down);
        if self.tx.try_send(record).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_with_ingress(
        &self,
        candidate: &TraceCandidate,
        bytes_up: u64,
        bytes_down: u64,
        ingress: Option<&crate::ingress::metadata::IngressMetadata>,
    ) {
        let record = AccessLogRecord::from_candidate_with_ingress(
            &self.node_id,
            candidate,
            bytes_up,
            bytes_down,
            ingress,
        );
        if self.tx.try_send(record).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Test-only constructor that skips the background writer entirely, so
    /// other modules' tests can assert on the records a completed connection
    /// produces without touching the filesystem or a real syslog socket.
    #[doc(hidden)]
    pub fn for_test() -> (Arc<AccessLogger>, mpsc::Receiver<AccessLogRecord>) {
        let (tx, rx) = mpsc::channel(64);
        let logger = Arc::new(AccessLogger {
            node_id: "test-node".to_string(),
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        });
        (logger, rx)
    }
}

/// Bundles `run_writer`'s configuration and shared state so the function
/// itself stays under clippy's argument-count lint; see its individual
/// fields' origins in [`AccessLogger::spawn`].
struct WriterConfig {
    dir: String,
    file_prefix: String,
    retention_days: u32,
    node_id: String,
    dropped: Arc<AtomicU64>,
    stats: Arc<TrafficStats>,
}

async fn run_writer(
    mut rx: mpsc::Receiver<AccessLogRecord>,
    mut syslog: Option<SyslogSink>,
    config: WriterConfig,
) {
    let WriterConfig {
        dir,
        file_prefix,
        retention_days,
        node_id,
        dropped,
        stats,
    } = config;
    let appender = tracing_appender::rolling::daily(&dir, &file_prefix);
    let (mut writer, _guard) = tracing_appender::non_blocking(appender);

    if let Err(e) = sweep_expired_logs(Path::new(&dir), &file_prefix, retention_days, today()) {
        warn!(error = %e, dir = %dir, "access log retention sweep failed");
    }

    let mut retention_tick = tokio::time::interval(RETENTION_SWEEP_INTERVAL);
    retention_tick.tick().await; // first tick fires immediately; already swept above.
    let mut drop_check_tick = tokio::time::interval(DROP_CHECK_INTERVAL);
    drop_check_tick.tick().await; // first tick fires immediately; nothing dropped yet.
    let mut last_dropped = 0u64;
    let mut stats_tick = tokio::time::interval(STATS_INTERVAL);
    stats_tick.tick().await; // first tick fires immediately; nothing to report yet.
    let mut last_bytes: HashMap<String, (u64, u64)> = HashMap::new();
    let mut last_egress_bytes: HashMap<String, (u64, u64)> = HashMap::new();

    loop {
        tokio::select! {
            maybe_record = rx.recv() => {
                let Some(record) = maybe_record else { break };
                if let Err(e) = writer.write_all(&record.to_json_line()) {
                    warn!(error = %e, "access log file write failed");
                }
                if let Some(sink) = syslog.as_mut() {
                    sink.send(&record).await;
                }
            }
            _ = retention_tick.tick() => {
                if let Err(e) = sweep_expired_logs(Path::new(&dir), &file_prefix, retention_days, today()) {
                    warn!(error = %e, dir = %dir, "access log retention sweep failed");
                }
            }
            _ = drop_check_tick.tick() => {
                let current = dropped.load(Ordering::Relaxed);
                if let Some(delta) = dropped_delta_since(current, &mut last_dropped) {
                    warn!(
                        dropped_since_last_check = delta,
                        dropped_total = current,
                        "access log dropped records because the write queue is saturated; consider increasing access_log.channel_capacity"
                    );
                }
            }
            _ = stats_tick.tick() => {
                let (listener_records, egress_records) = build_stats_records(
                    &node_id,
                    &stats,
                    &mut last_bytes,
                    &mut last_egress_bytes,
                );
                for stats_record in listener_records {
                    if let Err(e) = writer.write_all(&stats_record.to_json_line()) {
                        warn!(error = %e, "access log stats write failed");
                    }
                    if let Some(sink) = syslog.as_mut() {
                        sink.send_stats(&stats_record).await;
                    }
                }
                for egress_record in egress_records {
                    if let Err(e) = writer.write_all(&egress_record.to_json_line()) {
                        warn!(error = %e, "access log egress stats write failed");
                    }
                    if let Some(sink) = syslog.as_mut() {
                        sink.send_json(&egress_record.to_json_string()).await;
                    }
                }
            }
        }
    }
}

/// Snapshot the shared counters into one stats tick's worth of gauge lines,
/// advancing the per-name delta baselines. Pure with respect to time-keeping
/// inputs so the delta arithmetic is unit-testable without running the
/// writer loop.
fn build_stats_records(
    node_id: &str,
    stats: &TrafficStats,
    last_bytes: &mut HashMap<String, (u64, u64)>,
    last_egress_bytes: &mut HashMap<String, (u64, u64)>,
) -> (Vec<AccessLogStatsRecord>, Vec<EgressStatsRecord>) {
    let timestamp = unix_ts();
    let sniff_rows: HashMap<String, crate::stats::SniffStatsRow> = stats
        .sniff_rows()
        .into_iter()
        .map(|row| (row.listener.clone(), row))
        .collect();
    let listener_records = stats
        .listener_rows()
        .into_iter()
        .map(|row| {
            let (last_up, last_down) = last_bytes.entry(row.name.clone()).or_insert((0, 0));
            let sniff = sniff_rows.get(&row.name).cloned().unwrap_or_default();
            AccessLogStatsRecord {
                timestamp,
                node_id: node_id.to_string(),
                kind: "stats",
                listener: row.name,
                active_connections: row.active,
                bytes_up_total: row.bytes_up_total,
                bytes_down_total: row.bytes_down_total,
                bytes_up_delta: bytes_delta_since(row.bytes_up_total, last_up),
                bytes_down_delta: bytes_delta_since(row.bytes_down_total, last_down),
                sniff_matched_total: sniff.matched_total,
                sniff_unsupported_total: sniff.unsupported_total,
                sniff_timeout_total: sniff.timeout_total,
                sniff_malformed_total: sniff.malformed_total,
                sniff_limit_exceeded_total: sniff.limit_exceeded_total,
                sniff_incomplete_total: sniff.incomplete_total,
            }
        })
        .collect();
    let egress_records = stats
        .egress_rows()
        .into_iter()
        .map(|row| {
            let (last_up, last_down) = last_egress_bytes.entry(row.name.clone()).or_insert((0, 0));
            EgressStatsRecord {
                timestamp,
                node_id: node_id.to_string(),
                kind: "egress_stats",
                egress: row.name,
                active_connections: row.active,
                bytes_up_total: row.bytes_up_total,
                bytes_down_total: row.bytes_down_total,
                bytes_up_delta: bytes_delta_since(row.bytes_up_total, last_up),
                bytes_down_delta: bytes_delta_since(row.bytes_down_total, last_down),
            }
        })
        .collect();
    (listener_records, egress_records)
}

/// Returns `Some(delta)` and advances `last_seen` when the dropped-record
/// counter has increased since the previous check; `None` when nothing new
/// was dropped. Kept pure so it is unit-testable without a tracing
/// subscriber.
fn dropped_delta_since(current: u64, last_seen: &mut u64) -> Option<u64> {
    if current > *last_seen {
        let delta = current - *last_seen;
        *last_seen = current;
        Some(delta)
    } else {
        None
    }
}

fn today() -> NaiveDate {
    Local::now().date_naive()
}

/// Delete rotated access-log files older than `retention_days`, based on the
/// `{file_prefix}.YYYY-MM-DD` filename produced by daily rotation. Files that
/// don't match the naming convention (including the un-suffixed "current"
/// tracing-appender may briefly hold) are left untouched.
fn sweep_expired_logs(
    dir: &Path,
    file_prefix: &str,
    retention_days: u32,
    today: NaiveDate,
) -> std::io::Result<Vec<PathBuf>> {
    let mut removed = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(removed),
        Err(e) => return Err(e),
    };
    let dot_prefix = format!("{file_prefix}.");
    for entry in entries {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some(date_part) = name.strip_prefix(&dot_prefix) else {
            continue;
        };
        let Ok(file_date) = NaiveDate::parse_from_str(date_part, "%Y-%m-%d") else {
            continue;
        };
        let age_days = (today - file_date).num_days();
        if age_days > retention_days as i64 {
            let path = entry.path();
            if std::fs::remove_file(&path).is_ok() {
                removed.push(path);
            }
        }
    }
    Ok(removed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyslogProtocol {
    Udp,
    Tcp,
}

impl SyslogProtocol {
    fn parse(s: &str) -> anyhow::Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "udp" => Ok(SyslogProtocol::Udp),
            "tcp" => Ok(SyslogProtocol::Tcp),
            other => anyhow::bail!(
                "access_log.syslog.protocol: unsupported {other:?} (expected \"udp\" or \"tcp\")"
            ),
        }
    }
}

fn facility_code(name: &str) -> anyhow::Result<u8> {
    match name.trim().to_ascii_lowercase().as_str() {
        "kern" => Ok(0),
        "user" => Ok(1),
        "mail" => Ok(2),
        "daemon" => Ok(3),
        "auth" => Ok(4),
        "syslog" => Ok(5),
        "lpr" => Ok(6),
        "news" => Ok(7),
        "uucp" => Ok(8),
        "cron" => Ok(9),
        "authpriv" => Ok(10),
        "ftp" => Ok(11),
        "local0" => Ok(16),
        "local1" => Ok(17),
        "local2" => Ok(18),
        "local3" => Ok(19),
        "local4" => Ok(20),
        "local5" => Ok(21),
        "local6" => Ok(22),
        "local7" => Ok(23),
        other => anyhow::bail!("access_log.syslog.facility: unsupported {other:?}"),
    }
}

/// Hand-rolled RFC 3164 forwarder (UDP or TCP), used instead of pulling in a
/// dedicated syslog crate: the wire format is a single formatted line, and
/// implementing it directly keeps the drop-on-failure backpressure policy
/// fully in our control.
struct SyslogSink {
    address: String,
    protocol: SyslogProtocol,
    facility: u8,
    tag: String,
    node_id: String,
    udp: Option<UdpSocket>,
    tcp: Option<TcpStream>,
}

impl SyslogSink {
    fn new(cfg: &crate::config::SyslogConfig, node_id: String) -> anyhow::Result<Self> {
        if cfg.address.trim().is_empty() {
            anyhow::bail!("access_log.syslog.address must be set when syslog is enabled");
        }
        let protocol = SyslogProtocol::parse(&cfg.protocol)?;
        let facility = facility_code(&cfg.facility)?;
        Ok(SyslogSink {
            address: cfg.address.clone(),
            protocol,
            facility,
            tag: cfg.tag.clone(),
            node_id,
            udp: None,
            tcp: None,
        })
    }

    async fn send(&mut self, record: &AccessLogRecord) {
        let body = serde_json::to_string(record).unwrap_or_else(|_| "{}".to_string());
        self.send_json(&body).await;
    }

    async fn send_stats(&mut self, record: &AccessLogStatsRecord) {
        self.send_json(&record.to_json_string()).await;
    }

    async fn send_json(&mut self, body: &str) {
        let line = rfc3164_line(self.facility, &self.node_id, &self.tag, body);
        match self.protocol {
            SyslogProtocol::Udp => self.send_udp(&line).await,
            SyslogProtocol::Tcp => self.send_tcp(&line).await,
        }
    }

    async fn send_udp(&mut self, line: &str) {
        if self.udp.is_none() {
            match UdpSocket::bind("0.0.0.0:0").await {
                Ok(sock) => self.udp = Some(sock),
                Err(e) => {
                    warn!(error = %e, "syslog udp bind failed");
                    return;
                }
            }
        }
        if let Some(sock) = &self.udp {
            if let Err(e) = sock.send_to(line.as_bytes(), &self.address).await {
                warn!(error = %e, address = %self.address, "syslog udp send failed");
            }
        }
    }

    async fn send_tcp(&mut self, line: &str) {
        self.send_tcp_with_timeout(line, SYSLOG_TCP_WRITE_TIMEOUT)
            .await;
    }

    async fn send_tcp_with_timeout(&mut self, line: &str, timeout: Duration) {
        if self.tcp.is_none() {
            match TcpStream::connect(&self.address).await {
                Ok(stream) => self.tcp = Some(stream),
                Err(e) => {
                    warn!(error = %e, address = %self.address, "syslog tcp connect failed");
                    return;
                }
            }
        }
        if let Some(stream) = self.tcp.as_mut() {
            // RFC 6587 octet-counted framing, so the collector can split
            // messages on a stream without relying on trailing newlines.
            let framed = format!("{} {}", line.len(), line);
            match tokio::time::timeout(timeout, stream.write_all(framed.as_bytes())).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    warn!(error = %e, address = %self.address, "syslog tcp send failed");
                    self.tcp = None;
                }
                Err(_) => {
                    warn!(
                        address = %self.address,
                        timeout_secs = timeout.as_secs_f64(),
                        "syslog tcp send timed out; dropping connection so the next record reconnects instead of hanging the writer task"
                    );
                    self.tcp = None;
                }
            }
        }
    }
}

fn rfc3164_priority(facility: u8, severity: u8) -> u8 {
    facility * 8 + severity
}

fn rfc3164_timestamp(unix_secs: u64) -> String {
    Local
        .timestamp_opt(unix_secs as i64, 0)
        .single()
        .unwrap_or_else(Local::now)
        .format("%b %e %T")
        .to_string()
}

fn rfc3164_line(facility: u8, node_id: &str, tag: &str, body: &str) -> String {
    let pri = rfc3164_priority(facility, SYSLOG_SEVERITY_INFORMATIONAL);
    let ts = rfc3164_timestamp(unix_ts());
    format!("<{pri}>{ts} {node_id} {tag}: {body}")
}

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SyslogConfig;
    use tokio::net::TcpListener;

    fn candidate() -> TraceCandidate {
        TraceCandidate {
            listener: "http-in".to_string(),
            protocol: "http".to_string(),
            client_addr: Some("203.0.113.5:51234".to_string()),
            username: Some("alice".to_string()),
            target_host: Some("example.com".to_string()),
            target_port: Some(443),
            traffic: Some(
                crate::trace::TrafficIdentity::new("93.184.216.34", 443).with_observation(
                    crate::sniff::SniffObservation {
                        outcome: crate::sniff::SniffOutcome::Matched,
                        protocol: Some(crate::sniff::SniffProtocol::Tls),
                        host: Some("example.com".to_string()),
                    },
                ),
            ),
            decision: Some("upstream".to_string()),
            egress: None,
            chain_member: None,
            attempts: None,
            result: TraceResult::Ok,
            failure_stage: None,
            message: None,
            snapshot_version: 7,
            duration_ms: 42,
        }
    }

    #[test]
    fn record_from_candidate_carries_bytes_and_never_leaks_secrets() {
        let record = AccessLogRecord::from_candidate("edge-01", &candidate(), 1000, 2000);
        assert_eq!(record.node_id, "edge-01");
        assert_eq!(record.kind, "connection");
        assert_eq!(record.client_addr.as_deref(), Some("203.0.113.5:51234"));
        assert_eq!(record.bytes_up, 1000);
        assert_eq!(record.bytes_down, 2000);
        assert_eq!(record.result, "ok");
        assert_eq!(record.requested_host.as_deref(), Some("93.184.216.34"));
        assert_eq!(record.requested_port, Some(443));
        assert_eq!(record.sniffed_host.as_deref(), Some("example.com"));
        assert_eq!(record.sniff_protocol, Some("tls"));
        assert_eq!(record.sniff_outcome, Some("matched"));
        assert_eq!(
            record.effective_policy_host.as_deref(),
            Some("93.184.216.34")
        );

        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"kind\":\"connection\""));
        assert!(json.contains("\"username\":\"alice\""));
        assert!(json.contains("\"client_addr\":\"203.0.113.5:51234\""));
        assert!(json.contains("\"bytes_up\":1000"));
        assert!(!json.contains("password"));
        assert!(!json.contains("secret"));
        assert!(!json.contains("token"));
    }

    #[test]
    fn reverse_ingress_metadata_is_correlation_safe_and_secret_free() {
        let ingress = crate::ingress::metadata::IngressMetadata {
            relay_instance_id: "relay-hz-1".into(),
            tunnel_session_id: "00112233445566778899aabbccddeeff".into(),
            lease_id: 42,
            listener_id: "https-public".into(),
            ingress_id: Some("ffeeddccbbaa99887766554433221100".into()),
            flow_id: None,
            client_addr: "203.0.113.9:50000".parse().unwrap(),
            relay_addr: "198.51.100.8:9443".parse().unwrap(),
        };
        let record = AccessLogRecord::from_candidate_with_ingress(
            "edge-01",
            &candidate(),
            10,
            20,
            Some(&ingress),
        );

        assert_eq!(record.client_addr_source, Some("reverse_ingress"));
        assert_eq!(record.relay_instance_id.as_deref(), Some("relay-hz-1"));
        assert_eq!(
            record.tunnel_session_id.as_deref(),
            Some("00112233445566778899aabbccddeeff")
        );
        assert_eq!(
            record.ingress_id.as_deref(),
            Some("ffeeddccbbaa99887766554433221100")
        );
        assert_eq!(record.relay_addr.as_deref(), Some("198.51.100.8:9443"));
        let json = String::from_utf8(record.to_json_line()).unwrap();
        assert!(!json.contains("password"));
        assert!(!json.contains("token"));
    }

    #[test]
    fn to_json_line_ends_with_newline_and_is_valid_json() {
        let record = AccessLogRecord::from_candidate("edge-01", &candidate(), 10, 20);
        let line = record.to_json_line();
        assert_eq!(*line.last().unwrap(), b'\n');
        let text = String::from_utf8(line).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(text.trim_end()).unwrap();
        assert_eq!(parsed["node_id"], "edge-01");
    }

    #[test]
    fn dropped_delta_since_reports_increase_once_and_resets_baseline() {
        let mut last = 0u64;
        assert_eq!(dropped_delta_since(0, &mut last), None);
        assert_eq!(dropped_delta_since(3, &mut last), Some(3));
        assert_eq!(dropped_delta_since(3, &mut last), None);
        assert_eq!(dropped_delta_since(10, &mut last), Some(7));
    }

    #[test]
    fn bytes_delta_since_reports_increase_and_resets_baseline() {
        let mut last = 0u64;
        assert_eq!(bytes_delta_since(0, &mut last), 0);
        assert_eq!(bytes_delta_since(100, &mut last), 100);
        assert_eq!(bytes_delta_since(100, &mut last), 0);
        assert_eq!(bytes_delta_since(250, &mut last), 150);
    }

    #[test]
    fn access_log_stats_record_json_uses_kind_stats_and_gauge_fields() {
        let record = AccessLogStatsRecord {
            timestamp: 1_700_000_000,
            node_id: "edge-01".to_string(),
            kind: "stats",
            listener: "http-in".to_string(),
            active_connections: 3,
            bytes_up_total: 5000,
            bytes_down_total: 9000,
            bytes_up_delta: 500,
            bytes_down_delta: 900,
            sniff_matched_total: 12,
            sniff_unsupported_total: 3,
            sniff_timeout_total: 2,
            sniff_malformed_total: 1,
            sniff_limit_exceeded_total: 4,
            sniff_incomplete_total: 5,
        };

        let json = record.to_json_string();
        assert!(json.contains("\"kind\":\"stats\""));
        assert!(json.contains("\"listener\":\"http-in\""));
        assert!(json.contains("\"active_connections\":3"));
        assert!(json.contains("\"bytes_up_total\":5000"));
        assert!(json.contains("\"bytes_down_delta\":900"));
        assert!(json.contains("\"sniff_matched_total\":12"));
        assert!(json.contains("\"sniff_timeout_total\":2"));

        let line = record.to_json_line();
        assert_eq!(*line.last().unwrap(), b'\n');
        let parsed: serde_json::Value =
            serde_json::from_str(String::from_utf8(line).unwrap().trim_end()).unwrap();
        assert_eq!(parsed["kind"], "stats");
    }

    #[test]
    fn build_stats_records_snapshots_both_dimensions_with_deltas() {
        let stats = TrafficStats::new();
        stats.record_listener_bytes("http-in", 100, 200);
        stats.record_sniff("http-in", crate::sniff::SniffOutcome::Matched);
        stats.record_sniff("http-in", crate::sniff::SniffOutcome::Malformed);
        stats.record_egress_bytes("direct", 60, 120);
        stats.record_egress_bytes("upstream:10.0.0.5:1080", 40, 80);
        let _guard = stats.track_listener("http-in");

        let mut last = HashMap::new();
        let mut last_egress = HashMap::new();
        let (listeners, egress) =
            build_stats_records("edge-01", &stats, &mut last, &mut last_egress);

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].kind, "stats");
        assert_eq!(listeners[0].listener, "http-in");
        assert_eq!(listeners[0].active_connections, 1);
        assert_eq!(listeners[0].bytes_up_total, 100);
        assert_eq!(listeners[0].bytes_up_delta, 100);
        assert_eq!(listeners[0].sniff_matched_total, 1);
        assert_eq!(listeners[0].sniff_malformed_total, 1);

        assert_eq!(egress.len(), 2);
        assert_eq!(egress[0].kind, "egress_stats");
        assert_eq!(egress[0].egress, "direct");
        assert_eq!(egress[0].bytes_down_total, 120);
        assert_eq!(egress[1].egress, "upstream:10.0.0.5:1080");

        // Second tick with no new traffic: totals hold, deltas go to zero.
        stats.record_listener_bytes("http-in", 5, 0);
        let (listeners, egress) =
            build_stats_records("edge-01", &stats, &mut last, &mut last_egress);
        assert_eq!(listeners[0].bytes_up_total, 105);
        assert_eq!(listeners[0].bytes_up_delta, 5);
        assert_eq!(listeners[0].bytes_down_delta, 0);
        assert_eq!(egress[0].bytes_up_delta, 0);
    }

    #[test]
    fn egress_stats_record_json_uses_kind_egress_stats() {
        let record = EgressStatsRecord {
            timestamp: 1_700_000_000,
            node_id: "edge-01".to_string(),
            kind: "egress_stats",
            egress: "upstream:10.0.0.5:1080".to_string(),
            active_connections: 2,
            bytes_up_total: 10,
            bytes_down_total: 20,
            bytes_up_delta: 1,
            bytes_down_delta: 2,
        };
        let json = record.to_json_string();
        assert!(json.contains("\"kind\":\"egress_stats\""));
        assert!(json.contains("\"egress\":\"upstream:10.0.0.5:1080\""));
        let line = record.to_json_line();
        assert_eq!(*line.last().unwrap(), b'\n');
    }

    #[tokio::test]
    async fn record_drops_and_counts_when_channel_saturated() {
        let (tx, mut rx) = mpsc::channel(1);
        let logger = AccessLogger {
            node_id: "edge-01".to_string(),
            tx,
            dropped: Arc::new(AtomicU64::new(0)),
        };

        // First record fills the single channel slot; the rest are dropped.
        for _ in 0..5 {
            logger.record(&candidate(), 1, 1);
        }

        assert_eq!(logger.dropped_count(), 4);
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn sweep_removes_files_older_than_retention_and_keeps_recent() {
        let dir = temp_dir_for_test("sweep-basic");
        std::fs::create_dir_all(&dir).unwrap();
        for date in ["2026-06-20", "2026-06-24", "2026-07-01"] {
            std::fs::write(dir.join(format!("access.{date}")), b"{}\n").unwrap();
        }
        // Unrelated file must never be touched.
        std::fs::write(dir.join("other.txt"), b"keep").unwrap();

        let today = NaiveDate::from_ymd_opt(2026, 7, 1).unwrap();
        let removed = sweep_expired_logs(&dir, "access", 7, today).unwrap();

        assert_eq!(removed.len(), 1);
        assert!(!dir.join("access.2026-06-20").exists()); // 11 days old
        assert!(dir.join("access.2026-06-24").exists()); // exactly 7 days old, kept
        assert!(dir.join("access.2026-07-01").exists()); // today
        assert!(dir.join("other.txt").exists());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn sweep_on_missing_directory_is_a_no_op() {
        let dir = temp_dir_for_test("sweep-missing");
        let today = NaiveDate::from_ymd_opt(2026, 7, 1).unwrap();
        let removed = sweep_expired_logs(&dir, "access", 7, today).unwrap();
        assert!(removed.is_empty());
    }

    #[test]
    fn syslog_protocol_parses_case_insensitively_and_rejects_unknown() {
        assert_eq!(SyslogProtocol::parse("UDP").unwrap(), SyslogProtocol::Udp);
        assert_eq!(SyslogProtocol::parse("tcp").unwrap(), SyslogProtocol::Tcp);
        assert!(SyslogProtocol::parse("quic").is_err());
    }

    #[test]
    fn facility_code_maps_known_names_and_rejects_unknown() {
        assert_eq!(facility_code("local0").unwrap(), 16);
        assert_eq!(facility_code("LOCAL7").unwrap(), 23);
        assert_eq!(facility_code("user").unwrap(), 1);
        assert!(facility_code("bogus").is_err());
    }

    #[test]
    fn syslog_sink_new_rejects_empty_address() {
        let cfg = SyslogConfig {
            enable: true,
            address: String::new(),
            protocol: "udp".to_string(),
            facility: "local0".to_string(),
            tag: "rove".to_string(),
        };
        assert!(SyslogSink::new(&cfg, "edge-01".to_string()).is_err());
    }

    #[test]
    fn rfc3164_priority_combines_facility_and_informational_severity() {
        assert_eq!(rfc3164_priority(16, 6), 134); // local0 * 8 + informational
    }

    #[test]
    fn rfc3164_line_contains_pri_hostname_tag_and_body() {
        let line = rfc3164_line(16, "edge-01", "rove", "{\"a\":1}");
        assert!(line.starts_with("<134>"));
        assert!(line.contains(" edge-01 rove: {\"a\":1}"));
    }

    #[tokio::test]
    async fn syslog_sink_sends_udp_line_to_configured_address() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let addr = socket.local_addr().unwrap();

        let cfg = SyslogConfig {
            enable: true,
            address: addr.to_string(),
            protocol: "udp".to_string(),
            facility: "local0".to_string(),
            tag: "rove".to_string(),
        };
        let mut sink = SyslogSink::new(&cfg, "edge-01".to_string()).unwrap();
        sink.send(&AccessLogRecord::from_candidate(
            "edge-01",
            &candidate(),
            10,
            20,
        ))
        .await;

        let mut buf = [0u8; 2048];
        let n = recv_with_retry(&socket, &mut buf).await;
        let received = String::from_utf8_lossy(&buf[..n]);
        assert!(received.starts_with("<134>"));
        assert!(received.contains("edge-01 rove:"));
        assert!(received.contains("\"bytes_up\":10"));
    }

    #[tokio::test]
    async fn syslog_sink_sends_tcp_line_with_octet_count_framing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let cfg = SyslogConfig {
            enable: true,
            address: addr.to_string(),
            protocol: "tcp".to_string(),
            facility: "local0".to_string(),
            tag: "rove".to_string(),
        };
        let mut sink = SyslogSink::new(&cfg, "edge-01".to_string()).unwrap();

        let accept_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            use tokio::io::AsyncReadExt;
            let n = stream.read(&mut buf).await.unwrap();
            buf.truncate(n);
            buf
        });

        sink.send(&AccessLogRecord::from_candidate(
            "edge-01",
            &candidate(),
            10,
            20,
        ))
        .await;

        let received = String::from_utf8_lossy(&accept_task.await.unwrap()).to_string();
        // "<len> <rfc3164 line>" octet-counted framing.
        let (len_str, rest) = received.split_once(' ').unwrap();
        let declared_len: usize = len_str.parse().unwrap();
        assert_eq!(declared_len, rest.len());
        assert!(rest.starts_with("<134>"));
    }

    async fn recv_with_retry(socket: &std::net::UdpSocket, buf: &mut [u8]) -> usize {
        for _ in 0..100 {
            match socket.recv_from(buf) {
                Ok((n, _)) => return n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(e) => panic!("recv failed: {e}"),
            }
        }
        panic!("no udp datagram received after retries");
    }

    #[tokio::test]
    async fn syslog_tcp_send_times_out_on_stalled_peer_instead_of_hanging_forever() {
        // Accept the connection but never read from it, so a big enough
        // write is guaranteed to exceed the kernel receive buffer and block
        // for real -- proving the timeout path actually fires instead of
        // only exercising the happy path.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(stream);
        });

        let cfg = SyslogConfig {
            enable: true,
            address: addr.to_string(),
            protocol: "tcp".to_string(),
            facility: "local0".to_string(),
            tag: "rove".to_string(),
        };
        let mut sink = SyslogSink::new(&cfg, "edge-01".to_string()).unwrap();
        let huge_line = "x".repeat(30_000_000);

        let start = std::time::Instant::now();
        sink.send_tcp_with_timeout(&huge_line, Duration::from_millis(150))
            .await;
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(2),
            "timeout should cut the stalled write short, took {elapsed:?}"
        );
        assert!(
            sink.tcp.is_none(),
            "a timed-out connection must be dropped so the next record reconnects instead of reusing a stuck socket"
        );

        accept_task.abort();
    }

    fn temp_dir_for_test(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!("rove-access-log-{name}-{nanos}"))
    }
}
