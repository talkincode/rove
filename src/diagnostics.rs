//! Opt-in, short-lived MQTT diagnostic sessions.
//!
//! Unlike [`crate::trace::ProbeTracer`] (one arm, one matching connection, one
//! result), a diagnostic session stays armed for a bounded TTL and publishes a
//! structured, redacted event for every matching proxy connection, then a
//! summary at expiry or cancellation.
//!
//! Safety boundaries baked into this module:
//! - Sessions only exist after an explicit MQTT command arms them; nothing is
//!   persisted to disk.
//! - The hot proxy path calls [`DiagnosticRegistry::record`] inside a bounded
//!   synchronous critical section. Publication never awaits: events use
//!   `try_send` and are dropped (and counted) when the channel is full.
//! - Events only ever carry non-secret fields already surfaced by probe tracing
//!   (username identity, target host/port, routing decision, failure stage and a
//!   static message). Passwords, tokens and upstream credentials never enter here.

use crate::trace::{TraceCandidate, TraceResult};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

/// Bounded diagnostic event categories. `summary` is a session-lifecycle marker;
/// the rest map to the stage where a connection attempt concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticEventType {
    Auth,
    Policy,
    Limit,
    Outbound,
    Splice,
    Summary,
}

impl DiagnosticEventType {
    /// Per-connection event types (everything except the lifecycle `summary`).
    pub const PER_CONNECTION: [DiagnosticEventType; 5] = [
        DiagnosticEventType::Auth,
        DiagnosticEventType::Policy,
        DiagnosticEventType::Limit,
        DiagnosticEventType::Outbound,
        DiagnosticEventType::Splice,
    ];

    /// Parse a filter token from an arm request. Unknown tokens return `None`.
    pub fn from_token(token: &str) -> Option<DiagnosticEventType> {
        match token.trim().to_ascii_lowercase().as_str() {
            "auth" => Some(DiagnosticEventType::Auth),
            "policy" => Some(DiagnosticEventType::Policy),
            "limit" => Some(DiagnosticEventType::Limit),
            "outbound" => Some(DiagnosticEventType::Outbound),
            "splice" => Some(DiagnosticEventType::Splice),
            "summary" => Some(DiagnosticEventType::Summary),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            DiagnosticEventType::Auth => "auth",
            DiagnosticEventType::Policy => "policy",
            DiagnosticEventType::Limit => "limit",
            DiagnosticEventType::Outbound => "outbound",
            DiagnosticEventType::Splice => "splice",
            DiagnosticEventType::Summary => "summary",
        }
    }

    /// Classify a completed connection attempt. Protocol `parse` failures (and any
    /// unrecognised stage) are intentionally not diagnostic events: they predate
    /// user identity and stay the domain of one-shot probe tracing.
    fn from_candidate(candidate: &TraceCandidate) -> Option<DiagnosticEventType> {
        match candidate.failure_stage.as_deref() {
            Some("auth") => Some(DiagnosticEventType::Auth),
            Some("policy") => Some(DiagnosticEventType::Policy),
            Some("limit") => Some(DiagnosticEventType::Limit),
            Some(
                "outbound" | "dns" | "dial" | "tls" | "chain_exhausted" | "reverse_lookup"
                | "reverse_open" | "hop_connect",
            ) => Some(DiagnosticEventType::Outbound),
            Some("splice" | "stream_io") => Some(DiagnosticEventType::Splice),
            Some(_) => None,
            // A fully successful tunnel reaches the splice stage with no failure.
            None => match candidate.result {
                TraceResult::Ok => Some(DiagnosticEventType::Splice),
                TraceResult::Error => None,
            },
        }
    }
}

/// Operational bounds for diagnostic sessions.
#[derive(Debug, Clone, Copy)]
pub struct DiagnosticLimits {
    pub default_ttl: Duration,
    pub max_ttl: Duration,
    pub max_sessions: usize,
    pub max_sessions_per_user: usize,
}

impl DiagnosticLimits {
    /// Clamp a requested TTL (seconds) into `[1, max_ttl]`, falling back to the
    /// configured default when the request omits it.
    pub fn clamp_ttl(&self, requested_secs: Option<u64>) -> Duration {
        let max = self.max_ttl.as_secs().max(1);
        match requested_secs {
            Some(secs) => Duration::from_secs(secs.clamp(1, max)),
            None => {
                let default = self.default_ttl.as_secs().clamp(1, max);
                Duration::from_secs(default)
            }
        }
    }
}

/// A validated request to arm a diagnostic session. `username` is mandatory; the
/// remaining filters are optional additional scoping.
#[derive(Debug, Clone)]
pub struct DiagnosticSessionSpec {
    pub request_id: String,
    pub reply_topic: String,
    pub username: String,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub protocol: Option<String>,
    pub listener: Option<String>,
    /// Per-connection event types to publish. Callers resolve defaults before
    /// arming; only the types listed here stream (the lifecycle `summary` is
    /// always published regardless).
    pub event_types: HashSet<DiagnosticEventType>,
    pub ttl: Duration,
}

/// Why an arm request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartRejection {
    GlobalLimit,
    UserLimit,
}

impl StartRejection {
    pub fn message(self) -> &'static str {
        match self {
            StartRejection::GlobalLimit => "diagnostic session limit reached for this node",
            StartRejection::UserLimit => "diagnostic session limit reached for this user",
        }
    }
}

/// Outcome of arming a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartAccepted {
    pub ttl_secs: u64,
    /// Effective per-connection event types (sorted for deterministic replies).
    pub event_types: Vec<DiagnosticEventType>,
}

/// A published per-connection diagnostic event. Only redacted fields appear here.
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticEvent {
    pub request_id: String,
    pub node_id: String,
    pub event: &'static str,
    pub event_type: DiagnosticEventType,
    pub status: &'static str,
    pub listener: String,
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_member: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempts: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_stage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub snapshot_version: u64,
    pub duration_ms: u128,
    pub timestamp: u64,
}

/// A session-closing summary published at expiry or cancellation.
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticSummary {
    pub request_id: String,
    pub node_id: String,
    pub event: &'static str,
    pub status: &'static str,
    pub matched_events: u64,
    pub dropped_events: u64,
    pub ttl_secs: u64,
    pub timestamp: u64,
}

/// Channel item carrying a per-connection event to the MQTT publish loop.
#[derive(Debug, Clone)]
pub struct DiagnosticEnvelope {
    pub reply_topic: String,
    pub event: DiagnosticEvent,
}

/// A summary paired with the reply topic it should be published to.
#[derive(Debug, Clone)]
pub struct SummaryEnvelope {
    pub reply_topic: String,
    pub summary: DiagnosticSummary,
}

struct DiagnosticSession {
    request_id: String,
    reply_topic: String,
    username: String,
    target_host: Option<String>,
    target_port: Option<u16>,
    protocol: Option<String>,
    listener: Option<String>,
    event_types: HashSet<DiagnosticEventType>,
    expires_at: Instant,
    ttl_secs: u64,
    matched_events: u64,
    dropped_events: u64,
}

impl DiagnosticSession {
    fn matches(&self, candidate: &TraceCandidate) -> bool {
        optional_eq(Some(self.username.as_str()), candidate.username.as_deref())
            && optional_eq(
                self.target_host.as_deref(),
                candidate.target_host.as_deref(),
            )
            && self
                .target_port
                .map(|p| Some(p) == candidate.target_port)
                .unwrap_or(true)
            && optional_eq(self.protocol.as_deref(), Some(candidate.protocol.as_str()))
            && optional_eq(self.listener.as_deref(), Some(candidate.listener.as_str()))
    }

    fn wants(&self, event_type: DiagnosticEventType) -> bool {
        self.event_types.contains(&event_type)
    }

    fn summary(&self, node_id: &str) -> DiagnosticSummary {
        DiagnosticSummary {
            request_id: self.request_id.clone(),
            node_id: node_id.to_string(),
            event: "diagnostic_summary",
            status: "ok",
            matched_events: self.matched_events,
            dropped_events: self.dropped_events,
            ttl_secs: self.ttl_secs,
            timestamp: unix_ts(),
        }
    }
}

/// Holds the currently armed diagnostic sessions and fans matching connection
/// outcomes out as events. Cloneable handle around shared state.
pub struct DiagnosticRegistry {
    node_id: String,
    limits: DiagnosticLimits,
    inner: Mutex<HashMap<String, DiagnosticSession>>,
    tx: mpsc::Sender<DiagnosticEnvelope>,
}

impl DiagnosticRegistry {
    pub fn new(
        node_id: String,
        limits: DiagnosticLimits,
        tx: mpsc::Sender<DiagnosticEnvelope>,
    ) -> Self {
        DiagnosticRegistry {
            node_id,
            limits,
            inner: Mutex::new(HashMap::new()),
            tx,
        }
    }

    pub fn limits(&self) -> &DiagnosticLimits {
        &self.limits
    }

    /// Arm (or re-arm) a session. Enforces global and per-user caps for genuinely
    /// new sessions; re-arming an existing `request_id` refreshes it in place.
    pub fn start(&self, spec: DiagnosticSessionSpec) -> Result<StartAccepted, StartRejection> {
        let mut sessions = self.inner.lock().expect("diagnostic registry poisoned");
        let now = Instant::now();
        sessions.retain(|_, s| s.expires_at > now);

        let is_rearm = sessions.contains_key(&spec.request_id);
        if !is_rearm {
            if sessions.len() >= self.limits.max_sessions {
                return Err(StartRejection::GlobalLimit);
            }
            let per_user = sessions
                .values()
                .filter(|s| s.username == spec.username)
                .count();
            if per_user >= self.limits.max_sessions_per_user {
                return Err(StartRejection::UserLimit);
            }
        }

        let ttl_secs = spec.ttl.as_secs().max(1);
        let mut effective: Vec<DiagnosticEventType> = spec
            .event_types
            .iter()
            .copied()
            .filter(|t| DiagnosticEventType::PER_CONNECTION.contains(t))
            .collect();
        effective.sort_by_key(|t| t.as_str());

        sessions.insert(
            spec.request_id.clone(),
            DiagnosticSession {
                request_id: spec.request_id,
                reply_topic: spec.reply_topic,
                username: spec.username,
                target_host: spec.target_host,
                target_port: spec.target_port,
                protocol: spec.protocol,
                listener: spec.listener,
                event_types: effective.iter().copied().collect(),
                expires_at: now + spec.ttl,
                ttl_secs,
                matched_events: 0,
                dropped_events: 0,
            },
        );

        Ok(StartAccepted {
            ttl_secs,
            event_types: effective,
        })
    }

    /// Cancel a session, returning its final summary if it was still armed.
    pub fn cancel(&self, request_id: &str) -> Option<SummaryEnvelope> {
        let mut sessions = self.inner.lock().expect("diagnostic registry poisoned");
        let session = sessions.remove(request_id)?;
        Some(SummaryEnvelope {
            reply_topic: session.reply_topic.clone(),
            summary: session.summary(&self.node_id),
        })
    }

    /// Fan a completed connection outcome to every matching, still-armed session.
    /// The bounded registry lock is synchronous; publication never awaits and
    /// drops (and counts) events when the channel is saturated.
    pub fn record(&self, candidate: &TraceCandidate) {
        let Some(event_type) = DiagnosticEventType::from_candidate(candidate) else {
            return;
        };
        let now = Instant::now();
        let mut sessions = self.inner.lock().expect("diagnostic registry poisoned");
        if sessions.is_empty() {
            return;
        }
        for session in sessions.values_mut() {
            if session.expires_at <= now {
                continue;
            }
            if !session.matches(candidate) || !session.wants(event_type) {
                continue;
            }
            let envelope = DiagnosticEnvelope {
                reply_topic: session.reply_topic.clone(),
                event: build_event(&self.node_id, session, candidate, event_type),
            };
            match self.tx.try_send(envelope) {
                Ok(()) => session.matched_events += 1,
                Err(_) => session.dropped_events += 1,
            }
        }
    }

    /// Remove expired sessions and return their closing summaries.
    pub fn sweep_expired(&self) -> Vec<SummaryEnvelope> {
        let mut sessions = self.inner.lock().expect("diagnostic registry poisoned");
        let now = Instant::now();
        let expired: Vec<String> = sessions
            .iter()
            .filter(|(_, s)| s.expires_at <= now)
            .map(|(id, _)| id.clone())
            .collect();
        expired
            .into_iter()
            .filter_map(|id| sessions.remove(&id))
            .map(|session| SummaryEnvelope {
                reply_topic: session.reply_topic.clone(),
                summary: session.summary(&self.node_id),
            })
            .collect()
    }

    #[cfg(test)]
    fn active_len(&self) -> usize {
        self.inner
            .lock()
            .expect("diagnostic registry poisoned")
            .len()
    }
}

fn build_event(
    node_id: &str,
    session: &DiagnosticSession,
    candidate: &TraceCandidate,
    event_type: DiagnosticEventType,
) -> DiagnosticEvent {
    let status = match candidate.result {
        TraceResult::Ok => "ok",
        TraceResult::Error => "error",
    };
    DiagnosticEvent {
        request_id: session.request_id.clone(),
        node_id: node_id.to_string(),
        event: "diagnostic_event",
        event_type,
        status,
        listener: candidate.listener.clone(),
        protocol: candidate.protocol.clone(),
        client_addr: candidate.client_addr.clone(),
        username: candidate.username.clone(),
        target_host: candidate.target_host.clone(),
        target_port: candidate.target_port,
        decision: candidate.decision.clone(),
        egress: candidate.egress.clone(),
        chain_member: candidate.chain_member.clone(),
        attempts: candidate.attempts,
        failure_stage: candidate.failure_stage.clone(),
        message: candidate.message.clone(),
        snapshot_version: candidate.snapshot_version,
        duration_ms: candidate.duration_ms,
        timestamp: unix_ts(),
    }
}

fn optional_eq(expected: Option<&str>, actual: Option<&str>) -> bool {
    expected
        .map(|expected| {
            actual
                .map(|actual| actual.eq_ignore_ascii_case(expected))
                .unwrap_or(false)
        })
        .unwrap_or(true)
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

    fn test_limits() -> DiagnosticLimits {
        DiagnosticLimits {
            default_ttl: Duration::from_secs(30),
            max_ttl: Duration::from_secs(300),
            max_sessions: 4,
            max_sessions_per_user: 2,
        }
    }

    fn registry(cap: usize) -> (DiagnosticRegistry, mpsc::Receiver<DiagnosticEnvelope>) {
        let (tx, rx) = mpsc::channel(cap);
        (
            DiagnosticRegistry::new("edge-node-01".to_string(), test_limits(), tx),
            rx,
        )
    }

    fn spec(request_id: &str, username: &str) -> DiagnosticSessionSpec {
        DiagnosticSessionSpec {
            request_id: request_id.to_string(),
            reply_topic: format!("rove/replies/{request_id}"),
            username: username.to_string(),
            target_host: None,
            target_port: None,
            protocol: None,
            listener: None,
            event_types: DiagnosticEventType::PER_CONNECTION.into_iter().collect(),
            ttl: Duration::from_secs(60),
        }
    }

    fn candidate(username: &str, stage: Option<&str>, result: TraceResult) -> TraceCandidate {
        TraceCandidate {
            listener: "http-in".to_string(),
            protocol: "http".to_string(),
            client_addr: Some("203.0.113.5:51234".to_string()),
            username: Some(username.to_string()),
            target_host: Some("example.com".to_string()),
            target_port: Some(443),
            traffic: None,
            decision: Some("upstream".to_string()),
            egress: None,
            chain_member: None,
            attempts: None,
            result,
            failure_stage: stage.map(str::to_string),
            message: stage.map(|_| "upstream connect failed".to_string()),
            snapshot_version: 12,
            duration_ms: 35,
        }
    }

    #[test]
    fn clamp_ttl_defaults_and_bounds() {
        let limits = test_limits();
        assert_eq!(limits.clamp_ttl(None), Duration::from_secs(30));
        assert_eq!(limits.clamp_ttl(Some(0)), Duration::from_secs(1));
        assert_eq!(limits.clamp_ttl(Some(45)), Duration::from_secs(45));
        assert_eq!(limits.clamp_ttl(Some(9999)), Duration::from_secs(300));
    }

    #[test]
    fn event_type_from_candidate_maps_stages_and_skips_parse() {
        assert_eq!(
            DiagnosticEventType::from_candidate(&candidate("a", Some("auth"), TraceResult::Error)),
            Some(DiagnosticEventType::Auth)
        );
        assert_eq!(
            DiagnosticEventType::from_candidate(&candidate(
                "a",
                Some("outbound"),
                TraceResult::Error
            )),
            Some(DiagnosticEventType::Outbound)
        );
        for stage in [
            "dns",
            "dial",
            "tls",
            "chain_exhausted",
            "reverse_lookup",
            "reverse_open",
            "hop_connect",
        ] {
            assert_eq!(
                DiagnosticEventType::from_candidate(&candidate(
                    "a",
                    Some(stage),
                    TraceResult::Error
                )),
                Some(DiagnosticEventType::Outbound),
                "{stage} must remain visible as an outbound diagnostic event"
            );
        }
        assert_eq!(
            DiagnosticEventType::from_candidate(&candidate(
                "a",
                Some("stream_io"),
                TraceResult::Error
            )),
            Some(DiagnosticEventType::Splice)
        );
        assert_eq!(
            DiagnosticEventType::from_candidate(&candidate("a", None, TraceResult::Ok)),
            Some(DiagnosticEventType::Splice)
        );
        assert_eq!(
            DiagnosticEventType::from_candidate(&candidate("a", Some("parse"), TraceResult::Error)),
            None
        );
    }

    #[test]
    fn record_publishes_events_only_for_matching_active_sessions() {
        let (reg, mut rx) = registry(8);
        reg.start(DiagnosticSessionSpec {
            target_host: Some("example.com".to_string()),
            target_port: Some(443),
            protocol: Some("http".to_string()),
            ..spec("diag-1", "alice")
        })
        .unwrap();

        // Non-matching username -> no event.
        reg.record(&candidate("bob", Some("auth"), TraceResult::Error));
        assert!(rx.try_recv().is_err());

        reg.record(&candidate("alice", Some("outbound"), TraceResult::Error));
        let envelope = rx.try_recv().unwrap();
        assert_eq!(envelope.reply_topic, "rove/replies/diag-1");
        assert_eq!(envelope.event.event_type, DiagnosticEventType::Outbound);
        assert_eq!(envelope.event.status, "error");
        assert_eq!(envelope.event.node_id, "edge-node-01");
    }

    #[test]
    fn record_respects_event_type_filter() {
        let (reg, mut rx) = registry(8);
        let mut types = HashSet::new();
        types.insert(DiagnosticEventType::Outbound);
        reg.start(DiagnosticSessionSpec {
            event_types: types,
            ..spec("diag-1", "alice")
        })
        .unwrap();

        reg.record(&candidate("alice", Some("auth"), TraceResult::Error));
        assert!(rx.try_recv().is_err(), "auth event filtered out");

        reg.record(&candidate("alice", Some("outbound"), TraceResult::Error));
        assert!(rx.try_recv().is_ok(), "outbound event allowed");
    }

    #[test]
    fn events_never_leak_credentials() {
        let (reg, mut rx) = registry(8);
        reg.start(spec("diag-1", "alice")).unwrap();
        reg.record(&candidate("alice", Some("outbound"), TraceResult::Error));
        let envelope = rx.try_recv().unwrap();
        let json = serde_json::to_string(&envelope.event).unwrap();
        assert!(!json.contains("password"));
        assert!(!json.contains("secret"));
        assert!(!json.contains("authorization"));
        assert!(json.contains("\"username\":\"alice\""));
        assert!(json.contains("\"event_type\":\"outbound\""));
    }

    #[test]
    fn dropped_events_counted_when_channel_full_and_reported_in_summary() {
        let (reg, mut rx) = registry(1);
        reg.start(spec("diag-1", "alice")).unwrap();

        // First record fills the single channel slot; the rest are dropped.
        for _ in 0..5 {
            reg.record(&candidate("alice", Some("outbound"), TraceResult::Error));
        }

        let summary = reg.cancel("diag-1").unwrap().summary;
        assert_eq!(summary.matched_events, 1);
        assert_eq!(summary.dropped_events, 4);
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn start_enforces_global_and_per_user_caps() {
        let (reg, _rx) = registry(8);
        reg.start(spec("d1", "alice")).unwrap();
        reg.start(spec("d2", "alice")).unwrap();
        // Third session for alice exceeds per-user cap of 2.
        assert_eq!(
            reg.start(spec("d3", "alice")),
            Err(StartRejection::UserLimit)
        );

        reg.start(spec("d3", "bob")).unwrap();
        reg.start(spec("d4", "carol")).unwrap();
        // Global cap of 4 now reached.
        assert_eq!(
            reg.start(spec("d5", "dave")),
            Err(StartRejection::GlobalLimit)
        );

        // Re-arming an existing request_id is always allowed.
        assert!(reg.start(spec("d1", "alice")).is_ok());
    }

    #[test]
    fn rearm_does_not_grow_session_count() {
        let (reg, _rx) = registry(8);
        reg.start(spec("d1", "alice")).unwrap();
        reg.start(spec("d1", "alice")).unwrap();
        assert_eq!(reg.active_len(), 1);
    }

    #[test]
    fn cancel_unknown_session_returns_none() {
        let (reg, _rx) = registry(8);
        assert!(reg.cancel("missing").is_none());
    }

    #[test]
    fn sweep_expired_emits_summaries_and_clears_sessions() {
        let (reg, _rx) = registry(8);
        reg.start(DiagnosticSessionSpec {
            ttl: Duration::from_millis(0),
            ..spec("diag-1", "alice")
        })
        .unwrap();
        // A zero TTL clamps to >=1s at start; force expiry by re-inserting expired.
        {
            let mut sessions = reg.inner.lock().unwrap();
            if let Some(session) = sessions.get_mut("diag-1") {
                session.expires_at = Instant::now() - Duration::from_secs(1);
            }
        }
        let summaries = reg.sweep_expired();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].summary.request_id, "diag-1");
        assert_eq!(reg.active_len(), 0);
    }

    #[test]
    fn empty_event_type_filter_streams_no_per_connection_events() {
        let (reg, mut rx) = registry(8);
        reg.start(DiagnosticSessionSpec {
            event_types: HashSet::new(),
            ..spec("diag-1", "alice")
        })
        .unwrap();
        reg.record(&candidate("alice", Some("outbound"), TraceResult::Error));
        assert!(rx.try_recv().is_err(), "no per-connection events stream");
        let summary = reg.cancel("diag-1").unwrap().summary;
        assert_eq!(summary.matched_events, 0);
        assert_eq!(summary.dropped_events, 0);
    }

    #[test]
    fn start_reports_effective_event_types_sorted() {
        let (reg, _rx) = registry(8);
        let mut types = HashSet::new();
        types.insert(DiagnosticEventType::Splice);
        types.insert(DiagnosticEventType::Auth);
        // Summary in the filter is ignored for per-connection selection.
        types.insert(DiagnosticEventType::Summary);
        let accepted = reg
            .start(DiagnosticSessionSpec {
                event_types: types,
                ..spec("diag-1", "alice")
            })
            .unwrap();
        assert_eq!(
            accepted.event_types,
            vec![DiagnosticEventType::Auth, DiagnosticEventType::Splice]
        );
    }
}
