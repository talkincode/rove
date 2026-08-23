//! On-demand probe tracing.
//!
//! This is intentionally not a global per-user trace stream. MQTT arms a short
//! lived probe, then the next matching proxy connection reports its result.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficIdentity {
    pub requested_host: String,
    pub requested_port: u16,
    pub sniff: Option<crate::sniff::SniffObservation>,
    pub effective_policy_host: String,
    pub dial_host: String,
    pub dial_port: u16,
}

impl TrafficIdentity {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        let host = host.into();
        TrafficIdentity {
            requested_host: host.clone(),
            requested_port: port,
            sniff: None,
            effective_policy_host: host.clone(),
            dial_host: host,
            dial_port: port,
        }
    }

    pub fn with_observation(mut self, observation: crate::sniff::SniffObservation) -> Self {
        self.sniff = Some(observation);
        self
    }

    pub fn with_effective_policy_host(mut self, host: impl Into<String>) -> Self {
        self.effective_policy_host = host.into();
        self
    }
}

#[derive(Clone)]
pub struct ProbeTracer {
    inner: Arc<Mutex<HashMap<String, ProbeArm>>>,
    tx: mpsc::Sender<ProbeTraceReport>,
}

#[derive(Debug, Clone)]
pub struct ProbeArm {
    pub request_id: String,
    pub reply_topic: String,
    pub username: Option<String>,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub protocol: Option<String>,
    pub listener: Option<String>,
    pub expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct TraceCandidate {
    pub listener: String,
    pub protocol: String,
    /// Client source `ip:port` captured at TCP accept time, independent of
    /// any proxy protocol's own addressing. `None` only for candidates built
    /// outside a real accept loop (e.g. some unit tests).
    pub client_addr: Option<String>,
    pub username: Option<String>,
    pub target_host: Option<String>,
    pub target_port: Option<u16>,
    pub traffic: Option<TrafficIdentity>,
    pub decision: Option<String>,
    /// Physical egress actually used when it differs from `decision` (chain
    /// decisions): the winning member's outlet label, e.g. `reverse:h1`.
    pub egress: Option<String>,
    /// Winning chain member id.
    pub chain_member: Option<String>,
    /// Tunnel-establishment attempts made for chain decisions (populated on
    /// both success and exhaustion).
    pub attempts: Option<u32>,
    pub result: TraceResult,
    pub failure_stage: Option<String>,
    pub message: Option<String>,
    pub snapshot_version: u64,
    pub duration_ms: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceResult {
    Ok,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeTraceReport {
    pub request_id: String,
    pub reply_topic: String,
    pub event: String,
    pub status: String,
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

impl ProbeTracer {
    pub fn new(tx: mpsc::Sender<ProbeTraceReport>) -> Self {
        ProbeTracer {
            inner: Arc::new(Mutex::new(HashMap::new())),
            tx,
        }
    }

    pub async fn arm(&self, arm: ProbeArm) {
        self.inner.lock().await.insert(arm.request_id.clone(), arm);
    }

    pub async fn finish(&self, candidate: TraceCandidate) {
        let mut probes = self.inner.lock().await;
        let now = Instant::now();
        probes.retain(|_, arm| arm.expires_at > now);
        let Some(request_id) = probes
            .iter()
            .find(|(_, arm)| arm.matches(&candidate))
            .map(|(id, _)| id.clone())
        else {
            return;
        };
        let Some(arm) = probes.remove(&request_id) else {
            return;
        };
        drop(probes);

        let status = match candidate.result {
            TraceResult::Ok => "ok",
            TraceResult::Error => "error",
        };
        let traffic = candidate.traffic.as_ref();
        let sniff = traffic.and_then(|identity| identity.sniff.as_ref());
        let requested_host = traffic.map(|identity| identity.requested_host.clone());
        let requested_port = traffic.map(|identity| identity.requested_port);
        let sniffed_host = sniff.and_then(|observation| observation.host.clone());
        let sniff_protocol =
            sniff.and_then(|observation| observation.protocol.map(|value| value.as_str()));
        let sniff_outcome = sniff.map(|observation| observation.outcome.as_str());
        let effective_policy_host = traffic.map(|identity| identity.effective_policy_host.clone());
        let report = ProbeTraceReport {
            request_id: arm.request_id,
            reply_topic: arm.reply_topic,
            event: "probe_trace_result".to_string(),
            status: status.to_string(),
            listener: candidate.listener,
            protocol: candidate.protocol,
            client_addr: candidate.client_addr,
            username: candidate.username,
            target_host: candidate.target_host,
            target_port: candidate.target_port,
            requested_host,
            requested_port,
            sniffed_host,
            sniff_protocol,
            sniff_outcome,
            effective_policy_host,
            decision: candidate.decision,
            egress: candidate.egress,
            chain_member: candidate.chain_member,
            attempts: candidate.attempts,
            failure_stage: candidate.failure_stage,
            message: candidate.message,
            snapshot_version: candidate.snapshot_version,
            duration_ms: candidate.duration_ms,
            timestamp: unix_ts(),
        };
        let _ = self.tx.send(report).await;
    }
}

impl ProbeArm {
    pub fn new(request_id: String, reply_topic: String, ttl: Duration) -> Self {
        ProbeArm {
            request_id,
            reply_topic,
            username: None,
            target_host: None,
            target_port: None,
            protocol: None,
            listener: None,
            expires_at: Instant::now() + ttl,
        }
    }

    fn matches(&self, candidate: &TraceCandidate) -> bool {
        optional_eq(self.username.as_deref(), candidate.username.as_deref())
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

    #[tokio::test]
    async fn armed_probe_reports_once_on_match() {
        let (tx, mut rx) = mpsc::channel(4);
        let tracer = ProbeTracer::new(tx);
        let mut arm = ProbeArm::new(
            "probe-1".to_string(),
            "rove/replies/probe-1".to_string(),
            Duration::from_secs(30),
        );
        arm.username = Some("alice".to_string());
        arm.target_host = Some("example.com".to_string());
        arm.target_port = Some(443);
        arm.protocol = Some("http".to_string());
        tracer.arm(arm).await;

        tracer
            .finish(TraceCandidate {
                listener: "http-in".to_string(),
                protocol: "http".to_string(),
                client_addr: Some("198.51.100.9:4000".to_string()),
                username: Some("alice".to_string()),
                target_host: Some("example.com".to_string()),
                target_port: Some(443),
                traffic: Some(TrafficIdentity::new("93.184.216.34", 443).with_observation(
                    crate::sniff::SniffObservation {
                        outcome: crate::sniff::SniffOutcome::Matched,
                        protocol: Some(crate::sniff::SniffProtocol::Tls),
                        host: Some("example.com".to_string()),
                    },
                )),
                decision: Some("direct".to_string()),
                egress: None,
                chain_member: None,
                attempts: None,
                result: TraceResult::Ok,
                failure_stage: None,
                message: None,
                snapshot_version: 12,
                duration_ms: 3,
            })
            .await;

        let report = rx.recv().await.unwrap();
        assert_eq!(report.request_id, "probe-1");
        assert_eq!(report.status, "ok");
        assert_eq!(report.client_addr.as_deref(), Some("198.51.100.9:4000"));
        assert_eq!(report.requested_host.as_deref(), Some("93.184.216.34"));
        assert_eq!(report.sniffed_host.as_deref(), Some("example.com"));
        assert_eq!(report.sniff_protocol, Some("tls"));
        assert_eq!(report.sniff_outcome, Some("matched"));

        tracer
            .finish(TraceCandidate {
                listener: "http-in".to_string(),
                protocol: "http".to_string(),
                client_addr: Some("198.51.100.9:4000".to_string()),
                username: Some("alice".to_string()),
                target_host: Some("example.com".to_string()),
                target_port: Some(443),
                traffic: None,
                decision: Some("direct".to_string()),
                egress: None,
                chain_member: None,
                attempts: None,
                result: TraceResult::Ok,
                failure_stage: None,
                message: None,
                snapshot_version: 12,
                duration_ms: 3,
            })
            .await;
        assert!(rx.try_recv().is_err());
    }
}
