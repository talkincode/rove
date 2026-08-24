//! Optional MQTT control channel for network-isolated deployments.
//!
//! This intentionally preserves the old Rove MQTT contract for user policy
//! queries and sync commands, while mapping sync to the Rust snapshot puller.

use crate::config::MqttConfig;
use crate::diagnostics::{
    DiagnosticEnvelope, DiagnosticEventType, DiagnosticRegistry, DiagnosticSessionSpec,
    SummaryEnvelope,
};
use crate::engine::Engine;
use crate::model::UserPolicyView;
use crate::sync::{SyncOutcome, Syncer};
use crate::trace::{ProbeArm, ProbeTraceReport, ProbeTracer};
use rumqttc::{AsyncClient, Event, Incoming, MqttOptions, QoS, Transport};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};
use url::Url;

const STATUS_OK: &str = "ok";
const STATUS_NOT_FOUND: &str = "not_found";
const STATUS_BAD_REQUEST: &str = "bad_request";
const STATUS_ERROR: &str = "error";
const STATUS_THROTTLED: &str = "throttled";

const DIAGNOSTIC_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone)]
pub struct MqttService {
    cfg: MqttConfig,
    node_id: String,
    engine: Arc<Engine>,
    syncer: Arc<Syncer>,
    tracer: Arc<ProbeTracer>,
    trace_rx: Arc<Mutex<mpsc::Receiver<ProbeTraceReport>>>,
    diagnostics: Arc<DiagnosticRegistry>,
    diag_rx: Arc<Mutex<mpsc::Receiver<DiagnosticEnvelope>>>,
    last_sync_command_at: Arc<Mutex<Option<Instant>>>,
    version: String,
}

#[derive(Debug, Deserialize)]
struct UserPolicyQueryMessage {
    #[allow(dead_code)]
    command: Option<String>,
    request_id: Option<String>,
    reply_topic: Option<String>,
    username: Option<String>,
    client: Option<String>,
    #[serde(default)]
    data: UserPolicyQueryData,
}

#[derive(Debug, Default, Deserialize)]
struct UserPolicyQueryData {
    request_id: Option<String>,
    username: Option<String>,
    client: Option<String>,
}

#[derive(Debug, Serialize)]
struct UserPolicyQueryResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    node_id: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<UserPolicyView>,
    timestamp: u64,
}

#[derive(Debug, Default, Deserialize)]
struct SyncCommandMessage {
    #[allow(dead_code)]
    command: Option<String>,
    request_id: Option<String>,
    syncflag: Option<String>,
    #[serde(default)]
    data: SyncCommandData,
}

#[derive(Debug, Default, Deserialize)]
struct SyncCommandData {
    request_id: Option<String>,
    syncflag: Option<String>,
    sync_flag: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProbeTraceCommandMessage {
    request_id: Option<String>,
    reply_topic: Option<String>,
    #[serde(default)]
    data: ProbeTraceCommandData,
}

#[derive(Debug, Default, Deserialize)]
struct ProbeTraceCommandData {
    request_id: Option<String>,
    username: Option<String>,
    client: Option<String>,
    target_host: Option<String>,
    host: Option<String>,
    target_port: Option<u16>,
    port: Option<u16>,
    protocol: Option<String>,
    listener: Option<String>,
    ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ProbeTraceArmResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    node_id: String,
    event: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    ttl_secs: u64,
    timestamp: u64,
}

#[derive(Debug, Deserialize)]
struct DiagnosticCommandMessage {
    command: Option<String>,
    request_id: Option<String>,
    reply_topic: Option<String>,
    #[serde(default)]
    data: DiagnosticCommandData,
}

#[derive(Debug, Default, Deserialize)]
struct DiagnosticCommandData {
    request_id: Option<String>,
    username: Option<String>,
    client: Option<String>,
    target_host: Option<String>,
    host: Option<String>,
    target_port: Option<u16>,
    port: Option<u16>,
    protocol: Option<String>,
    listener: Option<String>,
    event_types: Option<Vec<String>>,
    ttl_secs: Option<u64>,
}

#[derive(Debug, Serialize)]
struct DiagnosticSessionResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    node_id: String,
    event: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_secs: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    event_types: Vec<String>,
    timestamp: u64,
}

/// Result of validating a `diagnostic_session_start` request before touching the
/// registry. Kept pure so it can be unit tested without a live MQTT client.
#[derive(Debug)]
enum DiagnosticStartPlan {
    /// Reply topic failed validation; nothing safe to publish, just drop.
    Ignore,
    /// Request was structurally invalid (e.g. missing username).
    BadRequest {
        reply_topic: String,
        request_id: String,
        message: &'static str,
    },
    /// Request is valid and should arm a session.
    Arm {
        reply_topic: String,
        request_id: String,
        spec: DiagnosticSessionSpec,
    },
}

#[derive(Debug, Serialize)]
struct NodeStatusMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    node_id: String,
    event: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    syncflag: Option<String>,
    success: bool,
    updated: bool,
    already_running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed_ms: Option<u128>,
    version: String,
    snapshot_version: u64,
    /// Wire-schema version of the applied snapshot. Lets the control plane
    /// confirm every node in the fleet speaks the schema it is about to
    /// publish before it rolls a snapshot out.
    snapshot_schema_version: u32,
    timestamp: u64,
}

impl MqttService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg: MqttConfig,
        node_id: String,
        engine: Arc<Engine>,
        syncer: Arc<Syncer>,
        tracer: Arc<ProbeTracer>,
        trace_rx: mpsc::Receiver<ProbeTraceReport>,
        diagnostics: Arc<DiagnosticRegistry>,
        diag_rx: mpsc::Receiver<DiagnosticEnvelope>,
        version: String,
    ) -> Self {
        MqttService {
            cfg,
            node_id,
            engine,
            syncer,
            tracer,
            trace_rx: Arc::new(Mutex::new(trace_rx)),
            diagnostics,
            diag_rx: Arc::new(Mutex::new(diag_rx)),
            last_sync_command_at: Arc::new(Mutex::new(None)),
            version,
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        if !self.cfg.enable {
            return Ok(());
        }
        if self.cfg.broker.trim().is_empty() {
            anyhow::bail!("mqtt broker is required when mqtt is enabled");
        }

        let mqtt_options = self.mqtt_options()?;
        let broker = mqtt_broker_log_target(&self.cfg.broker, self.cfg.tls.enable)?;
        let (client, mut eventloop) = AsyncClient::new(mqtt_options, 32);
        info!(
            client_id = %self.cfg.effective_client_id(&self.node_id),
            broker_scheme = %broker.scheme,
            broker_host = %broker.host,
            broker_port = broker.port,
            "mqtt client starting"
        );

        let mut sweep = tokio::time::interval(DIAGNOSTIC_SWEEP_INTERVAL);
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                event = eventloop.poll() => {
                    match event {
                        Ok(Event::Incoming(Incoming::ConnAck(_))) => {
                            self.subscribe(&client).await;
                            self.publish_startup_status(&client).await;
                        }
                        Ok(Event::Incoming(Incoming::Publish(publish))) => {
                            self.handle_publish(client.clone(), publish.topic, publish.payload.to_vec());
                        }
                        Ok(Event::Incoming(_)) | Ok(Event::Outgoing(_)) => {}
                        Err(e) => {
                            warn!(error = %e, "mqtt event loop error");
                            tokio::time::sleep(Duration::from_secs(3)).await;
                        }
                    }
                }
                report = recv_trace_report(self.trace_rx.clone()) => {
                    if let Some(report) = report {
                        self.publish_probe_trace_report(&client, report).await;
                    }
                }
                envelope = recv_diagnostic_event(self.diag_rx.clone()) => {
                    if let Some(envelope) = envelope {
                        self.publish_diagnostic_event(&client, envelope).await;
                    }
                }
                _ = sweep.tick() => {
                    for summary in self.diagnostics.sweep_expired() {
                        self.publish_diagnostic_summary(&client, summary).await;
                    }
                }
            }
        }
    }

    fn handle_publish(&self, client: AsyncClient, topic: String, payload: Vec<u8>) {
        if topic == self.cfg.topics.user_query {
            let svc = self.clone();
            tokio::spawn(async move {
                svc.handle_user_policy_query(client, &payload).await;
            });
            return;
        }
        if topic == self.cfg.topics.sync_command {
            let svc = self.clone();
            tokio::spawn(async move {
                svc.handle_sync_command(client, &payload).await;
            });
            return;
        }
        if topic == self.cfg.topics.probe_trace {
            let svc = self.clone();
            tokio::spawn(async move {
                svc.handle_probe_trace_command(client, &payload).await;
            });
            return;
        }
        if topic == self.cfg.topics.diagnostics_command {
            let svc = self.clone();
            tokio::spawn(async move {
                svc.handle_diagnostics_command(client, &payload).await;
            });
        }
    }

    async fn subscribe(&self, client: &AsyncClient) {
        let qos = self.qos();
        for topic in [
            self.cfg.topics.user_query.trim(),
            self.cfg.topics.sync_command.trim(),
            self.cfg.topics.probe_trace.trim(),
            self.cfg.topics.diagnostics_command.trim(),
        ] {
            if topic.is_empty() {
                continue;
            }
            if let Err(e) = client.subscribe(topic, qos).await {
                warn!(topic, error = %e, "mqtt subscribe failed");
            } else {
                info!(topic, "mqtt subscribed");
            }
        }
    }

    async fn handle_user_policy_query(&self, client: AsyncClient, payload: &[u8]) {
        let Some((topic, response)) = self.user_policy_response(payload) else {
            return;
        };
        if let Err(e) = publish_json(&client, topic, self.qos(), &response).await {
            warn!(error = %e, "mqtt user policy response publish failed");
        }
    }

    async fn handle_sync_command(&self, client: AsyncClient, payload: &[u8]) {
        let request = match parse_sync_command(payload) {
            Ok(req) => req,
            Err(e) => {
                warn!(error = %e, "mqtt sync command decode failed");
                let status = self
                    .node_status(None, "sync_command", STATUS_BAD_REQUEST, false)
                    .with_message("invalid sync command payload")
                    .with_outcome(None);
                self.publish_node_status(&client, status).await;
                return;
            }
        };

        let request_id = first_non_empty([
            request.request_id.as_deref(),
            request.data.request_id.as_deref(),
        ]);
        let syncflag = first_non_empty([
            request.data.syncflag.as_deref(),
            request.data.sync_flag.as_deref(),
            request.syncflag.as_deref(),
        ]);

        if !self.allow_sync_command().await {
            let status = self
                .node_status(request_id, "sync_command", STATUS_THROTTLED, false)
                .with_message("sync command ignored because throttle window is active")
                .with_syncflag(syncflag)
                .with_outcome(None);
            self.publish_node_status(&client, status).await;
            return;
        }

        let outcome = self.syncer.try_sync_once("mqtt").await;
        let status_name = if outcome.already_running {
            STATUS_THROTTLED
        } else if outcome.success {
            STATUS_OK
        } else {
            STATUS_ERROR
        };
        let status = self
            .node_status(request_id, "sync_command", status_name, outcome.success)
            .with_message(&outcome.message)
            .with_syncflag(syncflag)
            .with_outcome(Some(&outcome));
        self.publish_node_status(&client, status).await;
    }

    async fn handle_probe_trace_command(&self, client: AsyncClient, payload: &[u8]) {
        let req: ProbeTraceCommandMessage = match serde_json::from_slice(payload) {
            Ok(req) => req,
            Err(e) => {
                warn!(error = %e, "mqtt probe trace command decode failed");
                return;
            }
        };

        let reply_topic = req.reply_topic.as_deref().unwrap_or("").trim();
        if !allowed_reply_topic(reply_topic, &self.cfg.effective_reply_topic_prefix()) {
            warn!(
                reply_topic,
                "mqtt probe trace command rejected because reply topic is not allowed"
            );
            return;
        }

        let request_id =
            first_non_empty([req.request_id.as_deref(), req.data.request_id.as_deref()])
                .map(str::to_string)
                .unwrap_or_else(|| format!("probe-{}", unix_ts()));
        let ttl_secs = req.data.ttl_secs.unwrap_or(30).clamp(1, 300);
        let mut arm = ProbeArm::new(
            request_id.clone(),
            reply_topic.to_string(),
            Duration::from_secs(ttl_secs),
        );
        arm.username = first_non_empty([req.data.username.as_deref(), req.data.client.as_deref()])
            .map(str::to_string);
        arm.target_host =
            first_non_empty([req.data.target_host.as_deref(), req.data.host.as_deref()])
                .map(str::to_string);
        arm.target_port = req.data.target_port.or(req.data.port);
        arm.protocol = req.data.protocol.map(|p| p.to_ascii_lowercase());
        arm.listener = req.data.listener;
        self.tracer.arm(arm).await;

        let response = ProbeTraceArmResponse {
            request_id: Some(request_id),
            node_id: self.node_id.clone(),
            event: "probe_trace_armed".to_string(),
            status: STATUS_OK.to_string(),
            message: Some("probe trace armed".to_string()),
            ttl_secs,
            timestamp: unix_ts(),
        };
        if let Err(e) = publish_json(&client, reply_topic, self.qos(), &response).await {
            warn!(error = %e, "mqtt probe trace arm response publish failed");
        }
    }

    async fn handle_diagnostics_command(&self, client: AsyncClient, payload: &[u8]) {
        let req: DiagnosticCommandMessage = match serde_json::from_slice(payload) {
            Ok(req) => req,
            Err(e) => {
                warn!(error = %e, "mqtt diagnostics command decode failed");
                return;
            }
        };
        let command = req
            .command
            .as_deref()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        match command.as_str() {
            // The diagnostics topic is dedicated, so a missing command defaults to start.
            "" | "diagnostic_session_start" => self.start_diagnostic_session(client, req).await,
            "diagnostic_session_cancel" => self.cancel_diagnostic_session(client, req).await,
            other => warn!(command = other, "mqtt diagnostics command not recognized"),
        }
    }

    async fn start_diagnostic_session(&self, client: AsyncClient, req: DiagnosticCommandMessage) {
        match self.plan_diagnostic_start(&req) {
            DiagnosticStartPlan::Ignore => {
                warn!("mqtt diagnostics start rejected because reply topic is not allowed");
            }
            DiagnosticStartPlan::BadRequest {
                reply_topic,
                request_id,
                message,
            } => {
                let response = self.diagnostic_response(
                    Some(request_id),
                    "diagnostic_session_rejected",
                    STATUS_BAD_REQUEST,
                    Some(message.to_string()),
                    None,
                    Vec::new(),
                );
                self.publish_diagnostic_response(&client, &reply_topic, &response)
                    .await;
            }
            DiagnosticStartPlan::Arm {
                reply_topic,
                request_id,
                spec,
            } => {
                let response = match self.diagnostics.start(spec) {
                    Ok(accepted) => self.diagnostic_response(
                        Some(request_id),
                        "diagnostic_session_started",
                        STATUS_OK,
                        Some("diagnostic session armed".to_string()),
                        Some(accepted.ttl_secs),
                        accepted
                            .event_types
                            .iter()
                            .map(|t| t.as_str().to_string())
                            .collect(),
                    ),
                    Err(rejection) => self.diagnostic_response(
                        Some(request_id),
                        "diagnostic_session_rejected",
                        STATUS_THROTTLED,
                        Some(rejection.message().to_string()),
                        None,
                        Vec::new(),
                    ),
                };
                self.publish_diagnostic_response(&client, &reply_topic, &response)
                    .await;
            }
        }
    }

    async fn cancel_diagnostic_session(&self, client: AsyncClient, req: DiagnosticCommandMessage) {
        let Some(request_id) =
            first_non_empty([req.request_id.as_deref(), req.data.request_id.as_deref()])
        else {
            warn!("mqtt diagnostics cancel missing request_id");
            return;
        };
        match self.diagnostics.cancel(request_id) {
            Some(summary) => self.publish_diagnostic_summary(&client, summary).await,
            None => warn!(request_id, "mqtt diagnostics cancel: no active session"),
        }
    }

    fn plan_diagnostic_start(&self, req: &DiagnosticCommandMessage) -> DiagnosticStartPlan {
        let reply_topic = req.reply_topic.as_deref().unwrap_or("").trim();
        if !allowed_reply_topic(reply_topic, &self.cfg.effective_reply_topic_prefix()) {
            return DiagnosticStartPlan::Ignore;
        }
        let reply_topic = reply_topic.to_string();
        let request_id =
            first_non_empty([req.request_id.as_deref(), req.data.request_id.as_deref()])
                .map(str::to_string)
                .unwrap_or_else(|| format!("diag-{}", unix_ts()));

        let Some(username) =
            first_non_empty([req.data.username.as_deref(), req.data.client.as_deref()])
        else {
            return DiagnosticStartPlan::BadRequest {
                reply_topic,
                request_id,
                message: "username is required",
            };
        };

        let ttl = self.diagnostics.limits().clamp_ttl(req.data.ttl_secs);
        let spec = DiagnosticSessionSpec {
            request_id: request_id.clone(),
            reply_topic: reply_topic.clone(),
            username: username.to_string(),
            target_host: first_non_empty([
                req.data.target_host.as_deref(),
                req.data.host.as_deref(),
            ])
            .map(str::to_string),
            target_port: req.data.target_port.or(req.data.port),
            protocol: req.data.protocol.as_deref().map(str::to_ascii_lowercase),
            listener: req
                .data
                .listener
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            event_types: resolve_event_types(req.data.event_types.as_ref()),
            ttl,
        };
        DiagnosticStartPlan::Arm {
            reply_topic,
            request_id,
            spec,
        }
    }

    fn diagnostic_response(
        &self,
        request_id: Option<String>,
        event: &str,
        status: &str,
        message: Option<String>,
        ttl_secs: Option<u64>,
        event_types: Vec<String>,
    ) -> DiagnosticSessionResponse {
        DiagnosticSessionResponse {
            request_id,
            node_id: self.node_id.clone(),
            event: event.to_string(),
            status: status.to_string(),
            message,
            ttl_secs,
            event_types,
            timestamp: unix_ts(),
        }
    }

    async fn publish_diagnostic_response(
        &self,
        client: &AsyncClient,
        reply_topic: &str,
        response: &DiagnosticSessionResponse,
    ) {
        if let Err(e) = publish_json(client, reply_topic, self.qos(), response).await {
            warn!(error = %e, "mqtt diagnostics response publish failed");
        }
    }

    async fn publish_diagnostic_event(&self, client: &AsyncClient, envelope: DiagnosticEnvelope) {
        if let Err(e) =
            publish_json(client, envelope.reply_topic, self.qos(), &envelope.event).await
        {
            warn!(error = %e, "mqtt diagnostic event publish failed");
        }
    }

    async fn publish_diagnostic_summary(&self, client: &AsyncClient, envelope: SummaryEnvelope) {
        if let Err(e) =
            publish_json(client, envelope.reply_topic, self.qos(), &envelope.summary).await
        {
            warn!(error = %e, "mqtt diagnostic summary publish failed");
        }
    }

    fn user_policy_response(&self, payload: &[u8]) -> Option<(String, UserPolicyQueryResponse)> {
        let req: UserPolicyQueryMessage = match serde_json::from_slice(payload) {
            Ok(req) => req,
            Err(e) => {
                warn!(error = %e, "mqtt user policy query decode failed");
                return None;
            }
        };

        let reply_topic = req.reply_topic.as_deref().unwrap_or("").trim();
        if !allowed_reply_topic(reply_topic, &self.cfg.effective_reply_topic_prefix()) {
            warn!(
                reply_topic,
                "mqtt user policy query rejected because reply topic is not allowed"
            );
            return None;
        }

        let request_id =
            first_non_empty([req.request_id.as_deref(), req.data.request_id.as_deref()]);
        let username = first_non_empty([
            req.data.username.as_deref(),
            req.data.client.as_deref(),
            req.username.as_deref(),
            req.client.as_deref(),
        ]);

        let response = if let Some(username) = username {
            match self.engine.snapshot().user_policy(username) {
                Some(user) => UserPolicyQueryResponse {
                    request_id: request_id.map(str::to_string),
                    node_id: self.node_id.clone(),
                    status: STATUS_OK.to_string(),
                    message: None,
                    user: Some(user),
                    timestamp: unix_ts(),
                },
                None => UserPolicyQueryResponse {
                    request_id: request_id.map(str::to_string),
                    node_id: self.node_id.clone(),
                    status: STATUS_NOT_FOUND.to_string(),
                    message: Some("user not found".to_string()),
                    user: None,
                    timestamp: unix_ts(),
                },
            }
        } else {
            UserPolicyQueryResponse {
                request_id: request_id.map(str::to_string),
                node_id: self.node_id.clone(),
                status: STATUS_BAD_REQUEST.to_string(),
                message: Some("username is required".to_string()),
                user: None,
                timestamp: unix_ts(),
            }
        };

        Some((reply_topic.to_string(), response))
    }

    async fn publish_startup_status(&self, client: &AsyncClient) {
        self.publish_node_status(client, self.startup_status())
            .await;
    }

    fn startup_status(&self) -> NodeStatusMessage {
        if self.syncer.version() > 0 {
            self.node_status(None, "startup", "synced", true)
                .with_message("node snapshot is loaded")
        } else {
            self.node_status(None, "startup", "starting", false)
                .with_message("node has no loaded snapshot")
        }
    }

    async fn publish_node_status(&self, client: &AsyncClient, message: NodeStatusMessage) {
        let topic = self.cfg.topics.node_status.trim();
        if topic.is_empty() {
            return;
        }
        if let Err(e) = publish_json(client, topic, self.qos(), &message).await {
            warn!(error = %e, "mqtt node status publish failed");
        }
    }

    async fn publish_probe_trace_report(&self, client: &AsyncClient, report: ProbeTraceReport) {
        let topic = report.reply_topic.clone();
        if let Err(e) = publish_json(client, topic, self.qos(), &report).await {
            warn!(error = %e, "mqtt probe trace report publish failed");
        }
    }

    async fn allow_sync_command(&self) -> bool {
        let mut last = self.last_sync_command_at.lock().await;
        let now = Instant::now();
        if last
            .map(|t| now.duration_since(t) < Duration::from_secs(5))
            .unwrap_or(false)
        {
            return false;
        }
        *last = Some(now);
        true
    }

    fn node_status(
        &self,
        request_id: Option<&str>,
        event: &str,
        status: &str,
        success: bool,
    ) -> NodeStatusMessage {
        NodeStatusMessage {
            request_id: request_id.map(str::to_string),
            node_id: self.node_id.clone(),
            event: event.to_string(),
            status: status.to_string(),
            message: None,
            syncflag: None,
            success,
            updated: false,
            already_running: false,
            elapsed_ms: None,
            version: self.version.clone(),
            snapshot_version: self.syncer.version(),
            snapshot_schema_version: self.syncer.schema_version(),
            timestamp: unix_ts(),
        }
    }

    fn mqtt_options(&self) -> anyhow::Result<MqttOptions> {
        let broker = normalize_broker(&self.cfg.broker, self.cfg.tls.enable)?;
        let url = Url::parse(&broker)?;
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("mqtt broker host is required"))?;
        let scheme = url.scheme().to_ascii_lowercase();
        let transport = match scheme.as_str() {
            "tcp" | "mqtt" => Transport::tcp(),
            "ssl" | "tls" | "tcps" | "mqtts" => Transport::tls_with_default_config(),
            other => anyhow::bail!("unsupported mqtt broker scheme {other:?}"),
        };
        let port = url.port().unwrap_or(mqtt_default_port(&scheme)?);
        let mut options = MqttOptions::new(self.cfg.effective_client_id(&self.node_id), host, port);
        options.set_transport(transport);
        options.set_keep_alive(Duration::from_secs(30));
        options.set_clean_session(true);
        if !self.cfg.username.trim().is_empty() {
            options.set_credentials(self.cfg.username.trim(), self.cfg.password.clone());
        } else if !url.username().is_empty() {
            options.set_credentials(url.username(), url.password().unwrap_or_default());
        }
        Ok(options)
    }

    fn qos(&self) -> QoS {
        match self.cfg.effective_qos() {
            0 => QoS::AtMostOnce,
            2 => QoS::ExactlyOnce,
            _ => QoS::AtLeastOnce,
        }
    }
}

async fn recv_trace_report(
    rx: Arc<Mutex<mpsc::Receiver<ProbeTraceReport>>>,
) -> Option<ProbeTraceReport> {
    rx.lock().await.recv().await
}

async fn recv_diagnostic_event(
    rx: Arc<Mutex<mpsc::Receiver<DiagnosticEnvelope>>>,
) -> Option<DiagnosticEnvelope> {
    rx.lock().await.recv().await
}

/// Resolve the requested per-connection event types. An omitted or empty list
/// defaults to all types; a non-empty list keeps only recognised tokens (the
/// arm response echoes the effective set so operators can spot typos).
fn resolve_event_types(raw: Option<&Vec<String>>) -> HashSet<DiagnosticEventType> {
    match raw {
        Some(list) if !list.is_empty() => list
            .iter()
            .filter_map(|token| DiagnosticEventType::from_token(token))
            .collect(),
        _ => DiagnosticEventType::PER_CONNECTION.into_iter().collect(),
    }
}

impl NodeStatusMessage {
    fn with_message(mut self, message: &str) -> Self {
        if !message.trim().is_empty() {
            self.message = Some(message.to_string());
        }
        self
    }

    fn with_syncflag(mut self, syncflag: Option<&str>) -> Self {
        if let Some(syncflag) = syncflag {
            self.syncflag = Some(syncflag.to_string());
        }
        self
    }

    fn with_outcome(mut self, outcome: Option<&SyncOutcome>) -> Self {
        if let Some(outcome) = outcome {
            self.success = outcome.success;
            self.updated = outcome.updated;
            self.already_running = outcome.already_running;
            self.elapsed_ms = Some(outcome.elapsed_ms);
            self.snapshot_version = outcome.version;
        }
        self
    }
}

async fn publish_json<T: Serialize>(
    client: &AsyncClient,
    topic: impl Into<String>,
    qos: QoS,
    payload: &T,
) -> anyhow::Result<()> {
    let data = serde_json::to_vec(payload)?;
    client.publish(topic, qos, false, data).await?;
    Ok(())
}

fn parse_sync_command(payload: &[u8]) -> anyhow::Result<SyncCommandMessage> {
    if String::from_utf8_lossy(payload).trim().is_empty() {
        return Ok(SyncCommandMessage::default());
    }
    Ok(serde_json::from_slice(payload)?)
}

pub(crate) fn allowed_reply_topic(topic: &str, prefix: &str) -> bool {
    let topic = topic.trim();
    !topic.is_empty()
        && !topic.contains(['#', '+', ' ', '\t', '\r', '\n'])
        && topic.starts_with(prefix)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MqttBrokerLogTarget {
    scheme: String,
    host: String,
    port: u16,
}

fn mqtt_broker_log_target(broker: &str, tls_enabled: bool) -> anyhow::Result<MqttBrokerLogTarget> {
    let broker = normalize_broker(broker, tls_enabled)?;
    let url = Url::parse(&broker)?;
    let scheme = url.scheme().to_ascii_lowercase();
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("mqtt broker host is required"))?
        .to_string();
    let port = url.port().unwrap_or(mqtt_default_port(&scheme)?);
    Ok(MqttBrokerLogTarget { scheme, host, port })
}

fn mqtt_default_port(scheme: &str) -> anyhow::Result<u16> {
    match scheme {
        "tcp" | "mqtt" => Ok(1883),
        "ssl" | "tls" | "tcps" | "mqtts" => Ok(8883),
        other => anyhow::bail!("unsupported mqtt broker scheme {other:?}"),
    }
}

fn normalize_broker(broker: &str, tls_enabled: bool) -> anyhow::Result<String> {
    if !tls_enabled {
        return Ok(broker.trim().to_string());
    }
    let mut url = Url::parse(broker.trim())?;
    match url.scheme().to_ascii_lowercase().as_str() {
        "ssl" | "tls" | "tcps" | "mqtts" => Ok(url.to_string()),
        "tcp" | "mqtt" => {
            url.set_scheme("ssl")
                .map_err(|_| anyhow::anyhow!("failed to rewrite mqtt broker scheme"))?;
            Ok(url.to_string())
        }
        other => anyhow::bail!("mqtt tls requires tcp://, mqtt://, ssl://, tls://, tcps:// or mqtts:// broker scheme, got {other:?}"),
    }
}

fn first_non_empty<const N: usize>(values: [Option<&str>; N]) -> Option<&str> {
    values
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|v| !v.is_empty())
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
    use crate::config::{MqttTls, MqttTopics};
    use crate::model::{
        RawAction, RawChainMember, RawEgress, RawRoute, RawRoutingPolicy, RawSnapshot, RawUpstream,
        RawUser, Snapshot,
    };
    use std::collections::HashMap;

    fn service_with_snapshot() -> MqttService {
        let engine = Engine::new();
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            RawUser {
                password: "secret".to_string(),
                expire: Some("2099-12-31".to_string()),
                up_rate: 10,
                down_rate: 20,
                max_connections: 2,
                policy: "open".to_string(),
                frontends: Default::default(),
            },
        );
        users.insert(
            "bob".to_string(),
            RawUser {
                password: "secret-bob".to_string(),
                expire: None,
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                policy: "chained".to_string(),
                frontends: Default::default(),
            },
        );
        let routing_policies = HashMap::from([
            (
                "open".to_string(),
                RawRoutingPolicy {
                    routes: vec![
                        RawRoute {
                            selectors: vec!["full:blocked.example".to_string()],
                            action: RawAction::Block,
                        },
                        RawRoute {
                            selectors: vec!["example.com".to_string()],
                            action: RawAction::Egress {
                                egress: "tls-socks".to_string(),
                            },
                        },
                    ],
                    default_action: None,
                },
            ),
            (
                "chained".to_string(),
                RawRoutingPolicy {
                    routes: vec![RawRoute {
                        selectors: vec!["example.com".to_string()],
                        action: RawAction::Egress {
                            egress: "jp-pop".to_string(),
                        },
                    }],
                    default_action: None,
                },
            ),
        ]);
        let egresses = HashMap::from([
            (
                "tls-socks".to_string(),
                RawEgress::Upstream {
                    backend: RawUpstream {
                        kind: "socks5".to_string(),
                        addr: "proxy.example.com:1080".to_string(),
                        username: Some("upuser".to_string()),
                        password: Some("uppass".to_string()),
                        tls: true,
                        skip_cert_verify: false,
                    },
                },
            ),
            (
                "jp-pop".to_string(),
                RawEgress::Chain {
                    members: vec![
                        RawChainMember {
                            id: "jp-reverse-1".to_string(),
                            priority: 1,
                            backend: RawUpstream {
                                kind: "reverse".to_string(),
                                addr: "h1".to_string(),
                                username: None,
                                password: None,
                                tls: false,
                                skip_cert_verify: false,
                            },
                        },
                        RawChainMember {
                            id: "jp-socks-2".to_string(),
                            priority: 2,
                            backend: RawUpstream {
                                kind: "socks5".to_string(),
                                addr: "10.2.2.1:1080".to_string(),
                                username: Some("member-user".to_string()),
                                password: Some("member-pass".to_string()),
                                tls: false,
                                skip_cert_verify: false,
                            },
                        },
                    ],
                },
            ),
        ]);
        engine.replace(
            Snapshot::compile(
                RawSnapshot {
                    version: 7,
                    users,
                    routing_policies,
                    egresses,
                    ..Default::default()
                },
                "node-1",
            )
            .unwrap(),
        );

        let syncer = Arc::new(
            Syncer::new(
                crate::config::ControlPlane {
                    snapshot_url: "http://127.0.0.1".to_string(),
                    token: "token".to_string(),
                    poll_interval_secs: 30,
                    cache_path: "./target/test-snapshot.json".to_string(),
                },
                "node-1".to_string(),
                engine.clone(),
            )
            .unwrap(),
        );

        let (trace_tx, trace_rx) = mpsc::channel(8);
        let tracer = Arc::new(ProbeTracer::new(trace_tx));

        let (diag_tx, diag_rx) = mpsc::channel(8);
        let diagnostics = Arc::new(DiagnosticRegistry::new(
            "node-1".to_string(),
            crate::config::MqttDiagnostics::default().to_limits(),
            diag_tx,
        ));

        MqttService::new(
            MqttConfig {
                enable: true,
                broker: "tcp://127.0.0.1:1883".to_string(),
                client_id: String::new(),
                username: String::new(),
                password: String::new(),
                qos: 1,
                reply_topic_prefix: "rove/replies/".to_string(),
                topics: MqttTopics::default(),
                tls: MqttTls::default(),
                diagnostics: crate::config::MqttDiagnostics::default(),
            },
            "node-1".to_string(),
            engine,
            syncer,
            tracer,
            trace_rx,
            diagnostics,
            diag_rx,
            "Rove/test".to_string(),
        )
    }

    #[test]
    fn rejects_bad_reply_topics() {
        assert!(allowed_reply_topic(
            "rove/replies/request-1",
            "rove/replies/"
        ));
        assert!(!allowed_reply_topic("rove/other", "rove/replies/"));
        assert!(!allowed_reply_topic("rove/replies/#", "rove/replies/"));
    }

    #[test]
    fn user_policy_query_replies_without_passwords() {
        let svc = service_with_snapshot();
        let (topic, response) = svc
            .user_policy_response(
                br#"{"request_id":"r1","reply_topic":"rove/replies/r1","data":{"username":"alice"}}"#,
            )
            .unwrap();
        assert_eq!(topic, "rove/replies/r1");
        assert_eq!(response.status, STATUS_OK);
        let raw = serde_json::to_string(&response).unwrap();
        assert!(!raw.contains("secret"));
        assert!(!raw.contains("uppass"));
        assert!(raw.contains("\"auth\":true"));
    }

    #[test]
    fn user_policy_query_exposes_chain_reference_without_member_credentials() {
        let svc = service_with_snapshot();
        let (_, response) = svc
            .user_policy_response(
                br#"{"request_id":"r2","reply_topic":"rove/replies/r2","data":{"username":"bob"}}"#,
            )
            .unwrap();
        assert_eq!(response.status, STATUS_OK);
        let raw = serde_json::to_string(&response).unwrap();
        // The chain reference and its member inventory are visible…
        assert!(raw.contains("\"kind\":\"chain\""));
        assert!(raw.contains("\"addr\":\"jp-pop\""));
        assert!(raw.contains("\"jp-reverse-1\""));
        assert!(raw.contains("\"jp-socks-2\""));
        assert!(raw.contains("\"auth\":true"));
        // …but never member credentials.
        assert!(!raw.contains("member-pass"));
        assert!(!raw.contains("member-user"));
        assert!(!raw.contains("password"));
    }

    #[test]
    fn user_policy_query_exposes_routes_and_named_egresses_without_credentials() {
        let svc = service_with_snapshot();
        let document = crate::model::decode_snapshot(
            br#"{
                "schema_version": 1,
                "version": 8,
                "egresses": {
                    "tokyo": {
                        "type": "upstream",
                        "backend": {
                            "kind": "socks5",
                            "addr": "tokyo.example:1080",
                            "username": "upstream-user",
                            "password": "upstream-secret"
                        }
                    }
                },
                "routing_policies": {
                    "work": {
                        "routes": [
                            {"selectors": ["blocked.example"], "action": {"type": "block"}},
                            {"selectors": ["example.com"], "action": {"type": "egress", "egress": "tokyo"}},
                            {"selectors": ["direct.example"], "action": {"type": "direct"}}
                        ]
                    }
                },
                "users": {
                    "routed-user": {
                        "password": "login-secret",
                        "policy": "work"
                    }
                }
            }"#,
        )
        .unwrap();
        svc.engine
            .replace(Snapshot::compile(document, "node-1").unwrap());

        let (_, response) = svc
            .user_policy_response(
                br#"{"request_id":"r-routed","reply_topic":"rove/replies/r-routed","data":{"username":"routed-user"}}"#,
            )
            .unwrap();
        assert_eq!(response.status, STATUS_OK);
        let value = serde_json::to_value(&response).unwrap();
        let routing = &value["user"]["routing_policy"];
        assert_eq!(routing["id"], "work");
        assert_eq!(routing["routes"][0]["action"], "block");
        assert_eq!(routing["routes"][1]["action"], "egress");
        assert_eq!(routing["routes"][1]["egress"]["id"], "tokyo");
        assert_eq!(routing["routes"][2]["action"], "direct");
        // The default is always reported, so an operator reading a policy over
        // MQTT sees what an unmatched destination does without inferring it.
        assert_eq!(routing["default_action"]["action"], "direct");

        let raw = serde_json::to_string(&value).unwrap();
        assert!(!raw.contains("login-secret"));
        assert!(!raw.contains("upstream-secret"));
        assert!(!raw.contains("upstream-user"));
        assert!(!raw.contains("\"password\""));
    }

    #[test]
    fn user_policy_query_reports_missing_user() {
        let svc = service_with_snapshot();
        let (_, response) = svc
            .user_policy_response(
                br#"{"request_id":"r1","reply_topic":"rove/replies/r1","username":"missing"}"#,
            )
            .unwrap();
        assert_eq!(response.status, STATUS_NOT_FOUND);
    }

    #[test]
    fn user_policy_query_validates_payload_reply_topic_and_username() {
        let svc = service_with_snapshot();

        assert!(svc.user_policy_response(b"not json").is_none());
        assert!(svc
            .user_policy_response(br#"{"reply_topic":"rove/other","username":"alice"}"#)
            .is_none());

        let (_, response) = svc
            .user_policy_response(br#"{"reply_topic":"rove/replies/r1"}"#)
            .unwrap();
        assert_eq!(response.status, STATUS_BAD_REQUEST);
        assert_eq!(response.message.as_deref(), Some("username is required"));
    }

    #[test]
    fn sync_command_accepts_empty_payload_and_syncflag_aliases() {
        assert!(parse_sync_command(b"").is_ok());
        let req =
            parse_sync_command(br#"{"request_id":"s1","data":{"sync_flag":"private"}}"#).unwrap();
        assert_eq!(req.request_id.as_deref(), Some("s1"));
        assert_eq!(req.data.sync_flag.as_deref(), Some("private"));
        assert!(parse_sync_command(b"not json").is_err());
    }

    #[test]
    fn tls_enabled_rewrites_tcp_broker() {
        assert_eq!(
            normalize_broker("tcp://mqtt.example.com:1883", true).unwrap(),
            "ssl://mqtt.example.com:1883"
        );
        assert_eq!(
            normalize_broker("ssl://mqtt.example.com:8883", true).unwrap(),
            "ssl://mqtt.example.com:8883"
        );
        assert_eq!(
            normalize_broker("mqtt://mqtt.example.com", false).unwrap(),
            "mqtt://mqtt.example.com"
        );
        assert!(normalize_broker("http://mqtt.example.com", true).is_err());
        assert!(normalize_broker("wss://mqtt.example.com", true).is_err());
    }

    #[test]
    fn mqtt_options_accepts_supported_schemes_and_credentials() {
        crate::tls::init_crypto();
        let mut svc = service_with_snapshot();
        svc.cfg.broker = "mqtt://url-user:url-pass@mqtt.example.com".to_string();
        svc.cfg.username.clear();
        svc.cfg.password.clear();
        assert!(svc.mqtt_options().is_ok());

        svc.cfg.broker = "mqtts://mqtt.example.com".to_string();
        assert!(svc.mqtt_options().is_ok());

        svc.cfg.broker = "ws://mqtt.example.com".to_string();
        assert!(svc.mqtt_options().is_err());
    }

    #[test]
    fn mqtt_broker_log_target_never_contains_credentials() {
        let target =
            mqtt_broker_log_target("tcp://log-user:log-secret@mqtt.example.com:1883", false)
                .unwrap();
        assert_eq!(target.scheme, "tcp");
        assert_eq!(target.host, "mqtt.example.com");
        assert_eq!(target.port, 1883);

        let rendered = format!("{target:?}");
        assert!(!rendered.contains("log-user"));
        assert!(!rendered.contains("log-secret"));
    }

    #[test]
    fn qos_and_node_status_helpers_normalize_values() {
        let mut svc = service_with_snapshot();

        svc.cfg.qos = 0;
        assert_eq!(svc.qos(), QoS::AtMostOnce);
        svc.cfg.qos = 2;
        assert_eq!(svc.qos(), QoS::ExactlyOnce);
        svc.cfg.qos = 7;
        assert_eq!(svc.qos(), QoS::AtLeastOnce);

        let outcome = SyncOutcome {
            success: true,
            updated: true,
            already_running: false,
            message: "snapshot applied".to_string(),
            version: 42,
            elapsed_ms: 12,
        };
        let status = svc
            .node_status(Some("req-1"), "sync_command", STATUS_OK, true)
            .with_message("done")
            .with_syncflag(Some("force"))
            .with_outcome(Some(&outcome));

        assert_eq!(status.request_id.as_deref(), Some("req-1"));
        assert_eq!(status.message.as_deref(), Some("done"));
        assert_eq!(status.syncflag.as_deref(), Some("force"));
        assert!(status.success);
        assert!(status.updated);
        assert_eq!(status.snapshot_version, 42);
        assert_eq!(status.snapshot_schema_version, crate::model::SCHEMA_VERSION);
        assert_eq!(status.elapsed_ms, Some(12));
    }

    #[test]
    fn startup_status_reflects_whether_a_snapshot_is_loaded() {
        let svc = service_with_snapshot();
        let synced = svc.startup_status();
        assert_eq!(synced.status, "synced");
        assert!(synced.success);
        assert_eq!(synced.snapshot_version, 7);

        svc.engine.replace(Snapshot::empty());
        let starting = svc.startup_status();
        assert_eq!(starting.status, "starting");
        assert!(!starting.success);
        assert_eq!(starting.snapshot_version, 0);
    }

    #[tokio::test]
    async fn sync_command_throttle_allows_first_and_rejects_second() {
        let svc = service_with_snapshot();

        assert!(svc.allow_sync_command().await);
        assert!(!svc.allow_sync_command().await);
    }

    #[tokio::test]
    async fn probe_trace_command_arms_valid_requests_and_rejects_bad_ones() {
        let svc = service_with_snapshot();
        let (client, _eventloop) = AsyncClient::new(svc.mqtt_options().unwrap(), 8);

        svc.handle_probe_trace_command(client.clone(), b"not json")
            .await;
        svc.handle_probe_trace_command(
            client.clone(),
            br#"{"reply_topic":"elsewhere","data":{"username":"alice"}}"#,
        )
        .await;
        svc.handle_probe_trace_command(
            client,
            br#"{
                "request_id":"probe-1",
                "reply_topic":"rove/replies/probe-1",
                "data":{
                    "username":"alice",
                    "target_host":"example.com",
                    "target_port":443,
                    "protocol":"HTTP",
                    "listener":"https-in",
                    "ttl_secs":999
                }
            }"#,
        )
        .await;

        let mut report_rx = svc.trace_rx.lock().await;
        drop(report_rx.try_recv());
    }

    fn decode_diag_command(payload: &[u8]) -> DiagnosticCommandMessage {
        serde_json::from_slice(payload).expect("valid diagnostic command json")
    }

    fn outbound_error_candidate(username: &str) -> crate::trace::TraceCandidate {
        crate::trace::TraceCandidate {
            listener: "https-in".to_string(),
            protocol: "http".to_string(),
            client_addr: Some("198.51.100.20:5000".to_string()),
            username: Some(username.to_string()),
            target_host: Some("example.com".to_string()),
            target_port: Some(443),
            traffic: None,
            sniff: None,
            decision: Some("upstream".to_string()),
            egress: None,
            chain_member: None,
            attempts: None,
            result: crate::trace::TraceResult::Error,
            failure_stage: Some("outbound".to_string()),
            message: Some("upstream connect failed".to_string()),
            snapshot_version: 7,
            duration_ms: 12,
        }
    }

    #[test]
    fn resolve_event_types_defaults_to_all_and_filters_unknown_tokens() {
        assert_eq!(resolve_event_types(None).len(), 5);
        assert_eq!(resolve_event_types(Some(&Vec::new())).len(), 5);

        let picked = resolve_event_types(Some(&vec!["auth".to_string(), "policy".to_string()]));
        assert_eq!(
            picked,
            HashSet::from([DiagnosticEventType::Auth, DiagnosticEventType::Policy])
        );

        let filtered = resolve_event_types(Some(&vec!["auth".to_string(), "nope".to_string()]));
        assert_eq!(filtered, HashSet::from([DiagnosticEventType::Auth]));
    }

    #[test]
    fn plan_diagnostic_start_validates_reply_topic_username_and_ttl() {
        let svc = service_with_snapshot();

        let plan = svc.plan_diagnostic_start(&decode_diag_command(
            br#"{"reply_topic":"elsewhere","data":{"username":"alice"}}"#,
        ));
        assert!(matches!(plan, DiagnosticStartPlan::Ignore));

        let plan = svc.plan_diagnostic_start(&decode_diag_command(
            br#"{"request_id":"d-nou","reply_topic":"rove/replies/d-nou","data":{}}"#,
        ));
        match plan {
            DiagnosticStartPlan::BadRequest {
                request_id,
                message,
                ..
            } => {
                assert_eq!(request_id, "d-nou");
                assert_eq!(message, "username is required");
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }

        let plan = svc.plan_diagnostic_start(&decode_diag_command(
            br#"{
                "request_id":"d1",
                "reply_topic":"rove/replies/d1",
                "data":{
                    "username":"alice",
                    "target_host":"example.com",
                    "target_port":443,
                    "protocol":"HTTP",
                    "listener":"https-in",
                    "event_types":["auth","outbound"],
                    "ttl_secs":9999
                }
            }"#,
        ));
        match plan {
            DiagnosticStartPlan::Arm {
                reply_topic,
                request_id,
                spec,
            } => {
                assert_eq!(reply_topic, "rove/replies/d1");
                assert_eq!(request_id, "d1");
                assert_eq!(spec.username, "alice");
                assert_eq!(spec.target_host.as_deref(), Some("example.com"));
                assert_eq!(spec.target_port, Some(443));
                assert_eq!(spec.protocol.as_deref(), Some("http"));
                assert_eq!(spec.listener.as_deref(), Some("https-in"));
                // ttl clamped to the configured 300s maximum.
                assert_eq!(spec.ttl, Duration::from_secs(300));
                assert_eq!(
                    spec.event_types,
                    HashSet::from([DiagnosticEventType::Auth, DiagnosticEventType::Outbound])
                );
            }
            other => panic!("expected Arm, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn diagnostics_command_arms_records_and_cancels_sessions() {
        let svc = service_with_snapshot();
        let (client, _eventloop) = AsyncClient::new(svc.mqtt_options().unwrap(), 8);

        // Malformed payloads are swallowed without panicking.
        svc.handle_diagnostics_command(client.clone(), b"not json")
            .await;

        // A missing command on the dedicated topic defaults to start.
        svc.handle_diagnostics_command(
            client.clone(),
            br#"{"request_id":"d1","reply_topic":"rove/replies/d1","data":{"username":"alice","ttl_secs":30}}"#,
        )
        .await;

        // The armed session now fans a matching outcome out as an event.
        svc.diagnostics.record(&outbound_error_candidate("alice"));
        {
            let mut rx = svc.diag_rx.lock().await;
            let envelope = rx.try_recv().expect("diagnostic event enqueued");
            assert_eq!(envelope.reply_topic, "rove/replies/d1");
            assert_eq!(envelope.event.event_type, DiagnosticEventType::Outbound);
        }

        // Cancel removes the session (summary published); a second cancel finds nothing.
        svc.handle_diagnostics_command(
            client.clone(),
            br#"{"command":"diagnostic_session_cancel","request_id":"d1"}"#,
        )
        .await;
        assert!(svc.diagnostics.cancel("d1").is_none());
    }

    #[test]
    fn first_non_empty_trims_and_skips_blank_values() {
        assert_eq!(
            first_non_empty([Some(""), Some("  "), Some(" value ")]),
            Some("value")
        );
        assert_eq!(first_non_empty([None, Some("\t")]), None);
    }
}
