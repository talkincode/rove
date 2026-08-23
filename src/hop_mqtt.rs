//! Optional MQTT channel for remote `rove-hop doctor egress`.
//!
//! Isolated from the edge `MqttService`: hop has no snapshot, user query,
//! probe arm, or diagnostic session. Default off. Never runs on the splice
//! path. Replies reuse `egress_diagnostic::run` so the JSON is isomorphic
//! with `rove-hop doctor egress --json`.

use crate::egress_diagnostic::{self, EgressDiagnosticConfig, EgressDiagnosticReport};
use crate::mqtt::allowed_reply_topic;
use rumqttc::{AsyncClient, Event, Incoming, MqttOptions, QoS, Transport};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tracing::{info, warn};
use url::Url;

const EVENT: &str = "hop_egress_doctor";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
const MIN_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_MAX_HOPS: u8 = 20;
const DEFAULT_REPLY_PREFIX: &str = "rove/replies/";

#[derive(Debug, Clone)]
pub struct HopMqttConfig {
    pub broker: String,
    pub hop_id: String,
    pub client_id: String,
    pub username: String,
    pub password: String,
    pub reply_topic_prefix: String,
}

impl HopMqttConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.broker.trim().is_empty(),
            "mqtt broker is required when hop MQTT is enabled"
        );
        validate_hop_id(&self.hop_id)?;
        let prefix = self.effective_reply_prefix();
        anyhow::ensure!(
            !prefix.is_empty() && !prefix.contains(['#', '+', ' ', '\t', '\r', '\n']),
            "mqtt reply prefix must be a concrete topic prefix"
        );
        Ok(())
    }

    pub fn doctor_topic(&self) -> String {
        doctor_topic(&self.hop_id)
    }

    pub fn effective_reply_prefix(&self) -> String {
        let prefix = self.reply_topic_prefix.trim();
        if prefix.is_empty() {
            DEFAULT_REPLY_PREFIX.to_string()
        } else {
            prefix.to_string()
        }
    }

    pub fn effective_client_id(&self) -> String {
        let id = self.client_id.trim();
        if id.is_empty() {
            format!("rove-hop-{}", self.hop_id)
        } else {
            id.to_string()
        }
    }
}

pub fn doctor_topic(hop_id: &str) -> String {
    format!("rove/hop/{hop_id}/doctor")
}

pub fn validate_hop_id(hop_id: &str) -> anyhow::Result<()> {
    let hop_id = hop_id.trim();
    anyhow::ensure!(!hop_id.is_empty(), "mqtt hop id must not be empty");
    anyhow::ensure!(
        hop_id.len() <= 64,
        "mqtt hop id must be at most 64 characters"
    );
    anyhow::ensure!(
        hop_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
        "mqtt hop id {hop_id:?} must be [A-Za-z0-9._-]"
    );
    Ok(())
}

#[derive(Clone)]
pub struct HopMqttService {
    cfg: HopMqttConfig,
    inflight: Arc<Semaphore>,
}

impl HopMqttService {
    pub fn new(cfg: HopMqttConfig) -> anyhow::Result<Self> {
        cfg.validate()?;
        Ok(HopMqttService {
            cfg,
            inflight: Arc::new(Semaphore::new(1)),
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let mqtt_options = mqtt_options(&self.cfg)?;
        let broker = broker_log_target(&self.cfg.broker)?;
        let (client, mut eventloop) = AsyncClient::new(mqtt_options, 16);
        info!(
            hop_id = %self.cfg.hop_id,
            client_id = %self.cfg.effective_client_id(),
            broker_scheme = %broker.scheme,
            broker_host = %broker.host,
            broker_port = broker.port,
            topic = %self.cfg.doctor_topic(),
            "hop mqtt doctor starting"
        );

        loop {
            match eventloop.poll().await {
                Ok(Event::Incoming(Incoming::ConnAck(_))) => {
                    let topic = self.cfg.doctor_topic();
                    if let Err(e) = client.subscribe(&topic, QoS::AtLeastOnce).await {
                        warn!(topic = %topic, error = %e, "hop mqtt subscribe failed");
                    } else {
                        info!(topic = %topic, "hop mqtt subscribed");
                    }
                }
                Ok(Event::Incoming(Incoming::Publish(publish))) => {
                    if publish.topic == self.cfg.doctor_topic() {
                        self.handle_doctor(client.clone(), publish.payload.to_vec());
                    }
                }
                Ok(Event::Incoming(_)) | Ok(Event::Outgoing(_)) => {}
                Err(e) => {
                    warn!(error = %e, "hop mqtt event loop error");
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
            }
        }
    }

    fn handle_doctor(&self, client: AsyncClient, payload: Vec<u8>) {
        let cfg = self.cfg.clone();
        let inflight = self.inflight.clone();
        tokio::spawn(async move {
            match plan_doctor_command(&cfg, &payload) {
                PlanOutcome::Drop => {}
                PlanOutcome::Reject(reject) => {
                    publish_json(
                        &client,
                        &reject.reply_topic,
                        &reject.reply_with_hop(&cfg.hop_id),
                    )
                    .await;
                }
                PlanOutcome::Run(plan) => {
                    let Ok(_permit) = inflight.try_acquire_owned() else {
                        publish_json(
                            &client,
                            &plan.reply_topic,
                            &status_reply(
                                plan.request_id.clone(),
                                &cfg.hop_id,
                                "throttled",
                                "another hop doctor request is still running",
                            ),
                        )
                        .await;
                        return;
                    };
                    match run_planned_doctor(&cfg, &plan).await {
                        Ok(reply) => publish_json(&client, &plan.reply_topic, &reply).await,
                        Err(message) => {
                            publish_json(
                                &client,
                                &plan.reply_topic,
                                &status_reply(
                                    plan.request_id.clone(),
                                    &cfg.hop_id,
                                    "bad_request",
                                    &message,
                                ),
                            )
                            .await;
                        }
                    }
                }
            }
        });
    }
}

#[derive(Debug, Deserialize)]
struct HopDoctorCommand {
    command: Option<String>,
    request_id: Option<String>,
    reply_topic: Option<String>,
    #[serde(default)]
    data: HopDoctorData,
}

#[derive(Debug, Default, Deserialize)]
struct HopDoctorData {
    request_id: Option<String>,
    target: Option<String>,
    trace: Option<bool>,
    timeout_ms: Option<u64>,
    max_hops: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct PlannedDoctor {
    pub request_id: Option<String>,
    pub reply_topic: String,
    pub target: String,
    pub trace: bool,
    pub timeout: Duration,
    pub max_hops: u8,
}

#[derive(Debug)]
pub enum PlanOutcome {
    Drop,
    Reject(DoctorReject),
    Run(PlannedDoctor),
}

#[derive(Debug)]
pub struct DoctorReject {
    pub request_id: Option<String>,
    pub reply_topic: String,
    pub status: &'static str,
    pub message: String,
}

impl DoctorReject {
    pub fn reply_with_hop(&self, hop_id: &str) -> HopDoctorStatusReply {
        status_reply(self.request_id.clone(), hop_id, self.status, &self.message)
    }
}

#[derive(Debug, Serialize)]
pub struct HopDoctorReply {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub hop_id: String,
    pub event: &'static str,
    #[serde(flatten)]
    pub report: EgressDiagnosticReport,
}

#[derive(Debug, Serialize)]
pub struct HopDoctorStatusReply {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub hop_id: String,
    pub event: &'static str,
    pub status: String,
    pub message: String,
}

fn status_reply(
    request_id: Option<String>,
    hop_id: &str,
    status: &str,
    message: &str,
) -> HopDoctorStatusReply {
    HopDoctorStatusReply {
        request_id,
        hop_id: hop_id.to_string(),
        event: EVENT,
        status: status.to_string(),
        message: message.to_string(),
    }
}

pub fn plan_doctor_command(cfg: &HopMqttConfig, payload: &[u8]) -> PlanOutcome {
    let parsed: HopDoctorCommand = match serde_json::from_slice(payload) {
        Ok(parsed) => parsed,
        Err(_) => return PlanOutcome::Drop,
    };
    let request_id = first_non_empty([
        parsed.request_id.as_deref(),
        parsed.data.request_id.as_deref(),
    ]);
    let Some(reply_topic) = parsed
        .reply_topic
        .as_deref()
        .map(str::trim)
        .filter(|topic| !topic.is_empty())
    else {
        return PlanOutcome::Drop;
    };
    if !allowed_reply_topic(reply_topic, &cfg.effective_reply_prefix()) {
        return PlanOutcome::Drop;
    }

    if let Some(command) = parsed
        .command
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    {
        if !matches!(
            command,
            "hop_egress_doctor" | "doctor" | "egress" | "egress_doctor"
        ) {
            return PlanOutcome::Reject(DoctorReject {
                request_id,
                reply_topic: reply_topic.to_string(),
                status: "bad_request",
                message: format!("unknown hop doctor command {command:?}"),
            });
        }
    }

    let Some(target) = parsed
        .data
        .target
        .as_deref()
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .map(ToOwned::to_owned)
    else {
        return PlanOutcome::Reject(DoctorReject {
            request_id,
            reply_topic: reply_topic.to_string(),
            status: "bad_request",
            message: "target is required".to_string(),
        });
    };

    let timeout = clamp_timeout(
        parsed
            .data
            .timeout_ms
            .map(Duration::from_millis)
            .unwrap_or(DEFAULT_TIMEOUT),
    );
    let max_hops = parsed
        .data
        .max_hops
        .filter(|hops| (1..=64).contains(hops))
        .unwrap_or(DEFAULT_MAX_HOPS);

    PlanOutcome::Run(PlannedDoctor {
        request_id,
        reply_topic: reply_topic.to_string(),
        target,
        trace: parsed.data.trace.unwrap_or(false),
        timeout,
        max_hops,
    })
}

async fn run_planned_doctor(
    cfg: &HopMqttConfig,
    plan: &PlannedDoctor,
) -> Result<HopDoctorReply, String> {
    let target =
        egress_diagnostic::select_target(Some(plan.target.as_str())).map_err(|e| e.to_string())?;
    let report = egress_diagnostic::run(EgressDiagnosticConfig {
        target,
        trace: plan.trace,
        timeout: plan.timeout,
        max_hops: plan.max_hops,
        node_id: cfg.hop_id.clone(),
    })
    .await;
    Ok(HopDoctorReply {
        request_id: plan.request_id.clone(),
        hop_id: cfg.hop_id.clone(),
        event: EVENT,
        report,
    })
}

fn clamp_timeout(timeout: Duration) -> Duration {
    timeout.clamp(MIN_TIMEOUT, MAX_TIMEOUT)
}

fn first_non_empty<const N: usize>(values: [Option<&str>; N]) -> Option<String> {
    values
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn mqtt_options(cfg: &HopMqttConfig) -> anyhow::Result<MqttOptions> {
    let url = Url::parse(cfg.broker.trim())
        .map_err(|_| anyhow::anyhow!("mqtt broker must be a URL such as tcp://127.0.0.1:1883"))?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("mqtt broker host is required"))?;
    let scheme = url.scheme().to_ascii_lowercase();
    let transport = match scheme.as_str() {
        "tcp" | "mqtt" => Transport::tcp(),
        "ssl" | "tls" | "tcps" | "mqtts" => Transport::tls_with_default_config(),
        other => anyhow::bail!("unsupported mqtt broker scheme {other:?}"),
    };
    let port = url.port().unwrap_or(match scheme.as_str() {
        "tcp" | "mqtt" => 1883,
        _ => 8883,
    });
    let mut options = MqttOptions::new(cfg.effective_client_id(), host, port);
    options.set_transport(transport);
    options.set_keep_alive(Duration::from_secs(30));
    options.set_clean_session(true);
    if !cfg.username.trim().is_empty() {
        options.set_credentials(cfg.username.trim(), cfg.password.clone());
    } else if !url.username().is_empty() {
        options.set_credentials(url.username(), url.password().unwrap_or_default());
    }
    Ok(options)
}

struct BrokerLogTarget {
    scheme: String,
    host: String,
    port: u16,
}

fn broker_log_target(broker: &str) -> anyhow::Result<BrokerLogTarget> {
    let url = Url::parse(broker.trim())?;
    let scheme = url.scheme().to_ascii_lowercase();
    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("mqtt broker host is required"))?
        .to_string();
    let port = url.port().unwrap_or(match scheme.as_str() {
        "tcp" | "mqtt" => 1883,
        _ => 8883,
    });
    Ok(BrokerLogTarget { scheme, host, port })
}

async fn publish_json<T: Serialize>(client: &AsyncClient, topic: &str, payload: &T) {
    match serde_json::to_vec(payload) {
        Ok(data) => {
            if let Err(e) = client.publish(topic, QoS::AtLeastOnce, false, data).await {
                warn!(topic, error = %e, "hop mqtt publish failed");
            }
        }
        Err(e) => warn!(error = %e, "hop mqtt serialize failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> HopMqttConfig {
        HopMqttConfig {
            broker: "tcp://127.0.0.1:1883".to_string(),
            hop_id: "rove-hop-jp".to_string(),
            client_id: String::new(),
            username: String::new(),
            password: "mqtt-secret".to_string(),
            reply_topic_prefix: "rove/replies/".to_string(),
        }
    }

    #[test]
    fn doctor_topic_is_namespaced_by_hop_id() {
        assert_eq!(doctor_topic("rove-hop-jp"), "rove/hop/rove-hop-jp/doctor");
    }

    #[test]
    fn hop_id_rejects_wildcards_and_slashes() {
        assert!(validate_hop_id("rove-hop-jp").is_ok());
        assert!(validate_hop_id("rove/hop").is_err());
        assert!(validate_hop_id("hop+#").is_err());
        assert!(validate_hop_id("").is_err());
    }

    #[test]
    fn plan_requires_target_and_allows_isomorphic_command() {
        let outcome = plan_doctor_command(
            &cfg(),
            br#"{
                "command":"hop_egress_doctor",
                "request_id":"doc-1",
                "reply_topic":"rove/replies/hop-doctor-doc-1",
                "data":{"target":"api.openai.com:443","trace":true,"timeout_ms":1500}
            }"#,
        );
        match outcome {
            PlanOutcome::Run(plan) => {
                assert_eq!(plan.request_id.as_deref(), Some("doc-1"));
                assert_eq!(plan.reply_topic, "rove/replies/hop-doctor-doc-1");
                assert_eq!(plan.target, "api.openai.com:443");
                assert!(plan.trace);
                assert_eq!(plan.timeout, Duration::from_millis(1500));
            }
            other => panic!("expected run, got {other:?}"),
        }
    }

    #[test]
    fn plan_defaults_trace_off_and_clamps_timeout() {
        let outcome = plan_doctor_command(
            &cfg(),
            br#"{
                "request_id":"doc-2",
                "reply_topic":"rove/replies/hop-doctor-doc-2",
                "data":{"target":"127.0.0.1:9","timeout_ms":1}
            }"#,
        );
        match outcome {
            PlanOutcome::Run(plan) => {
                assert!(!plan.trace);
                assert_eq!(plan.timeout, MIN_TIMEOUT);
            }
            other => panic!("expected run, got {other:?}"),
        }
    }

    #[test]
    fn plan_rejects_missing_target_on_valid_reply_topic() {
        let outcome = plan_doctor_command(
            &cfg(),
            br#"{"request_id":"doc-3","reply_topic":"rove/replies/hop-doctor-doc-3","data":{}}"#,
        );
        match outcome {
            PlanOutcome::Reject(reject) => {
                assert_eq!(reject.status, "bad_request");
                assert!(reject.message.contains("target"));
                let raw = serde_json::to_string(&reject.reply_with_hop("rove-hop-jp")).unwrap();
                assert!(!raw.contains("mqtt-secret"));
            }
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn plan_drops_reply_topics_outside_prefix() {
        let outcome = plan_doctor_command(
            &cfg(),
            br#"{"reply_topic":"rove/other/doc","data":{"target":"example.com"}}"#,
        );
        assert!(matches!(outcome, PlanOutcome::Drop));
    }

    #[test]
    fn plan_drops_wildcard_reply_topics() {
        let outcome = plan_doctor_command(
            &cfg(),
            br#"{"reply_topic":"rove/replies/#","data":{"target":"example.com"}}"#,
        );
        assert!(matches!(outcome, PlanOutcome::Drop));
    }
}
