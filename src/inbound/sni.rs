//! TLS-transparent application egress gateway.
//!
//! This is deliberately not a reverse proxy: it reads only the bounded TLS
//! ClientHello necessary to obtain SNI, verifies that name against a closed
//! server-side allowlist, and then relays the original TLS bytes unchanged.
//! The gateway never accepts a client-selected arbitrary origin and never
//! terminates the TLS session.

use super::Ctx;
use crate::config::SniGatewayConfig;
use crate::error::ProxyError;
use crate::io::{splice, IoStream, PrefixedIo, SpliceStats};
use crate::model::Decision;
use crate::outbound;
use crate::outbound::decision_label as decision_name;
use crate::sniff::{capture_prefix, SniffObservation, SniffOutcome, SniffProtocol};
use crate::trace::{TraceCandidate, TraceResult, TrafficIdentity};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::debug;

pub(crate) async fn serve<S: IoStream>(
    mut stream: S,
    ctx: Arc<Ctx>,
    peer: SocketAddr,
    gateway: SniGatewayConfig,
    local: Option<SocketAddr>,
) -> anyhow::Result<()> {
    let _listener_guard = ctx.stats.track_listener(&ctx.listener);
    let started = Instant::now();

    // An L4 gateway has no client-side credential. The configured identity is
    // still checked for existence and expiry for every connection, so a stale
    // snapshot never becomes an anonymous relay.
    let auth = match ctx.engine.authenticate_bound_identity(&gateway.identity) {
        Ok(auth) => auth,
        Err(ProxyError::Expired) => {
            report(
                &ctx,
                started,
                peer,
                TraceFields {
                    username: Some(gateway.identity.clone()),
                    failure_stage: Some("auth"),
                    message: Some("bound gateway identity expired"),
                    ..TraceFields::default()
                },
            )
            .await;
            return Ok(());
        }
        Err(_) => {
            report(
                &ctx,
                started,
                peer,
                TraceFields {
                    username: Some(gateway.identity.clone()),
                    failure_stage: Some("auth"),
                    message: Some("bound gateway identity unavailable"),
                    ..TraceFields::default()
                },
            )
            .await;
            return Ok(());
        }
    };

    // Reserve the bound identity before reading untrusted ClientHello bytes.
    // This makes the existing per-user connection ceiling also bound slow or
    // incomplete TLS handshakes instead of letting them sit outside the quota.
    let _connection_permit = match ctx
        .engine
        .acquire_connection(&gateway.identity, auth.max_connections)
    {
        Ok(permit) => permit,
        Err(ProxyError::ConnectionLimitExceeded { .. }) => {
            report(
                &ctx,
                started,
                peer,
                TraceFields {
                    username: Some(gateway.identity.clone()),
                    ingress_mode: Some("sni"),
                    failure_stage: Some("limit"),
                    message: Some("connection limit exceeded"),
                    ..TraceFields::default()
                },
            )
            .await;
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    // SNI has no port field. Preserve the port the application connected to:
    // ordinary HTTPS is therefore 443, while a deliberately configured custom
    // TLS listener transparently reaches the same origin port.
    let origin_port = match local.map(|addr| addr.port()).filter(|port| *port != 0) {
        Some(port) => port,
        None => {
            report(
                &ctx,
                started,
                peer,
                TraceFields {
                    username: Some(gateway.identity.clone()),
                    failure_stage: Some("listener"),
                    message: Some("gateway listener port unavailable"),
                    ..TraceFields::default()
                },
            )
            .await;
            return Ok(());
        }
    };

    let captured = match capture_prefix(&mut stream, ctx.sniff.max_bytes, ctx.sniff.timeout()).await
    {
        Ok(captured) => captured,
        Err(error) => {
            debug!(peer = %peer, error = %error, "sni gateway ClientHello read failed");
            report(
                &ctx,
                started,
                peer,
                TraceFields {
                    username: Some(gateway.identity.clone()),
                    failure_stage: Some("sni_read"),
                    message: Some("ClientHello read failed"),
                    ..TraceFields::default()
                },
            )
            .await;
            return Ok(());
        }
    };

    let observation = captured.observation.clone();
    let host = match trusted_sni(&observation) {
        Some(host) => host.to_string(),
        None => {
            // Missing SNI, malformed TLS, non-TLS, timeout, and a prefix that
            // exceeds the bounded read window all stop here. No fallback target
            // exists by design.
            report(
                &ctx,
                started,
                peer,
                TraceFields {
                    username: Some(gateway.identity.clone()),
                    sniff: Some(observation),
                    failure_stage: Some("sni"),
                    message: Some("valid TLS SNI is required"),
                    ..TraceFields::default()
                },
            )
            .await;
            return Ok(());
        }
    };

    if !gateway.allows(&host) {
        report(
            &ctx,
            started,
            peer,
            TraceFields {
                username: Some(gateway.identity.clone()),
                target_host: Some(host),
                target_port: Some(origin_port),
                sniff: Some(observation),
                ingress_mode: Some("sni"),
                failure_stage: Some("sni_allowlist"),
                message: Some("SNI is not an allowed origin"),
                ..TraceFields::default()
            },
        )
        .await;
        return Ok(());
    }

    let resolved = ctx.engine.decide_with_sniff(&gateway.identity, &host, None);
    let decision = decision_name(&resolved.decision);
    let attribution = resolved.attribution();
    if matches!(&resolved.decision, Decision::Block) {
        report(
            &ctx,
            started,
            peer,
            TraceFields {
                username: Some(gateway.identity.clone()),
                target_host: Some(host.clone()),
                target_port: Some(origin_port),
                decision: Some(decision),
                sniff: Some(observation),
                policy: Some(attribution),
                ingress_mode: Some("sni"),
                origin_id: Some(host),
                failure_stage: Some("policy"),
                message: Some("blocked by policy"),
                ..TraceFields::default()
            },
        )
        .await;
        return Ok(());
    }

    let (outbound, egress) = match outbound::connect(
        resolved.decision,
        &host,
        origin_port,
        &ctx.egress,
    )
    .await
    {
        Ok(established) => established,
        Err(error) => {
            debug!(peer = %peer, target = %host, error = %error, "sni gateway outbound connect failed");
            report(
                &ctx,
                started,
                peer,
                TraceFields {
                    username: Some(gateway.identity.clone()),
                    target_host: Some(host.clone()),
                    target_port: Some(origin_port),
                    decision: Some(decision),
                    attempts: error.chain_attempts(),
                    sniff: Some(observation),
                    policy: Some(attribution),
                    ingress_mode: Some("sni"),
                    origin_id: Some(host),
                    failure_stage: Some(error.failure_stage()),
                    message: Some("upstream connect failed"),
                    ..TraceFields::default()
                },
            )
            .await;
            return Ok(());
        }
    };

    let _egress_guard = ctx.stats.track_egress(&egress.label);
    let splice_result = splice(
        PrefixedIo::new(captured.bytes, stream),
        outbound,
        auth.up_rate,
        auth.down_rate,
    )
    .await;
    match splice_result {
        Ok(SpliceStats {
            bytes_up,
            bytes_down,
        }) => {
            report(
                &ctx,
                started,
                peer,
                TraceFields {
                    username: Some(gateway.identity),
                    target_host: Some(host.clone()),
                    target_port: Some(origin_port),
                    decision: Some(decision),
                    egress: Some(egress.label),
                    chain_member: egress.member_id,
                    attempts: Some(egress.attempts),
                    sniff: Some(observation),
                    policy: Some(attribution),
                    ingress_mode: Some("sni"),
                    origin_id: Some(host),
                    result: TraceResult::Ok,
                    bytes_up,
                    bytes_down,
                    ..TraceFields::default()
                },
            )
            .await;
        }
        Err(error) => {
            debug!(peer = %peer, target = %host, error = %error, "sni gateway splice failed");
            report(
                &ctx,
                started,
                peer,
                TraceFields {
                    username: Some(gateway.identity),
                    target_host: Some(host.clone()),
                    target_port: Some(origin_port),
                    decision: Some(decision),
                    egress: Some(egress.label),
                    chain_member: egress.member_id,
                    attempts: Some(egress.attempts),
                    sniff: Some(observation),
                    policy: Some(attribution),
                    ingress_mode: Some("sni"),
                    origin_id: Some(host),
                    failure_stage: Some("splice"),
                    message: Some("TLS stream relay failed"),
                    ..TraceFields::default()
                },
            )
            .await;
        }
    }
    Ok(())
}

fn trusted_sni(observation: &SniffObservation) -> Option<&str> {
    (observation.outcome == SniffOutcome::Matched
        && observation.protocol == Some(SniffProtocol::Tls))
    .then_some(observation.host.as_deref())
    .flatten()
}

struct TraceFields {
    username: Option<String>,
    target_host: Option<String>,
    target_port: Option<u16>,
    decision: Option<String>,
    egress: Option<String>,
    chain_member: Option<String>,
    attempts: Option<u32>,
    sniff: Option<SniffObservation>,
    policy: Option<crate::model::PolicyAttribution>,
    ingress_mode: Option<&'static str>,
    origin_id: Option<String>,
    result: TraceResult,
    failure_stage: Option<&'static str>,
    message: Option<&'static str>,
    bytes_up: u64,
    bytes_down: u64,
}

impl Default for TraceFields {
    fn default() -> Self {
        TraceFields {
            username: None,
            target_host: None,
            target_port: None,
            decision: None,
            egress: None,
            chain_member: None,
            attempts: None,
            sniff: None,
            policy: None,
            ingress_mode: None,
            origin_id: None,
            result: TraceResult::Error,
            failure_stage: None,
            message: None,
            bytes_up: 0,
            bytes_down: 0,
        }
    }
}

async fn report(ctx: &Arc<Ctx>, started: Instant, peer: SocketAddr, fields: TraceFields) {
    ctx.stats
        .record_listener_bytes(&ctx.listener, fields.bytes_up, fields.bytes_down);
    if let Some(observation) = &fields.sniff {
        ctx.stats.record_sniff(&ctx.listener, observation.outcome);
    }
    if let Some(decision) = fields.egress.as_deref().or(fields.decision.as_deref()) {
        if decision != "block" {
            ctx.stats
                .record_egress_bytes(decision, fields.bytes_up, fields.bytes_down);
        }
    }

    if ctx.tracer.is_none() && ctx.diagnostics.is_none() && ctx.access_log.is_none() {
        return;
    }

    let traffic = fields
        .target_host
        .as_ref()
        .zip(fields.target_port)
        .map(|(host, port)| {
            let mut identity = TrafficIdentity::new(host.clone(), port);
            if let Some(policy) = fields.policy.clone() {
                identity = identity.with_policy(policy);
            }
            if let Some(observation) = fields.sniff.clone() {
                identity = identity.with_observation(observation);
            }
            if let Some(ingress_mode) = fields.ingress_mode {
                identity = identity.with_ingress_mode(ingress_mode);
            }
            if let Some(origin_id) = fields.origin_id.clone() {
                identity =
                    identity.with_gateway_origin(fields.ingress_mode.unwrap_or("sni"), origin_id);
            }
            identity
        });
    let candidate = TraceCandidate {
        listener: ctx.listener.clone(),
        protocol: "sni".to_string(),
        client_addr: Some(peer.to_string()),
        username: fields.username,
        target_host: fields.target_host,
        target_port: fields.target_port,
        traffic,
        sniff: fields.sniff.clone(),
        decision: fields.decision,
        egress: fields.egress,
        chain_member: fields.chain_member,
        attempts: fields.attempts,
        result: fields.result,
        failure_stage: fields.failure_stage.map(str::to_string),
        message: fields.message.map(str::to_string),
        snapshot_version: ctx.engine.version(),
        duration_ms: started.elapsed().as_millis(),
    };
    if let Some(diagnostics) = &ctx.diagnostics {
        diagnostics.record(&candidate);
    }
    if let Some(access_log) = &ctx.access_log {
        access_log.record(&candidate, fields.bytes_up, fields.bytes_down);
    }
    if let Some(tracer) = &ctx.tracer {
        tracer.finish(candidate).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_only_accepts_a_matched_tls_sni() {
        let matched = SniffObservation {
            outcome: SniffOutcome::Matched,
            protocol: Some(SniffProtocol::Tls),
            host: Some("api.example.com".to_string()),
        };
        assert_eq!(trusted_sni(&matched), Some("api.example.com"));

        for observation in [
            SniffObservation {
                outcome: SniffOutcome::Matched,
                protocol: Some(SniffProtocol::Tls),
                host: None,
            },
            SniffObservation {
                outcome: SniffOutcome::Matched,
                protocol: Some(SniffProtocol::Http),
                host: Some("api.example.com".to_string()),
            },
            SniffObservation {
                outcome: SniffOutcome::LimitExceeded,
                protocol: None,
                host: None,
            },
            SniffObservation {
                outcome: SniffOutcome::Malformed,
                protocol: None,
                host: None,
            },
        ] {
            assert!(trusted_sni(&observation).is_none());
        }
    }
}
