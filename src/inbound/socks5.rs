//! SOCKS5 inbound (CONNECT only) with mandatory username/password auth (RFC 1929).

use super::Ctx;
use crate::config::SniffMode;
use crate::io::{splice, IoStream, PrefixedIo};
use crate::model::Decision;
use crate::outbound;
use crate::outbound::decision_label as decision_name;
use crate::sniff::{capture_prefix, SniffObservation, SniffingIo};
use crate::trace::{TraceCandidate, TraceResult, TrafficIdentity};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tracing::debug;

const VER: u8 = 0x05;

pub async fn serve<S: IoStream>(
    mut stream: S,
    ctx: Arc<Ctx>,
    peer: SocketAddr,
    local: Option<SocketAddr>,
) -> anyhow::Result<()> {
    let _connection_guard = ctx.stats.track_listener(&ctx.listener);
    let started = Instant::now();
    // --- method negotiation: require user/pass (0x02) ---
    let mut hdr = [0u8; 2];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != VER {
        report_trace(
            &ctx,
            started,
            peer,
            TraceFields {
                failure_stage: Some("parse"),
                message: Some("bad socks version"),
                ..TraceFields::default()
            },
        )
        .await;
        return Ok(());
    }
    let mut methods = vec![0u8; hdr[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x02) {
        stream.write_all(&[VER, 0xFF]).await?;
        report_trace(
            &ctx,
            started,
            peer,
            TraceFields {
                failure_stage: Some("auth"),
                message: Some("username/password auth method missing"),
                ..TraceFields::default()
            },
        )
        .await;
        return Ok(());
    }
    stream.write_all(&[VER, 0x02]).await?;

    // --- username/password sub-negotiation (RFC 1929) ---
    let ver = read_u8(&mut stream).await?;
    if ver != 0x01 {
        report_trace(
            &ctx,
            started,
            peer,
            TraceFields {
                failure_stage: Some("auth"),
                message: Some("bad auth subnegotiation version"),
                ..TraceFields::default()
            },
        )
        .await;
        return Ok(());
    }
    let ulen = read_u8(&mut stream).await? as usize;
    let mut ubuf = vec![0u8; ulen];
    stream.read_exact(&mut ubuf).await?;
    let plen = read_u8(&mut stream).await? as usize;
    let mut pbuf = vec![0u8; plen];
    stream.read_exact(&mut pbuf).await?;
    let user = String::from_utf8_lossy(&ubuf).to_string();
    let pass = String::from_utf8_lossy(&pbuf).to_string();

    let auth = match ctx.engine.authenticate(&user, &pass) {
        Ok(a) => a,
        Err(_) => {
            stream.write_all(&[0x01, 0x01]).await?; // auth failure
            report_trace(
                &ctx,
                started,
                peer,
                TraceFields {
                    username: Some(user),
                    failure_stage: Some("auth"),
                    message: Some("authentication failed"),
                    ..TraceFields::default()
                },
            )
            .await;
            return Ok(());
        }
    };
    stream.write_all(&[0x01, 0x00]).await?; // auth success

    // --- request ---
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != VER {
        report_trace(
            &ctx,
            started,
            peer,
            TraceFields {
                username: Some(user),
                failure_stage: Some("parse"),
                message: Some("bad request version"),
                ..TraceFields::default()
            },
        )
        .await;
        return Ok(());
    }
    let cmd = req[1];
    let atyp = req[3];
    // Reject unsupported commands before consuming the address bytes: only
    // CONNECT (0x01) and UDP ASSOCIATE (0x03) carry an address we parse here, so
    // a BIND request that never sends one cannot stall the read.
    if cmd != 0x01 && cmd != 0x03 {
        reply(&mut stream, 0x07).await?; // command not supported
        report_trace(
            &ctx,
            started,
            peer,
            TraceFields {
                username: Some(user),
                failure_stage: Some("parse"),
                message: Some("unsupported socks command"),
                ..TraceFields::default()
            },
        )
        .await;
        return Ok(());
    }
    let host = match atyp {
        0x01 => {
            let mut a = [0u8; 4];
            stream.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        0x04 => {
            let mut a = [0u8; 16];
            stream.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        0x03 => {
            let l = read_u8(&mut stream).await? as usize;
            let mut d = vec![0u8; l];
            stream.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).to_string()
        }
        _ => {
            reply(&mut stream, 0x08).await?; // address type not supported
            report_trace(
                &ctx,
                started,
                peer,
                TraceFields {
                    username: Some(user),
                    failure_stage: Some("parse"),
                    message: Some("unsupported address type"),
                    ..TraceFields::default()
                },
            )
            .await;
            return Ok(());
        }
    };
    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    // UDP ASSOCIATE: hand off to the datagram relay. The host/port parsed above
    // is only the client's advertised UDP source (often 0.0.0.0:0); the real
    // targets are per-datagram, so it is not used as a target here.
    if cmd == 0x03 {
        return super::socks5_udp::serve_associate(stream, ctx, peer, local, user, started).await;
    }

    let resolved = ctx.engine.decide_with_sniff(&user, &host, None);
    let decision_name = decision_name(&resolved.decision);
    if let Decision::Block = resolved.decision {
        debug!(user = %user, target = %host, "blocked by policy");
        reply(&mut stream, 0x02).await?; // connection not allowed by ruleset
        report_trace(
            &ctx,
            started,
            peer,
            TraceFields {
                username: Some(user),
                target_host: Some(host),
                target_port: Some(port),
                decision: Some(decision_name),
                effective_policy_host: Some(resolved.effective_policy_host),
                failure_stage: Some("policy"),
                message: Some("blocked by policy"),
                ..TraceFields::default()
            },
        )
        .await;
        return Ok(());
    }

    let connection_permit = match ctx.engine.acquire_connection(&user, auth.max_connections) {
        Ok(permit) => permit,
        Err(crate::error::ProxyError::ConnectionLimitExceeded { current, max }) => {
            debug!(user = %user, current, max, "connection limit exceeded");
            reply(&mut stream, 0x02).await?; // connection not allowed by ruleset
            report_trace(
                &ctx,
                started,
                peer,
                TraceFields {
                    username: Some(user),
                    target_host: Some(host),
                    target_port: Some(port),
                    decision: Some(decision_name),
                    failure_stage: Some("limit"),
                    message: Some("connection limit exceeded"),
                    ..TraceFields::default()
                },
            )
            .await;
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };

    if ctx.sniff.enabled && ctx.sniff.mode == SniffMode::Route {
        return tunnel_connect_route(
            stream,
            ctx,
            peer,
            started,
            user,
            host,
            port,
            auth.up_rate,
            auth.down_rate,
            connection_permit,
            resolved,
            decision_name,
        )
        .await;
    }

    let (outbound, egress) =
        match outbound::connect(resolved.decision, &host, port, &ctx.egress).await {
            Ok(established) => established,
            Err(e) => {
                debug!(user = %user, target = %host, error = %e, "upstream connect failed");
                let stage = e.failure_stage();
                reply(&mut stream, 0x05).await?; // connection refused
                report_trace(
                    &ctx,
                    started,
                    peer,
                    TraceFields {
                        username: Some(user),
                        target_host: Some(host),
                        target_port: Some(port),
                        decision: Some(decision_name),
                        attempts: e.chain_attempts(),
                        failure_stage: Some(stage),
                        message: Some("upstream connect failed"),
                        ..TraceFields::default()
                    },
                )
                .await;
                return Ok(());
            }
        };

    reply(&mut stream, 0x00).await?;
    // The egress dimension counts *established* tunnels: taken only after
    // the outbound connect succeeded, keyed by the concrete egress
    // ("direct" / "upstream:<addr>" / "reverse:<hop>").
    let _egress_guard = ctx.stats.track_egress(&egress.label);
    debug!(user = %user, listener = %ctx.listener, target = %format!("{host}:{port}"), egress = %egress.label, "tunnel established");
    let (splice_result, sniff_observation) = if ctx.sniff.enabled {
        let (stream, handle) = SniffingIo::new(stream, ctx.sniff.max_bytes, ctx.sniff.timeout());
        let result = splice(stream, outbound, auth.up_rate, auth.down_rate).await;
        (result, Some(handle.observation()))
    } else {
        (
            splice(stream, outbound, auth.up_rate, auth.down_rate).await,
            None,
        )
    };
    drop(connection_permit);
    let (result, stage, message, bytes_up, bytes_down) = match &splice_result {
        Ok(stats) => (
            TraceResult::Ok,
            None,
            None,
            stats.bytes_up,
            stats.bytes_down,
        ),
        Err(_) => (
            TraceResult::Error,
            Some("splice"),
            Some("tunnel io failed"),
            0,
            0,
        ),
    };
    report_trace(
        &ctx,
        started,
        peer,
        TraceFields {
            username: Some(user),
            target_host: Some(host),
            target_port: Some(port),
            decision: Some(decision_name),
            egress: egress.chain_id.is_some().then(|| egress.label.clone()),
            chain_member: egress.member_id.clone(),
            attempts: egress.chain_id.is_some().then_some(egress.attempts),
            result,
            sniff: sniff_observation,
            effective_policy_host: Some(resolved.effective_policy_host),
            failure_stage: stage,
            message,
            bytes_up,
            bytes_down,
        },
    )
    .await;
    splice_result?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn tunnel_connect_route<S: IoStream>(
    mut stream: S,
    ctx: Arc<Ctx>,
    peer: SocketAddr,
    started: Instant,
    user: String,
    host: String,
    port: u16,
    up_rate: u64,
    down_rate: u64,
    connection_permit: crate::engine::ConnectionPermit,
    mut resolved: crate::model::ResolvedDecision,
    mut decision_name: String,
) -> anyhow::Result<()> {
    reply(&mut stream, 0x00).await?;
    let captured = match capture_prefix(&mut stream, ctx.sniff.max_bytes, ctx.sniff.timeout()).await
    {
        Ok(captured) => captured,
        Err(error) => {
            report_trace(
                &ctx,
                started,
                peer,
                TraceFields {
                    username: Some(user),
                    target_host: Some(host),
                    target_port: Some(port),
                    decision: Some(decision_name),
                    effective_policy_host: Some(resolved.effective_policy_host),
                    failure_stage: Some("sniff_read"),
                    message: Some("route sniff read failed"),
                    ..TraceFields::default()
                },
            )
            .await;
            return Err(error.into());
        }
    };
    resolved = ctx
        .engine
        .decide_with_sniff(&user, &host, captured.observation.host.as_deref());
    decision_name = crate::outbound::decision_label(&resolved.decision);
    let sniff_observation = Some(captured.observation);
    if let Decision::Block = resolved.decision {
        debug!(
            user = %user,
            target = %host,
            effective_policy_host = %resolved.effective_policy_host,
            "socks5 connect blocked by sniffed policy"
        );
        report_trace(
            &ctx,
            started,
            peer,
            TraceFields {
                username: Some(user),
                target_host: Some(host),
                target_port: Some(port),
                decision: Some(decision_name),
                sniff: sniff_observation,
                effective_policy_host: Some(resolved.effective_policy_host),
                failure_stage: Some("policy"),
                message: Some("blocked by requested or sniffed target policy"),
                ..TraceFields::default()
            },
        )
        .await;
        return Ok(());
    }

    let (outbound, egress) =
        match outbound::connect(resolved.decision, &host, port, &ctx.egress).await {
            Ok(established) => established,
            Err(e) => {
                debug!(user = %user, target = %host, error = %e, "upstream connect failed");
                report_trace(
                    &ctx,
                    started,
                    peer,
                    TraceFields {
                        username: Some(user),
                        target_host: Some(host),
                        target_port: Some(port),
                        decision: Some(decision_name),
                        sniff: sniff_observation,
                        effective_policy_host: Some(resolved.effective_policy_host),
                        attempts: e.chain_attempts(),
                        failure_stage: Some(e.failure_stage()),
                        message: Some("upstream connect failed"),
                        ..TraceFields::default()
                    },
                )
                .await;
                return Ok(());
            }
        };
    let _egress_guard = ctx.stats.track_egress(&egress.label);
    debug!(
        user = %user,
        listener = %ctx.listener,
        target = %format!("{host}:{port}"),
        egress = %egress.label,
        "tunnel established"
    );
    let stream = PrefixedIo::new(captured.bytes, stream);
    let splice_result = splice(stream, outbound, up_rate, down_rate).await;
    drop(connection_permit);
    let (result, stage, message, bytes_up, bytes_down) = match &splice_result {
        Ok(stats) => (
            TraceResult::Ok,
            None,
            None,
            stats.bytes_up,
            stats.bytes_down,
        ),
        Err(_) => (
            TraceResult::Error,
            Some("splice"),
            Some("tunnel io failed"),
            0,
            0,
        ),
    };
    report_trace(
        &ctx,
        started,
        peer,
        TraceFields {
            username: Some(user),
            target_host: Some(host),
            target_port: Some(port),
            decision: Some(decision_name),
            egress: egress.chain_id.is_some().then(|| egress.label.clone()),
            chain_member: egress.member_id.clone(),
            attempts: egress.chain_id.is_some().then_some(egress.attempts),
            result,
            sniff: sniff_observation,
            effective_policy_host: Some(resolved.effective_policy_host),
            failure_stage: stage,
            message,
            bytes_up,
            bytes_down,
        },
    )
    .await;
    splice_result?;
    Ok(())
}

async fn read_u8<S: AsyncRead + Unpin>(s: &mut S) -> std::io::Result<u8> {
    let mut b = [0u8; 1];
    s.read_exact(&mut b).await?;
    Ok(b[0])
}

async fn reply<S: IoStream>(s: &mut S, rep: u8) -> std::io::Result<()> {
    // VER REP RSV ATYP(IPv4) BND.ADDR(0.0.0.0) BND.PORT(0)
    s.write_all(&[VER, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await
}

struct TraceFields<'a> {
    username: Option<String>,
    target_host: Option<String>,
    target_port: Option<u16>,
    decision: Option<String>,
    /// Physical egress when the decision was a chain (winning member outlet).
    egress: Option<String>,
    chain_member: Option<String>,
    attempts: Option<u32>,
    sniff: Option<SniffObservation>,
    effective_policy_host: Option<String>,
    result: TraceResult,
    failure_stage: Option<&'a str>,
    message: Option<&'a str>,
    bytes_up: u64,
    bytes_down: u64,
}

impl Default for TraceFields<'_> {
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
            effective_policy_host: None,
            result: TraceResult::Error,
            failure_stage: None,
            message: None,
            bytes_up: 0,
            bytes_down: 0,
        }
    }
}

async fn report_trace(ctx: &Arc<Ctx>, started: Instant, peer: SocketAddr, fields: TraceFields<'_>) {
    // Traffic counters are always on (they feed SNMP even when tracing,
    // diagnostics and the access log are all disabled). Blocked decisions
    // never open an egress row: nothing left the node. Chain decisions count
    // bytes under the physical member outlet, matching `track_egress`.
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
            if let Some(host) = fields.effective_policy_host.clone() {
                identity = identity.with_effective_policy_host(host);
            }
            match fields.sniff.clone() {
                Some(observation) => identity.with_observation(observation),
                None => identity,
            }
        });
    let candidate = TraceCandidate {
        listener: ctx.listener.clone(),
        protocol: "socks5".to_string(),
        client_addr: Some(peer.to_string()),
        username: fields.username,
        target_host: fields.target_host,
        target_port: fields.target_port,
        traffic,
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
    // Diagnostics is the non-blocking, multi-session fan-out; the one-shot probe
    // tracer stays a separate, backward-compatible consumer of the same candidate.
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
    use crate::engine::Engine;
    use crate::model::{RawGroup, RawSnapshot, RawUser, Snapshot};
    use std::collections::HashMap;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    /// Fixed source address for tests that go through an in-memory
    /// `tokio::io::duplex` stream instead of a real TCP accept loop, so
    /// there is no real peer `SocketAddr` to use.
    fn test_peer() -> SocketAddr {
        "203.0.113.20:40000".parse().unwrap()
    }

    #[test]
    fn decision_name_embeds_upstream_address_but_never_credentials() {
        use crate::model::{Upstream, UpstreamKind};

        assert_eq!(decision_name(&Decision::Direct), "direct");
        assert_eq!(decision_name(&Decision::Block), "block");

        let via = Decision::Via(Upstream {
            kind: UpstreamKind::Socks5,
            addr: "10.0.0.9:1081".to_string(),
            username: Some("hop-user".to_string()),
            password: Some("hop-secret".to_string()),
            tls: false,
            skip_cert_verify: false,
        });
        let name = decision_name(&via);
        assert_eq!(name, "upstream:10.0.0.9:1081");
        assert!(!name.contains("hop-user"));
        assert!(!name.contains("hop-secret"));
    }

    #[tokio::test]
    async fn rejects_bad_socks_version() {
        // hdr[0] must be 0x05; a bad version is rejected before methods are read.
        let response = run_socks5(&[0x04, 0x01], engine_with_user("secret", "2099-12-31")).await;
        assert!(response.is_empty());
    }

    #[tokio::test]
    async fn rejects_missing_userpass_auth_method() {
        // Offers only "no auth" (0x00); server requires 0x02 and replies 0xFF.
        let response = run_socks5(
            &[0x05, 0x01, 0x00],
            engine_with_user("secret", "2099-12-31"),
        )
        .await;
        assert_eq!(response, vec![0x05, 0xFF]);
    }

    #[tokio::test]
    async fn rejects_bad_auth_subnegotiation_version() {
        let mut req = vec![0x05, 0x01, 0x02]; // method negotiation: offer user/pass
        req.push(0x00); // bad subnegotiation version (must be 0x01)
        let response = run_socks5(&req, engine_with_user("secret", "2099-12-31")).await;
        // Only the method-selection reply is sent; no auth reply follows.
        assert_eq!(response, vec![0x05, 0x02]);
    }

    #[tokio::test]
    async fn rejects_auth_failure() {
        let mut req = vec![0x05, 0x01, 0x02]; // method negotiation
        req.push(0x01); // subnegotiation version
        req.push(5);
        req.extend_from_slice(b"alice");
        req.push(5);
        req.extend_from_slice(b"wrong");
        let response = run_socks5(&req, engine_with_user("secret", "2099-12-31")).await;
        assert_eq!(response, vec![0x05, 0x02, 0x01, 0x01]);
    }

    #[tokio::test]
    async fn rejects_bad_request_version() {
        let mut req = valid_auth_prefix();
        req.extend_from_slice(&[0x04, 0x01, 0x00, 0x01]); // bad request version
        let response = run_socks5(&req, engine_with_user("secret", "2099-12-31")).await;
        // Method reply + auth-success reply only; no reply for a bad request version.
        assert_eq!(response, vec![0x05, 0x02, 0x01, 0x00]);
    }

    #[tokio::test]
    async fn rejects_unsupported_command() {
        let mut req = valid_auth_prefix();
        req.extend_from_slice(&[0x05, 0x02, 0x00, 0x01]); // BIND (0x02) is unsupported
        let response = run_socks5(&req, engine_with_user("secret", "2099-12-31")).await;
        let mut expected = vec![0x05, 0x02, 0x01, 0x00];
        expected.extend_from_slice(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        assert_eq!(response, expected);
    }

    #[tokio::test]
    async fn rejects_unsupported_address_type() {
        let mut req = valid_auth_prefix();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x02]); // atyp 0x02 is unsupported
        let response = run_socks5(&req, engine_with_user("secret", "2099-12-31")).await;
        let mut expected = vec![0x05, 0x02, 0x01, 0x00];
        expected.extend_from_slice(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        assert_eq!(response, expected);
    }

    #[tokio::test]
    async fn rejects_target_blocked_by_policy() {
        let domain = "blocked.example";
        let mut req = valid_auth_prefix();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]); // CONNECT, domain name
        req.push(domain.len() as u8);
        req.extend_from_slice(domain.as_bytes());
        req.extend_from_slice(&443u16.to_be_bytes());
        let response = run_socks5(
            &req,
            engine_with_blocked_host("secret", "2099-12-31", domain),
        )
        .await;
        let mut expected = vec![0x05, 0x02, 0x01, 0x00];
        expected.extend_from_slice(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        assert_eq!(response, expected);
    }

    #[tokio::test]
    async fn rejects_when_upstream_connect_fails() {
        // Reserve then release a loopback port so nothing is listening there;
        // connecting to it deterministically yields a real refused-connection.
        let dead_port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let mut req = valid_auth_prefix();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]); // CONNECT, IPv4
        req.extend_from_slice(&[127, 0, 0, 1]);
        req.extend_from_slice(&dead_port.to_be_bytes());
        let response = run_socks5(&req, engine_with_user("secret", "2099-12-31")).await;
        let mut expected = vec![0x05, 0x02, 0x01, 0x00];
        expected.extend_from_slice(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        assert_eq!(response, expected);
    }

    #[tokio::test]
    async fn access_log_records_completed_connections_independent_of_tracer_and_diagnostics() {
        let dead_port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };
        let mut req = valid_auth_prefix();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]); // CONNECT, IPv4
        req.extend_from_slice(&[127, 0, 0, 1]);
        req.extend_from_slice(&dead_port.to_be_bytes());

        let (logger, mut rx) = crate::access_log::AccessLogger::for_test();
        let (mut client, server) = tokio::io::duplex(4096);
        let ctx = Arc::new(Ctx {
            engine: engine_with_user("secret", "2099-12-31"),
            listener: "test-socks5".to_string(),
            sniff: crate::config::SniffConfig::default(),
            tracer: None,
            diagnostics: None,
            access_log: Some(logger),
            stats: crate::stats::TrafficStats::new(),
            egress: crate::outbound::EgressContext::default(),
        });
        client.write_all(&req).await.unwrap();
        let task = tokio::spawn(serve(server, ctx, test_peer(), None));
        task.await.unwrap().unwrap();

        let record = rx.try_recv().expect("access log record enqueued");
        assert_eq!(record.node_id, "test-node");
        assert_eq!(record.listener, "test-socks5");
        assert_eq!(record.protocol, "socks5");
        assert_eq!(record.client_addr.as_deref(), Some("203.0.113.20:40000"));
        assert_eq!(record.username.as_deref(), Some("alice"));
        assert_eq!(record.failure_stage.as_deref(), Some("dial"));
        assert_eq!(record.bytes_up, 0);
        assert_eq!(record.bytes_down, 0);
    }

    #[tokio::test]
    async fn active_connection_gauge_reflects_open_tunnel_and_clears_on_close() {
        let (logger, mut rx) = crate::access_log::AccessLogger::for_test();
        let stats = crate::stats::TrafficStats::new();
        let (target_addr, target_task) = start_echo_server().await;

        let mut req = valid_auth_prefix();
        req.extend_from_slice(&[0x05, 0x01, 0x00, 0x01]); // CONNECT, IPv4
        match target_addr.ip() {
            std::net::IpAddr::V4(ip) => req.extend_from_slice(&ip.octets()),
            std::net::IpAddr::V6(_) => unreachable!("echo server binds to 127.0.0.1"),
        }
        req.extend_from_slice(&target_addr.port().to_be_bytes());

        let (mut client, server) = tokio::io::duplex(4096);
        let ctx = Arc::new(Ctx {
            engine: engine_with_user("secret", "2099-12-31"),
            listener: "test-socks5".to_string(),
            sniff: crate::config::SniffConfig::default(),
            tracer: None,
            diagnostics: None,
            access_log: Some(logger.clone()),
            stats: stats.clone(),
            egress: crate::outbound::EgressContext::default(),
        });
        client.write_all(&req).await.unwrap();
        let task = tokio::spawn(serve(server, ctx, test_peer(), None));

        // Method-select (2 bytes) + auth-success (2 bytes) + CONNECT reply
        // (10 bytes) = 14 bytes; response[5] is the CONNECT REP byte.
        let mut response = [0u8; 14];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[5], 0x00, "expected CONNECT succeeded reply");

        // Tunnel is open end-to-end: the listener's and egress's active
        // gauges reflect the one in-flight connection, fed by the
        // `TrafficStats` guards held for the lifetime of `serve()`.
        let row = |rows: Vec<crate::stats::StatsRow>, name: &str| {
            rows.into_iter().find(|r| r.name == name)
        };
        assert_eq!(row(stats.listener_rows(), "test-socks5").unwrap().active, 1);
        assert_eq!(row(stats.egress_rows(), "direct").unwrap().active, 1);

        client.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        target_task.await.unwrap();

        // Connection fully closed: gauge guards dropped, back to zero, and
        // byte totals folded into both dimensions identically.
        let listener_row = row(stats.listener_rows(), "test-socks5").unwrap();
        let egress_row = row(stats.egress_rows(), "direct").unwrap();
        assert_eq!(listener_row.active, 0);
        assert_eq!(egress_row.active, 0);
        assert_eq!(listener_row.bytes_up_total, egress_row.bytes_up_total);
        assert_eq!(listener_row.bytes_down_total, egress_row.bytes_down_total);
        let record = rx.try_recv().expect("access log record enqueued");
        assert_eq!(record.result, "ok");
    }

    async fn start_echo_server() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                socket.write_all(&buf[..n]).await.unwrap();
            }
        });
        (addr, task)
    }

    /// Method negotiation (offer + accept user/pass) followed by a successful
    /// auth as alice/secret. Callers append the SOCKS request bytes after this.
    fn valid_auth_prefix() -> Vec<u8> {
        let mut req = vec![0x05, 0x01, 0x02];
        req.push(0x01); // subnegotiation version
        req.push(5);
        req.extend_from_slice(b"alice");
        req.push(6);
        req.extend_from_slice(b"secret");
        req
    }

    async fn run_socks5(bytes: &[u8], engine: Arc<Engine>) -> Vec<u8> {
        let (mut client, server) = tokio::io::duplex(4096);
        let ctx = Arc::new(Ctx {
            engine,
            listener: "test-socks5".to_string(),
            sniff: crate::config::SniffConfig::default(),
            tracer: None,
            diagnostics: None,
            access_log: None,
            stats: crate::stats::TrafficStats::new(),
            egress: crate::outbound::EgressContext::default(),
        });
        client.write_all(bytes).await.unwrap();
        let task = tokio::spawn(serve(server, ctx, test_peer(), None));
        task.await.unwrap().unwrap();
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await.unwrap();
        buf
    }

    fn engine_with_user(password: &str, expire: &str) -> Arc<Engine> {
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            RawUser {
                password: password.to_string(),
                expire: Some(expire.to_string()),
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                group: "open".to_string(),
                frontends: Default::default(),
            },
        );
        let mut groups = HashMap::new();
        groups.insert(
            "open".to_string(),
            RawGroup {
                upstream: None,
                default_upstream: None,
                proxy: Vec::new(),
                block: Vec::new(),
            },
        );
        let engine = Engine::new();
        engine.replace(
            Snapshot::compile(
                RawSnapshot {
                    version: 1,
                    users,
                    groups,
                    ..Default::default()
                },
                "node-1",
            )
            .unwrap(),
        );
        engine
    }

    fn engine_with_blocked_host(password: &str, expire: &str, blocked_host: &str) -> Arc<Engine> {
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            RawUser {
                password: password.to_string(),
                expire: Some(expire.to_string()),
                up_rate: 0,
                down_rate: 0,
                max_connections: 0,
                group: "open".to_string(),
                frontends: Default::default(),
            },
        );
        let mut groups = HashMap::new();
        groups.insert(
            "open".to_string(),
            RawGroup {
                upstream: None,
                default_upstream: None,
                proxy: Vec::new(),
                block: vec![blocked_host.to_string()],
            },
        );
        let engine = Engine::new();
        engine.replace(
            Snapshot::compile(
                RawSnapshot {
                    version: 1,
                    users,
                    groups,
                    ..Default::default()
                },
                "node-1",
            )
            .unwrap(),
        );
        engine
    }
}
