//! TUIC v5 front-end listener (QUIC).
//!
//! Adding this protocol keeps Rove's core role: the node still authenticates
//! locally (UUID + TLS-exported token, see [`crate::engine::Engine`]), applies
//! policy/limits, and reuses the existing egress. `Connect` (TCP) rides the
//! shared [`crate::outbound::connect`] path (rate-limited like HTTP/SOCKS5);
//! `Packet` (UDP, native datagram mode) rides [`crate::outbound::connect_udp`]
//! onto the reverse/2 UDP egress (un-throttled). Fails closed: unauthenticated
//! or policy-blocked traffic is dropped, never proxied.

pub mod codec;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::access_log::AccessLogger;
use crate::config::SniffMode;
use crate::engine::Engine;
use crate::io::{splice, PrefixedIo};
use crate::model::Decision;
use crate::outbound::EgressContext;
use crate::reverse::udp::UdpRelay;
use crate::reverse::QuicDuplex;
use crate::sniff::{capture_prefix, SniffObservation, SniffingIo};
use crate::stats::TrafficStats;
use crate::trace::{TraceCandidate, TraceResult, TrafficIdentity};
use codec::{cmd, Address, DatagramCommand};

/// How long an unauthenticated QUIC connection may stay open before the edge
/// closes it fail-closed.
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const CLOSE_OK: u32 = 0;

/// Static configuration for one TUIC listener.
#[derive(Debug, Clone)]
pub struct TuicListenerConfig {
    pub name: String,
    /// UDP `ip:port` the QUIC endpoint binds to.
    pub listen: String,
    pub cert: String,
    pub key: String,
    /// ALPN protocols to present; TUIC clients typically pin one (e.g. `h3`).
    pub alpn: Vec<String>,
    /// Optional fixed QUIC path MTU (max UDP-payload bytes) for a client base
    /// reached across an already-compressed outer tunnel. `None` = default PMTUD.
    pub initial_mtu: Option<u16>,
    pub sniff: crate::config::SniffConfig,
}

/// The authenticated client identity resolved once per connection.
struct Identity {
    username: String,
    up_rate: u64,
    down_rate: u64,
    max_connections: usize,
}

/// Shared per-connection context handed to every stream/datagram handler.
struct ConnCtx {
    engine: Arc<Engine>,
    egress: EgressContext,
    stats: Arc<TrafficStats>,
    access_log: Option<Arc<AccessLogger>>,
    listener: String,
    sniff: crate::config::SniffConfig,
    connection: quinn::Connection,
    peer: SocketAddr,
    ingress: Option<crate::ingress::metadata::IngressMetadata>,
    auth: watch::Receiver<Option<Arc<Identity>>>,
    assoc: Mutex<HashMap<u16, UdpAssoc>>,
}

struct UdpAssoc {
    relay: Arc<UdpRelay>,
    return_task: tokio::task::JoinHandle<()>,
}

impl Drop for UdpAssoc {
    fn drop(&mut self) {
        self.return_task.abort();
    }
}

/// Build the QUIC server config for a TUIC listener: TLS 1.3 cert/key, the
/// configured ALPN, and datagrams enabled (native UDP relay mode).
fn server_config(cfg: &TuicListenerConfig) -> anyhow::Result<quinn::ServerConfig> {
    let certs = crate::tls::load_cert_chain(&cfg.cert)?;
    let key = crate::tls::load_private_key(&cfg.key)?;
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("tuic server TLS config: {e}"))?;
    crypto.alpn_protocols = cfg.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .map_err(|e| anyhow::anyhow!("tuic QUIC server crypto: {e}"))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    if let Ok(t) = quinn::IdleTimeout::try_from(Duration::from_secs(45)) {
        transport.max_idle_timeout(Some(t));
    }
    transport.datagram_receive_buffer_size(Some(8 * 1024 * 1024));
    transport.datagram_send_buffer_size(2 * 1024 * 1024);
    crate::reverse::apply_initial_mtu(&mut transport, cfg.initial_mtu);
    server.transport_config(Arc::new(transport));
    Ok(server)
}

pub struct BoundListener {
    cfg: TuicListenerConfig,
    endpoint: quinn::Endpoint,
}

impl BoundListener {
    pub fn bind(cfg: TuicListenerConfig, stats: Arc<TrafficStats>) -> anyhow::Result<Self> {
        let server_cfg = server_config(&cfg)?;
        let addr: SocketAddr = cfg.listen.parse().map_err(|e| {
            anyhow::anyhow!("tuic listener {} listen {:?}: {e}", cfg.name, cfg.listen)
        })?;
        let endpoint = quinn::Endpoint::server(server_cfg, addr)
            .map_err(|e| anyhow::anyhow!("tuic listener {} bind {addr}: {e}", cfg.name))?;
        let bound = endpoint.local_addr().unwrap_or(addr);
        stats.register_listener(&cfg.name);
        info!(listener = %cfg.name, addr = %bound, "tuic listening");
        Ok(BoundListener { cfg, endpoint })
    }

    pub fn name(&self) -> &str {
        &self.cfg.name
    }

    pub async fn run_until(
        self,
        engine: Arc<Engine>,
        stats: Arc<TrafficStats>,
        access_log: Option<Arc<AccessLogger>>,
        egress: EgressContext,
        mut shutdown: watch::Receiver<bool>,
    ) -> anyhow::Result<()> {
        let BoundListener { cfg, endpoint } = self;
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = crate::lifecycle::shutdown_requested(&mut shutdown) => {
                    info!(listener = %cfg.name, active = connections.len(), "tuic listener stopped accepting new connections");
                    break;
                }
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break;
                    };
                    let engine = engine.clone();
                    let stats = stats.clone();
                    let access_log = access_log.clone();
                    let egress = egress.clone();
                    let listener = cfg.name.clone();
                    let sniff = cfg.sniff.clone();
                    let connection_shutdown = shutdown.clone();
                    connections.spawn(async move {
                        let transport_peer = incoming.remote_address();
                        let ingress = crate::ingress::metadata::lookup_udp(transport_peer);
                        let peer = ingress
                            .as_ref()
                            .map(|metadata| metadata.client_addr)
                            .unwrap_or(transport_peer);
                        let connection = match incoming.accept() {
                            Ok(c) => match c.await {
                                Ok(conn) => conn,
                                Err(e) => {
                                    debug!(peer = %peer, error = %e, "tuic handshake failed");
                                    return;
                                }
                            },
                            Err(e) => {
                                debug!(peer = %peer, error = %e, "tuic accept failed");
                                return;
                            }
                        };
                        handle_connection(
                            connection,
                            peer,
                            engine,
                            stats,
                            access_log,
                            egress,
                            listener,
                            sniff,
                            ingress,
                            connection_shutdown,
                        )
                        .await;
                    });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(e) = result {
                        debug!(listener = %cfg.name, error = %e, "tuic connection task ended unexpectedly");
                    }
                }
            }
        }
        while let Some(result) = connections.join_next().await {
            if let Err(e) = result {
                debug!(listener = %cfg.name, error = %e, "tuic connection task ended unexpectedly");
            }
        }
        info!(listener = %cfg.name, "tuic connections drained");
        Ok(())
    }
}

/// Bind and serve a TUIC listener until the process exits.
pub async fn run(
    cfg: TuicListenerConfig,
    engine: Arc<Engine>,
    stats: Arc<TrafficStats>,
    access_log: Option<Arc<AccessLogger>>,
    egress: EgressContext,
) -> anyhow::Result<()> {
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    run_until(cfg, engine, stats, access_log, egress, shutdown_rx).await
}

/// Bind and serve a TUIC listener until shutdown, then stop accepting new
/// QUIC connections/streams and drain established TCP relays.
pub async fn run_until(
    cfg: TuicListenerConfig,
    engine: Arc<Engine>,
    stats: Arc<TrafficStats>,
    access_log: Option<Arc<AccessLogger>>,
    egress: EgressContext,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    BoundListener::bind(cfg, stats.clone())?
        .run_until(engine, stats, access_log, egress, shutdown)
        .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    connection: quinn::Connection,
    peer: SocketAddr,
    engine: Arc<Engine>,
    stats: Arc<TrafficStats>,
    access_log: Option<Arc<AccessLogger>>,
    egress: EgressContext,
    listener: String,
    sniff: crate::config::SniffConfig,
    ingress: Option<crate::ingress::metadata::IngressMetadata>,
    shutdown: watch::Receiver<bool>,
) {
    let _guard = stats.track_listener(&listener);
    let (auth_tx, auth_rx) = watch::channel::<Option<Arc<Identity>>>(None);
    let ctx = Arc::new(ConnCtx {
        engine,
        egress,
        stats,
        access_log,
        listener,
        sniff,
        connection: connection.clone(),
        peer,
        ingress,
        auth: auth_rx,
        assoc: Mutex::new(HashMap::new()),
    });

    // Fail closed: drop a connection that never authenticates.
    let auth_watch = ctx.auth.clone();
    let timeout_conn = connection.clone();
    let auth_timeout = tokio::spawn(async move {
        if tokio::time::timeout(AUTH_TIMEOUT, wait_authenticated(auth_watch))
            .await
            .is_err()
        {
            timeout_conn.close(CLOSE_OK.into(), b"tuic auth timeout");
        }
    });

    let mut loops = JoinSet::new();
    loops.spawn(accept_uni_loop(ctx.clone(), auth_tx, shutdown.clone()));
    loops.spawn(accept_bi_loop(ctx.clone(), shutdown.clone()));
    loops.spawn(datagram_loop(ctx.clone(), shutdown.clone()));
    while let Some(result) = loops.join_next().await {
        if let Err(e) = result {
            debug!(peer = %peer, error = %e, "tuic connection loop ended unexpectedly");
        }
    }

    auth_timeout.abort();
    ctx.assoc.lock().expect("assoc poisoned").clear();
    if *shutdown.borrow() {
        connection.close(CLOSE_OK.into(), b"server draining");
    }
    let reason = connection.closed().await;
    debug!(peer = %peer, reason = %reason, "tuic connection closed");
}

/// Resolve the authenticated identity, waiting until the `Authenticate` command
/// arrives (or the connection ends).
async fn wait_authenticated(mut rx: watch::Receiver<Option<Arc<Identity>>>) -> Arc<Identity> {
    loop {
        if let Some(id) = rx.borrow().clone() {
            return id;
        }
        if rx.changed().await.is_err() {
            // Sender dropped (connection ending); park forever so the caller's
            // timeout / abort governs teardown.
            std::future::pending::<()>().await;
        }
    }
}

/// Uni-streams carry `Authenticate`, `Dissociate`, and (quic-mode) `Packet`.
async fn accept_uni_loop(
    ctx: Arc<ConnCtx>,
    auth_tx: watch::Sender<Option<Arc<Identity>>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut commands = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = crate::lifecycle::shutdown_requested(&mut shutdown) => break,
            accepted = ctx.connection.accept_uni() => {
                let Ok(mut recv) = accepted else {
                    break;
                };
                let ctx = ctx.clone();
                let auth_tx = auth_tx.clone();
                commands.spawn(async move {
                    let ty = match codec::read_command_type(&mut recv).await {
                        Ok(t) => t,
                        Err(e) => {
                            debug!(error = %e, "tuic uni: bad command header");
                            return;
                        }
                    };
                    match ty {
                        cmd::AUTHENTICATE => handle_authenticate(&ctx, &mut recv, &auth_tx).await,
                        cmd::DISSOCIATE => {
                            if let Ok(mut b) = read_u16(&mut recv).await {
                                let _ = &mut b;
                                ctx.assoc.lock().expect("assoc poisoned").remove(&b);
                                debug!(assoc_id = b, "tuic dissociate");
                            }
                        }
                        cmd::PACKET => {
                            // quic-mode Packet: header + payload on this uni-stream.
                            if let Ok(bytes) = read_to_end(&mut recv, 70_000).await {
                                handle_packet_bytes(&ctx, &bytes).await;
                            }
                        }
                        other => debug!(ty = other, "tuic uni: unsupported command"),
                    }
                });
            }
            Some(result) = commands.join_next(), if !commands.is_empty() => {
                if let Err(e) = result {
                    debug!(error = %e, "tuic uni command task ended unexpectedly");
                }
            }
        }
    }
    while let Some(result) = commands.join_next().await {
        if let Err(e) = result {
            debug!(error = %e, "tuic uni command task ended unexpectedly");
        }
    }
}

async fn handle_authenticate(
    ctx: &Arc<ConnCtx>,
    recv: &mut quinn::RecvStream,
    auth_tx: &watch::Sender<Option<Arc<Identity>>>,
) {
    let (uuid, token) = match codec::read_authenticate(recv).await {
        Ok(v) => v,
        Err(e) => {
            debug!(error = %e, "tuic: unreadable authenticate");
            return;
        }
    };
    let conn = ctx.connection.clone();
    let exporter = move |label: &[u8], context: &[u8], len: usize| -> Option<Vec<u8>> {
        let mut out = vec![0u8; len];
        conn.export_keying_material(&mut out, label, context)
            .ok()
            .map(|()| out)
    };
    match ctx.engine.authenticate_tuic(&uuid, &token, exporter) {
        Ok((username, ok)) => {
            info!(listener = %ctx.listener, peer = %ctx.peer, user = %username, "tuic authenticated");
            let _ = auth_tx.send(Some(Arc::new(Identity {
                username,
                up_rate: ok.up_rate,
                down_rate: ok.down_rate,
                max_connections: ok.max_connections,
            })));
        }
        Err(_) => {
            warn!(listener = %ctx.listener, peer = %ctx.peer, "tuic authentication failed");
            ctx.connection.close(CLOSE_OK.into(), b"tuic auth failed");
        }
    }
}

/// Bi-streams carry `Connect` (TCP relay). The client sends the command header
/// then raw bytes; the server never replies, it just splices.
async fn accept_bi_loop(ctx: Arc<ConnCtx>, mut shutdown: watch::Receiver<bool>) {
    let mut streams = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = crate::lifecycle::shutdown_requested(&mut shutdown) => break,
            accepted = ctx.connection.accept_bi() => {
                let Ok((send, mut recv)) = accepted else {
                    break;
                };
                let ctx = ctx.clone();
                streams.spawn(async move {
                    let ty = match codec::read_command_type(&mut recv).await {
                        Ok(t) => t,
                        Err(e) => {
                            debug!(error = %e, "tuic bi: bad command header");
                            return;
                        }
                    };
                    if ty != cmd::CONNECT {
                        debug!(ty, "tuic bi: expected CONNECT");
                        return;
                    }
                    let addr = match codec::read_address(&mut recv).await {
                        Ok(a) => a,
                        Err(e) => {
                            debug!(error = %e, "tuic connect: bad address");
                            return;
                        }
                    };
                    let Some((host, port)) = addr.host_port() else {
                        debug!("tuic connect: null address");
                        return;
                    };
                    handle_connect(&ctx, send, recv, host, port).await;
                });
            }
            Some(result) = streams.join_next(), if !streams.is_empty() => {
                if let Err(e) = result {
                    debug!(error = %e, "tuic connect task ended unexpectedly");
                }
            }
        }
    }
    while let Some(result) = streams.join_next().await {
        if let Err(e) = result {
            debug!(error = %e, "tuic connect task ended unexpectedly");
        }
    }
}

async fn handle_connect(
    ctx: &Arc<ConnCtx>,
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    host: String,
    port: u16,
) {
    let started = std::time::Instant::now();
    let Some(identity) = wait_auth_or_give_up(ctx).await else {
        return;
    };
    let mut resolved = ctx
        .engine
        .decide_with_sniff(&identity.username, &host, None);
    if matches!(&resolved.decision, Decision::Block) {
        debug!(user = %identity.username, target = %host, "tuic connect blocked by policy");
        record_tcp_access(
            ctx,
            started,
            TuicTcpTrace {
                username: &identity.username,
                host: &host,
                port,
                decision: "block",
                effective_policy_host: &resolved.effective_policy_host,
                snapshot_version: resolved.snapshot_version,
                observation: None,
                egress: None,
                chain_member: None,
                attempts: None,
                result: TraceResult::Error,
                failure_stage: Some("policy"),
                message: Some("blocked by requested target policy"),
                bytes_up: 0,
                bytes_down: 0,
            },
        );
        return;
    }
    let initial_decision_name = decision_label(&resolved.decision);
    let _permit = match ctx
        .engine
        .acquire_connection(&identity.username, identity.max_connections)
    {
        Ok(p) => p,
        Err(e) => {
            debug!(user = %identity.username, error = %e, "tuic connect limit");
            record_tcp_access(
                ctx,
                started,
                TuicTcpTrace {
                    username: &identity.username,
                    host: &host,
                    port,
                    decision: &initial_decision_name,
                    effective_policy_host: &resolved.effective_policy_host,
                    snapshot_version: resolved.snapshot_version,
                    observation: None,
                    egress: None,
                    chain_member: None,
                    attempts: None,
                    result: TraceResult::Error,
                    failure_stage: Some("limit"),
                    message: Some("connection limit exceeded"),
                    bytes_up: 0,
                    bytes_down: 0,
                },
            );
            return;
        }
    };
    let route_mode = ctx.sniff.enabled && ctx.sniff.mode == SniffMode::Route;
    let mut captured_prefix = Vec::new();
    let mut sniff_observation = None;
    if route_mode {
        let captured = match capture_prefix(&mut recv, ctx.sniff.max_bytes, ctx.sniff.timeout())
            .await
        {
            Ok(captured) => captured,
            Err(error) => {
                debug!(user = %identity.username, target = %host, error = %error, "tuic route sniff read failed");
                record_tcp_access(
                    ctx,
                    started,
                    TuicTcpTrace {
                        username: &identity.username,
                        host: &host,
                        port,
                        decision: &initial_decision_name,
                        effective_policy_host: &resolved.effective_policy_host,
                        snapshot_version: resolved.snapshot_version,
                        observation: None,
                        egress: None,
                        chain_member: None,
                        attempts: None,
                        result: TraceResult::Error,
                        failure_stage: Some("sniff_read"),
                        message: Some("route sniff read failed"),
                        bytes_up: 0,
                        bytes_down: 0,
                    },
                );
                return;
            }
        };
        ctx.stats
            .record_sniff(&ctx.listener, captured.observation.outcome);
        resolved = ctx.engine.decide_with_sniff(
            &identity.username,
            &host,
            captured.observation.host.as_deref(),
        );
        captured_prefix = captured.bytes;
        sniff_observation = Some(captured.observation);
        if matches!(&resolved.decision, Decision::Block) {
            debug!(
                user = %identity.username,
                target = %host,
                effective_policy_host = %resolved.effective_policy_host,
                "tuic connect blocked by sniffed policy"
            );
            record_tcp_access(
                ctx,
                started,
                TuicTcpTrace {
                    username: &identity.username,
                    host: &host,
                    port,
                    decision: "block",
                    effective_policy_host: &resolved.effective_policy_host,
                    snapshot_version: resolved.snapshot_version,
                    observation: sniff_observation,
                    egress: None,
                    chain_member: None,
                    attempts: None,
                    result: TraceResult::Error,
                    failure_stage: Some("policy"),
                    message: Some("blocked by requested or sniffed target policy"),
                    bytes_up: 0,
                    bytes_down: 0,
                },
            );
            return;
        }
    }
    let decision_name = decision_label(&resolved.decision);
    let effective_policy_host = resolved.effective_policy_host.clone();
    let snapshot_version = resolved.snapshot_version;
    let (outbound, egress) = match crate::outbound::connect(
        resolved.decision,
        &host,
        port,
        &ctx.egress,
    )
    .await
    {
        Ok(established) => established,
        Err(e) => {
            debug!(user = %identity.username, target = %host, error = %e, "tuic upstream connect failed");
            record_tcp_access(
                ctx,
                started,
                TuicTcpTrace {
                    username: &identity.username,
                    host: &host,
                    port,
                    decision: &decision_name,
                    effective_policy_host: &effective_policy_host,
                    snapshot_version,
                    observation: sniff_observation,
                    egress: None,
                    chain_member: None,
                    attempts: e.chain_attempts(),
                    result: TraceResult::Error,
                    failure_stage: Some(e.failure_stage()),
                    message: Some("upstream connect failed"),
                    bytes_up: 0,
                    bytes_down: 0,
                },
            );
            return;
        }
    };
    let _egress = ctx.stats.track_egress(&egress.label);
    info!(
        listener = %ctx.listener,
        user = %identity.username,
        target = %format!("{host}:{port}"),
        egress = %egress.label,
        "tuic tcp tunnel established"
    );
    let duplex = QuicDuplex::new(send, recv);
    let (splice_result, sniff_observation) = if route_mode {
        (
            splice(
                PrefixedIo::new(captured_prefix, duplex),
                outbound,
                identity.up_rate,
                identity.down_rate,
            )
            .await,
            sniff_observation,
        )
    } else if ctx.sniff.enabled {
        let (duplex, handle) = SniffingIo::new(duplex, ctx.sniff.max_bytes, ctx.sniff.timeout());
        let result = splice(duplex, outbound, identity.up_rate, identity.down_rate).await;
        (result, Some(handle.observation()))
    } else {
        (
            splice(duplex, outbound, identity.up_rate, identity.down_rate).await,
            None,
        )
    };
    if let Some(observation) = &sniff_observation {
        if !route_mode {
            ctx.stats.record_sniff(&ctx.listener, observation.outcome);
        }
    }
    let (result, failure_stage, message, bytes_up, bytes_down) = match &splice_result {
        Ok(stats) => (
            TraceResult::Ok,
            None,
            None,
            stats.bytes_up,
            stats.bytes_down,
        ),
        Err(_) => (
            TraceResult::Error,
            Some("stream_io"),
            Some("tunnel io failed"),
            0,
            0,
        ),
    };
    record_tcp_access(
        ctx,
        started,
        TuicTcpTrace {
            username: &identity.username,
            host: &host,
            port,
            decision: &decision_name,
            effective_policy_host: &effective_policy_host,
            snapshot_version,
            observation: sniff_observation,
            egress: egress.chain_id.is_some().then_some(egress.label.as_str()),
            chain_member: egress.member_id.as_deref(),
            attempts: egress.chain_id.is_some().then_some(egress.attempts),
            result,
            failure_stage,
            message,
            bytes_up,
            bytes_down,
        },
    );
}

struct TuicTcpTrace<'a> {
    username: &'a str,
    host: &'a str,
    port: u16,
    decision: &'a str,
    effective_policy_host: &'a str,
    snapshot_version: u64,
    observation: Option<SniffObservation>,
    egress: Option<&'a str>,
    chain_member: Option<&'a str>,
    attempts: Option<u32>,
    result: TraceResult,
    failure_stage: Option<&'a str>,
    message: Option<&'a str>,
    bytes_up: u64,
    bytes_down: u64,
}

fn record_tcp_access(ctx: &ConnCtx, started: std::time::Instant, trace: TuicTcpTrace<'_>) {
    let Some(log) = &ctx.access_log else {
        return;
    };
    let mut traffic = TrafficIdentity::new(trace.host, trace.port)
        .with_effective_policy_host(trace.effective_policy_host);
    if let Some(observation) = trace.observation {
        traffic = traffic.with_observation(observation);
    }
    let candidate = TraceCandidate {
        listener: ctx.listener.clone(),
        protocol: "tuic".to_string(),
        client_addr: Some(ctx.peer.to_string()),
        username: Some(trace.username.to_string()),
        target_host: Some(trace.host.to_string()),
        target_port: Some(trace.port),
        traffic: Some(traffic),
        decision: Some(trace.decision.to_string()),
        egress: trace.egress.map(str::to_string),
        chain_member: trace.chain_member.map(str::to_string),
        attempts: trace.attempts,
        result: trace.result,
        failure_stage: trace.failure_stage.map(str::to_string),
        message: trace.message.map(str::to_string),
        snapshot_version: trace.snapshot_version,
        duration_ms: started.elapsed().as_millis(),
    };
    log.record_with_ingress(
        &candidate,
        trace.bytes_up,
        trace.bytes_down,
        ctx.ingress.as_ref(),
    );
}

/// Datagrams carry native-mode `Packet` and `Heartbeat`. Per the TUIC spec the
/// server pauses relaying tasks until the connection is authenticated, so wait
/// for the identity before draining datagrams (quinn buffers any that arrive
/// early). Fails closed: if auth never completes, the loop never relays.
async fn datagram_loop(ctx: Arc<ConnCtx>, mut shutdown: watch::Receiver<bool>) {
    let authenticated = tokio::select! {
        biased;
        _ = crate::lifecycle::shutdown_requested(&mut shutdown) => return,
        auth = wait_auth_or_give_up(&ctx) => auth,
    };
    if authenticated.is_none() {
        return;
    }
    loop {
        let bytes = tokio::select! {
            biased;
            _ = crate::lifecycle::shutdown_requested(&mut shutdown) => break,
            received = ctx.connection.read_datagram() => {
                let Ok(bytes) = received else {
                    break;
                };
                bytes
            }
        };
        match codec::parse_datagram(&bytes) {
            Ok(DatagramCommand::Heartbeat) => {}
            Ok(DatagramCommand::Packet(hdr, payload)) => {
                if hdr.frag_total != 1 {
                    debug!(
                        frag_total = hdr.frag_total,
                        "tuic: dropping fragmented packet"
                    );
                    continue;
                }
                let Some((host, port)) = hdr.addr.host_port() else {
                    continue;
                };
                relay_uplink(&ctx, hdr.assoc_id, host, port, payload.to_vec()).await;
            }
            Err(e) => debug!(error = %e, "tuic: bad datagram"),
        }
    }
}

/// Parse+route a quic-mode `Packet` already read whole from a uni-stream.
async fn handle_packet_bytes(ctx: &Arc<ConnCtx>, bytes: &[u8]) {
    // bytes are the command body after `VER|TYPE`; re-wrap minimally.
    let mut framed = Vec::with_capacity(bytes.len() + 2);
    framed.push(codec::VERSION);
    framed.push(cmd::PACKET);
    framed.extend_from_slice(bytes);
    if let Ok(DatagramCommand::Packet(hdr, payload)) = codec::parse_datagram(&framed) {
        if hdr.frag_total == 1 {
            if let Some((host, port)) = hdr.addr.host_port() {
                relay_uplink(ctx, hdr.assoc_id, host, port, payload.to_vec()).await;
            }
        }
    }
}

/// Send one client UDP packet to the hop egress, opening the association (with
/// per-packet policy) on first use and starting its return pump.
async fn relay_uplink(
    ctx: &Arc<ConnCtx>,
    assoc_id: u16,
    host: String,
    port: u16,
    payload: Vec<u8>,
) {
    let Some(identity) = ctx.auth.borrow().clone() else {
        return; // not yet authenticated: drop
    };
    // Per-packet policy: block fails closed (drop), never forwarded.
    if let Decision::Block = ctx.engine.decide(&identity.username, &host) {
        debug!(user = %identity.username, target = %host, "tuic udp packet blocked");
        return;
    }
    let relay = {
        let existing = ctx
            .assoc
            .lock()
            .expect("assoc poisoned")
            .get(&assoc_id)
            .map(|a| a.relay.clone());
        match existing {
            Some(r) => r,
            None => match open_association(ctx, &identity.username, assoc_id, &host).await {
                Some(r) => r,
                None => return,
            },
        }
    };
    let _ = relay.send_to(&payload, &host, port).await;
}

/// Open a new UDP association: choose the egress via policy, open the reverse/2
/// relay, and spawn the pump that turns hop return packets into `Packet`
/// datagrams back to the client. For chain decisions only UDP-capable
/// (reverse) members are tried; the association then sticks to the selected
/// hop for its whole lifetime.
async fn open_association(
    ctx: &Arc<ConnCtx>,
    username: &str,
    assoc_id: u16,
    host: &str,
) -> Option<Arc<UdpRelay>> {
    let decision = ctx.engine.decide(username, host);
    let relay = match crate::outbound::connect_udp(decision, &ctx.egress).await {
        Ok((r, egress)) => {
            debug!(user = %username, assoc_id, egress = %egress.label, "tuic udp association opened");
            Arc::new(r)
        }
        Err(e) => {
            debug!(user = %username, error = %e, "tuic udp: no egress (fail closed)");
            return None;
        }
    };
    let pump = spawn_return_pump(ctx.connection.clone(), relay.clone(), assoc_id);
    let mut table = ctx.assoc.lock().expect("assoc poisoned");
    let entry = table.entry(assoc_id).or_insert_with(|| UdpAssoc {
        relay: relay.clone(),
        return_task: pump,
    });
    Some(entry.relay.clone())
}

/// Pump hop→client return packets: read from the relay, wrap as a native-mode
/// `Packet` datagram tagged with `assoc_id`, and send it to the client.
fn spawn_return_pump(
    connection: quinn::Connection,
    relay: Arc<UdpRelay>,
    assoc_id: u16,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let pkt_id = AtomicU16::new(0);
        while let Ok((payload, host, port)) = relay.recv_from().await {
            let addr = Address::from_host_port(&host, port);
            let id = pkt_id.fetch_add(1, Ordering::Relaxed);
            let dg = codec::encode_packet_datagram(assoc_id, id, &addr, &payload);
            if let Some(max) = connection.max_datagram_size() {
                if dg.len() > max {
                    continue; // no fragmentation
                }
            }
            if connection.send_datagram(dg.into()).is_err() {
                break;
            }
        }
    })
}

/// Wait for authentication with the connection-wide timeout backstop; returns
/// `None` if the connection ends first.
async fn wait_auth_or_give_up(ctx: &Arc<ConnCtx>) -> Option<Arc<Identity>> {
    let rx = ctx.auth.clone();
    tokio::time::timeout(AUTH_TIMEOUT, wait_authenticated(rx))
        .await
        .ok()
}

fn decision_label(decision: &Decision) -> String {
    crate::outbound::decision_label(decision)
}

async fn read_u16<R: tokio::io::AsyncRead + Unpin>(r: &mut R) -> std::io::Result<u16> {
    use tokio::io::AsyncReadExt;
    let mut b = [0u8; 2];
    r.read_exact(&mut b).await?;
    Ok(u16::from_be_bytes(b))
}

async fn read_to_end(recv: &mut quinn::RecvStream, cap: usize) -> std::io::Result<Vec<u8>> {
    recv.read_to_end(cap)
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))
}
