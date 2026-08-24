//! Hop-side reverse client: dial one or more edges, register, and serve the
//! bidirectional QUIC streams each edge opens for user tunnels.
//!
//! Multi-edge is an explicit, hop-owned concern (see issue #50 discussion): a
//! single hop egress can register to several edges so a roaming user keeps a
//! stable hop binding regardless of which edge they enter from. Each configured
//! edge is an independent session with its own address, `hop_id`, token,
//! reconnect loop, per-edge concurrency limit, and observability context. The
//! edges never learn about each other and never proxy for each other.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use super::frame::{
    self, codes, AssociateRequest, DissociateRequest, RegisterRequest, Reply, TunnelRequest,
};
use super::{client_config, udp, QuicDuplex};
use crate::access_log::AccessLogger;
use crate::io::splice;
use crate::stats::TrafficStats;
use crate::trace::{TraceCandidate, TraceResult};
use crate::util::host_of;

/// Default per-edge concurrent-tunnel ceiling on the hop side.
pub const DEFAULT_EDGE_MAX_STREAMS: u32 = 256;

/// One configured reverse edge session for this hop.
#[derive(Debug, Clone)]
pub struct ReverseEdgeConfig {
    /// `host:port` (UDP) of the edge's reverse-hop QUIC listener.
    pub edge_addr: String,
    /// Certificate name to verify / SNI to send. Defaults to the host part of
    /// `edge_addr` when left empty.
    pub server_name: String,
    /// Stable hop identity presented to this edge.
    pub hop_id: String,
    /// Shared registration token (deployment-owned; never logged).
    pub token: String,
    /// Optional label identifying this edge, for logs/metrics only.
    pub edge_id: Option<String>,
    /// Accept a self-signed / IP-only edge certificate. Explicit opt-in.
    pub skip_cert_verify: bool,
    /// Per-edge concurrent-tunnel ceiling.
    pub max_streams: u32,
    /// Optional fixed QUIC path MTU (max UDP-payload bytes) for an already-
    /// compressed outer tunnel. `None` keeps quinn's default PMTUD.
    pub initial_mtu: Option<u16>,
}

impl ReverseEdgeConfig {
    /// Resolve the certificate/SNI name, falling back to the edge host.
    fn effective_server_name(&self) -> String {
        let trimmed = self.server_name.trim();
        if trimmed.is_empty() {
            host_of(&self.edge_addr).to_string()
        } else {
            trimmed.to_string()
        }
    }
}

/// Whole-hop reverse client configuration.
#[derive(Debug, Clone)]
pub struct ReverseHopClientConfig {
    pub edges: Vec<ReverseEdgeConfig>,
    /// Global concurrent-tunnel ceiling across all edges. 0 = unlimited.
    pub global_max_streams: u32,
    /// Hop identity attached to access-log rows.
    pub node_id: String,
}

/// Spawn one independent, self-healing session task per configured edge. Each
/// runs until the process exits, reconnecting with capped exponential backoff.
pub fn spawn(
    config: ReverseHopClientConfig,
    access_log: Option<Arc<AccessLogger>>,
    stats: Arc<TrafficStats>,
) {
    let global = if config.global_max_streams == 0 {
        None
    } else {
        Some(Arc::new(Semaphore::new(config.global_max_streams as usize)))
    };
    for edge in config.edges {
        let global = global.clone();
        let access_log = access_log.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            edge_session_loop(edge, global, access_log, stats).await;
        });
    }
}

async fn edge_session_loop(
    edge: ReverseEdgeConfig,
    global: Option<Arc<Semaphore>>,
    access_log: Option<Arc<AccessLogger>>,
    stats: Arc<TrafficStats>,
) {
    let min_backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(30);
    let mut backoff = min_backoff;
    let per_edge = Arc::new(Semaphore::new(edge.max_streams.max(1) as usize));
    loop {
        let started = Instant::now();
        let outcome =
            connect_and_serve(&edge, &per_edge, &global, access_log.as_ref(), &stats).await;
        match outcome {
            Ok(()) => info!(
                edge_addr = %edge.edge_addr,
                hop_id = %edge.hop_id,
                "reverse edge session ended; reconnecting"
            ),
            Err(e) => warn!(
                edge_addr = %edge.edge_addr,
                hop_id = %edge.hop_id,
                error = %e,
                "reverse edge session failed; reconnecting"
            ),
        }
        // A session that stayed up for a while is a healthy edge — reset the
        // backoff so a later blip reconnects promptly.
        if started.elapsed() >= Duration::from_secs(30) {
            backoff = min_backoff;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(max_backoff);
    }
}

async fn connect_and_serve(
    edge: &ReverseEdgeConfig,
    per_edge: &Arc<Semaphore>,
    global: &Option<Arc<Semaphore>>,
    access_log: Option<&Arc<AccessLogger>>,
    stats: &Arc<TrafficStats>,
) -> anyhow::Result<()> {
    let (edge_host, edge_port) = edge
        .edge_addr
        .rsplit_once(':')
        .and_then(|(h, p)| p.parse::<u16>().ok().map(|p| (h, p)))
        .ok_or_else(|| anyhow::anyhow!("bad edge addr {}", edge.edge_addr))?;
    let remote: SocketAddr = crate::resolver::resolve_one(edge_host, edge_port)
        .await
        .map_err(|e| anyhow::anyhow!("resolve edge {}: {e}", edge.edge_addr))?;

    let bind: SocketAddr = if remote.is_ipv6() {
        "[::]:0".parse().expect("valid v6 bind")
    } else {
        "0.0.0.0:0".parse().expect("valid v4 bind")
    };
    let endpoint = quinn::Endpoint::client(bind)
        .map_err(|e| anyhow::anyhow!("bind reverse client socket: {e}"))?;
    let client_cfg = client_config(
        edge.skip_cert_verify,
        edge.max_streams.max(1),
        edge.initial_mtu,
    )?;

    let server_name = edge.effective_server_name();
    let connection = endpoint
        .connect_with(client_cfg, remote, &server_name)
        .map_err(|e| anyhow::anyhow!("connect edge {remote}: {e}"))?
        .await
        .map_err(|e| anyhow::anyhow!("handshake edge {remote}: {e}"))?;

    // Control/register stream: the hop's first bidirectional stream.
    let (mut control_send, mut control_recv) = connection
        .open_bi()
        .await
        .map_err(|e| anyhow::anyhow!("open control stream: {e}"))?;
    let register = RegisterRequest {
        hop_id: edge.hop_id.clone(),
        token: edge.token.clone(),
        edge_id: edge.edge_id.clone(),
        // Advertise UDP relay capability so the edge may route UDP associations
        // here. The matching ASSOCIATE handler lives in this hop's session loop;
        // the edge fails closed (`udp_unsupported`) for any hop that omits this.
        caps: vec!["udp".to_string()],
    };
    frame::write_frame(&mut control_send, &register.encode())
        .await
        .map_err(|e| anyhow::anyhow!("send register: {e}"))?;
    let reply_lines = frame::read_frame(&mut control_recv)
        .await
        .map_err(|e| anyhow::anyhow!("read register reply: {e}"))?;
    match Reply::parse(&reply_lines) {
        Ok(Reply::Ok) => info!(
            edge_addr = %edge.edge_addr,
            hop_id = %edge.hop_id,
            edge_id = ?edge.edge_id,
            "registered to reverse edge"
        ),
        Ok(Reply::Err(code)) => {
            // Unauthorized/duplicate are operator problems; surface loudly but
            // let the caller's backoff avoid a hot loop.
            anyhow::bail!("edge refused registration: {code}");
        }
        Err(e) => anyhow::bail!("malformed register reply: {e}"),
    }

    // Per-connection UDP relay state: one egress socket per association, an
    // idle sweeper, and a datagram reader that routes edge->hop packets. Capped
    // at the same per-edge stream ceiling. Only meaningful because we advertised
    // `caps: udp`; a hop that did not would simply never receive ASSOCIATE.
    let udp_table = udp::HopUdpTable::new(edge.max_streams.max(1) as usize);
    udp::spawn_hop_demux(connection.clone(), udp_table.clone());

    // Serve tunnel streams until the edge (or network) drops the connection.
    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                // Normal on graceful edge shutdown; caller reconnects.
                return Err(anyhow::anyhow!("edge connection closed: {e}"));
            }
        };

        let per_permit = per_edge.clone().try_acquire_owned().ok();
        let global_permit = match global {
            Some(sem) => sem.clone().try_acquire_owned().ok().map(Some),
            None => Some(None),
        };
        let (per_permit, global_permit) = match (per_permit, global_permit) {
            (Some(p), Some(g)) => (p, g),
            _ => {
                // At capacity: reply on this one stream only, connection intact.
                let hop_id = edge.hop_id.clone();
                tokio::spawn(async move {
                    let mut send = send;
                    let _ = frame::write_frame(
                        &mut send,
                        &Reply::Err(codes::AT_CAPACITY.into()).encode(),
                    )
                    .await;
                    let _ = send.finish();
                    warn!(hop_id = %hop_id, "reverse tunnel refused: at capacity");
                    drop(recv);
                });
                continue;
            }
        };

        let ctx = TunnelCtx {
            edge_addr: edge.edge_addr.clone(),
            edge_id: edge.edge_id.clone(),
            hop_id: edge.hop_id.clone(),
            remote,
            access_log: access_log.cloned(),
            stats: stats.clone(),
        };
        let udp_table = udp_table.clone();
        let conn = connection.clone();
        tokio::spawn(async move {
            serve_stream(ctx, udp_table, conn, send, recv).await;
            drop(per_permit);
            drop(global_permit);
        });
    }
}

/// Per-tunnel context captured for logging/metrics, kept free of secrets. The
/// hop's `node_id` is stamped by the shared [`AccessLogger`], so it is not
/// carried here.
struct TunnelCtx {
    edge_addr: String,
    edge_id: Option<String>,
    hop_id: String,
    remote: SocketAddr,
    access_log: Option<Arc<AccessLogger>>,
    stats: Arc<TrafficStats>,
}

/// Read the first frame on a newly accepted stream and dispatch by verb:
/// `CONNECT` opens a TCP tunnel, `ASSOCIATE` opens a UDP association. Anything
/// else is a bad request.
async fn serve_stream(
    ctx: TunnelCtx,
    udp_table: std::sync::Arc<udp::HopUdpTable>,
    connection: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) {
    let started = Instant::now();
    let lines = match frame::read_frame(&mut recv).await {
        Ok(lines) => lines,
        Err(e) => {
            debug!(hop_id = %ctx.hop_id, error = %e, "reverse stream: unreadable frame");
            let _ = frame::write_frame(&mut send, &Reply::Err(codes::BAD_REQUEST.into()).encode())
                .await;
            let _ = send.finish();
            record(
                &ctx,
                None,
                TraceResult::Error,
                Some("reverse_open"),
                Some("unreadable frame"),
                0,
                0,
                started,
            );
            return;
        }
    };
    let verb = lines
        .first()
        .and_then(|l| l.split_whitespace().next())
        .unwrap_or("");
    match verb {
        "CONNECT" => serve_tcp_tunnel(ctx, send, recv, lines, started).await,
        "ASSOCIATE" => {
            serve_udp_associate(udp_table, connection, send, recv, lines, &ctx.hop_id).await
        }
        other => {
            debug!(hop_id = %ctx.hop_id, verb = other, "reverse stream: unknown verb");
            let _ = frame::write_frame(&mut send, &Reply::Err(codes::BAD_REQUEST.into()).encode())
                .await;
            let _ = send.finish();
            record(
                &ctx,
                None,
                TraceResult::Error,
                Some("reverse_open"),
                Some("unknown verb"),
                0,
                0,
                started,
            );
        }
    }
}

/// Serve one UDP association: allocate an egress socket (via the shared table),
/// acknowledge, then hold the control stream open until the edge sends
/// `DISSOCIATE` or drops it, at which point the association is reclaimed.
async fn serve_udp_associate(
    udp_table: std::sync::Arc<udp::HopUdpTable>,
    connection: quinn::Connection,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    lines: Vec<String>,
    hop_id: &str,
) {
    let req = match AssociateRequest::parse(&lines) {
        Ok(r) => r,
        Err(e) => {
            debug!(hop_id = %hop_id, error = %e, "reverse udp: malformed ASSOCIATE");
            let _ = frame::write_frame(&mut send, &Reply::Err(codes::BAD_REQUEST.into()).encode())
                .await;
            let _ = send.finish();
            return;
        }
    };
    if !udp_table
        .associate(req.session_id, connection.clone())
        .await
    {
        let _ = frame::write_frame(
            &mut send,
            &Reply::Err(codes::UDP_AT_CAPACITY.into()).encode(),
        )
        .await;
        let _ = send.finish();
        warn!(
            hop_id = %hop_id,
            session_id = req.session_id,
            "reverse udp association refused: at capacity or bind failed"
        );
        return;
    }
    if frame::write_frame(&mut send, &Reply::Ok.encode())
        .await
        .is_err()
    {
        udp_table.remove(req.session_id);
        return;
    }
    info!(
        hop_id = %hop_id,
        session_id = req.session_id,
        assoc_id = ?req.assoc_id,
        "reverse udp association established"
    );
    // Hold the control stream until an explicit DISSOCIATE or the edge closing
    // it signals teardown. Unknown frames are ignored so the stream stays live.
    while let Ok(lines) = frame::read_frame(&mut recv).await {
        if DissociateRequest::parse(&lines).map(|d| d.session_id) == Ok(req.session_id) {
            break;
        }
    }
    udp_table.remove(req.session_id);
    debug!(
        hop_id = %hop_id,
        session_id = req.session_id,
        "reverse udp association closed"
    );
}

async fn serve_tcp_tunnel(
    ctx: TunnelCtx,
    mut send: quinn::SendStream,
    recv: quinn::RecvStream,
    lines: Vec<String>,
    started: Instant,
) {
    let request = match TunnelRequest::parse(&lines) {
        Ok(req) => req,
        Err(e) => {
            debug!(hop_id = %ctx.hop_id, error = %e, "reverse tunnel: malformed CONNECT");
            let _ = frame::write_frame(&mut send, &Reply::Err(codes::BAD_REQUEST.into()).encode())
                .await;
            let _ = send.finish();
            record(
                &ctx,
                None,
                TraceResult::Error,
                Some("reverse_open"),
                Some("malformed connect frame"),
                0,
                0,
                started,
            );
            return;
        }
    };

    let target = (request.host.clone(), request.port);
    let outbound = match crate::resolver::tcp_connect(request.host.as_str(), request.port).await {
        Ok(sock) => sock,
        Err(e) => {
            debug!(
                hop_id = %ctx.hop_id,
                tunnel_id = ?request.tunnel_id,
                target = %format!("{}:{}", request.host, request.port),
                error = %e,
                "reverse tunnel: target connect failed"
            );
            let _ = frame::write_frame(
                &mut send,
                &Reply::Err(codes::CONNECT_FAILED.into()).encode(),
            )
            .await;
            let _ = send.finish();
            record(
                &ctx,
                Some(target),
                TraceResult::Error,
                Some("hop_connect"),
                Some("target connect failed"),
                0,
                0,
                started,
            );
            return;
        }
    };
    let _ = outbound.set_nodelay(true);

    if let Err(e) = frame::write_frame(&mut send, &Reply::Ok.encode()).await {
        debug!(hop_id = %ctx.hop_id, error = %e, "reverse tunnel: OK write failed");
        record(
            &ctx,
            Some(target),
            TraceResult::Error,
            Some("stream_io"),
            Some("ok write failed"),
            0,
            0,
            started,
        );
        return;
    }

    info!(
        edge_id = ?ctx.edge_id,
        hop_id = %ctx.hop_id,
        tunnel_id = ?request.tunnel_id,
        target = %format!("{}:{}", request.host, request.port),
        "reverse tunnel established"
    );

    let _egress_guard = ctx.stats.track_egress("reverse");
    let duplex = QuicDuplex::new(send, recv);
    let splice_result = splice(duplex, outbound, 0, 0).await;
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
            Some("stream_io"),
            Some("tunnel io failed"),
            0,
            0,
        ),
    };
    ctx.stats
        .record_egress_bytes("reverse", bytes_up, bytes_down);
    record(
        &ctx,
        Some(target),
        result,
        stage,
        message,
        bytes_up,
        bytes_down,
        started,
    );
}

#[allow(clippy::too_many_arguments)]
fn record(
    ctx: &TunnelCtx,
    target: Option<(String, u16)>,
    result: TraceResult,
    failure_stage: Option<&str>,
    message: Option<&str>,
    bytes_up: u64,
    bytes_down: u64,
    started: Instant,
) {
    let Some(access_log) = &ctx.access_log else {
        return;
    };
    let (target_host, target_port) = match target {
        Some((h, p)) => (Some(h), Some(p)),
        None => (None, None),
    };
    let candidate = TraceCandidate {
        listener: ctx
            .edge_id
            .clone()
            .map(|id| format!("reverse:{id}"))
            .unwrap_or_else(|| format!("reverse:{}", ctx.edge_addr)),
        protocol: "reverse".to_string(),
        client_addr: Some(ctx.remote.to_string()),
        username: None,
        target_host,
        target_port,
        traffic: None,
        sniff: None,
        decision: Some(format!("reverse:{}", ctx.hop_id)),
        egress: None,
        chain_member: None,
        attempts: None,
        result,
        failure_stage: failure_stage.map(str::to_string),
        message: message.map(str::to_string),
        snapshot_version: 0,
        duration_ms: started.elapsed().as_millis(),
    };
    access_log.record(&candidate, bytes_up, bytes_down);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn effective_server_name_defaults_to_host() {
        let edge = ReverseEdgeConfig {
            edge_addr: "edge.example.com:9443".to_string(),
            server_name: String::new(),
            hop_id: "hop-1".to_string(),
            token: "t".to_string(),
            edge_id: None,
            skip_cert_verify: false,
            max_streams: 8,
            initial_mtu: None,
        };
        assert_eq!(edge.effective_server_name(), "edge.example.com");
    }

    #[test]
    fn effective_server_name_prefers_explicit() {
        let edge = ReverseEdgeConfig {
            edge_addr: "10.0.0.5:9443".to_string(),
            server_name: "edge.internal".to_string(),
            hop_id: "hop-1".to_string(),
            token: "t".to_string(),
            edge_id: None,
            skip_cert_verify: true,
            max_streams: 8,
            initial_mtu: None,
        };
        assert_eq!(edge.effective_server_name(), "edge.internal");
    }
}
