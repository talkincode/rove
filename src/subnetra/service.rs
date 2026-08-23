//! Startup orchestration: wire the subnetra data plane and userspace IP stack
//! into Rove's proxy engine.
//!
//! * **hub** — bind the UDP data plane, run the userspace IP stack listening on
//!   the overlay IP + proxy port, and serve each accepted overlay TCP connection
//!   with Rove's existing HTTP/SOCKS handlers. This is how a NAT'd spoke reaches
//!   Rove's proxy "over the tunnel".
//! * **spoke** — bind the data plane egress-only and hand back a [`NetHandle`] so
//!   Rove's outbound layer can dial overlay destinations.

use std::sync::Arc;

use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, info};

use crate::access_log::AccessLogger;
use crate::diagnostics::DiagnosticRegistry;
use crate::engine::Engine;
use crate::inbound::{self, Ctx};
use crate::outbound::EgressContext;
use crate::reverse::ReverseHopManager;
use crate::stats::TrafficStats;
use crate::trace::ProbeTracer;

use super::config::{Mode, SubnetraConfig};
use super::netstack::{self, NetHandle, SubnetraStream};
use super::reactor;

/// Bring up the subnetra services described by `cfg`. Returns the egress handle
/// (usable for spoke outbound; harmless to hold on a hub) and the bound UDP
/// address of the data plane. Fails closed on any config or bind error so an
/// enabled-but-broken mesh never starts silently.
#[allow(clippy::too_many_arguments)]
pub async fn start(
    cfg: &SubnetraConfig,
    engine: Arc<Engine>,
    stats: Arc<TrafficStats>,
    access_log: Option<Arc<AccessLogger>>,
    reverse: Option<Arc<ReverseHopManager>>,
    tracer: Option<Arc<ProbeTracer>>,
    diagnostics: Option<Arc<DiagnosticRegistry>>,
) -> anyhow::Result<(NetHandle, std::net::SocketAddr)> {
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let (handle, addr, _accept_task) = start_until(
        cfg,
        engine,
        stats,
        access_log,
        reverse,
        tracer,
        diagnostics,
        shutdown_rx,
    )
    .await?;
    Ok((handle, addr))
}

/// Start Subnetra with a process shutdown signal. Hub mode returns the task
/// that owns the overlay accept loop so the caller can include it in draining.
#[allow(clippy::too_many_arguments)]
pub async fn start_until(
    cfg: &SubnetraConfig,
    engine: Arc<Engine>,
    stats: Arc<TrafficStats>,
    access_log: Option<Arc<AccessLogger>>,
    reverse: Option<Arc<ReverseHopManager>>,
    tracer: Option<Arc<ProbeTracer>>,
    diagnostics: Option<Arc<DiagnosticRegistry>>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<(NetHandle, std::net::SocketAddr, Option<JoinHandle<()>>)> {
    let rt = cfg.to_runtime()?;
    let epoch = super::sample_boot_epoch()?;
    let overlay_ip = rt.overlay_ip();
    let overlay_prefix = rt.overlay.prefix_len();
    let mode = rt.mode;
    let hub_proxy = rt.hub_proxy.clone();
    let listen_port = hub_proxy.as_ref().map(|(_, port)| *port);
    let mtu = rt.mtu;

    let (dp, inbound_rx) = reactor::spawn(rt, epoch).await?;
    let bound = dp.local_addr();
    let (net, accept_rx) =
        netstack::spawn(dp, inbound_rx, overlay_ip, overlay_prefix, listen_port, mtu);

    let accept_task = if mode == Mode::Hub {
        let (proto, port) = hub_proxy.expect("hub_proxy present for hub mode (validated)");
        let ctx = Arc::new(Ctx {
            engine,
            listener: format!("subnetra-hub-{proto}"),
            sniff: crate::config::SniffConfig::default(),
            tracer,
            diagnostics,
            access_log,
            stats,
            egress: EgressContext::new(reverse, Some(net.clone())),
        });
        info!(
            overlay = %overlay_ip,
            port,
            protocol = %proto,
            "subnetra hub inbound proxy serving over the overlay"
        );
        Some(tokio::spawn(serve_accepts(accept_rx, ctx, proto, shutdown)))
    } else {
        info!(overlay = %overlay_ip, "subnetra spoke egress ready");
        None
    };

    Ok((net, bound, accept_task))
}

/// Serve each accepted overlay connection with Rove's HTTP/SOCKS dispatch. A
/// [`SubnetraStream`] is an `IoStream`, so it drops straight into the same
/// handlers a TCP listener uses.
async fn serve_accepts(
    mut accept_rx: tokio::sync::mpsc::Receiver<(SubnetraStream, std::net::SocketAddr)>,
    ctx: Arc<Ctx>,
    proto: String,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = crate::lifecycle::shutdown_requested(&mut shutdown) => {
                accept_rx.close();
                while let Some((stream, peer)) = accept_rx.recv().await {
                    spawn_connection(&mut connections, stream, peer, ctx.clone(), proto.clone());
                }
                info!(active = connections.len(), "subnetra hub stopped accepting new connections");
                break;
            }
            accepted = accept_rx.recv() => {
                let Some((stream, peer)) = accepted else {
                    break;
                };
                spawn_connection(&mut connections, stream, peer, ctx.clone(), proto.clone());
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(e) = result {
                    debug!(error = %e, "subnetra hub connection task ended unexpectedly");
                }
            }
        }
    }
    while let Some(result) = connections.join_next().await {
        if let Err(e) = result {
            debug!(error = %e, "subnetra hub connection task ended unexpectedly");
        }
    }
    info!("subnetra hub connections drained");
}

fn spawn_connection(
    connections: &mut JoinSet<()>,
    stream: SubnetraStream,
    peer: std::net::SocketAddr,
    ctx: Arc<Ctx>,
    proto: String,
) {
    connections.spawn(async move {
        let result = match proto.as_str() {
            "http" => inbound::http::serve(stream, ctx, peer).await,
            // UDP ASSOCIATE has no meaning over the overlay TCP path, so the
            // local-addr hint is `None`; TCP CONNECT is unaffected.
            "socks5" => inbound::socks5::serve(stream, ctx, peer, None).await,
            _ => Ok(()),
        };
        if let Err(e) = result {
            debug!(%peer, "subnetra hub connection ended: {e}");
        }
    });
}
