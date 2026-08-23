use rove::config::Config;
use rove::diagnostics::DiagnosticRegistry;
use rove::engine::Engine;
use rove::{inbound, mqtt, sync, tls, trace};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::{JoinHandle, JoinSet};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "validate-snapshot") {
        let exit_code = rove::snapshot_validator::run_cli(
            args.into_iter().skip(1),
            std::io::stdin().lock(),
            std::io::stdout().lock(),
        );
        if exit_code == 0 {
            return Ok(());
        }
        std::process::exit(exit_code.into());
    }

    let cfg_path = parse_config_path_from(args);
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run_daemon(cfg_path))
}

async fn run_daemon(cfg_path: String) -> anyhow::Result<()> {
    let cfg = Config::load(&cfg_path)?;
    init_tracing(&cfg.log.level);
    tls::init_crypto();
    // Install the dedicated egress resolver before any egress path starts. With
    // no `[dns].servers` configured this is a no-op and the OS resolver is used.
    rove::resolver::init(&cfg.dns.to_settings()?)?;
    if rove::resolver::is_custom() {
        info!(
            servers = cfg.dns.servers.len(),
            "using dedicated egress DNS"
        );
    }

    let Config {
        node_id,
        control_plane,
        health: health_cfg,
        shutdown: shutdown_cfg,
        listeners,
        mqtt,
        access_log: access_log_cfg,
        snmp: snmp_cfg,
        reverse_hop: reverse_hop_cfg,
        reverse_ingress: reverse_ingress_cfg,
        tuic_listeners,
        subnetra: subnetra_cfg,
        addrbook: addrbook_cfg,
        ..
    } = cfg;

    // A Subnetra *hub* serves its proxy over the overlay, so it needs no TCP
    // listener; every other node still requires at least one inbound listener.
    let subnetra_hub_enabled = subnetra_cfg
        .as_ref()
        .map(|s| s.enable && s.mode.trim().eq_ignore_ascii_case("hub"))
        .unwrap_or(false);

    info!(
        node_id = %node_id,
        tcp_listeners = listeners.len(),
        tuic_listeners = tuic_listeners.len(),
        "rove starting"
    );
    if !subnetra_hub_enabled {
        ensure_listeners_configured(&listeners, &tuic_listeners)?;
    }
    let data_plane_required = !listeners.is_empty() || !tuic_listeners.is_empty();
    let mut reverse_ingress = Vec::new();
    for connector in &reverse_ingress_cfg {
        if let Some(runtime) = connector.to_runtime(&node_id, &listeners, &tuic_listeners)? {
            reverse_ingress.push(runtime);
        }
    }

    let engine = Engine::new();
    // Load the addrbook before the first snapshot compile so `book:` rules
    // resolve from the start. A configured-but-unloadable artifact aborts
    // startup: serving without the requested book would fail open.
    let addrbook_service = match &addrbook_cfg {
        Some(ab) => Some(rove::addrbook::AddrBookService::load(&ab.path)?),
        None => None,
    };
    let mut syncer = sync::Syncer::new(control_plane, node_id.clone(), engine.clone())?;
    if let Some(service) = &addrbook_service {
        syncer = syncer.with_addrbook(service.clone());
    }
    let syncer = std::sync::Arc::new(syncer);
    let (trace_tx, trace_rx) = tokio::sync::mpsc::channel(128);
    let tracer = std::sync::Arc::new(trace::ProbeTracer::new(trace_tx));
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let runtime_health = rove::health::RuntimeHealth::new_with_data_plane(
        engine.clone(),
        syncer.clone(),
        Duration::from_secs(health_cfg.control_plane_unreachable_secs),
        data_plane_required,
    );

    // Traffic counters are always on (independent of the access log) so the
    // SNMP agent and periodic stats reports stay accurate even when JSONL
    // access logging is disabled.
    let stats = rove::stats::TrafficStats::new();

    // Bind every explicitly configured data-plane listener before background
    // services start. A bad address, certificate, key, or protocol is a startup
    // failure rather than a silently missing ingress.
    let mut bound_listeners = Vec::with_capacity(listeners.len());
    for listener in listeners {
        bound_listeners
            .push(inbound::listener::BoundListener::bind(listener, stats.clone()).await?);
    }
    let mut bound_tuic_listeners = Vec::with_capacity(tuic_listeners.len());
    for listener in tuic_listeners {
        bound_tuic_listeners.push(inbound::tuic::BoundListener::bind(
            listener.to_runtime(),
            stats.clone(),
        )?);
    }

    // The access log is the structured, grep-able replacement for legacy
    // GOST-style per-connection traffic logs; enabled by default so ops can
    // always reach for it during a fault investigation without a restart.
    let access_log = if access_log_cfg.enable {
        Some(rove::access_log::AccessLogger::spawn(
            &access_log_cfg,
            node_id.clone(),
            stats.clone(),
        )?)
    } else {
        None
    };

    let cache_outcome = syncer.load_cache();
    info!(
        success = cache_outcome.success,
        updated = cache_outcome.updated,
        version = cache_outcome.version,
        message = %cache_outcome.message,
        "snapshot cache load finished"
    );

    // Control-plane sync runs in the background and hot-swaps policy.
    tokio::spawn(syncer.clone().run_polling());

    // Addrbook hot reload: poll the artifact file and adopt new releases
    // atomically (book swap + snapshot recompile as one decision).
    if let (Some(service), Some(ab_cfg)) = (&addrbook_service, &addrbook_cfg) {
        tokio::spawn(rove::addrbook::poll_file_changes(
            service.clone(),
            syncer.clone(),
            ab_cfg.poll_interval_secs,
        ));
    }

    let mut services = JoinSet::new();

    if health_cfg.enable {
        let server = rove::health::HealthServer::bind(&health_cfg, runtime_health.clone()).await?;
        let health_shutdown = shutdown_rx.clone();
        services.spawn(async move {
            if let Err(e) = server.run(health_shutdown).await {
                error!(error = %e, "health endpoint stopped");
            }
        });
    }

    // Edge-side reverse-hop data plane: only started when explicitly enabled.
    // A bind/config failure here is fatal — the operator asked for reverse
    // egress, so silently continuing without it would fail every reverse route
    // in a way that looks like a routing bug rather than a startup problem.
    let reverse = if reverse_hop_cfg.enable {
        let listener_cfg = reverse_hop_cfg.to_listener_config(&node_id)?;
        let manager = rove::reverse::ReverseHopManager::spawn(listener_cfg)?;
        info!("reverse-hop QUIC data plane enabled");
        Some(manager)
    } else {
        None
    };

    // Diagnostic sessions are opt-in and only wired when MQTT is enabled, since
    // the command/response channel rides on the broker. Listeners share the same
    // registry Arc so hot paths can record events without blocking.
    let mut diagnostics: Option<Arc<DiagnosticRegistry>> = None;
    if mqtt.enable {
        let limits = mqtt.diagnostics.to_limits();
        let channel_capacity = mqtt.diagnostics.effective_channel_capacity();
        let (diag_tx, diag_rx) = tokio::sync::mpsc::channel(channel_capacity);
        let registry = Arc::new(DiagnosticRegistry::new(node_id.clone(), limits, diag_tx));
        diagnostics = Some(registry.clone());

        let service = mqtt::MqttService::new(
            mqtt,
            node_id.clone(),
            engine.clone(),
            syncer.clone(),
            tracer.clone(),
            trace_rx,
            registry,
            diag_rx,
            format!("Rove/{}", env!("CARGO_PKG_VERSION")),
        );
        tokio::spawn(async move {
            if let Err(e) = service.run().await {
                error!(error = %e, "mqtt service stopped");
            }
        });
    }

    // Embedded Subnetra mesh underlay (hub or spoke). A hub spawns an overlay
    // proxy accept loop; a spoke exposes an egress handle. A config/bind error is
    // fatal — the operator asked for the mesh, so failing closed beats a silently
    // dead tunnel. The returned handle is installed in the explicit egress
    // context shared by all front-end listeners.
    let mut subnetra_accept_task: Option<JoinHandle<()>> = None;
    let subnetra_egress = if let Some(sn) = subnetra_cfg.as_ref().filter(|s| s.enable) {
        let (handle, addr, accept_task) = rove::subnetra::service::start_until(
            sn,
            engine.clone(),
            stats.clone(),
            access_log.clone(),
            reverse.clone(),
            Some(tracer.clone()),
            diagnostics.clone(),
            shutdown_rx.clone(),
        )
        .await?;
        subnetra_accept_task = accept_task;
        info!(bound = %addr, "subnetra data plane bound");
        Some(handle)
    } else {
        None
    };
    let egress = rove::outbound::EgressContext::new(reverse.clone(), subnetra_egress);

    let (listener_failure_tx, mut listener_failure_rx) =
        tokio::sync::mpsc::unbounded_channel::<anyhow::Error>();
    for listener in bound_listeners {
        let engine = engine.clone();
        let tracer = Some(tracer.clone());
        let diagnostics = diagnostics.clone();
        let access_log = access_log.clone();
        let stats = stats.clone();
        let egress = egress.clone();
        let name = listener.name().to_string();
        let listener_health = runtime_health.clone();
        let failure_tx = listener_failure_tx.clone();
        let listener_shutdown = shutdown_rx.clone();
        let shutdown_observer = listener_shutdown.clone();
        services.spawn(async move {
            let _lease = listener_health.data_plane_online();
            let result = listener
                .run_until(
                    engine,
                    tracer,
                    diagnostics,
                    access_log,
                    stats,
                    egress,
                    listener_shutdown,
                )
                .await;
            if let Err(e) = &result {
                error!(listener = %name, error = %e, "listener stopped");
            }
            if !*shutdown_observer.borrow() {
                let failure = match result {
                    Ok(()) => anyhow::anyhow!("listener {name} stopped unexpectedly"),
                    Err(e) => anyhow::anyhow!("listener {name} stopped: {e:#}"),
                };
                let _ = failure_tx.send(failure);
            }
        });
    }

    // TUIC v5 front-end listeners (QUIC). Independent of the TCP listeners
    // above; each authenticates locally and reuses the shared egress.
    for listener in bound_tuic_listeners {
        let engine = engine.clone();
        let stats = stats.clone();
        let access_log = access_log.clone();
        let egress = egress.clone();
        let name = listener.name().to_string();
        let listener_health = runtime_health.clone();
        let failure_tx = listener_failure_tx.clone();
        let listener_shutdown = shutdown_rx.clone();
        let shutdown_observer = listener_shutdown.clone();
        services.spawn(async move {
            let _lease = listener_health.data_plane_online();
            let result = listener
                .run_until(engine, stats, access_log, egress, listener_shutdown)
                .await;
            if let Err(e) = &result {
                error!(listener = %name, error = %e, "tuic listener stopped");
            }
            if !*shutdown_observer.borrow() {
                let failure = match result {
                    Ok(()) => anyhow::anyhow!("tuic listener {name} stopped unexpectedly"),
                    Err(e) => anyhow::anyhow!("tuic listener {name} stopped: {e:#}"),
                };
                let _ = failure_tx.send(failure);
            }
        });
    }

    // NAT-side public ingress connector. It starts after local TCP/TUIC
    // listeners have been spawned, and may only target those named listeners.
    for config in reverse_ingress {
        let ingress_shutdown = shutdown_rx.clone();
        services.spawn(async move {
            if let Err(e) = rove::ingress::connector::run_until(config, ingress_shutdown).await {
                error!(error = %e, "reverse-ingress connector stopped");
            }
        });
    }

    // The read-only SNMP agent runs on its own UDP task; a bind failure (or
    // any later socket error) is logged but never stops the proxy.
    if snmp_cfg.enable {
        let identity = rove::snmp::AgentIdentity {
            node_id: node_id.clone(),
            role: rove::snmp::mib::NodeRole::Edge,
            version: env!("CARGO_PKG_VERSION").to_string(),
        };
        let snmp_stats = stats.clone();
        tokio::spawn(async move {
            if let Err(e) = rove::snmp::run_agent(snmp_cfg, identity, snmp_stats).await {
                error!(error = %e, "snmp agent stopped");
            }
        });
    }

    let _listener_failure_guard = listener_failure_tx;
    let fatal_listener_error = tokio::select! {
        signal = wait_for_shutdown_signal() => {
            let signal = signal?;
            info!(signal, "shutdown signal received");
            None
        }
        failure = listener_failure_rx.recv() => {
            let failure = failure
                .unwrap_or_else(|| anyhow::anyhow!("listener supervision channel closed"));
            error!(error = %failure, "data-plane listener failed; shutting down");
            Some(failure)
        }
    };
    runtime_health.begin_draining();
    let _ = shutdown_tx.send(true);
    let grace = Duration::from_secs(shutdown_cfg.grace_period_secs);
    info!(
        grace_period_secs = shutdown_cfg.grace_period_secs,
        "graceful shutdown started"
    );
    drain_services(&mut services, &mut subnetra_accept_task, grace).await;
    match fatal_listener_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn drain_services(
    services: &mut JoinSet<()>,
    subnetra_accept_task: &mut Option<JoinHandle<()>>,
    grace: Duration,
) {
    let drain = async {
        while let Some(result) = services.join_next().await {
            if let Err(e) = result {
                error!(error = %e, "service task ended unexpectedly");
            }
        }
        if let Some(task) = subnetra_accept_task.as_mut() {
            if let Err(e) = task.await {
                error!(error = %e, "subnetra accept task ended unexpectedly");
            }
        }
    };

    match tokio::time::timeout(grace, drain).await {
        Ok(()) => info!("graceful shutdown drain completed"),
        Err(_) => {
            let remaining = services.len() + usize::from(subnetra_accept_task.is_some());
            warn!(
                remaining,
                grace_period_secs = grace.as_secs(),
                "graceful shutdown timed out; aborting remaining connections"
            );
            services.abort_all();
            if let Some(task) = subnetra_accept_task.as_ref() {
                task.abort();
            }
            while services.join_next().await.is_some() {}
            if let Some(task) = subnetra_accept_task.take() {
                let _ = task.await;
            }
        }
    }
}

/// Block until a shutdown signal arrives and report which one it was.
///
/// SIGINT (ctrl_c) covers interactive use; SIGTERM is what `docker stop`,
/// Kubernetes and systemd send, so a production node must treat it as a clean
/// shutdown request instead of dying by the default signal disposition.
#[cfg(unix)]
async fn wait_for_shutdown_signal() -> anyhow::Result<&'static str> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        r = tokio::signal::ctrl_c() => r.map(|()| "SIGINT").map_err(Into::into),
        _ = sigterm.recv() => Ok("SIGTERM"),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> anyhow::Result<&'static str> {
    tokio::signal::ctrl_c().await?;
    Ok("ctrl_c")
}

fn parse_config_path_from<I>(args: I) -> String
where
    I: IntoIterator,
    I::Item: Into<String>,
{
    let args: Vec<String> = args.into_iter().map(Into::into).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                if i + 1 < args.len() {
                    return args[i + 1].clone();
                }
            }
            other if !other.starts_with('-') => return other.to_string(),
            _ => {}
        }
        i += 1;
    }
    "config.toml".to_string()
}

fn init_tracing(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("rove={level},warn")));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn ensure_listeners_configured(
    listeners: &[rove::config::Listener],
    tuic_listeners: &[rove::config::TuicListener],
) -> anyhow::Result<()> {
    if listeners.is_empty() && tuic_listeners.is_empty() {
        error!("no listeners configured; refusing to start");
        anyhow::bail!("at least one listener is required");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ensure_listeners_configured, parse_config_path_from};

    #[test]
    fn config_path_defaults_when_missing() {
        assert_eq!(parse_config_path_from(Vec::<String>::new()), "config.toml");
        assert_eq!(parse_config_path_from(["--unknown"]), "config.toml");
    }

    #[test]
    fn config_path_accepts_short_long_and_positional_forms() {
        assert_eq!(parse_config_path_from(["-c", "edge.toml"]), "edge.toml");
        assert_eq!(
            parse_config_path_from(["--config", "prod.toml"]),
            "prod.toml"
        );
        assert_eq!(
            parse_config_path_from(["--verbose", "positional.toml"]),
            "positional.toml"
        );
    }

    #[test]
    fn empty_listener_list_is_rejected() {
        let err = ensure_listeners_configured(&[], &[]).unwrap_err();

        assert!(err.to_string().contains("at least one listener"));
    }
}
