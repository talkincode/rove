use rove::ingress::relay::{RelayConfig, RelayServer};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_path = parse_config_path()?;
    init_tracing();
    rove::tls::init_crypto();
    let config = RelayConfig::load(&config_path)?;
    let relay = RelayServer::bind(config)?;
    let local_addr = relay.local_addr();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let signal = wait_for_shutdown_signal().await.unwrap_or("unknown");
        info!(event = "relay_shutdown", signal, listen = %local_addr);
        let _ = shutdown_tx.send(true);
    });
    relay.run_until(shutdown_rx).await
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> anyhow::Result<&'static str> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.map(|()| "SIGINT").map_err(Into::into),
        _ = sigterm.recv() => Ok("SIGTERM"),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> anyhow::Result<&'static str> {
    tokio::signal::ctrl_c().await?;
    Ok("CTRL_C")
}

fn parse_config_path() -> anyhow::Result<String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("-c" | "--config") => args
            .next()
            .ok_or_else(|| anyhow::anyhow!("--config requires a TOML file path")),
        Some("-h" | "--help") | None => {
            eprintln!("Usage: rove-relay --config relay.toml");
            std::process::exit(0);
        }
        Some(other) => anyhow::bail!("unknown argument {other:?}; expected --config PATH"),
    }
}

fn init_tracing() {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("rove=info,warn"));
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(filter)
        .with_target(false)
        .flatten_event(true)
        .init();
}
