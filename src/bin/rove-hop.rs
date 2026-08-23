use rove::access_log::AccessLogger;
use rove::config::{AccessLogConfig, SnmpConfig, SyslogConfig};
use rove::egress_diagnostic::{self, EgressDiagnosticConfig};
use rove::hop_mqtt::{HopMqttConfig, HopMqttService};
use rove::proxy::{self, Credentials, Listener, TlsFiles, DEFAULT_PASSWORD, DEFAULT_USERNAME};
use rove::reverse::hop::{ReverseEdgeConfig, ReverseHopClientConfig, DEFAULT_EDGE_MAX_STREAMS};
use std::time::Duration;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let raw_args = std::env::args().skip(1).collect::<Vec<_>>();
    if DoctorArgs::is_doctor_command(&raw_args) {
        let args = DoctorArgs::parse(raw_args)?;
        if args.help {
            print_doctor_usage();
            return Ok(());
        }
        init_tracing(&args.log_level);
        rove::tls::init_crypto();
        let target = egress_diagnostic::select_target(args.target.as_deref())?;
        let report = egress_diagnostic::run(EgressDiagnosticConfig {
            target,
            trace: args.trace,
            timeout: args.timeout,
            max_hops: args.max_hops,
            node_id: args.node_id,
        })
        .await;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            print!("{}", egress_diagnostic::render_text(&report));
        }
        return Ok(());
    }

    let args = Args::parse(raw_args)?;
    if args.help {
        print_usage();
        return Ok(());
    }
    // Reverse-only hops (no local listeners) are valid: they exist purely to
    // dial out to one or more edges. Require at least one of the two roles.
    let reverse_client = args.reverse_client_config()?;
    let hop_mqtt = args.mqtt_config()?;
    if args.listeners.is_empty() && reverse_client.is_none() {
        print_usage();
        anyhow::bail!("at least one listener or --reverse-quic edge is required");
    }

    init_tracing(&args.log_level);
    rove::tls::init_crypto();
    // Route hop egress DNS through a dedicated resolver when --dns-server is set;
    // otherwise this is a no-op and the OS resolver is used.
    rove::resolver::init(&args.dns_config().to_settings()?)?;
    if rove::resolver::is_custom() {
        info!(
            servers = args.dns_servers.len(),
            "hop using dedicated egress DNS"
        );
    }
    let credentials = args.credentials()?;
    if !args.listeners.is_empty() && credentials.uses_default() {
        warn!(
            username = credentials.username(),
            "rove hop proxy is using default authentication; set --username/--password or Rove_HOP_USERNAME/Rove_HOP_PASSWORD"
        );
    }

    info!(
        listeners = args.listeners.len(),
        reverse_edges = reverse_client.as_ref().map(|c| c.edges.len()).unwrap_or(0),
        username = credentials.username(),
        "rove hop proxy starting"
    );

    // Traffic counters are always on (independent of the access log) so SNMP
    // and periodic stats stay accurate even when JSONL logging is disabled.
    let stats = rove::stats::TrafficStats::new();

    // Shares the same structured JSONL access log as the main edge node, so
    // ops can grep hop-node connections with the same tooling; see
    // `rove::access_log` and `rove::proxy::record_access`.
    let access_log = if args.access_log.enable {
        Some(AccessLogger::spawn(
            &args.access_log,
            args.node_id.clone(),
            stats.clone(),
        )?)
    } else {
        None
    };

    for listener in args.listeners {
        let name = listener.name.clone();
        let credentials = credentials.clone();
        let access_log = access_log.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            if let Err(e) = proxy::run_listener(listener, credentials, access_log, stats).await {
                error!(listener = %name, error = %e, "hop proxy listener stopped");
            }
        });
    }

    // Reverse mode: dial out to each configured edge and serve the tunnel
    // streams they open. Each edge runs an independent, self-healing session.
    if let Some(reverse_client) = reverse_client {
        for edge in &reverse_client.edges {
            info!(
                edge_addr = %edge.edge_addr,
                hop_id = %edge.hop_id,
                edge_id = ?edge.edge_id,
                skip_cert_verify = edge.skip_cert_verify,
                "reverse edge session configured"
            );
        }
        rove::reverse::hop::spawn(reverse_client, access_log.clone(), stats.clone());
    }

    // Same isolation contract as the edge node: the SNMP agent is one UDP
    // task whose failures are logged and never touch the data plane.
    if args.snmp.enable {
        let identity = rove::snmp::AgentIdentity {
            node_id: args.node_id.clone(),
            role: rove::snmp::mib::NodeRole::Hop,
            version: env!("CARGO_PKG_VERSION").to_string(),
        };
        let snmp_stats = stats.clone();
        let snmp_cfg = args.snmp.clone();
        tokio::spawn(async move {
            if let Err(e) = rove::snmp::run_agent(snmp_cfg, identity, snmp_stats).await {
                error!(error = %e, "snmp agent stopped");
            }
        });
    }

    // Isolated from the proxy hot path and from edge MQTT. Failures stay in
    // this task so a broker outage cannot take down hop egress.
    if let Some(mqtt) = hop_mqtt {
        tokio::spawn(async move {
            match HopMqttService::new(mqtt) {
                Ok(service) => {
                    if let Err(e) = service.run().await {
                        error!(error = %e, "hop mqtt doctor stopped");
                    }
                }
                Err(e) => error!(error = %e, "hop mqtt doctor not started"),
            }
        });
    }

    tokio::signal::ctrl_c().await?;
    info!("hop proxy shutdown signal received");
    Ok(())
}

#[derive(Debug)]
struct DoctorArgs {
    target: Option<String>,
    trace: bool,
    json: bool,
    timeout: Duration,
    max_hops: u8,
    node_id: String,
    log_level: String,
    help: bool,
}

impl DoctorArgs {
    fn is_doctor_command(args: &[String]) -> bool {
        matches!(args.first().map(String::as_str), Some("doctor"))
    }

    fn parse<I>(args: I) -> anyhow::Result<Self>
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        let mut args = args.into_iter().map(Into::into).peekable();
        match args.next().as_deref() {
            Some("doctor") => {}
            _ => anyhow::bail!("doctor command must start with 'doctor'"),
        }
        match args.next().as_deref() {
            Some("egress") => {}
            Some("-h" | "--help") | None => {
                return Ok(DoctorArgs {
                    target: None,
                    trace: false,
                    json: false,
                    timeout: Duration::from_secs(5),
                    max_hops: 20,
                    node_id: "rove-hop".to_string(),
                    log_level: "warn".to_string(),
                    help: true,
                });
            }
            Some(other) => anyhow::bail!("unknown doctor command {other:?}; expected 'egress'"),
        }

        let mut parsed = DoctorArgs {
            target: None,
            trace: false,
            json: false,
            timeout: Duration::from_secs(5),
            max_hops: 20,
            node_id: "rove-hop".to_string(),
            log_level: "warn".to_string(),
            help: false,
        };
        let mut positional_target = None;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-h" | "--help" => parsed.help = true,
                "--trace" => parsed.trace = true,
                "--json" => parsed.json = true,
                "--target" => {
                    anyhow::ensure!(
                        parsed.target.is_none(),
                        "--target may only be provided once"
                    );
                    parsed.target = Some(next_value(&mut args, &arg)?);
                }
                "--timeout" => {
                    let value = next_value(&mut args, &arg)?;
                    parsed.timeout = parse_duration(&value)?;
                }
                "--max-hops" => {
                    let value = next_value(&mut args, &arg)?;
                    let max_hops: u8 = value.parse().map_err(|_| {
                        anyhow::anyhow!("--max-hops expects an integer from 1 to 64, got {value:?}")
                    })?;
                    anyhow::ensure!(
                        (1..=64).contains(&max_hops),
                        "--max-hops expects an integer from 1 to 64, got {max_hops}"
                    );
                    parsed.max_hops = max_hops;
                }
                "--node-id" => parsed.node_id = next_value(&mut args, &arg)?,
                "--log-level" => parsed.log_level = next_value(&mut args, &arg)?,
                other if other.starts_with('-') => {
                    anyhow::bail!("unknown doctor egress argument {other:?}")
                }
                other => {
                    anyhow::ensure!(
                        positional_target.is_none(),
                        "doctor egress accepts at most one positional target"
                    );
                    positional_target = Some(other.to_string());
                }
            }
        }

        anyhow::ensure!(
            parsed.target.is_none() || positional_target.is_none(),
            "use either a positional target or --target, not both"
        );
        if parsed.target.is_none() {
            parsed.target = positional_target;
        }
        Ok(parsed)
    }
}

#[derive(Debug)]
struct Args {
    listeners: Vec<Listener>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    log_level: String,
    username: Option<String>,
    password: Option<String>,
    node_id: String,
    access_log: AccessLogConfig,
    snmp: SnmpConfig,
    reverse_edges: Vec<ReverseEdgeArg>,
    reverse_global_max_streams: u32,
    reverse_default_hop_id: Option<String>,
    reverse_default_token: Option<String>,
    dns_servers: Vec<String>,
    dns_protocol: String,
    dns_tls_server_name: String,
    dns_doh_path: String,
    dns_ca: String,
    dns_insecure: bool,
    mqtt_broker: String,
    mqtt_hop_id: Option<String>,
    mqtt_username: String,
    mqtt_password: Option<String>,
    mqtt_reply_prefix: String,
    mqtt_client_id: String,
    help: bool,
}

/// One `--reverse-quic` edge session being assembled from CLI flags. Sub-flags
/// bind to the most recent `--reverse-quic` entry; anything left unset falls
/// back to the shared `--reverse-hop-id` / `--reverse-token` defaults (or the
/// `Rove_HOP_REVERSE_TOKEN` env var for the token).
#[derive(Debug, Default, Clone)]
struct ReverseEdgeArg {
    edge_addr: String,
    hop_id: Option<String>,
    token: Option<String>,
    edge_id: Option<String>,
    server_name: Option<String>,
    skip_cert_verify: bool,
    max_streams: Option<u32>,
    initial_mtu: Option<u16>,
}

impl Args {
    fn parse<I>(args: I) -> anyhow::Result<Self>
    where
        I: IntoIterator,
        I::Item: Into<String>,
    {
        let mut args = args.into_iter().map(Into::into).peekable();
        let mut parsed = Args {
            listeners: Vec::new(),
            tls_cert: None,
            tls_key: None,
            log_level: "info".to_string(),
            username: None,
            password: None,
            node_id: "rove-hop".to_string(),
            access_log: AccessLogConfig {
                syslog: SyslogConfig {
                    tag: "rove-hop".to_string(),
                    ..SyslogConfig::default()
                },
                ..AccessLogConfig::default()
            },
            snmp: SnmpConfig::default(),
            reverse_edges: Vec::new(),
            reverse_global_max_streams: 0,
            reverse_default_hop_id: None,
            reverse_default_token: None,
            dns_servers: Vec::new(),
            dns_protocol: "udp".to_string(),
            dns_tls_server_name: String::new(),
            dns_doh_path: String::new(),
            dns_ca: String::new(),
            dns_insecure: false,
            mqtt_broker: String::new(),
            mqtt_hop_id: None,
            mqtt_username: String::new(),
            mqtt_password: None,
            mqtt_reply_prefix: "rove/replies/".to_string(),
            mqtt_client_id: String::new(),
            help: false,
        };
        let mut https_listens = Vec::new();
        let mut socks5_listens = Vec::new();
        let mut socks5tls_listens = Vec::new();
        let mut snmp_allow: Vec<String> = Vec::new();
        let mut snmp_config_path: Option<String> = None;
        let mut snmp_quick_flag = false;

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-h" | "--help" => parsed.help = true,
                "--https" | "--https-listen" => {
                    https_listens.push(next_value(&mut args, &arg)?);
                }
                "--socks5" | "--socks5-listen" => {
                    socks5_listens.push(next_value(&mut args, &arg)?);
                }
                "--socks5tls" | "--socks5tls-listen" => {
                    socks5tls_listens.push(next_value(&mut args, &arg)?);
                }
                "--tls-cert" => parsed.tls_cert = Some(next_value(&mut args, &arg)?),
                "--tls-key" => parsed.tls_key = Some(next_value(&mut args, &arg)?),
                "--username" => parsed.username = Some(next_value(&mut args, &arg)?),
                "--password" => parsed.password = Some(next_value(&mut args, &arg)?),
                "--log-level" => parsed.log_level = next_value(&mut args, &arg)?,
                "--node-id" => parsed.node_id = next_value(&mut args, &arg)?,
                "--reverse-quic" | "--reverse-edge" => {
                    parsed.reverse_edges.push(ReverseEdgeArg {
                        edge_addr: next_value(&mut args, &arg)?,
                        ..ReverseEdgeArg::default()
                    });
                }
                "--reverse-hop-id" => {
                    let value = next_value(&mut args, &arg)?;
                    match parsed.reverse_edges.last_mut() {
                        Some(edge) => edge.hop_id = Some(value),
                        None => parsed.reverse_default_hop_id = Some(value),
                    }
                }
                "--reverse-token" => {
                    let value = next_value(&mut args, &arg)?;
                    match parsed.reverse_edges.last_mut() {
                        Some(edge) => edge.token = Some(value),
                        None => parsed.reverse_default_token = Some(value),
                    }
                }
                "--reverse-edge-id" => {
                    let value = next_value(&mut args, &arg)?;
                    let edge = parsed.reverse_edges.last_mut().ok_or_else(|| {
                        anyhow::anyhow!("--reverse-edge-id must follow a --reverse-quic")
                    })?;
                    edge.edge_id = Some(value);
                }
                "--reverse-server-name" => {
                    let value = next_value(&mut args, &arg)?;
                    let edge = parsed.reverse_edges.last_mut().ok_or_else(|| {
                        anyhow::anyhow!("--reverse-server-name must follow a --reverse-quic")
                    })?;
                    edge.server_name = Some(value);
                }
                "--reverse-insecure" => {
                    let edge = parsed.reverse_edges.last_mut().ok_or_else(|| {
                        anyhow::anyhow!("--reverse-insecure must follow a --reverse-quic")
                    })?;
                    edge.skip_cert_verify = true;
                }
                "--reverse-max-streams" => {
                    let value = next_value(&mut args, &arg)?;
                    let parsed_value: u32 = value.parse().map_err(|_| {
                        anyhow::anyhow!(
                            "--reverse-max-streams expects a positive integer, got {value:?}"
                        )
                    })?;
                    anyhow::ensure!(
                        parsed_value > 0,
                        "--reverse-max-streams must be greater than zero"
                    );
                    let edge = parsed.reverse_edges.last_mut().ok_or_else(|| {
                        anyhow::anyhow!("--reverse-max-streams must follow a --reverse-quic")
                    })?;
                    edge.max_streams = Some(parsed_value);
                }
                "--reverse-initial-mtu" => {
                    let value = next_value(&mut args, &arg)?;
                    let parsed_value: u16 = value.parse().map_err(|_| {
                        anyhow::anyhow!("--reverse-initial-mtu expects an integer, got {value:?}")
                    })?;
                    rove::config::validate_initial_mtu(
                        "--reverse-initial-mtu",
                        Some(parsed_value),
                    )?;
                    let edge = parsed.reverse_edges.last_mut().ok_or_else(|| {
                        anyhow::anyhow!("--reverse-initial-mtu must follow a --reverse-quic")
                    })?;
                    edge.initial_mtu = Some(parsed_value);
                }
                "--reverse-global-max-streams" => {
                    let value = next_value(&mut args, &arg)?;
                    parsed.reverse_global_max_streams = value.parse().map_err(|_| {
                        anyhow::anyhow!(
                            "--reverse-global-max-streams expects a non-negative integer, got {value:?}"
                        )
                    })?;
                }
                "--dns-server" => {
                    parsed.dns_servers.push(next_value(&mut args, &arg)?);
                }
                "--dns-protocol" => parsed.dns_protocol = next_value(&mut args, &arg)?,
                "--dns-server-name" => parsed.dns_tls_server_name = next_value(&mut args, &arg)?,
                "--dns-doh-path" => parsed.dns_doh_path = next_value(&mut args, &arg)?,
                "--dns-ca" => parsed.dns_ca = next_value(&mut args, &arg)?,
                "--dns-insecure" => parsed.dns_insecure = true,
                "--mqtt-broker" => parsed.mqtt_broker = next_value(&mut args, &arg)?,
                "--mqtt-hop-id" => parsed.mqtt_hop_id = Some(next_value(&mut args, &arg)?),
                "--mqtt-username" => parsed.mqtt_username = next_value(&mut args, &arg)?,
                "--mqtt-password" => parsed.mqtt_password = Some(next_value(&mut args, &arg)?),
                "--mqtt-reply-prefix" => parsed.mqtt_reply_prefix = next_value(&mut args, &arg)?,
                "--mqtt-client-id" => parsed.mqtt_client_id = next_value(&mut args, &arg)?,
                "--access-log-disable" => parsed.access_log.enable = false,
                "--access-log-dir" => parsed.access_log.dir = next_value(&mut args, &arg)?,
                "--access-log-file-prefix" => {
                    parsed.access_log.file_prefix = next_value(&mut args, &arg)?
                }
                "--access-log-retention-days" => {
                    let value = next_value(&mut args, &arg)?;
                    parsed.access_log.retention_days = value.parse().map_err(|_| {
                        anyhow::anyhow!(
                            "--access-log-retention-days expects a non-negative integer, got {value:?}"
                        )
                    })?;
                }
                "--access-log-channel-capacity" => {
                    let value = next_value(&mut args, &arg)?;
                    parsed.access_log.channel_capacity = value.parse().map_err(|_| {
                        anyhow::anyhow!(
                            "--access-log-channel-capacity expects a positive integer, got {value:?}"
                        )
                    })?;
                }
                "--access-log-syslog" => {
                    parsed.access_log.syslog.enable = true;
                    parsed.access_log.syslog.address = next_value(&mut args, &arg)?;
                }
                "--access-log-syslog-protocol" => {
                    parsed.access_log.syslog.protocol = next_value(&mut args, &arg)?;
                }
                "--access-log-syslog-facility" => {
                    parsed.access_log.syslog.facility = next_value(&mut args, &arg)?;
                }
                "--access-log-syslog-tag" => {
                    parsed.access_log.syslog.tag = next_value(&mut args, &arg)?;
                }
                "--snmp-listen" => {
                    parsed.snmp.listen = next_value(&mut args, &arg)?;
                    snmp_quick_flag = true;
                }
                "--snmp-community" => {
                    parsed.snmp.community = next_value(&mut args, &arg)?;
                    snmp_quick_flag = true;
                }
                "--snmp-allow" => {
                    snmp_allow.push(next_value(&mut args, &arg)?);
                    snmp_quick_flag = true;
                }
                "--snmp-config" => {
                    snmp_config_path = Some(next_value(&mut args, &arg)?);
                }
                other => anyhow::bail!("unknown argument {other:?}"),
            }
        }

        if let Some(path) = snmp_config_path {
            anyhow::ensure!(
                !snmp_quick_flag,
                "--snmp-config cannot be combined with --snmp-listen/--snmp-community/--snmp-allow"
            );
            parsed.snmp = load_snmp_config_file(&path)?;
        } else if snmp_quick_flag {
            parsed.snmp.enable = true;
            if !snmp_allow.is_empty() {
                parsed.snmp.allow_cidrs = snmp_allow;
            }
            parsed.snmp.validate()?;
        }

        if !https_listens.is_empty() || !socks5tls_listens.is_empty() {
            anyhow::ensure!(
                parsed.tls_cert.is_some() && parsed.tls_key.is_some(),
                "--https/--socks5tls require both --tls-cert and --tls-key"
            );
        }
        let tls = parsed
            .tls_cert
            .as_ref()
            .zip(parsed.tls_key.as_ref())
            .map(|(cert, key)| TlsFiles {
                cert: cert.clone(),
                key: key.clone(),
            });

        for (idx, listen) in https_listens.into_iter().enumerate() {
            parsed.listeners.push(Listener::https(
                format!("https-{}", idx + 1),
                listen,
                tls.clone().expect("TLS presence checked"),
            ));
        }
        for (idx, listen) in socks5_listens.into_iter().enumerate() {
            parsed
                .listeners
                .push(Listener::socks5(format!("socks5-{}", idx + 1), listen));
        }
        for (idx, listen) in socks5tls_listens.into_iter().enumerate() {
            parsed.listeners.push(Listener::socks5tls(
                format!("socks5tls-{}", idx + 1),
                listen,
                tls.clone().expect("TLS presence checked"),
            ));
        }

        Ok(parsed)
    }

    fn credentials(&self) -> anyhow::Result<Credentials> {
        let env_username = std::env::var("Rove_HOP_USERNAME").ok();
        let env_password = std::env::var("Rove_HOP_PASSWORD").ok();
        self.credentials_with_env(env_username.as_deref(), env_password.as_deref())
    }

    /// Build the egress DNS config from `--dns-server` / `--dns-protocol` and
    /// the encrypted-transport flags. Empty `servers` yields a config that keeps
    /// the operating-system resolver, so a hop only routes egress lookups
    /// through a dedicated (anti-pollution) DNS when explicitly asked to.
    fn dns_config(&self) -> rove::config::DnsConfig {
        rove::config::DnsConfig {
            servers: self.dns_servers.clone(),
            protocol: self.dns_protocol.clone(),
            tls_server_name: self.dns_tls_server_name.clone(),
            doh_path: self.dns_doh_path.clone(),
            tls_ca: self.dns_ca.clone(),
            tls_insecure: self.dns_insecure,
            ..rove::config::DnsConfig::default()
        }
    }

    /// Assemble the reverse-hop client configuration from the parsed
    /// `--reverse-*` flags, resolving each edge's `hop_id`/`token` from its own
    /// flags, the shared defaults, or `Rove_HOP_REVERSE_TOKEN`. Returns
    /// `None` when no reverse edge was requested.
    fn reverse_client_config(&self) -> anyhow::Result<Option<ReverseHopClientConfig>> {
        if self.reverse_edges.is_empty() {
            return Ok(None);
        }
        let env_token = std::env::var("Rove_HOP_REVERSE_TOKEN").ok();
        let mut edges = Vec::with_capacity(self.reverse_edges.len());
        for (idx, edge) in self.reverse_edges.iter().enumerate() {
            anyhow::ensure!(
                !edge.edge_addr.trim().is_empty(),
                "--reverse-quic requires an edge host:port"
            );
            let hop_id = edge
                .hop_id
                .clone()
                .or_else(|| self.reverse_default_hop_id.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "reverse edge {} ({}) needs --reverse-hop-id (or a shared default before the first --reverse-quic)",
                        idx + 1,
                        edge.edge_addr
                    )
                })?;
            let token = edge
                .token
                .clone()
                .or_else(|| self.reverse_default_token.clone())
                .or_else(|| env_token.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "reverse edge {} ({}) needs --reverse-token or Rove_HOP_REVERSE_TOKEN",
                        idx + 1,
                        edge.edge_addr
                    )
                })?;
            anyhow::ensure!(
                !hop_id.trim().is_empty(),
                "reverse hop_id must not be empty"
            );
            anyhow::ensure!(!token.trim().is_empty(), "reverse token must not be empty");
            edges.push(ReverseEdgeConfig {
                edge_addr: edge.edge_addr.clone(),
                server_name: edge.server_name.clone().unwrap_or_default(),
                hop_id,
                token,
                edge_id: edge.edge_id.clone(),
                skip_cert_verify: edge.skip_cert_verify,
                max_streams: edge.max_streams.unwrap_or(DEFAULT_EDGE_MAX_STREAMS),
                initial_mtu: edge.initial_mtu,
            });
        }
        Ok(Some(ReverseHopClientConfig {
            edges,
            global_max_streams: self.reverse_global_max_streams,
            node_id: self.node_id.clone(),
        }))
    }

    /// Optional hop-local MQTT doctor. Empty `--mqtt-broker` keeps the
    /// historical default: no MQTT client, no extra topics, same process
    /// behaviour as before this flag existed.
    fn mqtt_config(&self) -> anyhow::Result<Option<HopMqttConfig>> {
        if self.mqtt_broker.trim().is_empty() {
            return Ok(None);
        }
        let hop_id = self
            .mqtt_hop_id
            .clone()
            .or_else(|| self.reverse_default_hop_id.clone())
            .unwrap_or_else(|| self.node_id.clone());
        let username = if self.mqtt_username.trim().is_empty() {
            std::env::var("Rove_HOP_MQTT_USERNAME").unwrap_or_default()
        } else {
            self.mqtt_username.clone()
        };
        let password = self
            .mqtt_password
            .clone()
            .or_else(|| std::env::var("Rove_HOP_MQTT_PASSWORD").ok())
            .unwrap_or_default();
        let cfg = HopMqttConfig {
            broker: self.mqtt_broker.clone(),
            hop_id,
            client_id: self.mqtt_client_id.clone(),
            username,
            password,
            reply_topic_prefix: self.mqtt_reply_prefix.clone(),
        };
        cfg.validate()?;
        Ok(Some(cfg))
    }

    fn credentials_with_env(
        &self,
        env_username: Option<&str>,
        env_password: Option<&str>,
    ) -> anyhow::Result<Credentials> {
        let username = first_non_empty([
            self.username.as_deref(),
            env_username,
            Some(DEFAULT_USERNAME),
        ])
        .unwrap_or(DEFAULT_USERNAME);
        let password = first_non_empty([
            self.password.as_deref(),
            env_password,
            Some(DEFAULT_PASSWORD),
        ])
        .unwrap_or(DEFAULT_PASSWORD);
        Credentials::new(username, password)
    }
}

fn parse_duration(value: &str) -> anyhow::Result<Duration> {
    let value = value.trim();
    anyhow::ensure!(!value.is_empty(), "duration value is required");
    if let Some(ms) = value.strip_suffix("ms") {
        let ms: u64 = ms
            .parse()
            .map_err(|_| anyhow::anyhow!("bad duration {value:?}; expected 500ms, 5s, or 1m"))?;
        return Ok(Duration::from_millis(ms));
    }
    if let Some(secs) = value.strip_suffix('s') {
        let secs: u64 = secs
            .parse()
            .map_err(|_| anyhow::anyhow!("bad duration {value:?}; expected 500ms, 5s, or 1m"))?;
        return Ok(Duration::from_secs(secs));
    }
    if let Some(mins) = value.strip_suffix('m') {
        let mins: u64 = mins
            .parse()
            .map_err(|_| anyhow::anyhow!("bad duration {value:?}; expected 500ms, 5s, or 1m"))?;
        return Ok(Duration::from_secs(mins.saturating_mul(60)));
    }
    let secs: u64 = value
        .parse()
        .map_err(|_| anyhow::anyhow!("bad duration {value:?}; expected 500ms, 5s, or 1m"))?;
    Ok(Duration::from_secs(secs))
}

fn first_non_empty<const N: usize>(values: [Option<&str>; N]) -> Option<&str> {
    values
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
}

fn next_value<I>(args: &mut std::iter::Peekable<I>, flag: &str) -> anyhow::Result<String>
where
    I: Iterator<Item = String>,
{
    let Some(value) = args.next() else {
        anyhow::bail!("{flag} requires a value");
    };
    if value.starts_with('-') {
        anyhow::bail!("{flag} requires a value, got option {value:?}");
    }
    Ok(value)
}

/// Load a full `[snmp]` table from a TOML file. Used for anything beyond the
/// quick v2c flags — notably SNMPv3 users, whose passwords must not appear in
/// `argv`. Passing the flag is the explicit opt-in, so `enable` is implied.
fn load_snmp_config_file(path: &str) -> anyhow::Result<SnmpConfig> {
    #[derive(serde::Deserialize)]
    struct SnmpConfigFile {
        #[serde(default)]
        snmp: SnmpConfig,
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read snmp config {path}: {e}"))?;
    let file: SnmpConfigFile =
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("parse snmp config {path}: {e}"))?;
    let mut snmp = file.snmp;
    snmp.enable = true;
    snmp.validate()
        .map_err(|e| anyhow::anyhow!("snmp config {path}: {e}"))?;
    Ok(snmp)
}

fn init_tracing(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("rove={level},warn")));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn print_usage() {
    eprintln!(
        r#"Usage:
  rove-hop --socks5 0.0.0.0:1080
  rove-hop --https 0.0.0.0:8443 --socks5 0.0.0.0:1080 --socks5tls 0.0.0.0:1081 --tls-cert ./server.crt --tls-key ./server.key
  rove-hop --reverse-quic edge.example.com:9443 --reverse-hop-id hop-s604 --reverse-token <deployment-secret>
  rove-hop doctor egress [TARGET] [--trace] [--json]

Modes:
  --https ADDR       HTTP CONNECT proxy over TLS
  --socks5 ADDR      Plain SOCKS5 proxy
  --socks5tls ADDR   SOCKS5 proxy over TLS
  --reverse-quic ADDR  Dial an edge over QUIC and serve reverse tunnels (repeatable)
  doctor egress      Manual one-target outbound diagnostics; defaults to a random preset target

Reverse mode (for hops the edge cannot dial; each --reverse-quic starts a new edge session):
  --reverse-quic ADDR            Edge reverse-hop QUIC listener host:port (repeatable)
  --reverse-hop-id ID            Hop identity for the preceding edge (or a shared default if before any --reverse-quic)
  --reverse-token TOKEN          Registration token (env: Rove_HOP_REVERSE_TOKEN; keep secrets out of argv)
  --reverse-edge-id ID           Optional label for the preceding edge (logs/metrics only)
  --reverse-server-name NAME     Certificate/SNI name to verify (default: edge host)
  --reverse-insecure             Accept a self-signed / IP-only edge certificate for the preceding edge
  --reverse-max-streams N        Per-edge concurrent-tunnel ceiling (default: 256)
  --reverse-initial-mtu N        Fix the edge QUIC path MTU (UDP payload bytes, 1200-1500) for a compressed tunnel
  --reverse-global-max-streams N Global concurrent-tunnel ceiling across all edges (default: 0 = unlimited)

Authentication:
  --username USER   Proxy username (env: Rove_HOP_USERNAME; default: {DEFAULT_USERNAME})
  --password PASS   Proxy password (env: Rove_HOP_PASSWORD; default: {DEFAULT_PASSWORD})

Options:
  --tls-cert PATH    PEM certificate for --https / --socks5tls
  --tls-key PATH     PEM private key for --https / --socks5tls
  --dns-server ADDR  Egress DNS server ip or ip:port for hop target resolution (repeatable; default: system resolver)
  --dns-protocol P   Transport to reach --dns-server: udp (default) | tcp | tls/dot | https/doh
  --dns-server-name NAME  TLS SNI / certificate name to verify (required for tls/https)
  --dns-doh-path PATH     DoH URL path (default: /dns-query; https only)
  --dns-ca PATH           PEM CA that signs the DNS server cert (default: Mozilla webpki roots)
  --dns-insecure          Skip DNS server certificate verification (self-signed; dangerous)
  --log-level LEVEL  error|warn|info|debug|trace (default: info)
  --node-id ID       Identifier attached to access log / syslog records (default: rove-hop)
  -h, --help         Show this help

MQTT egress doctor (off by default; isolated from edge MQTT; not on the splice path):
  --mqtt-broker URL          Enable hop MQTT, e.g. tcp://127.0.0.1:1883
  --mqtt-hop-id ID           Topic identity rove/hop/<id>/doctor (default: --reverse-hop-id or --node-id)
  --mqtt-username USER       Broker username (env: Rove_HOP_MQTT_USERNAME)
  --mqtt-password PASS       Broker password (env: Rove_HOP_MQTT_PASSWORD; keep secrets out of argv)
  --mqtt-reply-prefix PREFIX Allowed one-shot reply prefix (default: rove/replies/)
  --mqtt-client-id ID        MQTT client id (default: rove-hop-<hop-id>)

Access log (structured JSONL, on by default, same schema as the main node):
  --access-log-disable              Turn off the local access log entirely
  --access-log-dir DIR              Log directory (default: ./logs)
  --access-log-file-prefix PREFIX   Rotated file name prefix (default: access)
  --access-log-retention-days N     Days to keep rotated files (default: 7)
  --access-log-channel-capacity N   Writer queue capacity (default: 8192)
  --access-log-syslog ADDR          Forward to a remote syslog collector (host:port)
  --access-log-syslog-protocol P    udp | tcp (default: udp)
  --access-log-syslog-facility F    Syslog facility name (default: local0)
  --access-log-syslog-tag TAG       Syslog TAG field (default: rove-hop)

SNMP agent (read-only, off by default; GET/GETNEXT/GETBULK only):
  --snmp-listen ADDR      UDP listen address (default: 0.0.0.0:161; enables the agent)
  --snmp-community S      SNMPv2c community string (enables the agent)
  --snmp-allow CIDR       Allowed source network, repeatable (default: 127.0.0.1/32, ::1/128)
  --snmp-config PATH      Load a full [snmp] TOML table (v2c + SNMPv3 users; keeps
                          passwords out of argv; implies enable; exclusive with the flags above)
"#
    );
}

fn print_doctor_usage() {
    let presets = egress_diagnostic::preset_names().join(", ");
    eprintln!(
        r#"Usage:
  rove-hop doctor egress
  rove-hop doctor egress github.com
  rove-hop doctor egress api.openai.com:443 --trace
  rove-hop doctor egress --target github --trace --json

Manual egress diagnostics for this hop node. By default this command randomly
selects exactly one preset target. It never scans every preset unless a caller
runs it repeatedly.

Targets:
  Presets: {presets}
  Manual: hostname, hostname:port, [ipv6]:port, or http(s)://host[:port]/path

Options:
  --target TARGET    Preset name or manual target; mutually exclusive with positional TARGET
  --trace            Run traceroute/tracepath and include concrete hop nodes
  --json             Emit structured JSON instead of detailed text
  --timeout DURATION Per-stage timeout, such as 500ms, 5s, or 1m (default: 5s)
  --max-hops N       Trace hop limit, 1-64 (default: 20)
  --node-id ID       Identifier shown in the diagnostic report (default: rove-hop)
  --log-level LEVEL  error|warn|info|debug|trace (default: warn)
  -h, --help         Show this help
"#
    );
}

#[cfg(test)]
mod tests {
    use super::{parse_duration, Args, DoctorArgs};
    use std::time::Duration;

    #[test]
    fn parses_socks5_listener() {
        let args = Args::parse(["--socks5", "127.0.0.1:1080"]).unwrap();

        assert_eq!(args.listeners.len(), 1);
        assert_eq!(args.listeners[0].listen, "127.0.0.1:1080");
    }

    #[test]
    fn tls_listener_requires_cert_and_key() {
        let err =
            Args::parse(["--https", "127.0.0.1:8443"]).expect_err("missing TLS files should fail");

        assert!(err.to_string().contains("--tls-cert"));
    }

    #[test]
    fn parses_tls_listeners() {
        let args = Args::parse([
            "--https",
            "127.0.0.1:8443",
            "--socks5tls",
            "127.0.0.1:1081",
            "--tls-cert",
            "server.crt",
            "--tls-key",
            "server.key",
        ])
        .unwrap();

        assert_eq!(args.listeners.len(), 2);
    }

    #[test]
    fn parses_mixed_listeners_log_level_and_help() {
        let args = Args::parse([
            "--help",
            "--socks5",
            "127.0.0.1:1080",
            "--username",
            "alice",
            "--password",
            "secret",
            "--log-level",
            "debug",
        ])
        .unwrap();

        assert!(args.help);
        assert_eq!(args.log_level, "debug");
        assert_eq!(args.listeners.len(), 1);
        assert_eq!(args.username.as_deref(), Some("alice"));
        assert_eq!(args.password.as_deref(), Some("secret"));
    }

    #[test]
    fn credentials_default_and_env_values() {
        let args = Args::parse(["--socks5", "127.0.0.1:1080"]).unwrap();
        assert!(args
            .credentials_with_env(None, None)
            .unwrap()
            .uses_default());

        assert!(!args
            .credentials_with_env(Some("env-user"), Some("env-pass"))
            .unwrap()
            .uses_default());
    }

    #[test]
    fn rejects_unknown_or_missing_option_values() {
        assert!(Args::parse(["--unknown"]).is_err());
        assert!(Args::parse(["--socks5"]).is_err());
        assert!(Args::parse(["--socks5", "--log-level"]).is_err());
    }

    #[test]
    fn mqtt_doctor_defaults_off_and_parses_broker() {
        let off = Args::parse(["--socks5", "127.0.0.1:1080"]).unwrap();
        assert!(off.mqtt_broker.is_empty());
        assert!(off.mqtt_config().unwrap().is_none());

        let on = Args::parse([
            "--socks5",
            "127.0.0.1:1080",
            "--mqtt-broker",
            "tcp://127.0.0.1:1883",
            "--mqtt-hop-id",
            "rove-hop-jp",
            "--mqtt-username",
            "mqtt-user",
            "--mqtt-password",
            "mqtt-pass",
        ])
        .unwrap();
        let cfg = on.mqtt_config().unwrap().expect("mqtt enabled");
        assert_eq!(cfg.broker, "tcp://127.0.0.1:1883");
        assert_eq!(cfg.hop_id, "rove-hop-jp");
        assert_eq!(cfg.username, "mqtt-user");
        assert_eq!(cfg.password, "mqtt-pass");
        assert_eq!(cfg.doctor_topic(), "rove/hop/rove-hop-jp/doctor");
    }

    #[test]
    fn mqtt_doctor_rejects_wildcard_hop_id() {
        let args = Args::parse([
            "--socks5",
            "127.0.0.1:1080",
            "--mqtt-broker",
            "tcp://127.0.0.1:1883",
            "--mqtt-hop-id",
            "bad/#id",
        ])
        .unwrap();
        assert!(args.mqtt_config().is_err());
    }

    #[test]
    fn parses_doctor_egress_defaults_and_manual_options() {
        let args = DoctorArgs::parse(["doctor", "egress"]).unwrap();
        assert!(args.target.is_none());
        assert!(!args.trace);
        assert!(!args.json);
        assert_eq!(args.timeout, Duration::from_secs(5));
        assert_eq!(args.max_hops, 20);

        let args = DoctorArgs::parse([
            "doctor",
            "egress",
            "api.openai.com:443",
            "--trace",
            "--json",
            "--timeout",
            "750ms",
            "--max-hops",
            "12",
            "--node-id",
            "hop-hk-01",
        ])
        .unwrap();
        assert_eq!(args.target.as_deref(), Some("api.openai.com:443"));
        assert!(args.trace);
        assert!(args.json);
        assert_eq!(args.timeout, Duration::from_millis(750));
        assert_eq!(args.max_hops, 12);
        assert_eq!(args.node_id, "hop-hk-01");
    }

    #[test]
    fn doctor_egress_rejects_ambiguous_or_bad_arguments() {
        assert!(DoctorArgs::parse(["doctor", "egress", "github", "--target", "openai"]).is_err());
        assert!(DoctorArgs::parse(["doctor", "egress", "--max-hops", "0"]).is_err());
        assert!(DoctorArgs::parse(["doctor", "other"]).is_err());
    }

    #[test]
    fn duration_parser_accepts_common_units() {
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("5s").unwrap(), Duration::from_secs(5));
        assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_duration("7").unwrap(), Duration::from_secs(7));
        assert!(parse_duration("abc").is_err());
    }

    #[test]
    fn access_log_defaults_are_enabled_with_sane_values() {
        let args = Args::parse(["--socks5", "127.0.0.1:1080"]).unwrap();

        assert!(args.access_log.enable);
        assert_eq!(args.access_log.retention_days, 7);
        assert_eq!(args.access_log.channel_capacity, 8192);
        assert!(!args.access_log.syslog.enable);
        assert_eq!(args.access_log.syslog.tag, "rove-hop");
        assert_eq!(args.node_id, "rove-hop");
    }

    #[test]
    fn access_log_flags_override_dir_disable_and_syslog_settings() {
        let args = Args::parse([
            "--socks5",
            "127.0.0.1:1080",
            "--node-id",
            "hop-hk-01",
            "--access-log-dir",
            "/var/log/rove-hop",
            "--access-log-file-prefix",
            "hop",
            "--access-log-retention-days",
            "3",
            "--access-log-channel-capacity",
            "512",
            "--access-log-syslog",
            "syslog.example.com:514",
            "--access-log-syslog-protocol",
            "tcp",
            "--access-log-syslog-facility",
            "local1",
            "--access-log-syslog-tag",
            "hop-hk-01",
        ])
        .unwrap();

        assert_eq!(args.node_id, "hop-hk-01");
        assert_eq!(args.access_log.dir, "/var/log/rove-hop");
        assert_eq!(args.access_log.file_prefix, "hop");
        assert_eq!(args.access_log.retention_days, 3);
        assert_eq!(args.access_log.channel_capacity, 512);
        assert!(args.access_log.syslog.enable);
        assert_eq!(args.access_log.syslog.address, "syslog.example.com:514");
        assert_eq!(args.access_log.syslog.protocol, "tcp");
        assert_eq!(args.access_log.syslog.facility, "local1");
        assert_eq!(args.access_log.syslog.tag, "hop-hk-01");
    }

    #[test]
    fn access_log_disable_flag_turns_off_default_enable() {
        let args = Args::parse(["--socks5", "127.0.0.1:1080", "--access-log-disable"]).unwrap();
        assert!(!args.access_log.enable);
    }

    #[test]
    fn snmp_is_disabled_by_default() {
        let args = Args::parse(["--socks5", "127.0.0.1:1080"]).unwrap();
        assert!(!args.snmp.enable);
    }

    #[test]
    fn snmp_quick_flags_enable_v2c_agent() {
        let args = Args::parse([
            "--socks5",
            "127.0.0.1:1080",
            "--snmp-listen",
            "127.0.0.1:1161",
            "--snmp-community",
            "cacti-ro",
            "--snmp-allow",
            "10.1.0.0/24",
            "--snmp-allow",
            "127.0.0.1/32",
        ])
        .unwrap();
        assert!(args.snmp.enable);
        assert_eq!(args.snmp.listen, "127.0.0.1:1161");
        assert_eq!(args.snmp.community, "cacti-ro");
        assert_eq!(args.snmp.allow_cidrs, vec!["10.1.0.0/24", "127.0.0.1/32"]);
    }

    #[test]
    fn snmp_quick_flags_without_community_fail_validation() {
        let err = Args::parse([
            "--socks5",
            "127.0.0.1:1080",
            "--snmp-listen",
            "127.0.0.1:1161",
        ])
        .expect_err("snmp without any credential must fail");
        assert!(err.to_string().contains("community"), "err: {err}");
    }

    #[test]
    fn snmp_config_file_loads_full_table_and_implies_enable() {
        let path = std::env::temp_dir().join(format!(
            "rove-hop-snmp-{}.toml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::write(
            &path,
            r#"
[snmp]
listen = "0.0.0.0:1161"
community = "cacti-ro"
allow_cidrs = ["192.0.2.0/24"]
state_path = "/tmp/snmp-state.json"

[[snmp.v3_users]]
username = "cacti"
auth_protocol = "sha1"
auth_password = "auth-secret-1"
"#,
        )
        .unwrap();
        let args = Args::parse([
            "--socks5",
            "127.0.0.1:1080",
            "--snmp-config",
            path.to_str().unwrap(),
        ])
        .unwrap();
        assert!(args.snmp.enable);
        assert_eq!(args.snmp.listen, "0.0.0.0:1161");
        assert_eq!(args.snmp.v3_users.len(), 1);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn snmp_config_file_conflicts_with_quick_flags() {
        let err = Args::parse([
            "--socks5",
            "127.0.0.1:1080",
            "--snmp-community",
            "x",
            "--snmp-config",
            "/nonexistent.toml",
        ])
        .expect_err("mixing --snmp-config with quick flags must fail");
        assert!(err.to_string().contains("--snmp-config"), "err: {err}");
    }

    #[test]
    fn access_log_retention_days_rejects_non_numeric_value() {
        let err = Args::parse([
            "--socks5",
            "127.0.0.1:1080",
            "--access-log-retention-days",
            "abc",
        ])
        .expect_err("non-numeric retention days should fail");
        assert!(err.to_string().contains("--access-log-retention-days"));
    }
}
