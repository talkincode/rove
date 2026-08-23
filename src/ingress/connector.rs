//! NAT-side reverse-ingress connector.

use super::frame::{
    self, codes, Datagram, Id128, LeaseRequest, OpenTcpRequest, RegisterRequest, Reply, Transport,
};
use super::metadata::{self, IngressMetadata};
use crate::config::{Listener, TuicListener};
use crate::io::splice;
use crate::reverse::QuicDuplex;
use bytes::Bytes;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpSocket, UdpSocket};
use tokio::sync::{watch, Mutex as AsyncMutex};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

const SESSION_TIMEOUT: Duration = Duration::from_secs(10);
const FLOW_IDLE: Duration = Duration::from_secs(60);
const FLOW_SWEEP_INTERVAL: Duration = Duration::from_secs(15);
const MAX_CONFIG_STREAMS: u32 = 65_536;
const MAX_CONFIG_UDP_FLOWS: usize = 65_536;
const MAX_RECONNECT_SECS: u64 = 3600;

#[derive(Debug, Clone, Deserialize)]
pub struct ReverseIngressConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub relay: String,
    #[serde(default)]
    pub server_name: String,
    #[serde(default)]
    pub token: String,
    #[serde(default)]
    pub token_env: String,
    #[serde(default)]
    pub skip_cert_verify: bool,
    #[serde(default)]
    pub initial_mtu: Option<u16>,
    #[serde(default = "default_max_streams")]
    pub max_streams: u32,
    #[serde(default = "default_max_udp_flows")]
    pub max_udp_flows: usize,
    #[serde(default = "default_reconnect_min_secs")]
    pub reconnect_min_secs: u64,
    #[serde(default = "default_reconnect_max_secs")]
    pub reconnect_max_secs: u64,
    #[serde(default)]
    pub listeners: Vec<IngressListenerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IngressListenerConfig {
    pub id: String,
    pub transport: String,
    #[serde(default)]
    pub public_port: u16,
    pub local_listener: String,
    #[serde(default = "default_max_inner_datagram")]
    pub max_inner_datagram: usize,
}

fn default_max_streams() -> u32 {
    super::DEFAULT_MAX_STREAMS
}
fn default_max_udp_flows() -> usize {
    4096
}
fn default_reconnect_min_secs() -> u64 {
    1
}
fn default_reconnect_max_secs() -> u64 {
    30
}
fn default_max_inner_datagram() -> usize {
    1200
}

impl Default for ReverseIngressConfig {
    fn default() -> Self {
        ReverseIngressConfig {
            enable: false,
            relay: String::new(),
            server_name: String::new(),
            token: String::new(),
            token_env: String::new(),
            skip_cert_verify: false,
            initial_mtu: None,
            max_streams: default_max_streams(),
            max_udp_flows: default_max_udp_flows(),
            reconnect_min_secs: default_reconnect_min_secs(),
            reconnect_max_secs: default_reconnect_max_secs(),
            listeners: Vec::new(),
        }
    }
}

impl ReverseIngressConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enable {
            return Ok(());
        }
        anyhow::ensure!(
            !self.relay.trim().is_empty(),
            "reverse_ingress.relay is required"
        );
        anyhow::ensure!(
            crate::util::split_host_port(&self.relay).is_some(),
            "reverse_ingress.relay must be host:port"
        );
        anyhow::ensure!(
            !self.server_name.trim().is_empty() || self.skip_cert_verify,
            "reverse_ingress.server_name is required unless skip_cert_verify is true"
        );
        match (self.token.trim(), self.token_env.trim()) {
            ("", "") => anyhow::bail!("reverse_ingress needs token or token_env"),
            (_, "") | ("", _) => {}
            _ => anyhow::bail!("reverse_ingress must set only one of token or token_env"),
        }
        anyhow::ensure!(
            (1..=MAX_CONFIG_STREAMS).contains(&self.max_streams),
            "reverse_ingress.max_streams must be in [1, {MAX_CONFIG_STREAMS}]"
        );
        anyhow::ensure!(
            (1..=MAX_CONFIG_UDP_FLOWS).contains(&self.max_udp_flows),
            "reverse_ingress.max_udp_flows must be in [1, {MAX_CONFIG_UDP_FLOWS}]"
        );
        anyhow::ensure!(
            self.reconnect_min_secs > 0 && self.reconnect_min_secs <= self.reconnect_max_secs,
            "reverse_ingress reconnect bounds are invalid"
        );
        anyhow::ensure!(
            self.reconnect_max_secs <= MAX_RECONNECT_SECS,
            "reverse_ingress.reconnect_max_secs must be <= {MAX_RECONNECT_SECS}"
        );
        if !self.token.trim().is_empty() {
            validate_token(self.token.trim())?;
        }
        crate::config::validate_initial_mtu("reverse_ingress.initial_mtu", self.initial_mtu)?;
        anyhow::ensure!(
            !self.listeners.is_empty(),
            "reverse_ingress needs at least one listener mapping"
        );
        let mut ids = HashSet::new();
        for listener in &self.listeners {
            validate_id("reverse_ingress listener id", &listener.id)?;
            validate_id("reverse_ingress local_listener", &listener.local_listener)?;
            let transport = Transport::parse(&listener.transport)
                .map_err(|e| anyhow::anyhow!("reverse_ingress listener {}: {e}", listener.id))?;
            anyhow::ensure!(
                ids.insert((listener.id.clone(), transport)),
                "duplicate reverse_ingress listener {} {}",
                listener.id,
                transport.as_str()
            );
            anyhow::ensure!(
                (576..=65_507).contains(&listener.max_inner_datagram),
                "reverse_ingress listener {} max_inner_datagram out of range [576, 65507]",
                listener.id
            );
        }
        Ok(())
    }

    pub fn to_runtime(
        &self,
        node_id: &str,
        tcp_listeners: &[Listener],
        tuic_listeners: &[TuicListener],
    ) -> anyhow::Result<Option<ConnectorConfig>> {
        self.validate()?;
        if !self.enable {
            return Ok(None);
        }
        let token = match (self.token.trim(), self.token_env.trim()) {
            (token, "") => token.to_string(),
            ("", env_name) => std::env::var(env_name).map_err(|_| {
                anyhow::anyhow!("reverse_ingress token environment variable {env_name} is not set")
            })?,
            _ => unreachable!("validated token source"),
        };
        validate_token(&token)?;
        validate_id("node_id", node_id)?;

        let mut targets = Vec::with_capacity(self.listeners.len());
        for mapping in &self.listeners {
            let transport = Transport::parse(&mapping.transport)
                .map_err(|e| anyhow::anyhow!("reverse_ingress listener {}: {e}", mapping.id))?;
            let local_addr = match transport {
                Transport::Tcp => {
                    let listener = tcp_listeners
                        .iter()
                        .find(|listener| listener.name == mapping.local_listener)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "reverse_ingress listener {} references unknown TCP listener {:?}",
                                mapping.id,
                                mapping.local_listener
                            )
                        })?;
                    normalize_loopback_target(&listener.listen)?
                }

                Transport::Udp => {
                    let listener = tuic_listeners
                        .iter()
                        .find(|listener| listener.name == mapping.local_listener)
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "reverse_ingress listener {} references unknown TUIC listener {:?}",
                                mapping.id,
                                mapping.local_listener
                            )
                        })?;
                    normalize_loopback_target(&listener.listen)?
                }
            };
            targets.push(LocalTarget {
                id: mapping.id.clone(),
                transport,
                public_port: mapping.public_port,
                local_listener: mapping.local_listener.clone(),
                local_addr,
                max_inner_datagram: mapping.max_inner_datagram,
            });
        }
        let server_name = if self.server_name.trim().is_empty() {
            crate::util::split_host_port(&self.relay)
                .map(|(host, _)| host)
                .ok_or_else(|| anyhow::anyhow!("invalid reverse_ingress relay"))?
        } else {
            self.server_name.trim().to_string()
        };
        Ok(Some(ConnectorConfig {
            node_id: node_id.to_string(),
            relay: self.relay.clone(),
            server_name,
            token,
            skip_cert_verify: self.skip_cert_verify,
            initial_mtu: self.initial_mtu,
            max_streams: self.max_streams,
            max_udp_flows: self.max_udp_flows,
            reconnect_min: Duration::from_secs(self.reconnect_min_secs),
            reconnect_max: Duration::from_secs(self.reconnect_max_secs),
            targets,
        }))
    }
}

fn validate_token(token: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!token.is_empty(), "reverse_ingress token must not be empty");
    anyhow::ensure!(
        token.len() <= frame::MAX_TOKEN_BYTES
            && !token.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)),
        "reverse_ingress token cannot be encoded safely"
    );
    Ok(())
}

fn normalize_loopback_target(raw: &str) -> anyhow::Result<SocketAddr> {
    let address: SocketAddr = raw
        .parse()
        .map_err(|e| anyhow::anyhow!("local listener address {raw:?}: {e}"))?;
    let ip = if address.ip().is_unspecified() {
        if address.is_ipv6() {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        }
    } else {
        address.ip()
    };
    anyhow::ensure!(
        ip.is_loopback(),
        "reverse_ingress local listener {raw:?} must bind loopback or wildcard"
    );
    Ok(SocketAddr::new(ip, address.port()))
}

fn validate_id(field: &str, value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !value.is_empty() && value.len() <= 128,
        "{field} is invalid"
    );
    anyhow::ensure!(
        value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':')),
        "{field} contains unsupported characters"
    );
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ConnectorConfig {
    node_id: String,
    relay: String,
    server_name: String,
    token: String,
    skip_cert_verify: bool,
    initial_mtu: Option<u16>,
    max_streams: u32,
    max_udp_flows: usize,
    reconnect_min: Duration,
    reconnect_max: Duration,
    targets: Vec<LocalTarget>,
}

#[derive(Debug, Clone)]
struct LocalTarget {
    id: String,
    transport: Transport,
    public_port: u16,
    local_listener: String,
    local_addr: SocketAddr,
    max_inner_datagram: usize,
}

#[derive(Debug, Clone)]
struct ActiveLease {
    lease_id: u64,
    target: LocalTarget,
    public_port: u16,
}

struct LeaseControl {
    _send: quinn::SendStream,
    _recv: quinn::RecvStream,
}

pub async fn run_until(
    config: ConnectorConfig,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut backoff = config.reconnect_min;
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let started = Instant::now();
        match connect_and_serve(&config, shutdown.clone()).await {
            Ok(()) if *shutdown.borrow() => return Ok(()),
            Ok(()) => warn!(event = "ingress_session_ended", relay = %config.relay),
            Err(e) => warn!(
                event = "ingress_session_failed",
                relay = %config.relay,
                error = %e
            ),
        }
        if started.elapsed() >= Duration::from_secs(30) {
            backoff = config.reconnect_min;
        }
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = crate::lifecycle::shutdown_requested(&mut shutdown) => return Ok(()),
        }
        backoff = (backoff * 2).min(config.reconnect_max);
    }
}

async fn connect_and_serve(
    config: &ConnectorConfig,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let (host, port) = crate::util::split_host_port(&config.relay)
        .ok_or_else(|| anyhow::anyhow!("invalid relay address {}", config.relay))?;
    let remote = crate::resolver::resolve_one(&host, port)
        .await
        .map_err(|e| anyhow::anyhow!("resolve relay {}: {e}", config.relay))?;
    let bind = if remote.is_ipv6() {
        "[::]:0".parse().expect("valid ipv6 bind")
    } else {
        "0.0.0.0:0".parse().expect("valid ipv4 bind")
    };
    let endpoint =
        quinn::Endpoint::client(bind).map_err(|e| anyhow::anyhow!("bind ingress client: {e}"))?;
    let client = super::client_config(
        config.skip_cert_verify,
        config.max_streams,
        config.initial_mtu,
    )?;
    let connection = endpoint
        .connect_with(client, remote, &config.server_name)
        .map_err(|e| anyhow::anyhow!("connect relay {remote}: {e}"))?
        .await
        .map_err(|e| anyhow::anyhow!("handshake relay {remote}: {e}"))?;
    let (mut control_send, mut control_recv) = connection.open_bi().await?;
    let register = RegisterRequest {
        node_id: config.node_id.clone(),
        token: config.token.clone(),
    };
    frame::write_frame(&mut control_send, &register.encode()?).await?;
    let reply = Reply::parse(&frame::read_frame(&mut control_recv).await?)?;
    let Reply::Ok(_) = &reply else {
        anyhow::bail!("relay refused registration");
    };
    let relay_id = reply
        .header("relay-id")
        .ok_or_else(|| anyhow::anyhow!("register reply missing relay-id"))?
        .to_string();
    let session_id = Id128::parse_hex(
        reply
            .header("session-id")
            .ok_or_else(|| anyhow::anyhow!("register reply missing session-id"))?,
    )?;
    info!(
        event = "ingress_registered",
        relay_id = %relay_id,
        node_id = %config.node_id,
        tunnel_session_id = %session_id,
        remote = %remote
    );

    let mut leases = HashMap::new();
    let mut lease_controls = Vec::new();
    for target in &config.targets {
        let (mut send, mut recv) = connection.open_bi().await?;
        let request = LeaseRequest {
            listener_id: target.id.clone(),
            transport: target.transport,
            public_port: target.public_port,
        };
        frame::write_frame(&mut send, &request.encode()?).await?;
        let reply = Reply::parse(&frame::read_frame(&mut recv).await?)?;
        match reply {
            Reply::Ok(_) => {
                let lease_id: u64 = reply
                    .header("lease-id")
                    .ok_or_else(|| anyhow::anyhow!("lease reply missing lease-id"))?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("lease reply has invalid lease-id"))?;
                let public_port: u16 = reply
                    .header("public-port")
                    .ok_or_else(|| anyhow::anyhow!("lease reply missing public-port"))?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("lease reply has invalid public-port"))?;
                leases.insert(
                    lease_id,
                    ActiveLease {
                        lease_id,
                        target: target.clone(),
                        public_port,
                    },
                );
                lease_controls.push(LeaseControl {
                    _send: send,
                    _recv: recv,
                });
                info!(
                    event = "ingress_lease_active",
                    relay_id = %relay_id,
                    listener_id = %target.id,
                    local_listener = %target.local_listener,
                    transport = target.transport.as_str(),
                    lease_id,
                    public_port
                );
            }
            Reply::Err(code) => {
                anyhow::bail!(
                    "relay refused listener {} {} lease: {code}",
                    target.id,
                    target.transport.as_str()
                );
            }
        }
    }
    let session = Arc::new(ConnectorSession {
        connection: connection.clone(),
        relay_addr: remote,
        relay_id,
        session_id,
        leases,
        max_udp_flows: config.max_udp_flows,
        flows: Arc::new(AsyncMutex::new(HashMap::new())),
    });
    let tcp_task = tokio::spawn(session.clone().tcp_loop());
    let udp_task = tokio::spawn(session.clone().udp_loop());
    let sweep_task = tokio::spawn(session.clone().flow_sweeper());
    tokio::select! {
        _ = connection.closed() => {}
        _ = crate::lifecycle::shutdown_requested(&mut shutdown) => {
            connection.close(0u32.into(), b"node shutdown");
        }
    }
    tcp_task.abort();
    udp_task.abort();
    sweep_task.abort();
    session.clear_flows().await;
    drop(lease_controls);
    drop(control_send);
    drop(control_recv);
    if *shutdown.borrow() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("relay connection closed"))
    }
}

struct ConnectorSession {
    connection: quinn::Connection,
    relay_addr: SocketAddr,
    relay_id: String,
    session_id: Id128,
    leases: HashMap<u64, ActiveLease>,
    max_udp_flows: usize,
    flows: Arc<AsyncMutex<HashMap<(u64, Id128), ConnectorFlow>>>,
}

struct ConnectorFlow {
    client_addr: SocketAddr,
    source_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    last_seen: Arc<Mutex<Instant>>,
    return_task: JoinHandle<()>,
}

impl ConnectorSession {
    async fn tcp_loop(self: Arc<Self>) {
        while let Ok((send, recv)) = self.connection.accept_bi().await {
            let session = self.clone();
            tokio::spawn(async move {
                session.handle_tcp(send, recv).await;
            });
        }
    }

    async fn handle_tcp(&self, mut send: quinn::SendStream, mut recv: quinn::RecvStream) {
        let lines = match frame::read_frame(&mut recv).await {
            Ok(lines) => lines,
            Err(_) => {
                write_error(&mut send, codes::BAD_REQUEST).await;
                return;
            }
        };
        let request = match OpenTcpRequest::parse(&lines) {
            Ok(request) => request,
            Err(_) => {
                write_error(&mut send, codes::BAD_REQUEST).await;
                return;
            }
        };
        let Some(lease) = self
            .leases
            .get(&request.lease_id)
            .filter(|lease| lease.target.transport == Transport::Tcp)
        else {
            write_error(&mut send, codes::FORBIDDEN).await;
            return;
        };
        if request.relay_instance_id != self.relay_id
            || request.tunnel_session_id != self.session_id
        {
            write_error(&mut send, codes::FORBIDDEN).await;
            return;
        }
        let metadata = IngressMetadata {
            relay_instance_id: self.relay_id.clone(),
            tunnel_session_id: self.session_id.to_string(),
            lease_id: request.lease_id,
            listener_id: lease.target.id.clone(),
            ingress_id: Some(request.ingress_id.to_string()),
            flow_id: None,
            client_addr: request.client_addr,
            relay_addr: self.relay_addr,
        };
        let local = match connect_local_tcp(lease.target.local_addr, metadata).await {
            Ok(stream) => stream,
            Err(e) => {
                warn!(
                    event = "ingress_local_connect_failed",
                    listener_id = %lease.target.id,
                    ingress_id = %request.ingress_id,
                    error = %e
                );
                write_error(&mut send, codes::LOCAL_UNAVAILABLE).await;
                return;
            }
        };
        let reply = Reply::ok().encode();
        let Ok(reply) = reply else {
            return;
        };
        if frame::write_frame(&mut send, &reply).await.is_err() {
            return;
        }
        let _ = splice(QuicDuplex::new(send, recv), local, 0, 0).await;
    }

    async fn udp_loop(self: Arc<Self>) {
        while let Ok(bytes) = self.connection.read_datagram().await {
            let Datagram::Uplink {
                lease_id,
                flow_id,
                client_addr,
                payload,
            } = (match Datagram::parse(&bytes) {
                Ok(datagram) => datagram,
                Err(e) => {
                    debug!(event = "ingress_malformed_datagram_drop", error = %e);
                    continue;
                }
            })
            else {
                debug!(event = "ingress_wrong_direction_datagram_drop");
                continue;
            };
            let Some(lease) = self
                .leases
                .get(&lease_id)
                .filter(|lease| lease.target.transport == Transport::Udp)
                .cloned()
            else {
                debug!(event = "ingress_unknown_lease_datagram_drop", lease_id);
                continue;
            };
            if payload.len() > lease.target.max_inner_datagram {
                warn!(
                    event = "oversized_datagram_drop",
                    direction = "local_uplink",
                    lease_id,
                    flow_id = %flow_id,
                    payload_len = payload.len(),
                    max = lease.target.max_inner_datagram
                );
                continue;
            }
            let socket = match self.get_or_open_flow(flow_id, client_addr, &lease).await {
                Some(socket) => socket,
                None => continue,
            };
            if socket
                .send_to(payload, lease.target.local_addr)
                .await
                .is_ok()
            {
                if let Some(flow) = self.flows.lock().await.get(&(lease_id, flow_id)) {
                    *flow.last_seen.lock().expect("flow clock poisoned") = Instant::now();
                }
            }
        }
    }

    async fn get_or_open_flow(
        &self,
        flow_id: Id128,
        client_addr: SocketAddr,
        lease: &ActiveLease,
    ) -> Option<Arc<UdpSocket>> {
        let key = (lease.lease_id, flow_id);
        {
            let flows = self.flows.lock().await;
            if let Some(flow) = flows.get(&key) {
                if flow.client_addr != client_addr {
                    warn!(
                        event = "ingress_udp_flow_identity_mismatch",
                        lease_id = lease.lease_id,
                        flow_id = %flow_id
                    );
                    return None;
                }
                return Some(flow.socket.clone());
            }
            if flows.len() >= self.max_udp_flows {
                warn!(event = "ingress_udp_flow_capacity_drop", flow_id = %flow_id);
                return None;
            }
        }
        let bind = if lease.target.local_addr.is_ipv6() {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        };
        let socket = Arc::new(UdpSocket::bind(bind).await.ok()?);
        let source_addr = socket.local_addr().ok()?;
        let metadata = IngressMetadata {
            relay_instance_id: self.relay_id.clone(),
            tunnel_session_id: self.session_id.to_string(),
            lease_id: lease.lease_id,
            listener_id: lease.target.id.clone(),
            ingress_id: None,
            flow_id: Some(flow_id.to_string()),
            client_addr,
            relay_addr: self.relay_addr,
        };
        if !metadata::register_udp(source_addr, metadata) {
            warn!(event = "ingress_metadata_capacity_drop", flow_id = %flow_id);
            return None;
        }
        let last_seen = Arc::new(Mutex::new(Instant::now()));
        let return_task = spawn_udp_return(
            self.connection.clone(),
            lease.lease_id,
            flow_id,
            socket.clone(),
            lease.target.local_addr,
            lease.target.max_inner_datagram,
            last_seen.clone(),
        );
        let mut flows = self.flows.lock().await;
        if let Some(existing) = flows.get(&key) {
            metadata::remove_udp(source_addr);
            return_task.abort();
            return Some(existing.socket.clone());
        }
        flows.insert(
            key,
            ConnectorFlow {
                client_addr,
                source_addr,
                socket: socket.clone(),
                last_seen,
                return_task,
            },
        );
        info!(
            event = "ingress_udp_flow_opened",
            relay_id = %self.relay_id,
            listener_id = %lease.target.id,
            lease_id = lease.lease_id,
            flow_id = %flow_id,
            client_addr = %client_addr,
            public_port = lease.public_port
        );
        Some(socket)
    }

    async fn flow_sweeper(self: Arc<Self>) {
        let mut interval = tokio::time::interval(FLOW_SWEEP_INTERVAL);
        loop {
            interval.tick().await;
            let now = Instant::now();
            let expired = {
                let flows = self.flows.lock().await;
                flows
                    .iter()
                    .filter(|(_, flow)| {
                        now.duration_since(*flow.last_seen.lock().expect("flow clock poisoned"))
                            >= FLOW_IDLE
                    })
                    .map(|(key, _)| *key)
                    .collect::<Vec<_>>()
            };
            for key in expired {
                self.remove_flow(key).await;
            }
        }
    }

    async fn remove_flow(&self, key: (u64, Id128)) {
        if let Some(flow) = self.flows.lock().await.remove(&key) {
            metadata::remove_udp(flow.source_addr);
            flow.return_task.abort();
            let (_, flow_id) = key;
            info!(event = "ingress_udp_flow_closed", flow_id = %flow_id);
        }
    }

    async fn clear_flows(&self) {
        let flows = std::mem::take(&mut *self.flows.lock().await);
        for (_, flow) in flows {
            metadata::remove_udp(flow.source_addr);
            flow.return_task.abort();
        }
    }
}

async fn connect_local_tcp(
    target: SocketAddr,
    metadata_value: IngressMetadata,
) -> anyhow::Result<tokio::net::TcpStream> {
    let socket = if target.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    let bind = if target.is_ipv6() {
        "[::1]:0".parse().expect("valid ipv6 loopback")
    } else {
        "127.0.0.1:0".parse().expect("valid ipv4 loopback")
    };
    socket.bind(bind)?;
    let source = socket.local_addr()?;
    anyhow::ensure!(
        metadata::register_tcp(source, metadata_value),
        "ingress TCP metadata registry is full"
    );
    match tokio::time::timeout(SESSION_TIMEOUT, socket.connect(target)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => {
            metadata::remove_tcp(source);
            Err(e.into())
        }
        Err(_) => {
            metadata::remove_tcp(source);
            anyhow::bail!("local listener connect timed out")
        }
    }
}

fn spawn_udp_return(
    connection: quinn::Connection,
    lease_id: u64,
    flow_id: Id128,
    socket: Arc<UdpSocket>,
    expected_source: SocketAddr,
    max_inner_datagram: usize,
    last_seen: Arc<Mutex<Instant>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65_535];
        loop {
            let (len, source) = match socket.recv_from(&mut buffer).await {
                Ok(value) => value,
                Err(_) => break,
            };
            if source != expected_source || len > max_inner_datagram {
                continue;
            }
            *last_seen.lock().expect("flow clock poisoned") = Instant::now();
            let encoded = Datagram::Downlink {
                lease_id,
                flow_id,
                payload: &buffer[..len],
            }
            .encode();
            if connection
                .max_datagram_size()
                .is_some_and(|max| encoded.len() > max)
            {
                warn!(
                    event = "oversized_datagram_drop",
                    direction = "downlink",
                    lease_id,
                    flow_id = %flow_id,
                    encoded_len = encoded.len(),
                    max = connection.max_datagram_size().unwrap_or(0)
                );
                continue;
            }
            if connection.send_datagram(Bytes::from(encoded)).is_err() {
                break;
            }
        }
    })
}

async fn write_error(send: &mut quinn::SendStream, code: &str) {
    if let Ok(bytes) = Reply::Err(code.to_string()).encode() {
        let _ = frame::write_frame(send, &bytes).await;
    }
    let _ = send.finish();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_listener_is_normalized_to_loopback() {
        assert_eq!(
            normalize_loopback_target("0.0.0.0:8443").unwrap(),
            "127.0.0.1:8443".parse().unwrap()
        );
        assert_eq!(
            normalize_loopback_target("[::]:8443").unwrap(),
            "[::1]:8443".parse().unwrap()
        );
        assert!(normalize_loopback_target("203.0.113.2:8443").is_err());
    }

    #[test]
    fn disabled_config_is_backward_compatible() {
        assert!(ReverseIngressConfig::default().validate().is_ok());
    }
}
