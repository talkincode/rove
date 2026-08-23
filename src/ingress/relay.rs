//! Public reverse-ingress relay.

use super::frame::{
    self, codes, Datagram, Id128, LeaseRequest, OpenTcpRequest, RegisterRequest, Reply, Transport,
};
use crate::io::splice;
use crate::reverse::QuicDuplex;
use bytes::Bytes;
use serde::Deserialize;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

const REGISTER_TIMEOUT: Duration = Duration::from_secs(10);
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_FLOW_IDLE: Duration = Duration::from_secs(60);
const FLOW_SWEEP_INTERVAL: Duration = Duration::from_secs(15);
const REJECT_LINGER: Duration = Duration::from_millis(50);
const DEFAULT_MAX_LEASES: usize = 16;
const DEFAULT_MAX_TCP_CONNECTIONS: usize = 4096;
const DEFAULT_MAX_UDP_FLOWS: usize = 4096;
const MAX_PORTS_PER_GRANT: usize = 4096;
const MAX_CONFIG_STREAMS: u32 = 65_536;
const MAX_CONFIG_LEASES: usize = 1024;
const MAX_CONFIG_CONNECTIONS: usize = 65_536;
const MAX_CONFIG_UDP_FLOWS: usize = 65_536;
const MAX_LEASE_GRACE_SECS: u64 = 86_400;
const CLOSE_OK: u32 = 0;

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub relay_id: String,
    pub listen: SocketAddr,
    pub public_bind: IpAddr,
    pub cert: String,
    pub key: String,
    pub initial_mtu: Option<u16>,
    pub max_streams: u32,
    pub lease_grace: Duration,
    pub nodes: HashMap<String, NodeGrant>,
}

#[derive(Debug, Clone)]
pub struct NodeGrant {
    tokens: Vec<String>,
    listeners: HashMap<(String, Transport), ListenerGrant>,
    max_leases: usize,
    max_tcp_connections: usize,
    max_udp_flows: usize,
}

#[derive(Debug, Clone)]
struct ListenerGrant {
    ports: Vec<PortRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PortRange {
    start: u16,
    end: u16,
}

#[derive(Debug, Deserialize)]
struct RelayFile {
    relay_id: String,
    listen: String,
    #[serde(default = "default_public_bind")]
    public_bind: String,
    cert: String,
    key: String,
    #[serde(default)]
    initial_mtu: Option<u16>,
    #[serde(default = "default_max_streams")]
    max_streams: u32,
    #[serde(default = "default_lease_grace_secs")]
    lease_grace_secs: u64,
    #[serde(default)]
    nodes: Vec<NodeFile>,
}

#[derive(Debug, Deserialize)]
struct NodeFile {
    node_id: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    token_env: String,
    #[serde(default)]
    tokens: Vec<String>,
    #[serde(default)]
    token_envs: Vec<String>,
    #[serde(default = "default_max_leases")]
    max_leases: usize,
    #[serde(default = "default_max_tcp_connections")]
    max_tcp_connections: usize,
    #[serde(default = "default_max_udp_flows")]
    max_udp_flows: usize,
    #[serde(default)]
    listeners: Vec<ListenerFile>,
}

#[derive(Debug, Deserialize)]
struct ListenerFile {
    id: String,
    transport: String,
    ports: Vec<String>,
}

fn default_public_bind() -> String {
    "0.0.0.0".into()
}
fn default_max_streams() -> u32 {
    super::DEFAULT_MAX_STREAMS
}
fn default_lease_grace_secs() -> u64 {
    30
}
fn default_max_leases() -> usize {
    DEFAULT_MAX_LEASES
}
fn default_max_tcp_connections() -> usize {
    DEFAULT_MAX_TCP_CONNECTIONS
}
fn default_max_udp_flows() -> usize {
    DEFAULT_MAX_UDP_FLOWS
}

impl RelayConfig {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read relay config {path}: {e}"))?;
        let file: RelayFile =
            toml::from_str(&text).map_err(|e| anyhow::anyhow!("parse relay config {path}: {e}"))?;
        file.compile()
    }
}

impl RelayFile {
    fn compile(self) -> anyhow::Result<RelayConfig> {
        validate_id("relay_id", &self.relay_id)?;
        anyhow::ensure!(!self.cert.trim().is_empty(), "relay cert is required");
        anyhow::ensure!(!self.key.trim().is_empty(), "relay key is required");
        anyhow::ensure!(
            (1..=MAX_CONFIG_STREAMS).contains(&self.max_streams),
            "relay max_streams must be in [1, {MAX_CONFIG_STREAMS}]"
        );
        anyhow::ensure!(
            (1..=MAX_LEASE_GRACE_SECS).contains(&self.lease_grace_secs),
            "relay lease_grace_secs must be in [1, {MAX_LEASE_GRACE_SECS}]"
        );
        crate::config::validate_initial_mtu("relay initial_mtu", self.initial_mtu)?;
        let listen = self
            .listen
            .parse()
            .map_err(|e| anyhow::anyhow!("relay listen {:?}: {e}", self.listen))?;
        let public_bind = self
            .public_bind
            .parse()
            .map_err(|e| anyhow::anyhow!("relay public_bind {:?}: {e}", self.public_bind))?;

        let mut nodes = HashMap::new();
        for node in self.nodes {
            validate_id("relay node_id", &node.node_id)?;
            anyhow::ensure!(
                !nodes.contains_key(&node.node_id),
                "duplicate relay node_id {:?}",
                node.node_id
            );
            anyhow::ensure!(
                (1..=MAX_CONFIG_LEASES).contains(&node.max_leases),
                "node max_leases must be in [1, {MAX_CONFIG_LEASES}]"
            );
            anyhow::ensure!(
                (1..=MAX_CONFIG_CONNECTIONS).contains(&node.max_tcp_connections),
                "node max_tcp_connections must be in [1, {MAX_CONFIG_CONNECTIONS}]"
            );
            anyhow::ensure!(
                (1..=MAX_CONFIG_UDP_FLOWS).contains(&node.max_udp_flows),
                "node max_udp_flows must be in [1, {MAX_CONFIG_UDP_FLOWS}]"
            );
            let mut tokens = node
                .tokens
                .into_iter()
                .map(|token| token.trim().to_string())
                .filter(|token| !token.is_empty())
                .collect::<Vec<_>>();
            if !node.token.trim().is_empty() {
                tokens.push(node.token.trim().to_string());
            }
            let mut token_envs = node.token_envs;
            if !node.token_env.trim().is_empty() {
                token_envs.push(node.token_env.trim().to_string());
            }
            for env_name in token_envs {
                let env_name = env_name.trim();
                anyhow::ensure!(!env_name.is_empty(), "relay token env name is empty");
                let token = std::env::var(env_name).map_err(|_| {
                    anyhow::anyhow!(
                        "relay node {} token environment variable {} is not set",
                        node.node_id,
                        env_name
                    )
                })?;
                anyhow::ensure!(!token.is_empty(), "relay node token must not be empty");
                tokens.push(token);
            }
            tokens.sort();
            tokens.dedup();
            anyhow::ensure!(
                !tokens.is_empty(),
                "relay node {} needs at least one token or token_env",
                node.node_id
            );
            anyhow::ensure!(
                tokens.iter().all(|token| {
                    token.len() <= frame::MAX_TOKEN_BYTES
                        && !token.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0))
                }),
                "relay node {} has a token that cannot be encoded safely",
                node.node_id
            );

            let mut listeners = HashMap::new();
            for listener in node.listeners {
                validate_id("relay listener id", &listener.id)?;
                let transport = Transport::parse(&listener.transport)
                    .map_err(|e| anyhow::anyhow!("listener {}: {e}", listener.id))?;
                let key = (listener.id.clone(), transport);
                anyhow::ensure!(
                    !listeners.contains_key(&key),
                    "duplicate relay listener {} {}",
                    listener.id,
                    transport.as_str()
                );
                let ports = compile_ports(&listener.ports)?;
                listeners.insert(key, ListenerGrant { ports });
            }
            anyhow::ensure!(
                !listeners.is_empty(),
                "relay node {} needs at least one listener grant",
                node.node_id
            );
            nodes.insert(
                node.node_id,
                NodeGrant {
                    tokens,
                    listeners,
                    max_leases: node.max_leases,
                    max_tcp_connections: node.max_tcp_connections,
                    max_udp_flows: node.max_udp_flows,
                },
            );
        }
        anyhow::ensure!(
            !nodes.is_empty(),
            "relay needs at least one authorized node"
        );
        Self::validate_non_overlapping_grants(&nodes)?;

        Ok(RelayConfig {
            relay_id: self.relay_id,
            listen,
            public_bind,
            cert: self.cert,
            key: self.key,
            initial_mtu: self.initial_mtu,
            max_streams: self.max_streams,
            lease_grace: Duration::from_secs(self.lease_grace_secs),
            nodes,
        })
    }

    fn validate_non_overlapping_grants(nodes: &HashMap<String, NodeGrant>) -> anyhow::Result<()> {
        let mut claimed: HashMap<(Transport, u16), String> = HashMap::new();
        for (node_id, node) in nodes {
            for ((listener_id, transport), grant) in &node.listeners {
                let owner = format!("{node_id}/{listener_id}/{}", transport.as_str());
                for range in &grant.ports {
                    for port in range.start..=range.end {
                        if let Some(existing) = claimed.insert((*transport, port), owner.clone()) {
                            anyhow::bail!(
                                "relay port grant overlap on {} {port}: {existing} and {owner}",
                                transport.as_str()
                            );
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn compile_ports(values: &[String]) -> anyhow::Result<Vec<PortRange>> {
    anyhow::ensure!(!values.is_empty(), "listener grant needs at least one port");
    let mut ranges = Vec::new();
    let mut total = 0usize;
    for raw in values {
        let raw = raw.trim();
        let range = if let Some((start, end)) = raw.split_once('-') {
            PortRange {
                start: start
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid port range {raw:?}"))?,
                end: end
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid port range {raw:?}"))?,
            }
        } else {
            let port = raw
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid port {raw:?}"))?;
            PortRange {
                start: port,
                end: port,
            }
        };
        anyhow::ensure!(
            range.start > 0 && range.start <= range.end,
            "invalid port range {raw:?}"
        );
        total = total.saturating_add(usize::from(range.end - range.start) + 1);
        anyhow::ensure!(
            total <= MAX_PORTS_PER_GRANT,
            "listener grant expands beyond {MAX_PORTS_PER_GRANT} ports"
        );
        ranges.push(range);
    }
    Ok(ranges)
}

fn validate_id(field: &str, value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!value.is_empty(), "{field} must not be empty");
    anyhow::ensure!(value.len() <= 128, "{field} is too long");
    anyhow::ensure!(
        value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':')),
        "{field} contains unsupported characters"
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReservationKey {
    node_id: String,
    listener_id: String,
    transport: Transport,
}

#[derive(Debug, Clone)]
struct Reservation {
    port: u16,
    expires_at: Instant,
}

struct LeasePortGuard {
    state: Arc<RelayState>,
    key: Option<ReservationKey>,
    port: u16,
}

impl LeasePortGuard {
    fn new(state: Arc<RelayState>, key: ReservationKey, port: u16) -> Self {
        LeasePortGuard {
            state,
            key: Some(key),
            port,
        }
    }
}

impl Drop for LeasePortGuard {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.state.remember_port(key, self.port);
        }
    }
}

struct RelayState {
    relay_id: String,
    public_bind: IpAddr,
    nodes: HashMap<String, NodeGrant>,
    sessions: Mutex<HashMap<String, usize>>,
    reservations: Mutex<HashMap<ReservationKey, Reservation>>,
    lease_seq: AtomicU64,
    lease_grace: Duration,
}

pub struct RelayServer {
    endpoint: quinn::Endpoint,
    state: Arc<RelayState>,
    local_addr: SocketAddr,
}

impl RelayServer {
    pub fn bind(config: RelayConfig) -> anyhow::Result<Self> {
        let server = super::server_config(
            &config.cert,
            &config.key,
            config.max_streams,
            config.initial_mtu,
        )?;
        let endpoint = quinn::Endpoint::server(server, config.listen)
            .map_err(|e| anyhow::anyhow!("bind relay {}: {e}", config.listen))?;
        let local_addr = endpoint.local_addr().unwrap_or(config.listen);
        Ok(RelayServer {
            endpoint,
            state: Arc::new(RelayState {
                relay_id: config.relay_id,
                public_bind: config.public_bind,
                nodes: config.nodes,
                sessions: Mutex::new(HashMap::new()),
                reservations: Mutex::new(HashMap::new()),
                lease_seq: AtomicU64::new(1),
                lease_grace: config.lease_grace,
            }),
            local_addr,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        self.run_until(shutdown_rx).await
    }

    pub async fn run_until(self, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
        info!(
            event = "relay_started",
            relay_id = %self.state.relay_id,
            listen = %self.local_addr,
            "reverse-ingress relay started"
        );
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = crate::lifecycle::shutdown_requested(&mut shutdown) => {
                    info!(event = "relay_draining", relay_id = %self.state.relay_id);
                    self.endpoint.close(CLOSE_OK.into(), b"relay shutdown");
                    break;
                }
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break;
                    };
                    let state = self.state.clone();
                    connections.spawn(async move {
                        let remote = incoming.remote_address();
                        let connection = match incoming.accept() {
                            Ok(connecting) => match connecting.await {
                                Ok(connection) => connection,
                                Err(e) => {
                                    warn!(event = "tunnel_handshake_failed", remote = %remote, error = %e);
                                    return;
                                }
                            },
                            Err(e) => {
                                warn!(event = "tunnel_accept_failed", remote = %remote, error = %e);
                                return;
                            }
                        };
                        state.handle_connection(connection, remote).await;
                    });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(e) = result {
                        debug!(event = "relay_session_task_failed", error = %e);
                    }
                }
            }
        }
        self.endpoint.close(CLOSE_OK.into(), b"relay stopped");
        while let Some(result) = connections.join_next().await {
            if let Err(e) = result {
                debug!(event = "relay_session_task_failed", error = %e);
            }
        }
        info!(
            event = "relay_stopped",
            relay_id = %self.state.relay_id,
            "reverse-ingress relay stopped"
        );
        Ok(())
    }
}

struct RegisteredSession {
    state: Arc<RelayState>,
    node_id: String,
    grant: NodeGrant,
    connection: quinn::Connection,
    remote: SocketAddr,
    session_id: Id128,
    lease_permits: Arc<Semaphore>,
    tcp_permits: Arc<Semaphore>,
    flows: Arc<Mutex<FlowTables>>,
}

#[derive(Default)]
struct FlowTables {
    by_key: HashMap<(u64, SocketAddr), Id128>,
    by_id: HashMap<(u64, Id128), RelayFlow>,
}

#[derive(Clone)]
struct RelayFlow {
    lease_id: u64,
    client_addr: SocketAddr,
    socket: Arc<UdpSocket>,
    listener_id: String,
    last_seen: Arc<Mutex<Instant>>,
    bytes_up: Arc<AtomicU64>,
    bytes_down: Arc<AtomicU64>,
}

impl RelayState {
    async fn handle_connection(self: Arc<Self>, connection: quinn::Connection, remote: SocketAddr) {
        let (mut send, mut recv) =
            match tokio::time::timeout(REGISTER_TIMEOUT, connection.accept_bi()).await {
                Ok(Ok(stream)) => stream,
                _ => {
                    connection.close(CLOSE_OK.into(), b"register timeout");
                    return;
                }
            };
        let lines = match frame::read_frame(&mut recv).await {
            Ok(lines) => lines,
            Err(_) => {
                reject(&connection, &mut send, codes::BAD_REQUEST).await;
                return;
            }
        };
        let request = match RegisterRequest::parse(&lines) {
            Ok(request) => request,
            Err(_) => {
                reject(&connection, &mut send, codes::BAD_REQUEST).await;
                return;
            }
        };
        let Some(grant) = self.nodes.get(&request.node_id).cloned() else {
            reject(&connection, &mut send, codes::UNAUTHORIZED).await;
            return;
        };
        if !grant
            .tokens
            .iter()
            .any(|token| crate::util::constant_time_eq(token, &request.token))
        {
            warn!(
                event = "node_auth_failed",
                node_id = %request.node_id,
                remote = %remote
            );
            reject(&connection, &mut send, codes::UNAUTHORIZED).await;
            return;
        }
        let duplicate = {
            let mut sessions = self.sessions.lock().expect("relay sessions poisoned");
            if sessions.contains_key(&request.node_id) {
                true
            } else {
                sessions.insert(request.node_id.clone(), connection.stable_id());
                false
            }
        };
        if duplicate {
            reject(&connection, &mut send, codes::DUPLICATE_NODE_ID).await;
            return;
        }
        let session_id = match Id128::random() {
            Ok(id) => id,
            Err(_) => {
                self.deregister(&request.node_id, connection.stable_id());
                reject(&connection, &mut send, codes::INTERNAL).await;
                return;
            }
        };
        let reply = Reply::ok_with([
            ("relay-id".into(), self.relay_id.clone()),
            ("session-id".into(), session_id.to_string()),
        ]);
        let bytes = match reply.encode() {
            Ok(bytes) => bytes,
            Err(_) => {
                self.deregister(&request.node_id, connection.stable_id());
                connection.close(CLOSE_OK.into(), b"reply encode failed");
                return;
            }
        };
        if frame::write_frame(&mut send, &bytes).await.is_err() {
            self.deregister(&request.node_id, connection.stable_id());
            connection.close(CLOSE_OK.into(), b"register ack failed");
            return;
        }

        info!(
            event = "node_registered",
            relay_id = %self.relay_id,
            node_id = %request.node_id,
            tunnel_session_id = %session_id,
            remote = %remote
        );
        let session = Arc::new(RegisteredSession {
            state: self.clone(),
            node_id: request.node_id.clone(),
            grant: grant.clone(),
            connection: connection.clone(),
            remote,
            session_id,
            lease_permits: Arc::new(Semaphore::new(grant.max_leases)),
            tcp_permits: Arc::new(Semaphore::new(grant.max_tcp_connections)),
            flows: Arc::new(Mutex::new(FlowTables::default())),
        });
        let datagrams = tokio::spawn(session.clone().downlink_loop());
        let sweeper = tokio::spawn(session.clone().flow_sweeper());
        let mut lease_tasks = JoinSet::new();

        loop {
            tokio::select! {
                stream = connection.accept_bi() => {
                    let (send, recv) = match stream {
                        Ok(stream) => stream,
                        Err(_) => break,
                    };
                    let session = session.clone();
                    lease_tasks.spawn(async move {
                        session.handle_lease(send, recv).await;
                    });
                }
                Some(_) = lease_tasks.join_next(), if !lease_tasks.is_empty() => {}
                _ = connection.closed() => break,
            }
        }
        lease_tasks.abort_all();
        while lease_tasks.join_next().await.is_some() {}
        datagrams.abort();
        sweeper.abort();
        self.deregister(&request.node_id, connection.stable_id());
        info!(
            event = "node_deregistered",
            relay_id = %self.relay_id,
            node_id = %request.node_id,
            tunnel_session_id = %session_id
        );
    }

    fn deregister(&self, node_id: &str, stable_id: usize) {
        let mut sessions = self.sessions.lock().expect("relay sessions poisoned");
        if sessions.get(node_id).copied() == Some(stable_id) {
            sessions.remove(node_id);
        }
    }

    fn reserve_port(
        &self,
        key: &ReservationKey,
        grant: &ListenerGrant,
        requested: u16,
    ) -> Result<u16, &'static str> {
        let now = Instant::now();
        let mut reservations = self.reservations.lock().expect("reservations poisoned");
        reservations.retain(|_, reservation| reservation.expires_at > now);

        if requested != 0 {
            if !port_allowed(grant, requested)
                || reservations
                    .iter()
                    .any(|(other, reservation)| other != key && reservation.port == requested)
            {
                return Err(codes::FORBIDDEN);
            }
            return Ok(requested);
        }
        if let Some(reservation) = reservations.get(key) {
            return Ok(reservation.port);
        }
        for range in &grant.ports {
            for port in range.start..=range.end {
                if reservations
                    .iter()
                    .any(|(other, reservation)| other != key && reservation.port == port)
                {
                    continue;
                }
                return Ok(port);
            }
        }
        Err(codes::PORT_UNAVAILABLE)
    }

    fn remember_port(&self, key: ReservationKey, port: u16) {
        self.reservations
            .lock()
            .expect("reservations poisoned")
            .insert(
                key,
                Reservation {
                    port,
                    expires_at: Instant::now() + self.lease_grace,
                },
            );
    }
}

impl RegisteredSession {
    async fn handle_lease(
        self: Arc<Self>,
        mut send: quinn::SendStream,
        mut recv: quinn::RecvStream,
    ) {
        let lines = match frame::read_frame(&mut recv).await {
            Ok(lines) => lines,
            Err(_) => {
                write_error(&mut send, codes::BAD_REQUEST).await;
                return;
            }
        };
        let request = match LeaseRequest::parse(&lines) {
            Ok(request) => request,
            Err(_) => {
                write_error(&mut send, codes::BAD_REQUEST).await;
                return;
            }
        };
        let Some(grant) = self
            .grant
            .listeners
            .get(&(request.listener_id.clone(), request.transport))
            .cloned()
        else {
            write_error(&mut send, codes::FORBIDDEN).await;
            return;
        };
        let permit = match self.lease_permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                write_error(&mut send, codes::AT_CAPACITY).await;
                return;
            }
        };
        let key = ReservationKey {
            node_id: self.node_id.clone(),
            listener_id: request.listener_id.clone(),
            transport: request.transport,
        };
        let preferred = match self.state.reserve_port(&key, &grant, request.public_port) {
            Ok(port) => port,
            Err(code) => {
                write_error(&mut send, code).await;
                return;
            }
        };
        match request.transport {
            Transport::Tcp => {
                let listener = match bind_tcp(
                    self.state.public_bind,
                    preferred,
                    &grant,
                    request.public_port != 0,
                )
                .await
                {
                    Ok(listener) => listener,
                    Err(_) => {
                        write_error(&mut send, codes::PORT_UNAVAILABLE).await;
                        return;
                    }
                };
                let public_addr = match listener.local_addr() {
                    Ok(addr) => addr,
                    Err(_) => {
                        write_error(&mut send, codes::INTERNAL).await;
                        return;
                    }
                };
                let lease_id = self.state.lease_seq.fetch_add(1, Ordering::Relaxed);
                if write_lease_ok(&mut send, lease_id, public_addr.port())
                    .await
                    .is_err()
                {
                    return;
                }
                let _port_guard = LeasePortGuard::new(self.state.clone(), key, public_addr.port());
                self.serve_tcp_lease(
                    listener,
                    request.listener_id.clone(),
                    lease_id,
                    public_addr,
                    &mut recv,
                )
                .await;
                drop(permit);
            }
            Transport::Udp => {
                let socket = match bind_udp(
                    self.state.public_bind,
                    preferred,
                    &grant,
                    request.public_port != 0,
                )
                .await
                {
                    Ok(socket) => Arc::new(socket),
                    Err(_) => {
                        write_error(&mut send, codes::PORT_UNAVAILABLE).await;
                        return;
                    }
                };
                let public_addr = match socket.local_addr() {
                    Ok(addr) => addr,
                    Err(_) => {
                        write_error(&mut send, codes::INTERNAL).await;
                        return;
                    }
                };
                let lease_id = self.state.lease_seq.fetch_add(1, Ordering::Relaxed);
                if write_lease_ok(&mut send, lease_id, public_addr.port())
                    .await
                    .is_err()
                {
                    return;
                }
                let _port_guard = LeasePortGuard::new(self.state.clone(), key, public_addr.port());
                self.serve_udp_lease(
                    socket,
                    request.listener_id.clone(),
                    lease_id,
                    public_addr,
                    &mut recv,
                )
                .await;
                self.remove_lease_flows(lease_id);
                drop(permit);
            }
        }
    }

    async fn serve_tcp_lease(
        self: &Arc<Self>,
        listener: TcpListener,
        listener_id: String,
        lease_id: u64,
        public_addr: SocketAddr,
        control: &mut quinn::RecvStream,
    ) {
        info!(
            event = "lease_opened",
            node_id = %self.node_id,
            listener_id = %listener_id,
            transport = "tcp",
            lease_id,
            public_addr = %public_addr,
            tunnel_peer = %self.remote
        );
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, client_addr) = match accepted {
                        Ok(pair) => pair,
                        Err(e) => {
                            warn!(event = "tcp_accept_failed", lease_id, error = %e);
                            continue;
                        }
                    };
                    let permit = match self.tcp_permits.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            warn!(event = "tcp_capacity_drop", lease_id, client_addr = %client_addr);
                            drop(stream);
                            continue;
                        }
                    };
                    let session = self.clone();
                    let listener_id = listener_id.clone();
                    tasks.spawn(async move {
                        session.forward_tcp(stream, client_addr, public_addr, listener_id, lease_id, permit).await;
                    });
                }
                read = control.read_u8() => {
                    if read.is_err() {
                        break;
                    }
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                _ = self.connection.closed() => break,
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        info!(event = "lease_closed", lease_id, transport = "tcp");
    }

    async fn forward_tcp(
        &self,
        stream: TcpStream,
        client_addr: SocketAddr,
        public_addr: SocketAddr,
        listener_id: String,
        lease_id: u64,
        _permit: OwnedSemaphorePermit,
    ) {
        let ingress_id = match Id128::random() {
            Ok(id) => id,
            Err(_) => return,
        };
        let started = Instant::now();
        let (mut send, mut recv) =
            match tokio::time::timeout(OPEN_TIMEOUT, self.connection.open_bi()).await {
                Ok(Ok(streams)) => streams,
                _ => {
                    warn!(event = "tcp_open_failed", ingress_id = %ingress_id, lease_id);
                    return;
                }
            };
        let request = OpenTcpRequest {
            lease_id,
            ingress_id,
            client_addr,
            public_addr,
            relay_instance_id: self.state.relay_id.clone(),
            tunnel_session_id: self.session_id,
        };
        let encoded = match request.encode() {
            Ok(encoded) => encoded,
            Err(_) => return,
        };
        if frame::write_frame(&mut send, &encoded).await.is_err() {
            return;
        }
        let reply = match tokio::time::timeout(OPEN_TIMEOUT, frame::read_frame(&mut recv)).await {
            Ok(Ok(lines)) => Reply::parse(&lines),
            _ => return,
        };
        if !matches!(reply, Ok(Reply::Ok(_))) {
            warn!(
                event = "tcp_local_rejected",
                ingress_id = %ingress_id,
                lease_id,
                listener_id = %listener_id
            );
            return;
        }
        let outcome = splice(stream, QuicDuplex::new(send, recv), 0, 0).await;
        let (result, bytes_up, bytes_down) = match outcome {
            Ok(stats) => ("ok", stats.bytes_up, stats.bytes_down),
            Err(_) => ("stream_io", 0, 0),
        };
        info!(
            event = "tcp_closed",
            relay_id = %self.state.relay_id,
            node_id = %self.node_id,
            listener_id = %listener_id,
            tunnel_session_id = %self.session_id,
            ingress_id = %ingress_id,
            lease_id,
            client_addr = %client_addr,
            public_addr = %public_addr,
            bytes_up,
            bytes_down,
            result,
            duration_ms = started.elapsed().as_millis()
        );
    }

    async fn serve_udp_lease(
        &self,
        socket: Arc<UdpSocket>,
        listener_id: String,
        lease_id: u64,
        public_addr: SocketAddr,
        control: &mut quinn::RecvStream,
    ) {
        info!(
            event = "lease_opened",
            node_id = %self.node_id,
            listener_id = %listener_id,
            transport = "udp",
            lease_id,
            public_addr = %public_addr,
            tunnel_peer = %self.remote
        );
        let mut buffer = vec![0u8; 65_535];
        loop {
            tokio::select! {
                received = socket.recv_from(&mut buffer) => {
                    let (len, client_addr) = match received {
                        Ok(value) => value,
                        Err(e) => {
                            warn!(event = "udp_receive_failed", lease_id, error = %e);
                            continue;
                        }
                    };
                    self.forward_udp(
                        socket.clone(),
                        &listener_id,
                        lease_id,
                        client_addr,
                        &buffer[..len],
                    );
                }
                read = control.read_u8() => {
                    if read.is_err() {
                        break;
                    }
                }
                _ = self.connection.closed() => break,
            }
        }
        info!(event = "lease_closed", lease_id, transport = "udp");
    }

    fn forward_udp(
        &self,
        socket: Arc<UdpSocket>,
        listener_id: &str,
        lease_id: u64,
        client_addr: SocketAddr,
        payload: &[u8],
    ) {
        let flow_id = {
            let mut tables = self.flows.lock().expect("relay flows poisoned");
            if let Some(id) = tables.by_key.get(&(lease_id, client_addr)).copied() {
                if let Some(flow) = tables.by_id.get(&(lease_id, id)) {
                    *flow.last_seen.lock().expect("flow clock poisoned") = Instant::now();
                    flow.bytes_up
                        .fetch_add(payload.len() as u64, Ordering::Relaxed);
                }
                id
            } else {
                if tables.by_id.len() >= self.grant.max_udp_flows {
                    warn!(event = "udp_flow_capacity_drop", lease_id, client_addr = %client_addr);
                    return;
                }
                let id = loop {
                    let id = match Id128::random() {
                        Ok(id) => id,
                        Err(_) => return,
                    };
                    if !tables.by_id.contains_key(&(lease_id, id)) {
                        break id;
                    }
                };
                let flow = RelayFlow {
                    lease_id,
                    client_addr,
                    socket,
                    listener_id: listener_id.to_string(),
                    last_seen: Arc::new(Mutex::new(Instant::now())),
                    bytes_up: Arc::new(AtomicU64::new(payload.len() as u64)),
                    bytes_down: Arc::new(AtomicU64::new(0)),
                };
                tables.by_key.insert((lease_id, client_addr), id);
                tables.by_id.insert((lease_id, id), flow);
                info!(
                    event = "udp_flow_opened",
                    node_id = %self.node_id,
                    listener_id,
                    lease_id,
                    flow_id = %id,
                    client_addr = %client_addr
                );
                id
            }
        };
        let encoded = Datagram::Uplink {
            lease_id,
            flow_id,
            client_addr,
            payload,
        }
        .encode();
        if self
            .connection
            .max_datagram_size()
            .is_some_and(|max| encoded.len() > max)
        {
            warn!(
                event = "oversized_datagram_drop",
                direction = "uplink",
                lease_id,
                flow_id = %flow_id,
                encoded_len = encoded.len(),
                max = self.connection.max_datagram_size().unwrap_or(0)
            );
            return;
        }
        if let Err(error) = self.connection.send_datagram(Bytes::from(encoded)) {
            debug!(event = "udp_send_drop", direction = "uplink", error = %error);
        }
    }

    async fn downlink_loop(self: Arc<Self>) {
        while let Ok(bytes) = self.connection.read_datagram().await {
            let Datagram::Downlink {
                lease_id,
                flow_id,
                payload,
            } = (match Datagram::parse(&bytes) {
                Ok(datagram) => datagram,
                Err(e) => {
                    debug!(event = "malformed_datagram_drop", error = %e);
                    continue;
                }
            })
            else {
                debug!(event = "wrong_direction_datagram_drop");
                continue;
            };
            let flow = self
                .flows
                .lock()
                .expect("relay flows poisoned")
                .by_id
                .get(&(lease_id, flow_id))
                .cloned();
            let Some(flow) = flow else {
                debug!(event = "unknown_udp_flow_drop", lease_id, flow_id = %flow_id);
                continue;
            };
            if flow.socket.send_to(payload, flow.client_addr).await.is_ok() {
                *flow.last_seen.lock().expect("flow clock poisoned") = Instant::now();
                flow.bytes_down
                    .fetch_add(payload.len() as u64, Ordering::Relaxed);
            }
        }
    }

    async fn flow_sweeper(self: Arc<Self>) {
        let mut interval = tokio::time::interval(FLOW_SWEEP_INTERVAL);
        loop {
            interval.tick().await;
            let now = Instant::now();
            let expired = {
                let tables = self.flows.lock().expect("relay flows poisoned");
                tables
                    .by_id
                    .iter()
                    .filter(|(_, flow)| {
                        now.duration_since(*flow.last_seen.lock().expect("flow clock poisoned"))
                            >= DEFAULT_FLOW_IDLE
                    })
                    .map(|(key, _)| *key)
                    .collect::<Vec<_>>()
            };
            for key in expired {
                self.remove_flow(key, "idle");
            }
        }
    }

    fn remove_lease_flows(&self, lease_id: u64) {
        let ids = {
            let tables = self.flows.lock().expect("relay flows poisoned");
            tables
                .by_id
                .iter()
                .filter(|((flow_lease_id, _), _)| *flow_lease_id == lease_id)
                .map(|(key, _)| *key)
                .collect::<Vec<_>>()
        };
        for key in ids {
            self.remove_flow(key, "lease_closed");
        }
    }

    fn remove_flow(&self, key: (u64, Id128), reason: &'static str) {
        let flow = {
            let mut tables = self.flows.lock().expect("relay flows poisoned");
            let flow = tables.by_id.remove(&key);
            if let Some(flow) = &flow {
                tables.by_key.remove(&(flow.lease_id, flow.client_addr));
            }
            flow
        };
        if let Some(flow) = flow {
            let (_, flow_id) = key;
            info!(
                event = "udp_flow_closed",
                node_id = %self.node_id,
                listener_id = %flow.listener_id,
                lease_id = flow.lease_id,
                flow_id = %flow_id,
                client_addr = %flow.client_addr,
                bytes_up = flow.bytes_up.load(Ordering::Relaxed),
                bytes_down = flow.bytes_down.load(Ordering::Relaxed),
                reason
            );
        }
    }
}

async fn bind_tcp(
    bind_ip: IpAddr,
    preferred: u16,
    grant: &ListenerGrant,
    fixed: bool,
) -> anyhow::Result<TcpListener> {
    for port in candidate_ports(preferred, grant, fixed) {
        if let Ok(listener) = TcpListener::bind(SocketAddr::new(bind_ip, port)).await {
            return Ok(listener);
        }
    }
    anyhow::bail!("no authorized TCP port is available")
}

async fn bind_udp(
    bind_ip: IpAddr,
    preferred: u16,
    grant: &ListenerGrant,
    fixed: bool,
) -> anyhow::Result<UdpSocket> {
    for port in candidate_ports(preferred, grant, fixed) {
        if let Ok(socket) = UdpSocket::bind(SocketAddr::new(bind_ip, port)).await {
            return Ok(socket);
        }
    }
    anyhow::bail!("no authorized UDP port is available")
}

fn candidate_ports(preferred: u16, grant: &ListenerGrant, fixed: bool) -> Vec<u16> {
    let mut ports = Vec::new();
    if preferred != 0 && port_allowed(grant, preferred) {
        ports.push(preferred);
    }
    if fixed {
        return ports;
    }
    for range in &grant.ports {
        for port in range.start..=range.end {
            if port != preferred {
                ports.push(port);
            }
        }
    }
    ports
}

fn port_allowed(grant: &ListenerGrant, port: u16) -> bool {
    grant
        .ports
        .iter()
        .any(|range| (range.start..=range.end).contains(&port))
}

async fn reject(connection: &quinn::Connection, send: &mut quinn::SendStream, code: &str) {
    write_error(send, code).await;
    let _ = tokio::time::timeout(REJECT_LINGER, connection.closed()).await;
    connection.close(CLOSE_OK.into(), b"registration rejected");
}

async fn write_error(send: &mut quinn::SendStream, code: &str) {
    if let Ok(bytes) = Reply::Err(code.to_string()).encode() {
        let _ = frame::write_frame(send, &bytes).await;
    }
    let _ = send.finish();
}

async fn write_lease_ok(
    send: &mut quinn::SendStream,
    lease_id: u64,
    public_port: u16,
) -> io::Result<()> {
    let reply = Reply::ok_with([
        ("lease-id".into(), lease_id.to_string()),
        ("public-port".into(), public_port.to_string()),
    ]);
    let bytes = reply
        .encode()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    frame::write_frame(send, &bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_ranges_are_bounded_and_authorize_members() {
        let ranges = compile_ports(&["443".into(), "10000-10002".into()]).unwrap();
        let grant = ListenerGrant { ports: ranges };
        assert!(port_allowed(&grant, 443));
        assert!(port_allowed(&grant, 10001));
        assert!(!port_allowed(&grant, 22));
        assert_eq!(candidate_ports(10001, &grant, false)[0], 10001);
        assert_eq!(candidate_ports(10001, &grant, true), vec![10001]);
        assert!(compile_ports(&["1-5000".into()]).is_err());
    }

    #[test]
    fn config_rejects_missing_credentials() {
        let file: RelayFile = toml::from_str(
            r#"
relay_id = "relay-1"
listen = "127.0.0.1:0"
cert = "cert"
key = "key"

[[nodes]]
node_id = "edge-1"
token = ""

[[nodes.listeners]]
id = "https"
transport = "tcp"
ports = ["443"]
"#,
        )
        .unwrap();
        assert!(file.compile().is_err());
    }

    #[test]
    fn config_rejects_overlapping_port_grants() {
        let file: RelayFile = toml::from_str(
            r#"
relay_id = "relay-1"
listen = "127.0.0.1:0"
cert = "cert"
key = "key"

[[nodes]]
node_id = "edge-1"
token = "a"

[[nodes.listeners]]
id = "one"
transport = "tcp"
ports = ["10000-10002"]

[[nodes]]
node_id = "edge-2"
token = "b"

[[nodes.listeners]]
id = "two"
transport = "tcp"
ports = ["10002"]
"#,
        )
        .unwrap();
        assert!(file.compile().is_err());
    }
}
