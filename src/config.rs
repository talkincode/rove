//! Flat, minimal configuration. Compare with GOST's services/chains/hops/
//! listeners/connectors graph — here a node only needs: who am I, where is the
//! control plane, and which ports to listen on.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub node_id: String,
    pub control_plane: ControlPlane,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub shutdown: ShutdownConfig,
    #[serde(default)]
    pub listeners: Vec<Listener>,
    #[serde(default)]
    pub mqtt: MqttConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub access_log: AccessLogConfig,
    #[serde(default)]
    pub snmp: SnmpConfig,
    #[serde(default)]
    pub reverse_hop: ReverseHopConfig,
    /// Optional NAT-side connector to a public reverse-ingress relay.
    #[serde(default)]
    pub reverse_ingress: Vec<crate::ingress::connector::ReverseIngressConfig>,
    /// TUIC v5 front-end QUIC listeners. Independent of `listeners` (which are
    /// TCP HTTP/SOCKS5); a node may run either, both, or neither.
    #[serde(default)]
    pub tuic_listeners: Vec<TuicListener>,
    /// Optional embedded Subnetra mesh underlay (hub or spoke). When present and
    /// enabled, Rove speaks the Subnetra v1 wire protocol natively so a light
    /// Layer-3 tunnel can carry HTTP/SOCKS without a separate daemon or TUN.
    #[serde(default)]
    pub subnetra: Option<crate::subnetra::config::SubnetraConfig>,
    /// Optional dedicated egress DNS. Empty/absent → the OS resolver is used and
    /// behaviour is unchanged. Populate `[dns].servers` to route every egress
    /// hostname lookup through a specific (e.g. anti-pollution) resolver instead.
    #[serde(default)]
    pub dns: DnsConfig,
    /// Optional rove-addrbook artifact (`.rab`): the versioned, general-purpose
    /// address dataset that snapshot rules reference via `book:<category>`.
    /// Absent → `book:` rules reject the snapshot (fail closed).
    #[serde(default)]
    pub addrbook: Option<AddrBookConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AddrBookConfig {
    /// Path to the `.rab` artifact built/released by `rove-abctl`.
    pub path: String,
    /// How often to check the artifact file for a new release (mtime poll).
    /// 0 disables hot reload; the book then only changes on restart.
    #[serde(default = "default_addrbook_poll_secs")]
    pub poll_interval_secs: u64,
}

fn default_addrbook_poll_secs() -> u64 {
    300
}

impl AddrBookConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.path.trim().is_empty() {
            anyhow::bail!("[addrbook] path is required");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ControlPlane {
    /// The complete snapshot sync URL, used exactly as given — the node
    /// never appends a path to it (only a `since` query parameter). There is
    /// no per-node path segment; every node fetches this same URL and gets
    /// byte-identical JSON back.
    pub snapshot_url: String,
    pub token: String,
    #[serde(default = "default_poll")]
    pub poll_interval_secs: u64,
    #[serde(default = "default_cache")]
    pub cache_path: String,
}

/// Loopback-first HTTP liveness/readiness endpoint for orchestrators.
#[derive(Debug, Clone, Deserialize)]
pub struct HealthConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default = "default_health_listen")]
    pub listen: String,
    /// A loaded snapshot remains ready during short control-plane glitches.
    /// Readiness turns degraded only after failures have persisted this long.
    #[serde(default = "default_control_plane_unreachable_secs")]
    pub control_plane_unreachable_secs: u64,
}

impl Default for HealthConfig {
    fn default() -> Self {
        HealthConfig {
            enable: false,
            listen: default_health_listen(),
            control_plane_unreachable_secs: default_control_plane_unreachable_secs(),
        }
    }
}

impl HealthConfig {
    fn validate(&self) -> anyhow::Result<()> {
        if !self.enable {
            return Ok(());
        }
        anyhow::ensure!(
            !self.listen.trim().is_empty(),
            "health.listen must be set when health.enable = true"
        );
        anyhow::ensure!(
            self.control_plane_unreachable_secs > 0,
            "health.control_plane_unreachable_secs must be greater than zero"
        );
        Ok(())
    }
}

/// Process-wide graceful-shutdown budget.
#[derive(Debug, Clone, Deserialize)]
pub struct ShutdownConfig {
    #[serde(default = "default_shutdown_grace_period_secs")]
    pub grace_period_secs: u64,
}

impl Default for ShutdownConfig {
    fn default() -> Self {
        ShutdownConfig {
            grace_period_secs: default_shutdown_grace_period_secs(),
        }
    }
}

impl ShutdownConfig {
    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.grace_period_secs > 0,
            "shutdown.grace_period_secs must be greater than zero"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Listener {
    pub name: String,
    /// `http` or `socks5`. TLS is orthogonal (set `[listeners.tls]`).
    pub protocol: String,
    pub listen: String,
    #[serde(default)]
    pub tls: Option<TlsFiles>,
    #[serde(default)]
    pub sniff: SniffConfig,
}

impl Listener {
    fn validate(&self) -> anyhow::Result<()> {
        self.sniff
            .validate(&format!("listener {}", self.name.trim()))?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SniffMode {
    #[default]
    Observe,
    Route,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SniffConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: SniffMode,
    #[serde(default = "default_sniff_max_bytes")]
    pub max_bytes: usize,
    #[serde(default = "default_sniff_timeout_ms")]
    pub timeout_ms: u64,
}

impl Default for SniffConfig {
    fn default() -> Self {
        SniffConfig {
            enabled: false,
            mode: SniffMode::Observe,
            max_bytes: default_sniff_max_bytes(),
            timeout_ms: default_sniff_timeout_ms(),
        }
    }
}

impl SniffConfig {
    fn validate(&self, owner: &str) -> anyhow::Result<()> {
        anyhow::ensure!(
            (1..=crate::sniff::HARD_MAX_SNIFF_BYTES).contains(&self.max_bytes),
            "{owner} sniff.max_bytes must be in 1..={}, got {}",
            crate::sniff::HARD_MAX_SNIFF_BYTES,
            self.max_bytes
        );
        anyhow::ensure!(
            (1..=5_000).contains(&self.timeout_ms),
            "{owner} sniff.timeout_ms must be in 1..=5000, got {}",
            self.timeout_ms
        );
        Ok(())
    }

    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.timeout_ms)
    }
}

fn default_sniff_max_bytes() -> usize {
    crate::sniff::DEFAULT_MAX_SNIFF_BYTES
}

fn default_sniff_timeout_ms() -> u64 {
    500
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsFiles {
    pub cert: String,
    pub key: String,
    /// Additional certificates selected by the outer TLS ClientHello SNI.
    /// The primary cert/key above remains the fallback for missing or unknown SNI.
    #[serde(default)]
    pub certificates: Vec<SniCertificate>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SniCertificate {
    /// Exact DNS names that select this certificate. Each name is checked
    /// against the leaf certificate when the listener binds.
    pub server_names: Vec<String>,
    pub cert: String,
    pub key: String,
}

/// A TUIC v5 front-end listener. QUIC mandates TLS 1.3, so cert/key are
/// required; auth uses per-user `frontends.tuic` (uuid + password) from the snapshot.
#[derive(Debug, Clone, Deserialize)]
pub struct TuicListener {
    pub name: String,
    /// UDP `ip:port` the QUIC endpoint binds to.
    pub listen: String,
    pub cert: String,
    pub key: String,
    /// ALPN protocols to present to clients (TUIC clients pin one).
    #[serde(default = "default_tuic_alpn")]
    pub alpn: Vec<String>,
    /// Optional fixed QUIC path MTU (max UDP-payload bytes), for a listener
    /// reached across an already-compressed outer tunnel. Range `[1200, 1500]`;
    /// unset keeps quinn's default PMTUD.
    #[serde(default)]
    pub initial_mtu: Option<u16>,
    #[serde(default)]
    pub sniff: SniffConfig,
}

fn default_tuic_alpn() -> Vec<String> {
    vec!["h3".to_string()]
}

impl TuicListener {
    /// Fail-closed validation for an entry: a half-configured listener (missing
    /// bind, cert, or key) must abort startup rather than serve insecurely.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.name.trim().is_empty(), "tuic listener needs a name");
        anyhow::ensure!(
            !self.listen.trim().is_empty(),
            "tuic listener {} needs a listen address",
            self.name
        );
        anyhow::ensure!(
            !self.cert.trim().is_empty() && !self.key.trim().is_empty(),
            "tuic listener {} requires cert and key (QUIC mandates TLS 1.3)",
            self.name
        );
        validate_initial_mtu("tuic listener initial_mtu", self.initial_mtu)?;
        self.sniff
            .validate(&format!("tuic listener {}", self.name.trim()))?;
        Ok(())
    }

    /// Map the file-format entry to the inbound runtime config.
    pub fn to_runtime(&self) -> crate::inbound::tuic::TuicListenerConfig {
        crate::inbound::tuic::TuicListenerConfig {
            name: self.name.clone(),
            listen: self.listen.clone(),
            cert: self.cert.clone(),
            key: self.key.clone(),
            alpn: self.alpn.clone(),
            initial_mtu: self.initial_mtu,
            sniff: self.sniff.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MqttConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub broker: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_mqtt_qos")]
    pub qos: u8,
    #[serde(default = "default_reply_topic_prefix")]
    pub reply_topic_prefix: String,
    #[serde(default)]
    pub topics: MqttTopics,
    #[serde(default)]
    pub tls: MqttTls,
    #[serde(default)]
    pub diagnostics: MqttDiagnostics,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MqttTopics {
    #[serde(default = "default_user_query_topic")]
    pub user_query: String,
    #[serde(default = "default_sync_command_topic")]
    pub sync_command: String,
    #[serde(default = "default_node_status_topic")]
    pub node_status: String,
    #[serde(default = "default_probe_trace_topic")]
    pub probe_trace: String,
    #[serde(default = "default_diagnostics_command_topic")]
    pub diagnostics_command: String,
}

/// Bounds for opt-in MQTT diagnostic sessions. All sessions are short-lived and
/// nothing is persisted; these knobs cap blast radius, not enable the feature.
#[derive(Debug, Clone, Deserialize)]
pub struct MqttDiagnostics {
    #[serde(default = "default_diag_default_ttl")]
    pub default_ttl_secs: u64,
    #[serde(default = "default_diag_max_ttl")]
    pub max_ttl_secs: u64,
    #[serde(default = "default_diag_max_sessions")]
    pub max_sessions: usize,
    #[serde(default = "default_diag_max_sessions_per_user")]
    pub max_sessions_per_user: usize,
    #[serde(default = "default_diag_channel_capacity")]
    pub channel_capacity: usize,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct MqttTls {
    #[serde(default)]
    pub enable: bool,
}

impl Default for MqttConfig {
    fn default() -> Self {
        MqttConfig {
            enable: false,
            broker: String::new(),
            client_id: String::new(),
            username: String::new(),
            password: String::new(),
            qos: default_mqtt_qos(),
            reply_topic_prefix: default_reply_topic_prefix(),
            topics: MqttTopics::default(),
            tls: MqttTls::default(),
            diagnostics: MqttDiagnostics::default(),
        }
    }
}

impl Default for MqttTopics {
    fn default() -> Self {
        MqttTopics {
            user_query: default_user_query_topic(),
            sync_command: default_sync_command_topic(),
            node_status: default_node_status_topic(),
            probe_trace: default_probe_trace_topic(),
            diagnostics_command: default_diagnostics_command_topic(),
        }
    }
}

impl Default for MqttDiagnostics {
    fn default() -> Self {
        MqttDiagnostics {
            default_ttl_secs: default_diag_default_ttl(),
            max_ttl_secs: default_diag_max_ttl(),
            max_sessions: default_diag_max_sessions(),
            max_sessions_per_user: default_diag_max_sessions_per_user(),
            channel_capacity: default_diag_channel_capacity(),
        }
    }
}

impl MqttDiagnostics {
    /// Normalise operator-supplied bounds into safe, non-zero values.
    pub fn effective_default_ttl_secs(&self) -> u64 {
        let max = self.effective_max_ttl_secs();
        self.default_ttl_secs.clamp(1, max)
    }

    pub fn effective_max_ttl_secs(&self) -> u64 {
        self.max_ttl_secs.max(1)
    }

    pub fn effective_max_sessions(&self) -> usize {
        self.max_sessions.max(1)
    }

    pub fn effective_max_sessions_per_user(&self) -> usize {
        self.max_sessions_per_user
            .clamp(1, self.effective_max_sessions())
    }

    pub fn effective_channel_capacity(&self) -> usize {
        self.channel_capacity.max(1)
    }

    /// Build the runtime [`crate::diagnostics::DiagnosticLimits`] from the
    /// normalised (clamped) configuration values.
    pub fn to_limits(&self) -> crate::diagnostics::DiagnosticLimits {
        crate::diagnostics::DiagnosticLimits {
            default_ttl: std::time::Duration::from_secs(self.effective_default_ttl_secs()),
            max_ttl: std::time::Duration::from_secs(self.effective_max_ttl_secs()),
            max_sessions: self.effective_max_sessions(),
            max_sessions_per_user: self.effective_max_sessions_per_user(),
        }
    }
}

impl MqttConfig {
    pub fn effective_client_id(&self, node_id: &str) -> String {
        if !self.client_id.trim().is_empty() {
            return self.client_id.trim().to_string();
        }
        if !node_id.trim().is_empty() {
            return format!("rove-{}", node_id.trim());
        }
        "rove".to_string()
    }

    pub fn effective_qos(&self) -> u8 {
        match self.qos {
            0..=2 => self.qos,
            _ => default_mqtt_qos(),
        }
    }

    pub fn effective_reply_topic_prefix(&self) -> String {
        let mut prefix = self.reply_topic_prefix.trim().to_string();
        if prefix.is_empty() {
            prefix = default_reply_topic_prefix();
        }
        if !prefix.ends_with('/') {
            prefix.push('/');
        }
        prefix
    }
}

#[derive(Debug, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        LogConfig {
            level: default_level(),
        }
    }
}

/// Structured JSONL access log: one line per completed connection (any
/// outcome), independent of `log.level` and MQTT. See `src/access_log.rs`.
#[derive(Debug, Clone, Deserialize)]
pub struct AccessLogConfig {
    #[serde(default = "default_access_log_enable")]
    pub enable: bool,
    #[serde(default = "default_access_log_dir")]
    pub dir: String,
    #[serde(default = "default_access_log_file_prefix")]
    pub file_prefix: String,
    #[serde(default = "default_access_log_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_access_log_channel_capacity")]
    pub channel_capacity: usize,
    #[serde(default)]
    pub syslog: SyslogConfig,
}

impl Default for AccessLogConfig {
    fn default() -> Self {
        AccessLogConfig {
            enable: default_access_log_enable(),
            dir: default_access_log_dir(),
            file_prefix: default_access_log_file_prefix(),
            retention_days: default_access_log_retention_days(),
            channel_capacity: default_access_log_channel_capacity(),
            syslog: SyslogConfig::default(),
        }
    }
}

/// Optional forwarding of the access log to a remote syslog collector (RFC
/// 3164 over UDP or TCP). Disabled by default: it requires an explicit
/// `address`, unlike the local file which is on by default.
#[derive(Debug, Clone, Deserialize)]
pub struct SyslogConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub address: String,
    #[serde(default = "default_syslog_protocol")]
    pub protocol: String,
    #[serde(default = "default_syslog_facility")]
    pub facility: String,
    #[serde(default = "default_syslog_tag")]
    pub tag: String,
}

impl Default for SyslogConfig {
    fn default() -> Self {
        SyslogConfig {
            enable: false,
            address: String::new(),
            protocol: default_syslog_protocol(),
            facility: default_syslog_facility(),
            tag: default_syslog_tag(),
        }
    }
}

/// Built-in read-only SNMP agent (see `src/snmp/`). Off by default; when
/// enabled at least one credential — a v2c community or a v3 user — must be
/// configured, plus a source allowlist that gates *all* SNMP traffic.
#[derive(Debug, Clone, Deserialize)]
pub struct SnmpConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default = "default_snmp_listen")]
    pub listen: String,
    /// v2c community. Empty string disables SNMPv2c entirely.
    #[serde(default)]
    pub community: String,
    /// Source-address allowlist applied before any parsing, for both v2c and
    /// v3. Defaults to loopback only: exposing SNMP beyond localhost must be
    /// an explicit decision.
    #[serde(default = "default_snmp_allow_cidrs")]
    pub allow_cidrs: Vec<String>,
    /// Where the SNMPv3 engine persists `snmpEngineBoots` across restarts.
    /// Only written when v3 users are configured.
    #[serde(default = "default_snmp_state_path")]
    pub state_path: String,
    #[serde(default)]
    pub v3_users: Vec<SnmpV3UserConfig>,
}

impl Default for SnmpConfig {
    fn default() -> Self {
        SnmpConfig {
            enable: false,
            listen: default_snmp_listen(),
            community: String::new(),
            allow_cidrs: default_snmp_allow_cidrs(),
            state_path: default_snmp_state_path(),
            v3_users: Vec::new(),
        }
    }
}

impl SnmpConfig {
    /// Validate an enabled SNMP configuration. Fail-closed: misconfiguration
    /// stops startup rather than silently running an unpollable or (worse)
    /// unexpectedly open agent.
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enable {
            return Ok(());
        }
        if self.community.is_empty() && self.v3_users.is_empty() {
            anyhow::bail!(
                "snmp.enable = true requires a v2c community or at least one [[snmp.v3_users]] entry"
            );
        }
        if self.allow_cidrs.is_empty() {
            anyhow::bail!("snmp.allow_cidrs must not be empty when SNMP is enabled");
        }
        for cidr in &self.allow_cidrs {
            cidr.parse::<ipnet::IpNet>()
                .map_err(|e| anyhow::anyhow!("snmp.allow_cidrs entry {cidr:?}: {e}"))?;
        }
        let mut seen = std::collections::HashSet::new();
        for user in &self.v3_users {
            user.validate()?;
            if !seen.insert(user.username.as_str()) {
                anyhow::bail!("duplicate snmp.v3_users username {:?}", user.username);
            }
        }
        if !self.v3_users.is_empty() && self.state_path.is_empty() {
            anyhow::bail!("snmp.state_path must be set when v3 users are configured");
        }
        Ok(())
    }
}

/// One SNMPv3 USM user. Authentication is mandatory (noAuthNoPriv polling is
/// not offered); privacy is optional but enforced once configured.
#[derive(Debug, Clone, Deserialize)]
pub struct SnmpV3UserConfig {
    pub username: String,
    /// `sha1` (HMAC-SHA1-96) or `sha256` (HMAC-SHA-256-192, RFC 7860).
    pub auth_protocol: String,
    pub auth_password: String,
    /// Optional: `aes128` (CFB128-AES-128, RFC 3826). DES is not supported.
    #[serde(default)]
    pub priv_protocol: String,
    #[serde(default)]
    pub priv_password: String,
}

impl SnmpV3UserConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.username.is_empty() {
            anyhow::bail!("snmp.v3_users entry with empty username");
        }
        if !matches!(self.auth_protocol.as_str(), "sha1" | "sha256") {
            anyhow::bail!(
                "snmp v3 user {:?}: auth_protocol must be \"sha1\" or \"sha256\", got {:?}",
                self.username,
                self.auth_protocol
            );
        }
        if self.auth_password.len() < 8 {
            anyhow::bail!(
                "snmp v3 user {:?}: auth_password must be at least 8 characters (RFC 3414)",
                self.username
            );
        }
        match self.priv_protocol.as_str() {
            "" => {
                if !self.priv_password.is_empty() {
                    anyhow::bail!(
                        "snmp v3 user {:?}: priv_password set without priv_protocol",
                        self.username
                    );
                }
            }
            "aes128" => {
                if self.priv_password.len() < 8 {
                    anyhow::bail!(
                        "snmp v3 user {:?}: priv_password must be at least 8 characters",
                        self.username
                    );
                }
            }
            other => {
                anyhow::bail!(
                    "snmp v3 user {:?}: priv_protocol must be \"aes128\" or unset, got {other:?} (DES is not supported)",
                    self.username
                );
            }
        }
        Ok(())
    }
}

fn default_poll() -> u64 {
    30
}
fn default_cache() -> String {
    "./data/snapshot.json".to_string()
}
fn default_health_listen() -> String {
    "127.0.0.1:9090".to_string()
}
fn default_control_plane_unreachable_secs() -> u64 {
    90
}
fn default_shutdown_grace_period_secs() -> u64 {
    30
}
fn default_level() -> String {
    "info".to_string()
}
fn default_mqtt_qos() -> u8 {
    1
}
fn default_reply_topic_prefix() -> String {
    "rove/replies/".to_string()
}
fn default_user_query_topic() -> String {
    "rove/user/query".to_string()
}
fn default_sync_command_topic() -> String {
    "rove/sync/command".to_string()
}
fn default_node_status_topic() -> String {
    "rove/node/status".to_string()
}
fn default_probe_trace_topic() -> String {
    "rove/probe/trace".to_string()
}
fn default_diagnostics_command_topic() -> String {
    "rove/diagnostics/command".to_string()
}
fn default_diag_default_ttl() -> u64 {
    30
}
fn default_diag_max_ttl() -> u64 {
    300
}
fn default_diag_max_sessions() -> usize {
    16
}
fn default_diag_max_sessions_per_user() -> usize {
    2
}
fn default_diag_channel_capacity() -> usize {
    256
}
fn default_access_log_enable() -> bool {
    true
}
fn default_access_log_dir() -> String {
    "./logs".to_string()
}
fn default_access_log_file_prefix() -> String {
    "access".to_string()
}
fn default_access_log_retention_days() -> u32 {
    7
}
fn default_access_log_channel_capacity() -> usize {
    8192
}
fn default_syslog_protocol() -> String {
    "udp".to_string()
}
fn default_syslog_facility() -> String {
    "local0".to_string()
}
fn default_syslog_tag() -> String {
    "rove".to_string()
}
fn default_snmp_listen() -> String {
    "0.0.0.0:161".to_string()
}
fn default_snmp_allow_cidrs() -> Vec<String> {
    vec!["127.0.0.1/32".to_string(), "::1/128".to_string()]
}
fn default_snmp_state_path() -> String {
    "./data/snmp-state.json".to_string()
}

/// Edge-side reverse-hop QUIC data plane (see `src/reverse/`). Off by default:
/// it opens a UDP QUIC listener and accepts authenticated hop registrations, so
/// enabling it is an explicit deployment decision. When enabled it requires a
/// certificate/key pair and at least one registration token.
#[derive(Debug, Clone, Deserialize)]
pub struct ReverseHopConfig {
    #[serde(default)]
    pub enable: bool,
    /// UDP `ip:port` the QUIC endpoint binds to.
    #[serde(default = "default_reverse_listen")]
    pub listen: String,
    /// PEM certificate / key the edge presents to hops (QUIC needs TLS 1.3).
    #[serde(default)]
    pub cert: String,
    #[serde(default)]
    pub key: String,
    /// Accepted registration tokens. Deployment-owned; use placeholders in
    /// examples. At least one non-empty token is required when enabled.
    #[serde(default)]
    pub tokens: Vec<String>,
    /// Duplicate `hop_id` policy: `reject` (default) or `replace`.
    #[serde(default = "default_reverse_duplicate")]
    pub duplicate: String,
    /// Per-hop concurrent-tunnel ceiling (also the QUIC bidi-stream cap).
    #[serde(default = "default_reverse_max_streams_per_hop")]
    pub max_streams_per_hop: u32,
    /// Seconds to wait for a hop to accept a tunnel before failing closed.
    #[serde(default = "default_reverse_open_timeout_secs")]
    pub open_timeout_secs: u64,
    /// Optional fixed QUIC path MTU (max UDP-payload bytes), for an edge that
    /// serves hops across an already-compressed outer tunnel. Range
    /// `[1200, 1500]`; unset keeps quinn's default PMTUD.
    #[serde(default)]
    pub initial_mtu: Option<u16>,
}

impl Default for ReverseHopConfig {
    fn default() -> Self {
        ReverseHopConfig {
            enable: false,
            listen: default_reverse_listen(),
            cert: String::new(),
            key: String::new(),
            tokens: Vec::new(),
            duplicate: default_reverse_duplicate(),
            max_streams_per_hop: default_reverse_max_streams_per_hop(),
            open_timeout_secs: default_reverse_open_timeout_secs(),
            initial_mtu: None,
        }
    }
}

/// QUIC path-MTU bounds (max UDP-payload bytes) shared by every `initial_mtu`
/// knob. The floor is quinn's mandatory minimum; the ceiling is a sane Ethernet
/// upper bound (the feature only ever *shrinks* the path for a small carrier).
pub const MIN_QUIC_MTU: u16 = 1200;
pub const MAX_QUIC_MTU: u16 = 1500;

/// Validate an optional QUIC `initial_mtu` against [`MIN_QUIC_MTU`]/[`MAX_QUIC_MTU`].
pub fn validate_initial_mtu(field: &str, mtu: Option<u16>) -> anyhow::Result<()> {
    if let Some(v) = mtu {
        anyhow::ensure!(
            (MIN_QUIC_MTU..=MAX_QUIC_MTU).contains(&v),
            "{field} {v} out of range [{MIN_QUIC_MTU}, {MAX_QUIC_MTU}]"
        );
    }
    Ok(())
}

/// Dedicated egress DNS. Off by default (`servers` empty) so Rove keeps using the
/// operating-system resolver. When one or more `servers` are set, every egress
/// hostname lookup is routed through them instead — useful when the host's
/// `/etc/resolv.conf` points at a polluted or split-horizon resolver but the
/// network also offers a clean one.
#[derive(Debug, Clone, Deserialize)]
pub struct DnsConfig {
    /// Upstream DNS servers as `ip` or `ip:port`. The default port depends on
    /// the transport: 53 for udp/tcp, 853 for tls (DoT), 443 for https (DoH).
    /// Empty means "use the system resolver".
    #[serde(default)]
    pub servers: Vec<String>,
    /// Transport to reach those servers: `udp` (default), `tcp`, `tls`/`dot`
    /// (DNS-over-TLS) or `https`/`doh` (DNS-over-HTTPS). The encrypted
    /// transports resist on-path DNS poisoning and require `tls_server_name`.
    #[serde(default = "default_dns_protocol")]
    pub protocol: String,
    /// Per-query timeout in milliseconds.
    #[serde(default = "default_dns_timeout_ms")]
    pub timeout_ms: u64,
    /// Query attempts per server before failing.
    #[serde(default = "default_dns_attempts")]
    pub attempts: usize,
    /// Prefer IPv4 answers (query A before AAAA). Most edge egress is IPv4-first.
    #[serde(default = "default_dns_ipv4_first")]
    pub ipv4_first: bool,
    /// In-memory answer cache size (records). `0` disables caching.
    #[serde(default = "default_dns_cache_size")]
    pub cache_size: u64,
    /// TLS server name for DoT/DoH: sent in SNI and verified against the server
    /// certificate. Required when `protocol` is tls/https. For a server that
    /// presents an IP-SAN certificate, set this to that IP.
    #[serde(default)]
    pub tls_server_name: String,
    /// DoH URL path. Empty uses the standard `/dns-query`. Ignored for DoT.
    #[serde(default)]
    pub doh_path: String,
    /// PEM CA bundle that signs the DNS server certificate. Empty trusts the
    /// Mozilla webpki roots (plus `Rove_EXTRA_CA_CERTS`). Point this at your
    /// private CA for a self-hosted anti-pollution resolver.
    #[serde(default)]
    pub tls_ca: String,
    /// Skip DNS server certificate verification (self-signed servers).
    /// Dangerous: disables the tamper protection that DoT/DoH exist to provide.
    #[serde(default)]
    pub tls_insecure: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            servers: Vec::new(),
            protocol: default_dns_protocol(),
            timeout_ms: default_dns_timeout_ms(),
            attempts: default_dns_attempts(),
            ipv4_first: default_dns_ipv4_first(),
            cache_size: default_dns_cache_size(),
            tls_server_name: String::new(),
            doh_path: String::new(),
            tls_ca: String::new(),
            tls_insecure: false,
        }
    }
}

impl DnsConfig {
    /// Parse and validate into runtime [`crate::resolver::DnsSettings`]. Fails
    /// closed on a malformed server address or unknown protocol so a typo never
    /// silently degrades to the system resolver.
    pub fn to_settings(&self) -> anyhow::Result<crate::resolver::DnsSettings> {
        use crate::resolver::DnsProtocol;
        use std::net::SocketAddr;

        let protocol = match self.protocol.trim().to_ascii_lowercase().as_str() {
            "udp" => DnsProtocol::Udp,
            "tcp" => DnsProtocol::Tcp,
            "tls" | "dot" => DnsProtocol::Tls,
            "https" | "doh" => DnsProtocol::Https,
            other => {
                anyhow::bail!(
                    "dns.protocol must be \"udp\", \"tcp\", \"tls\"/\"dot\" or \"https\"/\"doh\", got {other:?}"
                )
            }
        };

        // Bare IPs adopt the transport's well-known port.
        let default_port = match protocol {
            DnsProtocol::Udp | DnsProtocol::Tcp => 53,
            DnsProtocol::Tls => 853,
            DnsProtocol::Https => 443,
        };

        let mut servers = Vec::with_capacity(self.servers.len());
        for s in &self.servers {
            let s = s.trim();
            if s.is_empty() {
                continue;
            }
            // Accept a bare IP (default transport port) or a full ip:port.
            let addr: SocketAddr = if let Ok(ip) = s.parse::<std::net::IpAddr>() {
                SocketAddr::new(ip, default_port)
            } else {
                s.parse().map_err(|e| {
                    anyhow::anyhow!("dns.servers entry {s:?} is not an ip or ip:port: {e}")
                })?
            };
            servers.push(addr);
        }

        anyhow::ensure!(self.attempts >= 1, "dns.attempts must be >= 1");
        anyhow::ensure!(self.timeout_ms >= 1, "dns.timeout_ms must be >= 1");

        // Encrypted transports need a server name to verify the certificate
        // against; fail closed rather than silently skipping verification.
        let tls = match protocol {
            DnsProtocol::Tls | DnsProtocol::Https => {
                let server_name = self.tls_server_name.trim();
                anyhow::ensure!(
                    !server_name.is_empty(),
                    "dns.tls_server_name is required when dns.protocol is tls/https"
                );
                let doh_path = self.doh_path.trim();
                let ca_path = self.tls_ca.trim();
                Some(crate::resolver::DnsTlsSettings {
                    server_name: server_name.to_string(),
                    doh_path: (!doh_path.is_empty()).then(|| doh_path.to_string()),
                    ca_path: (!ca_path.is_empty()).then(|| ca_path.to_string()),
                    insecure: self.tls_insecure,
                })
            }
            DnsProtocol::Udp | DnsProtocol::Tcp => None,
        };

        Ok(crate::resolver::DnsSettings {
            servers,
            protocol,
            timeout: std::time::Duration::from_millis(self.timeout_ms),
            attempts: self.attempts,
            ipv4_first: self.ipv4_first,
            cache_size: self.cache_size,
            tls,
        })
    }
}

fn default_dns_protocol() -> String {
    "udp".to_string()
}
fn default_dns_timeout_ms() -> u64 {
    2000
}
fn default_dns_attempts() -> usize {
    2
}
fn default_dns_ipv4_first() -> bool {
    true
}
fn default_dns_cache_size() -> u64 {
    64
}

impl ReverseHopConfig {
    /// Validate an enabled reverse-hop configuration. Fail-closed so a
    /// half-configured listener never starts.
    pub fn validate(&self) -> anyhow::Result<()> {
        if !self.enable {
            return Ok(());
        }
        anyhow::ensure!(
            !self.listen.trim().is_empty(),
            "reverse_hop.listen must be set when reverse_hop.enable = true"
        );
        anyhow::ensure!(
            !self.cert.trim().is_empty() && !self.key.trim().is_empty(),
            "reverse_hop requires cert and key when enabled (QUIC mandates TLS 1.3)"
        );
        let non_empty_tokens = self.tokens.iter().filter(|t| !t.trim().is_empty()).count();
        anyhow::ensure!(
            non_empty_tokens > 0,
            "reverse_hop requires at least one non-empty token when enabled"
        );
        crate::reverse::edge::DuplicatePolicy::parse(&self.duplicate)?;
        anyhow::ensure!(
            self.max_streams_per_hop > 0,
            "reverse_hop.max_streams_per_hop must be greater than zero"
        );
        anyhow::ensure!(
            self.open_timeout_secs > 0,
            "reverse_hop.open_timeout_secs must be greater than zero"
        );
        validate_initial_mtu("reverse_hop.initial_mtu", self.initial_mtu)?;
        Ok(())
    }

    /// Build the runtime [`crate::reverse::ReverseListenerConfig`]. Assumes
    /// [`Self::validate`] has already passed.
    pub fn to_listener_config(
        &self,
        edge_id: &str,
    ) -> anyhow::Result<crate::reverse::ReverseListenerConfig> {
        let duplicate = crate::reverse::edge::DuplicatePolicy::parse(&self.duplicate)?;
        let tokens: Vec<String> = self
            .tokens
            .iter()
            .filter(|t| !t.trim().is_empty())
            .cloned()
            .collect();
        Ok(crate::reverse::ReverseListenerConfig {
            listen: self.listen.clone(),
            cert: self.cert.clone(),
            key: self.key.clone(),
            tokens,
            duplicate,
            max_streams_per_hop: self.max_streams_per_hop,
            open_timeout: std::time::Duration::from_secs(self.open_timeout_secs),
            edge_id: edge_id.to_string(),
            initial_mtu: self.initial_mtu,
        })
    }
}

fn default_reverse_listen() -> String {
    "0.0.0.0:9443".to_string()
}
fn default_reverse_duplicate() -> String {
    "reject".to_string()
}
fn default_reverse_max_streams_per_hop() -> u32 {
    256
}
fn default_reverse_open_timeout_secs() -> u64 {
    10
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Config> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read config {path}: {e}"))?;
        let cfg: Config =
            toml::from_str(&text).map_err(|e| anyhow::anyhow!("parse config {path}: {e}"))?;
        cfg.health.validate()?;
        cfg.shutdown.validate()?;
        cfg.snmp.validate()?;
        cfg.reverse_hop.validate()?;
        for listener in &cfg.listeners {
            listener.validate()?;
        }
        for ingress in &cfg.reverse_ingress {
            ingress.validate()?;
        }
        cfg.dns.to_settings()?;
        for t in &cfg.tuic_listeners {
            t.validate()?;
        }
        if let Some(ab) = &cfg.addrbook {
            ab.validate()?;
        }
        Ok(cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn listener_sniff_defaults_off_and_parses_observe_bounds() {
        let default_path = temp_path("sniff-default.toml");
        std::fs::write(
            &default_path,
            r#"
node_id = "edge-1"
[control_plane]
snapshot_url = "http://127.0.0.1/snapshot"
token = "test"
[[listeners]]
name = "http-in"
protocol = "http"
listen = "127.0.0.1:8080"
"#,
        )
        .unwrap();
        let default_cfg = Config::load(&default_path).unwrap();
        let sniff = &default_cfg.listeners[0].sniff;
        assert!(!sniff.enabled);
        assert_eq!(sniff.mode, SniffMode::Observe);
        assert_eq!(sniff.max_bytes, crate::sniff::DEFAULT_MAX_SNIFF_BYTES);
        assert_eq!(sniff.timeout_ms, 500);
        let _ = std::fs::remove_file(default_path);

        let enabled_path = temp_path("sniff-observe.toml");
        std::fs::write(
            &enabled_path,
            r#"
node_id = "edge-1"
[control_plane]
snapshot_url = "http://127.0.0.1/snapshot"
token = "test"
[[listeners]]
name = "socks-in"
protocol = "socks5"
listen = "127.0.0.1:1080"
[listeners.sniff]
enabled = true
mode = "observe"
max_bytes = 4096
timeout_ms = 250
"#,
        )
        .unwrap();
        let enabled_cfg = Config::load(&enabled_path).unwrap();
        let sniff = &enabled_cfg.listeners[0].sniff;
        assert!(sniff.enabled);
        assert_eq!(sniff.mode, SniffMode::Observe);
        assert_eq!(sniff.max_bytes, 4096);
        assert_eq!(sniff.timeout_ms, 250);
        let _ = std::fs::remove_file(enabled_path);
    }

    #[test]
    fn listener_sniff_rejects_invalid_limits_and_modes() {
        for (name, sniff, expected) in [
            (
                "zero-bytes",
                "enabled = true\nmax_bytes = 0",
                "sniff.max_bytes",
            ),
            (
                "too-many-bytes",
                "enabled = true\nmax_bytes = 65537",
                "sniff.max_bytes",
            ),
            (
                "zero-timeout",
                "enabled = true\ntimeout_ms = 0",
                "sniff.timeout_ms",
            ),
            (
                "long-timeout",
                "enabled = true\ntimeout_ms = 5001",
                "sniff.timeout_ms",
            ),
        ] {
            let path = temp_path(&format!("sniff-{name}.toml"));
            std::fs::write(
                &path,
                format!(
                    r#"
node_id = "edge-1"
[control_plane]
snapshot_url = "http://127.0.0.1/snapshot"
token = "test"
[[listeners]]
name = "http-in"
protocol = "http"
listen = "127.0.0.1:8080"
[listeners.sniff]
{sniff}
"#
                ),
            )
            .unwrap();

            let error = Config::load(&path).unwrap_err();
            assert!(error.to_string().contains(expected), "{name}: {error}");
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn listener_sniff_accepts_route_mode() {
        let path = temp_path("http-sniff-route.toml");
        std::fs::write(
            &path,
            r#"
node_id = "edge-1"
[control_plane]
snapshot_url = "http://127.0.0.1/snapshot"
token = "test"
[[listeners]]
name = "http-in"
protocol = "http"
listen = "127.0.0.1:8080"
[listeners.sniff]
enabled = true
mode = "route"
max_bytes = 4096
timeout_ms = 300
"#,
        )
        .unwrap();

        let config = Config::load(&path).unwrap();
        assert_eq!(config.listeners[0].sniff.mode, SniffMode::Route);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn tuic_listener_accepts_sniff_route_mode() {
        let path = temp_path("tuic-sniff-route.toml");
        std::fs::write(
            &path,
            r#"
node_id = "edge-1"
[control_plane]
snapshot_url = "http://127.0.0.1/snapshot"
token = "test"
[[tuic_listeners]]
name = "tuic-in"
listen = "127.0.0.1:8443"
cert = "server.crt"
key = "server.key"
[tuic_listeners.sniff]
enabled = true
mode = "route"
max_bytes = 4096
timeout_ms = 300
"#,
        )
        .unwrap();

        let config = Config::load(&path).unwrap();
        assert_eq!(config.tuic_listeners[0].sniff.mode, SniffMode::Route);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_applies_defaults_and_effective_mqtt_values() {
        let path = temp_path("minimal-config.toml");
        std::fs::write(
            &path,
            r#"
node_id = "edge-1"

[control_plane]
snapshot_url = "https://control.example.com/snapshot"
token = "NODE_TOKEN"
"#,
        )
        .unwrap();

        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.node_id, "edge-1");
        assert_eq!(cfg.control_plane.poll_interval_secs, 30);
        assert_eq!(cfg.control_plane.cache_path, "./data/snapshot.json");
        assert!(!cfg.health.enable);
        assert_eq!(cfg.health.listen, "127.0.0.1:9090");
        assert_eq!(cfg.health.control_plane_unreachable_secs, 90);
        assert_eq!(cfg.shutdown.grace_period_secs, 30);
        assert!(cfg.listeners.is_empty());
        assert!(!cfg.mqtt.enable);
        assert_eq!(cfg.mqtt.effective_client_id(&cfg.node_id), "rove-edge-1");
        assert_eq!(cfg.mqtt.effective_qos(), 1);
        assert_eq!(cfg.mqtt.effective_reply_topic_prefix(), "rove/replies/");
        assert_eq!(
            cfg.mqtt.topics.diagnostics_command,
            "rove/diagnostics/command"
        );
        assert_eq!(cfg.mqtt.diagnostics.effective_default_ttl_secs(), 30);
        assert_eq!(cfg.mqtt.diagnostics.effective_max_ttl_secs(), 300);
        assert_eq!(cfg.mqtt.diagnostics.effective_max_sessions(), 16);
        assert_eq!(cfg.mqtt.diagnostics.effective_max_sessions_per_user(), 2);
        assert_eq!(cfg.log.level, "info");
        assert!(cfg.access_log.enable);
        assert_eq!(cfg.access_log.dir, "./logs");
        assert_eq!(cfg.access_log.file_prefix, "access");
        assert_eq!(cfg.access_log.retention_days, 7);
        assert_eq!(cfg.access_log.channel_capacity, 8192);
        assert!(!cfg.access_log.syslog.enable);
        assert_eq!(cfg.access_log.syslog.protocol, "udp");
        assert_eq!(cfg.access_log.syslog.facility, "local0");
        assert_eq!(cfg.access_log.syslog.tag, "rove");
        assert!(!cfg.snmp.enable);
        assert_eq!(cfg.snmp.listen, "0.0.0.0:161");
        assert_eq!(cfg.snmp.community, "");
        assert_eq!(cfg.snmp.allow_cidrs, vec!["127.0.0.1/32", "::1/128"]);
        assert_eq!(cfg.snmp.state_path, "./data/snmp-state.json");
        assert!(cfg.snmp.v3_users.is_empty());

        // Reverse-hop is off by default and validates trivially.
        assert!(!cfg.reverse_hop.enable);
        assert_eq!(cfg.reverse_hop.listen, "0.0.0.0:9443");
        assert_eq!(cfg.reverse_hop.duplicate, "reject");
        assert_eq!(cfg.reverse_hop.max_streams_per_hop, 256);
        assert_eq!(cfg.reverse_hop.open_timeout_secs, 10);
        assert!(cfg.reverse_hop.validate().is_ok());
        assert!(cfg.reverse_ingress.is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_rejects_zero_health_and_shutdown_timeouts() {
        let health_path = temp_path("invalid-health-config.toml");
        std::fs::write(
            &health_path,
            r#"
node_id = "edge-1"
[control_plane]
snapshot_url = "https://control.example.com/snapshot"
token = "NODE_TOKEN"
[health]
enable = true
control_plane_unreachable_secs = 0
"#,
        )
        .unwrap();
        let health_err = Config::load(&health_path).unwrap_err();
        assert!(health_err
            .to_string()
            .contains("health.control_plane_unreachable_secs"));

        let shutdown_path = temp_path("invalid-shutdown-config.toml");
        std::fs::write(
            &shutdown_path,
            r#"
node_id = "edge-1"
[control_plane]
snapshot_url = "https://control.example.com/snapshot"
token = "NODE_TOKEN"
[shutdown]
grace_period_secs = 0
"#,
        )
        .unwrap();
        let shutdown_err = Config::load(&shutdown_path).unwrap_err();
        assert!(shutdown_err
            .to_string()
            .contains("shutdown.grace_period_secs"));

        let _ = std::fs::remove_file(health_path);
        let _ = std::fs::remove_file(shutdown_path);
    }

    #[test]
    fn reverse_hop_enabled_requires_cert_key_and_token() {
        let base = ReverseHopConfig {
            enable: true,
            cert: String::new(),
            key: String::new(),
            tokens: Vec::new(),
            ..ReverseHopConfig::default()
        };
        assert!(base.validate().is_err());

        let missing_token = ReverseHopConfig {
            enable: true,
            cert: "cert.pem".to_string(),
            key: "key.pem".to_string(),
            tokens: vec!["   ".to_string()],
            ..ReverseHopConfig::default()
        };
        assert!(missing_token.validate().is_err());

        let ok = ReverseHopConfig {
            enable: true,
            cert: "cert.pem".to_string(),
            key: "key.pem".to_string(),
            tokens: vec!["placeholder".to_string()],
            ..ReverseHopConfig::default()
        };
        ok.validate().expect("valid reverse config");
        let listener = ok.to_listener_config("edge-1").unwrap();
        assert_eq!(listener.edge_id, "edge-1");
        assert_eq!(listener.tokens, vec!["placeholder".to_string()]);
        assert_eq!(
            listener.duplicate,
            crate::reverse::edge::DuplicatePolicy::Reject
        );
    }

    #[test]
    fn reverse_hop_rejects_bad_duplicate_policy() {
        let cfg = ReverseHopConfig {
            enable: true,
            cert: "cert.pem".to_string(),
            key: "key.pem".to_string(),
            tokens: vec!["placeholder".to_string()],
            duplicate: "sometimes".to_string(),
            ..ReverseHopConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn example_config_file_parses_with_reverse_hop_section() {
        // Guards against drift between config.example.toml and the structs.
        let cfg = Config::load("config.example.toml").expect("example config parses");
        assert!(!cfg.reverse_hop.enable);
        assert_eq!(cfg.reverse_hop.listen, "0.0.0.0:9443");
    }

    #[test]
    fn load_accepts_full_snmp_config_and_rejects_invalid_ones() {
        let path = temp_path("snmp-config.toml");
        std::fs::write(
            &path,
            r#"
node_id = "edge-3"

[control_plane]
snapshot_url = "https://control.example.com/snapshot"
token = "NODE_TOKEN"

[snmp]
enable = true
listen = "0.0.0.0:1161"
community = "cacti-ro"
allow_cidrs = ["10.0.0.0/24", "127.0.0.1/32"]
state_path = "/var/lib/rove/snmp-state.json"

[[snmp.v3_users]]
username = "cacti"
auth_protocol = "sha256"
auth_password = "auth-secret-1"
priv_protocol = "aes128"
priv_password = "priv-secret-1"
"#,
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        assert!(cfg.snmp.enable);
        assert_eq!(cfg.snmp.listen, "0.0.0.0:1161");
        assert_eq!(cfg.snmp.community, "cacti-ro");
        assert_eq!(cfg.snmp.v3_users.len(), 1);
        assert_eq!(cfg.snmp.v3_users[0].username, "cacti");
        assert_eq!(cfg.snmp.v3_users[0].priv_protocol, "aes128");
        let _ = std::fs::remove_file(&path);

        // Enabled without any credential: rejected at load time.
        std::fs::write(
            &path,
            r#"
node_id = "edge-3"

[control_plane]
snapshot_url = "https://control.example.com/snapshot"
token = "NODE_TOKEN"

[snmp]
enable = true
"#,
        )
        .unwrap();
        let err = Config::load(&path).unwrap_err();
        assert!(err.to_string().contains("community"), "err: {err}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn snmp_validate_enforces_fail_closed_rules() {
        let valid_user = SnmpV3UserConfig {
            username: "cacti".into(),
            auth_protocol: "sha1".into(),
            auth_password: "12345678".into(),
            priv_protocol: String::new(),
            priv_password: String::new(),
        };

        // Disabled config never validates credentials.
        assert!(SnmpConfig::default().validate().is_ok());

        let mut cfg = SnmpConfig {
            enable: true,
            community: "public".into(),
            ..SnmpConfig::default()
        };
        assert!(cfg.validate().is_ok());

        cfg.allow_cidrs = vec!["not-a-cidr".into()];
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("allow_cidrs"));
        cfg.allow_cidrs = Vec::new();
        assert!(cfg.validate().is_err());
        cfg.allow_cidrs = default_snmp_allow_cidrs();

        // v3-only config requires a state path.
        cfg.community = String::new();
        cfg.v3_users = vec![valid_user.clone()];
        cfg.state_path = String::new();
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("state_path"));
        cfg.state_path = default_snmp_state_path();
        assert!(cfg.validate().is_ok());

        // Duplicate usernames rejected.
        cfg.v3_users = vec![valid_user.clone(), valid_user.clone()];
        assert!(cfg
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate"));

        // Per-user rules.
        let mut bad = valid_user.clone();
        bad.auth_protocol = "md5".into();
        assert!(bad
            .validate()
            .unwrap_err()
            .to_string()
            .contains("auth_protocol"));
        let mut bad = valid_user.clone();
        bad.auth_password = "short".into();
        assert!(bad
            .validate()
            .unwrap_err()
            .to_string()
            .contains("8 characters"));
        let mut bad = valid_user.clone();
        bad.priv_protocol = "des".into();
        assert!(bad.validate().unwrap_err().to_string().contains("DES"));
        let mut bad = valid_user.clone();
        bad.priv_protocol = "aes128".into();
        bad.priv_password = "short".into();
        assert!(bad.validate().is_err());
        let mut bad = valid_user;
        bad.priv_password = "orphan-priv-pass".into();
        assert!(bad
            .validate()
            .unwrap_err()
            .to_string()
            .contains("without priv_protocol"));
    }

    #[test]
    fn load_custom_listener_mqtt_and_log_settings() {
        let path = temp_path("full-config.toml");
        std::fs::write(
            &path,
            r#"
node_id = "edge-2"

[control_plane]
snapshot_url = "https://control.example.com/snapshot/"
token = "NODE_TOKEN"
poll_interval_secs = 5
cache_path = "/tmp/rove-snapshot.json"

[[listeners]]
name = "https-in"
protocol = "http"
listen = "127.0.0.1:8443"
[listeners.tls]
cert = "server.crt"
key = "server.key"

[mqtt]
enable = true
broker = "mqtt://mqtt.example.com"
client_id = "custom-client"
username = "mqtt-user"
password = "mqtt-pass"
qos = 9
reply_topic_prefix = "custom/replies"

[mqtt.topics]
user_query = "custom/user/query"
sync_command = "custom/sync"
node_status = "custom/status"
probe_trace = "custom/probe"
diagnostics_command = "custom/diagnostics"

[mqtt.diagnostics]
default_ttl_secs = 45
max_ttl_secs = 120
max_sessions = 3
max_sessions_per_user = 1
channel_capacity = 64

[mqtt.tls]
enable = true

[log]
level = "debug"

[access_log]
enable = false
dir = "/tmp/rove-access-logs"
file_prefix = "custom-access"
retention_days = 14
channel_capacity = 4096

[access_log.syslog]
enable = true
address = "127.0.0.1:5514"
protocol = "tcp"
facility = "local3"
tag = "rove-test"
"#,
        )
        .unwrap();

        let cfg = Config::load(&path).unwrap();

        assert_eq!(cfg.control_plane.poll_interval_secs, 5);
        assert_eq!(cfg.listeners.len(), 1);
        assert_eq!(cfg.listeners[0].name, "https-in");
        assert_eq!(cfg.listeners[0].tls.as_ref().unwrap().cert, "server.crt");
        assert!(cfg.mqtt.enable);
        assert_eq!(cfg.mqtt.effective_client_id(&cfg.node_id), "custom-client");
        assert_eq!(cfg.mqtt.effective_qos(), 1);
        assert_eq!(cfg.mqtt.effective_reply_topic_prefix(), "custom/replies/");
        assert_eq!(cfg.mqtt.topics.probe_trace, "custom/probe");
        assert_eq!(cfg.mqtt.topics.diagnostics_command, "custom/diagnostics");
        assert_eq!(cfg.mqtt.diagnostics.effective_default_ttl_secs(), 45);
        assert_eq!(cfg.mqtt.diagnostics.effective_max_ttl_secs(), 120);
        assert_eq!(cfg.mqtt.diagnostics.effective_max_sessions(), 3);
        assert_eq!(cfg.mqtt.diagnostics.effective_max_sessions_per_user(), 1);
        assert_eq!(cfg.mqtt.diagnostics.effective_channel_capacity(), 64);
        assert!(cfg.mqtt.tls.enable);
        assert_eq!(cfg.log.level, "debug");
        assert!(!cfg.access_log.enable);
        assert_eq!(cfg.access_log.dir, "/tmp/rove-access-logs");
        assert_eq!(cfg.access_log.file_prefix, "custom-access");
        assert_eq!(cfg.access_log.retention_days, 14);
        assert_eq!(cfg.access_log.channel_capacity, 4096);
        assert!(cfg.access_log.syslog.enable);
        assert_eq!(cfg.access_log.syslog.address, "127.0.0.1:5514");
        assert_eq!(cfg.access_log.syslog.protocol, "tcp");
        assert_eq!(cfg.access_log.syslog.facility, "local3");
        assert_eq!(cfg.access_log.syslog.tag, "rove-test");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn diagnostics_effective_values_clamp_zero_and_inverted_bounds() {
        let diag = MqttDiagnostics {
            default_ttl_secs: 0,
            max_ttl_secs: 0,
            max_sessions: 0,
            max_sessions_per_user: 0,
            channel_capacity: 0,
        };
        assert_eq!(diag.effective_max_ttl_secs(), 1);
        assert_eq!(diag.effective_default_ttl_secs(), 1);
        assert_eq!(diag.effective_max_sessions(), 1);
        assert_eq!(diag.effective_max_sessions_per_user(), 1);
        assert_eq!(diag.effective_channel_capacity(), 1);

        let diag = MqttDiagnostics {
            default_ttl_secs: 999,
            max_ttl_secs: 120,
            max_sessions: 4,
            max_sessions_per_user: 99,
            channel_capacity: 8,
        };
        // Default TTL is clamped down to the max, and per-user is clamped to global.
        assert_eq!(diag.effective_default_ttl_secs(), 120);
        assert_eq!(diag.effective_max_sessions_per_user(), 4);
    }

    #[test]
    fn load_reports_read_and_parse_errors() {
        let missing = Config::load("/definitely/missing/rove.toml").unwrap_err();
        assert!(missing.to_string().contains("read config"));

        let path = temp_path("bad-config.toml");
        std::fs::write(&path, "node_id = [").unwrap();

        let err = Config::load(&path).unwrap_err();
        assert!(err.to_string().contains("parse config"));

        let _ = std::fs::remove_file(path);
    }

    fn temp_path(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("rove-config-{nanos}-{name}"))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn dns_defaults_to_system_resolver() {
        let cfg = DnsConfig::default();
        let settings = cfg.to_settings().unwrap();
        assert!(settings.servers.is_empty());
        assert!(matches!(
            settings.protocol,
            crate::resolver::DnsProtocol::Udp
        ));
    }

    #[test]
    fn dns_parses_bare_ip_and_ip_port() {
        let cfg = DnsConfig {
            servers: vec!["1.1.1.1".to_string(), "8.8.8.8:5353".to_string()],
            protocol: "tcp".to_string(),
            ..DnsConfig::default()
        };
        let settings = cfg.to_settings().unwrap();
        assert_eq!(
            settings.servers,
            vec![
                "1.1.1.1:53".parse().unwrap(),
                "8.8.8.8:5353".parse().unwrap(),
            ]
        );
        assert!(matches!(
            settings.protocol,
            crate::resolver::DnsProtocol::Tcp
        ));
    }

    #[test]
    fn dns_rejects_bad_server_and_protocol() {
        let bad_addr = DnsConfig {
            servers: vec!["not an ip".to_string()],
            ..DnsConfig::default()
        };
        assert!(bad_addr.to_settings().is_err());

        let bad_proto = DnsConfig {
            servers: vec!["1.1.1.1".to_string()],
            protocol: "carrier-pigeon".to_string(),
            ..DnsConfig::default()
        };
        assert!(bad_proto.to_settings().is_err());
    }

    #[test]
    fn dns_dot_doh_ports_and_server_name() {
        // DoT: bare IP adopts port 853, requires a server name.
        let dot = DnsConfig {
            servers: vec!["1.1.1.1".to_string()],
            protocol: "dot".to_string(),
            tls_server_name: "cloudflare-dns.com".to_string(),
            ..DnsConfig::default()
        };
        let settings = dot.to_settings().unwrap();
        assert_eq!(settings.servers, vec!["1.1.1.1:853".parse().unwrap()]);
        assert!(matches!(
            settings.protocol,
            crate::resolver::DnsProtocol::Tls
        ));
        let tls = settings.tls.expect("DoT must carry tls settings");
        assert_eq!(tls.server_name, "cloudflare-dns.com");
        assert!(tls.doh_path.is_none());

        // DoH: bare IP adopts port 443, custom path + CA carried through.
        let doh = DnsConfig {
            servers: vec!["10.0.0.53".to_string()],
            protocol: "https".to_string(),
            tls_server_name: "dns.internal".to_string(),
            doh_path: "/resolve".to_string(),
            tls_ca: "/etc/rove/dns-ca.pem".to_string(),
            ..DnsConfig::default()
        };
        let settings = doh.to_settings().unwrap();
        assert_eq!(settings.servers, vec!["10.0.0.53:443".parse().unwrap()]);
        let tls = settings.tls.expect("DoH must carry tls settings");
        assert_eq!(tls.doh_path.as_deref(), Some("/resolve"));
        assert_eq!(tls.ca_path.as_deref(), Some("/etc/rove/dns-ca.pem"));
    }

    #[test]
    fn dns_encrypted_requires_server_name() {
        for proto in ["tls", "dot", "https", "doh"] {
            let cfg = DnsConfig {
                servers: vec!["1.1.1.1".to_string()],
                protocol: proto.to_string(),
                ..DnsConfig::default()
            };
            assert!(
                cfg.to_settings().is_err(),
                "{proto} without tls_server_name must fail closed"
            );
        }
    }

    #[test]
    fn load_parses_dns_section() {
        let path = temp_path("dns-config.toml");
        std::fs::write(
            &path,
            r#"
node_id = "edge-1"

[control_plane]
snapshot_url = "https://control.example.com/snapshot"
token = "NODE_TOKEN"

[dns]
servers = ["10.0.0.53", "10.0.0.54:5353"]
protocol = "tcp"
timeout_ms = 1500
ipv4_first = false
"#,
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.dns.servers.len(), 2);
        let settings = cfg.dns.to_settings().unwrap();
        assert_eq!(settings.servers.len(), 2);
        assert!(!settings.ipv4_first);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn initial_mtu_validation_enforces_bounds() {
        assert!(validate_initial_mtu("test", None).is_ok());
        assert!(validate_initial_mtu("test", Some(MIN_QUIC_MTU)).is_ok());
        assert!(validate_initial_mtu("test", Some(MAX_QUIC_MTU)).is_ok());
        assert!(validate_initial_mtu("test", Some(MIN_QUIC_MTU - 1)).is_err());
        assert!(validate_initial_mtu("test", Some(MAX_QUIC_MTU + 1)).is_err());
    }

    #[test]
    fn reverse_hop_rejects_out_of_range_initial_mtu() {
        let cfg = ReverseHopConfig {
            enable: true,
            cert: "c".to_string(),
            key: "k".to_string(),
            tokens: vec!["tok".to_string()],
            initial_mtu: Some(900),
            ..ReverseHopConfig::default()
        };
        assert!(cfg.validate().is_err());
    }
}
