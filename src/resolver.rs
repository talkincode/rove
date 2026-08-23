//! Egress DNS resolution.
//!
//! By default Rove resolves egress targets through the operating system resolver
//! (`getaddrinfo`, via [`tokio::net::lookup_host`]). Networks that run a
//! dedicated anti-pollution / split-horizon DNS server can instead point Rove at
//! it with the `[dns]` config block: [`init`] then builds a process-wide
//! [`hickory_resolver`] that queries those servers directly, bypassing the host's
//! `/etc/resolv.conf`.
//!
//! The resolver is a single [`OnceLock`]: set once at startup, read on every
//! egress connect. When it is left uninitialised (no `[dns]` servers configured,
//! or on the standalone `rove-hop` binary) every entry point falls back to the
//! system resolver, so behaviour is byte-for-byte unchanged unless an operator
//! opts in.
//!
//! Centralising resolution here also fixes a latent robustness gap: the call
//! sites used to take only the *first* resolved address, so a stale or
//! unreachable lead record produced a hard failure. [`tcp_connect`] now walks
//! every returned address in order until one connects.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::net::TcpStream;

use hickory_resolver::config::{
    ConnectionConfig, LookupIpStrategy, NameServerConfig, ProtocolConfig, ResolverConfig,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;

static RESOLVER: OnceLock<TokioResolver> = OnceLock::new();

/// Transport used to reach the configured DNS servers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsProtocol {
    /// Plain DNS over UDP (port 53 by default).
    Udp,
    /// Plain DNS over TCP (port 53 by default).
    Tcp,
    /// DNS-over-TLS / DoT (port 853 by default). Encrypted, tamper-resistant.
    Tls,
    /// DNS-over-HTTPS / DoH (port 443 by default). Encrypted, tamper-resistant.
    Https,
}

/// TLS parameters for the encrypted transports ([`DnsProtocol::Tls`] /
/// [`DnsProtocol::Https`]). Ignored for plain UDP/TCP.
#[derive(Debug, Clone)]
pub struct DnsTlsSettings {
    /// Name presented in SNI and verified against the server certificate. For a
    /// server whose cert carries an IP SAN this may be the IP as a string.
    pub server_name: String,
    /// DoH URL path. `None` uses the standard `/dns-query`. DoH only.
    pub doh_path: Option<String>,
    /// Path to a PEM CA bundle that signs the DNS server certificate. `None`
    /// trusts the Mozilla webpki roots (plus `Rove_EXTRA_CA_CERTS`).
    pub ca_path: Option<String>,
    /// Disable certificate verification entirely (self-signed servers). Unsafe.
    pub insecure: bool,
}

/// Resolved, validated DNS settings handed to [`init`].
#[derive(Debug, Clone)]
pub struct DnsSettings {
    /// Upstream DNS servers as `ip:port`. Empty means "use the system resolver".
    pub servers: Vec<SocketAddr>,
    /// Query transport for those servers.
    pub protocol: DnsProtocol,
    /// Per-query timeout.
    pub timeout: Duration,
    /// Query attempts before giving up on a server.
    pub attempts: usize,
    /// Prefer IPv4 answers (query A then AAAA). Most edge egress is IPv4-first;
    /// disable to query A and AAAA in parallel with AAAA ordered first.
    pub ipv4_first: bool,
    /// In-memory positive/negative cache size (records). `0` disables caching.
    pub cache_size: u64,
    /// TLS parameters, required for [`DnsProtocol::Tls`] / [`DnsProtocol::Https`]
    /// and `None` for the plaintext transports.
    pub tls: Option<DnsTlsSettings>,
}

/// Default DoH query path when the operator does not override it.
const DEFAULT_DOH_PATH: &str = "/dns-query";

/// Initialise the process-wide egress resolver.
///
/// With no configured servers this is a no-op: every entry point then uses the
/// system resolver. With servers present it builds a [`hickory_resolver`] that
/// queries exactly those servers and installs it as the process resolver. First
/// writer wins (there is only ever one egress resolver per process).
pub fn init(settings: &DnsSettings) -> anyhow::Result<()> {
    if settings.servers.is_empty() {
        return Ok(());
    }
    let resolver = build(settings)?;
    let _ = RESOLVER.set(resolver);
    Ok(())
}

/// Build (but do not install) a resolver from validated settings. Split out from
/// [`init`] so unit tests can exercise the UDP/TCP/DoT/DoH builders without
/// touching the process-global [`OnceLock`].
fn build(settings: &DnsSettings) -> anyhow::Result<TokioResolver> {
    let protocol = match settings.protocol {
        DnsProtocol::Udp => ProtocolConfig::Udp,
        DnsProtocol::Tcp => ProtocolConfig::Tcp,
        DnsProtocol::Tls => {
            let tls = settings
                .tls
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("DoT requires dns tls settings"))?;
            ProtocolConfig::Tls {
                server_name: Arc::from(tls.server_name.as_str()),
            }
        }
        DnsProtocol::Https => {
            let tls = settings
                .tls
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("DoH requires dns tls settings"))?;
            let path = tls.doh_path.as_deref().unwrap_or(DEFAULT_DOH_PATH);
            ProtocolConfig::Https {
                server_name: Arc::from(tls.server_name.as_str()),
                path: Arc::from(path),
            }
        }
    };

    let mut name_servers = Vec::with_capacity(settings.servers.len());
    for addr in &settings.servers {
        let mut connection = ConnectionConfig::new(protocol.clone());
        connection.port = addr.port();
        name_servers.push(NameServerConfig::new(addr.ip(), true, vec![connection]));
    }

    let config = ResolverConfig::from_parts(None, Vec::new(), name_servers);
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());

    // Encrypted transports need a rustls client config honouring the operator's
    // trust choice (custom CA / insecure / webpki default). Plaintext skips this.
    if let Some(tls) = &settings.tls {
        let client = crate::tls::dns_client_config(tls.ca_path.as_deref(), tls.insecure)?;
        builder = builder.with_tls_config(client);
    }

    {
        let opts = builder.options_mut();
        opts.timeout = settings.timeout;
        opts.attempts = settings.attempts;
        opts.cache_size = settings.cache_size;
        // Retry over TCP when a UDP answer is truncated — anti-pollution servers
        // often return large, EDNS-padded responses.
        opts.try_tcp_on_error = true;
        opts.ip_strategy = if settings.ipv4_first {
            LookupIpStrategy::Ipv4thenIpv6
        } else {
            LookupIpStrategy::Ipv4AndIpv6
        };
    }

    builder
        .build()
        .map_err(|e| anyhow::anyhow!("build dns resolver: {e}"))
}

/// True once a custom egress resolver has been installed.
pub fn is_custom() -> bool {
    RESOLVER.get().is_some()
}

/// Resolve `host:port` to one or more socket addresses.
///
/// A literal IP short-circuits DNS entirely. Otherwise the configured resolver
/// is used, falling back to the system resolver when none was installed. Returns
/// an error (never an empty vec) when nothing resolves.
pub async fn resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    match RESOLVER.get() {
        Some(resolver) => {
            let lookup = resolver
                .lookup_ip(host)
                .await
                .map_err(|e| io::Error::other(format!("resolve {host}: {e}")))?;
            let addrs: Vec<SocketAddr> =
                lookup.iter().map(|ip| SocketAddr::new(ip, port)).collect();
            if addrs.is_empty() {
                return Err(io::Error::other(format!("resolve {host}: no addresses")));
            }
            Ok(addrs)
        }
        None => {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
            if addrs.is_empty() {
                return Err(io::Error::other(format!("resolve {host}: no addresses")));
            }
            Ok(addrs)
        }
    }
}

/// Resolve a single address, preferring the first returned. Convenience for
/// call sites (UDP egress, edge dialing) that want one `SocketAddr`.
pub async fn resolve_one(host: &str, port: u16) -> io::Result<SocketAddr> {
    resolve(host, port)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| io::Error::other(format!("resolve {host}: no addresses")))
}

/// Why [`tcp_connect_detailed`] failed: lookup never produced an address, or
/// every resolved address refused/timed out the TCP handshake.
#[derive(Debug)]
pub enum TcpConnectError {
    Resolve(io::Error),
    Dial(io::Error),
}

impl std::fmt::Display for TcpConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpConnectError::Resolve(error) => write!(f, "{error}"),
            TcpConnectError::Dial(error) => write!(f, "{error}"),
        }
    }
}

impl From<TcpConnectError> for io::Error {
    fn from(error: TcpConnectError) -> Self {
        match error {
            TcpConnectError::Resolve(error) | TcpConnectError::Dial(error) => error,
        }
    }
}

/// Resolve `host:port` and TCP-connect, trying each resolved address in order
/// until one succeeds. `nodelay` is left to the caller.
pub async fn tcp_connect(host: &str, port: u16) -> io::Result<TcpStream> {
    tcp_connect_detailed(host, port).await.map_err(Into::into)
}

/// Same as [`tcp_connect`] but keeps DNS vs TCP-dial distinct for access-log
/// `failure_stage` classification.
pub async fn tcp_connect_detailed(host: &str, port: u16) -> Result<TcpStream, TcpConnectError> {
    let addrs = resolve(host, port)
        .await
        .map_err(TcpConnectError::Resolve)?;
    if addrs.is_empty() {
        return Err(TcpConnectError::Resolve(io::Error::other(format!(
            "resolve {host}: no addresses"
        ))));
    }
    let mut last_err: Option<io::Error> = None;
    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(TcpConnectError::Dial(last_err.unwrap_or_else(|| {
        io::Error::other(format!("no addresses for {host}:{port}"))
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn literal_ipv4_short_circuits_dns() {
        let addrs = resolve("93.184.216.34", 443).await.unwrap();
        assert_eq!(addrs, vec!["93.184.216.34:443".parse().unwrap()]);
    }

    #[tokio::test]
    async fn literal_ipv6_short_circuits_dns() {
        let addrs = resolve("::1", 80).await.unwrap();
        assert_eq!(addrs, vec!["[::1]:80".parse().unwrap()]);
    }

    #[test]
    fn empty_servers_leaves_system_resolver() {
        // init with no servers must not install a custom resolver.
        let settings = DnsSettings {
            servers: Vec::new(),
            protocol: DnsProtocol::Udp,
            timeout: Duration::from_secs(5),
            attempts: 2,
            ipv4_first: true,
            cache_size: 0,
            tls: None,
        };
        init(&settings).unwrap();
        assert!(!is_custom());
    }

    fn base_settings(protocol: DnsProtocol, tls: Option<DnsTlsSettings>) -> DnsSettings {
        DnsSettings {
            servers: vec!["1.1.1.1:853".parse().unwrap()],
            protocol,
            timeout: Duration::from_secs(5),
            attempts: 2,
            ipv4_first: true,
            cache_size: 0,
            tls,
        }
    }

    #[test]
    fn build_plaintext_transports() {
        // build() must not touch the process-global resolver, so these are safe
        // to run alongside empty_servers_leaves_system_resolver.
        assert!(build(&base_settings(DnsProtocol::Udp, None)).is_ok());
        assert!(build(&base_settings(DnsProtocol::Tcp, None)).is_ok());
    }

    #[test]
    fn build_encrypted_transports() {
        crate::tls::init_crypto();
        let dot = base_settings(
            DnsProtocol::Tls,
            Some(DnsTlsSettings {
                server_name: "cloudflare-dns.com".to_string(),
                doh_path: None,
                ca_path: None,
                insecure: false,
            }),
        );
        assert!(build(&dot).is_ok(), "DoT resolver should build");

        let doh = base_settings(
            DnsProtocol::Https,
            Some(DnsTlsSettings {
                server_name: "cloudflare-dns.com".to_string(),
                doh_path: Some("/dns-query".to_string()),
                ca_path: None,
                insecure: true,
            }),
        );
        assert!(build(&doh).is_ok(), "DoH resolver (insecure) should build");
    }

    #[test]
    fn build_encrypted_without_tls_settings_fails() {
        // Guards the invariant that config always attaches tls settings for the
        // encrypted transports.
        assert!(build(&base_settings(DnsProtocol::Tls, None)).is_err());
        assert!(build(&base_settings(DnsProtocol::Https, None)).is_err());
    }
}
