use thiserror::Error;

/// Proxy-level errors with enough structure for the inbound layer to map to a
/// protocol-specific rejection (HTTP status / SOCKS5 reply code).
#[allow(dead_code)] // AuthRequired/BadRequest are part of the mapping surface
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("authentication required")]
    AuthRequired,
    #[error("authentication failed")]
    AuthFailed,
    #[error("account expired")]
    Expired,
    #[error("connection limit exceeded: {current}/{max}")]
    ConnectionLimitExceeded { current: usize, max: usize },
    #[error("target blocked by policy: {0}")]
    Blocked(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("upstream connect failed: {0}")]
    Upstream(String),
    /// Egress hostname lookup failed before any TCP SYN. Failure stage: `dns`.
    #[error("dns resolve failed: {0}")]
    Dns(String),
    /// A resolved address was reached but TCP connect failed. Failure stage: `dial`.
    #[error("tcp dial failed: {0}")]
    Dial(String),
    /// Rove-terminated TLS handshake failed (upstream hop TLS, not inner CONNECT
    /// origin TLS). Failure stage: `tls`.
    #[error("tls handshake failed: {0}")]
    Tls(String),
    /// No authenticated reverse-hop session exists for the requested `hop_id`
    /// (or the reverse data plane is not configured on this node). Fails
    /// closed — never falls back to direct. Failure stage: `reverse_lookup`.
    #[error("reverse hop unavailable: {0}")]
    ReverseUnavailable(String),
    /// A reverse-hop session exists but opening/handshaking the per-tunnel
    /// QUIC stream failed (open, CONNECT write, reply read, or open timeout).
    /// Failure stage: `reverse_open`.
    #[error("reverse hop open failed: {0}")]
    ReverseOpen(String),
    /// The hop accepted the tunnel request but could not reach the final
    /// target (its local TCP dial failed, or it is at capacity). Scoped to
    /// this one stream, never poisons the QUIC connection. Failure stage:
    /// `hop_connect`.
    #[error("reverse hop target connect failed: {0}")]
    ReverseHopConnect(String),
    /// Every eligible member of a failover chain failed during tunnel
    /// establishment (or none was eligible for the requested transport).
    /// Fails closed — never falls back to direct. `attempts` is the number of
    /// establishment attempts actually made; `last` keeps the final member's
    /// error for diagnosis. Failure stage: `chain_exhausted`.
    #[error("chain {chain} exhausted after {attempts} attempts: {last}")]
    ChainExhausted {
        chain: String,
        attempts: u32,
        last: Box<ProxyError>,
    },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl ProxyError {
    /// Stable, secret-free failure-stage label for the access log. Distinct
    /// reverse stages let ops grep exactly where a reverse route broke. DNS /
    /// TCP / Rove-terminated TLS are split so "cannot open" is greppable;
    /// leftover `http`/`socks5` handshake refusals keep the historical
    /// `outbound` stage.
    pub fn failure_stage(&self) -> &'static str {
        match self {
            ProxyError::AuthRequired | ProxyError::AuthFailed | ProxyError::Expired => "auth",
            ProxyError::ConnectionLimitExceeded { .. } => "limit",
            ProxyError::Blocked(_) => "policy",
            ProxyError::BadRequest(_) => "parse",
            ProxyError::Dns(_) => "dns",
            ProxyError::Dial(_) => "dial",
            ProxyError::Tls(_) => "tls",
            ProxyError::Upstream(_) => "outbound",
            ProxyError::ReverseUnavailable(_) => "reverse_lookup",
            ProxyError::ReverseOpen(_) => "reverse_open",
            ProxyError::ReverseHopConnect(_) => "hop_connect",
            ProxyError::ChainExhausted { .. } => "chain_exhausted",
            ProxyError::Io(_) => "outbound",
        }
    }

    /// Number of chain establishment attempts behind this error, when it is a
    /// chain exhaustion — lets the access log report attempt counts even for
    /// fully failed connections.
    pub fn chain_attempts(&self) -> Option<u32> {
        match self {
            ProxyError::ChainExhausted { attempts, .. } => Some(*attempts),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, ProxyError>;

#[cfg(test)]
mod tests {
    use super::ProxyError;

    #[test]
    fn connect_failures_use_stable_stage_labels() {
        assert_eq!(
            ProxyError::Dns("resolve no-such-host.invalid: nxdomain".into()).failure_stage(),
            "dns"
        );
        assert_eq!(
            ProxyError::Dial("direct 127.0.0.1:9: connection refused".into()).failure_stage(),
            "dial"
        );
        assert_eq!(
            ProxyError::Tls("upstream tls 10.0.0.5:8443: corrupt message".into()).failure_stage(),
            "tls"
        );
        assert_eq!(
            ProxyError::Upstream("http upstream refused: HTTP/1.1 403".into()).failure_stage(),
            "outbound"
        );
        assert_eq!(
            ProxyError::ReverseHopConnect("target 1.2.3.4:443".into()).failure_stage(),
            "hop_connect"
        );
    }
}
