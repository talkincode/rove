//! Reverse-ingress data plane.
//!
//! A NAT-side Rove node dials a public relay over QUIC, leases explicitly
//! authorized TCP/UDP ports, and receives public ingress traffic over that
//! authenticated session. This is deliberately separate from `reverse`, whose
//! direction and policy role are egress.

pub mod connector;
pub mod frame;
pub mod metadata;
pub mod relay;

use std::sync::Arc;
use std::time::Duration;

/// Dedicated ALPN. Never negotiate the egress reverse-hop protocol on an
/// ingress connection: their commands and authorization boundaries differ.
pub const ALPN: &[u8] = b"rove-ingress/1";
pub const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
pub const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(45);
pub const DEFAULT_MAX_STREAMS: u32 = 1024;

fn transport_config(max_streams: u32, initial_mtu: Option<u16>) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    if let Ok(timeout) = quinn::IdleTimeout::try_from(MAX_IDLE_TIMEOUT) {
        transport.max_idle_timeout(Some(timeout));
    }
    transport.max_concurrent_bidi_streams(max_streams.into());
    transport.datagram_receive_buffer_size(Some(crate::reverse::DATAGRAM_RECV_BUFFER));
    transport.datagram_send_buffer_size(crate::reverse::DATAGRAM_SEND_BUFFER);
    crate::reverse::apply_initial_mtu(&mut transport, initial_mtu);
    transport
}

pub fn server_config(
    cert_path: &str,
    key_path: &str,
    max_streams: u32,
    initial_mtu: Option<u16>,
) -> anyhow::Result<quinn::ServerConfig> {
    let certs = crate::tls::load_cert_chain(cert_path)?;
    let key = crate::tls::load_private_key(key_path)?;
    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("reverse-ingress server TLS config: {e}"))?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(crypto)
        .map_err(|e| anyhow::anyhow!("reverse-ingress QUIC server crypto: {e}"))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    server.transport_config(Arc::new(transport_config(max_streams, initial_mtu)));
    Ok(server)
}

pub fn client_config(
    skip_cert_verify: bool,
    max_streams: u32,
    initial_mtu: Option<u16>,
) -> anyhow::Result<quinn::ClientConfig> {
    let mut crypto = if skip_cert_verify {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::AcceptAnyServerCert))
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .with_root_certificates(crate::tls::root_store())
            .with_no_client_auth()
    };
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| anyhow::anyhow!("reverse-ingress QUIC client crypto: {e}"))?;
    let mut client = quinn::ClientConfig::new(Arc::new(quic_crypto));
    client.transport_config(Arc::new(transport_config(max_streams, initial_mtu)));
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_configs_build() {
        crate::tls::init_crypto();
        let dir = std::env::temp_dir();
        let cert = dir.join(format!("ingress-{}.crt", std::process::id()));
        let key = dir.join(format!("ingress-{}.key", std::process::id()));
        std::fs::write(&cert, crate::tls::tests::TEST_CERT).unwrap();
        std::fs::write(&key, crate::tls::tests::TEST_KEY).unwrap();

        assert!(server_config(
            cert.to_str().unwrap(),
            key.to_str().unwrap(),
            64,
            Some(1452)
        )
        .is_ok());
        assert!(client_config(true, 64, Some(1452)).is_ok());

        let _ = std::fs::remove_file(cert);
        let _ = std::fs::remove_file(key);
    }
}
