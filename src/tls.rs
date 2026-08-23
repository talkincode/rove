//! rustls plumbing. Server acceptors give us `https` / `socks5-over-tls`
//! listeners by wrapping any protocol handler; the client config is for talking
//! to TLS upstreams (https proxy / socks5-over-tls).

use anyhow::Context;
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, ResolvesServerCertUsingSni};
use rustls::sign::CertifiedKey;
use std::collections::HashSet;
use std::sync::Arc;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::warn;

/// Install the process-wide crypto provider once. Safe to call repeatedly.
pub fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn load_certs(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path).with_context(|| format!("read cert {path}"))?;
    let certs = CertificateDer::pem_slice_iter(&data)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("parse certs {path}"))?;
    anyhow::ensure!(!certs.is_empty(), "no certificates in {path}");
    Ok(certs)
}

fn load_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path).with_context(|| format!("read key {path}"))?;
    match PrivateKeyDer::from_pem_slice(&data) {
        Ok(key) => Ok(key),
        Err(pem::Error::NoItemsFound) => anyhow::bail!("no private key in {path}"),
        Err(e) => Err(anyhow::Error::new(e)).with_context(|| format!("parse key {path}")),
    }
}

/// Load a PEM certificate chain from disk. Shared by the TCP TLS acceptors and
/// the reverse-hop QUIC server config.
pub(crate) fn load_cert_chain(path: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    load_certs(path)
}

/// Load a PEM private key from disk. Shared by the TCP TLS acceptors and the
/// reverse-hop QUIC server config.
pub(crate) fn load_private_key(path: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    load_key(path)
}

/// Root store trusting the Mozilla webpki set plus any `Rove_EXTRA_CA_CERTS`
/// PEM files. Shared by the TLS upstream connector and the reverse-hop QUIC
/// client (a hop verifying the edge's certificate).
pub(crate) fn root_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Err(e) = add_extra_roots_from_env(&mut roots) {
        warn!(error = %e, "failed to load extra TLS root certificates");
    }
    roots
}

pub fn server_acceptor(cert: &str, key: &str) -> anyhow::Result<TlsAcceptor> {
    let certs = load_certs(cert)?;
    let key = load_key(key)?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build server TLS config")?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub fn server_acceptor_with_sni(tls: &crate::config::TlsFiles) -> anyhow::Result<TlsAcceptor> {
    if tls.certificates.is_empty() {
        return server_acceptor(&tls.cert, &tls.key);
    }

    let fallback = Arc::new(load_certified_key(&tls.cert, &tls.key)?);
    let mut by_sni = ResolvesServerCertUsingSni::new();
    let mut server_names = HashSet::new();
    for certificate in &tls.certificates {
        anyhow::ensure!(
            !certificate.server_names.is_empty(),
            "SNI certificate {} requires at least one server name",
            certificate.cert
        );
        let certified_key = load_certified_key(&certificate.cert, &certificate.key)?;
        for server_name in &certificate.server_names {
            let server_name = server_name.trim();
            anyhow::ensure!(
                server_names.insert(server_name.to_ascii_lowercase()),
                "duplicate SNI server name {server_name:?}"
            );
            by_sni
                .add(server_name, certified_key.clone())
                .with_context(|| {
                    format!(
                        "map SNI {server_name:?} to certificate {}",
                        certificate.cert
                    )
                })?;
        }
    }

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SniCertificateResolver { by_sni, fallback }));
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_certified_key(cert: &str, key: &str) -> anyhow::Result<CertifiedKey> {
    CertifiedKey::from_der(
        load_certs(cert)?,
        load_key(key)?,
        &rustls::crypto::ring::default_provider(),
    )
    .with_context(|| format!("build certified key from {cert} and {key}"))
}

#[derive(Debug)]
struct SniCertificateResolver {
    by_sni: ResolvesServerCertUsingSni,
    fallback: Arc<CertifiedKey>,
}

impl ResolvesServerCert for SniCertificateResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.by_sni
            .resolve(client_hello)
            .or_else(|| Some(self.fallback.clone()))
    }
}

/// Client config trusting the Mozilla webpki root set, for TLS upstreams.
pub fn client_connector() -> TlsConnector {
    let roots = root_store();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

/// Build a rustls [`rustls::ClientConfig`] for encrypted egress DNS (DoT / DoH).
///
/// Trust model, highest precedence first:
/// * `insecure` — accept any server certificate (self-signed anti-pollution
///   boxes). A loud footgun: certificate verification is fully disabled.
/// * `ca_path` — trust *only* the CA chain in this PEM file, e.g. a private,
///   self-hosted anti-pollution resolver that runs its own CA.
/// * otherwise — the Mozilla webpki root set plus any `Rove_EXTRA_CA_CERTS`,
///   which is what a public DoT/DoH endpoint (1.1.1.1, 9.9.9.9, …) needs.
///
/// The process-wide ring crypto provider must already be installed
/// ([`init_crypto`]); both binaries do so before touching the resolver.
pub(crate) fn dns_client_config(
    ca_path: Option<&str>,
    insecure: bool,
) -> anyhow::Result<rustls::ClientConfig> {
    if insecure {
        return Ok(rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            .with_no_client_auth());
    }

    let roots = match ca_path {
        Some(path) => {
            let mut roots = rustls::RootCertStore::empty();
            for cert in load_certs(path)? {
                roots
                    .add(cert)
                    .with_context(|| format!("add dns CA cert {path}"))?;
            }
            anyhow::ensure!(!roots.is_empty(), "no certificates in dns CA {path}");
            roots
        }
        None => root_store(),
    };

    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

fn add_extra_roots_from_env(roots: &mut rustls::RootCertStore) -> anyhow::Result<()> {
    let Some(paths) = std::env::var_os("Rove_EXTRA_CA_CERTS") else {
        return Ok(());
    };

    for path in std::env::split_paths(&paths) {
        let path = path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("non-utf8 extra CA path"))?;
        for cert in load_certs(path)? {
            roots
                .add(cert)
                .with_context(|| format!("add extra CA cert {path}"))?;
        }
    }
    Ok(())
}

/// Rustls verifier that accepts any server certificate without checking
/// chain, hostname, or validity window. Used only for upstreams explicitly
/// marked `skip_cert_verify` in `RawUpstream` (self-signed / IP-only hop
/// certs) — never a blanket, implicit TLS bypass.
#[derive(Debug)]
pub(crate) struct AcceptAnyServerCert;

impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Client config that still encrypts the connection but skips all server
/// certificate verification (chain, hostname, validity). Only reached when a
/// group's upstream has `tls = true` and `skip_cert_verify = true` — an
/// explicit, per-upstream opt-in for self-signed or IP-only hop certs, never
/// a global default.
pub fn insecure_client_connector() -> TlsConnector {
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Self-signed localhost test certificate, also reused by
    /// `crate::inbound::listener`'s end-to-end TLS accept-loop test.
    pub(crate) const TEST_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUAhO4y5A+Ol+O93RC/xCs0+kTRkkwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYzMDE2NTMzMloXDTI2MDcw
MTE2NTMzMlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEA4czDicziIZKbupNwxPgbYa9jMAw1U9ypRAYUSlqcHG+5
shd/YkBxZ8fCZXDwr62GTVikRnyo99kzAeilgW22SgmlXzA8JKBpEzlN6YpZDhTh
yowwTtGts83z4mRWStXtHHzx1oomJTFpuwtvH6uNmvvVq8QGP9tRcPYXtJc80mZk
6qyFooKKxH8FinyqBpE0gLCnZoz9t/5CNTrZvkXt0kaZU9W5IwJGLw1ykktmzsC3
fl+vr24iHORg0HFI465tdFRN7fOhq9XMOdxxoEo9Fbe1J6AbwItkBMS6OJ8pMAMn
GOUqLDxvUxpICXUzvw6tRbfDjRjhRNAPJflJ5irmpQIDAQABo1MwUTAdBgNVHQ4E
FgQUTTYc3xMzdxugRyWHg9wY0SSWEXQwHwYDVR0jBBgwFoAUTTYc3xMzdxugRyWH
g9wY0SSWEXQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAvMhS
6sNjihQIHAMdZbQcxkBa1GsORK28flXAS1s41WI192gq6lCmP27mtig/vTzYEusY
qn0vMNhWaZXaAL1kUG5NMONrup5KA9N+vgdCClpGl9ffSrSMJciqvQZ/e3n/Eotn
fwJDlqASKGJ3ihQiEXfJx5oVpKA2VKSKxxlwKDmEPPUiwrbg3UH6iQlwFSed8Ypn
83niMaSI8VZf/Y2wtNldAOSW7K8jCvcfTCgO27qUepWAAnOl3Cy4NELtpZCTh6HH
ohVgaaT/RuT8aZbczsj7/5HH527DPpgJBmxKcOZ/e+jmdKtRsFnaoBziBr/CKwq4
IJsCUBadjBA5aZyBXg==
-----END CERTIFICATE-----"#;

    pub(crate) const TEST_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDhzMOJzOIhkpu6
k3DE+Bthr2MwDDVT3KlEBhRKWpwcb7myF39iQHFnx8JlcPCvrYZNWKRGfKj32TMB
6KWBbbZKCaVfMDwkoGkTOU3pilkOFOHKjDBO0a2zzfPiZFZK1e0cfPHWiiYlMWm7
C28fq42a+9WrxAY/21Fw9he0lzzSZmTqrIWigorEfwWKfKoGkTSAsKdmjP23/kI1
Otm+Re3SRplT1bkjAkYvDXKSS2bOwLd+X6+vbiIc5GDQcUjjrm10VE3t86Gr1cw5
3HGgSj0Vt7UnoBvAi2QExLo4nykwAycY5SosPG9TGkgJdTO/Dq1Ft8ONGOFE0A8l
+UnmKualAgMBAAECggEAGQ0luJkhkYX5fxaykTfRmeHiiEcid35ozSI7iBBLd6Ax
ov+WY2kw68mu2KBSI7uFxfkKqMNV38GaNiEAk75/VfGCBnCMi6e8YKSf70QpIzXP
4y/wgB4lPmigIULui/j2CI4YKqxDFSdJSrY3CvV2jXZZO2hRJS6I95ZmBOQunE0I
laMoBeZrhI1yJGFu+KRM2759jRVFl5JAqsf8JRJQk9PIe2rB3mSaCRKyKS1gnDIK
iiddOdcxf3hJSoKaqF3z5h+qK1OxZNiteKNL5fuvX+2KmN/7rQcwttLQqbXGdnsw
vNOyyfnB5VpvxnKy5gbfFNI3fEovHtT7ELWhTIKAIQKBgQDx7O9GO05XnlUoGOTs
R7Ccrd+sqMDMWIo9cA7AD63z9Cy83PuOoOuAvmfHKGvCTDUPrVJ90X6nnbeCdLxX
NwWWQMTKwhq/vZaZ6eCVSFSXCdvbRRYVYFv5xxbIaoFnguiXEGhd24sKiGPuw9GN
HHSZxxiu+Ef6s6q5Cz+3M/9ffQKBgQDu76o/QqRb4tivbrh4+yT8PHbe8Ro53RUE
oNB0n4sjKXgsalhFuAv7fw6MDCFHSxHGBL2lTtV7mZ/VEgT3fB70j/929EsSteAx
dNHonxhZ+YSoHu+v8FU85F9XpPo5qEHY8vW3lsYHxHf9fOZSx0wM9Ok36aUEPz9k
5x7C9jMcSQKBgCevxaTQz85B1Bhq1QsJy6g4QcwyNsaO88aWXmUVbWTqtngZDE9e
iKOrGJ0sPVk3ZTD4LuMi/dMDZXpKKidoiEsYvu/AHeE8ebswCb6TigTpAh8bWz8Q
eqYkCdHA3w+bAwrdDzHudQW6UCJ4DyVF+L7NUXhKlIxE8wm+Faq5JfiFAoGADsEw
Ay4LVj1A4jx1Gctwcj8NnCDJXM9hL+L6XGlJv0cdS6jZgJyn6MTk0hMhrvRcyZyb
VWzz0+kdrJurQNkiVDncLa1SQXqHuKYdHD9O0qeM4JDgfj3aFaOIm7HtXcgdINeI
AulFm08vlbCzzGLQOHCbQj+kWAnL0WBQTvvDFjkCgYEA7LA+RcGSZQjXw7PYm0Z2
410OnmEWlGBiF5h+jWGrWLpSEH632KdAryjXnw5L2QGnzc/7bpsINX0Kvpstut1m
4yU5RFQ1CphRafbztDMLnv5dO0gkqHWHvxE97MTBV/W9UZl6c52RB+5a8H+/QSbZ
v6K3aPttpZErFvOSVbzWaCY=
-----END PRIVATE KEY-----"#;

    #[test]
    fn server_acceptor_loads_valid_pem_pair() {
        let cert = temp_path("server.crt");
        let key = temp_path("server.key");
        std::fs::write(&cert, TEST_CERT).unwrap();
        std::fs::write(&key, TEST_KEY).unwrap();

        init_crypto();
        assert!(server_acceptor(&cert, &key).is_ok());

        let _ = std::fs::remove_file(cert);
        let _ = std::fs::remove_file(key);
    }

    #[test]
    fn cert_and_key_loaders_report_missing_or_empty_files() {
        let missing = load_certs("/definitely/missing/rove.crt").unwrap_err();
        assert!(missing.to_string().contains("read cert"));

        let cert = temp_path("empty.crt");
        let key = temp_path("empty.key");
        std::fs::write(&cert, "").unwrap();
        std::fs::write(&key, "").unwrap();

        assert!(load_certs(&cert)
            .unwrap_err()
            .to_string()
            .contains("no certificates"));
        assert!(load_key(&key)
            .unwrap_err()
            .to_string()
            .contains("no private key"));

        let _ = std::fs::remove_file(cert);
        let _ = std::fs::remove_file(key);
    }

    #[test]
    fn client_connector_accepts_extra_roots_env_when_valid() {
        let cert = temp_path("extra-root.crt");
        std::fs::write(&cert, TEST_CERT).unwrap();
        std::env::set_var("Rove_EXTRA_CA_CERTS", &cert);

        init_crypto();
        let _connector = client_connector();

        std::env::remove_var("Rove_EXTRA_CA_CERTS");
        let _ = std::fs::remove_file(cert);
    }

    fn temp_path(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("rove-tls-{nanos}-{name}"))
            .to_string_lossy()
            .into_owned()
    }
}
