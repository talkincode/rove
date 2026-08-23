//! Process-local trusted ingress metadata.
//!
//! The connector and the local Rove listeners run in the same process. Before
//! the connector opens a loopback TCP/UDP socket it registers the socket's
//! source address here; the listener consumes or looks up that entry before
//! parsing TLS or application bytes. This preserves end-to-end TLS and avoids
//! exposing a spoofable PROXY-protocol port.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};

const MAX_PENDING_TCP: usize = 8192;
const MAX_UDP_FLOWS: usize = 65_536;

tokio::task_local! {
    static CURRENT: Option<IngressMetadata>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressMetadata {
    pub relay_instance_id: String,
    pub tunnel_session_id: String,
    pub lease_id: u64,
    pub listener_id: String,
    pub ingress_id: Option<String>,
    pub flow_id: Option<String>,
    pub client_addr: SocketAddr,
    pub relay_addr: SocketAddr,
}

pub async fn scope<F>(metadata: Option<IngressMetadata>, future: F) -> F::Output
where
    F: Future,
{
    CURRENT.scope(metadata, future).await
}

pub fn current() -> Option<IngressMetadata> {
    CURRENT.try_with(Clone::clone).ok().flatten()
}

fn tcp_entries() -> &'static Mutex<HashMap<SocketAddr, IngressMetadata>> {
    static ENTRIES: OnceLock<Mutex<HashMap<SocketAddr, IngressMetadata>>> = OnceLock::new();
    ENTRIES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn udp_entries() -> &'static Mutex<HashMap<SocketAddr, IngressMetadata>> {
    static ENTRIES: OnceLock<Mutex<HashMap<SocketAddr, IngressMetadata>>> = OnceLock::new();
    ENTRIES.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn register_tcp(source: SocketAddr, metadata: IngressMetadata) -> bool {
    insert_bounded(tcp_entries(), source, metadata, MAX_PENDING_TCP)
}

pub fn take_tcp(source: SocketAddr) -> Option<IngressMetadata> {
    tcp_entries()
        .lock()
        .expect("ingress tcp metadata poisoned")
        .remove(&source)
}

pub fn remove_tcp(source: SocketAddr) {
    tcp_entries()
        .lock()
        .expect("ingress tcp metadata poisoned")
        .remove(&source);
}

pub fn register_udp(source: SocketAddr, metadata: IngressMetadata) -> bool {
    insert_bounded(udp_entries(), source, metadata, MAX_UDP_FLOWS)
}

pub fn lookup_udp(source: SocketAddr) -> Option<IngressMetadata> {
    udp_entries()
        .lock()
        .expect("ingress udp metadata poisoned")
        .get(&source)
        .cloned()
}

pub fn remove_udp(source: SocketAddr) {
    udp_entries()
        .lock()
        .expect("ingress udp metadata poisoned")
        .remove(&source);
}

fn insert_bounded(
    entries: &Mutex<HashMap<SocketAddr, IngressMetadata>>,
    source: SocketAddr,
    metadata: IngressMetadata,
    limit: usize,
) -> bool {
    let mut entries = entries.lock().expect("ingress metadata poisoned");
    if !entries.contains_key(&source) && entries.len() >= limit {
        return false;
    }
    entries.insert(source, metadata);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(client_port: u16) -> IngressMetadata {
        IngressMetadata {
            relay_instance_id: "relay-1".into(),
            tunnel_session_id: "session-1".into(),
            lease_id: 7,
            listener_id: "https-in".into(),
            ingress_id: Some("00112233445566778899aabbccddeeff".into()),
            flow_id: None,
            client_addr: format!("203.0.113.9:{client_port}").parse().unwrap(),
            relay_addr: "198.51.100.4:9443".parse().unwrap(),
        }
    }

    #[test]
    fn tcp_metadata_is_consumed_once() {
        let source = "127.0.0.1:31001".parse().unwrap();
        assert!(register_tcp(source, metadata(50000)));
        assert_eq!(take_tcp(source), Some(metadata(50000)));
        assert_eq!(take_tcp(source), None);
    }

    #[test]
    fn udp_metadata_persists_until_removed() {
        let source = "127.0.0.1:31002".parse().unwrap();
        assert!(register_udp(source, metadata(50001)));
        assert_eq!(lookup_udp(source), Some(metadata(50001)));
        assert_eq!(lookup_udp(source), Some(metadata(50001)));
        remove_udp(source);
        assert_eq!(lookup_udp(source), None);
    }
}
