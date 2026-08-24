//! Inbound (front-end) protocol layer. Adding a protocol = add a module here
//! and a match arm in `listener::dispatch` — the listener/TLS plumbing is shared.

pub mod http;
pub mod listener;
pub mod sni;
pub mod socks5;
pub mod socks5_udp;
pub mod tuic;

use crate::access_log::AccessLogger;
use crate::diagnostics::DiagnosticRegistry;
use crate::engine::Engine;
use crate::outbound::EgressContext;
use crate::stats::TrafficStats;
use crate::trace::ProbeTracer;
use std::sync::Arc;

/// Per-listener shared context handed to every protocol handler.
pub struct Ctx {
    pub engine: Arc<Engine>,
    pub listener: String,
    pub sniff: crate::config::SniffConfig,
    pub tracer: Option<Arc<ProbeTracer>>,
    pub diagnostics: Option<Arc<DiagnosticRegistry>>,
    pub access_log: Option<Arc<AccessLogger>>,
    /// Always-on traffic counters (listener + egress dimensions), feeding
    /// the periodic access-log gauge and the SNMP agent.
    pub stats: Arc<TrafficStats>,
    /// Runtime-owned optional egress capabilities. Missing capabilities fail
    /// closed when a policy selects them.
    pub egress: EgressContext,
}
