//! The in-process decision engine: an atomically swappable snapshot plus the
//! two hot-path operations (authenticate, decide). No gRPC, no DB.

use crate::error::{ProxyError, Result};
use crate::model::{Decision, ResolvedDecision, Snapshot};
use arc_swap::ArcSwap;
use chrono::Local;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

pub struct AuthOk {
    pub up_rate: u64,
    pub down_rate: u64,
    pub max_connections: usize,
}

pub struct Engine {
    snap: ArcSwap<Snapshot>,
    active_connections: Arc<Mutex<HashMap<String, usize>>>,
}

impl Engine {
    pub fn new() -> Arc<Self> {
        Arc::new(Engine {
            snap: ArcSwap::from_pointee(Snapshot::empty()),
            active_connections: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Hot-swap the serving snapshot (called by the control-plane sync loop).
    pub fn replace(&self, snap: Snapshot) {
        self.snap.store(Arc::new(snap));
    }

    #[allow(dead_code)] // admin/inspection surface
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snap.load_full()
    }

    pub fn version(&self) -> u64 {
        self.snap.load().version
    }

    /// Wire-schema version of the serving snapshot (1 when it did not
    /// declare one). Surfaced over MQTT so the control plane can confirm a
    /// fleet has applied a v2 (chain-capable) snapshot before relying on it.
    pub fn schema_version(&self) -> u32 {
        self.snap.load().schema_version
    }

    /// Verify credentials and expiry. O(1) user lookup.
    pub fn authenticate(&self, username: &str, password: &str) -> Result<AuthOk> {
        let snap = self.snap.load();
        let user = snap.user(username).ok_or(ProxyError::AuthFailed)?;
        if !constant_time_eq(&user.password, password) {
            return Err(ProxyError::AuthFailed);
        }
        if let Some(exp) = user.expire {
            // Expired once the local date is past the expiry day.
            if Local::now().date_naive() > exp {
                return Err(ProxyError::Expired);
            }
        }
        Ok(AuthOk {
            up_rate: user.up_rate,
            down_rate: user.down_rate,
            max_connections: user.max_connections,
        })
    }

    /// Authenticate a TUIC front-end client. `uuid_bytes` is the 16-byte raw
    /// UUID from the `Authenticate` command; `token` is the 32-byte value the
    /// client derived from the TLS keying-material exporter. `exporter` computes
    /// the same value on the server side of the TLS session, using the raw UUID
    /// as the label and the user's TUIC password as context (TUIC v5). Returns
    /// the resolved username so the caller can drive policy, limits, and logs.
    /// Fails closed for unknown uuid, bad token, or expiry — never falls back to
    /// the login password and never reveals which check failed.
    pub fn authenticate_tuic(
        &self,
        uuid_bytes: &[u8],
        token: &[u8],
        exporter: impl Fn(&[u8], &[u8], usize) -> Option<Vec<u8>>,
    ) -> Result<(String, AuthOk)> {
        const TUIC_TOKEN_LEN: usize = 32;
        if token.len() != TUIC_TOKEN_LEN {
            return Err(ProxyError::AuthFailed);
        }
        let uuid = format_uuid(uuid_bytes).ok_or(ProxyError::AuthFailed)?;
        let snap = self.snap.load();
        let (username, user) = snap
            .frontend_user("tuic", &uuid)
            .ok_or(ProxyError::AuthFailed)?;
        let password = user
            .frontends
            .get("tuic")
            .and_then(|c| c.password.as_deref())
            .ok_or(ProxyError::AuthFailed)?;
        let expected = exporter(uuid_bytes, password.as_bytes(), TUIC_TOKEN_LEN)
            .ok_or(ProxyError::AuthFailed)?;
        if !constant_time_eq_bytes(&expected, token) {
            return Err(ProxyError::AuthFailed);
        }
        if let Some(exp) = user.expire {
            if Local::now().date_naive() > exp {
                return Err(ProxyError::Expired);
            }
        }
        Ok((
            username.to_string(),
            AuthOk {
                up_rate: user.up_rate,
                down_rate: user.down_rate,
                max_connections: user.max_connections,
            },
        ))
    }

    pub fn acquire_connection(
        &self,
        username: &str,
        max_connections: usize,
    ) -> Result<ConnectionPermit> {
        let mut active = self
            .active_connections
            .lock()
            .expect("active connection counter poisoned");
        let current = active.get(username).copied().unwrap_or(0);
        if max_connections > 0 && current >= max_connections {
            return Err(ProxyError::ConnectionLimitExceeded {
                current,
                max: max_connections,
            });
        }
        active.insert(username.to_string(), current + 1);
        Ok(ConnectionPermit {
            active_connections: self.active_connections.clone(),
            username: username.to_string(),
        })
    }

    /// Route decision for an authenticated user + target host.
    pub fn decide(&self, username: &str, host: &str) -> Decision {
        self.snap.load().decide(username, host)
    }

    pub fn decide_with_sniff(
        &self,
        username: &str,
        requested_host: &str,
        sniffed_host: Option<&str>,
    ) -> ResolvedDecision {
        self.snap
            .load()
            .decide_with_sniff(username, requested_host, sniffed_host)
    }
}

pub struct ConnectionPermit {
    active_connections: Arc<Mutex<HashMap<String, usize>>>,
    username: String,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let Ok(mut active) = self.active_connections.lock() else {
            return;
        };
        let Some(count) = active.get_mut(&self.username) else {
            return;
        };
        if *count > 1 {
            *count -= 1;
        } else {
            active.remove(&self.username);
        }
    }
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    constant_time_eq_bytes(left.as_bytes(), right.as_bytes())
}

/// Constant-time byte comparison used for both passwords and TUIC tokens: the
/// loop length and early behaviour do not depend on where the first mismatch is.
fn constant_time_eq_bytes(left: &[u8], right: &[u8]) -> bool {
    let len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for i in 0..len {
        let a = left.get(i).copied().unwrap_or(0);
        let b = right.get(i).copied().unwrap_or(0);
        diff |= usize::from(a ^ b);
    }
    diff == 0
}

/// Format 16 raw UUID bytes as the canonical lowercase `8-4-4-4-12` string used
/// as the snapshot index key. Returns `None` for any length other than 16.
fn format_uuid(b: &[u8]) -> Option<String> {
    if b.len() != 16 {
        return None;
    }
    let mut hex = String::with_capacity(32);
    for byte in b {
        hex.push_str(&format!("{byte:02x}"));
    }
    Some(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

#[cfg(test)]
mod tests {
    use super::constant_time_eq;
    use super::Engine;
    use crate::model::test_support::PolicySpec;
    use crate::model::{RawFrontendCred, RawSnapshot, RawUser, Snapshot};
    use std::collections::HashMap;

    #[test]
    fn constant_time_eq_matches_string_equality() {
        assert!(constant_time_eq("secret", "secret"));
        assert!(!constant_time_eq("secret", "Secret"));
        assert!(!constant_time_eq("secret", "secret1"));
        assert!(!constant_time_eq("secret", "sec"));
    }

    /// A deterministic stand-in for the TLS keying-material exporter: mixes the
    /// label (uuid) and context (password) so the same inputs reproduce the same
    /// token, exactly as a real TLS session would for a given handshake.
    fn fake_exporter(label: &[u8], ctx: &[u8], len: usize) -> Option<Vec<u8>> {
        let mut out = vec![0u8; len];
        for (i, b) in out.iter_mut().enumerate() {
            *b = label[i % label.len()] ^ ctx[i % ctx.len()] ^ (i as u8);
        }
        Some(out)
    }

    fn engine_with_tuic_user() -> std::sync::Arc<Engine> {
        let mut users = HashMap::new();
        users.insert(
            "alice".to_string(),
            RawUser {
                password: "login-pw".to_string(),
                expire: None,
                up_rate: 100,
                down_rate: 200,
                max_connections: 5,
                policy: "g".to_string(),
                frontends: HashMap::from([(
                    "tuic".to_string(),
                    RawFrontendCred {
                        uuid: Some("01010101-0101-0101-0101-010101010101".to_string()),
                        password: Some("tuic-pw".to_string()),
                    },
                )]),
            },
        );
        let (routing_policies, egresses) = PolicySpec {
            egress: None,
            default_egress: None,
            routed: vec![],
            blocked: vec![],
        }
        .into_tables("g");
        let raw = RawSnapshot {
            version: 1,
            users,
            routing_policies,
            egresses,
            ..Default::default()
        };
        let snap = Snapshot::compile(raw, "node-test").expect("compile");
        let engine = Engine::new();
        engine.replace(snap);
        engine
    }

    #[test]
    fn authenticate_tuic_accepts_correct_uuid_and_token() {
        let engine = engine_with_tuic_user();
        let uuid = [1u8; 16];
        let token = fake_exporter(&uuid, b"tuic-pw", 32).unwrap();
        let (username, ok) = engine
            .authenticate_tuic(&uuid, &token, fake_exporter)
            .expect("auth ok");
        assert_eq!(username, "alice");
        assert_eq!(ok.up_rate, 100);
        assert_eq!(ok.down_rate, 200);
        assert_eq!(ok.max_connections, 5);
    }

    #[test]
    fn authenticate_tuic_fails_closed_on_bad_inputs() {
        let engine = engine_with_tuic_user();
        let uuid = [1u8; 16];
        let good = fake_exporter(&uuid, b"tuic-pw", 32).unwrap();
        // Wrong token.
        assert!(engine
            .authenticate_tuic(&uuid, &[0u8; 32], fake_exporter)
            .is_err());
        // Unknown uuid.
        assert!(engine
            .authenticate_tuic(&[2u8; 16], &good, fake_exporter)
            .is_err());
        // Malformed uuid length.
        assert!(engine
            .authenticate_tuic(&[1u8; 8], &good, fake_exporter)
            .is_err());
        // Malformed token length.
        assert!(engine
            .authenticate_tuic(&uuid, &[0u8; 16], fake_exporter)
            .is_err());
    }
}
