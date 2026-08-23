//! Minimal, credential-free HTTP liveness and readiness service.

use crate::config::HealthConfig;
use crate::engine::Engine;
use crate::sync::{SyncHealth, Syncer};
use crate::util::read_http_head;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;
use tracing::{info, warn};

pub struct RuntimeHealth {
    engine: Arc<Engine>,
    syncer: Arc<Syncer>,
    unreachable_after: Duration,
    data_plane_required: bool,
    active_listeners: AtomicUsize,
    draining: AtomicBool,
}

impl RuntimeHealth {
    pub fn new(engine: Arc<Engine>, syncer: Arc<Syncer>, unreachable_after: Duration) -> Arc<Self> {
        Self::new_with_data_plane(engine, syncer, unreachable_after, false)
    }

    pub fn new_with_data_plane(
        engine: Arc<Engine>,
        syncer: Arc<Syncer>,
        unreachable_after: Duration,
        data_plane_required: bool,
    ) -> Arc<Self> {
        Arc::new(RuntimeHealth {
            engine,
            syncer,
            unreachable_after,
            data_plane_required,
            active_listeners: AtomicUsize::new(0),
            draining: AtomicBool::new(false),
        })
    }

    pub fn data_plane_online(self: &Arc<Self>) -> DataPlaneLease {
        self.active_listeners.fetch_add(1, Ordering::AcqRel);
        DataPlaneLease {
            state: Arc::clone(self),
        }
    }

    pub fn begin_draining(&self) {
        self.draining.store(true, Ordering::Release);
    }

    pub fn snapshot(&self) -> HealthSnapshot {
        let data_plane = DataPlaneHealth {
            required: self.data_plane_required,
            active_listeners: self.active_listeners.load(Ordering::Acquire),
        };
        classify(
            self.engine.version(),
            self.engine.schema_version(),
            self.syncer.health(),
            unix_timestamp_secs(),
            self.unreachable_after,
            data_plane,
            self.draining.load(Ordering::Acquire),
        )
    }
}

pub struct DataPlaneLease {
    state: Arc<RuntimeHealth>,
}

impl Drop for DataPlaneLease {
    fn drop(&mut self) {
        let previous = self.state.active_listeners.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "data-plane listener count underflow");
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HealthSnapshot {
    pub status: &'static str,
    pub ready: bool,
    pub version: &'static str,
    pub snapshot: SnapshotHealth,
    pub control_plane: ControlPlaneHealth,
    pub data_plane: DataPlaneHealth,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotHealth {
    pub loaded: bool,
    pub version: u64,
    pub schema_version: u32,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ControlPlaneHealth {
    pub status: &'static str,
    pub consecutive_failures: u32,
    pub last_attempt_unix_secs: Option<u64>,
    pub last_success_unix_secs: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct DataPlaneHealth {
    pub required: bool,
    pub active_listeners: usize,
}

fn classify(
    snapshot_version: u64,
    schema_version: u32,
    sync: SyncHealth,
    now: u64,
    unreachable_after: Duration,
    data_plane: DataPlaneHealth,
    draining: bool,
) -> HealthSnapshot {
    let loaded = snapshot_version > 0;
    let unreachable = sync
        .failure_since_unix_secs
        .map(|since| now.saturating_sub(since) >= unreachable_after.as_secs())
        .unwrap_or(false);
    let data_plane_ready = !data_plane.required || data_plane.active_listeners > 0;
    let (status, ready) = if draining {
        ("draining", false)
    } else if !loaded {
        ("starting", false)
    } else if !data_plane_ready {
        ("unavailable", false)
    } else if unreachable {
        ("degraded", false)
    } else {
        ("ready", true)
    };
    let control_plane = if unreachable {
        "unreachable"
    } else if sync.last_success_unix_secs.is_some() {
        "ok"
    } else if sync.failure_since_unix_secs.is_some() {
        "retrying"
    } else {
        "unknown"
    };

    HealthSnapshot {
        status,
        ready,
        version: env!("CARGO_PKG_VERSION"),
        snapshot: SnapshotHealth {
            loaded,
            version: snapshot_version,
            schema_version,
        },
        control_plane: ControlPlaneHealth {
            status: control_plane,
            consecutive_failures: sync.consecutive_failures,
            last_attempt_unix_secs: sync.last_attempt_unix_secs,
            last_success_unix_secs: sync.last_success_unix_secs,
        },
        data_plane,
    }
}

pub struct HealthServer {
    listener: TcpListener,
    state: Arc<RuntimeHealth>,
}

impl HealthServer {
    pub async fn bind(cfg: &HealthConfig, state: Arc<RuntimeHealth>) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(&cfg.listen)
            .await
            .map_err(|e| anyhow::anyhow!("bind health endpoint {}: {e}", cfg.listen))?;
        info!(addr = %listener.local_addr()?, "health endpoint listening");
        Ok(HealthServer { listener, state })
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) -> anyhow::Result<()> {
        let HealthServer { listener, state } = self;
        let mut requests = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = crate::lifecycle::shutdown_requested(&mut shutdown) => break,
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(accepted) => accepted,
                        Err(e) => {
                            warn!(error = %e, "health endpoint accept failed");
                            continue;
                        }
                    };
                    let state = state.clone();
                    requests.spawn(async move {
                        if let Err(e) = serve_request(stream, state).await {
                            warn!(%peer, error = %e, "health request failed");
                        }
                    });
                }
                Some(_) = requests.join_next(), if !requests.is_empty() => {}
            }
        }
        drop(listener);
        while requests.join_next().await.is_some() {}
        info!("health endpoint stopped accepting requests");
        Ok(())
    }
}

async fn serve_request(mut stream: TcpStream, state: Arc<RuntimeHealth>) -> std::io::Result<()> {
    let head = read_http_head(&mut stream, 8 * 1024).await?;
    let request = String::from_utf8_lossy(&head);
    let mut parts = request.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let head_only = method.eq_ignore_ascii_case("HEAD");
    if !method.eq_ignore_ascii_case("GET") && !head_only {
        return respond(
            &mut stream,
            405,
            "Method Not Allowed",
            br#"{"status":"method_not_allowed"}"#,
            false,
        )
        .await;
    }

    match target.split('?').next().unwrap_or(target) {
        "/healthz" => {
            let body = serde_json::to_vec(&state.snapshot()).unwrap_or_else(|_| b"{}".to_vec());
            respond(&mut stream, 200, "OK", &body, head_only).await
        }
        "/readyz" => {
            let snapshot = state.snapshot();
            let status = if snapshot.ready { 200 } else { 503 };
            let reason = if snapshot.ready {
                "OK"
            } else {
                "Service Unavailable"
            };
            let body = serde_json::to_vec(&snapshot).unwrap_or_else(|_| b"{}".to_vec());
            respond(&mut stream, status, reason, &body, head_only).await
        }
        _ => {
            respond(
                &mut stream,
                404,
                "Not Found",
                br#"{"status":"not_found"}"#,
                head_only,
            )
            .await
        }
    }
}

async fn respond(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &[u8],
    head_only: bool,
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    if !head_only {
        stream.write_all(body).await?;
    }
    Ok(())
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ControlPlane;
    use crate::model::{RawSnapshot, Snapshot};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn syncer(engine: Arc<Engine>) -> Arc<Syncer> {
        Arc::new(
            Syncer::new(
                ControlPlane {
                    snapshot_url: "http://127.0.0.1:1/snapshot".to_string(),
                    token: "test-token".to_string(),
                    poll_interval_secs: 30,
                    cache_path: std::env::temp_dir()
                        .join("rove-health-missing-snapshot.json")
                        .to_string_lossy()
                        .into_owned(),
                },
                "health-test".to_string(),
                engine,
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn readiness_distinguishes_starting_ready_unreachable_and_draining() {
        let engine = Engine::new();
        let syncer = syncer(engine.clone());
        let health = RuntimeHealth::new(engine.clone(), syncer.clone(), Duration::ZERO);
        assert_eq!(health.snapshot().status, "starting");

        engine.replace(
            Snapshot::compile(
                RawSnapshot {
                    version: 7,
                    ..Default::default()
                },
                "health-test",
            )
            .unwrap(),
        );
        assert_eq!(health.snapshot().status, "ready");

        let outcome = syncer.sync_once("health-test").await;
        assert!(!outcome.success);
        let degraded = health.snapshot();
        assert_eq!(degraded.status, "degraded");
        assert_eq!(degraded.snapshot.version, 7);
        assert_eq!(degraded.control_plane.status, "unreachable");

        health.begin_draining();
        assert_eq!(health.snapshot().status, "draining");
    }

    #[test]
    fn readiness_tracks_required_data_plane_liveness() {
        let engine = Engine::new();
        let syncer = syncer(engine.clone());
        engine.replace(
            Snapshot::compile(
                RawSnapshot {
                    version: 7,
                    ..Default::default()
                },
                "health-test",
            )
            .unwrap(),
        );
        let health =
            RuntimeHealth::new_with_data_plane(engine, syncer, Duration::from_secs(90), true);

        let unavailable = health.snapshot();
        assert_eq!(unavailable.status, "unavailable");
        assert!(!unavailable.ready);
        assert_eq!(unavailable.data_plane.active_listeners, 0);

        let lease = health.data_plane_online();
        let ready = health.snapshot();
        assert_eq!(ready.status, "ready");
        assert_eq!(ready.data_plane.active_listeners, 1);

        drop(lease);
        assert_eq!(health.snapshot().status, "unavailable");
    }

    #[tokio::test]
    async fn endpoints_use_liveness_and_readiness_status_codes_without_secrets() {
        let engine = Engine::new();
        let syncer = syncer(engine.clone());
        let state = RuntimeHealth::new(engine, syncer, Duration::from_secs(90));
        let cfg = HealthConfig {
            enable: true,
            listen: "127.0.0.1:0".to_string(),
            control_plane_unreachable_secs: 90,
        };
        let server = HealthServer::bind(&cfg, state).await.unwrap();
        let addr = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(server.run(shutdown_rx));

        let healthz = request(addr, "/healthz").await;
        assert!(healthz.starts_with("HTTP/1.1 200"));
        assert!(healthz.contains("\"status\":\"starting\""));

        let readyz = request(addr, "/readyz").await;
        assert!(readyz.starts_with("HTTP/1.1 503"));
        assert!(!readyz.contains("test-token"));
        assert!(!readyz.contains("snapshot_url"));

        shutdown_tx.send(true).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn shutdown_closes_listener_before_slow_requests_finish() {
        let engine = Engine::new();
        let syncer = syncer(engine.clone());
        let state = RuntimeHealth::new(engine, syncer, Duration::from_secs(90));
        let cfg = HealthConfig {
            enable: true,
            listen: "127.0.0.1:0".to_string(),
            control_plane_unreachable_secs: 90,
        };
        let server = HealthServer::bind(&cfg, state).await.unwrap();
        let addr = server.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(server.run(shutdown_rx));

        let mut slow = TcpStream::connect(addr).await.unwrap();
        slow.write_all(b"GET /healthz HTTP/1.1\r\n").await.unwrap();
        shutdown_tx.send(true).unwrap();

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            if TcpStream::connect(addr).await.is_err() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "health listener remained open during drain"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        drop(slow);
        task.await.unwrap().unwrap();
    }

    async fn request(addr: SocketAddr, path: &str) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }
}
