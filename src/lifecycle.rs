//! Shared process-shutdown signal helpers.

use tokio::sync::watch;

/// Wait until the process-wide shutdown flag becomes true.
///
/// A dropped sender is not treated as a shutdown request: compatibility
/// wrappers intentionally drop their private sender to mean "run forever".
pub async fn shutdown_requested(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        if shutdown.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}
