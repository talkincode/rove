//! rove-addrbook: a versioned, general-purpose address dataset for routing.
//!
//! The stable protocol surface is the `.rab` binary artifact
//! (`docs/addrbook-format.md`), built offline by `rove-abctl` from public
//! provider data and curated lists, released like software, and consumed here
//! as the *primary* address source. Control-plane snapshot rules reference its
//! hierarchical categories through the `book:<category>` rule scheme; the
//! snapshot's own explicit domain/IP rules remain the operator-curated
//! supplement and are always evaluated first.
//!
//! Fail-closed rules:
//! * a configured artifact that cannot be loaded at startup aborts startup;
//! * a `book:` rule that cannot be resolved rejects the whole snapshot;
//! * a corrupt artifact discovered at reload keeps the previous book serving.

pub mod book;
pub mod builder;
pub mod export;
pub mod format;
pub mod sources;

pub use book::{AddrBook, Selector};
pub use builder::BookBuilder;
pub use export::{control_plane_catalog, control_plane_catalog_json};

use anyhow::{Context, Result};
use arc_swap::ArcSwap;
use std::fs::{File, Metadata};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{info, warn};

const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactStamp {
    modified: SystemTime,
    len: u64,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl ArtifactStamp {
    fn from_metadata(metadata: &Metadata) -> Result<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        Ok(Self {
            modified: metadata.modified().context("read artifact mtime")?,
            len: metadata.len(),
            #[cfg(unix)]
            dev: metadata.dev(),
            #[cfg(unix)]
            ino: metadata.ino(),
        })
    }
}

fn read_stable_artifact(path: &Path) -> Result<(Vec<u8>, ArtifactStamp)> {
    for _ in 0..3 {
        let mut file =
            File::open(path).with_context(|| format!("open addrbook artifact {path:?} failed"))?;
        let before = ArtifactStamp::from_metadata(
            &file
                .metadata()
                .with_context(|| format!("stat open addrbook artifact {path:?} failed"))?,
        )?;
        if before.len > MAX_ARTIFACT_BYTES {
            anyhow::bail!("addrbook artifact {path:?} exceeds {MAX_ARTIFACT_BYTES} byte limit");
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_ARTIFACT_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read addrbook artifact {path:?} failed"))?;
        if bytes.len() as u64 > MAX_ARTIFACT_BYTES {
            anyhow::bail!("addrbook artifact {path:?} exceeds {MAX_ARTIFACT_BYTES} byte limit");
        }
        let after = ArtifactStamp::from_metadata(
            &file
                .metadata()
                .with_context(|| format!("restat open addrbook artifact {path:?} failed"))?,
        )?;
        let path_stamp = ArtifactStamp::from_metadata(
            &std::fs::metadata(path)
                .with_context(|| format!("restat addrbook path {path:?} failed"))?,
        )?;
        if before == after && after == path_stamp {
            return Ok((bytes, after));
        }
    }
    anyhow::bail!("addrbook artifact {path:?} changed repeatedly while being read")
}

/// Loads the artifact configured under `[addrbook]` and serves the current
/// `Arc<AddrBook>` to snapshot compilation. Reloading is driven by
/// `poll_file_changes` (mtime based) and goes through the syncer so that the
/// book swap and the snapshot recompile stay one atomic decision.
pub struct AddrBookService {
    path: PathBuf,
    current: ArcSwap<AddrBook>,
    last_stamp: std::sync::Mutex<Option<ArtifactStamp>>,
}

impl AddrBookService {
    /// Load the artifact at `path`; a missing or invalid file is a hard error
    /// (the operator asked for an address book, serving without it would let
    /// `book:` block rules silently fail open).
    pub fn load(path: &str) -> Result<Arc<Self>> {
        let (bytes, stamp) = read_stable_artifact(Path::new(path))?;
        let book =
            AddrBook::from_bytes(&bytes).with_context(|| format!("load addrbook {path:?}"))?;
        info!(
            path = %path,
            epoch = book.build_epoch(),
            categories = book.category_count(),
            checksum = %book.checksum_hex(),
            "addrbook loaded"
        );
        Ok(Arc::new(AddrBookService {
            path: PathBuf::from(path),
            current: ArcSwap::from_pointee(book),
            last_stamp: std::sync::Mutex::new(Some(stamp)),
        }))
    }

    pub fn current(&self) -> Arc<AddrBook> {
        self.current.load_full()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Attempt to read + decode the artifact from disk. Returns `Ok(None)`
    /// when the content is unchanged (same checksum as the serving book).
    pub fn try_read_new(&self) -> Result<(Option<Arc<AddrBook>>, ArtifactStamp)> {
        let (bytes, stamp) = read_stable_artifact(&self.path)?;
        let book = AddrBook::from_bytes(&bytes)
            .with_context(|| format!("decode addrbook {:?}", self.path))?;
        if book.checksum() == self.current.load().checksum() {
            return Ok((None, stamp));
        }
        Ok((Some(Arc::new(book)), stamp))
    }

    /// Install a validated replacement book (called by the syncer after the
    /// trial snapshot recompile succeeded).
    pub fn install(&self, book: Arc<AddrBook>) {
        info!(
            epoch = book.build_epoch(),
            categories = book.category_count(),
            checksum = %book.checksum_hex(),
            "addrbook hot-swapped"
        );
        self.current.store(book);
    }

    /// Return a changed file identity without acknowledging it. The poller only
    /// acknowledges after the candidate is unchanged or successfully adopted;
    /// a rejected candidate remains pending and is retried after policy changes.
    pub fn changed_stamp(&self) -> Result<Option<ArtifactStamp>> {
        let meta = std::fs::metadata(&self.path)
            .with_context(|| format!("stat addrbook artifact {:?} failed", self.path))?;
        let stamp = ArtifactStamp::from_metadata(&meta)
            .with_context(|| format!("read addrbook identity {:?} failed", self.path))?;
        let last = self.last_stamp.lock().expect("addrbook stamp lock");
        if *last == Some(stamp) {
            return Ok(None);
        }
        Ok(Some(stamp))
    }

    pub fn acknowledge_stamp(&self, stamp: ArtifactStamp) {
        *self.last_stamp.lock().expect("addrbook stamp lock") = Some(stamp);
    }
}

/// Background poll loop: watch the artifact file and, when it changes, ask the
/// syncer to atomically adopt the new book (trial-recompiling the last raw
/// snapshot against it). A bad artifact logs and keeps the old book.
pub async fn poll_file_changes(
    service: Arc<AddrBookService>,
    syncer: Arc<crate::sync::Syncer>,
    interval_secs: u64,
) {
    if interval_secs == 0 {
        return;
    }
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        match service.changed_stamp() {
            Ok(None) => continue,
            Ok(Some(_)) => {}
            Err(e) => {
                warn!(error = %e, "addrbook file check failed; keeping previous book");
                continue;
            }
        };
        match service.try_read_new() {
            Ok((None, stamp)) => service.acknowledge_stamp(stamp),
            Ok((Some(book), stamp)) => {
                if let Err(e) = syncer.adopt_addrbook(book).await {
                    warn!(error = %e, "new addrbook rejected; keeping previous book");
                } else {
                    service.acknowledge_stamp(stamp);
                }
            }
            Err(e) => {
                warn!(error = %e, "addrbook reload failed; keeping previous book");
            }
        }
    }
}
