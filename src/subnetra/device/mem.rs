//! In-memory packet device for unit and integration testing without root/TUN privileges.

use std::io;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

use super::PacketIo;

/// An in-memory device that implements [`PacketIo`].
///
/// Packets passed to [`PacketIo::send`] are written to `to_peer_tx`.
/// Packets received via [`PacketIo::recv`] are read from `from_peer_rx`.
pub struct MemDevice {
    to_peer_tx: mpsc::Sender<Vec<u8>>,
    from_peer_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

/// The test-facing peer handle connected to a [`MemDevice`].
pub struct MemDevicePeer {
    to_dev_tx: mpsc::Sender<Vec<u8>>,
    from_dev_rx: mpsc::Receiver<Vec<u8>>,
}

impl MemDevice {
    /// Create a connected `(MemDevice, MemDevicePeer)` pair.
    pub fn pair(capacity: usize) -> (Arc<Self>, MemDevicePeer) {
        let (to_peer_tx, from_dev_rx) = mpsc::channel(capacity);
        let (to_dev_tx, from_peer_rx) = mpsc::channel(capacity);

        let dev = Arc::new(Self {
            to_peer_tx,
            from_peer_rx: Mutex::new(from_peer_rx),
        });
        let peer = MemDevicePeer {
            to_dev_tx,
            from_dev_rx,
        };
        (dev, peer)
    }
}

impl PacketIo for MemDevice {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rx = self.from_peer_rx.lock().await;
        match rx.recv().await {
            Some(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "mem device closed",
            )),
        }
    }

    async fn send(&self, pkt: &[u8]) -> io::Result<usize> {
        self.to_peer_tx
            .send(pkt.to_vec())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "peer closed"))?;
        Ok(pkt.len())
    }
}

impl MemDevicePeer {
    /// Inject a packet into the device (as if read from a kernel TUN interface).
    pub async fn inject(&self, pkt: &[u8]) -> Result<(), mpsc::error::SendError<Vec<u8>>> {
        self.to_dev_tx.send(pkt.to_vec()).await
    }

    /// Try to inject a packet without waiting.
    pub fn try_inject(&self, pkt: &[u8]) -> Result<(), mpsc::error::TrySendError<Vec<u8>>> {
        self.to_dev_tx.try_send(pkt.to_vec())
    }

    /// Receive a packet emitted by the device (as if written to a kernel TUN interface).
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.from_dev_rx.recv().await
    }

    /// Try to receive a packet without waiting.
    pub fn try_recv(&mut self) -> Result<Vec<u8>, mpsc::error::TryRecvError> {
        self.from_dev_rx.try_recv()
    }
}
