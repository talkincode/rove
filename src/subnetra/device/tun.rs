//! Kernel TUN device backend (Linux and macOS).

use std::io;
use std::net::Ipv4Addr;

use super::PacketIo;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub struct TunDevice {
    inner: tun_rs::AsyncDevice,
    name: String,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl TunDevice {
    /// Open a TUN device.
    ///
    /// If `manage` is true:
    /// - Creates or allocates the interface.
    /// - Assigns `overlay_ip` and subnet prefix length.
    /// - Sets MTU and enables the interface.
    /// - On macOS, configures overlay route association.
    ///
    /// If `manage` is false:
    /// - Attaches to an existing persistent TUN device (e.g. created beforehand
    ///   via `ip tuntap add dev rove0 mode tun user $USER`) without altering
    ///   addressing, MTU, or interface state.
    pub fn open(
        name: &str,
        overlay_ip: Ipv4Addr,
        prefix: u8,
        mtu: usize,
        manage: bool,
    ) -> anyhow::Result<Self> {
        use tun_rs::{DeviceBuilder, Layer};

        let dev = if manage {
            let mut builder = DeviceBuilder::new()
                .layer(Layer::L3)
                .name(name)
                .ipv4(overlay_ip, prefix, None)
                .mtu(mtu as u16)
                .enable(true);

            #[cfg(target_os = "macos")]
            {
                builder = builder.with(|b| {
                    b.associate_route(true);
                });
            }

            builder.build_async().map_err(|e| {
                anyhow::anyhow!(
                    "failed to create TUN device {name:?}: {e}; ensure CAP_NET_ADMIN or root"
                )
            })?
        } else {
            let builder = DeviceBuilder::new()
                .layer(Layer::L3)
                .name(name)
                .inherit_enable_state();

            builder.build_async().map_err(|e| {
                anyhow::anyhow!(
                    "failed to attach to persistent TUN device {name:?}: {e}; verify device exists (e.g. `ip tuntap add dev {name} mode tun user $USER`)"
                )
            })?
        };

        let actual_name = dev.name().unwrap_or_else(|_| name.to_string());
        Ok(Self {
            inner: dev,
            name: actual_name,
        })
    }

    /// Return the assigned interface name (e.g. `rove0` on Linux, `utunN` on macOS).
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl PacketIo for TunDevice {
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.recv(buf).await
    }

    async fn send(&self, pkt: &[u8]) -> io::Result<usize> {
        self.inner.send(pkt).await
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub struct TunDevice;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl TunDevice {
    pub fn open(
        _name: &str,
        _overlay_ip: Ipv4Addr,
        _prefix: u8,
        _mtu: usize,
        _manage: bool,
    ) -> anyhow::Result<Self> {
        anyhow::bail!("TUN device is unsupported on this platform");
    }

    pub fn name(&self) -> &str {
        ""
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl PacketIo for TunDevice {
    async fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TUN device is unsupported on this platform",
        ))
    }

    async fn send(&self, _pkt: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "TUN device is unsupported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_device_open_result_is_sane() {
        let res = TunDevice::open("rove0", Ipv4Addr::new(10, 0, 0, 2), 24, 1400, true);
        match res {
            Ok(dev) => {
                assert!(!dev.name().is_empty());
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(msg.contains("rove0") || msg.contains("TUN"));
            }
        }
    }
}
