//! Kernel TUN device for desktop and server daemons.

use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::MeshNode;

pub const DEVICE_NAME: &str = "towonel0";
/// IPv6's minimum, so every peer path can carry it.
pub const MTU: u16 = 1280;

pub struct Tun {
    dev: Arc<AsyncDevice>,
}

impl Tun {
    /// Needs root or `CAP_NET_ADMIN`. Routes the whole overlay: the /10 on
    /// the IPv4 address, the tenant's /48 on the IPv6 one.
    pub fn create(node: &MeshNode) -> anyhow::Result<Self> {
        let me = node.netmap().borrow().this_device.clone();
        let dev = DeviceBuilder::new()
            .name(DEVICE_NAME)
            .ipv4(me.ipv4.as_str(), 10, None)
            .ipv6(me.ipv6.as_str(), 48)
            .mtu(MTU)
            .build_async()
            .context("failed to create the TUN device")?;
        Ok(Self { dev: Arc::new(dev) })
    }

    pub async fn run(self, node: MeshNode, cancel: CancellationToken) {
        let (to_mesh, mut from_mesh) = node.packet_channel();
        let dev = Arc::clone(&self.dev);
        let reader = async move {
            let mut buf = vec![0u8; usize::from(MTU) + 64];
            loop {
                match dev.recv(&mut buf).await {
                    Ok(n) => {
                        let packet = Bytes::copy_from_slice(buf.get(..n).unwrap_or_default());
                        if to_mesh.send(packet).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, "TUN read failed");
                        return;
                    }
                }
            }
        };
        let writer = async {
            while let Some(packet) = from_mesh.recv().await {
                if let Err(e) = self.dev.send(&packet).await {
                    debug!(error = %e, "TUN write failed");
                }
            }
        };
        tokio::select! {
            () = cancel.cancelled() => {}
            () = reader => {}
            () = writer => {}
        }
    }
}
