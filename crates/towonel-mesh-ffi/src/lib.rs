//! UniFFI bindings over `towonel-mesh` for the Android, iOS and desktop apps.
//!
//! The app owns the OS VPN interface: it feeds packets in with
//! [`Mesh::send_packet`] and receives packets for the OS on
//! [`MeshListener::on_packet`].

use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use towonel_common::hub_error::HubApiError;
use towonel_mesh::api::{Device as ApiDevice, Enrolled};
use towonel_mesh::client::is_transient;
use towonel_mesh::{Enrollment, MeshClient, MeshNode, NodeOptions, Poll, StateDir, Stopped};

uniffi::setup_scaffolding!();

const OS: &str = std::env::consts::OS;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MeshError {
    #[error("this device is not in a mesh yet")]
    NotEnrolled,
    #[error("this device's key expired; sign in again")]
    KeyExpired,
    #[error("this device was removed from the mesh")]
    Removed,
    #[error("the sign-in code expired before it was approved")]
    CodeExpired,
    #[error("{message}")]
    Other { message: String },
}

impl From<anyhow::Error> for MeshError {
    fn from(e: anyhow::Error) -> Self {
        match e.downcast_ref::<HubApiError>().map(|h| h.code.as_str()) {
            Some("key_expired") => Self::KeyExpired,
            Some("gone") => Self::CodeExpired,
            _ => Self::Other {
                message: format!("{e:#}"),
            },
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct EnrollmentInfo {
    pub hub_url: String,
    pub tenant_id: String,
    pub device_id: String,
    pub name: String,
    pub ipv4: String,
    pub ipv6: String,
}

impl From<Enrollment> for EnrollmentInfo {
    fn from(e: Enrollment) -> Self {
        Self {
            hub_url: e.hub_url,
            tenant_id: e.tenant_id,
            device_id: e.device_id,
            name: e.name,
            ipv4: e.ipv4,
            ipv6: e.ipv6,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct Device {
    pub device_id: String,
    pub name: String,
    pub ipv4: String,
    pub ipv6: String,
    pub os: Option<String>,
    pub tags: Vec<String>,
    pub last_seen_at_ms: Option<i64>,
    pub connected: bool,
    /// `None` until a connection has picked a path.
    pub relayed: Option<bool>,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct SignInCode {
    pub user_code: String,
    pub verification_url: String,
    pub expires_in_secs: u64,
    pub interval_secs: u64,
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum StopReason {
    Removed,
    KeyExpired,
}

/// Implemented by the app. Called from background threads.
#[uniffi::export(with_foreign)]
pub trait MeshListener: Send + Sync {
    /// An IP packet to write to the OS VPN interface.
    fn on_packet(&self, packet: Vec<u8>);
    fn on_peers_changed(&self, peers: Vec<Device>);
    /// The hub stopped this device; `start` again only after signing in.
    fn on_stopped(&self, reason: StopReason);
}

struct Running {
    node: MeshNode,
    to_mesh: mpsc::Sender<Bytes>,
}

#[derive(uniffi::Object)]
pub struct Mesh {
    rt: Option<Runtime>,
    state_dir: PathBuf,
    running: Arc<Mutex<Option<Running>>>,
    /// Hub and code expiry of the pending sign-in.
    sign_in: Arc<Mutex<Option<(String, tokio::time::Instant)>>>,
}

#[uniffi::export]
impl Mesh {
    /// `state_dir` holds the device key and enrollment; use app-private storage.
    #[uniffi::constructor]
    pub fn new(state_dir: String) -> Result<Arc<Self>, MeshError> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| MeshError::Other {
                message: format!("tokio runtime: {e}"),
            })?;
        let state_dir = PathBuf::from(state_dir);
        StateDir::open(state_dir.clone())?;
        Ok(Arc::new(Self {
            rt: Some(rt),
            state_dir,
            running: Arc::new(Mutex::new(None)),
            sign_in: Arc::new(Mutex::new(None)),
        }))
    }

    /// The saved enrollment, without contacting the hub.
    pub fn enrollment(&self) -> Result<Option<EnrollmentInfo>, MeshError> {
        let state = StateDir::open(self.state_dir.clone())?;
        Ok(state.load_enrollment()?.map(EnrollmentInfo::from))
    }

    pub async fn enroll_with_auth_key(
        &self,
        hub_url: String,
        auth_key: String,
        name: String,
    ) -> Result<EnrollmentInfo, MeshError> {
        let state_dir = self.state_dir.clone();
        self.on_rt(async move {
            let state = StateDir::open(state_dir)?;
            let client = MeshClient::new(&hub_url, state.device_key()?)?;
            let enrolled = client.enroll(&auth_key, &name, OS).await?;
            save(&state, &hub_url, &enrolled)
        })
        .await
    }

    /// Start browser sign-in. Show the URL (or a QR code) and the code, then
    /// call [`Mesh::wait_for_sign_in`]. Also renews an expired key.
    pub async fn request_sign_in(
        &self,
        hub_url: String,
        name: String,
    ) -> Result<SignInCode, MeshError> {
        let state_dir = self.state_dir.clone();
        let pending = Arc::clone(&self.sign_in);
        self.on_rt(async move {
            let state = StateDir::open(state_dir)?;
            let client = MeshClient::new(&hub_url, state.device_key()?)?;
            let code = client.request_device_code(&name, OS).await?;
            let expires = tokio::time::Instant::now() + Duration::from_secs(code.expires_in_secs);
            *lock(&pending) = Some((hub_url, expires));
            Ok(SignInCode {
                user_code: code.user_code,
                verification_url: code.verification_url,
                expires_in_secs: code.expires_in_secs,
                interval_secs: code.interval_secs,
            })
        })
        .await
    }

    /// Resolves once the code is approved in the browser.
    pub async fn wait_for_sign_in(&self) -> Result<EnrollmentInfo, MeshError> {
        let state_dir = self.state_dir.clone();
        let (hub_url, expires) = lock(&self.sign_in).clone().ok_or(MeshError::Other {
            message: "call request_sign_in first".to_string(),
        })?;
        self.on_rt(async move {
            let state = StateDir::open(state_dir)?;
            let client = MeshClient::new(&hub_url, state.device_key()?)?;
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                match client.poll_device_code().await {
                    Ok(Poll::Enrolled(enrolled)) => return save(&state, &hub_url, &enrolled),
                    Ok(Poll::Pending) => {}
                    // Phones drop connectivity; keep waiting until the code expires.
                    Err(e) if is_transient(&e) && tokio::time::Instant::now() < expires => {}
                    Err(e) => return Err(e.into()),
                }
            }
        })
        .await
    }

    /// Connect to the mesh. Packets for the OS go to `listener.on_packet`.
    pub async fn start(&self, listener: Arc<dyn MeshListener>) -> Result<(), MeshError> {
        let state_dir = self.state_dir.clone();
        let running = Arc::clone(&self.running);
        self.on_rt(async move {
            let state = StateDir::open(state_dir)?;
            let enrollment = state.load_enrollment()?.ok_or(MeshError::NotEnrolled)?;
            let key = state.device_key()?;
            let client = MeshClient::new(&enrollment.hub_url, key.clone())?;
            let node = MeshNode::start(client, key, NodeOptions::default()).await?;
            let (to_mesh, mut from_mesh) = node.packet_channel();

            let packets = Arc::clone(&listener);
            tokio::spawn(async move {
                while let Some(packet) = from_mesh.recv().await {
                    packets.on_packet(packet.to_vec());
                }
            });
            let (peers_node, peers) = (node.clone(), Arc::clone(&listener));
            tokio::spawn(async move {
                let mut netmap = peers_node.netmap();
                loop {
                    peers.on_peers_changed(devices(&peers_node));
                    if netmap.changed().await.is_err() {
                        return;
                    }
                }
            });
            let stop_node = node.clone();
            tokio::spawn(async move {
                match stop_node.stopped().await {
                    Some(Stopped::Revoked) => listener.on_stopped(StopReason::Removed),
                    Some(Stopped::KeyExpired) => listener.on_stopped(StopReason::KeyExpired),
                    None => {}
                }
            });

            let old = lock(&running).replace(Running { node, to_mesh });
            if let Some(old) = old {
                old.node.shutdown().await;
            }
            Ok(())
        })
        .await
    }

    /// An IP packet read from the OS VPN interface. Dropped when not running
    /// or when the queue is full, like any congested link.
    pub fn send_packet(&self, packet: Vec<u8>) {
        if let Some(running) = lock(&self.running).as_ref() {
            drop(running.to_mesh.try_send(Bytes::from(packet)));
        }
    }

    /// Configure the VPN interface's DNS with [`resolver`] for this domain
    /// only, e.g. `nas.<domain>`. `None` until started.
    pub fn dns_domain(&self) -> Option<String> {
        lock(&self.running)
            .as_ref()
            .map(|r| r.node.netmap().borrow().dns_domain.clone())
    }

    pub fn peers(&self) -> Vec<Device> {
        lock(&self.running)
            .as_ref()
            .map(|r| devices(&r.node))
            .unwrap_or_default()
    }

    pub async fn stop(&self) {
        let running = lock(&self.running).take();
        if let Some(running) = running {
            drop(
                self.on_rt(async move {
                    running.node.shutdown().await;
                    Ok(())
                })
                .await,
            );
        }
    }
}

impl Mesh {
    /// Run on our own runtime: the foreign side's executor isn't tokio.
    async fn on_rt<T: Send + 'static>(
        &self,
        fut: impl Future<Output = Result<T, MeshError>> + Send + 'static,
    ) -> Result<T, MeshError> {
        let rt = self.rt.as_ref().ok_or(MeshError::Other {
            message: "runtime is shut down".to_string(),
        })?;
        rt.spawn(fut).await.map_err(|e| MeshError::Other {
            message: format!("task failed: {e}"),
        })?
    }
}

impl Drop for Mesh {
    fn drop(&mut self) {
        // Dropping a runtime blocks, which panics if the last reference goes
        // away on an async thread.
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

fn save(state: &StateDir, hub_url: &str, enrolled: &Enrolled) -> Result<EnrollmentInfo, MeshError> {
    let enrollment = Enrollment {
        hub_url: hub_url.to_string(),
        tenant_id: enrolled.tenant_id.clone(),
        device_id: enrolled.device.device_id.clone(),
        name: enrolled.device.name.clone(),
        ipv4: enrolled.device.ipv4.clone(),
        ipv6: enrolled.device.ipv6.clone(),
    };
    state.save_enrollment(&enrollment)?;
    Ok(enrollment.into())
}

fn devices(node: &MeshNode) -> Vec<Device> {
    node.peers()
        .into_iter()
        .map(|p| device(p.device, p.connected, p.relayed))
        .collect()
}

fn device(d: ApiDevice, connected: bool, relayed: Option<bool>) -> Device {
    Device {
        device_id: d.device_id,
        name: d.name,
        ipv4: d.ipv4,
        ipv6: d.ipv6,
        os: d.os,
        tags: d.tags,
        last_seen_at_ms: d.last_seen_at_ms,
        connected,
        relayed,
    }
}

/// Mesh DNS server address, inside the routed overlay.
#[uniffi::export]
#[must_use]
pub fn resolver() -> String {
    towonel_mesh::dns::RESOLVER.to_string()
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}
