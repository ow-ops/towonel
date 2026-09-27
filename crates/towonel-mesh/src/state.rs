use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use towonel_common::identity::load_or_generate_secret_key;

const KEY_FILE: &str = "device.key";
const ENROLLMENT_FILE: &str = "enrollment.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Enrollment {
    pub hub_url: String,
    pub tenant_id: String,
    pub device_id: String,
    pub name: String,
    pub ipv4: String,
    pub ipv6: String,
}

pub struct StateDir(PathBuf);

impl StateDir {
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        create_private_dir(&path)
            .with_context(|| format!("failed to create state dir {}", path.display()))?;
        Ok(Self(path))
    }

    /// `$XDG_STATE_HOME/towonel/mesh`, else `~/.local/state/towonel/mesh`,
    /// else `/var/lib/towonel/mesh` for services without a home.
    #[must_use]
    pub fn default_path() -> PathBuf {
        if let Some(dir) = std::env::var_os("XDG_STATE_HOME").filter(|d| !d.is_empty()) {
            return PathBuf::from(dir).join("towonel/mesh");
        }
        if let Some(home) = std::env::var_os("HOME").filter(|d| !d.is_empty()) {
            return PathBuf::from(home).join(".local/state/towonel/mesh");
        }
        PathBuf::from("/var/lib/towonel/mesh")
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn device_key(&self) -> anyhow::Result<iroh::SecretKey> {
        load_or_generate_secret_key(&self.0.join(KEY_FILE))
    }

    pub fn load_enrollment(&self) -> anyhow::Result<Option<Enrollment>> {
        let path = self.0.join(ENROLLMENT_FILE);
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .with_context(|| format!("corrupt {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("failed to read {}", path.display())),
        }
    }

    pub fn save_enrollment(&self, enrollment: &Enrollment) -> anyhow::Result<()> {
        let path = self.0.join(ENROLLMENT_FILE);
        let tmp = self.0.join(format!("{ENROLLMENT_FILE}.tmp"));
        std::fs::write(&tmp, serde_json::to_vec_pretty(enrollment)?)?;
        std::fs::rename(&tmp, &path).with_context(|| format!("failed to write {}", path.display()))
    }
}

/// For unattended devices: reuse the enrollment in `state`, or enroll with
/// `auth_key` the first time. A device removed from the mesh stays removed.
pub async fn join_unattended(
    state: &StateDir,
    hub_url: &str,
    auth_key: Option<&str>,
    name: &str,
) -> anyhow::Result<Enrollment> {
    let client = crate::MeshClient::new(hub_url, state.device_key()?)?;
    let device = if state.load_enrollment()?.is_some() {
        let netmap = client.netmap().await.map_err(|e| {
            let hint = match hub_code(&e) {
                Some("unauthorized") => format!(
                    "this device was removed from the mesh; delete {} to add it again",
                    state.path().display()
                ),
                Some("key_expired") => "this device's key expired; enroll with a tagged auth \
                                        key, whose devices never expire"
                    .to_string(),
                _ => return e,
            };
            e.context(hint)
        })?;
        Enrollment {
            hub_url: hub_url.to_string(),
            tenant_id: netmap.tenant_id,
            device_id: netmap.this_device.device_id,
            name: netmap.this_device.name,
            ipv4: netmap.this_device.ipv4,
            ipv6: netmap.this_device.ipv6,
        }
    } else {
        let auth_key = auth_key.context("TOWONEL_MESH_AUTH_KEY is required to join the mesh")?;
        let enrolled = client.enroll(auth_key, name, std::env::consts::OS).await?;
        Enrollment {
            hub_url: hub_url.to_string(),
            tenant_id: enrolled.tenant_id,
            device_id: enrolled.device.device_id,
            name: enrolled.device.name,
            ipv4: enrolled.device.ipv4,
            ipv6: enrolled.device.ipv6,
        }
    };
    state.save_enrollment(&device)?;
    Ok(device)
}

fn hub_code(e: &anyhow::Error) -> Option<&str> {
    e.downcast_ref::<towonel_common::hub_error::HubApiError>()
        .map(|h| h.code.as_str())
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_state() -> StateDir {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("towonel-mesh-test-{}-{n}", std::process::id()));
        StateDir::open(dir).unwrap()
    }

    #[test]
    fn device_key_is_stable_across_loads() {
        let state = temp_state();
        let a = state.device_key().unwrap();
        let b = state.device_key().unwrap();
        assert_eq!(a.public(), b.public());
        std::fs::remove_dir_all(state.path()).unwrap();
    }

    #[test]
    fn enrollment_round_trips() {
        let state = temp_state();
        assert_eq!(state.load_enrollment().unwrap(), None);
        let e = Enrollment {
            hub_url: "https://hub.test".into(),
            tenant_id: "t".into(),
            device_id: "d".into(),
            name: "nas".into(),
            ipv4: "100.64.0.1".into(),
            ipv6: "fd00::1".into(),
        };
        state.save_enrollment(&e).unwrap();
        assert_eq!(state.load_enrollment().unwrap(), Some(e));
        std::fs::remove_dir_all(state.path()).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn state_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let state = temp_state();
        state.device_key().unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(state.path()), 0o700);
        assert_eq!(mode(&state.path().join(KEY_FILE)), 0o600);
        std::fs::remove_dir_all(state.path()).unwrap();
    }
}
