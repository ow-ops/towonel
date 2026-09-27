//! Hub response shapes, as returned by `hub/api/mesh.rs`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub device_id: String,
    pub name: String,
    pub os: Option<String>,
    pub ipv4: String,
    pub ipv6: String,
    pub tags: Vec<String>,
    pub owner: Option<String>,
    pub key_expires_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub last_seen_at_ms: Option<i64>,
    #[serde(default)]
    pub endpoint: Option<iroh::EndpointAddr>,
    #[serde(default)]
    pub exit_node_advertised: bool,
    #[serde(default)]
    pub exit_node_approved: bool,
}

impl Device {
    #[must_use]
    pub const fn is_exit_node(&self) -> bool {
        self.exit_node_advertised && self.exit_node_approved
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cred {
    pub kid: u32,
    pub cred_b64: String,
    pub sig_b64: String,
    pub not_after_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enrolled {
    pub tenant_id: String,
    pub device: Device,
    pub cred: Cred,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCode {
    pub user_code: String,
    pub verification_url: String,
    pub expires_in_secs: u64,
    pub interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubKey {
    pub kid: u32,
    pub public_key_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Netmap {
    pub tenant_id: String,
    #[serde(rename = "self")]
    pub this_device: Device,
    pub peers: Vec<Device>,
    pub hub_keys: Vec<HubKey>,
    pub relay_url: Option<String>,
    #[serde(default)]
    pub policy: Option<crate::policy::Policy>,
    #[serde(default)]
    pub dns_domain: String,
}
