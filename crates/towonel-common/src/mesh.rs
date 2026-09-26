//! Mesh (private network) credentials and overlay addressing.

use std::net::{Ipv4Addr, Ipv6Addr};

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Verifier};
use serde::{Deserialize, Serialize};

use crate::edge_cred::Kid;
use crate::identity::{PQ_SIGNATURE_LEN, PqPublicKey, TenantId};

pub const MESH_CRED_VERSION: u16 = 1;

/// ML-DSA context for `MeshCred` signatures. `EdgeCred` is signed with the
/// empty context, so the two can never verify as each other.
pub const MESH_CRED_SIGN_CONTEXT: &[u8] = b"towonel/mesh-cred/1";

/// `100.64.0.0/10`, shared by every tenant; tenants never see each other's
/// devices so overlapping addresses are fine.
const MESH_IPV4_BASE: u32 = u32::from_be_bytes([100, 64, 0, 0]);
/// Highest usable host number: excludes the network (0) and broadcast.
pub const MESH_IPV4_MAX_HOST: u32 = (1 << 22) - 2;

pub type DeviceId = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeshCred {
    pub version: u16,
    pub kid: Kid,
    #[serde(with = "serde_bytes")]
    pub device_id: DeviceId,
    #[serde(with = "crate::edge_cred::serde_tenant_id_bytes")]
    pub tenant_id: TenantId,
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
    pub tags: Vec<String>,
    /// Owning user; `None` for tagged devices.
    pub owner: Option<String>,
    pub not_after_ms: u64,
}

impl MeshCred {
    pub fn to_cbor(&self) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(256);
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> anyhow::Result<Self> {
        ciborium::from_reader(bytes).map_err(Into::into)
    }
}

#[must_use]
pub fn verify_mesh_cred(
    pq_pubkey: &PqPublicKey,
    cred_cbor: &[u8],
    sig: &[u8; PQ_SIGNATURE_LEN],
) -> bool {
    ml_dsa_65::PublicKey::try_from_bytes(*pq_pubkey.as_bytes())
        .is_ok_and(|pk| pk.verify(cred_cbor, sig, MESH_CRED_SIGN_CONTEXT))
}

/// Overlay IPv4 for host number `host` (1-based) in `100.64.0.0/10`.
#[must_use]
pub fn mesh_ipv4(host: u32) -> Option<Ipv4Addr> {
    (1..=MESH_IPV4_MAX_HOST)
        .contains(&host)
        .then(|| Ipv4Addr::from(MESH_IPV4_BASE + host))
}

/// ULA `fd<tenant 40 bits>::<device 64 bits>`.
#[must_use]
pub fn mesh_ipv6(tenant_id: &TenantId, device_id: &DeviceId) -> Ipv6Addr {
    let t = tenant_id.as_bytes();
    let d = device_id;
    Ipv6Addr::from([
        0xfd, t[0], t[1], t[2], t[3], t[4], 0, 0, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::TenantKeypair;

    fn sample_cred() -> MeshCred {
        let tenant = TenantKeypair::generate().id();
        let device_id = [7u8; 32];
        MeshCred {
            version: MESH_CRED_VERSION,
            kid: 1,
            device_id,
            tenant_id: tenant,
            ipv4: Ipv4Addr::new(100, 64, 0, 1),
            ipv6: mesh_ipv6(&tenant, &device_id),
            tags: vec!["tag:server".to_string()],
            owner: None,
            not_after_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn cbor_round_trip() {
        let cred = sample_cred();
        let decoded = MeshCred::from_cbor(&cred.to_cbor().unwrap()).unwrap();
        assert_eq!(cred, decoded);
    }

    #[test]
    fn verify_requires_mesh_context() {
        let kp = TenantKeypair::generate();
        let bytes = sample_cred().to_cbor().unwrap();
        // `TenantKeypair::sign` uses the empty context, like `EdgeCred`.
        let sig = kp.sign(&bytes);
        assert!(!verify_mesh_cred(kp.public_key(), &bytes, &sig));
    }

    #[test]
    fn ipv4_host_bounds() {
        assert_eq!(mesh_ipv4(0), None);
        assert_eq!(mesh_ipv4(1), Some(Ipv4Addr::new(100, 64, 0, 1)));
        assert_eq!(
            mesh_ipv4(MESH_IPV4_MAX_HOST),
            Some(Ipv4Addr::new(100, 127, 255, 254))
        );
        assert_eq!(mesh_ipv4(MESH_IPV4_MAX_HOST + 1), None);
    }

    #[test]
    fn ipv6_is_ula_and_tenant_scoped() {
        let a = TenantKeypair::generate().id();
        let b = TenantKeypair::generate().id();
        let device = [9u8; 32];
        let ip_a = mesh_ipv6(&a, &device);
        assert_eq!(ip_a.octets()[0], 0xfd);
        assert_ne!(ip_a, mesh_ipv6(&b, &device));
    }
}
