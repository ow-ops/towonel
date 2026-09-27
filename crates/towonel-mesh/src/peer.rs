//! Peer authentication and the per-stream forwarding header.
#![expect(
    clippy::map_err_ignore,
    reason = "TryInto length-mismatch errors carry no information beyond our message"
)]

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{Context, ensure};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use towonel_common::edge_cred::{AuthFrame, Kid};
use towonel_common::identity::{PQ_SIGNATURE_LEN, PqPublicKey, TenantId};
use towonel_common::mesh::{MESH_CRED_VERSION, MeshCred, verify_mesh_cred};

use crate::api::{Cred, Netmap};
use crate::packet::PacketInfo;
use crate::policy::Policy;

pub const MESH_ALPN: &[u8] = b"towonel/mesh/1";
/// A hello is one `AuthFrame`: a few KiB of ML-DSA signature and CBOR.
pub const MAX_HELLO_LEN: usize = 16 * 1024;

const FORWARD_VERSION: u8 = 1;
const FORWARD_TCP: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ForwardStatus {
    Ok = 0,
    Denied = 1,
    Unreachable = 2,
}

impl ForwardStatus {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            0 => Self::Ok,
            1 => Self::Denied,
            _ => Self::Unreachable,
        }
    }
}

#[must_use]
pub const fn forward_header(port: u16) -> [u8; 4] {
    let [hi, lo] = port.to_be_bytes();
    [FORWARD_VERSION, FORWARD_TCP, hi, lo]
}

/// The requested local TCP port, or `None` for an unknown header.
#[must_use]
pub const fn parse_forward_header(header: [u8; 4]) -> Option<u16> {
    match header {
        [FORWARD_VERSION, FORWARD_TCP, hi, lo] => Some(u16::from_be_bytes([hi, lo])),
        _ => None,
    }
}

/// Everything peer checks need from the latest netmap.
#[derive(Debug, Clone)]
pub struct Trust {
    pub tenant: TenantId,
    pub peers: HashMap<[u8; 32], crate::api::Device>,
    pub by_ip: HashMap<IpAddr, [u8; 32]>,
    pub hub_keys: HashMap<Kid, PqPublicKey>,
    /// `None`: the built-in [`default_allows`].
    pub policy: Option<Policy>,
}

impl Trust {
    pub fn from_netmap(netmap: &Netmap) -> anyhow::Result<Self> {
        let tenant: TenantId = netmap.tenant_id.parse().context("netmap tenant_id")?;
        let mut hub_keys = HashMap::new();
        for key in &netmap.hub_keys {
            let bytes = B64.decode(&key.public_key_b64).context("hub key base64")?;
            let arr = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("hub key has the wrong length"))?;
            hub_keys.insert(key.kid, PqPublicKey::from_bytes(arr));
        }
        let mut peers = HashMap::new();
        let mut by_ip = HashMap::new();
        for peer in &netmap.peers {
            let id = device_id_bytes(&peer.device_id)?;
            for ip in [&peer.ipv4, &peer.ipv6] {
                by_ip.insert(ip.parse().context("peer overlay IP")?, id);
            }
            peers.insert(id, peer.clone());
        }
        Ok(Self {
            tenant,
            peers,
            by_ip,
            hub_keys,
            policy: netmap.policy.clone(),
        })
    }

    /// Accept `frame` from `remote` only if the hub signed it for this tenant,
    /// for that exact key, it hasn't expired, and the peer is still in the
    /// netmap (revocation).
    pub fn verify(
        &self,
        frame: &AuthFrame,
        remote: &[u8; 32],
        now_ms: u64,
    ) -> anyhow::Result<MeshCred> {
        let key = self
            .hub_keys
            .get(&frame.kid)
            .context("credential signed by an unknown hub key")?;
        ensure!(
            verify_mesh_cred(key, &frame.cred_cbor, &frame.sig),
            "credential signature does not verify"
        );
        let cred = MeshCred::from_cbor(&frame.cred_cbor)?;
        ensure!(
            cred.version == MESH_CRED_VERSION,
            "unsupported credential version"
        );
        ensure!(cred.kid == frame.kid, "credential kid mismatch");
        ensure!(
            cred.tenant_id == self.tenant,
            "credential is for another tenant"
        );
        ensure!(
            &cred.device_id == remote,
            "credential is for another device"
        );
        ensure!(cred.not_after_ms > now_ms, "credential expired");
        ensure!(self.peers.contains_key(remote), "peer is not in the netmap");
        Ok(cred)
    }
}

enum Principal<'a> {
    User(&'a str),
    /// Untagged, enrolled without a user (operator-minted key).
    Tenant,
    Tagged,
}

fn principal(cred: &MeshCred) -> Principal<'_> {
    match (&cred.owner, cred.tags.is_empty()) {
        (Some(user), _) => Principal::User(user),
        (None, true) => Principal::Tenant,
        (None, false) => Principal::Tagged,
    }
}

/// Policy for tenants without a stored one: users reach their own devices,
/// tenant devices reach each other, both reach tagged devices, and tagged
/// devices initiate nothing.
#[must_use]
pub fn default_allows(src: &MeshCred, dst: &MeshCred) -> bool {
    match (principal(src), principal(dst)) {
        (Principal::User(a), Principal::User(b)) => a == b,
        (Principal::Tenant, Principal::Tenant)
        | (Principal::User(_) | Principal::Tenant, Principal::Tagged) => true,
        _ => false,
    }
}

/// Whether `src` may open a flow to `dst`, under the tenant policy if it has
/// one.
#[must_use]
pub fn flow_allowed(
    policy: Option<&Policy>,
    src: &MeshCred,
    dst: &MeshCred,
    proto: u8,
    port: u16,
) -> bool {
    policy.map_or_else(
        || default_allows(src, dst),
        |p| p.allows(src, dst, proto, port),
    )
}

/// Whether a packet `peer` sent may reach this device. The source must be the
/// peer's own hub-signed address, so one device can't pose as another.
#[must_use]
pub fn inbound_allowed(
    info: &PacketInfo,
    peer: &MeshCred,
    own: &MeshCred,
    is_reply: bool,
    policy: Option<&Policy>,
) -> bool {
    let from_peer = info.src == IpAddr::V4(peer.ipv4) || info.src == IpAddr::V6(peer.ipv6);
    let to_us = info.dst == IpAddr::V4(own.ipv4) || info.dst == IpAddr::V6(own.ipv6);
    from_peer && to_us && (is_reply || flow_allowed(policy, peer, own, info.proto, info.dst_port))
}

/// Without a policy, whoever may reach `exit` may use it.
#[must_use]
pub fn internet_allowed(
    policy: Option<&Policy>,
    src: &MeshCred,
    exit: &MeshCred,
    proto: u8,
    port: u16,
) -> bool {
    policy.map_or_else(
        || default_allows(src, exit),
        |p| p.allows_internet(src, proto, port),
    )
}

#[must_use]
pub fn egress_allowed(
    info: &PacketInfo,
    peer: &MeshCred,
    own: &MeshCred,
    policy: Option<&Policy>,
) -> bool {
    let from_peer = info.src == IpAddr::V4(peer.ipv4) || info.src == IpAddr::V6(peer.ipv6);
    from_peer
        && is_internet(info.dst)
        && internet_allowed(policy, peer, own, info.proto, info.dst_port)
}

/// Only replies to flows we started.
#[must_use]
pub fn exit_reply_allowed(info: &PacketInfo, own: &MeshCred, is_reply: bool) -> bool {
    let to_us = info.dst == IpAddr::V4(own.ipv4) || info.dst == IpAddr::V6(own.ipv6);
    is_reply && to_us && is_internet(info.src)
}

/// Public unicast only, so an exit never bridges into its LAN or the overlay.
#[must_use]
pub const fn is_internet(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            let shared = a == 100 && (b & 0xc0) == 64;
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                || shared
                || a == 0
                || a >= 240)
        }
        IpAddr::V6(v6) => (v6.segments()[0] & 0xe000) == 0x2000,
    }
}

pub fn hello_frame(cred: &Cred) -> anyhow::Result<(AuthFrame, MeshCred)> {
    let cred_cbor = B64.decode(&cred.cred_b64).context("cred base64")?;
    let sig: [u8; PQ_SIGNATURE_LEN] = B64
        .decode(&cred.sig_b64)
        .context("sig base64")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signature has the wrong length"))?;
    let parsed = MeshCred::from_cbor(&cred_cbor)?;
    Ok((
        AuthFrame {
            kid: cred.kid,
            cred_cbor,
            sig,
        },
        parsed,
    ))
}

pub fn device_id_bytes(hex_id: &str) -> anyhow::Result<[u8; 32]> {
    <[u8; 32] as hex::FromHex>::from_hex(hex_id).context("device id is not 32 hex bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(owner: Option<&str>, tags: &[&str]) -> MeshCred {
        let tenant = towonel_common::identity::TenantKeypair::generate().id();
        MeshCred {
            version: MESH_CRED_VERSION,
            kid: 1,
            device_id: [1; 32],
            tenant_id: tenant,
            ipv4: "100.64.0.1".parse().unwrap(),
            ipv6: "fd00::1".parse().unwrap(),
            tags: tags.iter().map(|t| (*t).to_string()).collect(),
            owner: owner.map(str::to_string),
            not_after_ms: u64::MAX,
        }
    }

    #[test]
    fn default_policy() {
        let alice = cred(Some("alice"), &[]);
        let alice2 = cred(Some("alice"), &[]);
        let bob = cred(Some("bob"), &[]);
        let tenant = cred(None, &[]);
        let server = cred(None, &["tag:server"]);
        assert!(default_allows(&alice, &alice2));
        assert!(!default_allows(&alice, &bob));
        assert!(default_allows(&alice, &server));
        assert!(default_allows(&tenant, &tenant));
        assert!(default_allows(&tenant, &server));
        assert!(!default_allows(&tenant, &alice));
        assert!(!default_allows(&alice, &tenant));
        assert!(!default_allows(&server, &alice));
        assert!(!default_allows(&server, &server));
        assert!(!default_allows(&server, &tenant));
    }

    mod verify {
        use fips204::ml_dsa_65;
        use fips204::traits::{KeyGen, SerDes, Signer};
        use towonel_common::mesh::MESH_CRED_SIGN_CONTEXT;

        use super::super::*;
        use super::cred;
        use crate::api::Device;

        const REMOTE: [u8; 32] = [1; 32];
        const NOW: u64 = 1_000;

        struct Hub {
            key: ml_dsa_65::PrivateKey,
            trust: Trust,
        }

        impl Hub {
            fn new(peers: &[[u8; 32]]) -> Self {
                let (pk, key) = ml_dsa_65::KG::try_keygen().unwrap();
                let tenant = towonel_common::identity::TenantKeypair::generate().id();
                let peers = peers
                    .iter()
                    .map(|id| {
                        let device = Device {
                            device_id: hex::encode(id),
                            name: "peer".into(),
                            os: None,
                            ipv4: "100.64.0.9".into(),
                            ipv6: "fd00::9".into(),
                            tags: vec![],
                            owner: None,
                            key_expires_at_ms: None,
                            created_at_ms: 0,
                            last_seen_at_ms: None,
                            endpoint: None,
                            exit_node_advertised: false,
                            exit_node_approved: false,
                        };
                        (*id, device)
                    })
                    .collect();
                let trust = Trust {
                    tenant,
                    peers,
                    policy: None,
                    by_ip: HashMap::new(),
                    hub_keys: HashMap::from([(1, PqPublicKey::from_bytes(pk.into_bytes()))]),
                };
                Self { key, trust }
            }

            fn cred(&self) -> MeshCred {
                MeshCred {
                    tenant_id: self.trust.tenant,
                    device_id: REMOTE,
                    not_after_ms: NOW + 1,
                    ..cred(Some("alice"), &[])
                }
            }

            fn sign(&self, cred: &MeshCred, ctx: &[u8]) -> AuthFrame {
                let cred_cbor = cred.to_cbor().unwrap();
                let sig = self.key.try_sign(&cred_cbor, ctx).unwrap();
                AuthFrame {
                    kid: cred.kid,
                    cred_cbor,
                    sig,
                }
            }

            fn check(&self, frame: &AuthFrame) -> String {
                match self.trust.verify(frame, &REMOTE, NOW) {
                    Ok(_) => "ok".into(),
                    Err(e) => e.to_string(),
                }
            }
        }

        #[test]
        fn accepts_a_valid_credential() {
            let hub = Hub::new(&[REMOTE]);
            assert_eq!(
                hub.check(&hub.sign(&hub.cred(), MESH_CRED_SIGN_CONTEXT)),
                "ok"
            );
        }

        #[test]
        fn rejects_each_way_a_credential_can_be_wrong() {
            let hub = Hub::new(&[REMOTE]);
            let ctx = MESH_CRED_SIGN_CONTEXT;

            let mut tampered = hub.sign(&hub.cred(), ctx);
            let last = tampered.cred_cbor.len() - 1;
            tampered.cred_cbor[last] ^= 1;
            let other_tenant = MeshCred {
                tenant_id: towonel_common::identity::TenantKeypair::generate().id(),
                ..hub.cred()
            };
            let other_device = MeshCred {
                device_id: [2; 32],
                ..hub.cred()
            };
            let expired = MeshCred {
                not_after_ms: NOW,
                ..hub.cred()
            };
            let unknown_kid = MeshCred {
                kid: 7,
                ..hub.cred()
            };
            let mut kid_mismatch = hub.sign(&hub.cred(), ctx);
            kid_mismatch.kid = 7;

            let cases = vec![
                ("tampered", tampered, "does not verify"),
                (
                    "edge-cred context",
                    hub.sign(&hub.cred(), b""),
                    "does not verify",
                ),
                (
                    "other tenant",
                    hub.sign(&other_tenant, ctx),
                    "another tenant",
                ),
                (
                    "other device",
                    hub.sign(&other_device, ctx),
                    "another device",
                ),
                ("expired", hub.sign(&expired, ctx), "expired"),
                (
                    "unknown kid",
                    hub.sign(&unknown_kid, ctx),
                    "unknown hub key",
                ),
                ("kid mismatch", kid_mismatch, "unknown hub key"),
            ];
            for (name, frame, want) in cases {
                let got = hub.check(&frame);
                assert!(got.contains(want), "{name}: {got}");
            }
        }

        #[test]
        fn rejects_a_peer_missing_from_the_netmap() {
            let hub = Hub::new(&[]);
            let got = hub.check(&hub.sign(&hub.cred(), MESH_CRED_SIGN_CONTEXT));
            assert!(got.contains("not in the netmap"), "{got}");
        }
    }

    #[test]
    fn inbound_checks_source_destination_and_policy() {
        let laptop = cred(Some("alice"), &[]);
        let phone = MeshCred {
            ipv4: "100.64.0.2".parse().unwrap(),
            ipv6: "fd00::2".parse().unwrap(),
            ..cred(Some("alice"), &[])
        };
        let server = MeshCred {
            ipv4: "100.64.0.3".parse().unwrap(),
            ..cred(None, &["tag:server"])
        };
        let packet = |src: &str, dst: &str| PacketInfo {
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            proto: crate::packet::PROTO_UDP,
            src_port: 1,
            dst_port: 2,
        };

        assert!(inbound_allowed(
            &packet("100.64.0.2", "100.64.0.1"),
            &phone,
            &laptop,
            false,
            None
        ));
        assert!(inbound_allowed(
            &packet("fd00::2", "fd00::1"),
            &phone,
            &laptop,
            false,
            None
        ));
        // The phone claiming the server's address is dropped, whatever the policy.
        assert!(!inbound_allowed(
            &packet("100.64.0.3", "100.64.0.1"),
            &phone,
            &laptop,
            false,
            None
        ));
        assert!(!inbound_allowed(
            &packet("100.64.0.3", "100.64.0.1"),
            &phone,
            &laptop,
            true,
            None
        ));
        assert!(!inbound_allowed(
            &packet("100.64.0.2", "100.64.0.9"),
            &phone,
            &laptop,
            false,
            None
        ));
        // Tagged servers only get through as replies.
        assert!(!inbound_allowed(
            &packet("100.64.0.3", "100.64.0.1"),
            &server,
            &laptop,
            false,
            None
        ));
        assert!(inbound_allowed(
            &packet("100.64.0.3", "100.64.0.1"),
            &server,
            &laptop,
            true,
            None
        ));
    }

    #[test]
    fn exit_traffic_filters() {
        let laptop = cred(Some("alice"), &[]);
        let exit = MeshCred {
            ipv4: "100.64.0.3".parse().unwrap(),
            ..cred(None, &["tag:exit"])
        };
        let packet = |src: &str, dst: &str| PacketInfo {
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            proto: crate::packet::PROTO_TCP,
            src_port: 40000,
            dst_port: 443,
        };

        assert!(egress_allowed(
            &packet("100.64.0.1", "1.1.1.1"),
            &laptop,
            &exit,
            None
        ));
        assert!(egress_allowed(
            &packet("fd00::1", "2606:4700::1111"),
            &laptop,
            &exit,
            None
        ));
        // Tagged devices initiate nothing by default.
        assert!(!egress_allowed(
            &packet("100.64.0.3", "1.1.1.1"),
            &exit,
            &laptop,
            None
        ));
        assert!(!egress_allowed(
            &packet("100.64.0.9", "1.1.1.1"),
            &laptop,
            &exit,
            None
        ));
        for lan in [
            "192.168.1.1",
            "10.0.0.1",
            "100.64.0.2",
            "169.254.1.1",
            "fd00::2",
        ] {
            assert!(
                !egress_allowed(&packet("100.64.0.1", lan), &laptop, &exit, None),
                "{lan}"
            );
        }
        let deny_all = crate::policy::Policy::default();
        assert!(!egress_allowed(
            &packet("100.64.0.1", "1.1.1.1"),
            &laptop,
            &exit,
            Some(&deny_all)
        ));

        assert!(exit_reply_allowed(
            &packet("1.1.1.1", "100.64.0.1"),
            &laptop,
            true
        ));
        assert!(!exit_reply_allowed(
            &packet("1.1.1.1", "100.64.0.1"),
            &laptop,
            false
        ));
        assert!(!exit_reply_allowed(
            &packet("192.168.1.1", "100.64.0.1"),
            &laptop,
            true
        ));
    }

    #[test]
    fn forward_header_round_trips() {
        assert_eq!(parse_forward_header(forward_header(5432)), Some(5432));
        assert_eq!(parse_forward_header([9, 1, 0, 22]), None);
        assert_eq!(parse_forward_header([1, 2, 0, 22]), None);
    }
}
