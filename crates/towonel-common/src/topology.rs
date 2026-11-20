//! The edge set, pushed hub → edge → agent so agents don't poll the hub for it.

use std::time::Duration;

use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer, Verifier};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::edge_cred::Kid;
use crate::identity::{PQ_SIGNATURE_LEN, PqPublicKey};

/// How often an edge writes a keepalive to a subscribed agent when nothing
/// changed, so the agent can tell an idle stream from a stalled one.
pub const KEEPALIVE: Duration = Duration::from_secs(30);

/// How long an agent waits for a frame before treating the stream as stalled.
pub const SILENCE_LIMIT: Duration = Duration::from_secs(90);

/// Cap on one frame of the agent's topology stream.
const MAX_FRAME: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyEdge {
    pub id: iroh::EndpointId,
    #[serde(default)]
    pub addresses: Vec<String>,
    /// `host:port` of the edge's TLS tunnel listener.
    #[serde(default)]
    pub tls_addresses: Vec<String>,
    #[serde(default)]
    pub region: Option<String>,
}

impl TopologyEdge {
    #[must_use]
    pub const fn is_dialable(&self) -> bool {
        !self.addresses.is_empty() || !self.tls_addresses.is_empty()
    }

    fn in_regions(&self, regions: &[String]) -> bool {
        let region = self.region.as_deref().unwrap_or(crate::DEFAULT_REGION);
        regions.iter().any(|r| r == region)
    }
}

/// Every edge the hub currently has a link to.
///
/// `version` only grows, across hub restarts too, so a receiver holding
/// several copies keeps the newest. An edge missing from the list is not
/// known to be gone: a hub that just started has not heard from it yet.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Topology {
    pub version: u64,
    pub edges: Vec<TopologyEdge>,
}

impl Topology {
    /// The edges an agent limited to `regions` should hold sessions to. With
    /// no dialable edge in region that is every edge, so the agent is never
    /// stranded. Empty `regions` means no limit.
    #[must_use]
    pub fn wanted(&self, regions: &[String]) -> Vec<&TopologyEdge> {
        let any_in_region = self
            .edges
            .iter()
            .any(|e| e.in_regions(regions) && e.is_dialable());
        self.edges
            .iter()
            .filter(|e| regions.is_empty() || !any_in_region || e.in_regions(regions))
            .collect()
    }
}

/// ML-DSA context for topology signatures, so one can never verify as a
/// credential signed by the same key.
const SIGN_CONTEXT: &[u8] = b"towonel/topology/1";

/// A [`Topology`] as the hub signed it.
///
/// An agent takes a pushed set only when a key the hub gave it over HTTPS
/// signed it, so an edge can pass sets on but cannot make one up.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTopology {
    pub kid: Kid,
    #[serde(with = "serde_bytes")]
    topology_cbor: Vec<u8>,
    #[serde(with = "serde_bytes")]
    sig: Vec<u8>,
}

impl SignedTopology {
    pub fn sign(
        topology: &Topology,
        kid: Kid,
        key: &ml_dsa_65::PrivateKey,
    ) -> anyhow::Result<Self> {
        let mut topology_cbor = Vec::new();
        ciborium::into_writer(topology, &mut topology_cbor)?;
        let sig = key
            .try_sign(&topology_cbor, SIGN_CONTEXT)
            .map_err(|e| anyhow::anyhow!("ml-dsa-65 sign: {e}"))?;
        Ok(Self {
            kid,
            topology_cbor,
            sig: sig.to_vec(),
        })
    }

    /// The topology, if `key` signed it.
    #[must_use]
    pub fn verify(&self, key: &PqPublicKey) -> Option<Topology> {
        let sig: &[u8; PQ_SIGNATURE_LEN] = self.sig.as_slice().try_into().ok()?;
        let key = ml_dsa_65::PublicKey::try_from_bytes(*key.as_bytes()).ok()?;
        if !key.verify(&self.topology_cbor, sig, SIGN_CONTEXT) {
            return None;
        }
        self.decode_unverified()
    }

    /// The topology, whoever signed it: for an edge, which trusts its hub link.
    #[must_use]
    pub fn decode_unverified(&self) -> Option<Topology> {
        ciborium::from_reader(self.topology_cbor.as_slice()).ok()
    }
}

/// Write one frame of the agent's topology stream.
pub async fn write_topology<W: AsyncWrite + Unpin>(
    writer: &mut W,
    topology: &SignedTopology,
) -> std::io::Result<()> {
    let mut body = Vec::new();
    ciborium::into_writer(topology, &mut body).map_err(std::io::Error::other)?;
    let len = u32::try_from(body.len()).map_err(std::io::Error::other)?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&body).await
}

/// Write a keepalive: an empty frame, so an unchanged edge set costs four
/// bytes per agent instead of the whole set.
pub async fn write_keepalive<W: AsyncWrite + Unpin>(writer: &mut W) -> std::io::Result<()> {
    writer.write_all(&0u32.to_be_bytes()).await
}

/// Read one frame of the agent's topology stream; `None` is a keepalive.
pub async fn read_topology<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> std::io::Result<Option<SignedTopology>> {
    let len = reader.read_u32().await? as usize;
    if len == 0 {
        return Ok(None);
    }
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("topology frame of {len} bytes exceeds {MAX_FRAME}"),
        ));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    ciborium::from_reader(body.as_slice())
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(seed: u8, region: Option<&str>, dialable: bool) -> TopologyEdge {
        TopologyEdge {
            id: iroh::SecretKey::from([seed; 32]).public(),
            addresses: if dialable {
                vec![format!("192.0.2.{seed}:51820")]
            } else {
                Vec::new()
            },
            tls_addresses: Vec::new(),
            region: region.map(str::to_string),
        }
    }

    fn ids(edges: &[&TopologyEdge]) -> Vec<iroh::EndpointId> {
        edges.iter().map(|e| e.id).collect()
    }

    fn keypair(seed: u8) -> (ml_dsa_65::PrivateKey, PqPublicKey) {
        use fips204::traits::KeyGen;
        let (public, private) = ml_dsa_65::KG::keygen_from_seed(&[seed; 32]);
        (private, PqPublicKey::from_bytes(public.into_bytes()))
    }

    #[tokio::test]
    async fn frames_round_trip() {
        let topology = Topology {
            version: 7,
            edges: vec![edge(1, Some("EU"), true), edge(2, None, false)],
        };
        let (private, public) = keypair(1);
        let signed = SignedTopology::sign(&topology, 3, &private).unwrap();
        let mut buf = Vec::new();
        write_topology(&mut buf, &signed).await.unwrap();
        write_keepalive(&mut buf).await.unwrap();
        let mut reader = buf.as_slice();
        let read = read_topology(&mut reader).await.unwrap().unwrap();
        assert_eq!(read.kid, 3);
        assert_eq!(read.verify(&public), Some(topology));
        assert_eq!(read_topology(&mut reader).await.unwrap(), None);
    }

    #[test]
    fn only_the_signing_key_verifies_and_only_the_signed_bytes() {
        let topology = Topology {
            version: 7,
            edges: vec![edge(1, Some("EU"), true)],
        };
        let (private, public) = keypair(1);
        let (_, other) = keypair(2);
        let signed = SignedTopology::sign(&topology, 3, &private).unwrap();
        assert_eq!(signed.verify(&other), None);

        // An edge swapping in its own edge set keeps the hub's signature.
        let forged = Topology {
            version: u64::MAX,
            edges: Vec::new(),
        };
        let mut tampered = signed;
        tampered.topology_cbor = SignedTopology::sign(&forged, 3, &keypair(2).0)
            .unwrap()
            .topology_cbor;
        assert_eq!(tampered.decode_unverified(), Some(forged));
        assert_eq!(tampered.verify(&public), None);
    }

    #[tokio::test]
    async fn an_oversized_frame_is_rejected() {
        let buf = u32::MAX.to_be_bytes();
        read_topology(&mut buf.as_slice()).await.unwrap_err();
    }

    #[test]
    fn only_in_region_edges_are_wanted_when_one_is_dialable() {
        let topology = Topology {
            version: 1,
            edges: vec![edge(1, Some("EU"), true), edge(2, Some("NA"), true)],
        };
        let wanted = topology.wanted(&["EU".to_string()]);
        assert_eq!(ids(&wanted), vec![topology.edges[0].id]);
    }

    #[test]
    fn every_edge_is_wanted_when_none_in_region_is_dialable() {
        let topology = Topology {
            version: 1,
            edges: vec![edge(1, Some("EU"), false), edge(2, Some("NA"), true)],
        };
        assert_eq!(topology.wanted(&["EU".to_string()]).len(), 2);
    }

    #[test]
    fn a_missing_region_is_the_default_and_no_regions_is_no_limit() {
        let topology = Topology {
            version: 1,
            edges: vec![edge(1, None, true), edge(2, Some("NA"), true)],
        };
        let wanted = topology.wanted(&[crate::DEFAULT_REGION.to_string()]);
        assert_eq!(ids(&wanted), vec![topology.edges[0].id]);
        assert_eq!(topology.wanted(&[]).len(), 2);
    }
}
