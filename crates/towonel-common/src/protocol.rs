use std::sync::Arc;

use iroh::endpoint::{QuicTransportConfig, VarInt};
use noq_proto::congestion::Bbr3Config;

/// ALPN protocol identifier for towonel agent ↔ edge connections.
pub const ALPN_TUNNEL: &[u8] = b"towonel/tunnel/1";

/// Cap on concurrent in-flight tunnel streams per agent ↔ edge connection.
///
/// Advertised as QUIC `max_concurrent_bidi_streams` and enforced by the
/// agent's accept semaphore; the lower of the two is the real limit.
pub const TUNNEL_MAX_CONCURRENT_STREAMS: u32 = 100_000;

/// Per-stream receive window.
///
/// One client connection rides one QUIC stream, so this caps single-connection
/// throughput at `window / RTT`; the noq default (1.25 MiB) capped a stream at
/// ~100 Mbit/s at 100 ms RTT.
const TUNNEL_STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;

/// Connection-wide receive window. Bounds unread buffered bytes across all
/// streams of a connection (noq defaults to unlimited).
const TUNNEL_RECEIVE_WINDOW: u32 = 64 * 1024 * 1024;

/// Connection-wide unacked send budget shared by all streams; sized to match
/// [`TUNNEL_RECEIVE_WINDOW`] (noq defaults to 10 MiB).
const TUNNEL_SEND_WINDOW: u64 = 64 * 1024 * 1024;

/// QUIC transport tuning for both tunnel endpoints. Windows are negotiated
/// per side, so an untuned peer silently re-imposes the defaults. Keep both
/// ends on this one config.
#[must_use]
pub fn tunnel_transport_config() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .congestion_controller_factory(Arc::new(Bbr3Config::default()))
        .max_concurrent_bidi_streams(VarInt::from_u32(TUNNEL_MAX_CONCURRENT_STREAMS))
        .stream_receive_window(VarInt::from_u32(TUNNEL_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(TUNNEL_RECEIVE_WINDOW))
        .send_window(TUNNEL_SEND_WINDOW)
        .enable_segmentation_offload(udp_gso_enabled())
        .build()
}

/// `TOWONEL_DISABLE_UDP_GSO=true` turns off UDP segmentation offload. Some pod
/// datapaths (e.g. Cilium netkit) accept GSO super-datagrams from `sendmsg`
/// but drop the segments without an error, so noq-udp's EIO/EINVAL fallback
/// never triggers; single-segment sends survive.
fn udp_gso_enabled() -> bool {
    !matches!(
        std::env::var("TOWONEL_DISABLE_UDP_GSO")
            .as_deref()
            .map(str::trim),
        Ok("true" | "TRUE" | "True" | "1")
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh::EndpointAddr;
    use iroh::endpoint::{Endpoint, presets::Minimal};
    use noq_proto::congestion::Bbr3;

    use super::*;

    #[tokio::test]
    async fn tunnel_endpoints_use_bbr3() {
        let edge = Endpoint::builder(Minimal)
            .alpns(vec![ALPN_TUNNEL.to_vec()])
            .transport_config(tunnel_transport_config())
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .expect("edge bind address")
            .bind()
            .await
            .expect("edge endpoint bind");
        let agent = Endpoint::builder(Minimal)
            .transport_config(tunnel_transport_config())
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .expect("agent bind address")
            .bind()
            .await
            .expect("agent endpoint bind");
        let edge_socket = edge
            .bound_sockets()
            .into_iter()
            .next()
            .expect("edge bound socket");
        let edge_addr = EndpointAddr::new(edge.id()).with_ip_addr(edge_socket);
        let (agent_conn, edge_conn) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(agent.connect(edge_addr, ALPN_TUNNEL), async {
                edge.accept()
                    .await
                    .expect("incoming agent connection")
                    .await
            })
        })
        .await
        .expect("tunnel connection timeout");
        let agent_conn = agent_conn.expect("agent connect");
        let edge_conn = edge_conn.expect("edge accept");

        for conn in [&agent_conn, &edge_conn] {
            let paths = conn.paths();
            let selected = paths
                .iter()
                .find(iroh::endpoint::Path::is_selected)
                .expect("selected tunnel path");
            let controller = conn
                .congestion_state(selected.id())
                .expect("tunnel congestion controller")
                .into_any();
            assert!(controller.is::<Bbr3>(), "tunnel must use BBR3");
        }

        agent_conn.close(0u32.into(), b"done");
        agent.close().await;
        edge.close().await;
    }
}
