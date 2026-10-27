//! Scrape-time QUIC statistics for live agent↔edge sessions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use iroh::endpoint::Connection;
use prometheus::core::{Collector, Desc};
use prometheus::proto::MetricFamily;
use prometheus::{GaugeVec, IntCounterVec, IntGaugeVec, Opts, Registry};

use crate::transport::TunnelConn;

/// Collects current sessions without retaining old samples.
#[derive(Clone)]
pub struct QuicMetrics {
    connections: Arc<Mutex<HashMap<String, Connection>>>,
    descriptors: Arc<Samples>,
    prefix: &'static str,
    peer_label: &'static str,
}

impl QuicMetrics {
    #[must_use]
    #[expect(
        clippy::expect_used,
        reason = "duplicate metric registration is a startup error"
    )]
    pub fn register(registry: &Registry, prefix: &'static str, peer_label: &'static str) -> Self {
        let metrics = Self {
            connections: Arc::default(),
            descriptors: Arc::new(Samples::new(prefix, peer_label)),
            prefix,
            peer_label,
        };
        registry
            .register(Box::new(metrics.clone()))
            .expect("unique QUIC metric names");
        metrics
    }

    pub fn insert(&self, peer: &str, conn: &TunnelConn) {
        let mut connections = self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match conn {
            TunnelConn::Iroh(conn) => {
                connections.insert(peer.to_owned(), conn.clone());
            }
            TunnelConn::Tls(_) => {
                connections.remove(peer);
            }
        }
    }

    /// A superseded session's cleanup must not remove its replacement.
    pub fn remove(&self, peer: &str, stable_id: usize) {
        let mut connections = self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if connections
            .get(peer)
            .is_some_and(|conn| conn.stable_id() == stable_id)
        {
            connections.remove(peer);
        }
    }
}

impl Collector for QuicMetrics {
    fn desc(&self) -> Vec<&Desc> {
        self.descriptors
            .collectors()
            .into_iter()
            .flat_map(Collector::desc)
            .collect()
    }

    fn collect(&self) -> Vec<MetricFamily> {
        // Read QUIC state without holding the session map lock.
        let connections: Vec<_> = self
            .connections
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(peer, conn)| (peer.clone(), conn.clone()))
            .collect();
        let samples = Samples::new(self.prefix, self.peer_label);
        for (peer, conn) in connections {
            if conn.close_reason().is_none() {
                samples.record(&peer, &conn);
            }
        }
        samples
            .collectors()
            .into_iter()
            .flat_map(Collector::collect)
            .collect()
    }
}

struct Samples {
    rtt: GaugeVec,
    cwnd: GaugeVec,
    congestion_events: IntCounterVec,
    lost_packets: IntCounterVec,
    udp_bytes: IntCounterVec,
    selected: IntGaugeVec,
    relay: IntGaugeVec,
    frames: IntCounterVec,
}

impl Samples {
    #[expect(
        clippy::expect_used,
        reason = "metric names and labels are static programmer inputs"
    )]
    fn new(prefix: &str, peer: &str) -> Self {
        let opts = |suffix: &str, help| Opts::new(format!("{prefix}_{suffix}"), help);
        let path_labels = &[peer, "path"];
        Self {
            rtt: GaugeVec::new(
                opts(
                    "path_rtt_seconds",
                    "QUIC path round-trip time estimate in seconds",
                ),
                path_labels,
            )
            .expect("valid RTT metric"),
            cwnd: GaugeVec::new(
                opts("path_cwnd_bytes", "QUIC path congestion window in bytes"),
                path_labels,
            )
            .expect("valid congestion window metric"),
            congestion_events: IntCounterVec::new(
                opts(
                    "path_congestion_events_total",
                    "Congestion events over the QUIC path lifetime",
                ),
                path_labels,
            )
            .expect("valid congestion events metric"),
            lost_packets: IntCounterVec::new(
                opts(
                    "path_lost_packets_total",
                    "Packets lost over the QUIC path lifetime",
                ),
                path_labels,
            )
            .expect("valid lost packets metric"),
            udp_bytes: IntCounterVec::new(
                opts(
                    "path_udp_bytes_total",
                    "QUIC path UDP payload bytes by direction (tx|rx)",
                ),
                &[peer, "path", "direction"],
            )
            .expect("valid UDP bytes metric"),
            selected: IntGaugeVec::new(
                opts(
                    "path_selected",
                    "1 if the QUIC path is selected for application data, 0 otherwise",
                ),
                path_labels,
            )
            .expect("valid selected path metric"),
            relay: IntGaugeVec::new(
                opts("path_relay", "1 if the QUIC path uses a relay, 0 otherwise"),
                path_labels,
            )
            .expect("valid relay path metric"),
            frames: IntCounterVec::new(
                opts(
                    "frames_total",
                    "QUIC frames over the connection lifetime by direction (tx|rx) and frame type",
                ),
                &[peer, "direction", "frame"],
            )
            .expect("valid frame metric"),
        }
    }

    fn collectors(&self) -> [&dyn Collector; 8] {
        [
            &self.rtt,
            &self.cwnd,
            &self.congestion_events,
            &self.lost_packets,
            &self.udp_bytes,
            &self.selected,
            &self.relay,
            &self.frames,
        ]
    }

    #[expect(
        clippy::cast_precision_loss,
        reason = "Prometheus gauge samples use f64"
    )]
    fn record(&self, peer: &str, conn: &Connection) {
        for path in conn.paths().iter() {
            let stats = path.stats();
            let id = path.id().to_string();
            let labels = &[peer, id.as_str()];
            self.rtt
                .with_label_values(labels)
                .set(stats.rtt.as_secs_f64());
            self.cwnd.with_label_values(labels).set(stats.cwnd as f64);
            self.congestion_events
                .with_label_values(labels)
                .inc_by(stats.congestion_events);
            self.lost_packets
                .with_label_values(labels)
                .inc_by(stats.lost_packets);
            self.selected
                .with_label_values(labels)
                .set(i64::from(path.is_selected()));
            self.relay
                .with_label_values(labels)
                .set(i64::from(path.is_relay()));
            for (direction, udp) in [("tx", stats.udp_tx), ("rx", stats.udp_rx)] {
                self.udp_bytes
                    .with_label_values(&[peer, &id, direction])
                    .inc_by(udp.bytes);
            }
        }
        let stats = conn.stats();
        for (direction, frames) in [("tx", stats.frame_tx), ("rx", stats.frame_rx)] {
            for (frame, count) in [
                ("stream", frames.stream),
                ("max_streams_bidi", frames.max_streams_bidi),
                ("streams_blocked_bidi", frames.streams_blocked_bidi),
                ("max_data", frames.max_data),
            ] {
                self.frames
                    .with_label_values(&[peer, direction, frame])
                    .inc_by(count);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use iroh::EndpointAddr;
    use iroh::endpoint::{Endpoint, presets::Minimal};
    use prometheus::{Encoder, TextEncoder};

    use crate::protocol::ALPN_TUNNEL;

    use super::*;

    async fn endpoint() -> Endpoint {
        Endpoint::builder(Minimal)
            .alpns(vec![ALPN_TUNNEL.to_vec()])
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap()
    }

    async fn connect(agent: &Endpoint, edge: &Endpoint) -> (Connection, Connection) {
        let addr = EndpointAddr::new(edge.id())
            .with_ip_addr(edge.bound_sockets().into_iter().next().unwrap());
        let (agent_conn, edge_conn) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(agent.connect(addr, ALPN_TUNNEL), async {
                edge.accept().await.unwrap().await
            })
        })
        .await
        .unwrap();
        (agent_conn.unwrap(), edge_conn.unwrap())
    }

    async fn exchange_request(agent: &Connection, edge: &Connection) {
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                async {
                    let (mut send, mut recv) = edge.open_bi().await.unwrap();
                    send.write_all(b"request").await.unwrap();
                    send.finish().unwrap();
                    assert_eq!(recv.read_to_end(100).await.unwrap(), b"response");
                },
                async {
                    let (mut send, mut recv) = agent.accept_bi().await.unwrap();
                    assert_eq!(recv.read_to_end(100).await.unwrap(), b"request");
                    send.write_all(b"response").await.unwrap();
                    send.finish().unwrap();
                }
            );
        })
        .await
        .unwrap();
    }

    fn scrape(registry: &Registry) -> String {
        let mut buf = Vec::new();
        TextEncoder::new()
            .encode(&registry.gather(), &mut buf)
            .unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn sample(registry: &Registry, name: &str, labels: &[(&str, &str)]) -> f64 {
        let family = registry
            .gather()
            .into_iter()
            .find(|f| f.name() == name)
            .unwrap();
        let metric = family
            .get_metric()
            .iter()
            .find(|m| {
                labels.iter().all(|(name, value)| {
                    m.get_label()
                        .iter()
                        .any(|l| l.name() == *name && l.value() == *value)
                })
            })
            .unwrap();
        if family.get_field_type() == prometheus::proto::MetricType::COUNTER {
            metric.get_counter().get_value()
        } else {
            assert_eq!(
                family.get_field_type(),
                prometheus::proto::MetricType::GAUGE
            );
            metric.get_gauge().get_value()
        }
    }

    #[tokio::test]
    #[expect(
        clippy::float_cmp,
        reason = "these counts and boolean gauges are exact integers"
    )]
    async fn exports_live_connection_stats() {
        let edge = endpoint().await;
        let agent = endpoint().await;
        let (agent_conn, edge_conn) = connect(&agent, &edge).await;
        let registry = Registry::new();
        let agent_metrics = QuicMetrics::register(&registry, "towonel_agent_quic", "edge");
        let edge_metrics = QuicMetrics::register(&registry, "towonel_edge_quic", "agent");
        assert!(registry.gather().is_empty());
        agent_metrics.insert("edge-1", &TunnelConn::Iroh(agent_conn.clone()));
        edge_metrics.insert("agent-1", &TunnelConn::Iroh(edge_conn.clone()));

        exchange_request(&agent_conn, &edge_conn).await;

        let text = scrape(&registry);
        for (prefix, peer_label, peer, conn) in [
            ("towonel_agent_quic", "edge", "edge-1", &agent_conn),
            ("towonel_edge_quic", "agent", "agent-1", &edge_conn),
        ] {
            let path_id = conn
                .paths()
                .iter()
                .find(iroh::endpoint::Path::is_selected)
                .unwrap()
                .id()
                .to_string();
            let labels = &[(peer_label, peer), ("path", path_id.as_str())];
            assert!(sample(&registry, &format!("{prefix}_path_rtt_seconds"), labels) > 0.0);
            assert!(sample(&registry, &format!("{prefix}_path_cwnd_bytes"), labels) > 0.0);
            assert_eq!(
                sample(&registry, &format!("{prefix}_path_selected"), labels),
                1.0
            );
            assert_eq!(
                sample(&registry, &format!("{prefix}_path_relay"), labels),
                0.0
            );
            for direction in ["tx", "rx"] {
                let labels = &[
                    (peer_label, peer),
                    ("path", path_id.as_str()),
                    ("direction", direction),
                ];
                assert!(sample(&registry, &format!("{prefix}_path_udp_bytes_total"), labels) > 8.0);
                for frame in [
                    "stream",
                    "max_streams_bidi",
                    "streams_blocked_bidi",
                    "max_data",
                ] {
                    let labels = &[
                        (peer_label, peer),
                        ("direction", direction),
                        ("frame", frame),
                    ];
                    let count = sample(&registry, &format!("{prefix}_frames_total"), labels);
                    if frame == "stream" {
                        assert!(count > 0.0);
                        // Credit frames can still arrive after the exchange.
                        assert_eq!(
                            sample(&registry, &format!("{prefix}_frames_total"), labels),
                            count
                        );
                    }
                }
            }
            for suffix in ["path_congestion_events_total", "path_lost_packets_total"] {
                assert!(text.contains(&format!("# TYPE {prefix}_{suffix} counter")));
            }
        }
        agent_conn.close(0u32.into(), b"done");
        assert!(!scrape(&registry).contains("edge=\"edge-1\""));
        agent_metrics.remove("edge-1", agent_conn.stable_id());
        edge_metrics.remove("agent-1", edge_conn.stable_id());
        assert!(registry.gather().is_empty());
        agent.close().await;
        edge.close().await;
    }
}
