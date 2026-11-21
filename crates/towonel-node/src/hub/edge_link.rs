use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, info, info_span, warn};

use towonel_common::edge_link::{
    EdgeToHub, HubSigningKey, HubToEdge, read_edge_to_hub, write_hub_to_edge,
};
use towonel_common::identity::TenantId;
use towonel_common::routing::RouteTable;
use towonel_common::time::now_ms;
use towonel_common::tunnel::CONTROL_STATUS_INTERNAL_ERROR;

use crate::edge::hub_client::ControlFrameHandler;

use super::api::{AppState, trigger_route_rebuild};
use super::db::port_reservations::{PortProtocol, PortReservationRow};
use super::live_agents::SourceKey;
use super::live_edges::EdgeId;

const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// A half-open edge (node gone without FIN/RST) otherwise parks `read_loop`
/// until TCP gives up, and stays in `live_edges` handing agents an endpoint id
/// nobody answers for.
const EDGE_LINK_KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
const EDGE_LINK_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

fn configure_edge_link_socket(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::debug!(error = %e, "edge_link set_nodelay failed");
    }
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(EDGE_LINK_KEEPALIVE_IDLE)
        .with_interval(EDGE_LINK_KEEPALIVE_INTERVAL);
    if let Err(e) = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive) {
        tracing::debug!(error = %e, "edge_link set SO_KEEPALIVE failed");
    }
}

const MAX_INFLIGHT_CONTROL: usize = 32;

pub type LinkPsk = [u8; 32];

pub struct EdgeLinkServer {
    pub listener: TcpListener,
    pub psk: Arc<LinkPsk>,
    pub hub_id: [u8; 32],
    pub state: Arc<AppState>,
    pub control_handler: Arc<dyn ControlFrameHandler>,
}

impl EdgeLinkServer {
    /// Bind synchronously during startup so a bad `listen_addr` fails the
    /// hub instead of silently degrading inside a spawned task.
    pub async fn bind(
        listen_addr: &str,
        psk: Arc<LinkPsk>,
        hub_id: [u8; 32],
        state: Arc<AppState>,
        control_handler: Arc<dyn ControlFrameHandler>,
    ) -> anyhow::Result<Self> {
        let listener = TcpListener::bind(listen_addr).await?;
        info!(listen = %listen_addr, "hub edge_link listening");
        Ok(Self {
            listener,
            psk,
            hub_id,
            state,
            control_handler,
        })
    }

    pub async fn run(self, shutdown: CancellationToken) -> anyhow::Result<()> {
        let Self {
            listener,
            psk,
            hub_id,
            state,
            control_handler,
        } = self;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    info!("hub edge_link shutting down");
                    return Ok(());
                }
                accept = listener.accept() => {
                    let (stream, peer) = accept?;
                    let psk_clone = Arc::clone(&psk);
                    let state_clone = Arc::clone(&state);
                    let handler_clone = Arc::clone(&control_handler);
                    let route_rx = state.route_tx.subscribe();
                    let shutdown = shutdown.clone();
                    tokio::spawn(async move {
                        let span = info_span!("edge_link", peer = %peer);
                        if let Err(e) = handle_connection(
                            stream,
                            peer,
                            &psk_clone,
                            hub_id,
                            state_clone,
                            handler_clone,
                            route_rx,
                            shutdown,
                        )
                        .instrument(span)
                        .await
                        {
                            warn!(peer = %peer, error = %e, "edge_link connection ended");
                        }
                    });
                }
            }
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "private per-connection entry point; bundling these into a struct would obscure ownership of the half-streams"
)]
#[expect(
    clippy::too_many_lines,
    reason = "linear handshake: Hello, PSK check, Welcome, then the read loop"
)]
async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    expected_psk: &LinkPsk,
    hub_id: [u8; 32],
    state: Arc<AppState>,
    control_handler: Arc<dyn ControlFrameHandler>,
    route_rx: broadcast::Receiver<RouteTable>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    configure_edge_link_socket(&stream);
    let (read_half, write_half) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(read_half);

    let hello = match tokio::time::timeout(HELLO_TIMEOUT, read_edge_to_hub(&mut reader)).await {
        Ok(Ok(frame)) => frame,
        Ok(Err(e)) => anyhow::bail!("read Hello: {e}"),
        Err(_) => anyhow::bail!("hello timed out"),
    };

    let (
        edge_id,
        iroh_endpoints,
        software_version,
        capabilities,
        public_ips,
        region,
        tls_endpoints,
        held_topology,
    ) = match hello {
        EdgeToHub::Hello {
            edge_id,
            iroh_endpoints,
            software_version,
            psk,
            capabilities,
            public_ips,
            region,
            tls_endpoints,
            topology,
        } => {
            if expected_psk.ct_eq(&psk).into() {
                (
                    edge_id,
                    iroh_endpoints,
                    software_version,
                    capabilities,
                    public_ips,
                    region,
                    tls_endpoints,
                    topology,
                )
            } else {
                anyhow::bail!("Hello PSK mismatch");
            }
        }
        other => anyhow::bail!("first frame was not Hello: {other:?}"),
    };

    // Only the leader holds edge hub-links; make standbys refuse so the edge
    // reconnects to the leader.
    if !state.is_leader.load(std::sync::atomic::Ordering::Relaxed) {
        anyhow::bail!("hub is not the leader");
    }

    info!(
        peer = %peer,
        edge = %hex::encode(edge_id),
        version = %software_version,
        endpoints = iroh_endpoints.len(),
        public_ips = public_ips.len(),
        "edge_link authenticated"
    );

    let public_ips = canonical_ips(&public_ips);
    let edge_public_ips = public_ips.clone();

    let signing_keys = current_signing_keys(&state)?;
    let welcome = HubToEdge::Welcome {
        hub_id,
        signing_keys,
    };
    let mut writer = write_half;
    // Upsert AFTER Welcome lands so a peer that disconnects mid-handshake
    // doesn't leave a stale entry; there is no janitor yet.
    write_hub_to_edge(&mut writer, &welcome).await?;
    let generation = state.live_edges.upsert(
        edge_id,
        iroh_endpoints,
        capabilities,
        public_ips,
        region,
        tls_endpoints,
        now_ms(),
    );
    let source = SourceKey::Remote(edge_id, generation);
    super::api::publish_topology(&state, held_topology.unwrap_or(0));

    let (writer_tx, writer_rx) = mpsc::channel::<HubToEdge>(64);
    let writer_task = tokio::spawn(run_writer(writer, writer_rx));
    let topology_task = held_topology
        .map(|_| tokio::spawn(push_topology(state.topology.subscribe(), writer_tx.clone())));
    // Gates push_routes' first send on the edge's SessionsSnapshot. Without
    // it the first table reflects an empty set for this edge and others
    // miss-route its hostnames until the snapshot lands.
    let snapshot_received = Arc::new(tokio::sync::Notify::new());
    let pusher_task = tokio::spawn(push_routes(
        route_rx,
        writer_tx.clone(),
        state.clone(),
        Arc::clone(&snapshot_received),
        edge_public_ips,
    ));
    let control_semaphore = Arc::new(Semaphore::new(MAX_INFLIGHT_CONTROL));
    let read = read_loop(
        reader,
        ReadLoopCtx {
            state: &state,
            edge_id,
            source,
            control_handler: &control_handler,
            control_semaphore: &control_semaphore,
            writer_tx: writer_tx.clone(),
            shutdown: shutdown.clone(),
            snapshot_received,
        },
    );
    let result = tokio::select! {
        result = read => result,
        () = async {
            while state.is_leader.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        } => Err(anyhow::anyhow!("hub is no longer the leader")),
    };

    drop(writer_tx);
    pusher_task.abort();
    if let Some(task) = topology_task {
        task.abort();
    }
    writer_task.abort();
    state.live_edges.remove_if_current(&edge_id, generation);
    super::api::publish_topology(&state, 0);
    if state.live_agents.drop_source(source) {
        trigger_route_rebuild(&state);
    }
    info!(edge = %hex::encode(edge_id), "edge_link disconnected");
    result
}

struct ReadLoopCtx<'a> {
    state: &'a Arc<AppState>,
    edge_id: EdgeId,
    source: SourceKey,
    control_handler: &'a Arc<dyn ControlFrameHandler>,
    control_semaphore: &'a Arc<Semaphore>,
    writer_tx: mpsc::Sender<HubToEdge>,
    shutdown: CancellationToken,
    snapshot_received: Arc<tokio::sync::Notify>,
}

async fn read_loop<R>(mut reader: R, ctx: ReadLoopCtx<'_>) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin,
{
    let ReadLoopCtx {
        state,
        edge_id,
        source,
        control_handler,
        control_semaphore,
        writer_tx,
        shutdown,
        snapshot_received,
    } = ctx;
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return Ok(()),
            frame = read_edge_to_hub(&mut reader) => {
                match frame {
                    Ok(EdgeToHub::Hello { .. }) => {
                        warn!(edge = %hex::encode(edge_id), "duplicate Hello on established link; ignoring");
                    }
                    Ok(EdgeToHub::SessionAdded { agent_id, tenant_id }) => {
                        if state.live_agents.record_added(source, tenant_id, agent_id) {
                            trigger_route_rebuild(state);
                        }
                    }
                    Ok(EdgeToHub::SessionRemoved { agent_id }) => {
                        // tenant_of recovers the tenant from prior state.
                        if let Some(tenant_id) = state.live_agents.tenant_of(source, &agent_id)
                            && state.live_agents.record_removed(source, tenant_id, agent_id)
                        {
                            trigger_route_rebuild(state);
                        }
                    }
                    Ok(EdgeToHub::SessionsSnapshot { sessions }) => {
                        let pairs: Vec<_> = sessions.into_iter().map(|(a, t)| (t, a)).collect();
                        if state.live_agents.replace(source, pairs) {
                            trigger_route_rebuild(state);
                        }
                        snapshot_received.notify_one();
                    }
                    Ok(EdgeToHub::ControlRequest { request_id, frame }) => {
                        if let Ok(permit) = Arc::clone(control_semaphore).try_acquire_owned() {
                            // Spawn so a slow handler doesn't block the read loop.
                            let handler = Arc::clone(control_handler);
                            let writer_tx = writer_tx.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                let (status, body) = match handler.handle(frame).await {
                                    Ok(resp) => resp,
                                    Err(e) => {
                                        warn!(request_id, error = %e, "control handler errored");
                                        (CONTROL_STATUS_INTERNAL_ERROR, Vec::new())
                                    }
                                };
                                if writer_tx
                                    .send(HubToEdge::ControlResponse {
                                        request_id,
                                        status,
                                        body,
                                    })
                                    .await
                                    .is_err()
                                {
                                    tracing::debug!(request_id, "control response writer closed");
                                }
                            });
                        } else {
                            warn!(request_id, "control queue at capacity; refusing");
                            if writer_tx
                                .try_send(HubToEdge::ControlResponse {
                                    request_id,
                                    status: CONTROL_STATUS_INTERNAL_ERROR,
                                    body: Vec::new(),
                                })
                                .is_err()
                            {
                                tracing::debug!(
                                    request_id,
                                    "writer queue full while reporting overload"
                                );
                            }
                        }
                    }
                    Err(e) => return Err(anyhow::anyhow!("read frame: {e}")),
                }
            }
        }
    }
}

async fn run_writer<W>(mut writer: W, mut rx: mpsc::Receiver<HubToEdge>) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    while let Some(msg) = rx.recv().await {
        write_hub_to_edge(&mut writer, &msg).await?;
    }
    Ok(())
}

async fn push_topology(
    mut topology: crate::edge::hub_client::TopologyRx,
    writer_tx: mpsc::Sender<HubToEdge>,
) {
    loop {
        let current = topology.borrow_and_update().clone();
        if let Some(current) = current
            && writer_tx
                .send(HubToEdge::Topology(current.signed.clone()))
                .await
                .is_err()
        {
            return;
        }
        if topology.changed().await.is_err() {
            return;
        }
    }
}

async fn push_routes(
    mut route_rx: broadcast::Receiver<RouteTable>,
    writer_tx: mpsc::Sender<HubToEdge>,
    state: Arc<AppState>,
    snapshot_received: Arc<tokio::sync::Notify>,
    public_ips: Vec<String>,
) -> anyhow::Result<()> {
    // Wait for SessionsSnapshot before shipping the first table — see
    // the snapshot_received comment in handle_link.
    snapshot_received.notified().await;
    // Initial snapshot so a fresh edge converges before the next mutation.
    if let Ok(mut initial) = super::api::current_route_table(&state).await {
        filter_listeners_for_edge(&mut initial, &state, &public_ips);
        if writer_tx
            .send(HubToEdge::RouteSnapshot {
                table: Box::new(initial),
            })
            .await
            .is_err()
        {
            return Ok(());
        }
    }
    loop {
        match route_rx.recv().await {
            Ok(mut table) => {
                filter_listeners_for_edge(&mut table, &state, &public_ips);
                if writer_tx
                    .send(HubToEdge::RouteSnapshot {
                        table: Box::new(table),
                    })
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }
            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                warn!(skipped, "edge_link route stream lagged");
            }
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}

/// Covers edges that predate config-side IP normalization.
fn canonical_ips(ips: &[String]) -> Vec<String> {
    ips.iter().map(|s| crate::config::canonical_ip(s)).collect()
}

fn filter_listeners_for_edge(table: &mut RouteTable, state: &Arc<AppState>, public_ips: &[String]) {
    let reservations = state.port_reservations.load();
    table.retain_tcp_listeners(|port, binding| {
        edge_serves(
            &reservations,
            PortProtocol::Tcp,
            &binding.tenant,
            *port,
            public_ips,
        )
    });
    table.retain_udp_listeners(|port, binding| {
        edge_serves(
            &reservations,
            PortProtocol::Udp,
            &binding.tenant,
            *port,
            public_ips,
        )
    });
}

/// Whether an edge with `public_ips` listens on `port` for `tenant`: the
/// tenant's reservation covering the port is on one of those IPs, or names
/// none. Another tenant may hold the same port on another edge's IP.
fn edge_serves(
    reservations: &[PortReservationRow],
    protocol: PortProtocol,
    tenant: &TenantId,
    port: u16,
    public_ips: &[String],
) -> bool {
    let mut assigned_ips = reservations
        .iter()
        .filter(|r| {
            r.protocol == protocol
                && r.tenant_id == *tenant
                && (r.port..=r.port_end).contains(&port)
        })
        .filter_map(|r| r.ip_address.as_deref())
        .peekable();
    assigned_ips.peek().is_none() || assigned_ips.any(|ip| public_ips.iter().any(|p| p == ip))
}

fn current_signing_keys(state: &AppState) -> anyhow::Result<Vec<HubSigningKey>> {
    let signer = state.signer.as_ref();
    let pubkey = signer.public_key().as_bytes().to_vec();
    Ok(vec![HubSigningKey::new(signer.kid(), pubkey)?])
}

#[cfg(test)]
mod tests {
    use super::*;
    use towonel_common::edge_link::{EdgeCapabilities, read_hub_to_edge, write_edge_to_hub};
    use towonel_common::identity::{AgentKeypair, TenantKeypair};
    use towonel_common::topology::Topology;

    use crate::hub::test_helpers::TestHub;

    fn reserved(tenant: u8, ip: Option<&str>, ports: (u16, u16)) -> PortReservationRow {
        PortReservationRow {
            id: [0; 16],
            tenant_id: TenantId::from_bytes(&[tenant; 32]),
            ip_address: ip.map(str::to_owned),
            port: ports.0,
            port_end: ports.1,
            protocol: PortProtocol::Udp,
            label: None,
            claimed_at_ms: 0,
        }
    }

    fn serves(reservations: &[PortReservationRow], tenant: u8, port: u16, edge_ip: &str) -> bool {
        let tenant = TenantId::from_bytes(&[tenant; 32]);
        edge_serves(
            reservations,
            PortProtocol::Udp,
            &tenant,
            port,
            &[edge_ip.to_owned()],
        )
    }

    #[test]
    fn a_port_two_tenants_reserved_goes_to_the_edge_of_the_tenant_that_serves_it() {
        let reservations = [
            reserved(1, Some("192.0.2.1"), (3478, 3478)),
            reserved(2, Some("192.0.2.2"), (3478, 3478)),
        ];

        assert!(serves(&reservations, 1, 3478, "192.0.2.1"));
        assert!(!serves(&reservations, 1, 3478, "192.0.2.2"));
    }

    #[test]
    fn every_port_of_a_reserved_range_stays_on_its_edge() {
        let reservations = [reserved(1, Some("192.0.2.1"), (50100, 50200))];

        assert!(serves(&reservations, 1, 50150, "192.0.2.1"));
        assert!(!serves(&reservations, 1, 50150, "192.0.2.2"));
    }

    #[test]
    fn a_reservation_without_an_ip_is_served_by_every_edge() {
        let reservations = [reserved(1, None, (3478, 3478))];

        assert!(serves(&reservations, 1, 3478, "192.0.2.2"));
    }

    struct EchoControl;

    #[async_trait::async_trait]
    impl ControlFrameHandler for EchoControl {
        async fn handle(&self, frame: Vec<u8>) -> anyhow::Result<(u8, Vec<u8>)> {
            Ok((0, frame))
        }
    }

    async fn connect_link(
        state: Arc<AppState>,
        edge_id: EdgeId,
    ) -> (TcpStream, tokio::task::JoinHandle<anyhow::Result<()>>) {
        connect_link_with(state, edge_id, None).await
    }

    async fn connect_link_with(
        state: Arc<AppState>,
        edge_id: EdgeId,
        topology: Option<u64>,
    ) -> (TcpStream, tokio::task::JoinHandle<anyhow::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        let route_rx = state.route_tx.subscribe();
        let handler = tokio::spawn(async move {
            handle_connection(
                server,
                peer,
                &[7; 32],
                [8; 32],
                state,
                Arc::new(EchoControl),
                route_rx,
                CancellationToken::new(),
            )
            .await
        });
        write_edge_to_hub(
            &mut client,
            &EdgeToHub::Hello {
                edge_id,
                iroh_endpoints: vec!["127.0.0.1:51820".into()],
                software_version: "test".into(),
                psk: [7; 32],
                capabilities: EdgeCapabilities::default(),
                public_ips: vec!["127.0.0.1".into()],
                region: None,
                tls_endpoints: vec![],
                topology,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), read_hub_to_edge(&mut client))
                .await
                .unwrap()
                .unwrap(),
            HubToEdge::Welcome { .. }
        ));
        (client, handler)
    }

    async fn assert_link_responds(client: &mut TcpStream) {
        write_edge_to_hub(
            client,
            &EdgeToHub::ControlRequest {
                request_id: 42,
                frame: b"still live".to_vec(),
            },
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let HubToEdge::ControlResponse {
                    request_id: 42,
                    status,
                    body,
                } = read_hub_to_edge(client).await.unwrap()
                {
                    assert_eq!(status, 0);
                    assert_eq!(body, b"still live");
                    break;
                }
            }
        })
        .await
        .unwrap();
    }

    fn edge_id(seed: u8) -> EdgeId {
        *iroh::SecretKey::from([seed; 32]).public().as_bytes()
    }

    /// The next edge set pushed on the link, checked against the hub's key.
    async fn next_topology(hub: &TestHub, client: &mut TcpStream) -> Topology {
        let signed = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let HubToEdge::Topology(signed) = read_hub_to_edge(client).await.unwrap() {
                    break signed;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(signed.kid, hub.state.signer.kid());
        signed
            .verify(hub.state.signer.public_key())
            .expect("edge set not signed by the hub's key")
    }

    fn remote_ids(hub: &TestHub, topology: &Topology) -> Vec<EdgeId> {
        topology
            .edges
            .iter()
            .filter(|e| Some(e.id) != hub.state.identity.edge_node_id)
            .map(|e| *e.id.as_bytes())
            .collect()
    }

    #[tokio::test]
    async fn an_edge_that_asked_is_pushed_the_edge_set_and_its_changes() {
        let hub = TestHub::start().await;
        // An edge still holding a set from an earlier hub whose clock ran ahead.
        let held = now_ms() + 3_600_000;
        let (mut first, _first_handler) =
            connect_link_with(Arc::clone(&hub.state), edge_id(21), Some(held)).await;
        let alone = next_topology(&hub, &mut first).await;
        assert_eq!(remote_ids(&hub, &alone), vec![edge_id(21)]);
        assert_eq!(alone.version, held + 1);

        let (second, second_handler) = connect_link(Arc::clone(&hub.state), edge_id(22)).await;
        let both = next_topology(&hub, &mut first).await;
        assert!(both.version > alone.version);
        let mut ids = remote_ids(&hub, &both);
        ids.sort_unstable();
        let mut expected = vec![edge_id(21), edge_id(22)];
        expected.sort_unstable();
        assert_eq!(ids, expected);

        drop(second);
        drop(second_handler.await.unwrap());
        let after = next_topology(&hub, &mut first).await;
        assert!(after.version > both.version);
        assert_eq!(remote_ids(&hub, &after), vec![edge_id(21)]);
    }

    #[tokio::test]
    async fn an_edge_that_did_not_ask_is_never_sent_topology() {
        let hub = TestHub::start().await;
        let (mut old, _handler) = connect_link(Arc::clone(&hub.state), edge_id(21)).await;
        let (_other, _other_handler) = connect_link(Arc::clone(&hub.state), edge_id(22)).await;
        write_edge_to_hub(
            &mut old,
            &EdgeToHub::ControlRequest {
                request_id: 1,
                frame: b"ping".to_vec(),
            },
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                match read_hub_to_edge(&mut old).await.unwrap() {
                    HubToEdge::ControlResponse { .. } => break,
                    HubToEdge::Topology(_) => panic!("topology sent to an edge that predates it"),
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn edge_reconnects_after_demotion() {
        let old_hub = TestHub::start().await;
        let edge_id = [11; 32];
        let tenant = TenantKeypair::generate().id();
        let agent = AgentKeypair::generate().id();
        let key = (tenant, agent.clone());
        let snapshot = EdgeToHub::SessionsSnapshot {
            sessions: vec![(agent, tenant)],
        };
        let (mut old, old_handler) = connect_link(Arc::clone(&old_hub.state), edge_id).await;
        write_edge_to_hub(&mut old, &snapshot).await.unwrap();
        assert_link_responds(&mut old).await;
        assert!(old_hub.state.live_agents.snapshot().contains(&key));
        assert!(!old_hub.state.live_edges.snapshot().is_empty());

        old_hub
            .state
            .is_leader
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let result = tokio::time::timeout(Duration::from_secs(3), old_handler)
            .await
            .expect("former leader kept its idle edge link open")
            .unwrap();
        assert!(result.is_err());
        assert!(old_hub.state.live_edges.snapshot().is_empty());
        assert!(!old_hub.state.live_agents.snapshot().contains(&key));
        tokio::time::timeout(Duration::from_secs(2), async {
            while read_hub_to_edge(&mut old).await.is_ok() {}
        })
        .await
        .expect("former leader did not close the edge socket");

        let new_hub = TestHub::start().await;
        let (mut new, new_handler) = connect_link(Arc::clone(&new_hub.state), edge_id).await;
        write_edge_to_hub(&mut new, &snapshot).await.unwrap();
        assert_link_responds(&mut new).await;
        assert!(new_hub.state.live_agents.snapshot().contains(&key));
        assert!(
            new_hub
                .state
                .live_edges
                .snapshot()
                .iter()
                .any(|edge| edge.0 == edge_id)
        );
        drop(new);
        let _disconnected = tokio::time::timeout(Duration::from_secs(2), new_handler)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn old_hub_link_cleanup_preserves_replacement() {
        let hub = TestHub::start().await;
        let edge_id = [9; 32];
        let (mut old, old_handler) = connect_link(Arc::clone(&hub.state), edge_id).await;
        let (mut new, new_handler) = connect_link(Arc::clone(&hub.state), edge_id).await;
        let tenant = TenantKeypair::generate().id();
        let agent = AgentKeypair::generate().id();
        let live_key = (tenant, agent.clone());
        write_edge_to_hub(
            &mut new,
            &EdgeToHub::SessionsSnapshot {
                sessions: vec![(agent, tenant)],
            },
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !hub.state.live_agents.snapshot().contains(&live_key) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            hub.state
                .live_edges
                .snapshot()
                .iter()
                .any(|e| e.0 == edge_id)
        );

        // Ignore the old link's late snapshot.
        write_edge_to_hub(&mut old, &EdgeToHub::SessionsSnapshot { sessions: vec![] })
            .await
            .unwrap();
        assert_link_responds(&mut old).await;
        assert!(hub.state.live_agents.snapshot().contains(&live_key));

        drop(old);
        let _disconnected = tokio::time::timeout(Duration::from_secs(2), old_handler)
            .await
            .unwrap()
            .unwrap();
        let edge_present = hub
            .state
            .live_edges
            .snapshot()
            .iter()
            .any(|e| e.0 == edge_id);
        let agent_present = hub.state.live_agents.snapshot().contains(&live_key);

        assert_link_responds(&mut new).await;
        drop(new);
        let _disconnected = tokio::time::timeout(Duration::from_secs(2), new_handler)
            .await
            .unwrap()
            .unwrap();
        assert!(
            edge_present && agent_present,
            "old link removed the replacement's live state"
        );
    }

    #[tokio::test]
    async fn replacement_snapshot_fences_old_link_presence() {
        let hub = TestHub::start().await;
        let edge_id = [10; 32];
        let tenant = TenantKeypair::generate().id();
        let agent = AgentKeypair::generate().id();
        let key = (tenant, agent.clone());
        let snapshot = EdgeToHub::SessionsSnapshot {
            sessions: vec![(agent.clone(), tenant)],
        };
        let (mut old, old_handler) = connect_link(Arc::clone(&hub.state), edge_id).await;
        write_edge_to_hub(&mut old, &snapshot).await.unwrap();
        assert_link_responds(&mut old).await;
        assert!(hub.state.live_agents.snapshot().contains(&key));

        let (mut new, new_handler) = connect_link(Arc::clone(&hub.state), edge_id).await;
        write_edge_to_hub(&mut new, &snapshot).await.unwrap();
        write_edge_to_hub(
            &mut new,
            &EdgeToHub::SessionRemoved {
                agent_id: agent.clone(),
            },
        )
        .await
        .unwrap();
        assert_link_responds(&mut new).await;
        let removed = !hub.state.live_agents.snapshot().contains(&key);

        // The old link must not restore the removed agent.
        write_edge_to_hub(&mut old, &snapshot).await.unwrap();
        assert_link_responds(&mut old).await;
        let stale_snapshot_ignored = !hub.state.live_agents.snapshot().contains(&key);
        write_edge_to_hub(&mut new, &snapshot).await.unwrap();
        write_edge_to_hub(&mut new, &EdgeToHub::SessionsSnapshot { sessions: vec![] })
            .await
            .unwrap();
        assert_link_responds(&mut new).await;
        let empty_snapshot_removed = !hub.state.live_agents.snapshot().contains(&key);

        drop(new);
        let _disconnected = tokio::time::timeout(Duration::from_secs(2), new_handler)
            .await
            .unwrap()
            .unwrap();
        write_edge_to_hub(
            &mut old,
            &EdgeToHub::SessionAdded {
                agent_id: agent,
                tenant_id: tenant,
            },
        )
        .await
        .unwrap();
        assert_link_responds(&mut old).await;
        let stale_add_ignored = !hub.state.live_agents.snapshot().contains(&key);
        drop(old);
        let _disconnected = tokio::time::timeout(Duration::from_secs(2), old_handler)
            .await
            .unwrap()
            .unwrap();
        assert!(removed, "replacement removal left old-link presence behind");
        assert!(
            stale_snapshot_ignored,
            "old snapshot resurrected agent presence"
        );
        assert!(
            empty_snapshot_removed,
            "replacement snapshot left stale presence"
        );
        assert!(
            stale_add_ignored,
            "old link recreated presence after replacement closed"
        );
    }
}
