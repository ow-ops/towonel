use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use iroh::endpoint::{
    ConnectError, ConnectionError, PathEvent, PathEventStream, TransportErrorCode,
};
use iroh::{Endpoint, EndpointAddr, RelayUrl, TransportAddr};
use tokio::net::{TcpStream, lookup_host};
use tokio::task::JoinSet;
use tokio_stream::StreamExt as _;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, debug, error, info, info_span, warn};

use towonel_common::edge_cred::AuthFrame;
use towonel_common::protocol::ALPN_TUNNEL;
use towonel_common::transport::TunnelConn;
use towonel_common::transport::tls::TlsDialer;
use towonel_common::tunnel::{CONTROL_STATUS_OK, read_control_status, write_control_prefix};

use crate::metrics::AgentMetrics;
use crate::stateless::{CachedEdgeCred, EdgeContact};
use crate::tunnel::{self, ServiceMap};

const PRESENT_CRED_TIMEOUT: Duration = Duration::from_secs(5);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REBUILD_AFTER_TIMEOUTS: u32 = 3;
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

const REDIAL_DELAY: Duration = Duration::from_secs(5);
/// Cap on the redial backoff when an edge keeps failing to connect.
const REDIAL_MAX_DELAY: Duration = Duration::from_mins(1);

/// Redialing can't fix a mismatch; this just has to recover once the hub's
/// topology is corrected.
const IDENTITY_MISMATCH_COOLDOWN: Duration = Duration::from_mins(5);

/// TLS alert 48, `unknown_ca`: iroh's raw-public-key verifier rejected the peer.
const TLS_ALERT_UNKNOWN_CA: u8 = 48;

/// After QUIC fails, redials try TLS first for this long, and a TLS session
/// probes QUIC at this interval. A network that blocks UDP then doesn't pay the
/// QUIC timeout on every reconnect.
const QUIC_RETRY_AFTER: Duration = Duration::from_mins(10);

/// When QUIC last failed for an edge that TLS could still reach; outlives
/// single redials.
struct TransportMemory {
    retry_after: Duration,
    quic_failed_at: std::sync::Mutex<Option<Instant>>,
}

impl TransportMemory {
    const fn new(retry_after: Duration) -> Self {
        Self {
            retry_after,
            quic_failed_at: std::sync::Mutex::new(None),
        }
    }

    fn quic_recently_failed(&self) -> bool {
        self.quic_failed_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some_and(|at| at.elapsed() < self.retry_after)
    }

    fn quic_failed(&self) {
        *self
            .quic_failed_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Instant::now());
    }

    fn quic_worked(&self) {
        *self
            .quic_failed_at
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

struct ActiveSupervisor {
    token: CancellationToken,
    /// Addresses this supervisor was spawned with; a change for the same edge
    /// triggers a respawn.
    addrs: Vec<String>,
    tls_addrs: Vec<String>,
}

/// Per-edge supervisors reconciled against the hub's trusted-edge set. Each owns
/// a child of the process shutdown token, so an edge leaving the set is stopped
/// on its own without disturbing the others.
pub struct SupervisorPool {
    endpoint: Endpoint,
    service_map: Arc<ServiceMap>,
    metrics: Arc<AgentMetrics>,
    edge_cred: Arc<arc_swap::ArcSwapOption<CachedEdgeCred>>,
    relay_urls: Arc<Vec<RelayUrl>>,
    tls: TlsDialer,
    shutdown: CancellationToken,
    active: std::collections::HashMap<iroh::EndpointId, ActiveSupervisor>,
    tasks: JoinSet<()>,
    events: tokio::sync::mpsc::UnboundedReceiver<SessionEvent>,
    event_tx: tokio::sync::mpsc::UnboundedSender<SessionEvent>,
}

pub enum SessionEvent {
    Connected,
    ConnectTimeouts,
}

impl SupervisorPool {
    pub fn new(
        endpoint: &Endpoint,
        service_map: &Arc<ServiceMap>,
        metrics: &Arc<AgentMetrics>,
        edge_cred: &Arc<arc_swap::ArcSwapOption<CachedEdgeCred>>,
        relay_urls: Vec<RelayUrl>,
        tls: TlsDialer,
        shutdown: &CancellationToken,
    ) -> Self {
        let (event_tx, events) = tokio::sync::mpsc::unbounded_channel();
        Self {
            endpoint: endpoint.clone(),
            service_map: Arc::clone(service_map),
            metrics: Arc::clone(metrics),
            edge_cred: Arc::clone(edge_cred),
            relay_urls: Arc::new(relay_urls),
            tls,
            shutdown: shutdown.clone(),
            active: std::collections::HashMap::new(),
            tasks: JoinSet::new(),
            events,
            event_tx,
        }
    }

    pub async fn next_event(&mut self) -> Option<SessionEvent> {
        self.events.recv().await
    }

    /// Match running supervisors to `contacts`: stop supervisors whose edge is
    /// no longer in the set, and start one for each newly-present dialable edge.
    /// Edges already supervised are left running.
    pub fn reconcile(&mut self, contacts: &[EdgeContact]) {
        // Drain supervisors that have exited (only happens on cancellation),
        // so the `tasks` set doesn't accumulate finished handles.
        while self.tasks.try_join_next().is_some() {}

        let desired: std::collections::HashMap<iroh::EndpointId, &EdgeContact> =
            contacts.iter().map(|c| (c.id, c)).collect();

        // Stop supervisors whose edge left the set, or whose advertised
        // addresses changed — the spawn loop below then redials the new ones.
        let stale: Vec<iroh::EndpointId> = self
            .active
            .iter()
            .filter_map(|(id, sup)| {
                // Set comparison: hub snapshots aren't canonically ordered, so
                // a reordered-but-equal address list must not respawn a healthy
                // supervisor.
                let keep = matches!(
                    desired.get(id),
                    Some(c) if same_addr_set(&c.addrs, &sup.addrs)
                        && same_addr_set(&c.tls_addrs, &sup.tls_addrs)
                );
                (!keep).then_some(*id)
            })
            .collect();
        for id in stale {
            if let Some(sup) = self.active.remove(&id) {
                info!(edge = %id.fmt_short(), "edge left the set or changed address; stopping supervisor");
                sup.token.cancel();
            }
        }

        for contact in contacts {
            if self.active.contains_key(&contact.id) {
                continue;
            }
            if contact.addrs.is_empty()
                && contact.tls_addrs.is_empty()
                && self.relay_urls.is_empty()
            {
                warn!(
                    edge = %contact.id.fmt_short(),
                    "skipping edge with no advertised socket addresses and no relay configured"
                );
                continue;
            }
            let token = self.shutdown.child_token();
            let id = contact.id;
            info!(edge = %id.fmt_short(), "starting edge supervisor");
            self.tasks.spawn(supervise(
                self.endpoint.clone(),
                contact.clone(),
                Arc::clone(&self.service_map),
                Arc::clone(&self.metrics),
                token.clone(),
                Arc::clone(&self.edge_cred),
                Arc::clone(&self.relay_urls),
                self.tls.clone(),
                self.event_tx.clone(),
            ));
            self.active.insert(
                id,
                ActiveSupervisor {
                    token,
                    addrs: contact.addrs.clone(),
                    tls_addrs: contact.tls_addrs.clone(),
                },
            );
        }
    }

    /// Cancel every supervisor and wait for them to finish.
    pub async fn shutdown(mut self) {
        for (_, sup) in self.active.drain() {
            sup.token.cancel();
        }
        self.tasks.shutdown().await;
    }
}

/// Order-insensitive equality of two advertised-address lists.
fn same_addr_set(a: &[String], b: &[String]) -> bool {
    a.len() == b.len() && {
        let set: std::collections::HashSet<&str> = a.iter().map(String::as_str).collect();
        b.iter().all(|x| set.contains(x.as_str()))
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "per-edge supervisor state threaded through; a context struct would only rename the list"
)]
async fn supervise(
    endpoint: Endpoint,
    contact: EdgeContact,
    service_map: Arc<ServiceMap>,
    metrics: Arc<AgentMetrics>,
    shutdown: CancellationToken,
    edge_cred: Arc<arc_swap::ArcSwapOption<CachedEdgeCred>>,
    relay_urls: Arc<Vec<RelayUrl>>,
    tls: TlsDialer,
    events: tokio::sync::mpsc::UnboundedSender<SessionEvent>,
) {
    let edge_label = contact.id.fmt_short().to_string();
    let memory = TransportMemory::new(QUIC_RETRY_AFTER);
    let timeouts = std::sync::atomic::AtomicU32::new(0);
    let span = info_span!("edge_supervisor", edge = %edge_label);
    // A permanently-gone edge is cancelled by reconcile, so this just redials a
    // transiently-down one until it returns. Backoff escalates while dials keep
    // failing fast and resets once a session has held for a while.
    let (
        endpoint,
        contact,
        service_map,
        metrics,
        edge_cred,
        relay_urls,
        tls,
        memory,
        events,
        timeouts,
    ) = (
        &endpoint,
        &contact,
        &service_map,
        &metrics,
        &edge_cred,
        &relay_urls,
        &tls,
        &memory,
        &events,
        &timeouts,
    );
    crate::retry::supervise(
        &format!("edge:{edge_label}"),
        &shutdown,
        REDIAL_DELAY,
        REDIAL_MAX_DELAY,
        || async move {
            let session = match dial_and_serve(
                endpoint,
                contact,
                service_map,
                metrics,
                edge_cred,
                relay_urls,
                tls,
                memory,
                events,
                timeouts,
            )
            .await
            {
                Ok(session) => session,
                Err(e) if is_identity_mismatch(&e) => {
                    metrics
                        .edge_identity_mismatches
                        .with_label_values(&[&contact.id.fmt_short().to_string()])
                        .inc();
                    error!(
                        addrs = ?contact.addrs,
                        tls_addrs = ?contact.tls_addrs,
                        cooldown_secs = IDENTITY_MISMATCH_COOLDOWN.as_secs(),
                        "edge answered with a different endpoint identity than the hub \
                         advertised; the address belongs to another node"
                    );
                    // Ok, not Err: the supervisor would treat it as transient.
                    tokio::time::sleep(IDENTITY_MISMATCH_COOLDOWN).await;
                    return Ok(());
                }
                Err(e) => return Err(e),
            };
            debug!(session_secs = session.as_secs(), "session ended; redialing");
            Ok(())
        },
    )
    .instrument(span)
    .await;
}

/// True when the peer's key didn't match the endpoint id we dialed. For QUIC
/// only our own alert counts; the peer's would arrive as `ConnectionClosed`.
fn is_identity_mismatch(err: &anyhow::Error) -> bool {
    err.chain().any(|source| {
        matches!(
            source.downcast_ref::<ConnectError>(),
            Some(ConnectError::Connection {
                source: ConnectionError::TransportError(e),
                ..
            }) if e.code == TransportErrorCode::crypto(TLS_ALERT_UNKNOWN_CA)
        ) || source
            .downcast_ref::<std::io::Error>()
            .is_some_and(towonel_common::transport::tls::is_pin_mismatch)
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transport {
    Quic,
    Tls,
}

fn record_dial_failure(
    error: &anyhow::Error,
    timeouts: &std::sync::atomic::AtomicU32,
    events: &tokio::sync::mpsc::UnboundedSender<SessionEvent>,
) {
    use std::sync::atomic::Ordering;

    if error
        .chain()
        .any(<dyn std::error::Error>::is::<tokio::time::error::Elapsed>)
    {
        if timeouts.fetch_add(1, Ordering::Relaxed) + 1 >= REBUILD_AFTER_TIMEOUTS {
            drop(events.send(SessionEvent::ConnectTimeouts));
        }
    } else {
        timeouts.store(0, Ordering::Relaxed);
    }
}

/// Transports to try for this redial, in order. QUIC leads unless it failed
/// recently and TLS is on offer.
fn dial_order(can_quic: bool, can_tls: bool, quic_recently_failed: bool) -> Vec<Transport> {
    match (can_quic, can_tls) {
        (true, true) if quic_recently_failed => vec![Transport::Tls, Transport::Quic],
        (true, true) => vec![Transport::Quic, Transport::Tls],
        (true, false) => vec![Transport::Quic],
        (false, true) => vec![Transport::Tls],
        (false, false) => Vec::new(),
    }
}

struct Dialed {
    conn: TunnelConn,
    /// Kept for the path watcher, which only QUIC has.
    quic: Option<iroh::endpoint::Connection>,
    transport: Transport,
}

async fn connect_quic(
    endpoint: &Endpoint,
    contact: &EdgeContact,
    relay_urls: &[RelayUrl],
) -> anyhow::Result<iroh::endpoint::Connection> {
    let resolved = resolve_addrs(&contact.addrs).await;
    if resolved.is_empty() && relay_urls.is_empty() {
        anyhow::bail!("no addresses resolved for edge {}", contact.id.fmt_short());
    }
    // Offer both: iroh prefers the direct path, falls back to relay.
    let mut addr = EndpointAddr::new(contact.id);
    for sock in resolved {
        addr = addr.with_ip_addr(sock);
    }
    for relay in relay_urls {
        addr = addr.with_relay_url(relay.clone());
    }
    tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(addr, ALPN_TUNNEL))
        .await
        .with_context(|| format!("connect to edge {} timed out", contact.id.fmt_short()))?
        .with_context(|| format!("connect to edge {} failed", contact.id.fmt_short()))
}

/// Bounded as a whole, not per address: with several addresses that all black-hole,
/// per-address timeouts would stack well past QUIC's single `CONNECT_TIMEOUT`.
async fn connect_tls(tls: &TlsDialer, contact: &EdgeContact) -> anyhow::Result<TunnelConn> {
    tokio::time::timeout(CONNECT_TIMEOUT, connect_tls_addrs(tls, contact))
        .await
        .with_context(|| format!("TLS dial to edge {} timed out", contact.id.fmt_short()))?
}

async fn connect_tls_addrs(tls: &TlsDialer, contact: &EdgeContact) -> anyhow::Result<TunnelConn> {
    let resolved = resolve_addrs(&contact.tls_addrs).await;
    let mut last: Option<anyhow::Error> = None;
    for addr in resolved {
        let attempt = async {
            let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
                .await
                .with_context(|| format!("TCP connect to {addr} timed out"))?
                .with_context(|| format!("TCP connect to {addr} failed"))?;
            tls.connect(tcp, contact.id)
                .await
                .with_context(|| format!("TLS handshake with {addr} failed"))
        };
        match attempt.await {
            Ok(conn) => return Ok(TunnelConn::Tls(conn)),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| {
        anyhow::anyhow!(
            "no TLS address resolved for edge {}",
            contact.id.fmt_short()
        )
    }))
}

async fn dial(
    endpoint: &Endpoint,
    contact: &EdgeContact,
    relay_urls: &[RelayUrl],
    tls: &TlsDialer,
    memory: &TransportMemory,
) -> anyhow::Result<Dialed> {
    let can_quic = !contact.addrs.is_empty() || !relay_urls.is_empty();
    let can_tls = !contact.tls_addrs.is_empty();
    let order = dial_order(can_quic, can_tls, memory.quic_recently_failed());
    if order.is_empty() {
        anyhow::bail!(
            "no addresses advertised for edge {}",
            contact.id.fmt_short()
        );
    }

    let mut quic_failed = false;
    let mut mismatch: Option<anyhow::Error> = None;
    let mut last_err: Option<anyhow::Error> = None;
    for transport in order {
        let attempt = match transport {
            Transport::Quic => connect_quic(endpoint, contact, relay_urls)
                .await
                .map(|quic| Dialed {
                    conn: TunnelConn::Iroh(quic.clone()),
                    quic: Some(quic),
                    transport,
                }),
            Transport::Tls => connect_tls(tls, contact).await.map(|conn| Dialed {
                conn,
                quic: None,
                transport,
            }),
        };
        match attempt {
            Ok(dialed) => {
                match transport {
                    Transport::Quic => memory.quic_worked(),
                    // Only a TLS success after a QUIC failure says UDP is the
                    // problem; both failing means the edge is down.
                    Transport::Tls if quic_failed => memory.quic_failed(),
                    Transport::Tls => {}
                }
                return Ok(dialed);
            }
            // This address belongs to another node, but the other transport's
            // address may not; report the mismatch only if nothing connects.
            Err(e) if is_identity_mismatch(&e) => {
                mismatch.get_or_insert(e);
            }
            Err(e) => {
                debug!(edge = %contact.id.fmt_short(), ?transport, error = %e, "dial failed");
                quic_failed |= transport == Transport::Quic;
                last_err = Some(e);
            }
        }
    }
    Err(mismatch
        .or(last_err)
        .unwrap_or_else(|| anyhow::anyhow!("no transport could connect")))
}

/// While a session runs over TLS, tries QUIC every `every` and returns the
/// first connection that comes up.
async fn probe_quic(
    endpoint: &Endpoint,
    contact: &EdgeContact,
    relay_urls: &[RelayUrl],
    every: Duration,
) -> iroh::endpoint::Connection {
    loop {
        tokio::time::sleep(every).await;
        if let Ok(quic) = connect_quic(endpoint, contact, relay_urls).await {
            return quic;
        }
    }
}

/// Dials, then serves until the session ends. A session that fell back to TLS
/// moves to QUIC once it works again. Returns the session duration, or the dial
/// or credential error.
#[expect(
    clippy::too_many_arguments,
    reason = "per-edge supervisor state threaded through; a context struct would only rename the list"
)]
async fn dial_and_serve(
    endpoint: &Endpoint,
    contact: &EdgeContact,
    service_map: &Arc<ServiceMap>,
    metrics: &Arc<AgentMetrics>,
    edge_cred: &Arc<arc_swap::ArcSwapOption<CachedEdgeCred>>,
    relay_urls: &[RelayUrl],
    tls: &TlsDialer,
    memory: &TransportMemory,
    events: &tokio::sync::mpsc::UnboundedSender<SessionEvent>,
    timeouts: &std::sync::atomic::AtomicU32,
) -> anyhow::Result<Duration> {
    let dialed = match dial(endpoint, contact, relay_urls, tls, memory).await {
        Ok(dialed) => dialed,
        Err(error) => {
            record_dial_failure(&error, timeouts, events);
            return Err(error);
        }
    };
    let Dialed {
        mut conn,
        quic,
        mut transport,
    } = dialed;
    timeouts.store(0, std::sync::atomic::Ordering::Relaxed);

    let edge_label = contact.id.fmt_short().to_string();

    // Validate the EdgeCred before counting the session live, so a rejected
    // cred doesn't bump reconnects or flip the session gauge.
    if let Some(cred) = edge_cred.load_full()
        && let Err(e) = present_edge_cred(&conn, &edge_label, &cred).await
    {
        return Err(e);
    }

    info!(edge = %edge_label, ?transport, "edge session established");
    metrics
        .edge_session_reconnects
        .with_label_values(&[&edge_label])
        .inc();
    // Marks the session live; resets the gauge and aborts the path watcher on
    // Drop, surviving a mid-session cancellation (see `EdgeSessionGuard`).
    let mut guard = EdgeSessionGuard::live(Arc::clone(metrics), edge_label.clone(), conn.clone());
    drop(events.send(SessionEvent::Connected));
    guard.path_watcher = quic.map(|quic| watch_path(&quic, &edge_label, metrics));
    if transport == Transport::Tls {
        metrics.set_edge_path(&edge_label, "tls");
    }

    let started = Instant::now();
    loop {
        let serving = tunnel::handle_connection(
            conn.clone(),
            contact.id,
            Arc::clone(service_map),
            Arc::clone(metrics),
        );
        let can_move =
            transport == Transport::Tls && (!contact.addrs.is_empty() || !relay_urls.is_empty());
        if !can_move {
            serving.await;
            break;
        }
        let probe = probe_quic(endpoint, contact, relay_urls, memory.retry_after);
        tokio::select! {
            biased;
            quic = probe => {
                // The edge supersedes this TLS session as soon as QUIC connects,
                // so there is no staying on it: finish the move and, if the
                // credential is then refused, redial.
                info!(edge = %edge_label, "QUIC is reachable again; leaving the TLS session");
                let moved = TunnelConn::Iroh(quic.clone());
                if let Some(cred) = edge_cred.load_full() {
                    present_edge_cred(&moved, &edge_label, &cred).await?;
                }
                memory.quic_worked();
                conn = moved;
                transport = Transport::Quic;
                guard.switch_to(conn.clone(), Some(watch_path(&quic, &edge_label, metrics)));
            }
            () = serving => break,
        }
    }

    Ok(started.elapsed())
}

fn watch_path(
    quic: &iroh::endpoint::Connection,
    edge_label: &str,
    metrics: &Arc<AgentMetrics>,
) -> tokio::task::JoinHandle<()> {
    // iroh usually opens on the relay and upgrades to direct once holepunched.
    tokio::spawn(watch_paths(
        quic.path_events(),
        edge_label.to_string(),
        Arc::clone(metrics),
    ))
}

/// Resets the liveness gauge, aborts the path watcher and closes the connection
/// on Drop, so a cancelled session doesn't skip cleanup while forwarding
/// streams still hold the connection.
struct EdgeSessionGuard {
    metrics: Arc<AgentMetrics>,
    edge_label: String,
    path_watcher: Option<tokio::task::JoinHandle<()>>,
    conn: TunnelConn,
}

impl EdgeSessionGuard {
    fn live(metrics: Arc<AgentMetrics>, edge_label: String, conn: TunnelConn) -> Self {
        metrics.quic.insert(&edge_label, &conn);
        metrics
            .edge_session_state
            .with_label_values(&[&edge_label])
            .set(1);
        Self {
            metrics,
            edge_label,
            path_watcher: None,
            conn,
        }
    }
}

impl EdgeSessionGuard {
    /// Moves the guard to a new connection, closing the one it held.
    fn switch_to(&mut self, conn: TunnelConn, path_watcher: Option<tokio::task::JoinHandle<()>>) {
        self.metrics.clear_edge_path(&self.edge_label);
        self.conn.close(0, b"moved to QUIC");
        self.conn = conn;
        self.metrics.quic.insert(&self.edge_label, &self.conn);
        if let Some(old) = std::mem::replace(&mut self.path_watcher, path_watcher) {
            old.abort();
        }
    }
}

impl Drop for EdgeSessionGuard {
    fn drop(&mut self) {
        self.metrics
            .quic
            .remove(&self.edge_label, self.conn.stable_id());
        self.conn.close(0, b"edge supervisor stopped");
        if let Some(h) = self.path_watcher.take() {
            h.abort();
        }
        self.metrics.clear_edge_path(&self.edge_label);
        self.metrics
            .edge_session_state
            .with_label_values(&[&self.edge_label])
            .set(0);
    }
}

/// A rejected cred means the session is never reported live and no routes
/// will point at it — fail so the supervisor redials with a refreshed cred.
async fn present_edge_cred(
    conn: &TunnelConn,
    edge_label: &str,
    cred: &CachedEdgeCred,
) -> anyhow::Result<()> {
    let result = tokio::time::timeout(PRESENT_CRED_TIMEOUT, do_present_edge_cred(conn, cred)).await;
    match result {
        Ok(Ok(status)) if status == CONTROL_STATUS_OK => {
            info!(edge = %edge_label, "EdgeCred accepted");
            Ok(())
        }
        Ok(Ok(status)) => {
            warn!(edge = %edge_label, status, "EdgeCred rejected by edge");
            anyhow::bail!("edge {edge_label} rejected EdgeCred (status {status})")
        }
        Ok(Err(e)) => {
            warn!(edge = %edge_label, error = %e, "presenting EdgeCred failed");
            Err(e.context("presenting EdgeCred"))
        }
        Err(_) => {
            warn!(edge = %edge_label, "EdgeCred presentation timed out");
            anyhow::bail!("EdgeCred presentation to edge {edge_label} timed out")
        }
    }
}

async fn do_present_edge_cred(conn: &TunnelConn, cred: &CachedEdgeCred) -> anyhow::Result<u8> {
    let (mut send, mut recv) = conn.open_bi().await.context("open control bidi stream")?;
    write_control_prefix(&mut send)
        .await
        .context("write CONTROL_PREFIX")?;
    let frame = AuthFrame {
        kid: cred.kid,
        cred_cbor: cred.cred_cbor.clone(),
        sig: cred.sig,
    }
    .encode();
    send.write_all(&frame).await.context("write auth frame")?;
    send.finish().await.context("finish send stream")?;
    let status = read_control_status(&mut recv)
        .await
        .context("read control status")?;
    Ok(status)
}

/// Mirrors the connection's selected path into `edge_path` until it closes.
async fn watch_paths(mut events: PathEventStream, edge_label: String, metrics: Arc<AgentMetrics>) {
    while let Some(event) = events.next().await {
        if let PathEvent::Selected { remote_addr, .. } = event {
            let path = classify_path(&remote_addr);
            metrics.set_edge_path(&edge_label, path);
            info!(edge = %edge_label, path, "edge path selected");
        }
    }
}

fn classify_path(addr: &TransportAddr) -> &'static str {
    if addr.is_relay() {
        "relay"
    } else if addr.is_ip() {
        "direct"
    } else {
        "custom"
    }
}

async fn resolve_addrs(addrs: &[String]) -> Vec<SocketAddr> {
    let mut resolved = Vec::new();
    for s in addrs {
        match tokio::time::timeout(DNS_TIMEOUT, lookup_host(s)).await {
            Ok(Ok(iter)) => resolved.extend(iter),
            Ok(Err(e)) => warn!(addr = %s, error = %e, "edge address DNS lookup failed"),
            Err(_) => warn!(addr = %s, "edge address DNS lookup timed out"),
        }
    }
    filter_with(resolved, is_routable)
}

// Fall back to the unfiltered list if nothing is routable: iroh may still
// reach the node via the relay, and the v4/v6 mismatch the kernel sees now
// isn't worth turning into a hard failure.
fn filter_with(
    resolved: Vec<SocketAddr>,
    predicate: impl Fn(&SocketAddr) -> bool,
) -> Vec<SocketAddr> {
    let routable: Vec<SocketAddr> = resolved.iter().copied().filter(&predicate).collect();
    if routable.is_empty() {
        return resolved;
    }
    routable
}

// UDP connect performs a kernel route lookup without sending packets, so this
// returns false fast for v6 destinations on v4-only hosts.
fn is_routable(addr: &SocketAddr) -> bool {
    let bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let Ok(sock) = std::net::UdpSocket::bind(bind) else {
        return false;
    };
    sock.connect(addr).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn repeated_connect_timeouts_request_rebuild() {
        let (events, mut received) = tokio::sync::mpsc::unbounded_channel();
        let timeouts = std::sync::atomic::AtomicU32::new(0);
        let elapsed = tokio::time::timeout(Duration::ZERO, std::future::pending::<()>())
            .await
            .unwrap_err();
        let error = anyhow::Error::new(elapsed).context("connect to edge timed out");

        for _ in 0..REBUILD_AFTER_TIMEOUTS - 1 {
            record_dial_failure(&error, &timeouts, &events);
            assert!(received.try_recv().is_err());
        }
        record_dial_failure(&error, &timeouts, &events);
        assert!(matches!(
            received.try_recv(),
            Ok(SessionEvent::ConnectTimeouts)
        ));

        record_dial_failure(&anyhow::anyhow!("connection refused"), &timeouts, &events);
        record_dial_failure(&error, &timeouts, &events);
        assert!(received.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_new_endpoint_recovers_a_one_way_udp_blackhole() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::net::UdpSocket;

        drop(rustls::crypto::ring::default_provider().install_default());
        let edge = quic_endpoint(None, true).await;
        let agent = quic_endpoint(None, false).await;
        let edge_addr = edge.bound_sockets()[0];
        let old_addr = agent.bound_sockets()[0];
        let proxy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let contact = EdgeContact {
            id: edge.id(),
            addrs: vec![proxy.local_addr().unwrap().to_string()],
            tls_addrs: vec![],
        };
        let blocked = Arc::new(AtomicBool::new(false));
        let proxy_task = tokio::spawn({
            let blocked = Arc::clone(&blocked);
            async move {
                let mut client = None;
                let mut buf = vec![0; 65536];
                loop {
                    let (len, source) = proxy.recv_from(&mut buf).await.unwrap();
                    if source == edge_addr {
                        if let Some(target) = client
                            && !(target == old_addr && blocked.load(Ordering::Relaxed))
                        {
                            proxy.send_to(&buf[..len], target).await.unwrap();
                        }
                    } else {
                        client = Some(source);
                        proxy.send_to(&buf[..len], edge_addr).await.unwrap();
                    }
                }
            }
        });
        let accept_task = tokio::spawn({
            let edge = edge.clone();
            async move {
                while let Some(incoming) = edge.accept().await {
                    tokio::spawn(async move {
                        drop(incoming.await);
                    });
                }
            }
        });

        let connection = connect_quic(&agent, &contact, &[]).await.unwrap();
        connection.close(0u32.into(), b"test");
        blocked.store(true, Ordering::Relaxed);
        let error = connect_quic(&agent, &contact, &[]).await.unwrap_err();
        assert!(
            error
                .chain()
                .any(<dyn std::error::Error>::is::<tokio::time::error::Elapsed>)
        );

        let replacement = quic_endpoint(None, false).await;
        assert_ne!(replacement.bound_sockets()[0], old_addr);
        let connection = connect_quic(&replacement, &contact, &[]).await.unwrap();
        connection.close(0u32.into(), b"test");
        replacement.close().await;
        agent.close().await;
        edge.close().await;
        proxy_task.abort();
        accept_task.abort();
    }

    fn has_quic_metrics(metrics: &AgentMetrics) -> bool {
        metrics
            .registry()
            .gather()
            .iter()
            .any(|f| f.name() == "towonel_agent_quic_frames_total")
    }

    const V4: &str = "203.0.113.1:80";
    const V6: &str = "[2001:db8::1]:80";

    #[test]
    fn dial_order_leads_with_quic_unless_it_failed_recently() {
        use Transport::{Quic, Tls};
        assert_eq!(dial_order(true, true, false), [Quic, Tls]);
        assert_eq!(dial_order(true, true, true), [Tls, Quic]);
        assert_eq!(dial_order(true, false, true), [Quic]);
        assert_eq!(dial_order(false, true, false), [Tls]);
        assert!(dial_order(false, false, false).is_empty());
    }

    #[test]
    fn transport_memory_forgets_a_quic_failure_once_it_works() {
        let memory = TransportMemory::new(QUIC_RETRY_AFTER);
        assert!(!memory.quic_recently_failed());
        memory.quic_failed();
        assert!(memory.quic_recently_failed());
        memory.quic_worked();
        assert!(!memory.quic_recently_failed());
    }

    #[tokio::test]
    async fn falls_back_to_tls_and_carries_traffic_when_quic_cannot_dial() {
        use iroh::endpoint::presets::Minimal;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::time::timeout;
        use towonel_common::transport::tls::{TlsIdentity, TlsListener};
        use towonel_common::tunnel::{ClientAddrs, write_handshake};

        const SETUP: Duration = Duration::from_secs(10);
        const HOST: &str = "fallback.test";
        let (origin, services) = origin_and_services(HOST).await;
        let endpoint = Endpoint::builder(Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .bind()
            .await
            .unwrap();

        let edge_identity = TlsIdentity::new(&iroh::SecretKey::generate()).unwrap();
        let agent_key = iroh::SecretKey::generate();
        let edge_socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_addr = edge_socket.local_addr().unwrap().to_string();
        let tls_listener = TlsListener::new(&edge_identity).unwrap();

        let contact = EdgeContact {
            id: edge_identity.id(),
            // Not a socket address, so QUIC fails at once instead of waiting
            // out its connect timeout.
            addrs: vec!["not a socket".to_string()],
            tls_addrs: vec![tls_addr],
        };
        let dialer = TlsDialer::new(TlsIdentity::new(&agent_key).unwrap());
        let metrics = Arc::new(AgentMetrics::new());
        let memory = Arc::new(TransportMemory::new(QUIC_RETRY_AFTER));
        let session = tokio::spawn({
            let (metrics, memory) = (Arc::clone(&metrics), Arc::clone(&memory));
            async move {
                let cred = Arc::new(arc_swap::ArcSwapOption::empty());
                dial_and_serve(
                    &endpoint,
                    &contact,
                    &services,
                    &metrics,
                    &cred,
                    &[],
                    &dialer,
                    &memory,
                    &tokio::sync::mpsc::unbounded_channel().0,
                    &std::sync::atomic::AtomicU32::new(0),
                )
                .await
            }
        });

        let (tcp, _) = timeout(SETUP, edge_socket.accept()).await.unwrap().unwrap();
        let edge_conn = timeout(SETUP, tls_listener.accept(tcp))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(edge_conn.remote_id(), agent_key.public());

        let addrs = ClientAddrs {
            src: "127.0.0.1:12345".parse().unwrap(),
            dst: "127.0.0.1:443".parse().unwrap(),
        };
        let (mut send, mut recv) = edge_conn.open_bi().await.unwrap();
        write_handshake(&mut send, HOST, addrs).await.unwrap();
        send.write_all(b"ping").await.unwrap();
        let (mut socket, _) = timeout(SETUP, origin.accept()).await.unwrap().unwrap();
        let mut request = [0; 4];
        timeout(SETUP, socket.read_exact(&mut request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&request, b"ping");
        socket.write_all(b"pong").await.unwrap();
        let mut reply = [0; 4];
        timeout(SETUP, recv.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"pong");

        assert_eq!(metrics.active_edge_sessions(), 1);
        assert!(memory.quic_recently_failed());
        assert!(
            !has_quic_metrics(&metrics),
            "TLS sessions have no QUIC stats"
        );

        edge_conn.close(0, b"done");
        timeout(SETUP, session).await.unwrap().unwrap().unwrap();
        assert_eq!(metrics.active_edge_sessions(), 0);
    }

    async fn origin_and_services(hostname: &str) -> (tokio::net::TcpListener, Arc<ServiceMap>) {
        use towonel_common::tls_policy::TlsMode;

        use crate::config::{ProxyProtocol, ServiceConfig};

        drop(rustls::crypto::ring::default_provider().install_default());
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let services = Arc::new(
            ServiceMap::from_config(
                &[ServiceConfig {
                    hostname: hostname.to_string(),
                    origin: origin.local_addr().unwrap().to_string(),
                    origin_server_name: None,
                    tls_mode: TlsMode::Passthrough,
                    proxy_protocol: Some(ProxyProtocol::None),
                }],
                &[],
                &[],
            )
            .await
            .unwrap(),
        );
        (origin, services)
    }

    async fn quic_endpoint(secret: Option<iroh::SecretKey>, accept: bool) -> Endpoint {
        use iroh::endpoint::presets::Minimal;

        let mut builder = Endpoint::builder(Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .transport_config(towonel_common::protocol::tunnel_transport_config());
        if let Some(secret) = secret {
            builder = builder.secret_key(secret);
        }
        if accept {
            builder = builder.alpns(vec![ALPN_TUNNEL.to_vec()]);
        }
        builder.bind().await.unwrap()
    }

    #[tokio::test]
    async fn both_transports_failing_does_not_blame_quic() {
        use towonel_common::transport::tls::TlsIdentity;

        let (_origin, services) = origin_and_services("down.test").await;
        let endpoint = quic_endpoint(None, false).await;
        let closed_port = {
            let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            socket.local_addr().unwrap()
        };
        let contact = EdgeContact {
            id: iroh::SecretKey::generate().public(),
            addrs: vec!["not a socket".to_string()],
            tls_addrs: vec![closed_port.to_string()],
        };
        let dialer = TlsDialer::new(TlsIdentity::new(&iroh::SecretKey::generate()).unwrap());
        let metrics = Arc::new(AgentMetrics::new());
        let memory = TransportMemory::new(QUIC_RETRY_AFTER);

        let cred = Arc::new(arc_swap::ArcSwapOption::empty());
        dial_and_serve(
            &endpoint,
            &contact,
            &services,
            &metrics,
            &cred,
            &[],
            &dialer,
            &memory,
            &tokio::sync::mpsc::unbounded_channel().0,
            &std::sync::atomic::AtomicU32::new(0),
        )
        .await
        .unwrap_err();

        assert!(
            !memory.quic_recently_failed(),
            "an edge that is simply down must not push redials onto TLS"
        );
    }

    #[tokio::test]
    async fn a_tls_pin_mismatch_is_an_identity_mismatch() {
        use tokio::net::TcpListener;
        use towonel_common::transport::tls::{TlsIdentity, TlsListener};

        let (_origin, services) = origin_and_services("mismatch.test").await;
        let endpoint = quic_endpoint(None, false).await;
        let edge_identity = TlsIdentity::new(&iroh::SecretKey::generate()).unwrap();
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_addr = socket.local_addr().unwrap().to_string();
        let tls_listener = TlsListener::new(&edge_identity).unwrap();
        tokio::spawn(async move {
            let (tcp, _) = socket.accept().await.unwrap();
            drop(tls_listener.accept(tcp).await);
        });
        // The hub advertised a different node than the one at this address.
        let contact = EdgeContact {
            id: iroh::SecretKey::generate().public(),
            addrs: Vec::new(),
            tls_addrs: vec![tls_addr],
        };
        let dialer = TlsDialer::new(TlsIdentity::new(&iroh::SecretKey::generate()).unwrap());
        let metrics = Arc::new(AgentMetrics::new());
        let memory = TransportMemory::new(QUIC_RETRY_AFTER);

        let cred = Arc::new(arc_swap::ArcSwapOption::empty());
        let err = dial_and_serve(
            &endpoint,
            &contact,
            &services,
            &metrics,
            &cred,
            &[],
            &dialer,
            &memory,
            &tokio::sync::mpsc::unbounded_channel().0,
            &std::sync::atomic::AtomicU32::new(0),
        )
        .await
        .unwrap_err();

        assert!(is_identity_mismatch(&err), "got: {err:#}");
    }

    #[tokio::test]
    async fn a_tls_session_moves_to_quic_once_it_works() {
        use tokio::net::TcpListener;
        use tokio::time::timeout;
        use towonel_common::transport::tls::{TlsIdentity, TlsListener};

        const SETUP: Duration = Duration::from_secs(10);
        let (_origin, services) = origin_and_services("migrate.test").await;
        let edge_key = iroh::SecretKey::generate();
        let quic_edge = quic_endpoint(Some(edge_key.clone()), true).await;
        let agent_endpoint = quic_endpoint(None, false).await;
        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_listener = TlsListener::new(&TlsIdentity::new(&edge_key).unwrap()).unwrap();
        let contact = EdgeContact {
            id: edge_key.public(),
            addrs: quic_edge
                .bound_sockets()
                .iter()
                .map(ToString::to_string)
                .collect(),
            tls_addrs: vec![socket.local_addr().unwrap().to_string()],
        };
        let dialer = TlsDialer::new(TlsIdentity::new(&iroh::SecretKey::generate()).unwrap());
        let metrics = Arc::new(AgentMetrics::new());
        // QUIC "failed" a moment ago, so the dial leads with TLS and the probe
        // retries QUIC after the short window.
        let memory = Arc::new(TransportMemory::new(Duration::from_millis(1500)));
        memory.quic_failed();
        let session = tokio::spawn({
            let (metrics, memory) = (Arc::clone(&metrics), Arc::clone(&memory));
            async move {
                let cred = Arc::new(arc_swap::ArcSwapOption::empty());
                dial_and_serve(
                    &agent_endpoint,
                    &contact,
                    &services,
                    &metrics,
                    &cred,
                    &[],
                    &dialer,
                    &memory,
                    &tokio::sync::mpsc::unbounded_channel().0,
                    &std::sync::atomic::AtomicU32::new(0),
                )
                .await
            }
        });

        let (tcp, _) = timeout(SETUP, socket.accept()).await.unwrap().unwrap();
        let tls_conn = timeout(SETUP, tls_listener.accept(tcp))
            .await
            .unwrap()
            .unwrap();
        let incoming = timeout(SETUP, quic_edge.accept()).await.unwrap().unwrap();
        let quic_conn = timeout(SETUP, incoming).await.unwrap().unwrap();

        // The edge supersedes the TLS session the moment QUIC connects.
        tls_conn.close(0, b"superseded");
        timeout(SETUP, tls_conn.closed()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            !session.is_finished(),
            "the session must outlive the supersede"
        );
        assert!(!memory.quic_recently_failed());
        assert_eq!(metrics.active_edge_sessions(), 1);
        let label = edge_key.public().fmt_short().to_string();
        assert!(
            has_quic_metrics(&metrics),
            "migration must expose QUIC stats"
        );
        assert_eq!(
            metrics.edge_path.with_label_values(&[&label, "tls"]).get(),
            0,
            "the path gauge must stop saying tls"
        );

        quic_conn.close(0u32.into(), b"done");
        timeout(SETUP, session).await.unwrap().unwrap().unwrap();
        assert_eq!(metrics.active_edge_sessions(), 0);
        assert!(!has_quic_metrics(&metrics));
    }

    async fn cancellation_fixture(
        hostname: &str,
    ) -> (
        Endpoint,
        Endpoint,
        tokio::net::TcpListener,
        Arc<AgentMetrics>,
        SupervisorPool,
    ) {
        use iroh::endpoint::presets::Minimal;
        use tokio::net::TcpListener;
        use towonel_common::tls_policy::TlsMode;

        use crate::config::{ProxyProtocol, ServiceConfig};

        drop(rustls::crypto::ring::default_provider().install_default());
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let services = Arc::new(
            ServiceMap::from_config(
                &[ServiceConfig {
                    hostname: hostname.to_string(),
                    origin: origin.local_addr().unwrap().to_string(),
                    origin_server_name: None,
                    tls_mode: TlsMode::Passthrough,
                    proxy_protocol: Some(ProxyProtocol::None),
                }],
                &[],
                &[],
            )
            .await
            .unwrap(),
        );
        let edge = Endpoint::builder(Minimal)
            .alpns(vec![ALPN_TUNNEL.to_vec()])
            .relay_mode(iroh::RelayMode::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .transport_config(towonel_common::protocol::tunnel_transport_config())
            .bind()
            .await
            .unwrap();
        let agent = Endpoint::builder(Minimal)
            .relay_mode(iroh::RelayMode::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .transport_config(towonel_common::protocol::tunnel_transport_config())
            .bind()
            .await
            .unwrap();
        let metrics = Arc::new(AgentMetrics::new());
        let cred = Arc::new(arc_swap::ArcSwapOption::empty());
        let shutdown = CancellationToken::new();
        let tls = TlsDialer::new(
            towonel_common::transport::tls::TlsIdentity::new(&iroh::SecretKey::generate()).unwrap(),
        );
        let mut pool =
            SupervisorPool::new(&agent, &services, &metrics, &cred, vec![], tls, &shutdown);
        pool.reconcile(&[EdgeContact {
            id: edge.id(),
            addrs: edge
                .bound_sockets()
                .iter()
                .map(ToString::to_string)
                .collect(),
            tls_addrs: Vec::new(),
        }]);
        (edge, agent, origin, metrics, pool)
    }

    #[tokio::test]
    async fn cancelled_supervisor_does_not_leave_routable_unserved_connection() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout;
        use towonel_common::tunnel::{ClientAddrs, write_handshake};

        const SETUP: Duration = Duration::from_secs(3);
        const HOST: &str = "cancel.test";

        let (edge, agent, origin, metrics, mut pool) = cancellation_fixture(HOST).await;
        // Only forwarding tasks retain the agent connection.
        let peer = timeout(SETUP, async { edge.accept().await.unwrap().await.unwrap() })
            .await
            .unwrap();
        let addrs = ClientAddrs {
            src: "127.0.0.1:12345".parse().unwrap(),
            dst: "127.0.0.1:443".parse().unwrap(),
        };
        let (mut first_send, mut first_recv) = peer.open_bi().await.unwrap();
        write_handshake(&mut first_send, HOST, addrs).await.unwrap();
        first_send.write_all(b"ping").await.unwrap();
        let (mut socket, _) = timeout(SETUP, origin.accept()).await.unwrap().unwrap();
        let (release_origin, hold_origin) = tokio::sync::oneshot::channel();
        let origin_task = tokio::spawn(async move {
            let mut buf = [0; 4];
            loop {
                let n = socket.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                socket.write_all(&buf[..n]).await.unwrap();
            }
            // Hold the origin write half open until forwarding tasks exit.
            hold_origin.await.unwrap();
            drop(socket);
        });
        let mut reply = [0; 4];
        timeout(SETUP, first_recv.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"ping");
        assert_eq!(metrics.active_edge_sessions(), 1);
        assert_eq!(metrics.streams_active.get(), 1);
        assert!(has_quic_metrics(&metrics));

        pool.reconcile(&[]);
        timeout(SETUP, pool.tasks.join_next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(metrics.active_edge_sessions(), 0);
        timeout(SETUP, peer.closed())
            .await
            .expect("session still open after cancellation");
        assert!(
            !has_quic_metrics(&metrics),
            "cancellation must remove QUIC stats"
        );
        let _closed = peer
            .open_bi()
            .await
            .expect_err("closed session accepted a stream");
        let forwarding_released = timeout(SETUP, async {
            while metrics.streams_active.get() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        release_origin.send(()).unwrap();
        timeout(SETUP, origin_task).await.unwrap().unwrap();
        pool.shutdown().await;
        agent.close().await;
        edge.close().await;
        forwarding_released.expect("forwarding tasks still active after cancellation");
    }

    /// Context-wrapped like `dial_and_serve` reports it, so the chain walk is
    /// what's under test.
    fn dial_error(alert: u8) -> anyhow::Error {
        let transport = iroh::endpoint::TransportError::new(
            TransportErrorCode::crypto(alert),
            "invalid peer certificate: UnknownIssuer".to_string(),
        );
        anyhow::Error::new(ConnectError::from(ConnectionError::TransportError(
            transport,
        )))
        .context("connect to edge b1f027564a failed")
    }

    #[test]
    fn unknown_ca_is_an_identity_mismatch() {
        assert!(is_identity_mismatch(&dial_error(TLS_ALERT_UNKNOWN_CA)));
    }

    #[test]
    fn other_crypto_alerts_are_not() {
        // 42, bad_certificate.
        assert!(!is_identity_mismatch(&dial_error(42)));
    }

    #[test]
    fn unrelated_errors_are_not() {
        assert!(!is_identity_mismatch(&anyhow::anyhow!("dns lookup failed")));
    }

    #[test]
    fn loopback_is_routable() {
        assert!(is_routable(&"127.0.0.1:1".parse().unwrap()));
    }

    #[test]
    fn empty_input() {
        assert!(filter_with(Vec::new(), |_| true).is_empty());
    }

    #[test]
    fn drops_rejected() {
        let v4: SocketAddr = V4.parse().unwrap();
        let v6: SocketAddr = V6.parse().unwrap();
        assert_eq!(filter_with(vec![v4, v6], SocketAddr::is_ipv4), vec![v4]);
    }

    #[test]
    fn falls_back_when_all_rejected() {
        let input: Vec<SocketAddr> = vec![V4.parse().unwrap(), V6.parse().unwrap()];
        assert_eq!(filter_with(input.clone(), |_| false), input);
    }

    #[test]
    fn classify_path_maps_transport_addr() {
        let ip = TransportAddr::Ip(V4.parse().unwrap());
        let relay = TransportAddr::Relay("https://relay.example".parse().unwrap());
        assert_eq!(classify_path(&ip), "direct");
        assert_eq!(classify_path(&relay), "relay");
    }
}
