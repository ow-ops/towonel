use std::collections::HashMap;
use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Context;
use arc_swap::ArcSwap;
use rustls::pki_types::ServerName;
use tokio::io::{self, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tracing::{Instrument, debug, info, info_span, warn};

use towonel_common::hostname::wildcard_lookup;
use towonel_common::metrics::GaugeGuard;
use towonel_common::transport::{TunnelConn, TunnelRecv, TunnelSend};
use towonel_common::tunnel::{
    CONTROL_OPCODE_STREAM_ACK, CONTROL_STATUS_NOT_IMPLEMENTED, CONTROL_STATUS_OK, COPY_BUF_SIZE,
    ClientAddrs, CountingWriter, DatagramFrameReader, MAX_UDP_DATAGRAM, STREAM_ACK_PREFIX,
    TCP_ROUTE_PREFIX, UDP_ROUTE_PREFIX, copy_buf_counting, copy_tcp_counting, read_control_status,
    read_handshake, write_control_prefix, write_control_status, write_datagram_frame,
};

use crate::config::{ProxyProtocol, ServiceConfig, TcpServiceConfig, UdpServiceConfig};
use crate::metrics::{self, AgentMetrics};

mod proxy_protocol;

const DNS_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Cap on how long we wait for an edge to send the (hostname, client-addrs)
/// handshake bytes. Bounded to stop silent/malicious edges pinning tasks open.
const STREAM_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Cap on concurrent in-flight streams per edge connection. A buggy or
/// compromised edge can open bi-streams in a tight loop; without a bound the
/// agent would spawn an unbounded number of tasks and OOM. Reaching the cap
/// applies QUIC backpressure rather than dropping streams.
const MAX_CONCURRENT_STREAMS: usize =
    towonel_common::protocol::TUNNEL_MAX_CONCURRENT_STREAMS as usize;

/// Bound on each TCP/UDP `connect` to the configured origin. A tarpitting
/// or firewall-dropped origin must not pin an agent task indefinitely.
const ORIGIN_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Bound on the TLS handshake when the origin is `tls=true`. A peer that
/// accepts the TCP but never completes TLS would otherwise stall the task.
const ORIGIN_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Keepalive on origin sockets so the kernel reaps a half-open origin (gone
/// without FIN/RST) instead of leaving the copy blocked on it forever, leaking
/// the socket FD.
const ORIGIN_KEEPALIVE_IDLE: Duration = Duration::from_mins(1);
const ORIGIN_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Set `TCP_NODELAY` + `SO_KEEPALIVE` on a freshly connected origin socket.
fn configure_origin_socket(stream: &TcpStream) {
    if let Err(e) = stream.set_nodelay(true) {
        warn!(error = %e, "failed to set TCP_NODELAY on origin socket");
    }
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(ORIGIN_KEEPALIVE_IDLE)
        .with_interval(ORIGIN_KEEPALIVE_INTERVAL);
    if let Err(e) = socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive) {
        warn!(error = %e, "failed to set SO_KEEPALIVE on origin socket");
    }
}

async fn tcp_connect_timeout<A>(addr: A) -> std::io::Result<TcpStream>
where
    A: tokio::net::ToSocketAddrs,
{
    let stream = tokio::time::timeout(ORIGIN_CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .unwrap_or_else(|_elapsed| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "origin TCP connect timed out",
            ))
        })?;
    configure_origin_socket(&stream);
    Ok(stream)
}

/// Bound DNS resolution so a slow/hostile resolver can't pin tasks.
async fn lookup_host_timeout(host: &str) -> std::io::Result<Vec<SocketAddr>> {
    tokio::time::timeout(ORIGIN_CONNECT_TIMEOUT, lookup_host(host))
        .await
        .unwrap_or_else(|_elapsed| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "DNS lookup timed out",
            ))
        })
        .map(Iterator::collect)
}

async fn write_proxy_header(
    stream: &mut (impl AsyncWrite + Unpin),
    mode: ProxyProtocol,
    addrs: ClientAddrs,
) -> anyhow::Result<()> {
    let bytes = encode_proxy_header(mode, addrs)?;
    if !bytes.is_empty() {
        stream.write_all(&bytes).await?;
    }
    Ok(())
}

fn encode_proxy_header(mode: ProxyProtocol, addrs: ClientAddrs) -> anyhow::Result<Vec<u8>> {
    if mode == ProxyProtocol::V2 {
        proxy_protocol::encode_v2(addrs)
    } else {
        Ok(Vec::new())
    }
}

struct OriginTarget {
    address: String,
    /// Empty means resolution has never succeeded; callers fall back to a
    /// direct `TcpStream::connect(&address)` so a transient DNS outage at
    /// startup doesn't permanently break a service.
    resolved: ArcSwap<Vec<SocketAddr>>,
    is_literal: bool,
    /// Precomputed rustls `ServerName` for TLS-wrapped origins. Parsed once
    /// at config load time; cloning at stream open is cheap (owned `DnsName`
    /// wrapper, no extra validation).
    server_name: Option<ServerName<'static>>,
    proxy_protocol: ProxyProtocol,
}

impl OriginTarget {
    async fn connect(&self) -> anyhow::Result<TcpStream> {
        connect_tcp_origin(&self.address, &self.resolved).await
    }

    /// Dial the same origin host on port 80. ACME HTTP-01 (and any other
    /// `:80` traffic the edge routes here) always terminates at the
    /// origin's HTTP entrypoint, regardless of what port the configured
    /// `address` points at.
    async fn connect_http(&self) -> anyhow::Result<TcpStream> {
        let cached = self.resolved.load();
        let mut last_err: Option<std::io::Error> = None;
        for addr in cached.iter() {
            let mut at_port = *addr;
            at_port.set_port(80);
            match tcp_connect_timeout(at_port).await {
                Ok(s) => return Ok(s),
                Err(e) => last_err = Some(e),
            }
        }
        if let Some(e) = last_err {
            debug!(origin = %self.address, error = %e, "cached addrs exhausted on :80, re-resolving");
        }
        let host = host_of(&self.address);
        tcp_connect_timeout((host, 80))
            .await
            .with_context(|| format!("failed to connect to origin {host}:80"))
    }
}

fn host_of(address: &str) -> &str {
    if let Some(rest) = address.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return rest.get(..end).unwrap_or(rest);
    }
    address.rsplit_once(':').map_or(address, |(host, _)| host)
}

struct TcpOriginTarget {
    address: String,
    resolved: ArcSwap<Vec<SocketAddr>>,
    is_literal: bool,
    proxy_protocol: ProxyProtocol,
}

impl TcpOriginTarget {
    async fn connect(&self) -> anyhow::Result<TcpStream> {
        connect_tcp_origin(&self.address, &self.resolved).await
    }
}

/// Fall back to a fresh `TcpStream::connect(address)` when the cached addrs
/// are empty or all fail, so a startup DNS miss doesn't permanently brick the
/// service.
async fn connect_tcp_origin(
    address: &str,
    resolved: &ArcSwap<Vec<SocketAddr>>,
) -> anyhow::Result<TcpStream> {
    let cached = resolved.load();
    if !cached.is_empty() {
        let mut last_err: Option<std::io::Error> = None;
        for addr in cached.iter() {
            match tcp_connect_timeout(addr).await {
                Ok(s) => return Ok(s),
                Err(e) => last_err = Some(e),
            }
        }
        if let Some(e) = last_err {
            debug!(origin = %address, error = %e, "cached addrs exhausted, re-resolving");
        }
    }
    tcp_connect_timeout(address)
        .await
        .with_context(|| format!("failed to connect to origin {address}"))
}

/// One ephemeral UDP socket is opened per session, giving each remote client
/// its own source port at the origin — the same isolation classic NAT gives.
struct UdpOriginTarget {
    address: String,
    resolved: ArcSwap<Vec<SocketAddr>>,
    is_literal: bool,
    /// For port-range services the origin is host-only and each edge port is
    /// forwarded to the origin at the *same* port; the cached addresses carry
    /// port 0 and the connect port comes from the listener. Single-port
    /// services keep their configured origin port (`false`).
    use_listener_port: bool,
}

impl UdpOriginTarget {
    async fn connect(&self, listener_port: u16) -> anyhow::Result<UdpSocket> {
        let cached = self.resolved.load();
        let mut chosen: SocketAddr = if let Some(addr) = cached.first().copied() {
            addr
        } else {
            // Fall back to a fresh resolve so a transient startup DNS miss
            // doesn't permanently brick this service. Host-only (range) origins
            // resolve with a placeholder `:0` port that the listener overrides.
            let target = if self.use_listener_port {
                format!("{}:0", self.address)
            } else {
                self.address.clone()
            };
            lookup_host_timeout(&target)
                .await
                .with_context(|| format!("failed to resolve udp origin {}", self.address))?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!("udp origin {} resolved to no addresses", self.address)
                })?
        };
        if self.use_listener_port {
            chosen.set_port(listener_port);
        }
        let bind_addr: SocketAddr = match chosen {
            SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            SocketAddr::V6(_) => SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
        };
        let socket = UdpSocket::bind(bind_addr).await.with_context(|| {
            format!(
                "failed to bind ephemeral udp socket for origin {}",
                self.address
            )
        })?;
        let connect = tokio::time::timeout(ORIGIN_CONNECT_TIMEOUT, socket.connect(chosen))
            .await
            .map_err(|elapsed| {
                anyhow::anyhow!("UDP connect to origin {chosen} timed out: {elapsed}")
            })?;
        connect.with_context(|| format!("failed to connect udp socket to origin {chosen}"))?;
        Ok(socket)
    }
}

pub struct ServiceMap {
    services: HashMap<String, Arc<OriginTarget>>,
    tcp_services: HashMap<String, Arc<TcpOriginTarget>>,
    udp_services: HashMap<String, Arc<UdpOriginTarget>>,
    /// Shared rustls client config for TLS-wrapped origin connections. Built
    /// once at startup from the webpki roots and reused for every stream.
    tls_config: Arc<rustls::ClientConfig>,
}

impl ServiceMap {
    pub async fn from_config(
        services: &[ServiceConfig],
        tcp_services: &[TcpServiceConfig],
        udp_services: &[UdpServiceConfig],
    ) -> anyhow::Result<Self> {
        let mut map: HashMap<String, Arc<OriginTarget>> = HashMap::new();
        for svc in services {
            let (initial, is_literal) = resolve_origin(&svc.origin).await;
            let server_name = svc
                .origin_server_name
                .as_deref()
                .map(|name| {
                    ServerName::try_from(name.to_string()).map_err(|e| {
                        anyhow::anyhow!(
                            "service {:?}: invalid origin_server_name {name:?}: {e}",
                            svc.hostname
                        )
                    })
                })
                .transpose()?;
            let target = Arc::new(OriginTarget {
                address: svc.origin.clone(),
                resolved: ArcSwap::from_pointee(initial),
                is_literal,
                server_name,
                proxy_protocol: svc.resolved_proxy_protocol(),
            });
            map.insert(svc.hostname.to_lowercase(), target);
        }

        let mut tcp_map: HashMap<String, Arc<TcpOriginTarget>> = HashMap::new();
        for svc in tcp_services {
            let (initial, is_literal) = resolve_origin(&svc.origin).await;
            let target = Arc::new(TcpOriginTarget {
                address: svc.origin.clone(),
                resolved: ArcSwap::from_pointee(initial),
                is_literal,
                proxy_protocol: svc.resolved_proxy_protocol(),
            });
            tcp_map.insert(svc.name.clone(), target);
        }

        let mut udp_map: HashMap<String, Arc<UdpOriginTarget>> = HashMap::new();
        for svc in udp_services {
            // Range services forward each port to the origin host at the same
            // port, so their origin is host-only and resolves with port 0.
            let (initial, is_literal) = if svc.is_range() {
                resolve_origin_host_only(&svc.origin).await
            } else {
                resolve_origin(&svc.origin).await
            };
            let target = Arc::new(UdpOriginTarget {
                address: svc.origin.clone(),
                resolved: ArcSwap::from_pointee(initial),
                is_literal,
                use_listener_port: svc.is_range(),
            });
            udp_map.insert(svc.name.clone(), target);
        }

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.resumption = rustls::client::Resumption::in_memory_sessions(1024);
        let tls_config = Arc::new(config);

        Ok(Self {
            services: map,
            tcp_services: tcp_map,
            udp_services: udp_map,
            tls_config,
        })
    }

    /// Runs for the lifetime of the agent; no handle is returned because
    /// there is no cooperative shutdown path to call it from.
    pub fn spawn_dns_refresher(&self) {
        let hostname_targets: Vec<Arc<OriginTarget>> = self
            .services
            .values()
            .filter(|t| !t.is_literal)
            .cloned()
            .collect();
        let tcp_targets: Vec<Arc<TcpOriginTarget>> = self
            .tcp_services
            .values()
            .filter(|t| !t.is_literal)
            .cloned()
            .collect();
        let udp_targets: Vec<Arc<UdpOriginTarget>> = self
            .udp_services
            .values()
            .filter(|t| !t.is_literal)
            .cloned()
            .collect();
        if hostname_targets.is_empty() && tcp_targets.is_empty() && udp_targets.is_empty() {
            return;
        }
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(DNS_REFRESH_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await; // tokio interval fires immediately; skip it
            loop {
                ticker.tick().await;
                for target in &hostname_targets {
                    refresh_addr(&target.address, &target.resolved).await;
                }
                for target in &tcp_targets {
                    refresh_addr(&target.address, &target.resolved).await;
                }
                for target in &udp_targets {
                    refresh_addr(&target.address, &target.resolved).await;
                }
            }
        });
    }

    fn lookup(&self, hostname: &str) -> Option<&Arc<OriginTarget>> {
        wildcard_lookup(hostname, |key| self.services.get(key))
    }

    fn lookup_tcp(&self, name: &str) -> Option<&Arc<TcpOriginTarget>> {
        self.tcp_services.get(name)
    }

    fn lookup_udp(&self, name: &str) -> Option<&Arc<UdpOriginTarget>> {
        self.udp_services.get(name)
    }
}

async fn refresh_addr(address: &str, resolved: &ArcSwap<Vec<SocketAddr>>) {
    match lookup_host_timeout(address).await {
        Ok(addrs) => {
            if !addrs.is_empty() {
                resolved.store(Arc::new(addrs));
            }
        }
        Err(e) => {
            debug!(origin = %address, error = %e, "DNS refresh failed");
        }
    }
}

async fn resolve_origin(origin: &str) -> (Vec<SocketAddr>, bool) {
    if let Ok(addr) = origin.parse::<SocketAddr>() {
        return (vec![addr], true);
    }
    match lookup_host_timeout(origin).await {
        Ok(addrs) => (addrs, false),
        Err(e) => {
            warn!(origin, error = %e, "initial DNS resolution failed; will retry on first connect");
            (Vec::new(), false)
        }
    }
}

/// Resolve a host-only origin (no `:port`) to addresses with a placeholder
/// port 0; the actual connect port is supplied per-session by the listener.
/// Used by UDP port-range services.
async fn resolve_origin_host_only(host: &str) -> (Vec<SocketAddr>, bool) {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return (vec![SocketAddr::new(ip, 0)], true);
    }
    match lookup_host_timeout(&format!("{host}:0")).await {
        Ok(addrs) => (addrs, false),
        Err(e) => {
            warn!(origin = host, error = %e, "initial DNS resolution failed; will retry on first connect");
            (Vec::new(), false)
        }
    }
}

pub async fn handle_connection(
    conn: TunnelConn,
    remote_id: iroh::EndpointId,
    service_map: Arc<ServiceMap>,
    metrics: Arc<AgentMetrics>,
) {
    let stream_limit = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_STREAMS));
    handle_connection_with_stream_limit(conn, remote_id, service_map, metrics, stream_limit).await;
}

async fn handle_connection_with_stream_limit(
    conn: TunnelConn,
    remote_id: iroh::EndpointId,
    service_map: Arc<ServiceMap>,
    metrics: Arc<AgentMetrics>,
    stream_limit: Arc<tokio::sync::Semaphore>,
) {
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn({
        let conn = conn.clone();
        async move {
            if let Err(e) = enable_stream_acks(&conn).await {
                warn!(error = %e, "enabling stream acknowledgements failed");
                conn.close(504, b"stream acknowledgement negotiation failed");
            }
        }
    });
    loop {
        while tasks.try_join_next().is_some() {}
        // Backpressure stream opens, but still exit if a saturated session closes.
        let Ok(permit) = tokio::select! (
            permit = Arc::clone(&stream_limit).acquire_owned() => permit,
            error = conn.closed() => {
                info!("connection closed: {error}");
                return;
            }
        ) else {
            return;
        };
        let (send, recv) = match conn.accept_bi().await {
            Ok(streams) => streams,
            Err(e) => {
                info!("connection closed: {e}");
                return;
            }
        };

        let map = Arc::clone(&service_map);
        let m = Arc::clone(&metrics);
        tasks.spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_stream(send, recv, &map, remote_id, &m).await {
                if e.is::<CopyError>() {
                    debug!("stream error: {e}");
                } else {
                    warn!("stream error: {e}");
                }
            }
        });
    }
}

async fn enable_stream_acks(conn: &TunnelConn) -> io::Result<()> {
    let exchange = async {
        let (mut send, mut recv) = conn.open_bi().await?;
        write_control_prefix(&mut send).await?;
        send.write_all(&[CONTROL_OPCODE_STREAM_ACK]).await?;
        send.finish().await?;
        let status = read_control_status(&mut recv).await?;
        if status == CONTROL_STATUS_NOT_IMPLEMENTED {
            debug!(status, "edge does not support stream acknowledgements");
        } else if status != CONTROL_STATUS_OK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "edge rejected stream acknowledgement negotiation",
            ));
        }
        Ok(())
    };
    tokio::time::timeout(Duration::from_secs(15), exchange)
        .await
        .map_err(|_elapsed| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "stream acknowledgement negotiation timed out",
            )
        })?
}

#[expect(
    clippy::too_many_lines,
    reason = "stream dispatch dispatches over PROXY/TLS/TCP shapes; splitting fragments the flow"
)]
async fn handle_stream(
    mut quic_send: TunnelSend,
    mut quic_recv: TunnelRecv,
    service_map: &ServiceMap,
    edge_id: iroh::EndpointId,
    metrics: &AgentMetrics,
) -> anyhow::Result<()> {
    let start = Instant::now();
    metrics.streams_accepted.inc();
    let _active = GaugeGuard::inc(&metrics.streams_active);

    let handshake = async {
        read_handshake(&mut quic_recv)
            .await
            .context("failed to read PROXY v2 preamble")
    };
    let (route_key, client_addrs) =
        match tokio::time::timeout(STREAM_HANDSHAKE_TIMEOUT, handshake).await {
            Err(_) => {
                metrics.record_stream_error(metrics::stream_error::HANDSHAKE_TIMEOUT);
                return Err(anyhow::anyhow!("stream handshake timed out"));
            }
            Ok(Err(e)) => {
                metrics.record_stream_error(metrics::stream_error::HANDSHAKE_ERROR);
                return Err(e);
            }
            Ok(Ok(v)) => v,
        };

    let route_key = if let Some(route_key) = route_key.strip_prefix(STREAM_ACK_PREFIX) {
        write_control_status(&mut quic_send, CONTROL_STATUS_OK).await?;
        route_key
    } else {
        &route_key
    };

    if let Some(service_name) = route_key.strip_prefix(TCP_ROUTE_PREFIX) {
        return handle_tcp_stream(
            service_name,
            client_addrs,
            quic_send,
            quic_recv,
            service_map,
            edge_id,
            metrics,
            start,
        )
        .await;
    }

    if let Some(service_name) = route_key.strip_prefix(UDP_ROUTE_PREFIX) {
        return handle_udp_stream(
            service_name,
            client_addrs,
            quic_send,
            quic_recv,
            service_map,
            edge_id,
            metrics,
            start,
        )
        .await;
    }

    let hostname = route_key;
    let Some(target) = service_map.lookup(hostname) else {
        metrics.record_stream_error(metrics::stream_error::NO_SERVICE);
        return Err(anyhow::anyhow!(
            "no service configured for hostname {hostname}"
        ));
    };

    let span = info_span!("stream",
        %hostname,
        origin = %target.address,
        edge = %edge_id.fmt_short(),
        client = ?client_addrs.src,
    );

    async {
        debug!("forwarding to origin");

        let is_http_ingress = client_addrs.dst.port() == 80;

        let tcp_stream = if is_http_ingress {
            target.connect_http().await
        } else {
            target.connect().await
        };
        let tcp_stream = match tcp_stream {
            Ok(s) => s,
            Err(e) => {
                metrics.record_stream_error(metrics::stream_error::ORIGIN_CONNECT);
                return Err(e);
            }
        };

        // `:80` ingress is always cleartext, even if the route configured
        // `origin_server_name` for the `:443` path.
        let forward_res = match (&target.server_name, is_http_ingress) {
            (Some(sni), false) => {
                forward_tls(
                    tcp_stream,
                    sni.clone(),
                    Arc::clone(&service_map.tls_config),
                    target.proxy_protocol,
                    client_addrs,
                    &mut quic_recv,
                    &mut quic_send,
                    metrics,
                )
                .await
            }
            _ => {
                forward_plain(
                    tcp_stream,
                    target.proxy_protocol,
                    client_addrs,
                    &mut quic_recv,
                    &mut quic_send,
                    metrics,
                )
                .await
            }
        };

        if let Err(e) = forward_res {
            metrics.record_stream_error(metrics::stream_error::FORWARD_ERROR);
            return Err(e);
        }

        metrics.streams_completed.inc();
        // truncation is intentional: streams won't last 584 million years
        #[expect(
            clippy::cast_possible_truncation,
            reason = "streams won't last 584 million years"
        )]
        let duration_ms = start.elapsed().as_millis() as u64;
        debug!(duration_ms, "stream closed");
        Ok(())
    }
    .instrument(span)
    .await
}

/// A forward that ended on an I/O error in either direction: usually the
/// client or the origin hanging up. Counted in `stream_errors`, logged at debug.
#[derive(Debug)]
struct CopyError(&'static str);

impl std::fmt::Display for CopyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ended with a copy error", self.0)
    }
}

impl std::error::Error for CopyError {}

/// Runs a stream's two directions: `request` from the edge to the origin and
/// `reply` back.
///
/// A reply that fails means the origin is gone, so the request is cut short
/// (`None`). A request that fails does not end the reply: an origin may answer
/// and close while the client is still sending, and that answer must arrive.
async fn run_forward<Q, R>(request: Q, reply: R) -> (Option<io::Result<()>>, io::Result<()>)
where
    Q: Future<Output = io::Result<()>>,
    R: Future<Output = io::Result<()>>,
{
    tokio::pin!(request, reply);
    tokio::select! {
        replied = &mut reply => match replied {
            Ok(()) => (Some(request.await), Ok(())),
            Err(e) => (None, Err(e)),
        },
        requested = &mut request => (Some(requested), reply.await),
    }
}

/// Record byte counts from [`run_forward`], logging either direction's error.
/// The counters hold what was sent before an abnormal close. `e2o_label` and
/// `o2e_label` scope the log line to the caller. Returns `true` unless both
/// directions ended cleanly.
#[must_use]
fn record_copy_results(
    metrics: &AgentMetrics,
    edge_to_origin: (&AtomicU64, Option<io::Result<()>>),
    origin_to_edge: (&AtomicU64, io::Result<()>),
    e2o_label: &str,
    o2e_label: &str,
) -> bool {
    let (e2o_bytes, e2o_res) = edge_to_origin;
    metrics.add_bytes(
        metrics::direction::EDGE_TO_ORIGIN,
        e2o_bytes.load(Ordering::Relaxed),
    );
    if let Some(Err(e)) = &e2o_res {
        debug!("{e2o_label}: {e}");
    }
    let (o2e_bytes, o2e_res) = origin_to_edge;
    metrics.add_bytes(
        metrics::direction::ORIGIN_TO_EDGE,
        o2e_bytes.load(Ordering::Relaxed),
    );
    if let Err(e) = &o2e_res {
        debug!("{o2e_label}: {e}");
    }
    !matches!((e2o_res, o2e_res), (Some(Ok(())), Ok(())))
}

async fn forward_plain(
    mut origin: TcpStream,
    proxy: ProxyProtocol,
    addrs: ClientAddrs,
    quic_recv: &mut TunnelRecv,
    quic_send: &mut TunnelSend,
    metrics: &AgentMetrics,
) -> anyhow::Result<()> {
    // Written eagerly (not coalesced with the first client chunk) so a
    // server-speaks-first origin isn't left waiting for its PROXY header
    // while the client waits for the origin's banner.
    write_proxy_header(&mut origin, proxy, addrs).await?;

    let (mut origin_read, mut origin_write) = origin.into_split();

    let (e2o, o2e) = (AtomicU64::new(0), AtomicU64::new(0));
    let q2o = async {
        let res = {
            let mut counted = CountingWriter::new(&mut origin_write, &e2o);
            quic_recv.forward_to_writer(&mut counted).await.1
        };
        drop(origin_write.shutdown().await);
        res
    };
    let edge_stopped = quic_send.stopped();
    let o2q = async {
        let copy = async {
            let mut counted = CountingWriter::new(&mut *quic_send, &o2e);
            copy_tcp_counting(&mut origin_read, &mut counted).await.1
        };
        let res = tokio::select! {
            res = copy => res,
            // The edge's client is gone: there is no one to answer.
            () = edge_stopped => Ok(()),
        };
        // Finished, never reset: what the origin sent is delivered.
        drop(quic_send.finish().await);
        res
    };

    let (r1, r2) = run_forward(q2o, o2q).await;
    if record_copy_results(
        metrics,
        (&e2o, r1),
        (&o2e, r2),
        "edge->origin",
        "origin->edge",
    ) {
        return Err(CopyError("forwarding").into());
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "splitting into a config struct adds plumbing churn for negligible call-site benefit"
)]
async fn handle_tcp_stream(
    service_name: &str,
    client_addrs: ClientAddrs,
    mut quic_send: TunnelSend,
    mut quic_recv: TunnelRecv,
    service_map: &ServiceMap,
    edge_id: iroh::EndpointId,
    metrics: &AgentMetrics,
    start: Instant,
) -> anyhow::Result<()> {
    let Some(target) = service_map.lookup_tcp(service_name) else {
        metrics.record_stream_error(metrics::stream_error::NO_SERVICE);
        return Err(anyhow::anyhow!(
            "no tcp service configured for `{service_name}`"
        ));
    };

    let span = info_span!("tcp_stream",
        service = %service_name,
        origin = %target.address,
        edge = %edge_id.fmt_short(),
        client = ?client_addrs.src,
    );

    async {
        debug!("forwarding tcp service to origin");
        let origin = match target.connect().await {
            Ok(s) => s,
            Err(e) => {
                metrics.record_stream_error(metrics::stream_error::ORIGIN_CONNECT);
                return Err(e);
            }
        };

        let forwarded = forward_plain(
            origin,
            target.proxy_protocol,
            client_addrs,
            &mut quic_recv,
            &mut quic_send,
            metrics,
        )
        .await;
        if let Err(e) = forwarded {
            metrics.record_stream_error(metrics::stream_error::FORWARD_ERROR);
            return Err(e);
        }

        metrics.streams_completed.inc();
        #[expect(
            clippy::cast_possible_truncation,
            reason = "tcp streams won't last 584 million years"
        )]
        let duration_ms = start.elapsed().as_millis() as u64;
        debug!(duration_ms, "tcp stream closed");
        Ok(())
    }
    .instrument(span)
    .await
}

/// UDP sibling of [`handle_tcp_stream`]; payload framing per [`write_datagram_frame`].
/// Returns `true` for ICMP-derived errors that are transient on a UDP socket:
/// the origin may be momentarily unreachable but the session should survive.
const fn is_transient_origin_error(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NetworkUnreachable
            | std::io::ErrorKind::HostUnreachable
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "matches the shape of handle_tcp_stream; bundling these adds noise without benefit"
)]
async fn handle_udp_stream(
    service_name: &str,
    client_addrs: ClientAddrs,
    mut quic_send: TunnelSend,
    mut quic_recv: TunnelRecv,
    service_map: &ServiceMap,
    edge_id: iroh::EndpointId,
    metrics: &AgentMetrics,
    start: Instant,
) -> anyhow::Result<()> {
    let Some(target) = service_map.lookup_udp(service_name) else {
        metrics.record_stream_error(metrics::stream_error::NO_SERVICE);
        return Err(anyhow::anyhow!(
            "no udp service configured for `{service_name}`"
        ));
    };

    let span = info_span!("udp_stream",
        service = %service_name,
        origin = %target.address,
        edge = %edge_id.fmt_short(),
        client = ?client_addrs.src,
    );

    async {
        debug!("forwarding udp service to origin");
        // The edge listener port rides in `dst`; range services forward to the
        // origin host at this same port, single-port services ignore it.
        let socket = match target.connect(client_addrs.dst.port()).await {
            Ok(s) => s,
            Err(e) => {
                metrics.record_stream_error(metrics::stream_error::ORIGIN_CONNECT);
                return Err(e);
            }
        };

        let mut frame_reader = DatagramFrameReader::new();
        let mut buf_out = vec![0u8; MAX_UDP_DATAGRAM];
        let mut bytes_e2o: u64 = 0;
        let mut bytes_o2e: u64 = 0;
        let result: anyhow::Result<()> = loop {
            tokio::select! {
                read = frame_reader.next(&mut quic_recv) => match read {
                    Ok(payload) => {
                        let n = payload.len() as u64;
                        match socket.send(payload).await {
                            Ok(_) => {}
                            // ICMP-derived errors (port/net unreachable, reset): the origin
                            // may recover, so drop this datagram and keep the session alive.
                            Err(e) if is_transient_origin_error(e.kind()) => {
                                debug!(error = %e, "transient origin error on send, dropping datagram");
                            }
                            Err(e) => break Err(e.into()),
                        }
                        bytes_e2o = bytes_e2o.saturating_add(n);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break Ok(()),
                    Err(e) => break Err(e.into()),
                },
                recv = socket.recv(&mut buf_out) => match recv {
                    Ok(n) => {
                        #[expect(
                            clippy::indexing_slicing,
                            reason = "UdpSocket::recv guarantees n <= buf_out.len()"
                        )]
                        let payload = &buf_out[..n];
                        if let Err(e) = write_datagram_frame(&mut quic_send, payload).await {
                            break Err(e.into());
                        }
                        bytes_o2e = bytes_o2e.saturating_add(n as u64);
                    }
                    // ICMP-derived errors on recv: the origin is unreachable right now
                    // but the client may retry; keep the QUIC stream open.
                    Err(e) if is_transient_origin_error(e.kind()) => {
                        debug!(error = %e, "transient origin error on recv, continuing");
                    }
                    Err(e) => break Err(e.into()),
                },
            }
        };
        drop(quic_send.finish().await);

        metrics.add_bytes(metrics::direction::EDGE_TO_ORIGIN, bytes_e2o);
        metrics.add_bytes(metrics::direction::ORIGIN_TO_EDGE, bytes_o2e);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "udp streams won't last 584 million years"
        )]
        let duration_ms = start.elapsed().as_millis() as u64;
        if let Err(e) = result {
            // Best-effort: ICMP unreachable surfaces here too, so log at debug
            // rather than warn to avoid noisy alerts on transient origin loss.
            debug!(error = %e, "udp forwarding ended");
            metrics.record_stream_error(metrics::stream_error::FORWARD_ERROR);
        } else {
            metrics.streams_completed.inc();
        }
        debug!(duration_ms, "udp stream closed");
        Ok(())
    }
    .instrument(span)
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "splitting into a config struct adds plumbing churn for negligible call-site benefit"
)]
async fn forward_tls(
    mut origin: TcpStream,
    server_name: ServerName<'static>,
    tls_config: Arc<rustls::ClientConfig>,
    proxy: ProxyProtocol,
    addrs: ClientAddrs,
    quic_recv: &mut TunnelRecv,
    quic_send: &mut TunnelSend,
    metrics: &AgentMetrics,
) -> anyhow::Result<()> {
    // PROXY v2 must precede the TLS ClientHello so the origin's TLS layer
    // sees a normal handshake after consuming the header.
    write_proxy_header(&mut origin, proxy, addrs).await?;

    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let tls_stream = match tokio::time::timeout(
        ORIGIN_TLS_HANDSHAKE_TIMEOUT,
        connector.connect(server_name.clone(), origin),
    )
    .await
    {
        Ok(r) => {
            r.with_context(|| format!("TLS handshake with origin failed (SNI: {server_name:?})"))?
        }
        Err(_) => anyhow::bail!("TLS handshake with origin timed out (SNI: {server_name:?})"),
    };

    let (tls_read, mut tls_write) = tokio::io::split(tls_stream);
    let mut tls_read = io::BufReader::with_capacity(COPY_BUF_SIZE, tls_read);

    let (e2o, o2e) = (AtomicU64::new(0), AtomicU64::new(0));
    let q2o = async {
        let res = {
            let mut counted = CountingWriter::new(&mut tls_write, &e2o);
            quic_recv.forward_to_writer(&mut counted).await.1
        };
        drop(tls_write.shutdown().await);
        res
    };
    let edge_stopped = quic_send.stopped();
    let o2q = async {
        let copy = async {
            let mut counted = CountingWriter::new(&mut *quic_send, &o2e);
            copy_buf_counting(&mut tls_read, &mut counted).await.1
        };
        let res = tokio::select! {
            res = copy => res,
            () = edge_stopped => Ok(()),
        };
        drop(quic_send.finish().await);
        res
    };

    let (r1, r2) = run_forward(q2o, o2q).await;
    let failed = record_copy_results(
        metrics,
        (&e2o, r1),
        (&o2e, r2),
        "edge->origin(tls)",
        "origin(tls)->edge",
    );
    if failed {
        return Err(CopyError("tls forwarding").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn local_endpoint() -> iroh::Endpoint {
        iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
            .alpns(vec![towonel_common::protocol::ALPN_TUNNEL.to_vec()])
            .relay_mode(iroh::RelayMode::Disabled)
            .clear_ip_transports()
            .bind_addr("127.0.0.1:0")
            .unwrap()
            .transport_config(towonel_common::protocol::tunnel_transport_config())
            .bind()
            .await
            .unwrap()
    }

    async fn local_connection() -> (
        iroh::Endpoint,
        iroh::Endpoint,
        iroh::endpoint::Connection,
        iroh::endpoint::Connection,
    ) {
        let edge = local_endpoint().await;
        let agent = local_endpoint().await;
        let addr = iroh::EndpointAddr::new(edge.id())
            .with_ip_addr(edge.bound_sockets().into_iter().next().unwrap());
        let (conn, peer) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(
                agent.connect(addr, towonel_common::protocol::ALPN_TUNNEL),
                async { edge.accept().await.unwrap().await.unwrap() }
            )
        })
        .await
        .unwrap();
        (edge, agent, conn.unwrap(), peer)
    }

    #[tokio::test]
    async fn stream_ack_negotiation_accepts_legacy_edge() {
        let (edge, agent, conn, peer) = local_connection().await;
        let conn = TunnelConn::Iroh(conn);
        let (negotiated, ()) = tokio::join!(enable_stream_acks(&conn), async {
            let (mut send, mut recv) = peer.accept_bi().await.unwrap();
            towonel_common::tunnel::read_control_prefix(&mut recv)
                .await
                .unwrap();
            assert_eq!(
                recv.read_to_end(10).await.unwrap(),
                [CONTROL_OPCODE_STREAM_ACK]
            );
            send.write_all(&[CONTROL_STATUS_NOT_IMPLEMENTED])
                .await
                .unwrap();
            send.finish().unwrap();
        });
        negotiated.unwrap();
        assert!(peer.close_reason().is_none());
        agent.close().await;
        edge.close().await;
    }

    #[tokio::test]
    async fn peer_close_releases_forwarding_when_stream_limit_is_saturated() {
        use tokio::io::AsyncReadExt;
        use tokio::net::TcpListener;
        use tokio::time::timeout;
        use towonel_common::tls_policy::TlsMode;
        use towonel_common::tunnel::write_handshake;

        const SETUP: Duration = Duration::from_secs(3);
        const HOST: &str = "saturated.test";

        drop(rustls::crypto::ring::default_provider().install_default());
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let services = Arc::new(
            ServiceMap::from_config(
                &[ServiceConfig {
                    hostname: HOST.to_string(),
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
        let (edge, agent, conn, peer) = local_connection().await;
        let metrics = Arc::new(AgentMetrics::new());
        let stream_limit = Arc::new(tokio::sync::Semaphore::new(1));
        let mut handler = tokio::spawn(handle_connection_with_stream_limit(
            TunnelConn::Iroh(conn),
            edge.id(),
            services,
            Arc::clone(&metrics),
            Arc::clone(&stream_limit),
        ));
        let (mut send, mut recv) = peer.open_bi().await.unwrap();
        write_handshake(&mut send, &format!("{STREAM_ACK_PREFIX}{HOST}"), v4_addrs())
            .await
            .unwrap();
        assert_eq!(
            timeout(SETUP, read_control_status(&mut recv))
                .await
                .unwrap()
                .unwrap(),
            CONTROL_STATUS_OK
        );
        send.write_all(b"ping").await.unwrap();
        send.finish().unwrap();
        let (mut socket, _) = timeout(SETUP, origin.accept()).await.unwrap().unwrap();
        let mut request = Vec::new();
        timeout(SETUP, socket.read_to_end(&mut request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request, b"ping");
        // The half-closed origin holds the only stream permit.
        assert_eq!(metrics.streams_active.get(), 1);
        assert_eq!(stream_limit.available_permits(), 0);
        assert!(!handler.is_finished());

        peer.close(0u32.into(), b"test peer closed");
        let handler_exited = timeout(SETUP, &mut handler).await;
        // Abort before closing the origin so cleanup cannot mask the leak.
        handler.abort();
        let forwarding_released = timeout(SETUP, async {
            while metrics.streams_active.get() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        drop(socket);
        agent.close().await;
        edge.close().await;
        handler_exited
            .expect("permit wait blocked after peer closed")
            .unwrap();
        forwarding_released.expect("forwarding tasks still active after peer closed");
        assert_eq!(stream_limit.available_permits(), 1);
    }

    async fn origin_and_edge(
        host: &str,
    ) -> (
        tokio::net::TcpListener,
        iroh::Endpoint,
        iroh::Endpoint,
        iroh::endpoint::Connection,
        Arc<AgentMetrics>,
    ) {
        use towonel_common::tls_policy::TlsMode;

        drop(rustls::crypto::ring::default_provider().install_default());
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let services = Arc::new(
            ServiceMap::from_config(
                &[ServiceConfig {
                    hostname: host.to_string(),
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
        let (edge, agent, conn, peer) = local_connection().await;
        let metrics = Arc::new(AgentMetrics::new());
        tokio::spawn(handle_connection(
            TunnelConn::Iroh(conn),
            edge.id(),
            services,
            Arc::clone(&metrics),
        ));
        (origin, edge, agent, peer, metrics)
    }

    #[tokio::test]
    async fn an_edge_that_stops_reading_releases_the_origin() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout;
        use towonel_common::tunnel::write_handshake;

        const SETUP: Duration = Duration::from_secs(3);
        const HOST: &str = "gone.test";

        let (origin, edge, agent, peer, metrics) = origin_and_edge(HOST).await;
        let (mut send, recv) = peer.open_bi().await.unwrap();
        write_handshake(&mut send, HOST, v4_addrs()).await.unwrap();
        send.write_all(b"ping").await.unwrap();
        let (mut socket, _) = timeout(SETUP, origin.accept()).await.unwrap().unwrap();

        // What the edge does when its client resets: the request is finished,
        // not discarded, and the reply is no longer read.
        send.finish().unwrap();
        drop(recv);

        let mut request = Vec::new();
        timeout(SETUP, socket.read_to_end(&mut request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(request, b"ping");
        // A half-close would leave the origin free to keep writing; a closed
        // connection refuses it.
        let refused = timeout(SETUP, async {
            while socket.write_all(&[0; 1024]).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        refused.expect("origin connection still open after the edge stopped reading");
        timeout(SETUP, async {
            while metrics.streams_active.get() != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("stream still counted active");
        agent.close().await;
        edge.close().await;
    }

    #[tokio::test]
    async fn a_reply_sent_before_the_origin_hangs_up_on_an_upload_is_delivered() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::timeout;
        use towonel_common::tunnel::write_handshake;

        const SETUP: Duration = Duration::from_secs(5);
        const HOST: &str = "early.test";

        let (origin, edge, agent, peer, _metrics) = origin_and_edge(HOST).await;
        let (mut send, mut recv) = peer.open_bi().await.unwrap();
        write_handshake(&mut send, HOST, v4_addrs()).await.unwrap();
        send.write_all(b"POST").await.unwrap();
        let (mut socket, _) = timeout(SETUP, origin.accept()).await.unwrap().unwrap();
        let mut head = [0; 4];
        timeout(SETUP, socket.read_exact(&mut head))
            .await
            .unwrap()
            .unwrap();

        // The origin refuses the upload and closes without reading it.
        socket.write_all(b"413 too large").await.unwrap();
        drop(socket);
        let upload = tokio::spawn(async move {
            while send.write_all(&[0; 16 * 1024]).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        let reply = timeout(SETUP, recv.read_to_end(64)).await.unwrap();
        assert_eq!(reply.unwrap(), b"413 too large");
        timeout(SETUP, upload).await.unwrap().unwrap();
        agent.close().await;
        edge.close().await;
    }

    fn v4_addrs() -> ClientAddrs {
        ClientAddrs {
            src: "203.0.113.7:54321".parse().unwrap(),
            dst: "192.0.2.1:443".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn no_header_written_when_disabled() {
        let mut buf = Vec::new();
        write_proxy_header(&mut buf, ProxyProtocol::None, v4_addrs())
            .await
            .unwrap();
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn writes_v2_when_enabled() {
        let mut buf = Vec::new();
        write_proxy_header(&mut buf, ProxyProtocol::V2, v4_addrs())
            .await
            .unwrap();
        let header = ppp::v2::Header::try_from(buf.as_slice()).unwrap();
        assert_eq!(header.command, ppp::v2::Command::Proxy);
        assert!(matches!(header.addresses, ppp::v2::Addresses::IPv4(_)));
    }
}
