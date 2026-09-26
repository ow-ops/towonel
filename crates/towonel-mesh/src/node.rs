//! A running mesh device: iroh endpoint, peer handshakes, TCP forwarding.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use bytes::Bytes;
use iroh::address_lookup::MemoryLookup;
use iroh::endpoint::{Connection, QuicTransportConfig, RecvStream, SendStream, presets::Minimal};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, Watcher};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use towonel_common::edge_cred::AuthFrame;
use towonel_common::mesh::MeshCred;
use towonel_common::time::now_ms;
use tracing::{debug, info, warn};

use crate::api::{Device, Netmap};
use crate::client::{MeshClient, StreamEvent};
use crate::dns;
use crate::packet::{self, PacketInfo};
use crate::peer::{
    ForwardStatus, MAX_HELLO_LEN, MESH_ALPN, Trust, flow_allowed, forward_header, hello_frame,
    inbound_allowed, parse_forward_header,
};

const KEEP_ALIVE: Duration = Duration::from_secs(15);
/// Most paths carry 1400-byte UDP; PMTU discovery backs off if not.
const INITIAL_MTU: u16 = 1400;
/// Packets held per peer while its connection is being dialed.
const MAX_PENDING: usize = 16;
const PACKET_QUEUE: usize = 1024;
const FLOW_IDLE: Duration = Duration::from_mins(5);
const MAX_FLOWS: usize = 65_536;
const MAX_RECONNECT_DELAY: Duration = Duration::from_mins(1);
/// Coalesces bursts of address changes into one report.
const ADDR_REPORT_SETTLE: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Default)]
pub struct NodeOptions {
    /// Bind the iroh socket here instead of all interfaces.
    pub bind: Option<SocketAddr>,
}

/// Why a node stopped on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stopped {
    Revoked,
    KeyExpired,
}

#[derive(Debug, Clone)]
pub struct PeerStatus {
    pub device: Device,
    pub connected: bool,
    pub relayed: Option<bool>,
}

#[derive(Clone)]
pub struct MeshNode {
    inner: Arc<Inner>,
}

struct Inner {
    endpoint: Endpoint,
    client: MeshClient,
    lookup: MemoryLookup,
    netmap: watch::Sender<Netmap>,
    trust: RwLock<Trust>,
    hello: RwLock<(AuthFrame, MeshCred)>,
    conns: Mutex<HashMap<EndpointId, Connection>>,
    /// Packets waiting for a connection that's being dialed.
    pending: Mutex<HashMap<EndpointId, Vec<Bytes>>>,
    /// Flows this device started, so replies pass the inbound policy.
    flows: Mutex<HashMap<Flow, Instant>>,
    to_host: RwLock<Option<mpsc::Sender<Bytes>>>,
    /// Local ports of the iroh socket; its packets must never enter the TUN.
    transport_ports: Vec<u16>,
    stopped: RwLock<Option<Stopped>>,
    cancel: CancellationToken,
}

impl MeshNode {
    pub async fn start(
        client: MeshClient,
        key: iroh::SecretKey,
        opts: NodeOptions,
    ) -> anyhow::Result<Self> {
        let netmap = client.netmap().await?;
        let trust = Trust::from_netmap(&netmap)?;
        let hello = hello_frame(&client.cred().await?)?;

        let lookup = MemoryLookup::new();
        seed_lookup(&lookup, &netmap);
        let relay_mode = netmap
            .relay_url
            .as_deref()
            .map_or(RelayMode::Disabled, |u| {
                towonel_common::relay::relay_mode_from_url(u, "hub netmap")
            });
        let mut builder = Endpoint::builder(Minimal)
            .secret_key(key)
            .alpns(vec![MESH_ALPN.to_vec()])
            .relay_mode(relay_mode)
            .address_lookup(lookup.clone())
            .transport_config(
                QuicTransportConfig::builder()
                    .keep_alive_interval(KEEP_ALIVE)
                    .initial_mtu(INITIAL_MTU)
                    .build(),
            );
        if let Some(bind) = opts.bind {
            builder = builder
                .clear_ip_transports()
                .bind_addr(bind)
                .map_err(|e| anyhow::anyhow!("invalid bind address {bind}: {e}"))?;
        }
        let endpoint = builder
            .bind()
            .await
            .context("failed to bind the mesh endpoint")?;
        debug!(device = %endpoint.id(), "mesh endpoint ready");

        let transport_ports = endpoint
            .bound_sockets()
            .iter()
            .map(SocketAddr::port)
            .collect();
        let node = Self {
            inner: Arc::new(Inner {
                endpoint,
                client,
                lookup,
                netmap: watch::Sender::new(netmap),
                trust: RwLock::new(trust),
                hello: RwLock::new(hello),
                conns: Mutex::new(HashMap::new()),
                pending: Mutex::new(HashMap::new()),
                flows: Mutex::new(HashMap::new()),
                to_host: RwLock::new(None),
                transport_ports,
                stopped: RwLock::new(None),
                cancel: CancellationToken::new(),
            }),
        };
        tokio::spawn(node.clone().accept_loop());
        tokio::spawn(node.clone().follow_netmap());
        tokio::spawn(node.clone().report_addrs());
        tokio::spawn(node.clone().refresh_cred());
        Ok(node)
    }

    pub async fn shutdown(&self) {
        self.inner.cancel.cancel();
        self.inner.endpoint.close().await;
    }

    /// Resolves once the node stops, with the reason if the hub stopped it.
    pub async fn stopped(&self) -> Option<Stopped> {
        self.inner.cancel.cancelled().await;
        read(&self.inner.stopped).clone()
    }

    #[must_use]
    pub fn netmap(&self) -> watch::Receiver<Netmap> {
        self.inner.netmap.subscribe()
    }

    #[must_use]
    pub fn peers(&self) -> Vec<PeerStatus> {
        let netmap = self.inner.netmap.borrow().clone();
        let conns = lock(&self.inner.conns);
        netmap
            .peers
            .into_iter()
            .map(|device| {
                let conn = crate::peer::device_id_bytes(&device.device_id)
                    .ok()
                    .and_then(|id| EndpointId::from_bytes(&id).ok())
                    .and_then(|id| conns.get(&id))
                    .filter(|c| c.close_reason().is_none());
                PeerStatus {
                    relayed: conn.and_then(relayed),
                    connected: conn.is_some(),
                    device,
                }
            })
            .collect()
    }

    /// Route IP packets between the host and the mesh: packets sent on the
    /// returned sender go to peers, packets from peers arrive on the
    /// receiver. Attaching again replaces the previous channel.
    #[must_use]
    pub fn packet_channel(&self) -> (mpsc::Sender<Bytes>, mpsc::Receiver<Bytes>) {
        let (from_host_tx, mut from_host) = mpsc::channel::<Bytes>(PACKET_QUEUE);
        let (to_host, to_host_rx) = mpsc::channel(PACKET_QUEUE);
        *write(&self.inner.to_host) = Some(to_host);
        let node = self.clone();
        tokio::spawn(async move {
            loop {
                let packet = tokio::select! {
                    () = node.inner.cancel.cancelled() => return,
                    packet = from_host.recv() => match packet {
                        Some(p) => p,
                        None => return,
                    },
                };
                node.route_out(packet);
            }
        });
        (from_host_tx, to_host_rx)
    }

    fn route_out(&self, packet: Bytes) {
        let Some(info) = packet::parse(&packet) else {
            return;
        };
        let own = read(&self.inner.hello).1.clone();
        if info.src != IpAddr::V4(own.ipv4) && info.src != IpAddr::V6(own.ipv6) {
            return;
        }
        // Our own QUIC routed into the overlay would tunnel inside itself:
        // iroh probes every local address, including the TUN's.
        if info.proto == packet::PROTO_UDP && self.inner.transport_ports.contains(&info.src_port) {
            return;
        }
        if dns::is_query(&info) {
            if let Some(reply) = self.answer_dns(&packet) {
                self.deliver(Bytes::from(reply));
            }
            return;
        }
        let Some(id) = read(&self.inner.trust)
            .by_ip
            .get(&info.dst)
            .and_then(|id| EndpointId::from_bytes(id).ok())
        else {
            return;
        };
        self.track(Flow::outbound(&info));

        let live = lock(&self.inner.conns)
            .get(&id)
            .filter(|c| c.close_reason().is_none())
            .cloned();
        if let Some(conn) = live {
            self.send_packet(&conn, packet);
            return;
        }
        let first = {
            let mut pending = lock(&self.inner.pending);
            let queue = pending.entry(id).or_default();
            if queue.len() < MAX_PENDING {
                queue.push(packet);
            }
            let first = queue.len() == 1;
            drop(pending);
            first
        };
        if first {
            let node = self.clone();
            tokio::spawn(async move {
                let conn = node.connection(id).await;
                let queued = lock(&node.inner.pending).remove(&id).unwrap_or_default();
                match conn {
                    Ok(conn) => {
                        for packet in queued {
                            node.send_packet(&conn, packet);
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, peer = %id, "dropping packets for unreachable peer");
                    }
                }
            });
        }
    }

    fn send_packet(&self, conn: &Connection, packet: Bytes) {
        match conn.max_datagram_size() {
            Some(max) if packet.len() <= max => {
                if let Err(e) = conn.send_datagram(packet) {
                    debug!(error = %e, "datagram send failed");
                }
            }
            Some(max) => {
                // Only IPv4 can shrink: IPv6 hosts ignore MTUs below 1280.
                let mtu = u16::try_from(max).unwrap_or(u16::MAX);
                if let Some(icmp) = packet::icmpv4_frag_needed(&packet, mtu) {
                    self.deliver(Bytes::from(icmp));
                }
            }
            None => debug!("peer does not accept datagrams"),
        }
    }

    fn answer_dns(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let netmap = self.inner.netmap.borrow();
        let addrs = |d: &Device| Some((d.ipv4.parse().ok()?, d.ipv6.parse().ok()?));
        dns::answer(packet, &netmap.dns_domain, |name| {
            std::iter::once(&netmap.this_device)
                .chain(&netmap.peers)
                .find(|d| d.name == name)
                .and_then(addrs)
        })
    }

    fn route_in(&self, packet: Bytes, peer_cred: &MeshCred) {
        let Some(info) = packet::parse(&packet) else {
            return;
        };
        let own = read(&self.inner.hello).1.clone();
        let reply = lock(&self.inner.flows)
            .get(&Flow::reply_to(&info))
            .is_some_and(|seen| seen.elapsed() < FLOW_IDLE);
        let trust = read(&self.inner.trust);
        if inbound_allowed(&info, peer_cred, &own, reply, trust.policy.as_ref()) {
            self.deliver(packet);
        }
    }

    fn deliver(&self, packet: Bytes) {
        if let Some(tx) = read(&self.inner.to_host).as_ref()
            && tx.try_send(packet).is_err()
        {
            debug!("host packet queue full; dropping");
        }
    }

    fn track(&self, flow: Flow) {
        let mut flows = lock(&self.inner.flows);
        if flows.len() >= MAX_FLOWS {
            flows.retain(|_, seen| seen.elapsed() < FLOW_IDLE);
        }
        if flows.len() < MAX_FLOWS {
            flows.insert(flow, Instant::now());
        }
    }

    /// Open a TCP stream to `port` on `peer`'s loopback. `peer` is a device
    /// name, overlay IP, or device id.
    pub async fn open_tcp(
        &self,
        peer: &str,
        port: u16,
    ) -> anyhow::Result<(SendStream, RecvStream)> {
        let device = find_peer(&self.inner.netmap.borrow(), peer)
            .cloned()
            .with_context(|| format!("no device named {peer} in the mesh"))?;
        let id = EndpointId::from_bytes(&crate::peer::device_id_bytes(&device.device_id)?)?;
        let conn = self.connection(id).await?;
        let (mut send, mut recv) = conn.open_bi().await?;
        send.write_all(&forward_header(port)).await?;
        let mut status = [0u8; 1];
        recv.read_exact(&mut status).await?;
        match ForwardStatus::from_byte(status[0]) {
            ForwardStatus::Ok => Ok((send, recv)),
            ForwardStatus::Denied => bail!(
                "{} does not accept connections from this device",
                device.name
            ),
            ForwardStatus::Unreachable => bail!("nothing is listening on {}:{port}", device.name),
        }
    }

    async fn connection(&self, id: EndpointId) -> anyhow::Result<Connection> {
        if let Some(conn) = lock(&self.inner.conns)
            .get(&id)
            .filter(|c| c.close_reason().is_none())
        {
            return Ok(conn.clone());
        }
        let conn = self
            .inner
            .endpoint
            .connect(EndpointAddr::new(id), MESH_ALPN)
            .await
            .context("could not reach the peer")?;
        let (mut send, mut recv) = conn.open_bi().await?;
        self.send_hello(&mut send).await?;
        let theirs = AuthFrame::decode(&recv.read_to_end(MAX_HELLO_LEN).await?)?;
        let peer_cred = self.verify(&theirs, id)?;
        self.register(conn.clone(), peer_cred);
        Ok(conn)
    }

    async fn accept_loop(self) {
        loop {
            let incoming = tokio::select! {
                () = self.inner.cancel.cancelled() => return,
                incoming = self.inner.endpoint.accept() => incoming,
            };
            let Some(incoming) = incoming else { return };
            let node = self.clone();
            tokio::spawn(async move {
                if let Err(e) = node.accept(incoming).await {
                    debug!(error = %e, "inbound mesh connection rejected");
                }
            });
        }
    }

    async fn accept(&self, incoming: iroh::endpoint::Incoming) -> anyhow::Result<()> {
        let conn = incoming.await?;
        let id = conn.remote_id();
        let (mut send, mut recv) = conn.accept_bi().await?;
        let theirs = AuthFrame::decode(&recv.read_to_end(MAX_HELLO_LEN).await?)?;
        let peer_cred = match self.verify(&theirs, id) {
            Ok(c) => c,
            Err(e) => {
                conn.close(1u32.into(), b"unauthorized");
                return Err(e);
            }
        };
        self.send_hello(&mut send).await?;
        self.register(conn, peer_cred);
        Ok(())
    }

    async fn send_hello(&self, send: &mut SendStream) -> anyhow::Result<()> {
        let frame = read(&self.inner.hello).0.encode();
        send.write_all(&frame).await?;
        send.finish()?;
        Ok(())
    }

    fn verify(&self, frame: &AuthFrame, id: EndpointId) -> anyhow::Result<MeshCred> {
        read(&self.inner.trust).verify(frame, id.as_bytes(), now_ms())
    }

    fn register(&self, conn: Connection, peer_cred: MeshCred) {
        let id = conn.remote_id();
        let old = lock(&self.inner.conns).insert(id, conn.clone());
        if let Some(old) = old {
            old.close(0u32.into(), b"replaced");
        }
        tokio::spawn(self.clone().serve(conn, peer_cred));
    }

    /// Either side may open streams on a connection, whoever dialed it.
    async fn serve(self, conn: Connection, peer_cred: MeshCred) {
        loop {
            let (send, recv) = tokio::select! {
                () = self.inner.cancel.cancelled() => return,
                datagram = conn.read_datagram() => match datagram {
                    Ok(packet) => {
                        self.route_in(packet, &peer_cred);
                        continue;
                    }
                    Err(_) => break,
                },
                stream = conn.accept_bi() => match stream {
                    Ok(s) => s,
                    Err(_) => break,
                },
            };
            let node = self.clone();
            let peer_cred = peer_cred.clone();
            let allowed = move |port| {
                let own = read(&node.inner.hello).1.clone();
                let trust = read(&node.inner.trust);
                flow_allowed(
                    trust.policy.as_ref(),
                    &peer_cred,
                    &own,
                    packet::PROTO_TCP,
                    port,
                )
            };
            tokio::spawn(async move {
                if let Err(e) = forward(send, recv, allowed).await {
                    debug!(error = %e, "mesh forward ended");
                }
            });
        }
        let mut conns = lock(&self.inner.conns);
        if conns
            .get(&conn.remote_id())
            .is_some_and(|c| c.stable_id() == conn.stable_id())
        {
            conns.remove(&conn.remote_id());
        }
    }

    async fn follow_netmap(self) {
        let mut delay = Duration::from_secs(1);
        while !self.inner.cancel.is_cancelled() {
            match self.inner.client.netmap_stream().await {
                Ok(mut stream) => loop {
                    let event = tokio::select! {
                        () = self.inner.cancel.cancelled() => return,
                        event = stream.next() => event,
                    };
                    match event {
                        Ok(Some(StreamEvent::Netmap(netmap))) => {
                            delay = Duration::from_secs(1);
                            self.apply_netmap(*netmap);
                        }
                        Ok(Some(StreamEvent::Revoked)) => return self.stop(Stopped::Revoked),
                        Ok(Some(StreamEvent::KeyExpired)) => return self.stop(Stopped::KeyExpired),
                        Ok(None) => break,
                        Err(e) => {
                            debug!(error = %e, "netmap stream dropped");
                            break;
                        }
                    }
                },
                Err(e) => warn!(error = %e, "cannot reach the hub; retrying"),
            }
            tokio::select! {
                () = self.inner.cancel.cancelled() => return,
                () = tokio::time::sleep(delay) => {}
            }
            delay = (delay * 2).min(MAX_RECONNECT_DELAY);
        }
    }

    fn apply_netmap(&self, netmap: Netmap) {
        let trust = match Trust::from_netmap(&netmap) {
            Ok(t) => t,
            Err(e) => {
                warn!(error = %e, "ignoring malformed netmap");
                return;
            }
        };
        seed_lookup(&self.inner.lookup, &netmap);
        lock(&self.inner.conns).retain(|id, conn| {
            let keep = trust.peers.contains_key(id.as_bytes());
            if !keep {
                conn.close(2u32.into(), b"removed from mesh");
            }
            keep
        });
        *write(&self.inner.trust) = trust;
        self.inner.netmap.send_replace(netmap);
    }

    fn stop(&self, reason: Stopped) {
        info!(?reason, "hub stopped this device");
        *write(&self.inner.stopped) = Some(reason);
        self.inner.cancel.cancel();
    }

    async fn report_addrs(self) {
        let mut watcher = self.inner.endpoint.watch_addr();
        let mut reported: Option<EndpointAddr> = None;
        loop {
            let addr = without_overlay(watcher.get(), &self.inner.netmap.borrow().this_device);
            if !addr.addrs.is_empty() && reported.as_ref() != Some(&addr) {
                match self.inner.client.report_endpoint(&addr).await {
                    Ok(()) => reported = Some(addr),
                    Err(e) => debug!(error = %e, "endpoint report failed; will retry"),
                }
            }
            tokio::select! {
                () = self.inner.cancel.cancelled() => return,
                changed = watcher.updated() => if changed.is_err() { return },
                () = tokio::time::sleep(MAX_RECONNECT_DELAY), if reported.is_none() => {}
            }
            tokio::time::sleep(ADDR_REPORT_SETTLE).await;
        }
    }

    /// Re-fetch our own credential at half its lifetime.
    async fn refresh_cred(self) {
        loop {
            let not_after = read(&self.inner.hello).1.not_after_ms;
            let wait = Duration::from_millis(not_after.saturating_sub(now_ms()) / 2)
                .max(Duration::from_secs(30));
            tokio::select! {
                () = self.inner.cancel.cancelled() => return,
                () = tokio::time::sleep(wait) => {}
            }
            match self.inner.client.cred().await.and_then(|c| hello_frame(&c)) {
                Ok(hello) => *write(&self.inner.hello) = hello,
                Err(e) => warn!(error = %e, "credential refresh failed; will retry"),
            }
        }
    }
}

/// Splice an accepted stream to `127.0.0.1:port`. Only loopback: a peer can
/// reach this device's services, not its LAN.
async fn forward(
    mut send: SendStream,
    mut recv: RecvStream,
    allowed: impl FnOnce(u16) -> bool,
) -> anyhow::Result<()> {
    let mut header = [0u8; 4];
    recv.read_exact(&mut header).await?;
    let port = parse_forward_header(header).context("unknown forward header")?;
    if !allowed(port) {
        send.write_all(&[ForwardStatus::Denied as u8]).await?;
        return Ok(());
    }
    let Ok(tcp) = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await else {
        send.write_all(&[ForwardStatus::Unreachable as u8]).await?;
        return Ok(());
    };
    send.write_all(&[ForwardStatus::Ok as u8]).await?;
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let upstream = async {
        let res = tokio::io::copy(&mut recv, &mut tcp_write).await;
        drop(tcp_write.shutdown().await);
        res
    };
    let downstream = async {
        let res = tokio::io::copy(&mut tcp_read, &mut send).await;
        drop(send.finish());
        res
    };
    let (up, down) = tokio::join!(upstream, downstream);
    up?;
    down?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Flow {
    proto: u8,
    local_port: u16,
    remote: IpAddr,
    remote_port: u16,
}

impl Flow {
    const fn outbound(p: &PacketInfo) -> Self {
        Self {
            proto: p.proto,
            local_port: p.src_port,
            remote: p.dst,
            remote_port: p.dst_port,
        }
    }

    const fn reply_to(p: &PacketInfo) -> Self {
        Self {
            proto: p.proto,
            local_port: p.dst_port,
            remote: p.src,
            remote_port: p.src_port,
        }
    }
}

fn seed_lookup(lookup: &MemoryLookup, netmap: &Netmap) {
    for peer in &netmap.peers {
        if let Some(addr) = peer.endpoint.clone() {
            lookup.set_endpoint_info(without_overlay(addr, peer));
        }
    }
}

/// Drop a device's own overlay addresses from its endpoint: reaching it
/// through the mesh to build the mesh would loop.
fn without_overlay(mut addr: EndpointAddr, device: &Device) -> EndpointAddr {
    let overlay: Vec<IpAddr> = [&device.ipv4, &device.ipv6]
        .iter()
        .filter_map(|ip| ip.parse().ok())
        .collect();
    addr.addrs.retain(|a| match a {
        iroh::TransportAddr::Ip(sock) => !overlay.contains(&sock.ip()),
        _ => true,
    });
    addr
}

fn find_peer<'a>(netmap: &'a Netmap, query: &str) -> Option<&'a Device> {
    netmap
        .peers
        .iter()
        .find(|d| d.name == query || d.ipv4 == query || d.ipv6 == query || d.device_id == query)
}

fn relayed(conn: &Connection) -> Option<bool> {
    conn.paths()
        .iter()
        .find(iroh::endpoint::Path::is_selected)
        .map(|p| p.remote_addr().is_relay())
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn read<T>(l: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    l.read().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write<T>(l: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    l.write().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overlay_addresses_are_stripped_from_endpoints() {
        let device: Device = serde_json::from_value(serde_json::json!({
            "device_id": "00", "name": "nas", "os": null, "ipv4": "100.64.0.1",
            "ipv6": "fd12:3456:7800::1", "tags": [], "owner": null,
            "key_expires_at_ms": null, "created_at_ms": 0, "last_seen_at_ms": null
        }))
        .unwrap();
        let real: SocketAddr = "192.168.1.10:4000".parse().unwrap();
        // Same /10 as the overlay but not this device's address: a real CGNAT address.
        let cgnat: SocketAddr = "100.72.1.1:4000".parse().unwrap();
        let addr = EndpointAddr::from_parts(
            iroh::SecretKey::from([1; 32]).public(),
            [
                iroh::TransportAddr::Ip("100.64.0.1:4000".parse().unwrap()),
                iroh::TransportAddr::Ip("[fd12:3456:7800::1]:4000".parse().unwrap()),
                iroh::TransportAddr::Ip(real),
                iroh::TransportAddr::Ip(cgnat),
            ],
        );
        assert_eq!(
            without_overlay(addr, &device).addrs,
            [
                iroh::TransportAddr::Ip(real),
                iroh::TransportAddr::Ip(cgnat)
            ]
            .into()
        );
    }
}
