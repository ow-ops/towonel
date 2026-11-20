//! TLS 1.3 over TCP carrier for the agent↔edge tunnel.
//!
//! Peers authenticate with their iroh ed25519 key as a raw public key, so
//! `remote_id` is the same `EndpointId` the QUIC path yields. Streams are
//! multiplexed with yamux.

use std::future::{Future, poll_fn};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use iroh::{EndpointId, SecretKey};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{
    WebPkiSupportedAlgorithms, ring as provider, verify_tls13_signature_with_raw_key,
};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
    UnixTime,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error as TlsError, ServerConfig,
    SignatureScheme,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio_util::compat::{Compat, FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};
use zeroize::Zeroizing;

use crate::protocol::ALPN_TUNNEL;

/// Streams we have open at once; further opens wait, as on QUIC.
const MAX_STREAMS: usize = 1024;

/// yamux counts both directions and tears the connection down when its limit is
/// crossed, so it sits above `MAX_STREAMS`: room for the peer's own streams and
/// for streams still closing on either side.
const STREAM_SLACK: usize = 256;

/// Window above yamux's 256 KiB per-stream minimum; without it a stream's
/// window can never grow and each flow tops out at 256 KiB per round trip.
/// The total window is what bounds the memory a peer can pin.
const WINDOW_GROWTH: usize = 64 * 1024 * 1024;

const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

const KEEPALIVE_IDLE: Duration = Duration::from_secs(20);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
#[cfg(any(target_os = "linux", target_os = "android"))]
const KEEPALIVE_RETRIES: u32 = 3;
/// Must exceed `KEEPALIVE_IDLE + KEEPALIVE_INTERVAL * KEEPALIVE_RETRIES`, or
/// healthy idle sockets get killed.
#[cfg(any(target_os = "linux", target_os = "android"))]
const USER_TIMEOUT: Duration = Duration::from_secs(40);

/// rustls requires a name even when authentication is by raw public key.
const SERVER_NAME: &str = "towonel-edge.invalid";

const SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

static NEXT_CONN_ID: AtomicUsize = AtomicUsize::new(1);

fn spki_to_id(spki: &[u8]) -> Option<EndpointId> {
    let key: [u8; 32] = spki.strip_prefix(&SPKI_PREFIX[..])?.try_into().ok()?;
    EndpointId::from_bytes(&key).ok()
}

fn id_to_spki(id: &EndpointId) -> Vec<u8> {
    let mut spki = SPKI_PREFIX.to_vec();
    spki.extend_from_slice(id.as_bytes());
    spki
}

/// This node's TLS credentials, derived from its iroh secret key.
#[derive(Clone)]
pub struct TlsIdentity {
    key: Arc<CertifiedKey>,
    id: EndpointId,
}

impl TlsIdentity {
    pub fn new(secret: &SecretKey) -> io::Result<Self> {
        let mut pkcs8 = Zeroizing::new(Vec::with_capacity(PKCS8_PREFIX.len() + 32));
        pkcs8.extend_from_slice(&PKCS8_PREFIX);
        pkcs8.extend_from_slice(Zeroizing::new(secret.to_bytes()).as_slice());
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_slice()));
        let signer = provider::sign::any_supported_type(&der).map_err(io::Error::other)?;
        let id = secret.public();
        let spki = id_to_spki(&id);
        // `CertifiedKey::keys_match` parses X.509, so compare the SPKI directly.
        if signer.public_key().as_ref().map(AsRef::as_ref) != Some(spki.as_slice()) {
            return Err(io::Error::other("signing key does not match the iroh key"));
        }
        let key = CertifiedKey::new(vec![CertificateDer::from(spki)], signer);
        Ok(Self {
            key: Arc::new(key),
            id,
        })
    }

    #[must_use]
    pub const fn id(&self) -> EndpointId {
        self.id
    }
}

fn signature_schemes() -> Vec<SignatureScheme> {
    vec![SignatureScheme::ED25519]
}

fn verify_signature(
    algs: &WebPkiSupportedAlgorithms,
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, TlsError> {
    let spki = SubjectPublicKeyInfoDer::from(cert.as_ref());
    verify_tls13_signature_with_raw_key(message, &spki, dss, algs)
}

fn tls12_refused() -> TlsError {
    TlsError::General("TLS 1.2 is not supported".into())
}

/// Client side: accepts exactly the edge key it dialed.
#[derive(Debug)]
struct PinnedEdge {
    spki: Vec<u8>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedEdge {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if end_entity.as_ref() == self.spki.as_slice() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(tls12_refused())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_signature(&self.algs, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        signature_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Edge side: proves the agent holds a well-formed ed25519 key. Whether that
/// agent is allowed is decided afterwards, as on the QUIC path.
#[derive(Debug)]
struct AnyAgent {
    algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for AnyAgent {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        spki_to_id(end_entity.as_ref())
            .map(|_| ClientCertVerified::assertion())
            .ok_or_else(|| TlsError::General("agent key is not a valid ed25519 key".into()))
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(tls12_refused())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_signature(&self.algs, message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        signature_schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn client_config(me: &TlsIdentity, edge: &EndpointId) -> Result<ClientConfig, TlsError> {
    let crypto = Arc::new(provider::default_provider());
    let verifier = PinnedEdge {
        spki: id_to_spki(edge),
        algs: crypto.signature_verification_algorithms,
    };
    let mut config = ClientConfig::builder_with_provider(crypto)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_cert_resolver(Arc::new(
            rustls::client::AlwaysResolvesClientRawPublicKeys::new(Arc::clone(&me.key)),
        ));
    config.alpn_protocols = vec![ALPN_TUNNEL.to_vec()];
    // A resumed session would skip the pinned-key check.
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

fn server_config(me: &TlsIdentity) -> Result<ServerConfig, TlsError> {
    let crypto = Arc::new(provider::default_provider());
    let verifier = AnyAgent {
        algs: crypto.signature_verification_algorithms,
    };
    let mut config = ServerConfig::builder_with_provider(crypto)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_cert_resolver(Arc::new(
            rustls::server::AlwaysResolvesServerRawPublicKeys::new(Arc::clone(&me.key)),
        ));
    config.alpn_protocols = vec![ALPN_TUNNEL.to_vec()];
    config.send_tls13_tickets = 0;
    Ok(config)
}

fn yamux_config() -> yamux::Config {
    let streams = MAX_STREAMS + STREAM_SLACK;
    let mut config = yamux::Config::default();
    config.set_max_num_streams(streams);
    config.set_max_connection_receive_window(Some(
        streams * yamux::DEFAULT_CREDIT as usize + WINDOW_GROWTH,
    ));
    config
}

/// True when the dialer rejected the edge for presenting a key other than the
/// one it dialed for.
#[must_use]
pub fn is_pin_mismatch(err: &io::Error) -> bool {
    err.get_ref()
        .and_then(|inner| inner.downcast_ref::<TlsError>())
        .is_some_and(|e| {
            matches!(
                e,
                TlsError::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure
                )
            )
        })
}

/// yamux has no keepalive, so the kernel has to find dead peers; without this a
/// half-open connection is never noticed.
fn configure_tcp(tcp: &TcpStream) -> io::Result<()> {
    // Nagle plus delayed ACKs can stall small writes by ~40ms.
    tcp.set_nodelay(true)?;
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let keepalive = keepalive.with_retries(KEEPALIVE_RETRIES);
    let socket = socket2::SockRef::from(tcp);
    socket.set_tcp_keepalive(&keepalive)?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    socket.set_tcp_user_timeout(Some(USER_TIMEOUT))?;
    Ok(())
}

async fn within_handshake_timeout<T>(
    handshake: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_e| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))?
}

#[derive(Clone)]
pub struct TlsDialer {
    identity: TlsIdentity,
}

impl TlsDialer {
    #[must_use]
    pub const fn new(identity: TlsIdentity) -> Self {
        Self { identity }
    }

    /// `tcp` must already be connected; its keepalive and nodelay are set here.
    pub async fn connect(&self, tcp: TcpStream, edge: EndpointId) -> io::Result<TlsConn> {
        configure_tcp(&tcp)?;
        let config = client_config(&self.identity, &edge).map_err(io::Error::other)?;
        let name = ServerName::try_from(SERVER_NAME).map_err(io::Error::other)?;
        let tls = within_handshake_timeout(
            tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp),
        )
        .await?;
        if tls.get_ref().1.alpn_protocol() != Some(ALPN_TUNNEL) {
            return Err(io::Error::other("peer did not negotiate the tunnel ALPN"));
        }
        Ok(TlsConn::spawn(tls, edge, yamux::Mode::Client))
    }
}

#[derive(Clone)]
pub struct TlsListener {
    acceptor: tokio_rustls::TlsAcceptor,
}

impl TlsListener {
    pub fn new(identity: &TlsIdentity) -> io::Result<Self> {
        let config = server_config(identity).map_err(io::Error::other)?;
        Ok(Self {
            acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
        })
    }

    pub async fn accept(&self, tcp: TcpStream) -> io::Result<TlsConn> {
        configure_tcp(&tcp)?;
        let tls = within_handshake_timeout(self.acceptor.accept(tcp)).await?;
        let (_, session) = tls.get_ref();
        if session.alpn_protocol() != Some(ALPN_TUNNEL) {
            return Err(io::Error::other("peer did not negotiate the tunnel ALPN"));
        }
        let remote = session
            .peer_certificates()
            .and_then(|certs| certs.first())
            .and_then(|cert| spki_to_id(cert.as_ref()))
            .ok_or_else(|| io::Error::other("agent presented no valid ed25519 key"))?;
        Ok(TlsConn::spawn(tls, remote, yamux::Mode::Server))
    }
}

type OpenReply = oneshot::Sender<yamux::Result<yamux::Stream>>;

#[derive(Debug)]
struct Inner {
    remote: EndpointId,
    id: usize,
    open_tx: mpsc::Sender<OpenReply>,
    open_slots: Arc<Semaphore>,
    /// Unbounded is fine: yamux ends the connection if the peer opens more
    /// streams than its limit.
    accept_rx: Mutex<mpsc::UnboundedReceiver<yamux::Stream>>,
    /// Cancelled by a local `close` or a connection failure. yamux does not
    /// wake streams parked on a locally closed connection, so they watch this.
    aborted: CancellationToken,
    closed: CancellationToken,
    reason: Arc<OnceLock<String>>,
}

impl Inner {
    fn abort_error(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            self.reason
                .get()
                .cloned()
                .unwrap_or_else(|| "connection aborted".into()),
        )
    }
}

/// Handle to a multiplexed connection. Streams keep it alive, as iroh's
/// `Connection` does.
#[derive(Clone, Debug)]
pub struct TlsConn {
    inner: Arc<Inner>,
}

type Abort = Pin<Box<WaitForCancellationFutureOwned>>;

#[derive(Debug)]
pub struct TlsSend {
    half: WriteHalf<Compat<yamux::Stream>>,
    abort: Abort,
    conn: Arc<Inner>,
    _slot: Option<Arc<OwnedSemaphorePermit>>,
}

#[derive(Debug)]
pub struct TlsRecv {
    half: ReadHalf<Compat<yamux::Stream>>,
    abort: Abort,
    conn: Arc<Inner>,
    _slot: Option<Arc<OwnedSemaphorePermit>>,
}

enum End {
    CloseRequested,
    HandlesDropped,
    PeerClosed,
    Failed(String),
}

impl TlsConn {
    fn spawn<T>(io: T, remote: EndpointId, mode: yamux::Mode) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (open_tx, open_rx) = mpsc::channel(256);
        let (accept_tx, accept_rx) = mpsc::unbounded_channel();
        let inner = Arc::new(Inner {
            remote,
            id: NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed),
            open_tx,
            open_slots: Arc::new(Semaphore::new(MAX_STREAMS)),
            accept_rx: Mutex::new(accept_rx),
            aborted: CancellationToken::new(),
            closed: CancellationToken::new(),
            reason: Arc::new(OnceLock::new()),
        });
        let io = Linger { io, shut: false };
        let conn =
            yamux::Connection::new(TokioAsyncReadCompatExt::compat(io), yamux_config(), mode);
        tokio::spawn(drive(
            conn,
            open_rx,
            accept_tx,
            inner.aborted.clone(),
            inner.closed.clone(),
            Arc::clone(&inner.reason),
        ));
        Self { inner }
    }

    fn wrap(
        &self,
        stream: yamux::Stream,
        slot: Option<OwnedSemaphorePermit>,
    ) -> (TlsSend, TlsRecv) {
        let (read, write) = tokio::io::split(FuturesAsyncReadCompatExt::compat(stream));
        let slot = slot.map(Arc::new);
        let abort = || Box::pin(self.inner.aborted.clone().cancelled_owned());
        (
            TlsSend {
                half: write,
                abort: abort(),
                conn: Arc::clone(&self.inner),
                _slot: slot.clone(),
            },
            TlsRecv {
                half: read,
                abort: abort(),
                conn: Arc::clone(&self.inner),
                _slot: slot,
            },
        )
    }

    fn closed_error(&self) -> io::Error {
        io::Error::other(
            self.inner
                .reason
                .get()
                .cloned()
                .unwrap_or_else(|| "connection closed".into()),
        )
    }

    /// Waits for a free slot when `MAX_STREAMS` are open. yamux announces a
    /// stream with its first frame, so an opener that never writes stays
    /// invisible to the peer.
    pub async fn open_bi(&self) -> io::Result<(TlsSend, TlsRecv)> {
        tokio::select! {
            biased;
            () = self.inner.aborted.cancelled() => Err(self.inner.abort_error()),
            opened = self.open_stream() => opened,
        }
    }

    async fn open_stream(&self) -> io::Result<(TlsSend, TlsRecv)> {
        let slot = Arc::clone(&self.inner.open_slots)
            .acquire_owned()
            .await
            .map_err(|_e| self.closed_error())?;
        let (reply, stream) = oneshot::channel();
        self.inner
            .open_tx
            .send(reply)
            .await
            .map_err(|_e| self.closed_error())?;
        let stream = stream
            .await
            .map_err(|_e| self.closed_error())?
            .map_err(io::Error::other)?;
        Ok(self.wrap(stream, Some(slot)))
    }

    pub async fn accept_bi(&self) -> io::Result<(TlsSend, TlsRecv)> {
        let stream = self.inner.accept_rx.lock().await.recv().await;
        let Some(stream) = stream else {
            return Err(self.closed_error());
        };
        let (mut send, recv) = self.wrap(stream, None);
        // yamux acknowledges a stream with its first outgoing frame, and the
        // opener stalls after 256 unacknowledged ones. An empty write is that frame.
        poll_fn(|cx| AsyncWrite::poll_write(Pin::new(&mut send.half), cx, &[])).await?;
        Ok((send, recv))
    }

    /// yamux carries no close code, so `code` only reaches the local logs.
    pub fn close(&self, code: u32, reason: &[u8]) {
        let text = format!(
            "closed locally (code {code}): {}",
            String::from_utf8_lossy(reason)
        );
        drop(self.inner.reason.set(text));
        self.inner.aborted.cancel();
    }

    pub async fn closed(&self) -> io::Error {
        self.inner.closed.cancelled().await;
        self.closed_error()
    }

    #[must_use]
    pub fn remote_id(&self) -> EndpointId {
        self.inner.remote
    }

    #[must_use]
    pub fn stable_id(&self) -> usize {
        self.inner.id
    }
}

/// Reads on after shutdown until the peer closes too, within `CLOSE_TIMEOUT`.
/// Dropping a socket that holds unread data resets the connection, and the
/// peer then fails a write before it has read our close.
struct Linger<T> {
    io: T,
    shut: bool,
}

impl<T: AsyncRead + Unpin> AsyncRead for Linger<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Linger<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.shut {
            ready!(Pin::new(&mut this.io).poll_shutdown(cx))?;
            this.shut = true;
        }
        let mut discarded = [0u8; 4096];
        loop {
            let mut buf = ReadBuf::new(&mut discarded);
            let read = ready!(Pin::new(&mut this.io).poll_read(cx, &mut buf));
            if read.is_err() || buf.filled().is_empty() {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

async fn drive<T>(
    mut conn: yamux::Connection<Compat<Linger<T>>>,
    mut open_rx: mpsc::Receiver<OpenReply>,
    accept_tx: mpsc::UnboundedSender<yamux::Stream>,
    aborted: CancellationToken,
    closed: CancellationToken,
    reason: Arc<OnceLock<String>>,
) where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut close_fut = std::pin::pin!(aborted.cancelled());
    let mut pending: Option<OpenReply> = None;
    let end = poll_fn(|cx| {
        loop {
            if close_fut.as_mut().poll(cx).is_ready() {
                return Poll::Ready(End::CloseRequested);
            }
            if pending.is_none() {
                match open_rx.poll_recv(cx) {
                    Poll::Ready(Some(reply)) => pending = Some(reply),
                    Poll::Ready(None) => return Poll::Ready(End::HandlesDropped),
                    Poll::Pending => {}
                }
            }
            if let Some(reply) = pending.take() {
                if reply.is_closed() {
                    continue;
                }
                match conn.poll_new_outbound(cx) {
                    Poll::Ready(stream) => {
                        drop(reply.send(stream));
                        continue;
                    }
                    Poll::Pending => pending = Some(reply),
                }
            }
            match conn.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(stream))) => {
                    drop(accept_tx.send(stream));
                }
                Poll::Ready(Some(Err(e))) => return Poll::Ready(End::Failed(e.to_string())),
                Poll::Ready(None) => return Poll::Ready(End::PeerClosed),
                Poll::Pending => return Poll::Pending,
            }
        }
    })
    .await;
    let failed = matches!(end, End::Failed(_));
    let text = match end {
        End::CloseRequested => "closed locally".to_owned(),
        End::HandlesDropped => "all handles dropped".to_owned(),
        End::PeerClosed => "closed by peer".to_owned(),
        End::Failed(e) => e,
    };
    drop(reason.set(text));
    if failed {
        // yamux reports a failed connection to its streams as a clean EOF.
        aborted.cancel();
    }
    drop(tokio::time::timeout(CLOSE_TIMEOUT, poll_fn(|cx| conn.poll_close(cx))).await);
    closed.cancel();
}

impl TlsSend {
    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        AsyncWriteExt::write_all(self, buf).await
    }

    pub async fn finish(&mut self) -> io::Result<()> {
        AsyncWriteExt::shutdown(self).await
    }
}

impl TlsRecv {
    pub async fn read_to_end(&mut self, limit: usize) -> io::Result<Vec<u8>> {
        let mut buf = Vec::new();
        // One byte past the limit tells "exactly limit" from "too long".
        let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
        AsyncReadExt::take(&mut *self, cap)
            .read_to_end(&mut buf)
            .await?;
        if buf.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stream exceeds the read limit",
            ));
        }
        Ok(buf)
    }
}

impl AsyncWrite for TlsSend {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.abort.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(self.conn.abort_error()));
        }
        Pin::new(&mut self.half).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.abort.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(self.conn.abort_error()));
        }
        Pin::new(&mut self.half).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.abort.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(self.conn.abort_error()));
        }
        Pin::new(&mut self.half).poll_shutdown(cx)
    }
}

impl AsyncRead for TlsRecv {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.abort.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(self.conn.abort_error()));
        }
        Pin::new(&mut self.half).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use tokio::net::TcpListener;
    use tokio::time::timeout;

    use super::*;

    const SETUP: Duration = Duration::from_secs(10);

    fn identity() -> TlsIdentity {
        TlsIdentity::new(&SecretKey::generate()).unwrap()
    }

    async fn connected_pair() -> (TlsConn, TlsConn, TlsIdentity, TlsIdentity) {
        let edge = identity();
        let agent = identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tls_listener = TlsListener::new(&edge).unwrap();
        let accept = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            tls_listener.accept(tcp).await
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let dialed = timeout(SETUP, TlsDialer::new(agent.clone()).connect(tcp, edge.id()))
            .await
            .unwrap()
            .unwrap();
        let accepted = timeout(SETUP, accept).await.unwrap().unwrap().unwrap();
        (dialed, accepted, edge, agent)
    }

    /// Handshakes a client built by `client` against a fresh edge and returns
    /// what the edge's `accept` made of it.
    async fn edge_accepts(
        client: impl FnOnce(&TlsIdentity) -> ClientConfig,
    ) -> io::Result<TlsConn> {
        let edge = identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tls_listener = TlsListener::new(&edge).unwrap();
        let accept = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            tls_listener.accept(tcp).await
        });
        let config = client(&edge);
        let tcp = TcpStream::connect(addr).await.unwrap();
        let name = ServerName::try_from(SERVER_NAME).unwrap();
        // The client may finish its side before the edge rejects it.
        drop(
            tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(name, tcp)
                .await,
        );
        timeout(SETUP, accept).await.unwrap().unwrap()
    }

    fn pinned_client_builder(
        edge: &TlsIdentity,
    ) -> rustls::ConfigBuilder<ClientConfig, rustls::client::WantsClientCert> {
        let crypto = Arc::new(provider::default_provider());
        let verifier = PinnedEdge {
            spki: id_to_spki(&edge.id()),
            algs: crypto.signature_verification_algorithms,
        };
        ClientConfig::builder_with_provider(crypto)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
    }

    #[tokio::test]
    async fn the_harness_accepts_a_valid_ed25519_client() {
        let agent = identity();
        let expected = agent.id();
        let accepted = edge_accepts(|edge| {
            let mut config = pinned_client_builder(edge).with_client_cert_resolver(Arc::new(
                rustls::client::AlwaysResolvesClientRawPublicKeys::new(Arc::clone(&agent.key)),
            ));
            config.alpn_protocols = vec![ALPN_TUNNEL.to_vec()];
            config
        })
        .await
        .unwrap();
        assert_eq!(accepted.remote_id(), expected);
    }

    #[tokio::test]
    async fn the_edge_rejects_a_client_without_a_key() {
        let result = edge_accepts(|edge| {
            let mut config = pinned_client_builder(edge).with_no_client_auth();
            config.alpn_protocols = vec![ALPN_TUNNEL.to_vec()];
            config
        })
        .await;
        result.unwrap_err();
    }

    #[tokio::test]
    async fn the_edge_rejects_a_client_with_a_non_ed25519_key() {
        let result = edge_accepts(|edge| {
            let key_pair = rcgen::KeyPair::generate().unwrap();
            let pkcs8 = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
            let signer = provider::sign::any_supported_type(&pkcs8).unwrap();
            let spki = rcgen::PublicKeyData::subject_public_key_info(&key_pair);
            let certified = CertifiedKey::new(vec![CertificateDer::from(spki)], signer);
            let mut config = pinned_client_builder(edge).with_client_cert_resolver(Arc::new(
                rustls::client::AlwaysResolvesClientRawPublicKeys::new(Arc::new(certified)),
            ));
            config.alpn_protocols = vec![ALPN_TUNNEL.to_vec()];
            config
        })
        .await;
        result.unwrap_err();
    }

    #[tokio::test]
    async fn tunnel_sockets_get_keepalive_and_a_user_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        configure_tcp(&tcp).unwrap();
        let socket = socket2::SockRef::from(&tcp);
        assert!(tcp.nodelay().unwrap());
        assert!(socket.keepalive().unwrap());
        assert_eq!(socket.tcp_keepalive_time().unwrap(), KEEPALIVE_IDLE);
        assert_eq!(socket.tcp_keepalive_interval().unwrap(), KEEPALIVE_INTERVAL);
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            assert_eq!(socket.tcp_user_timeout().unwrap(), Some(USER_TIMEOUT));
            let detection = KEEPALIVE_IDLE + KEEPALIVE_INTERVAL * KEEPALIVE_RETRIES;
            assert!(USER_TIMEOUT > detection);
        }
    }

    #[test]
    fn spki_round_trips_and_rejects_other_shapes() {
        let id = SecretKey::generate().public();
        assert_eq!(spki_to_id(&id_to_spki(&id)), Some(id));
        assert_eq!(spki_to_id(&[0u8; 44]), None);
        assert_eq!(spki_to_id(&SPKI_PREFIX), None);
        let mut long = id_to_spki(&id);
        long.push(0);
        assert_eq!(spki_to_id(&long), None);
    }

    #[test]
    fn stream_cap_fits_the_connection_window() {
        // yamux asserts this when configuring; guard against a bad constant.
        let _ = yamux_config();
    }

    #[tokio::test]
    async fn handshake_reports_both_identities() {
        let (dialed, accepted, edge, agent) = connected_pair().await;
        assert_eq!(dialed.remote_id(), edge.id());
        assert_eq!(accepted.remote_id(), agent.id());
        assert_ne!(dialed.stable_id(), accepted.stable_id());
    }

    #[tokio::test]
    async fn dialing_with_the_wrong_edge_key_fails() {
        let edge = identity();
        let agent = identity();
        let impostor = identity();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tls_listener = TlsListener::new(&edge).unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            drop(tls_listener.accept(tcp).await);
        });
        let tcp = TcpStream::connect(addr).await.unwrap();
        let result = timeout(SETUP, TlsDialer::new(agent).connect(tcp, impostor.id()))
            .await
            .unwrap();
        assert!(is_pin_mismatch(&result.unwrap_err()));
    }

    #[tokio::test]
    async fn half_close_keeps_the_reply_path_open() {
        let (agent, edge, _, _) = connected_pair().await;
        let server = tokio::spawn(async move {
            let (mut send, mut recv) = edge.accept_bi().await.unwrap();
            let request = recv.read_to_end(1 << 20).await.unwrap();
            send.write_all(&request).await.unwrap();
            send.write_all(b"|done").await.unwrap();
            send.finish().await.unwrap();
            edge
        });
        let (mut send, mut recv) = agent.open_bi().await.unwrap();
        send.write_all(&vec![7u8; 100_000]).await.unwrap();
        send.finish().await.unwrap();
        let reply = recv.read_to_end(1 << 20).await.unwrap();
        assert_eq!(reply.len(), 100_005);
        assert!(reply.ends_with(b"|done"));
        let _edge = server.await.unwrap();
    }

    #[tokio::test]
    async fn read_to_end_enforces_its_limit() {
        let (agent, edge, _, _) = connected_pair().await;
        let (mut send, _recv) = agent.open_bi().await.unwrap();
        send.write_all(&[1u8; 100]).await.unwrap();
        send.finish().await.unwrap();
        let (_s, mut recv) = edge.accept_bi().await.unwrap();
        recv.read_to_end(99).await.unwrap_err();
    }

    #[tokio::test]
    async fn a_stalled_stream_does_not_block_another() {
        let (agent, edge, _, _) = connected_pair().await;
        let server = tokio::spawn(async move {
            let stalled = edge.accept_bi().await.unwrap();
            let (mut send, mut recv) = edge.accept_bi().await.unwrap();
            let mut byte = [0u8; 1];
            while recv.read_exact(&mut byte).await.is_ok() {
                if send.write_all(&byte).await.is_err() {
                    break;
                }
            }
            drop(stalled);
        });
        let (mut big, _big_recv) = agent.open_bi().await.unwrap();
        let (mut probe_send, mut probe_recv) = agent.open_bi().await.unwrap();
        // The receiver never reads, so this fills the stream window and blocks.
        let writer = tokio::spawn(async move {
            let chunk = vec![1u8; 64 * 1024];
            for _ in 0..1024 {
                if big.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        let started = Instant::now();
        for _ in 0..50 {
            probe_send.write_all(&[9]).await.unwrap();
            let mut byte = [0u8; 1];
            timeout(SETUP, probe_recv.read_exact(&mut byte))
                .await
                .unwrap()
                .unwrap();
        }
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!writer.is_finished());
        writer.abort();
        probe_send.finish().await.unwrap();
        timeout(SETUP, server).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn dropping_both_halves_ends_the_peer_stream() {
        let (agent, edge, _, _) = connected_pair().await;
        let (mut send, recv) = agent.open_bi().await.unwrap();
        send.write_all(b"x").await.unwrap();
        let (_edge_send, mut edge_recv) = edge.accept_bi().await.unwrap();
        drop(send);
        drop(recv);
        // EOF or a reset both end the read; hanging is the failure.
        drop(timeout(SETUP, edge_recv.read_to_end(1024)).await.unwrap());
    }

    #[tokio::test]
    async fn a_thousand_streams_open_and_echo() {
        let (agent, edge, _, _) = connected_pair().await;
        let server = tokio::spawn(async move {
            let mut held = Vec::new();
            for _ in 0..1000 {
                let (mut send, mut recv) = edge.accept_bi().await.unwrap();
                let mut byte = [0u8; 1];
                recv.read_exact(&mut byte).await.unwrap();
                send.write_all(&byte).await.unwrap();
                held.push((send, recv));
            }
            (held, edge)
        });
        let mut open = Vec::new();
        for i in 0..1000usize {
            let (mut send, mut recv) = agent.open_bi().await.unwrap();
            send.write_all(&[u8::try_from(i % 251).unwrap()])
                .await
                .unwrap();
            let mut byte = [0u8; 1];
            timeout(SETUP, recv.read_exact(&mut byte))
                .await
                .unwrap()
                .unwrap();
            open.push((send, recv));
        }
        let (held, _edge) = server.await.unwrap();
        assert_eq!((open.len(), held.len()), (1000, 1000));
    }

    #[tokio::test]
    async fn local_close_fails_parked_reads() {
        let (agent, edge, _, _) = connected_pair().await;
        let (mut send, mut recv) = agent.open_bi().await.unwrap();
        send.write_all(b"x").await.unwrap();
        let _held = edge.accept_bi().await.unwrap();
        let reader = tokio::spawn(async move { recv.read_to_end(1024).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        agent.close(0, b"superseded");
        timeout(Duration::from_secs(3), reader)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
    }

    #[tokio::test]
    async fn opens_beyond_the_stream_cap_wait() {
        let (agent, edge, _, _) = connected_pair().await;
        let server = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((mut send, mut recv)) = edge.accept_bi().await {
                let mut byte = [0u8; 1];
                if recv.read_exact(&mut byte).await.is_err() {
                    break;
                }
                send.write_all(&byte).await.unwrap();
                held.push((send, recv));
            }
            held
        });
        let mut open = Vec::new();
        for _ in 0..MAX_STREAMS {
            let (mut send, mut recv) = agent.open_bi().await.unwrap();
            send.write_all(&[1]).await.unwrap();
            let mut byte = [0u8; 1];
            timeout(SETUP, recv.read_exact(&mut byte))
                .await
                .unwrap()
                .unwrap();
            open.push((send, recv));
        }
        timeout(Duration::from_millis(300), agent.open_bi())
            .await
            .unwrap_err();
        drop(open.pop());
        timeout(Duration::from_secs(3), agent.open_bi())
            .await
            .unwrap()
            .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn unreplied_streams_do_not_block_new_opens() {
        let (agent, edge, _, _) = connected_pair().await;
        let server = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((send, mut recv)) = edge.accept_bi().await {
                let mut byte = [0u8; 1];
                if recv.read_exact(&mut byte).await.is_err() {
                    break;
                }
                held.push((send, recv));
            }
            held
        });
        let mut open = Vec::new();
        for _ in 0..300 {
            let (mut send, recv) = timeout(Duration::from_secs(2), agent.open_bi())
                .await
                .unwrap()
                .unwrap();
            send.write_all(&[1]).await.unwrap();
            open.push((send, recv));
        }
        assert_eq!(open.len(), 300);
        server.abort();
    }

    #[tokio::test]
    async fn closing_wakes_the_peer_and_fails_accepts() {
        let (agent, edge, _, _) = connected_pair().await;
        agent.close(7, b"bye");
        let err = timeout(SETUP, edge.closed()).await.unwrap();
        assert!(err.to_string().contains("closed by peer"));
        edge.accept_bi().await.unwrap_err();
        let local = timeout(SETUP, agent.closed()).await.unwrap();
        assert!(local.to_string().contains("bye"));
    }

    #[tokio::test]
    async fn streams_keep_the_connection_alive() {
        let (agent, edge, _, _) = connected_pair().await;
        let (mut send, mut recv) = agent.open_bi().await.unwrap();
        send.write_all(b"x").await.unwrap();
        let (mut edge_send, mut edge_recv) = edge.accept_bi().await.unwrap();
        drop(agent);
        drop(edge);
        let mut byte = [0u8; 1];
        timeout(SETUP, edge_recv.read_exact(&mut byte))
            .await
            .unwrap()
            .unwrap();
        edge_send.write_all(&byte).await.unwrap();
        timeout(SETUP, recv.read_exact(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&byte, b"x");
    }
}
