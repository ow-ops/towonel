//! Transport-neutral handles for agent↔edge tunnel connections.
//!
//! Enums rather than trait objects so the iroh path keeps static dispatch and
//! its zero-copy `read_chunk` copy loop.

pub mod tls;

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use iroh::EndpointId;
use tokio::io::{AsyncRead, AsyncWrite, BufReader, ReadBuf};

use crate::tunnel::{COPY_BUF_SIZE, copy_buf_counting, forward_quic_to_writer};

use self::tls::{TlsConn, TlsRecv, TlsSend};

#[derive(Debug, Clone)]
pub enum TunnelConn {
    Iroh(iroh::endpoint::Connection),
    Tls(TlsConn),
}

#[derive(Debug)]
pub enum TunnelSend {
    Iroh(iroh::endpoint::SendStream),
    Tls(TlsSend),
}

#[derive(Debug)]
pub enum TunnelRecv {
    Iroh(iroh::endpoint::RecvStream),
    Tls(TlsRecv),
}

impl TunnelConn {
    pub async fn open_bi(&self) -> io::Result<(TunnelSend, TunnelRecv)> {
        match self {
            Self::Iroh(c) => {
                let (send, recv) = c.open_bi().await.map_err(io::Error::other)?;
                Ok((TunnelSend::Iroh(send), TunnelRecv::Iroh(recv)))
            }
            Self::Tls(c) => {
                let (send, recv) = c.open_bi().await?;
                Ok((TunnelSend::Tls(send), TunnelRecv::Tls(recv)))
            }
        }
    }

    pub async fn accept_bi(&self) -> io::Result<(TunnelSend, TunnelRecv)> {
        match self {
            Self::Iroh(c) => {
                let (send, recv) = c.accept_bi().await.map_err(io::Error::other)?;
                Ok((TunnelSend::Iroh(send), TunnelRecv::Iroh(recv)))
            }
            Self::Tls(c) => {
                let (send, recv) = c.accept_bi().await?;
                Ok((TunnelSend::Tls(send), TunnelRecv::Tls(recv)))
            }
        }
    }

    pub fn close(&self, code: u32, reason: &[u8]) {
        match self {
            Self::Iroh(c) => c.close(code.into(), reason),
            Self::Tls(c) => c.close(code, reason),
        }
    }

    pub async fn closed(&self) -> io::Error {
        match self {
            Self::Iroh(c) => io::Error::other(c.closed().await),
            Self::Tls(c) => c.closed().await,
        }
    }

    #[must_use]
    pub fn remote_id(&self) -> EndpointId {
        match self {
            Self::Iroh(c) => c.remote_id(),
            Self::Tls(c) => c.remote_id(),
        }
    }

    #[must_use]
    pub fn stable_id(&self) -> usize {
        match self {
            Self::Iroh(c) => c.stable_id(),
            Self::Tls(c) => c.stable_id(),
        }
    }
}

impl TunnelSend {
    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Self::Iroh(s) => s.write_all(buf).await.map_err(io::Error::other),
            Self::Tls(s) => s.write_all(buf).await,
        }
    }

    pub async fn finish(&mut self) -> io::Result<()> {
        match self {
            Self::Iroh(s) => s.finish().map_err(io::Error::other),
            Self::Tls(s) => s.finish().await,
        }
    }

    /// Resolves once the peer has stopped reading this stream, which a proxy
    /// takes to mean that whoever it was writing for has gone. Never resolves
    /// over TLS, where a peer's two halves close together.
    pub fn stopped(&self) -> impl Future<Output = ()> + Send + 'static {
        let stopped = match self {
            Self::Iroh(s) => Some(s.stopped()),
            Self::Tls(_) => None,
        };
        async move {
            let stopped = match stopped {
                Some(stopped) => matches!(stopped.await, Ok(Some(_))),
                None => false,
            };
            if !stopped {
                // Finished or lost: the copy this races against ends by itself.
                std::future::pending::<()>().await;
            }
        }
    }

    pub fn reset(&mut self, code: u32) -> io::Result<()> {
        match self {
            Self::Iroh(s) => s.reset(code.into()).map_err(io::Error::other),
            // No-op: yamux cannot reset a split stream; the peer sees FIN or RST
            // only once both halves drop.
            Self::Tls(_) => Ok(()),
        }
    }
}

impl TunnelRecv {
    pub async fn read_to_end(&mut self, limit: usize) -> io::Result<Vec<u8>> {
        match self {
            Self::Iroh(r) => r.read_to_end(limit).await.map_err(io::Error::other),
            Self::Tls(r) => r.read_to_end(limit).await,
        }
    }

    /// Byte count is returned even on error; see [`forward_quic_to_writer`].
    pub async fn forward_to_writer<W>(&mut self, writer: &mut W) -> (u64, io::Result<()>)
    where
        W: AsyncWrite + Unpin,
    {
        match self {
            Self::Iroh(r) => forward_quic_to_writer(r, writer).await,
            Self::Tls(r) => {
                let mut reader = BufReader::with_capacity(COPY_BUF_SIZE, r);
                copy_buf_counting(&mut reader, writer).await
            }
        }
    }
}

impl AsyncWrite for TunnelSend {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Iroh(s) => AsyncWrite::poll_write(Pin::new(s), cx, buf),
            Self::Tls(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Iroh(s) => AsyncWrite::poll_flush(Pin::new(s), cx),
            Self::Tls(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Iroh(s) => AsyncWrite::poll_shutdown(Pin::new(s), cx),
            Self::Tls(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl AsyncRead for TunnelRecv {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Iroh(r) => AsyncRead::poll_read(Pin::new(r), cx, buf),
            Self::Tls(r) => Pin::new(r).poll_read(cx, buf),
        }
    }
}
