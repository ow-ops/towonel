//! Transport-neutral handles for agent↔edge tunnel connections.
//!
//! Enums rather than trait objects so the iroh path keeps static dispatch and
//! its zero-copy `read_chunk` copy loop.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use iroh::EndpointId;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::tunnel::forward_quic_to_writer;

#[derive(Debug, Clone)]
pub enum TunnelConn {
    Iroh(iroh::endpoint::Connection),
}

#[derive(Debug)]
pub enum TunnelSend {
    Iroh(iroh::endpoint::SendStream),
}

#[derive(Debug)]
pub enum TunnelRecv {
    Iroh(iroh::endpoint::RecvStream),
}

impl TunnelConn {
    pub async fn open_bi(&self) -> io::Result<(TunnelSend, TunnelRecv)> {
        match self {
            Self::Iroh(c) => {
                let (send, recv) = c.open_bi().await.map_err(io::Error::other)?;
                Ok((TunnelSend::Iroh(send), TunnelRecv::Iroh(recv)))
            }
        }
    }

    pub async fn accept_bi(&self) -> io::Result<(TunnelSend, TunnelRecv)> {
        match self {
            Self::Iroh(c) => {
                let (send, recv) = c.accept_bi().await.map_err(io::Error::other)?;
                Ok((TunnelSend::Iroh(send), TunnelRecv::Iroh(recv)))
            }
        }
    }

    pub fn close(&self, code: u32, reason: &[u8]) {
        match self {
            Self::Iroh(c) => c.close(code.into(), reason),
        }
    }

    pub async fn closed(&self) -> io::Error {
        match self {
            Self::Iroh(c) => io::Error::other(c.closed().await),
        }
    }

    #[must_use]
    pub fn remote_id(&self) -> EndpointId {
        match self {
            Self::Iroh(c) => c.remote_id(),
        }
    }

    #[must_use]
    pub fn stable_id(&self) -> usize {
        match self {
            Self::Iroh(c) => c.stable_id(),
        }
    }
}

impl TunnelSend {
    pub async fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        match self {
            Self::Iroh(s) => s.write_all(buf).await.map_err(io::Error::other),
        }
    }

    #[expect(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "yamux closes with an awaited FIN frame"
    )]
    pub async fn finish(&mut self) -> io::Result<()> {
        match self {
            Self::Iroh(s) => s.finish().map_err(io::Error::other),
        }
    }

    pub fn reset(&mut self, code: u32) -> io::Result<()> {
        match self {
            Self::Iroh(s) => s.reset(code.into()).map_err(io::Error::other),
        }
    }
}

impl TunnelRecv {
    pub async fn read_to_end(&mut self, limit: usize) -> io::Result<Vec<u8>> {
        match self {
            Self::Iroh(r) => r.read_to_end(limit).await.map_err(io::Error::other),
        }
    }

    /// Byte count is returned even on error; see [`forward_quic_to_writer`].
    pub async fn forward_to_writer<W>(&mut self, writer: &mut W) -> (u64, io::Result<()>)
    where
        W: AsyncWrite + Unpin,
    {
        match self {
            Self::Iroh(r) => forward_quic_to_writer(r, writer).await,
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
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Iroh(s) => AsyncWrite::poll_flush(Pin::new(s), cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Iroh(s) => AsyncWrite::poll_shutdown(Pin::new(s), cx),
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
        }
    }
}
