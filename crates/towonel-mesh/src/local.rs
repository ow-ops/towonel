//! Unix-socket API so CLI tools reach the running node without their own
//! endpoint: two endpoints can't share one device key.
//!
//! One JSON request line, one JSON response line; after a successful `dial`
//! the socket carries the raw TCP stream.

use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::MeshNode;

const SOCKET_FILE: &str = "mesh.sock";
const MAX_LINE: u64 = 4096;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    Dial { peer: String, port: u16 },
    Status,
}

#[derive(Debug, Serialize, Deserialize)]
struct Reply {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    peers: Vec<PeerLine>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerLine {
    pub name: String,
    pub ipv4: String,
    pub connected: bool,
    pub relayed: Option<bool>,
}

#[must_use]
pub fn socket_path(state_dir: &Path) -> PathBuf {
    state_dir.join(SOCKET_FILE)
}

pub async fn serve(node: MeshNode, path: PathBuf, cancel: CancellationToken) -> anyhow::Result<()> {
    // A leftover socket from a crashed run would make bind fail.
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("remove stale {}", path.display())),
    }
    let listener = UnixListener::bind(&path).with_context(|| format!("bind {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    loop {
        let stream = tokio::select! {
            () = cancel.cancelled() => break,
            accepted = listener.accept() => accepted?.0,
        };
        let node = node.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(node, stream).await {
                debug!(error = %e, "local api client ended");
            }
        });
    }
    drop(std::fs::remove_file(&path));
    Ok(())
}

async fn handle(node: MeshNode, stream: UnixStream) -> anyhow::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut read = BufReader::new(read);
    let mut line = String::new();
    (&mut read).take(MAX_LINE).read_line(&mut line).await?;
    let request: Request = serde_json::from_str(&line).context("bad request")?;
    match request {
        Request::Status => {
            let peers = node
                .peers()
                .into_iter()
                .map(|p| PeerLine {
                    name: p.device.name,
                    ipv4: p.device.ipv4,
                    connected: p.connected,
                    relayed: p.relayed,
                })
                .collect();
            reply(&mut write, &Reply { error: None, peers }).await
        }
        Request::Dial { peer, port } => match node.open_tcp(&peer, port).await {
            Ok((mut send, mut recv)) => {
                reply(
                    &mut write,
                    &Reply {
                        error: None,
                        peers: Vec::new(),
                    },
                )
                .await?;
                let upstream = async {
                    let res = tokio::io::copy(&mut read, &mut send).await;
                    drop(send.finish());
                    res
                };
                let downstream = async {
                    let res = tokio::io::copy(&mut recv, &mut write).await;
                    drop(write.shutdown().await);
                    res
                };
                let (up, down) = tokio::join!(upstream, downstream);
                up?;
                down?;
                Ok(())
            }
            Err(e) => {
                let error = Some(format!("{e:#}"));
                reply(
                    &mut write,
                    &Reply {
                        error,
                        peers: Vec::new(),
                    },
                )
                .await
            }
        },
    }
}

async fn reply(write: &mut tokio::net::unix::OwnedWriteHalf, reply: &Reply) -> anyhow::Result<()> {
    let mut line = serde_json::to_vec(reply)?;
    line.push(b'\n');
    write.write_all(&line).await?;
    Ok(())
}

/// A socket carrying a TCP stream to `peer:port` through the node.
pub async fn dial(state_dir: &Path, peer: &str, port: u16) -> anyhow::Result<UnixStream> {
    let request = Request::Dial {
        peer: peer.to_string(),
        port,
    };
    let (stream, reply) = request_reply(state_dir, &request).await?;
    match reply.error {
        Some(e) => bail!(e),
        None => Ok(stream),
    }
}

pub async fn status(state_dir: &Path) -> anyhow::Result<Vec<PeerLine>> {
    let (_, reply) = request_reply(state_dir, &Request::Status).await?;
    match reply.error {
        Some(e) => bail!(e),
        None => Ok(reply.peers),
    }
}

async fn request_reply(state_dir: &Path, request: &Request) -> anyhow::Result<(UnixStream, Reply)> {
    let path = socket_path(state_dir);
    let mut stream = UnixStream::connect(&path).await.with_context(|| {
        format!(
            "the mesh daemon is not running ({}); start it with `towonel mesh up`",
            path.display()
        )
    })?;
    let mut line = serde_json::to_vec(request)?;
    line.push(b'\n');
    stream.write_all(&line).await?;
    // Byte by byte so nothing after the reply line is buffered away.
    let mut reply = Vec::new();
    loop {
        let b = stream
            .read_u8()
            .await
            .context("the mesh daemon closed the socket")?;
        if b == b'\n' {
            break;
        }
        if reply.len() as u64 >= MAX_LINE {
            bail!("reply from the mesh daemon is too long");
        }
        reply.push(b);
    }
    Ok((stream, serde_json::from_slice(&reply)?))
}
