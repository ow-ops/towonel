//! The same workload over QUIC and over TLS/TCP, through `TunnelConn`, so the two
//! can be compared under the shaping `tests/transport-compare.sh` applies.
//!
//! One probe stream pings while several bulk streams download in the agent -> edge
//! direction; the probe's round trips show what a busy connection does to a
//! small flow, which is where TCP's shared loss recovery differs from QUIC's.

use std::any::Any;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use iroh::EndpointAddr;
use iroh::endpoint::{Endpoint, presets::Minimal};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use towonel_common::protocol::{ALPN_TUNNEL, tunnel_transport_config};
use towonel_common::transport::TunnelConn;
use towonel_common::transport::tls::{TlsDialer, TlsIdentity, TlsListener};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

const BULK_BYTES: usize = 32 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;
const PROBE_EVERY: Duration = Duration::from_millis(20);
const STEP_TIMEOUT: Duration = Duration::from_secs(120);

/// Connections plus anything that must stay alive while they are used. The
/// opener is the edge; the acceptor is the agent that serves the streams.
struct Pair {
    edge: TunnelConn,
    agent: TunnelConn,
    _keep: Box<dyn Any + Send>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "WAN-shaped diagnostic; run tests/transport-compare.sh"]
async fn compare_quic() -> TestResult {
    run("quic", quic_pair().await?).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "WAN-shaped diagnostic; run tests/transport-compare.sh"]
async fn compare_tls() -> TestResult {
    run("tls", tls_pair().await?).await
}

async fn quic_pair() -> Result<Pair, Box<dyn std::error::Error + Send + Sync>> {
    let edge = Endpoint::builder(Minimal)
        .alpns(vec![ALPN_TUNNEL.to_vec()])
        .transport_config(tunnel_transport_config())
        .clear_ip_transports()
        .bind_addr("127.0.0.2:0")?
        .bind()
        .await?;
    let agent = Endpoint::builder(Minimal)
        .transport_config(tunnel_transport_config())
        .clear_ip_transports()
        .bind_addr("127.0.0.3:0")?
        .bind()
        .await?;
    let addr = edge
        .bound_sockets()
        .into_iter()
        .next()
        .ok_or("no edge socket")?;
    let (agent_conn, edge_conn) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            agent.connect(EndpointAddr::new(edge.id()).with_ip_addr(addr), ALPN_TUNNEL),
            async {
                edge.accept()
                    .await
                    .ok_or("no incoming")?
                    .await
                    .map_err(|e| e.to_string())
            }
        )
    })
    .await?;
    let edge_conn = edge_conn?;
    Ok(Pair {
        edge: TunnelConn::Iroh(edge_conn),
        agent: TunnelConn::Iroh(agent_conn?),
        _keep: Box::new((edge, agent)),
    })
}

async fn tls_pair() -> Result<Pair, Box<dyn std::error::Error + Send + Sync>> {
    let edge_identity = TlsIdentity::new(&iroh::SecretKey::generate())?;
    let agent_identity = TlsIdentity::new(&iroh::SecretKey::generate())?;
    let socket = TcpListener::bind("127.0.0.2:0").await?;
    let addr = socket.local_addr()?;
    let listener = TlsListener::new(&edge_identity)?;
    let accepted = tokio::spawn(async move {
        let (tcp, _) = socket.accept().await?;
        listener.accept(tcp).await
    });
    let tcp = TcpStream::connect(addr).await?;
    let agent = TlsDialer::new(agent_identity)
        .connect(tcp, edge_identity.id())
        .await?;
    let edge = accepted.await??;
    Ok(Pair {
        edge: TunnelConn::Tls(edge),
        agent: TunnelConn::Tls(agent),
        _keep: Box::new(()),
    })
}

async fn run(label: &str, pair: Pair) -> TestResult {
    let streams: usize = std::env::var("BULK_STREAMS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    let per_stream = BULK_BYTES / streams;

    let agent = pair.agent.clone();
    let server = tokio::spawn(async move {
        let mut handlers = JoinSet::new();
        while let Ok((mut send, mut recv)) = agent.accept_bi().await {
            handlers.spawn(async move {
                let mut tag = [0u8; 1];
                if recv.read_exact(&mut tag).await.is_err() {
                    return;
                }
                if tag[0] == b'B' {
                    let chunk = vec![7u8; CHUNK];
                    let mut left = per_stream;
                    while left > 0 {
                        let n = left.min(CHUNK);
                        if send.write_all(&chunk[..n]).await.is_err() {
                            return;
                        }
                        left -= n;
                    }
                    drop(send.finish().await);
                } else {
                    let mut ping = [0u8; 8];
                    while recv.read_exact(&mut ping).await.is_ok() {
                        if send.write_all(&ping).await.is_err() {
                            break;
                        }
                    }
                }
            });
        }
    });

    let (mut probe_send, mut probe_recv) = pair.edge.open_bi().await?;
    probe_send.write_all(b"P").await?;
    let mut warm = [0u8; 8];
    probe_send.write_all(&0u64.to_be_bytes()).await?;
    probe_recv.read_exact(&mut warm).await?;

    let done = Arc::new(AtomicBool::new(false));
    let started = Instant::now();
    let bulk = tokio::spawn({
        let (edge, done) = (pair.edge.clone(), Arc::clone(&done));
        async move {
            let mut readers = JoinSet::new();
            for _ in 0..streams {
                let edge = edge.clone();
                readers.spawn(async move {
                    let (mut send, mut recv) = edge.open_bi().await?;
                    send.write_all(b"B").await?;
                    let mut buf = vec![0u8; CHUNK];
                    let mut total = 0usize;
                    loop {
                        let n = recv.read(&mut buf).await?;
                        if n == 0 {
                            break;
                        }
                        total += n;
                    }
                    Ok::<usize, std::io::Error>(total)
                });
            }
            let mut received = 0usize;
            while let Some(result) = readers.join_next().await {
                received += result.expect("bulk task")?;
            }
            done.store(true, Ordering::Release);
            Ok::<usize, std::io::Error>(received)
        }
    });

    let mut rtts = Vec::new();
    let mut seq = 1u64;
    while !done.load(Ordering::Acquire) {
        let sent = Instant::now();
        probe_send.write_all(&seq.to_be_bytes()).await?;
        tokio::time::timeout(STEP_TIMEOUT, probe_recv.read_exact(&mut warm)).await??;
        rtts.push(sent.elapsed());
        seq += 1;
        tokio::time::sleep(PROBE_EVERY).await;
    }
    let received = tokio::time::timeout(STEP_TIMEOUT, bulk).await???;
    let elapsed = started.elapsed();
    assert_eq!(received, per_stream * streams);

    rtts.sort();
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    let at = |q: f64| rtts[((rtts.len() - 1) as f64 * q) as usize];
    #[expect(clippy::cast_precision_loss, reason = "diagnostic output")]
    let mib_s = received as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64();
    println!(
        "RESULT transport={label} streams={streams} loss={} mib_s={mib_s:.1} probes={} \
         probe_p50_ms={:.0} probe_p99_ms={:.0} probe_max_ms={:.0}",
        std::env::var("LOSS").unwrap_or_else(|_| "?".into()),
        rtts.len(),
        ms(at(0.5)),
        ms(at(0.99)),
        ms(*rtts.last().unwrap_or(&Duration::ZERO)),
    );
    server.abort();
    Ok(())
}
