use iroh::endpoint::{Connection, QuicTransportConfig, VarInt, presets::Minimal};
use towonel_common::protocol::ALPN_TUNNEL;
use towonel_common::tunnel::read_handshake;

use super::*;

fn context() -> Arc<ConnCtx> {
    let metrics = EdgeMetrics::new();
    Arc::new(ConnCtx {
        router: Arc::new(Router::load_from_config(&[]).unwrap()),
        sessions: Arc::new(SessionRegistry::new(metrics.clone(), 10)),
        metrics,
        proxy_protocol: Arc::default(),
        hub_client: None,
        connection_permits: Arc::new(tokio::sync::Semaphore::new(10)),
    })
}

async fn endpoint(streams: u32) -> Endpoint {
    Endpoint::builder(Minimal)
        .alpns(vec![ALPN_TUNNEL.to_vec()])
        .clear_ip_transports()
        .bind_addr("127.0.0.1:0")
        .unwrap()
        .transport_config(
            QuicTransportConfig::builder()
                .max_concurrent_bidi_streams(VarInt::from_u32(streams))
                .build(),
        )
        .bind()
        .await
        .unwrap()
}

async fn register(
    ctx: &ConnCtx,
    agent: &Endpoint,
    edge: &Endpoint,
    acks: bool,
) -> (Connection, Arc<AgentSession>) {
    let addr =
        EndpointAddr::new(edge.id()).with_ip_addr(edge.bound_sockets().into_iter().next().unwrap());
    let (agent_conn, edge_conn) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(agent.connect(addr, ALPN_TUNNEL), async {
            edge.accept().await.unwrap().await.unwrap()
        })
    })
    .await
    .unwrap();
    let session = Arc::new(AgentSession::new(agent.id(), TunnelConn::Iroh(edge_conn)));
    if acks {
        session.enable_stream_acks();
    }
    ctx.sessions.register(&session);
    (agent_conn.unwrap(), session)
}

fn addrs() -> ClientAddrs {
    ClientAddrs {
        src: "127.0.0.1:1234".parse().unwrap(),
        dst: "127.0.0.1:443".parse().unwrap(),
    }
}

#[tokio::test]
async fn stalled_agent_fails_over_before_client_data_is_consumed() {
    use tokio::io::AsyncReadExt;

    let ctx = context();
    let edge = endpoint(100).await;
    let bad = endpoint(100).await;
    let good = endpoint(100).await;
    let (bad_conn, _) = register(&ctx, &bad, &edge, true).await;
    let (good_conn, _) = register(&ctx, &good, &edge, true).await;
    let responder_conn = good_conn.clone();
    let responder = tokio::spawn(async move {
        let (mut send, mut recv) = responder_conn.accept_bi().await.unwrap();
        let (route, got_addrs) = read_handshake(&mut recv).await.unwrap();
        assert_eq!(route, format!("{STREAM_ACK_PREFIX}a.test"));
        assert_eq!(got_addrs, addrs());
        send.write_all(&[CONTROL_STATUS_OK]).await.unwrap();
        assert_eq!(recv.read_to_end(100).await.unwrap(), b"request");
        send.write_all(b"response").await.unwrap();
        send.finish().unwrap();
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    client.write_all(b"request").await.unwrap();
    client.shutdown().await.unwrap();

    let candidates = smallvec::smallvec![EndpointAddr::new(bad.id())];
    let (selected, send, recv) = tokio::time::timeout(
        Duration::from_secs(10),
        pick_agent_and_open_stream(&ctx, Payload::Stream, "a.test", addrs(), candidates, || {
            Some(smallvec::smallvec![EndpointAddr::new(good.id())])
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(selected.id, good.id());
    // One timeout fails this connection over; it does not cost the stalled
    // agent's other connections their session.
    assert!(ctx.sessions.get(&bad.id()).is_some());
    assert!(bad_conn.close_reason().is_none());
    let mut untouched = [0; 7];
    assert_eq!(server.peek(&mut untouched).await.unwrap(), 7);
    assert_eq!(&untouched, b"request");
    let piped = pipe_tcp(server, "a.test", send, recv, &ctx.metrics);
    let (forwarded, response) = tokio::join!(piped, async {
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        response
    });
    assert_eq!(forwarded.unwrap(), (7, 8));
    assert_eq!(response, b"response");
    responder.await.unwrap();
    bad.close().await;
    good.close().await;
    edge.close().await;
}

#[tokio::test]
async fn an_agent_that_keeps_timing_out_is_evicted() {
    let ctx = context();
    let edge = endpoint(100).await;
    let agent = endpoint(100).await;
    let (conn, session) = register(&ctx, &agent, &edge, true).await;
    // Admissions have been timing out for most of the grace period already.
    let now = Instant::now();
    for ago in [12, 6] {
        let then = now.checked_sub(Duration::from_secs(ago)).unwrap();
        session.admission_timed_out(then, ADMISSION_FAILURE_GRACE);
    }

    open_agent_stream(&ctx, agent.id(), "a.test", addrs())
        .await
        .unwrap_err();
    assert!(ctx.sessions.get(&agent.id()).is_none());
    tokio::time::timeout(Duration::from_secs(1), conn.closed())
        .await
        .unwrap();
    agent.close().await;
    edge.close().await;
}

#[tokio::test]
async fn timeouts_far_apart_are_not_one_run() {
    let ctx = context();
    let edge = endpoint(100).await;
    let agent = endpoint(100).await;
    let (_conn, session) = register(&ctx, &agent, &edge, false).await;
    let now = Instant::now();
    let half_an_hour_ago = now.checked_sub(Duration::from_mins(30)).unwrap();
    session.admission_timed_out(half_an_hour_ago, ADMISSION_FAILURE_GRACE);
    let failing_for = session.admission_timed_out(now, ADMISSION_FAILURE_GRACE);
    assert_eq!(failing_for, Duration::ZERO);
    agent.close().await;
    edge.close().await;
}

#[tokio::test]
async fn an_admitted_stream_ends_a_run_of_timeouts() {
    let ctx = context();
    let edge = endpoint(100).await;
    let agent = endpoint(100).await;
    let (conn, session) = register(&ctx, &agent, &edge, false).await;
    let earlier = Instant::now().checked_sub(Duration::from_secs(5)).unwrap();
    session.admission_timed_out(earlier, ADMISSION_FAILURE_GRACE);

    let _stream = open_agent_stream(&ctx, agent.id(), "a.test", addrs())
        .await
        .unwrap();
    let failing_for = session.admission_timed_out(Instant::now(), ADMISSION_FAILURE_GRACE);
    assert_eq!(failing_for, Duration::ZERO);
    drop(conn);
    agent.close().await;
    edge.close().await;
}

#[tokio::test]
async fn a_client_reset_stops_the_agent_without_losing_the_request() {
    let ctx = context();
    let edge = endpoint(100).await;
    let agent = endpoint(100).await;
    let (conn, _) = register(&ctx, &agent, &edge, false).await;
    let (send, recv) = open_agent_stream(&ctx, agent.id(), "a.test", addrs())
        .await
        .unwrap();
    // The agent's side: an origin that takes the request and never answers.
    let (origin_reply, mut request) = conn.accept_bi().await.unwrap();
    read_handshake(&mut request).await.unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let metrics = ctx.metrics.clone();
    let piping =
        tokio::spawn(async move { pipe_tcp(server, "a.test", send, recv, &metrics).await });

    client.write_all(b"req").await.unwrap();
    // Linger 0 makes the close a reset, as a client that gave up sends.
    socket2::SockRef::from(&client)
        .set_linger(Some(Duration::ZERO))
        .unwrap();
    drop(client);

    // The request arrives whole and ends cleanly; the reply is refused.
    let got = tokio::time::timeout(Duration::from_secs(2), request.read_to_end(16))
        .await
        .expect("agent stream still open after the client reset");
    assert_eq!(got.unwrap(), b"req");
    let stopped = tokio::time::timeout(Duration::from_secs(2), origin_reply.stopped())
        .await
        .expect("agent was not told to stop replying");
    assert!(matches!(stopped, Ok(Some(_))));
    let forwarded = tokio::time::timeout(Duration::from_secs(2), piping)
        .await
        .expect("pipe still running after the client reset")
        .unwrap()
        .unwrap();
    assert_eq!(forwarded, (3, 0));
    assert_eq!(
        ctx.metrics
            .forward_errors
            .with_label_values(&["client_to_agent"])
            .get(),
        1
    );
    agent.close().await;
    edge.close().await;
}

#[tokio::test]
async fn legacy_agent_receives_plain_header() {
    let ctx = context();
    let edge = endpoint(100).await;
    let agent = endpoint(100).await;
    let (conn, _) = register(&ctx, &agent, &edge, false).await;
    let (_, mut recv) = open_agent_stream(&ctx, agent.id(), "a.test", addrs())
        .await
        .unwrap();
    let (mut send, mut request) = conn.accept_bi().await.unwrap();
    assert_eq!(read_handshake(&mut request).await.unwrap().0, "a.test");
    send.write_all(b"response").await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(100).await.unwrap(), b"response");
    agent.close().await;
    edge.close().await;
}

#[tokio::test]
async fn stale_admission_failure_keeps_replacement() {
    let ctx = context();
    let edge = endpoint(100).await;
    let agent = endpoint(100).await;
    let (old_conn, _) = register(&ctx, &agent, &edge, true).await;
    let opening = tokio::spawn({
        let ctx = Arc::clone(&ctx);
        let id = agent.id();
        async move { open_agent_stream(&ctx, id, "a.test", addrs()).await }
    });
    let (_send, mut recv) = old_conn.accept_bi().await.unwrap();
    read_handshake(&mut recv).await.unwrap();
    let (_new_conn, replacement) = register(&ctx, &agent, &edge, true).await;
    opening.await.unwrap().unwrap_err();
    assert_eq!(
        ctx.sessions.get(&agent.id()).unwrap().conn_stable_id(),
        replacement.conn_stable_id()
    );
    agent.close().await;
    edge.close().await;
}

#[tokio::test]
async fn exhausted_stream_credit_does_not_evict_session() {
    let ctx = context();
    let edge = endpoint(100).await;
    let agent = endpoint(1).await;
    let (_conn, session) = register(&ctx, &agent, &edge, true).await;
    let _held = session.open_stream().await.unwrap();
    open_agent_stream(&ctx, agent.id(), "a.test", addrs())
        .await
        .unwrap_err();
    assert!(ctx.sessions.get(&agent.id()).is_some());
    assert_eq!(
        ctx.metrics.connections_rejected_overload.agent_stream.get(),
        1
    );
    agent.close().await;
    edge.close().await;
}

#[tokio::test]
async fn invalid_client_addresses_do_not_evict_session() {
    let ctx = context();
    let edge = endpoint(100).await;
    let agent = endpoint(100).await;
    let (_conn, session) = register(&ctx, &agent, &edge, true).await;
    let mut client_addrs = addrs();
    client_addrs.dst = "[::1]:443".parse().unwrap();
    open_agent_stream(&ctx, agent.id(), "a.test", client_addrs)
        .await
        .unwrap_err();
    assert_eq!(
        ctx.sessions.get(&agent.id()).unwrap().conn_stable_id(),
        session.conn_stable_id()
    );
    agent.close().await;
    edge.close().await;
}
