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
    assert!(ctx.sessions.get(&bad.id()).is_none());
    tokio::time::timeout(Duration::from_secs(1), bad_conn.closed())
        .await
        .unwrap();
    let mut untouched = [0; 7];
    assert_eq!(server.peek(&mut untouched).await.unwrap(), 7);
    assert_eq!(&untouched, b"request");
    let (forwarded, response) = tokio::join!(pipe_tcp(server, "a.test", send, recv), async {
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
