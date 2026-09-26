//! Two in-process mesh nodes talking through the mesh, relay disabled.

use std::time::Duration;

use serde_json::{Value, json};
use towonel_common::identity::TenantKeypair;
use towonel_mesh::{MeshClient, MeshNode, NodeOptions, Stopped};

use super::api_tests::{signup_and_login_user, user_id_by_email};
use super::test_helpers::{OPERATOR_KEY, TestHub, create_invite, post_json, tenant_from_token};

struct Peer {
    node: MeshNode,
    id: String,
}

async fn join(hub: &TestHub, seed: u8, auth_key: &str, name: &str) -> Peer {
    let key = iroh::SecretKey::from([seed; 32]);
    let client = MeshClient::new(&hub.base_url, key.clone()).unwrap();
    client.enroll(auth_key, name, "linux").await.unwrap();
    let node = MeshNode::start(
        MeshClient::new(&hub.base_url, key.clone()).unwrap(),
        key.clone(),
        NodeOptions {
            bind: Some("127.0.0.1:0".parse().unwrap()),
        },
    )
    .await
    .unwrap();
    Peer {
        node,
        id: hex::encode(key.public().as_bytes()),
    }
}

/// Until `node` sees `name` with a reported endpoint.
async fn wait_for_peer(node: &MeshNode, name: &str) {
    let mut netmap = node.netmap();
    tokio::time::timeout(
        Duration::from_secs(10),
        netmap.wait_for(|m| {
            m.peers
                .iter()
                .any(|p| p.name == name && p.endpoint.is_some())
        }),
    )
    .await
    .expect("peer never showed up with an endpoint")
    .unwrap();
}

async fn echo_server() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                drop(tokio::io::copy(&mut r, &mut w).await);
            });
        }
    });
    port
}

async fn round_trip(node: &MeshNode, peer: &str, port: u16) -> anyhow::Result<Vec<u8>> {
    let (mut send, mut recv) = node.open_tcp(peer, port).await?;
    send.write_all(b"ping").await?;
    send.finish()?;
    Ok(recv.read_to_end(1024).await?)
}

/// Tenant owned by a fresh user, and an untagged key minted by that user.
async fn user_tenant(hub: &TestHub, client: &reqwest::Client) -> (TenantKeypair, String) {
    let cookie = Box::pin(signup_and_login_user(
        hub,
        client,
        "peer@example.test",
        "hunter22!",
    ))
    .await;
    let user_id = user_id_by_email(hub, "peer@example.test").await;
    let tenant =
        tenant_from_token(&create_invite(hub, client, "mesh-peer", &["p.mesh.test"]).await);
    hub.state
        .db
        .insert_tenant_ownership(super::db::tenant_ownership::NewTenantOwnership {
            user_id: &user_id,
            tenant_id: tenant.id().as_bytes(),
            invite_id: &[9u8; 16],
            display_name: "test",
            now_ms: 1,
        })
        .await
        .unwrap();
    let resp: Value = client
        .post(hub.url(&format!("/v1/tenants/{}/mesh/auth-keys", tenant.id())))
        .header(reqwest::header::COOKIE, &cookie)
        .json(&json!({"reusable": true}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    (tenant, resp["token"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn peers_forward_tcp_and_enforce_default_policy() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let (tenant, user_key) = Box::pin(user_tenant(&hub, &client)).await;
    let (_, server_key) = post_json(
        &client,
        &hub.url(&format!("/v1/tenants/{}/mesh/auth-keys", tenant.id())),
        json!({"tags": ["tag:server"]}),
        Some(OPERATOR_KEY),
    )
    .await;

    let laptop = join(&hub, 1, &user_key, "laptop").await;
    let phone = join(&hub, 2, &user_key, "phone").await;
    let server = join(&hub, 3, server_key["token"].as_str().unwrap(), "server").await;
    wait_for_peer(&phone.node, "laptop").await;
    wait_for_peer(&server.node, "laptop").await;
    wait_for_peer(&laptop.node, "server").await;

    let port = echo_server().await;
    assert_eq!(
        round_trip(&phone.node, "laptop", port).await.unwrap(),
        b"ping"
    );
    // By overlay IP too.
    assert_eq!(
        round_trip(&phone.node, "100.64.0.1", port).await.unwrap(),
        b"ping"
    );

    // Tagged devices can't initiate to user devices; users can reach them.
    let err = round_trip(&server.node, "laptop", port).await.unwrap_err();
    assert!(err.to_string().contains("does not accept"), "{err}");
    assert_eq!(
        round_trip(&laptop.node, "server", port).await.unwrap(),
        b"ping"
    );

    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_port = closed.local_addr().unwrap().port();
    drop(closed);
    let err = round_trip(&phone.node, "laptop", dead_port)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("nothing is listening"), "{err}");

    let err = round_trip(&phone.node, "nope", port).await.unwrap_err();
    assert!(err.to_string().contains("no device named"), "{err}");
}

#[tokio::test]
async fn revoked_peer_is_stopped_and_cut_off() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let (tenant, user_key) = Box::pin(user_tenant(&hub, &client)).await;
    let laptop = join(&hub, 1, &user_key, "laptop").await;
    let phone = join(&hub, 2, &user_key, "phone").await;
    wait_for_peer(&phone.node, "laptop").await;
    let port = echo_server().await;
    round_trip(&phone.node, "laptop", port).await.unwrap();

    let resp = client
        .delete(hub.url(&format!(
            "/v1/tenants/{}/mesh/devices/{}",
            tenant.id(),
            phone.id
        )))
        .bearer_auth(OPERATOR_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let reason = tokio::time::timeout(Duration::from_secs(10), phone.node.stopped())
        .await
        .expect("revoked node kept running");
    assert_eq!(reason, Some(Stopped::Revoked));

    // The laptop dropped the phone from its netmap and refuses it now.
    let mut netmap = laptop.node.netmap();
    tokio::time::timeout(
        Duration::from_secs(10),
        netmap.wait_for(|m| m.peers.is_empty()),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(laptop.node.peers().is_empty());
}

fn ipv4_udp(src: &str, dst: &str, sport: u16, dport: u16, payload: usize) -> bytes::Bytes {
    let src: std::net::Ipv4Addr = src.parse().unwrap();
    let dst: std::net::Ipv4Addr = dst.parse().unwrap();
    let total = u16::try_from(28 + payload).unwrap().to_be_bytes();
    let mut p = vec![0x45, 0, total[0], total[1], 0, 0, 0x40, 0, 64, 17, 0, 0];
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&u16::try_from(8 + payload).unwrap().to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.resize(28 + payload, 0x5a);
    p.into()
}

async fn recv_packet(rx: &mut tokio::sync::mpsc::Receiver<bytes::Bytes>) -> Option<bytes::Bytes> {
    tokio::time::timeout(Duration::from_millis(700), rx.recv())
        .await
        .ok()
        .flatten()
}

#[tokio::test]
async fn packets_route_between_peers_with_policy() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let (tenant, user_key) = Box::pin(user_tenant(&hub, &client)).await;
    let (_, server_key) = post_json(
        &client,
        &hub.url(&format!("/v1/tenants/{}/mesh/auth-keys", tenant.id())),
        json!({"tags": ["tag:server"]}),
        Some(OPERATOR_KEY),
    )
    .await;
    let laptop = join(&hub, 1, &user_key, "laptop").await;
    let phone = join(&hub, 2, &user_key, "phone").await;
    let server = join(&hub, 3, server_key["token"].as_str().unwrap(), "server").await;
    wait_for_peer(&phone.node, "laptop").await;
    wait_for_peer(&server.node, "laptop").await;
    wait_for_peer(&laptop.node, "server").await;
    let (laptop_ip, phone_ip, server_ip) = ("100.64.0.1", "100.64.0.2", "100.64.0.3");

    let (laptop_tx, mut laptop_rx) = laptop.node.packet_channel();
    let (phone_tx, mut phone_rx) = phone.node.packet_channel();
    let (server_tx, mut server_rx) = server.node.packet_channel();

    // Same user: delivered.
    let packet = ipv4_udp(phone_ip, laptop_ip, 5000, 6000, 100);
    phone_tx.send(packet.clone()).await.unwrap();
    assert_eq!(recv_packet(&mut laptop_rx).await, Some(packet));

    // A tagged server can't start a flow towards a user device…
    server_tx
        .send(ipv4_udp(server_ip, laptop_ip, 7000, 8000, 10))
        .await
        .unwrap();
    assert_eq!(recv_packet(&mut laptop_rx).await, None);

    // …but it can answer one the user started.
    let request = ipv4_udp(laptop_ip, server_ip, 8000, 7000, 10);
    laptop_tx.send(request.clone()).await.unwrap();
    assert_eq!(recv_packet(&mut server_rx).await, Some(request));
    let reply = ipv4_udp(server_ip, laptop_ip, 7000, 8000, 10);
    server_tx.send(reply.clone()).await.unwrap();
    assert_eq!(recv_packet(&mut laptop_rx).await, Some(reply));

    // Too big for a datagram: the sender's host gets "fragmentation needed".
    phone_tx
        .send(ipv4_udp(phone_ip, laptop_ip, 5000, 6000, 1600))
        .await
        .unwrap();
    let icmp = recv_packet(&mut phone_rx).await.expect("no ICMP back");
    assert_eq!((icmp[9], icmp[20], icmp[21]), (1, 3, 4));
    assert_eq!(recv_packet(&mut laptop_rx).await, None);

    // Packets not from this device's own overlay IP never leave it.
    phone_tx
        .send(ipv4_udp(server_ip, laptop_ip, 5000, 6000, 10))
        .await
        .unwrap();
    assert_eq!(recv_packet(&mut laptop_rx).await, None);
}

struct Collect(tokio::sync::mpsc::UnboundedSender<Vec<u8>>);

impl towonel_mesh_ffi::MeshListener for Collect {
    fn on_packet(&self, packet: Vec<u8>) {
        drop(self.0.send(packet));
    }
    fn on_peers_changed(&self, _peers: Vec<towonel_mesh_ffi::Device>) {}
    fn on_stopped(&self, _reason: towonel_mesh_ffi::StopReason) {}
}

/// The entry points the mobile and desktop apps call, end to end.
#[tokio::test]
async fn ffi_mesh_carries_packets() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let (_, user_key) = Box::pin(user_tenant(&hub, &client)).await;
    let dir = std::env::temp_dir().join(format!("towonel-ffi-test-{}", std::process::id()));

    let mut meshes = Vec::new();
    let mut inboxes = Vec::new();
    for name in ["tablet", "desktop"] {
        let mesh = towonel_mesh_ffi::Mesh::new(dir.join(name).display().to_string()).unwrap();
        assert!(mesh.enrollment().unwrap().is_none());
        let info = mesh
            .enroll_with_auth_key(hub.base_url.clone(), user_key.clone(), name.to_string())
            .await
            .unwrap();
        assert_eq!(mesh.enrollment().unwrap().unwrap().ipv4, info.ipv4);
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        mesh.start(std::sync::Arc::new(Collect(tx))).await.unwrap();
        meshes.push((mesh, info));
        inboxes.push(rx);
    }
    let (tablet, tablet_info) = &meshes[0];
    let (desktop, desktop_info) = &meshes[1];

    tokio::time::timeout(Duration::from_secs(10), async {
        while !tablet.peers().iter().any(|p| p.name == "desktop") {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();

    let packet = ipv4_udp(&tablet_info.ipv4, &desktop_info.ipv4, 1111, 2222, 64);
    let received = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            // The first packets can be lost while the peer's endpoint propagates.
            tablet.send_packet(packet.to_vec());
            if let Ok(Some(p)) =
                tokio::time::timeout(Duration::from_millis(300), inboxes[1].recv()).await
            {
                return p;
            }
        }
    })
    .await
    .expect("packet never arrived");
    assert_eq!(received, packet.to_vec());

    tablet.stop().await;
    desktop.stop().await;
    drop(meshes);
    drop(std::fs::remove_dir_all(&dir));
}

/// What `towonel mesh nc` / `connect` / `status` do through the daemon.
#[tokio::test]
async fn local_socket_dials_and_reports_peers() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use towonel_mesh::local;

    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let (_, user_key) = Box::pin(user_tenant(&hub, &client)).await;
    // Kept alive for the whole test: it's the peer being dialed.
    let _laptop = join(&hub, 1, &user_key, "laptop").await;
    let phone = join(&hub, 2, &user_key, "phone").await;
    wait_for_peer(&phone.node, "laptop").await;

    let dir = std::env::temp_dir().join(format!("towonel-local-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cancel = tokio_util::sync::CancellationToken::new();
    let server = tokio::spawn(local::serve(
        phone.node.clone(),
        local::socket_path(&dir),
        cancel.clone(),
    ));
    tokio::time::timeout(Duration::from_secs(5), async {
        while !local::socket_path(&dir).exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();

    let peers = local::status(&dir).await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].name, "laptop");

    let port = echo_server().await;
    let mut stream = local::dial(&dir, "laptop", port).await.unwrap();
    stream.write_all(b"through the socket").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"through the socket");

    let err = local::dial(&dir, "nope", port).await.unwrap_err();
    assert!(err.to_string().contains("no device named"), "{err}");

    cancel.cancel();
    server.await.unwrap().unwrap();
    assert!(!local::socket_path(&dir).exists(), "socket left behind");
    drop(std::fs::remove_dir_all(&dir));
}

#[tokio::test]
async fn hub_policy_replaces_the_default() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let (tenant, user_key) = Box::pin(user_tenant(&hub, &client)).await;
    let laptop = join(&hub, 1, &user_key, "laptop").await;
    let phone = join(&hub, 2, &user_key, "phone").await;
    wait_for_peer(&phone.node, "laptop").await;
    wait_for_peer(&laptop.node, "phone").await;
    let allowed_port = echo_server().await;
    let other_port = echo_server().await;
    // Default policy: same user, anything goes.
    round_trip(&phone.node, "laptop", other_port).await.unwrap();

    let resp = client
        .put(hub.url(&format!("/v1/tenants/{}/mesh/policy", tenant.id())))
        .bearer_auth(OPERATOR_KEY)
        .json(&json!({"rules": [{"from": ["*"], "to": ["self"], "ports": [allowed_port.to_string()], "proto": "tcp"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let mut netmap = laptop.node.netmap();
    tokio::time::timeout(
        Duration::from_secs(10),
        netmap.wait_for(|m| m.policy.is_some()),
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(
        round_trip(&phone.node, "laptop", allowed_port)
            .await
            .unwrap(),
        b"ping"
    );
    let err = round_trip(&phone.node, "laptop", other_port)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("does not accept"), "{err}");

    // Same rule at the packet level: UDP isn't in it.
    let (_, mut laptop_rx) = laptop.node.packet_channel();
    let (phone_tx, _) = phone.node.packet_channel();
    phone_tx
        .send(ipv4_udp("100.64.0.2", "100.64.0.1", 5000, allowed_port, 10))
        .await
        .unwrap();
    assert_eq!(recv_packet(&mut laptop_rx).await, None);
}

fn dns_query(src: &str, name: &str) -> bytes::Bytes {
    let mut dns = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        dns.push(u8::try_from(label.len()).unwrap());
        dns.extend_from_slice(label.as_bytes());
    }
    dns.extend_from_slice(&[0, 0, 1, 0, 1]);
    let mut p = ipv4_udp(src, "100.100.100.100", 40000, 53, dns.len()).to_vec();
    p[28..].copy_from_slice(&dns);
    p.into()
}

#[tokio::test]
async fn node_answers_dns_for_mesh_names() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let (_, user_key) = Box::pin(user_tenant(&hub, &client)).await;
    let _laptop = join(&hub, 1, &user_key, "laptop").await;
    let phone = join(&hub, 2, &user_key, "phone").await;
    wait_for_peer(&phone.node, "laptop").await;
    assert_eq!(phone.node.netmap().borrow().dns_domain, "towonel.internal");

    let (tx, mut rx) = phone.node.packet_channel();
    tx.send(dns_query("100.64.0.2", "laptop.towonel.internal"))
        .await
        .unwrap();
    let reply = recv_packet(&mut rx).await.expect("no DNS reply");
    // One answer, ending in laptop's address.
    assert_eq!(&reply[28..30], &[0xab, 0xcd]);
    assert_eq!(u16::from_be_bytes([reply[34], reply[35]]), 1);
    assert_eq!(&reply[reply.len() - 4..], &[100, 64, 0, 1]);

    tx.send(dns_query("100.64.0.2", "ghost.towonel.internal"))
        .await
        .unwrap();
    let reply = recv_packet(&mut rx).await.expect("no DNS reply");
    assert_eq!(reply[31] & 0x0f, 3, "NXDOMAIN");
}

/// iroh probes every local address, the TUN's included; its own packets
/// must never be tunnelled, or QUIC ends up running inside itself.
#[tokio::test]
async fn own_transport_never_enters_the_tunnel() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let (_, user_key) = Box::pin(user_tenant(&hub, &client)).await;
    let laptop = join(&hub, 1, &user_key, "laptop").await;
    let phone = join(&hub, 2, &user_key, "phone").await;
    wait_for_peer(&laptop.node, "phone").await;
    wait_for_peer(&phone.node, "laptop").await;

    let phone_port = laptop.node.netmap().borrow().peers[0]
        .endpoint
        .as_ref()
        .unwrap()
        .addrs
        .iter()
        .find_map(|a| match a {
            iroh::TransportAddr::Ip(s) => Some(s.port()),
            _ => None,
        })
        .unwrap();
    // The hub never learns an overlay address as a transport address.
    let endpoint = laptop.node.netmap().borrow().peers[0]
        .endpoint
        .clone()
        .unwrap();
    assert!(endpoint.addrs.iter().all(|a| match a {
        iroh::TransportAddr::Ip(s) => s.ip().to_string() != "100.64.0.2",
        _ => true,
    }));

    let (_, mut laptop_rx) = laptop.node.packet_channel();
    let (phone_tx, _) = phone.node.packet_channel();
    phone_tx
        .send(ipv4_udp("100.64.0.2", "100.64.0.1", phone_port, 9999, 10))
        .await
        .unwrap();
    assert_eq!(recv_packet(&mut laptop_rx).await, None);
    // Any other source port still goes through.
    let ok = ipv4_udp(
        "100.64.0.2",
        "100.64.0.1",
        phone_port.wrapping_add(1),
        9999,
        10,
    );
    phone_tx.send(ok.clone()).await.unwrap();
    assert_eq!(recv_packet(&mut laptop_rx).await, Some(ok));
}
