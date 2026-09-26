//! Mesh control-plane API: auth keys, enrollment, credentials, netmap.

use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sea_orm::{ConnectionTrait, Statement};
use serde_json::{Value, json};
use towonel_common::auth::sign_auth_header;
use towonel_common::identity::{PQ_SIGNATURE_LEN, PqPublicKey, TenantKeypair};
use towonel_common::mesh::{MeshCred, verify_mesh_cred};
use towonel_common::time::now_ms;

use super::api_tests::{signup_and_login_user, user_id_by_email};
use super::db::mesh::{MeshAuthKeyRow, NewMeshAuthKey};
use super::test_helpers::{
    OPERATOR_KEY, TestHub, create_invite, get_json, post_json, tenant_from_token,
};

struct Device {
    key: iroh::SecretKey,
    /// Bumped per request so back-to-back calls don't hit the replay cache.
    ts: AtomicU64,
}

impl Device {
    fn new(seed: u8) -> Self {
        Self {
            key: iroh::SecretKey::from([seed; 32]),
            ts: AtomicU64::new(now_ms()),
        }
    }

    fn id_hex(&self) -> String {
        hex::encode(self.key.public().as_bytes())
    }

    fn sign(&self, domain: &str, body: &[u8]) -> String {
        sign_auth_header(
            &self.key,
            domain,
            self.ts.fetch_add(1, Ordering::SeqCst),
            body,
        )
    }
}

async fn signed_post(
    hub: &TestHub,
    client: &reqwest::Client,
    path: &str,
    auth: String,
    body: Vec<u8>,
) -> (u16, Value) {
    let resp = client
        .post(hub.url(path))
        .header(reqwest::header::AUTHORIZATION, auth)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn enroll(
    hub: &TestHub,
    client: &reqwest::Client,
    device: &Device,
    auth_key: &str,
    name: &str,
) -> (u16, Value) {
    let body =
        serde_json::to_vec(&json!({"auth_key": auth_key, "name": name, "os": "linux"})).unwrap();
    let auth = device.sign("towonel/mesh-enroll/v1", &body);
    signed_post(hub, client, "/v1/mesh/enroll", auth, body).await
}

async fn netmap(hub: &TestHub, client: &reqwest::Client, device: &Device) -> (u16, Value) {
    let resp = client
        .get(hub.url("/v1/mesh/netmap"))
        .header(
            reqwest::header::AUTHORIZATION,
            device.sign("towonel/mesh-netmap/v1", &[]),
        )
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    (status, resp.json().await.unwrap_or(Value::Null))
}

async fn new_tenant(hub: &TestHub, client: &reqwest::Client, name: &str) -> TenantKeypair {
    let token = create_invite(hub, client, name, &[&format!("app.{name}.test")]).await;
    tenant_from_token(&token)
}

async fn mint_key(
    hub: &TestHub,
    client: &reqwest::Client,
    tenant: &TenantKeypair,
    body: Value,
) -> String {
    let (status, resp) = post_json(
        client,
        &hub.url(&format!("/v1/tenants/{}/mesh/auth-keys", tenant.id())),
        body,
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(status, 201, "mint auth key failed: {resp}");
    resp["token"].as_str().unwrap().to_string()
}

fn decode_cred(cred: &Value) -> (MeshCred, Vec<u8>, [u8; PQ_SIGNATURE_LEN]) {
    let bytes = B64.decode(cred["cred_b64"].as_str().unwrap()).unwrap();
    let sig: [u8; PQ_SIGNATURE_LEN] = B64
        .decode(cred["sig_b64"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    (MeshCred::from_cbor(&bytes).unwrap(), bytes, sig)
}

#[tokio::test]
async fn enroll_two_devices_and_see_each_other() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let tenant = new_tenant(&hub, &client, "mesh-a").await;
    let key = mint_key(
        &hub,
        &client,
        &tenant,
        json!({"tags": ["tag:server"], "reusable": true}),
    )
    .await;
    assert!(key.starts_with("tmk_"));

    let nas = Device::new(1);
    let laptop = Device::new(2);
    let (s, first) = enroll(&hub, &client, &nas, &key, "NAS").await;
    assert_eq!(s, 201, "{first}");
    let (s, second) = enroll(&hub, &client, &laptop, &key, "nas").await;
    assert_eq!(s, 201, "{second}");

    assert_eq!(first["device"]["name"], "nas");
    assert_eq!(second["device"]["name"], "nas-2");
    assert_eq!(first["device"]["ipv4"], "100.64.0.1");
    assert_eq!(second["device"]["ipv4"], "100.64.0.2");
    assert_eq!(first["device"]["tags"], json!(["tag:server"]));
    assert!(first["device"]["key_expires_at_ms"].is_null());

    let (s, map) = netmap(&hub, &client, &nas).await;
    assert_eq!(s, 200, "{map}");
    assert_eq!(map["self"]["device_id"], nas.id_hex());
    let peers = map["peers"].as_array().unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0]["device_id"], laptop.id_hex());

    let hub_key = &map["hub_keys"][0];
    let pubkey_bytes = B64
        .decode(hub_key["public_key_b64"].as_str().unwrap())
        .unwrap();
    let pubkey = PqPublicKey::from_bytes(pubkey_bytes.try_into().unwrap());
    let (cred, bytes, sig) = decode_cred(&first["cred"]);
    assert!(verify_mesh_cred(&pubkey, &bytes, &sig));
    assert_eq!(u64::from(cred.kid), hub_key["kid"].as_u64().unwrap());
    assert_eq!(cred.device_id, *nas.key.public().as_bytes());
    assert_eq!(cred.tenant_id, tenant.id());
    assert_eq!(cred.ipv4.to_string(), "100.64.0.1");
    assert_eq!(cred.ipv6.to_string(), first["device"]["ipv6"]);
    assert!(cred.not_after_ms > now_ms());
}

#[tokio::test]
async fn one_off_key_enrolls_only_once() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let tenant = new_tenant(&hub, &client, "mesh-b").await;
    let key = mint_key(&hub, &client, &tenant, json!({})).await;

    let (s, body) = enroll(&hub, &client, &Device::new(1), &key, "a").await;
    assert_eq!(s, 201, "{body}");
    let (s, body) = enroll(&hub, &client, &Device::new(2), &key, "b").await;
    assert_eq!(s, 401, "{body}");
    assert_eq!(body["error"]["code"], "unauthorized");
}

#[tokio::test]
async fn re_enroll_is_idempotent() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let tenant = new_tenant(&hub, &client, "mesh-c").await;
    let key = mint_key(&hub, &client, &tenant, json!({"reusable": true})).await;
    let device = Device::new(1);

    let (s, first) = enroll(&hub, &client, &device, &key, "box").await;
    assert_eq!(s, 201, "{first}");
    let (s, again) = enroll(&hub, &client, &device, &key, "renamed").await;
    assert_eq!(s, 200, "{again}");
    assert_eq!(again["device"]["ipv4"], first["device"]["ipv4"]);
    assert_eq!(again["device"]["name"], "box");
}

#[tokio::test]
async fn device_key_cannot_join_a_second_tenant() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let a = new_tenant(&hub, &client, "mesh-d1").await;
    let b = new_tenant(&hub, &client, "mesh-d2").await;
    let key_a = mint_key(&hub, &client, &a, json!({})).await;
    let key_b = mint_key(&hub, &client, &b, json!({})).await;
    let device = Device::new(1);

    let (s, _) = enroll(&hub, &client, &device, &key_a, "x").await;
    assert_eq!(s, 201);
    let (s, body) = enroll(&hub, &client, &device, &key_b, "x").await;
    assert_eq!(s, 409, "{body}");
    assert_eq!(body["error"]["code"], "device_already_enrolled");
}

#[tokio::test]
async fn untagged_device_is_owned_by_key_creator_and_expires() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let cookie = signup_and_login_user(&hub, &client, "mesh@example.test", "hunter22!").await;
    let user_id = user_id_by_email(&hub, "mesh@example.test").await;
    let tenant = new_tenant(&hub, &client, "mesh-e").await;
    hub.state
        .db
        .insert_tenant_ownership(super::db::tenant_ownership::NewTenantOwnership {
            user_id: &user_id,
            tenant_id: tenant.id().as_bytes(),
            invite_id: &[5u8; 16],
            display_name: "test",
            now_ms: 1,
        })
        .await
        .unwrap();

    let resp = client
        .post(hub.url(&format!("/v1/tenants/{}/mesh/auth-keys", tenant.id())))
        .header(reqwest::header::COOKIE, &cookie)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let key: Value = resp.json().await.unwrap();

    let (s, body) = enroll(
        &hub,
        &client,
        &Device::new(1),
        key["token"].as_str().unwrap(),
        "phone",
    )
    .await;
    assert_eq!(s, 201, "{body}");
    assert_eq!(body["device"]["owner"], user_id);
    assert!(body["device"]["key_expires_at_ms"].as_i64().unwrap() > 0);
    let (cred, _, _) = decode_cred(&body["cred"]);
    assert_eq!(cred.owner.as_deref(), Some(user_id.as_str()));
}

#[tokio::test]
async fn non_member_cannot_mint_auth_keys() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let cookie = signup_and_login_user(&hub, &client, "stranger@example.test", "hunter22!").await;
    let tenant = new_tenant(&hub, &client, "mesh-f").await;

    let resp = client
        .post(hub.url(&format!("/v1/tenants/{}/mesh/auth-keys", tenant.id())))
        .header(reqwest::header::COOKIE, &cookie)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn revoked_device_drops_out_of_netmap() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let tenant = new_tenant(&hub, &client, "mesh-g").await;
    let key = mint_key(&hub, &client, &tenant, json!({"reusable": true})).await;
    let keep = Device::new(1);
    let gone = Device::new(2);
    enroll(&hub, &client, &keep, &key, "keep").await;
    enroll(&hub, &client, &gone, &key, "gone").await;

    let resp = client
        .delete(hub.url(&format!(
            "/v1/tenants/{}/mesh/devices/{}",
            tenant.id(),
            gone.id_hex()
        )))
        .bearer_auth(OPERATOR_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let (s, _) = netmap(&hub, &client, &gone).await;
    assert_eq!(s, 401);
    let (s, map) = netmap(&hub, &client, &keep).await;
    assert_eq!(s, 200);
    assert!(map["peers"].as_array().unwrap().is_empty());

    let (s, devices) = get_json(
        &client,
        &hub.url(&format!("/v1/tenants/{}/mesh/devices", tenant.id())),
        Some(OPERATOR_KEY),
    )
    .await;
    assert_eq!(s, 200);
    assert_eq!(devices["devices"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn expired_and_revoked_auth_keys_are_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let tenant = new_tenant(&hub, &client, "mesh-h").await;

    let secret = "expired-secret";
    let hash: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(secret.as_bytes()).into();
    hub.state
        .db
        .insert_mesh_auth_key(NewMeshAuthKey {
            id: "expired",
            tenant_id: &tenant.id(),
            key_hash: &hash,
            created_by_user_id: None,
            tags: &[],
            reusable: true,
            expires_at_ms: 1,
            now_ms: 0,
        })
        .await
        .unwrap();
    let (s, _) = enroll(
        &hub,
        &client,
        &Device::new(1),
        &format!("tmk_{secret}"),
        "x",
    )
    .await;
    assert_eq!(s, 401);

    let key = mint_key(&hub, &client, &tenant, json!({"reusable": true})).await;
    let keys: Vec<MeshAuthKeyRow> = hub
        .state
        .db
        .list_mesh_auth_keys(&tenant.id())
        .await
        .unwrap();
    let live = keys.iter().find(|k| k.id != "expired").unwrap();
    let resp = client
        .delete(hub.url(&format!(
            "/v1/tenants/{}/mesh/auth-keys/{}",
            tenant.id(),
            live.id
        )))
        .bearer_auth(OPERATOR_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let (s, _) = enroll(&hub, &client, &Device::new(2), &key, "y").await;
    assert_eq!(s, 401);
}

#[tokio::test]
async fn device_requests_reject_bad_and_replayed_signatures() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let tenant = new_tenant(&hub, &client, "mesh-i").await;
    let key = mint_key(&hub, &client, &tenant, json!({})).await;
    let device = Device::new(1);
    enroll(&hub, &client, &device, &key, "d").await;

    let wrong_domain = device.sign("towonel/mesh-cred/v1", &[]);
    let resp = client
        .get(hub.url("/v1/mesh/netmap"))
        .header(reqwest::header::AUTHORIZATION, wrong_domain)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    let auth = device.sign("towonel/mesh-cred/v1", &[]);
    let (s, body) = signed_post(&hub, &client, "/v1/mesh/cred", auth.clone(), vec![]).await;
    assert_eq!(s, 200, "{body}");
    decode_cred(&body["cred"]);
    let (s, _) = signed_post(&hub, &client, "/v1/mesh/cred", auth, vec![]).await;
    assert_eq!(s, 401);
}

#[tokio::test]
async fn deleting_tenant_removes_devices_and_keys() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let tenant = new_tenant(&hub, &client, "mesh-j").await;
    let key = mint_key(&hub, &client, &tenant, json!({"reusable": true})).await;
    let (s, _) = enroll(&hub, &client, &Device::new(1), &key, "d").await;
    assert_eq!(s, 201);

    let resp = client
        .delete(hub.url(&format!("/v1/tenants/{}", tenant.id())))
        .bearer_auth(OPERATOR_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let db = &hub.state.db;
    assert!(db.list_mesh_devices(&tenant.id()).await.unwrap().is_empty());
    assert!(
        db.list_mesh_auth_keys(&tenant.id())
            .await
            .unwrap()
            .is_empty()
    );
}

async fn exec_sql(hub: &TestHub, sql: &str) {
    hub.state
        .db
        .conn
        .execute(Statement::from_string(
            sea_orm::DatabaseBackend::Sqlite,
            sql.to_string(),
        ))
        .await
        .unwrap();
}

async fn request_code(hub: &TestHub, client: &reqwest::Client, device: &Device) -> Value {
    let body = serde_json::to_vec(&json!({"name": "Pixel 9", "os": "android"})).unwrap();
    let auth = device.sign("towonel/mesh-device-code/v1", &body);
    let (s, resp) = signed_post(hub, client, "/v1/mesh/device-code", auth, body).await;
    assert_eq!(s, 201, "{resp}");
    resp
}

async fn poll(hub: &TestHub, client: &reqwest::Client, device: &Device) -> (u16, Value) {
    let auth = device.sign("towonel/mesh-device-poll/v1", &[]);
    signed_post(hub, client, "/v1/mesh/device-code/poll", auth, vec![]).await
}

async fn approve(
    hub: &TestHub,
    client: &reqwest::Client,
    cookie: &str,
    code: &str,
    tenant: &TenantKeypair,
) -> reqwest::StatusCode {
    client
        .post(hub.url(&format!("/v1/mesh/device-code/{code}/approve")))
        .header(reqwest::header::COOKIE, cookie)
        .json(&json!({"tenant_id": tenant.id().to_string()}))
        .send()
        .await
        .unwrap()
        .status()
}

/// Signed-up user who owns a fresh tenant. Returns (cookie, user id, tenant).
async fn owner_with_tenant(
    hub: &TestHub,
    client: &reqwest::Client,
    email: &str,
    tenant_name: &str,
) -> (String, String, TenantKeypair) {
    let cookie = signup_and_login_user(hub, client, email, "hunter22!").await;
    let user_id = user_id_by_email(hub, email).await;
    let tenant = new_tenant(hub, client, tenant_name).await;
    let invite_id: [u8; 16] = tenant.id().as_bytes()[..16].try_into().unwrap();
    hub.state
        .db
        .insert_tenant_ownership(super::db::tenant_ownership::NewTenantOwnership {
            user_id: &user_id,
            tenant_id: tenant.id().as_bytes(),
            invite_id: &invite_id,
            display_name: "test",
            now_ms: 1,
        })
        .await
        .unwrap();
    (cookie, user_id, tenant)
}

#[tokio::test]
async fn device_code_flow_enrolls_user_device() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let (cookie, user_id, tenant) = Box::pin(owner_with_tenant(
        &hub,
        &client,
        "phone@example.test",
        "mesh-k",
    ))
    .await;
    let phone = Device::new(1);

    let code = request_code(&hub, &client, &phone).await;
    let user_code = code["user_code"].as_str().unwrap();
    assert_eq!(user_code.len(), 9);
    assert_eq!(
        code["verification_url"],
        format!(
            "https://console.test.example/mesh/connect?code={}",
            user_code.replace('-', "")
        )
    );
    assert_eq!(code["interval_secs"], 5);

    let (s, body) = poll(&hub, &client, &phone).await;
    assert_eq!(s, 202, "{body}");
    assert_eq!(body["status"], "pending");

    let resp = client
        .get(hub.url(&format!("/v1/mesh/device-code/{user_code}")))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let info: Value = resp.json().await.unwrap();
    assert_eq!(info["name"], "pixel-9");
    assert_eq!(info["os"], "android");
    assert_eq!(info["requester_ip"], "127.0.0.1");
    assert!(info["enrolled_tenant_id"].is_null());

    assert_eq!(
        approve(&hub, &client, &cookie, user_code, &tenant).await,
        200
    );

    let (s, body) = poll(&hub, &client, &phone).await;
    assert_eq!(s, 201, "{body}");
    assert_eq!(body["device"]["owner"], user_id);
    assert_eq!(body["device"]["name"], "pixel-9");
    assert!(body["device"]["key_expires_at_ms"].as_i64().unwrap() > 0);
    decode_cred(&body["cred"]);

    let (s, _) = poll(&hub, &client, &phone).await;
    assert_eq!(s, 404);
    assert_eq!(
        approve(&hub, &client, &cookie, user_code, &tenant).await,
        404
    );
}

#[tokio::test]
async fn device_code_approval_requires_tenant_membership() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let (_, _, tenant) = Box::pin(owner_with_tenant(
        &hub,
        &client,
        "owner2@example.test",
        "mesh-l",
    ))
    .await;
    let stranger = signup_and_login_user(&hub, &client, "other@example.test", "hunter22!").await;
    let code = request_code(&hub, &client, &Device::new(1)).await;
    let user_code = code["user_code"].as_str().unwrap();

    assert_eq!(
        approve(&hub, &client, &stranger, user_code, &tenant).await,
        403
    );

    // Operator key is not a user and cannot approve.
    let resp = client
        .post(hub.url(&format!("/v1/mesh/device-code/{user_code}/approve")))
        .bearer_auth(OPERATOR_KEY)
        .json(&json!({"tenant_id": tenant.id().to_string()}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 403);
}

#[tokio::test]
async fn device_code_renews_expired_key_keeping_ip_and_name() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let (cookie, _, tenant) = Box::pin(owner_with_tenant(
        &hub,
        &client,
        "renew@example.test",
        "mesh-m",
    ))
    .await;
    let laptop = Device::new(1);

    let code = request_code(&hub, &client, &laptop).await;
    approve(
        &hub,
        &client,
        &cookie,
        code["user_code"].as_str().unwrap(),
        &tenant,
    )
    .await;
    let (s, first) = poll(&hub, &client, &laptop).await;
    assert_eq!(s, 201);

    exec_sql(&hub, "UPDATE mesh_devices SET key_expires_at_ms = 1").await;
    let (s, body) = netmap(&hub, &client, &laptop).await;
    assert_eq!(s, 401);
    assert_eq!(body["error"]["code"], "key_expired");

    let code = request_code(&hub, &client, &laptop).await;
    let user_code = code["user_code"].as_str().unwrap();
    let resp = client
        .get(hub.url(&format!("/v1/mesh/device-code/{user_code}")))
        .header(reqwest::header::COOKIE, &cookie)
        .send()
        .await
        .unwrap();
    let info: Value = resp.json().await.unwrap();
    assert_eq!(info["enrolled_tenant_id"], tenant.id().to_string());

    approve(&hub, &client, &cookie, user_code, &tenant).await;
    let (s, renewed) = poll(&hub, &client, &laptop).await;
    assert_eq!(s, 200, "{renewed}");
    assert_eq!(renewed["device"]["ipv4"], first["device"]["ipv4"]);
    assert_eq!(renewed["device"]["name"], first["device"]["name"]);
    assert!(renewed["device"]["key_expires_at_ms"].as_i64().unwrap() > 1);

    let (s, _) = netmap(&hub, &client, &laptop).await;
    assert_eq!(s, 200);
}

#[tokio::test]
async fn expired_device_code_is_rejected() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let (cookie, _, tenant) = Box::pin(owner_with_tenant(
        &hub,
        &client,
        "late@example.test",
        "mesh-n",
    ))
    .await;
    let device = Device::new(1);
    let code = request_code(&hub, &client, &device).await;
    let user_code = code["user_code"].as_str().unwrap();

    exec_sql(&hub, "UPDATE mesh_device_codes SET expires_at_ms = 1").await;

    assert_eq!(
        approve(&hub, &client, &cookie, user_code, &tenant).await,
        404
    );
    let (s, _) = poll(&hub, &client, &device).await;
    assert_eq!(s, 410);
}

struct EventStream {
    resp: reqwest::Response,
    buf: String,
}

impl EventStream {
    async fn open(hub: &TestHub, client: &reqwest::Client, device: &Device) -> Self {
        let resp = client
            .get(hub.url("/v1/mesh/netmap/stream"))
            .header(
                reqwest::header::AUTHORIZATION,
                device.sign("towonel/mesh-netmap-stream/v1", &[]),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        Self {
            resp,
            buf: String::new(),
        }
    }

    /// Next named event, skipping keep-alives. `None` when the stream ends.
    async fn next(&mut self) -> Option<(String, Value)> {
        loop {
            if let Some(end) = self.buf.find("\n\n") {
                let frame: String = self.buf.drain(..end + 2).collect();
                let mut event = None;
                let mut data = String::new();
                for line in frame.lines() {
                    if let Some(v) = line.strip_prefix("event:") {
                        event = Some(v.trim().to_string());
                    } else if let Some(v) = line.strip_prefix("data:") {
                        data.push_str(v.trim());
                    }
                }
                if let Some(event) = event {
                    return Some((event, serde_json::from_str(&data).unwrap()));
                }
                continue;
            }
            let chunk = tokio::time::timeout(std::time::Duration::from_secs(5), self.resp.chunk())
                .await
                .expect("timed out waiting for an event")
                .unwrap()?;
            self.buf.push_str(std::str::from_utf8(&chunk).unwrap());
        }
    }
}

#[tokio::test]
async fn netmap_stream_pushes_peer_changes() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let tenant = new_tenant(&hub, &client, "mesh-o").await;
    let key = mint_key(&hub, &client, &tenant, json!({"reusable": true})).await;
    let first = Device::new(1);
    let second = Device::new(2);
    enroll(&hub, &client, &first, &key, "first").await;

    let mut stream = EventStream::open(&hub, &client, &first).await;
    let (event, map) = stream.next().await.unwrap();
    assert_eq!(event, "netmap");
    assert!(map["peers"].as_array().unwrap().is_empty());

    enroll(&hub, &client, &second, &key, "second").await;
    let (event, map) = stream.next().await.unwrap();
    assert_eq!(event, "netmap");
    assert_eq!(map["peers"][0]["device_id"], second.id_hex());

    let resp = client
        .delete(hub.url(&format!(
            "/v1/tenants/{}/mesh/devices/{}",
            tenant.id(),
            second.id_hex()
        )))
        .bearer_auth(OPERATOR_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let (_, map) = stream.next().await.unwrap();
    assert!(map["peers"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn netmap_stream_ends_when_device_is_revoked() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let tenant = new_tenant(&hub, &client, "mesh-p").await;
    let key = mint_key(&hub, &client, &tenant, json!({})).await;
    let device = Device::new(1);
    enroll(&hub, &client, &device, &key, "d").await;

    let mut stream = EventStream::open(&hub, &client, &device).await;
    assert_eq!(stream.next().await.unwrap().0, "netmap");

    client
        .delete(hub.url(&format!(
            "/v1/tenants/{}/mesh/devices/{}",
            tenant.id(),
            device.id_hex()
        )))
        .bearer_auth(OPERATOR_KEY)
        .send()
        .await
        .unwrap();
    assert_eq!(stream.next().await.unwrap().0, "revoked");
    assert!(stream.next().await.is_none());
}

#[tokio::test]
async fn netmap_stream_ignores_other_tenants() {
    let hub = TestHub::start().await;
    let client = reqwest::Client::new();
    let a = new_tenant(&hub, &client, "mesh-q1").await;
    let b = new_tenant(&hub, &client, "mesh-q2").await;
    let key_a = mint_key(&hub, &client, &a, json!({"reusable": true})).await;
    let key_b = mint_key(&hub, &client, &b, json!({})).await;
    let watcher = Device::new(1);
    enroll(&hub, &client, &watcher, &key_a, "watcher").await;

    let mut stream = EventStream::open(&hub, &client, &watcher).await;
    stream.next().await.unwrap();

    enroll(&hub, &client, &Device::new(2), &key_b, "elsewhere").await;
    enroll(&hub, &client, &Device::new(3), &key_a, "neighbour").await;
    let (_, map) = stream.next().await.unwrap();
    let peers = map["peers"].as_array().unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0]["name"], "neighbour");
}
