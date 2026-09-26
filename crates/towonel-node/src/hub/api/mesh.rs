//! Mesh control plane. Devices sign requests with their iroh endpoint key.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;
use utoipa::ToSchema;

use towonel_common::edge_cred::Kid;
use towonel_common::identity::TenantId;
use towonel_common::mesh::{DeviceId, MESH_CRED_VERSION, MeshCred, mesh_ipv6};
use towonel_common::time::now_ms;

use super::auth::{client_ip_key, new_id};
use super::ports::authorize_tenant;
use super::signup_invites::now_ms_i64;
use super::{
    AGENT_REFRESH_MAX_PER_MIN, AppState, MAX_CLOCK_SKEW_MS, conflict, error_response, gone,
    internal_error, invalid_request, json_ok, json_with_status, not_found, unauthorized,
    user_required,
};
use crate::hub::auth::middleware::Principal;
use crate::hub::auth::verify_signature_header;
use crate::hub::db::admin_actions::NewAdminAction;
use crate::hub::db::is_unique_violation;
use crate::hub::db::mesh::{
    EnrollGrant, MeshAuthKeyRow, MeshDeviceCodeRow, MeshDeviceRow, NewMeshAuthKey, NewMeshDevice,
    NewMeshDeviceCode,
};

const ENROLL_AUTH_DOMAIN: &str = "towonel/mesh-enroll/v1";
const CRED_AUTH_DOMAIN: &str = "towonel/mesh-cred/v1";
const NETMAP_AUTH_DOMAIN: &str = "towonel/mesh-netmap/v1";
const DEVICE_CODE_AUTH_DOMAIN: &str = "towonel/mesh-device-code/v1";
const DEVICE_POLL_AUTH_DOMAIN: &str = "towonel/mesh-device-poll/v1";

const DEVICE_CODE_TTL_SECS: u64 = 10 * 60;
const DEVICE_CODE_TTL_MS: i64 = DEVICE_CODE_TTL_SECS.cast_signed() * 1000;
const DEVICE_CODE_POLL_SECS: u64 = 5;
/// RFC 8628 §6.1: consonants only, so codes never spell words.
const USER_CODE_ALPHABET: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";
const USER_CODE_LEN: usize = 8;

const AUTH_KEY_PREFIX: &str = "tmk_";
const AUTH_KEY_SECRET_BYTES: usize = 32;
const AUTH_KEY_DEFAULT_DAYS: i64 = 90;
const AUTH_KEY_MAX_DAYS: i64 = 90;
const MAX_AUTH_KEYS_PER_TENANT: usize = 100;

/// Long enough to ride out a hub outage; revocation is pushed, not TTL-bound.
const MESH_CRED_TTL_MS: u64 = 12 * 60 * 60 * 1000;
const USER_DEVICE_KEY_TTL_MS: i64 = 180 * MS_PER_DAY;
const MS_PER_DAY: i64 = 24 * 60 * 60 * 1000;

const MAX_TAGS: usize = 16;
const MAX_LABEL_LEN: usize = 63;
const MAX_OS_LEN: usize = 32;
const ENROLL_RETRIES: u32 = 4;

/// Same message for unknown, expired and spent keys: no oracle.
const INVALID_AUTH_KEY: &str = "auth key is invalid, expired, or already used";

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct CreateAuthKeyRequest {
    /// `tag:<name>` entries. Tagged devices are owned by the tenant, not a user.
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    reusable: bool,
    /// 1-90, default 90.
    expires_in_days: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
struct AuthKeyInfo {
    id: String,
    tags: Vec<String>,
    reusable: bool,
    expires_at_ms: i64,
    used_at_ms: Option<i64>,
    created_at_ms: i64,
}

impl From<MeshAuthKeyRow> for AuthKeyInfo {
    fn from(r: MeshAuthKeyRow) -> Self {
        Self {
            id: r.id,
            tags: r.tags,
            reusable: r.reusable,
            expires_at_ms: r.expires_at_ms,
            used_at_ms: r.used_at_ms,
            created_at_ms: r.created_at_ms,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
struct CreateAuthKeyResponse {
    #[serde(flatten)]
    key: AuthKeyInfo,
    /// Plaintext key, returned exactly once.
    token: String,
}

#[derive(Debug, Serialize, ToSchema)]
struct ListAuthKeysResponse {
    keys: Vec<AuthKeyInfo>,
}

#[derive(Debug, Serialize, ToSchema)]
struct DeviceView {
    /// Hex iroh endpoint id.
    device_id: String,
    name: String,
    os: Option<String>,
    ipv4: String,
    ipv6: String,
    tags: Vec<String>,
    owner: Option<String>,
    key_expires_at_ms: Option<i64>,
    created_at_ms: i64,
    last_seen_at_ms: Option<i64>,
}

impl From<&MeshDeviceRow> for DeviceView {
    fn from(d: &MeshDeviceRow) -> Self {
        Self {
            device_id: hex::encode(d.device_id),
            name: d.name.clone(),
            os: d.os.clone(),
            ipv4: d.ipv4.to_string(),
            ipv6: mesh_ipv6(&d.tenant_id, &d.device_id).to_string(),
            tags: d.tags.clone(),
            owner: d.user_id.clone(),
            key_expires_at_ms: d.key_expires_at_ms,
            created_at_ms: d.created_at_ms,
            last_seen_at_ms: d.last_seen_at_ms,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
struct ListDevicesResponse {
    devices: Vec<DeviceView>,
}

#[derive(Debug, Serialize)]
struct CredView {
    kid: Kid,
    cred_b64: String,
    sig_b64: String,
    not_after_ms: u64,
}

#[derive(Debug, Deserialize)]
struct EnrollRequest {
    auth_key: String,
    name: String,
    #[serde(default)]
    os: Option<String>,
}

#[derive(Debug, Serialize)]
struct EnrollResponse {
    tenant_id: String,
    device: DeviceView,
    cred: CredView,
}

#[derive(Debug, Serialize)]
struct CredResponse {
    cred: CredView,
}

#[derive(Debug, Serialize)]
struct HubKeyView {
    kid: Kid,
    public_key_b64: String,
}

#[derive(Debug, Serialize)]
struct NetmapResponse {
    tenant_id: String,
    #[serde(rename = "self")]
    this_device: DeviceView,
    peers: Vec<DeviceView>,
    /// Keys that sign peers' `MeshCred`s.
    hub_keys: Vec<HubKeyView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relay_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DeviceCodeRequest {
    name: String,
    #[serde(default)]
    os: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeviceCodeResponse {
    user_code: String,
    verification_url: String,
    expires_in_secs: u64,
    interval_secs: u64,
}

#[derive(Debug, Serialize, ToSchema)]
struct DeviceCodeInfo {
    user_code: String,
    name: String,
    os: Option<String>,
    requester_ip: Option<String>,
    created_at_ms: i64,
    expires_at_ms: i64,
    approved: bool,
    /// Set when the device is already enrolled: approving renews its key.
    enrolled_tenant_id: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub(super) struct ApproveDeviceCodeRequest {
    tenant_id: String,
}

#[utoipa::path(
    post,
    path = "/v1/tenants/{id}/mesh/auth-keys",
    tag = "mesh",
    params(("id" = String, Path, description = "Tenant id")),
    request_body = CreateAuthKeyRequest,
    responses(
        (status = 201, description = "Key created; `token` is shown only once", body = CreateAuthKeyResponse),
        (status = 400, description = "Invalid tags/expiry or key limit reached"),
        (status = 403, description = "Not a member of this tenant"),
    ),
    security(("session_cookie" = []), ("api_key" = []), ("operator_key" = [])),
)]
pub(super) async fn post_auth_key(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
    axum::Json(body): axum::Json<CreateAuthKeyRequest>,
) -> Response {
    let tenant_id = match tenant_for(&state, &principal, &id).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let tags = match normalize_tags(body.tags) {
        Ok(t) => t,
        Err(msg) => return invalid_request(msg),
    };
    let days = body.expires_in_days.unwrap_or(AUTH_KEY_DEFAULT_DAYS);
    if !(1..=AUTH_KEY_MAX_DAYS).contains(&days) {
        return invalid_request(format!(
            "expires_in_days must be between 1 and {AUTH_KEY_MAX_DAYS}"
        ));
    }

    match state.db.list_mesh_auth_keys(&tenant_id).await {
        Ok(keys) if keys.len() >= MAX_AUTH_KEYS_PER_TENANT => {
            return invalid_request("auth key limit reached; revoke an existing key first");
        }
        Ok(_) => {}
        Err(e) => {
            warn!(error = %e, "list_mesh_auth_keys failed");
            return internal_error();
        }
    }

    let now = now_ms_i64();
    let expires_at_ms = now.saturating_add(days.saturating_mul(MS_PER_DAY));
    let key_id = new_id(16);
    let (token, key_hash) = match mint_auth_key() {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, "OS RNG failure while minting mesh auth key");
            return internal_error();
        }
    };
    let (_, actor_user_id) = actor(&principal);
    if let Err(e) = state
        .db
        .insert_mesh_auth_key(NewMeshAuthKey {
            id: &key_id,
            tenant_id: &tenant_id,
            key_hash: &key_hash,
            created_by_user_id: actor_user_id,
            tags: &tags,
            reusable: body.reusable,
            expires_at_ms,
            now_ms: now,
        })
        .await
    {
        warn!(error = %e, "insert_mesh_auth_key failed");
        return internal_error();
    }
    audit(
        &state,
        actor(&principal),
        "mesh.auth_key.create",
        "mesh_auth_key",
        &key_id,
        serde_json::json!({
            "tenant_id": tenant_id.to_string(),
            "tags": tags,
            "reusable": body.reusable,
        }),
    )
    .await;

    json_with_status(
        StatusCode::CREATED,
        CreateAuthKeyResponse {
            key: AuthKeyInfo {
                id: key_id,
                tags,
                reusable: body.reusable,
                expires_at_ms,
                used_at_ms: None,
                created_at_ms: now,
            },
            token,
        },
    )
}

#[utoipa::path(
    get,
    path = "/v1/tenants/{id}/mesh/auth-keys",
    tag = "mesh",
    params(("id" = String, Path, description = "Tenant id")),
    responses(
        (status = 200, description = "Auth keys (no key material)", body = ListAuthKeysResponse),
        (status = 403, description = "Not a member of this tenant"),
    ),
    security(("session_cookie" = []), ("api_key" = []), ("operator_key" = [])),
)]
pub(super) async fn list_auth_keys(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Response {
    let tenant_id = match tenant_for(&state, &principal, &id).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    match state.db.list_mesh_auth_keys(&tenant_id).await {
        Ok(rows) => json_ok(ListAuthKeysResponse {
            keys: rows.into_iter().map(AuthKeyInfo::from).collect(),
        }),
        Err(e) => {
            warn!(error = %e, "list_mesh_auth_keys failed");
            internal_error()
        }
    }
}

#[utoipa::path(
    delete,
    path = "/v1/tenants/{id}/mesh/auth-keys/{key_id}",
    tag = "mesh",
    params(
        ("id" = String, Path, description = "Tenant id"),
        ("key_id" = String, Path, description = "Auth key id"),
    ),
    responses(
        (status = 200, description = "Key revoked; devices already enrolled with it stay enrolled"),
        (status = 403, description = "Not a member of this tenant"),
        (status = 404, description = "Key not found"),
    ),
    security(("session_cookie" = []), ("api_key" = []), ("operator_key" = [])),
)]
pub(super) async fn delete_auth_key(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path((id, key_id)): Path<(String, String)>,
) -> Response {
    let tenant_id = match tenant_for(&state, &principal, &id).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    match state.db.delete_mesh_auth_key(&tenant_id, &key_id).await {
        Ok(0) => not_found("auth key not found"),
        Ok(_) => {
            audit(
                &state,
                actor(&principal),
                "mesh.auth_key.revoke",
                "mesh_auth_key",
                &key_id,
                serde_json::json!({"tenant_id": tenant_id.to_string()}),
            )
            .await;
            json_ok(serde_json::json!({"ok": true}))
        }
        Err(e) => {
            warn!(error = %e, "delete_mesh_auth_key failed");
            internal_error()
        }
    }
}

#[utoipa::path(
    get,
    path = "/v1/tenants/{id}/mesh/devices",
    tag = "mesh",
    params(("id" = String, Path, description = "Tenant id")),
    responses(
        (status = 200, description = "Enrolled devices", body = ListDevicesResponse),
        (status = 403, description = "Not a member of this tenant"),
    ),
    security(("session_cookie" = []), ("api_key" = []), ("operator_key" = [])),
)]
pub(super) async fn list_devices(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(id): Path<String>,
) -> Response {
    let tenant_id = match tenant_for(&state, &principal, &id).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    match state.db.list_mesh_devices(&tenant_id).await {
        Ok(rows) => json_ok(ListDevicesResponse {
            devices: rows.iter().map(DeviceView::from).collect(),
        }),
        Err(e) => {
            warn!(error = %e, "list_mesh_devices failed");
            internal_error()
        }
    }
}

#[utoipa::path(
    delete,
    path = "/v1/tenants/{id}/mesh/devices/{device_id}",
    tag = "mesh",
    params(
        ("id" = String, Path, description = "Tenant id"),
        ("device_id" = String, Path, description = "Hex device id"),
    ),
    responses(
        (status = 200, description = "Device removed from the mesh"),
        (status = 403, description = "Not a member of this tenant"),
        (status = 404, description = "Device not found"),
    ),
    security(("session_cookie" = []), ("api_key" = []), ("operator_key" = [])),
)]
pub(super) async fn delete_device(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path((id, device_hex)): Path<(String, String)>,
) -> Response {
    let tenant_id = match tenant_for(&state, &principal, &id).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let Ok(device_id) = <DeviceId as hex::FromHex>::from_hex(&device_hex) else {
        return invalid_request("device_id must be 32 hex bytes");
    };
    match state.db.delete_mesh_device(&tenant_id, &device_id).await {
        Ok(0) => not_found("device not found"),
        Ok(_) => {
            audit(
                &state,
                actor(&principal),
                "mesh.device.revoke",
                "mesh_device",
                &device_hex,
                serde_json::json!({"tenant_id": tenant_id.to_string()}),
            )
            .await;
            json_ok(serde_json::json!({"ok": true}))
        }
        Err(e) => {
            warn!(error = %e, "delete_mesh_device failed");
            internal_error()
        }
    }
}

pub(super) async fn post_enroll(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let device_id = match verify_device_request(&state, &headers, ENROLL_AUTH_DOMAIN, &body).await {
        Ok(d) => d,
        Err(resp) => return resp,
    };
    let req: EnrollRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return invalid_request(format!("invalid JSON body: {e}")),
    };
    let auth_key = match usable_auth_key(&state, &req.auth_key).await {
        Ok(k) => k,
        Err(resp) => return resp,
    };

    // Idempotent so a client that lost the response can retry.
    match state.db.get_mesh_device(&device_id).await {
        Ok(Some(existing)) if existing.tenant_id == auth_key.tenant_id => {
            return enroll_response(&state, StatusCode::OK, &existing);
        }
        Ok(Some(_)) => {
            return conflict(
                "device_already_enrolled",
                "this device key is enrolled in another tenant",
            );
        }
        Ok(None) => {}
        Err(e) => {
            warn!(error = %e, "get_mesh_device failed");
            return internal_error();
        }
    }

    let tagged = !auth_key.tags.is_empty();
    let spec = DeviceSpec {
        tenant_id: &auth_key.tenant_id,
        user_id: if tagged {
            None
        } else {
            auth_key.created_by_user_id.as_deref()
        },
        tags: &auth_key.tags,
        name: &req.name,
        os: req.os.as_deref(),
    };
    let grant = EnrollGrant::AuthKey {
        id: &auth_key.id,
        reusable: auth_key.reusable,
    };
    let device = match insert_device(&state, &grant, &device_id, spec).await {
        Ok(Some(d)) => d,
        Ok(None) => return unauthorized(INVALID_AUTH_KEY),
        Err(resp) => return resp,
    };
    audit(
        &state,
        ("system", None),
        "mesh.device.enroll",
        "mesh_device",
        &hex::encode(device_id),
        serde_json::json!({
            "tenant_id": auth_key.tenant_id.to_string(),
            "auth_key_id": auth_key.id,
            "name": device.name,
        }),
    )
    .await;

    enroll_response(&state, StatusCode::CREATED, &device)
}

async fn usable_auth_key(state: &AppState, token: &str) -> Result<MeshAuthKeyRow, Response> {
    let key_hash = parse_auth_key(token).ok_or_else(|| unauthorized(INVALID_AUTH_KEY))?;
    let auth_key = match state.db.find_mesh_auth_key_by_hash(&key_hash).await {
        Ok(Some(k)) => k,
        Ok(None) => return Err(unauthorized(INVALID_AUTH_KEY)),
        Err(e) => {
            warn!(error = %e, "find_mesh_auth_key_by_hash failed");
            return Err(internal_error());
        }
    };
    let spent = !auth_key.reusable && auth_key.used_at_ms.is_some();
    let expired = auth_key.expires_at_ms <= now_ms_i64();
    if spent || expired || !state.policy.load().is_known_tenant(&auth_key.tenant_id) {
        return Err(unauthorized(INVALID_AUTH_KEY));
    }
    Ok(auth_key)
}

struct DeviceSpec<'a> {
    tenant_id: &'a TenantId,
    user_id: Option<&'a str>,
    tags: &'a [String],
    name: &'a str,
    os: Option<&'a str>,
}

/// `Ok(None)` when the grant was spent concurrently.
async fn insert_device(
    state: &AppState,
    grant: &EnrollGrant<'_>,
    device_id: &DeviceId,
    spec: DeviceSpec<'_>,
) -> Result<Option<MeshDeviceRow>, Response> {
    let now = now_ms_i64();
    let name = sanitize_label(spec.name).unwrap_or_else(|| "device".to_string());
    let os = clean_os(spec.os);
    for _ in 0..ENROLL_RETRIES {
        let new = NewMeshDevice {
            device_id,
            tenant_id: spec.tenant_id,
            name: &name,
            os: os.as_deref(),
            user_id: spec.user_id,
            tags: spec.tags,
            key_expires_at_ms: device_key_expiry(spec.tags, now),
            now_ms: now,
        };
        match state.db.enroll_mesh_device(grant, new).await {
            Ok(d) => return Ok(d),
            Err(e) if is_unique_violation(&e) => {}
            Err(e) => {
                warn!(error = %e, "enroll_mesh_device failed");
                return Err(internal_error());
            }
        }
    }
    Err(conflict("enroll_conflict", "concurrent enrollment; retry"))
}

/// Tagged devices belong to the tenant and don't expire.
fn device_key_expiry(tags: &[String], now: i64) -> Option<i64> {
    tags.is_empty()
        .then(|| now.saturating_add(USER_DEVICE_KEY_TTL_MS))
}

fn clean_os(os: Option<&str>) -> Option<String> {
    os.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(MAX_OS_LEN).collect())
}

pub(super) async fn post_cred(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let device = match authenticated_device(&state, &headers, CRED_AUTH_DOMAIN, &body).await {
        Ok(d) => d,
        Err(resp) => return resp,
    };
    match mint_cred(&state, &device) {
        Ok(cred) => json_ok(CredResponse { cred }),
        Err(resp) => *resp,
    }
}

pub(super) async fn get_netmap(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let device = match authenticated_device(&state, &headers, NETMAP_AUTH_DOMAIN, &[]).await {
        Ok(d) => d,
        Err(resp) => return resp,
    };
    let devices = match state.db.list_mesh_devices(&device.tenant_id).await {
        Ok(d) => d,
        Err(e) => {
            warn!(error = %e, "list_mesh_devices failed");
            return internal_error();
        }
    };
    let peers = devices
        .iter()
        .filter(|d| d.device_id != device.device_id)
        .map(DeviceView::from)
        .collect();
    let signer = state.signer.as_ref();
    json_ok(NetmapResponse {
        tenant_id: device.tenant_id.to_string(),
        this_device: DeviceView::from(&device),
        peers,
        hub_keys: vec![HubKeyView {
            kid: signer.kid(),
            public_key_b64: B64.encode(signer.public_key().as_bytes()),
        }],
        relay_url: state.identity.relay_url.clone(),
    })
}

pub(super) async fn post_device_code(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let device_id =
        match verify_device_request(&state, &headers, DEVICE_CODE_AUTH_DOMAIN, &body).await {
            Ok(d) => d,
            Err(resp) => return resp,
        };
    let req: DeviceCodeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return invalid_request(format!("invalid JSON body: {e}")),
    };
    let name = sanitize_label(&req.name).unwrap_or_else(|| "device".to_string());
    let os = clean_os(req.os.as_deref());
    let requester_ip = client_ip_key(&state.trusted_proxies, &peer, &headers);
    let now = now_ms_i64();

    let user_code = match new_user_code() {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "OS RNG failure while minting device code");
            return internal_error();
        }
    };
    if let Err(e) = state
        .db
        .insert_mesh_device_code(NewMeshDeviceCode {
            user_code: &user_code,
            device_id: &device_id,
            name: &name,
            os: os.as_deref(),
            requester_ip: Some(&requester_ip),
            expires_at_ms: now + DEVICE_CODE_TTL_MS,
            now_ms: now,
        })
        .await
    {
        warn!(error = %e, "insert_mesh_device_code failed");
        return internal_error();
    }
    let base = state.console_url.as_deref().unwrap_or(&state.public_url);
    json_with_status(
        StatusCode::CREATED,
        DeviceCodeResponse {
            verification_url: format!(
                "{}/mesh/connect?code={user_code}",
                base.trim_end_matches('/')
            ),
            user_code: display_user_code(&user_code),
            expires_in_secs: DEVICE_CODE_TTL_SECS,
            interval_secs: DEVICE_CODE_POLL_SECS,
        },
    )
}

#[utoipa::path(
    get,
    path = "/v1/mesh/device-code/{code}",
    tag = "mesh",
    params(("code" = String, Path, description = "User code, with or without the dash")),
    responses(
        (status = 200, description = "Pending device awaiting approval", body = DeviceCodeInfo),
        (status = 403, description = "Only user accounts approve devices"),
        (status = 404, description = "Unknown or expired code"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn get_device_code(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(code): Path<String>,
) -> Response {
    if !matches!(principal, Principal::User(_)) {
        return user_required("devices are approved by a user account");
    }
    let row = match live_device_code(&state, &code).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let enrolled_tenant_id = match state.db.get_mesh_device(&row.device_id).await {
        Ok(d) => d.map(|d| d.tenant_id.to_string()),
        Err(e) => {
            warn!(error = %e, "get_mesh_device failed");
            return internal_error();
        }
    };
    json_ok(DeviceCodeInfo {
        user_code: display_user_code(&row.user_code),
        name: row.name,
        os: row.os,
        requester_ip: row.requester_ip,
        created_at_ms: row.created_at_ms,
        expires_at_ms: row.expires_at_ms,
        approved: row.approved_tenant_id.is_some(),
        enrolled_tenant_id,
    })
}

#[utoipa::path(
    post,
    path = "/v1/mesh/device-code/{code}/approve",
    tag = "mesh",
    params(("code" = String, Path, description = "User code, with or without the dash")),
    request_body = ApproveDeviceCodeRequest,
    responses(
        (status = 200, description = "Approved; the device finishes enrollment on its next poll"),
        (status = 403, description = "Not a user account, or not a member of the tenant"),
        (status = 404, description = "Unknown, expired, or already approved code"),
        (status = 409, description = "Device is enrolled in another tenant"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn post_approve_device_code(
    State(state): State<Arc<AppState>>,
    principal: Principal,
    Path(code): Path<String>,
    axum::Json(body): axum::Json<ApproveDeviceCodeRequest>,
) -> Response {
    let Principal::User(user) = &principal else {
        return user_required("devices are approved by a user account");
    };
    let tenant_id = match tenant_for(&state, &principal, &body.tenant_id).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    let row = match live_device_code(&state, &code).await {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    match state.db.get_mesh_device(&row.device_id).await {
        Ok(Some(d)) if d.tenant_id != tenant_id => {
            return conflict(
                "device_already_enrolled",
                "this device is enrolled in another tenant",
            );
        }
        Ok(_) => {}
        Err(e) => {
            warn!(error = %e, "get_mesh_device failed");
            return internal_error();
        }
    }
    match state
        .db
        .approve_mesh_device_code(&row.user_code, &tenant_id, &user.id, now_ms_i64())
        .await
    {
        Ok(true) => {}
        Ok(false) => return not_found("device code is invalid, expired, or already approved"),
        Err(e) => {
            warn!(error = %e, "approve_mesh_device_code failed");
            return internal_error();
        }
    }
    audit(
        &state,
        actor(&principal),
        "mesh.device_code.approve",
        "mesh_device",
        &hex::encode(row.device_id),
        serde_json::json!({
            "tenant_id": tenant_id.to_string(),
            "name": row.name,
            "requester_ip": row.requester_ip,
        }),
    )
    .await;
    json_ok(serde_json::json!({"ok": true}))
}

pub(super) async fn post_device_poll(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let device_id =
        match verify_device_request(&state, &headers, DEVICE_POLL_AUTH_DOMAIN, &body).await {
            Ok(d) => d,
            Err(resp) => return resp,
        };
    let row = match state.db.find_mesh_device_code_for_device(&device_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return not_found("no pending device code for this device"),
        Err(e) => {
            warn!(error = %e, "find_mesh_device_code_for_device failed");
            return internal_error();
        }
    };
    if row.expires_at_ms <= now_ms_i64() {
        return gone("device code expired; request a new one");
    }
    let (Some(tenant_id), Some(user_id)) = (row.approved_tenant_id, &row.approved_by_user_id)
    else {
        return json_with_status(
            StatusCode::ACCEPTED,
            serde_json::json!({"status": "pending", "interval_secs": DEVICE_CODE_POLL_SECS}),
        );
    };
    if !state.policy.load().is_known_tenant(&tenant_id) {
        return gone("tenant no longer exists; request a new code");
    }

    match state.db.get_mesh_device(&device_id).await {
        Ok(Some(existing)) if existing.tenant_id == tenant_id => {
            renew_device(&state, &row, &existing).await
        }
        Ok(Some(_)) => conflict(
            "device_already_enrolled",
            "this device key is enrolled in another tenant",
        ),
        Ok(None) => enroll_with_code(&state, &row, &tenant_id, user_id).await,
        Err(e) => {
            warn!(error = %e, "get_mesh_device failed");
            internal_error()
        }
    }
}

async fn enroll_with_code(
    state: &AppState,
    row: &MeshDeviceCodeRow,
    tenant_id: &TenantId,
    user_id: &str,
) -> Response {
    let spec = DeviceSpec {
        tenant_id,
        user_id: Some(user_id),
        tags: &[],
        name: &row.name,
        os: row.os.as_deref(),
    };
    let grant = EnrollGrant::DeviceCode(&row.user_code);
    let device = match insert_device(state, &grant, &row.device_id, spec).await {
        Ok(Some(d)) => d,
        Ok(None) => return gone("device code already used; request a new one"),
        Err(resp) => return resp,
    };
    audit(
        state,
        ("user", Some(user_id)),
        "mesh.device.enroll",
        "mesh_device",
        &hex::encode(row.device_id),
        serde_json::json!({"tenant_id": tenant_id.to_string(), "name": device.name}),
    )
    .await;
    enroll_response(state, StatusCode::CREATED, &device)
}

/// Same IP and name; only the key expiry moves.
async fn renew_device(
    state: &AppState,
    row: &MeshDeviceCodeRow,
    existing: &MeshDeviceRow,
) -> Response {
    let now = now_ms_i64();
    let expiry = device_key_expiry(&existing.tags, now);
    match state
        .db
        .renew_mesh_device_key(&row.user_code, &existing.device_id, expiry, now)
        .await
    {
        Ok(true) => {}
        Ok(false) => return gone("device code already used; request a new one"),
        Err(e) => {
            warn!(error = %e, "renew_mesh_device_key failed");
            return internal_error();
        }
    }
    let renewed = MeshDeviceRow {
        key_expires_at_ms: expiry,
        last_seen_at_ms: Some(now),
        ..existing.clone()
    };
    enroll_response(state, StatusCode::OK, &renewed)
}

async fn live_device_code(state: &AppState, code: &str) -> Result<MeshDeviceCodeRow, Response> {
    let not_found_resp = || not_found("device code not found or expired");
    let code = normalize_user_code(code).ok_or_else(not_found_resp)?;
    match state.db.find_mesh_device_code(&code).await {
        Ok(Some(r)) if r.expires_at_ms > now_ms_i64() => Ok(r),
        Ok(_) => Err(not_found_resp()),
        Err(e) => {
            warn!(error = %e, "find_mesh_device_code failed");
            Err(internal_error())
        }
    }
}

async fn tenant_for(
    state: &Arc<AppState>,
    principal: &Principal,
    id: &str,
) -> Result<TenantId, Response> {
    let tenant_id: TenantId = id
        .parse()
        .map_err(|e| invalid_request(format!("invalid tenant_id: {e}")))?;
    authorize_tenant(state, principal, &tenant_id).await?;
    if !state.policy.load().is_known_tenant(&tenant_id) {
        return Err(not_found("tenant not found"));
    }
    Ok(tenant_id)
}

const fn actor(principal: &Principal) -> (&'static str, Option<&str>) {
    match principal {
        Principal::OperatorKey => ("operator_key", None),
        Principal::User(u) => ("user", Some(u.id.as_str())),
    }
}

async fn audit(
    state: &AppState,
    (actor_kind, actor_user_id): (&str, Option<&str>),
    action: &str,
    target_kind: &str,
    target_id: &str,
    metadata: serde_json::Value,
) {
    if let Err(e) = state
        .db
        .insert_admin_action(NewAdminAction {
            id: &new_id(16),
            actor_user_id,
            actor_kind,
            action,
            target_kind,
            target_id: Some(target_id),
            metadata: Some(metadata),
            now_ms: now_ms_i64(),
        })
        .await
    {
        warn!(error = %e, action, "audit insert failed");
    }
}

async fn verify_device_request(
    state: &AppState,
    headers: &HeaderMap,
    domain: &str,
    body: &[u8],
) -> Result<DeviceId, Response> {
    let (device_id, ts_ms) =
        verify_signature_header(headers, domain, MAX_CLOCK_SKEW_MS, body).map_err(unauthorized)?;
    let fresh = state
        .signed_request_nonces
        .entry((device_id, ts_ms))
        .or_insert_with(async {})
        .await
        .is_fresh();
    if !fresh {
        return Err(unauthorized("replayed signature"));
    }
    Ok(device_id)
}

async fn authenticated_device(
    state: &AppState,
    headers: &HeaderMap,
    domain: &str,
    body: &[u8],
) -> Result<MeshDeviceRow, Response> {
    let device_id = verify_device_request(state, headers, domain, body).await?;
    if !check_rate_limit(state, device_id).await {
        return Err(error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            format!("more than {AGENT_REFRESH_MAX_PER_MIN} requests per minute for this device"),
        ));
    }
    let device = match state.db.get_mesh_device(&device_id).await {
        Ok(Some(d)) => d,
        Ok(None) => return Err(unauthorized("device is not enrolled")),
        Err(e) => {
            warn!(error = %e, "get_mesh_device failed");
            return Err(internal_error());
        }
    };
    let now = now_ms_i64();
    if device.key_expires_at_ms.is_some_and(|t| t <= now) {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "key_expired",
            "device key expired; sign in again",
        ));
    }
    if let Err(e) = state.db.touch_mesh_device(&device_id, now).await {
        warn!(error = %e, "touch_mesh_device failed");
    }
    Ok(device)
}

async fn check_rate_limit(state: &AppState, device_id: DeviceId) -> bool {
    let counter: Arc<AtomicU32> = state
        .refresh_limiter
        .get_with(device_id, async { Arc::new(AtomicU32::new(0)) })
        .await;
    counter.fetch_add(1, Ordering::Relaxed) < AGENT_REFRESH_MAX_PER_MIN
}

fn enroll_response(state: &AppState, status: StatusCode, device: &MeshDeviceRow) -> Response {
    match mint_cred(state, device) {
        Ok(cred) => json_with_status(
            status,
            EnrollResponse {
                tenant_id: device.tenant_id.to_string(),
                device: DeviceView::from(device),
                cred,
            },
        ),
        Err(resp) => *resp,
    }
}

fn mint_cred(state: &AppState, device: &MeshDeviceRow) -> Result<CredView, Box<Response>> {
    let mut not_after_ms = now_ms() + MESH_CRED_TTL_MS;
    if let Some(expiry) = device.key_expires_at_ms.and_then(|t| u64::try_from(t).ok()) {
        not_after_ms = not_after_ms.min(expiry);
    }
    let cred = MeshCred {
        version: MESH_CRED_VERSION,
        kid: state.signer.kid(),
        device_id: device.device_id,
        tenant_id: device.tenant_id,
        ipv4: device.ipv4,
        ipv6: mesh_ipv6(&device.tenant_id, &device.device_id),
        tags: device.tags.clone(),
        owner: device.user_id.clone(),
        not_after_ms,
    };
    let (bytes, sig) = state.signer.sign_mesh_cred(&cred).map_err(|e| {
        warn!(error = %e, "MeshCred encoding failed");
        Box::new(internal_error())
    })?;
    Ok(CredView {
        kid: cred.kid,
        cred_b64: B64.encode(&bytes),
        sig_b64: B64.encode(sig),
        not_after_ms,
    })
}

fn mint_auth_key() -> anyhow::Result<(String, [u8; 32])> {
    let mut secret = [0u8; AUTH_KEY_SECRET_BYTES];
    getrandom::fill(&mut secret).map_err(|e| anyhow::anyhow!("OS RNG: {e}"))?;
    let secret = B64.encode(secret);
    let hash = hash_auth_key_secret(&secret);
    Ok((format!("{AUTH_KEY_PREFIX}{secret}"), hash))
}

fn parse_auth_key(token: &str) -> Option<[u8; 32]> {
    let secret = token.trim().strip_prefix(AUTH_KEY_PREFIX)?;
    (!secret.is_empty()).then(|| hash_auth_key_secret(secret))
}

fn hash_auth_key_secret(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

fn new_user_code() -> anyhow::Result<String> {
    let mut code = String::with_capacity(USER_CODE_LEN);
    while code.len() < USER_CODE_LEN {
        let mut b = [0u8; 1];
        getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("OS RNG: {e}"))?;
        // 240 = 12 * 20: rejecting the rest keeps `% 20` uniform.
        if let [b @ 0..240] = b
            && let Some(c) = USER_CODE_ALPHABET.get(usize::from(b % 20))
        {
            code.push(char::from(*c));
        }
    }
    Ok(code)
}

fn normalize_user_code(raw: &str) -> Option<String> {
    let code: String = raw
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (code.len() == USER_CODE_LEN && code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)))
        .then_some(code)
}

fn display_user_code(code: &str) -> String {
    let (a, b) = code.split_at(code.len() / 2);
    format!("{a}-{b}")
}

/// Lowercase DNS label: `[a-z0-9-]`, no leading/trailing `-`, max 63 chars.
fn sanitize_label(raw: &str) -> Option<String> {
    let mut label = String::new();
    for c in raw.trim().to_ascii_lowercase().chars() {
        let c = if c.is_ascii_alphanumeric() { c } else { '-' };
        if c == '-' && (label.is_empty() || label.ends_with('-')) {
            continue;
        }
        label.push(c);
    }
    label.truncate(MAX_LABEL_LEN);
    let label = label.trim_end_matches('-');
    (!label.is_empty()).then(|| label.to_string())
}

fn normalize_tags(raw: Vec<String>) -> Result<Vec<String>, String> {
    let mut tags = Vec::with_capacity(raw.len());
    for tag in raw {
        let tag = tag.trim().to_ascii_lowercase();
        let valid = tag.strip_prefix("tag:").is_some_and(|name| {
            !name.is_empty()
                && name.len() <= MAX_LABEL_LEN
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        });
        if !valid {
            return Err(format!(
                "invalid tag {tag:?}: expected tag:<name> with [a-z0-9-]"
            ));
        }
        tags.push(tag);
    }
    tags.sort();
    tags.dedup();
    if tags.len() > MAX_TAGS {
        return Err(format!("at most {MAX_TAGS} tags"));
    }
    Ok(tags)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_label_produces_dns_labels() {
        assert_eq!(
            sanitize_label("Erwan's MacBook Pro"),
            Some("erwan-s-macbook-pro".into())
        );
        assert_eq!(sanitize_label("--nas--"), Some("nas".into()));
        assert_eq!(sanitize_label("  "), None);
        assert_eq!(sanitize_label("日本"), None);
        let long = "a".repeat(100);
        assert_eq!(sanitize_label(&long).unwrap().len(), MAX_LABEL_LEN);
    }

    #[test]
    fn normalize_tags_validates_and_dedups() {
        assert_eq!(
            normalize_tags(vec![
                "TAG:Server".into(),
                "tag:server".into(),
                "tag:db".into()
            ]),
            Ok(vec!["tag:db".into(), "tag:server".into()])
        );
        normalize_tags(vec!["server".into()]).unwrap_err();
        normalize_tags(vec!["tag:".into()]).unwrap_err();
        normalize_tags(vec!["tag:a_b".into()]).unwrap_err();
    }

    #[test]
    fn user_codes_are_well_formed() {
        let code = new_user_code().unwrap();
        assert_eq!(code.len(), USER_CODE_LEN);
        let shown = display_user_code(&code);
        assert_eq!(shown.len(), USER_CODE_LEN + 1);
        assert_eq!(normalize_user_code(&shown.to_lowercase()), Some(code));
        assert_eq!(normalize_user_code("AAAA-AAAA"), None);
        assert_eq!(normalize_user_code("BCDF"), None);
    }

    #[test]
    fn auth_key_round_trips() {
        let (token, hash) = mint_auth_key().unwrap();
        assert!(token.starts_with(AUTH_KEY_PREFIX));
        assert_eq!(parse_auth_key(&token), Some(hash));
        assert_eq!(parse_auth_key("twk_abc"), None);
        assert_eq!(parse_auth_key(AUTH_KEY_PREFIX), None);
    }
}
