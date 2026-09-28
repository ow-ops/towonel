use std::io::Read;
use std::path::PathBuf;

use anyhow::{Context, bail};
use serde::Deserialize;
use tabled::{Table, Tabled, settings::Style};
use towonel_common::identity::TenantKeypair;
use towonel_common::invite::InviteToken;
use towonel_common::time::now_ms;
use towonel_mesh::api::Device;

use super::{check_response, resolve_api_key, resolve_hub_url};

/// Which tenant's mesh a command acts on, and as whom.
#[derive(clap::Args)]
pub struct TenantTarget {
    /// Defaults to `TOWONEL_HUB_URL`, else the invite token's hub.
    #[arg(long)]
    hub_url: Option<String>,
    /// Personal API key (`twk_…`) or operator key. Defaults to
    /// `TOWONEL_API_KEY`, else the operator key.
    #[arg(long)]
    api_key: Option<String>,
    /// Tenant (tunnel) id.
    #[arg(long, required_unless_present = "invite_token")]
    tenant_id: Option<String>,
    /// The agent's invite token, instead of `--tenant-id`.
    #[arg(long, env = "TOWONEL_INVITE_TOKEN", hide_env_values = true)]
    invite_token: Option<String>,
}

struct Mesh {
    /// `<hub>/v1/tenants/<id>/mesh`
    base: String,
    api_key: String,
    http: reqwest::Client,
}

impl TenantTarget {
    fn resolve(self) -> anyhow::Result<Mesh> {
        let (tenant_id, token_hub) = match (self.tenant_id, self.invite_token) {
            (Some(id), _) => (id, None),
            (None, Some(token)) => {
                let token = InviteToken::decode(&token).context("invalid invite token")?;
                let id = TenantKeypair::from_seed(token.tenant_seed).id().to_string();
                (id, Some(token.hub_url.clone()))
            }
            (None, None) => bail!("pass --tenant-id or --invite-token"),
        };
        let hub_url = resolve_hub_url(self.hub_url.or(token_hub));
        Ok(Mesh {
            base: format!(
                "{}/v1/tenants/{tenant_id}/mesh",
                hub_url.trim_end_matches('/')
            ),
            api_key: resolve_api_key(self.api_key)?,
            http: reqwest::Client::new(),
        })
    }
}

impl Mesh {
    async fn send(&self, req: reqwest::RequestBuilder) -> anyhow::Result<Vec<u8>> {
        let resp = req
            .bearer_auth(&self.api_key)
            .send()
            .await
            .with_context(|| format!("cannot reach {}", self.base))?;
        check_response(resp).await
    }
}

pub struct AuthKeyRequest {
    pub tags: Vec<String>,
    pub reusable: bool,
    pub expires_in_days: Option<i64>,
    /// Print a Kubernetes Secret with this name instead of the bare key.
    pub k8s_secret: Option<String>,
    pub namespace: Option<String>,
}

#[derive(Deserialize)]
struct Created {
    token: String,
    expires_at_ms: i64,
}

/// Only the key or the Secret goes to stdout, so it pipes into `kubectl`.
pub async fn cmd_mesh_auth_key(target: TenantTarget, req: AuthKeyRequest) -> anyhow::Result<()> {
    let mesh = target.resolve()?;
    // A Secret is shared by every replica, so each must be able to join.
    let reusable = req.reusable || req.k8s_secret.is_some();
    let body = mesh
        .send(
            mesh.http
                .post(format!("{}/auth-keys", mesh.base))
                .json(&serde_json::json!({
                    "tags": req.tags,
                    "reusable": reusable,
                    "expires_in_days": req.expires_in_days,
                })),
        )
        .await?;
    let created: Created = serde_json::from_slice(&body)?;

    eprintln!(
        "Auth key {} until {}.",
        if reusable {
            "adds devices"
        } else {
            "adds one device"
        },
        format_ms(created.expires_at_ms)
    );
    if req.tags.is_empty() {
        eprintln!("Untagged: its devices expire after 180 days. Use --tag for servers.");
    }
    match req.k8s_secret {
        Some(name) => print!(
            "{}",
            secret_manifest(&name, req.namespace.as_deref(), &created.token)
        ),
        None => println!("{}", created.token),
    }
    Ok(())
}

#[derive(Deserialize)]
struct PolicyResponse {
    policy: Option<serde_json::Value>,
    version: i64,
}

/// The policy as JSON on stdout, ready to edit and pass to `policy set`.
pub async fn cmd_policy_get(target: TenantTarget) -> anyhow::Result<()> {
    let mesh = target.resolve()?;
    let body = mesh
        .send(mesh.http.get(format!("{}/policy", mesh.base)))
        .await?;
    let resp: PolicyResponse = serde_json::from_slice(&body)?;
    match resp.policy {
        Some(policy) => println!("{}", serde_json::to_string_pretty(&policy)?),
        None => eprintln!("No custom policy: the default applies."),
    }
    Ok(())
}

/// `file` is JSON, or `-` for stdin. The hub rejects it if a test fails.
pub async fn cmd_policy_set(target: TenantTarget, file: PathBuf) -> anyhow::Result<()> {
    let raw = if file.as_os_str() == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        s
    } else {
        std::fs::read_to_string(&file).with_context(|| format!("cannot read {}", file.display()))?
    };
    let policy: serde_json::Value =
        serde_json::from_str(&raw).context("policy is not valid JSON")?;
    let mesh = target.resolve()?;
    let body = mesh
        .send(mesh.http.put(format!("{}/policy", mesh.base)).json(&policy))
        .await?;
    let resp: PolicyResponse = serde_json::from_slice(&body)?;
    eprintln!(
        "Saved policy version {}; devices apply it now.",
        resp.version
    );
    Ok(())
}

pub async fn cmd_policy_reset(target: TenantTarget) -> anyhow::Result<()> {
    let mesh = target.resolve()?;
    mesh.send(mesh.http.delete(format!("{}/policy", mesh.base)))
        .await?;
    eprintln!("Back to the default policy.");
    Ok(())
}

#[derive(Deserialize)]
struct DeviceList {
    devices: Vec<Device>,
}

async fn list_devices(mesh: &Mesh) -> anyhow::Result<Vec<Device>> {
    let body = mesh
        .send(mesh.http.get(format!("{}/devices", mesh.base)))
        .await?;
    Ok(serde_json::from_slice::<DeviceList>(&body)?.devices)
}

#[derive(Tabled)]
struct DeviceRow {
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "IPV4")]
    ipv4: String,
    #[tabled(rename = "TAGS")]
    tags: String,
    #[tabled(rename = "LAST SEEN")]
    last_seen: String,
    #[tabled(rename = "SERVICES")]
    services: String,
}

pub async fn cmd_devices(target: TenantTarget, json: bool) -> anyhow::Result<()> {
    let devices = list_devices(&target.resolve()?).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&devices)?);
        return Ok(());
    }
    let now = now_ms();
    let dash = |s: String| if s.is_empty() { "-".to_string() } else { s };
    let rows = devices.into_iter().map(|d| DeviceRow {
        last_seen: d
            .last_seen_at_ms
            .map_or_else(|| "-".to_string(), |t| crate::mesh_cli::ago(now, t)),
        tags: dash(d.tags.join(",")),
        services: dash(
            d.services
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ),
        name: d.name,
        ipv4: d.ipv4,
    });
    println!("{}", Table::new(rows).with(Style::blank()));
    Ok(())
}

/// `device` is a name, overlay IP or device id.
pub async fn cmd_remove(target: TenantTarget, device: String) -> anyhow::Result<()> {
    let mesh = target.resolve()?;
    let found = list_devices(&mesh)
        .await?
        .into_iter()
        .find(|d| d.name == device || d.ipv4 == device || d.ipv6 == device || d.device_id == device)
        .with_context(|| format!("no device {device} in this mesh"))?;
    mesh.send(
        mesh.http
            .delete(format!("{}/devices/{}", mesh.base, found.device_id)),
    )
    .await?;
    eprintln!("Removed {} ({}).", found.name, found.ipv4);
    Ok(())
}

fn secret_manifest(name: &str, namespace: Option<&str>, token: &str) -> String {
    let namespace = namespace.map_or_else(String::new, |ns| format!("  namespace: {ns}\n"));
    format!(
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: {name}\n{namespace}type: Opaque\n\
         stringData:\n  TOWONEL_MESH_AUTH_KEY: {token}\n"
    )
}

fn format_ms(ms: i64) -> String {
    let at = std::time::UNIX_EPOCH + std::time::Duration::from_millis(ms.try_into().unwrap_or(0));
    humantime::format_rfc3339_seconds(at).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_manifest_is_valid_yaml() {
        assert_eq!(
            secret_manifest("towonel-mesh", Some("net"), "tmk_abc"),
            "apiVersion: v1\nkind: Secret\nmetadata:\n  name: towonel-mesh\n  namespace: net\n\
             type: Opaque\nstringData:\n  TOWONEL_MESH_AUTH_KEY: tmk_abc\n"
        );
        assert!(!secret_manifest("s", None, "t").contains("namespace"));
    }

    #[test]
    fn formats_expiry() {
        assert_eq!(format_ms(1_798_761_600_000), "2027-01-01T00:00:00Z");
    }
}
