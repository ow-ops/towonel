use anyhow::{Context, bail};
use serde::Deserialize;
use towonel_common::identity::TenantKeypair;
use towonel_common::invite::InviteToken;

use super::{check_response, resolve_api_key, resolve_hub_url};

pub struct AuthKeyRequest {
    pub tenant_id: Option<String>,
    /// Stands in for `tenant_id`, and for the hub URL when none is given.
    pub invite_token: Option<String>,
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
pub async fn cmd_mesh_auth_key(
    hub_url: Option<String>,
    api_key: Option<String>,
    req: AuthKeyRequest,
) -> anyhow::Result<()> {
    let (tenant_id, token_hub) = match (req.tenant_id, req.invite_token) {
        (Some(id), _) => (id, None),
        (None, Some(token)) => {
            let token = InviteToken::decode(&token).context("invalid invite token")?;
            let id = TenantKeypair::from_seed(token.tenant_seed).id().to_string();
            (id, Some(token.hub_url.clone()))
        }
        (None, None) => bail!("pass --tenant-id or --invite-token"),
    };
    let hub_url = resolve_hub_url(hub_url.or(token_hub));
    let api_key = resolve_api_key(api_key)?;
    // A Secret is shared by every replica, so each must be able to join.
    let reusable = req.reusable || req.k8s_secret.is_some();
    let url = format!(
        "{}/v1/tenants/{tenant_id}/mesh/auth-keys",
        hub_url.trim_end_matches('/'),
    );
    let resp = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&api_key)
        .json(&serde_json::json!({
            "tags": req.tags,
            "reusable": reusable,
            "expires_in_days": req.expires_in_days,
        }))
        .send()
        .await
        .with_context(|| format!("failed to POST {url}"))?;
    let created: Created = serde_json::from_slice(&check_response(resp).await?)?;

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
