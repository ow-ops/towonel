//! Optional mesh device next to the tunnel: peers reach the services in
//! `TOWONEL_AGENT_MESH_SERVICES`, which are never published on an edge.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use prometheus::IntGauge;
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use towonel_mesh::{MeshClient, MeshNode, NodeOptions, StateDir, Stopped};
use tracing::{error, info, warn};

const RETRY_BASE: Duration = Duration::from_secs(5);
const RETRY_MAX: Duration = Duration::from_mins(1);

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshService {
    /// Port peers connect to on this device.
    pub port: u16,
    /// `host:port` the agent dials for them.
    pub origin: String,
}

/// Empty when unset: the agent doesn't join the mesh.
pub fn load_services() -> anyhow::Result<HashMap<u16, String>> {
    let Ok(raw) = std::env::var("TOWONEL_AGENT_MESH_SERVICES") else {
        return Ok(HashMap::new());
    };
    parse_services(&raw)
}

fn parse_services(raw: &str) -> anyhow::Result<HashMap<u16, String>> {
    let list: Vec<MeshService> =
        serde_json::from_str(raw).context("TOWONEL_AGENT_MESH_SERVICES is not valid JSON")?;
    let mut map = HashMap::new();
    for svc in list {
        if svc.port == 0 {
            bail!("mesh service port must not be 0");
        }
        if svc
            .origin
            .rsplit_once(':')
            .is_none_or(|(host, port)| host.is_empty() || port.parse::<u16>().is_err())
        {
            bail!("mesh service origin {:?} must be host:port", svc.origin);
        }
        if map.insert(svc.port, svc.origin).is_some() {
            bail!("duplicate mesh service port {}", svc.port);
        }
    }
    Ok(map)
}

/// Keeps the device in the mesh until `shutdown`. Stops for good when the
/// hub removes it, so a reusable auth key can't undo a revocation.
pub async fn run(
    hub_url: String,
    services: HashMap<u16, String>,
    up: IntGauge,
    shutdown: CancellationToken,
) {
    let services = Arc::new(services);
    let mut delay = RETRY_BASE;
    loop {
        let outcome = tokio::select! {
            () = shutdown.cancelled() => return,
            r = serve(&hub_url, &services, &up, &shutdown) => r,
        };
        let Err(e) = outcome else { return };
        warn!(error = %format!("{e:#}"), retry_secs = delay.as_secs(), "mesh unavailable");
        tokio::select! {
            () = shutdown.cancelled() => return,
            () = tokio::time::sleep(delay) => {}
        }
        delay = (delay * 2).min(RETRY_MAX);
    }
}

async fn serve(
    hub_url: &str,
    services: &Arc<HashMap<u16, String>>,
    up: &IntGauge,
    shutdown: &CancellationToken,
) -> anyhow::Result<()> {
    let dir = std::env::var_os("TOWONEL_MESH_STATE_DIR")
        .filter(|d| !d.is_empty())
        .map_or_else(StateDir::default_path, Into::into);
    let state = StateDir::open(dir)?;
    let name = std::env::var("TOWONEL_MESH_NAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "agent".to_string());
    let auth_key = std::env::var("TOWONEL_MESH_AUTH_KEY").ok();
    let enrolled = state.load_enrollment()?.is_some();
    if auth_key.is_none() && !enrolled {
        error!("TOWONEL_MESH_AUTH_KEY is required to join the mesh; mesh services are off");
        return Ok(());
    }
    let device =
        match towonel_mesh::join_unattended(&state, hub_url, auth_key.as_deref(), &name).await {
            Ok(d) => d,
            // Removed, expired or a bad key: waiting won't fix it.
            Err(e) if is_access_error(&e) && !enrolled => {
                error!(
                    error = %format!("{e:#}"),
                    "mesh auth key rejected; a one-use key only adds one replica. Put a \
                     reusable key in the Secret (`towonel mesh auth-key --k8s-secret`) and \
                     restart the pod"
                );
                return Ok(());
            }
            Err(e) if is_access_error(&e) => {
                error!(error = %format!("{e:#}"), "not joining the mesh");
                return Ok(());
            }
            Err(e) => return Err(e),
        };

    let key = state.device_key()?;
    let node = MeshNode::start(
        MeshClient::new(hub_url, key.clone())?,
        key,
        NodeOptions {
            services: Some(Arc::clone(services)),
            ..NodeOptions::default()
        },
    )
    .await?;
    let mut ports: Vec<_> = services.keys().copied().collect();
    ports.sort_unstable();
    info!(name = %device.name, ipv4 = %device.ipv4, ?ports, "in the mesh");
    up.set(1);

    tokio::select! {
        () = shutdown.cancelled() => {}
        reason = node.stopped() => match reason {
            Some(Stopped::Revoked) => error!("removed from the mesh; mesh services are off"),
            Some(Stopped::KeyExpired) => error!("mesh device key expired; mesh services are off"),
            None => {}
        },
    }
    up.set(0);
    node.shutdown().await;
    Ok(())
}

fn is_access_error(e: &anyhow::Error) -> bool {
    e.downcast_ref::<towonel_common::hub_error::HubApiError>()
        .is_some_and(|h| h.status == 401 || h.status == 403)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_validates_services() {
        let map = parse_services(r#"[{"port": 5432, "origin": "postgres.db.svc:5432"}]"#).unwrap();
        assert_eq!(map[&5432], "postgres.db.svc:5432");

        for (raw, want) in [
            (r#"[{"port": 0, "origin": "a:1"}]"#, "must not be 0"),
            (r#"[{"port": 1, "origin": "a"}]"#, "host:port"),
            (r#"[{"port": 1, "origin": ":5"}]"#, "host:port"),
            (
                r#"[{"port": 1, "origin": "a:1"}, {"port": 1, "origin": "b:2"}]"#,
                "duplicate",
            ),
            (
                r#"[{"port": 1, "origin": "a:1", "tls": true}]"#,
                "not valid JSON",
            ),
        ] {
            let err = format!("{:#}", parse_services(raw).unwrap_err());
            assert!(err.contains(want), "{raw}: {err}");
        }
    }
}
