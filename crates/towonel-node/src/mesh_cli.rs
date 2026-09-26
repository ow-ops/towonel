//! `towonel mesh …`: join this machine to a tenant's private mesh.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use tabled::{Table, Tabled, settings::Style};
use towonel_common::hub_error::HubApiError;
use towonel_common::time::now_ms;
use towonel_mesh::api::{Device, Enrolled, Netmap};
use towonel_mesh::client::is_transient;
use towonel_mesh::{Enrollment, MeshClient, Poll, StateDir, StreamEvent};

const OS: &str = std::env::consts::OS;
const MAX_RECONNECT_DELAY: Duration = Duration::from_mins(1);

pub async fn cmd_up(
    hub_url: Option<String>,
    auth_key: Option<String>,
    name: Option<String>,
    state_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    let state = open_state(state_dir)?;
    let existing = state.load_enrollment()?;
    let hub_url = hub_url
        .or_else(|| existing.as_ref().map(|e| e.hub_url.clone()))
        .context("--hub-url (or TOWONEL_HUB_URL) is required the first time")?;
    let client = MeshClient::new(&hub_url, state.device_key()?)?;

    let mut key_expired = false;
    if existing.is_some() {
        match client.netmap().await {
            Ok(netmap) => {
                let enrollment = enrollment_from(&hub_url, &netmap.tenant_id, &netmap.this_device);
                state.save_enrollment(&enrollment)?;
                println!("Already in the mesh as {}.", describe(&enrollment));
                return Ok(());
            }
            Err(e) if hub_code(&e) == Some("key_expired") => {
                println!("This device's key expired; sign in to renew it.\n");
                key_expired = true;
            }
            Err(e) if hub_code(&e) == Some("unauthorized") => {
                println!("This device was removed from the mesh; adding it again.\n");
            }
            Err(e) => return Err(e),
        }
    }

    let name = name
        .or_else(|| existing.map(|e| e.name))
        .unwrap_or_else(hostname);
    // Auth-key enrollment returns an expired device unchanged; renewal needs a user.
    let enrolled = match auth_key {
        Some(key) if !key_expired => client.enroll(&key, &name, OS).await?,
        _ => sign_in(&client, &name).await?,
    };
    let enrollment = enrollment_from(&hub_url, &enrolled.tenant_id, &enrolled.device);
    state.save_enrollment(&enrollment)?;
    println!("Joined the mesh as {}.", describe(&enrollment));
    Ok(())
}

pub async fn cmd_status(state_dir: Option<PathBuf>, watch: bool, json: bool) -> anyhow::Result<()> {
    let state = open_state(state_dir)?;
    let enrollment = state
        .load_enrollment()?
        .context("this device is not in a mesh yet; run `towonel mesh up`")?;
    let client = MeshClient::new(&enrollment.hub_url, state.device_key()?)?;

    if !watch {
        let netmap = client.netmap().await.map_err(explain)?;
        return print_netmap(&netmap, json);
    }

    let mut delay = Duration::from_secs(1);
    loop {
        match client.netmap_stream().await {
            Ok(mut stream) => loop {
                match stream.next().await {
                    Ok(Some(StreamEvent::Netmap(netmap))) => {
                        delay = Duration::from_secs(1);
                        if !json {
                            print!("\x1b[2J\x1b[H");
                        }
                        print_netmap(&netmap, json)?;
                    }
                    Ok(Some(StreamEvent::Revoked)) => {
                        bail!("this device was removed from the mesh")
                    }
                    Ok(Some(StreamEvent::KeyExpired)) => {
                        bail!("this device's key expired; run `towonel mesh up` to renew it")
                    }
                    Ok(None) => break,
                    Err(e) => {
                        eprintln!("lost connection to the hub ({e}); reconnecting");
                        break;
                    }
                }
            },
            Err(e) if is_access_error(&e) => return Err(explain(e)),
            Err(e) => eprintln!(
                "cannot reach the hub ({e}); retrying in {}s",
                delay.as_secs()
            ),
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(MAX_RECONNECT_DELAY);
    }
}

async fn sign_in(client: &MeshClient, name: &str) -> anyhow::Result<Enrolled> {
    let code = client.request_device_code(name, OS).await?;
    println!(
        "To add this device, open:\n\n    {}\n\nand check that it shows the code {}.\n",
        code.verification_url, code.user_code
    );
    if std::io::stdout().is_terminal() {
        print_qr(&code.verification_url);
    }
    open_browser(&code.verification_url);

    let interval = Duration::from_secs(code.interval_secs.max(1));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(code.expires_in_secs);
    loop {
        tokio::time::sleep(interval).await;
        match client.poll_device_code().await {
            Ok(Poll::Pending) => {}
            Ok(Poll::Enrolled(enrolled)) => return Ok(*enrolled),
            Err(e) if hub_code(&e) == Some("gone") => {
                bail!("the code expired before it was approved; run `towonel mesh up` again")
            }
            Err(e) if is_transient(&e) && tokio::time::Instant::now() < deadline => {
                eprintln!("cannot reach the hub ({e}); still waiting for approval");
            }
            Err(e) => return Err(e),
        }
    }
}

fn open_state(dir: Option<PathBuf>) -> anyhow::Result<StateDir> {
    StateDir::open(dir.unwrap_or_else(StateDir::default_path))
}

fn enrollment_from(hub_url: &str, tenant_id: &str, device: &Device) -> Enrollment {
    Enrollment {
        hub_url: hub_url.to_string(),
        tenant_id: tenant_id.to_string(),
        device_id: device.device_id.clone(),
        name: device.name.clone(),
        ipv4: device.ipv4.clone(),
        ipv6: device.ipv6.clone(),
    }
}

fn describe(e: &Enrollment) -> String {
    format!("{} ({}, {})", e.name, e.ipv4, e.ipv6)
}

#[derive(Tabled)]
struct PeerRow {
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "IPV4")]
    ipv4: String,
    #[tabled(rename = "OS")]
    os: String,
    #[tabled(rename = "LAST SEEN")]
    last_seen: String,
}

fn print_netmap(netmap: &Netmap, json: bool) -> anyhow::Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(netmap)?);
        return Ok(());
    }
    let now = now_ms();
    let row = |d: &Device, name: String| PeerRow {
        name,
        ipv4: d.ipv4.clone(),
        os: d.os.clone().unwrap_or_else(|| "-".to_string()),
        last_seen: d
            .last_seen_at_ms
            .map_or_else(|| "-".to_string(), |t| ago(now, t)),
    };
    let mut rows = vec![row(
        &netmap.this_device,
        format!("{} (this device)", netmap.this_device.name),
    )];
    rows.extend(netmap.peers.iter().map(|d| row(d, d.name.clone())));
    println!("{}", Table::new(rows).with(Style::blank()));
    if netmap.peers.is_empty() {
        println!("\nNo other devices yet. Run `towonel mesh up` on another machine.");
    }
    Ok(())
}

fn ago(now_ms: u64, then_ms: i64) -> String {
    let secs = u64::try_from(then_ms).map_or(0, |t| now_ms.saturating_sub(t) / 1000);
    match secs {
        0..60 => "just now".to_string(),
        60..3600 => format!("{}m ago", secs / 60),
        3600..86_400 => format!("{}h ago", secs / 3600),
        _ => format!("{}d ago", secs / 86_400),
    }
}

fn hub_code(e: &anyhow::Error) -> Option<&str> {
    e.downcast_ref::<HubApiError>().map(|h| h.code.as_str())
}

fn is_access_error(e: &anyhow::Error) -> bool {
    matches!(hub_code(e), Some("unauthorized" | "key_expired"))
}

fn explain(e: anyhow::Error) -> anyhow::Error {
    match hub_code(&e) {
        Some("key_expired") => {
            anyhow::anyhow!("this device's key expired; run `towonel mesh up` to renew it")
        }
        Some("unauthorized") => {
            anyhow::anyhow!("this device is not in the mesh; run `towonel mesh up` to add it")
        }
        _ => e,
    }
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "device".to_string())
}

/// Lets a headless machine be approved from a phone.
fn print_qr(url: &str) {
    match crate::mesh_qr::render(url) {
        Ok(qr) => println!("{qr}"),
        Err(e) => tracing::debug!(error = %e, "could not render QR code"),
    }
}

/// Best effort: headless machines just use the printed URL.
fn open_browser(url: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
    {
        "xdg-open"
    } else {
        return;
    };
    if let Err(e) = std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        tracing::debug!(error = %e, "could not open a browser");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ago_buckets() {
        let now = 10 * 86_400 * 1000;
        assert_eq!(ago(now, i64::try_from(now).unwrap() - 5_000), "just now");
        assert_eq!(ago(now, i64::try_from(now).unwrap() - 120_000), "2m ago");
        assert_eq!(ago(now, i64::try_from(now).unwrap() - 7_200_000), "2h ago");
        assert_eq!(ago(now, 0), "10d ago");
    }
}
