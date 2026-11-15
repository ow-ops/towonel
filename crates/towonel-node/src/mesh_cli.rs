//! `towonel mesh …`: join this machine to a tenant's private mesh.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, bail};
use tabled::{Table, Tabled, settings::Style};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use towonel_common::hub_error::HubApiError;
use towonel_common::time::now_ms;
use towonel_mesh::api::{Device, Enrolled, Netmap};
use towonel_mesh::client::is_transient;
use towonel_mesh::{
    Enrollment, MeshClient, MeshNode, NodeOptions, Poll, StateDir, Stopped, StreamEvent, local,
};

const OS: &str = std::env::consts::OS;
const MAX_RECONNECT_DELAY: Duration = Duration::from_mins(1);

/// Exit-node role for `mesh up`.
pub struct Exit {
    pub advertise: bool,
    /// Peer to send internet traffic through.
    pub via: Option<String>,
}

pub async fn cmd_up(
    hub_url: Option<String>,
    auth_key: Option<String>,
    name: Option<String>,
    state_dir: Option<PathBuf>,
    exit: Exit,
) -> anyhow::Result<()> {
    let state = open_state(state_dir)?;
    let hub_url = enroll_if_needed(&state, hub_url, auth_key, name).await?;
    Box::pin(run(&state, &hub_url, exit)).await
}

/// Runs until Ctrl-C / SIGTERM, or until the hub removes this device.
async fn run(state: &StateDir, hub_url: &str, exit: Exit) -> anyhow::Result<()> {
    let key = state.device_key()?;
    let node = MeshNode::start(
        MeshClient::new(hub_url, key.clone())?,
        key,
        NodeOptions::default(),
    )
    .await?;
    let cancel = CancellationToken::new();
    let api = tokio::spawn(local::serve(
        node.clone(),
        local::socket_path(state.path()),
        cancel.clone(),
    ));
    let tun = match towonel_mesh::tun::Tun::create(&node) {
        Ok(tun) => {
            println!(
                "Routing the mesh through {} (MTU {}).",
                towonel_mesh::tun::DEVICE_NAME,
                towonel_mesh::tun::MTU
            );
            configure_dns(&node.netmap().borrow().dns_domain);
            Some(tokio::spawn(tun.run(node.clone(), cancel.clone())))
        }
        Err(e) => {
            println!(
                "Overlay IPs are not routed ({e:#}). Run as root or with CAP_NET_ADMIN for that; \
                 `towonel mesh connect` and `nc` work without it."
            );
            None
        }
    };
    let exit_setup = match setup_exit(&node, hub_url, &exit, tun.is_some()).await {
        Ok(guard) => guard,
        Err(e) => {
            cancel.cancel();
            node.shutdown().await;
            return Err(e);
        }
    };
    println!("Mesh is up. Keep this running; press Ctrl-C to stop.");

    let result = tokio::select! {
        () = towonel_common::shutdown::shutdown_signal() => Ok(()),
        reason = node.stopped() => match reason {
            Some(Stopped::Revoked) => Err(anyhow::anyhow!("this device was removed from the mesh")),
            Some(Stopped::KeyExpired) => Err(anyhow::anyhow!(
                "this device's key expired; run `towonel mesh up` to renew it"
            )),
            None => Ok(()),
        },
    };
    drop(exit_setup);
    cancel.cancel();
    node.shutdown().await;
    if let Some(tun) = tun {
        drop(tun.await);
    }
    match api.await {
        Ok(Err(e)) => eprintln!("local api: {e:#}"),
        Err(e) => eprintln!("local api task: {e}"),
        Ok(Ok(())) => {}
    }
    result
}

type ExitGuard = Option<Box<dyn Send>>;

/// Returns what undoes the host changes on drop.
#[cfg(target_os = "linux")]
async fn setup_exit(
    node: &MeshNode,
    hub_url: &str,
    exit: &Exit,
    routed: bool,
) -> anyhow::Result<ExitGuard> {
    use towonel_mesh::exit::{ExitNat, ExitRoutes};

    let this = node.netmap().borrow().this_device.clone();
    if !exit.advertise
        && this.exit_node_advertised
        && let Err(e) = node.advertise_exit_node(false).await
    {
        eprintln!("could not stop offering this device as an exit node: {e:#}");
    }
    if (exit.advertise || exit.via.is_some()) && !routed {
        bail!("exit nodes need the TUN device: run as root or with CAP_NET_ADMIN");
    }
    if exit.advertise {
        let nat = ExitNat::install()?;
        node.advertise_exit_node(true).await?;
        if this.exit_node_approved {
            println!("Peers can send their internet traffic through this device.");
        } else {
            println!(
                "Offering to route internet traffic; a tenant member must approve {} as an exit node.",
                this.name
            );
        }
        return Ok(Some(Box::new(nat)));
    }
    let Some(via) = &exit.via else {
        return Ok(None);
    };
    node.set_exit_node(Some(via))?;
    let relay_url = node.netmap().borrow().relay_url.clone();
    let mut bypass = Vec::new();
    for url in std::iter::once(hub_url).chain(relay_url.as_deref()) {
        bypass.extend(resolve_url(url).await?);
    }
    let exit_routes = ExitRoutes::install(&node.transport_ports(), &bypass)?;
    println!("Internet traffic goes through {via}.");
    Ok(Some(Box::new(exit_routes)))
}

#[cfg(not(target_os = "linux"))]
async fn setup_exit(
    _node: &MeshNode,
    _hub_url: &str,
    exit: &Exit,
    _routed: bool,
) -> anyhow::Result<ExitGuard> {
    if exit.advertise || exit.via.is_some() {
        bail!("exit nodes are only supported on Linux");
    }
    Ok(None)
}

#[cfg(target_os = "linux")]
async fn resolve_url(url: &str) -> anyhow::Result<Vec<std::net::IpAddr>> {
    let parsed = url::Url::parse(url).with_context(|| format!("invalid URL {url}"))?;
    let host = parsed
        .host_str()
        .with_context(|| format!("{url} has no host"))?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs = tokio::net::lookup_host((host.trim_matches(['[', ']']), port))
        .await
        .with_context(|| format!("cannot resolve {host}"))?;
    Ok(addrs.map(|a| a.ip()).collect())
}

/// Split DNS for the mesh domain through systemd-resolved; the settings go
/// away with the interface.
fn configure_dns(domain: &str) {
    let dev = towonel_mesh::tun::DEVICE_NAME;
    let resolver = towonel_mesh::dns::RESOLVER.to_string();
    let routing_domain = format!("~{domain}");
    let ok = [
        vec!["dns", dev, resolver.as_str()],
        vec!["domain", dev, routing_domain.as_str()],
    ]
    .iter()
    .all(|args| {
        std::process::Command::new("resolvectl")
            .args(args)
            .status()
            .is_ok_and(|s| s.success())
    });
    if ok {
        println!("Mesh names resolve as <device>.{domain}.");
    } else {
        println!(
            "Could not set up DNS for {domain} (no systemd-resolved?). Point {domain} at {resolver} \
             to use device names."
        );
    }
}

/// Returns the hub URL to run against.
async fn enroll_if_needed(
    state: &StateDir,
    hub_url: Option<String>,
    auth_key: Option<String>,
    name: Option<String>,
) -> anyhow::Result<String> {
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
                return Ok(hub_url);
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
    Ok(hub_url)
}

pub async fn cmd_nc(state_dir: Option<PathBuf>, peer: String, port: u16) -> anyhow::Result<()> {
    let state = open_state(state_dir)?;
    let stream = local::dial(state.path(), &peer, port).await?;
    let (mut read, mut write) = stream.into_split();
    let upstream = async {
        let res = tokio::io::copy(&mut tokio::io::stdin(), &mut write).await;
        drop(write.shutdown().await);
        res
    };
    let mut stdout = tokio::io::stdout();
    let downstream = tokio::io::copy(&mut read, &mut stdout);
    let (up, down) = tokio::join!(upstream, downstream);
    // The reader going away (`| head`) is a normal end, not an error.
    let broken_pipe = |e: &std::io::Error| e.kind() == std::io::ErrorKind::BrokenPipe;
    up.or_else(|e| if broken_pipe(&e) { Ok(0) } else { Err(e) })?;
    down.or_else(|e| if broken_pipe(&e) { Ok(0) } else { Err(e) })?;
    Ok(())
}

pub async fn cmd_connect(
    state_dir: Option<PathBuf>,
    target: String,
    local: Option<String>,
) -> anyhow::Result<()> {
    let state = open_state(state_dir)?;
    let (peer, port) = target
        .rsplit_once(':')
        .and_then(|(p, port)| Some((p.to_string(), port.parse::<u16>().ok()?)))
        .context("expected <peer>:<port>, e.g. nas:22")?;
    let local = local.unwrap_or_else(|| format!("127.0.0.1:{port}"));
    let listener = tokio::net::TcpListener::bind(&local)
        .await
        .with_context(|| {
            format!(
                "cannot listen on {local}; pick another local port with --local 127.0.0.1:<port>"
            )
        })?;
    // Fail now rather than on the first connection if the daemon is down.
    local::status(state.path()).await?;
    println!("Forwarding {local} to {peer}:{port}. Press Ctrl-C to stop.");
    let state_dir = state.path().to_path_buf();
    loop {
        let (tcp, _) = tokio::select! {
            () = towonel_common::shutdown::shutdown_signal() => return Ok(()),
            accepted = listener.accept() => accepted?,
        };
        let (state_dir, peer) = (state_dir.clone(), peer.clone());
        tokio::spawn(async move {
            match local::dial(&state_dir, &peer, port).await {
                Ok(mut mesh) => {
                    let mut tcp = tcp;
                    drop(tokio::io::copy_bidirectional(&mut tcp, &mut mesh).await);
                }
                Err(e) => eprintln!("{peer}:{port}: {e:#}"),
            }
        });
    }
}

pub async fn cmd_status(state_dir: Option<PathBuf>, watch: bool, json: bool) -> anyhow::Result<()> {
    let state = open_state(state_dir)?;
    let enrollment = state
        .load_enrollment()?
        .context("this device is not in a mesh yet; run `towonel mesh up`")?;
    let client = MeshClient::new(&enrollment.hub_url, state.device_key()?)?;

    if !watch {
        let netmap = client.netmap().await.map_err(explain)?;
        if json {
            return print_netmap(&netmap, true, None);
        }
        let paths = local::status(state.path()).await.ok();
        return print_netmap(&netmap, false, paths.as_deref());
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
                        print_netmap(&netmap, json, None)?;
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
            Err(e) if hub_code(&e) == Some("not_found") => {
                bail!("the request was denied or has expired; run `towonel mesh up` again")
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
    #[tabled(rename = "PATH")]
    path: String,
    #[tabled(rename = "EXIT NODE")]
    exit: String,
    #[tabled(rename = "SERVICES")]
    services: String,
}

/// `paths` comes from the local daemon; `None` when it isn't running.
fn print_netmap(
    netmap: &Netmap,
    json: bool,
    paths: Option<&[local::PeerLine]>,
) -> anyhow::Result<()> {
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
        path: paths
            .and_then(|ps| ps.iter().find(|p| p.ipv4 == d.ipv4))
            .map_or("-", |p| match (p.connected, p.relayed) {
                (true, Some(true)) => "relay",
                (true, _) => "direct",
                (false, _) => "idle",
            })
            .to_string(),
        exit: match (d.exit_node_advertised, d.exit_node_approved) {
            (true, true) => "yes",
            (true, false) => "awaiting approval",
            (false, _) => "-",
        }
        .to_string(),
        services: if d.services.is_empty() {
            "-".to_string()
        } else {
            d.services
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        },
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

pub fn ago(now_ms: u64, then_ms: i64) -> String {
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
