//! Exit-node host setup on Linux; undone on drop.

use std::net::IpAddr;
use std::process::Command;

use anyhow::{Context, bail};
use tracing::debug;

use crate::tun::DEVICE_NAME;

const FORWARDING: [&str; 2] = [
    "/proc/sys/net/ipv4/ip_forward",
    "/proc/sys/net/ipv6/conf/all/forwarding",
];
const NFT_TABLE: &str = "towonel";
const ROUTE_TABLE: &str = "5270";
/// Rule priorities: bypasses, then the main table minus its default route,
/// then the default route into the TUN.
const PRIO_BYPASS: &str = "5270";
const PRIO_MAIN: &str = "5271";
const PRIO_EXIT: &str = "5272";

/// Forwarding and masquerade on the exit.
pub struct ExitNat(());

impl ExitNat {
    /// Needs root or `CAP_NET_ADMIN` and the `nft` tool. Forwarding stays on
    /// after drop: other services on the host may rely on it.
    pub fn install() -> anyhow::Result<Self> {
        for path in FORWARDING {
            let on = std::fs::read_to_string(path).is_ok_and(|v| v.trim() == "1");
            if !on {
                std::fs::write(path, "1").with_context(|| format!("failed to enable {path}"))?;
            }
        }
        // Declaring the table first makes the delete succeed on a clean host.
        let rules = format!(
            "table inet {NFT_TABLE}
delete table inet {NFT_TABLE}
table inet {NFT_TABLE} {{
    chain forward {{
        type filter hook forward priority filter; policy accept;
        oifname \"{DEVICE_NAME}\" ct state established,related accept
        oifname \"{DEVICE_NAME}\" drop
    }}
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        iifname \"{DEVICE_NAME}\" oifname != \"{DEVICE_NAME}\" masquerade
    }}
}}
"
        );
        run_stdin("nft", &["-f", "-"], &rules).context("failed to install the NAT rules")?;
        Ok(Self(()))
    }
}

impl Drop for ExitNat {
    fn drop(&mut self) {
        if let Err(e) = run("nft", &["delete", "table", "inet", NFT_TABLE]) {
            debug!(error = %e, "could not remove the NAT rules");
        }
    }
}

/// Default route into the TUN. The mesh's own traffic keeps the main
/// table: iroh by source port, hub and relay by address.
pub struct ExitRoutes(());

impl ExitRoutes {
    pub fn install(ports: &[u16], bypass: &[IpAddr]) -> anyhow::Result<Self> {
        // Dropped on error, which clears the rules added so far.
        let routes = Self(());
        for family in ["-4", "-6"] {
            clear(family);
            run(
                "ip",
                &[
                    family,
                    "route",
                    "replace",
                    "default",
                    "dev",
                    DEVICE_NAME,
                    "table",
                    ROUTE_TABLE,
                ],
            )?;
            for port in ports {
                let port = port.to_string();
                rule(
                    family,
                    &[
                        PRIO_BYPASS,
                        "ipproto",
                        "udp",
                        "sport",
                        &port,
                        "lookup",
                        "main",
                    ],
                )?;
            }
            for ip in bypass {
                if (family == "-4") == ip.is_ipv4() {
                    let ip = ip.to_string();
                    rule(family, &[PRIO_BYPASS, "to", &ip, "lookup", "main"])?;
                }
            }
            rule(
                family,
                &[PRIO_MAIN, "lookup", "main", "suppress_prefixlength", "0"],
            )?;
            rule(family, &[PRIO_EXIT, "lookup", ROUTE_TABLE])?;
        }
        Ok(routes)
    }
}

impl Drop for ExitRoutes {
    fn drop(&mut self) {
        for family in ["-4", "-6"] {
            clear(family);
        }
    }
}

fn rule(family: &str, spec: &[&str]) -> anyhow::Result<()> {
    let mut args = vec![family, "rule", "add", "priority"];
    args.extend_from_slice(spec);
    run("ip", &args)
}

/// Also removes what a crashed run left behind.
fn clear(family: &str) {
    for prio in [PRIO_BYPASS, PRIO_MAIN, PRIO_EXIT] {
        // One rule per call; bounded in case `ip` misbehaves.
        for _ in 0..256 {
            if run("ip", &[family, "rule", "del", "priority", prio]).is_err() {
                break;
            }
        }
    }
    drop(run("ip", &[family, "route", "flush", "table", ROUTE_TABLE]));
}

fn run(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let out = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {program}"))?;
    if !out.status.success() {
        bail!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn run_stdin(program: &str, args: &[&str], input: &str) -> anyhow::Result<()> {
    use std::io::Write;
    let mut child = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run {program}"))?;
    child
        .stdin
        .take()
        .context("no stdin")?
        .write_all(input.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("{program}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}
