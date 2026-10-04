use std::time::{Duration, Instant};

use anyhow::{Result, bail, ensure};

/// Transport the agent's edge session is expected to be on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expected {
    Quic,
    Tls,
}

impl Expected {
    pub fn from_env(raw: &str) -> Result<Self> {
        match raw {
            "quic" => Ok(Self::Quic),
            "tls" => Ok(Self::Tls),
            other => bail!("E2E_EXPECT_TRANSPORT must be quic or tls, got {other:?}"),
        }
    }
}

/// Asserts which transport the agent's edge session is on, from its own metrics,
/// so a profile that claims to exercise TLS cannot silently pass over QUIC.
///
/// The `edge_path` series is only set on a path-change event for QUIC, so it can
/// read all zeros there; QUIC is therefore "a live session that is not on TLS".
pub async fn run(metrics_url: &str, expected: Expected, budget: Duration) -> Result<()> {
    let deadline = Instant::now() + budget;
    let mut seen = Observed::default();
    while Instant::now() < deadline {
        if let Ok(response) = reqwest::get(metrics_url).await
            && let Ok(body) = response.text().await
        {
            seen = Observed::from_metrics(&body);
            let settled = match expected {
                Expected::Tls => seen.path.is_some(),
                Expected::Quic => seen.live_session,
            };
            if settled {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    ensure!(
        seen.live_session,
        "agent has no live edge session after {budget:?}"
    );
    match expected {
        Expected::Tls => ensure!(
            seen.path.as_deref() == Some("tls"),
            "expected the TLS fallback, agent path is {:?}",
            seen.path
        ),
        Expected::Quic => ensure!(
            seen.path.as_deref() != Some("tls"),
            "expected QUIC, agent fell back to TLS"
        ),
    }
    tracing::info!(path = ?seen.path, "agent_transport: PASS");
    Ok(())
}

#[derive(Debug, Default)]
struct Observed {
    live_session: bool,
    path: Option<String>,
}

impl Observed {
    fn from_metrics(body: &str) -> Self {
        Self {
            live_session: body.lines().any(|line| {
                line.starts_with("towonel_agent_edge_session_state{") && line.ends_with(" 1")
            }),
            path: active_path(body),
        }
    }
}

/// The `path` label of the `towonel_agent_edge_path` series currently at 1.
fn active_path(metrics: &str) -> Option<String> {
    metrics
        .lines()
        .filter(|line| line.starts_with("towonel_agent_edge_path{") && line.ends_with(" 1"))
        .find_map(|line| {
            let rest = line.split_once("path=\"")?.1;
            Some(rest.split_once('"')?.0.to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_the_series_that_is_set() {
        let body = "\
# HELP towonel_agent_edge_path path
towonel_agent_edge_path{edge=\"abc\",path=\"direct\"} 0
towonel_agent_edge_path{edge=\"abc\",path=\"relay\"} 0
towonel_agent_edge_path{edge=\"abc\",path=\"tls\"} 1
";
        assert_eq!(active_path(body).as_deref(), Some("tls"));
    }

    #[test]
    fn no_session_means_no_active_path() {
        let body = "towonel_agent_edge_path{edge=\"abc\",path=\"tls\"} 0\n";
        assert_eq!(active_path(body), None);
        assert_eq!(active_path(""), None);
    }

    #[test]
    fn a_quic_session_can_be_live_with_no_path_series_set() {
        let body = "\
towonel_agent_edge_session_state{edge=\"abc\"} 1
towonel_agent_edge_path{edge=\"abc\",path=\"direct\"} 0
towonel_agent_edge_path{edge=\"abc\",path=\"tls\"} 0
";
        let seen = Observed::from_metrics(body);
        assert!(seen.live_session);
        assert_eq!(seen.path, None);
    }

    #[test]
    fn a_dropped_session_is_not_live() {
        let body = "towonel_agent_edge_session_state{edge=\"abc\"} 0\n";
        assert!(!Observed::from_metrics(body).live_session);
    }

    #[test]
    fn rejects_an_unknown_expectation() {
        Expected::from_env("udp").unwrap_err();
        assert_eq!(Expected::from_env("tls").unwrap(), Expected::Tls);
    }
}
