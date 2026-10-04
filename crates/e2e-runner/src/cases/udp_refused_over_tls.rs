use anyhow::{Result, ensure};

/// UDP services are not carried over a TLS session, so with the only agent on
/// TLS a datagram to the edge must go unanswered.
pub async fn run(edge_host: &str, udp_echo_port: u16) -> Result<()> {
    let unanswered = super::udp_echo::no_reply(edge_host, udp_echo_port).await?;
    ensure!(
        unanswered,
        "udp reply arrived although the agent is only reachable over TLS"
    );
    tracing::info!("udp_refused_over_tls: PASS");
    Ok(())
}
