use clap::Parser;

#[derive(Parser)]
#[command(
    name = "towonel-agent",
    about = "towonel agent -- runs in your network, tunnels traffic from edges. Services come from TOWONEL_AGENT_SERVICES; identity from TOWONEL_INVITE_TOKEN."
)]
struct Cli {
    #[command(flatten)]
    agent: towonel_agent::AgentArgs,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ring provider install only fails if another provider is already installed,
    // which is a programming error and should panic at startup.
    #[expect(
        clippy::expect_used,
        reason = "duplicate CryptoProvider install is a startup-time programmer error"
    )]
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install ring CryptoProvider");

    let _telemetry = towonel_common::telemetry::init("towonel-agent", env!("CARGO_PKG_VERSION"));

    Box::pin(towonel_agent::run(Cli::parse().agent)).await
}
