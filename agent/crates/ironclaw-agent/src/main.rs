pub mod agent;

use ironclaw_core::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize standard env_logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!("Starting IRONCLAW Endpoint Agent...");

    // Load configuration
    let config = Config::from_env();
    log::info!("Configuration loaded: {:?}", config);

    // Initialize agent and run it
    let mut app = agent::AgentApp::new(config).await?;
    app.run().await?;

    Ok(())
}
