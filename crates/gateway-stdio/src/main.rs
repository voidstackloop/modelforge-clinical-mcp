use modelforge_clinical_mcp_server::{
    BootstrapServer, ClinicalPortsConfig, ClinicalServer, build_clinical_gateway,
};
use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_target(false)
        .init();

    if let Some(clinical_config) = ClinicalPortsConfig::from_env()? {
        let gateway = build_clinical_gateway(clinical_config).await?;
        tracing::info!("clinical gateway enabled");
        let service = ClinicalServer::new(gateway).serve(stdio()).await?;
        service.waiting().await?;
    } else {
        tracing::info!("clinical gateway not configured; serving bootstrap capabilities only");
        let service = BootstrapServer.serve(stdio()).await?;
        service.waiting().await?;
    }
    Ok(())
}
