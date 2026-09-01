use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration};

use modelforge_clinical_mcp_http::{
    JwksRefreshConfig, JwtAuthenticator, ManagedConfig, build_clinical_router, build_router,
    start_jwks_authenticator,
};
use modelforge_clinical_mcp_server::{ClinicalPortsConfig, build_clinical_gateway};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_target(false)
        .init();

    let bind: SocketAddr = required_env("MODELFORGE_MCP_BIND")?.parse()?;
    let resource = required_env("MODELFORGE_MCP_RESOURCE")?;
    let issuer = required_env("MODELFORGE_MCP_OIDC_ISSUER")?;
    let audience = required_env("MODELFORGE_MCP_OIDC_AUDIENCE")?;
    let config = ManagedConfig {
        resource,
        protected_resource_metadata_uri: required_env(
            "MODELFORGE_MCP_PROTECTED_RESOURCE_METADATA_URI",
        )?,
        issuer: issuer.clone(),
        audience: audience.clone(),
        required_scopes: csv_env("MODELFORGE_MCP_REQUIRED_SCOPES")?
            .into_iter()
            .collect::<BTreeSet<_>>(),
        allowed_hosts: csv_env("MODELFORGE_MCP_ALLOWED_HOSTS")?,
        allowed_origins: csv_env("MODELFORGE_MCP_ALLOWED_ORIGINS")?,
        max_request_body_bytes: 256 * 1024,
    };
    let jwks_uri = std::env::var("MODELFORGE_MCP_OIDC_JWKS_URI").ok();
    let public_key_path = std::env::var("MODELFORGE_MCP_OIDC_PUBLIC_KEY_PEM").ok();
    let (authenticator, _jwks_refresh_task) = match (jwks_uri, public_key_path) {
        (Some(uri), None) => {
            let refresh_interval = Duration::from_secs(optional_env(
                "MODELFORGE_MCP_OIDC_JWKS_REFRESH_SECONDS",
                300_u64,
            )?);
            let max_stale = Duration::from_secs(optional_env(
                "MODELFORGE_MCP_OIDC_JWKS_MAX_STALE_SECONDS",
                3_600_u64,
            )?);
            let (authenticator, task) = start_jwks_authenticator(
                &issuer,
                &audience,
                JwksRefreshConfig {
                    uri,
                    refresh_interval,
                    max_stale,
                },
            )
            .await?;
            (authenticator, Some(task))
        }
        (None, Some(path)) => {
            let public_key = std::fs::read(PathBuf::from(path))?;
            (
                JwtAuthenticator::from_rsa_pem(&issuer, &audience, &public_key)?,
                None,
            )
        }
        _ => anyhow::bail!(
            "exactly one of MODELFORGE_MCP_OIDC_JWKS_URI or MODELFORGE_MCP_OIDC_PUBLIC_KEY_PEM must be set"
        ),
    };
    let router = if let Some(clinical_config) = ClinicalPortsConfig::from_env()? {
        let gateway = build_clinical_gateway(clinical_config).await?;
        tracing::info!("clinical gateway enabled");
        build_clinical_router(config, authenticator, gateway)?
    } else {
        tracing::info!("clinical gateway not configured; serving bootstrap capabilities only");
        build_router(config, authenticator)?
    };
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(address = %listener.local_addr()?, "managed MCP gateway listening");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn required_env(name: &str) -> anyhow::Result<String> {
    std::env::var(name)
        .map_err(|_| anyhow::anyhow!("required environment variable {name} is missing"))
}

fn csv_env(name: &str) -> anyhow::Result<Vec<String>> {
    let values = required_env(name)?
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if values.is_empty() {
        anyhow::bail!("required environment variable {name} has no values");
    }
    Ok(values)
}

fn optional_env<T>(name: &str, default: T) -> anyhow::Result<T>
where
    T: FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    std::env::var(name).map_or(Ok(default), |value| {
        value
            .parse()
            .map_err(|error| anyhow::anyhow!("environment variable {name} is invalid: {error}"))
    })
}

async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_err() {
        tracing::error!("failed to install shutdown signal handler");
    }
}
