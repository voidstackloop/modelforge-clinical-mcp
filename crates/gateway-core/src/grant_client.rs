use async_trait::async_trait;
use reqwest::Client;

use crate::{ContextGrant, GatewayError, GrantResolver};

/// Resolves context grants by calling an existing `ModelForge` grant-issuing service over
/// HTTPS, rather than reading or storing grants itself — this repository deliberately contains
/// no grant-issuing logic of its own; grants are always short-lived handles minted elsewhere by
/// "`ModelForge`'s trusted UI" per the design doc, and this gateway only ever looks one up by
/// id.
pub struct HttpGrantResolver {
    client: Client,
    base_url: String,
}

impl HttpGrantResolver {
    /// `base_url` must be an `https://` origin; grant lookups are issued as
    /// `GET {base_url}/{grant_id}`.
    ///
    /// # Errors
    ///
    /// Returns an error if `base_url` is not a well-formed HTTPS URL or the HTTP client cannot
    /// be constructed.
    pub fn new(base_url: impl Into<String>) -> Result<Self, GatewayError> {
        let base_url = base_url.into();
        if !base_url.starts_with("https://") {
            return Err(GatewayError::AuthorizationUnavailable);
        }
        let client = Client::builder()
            .build()
            .map_err(|_| GatewayError::AuthorizationUnavailable)?;
        Ok(Self { client, base_url })
    }
}

#[async_trait]
impl GrantResolver for HttpGrantResolver {
    async fn resolve(&self, grant_id: &str) -> Result<ContextGrant, GatewayError> {
        if grant_id.is_empty() || grant_id.contains(['/', '?', '#']) {
            return Err(GatewayError::ContextGrantUnavailable);
        }
        let url = format!("{}/{grant_id}", self.base_url.trim_end_matches('/'));
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| GatewayError::ContextGrantUnavailable)?;
        if !response.status().is_success() {
            return Err(GatewayError::ContextGrantUnavailable);
        }
        response
            .json::<ContextGrant>()
            .await
            .map_err(|_| GatewayError::ContextGrantUnavailable)
    }
}
