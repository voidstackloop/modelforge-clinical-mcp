use std::{collections::BTreeSet, sync::Arc};

mod jwks;

pub use jwks::{JwksRefreshConfig, JwksRefreshError, start_jwks_authenticator};

use axum::{
    Json, Router,
    extract::{Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, decode_header};
use modelforge_clinical_mcp_core::{Gateway, SubjectContext};
use modelforge_clinical_mcp_server::{BootstrapServer, ClinicalServer};
use rmcp::transport::{
    StreamableHttpServerConfig, StreamableHttpService,
    streamable_http_server::session::local::LocalSessionManager,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_BEARER_TOKEN_BYTES: usize = 16 * 1024;
const MAX_ID_BYTES: usize = 200;
const MAX_ROLE_OR_SCOPE_COUNT: usize = 100;

#[derive(Clone, Debug)]
pub struct ManagedConfig {
    pub resource: String,
    pub protected_resource_metadata_uri: String,
    pub issuer: String,
    pub audience: String,
    pub required_scopes: BTreeSet<String>,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub max_request_body_bytes: usize,
}

impl ManagedConfig {
    /// Validates security-critical managed gateway configuration.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when an HTTPS identity, allowlist, or body limit is absent.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.resource.starts_with("https://") {
            return Err(ConfigError::HttpsResourceRequired);
        }
        if !is_safe_https_uri(&self.protected_resource_metadata_uri) {
            return Err(ConfigError::HttpsMetadataUriRequired);
        }
        if !self.issuer.starts_with("https://") {
            return Err(ConfigError::HttpsIssuerRequired);
        }
        if self.audience.is_empty() || self.audience.len() > 500 {
            return Err(ConfigError::InvalidAudience);
        }
        if self.allowed_hosts.is_empty() {
            return Err(ConfigError::AllowedHostsRequired);
        }
        if self.allowed_origins.is_empty() {
            return Err(ConfigError::AllowedOriginsRequired);
        }
        if self.required_scopes.is_empty()
            || self
                .required_scopes
                .iter()
                .any(|scope| !is_valid_scope(scope))
        {
            return Err(ConfigError::RequiredScopesInvalid);
        }
        if self.max_request_body_bytes == 0 || self.max_request_body_bytes > 1024 * 1024 {
            return Err(ConfigError::InvalidBodyLimit);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct JwtAuthenticator {
    keys: JwtKeys,
    validation: Validation,
}

#[derive(Clone)]
enum JwtKeys {
    Static(DecodingKey),
    Rotating(jwks::RotatingKeys),
}

impl JwtAuthenticator {
    /// Creates a strict RS256 OIDC access-token verifier.
    ///
    /// # Errors
    ///
    /// Returns an authentication error when the RSA public key cannot be decoded.
    pub fn from_rsa_pem(
        issuer: &str,
        audience: &str,
        public_key_pem: &[u8],
    ) -> Result<Self, AuthError> {
        let key = DecodingKey::from_rsa_pem(public_key_pem).map_err(|_| AuthError::InvalidKey)?;
        Ok(Self {
            keys: JwtKeys::Static(key),
            validation: strict_validation(issuer, audience),
        })
    }

    /// Creates a strict RS256 verifier from a bounded JWKS document.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, empty, oversized, duplicate, non-RSA, non-signing, or
    /// non-RS256 key sets and for invalid stale-key limits.
    pub fn from_jwks_json(
        issuer: &str,
        audience: &str,
        jwks_json: &[u8],
        max_stale: std::time::Duration,
    ) -> Result<Self, JwksRefreshError> {
        let loaded_at = jwks::epoch_seconds()?;
        Self::from_jwks_json_at(issuer, audience, jwks_json, max_stale, loaded_at)
    }

    pub(crate) fn from_jwks_json_at(
        issuer: &str,
        audience: &str,
        jwks_json: &[u8],
        max_stale: std::time::Duration,
        loaded_at_epoch_seconds: u64,
    ) -> Result<Self, JwksRefreshError> {
        let keys = jwks::RotatingKeys::new(jwks_json, loaded_at_epoch_seconds, max_stale)?;
        Ok(Self {
            keys: JwtKeys::Rotating(keys),
            validation: strict_validation(issuer, audience),
        })
    }

    /// Atomically replaces the current JWKS after fully validating its contents.
    ///
    /// Invalid updates leave the last known-good signing keys untouched.
    ///
    /// # Errors
    ///
    /// Returns an error when this verifier uses a static key or the replacement is invalid.
    pub fn replace_jwks(&self, jwks_json: &[u8]) -> Result<(), JwksRefreshError> {
        self.replace_jwks_at(jwks_json, jwks::epoch_seconds()?)
    }

    pub(crate) fn replace_jwks_at(
        &self,
        jwks_json: &[u8],
        loaded_at_epoch_seconds: u64,
    ) -> Result<(), JwksRefreshError> {
        match &self.keys {
            JwtKeys::Rotating(keys) => keys.replace(jwks_json, loaded_at_epoch_seconds),
            JwtKeys::Static(_) => Err(JwksRefreshError::InvalidConfig),
        }
    }

    /// Authenticates one bearer token without retaining the token or raw claims.
    ///
    /// # Errors
    ///
    /// Returns a generic authentication error for malformed, invalid, expired, or incomplete tokens.
    pub fn authenticate_header(
        &self,
        authorization: Option<&HeaderValue>,
    ) -> Result<SubjectContext, AuthError> {
        let value = authorization
            .and_then(|header| header.to_str().ok())
            .ok_or(AuthError::Unauthorized)?;
        let token = value
            .strip_prefix("Bearer ")
            .ok_or(AuthError::Unauthorized)?;
        if token.is_empty()
            || token.len() > MAX_BEARER_TOKEN_BYTES
            || token.contains(char::is_whitespace)
        {
            return Err(AuthError::Unauthorized);
        }
        let now = jwks::epoch_seconds().map_err(|_| AuthError::Unauthorized)?;
        self.authenticate_token_at(token, now)
    }

    fn authenticate_token_at(
        &self,
        token: &str,
        now_epoch_seconds: u64,
    ) -> Result<SubjectContext, AuthError> {
        let header = decode_header(token).map_err(|_| AuthError::Unauthorized)?;
        validate_header(&header)?;
        let key = match &self.keys {
            JwtKeys::Static(key) => key.clone(),
            JwtKeys::Rotating(keys) => {
                let key_id = header.kid.as_deref().ok_or(AuthError::Unauthorized)?;
                validate_key_id(key_id)?;
                keys.key(key_id, now_epoch_seconds)
                    .map_err(|_| AuthError::Unauthorized)?
            }
        };
        let claims = decode::<AccessTokenClaims>(token, &key, &self.validation)
            .map_err(|_| AuthError::Unauthorized)?
            .claims;
        claims.try_into()
    }
}

fn strict_validation(issuer: &str, audience: &str) -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 30;
    validation.reject_tokens_expiring_in_less_than = 15;
    validation
}

fn validate_header(header: &Header) -> Result<(), AuthError> {
    if header.alg != Algorithm::RS256
        || header
            .typ
            .as_deref()
            .is_some_and(|value| value != "JWT" && value != "at+jwt")
        || header.cty.is_some()
        || header.jku.is_some()
        || header.jwk.is_some()
        || header.x5u.is_some()
        || header.x5c.is_some()
        || header.crit.is_some()
        || header.enc.is_some()
        || header.zip.is_some()
    {
        return Err(AuthError::Unauthorized);
    }
    Ok(())
}

fn validate_key_id(key_id: &str) -> Result<(), AuthError> {
    if key_id.is_empty() || key_id.len() > MAX_ID_BYTES || key_id.chars().any(char::is_control) {
        return Err(AuthError::Unauthorized);
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct AccessTokenClaims {
    sub: String,
    #[serde(alias = "org")]
    organization_id: String,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    acr: String,
}

impl TryFrom<AccessTokenClaims> for SubjectContext {
    type Error = AuthError;

    fn try_from(claims: AccessTokenClaims) -> Result<Self, Self::Error> {
        let client_id = claims
            .azp
            .or(claims.client_id)
            .ok_or(AuthError::Unauthorized)?;
        validate_id(&claims.sub)?;
        validate_id(&client_id)?;
        validate_id(&claims.organization_id)?;
        let roles = bounded_values(claims.roles)?;
        let scopes = bounded_scopes(claims.scope.split_ascii_whitespace().map(str::to_owned))?;
        if claims.acr.len() > MAX_ID_BYTES {
            return Err(AuthError::Unauthorized);
        }
        Ok(Self {
            subject_id: claims.sub,
            client_id,
            organization_id: claims.organization_id,
            roles,
            scopes,
            authentication_strength: claims.acr,
        })
    }
}

fn validate_id(value: &str) -> Result<(), AuthError> {
    if value.is_empty() || value.len() > MAX_ID_BYTES || value.chars().any(char::is_control) {
        return Err(AuthError::Unauthorized);
    }
    Ok(())
}

fn bounded_values(values: impl IntoIterator<Item = String>) -> Result<BTreeSet<String>, AuthError> {
    let values = values.into_iter().collect::<BTreeSet<_>>();
    if values.len() > MAX_ROLE_OR_SCOPE_COUNT
        || values
            .iter()
            .any(|value| value.is_empty() || value.len() > MAX_ID_BYTES)
    {
        return Err(AuthError::Unauthorized);
    }
    Ok(values)
}

fn bounded_scopes(values: impl IntoIterator<Item = String>) -> Result<BTreeSet<String>, AuthError> {
    let values = values.into_iter().collect::<BTreeSet<_>>();
    if values.len() > MAX_ROLE_OR_SCOPE_COUNT || values.iter().any(|scope| !is_valid_scope(scope)) {
        return Err(AuthError::Unauthorized);
    }
    Ok(values)
}

fn is_valid_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= MAX_ID_BYTES
        && scope.bytes().all(|byte| {
            byte == b'!' || (b'#'..=b'[').contains(&byte) || (b']'..=b'~').contains(&byte)
        })
}

#[derive(Clone)]
struct HttpState {
    auth: JwtAuthenticator,
    metadata: ProtectedResourceMetadata,
    metadata_uri: String,
    required_scopes: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ProtectedResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
    bearer_methods_supported: Vec<&'static str>,
    scopes_supported: Vec<String>,
}

/// Builds the managed router with public metadata and an authenticated MCP endpoint.
///
/// # Errors
///
/// Returns a configuration error before constructing a listener when security settings are invalid.
pub fn build_router(config: ManagedConfig, auth: JwtAuthenticator) -> Result<Router, ConfigError> {
    config.validate()?;
    let state = Arc::new(HttpState {
        auth,
        metadata: ProtectedResourceMetadata {
            resource: config.resource,
            authorization_servers: vec![config.issuer],
            bearer_methods_supported: vec!["header"],
            scopes_supported: config.required_scopes.iter().cloned().collect(),
        },
        metadata_uri: config.protected_resource_metadata_uri,
        required_scopes: config.required_scopes,
    });
    let mcp_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_sse_keep_alive(None)
        .with_allowed_hosts(config.allowed_hosts)
        .with_allowed_origins(config.allowed_origins)
        .with_max_request_body_bytes(config.max_request_body_bytes)
        .with_stateless_protocol_metadata_required(true);
    let mcp: StreamableHttpService<BootstrapServer, LocalSessionManager> =
        StreamableHttpService::new(|| Ok(BootstrapServer), Arc::default(), mcp_config);
    let protected = Router::new()
        .nest_service("/mcp", mcp)
        .layer(middleware::from_fn_with_state(state.clone(), authorize));
    let public = Router::new()
        .route("/healthz", get(health))
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .with_state(state);
    Ok(public.merge(protected))
}

/// Builds the managed router with the authorized clinical tool set enabled.
///
/// The caller must supply a gateway composed from trusted tenant policy, grant-resolution, audit,
/// and domain-service ports. The bootstrap router remains the default for the executable until
/// that composition is explicitly configured.
///
/// # Errors
///
/// Returns a configuration error before constructing a listener when security settings are invalid.
pub fn build_clinical_router(
    config: ManagedConfig,
    auth: JwtAuthenticator,
    gateway: Arc<Gateway>,
) -> Result<Router, ConfigError> {
    config.validate()?;
    let state = Arc::new(HttpState {
        auth,
        metadata: ProtectedResourceMetadata {
            resource: config.resource,
            authorization_servers: vec![config.issuer],
            bearer_methods_supported: vec!["header"],
            scopes_supported: config.required_scopes.iter().cloned().collect(),
        },
        metadata_uri: config.protected_resource_metadata_uri,
        required_scopes: config.required_scopes,
    });
    let mcp_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_sse_keep_alive(None)
        .with_allowed_hosts(config.allowed_hosts)
        .with_allowed_origins(config.allowed_origins)
        .with_max_request_body_bytes(config.max_request_body_bytes)
        .with_stateless_protocol_metadata_required(true);
    let mcp: StreamableHttpService<ClinicalServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(ClinicalServer::new(gateway.clone())),
            Arc::default(),
            mcp_config,
        );
    let protected = Router::new()
        .nest_service("/mcp", mcp)
        .layer(middleware::from_fn_with_state(state.clone(), authorize));
    let public = Router::new()
        .route("/healthz", get(health))
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .with_state(state);
    Ok(public.merge(protected))
}

async fn health() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn protected_resource_metadata(
    State(state): State<Arc<HttpState>>,
) -> Json<ProtectedResourceMetadata> {
    Json(state.metadata.clone())
}

async fn authorize(
    State(state): State<Arc<HttpState>>,
    mut request: Request,
    next: Next,
) -> Response {
    match state
        .auth
        .authenticate_header(request.headers().get(header::AUTHORIZATION))
    {
        Ok(subject) => {
            if !state.required_scopes.is_subset(&subject.scopes) {
                return insufficient_scope_response(&state);
            }
            request.extensions_mut().insert(subject);
            next.run(request).await
        }
        Err(_) => unauthorized_response(&state),
    }
}

fn unauthorized_response(state: &HttpState) -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error":"unauthorized"})),
    )
        .into_response();
    let challenge = format!("Bearer resource_metadata=\"{}\"", state.metadata_uri);
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

fn insufficient_scope_response(state: &HttpState) -> Response {
    let mut response = (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({"error":"insufficient_scope"})),
    )
        .into_response();
    let scope = state
        .required_scopes
        .iter()
        .cloned()
        .collect::<Vec<_>>()
        .join(" ");
    let challenge = format!(
        "Bearer error=\"insufficient_scope\", scope=\"{scope}\", resource_metadata=\"{}\"",
        state.metadata_uri
    );
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

fn is_safe_https_uri(value: &str) -> bool {
    value.starts_with("https://")
        && value.len() <= 2_000
        && !value.contains('"')
        && !value.chars().any(char::is_control)
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AuthError {
    #[error("access token verification key is invalid")]
    InvalidKey,
    #[error("request is unauthorized")]
    Unauthorized,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ConfigError {
    #[error("managed resource URI must use HTTPS")]
    HttpsResourceRequired,
    #[error("protected-resource metadata URI must be a safe HTTPS URI")]
    HttpsMetadataUriRequired,
    #[error("OIDC issuer URI must use HTTPS")]
    HttpsIssuerRequired,
    #[error("OIDC audience is invalid")]
    InvalidAudience,
    #[error("at least one allowed Host is required")]
    AllowedHostsRequired,
    #[error("at least one allowed Origin is required")]
    AllowedOriginsRequired,
    #[error("at least one bounded required scope is required")]
    RequiredScopesInvalid,
    #[error("request body limit must be between 1 byte and 1 MiB")]
    InvalidBodyLimit,
}
