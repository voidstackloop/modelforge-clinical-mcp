use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{
    DecodingKey,
    jwk::{AlgorithmParameters, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse},
};
use reqwest::{Client, redirect::Policy};
use thiserror::Error;
use tokio::{task::JoinHandle, time::MissedTickBehavior};

use crate::JwtAuthenticator;

const MAX_JWKS_BYTES: usize = 256 * 1024;
const MAX_JWKS_KEYS: usize = 64;
const MAX_KEY_ID_BYTES: usize = 200;
const MIN_REFRESH_SECONDS: u64 = 30;
const MAX_REFRESH_SECONDS: u64 = 3_600;
const MAX_STALE_SECONDS: u64 = 86_400;

#[derive(Clone, Debug)]
pub struct JwksRefreshConfig {
    pub uri: String,
    pub refresh_interval: Duration,
    pub max_stale: Duration,
}

impl JwksRefreshConfig {
    /// Validates the remote signing-key refresh policy.
    ///
    /// # Errors
    ///
    /// Rejects non-HTTPS endpoints, credentials in URLs, fragments, and unsafe timing bounds.
    pub fn validate(&self) -> Result<(), JwksRefreshError> {
        let uri = reqwest::Url::parse(&self.uri).map_err(|_| JwksRefreshError::InvalidConfig)?;
        let refresh_seconds = self.refresh_interval.as_secs();
        let stale_seconds = self.max_stale.as_secs();
        if uri.scheme() != "https"
            || uri.host_str().is_none()
            || !uri.username().is_empty()
            || uri.password().is_some()
            || uri.fragment().is_some()
            || self.uri.len() > 2_000
            || !(MIN_REFRESH_SECONDS..=MAX_REFRESH_SECONDS).contains(&refresh_seconds)
            || stale_seconds < refresh_seconds.saturating_mul(2)
            || stale_seconds > MAX_STALE_SECONDS
        {
            return Err(JwksRefreshError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct RotatingKeys {
    current: Arc<RwLock<KeySetSnapshot>>,
    max_stale_seconds: u64,
}

impl RotatingKeys {
    pub(crate) fn new(
        jwks_json: &[u8],
        loaded_at_epoch_seconds: u64,
        max_stale: Duration,
    ) -> Result<Self, JwksRefreshError> {
        let snapshot = KeySetSnapshot::parse(jwks_json, loaded_at_epoch_seconds)?;
        if max_stale.as_secs() == 0 || max_stale.as_secs() > MAX_STALE_SECONDS {
            return Err(JwksRefreshError::InvalidConfig);
        }
        Ok(Self {
            current: Arc::new(RwLock::new(snapshot)),
            max_stale_seconds: max_stale.as_secs(),
        })
    }

    pub(crate) fn replace(
        &self,
        jwks_json: &[u8],
        loaded_at_epoch_seconds: u64,
    ) -> Result<(), JwksRefreshError> {
        let replacement = KeySetSnapshot::parse(jwks_json, loaded_at_epoch_seconds)?;
        let mut current = self
            .current
            .write()
            .map_err(|_| JwksRefreshError::KeySetUnavailable)?;
        *current = replacement;
        Ok(())
    }

    pub(crate) fn key(
        &self,
        key_id: &str,
        now_epoch_seconds: u64,
    ) -> Result<DecodingKey, JwksRefreshError> {
        let current = self
            .current
            .read()
            .map_err(|_| JwksRefreshError::KeySetUnavailable)?;
        if now_epoch_seconds
            > current
                .loaded_at_epoch_seconds
                .saturating_add(self.max_stale_seconds)
        {
            return Err(JwksRefreshError::KeySetStale);
        }
        current
            .keys
            .get(key_id)
            .cloned()
            .ok_or(JwksRefreshError::UnknownKey)
    }
}

struct KeySetSnapshot {
    keys: BTreeMap<String, DecodingKey>,
    loaded_at_epoch_seconds: u64,
}

impl KeySetSnapshot {
    fn parse(jwks_json: &[u8], loaded_at_epoch_seconds: u64) -> Result<Self, JwksRefreshError> {
        if jwks_json.is_empty() || jwks_json.len() > MAX_JWKS_BYTES {
            return Err(JwksRefreshError::InvalidKeySet);
        }
        let jwks: JwkSet =
            serde_json::from_slice(jwks_json).map_err(|_| JwksRefreshError::InvalidKeySet)?;
        if jwks.keys.is_empty() || jwks.keys.len() > MAX_JWKS_KEYS {
            return Err(JwksRefreshError::InvalidKeySet);
        }
        let mut keys = BTreeMap::new();
        for jwk in &jwks.keys {
            let key_id = jwk
                .common
                .key_id
                .as_deref()
                .ok_or(JwksRefreshError::InvalidKeySet)?;
            if key_id.is_empty()
                || key_id.len() > MAX_KEY_ID_BYTES
                || key_id.chars().any(char::is_control)
                || jwk.common.key_algorithm != Some(KeyAlgorithm::RS256)
                || !matches!(&jwk.algorithm, AlgorithmParameters::RSA(_))
                || !matches!(
                    jwk.common.public_key_use.as_ref(),
                    None | Some(PublicKeyUse::Signature)
                )
                || !valid_key_operations(jwk.common.key_operations.as_deref())
            {
                return Err(JwksRefreshError::InvalidKeySet);
            }
            let key = DecodingKey::from_jwk(jwk).map_err(|_| JwksRefreshError::InvalidKeySet)?;
            if keys.insert(key_id.to_owned(), key).is_some() {
                return Err(JwksRefreshError::InvalidKeySet);
            }
        }
        Ok(Self {
            keys,
            loaded_at_epoch_seconds,
        })
    }
}

fn valid_key_operations(operations: Option<&[KeyOperations]>) -> bool {
    operations.is_none_or(|operations| {
        operations.len() == 1 && operations.first() == Some(&KeyOperations::Verify)
    })
}

/// Fetches the initial JWKS and starts a bounded background refresh task.
///
/// The returned task must be retained for the lifetime of the server. Invalid refreshes never
/// replace the last known-good set; authentication fails closed when that set exceeds `max_stale`.
///
/// # Errors
///
/// Returns an error when configuration, HTTPS client construction, initial fetch, or parsing fails.
pub async fn start_jwks_authenticator(
    issuer: &str,
    audience: &str,
    config: JwksRefreshConfig,
) -> Result<(JwtAuthenticator, JoinHandle<()>), JwksRefreshError> {
    config.validate()?;
    let client = Client::builder()
        .https_only(true)
        .redirect(Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(8))
        .user_agent("modelforge-clinical-mcp/0.1")
        .build()
        .map_err(|_| JwksRefreshError::ClientUnavailable)?;
    let initial = fetch_jwks(&client, &config.uri).await?;
    let now = epoch_seconds()?;
    let authenticator =
        JwtAuthenticator::from_jwks_json_at(issuer, audience, &initial, config.max_stale, now)?;
    let refresh_authenticator = authenticator.clone();
    let task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(config.refresh_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            let refresh = async {
                let bytes = fetch_jwks(&client, &config.uri).await?;
                let loaded_at = epoch_seconds()?;
                refresh_authenticator.replace_jwks_at(&bytes, loaded_at)
            }
            .await;
            if let Err(error) = refresh {
                tracing::warn!(error_class = error.error_class(), "JWKS refresh failed");
            }
        }
    });
    Ok((authenticator, task))
}

async fn fetch_jwks(client: &Client, uri: &str) -> Result<Vec<u8>, JwksRefreshError> {
    let mut response = client
        .get(uri)
        .header(
            reqwest::header::ACCEPT,
            "application/jwk-set+json, application/json",
        )
        .send()
        .await
        .map_err(|_| JwksRefreshError::FetchFailed)?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > MAX_JWKS_BYTES as u64)
    {
        return Err(JwksRefreshError::FetchFailed);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| JwksRefreshError::FetchFailed)?
    {
        if body.len().saturating_add(chunk.len()) > MAX_JWKS_BYTES {
            return Err(JwksRefreshError::FetchFailed);
        }
        body.extend_from_slice(&chunk);
    }
    if body.is_empty() {
        return Err(JwksRefreshError::FetchFailed);
    }
    Ok(body)
}

pub(crate) fn epoch_seconds() -> Result<u64, JwksRefreshError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| JwksRefreshError::ClockUnavailable)
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum JwksRefreshError {
    #[error("JWKS refresh configuration is invalid")]
    InvalidConfig,
    #[error("JWKS HTTPS client is unavailable")]
    ClientUnavailable,
    #[error("JWKS fetch failed")]
    FetchFailed,
    #[error("JWKS document is invalid")]
    InvalidKeySet,
    #[error("JWKS key set is unavailable")]
    KeySetUnavailable,
    #[error("JWKS key set is stale")]
    KeySetStale,
    #[error("JWT signing key is unknown")]
    UnknownKey,
    #[error("system clock is unavailable")]
    ClockUnavailable,
}

impl JwksRefreshError {
    const fn error_class(self) -> &'static str {
        match self {
            Self::InvalidConfig => "invalid_config",
            Self::ClientUnavailable => "client_unavailable",
            Self::FetchFailed => "fetch_failed",
            Self::InvalidKeySet => "invalid_key_set",
            Self::KeySetUnavailable => "key_set_unavailable",
            Self::KeySetStale => "key_set_stale",
            Self::UnknownKey => "unknown_key",
            Self::ClockUnavailable => "clock_unavailable",
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "cryptographic test fixtures require immediate contextual failures"
    )]

    use jsonwebtoken::{
        Algorithm, EncodingKey,
        jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse},
    };
    use rand::rngs::OsRng;
    use rsa::{
        RsaPrivateKey,
        pkcs8::{EncodePrivateKey, LineEnding},
    };

    use super::*;

    fn test_jwks() -> Vec<u8> {
        let private = RsaPrivateKey::new(&mut OsRng, 2_048).expect("generate RSA test key");
        let pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode private key");
        let encoding = EncodingKey::from_rsa_pem(pem.as_bytes()).expect("decode private key");
        let mut jwk = Jwk::from_encoding_key(&encoding, Algorithm::RS256).expect("create JWK");
        jwk.common.key_id = Some("key-1".into());
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        jwk.common.key_operations = Some(vec![KeyOperations::Verify]);
        serde_json::to_vec(&JwkSet { keys: vec![jwk] }).expect("serialize JWKS")
    }

    #[test]
    fn stale_key_set_fails_closed() {
        let keys = RotatingKeys::new(&test_jwks(), 100, Duration::from_secs(10))
            .expect("construct rotating keys");
        assert!(keys.key("key-1", 110).is_ok());
        assert_eq!(
            keys.key("key-1", 111).err(),
            Some(JwksRefreshError::KeySetStale)
        );
    }

    #[test]
    fn refresh_configuration_rejects_redirect_prone_or_unsafe_urls() {
        let config = JwksRefreshConfig {
            uri: "http://identity.test/jwks".into(),
            refresh_interval: Duration::from_secs(300),
            max_stale: Duration::from_secs(3_600),
        };
        assert_eq!(config.validate(), Err(JwksRefreshError::InvalidConfig));
    }
}
