use std::collections::BTreeSet;

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::GatewayError;

/// What an approval ticket must attest to before a `RiskClass::ControlledWrite` operation may
/// execute, per the design doc: "single-use... bound to the subject, client, tool, normalized-
/// argument hash, grant, policy version, and expiry." `operation_digest` already folds in
/// subject, client, grant, and policy version, so binding to it plus the tool name covers the
/// full set without repeating each field separately.
pub struct ApprovalBinding<'a> {
    pub subject_id: &'a str,
    pub client_id: &'a str,
    pub tool_name: &'a str,
    pub operation_digest: &'a str,
}

/// Verifies and consumes approval tickets for `RiskClass::ControlledWrite` operations.
#[async_trait]
pub trait ApprovalVerifier: Send + Sync {
    /// Verifies `ticket` against `binding` and atomically marks it consumed so it cannot be
    /// replayed. `now_epoch_seconds` is caller-supplied (matching
    /// `ContextGrant::validate_binding` and the rest of the admission path) rather than read
    /// from the system clock internally, so expiry checks stay deterministic and testable.
    ///
    /// # Errors
    ///
    /// Returns [`GatewayError::ApprovalRequired`] for any invalid, expired, mismatched, or
    /// already-consumed ticket. Deliberately one error class for every rejection reason, so a
    /// caller cannot use the response to distinguish "wrong ticket" from "reused ticket" and
    /// narrow down a guess.
    async fn verify_and_consume(
        &self,
        ticket: &str,
        binding: &ApprovalBinding<'_>,
        now_epoch_seconds: u64,
    ) -> Result<(), GatewayError>;
}

#[derive(Serialize, Deserialize)]
struct ApprovalClaims {
    sub: String,
    azp: String,
    tool: String,
    digest: String,
    jti: String,
    exp: u64,
}

/// HMAC-signed (HS256), single-use approval tickets, backed by one server-held secret shared
/// with the signer. Matches the design doc's model where "the existing trusted `ModelForge`
/// UI/service boundary signs tickets" and this gateway only verifies them; `issue` is provided
/// so a deployment without a separate ticket-issuing service can still use this same scheme
/// end-to-end rather than needing to invent its own.
///
/// Single-use tracking is in-process only (a `BTreeSet` of consumed ticket IDs) — real, and
/// race-safe within one instance (`verify_and_consume` checks and inserts under one lock), but
/// not shared across replicas or durable across a restart. A deployment that needs either can
/// implement `ApprovalVerifier` against a shared store instead, since every caller depends on
/// the trait, not this type.
pub struct HmacApprovalVerifier {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    consumed: Mutex<BTreeSet<String>>,
}

impl HmacApprovalVerifier {
    #[must_use]
    pub fn new(secret: &[u8]) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            consumed: Mutex::new(BTreeSet::new()),
        }
    }

    /// Mints a signed, single-use ticket bound to `binding`, valid until
    /// `expires_at_epoch_seconds`.
    ///
    /// # Errors
    ///
    /// Returns [`GatewayError::ApprovalRequired`] if the claims cannot be encoded.
    pub fn issue(
        &self,
        binding: &ApprovalBinding<'_>,
        expires_at_epoch_seconds: u64,
    ) -> Result<String, GatewayError> {
        let claims = ApprovalClaims {
            sub: binding.subject_id.to_owned(),
            azp: binding.client_id.to_owned(),
            tool: binding.tool_name.to_owned(),
            digest: binding.operation_digest.to_owned(),
            jti: Uuid::new_v4().to_string(),
            exp: expires_at_epoch_seconds,
        };
        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)
            .map_err(|_| GatewayError::ApprovalRequired)
    }
}

#[async_trait]
impl ApprovalVerifier for HmacApprovalVerifier {
    async fn verify_and_consume(
        &self,
        ticket: &str,
        binding: &ApprovalBinding<'_>,
        now_epoch_seconds: u64,
    ) -> Result<(), GatewayError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_required_spec_claims(&["exp"]);
        // Expiry is checked manually below against the caller-supplied clock instead; disable
        // jsonwebtoken's own exp check, which otherwise reads the real system clock.
        validation.validate_exp = false;
        let data = decode::<ApprovalClaims>(ticket, &self.decoding_key, &validation)
            .map_err(|_| GatewayError::ApprovalRequired)?;
        let claims = data.claims;
        if claims.exp <= now_epoch_seconds
            || claims.sub != binding.subject_id
            || claims.azp != binding.client_id
            || claims.tool != binding.tool_name
            || claims.digest != binding.operation_digest
        {
            return Err(GatewayError::ApprovalRequired);
        }
        let mut consumed = self.consumed.lock().await;
        if !consumed.insert(claims.jti) {
            return Err(GatewayError::ApprovalRequired);
        }
        Ok(())
    }
}
