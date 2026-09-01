use std::sync::Arc;

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    CatalogEntry, ContextGrant, DomainAdapter, GatewayError, SubjectContext,
    response_contract::{self, ResponseContractCheckArguments},
};

const TOOL_NAME: &str = "clinical.medication_conflict_check";
const MAX_LIST_ITEMS: usize = 100;
const MAX_CLINICAL_TERM_BYTES: usize = 200;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MedicationConflictArguments {
    pub medications: Vec<String>,
    pub allergies: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MedicationConflictRequest {
    pub organization_id: String,
    pub case_id: String,
    pub medications: Vec<String>,
    pub allergies: Vec<String>,
}

/// Mirrors `MedicationConflictWarning["kind"]` in `app/src/medical-safety.ts` in the main
/// `ModelForge` app. `DuplicateClass` is part of that type's contract for a future provider but
/// is never produced by the built-in seed-list provider, same as upstream.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum MedicationConflictWarningKind {
    Allergy,
    DuplicateClass,
    KnownInteraction,
}

/// Mirrors `MedicationConflictWarning` in `medical-safety.ts`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MedicationConflictWarning {
    pub kind: MedicationConflictWarningKind,
    pub medication: String,
    pub conflicts_with: String,
    pub detail: String,
}

/// Mirrors `MedicationSafetyResult["status"]` in `medical-safety.ts`: the provider's own
/// coverage claim when a check actually ran, or why it didn't.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum MedicationCheckStatus {
    Demonstration,
    ClinicallyAuthoritative,
    Unavailable,
    Failed,
}

/// Mirrors `MedicationSafetyResult` in `medical-safety.ts`. `evaluated_at_epoch_seconds`
/// replaces the upstream ISO-8601 `evaluatedAt` string — this gateway already threads epoch
/// seconds through every other timestamp and has no other reason to depend on a datetime crate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MedicationConflictResult {
    pub provider_name: String,
    pub provider_label: String,
    pub status: MedicationCheckStatus,
    pub evaluated_at_epoch_seconds: u64,
    /// False when no allergies or medications were supplied at all — distinct from `true` with
    /// zero warnings, which means the check ran and found nothing.
    pub applicable: bool,
    pub warnings: Vec<MedicationConflictWarning>,
    pub limitations: String,
    /// Present only when `status` is `Failed` — a fixed, safe-to-display message, never the
    /// provider's raw error (which could otherwise echo back the medication/allergy text it was
    /// just given).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[async_trait]
pub trait MedicationConflictService: Send + Sync {
    async fn check(
        &self,
        request: MedicationConflictRequest,
    ) -> Result<MedicationConflictResult, GatewayError>;
}

/// Narrow adapter that can call only the medication-conflict service port and the
/// deterministic, in-process response-contract check.
pub struct ClinicalDomainAdapter {
    medication_conflicts: Arc<dyn MedicationConflictService>,
}

impl ClinicalDomainAdapter {
    #[must_use]
    pub fn new(medication_conflicts: Arc<dyn MedicationConflictService>) -> Self {
        Self {
            medication_conflicts,
        }
    }
}

#[async_trait]
impl DomainAdapter for ClinicalDomainAdapter {
    async fn call(
        &self,
        subject: &SubjectContext,
        operation: &CatalogEntry,
        grant: Option<&ContextGrant>,
        arguments: Value,
    ) -> Result<Value, GatewayError> {
        match operation.name.as_str() {
            TOOL_NAME => {
                let grant = grant.ok_or(GatewayError::ContextGrantRequired)?;
                let arguments: MedicationConflictArguments = serde_json::from_value(arguments)
                    .map_err(|_| {
                        GatewayError::PayloadRejected("invalid medication conflict input")
                    })?;
                validate_terms(&arguments.medications, false)?;
                validate_terms(&arguments.allergies, true)?;
                let result = self
                    .medication_conflicts
                    .check(MedicationConflictRequest {
                        organization_id: subject.organization_id.clone(),
                        case_id: grant.case_id.clone(),
                        medications: arguments.medications,
                        allergies: arguments.allergies,
                    })
                    .await?;
                serde_json::to_value(result).map_err(|_| GatewayError::DomainUnavailable)
            }
            response_contract::TOOL_NAME => {
                let _grant = grant.ok_or(GatewayError::ContextGrantRequired)?;
                let arguments: ResponseContractCheckArguments = serde_json::from_value(arguments)
                    .map_err(|_| {
                    GatewayError::PayloadRejected("invalid response contract input")
                })?;
                response_contract::validate_response(&arguments.assistant_response)?;
                let result = response_contract::check_response_contract_compliance(
                    &arguments.assistant_response,
                );
                serde_json::to_value(result).map_err(|_| GatewayError::DomainUnavailable)
            }
            _ => Err(GatewayError::UnknownOperation),
        }
    }
}

fn validate_terms(values: &[String], allow_empty: bool) -> Result<(), GatewayError> {
    if values.len() > MAX_LIST_ITEMS || (!allow_empty && values.is_empty()) {
        return Err(GatewayError::PayloadRejected(
            "clinical term list has an invalid size",
        ));
    }
    if values.iter().any(|value| {
        value.trim().is_empty()
            || value.len() > MAX_CLINICAL_TERM_BYTES
            || value.chars().any(char::is_control)
    }) {
        return Err(GatewayError::PayloadRejected(
            "clinical term is empty, too long, or contains control characters",
        ));
    }
    Ok(())
}
