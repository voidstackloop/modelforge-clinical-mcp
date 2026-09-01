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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MedicationConflictFinding {
    pub severity: String,
    pub summary: String,
    pub evidence_code: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MedicationConflictResult {
    pub findings: Vec<MedicationConflictFinding>,
    pub limitations: Vec<String>,
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
