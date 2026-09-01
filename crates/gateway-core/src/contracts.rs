use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RiskClass {
    ReadOnly,
    ControlledWrite,
    Prohibited,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EgressClass {
    None,
    LocalOnly,
    ApprovedRemote,
}

#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DestinationClass {
    LocalModelForge,
    ManagedModelForge,
    ApprovedThirdParty,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CatalogEntry {
    pub name: String,
    pub description: String,
    pub risk: RiskClass,
    pub egress: EgressClass,
    pub phi_fields: BTreeSet<String>,
    pub idempotency_required: bool,
}

impl CatalogEntry {
    #[must_use]
    pub fn requires_context_grant(&self) -> bool {
        !self.phi_fields.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectContext {
    pub subject_id: String,
    pub client_id: String,
    pub organization_id: String,
    pub roles: BTreeSet<String>,
    pub scopes: BTreeSet<String>,
    pub authentication_strength: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContextGrant {
    pub id: String,
    pub subject_id: String,
    pub client_id: String,
    pub organization_id: String,
    pub case_id: String,
    pub allowed_tools: BTreeSet<String>,
    pub allowed_fields: BTreeSet<String>,
    pub purpose: String,
    pub destination: DestinationClass,
    pub expires_at_epoch_seconds: u64,
    pub version: u64,
}

impl ContextGrant {
    /// Confirms that the grant belongs to the verified caller and covers the operation fields.
    ///
    /// # Errors
    ///
    /// Returns a binding, expiry, or scope error when the grant cannot authorize the request.
    pub fn validate_binding(
        &self,
        subject: &SubjectContext,
        entry: &CatalogEntry,
        now_epoch_seconds: u64,
    ) -> Result<(), crate::GatewayError> {
        if self.subject_id != subject.subject_id
            || self.client_id != subject.client_id
            || self.organization_id != subject.organization_id
        {
            return Err(crate::GatewayError::GrantBindingMismatch);
        }
        if self.expires_at_epoch_seconds <= now_epoch_seconds {
            return Err(crate::GatewayError::GrantExpired);
        }
        if !self.allowed_tools.contains(&entry.name)
            || !entry.phi_fields.is_subset(&self.allowed_fields)
        {
            return Err(crate::GatewayError::GrantScopeInsufficient);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicySnapshot {
    pub registry_version: String,
    pub rbac_version: String,
    pub egress_policy_version: String,
    pub kill_switch_version: String,
    pub tool_policy_version: String,
}

#[derive(Clone, Debug)]
pub struct AdmissionRequest {
    pub subject: SubjectContext,
    pub tool_name: String,
    pub arguments: Value,
    pub context_grant_id: Option<String>,
    pub approval_ticket: Option<String>,
    pub idempotency_key: Option<String>,
    pub now_epoch_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationResponse {
    pub operation_id: Uuid,
    pub operation_digest: String,
    pub policy_snapshot: PolicySnapshot,
    pub result: Value,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Admitted,
    Succeeded,
    Denied,
    Failed,
}

/// PHI-free audit metadata. Arguments, results, grant contents, and tickets are intentionally absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditEvent {
    pub operation_id: Uuid,
    pub subject_id: String,
    pub client_id: String,
    pub organization_id: String,
    pub tool_name: String,
    pub risk: RiskClass,
    pub outcome: AuditOutcome,
    pub policy_version: Option<String>,
    pub error_class: Option<String>,
}
