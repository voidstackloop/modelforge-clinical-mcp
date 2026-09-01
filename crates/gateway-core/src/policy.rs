use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CatalogEntry, ContextGrant, DestinationClass, EgressClass, GatewayError, PolicyEngine,
    PolicySnapshot, SubjectContext, catalog_entry,
};

const MAX_POLICY_VALUES: usize = 100;
const MAX_POLICY_VALUE_BYTES: usize = 200;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ToolEntitlement {
    pub allowed_roles: BTreeSet<String>,
    pub required_scopes: BTreeSet<String>,
    pub allowed_destinations: BTreeSet<DestinationClass>,
    /// Authentication strengths (the JWT `acr` claim) permitted to use this tool. Empty means
    /// unrestricted: any authenticated subject may proceed regardless of step-up status. Set
    /// this to require MFA/step-up (e.g. `{"urn:mfa"}`) for a specific PHI-bearing tool.
    #[serde(default)]
    pub allowed_authentication_strengths: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantPolicy {
    pub organization_id: String,
    pub tools: BTreeMap<String, ToolEntitlement>,
}

#[derive(Clone, Debug)]
pub struct PolicySet {
    tenants: BTreeMap<String, TenantPolicy>,
    snapshot: PolicySnapshot,
    kill_switch_active: bool,
}

impl PolicySet {
    /// Builds an immutable, versioned policy snapshot.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers, duplicate tenants, unknown tools, empty entitlements, and
    /// unversioned snapshots before the policy can serve authorization decisions.
    pub fn new(
        policies: impl IntoIterator<Item = TenantPolicy>,
        snapshot: PolicySnapshot,
        kill_switch_active: bool,
    ) -> Result<Self, PolicySetError> {
        validate_snapshot(&snapshot)?;
        let mut tenants = BTreeMap::new();
        for policy in policies {
            validate_value(&policy.organization_id)?;
            if policy.tools.is_empty() || policy.tools.len() > MAX_POLICY_VALUES {
                return Err(PolicySetError::InvalidEntitlement);
            }
            for (tool_name, entitlement) in &policy.tools {
                if catalog_entry(tool_name).is_none()
                    || entitlement.allowed_roles.is_empty()
                    || entitlement.required_scopes.is_empty()
                    || entitlement.allowed_destinations.is_empty()
                {
                    return Err(PolicySetError::InvalidEntitlement);
                }
                validate_values(&entitlement.allowed_roles)?;
                validate_values(&entitlement.required_scopes)?;
                validate_values(&entitlement.allowed_authentication_strengths)?;
            }
            let organization_id = policy.organization_id.clone();
            if tenants.insert(organization_id, policy).is_some() {
                return Err(PolicySetError::DuplicateTenant);
            }
        }
        if tenants.is_empty() {
            return Err(PolicySetError::NoTenants);
        }
        Ok(Self {
            tenants,
            snapshot,
            kill_switch_active,
        })
    }
}

#[async_trait]
impl PolicyEngine for PolicySet {
    async fn authorize(
        &self,
        subject: &SubjectContext,
        operation: &CatalogEntry,
        grant: Option<&ContextGrant>,
    ) -> Result<PolicySnapshot, GatewayError> {
        if self.kill_switch_active {
            return Err(GatewayError::PolicyDenied);
        }
        let tenant = self
            .tenants
            .get(&subject.organization_id)
            .ok_or(GatewayError::PolicyDenied)?;
        let entitlement = tenant
            .tools
            .get(&operation.name)
            .ok_or(GatewayError::PolicyDenied)?;
        if subject.roles.is_disjoint(&entitlement.allowed_roles)
            || !entitlement.required_scopes.is_subset(&subject.scopes)
        {
            return Err(GatewayError::PolicyDenied);
        }
        if !entitlement.allowed_authentication_strengths.is_empty()
            && !entitlement
                .allowed_authentication_strengths
                .contains(&subject.authentication_strength)
        {
            return Err(GatewayError::PolicyDenied);
        }
        if operation.requires_context_grant() {
            let grant = grant.ok_or(GatewayError::PolicyDenied)?;
            if grant.purpose.trim().is_empty()
                || !entitlement
                    .allowed_destinations
                    .contains(&grant.destination)
                || !egress_permits(operation.egress, grant.destination)
            {
                return Err(GatewayError::PolicyDenied);
            }
        }
        Ok(self.snapshot.clone())
    }
}

/// Enforces the catalog's declared egress class against a grant's destination, independent of
/// (and in addition to) the tenant-configured `allowed_destinations` allowlist: a tool the
/// catalog marks as never egressing data must not be authorized for a grant that names a
/// non-local destination, regardless of what a tenant policy misconfiguration might otherwise
/// allow.
fn egress_permits(egress: EgressClass, destination: DestinationClass) -> bool {
    match egress {
        EgressClass::None => destination == DestinationClass::LocalModelForge,
        EgressClass::LocalOnly => destination != DestinationClass::ApprovedThirdParty,
        EgressClass::ApprovedRemote => true,
    }
}

fn validate_snapshot(snapshot: &PolicySnapshot) -> Result<(), PolicySetError> {
    for version in [
        &snapshot.registry_version,
        &snapshot.rbac_version,
        &snapshot.egress_policy_version,
        &snapshot.kill_switch_version,
        &snapshot.tool_policy_version,
    ] {
        validate_value(version)?;
    }
    Ok(())
}

fn validate_values(values: &BTreeSet<String>) -> Result<(), PolicySetError> {
    if values.len() > MAX_POLICY_VALUES {
        return Err(PolicySetError::InvalidValue);
    }
    values.iter().try_for_each(|value| validate_value(value))
}

fn validate_value(value: &str) -> Result<(), PolicySetError> {
    if value.trim().is_empty()
        || value.len() > MAX_POLICY_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(PolicySetError::InvalidValue);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PolicySetError {
    #[error("at least one tenant policy is required")]
    NoTenants,
    #[error("tenant policy identifiers and versions must be bounded and non-empty")]
    InvalidValue,
    #[error("tenant policy contains an unknown tool or an empty entitlement")]
    InvalidEntitlement,
    #[error("tenant policy contains a duplicate organization")]
    DuplicateTenant,
}
