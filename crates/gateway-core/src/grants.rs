use std::collections::{BTreeMap, BTreeSet};

use async_trait::async_trait;
use thiserror::Error;

use crate::{ContextGrant, GatewayError, GrantResolver};

const MAX_GRANTS: usize = 10_000;
const MAX_GRANT_VALUES: usize = 100;
const MAX_GRANT_VALUE_BYTES: usize = 200;

/// Immutable grant material loaded from an authoritative, integrity-checked snapshot.
#[derive(Clone, Debug)]
pub struct GrantSnapshot {
    grants: BTreeMap<String, ContextGrant>,
}

impl GrantSnapshot {
    /// Validates and indexes a bounded grant snapshot.
    ///
    /// # Errors
    ///
    /// Rejects duplicate, malformed, unversioned, or excessively broad grants.
    pub fn new(grants: impl IntoIterator<Item = ContextGrant>) -> Result<Self, GrantSnapshotError> {
        let mut indexed = BTreeMap::new();
        for grant in grants {
            if indexed.len() >= MAX_GRANTS {
                return Err(GrantSnapshotError::TooManyGrants);
            }
            validate_grant(&grant)?;
            let id = grant.id.clone();
            if indexed.insert(id, grant).is_some() {
                return Err(GrantSnapshotError::DuplicateGrant);
            }
        }
        Ok(Self { grants: indexed })
    }
}

#[async_trait]
impl GrantResolver for GrantSnapshot {
    async fn resolve(&self, grant_id: &str) -> Result<ContextGrant, GatewayError> {
        self.grants
            .get(grant_id)
            .cloned()
            .ok_or(GatewayError::ContextGrantUnavailable)
    }
}

fn validate_grant(grant: &ContextGrant) -> Result<(), GrantSnapshotError> {
    for value in [
        &grant.id,
        &grant.subject_id,
        &grant.client_id,
        &grant.organization_id,
        &grant.case_id,
        &grant.purpose,
    ] {
        validate_value(value)?;
    }
    if grant.version == 0 || grant.expires_at_epoch_seconds == 0 {
        return Err(GrantSnapshotError::InvalidGrant);
    }
    validate_values(&grant.allowed_tools)?;
    validate_values(&grant.allowed_fields)?;
    if grant.allowed_tools.is_empty() || grant.allowed_fields.is_empty() {
        return Err(GrantSnapshotError::InvalidGrant);
    }
    Ok(())
}

fn validate_values(values: &BTreeSet<String>) -> Result<(), GrantSnapshotError> {
    if values.len() > MAX_GRANT_VALUES {
        return Err(GrantSnapshotError::GrantTooBroad);
    }
    values.iter().try_for_each(|value| validate_value(value))
}

fn validate_value(value: &str) -> Result<(), GrantSnapshotError> {
    if value.trim().is_empty()
        || value.len() > MAX_GRANT_VALUE_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(GrantSnapshotError::InvalidGrant);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum GrantSnapshotError {
    #[error("grant snapshot exceeds the configured grant count")]
    TooManyGrants,
    #[error("grant snapshot contains a duplicate grant identifier")]
    DuplicateGrant,
    #[error("grant snapshot contains an invalid grant")]
    InvalidGrant,
    #[error("grant snapshot contains an excessively broad grant")]
    GrantTooBroad,
}
