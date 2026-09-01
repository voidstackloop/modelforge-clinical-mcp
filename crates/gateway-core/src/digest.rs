use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{ContextGrant, PolicySnapshot, SubjectContext};

/// Produces the stable binding used by approval tickets and replay records.
#[must_use]
pub fn operation_digest(
    tool_name: &str,
    arguments: &Value,
    subject: &SubjectContext,
    grant: Option<&ContextGrant>,
    policy: &PolicySnapshot,
) -> String {
    let canonical = canonicalize(arguments);
    let mut hasher = Sha256::new();
    let grant_version = grant.map_or(0, |value| value.version).to_string();
    for component in [
        tool_name,
        &subject.subject_id,
        &subject.client_id,
        &subject.organization_id,
        grant.map_or("-", |value| value.id.as_str()),
        &grant_version,
        &policy.registry_version,
        &policy.rbac_version,
        &policy.egress_policy_version,
        &policy.kill_switch_version,
        &policy.tool_policy_version,
    ] {
        hasher.update(component.as_bytes());
        hasher.update([0]);
    }
    hasher.update(serde_json::to_vec(&canonical).unwrap_or_default());
    format!("sha256:{:x}", hasher.finalize())
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            let sorted = keys
                .into_iter()
                .map(|key| (key.clone(), canonicalize(&values[key])))
                .collect::<Map<_, _>>();
            Value::Object(sorted)
        }
        scalar => scalar.clone(),
    }
}
