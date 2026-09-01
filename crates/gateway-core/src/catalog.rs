use std::collections::BTreeSet;

use crate::{CatalogEntry, EgressClass, RiskClass};

pub const CATALOG_VERSION: &str = "2026-09-01.v1";

#[must_use]
pub fn catalog() -> Vec<CatalogEntry> {
    let mut entries = vec![
        entry(
            "clinical.medication_conflict_check",
            "Run ModelForge's deterministic medication conflict service and return provider limitations.",
            &["allergies", "medications"],
        ),
        entry(
            "clinical.response_contract_check",
            "Check a clinical response against ModelForge's deterministic eight-section contract.",
            &["assistantResponse"],
        ),
        entry(
            "modelforge.capabilities",
            "Return the versioned, authorization-filtered ModelForge Clinical MCP capability manifest.",
            &[],
        ),
        entry(
            "runtime.diagnostics",
            "Return bounded, non-secret ModelForge runtime diagnostics.",
            &[],
        ),
    ];
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    entries
}

#[must_use]
pub fn catalog_entry(name: &str) -> Option<CatalogEntry> {
    catalog().into_iter().find(|entry| entry.name == name)
}

fn entry(name: &str, description: &str, phi_fields: &[&str]) -> CatalogEntry {
    CatalogEntry {
        name: name.to_owned(),
        description: description.to_owned(),
        risk: RiskClass::ReadOnly,
        egress: EgressClass::None,
        phi_fields: phi_fields
            .iter()
            .map(|field| (*field).to_owned())
            .collect::<BTreeSet<_>>(),
        idempotency_required: false,
    }
}
