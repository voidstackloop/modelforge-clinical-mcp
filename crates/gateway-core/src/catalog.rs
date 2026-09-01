use std::collections::BTreeSet;

use crate::{CatalogEntry, EgressClass, RiskClass};

pub const CATALOG_VERSION: &str = "2026-09-01.v3";

#[must_use]
pub fn catalog() -> Vec<CatalogEntry> {
    let mut entries = vec![
        entry(
            "clinical.medication_conflict_check",
            "Run ModelForge's deterministic medication conflict service and return provider limitations.",
            &["allergies", "medications"],
        ),
        entry(
            "clinical.record_review_decision",
            "Record a clinician's review decision for a prior AI-assisted clinical operation.",
            &["rationale"],
        )
        .into_controlled_write(),
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
        entry(
            "clinical.submit_compute_request",
            "Submit a compute request to ModelForge's compute-control-plane scheduler.",
            &[],
        )
        .into_controlled_write(),
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

trait ControlledWrite {
    /// Promotes a read-only draft entry to the design doc's "narrowly idempotent" controlled
    /// write shape: `RiskClass::ControlledWrite` (requires an approval ticket) plus
    /// `idempotency_required: true` (a retried write replays its first result instead of
    /// re-executing). Egress stays `None`: recording a review decision is internal
    /// record-keeping, never a remote disclosure.
    fn into_controlled_write(self) -> Self;
}

impl ControlledWrite for CatalogEntry {
    fn into_controlled_write(mut self) -> Self {
        self.risk = RiskClass::ControlledWrite;
        self.idempotency_required = true;
        self
    }
}
