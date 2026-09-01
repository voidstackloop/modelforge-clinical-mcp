//! Deterministic medication/allergy conflict checking, ported byte-for-byte in behavior from
//! `app/src/medical-safety.ts` (`checkMedicationConflicts` / `builtInMedicationSafetyProvider`)
//! in the main `ModelForge` app. This is the same seed list, the same substring-matching
//! algorithm, and the same "demonstration coverage, not a licensed drug-interaction database"
//! labeling as the real desktop app's built-in provider — not a stub, but also not a claim of
//! clinical authority beyond what the source it mirrors claims for itself.

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;

use crate::{
    GatewayError,
    medication::{
        MedicationCheckStatus, MedicationConflictRequest, MedicationConflictResult,
        MedicationConflictService, MedicationConflictWarning, MedicationConflictWarningKind,
    },
};

const PROVIDER_NAME: &str = "modelforge-builtin-seed-list";
const PROVIDER_LABEL: &str = "Built-in demonstration list";
const LIMITATIONS: &str = "A small, non-exhaustive set of well-known interaction pairs and allergy-class synonyms, included only to demonstrate the warning mechanism — not a licensed drug-interaction database (e.g. First Databank, Lexicomp, Multum). Zero warnings from this list is not evidence that the recorded medications and allergies are safe together; independently verify with a pharmacist or clinical reference.";

/// Mirrors `KNOWN_INTERACTIONS` in `medical-safety.ts` exactly.
const KNOWN_INTERACTIONS: &[(&str, &str, &str)] = &[
    (
        "warfarin",
        "aspirin",
        "Combined use raises bleeding risk; requires clinician review.",
    ),
    (
        "warfarin",
        "ibuprofen",
        "NSAID + warfarin raises GI bleeding risk; requires clinician review.",
    ),
    (
        "maoi",
        "ssri",
        "Risk of serotonin syndrome; requires clinician review.",
    ),
    (
        "sildenafil",
        "nitrate",
        "Combined use can cause severe hypotension.",
    ),
    (
        "metformin",
        "contrast dye",
        "Risk of contrast-induced lactic acidosis; hold per protocol.",
    ),
];

/// Mirrors `ALLERGY_CLASS_SYNONYMS` in `medical-safety.ts` exactly.
const ALLERGY_CLASS_SYNONYMS: &[(&str, &[&str])] = &[
    ("penicillin", &["amoxicillin", "ampicillin", "penicillin"]),
    ("sulfa", &["sulfamethoxazole", "sulfasalazine", "bactrim"]),
    ("nsaid", &["ibuprofen", "naproxen", "aspirin", "diclofenac"]),
];

fn normalize(value: &str) -> String {
    value.trim().to_lowercase()
}

fn has_content(values: &[String]) -> bool {
    values.iter().any(|value| !normalize(value).is_empty())
}

fn synonym_group(allergy: &str) -> Vec<&'static str> {
    ALLERGY_CLASS_SYNONYMS
        .iter()
        .find(|(name, _)| *name == allergy)
        .map_or_else(Vec::new, |(_, synonyms)| synonyms.to_vec())
}

/// Mirrors `builtInMedicationSafetyProvider.checkConflicts` exactly: allergy/class-synonym
/// substring matching, then pairwise known-interaction substring matching over every
/// combination of two supplied medications.
fn check_conflicts(allergies: &[String], medications: &[String]) -> Vec<MedicationConflictWarning> {
    let mut warnings = Vec::new();
    let normalized_allergies = allergies
        .iter()
        .map(|value| normalize(value))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let normalized_medications = medications
        .iter()
        .map(|value| normalize(value))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    for allergy in &normalized_allergies {
        let group = synonym_group(allergy);
        let group: Vec<&str> = if group.is_empty() {
            vec![allergy.as_str()]
        } else {
            group
        };
        for medication in &normalized_medications {
            if group.iter().any(|synonym| {
                medication.contains(synonym) || synonym.contains(medication.as_str())
            }) {
                warnings.push(MedicationConflictWarning {
                    kind: MedicationConflictWarningKind::Allergy,
                    medication: medication.clone(),
                    conflicts_with: allergy.clone(),
                    detail: format!(
                        "Recorded allergy to \"{allergy}\" may conflict with medication \"{medication}\"."
                    ),
                });
            }
        }
    }

    for i in 0..normalized_medications.len() {
        for j in (i + 1)..normalized_medications.len() {
            let (med_a, med_b) = (&normalized_medications[i], &normalized_medications[j]);
            for (pair_a, pair_b, detail) in KNOWN_INTERACTIONS {
                let matches_forward = med_a.contains(pair_a) && med_b.contains(pair_b);
                let matches_reverse = med_a.contains(pair_b) && med_b.contains(pair_a);
                if matches_forward || matches_reverse {
                    warnings.push(MedicationConflictWarning {
                        kind: MedicationConflictWarningKind::KnownInteraction,
                        medication: normalized_medications[i].clone(),
                        conflicts_with: normalized_medications[j].clone(),
                        detail: (*detail).to_owned(),
                    });
                }
            }
        }
    }

    warnings
}

/// Mirrors `checkMedicationConflicts` in `medical-safety.ts`: the built-in provider is
/// synchronous and infallible (no I/O, no external service), so the `unavailable`/`failed`
/// status values this type supports for a future real provider are never produced here.
pub struct BuiltInMedicationConflictService;

#[async_trait]
impl MedicationConflictService for BuiltInMedicationConflictService {
    async fn check(
        &self,
        request: MedicationConflictRequest,
    ) -> Result<MedicationConflictResult, GatewayError> {
        let evaluated_at_epoch_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GatewayError::DomainUnavailable)?
            .as_secs();
        let applicable = has_content(&request.allergies) || has_content(&request.medications);
        let warnings = if applicable {
            check_conflicts(&request.allergies, &request.medications)
        } else {
            Vec::new()
        };
        Ok(MedicationConflictResult {
            provider_name: PROVIDER_NAME.into(),
            provider_label: PROVIDER_LABEL.into(),
            status: MedicationCheckStatus::Demonstration,
            evaluated_at_epoch_seconds,
            applicable,
            warnings,
            limitations: LIMITATIONS.into(),
            error: None,
        })
    }
}
