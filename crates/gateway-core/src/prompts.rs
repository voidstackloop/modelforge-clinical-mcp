use crate::response_contract::RESPONSE_CONTRACT_SECTION_HEADINGS;

/// Mirrors the trailing guidance paragraph of `CLINICAL_RESPONSE_CONTRACT`
/// (`frontend/src/lib/clinical-constants.ts`) in the main `ModelForge` app verbatim.
const RESPONSE_CONTRACT_GUIDANCE: &str = "Do not fabricate patient facts, sources, doses, contraindications, or test results. Mark inference and uncertainty clearly. Ask for missing high-impact information rather than guessing. State explicitly when the available evidence is insufficient to answer confidently, rather than answering anyway. Never silently convert units — preserve the original unit and show any conversion explicitly. This is decision support for a clinician, not an autonomous diagnosis or prescription — you are not treating the patient.";

/// Mirrors `CLINICAL_MODES.soap.instruction` in `clinical-constants.ts`.
const SOAP_MODE_INSTRUCTION: &str =
    "Draft a SOAP note (Subjective, Objective, Assessment, Plan) from the information provided.";

/// Mirrors `CLINICAL_MODES.differential.instruction` in `clinical-constants.ts`.
const DIFFERENTIAL_MODE_INSTRUCTION: &str = "Provide differential diagnosis support — a ranked list of possible interpretations, not a single diagnosis.";

/// Mirrors `CLINICAL_MODES.medicationReview.instruction` in `clinical-constants.ts`.
const MEDICATION_REVIEW_MODE_INSTRUCTION: &str = "Review the listed medications for interactions, duplication, and dosing concerns that warrant clinician attention.";

/// Gateway-specific: the desktop app has no equivalent clinical mode. Scoped to the design
/// doc's "evidence lookup" read-tool family rather than free clinical judgment.
const EVIDENCE_APPRAISAL_MODE_INSTRUCTION: &str = "Appraise the supplied evidence sources for relevance, recency, and quality. State clearly which claims each source does and does not support, and note when the available evidence is insufficient to draw a conclusion.";

/// Gateway-specific: the desktop app has no equivalent clinical mode. Scoped to the design
/// doc's `runtime.diagnostics` tool output rather than free clinical judgment.
const COMPUTE_INCIDENT_TRIAGE_MODE_INSTRUCTION: &str = "Using only the bounded runtime diagnostics provided, summarize the likely failure category, its operational impact, and the next diagnostic or escalation step. Do not speculate about causes the diagnostics do not support.";

/// Mirrors `CLINICAL_RESPONSE_CONTRACT` in `clinical-constants.ts` byte-for-byte: an intro
/// line, the same eight headings used to build `RESPONSE_CONTRACT_SECTION_HEADINGS`, and the
/// same trailing guidance paragraph.
#[must_use]
pub fn clinical_response_contract_prompt() -> String {
    format!(
        "When responding to a clinically relevant question, structure your answer using exactly these eight sections, in order, with these headings:\n{}\n\n{RESPONSE_CONTRACT_GUIDANCE}",
        RESPONSE_CONTRACT_SECTION_HEADINGS.join("\n"),
    )
}

/// One of the six V1 prompt templates named in the system design doc's API and Data
/// Contracts section: "clinical response contract, SOAP draft, differential support,
/// medication review, evidence appraisal, and compute incident triage."
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClinicalPromptTemplate {
    ResponseContract,
    SoapDraft,
    DifferentialSupport,
    MedicationReview,
    EvidenceAppraisal,
    ComputeIncidentTriage,
}

impl ClinicalPromptTemplate {
    fn mode_instruction(self) -> Option<&'static str> {
        match self {
            Self::ResponseContract => None,
            Self::SoapDraft => Some(SOAP_MODE_INSTRUCTION),
            Self::DifferentialSupport => Some(DIFFERENTIAL_MODE_INSTRUCTION),
            Self::MedicationReview => Some(MEDICATION_REVIEW_MODE_INSTRUCTION),
            Self::EvidenceAppraisal => Some(EVIDENCE_APPRAISAL_MODE_INSTRUCTION),
            Self::ComputeIncidentTriage => Some(COMPUTE_INCIDENT_TRIAGE_MODE_INSTRUCTION),
        }
    }

    /// Composes the response-contract text with this template's mode instruction, mirroring
    /// `buildSystemMessages` in `Chat.tsx`: `[CLINICAL_RESPONSE_CONTRACT, modeInstruction]`
    /// joined by a blank line, contract first.
    #[must_use]
    pub fn render(self) -> String {
        match self.mode_instruction() {
            Some(instruction) => {
                format!("{}\n\n{instruction}", clinical_response_contract_prompt())
            }
            None => clinical_response_contract_prompt(),
        }
    }
}
