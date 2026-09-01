use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::GatewayError;

pub(crate) const TOOL_NAME: &str = "clinical.response_contract_check";
const MAX_RESPONSE_BYTES: usize = 20_000;

/// Mirrors `RESPONSE_CONTRACT_SECTION_HEADINGS` in
/// `frontend/src/lib/clinical-constants.ts` in the main `ModelForge` app. Keep these two
/// lists identical so the desktop prompt/check and this gateway check can never drift apart.
pub const RESPONSE_CONTRACT_SECTION_HEADINGS: [&str; 8] = [
    "1. Summary",
    "2. Known patient facts",
    "3. Assessment or possible interpretations",
    "4. Missing information",
    "5. Red flags and urgent concerns",
    "6. Suggested next clinical steps",
    "7. Evidence and citations",
    "8. Uncertainty and limitations",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResponseContractCheckArguments {
    pub assistant_response: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResponseContractCheckResult {
    /// True only when the response appears to actually attempt the structured contract (at
    /// least one required heading present verbatim) — a short non-clinical reply was never
    /// going to have eight sections, and flagging it would be noise rather than signal.
    pub applicable: bool,
    /// Required headings absent from the response, in contract order.
    pub missing_sections: Vec<String>,
}

/// Deterministic, non-model check mirroring `checkResponseContractCompliance`
/// (`frontend/src/lib/clinical-constants.ts`): plain substring matching against the same
/// eight headings used to build the desktop app's system-prompt addendum.
#[must_use]
pub fn check_response_contract_compliance(text: &str) -> ResponseContractCheckResult {
    let attempted = RESPONSE_CONTRACT_SECTION_HEADINGS
        .iter()
        .any(|heading| text.contains(heading));
    if !attempted {
        return ResponseContractCheckResult {
            applicable: false,
            missing_sections: Vec::new(),
        };
    }
    ResponseContractCheckResult {
        applicable: true,
        missing_sections: RESPONSE_CONTRACT_SECTION_HEADINGS
            .iter()
            .filter(|heading| !text.contains(*heading))
            .map(|heading| (*heading).to_owned())
            .collect(),
    }
}

pub(crate) fn validate_response(text: &str) -> Result<(), GatewayError> {
    if text.trim().is_empty() || text.len() > MAX_RESPONSE_BYTES {
        return Err(GatewayError::PayloadRejected(
            "assistant response is empty or exceeds the maximum size",
        ));
    }
    if text
        .chars()
        .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(GatewayError::PayloadRejected(
            "assistant response contains disallowed control characters",
        ));
    }
    Ok(())
}
