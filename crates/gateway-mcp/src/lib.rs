use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use http::request::Parts;
use modelforge_clinical_mcp_core::{
    AdmissionRequest, CATALOG_VERSION, ClinicalPromptTemplate, Gateway, GatewayError,
    MedicationConflictArguments, OperationResponse, ResponseContractCheckArguments,
    ReviewDecisionArguments, ReviewDecisionOutcome, SubjectContext, catalog,
};
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::{tool::Extension, wrapper::Parameters},
    model::{
        ListResourcesResult, PaginatedRequestParams, PromptMessage, ReadResourceRequestParams,
        ReadResourceResponse, ReadResourceResult, Resource, ResourceContents, Role,
        ServerCapabilities, ServerInfo,
    },
    prompt, prompt_handler, prompt_router, schemars,
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};

mod production;

pub use production::{ClinicalPortsConfig, build_clinical_gateway};

/// Shared MCP handler used by every transport adapter.
#[derive(Clone, Default)]
pub struct BootstrapServer;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CapabilitiesInput {
    #[serde(default)]
    include_descriptions: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CapabilitySummary {
    catalog_version: &'static str,
    read_only: bool,
    tools: Vec<CapabilityTool>,
    excluded_families: Vec<&'static str>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
struct CapabilityTool {
    name: String,
    description: Option<String>,
    requires_context_grant: bool,
}

/// The `modelforge://capabilities` resource named first among the V1 resources in the system
/// design doc's API and Data Contracts section. Serves the same deterministic manifest as the
/// `modelforge.capabilities` tool, always with descriptions included since a resource read
/// carries no request-shaped input to select a briefer view.
const CAPABILITIES_RESOURCE_URI: &str = "modelforge://capabilities";

fn capabilities_summary(enabled: &[&str], include_descriptions: bool) -> CapabilitySummary {
    let tools = catalog()
        .into_iter()
        .filter(|entry| enabled.contains(&entry.name.as_str()))
        .map(|entry| {
            let requires_context_grant = entry.requires_context_grant();
            CapabilityTool {
                name: entry.name,
                description: include_descriptions.then_some(entry.description),
                requires_context_grant,
            }
        })
        .collect();
    CapabilitySummary {
        catalog_version: CATALOG_VERSION,
        read_only: true,
        tools,
        excluded_families: excluded_families(),
    }
}

#[tool_router]
impl BootstrapServer {
    #[tool(
        name = "modelforge.capabilities",
        description = "Return the deterministic read-only ModelForge Clinical MCP capability manifest.",
        annotations(
            title = "ModelForge capabilities",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    #[allow(clippy::unused_self)]
    fn capabilities(
        &self,
        Parameters(input): Parameters<CapabilitiesInput>,
    ) -> rmcp::Json<CapabilitySummary> {
        rmcp::Json(capabilities_summary(
            &["modelforge.capabilities"],
            input.include_descriptions,
        ))
    }
}

/// The six V1 prompt templates named in the system design doc: "clinical response contract,
/// SOAP draft, differential support, medication review, evidence appraisal, and compute
/// incident triage." Each renders to a single user-role message; prompts carry no PHI and
/// need no context grant, so they are available even from the bootstrap handler before any
/// trusted policy, grant, audit, or domain adapter is configured.
#[prompt_router]
impl BootstrapServer {
    #[prompt(
        name = "clinical.response_contract",
        description = "The ModelForge structured eight-section clinical response contract, with no mode-specific instruction added."
    )]
    #[allow(clippy::unused_self)]
    fn response_contract_prompt(&self) -> Vec<PromptMessage> {
        prompt_message(ClinicalPromptTemplate::ResponseContract)
    }

    #[prompt(
        name = "clinical.soap_draft",
        description = "The response contract plus an instruction to draft a SOAP note (Subjective, Objective, Assessment, Plan)."
    )]
    #[allow(clippy::unused_self)]
    fn soap_draft_prompt(&self) -> Vec<PromptMessage> {
        prompt_message(ClinicalPromptTemplate::SoapDraft)
    }

    #[prompt(
        name = "clinical.differential_support",
        description = "The response contract plus an instruction to provide ranked differential diagnosis support."
    )]
    #[allow(clippy::unused_self)]
    fn differential_support_prompt(&self) -> Vec<PromptMessage> {
        prompt_message(ClinicalPromptTemplate::DifferentialSupport)
    }

    #[prompt(
        name = "clinical.medication_review",
        description = "The response contract plus an instruction to review medications for interactions, duplication, and dosing concerns."
    )]
    #[allow(clippy::unused_self)]
    fn medication_review_prompt(&self) -> Vec<PromptMessage> {
        prompt_message(ClinicalPromptTemplate::MedicationReview)
    }

    #[prompt(
        name = "clinical.evidence_appraisal",
        description = "The response contract plus an instruction to appraise supplied evidence sources for relevance, recency, and quality."
    )]
    #[allow(clippy::unused_self)]
    fn evidence_appraisal_prompt(&self) -> Vec<PromptMessage> {
        prompt_message(ClinicalPromptTemplate::EvidenceAppraisal)
    }

    #[prompt(
        name = "clinical.compute_incident_triage",
        description = "The response contract plus an instruction to triage a compute/runtime incident using only bounded runtime diagnostics."
    )]
    #[allow(clippy::unused_self)]
    fn compute_incident_triage_prompt(&self) -> Vec<PromptMessage> {
        prompt_message(ClinicalPromptTemplate::ComputeIncidentTriage)
    }
}

fn prompt_message(template: ClinicalPromptTemplate) -> Vec<PromptMessage> {
    vec![PromptMessage::new_text(Role::User, template.render())]
}

/// Shared by every server's `list_resources`: currently just the one V1 resource.
fn list_capabilities_resource() -> ListResourcesResult {
    ListResourcesResult::with_all_items(vec![
        Resource::new(CAPABILITIES_RESOURCE_URI, "ModelForge capabilities")
            .with_description(
                "The deterministic, versioned ModelForge Clinical MCP capability manifest.",
            )
            .with_mime_type("application/json"),
    ])
}

/// Shared by every server's `read_resource`. `enabled_tools` scopes the manifest the same way
/// `capabilities_summary` does for the tool of the same name, so a resource read never reveals
/// more than that server's own `tools/call` surface would.
fn read_capabilities_resource(
    uri: &str,
    enabled_tools: &[&str],
) -> Result<ReadResourceResponse, ErrorData> {
    if uri != CAPABILITIES_RESOURCE_URI {
        return Err(ErrorData::resource_not_found(
            "unknown resource URI",
            Some(serde_json::json!({ "uri": uri })),
        ));
    }
    let summary = capabilities_summary(enabled_tools, true);
    let text = serde_json::to_string(&summary)
        .map_err(|_| ErrorData::internal_error("failed to encode capabilities", None))?;
    Ok(ReadResourceResult::new(vec![
        ResourceContents::text(text, CAPABILITIES_RESOURCE_URI).with_mime_type("application/json"),
    ])
    .into())
}

#[tool_handler]
#[prompt_handler]
impl ServerHandler for BootstrapServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .enable_resources()
                .build(),
        )
        .with_instructions(
            "Read-only bootstrap gateway. PHI-bearing operations remain hidden until trusted ModelForge policy, grant, audit, and domain adapters are configured.",
        )
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(list_capabilities_resource())
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        read_capabilities_resource(&request.uri, &["modelforge.capabilities"])
    }
}

/// Managed server enabled only after trusted policy, grant, audit, and domain ports are supplied.
#[derive(Clone)]
pub struct ClinicalServer {
    gateway: Arc<Gateway>,
}

impl ClinicalServer {
    #[must_use]
    pub fn new(gateway: Arc<Gateway>) -> Self {
        Self { gateway }
    }
}

const CLINICAL_ENABLED_TOOLS: [&str; 5] = [
    "clinical.medication_conflict_check",
    "clinical.record_review_decision",
    "clinical.response_contract_check",
    "modelforge.capabilities",
    "runtime.diagnostics",
];

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MedicationConflictInput {
    context_grant_id: String,
    medications: Vec<String>,
    allergies: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResponseContractCheckInput {
    context_grant_id: String,
    assistant_response: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordReviewDecisionInput {
    context_grant_id: String,
    /// Single-use ticket from `ModelForge`'s trusted UI, bound to this exact operation.
    approval_ticket: String,
    /// Caller-generated key scoped to organization, subject, tool, and normalized arguments —
    /// a retry with the same key and arguments replays the original result instead of
    /// recording a second decision.
    idempotency_key: String,
    reviewed_operation_id: uuid::Uuid,
    decision: ReviewDecisionOutcome,
    rationale: String,
}

#[tool_router]
impl ClinicalServer {
    #[tool(
        name = "modelforge.capabilities",
        description = "Return the deterministic read-only ModelForge Clinical MCP capability manifest.",
        annotations(
            title = "ModelForge capabilities",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    #[allow(clippy::unused_self)]
    fn capabilities(
        &self,
        Parameters(input): Parameters<CapabilitiesInput>,
    ) -> rmcp::Json<CapabilitySummary> {
        rmcp::Json(capabilities_summary(
            &CLINICAL_ENABLED_TOOLS,
            input.include_descriptions,
        ))
    }

    #[tool(
        name = "clinical.medication_conflict_check",
        description = "Run the authorized ModelForge medication conflict service for the case bound to a short-lived context grant.",
        annotations(
            title = "Medication conflict check",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn medication_conflict_check(
        &self,
        Parameters(input): Parameters<MedicationConflictInput>,
        Extension(parts): Extension<Parts>,
    ) -> Result<rmcp::Json<OperationResponse>, ErrorData> {
        let subject = parts
            .extensions
            .get::<SubjectContext>()
            .cloned()
            .ok_or_else(|| ErrorData::invalid_request("verified identity is unavailable", None))?;
        let now_epoch_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ErrorData::internal_error("system clock is unavailable", None))?
            .as_secs();
        let arguments = serde_json::to_value(MedicationConflictArguments {
            medications: input.medications,
            allergies: input.allergies,
        })
        .map_err(|_| ErrorData::invalid_params("invalid clinical input", None))?;
        self.gateway
            .execute(AdmissionRequest {
                subject,
                tool_name: "clinical.medication_conflict_check".into(),
                arguments,
                context_grant_id: Some(input.context_grant_id),
                approval_ticket: None,
                idempotency_key: None,
                now_epoch_seconds,
            })
            .await
            .map(rmcp::Json)
            .map_err(|error| protocol_error(&error))
    }

    #[tool(
        name = "clinical.response_contract_check",
        description = "Check a clinical response against ModelForge's deterministic eight-section response contract.",
        annotations(
            title = "Response contract check",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn response_contract_check(
        &self,
        Parameters(input): Parameters<ResponseContractCheckInput>,
        Extension(parts): Extension<Parts>,
    ) -> Result<rmcp::Json<OperationResponse>, ErrorData> {
        let subject = parts
            .extensions
            .get::<SubjectContext>()
            .cloned()
            .ok_or_else(|| ErrorData::invalid_request("verified identity is unavailable", None))?;
        let now_epoch_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ErrorData::internal_error("system clock is unavailable", None))?
            .as_secs();
        let arguments = serde_json::to_value(ResponseContractCheckArguments {
            assistant_response: input.assistant_response,
        })
        .map_err(|_| ErrorData::invalid_params("invalid clinical input", None))?;
        self.gateway
            .execute(AdmissionRequest {
                subject,
                tool_name: "clinical.response_contract_check".into(),
                arguments,
                context_grant_id: Some(input.context_grant_id),
                approval_ticket: None,
                idempotency_key: None,
                now_epoch_seconds,
            })
            .await
            .map(rmcp::Json)
            .map_err(|error| protocol_error(&error))
    }

    #[tool(
        name = "clinical.record_review_decision",
        description = "Record a clinician's review decision for a prior AI-assisted clinical operation. Requires a single-use approval ticket and an idempotency key.",
        annotations(
            title = "Record review decision",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn record_review_decision(
        &self,
        Parameters(input): Parameters<RecordReviewDecisionInput>,
        Extension(parts): Extension<Parts>,
    ) -> Result<rmcp::Json<OperationResponse>, ErrorData> {
        let subject = parts
            .extensions
            .get::<SubjectContext>()
            .cloned()
            .ok_or_else(|| ErrorData::invalid_request("verified identity is unavailable", None))?;
        let now_epoch_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ErrorData::internal_error("system clock is unavailable", None))?
            .as_secs();
        let arguments = serde_json::to_value(ReviewDecisionArguments {
            reviewed_operation_id: input.reviewed_operation_id,
            decision: input.decision,
            rationale: input.rationale,
        })
        .map_err(|_| ErrorData::invalid_params("invalid clinical input", None))?;
        self.gateway
            .execute(AdmissionRequest {
                subject,
                tool_name: "clinical.record_review_decision".into(),
                arguments,
                context_grant_id: Some(input.context_grant_id),
                approval_ticket: Some(input.approval_ticket),
                idempotency_key: Some(input.idempotency_key),
                now_epoch_seconds,
            })
            .await
            .map(rmcp::Json)
            .map_err(|error| protocol_error(&error))
    }

    #[tool(
        name = "runtime.diagnostics",
        description = "Return bounded, non-secret ModelForge runtime diagnostics.",
        annotations(
            title = "Runtime diagnostics",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn runtime_diagnostics(
        &self,
        Extension(parts): Extension<Parts>,
    ) -> Result<rmcp::Json<OperationResponse>, ErrorData> {
        let subject = parts
            .extensions
            .get::<SubjectContext>()
            .cloned()
            .ok_or_else(|| ErrorData::invalid_request("verified identity is unavailable", None))?;
        let now_epoch_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ErrorData::internal_error("system clock is unavailable", None))?
            .as_secs();
        self.gateway
            .execute(AdmissionRequest {
                subject,
                tool_name: "runtime.diagnostics".into(),
                arguments: serde_json::json!({}),
                context_grant_id: None,
                approval_ticket: None,
                idempotency_key: None,
                now_epoch_seconds,
            })
            .await
            .map(rmcp::Json)
            .map_err(|error| protocol_error(&error))
    }
}

/// Same six V1 prompt templates as `BootstrapServer` (see its `#[prompt_router]` block for why:
/// prompts carry no PHI and need no context grant, so the managed clinical server must expose
/// them too, not just the unauthenticated bootstrap handler).
#[prompt_router]
impl ClinicalServer {
    #[prompt(
        name = "clinical.response_contract",
        description = "The ModelForge structured eight-section clinical response contract, with no mode-specific instruction added."
    )]
    #[allow(clippy::unused_self)]
    fn response_contract_prompt(&self) -> Vec<PromptMessage> {
        prompt_message(ClinicalPromptTemplate::ResponseContract)
    }

    #[prompt(
        name = "clinical.soap_draft",
        description = "The response contract plus an instruction to draft a SOAP note (Subjective, Objective, Assessment, Plan)."
    )]
    #[allow(clippy::unused_self)]
    fn soap_draft_prompt(&self) -> Vec<PromptMessage> {
        prompt_message(ClinicalPromptTemplate::SoapDraft)
    }

    #[prompt(
        name = "clinical.differential_support",
        description = "The response contract plus an instruction to provide ranked differential diagnosis support."
    )]
    #[allow(clippy::unused_self)]
    fn differential_support_prompt(&self) -> Vec<PromptMessage> {
        prompt_message(ClinicalPromptTemplate::DifferentialSupport)
    }

    #[prompt(
        name = "clinical.medication_review",
        description = "The response contract plus an instruction to review medications for interactions, duplication, and dosing concerns."
    )]
    #[allow(clippy::unused_self)]
    fn medication_review_prompt(&self) -> Vec<PromptMessage> {
        prompt_message(ClinicalPromptTemplate::MedicationReview)
    }

    #[prompt(
        name = "clinical.evidence_appraisal",
        description = "The response contract plus an instruction to appraise supplied evidence sources for relevance, recency, and quality."
    )]
    #[allow(clippy::unused_self)]
    fn evidence_appraisal_prompt(&self) -> Vec<PromptMessage> {
        prompt_message(ClinicalPromptTemplate::EvidenceAppraisal)
    }

    #[prompt(
        name = "clinical.compute_incident_triage",
        description = "The response contract plus an instruction to triage a compute/runtime incident using only bounded runtime diagnostics."
    )]
    #[allow(clippy::unused_self)]
    fn compute_incident_triage_prompt(&self) -> Vec<PromptMessage> {
        prompt_message(ClinicalPromptTemplate::ComputeIncidentTriage)
    }
}

#[tool_handler]
#[prompt_handler]
impl ServerHandler for ClinicalServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_prompts()
                .enable_resources()
                .build(),
        )
        .with_instructions(
            "Read-only managed clinical gateway. Every PHI-bearing operation requires verified identity, tenant policy, and a short-lived context grant.",
        )
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, ErrorData> {
        Ok(list_capabilities_resource())
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, ErrorData> {
        read_capabilities_resource(&request.uri, &CLINICAL_ENABLED_TOOLS)
    }
}

fn protocol_error(error: &GatewayError) -> ErrorData {
    let data = Some(serde_json::json!({"errorClass": error.error_class()}));
    match error {
        GatewayError::PayloadRejected(_) => {
            ErrorData::invalid_params("clinical request was rejected", data)
        }
        GatewayError::PolicyDenied
        | GatewayError::ContextGrantRequired
        | GatewayError::ContextGrantUnavailable
        | GatewayError::GrantBindingMismatch
        | GatewayError::GrantExpired
        | GatewayError::GrantScopeInsufficient
        | GatewayError::ApprovalRequired
        | GatewayError::IdempotencyKeyRequired
        | GatewayError::IdempotencyKeyReused
        | GatewayError::IdempotencyOperationInProgress
        | GatewayError::UnknownOperation => {
            ErrorData::invalid_request("clinical operation was denied", data)
        }
        GatewayError::AuthorizationUnavailable
        | GatewayError::DomainUnavailable
        | GatewayError::AuditUnavailable
        | GatewayError::IdempotencyStoreUnavailable
        | GatewayError::ApprovalVerifierUnavailable => {
            ErrorData::internal_error("clinical dependency is unavailable", data)
        }
    }
}

fn excluded_families() -> Vec<&'static str> {
    vec![
        "clinical_orders",
        "case_deletion",
        "phi_export",
        "raw_pixels",
        "shell_and_filesystem",
        "secrets",
        "registry_administration",
        "break_glass",
    ]
}
