//! Shared, transport-neutral `ModelForge` Clinical MCP admission boundary.

mod approval;
mod audit;
mod catalog;
mod compute;
mod contracts;
mod digest;
mod error;
mod gateway;
mod grant_client;
mod grants;
mod idempotency;
mod limits;
mod medication;
mod medication_safety;
mod policy;
mod ports;
mod prompts;
mod response_contract;
mod review;
mod router;
mod runtime;

pub use approval::{ApprovalBinding, ApprovalVerifier, HmacApprovalVerifier};
pub use audit::FileAuditSink;
pub use catalog::{CATALOG_VERSION, catalog, catalog_entry};
pub use compute::{
    AcceleratorVendor, ComputeDomainAdapter, ComputePriority, ComputeRuntime,
    ComputeSchedulingStatus, ComputeSubmitArguments, ComputeSubmitRequest, ComputeSubmitResult,
    ComputeSubmitService, HttpComputeSubmitService, ResourceProfile, ResourceRequirements,
    UnconfiguredComputeSubmitService,
};
pub use contracts::{
    AdmissionRequest, AuditEvent, AuditOutcome, CatalogEntry, ContextGrant, DestinationClass,
    EgressClass, OperationResponse, PolicySnapshot, RiskClass, SubjectContext,
};
pub use digest::{arguments_digest, operation_digest};
pub use error::GatewayError;
pub use gateway::Gateway;
pub use grant_client::HttpGrantResolver;
pub use grants::{GrantSnapshot, GrantSnapshotError};
pub use idempotency::InMemoryIdempotencyStore;
pub use limits::PayloadLimits;
pub use medication::{
    ClinicalDomainAdapter, MedicationCheckStatus, MedicationConflictArguments,
    MedicationConflictRequest, MedicationConflictResult, MedicationConflictService,
    MedicationConflictWarning, MedicationConflictWarningKind,
};
pub use medication_safety::BuiltInMedicationConflictService;
pub use policy::{PolicySet, PolicySetError, TenantPolicy, ToolEntitlement};
pub use ports::{
    AuditSink, DomainAdapter, GrantResolver, IdempotencyAdmission, IdempotencyScope,
    IdempotencyStore, IdempotentCompletion, PolicyEngine,
};
pub use prompts::{ClinicalPromptTemplate, clinical_response_contract_prompt};
pub use response_contract::{
    RESPONSE_CONTRACT_SECTION_HEADINGS, ResponseContractCheckArguments,
    ResponseContractCheckResult, check_response_contract_compliance,
};
pub use review::{
    HttpReviewDecisionService, ReviewDecisionArguments, ReviewDecisionOutcome,
    ReviewDecisionRequest, ReviewDecisionResult, ReviewDecisionService, ReviewDomainAdapter,
    UnconfiguredReviewDecisionService,
};
pub use router::DomainRouter;
pub use runtime::{
    RuntimeBackendDiagnostics, RuntimeDiagnosticsResult, RuntimeDiagnosticsService,
    RuntimeDomainAdapter, RuntimeLifecycleState, UnconfiguredRuntimeDiagnostics,
};
