//! `clinical.submit_compute_request`: the design doc's second named controlled-write tool,
//! alongside `clinical.record_review_decision` ("Should V1 remain entirely read-only, or
//! include `record_review_decision` and `submit_compute_request` as the first controlled
//! writes?"). Submitting a compute request is inherently a remote write against `ModelForge`'s
//! own compute-control-plane scheduler (`packages/contracts/src/compute.ts`,
//! `server/src/compute/control-plane.ts` in the main app) — this repository does not
//! reimplement bin-packing or node scheduling, only forwards a typed, organization-bound
//! request, the same "adapter, not source of truth" shape as [`crate::HttpGrantResolver`] and
//! [`crate::HttpReviewDecisionService`].

use std::sync::Arc;

use async_trait::async_trait;
use reqwest::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{CatalogEntry, ContextGrant, DomainAdapter, GatewayError, SubjectContext};

pub(crate) const TOOL_NAME: &str = "clinical.submit_compute_request";
const MAX_IDENTIFIER_BYTES: usize = 200;
const MAX_ACCELERATOR_DEVICE_IDS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ComputePriority {
    Interactive,
    Imaging,
    Scheduled,
    Background,
    Maintenance,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceProfile {
    Interactive,
    Balanced,
    Throughput,
    EnergyEfficient,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ComputeRuntime {
    Llamacpp,
    Vllm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AcceleratorVendor {
    Nvidia,
    Amd,
    Intel,
    Apple,
    Other,
}

/// Mirrors `resourceRequirementsSchema` in `packages/contracts/src/compute.ts`, restricted to
/// the fields a caller may request (the real schema's cross-field `superRefine` checks are
/// re-enforced in [`validate_requirements`] since `serde` cannot express them).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "mirrors resourceRequirementsSchema's four independent scheduling-hint flags in packages/contracts/src/compute.ts byte-for-byte; splitting them into enums would drift from that source of truth"
)]
pub struct ResourceRequirements {
    pub cpu_threads: u32,
    /// `#[serde(rename)]` because `packages/contracts/src/compute.ts` spells this `ramMB`
    /// (capital MB, an abbreviation) — the automatic `camelCase` conversion of `ram_mb` would
    /// instead produce `ramMb`.
    #[serde(rename = "ramMB")]
    pub ram_mb: u64,
    #[serde(default, rename = "pinnedMemoryMB")]
    pub pinned_memory_mb: u64,
    #[serde(default)]
    pub accelerator_count: u32,
    #[serde(default)]
    pub accelerator_device_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accelerator_vendor: Option<AcceleratorVendor>,
    #[serde(default, rename = "vramMBPerDevice")]
    pub vram_mb_per_device: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute_capability: Option<String>,
    #[serde(default)]
    pub same_numa_node: bool,
    #[serde(default = "default_true")]
    pub same_vendor: bool,
    #[serde(default = "default_true")]
    pub exclusive_accelerators: bool,
    pub runtime: ComputeRuntime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(default)]
    pub allow_cpu_fallback: bool,
}

const fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComputeSubmitArguments {
    pub pool_id: String,
    pub workload_kind: String,
    pub priority: ComputePriority,
    #[serde(default = "ResourceProfile::default_profile")]
    pub profile: ResourceProfile,
    pub requirements: ResourceRequirements,
    #[serde(default)]
    pub checkpointable: bool,
    #[serde(default)]
    pub restartable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_at: Option<String>,
}

impl ResourceProfile {
    const fn default_profile() -> Self {
        Self::Balanced
    }
}

/// The submitting organization and subject come from the verified subject context — never from
/// `ComputeSubmitArguments` — matching every other tool's rule that no inbound organization or
/// subject identity is accepted from tool arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComputeSubmitRequest {
    pub organization_id: String,
    pub submitted_by_subject_id: String,
    pub pool_id: String,
    pub workload_kind: String,
    pub priority: ComputePriority,
    pub profile: ResourceProfile,
    pub requirements: ResourceRequirements,
    pub checkpointable: bool,
    pub restartable: bool,
    pub deadline_at: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComputeSchedulingStatus {
    Placed,
    Queued,
    Rejected,
}

/// Mirrors the `{ request, decision, lease }` shape of `SubmitResult` in
/// `server/src/compute/control-plane.ts`, projected down to what a caller needs to know: the
/// request's assigned id, the scheduler's decision, and (when placed) the lease id, never the
/// full node/accelerator inventory that decision carries internally.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ComputeSubmitResult {
    pub request_id: String,
    pub pool_id: String,
    pub status: ComputeSchedulingStatus,
    pub reasons: Vec<String>,
    pub lease_id: Option<String>,
}

#[async_trait]
pub trait ComputeSubmitService: Send + Sync {
    async fn submit(
        &self,
        request: ComputeSubmitRequest,
    ) -> Result<ComputeSubmitResult, GatewayError>;
}

/// Submitting a compute request has no meaningful local fallback (there is no deterministic,
/// in-repository scheduler to run instead), so a deployment that hasn't configured a compute
/// control-plane URL yet gets this: the tool stays listed and reachable but fails closed rather
/// than fabricating a placement decision, the same shape as
/// [`crate::UnconfiguredRuntimeDiagnostics`] and [`crate::UnconfiguredReviewDecisionService`].
#[derive(Default)]
pub struct UnconfiguredComputeSubmitService;

#[async_trait]
impl ComputeSubmitService for UnconfiguredComputeSubmitService {
    async fn submit(
        &self,
        _request: ComputeSubmitRequest,
    ) -> Result<ComputeSubmitResult, GatewayError> {
        Err(GatewayError::DomainUnavailable)
    }
}

/// Narrow adapter that can call only the compute-submission service port. Carries no PHI and
/// requires no context grant: `clinical.submit_compute_request` has no `phi_fields` in the
/// catalog — a compute job is organization-scoped infrastructure, not clinical case data.
pub struct ComputeDomainAdapter {
    compute: Arc<dyn ComputeSubmitService>,
}

impl ComputeDomainAdapter {
    #[must_use]
    pub fn new(compute: Arc<dyn ComputeSubmitService>) -> Self {
        Self { compute }
    }
}

#[async_trait]
impl DomainAdapter for ComputeDomainAdapter {
    async fn call(
        &self,
        subject: &SubjectContext,
        operation: &CatalogEntry,
        _grant: Option<&ContextGrant>,
        arguments: Value,
    ) -> Result<Value, GatewayError> {
        if operation.name != TOOL_NAME {
            return Err(GatewayError::UnknownOperation);
        }
        let arguments: ComputeSubmitArguments = serde_json::from_value(arguments)
            .map_err(|_| GatewayError::PayloadRejected("invalid compute request input"))?;
        validate_identifier(&arguments.pool_id)?;
        validate_identifier(&arguments.workload_kind)?;
        validate_requirements(&arguments.requirements)?;
        let result = self
            .compute
            .submit(ComputeSubmitRequest {
                organization_id: subject.organization_id.clone(),
                submitted_by_subject_id: subject.subject_id.clone(),
                pool_id: arguments.pool_id,
                workload_kind: arguments.workload_kind,
                priority: arguments.priority,
                profile: arguments.profile,
                requirements: arguments.requirements,
                checkpointable: arguments.checkpointable,
                restartable: arguments.restartable,
                deadline_at: arguments.deadline_at,
            })
            .await?;
        serde_json::to_value(result).map_err(|_| GatewayError::DomainUnavailable)
    }
}

fn validate_identifier(value: &str) -> Result<(), GatewayError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES {
        return Err(GatewayError::PayloadRejected(
            "pool id or workload kind is empty or too long",
        ));
    }
    Ok(())
}

/// Re-enforces `resourceRequirementsSchema`'s `superRefine` checks from
/// `packages/contracts/src/compute.ts`, since `serde` validates shape but not these cross-field
/// invariants.
fn validate_requirements(requirements: &ResourceRequirements) -> Result<(), GatewayError> {
    if requirements.cpu_threads == 0 {
        return Err(GatewayError::PayloadRejected("cpuThreads must be positive"));
    }
    if requirements.accelerator_device_ids.len() > MAX_ACCELERATOR_DEVICE_IDS {
        return Err(GatewayError::PayloadRejected(
            "acceleratorDeviceIds exceeded the maximum count",
        ));
    }
    if !requirements.accelerator_device_ids.is_empty()
        && requirements.accelerator_count as usize != requirements.accelerator_device_ids.len()
    {
        return Err(GatewayError::PayloadRejected(
            "acceleratorCount must match explicit acceleratorDeviceIds",
        ));
    }
    if requirements.accelerator_count == 0 && requirements.vram_mb_per_device > 0 {
        return Err(GatewayError::PayloadRejected(
            "VRAM cannot be requested without an accelerator",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ComputeSubmitRequestBody<'a> {
    submitted_by_subject_id: &'a str,
    pool_id: &'a str,
    workload_kind: &'a str,
    priority: ComputePriority,
    profile: ResourceProfile,
    requirements: &'a ResourceRequirements,
    checkpointable: bool,
    restartable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    deadline_at: Option<&'a str>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ComputeSubmitResponseBody {
    request: ComputeSubmitResponseRequest,
    decision: ComputeSubmitResponseDecision,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ComputeSubmitResponseRequest {
    id: String,
    #[serde(rename = "poolId")]
    pool_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ComputeSubmitResponseDecision {
    status: ComputeSchedulingStatus,
    #[serde(default)]
    reasons: Vec<String>,
    lease_id: Option<String>,
}

/// Submits compute requests by calling an existing `ModelForge` compute-control-plane service
/// over HTTPS — this repository stores no node inventory, scheduling state, or leases itself.
pub struct HttpComputeSubmitService {
    client: Client,
    base_url: String,
}

impl HttpComputeSubmitService {
    /// `base_url` must be an `https://` origin; requests are submitted as
    /// `POST {base_url}/organizations/{organizationId}/compute/requests`.
    ///
    /// # Errors
    ///
    /// Returns an error if `base_url` is not a well-formed HTTPS URL or the HTTP client cannot
    /// be constructed.
    pub fn new(base_url: impl Into<String>) -> Result<Self, GatewayError> {
        let base_url = base_url.into();
        if !base_url.starts_with("https://") {
            return Err(GatewayError::DomainUnavailable);
        }
        let client = Client::builder()
            .build()
            .map_err(|_| GatewayError::DomainUnavailable)?;
        Ok(Self { client, base_url })
    }
}

#[async_trait]
impl ComputeSubmitService for HttpComputeSubmitService {
    async fn submit(
        &self,
        request: ComputeSubmitRequest,
    ) -> Result<ComputeSubmitResult, GatewayError> {
        let url = format!(
            "{}/organizations/{}/compute/requests",
            self.base_url.trim_end_matches('/'),
            request.organization_id
        );
        let response = self
            .client
            .post(url)
            .json(&ComputeSubmitRequestBody {
                submitted_by_subject_id: &request.submitted_by_subject_id,
                pool_id: &request.pool_id,
                workload_kind: &request.workload_kind,
                priority: request.priority,
                profile: request.profile,
                requirements: &request.requirements,
                checkpointable: request.checkpointable,
                restartable: request.restartable,
                deadline_at: request.deadline_at.as_deref(),
            })
            .send()
            .await
            .map_err(|_| GatewayError::DomainUnavailable)?;
        if !response.status().is_success() {
            return Err(GatewayError::DomainUnavailable);
        }
        let body = response
            .json::<ComputeSubmitResponseBody>()
            .await
            .map_err(|_| GatewayError::DomainUnavailable)?;
        Ok(ComputeSubmitResult {
            request_id: body.request.id,
            pool_id: body.request.pool_id,
            status: body.decision.status,
            reasons: body.decision.reasons,
            lease_id: body.decision.lease_id,
        })
    }
}
