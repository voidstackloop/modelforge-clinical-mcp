//! `clinical.record_review_decision`: the design doc's first named controlled-write tool
//! ("Should V1 remain entirely read-only, or include `record_review_decision` and
//! `submit_compute_request` as the first controlled writes? Recommendation: read-only plus
//! those two narrowly idempotent writes"). Recording a decision is inherently a remote write —
//! unlike the medication check, there is no local, deterministic implementation possible — so
//! the only concrete `ReviewDecisionService` here calls out to an existing `ModelForge` review
//! service, the same "adapter, not source of truth" shape as [`crate::HttpGrantResolver`].

use std::sync::Arc;

use async_trait::async_trait;
use reqwest::Client;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{CatalogEntry, ContextGrant, DomainAdapter, GatewayError, SubjectContext};

pub(crate) const TOOL_NAME: &str = "clinical.record_review_decision";
const MAX_RATIONALE_BYTES: usize = 2_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecisionOutcome {
    Approved,
    Rejected,
    NeedsRevision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewDecisionArguments {
    /// The `operationId` (from a prior `OperationResponse`) this review is about.
    pub reviewed_operation_id: Uuid,
    pub decision: ReviewDecisionOutcome,
    pub rationale: String,
}

/// The reviewer's identity and case binding come from the verified subject and the resolved
/// context grant — never from `ReviewDecisionArguments` — matching every other tool's rule that
/// no inbound subject, organization, or case identity is accepted from tool arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewDecisionRequest {
    pub organization_id: String,
    pub case_id: String,
    pub reviewer_subject_id: String,
    pub reviewed_operation_id: Uuid,
    pub decision: ReviewDecisionOutcome,
    pub rationale: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewDecisionResult {
    pub review_id: Uuid,
    pub decision: ReviewDecisionOutcome,
}

#[async_trait]
pub trait ReviewDecisionService: Send + Sync {
    async fn record(
        &self,
        request: ReviewDecisionRequest,
    ) -> Result<ReviewDecisionResult, GatewayError>;
}

/// Narrow adapter that can call only the review-decision service port.
pub struct ReviewDomainAdapter {
    reviews: Arc<dyn ReviewDecisionService>,
}

impl ReviewDomainAdapter {
    #[must_use]
    pub fn new(reviews: Arc<dyn ReviewDecisionService>) -> Self {
        Self { reviews }
    }
}

#[async_trait]
impl DomainAdapter for ReviewDomainAdapter {
    async fn call(
        &self,
        subject: &SubjectContext,
        operation: &CatalogEntry,
        grant: Option<&ContextGrant>,
        arguments: Value,
    ) -> Result<Value, GatewayError> {
        if operation.name != TOOL_NAME {
            return Err(GatewayError::UnknownOperation);
        }
        let grant = grant.ok_or(GatewayError::ContextGrantRequired)?;
        let arguments: ReviewDecisionArguments = serde_json::from_value(arguments)
            .map_err(|_| GatewayError::PayloadRejected("invalid review decision input"))?;
        validate_rationale(&arguments.rationale)?;
        let result = self
            .reviews
            .record(ReviewDecisionRequest {
                organization_id: subject.organization_id.clone(),
                case_id: grant.case_id.clone(),
                reviewer_subject_id: subject.subject_id.clone(),
                reviewed_operation_id: arguments.reviewed_operation_id,
                decision: arguments.decision,
                rationale: arguments.rationale,
            })
            .await?;
        serde_json::to_value(result).map_err(|_| GatewayError::DomainUnavailable)
    }
}

fn validate_rationale(value: &str) -> Result<(), GatewayError> {
    if value.trim().is_empty()
        || value.len() > MAX_RATIONALE_BYTES
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err(GatewayError::PayloadRejected(
            "rationale is empty, too long, or contains control characters",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReviewDecisionRequestBody<'a> {
    organization_id: &'a str,
    case_id: &'a str,
    reviewer_subject_id: &'a str,
    reviewed_operation_id: Uuid,
    decision: ReviewDecisionOutcome,
    rationale: &'a str,
}

/// Records review decisions by calling an existing `ModelForge` review service over HTTPS —
/// this repository stores no review history itself, matching the same boundary
/// [`crate::HttpGrantResolver`] draws for grants.
pub struct HttpReviewDecisionService {
    client: Client,
    base_url: String,
}

impl HttpReviewDecisionService {
    /// `base_url` must be an `https://` origin; decisions are recorded as
    /// `POST {base_url}/reviews`.
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
impl ReviewDecisionService for HttpReviewDecisionService {
    async fn record(
        &self,
        request: ReviewDecisionRequest,
    ) -> Result<ReviewDecisionResult, GatewayError> {
        let url = format!("{}/reviews", self.base_url.trim_end_matches('/'));
        let response = self
            .client
            .post(url)
            .json(&ReviewDecisionRequestBody {
                organization_id: &request.organization_id,
                case_id: &request.case_id,
                reviewer_subject_id: &request.reviewer_subject_id,
                reviewed_operation_id: request.reviewed_operation_id,
                decision: request.decision,
                rationale: &request.rationale,
            })
            .send()
            .await
            .map_err(|_| GatewayError::DomainUnavailable)?;
        if !response.status().is_success() {
            return Err(GatewayError::DomainUnavailable);
        }
        response
            .json::<ReviewDecisionResult>()
            .await
            .map_err(|_| GatewayError::DomainUnavailable)
    }
}
