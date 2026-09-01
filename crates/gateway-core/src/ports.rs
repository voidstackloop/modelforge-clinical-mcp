use async_trait::async_trait;
use serde_json::Value;

use crate::{AuditEvent, CatalogEntry, ContextGrant, GatewayError, PolicySnapshot, SubjectContext};

#[async_trait]
pub trait PolicyEngine: Send + Sync {
    async fn authorize(
        &self,
        subject: &SubjectContext,
        operation: &CatalogEntry,
        grant: Option<&ContextGrant>,
    ) -> Result<PolicySnapshot, GatewayError>;
}

#[async_trait]
pub trait GrantResolver: Send + Sync {
    async fn resolve(&self, grant_id: &str) -> Result<ContextGrant, GatewayError>;
}

#[async_trait]
pub trait DomainAdapter: Send + Sync {
    async fn call(
        &self,
        subject: &SubjectContext,
        operation: &CatalogEntry,
        grant: Option<&ContextGrant>,
        arguments: Value,
    ) -> Result<Value, GatewayError>;
}

#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn record(&self, event: AuditEvent) -> Result<(), GatewayError>;
}

/// Identifies one idempotency scope: the same caller, tool, and idempotency key. Two admission
/// requests with the same scope but different normalized arguments are a key reuse, not a
/// retry.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct IdempotencyScope {
    pub organization_id: String,
    pub subject_id: String,
    pub tool_name: String,
    pub idempotency_key: String,
}

/// Everything a replay needs to reconstruct the exact `OperationResponse` the original call
/// returned, without re-running admission: the full `operation_digest` (distinct from the
/// `arguments_digest` used for reuse detection — it also binds subject, grant, and policy
/// version) and the `PolicySnapshot` frozen at the original admission.
#[derive(Clone, Debug)]
pub struct IdempotentCompletion {
    pub operation_digest: String,
    pub policy_snapshot: PolicySnapshot,
    pub result: Value,
}

/// What `IdempotencyStore::begin` found for a scope.
pub enum IdempotencyAdmission {
    /// No prior successful completion recorded for this scope; the caller must execute the
    /// operation and call `complete` with its result.
    Fresh,
    /// A prior call with the same scope and the same normalized-arguments digest already
    /// completed successfully; replay it instead of re-executing — and, critically, instead of
    /// re-running admission or approval verification at all. A single-use approval ticket
    /// cannot be presented again on a retry, so a replay that required re-approval could never
    /// actually succeed; the design doc's "returns [the stored result] for exact replays" means
    /// a replay bypasses re-approval by construction, not that it happens to reuse one.
    Replay(IdempotentCompletion),
}

/// Backs the design doc's idempotency-key replay guarantee: "the server stores the first
/// terminal result for the idempotency scope and returns it for exact replays; a reused key
/// with different normalized arguments is rejected." Deliberately caches only successful
/// completions, not failures — retrying a failed, non-side-effecting attempt (e.g. after a
/// transient dependency outage) should be free to succeed, not be pinned to its first failure.
///
/// `begin` must atomically reserve `scope` (not just check it) so two concurrent callers with
/// the same scope can never both observe [`IdempotencyAdmission::Fresh`] and race the
/// underlying operation twice; the second concurrent caller gets
/// [`GatewayError::IdempotencyOperationInProgress`] instead. A caller that reserved a `Fresh`
/// scope but then fails (admission, approval, or the domain call itself) must call `abort` so a
/// later retry is free to start over rather than being stuck behind a reservation nothing will
/// ever complete.
#[async_trait]
pub trait IdempotencyStore: Send + Sync {
    /// Checks and reserves `scope` for `arguments_digest`.
    ///
    /// # Errors
    ///
    /// Returns [`GatewayError::IdempotencyKeyReused`] when `scope` already completed with a
    /// different digest, [`GatewayError::IdempotencyOperationInProgress`] when another caller
    /// currently holds the reservation for `scope`, or
    /// [`GatewayError::IdempotencyStoreUnavailable`] if the store cannot be reached.
    async fn begin(
        &self,
        scope: &IdempotencyScope,
        arguments_digest: &str,
    ) -> Result<IdempotencyAdmission, GatewayError>;

    /// Records the successful terminal completion for a scope previously reserved via `begin`.
    ///
    /// # Errors
    ///
    /// Returns [`GatewayError::IdempotencyStoreUnavailable`] if the store cannot be reached.
    async fn complete(
        &self,
        scope: &IdempotencyScope,
        arguments_digest: &str,
        completion: IdempotentCompletion,
    ) -> Result<(), GatewayError>;

    /// Releases a reservation previously made via `begin` without completing it, so a later
    /// retry of the same scope is treated as fresh instead of stuck in progress forever.
    ///
    /// # Errors
    ///
    /// Returns [`GatewayError::IdempotencyStoreUnavailable`] if the store cannot be reached.
    async fn abort(&self, scope: &IdempotencyScope) -> Result<(), GatewayError>;
}
