use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum GatewayError {
    #[error("operation is not present in the approved catalog")]
    UnknownOperation,
    #[error("operation is disabled by policy")]
    PolicyDenied,
    #[error("a context grant is required")]
    ContextGrantRequired,
    #[error("context grant is invalid or unavailable")]
    ContextGrantUnavailable,
    #[error("context grant is bound to a different subject, client, or organization")]
    GrantBindingMismatch,
    #[error("context grant has expired")]
    GrantExpired,
    #[error("context grant does not authorize the requested tool and fields")]
    GrantScopeInsufficient,
    #[error("approval ticket is required")]
    ApprovalRequired,
    #[error("approval verifier is unavailable")]
    ApprovalVerifierUnavailable,
    #[error("idempotency key is required")]
    IdempotencyKeyRequired,
    #[error("idempotency key was reused with different arguments")]
    IdempotencyKeyReused,
    #[error("another request is already in progress for this idempotency key")]
    IdempotencyOperationInProgress,
    #[error("idempotency store is unavailable")]
    IdempotencyStoreUnavailable,
    #[error("payload violates gateway limits: {0}")]
    PayloadRejected(&'static str),
    #[error("authorization dependency is unavailable")]
    AuthorizationUnavailable,
    #[error("domain service is unavailable")]
    DomainUnavailable,
    #[error("audit dependency is unavailable")]
    AuditUnavailable,
}

impl GatewayError {
    #[must_use]
    pub const fn error_class(&self) -> &'static str {
        match self {
            Self::UnknownOperation => "unknown_operation",
            Self::PolicyDenied => "policy_denied",
            Self::ContextGrantRequired => "context_grant_required",
            Self::ContextGrantUnavailable => "context_grant_unavailable",
            Self::GrantBindingMismatch => "grant_binding_mismatch",
            Self::GrantExpired => "grant_expired",
            Self::GrantScopeInsufficient => "grant_scope_insufficient",
            Self::ApprovalRequired => "approval_required",
            Self::ApprovalVerifierUnavailable => "approval_verifier_unavailable",
            Self::IdempotencyKeyRequired => "idempotency_key_required",
            Self::IdempotencyKeyReused => "idempotency_key_reused",
            Self::IdempotencyOperationInProgress => "idempotency_operation_in_progress",
            Self::IdempotencyStoreUnavailable => "idempotency_store_unavailable",
            Self::PayloadRejected(_) => "payload_rejected",
            Self::AuthorizationUnavailable => "authorization_unavailable",
            Self::DomainUnavailable => "domain_unavailable",
            Self::AuditUnavailable => "audit_unavailable",
        }
    }
}
