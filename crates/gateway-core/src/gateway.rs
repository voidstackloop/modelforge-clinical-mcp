use std::{ops::ControlFlow, sync::Arc};

use uuid::Uuid;

use crate::{
    AdmissionRequest, ApprovalBinding, ApprovalVerifier, AuditEvent, AuditOutcome, AuditSink,
    CatalogEntry, DomainAdapter, GatewayError, GrantResolver, IdempotencyAdmission,
    IdempotencyScope, IdempotencyStore, OperationResponse, PayloadLimits, PolicyEngine,
    PolicySnapshot, RiskClass, arguments_digest, catalog_entry, operation_digest,
};

pub struct Gateway {
    policy: Arc<dyn PolicyEngine>,
    grants: Arc<dyn GrantResolver>,
    domain: Arc<dyn DomainAdapter>,
    audit: Arc<dyn AuditSink>,
    idempotency: Option<Arc<dyn IdempotencyStore>>,
    approval: Option<Arc<dyn ApprovalVerifier>>,
    limits: PayloadLimits,
}

impl Gateway {
    #[must_use]
    pub fn new(
        policy: Arc<dyn PolicyEngine>,
        grants: Arc<dyn GrantResolver>,
        domain: Arc<dyn DomainAdapter>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            policy,
            grants,
            domain,
            audit,
            idempotency: None,
            approval: None,
            limits: PayloadLimits::default(),
        }
    }

    #[must_use]
    pub fn with_limits(mut self, limits: PayloadLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Configures the idempotency store required by any catalog entry with
    /// `idempotency_required: true`. Without one, such an entry fails closed with
    /// [`GatewayError::IdempotencyStoreUnavailable`] rather than silently skipping replay
    /// protection.
    #[must_use]
    pub fn with_idempotency_store(mut self, idempotency: Arc<dyn IdempotencyStore>) -> Self {
        self.idempotency = Some(idempotency);
        self
    }

    /// Configures the approval verifier required by any catalog entry with
    /// `risk: RiskClass::ControlledWrite`. Without one, such an entry fails closed with
    /// [`GatewayError::ApprovalVerifierUnavailable`] rather than accepting any non-empty ticket
    /// string.
    #[must_use]
    pub fn with_approval_verifier(mut self, approval: Arc<dyn ApprovalVerifier>) -> Self {
        self.approval = Some(approval);
        self
    }

    /// Admits and executes one operation through the configured policy and domain ports.
    ///
    /// # Errors
    ///
    /// Returns a typed, non-PHI error when validation, authorization, grant resolution, audit, or
    /// the downstream domain service fails.
    pub async fn execute(
        &self,
        request: AdmissionRequest,
    ) -> Result<OperationResponse, GatewayError> {
        let operation_id = Uuid::new_v4();
        let Some(entry) = catalog_entry(&request.tool_name) else {
            self.record_unknown_operation(operation_id, &request)
                .await?;
            return Err(GatewayError::UnknownOperation);
        };

        let admission = self.admit(&request, &entry).await;
        let (grant, snapshot) = match admission {
            Ok(admission) => admission,
            Err(error) => {
                self.record_outcome(
                    operation_id,
                    &request,
                    &entry,
                    AuditOutcome::Denied,
                    None,
                    Some(error.error_class()),
                )
                .await?;
                return Err(error);
            }
        };
        let digest = operation_digest(
            &entry.name,
            &request.arguments,
            &request.subject,
            grant.as_ref(),
            &snapshot,
        );

        self.check_approval(operation_id, &request, &entry, &digest, &snapshot)
            .await?;

        self.record_outcome(
            operation_id,
            &request,
            &entry,
            AuditOutcome::Admitted,
            Some(&snapshot.tool_policy_version),
            None,
        )
        .await?;

        let idempotency = match self
            .resolve_idempotency(operation_id, &request, &entry, &digest, &snapshot)
            .await?
        {
            ControlFlow::Break(response) => return Ok(response),
            ControlFlow::Continue(scope) => scope,
        };

        let execution = self
            .domain
            .call(
                &request.subject,
                &entry,
                grant.as_ref(),
                request.arguments.clone(),
            )
            .await
            .and_then(|result| {
                self.limits.validate(&result)?;
                Ok(result)
            });
        let result = match execution {
            Ok(result) => result,
            Err(error) => {
                if let (Some(scope), Some(store)) = (&idempotency, &self.idempotency) {
                    store.abort(scope).await?;
                }
                self.record_outcome(
                    operation_id,
                    &request,
                    &entry,
                    AuditOutcome::Failed,
                    Some(&snapshot.tool_policy_version),
                    Some(error.error_class()),
                )
                .await?;
                return Err(error);
            }
        };

        if let (Some(scope), Some(store)) = (&idempotency, &self.idempotency) {
            let digest = arguments_digest(&entry.name, &request.arguments);
            store.complete(scope, &digest, &result).await?;
        }

        self.record_outcome(
            operation_id,
            &request,
            &entry,
            AuditOutcome::Succeeded,
            Some(&snapshot.tool_policy_version),
            None,
        )
        .await?;

        Ok(OperationResponse {
            operation_id,
            operation_digest: digest,
            policy_snapshot: snapshot,
            result,
        })
    }

    async fn record_unknown_operation(
        &self,
        operation_id: Uuid,
        request: &AdmissionRequest,
    ) -> Result<(), GatewayError> {
        self.audit
            .record(AuditEvent {
                operation_id,
                subject_id: request.subject.subject_id.clone(),
                client_id: request.subject.client_id.clone(),
                organization_id: request.subject.organization_id.clone(),
                tool_name: request.tool_name.clone(),
                risk: RiskClass::Prohibited,
                outcome: AuditOutcome::Denied,
                policy_version: None,
                error_class: Some(GatewayError::UnknownOperation.error_class().to_owned()),
            })
            .await
    }

    /// Resolves the idempotency admission for `entry`, if it requires one. Returns
    /// [`ControlFlow::Break`] with the response `execute` should return immediately (an exact
    /// replay), or [`ControlFlow::Continue`] with the reserved scope (if any) `execute` must
    /// later `complete` or `abort`.
    async fn resolve_idempotency(
        &self,
        operation_id: Uuid,
        request: &AdmissionRequest,
        entry: &CatalogEntry,
        digest: &str,
        snapshot: &PolicySnapshot,
    ) -> Result<ControlFlow<OperationResponse, Option<IdempotencyScope>>, GatewayError> {
        if !entry.idempotency_required {
            return Ok(ControlFlow::Continue(None));
        }
        match self.begin_idempotent(request, entry).await {
            Ok(IdempotencyAdmission::Replay(result)) => {
                self.record_outcome(
                    operation_id,
                    request,
                    entry,
                    AuditOutcome::Succeeded,
                    Some(&snapshot.tool_policy_version),
                    None,
                )
                .await?;
                Ok(ControlFlow::Break(OperationResponse {
                    operation_id,
                    operation_digest: digest.to_owned(),
                    policy_snapshot: snapshot.clone(),
                    result,
                }))
            }
            Ok(IdempotencyAdmission::Fresh) => Ok(ControlFlow::Continue(Some(idempotent_scope(
                request, entry,
            )?))),
            Err(error) => {
                self.record_outcome(
                    operation_id,
                    request,
                    entry,
                    AuditOutcome::Denied,
                    Some(&snapshot.tool_policy_version),
                    Some(error.error_class()),
                )
                .await?;
                Err(error)
            }
        }
    }

    async fn begin_idempotent(
        &self,
        request: &AdmissionRequest,
        entry: &CatalogEntry,
    ) -> Result<IdempotencyAdmission, GatewayError> {
        let store = self
            .idempotency
            .as_ref()
            .ok_or(GatewayError::IdempotencyStoreUnavailable)?;
        let scope = idempotent_scope(request, entry)?;
        let digest = arguments_digest(&entry.name, &request.arguments);
        store.begin(&scope, &digest).await
    }

    /// Verifies the approval ticket for a `RiskClass::ControlledWrite` entry against the full
    /// `operation_digest` (already bound to subject, client, grant, and policy version), so a
    /// ticket approved for one operation can never satisfy a different one. No-op for any other
    /// risk class.
    async fn verify_approval(
        &self,
        request: &AdmissionRequest,
        entry: &CatalogEntry,
        digest: &str,
    ) -> Result<(), GatewayError> {
        if entry.risk != RiskClass::ControlledWrite {
            return Ok(());
        }
        let verifier = self
            .approval
            .as_ref()
            .ok_or(GatewayError::ApprovalVerifierUnavailable)?;
        let ticket = request
            .approval_ticket
            .as_deref()
            .ok_or(GatewayError::ApprovalRequired)?;
        let binding = ApprovalBinding {
            subject_id: &request.subject.subject_id,
            client_id: &request.subject.client_id,
            tool_name: &entry.name,
            operation_digest: digest,
        };
        verifier
            .verify_and_consume(ticket, &binding, request.now_epoch_seconds)
            .await
    }

    /// Runs `verify_approval` and records a `Denied` audit event on failure before propagating
    /// the error, matching every other admission-denial path.
    async fn check_approval(
        &self,
        operation_id: Uuid,
        request: &AdmissionRequest,
        entry: &CatalogEntry,
        digest: &str,
        snapshot: &PolicySnapshot,
    ) -> Result<(), GatewayError> {
        if let Err(error) = self.verify_approval(request, entry, digest).await {
            self.record_outcome(
                operation_id,
                request,
                entry,
                AuditOutcome::Denied,
                Some(&snapshot.tool_policy_version),
                Some(error.error_class()),
            )
            .await?;
            return Err(error);
        }
        Ok(())
    }

    async fn admit(
        &self,
        request: &AdmissionRequest,
        entry: &crate::CatalogEntry,
    ) -> Result<(Option<crate::ContextGrant>, crate::PolicySnapshot), GatewayError> {
        self.limits.validate(&request.arguments)?;
        if entry.risk == RiskClass::Prohibited {
            return Err(GatewayError::PolicyDenied);
        }
        if entry.risk == RiskClass::ControlledWrite && request.approval_ticket.is_none() {
            return Err(GatewayError::ApprovalRequired);
        }
        if entry.idempotency_required && request.idempotency_key.is_none() {
            return Err(GatewayError::IdempotencyKeyRequired);
        }
        let grant = if entry.requires_context_grant() {
            let grant_id = request
                .context_grant_id
                .as_deref()
                .ok_or(GatewayError::ContextGrantRequired)?;
            let resolved = self.grants.resolve(grant_id).await?;
            resolved.validate_binding(&request.subject, entry, request.now_epoch_seconds)?;
            Some(resolved)
        } else {
            None
        };
        let snapshot = self
            .policy
            .authorize(&request.subject, entry, grant.as_ref())
            .await?;
        Ok((grant, snapshot))
    }

    async fn record_outcome(
        &self,
        operation_id: Uuid,
        request: &AdmissionRequest,
        entry: &crate::CatalogEntry,
        outcome: AuditOutcome,
        policy_version: Option<&str>,
        error_class: Option<&str>,
    ) -> Result<(), GatewayError> {
        self.audit
            .record(AuditEvent {
                operation_id,
                subject_id: request.subject.subject_id.clone(),
                client_id: request.subject.client_id.clone(),
                organization_id: request.subject.organization_id.clone(),
                tool_name: entry.name.clone(),
                risk: entry.risk,
                outcome,
                policy_version: policy_version.map(str::to_owned),
                error_class: error_class.map(str::to_owned),
            })
            .await
    }
}

fn idempotent_scope(
    request: &AdmissionRequest,
    entry: &CatalogEntry,
) -> Result<IdempotencyScope, GatewayError> {
    let idempotency_key = request
        .idempotency_key
        .clone()
        .ok_or(GatewayError::IdempotencyKeyRequired)?;
    Ok(IdempotencyScope {
        organization_id: request.subject.organization_id.clone(),
        subject_id: request.subject.subject_id.clone(),
        tool_name: entry.name.clone(),
        idempotency_key,
    })
}

// The real catalog `Gateway::execute` looks entries up in never declares a `RiskClass::Prohibited`
// entry (by design: nothing prohibited should be an advertised tool at all), so the `admit()`
// guard against it can't be exercised through the public `execute()` API with any real catalog
// entry. Unit-testing `admit()` directly against a hand-built `CatalogEntry` is the only way to
// cover this private defense-in-depth check.
#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "test fixtures use expect for immediate, contextual failures"
)]
mod tests {
    use std::collections::BTreeSet;

    use async_trait::async_trait;
    use serde_json::json;

    use super::{
        AdmissionRequest, AuditEvent, AuditSink, DomainAdapter, Gateway, GatewayError,
        GrantResolver, PolicyEngine, RiskClass,
    };
    use crate::{CatalogEntry, ContextGrant, EgressClass, PolicySnapshot, SubjectContext};

    #[derive(Default)]
    struct UnreachablePolicy;

    #[async_trait]
    impl PolicyEngine for UnreachablePolicy {
        async fn authorize(
            &self,
            _subject: &SubjectContext,
            _operation: &CatalogEntry,
            _grant: Option<&ContextGrant>,
        ) -> Result<PolicySnapshot, GatewayError> {
            unreachable!("a Prohibited operation must be rejected before policy is consulted")
        }
    }

    #[derive(Default)]
    struct UnreachableGrants;

    #[async_trait]
    impl GrantResolver for UnreachableGrants {
        async fn resolve(&self, _grant_id: &str) -> Result<ContextGrant, GatewayError> {
            unreachable!("a Prohibited operation must be rejected before grant resolution")
        }
    }

    #[derive(Default)]
    struct UnreachableDomain;

    #[async_trait]
    impl DomainAdapter for UnreachableDomain {
        async fn call(
            &self,
            _subject: &SubjectContext,
            _operation: &CatalogEntry,
            _grant: Option<&ContextGrant>,
            _arguments: serde_json::Value,
        ) -> Result<serde_json::Value, GatewayError> {
            unreachable!("a Prohibited operation must be rejected before dispatch")
        }
    }

    #[derive(Default)]
    struct NullAudit;

    #[async_trait]
    impl AuditSink for NullAudit {
        async fn record(&self, _event: AuditEvent) -> Result<(), GatewayError> {
            Ok(())
        }
    }

    fn prohibited_entry() -> CatalogEntry {
        CatalogEntry {
            name: "clinical_orders.place".into(),
            description: "hypothetical prohibited operation".into(),
            risk: RiskClass::Prohibited,
            egress: EgressClass::None,
            phi_fields: BTreeSet::new(),
            idempotency_required: false,
        }
    }

    fn idempotent_entry() -> CatalogEntry {
        CatalogEntry {
            name: "clinical_orders.record_review_decision".into(),
            description: "hypothetical idempotent controlled write".into(),
            risk: crate::RiskClass::ControlledWrite,
            egress: EgressClass::None,
            phi_fields: BTreeSet::new(),
            idempotency_required: true,
        }
    }

    fn subject() -> SubjectContext {
        SubjectContext {
            subject_id: "clinician-7".into(),
            client_id: "desktop-2".into(),
            organization_id: "org-3".into(),
            roles: BTreeSet::from(["clinician".into()]),
            scopes: BTreeSet::from(["clinical:read".into()]),
            authentication_strength: "local-attested".into(),
        }
    }

    #[tokio::test]
    async fn prohibited_risk_is_rejected_before_policy_grant_or_dispatch() {
        let gateway = Gateway::new(
            std::sync::Arc::new(UnreachablePolicy),
            std::sync::Arc::new(UnreachableGrants),
            std::sync::Arc::new(UnreachableDomain),
            std::sync::Arc::new(NullAudit),
        );
        let error = gateway
            .admit(
                &AdmissionRequest {
                    subject: subject(),
                    tool_name: "clinical_orders.place".into(),
                    arguments: json!({}),
                    context_grant_id: None,
                    approval_ticket: None,
                    idempotency_key: None,
                    now_epoch_seconds: 1_000,
                },
                &prohibited_entry(),
            )
            .await;
        assert_eq!(error.err(), Some(GatewayError::PolicyDenied));
    }

    fn idempotent_request(idempotency_key: &str) -> AdmissionRequest {
        AdmissionRequest {
            subject: subject(),
            tool_name: "clinical_orders.record_review_decision".into(),
            arguments: json!({"decision": "approved"}),
            context_grant_id: None,
            approval_ticket: Some("ticket".into()),
            idempotency_key: Some(idempotency_key.into()),
            now_epoch_seconds: 1_000,
        }
    }

    #[tokio::test]
    async fn begin_idempotent_fails_closed_without_a_configured_store() {
        let gateway = Gateway::new(
            std::sync::Arc::new(UnreachablePolicy),
            std::sync::Arc::new(UnreachableGrants),
            std::sync::Arc::new(UnreachableDomain),
            std::sync::Arc::new(NullAudit),
        );
        let error = gateway
            .begin_idempotent(&idempotent_request("key-1"), &idempotent_entry())
            .await;
        assert_eq!(error.err(), Some(GatewayError::IdempotencyStoreUnavailable));
    }

    #[tokio::test]
    async fn begin_idempotent_reserves_and_replays_through_the_configured_store() {
        let gateway = Gateway::new(
            std::sync::Arc::new(UnreachablePolicy),
            std::sync::Arc::new(UnreachableGrants),
            std::sync::Arc::new(UnreachableDomain),
            std::sync::Arc::new(NullAudit),
        )
        .with_idempotency_store(std::sync::Arc::new(
            crate::InMemoryIdempotencyStore::default(),
        ));
        let entry = idempotent_entry();

        let first = gateway
            .begin_idempotent(&idempotent_request("key-1"), &entry)
            .await;
        assert!(matches!(first, Ok(crate::IdempotencyAdmission::Fresh)));

        let concurrent = gateway
            .begin_idempotent(&idempotent_request("key-1"), &entry)
            .await;
        assert_eq!(
            concurrent.err(),
            Some(GatewayError::IdempotencyOperationInProgress)
        );

        let different_key = gateway
            .begin_idempotent(&idempotent_request("key-2"), &entry)
            .await;
        assert!(matches!(
            different_key,
            Ok(crate::IdempotencyAdmission::Fresh)
        ));
    }

    #[tokio::test]
    async fn verify_approval_fails_closed_without_a_configured_verifier() {
        let gateway = Gateway::new(
            std::sync::Arc::new(UnreachablePolicy),
            std::sync::Arc::new(UnreachableGrants),
            std::sync::Arc::new(UnreachableDomain),
            std::sync::Arc::new(NullAudit),
        );
        let error = gateway
            .verify_approval(
                &idempotent_request("key-1"),
                &idempotent_entry(),
                "digest-a",
            )
            .await;
        assert_eq!(error.err(), Some(GatewayError::ApprovalVerifierUnavailable));
    }

    #[tokio::test]
    async fn verify_approval_is_a_no_op_for_non_controlled_write_risk() {
        let gateway = Gateway::new(
            std::sync::Arc::new(UnreachablePolicy),
            std::sync::Arc::new(UnreachableGrants),
            std::sync::Arc::new(UnreachableDomain),
            std::sync::Arc::new(NullAudit),
        );
        let result = gateway
            .verify_approval(
                &AdmissionRequest {
                    subject: subject(),
                    tool_name: "clinical_orders.place".into(),
                    arguments: json!({}),
                    context_grant_id: None,
                    approval_ticket: None,
                    idempotency_key: None,
                    now_epoch_seconds: 1_000,
                },
                &prohibited_entry(),
                "digest-a",
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn verify_approval_accepts_a_ticket_bound_to_the_exact_digest_and_rejects_others() {
        let verifier = std::sync::Arc::new(crate::HmacApprovalVerifier::new(b"test-secret"));
        let gateway = Gateway::new(
            std::sync::Arc::new(UnreachablePolicy),
            std::sync::Arc::new(UnreachableGrants),
            std::sync::Arc::new(UnreachableDomain),
            std::sync::Arc::new(NullAudit),
        )
        .with_approval_verifier(verifier.clone());
        let entry = idempotent_entry();

        let ticket = verifier
            .issue(
                &crate::ApprovalBinding {
                    subject_id: &subject().subject_id,
                    client_id: &subject().client_id,
                    tool_name: &entry.name,
                    operation_digest: "digest-a",
                },
                2_000,
            )
            .expect("issue ticket");
        let mut request = idempotent_request("key-1");
        request.approval_ticket = Some(ticket);

        let wrong_digest = gateway.verify_approval(&request, &entry, "digest-b").await;
        assert_eq!(wrong_digest.err(), Some(GatewayError::ApprovalRequired));

        gateway
            .verify_approval(&request, &entry, "digest-a")
            .await
            .expect("matching digest is accepted");

        let reused = gateway.verify_approval(&request, &entry, "digest-a").await;
        assert_eq!(reused.err(), Some(GatewayError::ApprovalRequired));
    }
}
