use std::sync::Arc;

use uuid::Uuid;

use crate::{
    AdmissionRequest, AuditEvent, AuditOutcome, AuditSink, DomainAdapter, GatewayError,
    GrantResolver, OperationResponse, PayloadLimits, PolicyEngine, RiskClass, catalog_entry,
    operation_digest,
};

pub struct Gateway {
    policy: Arc<dyn PolicyEngine>,
    grants: Arc<dyn GrantResolver>,
    domain: Arc<dyn DomainAdapter>,
    audit: Arc<dyn AuditSink>,
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
            limits: PayloadLimits::default(),
        }
    }

    #[must_use]
    pub fn with_limits(mut self, limits: PayloadLimits) -> Self {
        self.limits = limits;
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

        self.record_outcome(
            operation_id,
            &request,
            &entry,
            AuditOutcome::Admitted,
            Some(&snapshot.tool_policy_version),
            None,
        )
        .await?;

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

// The real catalog `Gateway::execute` looks entries up in never declares a `RiskClass::Prohibited`
// entry (by design: nothing prohibited should be an advertised tool at all), so the `admit()`
// guard against it can't be exercised through the public `execute()` API with any real catalog
// entry. Unit-testing `admit()` directly against a hand-built `CatalogEntry` is the only way to
// cover this private defense-in-depth check.
#[cfg(test)]
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
}
