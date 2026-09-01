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
