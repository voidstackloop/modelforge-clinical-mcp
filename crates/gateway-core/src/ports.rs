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
