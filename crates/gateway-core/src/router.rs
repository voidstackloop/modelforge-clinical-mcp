use std::{collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use serde_json::Value;

use crate::{CatalogEntry, ContextGrant, DomainAdapter, GatewayError, SubjectContext};

/// Composes multiple narrow, single-family domain adapters (clinical, runtime, and future
/// evidence/compute adapters) behind the single `DomainAdapter` port `Gateway` accepts,
/// dispatching each call by catalog tool name. Deployment wiring registers only the adapters
/// it has trusted ports for; any catalog entry without a registered route fails closed.
#[derive(Default)]
pub struct DomainRouter {
    routes: BTreeMap<&'static str, Arc<dyn DomainAdapter>>,
}

impl DomainRouter {
    #[must_use]
    pub fn new() -> Self {
        Self {
            routes: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn with_route(mut self, tool_name: &'static str, adapter: Arc<dyn DomainAdapter>) -> Self {
        self.routes.insert(tool_name, adapter);
        self
    }
}

#[async_trait]
impl DomainAdapter for DomainRouter {
    async fn call(
        &self,
        subject: &SubjectContext,
        operation: &CatalogEntry,
        grant: Option<&ContextGrant>,
        arguments: Value,
    ) -> Result<Value, GatewayError> {
        let adapter = self
            .routes
            .get(operation.name.as_str())
            .ok_or(GatewayError::UnknownOperation)?;
        adapter.call(subject, operation, grant, arguments).await
    }
}
