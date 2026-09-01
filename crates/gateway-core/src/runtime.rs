use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{CatalogEntry, ContextGrant, DomainAdapter, GatewayError, SubjectContext};

pub(crate) const TOOL_NAME: &str = "runtime.diagnostics";
const MAX_BACKENDS: usize = 16;

/// Mirrors `RuntimeLifecycleState` in `app/src/local-server-manager.ts` in the main
/// `ModelForge` app, restricted to the closed set of values that type can take.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLifecycleState {
    Starting,
    Running,
    Stopping,
    Restarting,
    Unhealthy,
    Failed,
    Stopped,
}

/// A bounded, non-secret projection of one local runtime backend's status. Deliberately
/// excludes everything the upstream `LocalRuntimeStatus` type carries that could leak
/// operational detail: logs, `startupError` text, pid, port, `currentConfig`,
/// `commandCapabilities`, `environmentIssues`, `installCommand`, and free-text `detail` or
/// `model` values, all of which can contain local file paths or other non-clinical secrets.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeBackendDiagnostics {
    pub backend: String,
    pub state: RuntimeLifecycleState,
    pub model_loaded: bool,
    pub uptime_seconds: u64,
    pub active_requests: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeDiagnosticsResult {
    pub backends: Vec<RuntimeBackendDiagnostics>,
}

#[async_trait]
pub trait RuntimeDiagnosticsService: Send + Sync {
    async fn diagnostics(&self) -> Result<RuntimeDiagnosticsResult, GatewayError>;
}

/// Narrow adapter that can call only the runtime-diagnostics service port. Carries no PHI and
/// requires no context grant: `runtime.diagnostics` has no `phi_fields` in the catalog.
pub struct RuntimeDomainAdapter {
    diagnostics: std::sync::Arc<dyn RuntimeDiagnosticsService>,
}

impl RuntimeDomainAdapter {
    #[must_use]
    pub fn new(diagnostics: std::sync::Arc<dyn RuntimeDiagnosticsService>) -> Self {
        Self { diagnostics }
    }
}

#[async_trait]
impl DomainAdapter for RuntimeDomainAdapter {
    async fn call(
        &self,
        _subject: &SubjectContext,
        operation: &CatalogEntry,
        _grant: Option<&ContextGrant>,
        _arguments: Value,
    ) -> Result<Value, GatewayError> {
        if operation.name != TOOL_NAME {
            return Err(GatewayError::UnknownOperation);
        }
        let result = self.diagnostics.diagnostics().await?;
        if result.backends.len() > MAX_BACKENDS {
            return Err(GatewayError::PayloadRejected(
                "runtime diagnostics exceeded the maximum backend count",
            ));
        }
        serde_json::to_value(result).map_err(|_| GatewayError::DomainUnavailable)
    }
}
