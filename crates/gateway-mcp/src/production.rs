//! Composition root for a fully trusted `Gateway`: wires real policy, grant resolution, audit,
//! and domain-service ports together, shared by every transport binary so neither has to
//! duplicate this wiring. Reading the configuration itself (environment variables, CLI flags)
//! stays the caller's job — this module only turns already-resolved values into a `Gateway`.

use std::{path::PathBuf, sync::Arc};

use modelforge_clinical_mcp_core::{
    BuiltInMedicationConflictService, ClinicalDomainAdapter, DomainAdapter, DomainRouter,
    FileAuditSink, Gateway, HmacApprovalVerifier, HttpGrantResolver, InMemoryIdempotencyStore,
    PolicySet, PolicySnapshot, RuntimeDomainAdapter, TenantPolicy, UnconfiguredRuntimeDiagnostics,
};
use serde::Deserialize;

/// Resolved configuration for wiring a fully trusted [`Gateway`]. See the root `README.md`'s
/// "Clinical gateway" section for the environment variables that produce this.
pub struct ClinicalPortsConfig {
    pub policy_path: PathBuf,
    pub grant_service_url: String,
    pub audit_log_path: PathBuf,
    pub approval_secret: Vec<u8>,
}

impl ClinicalPortsConfig {
    /// Reads `MODELFORGE_MCP_POLICY_PATH`, `MODELFORGE_MCP_GRANT_SERVICE_URL`,
    /// `MODELFORGE_MCP_AUDIT_LOG_PATH`, and `MODELFORGE_MCP_APPROVAL_SECRET`. They must be set
    /// all together (enabling the clinical gateway) or all left unset (`Ok(None)`,
    /// bootstrap-only) — never partially, since a half-configured clinical gateway would be a
    /// confusing, hard-to-diagnose deployment state rather than a clean fail-closed one. Shared
    /// by every transport binary so neither has to redefine this rule.
    ///
    /// # Errors
    ///
    /// Returns an error if exactly some, but not all, of the four variables are set.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let policy_path = std::env::var("MODELFORGE_MCP_POLICY_PATH").ok();
        let grant_service_url = std::env::var("MODELFORGE_MCP_GRANT_SERVICE_URL").ok();
        let audit_log_path = std::env::var("MODELFORGE_MCP_AUDIT_LOG_PATH").ok();
        let approval_secret = std::env::var("MODELFORGE_MCP_APPROVAL_SECRET").ok();
        match (
            policy_path,
            grant_service_url,
            audit_log_path,
            approval_secret,
        ) {
            (None, None, None, None) => Ok(None),
            (
                Some(policy_path),
                Some(grant_service_url),
                Some(audit_log_path),
                Some(approval_secret),
            ) => Ok(Some(Self {
                policy_path: PathBuf::from(policy_path),
                grant_service_url,
                audit_log_path: PathBuf::from(audit_log_path),
                approval_secret: approval_secret.into_bytes(),
            })),
            _ => anyhow::bail!(
                "MODELFORGE_MCP_POLICY_PATH, MODELFORGE_MCP_GRANT_SERVICE_URL, \
                 MODELFORGE_MCP_AUDIT_LOG_PATH, and MODELFORGE_MCP_APPROVAL_SECRET must all be \
                 set together to enable the clinical gateway, or all left unset to run \
                 bootstrap-only"
            ),
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PolicyFile {
    policies: Vec<TenantPolicy>,
    snapshot: PolicySnapshot,
    #[serde(default)]
    kill_switch_active: bool,
}

/// Builds a fully wired [`Gateway`]: a local, versioned tenant policy; a grant resolver that
/// calls out to an existing `ModelForge` grant-issuing service rather than storing grants
/// itself; a durable, PHI-free audit log; the deterministic medication-safety check ported from
/// the desktop app; and idempotency/approval-ticket infrastructure ready for the first
/// controlled-write tool. Runtime diagnostics stay [`UnconfiguredRuntimeDiagnostics`] — no IPC
/// bridge to a running desktop process exists in this repository — so that tool is reachable but
/// fails closed rather than fabricating numbers.
///
/// Fails closed: returns `Err` rather than falling back to any permissive default if the policy
/// file is missing or invalid, the grant-service URL isn't a well-formed HTTPS origin, or the
/// audit log can't be opened.
///
/// # Errors
///
/// Returns an error if the policy file cannot be read, parsed, or validated, if the grant
/// service URL is invalid, or if the audit log cannot be opened for append.
pub async fn build_clinical_gateway(config: ClinicalPortsConfig) -> anyhow::Result<Arc<Gateway>> {
    if config.approval_secret.len() < 32 {
        anyhow::bail!(
            "approval-ticket signing secret must be at least 32 bytes, got {}",
            config.approval_secret.len()
        );
    }
    let policy_json = tokio::fs::read_to_string(&config.policy_path)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "failed to read policy file {}: {error}",
                config.policy_path.display()
            )
        })?;
    let policy_file: PolicyFile = serde_json::from_str(&policy_json).map_err(|error| {
        anyhow::anyhow!(
            "failed to parse policy file {}: {error}",
            config.policy_path.display()
        )
    })?;
    let policy = PolicySet::new(
        policy_file.policies,
        policy_file.snapshot,
        policy_file.kill_switch_active,
    )
    .map_err(|error| {
        anyhow::anyhow!(
            "invalid policy file {}: {error}",
            config.policy_path.display()
        )
    })?;

    let grants = HttpGrantResolver::new(config.grant_service_url)
        .map_err(|error| anyhow::anyhow!("invalid grant service configuration: {error}"))?;

    let audit = FileAuditSink::open(&config.audit_log_path)
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "failed to open audit log {}: {error}",
                config.audit_log_path.display()
            )
        })?;

    let clinical_adapter: Arc<dyn DomainAdapter> = Arc::new(ClinicalDomainAdapter::new(Arc::new(
        BuiltInMedicationConflictService,
    )));
    let runtime_adapter: Arc<dyn DomainAdapter> = Arc::new(RuntimeDomainAdapter::new(Arc::new(
        UnconfiguredRuntimeDiagnostics,
    )));
    let domain = DomainRouter::new()
        .with_route(
            "clinical.medication_conflict_check",
            clinical_adapter.clone(),
        )
        .with_route("clinical.response_contract_check", clinical_adapter)
        .with_route("runtime.diagnostics", runtime_adapter);

    let gateway = Gateway::new(
        Arc::new(policy),
        Arc::new(grants),
        Arc::new(domain),
        Arc::new(audit),
    )
    .with_idempotency_store(Arc::new(InMemoryIdempotencyStore::default()))
    .with_approval_verifier(Arc::new(HmacApprovalVerifier::new(&config.approval_secret)));
    Ok(Arc::new(gateway))
}
