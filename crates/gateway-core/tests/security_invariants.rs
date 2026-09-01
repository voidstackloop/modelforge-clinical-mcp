#![allow(
    clippy::expect_used,
    reason = "test fixtures use expect for immediate, contextual failures"
)]

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use modelforge_clinical_mcp_core::{
    AdmissionRequest, AuditEvent, AuditOutcome, AuditSink, CatalogEntry, ClinicalDomainAdapter,
    ClinicalPromptTemplate, ContextGrant, DestinationClass, DomainAdapter, DomainRouter, Gateway,
    GatewayError, GrantResolver, GrantSnapshot, MedicationConflictFinding,
    MedicationConflictRequest, MedicationConflictResult, MedicationConflictService, PolicyEngine,
    PolicySet, PolicySnapshot, RuntimeBackendDiagnostics, RuntimeDiagnosticsResult,
    RuntimeDiagnosticsService, RuntimeDomainAdapter, RuntimeLifecycleState, SubjectContext,
    TenantPolicy, ToolEntitlement, catalog, check_response_contract_compliance,
    clinical_response_contract_prompt, operation_digest,
};
use serde_json::{Value, json};

#[derive(Default)]
struct AllowPolicy;

#[async_trait]
impl PolicyEngine for AllowPolicy {
    async fn authorize(
        &self,
        _subject: &SubjectContext,
        _operation: &CatalogEntry,
        _grant: Option<&ContextGrant>,
    ) -> Result<PolicySnapshot, GatewayError> {
        Ok(PolicySnapshot {
            registry_version: "registry-1".into(),
            rbac_version: "rbac-1".into(),
            egress_policy_version: "egress-1".into(),
            kill_switch_version: "kills-1".into(),
            tool_policy_version: "tools-1".into(),
        })
    }
}

struct StaticGrant(ContextGrant);

#[async_trait]
impl GrantResolver for StaticGrant {
    async fn resolve(&self, grant_id: &str) -> Result<ContextGrant, GatewayError> {
        (grant_id == self.0.id)
            .then(|| self.0.clone())
            .ok_or(GatewayError::ContextGrantUnavailable)
    }
}

#[derive(Default)]
struct EchoDomain;

#[async_trait]
impl DomainAdapter for EchoDomain {
    async fn call(
        &self,
        _subject: &SubjectContext,
        operation: &CatalogEntry,
        _grant: Option<&ContextGrant>,
        arguments: Value,
    ) -> Result<Value, GatewayError> {
        Ok(json!({"tool": operation.name, "accepted": arguments.is_object()}))
    }
}

#[derive(Default)]
struct MemoryAudit(Mutex<Vec<AuditEvent>>);

#[async_trait]
impl AuditSink for MemoryAudit {
    async fn record(&self, event: AuditEvent) -> Result<(), GatewayError> {
        self.0
            .lock()
            .map_err(|_| GatewayError::AuditUnavailable)?
            .push(event);
        Ok(())
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

fn medication_grant() -> ContextGrant {
    ContextGrant {
        id: "grant-1".into(),
        subject_id: "clinician-7".into(),
        client_id: "desktop-2".into(),
        organization_id: "org-3".into(),
        case_id: "case-9".into(),
        allowed_tools: BTreeSet::from(["clinical.medication_conflict_check".into()]),
        allowed_fields: BTreeSet::from(["allergies".into(), "medications".into()]),
        purpose: "medication review".into(),
        destination: DestinationClass::LocalModelForge,
        expires_at_epoch_seconds: 2_000,
        version: 1,
    }
}

fn response_contract_grant() -> ContextGrant {
    ContextGrant {
        id: "grant-2".into(),
        subject_id: "clinician-7".into(),
        client_id: "desktop-2".into(),
        organization_id: "org-3".into(),
        case_id: "case-9".into(),
        allowed_tools: BTreeSet::from(["clinical.response_contract_check".into()]),
        allowed_fields: BTreeSet::from(["assistantResponse".into()]),
        purpose: "response contract review".into(),
        destination: DestinationClass::LocalModelForge,
        expires_at_epoch_seconds: 2_000,
        version: 1,
    }
}

#[test]
fn response_contract_check_flags_missing_sections_in_contract_order() {
    let partial = "1. Summary\nfine\n5. Red flags and urgent concerns\nnone";
    let result = check_response_contract_compliance(partial);
    assert!(result.applicable);
    assert_eq!(
        result.missing_sections,
        vec![
            "2. Known patient facts",
            "3. Assessment or possible interpretations",
            "4. Missing information",
            "6. Suggested next clinical steps",
            "7. Evidence and citations",
            "8. Uncertainty and limitations",
        ]
    );
}

#[test]
fn response_contract_check_is_not_applicable_without_any_heading() {
    let result = check_response_contract_compliance("Thanks, that's helpful.");
    assert!(!result.applicable);
    assert!(result.missing_sections.is_empty());
}

#[tokio::test]
async fn response_contract_adapter_rejects_oversized_or_empty_response() {
    let service = Arc::new(CapturingMedicationService::default());
    let adapter = ClinicalDomainAdapter::new(service);
    let entry = catalog()
        .into_iter()
        .find(|entry| entry.name == "clinical.response_contract_check")
        .expect("catalog entry");

    let empty = adapter
        .call(
            &subject(),
            &entry,
            Some(&response_contract_grant()),
            json!({"assistantResponse": "   "}),
        )
        .await;
    assert!(matches!(empty, Err(GatewayError::PayloadRejected(_))));

    let oversized = adapter
        .call(
            &subject(),
            &entry,
            Some(&response_contract_grant()),
            json!({"assistantResponse": "x".repeat(20_001)}),
        )
        .await;
    assert!(matches!(oversized, Err(GatewayError::PayloadRejected(_))));
}

#[tokio::test]
async fn response_contract_operation_requires_grant_and_audits_without_leaking_text() {
    let audit = Arc::new(MemoryAudit::default());
    let gateway = Gateway::new(
        Arc::new(AllowPolicy),
        Arc::new(StaticGrant(response_contract_grant())),
        Arc::new(ClinicalDomainAdapter::new(Arc::new(
            CapturingMedicationService::default(),
        ))),
        audit.clone(),
    );

    let denied = gateway
        .execute(AdmissionRequest {
            subject: subject(),
            tool_name: "clinical.response_contract_check".into(),
            arguments: json!({"assistantResponse": "patient has a secret-condition"}),
            context_grant_id: None,
            approval_ticket: None,
            idempotency_key: None,
            now_epoch_seconds: 1_000,
        })
        .await;
    assert_eq!(denied.err(), Some(GatewayError::ContextGrantRequired));

    let admitted = gateway
        .execute(AdmissionRequest {
            subject: subject(),
            tool_name: "clinical.response_contract_check".into(),
            arguments: json!({
                "assistantResponse": "1. Summary\npatient has a secret-condition"
            }),
            context_grant_id: Some("grant-2".into()),
            approval_ticket: None,
            idempotency_key: None,
            now_epoch_seconds: 1_000,
        })
        .await
        .expect("admitted response");
    assert_eq!(admitted.result["applicable"], true);

    let events = audit
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let serialized = serde_json::to_string(&*events).unwrap_or_default();
    assert!(!serialized.contains("secret-condition"));
}

#[derive(Default)]
struct StubRuntimeDiagnostics;

#[async_trait]
impl RuntimeDiagnosticsService for StubRuntimeDiagnostics {
    async fn diagnostics(&self) -> Result<RuntimeDiagnosticsResult, GatewayError> {
        Ok(RuntimeDiagnosticsResult {
            backends: vec![RuntimeBackendDiagnostics {
                backend: "vllm".into(),
                state: RuntimeLifecycleState::Running,
                model_loaded: true,
                uptime_seconds: 42,
                active_requests: 1,
            }],
        })
    }
}

#[derive(Default)]
struct OverflowingRuntimeDiagnostics;

#[async_trait]
impl RuntimeDiagnosticsService for OverflowingRuntimeDiagnostics {
    async fn diagnostics(&self) -> Result<RuntimeDiagnosticsResult, GatewayError> {
        Ok(RuntimeDiagnosticsResult {
            backends: (0..17)
                .map(|index| RuntimeBackendDiagnostics {
                    backend: format!("backend-{index}"),
                    state: RuntimeLifecycleState::Stopped,
                    model_loaded: false,
                    uptime_seconds: 0,
                    active_requests: 0,
                })
                .collect(),
        })
    }
}

#[tokio::test]
async fn runtime_diagnostics_adapter_returns_bounded_non_secret_summary() {
    let adapter = RuntimeDomainAdapter::new(Arc::new(StubRuntimeDiagnostics));
    let entry = catalog()
        .into_iter()
        .find(|entry| entry.name == "runtime.diagnostics")
        .expect("catalog entry");
    assert!(!entry.requires_context_grant());
    let result = adapter
        .call(&subject(), &entry, None, json!({}))
        .await
        .expect("runtime diagnostics result");
    assert_eq!(result["backends"][0]["backend"], "vllm");
    assert_eq!(result["backends"][0]["state"], "running");
    // Fields the upstream local-runtime status carries but this projection must never surface.
    let serialized = result.to_string();
    for leaked_field in [
        "logs",
        "startupError",
        "pid",
        "port",
        "currentConfig",
        "installCommand",
    ] {
        assert!(!serialized.contains(leaked_field));
    }
}

#[tokio::test]
async fn runtime_diagnostics_adapter_rejects_excess_backends() {
    let adapter = RuntimeDomainAdapter::new(Arc::new(OverflowingRuntimeDiagnostics));
    let entry = catalog()
        .into_iter()
        .find(|entry| entry.name == "runtime.diagnostics")
        .expect("catalog entry");
    let result = adapter.call(&subject(), &entry, None, json!({})).await;
    assert!(matches!(result, Err(GatewayError::PayloadRejected(_))));
}

#[tokio::test]
async fn domain_router_dispatches_by_tool_name_and_fails_closed_otherwise() {
    let router = DomainRouter::new()
        .with_route(
            "clinical.medication_conflict_check",
            Arc::new(ClinicalDomainAdapter::new(Arc::new(
                CapturingMedicationService::default(),
            ))),
        )
        .with_route(
            "runtime.diagnostics",
            Arc::new(RuntimeDomainAdapter::new(Arc::new(StubRuntimeDiagnostics))),
        );
    let runtime_entry = catalog()
        .into_iter()
        .find(|entry| entry.name == "runtime.diagnostics")
        .expect("catalog entry");
    assert!(
        router
            .call(&subject(), &runtime_entry, None, json!({}))
            .await
            .is_ok()
    );

    let unregistered = catalog()
        .into_iter()
        .find(|entry| entry.name == "modelforge.capabilities")
        .expect("catalog entry");
    assert_eq!(
        router
            .call(&subject(), &unregistered, None, json!({}))
            .await
            .err(),
        Some(GatewayError::UnknownOperation)
    );
}

#[test]
fn response_contract_prompt_lists_all_eight_headings_in_order() {
    let prompt = clinical_response_contract_prompt();
    let headings = [
        "1. Summary",
        "2. Known patient facts",
        "3. Assessment or possible interpretations",
        "4. Missing information",
        "5. Red flags and urgent concerns",
        "6. Suggested next clinical steps",
        "7. Evidence and citations",
        "8. Uncertainty and limitations",
    ];
    let mut previous_index = None;
    for heading in headings {
        let index = prompt.find(heading).expect("prompt missing heading");
        if let Some(previous) = previous_index {
            assert!(previous < index, "{heading} is out of order");
        }
        previous_index = Some(index);
    }
}

#[test]
fn prompt_templates_append_mode_instruction_after_the_response_contract() {
    let contract_only = ClinicalPromptTemplate::ResponseContract.render();
    assert_eq!(contract_only, clinical_response_contract_prompt());

    let soap = ClinicalPromptTemplate::SoapDraft.render();
    assert!(soap.starts_with(&clinical_response_contract_prompt()));
    assert!(soap.contains("Draft a SOAP note"));

    let compute_triage = ClinicalPromptTemplate::ComputeIncidentTriage.render();
    assert!(compute_triage.contains("bounded runtime diagnostics"));
}

#[test]
fn catalog_is_sorted_and_unique() {
    let names = catalog()
        .into_iter()
        .map(|entry| entry.name)
        .collect::<Vec<_>>();
    let mut expected = names.clone();
    expected.sort();
    expected.dedup();
    assert_eq!(names, expected);
}

#[test]
fn operation_digest_is_independent_of_object_key_order() {
    let left = json!({"b": [2, 1], "a": {"y": true, "x": null}});
    let right = json!({"a": {"x": null, "y": true}, "b": [2, 1]});
    let policy = PolicySnapshot {
        registry_version: "registry-1".into(),
        rbac_version: "rbac-1".into(),
        egress_policy_version: "egress-1".into(),
        kill_switch_version: "kills-1".into(),
        tool_policy_version: "tools-1".into(),
    };
    assert_eq!(
        operation_digest("tool", &left, &subject(), None, &policy),
        operation_digest("tool", &right, &subject(), None, &policy)
    );
}

#[test]
fn operation_digest_changes_when_subject_or_policy_changes() {
    let arguments = json!({"a": 1});
    let policy = PolicySnapshot {
        registry_version: "registry-1".into(),
        rbac_version: "rbac-1".into(),
        egress_policy_version: "egress-1".into(),
        kill_switch_version: "kills-1".into(),
        tool_policy_version: "tools-1".into(),
    };
    let baseline = operation_digest("tool", &arguments, &subject(), None, &policy);
    let mut other_subject = subject();
    other_subject.client_id = "different-client".into();
    let mut other_policy = policy.clone();
    other_policy.tool_policy_version = "tools-2".into();
    assert_ne!(
        baseline,
        operation_digest("tool", &arguments, &other_subject, None, &policy)
    );
    assert_ne!(
        baseline,
        operation_digest("tool", &arguments, &subject(), None, &other_policy)
    );
}

#[tokio::test]
async fn phi_operation_requires_a_bound_unexpired_grant() {
    let audit = Arc::new(MemoryAudit::default());
    let gateway = Gateway::new(
        Arc::new(AllowPolicy),
        Arc::new(StaticGrant(medication_grant())),
        Arc::new(EchoDomain),
        audit.clone(),
    );

    let response = gateway
        .execute(AdmissionRequest {
            subject: subject(),
            tool_name: "clinical.medication_conflict_check".into(),
            arguments: json!({"allergies": ["penicillin"], "medications": ["amoxicillin"]}),
            context_grant_id: Some("grant-1".into()),
            approval_ticket: None,
            idempotency_key: None,
            now_epoch_seconds: 1_000,
        })
        .await;

    assert!(response.is_ok());
    let events = audit
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(events.len(), 2);
    let serialized = serde_json::to_string(&*events).unwrap_or_default();
    assert!(!serialized.contains("penicillin"));
    assert!(!serialized.contains("amoxicillin"));
}

#[tokio::test]
async fn grant_replay_by_another_subject_is_rejected_before_domain_call() {
    let gateway = Gateway::new(
        Arc::new(AllowPolicy),
        Arc::new(StaticGrant(medication_grant())),
        Arc::new(EchoDomain),
        Arc::new(MemoryAudit::default()),
    );
    let mut other = subject();
    other.subject_id = "attacker".into();

    let error = gateway
        .execute(AdmissionRequest {
            subject: other,
            tool_name: "clinical.medication_conflict_check".into(),
            arguments: json!({}),
            context_grant_id: Some("grant-1".into()),
            approval_ticket: None,
            idempotency_key: None,
            now_epoch_seconds: 1_000,
        })
        .await;

    assert_eq!(error.err(), Some(GatewayError::GrantBindingMismatch));
}

#[tokio::test]
async fn oversized_input_is_rejected() {
    let gateway = Gateway::new(
        Arc::new(AllowPolicy),
        Arc::new(StaticGrant(medication_grant())),
        Arc::new(EchoDomain),
        Arc::new(MemoryAudit::default()),
    );
    let response = gateway
        .execute(AdmissionRequest {
            subject: subject(),
            tool_name: "modelforge.capabilities".into(),
            arguments: json!({"value": "x".repeat(70_000)}),
            context_grant_id: None,
            approval_ticket: None,
            idempotency_key: None,
            now_epoch_seconds: 1_000,
        })
        .await;

    assert!(matches!(response, Err(GatewayError::PayloadRejected(_))));
}

fn policy_snapshot() -> PolicySnapshot {
    PolicySnapshot {
        registry_version: "registry-1".into(),
        rbac_version: "rbac-1".into(),
        egress_policy_version: "egress-1".into(),
        kill_switch_version: "kills-1".into(),
        tool_policy_version: "tools-1".into(),
    }
}

fn tenant_policy() -> TenantPolicy {
    TenantPolicy {
        organization_id: "org-3".into(),
        tools: [(
            "clinical.medication_conflict_check".into(),
            ToolEntitlement {
                allowed_roles: BTreeSet::from(["clinician".into()]),
                required_scopes: BTreeSet::from(["clinical:read".into()]),
                allowed_destinations: BTreeSet::from([DestinationClass::LocalModelForge]),
            },
        )]
        .into_iter()
        .collect(),
    }
}

#[tokio::test]
async fn tenant_policy_rejects_cross_tenant_and_wrong_destination_access() {
    let policy = PolicySet::new([tenant_policy()], policy_snapshot(), false).expect("valid policy");
    let entry = catalog()
        .into_iter()
        .find(|entry| entry.name == "clinical.medication_conflict_check")
        .expect("catalog entry");

    let mut other_tenant = subject();
    other_tenant.organization_id = "org-attacker".into();
    assert_eq!(
        policy
            .authorize(&other_tenant, &entry, Some(&medication_grant()))
            .await,
        Err(GatewayError::PolicyDenied)
    );

    let mut remote_grant = medication_grant();
    remote_grant.destination = DestinationClass::ApprovedThirdParty;
    assert_eq!(
        policy
            .authorize(&subject(), &entry, Some(&remote_grant))
            .await,
        Err(GatewayError::PolicyDenied)
    );
}

#[tokio::test]
async fn kill_switch_denies_an_otherwise_authorized_operation() {
    let policy = PolicySet::new([tenant_policy()], policy_snapshot(), true).expect("valid policy");
    let entry = catalog()
        .into_iter()
        .find(|entry| entry.name == "clinical.medication_conflict_check")
        .expect("catalog entry");
    assert_eq!(
        policy
            .authorize(&subject(), &entry, Some(&medication_grant()))
            .await,
        Err(GatewayError::PolicyDenied)
    );
}

#[test]
fn grant_snapshot_rejects_duplicate_and_unversioned_grants() {
    let grant = medication_grant();
    assert!(GrantSnapshot::new([grant.clone(), grant]).is_err());
    let mut unversioned = medication_grant();
    unversioned.version = 0;
    assert!(GrantSnapshot::new([unversioned]).is_err());
}

#[derive(Default)]
struct CapturingMedicationService(Mutex<Option<MedicationConflictRequest>>);

#[async_trait]
impl MedicationConflictService for CapturingMedicationService {
    async fn check(
        &self,
        request: MedicationConflictRequest,
    ) -> Result<MedicationConflictResult, GatewayError> {
        *self.0.lock().map_err(|_| GatewayError::DomainUnavailable)? = Some(request);
        Ok(MedicationConflictResult {
            findings: vec![MedicationConflictFinding {
                severity: "high".into(),
                summary: "review required".into(),
                evidence_code: "MF-DRUG-1".into(),
            }],
            limitations: vec!["Decision support only".into()],
        })
    }
}

#[tokio::test]
async fn medication_adapter_injects_case_and_organization_from_trusted_context() {
    let service = Arc::new(CapturingMedicationService::default());
    let adapter = ClinicalDomainAdapter::new(service.clone());
    let entry = catalog()
        .into_iter()
        .find(|entry| entry.name == "clinical.medication_conflict_check")
        .expect("catalog entry");
    adapter
        .call(
            &subject(),
            &entry,
            Some(&medication_grant()),
            json!({"medications":["amoxicillin"],"allergies":["penicillin"]}),
        )
        .await
        .expect("adapter result");
    let captured = service
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let request = captured.as_ref().expect("captured request");
    assert_eq!(request.case_id, "case-9");
    assert_eq!(request.organization_id, "org-3");
}

#[tokio::test]
async fn denied_operation_emits_phi_free_terminal_audit_event() {
    let audit = Arc::new(MemoryAudit::default());
    let gateway = Gateway::new(
        Arc::new(AllowPolicy),
        Arc::new(StaticGrant(medication_grant())),
        Arc::new(EchoDomain),
        audit.clone(),
    );
    let result = gateway
        .execute(AdmissionRequest {
            subject: subject(),
            tool_name: "clinical.medication_conflict_check".into(),
            arguments: json!({"medications":["secret-drug"],"allergies":[]}),
            context_grant_id: None,
            approval_ticket: None,
            idempotency_key: None,
            now_epoch_seconds: 1_000,
        })
        .await;
    assert_eq!(result.err(), Some(GatewayError::ContextGrantRequired));
    let events = audit
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, AuditOutcome::Denied);
    assert_eq!(
        events[0].error_class.as_deref(),
        Some("context_grant_required")
    );
    assert!(
        !serde_json::to_string(&*events)
            .unwrap_or_default()
            .contains("secret-drug")
    );
}
