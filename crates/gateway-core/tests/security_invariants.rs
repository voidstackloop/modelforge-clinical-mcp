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
    AdmissionRequest, ApprovalBinding, ApprovalVerifier, AuditEvent, AuditOutcome, AuditSink,
    BuiltInMedicationConflictService, CatalogEntry, ClinicalDomainAdapter, ClinicalPromptTemplate,
    ContextGrant, DestinationClass, DomainAdapter, DomainRouter, EgressClass, FileAuditSink,
    Gateway, GatewayError, GrantResolver, GrantSnapshot, HmacApprovalVerifier,
    HttpReviewDecisionService, IdempotencyAdmission, IdempotencyScope, IdempotencyStore,
    IdempotentCompletion, InMemoryIdempotencyStore, MedicationCheckStatus,
    MedicationConflictRequest, MedicationConflictResult, MedicationConflictService,
    MedicationConflictWarning, MedicationConflictWarningKind, PolicyEngine, PolicySet,
    PolicySnapshot, ReviewDecisionOutcome, ReviewDecisionRequest, ReviewDecisionResult,
    ReviewDecisionService, ReviewDomainAdapter, RiskClass, RuntimeBackendDiagnostics,
    RuntimeDiagnosticsResult, RuntimeDiagnosticsService, RuntimeDomainAdapter,
    RuntimeLifecycleState, SubjectContext, TenantPolicy, ToolEntitlement, catalog,
    check_response_contract_compliance, clinical_response_contract_prompt, operation_digest,
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
async fn unconfigured_runtime_diagnostics_fails_closed_instead_of_fabricating_data() {
    let adapter = RuntimeDomainAdapter::new(Arc::new(
        modelforge_clinical_mcp_core::UnconfiguredRuntimeDiagnostics,
    ));
    let entry = catalog()
        .into_iter()
        .find(|entry| entry.name == "runtime.diagnostics")
        .expect("catalog entry");
    let result = adapter.call(&subject(), &entry, None, json!({})).await;
    assert_eq!(result.err(), Some(GatewayError::DomainUnavailable));
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
fn http_grant_resolver_rejects_a_non_https_base_url() {
    assert!(modelforge_clinical_mcp_core::HttpGrantResolver::new("http://grants.test").is_err());
}

#[tokio::test]
async fn http_grant_resolver_rejects_a_grant_id_with_path_or_query_characters() {
    let resolver = modelforge_clinical_mcp_core::HttpGrantResolver::new("https://grants.test")
        .expect("valid base url");
    for malformed in ["", "grant/1", "grant?x=1", "grant#frag"] {
        let result = resolver.resolve(malformed).await;
        assert_eq!(result.err(), Some(GatewayError::ContextGrantUnavailable));
    }
}

fn approval_binding() -> ApprovalBinding<'static> {
    ApprovalBinding {
        subject_id: "clinician-7",
        client_id: "desktop-2",
        tool_name: "clinical_orders.record_review_decision",
        operation_digest: "sha256:deadbeef",
    }
}

#[tokio::test]
async fn hmac_approval_verifier_accepts_a_matching_freshly_issued_ticket() {
    let verifier = HmacApprovalVerifier::new(b"test-secret");
    let ticket = verifier
        .issue(&approval_binding(), 2_000)
        .expect("issue ticket");
    verifier
        .verify_and_consume(&ticket, &approval_binding(), 1_000)
        .await
        .expect("verify ticket");
}

#[tokio::test]
async fn hmac_approval_verifier_rejects_a_ticket_reused_a_second_time() {
    let verifier = HmacApprovalVerifier::new(b"test-secret");
    let ticket = verifier
        .issue(&approval_binding(), 2_000)
        .expect("issue ticket");
    verifier
        .verify_and_consume(&ticket, &approval_binding(), 1_000)
        .await
        .expect("first use");
    let replay = verifier
        .verify_and_consume(&ticket, &approval_binding(), 1_000)
        .await;
    assert_eq!(replay.err(), Some(GatewayError::ApprovalRequired));
}

#[tokio::test]
async fn hmac_approval_verifier_rejects_a_ticket_bound_to_a_different_operation() {
    let verifier = HmacApprovalVerifier::new(b"test-secret");
    let ticket = verifier
        .issue(&approval_binding(), 2_000)
        .expect("issue ticket");
    let mut different_digest = approval_binding();
    different_digest.operation_digest = "sha256:different";
    let mismatched = verifier
        .verify_and_consume(&ticket, &different_digest, 1_000)
        .await;
    assert_eq!(mismatched.err(), Some(GatewayError::ApprovalRequired));
}

#[tokio::test]
async fn hmac_approval_verifier_rejects_an_expired_ticket() {
    let verifier = HmacApprovalVerifier::new(b"test-secret");
    let ticket = verifier
        .issue(&approval_binding(), 1_000)
        .expect("issue ticket");
    let expired = verifier
        .verify_and_consume(&ticket, &approval_binding(), 2_000)
        .await;
    assert_eq!(expired.err(), Some(GatewayError::ApprovalRequired));
}

#[tokio::test]
async fn hmac_approval_verifier_rejects_a_ticket_signed_with_a_different_secret() {
    let issuer = HmacApprovalVerifier::new(b"issuer-secret");
    let verifier = HmacApprovalVerifier::new(b"verifier-secret");
    let ticket = issuer
        .issue(&approval_binding(), 2_000)
        .expect("issue ticket");
    let forged = verifier
        .verify_and_consume(&ticket, &approval_binding(), 1_000)
        .await;
    assert_eq!(forged.err(), Some(GatewayError::ApprovalRequired));
}

fn idempotency_scope() -> IdempotencyScope {
    IdempotencyScope {
        organization_id: "org-3".into(),
        subject_id: "clinician-7".into(),
        tool_name: "clinical.medication_conflict_check".into(),
        idempotency_key: "key-1".into(),
    }
}

fn test_completion(result: Value) -> IdempotentCompletion {
    IdempotentCompletion {
        operation_digest: "sha256:test-operation-digest".into(),
        policy_snapshot: policy_snapshot(),
        result,
    }
}

#[tokio::test]
async fn idempotency_store_replays_the_stored_result_for_a_matching_digest() {
    let store = InMemoryIdempotencyStore::default();
    let scope = idempotency_scope();
    assert!(matches!(
        store.begin(&scope, "digest-a").await,
        Ok(IdempotencyAdmission::Fresh)
    ));
    store
        .complete(&scope, "digest-a", test_completion(json!({"ok": true})))
        .await
        .expect("complete");

    let replay = store.begin(&scope, "digest-a").await;
    assert!(matches!(
        replay,
        Ok(IdempotencyAdmission::Replay(ref completion)) if completion.result == json!({"ok": true})
    ));
}

#[tokio::test]
async fn idempotency_store_rejects_a_reused_key_with_different_arguments() {
    let store = InMemoryIdempotencyStore::default();
    let scope = idempotency_scope();
    store.begin(&scope, "digest-a").await.expect("first begin");
    store
        .complete(&scope, "digest-a", test_completion(json!({"ok": true})))
        .await
        .expect("complete");

    let reused = store.begin(&scope, "digest-b").await;
    assert_eq!(reused.err(), Some(GatewayError::IdempotencyKeyReused));
}

#[tokio::test]
async fn idempotency_store_rejects_a_concurrent_in_flight_duplicate() {
    let store = InMemoryIdempotencyStore::default();
    let scope = idempotency_scope();
    assert!(matches!(
        store.begin(&scope, "digest-a").await,
        Ok(IdempotencyAdmission::Fresh)
    ));

    let concurrent = store.begin(&scope, "digest-a").await;
    assert_eq!(
        concurrent.err(),
        Some(GatewayError::IdempotencyOperationInProgress),
        "a second caller must not also observe Fresh while the first is still in flight"
    );
}

#[tokio::test]
async fn idempotency_store_abort_frees_the_scope_for_a_fresh_retry() {
    let store = InMemoryIdempotencyStore::default();
    let scope = idempotency_scope();
    store.begin(&scope, "digest-a").await.expect("first begin");
    store.abort(&scope).await.expect("abort");

    assert!(matches!(
        store.begin(&scope, "digest-a").await,
        Ok(IdempotencyAdmission::Fresh)
    ));
}

#[tokio::test]
async fn file_audit_sink_appends_one_json_line_per_event_and_excludes_no_field() {
    let path = std::env::temp_dir().join(format!(
        "modelforge-audit-test-{}.jsonl",
        uuid::Uuid::new_v4()
    ));
    let sink = FileAuditSink::open(&path).await.expect("open audit file");

    let event = AuditEvent {
        operation_id: uuid::Uuid::new_v4(),
        subject_id: "clinician-7".into(),
        client_id: "desktop-2".into(),
        organization_id: "org-3".into(),
        tool_name: "clinical.medication_conflict_check".into(),
        risk: RiskClass::ReadOnly,
        outcome: AuditOutcome::Succeeded,
        policy_version: Some("tools-1".into()),
        error_class: None,
    };
    sink.record(event.clone()).await.expect("record event");
    sink.record(event.clone())
        .await
        .expect("record second event");

    let contents = tokio::fs::read_to_string(&path)
        .await
        .expect("read audit file");
    tokio::fs::remove_file(&path)
        .await
        .expect("clean up audit file");
    let lines = contents.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);
    for line in lines {
        let parsed: AuditEvent = serde_json::from_str(line).expect("valid JSON line");
        assert_eq!(parsed, event);
    }
}

fn medication_request(allergies: &[&str], medications: &[&str]) -> MedicationConflictRequest {
    MedicationConflictRequest {
        organization_id: "org-3".into(),
        case_id: "case-9".into(),
        allergies: allergies.iter().map(|value| (*value).to_owned()).collect(),
        medications: medications
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    }
}

#[tokio::test]
async fn built_in_medication_service_flags_an_allergy_class_synonym() {
    let result = BuiltInMedicationConflictService
        .check(medication_request(&["Penicillin"], &["Amoxicillin 500mg"]))
        .await
        .expect("check result");
    assert!(result.applicable);
    assert_eq!(result.status, MedicationCheckStatus::Demonstration);
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.kind == MedicationConflictWarningKind::Allergy)
    );
}

#[tokio::test]
async fn built_in_medication_service_flags_a_known_interaction_pair() {
    let result = BuiltInMedicationConflictService
        .check(medication_request(&[], &["Warfarin", "Ibuprofen"]))
        .await
        .expect("check result");
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| warning.kind == MedicationConflictWarningKind::KnownInteraction)
    );
}

#[tokio::test]
async fn built_in_medication_service_finds_nothing_for_unrelated_terms() {
    let result = BuiltInMedicationConflictService
        .check(medication_request(&["Latex"], &["Metoprolol"]))
        .await
        .expect("check result");
    assert!(result.applicable);
    assert!(result.warnings.is_empty());
}

#[tokio::test]
async fn built_in_medication_service_is_not_applicable_when_nothing_is_recorded() {
    let empty = BuiltInMedicationConflictService
        .check(medication_request(&[], &[]))
        .await
        .expect("check result");
    assert!(!empty.applicable);
    assert!(empty.warnings.is_empty());

    let whitespace_only = BuiltInMedicationConflictService
        .check(medication_request(&["  ", ""], &["   "]))
        .await
        .expect("check result");
    assert!(!whitespace_only.applicable);
}

#[tokio::test]
async fn built_in_medication_service_matching_is_case_and_whitespace_insensitive() {
    let padded = BuiltInMedicationConflictService
        .check(medication_request(
            &[" Penicillin "],
            &["AMOXICILLIN 500mg"],
        ))
        .await
        .expect("check result");
    let lowercase = BuiltInMedicationConflictService
        .check(medication_request(&["penicillin"], &["amoxicillin 500mg"]))
        .await
        .expect("check result");
    assert_eq!(padded.warnings.len(), lowercase.warnings.len());
    assert!(!padded.warnings.is_empty());
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
async fn unknown_operation_still_emits_an_audit_event() {
    let audit = Arc::new(MemoryAudit::default());
    let gateway = Gateway::new(
        Arc::new(AllowPolicy),
        Arc::new(StaticGrant(medication_grant())),
        Arc::new(EchoDomain),
        audit.clone(),
    );
    let error = gateway
        .execute(AdmissionRequest {
            subject: subject(),
            tool_name: "clinical.does_not_exist".into(),
            arguments: json!({}),
            context_grant_id: None,
            approval_ticket: None,
            idempotency_key: None,
            now_epoch_seconds: 1_000,
        })
        .await;
    assert_eq!(error.err(), Some(GatewayError::UnknownOperation));
    let events = audit
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, AuditOutcome::Denied);
    assert_eq!(events[0].error_class.as_deref(), Some("unknown_operation"));
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
                allowed_authentication_strengths: BTreeSet::new(),
            },
        )]
        .into_iter()
        .collect(),
    }
}

fn step_up_tenant_policy() -> TenantPolicy {
    TenantPolicy {
        organization_id: "org-3".into(),
        tools: [(
            "clinical.medication_conflict_check".into(),
            ToolEntitlement {
                allowed_roles: BTreeSet::from(["clinician".into()]),
                required_scopes: BTreeSet::from(["clinical:read".into()]),
                allowed_destinations: BTreeSet::from([DestinationClass::LocalModelForge]),
                allowed_authentication_strengths: BTreeSet::from(["urn:mfa".into()]),
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

#[tokio::test]
async fn step_up_authentication_strength_is_enforced_when_configured() {
    let policy =
        PolicySet::new([step_up_tenant_policy()], policy_snapshot(), false).expect("valid policy");
    let entry = catalog()
        .into_iter()
        .find(|entry| entry.name == "clinical.medication_conflict_check")
        .expect("catalog entry");

    assert_eq!(
        policy
            .authorize(&subject(), &entry, Some(&medication_grant()))
            .await,
        Err(GatewayError::PolicyDenied),
        "subject's authentication_strength is \"local-attested\", not the required \"urn:mfa\""
    );

    let mut stepped_up = subject();
    stepped_up.authentication_strength = "urn:mfa".into();
    assert!(
        policy
            .authorize(&stepped_up, &entry, Some(&medication_grant()))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn egress_none_operation_rejects_non_local_destination_even_when_tenant_policy_allows_it() {
    let permissive_policy = TenantPolicy {
        organization_id: "org-3".into(),
        tools: [(
            "clinical.medication_conflict_check".into(),
            ToolEntitlement {
                allowed_roles: BTreeSet::from(["clinician".into()]),
                required_scopes: BTreeSet::from(["clinical:read".into()]),
                allowed_destinations: BTreeSet::from([
                    DestinationClass::LocalModelForge,
                    DestinationClass::ApprovedThirdParty,
                ]),
                allowed_authentication_strengths: BTreeSet::new(),
            },
        )]
        .into_iter()
        .collect(),
    };
    let policy =
        PolicySet::new([permissive_policy], policy_snapshot(), false).expect("valid policy");
    let entry = catalog()
        .into_iter()
        .find(|entry| entry.name == "clinical.medication_conflict_check")
        .expect("catalog entry");
    assert_eq!(entry.egress, EgressClass::None);

    let mut remote_grant = medication_grant();
    remote_grant.destination = DestinationClass::ApprovedThirdParty;
    assert_eq!(
        policy
            .authorize(&subject(), &entry, Some(&remote_grant))
            .await,
        Err(GatewayError::PolicyDenied),
        "tenant policy allows the destination, but the catalog's egress: None must still block it"
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
            provider_name: "test-provider".into(),
            provider_label: "Test provider".into(),
            status: MedicationCheckStatus::Demonstration,
            evaluated_at_epoch_seconds: 1_000,
            applicable: true,
            warnings: vec![MedicationConflictWarning {
                kind: MedicationConflictWarningKind::KnownInteraction,
                medication: "amoxicillin".into(),
                conflicts_with: "penicillin".into(),
                detail: "review required".into(),
            }],
            limitations: "Decision support only".into(),
            error: None,
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

#[test]
fn http_review_decision_service_rejects_a_non_https_base_url() {
    assert!(HttpReviewDecisionService::new("http://reviews.test").is_err());
}

#[derive(Default)]
struct CapturingReviewService(Mutex<Vec<ReviewDecisionRequest>>);

#[async_trait]
impl ReviewDecisionService for CapturingReviewService {
    async fn record(
        &self,
        request: ReviewDecisionRequest,
    ) -> Result<ReviewDecisionResult, GatewayError> {
        let review_id = uuid::Uuid::new_v4();
        let decision = request.decision;
        self.0
            .lock()
            .map_err(|_| GatewayError::DomainUnavailable)?
            .push(request);
        Ok(ReviewDecisionResult {
            review_id,
            decision,
        })
    }
}

#[tokio::test]
async fn review_domain_adapter_injects_reviewer_and_case_from_trusted_context() {
    let service = Arc::new(CapturingReviewService::default());
    let adapter = ReviewDomainAdapter::new(service.clone());
    let entry = catalog()
        .into_iter()
        .find(|entry| entry.name == "clinical.record_review_decision")
        .expect("catalog entry");
    assert_eq!(entry.risk, RiskClass::ControlledWrite);
    assert!(entry.idempotency_required);

    adapter
        .call(
            &subject(),
            &entry,
            Some(&medication_grant()),
            json!({
                "reviewedOperationId": "11111111-1111-1111-1111-111111111111",
                "decision": "approved",
                "rationale": "Dosage confirmed correct for renal function."
            }),
        )
        .await
        .expect("adapter result");
    let captured = service
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let request = captured.first().expect("captured request");
    assert_eq!(request.reviewer_subject_id, "clinician-7");
    assert_eq!(request.case_id, "case-9");
    assert_eq!(request.organization_id, "org-3");
    assert_eq!(request.decision, ReviewDecisionOutcome::Approved);
}

#[tokio::test]
async fn review_domain_adapter_rejects_empty_or_oversized_rationale() {
    let adapter = ReviewDomainAdapter::new(Arc::new(CapturingReviewService::default()));
    let entry = catalog()
        .into_iter()
        .find(|entry| entry.name == "clinical.record_review_decision")
        .expect("catalog entry");

    let empty = adapter
        .call(
            &subject(),
            &entry,
            Some(&medication_grant()),
            json!({
                "reviewedOperationId": "11111111-1111-1111-1111-111111111111",
                "decision": "approved",
                "rationale": "   "
            }),
        )
        .await;
    assert!(matches!(empty, Err(GatewayError::PayloadRejected(_))));

    let oversized = adapter
        .call(
            &subject(),
            &entry,
            Some(&medication_grant()),
            json!({
                "reviewedOperationId": "11111111-1111-1111-1111-111111111111",
                "decision": "approved",
                "rationale": "x".repeat(2_001)
            }),
        )
        .await;
    assert!(matches!(oversized, Err(GatewayError::PayloadRejected(_))));
}

fn review_decision_grant() -> ContextGrant {
    ContextGrant {
        id: "grant-review".into(),
        subject_id: "clinician-7".into(),
        client_id: "desktop-2".into(),
        organization_id: "org-3".into(),
        case_id: "case-9".into(),
        allowed_tools: BTreeSet::from(["clinical.record_review_decision".into()]),
        allowed_fields: BTreeSet::from(["rationale".into()]),
        purpose: "review decision".into(),
        destination: DestinationClass::LocalModelForge,
        expires_at_epoch_seconds: 5_000,
        version: 1,
    }
}

fn review_decision_tenant_policy() -> TenantPolicy {
    TenantPolicy {
        organization_id: "org-3".into(),
        tools: [(
            "clinical.record_review_decision".into(),
            ToolEntitlement {
                allowed_roles: BTreeSet::from(["clinician".into()]),
                required_scopes: BTreeSet::from(["clinical:read".into()]),
                allowed_destinations: BTreeSet::from([DestinationClass::LocalModelForge]),
                allowed_authentication_strengths: BTreeSet::new(),
            },
        )]
        .into_iter()
        .collect(),
    }
}

fn review_decision_arguments() -> Value {
    json!({
        "reviewedOperationId": "11111111-1111-1111-1111-111111111111",
        "decision": "approved",
        "rationale": "Dosage confirmed correct for renal function."
    })
}

/// End to end through the public `Gateway::execute()` API — the first real catalog entry that
/// is both `RiskClass::ControlledWrite` and `idempotency_required: true`, so this is the first
/// test able to exercise the approval-ticket and idempotency machinery through the actual
/// admission path rather than by calling `Gateway`'s private methods directly.
#[allow(
    clippy::too_many_lines,
    reason = "a single connected scenario (no ticket, wrong digest, success, replay, reused key) sharing one gateway and one prior successful call; splitting it would duplicate that setup in each piece rather than shrink the test"
)]
#[tokio::test]
async fn record_review_decision_requires_approval_and_deduplicates_via_idempotency_key() {
    let policy = PolicySet::new([review_decision_tenant_policy()], policy_snapshot(), false)
        .expect("valid policy");
    let approval = Arc::new(HmacApprovalVerifier::new(
        b"test-secret-thats-well-over-32-bytes-long",
    ));
    let service = Arc::new(CapturingReviewService::default());
    let audit = Arc::new(MemoryAudit::default());
    let gateway = Gateway::new(
        Arc::new(policy),
        Arc::new(StaticGrant(review_decision_grant())),
        Arc::new(ReviewDomainAdapter::new(service.clone())),
        audit.clone(),
    )
    .with_idempotency_store(Arc::new(InMemoryIdempotencyStore::default()))
    .with_approval_verifier(approval.clone());

    let entry = catalog()
        .into_iter()
        .find(|entry| entry.name == "clinical.record_review_decision")
        .expect("catalog entry");
    let arguments = review_decision_arguments();

    // Missing approval ticket is rejected before the domain adapter is ever called.
    let no_ticket = gateway
        .execute(AdmissionRequest {
            subject: subject(),
            tool_name: entry.name.clone(),
            arguments: arguments.clone(),
            context_grant_id: Some("grant-review".into()),
            approval_ticket: None,
            idempotency_key: Some("key-1".into()),
            now_epoch_seconds: 1_000,
        })
        .await;
    assert_eq!(no_ticket.err(), Some(GatewayError::ApprovalRequired));
    assert!(
        service
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty(),
        "domain adapter must not run without a valid approval ticket"
    );

    // The ticket must be bound to the exact operation digest, which depends on the resolved
    // grant and policy snapshot — mint it against a placeholder and let verify_approval reject
    // the mismatch, matching how a real caller would learn the required digest from a prior
    // approval_required response rather than computing operation_digest itself.
    let mismatched_ticket = approval
        .issue(
            &ApprovalBinding {
                subject_id: "clinician-7",
                client_id: "desktop-2",
                tool_name: &entry.name,
                operation_digest: "sha256:not-the-real-digest",
            },
            5_000,
        )
        .expect("issue ticket");
    let wrong_digest = gateway
        .execute(AdmissionRequest {
            subject: subject(),
            tool_name: entry.name.clone(),
            arguments: arguments.clone(),
            context_grant_id: Some("grant-review".into()),
            approval_ticket: Some(mismatched_ticket),
            idempotency_key: Some("key-1".into()),
            now_epoch_seconds: 1_000,
        })
        .await;
    assert_eq!(wrong_digest.err(), Some(GatewayError::ApprovalRequired));

    // Compute the real digest the same way Gateway does, mint a ticket bound to it, and confirm
    // the operation now succeeds, runs the domain adapter exactly once, and produces a real
    // audit trail.
    let snapshot = policy_snapshot();
    let digest = operation_digest(
        &entry.name,
        &arguments,
        &subject(),
        Some(&review_decision_grant()),
        &snapshot,
    );
    let ticket = approval
        .issue(
            &ApprovalBinding {
                subject_id: "clinician-7",
                client_id: "desktop-2",
                tool_name: &entry.name,
                operation_digest: &digest,
            },
            5_000,
        )
        .expect("issue ticket");
    let first = gateway
        .execute(AdmissionRequest {
            subject: subject(),
            tool_name: entry.name.clone(),
            arguments: arguments.clone(),
            context_grant_id: Some("grant-review".into()),
            approval_ticket: Some(ticket.clone()),
            idempotency_key: Some("key-1".into()),
            now_epoch_seconds: 1_000,
        })
        .await
        .expect("first execution succeeds");
    assert_eq!(first.result["decision"], "approved");
    assert_eq!(
        service
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len(),
        1
    );

    // The same ticket cannot be replayed even for a retried call (single-use), but the
    // idempotency store already has a terminal result for this scope/digest, so the retry is
    // served as a replay and never reaches verify_approval or the domain adapter again.
    let retry = gateway
        .execute(AdmissionRequest {
            subject: subject(),
            tool_name: entry.name.clone(),
            arguments: arguments.clone(),
            context_grant_id: Some("grant-review".into()),
            approval_ticket: None,
            idempotency_key: Some("key-1".into()),
            now_epoch_seconds: 1_000,
        })
        .await
        .expect("retry replays the stored result");
    assert_eq!(retry.result, first.result);
    assert_eq!(
        service
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len(),
        1,
        "a replayed retry must not re-invoke the domain adapter"
    );

    // A reused idempotency key with different arguments is rejected outright.
    let mut different_arguments = review_decision_arguments();
    different_arguments["rationale"] = json!("A completely different rationale.");
    let reused_key = gateway
        .execute(AdmissionRequest {
            subject: subject(),
            tool_name: entry.name.clone(),
            arguments: different_arguments,
            context_grant_id: Some("grant-review".into()),
            approval_ticket: None,
            idempotency_key: Some("key-1".into()),
            now_epoch_seconds: 1_000,
        })
        .await;
    assert_eq!(reused_key.err(), Some(GatewayError::IdempotencyKeyReused));

    let events = audit
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let serialized = serde_json::to_string(&*events).unwrap_or_default();
    assert!(!serialized.contains("Dosage confirmed"));
    assert!(!serialized.contains("renal function"));
}
