#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "test fixtures require concise key generation and failure context"
)]

use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
};
use jsonwebtoken::{
    Algorithm, EncodingKey, Header, encode,
    jwk::{Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse},
};
use modelforge_clinical_mcp_core::{
    AuditEvent, AuditSink, ClinicalDomainAdapter, ContextGrant, DestinationClass, DomainAdapter,
    DomainRouter, Gateway, GatewayError, GrantSnapshot, MedicationConflictRequest,
    MedicationConflictResult, MedicationConflictService, PolicySet, PolicySnapshot,
    RuntimeBackendDiagnostics, RuntimeDiagnosticsResult, RuntimeDiagnosticsService,
    RuntimeDomainAdapter, RuntimeLifecycleState, TenantPolicy, ToolEntitlement,
};
use modelforge_clinical_mcp_http::{
    AuthError, JwtAuthenticator, ManagedConfig, build_clinical_router, build_router,
};
use rand::rngs::OsRng;
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
};
use serde::Serialize;
use serde_json::{Value, json};
use tower::ServiceExt;

const ISSUER: &str = "https://identity.test";
const AUDIENCE: &str = "https://mcp.test/mcp";

#[derive(Serialize)]
struct TestClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    sub: &'a str,
    organization_id: &'a str,
    azp: &'a str,
    scope: &'a str,
    roles: Vec<&'a str>,
    acr: &'a str,
    exp: u64,
    nbf: u64,
}

fn keys() -> &'static (String, String) {
    static KEYS: OnceLock<(String, String)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let private = RsaPrivateKey::new(&mut OsRng, 2_048).expect("generate RSA test key");
        let private_pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode private key")
            .to_string();
        let public_pem = private
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode public key");
        (private_pem, public_pem)
    })
}

fn rotated_keys() -> &'static (String, String) {
    static KEYS: OnceLock<(String, String)> = OnceLock::new();
    KEYS.get_or_init(|| {
        let private = RsaPrivateKey::new(&mut OsRng, 2_048).expect("generate rotated RSA test key");
        let private_pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode rotated private key")
            .to_string();
        let public_pem = private
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("encode rotated public key");
        (private_pem, public_pem)
    })
}

fn jwks(private_pem: &str, key_id: &str) -> Vec<u8> {
    let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("decode test key");
    let mut jwk = Jwk::from_encoding_key(&encoding_key, Algorithm::RS256).expect("create JWK");
    jwk.common.key_id = Some(key_id.into());
    jwk.common.public_key_use = Some(PublicKeyUse::Signature);
    jwk.common.key_operations = Some(vec![KeyOperations::Verify]);
    serde_json::to_vec(&JwkSet { keys: vec![jwk] }).expect("serialize JWKS")
}

fn authenticator(audience: &str) -> JwtAuthenticator {
    JwtAuthenticator::from_rsa_pem(ISSUER, audience, keys().1.as_bytes())
        .expect("construct authenticator")
}

fn token(audience: &str) -> String {
    token_with_scope(audience, "mcp:read clinical:read runtime:read")
}

fn token_with_scope(audience: &str, scope: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_secs();
    let claims = TestClaims {
        iss: ISSUER,
        aud: audience,
        sub: "clinician-7",
        organization_id: "org-3",
        azp: "desktop-2",
        scope,
        roles: vec!["clinician"],
        acr: "urn:mfa",
        exp: now + 300,
        nbf: now.saturating_sub(5),
    };
    encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(keys().0.as_bytes()).expect("decode private key"),
    )
    .expect("sign access token")
}

fn token_with_key(private_pem: &str, key_id: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_secs();
    let claims = TestClaims {
        iss: ISSUER,
        aud: AUDIENCE,
        sub: "clinician-7",
        organization_id: "org-3",
        azp: "desktop-2",
        scope: "mcp:read clinical:read",
        roles: vec!["clinician"],
        acr: "urn:mfa",
        exp: now + 300,
        nbf: now.saturating_sub(5),
    };
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key_id.into());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("decode signing key"),
    )
    .expect("sign keyed access token")
}

fn config() -> ManagedConfig {
    ManagedConfig {
        resource: AUDIENCE.into(),
        protected_resource_metadata_uri: "https://mcp.test/.well-known/oauth-protected-resource"
            .into(),
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
        required_scopes: ["mcp:read".into()].into_iter().collect(),
        allowed_hosts: vec!["mcp.test".into()],
        allowed_origins: vec!["https://app.test".into()],
        max_request_body_bytes: 64 * 1024,
    }
}

fn discover_request(token: Option<&str>, host: &str, origin: &str) -> Request<Body> {
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "managed-test", "version": "1.0"},
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let mut request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, host)
        .header(header::ORIGIN, origin)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "server/discover");
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    request
        .body(Body::from(
            json!({"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":meta}})
                .to_string(),
        ))
        .expect("build request")
}

#[test]
fn token_validation_binds_verified_identity() {
    let token = token(AUDIENCE);
    let subject = authenticator(AUDIENCE)
        .authenticate_header(Some(
            &format!("Bearer {token}").parse().expect("header value"),
        ))
        .expect("valid token");
    assert_eq!(subject.subject_id, "clinician-7");
    assert_eq!(subject.client_id, "desktop-2");
    assert_eq!(subject.organization_id, "org-3");
    assert!(subject.scopes.contains("clinical:read"));
}

#[test]
fn wrong_audience_is_rejected() {
    let token = token("https://other-resource.test");
    let result = authenticator(AUDIENCE).authenticate_header(Some(
        &format!("Bearer {token}").parse().expect("header value"),
    ));
    assert_eq!(result, Err(AuthError::Unauthorized));
}

#[test]
fn jwks_rotation_atomically_changes_accepted_signing_key() {
    let first_jwks = jwks(&keys().0, "key-1");
    let second_jwks = jwks(&rotated_keys().0, "key-2");
    let authenticator =
        JwtAuthenticator::from_jwks_json(ISSUER, AUDIENCE, &first_jwks, Duration::from_secs(3_600))
            .expect("construct JWKS authenticator");
    let first_token = token_with_key(&keys().0, "key-1");
    let second_token = token_with_key(&rotated_keys().0, "key-2");
    assert!(
        authenticator
            .authenticate_header(Some(
                &format!("Bearer {first_token}").parse().expect("header")
            ))
            .is_ok()
    );
    assert_eq!(
        authenticator.authenticate_header(Some(
            &format!("Bearer {second_token}").parse().expect("header")
        )),
        Err(AuthError::Unauthorized)
    );

    authenticator
        .replace_jwks(&second_jwks)
        .expect("replace JWKS");
    assert!(
        authenticator
            .authenticate_header(Some(
                &format!("Bearer {second_token}").parse().expect("header")
            ))
            .is_ok()
    );
    assert_eq!(
        authenticator.authenticate_header(Some(
            &format!("Bearer {first_token}").parse().expect("header")
        )),
        Err(AuthError::Unauthorized)
    );
}

#[test]
fn invalid_jwks_update_preserves_last_known_good_keys() {
    let first_jwks = jwks(&keys().0, "key-1");
    let authenticator =
        JwtAuthenticator::from_jwks_json(ISSUER, AUDIENCE, &first_jwks, Duration::from_secs(3_600))
            .expect("construct JWKS authenticator");
    let token = token_with_key(&keys().0, "key-1");
    assert!(authenticator.replace_jwks(br#"{"keys":[]}"#).is_err());
    assert!(
        authenticator
            .authenticate_header(Some(&format!("Bearer {token}").parse().expect("header")))
            .is_ok()
    );
}

#[test]
fn non_rs256_jwk_is_rejected_before_use() {
    let mut set: JwkSet = serde_json::from_slice(&jwks(&keys().0, "key-1")).expect("parse JWKS");
    set.keys[0].common.key_algorithm = Some(KeyAlgorithm::HS256);
    let encoded = serde_json::to_vec(&set).expect("serialize invalid JWKS");
    assert!(
        JwtAuthenticator::from_jwks_json(ISSUER, AUDIENCE, &encoded, Duration::from_secs(3_600))
            .is_err()
    );
}

#[tokio::test]
async fn unauthenticated_mcp_request_is_rejected_with_challenge() {
    let app = build_router(config(), authenticator(AUDIENCE)).expect("build router");
    let response = app
        .oneshot(discover_request(None, "mcp.test", "https://app.test"))
        .await
        .expect("router response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers()[header::WWW_AUTHENTICATE],
        "Bearer resource_metadata=\"https://mcp.test/.well-known/oauth-protected-resource\""
    );
}

#[tokio::test]
async fn protected_resource_metadata_is_public_and_scoped() {
    let app = build_router(config(), authenticator(AUDIENCE)).expect("build router");
    let response = app
        .oneshot(
            Request::builder()
                .uri("/.well-known/oauth-protected-resource")
                .body(Body::empty())
                .expect("build request"),
        )
        .await
        .expect("router response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("read body");
    let payload: Value = serde_json::from_slice(&body).expect("parse metadata");
    assert_eq!(payload["resource"], AUDIENCE);
    assert_eq!(payload["authorization_servers"][0], ISSUER);
    assert_eq!(payload["scopes_supported"][0], "mcp:read");
}

#[test]
fn unsafe_or_missing_security_configuration_is_rejected() {
    let mut missing_origins = config();
    missing_origins.allowed_origins.clear();
    assert!(missing_origins.validate().is_err());

    let mut unsafe_scope = config();
    unsafe_scope.required_scopes = ["mcp:read\" injected".into()].into_iter().collect();
    assert!(unsafe_scope.validate().is_err());
}

#[tokio::test]
async fn valid_token_without_required_scope_is_forbidden() {
    let app = build_router(config(), authenticator(AUDIENCE)).expect("build router");
    let access_token = token_with_scope(AUDIENCE, "clinical:read");
    let response = app
        .oneshot(discover_request(
            Some(&access_token),
            "mcp.test",
            "https://app.test",
        ))
        .await
        .expect("router response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        response.headers()[header::WWW_AUTHENTICATE]
            .to_str()
            .expect("challenge header")
            .contains("insufficient_scope")
    );
}

#[tokio::test]
async fn valid_token_can_use_2026_discovery() {
    let app = build_router(config(), authenticator(AUDIENCE)).expect("build router");
    let access_token = token(AUDIENCE);
    let response = app
        .oneshot(discover_request(
            Some(&access_token),
            "mcp.test",
            "https://app.test",
        ))
        .await
        .expect("router response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    let payload: Value = serde_json::from_slice(&body).expect("parse response");
    assert!(
        payload["result"]["supportedVersions"]
            .as_array()
            .expect("supported versions")
            .contains(&json!("2026-07-28"))
    );
}

#[tokio::test]
async fn host_and_origin_allowlists_are_enforced() {
    let access_token = token(AUDIENCE);
    let bad_host = build_router(config(), authenticator(AUDIENCE))
        .expect("build router")
        .oneshot(discover_request(
            Some(&access_token),
            "attacker.test",
            "https://app.test",
        ))
        .await
        .expect("router response");
    assert_eq!(bad_host.status(), StatusCode::FORBIDDEN);

    let bad_origin = build_router(config(), authenticator(AUDIENCE))
        .expect("build router")
        .oneshot(discover_request(
            Some(&access_token),
            "mcp.test",
            "https://attacker.test",
        ))
        .await
        .expect("router response");
    assert_eq!(bad_origin.status(), StatusCode::FORBIDDEN);
}

#[derive(Default)]
struct TestAudit;

#[async_trait]
impl AuditSink for TestAudit {
    async fn record(&self, _event: AuditEvent) -> Result<(), GatewayError> {
        Ok(())
    }
}

#[derive(Default)]
struct TestMedicationService(Mutex<Option<MedicationConflictRequest>>);

#[async_trait]
impl MedicationConflictService for TestMedicationService {
    async fn check(
        &self,
        request: MedicationConflictRequest,
    ) -> Result<MedicationConflictResult, GatewayError> {
        *self.0.lock().map_err(|_| GatewayError::DomainUnavailable)? = Some(request);
        Ok(MedicationConflictResult {
            findings: Vec::new(),
            limitations: vec!["Decision support only".into()],
        })
    }
}

#[derive(Default)]
struct TestRuntimeDiagnostics;

#[async_trait]
impl RuntimeDiagnosticsService for TestRuntimeDiagnostics {
    async fn diagnostics(&self) -> Result<RuntimeDiagnosticsResult, GatewayError> {
        Ok(RuntimeDiagnosticsResult {
            backends: vec![RuntimeBackendDiagnostics {
                backend: "vllm".into(),
                state: RuntimeLifecycleState::Running,
                model_loaded: true,
                uptime_seconds: 120,
                active_requests: 0,
            }],
        })
    }
}

fn clinical_gateway(now: u64, service: Arc<TestMedicationService>) -> Arc<Gateway> {
    let entitlement = ToolEntitlement {
        allowed_roles: BTreeSet::from(["clinician".into()]),
        required_scopes: BTreeSet::from(["clinical:read".into()]),
        allowed_destinations: BTreeSet::from([DestinationClass::LocalModelForge]),
    };
    let runtime_entitlement = ToolEntitlement {
        allowed_roles: BTreeSet::from(["clinician".into()]),
        required_scopes: BTreeSet::from(["runtime:read".into()]),
        allowed_destinations: BTreeSet::from([DestinationClass::LocalModelForge]),
    };
    let policy = PolicySet::new(
        [TenantPolicy {
            organization_id: "org-3".into(),
            tools: [
                (
                    "clinical.medication_conflict_check".into(),
                    entitlement.clone(),
                ),
                (
                    "clinical.response_contract_check".into(),
                    entitlement.clone(),
                ),
                ("runtime.diagnostics".into(), runtime_entitlement),
            ]
            .into_iter()
            .collect(),
        }],
        PolicySnapshot {
            registry_version: "registry-1".into(),
            rbac_version: "rbac-1".into(),
            egress_policy_version: "egress-1".into(),
            kill_switch_version: "kills-1".into(),
            tool_policy_version: "tools-1".into(),
        },
        false,
    )
    .expect("valid policy");
    let grants = GrantSnapshot::new([ContextGrant {
        id: "grant-1".into(),
        subject_id: "clinician-7".into(),
        client_id: "desktop-2".into(),
        organization_id: "org-3".into(),
        case_id: "case-from-grant".into(),
        allowed_tools: BTreeSet::from([
            "clinical.medication_conflict_check".into(),
            "clinical.response_contract_check".into(),
        ]),
        allowed_fields: BTreeSet::from([
            "allergies".into(),
            "medications".into(),
            "assistantResponse".into(),
        ]),
        purpose: "clinical review".into(),
        destination: DestinationClass::LocalModelForge,
        expires_at_epoch_seconds: now + 300,
        version: 1,
    }])
    .expect("valid grant snapshot");
    let clinical: Arc<dyn DomainAdapter> = Arc::new(ClinicalDomainAdapter::new(service));
    let domain = DomainRouter::new()
        .with_route("clinical.medication_conflict_check", clinical.clone())
        .with_route("clinical.response_contract_check", clinical)
        .with_route(
            "runtime.diagnostics",
            Arc::new(RuntimeDomainAdapter::new(Arc::new(TestRuntimeDiagnostics))),
        );
    Arc::new(Gateway::new(
        Arc::new(policy),
        Arc::new(grants),
        Arc::new(domain),
        Arc::new(TestAudit),
    ))
}

#[tokio::test]
async fn clinical_tool_uses_verified_identity_and_grant_bound_case() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_secs();
    let service = Arc::new(TestMedicationService::default());
    let app = build_clinical_router(
        config(),
        authenticator(AUDIENCE),
        clinical_gateway(now, service.clone()),
    )
    .expect("build clinical router");
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "managed-test", "version": "1.0"},
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "mcp.test")
        .header(header::ORIGIN, "https://app.test")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::AUTHORIZATION, format!("Bearer {}", token(AUDIENCE)))
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "clinical.medication_conflict_check")
        .body(Body::from(
            json!({
                "jsonrpc":"2.0",
                "id":9,
                "method":"tools/call",
                "params":{
                    "name":"clinical.medication_conflict_check",
                    "arguments":{
                        "contextGrantId":"grant-1",
                        "medications":["amoxicillin"],
                        "allergies":["penicillin"]
                    },
                    "_meta":meta
                }
            })
            .to_string(),
        ))
        .expect("build tool request");
    let response = app.oneshot(request).await.expect("router response");
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    let payload: Value = serde_json::from_slice(&body).expect("parse tool response");
    assert_eq!(status, StatusCode::OK, "tool response: {payload}");
    assert!(payload.get("error").is_none(), "tool failed: {payload}");
    let captured = service
        .0
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let upstream = captured.as_ref().expect("upstream request");
    assert_eq!(upstream.organization_id, "org-3");
    assert_eq!(upstream.case_id, "case-from-grant");
}

#[tokio::test]
async fn response_contract_tool_flags_missing_sections_without_leaking_response_text() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_secs();
    let service = Arc::new(TestMedicationService::default());
    let app = build_clinical_router(
        config(),
        authenticator(AUDIENCE),
        clinical_gateway(now, service),
    )
    .expect("build clinical router");
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "managed-test", "version": "1.0"},
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "mcp.test")
        .header(header::ORIGIN, "https://app.test")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::AUTHORIZATION, format!("Bearer {}", token(AUDIENCE)))
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "clinical.response_contract_check")
        .body(Body::from(
            json!({
                "jsonrpc":"2.0",
                "id":10,
                "method":"tools/call",
                "params":{
                    "name":"clinical.response_contract_check",
                    "arguments":{
                        "contextGrantId":"grant-1",
                        "assistantResponse":"1. Summary\npatient is stable\n5. Red flags and urgent concerns\nnone"
                    },
                    "_meta":meta
                }
            })
            .to_string(),
        ))
        .expect("build tool request");
    let response = app.oneshot(request).await.expect("router response");
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    let payload: Value = serde_json::from_slice(&body).expect("parse tool response");
    assert_eq!(status, StatusCode::OK, "tool response: {payload}");
    assert!(payload.get("error").is_none(), "tool failed: {payload}");
    // The gateway's result guard and audit trail never copy tool arguments into their output:
    // only the deterministic applicable/missingSections verdict should appear on the wire, never
    // the clinical text the caller sent in.
    assert!(!String::from_utf8_lossy(&body).contains("patient is stable"));
    let structured = &payload["result"]["structuredContent"]["result"];
    assert_eq!(structured["applicable"], true);
    let missing = structured["missingSections"]
        .as_array()
        .expect("missing sections array");
    assert!(missing.contains(&json!("2. Known patient facts")));
    assert!(!missing.contains(&json!("1. Summary")));
    assert!(!missing.contains(&json!("5. Red flags and urgent concerns")));
}

#[tokio::test]
async fn runtime_diagnostics_tool_returns_bounded_summary_without_a_grant() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after Unix epoch")
        .as_secs();
    let service = Arc::new(TestMedicationService::default());
    let app = build_clinical_router(
        config(),
        authenticator(AUDIENCE),
        clinical_gateway(now, service),
    )
    .expect("build clinical router");
    let meta = json!({
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": {"name": "managed-test", "version": "1.0"},
        "io.modelcontextprotocol/clientCapabilities": {}
    });
    let request = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::HOST, "mcp.test")
        .header(header::ORIGIN, "https://app.test")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json, text/event-stream")
        .header(header::AUTHORIZATION, format!("Bearer {}", token(AUDIENCE)))
        .header("MCP-Protocol-Version", "2026-07-28")
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "runtime.diagnostics")
        .body(Body::from(
            json!({
                "jsonrpc":"2.0",
                "id":11,
                "method":"tools/call",
                "params":{
                    "name":"runtime.diagnostics",
                    "arguments":{},
                    "_meta":meta
                }
            })
            .to_string(),
        ))
        .expect("build tool request");
    let response = app.oneshot(request).await.expect("router response");
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("read body");
    let payload: Value = serde_json::from_slice(&body).expect("parse tool response");
    assert_eq!(status, StatusCode::OK, "tool response: {payload}");
    assert!(payload.get("error").is_none(), "tool failed: {payload}");
    let backends = payload["result"]["structuredContent"]["result"]["backends"]
        .as_array()
        .expect("backends array");
    assert_eq!(backends[0]["backend"], "vllm");
    assert_eq!(backends[0]["state"], "running");
    assert_eq!(backends[0]["modelLoaded"], true);
}
