# ModelForge Clinical MCP Gateway

Security-first implementation of the first-party ModelForge MCP boundary. The project uses one
shared Rust core and thin transport adapters. Domain data remains behind ModelForge services; this
repository deliberately contains no JSON, SQLite, or PostgreSQL readers.

## Current milestone

The initial M1 slice contains:

- a deterministic, versioned read-only tool catalog;
- bounded request and result validation;
- subject, organization, policy-snapshot, and field-grant contracts;
- fail-closed policy, grant-resolution, domain-adapter, and PHI-free audit interfaces;
- immutable tenant policy and context-grant snapshots with bounded startup validation;
- role, scope, organization, destination, purpose, tool, field, and kill-switch enforcement;
- operation digests for approval and replay binding;
- a stdio MCP companion exposing capability discovery;
- a stateless managed `/mcp` adapter with RS256 OIDC validation;
- OAuth protected-resource metadata and standards-compatible challenges;
- explicit Host, Origin, audience, issuer, scope, and body-size enforcement;
- bounded HTTPS JWKS refresh with strict `kid`, RS256, signing-use, no-redirect, atomic replacement,
  and stale-key fail-closed behavior;
- a narrow medication-conflict adapter that injects case and organization identity from trusted
  context rather than accepting either value from model-controlled arguments;
- a deterministic response-contract check, `clinical.response_contract_check`, that mirrors the
  desktop app's eight-section `RESPONSE_CONTRACT_SECTION_HEADINGS` check byte-for-byte so the two
  can never silently drift apart;
- a `runtime.diagnostics` tool backed by a narrow, single-purpose adapter that returns only a
  bounded, non-secret per-backend summary (state, whether a model is loaded, uptime, active
  requests) and never the upstream `LocalRuntimeStatus` fields that can carry local file paths or
  other operational detail (logs, `startupError`, pid, port, `currentConfig`, `installCommand`);
- a `DomainRouter` that composes multiple narrow, single-family domain adapters (clinical, runtime,
  and future evidence/compute adapters) behind the one `DomainAdapter` port `Gateway` accepts,
  dispatching by catalog tool name and failing closed on anything unregistered;
- the V1 prompt surface named in the system design doc — `clinical.response_contract`,
  `clinical.soap_draft`, `clinical.differential_support`, `clinical.medication_review`,
  `clinical.evidence_appraisal`, and `clinical.compute_incident_triage` — the first four sourced
  byte-for-byte from the desktop app's `CLINICAL_RESPONSE_CONTRACT`/`CLINICAL_MODES`, the last two
  authored fresh for tool families (evidence, compute) that have no desktop-app equivalent. Prompts
  carry no PHI and need no context grant, so they are served directly by the bootstrap handler;
- the `modelforge://capabilities` resource named first among the V1 resources in the design doc,
  serving the same deterministic manifest as the `modelforge.capabilities` tool through
  `resources/list`/`resources/read` instead of `tools/call`;
- terminal admitted, denied, succeeded, and failed audit outcomes without arguments or results;
- real, non-test implementations of every trusted port `Gateway` needs: `BuiltInMedicationConflictService`
  (ports the desktop app's own deterministic seed-list checker), `FileAuditSink` (durable,
  fsynced JSON-lines audit log), `InMemoryIdempotencyStore` (race-safe reservation, not just a
  presence check), `HmacApprovalVerifier` (signed, single-use approval tickets bound to the full
  operation digest), and `HttpGrantResolver` (calls out to an existing ModelForge grant-issuing
  service rather than storing grants itself);
- both binaries construct a fully wired `Gateway` from those ports when configured (see "Clinical
  gateway" below) and fall back to the unchanged bootstrap-only default otherwise — live-verified
  end to end: real JWT → real tenant-policy authorization → real audit trail → real domain
  dispatch, including a PHI tool correctly rejected without a resolvable grant;
- tests for catalog determinism, grant binding, tenant isolation, kill switches, digest stability,
  payload limits, trusted-context injection, domain routing, prompt rendering, resource reads,
  idempotency reservation races, approval-ticket binding/expiry/replay, and audit privacy.

## Build

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release -p modelforge-clinical-mcp-stdio
cargo build --release -p modelforge-clinical-mcp-http
```

Run the local companion:

```bash
cargo run -p modelforge-clinical-mcp-stdio
```

Logs go to stderr. Stdout is reserved exclusively for MCP JSON-RPC frames.

Run the managed adapter behind a TLS-terminating reverse proxy:

```bash
export MODELFORGE_MCP_BIND=127.0.0.1:8080
export MODELFORGE_MCP_RESOURCE=https://mcp.example.com/mcp
export MODELFORGE_MCP_PROTECTED_RESOURCE_METADATA_URI=https://mcp.example.com/.well-known/oauth-protected-resource
export MODELFORGE_MCP_OIDC_ISSUER=https://identity.example.com
export MODELFORGE_MCP_OIDC_AUDIENCE=https://mcp.example.com/mcp
export MODELFORGE_MCP_OIDC_JWKS_URI=https://identity.example.com/.well-known/jwks.json
export MODELFORGE_MCP_OIDC_JWKS_REFRESH_SECONDS=300
export MODELFORGE_MCP_OIDC_JWKS_MAX_STALE_SECONDS=3600
export MODELFORGE_MCP_ALLOWED_HOSTS=mcp.example.com
export MODELFORGE_MCP_ALLOWED_ORIGINS=https://app.example.com
export MODELFORGE_MCP_REQUIRED_SCOPES=mcp:read
cargo run -p modelforge-clinical-mcp-http
```

Set `MODELFORGE_MCP_OIDC_PUBLIC_KEY_PEM` instead of `MODELFORGE_MCP_OIDC_JWKS_URI` for a controlled
static-key deployment; setting both is rejected. The managed binary refuses to start when any
security-critical setting is missing or invalid. It
expects TLS to terminate at a trusted local proxy and validates the external Host and Origin values
forwarded unchanged to the application. Private keys are neither required nor accepted.

## Clinical gateway

Both binaries default to the bootstrap-only surface above (capability discovery, prompts, the
capabilities resource — no PHI). Setting all four of the following env vars switches either
binary to the full `ClinicalServer`, wired to real ports; setting only some of them is a startup
error rather than a silent partial configuration:

```bash
export MODELFORGE_MCP_POLICY_PATH=/etc/modelforge/clinical-policy.json
export MODELFORGE_MCP_GRANT_SERVICE_URL=https://grants.example.com
export MODELFORGE_MCP_AUDIT_LOG_PATH=/var/log/modelforge/clinical-audit.jsonl
export MODELFORGE_MCP_APPROVAL_SECRET=<at least 32 random bytes>
```

`MODELFORGE_MCP_POLICY_PATH` points to a JSON tenant-policy file, loaded once at startup and
validated the same way `PolicySet::new` validates it in tests:

```json
{
  "policies": [
    {
      "organizationId": "org-3",
      "tools": {
        "clinical.medication_conflict_check": {
          "allowedRoles": ["clinician"],
          "requiredScopes": ["clinical:read"],
          "allowedDestinations": ["local_model_forge"],
          "allowedAuthenticationStrengths": []
        }
      }
    }
  ],
  "snapshot": {
    "registryVersion": "registry-1",
    "rbacVersion": "rbac-1",
    "egressPolicyVersion": "egress-1",
    "killSwitchVersion": "kill-1",
    "toolPolicyVersion": "tools-1"
  },
  "killSwitchActive": false
}
```

`MODELFORGE_MCP_GRANT_SERVICE_URL` must be an `https://` origin; grants are looked up as
`GET {url}/{grantId}` rather than stored by this repository. `MODELFORGE_MCP_APPROVAL_SECRET` signs
and verifies approval tickets for the first `RiskClass::ControlledWrite` tool — none exist in the
catalog yet, so this is infrastructure the moment one is added, not something exercised today.
`runtime.diagnostics` stays reachable but always returns `domain_unavailable`: no IPC bridge to a
running desktop process exists in this repository, and fabricating numbers would be worse than
failing closed.

**Known gap:** the managed HTTP adapter derives `SubjectContext` from a verified OIDC access
token, so the chain above is complete for it. The stdio companion has no equivalent identity
source yet — the design doc's "inherited, ACL-restricted channel" that the desktop app is meant to
authenticate over doesn't exist on either side of this repository. Enabling the clinical gateway
over stdio today means every tool call fails with "verified identity is unavailable" until the
desktop integration supplies that channel.

## Docker

`Dockerfile` is a multi-stage `cargo chef` build producing a ~63 MB distroless, non-root runtime
image with both binaries; it defaults to running the managed HTTP adapter and fails closed exactly
like the bare `cargo run` invocation above if required env vars are missing:

```bash
docker build -t modelforge-clinical-mcp .
docker run --rm -p 8080:8080 \
  -e MODELFORGE_MCP_BIND=0.0.0.0:8080 \
  -e MODELFORGE_MCP_RESOURCE=https://mcp.example.com/mcp \
  # ...remaining vars from the managed-adapter example above...
  modelforge-clinical-mcp
```

`MODELFORGE_MCP_BIND` must be `0.0.0.0:<port>` in a container — `127.0.0.1:<port>` (correct for the
bare-metal example above) would be unreachable from outside the container.

`Dockerfile.dev` is a toolchain-only image (rustup + clippy + rustfmt + cargo-watch) for iterating
with the source bind-mounted from the host; its default command re-runs this file's exact `fmt`/
`test`/`clippy` pipeline on every change:

```bash
docker build -f Dockerfile.dev -t modelforge-clinical-mcp:dev .
docker run --rm -it -v "$(pwd)":/workspace -v modelforge-clinical-mcp-target:/workspace/target \
  modelforge-clinical-mcp:dev
```

Both base images are `rust:1.89-slim-bookworm` rather than the full `bookworm` variant, which ships
hundreds of packages (docs, extra locales, unused CLI tools) this project never uses and that
otherwise show up as avoidable CVEs in image scans.

## Security invariants

- No inbound subject, organization, role, or scope is accepted from tool arguments.
- PHI-bearing operations require a short-lived grant bound to subject, client, organization, tool,
  fields, purpose, destination class, and expiry.
- Policy and domain dependencies fail closed.
- Tool arguments and results never enter audit events or tracing fields.
- The result guard rejects excessive nesting, strings, arrays, object width, and encoded size.
- No shell, filesystem, secret, raw-image, registry-administration, or direct-database tool exists.
