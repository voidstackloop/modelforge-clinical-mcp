# syntax=docker/dockerfile:1
#
# Production image for the ModelForge Clinical MCP Gateway.
#
# Builds both binaries but only the managed HTTP adapter is the default
# entrypoint: per the design doc, that is the deployable "managed
# organizations" surface, while the stdio companion is meant to be launched
# by its parent ModelForge process over an inherited/ACL-restricted channel,
# not run standalone as a network service. It is still included in the image
# so it can be invoked directly (`docker run <image> modelforge-clinical-mcp-stdio`)
# for local testing against an MCP client over `docker exec`/attached stdio.
#
# Build:
#   docker build -t modelforge-clinical-mcp .
#
# Run (see README.md for the full required env var list — the managed binary
# fails closed and refuses to start if any security-critical setting is
# missing or invalid):
#   docker run --rm -p 8080:8080 \
#     -e MODELFORGE_MCP_BIND=0.0.0.0:8080 \
#     -e MODELFORGE_MCP_RESOURCE=https://mcp.example.com/mcp \
#     -e MODELFORGE_MCP_PROTECTED_RESOURCE_METADATA_URI=https://mcp.example.com/.well-known/oauth-protected-resource \
#     -e MODELFORGE_MCP_OIDC_ISSUER=https://identity.example.com \
#     -e MODELFORGE_MCP_OIDC_AUDIENCE=https://mcp.example.com/mcp \
#     -e MODELFORGE_MCP_OIDC_JWKS_URI=https://identity.example.com/.well-known/jwks.json \
#     -e MODELFORGE_MCP_OIDC_JWKS_REFRESH_SECONDS=300 \
#     -e MODELFORGE_MCP_OIDC_JWKS_MAX_STALE_SECONDS=3600 \
#     -e MODELFORGE_MCP_ALLOWED_HOSTS=mcp.example.com \
#     -e MODELFORGE_MCP_ALLOWED_ORIGINS=https://app.example.com \
#     -e MODELFORGE_MCP_REQUIRED_SCOPES=mcp:read \
#     modelforge-clinical-mcp
#
# MODELFORGE_MCP_BIND must be 0.0.0.0:<port>, not 127.0.0.1:<port> — the
# README's example binds loopback-only for a bare-metal deployment behind a
# local reverse proxy; inside a container that would make the port
# unreachable from outside it. TLS still terminates at a trusted proxy in
# front of this container, per the design doc's security invariants.

################################################################################
# Planner: resolve a cargo-chef dependency recipe from the full source tree.
# This stage never compiles anything, so it reruns cheaply on every build.
################################################################################
FROM rust:1.89-slim-bookworm AS chef
WORKDIR /build
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && cargo install cargo-chef --locked
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

################################################################################
# Builder: compile dependencies from the cached recipe (rebuilds only when
# Cargo.toml/Cargo.lock change), then the workspace binaries.
################################################################################
FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked \
    -p modelforge-clinical-mcp-http \
    -p modelforge-clinical-mcp-stdio

################################################################################
# Runtime: distroless, non-root, nothing but the two compiled binaries and
# the CA roots reqwest/rustls needs to validate the OIDC issuer's JWKS TLS
# certificate (reqwest's rustls-tls feature bundles Mozilla's root list at
# compile time, so this is defense in depth rather than a hard requirement).
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /build/target/release/modelforge-clinical-mcp-http /usr/local/bin/modelforge-clinical-mcp-http
COPY --from=builder /build/target/release/modelforge-clinical-mcp-stdio /usr/local/bin/modelforge-clinical-mcp-stdio

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/modelforge-clinical-mcp-http"]
