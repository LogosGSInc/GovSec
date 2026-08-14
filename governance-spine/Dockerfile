FROM rust:1.85-slim AS builder
WORKDIR /build
COPY Cargo.toml .
COPY src/ ./src/
RUN cargo build --release --bin governance_spine_server 2>&1

FROM debian:bookworm-slim AS runtime
ARG VCS_REF
LABEL org.opencontainers.image.revision=$VCS_REF
# A2: constitution provenance — a versioned release artifact, not
# runtime-mutable config. Computed at build time from the actual files
# being baked in below (see docker-compose.yml / build invocation), so the
# labels can never drift from what's really in the image.
ARG CONSTITUTION_ID=unknown
ARG CONSTITUTION_VERSION=unknown
ARG CONSTITUTION_SHA256=unknown
ARG CONSTITUTION_SIGNER_FINGERPRINT=unknown
LABEL com.logosgs.constitution.id=$CONSTITUTION_ID
LABEL com.logosgs.constitution.version=$CONSTITUTION_VERSION
LABEL com.logosgs.constitution.sha256=$CONSTITUTION_SHA256
LABEL com.logosgs.constitution.signer_fingerprint=$CONSTITUTION_SIGNER_FINGERPRINT
RUN apt-get update && apt-get install -y \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /build/target/release/governance_spine_server ./governance_spine_server
# A2: the signed constitution — see constitution/README.md. Loaded and
# signature-verified at startup (src/server.rs main()); missing/invalid
# refuses to start.
COPY constitution/constitution.json ./constitution/constitution.json
COPY constitution/constitution.json.sig ./constitution/constitution.json.sig
RUN mkdir -p /data /app/audit
EXPOSE 8080
ENV RUST_LOG=info
ENV SENTOW_BIND=0.0.0.0:8080
ENV SENTOW_MEMORY_PATH=/data/strategic_memory.json
# Gate 1: departments/registry.json lives at the repo root, outside this
# image's build context (context: ./governance-spine — see docker-compose.yml),
# so it can't be COPY'd in at build time. Bind-mounted read-only at this path
# instead; GovMem::new() fails closed at startup if it's missing.
ENV GOVMEM_REGISTRY_PATH=/app/departments/registry.json
HEALTHCHECK --interval=15s --timeout=5s --retries=5 \
    CMD curl -f http://localhost:8080/health || exit 1
CMD ["./governance_spine_server"]
