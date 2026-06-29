# syntax=docker/dockerfile:1
#
# Multi-stage build for Keyward (internal CA / PKI authority).
#   - builder: rust:1.96-slim (Debian trixie; ships gcc for the `ring` C build).
#   - runtime: debian:trixie-slim (matching glibc), non-root, ca-certificates.
#
# Unlike keystone, Keyward links NO OpenSSL: rcgen uses the `ring` crypto backend and
# sqlx uses `rustls`, so the binary depends only on glibc — no libssl in either stage.
# The container HEALTHCHECK uses the built-in `keyward healthcheck` subcommand, so no
# extra HTTP tool is needed in the image.

FROM rust:1.96-slim AS builder
WORKDIR /build

# Cache the dependency graph first: build a throwaway lib/bin against the real manifest so
# `cargo build` only recompiles our crate when src/ changes, not the whole tree.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --bin keyward \
    && rm -rf src

# Now build the real binary.
COPY src ./src
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --bin keyward \
    && strip target/release/keyward

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (no shell, no home writes needed).
RUN useradd --system --uid 10001 --user-group --no-create-home keyward
COPY --from=builder /build/target/release/keyward /usr/local/bin/keyward

# Persistent CA material dir (CA_DIR). Created owned by the non-root uid so a mounted
# named volume inherits writable ownership — ca.crt/ca.key are generated/persisted at
# runtime under /ca (mode 0600 on the key), never baked into the image.
RUN mkdir -p /ca && chown 10001:10001 /ca
VOLUME ["/ca"]

USER keyward
# Default in-container bind; overridable at runtime.
ENV BIND_ADDR=0.0.0.0:8200
ENV CA_DIR=/ca
EXPOSE 8200

# Dependency-free liveness probe -> GET /healthz on the loopback, exit 0/1.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["keyward", "healthcheck"]

ENTRYPOINT ["keyward"]
