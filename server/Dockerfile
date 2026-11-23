ARG RUST_IMAGE=rust:1.91.1-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim
FROM ${RUST_IMAGE} AS build
WORKDIR /build
COPY server server
COPY crates crates
COPY verifiers/rust verifiers/rust
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/server/target \
    cargo build --locked --release --manifest-path server/Cargo.toml \
    && cp server/target/release/grantmint-server /usr/local/bin/grantmint-server \
    && cp server/target/release/import-v2 /usr/local/bin/import-v2

FROM ${RUNTIME_IMAGE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 --shell /usr/sbin/nologin grantmint \
    && install -d -o 10001 -g 10001 /app /keys
COPY --from=build /usr/local/bin/grantmint-server /app/grantmint-server
COPY --from=build /usr/local/bin/import-v2 /app/import-v2
USER 10001:10001
WORKDIR /app
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/app/grantmint-server"]
CMD ["serve"]
