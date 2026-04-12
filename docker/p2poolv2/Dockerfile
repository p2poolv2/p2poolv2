# syntax=docker/dockerfile:1.20
FROM rust:1.88-slim-bullseye AS builder

# Install required build dependencies
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    clang \
    cmake \
    git \
    libbz2-dev \
    liblz4-dev \
    libsnappy-dev \
    libssl-dev \
    libzmq3-dev \
    libzstd-dev \
    pkg-config \
    zlib1g-dev

# Create and set working directory
RUN mkdir -p /p2poolv2
WORKDIR /p2poolv2

# Copies just the essential files to be able to fetch
COPY --parents ./**/Cargo.toml .
COPY --parents ./**/lib.rs .
COPY --parents ./**/main.rs .
COPY --parents ./**/benches/*.rs .
COPY ./Cargo.lock .
COPY ./rust-toolchain.toml .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/rustup \
    --mount=type=cache,target=/p2poolv2/target \
    cargo fetch --locked

COPY --parents bitcoindrpc/ .
COPY --parents p2poolv2_cli/ .
COPY --parents p2poolv2_node/ .
COPY --parents p2poolv2_lib/ .
COPY --parents p2poolv2_api/ .

ENV RUST_LOG=info
ENV RUSTFLAGS='-C target-cpu=native'

# Build and install
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/rustup \
    --mount=type=cache,target=/p2poolv2/target \
    cargo install --locked --offline --path ./p2poolv2_node

FROM debian:bullseye-slim AS runner

RUN apt-get update && apt-get install -y --no-install-recommends curl

WORKDIR /p2poolv2
VOLUME /p2poolv2

# stratum, api, p2p
EXPOSE 3333 \
    46884 \
    6884

# Set sane container defaults
ENV RUST_BACKTRACE=full \
    RUST_LOG=debug \
    P2POOL_LOGGING_CONSOLE=1 \
    P2POOL_CONFIG=/etc/p2poolv2/config.toml

COPY --from=builder /usr/local/cargo/bin/p2poolv2 /usr/local/bin/p2poolv2
COPY --from=builder /usr/local/cargo/bin/p2poolv2_cli /usr/local/bin/p2poolv2_cli
COPY config-docker.sample.toml /etc/p2poolv2/config.toml

# TODO: add non-root user

HEALTHCHECK --interval=5s --timeout=1s --start-period=1s --retries=3 \
    CMD ["curl", "-sf", "http://127.0.0.1:46884/health"]

ENTRYPOINT ["/usr/local/bin/p2poolv2"]
