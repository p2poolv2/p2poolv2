# syntax=docker/dockerfile:1.20
FROM alpine:latest AS base

FROM base AS builder

# Install build dependencies
RUN apk add --no-cache \
    boost-dev \
    build-base \
    cmake \
    linux-headers \
    openssl-dev \
    libevent-dev \
    zeromq-dev \
    sqlite-dev \
    git \
    curl \
    python3 \
    capnproto \
    capnproto-dev

# Clone the latest release from Bitcoin Core repository
RUN git clone --depth 1 --branch v30.2 https://github.com/bitcoin/bitcoin.git /bitcoin

# Build Bitcoin Core
WORKDIR /bitcoin
RUN cmake -B build \
    -DWITH_MINIUPNPC=OFF \
    -DBUILD_GUI=OFF \
    -DBUILD_TESTS=OFF \
    -DBUILD_BENCH=OFF \
    -DENABLE_WALLET=OFF \
    -DBUILD_FUZZ_BINARY=OFF \
    -DENABLE_IPC=ON \
    -DWITH_ZMQ=ON \
    -DBUILD_CLI=ON \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo
RUN cmake --build build -j$(nproc)

FROM base AS runtime

COPY --from=builder /bitcoin/build/bin/bitcoin* /usr/local/bin/

# Install runtime dependencies
RUN apk add --no-cache \
    boost-system \
    boost-filesystem \
    boost-thread \
    libevent \
    libzmq \
    libstdc++ \
    sqlite-libs

# Create bitcoin user
RUN adduser -S bitcoin
RUN addgroup -S bitcoin

# Create data directory
RUN mkdir /data
RUN chown bitcoin:bitcoin /data

USER bitcoin
VOLUME ["/data"]

# Ports for signet
EXPOSE 38332 38333

# Ports for testnet4
EXPOSE 48332 48333

COPY signet/bitcoin-signet.conf /etc/bitcoin/
COPY testnet4/bitcoin-testnet4.conf /etc/bitcoin/
COPY bcli /usr/local/bin/

HEALTHCHECK --interval=5s --timeout=1s --start-period=3s --retries=3 \
    CMD ["ash", "-c", "nc -z 127.0.0.1 ${BTC_P2P_PORT:-38333}"]

ENTRYPOINT ["bitcoind"]
