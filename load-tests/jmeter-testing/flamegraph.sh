#!/usr/bin/env bash

# Generate a flamegraph of P2Poolv2 under jmeter load.
#
# Prerequisites:
#   - perf installed
#   - cargo-flamegraph installed (cargo install flamegraph)
#   - jmeter installed and in PATH
#   - node/npm installed
#
# Usage:
#   cd load-tests/jmeter-testing
#   JAVA_HOME=/usr/lib/jvm/java-21-openjdk ./flamegraph.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MOCK_BITCOIND_DIR="${SCRIPT_DIR}/mock-bitcoind"
JMX_FILE="${SCRIPT_DIR}/stratum.jmx"
CONFIG="${PROJECT_ROOT}/config-load-test.toml"
OUTPUT="flamegraph_loadtest.svg"

MOCK_PID=""
PERF_PID=""

log() {
    echo "[$(date '+%H:%M:%S')] $*"
}

cleanup() {
    log "Cleaning up..."
    if [[ -n "${PERF_PID}" ]]; then
        # Find the perf record child process and send SIGINT
        local perf_child
        perf_child=$(pgrep -P "${PERF_PID}" -f "perf record" 2>/dev/null || true)
        if [[ -n "${perf_child}" ]]; then
            kill -INT "${perf_child}" 2>/dev/null || true
        fi
        kill -INT "${PERF_PID}" 2>/dev/null || true
        wait "${PERF_PID}" 2>/dev/null || true
    fi
    if [[ -n "${MOCK_PID}" ]] && kill -0 "${MOCK_PID}" 2>/dev/null; then
        kill "${MOCK_PID}" 2>/dev/null || true
        wait "${MOCK_PID}" 2>/dev/null || true
    fi
}

trap cleanup EXIT

# Start mock-bitcoind
log "Starting mock-bitcoind..."
cd "${MOCK_BITCOIND_DIR}"
npm install --silent 2>/dev/null
node server.js > /dev/null 2>&1 &
MOCK_PID=$!
cd "${SCRIPT_DIR}"
sleep 2
log "mock-bitcoind running (PID: ${MOCK_PID})"

# Build and run P2Poolv2 under flamegraph
log "Building P2Poolv2 with debug symbols and starting under perf..."
cd "${PROJECT_ROOT}"
CARGO_PROFILE_RELEASE_DEBUG=true \
CARGO_PROFILE_RELEASE_STRIP=false \
RUSTFLAGS="-C force-frame-pointers=yes" \
    cargo flamegraph -p p2poolv2_node -o "${OUTPUT}" -- --config="${CONFIG}" > /tmp/flamegraph-build.log 2>&1 &
PERF_PID=$!
cd "${SCRIPT_DIR}"

# Wait for stratum server to start listening
log "Waiting for P2Poolv2 to start..."
for i in $(seq 1 180); do
    if lsof -i :3333 >/dev/null 2>&1; then
        log "P2Poolv2 stratum listening on port 3333 (after ${i}s)"
        break
    fi
    sleep 1
done

if ! lsof -i :3333 >/dev/null 2>&1; then
    log "ERROR: P2Poolv2 did not start within 180s"
    tail -20 /tmp/flamegraph-build.log
    exit 1
fi

# Run jmeter load test
log "Running jmeter load test..."
jmeter -n -t "${JMX_FILE}" -l /tmp/flamegraph-loadtest.jtl -j /tmp/flamegraph-jmeter.log 2>&1 | grep "^summary"
log "jmeter complete"

# Stop perf recording to generate flamegraph
log "Stopping P2Poolv2 and generating flamegraph..."
# Find the actual perf record process (child of cargo-flamegraph)
PERF_RECORD_PID=$(pgrep -f "perf record.*p2poolv2" 2>/dev/null || true)
if [[ -n "${PERF_RECORD_PID}" ]]; then
    kill -INT "${PERF_RECORD_PID}" 2>/dev/null || true
    log "Sent SIGINT to perf record (PID: ${PERF_RECORD_PID})"
fi

log "Waiting for flamegraph generation (symbol resolution takes time)..."
wait "${PERF_PID}" 2>/dev/null || true
PERF_PID=""

if [[ -f "${PROJECT_ROOT}/${OUTPUT}" ]]; then
    log "Flamegraph saved to ${PROJECT_ROOT}/${OUTPUT}"
    log "Open with: xdg-open ${PROJECT_ROOT}/${OUTPUT}"
else
    log "ERROR: Flamegraph was not generated"
    tail -20 /tmp/flamegraph-build.log
    exit 1
fi
