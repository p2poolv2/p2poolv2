#!/usr/bin/env bash

# Benchmark script for comparing P2Poolv2 build variants.
#
# Automates the A/B comparison between default and native builds:
# 1. Starts mock-bitcoind
# 2. Builds P2Poolv2 (default), runs jmeter, collects results
# 3. Builds P2Poolv2 (native), runs jmeter, collects results
# 4. Prints a summary comparing both runs
#
# Prerequisites:
#   - jmeter installed and available in PATH
#   - node/npm installed
#   - Rust toolchain installed
#
# Usage:
#   cd load-tests/jmeter-testing
#   ./benchmark.sh [--config <path>] [--skip-default] [--skip-native]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"
MOCK_BITCOIND_DIR="${SCRIPT_DIR}/mock-bitcoind"
JMX_FILE="${SCRIPT_DIR}/stratum.jmx"

CONFIG="${PROJECT_ROOT}/config-load-test.toml"
SKIP_DEFAULT=false
SKIP_NATIVE=false
SETTLE_SECONDS=5
P2POOL_PID=""
MOCK_PID=""

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --config <path>    Path to P2Poolv2 config file (default: config-load-test.toml)"
    echo "  --skip-default     Skip the default (portable) build test"
    echo "  --skip-native      Skip the native (CPU-optimized) build test"
    echo "  -h, --help         Show this help message"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)
            CONFIG="$2"
            shift 2
            ;;
        --skip-default)
            SKIP_DEFAULT=true
            shift
            ;;
        --skip-native)
            SKIP_NATIVE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

timestamp() {
    date "+%Y%m%d-%H%M%S"
}

log() {
    echo "[$(date '+%H:%M:%S')] $*"
}

cleanup() {
    log "Cleaning up..."
    if [[ -n "${P2POOL_PID}" ]] && kill -0 "${P2POOL_PID}" 2>/dev/null; then
        kill "${P2POOL_PID}" 2>/dev/null || true
        wait "${P2POOL_PID}" 2>/dev/null || true
    fi
    if [[ -n "${MOCK_PID}" ]] && kill -0 "${MOCK_PID}" 2>/dev/null; then
        kill "${MOCK_PID}" 2>/dev/null || true
        wait "${MOCK_PID}" 2>/dev/null || true
    fi
}

trap cleanup EXIT

check_prerequisites() {
    local missing=false
    for cmd in jmeter node npm cargo; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            echo "ERROR: ${cmd} is not installed or not in PATH"
            missing=true
        fi
    done
    if [[ "${missing}" = true ]]; then
        exit 1
    fi

    if [[ ! -f "${JMX_FILE}" ]]; then
        echo "ERROR: jmeter test file not found: ${JMX_FILE}"
        exit 1
    fi

    if [[ ! -f "${CONFIG}" ]]; then
        echo "ERROR: P2Poolv2 config not found: ${CONFIG}"
        exit 1
    fi
}

start_mock_bitcoind() {
    log "Starting mock-bitcoind..."
    cd "${MOCK_BITCOIND_DIR}"
    npm install --silent 2>/dev/null
    node server.js >"${RESULTS_DIR}/mock-bitcoind-${run_ts}.log" 2>&1 &
    MOCK_PID=$!
    cd "${SCRIPT_DIR}"
    sleep 2
    if ! kill -0 "${MOCK_PID}" 2>/dev/null; then
        echo "ERROR: mock-bitcoind failed to start"
        exit 1
    fi
    log "mock-bitcoind running (PID: ${MOCK_PID})"
}

stop_p2pool() {
    if [[ -n "${P2POOL_PID}" ]] && kill -0 "${P2POOL_PID}" 2>/dev/null; then
        log "Stopping P2Poolv2 (PID: ${P2POOL_PID})..."
        kill "${P2POOL_PID}" 2>/dev/null || true
        wait "${P2POOL_PID}" 2>/dev/null || true
        P2POOL_PID=""
    fi
}

build_p2pool() {
    local variant="$1"
    log "Building P2Poolv2 (${variant})..."
    cd "${PROJECT_ROOT}"
    if [[ "${variant}" = "native" ]]; then
        RUSTFLAGS='-C target-cpu=native' cargo build --workspace --release 2>&1
    else
        cargo build --workspace --release 2>&1
    fi
    cd "${SCRIPT_DIR}"
    log "Build complete (${variant})"
}

start_p2pool() {
    local variant="${1:-default}"
    local p2pool_log="${RESULTS_DIR}/p2poolv2-${variant}-${run_ts}.log"
    log "Starting P2Poolv2 (log: ${p2pool_log})..."
    "${PROJECT_ROOT}/target/release/p2poolv2" --config="${CONFIG}" >"${p2pool_log}" 2>&1 &
    P2POOL_PID=$!
    sleep "${SETTLE_SECONDS}"
    if ! kill -0 "${P2POOL_PID}" 2>/dev/null; then
        echo "ERROR: P2Poolv2 failed to start"
        exit 1
    fi
    log "P2Poolv2 running (PID: ${P2POOL_PID})"
}

run_jmeter() {
    local output_file="$1"
    log "Running jmeter load test -> ${output_file}"
    jmeter -n -t "${JMX_FILE}" -l "${output_file}" 2>&1
    log "jmeter complete"
}

# Parse a JTL file (CSV format) and print summary statistics.
# JTL columns: timeStamp,elapsed,label,responseCode,responseMessage,
#               threadName,dataType,success,failureMessage,bytes,
#               sentBytes,grpThreads,allThreads,URL,Latency,IdleTime,Connect
summarize_jtl() {
    local jtl_file="$1"
    local label="$2"

    if [[ ! -f "${jtl_file}" ]]; then
        echo "  No results file found: ${jtl_file}"
        return
    fi

    local total_samples
    local error_count
    local min_elapsed
    local max_elapsed
    local avg_elapsed
    local p50_elapsed
    local p95_elapsed
    local p99_elapsed

    # Skip header line, extract elapsed times
    total_samples=$(tail -n +2 "${jtl_file}" | wc -l)
    if [[ "${total_samples}" -eq 0 ]]; then
        echo "  No samples in ${jtl_file}"
        return
    fi

    error_count=$(tail -n +2 "${jtl_file}" | awk -F',' '{print $8}' | grep -c "false" || true)
    error_count=${error_count:-0}

    # Sort elapsed times for percentile calculation
    local sorted_file
    sorted_file=$(mktemp)
    tail -n +2 "${jtl_file}" | awk -F',' '{print $2}' | sort -n > "${sorted_file}"

    min_elapsed=$(head -1 "${sorted_file}")
    max_elapsed=$(tail -1 "${sorted_file}")
    avg_elapsed=$(awk '{sum += $1} END {printf "%.1f", sum/NR}' "${sorted_file}")

    local p50_index=$(( (total_samples * 50 + 99) / 100 ))
    local p95_index=$(( (total_samples * 95 + 99) / 100 ))
    local p99_index=$(( (total_samples * 99 + 99) / 100 ))

    p50_elapsed=$(sed -n "${p50_index}p" "${sorted_file}")
    p95_elapsed=$(sed -n "${p95_index}p" "${sorted_file}")
    p99_elapsed=$(sed -n "${p99_index}p" "${sorted_file}")

    rm -f "${sorted_file}"

    echo ""
    echo "=== ${label} ==="
    echo "  Total samples:  ${total_samples}"
    echo "  Errors:         ${error_count}"
    echo "  Elapsed time (ms):"
    echo "    Min:          ${min_elapsed}"
    echo "    Avg:          ${avg_elapsed}"
    echo "    p50:          ${p50_elapsed}"
    echo "    p95:          ${p95_elapsed}"
    echo "    p99:          ${p99_elapsed}"
    echo "    Max:          ${max_elapsed}"
}

# -- Main --

check_prerequisites

run_ts=$(timestamp)
mkdir -p "${RESULTS_DIR}"

log "Starting benchmark run: ${run_ts}"
log "Config: ${CONFIG}"

start_mock_bitcoind

default_jtl="${RESULTS_DIR}/p2poolv2-default-${run_ts}.jtl"
native_jtl="${RESULTS_DIR}/p2poolv2-native-${run_ts}.jtl"

if [[ "${SKIP_DEFAULT}" = false ]]; then
    log "--- Default build variant ---"
    build_p2pool "default"
    start_p2pool "default"
    run_jmeter "${default_jtl}"
    stop_p2pool
fi

if [[ "${SKIP_NATIVE}" = false ]]; then
    log "--- Native build variant ---"
    build_p2pool "native"
    start_p2pool "native"
    run_jmeter "${native_jtl}"
    stop_p2pool
fi

echo ""
echo "========================================"
echo "  Benchmark Results: ${run_ts}"
echo "========================================"

if [[ "${SKIP_DEFAULT}" = false ]]; then
    summarize_jtl "${default_jtl}" "Default build (portable)"
fi

if [[ "${SKIP_NATIVE}" = false ]]; then
    summarize_jtl "${native_jtl}" "Native build (target-cpu=native)"
fi

echo ""
echo "Raw results saved in: ${RESULTS_DIR}/"
log "Benchmark complete"
