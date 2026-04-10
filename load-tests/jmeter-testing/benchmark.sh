#!/usr/bin/env bash

# Benchmark script for comparing P2Poolv2 build variants and CKPool.
#
# Automates the comparison between default, native builds and CKPool:
# 1. Starts mock-bitcoind
# 2. Builds P2Poolv2 (default), runs jmeter, collects results
# 3. Builds P2Poolv2 (native), runs jmeter, collects results
# 4. Runs CKPool (if --ckpool provided), runs jmeter, collects results
# 5. Prints a summary comparing all runs
#
# Prerequisites:
#   - jmeter installed and available in PATH
#   - node/npm installed
#   - Rust toolchain installed
#   - CKPool binary built (optional, for --ckpool)
#
# Usage:
#   cd load-tests/jmeter-testing
#   ./benchmark.sh [--config <path>] [--skip-default] [--skip-native] [--ckpool <path>]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"
MOCK_BITCOIND_DIR="${SCRIPT_DIR}/mock-bitcoind"
JMX_FILE="${SCRIPT_DIR}/stratum.jmx"
CKPOOL_CONFIG="${SCRIPT_DIR}/ckpool-testnet4-solo.json"

CONFIG="${PROJECT_ROOT}/config-load-test.toml"
SKIP_DEFAULT=false
SKIP_NATIVE=false
CKPOOL_BIN=""
SETTLE_SECONDS=5
P2POOL_PID=""
CKPOOL_PID=""
MOCK_PID=""

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --config <path>    Path to P2Poolv2 config file (default: config-load-test.toml)"
    echo "  --skip-default     Skip the default (portable) build test"
    echo "  --skip-native      Skip the native (CPU-optimized) build test"
    echo "  --ckpool <path>    Path to ckpool binary (enables CKPool benchmark)"
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
        --ckpool)
            CKPOOL_BIN="$2"
            shift 2
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
    if [[ -n "${CKPOOL_PID}" ]] && kill -0 "${CKPOOL_PID}" 2>/dev/null; then
        kill "${CKPOOL_PID}" 2>/dev/null || true
        wait "${CKPOOL_PID}" 2>/dev/null || true
    fi
    if [[ -n "${MOCK_PID}" ]] && kill -0 "${MOCK_PID}" 2>/dev/null; then
        kill "${MOCK_PID}" 2>/dev/null || true
        wait "${MOCK_PID}" 2>/dev/null || true
    fi
}

trap cleanup EXIT

check_prerequisites() {
    local missing=false
    for cmd in jmeter node cargo; do
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

    if [[ -n "${CKPOOL_BIN}" ]] && [[ ! -x "${CKPOOL_BIN}" ]]; then
        echo "ERROR: ckpool binary not found or not executable: ${CKPOOL_BIN}"
        exit 1
    fi
}

start_mock_bitcoind() {
    log "Starting mock-bitcoind..."
    cd "${MOCK_BITCOIND_DIR}"
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

stop_ckpool() {
    if [[ -n "${CKPOOL_PID}" ]] && kill -0 "${CKPOOL_PID}" 2>/dev/null; then
        log "Stopping CKPool (PID: ${CKPOOL_PID})..."
        kill "${CKPOOL_PID}" 2>/dev/null || true
        wait "${CKPOOL_PID}" 2>/dev/null || true
        CKPOOL_PID=""
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

start_ckpool() {
    local ckpool_log="${RESULTS_DIR}/ckpool-${run_ts}.log"
    log "Starting CKPool (log: ${ckpool_log})..."
    "${CKPOOL_BIN}" --btcsolo --config="${CKPOOL_CONFIG}" >"${ckpool_log}" 2>&1 &
    CKPOOL_PID=$!
    sleep "${SETTLE_SECONDS}"
    if ! kill -0 "${CKPOOL_PID}" 2>/dev/null; then
        echo "ERROR: CKPool failed to start"
        exit 1
    fi
    log "CKPool running (PID: ${CKPOOL_PID})"
}

run_jmeter() {
    local output_file="$1"
    log "Running jmeter load test -> ${output_file}"
    jmeter -n -t "${JMX_FILE}" -l "${output_file}" 2>&1
    log "jmeter complete"
}

# Print percentile stats for a set of sorted elapsed times.
# Args: sorted_file sample_count label
print_sampler_stats() {
    local sorted_file="$1"
    local sample_count="$2"
    local sampler_label="$3"

    if [[ "${sample_count}" -eq 0 ]]; then
        echo "    ${sampler_label}: no samples"
        return
    fi

    local error_count="$4"
    local min_val max_val avg_val p50_val p95_val p99_val

    min_val=$(head -1 "${sorted_file}")
    max_val=$(tail -1 "${sorted_file}")
    avg_val=$(awk '{sum += $1} END {printf "%.1f", sum/NR}' "${sorted_file}")

    local p50_idx=$(( (sample_count * 50 + 99) / 100 ))
    local p95_idx=$(( (sample_count * 95 + 99) / 100 ))
    local p99_idx=$(( (sample_count * 99 + 99) / 100 ))

    p50_val=$(sed -n "${p50_idx}p" "${sorted_file}")
    p95_val=$(sed -n "${p95_idx}p" "${sorted_file}")
    p99_val=$(sed -n "${p99_idx}p" "${sorted_file}")

    printf "  %-20s samples=%-8d errors=%-5d  avg=%-8s p50=%-8s p95=%-8s p99=%-8s max=%s\n" \
        "${sampler_label}" "${sample_count}" "${error_count}" \
        "${avg_val}" "${p50_val}" "${p95_val}" "${p99_val}" "${max_val}"
}

# Parse a JTL file (CSV format) and print summary statistics per sampler.
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
    total_samples=$(tail -n +2 "${jtl_file}" | wc -l)
    if [[ "${total_samples}" -eq 0 ]]; then
        echo "  No samples in ${jtl_file}"
        return
    fi

    local total_errors
    total_errors=$(tail -n +2 "${jtl_file}" | awk -F',' '{print $8}' | grep -c "false" || true)
    total_errors=${total_errors:-0}

    echo ""
    echo "=== ${label} ==="
    echo "  Total samples: ${total_samples}  Errors: ${total_errors}"
    echo ""

    # Break down by sampler label (column 3)
    local samplers_file
    samplers_file=$(mktemp)
    tail -n +2 "${jtl_file}" | awk -F',' '{print $3}' | sort -u > "${samplers_file}"

    while IFS= read -r sampler_name; do
        local sorted_file
        sorted_file=$(mktemp)

        local sampler_count
        sampler_count=$(tail -n +2 "${jtl_file}" | awk -F',' -v s="${sampler_name}" '$3 == s {print $2}' | sort -n | tee "${sorted_file}" | wc -l)

        local sampler_errors
        sampler_errors=$(tail -n +2 "${jtl_file}" | awk -F',' -v s="${sampler_name}" '$3 == s && $8 == "false"' | wc -l)

        print_sampler_stats "${sorted_file}" "${sampler_count}" "${sampler_name}" "${sampler_errors}"

        rm -f "${sorted_file}"
    done < "${samplers_file}"

    rm -f "${samplers_file}"
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
ckpool_jtl="${RESULTS_DIR}/ckpool-${run_ts}.jtl"

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

if [[ -n "${CKPOOL_BIN}" ]]; then
    log "--- CKPool ---"
    if ! kill -0 "${MOCK_PID}" 2>/dev/null; then
        log "mock-bitcoind died, restarting..."
        start_mock_bitcoind
    fi
    # Wait for stratum port to be fully released after P2Poolv2 shutdown
    log "Waiting for port 3333 to be released..."
    port_wait=0
    while lsof -i :3333 >/dev/null 2>&1 && [[ "${port_wait}" -lt 30 ]]; do
        sleep 1
        port_wait=$((port_wait + 1))
    done
    # Verify mock-bitcoind still responds
    if ! curl -s --max-time 3 -X POST -H "Content-Type: application/json" \
        -d '{"method":"getdifficulty","params":[],"id":0}' \
        http://127.0.0.1:38332/ >/dev/null 2>&1; then
        log "mock-bitcoind not responding, restarting..."
        kill "${MOCK_PID}" 2>/dev/null || true
        wait "${MOCK_PID}" 2>/dev/null || true
        start_mock_bitcoind
    fi
    start_ckpool
    run_jmeter "${ckpool_jtl}"
    stop_ckpool
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

if [[ -n "${CKPOOL_BIN}" ]]; then
    summarize_jtl "${ckpool_jtl}" "CKPool"
fi

echo ""
echo "Raw results saved in: ${RESULTS_DIR}/"
log "Benchmark complete"
