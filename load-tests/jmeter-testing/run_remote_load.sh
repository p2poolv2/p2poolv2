#!/usr/bin/env bash

# Standalone JMeter load generator for a remote P2Poolv2 stratum server.
#
# The server is assumed to be already running (e.g. under perf/flamegraph)
# on a separate host. This script only drives the client-side traffic.
#
# Usage:
#   ./run_remote_load.sh --host <server-ip> [OPTIONS]
#
# Options:
#   --host <ip>         Stratum server IP/hostname (required)
#   --port <port>       Stratum server port (default: 3333)
#   --threads <n>       Number of simulated miners (default: 5000)
#   --ramp <seconds>    Ramp-up time in seconds (default: 60)
#   --duration <secs>   Test duration in seconds (default: 300)
#   --delay <ms>        Delay between submit calls per thread (default: 3000)
#   -h, --help          Show this help message
#
# Prerequisites:
#   - jmeter installed and in PATH
#   - JAVA_HOME set if needed (e.g. JAVA_HOME=/usr/lib/jvm/java-21-openjdk)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JMX_FILE="${SCRIPT_DIR}/stratum.jmx"
RESULTS_DIR="${SCRIPT_DIR}/results"

HOST=""
PORT="3333"
THREADS="5000"
RAMP="60"
DURATION="300"
DELAY="3000"

usage() {
    echo "Usage: $0 --host <server-ip> [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --host <ip>         Stratum server IP/hostname (required)"
    echo "  --port <port>       Stratum server port (default: 3333)"
    echo "  --threads <n>       Number of simulated miners (default: 5000)"
    echo "  --ramp <seconds>    Ramp-up time (default: 60)"
    echo "  --duration <secs>   Test duration (default: 300)"
    echo "  --delay <ms>        Submit interval per thread (default: 3000)"
    echo "  -h, --help          Show this help message"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)
            HOST="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --threads)
            THREADS="$2"
            shift 2
            ;;
        --ramp)
            RAMP="$2"
            shift 2
            ;;
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --delay)
            DELAY="$2"
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

if [[ -z "${HOST}" ]]; then
    echo "ERROR: --host is required"
    usage
    exit 1
fi

if ! command -v jmeter >/dev/null 2>&1; then
    echo "ERROR: jmeter is not installed or not in PATH"
    exit 1
fi

if [[ ! -f "${JMX_FILE}" ]]; then
    echo "ERROR: JMX file not found: ${JMX_FILE}"
    exit 1
fi

log() {
    echo "[$(date '+%H:%M:%S')] $*"
}

timestamp() {
    date "+%Y%m%d-%H%M%S"
}

run_ts=$(timestamp)
mkdir -p "${RESULTS_DIR}"

JTL_FILE="${RESULTS_DIR}/remote-${HOST}-${run_ts}.jtl"
JMETER_LOG="${RESULTS_DIR}/remote-${HOST}-${run_ts}-jmeter.log"

log "Target: ${HOST}:${PORT}"
log "Threads: ${THREADS}  Ramp: ${RAMP}s  Duration: ${DURATION}s  Submit delay: ${DELAY}ms"
log "Results: ${JTL_FILE}"

log "Running jmeter load test..."
jmeter -n -t "${JMX_FILE}" \
    -l "${JTL_FILE}" \
    -j "${JMETER_LOG}" \
    -Jstratum.host="${HOST}" \
    -Jstratum.port="${PORT}" \
    -JThreadGroup.num_threads="${THREADS}" \
    -JThreadGroup.ramp_time="${RAMP}" \
    -JThreadGroup.duration="${DURATION}" \
    -JConstantTimer.delay="${DELAY}" \
    2>&1 | grep "^summary"

log "jmeter complete"
log "Results: ${JTL_FILE}"
log "Log: ${JMETER_LOG}"
