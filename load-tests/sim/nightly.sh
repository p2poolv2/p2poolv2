#!/usr/bin/env bash
#
# Nightly simulation runner: end-to-end automated sim with pass/fail verdict.
#
# Starts regtest bitcoind if needed, launches a swarm via run-swarm.sh, waits
# for convergence, collects metrics via metrics.sh, evaluates pass/fail
# thresholds, cleans up, and exits 0 (pass) or 1 (fail).
#
# Usage:
#   load-tests/sim/nightly.sh
#
# Env overrides (nightly-specific):
#   NODE_COUNT                 number of sim nodes           (default 20)
#   CONVERGENCE_WAIT_SECONDS   seconds to let swarm run      (default 60)
#   UNCLE_RATE_THRESHOLD       max uncle rate % to pass      (default 25)
#   BITCOIND_DATADIR           regtest data directory        (default /tmp/bitcoind-p2poolv2)
#   BITCOIND_BIN               path to bitcoind binary       (auto-detected)
#   BITCOIN_CLI_BIN            path to bitcoin-cli binary    (auto-detected)
#
# All run-swarm.sh env vars (RUN_DIR, RPC_URL, RPC_USER, RPC_PASS, ZMQ,
# SHARES_PER_BLOCK, LATENCY_MS, IDEAL_BLOCK_TIME, etc.) are passed through as-is.
set -euo pipefail

show_help() {
  cat <<'HELP'
nightly.sh -- automated sim runner with pass/fail verdict

Starts regtest bitcoind if needed, launches a swarm, waits for convergence,
collects metrics, evaluates thresholds, and exits 0 (pass) or 1 (fail).

Usage:
  load-tests/sim/nightly.sh [--help]

Examples:
  ./load-tests/sim/nightly.sh                              # 20 nodes, 60s, default settings
  NODE_COUNT=5 CONVERGENCE_WAIT_SECONDS=30 ./load-tests/sim/nightly.sh
  IDEAL_BLOCK_TIME=1 SHARES_PER_BLOCK=100 ./load-tests/sim/nightly.sh  # time-compressed, frequent blocks

Env vars (nightly-specific):
  NODE_COUNT                 number of sim nodes           (default 20)
  CONVERGENCE_WAIT_SECONDS   seconds to let swarm run      (default 60)
  UNCLE_RATE_THRESHOLD       max uncle rate % to pass      (default 25)
  BITCOIND_DATADIR           regtest data directory        (default /tmp/bitcoind-p2poolv2)
  BITCOIND_BIN               path to bitcoind binary       (auto-detected)
  BITCOIN_CLI_BIN            path to bitcoin-cli binary    (auto-detected)

Env vars (passed through to run-swarm.sh):
  RUN_DIR                    work dir for configs/logs     (default /tmp/p2pool-sim)
  SHARES_PER_BLOCK           shares per block-find         (default 10000)
  IDEAL_BLOCK_TIME           share interval in seconds     (default 10; lower = time-compressed)
  LATENCY_MS                 per-node outbound delay ms    (default 0)
  DIAL_FANOUT                peers each node dials         (default 3)
  HASHRATE                   mean per-node hashrate        (default 1.0e12)
  RPC_URL / RPC_USER / RPC_PASS   bitcoind RPC             (default localhost:19443 p2pool/p2pool)
  ZMQ                        zmqpubhashblock               (default tcp://127.0.0.1:28332)

Related scripts:
  load-tests/sim/run-swarm.sh N    launch swarm for manual exploration
  load-tests/sim/stop-swarm.sh     stop a running swarm
  load-tests/sim/metrics.sh        show log-based metrics summary
  load-tests/sim/plot-metrics.sh   generate metrics PNG from last run
HELP
  exit 0
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  show_help
fi

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
NODE_COUNT="${NODE_COUNT:-20}"
CONVERGENCE_WAIT_SECONDS="${CONVERGENCE_WAIT_SECONDS:-60}"
UNCLE_RATE_THRESHOLD="${UNCLE_RATE_THRESHOLD:-25}"
BITCOIND_DATADIR="${BITCOIND_DATADIR:-/tmp/bitcoind-p2poolv2}"
RPC_URL="${RPC_URL:-http://127.0.0.1:19443}"
RPC_USER="${RPC_USER:-p2pool}"
RPC_PASS="${RPC_PASS:-p2pool}"
ZMQ="${ZMQ:-tcp://127.0.0.1:28332}"
RUN_DIR="${RUN_DIR:-/tmp/p2pool-sim}"
SHARES_PER_BLOCK="${SHARES_PER_BLOCK:-10000}"
DIAL_FANOUT="${DIAL_FANOUT:-3}"
export RUN_DIR RPC_URL RPC_USER RPC_PASS ZMQ SHARES_PER_BLOCK DIAL_FANOUT

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
STARTED_BITCOIND=0
SWARM_RUNNING=0
METRICS_OUTPUT=""

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

log_message() {
  echo "[$(date +%H:%M:%S)] $*"
}

rpc_call() {
  curl -s --user "$RPC_USER:$RPC_PASS" \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"n\",\"method\":\"$1\",\"params\":${2:-[]}}" \
    -H 'content-type: text/plain;' "$RPC_URL"
}

find_bitcoind_binary() {
  if [ -n "${BITCOIND_BIN:-}" ]; then
    return
  fi
  if [ -x /opt/homebrew/bin/bitcoind ]; then
    BITCOIND_BIN=/opt/homebrew/bin/bitcoind
    return
  fi
  if command -v bitcoind >/dev/null 2>&1; then
    BITCOIND_BIN="$(command -v bitcoind)"
    return
  fi
  echo "ERROR: bitcoind not found. Set BITCOIND_BIN or install bitcoind." >&2
  exit 1
}

find_bitcoin_cli_binary() {
  if [ -n "${BITCOIN_CLI_BIN:-}" ]; then
    return
  fi
  if [ -x /opt/homebrew/bin/bitcoin-cli ]; then
    BITCOIN_CLI_BIN=/opt/homebrew/bin/bitcoin-cli
    return
  fi
  if command -v bitcoin-cli >/dev/null 2>&1; then
    BITCOIN_CLI_BIN="$(command -v bitcoin-cli)"
    return
  fi
  echo "ERROR: bitcoin-cli not found. Set BITCOIN_CLI_BIN or install bitcoin-cli." >&2
  exit 1
}

bitcoin_cli() {
  "$BITCOIN_CLI_BIN" -regtest \
    -datadir="$BITCOIND_DATADIR" \
    -rpcport=19443 \
    -rpcuser="$RPC_USER" \
    -rpcpassword="$RPC_PASS" \
    "$@"
}

# ---------------------------------------------------------------------------
# Lifecycle functions
# ---------------------------------------------------------------------------

ensure_bitcoind_running() {
  if rpc_call getblockchaininfo '[]' 2>/dev/null | grep -q '"regtest"'; then
    log_message "regtest bitcoind already running at $RPC_URL"
    return
  fi

  log_message "Starting fresh regtest bitcoind..."
  rm -rf "$BITCOIND_DATADIR"
  mkdir -p "$BITCOIND_DATADIR"
  "$BITCOIND_BIN" -regtest \
    -datadir="$BITCOIND_DATADIR" \
    -daemon \
    -rpcport=19443 \
    -rpcuser="$RPC_USER" \
    -rpcpassword="$RPC_PASS" \
    -zmqpubhashblock="$ZMQ" \
    -fallbackfee=0.0001

  attempt=0
  max_attempts=30
  while [ "$attempt" -lt "$max_attempts" ]; do
    if rpc_call getblockchaininfo '[]' 2>/dev/null | grep -q '"regtest"'; then
      STARTED_BITCOIND=1
      log_message "bitcoind ready (attempt $((attempt + 1)))"
      return
    fi
    sleep 1
    attempt=$((attempt + 1))
  done

  echo "ERROR: bitcoind did not become ready within ${max_attempts}s" >&2
  exit 1
}

ensure_wallet_and_coins() {
  log_message "Ensuring wallet and coins..."
  bitcoin_cli createwallet p2pool 2>/dev/null || bitcoin_cli loadwallet p2pool 2>/dev/null || true

  block_count=$(bitcoin_cli getblockcount 2>/dev/null || echo 0)
  if [ "$block_count" -lt 101 ]; then
    blocks_needed=$((101 - block_count))
    address=$(bitcoin_cli getnewaddress)
    log_message "Mining $blocks_needed blocks to reach height 101..."
    bitcoin_cli generatetoaddress "$blocks_needed" "$address" >/dev/null
  fi

  log_message "Wallet ready, block height: $(bitcoin_cli getblockcount)"
}

run_swarm() {
  log_message "Starting ${NODE_COUNT}-node sim swarm..."
  "$SCRIPT_DIR/run-swarm.sh" "$NODE_COUNT"
  SWARM_RUNNING=1
}

wait_for_convergence() {
  log_message "Waiting ${CONVERGENCE_WAIT_SECONDS}s for convergence..."
  sleep "$CONVERGENCE_WAIT_SECONDS"
}

collect_metrics() {
  log_message "Collecting metrics..."
  METRICS_OUTPUT=$("$SCRIPT_DIR/metrics.sh" 2>&1) || true
  echo ""
  echo "$METRICS_OUTPUT"
  echo ""
}

stop_swarm() {
  if [ "$SWARM_RUNNING" -eq 1 ]; then
    log_message "Stopping swarm..."
    "$SCRIPT_DIR/stop-swarm.sh" || true
    SWARM_RUNNING=0
  fi
}

verify_all_chains() {
  local profile="${PROFILE:-release}"
  local verify_bin
  if [ "$profile" = "release" ]; then
    verify_bin="$REPO_ROOT/target/release/verify_chain"
  else
    verify_bin="$REPO_ROOT/target/debug/verify_chain"
  fi

  if [ ! -x "$verify_bin" ]; then
    log_message "Building verify_chain ($profile)..."
    local profile_flag=""
    [ "$profile" = "release" ] && profile_flag="--release"
    ( cd "$REPO_ROOT" && cargo build -p p2poolv2_node --bin verify_chain --features debug-tools $profile_flag )
  fi

  VERIFY_CHAIN_FAILURES=0
  VERIFY_CHAIN_TOTAL=0
  log_message "Running verify_chain on all ${NODE_COUNT} node stores..."
  for i in $(seq 0 $((NODE_COUNT - 1))); do
    local store="$RUN_DIR/store-$i.db"
    VERIFY_CHAIN_TOTAL=$((VERIFY_CHAIN_TOTAL + 1))
    if [ ! -d "$store" ]; then
      log_message "  node $i: FAIL (store not found at $store)"
      VERIFY_CHAIN_FAILURES=$((VERIFY_CHAIN_FAILURES + 1))
      continue
    fi
    if "$verify_bin" "$store" > "$RUN_DIR/verify-$i.log" 2>&1; then
      log_message "  node $i: PASS"
    else
      log_message "  node $i: FAIL (see $RUN_DIR/verify-$i.log)"
      VERIFY_CHAIN_FAILURES=$((VERIFY_CHAIN_FAILURES + 1))
    fi
  done
}

stop_bitcoind_if_started() {
  if [ "$STARTED_BITCOIND" -eq 1 ]; then
    log_message "Stopping bitcoind (started by this script)..."
    bitcoin_cli stop 2>/dev/null || true
    STARTED_BITCOIND=0
  fi
}

cleanup() {
  log_message "Cleaning up..."
  stop_swarm
  stop_bitcoind_if_started
}

# ---------------------------------------------------------------------------
# Evaluation functions
# ---------------------------------------------------------------------------

check_all_nodes_alive() {
  local pids_file="$RUN_DIR/pids.txt"
  if [ ! -f "$pids_file" ]; then
    ALIVE_COUNT=0
    ALIVE_TOTAL=0
    return 1
  fi

  ALIVE_COUNT=0
  ALIVE_TOTAL=0
  while read -r pid; do
    [ -z "$pid" ] && pid="skip"
    if [ "$pid" = "skip" ]; then
      ALIVE_TOTAL=$((ALIVE_TOTAL + 0))
    else
      ALIVE_TOTAL=$((ALIVE_TOTAL + 1))
      if kill -0 "$pid" 2>/dev/null; then
        ALIVE_COUNT=$((ALIVE_COUNT + 1))
      fi
    fi
  done < "$pids_file"

  [ "$ALIVE_COUNT" -eq "$ALIVE_TOTAL" ] && [ "$ALIVE_TOTAL" -gt 0 ]
}

check_chain_converged() {
  DISTINCT_HASHES=$(echo "$METRICS_OUTPUT" \
    | grep -oE "distinct block hash at height [0-9]+ across nodes: [0-9]+" \
    | grep -oE "[0-9]+$" || echo "-1")
  [ "$DISTINCT_HASHES" -eq 1 ]
}

check_chain_grew() {
  PROMOTION_COUNT=$(echo "$METRICS_OUTPUT" \
    | grep -oE "promotions=[0-9]+" \
    | head -1 \
    | grep -oE "[0-9]+" || echo "0")
  [ "$PROMOTION_COUNT" -gt 0 ]
}

check_no_panics() {
  PANIC_COUNT=$(echo "$METRICS_OUTPUT" \
    | grep -oE "panicked nodes: [0-9]+" \
    | grep -oE "[0-9]+" || echo "-1")
  [ "$PANIC_COUNT" -eq 0 ]
}

check_no_rejections() {
  ASERT_MISMATCH_COUNT=$(echo "$METRICS_OUTPUT" \
    | grep -oE "AsertMismatch=[0-9]+" \
    | grep -oE "[0-9]+" || echo "-1")
  MERKLE_PAYOUT_COUNT=$(echo "$METRICS_OUTPUT" \
    | grep -oE "merkle/payout=[0-9]+" \
    | grep -oE "[0-9]+" || echo "-1")
  [ "$ASERT_MISMATCH_COUNT" -eq 0 ] && [ "$MERKLE_PAYOUT_COUNT" -eq 0 ]
}

check_uncle_rate() {
  UNCLE_RATE=$(echo "$METRICS_OUTPUT" \
    | grep -oE "uncle rate \(node 0\): [0-9.]+" \
    | grep -oE "[0-9.]+$" || echo "0")
  awk -v rate="$UNCLE_RATE" -v threshold="$UNCLE_RATE_THRESHOLD" \
    'BEGIN { exit !(rate < threshold) }'
}

evaluate_results() {
  local failed=0

  local alive_result="PASS"
  if [ "$ALIVE_COUNT" -ne "$ALIVE_TOTAL" ] || [ "$ALIVE_TOTAL" -eq 0 ]; then
    alive_result="FAIL"
    failed=1
  fi

  local converged_result="PASS"
  if ! check_chain_converged; then
    converged_result="FAIL"
    failed=1
  fi

  local grew_result="PASS"
  if ! check_chain_grew; then
    grew_result="FAIL"
    failed=1
  fi

  local panics_result="PASS"
  if ! check_no_panics; then
    panics_result="FAIL"
    failed=1
  fi

  local rejections_result="PASS"
  if ! check_no_rejections; then
    rejections_result="FAIL"
    failed=1
  fi

  local uncle_result="PASS"
  if ! check_uncle_rate; then
    uncle_result="FAIL"
    failed=1
  fi

  local verify_result="PASS"
  if [ "${VERIFY_CHAIN_FAILURES:-0}" -gt 0 ]; then
    verify_result="FAIL"
    failed=1
  fi

  echo "=== NIGHTLY SIM RESULTS ==="
  printf "  nodes alive:        %-4s  (%s/%s)\n" \
    "$alive_result" "$ALIVE_COUNT" "$ALIVE_TOTAL"
  printf "  chain converged:    %-4s  (distinct hashes: %s)\n" \
    "$converged_result" "$DISTINCT_HASHES"
  printf "  chain grew:         %-4s  (promotions: %s)\n" \
    "$grew_result" "$PROMOTION_COUNT"
  printf "  no panics:          %-4s  (panicked nodes: %s)\n" \
    "$panics_result" "$PANIC_COUNT"
  printf "  no rejections:      %-4s  (AsertMismatch=%s merkle/payout=%s)\n" \
    "$rejections_result" "$ASERT_MISMATCH_COUNT" "$MERKLE_PAYOUT_COUNT"
  printf "  uncle rate:         %-4s  (%s%% < %s%%)\n" \
    "$uncle_result" "$UNCLE_RATE" "$UNCLE_RATE_THRESHOLD"
  printf "  verify_chain:       %-4s  (%s/%s passed)\n" \
    "$verify_result" "$((VERIFY_CHAIN_TOTAL - VERIFY_CHAIN_FAILURES))" "$VERIFY_CHAIN_TOTAL"

  if [ "$failed" -eq 0 ]; then
    echo "RESULT: PASS"
  else
    echo "RESULT: FAIL"
  fi

  return "$failed"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

find_bitcoind_binary
find_bitcoin_cli_binary

trap cleanup EXIT

ensure_bitcoind_running
ensure_wallet_and_coins

run_swarm
wait_for_convergence
check_all_nodes_alive || true
collect_metrics
stop_swarm
verify_all_chains

evaluate_results
