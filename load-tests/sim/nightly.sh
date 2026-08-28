#!/usr/bin/env bash
#
# Nightly simulation runner: end-to-end automated sim with pass/fail verdict.
#
# Starts regtest bitcoind if needed, launches a swarm via run-swarm.sh, injects
# a failure scenario via failures.sh, waits for convergence, collects metrics
# via metrics.sh, evaluates pass/fail thresholds, cleans up, and exits 0 (pass)
# or 1 (fail).
#
# Usage:
#   load-tests/sim/nightly.sh [scenario]
#
# The scenario selects which failure mode to inject; `clean` injects none. The
# nightly workflow runs this script once per scenario, so each failure mode
# gets its own swarm, its own verdict and its own artifacts.
#
# Env overrides (nightly-specific):
#   SCENARIO                   failure scenario to inject    (default clean)
#                              clean | restart-fast | restart-delayed |
#                              partition | all
#   NODE_COUNT                 number of sim nodes           (default 20)
#   CONVERGENCE_WAIT_SECONDS   seconds to settle after the
#                              scenario, before the checks   (default 60)
#   UNCLE_RATE_THRESHOLD       max uncle rate % to pass      (default 25)
#   BITCOIND_DATADIR           regtest data directory        (default /tmp/bitcoind-p2poolv2)
#   BITCOIND_BIN               path to bitcoind binary       (auto-detected)
#   BITCOIN_CLI_BIN            path to bitcoin-cli binary    (auto-detected)
#
# All run-swarm.sh env vars (RUN_DIR, RPC_URL, RPC_USER, RPC_PASS, ZMQ,
# SHARES_PER_BLOCK, LATENCY_MS, IDEAL_BLOCK_TIME, etc.) and all failures.sh
# env vars (FAILURE_SEED, FAILURE_WARMUP, FAILURE_SLOW_DOWN, etc.) are passed
# through as-is.
set -euo pipefail

show_help() {
  cat <<'HELP'
nightly.sh -- automated sim runner with pass/fail verdict

Starts regtest bitcoind if needed, launches a swarm, injects a failure
scenario, waits for convergence, collects metrics, evaluates thresholds, and
exits 0 (pass) or 1 (fail).

Usage:
  load-tests/sim/nightly.sh [scenario] [--help]

Scenarios (see load-tests/sim/failures.sh --help for the details):
  clean             no failures injected (the default)
  restart-fast      a node fails and comes back immediately
  restart-delayed   a node fails and comes back after a long delay
  partition         several nodes fail at once, cutting the dial chain
  all               the three failure scenarios in sequence

Examples:
  ./load-tests/sim/nightly.sh                              # 20 nodes, 60s, no failures
  ./load-tests/sim/nightly.sh restart-delayed              # long-downtime catch-up
  NODE_COUNT=5 CONVERGENCE_WAIT_SECONDS=30 ./load-tests/sim/nightly.sh
  IDEAL_BLOCK_TIME=1 SHARES_PER_BLOCK=100 ./load-tests/sim/nightly.sh  # time-compressed, frequent blocks

Env vars (nightly-specific):
  SCENARIO                   failure scenario to inject    (default clean)
  NODE_COUNT                 number of sim nodes           (default 20)
  CONVERGENCE_WAIT_SECONDS   seconds to settle after the
                             scenario, before the checks   (default 60)
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
  load-tests/sim/failures.sh S     inject scenario S into a running swarm
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
SCENARIO="${1:-${SCENARIO:-clean}}"
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
FAILURE_OUTPUT=""

# Validate the scenario here as well as in failures.sh, so a typo fails now
# rather than after bitcoind and the swarm have been brought up.
case "$SCENARIO" in
  clean|restart-fast|restart-delayed|partition|all) ;;
  *)
    echo "ERROR: unknown scenario '$SCENARIO' (expected clean, restart-fast, restart-delayed, partition or all)" >&2
    exit 2
    ;;
esac

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

# Run the failure scenario. Its progress streams straight through so a long
# scenario is visible in the CI log while it runs; the summary is read back
# from the results file afterwards.
inject_failures() {
  log_message "Injecting failure scenario '$SCENARIO'..."
  "$SCRIPT_DIR/failures.sh" "$SCENARIO" || true
  FAILURE_OUTPUT=$(cat "$RUN_DIR/failure-results.txt" 2>/dev/null) || FAILURE_OUTPUT=""
}

# Settle window between the last injected failure healing and the checks, so
# the swarm has time to converge on one chain again.
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

# Locate (or build) the p2poolv2_cli binary, used for the store-based
# convergence check. Sets CLI_BIN.
ensure_cli_built() {
  local profile="${PROFILE:-release}"
  if [ "$profile" = "release" ]; then
    CLI_BIN="$REPO_ROOT/target/release/p2poolv2_cli"
  else
    CLI_BIN="$REPO_ROOT/target/debug/p2poolv2_cli"
  fi

  if [ ! -x "$CLI_BIN" ]; then
    log_message "Building p2poolv2_cli ($profile)..."
    local profile_flag=""
    [ "$profile" = "release" ] && profile_flag="--release"
    ( cd "$REPO_ROOT" && cargo build -p p2poolv2_cli $profile_flag )
  fi
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

# Run a p2poolv2_cli query against a store and echo its JSON on stdout.
#
# On a non-zero exit the CLI's stderr is surfaced on OUR stderr (so it reaches
# the console log without polluting the value the caller captures) rather than
# being discarded. A silently empty result here is indistinguishable from an
# empty chain, which is what made a failed nightly undiagnosable from its
# artifact: a locked store, a missing binary and a corrupt chain all looked the
# same.
query_store() {
  local store="$1"
  shift
  local stderr_file output status=0
  stderr_file="$(mktemp)"
  output=$("$CLI_BIN" --db-path "$store" "$@" 2>"$stderr_file") || status=$?
  if [ "$status" -ne 0 ]; then
    log_message "  p2poolv2_cli $* failed on $store (exit $status):" >&2
    head -5 "$stderr_file" | sed 's/^/    /' >&2
  fi
  rm -f "$stderr_file"
  printf '%s' "$output"
}

# Confirmed tip height of a store, or empty on error. Uses `shares --num 1`
# (not `info`, which reads chain-tip metadata that can fail to decode on some
# stores).
store_tip_height() {
  query_store "$1" shares --num 1 \
    | python3 -c "
import sys, json
try:
    shares = json.load(sys.stdin).get('shares', [])
    print(shares[0]['height'] if shares else '')
except Exception:
    print('')
"
}

# Confirmed block hash at a specific height in a store, or empty if the store
# has no confirmed block at that height (or on error).
store_hash_at_height() {
  local store="$1" height="$2"
  query_store "$store" shares --to "$height" --num 1 \
    | python3 -c "
import sys, json
want = int(sys.argv[1])
try:
    shares = json.load(sys.stdin).get('shares', [])
    print(shares[0]['blockhash'] if shares and shares[0].get('height') == want else '')
except Exception:
    print('')
" "$height"
}

# Convergence is checked against the actual store state, not the logs. Reorgs
# resolve transient forks, but reorg_confirmed does not emit per-block
# "Promoted ... Some(H)" lines, so a log-based check reads stale pre-reorg
# hashes and reports false divergence. Compare the confirmed block hash two
# heights below the shallowest tip (a height every node has confirmed) across
# all stores; converged iff all stores agree and are within 2 of the deepest
# tip.
check_chain_converged() {
  local tips=() min_tip="" max_tip=""
  for i in $(seq 0 $((NODE_COUNT - 1))); do
    local store="$RUN_DIR/store-$i.db"
    [ -d "$store" ] || continue
    local tip_height
    tip_height=$(store_tip_height "$store")
    [ -n "$tip_height" ] || continue
    tips+=("$tip_height")
    if [ -z "$min_tip" ] || [ "$tip_height" -lt "$min_tip" ]; then min_tip="$tip_height"; fi
    if [ -z "$max_tip" ] || [ "$tip_height" -gt "$max_tip" ]; then max_tip="$tip_height"; fi
  done

  if [ "${#tips[@]}" -eq 0 ]; then
    log_message "  no confirmed tip readable from any store in $RUN_DIR (see the p2poolv2_cli errors above)" >&2
    DISTINCT_HASHES=-1
    WITHIN2="0/$NODE_COUNT"
    return 1
  fi

  local within=0
  for tip_height in "${tips[@]}"; do
    if [ "$tip_height" -ge "$((max_tip - 2))" ]; then within=$((within + 1)); fi
  done
  WITHIN2="$within/$NODE_COUNT"

  local converge_height
  converge_height=$([ "$min_tip" -gt 2 ] && echo $((min_tip - 2)) || echo "$min_tip")

  local hashes=()
  for i in $(seq 0 $((NODE_COUNT - 1))); do
    local store="$RUN_DIR/store-$i.db"
    [ -d "$store" ] || continue
    local block_hash
    block_hash=$(store_hash_at_height "$store" "$converge_height")
    if [ -n "$block_hash" ]; then hashes+=("$block_hash"); fi
  done

  if [ "${#hashes[@]}" -gt 0 ]; then
    DISTINCT_HASHES=$(printf "%s\n" "${hashes[@]}" | sort -u | wc -l | tr -d ' ')
  else
    DISTINCT_HASHES=-1
  fi

  [ "$DISTINCT_HASHES" -eq 1 ] \
    && [ "${#hashes[@]}" -eq "$NODE_COUNT" ] \
    && [ "$within" -eq "$NODE_COUNT" ]
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

# Every node killed by the scenario must have come back and caught up to the
# rest of the swarm within its timeout. Trivially passes for `clean`.
check_failure_recovery() {
  UNRECOVERED_COUNT=$(echo "$FAILURE_OUTPUT" \
    | grep -oE "unrecovered nodes: [0-9]+" \
    | grep -oE "[0-9]+" || echo "-1")
  # Empty when failures.sh died before writing its summary; the -1 count above
  # already fails the run, these just keep the results table readable.
  FAILURE_TARGETS=$(echo "$FAILURE_OUTPUT" | sed -nE 's/^targets:[[:space:]]*(.*)$/\1/p')
  FAILURE_TARGETS="${FAILURE_TARGETS:-unknown}"
  FAILURE_REJOINED=$(echo "$FAILURE_OUTPUT" | sed -nE 's/^rejoined: (.*)$/\1/p')
  FAILURE_REJOINED="${FAILURE_REJOINED:-unknown}"
  [ "$UNRECOVERED_COUNT" -eq 0 ]
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

  local recovery_result="PASS"
  if ! check_failure_recovery; then
    recovery_result="FAIL"
    failed=1
  fi

  echo "=== NIGHTLY SIM RESULTS (scenario: $SCENARIO) ==="
  printf "  nodes alive:        %-4s  (%s/%s)\n" \
    "$alive_result" "$ALIVE_COUNT" "$ALIVE_TOTAL"
  printf "  chain converged:    %-4s  (distinct hashes: %s, within 2 of tip: %s)\n" \
    "$converged_result" "$DISTINCT_HASHES" "$WITHIN2"
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
  printf "  failure recovery:   %-4s  (targets: %s, rejoined %s, unrecovered %s)\n" \
    "$recovery_result" "$FAILURE_TARGETS" "$FAILURE_REJOINED" "$UNRECOVERED_COUNT"

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
inject_failures
wait_for_convergence
check_all_nodes_alive || true
collect_metrics
stop_swarm
verify_all_chains
ensure_cli_built

evaluate_results
