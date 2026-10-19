#!/usr/bin/env bash
#
# Failure-mode injection for a running sim swarm.
#
# Runs ONE named scenario against a swarm already started by run-swarm.sh:
# kills nodes with SIGKILL, brings them back, and verifies each one rejoins
# and catches up to the rest of the swarm. Writes a plain-text summary to
# stdout and to $RUN_DIR/failure-results.txt; nightly.sh greps that summary
# for its verdict (same contract metrics.sh has with nightly.sh).
#
# Usage:
#   load-tests/sim/failures.sh <scenario>
#
# Scenarios:
#   clean             no-op (today's nightly behaviour)
#   restart-fast      one node fails and comes back immediately
#   restart-delayed   one node fails and comes back after a long delay, so we
#                     validate it catches up; the default downtime crosses the
#                     300s tip-age threshold, so the node rejoins "not current"
#                     and must bulk-sync via getheaders rather than inv gossip
#   partition         DIAL_FANOUT consecutive nodes fail at once, cutting the
#                     dial chain, then all come back. Kademlia may keep the two
#                     sides connected; the summary reports which happened
#   all               the three above in sequence (local use, not CI)
#   late-miner        payout maturity: node LATE_MINER, launched by run-swarm.sh
#                     with its emitter off, starts mining once the chain is past
#                     the maturity depth; maturity_check.py then checks against
#                     the regtest coinbases that it is paid only once mature.
#                     Needs a swarm launched with LATE_MINER; not part of
#                     `all`
#   pruned-join       once every node has pruned block bodies, one node is
#                     wiped and rejoins as a fresh node; it must sync from
#                     genesis off pruned peers without asking for a body they
#                     deleted. Needs the swarm past the sim prune target, so it
#                     runs time-compressed; not part of `all`
#   deep-fork-refused reorg depth limit: the swarm is launched split in two
#                     (FORK_GROUP_FROM) so the chain forks at genesis. Once
#                     every node has pruned, one minority node reconnects to
#                     the heavier majority and must refuse to reorg onto it,
#                     keep its own chain and keep confirming; not part of `all`
#   shallow-fork-reorged  control for deep-fork-refused: the minority node
#                     reconnects before the prune target, and must reorg onto
#                     the majority chain; not part of `all`
#
# Env overrides:
#   RUN_DIR                   swarm work dir                (default /tmp/p2pool-sim)
#   BASE_P2P / BASE_API       first libp2p / API port       (default 7000 / 7600)
#   PROFILE                   cargo profile: release|debug  (default release)
#   SIM_BIN                   sim binary path               (default from PROFILE)
#   DIAL_FANOUT               peers each node dials         (default 3)
#   FAILURE_SEED              target selection seed         (default 42)
#   FAILURE_WARMUP            settle before injecting (s)   (default 60)
#   FAILURE_FAST_DOWN         restart-fast downtime (s)     (default 10)
#   FAILURE_SLOW_DOWN         restart-delayed downtime (s)  (default 330)
#   FAILURE_PARTITION_DOWN    partition downtime (s)        (default 90)
#   FAILURE_CATCHUP_TIMEOUT   max wait for catch-up (s)     (default 240)
#   LATE_MINER                late-miner target node        (required for late-miner)
#   LATE_MINER_TIP_TIMEOUT    max wait for tip 2*maturity (s) (default 900)
#   LATE_MINER_CHECK_TIMEOUT  max wait for a verdict (s)    (default 900)
#   PRUNED_JOIN_TIP_TIMEOUT   max wait for every node to prune (s) (default 900)
#   FORK_GROUP_FROM           first node of the minority group (fork scenarios)
#   FORK_TIP_TIMEOUT          max wait to reach the reconnect point (s) (default 900)
#   FORK_OBSERVE_SECS         watch after the reconnect (s) (default 90)
#
# Node 0 is never a target: metrics.sh derives the share rate and uncle rate
# from node-0.log alone, so killing it would corrupt the run's own metrics.
#
# (no `set -e`: a node that fails to catch up must still reach the summary)
set -uo pipefail

show_help() {
  cat <<'HELP'
failures.sh -- inject one failure scenario into a running sim swarm

Kills nodes with SIGKILL, brings them back, and verifies each one rejoins and
catches up. Writes a summary to stdout and $RUN_DIR/failure-results.txt.

Usage:
  load-tests/sim/failures.sh <scenario>

Scenarios:
  clean             no-op (today's nightly behaviour)
  restart-fast      one node fails and comes back immediately
  restart-delayed   one node fails and comes back after a long delay, so we
                    validate it catches up; the default downtime crosses the
                    300s tip-age threshold, so the node rejoins "not current"
                    and must bulk-sync via getheaders rather than inv gossip
  partition         DIAL_FANOUT consecutive nodes fail at once, cutting the
                    dial chain, then all come back. Kademlia may keep the two
                    sides connected; the summary reports which happened
  all               the three above in sequence (local use, not CI)
  late-miner        payout maturity: node LATE_MINER, launched by run-swarm.sh
                    with its emitter off, starts mining once the chain is past
                    the maturity depth; maturity_check.py then checks against
                    the regtest coinbases that it is paid only once mature.
                    Needs a swarm launched with LATE_MINER; not part of
                    `all`
  pruned-join       once every node has pruned block bodies, one node is
                    wiped and rejoins as a fresh node; it must sync from
                    genesis off pruned peers without asking for a body they
                    deleted. Needs the swarm past the sim prune target, so it
                    runs time-compressed; not part of `all`
  deep-fork-refused reorg depth limit: the swarm is launched split in two
                    (FORK_GROUP_FROM) so the chain forks at genesis. Once
                    every node has pruned, one minority node reconnects to
                    the heavier majority and must refuse to reorg onto it,
                    keep its own chain and keep confirming; not part of `all`
  shallow-fork-reorged  control for deep-fork-refused: the minority node
                    reconnects before the prune target, and must reorg onto
                    the majority chain; not part of `all`

Env vars:
  RUN_DIR                   swarm work dir                (default /tmp/p2pool-sim)
  BASE_P2P / BASE_API       first libp2p / API port       (default 7000 / 7600)
  PROFILE                   cargo profile: release|debug  (default release)
  SIM_BIN                   sim binary path               (default from PROFILE)
  DIAL_FANOUT               peers each node dials         (default 3)
  FAILURE_SEED              target selection seed         (default 42)
  FAILURE_WARMUP            settle before injecting (s)   (default 60)
  FAILURE_FAST_DOWN         restart-fast downtime (s)     (default 10)
  FAILURE_SLOW_DOWN         restart-delayed downtime (s)  (default 330)
  FAILURE_PARTITION_DOWN    partition downtime (s)        (default 90)
  FAILURE_CATCHUP_TIMEOUT   max wait for catch-up (s)     (default 240)
  LATE_MINER                late-miner target node        (required for late-miner)
  LATE_MINER_TIP_TIMEOUT    max wait for tip 2*maturity (s) (default 900)
  LATE_MINER_CHECK_TIMEOUT  max wait for a verdict (s)    (default 900)
  PRUNED_JOIN_TIP_TIMEOUT   max wait for every node to prune (s) (default 900)
  FORK_GROUP_FROM           first node of the minority group (fork scenarios)
  FORK_TIP_TIMEOUT          max wait to reach the reconnect point (s) (default 900)
  FORK_OBSERVE_SECS         watch after the reconnect (s) (default 90)

Node 0 is never a target: metrics.sh derives the share rate and uncle rate
from node-0.log alone, so killing it would corrupt the run's own metrics.

Examples:
  load-tests/sim/failures.sh restart-fast
  FAILURE_WARMUP=20 FAILURE_SLOW_DOWN=60 load-tests/sim/failures.sh restart-delayed
  LATE_MINER=1 load-tests/sim/failures.sh late-miner
  load-tests/sim/failures.sh pruned-join
  FORK_GROUP_FROM=4 load-tests/sim/failures.sh deep-fork-refused

Related scripts:
  load-tests/sim/run-swarm.sh N    launch the swarm this operates on
  load-tests/sim/observe.sh        live per-node view (tip, peers, alive)
  load-tests/sim/nightly.sh        automated runner; calls this script
HELP
  exit 0
}

if [ "${1:-}" = "--help" ] || [ "${1:-}" = "-h" ]; then
  show_help
fi

SCENARIO="${1:-clean}"

RUN_DIR="${RUN_DIR:-/tmp/p2pool-sim}"
BASE_P2P="${BASE_P2P:-7000}"
BASE_API="${BASE_API:-7600}"
PROFILE="${PROFILE:-release}"
DIAL_FANOUT="${DIAL_FANOUT:-3}"
FAILURE_SEED="${FAILURE_SEED:-42}"
FAILURE_WARMUP="${FAILURE_WARMUP:-60}"
FAILURE_FAST_DOWN="${FAILURE_FAST_DOWN:-10}"
FAILURE_SLOW_DOWN="${FAILURE_SLOW_DOWN:-330}"
FAILURE_PARTITION_DOWN="${FAILURE_PARTITION_DOWN:-90}"
FAILURE_CATCHUP_TIMEOUT="${FAILURE_CATCHUP_TIMEOUT:-240}"
LATE_MINER="${LATE_MINER:-}"
LATE_MINER_TIP_TIMEOUT="${LATE_MINER_TIP_TIMEOUT:-900}"
LATE_MINER_CHECK_TIMEOUT="${LATE_MINER_CHECK_TIMEOUT:-900}"
PRUNED_JOIN_TIP_TIMEOUT="${PRUNED_JOIN_TIP_TIMEOUT:-900}"
FORK_GROUP_FROM="${FORK_GROUP_FROM:-}"
FORK_TIP_TIMEOUT="${FORK_TIP_TIMEOUT:-900}"
FORK_OBSERVE_SECS="${FORK_OBSERVE_SECS:-90}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
if [ "$PROFILE" = "release" ]; then
  BIN="${SIM_BIN:-$REPO_ROOT/target/release/p2poolv2_sim}"
else
  BIN="${SIM_BIN:-$REPO_ROOT/target/debug/p2poolv2_sim}"
fi

PIDS_FILE="$RUN_DIR/pids.txt"
RESULTS_FILE="$RUN_DIR/failure-results.txt"

# Summary state, printed by write_summary at the end.
SUMMARY_LINES=()
OBSERVATION_LINES=()
TARGET_LIST=""
REJOINED_OK=0
REJOINED_TOTAL=0
# Tip height of each node just before it was killed, indexed by node number.
TIP_AT_KILL=()
# late-miner only: PASS, FAIL, INCONCLUSIVE or SETUP ERROR from maturity_check.py.
MATURITY_VERDICT=""
# pruned-join only: PASS, FAIL (reasons) or INCONCLUSIVE.
JOIN_VERDICT=""
# deep-fork-refused and shallow-fork-reorged only: PASS, FAIL (reasons) or
# INCONCLUSIVE.
FORK_VERDICT=""

log_message() {
  echo "[$(date +%H:%M:%S)] $*"
}

# ---------------------------------------------------------------------------
# Node lifecycle
# ---------------------------------------------------------------------------

node_pid() {
  sed -n "$(($1 + 1))p" "$PIDS_FILE" 2>/dev/null
}

# Rewrite line i+1 of pids.txt so nightly.sh's alive check and observe.sh keep
# reading the current pid for this node.
set_node_pid() {
  local index="$1" pid="$2" tmp
  tmp="$(mktemp "$RUN_DIR/pids.XXXXXX")"
  awk -v line="$((index + 1))" -v pid="$pid" 'NR == line { print pid; next } { print }' \
    "$PIDS_FILE" > "$tmp"
  mv "$tmp" "$PIDS_FILE"
}

# SIGKILL a node and wait for the process to go away. The marker written into
# the node log must not contain "error" or "panic": observe.sh greps for those.
kill_node() {
  local index="$1" pid attempt
  pid="$(node_pid "$index")"
  TIP_AT_KILL[index]="$(log_tip_height "$index")"

  if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
    log_message "  node $index already down (no live pid)"
    return 1
  fi

  echo "=== failure injection: SIGKILL node $index at $(date +%H:%M:%S), tip ${TIP_AT_KILL[index]} ===" \
    >> "$RUN_DIR/node-$index.log"
  kill -9 "$pid" 2>/dev/null

  attempt=0
  while [ "$attempt" -lt 10 ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      log_message "  killed node $index (pid $pid, tip ${TIP_AT_KILL[index]})"
      return 0
    fi
    sleep 1
    attempt=$((attempt + 1))
  done
  log_message "  node $index (pid $pid) did not exit after SIGKILL"
  return 1
}

# Relaunch a node against its existing config and store. The log is APPENDED
# to: truncating it would destroy the promotion history metrics.sh reads.
start_node() {
  local index="$1" pid
  echo "=== failure injection: restarting node $index at $(date +%H:%M:%S) ===" \
    >> "$RUN_DIR/node-$index.log"
  "$BIN" --config "$RUN_DIR/node-$index.toml" >> "$RUN_DIR/node-$index.log" 2>&1 &
  pid=$!
  set_node_pid "$index" "$pid"
  log_message "  restarted node $index (pid $pid)"
}

# ---------------------------------------------------------------------------
# Observation (logs and API only: RocksDB is locked while a node runs, so the
# store-based checks in nightly.sh cannot be used mid-run)
# ---------------------------------------------------------------------------

log_tip_height() {
  local height
  height="$(grep -oE "to confirmed height Some\([0-9]+\)" "$RUN_DIR/node-$1.log" 2>/dev/null \
    | grep -oE "[0-9]+" | sort -n | tail -1)"
  echo "${height:-0}"
}

swarm_max_tip() {
  local index height max=0
  for index in $(seq 0 $((NODE_TOTAL - 1))); do
    height="$(log_tip_height "$index")"
    if [ "$height" -gt "$max" ]; then max="$height"; fi
  done
  echo "$max"
}

# Poll a restarted node's log until its confirmed tip reaches target_height.
# Sets CATCHUP_SECS. Returns non-zero on timeout or if the process died.
wait_for_catchup() {
  local index="$1" target="$2" timeout="$3" start now height pid
  start="$(date +%s)"
  CATCHUP_SECS=0
  while true; do
    now="$(date +%s)"
    CATCHUP_SECS=$((now - start))
    height="$(log_tip_height "$index")"
    if [ "$height" -ge "$target" ]; then
      return 0
    fi
    pid="$(node_pid "$index")"
    if [ -z "$pid" ] || ! kill -0 "$pid" 2>/dev/null; then
      log_message "  node $index died while catching up (tip $height, target $target)"
      return 1
    fi
    if [ "$CATCHUP_SECS" -ge "$timeout" ]; then
      log_message "  node $index did not reach height $target within ${timeout}s (tip $height)"
      return 1
    fi
    sleep 5
  done
}

# Listen ports of the peers a node has dialled OUT to. Inbound entries carry an
# ephemeral send_back port, so only outbound links map back to a node index --
# which is enough, because every link is outbound from one of its two ends.
outbound_peer_ports() {
  curl -s -m 2 "http://127.0.0.1:$((BASE_API + $1))/peers" 2>/dev/null \
    | jq -r '.[] | select(.direction == "Outbound") | .address' 2>/dev/null \
    | grep -oE "/tcp/[0-9]+" | cut -d/ -f3
}

# Count links from the nodes in $1 (space-separated) to the nodes in $2.
count_links_between() {
  local sources="$1" targets="$2" index port target_ports="" links=0
  for index in $targets; do
    target_ports="$target_ports $((BASE_P2P + index))"
  done
  for index in $sources; do
    while read -r port; do
      [ -z "$port" ] && continue
      case " $target_ports " in
        *" $port "*) links=$((links + 1)) ;;
      esac
    done < <(outbound_peer_ports "$index")
  done
  echo "$links"
}

# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

# Kill every node in the argument list, recording its pre-kill tip.
kill_nodes() {
  local index
  for index in "$@"; do
    kill_node "$index"
  done
}

# Restart every node in the argument list and verify each one catches up to
# where the surviving swarm has got to. Accumulates the summary rows.
restart_and_verify() {
  local index target gap rejoined
  target="$(swarm_max_tip)"
  log_message "Restarting node(s) '$*'; catch-up target is height $target"
  for index in "$@"; do
    start_node "$index"
  done
  for index in "$@"; do
    gap=$((target - ${TIP_AT_KILL[index]:-0}))
    if wait_for_catchup "$index" "$target" "$FAILURE_CATCHUP_TIMEOUT"; then
      rejoined="yes"
      REJOINED_OK=$((REJOINED_OK + 1))
      log_message "  node $index caught up to height $target in ${CATCHUP_SECS}s (gap ${gap} heights)"
    else
      rejoined="no"
    fi
    REJOINED_TOTAL=$((REJOINED_TOTAL + 1))
    SUMMARY_LINES+=("node $index: rejoined=$rejoined catchup_secs=$CATCHUP_SECS gap_heights=$gap target_height=$target")
  done
}

scenario_restart_fast() {
  log_message "--- restart-fast: node $TARGET_FAST down for ${FAILURE_FAST_DOWN}s ---"
  TARGET_LIST="$TARGET_LIST $TARGET_FAST"
  kill_nodes "$TARGET_FAST"
  sleep "$FAILURE_FAST_DOWN"
  restart_and_verify "$TARGET_FAST"
}

scenario_restart_delayed() {
  log_message "--- restart-delayed: node $TARGET_SLOW down for ${FAILURE_SLOW_DOWN}s ---"
  TARGET_LIST="$TARGET_LIST $TARGET_SLOW"
  kill_nodes "$TARGET_SLOW"
  sleep "$FAILURE_SLOW_DOWN"
  restart_and_verify "$TARGET_SLOW"
}

# Kill the nodes that bridge the dial chain, so nodes below and above the cut
# have no configured path to each other, then bring them back. Whether this is
# a real partition depends on Kademlia, which discovers and dials peers that
# were never in dial_peers; the observation lines record what actually happened.
scenario_partition() {
  local killed="" lower="" upper="" index links_down links_up elapsed sample
  for index in $(seq "$PARTITION_START" $((PARTITION_START + PARTITION_WIDTH - 1))); do
    killed="$killed $index"
  done
  for index in $(seq 0 $((PARTITION_START - 1))); do
    lower="$lower $index"
  done
  for index in $(seq $((PARTITION_START + PARTITION_WIDTH)) $((NODE_TOTAL - 1))); do
    upper="$upper $index"
  done

  log_message "--- partition: nodes$killed down for ${FAILURE_PARTITION_DOWN}s (lower side$lower, upper side$upper) ---"
  TARGET_LIST="$TARGET_LIST$killed"
  # shellcheck disable=SC2086
  kill_nodes $killed

  elapsed=0
  for sample in 15 45; do
    if [ "$sample" -le "$FAILURE_PARTITION_DOWN" ]; then
      sleep $((sample - elapsed))
      elapsed="$sample"
      links_down="$(count_links_between "$lower" "$upper")"
      links_up="$(count_links_between "$upper" "$lower")"
      OBSERVATION_LINES+=("cross-side links at +${sample}s: lower_to_upper=$links_down upper_to_lower=$links_up")
      log_message "  cross-side links at +${sample}s: lower->upper=$links_down upper->lower=$links_up"
    fi
  done
  if [ "$FAILURE_PARTITION_DOWN" -gt "$elapsed" ]; then
    sleep $((FAILURE_PARTITION_DOWN - elapsed))
  fi

  # shellcheck disable=SC2086
  restart_and_verify $killed
}

# Coinbase maturity depth of the sim build, from the "Sim depths" line the
# late node logs at startup. It is a compile-time constant, so every node has
# the same value.
late_miner_maturity() {
  sed -nE 's/.*Sim depths: coinbase maturity ([0-9]+) shares.*/\1/p' \
    "$RUN_DIR/node-$LATE_MINER.log" | head -n 1
}

# Poll until the swarm tip reaches the given height. Returns non-zero on
# timeout.
wait_for_swarm_height() {
  local target="$1" timeout="$2" start
  start="$(date +%s)"
  while [ "$(swarm_max_tip)" -lt "$target" ]; do
    if [ $(($(date +%s) - start)) -ge "$timeout" ]; then
      log_message "  swarm did not reach height $target within ${timeout}s (tip $(swarm_max_tip))"
      return 1
    fi
    sleep 5
  done
}

# Rewrite the late node's [sim] enabled flag so its next start runs the
# emitter. Uses awk + mv like set_node_pid, so it works with BSD and GNU tools.
enable_late_miner_emitter() {
  local config="$RUN_DIR/node-$LATE_MINER.toml" tmp
  tmp="$(mktemp "$RUN_DIR/config.XXXXXX")"
  awk '/^enabled = false$/ { print "enabled = true"; next } { print }' "$config" > "$tmp"
  mv "$tmp" "$config"
}

# Run maturity_check.py until it gives a verdict other than INCONCLUSIVE, or
# the timeout passes. Sets MATURITY_VERDICT and keeps the last report.
wait_for_maturity_verdict() {
  local start exit_code
  start="$(date +%s)"
  while true; do
    RUN_DIR="$RUN_DIR" LATE_MINER="$LATE_MINER" BASE_API="$BASE_API" \
      python3 "$SCRIPT_DIR/maturity_check.py" > "$RUN_DIR/maturity-check.txt" 2>&1
    exit_code=$?
    case "$exit_code" in
      0) MATURITY_VERDICT="PASS"; return 0 ;;
      1) MATURITY_VERDICT="FAIL"; return 1 ;;
      3) MATURITY_VERDICT="SETUP ERROR"; return 1 ;;
    esac
    if [ $(($(date +%s) - start)) -ge "$LATE_MINER_CHECK_TIMEOUT" ]; then
      MATURITY_VERDICT="INCONCLUSIVE"
      log_message "  no maturity verdict within ${LATE_MINER_CHECK_TIMEOUT}s"
      return 1
    fi
    sleep 15
  done
}

# Payout maturity. The late node has synced but mined nothing. Once the chain
# is two maturity depths deep, so the payout skip is at its full size, restart
# it with the emitter on and check the regtest coinbases pay it only once its
# shares are mature.
scenario_late_miner() {
  local maturity target line
  maturity="$(late_miner_maturity)"
  target=$((2 * maturity))
  log_message "--- late-miner: node $LATE_MINER starts mining once the tip reaches $target (maturity $maturity) ---"
  TARGET_LIST="$TARGET_LIST $LATE_MINER"
  if ! wait_for_swarm_height "$target" "$LATE_MINER_TIP_TIMEOUT"; then
    MATURITY_VERDICT="INCONCLUSIVE"
    return
  fi
  kill_nodes "$LATE_MINER"
  enable_late_miner_emitter
  restart_and_verify "$LATE_MINER"
  wait_for_maturity_verdict
  log_message "  maturity check: $MATURITY_VERDICT (report in $RUN_DIR/maturity-check.txt)"
  while read -r line; do
    OBSERVATION_LINES+=("$line")
  done < "$RUN_DIR/maturity-check.txt"
}

# Refuse a late-miner run that cannot finish: the swarm must have a late node
# with its emitter off, and that node must have logged its maturity depth.
require_late_miner_setup() {
  local maturity
  if [ -z "$LATE_MINER" ]; then
    echo "ERROR: late-miner needs LATE_MINER set to the node run-swarm.sh launched with its emitter off." >&2
    exit 2
  fi
  if ! grep -q "^enabled = false$" "$RUN_DIR/node-$LATE_MINER.toml" 2>/dev/null; then
    echo "ERROR: node $LATE_MINER is not a late miner; launch the swarm with LATE_MINER=$LATE_MINER." >&2
    exit 2
  fi
  maturity="$(late_miner_maturity)"
  if [ -z "$maturity" ]; then
    echo "ERROR: node $LATE_MINER has not logged its sim depths; is it a sim build?" >&2
    exit 2
  fi
}

# ---------------------------------------------------------------------------
# pruned-join
# ---------------------------------------------------------------------------

# Prune depth and interval of the sim build, from the "Sim depths" line node 0
# logs at startup. They are compile-time constants, the same on every node.
sim_prune_depth() {
  sed -nE 's/.*Sim depths: .*prune depth ([0-9]+) shares.*/\1/p' "$RUN_DIR/node-0.log" | head -n 1
}

sim_prune_interval() {
  sed -nE 's/.*Sim depths: .*prune interval ([0-9]+) shares.*/\1/p' "$RUN_DIR/node-0.log" | head -n 1
}

# Number of nodes whose log shows a completed block body pruning run.
count_pruned_nodes() {
  local index count=0
  for index in $(seq 0 $((NODE_TOTAL - 1))); do
    if grep -q "Pruned block bodies at heights" "$RUN_DIR/node-$index.log" 2>/dev/null; then
      count=$((count + 1))
    fi
  done
  echo "$count"
}

# Poll until every node has logged a pruning run. Returns non-zero on timeout.
wait_for_all_nodes_pruned() {
  local timeout="$1" start
  start="$(date +%s)"
  while [ "$(count_pruned_nodes)" -lt "$NODE_TOTAL" ]; do
    if [ $(($(date +%s) - start)) -ge "$timeout" ]; then
      log_message "  only $(count_pruned_nodes)/$NODE_TOTAL nodes pruned within ${timeout}s"
      return 1
    fi
    sleep 5
  done
}

# Confirmed blockhash a node's API reports at a height, or empty.
api_confirmed_hash() {
  local index="$1" height="$2"
  curl -s -m 5 "http://127.0.0.1:$((BASE_API + index))/share?height=$height" 2>/dev/null \
    | jq -r '.[]? | select((.chain | ascii_downcase) == "confirmed") | .blockhash' 2>/dev/null \
    | head -n 1
}

# A fresh node joins a swarm that has pruned. Wait until the swarm is past the
# sim prune target and every node has pruned, then wipe one node's store and
# restart it, so it syncs from genesis off peers that hold headers for every
# height but bodies only near the tip. The old log is moved aside, to a name
# outside the node-*.log glob: the fresh node's catch-up must be read from its
# own log, not the pre-wipe history.
scenario_pruned_join() {
  local depth interval tip_target index store low_height high_height
  local joiner_low peer_low joiner_high peer_high not_found failed_stores reasons=""
  depth="$(sim_prune_depth)"
  interval="$(sim_prune_interval)"
  if [ -z "$depth" ] || [ -z "$interval" ]; then
    log_message "  node 0 has not logged its sim depths; is it a sim build?"
    JOIN_VERDICT="INCONCLUSIVE"
    return
  fi
  tip_target=$((depth + 3 * interval))
  index="$TARGET_SLOW"
  store="$RUN_DIR/store-$index.db"
  log_message "--- pruned-join: node $index is wiped once the tip reaches $tip_target and every node has pruned (prune depth $depth, interval $interval) ---"
  TARGET_LIST="$TARGET_LIST $index"
  if ! wait_for_swarm_height "$tip_target" "$PRUNED_JOIN_TIP_TIMEOUT" \
    || ! wait_for_all_nodes_pruned "$PRUNED_JOIN_TIP_TIMEOUT"; then
    JOIN_VERDICT="INCONCLUSIVE"
    return
  fi
  OBSERVATION_LINES+=("nodes pruned before the join: $(count_pruned_nodes)/$NODE_TOTAL")

  kill_nodes "$index"
  rm -rf "$store"
  mv "$RUN_DIR/node-$index.log" "$RUN_DIR/prejoin-node-$index.log"
  log_message "  wiped node $index store and moved its log to prejoin-node-$index.log"
  restart_and_verify "$index"

  # One height the joiner holds header-only, below its own prune height, and
  # one near the tip it holds with a body.
  low_height=$interval
  high_height=$(($(log_tip_height "$index") - interval))
  joiner_low="$(api_confirmed_hash "$index" "$low_height")"
  peer_low="$(api_confirmed_hash 0 "$low_height")"
  joiner_high="$(api_confirmed_hash "$index" "$high_height")"
  peer_high="$(api_confirmed_hash 0 "$high_height")"
  not_found="$(grep -c "Received not found response" "$RUN_DIR/node-$index.log" 2>/dev/null)"
  failed_stores="$(grep -c "Failed to store and organise block" "$RUN_DIR/node-$index.log" 2>/dev/null)"
  OBSERVATION_LINES+=("joiner confirmed hash at $low_height: ${joiner_low:-none} (node 0: ${peer_low:-none})")
  OBSERVATION_LINES+=("joiner confirmed hash at $high_height: ${joiner_high:-none} (node 0: ${peer_high:-none})")
  OBSERVATION_LINES+=("joiner not-found responses: $not_found, failed stores: $failed_stores")

  if [ "$REJOINED_OK" -ne "$REJOINED_TOTAL" ]; then
    reasons="$reasons did-not-catch-up"
  fi
  if [ -z "$joiner_low" ] || [ "$joiner_low" != "$peer_low" ]; then
    reasons="$reasons pruned-height-mismatch"
  fi
  if [ -z "$joiner_high" ] || [ "$joiner_high" != "$peer_high" ]; then
    reasons="$reasons tip-height-mismatch"
  fi
  if [ "$not_found" -ne 0 ]; then
    reasons="$reasons requested-pruned-bodies"
  fi
  if [ "$failed_stores" -ne 0 ]; then
    reasons="$reasons failed-stores"
  fi
  if [ -z "$reasons" ]; then
    JOIN_VERDICT="PASS"
  else
    JOIN_VERDICT="FAIL (${reasons# })"
  fi
  log_message "  pruned-join: $JOIN_VERDICT"
}

# ---------------------------------------------------------------------------
# deep-fork-refused / shallow-fork-reorged
# ---------------------------------------------------------------------------

# Add node 0, in the majority group, to a node's dial list, so its next start
# connects the two groups. Uses awk + mv like set_node_pid.
dial_majority_group() {
  local config="$RUN_DIR/node-$1.toml" address tmp
  address="\"/ip4/127.0.0.1/tcp/$BASE_P2P\""
  tmp="$(mktemp "$RUN_DIR/config.XXXXXX")"
  awk -v address="$address" '
    /^dial_peers = \[\]$/ { print "dial_peers = [" address "]"; next }
    /^dial_peers = \[/ { sub(/^dial_peers = \[/, "dial_peers = [" address ", "); print; next }
    { print }' "$config" > "$tmp"
  mv "$tmp" "$config"
}

# Restart a minority node dialing the majority group. Sets RECONNECT_LOG_LINE
# to the log line count before the restart, so later checks read only what the
# node logged after it met the majority chain.
reconnect_to_majority() {
  local index="$1"
  kill_nodes "$index"
  dial_majority_group "$index"
  RECONNECT_LOG_LINE="$(wc -l < "$RUN_DIR/node-$index.log" | tr -d ' ')"
  start_node "$index"
}

# Lines a node logged since RECONNECT_LOG_LINE.
log_since_reconnect() {
  tail -n "+$((RECONNECT_LOG_LINE + 1))" "$RUN_DIR/node-$1.log" 2>/dev/null
}

# The majority group must outwork the minority, so a reorg onto it is wanted
# by chain work; only the reorg depth limit may refuse it. The swarm must have
# been launched split, with node 0 in the majority group.
require_fork_setup() {
  if [ -z "$FORK_GROUP_FROM" ] || [ "$FORK_GROUP_FROM" -lt 2 ] \
    || [ "$FORK_GROUP_FROM" -ge "$NODE_TOTAL" ]; then
    echo "ERROR: $SCENARIO needs a swarm launched with FORK_GROUP_FROM between 2 and $((NODE_TOTAL - 1))." >&2
    exit 2
  fi
  if grep -q "tcp/$BASE_P2P\"" "$RUN_DIR/node-$FORK_GROUP_FROM.toml" 2>/dev/null; then
    echo "ERROR: node $FORK_GROUP_FROM already dials node 0; launch the swarm with FORK_GROUP_FROM=$FORK_GROUP_FROM." >&2
    exit 2
  fi
}

# The groups fork at launch. Once both are past the sim prune target and every
# node has pruned, the minority group's fork point (genesis) is below its
# prune target. Reconnect one minority node: the majority chain has more work,
# but the node must refuse to reorg onto it, keep its own chain and keep
# confirming, while the majority keeps advancing.
scenario_deep_fork_refused() {
  local depth interval index tip_target minority_tip_before majority_tip_before
  local check_height minority_hash_before majority_hash links refusals
  local minority_hash_after minority_tip_after majority_tip_after reasons=""
  depth="$(sim_prune_depth)"
  interval="$(sim_prune_interval)"
  if [ -z "$depth" ] || [ -z "$interval" ]; then
    log_message "  node 0 has not logged its sim depths; is it a sim build?"
    FORK_VERDICT="INCONCLUSIVE"
    return
  fi
  index="$FORK_GROUP_FROM"
  tip_target=$((depth + 3 * interval))
  log_message "--- deep-fork-refused: node $index reconnects to the majority once every node has pruned (prune depth $depth, interval $interval) ---"
  TARGET_LIST="$TARGET_LIST $index"
  if ! wait_for_swarm_height "$tip_target" "$FORK_TIP_TIMEOUT" \
    || ! wait_for_all_nodes_pruned "$FORK_TIP_TIMEOUT"; then
    # A minority whose hashrate needs a share target easier than the ASERT
    # clamp mines below the ideal rate and may never reach the prune target.
    log_message "  if the minority lags, raise HASHRATE (e.g. 1e13 at IDEAL_BLOCK_TIME=1)"
    FORK_VERDICT="INCONCLUSIVE"
    return
  fi

  minority_tip_before="$(log_tip_height "$index")"
  majority_tip_before="$(log_tip_height 0)"
  check_height=$((minority_tip_before - interval))
  minority_hash_before="$(api_confirmed_hash "$index" "$check_height")"
  majority_hash="$(api_confirmed_hash 0 "$check_height")"
  OBSERVATION_LINES+=("before reconnect: minority tip $minority_tip_before, majority tip $majority_tip_before")

  reconnect_to_majority "$index"
  log_message "  observing for ${FORK_OBSERVE_SECS}s"
  sleep "$FORK_OBSERVE_SECS"

  links="$(count_links_between "$index" 0)"
  refusals="$(log_since_reconnect "$index" | grep -c "branch forks below the prune target")"
  minority_hash_after="$(api_confirmed_hash "$index" "$check_height")"
  minority_tip_after="$(log_tip_height "$index")"
  majority_tip_after="$(log_tip_height 0)"
  OBSERVATION_LINES+=("after reconnect: minority tip $minority_tip_after, majority tip $majority_tip_after, links to node 0: $links, refusals: $refusals")
  OBSERVATION_LINES+=("confirmed hash at $check_height: minority ${minority_hash_before:-none} -> ${minority_hash_after:-none}, majority ${majority_hash:-none}")

  if [ "$links" -lt 1 ]; then
    FORK_VERDICT="INCONCLUSIVE (node $index never connected to node 0)"
    log_message "  deep-fork-refused: $FORK_VERDICT"
    return
  fi
  if [ "$refusals" -lt 1 ]; then
    reasons="$reasons no-refusal"
  fi
  if [ -z "$minority_hash_before" ] || [ "$minority_hash_after" != "$minority_hash_before" ]; then
    reasons="$reasons left-own-branch"
  fi
  if [ "$minority_hash_before" = "$majority_hash" ]; then
    reasons="$reasons groups-did-not-fork"
  fi
  if [ "$minority_tip_after" -le "$minority_tip_before" ]; then
    reasons="$reasons minority-stalled"
  fi
  if [ "$majority_tip_after" -le "$majority_tip_before" ]; then
    reasons="$reasons majority-stalled"
  fi
  if [ -z "$reasons" ]; then
    FORK_VERDICT="PASS"
  else
    FORK_VERDICT="FAIL (${reasons# })"
  fi
  log_message "  deep-fork-refused: $FORK_VERDICT"
}

# Control for deep-fork-refused: the same split, but the minority node
# reconnects while the tips are still below the prune target. The fork point
# is then above it, so the node must follow the majority chain and log no
# refusal; the nightly convergence check then sees one chain. The reconnect
# height also keeps the fork within the PPLNS window cache, which bounds how
# deep a fork a node can pay out for.
scenario_shallow_fork_reorged() {
  local interval index reconnect_height check_height links refusals
  local minority_hash majority_hash reasons=""
  interval="$(sim_prune_interval)"
  if [ -z "$interval" ]; then
    log_message "  node 0 has not logged its sim depths; is it a sim build?"
    FORK_VERDICT="INCONCLUSIVE"
    return
  fi
  index="$FORK_GROUP_FROM"
  reconnect_height=$((3 * interval))
  log_message "--- shallow-fork-reorged: node $index reconnects to the majority at height $reconnect_height, above the prune target ---"
  TARGET_LIST="$TARGET_LIST $index"
  if ! wait_for_swarm_height "$reconnect_height" "$FORK_TIP_TIMEOUT"; then
    FORK_VERDICT="INCONCLUSIVE"
    return
  fi
  if [ "$(count_pruned_nodes)" -ne 0 ]; then
    FORK_VERDICT="INCONCLUSIVE (a node pruned before the reconnect)"
    log_message "  shallow-fork-reorged: $FORK_VERDICT"
    return
  fi

  reconnect_to_majority "$index"
  log_message "  observing for ${FORK_OBSERVE_SECS}s"
  sleep "$FORK_OBSERVE_SECS"

  links="$(count_links_between "$index" 0)"
  refusals="$(log_since_reconnect "$index" | grep -c "branch forks below the prune target")"
  check_height=$(($(log_tip_height 0) - interval))
  minority_hash="$(api_confirmed_hash "$index" "$check_height")"
  majority_hash="$(api_confirmed_hash 0 "$check_height")"
  OBSERVATION_LINES+=("after reconnect: links to node 0: $links, refusals: $refusals")
  OBSERVATION_LINES+=("confirmed hash at $check_height: minority ${minority_hash:-none}, majority ${majority_hash:-none}")

  if [ "$links" -lt 1 ]; then
    FORK_VERDICT="INCONCLUSIVE (node $index never connected to node 0)"
    log_message "  shallow-fork-reorged: $FORK_VERDICT"
    return
  fi
  if [ "$refusals" -ne 0 ]; then
    reasons="$reasons refused"
  fi
  if [ -z "$minority_hash" ] || [ "$minority_hash" != "$majority_hash" ]; then
    reasons="$reasons did-not-reorg"
  fi
  if [ -z "$reasons" ]; then
    FORK_VERDICT="PASS"
  else
    FORK_VERDICT="FAIL (${reasons# })"
  fi
  log_message "  shallow-fork-reorged: $FORK_VERDICT"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

write_summary() {
  local unrecovered=$((REJOINED_TOTAL - REJOINED_OK)) line
  {
    echo "=== failure injection summary (scenario: $SCENARIO) ==="
    echo "targets:${TARGET_LIST:- none}"
    for line in "${OBSERVATION_LINES[@]+"${OBSERVATION_LINES[@]}"}"; do
      echo "$line"
    done
    for line in "${SUMMARY_LINES[@]+"${SUMMARY_LINES[@]}"}"; do
      echo "$line"
    done
    echo "rejoined: $REJOINED_OK/$REJOINED_TOTAL"
    echo "unrecovered nodes: $unrecovered"
    if [ -n "$MATURITY_VERDICT" ]; then
      echo "maturity verdict: $MATURITY_VERDICT"
    fi
    if [ -n "$JOIN_VERDICT" ]; then
      echo "pruned-join verdict: $JOIN_VERDICT"
    fi
    if [ -n "$FORK_VERDICT" ]; then
      echo "fork verdict: $FORK_VERDICT"
    fi
  } | tee "$RESULTS_FILE"
  [ "$unrecovered" -eq 0 ] \
    && { [ -z "$MATURITY_VERDICT" ] || [ "$MATURITY_VERDICT" = "PASS" ]; } \
    && { [ -z "$JOIN_VERDICT" ] || [ "$JOIN_VERDICT" = "PASS" ]; } \
    && { [ -z "$FORK_VERDICT" ] || [ "$FORK_VERDICT" = "PASS" ]; }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

case "$SCENARIO" in
  clean|restart-fast|restart-delayed|partition|all|late-miner|pruned-join) ;;
  deep-fork-refused|shallow-fork-reorged) ;;
  *)
    echo "ERROR: unknown scenario '$SCENARIO' (expected clean, restart-fast, restart-delayed, partition, all, late-miner, pruned-join, deep-fork-refused or shallow-fork-reorged)" >&2
    exit 2
    ;;
esac

if [ ! -d "$RUN_DIR" ]; then
  echo "ERROR: no run dir at $RUN_DIR; start a swarm with run-swarm.sh first." >&2
  exit 1
fi
NODE_TOTAL=$(ls "$RUN_DIR"/node-*.toml 2>/dev/null | wc -l | tr -d ' ')
if [ "$NODE_TOTAL" -eq 0 ]; then
  echo "ERROR: no node configs in $RUN_DIR; start a swarm with run-swarm.sh first." >&2
  exit 1
fi

if [ "$SCENARIO" = "clean" ]; then
  log_message "scenario 'clean': no failures injected"
  write_summary
  exit $?
fi

if [ ! -x "$BIN" ]; then
  echo "ERROR: sim binary not found at $BIN (set PROFILE, or build with run-swarm.sh)." >&2
  exit 1
fi
if [ "$SCENARIO" = "late-miner" ]; then
  require_late_miner_setup
fi
if [ "$SCENARIO" = "deep-fork-refused" ] || [ "$SCENARIO" = "shallow-fork-reorged" ]; then
  require_fork_setup
fi
if [ "$NODE_TOTAL" -lt 3 ]; then
  echo "ERROR: failure injection needs at least 3 nodes (node 0 is never a target); have $NODE_TOTAL." >&2
  exit 1
fi

# Seeded target selection, so a failing nightly is reproducible. Same
# single-awk-with-srand idiom run-swarm.sh uses for its distributions.
# Targets are drawn from [1, N-1]; the partition cut keeps at least one node on
# each side of it.
read -r TARGET_FAST TARGET_SLOW PARTITION_START PARTITION_WIDTH < <(
  awk -v seed="$FAILURE_SEED" -v n="$NODE_TOTAL" -v fanout="$DIAL_FANOUT" 'BEGIN {
    srand(seed + 0)
    fast = 1 + int(rand() * (n - 1))
    slow = 1 + int(rand() * (n - 1))
    while (slow == fast && n > 2) { slow = 1 + int(rand() * (n - 1)) }
    width = fanout
    if (width > n - 2) width = n - 2
    if (width < 1) width = 1
    max_start = n - width - 1
    if (max_start < 1) max_start = 1
    start = 1 + int(rand() * max_start)
    printf "%d %d %d %d\n", fast, slow, start, width
  }'
)

log_message "scenario '$SCENARIO' on $NODE_TOTAL nodes (seed $FAILURE_SEED)"
log_message "Warming up for ${FAILURE_WARMUP}s before injecting failures..."
sleep "$FAILURE_WARMUP"

case "$SCENARIO" in
  restart-fast)    scenario_restart_fast ;;
  restart-delayed) scenario_restart_delayed ;;
  partition)       scenario_partition ;;
  late-miner)      scenario_late_miner ;;
  pruned-join)     scenario_pruned_join ;;
  deep-fork-refused)    scenario_deep_fork_refused ;;
  shallow-fork-reorged) scenario_shallow_fork_reorged ;;
  all)
    scenario_restart_fast
    scenario_restart_delayed
    scenario_partition
    ;;
esac

write_summary
