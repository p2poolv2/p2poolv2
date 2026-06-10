#!/usr/bin/env bash
#
# Launch a swarm of no-PoW sim nodes (Phase 2 harness) against one shared
# regtest bitcoind. Generates one config per node with distinct ports, a
# distinct RNG seed, a fresh store, and a dial_peers topology, then launches
# them all and records PIDs.
#
# Usage:
#   load-tests/sim/run-swarm.sh [N]          # N nodes, default 20
#
# Env overrides (defaults match config-dev.toml / the regtest stack):
#   RUN_DIR        work dir for configs/stores/logs   (default /tmp/p2pool-sim)
#   BASE_P2P       first libp2p port                  (default 7000)
#   BASE_STRATUM   first stratum port                 (default 7300)
#   BASE_API       first API port                     (default 7600)
#   RPC_URL        bitcoind rpc url                    (default http://127.0.0.1:19443)
#   RPC_USER       bitcoind rpc user                  (default p2pool)
#   RPC_PASS       bitcoind rpc pass                  (default p2pool)
#   ZMQ            zmqpubhashblock                     (default tcp://127.0.0.1:28332)
#   MINER_ADDRESS  payout identity for all nodes      (default bcrt1q...a0fu)
#   HASHRATE       mean per-node hashrate h/s         (default 1.0e12)
#   HASHRATE_DIST  equal | zipf                       (default zipf — power-law,
#                  total ≈ N*HASHRATE preserved; a few big miners + long tail)
#   ZIPF_ALPHA     power-law exponent for zipf        (default 1.0)
#   RATIO          block_to_share_ratio               (default 10000)
#   LATENCY_MS     mean per-node outbound delay (ms)   (default 0; raise to see uncles)
#   LATENCY_DIST   equal | spread                     (default spread — per-node
#                  log-uniform around LATENCY_MS; models heterogeneous links)
#   DIST_SEED      seed for the latency spread        (default 42; reproducible)
#   WINDOW_SHARES  PPLNS payout window size in shares   (default = RATIO; sets how
#                  (mainnet-like multi-miner payout)         many miners appear in a coinbase)
#   DISTINCT_ADDR  1 = each node gets its own payout    (default 1; needs a loaded
#                  address via RPC getnewaddress             wallet on the bitcoind)
#   POOL_SIGNATURE must be identical across nodes      (default P2Poolv2-dev)
#   DIAL_FANOUT    how many earlier peers each dials   (default 3)
#   PROFILE        cargo profile: release | debug      (default release)
#
# NOTE: release is the default on purpose. libp2p-request-response has a
# debug_assert_eq! in on_connection_closed (lib.rs:651) that fires under the
# connection churn of a many-node swarm and aborts the process; it is compiled
# out in release. (This is a sim *harness* build for load testing; it is NOT a
# shipped release binary, and the `sim` feature must never be in a real release.)
set -euo pipefail

N="${1:-20}"
RUN_DIR="${RUN_DIR:-/tmp/p2pool-sim}"
BASE_P2P="${BASE_P2P:-7000}"
BASE_STRATUM="${BASE_STRATUM:-7300}"
BASE_API="${BASE_API:-7600}"
RPC_URL="${RPC_URL:-http://127.0.0.1:19443}"
RPC_USER="${RPC_USER:-p2pool}"
RPC_PASS="${RPC_PASS:-p2pool}"
ZMQ="${ZMQ:-tcp://127.0.0.1:28332}"
MINER_ADDRESS="${MINER_ADDRESS:-bcrt1qqclp5usts33x0cgy2l5839659t7798w7g5a0fu}"
HASHRATE="${HASHRATE:-1.0e12}"
HASHRATE_DIST="${HASHRATE_DIST:-zipf}"
ZIPF_ALPHA="${ZIPF_ALPHA:-1.0}"
RATIO="${RATIO:-10000}"
LATENCY_MS="${LATENCY_MS:-0}"
LATENCY_DIST="${LATENCY_DIST:-spread}"
DIST_SEED="${DIST_SEED:-42}"
WINDOW_SHARES="${WINDOW_SHARES:-$RATIO}"
# Shared ASERT anchor = launch time (one value for all nodes; must match across
# nodes). Lets ASERT regulate around the 10s target instead of staying floored
# at the easy clamp because the fixed regtest genesis is dated in the past.
ASERT_ANCHOR="${ASERT_ANCHOR:-$(date +%s)}"
# Total network hashrate (sum over nodes). Anchors the genesis difficulty at the
# steady state so the chain starts regulated instead of climbing for ~15-20 min.
# Total is N*HASHRATE regardless of HASHRATE_DIST (zipf preserves the total).
NETWORK_HASHRATE="${NETWORK_HASHRATE:-$(awk -v n="$N" -v h="$HASHRATE" 'BEGIN{printf "%.0f", n*h}')}"
DISTINCT_ADDR="${DISTINCT_ADDR:-1}"
POOL_SIGNATURE="${POOL_SIGNATURE:-P2Poolv2-dev}"

# Minimal JSON-RPC helper against the shared regtest bitcoind.
rpc() {
  curl -s --user "$RPC_USER:$RPC_PASS" \
    --data-binary "{\"jsonrpc\":\"1.0\",\"id\":\"h\",\"method\":\"$1\",\"params\":$2}" \
    -H 'content-type: text/plain;' "$RPC_URL"
}
# Fetch a fresh bech32 address (empty on failure / no wallet).
new_address() { rpc getnewaddress '["sim","bech32"]' | jq -r '.result // empty'; }
DIAL_FANOUT="${DIAL_FANOUT:-3}"
PROFILE="${PROFILE:-release}"

# Resolve repo root from this script's location.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [ "$PROFILE" = "release" ]; then
  PROFILE_FLAG="--release"
  BIN="$REPO_ROOT/target/release/p2poolv2"
else
  PROFILE_FLAG=""
  BIN="$REPO_ROOT/target/debug/p2poolv2"
fi

echo "Building p2poolv2 ($PROFILE) with --features sim ..."
( cd "$REPO_ROOT" && cargo build -p p2poolv2_node --features sim $PROFILE_FLAG )

# Sanity: regtest bitcoind reachable?
if ! curl -s --user "$RPC_USER:$RPC_PASS" \
       --data-binary '{"jsonrpc":"1.0","id":"chk","method":"getblockchaininfo","params":[]}' \
       -H 'content-type: text/plain;' "$RPC_URL" | grep -q '"regtest"'; then
  echo "ERROR: regtest bitcoind not reachable at $RPC_URL (need rpc + zmq up)." >&2
  exit 1
fi

# Kill any leftover nodes from a previous swarm in this RUN_DIR before we wipe
# it — otherwise they keep their ports and the new nodes panic on bind. (We
# match on the config path so we don't touch an unrelated single-node run.)
existing=$(pgrep -f "$RUN_DIR/node-" 2>/dev/null || true)
if [ -n "$existing" ]; then
  echo "Killing leftover swarm processes in $RUN_DIR ..."
  # shellcheck disable=SC2086
  kill -9 $existing 2>/dev/null || true
  sleep 1
fi

rm -rf "$RUN_DIR"
mkdir -p "$RUN_DIR"
PIDS_FILE="$RUN_DIR/pids.txt"
: > "$PIDS_FILE"

# Precompute per-node hashrate and latency from the chosen distributions.
#  - zipf hashrate: wᵢ = (i+1)^(-alpha), hashrateᵢ = N·HASHRATE·wᵢ/Σw
#    (total network hashrate preserved, so the aggregate share rate is
#     comparable to the equal case while the per-miner split is skewed).
#  - spread latency: log-uniform in [0.3, 2.5]× LATENCY_MS (mean ≈ LATENCY_MS).
HR_ARR=(); LAT_ARR=()
while read -r idx hr lat; do
  HR_ARR[idx]="$hr"
  LAT_ARR[idx]="$lat"
done < <(awk -v N="$N" -v HR="$HASHRATE" -v ALPHA="$ZIPF_ALPHA" -v HDIST="$HASHRATE_DIST" \
             -v LAT="$LATENCY_MS" -v LDIST="$LATENCY_DIST" -v SEED="$DIST_SEED" 'BEGIN {
  srand(SEED + 0)
  sum = 0
  for (i = 0; i < N; i++) { w[i] = exp(-ALPHA * log(i + 1)); sum += w[i] }
  for (i = 0; i < N; i++) {
    hr = (HDIST == "equal") ? HR : (N * HR * w[i] / sum)
    if (LAT + 0 > 0 && LDIST == "spread") {
      f = 0.3 * exp(rand() * log(2.5 / 0.3)); lat = int(LAT * f + 0.5)
    } else {
      lat = int(LAT + 0)
    }
    printf "%d %.0f %d\n", i, hr, lat
  }
}')

echo "Launching $N sim nodes into $RUN_DIR ..."

for i in $(seq 0 $((N - 1))); do
  p2p_port=$((BASE_P2P + i))
  stratum_port=$((BASE_STRATUM + i))
  api_port=$((BASE_API + i))
  seed=$((i + 1))
  node_hashrate="${HR_ARR[i]}"
  node_latency="${LAT_ARR[i]}"
  cfg="$RUN_DIR/node-$i.toml"
  log="$RUN_DIR/node-$i.log"
  store="$RUN_DIR/store-$i.db"
  mkdir -p "$RUN_DIR/stats-$i"

  # Per-node payout identity. Distinct addresses make the PPLNS coinbase a real
  # multi-way split; fall back to the shared MINER_ADDRESS if no wallet.
  node_addr="$MINER_ADDRESS"
  if [ "$DISTINCT_ADDR" = "1" ]; then
    a=$(new_address)
    if [ -n "$a" ]; then node_addr="$a"; fi
  fi

  # Topology: each node dials up to DIAL_FANOUT earlier nodes (chain + chords),
  # which yields a single connected component. Node 0 dials nobody.
  dial=""
  for k in $(seq 1 "$DIAL_FANOUT"); do
    j=$((i - k))
    if [ "$j" -ge 0 ]; then
      peer_port=$((BASE_P2P + j))
      if [ -n "$dial" ]; then dial="$dial, "; fi
      dial="$dial\"/ip4/127.0.0.1/tcp/$peer_port\""
    fi
  done

  cat > "$cfg" <<EOF
[network]
listen_address = "/ip4/127.0.0.1/tcp/$p2p_port"
dial_peers = [$dial]
max_pending_incoming = 10
max_pending_outgoing = 10
max_established_incoming = 50
max_established_outgoing = 50
max_established_per_peer = 1
max_workbase_per_second = 10
max_userworkbase_per_second = 10
max_miningshare_per_second = 100
max_inventory_per_second = 100
max_transaction_per_second = 100
max_requests_per_second = 100
dial_timeout_secs = 30

[store]
path = "$store"
background_task_frequency_hours = 24
pplns_ttl_days = 7

[stratum]
wait_for_chain_sync = false
hostname = "127.0.0.1"
port = $stratum_port
start_difficulty = 1
minimum_difficulty = 1
solo_address = "$MINER_ADDRESS"
bootstrap_address = "$MINER_ADDRESS"
zmqpubhashblock = "$ZMQ"
network = "regtest"
version_mask = "1fffe000"
difficulty_multiplier = 1.0
pool_signature = "$POOL_SIGNATURE"

[bitcoinrpc]
url = "$RPC_URL"
username = "$RPC_USER"
password = "$RPC_PASS"

[logging]
console = true
level = "info"
stats_dir = "$RUN_DIR/stats-$i"

[api]
hostname = "127.0.0.1"
port = $api_port

[sim]
enabled = true
miner_address = "$node_addr"
hashrate = $node_hashrate
block_to_share_ratio = $RATIO
seed = $seed
propagation_delay_ms = $node_latency
pplns_window_shares = $WINDOW_SHARES
asert_anchor_time = $ASERT_ANCHOR
network_hashrate = $NETWORK_HASHRATE
EOF

  "$BIN" --config "$cfg" > "$log" 2>&1 &
  pid=$!
  echo "$pid" >> "$PIDS_FILE"
  printf "  node %2d  pid %-7s  p2p %d  api %d  hashrate %-10s lat %sms\n" \
    "$i" "$pid" "$p2p_port" "$api_port" "$node_hashrate" "$node_latency"
  # Small stagger so early dials land on already-listening peers.
  sleep 0.2
done

echo
echo "$N nodes launched. PIDs in $PIDS_FILE"
echo "Observe:  load-tests/sim/observe.sh"
echo "Stop:     load-tests/sim/stop-swarm.sh"
