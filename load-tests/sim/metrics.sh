#!/usr/bin/env bash
#
# Authoritative, log-based summary of a sim swarm run. Reads only the per-node
# logs and configs in RUN_DIR — it does NOT query the running nodes, so it is
# load-immune and safe to run during or after a run. (The HTTP API / observe.sh
# is for live watching; this is the source of truth for results. See RUNBOOK.md.)
#
# Usage: load-tests/sim/metrics.sh
# Env:   RUN_DIR (default /tmp/p2pool-sim)
set -uo pipefail

RUN_DIR="${RUN_DIR:-/tmp/p2pool-sim}"
N=$(ls "$RUN_DIR"/node-*.toml 2>/dev/null | wc -l | tr -d ' ')
if [ "$N" -eq 0 ]; then echo "No run in $RUN_DIR" >&2; exit 1; fi

# Target share interval (seconds): sim override, else the production 10s.
T=$(grep -E "^ideal_block_time_secs" "$RUN_DIR/node-0.toml" 2>/dev/null | awk '{print $NF}')
{ [ -z "${T:-}" ] || [ "${T:-0}" -eq 0 ]; } 2>/dev/null && T=10
target_rate=$(awk -v t="$T" 'BEGIN{printf "%.3f", 1/t}')
echo "=== sim swarm summary ($N nodes, ideal_block_time=${T}s → target ${target_rate}/s) ==="

# --- 1. convergence (confirmed height + tip-hash agreement, from logs) ---
declare -a MAXH; maxmax=-1; minmax=999999999
for i in $(seq 0 $((N - 1))); do
  h=$(grep -oE "to confirmed height Some\([0-9]+\)" "$RUN_DIR/node-$i.log" 2>/dev/null \
        | grep -oE "[0-9]+" | sort -n | tail -1)
  h="${h:-0}"; MAXH[i]="$h"
  [ "$h" -gt "$maxmax" ] && maxmax="$h"
  [ "$h" -lt "$minmax" ] && minmax="$h"
done
within2=$(printf "%s\n" "${MAXH[@]}" | awk -v m="$maxmax" '$1>=m-2' | wc -l | tr -d ' ')
# Tip-hash agreement at a height every node has reached (avoids frontier straddle).
H=$([ "$minmax" -gt 2 ] && echo $((minmax - 2)) || echo "$minmax")
distinct=$(for i in $(seq 0 $((N - 1))); do
  grep -oE "Promoted block [0-9a-f]+ to confirmed height Some\($H\)" "$RUN_DIR/node-$i.log" 2>/dev/null \
    | grep -oE "[0-9a-f]{16,}" | head -1
done | sort -u | wc -l | tr -d ' ')
echo "--- 1. convergence ---"
echo "max confirmed height: $maxmax   nodes within 2 of tip: $within2/$N   (lowest node: $minmax)"
echo "distinct block hash at height $H across nodes: $distinct  (1 = single converged chain)"

# --- 2. share rate vs target (node 0's view of the shared main chain) ---
echo "--- 2. main-chain share rate (node 0) ---"
grep "to confirmed height Some" "$RUN_DIR/node-0.log" 2>/dev/null \
  | sed -E 's/.*T([0-9]{2}):([0-9]{2}):([0-9]{2}).*/\1 \2 \3/' \
  | awk -v tr="$target_rate" '{t=$1*3600+$2*60+$3; if(NR==1)f=t; l=t; n++} END{
      if(n>1){span=l-f; printf "promotions=%d  span=%ds  rate=%.3f/s  (target %s/s)\n", n, span, (span>0?n/span:0), tr}
      else print "not enough promotions yet" }'

# --- 3. ASERT pool-difficulty trajectory (node 0) ---
echo "--- 3. ASERT pool-difficulty (node 0) ---"
grep "sim stats" "$RUN_DIR/node-0.log" 2>/dev/null \
  | grep -oE "pool_difficulty=[0-9.]+" | cut -d= -f2 \
  | awk 'NR==1{f=$1;mn=$1} {l=$1; if($1<mn)mn=$1; if($1>mx)mx=$1; n++} END{
      if(n) printf "first=%.0f  last=%.0f  min=%.0f  max=%.0f  samples=%d\n", f, l, mn, mx, n;
      else print "no sim-stats samples yet" }'

# --- 4. emission vs hashrate (validates heterogeneous-hashrate modeling) ---
echo "--- 4. emission ∝ hashrate (per node) ---"
printf "%-5s %-16s %-10s %-9s %-10s\n" node hashrate hr_share% emitted em_share%
hr_tot=0; em_tot=0; declare -a HRS EMS
for i in $(seq 0 $((N - 1))); do
  hr=$(grep -E "^hashrate" "$RUN_DIR/node-$i.toml" | awk '{print $NF}')
  em=$(grep "sim stats" "$RUN_DIR/node-$i.log" 2>/dev/null | tail -1 | grep -oE "emitted=[0-9]+" | cut -d= -f2)
  HRS[i]="${hr:-0}"; EMS[i]="${em:-0}"
  hr_tot=$(awk "BEGIN{print $hr_tot + ${hr:-0}}"); em_tot=$((em_tot + ${em:-0}))
done
for i in $(seq 0 $((N - 1))); do
  awk -v i="$i" -v hr="${HRS[i]}" -v em="${EMS[i]}" -v ht="$hr_tot" -v et="$em_tot" 'BEGIN{
    printf "%-5d %-16.0f %-10.1f %-9d %-10.1f\n", i, hr, (ht>0?100*hr/ht:0), em, (et>0?100*em/et:0) }'
done
echo "(hr_share% and em_share% track each other once enough shares accumulate)"

# --- 5. uncles, block-finds, health ---
echo "--- 5. uncles / block-finds / health ---"
n0="$RUN_DIR/node-0.log"
n0_promos=$(grep -c "to confirmed height Some" "$n0" 2>/dev/null || echo 0)
n0_uncles=$(grep -h "sim-uncle:" "$n0" 2>/dev/null | grep -oE "references [0-9]+" | awk '{s+=$2} END{print s+0}')
urate=$(awk -v u="${n0_uncles:-0}" -v p="${n0_promos:-0}" 'BEGIN{d=p+u; printf "%.1f", (d>0?100*u/d:0)}')
echo "uncle rate (node 0): ${urate}%   ($n0_uncles uncles / $n0_promos main-chain blocks)"
bf=$(grep -h "sim block-find" "$RUN_DIR"/node-*.log 2>/dev/null | wc -l | tr -d ' ')
echo "block-finds (all nodes): $bf"
asert=$(grep -ih "AsertMismatch" "$RUN_DIR"/node-*.log 2>/dev/null | wc -l | tr -d ' ')
merkle=$(grep -ih "don't match merkle\|does not match calculated" "$RUN_DIR"/node-*.log 2>/dev/null | wc -l | tr -d ' ')
panics=$(grep -il "panicked" "$RUN_DIR"/node-*.log 2>/dev/null | wc -l | tr -d ' ')
echo "rejections: AsertMismatch=$asert  merkle/payout=$merkle   panicked nodes: $panics"
