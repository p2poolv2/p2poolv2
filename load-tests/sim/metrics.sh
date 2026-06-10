#!/usr/bin/env bash
#
# Summarize sim swarm metrics from the per-node logs:
#   A. emission ∝ hashrate (validates heterogeneous-hashrate modeling)
#   B. ASERT pool-difficulty trajectory + main-chain share rate vs the 10s target
#
# Usage: load-tests/sim/metrics.sh
# Env:   RUN_DIR (default /tmp/p2pool-sim)
set -uo pipefail

RUN_DIR="${RUN_DIR:-/tmp/p2pool-sim}"
N=$(ls "$RUN_DIR"/node-*.toml 2>/dev/null | wc -l | tr -d ' ')
if [ "$N" -eq 0 ]; then echo "No run in $RUN_DIR" >&2; exit 1; fi

echo "=== A. emission vs hashrate (per node) ==="
printf "%-5s %-16s %-10s %-9s %-10s\n" node hashrate hr_share% emitted em_share%
hr_tot=0; em_tot=0
declare -a HRS EMS
for i in $(seq 0 $((N - 1))); do
  hr=$(grep -E "^hashrate" "$RUN_DIR/node-$i.toml" | awk '{print $NF}')
  em=$(grep "sim stats" "$RUN_DIR/node-$i.log" 2>/dev/null | tail -1 | grep -oE "emitted=[0-9]+" | cut -d= -f2)
  HRS[i]="${hr:-0}"; EMS[i]="${em:-0}"
  hr_tot=$(awk "BEGIN{print $hr_tot + ${hr:-0}}")
  em_tot=$((em_tot + ${em:-0}))
done
for i in $(seq 0 $((N - 1))); do
  awk -v i="$i" -v hr="${HRS[i]}" -v em="${EMS[i]}" -v ht="$hr_tot" -v et="$em_tot" 'BEGIN{
    printf "%-5d %-16.0f %-10.1f %-9d %-10.1f\n", i, hr, (ht>0?100*hr/ht:0), em, (et>0?100*em/et:0)
  }'
done
echo "(hr_share% and em_share% should track each other if emission ∝ hashrate)"

echo
echo "=== B. ASERT pool-difficulty trajectory (node 0) ==="
grep "sim stats" "$RUN_DIR/node-0.log" 2>/dev/null \
  | grep -oE "pool_difficulty=[0-9.]+" | cut -d= -f2 \
  | awk 'NR==1{f=$1} {l=$1; n++} END{
      if(n) printf "first=%.1f  last=%.1f  samples=%d  (rising => ASERT throttling toward target)\n", f, l, n;
      else print "no sim-stats samples yet" }'

echo
echo "=== B. main-chain share rate (node 0) vs 0.100/s target ==="
grep "Promoted block" "$RUN_DIR/node-0.log" 2>/dev/null \
  | sed -E 's/.*T([0-9]{2}):([0-9]{2}):([0-9]{2}).*/\1 \2 \3/' \
  | awk '{t=$1*3600+$2*60+$3; if(NR==1)f=t; l=t; n++} END{
      if(n>1){span=l-f; printf "promotions=%d  span=%ds  rate=%.3f/s  (target 0.100/s)\n", n, span, (span>0?n/span:0)}
      else print "not enough promotions yet" }'
