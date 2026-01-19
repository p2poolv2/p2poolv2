  #!/bin/bash
  # p2pool_diagnose.sh - Run while p2pool is under load

  PROC_NAME="hydrapool"
  PID=$(pgrep -x "$PROC_NAME" || pgrep -f "$PROC_NAME" | head -1)

  if [ -z "$PID" ]; then
      echo "ERROR: Cannot find $PROC_NAME process"
      exit 1
  fi

  echo "=========================================="
  echo "P2Pool Diagnostics - PID: $PID"
  echo "=========================================="
  echo ""

  echo "=== 1. SYSTEM LOAD & CPU ==="
  uptime
  echo ""
  mpstat -P ALL 1 3
  echo ""

  echo "=== 2. VMSTAT (memory, swap, io, context switches) ==="
  vmstat 1 5
  echo ""

  echo "=== 3. PROCESS THREADS ==="
  THREAD_COUNT=$(ps -T -p $PID | wc -l)
  echo "Thread count: $THREAD_COUNT"
  echo ""

  echo "=== 4. CONTEXT SWITCHES (per-process) ==="
  pidstat -w -p $PID 1 3
  echo ""

  echo "=== 5. I/O STATS ==="
  iostat -x 1 3
  echo ""

  echo "=== 6. FILE DESCRIPTORS ==="
  FD_COUNT=$(ls /proc/$PID/fd 2>/dev/null | wc -l)
  echo "Open file descriptors: $FD_COUNT"
  echo ""

  echo "=== 7. MEMORY USAGE ==="
  ps -o pid,rss,vsz,%mem,%cpu,comm -p $PID
  echo ""
  echo "Detailed memory:"
  cat /proc/$PID/status | grep -E "VmSize|VmRSS|VmSwap|Threads"
  echo ""

  echo "=== 8. NETWORK CONNECTIONS ==="
  ss -tnp | grep $PID | wc -l
  echo "TCP connections to p2pool"
  echo ""

  echo "=== 9. TOP THREADS BY CPU ==="
  ps -T -p $PID -o pid,tid,%cpu,%mem,comm --sort=-%cpu | head -20
  echo ""

  echo "=== 10. PERF STAT (5 seconds) ==="
  if command -v perf &> /dev/null; then
      perf stat -e context-switches,cpu-migrations,page-faults,cycles,instructions,cache-misses -p $PID sleep 5 2>&1
  else
      echo "perf not installed, skipping"
  fi
  echo ""

  echo "=== 11. SYSCALL SUMMARY (5 seconds) ==="
  if command -v strace &> /dev/null; then
      timeout 5 strace -c -f -p $PID 2>&1 || true
  else
      echo "strace not installed, skipping"
  fi
  echo ""

  echo "=========================================="
  echo "Diagnostics complete"
  echo "=========================================="
