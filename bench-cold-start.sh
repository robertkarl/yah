#!/usr/bin/env bash
# Cold-start latency benchmark for yah.
# Measures wall-clock time from process spawn to output for simple commands.
# Requires: a release build of yah (cargo build --release -p yah-cli).
#
# Usage:
#   ./bench-cold-start.sh              # uses release binary
#   ./bench-cold-start.sh ./target/debug/yah  # use a specific binary
#
# If you have hyperfine installed, use that instead for statistical rigor:
#   hyperfine --warmup 3 'yah classify "ls"'

set -euo pipefail

YAH="${1:-./target/release/yah}"

if [ ! -x "$YAH" ]; then
    echo "Binary not found at $YAH — building release..."
    cargo build --release -p yah-cli
fi

RUNS=100

echo "Cold-start benchmark: $RUNS iterations of '$YAH classify \"ls\"'"
echo "Binary: $(ls -lh "$YAH" | awk '{print $5}')"
echo ""

total=0
for i in $(seq 1 $RUNS); do
    start=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
    "$YAH" classify "ls" > /dev/null
    end=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
    elapsed=$(echo "$end - $start" | bc -l)
    total=$(echo "$total + $elapsed" | bc -l)
done

avg=$(echo "scale=6; $total / $RUNS" | bc -l)
avg_ms=$(echo "scale=3; $avg * 1000" | bc -l)

echo "Results ($RUNS runs):"
echo "  Total:   ${total}s"
echo "  Average: ${avg_ms}ms per invocation"
echo ""

if (( $(echo "$avg_ms < 1.0" | bc -l) )); then
    echo "PASS: sub-millisecond cold start (${avg_ms}ms)"
else
    echo "NOTE: ${avg_ms}ms average — above 1ms target"
    echo "      (process spawn overhead is expected on macOS)"
fi
