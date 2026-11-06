#!/usr/bin/env bash
# Benchmark matrix: same kernel-socket load generator, two servers:
#   utcp  : utcp-app --backend utcp   (TAP, user-space TCP)
#   kernel: utcp-app --backend kernel (veth, Linux TCP)
# Reports client-side goodput/transactions/latency and whole-system CPU.
# Usage: sudo bench.sh [filter]   (run scripts/netns.sh up first)
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-$HERE/../results}
mkdir -p "$OUT"
filter=${1:-}
J=$OUT/bench-$(date +%Y%m%d-%H%M%S).jsonl
: > "$J"

run() { # name srv_workers netem -- client args
    local name=$1 sw=$2 nem=$3; shift 4
    [ -n "$filter" ] && [[ "$name" != *$filter* ]] && return
    for be in utcp kernel; do
        if [ "$nem" != none ]; then "$HERE/netns.sh" netem "$nem"; else "$HERE/netns.sh" clear; fi
        sleep 0.3
        out=$("$HERE/pair.sh" $be $sw -- --json "$@" 2>&1)
        cli=$(echo "$out" | grep '"role":"client"' | head -1)
        cpu=$(echo "$out" | sed -n 's/.*system cpu busy: \([0-9]*\)%.*/\1/p')
        srv=$(echo "$out" | grep -E "^   utcp " | head -1 | sed 's/"/'"'"'/g')
        echo "{\"name\":\"$name\",\"server\":\"$be\",\"netem\":\"$nem\",\"sys_cpu_pct\":${cpu:-0},\"client\":${cli:-null},\"utcp_stats\":\"$srv\"}" >> "$J"
        printf "%-22s %-6s " "$name" "$be"; echo "$cli" | python3 -c 'import json,sys
d=json.load(sys.stdin); print("gbps=%.2f tps=%.0f p50=%.1fus p99=%.1fus errs=%d verr=%d" % (d["gbps"],d["tps"],d["p50_us"],d["p99_us"],d["conn_errors"],d["verify_errors"]), end="")' 2>/dev/null || echo -n "FAILED"
        echo "  cpu=${cpu}%"
    done
    "$HERE/netns.sh" clear
}

V=${VERIFY:---no-verify}
run stream-rx-1conn   1 none -- --workload stream --c2s 8G --conns 1 $V --duration 60
run stream-tx-1conn   1 none -- --workload stream --c2s 0 --s2c 8G --conns 1 $V --duration 60
run stream-duplex-1   1 none -- --workload stream --c2s 4G --s2c 4G --conns 1 $V --duration 60
run stream-16conn-4w  4 none -- --workload stream --workers 4 --conns 4 --c2s 1G --s2c 1G $V --duration 60
run rr-1conn          1 none -- --workload rr --conns 1 --duration 5
run rr-64conn-4w      4 none -- --workload rr --workers 4 --conns 16 --duration 5
run crr-1w            1 none -- --workload crr --conns 8 --duration 5
run crr-4w            4 none -- --workload crr --workers 4 --conns 8 --duration 5
run loss1-delay2ms    1 "delay 1ms loss 1%" -- --workload stream --c2s 128M --s2c 128M --conns 1 --duration 120
run loss0.1-delay5ms  1 "delay 2500us loss 0.1%" -- --workload stream --c2s 512M --conns 1 --duration 120
run reorder-delay2ms  1 "delay 1ms reorder 5% 50%" -- --workload stream --c2s 512M --conns 1 --duration 120
# server is the sender: utcp's loss recovery / congestion control vs Linux's
run tx-loss1-rtt4ms     1 "delay 1ms loss 1%" -- --workload stream --c2s 0 --s2c 128M --conns 1 --duration 120
run tx-loss0.1-rtt10ms  1 "delay 2500us loss 0.1%" -- --workload stream --c2s 0 --s2c 512M --conns 1 --duration 120
run tx-loss0.01-rtt20ms 1 "delay 5ms loss 0.01%" -- --workload stream --c2s 0 --s2c 1G --conns 1 --duration 120
run tx-reorder-rtt4ms   1 "delay 1ms reorder 5% 50%" -- --workload stream --c2s 0 --s2c 512M --conns 1 --duration 120
run tx-rate1g-rtt20ms   1 "delay 5ms rate 1gbit limit 2000" -- --workload stream --c2s 0 --s2c 256M --conns 1 --duration 120
echo "results: $J"
