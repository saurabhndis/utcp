#!/usr/bin/env bash
# utcp<->utcp (shared-memory link) vs kernel<->kernel (veth), same app and workloads.
HERE=$(cd "$(dirname "$0")" && pwd)
row() { python3 -c 'import json,sys
d=json.loads(sys.argv[2]); print("%-34s %-14s %8.2f Gbit/s %10.0f tps  p50 %8.1fus  p99 %8.1fus  errs %d" % (sys.argv[1], sys.argv[3], d["gbps"], d["tps"], d["p50_us"], d["p99_us"], d["conn_errors"]))' "$1" "$2" "$3"; }
run() { local name=$1 nw=$2; shift 2
    j=$("$HERE/pair.sh" kernel $nw -- --json "$@" 2>&1 | grep '"role":"client"'); row "$name" "$j" "kernel<->kernel"
    j=$("$HERE/linkpair.sh" $nw --json --max-tw 4096 "$@" 2>&1 | grep '"role":"client"'); row "$name" "$j" "utcp<->utcp"
}
run "stream 1 conn, 8G"          1 --workload stream --c2s 8G --conns 1 --no-verify --duration 60
run "stream duplex 1 conn, 4G+4G" 1 --workload stream --c2s 4G --s2c 4G --conns 1 --no-verify --duration 60
run "stream 16 conns, 4 workers" 4 --workload stream --workers 4 --conns 4 --c2s 1G --s2c 1G --no-verify --duration 60
run "rr 1 conn"                  1 --workload rr --conns 1 --duration 4
run "rr 64 conns, 4 workers"     4 --workload rr --workers 4 --conns 16 --duration 4
run "crr 1 worker"               1 --workload crr --conns 8 --duration 4
run "crr 4 workers"              4 --workload crr --workers 4 --conns 8 --duration 4
