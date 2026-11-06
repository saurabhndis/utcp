#!/usr/bin/env bash
# 10k concurrent connections, each: 10 x (128-byte request -> 64 KiB response), then close.
#   1) kernel client -> kernel server   (veth)
#   2) kernel client -> utcp server     (TAP)
#   3) utcp client   -> kernel server   (TAP)
#   4) utcp client   -> utcp server     (shared-memory link, no kernel in the path)
set -uo pipefail
B=${B:-/tmp/b/rel/app/utcp-app}
HERE=$(cd "$(dirname "$0")" && pwd)
CW=${CW:-4}; SW=${SW:-4}; CONNS=${CONNS:-2500}
WL="--workload rr --req 128 --resp 64K --trans 10 --conns $CONNS --duration 120 --json"

cpu_begin() { read -r _ u n s i _ < /proc/stat; T0=$((u+n+s)); I0=$i; }
cpu_end() { read -r _ u n s i _ < /proc/stat; local b=$((u+n+s-T0)); CPU=$((100*b/(b+i-I0))); }

report() { # label json
    python3 - "$1" "$2" "$CPU" <<'PY'
import json, sys
label, js, cpu = sys.argv[1], sys.argv[2], sys.argv[3]
d = json.loads(js)
print(f"{label:26s} conns {d['conns_done']:>6}/{d['conns_opened']:<6} errors {d['conn_errors']:<3} "
      f"requests {d['transactions']:>7} in {d['secs']:6.2f}s = {d['tps']:>8.0f} req/s  "
      f"{d['rx_bytes']*8/d['secs']/1e9:6.2f} Gbit/s  p50 {d['p50_us']:7.1f}us p99 {d['p99_us']:8.1f}us "
      f"p99.9 {d['p999_us']:8.1f}us  sys-cpu {cpu}%")
PY
}

pkill -x utcp-app; sleep 0.5

# 1) kernel -> kernel
ip netns exec kern $B --backend kernel --role server --ip 10.20.0.2 --workers $SW > /tmp/g-srv.log 2>&1 &
sleep 0.7; cpu_begin
j=$(ip netns exec peer $B --backend kernel --role client --ip 10.20.0.1 --peer 10.20.0.2 --workers $CW $WL 2>/dev/null | grep '"role":"client"')
cpu_end; pkill -INT -x utcp-app; sleep 1
report "kernel -> kernel" "$j"

# 2) kernel client -> utcp server
ip netns exec peer $B --backend utcp --role server --ip 10.10.0.2 --workers $SW > /tmp/g-srv.log 2>&1 &
sleep 0.7; cpu_begin
j=$(ip netns exec peer $B --backend kernel --role client --ip 10.10.0.1 --peer 10.10.0.2 --workers $CW $WL 2>/dev/null | grep '"role":"client"')
cpu_end; pkill -INT -x utcp-app; sleep 1
report "kernel -> utcp server" "$j"
grep -E "^   utcp|recovery|buffers" /tmp/g-srv.log | sed 's/^/      server: /'

# 3) utcp client -> kernel server
ip netns exec peer $B --backend kernel --role server --ip 10.10.0.1 --workers $SW > /tmp/g-srv.log 2>&1 &
sleep 0.7; cpu_begin
out=$(ip netns exec peer $B --backend utcp --role client --ip 10.10.0.2 --peer 10.10.0.1 --mac 02:00:00:00:00:02 --max-tw 4096 --workers $CW $WL 2>&1)
cpu_end; pkill -INT -x utcp-app; sleep 1
report "utcp client -> kernel" "$(echo "$out" | grep '"role":"client"')"

# 4) utcp client -> utcp server over the shared-memory link
$B --backend utcp --role server --link g10k --ip 10.30.0.2 --mac 02:00:00:00:30:02 --workers $SW > /tmp/g-srv.log 2>&1 &
sleep 0.7; cpu_begin
out=$($B --backend utcp --role client --link g10k --ip 10.30.0.1 --mac 02:00:00:00:30:01 --peer 10.30.0.2 \
    --max-tw 4096 --workers $CW $WL 2>&1)
cpu_end; pkill -INT -x utcp-app; sleep 1
report "utcp client -> utcp (shm)" "$(echo "$out" | grep '"role":"client"')"
grep -E "^   utcp|recovery" /tmp/g-srv.log | sed 's/^/      server: /'
