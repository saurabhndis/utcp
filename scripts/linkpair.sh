#!/usr/bin/env bash
# utcp server <-> utcp client over the shared-memory link (no kernel in the path).
# Usage: sudo linkpair.sh <workers> <client args...>
B=${B:-/tmp/b/rel/app/utcp-app}
nw=$1; shift
pkill -x utcp-app; sleep 0.3
$B --backend utcp --role server --link lp --ip 10.30.0.2 --mac 02:00:00:00:30:02 --workers $nw $SRV_EXTRA > /tmp/lp-srv.log 2>&1 &
sleep 0.5
read -r _ u n s i _ < /proc/stat; t0=$((u+n+s)); i0=$i
timeout ${TMO:-120} $B --backend utcp --role client --link lp --ip 10.30.0.1 --mac 02:00:00:00:30:01 \
    --peer 10.30.0.2 --workers $nw "$@"
rc=$?
read -r _ u n s i _ < /proc/stat; b=$((u+n+s-t0)); echo "   system cpu busy: $((100*b/(b+i-i0)))%"
pkill -INT -x utcp-app; sleep 0.5
grep -E "died|ERROR|runtime error" /tmp/lp-srv.log | head -3
exit $rc
