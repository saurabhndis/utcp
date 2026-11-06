#!/usr/bin/env bash
# pair.sh <server-backend utcp|kernel> <server workers> -- <client args...>
# Runs one server and one kernel-socket client on the shared topology and
# prints both summaries plus whole-system CPU utilisation during the run.
set -uo pipefail
B=${B:-/tmp/b/rel/app/utcp-app}
be=$1; nw=$2; shift 3
SRV_EXTRA=${SRV_EXTRA:-}
if [ "$be" = utcp ]; then
    srv_ns=peer; srv_ip=10.10.0.2; cli_ip=10.10.0.1
    ip netns exec peer $B --backend utcp --role server --ip $srv_ip --workers $nw $SRV_EXTRA \
        > /tmp/pair-srv.log 2>&1 &
else
    srv_ns=kern; srv_ip=10.20.0.2; cli_ip=10.20.0.1
    ip netns exec kern $B --backend kernel --role server --ip $srv_ip --workers $nw $SRV_EXTRA \
        > /tmp/pair-srv.log 2>&1 &
fi
spid=$!
sleep 0.7
read -r _ u n s i rest < /proc/stat; t0=$((u+n+s)); idle0=$i
ip netns exec peer $B --backend kernel --role client --ip $cli_ip --peer $srv_ip "$@"
rc=$?
read -r _ u n s i rest < /proc/stat; t1=$((u+n+s)); idle1=$i
busy=$((t1-t0)); tot=$((busy + idle1-idle0))
echo "   system cpu busy: $((100*busy/(tot>0?tot:1)))% of $(nproc) cores"
kill -INT $spid; wait $spid 2>/dev/null
sed -n '/^==/,$p' /tmp/pair-srv.log
exit $rc
