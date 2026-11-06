#!/usr/bin/env bash
# Kill a utcp server worker with SIGKILL mid-run; the zygote re-forks it, it
# re-attaches to its core and must carry on with its live connections.
B=/tmp/b/rel/app/utcp-app
pkill -x utcp-app; sleep 0.3
ip netns exec peer $B --backend utcp --role server --ip 10.10.0.2 --workers 4 > /tmp/crash-srv.log 2>&1 &
sleep 0.7
ip netns exec peer $B --backend kernel --role client --ip 10.10.0.1 --peer 10.10.0.2 \
    --workers 4 --conns 16 --workload ${WL:-rr} --duration ${DUR:-10} "$@" > /tmp/crash-cli.log 2>&1 &
cli=$!
sleep 3
zyg=$(pgrep -o -f 'backend utcp --role server')
victim=$(pgrep -P "$zyg" | sed -n 3p)
echo "killing server worker pid $victim with SIGKILL"
kill -9 "$victim"
wait $cli; rc=$?
pkill -INT -f "backend utcp --role server"; sleep 0.5
echo "--- client (rc=$rc)"; cat /tmp/crash-cli.log
echo "--- server"; cat /tmp/crash-srv.log
