#!/usr/bin/env bash
B=/tmp/b/rel/app/utcp-app
pkill -x utcp-app; sleep 0.3
ip netns exec peer $B --backend kernel --role server --ip 10.10.0.1 --workers 1 > /tmp/ks-root.log 2>&1 &
sleep 0.5
ip netns exec peer $B --backend utcp --role client --ip 10.10.0.2 --peer 10.10.0.1 "$@" > /tmp/uc-root.log 2>&1 &
sleep 2
pkill -USR1 -x utcp-app; sleep 0.3
ip netns exec peer ss -tni dst 10.10.0.2 | head -12
pkill -INT -x utcp-app; sleep 0.5
cat /tmp/uc-root.log
