#!/usr/bin/env bash
B=/tmp/b/rel/app/utcp-app
pkill -x utcp-app; sleep 0.3
ip netns exec peer $B --backend kernel --role server --ip 10.10.0.1 --workers 1 > /tmp/ks-root.log 2>&1 &
sleep 0.5
ip netns exec peer tcpdump -i utap0 -nn -tt -c ${NPKT:-40} > /tmp/cli-root.txt 2>/dev/null &
sleep 0.5
timeout ${TMO:-30} ip netns exec peer $B --backend utcp --role client --ip 10.10.0.2 --peer 10.10.0.1 --workers 1 "$@"
echo "client exit=$?"
sleep 0.3; pkill tcpdump; pkill -INT -x utcp-app; sleep 0.3
head -40 /tmp/cli-root.txt
