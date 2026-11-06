#!/usr/bin/env bash
# Per-packet loss comparison: segmentation offload off on both senders, so
# netem drops individual MTU-sized packets on both paths.
HERE=$(cd "$(dirname "$0")" && pwd)
ip netns exec kern ethtool -K vk1 tso off gso off >/dev/null 2>&1
ip netns exec peer ethtool -K utap0 gro off >/dev/null 2>&1; ip netns exec peer ethtool -K vk0 gro off >/dev/null 2>&1
for nem in "delay 1ms loss 1%" "delay 2500us loss 0.1%" "delay 5ms loss 0.01%" "delay 1ms reorder 5% 50%"; do
    "$HERE/netns.sh" netem "$nem"; sleep 0.3
    for be in utcp kernel; do
        extra=""; [ $be = utcp ] && extra="--no-tso"
        ip netns exec kern nstat -n >/dev/null
        out=$(SRV_EXTRA="$extra" "$HERE/pair.sh" $be 1 -- --json --workload stream --c2s 0 --s2c ${SZ:-256M} --conns 1 --no-verify --duration 120 2>&1)
        r=$(echo "$out" | grep '"role":"client"' | python3 -c 'import json,sys; print("%.3f" % json.load(sys.stdin)["gbps"])')
        if [ $be = utcp ]; then
            st=$(echo "$out" | sed -n 's/.*tx \([0-9]*\) pkts; retrans \([0-9]*\).*/segs=\1 retrans=\2/p'; echo "$out" | sed -n 's/.*recovery  episodes \([0-9]*\) undos \([0-9]*\) tlp \([0-9]*\) rto \([0-9]*\).*/recov=\1 undo=\2 tlp=\3 rto=\4/p')
        else
            st=$(ip netns exec kern nstat | awk '/TcpOutSegs/{o=$2}/TcpRetransSegs/{r=$2}/SackRecovery /{s=$2}/TCPSackRecovery /{s=$2}/LossUndo|SackRecoveryFail|DSACKUndo|PartialUndo/{u+=$2}/LossProbes /{p=$2}/TCPTimeouts/{t=$2} END{printf "segs=%d retrans=%d recov=%d undo=%d tlp=%d rto=%d", o, r, s, u, p, t}')
        fi
        printf "%-26s %-6s %7s Gbit/s  %s\n" "$nem" $be "$r" "$(echo $st)"
    done
done
"$HERE/netns.sh" clear
ip netns exec kern ethtool -K vk1 tso on gso on >/dev/null 2>&1
ip netns exec peer ethtool -K utap0 gro on >/dev/null 2>&1; ip netns exec peer ethtool -K vk0 gro on >/dev/null 2>&1
