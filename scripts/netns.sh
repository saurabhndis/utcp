#!/usr/bin/env bash
# Test topology (run as root):
#
#   netns "peer"  (kernel sockets: load generator / kernel-side endpoints)
#     utap0  10.10.0.1/24  <-- multi-queue TAP --> utcp-app (utcp stack 10.10.0.2)
#     vk0    10.20.0.1/24  <-- veth -->  netns "kern": vk1 10.20.0.2/24 (kernel-backend app)
#
# utcp-app (utcp backend) must run inside netns "peer" to open utap0; it does
# not use that namespace's TCP stack. Impairment (netem) is applied
# identically to both paths, in both directions, on the peer side.
set -euo pipefail
cmd=${1:-up}; shift || true
NQ=${NQ:-8}

down() {
    ip netns del peer 2>/dev/null || true
    ip netns del kern 2>/dev/null || true
}

netem() { # netem "<args>" : apply to both paths, both directions
    local args="$1"
    for dev in utap0 vk0; do
        ip netns exec peer tc qdisc replace dev $dev root netem $args
        ip netns exec peer ip link add ifb-$dev type ifb 2>/dev/null || true
        ip netns exec peer ip link set ifb-$dev up
        ip netns exec peer tc qdisc replace dev $dev handle ffff: ingress
        ip netns exec peer tc filter replace dev $dev parent ffff: matchall \
            action mirred egress redirect dev ifb-$dev
        ip netns exec peer tc qdisc replace dev ifb-$dev root netem $args
    done
}

clear_netem() {
    for dev in utap0 vk0; do
        ip netns exec peer tc qdisc del dev $dev root 2>/dev/null || true
        ip netns exec peer tc qdisc del dev $dev ingress 2>/dev/null || true
        ip netns exec peer ip link del ifb-$dev 2>/dev/null || true
    done
}

up() {
    down
    modprobe ifb numifbs=0 2>/dev/null || true
    ip netns add peer
    ip netns add kern
    ip netns exec peer ip link set lo up
    ip netns exec kern ip link set lo up
    # TAP for utcp
    ip netns exec peer ip tuntap add dev utap0 mode tap multi_queue
    ip netns exec peer ip addr add 10.10.0.1/24 dev utap0
    # per-queue ring (like NIC RX ring size); the 1000 default overflows at 10k conns
    ip netns exec peer ip link set utap0 txqueuelen 16384
    ip netns exec peer ip link set utap0 up
    # veth for the kernel backend
    ip link add vk0 type veth peer name vk1
    ip link set vk0 netns peer
    ip link set vk1 netns kern
    ip netns exec peer ip addr add 10.20.0.1/24 dev vk0
    ip netns exec kern ip addr add 10.20.0.2/24 dev vk1
    ip netns exec peer ip link set vk0 up
    ip netns exec kern ip link set vk1 up
    for ns in peer kern; do
        ip netns exec $ns sysctl -qw net.ipv4.tcp_tw_reuse=1
        # keep the load generator's connect() cheap at high CPS (both paths alike)
        ip netns exec $ns sysctl -qw net.ipv4.tcp_max_tw_buckets=4096
        ip netns exec $ns sysctl -qw net.ipv4.ip_local_port_range="10000 65000"
        ip netns exec $ns sysctl -qw net.core.somaxconn=65535
        ip netns exec $ns sysctl -qw net.ipv4.tcp_max_syn_backlog=65535
    done
    sysctl -qw net.core.rmem_max=33554432 net.core.wmem_max=33554432
    echo "topology up: utcp 10.10.0.2 via utap0 (peer ns), kernel 10.20.0.2 via veth (kern ns)"
}

case "$cmd" in
    up) up ;;
    down) down ;;
    netem) netem "$*" ;;
    clear) clear_netem ;;
    *) echo "usage: $0 up|down|netem <args>|clear"; exit 2 ;;
esac
