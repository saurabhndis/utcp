# utcp — user-space TCP/IPv4 stack

A full-duplex TCP stack in C11, implemented as a library. It follows current Linux TCP
behaviour (CUBIC + HyStart, SACK, RACK-TLP, PRR, D-SACK/Eifel undo, TSO autosizing) and is
written from the RFCs, without copying kernel source. It works with or without DPDK: all
packet I/O, memory, time and events go through callbacks the application registers.

Designed for one instance per core, each in its own process, with **all session state in
shared memory** so that:

- every session is owned by one core: there are no locks or atomics on the per-packet path;
- a packet that arrives on the wrong core is passed to the owner over a lock-free SPSC ring;
- a worker that crashes can be re-forked and re-attach to its core **without losing its
  connections** (shown below).

```
                    shared memory (mapped at the same address in every process)
   ┌──────────────────────────────────────────────────────────────────────────────┐
   │ region: config, Toeplitz tables, bucket→core table, ARP (seqlock), stats      │
   │ core 0: flow table, listeners, timer wheel │ core 1: ... │ core N: ...        │
   │ sockets, send/receive queues, retransmit scoreboard, packet buffers           │
   │ handoff rings  ring[from][to]  (SPSC, cache-line separated)                   │
   └──────────────────────────────────────────────────────────────────────────────┘
        ▲ utcp_attach(core 0)        ▲ utcp_attach(core 1)        ▲ ...
   ┌────┴─────┐                 ┌────┴─────┐
   │ worker 0 │  NIC queue 0    │ worker 1 │  NIC queue 1   (RSS uses utcp's key + table)
   └──────────┘                 └──────────┘
```

## Layout

| Path | What |
|---|---|
| `include/utcp.h` | Public API (the only header applications need) |
| `src/core.c` | Region, attach (address check, crash recovery), Toeplitz/RSS, rings, timer wheel, event dispatch, bucket migration |
| `src/net.c` | Ethernet, ARP, IPv4, ICMP (echo, PMTU), checksums, steering decision |
| `src/tcp_in.c` | Input: handshake, RFC 5961 checks, PAWS, ACK/SACK, RACK-TLP loss detection, PRR, undo, reassembly, SACK generation |
| `src/tcp_out.c` | Output: segmentation/TSO, zero-copy payload references, retransmission, RTO/TLP/persist/delayed-ACK timers |
| `src/tcp_cc.c` | CUBIC (RFC 9438, Linux semantics, HyStart) and Reno |
| `src/tcp_sock.c` | Socket API and lifecycle, ISN (RFC 6528, SipHash) |
| `app/` | `utcp-app`: benchmark app with two interchangeable backends (utcp over TAP, or kernel sockets), a zygote and per-core workers |
| `tests/` | Unit tests, deterministic network simulator plus 15 end-to-end scenarios, libFuzzer harness |
| `scripts/` | Network-namespace topology, benchmark matrix, loss comparison, crash test |

## Using the library

```c
struct utcp_ops ops = {
    .mem_alloc = my_shm_alloc, .mem_free = my_shm_free,       /* shared memory  */
    .buf_alloc = my_pkt_alloc, .buf_free = my_pkt_free,       /* packet buffers */
    .tx_burst  = my_tx,        .now_ns   = my_clock,
    .on_event  = my_events,    .on_migrate = my_migrate,      /* optional       */
};
struct utcp_config cfg;
utcp_config_default(&cfg);
cfg.ncores = N; cfg.local_ip = ...; memcpy(cfg.mac, ..., 6);
cfg.offloads = UTCP_OFFLOAD_TSO | UTCP_OFFLOAD_TX_CSUM;

struct utcp_region *r;
utcp_region_create(&cfg, &ops, ctx, &r);      /* once, in the zygote, before fork() */
/* ... fork one worker per core ... */
utcp_t *t = utcp_attach(r, core, &ops, ctx);  /* in each worker */
utcp_listen(t, 80, 4096);                     /* every core listens (per-core listeners) */
for (;;) {
    n = rx(pkts);                             /* NIC / TAP / AF_XDP: the app's choice */
    utcp_input_burst(t, pkts, n);             /* events fire, output is batched */
    utcp_poll(t);                             /* timers, handoff rings, flush */
}
```

Contract highlights (see `utcp.h`):

- **Shared memory**: the region and all `mem_alloc`/`buf_alloc` memory must be mapped at the
  same virtual address in every process. `utcp_attach` checks this and fails with `EFAULT`.
  Fork from a zygote, or map with `MAP_FIXED_NOREPLACE`.
- **Ownership**: a core may only touch its own `utcp_t` and sockets. Buffers may be freed on
  any core; the application's pool must handle remote frees.
- **TX packets** passed to `tx_burst` may reference send-queue memory (zero-copy) and must be
  released with `utcp_pkt_free()`. With DPDK, call it from the external-buffer free
  callback.
- **RSS**: program the NIC with `utcp_rss_key()` (40-byte symmetric Toeplitz key) and map RETA
  entries with `utcp_bucket_owner()`. Outgoing connections choose source ports whose hash
  maps back to the calling core.
- **Zero-copy receive**: `utcp_recv_zc()` and `utcp_recv_consume()`.
- **Rebalancing**: `utcp_migrate_bucket()` moves a bucket's sessions to another core
  (versioned handover: in-flight packets are held until the sessions arrive).
- **Crash recovery**: re-running `utcp_attach()` for a core repairs process-local state.
  `utcp_foreach_sock()` lets the application rebuild its own state.

## Build and test

Development happens on macOS, with Linux running in a Lima VM (`limactl start ... template:ubuntu-lts`).

```sh
meson setup build -Dbuildtype=release && ninja -C build
meson setup build-asan -Db_sanitize=address,undefined && ninja -C build-asan
build-asan/tests/test_unit
ASAN_OPTIONS=detect_leaks=0 build-asan/tests/test_wire        # 15 scenarios
clang -fsanitize=fuzzer,address,undefined -Iinclude src/*.c tests/fuzz_input.c -lm -o fuzz_input
sudo scripts/netns.sh up                                        # TAP + veth topology
sudo scripts/bench.sh                                           # utcp vs kernel matrix
sudo scripts/loss_cmp.sh                                        # per-packet loss behaviour
sudo scripts/crash_test.sh                                      # SIGKILL a worker mid-run
```

### Simulator scenarios (`tests/test_wire.c`)

Two utcp hosts over a simulated link with bandwidth, propagation delay, a tail-drop queue,
random loss, reordering and NIC-style software GSO. Every byte is pattern-verified. Each
scenario also checks for socket and buffer leaks and, on FIFO links, for spurious
retransmissions (any D-SACK fails the test).

| Scenario | Result |
|---|---|
| bulk TSO, 10G, 2 ms RTT | 9.1 Gbit/s, 0 retransmits |
| taildrop, queue 0.25 BDP | 5.9 Gbit/s, retransmits == drops, 0 spurious |
| 1% / 5% random loss, 0.1% loss with Reno | complete, data verified |
| 3% reordering (+3 ms) | 0.88 of 1 Gbit/s (undo + adaptive reorder window) |
| full duplex 10G | 12.8 Gbit/s combined |
| 1000 connections, 4×4 cores RSS, packet spraying (handoff rings), live bucket migration, zero window | pass |

## Results: utcp vs the Linux 7.0 kernel

Same application, same kernel-socket load generator, same machine (Apple M4, 8 vCPUs,
Linux 7.0 in a Lima VM). The utcp server runs over a multi-queue TAP with eBPF steering
that emulates NIC RSS; the kernel server runs over veth.

| Workload | utcp | kernel |
|---|---|---|
| RR, 64 conns, 4 workers | **1.30 M tps**, p99 148 µs | 1.10 M tps, p99 148 µs |
| CRR, 1 worker | **106 k conn/s**, p99 131 µs | 69 k conn/s, p99 148 µs |
| CRR, 4 workers | **193 k conn/s**, p99 459 µs | 174 k conn/s, p99 623 µs |
| RR, 1 conn | 29.7 k tps, p50 32.8 µs | 29.2 k tps, p50 32.8 µs |
| Stream, kernel → utcp, 1 conn | 105 Gbit/s | 119 Gbit/s |
| Stream, utcp → kernel, 1 conn | 71 Gbit/s | 120 Gbit/s |
| Stream, full duplex, 1 conn | 75 Gbit/s | 120 Gbit/s |
| Stream, 16 conns, 4 workers | 90 Gbit/s | 170 Gbit/s |
| Rate-limited 1 Gbit/s, 20 ms RTT (utcp sending) | 0.92 Gbit/s | 0.92 Gbit/s |

Raw results are written to `results/bench-*.jsonl` by `scripts/bench.sh`. The loss rows in
that script use netem on GSO-sized packets, so they are not comparable between paths; use
`scripts/loss_cmp.sh` (below) for loss behaviour.

Bulk streams are limited by TAP itself. Every payload byte crosses the user/kernel boundary
with a copy, while veth passes skbs without copying. On a NIC with DPDK those copies become
DMA. Workloads dominated by packet rate (RR/CRR) already favour utcp.

**Loss behaviour versus Linux** (`scripts/loss_cmp.sh`: utcp sending vs Linux sending, with
per-packet netem loss on both paths, segmentation offload and GRO off):

| Loss | utcp: recoveries / retransmits | kernel: recoveries / retransmits |
|---|---|---|
| 1%, 2 ms RTT | 1655 / 1869 | 1679 / 1873 |
| 0.1%, 5 ms RTT | 164 / 172 (0.090 Gbit/s) | 161 / 380 (0.085 Gbit/s) |
| 0.01%, 10 ms RTT | 22 (0.167 Gbit/s) | 22 (0.184 Gbit/s) |

**Crash survival**: during an RR run with 64 connections over 4 workers, a worker was killed
with SIGKILL. The zygote re-forked it and it re-attached with all 15 of its connections. The
client saw 0 errors; the packets lost during the restart were repaired by RTO and correctly
undone as spurious.

## Linux behaviour implemented

- **Connections**: RFC 9293 state machine, simultaneous open, RFC 5961 (challenge ACKs,
  exact-match RST), PAWS (RFC 7323), TIME_WAIT reuse by sequence number.
- **Options**: MSS, window scaling, timestamps, SACK-permitted.
- **Loss recovery**: SACK scoreboard with record splitting, D-SACK (RFC 2883), RACK-TLP
  (RFC 8985) with a reorder window that adapts after D-SACKs, PRR (RFC 6937), NewReno
  fallback, spurious-recovery undo (D-SACK, and Eifel per RFC 3522).
- **RTO**: computed as Linux does (`srtt + max(4·rttvar, 200 ms)`), exponential backoff.
- **Congestion control**: CUBIC with fast convergence, Reno-friendly region and delay-based
  HyStart; Reno; IW10; growth only when cwnd-limited.
- **ACKs**: delayed ACK, quickack, an immediate ACK for every out-of-order segment
  (`tcp_data_queue_ofo` semantics), SACK blocks ordered newest-first.
- **Receive window**: never shrinks, silly-window avoidance, window updates on read
  (`__tcp_cleanup_rbuf`), zero-window probes.
- **Sending**: Nagle / NODELAY, TSO autosizing to about 1 ms of pacing rate.
- **Offloads**: GRO input (virtio `gso_size`), TX and RX checksum offload.
- **ISN**: RFC 6528 with SipHash-2-4. **PMTU**: ICMP "fragmentation needed".

## Not implemented yet

IPv6, BBRv3, ECN/AccECN, TCP Fast Open, SYN cookies, keepalive, IP fragment reassembly
(fragments are dropped; TCP sets DF), a cap on TIME_WAIT entries and compact TIME_WAIT
entries, pacing beyond TSO autosizing, receive-buffer autotuning (`rcvbuf` is fixed per
socket), and the DPDK adapter in `utcp-app`. The library API already has what the DPDK
adapter needs: the RSS key and RETA, TX offload metadata (`l4_off`, `l4_hlen`, `gso_size`)
and zero-copy references.
