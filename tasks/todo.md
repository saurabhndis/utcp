# utcp — user-space TCP stack + TAP test application

## Goals
- C11 library with a plain C API. Our own code implementing current Linux TCP behaviour, no copied kernel source (no GPL).
- Usable with or without DPDK. All packet I/O goes through application callbacks.
- One instance per core, each in its own process. All session state, queues and packet
  buffers live in a shared memory region provided by the application, mapped at the same
  virtual address in every process (zygote fork, or `MAP_FIXED_NOREPLACE`). The library
  checks this when a process attaches.
- The library never allocates memory. The application supplies the memory, allocator, timer,
  packet output, event and data callbacks through `utcp_init()`.
- Each session is pinned to one owner core, so the per-packet path needs no locks.
- A high-performance application that runs the same workloads on either utcp (over TAP) or
  Linux kernel sockets, to compare correctness, behaviour and performance.

## Key design decisions (agreed)
| Topic | Decision |
|---|---|
| Linux behaviour | Our own code, following the RFCs and documented Linux behaviour |
| Process model | Separate processes, one shared region at the same virtual address; no ASLR changes needed |
| Concurrency | Each session has one owner core; no locks on the per-packet path |
| Distribution | The stack's hash is the NIC's hash: symmetric Toeplitz key + bucket-to-core table in shared memory |
| Outgoing connections | Source port chosen so the connection's hash maps back to the calling core |
| Packets on the wrong core | Lock-free single-producer/single-consumer ring per core pair. Fallback only: fragments, ICMP errors, migration, setups without RSS |
| Elephant flows | Offloads (TSO/LRO, checksum), zero copy, batching; detection and isolation onto a reserved core pool; payload hand-off hook; optional send/receive split later |
| Rebalancing | Versioned bucket migration; built-in policy that the application can replace; `on_migrate` callback |
| Remaining shared state | Per-core listener copies, per-core port ranges, per-core timers and statistics, per-core buffer pools with return rings, read-mostly ARP/route tables, cache-line alignment, one region per NUMA node |

## API sketch
```c
struct utcp_ops {             /* per process; never stored in shared memory */
    void *(*alloc)(void *ctx, size_t sz, size_t align, int numa);
    void  (*free)(void *ctx, void *p);
    struct utcp_buf *(*pkt_alloc)(void *ctx);           /* per-core pool */
    void  (*pkt_free)(void *ctx, struct utcp_buf *b);
    int   (*tx_burst)(void *ctx, struct utcp_buf **b, int n);
    uint64_t (*now_ns)(void *ctx);
    void  (*on_event)(void *ctx, utcp_sock_t s, uint32_t ev);   /* ACCEPT/CONNECTED/READABLE/WRITABLE/CLOSED */
    void  (*on_data)(void *ctx, utcp_sock_t s, struct utcp_buf **segs, int n);  /* zero copy */
    void  (*on_migrate)(void *ctx, utcp_sock_t s, int from, int to);
    const struct utcp_policy *policy;                   /* optional; NULL selects the default */
};
int  utcp_region_format(void *base, size_t len, const struct utcp_region_cfg *);  /* once, in the zygote */
utcp_t *utcp_init(void *region_base, int core_id, const struct utcp_ops *, void *ctx);
int  utcp_input_burst(utcp_t *, struct utcp_buf **pkts, int n);
int  utcp_poll(utcp_t *);     /* timers, handoff rings, transmit flush, rebalancer step */
/* listen / connect / send (zero copy and copying) / recv / shutdown / close / setsockopt / get_info */
```

## Plan

### Phase 0 — Environment and skeleton
- [x] Linux build and test environment (macOS has no TAP and no Linux TCP to compare against; see the open question)
- [x] Repository, Meson build, `-Wall -Werror`, ASan/UBSan/TSan builds, clang-format
- [x] Unit test framework, plus a fake-wire harness for scripted packet tests in the style of packetdrill

### Phase 1 — Core infrastructure
- [x] Shared region layout: header (magic, version, base-address check), per-NUMA areas, per-core blocks aligned to cache lines
- [x] `utcp_init` / ops contract; per-core packet buffer pools with return rings
- [x] Symmetric Toeplitz hash (software, matching the NIC), bucket-to-core table with versions
- [x] Single-producer/single-consumer rings, one per core pair
- [x] Per-core hierarchical timer wheel; per-core statistics summed when read

### Phase 2 — L2/L3
- [x] Ethernet, ARP (read-mostly table with one writer), IPv4, ICMP (including Path MTU discovery), IP fragment reassembly
- [x] Checksums: software, plus offload flags
- [ ] IPv6, ICMPv6, neighbour discovery (phase 2b)

### Phase 3 — TCP core (RFC 9293)
- [x] State machine, connection setup, simultaneous open, orderly close and reset handling (RFC 5961), TIME_WAIT
- [x] Per-core listener copies, half-open connection queue, SYN cookies, ISN generation (RFC 6528)
- [x] Options: MSS, window scaling, timestamps (RFC 7323), SACK-permitted
- [x] Zero-copy send and receive buffers, out-of-order queue, flow control, window shrink handling, delayed ACK and quick ACK
- [ ] Retransmission timeout (RFC 6298), keepalive, zero-window probes, user timeout
- [x] Per-core ephemeral port ranges, with source ports chosen to map back to the calling core

### Phase 4 — Linux-equivalent loss recovery and congestion control
- [x] SACK scoreboard, D-SACK, RACK-TLP (RFC 8985), PRR (RFC 6937)
- [x] Pluggable congestion-control interface; CUBIC (RFC 9438) with HyStart++ (RFC 9406); BBRv3
- [ ] Pacing; small-queue limits like Linux TSQ; ECN (RFC 3168) plus AccECN
- [ ] TCP Fast Open (RFC 7413)

### Phase 5 — Offloads and batching (needed for elephant flows)
- [x] Segments of up to 64 KB in both directions (TSO send, LRO/GRO receive), software GSO/GRO fallback
- [x] Burst processing of 32–64 packets, thinning of ACKs, header/data split

### Phase 6 — Multi-core distribution
- [x] Packet handoff to the owner core on the fast path
- [ ] Load tracking (per-bucket and per-core averages), elephant detection and isolation
- [x] Bucket migration protocol and `on_migrate`; default rebalancer with hysteresis; policy that the application can replace
- [ ] DPDK adapter: RSS table and key setup, `rte_flow` rules for elephants (optional build)

### Phase 7 — Test application with two interchangeable TCP backends (`utcp-app`)
One application binary. Its workload logic sits on a small transport interface with two
implementations, chosen by `--backend=utcp|kernel`. Everything else stays the same: worker
model, core pinning, workloads, metrics.

- [x] Transport interface: `listen` / `connect` / `send` / `recv` / `close` / `poll`, with readiness and data events (shaped like the utcp ops, so the utcp backend is a thin wrapper)
- [x] Shared worker model: a zygote forks N workers pinned to cores, each running one event loop that handles everything for its connections; the zygote restarts any worker that dies
- [x] **utcp backend**:
  - Each worker owns one queue of a multi-queue TAP (`IFF_MULTI_QUEUE`)
  - An eBPF steering program (`TUNSETSTEERINGEBPF`) applies the same Toeplitz hash and bucket table as the library, mimicking NIC RSS; a mode without it exercises the handoff rings
  - Batched `readv` / `writev` on the TAP, with `vnet_hdr` so 64 KB segments pass through (TSO/LRO paths)
  - Shared region mapped by the zygote
- [x] **kernel backend**, tuned so the comparison is fair:
  - non-blocking sockets with edge-triggered `epoll`
  - one `SO_REUSEPORT` listener per worker, with a BPF program steering each connection to its CPU
  - `TCP_NODELAY` where the workload needs it, `SO_BUSY_POLL`, optional `MSG_ZEROCOPY`
  - optional io_uring loop
- [x] Peer side: the same binary in client mode, running on kernel sockets in a second network namespace. Both servers sit behind identical paths, so only the server's TCP stack differs:
  - utcp server ↔ TAP ↔ peer namespace
  - kernel server namespace ↔ veth ↔ peer namespace
  - The roles also run reversed (app as client), plus utcp ↔ utcp
- [x] Workloads:
  - bulk send (elephant), in both directions
  - full duplex
  - connect/request/response (many small flows)
  - request/response latency
  - mixes of elephants and small flows
  - large numbers of idle concurrent connections
- [x] Data integrity: stream content from a seed, checked byte for byte at the receiver
- [x] Metrics per run, per backend:
  - throughput
  - connections/s
  - latency p50/p99/p99.9
  - CPU cycles per byte and per connection, measured separately for the TCP stack and for I/O
  - retransmits
  - congestion window over time, from `tcp_info` and utcp `get_info`
- [x] The same `tc netem` impairment profile (loss, delay, reordering, duplication) applied to both paths
- [ ] pcap of every run; a report comparing the two backends side by side
- [ ] Later backends: AF_XDP and DPDK for the utcp side, for performance comparisons on real NICs

### Phase 8 — Hardening
- [x] libFuzzer on the input path (fake wire)
- [ ] Interoperability matrix: Linux CUBIC/BBR peers, with and without SACK, timestamps and window scaling
- [ ] Profiling and per-packet cycle budget; NUMA tests; tests that kill and restart workers to check session recovery

## Review (2026-11-05)

**Done and verified**
- Library: `src/` (about 3.5k lines of C11). Unit tests check the Toeplitz hash against the
  Microsoft RSS reference vector, hash symmetry, rings and checksums.
- Simulator: 15 end-to-end scenarios pass under ASan/UBSan, with byte verification and
  socket/buffer leak checks. Any spurious retransmission on a FIFO link fails a scenario.
- Live against the Linux 7.0 kernel, in both directions (utcp server with a kernel client,
  and a utcp client with a kernel server), covering stream/rr/crr and 1–4 workers.
- eBPF TAP steering emulates NIC RSS; handoffs drop to 0.
- Crash survival: a worker was SIGKILLed mid-run and its 15 connections were recovered with
  0 client errors.
- Fuzzing: libFuzzer + ASan/UBSan on the input path, with a buffer-leak oracle; no findings.
- Benchmarks and loss parity: see README.

**Bugs found by the simulator and fixed**
1. Partial-ACK split only checked the original head record, which led to retransmitting
   below `snd_una`.
2. Missing spurious-recovery undo, so reordering permanently halved cwnd.
3. One ACK per burst lost SACK information when there were many holes; Linux sends one ACK
   per out-of-order segment.
4. The SACK block builder was capped at 8 OOO ranges, so new holes were never reported.

**Deviations from the plan**
- Packet steering uses an eBPF program on the TAP (`app/steer.bpf.c`), as planned. The TAP's
  built-in flow learning was tried first and did not steer correctly.
- Not yet: IPv6, BBRv3, ECN/AccECN, TFO, SYN cookies, keepalive, a TIME_WAIT cap,
  rcvbuf autotuning, the DPDK adapter.

**Known limitations**
- Bulk streams over TAP are limited by TAP's per-byte copies; a NIC with DPDK removes them.
- After a worker restart the TAP renumbers its queues; correctness is preserved by the
  handoff rings, but steering is not re-synchronised.
