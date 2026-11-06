/*
 * utcp - user-space TCP/IPv4 stack.
 *
 * Model
 * -----
 * One utcp "region" holds all shared state (sessions, handoff rings, bucket
 * table, ARP table).  The region lives in memory the application provides via
 * ops->mem_alloc and must be mapped at the SAME virtual address in every
 * process that attaches to it (fork from a zygote, or MAP_FIXED_NOREPLACE).
 * utcp_attach() verifies this.
 *
 * Each core runs one utcp instance (utcp_t) obtained with utcp_attach().  A
 * session is owned by exactly one core: owner = bucket_table[hash(4-tuple)].
 * The hash is a symmetric Toeplitz hash, identical to NIC RSS when the NIC is
 * programmed with utcp_rss_key()/utcp_bucket_owner(), so a correctly steered
 * packet is processed with no locks or atomics.  A packet that lands on the
 * wrong core is passed to the owner over a lock-free SPSC ring.
 *
 * Threading contract: a utcp_t and the sockets it owns may only be used by
 * the thread/process that attached that core.
 *
 * The library never allocates memory on its own.  Packet buffers come from
 * ops->buf_alloc and are returned with ops->buf_free; they must live in the
 * shared mapping and may be freed by a core other than the one that
 * allocated them (the application's pool must handle that).
 */
#ifndef UTCP_H
#define UTCP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UTCP_ABI_VERSION 1
#define UTCP_MAX_CORES   64

/* ---------------------------------------------------------------- buffers */

/* utcp_buf.flags */
#define UTCP_BUF_RX_CSUM_OK   0x0001 /* rx: L3/L4 checksums already verified  */
#define UTCP_BUF_TX_CSUM      0x0002 /* tx: L4 checksum left to device        */
#define UTCP_BUF_TSO          0x0004 /* tx: segment into gso_size payloads    */
#define UTCP_BUF_HASH_VALID   0x0008 /* rx: .hash holds the device RSS hash   */
#define UTCP_BUF_GRO          0x0010 /* rx: coalesced segment (gso_size=mss)  */
#define UTCP_BUF_EXT          0x0020 /* tx: fragment references `ext` (zero copy);
                                        release packets with utcp_pkt_free() */

struct utcp_buf {
    struct utcp_buf *next;    /* next fragment of the same packet          */
    struct utcp_buf *nextpkt; /* queue linkage, owned by whoever holds it  */
    uint8_t *base;            /* start of the buffer memory                */
    uint8_t *data;            /* start of valid data                       */
    uint32_t cap;             /* bytes from base to end of buffer          */
    uint32_t len;             /* valid bytes in this fragment              */
    uint32_t pkt_len;         /* total bytes in chain (head only)          */
    uint16_t flags;
    uint16_t gso_size;        /* tx TSO / rx GRO segment payload size      */
    uint16_t l3_off;          /* tx offload: offset of IP header           */
    uint16_t l4_off;          /* tx offload: offset of TCP header          */
    uint16_t l4_hlen;         /* tx offload: TCP header length             */
    uint16_t app_u16;         /* free for the application                  */
    uint32_t hash;            /* rx RSS hash if UTCP_BUF_HASH_VALID        */
    uint32_t seq;             /* internal                                  */
    uint64_t app_u64;         /* free for the application                  */
    struct utcp_buf *ext;     /* UTCP_BUF_EXT: buffer that owns `data`     */
    uint32_t refcnt;          /* internal: references to a send-queue chunk */
    uint32_t _pad;
};

static inline uint32_t utcp_buf_tailroom(const struct utcp_buf *b)
{
    return (uint32_t)(b->base + b->cap - (b->data + b->len));
}

/* ------------------------------------------------------------ callbacks */

struct utcp_sock;

/* events passed to on_event (bitmask) */
#define UTCP_EV_CONNECTED  0x01 /* active open completed                   */
#define UTCP_EV_ACCEPT     0x02 /* listener has connections to accept      */
#define UTCP_EV_READABLE   0x04 /* data (or EOF) available                 */
#define UTCP_EV_WRITABLE   0x08 /* send buffer has room again              */
#define UTCP_EV_EOF        0x10 /* peer sent FIN                           */
#define UTCP_EV_CLOSED     0x20 /* socket fully closed; handle now invalid
                                   after the callback returns              */
#define UTCP_EV_ERROR      0x40 /* reset / timeout; see utcp_sock_error()  */

struct utcp_ops {
    /* Shared memory (must be inside the region mapping). */
    void *(*mem_alloc)(void *ctx, size_t size, size_t align);
    void (*mem_free)(void *ctx, void *p);
    /* Packet buffers (shared memory). buf_alloc returns len=0, data=base+headroom. */
    struct utcp_buf *(*buf_alloc)(void *ctx);
    void (*buf_free)(void *ctx, struct utcp_buf *b);
    /* Transmit n packets; ownership of all n passes to the application. */
    int (*tx_burst)(void *ctx, struct utcp_buf **pkts, int n);
    /* Monotonic clock. */
    uint64_t (*now_ns)(void *ctx);
    /* Socket events, delivered from inside utcp_input_burst()/utcp_poll(). */
    void (*on_event)(void *ctx, struct utcp_sock *s, uint32_t events);
    /* Optional: socket moved between cores (called on the new owner). */
    void (*on_migrate)(void *ctx, struct utcp_sock *s, int from_core, int to_core);
    /* Optional: randomness for ISNs/ports; NULL uses an internal PRNG. */
    uint64_t (*random)(void *ctx);
};

/* -------------------------------------------------------------- config */

#define UTCP_OFFLOAD_TX_CSUM 0x1
#define UTCP_OFFLOAD_TSO     0x2

enum utcp_cc { UTCP_CC_CUBIC = 0, UTCP_CC_RENO = 1 };

struct utcp_config {
    uint32_t ncores;             /* number of instances (<= UTCP_MAX_CORES) */
    uint32_t nbuckets;           /* power of two; default 4096              */
    uint32_t flow_table_size;    /* per-core hash slots; default 65536      */
    uint32_t ring_size;          /* handoff ring entries; default 4096      */
    uint32_t local_ip;           /* network byte order                      */
    uint32_t netmask;            /* network byte order                      */
    uint32_t gateway;            /* network byte order, 0 = none            */
    uint8_t mac[6];
    uint16_t mtu;                /* default 1500                            */
    uint32_t offloads;           /* UTCP_OFFLOAD_*                          */
    uint32_t tso_max;            /* max TSO payload, default 65000          */
    uint32_t sndbuf;             /* default 4 MiB                           */
    uint32_t rcvbuf;             /* default 4 MiB                           */
    uint32_t time_wait_ms;       /* default 60000                           */
    uint32_t max_time_wait;      /* per core, like tcp_max_tw_buckets; 65536 */
    uint32_t delack_ms;          /* default 40                              */
    uint32_t rto_min_ms;         /* default 200                             */
    uint32_t cc;                 /* enum utcp_cc                            */
    uint16_t ephemeral_lo;       /* default 32768                           */
    uint16_t ephemeral_hi;       /* default 60999                           */
    uint8_t rss_key[40];         /* 0 = symmetric 0x6d5a key                */
};

void utcp_config_default(struct utcp_config *cfg);

/* --------------------------------------------------------------- setup */

struct utcp_region;
typedef struct utcp_inst utcp_t;

/* Create the shared region (once, e.g. in the zygote before forking). */
int utcp_region_create(const struct utcp_config *cfg, const struct utcp_ops *ops,
                       void *ctx, struct utcp_region **out);
/* Attach core `core` in the calling process. Fails (NULL, errno=EFAULT) if the
 * region is not mapped at the address it was created at. Re-attaching a core
 * after a crash keeps its sessions. */
utcp_t *utcp_attach(struct utcp_region *r, unsigned core, const struct utcp_ops *ops,
                    void *ctx);
void utcp_detach(utcp_t *t);
/* Visit every connection (not listeners) owned by this core, e.g. to rebuild
 * application state after re-attaching. */
void utcp_foreach_sock(utcp_t *t, void (*fn)(void *arg, struct utcp_sock *s), void *arg);
struct utcp_region *utcp_region(utcp_t *t);
unsigned utcp_core(utcp_t *t);

/* ------------------------------------------------------------- datapath */

/* Process received frames (Ethernet). Takes ownership of all n buffers. */
int utcp_input_burst(utcp_t *t, struct utcp_buf **pkts, int n);
/* Run timers, drain handoff rings, flush output. Returns units of work done. */
int utcp_poll(utcp_t *t);
/* Absolute time (ns, same clock as now_ns) of the next timer, or UINT64_MAX. */
uint64_t utcp_next_timer(utcp_t *t);

/* -------------------------------------------------------------- sockets */

#define UTCP_SHUT_WR 1

struct utcp_sock *utcp_listen(utcp_t *t, uint16_t port, int backlog);
struct utcp_sock *utcp_accept(utcp_t *t, struct utcp_sock *lsn);
/* Non-blocking; UTCP_EV_CONNECTED or UTCP_EV_ERROR follows. The source port
 * is chosen so the connection's hash maps back to this core. */
struct utcp_sock *utcp_connect(utcp_t *t, uint32_t dst_ip, uint16_t dst_port);
ssize_t utcp_send(utcp_t *t, struct utcp_sock *s, const void *buf, size_t len);
ssize_t utcp_recv(utcp_t *t, struct utcp_sock *s, void *buf, size_t len);
/* Zero-copy receive: fills up to `max` iovecs pointing into the receive
 * queue without consuming (same return convention as utcp_recv: count of
 * iovecs, 0 on EOF, -1/EAGAIN). Consume with utcp_recv_consume(). */
struct utcp_iov {
    const uint8_t *base;
    size_t len;
};
int utcp_recv_zc(utcp_t *t, struct utcp_sock *s, struct utcp_iov *iov, int max);
void utcp_recv_consume(utcp_t *t, struct utcp_sock *s, size_t bytes);
/* Release a packet handed to ops->tx_burst. Packets may reference send-queue
 * memory (UTCP_BUF_EXT fragments); this drops those references. Safe to
 * call on any core. */
void utcp_pkt_free(utcp_t *t, struct utcp_buf *pkt);
int utcp_shutdown(utcp_t *t, struct utcp_sock *s, int how);
/* Graceful close; the handle must not be used after this call (data still
 * queued is delivered in the background). */
int utcp_close(utcp_t *t, struct utcp_sock *s);
/* Abortive close (RST). */
int utcp_abort(utcp_t *t, struct utcp_sock *s);

#define UTCP_OPT_NODELAY 1
#define UTCP_OPT_SNDBUF  2
#define UTCP_OPT_RCVBUF  3
int utcp_setopt(utcp_t *t, struct utcp_sock *s, int opt, int val);

void utcp_sock_set_user(struct utcp_sock *s, void *user);
void *utcp_sock_user(const struct utcp_sock *s);
int utcp_sock_error(const struct utcp_sock *s); /* errno value or 0 */
size_t utcp_sock_sndspace(const struct utcp_sock *s);
size_t utcp_sock_readable(const struct utcp_sock *s);

struct utcp_info {
    uint8_t state;
    uint8_t ca_state;
    uint8_t snd_wscale, rcv_wscale;
    uint32_t mss;
    uint32_t cwnd;        /* bytes */
    uint32_t ssthresh;    /* bytes */
    uint32_t srtt_us;
    uint32_t rttvar_us;
    uint32_t min_rtt_us;
    uint32_t rto_ms;
    uint32_t snd_wnd;
    uint32_t rcv_wnd;
    uint32_t inflight;
    uint32_t sacked, lost, retrans; /* scoreboard bytes */
    uint32_t unacked;               /* snd_nxt - snd_una */
    uint64_t bytes_sent;
    uint64_t bytes_retrans;
    uint64_t bytes_acked;
    uint64_t bytes_received;
    uint32_t segs_out, segs_in;
    uint32_t retrans_segs;
    uint32_t rto_events;
    uint32_t tlp_probes;
    uint32_t recoveries;
    uint32_t dsacks;      /* D-SACKs received (spurious retransmissions) */
    uint32_t undos;       /* congestion reductions undone as spurious */
    uint32_t local_ip, remote_ip; /* network order */
    uint16_t local_port, remote_port;
};
int utcp_sock_info(const struct utcp_sock *s, struct utcp_info *info);
const char *utcp_state_name(int state);

/* ------------------------------------------------------- distribution */

uint32_t utcp_rss_hash(const struct utcp_region *r, uint32_t sip, uint32_t dip,
                       uint16_t sport, uint16_t dport); /* all network order */
const uint8_t *utcp_rss_key(const struct utcp_region *r);  /* 40 bytes */
uint32_t utcp_nbuckets(const struct utcp_region *r);
int utcp_bucket_owner(const struct utcp_region *r, uint32_t bucket);
/* Move a bucket (and its sessions) from this core to `to_core`. Must be called
 * on the current owner. The sessions arrive on the new core during its next
 * utcp_poll(), which calls ops->on_migrate for each. */
int utcp_migrate_bucket(utcp_t *t, uint32_t bucket, unsigned to_core);
/* Per-bucket load counters (packets seen since last reset). */
uint64_t utcp_bucket_load(const struct utcp_region *r, uint32_t bucket);

/* ARP / neighbour */
int utcp_arp_add(struct utcp_region *r, uint32_t ip, const uint8_t mac[6]);

/* ---------------------------------------------------------- statistics */

struct utcp_stats {
    uint64_t rx_pkts, tx_pkts;
    uint64_t rx_bytes, tx_bytes;
    uint64_t rx_drop_csum, rx_drop_short, rx_drop_noproto;
    uint64_t handoff_out, handoff_in, handoff_drop;
    uint64_t tcp_rst_sent;
    uint64_t tcp_active_opens, tcp_passive_opens;
    uint64_t tcp_estab_resets, tcp_attempt_fails;
    uint64_t tcp_retrans_segs;
    uint64_t tcp_ooo_pkts;
    uint64_t tcp_listen_drops;
    uint64_t arp_miss;
    uint64_t socks_alloc, socks_free;
    uint64_t tcp_recoveries, tcp_undos, tcp_tlp, tcp_rto, tcp_dsacks;
    uint64_t tcp_tw_overflow; /* TIME_WAIT skipped because the cap was hit */
};
void utcp_stats_get(const struct utcp_region *r, int core, struct utcp_stats *st);

#ifdef __cplusplus
}
#endif
#endif
