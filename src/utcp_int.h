/* Internal definitions shared by the utcp sources. */
#ifndef UTCP_INT_H
#define UTCP_INT_H

#include "utcp.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>

#define CACHELINE 128
#define ALIGNED_CL __attribute__((aligned(CACHELINE)))
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define UTCP_REGION_MAGIC 0x75746370524731ULL /* "utcpRG1" */
#define UTCP_SOCK_MAGIC 0x75534f4b            /* "uSOK" */

/* ------------------------------------------------------------ wire formats */

struct eth_hdr {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
} __attribute__((packed));

struct arp_hdr {
    uint16_t htype, ptype;
    uint8_t hlen, plen;
    uint16_t op;
    uint8_t sha[6];
    uint32_t spa;
    uint8_t tha[6];
    uint32_t tpa;
} __attribute__((packed));

struct ip_hdr {
    uint8_t vhl, tos;
    uint16_t tot_len, id, frag;
    uint8_t ttl, proto;
    uint16_t check;
    uint32_t saddr, daddr;
} __attribute__((packed));

struct tcp_hdr {
    uint16_t sport, dport;
    uint32_t seq, ack;
    uint8_t doff; /* upper 4 bits */
    uint8_t flags;
    uint16_t win, check, urg;
} __attribute__((packed));

struct icmp_hdr {
    uint8_t type, code;
    uint16_t check;
    uint16_t id, seq; /* or unused + next-hop MTU for type 3 code 4 */
} __attribute__((packed));

#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define IPPROTO_TCP_ 6
#define IPPROTO_ICMP_ 1
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80

#define TCPOPT_EOL 0
#define TCPOPT_NOP 1
#define TCPOPT_MSS 2
#define TCPOPT_WS 3
#define TCPOPT_SACK_PERM 4
#define TCPOPT_SACK 5
#define TCPOPT_TS 8

#define ETH_HLEN 14
#define IP_HLEN 20
#define TCP_HLEN 20
#define HDRS_LEN (ETH_HLEN + IP_HLEN + TCP_HLEN)
#define TCP_MAX_OPT 40

/* ---------------------------------------------------------- byte order */

static inline uint16_t bswap16(uint16_t x) { return __builtin_bswap16(x); }
static inline uint32_t bswap32(uint32_t x) { return __builtin_bswap32(x); }
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define hton16(x) bswap16(x)
#define ntoh16(x) bswap16(x)
#define hton32(x) bswap32(x)
#define ntoh32(x) bswap32(x)
#else
#define hton16(x) (x)
#define ntoh16(x) (x)
#define hton32(x) (x)
#define ntoh32(x) (x)
#endif

/* sequence arithmetic */
static inline bool seq_lt(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }
static inline bool seq_le(uint32_t a, uint32_t b) { return (int32_t)(a - b) <= 0; }
static inline bool seq_gt(uint32_t a, uint32_t b) { return (int32_t)(a - b) > 0; }
static inline bool seq_ge(uint32_t a, uint32_t b) { return (int32_t)(a - b) >= 0; }
static inline uint32_t seq_max(uint32_t a, uint32_t b) { return seq_gt(a, b) ? a : b; }
static inline uint32_t seq_min(uint32_t a, uint32_t b) { return seq_lt(a, b) ? a : b; }

/* ------------------------------------------------------------ SPSC ring */

struct ring {
    _Atomic uint32_t head ALIGNED_CL; /* written by producer */
    uint32_t tail_cache;
    _Atomic uint32_t tail ALIGNED_CL; /* written by consumer */
    uint32_t head_cache;
    uint32_t mask ALIGNED_CL;
    void *slots[];
};

static inline int ring_push(struct ring *r, void *p)
{
    uint32_t h = atomic_load_explicit(&r->head, memory_order_relaxed);
    if (h - r->tail_cache > r->mask) {
        r->tail_cache = atomic_load_explicit(&r->tail, memory_order_acquire);
        if (h - r->tail_cache > r->mask)
            return -1;
    }
    r->slots[h & r->mask] = p;
    atomic_store_explicit(&r->head, h + 1, memory_order_release);
    return 0;
}

static inline unsigned ring_pop_burst(struct ring *r, void **out, unsigned max)
{
    uint32_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);
    if (t == r->head_cache) {
        r->head_cache = atomic_load_explicit(&r->head, memory_order_acquire);
        if (t == r->head_cache)
            return 0;
    }
    unsigned n = MIN(max, r->head_cache - t);
    for (unsigned i = 0; i < n; i++)
        out[i] = r->slots[(t + i) & r->mask];
    atomic_store_explicit(&r->tail, t + n, memory_order_release);
    return n;
}

/* --------------------------------------------------------------- timers */

struct tmr_node {
    struct tmr_node *next, *prev;
    uint64_t expire_tick; /* 0 = not armed */
};

#define WHEEL_SLOTS 1024
#define TICK_NS 1000000ULL /* 1 ms */

struct wheel {
    uint64_t cur_tick;
    struct tmr_node slots[WHEEL_SLOTS]; /* sentinels */
};

/* ------------------------------------------------------------ TCP state */

enum {
    TCP_CLOSED = 0,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RCVD,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_LAST_ACK,
    TCP_TIME_WAIT,
};

/* congestion "ca_state", as in Linux */
enum { CA_OPEN = 0, CA_DISORDER, CA_CWR, CA_RECOVERY, CA_LOSS };

/* retransmission-queue record flags */
#define TR_SACKED 0x01
#define TR_LOST 0x02
#define TR_RETRANS 0x04 /* retransmitted, retransmission still outstanding */
#define TR_EVER_RETRANS 0x08
#define TR_FIN 0x10
#define TR_SYN 0x20

struct txrec {
    struct txrec *next, *prev;
    uint32_t start, end; /* sequence range (FIN/SYN included) */
    uint64_t xmit_ns;    /* last (re)transmission time */
    uint64_t delivered_at_send; /* for delivery-rate samples */
    uint64_t delivered_ns_at_send;
    uint8_t flags;
    uint8_t xmits;
};

/* sock.flags */
#define SF_NODELAY 0x0001
#define SF_TS_OK 0x0002
#define SF_SACK_OK 0x0004
#define SF_WS_OK 0x0008
#define SF_FIN_QUEUED 0x0010 /* app requested FIN after queued data */
#define SF_FIN_SENT 0x0020
#define SF_FIN_RCVD 0x0040
#define SF_ACK_NOW 0x0080
#define SF_IN_DIRTY 0x0100
#define SF_IN_EVLIST 0x0200
#define SF_CLOSED_BY_APP 0x0400 /* handle released */
#define SF_DEAD 0x0800          /* freed at end of burst */
#define SF_IN_ACCEPTQ 0x1000
#define SF_CWND_LIMITED 0x2000
#define SF_WANT_WRITABLE 0x4000
#define SF_RST_ON_CLOSE 0x8000

struct cubic {
    double w_max;      /* segments */
    double w_last_max;
    double K;          /* seconds */
    double cnt_acc;    /* fractional segment accumulator */
    double w_est;      /* reno-friendly estimate (segments) */
    uint64_t epoch_ns; /* 0 = not started */
    /* HyStart (delay) */
    uint32_t round_start_seq;
    uint32_t curr_rtt_us, last_rtt_us;
    uint32_t samples;
    bool hystart_done;
};

struct utcp_sock {
    uint32_t magic;
    uint8_t state;
    uint8_t ca_state;
    uint16_t core;
    uint32_t flags;

    /* identity (network order) */
    uint32_t lip, rip;
    uint16_t lport, rport;
    uint32_t hash, bucket;
    struct utcp_sock *hnext;   /* flow table chain */
    struct tmr_node tmr;       /* wheel node; must stay first-ish (container_of) */

    /* listener / accept */
    struct utcp_sock *parent;
    struct utcp_sock *acc_head, *acc_tail, *acc_next;
    uint32_t backlog, acc_len, syn_len;

    /* timer deadlines (ns, 0 = off) */
    uint64_t t_rtx;     /* RTO / TLP / RACK reorder / SYN retransmit */
    uint8_t rtx_kind;   /* RTX_* */
    uint64_t t_delack;
    uint64_t t_persist;
    uint64_t t_tw;      /* TIME_WAIT / FIN_WAIT_2 / generic expiry */

    /* send side */
    uint32_t iss, snd_una, snd_nxt, snd_wnd, snd_wl1, snd_wl2, max_wnd;
    uint8_t snd_wscale, rcv_wscale;
    uint16_t peer_mss;
    uint16_t mss;          /* payload per segment incl. option overhead deducted */
    uint32_t ts_recent;
    uint64_t ts_recent_ns;
    uint32_t ts_offset;
    uint32_t sndbuf;
    struct utcp_buf *sq_head, *sq_tail; /* payload chunks */
    uint32_t sq_seq;       /* seq of sq_head->data[0] */
    uint32_t sq_bytes;     /* bytes queued (acked bytes removed) */
    struct utcp_buf *sq_cur; /* cursor for new-data transmit */
    uint32_t sq_cur_seq;
    struct txrec *rtx_head, *rtx_tail;
    uint32_t sacked_bytes, lost_bytes, retrans_bytes;
    uint32_t cwnd, ssthresh, prior_cwnd;
    uint32_t high_seq;     /* recovery point */
    uint32_t prr_delivered, prr_out;
    uint32_t dupacks;
    uint32_t srtt_us;      /* smoothed (not scaled) */
    uint32_t rttvar_us;
    uint32_t min_rtt_us;
    uint64_t min_rtt_ns_stamp;
    uint32_t rto_ms;
    uint8_t backoff;
    uint8_t syn_retries;
    uint16_t rtx_count;    /* consecutive RTOs */
    uint64_t rack_xmit_ns;
    uint32_t rack_end_seq;
    uint32_t rack_rtt_us;
    uint32_t reo_wnd_us;   /* reorder window multiplier (Linux reo_wnd_steps) */
    uint8_t reord_seen;
    uint32_t tlp_high_seq;
    /* spurious-recovery undo (Linux undo_marker/undo_retrans, Eifel) */
    uint32_t undo_marker;
    int32_t undo_retrans;  /* bytes retransmitted minus bytes D-SACKed */
    uint32_t prior_ssthresh;
    uint32_t retrans_ts;   /* TSval of the first retransmission */
    uint8_t undo_valid;
    uint64_t delivered;    /* bytes delivered (acked or sacked) total */
    uint64_t delivered_ns;
    uint64_t pacing_rate;  /* bytes/sec, used for TSO autosizing */
    struct cubic cubic;
    uint64_t last_send_ns;

    /* receive side */
    uint32_t irs, rcv_nxt, rcv_adv, rcv_wup, rcvbuf;
    struct utcp_buf *rq_head, *rq_tail; /* in-order payload */
    uint32_t rq_bytes;
    struct utcp_buf *ooo_head; /* sorted by seq; buf->seq = start, len = payload */
    uint32_t ooo_bytes;
    uint32_t sack_blk[4][2]; /* regular SACK blocks, most recent first */
    uint8_t nsack;
    uint8_t dsack;           /* dsack_blk pending (sent once, first) */
    uint32_t dsack_blk[2];
    uint8_t quickack;
    uint32_t rcv_unacked;  /* bytes received since last ACK */
    uint32_t rcv_mss;      /* estimate of peer's segment size */
    uint32_t fin_rseq;     /* sequence of an out-of-order FIN */
    uint8_t fin_ooo;

    /* app */
    void *user;
    uint32_t ev_pending;
    int err;
    struct utcp_sock *ev_next, *dirty_next, *free_next;

    /* counters */
    uint64_t bytes_sent, bytes_retrans, bytes_acked, bytes_received;
    uint32_t segs_out, segs_in, retrans_segs, rto_events, tlp_probes, recoveries;
    uint32_t dsacks, undos;
} ALIGNED_CL;

enum { RTX_NONE = 0, RTX_RTO, RTX_TLP, RTX_REO, RTX_SYN };

/* ---------------------------------------------------------- region */

struct arp_ent {
    _Atomic uint32_t seq; /* seqlock: odd = writing */
    uint32_t ip;
    uint8_t mac[6];
    uint8_t valid;
};
#define ARP_SLOTS 256

struct core_stats {
    struct utcp_stats s;
} ALIGNED_CL;

/* Per-core state; touched only by the owning core (except rings & stats). */
struct core_state {
    struct utcp_sock **flows; /* hash -> chain */
    uint32_t flow_mask;
    struct utcp_sock *listeners[64]; /* small open table keyed by port */
    struct wheel wheel;
    struct txrec *txrec_free;
    uint32_t ip_id;
    uint64_t rng;
    _Atomic uint32_t attached;
    struct utcp_sock *pending_mig; /* sockets awaiting adoption (via ring) */
    uint32_t tw_count;
} ALIGNED_CL;

/* Bucket owner word: low 16 bits core, bit 16 = migrating flag. */
#define BKT_CORE(w) ((w) & 0xffffu)
#define BKT_MIGRATING 0x10000u

struct utcp_region {
    uint64_t magic;
    uint32_t abi;
    struct utcp_region *self; /* address at creation: attach check */
    struct utcp_config cfg;
    uint32_t toeplitz[12][256]; /* precomputed per-byte contributions */
    _Atomic uint32_t *bucket_owner;
    _Atomic uint64_t *bucket_load;
    struct ring **rings; /* [from * ncores + to] */
    struct core_state *cores;
    struct core_stats *stats;
    struct arp_ent arp[ARP_SLOTS];
    atomic_flag arp_wlock;
    uint8_t isn_key[16];
    uint64_t boot_ns;
};

/* Message on a handoff ring: either a packet or a migrated socket. Packets are
 * passed as-is; sockets are tagged with the low bit set. */
#define RING_SOCK_TAG 1u

#define TX_BATCH 64
#define RX_BATCH 64

/* Process-local per-core handle. */
struct utcp_inst {
    struct utcp_region *r;
    struct core_state *c;
    struct utcp_stats *st;
    unsigned core;
    struct utcp_ops ops;
    void *ctx;
    uint64_t now;          /* cached now_ns for the current burst */
    struct utcp_buf *txq[TX_BATCH];
    int ntx;
    struct utcp_sock *ev_list, *dirty_list, *free_list;
    int in_burst;
    struct utcp_buf *arp_pending[64];
    int narp_pending;
    struct utcp_buf *defer_head, *defer_tail; /* packets for a bucket mid-migration */
};

/* ----------------------------------------------------------- internals */

/* core.c */
uint32_t toeplitz_hash(const struct utcp_region *r, uint32_t sip, uint32_t dip, uint16_t sp,
                       uint16_t dp);
uint64_t utcp_rand(utcp_t *t);
void tmr_arm(utcp_t *t, struct utcp_sock *s);
void sock_mark_dirty(utcp_t *t, struct utcp_sock *s);
void sock_event(utcp_t *t, struct utcp_sock *s, uint32_t ev);
void tx_enqueue(utcp_t *t, struct utcp_buf *b);
void tx_flush(utcp_t *t);
void buf_free_chain(utcp_t *t, struct utcp_buf *b); /* EXT-aware */
void chunk_unref(utcp_t *t, struct utcp_buf *c);
struct utcp_buf *buf_alloc(utcp_t *t);
void handle_burst_end(utcp_t *t);
static inline uint64_t ns_to_tick(uint64_t ns) { return ns / TICK_NS; }

/* net.c */
uint16_t csum_fold(uint32_t sum);
uint32_t csum_partial(const void *p, size_t len, uint32_t sum);
uint32_t csum_chain(const struct utcp_buf *b, uint32_t off, uint32_t sum);
uint32_t pseudo_sum(uint32_t sip, uint32_t dip, uint8_t proto, uint16_t len);
void net_input(utcp_t *t, struct utcp_buf *b, bool from_ring);
int arp_lookup(struct utcp_region *r, uint32_t ip, uint8_t mac[6]);
void arp_learn(struct utcp_region *r, uint32_t ip, const uint8_t mac[6]);
/* Fill Ethernet + IPv4 header for an outgoing TCP packet whose IP payload is
 * l4len bytes. Returns 0, or -1 if the next hop is unresolved (packet queued). */
int ip_output(utcp_t *t, struct utcp_buf *b, uint32_t dip, uint16_t l4len);

/* flow table */
struct utcp_sock *flow_lookup(utcp_t *t, uint32_t lip, uint32_t rip, uint16_t lport,
                              uint16_t rport);
void flow_insert(utcp_t *t, struct utcp_sock *s);
void flow_remove(utcp_t *t, struct utcp_sock *s);
struct utcp_sock *listener_lookup(utcp_t *t, uint16_t port);

int handoff(utcp_t *t, struct utcp_buf *b, unsigned owner);

/* tcp_in.c */
void tcp_input(utcp_t *t, struct utcp_buf *b, struct ip_hdr *ip, struct tcp_hdr *th,
               uint32_t tcp_len);
void tcp_icmp_frag_needed(utcp_t *t, struct utcp_sock *s, uint16_t mtu);

/* tcp_out.c */
void tcp_output(utcp_t *t, struct utcp_sock *s);
void tcp_send_ack(utcp_t *t, struct utcp_sock *s);
void tcp_send_syn(utcp_t *t, struct utcp_sock *s, bool synack);
void tcp_send_rst(utcp_t *t, struct utcp_sock *s);
void tcp_send_rst_reply(utcp_t *t, struct ip_hdr *ip, struct tcp_hdr *th, uint32_t tcp_len);
void tcp_timer(utcp_t *t, struct utcp_sock *s);
void tcp_rack_timeout(utcp_t *t, struct utcp_sock *s);
void tcp_finish(utcp_t *t, struct utcp_sock *s); /* -> CLOSED */
void tcp_undo_begin(struct utcp_sock *s);
void tcp_enter_time_wait(utcp_t *t, struct utcp_sock *s);
void tcp_rearm_rtx(utcp_t *t, struct utcp_sock *s);
void tcp_update_rto(struct utcp_sock *s);
uint32_t tcp_rcv_window(struct utcp_sock *s);
uint32_t tcp_inflight(const struct utcp_sock *s);
void tcp_retransmit_rec(utcp_t *t, struct utcp_sock *s, struct txrec *rec);
struct txrec *txrec_split(utcp_t *t, struct utcp_sock *s, struct txrec *rec, uint32_t at);
void txrec_free(utcp_t *t, struct txrec *rec);
uint32_t tcp_ts_now(utcp_t *t, struct utcp_sock *s);

/* tcp_cc.c */
void cc_init(utcp_t *t, struct utcp_sock *s);
void cc_on_ack(utcp_t *t, struct utcp_sock *s, uint32_t acked, uint32_t rtt_us);
uint32_t cc_ssthresh(utcp_t *t, struct utcp_sock *s);
void cc_on_rto(utcp_t *t, struct utcp_sock *s);

/* tcp_sock.c */
struct utcp_sock *sock_alloc(utcp_t *t);
void sock_destroy(utcp_t *t, struct utcp_sock *s); /* deferred free */
void sock_set_state(utcp_t *t, struct utcp_sock *s, int state);
void sock_reset(utcp_t *t, struct utcp_sock *s, int err); /* abort locally */
void sock_init_tcp(utcp_t *t, struct utcp_sock *s);
uint32_t tcp_isn(utcp_t *t, uint32_t lip, uint32_t rip, uint16_t lp, uint16_t rp);
void sock_free_now(utcp_t *t, struct utcp_sock *s);

#endif
