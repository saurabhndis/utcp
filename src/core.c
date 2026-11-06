/* Region setup, per-core dispatch, timers, handoff rings, migration. */
#include "utcp_int.h"

#include <stdio.h>

static const uint8_t sym_key[40] = {
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
    0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
};

void utcp_config_default(struct utcp_config *c)
{
    memset(c, 0, sizeof(*c));
    c->ncores = 1;
    c->nbuckets = 4096;
    c->flow_table_size = 65536;
    c->ring_size = 4096;
    c->mtu = 1500;
    c->tso_max = 65000;
    c->sndbuf = 4u << 20;
    c->rcvbuf = 4u << 20;
    c->time_wait_ms = 60000;
    c->max_time_wait = 65536;
    c->delack_ms = 40;
    c->rto_min_ms = 200;
    c->cc = UTCP_CC_CUBIC;
    c->ephemeral_lo = 32768;
    c->ephemeral_hi = 60999;
}

/* ------------------------------------------------------------- hashing */

static uint32_t key_window(const uint8_t *key, unsigned bit)
{
    /* 32 key bits starting at bit `bit` (MSB-first bit string). */
    uint64_t w = 0;
    unsigned byte = bit / 8;
    for (unsigned i = 0; i < 5; i++)
        w = (w << 8) | (byte + i < 40 ? key[byte + i] : 0);
    return (uint32_t)(w >> (8 - bit % 8));
}

static void toeplitz_init(struct utcp_region *r)
{
    for (unsigned pos = 0; pos < 12; pos++)
        for (unsigned v = 0; v < 256; v++) {
            uint32_t h = 0;
            for (unsigned k = 0; k < 8; k++)
                if (v & (0x80 >> k))
                    h ^= key_window(r->cfg.rss_key, pos * 8 + k);
            r->toeplitz[pos][v] = h;
        }
}

uint32_t toeplitz_hash(const struct utcp_region *r, uint32_t sip, uint32_t dip, uint16_t sp,
                       uint16_t dp)
{
    uint8_t in[12];
    memcpy(in, &sip, 4);
    memcpy(in + 4, &dip, 4);
    memcpy(in + 8, &sp, 2);
    memcpy(in + 10, &dp, 2);
    uint32_t h = 0;
    for (int i = 0; i < 12; i++)
        h ^= r->toeplitz[i][in[i]];
    return h;
}

uint32_t utcp_rss_hash(const struct utcp_region *r, uint32_t sip, uint32_t dip, uint16_t sport,
                       uint16_t dport)
{
    return toeplitz_hash(r, sip, dip, sport, dport);
}

const uint8_t *utcp_rss_key(const struct utcp_region *r) { return r->cfg.rss_key; }
uint32_t utcp_nbuckets(const struct utcp_region *r) { return r->cfg.nbuckets; }

int utcp_bucket_owner(const struct utcp_region *r, uint32_t b)
{
    if (b >= r->cfg.nbuckets)
        return -1;
    return (int)BKT_CORE(atomic_load_explicit(&r->bucket_owner[b], memory_order_acquire));
}

uint64_t utcp_bucket_load(const struct utcp_region *r, uint32_t b)
{
    return b < r->cfg.nbuckets ? atomic_load_explicit(&r->bucket_load[b], memory_order_relaxed)
                               : 0;
}

static inline uint32_t fmix32(uint32_t h)
{
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

uint64_t utcp_rand(utcp_t *t)
{
    if (t->ops.random)
        return t->ops.random(t->ctx);
    uint64_t x = t->c->rng;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    t->c->rng = x;
    return x * 0x2545F4914F6CDD1DULL;
}

/* ------------------------------------------------------------- region */

static void *zalloc(const struct utcp_ops *ops, void *ctx, size_t sz, size_t align)
{
    void *p = ops->mem_alloc(ctx, sz, align);
    if (p)
        memset(p, 0, sz);
    return p;
}

int utcp_region_create(const struct utcp_config *cfg_in, const struct utcp_ops *ops, void *ctx,
                       struct utcp_region **out)
{
    struct utcp_config cfg = *cfg_in;
    if (!cfg.ncores || cfg.ncores > UTCP_MAX_CORES)
        return -EINVAL;
    if (!cfg.nbuckets || (cfg.nbuckets & (cfg.nbuckets - 1)))
        return -EINVAL;
    if (!cfg.flow_table_size || (cfg.flow_table_size & (cfg.flow_table_size - 1)))
        return -EINVAL;
    if (!cfg.ring_size || (cfg.ring_size & (cfg.ring_size - 1)))
        return -EINVAL;
    if (!ops->mem_alloc || !ops->buf_alloc || !ops->buf_free || !ops->tx_burst || !ops->now_ns)
        return -EINVAL;
    static const uint8_t zero[40];
    if (!memcmp(cfg.rss_key, zero, 40))
        memcpy(cfg.rss_key, sym_key, 40);
    if (!cfg.mtu)
        cfg.mtu = 1500;
    if (!cfg.tso_max)
        cfg.tso_max = 65000;

    struct utcp_region *r = zalloc(ops, ctx, sizeof(*r), CACHELINE);
    if (!r)
        return -ENOMEM;
    r->magic = UTCP_REGION_MAGIC;
    r->abi = UTCP_ABI_VERSION;
    r->self = r;
    r->cfg = cfg;
    toeplitz_init(r);
    atomic_flag_clear(&r->arp_wlock);

    unsigned n = cfg.ncores;
    r->bucket_owner = zalloc(ops, ctx, sizeof(*r->bucket_owner) * cfg.nbuckets, CACHELINE);
    r->bucket_load = zalloc(ops, ctx, sizeof(*r->bucket_load) * cfg.nbuckets, CACHELINE);
    r->rings = zalloc(ops, ctx, sizeof(*r->rings) * n * n, CACHELINE);
    r->cores = zalloc(ops, ctx, sizeof(*r->cores) * n, CACHELINE);
    r->stats = zalloc(ops, ctx, sizeof(*r->stats) * n, CACHELINE);
    if (!r->bucket_owner || !r->bucket_load || !r->rings || !r->cores || !r->stats)
        return -ENOMEM;
    for (uint32_t b = 0; b < cfg.nbuckets; b++)
        atomic_init(&r->bucket_owner[b], b % n);
    for (unsigned i = 0; i < n * n; i++) {
        if (i / n == i % n)
            continue;
        struct ring *rg = zalloc(ops, ctx, sizeof(*rg) + sizeof(void *) * cfg.ring_size,
                                 CACHELINE);
        if (!rg)
            return -ENOMEM;
        rg->mask = cfg.ring_size - 1;
        r->rings[i] = rg;
    }
    uint64_t seed = ops->random ? ops->random(ctx) : (ops->now_ns(ctx) ^ (uintptr_t)r);
    for (unsigned i = 0; i < n; i++) {
        struct core_state *c = &r->cores[i];
        c->flows = zalloc(ops, ctx, sizeof(*c->flows) * cfg.flow_table_size, CACHELINE);
        if (!c->flows)
            return -ENOMEM;
        c->flow_mask = cfg.flow_table_size - 1;
        c->rng = (seed + 0x9E3779B97F4A7C15ULL * (i + 1)) | 1;
        for (unsigned s = 0; s < WHEEL_SLOTS; s++)
            c->wheel.slots[s].next = c->wheel.slots[s].prev = &c->wheel.slots[s];
        c->wheel.cur_tick = ns_to_tick(ops->now_ns(ctx));
        c->ip_id = (uint32_t)(c->rng >> 7);
    }
    for (int i = 0; i < 16; i++) {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        r->isn_key[i] = (uint8_t)seed;
    }
    r->boot_ns = ops->now_ns(ctx);
    *out = r;
    return 0;
}

utcp_t *utcp_attach(struct utcp_region *r, unsigned core, const struct utcp_ops *ops, void *ctx)
{
    if (!r || r->magic != UTCP_REGION_MAGIC || r->abi != UTCP_ABI_VERSION) {
        errno = EINVAL;
        return NULL;
    }
    if (r->self != r) {
        errno = EFAULT; /* region mapped at a different address */
        return NULL;
    }
    if (core >= r->cfg.ncores) {
        errno = EINVAL;
        return NULL;
    }
    utcp_t *t = ops->mem_alloc(ctx, sizeof(*t), CACHELINE);
    if (!t) {
        errno = ENOMEM;
        return NULL;
    }
    memset(t, 0, sizeof(*t));
    t->r = r;
    t->c = &r->cores[core];
    t->st = &r->stats[core].s;
    t->core = core;
    t->ops = *ops;
    t->ctx = ctx;
    t->now = ops->now_ns(ctx);
    /* Re-attach after a crash: the previous process's dirty/event lists and
     * transmit queue died with it. Clear the list-membership flags of every
     * session on this core and schedule them for output, so pending ACKs and
     * data go out and nothing stays stranded. */
    struct core_state *c = t->c;
    for (uint32_t i = 0; i <= c->flow_mask; i++)
        for (struct utcp_sock *s = c->flows[i]; s; s = s->hnext) {
            s->flags &= ~(SF_IN_DIRTY | SF_IN_EVLIST);
            if (s->ev_pending)
                sock_event(t, s, 0);
            sock_mark_dirty(t, s);
        }
    for (unsigned i = 0; i < 64; i++) {
        struct utcp_sock *l = c->listeners[i];
        if (l && l != (void *)1)
            l->flags &= ~(SF_IN_DIRTY | SF_IN_EVLIST);
    }
    atomic_store(&c->attached, 1);
    return t;
}

void utcp_foreach_sock(utcp_t *t, void (*fn)(void *arg, struct utcp_sock *s), void *arg)
{
    struct core_state *c = t->c;
    for (uint32_t i = 0; i <= c->flow_mask; i++)
        for (struct utcp_sock *s = c->flows[i], *n; s; s = n) {
            n = s->hnext;
            fn(arg, s);
        }
}

void utcp_detach(utcp_t *t)
{
    if (!t)
        return;
    tx_flush(t);
    atomic_store(&t->c->attached, 0);
    if (t->ops.mem_free)
        t->ops.mem_free(t->ctx, t);
}

struct utcp_region *utcp_region(utcp_t *t) { return t->r; }
unsigned utcp_core(utcp_t *t) { return t->core; }

void utcp_stats_get(const struct utcp_region *r, int core, struct utcp_stats *st)
{
    memset(st, 0, sizeof(*st));
    unsigned lo = core < 0 ? 0 : (unsigned)core, hi = core < 0 ? r->cfg.ncores : lo + 1;
    for (unsigned i = lo; i < hi; i++) {
        const uint64_t *src = (const uint64_t *)&r->stats[i].s;
        uint64_t *dst = (uint64_t *)st;
        for (size_t k = 0; k < sizeof(*st) / 8; k++)
            dst[k] += src[k];
    }
}

/* -------------------------------------------------------------- flows */

static inline uint32_t flow_idx(utcp_t *t, uint32_t rip, uint16_t lport, uint16_t rport)
{
    return fmix32(rip ^ ((uint32_t)lport << 16 | rport)) & t->c->flow_mask;
}

struct utcp_sock *flow_lookup(utcp_t *t, uint32_t lip, uint32_t rip, uint16_t lport,
                              uint16_t rport)
{
    struct utcp_sock *s = t->c->flows[flow_idx(t, rip, lport, rport)];
    for (; s; s = s->hnext)
        if (s->rip == rip && s->lport == lport && s->rport == rport && s->lip == lip)
            return s;
    return NULL;
}

void flow_insert(utcp_t *t, struct utcp_sock *s)
{
    struct utcp_sock **head = &t->c->flows[flow_idx(t, s->rip, s->lport, s->rport)];
    s->hnext = *head;
    *head = s;
}

void flow_remove(utcp_t *t, struct utcp_sock *s)
{
    struct utcp_sock **pp = &t->c->flows[flow_idx(t, s->rip, s->lport, s->rport)];
    for (; *pp; pp = &(*pp)->hnext)
        if (*pp == s) {
            *pp = s->hnext;
            s->hnext = NULL;
            return;
        }
}

struct utcp_sock *listener_lookup(utcp_t *t, uint16_t port)
{
    unsigned h = ntoh16(port) & 63;
    for (unsigned i = 0; i < 64; i++) {
        struct utcp_sock *s = t->c->listeners[(h + i) & 63];
        if (!s)
            return NULL;
        if (s != (void *)1 && s->lport == port)
            return s;
    }
    return NULL;
}

/* --------------------------------------------------------------- timers */

static inline struct utcp_sock *tmr_sock(struct tmr_node *n)
{
    return (struct utcp_sock *)((char *)n - offsetof(struct utcp_sock, tmr));
}

static inline void tmr_unlink(struct tmr_node *n)
{
    if (n->expire_tick) {
        n->prev->next = n->next;
        n->next->prev = n->prev;
        n->next = n->prev = NULL;
        n->expire_tick = 0;
    }
}

static inline void tmr_link(struct wheel *w, struct tmr_node *n, uint64_t tick)
{
    struct tmr_node *slot = &w->slots[tick & (WHEEL_SLOTS - 1)];
    n->expire_tick = tick;
    n->next = slot->next;
    n->prev = slot;
    slot->next->prev = n;
    slot->next = n;
}

void tmr_arm(utcp_t *t, struct utcp_sock *s)
{
    uint64_t d = UINT64_MAX;
    if (s->t_rtx)
        d = MIN(d, s->t_rtx);
    if (s->t_delack)
        d = MIN(d, s->t_delack);
    if (s->t_persist)
        d = MIN(d, s->t_persist);
    if (s->t_tw)
        d = MIN(d, s->t_tw);
    struct wheel *w = &t->c->wheel;
    if (d == UINT64_MAX) {
        tmr_unlink(&s->tmr);
        return;
    }
    uint64_t tick = (d + TICK_NS - 1) / TICK_NS;
    if (tick <= w->cur_tick)
        tick = w->cur_tick + 1;
    if (s->tmr.expire_tick == tick)
        return;
    tmr_unlink(&s->tmr);
    tmr_link(w, &s->tmr, tick);
}

static int run_timers(utcp_t *t)
{
    struct wheel *w = &t->c->wheel;
    uint64_t now_tick = ns_to_tick(t->now);
    int fired = 0;
    if (now_tick > w->cur_tick + WHEEL_SLOTS)
        w->cur_tick = now_tick - WHEEL_SLOTS;
    while (w->cur_tick < now_tick) {
        w->cur_tick++;
        struct tmr_node *slot = &w->slots[w->cur_tick & (WHEEL_SLOTS - 1)];
        if (slot->next == slot)
            continue;
        /* detach the slot list */
        struct tmr_node tmp;
        tmp.next = slot->next;
        tmp.prev = slot->prev;
        tmp.next->prev = &tmp;
        tmp.prev->next = &tmp;
        slot->next = slot->prev = slot;
        while (tmp.next != &tmp) {
            struct tmr_node *n = tmp.next;
            n->prev->next = n->next;
            n->next->prev = n->prev;
            uint64_t tick = n->expire_tick;
            n->expire_tick = 0;
            if (tick <= w->cur_tick) {
                tcp_timer(t, tmr_sock(n));
                fired++;
            } else {
                tmr_link(w, n, tick);
            }
        }
    }
    return fired;
}

uint64_t utcp_next_timer(utcp_t *t)
{
    struct wheel *w = &t->c->wheel;
    for (unsigned i = 1; i <= WHEEL_SLOTS; i++) {
        struct tmr_node *slot = &w->slots[(w->cur_tick + i) & (WHEEL_SLOTS - 1)];
        if (slot->next != slot)
            return (w->cur_tick + i) * TICK_NS;
    }
    return UINT64_MAX;
}

/* --------------------------------------------------- events, dirty, tx */

void sock_event(utcp_t *t, struct utcp_sock *s, uint32_t ev)
{
    s->ev_pending |= ev;
    if (!(s->flags & SF_IN_EVLIST)) {
        s->flags |= SF_IN_EVLIST;
        s->ev_next = t->ev_list;
        t->ev_list = s;
    }
}

void sock_mark_dirty(utcp_t *t, struct utcp_sock *s)
{
    if (!(s->flags & SF_IN_DIRTY)) {
        s->flags |= SF_IN_DIRTY;
        s->dirty_next = t->dirty_list;
        t->dirty_list = s;
    }
}

struct utcp_buf *buf_alloc(utcp_t *t)
{
    struct utcp_buf *b = t->ops.buf_alloc(t->ctx);
    if (b) {
        b->next = b->nextpkt = NULL;
        b->len = b->pkt_len = 0;
        b->flags = 0;
        b->gso_size = 0;
        b->ext = NULL;
    }
    return b;
}

void chunk_unref(utcp_t *t, struct utcp_buf *c)
{
    if (__atomic_sub_fetch(&c->refcnt, 1, __ATOMIC_ACQ_REL) == 0)
        t->ops.buf_free(t->ctx, c);
}

void buf_free_chain(utcp_t *t, struct utcp_buf *b)
{
    while (b) {
        struct utcp_buf *n = b->next;
        if (b->flags & UTCP_BUF_EXT)
            chunk_unref(t, b->ext);
        t->ops.buf_free(t->ctx, b);
        b = n;
    }
}

void utcp_pkt_free(utcp_t *t, struct utcp_buf *pkt) { buf_free_chain(t, pkt); }

void tx_flush(utcp_t *t)
{
    if (!t->ntx)
        return;
    int n = t->ntx;
    t->ntx = 0;
    t->ops.tx_burst(t->ctx, t->txq, n);
}

void tx_enqueue(utcp_t *t, struct utcp_buf *b)
{
    t->st->tx_pkts++;
    t->st->tx_bytes += b->pkt_len;
    t->txq[t->ntx++] = b;
    if (t->ntx == TX_BATCH)
        tx_flush(t);
}

static void dispatch_events(utcp_t *t)
{
    while (t->ev_list) {
        struct utcp_sock *s = t->ev_list;
        t->ev_list = s->ev_next;
        s->flags &= ~SF_IN_EVLIST;
        uint32_t ev = s->ev_pending;
        s->ev_pending = 0;
        if (!(s->flags & SF_CLOSED_BY_APP) && t->ops.on_event && ev)
            t->ops.on_event(t->ctx, s, ev);
    }
}

void handle_burst_end(utcp_t *t)
{
    for (int iter = 0; iter < 8 && (t->ev_list || t->dirty_list); iter++) {
        dispatch_events(t);
        while (t->dirty_list) {
            struct utcp_sock *s = t->dirty_list;
            t->dirty_list = s->dirty_next;
            s->flags &= ~SF_IN_DIRTY;
            if (!(s->flags & SF_DEAD))
                tcp_output(t, s);
        }
    }
    tx_flush(t);
    struct utcp_sock *keep = NULL;
    while (t->free_list) {
        struct utcp_sock *s = t->free_list;
        t->free_list = s->free_next;
        if (s->flags & (SF_IN_DIRTY | SF_IN_EVLIST)) {
            s->free_next = keep; /* still referenced; free next time */
            keep = s;
        } else {
            sock_free_now(t, s);
        }
    }
    t->free_list = keep;
}

/* ------------------------------------------------------------- datapath */

int utcp_input_burst(utcp_t *t, struct utcp_buf **pkts, int n)
{
    t->now = t->ops.now_ns(t->ctx);
    t->in_burst = 1;
    for (int i = 0; i < n; i++) {
        if (i + 1 < n)
            __builtin_prefetch(pkts[i + 1]->data);
        net_input(t, pkts[i], false);
    }
    handle_burst_end(t);
    t->in_burst = 0;
    return n;
}

static void adopt_sock(utcp_t *t, struct utcp_sock *s, int from)
{
    s->core = (uint16_t)t->core;
    s->flags &= ~(SF_IN_DIRTY | SF_IN_EVLIST);
    s->tmr.expire_tick = 0;
    flow_insert(t, s);
    if (s->parent) {
        struct utcp_sock *l = listener_lookup(t, s->lport);
        s->parent = l;
        if (l && (s->flags & SF_IN_ACCEPTQ)) {
            s->acc_next = NULL;
            if (l->acc_tail)
                l->acc_tail->acc_next = s;
            else
                l->acc_head = s;
            l->acc_tail = s;
            l->acc_len++;
            sock_event(t, l, UTCP_EV_ACCEPT);
        } else if (l) {
            l->syn_len++;
        } else {
            s->flags &= ~SF_IN_ACCEPTQ;
        }
    }
    tmr_arm(t, s);
    sock_mark_dirty(t, s);
    if (t->ops.on_migrate)
        t->ops.on_migrate(t->ctx, s, from, (int)t->core);
}

static int drain_rings(utcp_t *t)
{
    unsigned n = t->r->cfg.ncores, work = 0;
    void *msgs[RX_BATCH];
    for (unsigned from = 0; from < n; from++) {
        if (from == t->core)
            continue;
        struct ring *rg = t->r->rings[from * n + t->core];
        unsigned k;
        while ((k = ring_pop_burst(rg, msgs, RX_BATCH)) > 0) {
            for (unsigned i = 0; i < k; i++) {
                uintptr_t v = (uintptr_t)msgs[i];
                switch (v & 3) {
                case 0:
                    t->st->handoff_in++;
                    net_input(t, (struct utcp_buf *)v, true);
                    break;
                case 1:
                    adopt_sock(t, (struct utcp_sock *)(v & ~(uintptr_t)3), (int)from);
                    break;
                case 2: { /* migration of bucket complete */
                    uint32_t b = (uint32_t)(v >> 2);
                    atomic_store_explicit(&t->r->bucket_owner[b], t->core, memory_order_release);
                    struct utcp_buf *d = t->defer_head;
                    t->defer_head = t->defer_tail = NULL;
                    while (d) {
                        struct utcp_buf *nx = d->nextpkt;
                        d->nextpkt = NULL;
                        net_input(t, d, true);
                        d = nx;
                    }
                    break;
                }
                }
            }
            work += k;
        }
    }
    return (int)work;
}

static void arp_retry(utcp_t *t)
{
    int n = t->narp_pending;
    if (!n)
        return;
    t->narp_pending = 0;
    for (int i = 0; i < n; i++) {
        struct utcp_buf *b = t->arp_pending[i];
        uint32_t age_ms = (uint32_t)(t->now / 1000000ULL) - b->seq;
        struct ip_hdr *ip = (struct ip_hdr *)(b->data + ETH_HLEN);
        if (age_ms > 3000) {
            buf_free_chain(t, b);
            continue;
        }
        uint32_t nh = ip->daddr;
        if (((nh ^ t->r->cfg.local_ip) & t->r->cfg.netmask) && t->r->cfg.gateway)
            nh = t->r->cfg.gateway;
        struct eth_hdr *eh = (struct eth_hdr *)b->data;
        if (arp_lookup(t->r, nh, eh->dst) == 0) {
            tx_enqueue(t, b);
        } else {
            t->arp_pending[t->narp_pending++] = b;
        }
    }
}

int utcp_poll(utcp_t *t)
{
    t->now = t->ops.now_ns(t->ctx);
    t->in_burst = 1;
    int work = drain_rings(t);
    work += run_timers(t);
    arp_retry(t);
    handle_burst_end(t);
    t->in_burst = 0;
    return work;
}

/* Called by net_input when the packet belongs to another core. */
int handoff(utcp_t *t, struct utcp_buf *b, unsigned owner)
{
    struct ring *rg = t->r->rings[t->core * t->r->cfg.ncores + owner];
    if (ring_push(rg, b) < 0) {
        t->st->handoff_drop++;
        buf_free_chain(t, b);
        return -1;
    }
    t->st->handoff_out++;
    return 0;
}

/* ----------------------------------------------------------- migration */

int utcp_migrate_bucket(utcp_t *t, uint32_t bucket, unsigned to)
{
    struct utcp_region *r = t->r;
    if (bucket >= r->cfg.nbuckets || to >= r->cfg.ncores)
        return -EINVAL;
    uint32_t w = atomic_load_explicit(&r->bucket_owner[bucket], memory_order_acquire);
    if (BKT_CORE(w) != t->core || (w & BKT_MIGRATING))
        return -EPERM;
    if (to == t->core)
        return 0;
    t->now = t->ops.now_ns(t->ctx);
    handle_burst_end(t); /* empty dirty/event lists */
    struct ring *rg = r->rings[t->core * r->cfg.ncores + to];
    /* Need room for every socket plus the completion marker. */
    unsigned cnt = 0;
    for (uint32_t i = 0; i <= t->c->flow_mask; i++)
        for (struct utcp_sock *s = t->c->flows[i]; s; s = s->hnext)
            if (s->bucket == bucket)
                cnt++;
    uint32_t used = atomic_load(&rg->head) - atomic_load(&rg->tail);
    if (used + cnt + 1 > rg->mask + 1)
        return -EAGAIN;

    atomic_store_explicit(&r->bucket_owner[bucket], to | BKT_MIGRATING, memory_order_release);
    for (uint32_t i = 0; i <= t->c->flow_mask; i++) {
        struct utcp_sock **pp = &t->c->flows[i];
        while (*pp) {
            struct utcp_sock *s = *pp;
            if (s->bucket != bucket) {
                pp = &s->hnext;
                continue;
            }
            *pp = s->hnext;
            s->hnext = NULL;
            tmr_unlink(&s->tmr);
            if (s->parent) {
                struct utcp_sock *l = s->parent;
                if (s->flags & SF_IN_ACCEPTQ) {
                    struct utcp_sock **ap = &l->acc_head, *prev = NULL;
                    for (; *ap; prev = *ap, ap = &(*ap)->acc_next)
                        if (*ap == s) {
                            *ap = s->acc_next;
                            if (l->acc_tail == s)
                                l->acc_tail = prev;
                            l->acc_len--;
                            break;
                        }
                } else if (l->syn_len) {
                    l->syn_len--;
                }
            }
            ring_push(rg, (void *)((uintptr_t)s | 1));
        }
    }
    ring_push(rg, (void *)(((uintptr_t)bucket << 2) | 2));
    return (int)cnt;
}
