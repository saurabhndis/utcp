#include "sim.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_CAP 2048
#define HEADROOM 128

struct sim_pkt {
    struct sim_pkt *next;
    uint64_t at;
    struct utcp_buf *b;
};

uint64_t sim_rand(struct sim *s)
{
    uint64_t x = s->rng;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    s->rng = x;
    return x * 0x2545F4914F6CDD1DULL;
}

static double sim_unif(struct sim *s) { return (sim_rand(s) >> 11) * (1.0 / 9007199254740992.0); }

/* ------------------------------------------------------------- ops */

static void *op_mem_alloc(void *ctx, size_t sz, size_t align)
{
    (void)ctx;
    void *p = NULL;
    if (posix_memalign(&p, align < sizeof(void *) ? sizeof(void *) : align, sz))
        return NULL;
    return p;
}

static void op_mem_free(void *ctx, void *p)
{
    (void)ctx;
    free(p);
}

static struct utcp_buf *op_buf_alloc(void *ctx)
{
    struct sim_hctx *hc = ctx;
    uint8_t *m = malloc(sizeof(struct utcp_buf) + BUF_CAP);
    if (!m)
        return NULL;
    struct utcp_buf *b = (struct utcp_buf *)m;
    memset(b, 0, sizeof(*b));
    b->base = m + sizeof(*b);
    b->cap = BUF_CAP;
    b->data = b->base + HEADROOM;
    hc->h->bufs_out++;
    return b;
}

static void op_buf_free(void *ctx, struct utcp_buf *b)
{
    struct sim_hctx *hc = ctx;
    hc->h->bufs_out--;
    free(b);
}

static uint64_t op_now(void *ctx)
{
    struct sim_hctx *hc = ctx;
    return hc->h->sim->now;
}

static void op_event(void *ctx, struct utcp_sock *s, uint32_t ev)
{
    struct sim_hctx *hc = ctx;
    if (hc->h->sim->on_event)
        hc->h->sim->on_event(hc->h, hc->core, s, ev);
}

static void op_migrate(void *ctx, struct utcp_sock *s, int from, int to)
{
    struct sim_hctx *hc = ctx;
    (void)from;
    if (hc->h->sim->on_migrate)
        hc->h->sim->on_migrate(hc->h, (unsigned)to, s);
}

/* ---------------------------------------------------- checksum + gso */

static uint32_t sum16(const uint8_t *p, size_t n, uint32_t s)
{
    while (n > 1) {
        s += (uint32_t)p[0] << 8 | p[1];
        p += 2;
        n -= 2;
    }
    if (n)
        s += (uint32_t)p[0] << 8;
    return s;
}

static uint16_t fold(uint32_t s)
{
    while (s >> 16)
        s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

/* Linearize a chain into a fresh contiguous buffer of up to 70 KB. */
static uint8_t *linearize(const struct utcp_buf *b, uint32_t *len)
{
    uint8_t *out = malloc(b->pkt_len);
    uint32_t o = 0;
    for (; b; b = b->next) {
        memcpy(out + o, b->data, b->len);
        o += b->len;
    }
    *len = o;
    return out;
}

static void fix_tcp_csum(uint8_t *f, uint32_t len)
{
    uint8_t *ip = f + 14;
    uint32_t ihl = (ip[0] & 0xf) * 4;
    uint8_t *th = ip + ihl;
    uint32_t l4 = len - 14 - ihl;
    th[16] = th[17] = 0;
    uint32_t s = 0;
    s = sum16(ip + 12, 8, s);
    s += 6 + l4;
    s = sum16(th, l4, s);
    uint16_t c = fold(s);
    th[16] = (uint8_t)(c >> 8);
    th[17] = (uint8_t)c;
}

static void fix_ip_csum(uint8_t *f)
{
    uint8_t *ip = f + 14;
    ip[10] = ip[11] = 0;
    uint16_t c = fold(sum16(ip, (ip[0] & 0xf) * 4u, 0));
    ip[10] = (uint8_t)(c >> 8);
    ip[11] = (uint8_t)c;
}

/* Allocate a frame buffer for the receiving host (single fragment when it
 * fits, otherwise chained). */
static struct utcp_buf *make_frame(struct sim_host *dst, const uint8_t *f, uint32_t len)
{
    struct utcp_buf *head = NULL, *tail = NULL;
    uint32_t o = 0;
    while (o < len) {
        struct utcp_buf *b = op_buf_alloc(&dst->hctx[0]);
        uint32_t room = (uint32_t)(b->base + b->cap - b->data);
        uint32_t c = len - o < room ? len - o : room;
        memcpy(b->data, f + o, c);
        b->len = c;
        o += c;
        if (tail)
            tail->next = b;
        else
            head = b;
        tail = b;
    }
    head->pkt_len = len;
    if (dst->hc.rx_csum_ok)
        head->flags |= UTCP_BUF_RX_CSUM_OK;
    return head;
}

/* -------------------------------------------------------------- link */

static void free_chain(struct sim_host *h, struct utcp_buf *b)
{
    while (b) {
        struct utcp_buf *n = b->next;
        op_buf_free(&h->hctx[0], b);
        b = n;
    }
}


static void link_enqueue(struct sim *s, int dir, struct utcp_buf *frame)
{
    uint64_t ser = (uint64_t)(frame->pkt_len * 8.0 / s->link.gbps);
    uint64_t start = s->link_free_at[dir] > s->now ? s->link_free_at[dir] : s->now;
    uint64_t backlog_ns = start - s->now;
    uint64_t qlimit_ns = (uint64_t)(s->link.queue_bytes * 8.0 / s->link.gbps);
    struct sim_host *dst = &s->host[dir ^ 1];
    if (backlog_ns > qlimit_ns) {
        s->drops_queue++;
#ifdef SIM_INTERNALS
        if (getenv("DROPLOG") && dir == 0) {
            const uint8_t *th = frame->data + 34;
            printf("    drop t=%.3fms seq=%u backlog=%.1fus\n", s->now / 1e6,
                   (uint32_t)th[4] << 24 | th[5] << 16 | th[6] << 8 | th[7], backlog_ns / 1e3);
        }
#endif
        free_chain(dst, frame);
        return;
    }
    s->link_free_at[dir] = start + ser;
    if (s->link.loss > 0 && sim_unif(s) < s->link.loss) {
        s->drops_random++;
        free_chain(dst, frame);
        return;
    }
    uint64_t at = start + ser + s->link.delay_ns;
    if (s->link.reorder > 0 && sim_unif(s) < s->link.reorder) {
        at += s->link.reorder_ns;
        s->reordered++;
    }
    struct sim_pkt *p = malloc(sizeof(*p));
    p->at = at;
    p->b = frame;
    struct sim_pkt **pp = &s->q[dir];
    while (*pp && (*pp)->at <= at)
        pp = &(*pp)->next;
    p->next = *pp;
    *pp = p;
}

/* Emulates the NIC: software GSO + checksum, then puts frames on the wire. */
static int op_tx(void *ctx, struct utcp_buf **pkts, int n)
{
    struct sim_hctx *hc = ctx;
    struct sim_host *h = hc->h;
    struct sim *s = h->sim;
    int dir = h->id;
    for (int i = 0; i < n; i++) {
        struct utcp_buf *b = pkts[i];
        uint32_t len;
        uint8_t *f = linearize(b, &len);
        uint16_t flags = b->flags, gso = b->gso_size, l4hl = b->l4_hlen;
        utcp_pkt_free(h->core[hc->core], b);
        struct sim_host *dst = &s->host[dir ^ 1];
        if ((flags & UTCP_BUF_TSO) && gso) {
            uint32_t hl = 14 + 20 + l4hl;
            uint32_t pl = len - hl;
            uint8_t *th = f + 34;
            uint32_t seq0 = (uint32_t)th[4] << 24 | th[5] << 16 | th[6] << 8 | th[7];
            uint8_t fl = th[13];
            uint16_t id0 = (uint16_t)(f[18] << 8 | f[19]);
            uint8_t *seg = malloc(hl + gso);
            for (uint32_t off = 0, k = 0; off < pl; off += gso, k++) {
                uint32_t c = pl - off < gso ? pl - off : gso;
                memcpy(seg, f, hl);
                memcpy(seg + hl, f + hl + off, c);
                uint32_t tot = 20 + l4hl + c;
                seg[16] = (uint8_t)(tot >> 8);
                seg[17] = (uint8_t)tot;
                uint16_t id = (uint16_t)(id0 + k);
                seg[18] = (uint8_t)(id >> 8);
                seg[19] = (uint8_t)id;
                uint32_t sq = seq0 + off;
                uint8_t *st = seg + 34;
                st[4] = (uint8_t)(sq >> 24);
                st[5] = (uint8_t)(sq >> 16);
                st[6] = (uint8_t)(sq >> 8);
                st[7] = (uint8_t)sq;
                st[13] = off + c < pl ? (uint8_t)(fl & ~(0x01 | 0x08)) : fl;
                fix_ip_csum(seg);
                fix_tcp_csum(seg, hl + c);
                link_enqueue(s, dir, make_frame(dst, seg, hl + c));
            }
            free(seg);
        } else {
            if (flags & UTCP_BUF_TX_CSUM)
                fix_tcp_csum(f, len);
            link_enqueue(s, dir, make_frame(dst, f, len));
        }
        free(f);
    }
    return n;
}

/* --------------------------------------------------------------- setup */

static void host_init(struct sim *s, int id, const struct sim_host_cfg *hc)
{
    struct sim_host *h = &s->host[id];
    memset(h, 0, sizeof(*h));
    h->sim = s;
    h->id = id;
    h->hc = *hc;
    utcp_config_default(&h->cfg);
    h->cfg.ncores = hc->ncores ? hc->ncores : 1;
    h->cfg.local_ip = htonl(0x0a000001u + (uint32_t)id);
    h->cfg.netmask = htonl(0xffffff00u);
    uint8_t mac[6] = {0x02, 0, 0, 0, 0, (uint8_t)(id + 1)};
    memcpy(h->cfg.mac, mac, 6);
    h->cfg.flow_table_size = 4096;
    h->cfg.ring_size = 8192;
    if (hc->tso)
        h->cfg.offloads = UTCP_OFFLOAD_TSO | UTCP_OFFLOAD_TX_CSUM;
    if (hc->rcvbuf)
        h->cfg.rcvbuf = hc->rcvbuf;
    if (hc->sndbuf)
        h->cfg.sndbuf = hc->sndbuf;
    h->cfg.cc = hc->cc;
    struct utcp_ops ops = {
        .mem_alloc = op_mem_alloc,
        .mem_free = op_mem_free,
        .buf_alloc = op_buf_alloc,
        .buf_free = op_buf_free,
        .tx_burst = op_tx,
        .now_ns = op_now,
        .on_event = op_event,
        .on_migrate = op_migrate,
    };
    for (unsigned c = 0; c < h->cfg.ncores; c++) {
        h->hctx[c].h = h;
        h->hctx[c].core = c;
    }
    if (utcp_region_create(&h->cfg, &ops, &h->hctx[0], &h->region) != 0)
        abort();
    for (unsigned c = 0; c < h->cfg.ncores; c++) {
        h->core[c] = utcp_attach(h->region, c, &ops, &h->hctx[c]);
        if (!h->core[c])
            abort();
    }
}

void sim_init(struct sim *s, const struct sim_link_cfg *lc, const struct sim_host_cfg *a,
              const struct sim_host_cfg *b, uint64_t seed)
{
    memset(s, 0, sizeof(*s));
    s->rng = seed | 1;
    s->now = 1000000000ULL;
    s->link = *lc;
    host_init(s, 0, a);
    host_init(s, 1, b);
    /* static ARP both ways */
    utcp_arp_add(s->host[0].region, s->host[1].cfg.local_ip, s->host[1].cfg.mac);
    utcp_arp_add(s->host[1].region, s->host[0].cfg.local_ip, s->host[0].cfg.mac);
}

static unsigned rx_core(struct sim *s, struct sim_host *h, struct utcp_buf *b)
{
    if (h->cfg.ncores == 1)
        return 0;
    if (h->hc.spray)
        return (unsigned)(sim_rand(s) % h->cfg.ncores);
    /* emulate NIC RSS with the stack's key/bucket table */
    const uint8_t *f = b->data;
    if (b->len < 38 || f[12] != 0x08 || f[13] != 0x00)
        return 0;
    const uint8_t *ip = f + 14;
    uint32_t ihl = (ip[0] & 0xf) * 4u;
    uint32_t sip, dip;
    uint16_t sp, dp;
    memcpy(&sip, ip + 12, 4);
    memcpy(&dip, ip + 16, 4);
    memcpy(&sp, ip + ihl, 2);
    memcpy(&dp, ip + ihl + 2, 2);
    uint32_t hsh = utcp_rss_hash(h->region, sip, dip, sp, dp);
    int o = utcp_bucket_owner(h->region, hsh & (utcp_nbuckets(h->region) - 1));
    return o < 0 ? 0 : (unsigned)o;
}

bool sim_run_until(struct sim *s, uint64_t until)
{
    while (s->now < until) {
        /* deliver due packets, grouped into bursts per core */
        for (int dir = 0; dir < 2; dir++) {
            struct sim_host *dst = &s->host[dir ^ 1];
            struct utcp_buf *burst[SIM_MAX_CORES][64];
            int nb[SIM_MAX_CORES] = {0};
            while (s->q[dir] && s->q[dir]->at <= s->now) {
                struct sim_pkt *p = s->q[dir];
                s->q[dir] = p->next;
                unsigned c = rx_core(s, dst, p->b);
                burst[c][nb[c]++] = p->b;
                s->delivered_pkts++;
                free(p);
                if (nb[c] == 64) {
                    utcp_input_burst(dst->core[c], burst[c], nb[c]);
                    nb[c] = 0;
                }
            }
            for (unsigned c = 0; c < dst->cfg.ncores; c++)
                if (nb[c])
                    utcp_input_burst(dst->core[c], burst[c], nb[c]);
        }
        /* poll every core until quiescent (handoff rings) */
        for (int round = 0; round < 4; round++) {
            int work = 0;
            for (int hi = 0; hi < 2; hi++)
                for (unsigned c = 0; c < s->host[hi].cfg.ncores; c++)
                    work += utcp_poll(s->host[hi].core[c]);
            if (!work)
                break;
        }
        /* advance time to the next event */
        uint64_t next = UINT64_MAX;
        for (int dir = 0; dir < 2; dir++)
            if (s->q[dir] && s->q[dir]->at < next)
                next = s->q[dir]->at;
        for (int hi = 0; hi < 2; hi++)
            for (unsigned c = 0; c < s->host[hi].cfg.ncores; c++) {
                uint64_t tn = utcp_next_timer(s->host[hi].core[c]);
                if (tn < next)
                    next = tn;
            }
        if (next == UINT64_MAX) {
            return false;
        }
        if (next <= s->now)
            next = s->now + 1000; /* 1 us granularity */
        if (next > until) {
            s->now = until;
            break;
        }
        s->now = next;
    }
    return true;
}

void sim_destroy(struct sim *s)
{
    for (int dir = 0; dir < 2; dir++)
        while (s->q[dir]) {
            struct sim_pkt *p = s->q[dir];
            s->q[dir] = p->next;
            free_chain(&s->host[dir ^ 1], p->b);
            free(p);
        }
}
