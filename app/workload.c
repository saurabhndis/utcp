/* Workloads, identical for both backends:
 *   stream: client sends c2s bytes while server sends s2c bytes (full duplex)
 *   rr:     request/response ping-pong on persistent connections
 *   crr:    connect, one request/response, close; repeat
 * All payload is a known pattern; receivers verify it byte for byte. */
#include "app.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define HELLO_MAGIC 0x50435455u /* "UTCP" */
#define PATLEN (1u << 20)
#define CHUNK (256u << 10)

struct hello {
    uint32_t magic, wl;
    uint64_t c2s, s2c;
    uint32_t req, resp;
    uint32_t seed, pad;
};

enum { C_FREE = 0, C_CONNECTING, C_HELLO, C_ACTIVE };

struct conn {
    struct conn *next_free;
    void *h;
    int state;
    bool server, shut, eof;
    struct hello hello;
    uint32_t hello_got, hello_sent;
    uint64_t tx_off, rx_off, tx_total, rx_total;
    uint32_t tx_seed, rx_seed;
    uint32_t msg_got, out_left;
    uint32_t ntrans;
    uint64_t t_start;
};

static uint8_t patbuf[PATLEN + CHUNK];
static uint8_t scratch[CHUNK];

uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static unsigned hist_idx(uint64_t v)
{
    if (v < 16)
        return (unsigned)v;
    unsigned msb = 63u - (unsigned)__builtin_clzll(v);
    unsigned e = msb - 3, sub = (unsigned)(v >> (msb - 4)) & 15;
    unsigned i = e * 16 + sub;
    return i < HIST_BUCKETS ? i : HIST_BUCKETS - 1;
}

static uint64_t hist_val(unsigned i)
{
    if (i < 16)
        return i;
    unsigned e = i / 16, sub = i % 16, msb = e + 3;
    return (uint64_t)(16 + sub) << (msb - 4);
}

void hist_add(struct wstats *st, uint64_t ns)
{
    atomic_fetch_add_explicit(&st->hist[hist_idx(ns)], 1, memory_order_relaxed);
}

uint64_t hist_pct(const uint64_t *h, double pct)
{
    uint64_t tot = 0;
    for (unsigned i = 0; i < HIST_BUCKETS; i++)
        tot += h[i];
    if (!tot)
        return 0;
    uint64_t want = (uint64_t)(tot * pct / 100.0), acc = 0;
    for (unsigned i = 0; i < HIST_BUCKETS; i++) {
        acc += h[i];
        if (acc > want)
            return hist_val(i);
    }
    return hist_val(HIST_BUCKETS - 1);
}

/* ------------------------------------------------------------- conns */

static struct conn *conn_alloc(struct worker *w)
{
    struct conn *c = w->free_conns;
    if (!c)
        return NULL;
    w->free_conns = c->next_free;
    memset(c, 0, sizeof(*c));
    w->active++;
    return c;
}

static void conn_release(struct worker *w, struct conn *c, bool ok)
{
    if (c->h) {
        w->tp->set_user(w, c->h, NULL);
        w->tp->close(w, c->h);
        c->h = NULL;
    }
    if (ok)
        atomic_fetch_add_explicit(&w->st->conns_done, 1, memory_order_relaxed);
    c->state = C_FREE;
    c->next_free = w->free_conns;
    w->free_conns = c;
    w->active--;
}

static inline const uint8_t *pat_at(uint32_t seed, uint64_t off)
{
    return patbuf + (uint32_t)((off + seed) & (PATLEN - 1));
}

static void verify(struct worker *w, struct conn *c, const uint8_t *p, size_t n)
{
    if (!w->o->verify)
        return;
    size_t done = 0;
    while (done < n) {
        uint32_t po = (uint32_t)((c->rx_off + done + c->rx_seed) & (PATLEN - 1));
        size_t k = MIN_U64(n - done, PATLEN + CHUNK - po);
        if (memcmp(p + done, patbuf + po, k)) {
            atomic_fetch_add_explicit(&w->st->verify_errors, 1, memory_order_relaxed);
            return;
        }
        done += k;
    }
}

static void client_open(struct worker *w);

/* Send as much as allowed; returns false if the connection was released. */
static bool pump_tx(struct worker *w, struct conn *c)
{
    const struct transport *tp = w->tp;
    if (!c->server && c->hello_sent < sizeof(c->hello)) {
        ssize_t r = tp->send(w, c->h, (uint8_t *)&c->hello + c->hello_sent,
                             sizeof(c->hello) - c->hello_sent);
        if (r < 0)
            return true;
        c->hello_sent += (uint32_t)r;
        if (c->hello_sent < sizeof(c->hello))
            return true;
    }
    uint32_t wl = c->server ? c->hello.wl : (uint32_t)w->o->wl;
    if (wl == WL_STREAM) {
        while (c->tx_off < c->tx_total) {
            size_t n = MIN_U64(c->tx_total - c->tx_off, CHUNK);
            ssize_t r = tp->send(w, c->h, pat_at(c->tx_seed, c->tx_off), n);
            if (r <= 0)
                return true;
            c->tx_off += (uint64_t)r;
            atomic_fetch_add_explicit(&w->st->bytes_tx, (uint64_t)r, memory_order_relaxed);
        }
        if (!c->shut) {
            tp->shutdown_wr(w, c->h);
            c->shut = true;
        }
        return true;
    }
    while (c->out_left) {
        ssize_t r = tp->send(w, c->h, patbuf, c->out_left);
        if (r <= 0)
            return true;
        c->out_left -= (uint32_t)r;
        atomic_fetch_add_explicit(&w->st->bytes_tx, (uint64_t)r, memory_order_relaxed);
    }
    return true;
}

static void stream_maybe_done(struct worker *w, struct conn *c)
{
    if (c->shut && c->eof && c->rx_off == c->rx_total)
        conn_release(w, c, true);
}

void wl_on_accept(struct worker *w, void *h)
{
    struct conn *c = conn_alloc(w);
    if (!c) {
        w->tp->close(w, h);
        return;
    }
    c->h = h;
    c->server = true;
    c->state = C_HELLO;
    w->tp->set_user(w, h, c);
    atomic_fetch_add_explicit(&w->st->conns_opened, 1, memory_order_relaxed);
    wl_on_readable(w, c);
}

void wl_on_connected(struct worker *w, void *user)
{
    struct conn *c = user;
    c->state = C_ACTIVE;
    if (w->o->wl == WL_RR)
        c->t_start = now_ns();
    c->out_left = w->o->wl == WL_STREAM ? 0 : w->o->req;
    pump_tx(w, c);
}

void wl_on_writable(struct worker *w, void *user)
{
    struct conn *c = user;
    if (c->state == C_CONNECTING || c->state == C_HELLO)
        return; /* server: nothing to send before the client's hello */
    pump_tx(w, c);
}

void wl_on_closed(struct worker *w, void *user, int err)
{
    struct conn *c = user;
    bool server = c->server;
    if (err || (c->state != C_FREE && !(c->eof && c->shut))) {
        if (!server || err)
            atomic_fetch_add_explicit(&w->st->conn_errors, 1, memory_order_relaxed);
    }
    conn_release(w, c, false);
    if (!server && w->o->wl != WL_STREAM && !w->stopping)
        client_open(w);
}

static void server_hello(struct worker *w, struct conn *c)
{
    struct hello *h = &c->hello;
    c->state = C_ACTIVE;
    c->rx_total = h->c2s;
    c->tx_total = h->s2c;
    c->rx_seed = h->seed;
    c->tx_seed = h->seed ^ 0x9e37u;
    if (h->wl == WL_STREAM)
        pump_tx(w, c);
}

enum { P_CONT, P_DONE, P_DEAD }; /* P_DONE: release (ok) after consuming input */

/* Handle n received bytes; never releases the connection itself. */
static int process(struct worker *w, struct conn *c, const uint8_t *p, size_t n)
{
    atomic_fetch_add_explicit(&w->st->bytes_rx, (uint64_t)n, memory_order_relaxed);
    if (c->server && c->state == C_HELLO) {
        size_t k = MIN_U64(n, sizeof(c->hello) - c->hello_got);
        memcpy((uint8_t *)&c->hello + c->hello_got, p, k);
        c->hello_got += (uint32_t)k;
        p += k;
        n -= k;
        if (c->hello_got < sizeof(c->hello))
            return P_CONT;
        if (c->hello.magic != HELLO_MAGIC) {
            atomic_fetch_add_explicit(&w->st->verify_errors, 1, memory_order_relaxed);
            return P_DEAD;
        }
        server_hello(w, c);
    }
    uint32_t wl = c->server ? c->hello.wl : (uint32_t)w->o->wl;
    if (wl == WL_STREAM) {
        verify(w, c, p, n);
        c->rx_off += n;
        return P_CONT;
    }
    uint32_t want = c->server ? c->hello.req : w->o->resp;
    while (n) {
        uint32_t k = MIN_U32(n, want - c->msg_got);
        c->msg_got += k;
        n -= k;
        if (c->msg_got < want)
            break;
        c->msg_got = 0;
        if (c->server) {
            c->out_left += c->hello.resp;
            pump_tx(w, c);
            continue;
        }
        uint64_t t = now_ns();
        hist_add(w->st, t - c->t_start);
        atomic_fetch_add_explicit(&w->st->transactions, 1, memory_order_relaxed);
        if (w->o->wl == WL_CRR || w->stopping ||
            (w->o->trans && ++c->ntrans >= w->o->trans))
            return P_DONE;
        c->t_start = t;
        c->out_left = w->o->req;
        pump_tx(w, c);
    }
    return P_CONT;
}

static void on_eof(struct worker *w, struct conn *c)
{
    c->eof = true;
    uint32_t wl = c->server ? c->hello.wl : (uint32_t)w->o->wl;
    if (wl == WL_STREAM)
        stream_maybe_done(w, c);
    else if (c->server)
        conn_release(w, c, true);
    else
        wl_on_closed(w, c, ECONNRESET);
}

static void finish(struct worker *w, struct conn *c, int st)
{
    if (st == P_DEAD) {
        conn_release(w, c, false);
    } else if (st == P_DONE) {
        conn_release(w, c, true);
        if (w->o->wl == WL_CRR && !w->stopping)
            client_open(w);
    }
}

void wl_on_readable(struct worker *w, void *user)
{
    struct conn *c = user;
    const struct transport *tp = w->tp;
    int st = P_CONT;
    for (;;) {
        if (tp->recv_zc) {
            struct utcp_iov iov[16];
            int k = tp->recv_zc(w, c->h, iov, 16);
            if (k == 0)
                break;
            if (k < 0)
                goto err;
            size_t tot = 0;
            for (int i = 0; i < k && st == P_CONT; i++) {
                st = process(w, c, iov[i].base, iov[i].len);
                tot += iov[i].len;
            }
            if (st != P_CONT) {
                size_t all = 0;
                for (int i = 0; i < k; i++)
                    all += iov[i].len;
                tp->consume(w, c->h, all);
                finish(w, c, st);
                return;
            }
            tp->consume(w, c->h, tot);
            continue;
        }
        ssize_t r = tp->recv(w, c->h, scratch, sizeof(scratch));
        if (r == 0)
            break;
        if (r < 0)
            goto err;
        st = process(w, c, scratch, (size_t)r);
        if (st != P_CONT) {
            finish(w, c, st);
            return;
        }
    }
    on_eof(w, c);
    return;
err:
    if (errno == EAGAIN || errno == EWOULDBLOCK)
        return;
    wl_on_closed(w, c, errno);
}

/* ------------------------------------------------------------- client */

static uint32_t seed_ctr;

static void client_open(struct worker *w)
{
    struct conn *c = conn_alloc(w);
    if (!c)
        return;
    c->state = C_CONNECTING;
    c->t_start = now_ns();
    c->h = w->tp->connect(w, w->o->peer_ip, w->o->port);
    if (!c->h && (errno == EADDRNOTAVAIL || errno == EAGAIN || errno == EMFILE)) {
        w->retry_opens++; /* local resources exhausted for now: try again later */
        c->state = C_FREE;
        c->next_free = w->free_conns;
        w->free_conns = c;
        w->active--;
        return;
    }
    if (!c->h) {
        atomic_fetch_add_explicit(&w->st->conn_errors, 1, memory_order_relaxed);
        c->state = C_FREE;
        c->next_free = w->free_conns;
        w->free_conns = c;
        w->active--;
        return;
    }
    atomic_fetch_add_explicit(&w->st->conns_opened, 1, memory_order_relaxed);
    w->tp->set_user(w, c->h, c);
    struct opts *o = w->o;
    c->hello = (struct hello){.magic = HELLO_MAGIC, .wl = (uint32_t)o->wl, .c2s = o->c2s,
                              .s2c = o->s2c, .req = o->req, .resp = o->resp,
                              .seed = (uint32_t)(w->id * 7919u + ++seed_ctr * 104729u)};
    if (o->wl != WL_STREAM) {
        c->hello.c2s = c->hello.s2c = 0;
    }
    c->tx_total = c->hello.c2s;
    c->rx_total = c->hello.s2c;
    c->tx_seed = c->hello.seed;
    c->rx_seed = c->hello.seed ^ 0x9e37u;
}

size_t wl_conn_size(void) { return sizeof(struct conn); }

int wl_start(struct worker *w)
{
    uint64_t x = 0x9E3779B97F4A7C15ULL;
    for (size_t i = 0; i < sizeof(patbuf); i++) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        patbuf[i] = (uint8_t)(x >> 24);
    }
    /* make the tail a copy of the head so pat_at() reads are contiguous */
    memcpy(patbuf + PATLEN, patbuf, CHUNK);
    int maxc = w->sh->wconns_n;
    w->conns = w->sh->wconns[w->id];
    w->nconns_max = maxc;
    bool restart = atomic_load(&w->st->restarts) > 0;
    /* After a restart the table (shared memory) still describes live
     * connections; rebuild only the process-local free list. */
    w->active = 0;
    for (int i = maxc - 1; i >= 0; i--) {
        if (restart && w->conns[i].state != C_FREE) {
            w->active++;
            continue;
        }
        memset(&w->conns[i], 0, sizeof(w->conns[i]));
        w->conns[i].next_free = w->free_conns;
        w->free_conns = &w->conns[i];
    }
    if (restart)
        fprintf(stderr, "worker %d restarted: %d live connections recovered\n", w->id, w->active);
    if (w->o->role == ROLE_SERVER) {
        int r = w->tp->listen(w, w->o->port);
        return (r && restart && errno == EADDRINUSE) ? 0 : r; /* listener survived */
    }
    w->stop_at = now_ns() + (uint64_t)(w->o->duration * 1e9);
    for (int i = 0; i < w->o->conns; i++)
        client_open(w);
    return 0;
}

void wl_tick(struct worker *w)
{
    if (w->o->role != ROLE_CLIENT || w->stopping)
        return;
    for (int n = w->retry_opens; n > 0 && w->retry_opens; n--) {
        w->retry_opens--;
        client_open(w);
    }
    if (now_ns() >= w->stop_at) {
        w->stopping = true;
        if (w->o->wl == WL_STREAM || w->o->trans) /* hard deadline: abort what is left */
            for (int i = 0; i < w->nconns_max; i++)
                if (w->conns[i].state != C_FREE) {
                    atomic_fetch_add_explicit(&w->st->conn_errors, 1, memory_order_relaxed);
                    conn_release(w, &w->conns[i], false);
                }
    }
}

void wl_dump(struct worker *w)
{
    fprintf(stderr, "worker %d: active %d stopping %d\n", w->id, w->active, w->stopping);
    if (w->o->backend == BE_UTCP)
        utcp_backend_census(w);
    for (int i = 0; i < w->nconns_max; i++) {
        struct conn *c = &w->conns[i];
        if (c->state == C_FREE)
            continue;
        fprintf(stderr, "  conn %d st=%d srv=%d tx %llu/%llu rx %llu/%llu shut=%d eof=%d hello=%u/%u\n",
                i, c->state, c->server, (unsigned long long)c->tx_off,
                (unsigned long long)c->tx_total, (unsigned long long)c->rx_off,
                (unsigned long long)c->rx_total, c->shut, c->eof, c->hello_sent, c->hello_got);
        if (w->o->backend == BE_UTCP)
            utcp_backend_dump(w, c->h);
    }
}

bool wl_done(struct worker *w)
{
    if (w->o->role != ROLE_CLIENT)
        return false;
    if (w->o->wl == WL_STREAM || (w->o->wl == WL_RR && w->o->trans))
        return w->active == 0;
    return w->stopping && w->active == 0;  /* pending retries are dropped at stop */
}
