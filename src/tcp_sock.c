/* Socket lifecycle and public socket API. */
#include "utcp_int.h"

/* ------------------------------------------------------------- SipHash */

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND                                                                              \
    do {                                                                                      \
        v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; v0 = ROTL(v0, 32);                             \
        v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2;                                                \
        v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0;                                                \
        v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; v2 = ROTL(v2, 32);                             \
    } while (0)

static uint64_t siphash24(const uint8_t key[16], const uint8_t *in, size_t len)
{
    uint64_t k0, k1;
    memcpy(&k0, key, 8);
    memcpy(&k1, key + 8, 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0, v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0, v3 = 0x7465646279746573ULL ^ k1;
    uint64_t b = (uint64_t)len << 56;
    size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        uint64_t m;
        memcpy(&m, in + i, 8);
        v3 ^= m;
        SIPROUND;
        SIPROUND;
        v0 ^= m;
    }
    for (size_t j = 0; i + j < len; j++)
        b |= (uint64_t)in[i + j] << (8 * j);
    v3 ^= b;
    SIPROUND;
    SIPROUND;
    v0 ^= b;
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

/* RFC 6528: ISN = M + F(localip, localport, remoteip, remoteport, secretkey) */
uint32_t tcp_isn(utcp_t *t, uint32_t lip, uint32_t rip, uint16_t lp, uint16_t rp)
{
    uint8_t in[12];
    memcpy(in, &lip, 4);
    memcpy(in + 4, &rip, 4);
    memcpy(in + 8, &lp, 2);
    memcpy(in + 10, &rp, 2);
    return (uint32_t)siphash24(t->r->isn_key, in, 12) + (uint32_t)(t->now >> 6);
}

/* ----------------------------------------------------------- lifecycle */

static const char *const state_names[] = {
    "CLOSED",     "LISTEN",     "SYN_SENT", "SYN_RCVD", "ESTABLISHED", "FIN_WAIT_1",
    "FIN_WAIT_2", "CLOSE_WAIT", "CLOSING",  "LAST_ACK", "TIME_WAIT",
};

const char *utcp_state_name(int st)
{
    return st >= 0 && st <= TCP_TIME_WAIT ? state_names[st] : "?";
}

struct utcp_sock *sock_alloc(utcp_t *t)
{
    struct utcp_sock *s = t->ops.mem_alloc(t->ctx, sizeof(*s), CACHELINE);
    if (!s)
        return NULL;
    memset(s, 0, sizeof(*s));
    s->magic = UTCP_SOCK_MAGIC;
    s->core = (uint16_t)t->core;
    t->st->socks_alloc++;
    return s;
}

void sock_init_tcp(utcp_t *t, struct utcp_sock *s)
{
    const struct utcp_config *cfg = &t->r->cfg;
    s->sndbuf = cfg->sndbuf;
    s->rcvbuf = cfg->rcvbuf;
    s->rto_ms = 1000;
    s->peer_mss = 536;
    s->mss = 536;
    s->rcv_mss = 536;
    s->min_rtt_us = UINT32_MAX;
    s->quickack = 16;
    /* Window scale: smallest shift that lets the window cover rcvbuf. */
    uint8_t ws = 0;
    while (ws < 14 && (65535u << ws) < s->rcvbuf)
        ws++;
    s->rcv_wscale = ws;
    s->ts_offset = (uint32_t)utcp_rand(t);
}

void sock_free_now(utcp_t *t, struct utcp_sock *s)
{
    s->magic = 0;
    t->st->socks_free++;
    if (t->ops.mem_free)
        t->ops.mem_free(t->ctx, s);
}

static void free_queues(utcp_t *t, struct utcp_sock *s, bool rx_too)
{
    for (struct utcp_buf *b = s->sq_head, *n; b; b = n) {
        n = b->nextpkt;
        chunk_unref(t, b);
    }
    s->sq_head = s->sq_tail = s->sq_cur = NULL;
    s->sq_bytes = 0;
    for (struct txrec *r = s->rtx_head, *n; r; r = n) {
        n = r->next;
        txrec_free(t, r);
    }
    s->rtx_head = s->rtx_tail = NULL;
    s->sacked_bytes = s->lost_bytes = s->retrans_bytes = 0;
    for (struct utcp_buf *b = s->ooo_head, *n; b; b = n) {
        n = b->nextpkt;
        buf_free_chain(t, b);
    }
    s->ooo_head = NULL;
    s->ooo_bytes = 0;
    if (rx_too) {
        for (struct utcp_buf *b = s->rq_head, *n; b; b = n) {
            n = b->nextpkt;
            buf_free_chain(t, b);
        }
        s->rq_head = s->rq_tail = NULL;
        s->rq_bytes = 0;
    }
}

static void tmr_cancel_all(struct utcp_sock *s)
{
    s->t_rtx = s->t_delack = s->t_persist = s->t_tw = 0;
    s->rtx_kind = RTX_NONE;
}

static void listener_remove(utcp_t *t, struct utcp_sock *l)
{
    for (unsigned i = 0; i < 64; i++)
        if (t->c->listeners[i] == l)
            t->c->listeners[i] = (void *)1; /* tombstone */
}

/* Release the socket memory at the end of the current burst. */
void sock_destroy(utcp_t *t, struct utcp_sock *s)
{
    if (s->flags & SF_DEAD)
        return;
    s->flags |= SF_DEAD;
    if (s->state == TCP_LISTEN)
        listener_remove(t, s);
    else
        flow_remove(t, s);
    tmr_cancel_all(s);
    tmr_arm(t, s); /* unlinks */
    free_queues(t, s, true);
    s->free_next = t->free_list;
    t->free_list = s;
}

void sock_set_state(utcp_t *t, struct utcp_sock *s, int st)
{
    (void)t;
    s->state = (uint8_t)st;
}

static void unlink_from_parent(struct utcp_sock *s)
{
    struct utcp_sock *l = s->parent;
    if (!l)
        return;
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
        s->flags &= ~SF_IN_ACCEPTQ;
    } else if (l->syn_len) {
        l->syn_len--;
    }
    s->parent = NULL;
}

/* Connection is finished (CLOSED). Free the socket if the app released it,
 * otherwise keep it around (with any unread data) and tell the app. */
void tcp_enter_time_wait(utcp_t *t, struct utcp_sock *s)
{
    if (t->c->tw_count >= t->r->cfg.max_time_wait) {
        /* Linux "time wait bucket table overflow": skip TIME_WAIT, but still
         * acknowledge the peer's FIN so its LAST_ACK completes. */
        t->st->tcp_tw_overflow++;
        tcp_send_ack(t, s);
        tcp_finish(t, s);
        return;
    }
    if (s->state != TCP_TIME_WAIT)
        t->c->tw_count++;
    s->state = TCP_TIME_WAIT;
    s->t_tw = t->now + (uint64_t)t->r->cfg.time_wait_ms * 1000000ULL;
    /* nothing left to send: release send-side memory early */
    s->t_rtx = s->t_persist = s->t_delack = 0;
    tmr_arm(t, s);
}

static void tcp_done(utcp_t *t, struct utcp_sock *s)
{
    if (s->state == TCP_TIME_WAIT && t->c->tw_count)
        t->c->tw_count--;
    bool app_owned = !(s->flags & SF_CLOSED_BY_APP) && !s->parent;
    if (s->parent) {
        unlink_from_parent(s);
        app_owned = false;
        s->flags |= SF_CLOSED_BY_APP; /* never handed to the app */
    }
    s->state = TCP_CLOSED;
    flow_remove(t, s);
    tmr_cancel_all(s);
    tmr_arm(t, s);
    free_queues(t, s, !app_owned);
    if (app_owned)
        sock_event(t, s, UTCP_EV_CLOSED | UTCP_EV_READABLE);
    else
        sock_destroy(t, s);
}

void sock_reset(utcp_t *t, struct utcp_sock *s, int err)
{
    s->err = err;
    if (s->state == TCP_SYN_SENT)
        t->st->tcp_attempt_fails++;
    else if (s->state == TCP_ESTABLISHED || s->state == TCP_CLOSE_WAIT)
        t->st->tcp_estab_resets++;
    sock_event(t, s, UTCP_EV_ERROR);
    tcp_done(t, s);
}

/* Exported for tcp_in/tcp_out */
void tcp_finish(utcp_t *t, struct utcp_sock *s);
void tcp_finish(utcp_t *t, struct utcp_sock *s) { tcp_done(t, s); }

/* ---------------------------------------------------------------- API */

#define SOCK_OK(s) ((s) && (s)->magic == UTCP_SOCK_MAGIC)

struct utcp_sock *utcp_listen(utcp_t *t, uint16_t port, int backlog)
{
    uint16_t p = hton16(port);
    struct utcp_sock *old = listener_lookup(t, p);
    if (old) {
        errno = EADDRINUSE;
        return NULL;
    }
    struct utcp_sock *s = sock_alloc(t);
    if (!s) {
        errno = ENOMEM;
        return NULL;
    }
    sock_init_tcp(t, s);
    s->state = TCP_LISTEN;
    s->lip = t->r->cfg.local_ip;
    s->lport = p;
    s->backlog = backlog > 0 ? (uint32_t)backlog : 128;
    unsigned h = port & 63;
    for (unsigned i = 0; i < 64; i++) {
        struct utcp_sock **slot = &t->c->listeners[(h + i) & 63];
        if (!*slot || *slot == (void *)1) {
            *slot = s;
            return s;
        }
    }
    sock_free_now(t, s);
    errno = ENOSPC;
    return NULL;
}

struct utcp_sock *utcp_accept(utcp_t *t, struct utcp_sock *l)
{
    (void)t;
    if (!SOCK_OK(l) || l->state != TCP_LISTEN || !l->acc_head) {
        errno = EAGAIN;
        return NULL;
    }
    struct utcp_sock *s = l->acc_head;
    l->acc_head = s->acc_next;
    if (!l->acc_head)
        l->acc_tail = NULL;
    l->acc_len--;
    s->acc_next = NULL;
    s->flags &= ~SF_IN_ACCEPTQ;
    s->parent = NULL;
    return s;
}

struct utcp_sock *utcp_connect(utcp_t *t, uint32_t dip, uint16_t dport)
{
    struct utcp_region *r = t->r;
    uint32_t lip = r->cfg.local_ip;
    uint16_t rp = hton16(dport);
    uint32_t lo = r->cfg.ephemeral_lo, range = r->cfg.ephemeral_hi - lo + 1;
    uint32_t start = (uint32_t)(utcp_rand(t) % range);
    for (uint32_t i = 0; i < range; i++) {
        uint16_t lp = hton16((uint16_t)(lo + (start + i) % range));
        uint32_t h = toeplitz_hash(r, dip, lip, rp, lp);
        uint32_t bkt = h & (r->cfg.nbuckets - 1);
        if (utcp_bucket_owner(r, bkt) != (int)t->core)
            continue;
        struct utcp_sock *old = flow_lookup(t, lip, dip, lp, rp);
        if (old) {
            /* Linux tcp_tw_reuse: recycle a TIME_WAIT port for an outgoing
             * connection if timestamps protect it (PAWS) and the last segment
             * from the peer is at least 1 s old. */
            if (old->state != TCP_TIME_WAIT || !(old->flags & SF_TS_OK) ||
                t->ops.now_ns(t->ctx) - old->ts_recent_ns < 1000000000ULL)
                continue;
            tcp_finish(t, old);
        }
        struct utcp_sock *s = sock_alloc(t);
        if (!s) {
            errno = ENOMEM;
            return NULL;
        }
        t->now = t->ops.now_ns(t->ctx);
        sock_init_tcp(t, s);
        s->lip = lip;
        s->rip = dip;
        s->lport = lp;
        s->rport = rp;
        s->hash = h;
        s->bucket = bkt;
        s->iss = tcp_isn(t, lip, dip, lp, rp);
        s->snd_una = s->iss;
        s->snd_nxt = s->iss;
        s->sq_seq = s->iss + 1;
        s->sq_cur_seq = s->iss + 1;
        s->state = TCP_SYN_SENT;
        flow_insert(t, s);
        cc_init(t, s);
        t->st->tcp_active_opens++;
        tcp_send_syn(t, s, false);
        if (!t->in_burst)
            tx_flush(t);
        return s;
    }
    errno = EADDRNOTAVAIL;
    return NULL;
}

ssize_t utcp_send(utcp_t *t, struct utcp_sock *s, const void *data, size_t len)
{
    if (!SOCK_OK(s)) {
        errno = EBADF;
        return -1;
    }
    if (s->err) {
        errno = s->err;
        return -1;
    }
    switch (s->state) {
    case TCP_SYN_SENT:
    case TCP_SYN_RCVD:
    case TCP_ESTABLISHED:
    case TCP_CLOSE_WAIT:
        break;
    default:
        errno = EPIPE;
        return -1;
    }
    if (s->flags & SF_FIN_QUEUED) {
        errno = EPIPE;
        return -1;
    }
    size_t space = s->sndbuf > s->sq_bytes ? s->sndbuf - s->sq_bytes : 0;
    size_t n = MIN(len, space);
    if (!n) {
        s->flags |= SF_WANT_WRITABLE;
        errno = EAGAIN;
        return -1;
    }
    const uint8_t *p = data;
    size_t left = n;
    while (left) {
        struct utcp_buf *b = s->sq_tail;
        uint32_t room = b ? utcp_buf_tailroom(b) : 0;
        if (!room) {
            b = buf_alloc(t);
            if (!b)
                break;
            b->data = b->base; /* payload-only chunk: use the whole buffer */
            b->refcnt = 1;     /* the send queue's reference */
            if (s->sq_tail)
                s->sq_tail->nextpkt = b;
            else
                s->sq_head = b;
            s->sq_tail = b;
            if (!s->sq_cur)
                s->sq_cur = b;
            room = utcp_buf_tailroom(b);
        }
        uint32_t c = (uint32_t)MIN(left, room);
        memcpy(b->data + b->len, p, c);
        b->len += c;
        p += c;
        left -= c;
        s->sq_bytes += c;
    }
    n -= left;
    if (!n) {
        errno = ENOBUFS;
        return -1;
    }
    sock_mark_dirty(t, s);
    return (ssize_t)n;
}

/* Receive-window update after the app consumed data (Linux
 * __tcp_cleanup_rbuf): ACK if the window we could advertise grew
 * substantially beyond what the peer knows. */
static void rcv_window_update(utcp_t *t, struct utcp_sock *s, uint32_t before)
{
    if (s->state < TCP_ESTABLISHED || s->state == TCP_TIME_WAIT)
        return;
    uint32_t now_win = tcp_rcv_window(s);
    uint32_t adv_left = s->rcv_adv - s->rcv_nxt;
    if (now_win > before && now_win >= adv_left + MAX(2u * s->rcv_mss, s->rcvbuf / 4)) {
        s->flags |= SF_ACK_NOW;
        sock_mark_dirty(t, s);
    }
}

static int recv_empty(const struct utcp_sock *s)
{
    if (s->flags & SF_FIN_RCVD || s->state == TCP_CLOSED)
        return 0;
    errno = s->err ? s->err : EAGAIN;
    return -1;
}

ssize_t utcp_recv(utcp_t *t, struct utcp_sock *s, void *dst, size_t len)
{
    if (!SOCK_OK(s)) {
        errno = EBADF;
        return -1;
    }
    uint8_t *p = dst;
    size_t got = 0;
    uint32_t before = tcp_rcv_window(s);
    while (got < len && s->rq_head) {
        struct utcp_buf *b = s->rq_head;
        uint32_t c = (uint32_t)MIN(len - got, b->len);
        memcpy(p + got, b->data, c);
        got += c;
        b->data += c;
        b->len -= c;
        s->rq_bytes -= c;
        if (!b->len) {
            s->rq_head = b->nextpkt;
            if (!s->rq_head)
                s->rq_tail = NULL;
            t->ops.buf_free(t->ctx, b);
        }
    }
    if (!got)
        return recv_empty(s);
    rcv_window_update(t, s, before);
    return (ssize_t)got;
}

int utcp_recv_zc(utcp_t *t, struct utcp_sock *s, struct utcp_iov *iov, int max)
{
    (void)t;
    if (!SOCK_OK(s)) {
        errno = EBADF;
        return -1;
    }
    int n = 0;
    for (struct utcp_buf *b = s->rq_head; b && n < max; b = b->nextpkt) {
        iov[n].base = b->data;
        iov[n].len = b->len;
        n++;
    }
    return n ? n : recv_empty(s);
}

void utcp_recv_consume(utcp_t *t, struct utcp_sock *s, size_t bytes)
{
    uint32_t before = tcp_rcv_window(s);
    while (bytes && s->rq_head) {
        struct utcp_buf *b = s->rq_head;
        uint32_t c = (uint32_t)MIN(bytes, b->len);
        b->data += c;
        b->len -= c;
        s->rq_bytes -= c;
        bytes -= c;
        if (!b->len) {
            s->rq_head = b->nextpkt;
            if (!s->rq_head)
                s->rq_tail = NULL;
            t->ops.buf_free(t->ctx, b);
        }
    }
    rcv_window_update(t, s, before);
}

static void queue_fin(utcp_t *t, struct utcp_sock *s)
{
    if (s->flags & SF_FIN_QUEUED)
        return;
    s->flags |= SF_FIN_QUEUED;
    if (s->state == TCP_ESTABLISHED || s->state == TCP_SYN_RCVD)
        s->state = TCP_FIN_WAIT_1;
    else if (s->state == TCP_CLOSE_WAIT)
        s->state = TCP_LAST_ACK;
    sock_mark_dirty(t, s);
}

int utcp_shutdown(utcp_t *t, struct utcp_sock *s, int how)
{
    if (!SOCK_OK(s))
        return -EBADF;
    if (!(how & UTCP_SHUT_WR))
        return 0;
    switch (s->state) {
    case TCP_SYN_SENT:
        tcp_done(t, s);
        return 0;
    case TCP_SYN_RCVD:
    case TCP_ESTABLISHED:
    case TCP_CLOSE_WAIT:
        queue_fin(t, s);
        return 0;
    default:
        return 0;
    }
}

int utcp_close(utcp_t *t, struct utcp_sock *s)
{
    if (!SOCK_OK(s) || (s->flags & SF_CLOSED_BY_APP))
        return -EBADF;
    s->flags |= SF_CLOSED_BY_APP;
    if (s->state == TCP_LISTEN) {
        /* abort queued and half-open children */
        for (uint32_t i = 0; i <= t->c->flow_mask; i++)
            for (struct utcp_sock *c = t->c->flows[i], *n; c; c = n) {
                n = c->hnext;
                if (c->parent == s) {
                    tcp_send_rst(t, c);
                    tcp_done(t, c);
                }
            }
        sock_destroy(t, s);
        return 0;
    }
    if (s->rq_bytes || (s->flags & SF_RST_ON_CLOSE)) {
        /* Unread data: abort (RFC 2525 / Linux behaviour). */
        if (s->state != TCP_CLOSED && s->state != TCP_SYN_SENT && s->state != TCP_TIME_WAIT)
            tcp_send_rst(t, s);
        if (!t->in_burst)
            tx_flush(t);
        if (s->state == TCP_CLOSED)
            sock_destroy(t, s);
        else
            tcp_done(t, s);
        return 0;
    }
    switch (s->state) {
    case TCP_CLOSED:
        sock_destroy(t, s);
        break;
    case TCP_SYN_SENT:
        tcp_done(t, s);
        break;
    case TCP_SYN_RCVD:
    case TCP_ESTABLISHED:
    case TCP_CLOSE_WAIT:
        queue_fin(t, s);
        break;
    case TCP_FIN_WAIT_2:
        /* orphaned: bound the wait for the peer's FIN (tcp_fin_timeout) */
        s->t_tw = t->now + 60000000000ULL;
        tmr_arm(t, s);
        break;
    default:
        break;
    }
    return 0;
}

int utcp_abort(utcp_t *t, struct utcp_sock *s)
{
    if (!SOCK_OK(s))
        return -EBADF;
    s->flags |= SF_RST_ON_CLOSE;
    return utcp_close(t, s);
}

int utcp_setopt(utcp_t *t, struct utcp_sock *s, int opt, int val)
{
    (void)t;
    if (!SOCK_OK(s))
        return -EBADF;
    switch (opt) {
    case UTCP_OPT_NODELAY:
        if (val)
            s->flags |= SF_NODELAY;
        else
            s->flags &= ~SF_NODELAY;
        return 0;
    case UTCP_OPT_SNDBUF:
        s->sndbuf = (uint32_t)MAX(val, 4096);
        return 0;
    case UTCP_OPT_RCVBUF:
        if (s->state != TCP_LISTEN && s->state != TCP_CLOSED)
            return -EISCONN; /* window scale already negotiated */
        s->rcvbuf = (uint32_t)MAX(val, 4096);
        s->rcv_wscale = 0;
        while (s->rcv_wscale < 14 && (65535u << s->rcv_wscale) < s->rcvbuf)
            s->rcv_wscale++;
        return 0;
    }
    return -ENOPROTOOPT;
}

void utcp_sock_set_user(struct utcp_sock *s, void *u) { s->user = u; }
void *utcp_sock_user(const struct utcp_sock *s) { return s->user; }
int utcp_sock_error(const struct utcp_sock *s) { return s->err; }
size_t utcp_sock_readable(const struct utcp_sock *s) { return s->rq_bytes; }
size_t utcp_sock_sndspace(const struct utcp_sock *s)
{
    return s->sndbuf > s->sq_bytes ? s->sndbuf - s->sq_bytes : 0;
}

int utcp_sock_info(const struct utcp_sock *s, struct utcp_info *i)
{
    if (!SOCK_OK(s))
        return -EBADF;
    memset(i, 0, sizeof(*i));
    i->state = s->state;
    i->ca_state = s->ca_state;
    i->snd_wscale = s->snd_wscale;
    i->rcv_wscale = s->rcv_wscale;
    i->mss = s->mss;
    i->cwnd = s->cwnd;
    i->ssthresh = s->ssthresh;
    i->srtt_us = s->srtt_us;
    i->rttvar_us = s->rttvar_us;
    i->min_rtt_us = s->min_rtt_us == UINT32_MAX ? 0 : s->min_rtt_us;
    i->rto_ms = s->rto_ms;
    i->snd_wnd = s->snd_wnd;
    i->rcv_wnd = s->rcv_adv - s->rcv_nxt;
    i->inflight = tcp_inflight(s);
    i->sacked = s->sacked_bytes;
    i->lost = s->lost_bytes;
    i->retrans = s->retrans_bytes;
    i->unacked = s->snd_nxt - s->snd_una;
    i->bytes_sent = s->bytes_sent;
    i->bytes_retrans = s->bytes_retrans;
    i->bytes_acked = s->bytes_acked;
    i->bytes_received = s->bytes_received;
    i->segs_out = s->segs_out;
    i->segs_in = s->segs_in;
    i->retrans_segs = s->retrans_segs;
    i->rto_events = s->rto_events;
    i->tlp_probes = s->tlp_probes;
    i->recoveries = s->recoveries;
    i->dsacks = s->dsacks;
    i->undos = s->undos;
    i->local_ip = s->lip;
    i->remote_ip = s->rip;
    i->local_port = ntoh16(s->lport);
    i->remote_port = ntoh16(s->rport);
    return 0;
}
