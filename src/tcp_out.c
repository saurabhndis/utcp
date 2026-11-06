/* TCP output: segment construction, TSO, retransmission, timers. */
#include "utcp_int.h"

#ifdef UTCP_DEBUG
#include <stdio.h>
#include <stdlib.h>
#endif

void tcp_finish(utcp_t *t, struct utcp_sock *s);
void tcp_rack_timeout(utcp_t *t, struct utcp_sock *s);
void tcp_enter_recovery_if_lost(utcp_t *t, struct utcp_sock *s);

/* ------------------------------------------------------------ txrecs */

static struct txrec *txrec_alloc(utcp_t *t)
{
    struct core_state *c = t->c;
    if (!c->txrec_free) {
        enum { CHUNK = 256 };
        struct txrec *a = t->ops.mem_alloc(t->ctx, sizeof(*a) * CHUNK, CACHELINE);
        if (!a)
            return NULL;
        for (int i = 0; i < CHUNK; i++) {
            a[i].next = c->txrec_free;
            c->txrec_free = &a[i];
        }
    }
    struct txrec *r = c->txrec_free;
    c->txrec_free = r->next;
    memset(r, 0, sizeof(*r));
    return r;
}

void txrec_free(utcp_t *t, struct txrec *r)
{
    r->next = t->c->txrec_free;
    t->c->txrec_free = r;
}

/* Split rec at sequence `at`; returns the new (upper) record. Byte counters
 * are unaffected because both halves inherit the flags. */
struct txrec *txrec_split(utcp_t *t, struct utcp_sock *s, struct txrec *rec, uint32_t at)
{
    struct txrec *n = txrec_alloc(t);
    if (!n)
        return NULL;
    *n = *rec;
    n->start = at;
    rec->end = at;
    rec->flags &= ~TR_FIN;
    n->prev = rec;
    n->next = rec->next;
    if (rec->next)
        rec->next->prev = n;
    else
        s->rtx_tail = n;
    rec->next = n;
    return n;
}

static void txrec_append(struct utcp_sock *s, struct txrec *r)
{
    r->prev = s->rtx_tail;
    r->next = NULL;
    if (s->rtx_tail)
        s->rtx_tail->next = r;
    else
        s->rtx_head = r;
    s->rtx_tail = r;
}

/* --------------------------------------------------------------- misc */

uint32_t tcp_ts_now(utcp_t *t, struct utcp_sock *s)
{
    return (uint32_t)(t->now / 1000000ULL) + s->ts_offset;
}

uint32_t tcp_inflight(const struct utcp_sock *s)
{
    uint32_t out = s->snd_nxt - s->snd_una;
    uint32_t left = s->sacked_bytes + s->lost_bytes;
    uint32_t f = out > left ? out - left : 0;
    return f + s->retrans_bytes;
}

uint32_t tcp_rcv_window(struct utcp_sock *s)
{
    uint32_t used = s->rq_bytes + s->ooo_bytes;
    return s->rcvbuf > used ? s->rcvbuf - used : 0;
}

/* Linux tcp_select_window(): never shrink the right edge, avoid silly
 * windows, respect the scale factor. Updates rcv_adv/rcv_wup. */
static uint16_t select_window(struct utcp_sock *s)
{
    uint32_t cur = seq_gt(s->rcv_adv, s->rcv_nxt) ? s->rcv_adv - s->rcv_nxt : 0;
    uint32_t free_space = tcp_rcv_window(s);
    uint32_t mss = MAX(s->rcv_mss, 536u);
    uint32_t win = free_space;
    if (free_space < s->rcvbuf / 2 && free_space < mss)
        win = 0;
    if (s->rcv_wscale)
        win &= ~((1u << s->rcv_wscale) - 1);
    if (win < cur)
        win = cur; /* do not shrink */
    uint32_t max = 65535u << s->rcv_wscale;
    if (win > max)
        win = max;
    s->rcv_adv = s->rcv_nxt + win;
    s->rcv_wup = s->rcv_nxt;
    return (uint16_t)(win >> s->rcv_wscale);
}

void tcp_update_rto(struct utcp_sock *s)
{
    /* Linux: rto = srtt + max(4*rttvar, rto_min), bounded to [rto_min, 120s] */
    uint32_t var4 = s->rttvar_us * 4;
    uint32_t rto_us = s->srtt_us + MAX(var4, 200000u);
    uint32_t ms = rto_us / 1000;
    s->rto_ms = MIN(MAX(ms, 200u), 120000u);
}

static inline uint32_t sack_count(const struct utcp_sock *s)
{
    if (!(s->flags & SF_SACK_OK))
        return 0;
    uint32_t max = (s->flags & SF_TS_OK) ? 3 : 4;
    return MIN(max, (uint32_t)s->nsack + s->dsack);
}

static inline uint32_t sack_opt_len(const struct utcp_sock *s)
{
    uint32_t n = sack_count(s);
    return n ? 4u + 8u * n : 0;
}

static inline uint32_t cur_mss(const struct utcp_sock *s)
{
    return s->mss - sack_opt_len(s);
}

/* Write options for a non-SYN segment; returns bytes (multiple of 4). */
static uint32_t write_opts(utcp_t *t, struct utcp_sock *s, uint8_t *p)
{
    uint32_t n = 0;
    if (s->flags & SF_TS_OK) {
        p[0] = TCPOPT_NOP;
        p[1] = TCPOPT_NOP;
        p[2] = TCPOPT_TS;
        p[3] = 10;
        uint32_t v = hton32(tcp_ts_now(t, s)), e = hton32(s->ts_recent);
        memcpy(p + 4, &v, 4);
        memcpy(p + 8, &e, 4);
        n = 12;
    }
    uint32_t nb = sack_count(s);
    if (nb) {
        p[n] = TCPOPT_NOP;
        p[n + 1] = TCPOPT_NOP;
        p[n + 2] = TCPOPT_SACK;
        p[n + 3] = (uint8_t)(2 + 8 * nb);
        n += 4;
        for (uint32_t i = 0, k = 0; k < nb; i++, k++) {
            const uint32_t *blk = s->dsack ? (i == 0 ? s->dsack_blk : s->sack_blk[i - 1])
                                           : s->sack_blk[i];
            uint32_t a = hton32(blk[0]), b = hton32(blk[1]);
            memcpy(p + n, &a, 4);
            memcpy(p + n + 4, &b, 4);
            n += 8;
        }
    }
    return n;
}

static void finish_csum(utcp_t *t, struct utcp_sock *s, struct utcp_buf *b, uint32_t thl,
                        uint32_t l4len)
{
    struct tcp_hdr *th = (struct tcp_hdr *)(b->data + ETH_HLEN + IP_HLEN);
    uint32_t ps = pseudo_sum(t->r->cfg.local_ip, s->rip, IPPROTO_TCP_, (uint16_t)l4len);
    b->l4_hlen = (uint16_t)thl;
    if (t->r->cfg.offloads & UTCP_OFFLOAD_TX_CSUM) {
        th->check = (uint16_t)ps; /* pseudo-header sum; device completes */
        b->flags |= UTCP_BUF_TX_CSUM;
    } else {
        th->check = 0;
        th->check = csum_fold(csum_chain(b, ETH_HLEN + IP_HLEN, ps));
    }
}

/* Locate the send-queue buffer holding `seq`. */
static struct utcp_buf *sq_find(struct utcp_sock *s, uint32_t seq, uint32_t *off)
{
    struct utcp_buf *b;
    uint32_t bseq;
    if (s->sq_cur && seq_ge(seq, s->sq_cur_seq)) {
        b = s->sq_cur;
        bseq = s->sq_cur_seq;
    } else {
        b = s->sq_head;
        bseq = s->sq_seq;
    }
#ifdef UTCP_DEBUG
    if (seq_lt(seq, s->sq_seq) || seq_gt(seq, s->sq_seq + s->sq_bytes)) {
        fprintf(stderr, "sq_find: seq %u outside [%u,%u) una=%u nxt=%u\n", seq, s->sq_seq,
                s->sq_seq + s->sq_bytes, s->snd_una, s->snd_nxt);
        abort();
    }
#endif
    while (b && seq_ge(seq, bseq + b->len)) {
        bseq += b->len;
        b = b->nextpkt;
    }
    if (b)
        *off = seq - bseq;
    return b;
}

#define ZC_MIN 1024 /* payloads above this are sent by reference */

/* Build one segment [seq, seq+len) with tcp flags `fl`. len may exceed the
 * MSS only when TSO is enabled. */
static struct utcp_buf *build_seg(utcp_t *t, struct utcp_sock *s, uint32_t seq, uint32_t len,
                                  uint8_t fl, uint32_t mss_now)
{
    struct utcp_buf *h = buf_alloc(t);
    if (!h)
        return NULL;
    struct tcp_hdr *th = (struct tcp_hdr *)(h->data + ETH_HLEN + IP_HLEN);
    uint32_t ol = write_opts(t, s, (uint8_t *)(th + 1));
    uint32_t thl = TCP_HLEN + ol;
    th->sport = s->lport;
    th->dport = s->rport;
    th->seq = hton32(seq);
    th->ack = hton32(s->rcv_nxt);
    th->doff = (uint8_t)((thl / 4) << 4);
    th->flags = fl | TH_ACK;
    th->win = hton16(select_window(s));
    th->urg = 0;
    h->len = ETH_HLEN + IP_HLEN + thl;

    /* payload */
    uint32_t off = 0, left = len;
    struct utcp_buf *sb = len ? sq_find(s, seq, &off) : NULL;
    struct utcp_buf *dst = h;
    if (len && seq_ge(seq, s->sq_cur_seq) && sb) {
        /* advance cursor for sequential new-data transmit */
        uint32_t bseq = seq - off;
        s->sq_cur = sb;
        s->sq_cur_seq = bseq;
    }
    /* Small payloads are copied behind the headers; larger ones are sent
     * zero-copy as fragments referencing the send-queue chunks. */
    bool zc = len > ZC_MIN;
    while (left && sb) {
        uint32_t c = MIN(left, sb->len - off);
        if (zc) {
            struct utcp_buf *nb = buf_alloc(t);
            if (!nb) {
                buf_free_chain(t, h);
                return NULL;
            }
            nb->flags = UTCP_BUF_EXT;
            nb->ext = sb;
            nb->data = sb->data + off;
            nb->len = c;
            __atomic_add_fetch(&sb->refcnt, 1, __ATOMIC_RELAXED);
            dst->next = nb;
            dst = nb;
        } else {
            uint32_t room = utcp_buf_tailroom(dst);
            if (!room) {
                struct utcp_buf *nb = buf_alloc(t);
                if (!nb) {
                    buf_free_chain(t, h);
                    return NULL;
                }
                nb->data = nb->base;
                dst->next = nb;
                dst = nb;
                room = utcp_buf_tailroom(dst);
            }
            c = MIN(c, room);
            memcpy(dst->data + dst->len, sb->data + off, c);
            dst->len += c;
        }
        left -= c;
        off += c;
        if (off == sb->len) {
            sb = sb->nextpkt;
            off = 0;
        }
    }
    if (left) { /* send queue shorter than expected: internal error */
        buf_free_chain(t, h);
        return NULL;
    }
    h->pkt_len = ETH_HLEN + IP_HLEN + thl + len;
    if (len > mss_now) {
        h->flags |= UTCP_BUF_TSO;
        h->gso_size = (uint16_t)mss_now;
    }
    finish_csum(t, s, h, thl, thl + len);
    s->segs_out += len > mss_now ? (len + mss_now - 1) / mss_now : 1;
    return h;
}

static void sent_ack(utcp_t *t, struct utcp_sock *s)
{
    s->flags &= ~SF_ACK_NOW;
    s->rcv_unacked = 0;
    if (s->t_delack) {
        s->t_delack = 0;
        tmr_arm(t, s);
    }
    if (s->quickack)
        s->quickack--;
    s->dsack = 0; /* a D-SACK is reported once */
}

void tcp_send_ack(utcp_t *t, struct utcp_sock *s)
{
    struct utcp_buf *b = build_seg(t, s, s->snd_nxt, 0, 0, s->mss);
    if (!b)
        return;
    sent_ack(t, s);
    ip_output(t, b, s->rip, (uint16_t)(b->pkt_len - ETH_HLEN - IP_HLEN));
}

static void send_probe0(utcp_t *t, struct utcp_sock *s)
{
    /* zero-window probe: out-of-window ACK (seq = snd_una - 1) */
    struct utcp_buf *b = build_seg(t, s, s->snd_una - 1, 0, 0, s->mss);
    if (b)
        ip_output(t, b, s->rip, (uint16_t)(b->pkt_len - ETH_HLEN - IP_HLEN));
}

void tcp_send_syn(utcp_t *t, struct utcp_sock *s, bool synack)
{
    struct utcp_buf *b = buf_alloc(t);
    if (!b)
        return;
    struct tcp_hdr *th = (struct tcp_hdr *)(b->data + ETH_HLEN + IP_HLEN);
    uint8_t *p = (uint8_t *)(th + 1);
    uint32_t n = 0;
    uint16_t mss = hton16((uint16_t)(t->r->cfg.mtu - 40));
    p[n++] = TCPOPT_MSS;
    p[n++] = 4;
    memcpy(p + n, &mss, 2);
    n += 2;
    bool sack = !synack || (s->flags & SF_SACK_OK);
    bool ts = !synack || (s->flags & SF_TS_OK);
    bool ws = !synack || (s->flags & SF_WS_OK);
    if (sack && ts) {
        p[n++] = TCPOPT_SACK_PERM;
        p[n++] = 2;
    } else if (sack) {
        p[n++] = TCPOPT_NOP;
        p[n++] = TCPOPT_NOP;
        p[n++] = TCPOPT_SACK_PERM;
        p[n++] = 2;
    }
    if (ts) {
        if (!sack) {
            p[n++] = TCPOPT_NOP;
            p[n++] = TCPOPT_NOP;
        }
        p[n++] = TCPOPT_TS;
        p[n++] = 10;
        uint32_t v = hton32(tcp_ts_now(t, s)), e = hton32(synack ? s->ts_recent : 0);
        memcpy(p + n, &v, 4);
        memcpy(p + n + 4, &e, 4);
        n += 8;
    }
    if (ws) {
        p[n++] = TCPOPT_NOP;
        p[n++] = TCPOPT_WS;
        p[n++] = 3;
        p[n++] = s->rcv_wscale;
    } else {
        s->rcv_wscale = 0;
    }
    uint32_t thl = TCP_HLEN + n;
    th->sport = s->lport;
    th->dport = s->rport;
    th->seq = hton32(s->iss);
    th->ack = synack ? hton32(s->rcv_nxt) : 0;
    th->doff = (uint8_t)((thl / 4) << 4);
    th->flags = TH_SYN | (synack ? TH_ACK : 0);
    uint32_t w = MIN(s->rcvbuf, 65535u);
    th->win = hton16((uint16_t)w);
    th->urg = 0;
    s->rcv_adv = s->rcv_nxt + w;
    b->len = b->pkt_len = ETH_HLEN + IP_HLEN + thl;
    finish_csum(t, s, b, thl, thl);
    s->snd_nxt = s->iss + 1;
    if (!s->t_rtx) {
        s->rtx_kind = RTX_SYN;
        s->t_rtx = t->now + (uint64_t)(1000u << s->syn_retries) * 1000000ULL;
        tmr_arm(t, s);
    }
    s->segs_out++;
    ip_output(t, b, s->rip, (uint16_t)thl);
}

void tcp_send_rst(utcp_t *t, struct utcp_sock *s)
{
    struct utcp_buf *b = buf_alloc(t);
    if (!b)
        return;
    struct tcp_hdr *th = (struct tcp_hdr *)(b->data + ETH_HLEN + IP_HLEN);
    th->sport = s->lport;
    th->dport = s->rport;
    th->seq = hton32(s->snd_nxt);
    th->ack = hton32(s->rcv_nxt);
    th->doff = 5 << 4;
    th->flags = TH_RST | TH_ACK;
    th->win = 0;
    th->urg = 0;
    b->len = b->pkt_len = HDRS_LEN;
    finish_csum(t, s, b, TCP_HLEN, TCP_HLEN);
    t->st->tcp_rst_sent++;
    ip_output(t, b, s->rip, TCP_HLEN);
}

void tcp_send_rst_reply(utcp_t *t, struct ip_hdr *ip, struct tcp_hdr *in, uint32_t tcp_len)
{
    if (in->flags & TH_RST)
        return;
    struct utcp_buf *b = buf_alloc(t);
    if (!b)
        return;
    struct tcp_hdr *th = (struct tcp_hdr *)(b->data + ETH_HLEN + IP_HLEN);
    uint32_t hl = (in->doff >> 4) * 4u;
    th->sport = in->dport;
    th->dport = in->sport;
    if (in->flags & TH_ACK) {
        th->seq = in->ack;
        th->ack = 0;
        th->flags = TH_RST;
    } else {
        uint32_t seglen = tcp_len - hl + !!(in->flags & TH_SYN) + !!(in->flags & TH_FIN);
        th->seq = 0;
        th->ack = hton32(ntoh32(in->seq) + seglen);
        th->flags = TH_RST | TH_ACK;
    }
    th->doff = 5 << 4;
    th->win = 0;
    th->urg = 0;
    b->len = b->pkt_len = HDRS_LEN;
    uint32_t ps = pseudo_sum(t->r->cfg.local_ip, ip->saddr, IPPROTO_TCP_, TCP_HLEN);
    th->check = 0;
    th->check = csum_fold(csum_partial(th, TCP_HLEN, ps));
    t->st->tcp_rst_sent++;
    ip_output(t, b, ip->saddr, TCP_HLEN);
}

/* ------------------------------------------------------ retransmission */

void tcp_retransmit_rec(utcp_t *t, struct utcp_sock *s, struct txrec *rec)
{
    uint32_t mss = cur_mss(s);
    bool fin = rec->flags & TR_FIN;
    uint32_t len = rec->end - rec->start - (fin ? 1 : 0);
    struct utcp_buf *b = build_seg(t, s, rec->start, len, fin ? TH_FIN : 0, mss);
    if (!b)
        return;
    sent_ack(t, s);
    if (!(rec->flags & TR_RETRANS)) {
        rec->flags |= TR_RETRANS;
        s->retrans_bytes += rec->end - rec->start;
    }
    rec->flags |= TR_EVER_RETRANS;
    if (s->undo_valid) {
        s->undo_retrans += (int32_t)len;
        if (!s->retrans_ts)
            s->retrans_ts = tcp_ts_now(t, s);
    }
    rec->xmit_ns = t->now;
    rec->xmits++;
    s->retrans_segs += len > mss ? (len + mss - 1) / mss : 1;
    t->st->tcp_retrans_segs++;
    s->bytes_retrans += len;
    if (s->ca_state == CA_RECOVERY)
        s->prr_out += rec->end - rec->start;
    ip_output(t, b, s->rip, (uint16_t)(b->pkt_len - ETH_HLEN - IP_HLEN));
}

static uint32_t tso_goal(utcp_t *t, struct utcp_sock *s, uint32_t mss)
{
    if (!(t->r->cfg.offloads & UTCP_OFFLOAD_TSO))
        return mss;
    uint32_t max = t->r->cfg.tso_max;
    if (!s->srtt_us)
        return max - max % mss;
    /* Linux tcp_tso_autosize(): ~1ms worth of the pacing rate, >= 2 MSS. */
    uint64_t rate = (uint64_t)s->cwnd * 1000000ULL / s->srtt_us;
    rate = rate * (s->cwnd < s->ssthresh ? 200 : 120) / 100;
    s->pacing_rate = rate;
    uint64_t goal = rate >> 10;
    goal = MAX(goal, 2ull * mss);
    goal = MIN(goal, (uint64_t)max);
    return (uint32_t)(goal - goal % mss);
}

void tcp_rearm_rtx(utcp_t *t, struct utcp_sock *s)
{
    if (s->snd_una == s->snd_nxt) {
        if (s->rtx_kind != RTX_SYN) {
            s->t_rtx = 0;
            s->rtx_kind = RTX_NONE;
        }
        tmr_arm(t, s);
        return;
    }
    uint64_t rto = t->now + ((uint64_t)s->rto_ms << s->backoff) * 1000000ULL;
    if (s->ca_state == CA_OPEN && (s->flags & SF_SACK_OK) && s->srtt_us && !s->tlp_high_seq &&
        !s->backoff) {
        /* RFC 8985 tail loss probe, Linux tcp_schedule_loss_probe():
         * 2*srtt + TCP_TIMEOUT_MIN (2 ms), or + TCP_RTO_MIN if only one
         * segment is outstanding (the peer may be delaying its ACK). */
        uint64_t pto = 2ull * s->srtt_us;
        pto += (s->snd_nxt - s->snd_una <= s->mss) ? 200000u : 2000u;
        uint64_t d = t->now + pto * 1000;
        if (d < rto) {
            s->rtx_kind = RTX_TLP;
            s->t_rtx = d;
            tmr_arm(t, s);
            return;
        }
    }
    s->rtx_kind = RTX_RTO;
    s->t_rtx = rto;
    tmr_arm(t, s);
}

/* ---------------------------------------------------------------- output */

static bool send_new_data(utcp_t *t, struct utcp_sock *s, bool probe)
{
    uint32_t data_end = s->sq_seq + s->sq_bytes;
    bool fin_pending = (s->flags & SF_FIN_QUEUED) && !(s->flags & SF_FIN_SENT);
    uint32_t avail = seq_gt(data_end, s->snd_nxt) ? data_end - s->snd_nxt : 0;
    if (!avail && !fin_pending)
        return false;
    uint32_t mss = cur_mss(s);
    uint32_t wnd_end = s->snd_una + s->snd_wnd;
    uint32_t wnd_left = seq_gt(wnd_end, s->snd_nxt) ? wnd_end - s->snd_nxt : 0;
    uint32_t inflight = tcp_inflight(s);
    uint32_t cwnd_left = s->cwnd > inflight ? s->cwnd - inflight : 0;
    if (probe)
        cwnd_left = MAX(cwnd_left, mss);
    if (!cwnd_left) {
        s->flags |= SF_CWND_LIMITED;
        return false;
    }
    if (!wnd_left && avail) {
        if (s->snd_una == s->snd_nxt && !s->t_persist) {
            s->t_persist = t->now + ((uint64_t)s->rto_ms << s->backoff) * 1000000ULL;
            tmr_arm(t, s);
        }
        return false;
    }
    uint32_t goal = probe ? mss : tso_goal(t, s, mss);
    uint32_t len = MIN(MIN(avail, wnd_left), MIN(cwnd_left, goal));
    if (len < avail) {
        if (len >= mss) {
            len -= len % mss;
        } else if (s->snd_nxt != s->snd_una) {
            /* sub-MSS segment forced by cwnd/window: wait for ACKs (SWS) */
            if (cwnd_left < mss)
                s->flags |= SF_CWND_LIMITED;
            if (!probe)
                return false;
        }
    } else if (len < mss && !fin_pending && !(s->flags & SF_NODELAY) &&
               s->snd_nxt != s->snd_una && !probe) {
        return false; /* Nagle */
    }
    bool fin = fin_pending && s->snd_nxt + len == data_end;
    if (!len && !fin)
        return false;
    uint8_t fl = (s->snd_nxt + len == data_end) ? TH_PSH : 0;
    if (fin)
        fl |= TH_FIN;
    struct utcp_buf *b = build_seg(t, s, s->snd_nxt, len, fl, mss);
    if (!b)
        return false;
    struct txrec *rec = txrec_alloc(t);
    if (!rec) {
        buf_free_chain(t, b);
        return false;
    }
    rec->start = s->snd_nxt;
    rec->end = s->snd_nxt + len + (fin ? 1 : 0);
    rec->xmit_ns = t->now;
    rec->xmits = 1;
    rec->flags = fin ? TR_FIN : 0;
    rec->delivered_at_send = s->delivered;
    rec->delivered_ns_at_send = s->delivered_ns ? s->delivered_ns : t->now;
    txrec_append(s, rec);
    s->snd_nxt = rec->end;
    if (fin)
        s->flags |= SF_FIN_SENT;
    s->bytes_sent += len;
    if (s->ca_state == CA_RECOVERY)
        s->prr_out += len + (fin ? 1 : 0);
    if (s->cwnd <= tcp_inflight(s))
        s->flags |= SF_CWND_LIMITED;
    s->last_send_ns = t->now;
    sent_ack(t, s);
    ip_output(t, b, s->rip, (uint16_t)(b->pkt_len - ETH_HLEN - IP_HLEN));
    return true;
}

void tcp_output(utcp_t *t, struct utcp_sock *s)
{
    switch (s->state) {
    case TCP_CLOSED:
    case TCP_LISTEN:
    case TCP_SYN_SENT:
    case TCP_SYN_RCVD:
        return;
    case TCP_TIME_WAIT:
        if (s->flags & SF_ACK_NOW)
            tcp_send_ack(t, s);
        return;
    default:
        break;
    }
    bool sent = false;
    /* 1. retransmit segments marked lost (RACK / RTO / dupack) */
    if (s->lost_bytes) {
        for (struct txrec *r = s->rtx_head; r; r = r->next) {
            if ((r->flags & (TR_LOST | TR_SACKED | TR_RETRANS)) != TR_LOST)
                continue;
            uint32_t inflight = tcp_inflight(s);
            if (inflight >= s->cwnd)
                break;
            uint32_t mss = cur_mss(s);
            uint32_t budget = s->cwnd - inflight;
            uint32_t segs = MAX(1u, budget / mss);
            uint32_t maxlen = (t->r->cfg.offloads & UTCP_OFFLOAD_TSO)
                                  ? MIN(segs * mss, t->r->cfg.tso_max - t->r->cfg.tso_max % mss)
                                  : mss;
            if (r->end - r->start > maxlen + ((r->flags & TR_FIN) ? 1 : 0))
                txrec_split(t, s, r, r->start + maxlen);
            tcp_retransmit_rec(t, s, r);
            sent = true;
        }
    }
    /* 2. new data */
    s->flags &= ~SF_CWND_LIMITED;
    int guard = 0;
    while (send_new_data(t, s, false) && ++guard < 4096)
        sent = true;
    if (sent) {
        if (!s->t_rtx || s->rtx_kind == RTX_TLP || s->rtx_kind == RTX_NONE)
            tcp_rearm_rtx(t, s);
    } else if (s->flags & SF_ACK_NOW) {
        tcp_send_ack(t, s);
    }
    /* writable notification */
    if ((s->flags & SF_WANT_WRITABLE) && utcp_sock_sndspace(s) >= s->sndbuf / 3) {
        s->flags &= ~SF_WANT_WRITABLE;
        sock_event(t, s, UTCP_EV_WRITABLE);
    }
}

/* ---------------------------------------------------------------- timers */

static void on_rto(utcp_t *t, struct utcp_sock *s)
{
    if (s->snd_una == s->snd_nxt) {
        s->t_rtx = 0;
        s->rtx_kind = RTX_NONE;
        return;
    }
    if (++s->rtx_count > 15) {
        sock_reset(t, s, ETIMEDOUT);
        return;
    }
    s->rto_events++;
    t->st->tcp_rto++;
    if (s->ca_state < CA_RECOVERY || !s->undo_valid)
        tcp_undo_begin(s);
    if (s->ca_state != CA_LOSS || s->backoff == 0) {
        s->ssthresh = cc_ssthresh(t, s);
        cc_on_rto(t, s);
    }
    s->ca_state = CA_LOSS;
    s->high_seq = s->snd_nxt;
    s->cwnd = s->mss;
    s->tlp_high_seq = 0;
    /* mark everything not SACKed as lost (Linux tcp_enter_loss) */
    s->retrans_bytes = 0;
    for (struct txrec *r = s->rtx_head; r; r = r->next) {
        r->flags &= ~TR_RETRANS;
        if (!(r->flags & (TR_SACKED | TR_LOST))) {
            r->flags |= TR_LOST;
            s->lost_bytes += r->end - r->start;
        }
    }
    if (s->backoff < 15)
        s->backoff++;
    /* retransmit the head segment */
    struct txrec *h = s->rtx_head;
    while (h && (h->flags & TR_SACKED))
        h = h->next;
    if (h) {
        uint32_t mss = cur_mss(s);
        if (h->end - h->start > mss + ((h->flags & TR_FIN) ? 1 : 0))
            txrec_split(t, s, h, h->start + mss);
        tcp_retransmit_rec(t, s, h);
    }
    s->rtx_kind = RTX_RTO;
    s->t_rtx = t->now + ((uint64_t)s->rto_ms << s->backoff) * 1000000ULL;
}

static void on_tlp(utcp_t *t, struct utcp_sock *s)
{
    s->tlp_probes++;
    t->st->tcp_tlp++;
    if (!send_new_data(t, s, true)) {
        /* retransmit the last segment (at most one MSS) */
        struct txrec *r = s->rtx_tail;
        if (r && !(r->flags & TR_SACKED)) {
            uint32_t mss = cur_mss(s);
            uint32_t len = r->end - r->start - ((r->flags & TR_FIN) ? 1 : 0);
            if (len > mss)
                r = txrec_split(t, s, r, r->end - ((r->flags & TR_FIN) ? 1 : 0) - mss);
            if (r)
                tcp_retransmit_rec(t, s, r);
        }
    }
    s->tlp_high_seq = s->snd_nxt;
    s->rtx_kind = RTX_RTO;
    s->t_rtx = t->now + ((uint64_t)s->rto_ms << s->backoff) * 1000000ULL;
}

static void on_syn_timeout(utcp_t *t, struct utcp_sock *s)
{
    unsigned max = s->state == TCP_SYN_SENT ? 6 : 5;
    if (++s->syn_retries > max) {
        if (s->state == TCP_SYN_RCVD && s->parent) {
            tcp_finish(t, s);
        } else {
            sock_reset(t, s, ETIMEDOUT);
        }
        return;
    }
    s->t_rtx = 0;
    tcp_send_syn(t, s, s->state == TCP_SYN_RCVD);
}

void tcp_timer(utcp_t *t, struct utcp_sock *s)
{
    uint64_t now = t->now;
    if (s->flags & SF_DEAD)
        return;
    if (s->t_tw && s->t_tw <= now) {
        s->t_tw = 0;
        if (s->state == TCP_TIME_WAIT || s->state == TCP_FIN_WAIT_2) {
            tcp_finish(t, s);
            return;
        }
    }
    if (s->t_rtx && s->t_rtx <= now) {
        uint8_t kind = s->rtx_kind;
        s->t_rtx = 0;
        s->rtx_kind = RTX_NONE;
        switch (kind) {
        case RTX_SYN:
            on_syn_timeout(t, s);
            break;
        case RTX_TLP:
            on_tlp(t, s);
            break;
        case RTX_REO:
            tcp_rack_timeout(t, s);
            break;
        case RTX_RTO:
            on_rto(t, s);
            break;
        }
        if (s->flags & SF_DEAD)
            return;
    }
    if (s->t_delack && s->t_delack <= now) {
        s->t_delack = 0;
        if (s->rcv_unacked || (s->flags & SF_ACK_NOW))
            tcp_send_ack(t, s);
    }
    if (s->t_persist && s->t_persist <= now) {
        s->t_persist = 0;
        if (s->snd_wnd == 0 && seq_gt(s->sq_seq + s->sq_bytes, s->snd_nxt)) {
            send_probe0(t, s);
            if (s->backoff < 15)
                s->backoff++;
            s->t_persist = now + ((uint64_t)s->rto_ms << s->backoff) * 1000000ULL;
        }
    }
    if (s->state != TCP_CLOSED)
        sock_mark_dirty(t, s);
    tmr_arm(t, s);
}
