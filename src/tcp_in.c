/* TCP input: connection setup, ACK/SACK processing, RACK-TLP loss detection,
 * PRR, receive reassembly, FIN handling. */
#include "utcp_int.h"

#ifdef UTCP_DEBUG
#include <stdio.h>
#include <stdlib.h>
#endif

void tcp_finish(utcp_t *t, struct utcp_sock *s);
void tcp_rack_timeout(utcp_t *t, struct utcp_sock *s);

struct tcp_opts {
    uint16_t mss;
    int16_t ws; /* -1 = absent */
    bool sack_perm;
    bool ts;
    uint32_t tsval, tsecr;
    uint8_t nsack;
    uint32_t sack[4][2];
};

static void parse_opts(const uint8_t *p, uint32_t len, struct tcp_opts *o, bool syn)
{
    memset(o, 0, sizeof(*o));
    o->ws = -1;
    uint32_t i = 0;
    while (i < len) {
        uint8_t k = p[i];
        if (k == TCPOPT_EOL)
            break;
        if (k == TCPOPT_NOP) {
            i++;
            continue;
        }
        if (i + 1 >= len)
            break;
        uint8_t l = p[i + 1];
        if (l < 2 || i + l > len)
            break;
        switch (k) {
        case TCPOPT_MSS:
            if (syn && l == 4) {
                uint16_t v;
                memcpy(&v, p + i + 2, 2);
                o->mss = ntoh16(v);
            }
            break;
        case TCPOPT_WS:
            if (syn && l == 3)
                o->ws = MIN(p[i + 2], 14);
            break;
        case TCPOPT_SACK_PERM:
            if (syn && l == 2)
                o->sack_perm = true;
            break;
        case TCPOPT_TS:
            if (l == 10) {
                uint32_t a, b;
                memcpy(&a, p + i + 2, 4);
                memcpy(&b, p + i + 6, 4);
                o->ts = true;
                o->tsval = ntoh32(a);
                o->tsecr = ntoh32(b);
            }
            break;
        case TCPOPT_SACK:
            if (!syn && (l - 2) % 8 == 0) {
                uint32_t n = MIN((uint32_t)(l - 2) / 8, 4u);
                for (uint32_t j = 0; j < n; j++) {
                    uint32_t a, b;
                    memcpy(&a, p + i + 2 + 8 * j, 4);
                    memcpy(&b, p + i + 6 + 8 * j, 4);
                    o->sack[j][0] = ntoh32(a);
                    o->sack[j][1] = ntoh32(b);
                }
                o->nsack = (uint8_t)n;
            }
            break;
        }
        i += l;
    }
}

static void setup_mss(utcp_t *t, struct utcp_sock *s)
{
    uint32_t m = MIN((uint32_t)s->peer_mss, (uint32_t)t->r->cfg.mtu - 40u);
    if (s->flags & SF_TS_OK)
        m -= 12;
    s->mss = (uint16_t)MAX(m, 64u);
    s->cwnd = 10u * s->mss; /* IW10 (RFC 6928) */
    s->ssthresh = UINT32_MAX;
}

static void apply_syn_opts(struct utcp_sock *s, const struct tcp_opts *o, bool we_offered_all)
{
    s->peer_mss = o->mss ? o->mss : 536;
    if (o->ts && we_offered_all) {
        s->flags |= SF_TS_OK;
        s->ts_recent = o->tsval;
    }
    if (o->sack_perm && we_offered_all)
        s->flags |= SF_SACK_OK;
    if (o->ws >= 0 && we_offered_all) {
        s->flags |= SF_WS_OK;
        s->snd_wscale = (uint8_t)o->ws;
    } else {
        s->snd_wscale = 0;
        s->rcv_wscale = 0;
    }
}

/* ------------------------------------------------------------- RTT/RACK */

static void rtt_sample(utcp_t *t, struct utcp_sock *s, uint32_t rtt_us)
{
    if (!rtt_us)
        rtt_us = 1;
    if (!s->srtt_us) {
        s->srtt_us = rtt_us;
        s->rttvar_us = rtt_us / 2;
    } else {
        uint32_t d = rtt_us > s->srtt_us ? rtt_us - s->srtt_us : s->srtt_us - rtt_us;
        s->rttvar_us = (3 * s->rttvar_us + d) / 4;
        s->srtt_us = (7 * (uint64_t)s->srtt_us + rtt_us) / 8;
    }
    if (rtt_us < s->min_rtt_us || t->now - s->min_rtt_ns_stamp > 10000000000ULL) {
        s->min_rtt_us = rtt_us;
        s->min_rtt_ns_stamp = t->now;
    }
    tcp_update_rto(s);
}

static void rack_update(utcp_t *t, struct utcp_sock *s, struct txrec *r)
{
    uint64_t rtt_ns = t->now - r->xmit_ns;
    if ((r->flags & TR_EVER_RETRANS) && s->min_rtt_us != UINT32_MAX &&
        rtt_ns < (uint64_t)s->min_rtt_us * 1000)
        return; /* ambiguous: ACK of the original transmission */
    if (r->xmit_ns > s->rack_xmit_ns ||
        (r->xmit_ns == s->rack_xmit_ns && seq_gt(r->end, s->rack_end_seq))) {
        s->rack_xmit_ns = r->xmit_ns;
        s->rack_end_seq = r->end;
        s->rack_rtt_us = (uint32_t)(rtt_ns / 1000);
    }
}

static void mark_lost(struct utcp_sock *s, struct txrec *r)
{
    if (r->flags & TR_RETRANS) {
        r->flags &= ~TR_RETRANS;
        s->retrans_bytes -= r->end - r->start;
    }
    if (!(r->flags & TR_LOST)) {
        r->flags |= TR_LOST;
        s->lost_bytes += r->end - r->start;
    }
}

/* RFC 8985 RACK_detect_loss(); returns the minimum reorder timeout (ns) for
 * segments not yet deemed lost, or 0. */
static uint64_t rack_detect(utcp_t *t, struct utcp_sock *s)
{
    if (!s->rack_xmit_ns)
        return 0;
    uint32_t reo = s->min_rtt_us == UINT32_MAX ? 0 : s->min_rtt_us / 4;
    if (s->reo_wnd_us)
        reo = MIN(reo * s->reo_wnd_us, s->srtt_us);
    if (!s->reord_seen && (s->ca_state >= CA_RECOVERY || s->sacked_bytes >= 3u * s->mss))
        reo = 0;
    uint64_t min_left = 0;
    for (struct txrec *r = s->rtx_head; r; r = r->next) {
        if (r->flags & TR_SACKED)
            continue;
        if ((r->flags & TR_LOST) && !(r->flags & TR_RETRANS))
            continue;
        bool sent_before = s->rack_xmit_ns > r->xmit_ns ||
                           (s->rack_xmit_ns == r->xmit_ns && seq_gt(s->rack_end_seq, r->end));
        if (!sent_before) {
            if (!(r->flags & TR_EVER_RETRANS) && seq_ge(r->start, s->rack_end_seq))
                break;
            continue;
        }
        uint64_t deadline = r->xmit_ns + ((uint64_t)s->rack_rtt_us + reo) * 1000;
        if (deadline <= t->now) {
            mark_lost(s, r);
        } else {
            uint64_t left = deadline - t->now;
            if (!min_left || left < min_left)
                min_left = left;
        }
    }
    return min_left;
}

void tcp_undo_begin(struct utcp_sock *s)
{
    s->undo_marker = s->snd_una;
    s->undo_retrans = 0;
    s->retrans_ts = 0;
    s->prior_cwnd = s->cwnd;
    /* Linux tcp_current_ssthresh() */
    s->prior_ssthresh = s->ssthresh == UINT32_MAX ? UINT32_MAX : MAX(s->ssthresh, s->cwnd / 4 * 3);
    s->undo_valid = 1;
}

/* Undo a congestion reduction that turned out to be spurious: every
 * retransmission was D-SACKed, or (Eifel, RFC 3522) the ACK echoes a
 * timestamp older than our first retransmission. */
static bool try_undo(struct utcp_sock *s, const struct tcp_opts *o, uint32_t acked)
{
    if (!s->undo_valid || s->ca_state < CA_RECOVERY || !s->retrans_ts)
        return false;
    bool spurious = s->undo_retrans <= 0;
    if (!spurious && acked && (s->flags & SF_TS_OK) && o->ts && o->tsecr &&
        (int32_t)(o->tsecr - s->retrans_ts) < 0)
        spurious = true;
    if (!spurious)
        return false;
    s->cwnd = MAX(s->cwnd, s->prior_cwnd);
    if (s->prior_ssthresh == UINT32_MAX || s->prior_ssthresh > s->ssthresh)
        s->ssthresh = s->prior_ssthresh;
    for (struct txrec *r = s->rtx_head; r; r = r->next)
        r->flags &= ~TR_LOST;
    s->lost_bytes = 0;
    s->ca_state = s->sacked_bytes ? CA_DISORDER : CA_OPEN;
    s->undo_valid = 0;
    s->reord_seen = 1;
    if (s->reo_wnd_us < 16)
        s->reo_wnd_us = s->reo_wnd_us ? s->reo_wnd_us + 1 : 2;
    s->undos++;
    return true;
}

static void enter_recovery(utcp_t *t, struct utcp_sock *s)
{
    tcp_undo_begin(s);
    s->ca_state = CA_RECOVERY;
    s->high_seq = s->snd_nxt;
    s->prior_cwnd = s->cwnd;
    s->ssthresh = cc_ssthresh(t, s);
    s->prr_delivered = 0;
    s->prr_out = 0;
    s->recoveries++;
    t->st->tcp_recoveries++;
}

static void prr_update(struct utcp_sock *s, uint32_t delivered, bool newly_lost)
{
    s->prr_delivered += delivered;
    uint32_t pipe = tcp_inflight(s);
    int64_t sndcnt;
    if (pipe > s->ssthresh) {
        uint64_t prior = MAX(s->prior_cwnd, 1u);
        sndcnt = (int64_t)(((uint64_t)s->prr_delivered * s->ssthresh + prior - 1) / prior) -
                 (int64_t)s->prr_out;
    } else {
        int64_t lim = MAX((int64_t)s->prr_delivered - (int64_t)s->prr_out, (int64_t)delivered);
        lim += s->mss;
        sndcnt = MIN((int64_t)s->ssthresh - (int64_t)pipe, lim);
    }
    /* RFC 6937bis: always allow the fast retransmit when loss is new */
    if (newly_lost && sndcnt < (int64_t)s->mss && !s->prr_out)
        sndcnt = s->mss;
    if (sndcnt < 0)
        sndcnt = 0;
    s->cwnd = pipe + (uint32_t)sndcnt;
    if (s->cwnd < s->mss)
        s->cwnd = s->mss;
}

static void arm_reo(utcp_t *t, struct utcp_sock *s, uint64_t left)
{
    s->rtx_kind = RTX_REO;
    s->t_rtx = t->now + left;
    tmr_arm(t, s);
}

void tcp_rack_timeout(utcp_t *t, struct utcp_sock *s)
{
    uint32_t lost_before = s->lost_bytes;
    uint64_t left = rack_detect(t, s);
    if (s->lost_bytes > lost_before) {
        if (s->ca_state < CA_RECOVERY)
            enter_recovery(t, s);
        if (s->ca_state == CA_RECOVERY)
            prr_update(s, 0, true);
    }
    tcp_output(t, s);
    if (left)
        arm_reo(t, s, left);
    else
        tcp_rearm_rtx(t, s);
}

/* ------------------------------------------------------------- SACK in */

static uint32_t mark_sacked(utcp_t *t, struct utcp_sock *s, struct txrec *r)
{
    if (r->flags & TR_SACKED)
        return 0;
    uint32_t len = r->end - r->start;
    r->flags |= TR_SACKED;
    s->sacked_bytes += len;
    if (r->flags & TR_LOST) {
        r->flags &= ~TR_LOST;
        s->lost_bytes -= len;
    }
    if (r->flags & TR_RETRANS) {
        r->flags &= ~TR_RETRANS;
        s->retrans_bytes -= len;
    }
    rack_update(t, s, r);
    return len;
}

static uint32_t process_sack(utcp_t *t, struct utcp_sock *s, const struct tcp_opts *o,
                             uint32_t ack)
{
    uint32_t newly = 0;
#ifdef UTCP_DEBUG
    if (getenv("SACKLOG")) {
        fprintf(stderr, "t=%.3f ack=+%d n=%d:", t->now / 1e6, (int)(ack - s->snd_una), o->nsack);
        for (int i = 0; i < o->nsack; i++)
            fprintf(stderr, " [%d,%d)", (int)(o->sack[i][0] - s->snd_una),
                    (int)(o->sack[i][1] - s->snd_una));
        fprintf(stderr, "\n");
    }
#endif
    for (int i = 0; i < o->nsack; i++) {
        uint32_t a = o->sack[i][0], b = o->sack[i][1];
        if (!seq_lt(a, b) || seq_gt(b, s->snd_nxt))
            continue;
        /* D-SACK (RFC 2883): first block below the cumulative ACK or inside
         * the second block. Signals reordering / spurious retransmission. */
        if (i == 0 && (seq_le(b, ack) || (o->nsack > 1 && seq_ge(a, o->sack[1][0]) &&
                                          seq_le(b, o->sack[1][1])))) {
            s->reord_seen = 1;
            s->dsacks++;
            t->st->tcp_dsacks++;
            if (s->reo_wnd_us < 16)
                s->reo_wnd_us = s->reo_wnd_us ? s->reo_wnd_us + 1 : 2;
            if (s->undo_valid && seq_ge(a, s->undo_marker))
                s->undo_retrans -= (int32_t)(b - a);
            continue;
        }
        if (seq_le(b, s->snd_una))
            continue;
        if (seq_lt(a, s->snd_una))
            a = s->snd_una;
        for (struct txrec *r = s->rtx_head; r && seq_lt(r->start, b); r = r->next) {
            if (seq_le(r->end, a) || (r->flags & TR_SACKED))
                continue;
            /* never split the FIN off its final byte boundary incorrectly */
            if (seq_lt(r->start, a)) {
                struct txrec *n = txrec_split(t, s, r, a);
                if (!n)
                    break;
                continue; /* loop moves to n */
            }
            if (seq_gt(r->end, b)) {
                if ((r->flags & TR_FIN) && r->end - b == 1 && r->end - r->start == 1)
                    break;
                if (!txrec_split(t, s, r, b))
                    break;
            }
            newly += mark_sacked(t, s, r);
        }
    }
    return newly;
}

/* ---------------------------------------------------------- send queue */

static void sq_ack(utcp_t *t, struct utcp_sock *s, uint32_t ack)
{
    uint32_t data_end = s->sq_seq + s->sq_bytes;
    uint32_t upto = seq_lt(ack, data_end) ? ack : data_end;
    if (!seq_gt(upto, s->sq_seq))
        return;
    uint32_t n = upto - s->sq_seq;
    while (n && s->sq_head) {
        struct utcp_buf *b = s->sq_head;
        uint32_t c = MIN(n, b->len);
        b->data += c;
        b->len -= c;
        s->sq_seq += c;
        s->sq_bytes -= c;
        n -= c;
        if (s->sq_cur == b)
            s->sq_cur_seq = s->sq_seq;
        if (b->len)
            break;
        if (b == s->sq_tail && __atomic_load_n(&b->refcnt, __ATOMIC_ACQUIRE) == 1) {
            b->data = b->base; /* no packet references it: reuse for writes */
            break;
        }
        s->sq_head = b->nextpkt;
        if (b == s->sq_tail)
            s->sq_tail = NULL;
        if (s->sq_cur == b) {
            s->sq_cur = s->sq_head;
            s->sq_cur_seq = s->sq_seq;
        }
        chunk_unref(t, b);
    }
}

/* --------------------------------------------------------------- ACK in */

/* Returns false if the segment must be dropped. */
static bool tcp_ack(utcp_t *t, struct utcp_sock *s, const struct tcp_hdr *th,
                    const struct tcp_opts *o, uint32_t seq, uint32_t plen)
{
    uint32_t ack = ntoh32(th->ack);
    uint32_t wnd = (uint32_t)ntoh16(th->win) << s->snd_wscale;

    if (seq_gt(ack, s->snd_nxt)) {
        s->flags |= SF_ACK_NOW; /* RFC 5961 5.2: ack too new */
        sock_mark_dirty(t, s);
        return false;
    }
    if (seq_lt(ack, s->snd_una - MAX(s->max_wnd, 65535u))) {
        s->flags |= SF_ACK_NOW; /* challenge ACK: ack too old */
        sock_mark_dirty(t, s);
        return false;
    }
    if (seq_lt(ack, s->snd_una))
        return true; /* old ACK: ignore for ack processing, keep data */

    uint32_t prior_inflight = tcp_inflight(s);
    uint32_t prior_wnd = s->snd_wnd;
    if (seq_lt(s->snd_wl1, seq) || (s->snd_wl1 == seq && seq_le(s->snd_wl2, ack))) {
        s->snd_wnd = wnd;
        s->snd_wl1 = seq;
        s->snd_wl2 = ack;
        if (wnd > s->max_wnd)
            s->max_wnd = wnd;
    }
    if (s->snd_wnd && s->t_persist) {
        s->t_persist = 0;
        s->backoff = 0;
        tmr_arm(t, s);
    }

    uint32_t lost_before = s->lost_bytes;
    uint32_t newly_sacked = 0;
    if ((s->flags & SF_SACK_OK) && o->nsack)
        newly_sacked = process_sack(t, s, o, ack);

    uint32_t acked = 0, delivered = newly_sacked;
    int64_t rtt_us = -1;
    if (seq_gt(ack, s->snd_una)) {
        acked = ack - s->snd_una;
        struct txrec *r;
        while ((r = s->rtx_head) && seq_lt(r->start, ack)) {
            if (seq_gt(r->end, ack) && !txrec_split(t, s, r, ack))
                break;
            uint32_t len = r->end - r->start;
            if (r->flags & TR_SACKED)
                s->sacked_bytes -= len;
            else {
                delivered += len;
                rack_update(t, s, r);
                if (!(r->flags & TR_EVER_RETRANS) && rtt_us < 0)
                    rtt_us = (int64_t)((t->now - r->xmit_ns) / 1000);
            }
            if (r->flags & TR_LOST)
                s->lost_bytes -= len;
            if (r->flags & TR_RETRANS)
                s->retrans_bytes -= len;
            s->rtx_head = r->next;
            if (s->rtx_head)
                s->rtx_head->prev = NULL;
            else
                s->rtx_tail = NULL;
            txrec_free(t, r);
        }
        s->snd_una = ack;
        sq_ack(t, s, ack);
        s->bytes_acked += acked;
        s->rtx_count = 0;
        s->backoff = 0;
        s->dupacks = 0;
    } else if (!plen && wnd == prior_wnd && s->snd_una != s->snd_nxt &&
               !(th->flags & (TH_SYN | TH_FIN))) {
        s->dupacks++;
    }
    if (rtt_us < 0 && newly_sacked && s->rack_rtt_us)
        rtt_us = s->rack_rtt_us; /* SACK RTT sample */
    if (rtt_us >= 0)
        rtt_sample(t, s, (uint32_t)rtt_us);
    if (delivered) {
        s->delivered += delivered;
        s->delivered_ns = t->now;
    }

    /* loss detection */
    uint64_t reo_left = 0;
    if (s->flags & SF_SACK_OK) {
        reo_left = rack_detect(t, s);
    } else if (s->dupacks >= 3 && s->rtx_head && !(s->rtx_head->flags & TR_LOST)) {
        /* NewReno fallback for peers without SACK */
        struct txrec *h = s->rtx_head;
        if (h->end - h->start > s->mss + ((h->flags & TR_FIN) ? 1u : 0u))
            txrec_split(t, s, h, h->start + s->mss);
        mark_lost(s, h);
    }
    bool undone = try_undo(s, o, acked);
    if (undone)
        t->st->tcp_undos++;
    if (!undone && (s->ca_state == CA_RECOVERY || s->ca_state == CA_LOSS) &&
        seq_ge(s->snd_una, s->high_seq)) {
        if (s->ca_state == CA_RECOVERY && s->ssthresh < UINT32_MAX)
            s->cwnd = MAX(s->ssthresh, 2u * s->mss);
        s->ca_state = CA_OPEN;
        s->undo_valid = 0;
    }
    /* NewReno partial ack: next hole is lost too */
    if (!(s->flags & SF_SACK_OK) && s->ca_state == CA_RECOVERY && acked && s->rtx_head &&
        !(s->rtx_head->flags & TR_LOST)) {
        struct txrec *h = s->rtx_head;
        if (h->end - h->start > s->mss + ((h->flags & TR_FIN) ? 1u : 0u))
            txrec_split(t, s, h, h->start + s->mss);
        mark_lost(s, h);
    }
    bool newly_lost = s->lost_bytes > lost_before;
    if (s->lost_bytes && s->ca_state < CA_RECOVERY)
        enter_recovery(t, s);
    if (s->ca_state == CA_RECOVERY) {
        prr_update(s, delivered, newly_lost);
    } else if (acked) {
        bool limited = (s->flags & SF_CWND_LIMITED) ||
                       (s->cwnd < s->ssthresh && prior_inflight * 2 >= s->cwnd) ||
                       prior_inflight + s->mss >= s->cwnd;
        if (limited)
            cc_on_ack(t, s, acked, rtt_us >= 0 ? (uint32_t)rtt_us : 0);
        if (s->ca_state == CA_OPEN && s->sacked_bytes)
            s->ca_state = CA_DISORDER;
        else if (s->ca_state == CA_DISORDER && !s->sacked_bytes)
            s->ca_state = CA_OPEN;
    }
    if (s->tlp_high_seq && seq_ge(ack, s->tlp_high_seq))
        s->tlp_high_seq = 0;

    /* timers */
    if (s->snd_una == s->snd_nxt) {
        s->t_rtx = 0;
        s->rtx_kind = RTX_NONE;
        tmr_arm(t, s);
    } else if (reo_left && !s->lost_bytes) {
        arm_reo(t, s, reo_left);
    } else if (acked || (s->rtx_kind == RTX_REO && !reo_left)) {
        tcp_rearm_rtx(t, s);
    }
    if (acked || newly_sacked || s->lost_bytes || s->snd_wnd != prior_wnd)
        sock_mark_dirty(t, s);
    return true;
}

/* ------------------------------------------------------------ receive */

/* Turn a packet chain into nextpkt-linked single buffers and append to rq. */
static void rq_append(struct utcp_sock *s, struct utcp_buf *b, uint32_t len)
{
    while (b) {
        struct utcp_buf *n = b->next;
        b->next = NULL;
        b->nextpkt = NULL;
        if (b->len) {
            if (s->rq_tail)
                s->rq_tail->nextpkt = b;
            else
                s->rq_head = b;
            s->rq_tail = b;
        } else if (s->rq_tail || n) {
            /* empty fragment: drop it (handled by caller's free path) */
        }
        b = n;
    }
    s->rq_bytes += len;
}

static struct utcp_buf *pl_trim_front(utcp_t *t, struct utcp_buf *b, uint32_t n)
{
    while (b && n) {
        if (n < b->len) {
            b->data += n;
            b->len -= n;
            return b;
        }
        n -= b->len;
        struct utcp_buf *nx = b->next;
        t->ops.buf_free(t->ctx, b);
        b = nx;
    }
    while (b && !b->len) {
        struct utcp_buf *nx = b->next;
        t->ops.buf_free(t->ctx, b);
        b = nx;
    }
    return b;
}

static void pl_trim_back(utcp_t *t, struct utcp_buf *b, uint32_t keep)
{
    for (; b; b = b->next) {
        if (keep <= b->len) {
            b->len = keep;
            buf_free_chain(t, b->next);
            b->next = NULL;
            return;
        }
        keep -= b->len;
    }
}

/* Linux tcp_sack_new_ofo_skb()/tcp_sack_remove(): the block holding the
 * newest segment goes first; previously reported blocks follow in order,
 * dropping any that merged into it or were filled by rcv_nxt. */
static void rebuild_sack(struct utcp_sock *s, uint32_t last_seq)
{
    uint32_t a = 0, e = 0;
    bool have = false;
    for (struct utcp_buf *q = s->ooo_head; q; q = q->nextpkt) {
        uint32_t qa = q->seq, qe = q->seq + q->pkt_len;
        if (have && qa == e) {
            e = qe;
            continue;
        }
        if (have && seq_lt(last_seq, e))
            break;
        a = qa;
        e = qe;
        have = seq_ge(last_seq, qa) && seq_lt(last_seq, qe);
        if (!have && seq_gt(qa, last_seq))
            break;
    }
    uint32_t blk[4][2], n = 0;
    if (have) {
        blk[0][0] = a;
        blk[0][1] = e;
        n = 1;
    }
    for (int i = 0; i < s->nsack && n < 4; i++) {
        uint32_t ba = s->sack_blk[i][0], be = s->sack_blk[i][1];
        if (seq_le(be, s->rcv_nxt))
            continue; /* filled */
        if (have && seq_le(a, ba) && seq_ge(e, be))
            continue; /* merged into the new block */
        if (have && seq_lt(ba, e) && seq_gt(be, a))
            continue;
        blk[n][0] = ba;
        blk[n][1] = be;
        n++;
    }
    memcpy(s->sack_blk, blk, sizeof(blk[0]) * n);
    s->nsack = (uint8_t)n;
}

static void set_dsack(struct utcp_sock *s, uint32_t a, uint32_t b)
{
    if (!(s->flags & SF_SACK_OK))
        return;
    s->dsack = 1;
    s->dsack_blk[0] = a;
    s->dsack_blk[1] = b;
}

static void ooo_insert(utcp_t *t, struct utcp_sock *s, struct utcp_buf *b, uint32_t seq,
                       uint32_t len)
{
    uint32_t end = seq + len;
    struct utcp_buf *prev = NULL, *q = s->ooo_head;
    while (q && seq_le(q->seq, seq)) {
        prev = q;
        q = q->nextpkt;
    }
    if (prev) {
        uint32_t pend = prev->seq + prev->pkt_len;
        if (seq_ge(pend, end)) {
            set_dsack(s, seq, end);
            buf_free_chain(t, b);
            return;
        }
        if (seq_gt(pend, seq)) {
            b = pl_trim_front(t, b, pend - seq);
            len -= pend - seq;
            seq = pend;
        }
    }
    while (q && seq_lt(q->seq, end)) {
        uint32_t qend = q->seq + q->pkt_len;
        if (seq_le(qend, end)) { /* new segment covers q entirely */
            struct utcp_buf *nx = q->nextpkt;
            s->ooo_bytes -= q->pkt_len;
            buf_free_chain(t, q);
            if (prev)
                prev->nextpkt = nx;
            else
                s->ooo_head = nx;
            q = nx;
            continue;
        }
        len = q->seq - seq;
        pl_trim_back(t, b, len);
        end = seq + len;
        break;
    }
    if (!len || !b) {
        buf_free_chain(t, b);
        return;
    }
    b->seq = seq;
    b->pkt_len = len;
    b->nextpkt = q;
    if (prev)
        prev->nextpkt = b;
    else
        s->ooo_head = b;
    s->ooo_bytes += len;
    t->st->tcp_ooo_pkts++;
    rebuild_sack(s, seq);
}

static void process_fin(utcp_t *t, struct utcp_sock *s)
{
    s->rcv_nxt++;
    s->flags |= SF_FIN_RCVD | SF_ACK_NOW;
    sock_event(t, s, UTCP_EV_EOF | UTCP_EV_READABLE);
    switch (s->state) {
    case TCP_SYN_RCVD:
    case TCP_ESTABLISHED:
        s->state = TCP_CLOSE_WAIT;
        break;
    case TCP_FIN_WAIT_1:
        if ((s->flags & SF_FIN_SENT) && s->snd_una == s->snd_nxt) {
            tcp_enter_time_wait(t, s);
        } else {
            s->state = TCP_CLOSING;
        }
        break;
    case TCP_FIN_WAIT_2:
        tcp_enter_time_wait(t, s);
        break;
    }
    sock_mark_dirty(t, s);
}

/* Out-of-order arrivals, hole fills and duplicates are ACKed per segment, as
 * Linux does (tcp_data_queue_ofo -> quickack): each ACK carries the newest
 * SACK block, so the sender learns every hole even though an ACK has room for
 * only 3-4 blocks. In-order data is still ACKed once per burst. */
static void ack_immediately(utcp_t *t, struct utcp_sock *s)
{
    tcp_send_ack(t, s);
}

/* Consume payload `b` (headers already stripped) of length plen at seq. */
static void tcp_data(utcp_t *t, struct utcp_sock *s, struct utcp_buf *b, uint32_t seq,
                     uint32_t plen, bool fin, uint16_t gso)
{
    uint32_t fin_seq = seq + plen;
    if (s->state != TCP_ESTABLISHED && s->state != TCP_FIN_WAIT_1 &&
        s->state != TCP_FIN_WAIT_2 && s->state != TCP_SYN_RCVD) {
        buf_free_chain(t, b);
        return;
    }
    if (plen) {
        uint32_t end = seq + plen;
        if (seq_le(end, s->rcv_nxt)) {
            set_dsack(s, seq, end);
            ack_immediately(t, s);
            buf_free_chain(t, b);
            b = NULL;
            plen = 0;
        } else {
            if (seq_lt(seq, s->rcv_nxt)) {
                uint32_t d = s->rcv_nxt - seq;
                set_dsack(s, seq, s->rcv_nxt);
                b = pl_trim_front(t, b, d);
                seq += d;
                plen -= d;
                s->flags |= SF_ACK_NOW;
            }
            /* hard memory bound: twice the receive buffer */
            uint32_t used = s->rq_bytes + s->ooo_bytes;
            uint32_t lim = 2 * s->rcvbuf;
            uint32_t edge = s->rcv_nxt + MAX(s->rcv_adv - s->rcv_nxt, 0u);
            if (seq_gt(seq + plen, edge) && seq_lt(seq, edge)) {
                pl_trim_back(t, b, edge - seq);
                plen = edge - seq;
                fin = false;
            } else if (seq_ge(seq, edge) && s->rcv_adv != s->rcv_nxt) {
                buf_free_chain(t, b);
                s->flags |= SF_ACK_NOW;
                sock_mark_dirty(t, s);
                return;
            }
            if (used + plen > lim) {
                buf_free_chain(t, b);
                s->flags |= SF_ACK_NOW;
                sock_mark_dirty(t, s);
                return;
            }
            uint32_t est = gso ? gso : plen;
            if (est <= 65535 && est > s->rcv_mss)
                s->rcv_mss = MIN(est, (uint32_t)t->r->cfg.mtu - 40u);
            if (seq == s->rcv_nxt) {
                bool had_ooo = s->ooo_head != NULL;
                rq_append(s, b, plen);
                s->rcv_nxt += plen;
                s->bytes_received += plen;
                s->rcv_unacked += plen;
                while (s->ooo_head && seq_le(s->ooo_head->seq, s->rcv_nxt)) {
                    struct utcp_buf *q = s->ooo_head;
                    s->ooo_head = q->nextpkt;
                    s->ooo_bytes -= q->pkt_len;
                    uint32_t qend = q->seq + q->pkt_len;
                    if (seq_le(qend, s->rcv_nxt)) {
                        buf_free_chain(t, q);
                        continue;
                    }
                    uint32_t d = s->rcv_nxt - q->seq, ql = q->pkt_len - d;
                    q = pl_trim_front(t, q, d);
                    rq_append(s, q, ql);
                    s->rcv_nxt += ql;
                    s->bytes_received += ql;
                }
                if (had_ooo) {
                    rebuild_sack(s, s->rcv_nxt - 1);
                    ack_immediately(t, s);
                }
                sock_event(t, s, UTCP_EV_READABLE);
                if (s->rcv_unacked >= 2u * s->rcv_mss || s->quickack)
                    s->flags |= SF_ACK_NOW;
                else if (!s->t_delack) {
                    s->t_delack = t->now + (uint64_t)t->r->cfg.delack_ms * 1000000ULL;
                    tmr_arm(t, s);
                }
            } else {
                ooo_insert(t, s, b, seq, plen);
                s->quickack = MAX(s->quickack, (uint8_t)2);
                ack_immediately(t, s);
            }
            b = NULL;
            sock_mark_dirty(t, s);
        }
    }
    if (b)
        buf_free_chain(t, b);
    if (fin) {
        if (fin_seq == s->rcv_nxt)
            process_fin(t, s);
        else if (seq_gt(fin_seq, s->rcv_nxt)) {
            s->fin_rseq = fin_seq;
            s->fin_ooo = 1;
            s->flags |= SF_ACK_NOW;
        }
    }
    if (s->fin_ooo && s->fin_rseq == s->rcv_nxt && !(s->flags & SF_FIN_RCVD)) {
        s->fin_ooo = 0;
        process_fin(t, s);
    }
    if (s->flags & SF_ACK_NOW)
        sock_mark_dirty(t, s);
}

/* --------------------------------------------------------- connection */

static int ts_rtt_ms(utcp_t *t, struct utcp_sock *s, const struct tcp_opts *o)
{
    if (!o->ts || !o->tsecr)
        return -1;
    uint32_t d = tcp_ts_now(t, s) - o->tsecr;
    return d < 60000 ? (int)d : -1;
}

static void listen_input(utcp_t *t, struct utcp_sock *l, struct utcp_buf *b, struct ip_hdr *ip,
                         struct tcp_hdr *th, uint32_t tcp_len, const struct tcp_opts *o)
{
    uint8_t fl = th->flags;
    if (fl & TH_RST)
        goto drop;
    if (fl & TH_ACK) {
        tcp_send_rst_reply(t, ip, th, tcp_len);
        goto drop;
    }
    if (!(fl & TH_SYN))
        goto drop;
    if (l->syn_len + l->acc_len >= l->backlog) {
        t->st->tcp_listen_drops++;
        goto drop;
    }
    struct utcp_sock *s = sock_alloc(t);
    if (!s)
        goto drop;
    sock_init_tcp(t, s);
    s->rcvbuf = l->rcvbuf;
    s->sndbuf = l->sndbuf;
    s->rcv_wscale = l->rcv_wscale;
    s->flags |= l->flags & SF_NODELAY;
    s->lip = ip->daddr;
    s->rip = ip->saddr;
    s->lport = th->dport;
    s->rport = th->sport;
    s->hash = b->hash;
    s->bucket = b->hash & (t->r->cfg.nbuckets - 1);
    s->parent = l;
    l->syn_len++;
    uint32_t seq = ntoh32(th->seq);
    s->irs = seq;
    s->rcv_nxt = seq + 1;
    s->rcv_wup = s->rcv_nxt;
    apply_syn_opts(s, o, true);
    s->iss = tcp_isn(t, s->lip, s->rip, s->lport, s->rport);
    s->snd_una = s->iss;
    s->snd_nxt = s->iss;
    s->sq_seq = s->iss + 1;
    s->sq_cur_seq = s->iss + 1;
    s->snd_wnd = ntoh16(th->win);
    s->snd_wl1 = seq;
    s->snd_wl2 = s->iss;
    s->max_wnd = s->snd_wnd;
    setup_mss(t, s);
    cc_init(t, s);
    s->state = TCP_SYN_RCVD;
    flow_insert(t, s);
    t->st->tcp_passive_opens++;
    tcp_send_syn(t, s, true);
drop:
    buf_free_chain(t, b);
}

static void syn_sent_input(utcp_t *t, struct utcp_sock *s, struct utcp_buf *b, struct ip_hdr *ip,
                           struct tcp_hdr *th, uint32_t tcp_len, const struct tcp_opts *o)
{
    uint8_t fl = th->flags;
    uint32_t ack = ntoh32(th->ack), seq = ntoh32(th->seq);
    if (fl & TH_ACK) {
        if (seq_le(ack, s->iss) || seq_gt(ack, s->snd_nxt)) {
            if (!(fl & TH_RST))
                tcp_send_rst_reply(t, ip, th, tcp_len);
            goto drop;
        }
    }
    if (fl & TH_RST) {
        if (fl & TH_ACK)
            sock_reset(t, s, ECONNREFUSED);
        goto drop;
    }
    if (!(fl & TH_SYN))
        goto drop;
    s->irs = seq;
    s->rcv_nxt = seq + 1;
    s->rcv_wup = s->rcv_nxt;
    apply_syn_opts(s, o, true);
    setup_mss(t, s);
    s->snd_wnd = ntoh16(th->win);
    s->max_wnd = s->snd_wnd;
    s->snd_wl1 = seq;
    s->snd_wl2 = ack;
    if (fl & TH_ACK) {
        s->snd_una = ack;
        s->t_rtx = 0;
        s->rtx_kind = RTX_NONE;
        s->syn_retries = 0;
        tmr_arm(t, s);
        int r = ts_rtt_ms(t, s, o);
        if (r >= 0)
            rtt_sample(t, s, (uint32_t)r * 1000u + 1);
        s->state = TCP_ESTABLISHED;
        s->flags |= SF_ACK_NOW;
        sock_event(t, s, UTCP_EV_CONNECTED | UTCP_EV_WRITABLE);
        sock_mark_dirty(t, s);
    } else {
        /* simultaneous open */
        s->state = TCP_SYN_RCVD;
        s->t_rtx = 0;
        tcp_send_syn(t, s, true);
    }
drop:
    buf_free_chain(t, b);
}

void tcp_icmp_frag_needed(utcp_t *t, struct utcp_sock *s, uint16_t mtu)
{
    if (mtu < 576 || mtu >= t->r->cfg.mtu)
        return;
    uint32_t m = mtu - 40u - ((s->flags & SF_TS_OK) ? 12u : 0u);
    if (m >= s->mss)
        return;
    s->mss = (uint16_t)m;
    s->peer_mss = (uint16_t)MIN((uint32_t)s->peer_mss, mtu - 40u);
    /* tcp_simple_retransmit(): resend everything outstanding at the new size */
    for (struct txrec *r = s->rtx_head; r; r = r->next)
        if (!(r->flags & TR_SACKED))
            mark_lost(s, r);
    sock_mark_dirty(t, s);
}

/* --------------------------------------------------------------- input */

void tcp_input(utcp_t *t, struct utcp_buf *b, struct ip_hdr *ip, struct tcp_hdr *th,
               uint32_t tcp_len)
{
    uint32_t thl = (th->doff >> 4) * 4u;
    uint32_t hdr_end = (uint32_t)((uint8_t *)th - b->data) + thl;
    if (thl < TCP_HLEN || thl > tcp_len || hdr_end > b->len) {
        t->st->rx_drop_short++;
        buf_free_chain(t, b);
        return;
    }
    uint8_t fl = th->flags;
    struct tcp_opts o;
    parse_opts((const uint8_t *)(th + 1), thl - TCP_HLEN, &o, fl & TH_SYN);

    struct utcp_sock *s = flow_lookup(t, ip->daddr, ip->saddr, th->dport, th->sport);
    if (s && s->state == TCP_TIME_WAIT && (fl & TH_SYN) && !(fl & (TH_ACK | TH_RST)) &&
        seq_gt(ntoh32(th->seq), s->rcv_nxt)) {
        /* RFC 6191-style TIME_WAIT reuse: a new incarnation */
        tcp_finish(t, s);
        s = NULL;
    }
    if (!s) {
        struct utcp_sock *l = listener_lookup(t, th->dport);
        if (l) {
            listen_input(t, l, b, ip, th, tcp_len, &o);
            return;
        }
        tcp_send_rst_reply(t, ip, th, tcp_len);
        buf_free_chain(t, b);
        return;
    }
    s->segs_in++;
    if (s->state == TCP_SYN_SENT) {
        syn_sent_input(t, s, b, ip, th, tcp_len, &o);
        return;
    }

    uint32_t seq = ntoh32(th->seq);
    uint32_t plen = tcp_len - thl;
    uint32_t seg_end = seq + plen + !!(fl & TH_SYN) + !!(fl & TH_FIN);
    uint16_t gso = (b->flags & UTCP_BUF_GRO) ? b->gso_size : 0;

    /* PAWS (RFC 7323) */
    if ((s->flags & SF_TS_OK) && o.ts && !(fl & TH_RST) &&
        (int32_t)(o.tsval - s->ts_recent) < 0 &&
        t->now - s->ts_recent_ns < 24ULL * 86400 * 1000000000ULL && s->ts_recent_ns) {
        s->flags |= SF_ACK_NOW;
        sock_mark_dirty(t, s);
        goto drop;
    }
    /* acceptability (Linux tcp_sequence) */
    uint32_t rwnd = seq_gt(s->rcv_adv, s->rcv_nxt) ? s->rcv_adv - s->rcv_nxt : 0;
    if (seq_lt(seg_end, s->rcv_wup) || seq_gt(seq, s->rcv_nxt + rwnd)) {
        if (!(fl & TH_RST)) {
            s->flags |= SF_ACK_NOW;
            if (seq_lt(seg_end, s->rcv_nxt) && plen)
                set_dsack(s, seq, seq + plen);
            sock_mark_dirty(t, s);
        }
        goto drop;
    }
    /* RST (RFC 5961 3.2) */
    if (fl & TH_RST) {
        if (seq == s->rcv_nxt) {
            if (s->state == TCP_SYN_RCVD && s->parent)
                tcp_finish(t, s);
            else if (s->state == TCP_TIME_WAIT || s->state == TCP_LAST_ACK ||
                     s->state == TCP_CLOSING)
                tcp_finish(t, s);
            else
                sock_reset(t, s, ECONNRESET);
        } else {
            s->flags |= SF_ACK_NOW; /* challenge ACK */
            sock_mark_dirty(t, s);
        }
        goto drop;
    }
    /* SYN in a synchronized state: challenge ACK (RFC 5961 4.2) */
    if (fl & TH_SYN) {
        if (s->state == TCP_SYN_RCVD && seq == s->irs) {
            /* retransmitted SYN: resend SYN-ACK */
            s->t_rtx = 0;
            tcp_send_syn(t, s, true);
        } else {
            s->flags |= SF_ACK_NOW;
            sock_mark_dirty(t, s);
        }
        goto drop;
    }
    if (!(fl & TH_ACK))
        goto drop;

    /* timestamp bookkeeping */
    if ((s->flags & SF_TS_OK) && o.ts && seq_le(seq, s->rcv_wup)) {
        s->ts_recent = o.tsval;
        s->ts_recent_ns = t->now;
    }

    if (s->state == TCP_SYN_RCVD) {
        uint32_t ack = ntoh32(th->ack);
        if (!(seq_gt(ack, s->snd_una) && seq_le(ack, s->snd_nxt))) {
            tcp_send_rst_reply(t, ip, th, tcp_len);
            goto drop;
        }
        s->snd_una = ack;
        s->t_rtx = 0;
        s->rtx_kind = RTX_NONE;
        s->syn_retries = 0;
        tmr_arm(t, s);
        s->snd_wnd = (uint32_t)ntoh16(th->win) << s->snd_wscale;
        s->max_wnd = s->snd_wnd;
        s->snd_wl1 = seq;
        s->snd_wl2 = ack;
        int r = ts_rtt_ms(t, s, &o);
        if (r >= 0)
            rtt_sample(t, s, (uint32_t)r * 1000u + 1);
        s->state = (s->flags & SF_FIN_QUEUED) ? TCP_FIN_WAIT_1 : TCP_ESTABLISHED;
        struct utcp_sock *l = s->parent;
        if (l) {
            l->syn_len--;
            s->acc_next = NULL;
            if (l->acc_tail)
                l->acc_tail->acc_next = s;
            else
                l->acc_head = s;
            l->acc_tail = s;
            l->acc_len++;
            s->flags |= SF_IN_ACCEPTQ;
            sock_event(t, l, UTCP_EV_ACCEPT);
        } else {
            sock_event(t, s, UTCP_EV_CONNECTED | UTCP_EV_WRITABLE);
        }
    } else if (!tcp_ack(t, s, th, &o, seq, plen)) {
        goto drop;
    }

    bool fin_acked = (s->flags & SF_FIN_SENT) && s->snd_una == s->snd_nxt;
    switch (s->state) {
    case TCP_FIN_WAIT_1:
        if (fin_acked) {
            s->state = TCP_FIN_WAIT_2;
            if (s->flags & SF_CLOSED_BY_APP) {
                s->t_tw = t->now + 60000000000ULL;
                tmr_arm(t, s);
            }
        }
        break;
    case TCP_CLOSING:
        if (fin_acked)
            tcp_enter_time_wait(t, s);
        goto drop;
    case TCP_LAST_ACK:
        if (fin_acked) {
            tcp_finish(t, s);
        }
        goto drop;
    case TCP_TIME_WAIT:
        if (fl & TH_FIN) { /* retransmitted FIN: re-ACK and restart 2MSL */
            s->flags |= SF_ACK_NOW;
            s->t_tw = t->now + (uint64_t)t->r->cfg.time_wait_ms * 1000000ULL;
            tmr_arm(t, s);
            sock_mark_dirty(t, s);
        }
        goto drop;
    case TCP_CLOSE_WAIT:
        goto drop; /* peer already sent FIN; ignore further data */
    }

    if (plen || (fl & TH_FIN)) {
        /* strip headers */
        uint32_t hdr = hdr_end;
        b->pkt_len -= hdr;
        b = pl_trim_front(t, b, hdr);
        tcp_data(t, s, b, seq, plen, fl & TH_FIN, gso);
        return;
    }
drop:
    buf_free_chain(t, b);
}
