/* Congestion control: CUBIC (RFC 9438, Linux tcp_cubic semantics incl. delay
 * HyStart) and Reno. cwnd/ssthresh are in bytes. */
#include "utcp_int.h"

#include <math.h>

#define CUBIC_C 0.4
#define CUBIC_BETA 0.7
#define HYSTART_LOW_WINDOW 16
#define HYSTART_MIN_SAMPLES 8

void cc_init(utcp_t *t, struct utcp_sock *s)
{
    (void)t;
    memset(&s->cubic, 0, sizeof(s->cubic));
    s->cubic.curr_rtt_us = UINT32_MAX;
}

static void cubic_reset(struct cubic *c)
{
    c->epoch_ns = 0;
    c->cnt_acc = 0;
}

uint32_t cc_ssthresh(utcp_t *t, struct utcp_sock *s)
{
    uint32_t mss = s->mss;
    if (t->r->cfg.cc == UTCP_CC_RENO)
        return MAX(tcp_inflight(s) / 2, 2u * mss);
    struct cubic *c = &s->cubic;
    double w = (double)s->cwnd / mss;
    cubic_reset(c);
    if (w < c->w_last_max)
        c->w_last_max = w * (1.0 + CUBIC_BETA) / 2.0; /* fast convergence */
    else
        c->w_last_max = w;
    c->w_max = c->w_last_max;
    return MAX((uint32_t)(s->cwnd * CUBIC_BETA), 2u * mss);
}

void cc_on_rto(utcp_t *t, struct utcp_sock *s)
{
    (void)t;
    cubic_reset(&s->cubic);
    s->cubic.hystart_done = true;
}

static void hystart_update(utcp_t *t, struct utcp_sock *s, uint32_t rtt_us)
{
    struct cubic *c = &s->cubic;
    (void)t;
    if (c->hystart_done || !rtt_us)
        return;
    if (seq_gt(s->snd_una, c->round_start_seq) || !c->round_start_seq) {
        c->last_rtt_us = c->curr_rtt_us;
        c->curr_rtt_us = UINT32_MAX;
        c->samples = 0;
        c->round_start_seq = s->snd_nxt;
    }
    if (s->cwnd < HYSTART_LOW_WINDOW * s->mss)
        return;
    if (c->samples < HYSTART_MIN_SAMPLES) {
        if (rtt_us < c->curr_rtt_us)
            c->curr_rtt_us = rtt_us;
        c->samples++;
        return;
    }
    if (c->last_rtt_us == UINT32_MAX || c->curr_rtt_us == UINT32_MAX)
        return;
    uint32_t eta = MIN(MAX(c->last_rtt_us / 8, 4000u), 16000u);
    if (c->curr_rtt_us >= c->last_rtt_us + eta) {
        c->hystart_done = true;
        s->ssthresh = s->cwnd;
    }
}

static void cubic_ca(utcp_t *t, struct utcp_sock *s, uint32_t acked)
{
    struct cubic *c = &s->cubic;
    double mss = s->mss;
    double w = s->cwnd / mss;
    double acked_segs = acked / mss;
    if (!c->epoch_ns) {
        c->epoch_ns = t->now;
        if (w < c->w_max) {
            c->K = cbrt((c->w_max - w) / CUBIC_C);
        } else {
            c->K = 0;
            c->w_max = w;
        }
        c->w_est = w;
        c->cnt_acc = 0;
    }
    double rtt_s = (s->min_rtt_us == UINT32_MAX ? 0 : s->min_rtt_us) / 1e6;
    double tt = (t->now - c->epoch_ns) / 1e9 + rtt_s;
    double d = tt - c->K;
    double target = c->w_max + CUBIC_C * d * d * d;
    double cnt; /* acks (in segments) per one-segment increase */
    if (target > w)
        cnt = w / (target - w);
    else
        cnt = 100.0 * w;
    /* Reno-friendly region */
    c->w_est += acked_segs * (3.0 * (1.0 - CUBIC_BETA) / (1.0 + CUBIC_BETA)) / w;
    if (c->w_est > w) {
        double cr = w / (c->w_est - w);
        if (cr < cnt)
            cnt = cr;
    }
    if (cnt < 2.0)
        cnt = 2.0; /* at most 1.5x per RTT, as in Linux */
    c->cnt_acc += acked_segs / cnt;
    if (c->cnt_acc >= 1.0) {
        uint32_t inc = (uint32_t)c->cnt_acc;
        c->cnt_acc -= inc;
        s->cwnd += inc * s->mss;
    }
}

static void reno_ca(struct utcp_sock *s, uint32_t acked)
{
    /* cwnd += mss*mss/cwnd per mss acked, accumulated in cnt_acc (bytes) */
    s->cubic.cnt_acc += (double)acked * s->mss / s->cwnd;
    if (s->cubic.cnt_acc >= s->mss) {
        uint32_t inc = (uint32_t)(s->cubic.cnt_acc / s->mss);
        s->cubic.cnt_acc -= (double)inc * s->mss;
        s->cwnd += inc * s->mss;
    }
}

void cc_on_ack(utcp_t *t, struct utcp_sock *s, uint32_t acked, uint32_t rtt_us)
{
    if (s->cwnd < s->ssthresh) {
        if (t->r->cfg.cc == UTCP_CC_CUBIC)
            hystart_update(t, s, rtt_us);
        uint32_t room = s->ssthresh - s->cwnd;
        uint32_t inc = MIN(acked, room);
        s->cwnd += inc;
        acked -= inc;
        if (!acked)
            return;
    }
    if (t->r->cfg.cc == UTCP_CC_RENO)
        reno_ca(s, acked);
    else
        cubic_ca(t, s, acked);
    uint32_t cap = 0x3fffffff;
    if (s->cwnd > cap)
        s->cwnd = cap;
}
