/* End-to-end scenarios: two utcp hosts over the simulated link. Every byte is
 * pattern-verified; every scenario checks socket and buffer leaks. */
#include "sim.h"
#ifdef SIM_INTERNALS
#include <stdio.h>
#include "../src/utcp_int.h"
static void dump(struct utcp_sock *snd, struct utcp_sock *rcv)
{
    printf("  SND una=%u nxt=%u sacked=%u lost=%u rtx=%u cwnd=%u rack_end=%u rack_rtt=%u\n",
           snd->snd_una, snd->snd_nxt, snd->sacked_bytes, snd->lost_bytes, snd->retrans_bytes,
           snd->cwnd, snd->rack_end_seq, snd->rack_rtt_us);
    int n = 0;
    for (struct txrec *r = snd->rtx_head; r && n < 12; r = r->next, n++)
        printf("    rec [%u,%u) len=%u fl=%02x xmits=%u xmit=%.3fms\n", r->start - snd->snd_una,
               r->end - snd->snd_una, r->end - r->start, r->flags, r->xmits, r->xmit_ns / 1e6);
    if (rcv) {
        printf("  RCV rcv_nxt=%+d adv=%u nsack=%u ooo:", (int)(rcv->rcv_nxt - snd->snd_una),
               rcv->rcv_adv - rcv->rcv_nxt, rcv->nsack);
        n = 0;
        for (struct utcp_buf *q = rcv->ooo_head; q && n < 8; q = q->nextpkt, n++)
            printf(" [%u,+%u)", q->seq - snd->snd_una, q->pkt_len);
        printf("\n");
    }
}
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PORT 5001
#define MAXC 4096

static inline uint8_t pat(uint32_t seed, uint64_t off)
{
    uint64_t x = off * 0x9E3779B97F4A7C15ULL + seed;
    return (uint8_t)(x >> 29);
}

struct conn {
    struct utcp_sock *s;
    utcp_t *t;
    int side; /* 0 client, 1 server */
    uint64_t to_send, sent, to_recv, recvd;
    uint32_t seed_tx, seed_rx;
    int shut, eof, closed, err, done, bad;
    uint64_t start_ns, done_ns;
    int paused;
};

struct scen {
    const char *name;
    struct sim_link_cfg link;
    struct sim_host_cfg a, b;
    int nconns;
    uint64_t c2s, s2c;
    uint64_t time_limit_ns;
    int migrate_at_ms;     /* >0: migrate core-0 buckets of host B mid-run */
    int pause_server_ms;   /* >0: server doesn't read until this time */
    double min_gbps;       /* >0: required goodput for conn 0 */
    int expect_refused;
};

static struct {
    struct sim sim;
    const struct scen *sc;
    struct conn conns[2 * MAXC];
    int nconn;
    int done, errors, bad;
    uint64_t rto, tlp, rec, rsegs, osegs, dsacks, undos;
    uint64_t t0;
    int migrated;
} G;

static struct conn *conn_new(void)
{
    struct conn *c = &G.conns[G.nconn++];
    memset(c, 0, sizeof(*c));
    return c;
}

static void maybe_finish(struct conn *c)
{
    if (c->done || c->closed)
        return;
    if (c->shut && c->eof && c->recvd == c->to_recv && c->sent == c->to_send) {
        c->done = 1;
        c->done_ns = G.sim.now;
        struct utcp_info in;
        utcp_sock_info(c->s, &in);
        G.rto += in.rto_events;
        G.tlp += in.tlp_probes;
        G.rec += in.recoveries;
        G.rsegs += in.retrans_segs;
        G.osegs += in.segs_out;
        G.dsacks += in.dsacks;
        G.undos += in.undos;
        G.done++;
        utcp_close(c->t, c->s);
        c->s = NULL;
    }
}

static void pump_send(struct conn *c)
{
    static uint8_t buf[65536];
    while (c->s && c->sent < c->to_send) {
        uint64_t n = c->to_send - c->sent;
        if (n > sizeof(buf))
            n = sizeof(buf);
        for (uint64_t i = 0; i < n; i++)
            buf[i] = pat(c->seed_tx, c->sent + i);
        ssize_t w = utcp_send(c->t, c->s, buf, n);
        if (w < 0)
            break;
        c->sent += (uint64_t)w;
    }
    if (c->s && c->sent == c->to_send && !c->shut) {
        utcp_shutdown(c->t, c->s, UTCP_SHUT_WR);
        c->shut = 1;
    }
}

static void pump_recv(struct conn *c)
{
    static uint8_t buf[65536];
    while (c->s && !c->paused) {
        ssize_t r = utcp_recv(c->t, c->s, buf, sizeof(buf));
        if (r > 0) {
            for (ssize_t i = 0; i < r; i++)
                if (buf[i] != pat(c->seed_rx, c->recvd + (uint64_t)i)) {
                    if (!c->bad)
                        fprintf(stderr, "  data mismatch side=%d at %" PRIu64 "\n", c->side,
                                c->recvd + (uint64_t)i);
                    c->bad = 1;
                    G.bad++;
                    break;
                }
            c->recvd += (uint64_t)r;
            continue;
        }
        if (r == 0)
            c->eof = 1;
        break;
    }
}

static void on_event(struct sim_host *h, unsigned core, struct utcp_sock *s, uint32_t ev)
{
    utcp_t *t = h->core[core];
    if (ev & UTCP_EV_ACCEPT) {
        struct utcp_sock *ns;
        while ((ns = utcp_accept(t, s))) {
            struct utcp_info in;
            utcp_sock_info(ns, &in);
            struct conn *c = conn_new();
            c->s = ns;
            c->t = t;
            c->side = 1;
            c->to_send = G.sc->s2c;
            c->to_recv = G.sc->c2s;
            c->seed_rx = in.remote_port;
            c->seed_tx = in.remote_port ^ 0x5555u;
            c->start_ns = G.sim.now;
            c->paused = G.sc->pause_server_ms > 0;
            utcp_setopt(t, ns, UTCP_OPT_NODELAY, 1);
            utcp_sock_set_user(ns, c);
            pump_send(c);
            pump_recv(c);
        }
        return;
    }
    struct conn *c = utcp_sock_user(s);
    if (!c)
        return;
    if (ev & UTCP_EV_ERROR) {
        c->err = utcp_sock_error(s);
        if (!(G.sc->expect_refused && c->err == ECONNREFUSED)) {
            fprintf(stderr, "  error side=%d err=%d (%s)\n", c->side, c->err, strerror(c->err));
            G.errors++;
        } else {
            G.done++;
        }
    }
    if (ev & (UTCP_EV_CONNECTED | UTCP_EV_WRITABLE))
        pump_send(c);
    if (ev & (UTCP_EV_READABLE | UTCP_EV_EOF))
        pump_recv(c);
    if (ev & UTCP_EV_CLOSED) {
        if (c->s) {
            if (!c->done && !c->err) {
                fprintf(stderr, "  unexpected close side=%d\n", c->side);
                G.errors++;
            }
            utcp_close(t, c->s);
            c->s = NULL;
        }
        c->closed = 1;
        return;
    }
    maybe_finish(c);
}

static void on_migrate(struct sim_host *h, unsigned core, struct utcp_sock *s)
{
    struct conn *c = utcp_sock_user(s);
    if (c)
        c->t = h->core[core];
}

static int run(const struct scen *sc)
{
    memset(&G, 0, sizeof(G));
    G.sc = sc;
    sim_init(&G.sim, &sc->link, &sc->a, &sc->b, 0x1234567ULL);
    G.sim.on_event = on_event;
    G.sim.on_migrate = on_migrate;
    struct sim_host *A = &G.sim.host[0], *B = &G.sim.host[1];
    struct utcp_sock *lsn[SIM_MAX_CORES] = {0};
    if (!sc->expect_refused)
        for (unsigned c = 0; c < B->cfg.ncores; c++) {
            lsn[c] = utcp_listen(B->core[c], PORT, 4096);
            utcp_setopt(B->core[c], lsn[c], UTCP_OPT_NODELAY, 1);
        }
    G.t0 = G.sim.now;
    for (int i = 0; i < sc->nconns; i++) {
        unsigned core = (unsigned)i % A->cfg.ncores;
        utcp_t *t = A->core[core];
        struct utcp_sock *s = utcp_connect(t, B->cfg.local_ip, PORT);
        if (!s) {
            fprintf(stderr, "  connect failed: %s\n", strerror(errno));
            return 1;
        }
        struct utcp_info in;
        utcp_sock_info(s, &in);
        struct conn *c = conn_new();
        c->s = s;
        c->t = t;
        c->to_send = sc->c2s;
        c->to_recv = sc->s2c;
        c->seed_tx = in.local_port;
        c->seed_rx = in.local_port ^ 0x5555u;
        c->start_ns = G.sim.now;
        utcp_setopt(t, s, UTCP_OPT_NODELAY, 1);
        utcp_sock_set_user(s, c);
    }
    int want = sc->expect_refused ? sc->nconns : 2 * sc->nconns;
    uint64_t deadline = G.t0 + sc->time_limit_ns;
    while (G.done < want && !G.errors && G.sim.now < deadline) {
        sim_run_until(&G.sim, G.sim.now + 1000000ULL);
        uint64_t ms = (G.sim.now - G.t0) / 1000000ULL;
        if (getenv("TRACE") && ms % (uint64_t)atoi(getenv("TRACE")) == 0 && G.conns[0].s) {
            struct utcp_info in;
            utcp_sock_info(G.conns[0].s, &in);
            printf("  t=%4" PRIu64 "ms cwnd=%u ssth=%u inflight=%u srtt=%uus minrtt=%u snd_wnd=%u "
                   "ca=%u sent=%" PRIu64 "MB | out=%u sack=%u lost=%u rtx=%u\n",
                   ms, in.cwnd / in.mss, in.ssthresh == UINT32_MAX ? 0 : in.ssthresh / in.mss,
                   in.inflight / in.mss, in.srtt_us, in.min_rtt_us, in.snd_wnd, in.ca_state,
                   in.bytes_acked >> 20, in.unacked / in.mss, in.sacked / in.mss,
                   in.lost / in.mss, in.retrans / in.mss);
        }
#ifdef SIM_INTERNALS
#include <stdio.h>
        if (getenv("DUMPAT") && ms == (uint64_t)atoi(getenv("DUMPAT"))) {
            struct utcp_sock *srv = NULL;
            for (int i = 0; i < G.nconn; i++)
                if (G.conns[i].side == 1)
                    srv = G.conns[i].s;
            dump(G.conns[0].s, srv);
        }
#endif
        if (sc->migrate_at_ms && !G.migrated && ms >= (uint64_t)sc->migrate_at_ms) {
            int moved = 0, socks = 0;
            for (uint32_t b = 0; b < utcp_nbuckets(B->region); b++)
                if (utcp_bucket_owner(B->region, b) == 0) {
                    int r = utcp_migrate_bucket(B->core[0], b, 1 + b % (B->cfg.ncores - 1));
                    if (r >= 0) {
                        moved++;
                        socks += r;
                    }
                }
            printf("  migrated %d buckets (%d sockets) from core 0\n", moved, socks);
            G.migrated = 1;
        }
        if (sc->pause_server_ms && ms >= (uint64_t)sc->pause_server_ms)
            for (int i = 0; i < G.nconn; i++)
                if (G.conns[i].side == 1 && G.conns[i].paused) {
                    G.conns[i].paused = 0;
                    pump_recv(&G.conns[i]);
                    maybe_finish(&G.conns[i]);
                }
    }
    uint64_t data_done = G.sim.now;
    /* drain: TIME_WAIT etc. */
    for (unsigned c = 0; c < B->cfg.ncores; c++)
        if (lsn[c])
            utcp_close(B->core[c], lsn[c]);
    sim_run_until(&G.sim, G.sim.now + 200ULL * 1000000000ULL);

    int fail = 0;
    if (G.done < want) {
        printf("  FAIL: only %d/%d endpoints completed\n", G.done, want);
        fail = 1;
    }
    if (G.errors || G.bad) {
        printf("  FAIL: errors=%d bad=%d\n", G.errors, G.bad);
        fail = 1;
    }
    for (int h = 0; h < 2; h++) {
        struct utcp_stats st;
        utcp_stats_get(G.sim.host[h].region, -1, &st);
        if (st.socks_alloc != st.socks_free) {
            printf("  FAIL: host %d leaked sockets alloc=%" PRIu64 " free=%" PRIu64 "\n", h,
                   st.socks_alloc, st.socks_free);
            fail = 1;
        }
        if (G.sim.host[h].bufs_out) {
            printf("  FAIL: host %d leaked %" PRIu64 " buffers\n", h, G.sim.host[h].bufs_out);
            fail = 1;
        }
    }
    struct utcp_stats sa, sb;
    utcp_stats_get(A->region, -1, &sa);
    utcp_stats_get(B->region, -1, &sb);
    double secs = (data_done - G.t0) / 1e9;
    uint64_t bytes = (sc->c2s + sc->s2c) * (uint64_t)sc->nconns;
    double gbps = bytes * 8 / secs / 1e9;
    if (!sc->expect_refused)
        printf("  %.3fs sim, goodput %.2f Gbit/s, retrans A=%" PRIu64 " B=%" PRIu64
               ", drops q=%" PRIu64 " rnd=%" PRIu64 ", handoff B=%" PRIu64 "\n",
               secs, gbps, sa.tcp_retrans_segs, sb.tcp_retrans_segs, G.sim.drops_queue,
               G.sim.drops_random, sb.handoff_out);
    if (getenv("TRACE"))
        printf("  B rx: pkts=%" PRIu64 " csum=%" PRIu64 " short=%" PRIu64 " noproto=%" PRIu64
               " ooo=%" PRIu64 " rst=%" PRIu64 "\n",
               sb.rx_pkts, sb.rx_drop_csum, sb.rx_drop_short, sb.rx_drop_noproto,
               sb.tcp_ooo_pkts, sb.tcp_rst_sent);
    if (!sc->expect_refused)
        printf("  per-conn totals: segs_out=%" PRIu64 " retrans=%" PRIu64 " rto=%" PRIu64
               " tlp=%" PRIu64 " recoveries=%" PRIu64 " dsacks=%" PRIu64 " undos=%" PRIu64 "\n",
               G.osegs, G.rsegs, G.rto, G.tlp, G.rec, G.dsacks, G.undos);
    if (sc->link.reorder == 0 && G.dsacks > 0) {
        /* FIFO link: any D-SACK means we retransmitted something not lost */
        printf("  FAIL: %" PRIu64 " spurious retransmissions on a FIFO link\n", G.dsacks);
        fail = 1;
    }
    if (sc->min_gbps > 0 && gbps < sc->min_gbps) {
        printf("  FAIL: goodput %.2f < %.2f Gbit/s\n", gbps, sc->min_gbps);
        fail = 1;
    }
    sim_destroy(&G.sim);
    return fail;
}

#define MB (1024ull * 1024)
#define SEC 1000000000ULL

int main(int argc, char **argv)
{
    static const struct scen scens[] = {
        {.name = "basic: 1 conn, 1MB each way",
         .link = {.gbps = 1, .delay_ns = 500000, .queue_bytes = 1 * MB},
         .a = {.ncores = 1}, .b = {.ncores = 1},
         .nconns = 1, .c2s = 1 * MB, .s2c = 1 * MB, .time_limit_ns = 10 * SEC},
        {.name = "refused: connect to closed port -> ECONNREFUSED",
         .link = {.gbps = 1, .delay_ns = 500000, .queue_bytes = 1 * MB},
         .a = {.ncores = 1}, .b = {.ncores = 1},
         .nconns = 3, .time_limit_ns = 5 * SEC, .expect_refused = 1},
        {.name = "bulk TSO: 10G, 2ms RTT, 1 BDP queue, 400MB",
         .link = {.gbps = 10, .delay_ns = 1000000, .queue_bytes = 2500000},
         .a = {.ncores = 1, .tso = true}, .b = {.ncores = 1, .tso = true, .rcvbuf = 16 * MB},
         .nconns = 1, .c2s = 400 * MB, .time_limit_ns = 60 * SEC, .min_gbps = 7.5},
        {.name = "taildrop: 1 flow, 10G 2ms RTT, queue 0.25 BDP, 200MB",
         .link = {.gbps = 10, .delay_ns = 1000000, .queue_bytes = 625000},
         .a = {.ncores = 1, .tso = true}, .b = {.ncores = 1, .tso = true, .rcvbuf = 16 * MB},
         .nconns = 1, .c2s = 200 * MB, .time_limit_ns = 60 * SEC},
        {.name = "bulk no-TSO, sw checksums, 1G 20ms RTT, 100MB",
         .link = {.gbps = 1, .delay_ns = 10000000, .queue_bytes = 2500000},
         .a = {.ncores = 1}, .b = {.ncores = 1, .rcvbuf = 8 * MB},
         .nconns = 1, .c2s = 100 * MB, .time_limit_ns = 60 * SEC, .min_gbps = 0.8},
        {.name = "random loss 1%, 1G 10ms RTT, 20MB",
         .link = {.gbps = 1, .delay_ns = 5000000, .queue_bytes = 2 * MB, .loss = 0.01},
         .a = {.ncores = 1, .tso = true}, .b = {.ncores = 1},
         .nconns = 1, .c2s = 20 * MB, .s2c = 1 * MB, .time_limit_ns = 120 * SEC},
        {.name = "heavy loss 5%, 100M 20ms RTT, 4MB",
         .link = {.gbps = 0.1, .delay_ns = 10000000, .queue_bytes = 1 * MB, .loss = 0.05},
         .a = {.ncores = 1}, .b = {.ncores = 1},
         .nconns = 1, .c2s = 4 * MB, .s2c = 4 * MB, .time_limit_ns = 600 * SEC},
        {.name = "reordering 3% (+3ms), 1G 4ms RTT, 50MB",
         .link = {.gbps = 1, .delay_ns = 2000000, .queue_bytes = 2 * MB, .reorder = 0.03,
                  .reorder_ns = 3000000},
         .a = {.ncores = 1, .tso = true}, .b = {.ncores = 1},
         .nconns = 1, .c2s = 50 * MB, .time_limit_ns = 120 * SEC},
        {.name = "full duplex: 100MB both directions concurrently, 10G",
         .link = {.gbps = 10, .delay_ns = 500000, .queue_bytes = 2 * MB},
         .a = {.ncores = 1, .tso = true}, .b = {.ncores = 1, .tso = true},
         .nconns = 1, .c2s = 100 * MB, .s2c = 100 * MB, .time_limit_ns = 60 * SEC,
         .min_gbps = 12},
        {.name = "many conns: 1000 x 64KB each way",
         .link = {.gbps = 10, .delay_ns = 200000, .queue_bytes = 4 * MB},
         .a = {.ncores = 1, .tso = true}, .b = {.ncores = 1, .tso = true},
         .nconns = 1000, .c2s = 65536, .s2c = 65536, .time_limit_ns = 60 * SEC},
        {.name = "multicore RSS: 4x4 cores, 64 conns x 2MB each way",
         .link = {.gbps = 10, .delay_ns = 200000, .queue_bytes = 4 * MB},
         .a = {.ncores = 4, .tso = true}, .b = {.ncores = 4, .tso = true},
         .nconns = 64, .c2s = 2 * MB, .s2c = 2 * MB, .time_limit_ns = 60 * SEC},
        {.name = "multicore spray (no RSS, handoff rings): 4 cores, 32 conns x 2MB",
         .link = {.gbps = 10, .delay_ns = 200000, .queue_bytes = 4 * MB},
         .a = {.ncores = 2, .tso = true, .spray = true},
         .b = {.ncores = 4, .tso = true, .spray = true},
         .nconns = 32, .c2s = 2 * MB, .s2c = 2 * MB, .time_limit_ns = 60 * SEC},
        {.name = "migration: move all core-0 buckets mid-transfer, 4 cores, 32 x 8MB",
         .link = {.gbps = 10, .delay_ns = 500000, .queue_bytes = 4 * MB},
         .a = {.ncores = 1, .tso = true}, .b = {.ncores = 4, .tso = true},
         .nconns = 32, .c2s = 8 * MB, .s2c = 8 * MB, .time_limit_ns = 60 * SEC,
         .migrate_at_ms = 30},
        {.name = "zero window: server stops reading for 2s, 64KB rcvbuf",
         .link = {.gbps = 1, .delay_ns = 1000000, .queue_bytes = 1 * MB},
         .a = {.ncores = 1}, .b = {.ncores = 1, .rcvbuf = 65536},
         .nconns = 1, .c2s = 8 * MB, .time_limit_ns = 60 * SEC, .pause_server_ms = 2000},
        {.name = "reno cc, 1G 10ms, 0.1% loss, 30MB",
         .link = {.gbps = 1, .delay_ns = 5000000, .queue_bytes = 1 * MB, .loss = 0.001},
         .a = {.ncores = 1, .tso = true, .cc = UTCP_CC_RENO},
         .b = {.ncores = 1, .cc = UTCP_CC_RENO},
         .nconns = 1, .c2s = 30 * MB, .time_limit_ns = 120 * SEC},
    };
    int n = (int)(sizeof(scens) / sizeof(scens[0])), fails = 0;
    const char *only = argc > 1 ? argv[1] : NULL;
    for (int i = 0; i < n; i++) {
        if (only && !strstr(scens[i].name, only))
            continue;
        printf("[%2d] %s\n", i, scens[i].name);
        fflush(stdout);
        int f = run(&scens[i]);
        printf("  %s\n", f ? "FAILED" : "ok");
        fails += f;
    }
    printf("%s: %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
