/* utcp-app: zygote + per-core workers.
 *
 * The zygote maps one shared region, creates the utcp region inside it (utcp
 * backend), then forks one worker per core. Workers inherit the mapping at
 * the same virtual address. A worker that dies is re-forked and re-attaches
 * to its core, keeping the core's sessions. */

#include "app.h"

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

int utcp_backend_setup(struct shared *sh);

static struct shared *SH;
static volatile sig_atomic_t g_stop;

static volatile sig_atomic_t g_dump;
static void on_usr1(int s)
{
    (void)s;
    g_dump = 1;
}

static void on_sig(int s)
{
    (void)s;
    g_stop = 1;
    if (SH)
        atomic_store(&SH->stop, 1);
}

static void usage(void)
{
    fprintf(stderr,
            "usage: utcp-app --backend utcp|kernel --role server|client [options]\n"
            "  --workers N        worker processes (one per core)       [1]\n"
            "  --cpu N            pin worker i to CPU N+i (-1: no pin)   [-1]\n"
            "  --ip A.B.C.D       local address (utcp: stack IP)\n"
            "  --peer A.B.C.D     client: server address\n"
            "  --gw A.B.C.D       utcp: default gateway\n"
            "  --port P           [5001]\n"
            "  --tap NAME         utcp: multi-queue TAP device           [utap0]\n"
            "  --mac XX:..        utcp: stack MAC                        [02:00:00:00:00:02]\n"
            "  --workload stream|rr|crr                                  [stream]\n"
            "  --conns N          client: connections per worker         [1]\n"
            "  --c2s BYTES --s2c BYTES   stream sizes per connection     [1G 0]\n"
            "  --req B --resp B   rr/crr message sizes                   [64 64]\n"
            "  --duration SEC     rr/crr run time; stream deadline       [10]\n"
            "  --no-verify        skip payload verification\n"
            "  --busy-poll        never sleep\n"
            "  --no-tso           utcp: disable TSO\n"
            "  --bufs N --buf-size B   utcp packet buffers per worker    [32768 16384]\n"
            "  --sndbuf B --rcvbuf B\n"
            "  --cc cubic|reno\n"
            "  --json             machine-readable summary\n");
    exit(2);
}

static uint64_t parse_size(const char *s)
{
    char *e;
    double v = strtod(s, &e);
    switch (*e) {
    case 'k': case 'K': v *= 1024; break;
    case 'm': case 'M': v *= 1024 * 1024; break;
    case 'g': case 'G': v *= 1024.0 * 1024 * 1024; break;
    }
    return (uint64_t)v;
}

static void parse(int argc, char **argv, struct opts *o)
{
    memset(o, 0, sizeof(*o));
    o->workers = 1;
    o->cpu0 = -1;
    o->port = 5001;
    snprintf(o->tap, sizeof(o->tap), "utap0");
    uint8_t mac[6] = {0x02, 0, 0, 0, 0, 0x02};
    memcpy(o->mac, mac, 6);
    o->conns = 1;
    o->c2s = 1ull << 30;
    o->req = o->resp = 64;
    o->duration = 10;
    o->verify = true;
    o->nbufs = 32768;
    o->buf_size = 16384;
    o->tso = true;
    o->role = ROLE_SERVER;
    enum { O_BACKEND = 256, O_ROLE, O_WORKERS, O_CPU, O_IP, O_PEER, O_GW, O_PORT, O_TAP, O_MAC,
           O_WL, O_CONNS, O_C2S, O_S2C, O_REQ, O_RESP, O_DUR, O_NOVERIFY, O_BUSY, O_NOTSO,
           O_BUFS, O_BUFSZ, O_SNDBUF, O_RCVBUF, O_JSON, O_CC };
    static const struct option lo[] = {
        {"backend", 1, 0, O_BACKEND}, {"role", 1, 0, O_ROLE},       {"workers", 1, 0, O_WORKERS},
        {"cpu", 1, 0, O_CPU},         {"ip", 1, 0, O_IP},           {"peer", 1, 0, O_PEER},
        {"gw", 1, 0, O_GW},           {"port", 1, 0, O_PORT},       {"tap", 1, 0, O_TAP},
        {"mac", 1, 0, O_MAC},         {"workload", 1, 0, O_WL},     {"conns", 1, 0, O_CONNS},
        {"c2s", 1, 0, O_C2S},         {"s2c", 1, 0, O_S2C},         {"req", 1, 0, O_REQ},
        {"resp", 1, 0, O_RESP},       {"duration", 1, 0, O_DUR},    {"no-verify", 0, 0, O_NOVERIFY},
        {"busy-poll", 0, 0, O_BUSY},  {"no-tso", 0, 0, O_NOTSO},    {"bufs", 1, 0, O_BUFS},
        {"buf-size", 1, 0, O_BUFSZ},  {"sndbuf", 1, 0, O_SNDBUF},   {"rcvbuf", 1, 0, O_RCVBUF},
        {"json", 0, 0, O_JSON},       {"cc", 1, 0, O_CC},           {0, 0, 0, 0},
    };
    int c;
    while ((c = getopt_long(argc, argv, "h", lo, NULL)) != -1) {
        switch (c) {
        case O_BACKEND:
            o->backend = !strcmp(optarg, "kernel") ? BE_KERNEL : BE_UTCP;
            break;
        case O_ROLE: o->role = !strcmp(optarg, "client") ? ROLE_CLIENT : ROLE_SERVER; break;
        case O_WORKERS: o->workers = atoi(optarg); break;
        case O_CPU: o->cpu0 = atoi(optarg); break;
        case O_IP: o->local_ip = inet_addr(optarg); break;
        case O_PEER: o->peer_ip = inet_addr(optarg); break;
        case O_GW: o->gw_ip = inet_addr(optarg); break;
        case O_PORT: o->port = (uint16_t)atoi(optarg); break;
        case O_TAP: snprintf(o->tap, sizeof(o->tap), "%s", optarg); break;
        case O_MAC:
            if (sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &o->mac[0], &o->mac[1],
                       &o->mac[2], &o->mac[3], &o->mac[4], &o->mac[5]) != 6)
                usage();
            break;
        case O_WL:
            o->wl = !strcmp(optarg, "rr") ? WL_RR : !strcmp(optarg, "crr") ? WL_CRR : WL_STREAM;
            break;
        case O_CONNS: o->conns = atoi(optarg); break;
        case O_C2S: o->c2s = parse_size(optarg); break;
        case O_S2C: o->s2c = parse_size(optarg); break;
        case O_REQ: o->req = (uint32_t)parse_size(optarg); break;
        case O_RESP: o->resp = (uint32_t)parse_size(optarg); break;
        case O_DUR: o->duration = atof(optarg); break;
        case O_NOVERIFY: o->verify = false; break;
        case O_BUSY: o->busy_poll = true; break;
        case O_NOTSO: o->tso = false; break;
        case O_BUFS: o->nbufs = (uint32_t)atoi(optarg); break;
        case O_BUFSZ: o->buf_size = (uint32_t)parse_size(optarg); break;
        case O_SNDBUF: o->sndbuf = (uint32_t)parse_size(optarg); break;
        case O_RCVBUF: o->rcvbuf = (uint32_t)parse_size(optarg); break;
        case O_JSON: o->json = true; break;
        case O_CC: o->cc = !strcmp(optarg, "reno") ? UTCP_CC_RENO : UTCP_CC_CUBIC; break;
        default: usage();
        }
    }
    if (o->workers < 1 || o->workers > APP_MAX_WORKERS || !o->local_ip ||
        (o->role == ROLE_CLIENT && !o->peer_ip))
        usage();
    if (o->req > 256 * 1024 || o->resp > 256 * 1024 || !o->req || !o->resp)
        usage();
}

/* ------------------------------------------------------------- worker */

static int worker_main(int id)
{
    struct worker w;
    memset(&w, 0, sizeof(w));
    w.id = id;
    w.sh = SH;
    w.o = &SH->o;
    w.st = &SH->ws[id];
    w.tp = SH->o.backend == BE_UTCP ? &tp_utcp : &tp_kernel;
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (SH->o.cpu0 >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(SH->o.cpu0 + id, &set);
        if (sched_setaffinity(0, sizeof(set), &set))
            perror("sched_setaffinity");
    }
    w.st->t_begin = now_ns();
    if (w.tp->init(&w) || wl_start(&w)) {
        fprintf(stderr, "worker %d: init failed\n", id);
        return 1;
    }
    while (!atomic_load_explicit(&SH->stop, memory_order_relaxed) && !wl_done(&w)) {
        uint64_t t0 = now_ns();
        int work = w.tp->run(&w, 1000);
        wl_tick(&w);
        if (g_dump) {
            g_dump = 0;
            wl_dump(&w);
        }
        if (work)
            atomic_fetch_add_explicit(&w.st->busy_ns, now_ns() - t0, memory_order_relaxed);
        atomic_fetch_add_explicit(&w.st->loops, 1, memory_order_relaxed);
    }
    w.st->t_end = now_ns();
    /* let FIN/ACK exchanges finish */
    uint64_t end = now_ns() + 200000000ULL;
    while (now_ns() < end && SH->o.role == ROLE_CLIENT)
        w.tp->run(&w, 1000);
    atomic_store(&w.st->finished, 1);
    return 0;
}

static pid_t spawn(int id)
{
    pid_t p = fork();
    if (p == 0)
        _exit(worker_main(id));
    return p;
}

/* ------------------------------------------------------------ summary */

static uint64_t m_pool_fail(int i) { return SH->m->pool[i].alloc_fail; }

static void summary(double secs)
{
    struct opts *o = &SH->o;
    uint64_t tx = 0, rx = 0, opened = 0, done = 0, errs = 0, verr = 0, trans = 0, busy = 0,
             stack = 0, io = 0, restarts = 0;
    static uint64_t hist[HIST_BUCKETS];
    memset(hist, 0, sizeof(hist));
    for (int i = 0; i < o->workers; i++) {
        struct wstats *s = &SH->ws[i];
        tx += s->bytes_tx;
        rx += s->bytes_rx;
        opened += s->conns_opened;
        done += s->conns_done;
        errs += s->conn_errors;
        verr += s->verify_errors;
        trans += s->transactions;
        busy += s->busy_ns;
        stack += s->stack_ns;
        io += s->io_ns;
        restarts += s->restarts;
        for (int k = 0; k < HIST_BUCKETS; k++)
            hist[k] += s->hist[k];
    }
    struct rusage ru;
    getrusage(RUSAGE_CHILDREN, &ru);
    double cpu = ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6 + ru.ru_stime.tv_sec +
                 ru.ru_stime.tv_usec / 1e6;
    double usr = ru.ru_utime.tv_sec + ru.ru_utime.tv_usec / 1e6;
    const char *be = o->backend == BE_UTCP ? "utcp" : "kernel";
    const char *wl = o->wl == WL_STREAM ? "stream" : o->wl == WL_RR ? "rr" : "crr";
    double gbps = (double)(tx + rx) * 8 / secs / 1e9;
    if (o->json) {
        printf("{\"backend\":\"%s\",\"role\":\"%s\",\"workload\":\"%s\",\"workers\":%d,"
               "\"secs\":%.3f,\"tx_bytes\":%" PRIu64 ",\"rx_bytes\":%" PRIu64
               ",\"gbps\":%.3f,\"conns_opened\":%" PRIu64 ",\"conns_done\":%" PRIu64
               ",\"conn_errors\":%" PRIu64 ",\"verify_errors\":%" PRIu64
               ",\"transactions\":%" PRIu64 ",\"tps\":%.0f,\"p50_us\":%.1f,\"p90_us\":%.1f,"
               "\"p99_us\":%.1f,\"p999_us\":%.1f,\"cpu_s\":%.3f,\"usr_s\":%.3f,"
               "\"stack_s\":%.3f,\"io_s\":%.3f,\"restarts\":%" PRIu64 "}\n",
               be, o->role == ROLE_CLIENT ? "client" : "server", wl, o->workers, secs, tx, rx,
               gbps, opened, done, errs, verr, trans, trans / secs, hist_pct(hist, 50) / 1e3,
               hist_pct(hist, 90) / 1e3, hist_pct(hist, 99) / 1e3, hist_pct(hist, 99.9) / 1e3,
               cpu, usr, stack / 1e9, io / 1e9, restarts);
        return;
    }
    printf("== %s %s %s: %d worker(s), %.2fs\n", be, o->role == ROLE_CLIENT ? "client" : "server",
           wl, o->workers, secs);
    printf("   goodput   %.3f Gbit/s (tx %.1f MB, rx %.1f MB)\n", gbps, tx / 1e6, rx / 1e6);
    printf("   conns     opened %" PRIu64 ", completed %" PRIu64 ", errors %" PRIu64
           ", verify errors %" PRIu64 "\n", opened, done, errs, verr);
    if (trans)
        printf("   trans     %" PRIu64 " (%.0f/s)  latency p50 %.1f p90 %.1f p99 %.1f p99.9 %.1f us\n",
               trans, trans / secs, hist_pct(hist, 50) / 1e3, hist_pct(hist, 90) / 1e3,
               hist_pct(hist, 99) / 1e3, hist_pct(hist, 99.9) / 1e3);
    printf("   cpu       %.2fs (user %.2fs); stack %.2fs, io %.2fs; restarts %" PRIu64 "\n", cpu,
           usr, stack / 1e9, io / 1e9, restarts);
    if (o->workers > 1) {
        printf("   per-worker");
        for (int i = 0; i < o->workers; i++)
            printf(" [%d: %.0fMB conns %" PRIu64 " busy %.2fs]", i,
                   (SH->ws[i].bytes_rx + SH->ws[i].bytes_tx) / 1e6, SH->ws[i].conns_opened,
                   SH->ws[i].busy_ns / 1e9);
        printf("\n");
    }
    if (o->backend == BE_UTCP && SH->region) {
        struct utcp_stats u;
        utcp_stats_get(SH->region, -1, &u);
        printf("   utcp      rx %" PRIu64 " tx %" PRIu64 " pkts; retrans %" PRIu64 " ooo %" PRIu64
               " rst %" PRIu64 " listen_drops %" PRIu64 " csum_drops %" PRIu64
               "; handoff out %" PRIu64 " drop %" PRIu64 "; socks %" PRIu64 "/%" PRIu64
               " (alloc/free) arp_miss %" PRIu64 "\n   recovery  episodes %" PRIu64
               " undos %" PRIu64 " tlp %" PRIu64 " rto %" PRIu64 " dsacks %" PRIu64 "\n",
               u.rx_pkts, u.tx_pkts, u.tcp_retrans_segs, u.tcp_ooo_pkts, u.tcp_rst_sent,
               u.tcp_listen_drops, u.rx_drop_csum, u.handoff_out, u.handoff_drop, u.socks_alloc,
               u.socks_free, u.arp_miss, u.tcp_recoveries, u.tcp_undos, u.tcp_tlp, u.tcp_rto,
               u.tcp_dsacks);
        uint64_t fails = 0;
        for (int i = 0; i < o->workers; i++)
            fails += m_pool_fail(i);
        printf("   buffers   alloc failures %" PRIu64 "\n", fails);
    }
}

int main(int argc, char **argv)
{
    struct opts o;
    parse(argc, argv, &o);
    setvbuf(stdout, NULL, _IOLBF, 0);
    size_t shm_size = sizeof(struct shared) + ((size_t)256 << 20);
    if (o.backend == BE_UTCP)
        shm_size += (size_t)o.workers * o.nbufs * (o.buf_size + 512) + ((size_t)64 << 20) * o.workers;
    struct shm *m = shm_create(shm_size);
    if (!m) {
        perror("mmap shared region");
        return 1;
    }
    m->buf_size = o.buf_size;
    m->headroom = 128;
    SH = shm_bump(m, sizeof(*SH), 4096);
    memset(SH, 0, sizeof(*SH));
    SH->m = m;
    SH->o = o;
    if (o.backend == BE_UTCP && utcp_backend_setup(SH))
        return 1;
    SH->wconns_n = o.role == ROLE_CLIENT ? o.conns : 65536;
    for (int i = 0; i < o.workers; i++) {
        SH->wconns[i] = shm_bump(m, wl_conn_size() * (size_t)SH->wconns_n, 128);
        if (!SH->wconns[i]) {
            fprintf(stderr, "out of shared memory for connection tables\n");
            return 1;
        }
    }

    struct sigaction sa = {.sa_handler = on_sig};
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    struct sigaction su = {.sa_handler = on_usr1};
    sigaction(SIGUSR1, &su, NULL);
    signal(SIGPIPE, SIG_IGN);

    pid_t pids[APP_MAX_WORKERS];
    uint64_t t0 = now_ns();
    SH->start_ns = t0;
    for (int i = 0; i < o.workers; i++)
        pids[i] = spawn(i);
    if (o.role == ROLE_SERVER)
        fprintf(stderr, "utcp-app: %s server, %d worker(s), port %u\n",
                o.backend == BE_UTCP ? "utcp" : "kernel", o.workers, o.port);

    int alive = o.workers;
    while (alive) {
        int status;
        pid_t p = waitpid(-1, &status, 0);
        if (p < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        for (int i = 0; i < o.workers; i++) {
            if (pids[i] != p)
                continue;
            bool crashed = WIFSIGNALED(status) || (WIFEXITED(status) && WEXITSTATUS(status));
            if (crashed && !g_stop && !SH->ws[i].finished && WIFSIGNALED(status) &&
                WTERMSIG(status) != SIGTERM && WTERMSIG(status) != SIGINT) {
                /* zygote restart: same core, same shared sessions */
                fprintf(stderr, "worker %d died (signal %d), restarting\n", i, WTERMSIG(status));
                atomic_fetch_add(&SH->ws[i].restarts, 1);
                pids[i] = spawn(i);
            } else {
                pids[i] = -1;
                alive--;
            }
        }
    }
    double secs = (now_ns() - t0) / 1e9;
    if (o.role == ROLE_CLIENT) {
        uint64_t b = UINT64_MAX, e = 0;
        for (int i = 0; i < o.workers; i++) {
            b = SH->ws[i].t_begin < b ? SH->ws[i].t_begin : b;
            e = SH->ws[i].t_end > e ? SH->ws[i].t_end : e;
        }
        if (e > b)
            secs = (e - b) / 1e9;
    }
    summary(secs);
    uint64_t verr = 0, errs = 0;
    for (int i = 0; i < o.workers; i++) {
        verr += SH->ws[i].verify_errors;
        errs += SH->ws[i].conn_errors;
    }
    return (verr || (o.role == ROLE_CLIENT && errs)) ? 1 : 0;
}
