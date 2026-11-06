/* utcp-app: one benchmark application, two interchangeable TCP backends. */
#ifndef APP_H
#define APP_H

#include "shm.h"
#include "utcp.h"

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

enum backend { BE_UTCP, BE_KERNEL };
enum role { ROLE_SERVER, ROLE_CLIENT };
enum workload { WL_STREAM, WL_RR, WL_CRR };

struct opts {
    enum backend backend;
    enum role role;
    enum workload wl;
    int workers;
    int cpu0;               /* first CPU to pin to (-1 = no pinning) */
    uint32_t local_ip;      /* network order */
    uint32_t peer_ip;       /* client: server address */
    uint32_t gw_ip;
    uint16_t port;
    char tap[16];
    uint8_t mac[6];
    int conns;              /* client: concurrent connections per worker */
    uint64_t c2s, s2c;      /* stream bytes per connection */
    uint32_t req, resp;     /* rr/crr message sizes */
    double duration;        /* seconds (rr/crr; stream: upper bound) */
    bool verify;
    uint32_t nbufs;         /* utcp packet buffers per worker */
    uint32_t buf_size;
    bool busy_poll;
    bool tso;
    uint32_t sndbuf, rcvbuf;
    bool json;
    int cc;
};

#define HIST_BUCKETS (64 * 16)

/* Per-worker counters in shared memory, read by the zygote. */
struct wstats {
    _Atomic uint64_t bytes_tx, bytes_rx;
    _Atomic uint64_t conns_opened, conns_done, conn_errors, verify_errors;
    _Atomic uint64_t transactions;
    _Atomic uint64_t busy_ns, stack_ns, io_ns, loops;
    _Atomic int finished;
    _Atomic uint64_t hist[HIST_BUCKETS]; /* latency in ns, log-linear */
    _Atomic uint64_t restarts;
    _Atomic uint64_t t_begin, t_end; /* client: workload start / completion */
} __attribute__((aligned(128)));

struct shared {
    struct shm *m;
    struct opts o;
    struct utcp_region *region;
    _Atomic int stop;
    _Atomic uint64_t start_ns;
    struct wstats ws[APP_MAX_WORKERS];
    void *wconns[APP_MAX_WORKERS]; /* per-worker connection table (shared, survives restarts) */
    int wconns_n;
};

struct worker;

/* Transport: a minimal non-blocking socket API with readiness callbacks. */
struct transport {
    const char *name;
    int (*init)(struct worker *w);
    int (*listen)(struct worker *w, uint16_t port);
    void *(*connect)(struct worker *w, uint32_t ip, uint16_t port);
    ssize_t (*send)(struct worker *w, void *h, const void *buf, size_t len);
    ssize_t (*recv)(struct worker *w, void *h, void *buf, size_t len);
    /* optional zero-copy receive (NULL for the kernel backend) */
    int (*recv_zc)(struct worker *w, void *h, struct utcp_iov *iov, int max);
    void (*consume)(struct worker *w, void *h, size_t n);
    void (*shutdown_wr)(struct worker *w, void *h);
    void (*close)(struct worker *w, void *h);
    void (*set_user)(struct worker *w, void *h, void *user);
    /* Process I/O; may block up to timeout_us when idle. Returns work done. */
    int (*run)(struct worker *w, int timeout_us);
};

/* Callbacks from transport to workload. */
void wl_on_accept(struct worker *w, void *h);
void wl_on_connected(struct worker *w, void *user);
void wl_on_readable(struct worker *w, void *user);
void wl_on_writable(struct worker *w, void *user);
void wl_on_closed(struct worker *w, void *user, int err);

struct worker {
    int id;
    struct shared *sh;
    struct opts *o;
    struct wstats *st;
    const struct transport *tp;
    void *be;                /* backend private */
    uint64_t now;
    struct conn *conns;      /* workload state */
    int nconns_max;
    struct conn *free_conns;
    int active;
    uint64_t stop_at;
    bool stopping;
};

#define MIN_U32(a, b) ((uint32_t)(a) < (uint32_t)(b) ? (uint32_t)(a) : (uint32_t)(b))
#define MIN_U64(a, b) ((uint64_t)(a) < (uint64_t)(b) ? (uint64_t)(a) : (uint64_t)(b))
static inline uint32_t htonl_mask24(void) { return __builtin_bswap32(0xffffff00u); }

uint64_t now_ns(void);
void hist_add(struct wstats *st, uint64_t ns);
uint64_t hist_pct(const uint64_t *h, double pct);

extern const struct transport tp_utcp, tp_kernel;
int wl_start(struct worker *w);
void wl_tick(struct worker *w);
bool wl_done(struct worker *w);
size_t wl_conn_size(void);
void wl_dump(struct worker *w); /* SIGUSR1: print per-connection state */
void utcp_backend_dump(struct worker *w, void *h);

#endif
