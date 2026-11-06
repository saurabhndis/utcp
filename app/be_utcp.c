/* utcp backend: multi-queue TAP with virtio-net headers (TSO/GRO, partial
 * checksums). Each worker owns one TAP queue and one utcp core. */
#include "app.h"
#include "link.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/virtio_net.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define RX_BURST 64
#define MAX_FRAGS 8

struct ube {
    utcp_t *t;
    int fd;
    struct worker *w;
    uint64_t rx_pkts, tx_pkts, rx_gso, tx_gso;
};

static struct worker *g_w; /* one worker per process */
static struct link g_link;  /* set up by the zygote when --link is used */
static bool g_use_link;

/* Copy a packet into the peer's ring (one copy, like NIC DMA). A full ring is
 * given a short grace period, then the packet is dropped, as a NIC would. */
static void link_tx(struct worker *w, struct ube *u, struct utcp_buf *b)
{
    int q = link_tx_queue(&g_link, w->sh->region, b);
    struct link_ring *r = link_tx_ring(&g_link, q);
    uint32_t len = b->pkt_len;
    if (len > LINK_MAX_PKT)
        return;
    uint32_t need = link_rec_size(len);
    uint64_t h = atomic_load_explicit(&r->head, memory_order_relaxed);
    uint32_t pos = (uint32_t)(h % LINK_RING_BYTES);
    uint32_t pad = (pos + need > LINK_RING_BYTES) ? LINK_RING_BYTES - pos : 0;
    uint64_t deadline = 0;
    while (h + pad + need - atomic_load_explicit(&r->tail, memory_order_acquire) >
           LINK_RING_BYTES) {
        uint64_t now = now_ns();
        if (!deadline)
            deadline = now + 20000;
        else if (now > deadline) {
            __atomic_fetch_add(&r->drops, 1, __ATOMIC_RELAXED);
            return;
        }
    }
    if (pad) {
        ((struct link_rec *)(r->buf + pos))->len = LINK_WRAP;
        h += pad;
        pos = 0;
    }
    struct link_rec *rec = (struct link_rec *)(r->buf + pos);
    uint32_t off = 0;
    for (struct utcp_buf *f = b; f && off + f->len <= len; f = f->next) {
        memcpy(rec->data + off, f->data, f->len);
        off += f->len;
    }
    rec->len = off;
    rec->flags = UTCP_BUF_RX_CSUM_OK; /* trusted virtual wire, like virtio */
    rec->gso_size = 0;
    if ((b->flags & UTCP_BUF_TSO) && b->gso_size) {
        rec->flags |= UTCP_BUF_GRO;
        rec->gso_size = b->gso_size;
        u->tx_gso++;
    }
    atomic_store_explicit(&r->head, h + need, memory_order_release);
}

/* ---------------------------------------------------------------- ops */

static void *op_mem_alloc(void *ctx, size_t sz, size_t align)
{
    struct worker *w = ctx;
    (void)align; /* every block is 128-byte aligned */
    return shm_alloc(w->sh->m, w->id, sz);
}

static void op_mem_free(void *ctx, void *p)
{
    struct worker *w = ctx;
    shm_free(w->sh->m, w->id, p);
}

static struct utcp_buf *op_buf_alloc(void *ctx)
{
    struct worker *w = ctx;
    return shm_buf_alloc(w->sh->m, w->id);
}

static void op_buf_free(void *ctx, struct utcp_buf *b)
{
    struct worker *w = ctx;
    shm_buf_free(w->sh->m, w->id, b);
}

static uint64_t op_now(void *ctx)
{
    (void)ctx;
    return now_ns();
}

static int op_tx(void *ctx, struct utcp_buf **pkts, int n)
{
    struct worker *w = ctx;
    struct ube *u = w->be;
    uint64_t t0 = now_ns();
    for (int i = 0; g_use_link && i < n; i++) {
        link_tx(w, u, pkts[i]);
        u->tx_pkts++;
        utcp_pkt_free(u->t, pkts[i]);
    }
    if (g_use_link) {
        atomic_fetch_add_explicit(&w->st->io_ns, now_ns() - t0, memory_order_relaxed);
        return n;
    }
    for (int i = 0; i < n; i++) {
        struct utcp_buf *b = pkts[i];
        struct virtio_net_hdr vh = {0};
        if (b->flags & (UTCP_BUF_TX_CSUM | UTCP_BUF_TSO)) {
            vh.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
            vh.csum_start = b->l4_off;
            vh.csum_offset = 16;
        }
        if (b->flags & UTCP_BUF_TSO) {
            vh.gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
            vh.gso_size = b->gso_size;
            vh.hdr_len = (uint16_t)(b->l4_off + b->l4_hlen);
            u->tx_gso++;
        }
        struct iovec iov[1 + 64];
        int k = 0;
        iov[k].iov_base = &vh;
        iov[k++].iov_len = sizeof(vh);
        for (struct utcp_buf *f = b; f && k < 65; f = f->next) {
            iov[k].iov_base = f->data;
            iov[k++].iov_len = f->len;
        }
        if (writev(u->fd, iov, k) < 0 && errno != EAGAIN && errno != ENOBUFS)
            perror("tap writev");
        u->tx_pkts++;
        utcp_pkt_free(u->t, b);
    }
    atomic_fetch_add_explicit(&w->st->io_ns, now_ns() - t0, memory_order_relaxed);
    return n;
}

static void op_event(void *ctx, struct utcp_sock *s, uint32_t ev)
{
    struct worker *w = ctx;
    if (ev & UTCP_EV_ACCEPT) {
        struct utcp_sock *c;
        struct ube *u = w->be;
        while ((c = utcp_accept(u->t, s))) {
            utcp_setopt(u->t, c, UTCP_OPT_NODELAY, 1);
            wl_on_accept(w, c);
        }
        return;
    }
    void *user = utcp_sock_user(s);
    if (!user) {
        if (ev & UTCP_EV_CLOSED)
            utcp_close(((struct ube *)w->be)->t, s);
        return;
    }
    /* Each callback may release the connection: re-read the user pointer. */
    if ((ev & UTCP_EV_CONNECTED) && (user = utcp_sock_user(s)))
        wl_on_connected(w, user);
    if ((ev & (UTCP_EV_READABLE | UTCP_EV_EOF)) && (user = utcp_sock_user(s)))
        wl_on_readable(w, user);
    if ((ev & UTCP_EV_WRITABLE) && (user = utcp_sock_user(s)))
        wl_on_writable(w, user);
    if ((ev & (UTCP_EV_CLOSED | UTCP_EV_ERROR)) && !(user = utcp_sock_user(s))) {
        if (ev & UTCP_EV_CLOSED)
            utcp_close(((struct ube *)w->be)->t, s);
        return;
    }
    if (ev & (UTCP_EV_CLOSED | UTCP_EV_ERROR)) {
        utcp_sock_set_user(s, NULL);
        wl_on_closed(w, user, utcp_sock_error(s)); /* workload calls tp->close */
    }
}

static void op_migrate(void *ctx, struct utcp_sock *s, int from, int to)
{
    (void)ctx;
    (void)s;
    (void)from;
    (void)to; /* this app never migrates; sockets carry their own state */
}

static const struct utcp_ops OPS = {
    .mem_alloc = op_mem_alloc,
    .mem_free = op_mem_free,
    .buf_alloc = op_buf_alloc,
    .buf_free = op_buf_free,
    .tx_burst = op_tx,
    .now_ns = op_now,
    .on_event = op_event,
    .on_migrate = op_migrate,
};

/* Called once by the zygote, before forking. */
int utcp_backend_setup(struct shared *sh);
int utcp_backend_setup(struct shared *sh)
{
    struct opts *o = &sh->o;
    struct utcp_config cfg;
    utcp_config_default(&cfg);
    cfg.ncores = (uint32_t)o->workers;
    cfg.local_ip = o->local_ip;
    cfg.netmask = htonl_mask24();
    cfg.gateway = o->gw_ip;
    memcpy(cfg.mac, o->mac, 6);
    cfg.mtu = 1500;
    cfg.offloads = o->tso ? (UTCP_OFFLOAD_TSO | UTCP_OFFLOAD_TX_CSUM) : UTCP_OFFLOAD_TX_CSUM;
    if (o->sndbuf)
        cfg.sndbuf = o->sndbuf;
    if (o->rcvbuf)
        cfg.rcvbuf = o->rcvbuf;
    cfg.cc = (uint32_t)o->cc;
    cfg.flow_table_size = 1u << 16;
    if (o->max_tw)
        cfg.max_time_wait = o->max_tw;
    cfg.ring_size = 8192;
    struct worker zw = {.id = -1, .sh = sh};
    int rc = utcp_region_create(&cfg, &OPS, &zw, &sh->region);
    if (rc) {
        fprintf(stderr, "utcp_region_create: %s\n", strerror(-rc));
        return -1;
    }
    for (int i = 0; i < o->workers; i++)
        if (shm_pool_init(sh->m, i, o->nbufs)) {
            fprintf(stderr, "buffer pool: out of shared memory\n");
            return -1;
        }
    if (o->link[0]) {
        if (link_open(&g_link, o->link, o->role == ROLE_SERVER ? 0 : 1, o->workers))
            return -1;
        link_publish(&g_link, sh->region, o->local_ip, o->mac);
        g_use_link = true;
    }
    return 0;
}

static int tap_open(const char *name)
{
    int fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0) {
        perror("/dev/net/tun");
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR | IFF_MULTI_QUEUE;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        perror("TUNSETIFF");
        close(fd);
        return -1;
    }
    int hdr = sizeof(struct virtio_net_hdr);
    if (ioctl(fd, TUNSETVNETHDRSZ, &hdr) < 0)
        perror("TUNSETVNETHDRSZ");
    unsigned off = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
    if (ioctl(fd, TUNSETOFFLOAD, off) < 0)
        perror("TUNSETOFFLOAD");
    return fd;
}

#ifdef HAVE_BPF
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* Program the TAP's queue selection like NIC RSS: same key, same bucket
 * table. Returns 0 on success; handoff rings cover any failure. */
static int steer_attach(struct worker *w, int fd)
{
    char path[512];
    ssize_t n = readlink("/proc/self/exe", path, sizeof(path) - 32);
    if (n < 0)
        return -1;
    path[n] = 0;
    char *slash = strrchr(path, '/');
    snprintf(slash ? slash + 1 : path, 32, "steer.bpf.o");
    struct bpf_object *obj = bpf_object__open_file(path, NULL);
    if (!obj || bpf_object__load(obj)) {
        fprintf(stderr, "steering: cannot load %s\n", path);
        return -1;
    }
    struct utcp_region *r = w->sh->region;
    const uint8_t *key = utcp_rss_key(r);
    int tm = bpf_object__find_map_fd_by_name(obj, "toeplitz");
    int om = bpf_object__find_map_fd_by_name(obj, "owner");
    int cm = bpf_object__find_map_fd_by_name(obj, "conf");
    for (uint32_t pos = 0; pos < 12; pos++)
        for (uint32_t v = 0; v < 256; v++) {
            uint32_t h = 0;
            for (unsigned k = 0; k < 8; k++)
                if (v & (0x80u >> k)) {
                    unsigned bit = pos * 8 + k, byte = bit / 8;
                    uint64_t win = 0;
                    for (unsigned i = 0; i < 5; i++)
                        win = (win << 8) | (byte + i < 40 ? key[byte + i] : 0);
                    h ^= (uint32_t)(win >> (8 - bit % 8));
                }
            uint32_t idx = pos * 256 + v;
            bpf_map_update_elem(tm, &idx, &h, BPF_ANY);
        }
    uint32_t nb = utcp_nbuckets(r);
    for (uint32_t b = 0; b < nb; b++) {
        uint32_t o = (uint32_t)utcp_bucket_owner(r, b);
        bpf_map_update_elem(om, &b, &o, BPF_ANY);
    }
    uint32_t z = 0, mask = nb - 1;
    bpf_map_update_elem(cm, &z, &mask, BPF_ANY);
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "steer");
    int pfd = bpf_program__fd(prog);
    if (ioctl(fd, TUNSETSTEERINGEBPF, &pfd) < 0) {
        perror("TUNSETSTEERINGEBPF");
        return -1;
    }
    /* sanity check against the stack's own hash */
    uint32_t h = utcp_rss_hash(r, 0x0100000a, 0x0200000a, 0x3412, 0x8913);
    fprintf(stderr, "steering: eBPF RSS emulation attached (%u buckets, probe hash %08x)\n", nb,
            h);
    return 0;
}
#endif

static int u_init(struct worker *w)
{
    static struct ube u;
    memset(&u, 0, sizeof(u));
    u.w = w;
    w->be = &u;
    g_w = w;
    if (g_use_link) {
        u.fd = -1;
        if (link_wait_peer(&g_link, 10000)) {
            fprintf(stderr, "link: peer did not come up\n");
            return -1;
        }
        const struct link_side *peer = &g_link.h->side[!g_link.side];
        utcp_arp_add(w->sh->region, peer->ip, peer->mac); /* point-to-point wire */
    } else {
        u.fd = tap_open(w->o->tap);
        if (u.fd < 0)
            return -1;
    }
    u.t = utcp_attach(w->sh->region, (unsigned)w->id, &OPS, w);
    if (!u.t) {
        perror("utcp_attach");
        return -1;
    }
#ifdef HAVE_BPF
    if (w->id == 0 && !g_use_link && !getenv("UTCP_NO_STEER"))
        steer_attach(w, u.fd);
#endif
    return 0;
}

static int u_listen(struct worker *w, uint16_t port)
{
    struct ube *u = w->be;
    struct utcp_sock *l = utcp_listen(u->t, port, 65535);
    if (!l)
        return -1;
    utcp_setopt(u->t, l, UTCP_OPT_NODELAY, 1);
    return 0;
}

static void *u_connect(struct worker *w, uint32_t ip, uint16_t port)
{
    struct ube *u = w->be;
    struct utcp_sock *s = utcp_connect(u->t, ip, port);
    if (s)
        utcp_setopt(u->t, s, UTCP_OPT_NODELAY, 1);
    return s;
}

static ssize_t u_send(struct worker *w, void *h, const void *b, size_t n)
{
    return utcp_send(((struct ube *)w->be)->t, h, b, n);
}

static ssize_t u_recv(struct worker *w, void *h, void *b, size_t n)
{
    return utcp_recv(((struct ube *)w->be)->t, h, b, n);
}

static int u_recv_zc(struct worker *w, void *h, struct utcp_iov *iov, int max)
{
    return utcp_recv_zc(((struct ube *)w->be)->t, h, iov, max);
}

static void u_consume(struct worker *w, void *h, size_t n)
{
    utcp_recv_consume(((struct ube *)w->be)->t, h, n);
}

static void u_shutdown(struct worker *w, void *h)
{
    utcp_shutdown(((struct ube *)w->be)->t, h, UTCP_SHUT_WR);
}

static void u_close(struct worker *w, void *h)
{
    utcp_sock_set_user(h, NULL);
    utcp_close(((struct ube *)w->be)->t, h);
}

static void u_set_user(struct worker *w, void *h, void *user)
{
    (void)w;
    utcp_sock_set_user(h, user);
}

static int link_rx_burst(struct worker *w, struct ube *u)
{
    struct link_ring *r = link_rx_ring(&g_link, w->id);
    uint64_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);
    uint64_t h = atomic_load_explicit(&r->head, memory_order_acquire);
    struct utcp_buf *pkts[RX_BURST];
    struct shm *m = w->sh->m;
    int n = 0;
    uint64_t t0 = now_ns();
    while (t != h && n < RX_BURST) {
        uint32_t pos = (uint32_t)(t % LINK_RING_BYTES);
        struct link_rec *rec = (struct link_rec *)(r->buf + pos);
        if (rec->len == LINK_WRAP) {
            t += LINK_RING_BYTES - pos;
            continue;
        }
        struct utcp_buf *head = NULL, *prev = NULL;
        uint32_t off = 0;
        bool ok = true;
        while (off < rec->len) {
            struct utcp_buf *f = shm_buf_alloc(m, w->id);
            if (!f) {
                ok = false;
                break;
            }
            if (prev)
                f->data = f->base;
            uint32_t c = MIN_U32(rec->len - off, utcp_buf_tailroom(f));
            memcpy(f->data, rec->data + off, c);
            f->len = c;
            off += c;
            if (prev)
                prev->next = f;
            else
                head = f;
            prev = f;
        }
        uint32_t len = rec->len;
        uint16_t flags = rec->flags, gso = rec->gso_size;
        t += link_rec_size(len);
        if (!ok || !head) {
            if (head)
                utcp_pkt_free(u->t, head);
            continue;
        }
        head->pkt_len = len;
        head->flags = flags;
        head->gso_size = gso;
        if (gso)
            u->rx_gso++;
        pkts[n++] = head;
    }
    atomic_store_explicit(&r->tail, t, memory_order_release);
    uint64_t t1 = now_ns();
    atomic_fetch_add_explicit(&w->st->io_ns, t1 - t0, memory_order_relaxed);
    if (n) {
        u->rx_pkts += (uint64_t)n;
        utcp_input_burst(u->t, pkts, n);
        atomic_fetch_add_explicit(&w->st->stack_ns, now_ns() - t1, memory_order_relaxed);
    }
    return n;
}

static int rx_burst(struct worker *w, struct ube *u)
{
    if (g_use_link)
        return link_rx_burst(w, u);
    struct utcp_buf *pkts[RX_BURST];
    int n = 0;
    struct shm *m = w->sh->m;
    uint64_t t0 = now_ns();
    while (n < RX_BURST) {
        struct utcp_buf *frag[MAX_FRAGS];
        struct iovec iov[1 + MAX_FRAGS];
        struct virtio_net_hdr vh;
        iov[0].iov_base = &vh;
        iov[0].iov_len = sizeof(vh);
        int nf = 0;
        for (; nf < MAX_FRAGS; nf++) {
            frag[nf] = shm_buf_alloc(m, w->id);
            if (!frag[nf])
                break;
            if (nf)
                frag[nf]->data = frag[nf]->base;
            iov[1 + nf].iov_base = frag[nf]->data;
            iov[1 + nf].iov_len = utcp_buf_tailroom(frag[nf]);
        }
        if (nf == 0)
            break;
        ssize_t r = readv(u->fd, iov, 1 + nf);
        if (r <= (ssize_t)sizeof(vh)) {
            for (int i = 0; i < nf; i++)
                shm_buf_free(m, w->id, frag[i]);
            break;
        }
        uint32_t left = (uint32_t)(r - (ssize_t)sizeof(vh));
        struct utcp_buf *head = frag[0];
        head->pkt_len = left;
        int used = 0;
        for (; used < nf && left; used++) {
            uint32_t c = MIN_U32(left, utcp_buf_tailroom(frag[used]));
            frag[used]->len = c;
            left -= c;
            if (used)
                frag[used - 1]->next = frag[used];
        }
        for (int i = used; i < nf; i++)
            shm_buf_free(m, w->id, frag[i]);
        if (vh.flags & (VIRTIO_NET_HDR_F_NEEDS_CSUM | VIRTIO_NET_HDR_F_DATA_VALID))
            head->flags |= UTCP_BUF_RX_CSUM_OK;
        if (vh.gso_type != VIRTIO_NET_HDR_GSO_NONE && vh.gso_size) {
            head->flags |= UTCP_BUF_GRO;
            head->gso_size = vh.gso_size;
            u->rx_gso++;
        }
        pkts[n++] = head;
    }
    uint64_t t1 = now_ns();
    atomic_fetch_add_explicit(&w->st->io_ns, t1 - t0, memory_order_relaxed);
    if (n) {
        u->rx_pkts += (uint64_t)n;
        utcp_input_burst(u->t, pkts, n);
        atomic_fetch_add_explicit(&w->st->stack_ns, now_ns() - t1, memory_order_relaxed);
    }
    return n;
}

static int u_run(struct worker *w, int timeout_us)
{
    struct ube *u = w->be;
    int work = rx_burst(w, u);
    uint64_t t0 = now_ns();
    work += utcp_poll(u->t);
    atomic_fetch_add_explicit(&w->st->stack_ns, now_ns() - t0, memory_order_relaxed);
    static unsigned idle;
    if (g_use_link) { /* no fd to sleep on: spin briefly, then nap */
        idle = work ? 0 : idle + 1;
        if (!w->o->busy_poll && idle > 2000) {
            uint64_t nt = utcp_next_timer(u->t), now = now_ns();
            if (nt > now + 20000)
                nanosleep(&(struct timespec){0, 20000}, NULL);
        }
        return work;
    }
    if (!work && timeout_us > 0 && !w->o->busy_poll) {
        uint64_t nt = utcp_next_timer(u->t), now = now_ns();
        int to = timeout_us;
        if (nt != UINT64_MAX)
            to = nt <= now ? 0 : (int)MIN_U64((nt - now) / 1000, (uint64_t)timeout_us);
        if (to > 0) {
            struct pollfd p = {.fd = u->fd, .events = POLLIN};
            /* handoff rings from other workers are checked at least every 200us */
            ppoll(&p, 1, &(struct timespec){0, (long)MIN_U64((uint64_t)to, 200) * 1000}, NULL);
        }
    }
    return work;
}

static void count_state(void *arg, struct utcp_sock *s)
{
    struct utcp_info i;
    utcp_sock_info(s, &i);
    ((unsigned *)arg)[i.state]++;
}

void utcp_backend_census(struct worker *w)
{
    unsigned n[16] = {0};
    utcp_foreach_sock(((struct ube *)w->be)->t, count_state, n);
    fprintf(stderr, "  worker %d sockets:", w->id);
    for (int st = 0; st < 11; st++)
        if (n[st])
            fprintf(stderr, " %s=%u", utcp_state_name(st), n[st]);
    fprintf(stderr, "\n");
}

void utcp_backend_dump(struct worker *w, void *h)
{
    (void)w;
    struct utcp_info i;
    if (!h || utcp_sock_info(h, &i))
        return;
    fprintf(stderr, "    tcp %s ca=%u cwnd=%u inflight=%u unacked=%u snd_wnd=%u rcv_wnd=%u "
                    "sndspace=%zu readable=%zu rto=%u segs out/in %u/%u\n",
            utcp_state_name(i.state), i.ca_state, i.cwnd, i.inflight, i.unacked, i.snd_wnd,
            i.rcv_wnd, utcp_sock_sndspace(h), utcp_sock_readable(h), i.rto_ms, i.segs_out,
            i.segs_in);
}

const struct transport tp_utcp = {
    .name = "utcp",
    .init = u_init,
    .listen = u_listen,
    .connect = u_connect,
    .send = u_send,
    .recv = u_recv,
    .recv_zc = u_recv_zc,
    .consume = u_consume,
    .shutdown_wr = u_shutdown,
    .close = u_close,
    .set_user = u_set_user,
    .run = u_run,
};
