/* libFuzzer harness for the receive path.
 *
 * Input = sequence of records:  [ctl:1][len:2][bytes:len]
 *   ctl bit 0  : bytes are a TCP header+payload; harness wraps them in a
 *                valid Ethernet/IPv4 header from the peer and fixes checksums
 *       bit 1  :   ... and sets ack = last sequence the stack transmitted
 *       bit 2  :   ... and sets seq = last ack the stack transmitted
 *       bit 3  : advance the clock by (len * 7) ms after this record
 *       bit 4  : app action (send / recv / close / connect) chosen by len
 *   otherwise  : bytes are a raw Ethernet frame
 * The stack is deterministic (fixed RNG and clock), so the fuzzer can learn
 * handshakes. Two cores are configured so the handoff path is exercised. */
#include "../src/utcp_int.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFCAP 2048

static uint64_t g_now;
static uint32_t g_tx_seq_end, g_tx_ack;
static int g_bufs; /* outstanding packet buffers */
static utcp_t *g_t[2];
static struct utcp_sock *g_socks[64];
static int g_nsocks;

/* Arena: everything the stack allocates is released after each input. */
static void *g_mem[1 << 16];
static int g_nmem;
static void *ma(void *c, size_t s, size_t a)
{
    (void)c;
    void *p;
    if (g_nmem == (int)(sizeof(g_mem) / sizeof(g_mem[0])) ||
        posix_memalign(&p, a < 16 ? 16 : a, s))
        return NULL;
    g_mem[g_nmem++] = p;
    return p;
}
static void mf(void *c, void *p)
{
    (void)c;
    (void)p; /* released with the arena */
}
static struct utcp_buf *ba(void *c)
{
    (void)c;
    uint8_t *m = malloc(sizeof(struct utcp_buf) + BUFCAP);
    struct utcp_buf *b = (struct utcp_buf *)m;
    memset(b, 0, sizeof(*b));
    b->base = m + sizeof(*b);
    b->cap = BUFCAP;
    b->data = b->base + 128;
    g_bufs++;
    return b;
}
static void bf(void *c, struct utcp_buf *b)
{
    (void)c;
    g_bufs--;
    free(b);
}
static uint64_t now(void *c)
{
    (void)c;
    return g_now;
}
static uint64_t rnd(void *c)
{
    (void)c;
    return 0x1234567890abcdefULL;
}
static int tx(void *c, struct utcp_buf **p, int n)
{
    for (int i = 0; i < n; i++) {
        struct utcp_buf *b = p[i];
        if (b->len >= HDRS_LEN) {
            struct ip_hdr *ip = (struct ip_hdr *)(b->data + ETH_HLEN);
            if (ip->proto == IPPROTO_TCP_) {
                struct tcp_hdr *th = (struct tcp_hdr *)(b->data + ETH_HLEN + IP_HLEN);
                uint32_t plen = ntohs(ip->tot_len) - IP_HLEN - (th->doff >> 4) * 4u;
                g_tx_seq_end = ntohl(th->seq) + plen + !!(th->flags & (TH_SYN | TH_FIN));
                g_tx_ack = ntohl(th->ack);
            }
        }
        utcp_pkt_free(g_t[0], b);
    }
    (void)c;
    return n;
}
static void ev(void *c, struct utcp_sock *s, uint32_t e)
{
    utcp_t *t = c;
    if (e & UTCP_EV_ACCEPT) {
        struct utcp_sock *n;
        while ((n = utcp_accept(t, s)))
            if (g_nsocks < 64)
                g_socks[g_nsocks++] = n;
            else
                utcp_close(t, n);
        return;
    }
    if (e & UTCP_EV_READABLE) {
        uint8_t buf[4096];
        while (utcp_recv(t, s, buf, sizeof(buf)) > 0)
            ;
    }
    if (e & UTCP_EV_CLOSED) {
        for (int i = 0; i < g_nsocks; i++)
            if (g_socks[i] == s)
                g_socks[i] = g_socks[--g_nsocks];
        utcp_close(t, s);
    }
}

static const uint8_t MAC_US[6] = {2, 0, 0, 0, 0, 1}, MAC_PEER[6] = {2, 0, 0, 0, 0, 2};

static struct utcp_buf *wrap_tcp(const uint8_t *d, size_t n, uint8_t ctl)
{
    if (n < 20 || n > 1400)
        return NULL;
    struct utcp_buf *b = ba(NULL);
    uint8_t *f = b->data;
    struct eth_hdr *eh = (struct eth_hdr *)f;
    memcpy(eh->dst, MAC_US, 6);
    memcpy(eh->src, MAC_PEER, 6);
    eh->type = htons(ETH_P_IP);
    struct ip_hdr *ip = (struct ip_hdr *)(f + ETH_HLEN);
    memset(ip, 0, IP_HLEN);
    ip->vhl = 0x45;
    ip->tot_len = htons((uint16_t)(IP_HLEN + n));
    ip->ttl = 64;
    ip->proto = IPPROTO_TCP_;
    ip->saddr = inet_addr("10.0.0.2");
    ip->daddr = inet_addr("10.0.0.1");
    ip->check = csum_fold(csum_partial(ip, IP_HLEN, 0));
    struct tcp_hdr *th = (struct tcp_hdr *)(f + ETH_HLEN + IP_HLEN);
    memcpy(th, d, n);
    if (ctl & 2)
        th->ack = htonl(g_tx_seq_end);
    if (ctl & 4)
        th->seq = htonl(g_tx_ack);
    th->check = 0;
    uint32_t ps = pseudo_sum(ip->saddr, ip->daddr, IPPROTO_TCP_, (uint16_t)n);
    th->check = csum_fold(csum_partial(th, n, ps));
    b->len = b->pkt_len = (uint32_t)(ETH_HLEN + IP_HLEN + n);
    return b;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct utcp_ops ops = {.mem_alloc = ma, .mem_free = mf, .buf_alloc = ba, .buf_free = bf,
                           .tx_burst = tx, .now_ns = now, .on_event = ev, .random = rnd};
    struct utcp_config cfg;
    utcp_config_default(&cfg);
    cfg.ncores = 2;
    cfg.flow_table_size = 256;
    cfg.ring_size = 256;
    cfg.nbuckets = 64;
    cfg.local_ip = inet_addr("10.0.0.1");
    cfg.netmask = inet_addr("255.255.255.0");
    memcpy(cfg.mac, MAC_US, 6);
    cfg.offloads = (data[0] & 1) ? (UTCP_OFFLOAD_TSO | UTCP_OFFLOAD_TX_CSUM) : 0;
    cfg.rcvbuf = 65536;
    cfg.time_wait_ms = 1000;
    g_now = 1000000000ULL;
    g_nsocks = 0;
    g_bufs = 0;
    struct utcp_region *r;
    if (utcp_region_create(&cfg, &ops, NULL, &r))
        abort();
    for (int i = 0; i < 2; i++) {
        g_t[i] = utcp_attach(r, (unsigned)i, &ops, NULL);
        g_t[i]->ctx = g_t[i];
        utcp_listen(g_t[i], 80, 16);
    }
    utcp_arp_add(r, inet_addr("10.0.0.2"), MAC_PEER);

    size_t off = 0;
    int steps = 0;
    while (off + 3 <= size && steps++ < 256) {
        uint8_t ctl = data[off];
        size_t len = (size_t)data[off + 1] | (size_t)data[off + 2] << 8;
        off += 3;
        if (len > size - off)
            len = size - off;
        const uint8_t *p = data + off;
        off += len;
        utcp_t *t = g_t[ctl >> 7];
        if (ctl & 16) {
            uint8_t buf[3000];
            memset(buf, 'x', sizeof(buf));
            switch (len % 5) {
            case 0:
                if (g_nsocks)
                    utcp_send(t, g_socks[len % g_nsocks], buf, len * 3 % sizeof(buf));
                break;
            case 1:
                if (g_nsocks) {
                    int k = (int)(len % (size_t)g_nsocks);
                    struct utcp_sock *s = g_socks[k];
                    g_socks[k] = g_socks[g_nsocks - 1];
                    g_nsocks--;
                    utcp_close(t, s);
                }
                break;
            case 2: {
                struct utcp_sock *s = utcp_connect(t, inet_addr("10.0.0.2"), (uint16_t)(len + 1));
                if (s && g_nsocks < 64)
                    g_socks[g_nsocks++] = s;
                else if (s)
                    utcp_close(t, s);
                break;
            }
            case 3:
                if (g_nsocks)
                    utcp_shutdown(t, g_socks[len % g_nsocks], UTCP_SHUT_WR);
                break;
            case 4:
                if (g_nsocks) {
                    int k = (int)(len % (size_t)g_nsocks);
                    struct utcp_sock *s = g_socks[k];
                    g_socks[k] = g_socks[g_nsocks - 1];
                    g_nsocks--;
                    utcp_abort(t, s);
                }
                break;
            }
        } else {
            struct utcp_buf *b = NULL;
            if (ctl & 1) {
                b = wrap_tcp(p, len, ctl);
            } else if (len >= 14 && len <= BUFCAP - 128) {
                b = ba(NULL);
                memcpy(b->data, p, len);
                b->len = b->pkt_len = (uint32_t)len;
            }
            if (b)
                utcp_input_burst(t, &b, 1);
        }
        if (ctl & 8)
            g_now += (uint64_t)(len * 7 + 1) * 1000000ULL;
        utcp_poll(g_t[0]);
        utcp_poll(g_t[1]);
    }
    /* Tear down: abort everything, let timers drain, then check for leaks. */
    for (int i = 0; i < g_nsocks; i++)
        utcp_abort(g_t[0], g_socks[i]);
    g_nsocks = 0;
    for (int k = 0; k < 400; k++) {
        g_now += 500000000ULL;
        utcp_poll(g_t[0]);
        utcp_poll(g_t[1]);
    }
    /* Leak oracle: once every connection is gone, no packet buffer may remain
     * outstanding (send/receive/out-of-order queues, retransmit references,
     * handoff rings, ARP queue). */
    struct utcp_stats st;
    utcp_stats_get(r, -1, &st);
    if (g_bufs != 0 && st.socks_alloc == st.socks_free + 2 /* listeners */) {
        fprintf(stderr, "buffer leak: %d outstanding, socks %llu/%llu\n", g_bufs,
                (unsigned long long)st.socks_alloc, (unsigned long long)st.socks_free);
        abort();
    }
    for (int i = 0; i < g_nmem; i++)
        free(g_mem[i]);
    g_nmem = 0;
    return 0;
}
