#include "link.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define LINK_MAGIC 0x4c494e4b55544350ULL /* "LINKUTCP" */

#define HDR_SIZE ((sizeof(struct link_hdr) + 4095) & ~(size_t)4095)
#define RING_SIZE ((sizeof(struct link_ring) + 4095) & ~(size_t)4095)

static size_t link_size(int nq) { return HDR_SIZE + (size_t)2 * nq * RING_SIZE; }

int link_open(struct link *l, const char *name, int side, int nq)
{
    char path[128];
    snprintf(path, sizeof(path), "/utcp-link-%s", name);
    if (nq < 1 || nq > LINK_MAXQ)
        return -1;
    size_t sz = link_size(nq);
    int fd;
    if (side == 0) {
        shm_unlink(path); /* stale segment from an earlier run */
        fd = shm_open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
        if (fd < 0 || ftruncate(fd, (off_t)sz) < 0) {
            perror("link shm_open");
            return -1;
        }
    } else {
        for (int i = 0; i < 500 && (fd = shm_open(path, O_RDWR, 0)) < 0; i++)
            usleep(10000);
        if (fd < 0) {
            perror("link shm_open (is the side-0 app running?)");
            return -1;
        }
    }
    void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) {
        perror("link mmap");
        return -1;
    }
    l->h = p;
    l->side = side;
    if (side == 0) {
        struct link_hdr *h = l->h;
        h->nq = (uint32_t)nq;
        size_t off = HDR_SIZE, rs = RING_SIZE;
        for (int s = 0; s < 2; s++)
            for (int q = 0; q < nq; q++, off += rs) {
                h->ring_off[s][q] = off;
                struct link_ring *r = (struct link_ring *)((uint8_t *)p + off);
                atomic_init(&r->head, 0);
                atomic_init(&r->tail, 0);
                r->drops = 0;
            }
        atomic_thread_fence(memory_order_release);
        h->magic = LINK_MAGIC;
    } else {
        for (int i = 0; i < 500 && ((volatile struct link_hdr *)l->h)->magic != LINK_MAGIC; i++)
            usleep(10000);
        if (l->h->magic != LINK_MAGIC || (int)l->h->nq != nq) {
            fprintf(stderr, "link: peer not ready or --workers differs (peer %u, us %d)\n",
                    l->h->nq, nq);
            return -1;
        }
    }
    return 0;
}

void link_publish(struct link *l, struct utcp_region *r, uint32_t ip, const uint8_t mac[6])
{
    struct link_side *me = &l->h->side[l->side];
    me->ip = ip;
    memcpy(me->mac, mac, 6);
    me->nbuckets = utcp_nbuckets(r);
    for (uint32_t b = 0; b < LINK_NB && b < me->nbuckets; b++)
        me->owner[b] = (uint16_t)utcp_bucket_owner(r, b);
    atomic_store_explicit(&me->ready, 1, memory_order_release);
}

int link_wait_peer(struct link *l, int timeout_ms)
{
    struct link_side *peer = &l->h->side[!l->side];
    for (int i = 0; i < timeout_ms; i++) {
        if (atomic_load_explicit(&peer->ready, memory_order_acquire))
            return 0;
        usleep(1000);
    }
    return -1;
}

struct link_ring *link_rx_ring(struct link *l, int q)
{
    return (struct link_ring *)((uint8_t *)l->h + l->h->ring_off[l->side][q]);
}

struct link_ring *link_tx_ring(struct link *l, int q)
{
    return (struct link_ring *)((uint8_t *)l->h + l->h->ring_off[!l->side][q]);
}

int link_tx_queue(struct link *l, struct utcp_region *r, const struct utcp_buf *b)
{
    const uint8_t *f = b->data;
    if (b->len < 38 || f[12] != 0x08 || f[13] != 0x00 || f[23] != 6)
        return 0; /* ARP, ICMP: queue 0 (the stack hands off if needed) */
    uint32_t ihl = (f[14] & 0xf) * 4u, sip, dip;
    uint16_t sp, dp;
    memcpy(&sip, f + 26, 4);
    memcpy(&dip, f + 30, 4);
    memcpy(&sp, f + 14 + ihl, 2);
    memcpy(&dp, f + 16 + ihl, 2);
    /* both sides use utcp's symmetric default key: hash with ours, look up
     * the receiver's bucket table */
    struct link_side *peer = &l->h->side[!l->side];
    uint32_t h = utcp_rss_hash(r, sip, dip, sp, dp);
    return peer->owner[h & (peer->nbuckets - 1) & (LINK_NB - 1)] % l->h->nq;
}
