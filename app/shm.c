#include "shm.h"

#include <string.h>
#include <sys/mman.h>

#define SHM_MAGIC 0x55534d454d4f5259ULL
#define CHUNK (4u << 20)

struct blk_hdr {
    uint32_t cls;  /* size class, or 0xffffffff for a bump-only block */
    uint32_t home; /* owning heap */
};

struct shm *shm_create(size_t size)
{
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS | MAP_NORESERVE,
                   -1, 0);
    if (p == MAP_FAILED)
        return NULL;
    struct shm *m = p;
    memset(m, 0, sizeof(*m));
    m->magic = SHM_MAGIC;
    m->base = p;
    m->size = size;
    atomic_init(&m->off, (sizeof(*m) + 4095) & ~(size_t)4095);
    return m;
}

void *shm_bump(struct shm *m, size_t size, size_t align)
{
    size_t off = atomic_load(&m->off), n;
    do {
        n = (off + align - 1) & ~(align - 1);
        if (n + size > m->size)
            return NULL;
    } while (!atomic_compare_exchange_weak(&m->off, &off, n + size));
    return (uint8_t *)m->base + n;
}

static inline int size_class(size_t sz)
{
    size_t c = 128;
    for (int i = 0; i < SHM_NCLASS; i++, c <<= 1)
        if (sz <= c)
            return i;
    return -1;
}

static inline size_t class_size(int c) { return (size_t)128 << c; }

static inline int heap_idx(int core) { return core < 0 ? APP_MAX_WORKERS : core; }

void *shm_alloc(struct shm *m, int core, size_t size)
{
    int hi = heap_idx(core);
    struct shm_heap *h = &m->heap[hi];
    int c = size_class(size);
    if (c < 0) { /* huge: bump only, never reused */
        uint8_t *p = shm_bump(m, size + SHM_HDR, 4096);
        if (!p)
            return NULL;
        struct blk_hdr *bh = (struct blk_hdr *)p;
        bh->cls = 0xffffffffu;
        bh->home = (uint32_t)hi;
        return p + SHM_HDR;
    }
    struct shm_class *k = &h->cls[c];
    if (!k->local)
        k->local = atomic_exchange_explicit(&k->remote, NULL, memory_order_acquire);
    uint8_t *blk;
    if (k->local) {
        blk = k->local;
        k->local = *(void **)(blk + SHM_HDR);
    } else {
        size_t need = class_size(c) + SHM_HDR;
        if ((size_t)(h->end - h->cur) < need) {
            size_t chunk = need > CHUNK ? need : CHUNK;
            h->cur = shm_bump(m, chunk, 128);
            if (!h->cur)
                return NULL;
            h->end = h->cur + chunk;
        }
        blk = h->cur;
        h->cur += need;
        struct blk_hdr *bh = (struct blk_hdr *)blk;
        bh->cls = (uint32_t)c;
        bh->home = (uint32_t)hi;
    }
    h->allocs++;
    return blk + SHM_HDR;
}

void shm_free(struct shm *m, int core, void *p)
{
    if (!p)
        return;
    uint8_t *blk = (uint8_t *)p - SHM_HDR;
    struct blk_hdr *bh = (struct blk_hdr *)blk;
    if (bh->cls == 0xffffffffu)
        return;
    struct shm_heap *home = &m->heap[bh->home];
    struct shm_class *k = &home->cls[bh->cls];
    if ((int)bh->home == heap_idx(core)) {
        *(void **)p = k->local;
        k->local = blk;
        home->frees++;
        return;
    }
    void *old = atomic_load_explicit(&k->remote, memory_order_relaxed);
    do {
        *(void **)p = old;
    } while (!atomic_compare_exchange_weak_explicit(&k->remote, &old, blk, memory_order_release,
                                                    memory_order_relaxed));
    m->heap[heap_idx(core)].remote_frees++;
}

/* ----------------------------------------------------------- buffers */

int shm_pool_init(struct shm *m, int core, uint32_t nbufs)
{
    struct buf_pool *bp = &m->pool[core];
    size_t stride = sizeof(struct utcp_buf) + m->headroom + m->buf_size;
    stride = (stride + 127) & ~(size_t)127;
    uint8_t *mem = shm_bump(m, stride * nbufs, 4096);
    bp->stack = shm_bump(m, sizeof(*bp->stack) * nbufs, 128);
    if (!mem || !bp->stack)
        return -1;
    for (uint32_t i = 0; i < nbufs; i++) {
        struct utcp_buf *b = (struct utcp_buf *)(mem + i * stride);
        memset(b, 0, sizeof(*b));
        b->base = (uint8_t *)(b + 1);
        b->cap = m->headroom + m->buf_size;
        b->app_u16 = (uint16_t)core;
        bp->stack[i] = b;
    }
    bp->top = bp->count = nbufs;
    atomic_init(&bp->remote, NULL);
    return 0;
}

struct utcp_buf *shm_buf_alloc(struct shm *m, int core)
{
    struct buf_pool *bp = &m->pool[core];
    if (!bp->top) {
        struct utcp_buf *r = atomic_exchange_explicit(&bp->remote, NULL, memory_order_acquire);
        while (r) {
            struct utcp_buf *n = r->nextpkt;
            bp->stack[bp->top++] = r;
            r = n;
        }
        if (!bp->top) {
            bp->alloc_fail++;
            return NULL;
        }
    }
    struct utcp_buf *b = bp->stack[--bp->top];
    b->data = b->base + m->headroom;
    b->len = b->pkt_len = 0;
    b->next = b->nextpkt = NULL;
    b->flags = 0;
    b->gso_size = 0;
    return b;
}

void shm_buf_free(struct shm *m, int core, struct utcp_buf *b)
{
    int home = b->app_u16;
    struct buf_pool *bp = &m->pool[home];
    if (home == core) {
        bp->stack[bp->top++] = b;
        return;
    }
    struct utcp_buf *old = atomic_load_explicit(&bp->remote, memory_order_relaxed);
    do {
        b->nextpkt = old;
    } while (!atomic_compare_exchange_weak_explicit(&bp->remote, &old, b, memory_order_release,
                                                    memory_order_relaxed));
}

uint32_t shm_pool_avail(struct shm *m, int core) { return m->pool[core].top; }
