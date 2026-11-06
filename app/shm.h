/* Shared-memory arena, lock-free size-class allocator and packet-buffer pool.
 *
 * The zygote maps one anonymous MAP_SHARED region before forking, so every
 * worker sees it at the same virtual address. Each core has its own heaps;
 * a block freed by another core is pushed onto the home core's lock-free
 * "remote free" stack and reclaimed there. */
#ifndef APP_SHM_H
#define APP_SHM_H

#include "utcp.h"

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#define APP_MAX_WORKERS 64
#define SHM_NCLASS 16 /* 128 B .. 4 MiB */
#define SHM_HDR 128   /* per-block header; keeps payload 128-byte aligned */

struct shm_class {
    void *local;               /* owner-only free list */
    _Atomic(void *) remote;    /* pushed by other cores */
};

struct shm_heap {
    uint8_t *cur, *end;        /* bump chunk */
    struct shm_class cls[SHM_NCLASS];
    uint64_t allocs, frees, remote_frees;
} __attribute__((aligned(128)));

struct buf_pool {
    struct utcp_buf **stack;   /* owner-only free stack */
    uint32_t top, count;
    _Atomic(struct utcp_buf *) remote;
    uint64_t alloc_fail;
} __attribute__((aligned(128)));

struct shm {
    uint64_t magic;
    void *base;
    size_t size;
    _Atomic size_t off;        /* global bump pointer */
    uint32_t buf_size;         /* data bytes per packet buffer */
    uint32_t headroom;
    struct shm_heap heap[APP_MAX_WORKERS + 1]; /* [APP_MAX_WORKERS] = zygote */
    struct buf_pool pool[APP_MAX_WORKERS];
};

struct shm *shm_create(size_t size);
void *shm_bump(struct shm *m, size_t size, size_t align);
void *shm_alloc(struct shm *m, int core, size_t size);
void shm_free(struct shm *m, int core, void *p);
int shm_pool_init(struct shm *m, int core, uint32_t nbufs);
struct utcp_buf *shm_buf_alloc(struct shm *m, int core);
void shm_buf_free(struct shm *m, int core, struct utcp_buf *b);
uint32_t shm_pool_avail(struct shm *m, int core);

#endif
