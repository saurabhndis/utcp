/* Shared-memory point-to-point link between two utcp-app instances (like
 * DPDK memif). Side 0 (server) creates the segment, side 1 attaches. Each
 * direction has one SPSC ring per receiving worker; the sender steers by the
 * receiver's published RSS bucket table, exactly as a NIC would. The two
 * apps map the segment at different addresses, so it holds offsets only. */
#ifndef APP_LINK_H
#define APP_LINK_H

#include "utcp.h"

#include <stdatomic.h>
#include <stdint.h>

#define LINK_MAXQ 16
#define LINK_RING_BYTES (32u << 20) /* per queue; like a large NIC RX ring */
#define LINK_MAX_PKT (65536 + 256)
#define LINK_NB 4096
#define LINK_WRAP 0xffffffffu

/* Variable-length records in a byte ring: [len|flags|gso][data], 64-byte
 * aligned. A record never straddles the end; a WRAP marker skips the tail. */
struct link_rec {
    uint32_t len;
    uint16_t flags;    /* UTCP_BUF_* as seen by the receiver */
    uint16_t gso_size;
    uint8_t data[];
};

struct link_ring {
    _Atomic uint64_t head __attribute__((aligned(128))); /* bytes produced */
    _Atomic uint64_t tail __attribute__((aligned(128))); /* bytes consumed */
    uint64_t drops __attribute__((aligned(128)));
    uint8_t buf[LINK_RING_BYTES] __attribute__((aligned(128)));
};

static inline uint32_t link_rec_size(uint32_t len)
{
    return (uint32_t)((sizeof(struct link_rec) + len + 63) & ~63u);
}

struct link_side {
    _Atomic uint32_t ready;
    uint32_t ip;
    uint8_t mac[6];
    uint32_t nbuckets;
    uint16_t owner[LINK_NB]; /* receiver's bucket -> queue table */
};

struct link_hdr {
    uint64_t magic;
    uint32_t nq;                 /* queues per direction (= workers per side) */
    struct link_side side[2];
    uint64_t ring_off[2][LINK_MAXQ]; /* [rx side][queue] */
};

struct link {
    struct link_hdr *h;
    int side;
};

int link_open(struct link *l, const char *name, int side, int nq);
void link_publish(struct link *l, struct utcp_region *r, uint32_t ip, const uint8_t mac[6]);
int link_wait_peer(struct link *l, int timeout_ms);
struct link_ring *link_rx_ring(struct link *l, int q);
struct link_ring *link_tx_ring(struct link *l, int q);
/* queue on the peer that owns the flow in this frame */
int link_tx_queue(struct link *l, struct utcp_region *r, const struct utcp_buf *b);

#endif
