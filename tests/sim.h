/* Discrete-event network simulator for utcp tests: two hosts joined by a
 * full-duplex link with bandwidth, propagation delay, a tail-drop queue,
 * random loss and reordering. Time is simulated (deterministic). */
#ifndef UTCP_SIM_H
#define UTCP_SIM_H

#include "utcp.h"

#include <stdbool.h>
#include <stdint.h>

#define SIM_MAX_CORES 8

struct sim;

struct sim_link_cfg {
    double gbps;          /* serialization rate */
    uint64_t delay_ns;    /* one-way propagation delay */
    uint64_t queue_bytes; /* tail-drop queue limit */
    double loss;          /* random loss probability */
    double reorder;       /* probability a packet gets extra delay */
    uint64_t reorder_ns;  /* extra delay for reordered packets */
};

struct sim_host_cfg {
    unsigned ncores;
    bool tso;             /* TSO + TX checksum offload */
    bool rx_csum_ok;      /* deliver with RX_CSUM_OK */
    bool spray;           /* deliver packets to random cores (no RSS) */
    uint32_t rcvbuf, sndbuf;
    uint32_t cc;
};

struct sim_host {
    struct sim *sim;
    int id;
    struct utcp_config cfg;
    struct utcp_region *region;
    utcp_t *core[SIM_MAX_CORES];
    struct sim_hctx {
        struct sim_host *h;
        unsigned core;
    } hctx[SIM_MAX_CORES];
    struct sim_host_cfg hc;
    uint64_t bufs_out; /* outstanding packet buffers */
};

struct sim {
    uint64_t now;
    uint64_t rng;
    struct sim_host host[2];
    struct sim_link_cfg link;
    struct sim_pkt *q[2];      /* in-flight packets per direction (sorted) */
    uint64_t link_free_at[2];
    uint64_t drops_queue, drops_random, delivered_pkts, reordered;
    void (*on_event)(struct sim_host *h, unsigned core, struct utcp_sock *s, uint32_t ev);
    void (*on_migrate)(struct sim_host *h, unsigned core, struct utcp_sock *s);
    void *user;
};

void sim_init(struct sim *s, const struct sim_link_cfg *lc, const struct sim_host_cfg *a,
              const struct sim_host_cfg *b, uint64_t seed);
/* Run until `until` ns or idle; returns false if idle. */
bool sim_run_until(struct sim *s, uint64_t until);
void sim_destroy(struct sim *s);
uint64_t sim_rand(struct sim *s);

#endif
