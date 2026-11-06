/* Ethernet, ARP, IPv4, ICMP, checksums, and the per-packet steering decision. */
#include "utcp_int.h"

/* ------------------------------------------------------------ checksums */

uint32_t csum_partial(const void *p, size_t len, uint32_t sum32)
{
    uint64_t sum = sum32;
    const uint8_t *b = p;
    while (len >= 8) {
        uint64_t v;
        memcpy(&v, b, 8);
        sum += (v & 0xffffffffu) + (v >> 32);
        b += 8;
        len -= 8;
    }
    while (len >= 2) {
        uint16_t v;
        memcpy(&v, b, 2);
        sum += v;
        b += 2;
        len -= 2;
    }
    if (len) {
        uint16_t v = 0;
        memcpy(&v, b, 1);
        sum += v;
    }
    while (sum >> 32)
        sum = (sum & 0xffffffffu) + (sum >> 32);
    return (uint32_t)sum;
}

uint16_t csum_fold(uint32_t sum)
{
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static inline uint32_t fold16(uint32_t s)
{
    s = (s & 0xffff) + (s >> 16);
    return (s & 0xffff) + (s >> 16);
}

uint32_t csum_chain(const struct utcp_buf *b, uint32_t off, uint32_t sum)
{
    uint32_t total = 0;
    for (; b; b = b->next) {
        if (off >= b->len) {
            off -= b->len;
            continue;
        }
        uint32_t n = b->len - off;
        uint32_t part = fold16(csum_partial(b->data + off, n, 0));
        if (total & 1)
            part = ((part & 0xff) << 8) | (part >> 8);
        sum = fold16(sum + part);
        total += n;
        off = 0;
    }
    return sum;
}

uint32_t pseudo_sum(uint32_t sip, uint32_t dip, uint8_t proto, uint16_t len)
{
    uint32_t s = 0;
    s += sip & 0xffff;
    s += sip >> 16;
    s += dip & 0xffff;
    s += dip >> 16;
    s += hton16((uint16_t)proto);
    s += hton16(len);
    return fold16(s);
}

/* ------------------------------------------------------------------ ARP */

static inline unsigned arp_slot(uint32_t ip)
{
    uint32_t h = ip * 0x9e3779b1u;
    return h >> 24; /* ARP_SLOTS == 256 */
}

int arp_lookup(struct utcp_region *r, uint32_t ip, uint8_t mac[6])
{
    for (unsigned i = 0; i < 8; i++) {
        struct arp_ent *e = &r->arp[(arp_slot(ip) + i) & (ARP_SLOTS - 1)];
        uint32_t s1, s2;
        uint32_t eip;
        uint8_t valid;
        do {
            s1 = atomic_load_explicit(&e->seq, memory_order_acquire);
            eip = e->ip;
            valid = e->valid;
            memcpy(mac, e->mac, 6);
            atomic_thread_fence(memory_order_acquire);
            s2 = atomic_load_explicit(&e->seq, memory_order_relaxed);
        } while ((s1 & 1) || s1 != s2);
        if (!valid)
            return -1;
        if (eip == ip)
            return 0;
    }
    return -1;
}

void arp_learn(struct utcp_region *r, uint32_t ip, const uint8_t mac[6])
{
    uint8_t cur[6];
    if (arp_lookup(r, ip, cur) == 0 && !memcmp(cur, mac, 6))
        return;
    while (atomic_flag_test_and_set_explicit(&r->arp_wlock, memory_order_acquire))
        ;
    struct arp_ent *e = NULL;
    for (unsigned i = 0; i < 8; i++) {
        struct arp_ent *c = &r->arp[(arp_slot(ip) + i) & (ARP_SLOTS - 1)];
        if (!c->valid || c->ip == ip) {
            e = c;
            break;
        }
    }
    if (!e)
        e = &r->arp[arp_slot(ip)];
    uint32_t s = atomic_load_explicit(&e->seq, memory_order_relaxed);
    atomic_store_explicit(&e->seq, s + 1, memory_order_relaxed);
    atomic_thread_fence(memory_order_release);
    e->ip = ip;
    memcpy(e->mac, mac, 6);
    e->valid = 1;
    atomic_store_explicit(&e->seq, s + 2, memory_order_release);
    atomic_flag_clear_explicit(&r->arp_wlock, memory_order_release);
}

int utcp_arp_add(struct utcp_region *r, uint32_t ip, const uint8_t mac[6])
{
    arp_learn(r, ip, mac);
    return 0;
}

static void arp_send(utcp_t *t, uint16_t op, const uint8_t tha[6], uint32_t tpa,
                     const uint8_t eth_dst[6])
{
    struct utcp_buf *b = buf_alloc(t);
    if (!b)
        return;
    struct eth_hdr *eh = (struct eth_hdr *)b->data;
    struct arp_hdr *ah = (struct arp_hdr *)(eh + 1);
    memcpy(eh->dst, eth_dst, 6);
    memcpy(eh->src, t->r->cfg.mac, 6);
    eh->type = hton16(ETH_P_ARP);
    ah->htype = hton16(1);
    ah->ptype = hton16(ETH_P_IP);
    ah->hlen = 6;
    ah->plen = 4;
    ah->op = hton16(op);
    memcpy(ah->sha, t->r->cfg.mac, 6);
    ah->spa = t->r->cfg.local_ip;
    memcpy(ah->tha, tha, 6);
    ah->tpa = tpa;
    b->len = b->pkt_len = 60;
    memset(b->data + ETH_HLEN + sizeof(*ah), 0, 60 - ETH_HLEN - sizeof(*ah));
    tx_enqueue(t, b);
}

static void arp_input(utcp_t *t, struct utcp_buf *b)
{
    if (b->len < ETH_HLEN + sizeof(struct arp_hdr))
        goto out;
    struct arp_hdr *ah = (struct arp_hdr *)(b->data + ETH_HLEN);
    if (ah->htype != hton16(1) || ah->ptype != hton16(ETH_P_IP) || ah->hlen != 6 || ah->plen != 4)
        goto out;
    if (ah->tpa != t->r->cfg.local_ip)
        goto out;
    arp_learn(t->r, ah->spa, ah->sha);
    if (ah->op == hton16(1))
        arp_send(t, 2, ah->sha, ah->spa, ah->sha);
out:
    buf_free_chain(t, b);
}

/* ----------------------------------------------------------------- IPv4 */

int ip_output(utcp_t *t, struct utcp_buf *b, uint32_t dip, uint16_t l4len)
{
    struct eth_hdr *eh = (struct eth_hdr *)b->data;
    struct ip_hdr *ip = (struct ip_hdr *)(b->data + ETH_HLEN);
    ip->vhl = 0x45;
    ip->tos = 0;
    ip->tot_len = hton16((uint16_t)(IP_HLEN + l4len));
    ip->id = hton16((uint16_t)(t->c->ip_id++));
    ip->frag = hton16(IP_DF);
    ip->ttl = 64;
    ip->proto = IPPROTO_TCP_;
    ip->check = 0;
    ip->saddr = t->r->cfg.local_ip;
    ip->daddr = dip;
    ip->check = csum_fold(csum_partial(ip, IP_HLEN, 0));
    memcpy(eh->src, t->r->cfg.mac, 6);
    eh->type = hton16(ETH_P_IP);
    b->l3_off = ETH_HLEN;
    b->l4_off = ETH_HLEN + IP_HLEN;

    uint32_t nh = dip;
    if (((dip ^ t->r->cfg.local_ip) & t->r->cfg.netmask) && t->r->cfg.gateway)
        nh = t->r->cfg.gateway;
    if (likely(arp_lookup(t->r, nh, eh->dst) == 0)) {
        tx_enqueue(t, b);
        return 0;
    }
    t->st->arp_miss++;
    bool first = true;
    for (int i = 0; i < t->narp_pending; i++) {
        struct ip_hdr *pip = (struct ip_hdr *)(t->arp_pending[i]->data + ETH_HLEN);
        if (pip->daddr == dip)
            first = false;
    }
    if (t->narp_pending == (int)(sizeof(t->arp_pending) / sizeof(t->arp_pending[0]))) {
        buf_free_chain(t, b);
    } else {
        b->seq = (uint32_t)(t->now / 1000000ULL);
        t->arp_pending[t->narp_pending++] = b;
    }
    if (first) {
        static const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        static const uint8_t zero[6] = {0};
        arp_send(t, 1, zero, nh, bcast);
    }
    return -1;
}

/* Trim a packet chain to `len` bytes total (drops Ethernet padding). */
static void buf_trim(utcp_t *t, struct utcp_buf *b, uint32_t len)
{
    b->pkt_len = len;
    for (; b; b = b->next) {
        if (len <= b->len) {
            b->len = len;
            buf_free_chain(t, b->next);
            b->next = NULL;
            return;
        }
        len -= b->len;
    }
}

static void icmp_input(utcp_t *t, struct utcp_buf *b, struct ip_hdr *ip, uint32_t ihl,
                       uint32_t len)
{
    struct icmp_hdr *ic = (struct icmp_hdr *)((uint8_t *)ip + ihl);
    if (len < sizeof(*ic) || b->next) /* we only handle linear ICMP */
        goto drop;
    if (csum_fold(csum_partial(ic, len, 0)) != 0)
        goto drop;
    if (ic->type == 8 && ic->code == 0) { /* echo request -> reply in place */
        struct eth_hdr *eh = (struct eth_hdr *)b->data;
        uint8_t tmp[6];
        memcpy(tmp, eh->dst, 6);
        memcpy(eh->dst, eh->src, 6);
        memcpy(eh->src, tmp, 6);
        uint32_t a = ip->saddr;
        ip->saddr = ip->daddr;
        ip->daddr = a;
        ip->ttl = 64;
        ip->check = 0;
        ip->check = csum_fold(csum_partial(ip, ihl, 0));
        ic->type = 0;
        ic->check = 0;
        ic->check = csum_fold(csum_partial(ic, len, 0));
        b->flags = 0;
        tx_enqueue(t, b);
        return;
    }
    if (ic->type == 3 && ic->code == 4 && len >= 8 + IP_HLEN + 8) { /* frag needed */
        struct ip_hdr *in = (struct ip_hdr *)(ic + 1);
        uint32_t iihl = (in->vhl & 0xf) * 4u;
        if (in->proto != IPPROTO_TCP_ || in->saddr != t->r->cfg.local_ip ||
            len < 8 + iihl + 8)
            goto drop;
        const uint16_t *ports = (const uint16_t *)((uint8_t *)in + iihl);
        /* our packet: saddr=us sport=ports[0] */
        uint32_t h = toeplitz_hash(t->r, in->daddr, in->saddr, ports[1], ports[0]);
        uint32_t w = atomic_load_explicit(&t->r->bucket_owner[h & (t->r->cfg.nbuckets - 1)],
                                          memory_order_acquire);
        if (BKT_CORE(w) != t->core) {
            handoff(t, b, BKT_CORE(w));
            return;
        }
        struct utcp_sock *s = flow_lookup(t, in->saddr, in->daddr, ports[0], ports[1]);
        if (s)
            tcp_icmp_frag_needed(t, s, ntoh16(ic->seq));
    }
drop:
    buf_free_chain(t, b);
}

void net_input(utcp_t *t, struct utcp_buf *b, bool from_ring)
{
    struct utcp_region *r = t->r;
    if (!from_ring) {
        t->st->rx_pkts++;
        t->st->rx_bytes += b->pkt_len;
    }
    if (unlikely(b->len < ETH_HLEN)) {
        t->st->rx_drop_short++;
        goto drop;
    }
    struct eth_hdr *eh = (struct eth_hdr *)b->data;
    if (eh->type == hton16(ETH_P_ARP)) {
        arp_input(t, b);
        return;
    }
    if (eh->type != hton16(ETH_P_IP)) {
        t->st->rx_drop_noproto++;
        goto drop;
    }
    if (unlikely(b->len < ETH_HLEN + IP_HLEN)) {
        t->st->rx_drop_short++;
        goto drop;
    }
    struct ip_hdr *ip = (struct ip_hdr *)(b->data + ETH_HLEN);
    uint32_t ihl = (ip->vhl & 0xf) * 4u;
    uint32_t tot = ntoh16(ip->tot_len);
    if (unlikely((ip->vhl >> 4) != 4 || ihl < IP_HLEN || b->len < ETH_HLEN + ihl ||
                 tot < ihl || ETH_HLEN + tot > b->pkt_len)) {
        t->st->rx_drop_short++;
        goto drop;
    }
    if (ip->daddr != r->cfg.local_ip) {
        t->st->rx_drop_noproto++;
        goto drop;
    }
    if (!(b->flags & UTCP_BUF_RX_CSUM_OK) && csum_fold(csum_partial(ip, ihl, 0)) != 0) {
        t->st->rx_drop_csum++;
        goto drop;
    }
    if (ip->frag & hton16(IP_MF | IP_OFFMASK)) {
        /* Fragments are not reassembled (TCP uses DF + PMTUD). */
        t->st->rx_drop_noproto++;
        goto drop;
    }
    if (ETH_HLEN + tot < b->pkt_len)
        buf_trim(t, b, ETH_HLEN + tot);
    uint32_t l4len = tot - ihl;

    if (ip->proto == IPPROTO_ICMP_) {
        icmp_input(t, b, ip, ihl, l4len);
        return;
    }
    if (ip->proto != IPPROTO_TCP_ || l4len < TCP_HLEN || b->len < ETH_HLEN + ihl + TCP_HLEN) {
        t->st->rx_drop_noproto++;
        goto drop;
    }
    struct tcp_hdr *th = (struct tcp_hdr *)((uint8_t *)ip + ihl);

    /* Steering: owner = bucket_owner[hash & (nbuckets-1)] */
    uint32_t h = (b->flags & UTCP_BUF_HASH_VALID)
                     ? b->hash
                     : toeplitz_hash(r, ip->saddr, ip->daddr, th->sport, th->dport);
    uint32_t bkt = h & (r->cfg.nbuckets - 1);
    uint32_t w = atomic_load_explicit(&r->bucket_owner[bkt], memory_order_acquire);
    if (BKT_CORE(w) != t->core) {
        b->hash = h;
        b->flags |= UTCP_BUF_HASH_VALID;
        handoff(t, b, BKT_CORE(w));
        return;
    }
    if (unlikely(w & BKT_MIGRATING) &&
        !flow_lookup(t, ip->daddr, ip->saddr, th->dport, th->sport)) {
        /* Sockets for this bucket have not arrived yet; hold the packet. */
        b->nextpkt = NULL;
        if (t->defer_tail)
            t->defer_tail->nextpkt = b;
        else
            t->defer_head = b;
        t->defer_tail = b;
        return;
    }
    atomic_store_explicit(&r->bucket_load[bkt],
                          atomic_load_explicit(&r->bucket_load[bkt], memory_order_relaxed) + 1,
                          memory_order_relaxed);
    if (!(b->flags & UTCP_BUF_RX_CSUM_OK)) {
        uint32_t s = pseudo_sum(ip->saddr, ip->daddr, IPPROTO_TCP_, (uint16_t)l4len);
        if (csum_fold(csum_chain(b, ETH_HLEN + ihl, s)) != 0) {
            t->st->rx_drop_csum++;
            goto drop;
        }
    }
    b->hash = h;
    tcp_input(t, b, ip, th, l4len);
    return;
drop:
    buf_free_chain(t, b);
}
