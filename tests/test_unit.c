/* Unit tests for internal building blocks: Toeplitz symmetry and reference
 * vector, SPSC ring, checksums, sequence arithmetic. */
#include "../src/utcp_int.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

static int fails;
#define CHECK(c)                                                                              \
    do {                                                                                      \
        if (!(c)) {                                                                           \
            printf("  FAIL %s:%d %s\n", __FILE__, __LINE__, #c);                              \
            fails++;                                                                          \
        }                                                                                     \
    } while (0)

static void *ma(void *c, size_t s, size_t a) { (void)c; void *p; return posix_memalign(&p, a, s) ? NULL : p; }
static void mf(void *c, void *p) { (void)c; free(p); }
static struct utcp_buf *ba(void *c) { (void)c; return NULL; }
static void bf(void *c, struct utcp_buf *b) { (void)c; (void)b; }
static int tx(void *c, struct utcp_buf **b, int n) { (void)c; (void)b; return n; }
static uint64_t now(void *c) { (void)c; return 1; }

int main(void)
{
    struct utcp_ops ops = {.mem_alloc = ma, .mem_free = mf, .buf_alloc = ba, .buf_free = bf,
                           .tx_burst = tx, .now_ns = now};
    /* Microsoft RSS verification vector (default key):
     * 66.9.149.187:2794 -> 161.142.100.80:1766  hash 0x51ccc178 */
    static const uint8_t mskey[40] = {
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2, 0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3,
        0x8f, 0xb0, 0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4, 0x77, 0xcb, 0x2d, 0xa3,
        0x80, 0x30, 0xf2, 0x0c, 0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa};
    struct utcp_config cfg;
    utcp_config_default(&cfg);
    memcpy(cfg.rss_key, mskey, 40);
    struct utcp_region *r;
    CHECK(utcp_region_create(&cfg, &ops, NULL, &r) == 0);
    uint32_t h = utcp_rss_hash(r, inet_addr("66.9.149.187"), inet_addr("161.142.100.80"),
                               htons(2794), htons(1766));
    printf("toeplitz reference: 0x%08x (expect 0x51ccc178)\n", h);
    CHECK(h == 0x51ccc178);

    /* symmetric key: hash(a,b) == hash(b,a) */
    utcp_config_default(&cfg);
    cfg.ncores = 4;
    struct utcp_region *rs;
    CHECK(utcp_region_create(&cfg, &ops, NULL, &rs) == 0);
    uint64_t x = 88172645463325252ULL;
    int asym = 0;
    for (int i = 0; i < 100000; i++) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        uint32_t a = (uint32_t)x, b = (uint32_t)(x >> 32);
        uint16_t p = (uint16_t)(x >> 3), q = (uint16_t)(x >> 19);
        if (utcp_rss_hash(rs, a, b, p, q) != utcp_rss_hash(rs, b, a, q, p))
            asym++;
    }
    printf("symmetric hash mismatches: %d / 100000\n", asym);
    CHECK(asym == 0);

    /* attach check: region must be at its creation address */
    utcp_t *t = utcp_attach(rs, 0, &ops, NULL);
    CHECK(t != NULL);
    struct utcp_region *copy = malloc(sizeof(*copy));
    memcpy(copy, rs, sizeof(*copy));
    CHECK(utcp_attach(copy, 0, &ops, NULL) == NULL && errno == EFAULT);
    free(copy);

    /* bucket distribution across 4 cores */
    int cnt[4] = {0};
    for (uint32_t b = 0; b < utcp_nbuckets(rs); b++)
        cnt[utcp_bucket_owner(rs, b)]++;
    CHECK(cnt[0] == 1024 && cnt[3] == 1024);

    /* SPSC ring */
    struct ring *rg = rs->rings[0 * 4 + 1];
    for (uintptr_t i = 1; i <= 4096; i++)
        CHECK(ring_push(rg, (void *)(i << 2)) == 0);
    CHECK(ring_push(rg, (void *)4) < 0);
    void *out[64];
    uintptr_t expect = 1;
    unsigned k;
    while ((k = ring_pop_burst(rg, out, 64)))
        for (unsigned i = 0; i < k; i++)
            CHECK((uintptr_t)out[i] == (expect++ << 2));
    CHECK(expect == 4097);

    /* checksum: chained == linear, odd split */
    uint8_t data[1001];
    for (int i = 0; i < 1001; i++)
        data[i] = (uint8_t)(i * 7 + 3);
    uint16_t lin = csum_fold(csum_partial(data, 1001, 0));
    struct utcp_buf b1 = {0}, b2 = {0}, b3 = {0};
    b1.data = data; b1.len = 333; b1.next = &b2;
    b2.data = data + 333; b2.len = 1; b2.next = &b3;
    b3.data = data + 334; b3.len = 667;
    uint16_t ch = csum_fold(csum_chain(&b1, 0, 0));
    printf("checksum linear=0x%04x chained=0x%04x\n", lin, ch);
    CHECK(lin == ch);

    /* sequence arithmetic across wrap */
    CHECK(seq_lt(0xfffffff0u, 0x10u));
    CHECK(seq_gt(0x10u, 0xfffffff0u));
    CHECK(seq_le(5, 5) && seq_ge(5, 5));

    printf("%s: %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails != 0;
}
