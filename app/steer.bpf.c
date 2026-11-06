/* TAP queue steering (TUNSETSTEERINGEBPF): emulates NIC RSS with utcp's
 * Toeplitz key and bucket->core table, so each packet is delivered to the
 * TAP queue of the worker that owns its session. The return value is the
 * queue index. Same input byte order as utcp_rss_hash(): sip, dip, sp, dp. */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 12 * 256);
    __type(key, __u32);
    __type(value, __u32);
} toeplitz SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u32);
} owner SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} conf SEC(".maps"); /* [0] = nbuckets - 1 */

SEC("socket")
int steer(struct __sk_buff *skb)
{
    __u8 hdr[24];
    if (bpf_skb_load_bytes(skb, 12, hdr, 2))
        return 0;
    if (hdr[0] != 0x08 || hdr[1] != 0x00) /* not IPv4 (ARP etc.) */
        return 0;
    __u8 ip[20];
    if (bpf_skb_load_bytes(skb, 14, ip, 20))
        return 0;
    if (ip[9] != 6) /* TCP only; ICMP errors are steered by the stack */
        return 0;
    __u32 ihl = (ip[0] & 0xf) * 4;
    if (ihl < 20 || ihl > 60)
        return 0;
    __u8 in[12];
    __builtin_memcpy(in, ip + 12, 8);
    if (bpf_skb_load_bytes(skb, 14 + ihl, in + 8, 4))
        return 0;
    __u32 h = 0;
#pragma unroll
    for (int i = 0; i < 12; i++) {
        __u32 k = (__u32)i * 256 + in[i];
        __u32 *v = bpf_map_lookup_elem(&toeplitz, &k);
        if (v)
            h ^= *v;
    }
    __u32 z = 0;
    __u32 *mask = bpf_map_lookup_elem(&conf, &z);
    if (!mask)
        return 0;
    __u32 b = h & *mask;
    __u32 *o = bpf_map_lookup_elem(&owner, &b);
    return o ? (int)*o : 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
