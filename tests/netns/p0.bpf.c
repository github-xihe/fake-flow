// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>

struct settings { __u32 wan, builder; };
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct settings);
} config SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");
static __always_inline void count(__u32 k) {
    __u64 *v = bpf_map_lookup_elem(&stats, &k);
    if (v) __sync_fetch_and_add(v, 1);
}
/* P0 only: fixed credentials and protocol marker are deliberately confined to
 * a disposable namespace. Production must use single-use map-backed requests. */
SEC("tc") int observer(struct __sk_buff *skb) {
    __u32 k = 0;
    struct settings *c = bpf_map_lookup_elem(&config, &k);
    unsigned char hdr[2];
    if (!c || bpf_skb_load_bytes(skb, 12, hdr, 2) || hdr[0] != 8 || hdr[1])
        return TC_ACT_UNSPEC;
    if (skb->cb[0] == 0xf10a1234) { count(2); skb->cb[0] = 0; return TC_ACT_UNSPEC; }
    __u32 saved = skb->cb[0];
    skb->cb[0] = 0xf10a5678;
    long rc = bpf_clone_redirect(skb, c->builder, 0);
    skb->cb[0] = saved;
    count(rc ? 4 : 0);
    return TC_ACT_UNSPEC;
}
SEC("tc") int builder(struct __sk_buff *skb) {
    __u32 k = 0;
    struct settings *c = bpf_map_lookup_elem(&config, &k);
    if (!c || skb->cb[0] != 0xf10a5678) { count(5); return TC_ACT_SHOT; }
    count(1);
    /* Resize only the clone. A distinctive Ethernet payload is sufficient for
     * this transport-path probe; protocol construction has separate tests. */
    if (bpf_skb_change_tail(skb, 80, 0)) { count(6); return TC_ACT_SHOT; }
    unsigned char marker = 0x42;
    if (bpf_skb_store_bytes(skb, 79, &marker, 1, 0)) return TC_ACT_SHOT;
    skb->cb[0] = 0xf10a1234;
    return bpf_redirect(c->wan, 0);
}
SEC("tc") int following(struct __sk_buff *skb) {
    (void)skb; count(3); return TC_ACT_UNSPEC;
}
char LICENSE[] SEC("license") = "GPL";
