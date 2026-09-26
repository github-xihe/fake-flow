/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FF_MAPS_H
#define FF_MAPS_H
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "abi.h"
struct ff_flow {
    __u32 reserved;
    __u32 syn_seq, syn_bytes, active, stopped, batches, packets, outbound, remote_ttl;
    __u64 seen, emitted;
};
struct ff_budget { struct bpf_spin_lock lock; __u32 generation; __u64 at, tokens; };
struct ff_lock { struct bpf_spin_lock lock; __u32 reserved; };
struct ff_request {
    __u64 expires;
    __u32 state, ifindex, ifgen, config_gen, mode, reverse, ttl;
    /* Template variant chosen once per trigger so that every clone of the same
     * fake datagram carries one identity. A SIP retransmission must reuse its
     * branch and Call-ID, so per-clone randomness would itself be a new
     * fingerprint rather than a fix. */
    __u32 variant;
    /* Only cb[0] and cb[1] carry the request id, so the entry stores only the
     * words that emit() overwrites. A smaller entry also shrinks emit()'s own
     * frame, because the entry is a stack object there before it is published. */
    __u32 saved_cb[2];
};
/* reported is an edge flag: a lease outage is counted once instead of once per
 * packet, and userspace clears it on every successful refresh. */
struct ff_lease { __u64 until; __u32 reported; __u32 pad; };
#define MAP(name,kind,kt,vt,n) struct { __uint(type,kind); __uint(max_entries,n); __type(key,kt); __type(value,vt); } name SEC(".maps")
MAP(active_config,BPF_MAP_TYPE_ARRAY,__u32,__u32,1);
MAP(configs,BPF_MAP_TYPE_HASH,__u32,struct ff_config,16);
MAP(leases,BPF_MAP_TYPE_ARRAY,__u32,struct ff_lease,1);
MAP(interfaces,BPF_MAP_TYPE_HASH,__u32,struct ff_interface,FF_INTERFACES);
/* Holds 2 * FF_TEMPLATE_VARIANTS keys per generation. The reaper keeps the
 * active and the previous generation (three during a publish), so 3 * 2 * 32 =
 * 192 keys are live at the peak; 256 leaves headroom without a large
 * preallocation. */
MAP(templates,BPF_MAP_TYPE_HASH,__u32,struct ff_template,256);
MAP(tcp_flows,BPF_MAP_TYPE_LRU_HASH,struct ff_key,struct ff_flow,8192);
MAP(udp_flows,BPF_MAP_TYPE_LRU_HASH,struct ff_key,struct ff_flow,8192);
/* LRU maps cannot embed bpf_spin_lock. A stable key-derived array lock guards
 * updates; LRU eviction can still lose coverage as permitted by the spec. */
MAP(flow_locks,BPF_MAP_TYPE_ARRAY,__u32,struct ff_lock,1024);
MAP(requests,BPF_MAP_TYPE_HASH,__u64,struct ff_request,256);
MAP(sequence,BPF_MAP_TYPE_ARRAY,__u32,__u64,1);
MAP(budgets,BPF_MAP_TYPE_ARRAY,__u32,struct ff_budget,FF_INTERFACES);
MAP(stats,BPF_MAP_TYPE_PERCPU_ARRAY,__u32,__u64,FF_STATS_MAX);
static __always_inline void stat(__u32 id) {
    __u64 *n=bpf_map_lookup_elem(&stats,&id); if(n) (*n)++;
}
static __always_inline struct ff_config *configuration(void) {
    __u32 z=0,*gen=bpf_map_lookup_elem(&active_config,&z);
    if(!gen) return 0;
    return bpf_map_lookup_elem(&configs,gen);
}
static __always_inline int alive(__u64 now) {
    __u32 z=0; struct ff_lease *l=bpf_map_lookup_elem(&leases,&z);
    if(!l) return 0;
    if(now<l->until) return 1;   /* fast path keeps the lease map read-only */
    if(!l->reported && !__sync_val_compare_and_swap(&l->reported,0,1)) stat(FF_LEASE_EXPIRED);
    return 0;
}
static __always_inline struct ff_lock *flow_lock(struct ff_key *key) {
    __u32 bucket=(key->local_port^key->remote_port^key->ifindex)&1023;
    return bpf_map_lookup_elem(&flow_locks,&bucket);
}
#endif
