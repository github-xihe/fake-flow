/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FF_UDP_H
#define FF_UDP_H
#include "parse.h"
static __always_inline int udp_trigger(struct packet *p,struct ff_config *c,int in,__u64 now,__u32 *ttl) {
    struct ff_lock *lock=flow_lock(&p->key);if(!lock)return 0;
    struct ff_flow *f=bpf_map_lookup_elem(&udp_flows,&p->key);
    if(!f) {
        struct ff_flow initial={};
        if(!bpf_map_update_elem(&udp_flows,&p->key,&initial,BPF_NOEXIST)) stat(FF_UDP_NEW);
        f=bpf_map_lookup_elem(&udp_flows,&p->key);
        if(!f) {stat(FF_MAP_FAILED);return 0;}
    }
    int emit=0,early=0;
    bpf_spin_lock(&lock->lock);
    if(now-f->seen>(__u64)c->udp_idle*FF_NS) {
        f->packets=0;f->batches=0;f->outbound=0;f->remote_ttl=0;
    }
    f->seen=now;
    if(f->packets<0xffffffff) f->packets++;
    if(in) f->remote_ttl=p->ttl;
    else f->outbound=1;
    early=f->packets<=c->udp_packets;
    if(early && f->batches<c->udp_packets && (!in || (c->udp_both && f->outbound))) {
        f->batches++;emit=1;*ttl=f->remote_ttl;
    }
    bpf_spin_unlock(&lock->lock);
    stat(early?FF_UDP_EARLY:FF_UDP_EXHAUSTED);
    return emit;
}
#endif
