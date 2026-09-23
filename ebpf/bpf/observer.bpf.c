/* SPDX-License-Identifier: GPL-2.0-only */
#include "tcp.h"
#include "udp.h"
#include "builder.bpf.c"
static __always_inline int reserve(struct ff_interface *iface,struct ff_config *c,__u64 now) {
    __u32 slot=iface->slot;
    struct ff_budget *b=bpf_map_lookup_elem(&budgets,&slot);
    if(!b) return 0;
    int ok=0;
    bpf_spin_lock(&b->lock);
    if(!b->at) {b->tokens=(__u64)c->burst*FF_NS;b->at=now;}
    __u64 elapsed=now-b->at;
    __u64 limit=(__u64)c->burst*FF_NS, tokens=limit;
    if(c->rate && elapsed<=limit/c->rate) tokens=b->tokens+elapsed*c->rate;
    if(tokens>limit) tokens=limit;
    b->at=now;b->tokens=tokens;
    if(tokens>=(__u64)c->repeat*FF_NS) {b->tokens-=(__u64)c->repeat*FF_NS;ok=1;}
    bpf_spin_unlock(&b->lock);
    if(!ok) stat(FF_RATE_LIMITED);
    return ok;
}
static __noinline int emit(struct __sk_buff *skb,struct ff_interface *iface,struct ff_config *c,int reverse,__u32 remote_ttl) {
    __u64 now=bpf_ktime_get_ns();__u32 ttl=c->ttl,z=0;
    if(c->estimate_hops && remote_ttl) {
        __u32 initial=remote_ttl<=64?64:remote_ttl<=128?128:255;
        __u32 hops=initial-remote_ttl;
        __u32 dynamic=hops*c->percent/100;
        if(dynamic>ttl) ttl=dynamic;
        if(ttl>=hops) {stat(FF_SKIP_NEAR);return 0;}
    } else if(!remote_ttl) stat(FF_TTL_UNKNOWN);
    if(!reserve(iface,c,now)) return 0;
    __u64 *seq=bpf_map_lookup_elem(&sequence,&z);
    if(!seq) return 0;
    __u32 saved[5];
    __builtin_memcpy(saved,skb->cb,sizeof(saved));
    for(int i=0;i<8;i++) {
        if(i>=c->repeat) break;
        stat(FF_ATTEMPT);
        __u64 id=__sync_fetch_and_add(seq,1)+1;
        struct ff_request r={.expires=now+FF_REQUEST_NS,.ifindex=skb->ifindex,
            .ifgen=iface->generation,.config_gen=c->generation,.mode=iface->mode,
            .reverse=reverse,.ttl=ttl};
        __builtin_memcpy(r.saved_cb,saved,sizeof(saved));
        if(bpf_map_update_elem(&requests,&id,&r,BPF_NOEXIST)) {stat(FF_MAP_FAILED);continue;}
        skb->cb[0]=id;skb->cb[1]=id>>32;
        long rc=bpf_clone_redirect(skb,iface->builder,0);
        __builtin_memcpy(skb->cb,saved,sizeof(saved));
        struct ff_request *result=bpf_map_lookup_elem(&requests,&id);
        if(rc) stat(FF_CLONE_FAILED);
        else if(result && result->state==3) stat(FF_SUBMIT_OK);
        else stat(FF_BUILD_FAILED);
        bpf_map_delete_elem(&requests,&id);
    }
    return 0;
}
static __always_inline int observe(struct __sk_buff *skb,int in) {
    __u64 id=((__u64)skb->cb[1]<<32)|skb->cb[0];
    struct ff_request *r=bpf_map_lookup_elem(&requests,&id);
    if(r && r->state==2 && r->ifindex==skb->ifindex && !in) {
        __u32 idx=skb->ifindex;
        struct ff_interface *iface=bpf_map_lookup_elem(&interfaces,&idx);
        if(!iface || iface->generation!=r->ifgen || __sync_val_compare_and_swap(&r->state,2,3)!=2) return TC_ACT_SHOT;
        __builtin_memcpy(skb->cb,r->saved_cb,sizeof(r->saved_cb));
        stat(FF_INTERNAL);return TC_ACT_UNSPEC;
    }
    __u64 now=bpf_ktime_get_ns();
    if(!alive(now)) {stat(FF_LEASE_EXPIRED);return TC_ACT_UNSPEC;}
    struct ff_config *c=configuration();
    __u32 idx=skb->ifindex;
    struct ff_interface *iface=bpf_map_lookup_elem(&interfaces,&idx);
    if(!c || !iface) return TC_ACT_UNSPEC;
    struct packet p={};
    if(parse(skb,iface,in,&p)) {stat(FF_SKIP_LAYOUT);return TC_ACT_UNSPEC;}
    if(!remote_allowed(&p,c)) {stat(FF_SKIP_PRIVATE);return TC_ACT_UNSPEC;}
    __u32 remote_ttl=0;int trigger=0;
    if(p.key.protocol==6 && c->tcp_enabled) trigger=tcp_trigger(skb,&p,c,in,now,&remote_ttl);
    else if(p.key.protocol==17 && c->udp_enabled) trigger=udp_trigger(&p,c,in,now,&remote_ttl);
    if(trigger) emit(skb,iface,c,in,remote_ttl);
    return TC_ACT_UNSPEC;
}
SEC("tc") int ff_ingress(struct __sk_buff *skb) {return observe(skb,1);}
SEC("tc") int ff_egress(struct __sk_buff *skb) {return observe(skb,0);}
char LICENSE[] SEC("license")="GPL";
