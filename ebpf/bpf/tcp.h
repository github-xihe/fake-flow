/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FF_TCP_H
#define FF_TCP_H
#include "parse.h"
struct option_scan {
    __u8 old[40], replacement[40];
    __u32 n, next, nop_until, strip, changed, rejected;
};
static long scan_option(__u32 i,void *context) {
    struct option_scan *s=context;
    if(i>=40 || i>=s->n) return 1;
    if(i<s->next) {if(i<s->nop_until)s->replacement[i]=1;return 0;}
    __u8 kind=s->old[i];
    if(!kind) return 1;
    if(kind==1) {s->next=i+1;return 0;}
    if(i+1>=40 || i+1>=s->n) {s->rejected=1;return 1;}
    __u32 len=s->old[i+1];
    if(len<2 || i+len>s->n) {s->rejected=1;return 1;}
    if(kind==19 || kind==29) {s->rejected=2;return 1;}
    s->next=i+len;
    if(kind==34 && s->strip) {s->nop_until=s->next;s->replacement[i]=1;s->changed=1;}
    return 0;
}
/* Parse the complete option list before any write. Authenticated/malformed
 * options veto both stripping and injection, including an earlier TFO option. */
static __always_inline int options(struct __sk_buff *skb,struct packet *p,int strip) {
    struct option_scan s={};__u32 n=p->hlen-20;
    if(!n) return 0;
    if(n>40 || bpf_skb_load_bytes(skb,p->l4+20,s.old,n)) return -1;
    __builtin_memcpy(s.replacement,s.old,40);s.n=n;s.strip=strip;
    if(bpf_loop(40,scan_option,&s,0)<0 || s.rejected) {
        if(s.rejected==2)stat(FF_SKIP_AUTH);
        return -1;
    }
    if(!s.changed) return 0;
    /* Preflight COW/linearization before mutation. store_bytes and checksum
     * helper operate on validated, already-writable bounds; keep backups. */
    if(bpf_skb_pull_data(skb,p->l4+p->hlen)) {stat(FF_TFO_FAILED);return -1;}
    __s64 delta=bpf_csum_diff((__be32*)s.old,40,(__be32*)s.replacement,40,0);
    if(delta<0) return -1;
    if(bpf_skb_store_bytes(skb,p->l4+20,s.replacement,n,BPF_F_RECOMPUTE_CSUM)) {
        stat(FF_TFO_FAILED);return -1;
    }
    if(bpf_l4_csum_replace(skb,p->l4+16,0,delta,0)) {
        bpf_skb_store_bytes(skb,p->l4+20,s.old,n,BPF_F_RECOMPUTE_CSUM);
        bpf_skb_store_bytes(skb,p->l4+16,&p->checksum,2,0);
        stat(FF_TFO_FAILED);return -1;
    }
    stat(FF_TFO_STRIPPED);return 0;
}
static __always_inline int tcp_trigger(struct __sk_buff *skb,struct packet *p,struct ff_config *c,int in,__u64 now,__u32 *ttl) {
    int syn=(p->flags&0x17)==2, synack=(p->flags&0x17)==0x12;
    struct ff_lock *lock=flow_lock(&p->key);if(!lock)return 0;
    struct ff_flow *f=bpf_map_lookup_elem(&tcp_flows,&p->key);
    if(syn) {
        if(!(c->directions&(in?2:1))) return 0;
        stat(FF_TCP_SYN);
        int rejected=options(skb,p,c->strip_tfo);
        if(!f) {
            struct ff_flow initial={};
            initial.syn_seq=p->seq;initial.syn_bytes=p->bytes;initial.active=!in;
            initial.seen=now;initial.remote_ttl=in?p->ttl:0;initial.stopped=rejected!=0;
            if(bpf_map_update_elem(&tcp_flows,&p->key,&initial,BPF_NOEXIST)) {
                f=bpf_map_lookup_elem(&tcp_flows,&p->key);
                if(!f) stat(FF_MAP_FAILED);
            } else return 0;
        }
        if(!f) return 0;
        bpf_spin_lock(&lock->lock);
        if(now-f->seen>30*FF_NS || (f->syn_seq!=p->seq && f->active==!in)) {
            f->syn_seq=p->seq;f->syn_bytes=p->bytes;f->active=!in;
            f->stopped=0;f->batches=0;f->emitted=0;
        } else if(f->active!=!in) f->stopped=1; /* simultaneous open */
        if(rejected) f->stopped=1;
        f->seen=now;if(in) f->remote_ttl=p->ttl;
        bpf_spin_unlock(&lock->lock);
        return 0;
    }
    if(!f) return 0;
    int reject=0;
    if(synack) reject=p->bytes || options(skb,p,0);
    if(synack && p->bytes) stat(FF_SKIP_SYNACK_DATA);
    int emit=0;
    bpf_spin_lock(&lock->lock);
    if(now-f->seen>30*FF_NS) f->stopped=1;
    f->seen=now;
    if(!synack || reject) f->stopped=1;
    if(synack && f->active==in && !f->stopped &&
       (c->directions&(f->active?1:2)) &&
       (p->ack==f->syn_seq+1 || p->ack==f->syn_seq+1+f->syn_bytes) &&
       f->batches<c->tcp_batches && (!f->batches || now-f->emitted>=200000000ULL)) {
        f->batches++;f->emitted=now;emit=1;
        *ttl=in?p->ttl:f->remote_ttl;
    }
    bpf_spin_unlock(&lock->lock);
    if(emit) stat(FF_TCP_ELIGIBLE);
    return emit;
}
#endif
