/* SPDX-License-Identifier: GPL-2.0-only */
/* Included by observer.bpf.c: one ELF object shares maps between all programs. */
#include "parse.h"
static __always_inline __u16 fold_checksum(__u64 sum) {
    sum=(sum&0xffffffff)+(sum>>32);
    sum=(sum&0xffff)+(sum>>16);sum=(sum&0xffff)+(sum>>16);
    return ~sum;
}
static __noinline int build(struct __sk_buff *skb,struct ff_request *r,struct ff_interface *iface) {
    struct packet p={};
    if(parse(skb,iface,r->reverse,&p)) return -1;
    __u32 tk=r->config_gen*2+(p.key.protocol==17);
    struct ff_template *t=bpf_map_lookup_elem(&templates,&tk);
    if(!t || p.l3>30) return -1;
    __u32 payload=t->len;
    if(!payload || payload>FF_PAYLOAD_MAX) return -1;
    __u32 iplen=p.key.family==4?20:40, thlen=p.key.protocol==6?20:8;
    __u32 transport=thlen+payload, length=p.l3+iplen+transport;
    if(iplen+transport>iface->mtu) {stat(FF_SKIP_MTU);return -1;}
    /* Keep the original checksum field as a seed. The checksum helper handles
     * CHECKSUM_PARTIAL: data deltas are ignored there, pseudo-header deltas
     * update the seed. Software-checksummed packets receive both deltas. */
    __u32 oldsum=0;
    __u8 block[64];
    for(int i=0;i<64;i++) {
        __u32 off=p.l4+i*64;
        if(off>=p.end) break;
        __u32 n=p.end-off;if(n>64)n=64;
        __builtin_memset(block,0,sizeof(block));
        if(bpf_skb_load_bytes(skb,off,block,n)) return -1;
        oldsum=bpf_csum_diff(0,0,(__be32*)block,64,oldsum);
    }
    __u8 eth[32]={},ip[40]={},th[20]={};
    __u32 l2len=p.l3&31;
    if(l2len && bpf_skb_load_bytes(skb,0,eth,l2len)) return -1;
    if(bpf_skb_load_bytes(skb,p.l3,ip,iplen)) return -1;
    if(r->reverse && p.l3) {
        __builtin_memcpy(eth,p.eth+6,6);__builtin_memcpy(eth+6,p.eth,6);
    }
    if(p.key.session) {
        if(p.l3<8 || p.l3>30) return -1;
        /* PPPoE LENGTH starts four bytes before the PPP protocol field. */
        __u32 at=p.l3-4;
        eth[at]=((iplen+transport+2)>>8);eth[at+1]=iplen+transport+2;
    }
    if(p.key.family==4) {
        __builtin_memcpy(ip+12,p.key.local,4);__builtin_memcpy(ip+16,p.key.remote,4);
        write16(ip+2,iplen+transport);ip[8]=r->ttl;ip[10]=ip[11]=0;
        __u16 sum=fold_checksum(bpf_csum_diff(0,0,(__be32*)ip,40,0));
        __builtin_memcpy(ip+10,&sum,2);
    } else {
        __builtin_memcpy(ip+8,p.key.local,16);__builtin_memcpy(ip+24,p.key.remote,16);
        write16(ip+4,transport);ip[7]=r->ttl;
    }
    write16(th,p.key.local_port);write16(th+2,p.key.remote_port);
    __u32 cs;
    if(p.key.protocol==6) {
        write32(th+4,r->reverse?p.ack:p.seq+1);
        write32(th+8,r->reverse?p.seq+1:p.ack);
        th[12]=0x50;th[13]=0x18;write16(th+14,128);cs=p.l4+16;
        __builtin_memcpy(th+16,&p.checksum,2);
    } else {
        write16(th+4,transport);cs=p.l4+6;
        __builtin_memcpy(th+6,&p.checksum,2);
    }
    __u32 newsum=bpf_csum_diff(0,0,(__be32*)th,20,0);
    __u32 padded=(payload+3)&~3;
    if(padded>FF_PAYLOAD_MAX) return -1;
    newsum=bpf_csum_diff(0,0,(__be32*)t->data,padded,newsum);
    __u64 delta=(__u64)(~oldsum)+newsum;
    delta=(delta&0xffffffff)+(delta>>32);
    if(bpf_skb_change_tail(skb,length,0)) return -1;
    if(l2len && bpf_skb_store_bytes(skb,0,eth,l2len,BPF_F_RECOMPUTE_CSUM)) return -1;
    if(bpf_skb_store_bytes(skb,p.l3,ip,iplen,BPF_F_RECOMPUTE_CSUM) ||
       bpf_skb_store_bytes(skb,p.l4,th,thlen,BPF_F_RECOMPUTE_CSUM) ||
       bpf_skb_store_bytes(skb,p.l4+thlen,t->data,payload,BPF_F_RECOMPUTE_CSUM)) return -1;
    __u64 flags=p.key.protocol==17?BPF_F_MARK_MANGLED_0:0;
    if(bpf_l4_csum_replace(skb,cs,0,delta,flags) ||
       bpf_l4_csum_replace(skb,cs,bpf_htonl(p.end-p.l4),bpf_htonl(transport),4|BPF_F_PSEUDO_HDR|flags)) return -1;
    bpf_csum_level(skb,BPF_CSUM_LEVEL_RESET);
    return 0;
}
SEC("tc") int ff_builder(struct __sk_buff *skb) {
    __u64 id=((__u64)skb->cb[1]<<32)|skb->cb[0];
    struct ff_request *r=bpf_map_lookup_elem(&requests,&id);
    __u64 now=bpf_ktime_get_ns();
    if(!r || r->expires<now || !alive(now)) {stat(FF_REQUEST_EXPIRED);return TC_ACT_SHOT;}
    struct ff_interface *iface=bpf_map_lookup_elem(&interfaces,&r->ifindex);
    if(!iface || iface->generation!=r->ifgen || iface->builder!=skb->ifindex ||
       __sync_val_compare_and_swap(&r->state,0,1)!=0) return TC_ACT_SHOT;
    if(build(skb,r,iface)) {stat(FF_BUILD_FAILED);return TC_ACT_SHOT;}
    stat(FF_BUILD_OK);
    r->state=2;
    return bpf_redirect(r->ifindex,0);
}
SEC("tc") int ff_drop(struct __sk_buff *skb) { (void)skb;return TC_ACT_SHOT; }
