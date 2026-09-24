/* SPDX-License-Identifier: GPL-2.0-only */
/* Included by observer.bpf.c: one ELF object shares maps between all programs. */
#include "parse.h"
static __always_inline __u16 fold_checksum(__u64 sum) {
    sum=(sum&0xffffffff)+(sum>>32);
    sum=(sum&0xffff)+(sum>>16);sum=(sum&0xffff)+(sum>>16);
    return ~sum;
}
static __noinline int store_payload(struct __sk_buff *skb,__u32 off,const void *data,__u64 bytes) {
    /* Keep the range proof in this frame. Barriers prevent LLVM from removing
     * checks using the caller's bounds, which older verifiers lose on spills.
     * Reconstruct 1..MAX from a proven 0..MAX-1 range: on Linux 6.6 merely
     * excluding zero with JEQ does not establish a positive unsigned bound. */
    asm volatile("" : "+r"(bytes));
    bytes--;
    asm volatile("" : "+r"(bytes));
    if(bytes>=FF_PAYLOAD_MAX) return -1;
    asm volatile("" : "+r"(bytes));
    bytes++;
    return bpf_skb_store_bytes(skb,off,data,bytes,BPF_F_RECOMPUTE_CSUM);
}
static __noinline int load_chunk(struct __sk_buff *skb,__u32 off,void *data,__u64 bytes) {
    /* The checksum loop needs the same explicit 64-bit positive range proof. */
    asm volatile("" : "+r"(bytes));
    bytes--;
    asm volatile("" : "+r"(bytes));
    if(bytes>=64) return -1;
    asm volatile("" : "+r"(bytes));
    bytes++;
    return bpf_skb_load_bytes(skb,off,data,bytes);
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
        if(p.first_fragment) break;
        __u32 off=p.l4+i*64;
        if(off>=p.end) break;
        __u32 n=p.end-off;if(n>64)n=64;
        __builtin_memset(block,0,sizeof(block));
        if(load_chunk(skb,off,block,n)) return -1;
        oldsum=bpf_csum_diff(0,0,(__be32*)block,64,oldsum);
    }
    __u8 eth[32]={},ip[40]={},th[20]={};
    /* Older verifiers lose the nonzero bound when an ALU32 length is spilled
     * before its check and reloaded for a helper. Use constant helper sizes.
     * parse() guarantees at least 14 L2 + 20 IP + 8 transport bytes on L2
     * paths, so reading 32 bytes is safe; only the L2 prefix is written back. */
    if(p.l3 && bpf_skb_load_bytes(skb,0,eth,sizeof(eth))) return -1;
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
        /* The injected datagram is complete, independent of the real fragments. */
        if(p.first_fragment)write16(ip+6,0);
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
        if(!p.first_fragment)__builtin_memcpy(th+6,&p.checksum,2);
    }
    __u32 newsum=bpf_csum_diff(0,0,(__be32*)th,20,0);
    /* Linux 6.6 limits csum_diff scratch space to 512 bytes. Fixed 80-byte
     * chunks divide the 1200-byte zero-padded template and stay within it. */
    for(int i=0;i<15;i++) {
        __u32 offset=i*80;
        if(offset>=payload)break;
        if(offset>1120)return -1;
        __s64 part=bpf_csum_diff(0,0,(__be32*)(t->data+offset),80,newsum);
        if(part<0)return -1;
        newsum=part;
    }
    __u64 delta=(__u64)(~oldsum)+newsum;
    delta=(delta&0xffffffff)+(delta>>32);
    __u32 pseudo=0;
    if(p.first_fragment) {
        /* The original UDP checksum covers missing fragments; it cannot seed
         * an incremental update. Start at one's-complement zero, then apply
         * data and pseudo-header sums separately. l4_csum_replace ignores the
         * data sum for CHECKSUM_PARTIAL and produces its correct offload seed. */
        __builtin_memset(block,0,sizeof(block));
        __builtin_memcpy(block,ip+12,8);block[9]=17;write16(block+10,transport);
        pseudo=bpf_csum_diff(0,0,(__be32*)block,12,0);
        delta=newsum;th[6]=th[7]=0xff;
    }
    if(bpf_skb_change_tail(skb,length,0)) return -1;
    if(p.l3) {
        if(bpf_skb_store_bytes(skb,0,eth,14,BPF_F_RECOMPUTE_CSUM)) return -1;
        /* Supported L2 sizes: 14/18/22/26/30 (Ethernet, VLAN, PPPoE).
         * Keep each VLAN/PPPoE chunk constant even on kernels that cannot
         * propagate scalar range refinement back to a 32-bit stack spill. */
#pragma unroll
        for(int off=14;off<30;off+=4) {
            if(p.l3>=off+4 && bpf_skb_store_bytes(skb,off,eth+off,4,BPF_F_RECOMPUTE_CSUM)) return -1;
        }
    }
    if(bpf_skb_store_bytes(skb,p.l3,ip,iplen,BPF_F_RECOMPUTE_CSUM) ||
       bpf_skb_store_bytes(skb,p.l4,th,thlen,BPF_F_RECOMPUTE_CSUM) ||
       store_payload(skb,p.l4+thlen,t->data,payload)) return -1;
    __u64 flags=p.key.protocol==17?BPF_F_MARK_MANGLED_0:0;
    if(bpf_l4_csum_replace(skb,cs,0,delta,flags)) return -1;
    if(p.first_fragment) {
        if(bpf_l4_csum_replace(skb,cs,0,pseudo,BPF_F_PSEUDO_HDR|flags)) return -1;
    } else if(bpf_l4_csum_replace(skb,cs,bpf_htonl(p.end-p.l4),bpf_htonl(transport),4|BPF_F_PSEUDO_HDR|flags)) return -1;
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
    if(!alive(bpf_ktime_get_ns()))return TC_ACT_SHOT;
    stat(FF_BUILD_OK);
    r->state=2;
    return bpf_redirect(r->ifindex,0);
}
SEC("tc") int ff_drop(struct __sk_buff *skb) { (void)skb;return TC_ACT_SHOT; }
