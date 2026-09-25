/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FF_PARSE_H
#define FF_PARSE_H
#include "maps.h"
struct packet {
    struct ff_key key;
    __u32 l3,l4,end,hlen,bytes,seq,ack;
    __u16 checksum;
    __u8 ttl,flags,first_fragment,fragment_header,eth[22];
};
static __always_inline __u16 read16(const __u8 *p) {return ((__u16)p[0]<<8)|p[1];}
static __always_inline __u32 read32(const __u8 *p) {return ((__u32)read16(p)<<16)|read16(p+2);}
static __always_inline void write16(__u8 *p,__u16 n) {p[0]=n>>8;p[1]=n;}
static __always_inline void write32(__u8 *p,__u32 n) {write16(p,n>>16);write16(p+2,n);}
static __always_inline int parse(struct __sk_buff *skb,struct ff_interface *iface,int in,struct packet *p) {
    __u8 h[40]={}; __u32 off=0, proto=0, envelope=skb->len;
    p->key.ifindex=skb->ifindex; p->key.generation=iface->generation;
    if(skb->gso_segs>1 || skb->gso_size) {stat(FF_SKIP_GSO);return -1;}
    if(skb->len>4096) {stat(FF_SKIP_LEN);return -1;}
    if(iface->mode!=FF_L3) {
        if(bpf_skb_load_bytes(skb,0,p->eth,14)) {stat(FF_SKIP_L2);return -1;}
        if((p->eth[0]&1)||(p->eth[6]&1)) {stat(FF_SKIP_L2);return -1;}
        off=14;proto=read16(p->eth+12);
        int tags=0;
        if(skb->vlan_present) {p->key.vlan[0]=skb->vlan_tci;p->key.vlan_proto[0]=bpf_ntohs(skb->vlan_proto);tags=1;}
        for(int i=0;i<2;i++) {
            if(proto!=0x8100 && proto!=0x88a8) break;
            if(tags>=2 || bpf_skb_load_bytes(skb,off,h,4)) {stat(FF_SKIP_L2);return -1;}
            if(!tags) {p->key.vlan[0]=read16(h);p->key.vlan_proto[0]=proto;}
            else {p->key.vlan[1]=read16(h);p->key.vlan_proto[1]=proto;}
            tags++;proto=read16(h+2);off+=4;
        }
        p->key.vlan_count=tags;
        if(proto==0x8864) {
            if(iface->mode!=FF_PPPOE || bpf_skb_load_bytes(skb,off,h,8)) {stat(FF_SKIP_L2);return -1;}
            if(h[0]!=0x11 || h[1] || !read16(h+2) || read16(h+4)<2 || off+6+read16(h+4)>skb->len) {stat(FF_SKIP_L2);return -1;}
            p->key.session=read16(h+2);
            envelope=off+6+read16(h+4);
            __builtin_memcpy(p->key.peer,p->eth+(in?6:0),6);
            proto=read16(h+6);proto=proto==0x21?0x800:proto==0x57?0x86dd:0;
            off+=8;
        } else if(iface->mode==FF_PPPOE) {stat(FF_SKIP_L2);return -1;}
    }
    p->l3=off;
    if(bpf_skb_load_bytes(skb,off,h,20)) {stat(FF_SKIP_TRUNC);return -1;}
    if((h[0]>>4)==4 && (iface->mode==FF_L3 || proto==0x800)) {
        if(h[0]!=0x45) {stat(FF_SKIP_IPV4_OPTS);return -1;}
        __u16 frag=read16(h+6);
        /* A UDP first fragment contains the tuple. Never treat later fragments
         * as transport headers or consume the early-packet window for them. */
        if((frag&0x1fff) || ((frag&0x2000) && h[9]!=17)) {stat(FF_SKIP_FRAGMENT);return -1;}
        p->first_fragment=!!(frag&0x2000);
        if(p->first_fragment && ((frag&0xc000) || read16(h+2)<28 || ((read16(h+2)-20)&7))) {stat(FF_SKIP_FRAGMENT);return -1;}
        p->key.family=4;p->key.protocol=h[9];p->ttl=h[8];
        p->end=off+read16(h+2);p->l4=off+20;
        __builtin_memcpy(p->key.local,in?h+16:h+12,4);
        __builtin_memcpy(p->key.remote,in?h+12:h+16,4);
    } else if((h[0]>>4)==6 && (iface->mode==FF_L3 || proto==0x86dd)) {
        if(bpf_skb_load_bytes(skb,off,h,40)) {stat(FF_SKIP_TRUNC);return -1;}
        p->key.family=6;p->key.protocol=h[6];p->ttl=h[7];
        p->end=off+40+read16(h+4);p->l4=off+40;
        __builtin_memcpy(p->key.local,in?h+24:h+8,16);
        __builtin_memcpy(p->key.remote,in?h+8:h+24,16);
        /* Support the bounded IPv6 -> Fragment -> UDP layout. Later pieces
         * have no usable tuple. Other extension chains remain fail-open. */
        if(p->key.protocol==44) {
            if(p->end>envelope || p->end<p->l4+8 ||
               bpf_skb_load_bytes(skb,p->l4,h,8)) {stat(FF_SKIP_TRUNC);return -1;}
            __u16 frag=read16(h+2);
            if((frag&0xfff8) || h[0]!=17) {stat(FF_SKIP_FRAGMENT);return -1;}
            if(h[1] || (frag&6)) {stat(FF_SKIP_FRAGMENT);return -1;}
            p->fragment_header=1;p->first_fragment=frag&1;
            p->key.protocol=17;p->l4+=8;
            if(p->first_fragment && ((p->end-p->l4)&7)) {stat(FF_SKIP_FRAGMENT);return -1;}
        }
    } else {stat(FF_SKIP_IPVER);return -1;}
    if(p->end>envelope || p->end<p->l4) {stat(FF_SKIP_TRUNC);return -1;}
    if(p->key.protocol==6) {
        if(p->end<p->l4+20 || bpf_skb_load_bytes(skb,p->l4,h,20)) {stat(FF_SKIP_TRUNC);return -1;}
        p->hlen=(h[12]>>4)*4;p->flags=h[13];p->seq=read32(h+4);p->ack=read32(h+8);
        if(p->hlen<20 || p->hlen>60 || p->l4+p->hlen>p->end) {stat(FF_SKIP_TRUNC);return -1;}
        __builtin_memcpy(&p->checksum,h+16,2);
    } else if(p->key.protocol==17) {
        if(p->end<p->l4+8 || bpf_skb_load_bytes(skb,p->l4,h,8)) {stat(FF_SKIP_TRUNC);return -1;}
        __u32 udp_len=read16(h+4),present=p->end-p->l4;
        if(p->first_fragment) {
            if(udp_len<=present || (p->key.family==4 && udp_len>65515)) {stat(FF_SKIP_TRUNC);return -1;}
        } else if(udp_len!=present) {stat(FF_SKIP_TRUNC);return -1;}
        p->hlen=8;__builtin_memcpy(&p->checksum,h+6,2);
        if(p->key.family==6 && !p->checksum) {stat(FF_SKIP_TRUNC);return -1;}
    } else {stat(FF_SKIP_PROTO);return -1;}
    __u16 source_port=read16(h),destination_port=read16(h+2);
    p->key.local_port=in?destination_port:source_port;
    p->key.remote_port=in?source_port:destination_port;
    p->bytes=p->end-p->l4-p->hlen;
    return 0;
}
static __always_inline int remote_allowed(struct packet *p,struct ff_config *c) {
    __u8 *a=p->key.remote;
    if(p->key.family==4) {
        if(a[0]>=224 || !a[0] || a[0]==127) return 0;
        if(!c->allow_private && (a[0]==10 || (a[0]==172 && (a[1]&240)==16) ||
            (a[0]==192 && a[1]==168) || (a[0]==169 && a[1]==254) ||
            (a[0]==100 && (a[1]&192)==64))) return 0;
    } else {
        if(a[0]==255) return 0;
        __u32 w0=read32(a),w1=read32(a+4),w2=read32(a+8),w3=read32(a+12);
        if(!c->allow_private && ((a[0]&0xfe)==0xfc || (a[0]==0xfe && (a[1]&0xc0)==0x80) ||
            (w0==0 && w1==0 && ((w2==0 && w3<=1) || w2==0xffff)) ||
            (w0==0x0064ff9b && ((w1==0 && w2==0) || (w1>>16)==1)) ||
            (w0>>16)==0x2002)) return 0;
    }
    return 1;
}
#endif
