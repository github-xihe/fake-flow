/* SPDX-License-Identifier: GPL-2.0-only */
#include "fakeflow.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/random.h>
static int custom(const char *path, struct ff_template *t) {
    FILE *f=fopen(path,"rb"); if(!f) return -1;
    t->len=fread(t->data,1,FF_PAYLOAD_MAX,f);
    int extra=fgetc(f), bad=ferror(f);
    fclose(f); return (!t->len || extra!=EOF || bad) ? -1 : 0;
}
static int safe_text(const char *s) {
    if(!*s) return 0;
    for(;*s;s++) if((unsigned char)*s<=32 || (unsigned char)*s>=127) return 0;
    return 1;
}
static void put16(unsigned char *p,unsigned n) {p[0]=n>>8;p[1]=n;}
/* Fixed-length random hex token. Placeholder constants in the generated
 * datagram ("fakeflow", "example.com", 192.0.2.1, a bare "Mozilla/5.0") are
 * trivial DPI fingerprints, so identity fields are derived from the configured
 * URI and every variable part is randomised. */
static void hex_raw(char *out,unsigned bytes) {
    static const char d[]="0123456789abcdef";
    unsigned char r[32];
    if(bytes>sizeof(r)) bytes=sizeof(r);
    if(getrandom(r,bytes,0)!=(long)bytes)
        for(unsigned i=0;i<bytes;i++) r[i]=(unsigned char)(i*37+11);
    for(unsigned i=0;i<bytes;i++) {out[i*2]=d[r[i]>>4];out[i*2+1]=d[r[i]&15];}
}
/* NUL-terminated form for fields that are consumed as C strings. */
static void hex_token(char *out,unsigned bytes) {hex_raw(out,bytes);out[bytes*2]=0;}
static int is_hex(char c) {return (c>='0'&&c<='9')||(c>='a'&&c<='f');}
static int tls(struct ff_template *t,const char *hostname) {
    size_t n=strlen(hostname); unsigned char *p=t->data;
    /* TLS 1.2 ClientHello with SNI and a single supported cipher suite. The
     * 32-byte ClientHello random is generated here, so a variant of this
     * template is produced by rendering again rather than by patching bytes. */
    memset(t,0,sizeof(*t));
    p[0]=22;p[1]=3;p[2]=1;p[5]=1;
    p[9]=3;p[10]=3;
    if(getrandom(p+11,32,0)!=32) return -1;
    unsigned pos=43;
    p[pos++]=0; put16(p+pos,2);pos+=2;put16(p+pos,0xc02f);pos+=2;
    p[pos++]=1;p[pos++]=0;
    put16(p+pos,n+9);pos+=2;put16(p+pos,0);pos+=2;
    put16(p+pos,n+5);pos+=2;put16(p+pos,n+3);pos+=2;p[pos++]=0;
    put16(p+pos,n);pos+=2;memcpy(p+pos,hostname,n);pos+=n;
    put16(p+3,pos-5); p[6]=(pos-9)>>16;p[7]=(pos-9)>>8;p[8]=pos-9;
    t->len=pos;return 0;
}
/* HTTP request template. Shared by the primary slot and by any extra slot whose
 * payload is `http`, so a `Host:` template can carry a port that HTTPS does not
 * use. */
static int http(struct ff_template *t,const char *hostname) {
    memset(t,0,sizeof(*t));
    int n=snprintf((char*)t->data,FF_PAYLOAD_MAX,
        "GET / HTTP/1.1\r\nHost: %s\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n",hostname);
    if(n<0 || n>=FF_PAYLOAD_MAX) return -1;
    t->len=n;return 0;
}
/* Render one port-matched slot. A payload file wins over the generated kinds, so
 * a slot with both is rejected during parsing instead of here. Returns -1 for an
 * unreadable or oversized payload file and -2 for anything else, which is the
 * distinction the caller turns into its two error messages. */
static int slot_template(struct ff_tcp_slot *s,unsigned kind,struct ff_plan *plan) {
    if(*s->file) {
        if(custom(s->file,&s->tpl)) return -1;
        return 0;
    }
    if(!safe_text(s->hostname)) return -2;
    if(kind==FF_SLOT_HTTP) return http(&s->tpl,s->hostname)?-2:0;
    if(tls(&s->tpl,s->hostname)) return -2;
    plan->kind=FF_VARIANT_RENDER;plan->variants=FF_TEMPLATE_VARIANTS;
    return 0;
}
/* Record where the randomised identity fields landed, so PATCH variants can be
 * produced without re-parsing the datagram. Requiring the terminator and
 * hex-only digits rejects a field that shifted or was truncated, which would
 * otherwise let a variant write past the datagram. */
static int locate(struct ff_plan *plan,const struct ff_template *t) {
    static const struct { const char *mark; unsigned skip, bytes; char term; } field[FF_RAND_FIELDS]={
        {";branch=z9hG4bK",15,16,'\r'},
        {";tag=",           5, 4,'\r'},
        {"Call-ID: ",       9,16,'@' },
    };
    const char *buf=(const char*)t->data;
    plan->rand_count=0;
    for(unsigned i=0;i<FF_RAND_FIELDS;i++) {
        const char *q=strstr(buf,field[i].mark);
        if(!q) return -1;
        unsigned off=(unsigned)(q-buf)+field[i].skip, span=field[i].bytes*2;
        if(off+span>=(unsigned)t->len) return -1;
        if(buf[off+span]!=field[i].term) return -1;
        for(unsigned k=0;k<span;k++) if(!is_hex(buf[off+k])) return -1;
        plan->rand[i].off=off;plan->rand[i].bytes=field[i].bytes;
        plan->rand_count=i+1;
    }
    return 0;
}
int ff_templates(struct ff_options *o,char *error,size_t cap) {
    int n=0;
    struct ff_plan *tcp0=&o->plan[FF_TEMPLATE_PLAN(0,0)];
    struct ff_plan *udp0=&o->plan[FF_TEMPLATE_PLAN(1,0)];
    memset(&o->tcp_template,0,sizeof(o->tcp_template));
    memset(&o->udp_template,0,sizeof(o->udp_template));
    memset(o->plan,0,sizeof(o->plan));
    /* o->extra is deliberately not cleared here: the parser filled the slots'
     * hostname/file/kind and this function only renders them. Callers must pass a
     * zeroed struct (ff_config_read does, which is also what keeps the slots the
     * configuration did not define empty and therefore unpublished). */
    /* A template without randomised bytes is published once; the others get the
     * full pre-rendered set the observer picks from. */
    for(unsigned p=0;p<FF_TEMPLATE_PLAN_COUNT;p++) {
        o->plan[p].kind=FF_VARIANT_SAME;o->plan[p].variants=1;
    }

    if(!strcmp(o->tcp_payload,"custom")) {
        if(custom(o->tcp_file,&o->tcp_template)) goto bad_file;
    } else {
        if(*o->tcp_file || !safe_text(o->hostname)) goto bad;
        if(!strcmp(o->tcp_payload,"http")) {
            if(http(&o->tcp_template,o->hostname)) goto bad;
        } else if(!strcmp(o->tcp_payload,"tls")) {
            if(tls(&o->tcp_template,o->hostname)) goto bad;
            tcp0->kind=FF_VARIANT_RENDER;tcp0->variants=FF_TEMPLATE_VARIANTS;
        } else goto bad;
    }

    /* Slot 0 mirrors the primary template, so the publish loop and the variant
     * renderer treat every slot the same way instead of special-casing the
     * primary. */
    o->extra[0].tpl=o->tcp_template;
    strcpy(o->extra[0].hostname,o->hostname);
    strcpy(o->extra[0].file,o->tcp_file);
    /* Port-matched slots, in configuration order: the https_* compatibility keys
     * take slot 1, then each [[tcp.extra]] entry the next free slot. The parser
     * filled their hostname/file/kind and bounds extra_count to the slots that
     * exist, so a slot the configuration did not define is never rendered (and
     * never published, which is what keeps its connections on the primary). */
    for(unsigned s=1;s<=o->extra_count && s<FF_TEMPLATE_SLOTS;s++) {
        int rc=slot_template(&o->extra[s],o->extra_kind[s],&o->plan[FF_TEMPLATE_PLAN(0,s)]);
        if(rc==-1) goto bad_file;
        if(rc) goto bad;
    }

    if(!strcmp(o->udp_payload,"custom")) {
        if(custom(o->udp_file,&o->udp_template)) goto bad_file;
    } else {
        if(strcmp(o->udp_payload,"sip") || *o->udp_file || !safe_text(o->sip_uri) || strncmp(o->sip_uri,"sip:",4)) goto bad;
        /* Identity fields come from the configured URI; nothing from this
         * program's own name or from documentation address ranges is embedded,
         * because those are stable fingerprints in the produced datagram. */
        char host[256],user[128],branch[40],tag[16],callid[72],body[640];
        const char *u=o->sip_uri+4,*at=strchr(u,'@'),*h=at?at+1:u;
        size_t ul=at?(size_t)(at-u):0,hl=strcspn(h,":;>");
        if(hl>=sizeof(host)) hl=sizeof(host)-1;
        if(ul>=sizeof(user)) ul=sizeof(user)-1;
        if(ul) {memcpy(user,u,ul);user[ul]=0;} else memcpy(user,"caller",7);
        memcpy(host,h,hl);host[hl]=0;
        hex_token(branch,16);hex_token(tag,4);hex_token(callid,16);
        snprintf(body,sizeof(body),
            "v=0\r\no=- 1 1 IN IP4 %s\r\ns=-\r\nc=IN IP4 %s\r\nt=0 0\r\n"
            "m=audio 49170 RTP/AVP 0\r\n",host,host);
        n=snprintf((char*)o->udp_template.data,FF_PAYLOAD_MAX,
            "INVITE %s SIP/2.0\r\nVia: SIP/2.0/UDP %s:5060;branch=z9hG4bK%s\r\n"
            "Max-Forwards: 70\r\nFrom: <sip:%s@%s>;tag=%s\r\nTo: <%s>\r\n"
            "Call-ID: %s@%s\r\nCSeq: 1 INVITE\r\nContact: <sip:%s@%s>\r\n"
            "Content-Type: application/sdp\r\nContent-Length: %zu\r\n\r\n%s",
            o->sip_uri,host,branch,user,host,tag,o->sip_uri,callid,host,user,host,
            strlen(body),body);
        if(n<0 || n>=FF_PAYLOAD_MAX) goto bad;
        o->udp_template.len=n;
        if(locate(udp0,&o->udp_template)) goto bad;
        udp0->kind=FF_VARIANT_PATCH;udp0->variants=FF_TEMPLATE_VARIANTS;
    }
    return 0;
bad_file:
    snprintf(error,cap,"custom payload must be a readable file containing 1..1200 bytes");return -1;
bad:
    snprintf(error,cap,"invalid payload type, hostname, SIP URI or conflicting payload_file");return -1;
}
int ff_variants(const struct ff_options *o,struct ff_template out[][FF_TEMPLATE_VARIANTS],unsigned n) {
    if(!n || n>FF_TEMPLATE_VARIANTS) return -1;
    for(unsigned plan=0;plan<FF_TEMPLATE_PLAN_COUNT;plan++) {
        const struct ff_plan *p=&o->plan[plan];
        const struct ff_template *base;
        const char *host="";
        /* Plans 0..FF_TEMPLATE_SLOTS-1 are the TCP slots and slot 0 mirrors the
         * primary template; UDP publishes only its slot 0. */
        unsigned slot=plan%FF_TEMPLATE_SLOTS;
        if(plan<FF_TEMPLATE_SLOTS) {base=&o->extra[slot].tpl;host=o->extra[slot].hostname;}
        else if(plan==FF_TEMPLATE_PLAN(1,0)) base=&o->udp_template;
        else continue;
        unsigned count=p->variants?p->variants:1;
        if(count>n) count=n;
        for(unsigned v=0;v<count;v++) {
            out[plan][v]=*base;
            /* Variant zero stays canonical: a decode of live traffic can always
             * be compared byte for byte with what `validate` reports. */
            if(!v) continue;
            if(p->kind==FF_VARIANT_PATCH) {
                for(unsigned i=0;i<p->rand_count && i<FF_RAND_FIELDS;i++) {
                    if(!p->rand[i].bytes) continue;
                    unsigned off=p->rand[i].off, span=(unsigned)p->rand[i].bytes*2;
                    if(off+span>=(unsigned)out[plan][v].len) return -1;
                    hex_raw((char*)out[plan][v].data+off,p->rand[i].bytes);
                }
            } else if(p->kind==FF_VARIANT_RENDER) {
                if(tls(&out[plan][v],host)) return -1;
            }
        }
        /* A caller that publishes the whole span must never write an undefined
         * entry, so the unused tail repeats the canonical template. */
        for(unsigned v=count;v<n;v++) out[plan][v]=*base;
    }
    return 0;
}
