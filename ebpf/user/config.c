/* SPDX-License-Identifier: GPL-2.0-only */
#include "fakeflow.h"
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *trim(char *s) {
    while (isspace((unsigned char)*s)) s++;
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n-1])) s[--n] = 0;
    return s;
}
static int string(char *v, char *out, size_t size) {
    size_t n = strlen(v);
    if (n < 2 || v[0] != '"' || v[n-1] != '"' || n-2 >= size) return -1;
    for (size_t i = 1; i < n-1; i++)
        if ((unsigned char)v[i] < 32 || v[i] == '"' || v[i] == '\\') return -1;
    memcpy(out, v+1, n-2); out[n-2] = 0; return 0;
}
static int number(char *v, __u32 *out, unsigned lo, unsigned hi) {
    char *end; errno = 0;
    if (!isdigit((unsigned char)*v)) return -1;
    unsigned long n = strtoul(v, &end, 10);
    if (*end || errno || n < lo || n > hi) return -1;
    *out = n; return 0;
}
static int boolean(char *v, __u32 *out) {
    if (!strcmp(v, "true")) *out = 1;
    else if (!strcmp(v, "false")) *out = 0;
    else return -1;
    return 0;
}
/* [443] or [443, 8443]. Only the deprecated https_ports key still reaches this,
 * and its value is discarded: rules are no longer selected by port, so the list
 * is accepted (and its syntax checked) purely so an existing configuration keeps
 * parsing. */
#define FF_PORTS_MAX 8
static int ports(char *v, unsigned *out, unsigned *count) {
    char compact[128]; unsigned n = 0;
    for (char *p = v; *p && n < sizeof(compact)-1; p++)
        if (!isspace((unsigned char)*p)) compact[n++] = *p;
    compact[n] = 0;
    *count = 0;
    char *p = compact;
    if (*p++ != '[' || *p == ']' || !*p) return -1;
    for (;;) {
        char *end; errno = 0;
        if (!isdigit((unsigned char)*p)) return -1;
        unsigned long num = strtoul(p, &end, 10);
        if (errno || num < 1 || num > 65535 || end == p) return -1;
        for (unsigned i = 0; i < *count; i++) if (out[i] == num) return -1;
        if (*count == FF_PORTS_MAX) return -1;
        out[(*count)++] = num;
        p = end;
        if (*p == ']' && !p[1]) return 0;
        if (*p != ',') return -1;
        p++;
    }
}
int ff_config_read(const char *path, struct ff_options *o, char *error, size_t cap) {
    memset(o, 0, sizeof(*o));
    o->kernel = (struct ff_config){.tcp_enabled=1,.udp_enabled=1,.directions=3,
        .strip_tfo=1,.tcp_batches=3,.udp_packets=5,.udp_idle=30,
        .ttl=3,.repeat=2,.estimate_hops=1,.rate=1000,.burst=2000};
    o->tcp_entries=8192; o->udp_entries=8192; o->lease=10;
    /* Legacy scratch fields: a configuration without [[tcp.rule]] entries is read
     * through these and turned into rules after parsing. */
    strcpy(o->tcp_payload,"http"); strcpy(o->udp_payload,"sip");
    strcpy(o->hostname,"www.example.com"); strcpy(o->sip_uri,"sip:service@example.com");
    char https_hostname[254] = "", https_file[1024] = "";
    FILE *f = fopen(path,"r");
    if (!f) { snprintf(error,cap,"%s: %s",path,strerror(errno)); return -1; }
    char line[2048], section[32]="", seen[128][96];
    unsigned lineno=0, count=0, version=0, sections_seen=0;
    int bad=0, ports_given=0, legacy_https=0;
    unsigned throwaway[FF_PORTS_MAX], throwaway_count=0;
    while (fgets(line,sizeof(line),f)) {
        lineno++;
        if (!strchr(line,'\n') && !feof(f)) { bad=1; break; }
        int quoted=0;
        for (char *p=line; *p; p++) {
            if (*p=='"') quoted=!quoted;
            if (*p=='#' && !quoted) { *p=0; break; }
        }
        char *s=trim(line), *v;
        if (!*s) continue;
        if (*s=='[') {
            if (!strcmp(s,"[[interfaces]]")) {
                if (o->device_count==FF_INTERFACES) { bad=1; break; }
                o->device_count++; strcpy(section,"interfaces"); continue;
            }
            /* [[tcp.rule]] blocks carry the TCP payload rules; their order is the
             * order the rotation visits them. */
            if (!strcmp(s,"[[tcp.rule]]")) {
                if (o->rule_count==FF_TCP_RULES_MAX) { bad=1; break; }
                o->rules[o->rule_count].enabled=1;
                o->rule_count++; strcpy(section,"tcp.rule"); continue;
            }
            const char *sections[]={"tcp","udp","injection","runtime"};
            int found=0;
            for (unsigned i=0;i<4;i++) {
                char expected[32]; snprintf(expected,sizeof(expected),"[%s]",sections[i]);
                if (!strcmp(s,expected)) {
                    if(sections_seen&(1u<<i)) {bad=1;break;}
                    sections_seen|=1u<<i;strcpy(section,sections[i]);found=1;
                }
            }
            if (!found) { bad=1; break; }
            continue;
        }
        v=strchr(s,'='); if (!v) { bad=1; break; } *v++=0;
        s=trim(s); v=trim(v);
        char id[96];
        unsigned index = !strcmp(section,"interfaces") ? o->device_count :
                         !strcmp(section,"tcp.rule") ? o->rule_count : 0;
        if (snprintf(id,sizeof(id),"%s.%u.%s",section,index,s)>=(int)sizeof(id)) { bad=1; break; }
        for(unsigned i=0;i<count;i++) if (!strcmp(seen[i],id)) bad=1;
        if(bad || count==128) { bad=1; break; }
        strcpy(seen[count++],id);
        int rc=-1;
#define KEY(sec,key) (!strcmp(section,sec) && !strcmp(s,key))
#define NUM(sec,key,field,lo,hi) if (KEY(sec,key)) rc=number(v,&(field),lo,hi)
#define BOOL(sec,key,field) if (KEY(sec,key)) rc=boolean(v,&(field))
#define STR(sec,key,field) if (KEY(sec,key)) rc=string(v,field,sizeof(field))
#define RULE (o->rule_count ? &o->rules[o->rule_count-1] : NULL)
        NUM("","version",version,1,1);
        if (KEY("interfaces","name")) rc=string(v,o->devices[o->device_count-1].name,IF_NAMESIZE);
        if (KEY("interfaces","mode")) {
            char mode[16]; rc=string(v,mode,sizeof(mode));
            if (!rc) {
                if(!strcmp(mode,"ethernet")) o->devices[o->device_count-1].mode=FF_ETHERNET;
                else if(!strcmp(mode,"l3")) o->devices[o->device_count-1].mode=FF_L3;
                else if(!strcmp(mode,"pppoe")) o->devices[o->device_count-1].mode=FF_PPPOE;
                else rc=-1;
            }
        }
        /* One TCP payload rule. type and payload are resolved after the whole file
         * is read, because TOML does not promise which of the two comes first. */
        if (KEY("tcp.rule","type")) {
            char t[16]; rc=string(v,t,sizeof(t));
            if(!rc && strcmp(t,"http") && strcmp(t,"tls") && strcmp(t,"custom")) rc=-1;
            else if(!rc) strcpy(RULE->type,t);
        }
        if (KEY("tcp.rule","payload")) rc=string(v,RULE->payload,sizeof(RULE->payload));
        if (KEY("tcp.rule","enabled")) rc=boolean(v,&RULE->enabled);
        if (KEY("tcp.rule","comment")) { char note[128]; rc=string(v,note,sizeof(note)); }
        BOOL("tcp","enabled",o->kernel.tcp_enabled);
        BOOL("udp","enabled",o->kernel.udp_enabled);
        STR("udp","payload",o->udp_payload);
        STR("udp","sip_uri",o->sip_uri);
        STR("udp","payload_file",o->udp_file);
        /* Deprecated single-template keys. They still configure the first (and
         * second) rule when no [[tcp.rule]] block is present, and are ignored with a
         * warning otherwise. */
        STR("tcp","payload",o->tcp_payload);
        STR("tcp","hostname",o->hostname);
        STR("tcp","payload_file",o->tcp_file);
        STR("tcp","https_hostname",https_hostname);
        STR("tcp","https_payload_file",https_file);
        if (KEY("tcp","directions")) {
            char compact[128]; unsigned n=0;
            for(char *p=v; *p && n<sizeof(compact)-1; p++) if(!isspace((unsigned char)*p)) compact[n++]=*p;
            compact[n]=0; rc=0;
            if(!strcmp(compact,"[\"active\"]")) o->kernel.directions=1;
            else if(!strcmp(compact,"[\"passive\"]")) o->kernel.directions=2;
            else if(!strcmp(compact,"[\"active\",\"passive\"]") || !strcmp(compact,"[\"passive\",\"active\"]")) o->kernel.directions=3;
            else rc=-1;
        }
        if(KEY("tcp","tfo")) {
            if(!strcmp(v,"\"strip-syn\"")) {o->kernel.strip_tfo=1;rc=0;}
            if(!strcmp(v,"\"preserve\"")) {o->kernel.strip_tfo=0;rc=0;}
        }
        if(KEY("tcp","https_ports")) {rc=ports(v,throwaway,&throwaway_count);ports_given=!rc;}
        if(KEY("udp","trigger")) {
            if(!strcmp(v,"\"egress\"")) {o->kernel.udp_both=0;rc=0;}
            if(!strcmp(v,"\"both\"")) {o->kernel.udp_both=1;rc=0;}
        }
        NUM("tcp","max_batches",o->kernel.tcp_batches,1,32);
        NUM("udp","initial_packets",o->kernel.udp_packets,1,32);
        NUM("udp","idle_timeout_seconds",o->kernel.udp_idle,1,3600);
        NUM("injection","ttl",o->kernel.ttl,1,255);
        NUM("injection","repeat",o->kernel.repeat,1,8);
        BOOL("injection","estimate_hops",o->kernel.estimate_hops);
        NUM("injection","dynamic_percent",o->kernel.percent,0,99);
        NUM("injection","max_packets_per_second",o->kernel.rate,1,1000000);
        NUM("injection","burst",o->kernel.burst,1,1000000);
        BOOL("injection","allow_private",o->kernel.allow_private);
        NUM("runtime","tcp_entries",o->tcp_entries,64,1048576);
        NUM("runtime","udp_entries",o->udp_entries,64,1048576);
        NUM("runtime","lease_seconds",o->lease,4,60);
        if(rc) {bad=1;break;}
    }
    if (ferror(f)) bad=1;
    fclose(f);
    if (bad) {snprintf(error,cap,"%s:%u: invalid, duplicate or unsupported setting",path,lineno);return -1;}
    if(!version || !o->device_count) {snprintf(error,cap,"version = 1 and [[interfaces]] required");return -1;}
    for(unsigned i=0;i<o->device_count;i++) {
        const char *n=o->devices[i].name;
        if(!*n || strspn(n,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-:")!=strlen(n)) {
            snprintf(error,cap,"invalid interface name");return -1;
        }
        for(unsigned j=0;j<i;j++) if(!strcmp(n,o->devices[j].name)) {
            snprintf(error,cap,"duplicate interface %s",n);return -1;
        }
    }
    if(o->kernel.burst<o->kernel.repeat) {snprintf(error,cap,"burst must be >= repeat");return -1;}
    legacy_https = *https_hostname || *https_file;
    if (!o->rule_count) {
        /* No [[tcp.rule]] entries: translate the single-template keys into rules,
         * in the order the old configuration implied (primary first, then the
         * https_* one). A connection is no longer pinned by port, so the first
         * connection may get either shape; that is the documented change from the
         * port-matched model. */
        struct ff_rule *r0=&o->rules[0];
        r0->enabled=1;
        if(!strcmp(o->tcp_payload,"custom")) {
            strcpy(r0->type,"custom"); strcpy(r0->payload,o->tcp_file);
        } else if(!strcmp(o->tcp_payload,"tls")) {
            strcpy(r0->type,"tls"); strcpy(r0->payload,o->hostname);
        } else {
            strcpy(r0->type,"http"); strcpy(r0->payload,o->hostname);
        }
        o->rule_count=1;
        if(legacy_https) {
            struct ff_rule *r1=&o->rules[1];
            r1->enabled=1;
            if(*https_file) { strcpy(r1->type,"custom"); strcpy(r1->payload,https_file); }
            else { strcpy(r1->type,"tls"); strcpy(r1->payload,https_hostname); }
            o->rule_count=2;
        }
        if(ports_given) snprintf(o->warning,sizeof(o->warning),
            "tcp.https_ports is ignored: TCP rules are not selected by port");
    } else {
        if(legacy_https || strcmp(o->tcp_payload,"http") || strcmp(o->hostname,"www.example.com") ||
           *o->tcp_file || ports_given)
            snprintf(o->warning,sizeof(o->warning),
                "tcp.payload/hostname/payload_file/https_* are ignored while [[tcp.rule]] entries exist");
    }
    /* Resolve every enabled rule's payload into the field its type reads and check
     * the shape, so the datapath never renders a rule with nothing to send. */
    for(unsigned i=0;i<o->rule_count;i++) {
        struct ff_rule *r=&o->rules[i];
        if(!r->enabled) continue;
        if(!r->type[0]) {snprintf(error,cap,"[[tcp.rule]] #%u: type is required",i+1);return -1;}
        if(!r->payload[0]) {snprintf(error,cap,"[[tcp.rule]] #%u: payload is required",i+1);return -1;}
        if(!strcmp(r->type,"custom")) {
            if(r->payload[0]!='/') {snprintf(error,cap,"[[tcp.rule]] #%u: payload must be a path for type custom",i+1);return -1;}
            strcpy(r->file,r->payload);
        } else {
            for(char *p=r->payload; *p; p++)
                if(*p=='/' || *p==':' || *p==' ') {
                    snprintf(error,cap,"[[tcp.rule]] #%u: hostname must be a bare name (no scheme, port or path)",i+1);
                    return -1;
                }
            strcpy(r->hostname,r->payload);
        }
    }
    for(unsigned i=0;i<count;i++) {
        if(!strcmp(o->udp_payload,"custom") && !strcmp(seen[i],"udp.0.sip_uri")) {
            snprintf(error,cap,"custom payload_file cannot be combined with sip_uri");return -1;
        }
    }
    return ff_templates(o,error,cap);
}
