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
int ff_config_read(const char *path, struct ff_options *o, char *error, size_t cap) {
    memset(o, 0, sizeof(*o));
    o->kernel = (struct ff_config){.tcp_enabled=1,.udp_enabled=1,.directions=3,
        .strip_tfo=1,.tcp_batches=3,.udp_packets=5,.udp_idle=30,
        .ttl=3,.repeat=2,.estimate_hops=1,.rate=1000,.burst=2000};
    o->tcp_entries=8192; o->udp_entries=8192; o->lease=10;
    strcpy(o->tcp_payload,"http"); strcpy(o->udp_payload,"sip");
    strcpy(o->hostname,"www.example.com"); strcpy(o->sip_uri,"sip:service@example.com");
    FILE *f = fopen(path,"r");
    if (!f) { snprintf(error,cap,"%s: %s",path,strerror(errno)); return -1; }
    char line[2048], section[32]="", seen[128][96];
    unsigned lineno=0, count=0, version=0, sections_seen=0;
    int bad=0, ports_given=0;
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
        if (snprintf(id,sizeof(id),"%s.%u.%s",section,!strcmp(section,"interfaces")?o->device_count:0,s)>=(int)sizeof(id)) { bad=1; break; }
        for(unsigned i=0;i<count;i++) if (!strcmp(seen[i],id)) bad=1;
        if(bad || count==128) { bad=1; break; }
        strcpy(seen[count++],id);
        int rc=-1;
#define KEY(sec,key) (!strcmp(section,sec) && !strcmp(s,key))
#define NUM(sec,key,field,lo,hi) if (KEY(sec,key)) rc=number(v,&(field),lo,hi)
#define BOOL(sec,key,field) if (KEY(sec,key)) rc=boolean(v,&(field))
#define STR(sec,key,field) if (KEY(sec,key)) rc=string(v,field,sizeof(field))
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
        BOOL("tcp","enabled",o->kernel.tcp_enabled);
        BOOL("udp","enabled",o->kernel.udp_enabled);
        STR("tcp","payload",o->tcp_payload); STR("udp","payload",o->udp_payload);
        STR("tcp","hostname",o->hostname); STR("udp","sip_uri",o->sip_uri);
        STR("tcp","payload_file",o->tcp_file); STR("udp","payload_file",o->udp_file);
        STR("tcp","https_hostname",o->https_hostname);
        STR("tcp","https_payload_file",o->https_file);
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
        if(KEY("tcp","https_ports")) {
            /* [443] or [443, 8443]. This list selects the second TCP template
             * for a connection whose local or remote port matches. An empty
             * list, a trailing comma, a duplicate or an out-of-range port is an
             * error rather than something quietly unreachable. */
            char compact[128]; unsigned n=0;
            for(char *p=v; *p && n<sizeof(compact)-1; p++) if(!isspace((unsigned char)*p)) compact[n++]=*p;
            compact[n]=0; rc=0; ports_given=1;
            char *p=compact;
            if(*p++!='[' || *p==']' || !*p) rc=-1;
            while(!rc) {
                char *end; errno=0;
                if(!isdigit((unsigned char)*p)) {rc=-1;break;}
                unsigned long num=strtoul(p,&end,10);
                if(errno || num<1 || num>65535 || end==p) {rc=-1;break;}
                for(unsigned i=0;i<o->kernel.port_count;i++)
                    if(o->kernel.ports[i]==num) {rc=-1;break;}
                if(rc || o->kernel.port_count==FF_HTTPS_PORTS_MAX) {rc=-1;break;}
                o->kernel.ports[o->kernel.port_count++]=num;
                p=end;
                if(*p==']' && !p[1]) break;
                if(*p!=',') {rc=-1;break;}
                p++;
            }
        }
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
    /* The second TCP template exists only when one of its payload sources is
     * set, and its port list is only meaningful in that case. Without an
     * explicit list it is selected on 443, which is what the predecessor
     * injected as "https". */
    if(*o->https_hostname || *o->https_file) {
        if(!ports_given) {o->kernel.ports[0]=443;o->kernel.port_count=1;}
    } else o->kernel.port_count=0;
    for(unsigned i=0;i<count;i++) {
        if((!strcmp(o->tcp_payload,"custom") && !strcmp(seen[i],"tcp.0.hostname")) ||
           (!strcmp(o->udp_payload,"custom") && !strcmp(seen[i],"udp.0.sip_uri")) ||
           (*o->https_file && !strcmp(seen[i],"tcp.0.https_hostname"))) {
            snprintf(error,cap,"custom payload_file cannot be combined with hostname or sip_uri");return -1;
        }
    }
    return ff_templates(o,error,cap);
}
