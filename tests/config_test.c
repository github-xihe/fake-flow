/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "../ebpf/user/fakeflow.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int parse_text(const char *text,struct ff_options *o) {
    char file[]="/tmp/fakeflow-config-XXXXXX",err[512];
    int fd=mkstemp(file);assert(fd>=0);
    assert(write(fd,text,strlen(text))==(ssize_t)strlen(text));close(fd);
    int result=ff_config_read(file,o,err,sizeof(err));unlink(file);return result;
}
static unsigned u16(const unsigned char *p){return (p[0]<<8)|p[1];}
int main(void) {
    struct ff_options o;char error[512];
    const char *base="version = 1\n[[interfaces]]\nname = \"wan\"\n";
    assert(!parse_text(base,&o));
    assert(o.kernel.strip_tfo && o.kernel.repeat==2 && o.kernel.ttl==3);
    assert(memmem(o.tcp_template.data,o.tcp_template.len,"Host: www.example.com",21));
    assert(memmem(o.udp_template.data,o.udp_template.len,"INVITE sip:",11));
    assert(!parse_text("version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\npayload=\"tls\"\nhostname=\"unit.example\"\n",&o));
    assert(o.tcp_template.data[0]==22 && o.tcp_template.data[5]==1);
    assert(u16(o.tcp_template.data+3)==o.tcp_template.len-5);
    assert(u16(o.tcp_template.data+7)==o.tcp_template.len-9);
    assert(memmem(o.tcp_template.data,o.tcp_template.len,"unit.example",12));
    const char *invalid[]={
        "version=2\n[[interfaces]]\nname=\"wan\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\nname=\"wan2\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\ntfo=\"strip-empty-syn\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[injection]\nttl=0\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[injection]\nrepeat=9\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\nhostname=\"bad host\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\nenabled=1\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[interfaces]]\nname=\"wan\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\nunknown=true\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\npayload=\"custom\"\npayload_file=\"/does/not/exist\"\n"
    };
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++)assert(parse_text(invalid[i],&o));
    assert(!parse_text(base,&o));
    char file[]="/tmp/fakeflow-payload-XXXXXX";int fd=mkstemp(file);assert(fd>=0);
    unsigned char data[1201];for(unsigned i=0;i<sizeof(data);i++)data[i]=i;
    assert(write(fd,data,1200)==1200);close(fd);
    strcpy(o.tcp_payload,"custom");strcpy(o.tcp_file,file);
    assert(!ff_templates(&o,error,sizeof(error)) && o.tcp_template.len==1200);
    assert(!memcmp(data,o.tcp_template.data,1200));
    FILE *f=fopen(file,"ab");assert(f);fputc(1,f);fclose(f);
    assert(ff_templates(&o,error,sizeof(error)));unlink(file);

    /* Second TCP template: present only when a payload source is configured, and
     * selected by the port list, which defaults to 443. */
    assert(!parse_text(base,&o));
    assert(o.kernel.port_count==0 && o.tcp_https_template.len==0);
    const char *https="version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\nhttps_hostname=\"tls.example\"\n";
    assert(!parse_text(https,&o));
    assert(o.kernel.port_count==1 && o.kernel.ports[0]==443);
    assert(o.tcp_https_template.len>43 && o.tcp_https_template.data[0]==22 && o.tcp_https_template.data[5]==1);
    assert(memmem(o.tcp_https_template.data,o.tcp_https_template.len,"tls.example",11));
    assert(u16(o.tcp_https_template.data+3)==o.tcp_https_template.len-5);
    /* The primary template still matches every other port, unchanged. */
    assert(memmem(o.tcp_template.data,o.tcp_template.len,"Host: www.example.com",21));
    assert(o.plan[FF_TEMPLATE_PLAN(0,0)].kind==FF_VARIANT_SAME && o.plan[FF_TEMPLATE_PLAN(0,0)].variants==1);
    assert(o.plan[FF_TEMPLATE_PLAN(0,1)].kind==FF_VARIANT_RENDER &&
           o.plan[FF_TEMPLATE_PLAN(0,1)].variants==FF_TEMPLATE_VARIANTS);
    assert(o.plan[FF_TEMPLATE_PLAN(1,0)].kind==FF_VARIANT_PATCH &&
           o.plan[FF_TEMPLATE_PLAN(1,0)].variants==FF_TEMPLATE_VARIANTS);
    /* A TLS ClientHello is re-rendered per variant, so its random differs; the
     * HTTP template needs a single copy because it has no random bytes. */
    static struct ff_template variants[FF_TEMPLATE_PLAN_COUNT][FF_TEMPLATE_VARIANTS];
    assert(!ff_variants(&o,variants,FF_TEMPLATE_VARIANTS));
    assert(memcmp(variants[FF_TEMPLATE_PLAN(0,0)][0].data,variants[FF_TEMPLATE_PLAN(0,0)][1].data,1200)==0);
    assert(memcmp(variants[FF_TEMPLATE_PLAN(0,1)][0].data,variants[FF_TEMPLATE_PLAN(0,1)][1].data,1200)!=0);
    assert(variants[FF_TEMPLATE_PLAN(0,1)][0].len==variants[FF_TEMPLATE_PLAN(0,1)][31].len);
    assert(!parse_text("version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\nhttps_hostname=\"t.example\"\nhttps_ports=[8443, 443]\n",&o));
    assert(o.kernel.port_count==2 && o.kernel.ports[0]==8443 && o.kernel.ports[1]==443);

    const char *invalid_https[]={
        "version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\nhttps_hostname=\"h\"\nhttps_payload_file=\"/tmp/x\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\nhttps_hostname=\"h\"\nhttps_ports=[]\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\nhttps_hostname=\"h\"\nhttps_ports=[443,]\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\nhttps_hostname=\"h\"\nhttps_ports=[443,443]\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\nhttps_hostname=\"h\"\nhttps_ports=[0]\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\nhttps_hostname=\"h\"\nhttps_ports=[65536]\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\nhttps_hostname=\"h\"\nhttps_ports=[443,8443,9443,10443,11443]\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\nhttps_hostname=\"bad host\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\nhttps_hostname=\"h\"\nhttps_hostname=\"h2\"\n"
    };
    for(unsigned i=0;i<sizeof(invalid_https)/sizeof(invalid_https[0]);i++)
        assert(parse_text(invalid_https[i],&o));
    puts("PASS: strict configuration, defaults, TLS lengths/SNI, binary payload bounds, port-matched template");
    return 0;
}
