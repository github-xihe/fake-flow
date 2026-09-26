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
    assert(o.extra_count==0 && o.kernel.port_count[1]==0 && o.extra[1].tpl.len==0);
    const char *https="version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\nhttps_hostname=\"tls.example\"\n";
    assert(!parse_text(https,&o));
    assert(o.extra_count==1 && o.kernel.port_count[1]==1 && o.kernel.ports[1][0]==443);
    assert(o.extra[1].tpl.len>43 && o.extra[1].tpl.data[0]==22 && o.extra[1].tpl.data[5]==1);
    assert(memmem(o.extra[1].tpl.data,o.extra[1].tpl.len,"tls.example",11));
    assert(u16(o.extra[1].tpl.data+3)==o.extra[1].tpl.len-5);
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
    assert(o.kernel.port_count[1]==2 && o.kernel.ports[1][0]==8443 && o.kernel.ports[1][1]==443);

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

    /* [[tcp.extra]]: every entry becomes its own port-matched slot, in
     * configuration order after the https_* compatibility keys. */
    const char *extras=
        "version=1\n[[interfaces]]\nname=\"wan\"\n"
        "[tcp]\nhttps_hostname=\"tls.example\"\nhttps_ports=[443, 8443]\n"
        "[[tcp.extra]]\nhostname=\"cdn.example\"\nports=[8080]\n"
        "[[tcp.extra]]\nhostname=\"plain.example\"\npayload=\"http\"\nports=[8000, 8001]\n"
        "[udp]\nsip_uri=\"sip:u@10.0.0.1\"\n";
    assert(!parse_text(extras,&o));
    assert(o.extra_count==3);
    assert(o.kernel.port_count[0]==0);
    assert(o.kernel.port_count[1]==2 && o.kernel.ports[1][0]==443 && o.kernel.ports[1][1]==8443);
    assert(o.kernel.port_count[2]==1 && o.kernel.ports[2][0]==8080);
    assert(o.kernel.port_count[3]==2 && o.kernel.ports[3][0]==8000 && o.kernel.ports[3][1]==8001);
    assert(o.extra_kind[1]==FF_SLOT_TLS && o.extra_kind[2]==FF_SLOT_TLS && o.extra_kind[3]==FF_SLOT_HTTP);
    assert(o.extra[1].tpl.data[0]==22 && memmem(o.extra[1].tpl.data,o.extra[1].tpl.len,"tls.example",11));
    assert(o.extra[2].tpl.data[0]==22 && memmem(o.extra[2].tpl.data,o.extra[2].tpl.len,"cdn.example",11));
    assert(memmem(o.extra[3].tpl.data,o.extra[3].tpl.len,"Host: plain.example",19));
    assert(!memmem(o.extra[3].tpl.data,o.extra[3].tpl.len,"www.example.com",15));
    /* Each slot keeps its own variant strategy: an HTTP template needs a single
     * copy, a ClientHello is re-rendered so its random differs per datagram. */
    assert(o.plan[FF_TEMPLATE_PLAN(0,2)].kind==FF_VARIANT_RENDER &&
           o.plan[FF_TEMPLATE_PLAN(0,2)].variants==FF_TEMPLATE_VARIANTS);
    assert(o.plan[FF_TEMPLATE_PLAN(0,3)].kind==FF_VARIANT_SAME && o.plan[FF_TEMPLATE_PLAN(0,3)].variants==1);
    static struct ff_template extra_variants[FF_TEMPLATE_PLAN_COUNT][FF_TEMPLATE_VARIANTS];
    assert(!ff_variants(&o,extra_variants,FF_TEMPLATE_VARIANTS));
    assert(memcmp(extra_variants[FF_TEMPLATE_PLAN(0,2)][0].data,
                  extra_variants[FF_TEMPLATE_PLAN(0,2)][5].data,1200)!=0);
    assert(memcmp(extra_variants[FF_TEMPLATE_PLAN(0,3)][0].data,
                  extra_variants[FF_TEMPLATE_PLAN(0,3)][5].data,1200)==0);
    /* The primary and UDP templates are untouched by the extra slots. */
    assert(memmem(o.tcp_template.data,o.tcp_template.len,"Host: www.example.com",21));
    assert(memmem(o.udp_template.data,o.udp_template.len,"INVITE sip:u@10.0.0.1",21));

    /* Without the https_* keys the first extra takes slot 1, so a configuration
     * that predates them keeps working when it is rewritten in the new form. */
    assert(!parse_text("version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.extra]]\n"
                       "hostname=\"only.example\"\nports=[9000]\n",&o));
    assert(o.extra_count==1 && o.extra_kind[1]==FF_SLOT_TLS);
    assert(o.kernel.port_count[1]==1 && o.kernel.ports[1][0]==9000);
    assert(memmem(o.extra[1].tpl.data,o.extra[1].tpl.len,"only.example",12));

    /* A payload file wins over the generated kinds and makes the slot
     * byte-identical to the file. */
    char payload[]="/tmp/fakeflow-extra-XXXXXX";int pfd=mkstemp(payload);assert(pfd>=0);
    assert(write(pfd,data,1200)==1200);close(pfd);
    char extra_file[1400];
    snprintf(extra_file,sizeof(extra_file),
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.extra]]\npayload_file=\"%s\"\nports=[1234]\n",payload);
    assert(!parse_text(extra_file,&o));
    assert(o.extra[1].tpl.len==1200 && !memcmp(data,o.extra[1].tpl.data,1200));
    unlink(payload);

    const char *invalid_extras[]={
        /* ports selects the slot, so it is required rather than defaulted */
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.extra]]\nhostname=\"h\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.extra]]\nhostname=\"h\"\npayload_file=\"/tmp/x\"\nports=[1]\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.extra]]\nports=[1]\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.extra]]\nhostname=\"h\"\npayload=\"sip\"\nports=[1]\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.extra]]\nhostname=\"h\"\npayload=\"http\"\npayload_file=\"/tmp/x\"\nports=[1]\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.extra]]\nhostname=\"h\"\nports=[]\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.extra]]\nhostname=\"h\"\nports=[1,]\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.extra]]\nhostname=\"h\"\nports=[70000]\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.extra]]\nhostname=\"h\"\nports=[1,1]\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.extra]]\nhostname=\"bad host\"\nports=[1]\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.extra]]\nhostname=\"h\"\nports=[1]\nhostname=\"h2\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.extra]]\nunknown=1\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.extra]]\npayload_file=\"/does/not/exist\"\nports=[1]\n",
        /* A port claimed by two slots would leave one of them unreachable: the
         * datapath takes the first match, so this is refused. */
        "version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\nhttps_hostname=\"a\"\nhttps_ports=[443]\n"
        "[[tcp.extra]]\nhostname=\"b\"\nports=[443]\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.extra]]\nhostname=\"a\"\nports=[1]\n"
        "[[tcp.extra]]\nhostname=\"b\"\nports=[1]\n",
        /* https_* plus three extras is one port-matched template too many. */
        "version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\nhttps_hostname=\"a\"\n"
        "[[tcp.extra]]\nhostname=\"b\"\nports=[1]\n[[tcp.extra]]\nhostname=\"c\"\nports=[2]\n"
        "[[tcp.extra]]\nhostname=\"d\"\nports=[3]\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.extra]]\nhostname=\"a\"\nports=[1]\n"
        "[[tcp.extra]]\nhostname=\"b\"\nports=[2]\n[[tcp.extra]]\nhostname=\"c\"\nports=[3]\n"
        "[[tcp.extra]]\nhostname=\"d\"\nports=[4]\n"
    };
    for(unsigned i=0;i<sizeof(invalid_extras)/sizeof(invalid_extras[0]);i++)
        assert(parse_text(invalid_extras[i],&o));
    puts("PASS: strict configuration, defaults, TLS lengths/SNI, binary payload bounds, port-matched template, [[tcp.extra]] slots");
    return 0;
}
