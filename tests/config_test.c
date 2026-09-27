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
static const char *base="version = 1\n[[interfaces]]\nname = \"wan\"\n";
int main(void) {
    struct ff_options o;char error[512];

    /* Defaults: a configuration that says nothing about TCP payloads keeps the
     * historical behaviour - one HTTP rule for www.example.com, every port. */
    assert(!parse_text(base,&o));
    assert(o.kernel.strip_tfo && o.kernel.repeat==2 && o.kernel.ttl==3);
    assert(o.rule_count==1 && o.rules[0].enabled && !strcmp(o.rules[0].type,"http"));
    assert(o.kernel.rule_count==1 && o.kernel.rule_map[0]==0);
    assert(memmem(o.tcp_template.data,o.tcp_template.len,"Host: www.example.com",21));
    assert(memmem(o.udp_template.data,o.udp_template.len,"INVITE sip:",11));
    assert(o.plan[0].kind==FF_VARIANT_SAME && o.plan[0].variants==1);
    assert(o.plan[FF_TEMPLATE_PLAN_UDP].kind==FF_VARIANT_PATCH &&
           o.plan[FF_TEMPLATE_PLAN_UDP].variants==FF_TEMPLATE_VARIANTS);

    /* Legacy single-template keys still configure rule 0. */
    assert(!parse_text("version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\npayload=\"tls\"\nhostname=\"unit.example\"\n",&o));
    assert(o.rule_count==1 && !strcmp(o.rules[0].type,"tls"));
    assert(o.tcp_template.data[0]==22 && o.tcp_template.data[5]==1);
    assert(u16(o.tcp_template.data+3)==o.tcp_template.len-5);
    assert(u16(o.tcp_template.data+7)==o.tcp_template.len-9);
    assert(memmem(o.tcp_template.data,o.tcp_template.len,"unit.example",12));
    assert(o.plan[0].kind==FF_VARIANT_RENDER && o.plan[0].variants==FF_TEMPLATE_VARIANTS);

    /* Legacy https_* keys become rule 1, and the retired port list is accepted
     * (syntax checked) but ignored, with a warning. */
    assert(!parse_text("version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\n"
                       "payload=\"http\"\nhostname=\"a.example\"\n"
                       "https_hostname=\"b.example\"\nhttps_ports=[8443, 443]\n",&o));
    assert(o.rule_count==2 && !strcmp(o.rules[0].type,"http") && !strcmp(o.rules[1].type,"tls"));
    assert(o.kernel.rule_count==2 && o.kernel.rule_map[0]==0 && o.kernel.rule_map[1]==1);
    assert(memmem(o.rules[1].tpl.data,o.rules[1].tpl.len,"b.example",9));
    assert(!strcmp(o.rules[1].hostname,"b.example"));

    /* Rule table: order is the rotation order, enabled=false drops a rule from the
     * rotation, and every type renders the template it promises. */
    const char *rules="version=1\n[[interfaces]]\nname=\"wan\"\n"
        "[[tcp.rule]]\ntype=\"http\"\npayload=\"one.example\"\ncomment=\"first\"\n"
        "[[tcp.rule]]\ntype=\"tls\"\npayload=\"two.example\"\nenabled=false\n"
        "[[tcp.rule]]\ntype=\"tls\"\npayload=\"three.example\"\n";
    assert(!parse_text(rules,&o));
    assert(o.rule_count==3);
    assert(o.kernel.rule_count==2 && o.kernel.rule_map[0]==0 && o.kernel.rule_map[1]==2);
    assert(!o.rules[1].tpl.len);
    assert(memmem(o.rules[0].tpl.data,o.rules[0].tpl.len,"Host: one.example",17));
    assert(memmem(o.rules[2].tpl.data,o.rules[2].tpl.len,"three.example",13));
    assert(o.plan[0].kind==FF_VARIANT_SAME && o.plan[2].kind==FF_VARIANT_RENDER);
    assert(o.plan[1].variants==1 && !o.rules[1].enabled);

    /* Variants: an HTTP rule is byte-identical across copies, a TLS rule is
     * re-rendered (its random differs), UDP patches its recorded byte ranges. */
    static struct ff_template variants[FF_TEMPLATE_PLAN_COUNT][FF_TEMPLATE_VARIANTS];
    assert(!ff_variants(&o,variants,FF_TEMPLATE_VARIANTS));
    assert(memcmp(variants[0][0].data,variants[0][1].data,1200)==0);
    assert(memcmp(variants[2][0].data,variants[2][1].data,1200)!=0);
    assert(variants[2][0].len==variants[2][31].len);
    assert(memcmp(variants[FF_TEMPLATE_PLAN_UDP][0].data,
                  variants[FF_TEMPLATE_PLAN_UDP][1].data,1200)!=0);

    /* The template map key has to be the same on both sides of the ABI. */
    assert(FF_TEMPLATE_KEY(0,0,0)==0 && FF_TEMPLATE_KEY(0,0,1)==1);
    assert(FF_TEMPLATE_KEY(0,FF_TEMPLATE_PLAN_UDP,0)==FF_TCP_RULES_MAX*FF_TEMPLATE_VARIANTS);
    assert(FF_TEMPLATE_KEY(1,0,0)==FF_TEMPLATE_PLAN_COUNT*FF_TEMPLATE_VARIANTS);

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
        "version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\npayload=\"custom\"\npayload_file=\"/does/not/exist\"\n",
        /* Rule-table rejections. */
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.rule]]\npayload=\"a.example\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.rule]]\ntype=\"https\"\npayload=\"a.example\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.rule]]\ntype=\"http\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.rule]]\ntype=\"http\"\npayload=\"https://a.example\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.rule]]\ntype=\"tls\"\npayload=\"a.example:443\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.rule]]\ntype=\"tls\"\npayload=\"a.example/pat\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.rule]]\ntype=\"custom\"\npayload=\"relative.bin\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.rule]]\ntype=\"http\"\npayload=\"a.example\"\n"
            "[[tcp.rule]]\ntype=\"http\"\npayload=\"b.example\"\n"
            "[[tcp.rule]]\ntype=\"http\"\npayload=\"c.example\"\n"
            "[[tcp.rule]]\ntype=\"http\"\npayload=\"d.example\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.rule]]\ntype=\"http\"\npayload=\"a.example\"\n"
            "[[tcp.rule]]\ntype=\"http\"\npayload=\"a.example\"\n"
            "[[tcp.rule]]\ntype=\"http\"\npayload=\"a.example\"\nenabled=false\n"
            "[[tcp.rule]]\ntype=\"http\"\npayload=\"a.example\"\n",
        "version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.rule]]\ntype=\"tls\"\npayload=\"a.example\"\n"
            "payload=\"b.example\"\n"
    };
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) {
        if(!parse_text(invalid[i],&o)) {printf("expected rejection: %s\n",invalid[i]);assert(0);}
    }

    /* Custom payload files: read into the rule, bounded at 1200 bytes. */
    assert(!parse_text(base,&o));
    char file[]="/tmp/fakeflow-payload-XXXXXX";int fd=mkstemp(file);assert(fd>=0);
    unsigned char data[1201];for(unsigned i=0;i<sizeof(data);i++)data[i]=i;
    assert(write(fd,data,1200)==1200);close(fd);
    strcpy(o.rules[0].type,"custom");strcpy(o.rules[0].file,file);o.rule_count=1;
    assert(!ff_templates(&o,error,sizeof(error)) && o.rules[0].tpl.len==1200);
    assert(!memcmp(data,o.rules[0].tpl.data,1200));
    assert(o.kernel.rule_map[0]==0 && o.kernel.rule_count==1);
    FILE *f=fopen(file,"ab");assert(f);fputc(1,f);fclose(f);
    assert(ff_templates(&o,error,sizeof(error)));unlink(file);

    /* A rule list of only disabled rules leaves nothing to send, so it is rejected
     * rather than accepted with an empty rotation. */
    assert(parse_text("version=1\n[[interfaces]]\nname=\"wan\"\n"
                      "[[tcp.rule]]\ntype=\"http\"\npayload=\"a.example\"\nenabled=false\n",&o));

    /* Retired keys still parse and produce a notice instead of failing. */
    assert(!parse_text("version=1\n[[interfaces]]\nname=\"wan\"\n[tcp]\n"
                       "hostname=\"a.example\"\nhttps_hostname=\"b.example\"\nhttps_ports=[443]\n",&o));
    assert(strstr(o.warning,"https_ports is ignored"));
    assert(!parse_text("version=1\n[[interfaces]]\nname=\"wan\"\n[[tcp.rule]]\ntype=\"http\"\n"
                       "payload=\"a.example\"\n[tcp]\nhttps_hostname=\"b.example\"\n",&o));
    assert(strstr(o.warning,"are ignored while"));

    puts("PASS: strict configuration, defaults, TLS lengths/SNI, binary payload bounds, TCP payload rules");
    return 0;
}
