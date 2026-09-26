/* SPDX-License-Identifier: GPL-2.0-only */
#include "fakeflow.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifndef FF_RUNTIME_DIR
#define FF_RUNTIME_DIR "/run/fakeflow"
#endif
const char *ff_stat_names[FF_STATS_MAX]={
    "tcp_syn_seen","tcp_synack_eligible","tfo_stripped","skip_synack_data",
    "udp_new_flow","udp_early_seen","udp_window_exhausted",
    "fake_attempt","fake_build_ok","fake_submit_ok","clone_failed","builder_failed",
    "skip_private_remote","skip_near_peer","ttl_unestimated","skip_fragment",
    "skip_gso","skip_layout","map_insert_failed","request_expired",
    "rate_limited","lease_expired","internal_loop_blocked","skip_auth",
    "skip_mtu","tfo_failed",
    "skip_len","skip_l2","skip_ipver","skip_ipv4_opts","skip_proto","skip_trunc"
};
int main(int argc,char **argv) {
    const char *config="/etc/fakeflow.toml",*object="/usr/lib/fakeflow/fakeflow.bpf.o",*runtime=FF_RUNTIME_DIR,*logfile="";
    int explicit_config=0;
    if(argc<2) goto usage;
    for(int i=2;i<argc;i++) {
        if(!strcmp(argv[i],"--json")) continue;
        if(i+1==argc) goto usage;
        if(!strcmp(argv[i],"--config")) {config=argv[++i];explicit_config=1;}
        else if(!strcmp(argv[i],"--object")) object=argv[++i];
        else if(!strcmp(argv[i],"--runtime-dir")) runtime=argv[++i];
        else if(!strcmp(argv[i],"--log-file")) logfile=argv[++i];
        else goto usage;
    }
    if(!strcmp(argv[1],"run")) return ff_run(config,object,runtime,logfile);
    if(!strcmp(argv[1],"check") || !strcmp(argv[1],"validate")) {
        struct ff_options o;char error[512];
        if(ff_config_read(config,&o,error,sizeof(error))) {fprintf(stderr,"%s\n",error);return 1;}
        if(!strcmp(argv[1],"check")) return ff_check(&o);
        /* The port-matched template is reported only when the configuration
         * defines one, so the existing line stays byte-identical otherwise. */
        if(o.tcp_https_template.len)
            printf("Configuration valid; TCP template %u B, TCP port-matched template %u B, UDP template %u B\n",
                o.tcp_template.len,o.tcp_https_template.len,o.udp_template.len);
        else
            printf("Configuration valid; TCP template %u B, UDP template %u B\n",o.tcp_template.len,o.udp_template.len);
        return 0;
    }
    if(!strcmp(argv[1],"status") || !strcmp(argv[1],"stats") ||
       !strcmp(argv[1],"reload") || !strcmp(argv[1],"stop")) {
        if(!strcmp(argv[1],"reload") && explicit_config) {
            char *absolute=realpath(config,NULL),command[1100];
            if(!absolute) {perror(config);return 1;}
            int n=snprintf(command,sizeof(command),"reload %s",absolute);free(absolute);
            if(n>=(int)sizeof(command))return 1;
            return ff_client(runtime,command);
        }
        return ff_client(runtime,argv[1]);
    }
usage:
    fprintf(stderr,"Usage: fakeflow {check|validate|run|status|stats|reload|stop} [--config FILE] [--object FILE] [--runtime-dir DIR] [--log-file FILE] [--json]\n");
    return 2;
}
