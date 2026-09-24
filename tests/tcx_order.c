/* SPDX-License-Identifier: GPL-2.0-only */
/* Test-only inspection: query the actual TCX chain, not legacy tc filters. */
#include <bpf/bpf.h>
#include <net/if.h>
#include <stdio.h>
int main(int argc,char **argv) {
    if(argc!=2)return 2;
    __u32 ids[64];
    struct bpf_prog_query_opts opts={.sz=sizeof(opts),.prog_ids=ids,.count=64};
    if(bpf_prog_query_opts(if_nametoindex(argv[1]),BPF_TCX_INGRESS,&opts)) {perror("TCX query");return 1;}
    for(unsigned i=0;i<opts.count;i++) {
        int fd=bpf_prog_get_fd_by_id(ids[i]);
        struct bpf_prog_info info={0};__u32 len=sizeof(info);
        if(fd<0 || bpf_prog_get_info_by_fd(fd,&info,&len))return 1;
        printf("%s\n",info.name);
    }
    return 0;
}
