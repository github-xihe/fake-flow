/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "attach.h"
#include <bpf/bpf.h>
#include <linux/if_tun.h>
#include <linux/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
int ff_command(const char *const args[]) {
    pid_t p=fork();if(p<0)return -1;
    if(!p) {execvp(args[0],(char *const*)args);_exit(127);}
    int s;while(waitpid(p,&s,0)<0) if(errno!=EINTR)return -1;
    return WIFEXITED(s)&&!WEXITSTATUS(s)?0:-1;
}
int ff_priority_available(const char *name,const char *direction) {
    int pipes[2];if(pipe(pipes)) return -1;
    pid_t p=fork();
    if(p<0) {close(pipes[0]);close(pipes[1]);return -1;}
    if(!p) {
        close(pipes[0]);dup2(pipes[1],1);close(pipes[1]);
        execlp("tc","tc","filter","show","dev",name,direction,(char*)0);_exit(127);
    }
    close(pipes[1]);FILE *f=fdopen(pipes[0],"r");char line[4096];int conflict=0;
    if(!f) {close(pipes[0]);conflict=1;}
    else {while(fgets(line,sizeof(line),f)) if(strstr(line,"pref 1 ")) conflict=1;fclose(f);}
    int status;while(waitpid(p,&status,0)<0) if(errno!=EINTR)return -1;
    return !conflict&&WIFEXITED(status)&&!WEXITSTATUS(status)?0:-1;
}
int ff_attach(unsigned idx,enum bpf_tc_attach_point point,int fd,unsigned priority,struct ff_attachment *r) {
    struct bpf_tc_hook h={.sz=sizeof(h),.ifindex=idx,.attach_point=point};
    struct bpf_tc_opts o={.sz=sizeof(o),.prog_fd=fd,.priority=priority,.handle=1};
    int e=bpf_tc_hook_create(&h);if(e && e!=-EEXIST) return e;
    e=bpf_tc_attach(&h,&o);if(e)return e;
    *r=(struct ff_attachment){idx,point,priority,1,o.prog_id};return 0;
}
void ff_detach(const struct ff_attachment *r) {
    struct bpf_tc_hook h={.sz=sizeof(h),.ifindex=r->index,.attach_point=r->point};
    struct bpf_tc_opts o={.sz=sizeof(o),.priority=r->priority,.handle=r->handle};
    if(!bpf_tc_query(&h,&o) && o.prog_id==r->id) {
        o.prog_id=0;o.prog_fd=0;o.flags=0;
        if(bpf_tc_detach(&h,&o)) fprintf(stderr,"Cannot detach owned filter on ifindex %u\n",r->index);
    }
    /* Keep clsact: another process may have installed a filter meanwhile. */
}
int ff_link(const char *name,unsigned mode,unsigned *index,unsigned *mtu) {
    struct ifreq r={};snprintf(r.ifr_name,sizeof(r.ifr_name),"%s",name);
    *index=if_nametoindex(name);if(!*index) return -1;
    int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);if(fd<0)return -1;
    int e=ioctl(fd,SIOCGIFHWADDR,&r);
    unsigned type=r.ifr_hwaddr.sa_family;
    if(!e && ((mode!=FF_L3 && type!=ARPHRD_ETHER) ||
        (mode==FF_L3 && type!=ARPHRD_PPP && type!=ARPHRD_NONE))) e=-1;
    if(!e) e=ioctl(fd,SIOCGIFMTU,&r);
    if(!e) {
        if(mode==FF_PPPOE && r.ifr_mtu<=8)e=-1;
        else *mtu=r.ifr_mtu-(mode==FF_PPPOE?8:0);
    }
    close(fd);return e;
}
int ff_dummy(char *name,size_t cap) {
    snprintf(name,cap,"ff%xl2",getpid());
    const char *args[]={"ip","link","add",name,"type","dummy",NULL};
    return ff_command(args);
}
int ff_tun(char *name,size_t cap) {
    int fd=open("/dev/net/tun",O_RDWR|O_CLOEXEC);if(fd<0)return -1;
    struct ifreq r={};r.ifr_flags=IFF_TUN|IFF_NO_PI;
    snprintf(r.ifr_name,sizeof(r.ifr_name),"ff%xl3",getpid());
    if(ioctl(fd,TUNSETIFF,&r)) {close(fd);return -1;}
    snprintf(name,cap,"%s",r.ifr_name);return fd;
}
int ff_check(const struct ff_options *o) {
    int failed=0;
    printf("Read-only check; no BPF program loaded or attached.\n");
    for(unsigned i=0;i<o->device_count;i++) {
        unsigned idx,mtu;
        if(ff_link(o->devices[i].name,o->devices[i].mode,&idx,&mtu)) {
            fprintf(stderr,"%s: missing interface or incompatible link mode\n",o->devices[i].name);failed=1;continue;
        }
        printf("%s: ifindex=%u mtu=%u mode=%u\n",o->devices[i].name,idx,mtu,o->devices[i].mode);
        if(ff_priority_available(o->devices[i].name,"egress")) {
            fprintf(stderr,"%s: TC egress priority 1 is occupied or tc inspection failed\n",o->devices[i].name);failed=1;
        }
    }
    printf("Flow map storage estimate (before kernel overhead): %llu bytes\n",
        (unsigned long long)(o->tcp_entries+o->udp_entries)*(sizeof(struct ff_key)+72));
    printf("BTF: %s; kernel helper/verifier and hardware-offload coverage require run/tests.\n",
        access("/sys/kernel/btf/vmlinux",R_OK)?"not available":"available");
    return failed;
}
