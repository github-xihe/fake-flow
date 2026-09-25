/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include "attach.h"
#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

struct runtime {
    struct bpf_object *obj;
    struct ff_options options;
    struct ff_attachment attached[FF_INTERFACES*2+4];unsigned count;
    /* Unpinned TCX links detach on process exit, including SIGKILL. */
    struct bpf_link *ingress[FF_INTERFACES];
    unsigned index[FF_INTERFACES], generation[FF_INTERFACES], epoch, config_gen;
    unsigned l2,l3;
    int tun,server,lock,route;
    char dummy[IF_NAMESIZE],tun_name[IF_NAMESIZE],state[1024],socket[108];
    char owner[96];
};
static volatile sig_atomic_t quitting,reloading;
static void on_signal(int s) {if(s==SIGHUP) reloading=1;else quitting=1;}
static __u64 monotime(void) {
    struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
    return (__u64)t.tv_sec*FF_NS+t.tv_nsec;
}
static int map(struct runtime *r,const char *name) {return bpf_object__find_map_fd_by_name(r->obj,name);}
static int program(struct runtime *r,const char *name) {return bpf_program__fd(bpf_object__find_program_by_name(r->obj,name));}
static int lease(struct runtime *r,int enabled) {
    unsigned zero=0;
    /* Layout must match struct ff_lease in maps.h. reported=1 while disabling
     * keeps a clean shutdown from logging a lease edge. */
    struct ff_lease_local {__u64 until;__u32 reported;__u32 pad;} v={
        enabled?monotime()+r->options.lease*FF_NS:0,enabled?0:1,0};
    return bpf_map_update_elem(map(r,"leases"),&zero,&v,BPF_ANY);
}
static void drain_requests(struct runtime *r) {
    int fd=map(r,"requests");__u64 key,deadline=monotime()+2*FF_NS;
    unsigned empty=0;
    while(monotime()<deadline && empty<2) {
        if(bpf_map_get_next_key(fd,NULL,&key) && errno==ENOENT)empty++;
        else empty=0;
        struct timespec pause={.tv_nsec=10000000};nanosleep(&pause,NULL);
    }
}
static int save_state(struct runtime *r) {
    char staging[1050];snprintf(staging,sizeof(staging),"%s.tmp",r->state);
    FILE *f=fopen(staging,"w");if(!f)return -1;
    for(unsigned i=0;i<r->count;i++) {
        struct ff_attachment *a=&r->attached[i];
        fprintf(f,"F %u %u %u %u %u\n",a->index,a->point,a->priority,a->handle,a->id);
    }
    if(*r->dummy && r->l2)fprintf(f,"D %u %s %s\n",r->l2,r->dummy,r->owner);
    int e=fflush(f);if(!e)e=fsync(fileno(f));if(fclose(f))e=-1;
    if(!e)e=rename(staging,r->state);
    return e;
}
static void stale_filters(const char *path) {
    FILE *f=fopen(path,"r");if(!f)return;
    struct ff_attachment a;char line[512];
    while(fgets(line,sizeof(line),f)) {
        if(sscanf(line,"F %u %u %u %u %u",&a.index,&a.point,&a.priority,&a.handle,&a.id)==5)ff_detach(&a);
        unsigned index;char name[IF_NAMESIZE],owner[96];
        if(sscanf(line,"D %u %15s %95s",&index,name,owner)==3 && if_nametoindex(name)==index) {
            char aliaspath[128],alias[128];snprintf(aliaspath,sizeof(aliaspath),"/sys/class/net/%s/ifalias",name);
            FILE *af=fopen(aliaspath,"r");
            if(af) {
                if(fgets(alias,sizeof(alias),af)) {
                    alias[strcspn(alias,"\r\n")]=0;
                    if(!strcmp(alias,owner)) {const char *del[]={"ip","link","delete","dev",name,NULL};ff_command(del);}
                }
                fclose(af);
            }
        }
    }
    fclose(f);
}
static int attach_one(struct runtime *r,unsigned index,enum bpf_tc_attach_point point,const char *name,unsigned priority) {
    if(r->count>=sizeof(r->attached)/sizeof(r->attached[0]))return -1;
    int e=ff_attach(index,point,program(r,name),priority,&r->attached[r->count]);
    if(e)return e;
    r->count++;return save_state(r);
}
static void forget_index(struct runtime *r,unsigned idx) {
    if(!idx)return;
    bpf_map_delete_elem(map(r,"interfaces"),&idx);
    for(unsigned i=0;i<r->options.device_count;i++) if(r->index[i]==idx) {
        bpf_link__destroy(r->ingress[i]);r->ingress[i]=NULL;
    }
    for(unsigned i=0;i<r->count;) {
        if(r->attached[i].index==idx) {
            ff_detach(&r->attached[i]);r->attached[i]=r->attached[--r->count];
        } else i++;
    }
    save_state(r);
}
static int refresh(struct runtime *r,int initial) {
    for(unsigned i=0;i<r->options.device_count;i++) {
        struct ff_device *d=&r->options.devices[i];unsigned idx=0,mtu=0;
        int exists=!ff_link(d->name,d->mode,&idx,&mtu);
        if(!exists || idx!=r->index[i]) {
            forget_index(r,r->index[i]);r->index[i]=0;
        }
        if(!exists) {if(initial)return -1;continue;}
        if(!r->index[i]) {
            if(ff_priority_available(d->name,"egress")) {
                fprintf(stderr,"%s: TC egress priority 1 conflict\n",d->name);return -1;
            }
            struct bpf_tcx_opts opts={.sz=sizeof(opts),.flags=BPF_F_BEFORE};
            struct bpf_link *link=bpf_program__attach_tcx(
                bpf_object__find_program_by_name(r->obj,"ff_ingress"),idx,&opts);
            if(!link || libbpf_get_error(link)) {
                fprintf(stderr,"%s: TCX ingress prepend failed (Linux 6.6+ required)\n",d->name);
                return -1;
            }
            r->ingress[i]=link;r->index[i]=idx;
            if(attach_one(r,idx,BPF_TC_EGRESS,"ff_egress",1)) {
                forget_index(r,idx);return -1;
            }
            r->index[i]=idx;r->generation[i]=++r->epoch;
        }
        struct ff_interface iface={.generation=r->generation[i],.slot=i,.mode=d->mode,
            .mtu=mtu,.builder=d->mode==FF_L3?r->l3:r->l2};
        if(bpf_map_update_elem(map(r,"interfaces"),&idx,&iface,BPF_ANY))return -1;
    }
    return 0;
}
static int same_layout(struct ff_options *a,struct ff_options *b) {
    return a->device_count==b->device_count && !memcmp(a->devices,b->devices,sizeof(a->devices)) &&
        a->tcp_entries==b->tcp_entries && a->udp_entries==b->udp_entries;
}
static int publish(struct runtime *r,struct ff_options *o) {
    unsigned gen=r->config_gen+1,zero=0,tcp=gen*2,udp=tcp+1;
    if(gen>0x7ffffffe) return -1;
    o->kernel.generation=gen;
    if(bpf_map_update_elem(map(r,"templates"),&tcp,&o->tcp_template,BPF_NOEXIST) ||
       bpf_map_update_elem(map(r,"templates"),&udp,&o->udp_template,BPF_NOEXIST) ||
       bpf_map_update_elem(map(r,"configs"),&gen,&o->kernel,BPF_NOEXIST) ||
       bpf_map_update_elem(map(r,"active_config"),&zero,&gen,BPF_ANY)) {
        bpf_map_delete_elem(map(r,"templates"),&tcp);bpf_map_delete_elem(map(r,"templates"),&udp);
        bpf_map_delete_elem(map(r,"configs"),&gen);return -1;
    }
    r->config_gen=gen;r->options=*o;return 0;
}
static void reap_configs(struct runtime *r) {
    /* Retain the current and previous generation. Called after >=2 seconds
     * without a reload, longer than the one-second request lifetime. */
    unsigned key=0,next;
    int fd=map(r,"configs");
    while(!bpf_map_get_next_key(fd,key?&key:NULL,&next)) {
        key=next;
        if(key+1<r->config_gen) {
            unsigned t=key*2,u=t+1;
            bpf_map_delete_elem(map(r,"templates"),&t);bpf_map_delete_elem(map(r,"templates"),&u);
            bpf_map_delete_elem(fd,&key);key=0;
        }
    }
}
static int reload(struct runtime *r,const char *path,char *result,size_t size) {
    struct ff_options next;
    if(ff_config_read(path,&next,result,size))return -1;
    if(!same_layout(&r->options,&next)) {
        snprintf(result,size,"interface layout and map capacities require restart");return -1;
    }
    if(publish(r,&next)) {snprintf(result,size,"map publication failed; active config preserved");return -1;}
    snprintf(result,size,"configuration generation %u active",r->config_gen);return 0;
}
static void stats_json(struct runtime *r,FILE *out) {
    int n=libbpf_num_possible_cpus();if(n<=0){fputs("{\"error\":\"CPU query failed\"}\n",out);return;}
    __u64 *values=calloc(n,sizeof(*values));if(!values){fputs("{\"error\":\"allocation failed\"}\n",out);return;}
    fputc('{',out);
    for(unsigned k=0;k<FF_STATS_MAX;k++) {
        unsigned long long total=0;
        if(!bpf_map_lookup_elem(map(r,"stats"),&k,values)) for(int i=0;i<n;i++)total+=values[i];
        fprintf(out,"%s\"%s\":%llu",k?",":"",ff_stat_names[k],total);
    }
    fputs("}\n",out);free(values);
}
static int control_socket(struct runtime *r,const char *runtime) {
    if(snprintf(r->socket,sizeof(r->socket),"%s/control.sock",runtime)>=(int)sizeof(r->socket))return -1;
    r->server=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);if(r->server<0)return -1;
    struct sockaddr_un addr={.sun_family=AF_UNIX};strcpy(addr.sun_path,r->socket);
    unlink(r->socket);
    if(bind(r->server,(struct sockaddr*)&addr,sizeof(addr)) || listen(r->server,8)) return -1;
    return 0;
}
static int route_socket(void) {
    int fd=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK,NETLINK_ROUTE);if(fd<0)return -1;
    struct sockaddr_nl addr={.nl_family=AF_NETLINK,.nl_groups=RTMGRP_LINK};
    if(bind(fd,(struct sockaddr*)&addr,sizeof(addr))) {close(fd);return -1;}
    return fd;
}
static void link_events(struct runtime *r) {
    char buffer[16384];ssize_t n;
    while((n=recv(r->route,buffer,sizeof(buffer),0))>0) {
        for(struct nlmsghdr *h=(void*)buffer;NLMSG_OK(h,(unsigned)n);h=NLMSG_NEXT(h,n)) {
            if(h->nlmsg_type==RTM_DELLINK && h->nlmsg_len>=NLMSG_LENGTH(sizeof(struct ifinfomsg))) {
                struct ifinfomsg *info=NLMSG_DATA(h);
                for(unsigned i=0;i<r->options.device_count;i++) if(r->index[i]==(unsigned)info->ifi_index) {
                    forget_index(r,r->index[i]);r->index[i]=0;
                }
            }
        }
    }
    if(n<0 && errno!=EAGAIN && errno!=EWOULDBLOCK) {
        /* A lost link event could hide ifindex reuse. Invalidate all epochs. */
        for(unsigned i=0;i<r->options.device_count;i++) {forget_index(r,r->index[i]);r->index[i]=0;}
    }
}
int ff_run(const char *path,const char *object,const char *runtime) {
    struct runtime r={.tun=-1,.server=-1,.lock=-1,.route=-1};
    char error[1024],lockpath[1024],config_path[1024];int rc=1;__u64 last_reload=0;
    if(snprintf(config_path,sizeof(config_path),"%s",path)>=(int)sizeof(config_path))return 1;
    if(geteuid()) {fprintf(stderr,"run requires root\n");return 1;}
    if(ff_config_read(path,&r.options,error,sizeof(error))) {fprintf(stderr,"%s\n",error);return 1;}
    /* Reject ambiguous logical/physical PPPoE duplication conservatively. */
    unsigned l3=0,pppoe=0;
    for(unsigned i=0;i<r.options.device_count;i++) {l3+=r.options.devices[i].mode==FF_L3;pppoe+=r.options.devices[i].mode==FF_PPPOE;}
    if(l3 && pppoe) {fprintf(stderr,"Do not combine l3 and physical pppoe paths in one instance\n");return 1;}
    if(mkdir(runtime,0700) && errno!=EEXIST) {perror(runtime);return 1;}
    struct stat st;
    if(lstat(runtime,&st) || !S_ISDIR(st.st_mode) || st.st_uid!=geteuid() || (st.st_mode&0077)) {
        fprintf(stderr,"runtime directory must be owned by root with mode 0700\n");return 1;
    }
    if(snprintf(lockpath,sizeof(lockpath),"%s/lock",runtime)>=(int)sizeof(lockpath) ||
       snprintf(r.state,sizeof(r.state),"%s/filters",runtime)>=(int)sizeof(r.state))return 1;
    r.lock=open(lockpath,O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);
    if(r.lock<0 || flock(r.lock,LOCK_EX|LOCK_NB)) {fprintf(stderr,"another instance owns this runtime directory\n");goto out;}
    stale_filters(r.state);
    if(ff_check(&r.options))goto out;
    struct rlimit limit={RLIM_INFINITY,RLIM_INFINITY};
    if(setrlimit(RLIMIT_MEMLOCK,&limit)) fprintf(stderr,"memlock limit unchanged: %s\n",strerror(errno));
    r.obj=bpf_object__open_file(object,NULL);
    if(libbpf_get_error(r.obj)) {r.obj=NULL;goto out;}
    bpf_map__set_max_entries(bpf_object__find_map_by_name(r.obj,"tcp_flows"),r.options.tcp_entries);
    bpf_map__set_max_entries(bpf_object__find_map_by_name(r.obj,"udp_flows"),r.options.udp_entries);
    bpf_program__set_expected_attach_type(bpf_object__find_program_by_name(r.obj,"ff_ingress"),BPF_TCX_INGRESS);
    if(bpf_object__load(r.obj))goto out;
    __u64 seed;unsigned zero=0;
    if(getrandom(&seed,sizeof(seed),0)!=(ssize_t)sizeof(seed) ||
       bpf_map_update_elem(map(&r,"sequence"),&zero,&seed,BPF_ANY))goto out;
    /* Disable modifications until every private and WAN filter is ready. */
    if(lease(&r,0))goto out;
    if(ff_dummy(r.dummy,sizeof(r.dummy))) {r.dummy[0]=0;goto out;}
    r.l2=if_nametoindex(r.dummy);
    snprintf(r.owner,sizeof(r.owner),"fakeflow:%u:%llu",getpid(),(unsigned long long)monotime());
    const char *alias[]={"ip","link","set","dev",r.dummy,"alias",r.owner,NULL};
    if(ff_command(alias) || save_state(&r))goto out;
    if(l3) {r.tun=ff_tun(r.tun_name,sizeof(r.tun_name));if(r.tun<0)goto out;r.l3=if_nametoindex(r.tun_name);}
    for(unsigned i=0;i<(l3?2u:1u);i++) {
        unsigned idx=i?r.l3:r.l2;const char *name=i?r.tun_name:r.dummy;
        if(attach_one(&r,idx,BPF_TC_EGRESS,"ff_drop",2) || attach_one(&r,idx,BPF_TC_EGRESS,"ff_builder",1))goto out;
        char ipv6path[128];snprintf(ipv6path,sizeof(ipv6path),"/proc/sys/net/ipv6/conf/%s/disable_ipv6",name);
        int ipv6fd=open(ipv6path,O_WRONLY|O_CLOEXEC);
        if(ipv6fd>=0) {int e=write(ipv6fd,"1\n",2)!=2;close(ipv6fd);if(e)goto out;}
        else if(errno!=ENOENT)goto out;
        const char *up[]={"ip","link","set","dev",name,"up",NULL};if(ff_command(up))goto out;
    }
    r.route=route_socket();if(r.route<0)goto out;
    if(refresh(&r,1) || publish(&r,&r.options) || control_socket(&r,runtime) || lease(&r,1))goto out;
    struct sigaction action={.sa_handler=on_signal};sigemptyset(&action.sa_mask);
    sigaction(SIGINT,&action,NULL);sigaction(SIGTERM,&action,NULL);sigaction(SIGHUP,&action,NULL);signal(SIGPIPE,SIG_IGN);
    printf("READY generation=%u\n",r.config_gen);fflush(stdout);
    __u64 next_lease=0;
    while(!quitting) {
        __u64 now=monotime();
        if(now>=next_lease) {
            if(refresh(&r,0) || lease(&r,1)) {fprintf(stderr,"interface refresh or lease failed\n");goto out;}
            if(now-last_reload>2*FF_NS)reap_configs(&r);
            next_lease=now+2*FF_NS;
        }
        if(reloading) {reloading=0;int e=reload(&r,config_path,error,sizeof(error));last_reload=now;fprintf(stderr,"reload %s: %s\n",e?"failed":"ok",error);}
        struct pollfd fds[2]={{r.server,POLLIN,0},{r.route,POLLIN,0}};
        int n=poll(fds,2,200);if(n<0 && errno!=EINTR)goto out;
        if(fds[1].revents&POLLIN)link_events(&r);
        if(fds[0].revents&POLLIN) {
            int client=accept4(r.server,NULL,NULL,SOCK_CLOEXEC);if(client<0)continue;
            struct timeval timeout={.tv_sec=1};setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
            struct ucred peer;socklen_t len=sizeof(peer);
            if(getsockopt(client,SOL_SOCKET,SO_PEERCRED,&peer,&len) || peer.uid!=geteuid()) {close(client);continue;}
            char command[1200]={};ssize_t got=0,part;
            while(got<(ssize_t)sizeof(command)-1 && (part=read(client,command+got,sizeof(command)-1-got))>0)got+=part;
            FILE *out=fdopen(client,"w");if(!out){close(client);continue;}
            if(got<=0) {fclose(out);continue;}
            command[strcspn(command,"\r\n")]=0;
            if(!strcmp(command,"stats"))stats_json(&r,out);
            else if(!strcmp(command,"status"))fprintf(out,"{\"running\":true,\"generation\":%u,\"interfaces\":%u}\n",r.config_gen,r.options.device_count);
            else if(!strcmp(command,"stop")) {quitting=1;fputs("OK stopping\n",out);}
            else if(!strcmp(command,"reload") || !strncmp(command,"reload ",7)) {
                const char *selected=command[6]==' '?command+7:config_path;
                int e;
                if(strlen(selected)>=sizeof(config_path)) {snprintf(error,sizeof(error),"configuration path too long");e=-1;}
                else {e=reload(&r,selected,error,sizeof(error));if(!e && selected!=config_path)strcpy(config_path,selected);}
                last_reload=monotime();fprintf(out,"%s %s\n",e?"ERROR":"OK",error);
            }
            else fputs("ERROR unknown command\n",out);
            fclose(out);
        }
    }
    rc=0;
out:
    if(r.obj && map(&r,"leases")>=0) {lease(&r,0);drain_requests(&r);}
    for(unsigned i=0;i<FF_INTERFACES;i++)bpf_link__destroy(r.ingress[i]);
    for(unsigned i=r.count;i>0;i--)ff_detach(&r.attached[i-1]);
    if(r.tun>=0)close(r.tun);
    if(*r.dummy) {const char *del[]={"ip","link","delete","dev",r.dummy,NULL};ff_command(del);}
    if(r.server>=0) {close(r.server);unlink(r.socket);}
    if(r.route>=0)close(r.route);
    if(r.obj)bpf_object__close(r.obj);
    if(r.lock>=0) {if(r.count)unlink(r.state);close(r.lock);}
    return rc;
}
int ff_client(const char *runtime,const char *command) {
    struct sockaddr_un addr={.sun_family=AF_UNIX};
    if(snprintf(addr.sun_path,sizeof(addr.sun_path),"%s/control.sock",runtime)>=(int)sizeof(addr.sun_path))return 1;
    int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);if(fd<0)return 1;
    struct timeval timeout={.tv_sec=5};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    if(connect(fd,(struct sockaddr*)&addr,sizeof(addr)) || write(fd,command,strlen(command))!=(ssize_t)strlen(command)) {
        perror("control socket");close(fd);return 1;
    }
    shutdown(fd,SHUT_WR);char buffer[8192];ssize_t n;int rc=0;
    while((n=read(fd,buffer,sizeof(buffer)))>0) {if(n>=5 && !memcmp(buffer,"ERROR",5))rc=1;fwrite(buffer,1,n,stdout);}
    if(n<0){perror("control read");rc=1;}close(fd);return rc;
}
