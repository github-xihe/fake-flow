// SPDX-License-Identifier: GPL-2.0-only
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
static volatile sig_atomic_t done;
static void stop(int s) { (void)s; done = 1; }
static int attach(int idx, int fd, int priority) {
    struct bpf_tc_hook h = {.sz = sizeof(h), .ifindex = idx, .attach_point = BPF_TC_EGRESS};
    struct bpf_tc_opts o = {.sz = sizeof(o), .prog_fd = fd, .handle = 1, .priority = priority};
    int e = bpf_tc_hook_create(&h);
    if (e && e != -EEXIST) return e;
    return bpf_tc_attach(&h, &o);
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    struct bpf_object *obj = bpf_object__open_file("build/p0.bpf.o", NULL);
    if (libbpf_get_error(obj) || bpf_object__load(obj)) return 1;
    unsigned c[2] = {if_nametoindex(argv[1]), if_nametoindex(argv[2])}, k = 0;
    if (!c[0] || !c[1] || bpf_map_update_elem(bpf_object__find_map_fd_by_name(obj, "config"), &k, c, BPF_ANY)) return 1;
    if (attach(c[1], bpf_program__fd(bpf_object__find_program_by_name(obj, "builder")), 10) ||
        attach(c[0], bpf_program__fd(bpf_object__find_program_by_name(obj, "observer")), 10) ||
        attach(c[0], bpf_program__fd(bpf_object__find_program_by_name(obj, "following")), 20)) return 1;
    signal(SIGTERM, stop); signal(SIGINT, stop);
    puts("READY"); fflush(stdout);
    while (!done) pause();
    int fd = bpf_object__find_map_fd_by_name(obj, "stats");
    for (k = 0; k < 8; k++) {
        unsigned long long v = 0;
        if (bpf_map_lookup_elem(fd, &k, &v)) return 1;
        printf("%u=%llu\n", k, v);
    }
    bpf_object__close(obj);
    return 0;
}
