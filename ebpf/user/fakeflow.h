/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FAKEFLOW_USER_H
#define FAKEFLOW_USER_H
#include "../include/abi.h"
#include <stddef.h>
#include <net/if.h>
struct ff_device { char name[IF_NAMESIZE]; unsigned mode; };
struct ff_options {
    struct ff_config kernel;
    struct ff_device devices[FF_INTERFACES];
    unsigned device_count, tcp_entries, udp_entries, lease;
    char tcp_payload[16], udp_payload[16], hostname[254], sip_uri[254];
    char tcp_file[1024], udp_file[1024];
    struct ff_template tcp_template, udp_template;
};
int ff_config_read(const char *path, struct ff_options *out, char *error, size_t cap);
int ff_templates(struct ff_options *o, char *error, size_t cap);
int ff_check(const struct ff_options *o);
int ff_run(const char *path, const char *object, const char *runtime);
int ff_client(const char *runtime, const char *command);
extern const char *ff_stat_names[FF_STATS_MAX];
#endif
