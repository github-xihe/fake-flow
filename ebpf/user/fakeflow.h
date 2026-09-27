/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FAKEFLOW_USER_H
#define FAKEFLOW_USER_H
#include "../include/abi.h"
#include <stddef.h>
#include <net/if.h>
struct ff_device { char name[IF_NAMESIZE]; unsigned mode; };
/* Byte ranges of the generated template that carry a randomised identity.
 * Recorded while the template is rendered so variants can be produced without
 * re-parsing the datagram. */
#define FF_RAND_FIELDS 3
struct ff_rand_field { __u16 off, bytes; };
/* How a plan pre-renders its variants. SAME keeps a single byte-identical copy
 * for a template with no randomised bytes, PATCH rewrites the recorded byte
 * ranges, and RENDER runs the generator again for a payload whose randomness
 * lives inside the generator (the TLS ClientHello random). */
enum ff_variant_kind { FF_VARIANT_SAME = 0, FF_VARIANT_PATCH, FF_VARIANT_RENDER };
/* One TCP payload rule. The type decides which field is read (http and tls take
 * hostname, custom takes file) and how the datagram is rendered. Rules are not
 * selected by port: a connection is pinned to one of them for its lifetime. */
struct ff_rule {
    char type[16], payload[1024];   /* payload is resolved into hostname or file */
    char hostname[254], file[1024];
    unsigned enabled;
    struct ff_template tpl;
};
/* One entry per published template: plans 0..FF_TCP_RULES_MAX-1 are the TCP
 * rules and FF_TEMPLATE_PLAN_UDP is the single UDP template. */
struct ff_plan {
    unsigned kind, variants, rand_count;
    struct ff_rand_field rand[FF_RAND_FIELDS];
};
struct ff_options {
    struct ff_config kernel;
    struct ff_device devices[FF_INTERFACES];
    unsigned device_count, tcp_entries, udp_entries, lease;
    char tcp_payload[16], udp_payload[16], hostname[254], sip_uri[254];
    char tcp_file[1024], udp_file[1024];
    /* TCP payload rules in configured order; a rule a configuration did not
     * enable keeps an empty type and is never rendered or published. */
    struct ff_rule rules[FF_TCP_RULES_MAX];
    unsigned rule_count;
    /* Deprecation notice produced while parsing (retired keys), logged by the
     * daemon and printed by the CLI. Keeps config.c free of the log plumbing. */
    char warning[192];
    struct ff_template tcp_template, udp_template;
    struct ff_plan plan[FF_TEMPLATE_PLAN_COUNT];
};
int ff_config_read(const char *path, struct ff_options *out, char *error, size_t cap);
int ff_templates(struct ff_options *o, char *error, size_t cap);
int ff_variants(const struct ff_options *o, struct ff_template out[][FF_TEMPLATE_VARIANTS], unsigned n);
int ff_check(const struct ff_options *o);
/* Levels for the daemon's own log stream. Lines carry a timestamp and their
 * level because the file is the primary place this output is read (syslog no
 * longer sees it), and so that both the file and the LuCI view can be filtered.
 * ff_log_set is called once in run mode; without it the stream is stderr at
 * FF_LOG_INFO, which keeps CLI diagnostics unchanged. */
enum { FF_LOG_ERROR = 0, FF_LOG_WARN, FF_LOG_INFO, FF_LOG_DEBUG };
void ff_log_set(int level);
/* Nonzero once run mode installed the logger, so shared code (the pre-flight
 * check) can stamp its lines instead of printing unstamped output that would
 * still land in the log file. */
int ff_log_active(void);
void ff_log(int level, const char *format, ...) __attribute__((format(printf,2,3)));
int ff_run(const char *path, const char *object, const char *runtime, const char *logfile, int log_level);
int ff_client(const char *runtime, const char *command);
extern const char *ff_stat_names[FF_STATS_MAX];
#endif
