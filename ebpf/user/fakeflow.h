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
/* One TCP template slot. Slot 0 mirrors the primary template after parsing, so
 * the publish loop and the variant renderer treat every slot the same way; the
 * port-matched templates (`https_*`, then each `[[tcp.extra]]`) fill slots 1
 * upwards in configuration order. */
struct ff_tcp_slot {
    char hostname[254], file[1024];
    struct ff_template tpl;
};
/* Payload a port-matched slot generates when no payload file is configured. The
 * https compatibility keys are always TLS, which is what they have always
 * produced; an `[[tcp.extra]]` entry picks one explicitly. */
enum { FF_SLOT_TLS = 0, FF_SLOT_HTTP };
/* One entry per published template, indexed by FF_TEMPLATE_PLAN(proto, slot). */
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
    /* Second TCP template (selected by port). It exists only when
     * https_hostname or https_file is set; the payload kind is implied by which
     * of the two was configured. */
    char https_hostname[254], https_file[1024];
    /* Indexed by TCP slot, and always populated for the slots the configuration
     * defines (slot 0 mirrors the primary template). extra_count is how many
     * port-matched slots are in use, 0..FF_TCP_EXTRA_MAX. */
    struct ff_tcp_slot extra[FF_TEMPLATE_SLOTS];
    unsigned extra_count;
    /* Payload each port-matched slot generates; see FF_SLOT_TLS/FF_SLOT_HTTP. */
    unsigned extra_kind[FF_TEMPLATE_SLOTS];
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
