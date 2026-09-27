/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FAKEFLOW_ABI_H
#define FAKEFLOW_ABI_H
#include <linux/types.h>
#define FF_PAYLOAD_MAX 1200
/* Pre-rendered datagram variants per protocol. The builder picks one at random
 * for every injected packet, so randomised identity fields (SIP branch, tag,
 * Call-ID) differ between datagrams. Rendering every variant in userspace
 * keeps the datapath free of byte patching and checksum surgery, and variant 0
 * stays byte-identical to the canonical template that `validate` reports. Must
 * be a power of two: selection masks the high bits of bpf_get_prandom_u32().
 * 2 * FF_TEMPLATE_VARIANTS keys are live per configuration generation. */
#define FF_TEMPLATE_VARIANTS 32
/* Datagram templates are keyed by (generation, plan, variant); a plan is one TCP
 * payload rule (0..FF_TCP_RULES_MAX-1) or FF_TEMPLATE_PLAN_UDP for UDP. Rules are
 * not selected by port any more: a connection is assigned one rule when its flow
 * state is created and keeps it for its lifetime, so consecutive connections
 * rotate through the configured rules while a single connection never mixes two
 * payload shapes. */
#define FF_TCP_RULES_MAX 3
#define FF_TEMPLATE_VARIANT_BITS 5
#define FF_TEMPLATE_PLAN_UDP FF_TCP_RULES_MAX
#define FF_TEMPLATE_PLAN_COUNT (FF_TCP_RULES_MAX + 1)
/* Template map key: one span of FF_TEMPLATE_VARIANTS entries per plan, one span of
 * plans per generation. The builder and the publisher must agree, so both use
 * this macro rather than repeating the arithmetic. */
#define FF_TEMPLATE_KEY(gen, plan, variant) \
    ((((gen) * FF_TEMPLATE_PLAN_COUNT + (plan)) * FF_TEMPLATE_VARIANTS) + (variant))
#define FF_INTERFACES 8
#define FF_NS 1000000000ULL
#define FF_REQUEST_NS (1 * FF_NS)
enum ff_mode { FF_ETHERNET, FF_L3, FF_PPPOE };
enum ff_stat {
    FF_TCP_SYN, FF_TCP_ELIGIBLE, FF_TFO_STRIPPED, FF_SKIP_SYNACK_DATA,
    FF_UDP_NEW, FF_UDP_EARLY, FF_UDP_EXHAUSTED,
    FF_ATTEMPT, FF_BUILD_OK, FF_SUBMIT_OK, FF_CLONE_FAILED, FF_BUILD_FAILED,
    FF_SKIP_PRIVATE, FF_SKIP_NEAR, FF_TTL_UNKNOWN, FF_SKIP_FRAGMENT,
    FF_SKIP_GSO, FF_SKIP_LAYOUT, FF_MAP_FAILED, FF_REQUEST_EXPIRED,
    FF_RATE_LIMITED, FF_LEASE_EXPIRED, FF_INTERNAL, FF_SKIP_AUTH,
    FF_SKIP_MTU, FF_TFO_FAILED,
    /* Appended: per-reason parse() rejections. The caller used to fold every
     * parse() failure into skip_layout, which made skip_layout a superset of
     * skip_gso/skip_fragment and useless for diagnosis. Appended so existing
     * counter indices keep their meaning. */
    FF_SKIP_LEN, FF_SKIP_L2, FF_SKIP_IPVER, FF_SKIP_IPV4_OPTS, FF_SKIP_PROTO, FF_SKIP_TRUNC,
    FF_STATS_MAX
};
struct ff_config {
    __u32 generation, tcp_enabled, udp_enabled, directions;
    __u32 strip_tfo, tcp_batches, udp_both, udp_packets;
    __u32 udp_idle, ttl, repeat, estimate_hops;
    __u32 percent, rate, burst, allow_private;
    /* Enabled TCP payload rules, in the order the rotation visits them. A
     * connection is pinned to one of them for its lifetime; disabled rules are
     * left out so the datapath can never pick an unpublished plan. */
    __u32 rule_map[FF_TCP_RULES_MAX], rule_count;
    /* Pre-rendered variants per plan index. The observer masks its random pick
     * with this value so the builder always asks for a published key; a plan
     * whose template has no randomised bytes is published with one variant. */
    __u32 variants[FF_TEMPLATE_PLAN_COUNT];
};
struct ff_interface {
    __u32 generation, slot, mode, mtu, builder;
};
struct ff_template { __u32 len; __u8 data[FF_PAYLOAD_MAX]; };
struct ff_key {
    __u32 ifindex, generation;
    __u8 local[16], remote[16];
    __u16 local_port, remote_port;
    __u16 vlan[2], vlan_proto[2], session;
    __u8 peer[6], family, protocol;
    __u8 vlan_count, pad;
};
#endif
