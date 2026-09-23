/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FAKEFLOW_ABI_H
#define FAKEFLOW_ABI_H
#include <linux/types.h>
#define FF_PAYLOAD_MAX 1200
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
    FF_SKIP_MTU, FF_TFO_FAILED, FF_STATS_MAX
};
struct ff_config {
    __u32 generation, tcp_enabled, udp_enabled, directions;
    __u32 strip_tfo, tcp_batches, udp_both, udp_packets;
    __u32 udp_idle, ttl, repeat, estimate_hops;
    __u32 percent, rate, burst, allow_private;
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
