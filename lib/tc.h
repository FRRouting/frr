/*
 * Traffic Control (TC) main header
 * Copyright (C) 2022  Shichu Yang
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _TC_H
#define _TC_H

#include <zebra.h>
#include "stream.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TC_STR "Traffic Control\n"

/* qdisc definitions */

/* qdisc kind (same as class kinds) */
enum tc_qdisc_kind {
	TC_QDISC_UNSPEC,
	TC_QDISC_HTB,
	TC_QDISC_NOQUEUE,
};

struct tc_qdisc_htb {
	/* currently no members */
};

struct tc_qdisc {
	ifindex_t ifindex;

	enum tc_qdisc_kind kind;
	union {
		struct tc_qdisc_htb htb;
	} u;
};

/* class definitions */

/* since classes share the same kinds of qdisc, duplicates omitted */
struct tc_class_htb {
	uint64_t rate;
	uint64_t ceil;
};

struct tc_class {
	ifindex_t ifindex;
	uint32_t handle;

	enum tc_qdisc_kind kind;
	union {
		struct tc_class_htb htb;
	} u;
};

/* filter definitions */

/* filter kinds */
enum tc_filter_kind {
	TC_FILTER_UNSPEC,
	TC_FILTER_BPF,
	TC_FILTER_FLOW,
	TC_FILTER_FLOWER,
	TC_FILTER_U32,
};

struct tc_bpf {
	/* TODO: fill in */
};

struct tc_flow {
	/* TODO: fill in */
};

struct tc_flower {
	uint32_t classid;

#define TC_FLOWER_IP_PROTOCOL (1 << 0)
#define TC_FLOWER_SRC_IP (1 << 1)
#define TC_FLOWER_DST_IP (1 << 2)
#define TC_FLOWER_SRC_PORT (1 << 3)
#define TC_FLOWER_DST_PORT (1 << 4)
#define TC_FLOWER_DSFIELD (1 << 5)

	uint32_t filter_bm;

	uint8_t ip_proto;

	struct prefix src_ip;
	struct prefix dst_ip;

	uint16_t src_port_min;
	uint16_t src_port_max;
	uint16_t dst_port_min;
	uint16_t dst_port_max;

	uint8_t dsfield;
	uint8_t dsfield_mask;
};

struct tc_u32 {
	/* TODO: fill in */
};

struct tc_filter {
	ifindex_t ifindex;
	uint32_t handle;

	uint32_t priority;
	uint16_t protocol;

	enum tc_filter_kind kind;

	union {
		struct tc_bpf bpf;
		struct tc_flow flow;
		struct tc_flower flower;
		struct tc_u32 u32;
	} u;
};

extern int tc_getrate(const char *str, uint64_t *rate);

extern int zapi_tc_qdisc_encode(uint8_t cmd, struct stream *s,
				struct tc_qdisc *qdisc);
extern int zapi_tc_class_encode(uint8_t cmd, struct stream *s,
				struct tc_class *class);
extern int zapi_tc_filter_encode(uint8_t cmd, struct stream *s,
				 struct tc_filter *filter);

#ifdef __cplusplus
}
#endif

#endif /* _TC_H */
