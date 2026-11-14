// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Traffic Control (TC) main header
 * Copyright (C) 2022  Shichu Yang
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
	TC_QDISC_CLSACT, /* ingress/egress classification hooks, no queueing */
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
#define TC_FLOWER_VLAN_ID	(1 << 6)
#define TC_FLOWER_VLAN_PRIO	(1 << 7)
#define TC_FLOWER_VLAN_ETH_TYPE (1 << 8)

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

	/* 802.1Q keys; only valid when the filter protocol is ETH_P_8021Q */
	uint16_t vlan_id;
	uint8_t vlan_prio;
	uint16_t vlan_eth_type; /* ethertype inside the tag, host order */
};

struct tc_u32 {
	/* TODO: fill in */
};

/* Where a filter is attached */
enum tc_filter_attach {
	TC_ATTACH_ROOT = 0, /* zebra's root qdisc (htb), classid steering */
	TC_ATTACH_INGRESS,  /* clsact ingress hook */
	TC_ATTACH_EGRESS,   /* clsact egress hook */
};

/*
 * skbedit action: set skb->priority and/or a masked skb->mark, then
 * continue (TC_ACT_PIPE).
 */
struct tc_action_skbedit {
	bool set_priority;
	uint32_t priority;

	bool set_mark;
	uint32_t mark;
	uint32_t mark_mask;
};

struct tc_filter {
	ifindex_t ifindex;
	uint32_t handle;

	uint32_t priority;
	uint16_t protocol;

	enum tc_filter_kind kind;

	enum tc_filter_attach attach;

	/*
	 * When set, the filter runs the skbedit action instead of steering
	 * to u.flower.classid.
	 */
	bool has_action;
	struct tc_action_skbedit skbedit;

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
