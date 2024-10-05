// SPDX-License-Identifier: GPL-2.0-or-later
/* Policy Based Routing (PBR) main header
 * Copyright (C) 2018 6WIND
 * Portions:
 *      Copyright (c) 2021 The MITRE Corporation.
 *      Copyright (c) 2023 LabN Consulting, L.L.C.
 */

#ifndef _PBR_H
#define _PBR_H

#include <zebra.h>
#include "stream.h"
#include "prefix.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PBR_STR "Policy Based Routing\n"

/*
 * A PBR filter
 *
 * The filter or match criteria in a PBR rule.
 * For simplicity, all supported filters are grouped into a structure rather
 * than delineating further. A bitmask denotes which filters are actually
 * specified.
 */
struct pbr_filter {
	uint32_t filter_bm;
#define PBR_FILTER_SRC_IP         (1 << 0)
#define PBR_FILTER_DST_IP         (1 << 1)
#define PBR_FILTER_SRC_PORT       (1 << 2)
#define PBR_FILTER_DST_PORT       (1 << 3)
#define PBR_FILTER_FWMARK         (1 << 4)
#define PBR_FILTER_IP_PROTOCOL	  (1 << 5)
#define PBR_FILTER_SRC_PORT_RANGE (1 << 6)
#define PBR_FILTER_DST_PORT_RANGE (1 << 7)
#define PBR_FILTER_DSCP		  (1 << 8)
#define PBR_FILTER_ECN		  (1 << 9)
#define PBR_FILTER_PCP            (1 << 10)
#define PBR_FILTER_VLAN_FLAGS     (1 << 11)
#define PBR_FILTER_VLAN_ID        (1 << 12)

#define PBR_DSFIELD_DSCP (0xfc) /* Upper 6 bits of DS field: DSCP */
#define PBR_DSFIELD_ECN (0x03)	/* Lower 2 bits of DS field: BCN */

#define PBR_PCP (0x07)		/* 3-bit value 0..7 for prioritization*/

#define PBR_VLAN_FLAGS_NO_WILD	  0
#define PBR_VLAN_FLAGS_TAGGED	  (1 << 0)
#define PBR_VLAN_FLAGS_UNTAGGED	  (1 << 1)
#define PBR_VLAN_FLAGS_UNTAGGED_0 (1 << 2)

	/* Source and Destination IP address with masks */
	struct prefix src_ip;
	struct prefix dst_ip;

	/* Source and Destination layer 4 (TCP/UDP/etc.) port numbers */
	uint16_t src_port;
	uint16_t dst_port;

	/* Filter by VLAN and prioritization */
	uint8_t pcp;
	uint16_t vlan_id;
	uint16_t vlan_flags;

	/* Filter by Differentiated Services field  */
	uint8_t dsfield; /* DSCP (6 bits) & ECN (2 bits) */

	/* Filter with fwmark */
	uint32_t fwmark;

	/* Filter with the ip protocol */
	uint8_t ip_proto;
};

/*
 * A PBR action
 *
 * The action corresponding to a PBR rule.
 * While the user specifies the action in a particular way, the forwarding
 * plane implementation (Linux only) requires that to be encoded into a
 * route table and the rule then point to that route table; in some cases,
 * the user criteria may directly point to a table too.
 */
struct pbr_action {
	uint32_t flags;

#define PBR_ACTION_TABLE		(1 << 0)
#define PBR_ACTION_QUEUE_ID		(1 << 1)
#define PBR_ACTION_PCP			(1 << 2)
#define PBR_ACTION_VLAN_ID		(1 << 3)
#define PBR_ACTION_VLAN_STRIP_INNER_ANY (1 << 4)
#define PBR_ACTION_SRC_IP		(1 << 5)
#define PBR_ACTION_DST_IP		(1 << 6)
#define PBR_ACTION_SRC_PORT		(1 << 7)
#define PBR_ACTION_DST_PORT		(1 << 8)
#define PBR_ACTION_DSCP			(1 << 9)
#define PBR_ACTION_ECN			(1 << 10)
#define PBR_ACTION_DROP			(1 << 11) /* nexthop == blackhole */

	uint32_t table;
	uint32_t queue_id;

	/* VLAN */
	uint8_t pcp;
	uint16_t vlan_id;

	/* Source and Destination IP addresses */
	union sockunion src_ip;
	union sockunion dst_ip;

	/* Source and Destination layer 4 (TCP/UDP/etc.) port numbers */
	uint32_t src_port;
	uint32_t dst_port;

	/* Differentiated Services field  */
	uint8_t dscp; /* stored here already shifted to upper 6 bits */
	uint8_t ecn;  /* stored here as lower 2 bits */
};

/*
 * A PBR rule
 *
 * This is a combination of the filter criteria and corresponding action.
 * Rules also have a user-defined sequence number which defines the relative
 * order amongst rules.
 */
struct pbr_rule {
	vrf_id_t vrf_id;
	uint8_t family; /* netlink: select which rule database */

	uint32_t seq;
	uint32_t priority;
	uint32_t unique;
	struct pbr_filter filter;
	struct pbr_action action;

	char ifname[IFNAMSIZ + 1];
};

/* TCP flags value shared
 * those are values of byte 13 of TCP header
 * as mentioned in rfc793
 */
#define TCP_HEADER_FIN (0x01)
#define TCP_HEADER_SYN (0x02)
#define TCP_HEADER_RST (0x04)
#define TCP_HEADER_PSH (0x08)
#define TCP_HEADER_ACK (0x10)
#define TCP_HEADER_URG (0x20)
#define TCP_HEADER_ALL_FLAGS (TCP_HEADER_FIN | TCP_HEADER_SYN \
			      | TCP_HEADER_RST | TCP_HEADER_PSH \
			      | TCP_HEADER_ACK | TCP_HEADER_URG)

/* Pbr IPTable defines
 * those are common flags shared between BGP and Zebra
 */
#define MATCH_IP_SRC_SET		(1 << 0)
#define MATCH_IP_DST_SET		(1 << 1)
#define MATCH_PORT_SRC_SET		(1 << 2)
#define MATCH_PORT_DST_SET		(1 << 3)
#define MATCH_PORT_SRC_RANGE_SET	(1 << 4)
#define MATCH_PORT_DST_RANGE_SET	(1 << 5)
#define MATCH_DSCP_SET			(1 << 6)
#define MATCH_DSCP_INVERSE_SET		(1 << 7)
#define MATCH_PKT_LEN_INVERSE_SET	(1 << 8)
#define MATCH_FRAGMENT_INVERSE_SET	(1 << 9)
#define MATCH_ICMP_SET			(1 << 10)
#define MATCH_PROTOCOL_SET		(1 << 11)
#define MATCH_FLOW_LABEL_SET		(1 << 12)
#define MATCH_FLOW_LABEL_INVERSE_SET	(1 << 13)

extern int zapi_pbr_rule_encode(struct stream *s, struct pbr_rule *r);
extern bool zapi_pbr_rule_decode(struct stream *s, struct pbr_rule *r);

#ifdef __cplusplus
}
#endif

#endif /* _PBR_H */
