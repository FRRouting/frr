/* Policy Based Routing (PBR) main header
 * Copyright (C) 2018 6WIND
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
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
	uint32_t filter_bm; /* not encoded by zapi
			     */
#define PBR_FILTER_SRC_IP		(1 << 0)
#define PBR_FILTER_DST_IP		(1 << 1)
#define PBR_FILTER_SRC_PORT		(1 << 2)
#define PBR_FILTER_DST_PORT		(1 << 3)
#define PBR_FILTER_FWMARK		(1 << 4)
#define PBR_FILTER_PROTO		(1 << 5)
#define PBR_FILTER_SRC_PORT_RANGE	(1 << 6)
#define PBR_FILTER_DST_PORT_RANGE	(1 << 7)

	/* Source and Destination IP address with masks. */
	struct prefix src_ip;
	struct prefix dst_ip;

	/* Source and Destination higher-layer (TCP/UDP) port numbers. */
	uint16_t src_port;
	uint16_t dst_port;

	/* Filter with fwmark */
	uint32_t fwmark;
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
	uint32_t table;
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

	uint32_t seq;
	uint32_t priority;
	uint32_t unique;
	struct pbr_filter filter;
	struct pbr_action action;
	ifindex_t ifindex;
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

extern int zapi_pbr_rule_encode(uint8_t cmd, struct stream *s,
				struct pbr_rule *zrule);

#ifdef __cplusplus
}
#endif

#endif /* _PBR_H */
