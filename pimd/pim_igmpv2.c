/*
 * PIM for Quagga
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Daniel Walton
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "zebra.h"

#include "pimd.h"
#include "pim_igmp.h"
#include "pim_igmpv2.h"
#include "pim_igmpv3.h"
#include "pim_str.h"
#include "pim_time.h"
#include "pim_util.h"


static void on_trace(const char *label, struct interface *ifp,
		     struct in_addr from)
{
	if (PIM_DEBUG_IGMP_TRACE) {
		char from_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<from?>", from, from_str, sizeof(from_str));
		zlog_debug("%s: from %s on %s", label, from_str, ifp->name);
	}
}

void igmp_v2_send_query(struct igmp_group *group, int fd, const char *ifname,
			char *query_buf, struct in_addr dst_addr,
			struct in_addr group_addr,
			int query_max_response_time_dsec)
{
	ssize_t msg_size = 8;
	uint8_t max_resp_code;
	ssize_t sent;
	struct sockaddr_in to;
	socklen_t tolen;
	uint16_t checksum;

	/* max_resp_code must be non-zero else this will look like an IGMP v1
	 * query */
	max_resp_code = igmp_msg_encode16to8(query_max_response_time_dsec);
	zassert(max_resp_code > 0);

	query_buf[0] = PIM_IGMP_MEMBERSHIP_QUERY;
	query_buf[1] = max_resp_code;
	*(uint16_t *)(query_buf + IGMP_CHECKSUM_OFFSET) =
		0; /* for computing checksum */
	memcpy(query_buf + 4, &group_addr, sizeof(struct in_addr));

	checksum = in_cksum(query_buf, msg_size);
	*(uint16_t *)(query_buf + IGMP_CHECKSUM_OFFSET) = checksum;

	if (PIM_DEBUG_IGMP_PACKETS) {
		char dst_str[INET_ADDRSTRLEN];
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<dst?>", dst_addr, dst_str, sizeof(dst_str));
		pim_inet4_dump("<group?>", group_addr, group_str,
			       sizeof(group_str));
		zlog_debug("Send IGMPv2 QUERY to %s on %s for group %s",
			   dst_str, ifname, group_str);
	}

	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr = dst_addr;
	tolen = sizeof(to);

	sent = sendto(fd, query_buf, msg_size, MSG_DONTWAIT,
		      (struct sockaddr *)&to, tolen);
	if (sent != (ssize_t)msg_size) {
		char dst_str[INET_ADDRSTRLEN];
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<dst?>", dst_addr, dst_str, sizeof(dst_str));
		pim_inet4_dump("<group?>", group_addr, group_str,
			       sizeof(group_str));
		if (sent < 0) {
			zlog_warn(
				"Send IGMPv2 QUERY failed due to %s on %s: group=%s msg_size=%zd: errno=%d: %s",
				dst_str, ifname, group_str, msg_size, errno,
				safe_strerror(errno));
		} else {
			zlog_warn(
				"Send IGMPv2 QUERY failed due to %s on %s: group=%s msg_size=%zd: sent=%zd",
				dst_str, ifname, group_str, msg_size, sent);
		}
		return;
	}
}

int igmp_v2_recv_report(struct igmp_sock *igmp, struct in_addr from,
			const char *from_str, char *igmp_msg, int igmp_msg_len)
{
	struct interface *ifp = igmp->interface;
	struct in_addr group_addr;
	char group_str[INET_ADDRSTRLEN];

	on_trace(__PRETTY_FUNCTION__, igmp->interface, from);

	if (igmp->mtrace_only)
		return 0;

	if (igmp_msg_len != IGMP_V12_MSG_SIZE) {
		zlog_warn(
			"Recv IGMPv2 REPORT from %s on %s: size=%d other than correct=%d",
			from_str, ifp->name, igmp_msg_len, IGMP_V12_MSG_SIZE);
		return -1;
	}

	/* Collecting IGMP Rx stats */
	igmp->rx_stats.report_v2++;

	memcpy(&group_addr, igmp_msg + 4, sizeof(struct in_addr));

	if (PIM_DEBUG_IGMP_PACKETS) {
		pim_inet4_dump("<dst?>", group_addr, group_str,
			       sizeof(group_str));
		zlog_debug("Recv IGMPv2 REPORT from %s on %s for %s", from_str,
			   ifp->name, group_str);
	}

	/*
	 * RFC 3376
	 * 7.3.2. In the Presence of Older Version Group Members
	 *
	 * When Group Compatibility Mode is IGMPv2, a router internally
	 * translates the following IGMPv2 messages for that group to their
	 * IGMPv3 equivalents:
	 *
	 * IGMPv2 Message                IGMPv3 Equivalent
	 * --------------                -----------------
	 * Report                        IS_EX( {} )
	 * Leave                         TO_IN( {} )
	 */
	igmpv3_report_isex(igmp, from, group_addr, 0, NULL, 1);

	return 0;
}

int igmp_v2_recv_leave(struct igmp_sock *igmp, struct in_addr from,
		       const char *from_str, char *igmp_msg, int igmp_msg_len)
{
	struct interface *ifp = igmp->interface;
	struct in_addr group_addr;
	char group_str[INET_ADDRSTRLEN];

	on_trace(__PRETTY_FUNCTION__, igmp->interface, from);

	if (igmp->mtrace_only)
		return 0;

	if (igmp_msg_len != IGMP_V12_MSG_SIZE) {
		zlog_warn(
			"Recv IGMPv2 LEAVE from %s on %s: size=%d other than correct=%d",
			from_str, ifp->name, igmp_msg_len, IGMP_V12_MSG_SIZE);
		return -1;
	}

	/* Collecting IGMP Rx stats */
	igmp->rx_stats.leave_v2++;

	memcpy(&group_addr, igmp_msg + 4, sizeof(struct in_addr));

	if (PIM_DEBUG_IGMP_PACKETS) {
		pim_inet4_dump("<dst?>", group_addr, group_str,
			       sizeof(group_str));
		zlog_debug("Recv IGMPv2 LEAVE from %s on %s for %s", from_str,
			   ifp->name, group_str);
	}

	/*
	 * RFC 3376
	 * 7.3.2. In the Presence of Older Version Group Members
	 *
	 * When Group Compatibility Mode is IGMPv2, a router internally
	 * translates the following IGMPv2 messages for that group to their
	 * IGMPv3 equivalents:
	 *
	 * IGMPv2 Message                IGMPv3 Equivalent
	 * --------------                -----------------
	 * Report                        IS_EX( {} )
	 * Leave                         TO_IN( {} )
	 */
	igmpv3_report_toin(igmp, from, group_addr, 0, NULL);

	return 0;
}
