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
#include "pim_instance.h"
#include "pim_igmp.h"
#include "pim_igmpv2.h"
#include "pim_igmpv3.h"
#include "pim_ssm.h"
#include "pim_str.h"
#include "pim_time.h"
#include "pim_util.h"


static void on_trace(const char *label, struct interface *ifp,
		     struct in_addr from)
{
	if (PIM_DEBUG_GM_TRACE) {
		char from_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<from?>", from, from_str, sizeof(from_str));
		zlog_debug("%s: from %s on %s", label, from_str, ifp->name);
	}
}

void igmp_v2_send_query(struct gm_group *group, int fd, const char *ifname,
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
	/* RFC 2236: 2.2. , v2's is equal to it */
	max_resp_code = query_max_response_time_dsec;
	assert(max_resp_code > 0);

	query_buf[0] = PIM_IGMP_MEMBERSHIP_QUERY;
	query_buf[1] = max_resp_code;
	*(uint16_t *)(query_buf + IGMP_CHECKSUM_OFFSET) =
		0; /* for computing checksum */
	memcpy(query_buf + 4, &group_addr, sizeof(struct in_addr));

	checksum = in_cksum(query_buf, msg_size);
	*(uint16_t *)(query_buf + IGMP_CHECKSUM_OFFSET) = checksum;

	if (PIM_DEBUG_GM_PACKETS) {
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

int igmp_v2_recv_report(struct gm_sock *igmp, struct in_addr from,
			const char *from_str, char *igmp_msg, int igmp_msg_len)
{
	struct interface *ifp = igmp->interface;
	struct in_addr group_addr;
	struct pim_interface *pim_ifp;
	char group_str[INET_ADDRSTRLEN];

	on_trace(__func__, igmp->interface, from);

	pim_ifp = ifp->info;

	if (igmp->mtrace_only)
		return 0;

	if (igmp_msg_len != IGMP_V12_MSG_SIZE) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug(
				"Recv IGMPv2 REPORT from %s on %s: size=%d other than correct=%d",
				from_str, ifp->name, igmp_msg_len,
				IGMP_V12_MSG_SIZE);
	}

	if (igmp_validate_checksum(igmp_msg, igmp_msg_len) == -1) {
		zlog_warn(
			"Recv IGMPv2 REPORT from %s on %s: size=%d with invalid checksum",
			from_str, ifp->name, igmp_msg_len);
		return -1;
	}

	/* Collecting IGMP Rx stats */
	igmp->igmp_stats.report_v2++;

	memcpy(&group_addr, igmp_msg + 4, sizeof(struct in_addr));

	if (PIM_DEBUG_GM_PACKETS) {
		pim_inet4_dump("<dst?>", group_addr, group_str,
			       sizeof(group_str));
		zlog_debug("Recv IGMPv2 REPORT from %s on %s for %s", from_str,
			   ifp->name, group_str);
	}

	/*
	 * RFC 4604
	 * section 2.2.1
	 * EXCLUDE mode does not apply to SSM addresses, and an SSM-aware router
	 * will ignore MODE_IS_EXCLUDE and CHANGE_TO_EXCLUDE_MODE requests in
	 * the SSM range.
	 */
	if (pim_is_grp_ssm(pim_ifp->pim, group_addr)) {
		if (PIM_DEBUG_GM_PACKETS) {
			zlog_debug(
				"Ignoring IGMPv2 group record %pI4 from %s on %s exclude mode in SSM range",
				&group_addr.s_addr, from_str, ifp->name);
		}
		return -1;
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

int igmp_v2_recv_leave(struct gm_sock *igmp, struct ip *ip_hdr,
		       const char *from_str, char *igmp_msg, int igmp_msg_len)
{
	struct interface *ifp = igmp->interface;
	struct in_addr group_addr;
	char group_str[INET_ADDRSTRLEN];
	struct in_addr from = ip_hdr->ip_src;

	on_trace(__func__, igmp->interface, from);

	if (igmp->mtrace_only)
		return 0;

	if (igmp_msg_len != IGMP_V12_MSG_SIZE) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug(
				"Recv IGMPv2 LEAVE from %s on %s: size=%d other than correct=%d",
				from_str, ifp->name, igmp_msg_len,
				IGMP_V12_MSG_SIZE);
	}

	if (igmp_validate_checksum(igmp_msg, igmp_msg_len) == -1) {
		zlog_warn(
			"Recv IGMPv2 LEAVE from %s on %s with invalid checksum",
			from_str, ifp->name);
		return -1;
	}


	memcpy(&group_addr, igmp_msg + 4, sizeof(struct in_addr));

	if (PIM_DEBUG_GM_PACKETS) {
		pim_inet4_dump("<dst?>", group_addr, group_str,
			       sizeof(group_str));
		zlog_debug("Recv IGMPv2 LEAVE from %s on %s for %s", from_str,
			   ifp->name, group_str);
	}
	/*
	 * As per RFC 2236, section 9:
	 Message Type                  Destination Group
	 ------------                  -----------------
	 General Query                 ALL-SYSTEMS (224.0.0.1)
	 Group-Specific Query          The group being queried
	 Membership Report             The group being reported
	 Leave Message                 ALL-ROUTERS (224.0.0.2)

	 Note: in older (i.e., non-standard and now obsolete) versions of
	 IGMPv2, hosts send Leave Messages to the group being left.  A
	 router SHOULD accept Leave Messages addressed to the group being
	 left in the interests of backwards compatibility with such hosts.
	 In all cases, however, hosts MUST send to the ALL-ROUTERS address
	 to be compliant with this specification.
	*/
	if ((ntohl(ip_hdr->ip_dst.s_addr) != INADDR_ALLRTRS_GROUP)
	    && (ip_hdr->ip_dst.s_addr != group_addr.s_addr)) {
		if (PIM_DEBUG_GM_EVENTS)
			zlog_debug(
				"IGMPv2 Leave message is ignored since received on address other than ALL-ROUTERS or Group-address");
		return -1;
	}

	/* Collecting IGMP Rx stats */
	igmp->igmp_stats.leave_v2++;

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
