/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
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

#include <zebra.h>

#include "memory.h"
#include "prefix.h"
#include "if.h"
#include "hash.h"
#include "jhash.h"
#include "lib_errors.h"

#include "pimd.h"
#include "pim_igmp.h"
#include "pim_igmpv2.h"
#include "pim_igmpv3.h"
#include "pim_igmp_mtrace.h"
#include "pim_iface.h"
#include "pim_sock.h"
#include "pim_mroute.h"
#include "pim_str.h"
#include "pim_util.h"
#include "pim_time.h"
#include "pim_zebra.h"

static void group_timer_off(struct igmp_group *group);
static int pim_igmp_general_query(struct thread *t);

/* This socket is used for TXing IGMP packets only, IGMP RX happens
 * in pim_mroute_msg()
 */
static int igmp_sock_open(struct in_addr ifaddr, struct interface *ifp,
			  uint32_t pim_options)
{
	int fd;
	int join = 0;
	struct in_addr group;

	fd = pim_socket_mcast(IPPROTO_IGMP, ifaddr, ifp, 1);

	if (fd < 0)
		return -1;

	if (PIM_IF_TEST_IGMP_LISTEN_ALLROUTERS(pim_options)) {
		if (inet_aton(PIM_ALL_ROUTERS, &group)) {
			if (!pim_socket_join(fd, group, ifaddr, ifp->ifindex))
				++join;
		} else {
			zlog_warn(
				"%s %s: IGMP socket fd=%d interface %s: could not solve %s to group address: errno=%d: %s",
				__FILE__, __PRETTY_FUNCTION__, fd,
				inet_ntoa(ifaddr), PIM_ALL_ROUTERS, errno,
				safe_strerror(errno));
		}
	}

	/*
	  IGMP routers periodically send IGMP general queries to
	  AllSystems=224.0.0.1
	  IGMP routers must receive general queries for querier election.
	*/
	if (inet_aton(PIM_ALL_SYSTEMS, &group)) {
		if (!pim_socket_join(fd, group, ifaddr, ifp->ifindex))
			++join;
	} else {
		zlog_warn(
			"%s %s: IGMP socket fd=%d interface %s: could not solve %s to group address: errno=%d: %s",
			__FILE__, __PRETTY_FUNCTION__, fd, inet_ntoa(ifaddr),
			PIM_ALL_SYSTEMS, errno, safe_strerror(errno));
	}

	if (inet_aton(PIM_ALL_IGMP_ROUTERS, &group)) {
		if (!pim_socket_join(fd, group, ifaddr, ifp->ifindex)) {
			++join;
		}
	} else {
		zlog_warn(
			"%s %s: IGMP socket fd=%d interface %s: could not solve %s to group address: errno=%d: %s",
			__FILE__, __PRETTY_FUNCTION__, fd, inet_ntoa(ifaddr),
			PIM_ALL_IGMP_ROUTERS, errno, safe_strerror(errno));
	}

	if (!join) {
		flog_err_sys(
			EC_LIB_SOCKET,
			"IGMP socket fd=%d could not join any group on interface address %s",
			fd, inet_ntoa(ifaddr));
		close(fd);
		fd = -1;
	}

	return fd;
}

#undef IGMP_SOCK_DUMP

#ifdef IGMP_SOCK_DUMP
static void igmp_sock_dump(array_t *igmp_sock_array)
{
	int size = array_size(igmp_sock_array);
	for (int i = 0; i < size; ++i) {

		struct igmp_sock *igmp = array_get(igmp_sock_array, i);

		zlog_debug("%s %s: [%d/%d] igmp_addr=%s fd=%d", __FILE__,
			   __PRETTY_FUNCTION__, i, size,
			   inet_ntoa(igmp->ifaddr), igmp->fd);
	}
}
#endif

struct igmp_sock *pim_igmp_sock_lookup_ifaddr(struct list *igmp_sock_list,
					      struct in_addr ifaddr)
{
	struct listnode *sock_node;
	struct igmp_sock *igmp;

#ifdef IGMP_SOCK_DUMP
	igmp_sock_dump(igmp_sock_list);
#endif

	for (ALL_LIST_ELEMENTS_RO(igmp_sock_list, sock_node, igmp))
		if (ifaddr.s_addr == igmp->ifaddr.s_addr)
			return igmp;

	return 0;
}

struct igmp_sock *igmp_sock_lookup_by_fd(struct list *igmp_sock_list, int fd)
{
	struct listnode *sock_node;
	struct igmp_sock *igmp;

	for (ALL_LIST_ELEMENTS_RO(igmp_sock_list, sock_node, igmp))
		if (fd == igmp->fd)
			return igmp;

	return 0;
}

static int pim_igmp_other_querier_expire(struct thread *t)
{
	struct igmp_sock *igmp;

	igmp = THREAD_ARG(t);

	zassert(!igmp->t_igmp_query_timer);

	if (PIM_DEBUG_IGMP_TRACE) {
		char ifaddr_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<ifaddr?>", igmp->ifaddr, ifaddr_str,
			       sizeof(ifaddr_str));
		zlog_debug("%s: Querier %s resuming", __PRETTY_FUNCTION__,
			   ifaddr_str);
	}

	/*
	  We are the current querier, then
	  re-start sending general queries.
	  RFC 2236 - sec 7 Other Querier
	  present timer expired (Send General
	  Query, Set Gen. Query. timer)
	*/
	pim_igmp_general_query(t);

	return 0;
}

void pim_igmp_other_querier_timer_on(struct igmp_sock *igmp)
{
	long other_querier_present_interval_msec;
	struct pim_interface *pim_ifp;

	zassert(igmp);
	zassert(igmp->interface);
	zassert(igmp->interface->info);

	pim_ifp = igmp->interface->info;

	if (igmp->t_other_querier_timer) {
		/*
		  There is other querier present already,
		  then reset the other-querier-present timer.
		*/

		if (PIM_DEBUG_IGMP_TRACE) {
			char ifaddr_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<ifaddr?>", igmp->ifaddr, ifaddr_str,
				       sizeof(ifaddr_str));
			zlog_debug(
				"Querier %s resetting TIMER event for Other-Querier-Present",
				ifaddr_str);
		}
		THREAD_OFF(igmp->t_other_querier_timer);
	} else {
		/*
		  We are the current querier, then stop sending general queries:
		  igmp->t_igmp_query_timer = NULL;
		*/
		pim_igmp_general_query_off(igmp);
	}

	/*
	  Since this socket is starting the other-querier-present timer,
	  there should not be periodic query timer for this socket.
	 */
	zassert(!igmp->t_igmp_query_timer);

	/*
	  RFC 3376: 8.5. Other Querier Present Interval

	  The Other Querier Present Interval is the length of time that must
	  pass before a multicast router decides that there is no longer
	  another multicast router which should be the querier.  This value
	  MUST be ((the Robustness Variable) times (the Query Interval)) plus
	  (one half of one Query Response Interval).

	  other_querier_present_interval_msec = \
	    igmp->querier_robustness_variable * \
	    1000 * igmp->querier_query_interval + \
	    100 * (pim_ifp->query_max_response_time_dsec >> 1);
	*/
	other_querier_present_interval_msec = PIM_IGMP_OQPI_MSEC(
		igmp->querier_robustness_variable, igmp->querier_query_interval,
		pim_ifp->igmp_query_max_response_time_dsec);

	if (PIM_DEBUG_IGMP_TRACE) {
		char ifaddr_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<ifaddr?>", igmp->ifaddr, ifaddr_str,
			       sizeof(ifaddr_str));
		zlog_debug(
			"Querier %s scheduling %ld.%03ld sec TIMER event for Other-Querier-Present",
			ifaddr_str, other_querier_present_interval_msec / 1000,
			other_querier_present_interval_msec % 1000);
	}

	thread_add_timer_msec(router->master, pim_igmp_other_querier_expire,
			      igmp, other_querier_present_interval_msec,
			      &igmp->t_other_querier_timer);
}

void pim_igmp_other_querier_timer_off(struct igmp_sock *igmp)
{
	zassert(igmp);

	if (PIM_DEBUG_IGMP_TRACE) {
		if (igmp->t_other_querier_timer) {
			char ifaddr_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<ifaddr?>", igmp->ifaddr, ifaddr_str,
				       sizeof(ifaddr_str));
			zlog_debug(
				"IGMP querier %s fd=%d cancelling other-querier-present TIMER event on %s",
				ifaddr_str, igmp->fd, igmp->interface->name);
		}
	}
	THREAD_OFF(igmp->t_other_querier_timer);
}

static int igmp_recv_query(struct igmp_sock *igmp, int query_version,
			   int max_resp_code, struct in_addr from,
			   const char *from_str, char *igmp_msg,
			   int igmp_msg_len)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	struct in_addr group_addr;
	uint16_t recv_checksum;
	uint16_t checksum;

	if (igmp->mtrace_only)
		return 0;

	memcpy(&group_addr, igmp_msg + 4, sizeof(struct in_addr));

	ifp = igmp->interface;
	pim_ifp = ifp->info;

	recv_checksum = *(uint16_t *)(igmp_msg + IGMP_CHECKSUM_OFFSET);

	/* for computing checksum */
	*(uint16_t *)(igmp_msg + IGMP_CHECKSUM_OFFSET) = 0;

	checksum = in_cksum(igmp_msg, igmp_msg_len);
	if (checksum != recv_checksum) {
		zlog_warn(
			"Recv IGMP query v%d from %s on %s: checksum mismatch: received=%x computed=%x",
			query_version, from_str, ifp->name, recv_checksum,
			checksum);
		return -1;
	}

	if (!pim_if_connected_to_source(ifp, from)) {
		if (PIM_DEBUG_IGMP_PACKETS)
			zlog_debug("Recv IGMP query on interface: %s from a non-connected source: %s",
				   ifp->name, from_str);
		return 0;
	}

	if (if_lookup_address(&from, AF_INET, ifp->vrf_id)) {
		if (PIM_DEBUG_IGMP_PACKETS)
			zlog_debug("Recv IGMP query on interface: %s from ourself %s",
				   ifp->name, from_str);
		return 0;
	}

	/* Collecting IGMP Rx stats */
	switch (query_version) {
	case 1:
		igmp->rx_stats.query_v1++;
		break;
	case 2:
		igmp->rx_stats.query_v2++;
		break;
	case 3:
		igmp->rx_stats.query_v3++;
		break;
	default:
		igmp->rx_stats.unsupported++;
	}

	/*
	 * RFC 3376 defines some guidelines on operating in backwards
	 * compatibility with older versions of IGMP but there are some gaps in
	 * the logic:
	 *
	 * - once we drop from say version 3 to version 2 we will never go back
	 *   to version 3 even if the node that TXed an IGMP v2 query upgrades
	 *   to v3
	 *
	 * - The node with the lowest IP is the querier so we will only know to
	 *   drop from v3 to v2 if the node that is the querier is also the one
	 *   that is running igmp v2.  If a non-querier only supports igmp v2
	 *   we will have no way of knowing.
	 *
	 * For now we will simplify things and inform the user that they need to
	 * configure all PIM routers to use the same version of IGMP.
	 */
	if (query_version != pim_ifp->igmp_version) {
		zlog_warn(
			"Recv IGMP query v%d from %s on %s but we are using v%d, please "
			"configure all PIM routers on this subnet to use the same "
			"IGMP version",
			query_version, from_str, ifp->name,
			pim_ifp->igmp_version);
		return 0;
	}

	if (PIM_DEBUG_IGMP_PACKETS) {
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group_addr, group_str,
			       sizeof(group_str));
		zlog_debug("Recv IGMP query v%d from %s on %s for group %s",
			   query_version, from_str, ifp->name, group_str);
	}

	/*
	  RFC 3376: 6.6.2. Querier Election

	  When a router receives a query with a lower IP address, it sets
	  the Other-Querier-Present timer to Other Querier Present Interval
	  and ceases to send queries on the network if it was the previously
	  elected querier.
	 */
	if (ntohl(from.s_addr) < ntohl(igmp->ifaddr.s_addr)) {

		if (PIM_DEBUG_IGMP_TRACE) {
			char ifaddr_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<ifaddr?>", igmp->ifaddr, ifaddr_str,
				       sizeof(ifaddr_str));
			zlog_debug(
				"%s: local address %s (%u) lost querier election to %s (%u)",
				ifp->name, ifaddr_str,
				ntohl(igmp->ifaddr.s_addr), from_str,
				ntohl(from.s_addr));
		}

		pim_igmp_other_querier_timer_on(igmp);
	}

	/* IGMP version 3 is the only one where we process the RXed query */
	if (query_version == 3) {
		igmp_v3_recv_query(igmp, from_str, igmp_msg);
	}

	return 0;
}

static void on_trace(const char *label, struct interface *ifp,
		     struct in_addr from)
{
	if (PIM_DEBUG_IGMP_TRACE) {
		char from_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<from?>", from, from_str, sizeof(from_str));
		zlog_debug("%s: from %s on %s", label, from_str, ifp->name);
	}
}

static int igmp_v1_recv_report(struct igmp_sock *igmp, struct in_addr from,
			       const char *from_str, char *igmp_msg,
			       int igmp_msg_len)
{
	struct interface *ifp = igmp->interface;
	struct igmp_group *group;
	struct in_addr group_addr;

	on_trace(__PRETTY_FUNCTION__, igmp->interface, from);

	if (igmp->mtrace_only)
		return 0;

	if (igmp_msg_len != IGMP_V12_MSG_SIZE) {
		zlog_warn(
			"Recv IGMP report v1 from %s on %s: size=%d other than correct=%d",
			from_str, ifp->name, igmp_msg_len, IGMP_V12_MSG_SIZE);
		return -1;
	}

	/* Collecting IGMP Rx stats */
	igmp->rx_stats.report_v1++;

	if (PIM_DEBUG_IGMP_TRACE) {
		zlog_warn("%s %s: FIXME WRITEME", __FILE__,
			  __PRETTY_FUNCTION__);
	}

	memcpy(&group_addr, igmp_msg + 4, sizeof(struct in_addr));

	if (pim_is_group_filtered(ifp->info, &group_addr))
		return -1;

	/* non-existant group is created as INCLUDE {empty} */
	group = igmp_add_group_by_addr(igmp, group_addr);
	if (!group) {
		return -1;
	}

	group->last_igmp_v1_report_dsec = pim_time_monotonic_dsec();

	return 0;
}

int pim_igmp_packet(struct igmp_sock *igmp, char *buf, size_t len)
{
	struct ip *ip_hdr;
	size_t ip_hlen; /* ip header length in bytes */
	char *igmp_msg;
	int igmp_msg_len;
	int msg_type;
	char from_str[INET_ADDRSTRLEN];
	char to_str[INET_ADDRSTRLEN];

	if (len < sizeof(*ip_hdr)) {
		zlog_warn("IGMP packet size=%zu shorter than minimum=%zu", len,
			  sizeof(*ip_hdr));
		return -1;
	}

	ip_hdr = (struct ip *)buf;

	pim_inet4_dump("<src?>", ip_hdr->ip_src, from_str, sizeof(from_str));
	pim_inet4_dump("<dst?>", ip_hdr->ip_dst, to_str, sizeof(to_str));

	ip_hlen = ip_hdr->ip_hl << 2; /* ip_hl gives length in 4-byte words */

	igmp_msg = buf + ip_hlen;
	msg_type = *igmp_msg;
	igmp_msg_len = len - ip_hlen;

	if (PIM_DEBUG_IGMP_PACKETS) {
		zlog_debug(
			"Recv IGMP packet from %s to %s on %s: size=%zu ttl=%d msg_type=%d msg_size=%d",
			from_str, to_str, igmp->interface->name, len, ip_hdr->ip_ttl,
			msg_type, igmp_msg_len);
	}

	if (igmp_msg_len < PIM_IGMP_MIN_LEN) {
		zlog_warn("IGMP message size=%d shorter than minimum=%d",
			  igmp_msg_len, PIM_IGMP_MIN_LEN);
		return -1;
	}

	switch (msg_type) {
	case PIM_IGMP_MEMBERSHIP_QUERY: {
		int max_resp_code = igmp_msg[1];
		int query_version;

		/*
		  RFC 3376: 7.1. Query Version Distinctions
		  IGMPv1 Query: length = 8 octets AND Max Resp Code field is
		  zero
		  IGMPv2 Query: length = 8 octets AND Max Resp Code field is
		  non-zero
		  IGMPv3 Query: length >= 12 octets
		*/

		if (igmp_msg_len == 8) {
			query_version = max_resp_code ? 2 : 1;
		} else if (igmp_msg_len >= 12) {
			query_version = 3;
		} else {
			zlog_warn("Unknown IGMP query version");
			return -1;
		}

		return igmp_recv_query(igmp, query_version, max_resp_code,
				       ip_hdr->ip_src, from_str, igmp_msg,
				       igmp_msg_len);
	}

	case PIM_IGMP_V3_MEMBERSHIP_REPORT:
		return igmp_v3_recv_report(igmp, ip_hdr->ip_src, from_str,
					   igmp_msg, igmp_msg_len);

	case PIM_IGMP_V2_MEMBERSHIP_REPORT:
		return igmp_v2_recv_report(igmp, ip_hdr->ip_src, from_str,
					   igmp_msg, igmp_msg_len);

	case PIM_IGMP_V1_MEMBERSHIP_REPORT:
		return igmp_v1_recv_report(igmp, ip_hdr->ip_src, from_str,
					   igmp_msg, igmp_msg_len);

	case PIM_IGMP_V2_LEAVE_GROUP:
		return igmp_v2_recv_leave(igmp, ip_hdr->ip_src, from_str,
					  igmp_msg, igmp_msg_len);

	case PIM_IGMP_MTRACE_RESPONSE:
		return igmp_mtrace_recv_response(igmp, ip_hdr, ip_hdr->ip_src,
						 from_str, igmp_msg,
						 igmp_msg_len);
	case PIM_IGMP_MTRACE_QUERY_REQUEST:
		return igmp_mtrace_recv_qry_req(igmp, ip_hdr, ip_hdr->ip_src,
						from_str, igmp_msg,
						igmp_msg_len);
	}

	zlog_warn("Ignoring unsupported IGMP message type: %d", msg_type);

	/* Collecting IGMP Rx stats */
	igmp->rx_stats.unsupported++;

	return -1;
}

void pim_igmp_general_query_on(struct igmp_sock *igmp)
{
	struct pim_interface *pim_ifp;
	int startup_mode;
	int query_interval;

	/*
	  Since this socket is starting as querier,
	  there should not exist a timer for other-querier-present.
	 */
	zassert(!igmp->t_other_querier_timer);
	pim_ifp = igmp->interface->info;
	zassert(pim_ifp);

	/*
	  RFC 3376: 8.6. Startup Query Interval

	  The Startup Query Interval is the interval between General Queries
	  sent by a Querier on startup.  Default: 1/4 the Query Interval.
	  The first one should be sent out immediately instead of 125/4
	  seconds from now.
	*/
	startup_mode = igmp->startup_query_count > 0;
	if (startup_mode) {
		/*
		 * If this is the first time we are sending a query on a
		 * newly configured igmp interface send it out in 1 second
		 * just to give the entire world a tiny bit of time to settle
		 * else the query interval is:
		 * query_interval = pim_ifp->igmp_default_query_interval >> 2;
		 */
		if (igmp->startup_query_count
		    == igmp->querier_robustness_variable)
			query_interval = 1;
		else
			query_interval = PIM_IGMP_SQI(
				pim_ifp->igmp_default_query_interval);

		--igmp->startup_query_count;
	} else {
		query_interval = igmp->querier_query_interval;
	}

	if (PIM_DEBUG_IGMP_TRACE) {
		char ifaddr_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<ifaddr?>", igmp->ifaddr, ifaddr_str,
			       sizeof(ifaddr_str));
		zlog_debug(
			"Querier %s scheduling %d-second (%s) TIMER event for IGMP query on fd=%d",
			ifaddr_str, query_interval,
			startup_mode ? "startup" : "non-startup", igmp->fd);
	}
	igmp->t_igmp_query_timer = NULL;
	thread_add_timer(router->master, pim_igmp_general_query, igmp,
			 query_interval, &igmp->t_igmp_query_timer);
}

void pim_igmp_general_query_off(struct igmp_sock *igmp)
{
	zassert(igmp);

	if (PIM_DEBUG_IGMP_TRACE) {
		if (igmp->t_igmp_query_timer) {
			char ifaddr_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<ifaddr?>", igmp->ifaddr, ifaddr_str,
				       sizeof(ifaddr_str));
			zlog_debug(
				"IGMP querier %s fd=%d cancelling query TIMER event on %s",
				ifaddr_str, igmp->fd, igmp->interface->name);
		}
	}
	THREAD_OFF(igmp->t_igmp_query_timer);
}

/* Issue IGMP general query */
static int pim_igmp_general_query(struct thread *t)
{
	struct igmp_sock *igmp;
	struct in_addr dst_addr;
	struct in_addr group_addr;
	struct pim_interface *pim_ifp;
	int query_buf_size;

	igmp = THREAD_ARG(t);

	zassert(igmp->interface);
	zassert(igmp->interface->info);

	pim_ifp = igmp->interface->info;

	if (pim_ifp->igmp_version == 3) {
		query_buf_size = PIM_IGMP_BUFSIZE_WRITE;
	} else {
		query_buf_size = IGMP_V12_MSG_SIZE;
	}

	char query_buf[query_buf_size];

	/*
	  RFC3376: 4.1.12. IP Destination Addresses for Queries

	  In IGMPv3, General Queries are sent with an IP destination address
	  of 224.0.0.1, the all-systems multicast address.  Group-Specific
	  and Group-and-Source-Specific Queries are sent with an IP
	  destination address equal to the multicast address of interest.
	*/

	dst_addr.s_addr = htonl(INADDR_ALLHOSTS_GROUP);
	group_addr.s_addr = PIM_NET_INADDR_ANY;

	if (PIM_DEBUG_IGMP_TRACE) {
		char querier_str[INET_ADDRSTRLEN];
		char dst_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<querier?>", igmp->ifaddr, querier_str,
			       sizeof(querier_str));
		pim_inet4_dump("<dst?>", dst_addr, dst_str, sizeof(dst_str));
		zlog_debug("Querier %s issuing IGMP general query to %s on %s",
			   querier_str, dst_str, igmp->interface->name);
	}

	igmp_send_query(pim_ifp->igmp_version, 0 /* igmp_group */, igmp->fd,
			igmp->interface->name, query_buf, sizeof(query_buf),
			0 /* num_sources */, dst_addr, group_addr,
			pim_ifp->igmp_query_max_response_time_dsec,
			1 /* s_flag: always set for general queries */,
			igmp->querier_robustness_variable,
			igmp->querier_query_interval);

	pim_igmp_general_query_on(igmp);

	return 0;
}

static void sock_close(struct igmp_sock *igmp)
{
	pim_igmp_other_querier_timer_off(igmp);
	pim_igmp_general_query_off(igmp);

	if (PIM_DEBUG_IGMP_TRACE_DETAIL) {
		if (igmp->t_igmp_read) {
			zlog_debug(
				"Cancelling READ event on IGMP socket %s fd=%d on interface %s",
				inet_ntoa(igmp->ifaddr), igmp->fd,
				igmp->interface->name);
		}
	}
	THREAD_OFF(igmp->t_igmp_read);

	if (close(igmp->fd)) {
		flog_err(
			EC_LIB_SOCKET,
			"Failure closing IGMP socket %s fd=%d on interface %s: errno=%d: %s",
			inet_ntoa(igmp->ifaddr), igmp->fd,
			igmp->interface->name, errno, safe_strerror(errno));
	}

	if (PIM_DEBUG_IGMP_TRACE_DETAIL) {
		zlog_debug("Deleted IGMP socket %s fd=%d on interface %s",
			   inet_ntoa(igmp->ifaddr), igmp->fd,
			   igmp->interface->name);
	}
}

void igmp_startup_mode_on(struct igmp_sock *igmp)
{
	struct pim_interface *pim_ifp;

	pim_ifp = igmp->interface->info;

	/*
	  RFC 3376: 8.7. Startup Query Count

	  The Startup Query Count is the number of Queries sent out on
	  startup, separated by the Startup Query Interval.  Default: the
	  Robustness Variable.
	*/
	igmp->startup_query_count = igmp->querier_robustness_variable;

	/*
	  Since we're (re)starting, reset QQI to default Query Interval
	*/
	igmp->querier_query_interval = pim_ifp->igmp_default_query_interval;
}

static void igmp_group_free(struct igmp_group *group)
{
	list_delete(&group->group_source_list);

	XFREE(MTYPE_PIM_IGMP_GROUP, group);
}

void igmp_group_delete(struct igmp_group *group)
{
	struct listnode *src_node;
	struct listnode *src_nextnode;
	struct igmp_source *src;

	if (PIM_DEBUG_IGMP_TRACE) {
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		zlog_debug("Deleting IGMP group %s from socket %d interface %s",
			   group_str, group->group_igmp_sock->fd,
			   group->group_igmp_sock->interface->name);
	}

	for (ALL_LIST_ELEMENTS(group->group_source_list, src_node, src_nextnode,
			       src)) {
		igmp_source_delete(src);
	}

	if (group->t_group_query_retransmit_timer) {
		THREAD_OFF(group->t_group_query_retransmit_timer);
	}

	group_timer_off(group);
	listnode_delete(group->group_igmp_sock->igmp_group_list, group);
	hash_release(group->group_igmp_sock->igmp_group_hash, group);

	igmp_group_free(group);
}

void igmp_group_delete_empty_include(struct igmp_group *group)
{
	zassert(!group->group_filtermode_isexcl);
	zassert(!listcount(group->group_source_list));

	igmp_group_delete(group);
}

void igmp_sock_free(struct igmp_sock *igmp)
{
	zassert(!igmp->t_igmp_read);
	zassert(!igmp->t_igmp_query_timer);
	zassert(!igmp->t_other_querier_timer);
	zassert(igmp->igmp_group_list);
	zassert(!listcount(igmp->igmp_group_list));

	list_delete(&igmp->igmp_group_list);
	hash_free(igmp->igmp_group_hash);

	XFREE(MTYPE_PIM_IGMP_SOCKET, igmp);
}

void igmp_sock_delete(struct igmp_sock *igmp)
{
	struct pim_interface *pim_ifp;
	struct listnode *grp_node;
	struct listnode *grp_nextnode;
	struct igmp_group *grp;

	for (ALL_LIST_ELEMENTS(igmp->igmp_group_list, grp_node, grp_nextnode,
			       grp)) {
		igmp_group_delete(grp);
	}

	sock_close(igmp);

	pim_ifp = igmp->interface->info;

	listnode_delete(pim_ifp->igmp_socket_list, igmp);

	igmp_sock_free(igmp);
}

void igmp_sock_delete_all(struct interface *ifp)
{
	struct pim_interface *pim_ifp;
	struct listnode *igmp_node, *igmp_nextnode;
	struct igmp_sock *igmp;

	pim_ifp = ifp->info;

	for (ALL_LIST_ELEMENTS(pim_ifp->igmp_socket_list, igmp_node,
			       igmp_nextnode, igmp)) {
		igmp_sock_delete(igmp);
	}
}

static unsigned int igmp_group_hash_key(const void *arg)
{
	const struct igmp_group *group = arg;

	return jhash_1word(group->group_addr.s_addr, 0);
}

static bool igmp_group_hash_equal(const void *arg1, const void *arg2)
{
	const struct igmp_group *g1 = (const struct igmp_group *)arg1;
	const struct igmp_group *g2 = (const struct igmp_group *)arg2;

	if (g1->group_addr.s_addr == g2->group_addr.s_addr)
		return true;

	return false;
}

static struct igmp_sock *igmp_sock_new(int fd, struct in_addr ifaddr,
				       struct interface *ifp, int mtrace_only)
{
	struct pim_interface *pim_ifp;
	struct igmp_sock *igmp;
	char hash_name[64];

	pim_ifp = ifp->info;

	if (PIM_DEBUG_IGMP_TRACE) {
		zlog_debug(
			"Creating IGMP socket fd=%d for address %s on interface %s",
			fd, inet_ntoa(ifaddr), ifp->name);
	}

	igmp = XCALLOC(MTYPE_PIM_IGMP_SOCKET, sizeof(*igmp));

	igmp->igmp_group_list = list_new();
	igmp->igmp_group_list->del = (void (*)(void *))igmp_group_free;

	snprintf(hash_name, 64, "IGMP %s hash", ifp->name);
	igmp->igmp_group_hash = hash_create(igmp_group_hash_key,
					    igmp_group_hash_equal, hash_name);

	igmp->fd = fd;
	igmp->interface = ifp;
	igmp->ifaddr = ifaddr;
	igmp->t_igmp_read = NULL;
	igmp->t_igmp_query_timer = NULL;
	igmp->t_other_querier_timer = NULL; /* no other querier present */
	igmp->querier_robustness_variable =
		pim_ifp->igmp_default_robustness_variable;
	igmp->sock_creation = pim_time_monotonic_sec();

	igmp_stats_init(&igmp->rx_stats);

	if (mtrace_only) {
		igmp->mtrace_only = mtrace_only;
		return igmp;
	}

	igmp->mtrace_only = false;

	/*
	  igmp_startup_mode_on() will reset QQI:

	  igmp->querier_query_interval = pim_ifp->igmp_default_query_interval;
	*/
	igmp_startup_mode_on(igmp);
	pim_igmp_general_query_on(igmp);

	return igmp;
}

static void igmp_read_on(struct igmp_sock *igmp);

static int pim_igmp_read(struct thread *t)
{
	uint8_t buf[10000];
	struct igmp_sock *igmp = (struct igmp_sock *)THREAD_ARG(t);
	struct sockaddr_in from;
	struct sockaddr_in to;
	socklen_t fromlen = sizeof(from);
	socklen_t tolen = sizeof(to);
	ifindex_t ifindex = -1;
	int len;

	while (1) {
		len = pim_socket_recvfromto(igmp->fd, buf, sizeof(buf), &from,
					    &fromlen, &to, &tolen, &ifindex);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;

			goto done;
		}
	}

done:
	igmp_read_on(igmp);
	return 0;
}

static void igmp_read_on(struct igmp_sock *igmp)
{

	if (PIM_DEBUG_IGMP_TRACE_DETAIL) {
		zlog_debug("Scheduling READ event on IGMP socket fd=%d",
			   igmp->fd);
	}
	igmp->t_igmp_read = NULL;
	thread_add_read(router->master, pim_igmp_read, igmp, igmp->fd,
			&igmp->t_igmp_read);
}

struct igmp_sock *pim_igmp_sock_add(struct list *igmp_sock_list,
				    struct in_addr ifaddr,
				    struct interface *ifp,
				    bool mtrace_only)
{
	struct pim_interface *pim_ifp;
	struct igmp_sock *igmp;
	int fd;

	pim_ifp = ifp->info;

	fd = igmp_sock_open(ifaddr, ifp, pim_ifp->options);
	if (fd < 0) {
		zlog_warn("Could not open IGMP socket for %s on %s",
			  inet_ntoa(ifaddr), ifp->name);
		return 0;
	}

	igmp = igmp_sock_new(fd, ifaddr, ifp, mtrace_only);

	igmp_read_on(igmp);

	listnode_add(igmp_sock_list, igmp);

#ifdef IGMP_SOCK_DUMP
	igmp_sock_dump(igmp_sock_array);
#endif

	return igmp;
}

/*
  RFC 3376: 6.5. Switching Router Filter-Modes

  When a router's filter-mode for a group is EXCLUDE and the group
  timer expires, the router filter-mode for the group transitions to
  INCLUDE.

  A router uses source records with running source timers as its state
  for the switch to a filter-mode of INCLUDE.  If there are any source
  records with source timers greater than zero (i.e., requested to be
  forwarded), a router switches to filter-mode of INCLUDE using those
  source records.  Source records whose timers are zero (from the
  previous EXCLUDE mode) are deleted.
 */
static int igmp_group_timer(struct thread *t)
{
	struct igmp_group *group;

	group = THREAD_ARG(t);

	if (PIM_DEBUG_IGMP_TRACE) {
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		zlog_debug("%s: Timer for group %s on interface %s",
			   __PRETTY_FUNCTION__, group_str,
			   group->group_igmp_sock->interface->name);
	}

	zassert(group->group_filtermode_isexcl);

	group->group_filtermode_isexcl = 0;

	/* Any source (*,G) is forwarded only if mode is EXCLUDE {empty} */
	igmp_anysource_forward_stop(group);

	igmp_source_delete_expired(group->group_source_list);

	zassert(!group->group_filtermode_isexcl);

	/*
	  RFC 3376: 6.2.2. Definition of Group Timers

	  If there are no more source records for the group, delete group
	  record.
	*/
	if (listcount(group->group_source_list) < 1) {
		igmp_group_delete_empty_include(group);
	}

	return 0;
}

static void group_timer_off(struct igmp_group *group)
{
	if (!group->t_group_timer)
		return;

	if (PIM_DEBUG_IGMP_TRACE) {
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		zlog_debug("Cancelling TIMER event for group %s on %s",
			   group_str, group->group_igmp_sock->interface->name);
	}
	THREAD_OFF(group->t_group_timer);
}

void igmp_group_timer_on(struct igmp_group *group, long interval_msec,
			 const char *ifname)
{
	group_timer_off(group);

	if (PIM_DEBUG_IGMP_EVENTS) {
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		zlog_debug(
			"Scheduling %ld.%03ld sec TIMER event for group %s on %s",
			interval_msec / 1000, interval_msec % 1000, group_str,
			ifname);
	}

	/*
	  RFC 3376: 6.2.2. Definition of Group Timers

	  The group timer is only used when a group is in EXCLUDE mode and
	  it represents the time for the *filter-mode* of the group to
	  expire and switch to INCLUDE mode.
	*/
	zassert(group->group_filtermode_isexcl);

	thread_add_timer_msec(router->master, igmp_group_timer, group,
			      interval_msec, &group->t_group_timer);
}

struct igmp_group *find_group_by_addr(struct igmp_sock *igmp,
				      struct in_addr group_addr)
{
	struct igmp_group lookup;

	lookup.group_addr.s_addr = group_addr.s_addr;

	return hash_lookup(igmp->igmp_group_hash, &lookup);
}

struct igmp_group *igmp_add_group_by_addr(struct igmp_sock *igmp,
					  struct in_addr group_addr)
{
	struct igmp_group *group;

	group = find_group_by_addr(igmp, group_addr);
	if (group) {
		return group;
	}

	if (!pim_is_group_224_4(group_addr)) {
		zlog_warn("%s: Group Specified is not part of 224.0.0.0/4",
			  __PRETTY_FUNCTION__);
		return NULL;
	}

	if (pim_is_group_224_0_0_0_24(group_addr)) {
		zlog_warn("%s: Group specified is part of 224.0.0.0/24",
			  __PRETTY_FUNCTION__);
		return NULL;
	}
	/*
	  Non-existant group is created as INCLUDE {empty}:

	  RFC 3376 - 5.1. Action on Change of Interface State

	  If no interface state existed for that multicast address before
	  the change (i.e., the change consisted of creating a new
	  per-interface record), or if no state exists after the change
	  (i.e., the change consisted of deleting a per-interface record),
	  then the "non-existent" state is considered to have a filter mode
	  of INCLUDE and an empty source list.
	*/

	group = XCALLOC(MTYPE_PIM_IGMP_GROUP, sizeof(*group));

	group->group_source_list = list_new();
	group->group_source_list->del = (void (*)(void *))igmp_source_free;

	group->t_group_timer = NULL;
	group->t_group_query_retransmit_timer = NULL;
	group->group_specific_query_retransmit_count = 0;
	group->group_addr = group_addr;
	group->group_igmp_sock = igmp;
	group->last_igmp_v1_report_dsec = -1;
	group->last_igmp_v2_report_dsec = -1;
	group->group_creation = pim_time_monotonic_sec();
	group->igmp_version = IGMP_DEFAULT_VERSION;

	/* initialize new group as INCLUDE {empty} */
	group->group_filtermode_isexcl = 0; /* 0=INCLUDE, 1=EXCLUDE */

	listnode_add(igmp->igmp_group_list, group);
	group = hash_get(igmp->igmp_group_hash, group, hash_alloc_intern);

	if (PIM_DEBUG_IGMP_TRACE) {
		char group_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", group->group_addr, group_str,
			       sizeof(group_str));
		zlog_debug(
			"Creating new IGMP group %s on socket %d interface %s",
			group_str, igmp->fd, igmp->interface->name);
	}

	/*
	  RFC 3376: 6.2.2. Definition of Group Timers

	  The group timer is only used when a group is in EXCLUDE mode and
	  it represents the time for the *filter-mode* of the group to
	  expire and switch to INCLUDE mode.
	*/
	zassert(!group->group_filtermode_isexcl); /* INCLUDE mode */
	zassert(!group->t_group_timer);		  /* group timer == 0 */

	/* Any source (*,G) is forwarded only if mode is EXCLUDE {empty} */
	igmp_anysource_forward_stop(group);

	return group;
}

void igmp_send_query(int igmp_version, struct igmp_group *group, int fd,
		     const char *ifname, char *query_buf, int query_buf_size,
		     int num_sources, struct in_addr dst_addr,
		     struct in_addr group_addr,
		     int query_max_response_time_dsec, uint8_t s_flag,
		     uint8_t querier_robustness_variable,
		     uint16_t querier_query_interval)
{
	if (igmp_version == 3) {
		igmp_v3_send_query(group, fd, ifname, query_buf, query_buf_size,
				   num_sources, dst_addr, group_addr,
				   query_max_response_time_dsec, s_flag,
				   querier_robustness_variable,
				   querier_query_interval);
	} else if (igmp_version == 2) {
		igmp_v2_send_query(group, fd, ifname, query_buf, dst_addr,
				   group_addr, query_max_response_time_dsec);
	}
}

void igmp_send_query_on_intf(struct interface *ifp, int igmp_ver)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct listnode *sock_node = NULL;
	struct igmp_sock *igmp = NULL;
	struct in_addr dst_addr;
	struct in_addr group_addr;
	int query_buf_size;

	if (!igmp_ver)
		igmp_ver = 2;

	if (igmp_ver == 3)
		query_buf_size = PIM_IGMP_BUFSIZE_WRITE;
	else
		query_buf_size = IGMP_V12_MSG_SIZE;

	dst_addr.s_addr = htonl(INADDR_ALLHOSTS_GROUP);
	group_addr.s_addr = PIM_NET_INADDR_ANY;

	if (PIM_DEBUG_IGMP_TRACE)
		zlog_debug("Issuing general query on request on %s",
				ifp->name);

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->igmp_socket_list, sock_node, igmp)) {

		char query_buf[query_buf_size];

		igmp_send_query(igmp_ver, 0 /* igmp_group */, igmp->fd,
				igmp->interface->name, query_buf,
				sizeof(query_buf), 0 /* num_sources */,
				dst_addr, group_addr,
				pim_ifp->igmp_query_max_response_time_dsec,
				1 /* s_flag: always set for general queries */,
				igmp->querier_robustness_variable,
				igmp->querier_query_interval);
	}
}
