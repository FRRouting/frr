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

#include "log.h"
#include "prefix.h"
#include "if.h"
#include "vty.h"
#include "plist.h"

#include "pimd.h"
#include "pim_str.h"
#include "pim_tlv.h"
#include "pim_msg.h"
#include "pim_pim.h"
#include "pim_join.h"
#include "pim_oil.h"
#include "pim_iface.h"
#include "pim_hello.h"
#include "pim_ifchannel.h"
#include "pim_rpf.h"
#include "pim_rp.h"
#include "pim_jp_agg.h"
#include "pim_util.h"

static void on_trace(const char *label, struct interface *ifp,
		     struct in_addr src)
{
	if (PIM_DEBUG_PIM_TRACE) {
		char src_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", src, src_str, sizeof(src_str));
		zlog_debug("%s: from %s on %s", label, src_str, ifp->name);
	}
}

static void recv_join(struct interface *ifp, struct pim_neighbor *neigh,
		      uint16_t holdtime, struct in_addr upstream,
		      struct prefix_sg *sg, uint8_t source_flags)
{
	struct pim_interface *pim_ifp = NULL;

	if (PIM_DEBUG_PIM_TRACE) {
		char up_str[INET_ADDRSTRLEN];
		char neigh_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<upstream?>", upstream, up_str, sizeof(up_str));
		pim_inet4_dump("<neigh?>", neigh->source_addr, neigh_str,
			       sizeof(neigh_str));
		zlog_debug(
			"%s: join (S,G)=%s rpt=%d wc=%d upstream=%s holdtime=%d from %s on %s",
			__PRETTY_FUNCTION__, pim_str_sg_dump(sg),
			!!(source_flags & PIM_RPT_BIT_MASK),
			!!(source_flags & PIM_WILDCARD_BIT_MASK), up_str,
			holdtime, neigh_str, ifp->name);
	}

	pim_ifp = ifp->info;
	zassert(pim_ifp);

	++pim_ifp->pim_ifstat_join_recv;

	/*
	 * If the RPT and WC are set it's a (*,G)
	 * and the source is the RP
	 */
	if ((source_flags & PIM_RPT_BIT_MASK)
	    && (source_flags & PIM_WILDCARD_BIT_MASK)) {
		struct pim_rpf *rp = RP(pim_ifp->pim, sg->grp);

		/*
		 * If the RP sent in the message is not
		 * our RP for the group, drop the message
		 */
		if (sg->src.s_addr != rp->rpf_addr.u.prefix4.s_addr) {
			char received_rp[INET_ADDRSTRLEN];
			char local_rp[INET_ADDRSTRLEN];
			pim_inet4_dump("<received?>", sg->src, received_rp,
				       sizeof(received_rp));
			pim_inet4_dump("<local?>", rp->rpf_addr.u.prefix4,
				       local_rp, sizeof(local_rp));
			zlog_warn("%s: Specified RP(%s) in join is different than our configured RP(%s)",
				  __PRETTY_FUNCTION__, received_rp, local_rp);
			return;
		}

		sg->src.s_addr = INADDR_ANY;
	}

	/* Restart join expiry timer */
	pim_ifchannel_join_add(ifp, neigh->source_addr, upstream, sg,
			       source_flags, holdtime);
}

static void recv_prune(struct interface *ifp, struct pim_neighbor *neigh,
		       uint16_t holdtime, struct in_addr upstream,
		       struct prefix_sg *sg, uint8_t source_flags)
{
	struct pim_interface *pim_ifp = NULL;

	if (PIM_DEBUG_PIM_TRACE) {
		char up_str[INET_ADDRSTRLEN];
		char neigh_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<upstream?>", upstream, up_str, sizeof(up_str));
		pim_inet4_dump("<neigh?>", neigh->source_addr, neigh_str,
			       sizeof(neigh_str));
		zlog_debug(
			"%s: prune (S,G)=%s rpt=%d wc=%d upstream=%s holdtime=%d from %s on %s",
			__PRETTY_FUNCTION__, pim_str_sg_dump(sg),
			source_flags & PIM_RPT_BIT_MASK,
			source_flags & PIM_WILDCARD_BIT_MASK, up_str, holdtime,
			neigh_str, ifp->name);
	}

	pim_ifp = ifp->info;
	zassert(pim_ifp);

	++pim_ifp->pim_ifstat_prune_recv;

	if ((source_flags & PIM_RPT_BIT_MASK)
	    && (source_flags & PIM_WILDCARD_BIT_MASK)) {
		struct pim_rpf *rp = RP(pim_ifp->pim, sg->grp);

		// Ignoring Prune *,G's at the moment.
		if (sg->src.s_addr != rp->rpf_addr.u.prefix4.s_addr)
			return;

		sg->src.s_addr = INADDR_ANY;
	}

	pim_ifchannel_prune(ifp, upstream, sg, source_flags, holdtime);
}

int pim_joinprune_recv(struct interface *ifp, struct pim_neighbor *neigh,
		       struct in_addr src_addr, uint8_t *tlv_buf,
		       int tlv_buf_size)
{
	struct prefix msg_upstream_addr;
	struct pim_interface *pim_ifp;
	uint8_t msg_num_groups;
	uint16_t msg_holdtime;
	int addr_offset;
	uint8_t *buf;
	uint8_t *pastend;
	int remain;
	int group;

	buf = tlv_buf;
	pastend = tlv_buf + tlv_buf_size;
	pim_ifp = ifp->info;

	/*
	  Parse ucast addr
	*/
	addr_offset =
		pim_parse_addr_ucast(&msg_upstream_addr, buf, pastend - buf);
	if (addr_offset < 1) {
		char src_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", src_addr, src_str, sizeof(src_str));
		zlog_warn("%s: pim_parse_addr_ucast() failure: from %s on %s",
			  __PRETTY_FUNCTION__, src_str, ifp->name);
		return -1;
	}
	buf += addr_offset;

	/*
	  Check upstream address family
	 */
	if (msg_upstream_addr.family != AF_INET) {
		char src_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", src_addr, src_str, sizeof(src_str));
		zlog_warn("%s: ignoring join/prune directed to unexpected addr family=%d from %s on %s",
			  __PRETTY_FUNCTION__, msg_upstream_addr.family,
			  src_str, ifp->name);
		return -2;
	}

	remain = pastend - buf;
	if (remain < 4) {
		char src_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", src_addr, src_str, sizeof(src_str));
		zlog_warn(
			"%s: short join/prune message buffer for group list: size=%d minimum=%d from %s on %s",
			__PRETTY_FUNCTION__, remain, 4, src_str, ifp->name);
		return -4;
	}

	++buf; /* skip reserved byte */
	msg_num_groups = *(const uint8_t *)buf;
	++buf;
	msg_holdtime = ntohs(*(const uint16_t *)buf);
	++buf;
	++buf;

	if (PIM_DEBUG_PIM_J_P) {
		char src_str[INET_ADDRSTRLEN];
		char upstream_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", src_addr, src_str, sizeof(src_str));
		pim_inet4_dump("<addr?>", msg_upstream_addr.u.prefix4,
			       upstream_str, sizeof(upstream_str));
		zlog_debug(
			"%s: join/prune upstream=%s groups=%d holdtime=%d from %s on %s",
			__PRETTY_FUNCTION__, upstream_str, msg_num_groups,
			msg_holdtime, src_str, ifp->name);
	}

	/* Scan groups */
	for (group = 0; group < msg_num_groups; ++group) {
		struct prefix_sg sg;
		uint8_t msg_source_flags;
		uint16_t msg_num_joined_sources;
		uint16_t msg_num_pruned_sources;
		int source;
		struct pim_ifchannel *starg_ch = NULL, *sg_ch = NULL;
		bool filtered = false;

		memset(&sg, 0, sizeof(struct prefix_sg));
		addr_offset = pim_parse_addr_group(&sg, buf, pastend - buf);
		if (addr_offset < 1) {
			return -5;
		}
		buf += addr_offset;

		remain = pastend - buf;
		if (remain < 4) {
			char src_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<src?>", src_addr, src_str,
				       sizeof(src_str));
			zlog_warn(
				"%s: short join/prune buffer for source list: size=%d minimum=%d from %s on %s",
				__PRETTY_FUNCTION__, remain, 4, src_str,
				ifp->name);
			return -6;
		}

		msg_num_joined_sources = ntohs(*(const uint16_t *)buf);
		buf += 2;
		msg_num_pruned_sources = ntohs(*(const uint16_t *)buf);
		buf += 2;

		if (PIM_DEBUG_PIM_J_P) {
			char src_str[INET_ADDRSTRLEN];
			char upstream_str[INET_ADDRSTRLEN];
			char group_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<src?>", src_addr, src_str,
				       sizeof(src_str));
			pim_inet4_dump("<addr?>", msg_upstream_addr.u.prefix4,
				       upstream_str, sizeof(upstream_str));
			pim_inet4_dump("<grp?>", sg.grp, group_str,
				       sizeof(group_str));
			zlog_debug(
				"%s: join/prune upstream=%s group=%s/32 join_src=%d prune_src=%d from %s on %s",
				__PRETTY_FUNCTION__, upstream_str, group_str,
				msg_num_joined_sources, msg_num_pruned_sources,
				src_str, ifp->name);
		}

		/* boundary check */
		filtered = pim_is_group_filtered(pim_ifp, &sg.grp);

		/* Scan joined sources */
		for (source = 0; source < msg_num_joined_sources; ++source) {
			addr_offset = pim_parse_addr_source(
				&sg, &msg_source_flags, buf, pastend - buf);
			if (addr_offset < 1) {
				return -7;
			}

			buf += addr_offset;

			/* if we are filtering this group, skip the join */
			if (filtered)
				continue;

			recv_join(ifp, neigh, msg_holdtime,
				  msg_upstream_addr.u.prefix4, &sg,
				  msg_source_flags);

			if (sg.src.s_addr == INADDR_ANY) {
				starg_ch = pim_ifchannel_find(ifp, &sg);
				if (starg_ch)
					pim_ifchannel_set_star_g_join_state(
						starg_ch, 0, 1);
			}
		}

		/* Scan pruned sources */
		for (source = 0; source < msg_num_pruned_sources; ++source) {
			addr_offset = pim_parse_addr_source(
				&sg, &msg_source_flags, buf, pastend - buf);
			if (addr_offset < 1) {
				return -8;
			}

			buf += addr_offset;

			/* if we are filtering this group, skip the prune */
			if (filtered)
				continue;

			recv_prune(ifp, neigh, msg_holdtime,
				   msg_upstream_addr.u.prefix4, &sg,
				   msg_source_flags);

			/*
			 * So if we are receiving a S,G,RPT prune
			 * before we have any data for that S,G
			 * We need to retrieve the sg_ch after
			 * we parse the prune.
			 */
			sg_ch = pim_ifchannel_find(ifp, &sg);

			/* Received SG-RPT Prune delete oif from specific S,G */
			if (starg_ch && sg_ch
			    && (msg_source_flags & PIM_RPT_BIT_MASK)
			    && !(msg_source_flags & PIM_WILDCARD_BIT_MASK)) {
				struct pim_upstream *up = sg_ch->upstream;
				PIM_IF_FLAG_SET_S_G_RPT(sg_ch->flags);
				if (up) {
					if (PIM_DEBUG_TRACE)
						zlog_debug(
							"%s: SGRpt flag is set, del inherit oif from up %s",
							__PRETTY_FUNCTION__,
							up->sg_str);
					pim_channel_del_oif(
						up->channel_oil,
						starg_ch->interface,
						PIM_OIF_FLAG_PROTO_STAR);
				}
			}
		}
		if (starg_ch && !filtered)
			pim_ifchannel_set_star_g_join_state(starg_ch, 1, 0);
		starg_ch = NULL;
	} /* scan groups */

	return 0;
}

/*
 * J/P Message Format
 *
 * While the RFC clearly states that this is 32 bits wide, it
 * is cheating.  These fields:
 * Encoded-Unicast format   (6 bytes MIN)
 * Encoded-Group format     (8 bytes MIN)
 * Encoded-Source format    (8 bytes MIN)
 * are *not* 32 bits wide.
 *
 * Nor does the RFC explicitly call out the size for:
 * Reserved                 (1 byte)
 * Num Groups               (1 byte)
 * Holdtime                 (2 bytes)
 * Number of Joined Sources (2 bytes)
 * Number of Pruned Sources (2 bytes)
 *
 * This leads to a missleading representation from casual
 * reading and making assumptions.  Be careful!
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |PIM Ver| Type  |   Reserved    |           Checksum            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Upstream Neighbor Address (Encoded-Unicast format)     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Reserved     | Num groups    |          Holdtime             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Multicast Group Address 1 (Encoded-Group format)      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Number of Joined Sources    |   Number of Pruned Sources    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Joined Source Address 1 (Encoded-Source format)        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                             .                                 |
 *  |                             .                                 |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Joined Source Address n (Encoded-Source format)        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Pruned Source Address 1 (Encoded-Source format)        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                             .                                 |
 *  |                             .                                 |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Pruned Source Address n (Encoded-Source format)        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Multicast Group Address m (Encoded-Group format)      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Number of Joined Sources    |   Number of Pruned Sources    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Joined Source Address 1 (Encoded-Source format)        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                             .                                 |
 *  |                             .                                 |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Joined Source Address n (Encoded-Source format)        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Pruned Source Address 1 (Encoded-Source format)        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                             .                                 |
 *  |                             .                                 |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Pruned Source Address n (Encoded-Source format)        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
int pim_joinprune_send(struct pim_rpf *rpf, struct list *groups)
{
	struct pim_jp_agg_group *group;
	struct pim_interface *pim_ifp = NULL;
	struct pim_jp_groups *grp = NULL;
	struct pim_jp *msg = NULL;
	struct listnode *node, *nnode;
	uint8_t pim_msg[10000];
	uint8_t *curr_ptr = pim_msg;
	bool new_packet = true;
	size_t packet_left = 0;
	size_t packet_size = 0;
	size_t group_size = 0;

	if (rpf->source_nexthop.interface)
		pim_ifp = rpf->source_nexthop.interface->info;
	else {
		zlog_warn("%s: RPF interface is not present",
			  __PRETTY_FUNCTION__);
		return -1;
	}

	on_trace(__PRETTY_FUNCTION__, rpf->source_nexthop.interface,
		rpf->rpf_addr.u.prefix4);

	if (!pim_ifp) {
		zlog_warn("%s: multicast not enabled on interface %s",
			  __PRETTY_FUNCTION__,
			  rpf->source_nexthop.interface->name);
		return -1;
	}

	if (PIM_INADDR_IS_ANY(rpf->rpf_addr.u.prefix4)) {
		if (PIM_DEBUG_PIM_J_P) {
			char dst_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<dst?>", rpf->rpf_addr.u.prefix4,
				       dst_str, sizeof(dst_str));
			zlog_debug("%s: upstream=%s is myself on interface %s",
				   __PRETTY_FUNCTION__, dst_str,
				   rpf->source_nexthop.interface->name);
		}
		return 0;
	}

	/*
	  RFC 4601: 4.3.1.  Sending Hello Messages

	  Thus, if a router needs to send a Join/Prune or Assert message on
	  an interface on which it has not yet sent a Hello message with the
	  currently configured IP address, then it MUST immediately send the
	  relevant Hello message without waiting for the Hello Timer to
	  expire, followed by the Join/Prune or Assert message.
	*/
	pim_hello_require(rpf->source_nexthop.interface);

	for (ALL_LIST_ELEMENTS(groups, node, nnode, group)) {
		if (new_packet) {
			msg = (struct pim_jp *)pim_msg;

			memset(msg, 0, sizeof(*msg));

			pim_msg_addr_encode_ipv4_ucast((uint8_t *)&msg->addr,
						       rpf->rpf_addr.u.prefix4);
			msg->reserved = 0;
			msg->holdtime = htons(PIM_JP_HOLDTIME);

			new_packet = false;

			grp = &msg->groups[0];
			curr_ptr = (uint8_t *)grp;
			packet_size = sizeof(struct pim_msg_header);
			packet_size += sizeof(struct pim_encoded_ipv4_unicast);
			packet_size +=
				4; // reserved (1) + groups (1) + holdtime (2)

			packet_left = rpf->source_nexthop.interface->mtu - 24;
			packet_left -= packet_size;
		}
		if (PIM_DEBUG_PIM_J_P) {
			char dst_str[INET_ADDRSTRLEN];
			char grp_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<dst?>", rpf->rpf_addr.u.prefix4,
				       dst_str, sizeof(dst_str));
			pim_inet4_dump("<grp?>", group->group, grp_str,
				       sizeof(grp_str));
			zlog_debug(
				"%s: sending (G)=%s to upstream=%s on interface %s",
				__PRETTY_FUNCTION__, grp_str, dst_str,
				rpf->source_nexthop.interface->name);
		}

		group_size = pim_msg_get_jp_group_size(group->sources);
		if (group_size > packet_left) {
			pim_msg_build_header(pim_msg, packet_size,
					     PIM_MSG_TYPE_JOIN_PRUNE, false);
			if (pim_msg_send(pim_ifp->pim_sock_fd,
					 pim_ifp->primary_address,
					 qpim_all_pim_routers_addr, pim_msg,
					 packet_size,
					 rpf->source_nexthop.interface->name)) {
				zlog_warn(
					"%s: could not send PIM message on interface %s",
					__PRETTY_FUNCTION__,
					rpf->source_nexthop.interface->name);
			}

			msg = (struct pim_jp *)pim_msg;
			memset(msg, 0, sizeof(*msg));

			pim_msg_addr_encode_ipv4_ucast((uint8_t *)&msg->addr,
						       rpf->rpf_addr.u.prefix4);
			msg->reserved = 0;
			msg->holdtime = htons(PIM_JP_HOLDTIME);

			new_packet = false;

			grp = &msg->groups[0];
			curr_ptr = (uint8_t *)grp;
			packet_size = sizeof(struct pim_msg_header);
			packet_size += sizeof(struct pim_encoded_ipv4_unicast);
			packet_size +=
				4; // reserved (1) + groups (1) + holdtime (2)

			packet_left = rpf->source_nexthop.interface->mtu - 24;
			packet_left -= packet_size;
		}

		msg->num_groups++;
		/*
		  Build PIM message
		*/

		curr_ptr += group_size;
		packet_left -= group_size;
		packet_size += group_size;
		pim_msg_build_jp_groups(grp, group, group_size);

		pim_ifp->pim_ifstat_join_send += ntohs(grp->joins);
		pim_ifp->pim_ifstat_prune_send += ntohs(grp->prunes);

		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"%s: interface %s num_joins %u num_prunes %u",
				__PRETTY_FUNCTION__,
				rpf->source_nexthop.interface->name,
				ntohs(grp->joins), ntohs(grp->prunes));

		grp = (struct pim_jp_groups *)curr_ptr;
		if (packet_left < sizeof(struct pim_jp_groups)
		    || msg->num_groups == 255) {
			pim_msg_build_header(pim_msg, packet_size,
					     PIM_MSG_TYPE_JOIN_PRUNE, false);
			if (pim_msg_send(pim_ifp->pim_sock_fd,
					 pim_ifp->primary_address,
					 qpim_all_pim_routers_addr, pim_msg,
					 packet_size,
					 rpf->source_nexthop.interface->name)) {
				zlog_warn(
					"%s: could not send PIM message on interface %s",
					__PRETTY_FUNCTION__,
					rpf->source_nexthop.interface->name);
			}

			new_packet = true;
		}
	}


	if (!new_packet) {
		// msg->num_groups = htons (msg->num_groups);
		pim_msg_build_header(pim_msg, packet_size,
				     PIM_MSG_TYPE_JOIN_PRUNE, false);
		if (pim_msg_send(pim_ifp->pim_sock_fd, pim_ifp->primary_address,
				 qpim_all_pim_routers_addr, pim_msg,
				 packet_size,
				 rpf->source_nexthop.interface->name)) {
			zlog_warn(
				"%s: could not send PIM message on interface %s",
				__PRETTY_FUNCTION__,
				rpf->source_nexthop.interface->name);
		}
	}
	return 0;
}
