/*
 * Multicast traceroute for FRRouting
 * Copyright (C) 2017  Mladen Sablic
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

#include "pimd.h"
#include "pim_util.h"
#include "pim_sock.h"
#include "pim_rp.h"
#include "pim_oil.h"
#include "pim_ifchannel.h"
#include "pim_macro.h"
#include "pim_igmp_mtrace.h"

static void mtrace_rsp_init(struct igmp_mtrace_rsp *mtrace_rspp)
{
	mtrace_rspp->arrival = 0;
	mtrace_rspp->incoming.s_addr = 0;
	mtrace_rspp->outgoing.s_addr = 0;
	mtrace_rspp->prev_hop.s_addr = 0;
	mtrace_rspp->in_count = MTRACE_UNKNOWN_COUNT;
	mtrace_rspp->out_count = MTRACE_UNKNOWN_COUNT;
	mtrace_rspp->total = MTRACE_UNKNOWN_COUNT;
	mtrace_rspp->rtg_proto = 0;
	mtrace_rspp->fwd_ttl = 0;
	mtrace_rspp->mbz = 0;
	mtrace_rspp->s = 0;
	mtrace_rspp->src_mask = 0;
	mtrace_rspp->fwd_code = MTRACE_FWD_CODE_NO_ERROR;
}

static void mtrace_rsp_debug(uint32_t qry_id, int rsp,
			     struct igmp_mtrace_rsp *mrspp)
{
	char inc_str[INET_ADDRSTRLEN];
	char out_str[INET_ADDRSTRLEN];
	char prv_str[INET_ADDRSTRLEN];

	zlog_debug(
		"Rx mt(%d) qid=%ud arr=%x in=%s out=%s prev=%s proto=%d fwd=%d",
		rsp, ntohl(qry_id), mrspp->arrival,
		inet_ntop(AF_INET, &(mrspp->incoming), inc_str,
			  sizeof(inc_str)),
		inet_ntop(AF_INET, &(mrspp->outgoing), out_str,
			  sizeof(out_str)),
		inet_ntop(AF_INET, &(mrspp->prev_hop), prv_str,
			  sizeof(prv_str)),
		mrspp->rtg_proto, mrspp->fwd_code);
}

static void mtrace_debug(struct pim_interface *pim_ifp,
			 struct igmp_mtrace *mtracep, int mtrace_len)
{
	char inc_str[INET_ADDRSTRLEN];
	char grp_str[INET_ADDRSTRLEN];
	char src_str[INET_ADDRSTRLEN];
	char dst_str[INET_ADDRSTRLEN];
	char rsp_str[INET_ADDRSTRLEN];

	zlog_debug(
		"Rx mtrace packet incoming on %s: "
		"hops=%d type=%d size=%d, grp=%s, src=%s,"
		" dst=%s rsp=%s ttl=%d qid=%ud",
		inet_ntop(AF_INET, &(pim_ifp->primary_address), inc_str,
			  sizeof(inc_str)),
		mtracep->hops, mtracep->type, mtrace_len,
		inet_ntop(AF_INET, &(mtracep->grp_addr), grp_str,
			  sizeof(grp_str)),
		inet_ntop(AF_INET, &(mtracep->src_addr), src_str,
			  sizeof(src_str)),
		inet_ntop(AF_INET, &(mtracep->dst_addr), dst_str,
			  sizeof(dst_str)),
		inet_ntop(AF_INET, &(mtracep->rsp_addr), rsp_str,
			  sizeof(rsp_str)),
		mtracep->rsp_ttl, ntohl(mtracep->qry_id));
	if (mtrace_len > (int)sizeof(struct igmp_mtrace)) {

		int i;

		int responses = mtrace_len - sizeof(struct igmp_mtrace);

		if ((responses % sizeof(struct igmp_mtrace_rsp)) != 0)
			if (PIM_DEBUG_MTRACE)
				zlog_debug(
					"Mtrace response block of wrong"
					" length");

		responses = responses / sizeof(struct igmp_mtrace_rsp);

		for (i = 0; i < responses; i++)
			mtrace_rsp_debug(mtracep->qry_id, i, &mtracep->rsp[i]);
	}
}

/* 5.1 Query Arrival Time */
static uint32_t query_arrival_time(void)
{
	struct timeval tv;
	uint32_t qat;

	char m_qat[] = "Query arrival time lookup failed: errno=%d: %s";

	if (gettimeofday(&tv, NULL) < 0) {
		if (PIM_DEBUG_MTRACE)
			zlog_warn(m_qat, errno, safe_strerror(errno));
		return 0;
	}
	/* not sure second offset correct, as I get different value */
	qat = ((tv.tv_sec + 32384) << 16) + ((tv.tv_usec << 10) / 15625);

	return qat;
}

static int mtrace_send_packet(struct interface *ifp,
			      struct igmp_mtrace *mtracep,
			      size_t mtrace_buf_len, struct in_addr dst_addr,
			      struct in_addr group_addr)
{
	struct sockaddr_in to;
	struct pim_interface *pim_ifp;
	socklen_t tolen;
	ssize_t sent;
	int ret;
	int fd;
	char pim_str[INET_ADDRSTRLEN];
	char rsp_str[INET_ADDRSTRLEN];
	u_char ttl;

	pim_ifp = ifp->info;

	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr = dst_addr;
	tolen = sizeof(to);

	if (PIM_DEBUG_MTRACE)
		zlog_debug("Sending mtrace packet to %s on %s",
			   inet_ntop(AF_INET, &mtracep->rsp_addr, rsp_str,
				     sizeof(rsp_str)),
			   inet_ntop(AF_INET, &pim_ifp->primary_address,
				     pim_str, sizeof(pim_str)));

	fd = pim_socket_raw(IPPROTO_IGMP);

	if (fd < 0)
		return -1;

	ret = pim_socket_bind(fd, ifp);

	if (ret < 0) {
		ret = -1;
		goto close_fd;
	}

	if (IPV4_CLASS_DE(ntohl(dst_addr.s_addr))) {
		if (IPV4_MC_LINKLOCAL(ntohl(dst_addr.s_addr))) {
			ttl = 1;
		} else {
			if (mtracep->type == PIM_IGMP_MTRACE_RESPONSE)
				ttl = mtracep->rsp_ttl;
			else
				ttl = 64;
		}
		ret = setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,
				 sizeof(ttl));

		if (ret < 0) {
			if (PIM_DEBUG_MTRACE)
				zlog_warn("Failed to set socket multicast TTL");
			ret = -1;
			goto close_fd;
		}
	}

	sent = sendto(fd, (char *)mtracep, mtrace_buf_len, MSG_DONTWAIT,
		      (struct sockaddr *)&to, tolen);

	if (sent != (ssize_t)mtrace_buf_len) {
		char dst_str[INET_ADDRSTRLEN];
		char group_str[INET_ADDRSTRLEN];

		pim_inet4_dump("<dst?>", dst_addr, dst_str, sizeof(dst_str));
		pim_inet4_dump("<group?>", group_addr, group_str,
			       sizeof(group_str));
		if (sent < 0) {
			if (PIM_DEBUG_MTRACE)
				zlog_warn(
					"Send mtrace request failed for %s on"
					"%s: group=%s msg_size=%zd: errno=%d: "
					" %s",
					dst_str, ifp->name, group_str,
					mtrace_buf_len, errno,
					safe_strerror(errno));
		} else {
			if (PIM_DEBUG_MTRACE)
				zlog_warn(
					"Send mtrace request failed for %s on"
					" %s: group=%s msg_size=%zd: sent=%zd",
					dst_str, ifp->name, group_str,
					mtrace_buf_len, sent);
		}
		ret = -1;
		goto close_fd;
	}
	ret = 0;
close_fd:
	close(fd);
	return ret;
}

static int mtrace_un_forward_packet(struct pim_instance *pim, struct ip *ip_hdr,
				    struct interface *interface)
{
	struct pim_nexthop nexthop;
	struct sockaddr_in to;
	struct interface *if_out;
	socklen_t tolen;
	int ret;
	int fd;
	int sent;
	uint16_t checksum;

	checksum = ip_hdr->ip_sum;

	ip_hdr->ip_sum = 0;

	if (checksum != in_cksum(ip_hdr, ip_hdr->ip_hl * 4))
		return -1;

	if (ip_hdr->ip_ttl-- <= 1)
		return -1;

	ip_hdr->ip_sum = in_cksum(ip_hdr, ip_hdr->ip_hl * 4);

	fd = pim_socket_raw(IPPROTO_RAW);

	if (fd < 0)
		return -1;

	pim_socket_ip_hdr(fd);

	if (interface == NULL) {
		ret = pim_nexthop_lookup(pim, &nexthop, ip_hdr->ip_dst, 0);

		if (ret != 0) {
			if (PIM_DEBUG_MTRACE)
				zlog_warn(
					"Dropping mtrace packet, "
					"no route to destination");
			return -1;
		}

		if_out = nexthop.interface;
	} else {
		if_out = interface;
	}

	ret = pim_socket_bind(fd, if_out);

	if (ret < 0) {
		close(fd);
		return -1;
	}

	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr = ip_hdr->ip_dst;
	tolen = sizeof(to);

	sent = sendto(fd, ip_hdr, ntohs(ip_hdr->ip_len), 0,
		      (struct sockaddr *)&to, tolen);

	close(fd);

	if (sent < 0) {
		if (PIM_DEBUG_MTRACE)
			zlog_warn(
				"Failed to forward mtrace packet:"
				" sendto errno=%d, %s",
				errno, safe_strerror(errno));
		return -1;
	}

	if (PIM_DEBUG_MTRACE) {
		zlog_debug("Fwd mtrace packet len=%u to %s ttl=%u",
			   ntohs(ip_hdr->ip_len), inet_ntoa(ip_hdr->ip_dst),
			   ip_hdr->ip_ttl);
	}

	return 0;
}

static int mtrace_mc_forward_packet(struct pim_instance *pim, struct ip *ip_hdr)
{
	struct prefix_sg sg;
	struct channel_oil *c_oil;
	struct listnode *chnode;
	struct listnode *chnextnode;
	struct pim_ifchannel *ch = NULL;
	int ret = -1;

	memset(&sg, 0, sizeof(struct prefix_sg));
	sg.grp = ip_hdr->ip_dst;

	c_oil = pim_find_channel_oil(pim, &sg);

	if (c_oil == NULL) {
		if (PIM_DEBUG_MTRACE) {
			zlog_debug(
				"Dropping mtrace multicast packet "
				"len=%u to %s ttl=%u",
				ntohs(ip_hdr->ip_len),
				inet_ntoa(ip_hdr->ip_dst), ip_hdr->ip_ttl);
		}
		return -1;
	}
	if (c_oil->up == NULL)
		return -1;
	if (c_oil->up->ifchannels == NULL)
		return -1;
	for (ALL_LIST_ELEMENTS(c_oil->up->ifchannels, chnode, chnextnode, ch)) {
		if (pim_macro_chisin_oiflist(ch)) {
			int r;

			r = mtrace_un_forward_packet(pim, ip_hdr,
						     ch->interface);
			if (r == 0)
				ret = 0;
		}
	}
	return ret;
}


static int mtrace_forward_packet(struct pim_instance *pim, struct ip *ip_hdr)
{
	if (IPV4_CLASS_DE(ntohl(ip_hdr->ip_dst.s_addr)))
		return mtrace_mc_forward_packet(pim, ip_hdr);
	else
		return mtrace_un_forward_packet(pim, ip_hdr, NULL);
}

/* 6.5 Sending Traceroute Responses */
static int mtrace_send_mc_response(struct pim_instance *pim,
				   struct igmp_mtrace *mtracep,
				   size_t mtrace_len)
{
	struct prefix_sg sg;
	struct channel_oil *c_oil;
	struct listnode *chnode;
	struct listnode *chnextnode;
	struct pim_ifchannel *ch = NULL;
	int ret = -1;

	memset(&sg, 0, sizeof(struct prefix_sg));
	sg.grp = mtracep->rsp_addr;

	c_oil = pim_find_channel_oil(pim, &sg);

	if (c_oil == NULL) {
		if (PIM_DEBUG_MTRACE) {
			zlog_debug(
				"Dropping mtrace multicast response packet "
				"len=%u to %s",
				(unsigned int)mtrace_len,
				inet_ntoa(mtracep->rsp_addr));
		}
		return -1;
	}
	if (c_oil->up == NULL)
		return -1;
	if (c_oil->up->ifchannels == NULL)
		return -1;
	for (ALL_LIST_ELEMENTS(c_oil->up->ifchannels, chnode, chnextnode, ch)) {
		if (pim_macro_chisin_oiflist(ch)) {
			int r;

			r = mtrace_send_packet(ch->interface, mtracep,
					       mtrace_len, mtracep->rsp_addr,
					       mtracep->grp_addr);
			if (r == 0)
				ret = 0;
		}
	}
	return ret;
}

static int mtrace_send_response(struct pim_instance *pim,
				struct igmp_mtrace *mtracep, size_t mtrace_len)
{
	struct pim_nexthop nexthop;
	int ret;

	mtracep->type = PIM_IGMP_MTRACE_RESPONSE;

	mtracep->checksum = 0;
	mtracep->checksum = in_cksum((char *)mtracep, mtrace_len);

	if (IPV4_CLASS_DE(ntohl(mtracep->rsp_addr.s_addr))) {
		struct pim_rpf *p_rpf;
		char grp_str[INET_ADDRSTRLEN];

		if (pim_rp_i_am_rp(pim, mtracep->rsp_addr))
			return mtrace_send_mc_response(pim, mtracep,
						       mtrace_len);

		p_rpf = pim_rp_g(pim, mtracep->rsp_addr);

		if (p_rpf == NULL) {
			if (PIM_DEBUG_MTRACE)
				zlog_warn("mtrace no RP for %s",
					  inet_ntop(AF_INET,
						    &(mtracep->rsp_addr),
						    grp_str, sizeof(grp_str)));
			return -1;
		}
		nexthop = p_rpf->source_nexthop;
		if (PIM_DEBUG_MTRACE)
			zlog_debug("mtrace response to RP");
	} else {
		/* TODO: should use unicast rib lookup */
		ret = pim_nexthop_lookup(pim, &nexthop, mtracep->rsp_addr, 1);

		if (ret != 0) {
			if (PIM_DEBUG_MTRACE)
				zlog_warn(
					"Dropped response qid=%ud, no route to "
					"response address",
					mtracep->qry_id);
			return -1;
		}
	}

	return mtrace_send_packet(nexthop.interface, mtracep, mtrace_len,
				  mtracep->rsp_addr, mtracep->grp_addr);
}

int igmp_mtrace_recv_qry_req(struct igmp_sock *igmp, struct ip *ip_hdr,
			     struct in_addr from, const char *from_str,
			     char *igmp_msg, int igmp_msg_len)
{
	static uint32_t qry_id, qry_src;
	char mtrace_buf[MTRACE_HDR_SIZE + MTRACE_MAX_HOPS * MTRACE_RSP_SIZE];
	struct pim_nexthop nexthop;
	struct interface *ifp;
	struct interface *out_ifp;
	struct pim_interface *pim_ifp;
	struct pim_interface *pim_out_ifp;
	struct pim_instance *pim;
	struct igmp_mtrace *mtracep;
	struct igmp_mtrace_rsp *rspp;
	struct in_addr nh_addr;
	enum mtrace_fwd_code fwd_code = MTRACE_FWD_CODE_NO_ERROR;
	int ret;
	size_t r_len;
	int last_rsp_ind = 0;
	size_t mtrace_len;
	uint16_t recv_checksum;
	uint16_t checksum;

	ifp = igmp->interface;
	pim_ifp = ifp->info;
	pim = pim_ifp->pim;

	/*
	 * 6. Router Behaviour
	 * Check if mtrace packet is addressed elsewhere and forward,
	 * if applicable
	 */
	if (!IPV4_CLASS_DE(ntohl(ip_hdr->ip_dst.s_addr)))
		if (!if_lookup_exact_address(&ip_hdr->ip_dst, AF_INET,
					     pim->vrf_id))
			return mtrace_forward_packet(pim, ip_hdr);

	if (igmp_msg_len < (int)sizeof(struct igmp_mtrace)) {
		if (PIM_DEBUG_MTRACE)
			zlog_warn(
				"Recv mtrace packet from %s on %s: too short,"
				" len=%d, min=%zu",
				from_str, ifp->name, igmp_msg_len,
				sizeof(struct igmp_mtrace));
		return -1;
	}

	mtracep = (struct igmp_mtrace *)igmp_msg;

	recv_checksum = mtracep->checksum;

	mtracep->checksum = 0;

	checksum = in_cksum(igmp_msg, igmp_msg_len);

	if (recv_checksum != checksum) {
		if (PIM_DEBUG_MTRACE)
			zlog_warn(
				"Recv mtrace packet from %s on %s: checksum"
				" mismatch: received=%x computed=%x",
				from_str, ifp->name, recv_checksum, checksum);
		return -1;
	}

	if (PIM_DEBUG_MTRACE)
		mtrace_debug(pim_ifp, mtracep, igmp_msg_len);

	/* subtract header from message length */
	r_len = igmp_msg_len - sizeof(struct igmp_mtrace);

	/* Classify mtrace packet, check if it is a query */
	if (!r_len) {
		if (PIM_DEBUG_MTRACE)
			zlog_debug("Received IGMP multicast traceroute query");

		/* 6.1.1  Packet verification */
		if (!pim_if_connected_to_source(ifp, mtracep->dst_addr)) {
			if (IPV4_CLASS_DE(ntohl(ip_hdr->ip_dst.s_addr))) {
				if (PIM_DEBUG_MTRACE)
					zlog_debug(
						"Dropping multicast query "
						"on wrong interface");
				return -1;
			}
			/* Unicast query on wrong interface */
			fwd_code = MTRACE_FWD_CODE_WRONG_IF;
		}
		if (qry_id == mtracep->qry_id && qry_src == from.s_addr) {
			if (PIM_DEBUG_MTRACE)
				zlog_debug(
					"Dropping multicast query with "
					"duplicate source and id");
			return -1;
		}
		qry_id = mtracep->qry_id;
		qry_src = from.s_addr;
	}
	/* if response fields length is equal to a whole number of responses */
	else if ((r_len % sizeof(struct igmp_mtrace_rsp)) == 0) {
		r_len = igmp_msg_len - sizeof(struct igmp_mtrace);

		if (r_len != 0)
			last_rsp_ind = r_len / sizeof(struct igmp_mtrace_rsp);
		if (last_rsp_ind > MTRACE_MAX_HOPS) {
			if (PIM_DEBUG_MTRACE)
				zlog_warn("Mtrace request of excessive size");
			return -1;
		}
	} else {
		if (PIM_DEBUG_MTRACE)
			zlog_warn(
				"Recv mtrace packet from %s on %s: "
				"invalid length %d",
				from_str, ifp->name, igmp_msg_len);
		return -1;
	}

	/* 6.2.1 Packet Verification - drop not link-local multicast */
	if (IPV4_CLASS_DE(ntohl(ip_hdr->ip_dst.s_addr))
	    && !IPV4_MC_LINKLOCAL(ntohl(ip_hdr->ip_dst.s_addr))) {
		if (PIM_DEBUG_MTRACE)
			zlog_warn(
				"Recv mtrace packet from %s on %s:"
				" not link-local multicast %s",
				from_str, ifp->name, inet_ntoa(ip_hdr->ip_dst));
		return -1;
	}

	/* 6.2.2. Normal Processing */

	/* 6.2.2. 1. */

	if (last_rsp_ind == MTRACE_MAX_HOPS) {
		mtracep->rsp[MTRACE_MAX_HOPS - 1].fwd_code =
			MTRACE_FWD_CODE_NO_SPACE;
		return mtrace_send_response(pim_ifp->pim, mtracep,
					    igmp_msg_len);
	}

	/* calculate new mtrace mtrace lenght with extra response */
	mtrace_len = igmp_msg_len + sizeof(struct igmp_mtrace_rsp);

	/* copy received query/request */
	memcpy(mtrace_buf, igmp_msg, igmp_msg_len);

	/* repoint mtracep pointer to copy */
	mtracep = (struct igmp_mtrace *)mtrace_buf;

	/* pointer for extra response field to be filled in */
	rspp = &mtracep->rsp[last_rsp_ind];

	/* initialize extra response field */
	mtrace_rsp_init(rspp);

	rspp->arrival = htonl(query_arrival_time());
	rspp->outgoing = pim_ifp->primary_address;
	rspp->out_count = htonl(MTRACE_UNKNOWN_COUNT);

	/* 6.2.2. 2. Attempt to determine forwarding information */

	nh_addr.s_addr = 0;

	ret = pim_nexthop_lookup(pim, &nexthop, mtracep->src_addr, 1);

	if (ret == 0) {
		char nexthop_str[INET_ADDRSTRLEN];

		if (PIM_DEBUG_MTRACE)
			zlog_debug("mtrace pim_nexthop_lookup OK");

		if (PIM_DEBUG_MTRACE)
			zlog_warn("mtrace next_hop=%s",
				  inet_ntop(nexthop.mrib_nexthop_addr.family,
					    &nexthop.mrib_nexthop_addr.u.prefix,
					    nexthop_str, sizeof(nexthop_str)));

		if (nexthop.mrib_nexthop_addr.family == AF_INET)
			nh_addr = nexthop.mrib_nexthop_addr.u.prefix4;
	}
	/* 6.4 Forwarding Traceroute Requests: ... Otherwise, ... */
	else {
		if (PIM_DEBUG_MTRACE)
			zlog_debug("mtrace not found neighbor");
		if (!fwd_code)
			rspp->fwd_code = MTRACE_FWD_CODE_NO_ROUTE;
		else
			rspp->fwd_code = fwd_code;
		/* 6.5 Sending Traceroute Responses */
		return mtrace_send_response(pim, mtracep, mtrace_len);
	}

	out_ifp = nexthop.interface;
	pim_out_ifp = out_ifp->info;

	rspp->incoming = pim_out_ifp->primary_address;
	rspp->prev_hop = nh_addr;
	rspp->in_count = htonl(MTRACE_UNKNOWN_COUNT);
	rspp->total = htonl(MTRACE_UNKNOWN_COUNT);
	rspp->rtg_proto = MTRACE_RTG_PROTO_PIM;
	rspp->s = 1;
	rspp->src_mask = 32;

	if (nh_addr.s_addr == 0) {
		/* reached source? */
		if (pim_if_connected_to_source(out_ifp, mtracep->src_addr))
			return mtrace_send_response(pim, mtracep, mtrace_len);
		/*
		 * 6.4 Forwarding Traceroute Requests:
		 * Previous-hop router not known
		 */
		inet_aton(MCAST_ALL_ROUTERS, &nh_addr);
	}

	if (mtracep->hops <= (last_rsp_ind + 1))
		return mtrace_send_response(pim, mtracep, mtrace_len);

	mtracep->checksum = 0;

	mtracep->checksum = in_cksum(mtrace_buf, mtrace_len);

	return mtrace_send_packet(out_ifp, mtracep, mtrace_len, nh_addr,
				  mtracep->grp_addr);
}

int igmp_mtrace_recv_response(struct igmp_sock *igmp, struct ip *ip_hdr,
			      struct in_addr from, const char *from_str,
			      char *igmp_msg, int igmp_msg_len)
{
	static uint32_t qry_id, rsp_dst;
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	struct pim_instance *pim;
	struct igmp_mtrace *mtracep;
	uint16_t recv_checksum;
	uint16_t checksum;

	ifp = igmp->interface;
	pim_ifp = ifp->info;
	pim = pim_ifp->pim;

	mtracep = (struct igmp_mtrace *)igmp_msg;

	recv_checksum = mtracep->checksum;

	mtracep->checksum = 0;

	checksum = in_cksum(igmp_msg, igmp_msg_len);

	if (recv_checksum != checksum) {
		if (PIM_DEBUG_MTRACE)
			zlog_warn(
				"Recv mtrace response from %s on %s: checksum"
				" mismatch: received=%x computed=%x",
				from_str, ifp->name, recv_checksum, checksum);
		return -1;
	}

	mtracep->checksum = checksum;

	if (PIM_DEBUG_MTRACE)
		mtrace_debug(pim_ifp, mtracep, igmp_msg_len);

	/* Drop duplicate packets */
	if (qry_id == mtracep->qry_id && rsp_dst == ip_hdr->ip_dst.s_addr) {
		if (PIM_DEBUG_MTRACE)
			zlog_debug("duplicate mtrace response packet dropped");
		return -1;
	}

	qry_id = mtracep->qry_id;
	rsp_dst = ip_hdr->ip_dst.s_addr;

	return mtrace_forward_packet(pim, ip_hdr);
}
