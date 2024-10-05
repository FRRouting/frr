// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Multicast traceroute for FRRouting
 * Copyright (C) 2017  Mladen Sablic
 */

/* based on draft-ietf-idmr-traceroute-ipm-07 */

#include <zebra.h>

#include "pimd.h"
#include "pim_instance.h"
#include "pim_util.h"
#include "pim_sock.h"
#include "pim_rp.h"
#include "pim_oil.h"
#include "pim_ifchannel.h"
#include "pim_macro.h"
#include "pim_igmp_mtrace.h"

static struct in_addr mtrace_primary_address(struct interface *ifp)
{
	struct connected *ifc;
	struct in_addr any;
	struct pim_interface *pim_ifp;

	if (ifp->info) {
		pim_ifp = ifp->info;
		return pim_ifp->primary_address;
	}

	any.s_addr = INADDR_ANY;

	frr_each (if_connected, ifp->connected, ifc) {
		struct prefix *p = ifc->address;

		if (p->family != AF_INET)
			continue;

		if (!CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY))
			return p->u.prefix4;
		/* in case no primary found, return a secondary */
		any = p->u.prefix4;
	}
	return any;
}

static bool mtrace_fwd_info_weak(struct pim_instance *pim,
				    struct igmp_mtrace *mtracep,
				    struct igmp_mtrace_rsp *rspp,
				    struct interface **ifpp)
{
	struct pim_nexthop nexthop;
	struct interface *ifp_in;
	struct in_addr nh_addr;

	nh_addr.s_addr = INADDR_ANY;

	memset(&nexthop, 0, sizeof(nexthop));

	if (!pim_nexthop_lookup(pim, &nexthop, mtracep->src_addr, 1)) {
		if (PIM_DEBUG_MTRACE)
			zlog_debug("mtrace not found neighbor");
		return false;
	}

	if (PIM_DEBUG_MTRACE)
		zlog_debug("mtrace pim_nexthop_lookup OK");

	if (PIM_DEBUG_MTRACE)
		zlog_debug("mtrace next_hop=%pPAs", &nexthop.mrib_nexthop_addr);

	nh_addr = nexthop.mrib_nexthop_addr;

	ifp_in = nexthop.interface;

	/* return interface for forwarding mtrace packets */
	*ifpp = ifp_in;

	/* 6.2.2. 4. Fill in the Incoming Interface Address... */
	rspp->incoming = mtrace_primary_address(ifp_in);
	rspp->prev_hop = nh_addr;
	rspp->in_count = htonl(MTRACE_UNKNOWN_COUNT);
	rspp->total = htonl(MTRACE_UNKNOWN_COUNT);
	rspp->rtg_proto = MTRACE_RTG_PROTO_PIM;
	return true;
}

static bool mtrace_fwd_info(struct pim_instance *pim,
			    struct igmp_mtrace *mtracep,
			    struct igmp_mtrace_rsp *rspp,
			    struct interface **ifpp)
{
	pim_sgaddr sg;
	struct pim_upstream *up;
	struct interface *ifp_in;
	struct in_addr nh_addr;
	uint32_t total;

	memset(&sg, 0, sizeof(sg));
	sg.src = mtracep->src_addr;
	sg.grp = mtracep->grp_addr;

	up = pim_upstream_find(pim, &sg);

	if (!up) {
		sg.src = PIMADDR_ANY;
		up = pim_upstream_find(pim, &sg);
	}

	if (!up)
		return false;

	if (!up->rpf.source_nexthop.interface) {
		if (PIM_DEBUG_TRACE)
			zlog_debug("%s: up %s RPF is not present", __func__,
				   up->sg_str);
		return false;
	}

	ifp_in = up->rpf.source_nexthop.interface;
	nh_addr = up->rpf.source_nexthop.mrib_nexthop_addr;
	total = htonl(MTRACE_UNKNOWN_COUNT);

	if (PIM_DEBUG_MTRACE)
		zlog_debug("fwd_info: upstream next hop=%pI4", &nh_addr);

	if (up->channel_oil)
		total = up->channel_oil->cc.pktcnt;

	/* return interface for forwarding mtrace packets */
	*ifpp = ifp_in;

	/* 6.2.2. 4. Fill in the Incoming Interface Address... */
	rspp->incoming = mtrace_primary_address(ifp_in);
	rspp->prev_hop = nh_addr;
	rspp->in_count = htonl(MTRACE_UNKNOWN_COUNT);
	rspp->total = total;
	rspp->rtg_proto = MTRACE_RTG_PROTO_PIM;

	/* 6.2.2. 4. Fill in ... S, and Src Mask */
	if (!pim_addr_is_any(sg.src)) {
		rspp->s = 1;
		rspp->src_mask = MTRACE_SRC_MASK_SOURCE;
	} else {
		rspp->s = 0;
		rspp->src_mask = MTRACE_SRC_MASK_GROUP;
	}

	return true;
}

static void mtrace_rsp_set_fwd_code(struct igmp_mtrace_rsp *mtrace_rspp,
				    enum mtrace_fwd_code fwd_code)
{
	if (mtrace_rspp->fwd_code == MTRACE_FWD_CODE_NO_ERROR)
		mtrace_rspp->fwd_code = fwd_code;
}

static void mtrace_rsp_init(struct igmp_mtrace_rsp *mtrace_rspp)
{
	mtrace_rspp->arrival = 0;
	mtrace_rspp->incoming.s_addr = INADDR_ANY;
	mtrace_rspp->outgoing.s_addr = INADDR_ANY;
	mtrace_rspp->prev_hop.s_addr = INADDR_ANY;
	mtrace_rspp->in_count = htonl(MTRACE_UNKNOWN_COUNT);
	mtrace_rspp->out_count = htonl(MTRACE_UNKNOWN_COUNT);
	mtrace_rspp->total = htonl(MTRACE_UNKNOWN_COUNT);
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
	struct in_addr incoming = mrspp->incoming;
	struct in_addr outgoing = mrspp->outgoing;
	struct in_addr prev_hop = mrspp->prev_hop;

	zlog_debug(
		"Rx mt(%d) qid=%ud arr=%x in=%pI4 out=%pI4 prev=%pI4 proto=%d fwd=%d",
		rsp, ntohl(qry_id), mrspp->arrival, &incoming, &outgoing,
		&prev_hop, mrspp->rtg_proto, mrspp->fwd_code);
}

static void mtrace_debug(struct pim_interface *pim_ifp,
			 struct igmp_mtrace *mtracep, int mtrace_len)
{
	struct in_addr ga, sa, da, ra;

	ga = mtracep->grp_addr;
	sa = mtracep->src_addr;
	da = mtracep->dst_addr;
	ra = mtracep->rsp_addr;

	zlog_debug(
		"Rx mtrace packet incoming on %pI4: hops=%d type=%d size=%d, grp=%pI4, src=%pI4, dst=%pI4 rsp=%pI4 ttl=%d qid=%ud",
		&pim_ifp->primary_address, mtracep->hops, mtracep->type,
		mtrace_len, &ga, &sa, &da, &ra, mtracep->rsp_ttl,
		ntohl(mtracep->qry_id));
	if (mtrace_len > (int)sizeof(struct igmp_mtrace)) {

		int i;

		int responses = mtrace_len - sizeof(struct igmp_mtrace);

		if ((responses % sizeof(struct igmp_mtrace_rsp)) != 0)
			if (PIM_DEBUG_MTRACE)
				zlog_debug(
					"Mtrace response block of wrong length");

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

	if (gettimeofday(&tv, NULL) < 0) {
		if (PIM_DEBUG_MTRACE)
			zlog_debug("Query arrival time lookup failed: errno=%d: %s",
				   errno, safe_strerror(errno));
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
	socklen_t tolen;
	ssize_t sent;
	int ret;
	int fd;
	uint8_t ttl;

	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr = dst_addr;
	tolen = sizeof(to);

	if (PIM_DEBUG_MTRACE) {
		struct in_addr if_addr;
		struct in_addr rsp_addr = mtracep->rsp_addr;

		if_addr = mtrace_primary_address(ifp);
		zlog_debug("Sending mtrace packet to %pI4 on %pI4", &rsp_addr,
			   &if_addr);
	}

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
				zlog_debug("Failed to set socket multicast TTL");
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
				zlog_debug(
					"Send mtrace request failed for %s on%s: group=%s msg_size=%zd: errno=%d:  %s",
					dst_str, ifp->name, group_str,
					mtrace_buf_len, errno,
					safe_strerror(errno));
		} else {
			if (PIM_DEBUG_MTRACE)
				zlog_debug(
					"Send mtrace request failed for %s on %s: group=%s msg_size=%zd: sent=%zd",
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

	if (interface == NULL) {
		memset(&nexthop, 0, sizeof(nexthop));
		if (!pim_nexthop_lookup(pim, &nexthop, ip_hdr->ip_dst, 0)) {
			if (PIM_DEBUG_MTRACE)
				zlog_debug(
					"Dropping mtrace packet, no route to destination");
			return -1;
		}

		if_out = nexthop.interface;
	} else {
		if_out = interface;
	}

	ip_hdr->ip_sum = in_cksum(ip_hdr, ip_hdr->ip_hl * 4);

	fd = pim_socket_raw(IPPROTO_RAW);

	if (fd < 0)
		return -1;

	pim_socket_ip_hdr(fd);

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
			zlog_debug(
				"Failed to forward mtrace packet: sendto errno=%d, %s",
				errno, safe_strerror(errno));
		return -1;
	}

	if (PIM_DEBUG_MTRACE) {
		zlog_debug("Fwd mtrace packet len=%u to %pI4 ttl=%u",
			   ntohs(ip_hdr->ip_len), &ip_hdr->ip_dst,
			   ip_hdr->ip_ttl);
	}

	return 0;
}

static int mtrace_mc_forward_packet(struct pim_instance *pim, struct ip *ip_hdr)
{
	pim_sgaddr sg;
	struct channel_oil *c_oil;
	struct listnode *chnode;
	struct listnode *chnextnode;
	struct pim_ifchannel *ch = NULL;
	int ret = -1;

	memset(&sg, 0, sizeof(sg));
	sg.grp = ip_hdr->ip_dst;

	c_oil = pim_find_channel_oil(pim, &sg);

	if (c_oil == NULL) {
		if (PIM_DEBUG_MTRACE) {
			zlog_debug(
				"Dropping mtrace multicast packet len=%u to %pI4 ttl=%u",
				ntohs(ip_hdr->ip_len),
				&ip_hdr->ip_dst, ip_hdr->ip_ttl);
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

static int mtrace_send_mc_response(struct pim_instance *pim,
				   struct igmp_mtrace *mtracep,
				   size_t mtrace_len)
{
	pim_sgaddr sg;
	struct channel_oil *c_oil;
	struct listnode *chnode;
	struct listnode *chnextnode;
	struct pim_ifchannel *ch = NULL;
	int ret = -1;

	memset(&sg, 0, sizeof(sg));
	sg.grp = mtracep->rsp_addr;

	c_oil = pim_find_channel_oil(pim, &sg);

	if (c_oil == NULL) {
		if (PIM_DEBUG_MTRACE) {
			struct in_addr rsp_addr = mtracep->rsp_addr;

			zlog_debug(
				"Dropping mtrace multicast response packet len=%u to %pI4",
				(unsigned int)mtrace_len, &rsp_addr);
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

/* 6.5 Sending Traceroute Responses */
static int mtrace_send_response(struct pim_instance *pim,
				struct igmp_mtrace *mtracep, size_t mtrace_len)
{
	struct pim_nexthop nexthop;

	mtracep->type = PIM_IGMP_MTRACE_RESPONSE;

	mtracep->checksum = 0;
	mtracep->checksum = in_cksum((char *)mtracep, mtrace_len);

	if (IPV4_CLASS_DE(ntohl(mtracep->rsp_addr.s_addr))) {
		struct pim_rpf *p_rpf;

		if (pim_rp_i_am_rp(pim, mtracep->rsp_addr))
			return mtrace_send_mc_response(pim, mtracep,
						       mtrace_len);

		p_rpf = pim_rp_g(pim, mtracep->rsp_addr);

		if (p_rpf == NULL) {
			if (PIM_DEBUG_MTRACE) {
				struct in_addr rsp_addr = mtracep->rsp_addr;

				zlog_debug("mtrace no RP for %pI4", &rsp_addr);
			}
			return -1;
		}
		nexthop = p_rpf->source_nexthop;
		if (PIM_DEBUG_MTRACE)
			zlog_debug("mtrace response to RP");
	} else {
		memset(&nexthop, 0, sizeof(nexthop));
		/* TODO: should use unicast rib lookup */
		if (!pim_nexthop_lookup(pim, &nexthop, mtracep->rsp_addr, 1)) {
			if (PIM_DEBUG_MTRACE)
				zlog_debug(
					"Dropped response qid=%ud, no route to response address",
					mtracep->qry_id);
			return -1;
		}
	}

	return mtrace_send_packet(nexthop.interface, mtracep, mtrace_len,
				  mtracep->rsp_addr, mtracep->grp_addr);
}

int igmp_mtrace_recv_qry_req(struct gm_sock *igmp, struct ip *ip_hdr,
			     struct in_addr from, const char *from_str,
			     char *igmp_msg, int igmp_msg_len)
{
	static uint32_t qry_id, qry_src;
	char mtrace_buf[MTRACE_HDR_SIZE + MTRACE_MAX_HOPS * MTRACE_RSP_SIZE];
	struct interface *ifp;
	struct interface *out_ifp = NULL;
	struct pim_interface *pim_ifp;
	struct pim_instance *pim;
	struct igmp_mtrace *mtracep;
	struct igmp_mtrace_rsp *rspp;
	struct in_addr nh_addr;
	enum mtrace_fwd_code fwd_code = MTRACE_FWD_CODE_NO_ERROR;
	size_t r_len;
	int last_rsp_ind = 0;
	size_t mtrace_len;
	uint16_t recv_checksum;
	uint16_t checksum;
	bool reached_source;
	bool fwd_info;

	ifp = igmp->interface;
	pim_ifp = ifp->info;
	pim = pim_ifp->pim;

	/*
	 * 6. Router Behaviour
	 * Check if mtrace packet is addressed elsewhere and forward,
	 * if applicable
	 */
	if (!IPV4_CLASS_DE(ntohl(ip_hdr->ip_dst.s_addr)))
		if (!if_address_is_local(&ip_hdr->ip_dst, AF_INET,
					 pim->vrf->vrf_id))
			return mtrace_forward_packet(pim, ip_hdr);

	if (igmp_msg_len < (int)sizeof(struct igmp_mtrace)) {
		if (PIM_DEBUG_MTRACE)
			zlog_debug(
				"Recv mtrace packet from %s on %s: too short, len=%d, min=%zu",
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
			zlog_debug(
				"Recv mtrace packet from %s on %s: checksum mismatch: received=%x computed=%x",
				from_str, ifp->name, recv_checksum, checksum);
		return -1;
	}

	/* Collecting IGMP Rx stats */
	igmp->igmp_stats.mtrace_req++;

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
						"Dropping multicast query on wrong interface");
				return -1;
			}
			/* Unicast query on wrong interface */
			fwd_code = MTRACE_FWD_CODE_WRONG_IF;
			if (PIM_DEBUG_MTRACE)
				zlog_debug("Multicast query on wrong interface");
		}
		if (qry_id == mtracep->qry_id && qry_src == from.s_addr) {
			if (PIM_DEBUG_MTRACE)
				zlog_debug(
					"Dropping multicast query with duplicate source and id");
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
				zlog_debug("Mtrace request of excessive size");
			return -1;
		}
	} else {
		if (PIM_DEBUG_MTRACE)
			zlog_debug(
				"Recv mtrace packet from %s on %s: invalid length %d",
				from_str, ifp->name, igmp_msg_len);
		return -1;
	}

	/* 6.2.1 Packet Verification - drop not link-local multicast */
	if (IPV4_CLASS_DE(ntohl(ip_hdr->ip_dst.s_addr))
	    && !IPV4_MC_LINKLOCAL(ntohl(ip_hdr->ip_dst.s_addr))) {
		if (PIM_DEBUG_MTRACE)
			zlog_debug(
				"Recv mtrace packet from %s on %s: not link-local multicast %pI4",
				from_str, ifp->name, &ip_hdr->ip_dst);
		return -1;
	}

	/* 6.2.2. Normal Processing */

	/* 6.2.2. 1. If there is room in the current buffer? */

	if (last_rsp_ind == MTRACE_MAX_HOPS) {
		/* ...there was no room... */
		mtracep->rsp[MTRACE_MAX_HOPS - 1].fwd_code =
			MTRACE_FWD_CODE_NO_SPACE;
		return mtrace_send_response(pim_ifp->pim, mtracep,
					    igmp_msg_len);
	}

	/* ...insert new response block... */

	/* calculate new mtrace lenght with extra response */
	mtrace_len = igmp_msg_len + sizeof(struct igmp_mtrace_rsp);

	/* copy received query/request */
	memcpy(mtrace_buf, igmp_msg, igmp_msg_len);

	/* repoint mtracep pointer to copy */
	mtracep = (struct igmp_mtrace *)mtrace_buf;

	/* pointer for extra response field to be filled in */
	rspp = &mtracep->rsp[last_rsp_ind];

	/* initialize extra response field */
	mtrace_rsp_init(rspp);

	/* carry over any error noted when receiving the query */
	rspp->fwd_code = fwd_code;

	/* ...and fill in Query Arrival Time... */
	rspp->arrival = htonl(query_arrival_time());
	rspp->outgoing = pim_ifp->primary_address;
	rspp->out_count = htonl(MTRACE_UNKNOWN_COUNT);
	rspp->fwd_ttl = 1;

	/* 6.2.2. 2. Attempt to determine the forwarding information... */

	if (mtracep->grp_addr.s_addr != INADDR_ANY)
		fwd_info = mtrace_fwd_info(pim, mtracep, rspp, &out_ifp);
	else
		fwd_info = mtrace_fwd_info_weak(pim, mtracep, rspp, &out_ifp);

	/* 6.2.2 3. If no forwarding information... */
	if (!fwd_info) {
		if (PIM_DEBUG_MTRACE)
			zlog_debug("mtrace not found multicast state");
		mtrace_rsp_set_fwd_code(rspp, MTRACE_FWD_CODE_NO_ROUTE);
		/* 6.2.2. 3. forward the packet to requester */
		return mtrace_send_response(pim, mtracep, mtrace_len);
	}

	nh_addr = rspp->prev_hop;

	reached_source = false;

	if (nh_addr.s_addr == INADDR_ANY) {
		/* no pim? i.e. 7.5.3. No Previous Hop */
		if (!out_ifp->info) {
			if (PIM_DEBUG_MTRACE)
				zlog_debug("mtrace not found incoming if w/ pim");
			mtrace_rsp_set_fwd_code(rspp,
						MTRACE_FWD_CODE_NO_MULTICAST);
			return mtrace_send_response(pim, mtracep, mtrace_len);
		}
		/* reached source? i.e. 7.5.1 Arriving at source */
		if (pim_if_connected_to_source(out_ifp, mtracep->src_addr)) {
			reached_source = true;
			rspp->prev_hop = mtracep->src_addr;
		}
		/*
		 * 6.4 Forwarding Traceroute Requests:
		 * Previous-hop router not known,
		 * packet is sent to an appropriate multicast address
		 */
		(void)inet_aton(MCAST_ALL_ROUTERS, &nh_addr);
	}

	/* 6.2.2 8. If this router is the Rendez-vous Point */
	if (mtracep->grp_addr.s_addr != INADDR_ANY &&
	    pim_rp_i_am_rp(pim, mtracep->grp_addr)) {
		mtrace_rsp_set_fwd_code(rspp, MTRACE_FWD_CODE_REACHED_RP);
		/* 7.7.1. PIM-SM ...RP has not performed source-specific join */
		if (rspp->src_mask == MTRACE_SRC_MASK_GROUP)
			return mtrace_send_response(pim, mtracep, mtrace_len);
	}

	/*
	 * 6.4 Forwarding Traceroute Requests: the number of response
	 * blocks exceeds number of responses, so forward to the requester.
	 */
	if (mtracep->hops <= (last_rsp_ind + 1))
		return mtrace_send_response(pim, mtracep, mtrace_len);

	/* 7.5.1. Arriving at source: terminate trace */
	if (reached_source)
		return mtrace_send_response(pim, mtracep, mtrace_len);

	mtracep->checksum = 0;

	mtracep->checksum = in_cksum(mtrace_buf, mtrace_len);

	/* 6.4 Forwarding Traceroute Requests: response blocks less than req. */
	return mtrace_send_packet(out_ifp, mtracep, mtrace_len, nh_addr,
				  mtracep->grp_addr);
}

/* 6.3. Traceroute responses */
int igmp_mtrace_recv_response(struct gm_sock *igmp, struct ip *ip_hdr,
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

	if (igmp_msg_len < (int)sizeof(struct igmp_mtrace)) {
		if (PIM_DEBUG_MTRACE)
			zlog_debug(
				"Recv mtrace packet from %s on %s: too short, len=%d, min=%zu",
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
			zlog_debug(
				"Recv mtrace response from %s on %s: checksum mismatch: received=%x computed=%x",
				from_str, ifp->name, recv_checksum, checksum);
		return -1;
	}

	mtracep->checksum = checksum;

	/* Collecting IGMP Rx stats */
	igmp->igmp_stats.mtrace_rsp++;

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
