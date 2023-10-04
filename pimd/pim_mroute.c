// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>
#include "log.h"
#include "privs.h"
#include "if.h"
#include "prefix.h"
#include "vty.h"
#include "plist.h"
#include "sockopt.h"
#include "lib_errors.h"
#include "lib/network.h"

#include "pimd.h"
#include "pim_rpf.h"
#include "pim_mroute.h"
#include "pim_oil.h"
#include "pim_str.h"
#include "pim_time.h"
#include "pim_iface.h"
#include "pim_macro.h"
#include "pim_rp.h"
#include "pim_oil.h"
#include "pim_register.h"
#include "pim_ifchannel.h"
#include "pim_zlookup.h"
#include "pim_ssm.h"
#include "pim_sock.h"
#include "pim_vxlan.h"
#include "pim_msg.h"

static void mroute_read_on(struct pim_instance *pim);
static int pim_upstream_mroute_update(struct channel_oil *c_oil,
				      const char *name);

int pim_mroute_set(struct pim_instance *pim, int enable)
{
	int err;
	int opt, data;
	socklen_t data_len = sizeof(data);

	/*
	 * We need to create the VRF table for the pim mroute_socket
	 */
	if (enable && pim->vrf->vrf_id != VRF_DEFAULT) {
		frr_with_privs (&pimd_privs) {

			data = pim->vrf->data.l.table_id;
			err = setsockopt(pim->mroute_socket, PIM_IPPROTO,
					 MRT_TABLE, &data, data_len);
			if (err) {
				zlog_warn(
					"%s %s: failure: setsockopt(fd=%d,PIM_IPPROTO, MRT_TABLE=%d): errno=%d: %s",
					__FILE__, __func__, pim->mroute_socket,
					data, errno, safe_strerror(errno));
				return -1;
			}
		}
	}

	frr_with_privs (&pimd_privs) {
		opt = enable ? MRT_INIT : MRT_DONE;
		/*
		 * *BSD *cares* about what value we pass down
		 * here
		 */
		data = 1;
		err = setsockopt(pim->mroute_socket, PIM_IPPROTO, opt, &data,
				 data_len);
		if (err) {
			zlog_warn(
				"%s %s: failure: setsockopt(fd=%d,PIM_IPPROTO,%s=%d): errno=%d: %s",
				__FILE__, __func__, pim->mroute_socket,
				enable ? "MRT_INIT" : "MRT_DONE", data, errno,
				safe_strerror(errno));
			return -1;
		}
	}

#if defined(HAVE_IP_PKTINFO)
	if (enable) {
		/* Linux and Solaris IP_PKTINFO */
		data = 1;
		if (setsockopt(pim->mroute_socket, PIM_IPPROTO, IP_PKTINFO,
			       &data, data_len)) {
			zlog_warn(
				"Could not set IP_PKTINFO on socket fd=%d: errno=%d: %s",
				pim->mroute_socket, errno,
				safe_strerror(errno));
		}
	}
#endif

#if PIM_IPV == 6
	if (enable) {
		/* Linux and Solaris IPV6_PKTINFO */
		data = 1;
		if (setsockopt(pim->mroute_socket, PIM_IPPROTO,
			       IPV6_RECVPKTINFO, &data, data_len)) {
			zlog_warn(
				"Could not set IPV6_RECVPKTINFO on socket fd=%d: errno=%d: %s",
				pim->mroute_socket, errno,
				safe_strerror(errno));
		}
	}
#endif
	setsockopt_so_recvbuf(pim->mroute_socket, 1024 * 1024 * 8);

	if (set_nonblocking(pim->mroute_socket) < 0) {
		zlog_warn(
			"Could not set non blocking on socket fd=%d: errno=%d: %s",
			pim->mroute_socket, errno, safe_strerror(errno));
		return -1;
	}

	if (enable) {
#if defined linux
		int upcalls = GMMSG_WRVIFWHOLE;
		opt = MRT_PIM;

		err = setsockopt(pim->mroute_socket, PIM_IPPROTO, opt, &upcalls,
				 sizeof(upcalls));
		if (err) {
			zlog_warn(
				"Failure to register for VIFWHOLE and WRONGVIF upcalls %d %s",
				errno, safe_strerror(errno));
			return -1;
		}
#else
		zlog_warn(
			"PIM-SM will not work properly on this platform, until the ability to receive the WRVIFWHOLE upcall");
#endif
	}

	return 0;
}

static const char *const gmmsgtype2str[GMMSG_WRVIFWHOLE + 1] = {
	"<unknown_upcall?>", "NOCACHE", "WRONGVIF", "WHOLEPKT", "WRVIFWHOLE"};


int pim_mroute_msg_nocache(int fd, struct interface *ifp, const kernmsg *msg)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct pim_upstream *up;
	pim_sgaddr sg;
	bool desync = false;

	memset(&sg, 0, sizeof(sg));
	sg.src = msg->msg_im_src;
	sg.grp = msg->msg_im_dst;


	if (!pim_ifp || !pim_ifp->pim_enable) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug(
				"%s: %s on interface, dropping packet to %pSG",
				ifp->name,
				!pim_ifp ? "Multicast not enabled"
					 : "PIM not enabled",
				&sg);
		return 0;
	}

	if (!pim_is_grp_ssm(pim_ifp->pim, sg.grp)) {
		/* for ASM, check that we have enough information (i.e. path
		 * to RP) to make a decision on what to do with this packet.
		 *
		 * for SSM, this is meaningless, everything is join-driven,
		 * and for NOCACHE we need to install an empty OIL MFC entry
		 * so the kernel doesn't keep nagging us.
		 */
		struct pim_rpf *rpg;

		rpg = RP(pim_ifp->pim, msg->msg_im_dst);
		if (!rpg) {
			if (PIM_DEBUG_MROUTE)
				zlog_debug("%s: no RPF for packet to %pSG",
					   ifp->name, &sg);
			return 0;
		}
		if (pim_rpf_addr_is_inaddr_any(rpg)) {
			if (PIM_DEBUG_MROUTE)
				zlog_debug("%s: null RPF for packet to %pSG",
					   ifp->name, &sg);
			return 0;
		}
	}

	/*
	 * If we've received a multicast packet that isn't connected to
	 * us
	 */
	if (!pim_if_connected_to_source(ifp, msg->msg_im_src)) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug(
				"%s: incoming packet to %pSG from non-connected source",
				ifp->name, &sg);
		return 0;
	}

	if (!(PIM_I_am_DR(pim_ifp))) {
		/* unlike the other debug messages, this one is further in the
		 * "normal operation" category and thus under _DETAIL
		 */
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug(
				"%s: not DR on interface, not forwarding traffic for %pSG",
				ifp->name, &sg);

		/*
		 * We are not the DR, but we are still receiving packets
		 * Let's blackhole those packets for the moment
		 * As that they will be coming up to the cpu
		 * and causing us to consider them.
		 *
		 * This *will* create a dangling channel_oil
		 * that I see no way to get rid of.  Just noting
		 * this for future reference.
		 */
		up = pim_upstream_find_or_add(
			&sg, ifp, PIM_UPSTREAM_FLAG_MASK_SRC_NOCACHE, __func__);
		pim_upstream_mroute_add(up->channel_oil, __func__);

		return 0;
	}

	up = pim_upstream_find_or_add(&sg, ifp, PIM_UPSTREAM_FLAG_MASK_FHR,
				      __func__);
	if (up->channel_oil->installed) {
		zlog_warn(
			"%s: NOCACHE for %pSG, MFC entry disappeared - reinstalling",
			ifp->name, &sg);
		desync = true;
	}

	/*
	 * I moved this debug till after the actual add because
	 * I want to take advantage of the up->sg_str being filled in.
	 */
	if (PIM_DEBUG_MROUTE) {
		zlog_debug("%s: Adding a Route %s for WHOLEPKT consumption",
			   __func__, up->sg_str);
	}

	PIM_UPSTREAM_FLAG_SET_SRC_STREAM(up->flags);
	pim_upstream_keep_alive_timer_start(up, pim_ifp->pim->keep_alive_time);

	up->channel_oil->cc.pktcnt++;
	// resolve mfcc_parent prior to mroute_add in channel_add_oif
	if (up->rpf.source_nexthop.interface &&
	    *oil_incoming_vif(up->channel_oil) >= MAXVIFS) {
		pim_upstream_mroute_iif_update(up->channel_oil, __func__);
	}
	pim_register_join(up);
	/* if we have receiver, inherit from parent */
	pim_upstream_inherited_olist_decide(pim_ifp->pim, up);

	/* we just got NOCACHE from the kernel, so...  MFC is not in the
	 * kernel for some reason or another.  Try installing again.
	 */
	if (desync)
		pim_upstream_mroute_update(up->channel_oil, __func__);
	return 0;
}

int pim_mroute_msg_wholepkt(int fd, struct interface *ifp, const char *buf,
			    size_t len)
{
	struct pim_interface *pim_ifp;
	pim_sgaddr sg;
	struct pim_rpf *rpg;
	const ipv_hdr *ip_hdr;
	struct pim_upstream *up;

	pim_ifp = ifp->info;

	ip_hdr = (const ipv_hdr *)buf;

	memset(&sg, 0, sizeof(sg));
	sg.src = IPV_SRC(ip_hdr);
	sg.grp = IPV_DST(ip_hdr);

	up = pim_upstream_find(pim_ifp->pim, &sg);
	if (!up) {
		pim_sgaddr star = sg;
		star.src = PIMADDR_ANY;

		up = pim_upstream_find(pim_ifp->pim, &star);

		if (up && PIM_UPSTREAM_FLAG_TEST_CAN_BE_LHR(up->flags)) {
			up = pim_upstream_add(pim_ifp->pim, &sg, ifp,
					      PIM_UPSTREAM_FLAG_MASK_SRC_LHR,
					      __func__, NULL);
			if (!up) {
				if (PIM_DEBUG_MROUTE)
					zlog_debug(
						"%s: Unable to create upstream information for %pSG",
						__func__, &sg);
				return 0;
			}
			pim_upstream_keep_alive_timer_start(
				up, pim_ifp->pim->keep_alive_time);
			pim_upstream_inherited_olist(pim_ifp->pim, up);
			pim_upstream_update_join_desired(pim_ifp->pim, up);

			if (PIM_DEBUG_MROUTE)
				zlog_debug("%s: Creating %s upstream on LHR",
					   __func__, up->sg_str);
			return 0;
		}
		if (PIM_DEBUG_MROUTE_DETAIL) {
			zlog_debug(
				"%s: Unable to find upstream channel WHOLEPKT%pSG",
				__func__, &sg);
		}
		return 0;
	}

	if (!up->rpf.source_nexthop.interface) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: up %s RPF is not present", __func__,
				   up->sg_str);
		return 0;
	}

	pim_ifp = up->rpf.source_nexthop.interface->info;

	rpg = pim_ifp ? RP(pim_ifp->pim, sg.grp) : NULL;

	if ((pim_rpf_addr_is_inaddr_any(rpg)) || (!pim_ifp) ||
	    (!(PIM_I_am_DR(pim_ifp)))) {
		if (PIM_DEBUG_MROUTE) {
			zlog_debug("%s: Failed Check send packet", __func__);
		}
		return 0;
	}

	/*
	 * If we've received a register suppress
	 */
	if (!up->t_rs_timer) {
		if (pim_is_grp_ssm(pim_ifp->pim, sg.grp)) {
			if (PIM_DEBUG_PIM_REG)
				zlog_debug(
					"%pSG register forward skipped as group is SSM",
					&sg);
			return 0;
		}

		if (!PIM_UPSTREAM_FLAG_TEST_FHR(up->flags)) {
			if (PIM_DEBUG_PIM_REG)
				zlog_debug(
					"%s register forward skipped, not FHR",
					up->sg_str);
			return 0;
		}

		pim_register_send((uint8_t *)buf + sizeof(ipv_hdr),
				  len - sizeof(ipv_hdr),
				  pim_ifp->primary_address, rpg, 0, up);
	}
	return 0;
}

int pim_mroute_msg_wrongvif(int fd, struct interface *ifp, const kernmsg *msg)
{
	struct pim_ifchannel *ch;
	struct pim_interface *pim_ifp;
	pim_sgaddr sg;

	memset(&sg, 0, sizeof(sg));
	sg.src = msg->msg_im_src;
	sg.grp = msg->msg_im_dst;

	/*
	  Send Assert(S,G) on iif as response to WRONGVIF kernel upcall.

	  RFC 4601 4.8.2.  PIM-SSM-Only Routers

	  iif is the incoming interface of the packet.
	  if (iif is in inherited_olist(S,G)) {
	  send Assert(S,G) on iif
	  }
	*/

	if (!ifp) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug(
				"%s: WRONGVIF (S,G)=%pSG could not find input interface for input_vif_index=%d",
				__func__, &sg, msg->msg_im_vif);
		return -1;
	}

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug(
				"%s: WRONGVIF (S,G)=%pSG multicast not enabled on interface %s",
				__func__, &sg, ifp->name);
		return -2;
	}

	ch = pim_ifchannel_find(ifp, &sg);
	if (!ch) {
		pim_sgaddr star_g = sg;
		if (PIM_DEBUG_MROUTE)
			zlog_debug(
				"%s: WRONGVIF (S,G)=%pSG could not find channel on interface %s",
				__func__, &sg, ifp->name);

		star_g.src = PIMADDR_ANY;
		ch = pim_ifchannel_find(ifp, &star_g);
		if (!ch) {
			if (PIM_DEBUG_MROUTE)
				zlog_debug(
					"%s: WRONGVIF (*,G)=%pSG could not find channel on interface %s",
					__func__, &star_g, ifp->name);
			return -3;
		}
	}

	/*
	  RFC 4601: 4.6.1.  (S,G) Assert Message State Machine

	  Transitions from NoInfo State

	  An (S,G) data packet arrives on interface I, AND
	  CouldAssert(S,G,I)==TRUE An (S,G) data packet arrived on an
	  downstream interface that is in our (S,G) outgoing interface
	  list.  We optimistically assume that we will be the assert
	  winner for this (S,G), and so we transition to the "I am Assert
	  Winner" state and perform Actions A1 (below), which will
	  initiate the assert negotiation for (S,G).
	*/

	if (ch->ifassert_state != PIM_IFASSERT_NOINFO) {
		if (PIM_DEBUG_MROUTE) {
			zlog_debug(
				"%s: WRONGVIF (S,G)=%s channel is not on Assert NoInfo state for interface %s",
				__func__, ch->sg_str, ifp->name);
		}
		return -4;
	}

	if (!PIM_IF_FLAG_TEST_COULD_ASSERT(ch->flags)) {
		if (PIM_DEBUG_MROUTE) {
			zlog_debug(
				"%s: WRONGVIF (S,G)=%s interface %s is not downstream for channel",
				__func__, ch->sg_str, ifp->name);
		}
		return -5;
	}

	if (assert_action_a1(ch)) {
		if (PIM_DEBUG_MROUTE) {
			zlog_debug(
				"%s: WRONGVIF (S,G)=%s assert_action_a1 failure on interface %s",
				__func__, ch->sg_str, ifp->name);
		}
		return -6;
	}

	return 0;
}

int pim_mroute_msg_wrvifwhole(int fd, struct interface *ifp, const char *buf,
			      size_t len)
{
	const ipv_hdr *ip_hdr = (const ipv_hdr *)buf;
	struct pim_interface *pim_ifp;
	struct pim_instance *pim;
	struct pim_ifchannel *ch;
	struct pim_upstream *up;
	pim_sgaddr star_g;
	pim_sgaddr sg;

	pim_ifp = ifp->info;

	memset(&sg, 0, sizeof(sg));
	sg.src = IPV_SRC(ip_hdr);
	sg.grp = IPV_DST(ip_hdr);

	ch = pim_ifchannel_find(ifp, &sg);
	if (ch) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug(
				"WRVIFWHOLE (S,G)=%s found ifchannel on interface %s",
				ch->sg_str, ifp->name);
		return -1;
	}

	star_g = sg;
	star_g.src = PIMADDR_ANY;

	pim = pim_ifp->pim;
	/*
	 * If the incoming interface is the pimreg, then
	 * we know the callback is associated with a pim register
	 * packet and there is nothing to do here as that
	 * normal pim processing will see the packet and allow
	 * us to do the right thing.
	 */
	if (ifp == pim->regiface) {
		return 0;
	}

	up = pim_upstream_find(pim_ifp->pim, &sg);
	if (up) {
		struct pim_upstream *parent;
		struct pim_nexthop source;
		struct pim_rpf *rpf = RP(pim_ifp->pim, sg.grp);

		/* No RPF or No RPF interface or No mcast on RPF interface */
		if (!rpf || !rpf->source_nexthop.interface ||
		    !rpf->source_nexthop.interface->info)
			return 0;

		/*
		 * If we have received a WRVIFWHOLE and are at this
		 * point, we could be receiving the packet on the *,G
		 * tree, let's check and if so we can safely drop
		 * it.
		 */
		parent = pim_upstream_find(pim_ifp->pim, &star_g);
		if (parent && parent->rpf.source_nexthop.interface == ifp)
			return 0;

		pim_ifp = rpf->source_nexthop.interface->info;

		memset(&source, 0, sizeof(source));
		/*
		 * If we are the fhr that means we are getting a callback during
		 * the pimreg period, so I believe we can ignore this packet
		 */
		if (!PIM_UPSTREAM_FLAG_TEST_FHR(up->flags)) {
			/*
			 * No if channel, but upstream we are at the RP.
			 *
			 * This could be a anycast RP too and we may
			 * not have received a register packet from
			 * the source here at all.  So gracefully
			 * bow out of doing a nexthop lookup and
			 * setting the SPTBIT to true
			 */
			if (!(pim_addr_is_any(up->upstream_register)) &&
			    pim_nexthop_lookup(pim_ifp->pim, &source,
					       up->upstream_register, 0)) {
				pim_register_stop_send(source.interface, &sg,
						       pim_ifp->primary_address,
						       up->upstream_register);
				up->sptbit = PIM_UPSTREAM_SPTBIT_TRUE;
			}

			pim_upstream_inherited_olist(pim_ifp->pim, up);
			if (!up->channel_oil->installed)
				pim_upstream_mroute_add(up->channel_oil,
							__func__);
		} else {
			if (I_am_RP(pim_ifp->pim, up->sg.grp)) {
				if (pim_nexthop_lookup(pim_ifp->pim, &source,
						       up->upstream_register,
						       0))
					pim_register_stop_send(
						source.interface, &sg,
						pim_ifp->primary_address,
						up->upstream_register);
				up->sptbit = PIM_UPSTREAM_SPTBIT_TRUE;
			} else {
				/*
				 * At this point pimd is connected to
				 * the source, it has a parent, we are not
				 * the RP  and the SPTBIT should be set
				 * since we know *the* S,G is on the SPT.
				 * The first time this happens, let's cause
				 * an immediate join to go out so that
				 * the RP can trim this guy immediately
				 * if necessary, instead of waiting
				 * one join/prune send cycle
				 */
				if (up->sptbit != PIM_UPSTREAM_SPTBIT_TRUE &&
				    up->parent &&
				    up->rpf.source_nexthop.interface !=
					    up->parent->rpf.source_nexthop
						    .interface) {
					up->sptbit = PIM_UPSTREAM_SPTBIT_TRUE;
					pim_jp_agg_single_upstream_send(
						&up->parent->rpf, up->parent,
						true);
				}
			}
			pim_upstream_keep_alive_timer_start(
				up, pim_ifp->pim->keep_alive_time);
			pim_upstream_inherited_olist(pim_ifp->pim, up);
			pim_mroute_msg_wholepkt(fd, ifp, buf, len);
		}
		return 0;
	}

	pim_ifp = ifp->info;
	if (pim_if_connected_to_source(ifp, sg.src)) {
		up = pim_upstream_add(pim_ifp->pim, &sg, ifp,
				      PIM_UPSTREAM_FLAG_MASK_FHR, __func__,
				      NULL);
		if (!up) {
			if (PIM_DEBUG_MROUTE)
				zlog_debug(
					"%pSG: WRONGVIF%s unable to create upstream on interface",
					&sg, ifp->name);
			return -2;
		}
		PIM_UPSTREAM_FLAG_SET_SRC_STREAM(up->flags);
		pim_upstream_keep_alive_timer_start(
			up, pim_ifp->pim->keep_alive_time);
		up->channel_oil->cc.pktcnt++;
		pim_register_join(up);
		pim_upstream_inherited_olist(pim_ifp->pim, up);
		if (!up->channel_oil->installed)
			pim_upstream_mroute_add(up->channel_oil, __func__);

		// Send the packet to the RP
		pim_mroute_msg_wholepkt(fd, ifp, buf, len);
	} else {
		up = pim_upstream_add(pim_ifp->pim, &sg, ifp,
				      PIM_UPSTREAM_FLAG_MASK_SRC_NOCACHE,
				      __func__, NULL);
		if (!up->channel_oil->installed)
			pim_upstream_mroute_add(up->channel_oil, __func__);
	}

	return 0;
}

#if PIM_IPV == 4
static int process_igmp_packet(struct pim_instance *pim, const char *buf,
			       size_t buf_size, ifindex_t ifindex)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	struct in_addr ifaddr;
	struct gm_sock *igmp;
	const struct prefix *connected_src;
	const struct ip *ip_hdr = (const struct ip *)buf;

	/* We have the IP packet but we do not know which interface this
	 * packet was
	 * received on. Find the interface that is on the same subnet as
	 * the source
	 * of the IP packet.
	 */
	ifp = if_lookup_by_index(ifindex, pim->vrf->vrf_id);

	if (!ifp || !ifp->info)
		return 0;

	connected_src = pim_if_connected_to_source(ifp, ip_hdr->ip_src);

	if (!connected_src && !pim_addr_is_any(ip_hdr->ip_src)) {
		if (PIM_DEBUG_GM_PACKETS) {
			zlog_debug(
				"Recv IGMP packet on interface: %s from a non-connected source: %pI4",
				ifp->name, &ip_hdr->ip_src);
		}
		return 0;
	}

	pim_ifp = ifp->info;
	ifaddr = connected_src ? connected_src->u.prefix4
			       : pim_ifp->primary_address;
	igmp = pim_igmp_sock_lookup_ifaddr(pim_ifp->gm_socket_list, ifaddr);

	if (PIM_DEBUG_GM_PACKETS) {
		zlog_debug(
			"%s(%s): igmp kernel upcall on %s(%p) for %pI4 -> %pI4",
			__func__, pim->vrf->name, ifp->name, igmp,
			&ip_hdr->ip_src, &ip_hdr->ip_dst);
	}
	if (igmp)
		pim_igmp_packet(igmp, (char *)buf, buf_size);
	else if (PIM_DEBUG_GM_PACKETS)
		zlog_debug(
			"No IGMP socket on interface: %s with connected source: %pI4",
			ifp->name, &ifaddr);

	return 0;
}
#endif

int pim_mroute_msg(struct pim_instance *pim, const char *buf, size_t buf_size,
		   ifindex_t ifindex)
{
	struct interface *ifp;
	const ipv_hdr *ip_hdr;
	const kernmsg *msg;

	if (buf_size < (int)sizeof(ipv_hdr))
		return 0;

	ip_hdr = (const ipv_hdr *)buf;

#if PIM_IPV == 4
	if (ip_hdr->ip_p == IPPROTO_IGMP) {
		process_igmp_packet(pim, buf, buf_size, ifindex);
	} else if (ip_hdr->ip_p) {
		if (PIM_DEBUG_MROUTE_DETAIL) {
			zlog_debug(
				"%s: no kernel upcall proto=%d src: %pI4 dst: %pI4 msg_size=%ld",
				__func__, ip_hdr->ip_p, &ip_hdr->ip_src,
				&ip_hdr->ip_dst, (long int)buf_size);
		}

	} else {
#else

	if ((ip_hdr->ip6_vfc & 0xf) == 0) {
#endif
		msg = (const kernmsg *)buf;

		ifp = pim_if_find_by_vif_index(pim, msg->msg_im_vif);

		if (!ifp)
			return 0;
		if (PIM_DEBUG_MROUTE) {
#if PIM_IPV == 4
			zlog_debug(
				"%s: pim kernel upcall %s type=%d ip_p=%d from fd=%d for (S,G)=(%pI4,%pI4) on %s vifi=%d  size=%ld",
				__func__, gmmsgtype2str[msg->msg_im_msgtype],
				msg->msg_im_msgtype, ip_hdr->ip_p,
				pim->mroute_socket, &msg->msg_im_src,
				&msg->msg_im_dst, ifp->name, msg->msg_im_vif,
				(long int)buf_size);
#else
			zlog_debug(
				"%s: pim kernel upcall %s type=%d ip_p=%d from fd=%d for (S,G)=(%pI6,%pI6) on %s vifi=%d  size=%ld",
				__func__, gmmsgtype2str[msg->msg_im_msgtype],
				msg->msg_im_msgtype, ip_hdr->ip6_nxt,
				pim->mroute_socket, &msg->msg_im_src,
				&msg->msg_im_dst, ifp->name, msg->msg_im_vif,
				(long int)buf_size);
#endif
		}

		switch (msg->msg_im_msgtype) {
		case GMMSG_WRONGVIF:
			return pim_mroute_msg_wrongvif(pim->mroute_socket, ifp,
						       msg);
		case GMMSG_NOCACHE:
			return pim_mroute_msg_nocache(pim->mroute_socket, ifp,
						      msg);
		case GMMSG_WHOLEPKT:
			return pim_mroute_msg_wholepkt(pim->mroute_socket, ifp,
						       (const char *)msg,
						       buf_size);
		case GMMSG_WRVIFWHOLE:
			return pim_mroute_msg_wrvifwhole(pim->mroute_socket,
							 ifp, (const char *)msg,
							 buf_size);
		default:
			break;
		}
	}

	return 0;
}

static void mroute_read(struct event *t)
{
	struct pim_instance *pim;
	static long long count;
	char buf[10000];
	int cont = 1;
	int rd;
	ifindex_t ifindex;
	pim = EVENT_ARG(t);

	while (cont) {
		rd = pim_socket_recvfromto(pim->mroute_socket, (uint8_t *)buf,
					   sizeof(buf), NULL, NULL, NULL, NULL,
					   &ifindex);
		if (rd <= 0) {
			if (errno == EINTR)
				continue;
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;

			zlog_warn(
				"%s: failure reading rd=%d: fd=%d: errno=%d: %s",
				__func__, rd, pim->mroute_socket, errno,
				safe_strerror(errno));
			goto done;
		}

		pim_mroute_msg(pim, buf, rd, ifindex);

		count++;
		if (count % router->packet_process == 0)
			cont = 0;
	}
/* Keep reading */
done:
	mroute_read_on(pim);

	return;
}

static void mroute_read_on(struct pim_instance *pim)
{
	event_add_read(router->master, mroute_read, pim, pim->mroute_socket,
		       &pim->thread);
}

static void mroute_read_off(struct pim_instance *pim)
{
	EVENT_OFF(pim->thread);
}

int pim_mroute_socket_enable(struct pim_instance *pim)
{
	int fd;

	frr_with_privs(&pimd_privs) {

#if PIM_IPV == 4
		fd = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);
#else
		fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
#endif
		if (fd < 0) {
			zlog_warn("Could not create mroute socket: errno=%d: %s",
				  errno,
				  safe_strerror(errno));
			return -2;
		}

#if PIM_IPV == 6
		struct icmp6_filter filter[1];
		int ret;

		/* Unlike IPv4, this socket is not used for MLD, so just drop
		 * everything with an empty ICMP6 filter.  Otherwise we get
		 * all kinds of garbage here, possibly even non-multicast
		 * related ICMPv6 traffic (e.g. ping)
		 *
		 * (mroute kernel upcall "packets" are injected directly on the
		 * socket, this sockopt -or any other- has no effect on them)
		 */
		ICMP6_FILTER_SETBLOCKALL(filter);
		ret = setsockopt(fd, SOL_ICMPV6, ICMP6_FILTER, filter,
				 sizeof(filter));
		if (ret)
			zlog_err(
				"(VRF %s) failed to set mroute control filter: %m",
				pim->vrf->name);
#endif

#ifdef SO_BINDTODEVICE
		if (pim->vrf->vrf_id != VRF_DEFAULT
		    && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
				  pim->vrf->name, strlen(pim->vrf->name))) {
			zlog_warn("Could not setsockopt SO_BINDTODEVICE: %s",
				  safe_strerror(errno));
			close(fd);
			return -3;
		}
#endif

	}

	pim->mroute_socket = fd;
	if (pim_mroute_set(pim, 1)) {
		zlog_warn(
			"Could not enable mroute on socket fd=%d: errno=%d: %s",
			fd, errno, safe_strerror(errno));
		close(fd);
		pim->mroute_socket = -1;
		return -3;
	}

	pim->mroute_socket_creation = pim_time_monotonic_sec();

	mroute_read_on(pim);

	return 0;
}

int pim_mroute_socket_disable(struct pim_instance *pim)
{
	if (pim_mroute_set(pim, 0)) {
		zlog_warn(
			"Could not disable mroute on socket fd=%d: errno=%d: %s",
			pim->mroute_socket, errno, safe_strerror(errno));
		return -2;
	}

	if (close(pim->mroute_socket)) {
		zlog_warn("Failure closing mroute socket: fd=%d errno=%d: %s",
			  pim->mroute_socket, errno, safe_strerror(errno));
		return -3;
	}

	mroute_read_off(pim);
	pim->mroute_socket = -1;

	return 0;
}

/*
  For each network interface (e.g., physical or a virtual tunnel) that
  would be used for multicast forwarding, a corresponding multicast
  interface must be added to the kernel.
 */
int pim_mroute_add_vif(struct interface *ifp, pim_addr ifaddr,
		       unsigned char flags)
{
	struct pim_interface *pim_ifp = ifp->info;
	pim_vifctl vc;
	int err;

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: Add Vif %d (%s[%s])", __func__,
			   pim_ifp->mroute_vif_index, ifp->name,
			   pim_ifp->pim->vrf->name);

	memset(&vc, 0, sizeof(vc));
	vc.vc_vifi = pim_ifp->mroute_vif_index;
#if PIM_IPV == 4
#ifdef VIFF_USE_IFINDEX
	vc.vc_lcl_ifindex = ifp->ifindex;
#else
	if (ifaddr.s_addr == INADDR_ANY) {
		zlog_warn(
			"%s: unnumbered interfaces are not supported on this platform",
			__func__);
		return -1;
	}
	memcpy(&vc.vc_lcl_addr, &ifaddr, sizeof(vc.vc_lcl_addr));
#endif
#else
	vc.vc_pifi = ifp->ifindex;
#endif
	vc.vc_flags = flags;
	vc.vc_threshold = PIM_MROUTE_MIN_TTL;
	vc.vc_rate_limit = 0;

#if PIM_IPV == 4
#ifdef PIM_DVMRP_TUNNEL
	if (vc.vc_flags & VIFF_TUNNEL) {
		memcpy(&vc.vc_rmt_addr, &vif_remote_addr,
		       sizeof(vc.vc_rmt_addr));
	}
#endif
#endif

	err = setsockopt(pim_ifp->pim->mroute_socket, PIM_IPPROTO, MRT_ADD_VIF,
			 (void *)&vc, sizeof(vc));
	if (err) {
		zlog_warn(
			"%s: failure: setsockopt(fd=%d,PIM_IPPROTO,MRT_ADD_VIF,vif_index=%d,ifaddr=%pPAs,flag=%d): errno=%d: %s",
			__func__, pim_ifp->pim->mroute_socket, ifp->ifindex,
			&ifaddr, flags, errno, safe_strerror(errno));
		return -2;
	}

	return 0;
}

int pim_mroute_del_vif(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;
	pim_vifctl vc;
	int err;

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: Del Vif %d (%s[%s])", __func__,
			   pim_ifp->mroute_vif_index, ifp->name,
			   pim_ifp->pim->vrf->name);

	memset(&vc, 0, sizeof(vc));
	vc.vc_vifi = pim_ifp->mroute_vif_index;

	err = setsockopt(pim_ifp->pim->mroute_socket, PIM_IPPROTO, MRT_DEL_VIF,
			 (void *)&vc, sizeof(vc));
	if (err) {
		zlog_warn(
			"%s %s: failure: setsockopt(fd=%d,PIM_IPPROTO,MRT_DEL_VIF,vif_index=%d): errno=%d: %s",
			__FILE__, __func__, pim_ifp->pim->mroute_socket,
			pim_ifp->mroute_vif_index, errno, safe_strerror(errno));
		return -2;
	}

	return 0;
}

/*
 * Prevent creating MFC entry with OIF=IIF.
 *
 * This is a protection against implementation mistakes.
 *
 * PIM protocol implicitely ensures loopfree multicast topology.
 *
 * IGMP must be protected against adding looped MFC entries created
 * by both source and receiver attached to the same interface. See
 * TODO T22.
 * We shall allow igmp to create upstream when it is DR for the intf.
 * Assume RP reachable via non DR.
 */
bool pim_mroute_allow_iif_in_oil(struct channel_oil *c_oil,
		int oif_index)
{
#ifdef PIM_ENFORCE_LOOPFREE_MFC
	struct interface *ifp_out;
	struct pim_interface *pim_ifp;

	if (c_oil->up &&
		PIM_UPSTREAM_FLAG_TEST_ALLOW_IIF_IN_OIL(c_oil->up->flags))
		return true;

	ifp_out = pim_if_find_by_vif_index(c_oil->pim, oif_index);
	if (!ifp_out)
		return false;
	pim_ifp = ifp_out->info;
	if (!pim_ifp)
		return false;
	if ((c_oil->oif_flags[oif_index] & PIM_OIF_FLAG_PROTO_GM) &&
	    PIM_I_am_DR(pim_ifp))
		return true;

	return false;
#else
	return true;
#endif
}

static inline void pim_mroute_copy(struct channel_oil *out,
				   struct channel_oil *in)
{
	int i;

	*oil_origin(out) = *oil_origin(in);
	*oil_mcastgrp(out) = *oil_mcastgrp(in);
	*oil_incoming_vif(out) = *oil_incoming_vif(in);

	for (i = 0; i < MAXVIFS; ++i) {
		if (*oil_incoming_vif(out) == i &&
		    !pim_mroute_allow_iif_in_oil(in, i)) {
			oil_if_set(out, i, 0);
			continue;
		}

		if (in->oif_flags[i] & PIM_OIF_FLAG_MUTE)
			oil_if_set(out, i, 0);
		else
			oil_if_set(out, i, oil_if_has(in, i));
	}
}

/* This function must not be called directly 0
 * use pim_upstream_mroute_add or pim_static_mroute_add instead
 */
static int pim_mroute_add(struct channel_oil *c_oil, const char *name)
{
	struct pim_instance *pim = c_oil->pim;
	struct channel_oil tmp_oil[1] = { };
	int err;

	pim->mroute_add_last = pim_time_monotonic_sec();
	++pim->mroute_add_events;

	/* Copy the oil to a temporary structure to fixup (without need to
	 * later restore) before sending the mroute add to the dataplane
	 */
	pim_mroute_copy(tmp_oil, c_oil);

	/* The linux kernel *expects* the incoming
	 * vif to be part of the outgoing list
	 * in the case of a (*,G).
	 */
	if (pim_addr_is_any(*oil_origin(c_oil))) {
		oil_if_set(tmp_oil, *oil_incoming_vif(c_oil), 1);
	}

	/*
	 * If we have an unresolved cache entry for the S,G
	 * it is owned by the pimreg for the incoming IIF
	 * So set pimreg as the IIF temporarily to cause
	 * the packets to be forwarded.  Then set it
	 * to the correct IIF afterwords.
	 */
	if (!c_oil->installed && !pim_addr_is_any(*oil_origin(c_oil)) &&
	    *oil_incoming_vif(c_oil) != 0) {
		*oil_incoming_vif(tmp_oil) = 0;
	}
	/* For IPv6 MRT_ADD_MFC is defined to MRT6_ADD_MFC */
	err = setsockopt(pim->mroute_socket, PIM_IPPROTO, MRT_ADD_MFC,
			 &tmp_oil->oil, sizeof(tmp_oil->oil));

	if (!err && !c_oil->installed && !pim_addr_is_any(*oil_origin(c_oil)) &&
	    *oil_incoming_vif(c_oil) != 0) {
		*oil_incoming_vif(tmp_oil) = *oil_incoming_vif(c_oil);
		err = setsockopt(pim->mroute_socket, PIM_IPPROTO, MRT_ADD_MFC,
				 &tmp_oil->oil, sizeof(tmp_oil->oil));
	}

	if (err) {
		zlog_warn(
			"%s %s: failure: setsockopt(fd=%d,PIM_IPPROTO,MRT_ADD_MFC): errno=%d: %s",
			__FILE__, __func__, pim->mroute_socket, errno,
			safe_strerror(errno));
		return -2;
	}

	if (PIM_DEBUG_MROUTE) {
		char buf[1000];
		zlog_debug("%s(%s), vrf %s Added Route: %s", __func__, name,
			   pim->vrf->name,
			   pim_channel_oil_dump(c_oil, buf, sizeof(buf)));
	}

	if (!c_oil->installed) {
		c_oil->installed = 1;
		c_oil->mroute_creation = pim_time_monotonic_sec();
	}

	return 0;
}

static int pim_upstream_get_mroute_iif(struct channel_oil *c_oil,
		const char *name)
{
	vifi_t iif = MAXVIFS;
	struct interface *ifp = NULL;
	struct pim_interface *pim_ifp;
	struct pim_upstream *up = c_oil->up;

	if (up) {
		if (PIM_UPSTREAM_FLAG_TEST_USE_RPT(up->flags)) {
			if (up->parent)
				ifp = up->parent->rpf.source_nexthop.interface;
		} else {
			ifp = up->rpf.source_nexthop.interface;
		}
		if (ifp) {
			pim_ifp = (struct pim_interface *)ifp->info;
			if (pim_ifp)
				iif = pim_ifp->mroute_vif_index;
		}
	}
	return iif;
}

static int pim_upstream_mroute_update(struct channel_oil *c_oil,
		const char *name)
{
	char buf[1000];

	if (*oil_incoming_vif(c_oil) >= MAXVIFS) {
		/* the c_oil cannot be installed as a mroute yet */
		if (PIM_DEBUG_MROUTE)
			zlog_debug(
					"%s(%s) %s mroute not ready to be installed; %s",
					__func__, name,
					pim_channel_oil_dump(c_oil, buf,
						sizeof(buf)),
					c_oil->installed ?
					"uninstall" : "skip");
		/* if already installed flush it out as we are going to stop
		 * updates to it leaving it in a stale state
		 */
		if (c_oil->installed)
			pim_mroute_del(c_oil, name);
		/* return success (skipped) */
		return 0;
	}

	return pim_mroute_add(c_oil, name);
}

/* IIF associated with SGrpt entries are re-evaluated when the parent
 * (*,G) entries IIF changes
 */
static void pim_upstream_all_sources_iif_update(struct pim_upstream *up)
{
	struct listnode *listnode;
	struct pim_upstream *child;

	for (ALL_LIST_ELEMENTS_RO(up->sources, listnode,
				child)) {
		if (PIM_UPSTREAM_FLAG_TEST_USE_RPT(child->flags))
			pim_upstream_mroute_iif_update(child->channel_oil,
					__func__);
	}
}

/* In the case of "PIM state machine" added mroutes an upstream entry
 * must be present to decide on the SPT-forwarding vs. RPT-forwarding.
 */
int pim_upstream_mroute_add(struct channel_oil *c_oil, const char *name)
{
	vifi_t iif;

	iif = pim_upstream_get_mroute_iif(c_oil, name);

	if (*oil_incoming_vif(c_oil) != iif) {
		*oil_incoming_vif(c_oil) = iif;
		if (pim_addr_is_any(*oil_origin(c_oil)) &&
				c_oil->up)
			pim_upstream_all_sources_iif_update(c_oil->up);
	} else {
		*oil_incoming_vif(c_oil) = iif;
	}

	return pim_upstream_mroute_update(c_oil, name);
}

/* Look for IIF changes and update the dateplane entry only if the IIF
 * has changed.
 */
int pim_upstream_mroute_iif_update(struct channel_oil *c_oil, const char *name)
{
	vifi_t iif;
	char buf[1000];

	iif = pim_upstream_get_mroute_iif(c_oil, name);
	if (*oil_incoming_vif(c_oil) == iif) {
		/* no change */
		return 0;
	}
	*oil_incoming_vif(c_oil) = iif;

	if (pim_addr_is_any(*oil_origin(c_oil)) &&
			c_oil->up)
		pim_upstream_all_sources_iif_update(c_oil->up);

	if (PIM_DEBUG_MROUTE_DETAIL)
		zlog_debug("%s(%s) %s mroute iif update %d",
				__func__, name,
				pim_channel_oil_dump(c_oil, buf,
					sizeof(buf)), iif);
	/* XXX: is this hack needed? */
	c_oil->oil_inherited_rescan = 1;
	return pim_upstream_mroute_update(c_oil, name);
}

int pim_static_mroute_add(struct channel_oil *c_oil, const char *name)
{
	return pim_mroute_add(c_oil, name);
}

void pim_static_mroute_iif_update(struct channel_oil *c_oil,
				int input_vif_index,
				const char *name)
{
	if (*oil_incoming_vif(c_oil) == input_vif_index)
		return;

	*oil_incoming_vif(c_oil) = input_vif_index;
	if (input_vif_index == MAXVIFS)
		pim_mroute_del(c_oil, name);
	else
		pim_static_mroute_add(c_oil, name);
}

int pim_mroute_del(struct channel_oil *c_oil, const char *name)
{
	struct pim_instance *pim = c_oil->pim;
	int err;

	pim->mroute_del_last = pim_time_monotonic_sec();
	++pim->mroute_del_events;

	if (!c_oil->installed) {
		if (PIM_DEBUG_MROUTE) {
			char buf[1000];
			struct interface *iifp =
				pim_if_find_by_vif_index(pim, *oil_incoming_vif(
								      c_oil));

			zlog_debug("%s %s: incoming interface %s for route is %s not installed, do not need to send del req. ",
				   __FILE__, __func__,
				   iifp ? iifp->name : "Unknown",
				   pim_channel_oil_dump(c_oil, buf,
							sizeof(buf)));
		}
		return -2;
	}

	err = setsockopt(pim->mroute_socket, PIM_IPPROTO, MRT_DEL_MFC,
			 &c_oil->oil, sizeof(c_oil->oil));
	if (err) {
		if (PIM_DEBUG_MROUTE)
			zlog_warn(
				"%s %s: failure: setsockopt(fd=%d,PIM_IPPROTO,MRT_DEL_MFC): errno=%d: %s",
				__FILE__, __func__, pim->mroute_socket, errno,
				safe_strerror(errno));
		return -2;
	}

	if (PIM_DEBUG_MROUTE) {
		char buf[1000];
		zlog_debug("%s(%s), vrf %s Deleted Route: %s", __func__, name,
			   pim->vrf->name,
			   pim_channel_oil_dump(c_oil, buf, sizeof(buf)));
	}

	// Reset kernel installed flag
	c_oil->installed = 0;

	return 0;
}

void pim_mroute_update_counters(struct channel_oil *c_oil)
{
	struct pim_instance *pim = c_oil->pim;
	pim_sioc_sg_req sgreq;

	c_oil->cc.oldpktcnt = c_oil->cc.pktcnt;
	c_oil->cc.oldbytecnt = c_oil->cc.bytecnt;
	c_oil->cc.oldwrong_if = c_oil->cc.wrong_if;

	if (!c_oil->installed) {
		c_oil->cc.lastused = 100 * pim->keep_alive_time;
		if (PIM_DEBUG_MROUTE) {
			pim_sgaddr sg;

			sg.src = *oil_origin(c_oil);
			sg.grp = *oil_mcastgrp(c_oil);
			zlog_debug("Channel%pSG is not installed no need to collect data from kernel",
				   &sg);
		}
		return;
	}


	memset(&sgreq, 0, sizeof(sgreq));

	pim_zlookup_sg_statistics(c_oil);

#if PIM_IPV == 4
	sgreq.src = *oil_origin(c_oil);
	sgreq.grp = *oil_mcastgrp(c_oil);
#else
	sgreq.src = c_oil->oil.mf6cc_origin;
	sgreq.grp = c_oil->oil.mf6cc_mcastgrp;
#endif
	if (ioctl(pim->mroute_socket, PIM_SIOCGETSGCNT, &sgreq)) {
		pim_sgaddr sg;

		sg.src = *oil_origin(c_oil);
		sg.grp = *oil_mcastgrp(c_oil);

		zlog_warn(
			"ioctl(PIM_SIOCGETSGCNT=%lu) failure for (S,G)=%pSG: errno=%d: %s",
			(unsigned long)PIM_SIOCGETSGCNT, &sg, errno,
			safe_strerror(errno));
		return;
	}

	c_oil->cc.pktcnt = sgreq.pktcnt;
	c_oil->cc.bytecnt = sgreq.bytecnt;
	c_oil->cc.wrong_if = sgreq.wrong_if;
	return;
}
