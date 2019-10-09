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
#include "privs.h"
#include "if.h"
#include "prefix.h"
#include "vty.h"
#include "plist.h"
#include "sockopt.h"
#include "lib_errors.h"

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

static void mroute_read_on(struct pim_instance *pim);

static int pim_mroute_set(struct pim_instance *pim, int enable)
{
	int err;
	int opt, data;
	socklen_t data_len = sizeof(data);
	long flags;

	/*
	 * We need to create the VRF table for the pim mroute_socket
	 */
	if (pim->vrf_id != VRF_DEFAULT) {
		frr_with_privs(&pimd_privs) {

			data = pim->vrf->data.l.table_id;
			err = setsockopt(pim->mroute_socket, IPPROTO_IP,
					 MRT_TABLE,
					 &data, data_len);
			if (err) {
				zlog_warn(
					  "%s %s: failure: setsockopt(fd=%d,IPPROTO_IP, MRT_TABLE=%d): errno=%d: %s",
					  __FILE__, __PRETTY_FUNCTION__,
					  pim->mroute_socket, data, errno,
					  safe_strerror(errno));
				return -1;
			}

		}
	}

	frr_with_privs(&pimd_privs) {
		opt = enable ? MRT_INIT : MRT_DONE;
		/*
		 * *BSD *cares* about what value we pass down
		 * here
		 */
		data = 1;
		err = setsockopt(pim->mroute_socket, IPPROTO_IP,
				 opt, &data, data_len);
		if (err) {
			zlog_warn(
				  "%s %s: failure: setsockopt(fd=%d,IPPROTO_IP,%s=%d): errno=%d: %s",
				  __FILE__, __PRETTY_FUNCTION__,
				  pim->mroute_socket,
				  enable ? "MRT_INIT" : "MRT_DONE", data, errno,
				  safe_strerror(errno));
			return -1;
		}
	}

#if defined(HAVE_IP_PKTINFO)
	if (enable) {
		/* Linux and Solaris IP_PKTINFO */
		data = 1;
		if (setsockopt(pim->mroute_socket, IPPROTO_IP, IP_PKTINFO,
			       &data, data_len)) {
			zlog_warn(
				"Could not set IP_PKTINFO on socket fd=%d: errno=%d: %s",
				pim->mroute_socket, errno,
				safe_strerror(errno));
		}
	}
#endif

	setsockopt_so_recvbuf(pim->mroute_socket, 1024 * 1024 * 8);

	flags = fcntl(pim->mroute_socket, F_GETFL, 0);
	if (flags < 0) {
		zlog_warn("Could not get flags on socket fd:%d %d %s",
			  pim->mroute_socket, errno, safe_strerror(errno));
		close(pim->mroute_socket);
		return -1;
	}
	if (fcntl(pim->mroute_socket, F_SETFL, flags | O_NONBLOCK)) {
		zlog_warn("Could not set O_NONBLOCK on socket fd:%d %d %s",
			  pim->mroute_socket, errno, safe_strerror(errno));
		close(pim->mroute_socket);
		return -1;
	}

	if (enable) {
#if defined linux
		int upcalls = IGMPMSG_WRVIFWHOLE;
		opt = MRT_PIM;

		err = setsockopt(pim->mroute_socket, IPPROTO_IP, opt, &upcalls,
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

static const char *igmpmsgtype2str[IGMPMSG_WRVIFWHOLE + 1] = {
	"<unknown_upcall?>", "NOCACHE", "WRONGVIF", "WHOLEPKT", "WRVIFWHOLE"};

static int pim_mroute_msg_nocache(int fd, struct interface *ifp,
				  const struct igmpmsg *msg)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct pim_upstream *up;
	struct pim_rpf *rpg;
	struct prefix_sg sg;

	rpg = pim_ifp ? RP(pim_ifp->pim, msg->im_dst) : NULL;
	/*
	 * If the incoming interface is unknown OR
	 * the Interface type is SSM we don't need to
	 * do anything here
	 */
	if (!rpg || pim_rpf_addr_is_inaddr_none(rpg)) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug(
				"%s: Interface is not configured correctly to handle incoming packet: Could be !pim_ifp, !SM, !RP",
				__PRETTY_FUNCTION__);

		return 0;
	}

	/*
	 * If we've received a multicast packet that isn't connected to
	 * us
	 */
	if (!pim_if_connected_to_source(ifp, msg->im_src)) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug(
				"%s: Received incoming packet that doesn't originate on our seg",
				__PRETTY_FUNCTION__);
		return 0;
	}

	memset(&sg, 0, sizeof(struct prefix_sg));
	sg.src = msg->im_src;
	sg.grp = msg->im_dst;

	if (!(PIM_I_am_DR(pim_ifp))) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: Interface is not the DR blackholing incoming traffic for %s",
				   __PRETTY_FUNCTION__, pim_str_sg_dump(&sg));

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
			&sg, ifp, PIM_UPSTREAM_FLAG_MASK_SRC_NOCACHE,
			__PRETTY_FUNCTION__);
		pim_mroute_add(up->channel_oil, __PRETTY_FUNCTION__);

		return 0;
	}

	up = pim_upstream_find_or_add(&sg, ifp, PIM_UPSTREAM_FLAG_MASK_FHR,
				      __PRETTY_FUNCTION__);

	/*
	 * I moved this debug till after the actual add because
	 * I want to take advantage of the up->sg_str being filled in.
	 */
	if (PIM_DEBUG_MROUTE) {
		zlog_debug("%s: Adding a Route %s for WHOLEPKT consumption",
			   __PRETTY_FUNCTION__, up->sg_str);
	}

	PIM_UPSTREAM_FLAG_SET_SRC_STREAM(up->flags);
	pim_upstream_keep_alive_timer_start(up, pim_ifp->pim->keep_alive_time);

	up->channel_oil->cc.pktcnt++;
	PIM_UPSTREAM_FLAG_SET_FHR(up->flags);
	// resolve mfcc_parent prior to mroute_add in channel_add_oif
	if (up->rpf.source_nexthop.interface &&
	    up->channel_oil->oil.mfcc_parent >= MAXVIFS) {
		int vif_index = 0;
		vif_index = pim_if_find_vifindex_by_ifindex(
			pim_ifp->pim,
			up->rpf.source_nexthop.interface->ifindex);
		pim_channel_oil_change_iif(pim_ifp->pim, up->channel_oil,
					   vif_index, __PRETTY_FUNCTION__);
	}
	pim_register_join(up);

	return 0;
}

static int pim_mroute_msg_wholepkt(int fd, struct interface *ifp,
				   const char *buf)
{
	struct pim_interface *pim_ifp;
	struct prefix_sg sg;
	struct pim_rpf *rpg;
	const struct ip *ip_hdr;
	struct pim_upstream *up;

	pim_ifp = ifp->info;

	ip_hdr = (const struct ip *)buf;

	memset(&sg, 0, sizeof(struct prefix_sg));
	sg.src = ip_hdr->ip_src;
	sg.grp = ip_hdr->ip_dst;

	up = pim_upstream_find(pim_ifp->pim, &sg);
	if (!up) {
		struct prefix_sg star = sg;
		star.src.s_addr = INADDR_ANY;

		up = pim_upstream_find(pim_ifp->pim, &star);

		if (up && PIM_UPSTREAM_FLAG_TEST_SRC_IGMP(up->flags)) {
			up = pim_upstream_add(pim_ifp->pim, &sg, ifp,
					      PIM_UPSTREAM_FLAG_MASK_SRC_LHR,
					      __PRETTY_FUNCTION__, NULL);
			if (!up) {
				if (PIM_DEBUG_MROUTE)
					zlog_debug(
						"%s: Unable to create upstream information for %s",
						__PRETTY_FUNCTION__,
						pim_str_sg_dump(&sg));
				return 0;
			}
			pim_upstream_keep_alive_timer_start(
				up, pim_ifp->pim->keep_alive_time);
			pim_upstream_inherited_olist(pim_ifp->pim, up);
			pim_upstream_switch(pim_ifp->pim, up,
					    PIM_UPSTREAM_JOINED);

			if (PIM_DEBUG_MROUTE)
				zlog_debug("%s: Creating %s upstream on LHR",
					   __PRETTY_FUNCTION__, up->sg_str);
			return 0;
		}
		if (PIM_DEBUG_MROUTE_DETAIL) {
			zlog_debug(
				"%s: Unable to find upstream channel WHOLEPKT%s",
				__PRETTY_FUNCTION__, pim_str_sg_dump(&sg));
		}
		return 0;
	}

	if (!up->rpf.source_nexthop.interface) {
		if (PIM_DEBUG_TRACE)
			zlog_debug("%s: up %s RPF is not present",
				__PRETTY_FUNCTION__, up->sg_str);
		return 0;
	}

	pim_ifp = up->rpf.source_nexthop.interface->info;

	rpg = pim_ifp ? RP(pim_ifp->pim, sg.grp) : NULL;

	if ((pim_rpf_addr_is_inaddr_none(rpg)) || (!pim_ifp)
	    || (!(PIM_I_am_DR(pim_ifp)))) {
		if (PIM_DEBUG_MROUTE) {
			zlog_debug("%s: Failed Check send packet",
				   __PRETTY_FUNCTION__);
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
					"%s register forward skipped as group is SSM",
					pim_str_sg_dump(&sg));
			return 0;
		}
		pim_register_send((uint8_t *)buf + sizeof(struct ip),
				  ntohs(ip_hdr->ip_len) - sizeof(struct ip),
				  pim_ifp->primary_address, rpg, 0, up);
	}
	return 0;
}

static int pim_mroute_msg_wrongvif(int fd, struct interface *ifp,
				   const struct igmpmsg *msg)
{
	struct pim_ifchannel *ch;
	struct pim_interface *pim_ifp;
	struct prefix_sg sg;

	memset(&sg, 0, sizeof(struct prefix_sg));
	sg.src = msg->im_src;
	sg.grp = msg->im_dst;

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
				"%s: WRONGVIF (S,G)=%s could not find input interface for input_vif_index=%d",
				__PRETTY_FUNCTION__, pim_str_sg_dump(&sg),
				msg->im_vif);
		return -1;
	}

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug(
				"%s: WRONGVIF (S,G)=%s multicast not enabled on interface %s",
				__PRETTY_FUNCTION__, pim_str_sg_dump(&sg),
				ifp->name);
		return -2;
	}

	ch = pim_ifchannel_find(ifp, &sg);
	if (!ch) {
		struct prefix_sg star_g = sg;
		if (PIM_DEBUG_MROUTE)
			zlog_debug(
				"%s: WRONGVIF (S,G)=%s could not find channel on interface %s",
				__PRETTY_FUNCTION__, pim_str_sg_dump(&sg),
				ifp->name);

		star_g.src.s_addr = INADDR_ANY;
		ch = pim_ifchannel_find(ifp, &star_g);
		if (!ch) {
			if (PIM_DEBUG_MROUTE)
				zlog_debug(
					"%s: WRONGVIF (*,G)=%s could not find channel on interface %s",
					__PRETTY_FUNCTION__,
					pim_str_sg_dump(&star_g), ifp->name);
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
				__PRETTY_FUNCTION__, ch->sg_str, ifp->name);
		}
		return -4;
	}

	if (!PIM_IF_FLAG_TEST_COULD_ASSERT(ch->flags)) {
		if (PIM_DEBUG_MROUTE) {
			zlog_debug(
				"%s: WRONGVIF (S,G)=%s interface %s is not downstream for channel",
				__PRETTY_FUNCTION__, ch->sg_str, ifp->name);
		}
		return -5;
	}

	if (assert_action_a1(ch)) {
		if (PIM_DEBUG_MROUTE) {
			zlog_debug(
				"%s: WRONGVIF (S,G)=%s assert_action_a1 failure on interface %s",
				__PRETTY_FUNCTION__, ch->sg_str, ifp->name);
		}
		return -6;
	}

	return 0;
}

static int pim_mroute_msg_wrvifwhole(int fd, struct interface *ifp,
				     const char *buf)
{
	const struct ip *ip_hdr = (const struct ip *)buf;
	struct pim_interface *pim_ifp;
	struct pim_ifchannel *ch;
	struct pim_upstream *up;
	struct prefix_sg star_g;
	struct prefix_sg sg;

	pim_ifp = ifp->info;

	memset(&sg, 0, sizeof(struct prefix_sg));
	sg.src = ip_hdr->ip_src;
	sg.grp = ip_hdr->ip_dst;

	ch = pim_ifchannel_find(ifp, &sg);
	if (ch) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug(
				"WRVIFWHOLE (S,G)=%s found ifchannel on interface %s",
				ch->sg_str, ifp->name);
		return -1;
	}

	star_g = sg;
	star_g.src.s_addr = INADDR_ANY;
#if 0
  ch = pim_ifchannel_find(ifp, &star_g);
  if (ch)
    {
      if (PIM_DEBUG_MROUTE)
	zlog_debug ("WRVIFWHOLE (*,G)=%s found ifchannel on interface %s",
		    pim_str_sg_dump (&star_g), ifp->name);
      return -1;
    }
#endif

	up = pim_upstream_find(pim_ifp->pim, &sg);
	if (up) {
		struct pim_upstream *parent;
		struct pim_nexthop source;
		struct pim_rpf *rpf = RP(pim_ifp->pim, sg.grp);
		if (!rpf || !rpf->source_nexthop.interface)
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
			// No if channel, but upstream we are at the RP.
			if (pim_nexthop_lookup(pim_ifp->pim, &source,
					       up->upstream_register, 0)) {
				pim_register_stop_send(source.interface, &sg,
						       pim_ifp->primary_address,
						       up->upstream_register);
				up->sptbit = PIM_UPSTREAM_SPTBIT_TRUE;
			}

			pim_upstream_inherited_olist(pim_ifp->pim, up);
			if (!up->channel_oil->installed)
				pim_mroute_add(up->channel_oil,
					       __PRETTY_FUNCTION__);
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
			}
			pim_upstream_keep_alive_timer_start(
				up, pim_ifp->pim->keep_alive_time);
			pim_upstream_inherited_olist(pim_ifp->pim, up);
			pim_mroute_msg_wholepkt(fd, ifp, buf);
		}
		return 0;
	}

	pim_ifp = ifp->info;
	if (pim_if_connected_to_source(ifp, sg.src)) {
		up = pim_upstream_add(pim_ifp->pim, &sg, ifp,
				      PIM_UPSTREAM_FLAG_MASK_FHR,
				      __PRETTY_FUNCTION__, NULL);
		if (!up) {
			if (PIM_DEBUG_MROUTE)
				zlog_debug(
					"%s: WRONGVIF%s unable to create upstream on interface",
					pim_str_sg_dump(&sg), ifp->name);
			return -2;
		}
		PIM_UPSTREAM_FLAG_SET_SRC_STREAM(up->flags);
		pim_upstream_keep_alive_timer_start(
			up, pim_ifp->pim->keep_alive_time);
		up->channel_oil->cc.pktcnt++;
		pim_register_join(up);
		pim_upstream_inherited_olist(pim_ifp->pim, up);

		// Send the packet to the RP
		pim_mroute_msg_wholepkt(fd, ifp, buf);
	} else {
		up = pim_upstream_add(pim_ifp->pim, &sg, ifp,
				      PIM_UPSTREAM_FLAG_MASK_SRC_NOCACHE,
				      __PRETTY_FUNCTION__, NULL);
		if (!up->channel_oil->installed)
			pim_mroute_add(up->channel_oil, __PRETTY_FUNCTION__);
	}

	return 0;
}

static int pim_mroute_msg(struct pim_instance *pim, const char *buf,
			  int buf_size, ifindex_t ifindex)
{
	struct interface *ifp;
	struct pim_interface *pim_ifp;
	const struct ip *ip_hdr;
	const struct igmpmsg *msg;
	char ip_src_str[INET_ADDRSTRLEN] = "";
	char ip_dst_str[INET_ADDRSTRLEN] = "";
	char src_str[INET_ADDRSTRLEN] = "<src?>";
	char grp_str[INET_ADDRSTRLEN] = "<grp?>";
	struct in_addr ifaddr;
	struct igmp_sock *igmp;

	ip_hdr = (const struct ip *)buf;

	if (ip_hdr->ip_p == IPPROTO_IGMP) {

		/* We have the IP packet but we do not know which interface this
		 * packet was
		 * received on. Find the interface that is on the same subnet as
		 * the source
		 * of the IP packet.
		 */
		ifp = if_lookup_by_index(ifindex, pim->vrf_id);

		if (!ifp || !ifp->info)
			return 0;

		pim_ifp = ifp->info;
		ifaddr = pim_find_primary_addr(ifp);
		igmp = pim_igmp_sock_lookup_ifaddr(pim_ifp->igmp_socket_list,
						   ifaddr);

		if (PIM_DEBUG_MROUTE) {
			pim_inet4_dump("<src?>", ip_hdr->ip_src, ip_src_str,
				       sizeof(ip_src_str));
			pim_inet4_dump("<dst?>", ip_hdr->ip_dst, ip_dst_str,
				       sizeof(ip_dst_str));

			zlog_debug(
				"%s(%s): igmp kernel upcall on %s(%p) for %s -> %s",
				__PRETTY_FUNCTION__, pim->vrf->name, ifp->name,
				igmp, ip_src_str, ip_dst_str);
		}
		if (igmp)
			pim_igmp_packet(igmp, (char *)buf, buf_size);

	} else if (ip_hdr->ip_p) {
		if (PIM_DEBUG_MROUTE_DETAIL) {
			pim_inet4_dump("<src?>", ip_hdr->ip_src, src_str,
				       sizeof(src_str));
			pim_inet4_dump("<grp?>", ip_hdr->ip_dst, grp_str,
				       sizeof(grp_str));
			zlog_debug(
				"%s: no kernel upcall proto=%d src: %s dst: %s msg_size=%d",
				__PRETTY_FUNCTION__, ip_hdr->ip_p, src_str,
				grp_str, buf_size);
		}

	} else {
		msg = (const struct igmpmsg *)buf;

		ifp = pim_if_find_by_vif_index(pim, msg->im_vif);

		if (!ifp)
			return 0;
		if (PIM_DEBUG_MROUTE) {
			pim_inet4_dump("<src?>", msg->im_src, src_str,
				       sizeof(src_str));
			pim_inet4_dump("<grp?>", msg->im_dst, grp_str,
				       sizeof(grp_str));
			zlog_debug(
				"%s: pim kernel upcall %s type=%d ip_p=%d from fd=%d for (S,G)=(%s,%s) on %s vifi=%d  size=%d",
				__PRETTY_FUNCTION__,
				igmpmsgtype2str[msg->im_msgtype],
				msg->im_msgtype, ip_hdr->ip_p,
				pim->mroute_socket, src_str, grp_str, ifp->name,
				msg->im_vif, buf_size);
		}

		switch (msg->im_msgtype) {
		case IGMPMSG_WRONGVIF:
			return pim_mroute_msg_wrongvif(pim->mroute_socket, ifp,
						       msg);
			break;
		case IGMPMSG_NOCACHE:
			return pim_mroute_msg_nocache(pim->mroute_socket, ifp,
						      msg);
			break;
		case IGMPMSG_WHOLEPKT:
			return pim_mroute_msg_wholepkt(pim->mroute_socket, ifp,
						       (const char *)msg);
			break;
		case IGMPMSG_WRVIFWHOLE:
			return pim_mroute_msg_wrvifwhole(
				pim->mroute_socket, ifp, (const char *)msg);
			break;
		default:
			break;
		}
	}

	return 0;
}

static int mroute_read(struct thread *t)
{
	struct pim_instance *pim;
	static long long count;
	char buf[10000];
	int result = 0;
	int cont = 1;
	int rd;
	ifindex_t ifindex;
	pim = THREAD_ARG(t);

	while (cont) {
		rd = pim_socket_recvfromto(pim->mroute_socket, (uint8_t *)buf,
					   sizeof(buf), NULL, NULL, NULL, NULL,
					   &ifindex);
		if (rd <= 0) {
			if (errno == EINTR)
				continue;
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;

			zlog_warn("%s: failure reading rd=%d: fd=%d: errno=%d: %s",
				  __PRETTY_FUNCTION__, rd, pim->mroute_socket,
				  errno, safe_strerror(errno));
			goto done;
		}

		result = pim_mroute_msg(pim, buf, rd, ifindex);

		count++;
		if (count % router->packet_process == 0)
			cont = 0;
	}
/* Keep reading */
done:
	mroute_read_on(pim);

	return result;
}

static void mroute_read_on(struct pim_instance *pim)
{
	thread_add_read(router->master, mroute_read, pim, pim->mroute_socket,
			&pim->thread);
}

static void mroute_read_off(struct pim_instance *pim)
{
	THREAD_OFF(pim->thread);
}

int pim_mroute_socket_enable(struct pim_instance *pim)
{
	int fd;

	frr_with_privs(&pimd_privs) {

		fd = socket(AF_INET, SOCK_RAW, IPPROTO_IGMP);

		if (fd < 0) {
			zlog_warn("Could not create mroute socket: errno=%d: %s",
				  errno,
				  safe_strerror(errno));
			return -2;
		}

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
int pim_mroute_add_vif(struct interface *ifp, struct in_addr ifaddr,
		       unsigned char flags)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct vifctl vc;
	int err;

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: Add Vif %d (%s[%s])", __PRETTY_FUNCTION__,
			   pim_ifp->mroute_vif_index, ifp->name,
			   pim_ifp->pim->vrf->name);

	memset(&vc, 0, sizeof(vc));
	vc.vifc_vifi = pim_ifp->mroute_vif_index;
#ifdef VIFF_USE_IFINDEX
	vc.vifc_lcl_ifindex = ifp->ifindex;
#else
	if (ifaddr.s_addr == INADDR_ANY) {
		zlog_warn(
			"%s: unnumbered interfaces are not supported on this platform",
			__PRETTY_FUNCTION__);
		return -1;
	}
	memcpy(&vc.vifc_lcl_addr, &ifaddr, sizeof(vc.vifc_lcl_addr));
#endif
	vc.vifc_flags = flags;
	vc.vifc_threshold = PIM_MROUTE_MIN_TTL;
	vc.vifc_rate_limit = 0;

#ifdef PIM_DVMRP_TUNNEL
	if (vc.vifc_flags & VIFF_TUNNEL) {
		memcpy(&vc.vifc_rmt_addr, &vif_remote_addr,
		       sizeof(vc.vifc_rmt_addr));
	}
#endif

	err = setsockopt(pim_ifp->pim->mroute_socket, IPPROTO_IP, MRT_ADD_VIF,
			 (void *)&vc, sizeof(vc));
	if (err) {
		char ifaddr_str[INET_ADDRSTRLEN];

		pim_inet4_dump("<ifaddr?>", ifaddr, ifaddr_str,
			       sizeof(ifaddr_str));

		zlog_warn(
			"%s: failure: setsockopt(fd=%d,IPPROTO_IP,MRT_ADD_VIF,vif_index=%d,ifaddr=%s,flag=%d): errno=%d: %s",
			__PRETTY_FUNCTION__, pim_ifp->pim->mroute_socket,
			ifp->ifindex, ifaddr_str, flags, errno,
			safe_strerror(errno));
		return -2;
	}

	return 0;
}

int pim_mroute_del_vif(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct vifctl vc;
	int err;

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: Del Vif %d (%s[%s])", __PRETTY_FUNCTION__,
			   pim_ifp->mroute_vif_index, ifp->name,
			   pim_ifp->pim->vrf->name);

	memset(&vc, 0, sizeof(vc));
	vc.vifc_vifi = pim_ifp->mroute_vif_index;

	err = setsockopt(pim_ifp->pim->mroute_socket, IPPROTO_IP, MRT_DEL_VIF,
			 (void *)&vc, sizeof(vc));
	if (err) {
		zlog_warn(
			"%s %s: failure: setsockopt(fd=%d,IPPROTO_IP,MRT_DEL_VIF,vif_index=%d): errno=%d: %s",
			__FILE__, __PRETTY_FUNCTION__,
			pim_ifp->pim->mroute_socket, pim_ifp->mroute_vif_index,
			errno, safe_strerror(errno));
		return -2;
	}

	return 0;
}

int pim_mroute_add(struct channel_oil *c_oil, const char *name)
{
	struct pim_instance *pim = c_oil->pim;
	int err;
	int orig = 0;
	int orig_iif_vif = 0;
	struct pim_interface *pim_reg_ifp = NULL;
	int orig_pimreg_ttl = 0;
	bool pimreg_ttl_reset = false;
	struct pim_interface *vxlan_ifp = NULL;
	int orig_term_ttl = 0;
	bool orig_term_ttl_reset = false;

	pim->mroute_add_last = pim_time_monotonic_sec();
	++pim->mroute_add_events;

	/* Do not install route if incoming interface is undefined. */
	if (c_oil->oil.mfcc_parent >= MAXVIFS) {
		if (PIM_DEBUG_MROUTE) {
			char buf[1000];
			zlog_debug(
				"%s(%s) %s Attempting to add vifi that is invalid to mroute table",
				__PRETTY_FUNCTION__, name,
				pim_channel_oil_dump(c_oil, buf, sizeof(buf)));
		}
		return -2;
	}

	/* The linux kernel *expects* the incoming
	 * vif to be part of the outgoing list
	 * in the case of a (*,G).
	 */
	if (c_oil->oil.mfcc_origin.s_addr == INADDR_ANY) {
		orig = c_oil->oil.mfcc_ttls[c_oil->oil.mfcc_parent];
		c_oil->oil.mfcc_ttls[c_oil->oil.mfcc_parent] = 1;
	}

	if (c_oil->up) {
		/* suppress pimreg in the OIL if the mroute is not supposed to
		 * trigger register encapsulated data
		 */
		if (PIM_UPSTREAM_FLAG_TEST_NO_PIMREG_DATA(c_oil->up->flags)) {
			pim_reg_ifp = pim->regiface->info;
			orig_pimreg_ttl =
				c_oil->oil.mfcc_ttls[pim_reg_ifp->mroute_vif_index];
			c_oil->oil.mfcc_ttls[pim_reg_ifp->mroute_vif_index] = 0;
			/* remember to flip it back after MFC programming */
			pimreg_ttl_reset = true;
		}

		vxlan_ifp = pim_vxlan_get_term_ifp(pim);
		/* 1. vxlan termination device must never be added to the
		 * origination mroute (and that can actually happen because
		 * of XG inheritance from the termination mroute) otherwise
		 * traffic will end up looping.
		 * 2. vxlan termination device should be removed from the non-DF
		 * to prevent duplicates to the overlay rxer
		 */
		if (vxlan_ifp &&
			(PIM_UPSTREAM_FLAG_TEST_SRC_VXLAN_ORIG(c_oil->up->flags) ||
			 PIM_UPSTREAM_FLAG_TEST_MLAG_NON_DF(c_oil->up->flags))) {
			orig_term_ttl_reset = true;
			orig_term_ttl =
				c_oil->oil.mfcc_ttls[vxlan_ifp->mroute_vif_index];
			c_oil->oil.mfcc_ttls[vxlan_ifp->mroute_vif_index] = 0;
		}
	}

	/*
	 * If we have an unresolved cache entry for the S,G
	 * it is owned by the pimreg for the incoming IIF
	 * So set pimreg as the IIF temporarily to cause
	 * the packets to be forwarded.  Then set it
	 * to the correct IIF afterwords.
	 */
	if (!c_oil->installed && c_oil->oil.mfcc_origin.s_addr != INADDR_ANY
	    && c_oil->oil.mfcc_parent != 0) {
		orig_iif_vif = c_oil->oil.mfcc_parent;
		c_oil->oil.mfcc_parent = 0;
	}
	err = setsockopt(pim->mroute_socket, IPPROTO_IP, MRT_ADD_MFC,
			 &c_oil->oil, sizeof(c_oil->oil));

	if (!err && !c_oil->installed
	    && c_oil->oil.mfcc_origin.s_addr != INADDR_ANY
	    && orig_iif_vif != 0) {
		c_oil->oil.mfcc_parent = orig_iif_vif;
		err = setsockopt(pim->mroute_socket, IPPROTO_IP, MRT_ADD_MFC,
				 &c_oil->oil, sizeof(c_oil->oil));
	}

	if (c_oil->oil.mfcc_origin.s_addr == INADDR_ANY)
		c_oil->oil.mfcc_ttls[c_oil->oil.mfcc_parent] = orig;

	if (pimreg_ttl_reset) {
		assert(pim_reg_ifp);
		c_oil->oil.mfcc_ttls[pim_reg_ifp->mroute_vif_index] =
			orig_pimreg_ttl;
	}

	if (orig_term_ttl_reset)
		c_oil->oil.mfcc_ttls[vxlan_ifp->mroute_vif_index] =
			orig_term_ttl;

	if (err) {
		zlog_warn(
			"%s %s: failure: setsockopt(fd=%d,IPPROTO_IP,MRT_ADD_MFC): errno=%d: %s",
			__FILE__, __PRETTY_FUNCTION__, pim->mroute_socket,
			errno, safe_strerror(errno));
		return -2;
	}

	if (PIM_DEBUG_MROUTE) {
		char buf[1000];
		zlog_debug("%s(%s), vrf %s Added Route: %s",
			   __PRETTY_FUNCTION__, name, pim->vrf->name,
			   pim_channel_oil_dump(c_oil, buf, sizeof(buf)));
	}

	c_oil->installed = 1;
	c_oil->mroute_creation = pim_time_monotonic_sec();

	return 0;
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
			zlog_debug(
				"%s %s: vifi %d for route is %s not installed, do not need to send del req. ",
				__FILE__, __PRETTY_FUNCTION__,
				c_oil->oil.mfcc_parent,
				pim_channel_oil_dump(c_oil, buf, sizeof(buf)));
		}
		return -2;
	}

	err = setsockopt(pim->mroute_socket, IPPROTO_IP, MRT_DEL_MFC,
			 &c_oil->oil, sizeof(c_oil->oil));
	if (err) {
		if (PIM_DEBUG_MROUTE)
			zlog_warn(
				"%s %s: failure: setsockopt(fd=%d,IPPROTO_IP,MRT_DEL_MFC): errno=%d: %s",
				__FILE__, __PRETTY_FUNCTION__,
				pim->mroute_socket, errno,
				safe_strerror(errno));
		return -2;
	}

	if (PIM_DEBUG_MROUTE) {
		char buf[1000];
		zlog_debug("%s(%s), vrf %s Deleted Route: %s",
			   __PRETTY_FUNCTION__, name, pim->vrf->name,
			   pim_channel_oil_dump(c_oil, buf, sizeof(buf)));
	}

	// Reset kernel installed flag
	c_oil->installed = 0;

	return 0;
}

void pim_mroute_update_counters(struct channel_oil *c_oil)
{
	struct pim_instance *pim = c_oil->pim;
	struct sioc_sg_req sgreq;

	c_oil->cc.oldpktcnt = c_oil->cc.pktcnt;
	c_oil->cc.oldbytecnt = c_oil->cc.bytecnt;
	c_oil->cc.oldwrong_if = c_oil->cc.wrong_if;

	if (!c_oil->installed) {
		c_oil->cc.lastused = 100 * pim->keep_alive_time;
		if (PIM_DEBUG_MROUTE) {
			struct prefix_sg sg;

			sg.src = c_oil->oil.mfcc_origin;
			sg.grp = c_oil->oil.mfcc_mcastgrp;
			if (PIM_DEBUG_MROUTE)
				zlog_debug(
					"Channel%s is not installed no need to collect data from kernel",
					pim_str_sg_dump(&sg));
		}
		return;
	}

	memset(&sgreq, 0, sizeof(sgreq));
	sgreq.src = c_oil->oil.mfcc_origin;
	sgreq.grp = c_oil->oil.mfcc_mcastgrp;

	pim_zlookup_sg_statistics(c_oil);
	if (ioctl(pim->mroute_socket, SIOCGETSGCNT, &sgreq)) {
		struct prefix_sg sg;

		sg.src = c_oil->oil.mfcc_origin;
		sg.grp = c_oil->oil.mfcc_mcastgrp;

		zlog_warn("ioctl(SIOCGETSGCNT=%lu) failure for (S,G)=%s: errno=%d: %s",
			  (unsigned long)SIOCGETSGCNT, pim_str_sg_dump(&sg),
			  errno, safe_strerror(errno));
		return;
	}

	c_oil->cc.pktcnt = sgreq.pktcnt;
	c_oil->cc.bytecnt = sgreq.bytecnt;
	c_oil->cc.wrong_if = sgreq.wrong_if;

	return;
}
