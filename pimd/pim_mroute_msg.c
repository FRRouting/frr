/*
 * PIM for Quagga
 * Copyright (C) 2022  Dell Technologies Ltd
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
#include "lib/network.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_mroute.h"
#include "pim_oil.h"
#include "pim_str.h"
#include "pim_iface.h"
#include "pim_macro.h"
#include "pim_rp.h"
#include "pim_oil.h"
#include "pim_msg.h"
#include "pim_sock.h"


int pim_mroute_set(struct pim_instance *pim, int enable)
{
	int err;
	int opt, data;
	socklen_t data_len = sizeof(data);

	/*
	 * We need to create the VRF table for the pim mroute_socket
	 */
	if (pim->vrf->vrf_id != VRF_DEFAULT) {
		frr_with_privs(&pimd_privs) {

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

	frr_with_privs(&pimd_privs) {
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

	setsockopt_so_recvbuf(pim->mroute_socket, 1024 * 1024 * 8);

	if (set_nonblocking (pim->mroute_socket) < 0) {
		zlog_warn(
			"Could not set non blocking on socket fd=%d: errno=%d: %s",
			pim->mroute_socket, errno,
			safe_strerror(errno));
		return -1;
	}

	if (enable) {
#if defined linux
		int upcalls = IGMPMSG_WRVIFWHOLE;
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

static const char *const igmpmsgtype2str[IGMPMSG_WRVIFWHOLE + 1] = {
	"<unknown_upcall?>", "NOCACHE", "WRONGVIF", "WHOLEPKT", "WRVIFWHOLE"};


int pim_mroute_msg(struct pim_instance *pim, const char *buf,
			  size_t buf_size, ifindex_t ifindex)
{
	struct interface *ifp;
	const struct ip *ip_hdr;
	const struct igmpmsg *msg;

	if (buf_size < (int)sizeof(struct ip))
		return 0;

	ip_hdr = (const struct ip *)buf;

	if (ip_hdr->ip_p == IPPROTO_IGMP) {
		struct pim_interface *pim_ifp;
		struct in_addr ifaddr;
		struct gm_sock *igmp;
		const struct prefix *connected_src;

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

		if (!connected_src) {
			if (PIM_DEBUG_IGMP_PACKETS) {
				zlog_debug(
					"Recv IGMP packet on interface: %s from a non-connected source: %pI4",
					ifp->name, &ip_hdr->ip_src);
			}
			return 0;
		}

		pim_ifp = ifp->info;
		ifaddr = connected_src->u.prefix4;
		igmp = pim_igmp_sock_lookup_ifaddr(pim_ifp->gm_socket_list,
						   ifaddr);

		if (PIM_DEBUG_IGMP_PACKETS) {
			zlog_debug(
				"%s(%s): igmp kernel upcall on %s(%p) for %pI4 -> %pI4",
				__func__, pim->vrf->name, ifp->name, igmp,
				&ip_hdr->ip_src, &ip_hdr->ip_dst);
		}
		if (igmp)
			pim_igmp_packet(igmp, (char *)buf, buf_size);
		else if (PIM_DEBUG_IGMP_PACKETS) {
			zlog_debug(
				"No IGMP socket on interface: %s with connected source: %pFX",
				ifp->name, connected_src);
		}
	} else if (ip_hdr->ip_p) {
		if (PIM_DEBUG_MROUTE_DETAIL) {
			zlog_debug(
				"%s: no kernel upcall proto=%d src: %pI4 dst: %pI4 msg_size=%ld",
				__func__, ip_hdr->ip_p, &ip_hdr->ip_src,
				&ip_hdr->ip_dst, (long int)buf_size);
		}

	} else {
		msg = (const struct igmpmsg *)buf;

		ifp = pim_if_find_by_vif_index(pim, msg->im_vif);

		if (!ifp)
			return 0;
		if (PIM_DEBUG_MROUTE) {
			zlog_debug(
				"%s: pim kernel upcall %s type=%d ip_p=%d from fd=%d for (S,G)=(%pI4,%pI4) on %s vifi=%d  size=%ld",
				__func__, igmpmsgtype2str[msg->im_msgtype],
				msg->im_msgtype, ip_hdr->ip_p,
				pim->mroute_socket, &msg->im_src, &msg->im_dst,
				ifp->name, msg->im_vif, (long int)buf_size);
		}

		switch (msg->im_msgtype) {
		case IGMPMSG_WRONGVIF:
			return pim_mroute_msg_wrongvif(pim->mroute_socket, ifp,
						       msg);
		case IGMPMSG_NOCACHE:
			return pim_mroute_msg_nocache(pim->mroute_socket, ifp,
						      msg);
		case IGMPMSG_WHOLEPKT:
			return pim_mroute_msg_wholepkt(pim->mroute_socket, ifp,
						       (const char *)msg,
						       buf_size);
		case IGMPMSG_WRVIFWHOLE:
			return pim_mroute_msg_wrvifwhole(pim->mroute_socket,
							 ifp, (const char *)msg,
							 buf_size);
		default:
			break;
		}
	}

	return 0;
}
