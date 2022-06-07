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
#include "pim_time.h"
#include "pim_iface.h"
#include "pim_macro.h"
#include "pim_rp.h"
#include "pim_oil.h"
#include "pim_ssm.h"
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
		frr_with_privs (&pimd_privs) {

			data = pim->vrf->data.l.table_id;
			err = setsockopt(pim->mroute_socket, PIM_IPPROTO,
					 MRT6_TABLE, &data, data_len);
			if (err) {
				zlog_warn(
					"%s %s: failure: setsockopt(fd=%d,PIM_IPPROTO, MRT6_TABLE=%d): errno=%d: %s",
					__FILE__, __func__, pim->mroute_socket,
					data, errno, safe_strerror(errno));
				return -1;
			}
		}
	}

	frr_with_privs (&pimd_privs) {
		opt = enable ? MRT6_INIT : MRT6_DONE;
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
				enable ? "MRT6_INIT" : "MRT6_DONE", data, errno,
				safe_strerror(errno));
			return -1;
		}
	}

	if (enable) {
		/* Linux and Solaris IPV6_PKTINFO */
		data = 1;
		if (setsockopt(pim->mroute_socket, PIM_IPPROTO, IPV6_RECVPKTINFO,
			       &data, data_len)) {
			zlog_warn(
				"Could not set IPV6_PKTINFO on socket fd=%d: errno=%d: %s",
				pim->mroute_socket, errno,
				safe_strerror(errno));
		}
	}

	setsockopt_so_recvbuf(pim->mroute_socket, 1024 * 1024 * 8);

	if (set_nonblocking (pim->mroute_socket) < 0) {
		zlog_warn(
			"Could not set non blocking on socket fd=%d: errno=%d: %s",
			pim->mroute_socket, errno,
			safe_strerror(errno));
	}

	if (enable) {
#if defined linux
		int upcalls = MRT6MSG_WRMIFWHOLE;
		opt = MRT6_PIM;

		err = setsockopt(pim->mroute_socket, PIM_IPPROTO, opt, &upcalls,
				 sizeof(upcalls));
		if (err) {
			zlog_warn(
				"Failure to register for WHOLE and WRONGMIF upcalls %d %s",
				errno, safe_strerror(errno));
			return -1;
		}
#else
		zlog_warn(
			"PIM-SM will not work properly on this platform, until the ability to receive the WHOLEPKT upcall");
#endif
	}

	return 0;
}
static const char *const mrt6msgtype2str[MRT6MSG_WRMIFWHOLE + 1] = {
	"<unknown_upcall?>", "NOCACHE", "WRONGMIF", "WHOLEPKT", "WRMIFWHOLE"};

int pim_mroute_msg(struct pim_instance *pim, const char *buf,
			  size_t buf_size, ifindex_t ifindex)
{
	struct interface *ifp;
	const struct ip6_hdr *ip6_hdr;
	const struct mrt6msg *msg;

	if (buf_size < (int)sizeof(struct ip6_hdr))
		return 0;

	ip6_hdr = (const struct ip6_hdr *)buf;

	if ((ip6_hdr->ip6_vfc & 0xf) == 0) {
		msg = (const struct mrt6msg *)buf;

		ifp = pim_if_find_by_vif_index(pim, msg->im6_mif);

		if (!ifp)
			return 0;
		if (PIM_DEBUG_MROUTE) {
			zlog_debug(
				"%s: pim kernel upcall %s type=%d ip_p=%d from fd=%d for (S,G)=(%pI6,%pI6) on %s mifi=%d  size=%ld",
				__func__, mrt6msgtype2str[msg->im6_msgtype],
				msg->im6_msgtype, ip6_hdr->ip6_nxt,
				pim->mroute_socket, &msg->im6_src,
				&msg->im6_dst, ifp->name, msg->im6_mif,
				(long int)buf_size);
		}

		switch (msg->im6_msgtype) {
		case MRT6MSG_WRONGMIF:
			return pim_mroute_msg_wrongvif(pim->mroute_socket, ifp,
							msg);
		case MRT6MSG_NOCACHE:
			return pim_mroute_msg_nocache(pim->mroute_socket, ifp,
						       msg);
		case MRT6MSG_WHOLEPKT:
			return pim_mroute_msg_wholepkt(pim->mroute_socket, ifp,
						       (const char *)msg,
						       buf_size);
		case MRT6MSG_WRMIFWHOLE:
			return pim_mroute_msg_wrvifwhole(pim->mroute_socket,
							 ifp, (const char *)msg,
							 buf_size);
		default:
			break;
		}
	} 

	return 0;
}

