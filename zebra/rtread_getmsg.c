/*
 * Kernel routing table readup by getmsg(2)
 * Copyright (C) 1999 Michael Handler
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#ifdef SUNOS_5

#include "prefix.h"
#include "log.h"
#include "if.h"
#include "vrf.h"
#include "vty.h"
#include "lib_errors.h"

#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zebra_pbr.h"
#include "zebra/zebra_errors.h"

/* Thank you, Solaris, for polluting application symbol namespace. */
#undef hook_register
#undef hook_unregister

#include <sys/stream.h>
#include <sys/tihdr.h>

/* Solaris defines these in both <netinet/in.h> and <inet/in.h>, sigh */
#ifdef SUNOS_5
#include <sys/tiuser.h>
#ifndef T_CURRENT
#define T_CURRENT       MI_T_CURRENT
#endif /* T_CURRENT */
#ifndef IRE_CACHE
#define IRE_CACHE               0x0020  /* Cached Route entry */
#endif /* IRE_CACHE */
#ifndef IRE_HOST_REDIRECT
#define IRE_HOST_REDIRECT       0x0200  /* Host route entry from redirects */
#endif /* IRE_HOST_REDIRECT */
#ifndef IRE_CACHETABLE
#define IRE_CACHETABLE (IRE_CACHE | IRE_BROADCAST | IRE_LOCAL | IRE_LOOPBACK)
#endif /* IRE_CACHETABLE */
#undef IPOPT_EOL
#undef IPOPT_NOP
#undef IPOPT_LSRR
#undef IPOPT_RR
#undef IPOPT_SSRR
#endif /* SUNOS_5 */

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/mib2.h>

/* device to read IP routing table from */
#ifndef _PATH_GETMSG_ROUTE
#define _PATH_GETMSG_ROUTE	"/dev/ip"
#endif /* _PATH_GETMSG_ROUTE */

#define RT_BUFSIZ		8192

static void handle_route_entry(mib2_ipRouteEntry_t *routeEntry)
{
	struct prefix prefix;
	struct in_addr tmpaddr;
	struct nexthop nh;
	uint8_t zebra_flags = 0;

	if (routeEntry->ipRouteInfo.re_ire_type & IRE_CACHETABLE)
		return;

	if (routeEntry->ipRouteInfo.re_ire_type & IRE_HOST_REDIRECT)
		zebra_flags |= ZEBRA_FLAG_SELFROUTE;

	prefix.family = AF_INET;

	tmpaddr.s_addr = routeEntry->ipRouteDest;
	prefix.u.prefix4 = tmpaddr;

	tmpaddr.s_addr = routeEntry->ipRouteMask;
	prefix.prefixlen = ip_masklen(tmpaddr);

	memset(&nh, 0, sizeof(nh));
	nh.vrf_id = VRF_DEFAULT;
	nh.type = NEXTHOP_TYPE_IPV4;
	nh.gate.ipv4.s_addr = routeEntry->ipRouteNextHop;

	rib_add(AFI_IP, SAFI_UNICAST, VRF_DEFAULT, ZEBRA_ROUTE_KERNEL, 0,
		zebra_flags, &prefix, NULL, &nh, 0, 0, 0, 0, 0, 0);
}

void route_read(struct zebra_ns *zns)
{
	char storage[RT_BUFSIZ];

	struct T_optmgmt_req *TLIreq = (struct T_optmgmt_req *)storage;
	struct T_optmgmt_ack *TLIack = (struct T_optmgmt_ack *)storage;
	struct T_error_ack *TLIerr = (struct T_error_ack *)storage;

	struct opthdr *MIB2hdr;

	mib2_ipRouteEntry_t *routeEntry, *lastRouteEntry;

	struct strbuf msgdata;
	int flags, dev, retval, process;

	if ((dev = open(_PATH_GETMSG_ROUTE, O_RDWR)) == -1) {
		flog_err_sys(EC_LIB_SYSTEM_CALL, "can't open %s: %s",
			     _PATH_GETMSG_ROUTE, safe_strerror(errno));
		return;
	}

	TLIreq->PRIM_type = T_OPTMGMT_REQ;
	TLIreq->OPT_offset = sizeof(struct T_optmgmt_req);
	TLIreq->OPT_length = sizeof(struct opthdr);
	TLIreq->MGMT_flags = T_CURRENT;

	MIB2hdr = (struct opthdr *)&TLIreq[1];

	MIB2hdr->level = MIB2_IP;
	MIB2hdr->name = 0;
	MIB2hdr->len = 0;

	msgdata.buf = storage;
	msgdata.len = sizeof(struct T_optmgmt_req) + sizeof(struct opthdr);

	flags = 0;

	if (putmsg(dev, &msgdata, NULL, flags) == -1) {
		flog_err_sys(EC_LIB_SOCKET, "putmsg failed: %s",
			     safe_strerror(errno));
		goto exit;
	}

	MIB2hdr = (struct opthdr *)&TLIack[1];
	msgdata.maxlen = sizeof(storage);

	while (1) {
		flags = 0;
		retval = getmsg(dev, &msgdata, NULL, &flags);

		if (retval == -1) {
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "getmsg(ctl) failed: %s",
				     safe_strerror(errno));
			goto exit;
		}

		/* This is normal loop termination */
		if (retval == 0
		    && (size_t)msgdata.len >= sizeof(struct T_optmgmt_ack)
		    && TLIack->PRIM_type == T_OPTMGMT_ACK
		    && TLIack->MGMT_flags == T_SUCCESS && MIB2hdr->len == 0)
			break;

		if ((size_t)msgdata.len >= sizeof(struct T_error_ack)
		    && TLIerr->PRIM_type == T_ERROR_ACK) {
			zlog_debug("getmsg(ctl) returned T_ERROR_ACK: %s",
				   safe_strerror((TLIerr->TLI_error == TSYSERR)
							 ? TLIerr->UNIX_error
							 : EPROTO));
			break;
		}

		/* should dump more debugging info to the log statement,
		   like what GateD does in this instance, but not
		   critical yet. */
		if (retval != MOREDATA
		    || (size_t)msgdata.len < sizeof(struct T_optmgmt_ack)
		    || TLIack->PRIM_type != T_OPTMGMT_ACK
		    || TLIack->MGMT_flags != T_SUCCESS) {
			errno = ENOMSG;
			zlog_debug("getmsg(ctl) returned bizarreness");
			break;
		}

		/* MIB2_IP_21 is the the pseudo-MIB2 ipRouteTable
		   entry, see <inet/mib2.h>. "This isn't the MIB data
		   you're looking for." */
		process = (MIB2hdr->level == MIB2_IP
			   && MIB2hdr->name == MIB2_IP_21)
				  ? 1
				  : 0;

		/* getmsg writes the data buffer out completely, not
		   to the closest smaller multiple. Unless reassembling
		   data structures across buffer boundaries is your idea
		   of a good time, set maxlen to the closest smaller
		   multiple of the size of the datastructure you're
		   retrieving. */
		msgdata.maxlen =
			sizeof(storage)
			- (sizeof(storage) % sizeof(mib2_ipRouteEntry_t));

		msgdata.len = 0;
		flags = 0;

		do {
			retval = getmsg(dev, NULL, &msgdata, &flags);

			if (retval == -1) {
				flog_err_sys(EC_LIB_SYSTEM_CALL,
					     "getmsg(data) failed: %s",
					     safe_strerror(errno));
				goto exit;
			}

			if (!(retval == 0 || retval == MOREDATA)) {
				zlog_debug("getmsg(data) returned %d", retval);
				goto exit;
			}

			if (process) {
				if (msgdata.len % sizeof(mib2_ipRouteEntry_t)
				    != 0) {
					zlog_debug(
						"getmsg(data) returned "
						"msgdata.len = %d (%% sizeof (mib2_ipRouteEntry_t) != 0)",
						msgdata.len);
					goto exit;
				}

				routeEntry = (mib2_ipRouteEntry_t *)msgdata.buf;
				lastRouteEntry =
					(mib2_ipRouteEntry_t *)(msgdata.buf
								+ msgdata.len);
				do {
					handle_route_entry(routeEntry);
				} while (++routeEntry < lastRouteEntry);
			}
		} while (retval == MOREDATA);
	}

exit:
	close(dev);
}

/* Only implemented for netlink method */
void macfdb_read(struct zebra_ns *zns)
{
}

void macfdb_read_for_bridge(struct zebra_ns *zns, struct interface *ifp,
			    struct interface *br_if)
{
}

void macfdb_read_specific_mac(struct zebra_ns *zns, struct interface *br_if,
			      struct ethaddr *mac, vlanid_t vid)
{
}

void neigh_read(struct zebra_ns *zns)
{
}

void neigh_read_for_vlan(struct zebra_ns *zns, struct interface *vlan_if)
{
}

void neigh_read_specific_ip(struct ipaddr *ip, struct interface *vlan_if)
{
}

void kernel_read_pbr_rules(struct zebra_ns *zns)
{
}

#endif /* SUNOS_5 */
