/*
 * Kernel routing table updates by routing socket.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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

#ifndef HAVE_NETLINK

#ifdef __OpenBSD__
#include <netmpls/mpls.h>
#endif

#include "if.h"
#include "prefix.h"
#include "sockunion.h"
#include "log.h"
#include "privs.h"
#include "vxlan.h"
#include "lib_errors.h"

#include "zebra/debug.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/kernel_socket.h"
#include "zebra/zebra_mpls.h"
#include "zebra/zebra_errors.h"

extern struct zebra_privs_t zserv_privs;

#ifdef __OpenBSD__
static int kernel_rtm_add_labels(struct mpls_label_stack *nh_label,
				 struct sockaddr_mpls *smpls)
{
	if (nh_label->num_labels > 1) {
		flog_warn(EC_ZEBRA_MAX_LABELS_PUSH,
			  "%s: can't push %u labels at "
			  "once (maximum is 1)",
			  __func__, nh_label->num_labels);
		return -1;
	}

	memset(smpls, 0, sizeof(*smpls));
	smpls->smpls_len = sizeof(*smpls);
	smpls->smpls_family = AF_MPLS;
	smpls->smpls_label = htonl(nh_label->label[0] << MPLS_LABEL_OFFSET);

	return 0;
}
#endif

/* Interface between zebra message and rtm message. */
static int kernel_rtm(int cmd, const struct prefix *p,
		      const struct nexthop_group *ng, uint32_t metric)

{
	union sockunion sin_dest, sin_mask, sin_gate;
#ifdef __OpenBSD__
	struct sockaddr_mpls smpls;
#endif
	union sockunion *smplsp = NULL;
	struct nexthop *nexthop;
	int nexthop_num = 0;
	ifindex_t ifindex = 0;
	bool gate = false;
	int error;
	char gate_buf[INET6_BUFSIZ];
	char prefix_buf[PREFIX_STRLEN];
	enum blackhole_type bh_type = BLACKHOLE_UNSPEC;

	prefix2str(p, prefix_buf, sizeof(prefix_buf));

	/*
	 * We only have the ability to ADD or DELETE at this point
	 * in time.
	 */
	if (cmd != RTM_ADD && cmd != RTM_DELETE) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: %s odd command %s",
				   __func__, prefix_buf,
				   lookup_msg(rtm_type_str, cmd, NULL));
		return 0;
	}

	memset(&sin_dest, 0, sizeof(sin_dest));
	memset(&sin_gate, 0, sizeof(sin_gate));
	memset(&sin_mask, 0, sizeof(sin_mask));

	switch (p->family) {
	case AF_INET:
		sin_dest.sin.sin_family = AF_INET;
		sin_dest.sin.sin_addr = p->u.prefix4;
		sin_gate.sin.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sin_dest.sin.sin_len = sizeof(struct sockaddr_in);
		sin_gate.sin.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
		break;
	case AF_INET6:
		sin_dest.sin6.sin6_family = AF_INET6;
		sin_dest.sin6.sin6_addr = p->u.prefix6;
		sin_gate.sin6.sin6_family = AF_INET6;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sin_dest.sin6.sin6_len = sizeof(struct sockaddr_in6);
		sin_gate.sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
		break;
	}

	/* Make gateway. */
	for (ALL_NEXTHOPS_PTR(ng, nexthop)) {
		/*
		 * We only want to use the actual good nexthops
		 */
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE) ||
		    !CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE))
			continue;

		smplsp = NULL;
		gate = false;
		snprintf(gate_buf, sizeof(gate_buf), "NULL");

		switch (nexthop->type) {
		case NEXTHOP_TYPE_IPV4:
		case NEXTHOP_TYPE_IPV4_IFINDEX:
			sin_gate.sin.sin_addr = nexthop->gate.ipv4;
			sin_gate.sin.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
			sin_gate.sin.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
			ifindex = nexthop->ifindex;
			gate = true;
			break;
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			sin_gate.sin6.sin6_addr = nexthop->gate.ipv6;
			sin_gate.sin6.sin6_family = AF_INET6;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
			sin_gate.sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
			ifindex = nexthop->ifindex;
/* Under kame set interface index to link local address */
#ifdef KAME

#define SET_IN6_LINKLOCAL_IFINDEX(a, i)                                        \
	do {                                                                   \
		(a).s6_addr[2] = ((i) >> 8) & 0xff;                            \
		(a).s6_addr[3] = (i)&0xff;                                     \
	} while (0)

			if (IN6_IS_ADDR_LINKLOCAL(&sin_gate.sin6.sin6_addr))
				SET_IN6_LINKLOCAL_IFINDEX(
					sin_gate.sin6.sin6_addr,
					ifindex);
#endif /* KAME */

			gate = true;
			break;
		case NEXTHOP_TYPE_IFINDEX:
			ifindex = nexthop->ifindex;
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			bh_type = nexthop->bh_type;
			switch (p->family) {
			case AFI_IP: {
				struct in_addr loopback;
				loopback.s_addr = htonl(INADDR_LOOPBACK);
				sin_gate.sin.sin_addr = loopback;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
				sin_gate.sin.sin_len =
					sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
				gate = true;
			}
				break;
			case AFI_IP6:
				break;
			}
		}

		switch (p->family) {
		case AF_INET:
			masklen2ip(p->prefixlen, &sin_mask.sin.sin_addr);
			sin_mask.sin.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
			sin_mask.sin.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
			break;
		case AF_INET6:
			masklen2ip6(p->prefixlen, &sin_mask.sin6.sin6_addr);
			sin_mask.sin6.sin6_family = AF_INET6;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
			sin_mask.sin6.sin6_len = sizeof(struct sockaddr_in6);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
			break;
		}

#ifdef __OpenBSD__
		if (nexthop->nh_label) {
			if (kernel_rtm_add_labels(nexthop->nh_label,
						  &smpls) != 0)
				continue;
			smplsp = (union sockunion *)&smpls;
		}
#endif
		error = rtm_write(cmd, &sin_dest, &sin_mask,
				  gate ? &sin_gate : NULL, smplsp,
				  ifindex, bh_type, metric);

		if (IS_ZEBRA_DEBUG_KERNEL) {
			if (!gate) {
				zlog_debug(
					"%s: %s: attention! gate not found for re",
					__func__, prefix_buf);
			} else {
				switch (p->family) {
				case AFI_IP:
					inet_ntop(AF_INET,
						  &sin_gate.sin.sin_addr,
						  gate_buf, sizeof(gate_buf));
					break;

				case AFI_IP6:
					inet_ntop(AF_INET6,
						  &sin_gate.sin6.sin6_addr,
						  gate_buf, sizeof(gate_buf));
					break;

				default:
					snprintf(gate_buf, sizeof(gate_buf),
						 "(invalid-af)");
					break;
				}
			}
		}
		switch (error) {
			/* We only flag nexthops as being in FIB if
			 * rtm_write() did its work. */
		case ZEBRA_ERR_NOERROR:
			nexthop_num++;
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s: %s: successfully did NH %s",
					   __func__, prefix_buf, gate_buf);
			if (cmd == RTM_ADD)
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
			break;

			/* The only valid case for this error is
			 * kernel's failure to install a multipath
			 * route, which is common for FreeBSD. This
			 * should be ignored silently, but logged as an error
			 * otherwise.
			 */
		case ZEBRA_ERR_RTEXIST:
			if (cmd != RTM_ADD)
				flog_err(EC_LIB_SYSTEM_CALL,
					 "%s: rtm_write() returned %d for command %d",
					 __func__, error, cmd);
			continue;

			/* Note any unexpected status returns */
		default:
			flog_err(
				EC_LIB_SYSTEM_CALL,
				"%s: %s: rtm_write() unexpectedly returned %d for command %s",
				__func__, prefix_buf, error,
				lookup_msg(rtm_type_str, cmd, NULL));
			break;
		}
	} /* for (ALL_NEXTHOPS(...))*/

	/* If there was no useful nexthop, then complain. */
	if (nexthop_num == 0) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug(
				"%s: No useful nexthops were found in RIB prefix %s",
				__func__, prefix_buf);
		return 1;
	}

	return 0; /*XXX*/
}

/*
 * Update or delete a prefix from the kernel,
 * using info from a dataplane context struct.
 */
enum zebra_dplane_result kernel_route_update(struct zebra_dplane_ctx *ctx)
{
	enum zebra_dplane_result res = ZEBRA_DPLANE_REQUEST_SUCCESS;
	uint32_t type, old_type;

	if (dplane_ctx_get_src(ctx) != NULL) {
		zlog_err("route add: IPv6 sourcedest routes unsupported!");
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	type = dplane_ctx_get_type(ctx);
	old_type = dplane_ctx_get_old_type(ctx);

	frr_with_privs(&zserv_privs) {

		if (dplane_ctx_get_op(ctx) == DPLANE_OP_ROUTE_DELETE) {
			if (!RSYSTEM_ROUTE(type))
				kernel_rtm(RTM_DELETE, dplane_ctx_get_dest(ctx),
					   dplane_ctx_get_ng(ctx),
					   dplane_ctx_get_metric(ctx));
		} else if (dplane_ctx_get_op(ctx) == DPLANE_OP_ROUTE_INSTALL) {
			if (!RSYSTEM_ROUTE(type))
				kernel_rtm(RTM_ADD, dplane_ctx_get_dest(ctx),
					   dplane_ctx_get_ng(ctx),
					   dplane_ctx_get_metric(ctx));
		} else if (dplane_ctx_get_op(ctx) == DPLANE_OP_ROUTE_UPDATE) {
			/* Must do delete and add separately -
			 * no update available
			 */
			if (!RSYSTEM_ROUTE(old_type))
				kernel_rtm(RTM_DELETE, dplane_ctx_get_dest(ctx),
					   dplane_ctx_get_old_ng(ctx),
					   dplane_ctx_get_old_metric(ctx));

			if (!RSYSTEM_ROUTE(type))
				kernel_rtm(RTM_ADD, dplane_ctx_get_dest(ctx),
					   dplane_ctx_get_ng(ctx),
					   dplane_ctx_get_metric(ctx));
		} else {
			zlog_err("Invalid routing socket update op %s (%u)",
				 dplane_op2str(dplane_ctx_get_op(ctx)),
				 dplane_ctx_get_op(ctx));
			res = ZEBRA_DPLANE_REQUEST_FAILURE;
		}
	} /* Elevated privs */

	if (RSYSTEM_ROUTE(type)
	    && dplane_ctx_get_op(ctx) != DPLANE_OP_ROUTE_DELETE) {
		struct nexthop *nexthop;

		for (ALL_NEXTHOPS_PTR(dplane_ctx_get_ng(ctx), nexthop)) {
			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
				continue;

			if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE)) {
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
			}
		}
	}

	return res;
}

enum zebra_dplane_result kernel_nexthop_update(struct zebra_dplane_ctx *ctx)
{
	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

int kernel_neigh_update(int add, int ifindex, uint32_t addr, char *lla,
			int llalen, ns_id_t ns_id)
{
	/* TODO */
	return 0;
}

/* NYI on routing-socket platforms, but we've always returned 'success'... */
enum zebra_dplane_result kernel_neigh_update_ctx(struct zebra_dplane_ctx *ctx)
{
	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

extern int kernel_get_ipmr_sg_stats(struct zebra_vrf *zvrf, void *mroute)
{
	return 0;
}

/*
 * Update MAC, using dataplane context object. No-op here for now.
 */
enum zebra_dplane_result kernel_mac_update_ctx(struct zebra_dplane_ctx *ctx)
{
	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

extern int kernel_interface_set_master(struct interface *master,
				       struct interface *slave)
{
	return 0;
}

uint32_t kernel_get_speed(struct interface *ifp, int *error)
{
	return ifp->speed;
}

#endif /* !HAVE_NETLINK */
