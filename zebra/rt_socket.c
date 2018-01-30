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

#include "zebra/debug.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/kernel_socket.h"
#include "zebra/zebra_mpls.h"

extern struct zebra_privs_t zserv_privs;

#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
/* Adjust netmask socket length. Return value is a adjusted sin_len
   value. */
static int sin_masklen(struct in_addr mask)
{
	char *p, *lim;
	int len;
	struct sockaddr_in sin;

	if (mask.s_addr == 0)
		return sizeof(long);

	sin.sin_addr = mask;
	len = sizeof(struct sockaddr_in);

	lim = (char *)&sin.sin_addr;
	p = lim + sizeof(sin.sin_addr);

	while (*--p == 0 && p >= lim)
		len--;
	return len;
}
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */

#ifdef __OpenBSD__
static int kernel_rtm_add_labels(struct mpls_label_stack *nh_label,
				 struct sockaddr_mpls *smpls)
{
	if (nh_label->num_labels > 1) {
		zlog_warn(
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
static int kernel_rtm_ipv4(int cmd, struct prefix *p, struct route_entry *re)

{
	struct sockaddr_in *mask = NULL;
	struct sockaddr_in sin_dest, sin_mask, sin_gate;
#ifdef __OpenBSD__
	struct sockaddr_mpls smpls;
#endif
	union sockunion *smplsp = NULL;
	struct nexthop *nexthop;
	int nexthop_num = 0;
	ifindex_t ifindex = 0;
	int gate = 0;
	int error;
	char prefix_buf[PREFIX_STRLEN];
	enum blackhole_type bh_type = BLACKHOLE_UNSPEC;

	if (IS_ZEBRA_DEBUG_RIB)
		prefix2str(p, prefix_buf, sizeof(prefix_buf));
	memset(&sin_dest, 0, sizeof(struct sockaddr_in));
	sin_dest.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	sin_dest.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
	sin_dest.sin_addr = p->u.prefix4;

	memset(&sin_mask, 0, sizeof(struct sockaddr_in));

	memset(&sin_gate, 0, sizeof(struct sockaddr_in));
	sin_gate.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	sin_gate.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */

	/* Make gateway. */
	for (ALL_NEXTHOPS(re->nexthop, nexthop)) {
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
			continue;

		gate = 0;
		char gate_buf[INET_ADDRSTRLEN] = "NULL";

		/*
		 * XXX We need to refrain from kernel operations in some cases,
		 * but this if statement seems overly cautious - what about
		 * other than ADD and DELETE?
		 */
		if ((cmd == RTM_ADD
		     && NEXTHOP_IS_ACTIVE(nexthop->flags))
		    || (cmd == RTM_DELETE
			&& CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB))) {
			if (nexthop->type == NEXTHOP_TYPE_IPV4
			    || nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX) {
				sin_gate.sin_addr = nexthop->gate.ipv4;
				gate = 1;
			}
			if (nexthop->type == NEXTHOP_TYPE_IFINDEX
			    || nexthop->type == NEXTHOP_TYPE_IPV4_IFINDEX)
				ifindex = nexthop->ifindex;
			if (nexthop->type == NEXTHOP_TYPE_BLACKHOLE) {
				struct in_addr loopback;
				loopback.s_addr = htonl(INADDR_LOOPBACK);
				sin_gate.sin_addr = loopback;
				bh_type = nexthop->bh_type;
				gate = 1;
			}

			if (gate && p->prefixlen == 32)
				mask = NULL;
			else {
				masklen2ip(p->prefixlen, &sin_mask.sin_addr);
				sin_mask.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
				sin_mask.sin_len =
					sin_masklen(sin_mask.sin_addr);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
				mask = &sin_mask;
			}

#ifdef __OpenBSD__
			if (nexthop->nh_label
			    && !kernel_rtm_add_labels(nexthop->nh_label,
						      &smpls))
				continue;
			smplsp = (union sockunion *)&smpls;
#endif

			error = rtm_write(cmd, (union sockunion *)&sin_dest,
					  (union sockunion *)mask,
					  gate ? (union sockunion *)&sin_gate
					       : NULL,
					  smplsp, ifindex, bh_type, re->metric);

			if (IS_ZEBRA_DEBUG_RIB) {
				if (!gate) {
					zlog_debug(
						"%s: %s: attention! gate not found for re %p",
						__func__, prefix_buf, re);
					route_entry_dump(p, NULL, re);
				} else
					inet_ntop(AF_INET, &sin_gate.sin_addr,
						  gate_buf, INET_ADDRSTRLEN);
			}

			switch (error) {
			/* We only flag nexthops as being in FIB if rtm_write()
			 * did its work. */
			case ZEBRA_ERR_NOERROR:
				nexthop_num++;
				if (IS_ZEBRA_DEBUG_RIB)
					zlog_debug(
						"%s: %s: successfully did NH %s",
						__func__, prefix_buf, gate_buf);
				break;

			/* The only valid case for this error is kernel's
			 * failure to install
			 * a multipath route, which is common for FreeBSD. This
			 * should be
			 * ignored silently, but logged as an error otherwise.
			 */
			case ZEBRA_ERR_RTEXIST:
				if (cmd != RTM_ADD)
					zlog_err(
						"%s: rtm_write() returned %d for command %d",
						__func__, error, cmd);
				continue;
				break;

			/* Given that our NEXTHOP_FLAG_FIB matches real kernel
			 * FIB, it isn't
			 * normal to get any other messages in ANY case.
			 */
			case ZEBRA_ERR_RTNOEXIST:
			case ZEBRA_ERR_RTUNREACH:
			default:
				zlog_err(
					"%s: %s: rtm_write() unexpectedly returned %d for command %s",
					__func__,
					prefix2str(p, prefix_buf,
						   sizeof(prefix_buf)),
					error,
					lookup_msg(rtm_type_str, cmd, NULL));
				break;
			}
		} /* if (cmd and flags make sense) */
		else if (IS_ZEBRA_DEBUG_RIB)
			zlog_debug("%s: odd command %s for flags %d", __func__,
				   lookup_msg(rtm_type_str, cmd, NULL),
				   nexthop->flags);
	} /* for (ALL_NEXTHOPS(...))*/

	/* If there was no useful nexthop, then complain. */
	if (nexthop_num == 0 && IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: No useful nexthops were found in RIB entry %p",
			   __func__, re);

	return 0; /*XXX*/
}

#ifdef SIN6_LEN
/* Calculate sin6_len value for netmask socket value. */
static int sin6_masklen(struct in6_addr mask)
{
	struct sockaddr_in6 sin6;
	char *p, *lim;
	int len;

	if (IN6_IS_ADDR_UNSPECIFIED(&mask))
		return sizeof(long);

	sin6.sin6_addr = mask;
	len = sizeof(struct sockaddr_in6);

	lim = (char *)&sin6.sin6_addr;
	p = lim + sizeof(sin6.sin6_addr);

	while (*--p == 0 && p >= lim)
		len--;

	return len;
}
#endif /* SIN6_LEN */

/* Interface between zebra message and rtm message. */
static int kernel_rtm_ipv6(int cmd, struct prefix *p, struct route_entry *re)
{
	struct sockaddr_in6 *mask;
	struct sockaddr_in6 sin_dest, sin_mask, sin_gate;
#ifdef __OpenBSD__
	struct sockaddr_mpls smpls;
#endif
	union sockunion *smplsp = NULL;
	struct nexthop *nexthop;
	int nexthop_num = 0;
	ifindex_t ifindex = 0;
	int gate = 0;
	int error;
	enum blackhole_type bh_type = BLACKHOLE_UNSPEC;

	memset(&sin_dest, 0, sizeof(struct sockaddr_in6));
	sin_dest.sin6_family = AF_INET6;
#ifdef SIN6_LEN
	sin_dest.sin6_len = sizeof(struct sockaddr_in6);
#endif /* SIN6_LEN */
	sin_dest.sin6_addr = p->u.prefix6;

	memset(&sin_mask, 0, sizeof(struct sockaddr_in6));

	memset(&sin_gate, 0, sizeof(struct sockaddr_in6));
	sin_gate.sin6_family = AF_INET6;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	sin_gate.sin6_len = sizeof(struct sockaddr_in6);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */

	/* Make gateway. */
	for (ALL_NEXTHOPS(re->nexthop, nexthop)) {
		if (CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_RECURSIVE))
			continue;

		gate = 0;

		if ((cmd == RTM_ADD
		     && NEXTHOP_IS_ACTIVE(nexthop->flags))
		    || (cmd == RTM_DELETE)) {
			if (nexthop->type == NEXTHOP_TYPE_IPV6
			    || nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX) {
				sin_gate.sin6_addr = nexthop->gate.ipv6;
				gate = 1;
			}
			if (nexthop->type == NEXTHOP_TYPE_IFINDEX
			    || nexthop->type == NEXTHOP_TYPE_IPV6_IFINDEX)
				ifindex = nexthop->ifindex;

			if (nexthop->type == NEXTHOP_TYPE_BLACKHOLE)
				bh_type = nexthop->bh_type;
		}

/* Under kame set interface index to link local address. */
#ifdef KAME

#define SET_IN6_LINKLOCAL_IFINDEX(a, i)                                        \
	do {                                                                   \
		(a).s6_addr[2] = ((i) >> 8) & 0xff;                            \
		(a).s6_addr[3] = (i)&0xff;                                     \
	} while (0)

		if (gate && IN6_IS_ADDR_LINKLOCAL(&sin_gate.sin6_addr))
			SET_IN6_LINKLOCAL_IFINDEX(sin_gate.sin6_addr, ifindex);
#endif /* KAME */

		if (gate && p->prefixlen == 128)
			mask = NULL;
		else {
			masklen2ip6(p->prefixlen, &sin_mask.sin6_addr);
			sin_mask.sin6_family = AF_INET6;
#ifdef SIN6_LEN
			sin_mask.sin6_len = sin6_masklen(sin_mask.sin6_addr);
#endif /* SIN6_LEN */
			mask = &sin_mask;
		}

#ifdef __OpenBSD__
		if (nexthop->nh_label
		    && !kernel_rtm_add_labels(nexthop->nh_label, &smpls))
			continue;
		smplsp = (union sockunion *)&smpls;
#endif

		error = rtm_write(cmd, (union sockunion *)&sin_dest,
				  (union sockunion *)mask,
				  gate ? (union sockunion *)&sin_gate : NULL,
				  smplsp, ifindex, bh_type, re->metric);
		(void)error;

		nexthop_num++;
	}

	/* If there is no useful nexthop then return. */
	if (nexthop_num == 0) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("kernel_rtm_ipv6(): No useful nexthop.");
		return 0;
	}

	return 0; /*XXX*/
}

static int kernel_rtm(int cmd, struct prefix *p, struct route_entry *re)
{
	switch (PREFIX_FAMILY(p)) {
	case AF_INET:
		return kernel_rtm_ipv4(cmd, p, re);
	case AF_INET6:
		return kernel_rtm_ipv6(cmd, p, re);
	}
	return 0;
}

void kernel_route_rib(struct route_node *rn, struct prefix *p,
		      struct prefix *src_p, struct route_entry *old,
		      struct route_entry *new)
{
	int route = 0;

	if (src_p && src_p->prefixlen) {
		zlog_err("route add: IPv6 sourcedest routes unsupported!");
		return;
	}

	if (zserv_privs.change(ZPRIVS_RAISE))
		zlog_err("Can't raise privileges");

	if (old)
		route |= kernel_rtm(RTM_DELETE, p, old);

	if (new)
		route |= kernel_rtm(RTM_ADD, p, new);

	if (zserv_privs.change(ZPRIVS_LOWER))
		zlog_err("Can't lower privileges");

	if (new) {
		kernel_route_rib_pass_fail(rn, p, new,
					   (!route) ?
					   SOUTHBOUND_INSTALL_SUCCESS :
					   SOUTHBOUND_INSTALL_FAILURE);
	} else {
		kernel_route_rib_pass_fail(rn, p, old,
					   (!route) ?
					   SOUTHBOUND_DELETE_SUCCESS :
					   SOUTHBOUND_DELETE_FAILURE);
	}
}

int kernel_neigh_update(int add, int ifindex, uint32_t addr, char *lla,
			int llalen)
{
	/* TODO */
	return 0;
}

extern int kernel_get_ipmr_sg_stats(struct zebra_vrf *zvrf, void *mroute)
{
	return 0;
}

int kernel_add_vtep(vni_t vni, struct interface *ifp, struct in_addr *vtep_ip)
{
	return 0;
}

int kernel_del_vtep(vni_t vni, struct interface *ifp, struct in_addr *vtep_ip)
{
	return 0;
}

int kernel_add_mac(struct interface *ifp, vlanid_t vid, struct ethaddr *mac,
		   struct in_addr vtep_ip, u_char sticky)
{
	return 0;
}

int kernel_del_mac(struct interface *ifp, vlanid_t vid, struct ethaddr *mac,
		   struct in_addr vtep_ip, int local)
{
	return 0;
}

int kernel_add_neigh(struct interface *ifp, struct ipaddr *ip,
		     struct ethaddr *mac)
{
	return 0;
}

int kernel_del_neigh(struct interface *ifp, struct ipaddr *ip)
{
	return 0;
}

extern int kernel_interface_set_master(struct interface *master,
				       struct interface *slave)
{
	return 0;
}

uint32_t kernel_get_speed(struct interface *ifp)
{
	return ifp->speed;
}

#endif /* !HAVE_NETLINK */
