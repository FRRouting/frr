/*
 * Interface looking up by ioctl () on Solaris.
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

#ifdef SUNOS_5

#include "if.h"
#include "sockunion.h"
#include "prefix.h"
#include "ioctl.h"
#include "connected.h"
#include "memory.h"
#include "zebra_memory.h"
#include "log.h"
#include "privs.h"
#include "vrf.h"
#include "vty.h"
#include "lib_errors.h"

#include "zebra/interface.h"
#include "zebra/ioctl_solaris.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zebra_errors.h"

static int if_get_addr(struct interface *, struct sockaddr *, const char *);
static void interface_info_ioctl(struct interface *);
extern struct zebra_privs_t zserv_privs;

static int interface_list_ioctl(int af)
{
	int ret;
	int sock;
#define IFNUM_BASE 32
	struct lifnum lifn;
	int ifnum;
	struct lifreq *lifreq;
	struct lifconf lifconf;
	struct interface *ifp;
	int n;
	size_t needed, lastneeded = 0;
	char *buf = NULL;

	frr_with_privs(&zserv_privs) {
		sock = socket(af, SOCK_DGRAM, 0);
	}

	if (sock < 0) {
		flog_err_sys(EC_LIB_SOCKET, "Can't make %s socket stream: %s",
			     (af == AF_INET ? "AF_INET" : "AF_INET6"),
			     safe_strerror(errno));
		return -1;
	}

calculate_lifc_len:
	frr_with_privs(&zserv_privs) {
		lifn.lifn_family = af;
		lifn.lifn_flags = LIFC_NOXMIT;
		/* we want NOXMIT interfaces too */
		ret = ioctl(sock, SIOCGLIFNUM, &lifn);
	}

	if (ret < 0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "interface_list_ioctl: SIOCGLIFNUM failed %s",
			     safe_strerror(errno));
		close(sock);
		return -1;
	}
	ifnum = lifn.lifn_count;

	/*
	 * When calculating the buffer size needed, add a small number
	 * of interfaces to those we counted.  We do this to capture
	 * the interface status of potential interfaces which may have
	 * been plumbed between the SIOCGLIFNUM and the SIOCGLIFCONF.
	 */
	needed = (ifnum + 4) * sizeof(struct lifreq);
	if (needed > lastneeded || needed < lastneeded / 2) {
		if (buf != NULL)
			XFREE(MTYPE_TMP, buf);
		buf = XMALLOC(MTYPE_TMP, needed);
	}
	lastneeded = needed;

	lifconf.lifc_family = af;
	lifconf.lifc_flags = LIFC_NOXMIT;
	lifconf.lifc_len = needed;
	lifconf.lifc_buf = buf;

	frr_with_privs(&zserv_privs) {
		ret = ioctl(sock, SIOCGLIFCONF, &lifconf);
	}

	if (ret < 0) {
		if (errno == EINVAL)
			goto calculate_lifc_len;

		flog_err_sys(EC_LIB_SYSTEM_CALL, "SIOCGLIFCONF: %s",
			     safe_strerror(errno));
		goto end;
	}

	/* Allocate interface. */
	lifreq = lifconf.lifc_req;

	for (n = 0; n < lifconf.lifc_len; n += sizeof(struct lifreq)) {
		/* we treat Solaris logical interfaces as addresses, because
		 * that is
		 * how PF_ROUTE on Solaris treats them. Hence we can not
		 * directly use
		 * the lifreq_name to get the ifp.  We need to normalise the
		 * name
		 * before attempting get.
		 *
		 * Solaris logical interface names are in the form of:
		 * <interface name>:<logical interface id>
		 */
		unsigned int normallen = 0;
		uint64_t lifflags;

		/* We should exclude ~IFF_UP interfaces, as we'll find out about
		 * them
		 * coming up later through RTM_NEWADDR message on the route
		 * socket.
		 */
		if (if_get_flags_direct(lifreq->lifr_name, &lifflags,
					lifreq->lifr_addr.ss_family)
		    || !CHECK_FLAG(lifflags, IFF_UP)) {
			lifreq++;
			continue;
		}

		/* Find the normalised name */
		while ((normallen < sizeof(lifreq->lifr_name))
		       && (*(lifreq->lifr_name + normallen) != '\0')
		       && (*(lifreq->lifr_name + normallen) != ':'))
			normallen++;

		ifp = if_get_by_name(lifreq->lifr_name, VRF_DEFAULT);

		if (lifreq->lifr_addr.ss_family == AF_INET)
			ifp->flags |= IFF_IPV4;

		if (lifreq->lifr_addr.ss_family == AF_INET6) {
			ifp->flags |= IFF_IPV6;
		}

		if_add_update(ifp);

		interface_info_ioctl(ifp);

		/* If a logical interface pass the full name so it can be
		 * as a label on the address
		 */
		if (*(lifreq->lifr_name + normallen) != '\0')
			if_get_addr(ifp, (struct sockaddr *)&lifreq->lifr_addr,
				    lifreq->lifr_name);
		else
			if_get_addr(ifp, (struct sockaddr *)&lifreq->lifr_addr,
				    NULL);

		/* Poke the interface flags. Lets IFF_UP mangling kick in */
		if_flags_update(ifp, ifp->flags);

		lifreq++;
	}

end:
	close(sock);
	XFREE(MTYPE_TMP, lifconf.lifc_buf);
	return ret;
}

/* Get interface's index by ioctl. */
static int if_get_index(struct interface *ifp)
{
	int ret;
	struct lifreq lifreq;

	lifreq_set_name(&lifreq, ifp->name);

	if (ifp->flags & IFF_IPV4)
		ret = AF_IOCTL(AF_INET, SIOCGLIFINDEX, (caddr_t)&lifreq);
	else if (ifp->flags & IFF_IPV6)
		ret = AF_IOCTL(AF_INET6, SIOCGLIFINDEX, (caddr_t)&lifreq);
	else
		ret = -1;

	if (ret < 0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL, "SIOCGLIFINDEX(%s) failed",
			     ifp->name);
		return ret;
	}

/* OK we got interface index. */
#ifdef ifr_ifindex
	if_set_index(ifp, lifreq.lifr_ifindex);
#else
	if_set_index(ifp, lifreq.lifr_index);
#endif
	return ifp->ifindex;
}


/* Interface address lookup by ioctl.  This function only looks up
   IPv4 address. */
#define ADDRLEN(sa)                                                            \
	(((sa)->sa_family == AF_INET ? sizeof(struct sockaddr_in)              \
				     : sizeof(struct sockaddr_in6)))

#define SIN(s) ((struct sockaddr_in *)(s))
#define SIN6(s) ((struct sockaddr_in6 *)(s))

/* Retrieve address information for the given ifp */
static int if_get_addr(struct interface *ifp, struct sockaddr *addr,
		       const char *label)
{
	int ret;
	struct lifreq lifreq;
	struct sockaddr_storage mask, dest;
	char *dest_pnt = NULL;
	uint8_t prefixlen = 0;
	afi_t af;
	int flags = 0;

	/* Interface's name and address family.
	 * We need to use the logical interface name / label, if we've been
	 * given one, in order to get the right address
	 */
	strlcpy(lifreq.lifr_name, (label ? label : ifp->name),
		sizeof(lifreq.lifr_name));

	/* Interface's address. */
	memcpy(&lifreq.lifr_addr, addr, ADDRLEN(addr));
	af = addr->sa_family;

	/* Point to point or broad cast address pointer init. */
	dest_pnt = NULL;

	if (AF_IOCTL(af, SIOCGLIFDSTADDR, (caddr_t)&lifreq) >= 0) {
		memcpy(&dest, &lifreq.lifr_dstaddr, ADDRLEN(addr));
		if (af == AF_INET)
			dest_pnt = (char *)&(SIN(&dest)->sin_addr);
		else
			dest_pnt = (char *)&(SIN6(&dest)->sin6_addr);
		flags = ZEBRA_IFA_PEER;
	}

	if (af == AF_INET) {
		ret = if_ioctl(SIOCGLIFNETMASK, (caddr_t)&lifreq);

		if (ret < 0) {
			if (errno != EADDRNOTAVAIL) {
				flog_err_sys(EC_LIB_SYSTEM_CALL,
					     "SIOCGLIFNETMASK (%s) fail: %s",
					     ifp->name, safe_strerror(errno));
				return ret;
			}
			return 0;
		}
		memcpy(&mask, &lifreq.lifr_addr, ADDRLEN(addr));

		prefixlen = ip_masklen(SIN(&mask)->sin_addr);
		if (!dest_pnt
		    && (if_ioctl(SIOCGLIFBRDADDR, (caddr_t)&lifreq) >= 0)) {
			memcpy(&dest, &lifreq.lifr_broadaddr,
			       sizeof(struct sockaddr_in));
			dest_pnt = (char *)&SIN(&dest)->sin_addr;
		}
	} else if (af == AF_INET6) {
		if (if_ioctl_ipv6(SIOCGLIFSUBNET, (caddr_t)&lifreq) < 0) {
			if (ifp->flags & IFF_POINTOPOINT)
				prefixlen = IPV6_MAX_BITLEN;
			else
				flog_err_sys(EC_LIB_SYSTEM_CALL,
					     "SIOCGLIFSUBNET (%s) fail: %s",
					     ifp->name, safe_strerror(errno));
		} else {
			prefixlen = lifreq.lifr_addrlen;
		}
	}

	/* Set address to the interface. */
	if (af == AF_INET)
		connected_add_ipv4(ifp, flags, &SIN(addr)->sin_addr, prefixlen,
				   (struct in_addr *)dest_pnt, label,
				   METRIC_MAX);
	else if (af == AF_INET6)
		connected_add_ipv6(ifp, flags, &SIN6(addr)->sin6_addr, NULL,
				   prefixlen, label, METRIC_MAX);

	return 0;
}

/* Fetch interface information via ioctl(). */
static void interface_info_ioctl(struct interface *ifp)
{
	if_get_index(ifp);
	if_get_flags(ifp);
	if_get_mtu(ifp);
	if_get_metric(ifp);
}

/* Lookup all interface information. */
void interface_list(struct zebra_ns *zns)
{
	if (zns->ns_id != NS_DEFAULT) {
		zlog_debug("interface_list: ignore NS %u", zns->ns_id);
		return;
	}
	interface_list_ioctl(AF_INET);
	interface_list_ioctl(AF_INET6);
	interface_list_ioctl(AF_UNSPEC);
}

struct connected *if_lookup_linklocal(struct interface *ifp)
{
	struct listnode *node;
	struct connected *ifc;

	if (ifp == NULL)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc)) {
		if ((ifc->address->family == AF_INET6)
		    && (IN6_IS_ADDR_LINKLOCAL(&ifc->address->u.prefix6)))
			return ifc;
	}

	return NULL;
}

#endif /* SUNOS_5 */
