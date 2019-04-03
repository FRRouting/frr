/*
 * Common ioctl functions.
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

#include "linklist.h"
#include "if.h"
#include "prefix.h"
#include "ioctl.h"
#include "log.h"
#include "privs.h"
#include "lib_errors.h"

#include "vty.h"
#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/interface.h"
#include "zebra/zebra_errors.h"

#ifndef SUNOS_5

#ifdef HAVE_BSD_LINK_DETECT
#include <net/if_media.h>
#endif /* HAVE_BSD_LINK_DETECT*/

extern struct zebra_privs_t zserv_privs;

/* clear and set interface name string */
void ifreq_set_name(struct ifreq *ifreq, struct interface *ifp)
{
	strlcpy(ifreq->ifr_name, ifp->name, sizeof(ifreq->ifr_name));
}

/* call ioctl system call */
int if_ioctl(unsigned long request, caddr_t buffer)
{
	int sock;
	int ret;
	int err = 0;

	frr_elevate_privs(&zserv_privs) {
		sock = socket(AF_INET, SOCK_DGRAM, 0);
		if (sock < 0) {
			zlog_err("Cannot create UDP socket: %s",
				 safe_strerror(errno));
			exit(1);
		}
		if ((ret = ioctl(sock, request, buffer)) < 0)
			err = errno;
	}
	close(sock);

	if (ret < 0) {
		errno = err;
		return ret;
	}
	return 0;
}

/* call ioctl system call */
int vrf_if_ioctl(unsigned long request, caddr_t buffer, vrf_id_t vrf_id)
{
	int sock;
	int ret;
	int err = 0;

	frr_elevate_privs(&zserv_privs) {
		sock = vrf_socket(AF_INET, SOCK_DGRAM, 0, vrf_id, NULL);
		if (sock < 0) {
			zlog_err("Cannot create UDP socket: %s",
				 safe_strerror(errno));
			exit(1);
		}
		ret = vrf_ioctl(vrf_id, sock, request, buffer);
		if (ret < 0)
			err = errno;
	}
	close(sock);

	if (ret < 0) {
		errno = err;
		return ret;
	}
	return 0;
}

#ifndef HAVE_NETLINK
static int if_ioctl_ipv6(unsigned long request, caddr_t buffer)
{
	int sock;
	int ret;
	int err = 0;

	frr_elevate_privs(&zserv_privs) {
		sock = socket(AF_INET6, SOCK_DGRAM, 0);
		if (sock < 0) {
			zlog_err("Cannot create IPv6 datagram socket: %s",
				 safe_strerror(errno));
			exit(1);
		}

		if ((ret = ioctl(sock, request, buffer)) < 0)
			err = errno;
	}
	close(sock);

	if (ret < 0) {
		errno = err;
		return ret;
	}
	return 0;
}
#endif /* ! HAVE_NETLINK */

/*
 * get interface metric
 *   -- if value is not avaliable set -1
 */
void if_get_metric(struct interface *ifp)
{
#ifdef SIOCGIFMETRIC
	struct ifreq ifreq;

	ifreq_set_name(&ifreq, ifp);

	if (vrf_if_ioctl(SIOCGIFMETRIC, (caddr_t)&ifreq, ifp->vrf_id) < 0)
		return;
	ifp->metric = ifreq.ifr_metric;
	if (ifp->metric == 0)
		ifp->metric = 1;
#else  /* SIOCGIFMETRIC */
	ifp->metric = -1;
#endif /* SIOCGIFMETRIC */
}

/* get interface MTU */
void if_get_mtu(struct interface *ifp)
{
	struct ifreq ifreq;

	ifreq_set_name(&ifreq, ifp);

#if defined(SIOCGIFMTU)
	if (vrf_if_ioctl(SIOCGIFMTU, (caddr_t)&ifreq, ifp->vrf_id) < 0) {
		zlog_info("Can't lookup mtu by ioctl(SIOCGIFMTU)");
		ifp->mtu6 = ifp->mtu = -1;
		return;
	}

#ifdef SUNOS_5
	ifp->mtu6 = ifp->mtu = ifreq.ifr_metric;
#else
	ifp->mtu6 = ifp->mtu = ifreq.ifr_mtu;
#endif /* SUNOS_5 */

	/* propogate */
	zebra_interface_up_update(ifp);

#else
	zlog_info("Can't lookup mtu on this system");
	ifp->mtu6 = ifp->mtu = -1;
#endif
}

#ifdef HAVE_NETLINK
/* Interface address setting via netlink interface. */
int if_set_prefix(struct interface *ifp, struct connected *ifc)
{
	return kernel_address_add_ipv4(ifp, ifc);
}

/* Interface address is removed using netlink interface. */
int if_unset_prefix(struct interface *ifp, struct connected *ifc)
{
	return kernel_address_delete_ipv4(ifp, ifc);
}
#else /* ! HAVE_NETLINK */
#ifdef HAVE_STRUCT_IFALIASREQ
/* Set up interface's IP address, netmask (and broadcas? ).  *BSD may
   has ifaliasreq structure.  */
int if_set_prefix(struct interface *ifp, struct connected *ifc)
{
	int ret;
	struct ifaliasreq addreq;
	struct sockaddr_in addr, mask, peer;
	struct prefix_ipv4 *p;

	/* don't configure PtP addresses on broadcast ifs or reverse */
	if (!(ifp->flags & IFF_POINTOPOINT) != !CONNECTED_PEER(ifc)) {
		errno = EINVAL;
		return -1;
	}

	p = (struct prefix_ipv4 *)ifc->address;
	rib_lookup_and_pushup(p, ifp->vrf_id);

	memset(&addreq, 0, sizeof addreq);
	strncpy((char *)&addreq.ifra_name, ifp->name, sizeof addreq.ifra_name);

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_addr = p->prefix;
	addr.sin_family = p->family;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	addr.sin_len = sizeof(struct sockaddr_in);
#endif
	memcpy(&addreq.ifra_addr, &addr, sizeof(struct sockaddr_in));

	if (CONNECTED_PEER(ifc)) {
		p = (struct prefix_ipv4 *)ifc->destination;
		memset(&mask, 0, sizeof(struct sockaddr_in));
		peer.sin_addr = p->prefix;
		peer.sin_family = p->family;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
		peer.sin_len = sizeof(struct sockaddr_in);
#endif
		memcpy(&addreq.ifra_broadaddr, &peer,
		       sizeof(struct sockaddr_in));
	}

	memset(&mask, 0, sizeof(struct sockaddr_in));
	masklen2ip(p->prefixlen, &mask.sin_addr);
	mask.sin_family = p->family;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	mask.sin_len = sizeof(struct sockaddr_in);
#endif
	memcpy(&addreq.ifra_mask, &mask, sizeof(struct sockaddr_in));

	ret = if_ioctl(SIOCAIFADDR, (caddr_t)&addreq);
	if (ret < 0)
		return ret;
	return 0;
}

/* Set up interface's IP address, netmask (and broadcas? ).  *BSD may
   has ifaliasreq structure.  */
int if_unset_prefix(struct interface *ifp, struct connected *ifc)
{
	int ret;
	struct ifaliasreq addreq;
	struct sockaddr_in addr, mask, peer;
	struct prefix_ipv4 *p;

	/* this would probably wreak havoc */
	if (!(ifp->flags & IFF_POINTOPOINT) != !CONNECTED_PEER(ifc)) {
		errno = EINVAL;
		return -1;
	}

	p = (struct prefix_ipv4 *)ifc->address;

	memset(&addreq, 0, sizeof addreq);
	strncpy((char *)&addreq.ifra_name, ifp->name, sizeof addreq.ifra_name);

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_addr = p->prefix;
	addr.sin_family = p->family;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	addr.sin_len = sizeof(struct sockaddr_in);
#endif
	memcpy(&addreq.ifra_addr, &addr, sizeof(struct sockaddr_in));

	if (CONNECTED_PEER(ifc)) {
		p = (struct prefix_ipv4 *)ifc->destination;
		memset(&mask, 0, sizeof(struct sockaddr_in));
		peer.sin_addr = p->prefix;
		peer.sin_family = p->family;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
		peer.sin_len = sizeof(struct sockaddr_in);
#endif
		memcpy(&addreq.ifra_broadaddr, &peer,
		       sizeof(struct sockaddr_in));
	}

	memset(&mask, 0, sizeof(struct sockaddr_in));
	masklen2ip(p->prefixlen, &mask.sin_addr);
	mask.sin_family = p->family;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	mask.sin_len = sizeof(struct sockaddr_in);
#endif
	memcpy(&addreq.ifra_mask, &mask, sizeof(struct sockaddr_in));

	ret = if_ioctl(SIOCDIFADDR, (caddr_t)&addreq);
	if (ret < 0)
		return ret;
	return 0;
}
#else
/* Set up interface's address, netmask (and broadcas? ).  Linux or
   Solaris uses ifname:number semantics to set IP address aliases. */
int if_set_prefix(struct interface *ifp, struct connected *ifc)
{
	int ret;
	struct ifreq ifreq;
	struct sockaddr_in addr;
	struct sockaddr_in broad;
	struct sockaddr_in mask;
	struct prefix_ipv4 ifaddr;
	struct prefix_ipv4 *p;

	p = (struct prefix_ipv4 *)ifc->address;

	ifaddr = *p;

	ifreq_set_name(&ifreq, ifp);

	addr.sin_addr = p->prefix;
	addr.sin_family = p->family;
	memcpy(&ifreq.ifr_addr, &addr, sizeof(struct sockaddr_in));
	ret = if_ioctl(SIOCSIFADDR, (caddr_t)&ifreq);
	if (ret < 0)
		return ret;

	/* We need mask for make broadcast addr. */
	masklen2ip(p->prefixlen, &mask.sin_addr);

	if (if_is_broadcast(ifp)) {
		apply_mask_ipv4(&ifaddr);
		addr.sin_addr = ifaddr.prefix;

		broad.sin_addr.s_addr =
			(addr.sin_addr.s_addr | ~mask.sin_addr.s_addr);
		broad.sin_family = p->family;

		memcpy(&ifreq.ifr_broadaddr, &broad,
		       sizeof(struct sockaddr_in));
		ret = if_ioctl(SIOCSIFBRDADDR, (caddr_t)&ifreq);
		if (ret < 0)
			return ret;
	}

	mask.sin_family = p->family;
#ifdef SUNOS_5
	memcpy(&mask, &ifreq.ifr_addr, sizeof(mask));
#else
	memcpy(&ifreq.ifr_netmask, &mask, sizeof(struct sockaddr_in));
#endif /* SUNOS5 */
	ret = if_ioctl(SIOCSIFNETMASK, (caddr_t)&ifreq);
	if (ret < 0)
		return ret;

	return 0;
}

/* Set up interface's address, netmask (and broadcas? ).  Linux or
   Solaris uses ifname:number semantics to set IP address aliases. */
int if_unset_prefix(struct interface *ifp, struct connected *ifc)
{
	int ret;
	struct ifreq ifreq;
	struct sockaddr_in addr;
	struct prefix_ipv4 *p;

	p = (struct prefix_ipv4 *)ifc->address;

	ifreq_set_name(&ifreq, ifp);

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = p->family;
	memcpy(&ifreq.ifr_addr, &addr, sizeof(struct sockaddr_in));
	ret = if_ioctl(SIOCSIFADDR, (caddr_t)&ifreq);
	if (ret < 0)
		return ret;

	return 0;
}
#endif /* HAVE_STRUCT_IFALIASREQ */
#endif /* HAVE_NETLINK */

/* get interface flags */
void if_get_flags(struct interface *ifp)
{
	int ret;
	struct ifreq ifreq;
#ifdef HAVE_BSD_LINK_DETECT
	struct ifmediareq ifmr;
#endif /* HAVE_BSD_LINK_DETECT */

	ifreq_set_name(&ifreq, ifp);

	ret = vrf_if_ioctl(SIOCGIFFLAGS, (caddr_t)&ifreq, ifp->vrf_id);
	if (ret < 0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "vrf_if_ioctl(SIOCGIFFLAGS) failed: %s",
			     safe_strerror(errno));
		return;
	}
#ifdef HAVE_BSD_LINK_DETECT /* Detect BSD link-state at start-up */

	/* Per-default, IFF_RUNNING is held high, unless link-detect says
	 * otherwise - we abuse IFF_RUNNING inside zebra as a link-state flag,
	 * following practice on Linux and Solaris kernels
	 */
	SET_FLAG(ifreq.ifr_flags, IFF_RUNNING);

	if (CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION)) {
		(void)memset(&ifmr, 0, sizeof(ifmr));
		strncpy(ifmr.ifm_name, ifp->name, IFNAMSIZ);

		/* Seems not all interfaces implement this ioctl */
		if (if_ioctl(SIOCGIFMEDIA, (caddr_t)&ifmr) == -1 &&
		    errno != EINVAL)
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "if_ioctl(SIOCGIFMEDIA) failed: %s",
				     safe_strerror(errno));
		else if (ifmr.ifm_status & IFM_AVALID) /* Link state is valid */
		{
			if (ifmr.ifm_status & IFM_ACTIVE)
				SET_FLAG(ifreq.ifr_flags, IFF_RUNNING);
			else
				UNSET_FLAG(ifreq.ifr_flags, IFF_RUNNING);
		}
	}
#endif /* HAVE_BSD_LINK_DETECT */

	if_flags_update(ifp, (ifreq.ifr_flags & 0x0000ffff));
}

/* Set interface flags */
int if_set_flags(struct interface *ifp, uint64_t flags)
{
	int ret;
	struct ifreq ifreq;

	memset(&ifreq, 0, sizeof(struct ifreq));
	ifreq_set_name(&ifreq, ifp);

	ifreq.ifr_flags = ifp->flags;
	ifreq.ifr_flags |= flags;

	ret = vrf_if_ioctl(SIOCSIFFLAGS, (caddr_t)&ifreq, ifp->vrf_id);

	if (ret < 0) {
		zlog_info("can't set interface flags");
		return ret;
	}
	return 0;
}

/* Unset interface's flag. */
int if_unset_flags(struct interface *ifp, uint64_t flags)
{
	int ret;
	struct ifreq ifreq;

	memset(&ifreq, 0, sizeof(struct ifreq));
	ifreq_set_name(&ifreq, ifp);

	ifreq.ifr_flags = ifp->flags;
	ifreq.ifr_flags &= ~flags;

	ret = vrf_if_ioctl(SIOCSIFFLAGS, (caddr_t)&ifreq, ifp->vrf_id);

	if (ret < 0) {
		zlog_info("can't unset interface flags");
		return ret;
	}
	return 0;
}

#ifdef LINUX_IPV6
#ifndef _LINUX_IN6_H
/* linux/include/net/ipv6.h */
struct in6_ifreq {
	struct in6_addr ifr6_addr;
	uint32_t ifr6_prefixlen;
	int ifr6_ifindex;
};
#endif /* _LINUX_IN6_H */
/* Interface's address add/delete functions. */
int if_prefix_add_ipv6(struct interface *ifp, struct connected *ifc)
{
#ifdef HAVE_NETLINK
	return kernel_address_add_ipv6(ifp, ifc);
#endif /* HAVE_NETLINK */
}

int if_prefix_delete_ipv6(struct interface *ifp, struct connected *ifc)
{
#ifdef HAVE_NETLINK
	return kernel_address_delete_ipv6(ifp, ifc);
#endif /* HAVE_NETLINK */
}
#else /* LINUX_IPV6 */
#ifdef HAVE_STRUCT_IN6_ALIASREQ
#ifndef ND6_INFINITE_LIFETIME
#define ND6_INFINITE_LIFETIME 0xffffffffL
#endif /* ND6_INFINITE_LIFETIME */
int if_prefix_add_ipv6(struct interface *ifp, struct connected *ifc)
{
	int ret;
	struct in6_aliasreq addreq;
	struct sockaddr_in6 addr;
	struct sockaddr_in6 mask;
	struct prefix_ipv6 *p;

	p = (struct prefix_ipv6 *)ifc->address;

	memset(&addreq, 0, sizeof addreq);
	strncpy((char *)&addreq.ifra_name, ifp->name, sizeof addreq.ifra_name);

	memset(&addr, 0, sizeof(struct sockaddr_in6));
	addr.sin6_addr = p->prefix;
	addr.sin6_family = p->family;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
	memcpy(&addreq.ifra_addr, &addr, sizeof(struct sockaddr_in6));

	memset(&mask, 0, sizeof(struct sockaddr_in6));
	masklen2ip6(p->prefixlen, &mask.sin6_addr);
	mask.sin6_family = p->family;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	mask.sin6_len = sizeof(struct sockaddr_in6);
#endif
	memcpy(&addreq.ifra_prefixmask, &mask, sizeof(struct sockaddr_in6));

	addreq.ifra_lifetime.ia6t_vltime = 0xffffffff;
	addreq.ifra_lifetime.ia6t_pltime = 0xffffffff;

#ifdef HAVE_STRUCT_IF6_ALIASREQ_IFRA_LIFETIME
	addreq.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
	addreq.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
#endif

	ret = if_ioctl_ipv6(SIOCAIFADDR_IN6, (caddr_t)&addreq);
	if (ret < 0)
		return ret;
	return 0;
}

int if_prefix_delete_ipv6(struct interface *ifp, struct connected *ifc)
{
	int ret;
	struct in6_aliasreq addreq;
	struct sockaddr_in6 addr;
	struct sockaddr_in6 mask;
	struct prefix_ipv6 *p;

	p = (struct prefix_ipv6 *)ifc->address;

	memset(&addreq, 0, sizeof addreq);
	strncpy((char *)&addreq.ifra_name, ifp->name, sizeof addreq.ifra_name);

	memset(&addr, 0, sizeof(struct sockaddr_in6));
	addr.sin6_addr = p->prefix;
	addr.sin6_family = p->family;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
	memcpy(&addreq.ifra_addr, &addr, sizeof(struct sockaddr_in6));

	memset(&mask, 0, sizeof(struct sockaddr_in6));
	masklen2ip6(p->prefixlen, &mask.sin6_addr);
	mask.sin6_family = p->family;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	mask.sin6_len = sizeof(struct sockaddr_in6);
#endif
	memcpy(&addreq.ifra_prefixmask, &mask, sizeof(struct sockaddr_in6));

#ifdef HAVE_STRUCT_IF6_ALIASREQ_IFRA_LIFETIME
	addreq.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;
	addreq.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
#endif

	ret = if_ioctl_ipv6(SIOCDIFADDR_IN6, (caddr_t)&addreq);
	if (ret < 0)
		return ret;
	return 0;
}
#else
int if_prefix_add_ipv6(struct interface *ifp, struct connected *ifc)
{
	return 0;
}

int if_prefix_delete_ipv6(struct interface *ifp, struct connected *ifc)
{
	return 0;
}
#endif /* HAVE_STRUCT_IN6_ALIASREQ */

#endif /* LINUX_IPV6 */

#endif /* !SUNOS_5 */
