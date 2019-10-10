/*
 * Common ioctl functions for Solaris.
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

#include "linklist.h"
#include "if.h"
#include "prefix.h"
#include "ioctl.h"
#include "log.h"
#include "privs.h"
#include "vty.h"
#include "vrf.h"
#include "lib_errors.h"

#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/interface.h"
#include "zebra/ioctl_solaris.h"
#include "zebra/zebra_errors.h"
#include "zebra/debug.h"

extern struct zebra_privs_t zserv_privs;

/* Prototypes */
static int if_set_prefix_ctx(const struct zebra_dplane_ctx *ctx);
static int if_unset_prefix_ctx(const struct zebra_dplane_ctx *ctx);
static int if_set_prefix6_ctx(const struct zebra_dplane_ctx *ctx);
static int if_unset_prefix6_ctx(const struct zebra_dplane_ctx *ctx);

/* clear and set interface name string */
void lifreq_set_name(struct lifreq *lifreq, const char *ifname)
{
	strlcpy(lifreq->lifr_name, ifname, sizeof(lifreq->lifr_name));
}

int vrf_if_ioctl(unsigned long request, caddr_t buffer, vrf_id_t vrf_id)
{
	return if_ioctl(request, buffer);
}

/* call ioctl system call */
int if_ioctl(unsigned long request, caddr_t buffer)
{
	int sock;
	int ret;
	int err;

	frr_with_privs(&zserv_privs) {

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


int if_ioctl_ipv6(unsigned long request, caddr_t buffer)
{
	int sock;
	int ret;
	int err;

	frr_with_privs(&zserv_privs) {

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

/*
 * get interface metric
 *   -- if value is not avaliable set -1
 */
void if_get_metric(struct interface *ifp)
{
	struct lifreq lifreq;
	int ret;

	lifreq_set_name(&lifreq, ifp->name);

	if (ifp->flags & IFF_IPV4)
		ret = AF_IOCTL(AF_INET, SIOCGLIFMETRIC, (caddr_t)&lifreq);
#ifdef SOLARIS_IPV6
	else if (ifp->flags & IFF_IPV6)
		ret = AF_IOCTL(AF_INET6, SIOCGLIFMETRIC, (caddr_t)&lifreq);
#endif /* SOLARIS_IPV6 */
	else
		ret = -1;

	if (ret < 0)
		return;

	ifp->metric = lifreq.lifr_metric;

	if (ifp->metric == 0)
		ifp->metric = 1;
}

/* get interface MTU */
void if_get_mtu(struct interface *ifp)
{
	struct lifreq lifreq;
	int ret;
	uint8_t changed = 0;

	if (ifp->flags & IFF_IPV4) {
		lifreq_set_name(&lifreq, ifp->name);
		ret = AF_IOCTL(AF_INET, SIOCGLIFMTU, (caddr_t)&lifreq);
		if (ret < 0) {
			zlog_info(
				"Can't lookup mtu on %s by ioctl(SIOCGLIFMTU)",
				ifp->name);
			ifp->mtu = -1;
		} else {
			ifp->mtu = lifreq.lifr_metric;
			changed = 1;
		}
	}

	if (ifp->flags & IFF_IPV6) {
		memset(&lifreq, 0, sizeof(lifreq));
		lifreq_set_name(&lifreq, ifp->name);

		ret = AF_IOCTL(AF_INET6, SIOCGLIFMTU, (caddr_t)&lifreq);
		if (ret < 0) {
			zlog_info(
				"Can't lookup mtu6 on %s by ioctl(SIOCGIFMTU)",
				ifp->name);
			ifp->mtu6 = -1;
		} else {
			ifp->mtu6 = lifreq.lifr_metric;
			changed = 1;
		}
	}

	if (changed)
		zebra_interface_up_update(ifp);
}

/*
 *
 */
enum zebra_dplane_result kernel_address_update_ctx(
	struct zebra_dplane_ctx *ctx)
{
	int ret = -1;
	const struct prefix *p;

	p = dplane_ctx_get_intf_addr(ctx);

	if (dplane_ctx_get_op(ctx) == DPLANE_OP_ADDR_INSTALL) {
		if (p->family == AF_INET)
			ret = if_set_prefix_ctx(ctx);
		else
			ret = if_set_prefix6_ctx(ctx);
	} else if (dplane_ctx_get_op(ctx) == DPLANE_OP_ADDR_UNINSTALL) {
		if (p->family == AF_INET)
			ret = if_unset_prefix_ctx(ctx);
		else
			ret = if_unset_prefix6_ctx(ctx);
	} else {
		if (IS_ZEBRA_DEBUG_DPLANE)
			zlog_debug("Invalid op in interface-addr install");
	}

	return (ret == 0 ?
		ZEBRA_DPLANE_REQUEST_SUCCESS : ZEBRA_DPLANE_REQUEST_FAILURE);
}

/* Set up interface's address, netmask (and broadcast? ).
   Solaris uses ifname:number semantics to set IP address aliases. */
static int if_set_prefix_ctx(const struct zebra_dplane_ctx *ctx)
{
	int ret;
	struct ifreq ifreq;
	struct sockaddr_in addr, broad, mask;
	struct prefix_ipv4 ifaddr;
	struct prefix_ipv4 *p;

	p = (struct prefix_ipv4 *)dplane_ctx_get_intf_addr(ctx);

	ifaddr = *p;

	strlcpy(ifreq.ifr_name, dplane_ctx_get_ifname(ctx),
		sizeof(ifreq.ifr_name));

	addr.sin_addr = p->prefix;
	addr.sin_family = p->family;
	memcpy(&ifreq.ifr_addr, &addr, sizeof(struct sockaddr_in));

	ret = if_ioctl(SIOCSIFADDR, (caddr_t)&ifreq);

	if (ret < 0)
		return ret;

	/* We need mask for make broadcast addr. */
	masklen2ip(p->prefixlen, &mask.sin_addr);

	if (dplane_ctx_intf_is_broadcast(ctx)) {
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
#endif /* SUNOS_5 */
	ret = if_ioctl(SIOCSIFNETMASK, (caddr_t)&ifreq);

	return ((ret < 0) ? ret : 0);
}

/* Set up interface's address, netmask (and broadcast).
   Solaris uses ifname:number semantics to set IP address aliases. */
static int if_unset_prefix_ctx(const struct zebra_dplane_ctx *ctx)
{
	int ret;
	struct ifreq ifreq;
	struct sockaddr_in addr;
	struct prefix_ipv4 *p;

	p = (struct prefix_ipv4 *)dplane_ctx_get_intf_addr(ctx);

	strlcpy(ifreq.ifr_name, dplane_ctx_get_ifname(ctx),
		sizeof(ifreq.ifr_name));

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = p->family;
	memcpy(&ifreq.ifr_addr, &addr, sizeof(struct sockaddr_in));

	ret = if_ioctl(SIOCSIFADDR, (caddr_t)&ifreq);

	if (ret < 0)
		return ret;

	return 0;
}

/* Get just the flags for the given name.
 * Used by the normal 'if_get_flags' function, as well
 * as the bootup interface-list code, which has to peek at per-address
 * flags in order to figure out which ones should be ignored..
 */
int if_get_flags_direct(const char *ifname, uint64_t *flags, unsigned int af)
{
	struct lifreq lifreq;
	int ret;

	lifreq_set_name(&lifreq, ifname);

	ret = AF_IOCTL(af, SIOCGLIFFLAGS, (caddr_t)&lifreq);

	if (ret)
		zlog_debug("%s: ifname %s, error %s (%d)", __func__, ifname,
			   safe_strerror(errno), errno);

	*flags = lifreq.lifr_flags;

	return ret;
}

/* get interface flags */
void if_get_flags(struct interface *ifp)
{
	int ret4 = 0, ret6 = 0;
	uint64_t newflags = 0;
	uint64_t tmpflags;

	if (ifp->flags & IFF_IPV4) {
		ret4 = if_get_flags_direct(ifp->name, &tmpflags, AF_INET);

		if (!ret4)
			newflags |= tmpflags;
		else if (errno == ENXIO) {
			/* it's gone */
			UNSET_FLAG(ifp->flags, IFF_UP);
			if_flags_update(ifp, ifp->flags);
		}
	}

	if (ifp->flags & IFF_IPV6) {
		ret6 = if_get_flags_direct(ifp->name, &tmpflags, AF_INET6);

		if (!ret6)
			newflags |= tmpflags;
		else if (errno == ENXIO) {
			/* it's gone */
			UNSET_FLAG(ifp->flags, IFF_UP);
			if_flags_update(ifp, ifp->flags);
		}
	}

	/* only update flags if one of above succeeded */
	if (!(ret4 && ret6))
		if_flags_update(ifp, newflags);
}

/* Set interface flags */
int if_set_flags(struct interface *ifp, uint64_t flags)
{
	int ret;
	struct lifreq lifreq;

	lifreq_set_name(&lifreq, ifp->name);

	lifreq.lifr_flags = ifp->flags;
	lifreq.lifr_flags |= flags;

	if (ifp->flags & IFF_IPV4)
		ret = AF_IOCTL(AF_INET, SIOCSLIFFLAGS, (caddr_t)&lifreq);
	else if (ifp->flags & IFF_IPV6)
		ret = AF_IOCTL(AF_INET6, SIOCSLIFFLAGS, (caddr_t)&lifreq);
	else
		ret = -1;

	if (ret < 0)
		zlog_info("can't set interface flags on %s: %s", ifp->name,
			  safe_strerror(errno));
	else
		ret = 0;

	return ret;
}

/* Unset interface's flag. */
int if_unset_flags(struct interface *ifp, uint64_t flags)
{
	int ret;
	struct lifreq lifreq;

	lifreq_set_name(&lifreq, ifp->name);

	lifreq.lifr_flags = ifp->flags;
	lifreq.lifr_flags &= ~flags;

	if (ifp->flags & IFF_IPV4)
		ret = AF_IOCTL(AF_INET, SIOCSLIFFLAGS, (caddr_t)&lifreq);
	else if (ifp->flags & IFF_IPV6)
		ret = AF_IOCTL(AF_INET6, SIOCSLIFFLAGS, (caddr_t)&lifreq);
	else
		ret = -1;

	if (ret < 0)
		zlog_info("can't unset interface flags");
	else
		ret = 0;

	return ret;
}

/* Interface's address add/delete functions. */
static int if_set_prefix6_ctx(const struct zebra_dplane_ctx *ctx)
{
	char addrbuf[PREFIX_STRLEN];

	prefix2str(dplane_ctx_get_intf_addr(ctx), addrbuf, sizeof(addrbuf));

	flog_warn(EC_LIB_DEVELOPMENT, "Can't set %s on interface %s",
		  addrbuf, dplane_ctx_get_ifname(ctx));

	return 0;
}

static int if_unset_prefix6_ctx(const struct zebra_dplane_ctx *ctx)
{
	char addrbuf[PREFIX_STRLEN];

	prefix2str(dplane_ctx_get_intf_addr(ctx), addrbuf, sizeof(addrbuf));

	flog_warn(EC_LIB_DEVELOPMENT, "Can't delete %s on interface %s",
		  addrbuf, dplane_ctx_get_ifname(ctx));

	return 0;
}

#endif /* SUNOS_5 */
