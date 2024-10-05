// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Common ioctl functions.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 */

#include <zebra.h>

#include <sys/ioctl.h>

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
#include "zebra/debug.h"

#ifdef HAVE_BSD_LINK_DETECT
#include <net/if_media.h>
#endif /* HAVE_BSD_LINK_DETECT*/

extern struct zebra_privs_t zserv_privs;

/* clear and set interface name string */
void ifreq_set_name(struct ifreq *ifreq, struct interface *ifp)
{
	strlcpy(ifreq->ifr_name, ifp->name, sizeof(ifreq->ifr_name));
}

#ifndef HAVE_NETLINK
/* call ioctl system call */
int if_ioctl(unsigned long request, caddr_t buffer)
{
	int sock;
	int ret;
	int err = 0;

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
#endif

/* call ioctl system call */
int vrf_if_ioctl(unsigned long request, caddr_t buffer, vrf_id_t vrf_id)
{
	int sock;
	int ret;
	int err = 0;

	frr_with_privs(&zserv_privs) {
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
#ifdef SIOCGIFMETRIC
	struct ifreq ifreq = {};

	ifreq_set_name(&ifreq, ifp);

	if (vrf_if_ioctl(SIOCGIFMETRIC, (caddr_t)&ifreq, ifp->vrf->vrf_id) < 0)
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
	struct ifreq ifreq = {};

	ifreq_set_name(&ifreq, ifp);

#if defined(SIOCGIFMTU)
	if (vrf_if_ioctl(SIOCGIFMTU, (caddr_t)&ifreq, ifp->vrf->vrf_id) < 0) {
		zlog_info("Can't lookup mtu by ioctl(SIOCGIFMTU) for %s(%u)",
			  ifp->name, ifp->vrf->vrf_id);
		ifp->mtu6 = ifp->mtu = -1;
		return;
	}

	ifp->mtu6 = ifp->mtu = ifreq.ifr_mtu;

	/* propogate */
	zebra_interface_up_update(ifp);

#else
	zlog_info("Can't lookup mtu on this system for %s(%u)", ifp->name,
		  ifp->vrf->vrf_id);
	ifp->mtu6 = ifp->mtu = -1;
#endif
}
#endif /* ! HAVE_NETLINK */

/*
 * Handler for interface address programming via the zebra dplane,
 * for non-netlink platforms. This handler dispatches to per-platform
 * helpers, based on the operation requested.
 */
#ifndef HAVE_NETLINK

/* Prototypes: these are placed in this block so that they're only seen
 * on non-netlink platforms.
 */
static int if_set_prefix_ctx(const struct zebra_dplane_ctx *ctx);
static int if_unset_prefix_ctx(const struct zebra_dplane_ctx *ctx);
static int if_set_prefix6_ctx(const struct zebra_dplane_ctx *ctx);
static int if_unset_prefix6_ctx(const struct zebra_dplane_ctx *ctx);

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

#ifdef HAVE_STRUCT_IFALIASREQ

/*
 * Helper for interface-addr install, non-netlink
 */
static int if_set_prefix_ctx(const struct zebra_dplane_ctx *ctx)
{
	int ret;
	struct ifaliasreq addreq;
	struct sockaddr_in addr, mask, peer;
	struct prefix_ipv4 *p;

	p = (struct prefix_ipv4 *)dplane_ctx_get_intf_addr(ctx);

	memset(&addreq, 0, sizeof(addreq));
	strlcpy((char *)&addreq.ifra_name, dplane_ctx_get_ifname(ctx),
		sizeof(addreq.ifra_name));

	memset(&addr, 0, sizeof(addr));
	addr.sin_addr = p->prefix;
	addr.sin_family = p->family;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	addr.sin_len = sizeof(struct sockaddr_in);
#endif
	memcpy(&addreq.ifra_addr, &addr, sizeof(struct sockaddr_in));

	if (dplane_ctx_intf_is_connected(ctx)) {
		p = (struct prefix_ipv4 *)dplane_ctx_get_intf_dest(ctx);
		memset(&mask, 0, sizeof(mask));
		peer.sin_addr = p->prefix;
		peer.sin_family = p->family;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
		peer.sin_len = sizeof(struct sockaddr_in);
#endif
		memcpy(&addreq.ifra_broadaddr, &peer,
		       sizeof(struct sockaddr_in));
	}

	memset(&mask, 0, sizeof(mask));
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

/*
 * Helper for interface-addr un-install, non-netlink
 */
static int if_unset_prefix_ctx(const struct zebra_dplane_ctx *ctx)
{
	int ret;
	struct ifaliasreq addreq;
	struct sockaddr_in addr, mask, peer;
	struct prefix_ipv4 *p;

	p = (struct prefix_ipv4 *)dplane_ctx_get_intf_addr(ctx);

	memset(&addreq, 0, sizeof(addreq));
	strlcpy((char *)&addreq.ifra_name, dplane_ctx_get_ifname(ctx),
		sizeof(addreq.ifra_name));

	memset(&addr, 0, sizeof(addr));
	addr.sin_addr = p->prefix;
	addr.sin_family = p->family;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	addr.sin_len = sizeof(struct sockaddr_in);
#endif
	memcpy(&addreq.ifra_addr, &addr, sizeof(struct sockaddr_in));

	if (dplane_ctx_intf_is_connected(ctx)) {
		p = (struct prefix_ipv4 *)dplane_ctx_get_intf_dest(ctx);
		memset(&mask, 0, sizeof(mask));
		peer.sin_addr = p->prefix;
		peer.sin_family = p->family;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
		peer.sin_len = sizeof(struct sockaddr_in);
#endif
		memcpy(&addreq.ifra_broadaddr, &peer,
		       sizeof(struct sockaddr_in));
	}

	memset(&mask, 0, sizeof(mask));
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
int if_set_prefix_ctx(const struct zebra_dplane_ctx *ctx)
{
	int ret;
	struct ifreq ifreq;
	struct sockaddr_in addr;
	struct sockaddr_in broad;
	struct sockaddr_in mask;
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
	memcpy(&ifreq.ifr_addr, &mask, sizeof(struct sockaddr_in));
	ret = if_ioctl(SIOCSIFNETMASK, (caddr_t)&ifreq);
	if (ret < 0)
		return ret;

	return 0;
}

/* Set up interface's address, netmask (and broadcas? ).  Linux or
   Solaris uses ifname:number semantics to set IP address aliases. */
int if_unset_prefix_ctx(const struct zebra_dplane_ctx *ctx)
{
	int ret;
	struct ifreq ifreq;
	struct sockaddr_in addr;
	struct prefix_ipv4 *p;

	p = (struct prefix_ipv4 *)dplane_ctx_get_intf_addr(ctx);

	strlcpy(ifreq.ifr_name, dplane_ctx_get_ifname(ctx),
		sizeof(ifreq.ifr_name));

	memset(&addr, 0, sizeof(addr));
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
	struct ifreq ifreqflags = {};
	struct ifreq ifreqdata = {};

	ifreq_set_name(&ifreqflags, ifp);
	ifreq_set_name(&ifreqdata, ifp);

	ret = vrf_if_ioctl(SIOCGIFFLAGS, (caddr_t)&ifreqflags,
			   ifp->vrf->vrf_id);
	if (ret < 0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "vrf_if_ioctl(SIOCGIFFLAGS %s) failed: %s",
			     ifp->name, safe_strerror(errno));
		return;
	}

	if (!CHECK_FLAG(ifp->status, ZEBRA_INTERFACE_LINKDETECTION))
		goto out;

	/* Per-default, IFF_RUNNING is held high, unless link-detect
	 * says otherwise - we abuse IFF_RUNNING inside zebra as a
	 * link-state flag, following practice on Linux and Solaris
	 * kernels
	 */

#ifdef SIOCGIFDATA
	/*
	 * BSD gets link state from ifi_link_link in struct if_data.
	 * All BSD's have this in getifaddrs(3) ifa_data for AF_LINK
	 * addresses. We can also access it via SIOCGIFDATA.
	 */

#ifdef __NetBSD__
	struct ifdatareq ifdr = {.ifdr_data.ifi_link_state = 0};
	struct if_data *ifdata = &ifdr.ifdr_data;

	strlcpy(ifdr.ifdr_name, ifp->name, sizeof(ifdr.ifdr_name));
	ret = vrf_if_ioctl(SIOCGIFDATA, (caddr_t)&ifdr, ifp->vrf->vrf_id);
#else
	struct if_data ifd = {.ifi_link_state = 0};
	struct if_data *ifdata = &ifd;

	ifreqdata.ifr_data = (caddr_t)ifdata;
	ret = vrf_if_ioctl(SIOCGIFDATA, (caddr_t)&ifreqdata, ifp->vrf->vrf_id);
#endif

	if (ret == -1)
		/* Very unlikely. Did the interface disappear? */
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "if_ioctl(SIOCGIFDATA %s) failed: %s", ifp->name,
			     safe_strerror(errno));
	else {
		if (ifdata->ifi_link_state >= LINK_STATE_UP)
			SET_FLAG(ifreqflags.ifr_flags, IFF_RUNNING);
		else if (ifdata->ifi_link_state == LINK_STATE_UNKNOWN)
			/* BSD traditionally treats UNKNOWN as UP */
			SET_FLAG(ifreqflags.ifr_flags, IFF_RUNNING);
		else
			UNSET_FLAG(ifreqflags.ifr_flags, IFF_RUNNING);
	}

#elif defined(HAVE_BSD_LINK_DETECT)
	/*
	 * This is only needed for FreeBSD older than FreeBSD-13.
	 * Valid and active media generally means the link state is
	 * up, but this is not always the case.
	 * For example, some BSD's with a net80211 interface in MONITOR
	 * mode will treat the media as valid and active but the
	 * link state is down - because we cannot send anything.
	 * Also, virtual interfaces such as PPP, VLAN, etc generally
	 * don't support media at all, so the ioctl will just fail.
	 */
	struct ifmediareq ifmr = {.ifm_status = 0};

	strlcpy(ifmr.ifm_name, ifp->name, sizeof(ifmr.ifm_name));

	if (if_ioctl(SIOCGIFMEDIA, (caddr_t)&ifmr) == -1) {
		if (errno != EINVAL)
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "if_ioctl(SIOCGIFMEDIA %s) failed: %s",
				     ifp->name, safe_strerror(errno));
	} else if (ifmr.ifm_status & IFM_AVALID) { /* media state is valid */
		if (ifmr.ifm_status & IFM_ACTIVE)  /* media is active */
			SET_FLAG(ifreqflags.ifr_flags, IFF_RUNNING);
		else
			UNSET_FLAG(ifreqflags.ifr_flags, IFF_RUNNING);
	}
#endif /* HAVE_BSD_LINK_DETECT */

out:
	if_flags_update(ifp, (ifreqflags.ifr_flags & 0x0000ffff));
}

/* Set interface flags */
int if_set_flags(struct interface *ifp, uint64_t flags)
{
	int ret;
	struct ifreq ifreq;

	memset(&ifreq, 0, sizeof(ifreq));
	ifreq_set_name(&ifreq, ifp);

	ifreq.ifr_flags = ifp->flags;
	ifreq.ifr_flags |= flags;

	ret = vrf_if_ioctl(SIOCSIFFLAGS, (caddr_t)&ifreq, ifp->vrf->vrf_id);

	if (ret < 0) {
		zlog_info("can't set interface %s(%u) flags %" PRIu64,
			  ifp->name, ifp->vrf->vrf_id, flags);
		return ret;
	}
	return 0;
}

/* Unset interface's flag. */
int if_unset_flags(struct interface *ifp, uint64_t flags)
{
	int ret;
	struct ifreq ifreq;

	memset(&ifreq, 0, sizeof(ifreq));
	ifreq_set_name(&ifreq, ifp);

	ifreq.ifr_flags = ifp->flags;
	ifreq.ifr_flags &= ~flags;

	ret = vrf_if_ioctl(SIOCSIFFLAGS, (caddr_t)&ifreq, ifp->vrf->vrf_id);

	if (ret < 0) {
		zlog_warn("can't unset interface %s(%u) flags %" PRIu64,
			  ifp->name, ifp->vrf->vrf_id, flags);
		return ret;
	}
	return 0;
}

#ifndef LINUX_IPV6 /* Netlink has its own code */

#ifdef HAVE_STRUCT_IN6_ALIASREQ
#ifndef ND6_INFINITE_LIFETIME
#define ND6_INFINITE_LIFETIME 0xffffffffL
#endif /* ND6_INFINITE_LIFETIME */

/*
 * Helper for interface-addr install, non-netlink
 */
static int if_set_prefix6_ctx(const struct zebra_dplane_ctx *ctx)
{
	int ret;
	struct in6_aliasreq addreq;
	struct sockaddr_in6 addr;
	struct sockaddr_in6 mask;
	struct prefix_ipv6 *p;

	p = (struct prefix_ipv6 *)dplane_ctx_get_intf_addr(ctx);

	memset(&addreq, 0, sizeof(addreq));
	strlcpy((char *)&addreq.ifra_name,
		dplane_ctx_get_ifname(ctx), sizeof(addreq.ifra_name));

	memset(&addr, 0, sizeof(addr));
	addr.sin6_addr = p->prefix;
	addr.sin6_family = p->family;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
	memcpy(&addreq.ifra_addr, &addr, sizeof(struct sockaddr_in6));

	memset(&mask, 0, sizeof(mask));
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

/*
 * Helper for interface-addr un-install, non-netlink
 */
static int if_unset_prefix6_ctx(const struct zebra_dplane_ctx *ctx)
{
	int ret;
	struct in6_aliasreq addreq;
	struct sockaddr_in6 addr;
	struct sockaddr_in6 mask;
	struct prefix_ipv6 *p;

	p = (struct prefix_ipv6 *)dplane_ctx_get_intf_addr(ctx);

	memset(&addreq, 0, sizeof(addreq));
	strlcpy((char *)&addreq.ifra_name,
		dplane_ctx_get_ifname(ctx), sizeof(addreq.ifra_name));

	memset(&addr, 0, sizeof(addr));
	addr.sin6_addr = p->prefix;
	addr.sin6_family = p->family;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
	memcpy(&addreq.ifra_addr, &addr, sizeof(struct sockaddr_in6));

	memset(&mask, 0, sizeof(mask));
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
/* The old, pre-dataplane code here just returned, so we're retaining that
 * choice.
 */
static int if_set_prefix6_ctx(const struct zebra_dplane_ctx *ctx)
{
	return 0;
}

static int if_unset_prefix6_ctx(const struct zebra_dplane_ctx *ctx)
{
	return 0;
}
#endif /* HAVE_STRUCT_IN6_ALIASREQ */

#endif /* LINUX_IPV6 */
