// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Kernel routing table read by sysctl function.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 */

#include <zebra.h>

#include <net/route.h>

#if !defined(GNU_LINUX)

#include "memory.h"
#include "log.h"
#include "vrf.h"

#include "zebra/rt.h"
#include "zebra/kernel_socket.h"
#include "zebra/zebra_pbr.h"
#include "zebra/zebra_tc.h"
#include "zebra/zebra_errors.h"

/* Kernel routing table read up by sysctl function. */
void route_read(struct zebra_ns *zns)
{
	caddr_t buf, end, ref;
	size_t bufsiz;
	struct rt_msghdr *rtm;

#define MIBSIZ 6
	int mib[MIBSIZ] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_DUMP, 0};

	if (zns->ns_id != NS_DEFAULT)
		return;

	/* Get buffer size. */
	if (sysctl(mib, MIBSIZ, NULL, &bufsiz, NULL, 0) < 0) {
		flog_warn(EC_ZEBRA_SYSCTL_FAILED, "sysctl fail: %s",
			  safe_strerror(errno));
		return;
	}

	/* Allocate buffer. */
	ref = buf = XMALLOC(MTYPE_TMP, bufsiz);

	/* Read routing table information by calling sysctl(). */
	if (sysctl(mib, MIBSIZ, buf, &bufsiz, NULL, 0) < 0) {
		flog_warn(EC_ZEBRA_SYSCTL_FAILED, "sysctl() fail by %s",
			  safe_strerror(errno));
		XFREE(MTYPE_TMP, ref);
		return;
	}

	for (end = buf + bufsiz; buf < end; buf += rtm->rtm_msglen) {
		rtm = (struct rt_msghdr *)buf;
		/* We must set RTF_DONE here, so rtm_read() doesn't ignore the
		 * message. */
		SET_FLAG(rtm->rtm_flags, RTF_DONE);
		rtm_read(rtm);
	}

	/* Free buffer. */
	XFREE(MTYPE_TMP, ref);

	return;
}

/* Only implemented for the netlink method. */
void macfdb_read(struct zebra_ns *zns)
{
}

void macfdb_read_for_bridge(struct zebra_ns *zns, struct interface *ifp,
			    struct interface *br_if, vlanid_t vid)
{
}

void macfdb_read_mcast_entry_for_vni(struct zebra_ns *zns,
				     struct interface *ifp, vni_t vni)
{
}

void macfdb_read_specific_mac(struct zebra_ns *zns, struct interface *br_if,
			      const struct ethaddr *mac, vlanid_t vid)
{
}

void neigh_read(struct zebra_ns *zns)
{
}

void neigh_read_for_vlan(struct zebra_ns *zns, struct interface *vlan_if)
{
}

void neigh_read_specific_ip(const struct ipaddr *ip, struct interface *vlan_if)
{
}

void kernel_read_pbr_rules(struct zebra_ns *zns)
{
}

void kernel_read_tc_qdisc(struct zebra_ns *zns)
{
}

void vlan_read(struct zebra_ns *zns)
{
}

#endif /* !defined(GNU_LINUX) */
