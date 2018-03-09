/*
 * Kernel routing table read by sysctl function.
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

#if !defined(GNU_LINUX) && !defined(SUNOS_5)

#include "memory.h"
#include "zebra_memory.h"
#include "log.h"
#include "vrf.h"

#include "zebra/rt.h"
#include "zebra/kernel_socket.h"
#include "zebra/zebra_pbr.h"

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
		zlog_warn("sysctl fail: %s", safe_strerror(errno));
		return;
	}

	/* Allocate buffer. */
	ref = buf = XMALLOC(MTYPE_TMP, bufsiz);

	/* Read routing table information by calling sysctl(). */
	if (sysctl(mib, MIBSIZ, buf, &bufsiz, NULL, 0) < 0) {
		zlog_warn("sysctl() fail by %s", safe_strerror(errno));
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
			    struct interface *br_if)
{
}

void neigh_read(struct zebra_ns *zns)
{
}

void neigh_read_for_vlan(struct zebra_ns *zns, struct interface *vlan_if)
{
}

void kernel_read_pbr_rules(struct zebra_ns *zns)
{
}

#endif /* !defined(GNU_LINUX) && !defined(SUNOS_5) */
