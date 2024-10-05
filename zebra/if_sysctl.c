// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Get interface's address and mask information by sysctl() function.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 */

#include <zebra.h>

#include <net/route.h>

#if !defined(GNU_LINUX) && !defined(OPEN_BSD)

#include "if.h"
#include "sockunion.h"
#include "prefix.h"
#include "connected.h"
#include "memory.h"
#include "ioctl.h"
#include "log.h"
#include "interface.h"
#include "vrf.h"

#include "zebra/rt.h"
#include "zebra/kernel_socket.h"
#include "zebra/rib.h"
#include "zebra/zebra_errors.h"

void ifstat_update_sysctl(void)
{
	caddr_t ref, buf, end;
	size_t bufsiz;
	struct if_msghdr *ifm;
	struct interface *ifp;

#define MIBSIZ 6
	int mib[MIBSIZ] = {
		CTL_NET,       PF_ROUTE, 0, 0, /*  AF_INET & AF_INET6 */
		NET_RT_IFLIST, 0};

	/* Query buffer size. */
	if (sysctl(mib, MIBSIZ, NULL, &bufsiz, NULL, 0) < 0) {
		flog_warn(EC_ZEBRA_SYSCTL_FAILED, "sysctl() error by %s",
			  safe_strerror(errno));
		return;
	}

	/* We free this memory at the end of this function. */
	ref = buf = XMALLOC(MTYPE_TMP, bufsiz);

	/* Fetch interface information into allocated buffer. */
	if (sysctl(mib, MIBSIZ, buf, &bufsiz, NULL, 0) < 0) {
		flog_warn(EC_ZEBRA_SYSCTL_FAILED, "sysctl error by %s",
			  safe_strerror(errno));
		XFREE(MTYPE_TMP, ref);
		return;
	}

	/* Parse both interfaces and addresses. */
	for (end = buf + bufsiz; buf < end; buf += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)buf;
		if (ifm->ifm_type == RTM_IFINFO) {
			ifp = if_lookup_by_index(ifm->ifm_index, VRF_DEFAULT);
			if (ifp)
				ifp->stats = ifm->ifm_data;
		}
	}

	/* Free sysctl buffer. */
	XFREE(MTYPE_TMP, ref);

	return;
}

/* Interface listing up function using sysctl(). */
void interface_list(struct zebra_ns *zns)
{
	caddr_t ref, buf, end;
	size_t bufsiz;
	struct if_msghdr *ifm;

#define MIBSIZ 6
	int mib[MIBSIZ] = {
		CTL_NET,       PF_ROUTE, 0, 0, /*  AF_INET & AF_INET6 */
		NET_RT_IFLIST, 0};

	if (zns->ns_id != NS_DEFAULT) {
		zlog_debug("%s: ignore NS %u", __func__, zns->ns_id);
		return;
	}

	/* Query buffer size. */
	if (sysctl(mib, MIBSIZ, NULL, &bufsiz, NULL, 0) < 0) {
		flog_err_sys(EC_ZEBRA_IFLIST_FAILED,
			     "Could not enumerate interfaces: %s",
			     safe_strerror(errno));
		return;
	}

	/* We free this memory at the end of this function. */
	ref = buf = XMALLOC(MTYPE_TMP, bufsiz);

	/* Fetch interface information into allocated buffer. */
	if (sysctl(mib, MIBSIZ, buf, &bufsiz, NULL, 0) < 0) {
		flog_err_sys(EC_ZEBRA_IFLIST_FAILED,
			     "Could not enumerate interfaces: %s",
			     safe_strerror(errno));
		return;
	}

	/* Parse both interfaces and addresses. */
	for (end = buf + bufsiz; buf < end; buf += ifm->ifm_msglen) {
		ifm = (struct if_msghdr *)buf;

		switch (ifm->ifm_type) {
		case RTM_IFINFO:
			ifm_read(ifm);
			break;
		case RTM_NEWADDR:
			ifam_read((struct ifa_msghdr *)ifm);
			break;
		default:
			zlog_info("%s: unexpected message type", __func__);
			XFREE(MTYPE_TMP, ref);
			return;
			break;
		}
	}

	/* Free sysctl buffer. */
	XFREE(MTYPE_TMP, ref);

	zebra_dplane_startup_stage(zns, ZEBRA_DPLANE_INTERFACES_READ);
}

#endif /* !defined(GNU_LINUX) && !defined(OPEN_BSD) */
