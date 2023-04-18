// SPDX-License-Identifier: GPL-2.0-or-later
/* IP forward control by sysctl function.
 * Copyright (C) 1997, 1999 Kunihiro Ishiguro
 */

#include <zebra.h>

#if !defined(GNU_LINUX)

#include "privs.h"
#include "zebra/ipforward.h"
#include "zebra/zebra_errors.h"

#include "log.h"
#include "lib_errors.h"

#define MIB_SIZ 4

extern struct zebra_privs_t zserv_privs;

/* IPv4 forwarding control MIB. */
int mib[MIB_SIZ] = {CTL_NET, PF_INET, IPPROTO_IP, IPCTL_FORWARDING};

int ipforward(void)
{
	size_t len;
	int ipforwarding = 0;

	len = sizeof(ipforwarding);
	if (sysctl(mib, MIB_SIZ, &ipforwarding, &len, 0, 0) < 0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "Can't get ipforwarding value");
		return -1;
	}
	return ipforwarding;
}

int ipforward_on(void)
{
	size_t len;
	int ipforwarding = 1;

	len = sizeof(ipforwarding);
	frr_with_privs(&zserv_privs) {
		if (sysctl(mib, MIB_SIZ, NULL, NULL, &ipforwarding, len) < 0) {
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "Can't set ipforwarding on");
			return -1;
		}
	}
	return ipforwarding;
}

int ipforward_off(void)
{
	size_t len;
	int ipforwarding = 0;

	len = sizeof(ipforwarding);
	frr_with_privs(&zserv_privs) {
		if (sysctl(mib, MIB_SIZ, NULL, NULL, &ipforwarding, len) < 0) {
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "Can't set ipforwarding on");
			return -1;
		}
	}
	return ipforwarding;
}

/* IPv6 forwarding control MIB. */
int mib_ipv6[MIB_SIZ] = {CTL_NET, PF_INET6,
#if defined(BSD_V6_SYSCTL)
			 IPPROTO_IPV6, IPV6CTL_FORWARDING
#else  /* NOT BSD_V6_SYSCTL */
			 IPPROTO_IP, IP6CTL_FORWARDING
#endif /* BSD_V6_SYSCTL */
};

int ipforward_ipv6(void)
{
	size_t len;
	int ip6forwarding = 0;

	len = sizeof(ip6forwarding);
	frr_with_privs(&zserv_privs) {
		if (sysctl(mib_ipv6, MIB_SIZ, &ip6forwarding, &len, 0, 0) < 0) {
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "can't get ip6forwarding value");
			return -1;
		}
	}
	return ip6forwarding;
}

int ipforward_ipv6_on(void)
{
	size_t len;
	int ip6forwarding = 1;

	len = sizeof(ip6forwarding);
	frr_with_privs(&zserv_privs) {
		if (sysctl(mib_ipv6, MIB_SIZ, NULL, NULL, &ip6forwarding, len)
		    < 0) {
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "can't get ip6forwarding value");
			return -1;
		}
	}
	return ip6forwarding;
}

int ipforward_ipv6_off(void)
{
	size_t len;
	int ip6forwarding = 0;

	len = sizeof(ip6forwarding);
	frr_with_privs(&zserv_privs) {
		if (sysctl(mib_ipv6, MIB_SIZ, NULL, NULL, &ip6forwarding, len)
		    < 0) {
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "can't get ip6forwarding value");
			return -1;
		}
	}
	return ip6forwarding;
}

#endif /* !defined(GNU_LINUX) */
