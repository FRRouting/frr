// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Interface's address and mask.
 * Copyright (C) 1997 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_CONNECTED_H
#define _ZEBRA_CONNECTED_H

#include <zebra.h>
#include <stdint.h>

#include "lib/if.h"
#include "lib/prefix.h"

#ifdef __cplusplus
extern "C" {
#endif

extern struct connected *connected_check(struct interface *ifp,
					 union prefixconstptr p);
extern struct connected *connected_check_ptp(struct interface *ifp,
					     union prefixconstptr p,
					     union prefixconstptr d);

extern void connected_add_ipv4(struct interface *ifp, int flags,
			       const struct in_addr *addr, uint16_t prefixlen,
			       const struct in_addr *dest, const char *label,
			       uint32_t metric);

extern void connected_delete_ipv4(struct interface *ifp, int flags,
				  const struct in_addr *addr,
				  uint16_t prefixlen,
				  const struct in_addr *dest);

extern void connected_delete_ipv4_unnumbered(struct connected *ifc);

extern void connected_up(struct interface *ifp, struct connected *ifc);
extern void connected_down(struct interface *ifp, struct connected *ifc);

extern void connected_add_ipv6(struct interface *ifp, int flags,
			       const struct in6_addr *address,
			       const struct in6_addr *dest, uint16_t prefixlen,
			       const char *label, uint32_t metric);
extern void connected_delete_ipv6(struct interface *ifp,
				  const struct in6_addr *address,
				  const struct in6_addr *dest,
				  uint16_t prefixlen);

extern int connected_is_unnumbered(struct interface *);

#ifdef __cplusplus
}
#endif
#endif /*_ZEBRA_CONNECTED_H */
