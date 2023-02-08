// SPDX-License-Identifier: GPL-2.0-or-later
/* RIPng nexthop support
 * Copyright (C) 6WIND Vincent Jardin <vincent.jardin@6wind.com>
 */

#ifndef _ZEBRA_RIPNG_RIPNG_NEXTHOP_H
#define _ZEBRA_RIPNG_RIPNG_NEXTHOP_H

#include <zebra.h>
#include "linklist.h"
#include "ripngd/ripng_route.h"
#include "ripngd/ripngd.h"

extern struct list *ripng_rte_new(void);
extern void ripng_rte_free(struct list *ripng_rte_list);
extern void ripng_rte_add(struct list *ripng_rte_list, struct prefix_ipv6 *p,
			  struct ripng_info *rinfo,
			  struct ripng_aggregate *aggregate);
extern void ripng_rte_send(struct list *ripng_rte_list, struct interface *ifp,
			   struct sockaddr_in6 *to);

/***
 * 1 if A > B
 * 0 if A = B
 * -1 if A < B
 **/
static inline int addr6_cmp(struct in6_addr *A, struct in6_addr *B)
{
#define a(i) A->s6_addr32[i]
#define b(i) B->s6_addr32[i]

	if (a(3) > b(3))
		return 1;
	else if ((a(3) == b(3)) && (a(2) > b(2)))
		return 1;
	else if ((a(3) == b(3)) && (a(2) == b(2)) && (a(1) > b(1)))
		return 1;
	else if ((a(3) == b(3)) && (a(2) == b(2)) && (a(1) == b(1))
		 && (a(0) > b(0)))
		return 1;

	if ((a(3) == b(3)) && (a(2) == b(2)) && (a(1) == b(1))
	    && (a(0) == b(0)))
		return 0;

	return -1;
}

#endif /* _ZEBRA_RIPNG_RIPNG_NEXTHOP_H */
