/*
 * Nexthop structure definition.
 * Copyright (C) 1997, 98, 99, 2001 Kunihiro Ishiguro
 * Copyright (C) 2013 Cumulus Networks, Inc.
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _LIB_NEXTHOP_H
#define _LIB_NEXTHOP_H

#include "prefix.h"
#include "mpls.h"

/* Maximum next hop string length - gateway + ifindex */
#define NEXTHOP_STRLEN (INET6_ADDRSTRLEN + 30)

union g_addr {
	struct in_addr ipv4;
	struct in6_addr ipv6;
};

enum nexthop_types_t {
	NEXTHOP_TYPE_IFINDEX = 1,  /* Directly connected.  */
	NEXTHOP_TYPE_IPV4,	 /* IPv4 nexthop.  */
	NEXTHOP_TYPE_IPV4_IFINDEX, /* IPv4 nexthop with ifindex.  */
	NEXTHOP_TYPE_IPV6,	 /* IPv6 nexthop.  */
	NEXTHOP_TYPE_IPV6_IFINDEX, /* IPv6 nexthop with ifindex.  */
	NEXTHOP_TYPE_BLACKHOLE,    /* Null0 nexthop.  */
};

enum blackhole_type {
	BLACKHOLE_UNSPEC = 0,
	BLACKHOLE_NULL,
	BLACKHOLE_REJECT,
	BLACKHOLE_ADMINPROHIB,
};

/* IPV[46] -> IPV[46]_IFINDEX */
#define NEXTHOP_FIRSTHOPTYPE(type) \
	((type) == NEXTHOP_TYPE_IFINDEX || (type) == NEXTHOP_TYPE_BLACKHOLE) \
		? (type) : ((type) | 1)

/* Nexthop structure. */
struct nexthop {
	struct nexthop *next;
	struct nexthop *prev;

	/* Interface index. */
	ifindex_t ifindex;

	enum nexthop_types_t type;

	u_char flags;
#define NEXTHOP_FLAG_ACTIVE     (1 << 0) /* This nexthop is alive. */
#define NEXTHOP_FLAG_FIB        (1 << 1) /* FIB nexthop. */
#define NEXTHOP_FLAG_RECURSIVE  (1 << 2) /* Recursive nexthop. */
#define NEXTHOP_FLAG_ONLINK     (1 << 3) /* Nexthop should be installed onlink. */
#define NEXTHOP_FLAG_MATCHED    (1 << 4) /* Already matched vs a nexthop */
#define NEXTHOP_FLAG_FILTERED   (1 << 5) /* rmap filtered, used by static only */
#define NEXTHOP_FLAG_DUPLICATE  (1 << 6) /* nexthop duplicates another active one */
#define NEXTHOP_FLAG_EVPN_RVTEP (1 << 7) /* EVPN remote vtep nexthop */
#define NEXTHOP_IS_ACTIVE(flags) \
	(CHECK_FLAG(flags, NEXTHOP_FLAG_ACTIVE) \
		&& !CHECK_FLAG(flags, NEXTHOP_FLAG_DUPLICATE))

	/* Nexthop address */
	union {
		union g_addr gate;
		enum blackhole_type bh_type;
	};
	union g_addr src;
	union g_addr rmap_src; /* Src is set via routemap */

	/* Nexthops obtained by recursive resolution.
	 *
	 * If the nexthop struct needs to be resolved recursively,
	 * NEXTHOP_FLAG_RECURSIVE will be set in flags and the nexthops
	 * obtained by recursive resolution will be added to `resolved'.
	 */
	struct nexthop *resolved;
	/* Recursive parent */
	struct nexthop *rparent;

	/* Type of label(s), if any */
	enum lsp_types_t nh_label_type;

	/* Label(s) associated with this nexthop. */
	struct mpls_label_stack *nh_label;
};

/* The following for loop allows to iterate over the nexthop
 * structure of routes.
 *
 * head:      The pointer to the first nexthop in the chain.
 *
 * nexthop:   The pointer to the current nexthop, either in the
 *            top-level chain or in a resolved chain.
 */
#define ALL_NEXTHOPS(head, nexthop)                                            \
	(nexthop) = (head);                                                    \
	(nexthop);                                                             \
	(nexthop) = nexthop_next(nexthop)

extern int zebra_rnh_ip_default_route;
extern int zebra_rnh_ipv6_default_route;

static inline int nh_resolve_via_default(int family)
{
	if (((family == AF_INET) && zebra_rnh_ip_default_route)
	    || ((family == AF_INET6) && zebra_rnh_ipv6_default_route))
		return 1;
	else
		return 0;
}

struct nexthop *nexthop_new(void);
void nexthop_add(struct nexthop **target, struct nexthop *nexthop);

void copy_nexthops(struct nexthop **tnh, struct nexthop *nh,
		   struct nexthop *rparent);
void nexthop_free(struct nexthop *nexthop);
void nexthops_free(struct nexthop *nexthop);

void nexthop_add_labels(struct nexthop *, enum lsp_types_t, u_int8_t,
			mpls_label_t *);
void nexthop_del_labels(struct nexthop *);

extern const char *nexthop_type_to_str(enum nexthop_types_t nh_type);
extern int nexthop_same_no_recurse(const struct nexthop *next1,
				   const struct nexthop *next2);
extern int nexthop_labels_match(struct nexthop *nh1, struct nexthop *nh2);
extern int nexthop_same_firsthop (struct nexthop *next1, struct nexthop *next2);

extern const char *nexthop2str(struct nexthop *nexthop, char *str, int size);
extern struct nexthop *nexthop_next(struct nexthop *nexthop);
extern unsigned int nexthop_level(struct nexthop *nexthop);
#endif /*_LIB_NEXTHOP_H */
