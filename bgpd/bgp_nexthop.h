/* BGP nexthop scan
 * Copyright (C) 2000 Kunihiro Ishiguro
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

#ifndef _QUAGGA_BGP_NEXTHOP_H
#define _QUAGGA_BGP_NEXTHOP_H

#include "if.h"
#include "queue.h"
#include "prefix.h"

#define NEXTHOP_FAMILY(nexthop_len)                                            \
	(((nexthop_len) == 4 || (nexthop_len) == 12                            \
		  ? AF_INET                                                    \
		  : ((nexthop_len) == 16 || (nexthop_len) == 24                \
				     || (nexthop_len) == 32                    \
				     || (nexthop_len) == 48                    \
			     ? AF_INET6                                        \
			     : AF_UNSPEC)))

#define BGP_MP_NEXTHOP_FAMILY NEXTHOP_FAMILY

/* BGP nexthop cache value structure. */
struct bgp_nexthop_cache {
	/* IGP route's metric. */
	uint32_t metric;

	/* Nexthop number and nexthop linked list.*/
	uint8_t nexthop_num;
	struct nexthop *nexthop;
	time_t last_update;
	uint16_t flags;

#define BGP_NEXTHOP_VALID             (1 << 0)
#define BGP_NEXTHOP_REGISTERED        (1 << 1)
#define BGP_NEXTHOP_CONNECTED         (1 << 2)
#define BGP_NEXTHOP_PEER_NOTIFIED     (1 << 3)
#define BGP_STATIC_ROUTE              (1 << 4)
#define BGP_STATIC_ROUTE_EXACT_MATCH  (1 << 5)
#define BGP_NEXTHOP_LABELED_VALID     (1 << 6)

	uint16_t change_flags;

#define BGP_NEXTHOP_CHANGED           (1 << 0)
#define BGP_NEXTHOP_METRIC_CHANGED    (1 << 1)
#define BGP_NEXTHOP_CONNECTED_CHANGED (1 << 2)

	struct bgp_node *node;
	void *nht_info; /* In BGP, peer session */
	LIST_HEAD(path_list, bgp_info) paths;
	unsigned int path_count;
	struct bgp *bgp;
};

/* BGP own address structure */
struct bgp_addr {
	struct in_addr addr;
	int refcnt;
};

/* Own tunnel-ip address structure */
struct tip_addr {
	struct in_addr addr;
	int refcnt;
};

extern int bgp_nexthop_lookup(afi_t, struct peer *peer, struct bgp_info *,
			      int *, int *);
extern void bgp_connected_add(struct bgp *bgp, struct connected *c);
extern void bgp_connected_delete(struct bgp *bgp, struct connected *c);
extern int bgp_subgrp_multiaccess_check_v4(struct in_addr nexthop,
					   struct update_subgroup *subgrp);
extern int bgp_multiaccess_check_v4(struct in_addr, struct peer *);
extern int bgp_config_write_scan_time(struct vty *);
extern int bgp_nexthop_self(struct bgp *, struct in_addr);
extern struct bgp_nexthop_cache *bnc_new(void);
extern void bnc_free(struct bgp_nexthop_cache *bnc);
extern void bnc_nexthop_free(struct bgp_nexthop_cache *bnc);
extern char *bnc_str(struct bgp_nexthop_cache *bnc, char *buf, int size);
extern void bgp_scan_init(struct bgp *bgp);
extern void bgp_scan_finish(struct bgp *bgp);
extern void bgp_scan_vty_init(void);
extern void bgp_address_init(struct bgp *bgp);
extern void bgp_address_destroy(struct bgp *bgp);
extern void bgp_tip_add(struct bgp *bgp, struct in_addr *tip);
extern void bgp_tip_del(struct bgp *bgp, struct in_addr *tip);
extern void bgp_tip_hash_init(struct bgp *bgp);
extern void bgp_tip_hash_destroy(struct bgp *bgp);

#endif /* _QUAGGA_BGP_NEXTHOP_H */
