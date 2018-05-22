/*
 * Routing Information Base header
 * Copyright (C) 1997 Kunihiro Ishiguro
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

#ifndef _ZEBRA_RIB_H
#define _ZEBRA_RIB_H

#include "zebra.h"
#include "hook.h"
#include "linklist.h"
#include "prefix.h"
#include "table.h"
#include "queue.h"
#include "nexthop.h"
#include "nexthop_group.h"
#include "vrf.h"
#include "if.h"
#include "mpls.h"
#include "srcdest_table.h"

#define DISTANCE_INFINITY  255
#define ZEBRA_KERNEL_TABLE_MAX 252 /* support for no more than this rt tables */

struct route_entry {
	/* Link list. */
	struct route_entry *next;
	struct route_entry *prev;

	/* Nexthop structure */
	struct nexthop_group ng;

	/* Tag */
	route_tag_t tag;

	/* Uptime. */
	time_t uptime;

	/* Type fo this route. */
	int type;

	/* Source protocol instance */
	unsigned short instance;

	/* VRF identifier. */
	vrf_id_t vrf_id;

	/* Which routing table */
	uint32_t table;

	/* Metric */
	uint32_t metric;

	/* MTU */
	uint32_t mtu;
	uint32_t nexthop_mtu;

	/* Distance. */
	uint8_t distance;

	/* Flags of this route.
	 * This flag's definition is in lib/zebra.h ZEBRA_FLAG_* and is exposed
	 * to clients via Zserv
	 */
	uint32_t flags;

	/* RIB internal status */
	uint8_t status;
#define ROUTE_ENTRY_REMOVED          0x1
/* to simplify NHT logic when NHs change, instead of doing a NH by NH cmp */
#define ROUTE_ENTRY_NEXTHOPS_CHANGED 0x2
#define ROUTE_ENTRY_CHANGED          0x4
#define ROUTE_ENTRY_LABELS_CHANGED   0x8

	/* Nexthop information. */
	uint8_t nexthop_num;
	uint8_t nexthop_active_num;
};

/* meta-queue structure:
 * sub-queue 0: connected, kernel
 * sub-queue 1: static
 * sub-queue 2: RIP, RIPng, OSPF, OSPF6, IS-IS, EIGRP, NHRP
 * sub-queue 3: iBGP, eBGP
 * sub-queue 4: any other origin (if any)
 */
#define MQ_SIZE 5
struct meta_queue {
	struct list *subq[MQ_SIZE];
	uint32_t size; /* sum of lengths of all subqueues */
};

/*
 * Structure that represents a single destination (prefix).
 */
typedef struct rib_dest_t_ {

	/*
	 * Back pointer to the route node for this destination. This helps
	 * us get to the prefix that this structure is for.
	 */
	struct route_node *rnode;

	/*
	 * Doubly-linked list of routes for this prefix.
	 */
	struct route_entry *routes;

	struct route_entry *selected_fib;

	/*
	 * Flags, see below.
	 */
	uint32_t flags;

	/*
	 * Linkage to put dest on the FPM processing queue.
	 */
	TAILQ_ENTRY(rib_dest_t_) fpm_q_entries;

} rib_dest_t;

#define RIB_ROUTE_QUEUED(x)	(1 << (x))
// If MQ_SIZE is modified this value needs to be updated.
#define RIB_ROUTE_ANY_QUEUED    0x1F

/*
 * The maximum qindex that can be used.
 */
#define ZEBRA_MAX_QINDEX        (MQ_SIZE - 1)

/*
 * This flag indicates that a given prefix has been 'advertised' to
 * the FPM to be installed in the forwarding plane.
 */
#define RIB_DEST_SENT_TO_FPM   (1 << (ZEBRA_MAX_QINDEX + 1))

/*
 * This flag is set when we need to send an update to the FPM about a
 * dest.
 */
#define RIB_DEST_UPDATE_FPM    (1 << (ZEBRA_MAX_QINDEX + 2))

/*
 * Macro to iterate over each route for a destination (prefix).
 */
#define RE_DEST_FOREACH_ROUTE(dest, re)                                        \
	for ((re) = (dest) ? (dest)->routes : NULL; (re); (re) = (re)->next)

/*
 * Same as above, but allows the current node to be unlinked.
 */
#define RE_DEST_FOREACH_ROUTE_SAFE(dest, re, next)                             \
	for ((re) = (dest) ? (dest)->routes : NULL;                            \
	     (re) && ((next) = (re)->next, 1); (re) = (next))

#define RNODE_FOREACH_RE(rn, re)                                               \
	RE_DEST_FOREACH_ROUTE (rib_dest_from_rnode(rn), re)

#define RNODE_FOREACH_RE_SAFE(rn, re, next)                                    \
	RE_DEST_FOREACH_ROUTE_SAFE (rib_dest_from_rnode(rn), re, next)

#if defined(HAVE_RTADV)
/* Structure which hold status of router advertisement. */
struct rtadv {
	int sock;

	int adv_if_count;
	int adv_msec_if_count;

	struct thread *ra_read;
	struct thread *ra_timer;
};
#endif /* HAVE_RTADV */

/*
 * rib_table_info_t
 *
 * Structure that is hung off of a route_table that holds information about
 * the table.
 */
typedef struct rib_table_info_t_ {

	/*
	 * Back pointer to zebra_vrf.
	 */
	struct zebra_vrf *zvrf;
	afi_t afi;
	safi_t safi;

} rib_table_info_t;

typedef enum {
	RIB_TABLES_ITER_S_INIT,
	RIB_TABLES_ITER_S_ITERATING,
	RIB_TABLES_ITER_S_DONE
} rib_tables_iter_state_t;

/*
 * Structure that holds state for iterating over all tables in the
 * Routing Information Base.
 */
typedef struct rib_tables_iter_t_ {
	vrf_id_t vrf_id;
	int afi_safi_ix;

	rib_tables_iter_state_t state;
} rib_tables_iter_t;

/* Events/reasons triggering a RIB update. */
typedef enum {
	RIB_UPDATE_IF_CHANGE,
	RIB_UPDATE_RMAP_CHANGE,
	RIB_UPDATE_OTHER
} rib_update_event_t;

extern struct nexthop *route_entry_nexthop_ifindex_add(struct route_entry *re,
						       ifindex_t ifindex,
						       vrf_id_t nh_vrf_id);
extern struct nexthop *
route_entry_nexthop_blackhole_add(struct route_entry *re,
				  enum blackhole_type bh_type);
extern struct nexthop *route_entry_nexthop_ipv4_add(struct route_entry *re,
						    struct in_addr *ipv4,
						    struct in_addr *src,
						    vrf_id_t nh_vrf_id);
extern struct nexthop *
route_entry_nexthop_ipv4_ifindex_add(struct route_entry *re,
				     struct in_addr *ipv4, struct in_addr *src,
				     ifindex_t ifindex, vrf_id_t nh_vrf_id);
extern void route_entry_nexthop_delete(struct route_entry *re,
				       struct nexthop *nexthop);
extern struct nexthop *route_entry_nexthop_ipv6_add(struct route_entry *re,
						    struct in6_addr *ipv6,
						    vrf_id_t nh_vrf_id);
extern struct nexthop *
route_entry_nexthop_ipv6_ifindex_add(struct route_entry *re,
				     struct in6_addr *ipv6, ifindex_t ifindex,
				     vrf_id_t nh_vrf_id);
extern void route_entry_nexthop_add(struct route_entry *re,
				    struct nexthop *nexthop);
extern void route_entry_copy_nexthops(struct route_entry *re,
				      struct nexthop *nh);

#define route_entry_dump(prefix, src, re) _route_entry_dump(__func__, prefix, src, re)
extern void _route_entry_dump(const char *func, union prefixconstptr pp,
			      union prefixconstptr src_pp,
			      const struct route_entry *re);
/* RPF lookup behaviour */
enum multicast_mode {
	MCAST_NO_CONFIG = 0,  /* MIX_MRIB_FIRST, but no show in config write */
	MCAST_MRIB_ONLY,      /* MRIB only */
	MCAST_URIB_ONLY,      /* URIB only */
	MCAST_MIX_MRIB_FIRST, /* MRIB, if nothing at all then URIB */
	MCAST_MIX_DISTANCE,   /* MRIB & URIB, lower distance wins */
	MCAST_MIX_PFXLEN,     /* MRIB & URIB, longer prefix wins */
			      /* on equal value, MRIB wins for last 2 */
};

extern void multicast_mode_ipv4_set(enum multicast_mode mode);
extern enum multicast_mode multicast_mode_ipv4_get(void);

extern void rib_lookup_and_dump(struct prefix_ipv4 *p, vrf_id_t vrf_id);
extern void rib_lookup_and_pushup(struct prefix_ipv4 *p, vrf_id_t vrf_id);

extern int rib_lookup_ipv4_route(struct prefix_ipv4 *p, union sockunion *qgate,
				 vrf_id_t vrf_id);
#define ZEBRA_RIB_LOOKUP_ERROR -1
#define ZEBRA_RIB_FOUND_EXACT 0
#define ZEBRA_RIB_FOUND_NOGATE 1
#define ZEBRA_RIB_FOUND_CONNECTED 2
#define ZEBRA_RIB_NOTFOUND 3

extern int is_zebra_valid_kernel_table(uint32_t table_id);
extern int is_zebra_main_routing_table(uint32_t table_id);
extern int zebra_check_addr(struct prefix *p);

extern void rib_addnode(struct route_node *rn, struct route_entry *re,
			int process);
extern void rib_delnode(struct route_node *rn, struct route_entry *re);
extern void rib_install_kernel(struct route_node *rn, struct route_entry *re,
			       struct route_entry *old);
extern void rib_uninstall_kernel(struct route_node *rn, struct route_entry *re);

/* NOTE:
 * All rib_add function will not just add prefix into RIB, but
 * also implicitly withdraw equal prefix of same type. */
extern int rib_add(afi_t afi, safi_t safi, vrf_id_t vrf_id, int type,
		   unsigned short instance, int flags, struct prefix *p,
		   struct prefix_ipv6 *src_p, const struct nexthop *nh,
		   uint32_t table_id, uint32_t metric, uint32_t mtu,
		   uint8_t distance, route_tag_t tag);

extern int rib_add_multipath(afi_t afi, safi_t safi, struct prefix *p,
			     struct prefix_ipv6 *src_p, struct route_entry *re);

extern void rib_delete(afi_t afi, safi_t safi, vrf_id_t vrf_id, int type,
		       unsigned short instance, int flags, struct prefix *p,
		       struct prefix_ipv6 *src_p, const struct nexthop *nh,
		       uint32_t table_id, uint32_t metric, bool fromkernel);

extern struct route_entry *rib_match(afi_t afi, safi_t safi, vrf_id_t vrf_id,
				     union g_addr *addr,
				     struct route_node **rn_out);
extern struct route_entry *rib_match_ipv4_multicast(vrf_id_t vrf_id,
						    struct in_addr addr,
						    struct route_node **rn_out);

extern struct route_entry *rib_lookup_ipv4(struct prefix_ipv4 *p,
					   vrf_id_t vrf_id);

extern void rib_update(vrf_id_t vrf_id, rib_update_event_t event);
extern void rib_sweep_route(void);
extern void rib_sweep_table(struct route_table *table);
extern void rib_close_table(struct route_table *table);
extern void rib_init(void);
extern unsigned long rib_score_proto(uint8_t proto, unsigned short instance);
extern unsigned long rib_score_proto_table(uint8_t proto,
					   unsigned short instance,
					   struct route_table *table);
extern void rib_queue_add(struct route_node *rn);
extern void meta_queue_free(struct meta_queue *mq);
extern int zebra_rib_labeled_unicast(struct route_entry *re);
extern struct route_table *rib_table_ipv6;

extern void rib_unlink(struct route_node *rn, struct route_entry *re);
extern int rib_gc_dest(struct route_node *rn);
extern struct route_table *rib_tables_iter_next(rib_tables_iter_t *iter);

extern uint8_t route_distance(int type);

/*
 * Inline functions.
 */

/*
 * rib_table_info
 */
static inline rib_table_info_t *rib_table_info(struct route_table *table)
{
	return (rib_table_info_t *)table->info;
}

/*
 * rib_dest_from_rnode
 */
static inline rib_dest_t *rib_dest_from_rnode(struct route_node *rn)
{
	return (rib_dest_t *)rn->info;
}

/*
 * rnode_to_ribs
 *
 * Returns a pointer to the list of routes corresponding to the given
 * route_node.
 */
static inline struct route_entry *rnode_to_ribs(struct route_node *rn)
{
	rib_dest_t *dest;

	dest = rib_dest_from_rnode(rn);
	if (!dest)
		return NULL;

	return dest->routes;
}

/*
 * rib_dest_prefix
 */
static inline struct prefix *rib_dest_prefix(rib_dest_t *dest)
{
	return &dest->rnode->p;
}

/*
 * rib_dest_af
 *
 * Returns the address family that the destination is for.
 */
static inline uint8_t rib_dest_af(rib_dest_t *dest)
{
	return dest->rnode->p.family;
}

/*
 * rib_dest_table
 */
static inline struct route_table *rib_dest_table(rib_dest_t *dest)
{
	return srcdest_rnode_table(dest->rnode);
}

/*
 * rib_dest_vrf
 */
static inline struct zebra_vrf *rib_dest_vrf(rib_dest_t *dest)
{
	return rib_table_info(rib_dest_table(dest))->zvrf;
}

/*
 * rib_tables_iter_init
 */
static inline void rib_tables_iter_init(rib_tables_iter_t *iter)

{
	memset(iter, 0, sizeof(*iter));
	iter->state = RIB_TABLES_ITER_S_INIT;
}

/*
 * rib_tables_iter_started
 *
 * Returns TRUE if this iterator has started iterating over the set of
 * tables.
 */
static inline int rib_tables_iter_started(rib_tables_iter_t *iter)
{
	return iter->state != RIB_TABLES_ITER_S_INIT;
}

/*
 * rib_tables_iter_cleanup
 */
static inline void rib_tables_iter_cleanup(rib_tables_iter_t *iter)
{
	iter->state = RIB_TABLES_ITER_S_DONE;
}

DECLARE_HOOK(rib_update, (struct route_node * rn, const char *reason),
	     (rn, reason))


extern void zebra_vty_init(void);
extern int static_config(struct vty *vty, struct zebra_vrf *zvrf, afi_t afi,
			 safi_t safi, const char *cmd);
extern void static_config_install_delayed_routes(struct zebra_vrf *zvrf);

extern pid_t pid;

extern bool v6_rr_semantics;
#endif /*_ZEBRA_RIB_H */
