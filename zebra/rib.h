// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Routing Information Base header
 * Copyright (C) 1997 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_RIB_H
#define _ZEBRA_RIB_H

#include "zebra.h"
#include "memory.h"
#include "hook.h"
#include "typesafe.h"
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
#include "zebra/zebra_nhg.h"

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MGROUP(ZEBRA);

DECLARE_MTYPE(RE);

PREDECL_LIST(rnh_list);

/* Nexthop structure. */
struct rnh {
	uint8_t flags;

#define ZEBRA_NHT_CONNECTED 0x1
#define ZEBRA_NHT_DELETED 0x2
#define ZEBRA_NHT_RESOLVE_VIA_DEFAULT 0x4

	/* VRF identifier. */
	vrf_id_t vrf_id;

	afi_t afi;
	safi_t safi;

	uint32_t seqno;

	struct route_entry *state;
	struct prefix resolved_route;
	struct list *client_list;

	/* pseudowires dependent on this nh */
	struct list *zebra_pseudowire_list;

	struct route_node *node;

	/*
	 * if this has been filtered for the client
	 */
	int filtered[ZEBRA_ROUTE_MAX];

	struct rnh_list_item rnh_list_item;
};

#define DISTANCE_INFINITY  255
#define ZEBRA_KERNEL_TABLE_MAX 252 /* support for no more than this rt tables */

PREDECL_LIST(re_list);

struct re_opaque {
	uint16_t length;
	uint8_t data[];
};

struct route_entry {
	/* Link list. */
	struct re_list_item next;

	/* Nexthop group, shared/refcounted, based on the nexthop(s)
	 * provided by the owner of the route
	 */
	struct nhg_hash_entry *nhe;

	/* Nexthop group hash entry IDs. The "installed" id is the id
	 * used in linux/netlink, if available.
	 */
	uint32_t nhe_id;
	uint32_t nhe_installed_id;

	uint32_t pic_nhe_id;
	uint32_t pic_nhe_installed_id;

	/* Type of this route. */
	int type;

	/* VRF identifier. */
	vrf_id_t vrf_id;

	/* Which routing table */
	uint32_t table;

	/* Metric */
	uint32_t metric;

	/* MTU */
	uint32_t mtu;
	uint32_t nexthop_mtu;

	/* Flags of this route.
	 * This flag's definition is in lib/zclient.h ZEBRA_FLAG_* and is
	 * exposed to clients via Zserv
	 */
	uint32_t flags;

	/* RIB internal status */
	uint32_t status;
#define ROUTE_ENTRY_REMOVED          0x1
/* The Route Entry has changed */
#define ROUTE_ENTRY_CHANGED          0x2
/* The Label has changed on the Route entry */
#define ROUTE_ENTRY_LABELS_CHANGED   0x4
/* Route is queued for Installation into the Data Plane */
#define ROUTE_ENTRY_QUEUED   0x8
/* Route is installed into the Data Plane */
#define ROUTE_ENTRY_INSTALLED        0x10
/* Route has Failed installation into the Data Plane in some manner */
#define ROUTE_ENTRY_FAILED           0x20
/* Route has a 'fib' set of nexthops, probably because the installed set
 * differs from the rib/normal set of nexthops.
 */
#define ROUTE_ENTRY_USE_FIB_NHG      0x40
/*
 * Route entries that are going to the dplane for a Route Replace
 * let's note the fact that this is happening.  This will
 * be useful when zebra is determing if a route can be
 * used for nexthops
 */
#define ROUTE_ENTRY_ROUTE_REPLACING 0x80

	/* Sequence value incremented for each dataplane operation */
	uint32_t dplane_sequence;

	/* Source protocol instance */
	uint16_t instance;

	/* Distance. */
	uint8_t distance;

	/* Tag */
	route_tag_t tag;

	/* Uptime. */
	time_t uptime;

	struct re_opaque *opaque;

	/* Nexthop group from FIB (optional), reflecting what is actually
	 * installed in the FIB if that differs. The 'backup' group is used
	 * when backup nexthops are present in the route's nhg.
	 */
	struct nexthop_group fib_ng;
	struct nexthop_group fib_backup_ng;
};

#define RIB_SYSTEM_ROUTE(R) RSYSTEM_ROUTE((R)->type)

#define RIB_KERNEL_ROUTE(R) RKERNEL_ROUTE((R)->type)

/* Define route types that are equivalent to "connected". */
#define RIB_CONNECTED_ROUTE(R)                                                 \
	((R)->type == ZEBRA_ROUTE_CONNECT || (R)->type == ZEBRA_ROUTE_LOCAL || (R)->type == ZEBRA_ROUTE_NHRP)

/* meta-queue structure:
 * sub-queue 0: nexthop group objects
 * sub-queue 1: EVPN/VxLAN objects
 * sub-queue 2: Early Route Processing
 * sub-queue 3: Early Label Processing
 * sub-queue 4: connected
 * sub-queue 5: kernel
 * sub-queue 6: static
 * sub-queue 7: RIP, RIPng, OSPF, OSPF6, IS-IS, EIGRP, NHRP
 * sub-queue 8: iBGP, eBGP
 * sub-queue 9: any other origin (if any) typically those that
 *              don't generate routes
 */
#define MQ_SIZE 11

/* For checking that an object has already queued in some sub-queue */
#define MQ_BIT_MASK ((1 << MQ_SIZE) - 1)

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
	struct re_list_head routes;

	struct route_entry *selected_fib;

	/*
	 * Flags, see below.
	 */
	uint32_t flags;

	/*
	 * The list of nht prefixes that have ended up
	 * depending on this route node.
	 * After route processing is returned from
	 * the data plane we will run evaluate_rnh
	 * on these prefixes.
	 */
	struct rnh_list_head nht;

	/*
	 * Linkage to put dest on the FPM processing queue.
	 */
	TAILQ_ENTRY(rib_dest_t_) fpm_q_entries;

} rib_dest_t;

DECLARE_LIST(rnh_list, struct rnh, rnh_list_item);
DECLARE_LIST(re_list, struct route_entry, next);

#define RIB_ROUTE_QUEUED(x)	(1 << (x))
// If MQ_SIZE is modified this value needs to be updated.
#define RIB_ROUTE_ANY_QUEUED 0x3F

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

#define RIB_DEST_UPDATE_LSPS   (1 << (ZEBRA_MAX_QINDEX + 3))

/*
 * Macro to iterate over each route for a destination (prefix).
 */
#define RE_DEST_FOREACH_ROUTE(dest, re)                                        \
	for ((re) = (dest) ? re_list_first(&((dest)->routes)) : NULL; (re);    \
	     (re) = re_list_next(&((dest)->routes), (re)))

/*
 * Same as above, but allows the current node to be unlinked.
 */
#define RE_DEST_FOREACH_ROUTE_SAFE(dest, re, next)                             \
	for ((re) = (dest) ? re_list_first(&((dest)->routes)) : NULL;          \
	     (re) && ((next) = re_list_next(&((dest)->routes), (re)), 1);      \
	     (re) = (next))

#define RE_DEST_FIRST_ROUTE(dest, re)                                          \
	((re) = (dest) ? re_list_first(&((dest)->routes)) : NULL)

#define RE_DEST_NEXT_ROUTE(dest, re)                                           \
	((re) = (dest) ? re_list_next(&((dest)->routes), (re)) : NULL)

#define RNODE_FOREACH_RE(rn, re)                                               \
	RE_DEST_FOREACH_ROUTE (rib_dest_from_rnode(rn), re)

#define RNODE_FOREACH_RE_SAFE(rn, re, next)                                    \
	RE_DEST_FOREACH_ROUTE_SAFE (rib_dest_from_rnode(rn), re, next)

#define RNODE_FIRST_RE(rn, re) RE_DEST_FIRST_ROUTE(rib_dest_from_rnode(rn), re)

#define RNODE_NEXT_RE(rn, re) RE_DEST_NEXT_ROUTE(rib_dest_from_rnode(rn), re)

/*
 * rib_table_info_t
 *
 * Structure that is hung off of a route_table that holds information about
 * the table.
 */
struct rib_table_info {

	/*
	 * Back pointer to zebra_vrf.
	 */
	struct zebra_vrf *zvrf;
	afi_t afi;
	safi_t safi;
	uint32_t table_id;
};

enum rib_tables_iter_state {
	RIB_TABLES_ITER_S_INIT,
	RIB_TABLES_ITER_S_ITERATING,
	RIB_TABLES_ITER_S_DONE
};

/*
 * Structure that holds state for iterating over all tables in the
 * Routing Information Base.
 */
typedef struct rib_tables_iter_t_ {
	vrf_id_t vrf_id;
	int afi_safi_ix;

	enum rib_tables_iter_state state;
} rib_tables_iter_t;

/* Events/reasons triggering a RIB update. */
enum rib_update_event {
	RIB_UPDATE_INTERFACE_DOWN,
	RIB_UPDATE_KERNEL,
	RIB_UPDATE_RMAP_CHANGE,
	RIB_UPDATE_OTHER,
	RIB_UPDATE_MAX
};
void rib_update_finish(void);

int route_entry_update_nhe(struct route_entry *re,
			   struct nhg_hash_entry *new_nhghe);

/* NHG replace has happend, we have to update route_entry pointers to new one */
int rib_handle_nhg_replace(struct nhg_hash_entry *old_entry,
			   struct nhg_hash_entry *new_entry);

#define route_entry_dump(prefix, src, re) _route_entry_dump(__func__, prefix, src, re)
extern void _route_entry_dump(const char *func, union prefixconstptr pp,
			      union prefixconstptr src_pp,
			      const struct route_entry *re);

void zebra_rib_route_entry_free(struct route_entry *re);

struct route_entry *
zebra_rib_route_entry_new(vrf_id_t vrf_id, int type, uint8_t instance,
			  uint32_t flags, uint32_t nhe_id, uint32_t table_id,
			  uint32_t metric, uint32_t mtu, uint8_t distance,
			  route_tag_t tag);

#define ZEBRA_RIB_LOOKUP_ERROR -1
#define ZEBRA_RIB_FOUND_EXACT 0
#define ZEBRA_RIB_FOUND_NOGATE 1
#define ZEBRA_RIB_FOUND_CONNECTED 2
#define ZEBRA_RIB_NOTFOUND 3

extern int is_zebra_valid_kernel_table(uint32_t table_id);
extern int is_zebra_main_routing_table(uint32_t table_id);
extern int zebra_check_addr(const struct prefix *p);

extern void rib_delnode(struct route_node *rn, struct route_entry *re);
extern void rib_install_kernel(struct route_node *rn, struct route_entry *re,
			       struct route_entry *old);
extern void rib_uninstall_kernel(struct route_node *rn, struct route_entry *re);

/* NOTE:
 * All rib_add function will not just add prefix into RIB, but
 * also implicitly withdraw equal prefix of same type. */
extern int rib_add(afi_t afi, safi_t safi, vrf_id_t vrf_id, int type,
		   unsigned short instance, uint32_t flags, struct prefix *p,
		   struct prefix_ipv6 *src_p, const struct nexthop *nh,
		   uint32_t nhe_id, uint32_t table_id, uint32_t metric,
		   uint32_t mtu, uint8_t distance, route_tag_t tag,
		   bool startup);
/*
 * Multipath route apis.
 */
extern int rib_add_multipath(afi_t afi, safi_t safi, struct prefix *p,
			     struct prefix_ipv6 *src_p, struct route_entry *re,
			     struct nexthop_group *ng, bool startup);
/*
 * -1 -> some sort of error
 *  0 -> an add
 *  1 -> an update
 */
extern int rib_add_multipath_nhe(afi_t afi, safi_t safi, struct prefix *p,
				 struct prefix_ipv6 *src_p,
				 struct route_entry *re,
				 struct nhg_hash_entry *nhe, bool startup);

extern void rib_delete(afi_t afi, safi_t safi, vrf_id_t vrf_id, int type,
		       unsigned short instance, uint32_t flags,
		       const struct prefix *p, const struct prefix_ipv6 *src_p,
		       const struct nexthop *nh, uint32_t nhe_id,
		       uint32_t table_id, uint32_t metric, uint8_t distance,
		       bool fromkernel);

extern struct route_entry *rib_match(afi_t afi, safi_t safi, vrf_id_t vrf_id,
				     const union g_addr *addr,
				     struct route_node **rn_out);
extern struct route_entry *rib_match_multicast(afi_t afi, vrf_id_t vrf_id,
					       union g_addr *gaddr,
					       struct route_node **rn_out);

extern void rib_update(enum rib_update_event event);
extern void rib_update_table(struct route_table *table,
			     enum rib_update_event event, int rtype);
extern void rib_sweep_route(struct event *t);
extern void rib_sweep_table(struct route_table *table);
extern void rib_close_table(struct route_table *table);
extern void zebra_rib_init(void);
extern void zebra_rib_terminate(void);
extern unsigned long rib_score_proto(uint8_t proto, unsigned short instance);
extern unsigned long rib_score_proto_table(uint8_t proto,
					   unsigned short instance,
					   struct route_table *table);

extern int rib_queue_add(struct route_node *rn);

struct nhg_ctx; /* Forward declaration */

/* Enqueue incoming nhg from OS for processing */
extern int rib_queue_nhg_ctx_add(struct nhg_ctx *ctx);

/* Enqueue incoming nhg from proto daemon for processing */
extern int rib_queue_nhe_add(struct nhg_hash_entry *nhe);
extern int rib_queue_nhe_del(struct nhg_hash_entry *nhe);

/* Enqueue evpn route for processing */
int zebra_rib_queue_evpn_route_add(vrf_id_t vrf_id, const struct ethaddr *rmac,
				   const struct ipaddr *vtep_ip,
				   const struct prefix *host_prefix);
int zebra_rib_queue_evpn_route_del(vrf_id_t vrf_id,
				   const struct ipaddr *vtep_ip,
				   const struct prefix *host_prefix);
/* Enqueue EVPN remote ES for processing */
int zebra_rib_queue_evpn_rem_es_add(const esi_t *esi,
				    const struct in_addr *vtep_ip,
				    bool esr_rxed, uint8_t df_alg,
				    uint16_t df_pref);
int zebra_rib_queue_evpn_rem_es_del(const esi_t *esi,
				    const struct in_addr *vtep_ip);
/* Enqueue EVPN remote macip update for processing */
int zebra_rib_queue_evpn_rem_macip_del(vni_t vni, const struct ethaddr *macaddr,
				       const struct ipaddr *ip,
				       struct in_addr vtep_ip);
int zebra_rib_queue_evpn_rem_macip_add(vni_t vni, const struct ethaddr *macaddr,
				       const struct ipaddr *ipaddr,
				       uint8_t flags, uint32_t seq,
				       struct in_addr vtep_ip,
				       const esi_t *esi);
/* Enqueue VXLAN remote vtep update for processing */
int zebra_rib_queue_evpn_rem_vtep_add(vrf_id_t vrf_id, vni_t vni,
				      struct in_addr vtep_ip,
				      int flood_control);
int zebra_rib_queue_evpn_rem_vtep_del(vrf_id_t vrf_id, vni_t vni,
				      struct in_addr vtep_ip);

extern void meta_queue_free(struct meta_queue *mq, struct zebra_vrf *zvrf);
extern int zebra_rib_labeled_unicast(struct route_entry *re);
extern struct route_table *rib_table_ipv6;

extern void rib_unlink(struct route_node *rn, struct route_entry *re);
extern int rib_gc_dest(struct route_node *rn);
extern struct route_table *rib_tables_iter_next(rib_tables_iter_t *iter);

extern uint8_t route_distance(int type);
extern bool zebra_update_pic_nhe(struct route_node *rn);

extern void zebra_rib_evaluate_rn_nexthops(struct route_node *rn, uint32_t seq,
					   bool rt_delete);

extern void rib_update_handle_vrf_all(enum rib_update_event event, int rtype);

/*
 * rib_find_rn_from_ctx
 *
 * Returns a lock increased route_node for the appropriate
 * table and prefix specified by the context.  Developer
 * should unlock the node when done.
 */
extern struct route_node *
rib_find_rn_from_ctx(const struct zebra_dplane_ctx *ctx);

/*
 * Inline functions.
 */

/*
 * rib_table_info
 */
static inline struct rib_table_info *rib_table_info(struct route_table *table)
{
	return (struct rib_table_info *)route_table_get_info(table);
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

	return re_list_first(&dest->routes);
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
 * Create the rib_dest_t and attach it to the specified node
 */
extern rib_dest_t *zebra_rib_create_dest(struct route_node *rn);

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
 * Returns true if this iterator has started iterating over the set of
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
	     (rn, reason));
DECLARE_HOOK(rib_shutdown, (struct route_node * rn), (rn));

/*
 * Access installed/fib nexthops, which may be a subset of the
 * rib nexthops.
 */
static inline struct nexthop_group *rib_get_fib_nhg(struct route_entry *re)
{
	/* If the fib set is a subset of the active rib set,
	 * use the dedicated fib list.
	 */
	if (CHECK_FLAG(re->status, ROUTE_ENTRY_USE_FIB_NHG))
		return &(re->fib_ng);
	else
		return &(re->nhe->nhg);
}

/*
 * Access backup nexthop-group that represents the installed backup nexthops;
 * any installed backup will be on the fib list.
 */
static inline struct nexthop_group *rib_get_fib_backup_nhg(
	struct route_entry *re)
{
	return &(re->fib_backup_ng);
}

extern void zebra_gr_process_client(afi_t afi, vrf_id_t vrf_id, uint8_t proto,
				    uint8_t instance, time_t restart_time);

extern int rib_add_gr_run(afi_t afi, vrf_id_t vrf_id, uint8_t proto,
			  uint8_t instance, time_t restart_time);

extern void zebra_vty_init(void);
extern uint32_t zebra_rib_dplane_results_count(void);

extern pid_t pid;

extern uint32_t rt_table_main_id;

void route_entry_dump_nh(const struct route_entry *re, const char *straddr,
			 const struct vrf *re_vrf,
			 const struct nexthop *nexthop);

/* Name of hook calls */
#define ZEBRA_ON_RIB_PROCESS_HOOK_CALL "on_rib_process_dplane_results"

extern bool fpm_pic_nexthop;

#ifdef __cplusplus
}
#endif

#endif /*_ZEBRA_RIB_H */
