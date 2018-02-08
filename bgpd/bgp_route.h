/* BGP routing information base
 * Copyright (C) 1996, 97, 98, 2000 Kunihiro Ishiguro
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

#ifndef _QUAGGA_BGP_ROUTE_H
#define _QUAGGA_BGP_ROUTE_H

#include "queue.h"
#include "nexthop.h"
#include "bgp_table.h"

struct bgp_nexthop_cache;
struct bgp_route_evpn;

enum bgp_show_type {
	bgp_show_type_normal,
	bgp_show_type_regexp,
	bgp_show_type_prefix_list,
	bgp_show_type_filter_list,
	bgp_show_type_route_map,
	bgp_show_type_neighbor,
	bgp_show_type_cidr_only,
	bgp_show_type_prefix_longer,
	bgp_show_type_community_all,
	bgp_show_type_community,
	bgp_show_type_community_exact,
	bgp_show_type_community_list,
	bgp_show_type_community_list_exact,
	bgp_show_type_lcommunity_all,
	bgp_show_type_lcommunity,
	bgp_show_type_lcommunity_list,
	bgp_show_type_flap_statistics,
	bgp_show_type_flap_neighbor,
	bgp_show_type_dampend_paths,
	bgp_show_type_damp_neighbor
};


#define BGP_SHOW_SCODE_HEADER                                                  \
	"Status codes: s suppressed, d damped, "                               \
	"h history, * valid, > best, = multipath,\n"                           \
	"              i internal, r RIB-failure, S Stale, R Removed\n"
#define BGP_SHOW_OCODE_HEADER "Origin codes: i - IGP, e - EGP, ? - incomplete\n\n"
#define BGP_SHOW_HEADER "   Network          Next Hop            Metric LocPrf Weight Path\n"

/* Maximum number of labels we can process or send with a prefix. We
 * really do only 1 for MPLS (BGP-LU) but we can do 2 for EVPN-VxLAN.
 */
#define BGP_MAX_LABELS 2

/* Ancillary information to struct bgp_info,
 * used for uncommonly used data (aggregation, MPLS, etc.)
 * and lazily allocated to save memory.
 */
struct bgp_info_extra {
	/* Pointer to dampening structure.  */
	struct bgp_damp_info *damp_info;

	/* This route is suppressed with aggregation.  */
	int suppress;

	/* Nexthop reachability check.  */
	u_int32_t igpmetric;

	/* MPLS label(s) - VNI(s) for EVPN-VxLAN  */
	mpls_label_t label[BGP_MAX_LABELS];
	u_int32_t num_labels;

#if ENABLE_BGP_VNC
	union {

		struct {
			void *rfapi_handle; /* export: NVE advertising this
					       route */
			struct list *local_nexthops; /* optional, for static
							routes */
		} export;

		struct {
			struct thread *timer;
			void *hme; /* encap monitor, if this is a VPN route */
			struct prefix_rd
				rd; /* import: route's route-distinguisher */
			u_char un_family; /* family of cached un address, 0 if
					     unset */
			union {
				struct in_addr addr4;
				struct in6_addr addr6;
			} un; /* cached un address */
			time_t create_time;
			struct
				prefix
					aux_prefix; /* AFI_L2VPN: the IP addr,
						       if family set */
		} import;

	} vnc;
#endif

	/* For imported routes into a VNI (or VRF), this points to the parent.
	 */
	void *parent;
};

struct bgp_info {
	/* For linked list. */
	struct bgp_info *next;
	struct bgp_info *prev;

	/* For nexthop linked list */
	LIST_ENTRY(bgp_info) nh_thread;

	/* Back pointer to the prefix node */
	struct bgp_node *net;

	/* Back pointer to the nexthop structure */
	struct bgp_nexthop_cache *nexthop;

	/* Peer structure.  */
	struct peer *peer;

	/* Attribute structure.  */
	struct attr *attr;

	/* Extra information */
	struct bgp_info_extra *extra;


	/* Multipath information */
	struct bgp_info_mpath *mpath;

	/* Uptime.  */
	time_t uptime;

	/* reference count */
	int lock;

	/* BGP information status.  */
	u_int16_t flags;
#define BGP_INFO_IGP_CHANGED    (1 << 0)
#define BGP_INFO_DAMPED         (1 << 1)
#define BGP_INFO_HISTORY        (1 << 2)
#define BGP_INFO_SELECTED       (1 << 3)
#define BGP_INFO_VALID          (1 << 4)
#define BGP_INFO_ATTR_CHANGED   (1 << 5)
#define BGP_INFO_DMED_CHECK     (1 << 6)
#define BGP_INFO_DMED_SELECTED  (1 << 7)
#define BGP_INFO_STALE          (1 << 8)
#define BGP_INFO_REMOVED        (1 << 9)
#define BGP_INFO_COUNTED	(1 << 10)
#define BGP_INFO_MULTIPATH      (1 << 11)
#define BGP_INFO_MULTIPATH_CHG  (1 << 12)
#define BGP_INFO_RIB_ATTR_CHG   (1 << 13)

	/* BGP route type.  This can be static, RIP, OSPF, BGP etc.  */
	u_char type;

	/* When above type is BGP.  This sub type specify BGP sub type
	   information.  */
	u_char sub_type;
#define BGP_ROUTE_NORMAL       0
#define BGP_ROUTE_STATIC       1
#define BGP_ROUTE_AGGREGATE    2
#define BGP_ROUTE_REDISTRIBUTE 3 
#ifdef ENABLE_BGP_VNC
# define BGP_ROUTE_RFP          4 
#endif

	u_short instance;

	/* Addpath identifiers */
	u_int32_t addpath_rx_id;
	u_int32_t addpath_tx_id;
};

/* Structure used in BGP path selection */
struct bgp_info_pair {
	struct bgp_info *old;
	struct bgp_info *new;
};

/* BGP static route configuration. */
struct bgp_static {
	/* Backdoor configuration.  */
	int backdoor;

	/* Label index configuration; applies to LU prefixes. */
	u_int32_t label_index;
#define BGP_INVALID_LABEL_INDEX   0xFFFFFFFF

	/* Import check status.  */
	u_char valid;

	/* IGP metric. */
	u_int32_t igpmetric;

	/* IGP nexthop. */
	struct in_addr igpnexthop;

	/* Atomic set reference count (ie cause of pathlimit) */
	u_int32_t atomic;

	/* BGP redistribute route-map.  */
	struct {
		char *name;
		struct route_map *map;
	} rmap;

	/* Route Distinguisher */
	struct prefix_rd prd;

	/* MPLS label.  */
	mpls_label_t label;

	/* EVPN */
	struct eth_segment_id *eth_s_id;
	struct ethaddr *router_mac;
	uint16_t encap_tunneltype;
	struct prefix gatewayIp;
};

#define BGP_NEXTHOP_AFI_FROM_NHLEN(nhlen)                                      \
	((nhlen) < IPV4_MAX_BYTELEN                                            \
		 ? 0                                                           \
		 : ((nhlen) < IPV6_MAX_BYTELEN ? AFI_IP : AFI_IP6))

#define BGP_ATTR_NEXTHOP_AFI_IP6(attr)                                         \
	(!CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP))             \
	 && ((attr)->mp_nexthop_len == 16 || (attr)->mp_nexthop_len == 32))
#define BGP_INFO_COUNTABLE(BI)                                                 \
	(!CHECK_FLAG((BI)->flags, BGP_INFO_HISTORY)                            \
	 && !CHECK_FLAG((BI)->flags, BGP_INFO_REMOVED))

/* Flags which indicate a route is unuseable in some form */
#define BGP_INFO_UNUSEABLE                                                     \
	(BGP_INFO_HISTORY | BGP_INFO_DAMPED | BGP_INFO_REMOVED)
/* Macro to check BGP information is alive or not.  Sadly,
 * not equivalent to just checking previous, because of the
 * sense of the additional VALID flag.
 */
#define BGP_INFO_HOLDDOWN(BI)                                                  \
	(!CHECK_FLAG((BI)->flags, BGP_INFO_VALID)                              \
	 || CHECK_FLAG((BI)->flags, BGP_INFO_UNUSEABLE))

#define DISTRIBUTE_IN_NAME(F)   ((F)->dlist[FILTER_IN].name)
#define DISTRIBUTE_IN(F)        ((F)->dlist[FILTER_IN].alist)
#define DISTRIBUTE_OUT_NAME(F)  ((F)->dlist[FILTER_OUT].name)
#define DISTRIBUTE_OUT(F)       ((F)->dlist[FILTER_OUT].alist)

#define PREFIX_LIST_IN_NAME(F)  ((F)->plist[FILTER_IN].name)
#define PREFIX_LIST_IN(F)       ((F)->plist[FILTER_IN].plist)
#define PREFIX_LIST_OUT_NAME(F) ((F)->plist[FILTER_OUT].name)
#define PREFIX_LIST_OUT(F)      ((F)->plist[FILTER_OUT].plist)

#define FILTER_LIST_IN_NAME(F)  ((F)->aslist[FILTER_IN].name)
#define FILTER_LIST_IN(F)       ((F)->aslist[FILTER_IN].aslist)
#define FILTER_LIST_OUT_NAME(F) ((F)->aslist[FILTER_OUT].name)
#define FILTER_LIST_OUT(F)      ((F)->aslist[FILTER_OUT].aslist)

#define ROUTE_MAP_IN_NAME(F)    ((F)->map[RMAP_IN].name)
#define ROUTE_MAP_IN(F)         ((F)->map[RMAP_IN].map)
#define ROUTE_MAP_OUT_NAME(F)   ((F)->map[RMAP_OUT].name)
#define ROUTE_MAP_OUT(F)        ((F)->map[RMAP_OUT].map)

#define UNSUPPRESS_MAP_NAME(F)  ((F)->usmap.name)
#define UNSUPPRESS_MAP(F)       ((F)->usmap.map)

/* path PREFIX (addpath rxid NUMBER) */
#define PATH_ADDPATH_STR_BUFFER PREFIX2STR_BUFFER + 32

enum bgp_path_type { BGP_PATH_ALL, BGP_PATH_BESTPATH, BGP_PATH_MULTIPATH };

static inline void bgp_bump_version(struct bgp_node *node)
{
	node->version = bgp_table_next_version(bgp_node_table(node));
}

static inline int bgp_fibupd_safi(safi_t safi)
{
	if (safi == SAFI_UNICAST || safi == SAFI_MULTICAST
	    || safi == SAFI_LABELED_UNICAST)
		return 1;
	return 0;
}

/* Prototypes. */
extern void bgp_rib_remove(struct bgp_node *rn, struct bgp_info *ri,
			   struct peer *peer, afi_t afi, safi_t safi);
extern void bgp_process_queue_init(void);
extern void bgp_route_init(void);
extern void bgp_route_finish(void);
extern void bgp_cleanup_routes(struct bgp *);
extern void bgp_announce_route(struct peer *, afi_t, safi_t);
extern void bgp_stop_announce_route_timer(struct peer_af *paf);
extern void bgp_announce_route_all(struct peer *);
extern void bgp_default_originate(struct peer *, afi_t, safi_t, int);
extern void bgp_soft_reconfig_in(struct peer *, afi_t, safi_t);
extern void bgp_clear_route(struct peer *, afi_t, safi_t);
extern void bgp_clear_route_all(struct peer *);
extern void bgp_clear_adj_in(struct peer *, afi_t, safi_t);
extern void bgp_clear_stale_route(struct peer *, afi_t, safi_t);

extern struct bgp_node *bgp_afi_node_get(struct bgp_table *table, afi_t afi,
					 safi_t safi, struct prefix *p,
					 struct prefix_rd *prd);
extern struct bgp_info *bgp_info_lock(struct bgp_info *);
extern struct bgp_info *bgp_info_unlock(struct bgp_info *);
extern void bgp_info_add(struct bgp_node *rn, struct bgp_info *ri);
extern void bgp_info_reap(struct bgp_node *rn, struct bgp_info *ri);
extern void bgp_info_delete(struct bgp_node *rn, struct bgp_info *ri);
extern struct bgp_info_extra *bgp_info_extra_get(struct bgp_info *);
extern void bgp_info_set_flag(struct bgp_node *, struct bgp_info *, u_int32_t);
extern void bgp_info_unset_flag(struct bgp_node *, struct bgp_info *,
				u_int32_t);
extern void bgp_info_path_with_addpath_rx_str(struct bgp_info *ri, char *buf);

extern int bgp_nlri_parse_ip(struct peer *, struct attr *, struct bgp_nlri *);

extern int bgp_maximum_prefix_overflow(struct peer *, afi_t, safi_t, int);

extern void bgp_redistribute_add(struct bgp *bgp, struct prefix *p,
				 const union g_addr *nexthop, ifindex_t ifindex,
				 enum nexthop_types_t nhtype, uint32_t metric,
				 u_char type, u_short instance,
				 route_tag_t tag);
extern void bgp_redistribute_delete(struct bgp *, struct prefix *, u_char,
				    u_short);
extern void bgp_redistribute_withdraw(struct bgp *, afi_t, int, u_short);

extern void bgp_static_add(struct bgp *);
extern void bgp_static_delete(struct bgp *);
extern void bgp_static_redo_import_check(struct bgp *);
extern void bgp_purge_static_redist_routes(struct bgp *bgp);
extern void bgp_static_update(struct bgp *, struct prefix *,
			      struct bgp_static *, afi_t, safi_t);
extern void bgp_static_withdraw(struct bgp *, struct prefix *, afi_t, safi_t);

extern int bgp_static_set_safi(afi_t afi, safi_t safi, struct vty *vty,
			       const char *, const char *, const char *,
			       const char *, int, const char *, const char *,
			       const char *, const char *);

extern int bgp_static_unset_safi(afi_t afi, safi_t safi, struct vty *,
				 const char *, const char *, const char *, int,
				 const char *, const char *, const char *);

/* this is primarily for MPLS-VPN */
extern int bgp_update(struct peer *, struct prefix *, u_int32_t, struct attr *,
		      afi_t, safi_t, int, int, struct prefix_rd *,
		      mpls_label_t *, u_int32_t, int, struct bgp_route_evpn *);
extern int bgp_withdraw(struct peer *, struct prefix *, u_int32_t,
			struct attr *, afi_t, safi_t, int, int,
			struct prefix_rd *, mpls_label_t *, u_int32_t,
			struct bgp_route_evpn *);

/* for bgp_nexthop and bgp_damp */
extern void bgp_process(struct bgp *, struct bgp_node *, afi_t, safi_t);

/*
 * Add an end-of-initial-update marker to the process queue. This is just a
 * queue element with NULL bgp node.
 */
extern void bgp_add_eoiu_mark(struct bgp *);
extern void bgp_config_write_table_map(struct vty *, struct bgp *, afi_t,
				       safi_t);
extern void bgp_config_write_network(struct vty *, struct bgp *, afi_t, safi_t);
extern void bgp_config_write_distance(struct vty *, struct bgp *, afi_t,
				      safi_t);

extern void bgp_aggregate_increment(struct bgp *, struct prefix *,
				    struct bgp_info *, afi_t, safi_t);
extern void bgp_aggregate_decrement(struct bgp *, struct prefix *,
				    struct bgp_info *, afi_t, safi_t);

extern u_char bgp_distance_apply(struct prefix *, struct bgp_info *, afi_t,
				 safi_t, struct bgp *);

extern afi_t bgp_node_afi(struct vty *);
extern safi_t bgp_node_safi(struct vty *);

extern struct bgp_info *info_make(int type, int sub_type, u_short instance,
				  struct peer *peer, struct attr *attr,
				  struct bgp_node *rn);

extern void route_vty_out(struct vty *, struct prefix *, struct bgp_info *, int,
			  safi_t, json_object *);
extern void route_vty_out_tag(struct vty *, struct prefix *, struct bgp_info *,
			      int, safi_t, json_object *);
extern void route_vty_out_tmp(struct vty *, struct prefix *, struct attr *,
			      safi_t, u_char, json_object *);
extern void route_vty_out_overlay(struct vty *vty, struct prefix *p,
				  struct bgp_info *binfo, int display,
				  json_object *json);

extern int subgroup_process_announce_selected(struct update_subgroup *subgrp,
					      struct bgp_info *selected,
					      struct bgp_node *rn,
					      u_int32_t addpath_tx_id);

extern int subgroup_announce_check(struct bgp_node *rn, struct bgp_info *ri,
				   struct update_subgroup *subgrp,
				   struct prefix *p, struct attr *attr);

extern void bgp_peer_clear_node_queue_drain_immediate(struct peer *peer);
extern void bgp_process_queues_drain_immediate(void);

/* for encap/vpn */
extern struct bgp_node *bgp_afi_node_lookup(struct bgp_table *table, afi_t afi,
					    safi_t safi, struct prefix *p,
					    struct prefix_rd *prd);
extern struct bgp_info *bgp_info_new(void);
extern void bgp_info_restore(struct bgp_node *, struct bgp_info *);

extern int bgp_info_cmp_compatible(struct bgp *, struct bgp_info *,
				   struct bgp_info *, char *pfx_buf, afi_t afi,
				   safi_t safi);
extern void bgp_attr_add_gshut_community(struct attr *attr);

extern void bgp_best_selection(struct bgp *bgp, struct bgp_node *rn,
			       struct bgp_maxpaths_cfg *mpath_cfg,
			       struct bgp_info_pair *result, afi_t afi,
			       safi_t safi);
extern void bgp_zebra_clear_route_change_flags(struct bgp_node *rn);
extern int bgp_zebra_has_route_changed(struct bgp_node *rn,
				       struct bgp_info *selected);

extern void route_vty_out_detail_header(struct vty *vty, struct bgp *bgp,
					struct bgp_node *rn,
					struct prefix_rd *prd, afi_t afi,
					safi_t safi, json_object *json);
extern void route_vty_out_detail(struct vty *vty, struct bgp *bgp,
				 struct prefix *p, struct bgp_info *binfo,
				 afi_t afi, safi_t safi,
				 json_object *json_paths);
extern int bgp_show_table_rd(struct vty *vty, struct bgp *bgp, safi_t safi,
			     struct bgp_table *table, struct prefix_rd *prd,
			     enum bgp_show_type type, void *output_arg,
			     u_char use_json);
#endif /* _QUAGGA_BGP_ROUTE_H */
