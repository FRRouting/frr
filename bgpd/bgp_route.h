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

#include <stdbool.h>

#include "hook.h"
#include "queue.h"
#include "nexthop.h"
#include "bgp_table.h"
#include "bgp_addpath_types.h"

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
	bgp_show_type_lcommunity_exact,
	bgp_show_type_lcommunity_list,
	bgp_show_type_lcommunity_list_exact,
	bgp_show_type_flap_statistics,
	bgp_show_type_flap_neighbor,
	bgp_show_type_dampend_paths,
	bgp_show_type_damp_neighbor,
	bgp_show_type_detail,
};

enum bgp_show_adj_route_type {
	bgp_show_adj_route_advertised,
	bgp_show_adj_route_received,
	bgp_show_adj_route_filtered,
};


#define BGP_SHOW_SCODE_HEADER                                                  \
	"Status codes:  s suppressed, d damped, "                              \
	"h history, * valid, > best, = multipath,\n"                           \
	"               i internal, r RIB-failure, S Stale, R Removed\n"
#define BGP_SHOW_OCODE_HEADER "Origin codes:  i - IGP, e - EGP, ? - incomplete\n\n"
#define BGP_SHOW_NCODE_HEADER "Nexthop codes: @NNN nexthop's vrf id, < announce-nh-self\n"
#define BGP_SHOW_HEADER "   Network          Next Hop            Metric LocPrf Weight Path\n"

/* Maximum number of labels we can process or send with a prefix. We
 * really do only 1 for MPLS (BGP-LU) but we can do 2 for EVPN-VxLAN.
 */
#define BGP_MAX_LABELS 2

/* Maximum number of sids we can process or send with a prefix. */
#define BGP_MAX_SIDS 6

/* Error codes for handling NLRI */
#define BGP_NLRI_PARSE_OK 0
#define BGP_NLRI_PARSE_ERROR_PREFIX_OVERFLOW -1
#define BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW -2
#define BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH -3
#define BGP_NLRI_PARSE_ERROR_PACKET_LENGTH -4
#define BGP_NLRI_PARSE_ERROR_LABEL_LENGTH -5
#define BGP_NLRI_PARSE_ERROR_EVPN_MISSING_TYPE -6
#define BGP_NLRI_PARSE_ERROR_EVPN_TYPE2_SIZE -7
#define BGP_NLRI_PARSE_ERROR_EVPN_TYPE3_SIZE -8
#define BGP_NLRI_PARSE_ERROR_EVPN_TYPE4_SIZE -9
#define BGP_NLRI_PARSE_ERROR_EVPN_TYPE5_SIZE -10
#define BGP_NLRI_PARSE_ERROR_FLOWSPEC_IPV6_NOT_SUPPORTED -11
#define BGP_NLRI_PARSE_ERROR_FLOWSPEC_NLRI_SIZELIMIT -12
#define BGP_NLRI_PARSE_ERROR_FLOWSPEC_BAD_FORMAT -13
#define BGP_NLRI_PARSE_ERROR_ADDRESS_FAMILY -14
#define BGP_NLRI_PARSE_ERROR_EVPN_TYPE1_SIZE -15
#define BGP_NLRI_PARSE_ERROR -32

/* MAC-IP/type-2 path_info in the global routing table is linked to the
 * destination ES
 */
struct bgp_path_es_info {
	/* back pointer to the route */
	struct bgp_path_info *pi;
	vni_t vni;
	/* destination ES */
	struct bgp_evpn_es *es;
	/* memory used for linking the path to the destination ES */
	struct listnode es_listnode;
};

/* Ancillary information to struct bgp_path_info,
 * used for uncommonly used data (aggregation, MPLS, etc.)
 * and lazily allocated to save memory.
 */
struct bgp_path_info_extra {
	/* Pointer to dampening structure.  */
	struct bgp_damp_info *damp_info;

	/* This route is suppressed with aggregation.  */
	int suppress;

	/* Nexthop reachability check.  */
	uint32_t igpmetric;

	/* MPLS label(s) - VNI(s) for EVPN-VxLAN  */
	mpls_label_t label[BGP_MAX_LABELS];
	uint32_t num_labels;

	/* af specific flags */
	uint16_t af_flags;
#define BGP_EVPN_MACIP_TYPE_SVI_IP (1 << 0)

	/* SRv6 SID(s) for SRv6-VPN */
	struct in6_addr sid[BGP_MAX_SIDS];
	uint32_t num_sids;

#ifdef ENABLE_BGP_VNC
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
			uint8_t un_family; /* family of cached un address, 0 if
					     unset */
			union {
				struct in_addr addr4;
				struct in6_addr addr6;
			} un; /* cached un address */
			time_t create_time;
			struct prefix aux_prefix; /* AFI_L2VPN: the IP addr,
						     if family set */
		} import;

	} vnc;
#endif

	/* For imported routes into a VNI (or VRF), this points to the parent.
	 */
	void *parent;

	/*
	 * Some tunnelish parameters follow. Maybe consolidate into an
	 * internal tunnel structure?
	 */

	/*
	 * Original bgp instance for imported routes. Needed for:
	 * 1. Find all routes from a specific vrf for deletion
	 * 2. vrf context of original nexthop
	 *
	 * Store pointer to bgp instance rather than bgp->vrf_id because
	 * bgp->vrf_id is not always valid (or may change?).
	 *
	 * Set to NULL if route is not imported from another bgp instance.
	 */
	struct bgp *bgp_orig;

	/*
	 * Nexthop in context of original bgp instance. Needed
	 * for label resolution of core mpls routes exported to a vrf.
	 * Set nexthop_orig.family to 0 if not valid.
	 */
	struct prefix nexthop_orig;
	/* presence of FS pbr firewall based entry */
	struct list *bgp_fs_pbr;
	/* presence of FS pbr iprule based entry */
	struct list *bgp_fs_iprule;
	/* Destination Ethernet Segment links for EVPN MH */
	struct bgp_path_es_info *es_info;
};

struct bgp_path_info {
	/* For linked list. */
	struct bgp_path_info *next;
	struct bgp_path_info *prev;

	/* For nexthop linked list */
	LIST_ENTRY(bgp_path_info) nh_thread;

	/* Back pointer to the prefix node */
	struct bgp_node *net;

	/* Back pointer to the nexthop structure */
	struct bgp_nexthop_cache *nexthop;

	/* Peer structure.  */
	struct peer *peer;

	/* Attribute structure.  */
	struct attr *attr;

	/* Extra information */
	struct bgp_path_info_extra *extra;


	/* Multipath information */
	struct bgp_path_info_mpath *mpath;

	/* Uptime.  */
	time_t uptime;

	/* reference count */
	int lock;

	/* BGP information status.  */
	uint16_t flags;
#define BGP_PATH_IGP_CHANGED (1 << 0)
#define BGP_PATH_DAMPED (1 << 1)
#define BGP_PATH_HISTORY (1 << 2)
#define BGP_PATH_SELECTED (1 << 3)
#define BGP_PATH_VALID (1 << 4)
#define BGP_PATH_ATTR_CHANGED (1 << 5)
#define BGP_PATH_DMED_CHECK (1 << 6)
#define BGP_PATH_DMED_SELECTED (1 << 7)
#define BGP_PATH_STALE (1 << 8)
#define BGP_PATH_REMOVED (1 << 9)
#define BGP_PATH_COUNTED (1 << 10)
#define BGP_PATH_MULTIPATH (1 << 11)
#define BGP_PATH_MULTIPATH_CHG (1 << 12)
#define BGP_PATH_RIB_ATTR_CHG (1 << 13)
#define BGP_PATH_ANNC_NH_SELF (1 << 14)
#define BGP_PATH_LINK_BW_CHG (1 << 15)

	/* BGP route type.  This can be static, RIP, OSPF, BGP etc.  */
	uint8_t type;

	/* When above type is BGP.  This sub type specify BGP sub type
	   information.  */
	uint8_t sub_type;
#define BGP_ROUTE_NORMAL       0
#define BGP_ROUTE_STATIC       1
#define BGP_ROUTE_AGGREGATE    2
#define BGP_ROUTE_REDISTRIBUTE 3
#ifdef ENABLE_BGP_VNC
# define BGP_ROUTE_RFP          4
#endif
#define BGP_ROUTE_IMPORTED     5        /* from another bgp instance/safi */

	unsigned short instance;

	/* Addpath identifiers */
	uint32_t addpath_rx_id;
	struct bgp_addpath_info_data tx_addpath;
};

/* Structure used in BGP path selection */
struct bgp_path_info_pair {
	struct bgp_path_info *old;
	struct bgp_path_info *new;
};

/* BGP static route configuration. */
struct bgp_static {
	/* Backdoor configuration.  */
	int backdoor;

	/* Label index configuration; applies to LU prefixes. */
	uint32_t label_index;
#define BGP_INVALID_LABEL_INDEX   0xFFFFFFFF

	/* Import check status.  */
	uint8_t valid;

	/* IGP metric. */
	uint32_t igpmetric;

	/* IGP nexthop. */
	struct in_addr igpnexthop;

	/* Atomic set reference count (ie cause of pathlimit) */
	uint32_t atomic;

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
	esi_t *eth_s_id;
	struct ethaddr *router_mac;
	uint16_t encap_tunneltype;
	struct prefix gatewayIp;
};

/* Aggreagete address:
 *
 *  advertise-map  Set condition to advertise attribute
 *  as-set         Generate AS set path information
 *  attribute-map  Set attributes of aggregate
 *  route-map      Set parameters of aggregate
 *  summary-only   Filter more specific routes from updates
 *  suppress-map   Conditionally filter more specific routes from updates
 *  <cr>
 */
struct bgp_aggregate {
	/* Summary-only flag. */
	uint8_t summary_only;

	/* AS set generation. */
	uint8_t as_set;

	/* Route-map for aggregated route. */
	struct {
		char *name;
		struct route_map *map;
	} rmap;

	/* Suppress-count. */
	unsigned long count;

	/* Count of routes of origin type incomplete under this aggregate. */
	unsigned long incomplete_origin_count;

	/* Count of routes of origin type egp under this aggregate. */
	unsigned long egp_origin_count;

	/* Optional modify flag to override ORIGIN */
	uint8_t origin;

	/* Hash containing the communities of all the
	 * routes under this aggregate.
	 */
	struct hash *community_hash;

	/* Hash containing the extended communities of all the
	 * routes under this aggregate.
	 */
	struct hash *ecommunity_hash;

	/* Hash containing the large communities of all the
	 * routes under this aggregate.
	 */
	struct hash *lcommunity_hash;

	/* Hash containing the AS-Path of all the
	 * routes under this aggregate.
	 */
	struct hash *aspath_hash;

	/* Aggregate route's community. */
	struct community *community;

	/* Aggregate route's extended community. */
	struct ecommunity *ecommunity;

	/* Aggregate route's large community. */
	struct lcommunity *lcommunity;

	/* Aggregate route's as-path. */
	struct aspath *aspath;

	/* SAFI configuration. */
	safi_t safi;
};

#define BGP_NEXTHOP_AFI_FROM_NHLEN(nhlen)                                      \
	((nhlen) < IPV4_MAX_BYTELEN                                            \
		 ? 0                                                           \
		 : ((nhlen) < IPV6_MAX_BYTELEN ? AFI_IP : AFI_IP6))

#define BGP_ATTR_NEXTHOP_AFI_IP6(attr)                                         \
	(!CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP))             \
	 && ((attr)->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL              \
	     || (attr)->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL    \
	     || (attr)->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV6_GLOBAL          \
	     || (attr)->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL))
#define BGP_PATH_COUNTABLE(BI)                                                 \
	(!CHECK_FLAG((BI)->flags, BGP_PATH_HISTORY)                            \
	 && !CHECK_FLAG((BI)->flags, BGP_PATH_REMOVED))

/* Flags which indicate a route is unuseable in some form */
#define BGP_PATH_UNUSEABLE                                                     \
	(BGP_PATH_HISTORY | BGP_PATH_DAMPED | BGP_PATH_REMOVED)
/* Macro to check BGP information is alive or not.  Sadly,
 * not equivalent to just checking previous, because of the
 * sense of the additional VALID flag.
 */
#define BGP_PATH_HOLDDOWN(BI)                                                  \
	(!CHECK_FLAG((BI)->flags, BGP_PATH_VALID)                              \
	 || CHECK_FLAG((BI)->flags, BGP_PATH_UNUSEABLE))

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

enum bgp_path_type {
	BGP_PATH_SHOW_ALL,
	BGP_PATH_SHOW_BESTPATH,
	BGP_PATH_SHOW_MULTIPATH
};

static inline void bgp_bump_version(struct bgp_node *node)
{
	node->version = bgp_table_next_version(bgp_node_table(node));
}

static inline int bgp_fibupd_safi(safi_t safi)
{
	if (safi == SAFI_UNICAST || safi == SAFI_MULTICAST
	    || safi == SAFI_LABELED_UNICAST
	    || safi == SAFI_FLOWSPEC)
		return 1;
	return 0;
}

/* Flag if the route path's family matches params. */
static inline bool is_pi_family_matching(struct bgp_path_info *pi,
					 afi_t afi, safi_t safi)
{
	struct bgp_table *table;
	struct bgp_node *rn;

	rn = pi->net;
	if (!rn)
		return false;
	table = bgp_node_table(rn);
	if (table &&
	    table->afi == afi &&
	    table->safi == safi)
		return true;
	return false;
}

static inline void prep_for_rmap_apply(struct bgp_path_info *dst_pi,
				       struct bgp_path_info_extra *dst_pie,
				       struct bgp_node *rn,
				       struct bgp_path_info *src_pi,
				       struct peer *peer, struct attr *attr)
{
	memset(dst_pi, 0, sizeof(struct bgp_path_info));
	dst_pi->peer = peer;
	dst_pi->attr = attr;
	dst_pi->net = rn;
	dst_pi->flags = src_pi->flags;
	dst_pi->type = src_pi->type;
	dst_pi->sub_type = src_pi->sub_type;
	dst_pi->mpath = src_pi->mpath;
	if (src_pi->extra) {
		memcpy(dst_pie, src_pi->extra,
		       sizeof(struct bgp_path_info_extra));
		dst_pi->extra = dst_pie;
	}
}

/* called before bgp_process() */
DECLARE_HOOK(bgp_process,
		(struct bgp *bgp, afi_t afi, safi_t safi,
			struct bgp_node *bn, struct peer *peer, bool withdraw),
		(bgp, afi, safi, bn, peer, withdraw))

/* Prototypes. */
extern void bgp_rib_remove(struct bgp_node *rn, struct bgp_path_info *pi,
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
extern bool bgp_outbound_policy_exists(struct peer *, struct bgp_filter *);
extern bool bgp_inbound_policy_exists(struct peer *, struct bgp_filter *);

extern struct bgp_node *bgp_afi_node_get(struct bgp_table *table, afi_t afi,
					 safi_t safi, const struct prefix *p,
					 struct prefix_rd *prd);
extern struct bgp_path_info *bgp_path_info_lock(struct bgp_path_info *path);
extern struct bgp_path_info *bgp_path_info_unlock(struct bgp_path_info *path);
extern void bgp_path_info_add(struct bgp_node *rn, struct bgp_path_info *pi);
extern void bgp_path_info_extra_free(struct bgp_path_info_extra **extra);
extern void bgp_path_info_reap(struct bgp_node *rn, struct bgp_path_info *pi);
extern void bgp_path_info_delete(struct bgp_node *rn, struct bgp_path_info *pi);
extern struct bgp_path_info_extra *
bgp_path_info_extra_get(struct bgp_path_info *path);
extern void bgp_path_info_set_flag(struct bgp_node *rn,
				   struct bgp_path_info *path, uint32_t flag);
extern void bgp_path_info_unset_flag(struct bgp_node *rn,
				     struct bgp_path_info *path, uint32_t flag);
extern void bgp_path_info_path_with_addpath_rx_str(struct bgp_path_info *pi,
						   char *buf);

extern int bgp_nlri_parse_ip(struct peer *, struct attr *, struct bgp_nlri *);

extern bool bgp_maximum_prefix_overflow(struct peer *, afi_t, safi_t, int);

extern void bgp_redistribute_add(struct bgp *bgp, struct prefix *p,
				 const union g_addr *nexthop, ifindex_t ifindex,
				 enum nexthop_types_t nhtype, uint32_t metric,
				 uint8_t type, unsigned short instance,
				 route_tag_t tag);
extern void bgp_redistribute_delete(struct bgp *, struct prefix *, uint8_t,
				    unsigned short);
extern void bgp_redistribute_withdraw(struct bgp *, afi_t, int, unsigned short);

extern void bgp_static_add(struct bgp *);
extern void bgp_static_delete(struct bgp *);
extern void bgp_static_redo_import_check(struct bgp *);
extern void bgp_purge_static_redist_routes(struct bgp *bgp);
extern void bgp_static_update(struct bgp *bgp, const struct prefix *p,
			      struct bgp_static *s, afi_t afi, safi_t safi);
extern void bgp_static_withdraw(struct bgp *bgp, const struct prefix *p,
				afi_t afi, safi_t safi);

extern int bgp_static_set_safi(afi_t afi, safi_t safi, struct vty *vty,
			       const char *, const char *, const char *,
			       const char *, int, const char *, const char *,
			       const char *, const char *);

extern int bgp_static_unset_safi(afi_t afi, safi_t safi, struct vty *,
				 const char *, const char *, const char *, int,
				 const char *, const char *, const char *);

/* this is primarily for MPLS-VPN */
extern int bgp_update(struct peer *peer, const struct prefix *p,
		      uint32_t addpath_id, struct attr *attr,
		      afi_t afi, safi_t safi, int type, int sub_type,
		      struct prefix_rd *prd, mpls_label_t *label,
		      uint32_t num_labels, int soft_reconfig,
		      struct bgp_route_evpn *evpn);
extern int bgp_withdraw(struct peer *peer, const struct prefix *p,
			uint32_t addpath_id, struct attr *attr, afi_t afi,
			safi_t safi, int type, int sub_type,
			struct prefix_rd *prd, mpls_label_t *label,
			uint32_t num_labels, struct bgp_route_evpn *evpn);

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

extern void bgp_aggregate_delete(struct bgp *bgp, const struct prefix *p,
				 afi_t afi, safi_t safi,
				 struct bgp_aggregate *aggregate);
extern void bgp_aggregate_route(struct bgp *bgp, const struct prefix *p,
				afi_t afi, safi_t safi,
				struct bgp_aggregate *aggregate);
extern void bgp_aggregate_increment(struct bgp *bgp, const struct prefix *p,
				    struct bgp_path_info *path, afi_t afi,
				    safi_t safi);
extern void bgp_aggregate_decrement(struct bgp *bgp, const struct prefix *p,
				    struct bgp_path_info *path, afi_t afi,
				    safi_t safi);

extern uint8_t bgp_distance_apply(const struct prefix *p,
				  struct bgp_path_info *path, afi_t afi,
				  safi_t safi, struct bgp *bgp);

extern afi_t bgp_node_afi(struct vty *);
extern safi_t bgp_node_safi(struct vty *);

extern struct bgp_path_info *info_make(int type, int sub_type,
				       unsigned short instance,
				       struct peer *peer, struct attr *attr,
				       struct bgp_node *rn);

extern void route_vty_out(struct vty *vty, const struct prefix *p,
			  struct bgp_path_info *path, int display, safi_t safi,
			  json_object *json_paths);
extern void route_vty_out_tag(struct vty *vty, const struct prefix *p,
			      struct bgp_path_info *path, int display,
			      safi_t safi, json_object *json);
extern void route_vty_out_tmp(struct vty *vty, const struct prefix *p,
			      struct attr *attr, safi_t safi, bool use_json,
			      json_object *json_ar);
extern void route_vty_out_overlay(struct vty *vty, const struct prefix *p,
				  struct bgp_path_info *path, int display,
				  json_object *json);

extern void subgroup_process_announce_selected(struct update_subgroup *subgrp,
					       struct bgp_path_info *selected,
					       struct bgp_node *rn,
					       uint32_t addpath_tx_id);

extern bool subgroup_announce_check(struct bgp_node *rn,
				    struct bgp_path_info *pi,
				    struct update_subgroup *subgrp,
				    const struct prefix *p, struct attr *attr);

extern void bgp_peer_clear_node_queue_drain_immediate(struct peer *peer);
extern void bgp_process_queues_drain_immediate(void);

/* for encap/vpn */
extern struct bgp_node *bgp_afi_node_lookup(struct bgp_table *table, afi_t afi,
					    safi_t safi, const struct prefix *p,
					    struct prefix_rd *prd);
extern void bgp_path_info_restore(struct bgp_node *rn,
				  struct bgp_path_info *path);

extern int bgp_path_info_cmp_compatible(struct bgp *bgp,
					struct bgp_path_info *new,
					struct bgp_path_info *exist,
					char *pfx_buf, afi_t afi, safi_t safi,
					enum bgp_path_selection_reason *reason);
extern void bgp_attr_add_gshut_community(struct attr *attr);

extern void bgp_best_selection(struct bgp *bgp, struct bgp_node *rn,
			       struct bgp_maxpaths_cfg *mpath_cfg,
			       struct bgp_path_info_pair *result, afi_t afi,
			       safi_t safi);
extern void bgp_zebra_clear_route_change_flags(struct bgp_node *rn);
extern bool bgp_zebra_has_route_changed(struct bgp_node *rn,
					struct bgp_path_info *selected);

extern void route_vty_out_detail_header(struct vty *vty, struct bgp *bgp,
					struct bgp_node *rn,
					struct prefix_rd *prd, afi_t afi,
					safi_t safi, json_object *json);
extern void route_vty_out_detail(struct vty *vty, struct bgp *bgp,
				 struct bgp_node *bn,
				 struct bgp_path_info *path,
				 afi_t afi, safi_t safi,
				 json_object *json_paths);
extern int bgp_show_table_rd(struct vty *vty, struct bgp *bgp, safi_t safi,
			     struct bgp_table *table, struct prefix_rd *prd,
			     enum bgp_show_type type, void *output_arg,
			     bool use_json);
extern int bgp_best_path_select_defer(struct bgp *bgp, afi_t afi, safi_t safi);
extern bool bgp_update_martian_nexthop(struct bgp *bgp, afi_t afi, safi_t safi,
				       uint8_t type, uint8_t stype,
				       struct attr *attr, struct bgp_node *rn);
extern int bgp_evpn_path_info_cmp(struct bgp *bgp, struct bgp_path_info *new,
			     struct bgp_path_info *exist, int *paths_eq);
#endif /* _QUAGGA_BGP_ROUTE_H */
