// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP routing information base
 * Copyright (C) 1996, 97, 98, 2000 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_ROUTE_H
#define _QUAGGA_BGP_ROUTE_H

#include <stdbool.h>

#include "hook.h"
#include "queue.h"
#include "nexthop.h"
#include "bgp_table.h"
#include "bgp_addpath_types.h"
#include "bgp_rpki.h"

struct bgp_nexthop_cache;
struct bgp_route_evpn;

enum bgp_show_type {
	bgp_show_type_normal,
	bgp_show_type_regexp,
	bgp_show_type_prefix_list,
	bgp_show_type_access_list,
	bgp_show_type_filter_list,
	bgp_show_type_route_map,
	bgp_show_type_neighbor,
	bgp_show_type_cidr_only,
	bgp_show_type_prefix_longer,
	bgp_show_type_community_alias,
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
	bgp_show_type_rpki,
	bgp_show_type_prefix_version,
	bgp_show_type_self_originated,
};

enum bgp_show_adj_route_type {
	bgp_show_adj_route_advertised,
	bgp_show_adj_route_received,
	bgp_show_adj_route_filtered,
	bgp_show_adj_route_bestpath,
};


#define BGP_SHOW_SCODE_HEADER                                                  \
	"Status codes:  s suppressed, d damped, "                              \
	"h history, u unsorted, * valid, > best, = multipath,\n"               \
	"               i internal, r RIB-failure, S Stale, R Removed\n"
#define BGP_SHOW_OCODE_HEADER                                                  \
	"Origin codes:  i - IGP, e - EGP, ? - incomplete\n"
#define BGP_SHOW_NCODE_HEADER "Nexthop codes: @NNN nexthop's vrf id, < announce-nh-self\n"
#define BGP_SHOW_RPKI_HEADER                                                   \
	"RPKI validation codes: V valid, I invalid, N Not found\n\n"
#define BGP_SHOW_HEADER "     Network          Next Hop            Metric LocPrf Weight Path\n"
#define BGP_SHOW_HEADER_WIDE "     Network                                      Next Hop                                  Metric LocPrf Weight Path\n"

/* Maximum number of sids we can process or send with a prefix. */
#define BGP_MAX_SIDS 6

/* Maximum buffer length for storing BGP best path selection reason */
#define BGP_MAX_SELECTION_REASON_STR_BUF 32

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

/* 1. local MAC-IP/type-2 paths in the VNI routing table are linked to the
 * destination ES
 * 2. remote MAC-IP paths in the global routing table are linked to the
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
	uint8_t flags;
/* Path is linked to the VNI list */
#define BGP_EVPN_PATH_ES_INFO_VNI_LIST (1 << 0)
/* Path is linked to the global list */
#define BGP_EVPN_PATH_ES_INFO_GLOBAL_LIST (1 << 1)
};

/* IP paths imported into the VRF from an EVPN route source
 * are linked to the nexthop/VTEP IP
 */
struct bgp_path_evpn_nh_info {
	/* back pointer to the route */
	struct bgp_path_info *pi;
	struct bgp_evpn_nh *nh;
	/* memory used for linking the path to the nexthop */
	struct listnode nh_listnode;
};

struct bgp_path_mh_info {
	struct bgp_path_es_info *es_info;
	struct bgp_path_evpn_nh_info *nh_info;
};

struct bgp_sid_info {
	struct in6_addr sid;
	uint8_t loc_block_len;
	uint8_t loc_node_len;
	uint8_t func_len;
	uint8_t arg_len;
	uint8_t transposition_len;
	uint8_t transposition_offset;
};

/* new structure for EVPN */
struct bgp_path_info_extra_evpn {
#define BGP_EVPN_MACIP_TYPE_SVI_IP (1 << 0)
	/* af specific flags */
	uint16_t af_flags;
	union {
		struct ethaddr mac; /* MAC set here for VNI IP table */
		struct ipaddr ip;   /* IP set here for VNI MAC table */
	} vni_info;
	/* Destination Ethernet Segment links for EVPN MH */
	struct bgp_path_mh_info *mh_info;
};

/* new structure for flowspec*/
struct bgp_path_info_extra_fs {
	/* presence of FS pbr firewall based entry */
	struct list *bgp_fs_pbr;
	/* presence of FS pbr iprule based entry */
	struct list *bgp_fs_iprule;
};

/* new structure for vrfleak*/
struct bgp_path_info_extra_vrfleak {
	void *parent; /* parent from global table */
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
	 * Original bgp session to know if the session is a
	 * connected EBGP session or not
	 */
	struct peer *peer_orig;
	/*
	 * Nexthop in context of original bgp instance. Needed
	 * for label resolution of core mpls routes exported to a vrf.
	 * Set nexthop_orig.family to 0 if not valid.
	 */
	struct prefix nexthop_orig;
};

#ifdef ENABLE_BGP_VNC
struct bgp_path_info_extra_vnc {
	union {
		struct {
			void *rfapi_handle; /* export: NVE advertising this
					       route */
			struct list *local_nexthops; /* optional, for static
							routes */
		} export;

		struct {
			struct event *timer;
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
};
#endif

/* Ancillary information to struct bgp_path_info,
 * used for uncommonly used data (aggregation, MPLS, etc.)
 * and lazily allocated to save memory.
 */
struct bgp_path_info_extra {
	/* Pointer to dampening structure.  */
	struct bgp_damp_info *damp_info;

	/** List of aggregations that suppress this path. */
	struct list *aggr_suppressors;

	/* Nexthop reachability check.  */
	uint32_t igpmetric;

	/* MPLS label(s) - VNI(s) for EVPN-VxLAN  */
	struct bgp_labels *labels;

	/* timestamp of the rib installation */
	time_t bgp_rib_uptime;

	/*For EVPN*/
	struct bgp_path_info_extra_evpn *evpn;

#ifdef ENABLE_BGP_VNC
	struct bgp_path_info_extra_vnc *vnc;
#endif

	/* For flowspec*/
	struct bgp_path_info_extra_fs *flowspec;

	/* For vrf leaking*/
	struct bgp_path_info_extra_vrfleak *vrfleak;
};

struct bgp_mplsvpn_label_nh {
	/* For nexthop per label linked list */
	LIST_ENTRY(bgp_path_info) label_nh_thread;

	/* Back pointer to the bgp label per nexthop structure */
	struct bgp_label_per_nexthop_cache *label_nexthop_cache;
};

struct bgp_mplsvpn_nh_label_bind {
	/* For mplsvpn nexthop label bind linked list */
	LIST_ENTRY(bgp_path_info) nh_label_bind_thread;

	/* Back pointer to the bgp mplsvpn nexthop label bind structure */
	struct bgp_mplsvpn_nh_label_bind_cache *nh_label_bind_cache;
};

struct bgp_path_info {
	/* For linked list. */
	struct bgp_path_info *next;
	struct bgp_path_info *prev;

	/* For nexthop linked list */
	LIST_ENTRY(bgp_path_info) nh_thread;

	/* Back pointer to the prefix node */
	struct bgp_dest *net;

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
	uint32_t flags;
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
#define BGP_PATH_ACCEPT_OWN (1 << 16)
#define BGP_PATH_MPLSVPN_LABEL_NH (1 << 17)
#define BGP_PATH_MPLSVPN_NH_LABEL_BIND (1 << 18)
#define BGP_PATH_UNSORTED (1 << 19)

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

	enum bgp_path_selection_reason reason;

	/* Addpath identifiers */
	uint32_t addpath_rx_id;
	struct bgp_addpath_info_data tx_addpath;

	union {
		struct bgp_mplsvpn_label_nh blnc;
		struct bgp_mplsvpn_nh_label_bind bmnc;
	} mplsvpn;
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

	uint16_t encap_tunneltype;

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
	char *prd_pretty;

	/* MPLS label.  */
	mpls_label_t label;

	/* EVPN */
	esi_t *eth_s_id;
	struct ethaddr *router_mac;
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

	/* Optional modify flag to override ORIGIN */
	uint8_t origin;

	/** Are there MED mismatches? */
	bool med_mismatched;
	/* MED matching state. */
	/** Did we get the first MED value? */
	bool med_initialized;
	/** Match only equal MED. */
	bool match_med;

	/* Route-map for aggregated route. */
	struct {
		char *name;
		struct route_map *map;
		bool changed;
	} rmap;

	/* Suppress-count. */
	unsigned long count;

	/* Count of routes of origin type incomplete under this aggregate. */
	unsigned long incomplete_origin_count;

	/* Count of routes of origin type egp under this aggregate. */
	unsigned long egp_origin_count;

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

	/** MED value found in current group. */
	uint32_t med_matched_value;

	/**
	 * Test if aggregated address MED of all route match, otherwise
	 * returns `false`. This macro will also return `true` if MED
	 * matching is disabled.
	 */
#define AGGREGATE_MED_VALID(aggregate)                                         \
	(((aggregate)->match_med && !(aggregate)->med_mismatched)              \
	 || !(aggregate)->match_med)

	/** Suppress map route map name (`NULL` when disabled). */
	char *suppress_map_name;
	/** Suppress map route map pointer. */
	struct route_map *suppress_map;
};

#define BGP_NEXTHOP_AFI_FROM_NHLEN(nhlen)                                      \
	((nhlen) < IPV4_MAX_BYTELEN                                            \
		 ? 0                                                           \
		 : ((nhlen) < IPV6_MAX_BYTELEN ? AFI_IP : AFI_IP6))

#define BGP_ATTR_MP_NEXTHOP_LEN_IP6(attr)                                      \
	((attr)->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL ||               \
	 (attr)->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL ||        \
	 (attr)->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV6_GLOBAL ||              \
	 (attr)->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL)

#define BGP_ATTR_NEXTHOP_AFI_IP6(attr)                                         \
	(!CHECK_FLAG(attr->flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP)) &&          \
	 BGP_ATTR_MP_NEXTHOP_LEN_IP6(attr))

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

#define ADVERTISE_MAP_NAME(F)	((F)->advmap.aname)
#define ADVERTISE_MAP(F)	((F)->advmap.amap)

#define ADVERTISE_CONDITION(F)	((F)->advmap.condition)

#define CONDITION_MAP_NAME(F)	((F)->advmap.cname)
#define CONDITION_MAP(F)	((F)->advmap.cmap)

/* path PREFIX (addpath rxid NUMBER) */
#define PATH_ADDPATH_STR_BUFFER PREFIX2STR_BUFFER + 32

#define BGP_PATH_INFO_NUM_LABELS(pi)                                           \
	((pi) && (pi)->extra && (pi)->extra->labels                            \
		 ? (pi)->extra->labels->num_labels                             \
		 : 0)

enum bgp_path_type {
	BGP_PATH_SHOW_ALL,
	BGP_PATH_SHOW_BESTPATH,
	BGP_PATH_SHOW_MULTIPATH
};

static inline void bgp_bump_version(struct bgp_dest *dest)
{
	dest->version = bgp_table_next_version(bgp_dest_table(dest));
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
	struct bgp_dest *dest;

	dest = pi->net;
	if (!dest)
		return false;
	table = bgp_dest_table(dest);
	if (table &&
	    table->afi == afi &&
	    table->safi == safi)
		return true;
	return false;
}

static inline void prep_for_rmap_apply(struct bgp_path_info *dst_pi,
				       struct bgp_path_info_extra *dst_pie,
				       struct bgp_dest *dest,
				       struct bgp_path_info *src_pi,
				       struct peer *peer, struct attr *attr)
{
	memset(dst_pi, 0, sizeof(struct bgp_path_info));
	dst_pi->peer = peer;
	dst_pi->attr = attr;
	dst_pi->net = dest;
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

static inline bool bgp_check_advertise(struct bgp *bgp, struct bgp_dest *dest,
				       safi_t safi)
{
	if (!bgp_fibupd_safi(safi))
		return true;

	return (!(BGP_SUPPRESS_FIB_ENABLED(bgp) &&
		  CHECK_FLAG(dest->flags, BGP_NODE_FIB_INSTALL_PENDING) &&
		 (!bgp_option_check(BGP_OPT_NO_FIB))));
}

/*
 * If we have a fib result and it failed to install( or was withdrawn due
 * to better admin distance we need to send down the wire a withdrawal.
 * This function assumes that bgp_check_advertise was already returned
 * as good to go.
 */
static inline bool bgp_check_withdrawal(struct bgp *bgp, struct bgp_dest *dest,
					safi_t safi)
{
	struct bgp_path_info *pi, *selected = NULL;

	if (!bgp_fibupd_safi(safi) || !BGP_SUPPRESS_FIB_ENABLED(bgp))
		return false;

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)) {
			selected = pi;
			continue;
		}

		if (pi->sub_type != BGP_ROUTE_NORMAL)
			return true;
	}

	/*
	 * pi is selected and bgp is dealing with a static route
	 * ( ie a network statement of some sort ).  FIB installed
	 * is irrelevant
	 *
	 * I am not sure what the above for loop is wanted in this
	 * manner at this point.  But I do know that if I have
	 * a static route that is selected and it's the one
	 * being checked for should I withdrawal we do not
	 * want to withdraw the route on installation :)
	 */
	if (selected && selected->sub_type == BGP_ROUTE_STATIC)
		return false;

	if (CHECK_FLAG(dest->flags, BGP_NODE_FIB_INSTALLED))
		return false;

	return true;
}

/* called before bgp_process() */
DECLARE_HOOK(bgp_process,
	     (struct bgp *bgp, afi_t afi, safi_t safi, struct bgp_dest *bn,
	      struct peer *peer, bool withdraw),
	     (bgp, afi, safi, bn, peer, withdraw));

/* called when a route is updated in the rib */
DECLARE_HOOK(bgp_route_update,
	     (struct bgp *bgp, afi_t afi, safi_t safi, struct bgp_dest *bn,
	      struct bgp_path_info *old_route, struct bgp_path_info *new_route),
	     (bgp, afi, safi, bn, old_route, new_route));

/* BGP show options */
#define BGP_SHOW_OPT_JSON (1 << 0)
#define BGP_SHOW_OPT_WIDE (1 << 1)
#define BGP_SHOW_OPT_AFI_ALL (1 << 2)
#define BGP_SHOW_OPT_AFI_IP (1 << 3)
#define BGP_SHOW_OPT_AFI_IP6 (1 << 4)
#define BGP_SHOW_OPT_ESTABLISHED (1 << 5)
#define BGP_SHOW_OPT_FAILED (1 << 6)
#define BGP_SHOW_OPT_JSON_DETAIL (1 << 7)
#define BGP_SHOW_OPT_TERSE (1 << 8)
#define BGP_SHOW_OPT_ROUTES_DETAIL (1 << 9)

/* Prototypes. */
extern void bgp_rib_remove(struct bgp_dest *dest, struct bgp_path_info *pi,
			   struct peer *peer, afi_t afi, safi_t safi);
extern void bgp_process_queue_init(struct bgp *bgp);
extern void bgp_route_init(void);
extern void bgp_route_finish(void);
extern void bgp_cleanup_routes(struct bgp *);
extern void bgp_free_aggregate_info(struct bgp_aggregate *aggregate);
extern void bgp_announce_route(struct peer *peer, afi_t afi, safi_t safi,
			       bool force);
extern void bgp_stop_announce_route_timer(struct peer_af *paf);
extern void bgp_announce_route_all(struct peer *);
extern void bgp_default_originate(struct peer *peer, afi_t afi, safi_t safi,
				  bool withdraw);
extern void bgp_soft_reconfig_table_task_cancel(const struct bgp *bgp,
						const struct bgp_table *table,
						const struct peer *peer);

/*
 * If this peer is configured for soft reconfig in then do the work
 * and return true.  If it is not return false; and do nothing
 */
extern bool bgp_soft_reconfig_in(struct peer *peer, afi_t afi, safi_t safi);
extern void bgp_clear_route(struct peer *, afi_t, safi_t);
extern void bgp_clear_route_all(struct peer *);
extern void bgp_clear_adj_in(struct peer *, afi_t, safi_t);
extern void bgp_clear_stale_route(struct peer *, afi_t, safi_t);
extern void bgp_set_stale_route(struct peer *peer, afi_t afi, safi_t safi);
extern bool bgp_outbound_policy_exists(struct peer *, struct bgp_filter *);
extern bool bgp_inbound_policy_exists(struct peer *, struct bgp_filter *);

extern struct bgp_dest *bgp_afi_node_get(struct bgp_table *table, afi_t afi,
					 safi_t safi, const struct prefix *p,
					 struct prefix_rd *prd);
extern struct bgp_path_info *bgp_path_info_lock(struct bgp_path_info *path);
extern struct bgp_path_info *bgp_path_info_unlock(struct bgp_path_info *path);
extern bool bgp_path_info_nexthop_changed(struct bgp_path_info *pi,
					  struct peer *to, afi_t afi);
extern struct bgp_path_info *
bgp_get_imported_bpi_ultimate(struct bgp_path_info *info);
extern void bgp_path_info_add(struct bgp_dest *dest, struct bgp_path_info *pi);
extern void bgp_path_info_extra_free(struct bgp_path_info_extra **extra);
extern struct bgp_dest *bgp_path_info_reap(struct bgp_dest *dest,
					   struct bgp_path_info *pi);
extern void bgp_path_info_delete(struct bgp_dest *dest,
				 struct bgp_path_info *pi);
extern struct bgp_path_info_extra *
bgp_path_info_extra_get(struct bgp_path_info *path);
extern bool bgp_path_info_has_valid_label(const struct bgp_path_info *path);
extern void bgp_path_info_set_flag(struct bgp_dest *dest,
				   struct bgp_path_info *path, uint32_t flag);
extern void bgp_path_info_unset_flag(struct bgp_dest *dest,
				     struct bgp_path_info *path, uint32_t flag);
extern void bgp_path_info_path_with_addpath_rx_str(struct bgp_path_info *pi,
						   char *buf, size_t buf_len);
extern bool bgp_path_info_labels_same(const struct bgp_path_info *bpi,
				      const mpls_label_t *label, uint32_t n);

extern int bgp_nlri_parse_ip(struct peer *, struct attr *, struct bgp_nlri *);

extern bool bgp_maximum_prefix_overflow(struct peer *, afi_t, safi_t, int);

extern void bgp_redistribute_add(struct bgp *bgp, struct prefix *p,
				 const union g_addr *nexthop, ifindex_t ifindex,
				 enum nexthop_types_t nhtype, uint8_t distance,
				 enum blackhole_type bhtype, uint32_t metric,
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
				afi_t afi, safi_t safi, struct prefix_rd *prd);

extern int bgp_static_set(struct vty *vty, bool negate, const char *ip_str,
			  const char *rd_str, const char *label_str, afi_t afi,
			  safi_t safi, const char *rmap, int backdoor,
			  uint32_t label_index, int evpn_type, const char *esi,
			  const char *gwip, const char *ethtag,
			  const char *routermac);

/* this is primarily for MPLS-VPN */
extern void bgp_update(struct peer *peer, const struct prefix *p,
		       uint32_t addpath_id, struct attr *attr, afi_t afi,
		       safi_t safi, int type, int sub_type,
		       struct prefix_rd *prd, mpls_label_t *label,
		       uint8_t num_labels, int soft_reconfig,
		       struct bgp_route_evpn *evpn);
extern void bgp_withdraw(struct peer *peer, const struct prefix *p,
			 uint32_t addpath_id, afi_t afi, safi_t safi, int type,
			 int sub_type, struct prefix_rd *prd,
			 mpls_label_t *label, uint8_t num_labels,
			 struct bgp_route_evpn *evpn);

/* for bgp_nexthop and bgp_damp */
extern void bgp_process(struct bgp *bgp, struct bgp_dest *dest,
			struct bgp_path_info *pi, afi_t afi, safi_t safi);

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
extern bool bgp_aggregate_route(struct bgp *bgp, const struct prefix *p,
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
				       struct bgp_dest *dest);

extern void route_vty_out(struct vty *vty, const struct prefix *p,
			  struct bgp_path_info *path, int display, safi_t safi,
			  json_object *json_paths, bool wide);
extern void route_vty_out_tag(struct vty *vty, const struct prefix *p,
			      struct bgp_path_info *path, int display,
			      safi_t safi, json_object *json);
extern void route_vty_out_tmp(struct vty *vty, struct bgp *bgp,
			      struct bgp_dest *dest, const struct prefix *p,
			      struct attr *attr, safi_t safi, bool use_json,
			      json_object *json_ar, bool wide);
extern void route_vty_out_overlay(struct vty *vty, const struct prefix *p,
				  struct bgp_path_info *path, int display,
				  json_object *json);

extern void bgp_notify_conditional_adv_scanner(struct update_subgroup *subgrp);

extern void subgroup_process_announce_selected(struct update_subgroup *subgrp,
					       struct bgp_path_info *selected,
					       struct bgp_dest *dest, afi_t afi,
					       safi_t safi,
					       uint32_t addpath_tx_id);

extern bool subgroup_announce_check(struct bgp_dest *dest,
				    struct bgp_path_info *pi,
				    struct update_subgroup *subgrp,
				    const struct prefix *p, struct attr *attr,
				    struct attr *post_attr);

extern void bgp_peer_clear_node_queue_drain_immediate(struct peer *peer);
extern void bgp_process_queues_drain_immediate(void);

/* for encap/vpn */
extern struct bgp_dest *bgp_safi_node_lookup(struct bgp_table *table,
					     safi_t safi,
					     const struct prefix *p,
					     struct prefix_rd *prd);
extern void bgp_path_info_restore(struct bgp_dest *dest,
				  struct bgp_path_info *path);

extern int bgp_path_info_cmp_compatible(struct bgp *bgp,
					struct bgp_path_info *new,
					struct bgp_path_info *exist,
					char *pfx_buf, afi_t afi, safi_t safi,
					enum bgp_path_selection_reason *reason);
extern void bgp_attr_add_llgr_community(struct attr *attr);
extern void bgp_attr_add_gshut_community(struct attr *attr);

extern void bgp_best_selection(struct bgp *bgp, struct bgp_dest *dest,
			       struct bgp_maxpaths_cfg *mpath_cfg,
			       struct bgp_path_info_pair *result, afi_t afi,
			       safi_t safi);
extern void bgp_zebra_clear_route_change_flags(struct bgp_dest *dest);
extern bool bgp_zebra_has_route_changed(struct bgp_path_info *selected);

extern void route_vty_out_detail_header(struct vty *vty, struct bgp *bgp,
					struct bgp_dest *dest,
					const struct prefix *p,
					const struct prefix_rd *prd, afi_t afi,
					safi_t safi, json_object *json,
					bool incremental_print);
extern void route_vty_out_detail(struct vty *vty, struct bgp *bgp,
				 struct bgp_dest *bn, const struct prefix *p,
				 struct bgp_path_info *path, afi_t afi,
				 safi_t safi, enum rpki_states,
				 json_object *json_paths);
extern int bgp_show_table_rd(struct vty *vty, struct bgp *bgp, afi_t afi, safi_t safi,
			     struct bgp_table *table, struct prefix_rd *prd,
			     enum bgp_show_type type, void *output_arg,
			     uint16_t show_flags);
extern void bgp_best_path_select_defer(struct bgp *bgp, afi_t afi, safi_t safi);
extern bool bgp_update_martian_nexthop(struct bgp *bgp, afi_t afi, safi_t safi,
				       uint8_t type, uint8_t stype,
				       struct attr *attr, struct bgp_dest *dest);
extern int bgp_evpn_path_info_cmp(struct bgp *bgp, struct bgp_path_info *new,
				  struct bgp_path_info *exist, int *paths_eq,
				  bool debug);
extern void bgp_aggregate_toggle_suppressed(struct bgp_aggregate *aggregate,
					    struct bgp *bgp,
					    const struct prefix *p, afi_t afi,
					    safi_t safi, bool suppress);
extern void subgroup_announce_reset_nhop(uint8_t family, struct attr *attr);
const char *
bgp_path_selection_reason2str(enum bgp_path_selection_reason reason);
extern bool bgp_path_suppressed(struct bgp_path_info *pi);
extern bool bgp_addpath_encode_rx(struct peer *peer, afi_t afi, safi_t safi);
extern const struct prefix_rd *bgp_rd_from_dest(const struct bgp_dest *dest,
						safi_t safi);
extern void bgp_path_info_free_with_caller(const char *caller,
					   struct bgp_path_info *path);
extern void bgp_path_info_add_with_caller(const char *caller,
					  struct bgp_dest *dest,
					  struct bgp_path_info *pi);
extern void bgp_aggregate_free(struct bgp_aggregate *aggregate);
extern int bgp_path_info_cmp(struct bgp *bgp, struct bgp_path_info *new,
			     struct bgp_path_info *exist, int *paths_eq,
			     struct bgp_maxpaths_cfg *mpath_cfg, bool debug,
			     char *pfx_buf, afi_t afi, safi_t safi,
			     enum bgp_path_selection_reason *reason);
#define bgp_path_info_add(A, B)                                                \
	bgp_path_info_add_with_caller(__func__, (A), (B))
#define bgp_path_info_free(B) bgp_path_info_free_with_caller(__func__, (B))
#endif /* _QUAGGA_BGP_ROUTE_H */
