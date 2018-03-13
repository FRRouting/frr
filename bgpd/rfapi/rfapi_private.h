/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * Internal definitions for RFAPI. Not for use by other code
 */

#ifndef _QUAGGA_BGP_RFAPI_PRIVATE_H
#define _QUAGGA_BGP_RFAPI_PRIVATE_H

#include "lib/linklist.h"
#include "lib/skiplist.h"
#include "lib/workqueue.h"

#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"

#include "rfapi.h"

/*
 * Lists of rfapi_adb. Each rfapi_adb is referenced twice:
 *
 * 1. each is referenced in by_lifetime
 * 2. each is referenced by exactly one of: ipN_by_prefix, ip0_by_ether
 */
struct rfapi_advertised_prefixes {
	struct skiplist *ipN_by_prefix; /* all except 0/32, 0/128 */
	struct skiplist *ip0_by_ether;  /* ip prefix 0/32, 0/128 */
	struct skiplist *by_lifetime;   /* all */
};

struct rfapi_descriptor {
	struct route_node *un_node; /* backref to un table */

	struct rfapi_descriptor *next; /* next vn_addr */

	/* supplied by client */
	struct bgp *bgp; /* from rfp_start_val */
	struct rfapi_ip_addr vn_addr;
	struct rfapi_ip_addr un_addr;
	rfapi_response_cb_t *response_cb; /* override per-bgp response_cb */
	void *cookie;			  /* for callbacks */
	struct rfapi_tunneltype_option default_tunneltype_option;

	/* supplied by matched configuration */
	struct prefix_rd rd;
	struct ecommunity *rt_export_list;
	uint32_t response_lifetime;

	/* list of prefixes currently being advertised by this nve */
	struct rfapi_advertised_prefixes advertised;

	time_t open_time;

	uint32_t max_prefix_lifetime;
	uint32_t min_prefix_lifetime;

	/* reference to this nve's import table */
	struct rfapi_import_table *import_table;

	uint32_t monitor_count;
	struct route_table *mon;  /* rfapi_monitors */
	struct skiplist *mon_eth; /* ethernet monitors */

	/*
	 * rib            RIB as seen by NVE
	 * rib_pending    RIB containing nodes with updated info chains
	 * rsp_times      last time we sent response containing pfx
	 */
	uint32_t rib_prefix_count; /* pfxes with routes */
	struct route_table *rib[AFI_MAX];
	struct route_table *rib_pending[AFI_MAX];
	struct work_queue *updated_responses_queue;
	struct route_table *rsp_times[AFI_MAX];

	uint32_t rsp_counter;	 /* dedup initial rsp */
	time_t rsp_time;	      /* dedup initial rsp */
	time_t ftd_last_allowed_time; /* FTD filter */

	unsigned int stat_count_nh_reachable;
	unsigned int stat_count_nh_removal;

	/*
	 * points to the original nve group structure that matched
	 * when this nve_descriptor was created. We use this pointer
	 * in rfapi_close() to find the nve group structure and
	 * delete its reference back to us.
	 *
	 * If the nve group structure is deleted (via configuration
	 * change) while this nve_descriptor exists, this rfg pointer
	 * will be set to NULL.
	 */
	struct rfapi_nve_group_cfg *rfg;

	/*
	 * This ~7kB structure is here to permit multiple routes for
	 * a prefix to be injected to BGP. There are at least two
	 * situations where such conditions obtain:
	 *
	 * When an VNC route is exported to BGP on behalf of the set of
	 * NVEs that belong to the export NVE group, it is replicated
	 * so that there is one route per NVE (and the route's nexthop
	 * is the NVE's VN address).
	 *
	 * Each of these routes being injected to BGP must have a distinct
	 * peer pointer (otherwise, if they have the same peer pointer, each
	 * route will be considered an implicit waithdraw of the previous
	 * route injected from that peer, and the new route will replace
	 * rather than augment the old one(s)).
	 */
	struct peer *peer;

	uint32_t flags;
#define RFAPI_HD_FLAG_CALLBACK_SCHEDULED_AFI_IP		0x00000001
#define RFAPI_HD_FLAG_CALLBACK_SCHEDULED_AFI_IP6	0x00000002
#define RFAPI_HD_FLAG_CALLBACK_SCHEDULED_AFI_L2VPN	0x00000004
#define RFAPI_HD_FLAG_PROVISIONAL			0x00000008
#define RFAPI_HD_FLAG_CLOSING_ADMINISTRATIVELY		0x00000010
#define RFAPI_HD_FLAG_IS_VRF             		0x00000012
};

#define RFAPI_QUEUED_FLAG(afi)                                                      \
	(((afi) == AFI_IP)                                                          \
		 ? RFAPI_HD_FLAG_CALLBACK_SCHEDULED_AFI_IP                          \
		 : (((afi) == AFI_IP6)                                              \
			    ? RFAPI_HD_FLAG_CALLBACK_SCHEDULED_AFI_IP6              \
			    : (((afi) == AFI_L2VPN)                                 \
				       ? RFAPI_HD_FLAG_CALLBACK_SCHEDULED_AFI_L2VPN \
				       : (assert(0), 0))))


struct rfapi_global_stats {
	time_t last_reset;
	unsigned int max_descriptors;

	unsigned int count_unknown_nves;

	unsigned int count_queries;
	unsigned int count_queries_failed;

	unsigned int max_responses; /* semantics? */

	unsigned int count_registrations;
	unsigned int count_registrations_failed;

	unsigned int count_updated_response_updates;
	unsigned int count_updated_response_deletes;
};

/*
 * There is one of these per BGP instance.
 *
 * Radix tree is indexed by un address; follow chain and
 * check vn address to get exact match.
 */
struct rfapi {
	struct route_table *un[AFI_MAX];
	struct rfapi_import_table *imports; /* IPv4, IPv6 */
	struct list descriptors;	    /* debug & resolve-nve imports */

	struct rfapi_global_stats stat;

	/*
	 * callbacks into RFP, set at startup time (bgp_rfapi_new() gets
	 * values from rfp_start()) or via rfapi_rfp_set_cb_methods()
	 * (otherwise NULL). Note that the response_cb method can also
	 * be overridden per-rfd (currently used only for debug/test scenarios)
	 */
	struct rfapi_rfp_cb_methods rfp_methods;

	/*
	 * Import tables for Ethernet over IPSEC
	 *
	 * The skiplist keys are LNIs. Values are pointers
	 * to struct rfapi_import_table.
	 */
	struct skiplist *import_mac; /* L2 */

	/*
	 * when exporting plain routes ("registered-nve" mode) to
	 * bgp unicast or zebra, we need to keep track of information
	 * related to expiring the routes according to the VNC lifetime
	 */
	struct route_table *rt_export_bgp[AFI_MAX];
	struct route_table *rt_export_zebra[AFI_MAX];

	/*
	 * For VNC->BGP unicast exports in CE mode, we need a
	 * routing table that collects all of the VPN routes
	 * in a single tree. The VPN rib is split up according
	 * to RD first, so we can't use that. This is an import
	 * table that matches all RTs.
	 */
	struct rfapi_import_table *it_ce;

	/*
	 * when importing bgp-direct routes in resolve-nve mode,
	 * this list maps unicast route nexthops to their bgp_infos
	 * in the unicast table
	 */
	struct skiplist *resolve_nve_nexthop;

	/*
	 * Descriptors for which rfapi_close() was called during a callback.
	 * They will be closed after the callback finishes.
	 */
	struct work_queue *deferred_close_q;

	/*
	 * For "show vnc responses"
	 */
	uint32_t response_immediate_count;
	uint32_t response_updated_count;
	uint32_t monitor_count;

	uint32_t rib_prefix_count_total;
	uint32_t rib_prefix_count_total_max;

	uint32_t flags;
#define RFAPI_INCALLBACK	0x00000001
	void *rfp; /* from rfp_start */
};

#define RFAPI_RIB_PREFIX_COUNT_INCR(rfd, rfapi)                                \
	do {                                                                   \
		++(rfd)->rib_prefix_count;                                     \
		++(rfapi)->rib_prefix_count_total;                             \
		if ((rfapi)->rib_prefix_count_total                            \
		    > (rfapi)->rib_prefix_count_total_max)                     \
			++(rfapi)->rib_prefix_count_total_max;                 \
	} while (0)

#define RFAPI_RIB_PREFIX_COUNT_DECR(rfd, rfapi)                                \
	do {                                                                   \
		--(rfd)->rib_prefix_count;                                     \
		--(rfapi)->rib_prefix_count_total;                             \
	} while (0)

#define RFAPI_0_PREFIX(prefix)                                                 \
	((((prefix)->family == AF_INET)                                        \
		  ? (prefix)->u.prefix4.s_addr == 0                            \
		  : (((prefix)->family == AF_INET6)                            \
			     ? (IN6_IS_ADDR_UNSPECIFIED(&(prefix)->u.prefix6)) \
			     : 0)))

#define RFAPI_0_ETHERADDR(ea)                                                  \
	(((ea)->octet[0] | (ea)->octet[1] | (ea)->octet[2] | (ea)->octet[3]    \
	  | (ea)->octet[4] | (ea)->octet[5])                                   \
	 == 0)

#define RFAPI_HOST_PREFIX(prefix)                                              \
	(((prefix)->family == AF_INET)                                         \
		 ? ((prefix)->prefixlen == 32)                                 \
		 : (((prefix)->family == AF_INET6)                             \
			    ? ((prefix)->prefixlen == 128)                     \
			    : 0))

extern void rfapiQprefix2Rprefix(struct prefix *qprefix,
				 struct rfapi_ip_prefix *rprefix);

extern int rfapi_find_rfd(struct bgp *bgp, struct rfapi_ip_addr *vn_addr,
			  struct rfapi_ip_addr *un_addr,
			  struct rfapi_descriptor **rfd);

extern void
add_vnc_route(struct rfapi_descriptor *rfd, /* cookie + UN addr for VPN */
	      struct bgp *bgp, int safi, struct prefix *p,
	      struct prefix_rd *prd, struct rfapi_ip_addr *nexthop,
	      uint32_t *local_pref, /* host byte order */
	      uint32_t *lifetime,   /* host byte order */
	      struct bgp_tea_options *rfp_options,
	      struct rfapi_un_option *options_un,
	      struct rfapi_vn_option *options_vn,
	      struct ecommunity *rt_export_list, uint32_t *med, uint32_t *label,
	      uint8_t type, uint8_t sub_type, int flags);
#define RFAPI_AHR_NO_TUNNEL_SUBTLV	0x00000001
#define RFAPI_AHR_RFPOPT_IS_VNCTLV	0x00000002      /* hack! */
#if 0 /* unused? */
#  define RFAPI_AHR_SET_PFX_TO_NEXTHOP	0x00000004
#endif

extern void del_vnc_route(struct rfapi_descriptor *rfd, struct peer *peer,
			  struct bgp *bgp, safi_t safi, struct prefix *p,
			  struct prefix_rd *prd, uint8_t type, uint8_t sub_type,
			  struct rfapi_nexthop *lnh, int kill);

extern int rfapiCliGetPrefixAddr(struct vty *vty, const char *str,
				 struct prefix *p);

extern int rfapiGetVncLifetime(struct attr *attr, uint32_t *lifetime);

extern int rfapiGetTunnelType(struct attr *attr, bgp_encap_types *type);

extern int rfapiGetVncTunnelUnAddr(struct attr *attr, struct prefix *p);

extern int rfapi_reopen(struct rfapi_descriptor *rfd, struct bgp *bgp);

extern void vnc_import_bgp_add_rfp_host_route_mode_resolve_nve(
	struct bgp *bgp, struct rfapi_descriptor *rfd, struct prefix *prefix);

extern void vnc_import_bgp_del_rfp_host_route_mode_resolve_nve(
	struct bgp *bgp, struct rfapi_descriptor *rfd, struct prefix *prefix);

extern void rfapiFreeBgpTeaOptionChain(struct bgp_tea_options *p);

extern struct rfapi_vn_option *rfapiVnOptionsDup(struct rfapi_vn_option *orig);

extern struct rfapi_un_option *rfapiUnOptionsDup(struct rfapi_un_option *orig);

extern struct bgp_tea_options *rfapiOptionsDup(struct bgp_tea_options *orig);

extern int rfapi_ip_addr_cmp(struct rfapi_ip_addr *a1,
			     struct rfapi_ip_addr *a2);

extern uint32_t rfp_cost_to_localpref(uint8_t cost);

extern int rfapi_set_autord_from_vn(struct prefix_rd *rd,
				    struct rfapi_ip_addr *vn);

extern struct rfapi_nexthop *rfapi_nexthop_new(struct rfapi_nexthop *copyme);

extern void rfapi_nexthop_free(void *goner);

extern struct rfapi_vn_option *
rfapi_vn_options_dup(struct rfapi_vn_option *existing);

extern void rfapi_un_options_free(struct rfapi_un_option *goner);

extern void rfapi_vn_options_free(struct rfapi_vn_option *goner);

extern void vnc_add_vrf_opener(struct bgp *bgp,
			       struct rfapi_nve_group_cfg *rfg);
extern void clear_vnc_vrf_closer(struct rfapi_nve_group_cfg *rfg);
/*------------------------------------------
 * rfapi_extract_l2o
 *
 * Find Layer 2 options in an option chain
 *
 * input:
 *	pHop		option chain
 *
 * output:
 *	l2o		layer 2 options extracted
 *
 * return value:
 *	0		OK
 *	1		no options found
 *
 --------------------------------------------*/
extern int rfapi_extract_l2o(
	struct bgp_tea_options *pHop,	/* chain of options */
	struct rfapi_l2address_option *l2o); /* return extracted value */

/*
 * compaitibility to old quagga_time call
 * time_t value in terms of stabilised absolute time.
 * replacement for POSIX time()
 */
extern time_t rfapi_time(time_t *t);

DECLARE_MGROUP(RFAPI)
DECLARE_MTYPE(RFAPI_CFG)
DECLARE_MTYPE(RFAPI_GROUP_CFG)
DECLARE_MTYPE(RFAPI_L2_CFG)
DECLARE_MTYPE(RFAPI_RFP_GROUP_CFG)
DECLARE_MTYPE(RFAPI)
DECLARE_MTYPE(RFAPI_DESC)
DECLARE_MTYPE(RFAPI_IMPORTTABLE)
DECLARE_MTYPE(RFAPI_MONITOR)
DECLARE_MTYPE(RFAPI_MONITOR_ENCAP)
DECLARE_MTYPE(RFAPI_NEXTHOP)
DECLARE_MTYPE(RFAPI_VN_OPTION)
DECLARE_MTYPE(RFAPI_UN_OPTION)
DECLARE_MTYPE(RFAPI_WITHDRAW)
DECLARE_MTYPE(RFAPI_RFG_NAME)
DECLARE_MTYPE(RFAPI_ADB)
DECLARE_MTYPE(RFAPI_ETI)
DECLARE_MTYPE(RFAPI_NVE_ADDR)
DECLARE_MTYPE(RFAPI_PREFIX_BAG)
DECLARE_MTYPE(RFAPI_IT_EXTRA)
DECLARE_MTYPE(RFAPI_INFO)
DECLARE_MTYPE(RFAPI_ADDR)
DECLARE_MTYPE(RFAPI_UPDATED_RESPONSE_QUEUE)
DECLARE_MTYPE(RFAPI_RECENT_DELETE)
DECLARE_MTYPE(RFAPI_L2ADDR_OPT)
DECLARE_MTYPE(RFAPI_AP)
DECLARE_MTYPE(RFAPI_MONITOR_ETH)


/*
 * Caller must supply an already-allocated rfd with the "caller"
 * fields already set (vn_addr, un_addr, callback, cookie)
 * The advertised_prefixes[] array elements should be NULL to
 * have this function set them to newly-allocated radix trees.
 */
extern int rfapi_init_and_open(struct bgp *bgp, struct rfapi_descriptor *rfd,
			       struct rfapi_nve_group_cfg *rfg);

#endif /* _QUAGGA_BGP_RFAPI_PRIVATE_H */
