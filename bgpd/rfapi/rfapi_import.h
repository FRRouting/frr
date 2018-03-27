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
 * File:	rfapi_import.h
 * Purpose:	Handle import of routes from BGP to RFAPI
 */

#ifndef QUAGGA_HGP_RFAPI_IMPORT_H
#define QUAGGA_HGP_RFAPI_IMPORT_H

#include "lib/thread.h"

/*
 * These are per-rt-import-list
 *
 * routes are not segregated by RD - the RD is stored in bgp_info_extra
 * and is needed to determine if two prefixes are the same.
 */
struct rfapi_import_table {
	struct rfapi_import_table *next;
	struct rfapi_nve_group_cfg *rfg;
	struct ecommunity *rt_import_list; /* copied from nve grp */
	int refcount;			   /* nve grps and nves */
	uint32_t l2_logical_net_id;	/* L2 only: EVPN Eth Seg Id */
	struct route_table *imported_vpn[AFI_MAX];
	struct rfapi_monitor_vpn *vpn0_queries[AFI_MAX];
	struct rfapi_monitor_eth *eth0_queries;
	struct route_table *imported_encap[AFI_MAX];
	struct skiplist *monitor_exterior_orphans;
	int local_count[AFI_MAX];
	int remote_count[AFI_MAX];
	int holddown_count[AFI_MAX];
	int imported_count[AFI_MAX];
};

#define RFAPI_LOCAL_BI(bi)                                                     \
	(((bi)->type == ZEBRA_ROUTE_BGP) && ((bi)->sub_type == BGP_ROUTE_RFP))

#define RFAPI_DIRECT_IMPORT_BI(bi)                                             \
	(((bi)->type == ZEBRA_ROUTE_BGP_DIRECT)                                \
	 || ((bi)->type == ZEBRA_ROUTE_BGP_DIRECT_EXT))

#define RFAPI_UPDATE_ITABLE_COUNT(bi, itable, afi, cnt)                        \
	if (RFAPI_LOCAL_BI(bi)) {                                              \
		(itable)->local_count[(afi)] += (cnt);                         \
	} else {                                                               \
		if (RFAPI_DIRECT_IMPORT_BI(bi))                                \
			(itable)->imported_count[(afi)] += (cnt);              \
		else                                                           \
			(itable)->remote_count[(afi)] += (cnt);                \
	}

extern uint8_t rfapiRfpCost(struct attr *attr);

extern void rfapiDebugBacktrace(void);

extern void rfapiCheckRouteCount(void);

/*
 * Print BI in an Import Table
 */
extern void rfapiPrintBi(void *stream, struct bgp_info *bi);

extern void rfapiShowImportTable(void *stream, const char *label,
				 struct route_table *rt, int isvpn);

extern struct rfapi_import_table *
rfapiImportTableRefAdd(struct bgp *bgp, struct ecommunity *rt_import_list,
		       struct rfapi_nve_group_cfg *rfg);

extern void rfapiImportTableRefDelByIt(struct bgp *bgp,
				       struct rfapi_import_table *it_target);


/*
 * Construct an rfapi nexthop list based on the routes attached to
 * the specified node.
 *
 * If there are any routes that do NOT have BGP_INFO_REMOVED set,
 * return those only. If there are ONLY routes with BGP_INFO_REMOVED,
 * then return those, and also include all the non-removed routes from the
 * next less-specific node (i.e., this node's parent) at the end.
 */
extern struct rfapi_next_hop_entry *rfapiRouteNode2NextHopList(
	struct route_node *rn, uint32_t lifetime, /* put into nexthop entries */
	struct rfapi_ip_addr *exclude_vnaddr,     /* omit routes to same NVE */
	struct route_table *rfd_rib_table,   /* preload this NVE rib table */
	struct prefix *pfx_target_original); /* query target */

extern struct rfapi_next_hop_entry *rfapiRouteTable2NextHopList(
	struct route_table *rt,
	uint32_t lifetime,		      /* put into nexthop entries */
	struct rfapi_ip_addr *exclude_vnaddr, /* omit routes to same NVE */
	struct route_table *rfd_rib_table,    /* preload this NVE rib table */
	struct prefix *pfx_target_original);  /* query target */

extern struct rfapi_next_hop_entry *rfapiEthRouteTable2NextHopList(
	uint32_t logical_net_id, struct rfapi_ip_prefix *rprefix,
	uint32_t lifetime,		      /* put into nexthop entries */
	struct rfapi_ip_addr *exclude_vnaddr, /* omit routes to same NVE */
	struct route_table *rib_route_table,  /* preload NVE rib node */
	struct prefix *pfx_target_original);  /* query target */

extern int rfapiEcommunitiesIntersect(struct ecommunity *e1,
				      struct ecommunity *e2);

extern void rfapiCheckRefcount(struct route_node *rn, safi_t safi,
			       int lockoffset);

extern int rfapiHasNonRemovedRoutes(struct route_node *rn);

extern int rfapiProcessDeferredClose(struct thread *t);

extern int rfapiGetUnAddrOfVpnBi(struct bgp_info *bi, struct prefix *p);

extern void rfapiNexthop2Prefix(struct attr *attr, struct prefix *p);

extern void rfapiUnicastNexthop2Prefix(afi_t afi, struct attr *attr,
				       struct prefix *p);

/* Filtered Import Function actions */
#define FIF_ACTION_UPDATE	0
#define FIF_ACTION_WITHDRAW	1
#define FIF_ACTION_KILL		2

extern void rfapiBgpInfoFilteredImportVPN(
	struct rfapi_import_table *import_table, int action, struct peer *peer,
	void *rfd, /* set for looped back routes */
	struct prefix *p,
	struct prefix *aux_prefix, /* AFI_ETHER: optional IP */
	afi_t afi, struct prefix_rd *prd,
	struct attr *attr, /* part of bgp_info */
	uint8_t type,      /* part of bgp_info */
	uint8_t sub_type,  /* part of bgp_info */
	uint32_t *label);  /* part of bgp_info */

extern struct rfapi_next_hop_entry *rfapiEthRouteNode2NextHopList(
	struct route_node *rn, struct rfapi_ip_prefix *rprefix,
	uint32_t lifetime,		      /* put into nexthop entries */
	struct rfapi_ip_addr *exclude_vnaddr, /* omit routes to same NVE */
	struct route_table *rib_route_table,  /* preload NVE rib table */
	struct prefix *pfx_target_original);  /* query target */

extern struct rfapi_import_table *rfapiMacImportTableGetNoAlloc(struct bgp *bgp,
								uint32_t lni);

extern struct rfapi_import_table *rfapiMacImportTableGet(struct bgp *bgp,
							 uint32_t lni);

extern int rfapiGetL2o(struct attr *attr, struct rfapi_l2address_option *l2o);

extern int rfapiEcommunityGetLNI(struct ecommunity *ecom, uint32_t *lni);

extern int rfapiEcommunityGetEthernetTag(struct ecommunity *ecom,
					 uint16_t *tag_id);

/* enable for debugging; disable for performance */
#if 0
#define RFAPI_CHECK_REFCOUNT(rn, safi, lo) rfapiCheckRefcount((rn),(safi),(lo))
#else
#define RFAPI_CHECK_REFCOUNT(rn, safi, lo) {}
#endif

/*------------------------------------------
 * rfapiDeleteRemotePrefixes
 *
 * UI helper: For use by the "clear vnc prefixes" command
 *
 * input:
 *	un			if set, tunnel must match this prefix
 *	vn			if set, nexthop prefix must match this prefix
 *	p			if set, prefix must match this prefix
 *      it                      if set, only look in this import table
 *
 * output
 *	pARcount		number of active routes deleted
 *	pAHcount		number of active nves deleted
 *	pHRcount		number of holddown routes deleted
 *	pHHcount		number of holddown nves deleted
 *
 * return value:
 *	void
 --------------------------------------------*/
extern void rfapiDeleteRemotePrefixes(struct prefix *un, struct prefix *vn,
				      struct prefix *p,
				      struct rfapi_import_table *it,
				      int delete_active, int delete_holddown,
				      uint32_t *pARcount,  /* active routes */
				      uint32_t *pAHcount,  /* active nves */
				      uint32_t *pHRcount,  /* holddown routes */
				      uint32_t *pHHcount); /* holddown nves */

/*------------------------------------------
 * rfapiCountAllItRoutes
 *
 * UI helper: count VRF routes from BGP side
 *
 * input:
 *
 * output
 *	pARcount		count of active routes
 *	pHRcount		count of holddown routes
 *	pIRcount		count of holddown routes
 *
 * return value:
 *	void
 --------------------------------------------*/
extern void rfapiCountAllItRoutes(int *pALRcount, /* active local routes */
				  int *pARRcount, /* active remote routes */
				  int *pHRcount,  /* holddown routes */
				  int *pIRcount); /* direct imported routes */

/*------------------------------------------
 * rfapiGetHolddownFromLifetime
 *
 * calculate holddown value based on lifetime
 *
 * input:
 *     lifetime                lifetime
 *
 * return value:
 *     Holddown value based on lifetime, holddown_factor,
 *     and RFAPI_LIFETIME_INFINITE_WITHDRAW_DELAY
 *
 --------------------------------------------*/
extern uint32_t rfapiGetHolddownFromLifetime(uint32_t lifetime);

#endif /* QUAGGA_HGP_RFAPI_IMPORT_H */
