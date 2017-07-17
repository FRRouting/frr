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

#ifndef QUAGGA_HGP_RFAPI_MONITOR_H
#define QUAGGA_HGP_RFAPI_MONITOR_H

#include "lib/zebra.h"
#include "lib/prefix.h"
#include "lib/table.h"

/*
 * These get attached to the nodes in an import table (using "aggregate" ptr)
 * to indicate which nves are interested in a prefix/target
 */
struct rfapi_monitor_vpn {
	struct rfapi_monitor_vpn *next; /* chain from struct route_node */
	struct rfapi_descriptor *rfd;   /* which NVE requested the route */
	struct prefix p;		/* constant: pfx in original request */
	struct route_node *node;	/* node we're currently attached to */
	uint32_t flags;
#define RFAPI_MON_FLAG_NEEDCALLBACK	0x00000001      /* deferred callback */

	// int				dcount;	/* debugging counter */
	struct thread *timer;
};

struct rfapi_monitor_encap {
	struct rfapi_monitor_encap *next;
	struct rfapi_monitor_encap *prev;
	struct route_node *node; /* VPN node */
	struct bgp_info *bi;     /* VPN bi */
	struct route_node *rn;   /* parent node */
};

struct rfapi_monitor_eth {
	struct rfapi_monitor_eth *next; /* for use in vpn0_queries list */
	struct rfapi_descriptor *rfd;   /* which NVE requested the route */
	struct ethaddr macaddr;
	uint32_t logical_net_id;
	struct thread *timer;
};

/*
 * This is referenced by the "aggregate" field of a route node
 * in an RFAPI import table.
 *
 * node lock/unlock:
 *	- one lock increment for this structure itself
 *	- one lock per chained struct rfapi_monitor_vpn
 *	- one lock for the mon_eth skiplist itself
 *	- one lock per mon_eth skiplist entry
 *	- one lock for the ext skiplist itself
 *	- one lock for each ext skiplist entry
 *		remember to free skiplist when freeing rfapi_it_extra
 *	- one lock per chained struct rfapi_monitor_encap
 *
 */
struct rfapi_it_extra {
	union {
		struct {
			struct rfapi_monitor_vpn *v;
			struct skiplist *idx_rd;  /* RD index */
			struct skiplist *mon_eth; /* ether queries */
			struct {
				/* routes with UN addrs, either cached encap or
				 * Encap TLV */
				int valid_interior_count;

				/* unicast exterior routes, key=bi,
				 * val=allocated prefix */
				struct skiplist *source;
			} e;
		} vpn;
		struct {
			struct rfapi_monitor_encap *e;
		} encap;
	} u;
};

#define RFAPI_IT_EXTRA_GET(rn)                                                 \
	((struct rfapi_it_extra                                                \
		  *)((rn)->aggregate                                           \
			     ? (rn)->aggregate                                 \
			     : (route_lock_node(rn),                           \
				(rn)->aggregate = XCALLOC(                     \
					MTYPE_RFAPI_IT_EXTRA,                  \
					sizeof(struct rfapi_it_extra)))))

#define RFAPI_RDINDEX(rn)                                                      \
	((rn)->aggregate ? RFAPI_IT_EXTRA_GET(rn)->u.vpn.idx_rd : NULL)

#define RFAPI_RDINDEX_W_ALLOC(rn) (RFAPI_IT_EXTRA_GET(rn)->u.vpn.idx_rd)

#define RFAPI_MONITOR_ETH(rn)                                                  \
	((rn)->aggregate ? RFAPI_IT_EXTRA_GET(rn)->u.vpn.mon_eth : NULL)

#define RFAPI_MONITOR_ETH_W_ALLOC(rn) (RFAPI_IT_EXTRA_GET(rn)->u.vpn.mon_eth)

#define RFAPI_MONITOR_VPN(rn)                                                  \
	((rn)->aggregate ? RFAPI_IT_EXTRA_GET(rn)->u.vpn.v : NULL)

#define RFAPI_MONITOR_VPN_W_ALLOC(rn) (RFAPI_IT_EXTRA_GET(rn)->u.vpn.v)

#define RFAPI_MONITOR_ENCAP(rn)                                                \
	((rn)->aggregate ? RFAPI_IT_EXTRA_GET(rn)->u.encap.e : NULL)

#define RFAPI_MONITOR_ENCAP_W_ALLOC(rn) (RFAPI_IT_EXTRA_GET(rn)->u.encap.e)

#define RFAPI_MONITOR_EXTERIOR(rn) (&(RFAPI_IT_EXTRA_GET(rn)->u.vpn.e))

#define RFAPI_HAS_MONITOR_EXTERIOR(rn)                                         \
	(rn && rn->aggregate                                                   \
	 && ((struct rfapi_it_extra *)(rn->aggregate))->u.vpn.e.source         \
	 && !skiplist_first(((struct rfapi_it_extra *)(rn->aggregate))         \
				    ->u.vpn.e.source,                          \
			    NULL, NULL))

extern void rfapiMonitorLoopCheck(struct rfapi_monitor_vpn *mchain);

extern void rfapiMonitorCleanCheck(struct bgp *bgp);

extern void rfapiMonitorCheckAttachAllowed(void);

extern void rfapiMonitorExtraFlush(safi_t safi, struct route_node *rn);

extern struct route_node *
rfapiMonitorGetAttachNode(struct rfapi_descriptor *rfd, struct prefix *p);

extern void rfapiMonitorAttachImportHd(struct rfapi_descriptor *rfd);

extern struct route_node *rfapiMonitorAdd(struct bgp *bgp,
					  struct rfapi_descriptor *rfd,
					  struct prefix *p);

extern void rfapiMonitorDetachImportHd(struct rfapi_descriptor *rfd);

extern void rfapiMonitorDel(struct bgp *bgp, struct rfapi_descriptor *rfd,
			    struct prefix *p);

extern int rfapiMonitorDelHd(struct rfapi_descriptor *rfd);

extern void rfapiMonitorCallbacksOff(struct bgp *bgp);

extern void rfapiMonitorCallbacksOn(struct bgp *bgp);

extern void rfapiMonitorResponseRemovalOff(struct bgp *bgp);

extern void rfapiMonitorResponseRemovalOn(struct bgp *bgp);

extern void rfapiMonitorExtraPrune(safi_t safi, struct route_node *rn);

extern void rfapiMonitorTimersRestart(struct rfapi_descriptor *rfd,
				      struct prefix *p);

extern void rfapiMonitorItNodeChanged(struct rfapi_import_table *import_table,
				      struct route_node *it_node,
				      struct rfapi_monitor_vpn *monitor_list);

extern void rfapiMonitorMovedUp(struct rfapi_import_table *import_table,
				struct route_node *old_node,
				struct route_node *new_node,
				struct rfapi_monitor_vpn *monitor_list);

extern struct route_node *rfapiMonitorEthAdd(struct bgp *bgp,
					     struct rfapi_descriptor *rfd,
					     struct ethaddr *macaddr,
					     uint32_t logical_net_id);

extern void rfapiMonitorEthDel(struct bgp *bgp, struct rfapi_descriptor *rfd,
			       struct ethaddr *macaddr,
			       uint32_t logical_net_id);

#endif /* QUAGGA_HGP_RFAPI_MONITOR_H */
