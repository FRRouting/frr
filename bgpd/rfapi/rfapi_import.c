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
 * File:	rfapi_import.c
 * Purpose:	Handle import of routes from BGP to RFAPI
 */

#include <errno.h>

#include "lib/zebra.h"
#include "lib/prefix.h"
#include "lib/table.h"
#include "lib/vty.h"
#include "lib/memory.h"
#include "lib/log.h"
#include "lib/skiplist.h"
#include "lib/thread.h"
#include "lib/stream.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_mplsvpn.h" /* prefix_rd2str() */
#include "bgpd/bgp_vnc_types.h"
#include "bgpd/bgp_rd.h"

#include "bgpd/rfapi/rfapi.h"
#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#include "bgpd/rfapi/rfapi_backend.h"
#include "bgpd/rfapi/rfapi_import.h"
#include "bgpd/rfapi/rfapi_private.h"
#include "bgpd/rfapi/rfapi_monitor.h"
#include "bgpd/rfapi/rfapi_nve_addr.h"
#include "bgpd/rfapi/rfapi_vty.h"
#include "bgpd/rfapi/vnc_export_bgp.h"
#include "bgpd/rfapi/vnc_export_bgp_p.h"
#include "bgpd/rfapi/vnc_zebra.h"
#include "bgpd/rfapi/vnc_import_bgp.h"
#include "bgpd/rfapi/vnc_import_bgp_p.h"
#include "bgpd/rfapi/rfapi_rib.h"
#include "bgpd/rfapi/rfapi_encap_tlv.h"
#include "bgpd/rfapi/vnc_debug.h"

#ifdef HAVE_GLIBC_BACKTRACE
/* for backtrace and friends */
#include <execinfo.h>
#endif /* HAVE_GLIBC_BACKTRACE */

#undef DEBUG_MONITOR_MOVE_SHORTER
#undef DEBUG_RETURNED_NHL
#undef DEBUG_ROUTE_COUNTERS
#undef DEBUG_ENCAP_MONITOR
#undef DEBUG_L2_EXTRA
#undef DEBUG_IT_NODES
#undef DEBUG_BI_SEARCH

/*
 * Allocated for each withdraw timer instance; freed when the timer
 * expires or is canceled
 */
struct rfapi_withdraw {
	struct rfapi_import_table *import_table;
	struct route_node *node;
	struct bgp_info *info;
	safi_t safi; /* used only for bulk operations */
	/*
	 * For import table node reference count checking (i.e., debugging).
	 * Normally when a timer expires, lockoffset should be 0. However, if
	 * the timer expiration function is called directly (e.g.,
	 * rfapiExpireVpnNow), the node could be locked by a preceding
	 * route_top() or route_next() in a loop, so we need to pass this
	 * value in.
	 */
	int lockoffset;
};

/*
 * DEBUG FUNCTION
 * It's evil and fiendish. It's compiler-dependent.
 * ? Might need LDFLAGS -rdynamic to produce all function names
 */
void rfapiDebugBacktrace(void)
{
#ifdef HAVE_GLIBC_BACKTRACE
#define RFAPI_DEBUG_BACKTRACE_NENTRIES	200
	void *buf[RFAPI_DEBUG_BACKTRACE_NENTRIES];
	char **syms;
	size_t i;
	size_t size;

	size = backtrace(buf, RFAPI_DEBUG_BACKTRACE_NENTRIES);
	syms = backtrace_symbols(buf, size);

	for (i = 0; i < size && i < RFAPI_DEBUG_BACKTRACE_NENTRIES; ++i) {
		vnc_zlog_debug_verbose("backtrace[%2zu]: %s", i, syms[i]);
	}

	free(syms);
#else
#endif
}

/*
 * DEBUG FUNCTION
 * Count remote routes and compare with actively-maintained values.
 * Abort if they disagree.
 */
void rfapiCheckRouteCount()
{
	struct bgp *bgp = bgp_get_default();
	struct rfapi *h;
	struct rfapi_import_table *it;
	afi_t afi;

	assert(bgp);

	h = bgp->rfapi;
	assert(h);

	for (it = h->imports; it; it = it->next) {
		for (afi = AFI_IP; afi < AFI_MAX; ++afi) {

			struct route_table *rt;
			struct route_node *rn;

			int holddown_count = 0;
			int local_count = 0;
			int imported_count = 0;
			int remote_count = 0;

			rt = it->imported_vpn[afi];

			for (rn = route_top(rt); rn; rn = route_next(rn)) {
				struct bgp_info *bi;
				struct bgp_info *next;

				for (bi = rn->info; bi; bi = next) {
					next = bi->next;

					if (CHECK_FLAG(bi->flags,
						       BGP_INFO_REMOVED)) {
						++holddown_count;

					} else {
						if (RFAPI_LOCAL_BI(bi)) {
							++local_count;
						} else {
							if (RFAPI_DIRECT_IMPORT_BI(
								    bi)) {
								++imported_count;
							} else {
								++remote_count;
							}
						}
					}
				}
			}

			if (it->holddown_count[afi] != holddown_count) {
				vnc_zlog_debug_verbose(
					"%s: it->holddown_count %d != holddown_count %d",
					__func__, it->holddown_count[afi],
					holddown_count);
				assert(0);
			}
			if (it->remote_count[afi] != remote_count) {
				vnc_zlog_debug_verbose(
					"%s: it->remote_count %d != remote_count %d",
					__func__, it->remote_count[afi],
					remote_count);
				assert(0);
			}
			if (it->imported_count[afi] != imported_count) {
				vnc_zlog_debug_verbose(
					"%s: it->imported_count %d != imported_count %d",
					__func__, it->imported_count[afi],
					imported_count);
				assert(0);
			}
		}
	}
}

#if DEBUG_ROUTE_COUNTERS
#define VNC_ITRCCK do {rfapiCheckRouteCount();} while (0)
#else
#define VNC_ITRCCK
#endif

/*
 * Validate reference count for a node in an import table
 *
 * Normally lockoffset is 0 for nodes in quiescent state. However,
 * route_unlock_node will delete the node if it is called when
 * node->lock == 1, and we have to validate the refcount before
 * the node is deleted. In this case, we specify lockoffset 1.
 */
void rfapiCheckRefcount(struct route_node *rn, safi_t safi, int lockoffset)
{
	unsigned int count_bi = 0;
	unsigned int count_monitor = 0;
	struct bgp_info *bi;
	struct rfapi_monitor_encap *hme;
	struct rfapi_monitor_vpn *hmv;

	for (bi = rn->info; bi; bi = bi->next)
		++count_bi;


	if (rn->aggregate) {
		++count_monitor; /* rfapi_it_extra */

		switch (safi) {
			void *cursor;
			int rc;

		case SAFI_ENCAP:
			for (hme = RFAPI_MONITOR_ENCAP(rn); hme;
			     hme = hme->next)
				++count_monitor;
			break;

		case SAFI_MPLS_VPN:

			for (hmv = RFAPI_MONITOR_VPN(rn); hmv; hmv = hmv->next)
				++count_monitor;

			if (RFAPI_MONITOR_EXTERIOR(rn)->source) {
				++count_monitor; /* sl */
				cursor = NULL;
				for (rc = skiplist_next(
					     RFAPI_MONITOR_EXTERIOR(rn)->source,
					     NULL, NULL, &cursor);
				     !rc;
				     rc = skiplist_next(
					     RFAPI_MONITOR_EXTERIOR(rn)->source,
					     NULL, NULL, &cursor)) {

					++count_monitor; /* sl entry */
				}
			}
			break;

		default:
			assert(0);
		}
	}

	if (count_bi + count_monitor + lockoffset != rn->lock) {
		vnc_zlog_debug_verbose(
			"%s: count_bi=%d, count_monitor=%d, lockoffset=%d, rn->lock=%d",
			__func__, count_bi, count_monitor, lockoffset,
			rn->lock);
		assert(0);
	}
}

/*
 * Perform deferred rfapi_close operations that were queued
 * during callbacks.
 */
static wq_item_status rfapi_deferred_close_workfunc(struct work_queue *q,
						    void *data)
{
	struct rfapi_descriptor *rfd = data;
	struct rfapi *h = q->spec.data;

	assert(!(h->flags & RFAPI_INCALLBACK));
	rfapi_close(rfd);
	vnc_zlog_debug_verbose("%s: completed deferred close on handle %p",
			       __func__, rfd);
	return WQ_SUCCESS;
}

/*
 * Extract layer 2 option from Encap TLVS in BGP attrs
 */
int rfapiGetL2o(struct attr *attr, struct rfapi_l2address_option *l2o)
{
	if (attr) {

		struct bgp_attr_encap_subtlv *pEncap;

		for (pEncap = attr->vnc_subtlvs; pEncap;
		     pEncap = pEncap->next) {

			if (pEncap->type == BGP_VNC_SUBTLV_TYPE_RFPOPTION) {
				if (pEncap->value[0]
				    == RFAPI_VN_OPTION_TYPE_L2ADDR) {

					if (pEncap->value[1] == 14) {
						memcpy(l2o->macaddr.octet,
						       pEncap->value + 2,
						       ETH_ALEN);
						l2o->label =
							((pEncap->value[10]
							  >> 4)
							 & 0x0f)
							+ ((pEncap->value[9]
							    << 4)
							   & 0xff0)
							+ ((pEncap->value[8]
							    << 12)
							   & 0xff000);

						l2o->local_nve_id =
							pEncap->value[12];

						l2o->logical_net_id =
							(pEncap->value[15]
							 & 0xff)
							+ ((pEncap->value[14]
							    << 8)
							   & 0xff00)
							+ ((pEncap->value[13]
							    << 16)
							   & 0xff0000);
					}

					return 0;
				}
			}
		}
	}

	return ENOENT;
}

/*
 * Extract the lifetime from the Tunnel Encap attribute of a route in
 * an import table
 */
int rfapiGetVncLifetime(struct attr *attr, uint32_t *lifetime)
{
	struct bgp_attr_encap_subtlv *pEncap;

	*lifetime = RFAPI_INFINITE_LIFETIME; /* default to infinite */

	if (attr) {

		for (pEncap = attr->vnc_subtlvs; pEncap;
		     pEncap = pEncap->next) {

			if (pEncap->type
			    == BGP_VNC_SUBTLV_TYPE_LIFETIME) { /* lifetime */
				if (pEncap->length == 4) {
					memcpy(lifetime, pEncap->value, 4);
					*lifetime = ntohl(*lifetime);
					return 0;
				}
			}
		}
	}

	return ENOENT;
}

/*
 * Extract the tunnel type from the extended community
 */
int rfapiGetTunnelType(struct attr *attr, bgp_encap_types *type)
{
	*type = BGP_ENCAP_TYPE_MPLS; /* default to MPLS */
	if (attr && attr->ecommunity) {
		struct ecommunity *ecom = attr->ecommunity;
		int i;

		for (i = 0; i < (ecom->size * ECOMMUNITY_SIZE);
		     i += ECOMMUNITY_SIZE) {
			uint8_t *ep;

			ep = ecom->val + i;
			if (ep[0] == ECOMMUNITY_ENCODE_OPAQUE
			    && ep[1] == ECOMMUNITY_OPAQUE_SUBTYPE_ENCAP) {
				*type = (ep[6] << 8) + ep[7];
				return 0;
			}
		}
	}

	return ENOENT;
}


/*
 * Look for UN address in Encap attribute
 */
int rfapiGetVncTunnelUnAddr(struct attr *attr, struct prefix *p)
{
	struct bgp_attr_encap_subtlv *pEncap;
	bgp_encap_types tun_type;

	rfapiGetTunnelType(attr, &tun_type);
	if (tun_type == BGP_ENCAP_TYPE_MPLS) {
		if (!p)
			return 0;
		/* MPLS carries UN address in next hop */
		rfapiNexthop2Prefix(attr, p);
		if (p->family != 0)
			return 0;

		return ENOENT;
	}
	if (attr) {
		for (pEncap = attr->encap_subtlvs; pEncap;
		     pEncap = pEncap->next) {

			if (pEncap->type
			    == BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT) { /* un
									   addr
									   */
				switch (pEncap->length) {
				case 8:
					if (p) {
						p->family = AF_INET;
						p->prefixlen = 32;
						memcpy(p->u.val, pEncap->value,
						       4);
					}
					return 0;

				case 20:
					if (p) {
						p->family = AF_INET6;
						p->prefixlen = 128;
						memcpy(p->u.val, pEncap->value,
						       16);
					}
					return 0;
				}
			}
		}
	}

	return ENOENT;
}

/*
 * Get UN address wherever it might be
 */
int rfapiGetUnAddrOfVpnBi(struct bgp_info *bi, struct prefix *p)
{
	/* If it's in this route's VNC attribute, we're done */
	if (!rfapiGetVncTunnelUnAddr(bi->attr, p))
		return 0;
	/*
	 * Otherwise, see if it's cached from a corresponding ENCAP SAFI
	 * advertisement
	 */
	if (bi->extra) {
		switch (bi->extra->vnc.import.un_family) {
		case AF_INET:
			if (p) {
				p->family = bi->extra->vnc.import.un_family;
				p->u.prefix4 = bi->extra->vnc.import.un.addr4;
				p->prefixlen = 32;
			}
			return 0;
		case AF_INET6:
			if (p) {
				p->family = bi->extra->vnc.import.un_family;
				p->u.prefix6 = bi->extra->vnc.import.un.addr6;
				p->prefixlen = 128;
			}
			return 0;
		default:
			if (p)
				p->family = 0;
#if DEBUG_ENCAP_MONITOR
			vnc_zlog_debug_verbose(
				"%s: bi->extra->vnc.import.un_family is 0, no UN addr",
				__func__);
#endif
			break;
		}
	}

	return ENOENT;
}


/*
 * Make a new bgp_info from gathered parameters
 */
static struct bgp_info *rfapiBgpInfoCreate(struct attr *attr, struct peer *peer,
					   void *rfd, struct prefix_rd *prd,
					   u_char type, u_char sub_type,
					   uint32_t *label)
{
	struct bgp_info *new;

	new = bgp_info_new();
	assert(new);

	if (attr) {
		if (!new->attr)
			new->attr = bgp_attr_intern(attr);
	}
	bgp_info_extra_get(new);
	if (prd) {
		new->extra->vnc.import.rd = *prd;
		rfapi_time(&new->extra->vnc.import.create_time);
	}
	if (label)
		encode_label(*label, &new->extra->label[0]);
	new->type = type;
	new->sub_type = sub_type;
	new->peer = peer;
	peer_lock(peer);

	return new;
}

/*
 * Frees bgp_info as used in import tables (parts are not
 * allocated exactly the way they are in the main RIBs)
 */
static void rfapiBgpInfoFree(struct bgp_info *goner)
{
	if (!goner)
		return;

	if (goner->peer) {
		vnc_zlog_debug_verbose("%s: calling peer_unlock(%p), #%d",
				       __func__, goner->peer,
				       goner->peer->lock);
		peer_unlock(goner->peer);
	}

	if (goner->attr) {
		bgp_attr_unintern(&goner->attr);
	}
	if (goner->extra) {
		assert(!goner->extra->damp_info); /* Not used in import tbls */
		XFREE(MTYPE_BGP_ROUTE_EXTRA, goner->extra);
		goner->extra = NULL;
	}
	XFREE(MTYPE_BGP_ROUTE, goner);
}

struct rfapi_import_table *rfapiMacImportTableGetNoAlloc(struct bgp *bgp,
							 uint32_t lni)
{
	struct rfapi *h;
	struct rfapi_import_table *it = NULL;
	uintptr_t lni_as_ptr = lni;

	h = bgp->rfapi;
	if (!h)
		return NULL;

	if (!h->import_mac)
		return NULL;

	if (skiplist_search(h->import_mac, (void *)lni_as_ptr, (void **)&it))
		return NULL;

	return it;
}

struct rfapi_import_table *rfapiMacImportTableGet(struct bgp *bgp, uint32_t lni)
{
	struct rfapi *h;
	struct rfapi_import_table *it = NULL;
	uintptr_t lni_as_ptr = lni;

	h = bgp->rfapi;
	assert(h);

	if (!h->import_mac) {
		/* default cmp is good enough for LNI */
		h->import_mac = skiplist_new(0, NULL, NULL);
	}

	if (skiplist_search(h->import_mac, (void *)lni_as_ptr, (void **)&it)) {

		struct ecommunity *enew;
		struct ecommunity_val eval;
		afi_t afi;

		it = XCALLOC(MTYPE_RFAPI_IMPORTTABLE,
			     sizeof(struct rfapi_import_table));
		/* set RT list of new import table based on LNI */
		memset((char *)&eval, 0, sizeof(eval));
		eval.val[0] = 0; /* VNC L2VPN */
		eval.val[1] = 2; /* VNC L2VPN */
		eval.val[5] = (lni >> 16) & 0xff;
		eval.val[6] = (lni >> 8) & 0xff;
		eval.val[7] = (lni >> 0) & 0xff;

		enew = ecommunity_new();
		ecommunity_add_val(enew, &eval);
		it->rt_import_list = enew;

		for (afi = AFI_IP; afi < AFI_MAX; ++afi) {
			it->imported_vpn[afi] = route_table_init();
			it->imported_encap[afi] = route_table_init();
		}

		it->l2_logical_net_id = lni;

		skiplist_insert(h->import_mac, (void *)lni_as_ptr, it);
	}

	assert(it);
	return it;
}

/*
 * Implement MONITOR_MOVE_SHORTER(original_node) from
 * RFAPI-Import-Event-Handling.txt
 *
 * Returns pointer to the list of moved monitors
 */
static struct rfapi_monitor_vpn *
rfapiMonitorMoveShorter(struct route_node *original_vpn_node, int lockoffset)
{
	struct bgp_info *bi;
	struct route_node *par;
	struct rfapi_monitor_vpn *m;
	struct rfapi_monitor_vpn *mlast;
	struct rfapi_monitor_vpn *moved;
	int movecount = 0;
	int parent_already_refcounted = 0;

	RFAPI_CHECK_REFCOUNT(original_vpn_node, SAFI_MPLS_VPN, lockoffset);

#if DEBUG_MONITOR_MOVE_SHORTER
	{
		char buf[PREFIX_STRLEN];

		prefix2str(&original_vpn_node->p, buf, sizeof(buf));
		vnc_zlog_debug_verbose("%s: called with node pfx=%s", __func__,
				       buf);
	}
#endif

	/*
	 * 1. If there is at least one bi (either regular route or
	 *    route marked as withdrawn, with a pending timer) at
	 *    original_node with a valid UN address, we're done. Return.
	 */
	for (bi = original_vpn_node->info; bi; bi = bi->next) {
		struct prefix pfx;

		if (!rfapiGetUnAddrOfVpnBi(bi, &pfx)) {
#if DEBUG_MONITOR_MOVE_SHORTER
			vnc_zlog_debug_verbose(
				"%s: have valid UN at original node, no change",
				__func__);
#endif
			return NULL;
		}
	}

	/*
	 * 2. Travel up the tree (toward less-specific prefixes) from
	 *    original_node to find the first node that has at least
	 *    one route (even if it is only a withdrawn route) with a
	 *    valid UN address. Call this node "Node P."
	 */
	for (par = original_vpn_node->parent; par; par = par->parent) {
		for (bi = par->info; bi; bi = bi->next) {
			struct prefix pfx;
			if (!rfapiGetUnAddrOfVpnBi(bi, &pfx)) {
				break;
			}
		}
		if (bi)
			break;
	}

	if (par) {
		RFAPI_CHECK_REFCOUNT(par, SAFI_MPLS_VPN, 0);
	}

	/*
	 * If no less-specific routes, try to use the 0/0 node
	 */
	if (!par) {
		/* this isn't necessarily 0/0 */
		par = route_top(original_vpn_node->table);

		/*
		 * If we got the top node but it wasn't 0/0,
		 * ignore it
		 */
		if (par && par->p.prefixlen) {
			route_unlock_node(par); /* maybe free */
			par = NULL;
		}

		if (par) {
			++parent_already_refcounted;
		}
	}

	/*
	 * Create 0/0 node if it isn't there
	 */
	if (!par) {
		struct prefix pfx_default;

		memset(&pfx_default, 0, sizeof(pfx_default));
		pfx_default.family = original_vpn_node->p.family;

		/* creates default node if none exists */
		par = route_node_get(original_vpn_node->table, &pfx_default);
		++parent_already_refcounted;
	}

	/*
	 * 3. Move each of the monitors found at original_node to Node P.
	 *    These are "Moved Monitors."
	 *
	 */

	/*
	 * Attach at end so that the list pointer we return points
	 * only to the moved routes
	 */
	for (m = RFAPI_MONITOR_VPN(par), mlast = NULL; m;
	     mlast = m, m = m->next)
		;

	if (mlast) {
		moved = mlast->next = RFAPI_MONITOR_VPN(original_vpn_node);
	} else {
		moved = RFAPI_MONITOR_VPN_W_ALLOC(par) =
			RFAPI_MONITOR_VPN(original_vpn_node);
	}
	if (RFAPI_MONITOR_VPN(
		    original_vpn_node)) /* check agg, so not allocated */
		RFAPI_MONITOR_VPN_W_ALLOC(original_vpn_node) = NULL;

	/*
	 * update the node pointers on the monitors
	 */
	for (m = moved; m; m = m->next) {
		++movecount;
		m->node = par;
	}

	RFAPI_CHECK_REFCOUNT(par, SAFI_MPLS_VPN,
			     parent_already_refcounted - movecount);
	while (movecount > parent_already_refcounted) {
		route_lock_node(par);
		++parent_already_refcounted;
	}
	while (movecount < parent_already_refcounted) {
		/* unlikely, but code defensively */
		route_unlock_node(par);
		--parent_already_refcounted;
	}
	RFAPI_CHECK_REFCOUNT(original_vpn_node, SAFI_MPLS_VPN,
			     movecount + lockoffset);
	while (movecount--) {
		route_unlock_node(original_vpn_node);
	}

#if DEBUG_MONITOR_MOVE_SHORTER
	{
		char buf[PREFIX_STRLEN];

		prefix2str(&par->p, buf, sizeof(buf));
		vnc_zlog_debug_verbose("%s: moved to node pfx=%s", __func__,
				       buf);
	}
#endif


	return moved;
}

/*
 * Implement MONITOR_MOVE_LONGER(new_node) from
 * RFAPI-Import-Event-Handling.txt
 */
static void rfapiMonitorMoveLonger(struct route_node *new_vpn_node)
{
	struct rfapi_monitor_vpn *monitor;
	struct rfapi_monitor_vpn *mlast;
	struct bgp_info *bi;
	struct route_node *par;

	RFAPI_CHECK_REFCOUNT(new_vpn_node, SAFI_MPLS_VPN, 0);

	/*
	 * Make sure we have at least one valid route at the new node
	 */
	for (bi = new_vpn_node->info; bi; bi = bi->next) {
		struct prefix pfx;
		if (!rfapiGetUnAddrOfVpnBi(bi, &pfx))
			break;
	}

	if (!bi) {
		vnc_zlog_debug_verbose(
			"%s: no valid routes at node %p, so not attempting moves",
			__func__, new_vpn_node);
		return;
	}

	/*
	 * Find first parent node that has monitors
	 */
	for (par = new_vpn_node->parent; par; par = par->parent) {
		if (RFAPI_MONITOR_VPN(par))
			break;
	}

	if (!par) {
		vnc_zlog_debug_verbose(
			"%s: no parent nodes with monitors, done", __func__);
		return;
	}

	/*
	 * Check each of these monitors to see of their longest-match
	 * is now the updated node. Move any such monitors to the more-
	 * specific updated node
	 */
	for (mlast = NULL, monitor = RFAPI_MONITOR_VPN(par); monitor;) {

		/*
		 * If new longest match for monitor prefix is the new
		 * route's prefix, move monitor to new route's prefix
		 */
		if (prefix_match(&new_vpn_node->p, &monitor->p)) {
			/* detach */
			if (mlast) {
				mlast->next = monitor->next;
			} else {
				RFAPI_MONITOR_VPN_W_ALLOC(par) = monitor->next;
			}


			/* attach */
			monitor->next = RFAPI_MONITOR_VPN(new_vpn_node);
			RFAPI_MONITOR_VPN_W_ALLOC(new_vpn_node) = monitor;
			monitor->node = new_vpn_node;

			route_lock_node(new_vpn_node); /* incr refcount */

			monitor = mlast ? mlast->next : RFAPI_MONITOR_VPN(par);

			RFAPI_CHECK_REFCOUNT(par, SAFI_MPLS_VPN, 1);
			/* decr refcount after we're done with par as this might
			 * free it */
			route_unlock_node(par);

			continue;
		}
		mlast = monitor;
		monitor = monitor->next;
	}

	RFAPI_CHECK_REFCOUNT(new_vpn_node, SAFI_MPLS_VPN, 0);
}


static void rfapiBgpInfoChainFree(struct bgp_info *bi)
{
	struct bgp_info *next;

	while (bi) {

		/*
		 * If there is a timer waiting to delete this bi, cancel
		 * the timer and delete immediately
		 */
		if (CHECK_FLAG(bi->flags, BGP_INFO_REMOVED)
		    && bi->extra->vnc.import.timer) {

			struct thread *t =
				(struct thread *)bi->extra->vnc.import.timer;
			struct rfapi_withdraw *wcb = t->arg;

			XFREE(MTYPE_RFAPI_WITHDRAW, wcb);
			thread_cancel(t);
		}

		next = bi->next;
		bi->next = NULL;
		rfapiBgpInfoFree(bi);
		bi = next;
	}
}

static void rfapiImportTableFlush(struct rfapi_import_table *it)
{
	afi_t afi;

	/*
	 * Free ecommunity
	 */
	ecommunity_free(&it->rt_import_list);
	it->rt_import_list = NULL;

	for (afi = AFI_IP; afi < AFI_MAX; ++afi) {

		struct route_node *rn;

		for (rn = route_top(it->imported_vpn[afi]); rn;
		     rn = route_next(rn)) {
			/*
			 * Each route_node has:
			 * aggregate: points to rfapi_it_extra with monitor
			 * chain(s)
			 * info: points to chain of bgp_info
			 */
			/* free bgp_info and its children */
			rfapiBgpInfoChainFree(rn->info);
			rn->info = NULL;

			rfapiMonitorExtraFlush(SAFI_MPLS_VPN, rn);
		}

		for (rn = route_top(it->imported_encap[afi]); rn;
		     rn = route_next(rn)) {
			/* free bgp_info and its children */
			rfapiBgpInfoChainFree(rn->info);
			rn->info = NULL;

			rfapiMonitorExtraFlush(SAFI_ENCAP, rn);
		}

		route_table_finish(it->imported_vpn[afi]);
		route_table_finish(it->imported_encap[afi]);
	}
	if (it->monitor_exterior_orphans) {
		skiplist_free(it->monitor_exterior_orphans);
	}
}

void rfapiImportTableRefDelByIt(struct bgp *bgp,
				struct rfapi_import_table *it_target)
{
	struct rfapi *h;
	struct rfapi_import_table *it;
	struct rfapi_import_table *prev = NULL;

	assert(it_target);

	h = bgp->rfapi;
	assert(h);

	for (it = h->imports; it; prev = it, it = it->next) {
		if (it == it_target)
			break;
	}

	assert(it);
	assert(it->refcount);

	it->refcount -= 1;

	if (!it->refcount) {
		if (prev) {
			prev->next = it->next;
		} else {
			h->imports = it->next;
		}
		rfapiImportTableFlush(it);
		XFREE(MTYPE_RFAPI_IMPORTTABLE, it);
	}
}

#if RFAPI_REQUIRE_ENCAP_BEEC
/*
 * Look for magic BGP Encapsulation Extended Community value
 * Format in RFC 5512 Sect. 4.5
 */
static int rfapiEcommunitiesMatchBeec(struct ecommunity *ecom,
				      bgp_encap_types type)
{
	int i;

	if (!ecom)
		return 0;

	for (i = 0; i < (ecom->size * ECOMMUNITY_SIZE); i += ECOMMUNITY_SIZE) {

		uint8_t *ep;

		ep = ecom->val + i;

		if (ep[0] == ECOMMUNITY_ENCODE_OPAQUE
		    && ep[1] == ECOMMUNITY_OPAQUE_SUBTYPE_ENCAP
		    && ep[6] == ((type && 0xff00) >> 8)
		    && ep[7] == (type & 0xff)) {

			return 1;
		}
	}
	return 0;
}
#endif

int rfapiEcommunitiesIntersect(struct ecommunity *e1, struct ecommunity *e2)
{
	int i, j;

	if (!e1 || !e2)
		return 0;

	{
		char *s1, *s2;
		s1 = ecommunity_ecom2str(e1, ECOMMUNITY_FORMAT_DISPLAY, 0);
		s2 = ecommunity_ecom2str(e2, ECOMMUNITY_FORMAT_DISPLAY, 0);
		vnc_zlog_debug_verbose("%s: e1[%s], e2[%s]", __func__, s1, s2);
		XFREE(MTYPE_ECOMMUNITY_STR, s1);
		XFREE(MTYPE_ECOMMUNITY_STR, s2);
	}

	for (i = 0; i < e1->size; ++i) {
		for (j = 0; j < e2->size; ++j) {
			if (!memcmp(e1->val + (i * ECOMMUNITY_SIZE),
				    e2->val + (j * ECOMMUNITY_SIZE),
				    ECOMMUNITY_SIZE)) {

				return 1;
			}
		}
	}
	return 0;
}

int rfapiEcommunityGetLNI(struct ecommunity *ecom, uint32_t *lni)
{
	if (ecom) {
		int i;
		for (i = 0; i < ecom->size; ++i) {
			uint8_t *p = ecom->val + (i * ECOMMUNITY_SIZE);

			if ((*(p + 0) == 0x00) && (*(p + 1) == 0x02)) {

				*lni = (*(p + 5) << 16) | (*(p + 6) << 8)
				       | (*(p + 7));
				return 0;
			}
		}
	}
	return ENOENT;
}

int rfapiEcommunityGetEthernetTag(struct ecommunity *ecom, uint16_t *tag_id)
{
	struct bgp *bgp = bgp_get_default();
	*tag_id = 0; /* default to untagged */
	if (ecom) {
		int i;
		for (i = 0; i < ecom->size; ++i) {
			as_t as = 0;
			int encode = 0;
			uint8_t *p = ecom->val + (i * ECOMMUNITY_SIZE);

			/* High-order octet of type. */
			encode = *p++;

			if (*p++ == ECOMMUNITY_ROUTE_TARGET) {
				if (encode == ECOMMUNITY_ENCODE_AS4) {
					p = ptr_get_be32(p, &as);
				} else if (encode == ECOMMUNITY_ENCODE_AS) {
					as = (*p++ << 8);
					as |= (*p++);
					p +=
						2; /* skip next two, tag/vid
						      always in lowest bytes */
				}
				if (as == bgp->as) {
					*tag_id = *p++ << 8;
					*tag_id |= (*p++);
					return 0;
				}
			}
		}
	}
	return ENOENT;
}

static int rfapiVpnBiNhEqualsPt(struct bgp_info *bi, struct rfapi_ip_addr *hpt)
{
	uint8_t family;

	if (!hpt || !bi)
		return 0;

	family = BGP_MP_NEXTHOP_FAMILY(bi->attr->mp_nexthop_len);

	if (hpt->addr_family != family)
		return 0;

	switch (family) {
	case AF_INET:
		if (bi->attr->mp_nexthop_global_in.s_addr
		    != hpt->addr.v4.s_addr)
			return 0;
		break;

	case AF_INET6:
		if (IPV6_ADDR_CMP(&bi->attr->mp_nexthop_global, &hpt->addr.v6))
			return 0;
		break;

	default:
		return 0;
		break;
	}

	return 1;
}


/*
 * Compare 2 VPN BIs. Return true if they have the same VN and UN addresses
 */
static int rfapiVpnBiSamePtUn(struct bgp_info *bi1, struct bgp_info *bi2)
{
	struct prefix pfx_un1;
	struct prefix pfx_un2;

	if (!bi1 || !bi2)
		return 0;

	if (!bi1->attr || !bi2->attr)
		return 0;

	/*
	 * VN address comparisons
	 */

	if (BGP_MP_NEXTHOP_FAMILY(bi1->attr->mp_nexthop_len)
	    != BGP_MP_NEXTHOP_FAMILY(bi2->attr->mp_nexthop_len)) {
		return 0;
	}

	switch (BGP_MP_NEXTHOP_FAMILY(bi1->attr->mp_nexthop_len)) {
	case AF_INET:
		if (bi1->attr->mp_nexthop_global_in.s_addr
		    != bi2->attr->mp_nexthop_global_in.s_addr)
			return 0;
		break;

	case AF_INET6:
		if (IPV6_ADDR_CMP(&bi1->attr->mp_nexthop_global,
				  &bi2->attr->mp_nexthop_global))
			return 0;
		break;

	default:
		return 0;
		break;
	}

	/*
	 * UN address comparisons
	 */
	if (rfapiGetVncTunnelUnAddr(bi1->attr, &pfx_un1)) {
		if (bi1->extra) {
			pfx_un1.family = bi1->extra->vnc.import.un_family;
			switch (bi1->extra->vnc.import.un_family) {
			case AF_INET:
				pfx_un1.u.prefix4 =
					bi1->extra->vnc.import.un.addr4;
				break;
			case AF_INET6:
				pfx_un1.u.prefix6 =
					bi1->extra->vnc.import.un.addr6;
				break;
			default:
				pfx_un1.family = 0;
				break;
			}
		}
	}

	if (rfapiGetVncTunnelUnAddr(bi2->attr, &pfx_un2)) {
		if (bi2->extra) {
			pfx_un2.family = bi2->extra->vnc.import.un_family;
			switch (bi2->extra->vnc.import.un_family) {
			case AF_INET:
				pfx_un2.u.prefix4 =
					bi2->extra->vnc.import.un.addr4;
				break;
			case AF_INET6:
				pfx_un2.u.prefix6 =
					bi2->extra->vnc.import.un.addr6;
				break;
			default:
				pfx_un2.family = 0;
				break;
			}
		}
	}

	if (!pfx_un1.family || !pfx_un2.family)
		return 0;

	if (pfx_un1.family != pfx_un2.family)
		return 0;

	switch (pfx_un1.family) {
	case AF_INET:
		if (!IPV4_ADDR_SAME(&pfx_un1.u.prefix4,
				    &pfx_un2.u.prefix4))
			return 0;
		break;
	case AF_INET6:
		if (!IPV6_ADDR_SAME(&pfx_un1.u.prefix6, &pfx_un2.u.prefix6))
			return 0;
		break;
	}


	return 1;
}

uint8_t rfapiRfpCost(struct attr *attr)
{
	if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)) {
		if (attr->local_pref > 255) {
			return 0;
		}
		return 255 - attr->local_pref;
	}

	return 255;
}

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
int rfapi_extract_l2o(
	struct bgp_tea_options *pHop,       /* chain of options */
	struct rfapi_l2address_option *l2o) /* return extracted value */
{
	struct bgp_tea_options *p;

	for (p = pHop; p; p = p->next) {
		if ((p->type == RFAPI_VN_OPTION_TYPE_L2ADDR)
		    && (p->length >= 8)) {

			char *v = p->value;

			memcpy(&l2o->macaddr, v, 6);

			l2o->label = ((v[6] << 12) & 0xff000)
				     + ((v[7] << 4) & 0xff0)
				     + ((v[8] >> 4) & 0xf);

			l2o->local_nve_id = (uint8_t)v[10];

			l2o->logical_net_id =
				(v[11] << 16) + (v[12] << 8) + (v[13] << 0);

			return 0;
		}
	}
	return 1;
}

static struct rfapi_next_hop_entry *
rfapiRouteInfo2NextHopEntry(struct rfapi_ip_prefix *rprefix,
			    struct bgp_info *bi,   /* route to encode */
			    uint32_t lifetime,     /* use this in nhe */
			    struct route_node *rn) /* req for L2 eth addr */
{
	struct rfapi_next_hop_entry *new;
	int have_vnc_tunnel_un = 0;

#if DEBUG_ENCAP_MONITOR
	vnc_zlog_debug_verbose("%s: entry, bi %p, rn %p", __func__, bi, rn);
#endif

	new = XCALLOC(MTYPE_RFAPI_NEXTHOP, sizeof(struct rfapi_next_hop_entry));
	assert(new);

	new->prefix = *rprefix;

	if (bi->extra
	    && decode_rd_type(bi->extra->vnc.import.rd.val)
		       == RD_TYPE_VNC_ETH) {
		/* ethernet */

		struct rfapi_vn_option *vo;

		vo = XCALLOC(MTYPE_RFAPI_VN_OPTION,
			     sizeof(struct rfapi_vn_option));
		assert(vo);

		vo->type = RFAPI_VN_OPTION_TYPE_L2ADDR;

		memcpy(&vo->v.l2addr.macaddr, &rn->p.u.prefix_eth.octet,
		       ETH_ALEN);
		/* only low 3 bytes of this are significant */
		if (bi->attr) {
			(void)rfapiEcommunityGetLNI(
				bi->attr->ecommunity,
				&vo->v.l2addr.logical_net_id);
			(void)rfapiEcommunityGetEthernetTag(
				bi->attr->ecommunity, &vo->v.l2addr.tag_id);
		}

		/* local_nve_id comes from lower byte of RD type */
		vo->v.l2addr.local_nve_id = bi->extra->vnc.import.rd.val[1];

		/* label comes from MP_REACH_NLRI label */
		vo->v.l2addr.label = decode_label(&bi->extra->label[0]);

		new->vn_options = vo;

		/*
		 * If there is an auxiliary prefix (i.e., host IP address),
		 * use it as the nexthop prefix instead of the query prefix
		 */
		if (bi->extra->vnc.import.aux_prefix.family) {
			rfapiQprefix2Rprefix(&bi->extra->vnc.import.aux_prefix,
					     &new->prefix);
		}
	}

	if (bi->attr) {
		bgp_encap_types tun_type;
		new->prefix.cost = rfapiRfpCost(bi->attr);

		struct bgp_attr_encap_subtlv *pEncap;

		switch (BGP_MP_NEXTHOP_FAMILY(bi->attr->mp_nexthop_len)) {
		case AF_INET:
			new->vn_address.addr_family = AF_INET;
			new->vn_address.addr.v4 =
				bi->attr->mp_nexthop_global_in;
			break;

		case AF_INET6:
			new->vn_address.addr_family = AF_INET6;
			new->vn_address.addr.v6 = bi->attr->mp_nexthop_global;
			break;

		default:
			zlog_warn("%s: invalid vpn nexthop length: %d",
				  __func__, bi->attr->mp_nexthop_len);
			rfapi_free_next_hop_list(new);
			return NULL;
		}

		for (pEncap = bi->attr->vnc_subtlvs; pEncap;
		     pEncap = pEncap->next) {
			switch (pEncap->type) {
			case BGP_VNC_SUBTLV_TYPE_LIFETIME:
				/* use configured lifetime, not attr lifetime */
				break;

			default:
				zlog_warn("%s: unknown VNC option type %d",
					  __func__, pEncap->type);


				break;
			}
		}

		rfapiGetTunnelType(bi->attr, &tun_type);
		if (tun_type == BGP_ENCAP_TYPE_MPLS) {
			struct prefix p;
			/* MPLS carries UN address in next hop */
			rfapiNexthop2Prefix(bi->attr, &p);
			if (p.family != 0) {
				rfapiQprefix2Raddr(&p, &new->un_address);
				have_vnc_tunnel_un = 1;
			}
		}

		for (pEncap = bi->attr->encap_subtlvs; pEncap;
		     pEncap = pEncap->next) {
			switch (pEncap->type) {
			case BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT:
				/*
				 * Overrides ENCAP UN address, if any
				 */
				switch (pEncap->length) {

				case 8:
					new->un_address.addr_family = AF_INET;
					memcpy(&new->un_address.addr.v4,
					       pEncap->value, 4);
					have_vnc_tunnel_un = 1;
					break;

				case 20:
					new->un_address.addr_family = AF_INET6;
					memcpy(&new->un_address.addr.v6,
					       pEncap->value, 16);
					have_vnc_tunnel_un = 1;
					break;

				default:
					zlog_warn(
						"%s: invalid tunnel subtlv UN addr length (%d) for bi %p",
						__func__, pEncap->length, bi);
				}
				break;

			default:
				zlog_warn(
					"%s: unknown Encap Attribute option type %d",
					__func__, pEncap->type);


				break;
			}
		}

		new->un_options = rfapi_encap_tlv_to_un_option(bi->attr);

#if DEBUG_ENCAP_MONITOR
		vnc_zlog_debug_verbose("%s: line %d: have_vnc_tunnel_un=%d",
				       __func__, __LINE__, have_vnc_tunnel_un);
#endif

		if (!have_vnc_tunnel_un && bi->extra) {
			/*
			 * use cached UN address from ENCAP route
			 */
			new->un_address.addr_family =
				bi->extra->vnc.import.un_family;
			switch (new->un_address.addr_family) {
			case AF_INET:
				new->un_address.addr.v4 =
					bi->extra->vnc.import.un.addr4;
				break;
			case AF_INET6:
				new->un_address.addr.v6 =
					bi->extra->vnc.import.un.addr6;
				break;
			default:
				zlog_warn(
					"%s: invalid UN addr family (%d) for bi %p",
					__func__, new->un_address.addr_family,
					bi);
				rfapi_free_next_hop_list(new);
				return NULL;
				break;
			}
		}
	}

	new->lifetime = lifetime;
	return new;
}

int rfapiHasNonRemovedRoutes(struct route_node *rn)
{
	struct bgp_info *bi;

	for (bi = rn->info; bi; bi = bi->next) {
		struct prefix pfx;

		if (!CHECK_FLAG(bi->flags, BGP_INFO_REMOVED)
		    && (bi->extra && !rfapiGetUnAddrOfVpnBi(bi, &pfx))) {

			return 1;
		}
	}
	return 0;
}

#if DEBUG_IT_NODES
/*
 * DEBUG FUNCTION
 */
void rfapiDumpNode(struct route_node *rn)
{
	struct bgp_info *bi;

	vnc_zlog_debug_verbose("%s: rn=%p", __func__, rn);
	for (bi = rn->info; bi; bi = bi->next) {
		struct prefix pfx;
		int ctrc = rfapiGetUnAddrOfVpnBi(bi, &pfx);
		int nr;

		if (!CHECK_FLAG(bi->flags, BGP_INFO_REMOVED)
		    && (bi->extra && !ctrc)) {

			nr = 1;
		} else {
			nr = 0;
		}

		vnc_zlog_debug_verbose(
			"  bi=%p, nr=%d, flags=0x%x, extra=%p, ctrc=%d", bi, nr,
			bi->flags, bi->extra, ctrc);
	}
}
#endif

static int rfapiNhlAddNodeRoutes(
	struct route_node *rn,		      /* in */
	struct rfapi_ip_prefix *rprefix,      /* in */
	uint32_t lifetime,		      /* in */
	int removed,			      /* in */
	struct rfapi_next_hop_entry **head,   /* in/out */
	struct rfapi_next_hop_entry **tail,   /* in/out */
	struct rfapi_ip_addr *exclude_vnaddr, /* omit routes to same NVE */
	struct route_node *rfd_rib_node,      /* preload this NVE rib node */
	struct prefix *pfx_target_original)   /* query target */
{
	struct bgp_info *bi;
	struct rfapi_next_hop_entry *new;
	struct prefix pfx_un;
	struct skiplist *seen_nexthops;
	int count = 0;
	int is_l2 = (rn->p.family == AF_ETHERNET);

	if (rfapiRibFTDFilterRecentPrefix(
		    (struct rfapi_descriptor *)(rfd_rib_node->table->info), rn,
		    pfx_target_original)) {
		return 0;
	}

	seen_nexthops =
		skiplist_new(0, vnc_prefix_cmp, (void (*)(void *))prefix_free);

	for (bi = rn->info; bi; bi = bi->next) {

		struct prefix pfx_vn;
		struct prefix *newpfx;

		if (removed && !CHECK_FLAG(bi->flags, BGP_INFO_REMOVED)) {
#if DEBUG_RETURNED_NHL
			vnc_zlog_debug_verbose(
				"%s: want holddown, this route not holddown, skip",
				__func__);
#endif
			continue;
		}
		if (!removed && CHECK_FLAG(bi->flags, BGP_INFO_REMOVED)) {
			continue;
		}

		if (!bi->extra) {
			continue;
		}

		/*
		 * Check for excluded VN address
		 */
		if (rfapiVpnBiNhEqualsPt(bi, exclude_vnaddr))
			continue;

		/*
		 * Check for VN address (nexthop) copied already
		 */
		if (is_l2) {
			/* L2 routes: semantic nexthop in aux_prefix; VN addr
			 * ain't it */
			pfx_vn = bi->extra->vnc.import.aux_prefix;
		} else {
			rfapiNexthop2Prefix(bi->attr, &pfx_vn);
		}
		if (!skiplist_search(seen_nexthops, &pfx_vn, NULL)) {
#if DEBUG_RETURNED_NHL
			char buf[PREFIX_STRLEN];

			prefix2str(&pfx_vn, buf, sizeof(buf));
			vnc_zlog_debug_verbose(
				"%s: already put VN/nexthop %s, skip", __func__,
				buf);
#endif
			continue;
		}

		if (rfapiGetUnAddrOfVpnBi(bi, &pfx_un)) {
#if DEBUG_ENCAP_MONITOR
			vnc_zlog_debug_verbose(
				"%s: failed to get UN address of this VPN bi",
				__func__);
#endif
			continue;
		}

		newpfx = prefix_new();
		*newpfx = pfx_vn;
		skiplist_insert(seen_nexthops, newpfx, newpfx);

		new = rfapiRouteInfo2NextHopEntry(rprefix, bi, lifetime, rn);
		if (new) {
			if (rfapiRibPreloadBi(rfd_rib_node, &pfx_vn, &pfx_un,
					      lifetime, bi)) {
				/* duplicate filtered by RIB */
				rfapi_free_next_hop_list(new);
				new = NULL;
			}
		}

		if (new) {
			if (*tail) {
				(*tail)->next = new;
			} else {
				*head = new;
			}
			*tail = new;
			++count;
		}
	}

	skiplist_free(seen_nexthops);

	return count;
}


/*
 * Breadth-first
 *
 * omit_node is meant for the situation where we are adding a subtree
 * of a parent of some original requested node. The response already
 * contains the original requested node, and we don't want to duplicate
 * its routes in the list, so we skip it if the right or left node
 * matches (of course, we still travel down its child subtrees).
 */
static int rfapiNhlAddSubtree(
	struct route_node *rn,		      /* in */
	uint32_t lifetime,		      /* in */
	struct rfapi_next_hop_entry **head,   /* in/out */
	struct rfapi_next_hop_entry **tail,   /* in/out */
	struct route_node *omit_node,	 /* in */
	struct rfapi_ip_addr *exclude_vnaddr, /* omit routes to same NVE */
	struct route_table *rfd_rib_table,    /* preload here */
	struct prefix *pfx_target_original)   /* query target */
{
	struct rfapi_ip_prefix rprefix;
	int rcount = 0;

	/* FIXME: need to find a better way here to work without sticking our
	 * hands in node->link */
	if (rn->l_left && rn->l_left != omit_node) {
		if (rn->l_left->info) {
			int count = 0;
			struct route_node *rib_rn = NULL;

			rfapiQprefix2Rprefix(&rn->l_left->p, &rprefix);
			if (rfd_rib_table) {
				rib_rn = route_node_get(rfd_rib_table,
							&rn->l_left->p);
			}

			count = rfapiNhlAddNodeRoutes(
				rn->l_left, &rprefix, lifetime, 0, head, tail,
				exclude_vnaddr, rib_rn, pfx_target_original);
			if (!count) {
				count = rfapiNhlAddNodeRoutes(
					rn->l_left, &rprefix, lifetime, 1, head,
					tail, exclude_vnaddr, rib_rn,
					pfx_target_original);
			}
			rcount += count;
			if (rib_rn)
				route_unlock_node(rib_rn);
		}
	}

	if (rn->l_right && rn->l_right != omit_node) {
		if (rn->l_right->info) {
			int count = 0;
			struct route_node *rib_rn = NULL;

			rfapiQprefix2Rprefix(&rn->l_right->p, &rprefix);
			if (rfd_rib_table) {
				rib_rn = route_node_get(rfd_rib_table,
							&rn->l_right->p);
			}
			count = rfapiNhlAddNodeRoutes(
				rn->l_right, &rprefix, lifetime, 0, head, tail,
				exclude_vnaddr, rib_rn, pfx_target_original);
			if (!count) {
				count = rfapiNhlAddNodeRoutes(
					rn->l_right, &rprefix, lifetime, 1,
					head, tail, exclude_vnaddr, rib_rn,
					pfx_target_original);
			}
			rcount += count;
			if (rib_rn)
				route_unlock_node(rib_rn);
		}
	}

	if (rn->l_left) {
		rcount += rfapiNhlAddSubtree(
			rn->l_left, lifetime, head, tail, omit_node,
			exclude_vnaddr, rfd_rib_table, pfx_target_original);
	}
	if (rn->l_right) {
		rcount += rfapiNhlAddSubtree(
			rn->l_right, lifetime, head, tail, omit_node,
			exclude_vnaddr, rfd_rib_table, pfx_target_original);
	}

	return rcount;
}

/*
 * Implementation of ROUTE_LIST(node) from RFAPI-Import-Event-Handling.txt
 *
 * Construct an rfapi nexthop list based on the routes attached to
 * the specified node.
 *
 * If there are any routes that do NOT have BGP_INFO_REMOVED set,
 * return those only. If there are ONLY routes with BGP_INFO_REMOVED,
 * then return those, and also include all the non-removed routes from the
 * next less-specific node (i.e., this node's parent) at the end.
 */
struct rfapi_next_hop_entry *rfapiRouteNode2NextHopList(
	struct route_node *rn, uint32_t lifetime, /* put into nexthop entries */
	struct rfapi_ip_addr *exclude_vnaddr,     /* omit routes to same NVE */
	struct route_table *rfd_rib_table,	/* preload here */
	struct prefix *pfx_target_original)       /* query target */
{
	struct rfapi_ip_prefix rprefix;
	struct rfapi_next_hop_entry *answer = NULL;
	struct rfapi_next_hop_entry *last = NULL;
	struct route_node *parent;
	int count = 0;
	struct route_node *rib_rn;

#if DEBUG_RETURNED_NHL
	{
		char buf[PREFIX_STRLEN];

		prefix2str(&rn->p, buf, sizeof(buf));
		vnc_zlog_debug_verbose("%s: called with node pfx=%s", __func__,
				       buf);
	}
	rfapiDebugBacktrace();
#endif

	rfapiQprefix2Rprefix(&rn->p, &rprefix);

	rib_rn = rfd_rib_table ? route_node_get(rfd_rib_table, &rn->p) : NULL;

	/*
	 * Add non-withdrawn routes at this node
	 */
	count = rfapiNhlAddNodeRoutes(rn, &rprefix, lifetime, 0, &answer, &last,
				      exclude_vnaddr, rib_rn,
				      pfx_target_original);

	/*
	 * If the list has at least one entry, it's finished
	 */
	if (count) {
		count += rfapiNhlAddSubtree(rn, lifetime, &answer, &last, NULL,
					    exclude_vnaddr, rfd_rib_table,
					    pfx_target_original);
		vnc_zlog_debug_verbose("%s: %d nexthops, answer=%p", __func__,
				       count, answer);
#if DEBUG_RETURNED_NHL
		rfapiPrintNhl(NULL, answer);
#endif
		if (rib_rn)
			route_unlock_node(rib_rn);
		return answer;
	}

	/*
	 * Add withdrawn routes at this node
	 */
	count = rfapiNhlAddNodeRoutes(rn, &rprefix, lifetime, 1, &answer, &last,
				      exclude_vnaddr, rib_rn,
				      pfx_target_original);
	if (rib_rn)
		route_unlock_node(rib_rn);

	// rfapiPrintNhl(NULL, answer);

	/*
	 * walk up the tree until we find a node with non-deleted
	 * routes, then add them
	 */
	for (parent = rn->parent; parent; parent = parent->parent) {
		if (rfapiHasNonRemovedRoutes(parent)) {
			break;
		}
	}

	/*
	 * Add non-withdrawn routes from less-specific prefix
	 */
	if (parent) {
		rib_rn = rfd_rib_table
				 ? route_node_get(rfd_rib_table, &parent->p)
				 : NULL;
		rfapiQprefix2Rprefix(&parent->p, &rprefix);
		count += rfapiNhlAddNodeRoutes(parent, &rprefix, lifetime, 0,
					       &answer, &last, exclude_vnaddr,
					       rib_rn, pfx_target_original);
		count += rfapiNhlAddSubtree(parent, lifetime, &answer, &last,
					    rn, exclude_vnaddr, rfd_rib_table,
					    pfx_target_original);
		if (rib_rn)
			route_unlock_node(rib_rn);
	} else {
		/*
		 * There is no parent with non-removed routes. Still need to
		 * add subtree of original node if it contributed routes to the
		 * answer.
		 */
		if (count)
			count += rfapiNhlAddSubtree(rn, lifetime, &answer,
						    &last, rn, exclude_vnaddr,
						    rfd_rib_table,
						    pfx_target_original);
	}

	vnc_zlog_debug_verbose("%s: %d nexthops, answer=%p", __func__, count,
			       answer);
#if DEBUG_RETURNED_NHL
	rfapiPrintNhl(NULL, answer);
#endif
	return answer;
}

/*
 * Construct nexthop list of all routes in table
 */
struct rfapi_next_hop_entry *rfapiRouteTable2NextHopList(
	struct route_table *rt,
	uint32_t lifetime,		      /* put into nexthop entries */
	struct rfapi_ip_addr *exclude_vnaddr, /* omit routes to same NVE */
	struct route_table *rfd_rib_table,    /* preload this NVE rib table */
	struct prefix *pfx_target_original)   /* query target */
{
	struct route_node *rn;
	struct rfapi_next_hop_entry *biglist = NULL;
	struct rfapi_next_hop_entry *nhl;
	struct rfapi_next_hop_entry *tail = NULL;
	int count = 0;

	for (rn = route_top(rt); rn; rn = route_next(rn)) {

		nhl = rfapiRouteNode2NextHopList(rn, lifetime, exclude_vnaddr,
						 rfd_rib_table,
						 pfx_target_original);
		if (!tail) {
			tail = biglist = nhl;
			if (tail)
				count = 1;
		} else {
			tail->next = nhl;
		}
		if (tail) {
			while (tail->next) {
				++count;
				tail = tail->next;
			}
		}
	}

	vnc_zlog_debug_verbose("%s: returning %d routes", __func__, count);
	return biglist;
}

struct rfapi_next_hop_entry *rfapiEthRouteNode2NextHopList(
	struct route_node *rn, struct rfapi_ip_prefix *rprefix,
	uint32_t lifetime,		      /* put into nexthop entries */
	struct rfapi_ip_addr *exclude_vnaddr, /* omit routes to same NVE */
	struct route_table *rfd_rib_table,    /* preload NVE rib table */
	struct prefix *pfx_target_original)   /* query target */
{
	int count = 0;
	struct rfapi_next_hop_entry *answer = NULL;
	struct rfapi_next_hop_entry *last = NULL;
	struct route_node *rib_rn;

	rib_rn = rfd_rib_table ? route_node_get(rfd_rib_table, &rn->p) : NULL;

	count = rfapiNhlAddNodeRoutes(rn, rprefix, lifetime, 0, &answer, &last,
				      NULL, rib_rn, pfx_target_original);

#if DEBUG_ENCAP_MONITOR
	vnc_zlog_debug_verbose("%s: node %p: %d non-holddown routes", __func__,
			       rn, count);
#endif

	if (!count) {
		count = rfapiNhlAddNodeRoutes(rn, rprefix, lifetime, 1, &answer,
					      &last, exclude_vnaddr, rib_rn,
					      pfx_target_original);
		vnc_zlog_debug_verbose("%s: node %p: %d holddown routes",
				       __func__, rn, count);
	}

	if (rib_rn)
		route_unlock_node(rib_rn);

#if DEBUG_RETURNED_NHL
	rfapiPrintNhl(NULL, answer);
#endif

	return answer;
}


/*
 * Construct nexthop list of all routes in table
 */
struct rfapi_next_hop_entry *rfapiEthRouteTable2NextHopList(
	uint32_t logical_net_id, struct rfapi_ip_prefix *rprefix,
	uint32_t lifetime,		      /* put into nexthop entries */
	struct rfapi_ip_addr *exclude_vnaddr, /* omit routes to same NVE */
	struct route_table *rfd_rib_table,    /* preload NVE rib node */
	struct prefix *pfx_target_original)   /* query target */
{
	struct rfapi_import_table *it;
	struct bgp *bgp = bgp_get_default();
	struct route_table *rt;
	struct route_node *rn;
	struct rfapi_next_hop_entry *biglist = NULL;
	struct rfapi_next_hop_entry *nhl;
	struct rfapi_next_hop_entry *tail = NULL;
	int count = 0;


	it = rfapiMacImportTableGet(bgp, logical_net_id);
	rt = it->imported_vpn[AFI_L2VPN];

	for (rn = route_top(rt); rn; rn = route_next(rn)) {

		nhl = rfapiEthRouteNode2NextHopList(
			rn, rprefix, lifetime, exclude_vnaddr, rfd_rib_table,
			pfx_target_original);
		if (!tail) {
			tail = biglist = nhl;
			if (tail)
				count = 1;
		} else {
			tail->next = nhl;
		}
		if (tail) {
			while (tail->next) {
				++count;
				tail = tail->next;
			}
		}
	}

	vnc_zlog_debug_verbose("%s: returning %d routes", __func__, count);
	return biglist;
}

/*
 * Insert a new bi to the imported route table node,
 * keeping the list of BIs sorted best route first
 */
static void rfapiBgpInfoAttachSorted(struct route_node *rn,
				     struct bgp_info *info_new, afi_t afi,
				     safi_t safi)
{
	struct bgp *bgp;
	struct bgp_info *prev;
	struct bgp_info *next;
	char pfx_buf[PREFIX2STR_BUFFER];


	bgp = bgp_get_default(); /* assume 1 instance for now */

	if (VNC_DEBUG(IMPORT_BI_ATTACH)) {
		vnc_zlog_debug_verbose("%s: info_new->peer=%p", __func__,
				       info_new->peer);
		vnc_zlog_debug_verbose("%s: info_new->peer->su_remote=%p",
				       __func__, info_new->peer->su_remote);
	}

	for (prev = NULL, next = rn->info; next;
	     prev = next, next = next->next) {
		if (!bgp || (!CHECK_FLAG(info_new->flags, BGP_INFO_REMOVED)
			     && CHECK_FLAG(next->flags, BGP_INFO_REMOVED))
		    || bgp_info_cmp_compatible(bgp, info_new, next, pfx_buf,
					       afi, safi)
			       == -1) { /* -1 if 1st is better */
			break;
		}
	}
	vnc_zlog_debug_verbose("%s: prev=%p, next=%p", __func__, prev, next);
	if (prev) {
		prev->next = info_new;
	} else {
		rn->info = info_new;
	}
	info_new->prev = prev;
	info_new->next = next;
	if (next)
		next->prev = info_new;
	bgp_attr_intern(info_new->attr);
}

static void rfapiBgpInfoDetach(struct route_node *rn, struct bgp_info *bi)
{
	/*
	 * Remove the route (doubly-linked)
	 */
	//  bgp_attr_unintern (&bi->attr);
	if (bi->next)
		bi->next->prev = bi->prev;
	if (bi->prev)
		bi->prev->next = bi->next;
	else
		rn->info = bi->next;
}

/*
 * For L3-indexed import tables
 */
static int rfapi_bi_peer_rd_cmp(void *b1, void *b2)
{
	struct bgp_info *bi1 = b1;
	struct bgp_info *bi2 = b2;

	/*
	 * Compare peers
	 */
	if (bi1->peer < bi2->peer)
		return -1;
	if (bi1->peer > bi2->peer)
		return 1;

	/*
	 * compare RDs
	 */
	return vnc_prefix_cmp((struct prefix *)&bi1->extra->vnc.import.rd,
			      (struct prefix *)&bi2->extra->vnc.import.rd);
}

/*
 * For L2-indexed import tables
 * The BIs in these tables should ALWAYS have an aux_prefix set because
 * they arrive via IPv4 or IPv6 advertisements.
 */
static int rfapi_bi_peer_rd_aux_cmp(void *b1, void *b2)
{
	struct bgp_info *bi1 = b1;
	struct bgp_info *bi2 = b2;
	int rc;

	/*
	 * Compare peers
	 */
	if (bi1->peer < bi2->peer)
		return -1;
	if (bi1->peer > bi2->peer)
		return 1;

	/*
	 * compare RDs
	 */
	rc = vnc_prefix_cmp((struct prefix *)&bi1->extra->vnc.import.rd,
			    (struct prefix *)&bi2->extra->vnc.import.rd);
	if (rc) {
		return rc;
	}

	/*
	 * L2 import tables can have multiple entries with the
	 * same MAC address, same RD, but different L3 addresses.
	 *
	 * Use presence of aux_prefix with AF=ethernet and prefixlen=1
	 * as magic value to signify explicit wildcarding of the aux_prefix.
	 * This magic value will not appear in bona fide bi entries in
	 * the import table, but is allowed in the "fake" bi used to
	 * probe the table when searching. (We have to test both b1 and b2
	 * because there is no guarantee of the order the test key and
	 * the real key will be passed)
	 */
	if ((bi1->extra->vnc.import.aux_prefix.family == AF_ETHERNET
	     && (bi1->extra->vnc.import.aux_prefix.prefixlen == 1))
	    || (bi2->extra->vnc.import.aux_prefix.family == AF_ETHERNET
		&& (bi2->extra->vnc.import.aux_prefix.prefixlen == 1))) {

		/*
		 * wildcard aux address specified
		 */
		return 0;
	}

	return vnc_prefix_cmp(&bi1->extra->vnc.import.aux_prefix,
			      &bi2->extra->vnc.import.aux_prefix);
}


/*
 * Index on RD and Peer
 */
static void rfapiItBiIndexAdd(struct route_node *rn, /* Import table VPN node */
			      struct bgp_info *bi)   /* new BI */
{
	struct skiplist *sl;

	assert(rn);
	assert(bi);
	assert(bi->extra);

	{
		char buf[RD_ADDRSTRLEN];

		vnc_zlog_debug_verbose("%s: bi %p, peer %p, rd %s", __func__,
				       bi, bi->peer,
				       prefix_rd2str(&bi->extra->vnc.import.rd,
						     buf, sizeof(buf)));
	}

	sl = RFAPI_RDINDEX_W_ALLOC(rn);
	if (!sl) {
		if (AF_ETHERNET == rn->p.family) {
			sl = skiplist_new(0, rfapi_bi_peer_rd_aux_cmp, NULL);
		} else {
			sl = skiplist_new(0, rfapi_bi_peer_rd_cmp, NULL);
		}
		RFAPI_IT_EXTRA_GET(rn)->u.vpn.idx_rd = sl;
		route_lock_node(rn); /* for skiplist */
	}
	assert(!skiplist_insert(sl, (void *)bi, (void *)bi));
	route_lock_node(rn); /* for skiplist entry */

	/* NB: BIs in import tables are not refcounted */
}

static void rfapiItBiIndexDump(struct route_node *rn)
{
	struct skiplist *sl;
	void *cursor = NULL;
	struct bgp_info *k;
	struct bgp_info *v;
	int rc;

	sl = RFAPI_RDINDEX(rn);
	if (!sl)
		return;

	for (rc = skiplist_next(sl, (void **)&k, (void **)&v, &cursor); !rc;
	     rc = skiplist_next(sl, (void **)&k, (void **)&v, &cursor)) {

		char buf[RD_ADDRSTRLEN];
		char buf_aux_pfx[PREFIX_STRLEN];

		prefix_rd2str(&k->extra->vnc.import.rd, buf, sizeof(buf));
		if (k->extra->vnc.import.aux_prefix.family) {
			prefix2str(&k->extra->vnc.import.aux_prefix,
				   buf_aux_pfx, sizeof(buf_aux_pfx));
		} else
			strncpy(buf_aux_pfx, "(none)", PREFIX_STRLEN);

		vnc_zlog_debug_verbose("bi %p, peer %p, rd %s, aux_prefix %s",
				       k, k->peer, buf, buf_aux_pfx);
	}
}

static struct bgp_info *rfapiItBiIndexSearch(
	struct route_node *rn, /* Import table VPN node */
	struct prefix_rd *prd, struct peer *peer,
	struct prefix *aux_prefix) /* optional L3 addr for L2 ITs */
{
	struct skiplist *sl;
	int rc;
	struct bgp_info bi_fake;
	struct bgp_info_extra bi_extra;
	struct bgp_info *bi_result;

	sl = RFAPI_RDINDEX(rn);
	if (!sl)
		return NULL;

#if DEBUG_BI_SEARCH
	{
		char buf[RD_ADDRSTRLEN];
		char buf_aux_pfx[PREFIX_STRLEN];

		if (aux_prefix) {
			prefix2str(aux_prefix, buf_aux_pfx,
				   sizeof(buf_aux_pfx));
		} else
			strncpy(buf_aux_pfx, "(nil)", sizeof(buf_aux_pfx));

		vnc_zlog_debug_verbose("%s want prd=%s, peer=%p, aux_prefix=%s",
				       __func__,
				       prefix_rd2str(prd, buf, sizeof(buf)),
				       peer, buf_aux_pfx);
		rfapiItBiIndexDump(rn);
	}
#endif

	/* threshold is a WAG */
	if (sl->count < 3) {
#if DEBUG_BI_SEARCH
		vnc_zlog_debug_verbose("%s: short list algorithm", __func__);
#endif
		/* if short list, linear search might be faster */
		for (bi_result = rn->info; bi_result;
		     bi_result = bi_result->next) {
#if DEBUG_BI_SEARCH
			{
				char buf[RD_ADDRSTRLEN];

				vnc_zlog_debug_verbose(
					"%s: bi has prd=%s, peer=%p", __func__,
					prefix_rd2str(&bi_result->extra->vnc.import.rd,
						      buf,
						      sizeof(buf)),
					bi_result->peer);
			}
#endif
			if (peer == bi_result->peer
			    && !prefix_cmp((struct prefix *)&bi_result->extra
						   ->vnc.import.rd,
					   (struct prefix *)prd)) {

#if DEBUG_BI_SEARCH
				vnc_zlog_debug_verbose(
					"%s: peer and RD same, doing aux_prefix check",
					__func__);
#endif
				if (!aux_prefix
				    || !prefix_cmp(aux_prefix,
						   &bi_result->extra->vnc.import
							    .aux_prefix)) {

#if DEBUG_BI_SEARCH
					vnc_zlog_debug_verbose("%s: match",
							       __func__);
#endif
					break;
				}
			}
		}
		return bi_result;
	}

	bi_fake.peer = peer;
	bi_fake.extra = &bi_extra;
	bi_fake.extra->vnc.import.rd = *(struct prefix_rd *)prd;
	if (aux_prefix) {
		bi_fake.extra->vnc.import.aux_prefix = *aux_prefix;
	} else {
		/* wildcard */
		bi_fake.extra->vnc.import.aux_prefix.family = AF_ETHERNET;
		bi_fake.extra->vnc.import.aux_prefix.prefixlen = 1;
	}

	rc = skiplist_search(sl, (void *)&bi_fake, (void *)&bi_result);

	if (rc) {
#if DEBUG_BI_SEARCH
		vnc_zlog_debug_verbose("%s: no match", __func__);
#endif
		return NULL;
	}

#if DEBUG_BI_SEARCH
	vnc_zlog_debug_verbose("%s: matched bi=%p", __func__, bi_result);
#endif

	return bi_result;
}

static void rfapiItBiIndexDel(struct route_node *rn, /* Import table VPN node */
			      struct bgp_info *bi)   /* old BI */
{
	struct skiplist *sl;
	int rc;

	{
		char buf[RD_ADDRSTRLEN];

		vnc_zlog_debug_verbose("%s: bi %p, peer %p, rd %s", __func__,
				       bi, bi->peer,
				       prefix_rd2str(&bi->extra->vnc.import.rd,
						     buf, sizeof(buf)));
	}

	sl = RFAPI_RDINDEX(rn);
	assert(sl);

	rc = skiplist_delete(sl, (void *)(bi), (void *)bi);
	if (rc) {
		rfapiItBiIndexDump(rn);
	}
	assert(!rc);

	route_unlock_node(rn); /* for skiplist entry */

	/* NB: BIs in import tables are not refcounted */
}

/*
 * Add a backreference at the ENCAP node to the VPN route that
 * refers to it
 */
static void rfapiMonitorEncapAdd(struct rfapi_import_table *import_table,
				 struct prefix *p,	  /* VN address */
				 struct route_node *vpn_rn, /* VPN node */
				 struct bgp_info *vpn_bi)   /* VPN bi/route */
{
	afi_t afi = family2afi(p->family);
	struct route_node *rn;
	struct rfapi_monitor_encap *m;

	assert(afi);
	rn = route_node_get(import_table->imported_encap[afi],
			    p); /* locks rn */
	assert(rn);

	m = XCALLOC(MTYPE_RFAPI_MONITOR_ENCAP,
		    sizeof(struct rfapi_monitor_encap));
	assert(m);

	m->node = vpn_rn;
	m->bi = vpn_bi;
	m->rn = rn;

	/* insert to encap node's list */
	m->next = RFAPI_MONITOR_ENCAP(rn);
	if (m->next)
		m->next->prev = m;
	RFAPI_MONITOR_ENCAP_W_ALLOC(rn) = m;

	/* for easy lookup when deleting vpn route */
	vpn_bi->extra->vnc.import.hme = m;

	vnc_zlog_debug_verbose(
		"%s: it=%p, vpn_bi=%p, afi=%d, encap rn=%p, setting vpn_bi->extra->vnc.import.hme=%p",
		__func__, import_table, vpn_bi, afi, rn, m);

	RFAPI_CHECK_REFCOUNT(rn, SAFI_ENCAP, 0);
	bgp_attr_intern(vpn_bi->attr);
}

static void rfapiMonitorEncapDelete(struct bgp_info *vpn_bi)
{
	/*
	 * Remove encap monitor
	 */
	vnc_zlog_debug_verbose("%s: vpn_bi=%p", __func__, vpn_bi);
	if (vpn_bi->extra) {
		struct rfapi_monitor_encap *hme = vpn_bi->extra->vnc.import.hme;

		if (hme) {

			vnc_zlog_debug_verbose("%s: hme=%p", __func__, hme);

			/* Refcount checking takes too long here */
			// RFAPI_CHECK_REFCOUNT(hme->rn, SAFI_ENCAP, 0);
			if (hme->next)
				hme->next->prev = hme->prev;
			if (hme->prev)
				hme->prev->next = hme->next;
			else
				RFAPI_MONITOR_ENCAP_W_ALLOC(hme->rn) =
					hme->next;
			/* Refcount checking takes too long here */
			// RFAPI_CHECK_REFCOUNT(hme->rn, SAFI_ENCAP, 1);

			/* see if the struct rfapi_it_extra is empty and can be
			 * freed */
			rfapiMonitorExtraPrune(SAFI_ENCAP, hme->rn);

			route_unlock_node(hme->rn); /* decr ref count */
			XFREE(MTYPE_RFAPI_MONITOR_ENCAP, hme);
			vpn_bi->extra->vnc.import.hme = NULL;
		}
	}
}

/*
 * quagga lib/thread.h says this must return int even though
 * it doesn't do anything with the return value
 */
static int rfapiWithdrawTimerVPN(struct thread *t)
{
	struct rfapi_withdraw *wcb = t->arg;
	struct bgp_info *bi = wcb->info;
	struct bgp *bgp = bgp_get_default();

	struct rfapi_monitor_vpn *moved;
	afi_t afi;

	assert(wcb->node);
	assert(bi);
	assert(wcb->import_table);
	assert(bi->extra);

	RFAPI_CHECK_REFCOUNT(wcb->node, SAFI_MPLS_VPN, wcb->lockoffset);

	{
		char buf[BUFSIZ];

		vnc_zlog_debug_verbose(
			"%s: removing bi %p at prefix %s/%d", __func__, bi,
			rfapi_ntop(wcb->node->p.family, &wcb->node->p.u.prefix,
				   buf, BUFSIZ),
			wcb->node->p.prefixlen);
	}

	/*
	 * Remove the route (doubly-linked)
	 */
	if (CHECK_FLAG(bi->flags, BGP_INFO_VALID)
	    && VALID_INTERIOR_TYPE(bi->type))
		RFAPI_MONITOR_EXTERIOR(wcb->node)->valid_interior_count--;

	afi = family2afi(wcb->node->p.family);
	wcb->import_table->holddown_count[afi] -= 1; /* keep count consistent */
	rfapiItBiIndexDel(wcb->node, bi);
	rfapiBgpInfoDetach(wcb->node, bi); /* with removed bi */

	vnc_import_bgp_exterior_del_route_interior(bgp, wcb->import_table,
						   wcb->node, bi);


	/*
	 * If VNC is configured to send response remove messages, AND
	 * if the removed route had a UN address, do response removal
	 * processing.
	 */
	if (!(bgp->rfapi_cfg->flags
	      & BGP_VNC_CONFIG_RESPONSE_REMOVAL_DISABLE)) {

		int has_valid_duplicate = 0;
		struct bgp_info *bii;

		/*
		 * First check if there are any OTHER routes at this node
		 * that have the same nexthop and a valid UN address. If
		 * there are (e.g., from other peers), then the route isn't
		 * really gone, so skip sending a response removal message.
		 */
		for (bii = wcb->node->info; bii; bii = bii->next) {
			if (rfapiVpnBiSamePtUn(bi, bii)) {
				has_valid_duplicate = 1;
				break;
			}
		}

		vnc_zlog_debug_verbose("%s: has_valid_duplicate=%d", __func__,
				       has_valid_duplicate);

		if (!has_valid_duplicate) {
			rfapiRibPendingDeleteRoute(bgp, wcb->import_table, afi,
						   wcb->node);
		}
	}

	rfapiMonitorEncapDelete(bi);

	/*
	 * If there are no VPN monitors at this VPN Node A,
	 * we are done
	 */
	if (!RFAPI_MONITOR_VPN(wcb->node)) {
		vnc_zlog_debug_verbose("%s: no VPN monitors at this node",
				       __func__);
		goto done;
	}

	/*
	 * rfapiMonitorMoveShorter only moves monitors if there are
	 * no remaining valid routes at the current node
	 */
	moved = rfapiMonitorMoveShorter(wcb->node, 1);

	if (moved) {
		rfapiMonitorMovedUp(wcb->import_table, wcb->node, moved->node,
				    moved);
	}

done:
	/*
	 * Free VPN bi
	 */
	rfapiBgpInfoFree(bi);
	wcb->info = NULL;

	/*
	 * If route count at this node has gone to 0, withdraw exported prefix
	 */
	if (!wcb->node->info) {
		/* see if the struct rfapi_it_extra is empty and can be freed */
		rfapiMonitorExtraPrune(SAFI_MPLS_VPN, wcb->node);
		vnc_direct_bgp_del_prefix(bgp, wcb->import_table, wcb->node);
		vnc_zebra_del_prefix(bgp, wcb->import_table, wcb->node);
	} else {
		/*
		 * nexthop change event
		 * vnc_direct_bgp_add_prefix() will recompute the VN addr
		 * ecommunity
		 */
		vnc_direct_bgp_add_prefix(bgp, wcb->import_table, wcb->node);
	}

	RFAPI_CHECK_REFCOUNT(wcb->node, SAFI_MPLS_VPN, 1 + wcb->lockoffset);
	route_unlock_node(wcb->node); /* decr ref count */
	XFREE(MTYPE_RFAPI_WITHDRAW, wcb);
	return 0;
}

/*
 * This works for multiprotocol extension, but not for plain ol'
 * unicast IPv4 because that nexthop is stored in attr->nexthop
 */
void rfapiNexthop2Prefix(struct attr *attr, struct prefix *p)
{
	assert(p);
	assert(attr);

	memset(p, 0, sizeof(struct prefix));

	switch (p->family = BGP_MP_NEXTHOP_FAMILY(attr->mp_nexthop_len)) {
	case AF_INET:
		p->u.prefix4 = attr->mp_nexthop_global_in;
		p->prefixlen = 32;
		break;

	case AF_INET6:
		p->u.prefix6 = attr->mp_nexthop_global;
		p->prefixlen = 128;
		break;

	default:
		vnc_zlog_debug_verbose("%s: Family is unknown = %d", __func__,
				       p->family);
	}
}

void rfapiUnicastNexthop2Prefix(afi_t afi, struct attr *attr, struct prefix *p)
{
	if (afi == AFI_IP) {
		p->family = AF_INET;
		p->prefixlen = 32;
		p->u.prefix4 = attr->nexthop;
	} else {
		rfapiNexthop2Prefix(attr, p);
	}
}

static int rfapiAttrNexthopAddrDifferent(struct prefix *p1, struct prefix *p2)
{
	if (!p1 || !p2) {
		vnc_zlog_debug_verbose("%s: p1 or p2 is NULL", __func__);
		return 1;
	}

	/*
	 * Are address families the same?
	 */
	if (p1->family != p2->family) {
		return 1;
	}

	switch (p1->family) {
	case AF_INET:
		if (IPV4_ADDR_SAME(&p1->u.prefix4, &p2->u.prefix4))
			return 0;
		break;

	case AF_INET6:
		if (IPV6_ADDR_SAME(&p1->u.prefix6, &p2->u.prefix6))
			return 0;
		break;

	default:
		assert(1);
	}

	return 1;
}

static void rfapiCopyUnEncap2VPN(struct bgp_info *encap_bi,
				 struct bgp_info *vpn_bi)
{
	if (!encap_bi->attr) {
		zlog_warn("%s: no encap bi attr/extra, can't copy UN address",
			  __func__);
		return;
	}

	if (!vpn_bi || !vpn_bi->extra) {
		zlog_warn("%s: no vpn  bi attr/extra, can't copy UN address",
			  __func__);
		return;
	}

	switch (BGP_MP_NEXTHOP_FAMILY(encap_bi->attr->mp_nexthop_len)) {
	case AF_INET:

		/*
		 * instrumentation to debug segfault of 091127
		 */
		vnc_zlog_debug_verbose("%s: vpn_bi=%p", __func__, vpn_bi);
		if (vpn_bi) {
			vnc_zlog_debug_verbose("%s: vpn_bi->extra=%p", __func__,
					       vpn_bi->extra);
		}

		vpn_bi->extra->vnc.import.un_family = AF_INET;
		vpn_bi->extra->vnc.import.un.addr4 =
			encap_bi->attr->mp_nexthop_global_in;
		break;

	case AF_INET6:
		vpn_bi->extra->vnc.import.un_family = AF_INET6;
		vpn_bi->extra->vnc.import.un.addr6 =
			encap_bi->attr->mp_nexthop_global;
		break;

	default:
		zlog_warn("%s: invalid encap nexthop length: %d", __func__,
			  encap_bi->attr->mp_nexthop_len);
		vpn_bi->extra->vnc.import.un_family = 0;
		break;
	}
}

/*
 * returns 0 on success, nonzero on error
 */
static int rfapiWithdrawEncapUpdateCachedUn(
	struct rfapi_import_table *import_table, struct bgp_info *encap_bi,
	struct route_node *vpn_rn, struct bgp_info *vpn_bi)
{
	if (!encap_bi) {

		/*
		 * clear cached UN address
		 */
		if (!vpn_bi || !vpn_bi->extra) {
			zlog_warn(
				"%s: missing VPN bi/extra, can't clear UN addr",
				__func__);
			return 1;
		}
		vpn_bi->extra->vnc.import.un_family = 0;
		memset(&vpn_bi->extra->vnc.import.un, 0,
		       sizeof(vpn_bi->extra->vnc.import.un));
		if (CHECK_FLAG(vpn_bi->flags, BGP_INFO_VALID)) {
			if (rfapiGetVncTunnelUnAddr(vpn_bi->attr, NULL)) {
				UNSET_FLAG(vpn_bi->flags, BGP_INFO_VALID);
				if (VALID_INTERIOR_TYPE(vpn_bi->type))
					RFAPI_MONITOR_EXTERIOR(vpn_rn)
						->valid_interior_count--;
				/* signal interior route withdrawal to
				 * import-exterior */
				vnc_import_bgp_exterior_del_route_interior(
					bgp_get_default(), import_table, vpn_rn,
					vpn_bi);
			}
		}

	} else {
		if (!vpn_bi) {
			zlog_warn("%s: missing VPN bi, can't clear UN addr",
				  __func__);
			return 1;
		}
		rfapiCopyUnEncap2VPN(encap_bi, vpn_bi);
		if (!CHECK_FLAG(vpn_bi->flags, BGP_INFO_VALID)) {
			SET_FLAG(vpn_bi->flags, BGP_INFO_VALID);
			if (VALID_INTERIOR_TYPE(vpn_bi->type))
				RFAPI_MONITOR_EXTERIOR(vpn_rn)
					->valid_interior_count++;
			/* signal interior route withdrawal to import-exterior
			 */
			vnc_import_bgp_exterior_add_route_interior(
				bgp_get_default(), import_table, vpn_rn,
				vpn_bi);
		}
	}
	return 0;
}

static int rfapiWithdrawTimerEncap(struct thread *t)
{
	struct rfapi_withdraw *wcb = t->arg;
	struct bgp_info *bi = wcb->info;
	int was_first_route = 0;
	struct rfapi_monitor_encap *em;
	struct skiplist *vpn_node_sl = skiplist_new(0, NULL, NULL);

	assert(wcb->node);
	assert(bi);
	assert(wcb->import_table);

	RFAPI_CHECK_REFCOUNT(wcb->node, SAFI_ENCAP, 0);

	if (wcb->node->info == bi)
		was_first_route = 1;

	/*
	 * Remove the route/bi and free it
	 */
	rfapiBgpInfoDetach(wcb->node, bi);
	rfapiBgpInfoFree(bi);

	if (!was_first_route)
		goto done;

	for (em = RFAPI_MONITOR_ENCAP(wcb->node); em; em = em->next) {

		/*
		 * Update monitoring VPN BIs with new encap info at the
		 * head of the encap bi chain (which could be NULL after
		 * removing the expiring bi above)
		 */
		if (rfapiWithdrawEncapUpdateCachedUn(wcb->import_table,
						     wcb->node->info, em->node,
						     em->bi))
			continue;

		/*
		 * Build a list of unique VPN nodes referenced by these
		 * monitors.
		 * Use a skiplist for speed.
		 */
		skiplist_insert(vpn_node_sl, em->node, em->node);
	}


	/*
	 * for each VPN node referenced in the ENCAP monitors:
	 */
	struct route_node *rn;
	while (!skiplist_first(vpn_node_sl, (void **)&rn, NULL)) {
		if (!wcb->node->info) {
			struct rfapi_monitor_vpn *moved;

			moved = rfapiMonitorMoveShorter(rn, 0);
			if (moved) {
				// rfapiDoRouteCallback(wcb->import_table,
				// moved->node, moved);
				rfapiMonitorMovedUp(wcb->import_table, rn,
						    moved->node, moved);
			}
		} else {
			// rfapiDoRouteCallback(wcb->import_table, rn, NULL);
			rfapiMonitorItNodeChanged(wcb->import_table, rn, NULL);
		}
		skiplist_delete_first(vpn_node_sl);
	}

done:
	RFAPI_CHECK_REFCOUNT(wcb->node, SAFI_ENCAP, 1);
	route_unlock_node(wcb->node); /* decr ref count */
	XFREE(MTYPE_RFAPI_WITHDRAW, wcb);
	skiplist_free(vpn_node_sl);
	return 0;
}


/*
 * Works for both VPN and ENCAP routes; timer_service_func is different
 * in each case
 */
static void
rfapiBiStartWithdrawTimer(struct rfapi_import_table *import_table,
			  struct route_node *rn, struct bgp_info *bi, afi_t afi,
			  safi_t safi,
			  int (*timer_service_func)(struct thread *))
{
	uint32_t lifetime;
	struct rfapi_withdraw *wcb;

	if
		CHECK_FLAG(bi->flags, BGP_INFO_REMOVED)
		{
			/*
			 * Already on the path to being withdrawn,
			 * should already have a timer set up to
			 * delete it.
			 */
			vnc_zlog_debug_verbose(
				"%s: already being withdrawn, do nothing",
				__func__);
			return;
		}

	rfapiGetVncLifetime(bi->attr, &lifetime);
	vnc_zlog_debug_verbose("%s: VNC lifetime is %u", __func__, lifetime);

	/*
	 * withdrawn routes get to hang around for a while
	 */
	SET_FLAG(bi->flags, BGP_INFO_REMOVED);

	/* set timer to remove the route later */
	lifetime = rfapiGetHolddownFromLifetime(lifetime);
	vnc_zlog_debug_verbose("%s: using timeout %u", __func__, lifetime);

	/*
	 * Stash import_table, node, and info for use by timer
	 * service routine, which is supposed to free the wcb.
	 */
	wcb = XCALLOC(MTYPE_RFAPI_WITHDRAW, sizeof(struct rfapi_withdraw));
	assert(wcb);
	wcb->node = rn;
	wcb->info = bi;
	wcb->import_table = import_table;
	bgp_attr_intern(bi->attr);

	if (VNC_DEBUG(VERBOSE)) {
		vnc_zlog_debug_verbose(
			"%s: wcb values: node=%p, info=%p, import_table=%p (bi follows)",
			__func__, wcb->node, wcb->info, wcb->import_table);
		rfapiPrintBi(NULL, bi);
	}


	assert(bi->extra);
	if (lifetime > UINT32_MAX / 1001) {
		/* sub-optimal case, but will probably never happen */
		bi->extra->vnc.import.timer = NULL;
		thread_add_timer(bm->master, timer_service_func, wcb, lifetime,
				 &bi->extra->vnc.import.timer);
	} else {
		static uint32_t jitter;
		uint32_t lifetime_msec;

		/*
		 * the goal here is to spread out the timers so they are
		 * sortable in the skip list
		 */
		if (++jitter >= 1000)
			jitter = 0;

		lifetime_msec = (lifetime * 1000) + jitter;

		bi->extra->vnc.import.timer = NULL;
		thread_add_timer_msec(bm->master, timer_service_func, wcb,
				      lifetime_msec,
				      &bi->extra->vnc.import.timer);
	}

	/* re-sort route list (BGP_INFO_REMOVED routes are last) */
	if (((struct bgp_info *)rn->info)->next) {
		rfapiBgpInfoDetach(rn, bi);
		rfapiBgpInfoAttachSorted(rn, bi, afi, safi);
	}
}


typedef void(rfapi_bi_filtered_import_f)(struct rfapi_import_table *, int,
					 struct peer *, void *, struct prefix *,
					 struct prefix *, afi_t,
					 struct prefix_rd *, struct attr *,
					 u_char, u_char, uint32_t *);


static void rfapiExpireEncapNow(struct rfapi_import_table *it,
				struct route_node *rn, struct bgp_info *bi)
{
	struct rfapi_withdraw *wcb;
	struct thread t;

	/*
	 * pretend we're an expiring timer
	 */
	wcb = XCALLOC(MTYPE_RFAPI_WITHDRAW, sizeof(struct rfapi_withdraw));
	wcb->info = bi;
	wcb->node = rn;
	wcb->import_table = it;
	memset(&t, 0, sizeof(t));
	t.arg = wcb;
	rfapiWithdrawTimerEncap(&t); /* frees wcb */
}

static int rfapiGetNexthop(struct attr *attr, struct prefix *prefix)
{
	switch (BGP_MP_NEXTHOP_FAMILY(attr->mp_nexthop_len)) {
	case AF_INET:
		prefix->family = AF_INET;
		prefix->prefixlen = 32;
		prefix->u.prefix4 = attr->mp_nexthop_global_in;
		break;
	case AF_INET6:
		prefix->family = AF_INET6;
		prefix->prefixlen = 128;
		prefix->u.prefix6 = attr->mp_nexthop_global;
		break;
	default:
		vnc_zlog_debug_verbose("%s: unknown attr->mp_nexthop_len %d",
				       __func__, attr->mp_nexthop_len);
		return EINVAL;
	}
	return 0;
}

/*
 * import a bgp_info if its route target list intersects with the
 * import table's route target list
 */
static void rfapiBgpInfoFilteredImportEncap(
	struct rfapi_import_table *import_table, int action, struct peer *peer,
	void *rfd, /* set for looped back routes */
	struct prefix *p,
	struct prefix *aux_prefix, /* Unused for encap routes */
	afi_t afi, struct prefix_rd *prd,
	struct attr *attr, /* part of bgp_info */
	u_char type,       /* part of bgp_info */
	u_char sub_type,   /* part of bgp_info */
	uint32_t *label)   /* part of bgp_info */
{
	struct route_table *rt = NULL;
	struct route_node *rn;
	struct bgp_info *info_new;
	struct bgp_info *bi;
	struct bgp_info *next;
	char buf[BUFSIZ];

	struct prefix p_firstbi_old;
	struct prefix p_firstbi_new;
	int replacing = 0;
	const char *action_str = NULL;
	struct prefix un_prefix;

	struct bgp *bgp;
	bgp = bgp_get_default(); /* assume 1 instance for now */

	switch (action) {
	case FIF_ACTION_UPDATE:
		action_str = "update";
		break;
	case FIF_ACTION_WITHDRAW:
		action_str = "withdraw";
		break;
	case FIF_ACTION_KILL:
		action_str = "kill";
		break;
	default:
		assert(0);
		break;
	}

	vnc_zlog_debug_verbose(
		"%s: entry: %s: prefix %s/%d", __func__, action_str,
		inet_ntop(p->family, &p->u.prefix, buf, BUFSIZ), p->prefixlen);

	memset(&p_firstbi_old, 0, sizeof(p_firstbi_old));
	memset(&p_firstbi_new, 0, sizeof(p_firstbi_new));

	if (action == FIF_ACTION_UPDATE) {
		/*
		 * Compare rt lists. If no intersection, don't import this route
		 * On a withdraw, peer and RD are sufficient to determine if
		 * we should act.
		 */
		if (!attr || !attr->ecommunity) {

			vnc_zlog_debug_verbose(
				"%s: attr, extra, or ecommunity missing, not importing",
				__func__);
			return;
		}
#if RFAPI_REQUIRE_ENCAP_BEEC
		if (!rfapiEcommunitiesMatchBeec(attr->ecommunity)) {
			vnc_zlog_debug_verbose(
				"%s: it=%p: no match for BGP Encapsulation ecommunity",
				__func__, import_table);
			return;
		}
#endif
		if (!rfapiEcommunitiesIntersect(import_table->rt_import_list,
						attr->ecommunity)) {

			vnc_zlog_debug_verbose(
				"%s: it=%p: no ecommunity intersection",
				__func__, import_table);
			return;
		}

		/*
		 * Updates must also have a nexthop address
		 */
		memset(&un_prefix, 0,
		       sizeof(un_prefix)); /* keep valgrind happy */
		if (rfapiGetNexthop(attr, &un_prefix)) {
			vnc_zlog_debug_verbose("%s: missing nexthop address",
					       __func__);
			return;
		}
	}

	/*
	 * Figure out which radix tree the route would go into
	 */
	switch (afi) {
	case AFI_IP:
	case AFI_IP6:
		rt = import_table->imported_encap[afi];
		break;

	default:
		zlog_err("%s: bad afi %d", __func__, afi);
		return;
	}

	/*
	 * route_node_lookup returns a node only if there is at least
	 * one route attached.
	 */
	rn = route_node_lookup(rt, p);

#if DEBUG_ENCAP_MONITOR
	vnc_zlog_debug_verbose("%s: initial encap lookup(it=%p) rn=%p",
			       __func__, import_table, rn);
#endif

	if (rn) {

		RFAPI_CHECK_REFCOUNT(rn, SAFI_ENCAP, 1);
		route_unlock_node(rn); /* undo lock in route_node_lookup */


		/*
		 * capture nexthop of first bi
		 */
		if (rn->info) {
			rfapiNexthop2Prefix(
				((struct bgp_info *)(rn->info))->attr,
				&p_firstbi_old);
		}

		for (bi = rn->info; bi; bi = bi->next) {

			/*
			 * Does this bgp_info refer to the same route
			 * as we are trying to add?
			 */
			vnc_zlog_debug_verbose("%s: comparing BI %p", __func__,
					       bi);


			/*
			 * Compare RDs
			 *
			 * RD of import table bi is in bi->extra->vnc.import.rd
			 * RD of info_orig is in prd
			 */
			if (!bi->extra) {
				vnc_zlog_debug_verbose("%s: no bi->extra",
						       __func__);
				continue;
			}
			if (prefix_cmp(
				    (struct prefix *)&bi->extra->vnc.import.rd,
				    (struct prefix *)prd)) {

				vnc_zlog_debug_verbose("%s: prd does not match",
						       __func__);
				continue;
			}

			/*
			 * Compare peers
			 */
			if (bi->peer != peer) {
				vnc_zlog_debug_verbose(
					"%s: peer does not match", __func__);
				continue;
			}

			vnc_zlog_debug_verbose("%s: found matching bi",
					       __func__);

			/* Same route. Delete this bi, replace with new one */

			if (action == FIF_ACTION_WITHDRAW) {

				vnc_zlog_debug_verbose(
					"%s: withdrawing at prefix %s/%d",
					__func__,
					inet_ntop(rn->p.family, &rn->p.u.prefix,
						  buf, BUFSIZ),
					rn->p.prefixlen);

				rfapiBiStartWithdrawTimer(
					import_table, rn, bi, afi, SAFI_ENCAP,
					rfapiWithdrawTimerEncap);

			} else {
				vnc_zlog_debug_verbose(
					"%s: %s at prefix %s/%d", __func__,
					((action == FIF_ACTION_KILL)
						 ? "killing"
						 : "replacing"),
					inet_ntop(rn->p.family, &rn->p.u.prefix,
						  buf, BUFSIZ),
					rn->p.prefixlen);

				/*
				 * If this route is waiting to be deleted
				 * because of
				 * a previous withdraw, we must cancel its
				 * timer.
				 */
				if (CHECK_FLAG(bi->flags, BGP_INFO_REMOVED)
				    && bi->extra->vnc.import.timer) {

					struct thread *t =
						(struct thread *)bi->extra->vnc
							.import.timer;
					struct rfapi_withdraw *wcb = t->arg;

					XFREE(MTYPE_RFAPI_WITHDRAW, wcb);
					thread_cancel(t);
				}

				if (action == FIF_ACTION_UPDATE) {
					rfapiBgpInfoDetach(rn, bi);
					rfapiBgpInfoFree(bi);
					replacing = 1;
				} else {
					/*
					 * Kill: do export stuff when removing
					 * bi
					 */
					struct rfapi_withdraw *wcb;
					struct thread t;

					/*
					 * pretend we're an expiring timer
					 */
					wcb = XCALLOC(
						MTYPE_RFAPI_WITHDRAW,
						sizeof(struct rfapi_withdraw));
					wcb->info = bi;
					wcb->node = rn;
					wcb->import_table = import_table;
					memset(&t, 0, sizeof(t));
					t.arg = wcb;
					rfapiWithdrawTimerEncap(
						&t); /* frees wcb */
				}
			}

			break;
		}
	}

	if (rn)
		RFAPI_CHECK_REFCOUNT(rn, SAFI_ENCAP, replacing ? 1 : 0);

	if (action == FIF_ACTION_WITHDRAW || action == FIF_ACTION_KILL)
		return;

	info_new =
		rfapiBgpInfoCreate(attr, peer, rfd, prd, type, sub_type, NULL);

	if (rn) {
		if (!replacing)
			route_lock_node(rn); /* incr ref count for new BI */
	} else {
		rn = route_node_get(rt, p);
	}

	vnc_zlog_debug_verbose(
		"%s: (afi=%d, rn=%p) inserting at prefix %s/%d", __func__, afi,
		rn, inet_ntop(rn->p.family, &rn->p.u.prefix, buf, BUFSIZ),
		rn->p.prefixlen);

	rfapiBgpInfoAttachSorted(rn, info_new, afi, SAFI_ENCAP);

	/*
	 * Delete holddown routes from same NVE. See details in
	 * rfapiBgpInfoFilteredImportVPN()
	 */
	for (bi = info_new->next; bi; bi = next) {

		struct prefix pfx_un;
		int un_match = 0;

		next = bi->next;
		if (!CHECK_FLAG(bi->flags, BGP_INFO_REMOVED))
			continue;

		/*
		 * We already match the VN address (it is the prefix
		 * of the route node)
		 */

		if (!rfapiGetNexthop(bi->attr, &pfx_un)
		    && prefix_same(&pfx_un, &un_prefix)) {

			un_match = 1;
		}

		if (!un_match)
			continue;

		vnc_zlog_debug_verbose(
			"%s: removing holddown bi matching NVE of new route",
			__func__);
		if (bi->extra->vnc.import.timer) {
			struct thread *t =
				(struct thread *)bi->extra->vnc.import.timer;
			struct rfapi_withdraw *wcb = t->arg;

			XFREE(MTYPE_RFAPI_WITHDRAW, wcb);
			thread_cancel(t);
		}
		rfapiExpireEncapNow(import_table, rn, bi);
	}

	rfapiNexthop2Prefix(((struct bgp_info *)(rn->info))->attr,
			    &p_firstbi_new);

	/*
	 * If the nexthop address of the selected Encap route (i.e.,
	 * the UN address) has changed, then we must update the VPN
	 * routes that refer to this Encap route and possibly force
	 * rfapi callbacks.
	 */
	if (rfapiAttrNexthopAddrDifferent(&p_firstbi_old, &p_firstbi_new)) {

		struct rfapi_monitor_encap *m;
		struct rfapi_monitor_encap *mnext;

		struct route_node *referenced_vpn_prefix;

		/*
		 * Optimized approach: build radix tree on the fly to
		 * hold list of VPN nodes referenced by the ENCAP monitors
		 *
		 * The nodes in this table correspond to prefixes of VPN routes.
		 * The "info" pointer of the node points to a chain of
		 * struct rfapi_monitor_encap, each of which refers to a
		 * specific VPN node.
		 */
		struct route_table *referenced_vpn_table;

		referenced_vpn_table = route_table_init();
		assert(referenced_vpn_table);

/*
 * iterate over the set of monitors at this ENCAP node.
 */
#if DEBUG_ENCAP_MONITOR
		vnc_zlog_debug_verbose("%s: examining monitors at rn=%p",
				       __func__, rn);
#endif
		for (m = RFAPI_MONITOR_ENCAP(rn); m; m = m->next) {

			/*
			 * For each referenced bi/route, copy the ENCAP route's
			 * nexthop to the VPN route's cached UN address field
			 * and set
			 * the address family of the cached UN address field.
			 */
			rfapiCopyUnEncap2VPN(info_new, m->bi);
			if (!CHECK_FLAG(m->bi->flags, BGP_INFO_VALID)) {
				SET_FLAG(m->bi->flags, BGP_INFO_VALID);
				if (VALID_INTERIOR_TYPE(m->bi->type))
					RFAPI_MONITOR_EXTERIOR(m->node)
						->valid_interior_count++;
				vnc_import_bgp_exterior_add_route_interior(
					bgp, import_table, m->node, m->bi);
			}

			/*
			 * Build a list of unique VPN nodes referenced by these
			 * monitors
			 *
			 * There could be more than one VPN node here with a
			 * given
			 * prefix. Those are currently in an unsorted linear
			 * list
			 * per prefix.
			 */

			referenced_vpn_prefix = route_node_get(
				referenced_vpn_table, &m->node->p);
			assert(referenced_vpn_prefix);
			for (mnext = referenced_vpn_prefix->info; mnext;
			     mnext = mnext->next) {

				if (mnext->node == m->node)
					break;
			}

			if (mnext) {
				/*
				 * already have an entry for this VPN node
				 */
				route_unlock_node(referenced_vpn_prefix);
			} else {
				mnext = XCALLOC(
					MTYPE_RFAPI_MONITOR_ENCAP,
					sizeof(struct rfapi_monitor_encap));
				assert(mnext);
				mnext->node = m->node;
				mnext->next = referenced_vpn_prefix->info;
				referenced_vpn_prefix->info = mnext;
			}
		}

		/*
		 * for each VPN node referenced in the ENCAP monitors:
		 */
		for (referenced_vpn_prefix = route_top(referenced_vpn_table);
		     referenced_vpn_prefix; referenced_vpn_prefix = route_next(
						    referenced_vpn_prefix)) {

			while ((m = referenced_vpn_prefix->info)) {

				struct route_node *n;

				rfapiMonitorMoveLonger(m->node);
				for (n = m->node; n; n = n->parent) {
					// rfapiDoRouteCallback(import_table, n,
					// NULL);
				}
				rfapiMonitorItNodeChanged(import_table, m->node,
							  NULL);

				referenced_vpn_prefix->info = m->next;
				route_unlock_node(referenced_vpn_prefix);
				XFREE(MTYPE_RFAPI_MONITOR_ENCAP, m);
			}
		}
		route_table_finish(referenced_vpn_table);
	}

	RFAPI_CHECK_REFCOUNT(rn, SAFI_ENCAP, 0);
}

static void rfapiExpireVpnNow(struct rfapi_import_table *it,
			      struct route_node *rn, struct bgp_info *bi,
			      int lockoffset)
{
	struct rfapi_withdraw *wcb;
	struct thread t;

	/*
	 * pretend we're an expiring timer
	 */
	wcb = XCALLOC(MTYPE_RFAPI_WITHDRAW, sizeof(struct rfapi_withdraw));
	wcb->info = bi;
	wcb->node = rn;
	wcb->import_table = it;
	wcb->lockoffset = lockoffset;
	memset(&t, 0, sizeof(t));
	t.arg = wcb;
	rfapiWithdrawTimerVPN(&t); /* frees wcb */
}


/*
 * import a bgp_info if its route target list intersects with the
 * import table's route target list
 */
void rfapiBgpInfoFilteredImportVPN(
	struct rfapi_import_table *import_table, int action, struct peer *peer,
	void *rfd, /* set for looped back routes */
	struct prefix *p,
	struct prefix *aux_prefix, /* AFI_L2VPN: optional IP */
	afi_t afi, struct prefix_rd *prd,
	struct attr *attr, /* part of bgp_info */
	u_char type,       /* part of bgp_info */
	u_char sub_type,   /* part of bgp_info */
	uint32_t *label)   /* part of bgp_info */
{
	struct route_table *rt = NULL;
	struct route_node *rn;
	struct route_node *n;
	struct bgp_info *info_new;
	struct bgp_info *bi;
	struct bgp_info *next;
	char buf[BUFSIZ];
	struct prefix vn_prefix;
	struct prefix un_prefix;
	int un_prefix_valid = 0;
	struct route_node *ern;
	int replacing = 0;
	int original_had_routes = 0;
	struct prefix original_nexthop;
	const char *action_str = NULL;
	int is_it_ce = 0;

	struct bgp *bgp;
	bgp = bgp_get_default(); /* assume 1 instance for now */

	switch (action) {
	case FIF_ACTION_UPDATE:
		action_str = "update";
		break;
	case FIF_ACTION_WITHDRAW:
		action_str = "withdraw";
		break;
	case FIF_ACTION_KILL:
		action_str = "kill";
		break;
	default:
		assert(0);
		break;
	}

	if (import_table == bgp->rfapi->it_ce)
		is_it_ce = 1;

	vnc_zlog_debug_verbose("%s: entry: %s%s: prefix %s/%d: it %p, afi %s",
			       __func__, (is_it_ce ? "CE-IT " : ""), action_str,
			       rfapi_ntop(p->family, &p->u.prefix, buf, BUFSIZ),
			       p->prefixlen, import_table, afi2str(afi));

	VNC_ITRCCK;

	/*
	 * Compare rt lists. If no intersection, don't import this route
	 * On a withdraw, peer and RD are sufficient to determine if
	 * we should act.
	 */
	if (action == FIF_ACTION_UPDATE) {
		if (!attr || !attr->ecommunity) {

			vnc_zlog_debug_verbose(
				"%s: attr, extra, or ecommunity missing, not importing",
				__func__);
			return;
		}
		if ((import_table != bgp->rfapi->it_ce)
		    && !rfapiEcommunitiesIntersect(import_table->rt_import_list,
						   attr->ecommunity)) {

			vnc_zlog_debug_verbose(
				"%s: it=%p: no ecommunity intersection",
				__func__, import_table);
			return;
		}

		memset(&vn_prefix, 0,
		       sizeof(vn_prefix)); /* keep valgrind happy */
		if (rfapiGetNexthop(attr, &vn_prefix)) {
			/* missing nexthop address would be a bad, bad thing */
			vnc_zlog_debug_verbose("%s: missing nexthop", __func__);
			return;
		}
	}

	/*
	 * Figure out which radix tree the route would go into
	 */
	switch (afi) {
	case AFI_IP:
	case AFI_IP6:
	case AFI_L2VPN:
		rt = import_table->imported_vpn[afi];
		break;

	default:
		zlog_err("%s: bad afi %d", __func__, afi);
		return;
	}

	/* clear it */
	memset(&original_nexthop, 0, sizeof(original_nexthop));

	/*
	 * route_node_lookup returns a node only if there is at least
	 * one route attached.
	 */
	rn = route_node_lookup(rt, p);

	vnc_zlog_debug_verbose("%s: rn=%p", __func__, rn);

	if (rn) {

		RFAPI_CHECK_REFCOUNT(rn, SAFI_MPLS_VPN, 1);
		route_unlock_node(rn); /* undo lock in route_node_lookup */

		if (rn->info)
			original_had_routes = 1;

		if (VNC_DEBUG(VERBOSE)) {
			vnc_zlog_debug_verbose("%s: showing IT node on entry",
					       __func__);
			rfapiShowItNode(NULL, rn); /* debug */
		}

		/*
		 * Look for same route (will have same RD and peer)
		 */
		bi = rfapiItBiIndexSearch(rn, prd, peer, aux_prefix);

		if (bi) {

			/*
			 * This was an old test when we iterated over the
			 * BIs linearly. Since we're now looking up with
			 * RD and peer, comparing types should not be
			 * needed. Changed to assertion.
			 *
			 * Compare types. Doing so prevents a RFP-originated
			 * route from matching an imported route, for example.
			 */
			if (VNC_DEBUG(VERBOSE) && bi->type != type)
				/* should be handled by RDs, but warn for now */
				zlog_warn("%s: type mismatch! (bi=%d, arg=%d)",
					  __func__, bi->type, type);

			vnc_zlog_debug_verbose("%s: found matching bi",
					       __func__);

			/*
			 * In the special CE table, withdrawals occur without
			 * holddown
			 */
			if (import_table == bgp->rfapi->it_ce) {
				vnc_direct_bgp_del_route_ce(bgp, rn, bi);
				if (action == FIF_ACTION_WITHDRAW)
					action = FIF_ACTION_KILL;
			}

			if (action == FIF_ACTION_WITHDRAW) {

				int washolddown =
					CHECK_FLAG(bi->flags, BGP_INFO_REMOVED);

				vnc_zlog_debug_verbose(
					"%s: withdrawing at prefix %s/%d%s",
					__func__, rfapi_ntop(rn->p.family,
							     &rn->p.u.prefix,
							     buf, BUFSIZ),
					rn->p.prefixlen,
					(washolddown
						 ? " (already being withdrawn)"
						 : ""));

				VNC_ITRCCK;
				if (!washolddown) {
					rfapiBiStartWithdrawTimer(
						import_table, rn, bi, afi,
						SAFI_MPLS_VPN,
						rfapiWithdrawTimerVPN);

					RFAPI_UPDATE_ITABLE_COUNT(
						bi, import_table, afi, -1);
					import_table->holddown_count[afi] += 1;
				}
				VNC_ITRCCK;
			} else {
				vnc_zlog_debug_verbose(
					"%s: %s at prefix %s/%d", __func__,
					((action == FIF_ACTION_KILL)
						 ? "killing"
						 : "replacing"),
					rfapi_ntop(rn->p.family,
						   &rn->p.u.prefix, buf,
						   BUFSIZ),
					rn->p.prefixlen);

				/*
				 * If this route is waiting to be deleted
				 * because of
				 * a previous withdraw, we must cancel its
				 * timer.
				 */
				if (CHECK_FLAG(bi->flags, BGP_INFO_REMOVED)
				    && bi->extra->vnc.import.timer) {

					struct thread *t =
						(struct thread *)bi->extra->vnc
							.import.timer;
					struct rfapi_withdraw *wcb = t->arg;

					XFREE(MTYPE_RFAPI_WITHDRAW, wcb);
					thread_cancel(t);

					import_table->holddown_count[afi] -= 1;
					RFAPI_UPDATE_ITABLE_COUNT(
						bi, import_table, afi, 1);
				}
				/*
				 * decrement remote count (if route is remote)
				 * because
				 * we are going to remove it below
				 */
				RFAPI_UPDATE_ITABLE_COUNT(bi, import_table, afi,
							  -1);
				if (action == FIF_ACTION_UPDATE) {
					replacing = 1;

					/*
					 * make copy of original nexthop so we
					 * can see if it changed
					 */
					rfapiGetNexthop(bi->attr,
							&original_nexthop);

					/*
					 * remove bi without doing any export
					 * processing
					 */
					if (CHECK_FLAG(bi->flags,
						       BGP_INFO_VALID)
					    && VALID_INTERIOR_TYPE(bi->type))
						RFAPI_MONITOR_EXTERIOR(rn)
							->valid_interior_count--;
					rfapiItBiIndexDel(rn, bi);
					rfapiBgpInfoDetach(rn, bi);
					rfapiMonitorEncapDelete(bi);
					vnc_import_bgp_exterior_del_route_interior(
						bgp, import_table, rn, bi);
					rfapiBgpInfoFree(bi);
				} else {
					/* Kill */
					/*
					 * remove bi and do export processing
					 */
					import_table->holddown_count[afi] += 1;
					rfapiExpireVpnNow(import_table, rn, bi,
							  0);
				}
			}
		}
	}

	if (rn)
		RFAPI_CHECK_REFCOUNT(rn, SAFI_MPLS_VPN, replacing ? 1 : 0);

	if (action == FIF_ACTION_WITHDRAW || action == FIF_ACTION_KILL) {
		VNC_ITRCCK;
		return;
	}

	info_new =
		rfapiBgpInfoCreate(attr, peer, rfd, prd, type, sub_type, label);

	/*
	 * lookup un address in encap table
	 */
	ern = route_node_match(import_table->imported_encap[afi], &vn_prefix);
	if (ern) {
		rfapiCopyUnEncap2VPN(ern->info, info_new);
		route_unlock_node(ern); /* undo lock in route_note_match */
	} else {
		char buf[PREFIX_STRLEN];

		prefix2str(&vn_prefix, buf, sizeof(buf));
		/* Not a big deal, just means VPN route got here first */
		vnc_zlog_debug_verbose("%s: no encap route for vn addr %s",
				       __func__, buf);
		info_new->extra->vnc.import.un_family = 0;
	}

	if (rn) {
		if (!replacing)
			route_lock_node(rn);
	} else {
		/*
		 * No need to increment reference count, so only "get"
		 * if the node is not there already
		 */
		rn = route_node_get(rt, p);
	}

	/*
	 * For ethernet routes, if there is an accompanying IP address,
	 * save it in the bi
	 */
	if ((AFI_L2VPN == afi) && aux_prefix) {

		vnc_zlog_debug_verbose("%s: setting BI's aux_prefix", __func__);
		info_new->extra->vnc.import.aux_prefix = *aux_prefix;
	}

	vnc_zlog_debug_verbose(
		"%s: inserting bi %p at prefix %s/%d #%d", __func__, info_new,
		rfapi_ntop(rn->p.family, &rn->p.u.prefix, buf, BUFSIZ),
		rn->p.prefixlen, rn->lock);

	rfapiBgpInfoAttachSorted(rn, info_new, afi, SAFI_MPLS_VPN);
	rfapiItBiIndexAdd(rn, info_new);
	if (!rfapiGetUnAddrOfVpnBi(info_new, NULL)) {
		if (VALID_INTERIOR_TYPE(info_new->type))
			RFAPI_MONITOR_EXTERIOR(rn)->valid_interior_count++;
		SET_FLAG(info_new->flags, BGP_INFO_VALID);
	}
	RFAPI_UPDATE_ITABLE_COUNT(info_new, import_table, afi, 1);
	vnc_import_bgp_exterior_add_route_interior(bgp, import_table, rn,
						   info_new);

	if (import_table == bgp->rfapi->it_ce)
		vnc_direct_bgp_add_route_ce(bgp, rn, info_new);

	if (VNC_DEBUG(VERBOSE)) {
		vnc_zlog_debug_verbose("%s: showing IT node", __func__);
		rfapiShowItNode(NULL, rn); /* debug */
	}

	rfapiMonitorEncapAdd(import_table, &vn_prefix, rn, info_new);

	if (!rfapiGetUnAddrOfVpnBi(info_new, &un_prefix)) {

		/*
		 * if we have a valid UN address (either via Encap route
		 * or via tunnel attribute), then we should attempt
		 * to move any monitors at less-specific nodes to this node
		 */
		rfapiMonitorMoveLonger(rn);

		un_prefix_valid = 1;
	}

	/*
	 * 101129 Enhancement: if we add a route (implication: it is not
	 * in holddown), delete all other routes from this nve at this
	 * node that are in holddown, regardless of peer.
	 *
	 * Reasons it's OK to do that:
	 *
	 * - if the holddown route being deleted originally came from BGP VPN,
	 *   it is already gone from BGP (implication of holddown), so there
	 *   won't be any added inconsistency with the BGP RIB.
	 *
	 * - once a fresh route is added at a prefix, any routes in holddown
	 *   at that prefix will not show up in RFP responses, so deleting
	 *   the holddown routes won't affect the contents of responses.
	 *
	 * - lifetimes are supposed to be consistent, so there should not
	 *   be a case where the fresh route has a shorter lifetime than
	 *   the holddown route, so we don't expect the fresh route to
	 *   disappear and complete its holddown time before the existing
	 *   holddown routes time out. Therefore, we won't have a situation
	 *   where we expect the existing holddown routes to be hidden and
	 *   then  to reappear sometime later (as holddown routes) in a
	 *   RFP response.
	 *
	 * Among other things, this would enable us to skirt the problem
	 * of local holddown routes that refer to NVE descriptors that
	 * have already been closed (if the same NVE triggers a subsequent
	 * rfapi_open(), the new peer is different and doesn't match the
	 * peer of the holddown route, so the stale holddown route still
	 * hangs around until it times out instead of just being replaced
	 * by the fresh route).
	 */
	/*
	 * We know that the new bi will have been inserted before any routes
	 * in holddown, so we can skip any that came before it
	 */
	for (bi = info_new->next; bi; bi = next) {

		struct prefix pfx_vn;
		struct prefix pfx_un;
		int un_match = 0;
		int remote_peer_match = 0;

		next = bi->next;

		/*
		 * Must be holddown
		 */
		if (!CHECK_FLAG(bi->flags, BGP_INFO_REMOVED))
			continue;

		/*
		 * Must match VN address (nexthop of VPN route)
		 */
		if (rfapiGetNexthop(bi->attr, &pfx_vn))
			continue;
		if (!prefix_same(&pfx_vn, &vn_prefix))
			continue;

		if (un_prefix_valid && /* new route UN addr */
		    !rfapiGetUnAddrOfVpnBi(bi, &pfx_un)
		    &&					/* old route UN addr */
		    prefix_same(&pfx_un, &un_prefix)) { /* compare */
			un_match = 1;
		}
		if (!RFAPI_LOCAL_BI(bi) && !RFAPI_LOCAL_BI(info_new)
		    && sockunion_same(&bi->peer->su, &info_new->peer->su)) {
			/* old & new are both remote, same peer */
			remote_peer_match = 1;
		}

		if (!un_match & !remote_peer_match)
			continue;

		vnc_zlog_debug_verbose(
			"%s: removing holddown bi matching NVE of new route",
			__func__);
		if (bi->extra->vnc.import.timer) {
			struct thread *t =
				(struct thread *)bi->extra->vnc.import.timer;
			struct rfapi_withdraw *wcb = t->arg;

			XFREE(MTYPE_RFAPI_WITHDRAW, wcb);
			thread_cancel(t);
		}
		rfapiExpireVpnNow(import_table, rn, bi, 0);
	}

	if (!original_had_routes) {
		/*
		 * We went from 0 usable routes to 1 usable route. Perform the
		 * "Adding a Route" export process.
		 */
		vnc_direct_bgp_add_prefix(bgp, import_table, rn);
		vnc_zebra_add_prefix(bgp, import_table, rn);
	} else {
		/*
		 * Check for nexthop change event
		 * Note: the prefix_same() test below detects two situations:
		 * 1. route is replaced, new route has different nexthop
		 * 2. new route is added (original_nexthop is 0)
		 */
		struct prefix new_nexthop;

		rfapiGetNexthop(attr, &new_nexthop);
		if (!prefix_same(&original_nexthop, &new_nexthop)) {
			/*
			 * nexthop change event
			 * vnc_direct_bgp_add_prefix() will recompute VN addr
			 * ecommunity
			 */
			vnc_direct_bgp_add_prefix(bgp, import_table, rn);
		}
	}

	if (!(bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_CALLBACK_DISABLE)) {
		for (n = rn; n; n = n->parent) {
			// rfapiDoRouteCallback(import_table, n, NULL);
		}
		rfapiMonitorItNodeChanged(import_table, rn, NULL);
	}
	RFAPI_CHECK_REFCOUNT(rn, SAFI_MPLS_VPN, 0);
	VNC_ITRCCK;
}

static void rfapiBgpInfoFilteredImportBadSafi(
	struct rfapi_import_table *import_table, int action, struct peer *peer,
	void *rfd, /* set for looped back routes */
	struct prefix *p,
	struct prefix *aux_prefix, /* AFI_L2VPN: optional IP */
	afi_t afi, struct prefix_rd *prd,
	struct attr *attr, /* part of bgp_info */
	u_char type,       /* part of bgp_info */
	u_char sub_type,   /* part of bgp_info */
	uint32_t *label)   /* part of bgp_info */
{
	vnc_zlog_debug_verbose("%s: Error, bad safi", __func__);
}

static rfapi_bi_filtered_import_f *
rfapiBgpInfoFilteredImportFunction(safi_t safi)
{
	switch (safi) {
	case SAFI_MPLS_VPN:
		return rfapiBgpInfoFilteredImportVPN;

	case SAFI_ENCAP:
		return rfapiBgpInfoFilteredImportEncap;

	default:
		/* not expected */
		zlog_err("%s: bad safi %d", __func__, safi);
		return rfapiBgpInfoFilteredImportBadSafi;
	}
}

void rfapiProcessUpdate(struct peer *peer,
			void *rfd, /* set when looped from RFP/RFAPI */
			struct prefix *p, struct prefix_rd *prd,
			struct attr *attr, afi_t afi, safi_t safi, u_char type,
			u_char sub_type, uint32_t *label)
{
	struct bgp *bgp;
	struct rfapi *h;
	struct rfapi_import_table *it;
	int has_ip_route = 1;
	uint32_t lni = 0;

	bgp = bgp_get_default(); /* assume 1 instance for now */
	assert(bgp);

	h = bgp->rfapi;
	assert(h);

	/*
	 * look at high-order byte of RD. FF means MAC
	 * address is present (VNC L2VPN)
	 */
	if ((safi == SAFI_MPLS_VPN)
	    && (decode_rd_type(prd->val) == RD_TYPE_VNC_ETH)) {
		struct prefix pfx_mac_buf;
		struct prefix pfx_nexthop_buf;
		int rc;

		/*
		 * Set flag if prefix and nexthop are the same - don't
		 * add the route to normal IP-based import tables
		 */
		if (!rfapiGetNexthop(attr, &pfx_nexthop_buf)) {
			if (!prefix_cmp(&pfx_nexthop_buf, p)) {
				has_ip_route = 0;
			}
		}

		memset(&pfx_mac_buf, 0, sizeof(pfx_mac_buf));
		pfx_mac_buf.family = AF_ETHERNET;
		pfx_mac_buf.prefixlen = 48;
		memcpy(&pfx_mac_buf.u.prefix_eth.octet, prd->val + 2, 6);

		/*
		 * Find rt containing LNI (Logical Network ID), which
		 * _should_ always be present when mac address is present
		 */
		rc = rfapiEcommunityGetLNI(attr->ecommunity, &lni);

		vnc_zlog_debug_verbose(
			"%s: rfapiEcommunityGetLNI returned %d, lni=%d, attr=%p",
			__func__, rc, lni, attr);
		if (!rc) {
			it = rfapiMacImportTableGet(bgp, lni);

			rfapiBgpInfoFilteredImportVPN(
				it, FIF_ACTION_UPDATE, peer, rfd,
				&pfx_mac_buf, /* prefix */
				p,	    /* aux prefix: IP addr */
				AFI_L2VPN, prd, attr, type, sub_type, label);
		}
	}

	if (!has_ip_route)
		return;

	/*
	 * Iterate over all import tables; do a filtered import
	 * for the afi/safi combination
	 */
	for (it = h->imports; it; it = it->next) {
		(*rfapiBgpInfoFilteredImportFunction(safi))(
			it, FIF_ACTION_UPDATE, peer, rfd, p, /* prefix */
			NULL, afi, prd, attr, type, sub_type, label);
	}

	if (safi == SAFI_MPLS_VPN) {
		vnc_direct_bgp_rh_add_route(bgp, afi, p, peer, attr);
		rfapiBgpInfoFilteredImportVPN(
			bgp->rfapi->it_ce, FIF_ACTION_UPDATE, peer, rfd,
			p, /* prefix */
			NULL, afi, prd, attr, type, sub_type, label);
	}
}


void rfapiProcessWithdraw(struct peer *peer, void *rfd, struct prefix *p,
			  struct prefix_rd *prd, struct attr *attr, afi_t afi,
			  safi_t safi, u_char type, int kill)
{
	struct bgp *bgp;
	struct rfapi *h;
	struct rfapi_import_table *it;

	bgp = bgp_get_default(); /* assume 1 instance for now */
	assert(bgp);

	h = bgp->rfapi;
	assert(h);

	/*
	 * look at high-order byte of RD. FF means MAC
	 * address is present (VNC L2VPN)
	 */
	if (h->import_mac != NULL && safi == SAFI_MPLS_VPN
	    && decode_rd_type(prd->val) == RD_TYPE_VNC_ETH) {
		struct prefix pfx_mac_buf;
		void *cursor = NULL;
		int rc;

		memset(&pfx_mac_buf, 0, sizeof(pfx_mac_buf));
		pfx_mac_buf.family = AF_ETHERNET;
		pfx_mac_buf.prefixlen = 48;
		memcpy(&pfx_mac_buf.u.prefix_eth, prd->val + 2, 6);

		/*
		 * withdraw does not contain attrs, so we don't have
		 * access to the route's LNI, which would ordinarily
		 * select the specific mac-based import table. Instead,
		 * we must iterate over all mac-based tables and rely
		 * on the RD to match.
		 *
		 * If this approach is too slow, add an index where
		 * key is {RD, peer} and value is the import table
		 */
		for (rc = skiplist_next(h->import_mac, NULL, (void **)&it,
					&cursor);
		     rc == 0; rc = skiplist_next(h->import_mac, NULL,
						 (void **)&it, &cursor)) {

#if DEBUG_L2_EXTRA
			vnc_zlog_debug_verbose(
				"%s: calling rfapiBgpInfoFilteredImportVPN(it=%p, afi=AFI_L2VPN)",
				__func__, it);
#endif

			rfapiBgpInfoFilteredImportVPN(
				it,
				(kill ? FIF_ACTION_KILL : FIF_ACTION_WITHDRAW),
				peer, rfd, &pfx_mac_buf, /* prefix */
				p,			 /* aux_prefix: IP */
				AFI_L2VPN, prd, attr, type, 0,
				NULL); /* sub_type & label unused for withdraw
					  */
		}
	}

	/*
	 * XXX For the case where the withdraw involves an L2
	 * route with no IP information, we rely on the lack
	 * of RT-list intersection to filter out the withdraw
	 * from the IP-based import tables below
	 */

	/*
	 * Iterate over all import tables; do a filtered import
	 * for the afi/safi combination
	 */

	for (it = h->imports; it; it = it->next) {
		(*rfapiBgpInfoFilteredImportFunction(safi))(
			it, (kill ? FIF_ACTION_KILL : FIF_ACTION_WITHDRAW),
			peer, rfd, p, /* prefix */
			NULL, afi, prd, attr, type, 0,
			NULL); /* sub_type & label unused for withdraw */
	}

	/* TBD the deletion should happen after the lifetime expires */
	if (safi == SAFI_MPLS_VPN)
		vnc_direct_bgp_rh_del_route(bgp, afi, p, peer);

	if (safi == SAFI_MPLS_VPN) {
		rfapiBgpInfoFilteredImportVPN(
			bgp->rfapi->it_ce,
			(kill ? FIF_ACTION_KILL : FIF_ACTION_WITHDRAW), peer,
			rfd, p, /* prefix */
			NULL, afi, prd, attr, type, 0,
			NULL); /* sub_type & label unused for withdraw */
	}
}

/*
 * TBD optimized withdraw timer algorithm for case of many
 * routes expiring at the same time due to peer drop.
 */
/*
 * 1. Visit all BIs in all ENCAP import tables.
 *
 *    a. If a bi's peer is the failed peer, remove the bi.
 *	  b. If the removed ENCAP bi was first in the list of
 *       BIs at this ENCAP node, loop over all monitors
 *       at this node:
 *
 *       (1) for each ENCAP monitor, loop over all its
 *           VPN node monitors and set their RFAPI_MON_FLAG_NEEDCALLBACK
 *           flags.
 *
 * 2. Visit all BIs in all VPN import tables.
 *    a. If a bi's peer is the failed peer, remove the bi.
 *    b. loop over all the VPN node monitors and set their
 *       RFAPI_MON_FLAG_NEEDCALLBACK flags
 *    c. If there are no BIs left at this VPN node,
 *
 */


/* surprise, this gets called from peer_delete(), from rfapi_close() */
static void rfapiProcessPeerDownRt(struct peer *peer,
				   struct rfapi_import_table *import_table,
				   afi_t afi, safi_t safi)
{
	struct route_node *rn;
	struct bgp_info *bi;
	struct route_table *rt;
	int (*timer_service_func)(struct thread *);

	assert(afi == AFI_IP || afi == AFI_IP6);

	VNC_ITRCCK;

	switch (safi) {
	case SAFI_MPLS_VPN:
		rt = import_table->imported_vpn[afi];
		timer_service_func = rfapiWithdrawTimerVPN;
		break;
	case SAFI_ENCAP:
		rt = import_table->imported_encap[afi];
		timer_service_func = rfapiWithdrawTimerEncap;
		break;
	default:
		assert(0);
	}


	for (rn = route_top(rt); rn; rn = route_next(rn)) {
		for (bi = rn->info; bi; bi = bi->next) {
			if (bi->peer == peer) {

				if (CHECK_FLAG(bi->flags, BGP_INFO_REMOVED)) {
					/* already in holddown, skip */
					continue;
				}

				if (safi == SAFI_MPLS_VPN) {
					RFAPI_UPDATE_ITABLE_COUNT(
						bi, import_table, afi, -1);
					import_table->holddown_count[afi] += 1;
				}
				rfapiBiStartWithdrawTimer(import_table, rn, bi,
							  afi, safi,
							  timer_service_func);
			}
		}
	}
	VNC_ITRCCK;
}

/*
 * This gets called when a peer connection drops. We have to remove
 * all the routes from this peer.
 *
 * Current approach is crude. TBD Optimize by setting fewer timers and
 * grouping withdrawn routes so we can generate callbacks more
 * efficiently.
 */
void rfapiProcessPeerDown(struct peer *peer)
{
	struct bgp *bgp;
	struct rfapi *h;
	struct rfapi_import_table *it;

	/*
	 * If this peer is a "dummy" peer structure atached to a RFAPI
	 * nve_descriptor, we don't need to walk the import tables
	 * because the routes are already withdrawn by rfapi_close()
	 */
	if (CHECK_FLAG(peer->flags, PEER_FLAG_IS_RFAPI_HD))
		return;

	/*
	 * 1. Visit all BIs in all ENCAP import tables.
	 *    Start withdraw timer on the BIs that match peer.
	 *
	 * 2. Visit All BIs in all VPN import tables.
	 *    Start withdraw timer on the BIs that match peer.
	 */

	bgp = bgp_get_default(); /* assume 1 instance for now */
	if (!bgp)
		return;

	h = bgp->rfapi;
	assert(h);

	for (it = h->imports; it; it = it->next) {
		rfapiProcessPeerDownRt(peer, it, AFI_IP, SAFI_ENCAP);
		rfapiProcessPeerDownRt(peer, it, AFI_IP6, SAFI_ENCAP);
		rfapiProcessPeerDownRt(peer, it, AFI_IP, SAFI_MPLS_VPN);
		rfapiProcessPeerDownRt(peer, it, AFI_IP6, SAFI_MPLS_VPN);
	}

	if (h->it_ce) {
		rfapiProcessPeerDownRt(peer, h->it_ce, AFI_IP, SAFI_MPLS_VPN);
		rfapiProcessPeerDownRt(peer, h->it_ce, AFI_IP6, SAFI_MPLS_VPN);
	}
}

/*
 * Import an entire RIB (for an afi/safi) to an import table RIB,
 * filtered according to the import table's RT list
 *
 * TBD: does this function need additions to match rfapiProcessUpdate()
 * for, e.g., L2 handling?
 */
static void rfapiBgpTableFilteredImport(struct bgp *bgp,
					struct rfapi_import_table *it,
					afi_t afi, safi_t safi)
{
	struct bgp_node *rn1;
	struct bgp_node *rn2;

	/* Only these SAFIs have 2-level RIBS */
	assert(safi == SAFI_MPLS_VPN || safi == SAFI_ENCAP);

	/*
	 * Now visit all the rd nodes and the nodes of all the
	 * route tables attached to them, and import the routes
	 * if they have matching route targets
	 */
	for (rn1 = bgp_table_top(bgp->rib[afi][safi]); rn1;
	     rn1 = bgp_route_next(rn1)) {

		if (rn1->info) {
			for (rn2 = bgp_table_top(rn1->info); rn2;
			     rn2 = bgp_route_next(rn2)) {

				struct bgp_info *bi;

				for (bi = rn2->info; bi; bi = bi->next) {
					u_int32_t label = 0;

					if (CHECK_FLAG(bi->flags,
						       BGP_INFO_REMOVED))
						continue;

					if (bi->extra)
						label = decode_label(
							&bi->extra->label[0]);
					(*rfapiBgpInfoFilteredImportFunction(
						safi))(
						it, /* which import table */
						FIF_ACTION_UPDATE, bi->peer,
						NULL, &rn2->p, /* prefix */
						NULL, afi,
						(struct prefix_rd *)&rn1->p,
						bi->attr, bi->type,
						bi->sub_type, &label);
				}
			}
		}
	}
}


/* per-bgp-instance rfapi data */
struct rfapi *bgp_rfapi_new(struct bgp *bgp)
{
	struct rfapi *h;
	afi_t afi;
	struct rfapi_rfp_cfg *cfg = NULL;
	struct rfapi_rfp_cb_methods *cbm = NULL;

	assert(bgp->rfapi_cfg == NULL);

	h = (struct rfapi *)XCALLOC(MTYPE_RFAPI, sizeof(struct rfapi));

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		h->un[afi] = route_table_init();
	}

	/*
	 * initialize the ce import table
	 */
	h->it_ce = XCALLOC(MTYPE_RFAPI_IMPORTTABLE,
			   sizeof(struct rfapi_import_table));
	h->it_ce->imported_vpn[AFI_IP] = route_table_init();
	h->it_ce->imported_vpn[AFI_IP6] = route_table_init();
	h->it_ce->imported_encap[AFI_IP] = route_table_init();
	h->it_ce->imported_encap[AFI_IP6] = route_table_init();
	rfapiBgpTableFilteredImport(bgp, h->it_ce, AFI_IP, SAFI_MPLS_VPN);
	rfapiBgpTableFilteredImport(bgp, h->it_ce, AFI_IP6, SAFI_MPLS_VPN);

	/*
	 * Set up work queue for deferred rfapi_close operations
	 */
	h->deferred_close_q =
		work_queue_new(bm->master, "rfapi deferred close");
	h->deferred_close_q->spec.workfunc = rfapi_deferred_close_workfunc;
	h->deferred_close_q->spec.data = h;

	h->rfp = rfp_start(bm->master, &cfg, &cbm);
	bgp->rfapi_cfg = bgp_rfapi_cfg_new(cfg);
	if (cbm != NULL) {
		h->rfp_methods = *cbm;
	}
	return h;
}

void bgp_rfapi_destroy(struct bgp *bgp, struct rfapi *h)
{
	afi_t afi;

	if (bgp == NULL || h == NULL)
		return;

	if (h->resolve_nve_nexthop) {
		skiplist_free(h->resolve_nve_nexthop);
		h->resolve_nve_nexthop = NULL;
	}

	route_table_finish(h->it_ce->imported_vpn[AFI_IP]);
	route_table_finish(h->it_ce->imported_vpn[AFI_IP6]);
	route_table_finish(h->it_ce->imported_encap[AFI_IP]);
	route_table_finish(h->it_ce->imported_encap[AFI_IP6]);

	if (h->import_mac) {
		struct rfapi_import_table *it;
		void *cursor;
		int rc;

		for (cursor = NULL,
		    rc = skiplist_next(h->import_mac, NULL, (void **)&it,
				       &cursor);
		     !rc; rc = skiplist_next(h->import_mac, NULL, (void **)&it,
					     &cursor)) {

			rfapiImportTableFlush(it);
			XFREE(MTYPE_RFAPI_IMPORTTABLE, it);
		}
		skiplist_free(h->import_mac);
		h->import_mac = NULL;
	}

	work_queue_free(h->deferred_close_q);

	if (h->rfp != NULL)
		rfp_stop(h->rfp);

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		route_table_finish(h->un[afi]);
	}

	XFREE(MTYPE_RFAPI_IMPORTTABLE, h->it_ce);
	XFREE(MTYPE_RFAPI, h);
}

struct rfapi_import_table *
rfapiImportTableRefAdd(struct bgp *bgp, struct ecommunity *rt_import_list,
		       struct rfapi_nve_group_cfg *rfg)
{
	struct rfapi *h;
	struct rfapi_import_table *it;
	afi_t afi;

	h = bgp->rfapi;
	assert(h);

	for (it = h->imports; it; it = it->next) {
		if (ecommunity_cmp(it->rt_import_list, rt_import_list))
			break;
	}

	vnc_zlog_debug_verbose("%s: matched it=%p", __func__, it);

	if (!it) {
		it = XCALLOC(MTYPE_RFAPI_IMPORTTABLE,
			     sizeof(struct rfapi_import_table));
		assert(it);
		it->next = h->imports;
		h->imports = it;

		it->rt_import_list = ecommunity_dup(rt_import_list);
		it->rfg = rfg;
		it->monitor_exterior_orphans =
			skiplist_new(0, NULL, (void (*)(void *))prefix_free);

		/*
		 * fill import route tables from RIBs
		 *
		 * Potential area for optimization. If this occurs when
		 * tables are large (e.g., the operator adds a nve group
		 * with a new RT list to a running system), it could take
		 * a while.
		 *
		 */
		for (afi = AFI_IP; afi < AFI_MAX; ++afi) {

			it->imported_vpn[afi] = route_table_init();
			it->imported_encap[afi] = route_table_init();

			rfapiBgpTableFilteredImport(bgp, it, afi,
						    SAFI_MPLS_VPN);
			rfapiBgpTableFilteredImport(bgp, it, afi, SAFI_ENCAP);

			vnc_import_bgp_exterior_redist_enable_it(bgp, afi, it);
		}
	}

	it->refcount += 1;

	return it;
}

/*
 * skiplist element free function
 */
static void delete_rem_pfx_na_free(void *na)
{
	uint32_t *pCounter = ((struct rfapi_nve_addr *)na)->info;

	*pCounter += 1;
	XFREE(MTYPE_RFAPI_NVE_ADDR, na);
}

/*
 * Common deleter for IP and MAC import tables
 */
static void rfapiDeleteRemotePrefixesIt(
	struct bgp *bgp, struct rfapi_import_table *it, struct prefix *un,
	struct prefix *vn, struct prefix *p, int delete_active,
	int delete_holddown, uint32_t *pARcount, uint32_t *pAHcount,
	uint32_t *pHRcount, uint32_t *pHHcount,
	struct skiplist *uniq_active_nves, struct skiplist *uniq_holddown_nves)
{
	afi_t afi;

#if DEBUG_L2_EXTRA
	{
		char buf_pfx[PREFIX_STRLEN];

		if (p) {
			prefix2str(p, buf_pfx, sizeof(buf_pfx));
		} else {
			buf_pfx[0] = '*';
			buf_pfx[1] = 0;
		}

		vnc_zlog_debug_verbose(
			"%s: entry, p=%s, delete_active=%d, delete_holddown=%d",
			__func__, buf_pfx, delete_active, delete_holddown);
	}
#endif

	for (afi = AFI_IP; afi < AFI_MAX; ++afi) {

		struct route_table *rt;
		struct route_node *rn;

		if (p && (family2afi(p->family) != afi)) {
			continue;
		}

		rt = it->imported_vpn[afi];
		if (!rt)
			continue;

		vnc_zlog_debug_verbose("%s: scanning rt for afi=%d", __func__,
				       afi);

		for (rn = route_top(rt); rn; rn = route_next(rn)) {
			struct bgp_info *bi;
			struct bgp_info *next;

			if (VNC_DEBUG(IMPORT_DEL_REMOTE)) {
				char p1line[PREFIX_STRLEN];
				char p2line[PREFIX_STRLEN];

				prefix2str(p, p1line, sizeof(p1line));
				prefix2str(&rn->p, p2line, sizeof(p2line));
				vnc_zlog_debug_any("%s: want %s, have %s",
						   __func__, p1line, p2line);
			}

			if (p && prefix_cmp(p, &rn->p))
				continue;

			{
				char buf_pfx[PREFIX_STRLEN];

				prefix2str(&rn->p, buf_pfx, sizeof(buf_pfx));
				vnc_zlog_debug_verbose("%s: rn pfx=%s",
						       __func__, buf_pfx);
			}

			/* TBD is this valid for afi == AFI_L2VPN? */
			RFAPI_CHECK_REFCOUNT(rn, SAFI_MPLS_VPN, 1);

			for (bi = rn->info; bi; bi = next) {
				next = bi->next;

				struct prefix qpt;
				struct prefix qct;
				int qpt_valid = 0;
				int qct_valid = 0;
				int is_active = 0;

				vnc_zlog_debug_verbose("%s: examining bi %p",
						       __func__, bi);

				if (bi->attr) {
					if (!rfapiGetNexthop(bi->attr, &qpt))
						qpt_valid = 1;
				}
				if (vn) {
					if (!qpt_valid
					    || !prefix_match(vn, &qpt)) {
#if DEBUG_L2_EXTRA
						vnc_zlog_debug_verbose(
							"%s: continue at vn && !qpt_valid || !prefix_match(vn, &qpt)",
							__func__);
#endif
						continue;
					}
				}

				if (!rfapiGetUnAddrOfVpnBi(bi, &qct))
					qct_valid = 1;

				if (un) {
					if (!qct_valid
					    || !prefix_match(un, &qct)) {
#if DEBUG_L2_EXTRA
						vnc_zlog_debug_verbose(
							"%s: continue at un && !qct_valid || !prefix_match(un, &qct)",
							__func__);
#endif
						continue;
					}
				}


				/*
				 * Blow bi away
				 */
				/*
				 * If this route is waiting to be deleted
				 * because of
				 * a previous withdraw, we must cancel its
				 * timer.
				 */
				if (CHECK_FLAG(bi->flags, BGP_INFO_REMOVED)) {
					if (!delete_holddown)
						continue;
					if (bi->extra->vnc.import.timer) {

						struct thread *t =
							(struct thread *)bi
								->extra->vnc
								.import.timer;
						struct rfapi_withdraw *wcb =
							t->arg;

						wcb->import_table
							->holddown_count[afi] -=
							1;
						RFAPI_UPDATE_ITABLE_COUNT(
							bi, wcb->import_table,
							afi, 1);
						XFREE(MTYPE_RFAPI_WITHDRAW,
						      wcb);
						thread_cancel(t);
					}
				} else {
					if (!delete_active)
						continue;
					is_active = 1;
				}

				vnc_zlog_debug_verbose(
					"%s: deleting bi %p (qct_valid=%d, qpt_valid=%d, delete_holddown=%d, delete_active=%d)",
					__func__, bi, qct_valid, qpt_valid,
					delete_holddown, delete_active);


				/*
				 * add nve to list
				 */
				if (qct_valid && qpt_valid) {

					struct rfapi_nve_addr na;
					struct rfapi_nve_addr *nap;

					memset(&na, 0, sizeof(na));
					assert(!rfapiQprefix2Raddr(&qct,
								   &na.un));
					assert(!rfapiQprefix2Raddr(&qpt,
								   &na.vn));

					if (skiplist_search(
						    (is_active
							     ? uniq_active_nves
							     : uniq_holddown_nves),
						    &na, (void **)&nap)) {
						char line[BUFSIZ];

						nap = XCALLOC(
							MTYPE_RFAPI_NVE_ADDR,
							sizeof(struct
							       rfapi_nve_addr));
						assert(nap);
						*nap = na;
						nap->info = is_active
								    ? pAHcount
								    : pHHcount;
						skiplist_insert(
							(is_active
								 ? uniq_active_nves
								 : uniq_holddown_nves),
							nap, nap);

						rfapiNveAddr2Str(nap, line,
								 BUFSIZ);
					}
				}

				vnc_direct_bgp_rh_del_route(bgp, afi, &rn->p,
							    bi->peer);

				RFAPI_UPDATE_ITABLE_COUNT(bi, it, afi, -1);
				it->holddown_count[afi] += 1;
				rfapiExpireVpnNow(it, rn, bi, 1);

				vnc_zlog_debug_verbose(
					"%s: incrementing count (is_active=%d)",
					__func__, is_active);

				if (is_active)
					++*pARcount;
				else
					++*pHRcount;
			}
		}
	}
}


/*
 * For use by the "clear vnc prefixes" command
 */
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
void rfapiDeleteRemotePrefixes(struct prefix *un, struct prefix *vn,
			       struct prefix *p,
			       struct rfapi_import_table *arg_it,
			       int delete_active, int delete_holddown,
			       uint32_t *pARcount, uint32_t *pAHcount,
			       uint32_t *pHRcount, uint32_t *pHHcount)
{
	struct bgp *bgp;
	struct rfapi *h;
	struct rfapi_import_table *it;
	uint32_t deleted_holddown_route_count = 0;
	uint32_t deleted_active_route_count = 0;
	uint32_t deleted_holddown_nve_count = 0;
	uint32_t deleted_active_nve_count = 0;
	struct skiplist *uniq_holddown_nves;
	struct skiplist *uniq_active_nves;

	VNC_ITRCCK;

	bgp = bgp_get_default(); /* assume 1 instance for now */
	/* If no bgp instantiated yet, no vnc prefixes exist */
	if (!bgp)
		return;

	h = bgp->rfapi;
	assert(h);

	uniq_holddown_nves =
		skiplist_new(0, rfapi_nve_addr_cmp, delete_rem_pfx_na_free);
	uniq_active_nves =
		skiplist_new(0, rfapi_nve_addr_cmp, delete_rem_pfx_na_free);

	/*
	 * Iterate over all import tables; do a filtered import
	 * for the afi/safi combination
	 */

	if (arg_it)
		it = arg_it;
	else
		it = h->imports;
	for (; it;) {

		vnc_zlog_debug_verbose(
			"%s: calling rfapiDeleteRemotePrefixesIt() on (IP) import %p",
			__func__, it);

		rfapiDeleteRemotePrefixesIt(
			bgp, it, un, vn, p, delete_active, delete_holddown,
			&deleted_active_route_count, &deleted_active_nve_count,
			&deleted_holddown_route_count,
			&deleted_holddown_nve_count, uniq_active_nves,
			uniq_holddown_nves);

		if (arg_it)
			it = NULL;
		else
			it = it->next;
	}

	/*
	 * Now iterate over L2 import tables
	 */
	if (h->import_mac && !(p && (p->family != AF_ETHERNET))) {

		void *cursor = NULL;
		int rc;

		for (cursor = NULL,
		    rc = skiplist_next(h->import_mac, NULL, (void **)&it,
				       &cursor);
		     !rc; rc = skiplist_next(h->import_mac, NULL, (void **)&it,
					     &cursor)) {

			vnc_zlog_debug_verbose(
				"%s: calling rfapiDeleteRemotePrefixesIt() on import_mac %p",
				__func__, it);

			rfapiDeleteRemotePrefixesIt(
				bgp, it, un, vn, p, delete_active,
				delete_holddown, &deleted_active_route_count,
				&deleted_active_nve_count,
				&deleted_holddown_route_count,
				&deleted_holddown_nve_count, uniq_active_nves,
				uniq_holddown_nves);
		}
	}

	/*
	 * our custom element freeing function above counts as it deletes
	 */
	skiplist_free(uniq_holddown_nves);
	skiplist_free(uniq_active_nves);

	if (pARcount)
		*pARcount = deleted_active_route_count;
	if (pAHcount)
		*pAHcount = deleted_active_nve_count;
	if (pHRcount)
		*pHRcount = deleted_holddown_route_count;
	if (pHHcount)
		*pHHcount = deleted_holddown_nve_count;

	VNC_ITRCCK;
}

/*------------------------------------------
 * rfapiCountRemoteRoutes
 *
 * UI helper: count VRF routes from BGP side
 *
 * input:
 *
 * output
 *	pALRcount		count of active local routes
 *	pARRcount		count of active remote routes
 *	pHRcount		count of holddown routes
 *	pIRcount		count of direct imported routes
 *
 * return value:
 *	void
 --------------------------------------------*/
void rfapiCountAllItRoutes(int *pALRcount, /* active local routes */
			   int *pARRcount, /* active remote routes */
			   int *pHRcount,  /* holddown routes */
			   int *pIRcount)  /* imported routes */
{
	struct bgp *bgp;
	struct rfapi *h;
	struct rfapi_import_table *it;
	afi_t afi;

	int total_active_local = 0;
	int total_active_remote = 0;
	int total_holddown = 0;
	int total_imported = 0;

	bgp = bgp_get_default(); /* assume 1 instance for now */
	assert(bgp);

	h = bgp->rfapi;
	assert(h);

	/*
	 * Iterate over all import tables; do a filtered import
	 * for the afi/safi combination
	 */

	for (it = h->imports; it; it = it->next) {

		for (afi = AFI_IP; afi < AFI_MAX; ++afi) {

			total_active_local += it->local_count[afi];
			total_active_remote += it->remote_count[afi];
			total_holddown += it->holddown_count[afi];
			total_imported += it->imported_count[afi];
		}
	}

	void *cursor;
	int rc;

	if (h->import_mac) {
		for (cursor = NULL,
		    rc = skiplist_next(h->import_mac, NULL, (void **)&it,
				       &cursor);
		     !rc; rc = skiplist_next(h->import_mac, NULL, (void **)&it,
					     &cursor)) {

			total_active_local += it->local_count[AFI_L2VPN];
			total_active_remote += it->remote_count[AFI_L2VPN];
			total_holddown += it->holddown_count[AFI_L2VPN];
			total_imported += it->imported_count[AFI_L2VPN];
		}
	}


	if (pALRcount) {
		*pALRcount = total_active_local;
	}
	if (pARRcount) {
		*pARRcount = total_active_remote;
	}
	if (pHRcount) {
		*pHRcount = total_holddown;
	}
	if (pIRcount) {
		*pIRcount = total_imported;
	}
}

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
/* hold down time maxes out at RFAPI_LIFETIME_INFINITE_WITHDRAW_DELAY */
uint32_t rfapiGetHolddownFromLifetime(uint32_t lifetime)
{
	uint32_t factor;
	struct bgp *bgp;

	bgp = bgp_get_default();
	if (bgp && bgp->rfapi_cfg)
		factor = bgp->rfapi_cfg->rfp_cfg.holddown_factor;
	else
		factor = RFAPI_RFP_CFG_DEFAULT_HOLDDOWN_FACTOR;

	if (factor < 100 || lifetime < RFAPI_LIFETIME_INFINITE_WITHDRAW_DELAY)
		lifetime = lifetime * factor / 100;
	if (lifetime < RFAPI_LIFETIME_INFINITE_WITHDRAW_DELAY)
		return lifetime;
	else
		return RFAPI_LIFETIME_INFINITE_WITHDRAW_DELAY;
}
