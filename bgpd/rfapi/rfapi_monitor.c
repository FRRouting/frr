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
 * File:	rfapi_monitor.c
 */

/* TBD remove unneeded includes */

#include <errno.h>

#include "lib/zebra.h"
#include "lib/prefix.h"
#include "lib/table.h"
#include "lib/vty.h"
#include "lib/memory.h"
#include "lib/log.h"
#include "lib/table.h"
#include "lib/skiplist.h"

#include "bgpd/bgpd.h"

#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#include "bgpd/rfapi/rfapi.h"
#include "bgpd/rfapi/rfapi_backend.h"

#include "bgpd/rfapi/rfapi.h"
#include "bgpd/rfapi/rfapi_import.h"
#include "bgpd/rfapi/vnc_import_bgp.h"
#include "bgpd/rfapi/rfapi_private.h"
#include "bgpd/rfapi/rfapi_monitor.h"
#include "bgpd/rfapi/rfapi_vty.h"
#include "bgpd/rfapi/rfapi_rib.h"
#include "bgpd/rfapi/vnc_debug.h"

#define DEBUG_L2_EXTRA 0
#define DEBUG_DUP_CHECK 0
#define DEBUG_ETH_SL 0

static void rfapiMonitorTimerRestart(struct rfapi_monitor_vpn *m);

static void rfapiMonitorEthTimerRestart(struct rfapi_monitor_eth *m);

/*
 * Forward declarations
 */
static void rfapiMonitorEthDetachImport(struct bgp *bgp,
					struct rfapi_monitor_eth *mon);

#if DEBUG_ETH_SL
/*
 * Debug function, special case
 */
void rfapiMonitorEthSlCheck(struct route_node *rn, const char *tag1,
			    const char *tag2)
{
	struct route_node *rn_saved = NULL;
	static struct skiplist *sl_saved = NULL;
	struct skiplist *sl;

	if (!rn)
		return;

	if (rn_saved && (rn != rn_saved))
		return;

	if (!rn_saved)
		rn_saved = rn;

	sl = RFAPI_MONITOR_ETH(rn);
	if (sl || sl_saved) {
		vnc_zlog_debug_verbose(
			"%s[%s%s]: rn=%p, rn->lock=%d, old sl=%p, new sl=%p",
			__func__, (tag1 ? tag1 : ""), (tag2 ? tag2 : ""), rn,
			rn->lock, sl_saved, sl);
		sl_saved = sl;
	}
}
#endif

/*
 * Debugging function that aborts when it finds monitors whose
 * "next" pointer * references themselves
 */
void rfapiMonitorLoopCheck(struct rfapi_monitor_vpn *mchain)
{
	struct rfapi_monitor_vpn *m;

	for (m = mchain; m; m = m->next)
		assert(m != m->next);
}

#if DEBUG_DUP_CHECK
/*
 * Debugging code: see if a monitor is mentioned more than once
 * in a HD's monitor list
 */
void rfapiMonitorDupCheck(struct bgp *bgp)
{
	struct listnode *hnode;
	struct rfapi_descriptor *rfd;

	for (ALL_LIST_ELEMENTS_RO(&bgp->rfapi->descriptors, hnode, rfd)) {
		struct route_node *mrn;

		if (!rfd->mon)
			continue;

		for (mrn = route_top(rfd->mon); mrn; mrn = route_next(mrn)) {
			struct rfapi_monitor_vpn *m;
			for (m = (struct rfapi_monitor_vpn *)(mrn->info); m;
			     m = m->next)
				m->dcount = 0;
		}
	}

	for (ALL_LIST_ELEMENTS_RO(&bgp->rfapi->descriptors, hnode, rfd)) {
		struct route_node *mrn;

		if (!rfd->mon)
			continue;

		for (mrn = route_top(rfd->mon); mrn; mrn = route_next(mrn)) {
			struct rfapi_monitor_vpn *m;

			for (m = (struct rfapi_monitor_vpn *)(mrn->info); m;
			     m = m->next)
				assert(++m->dcount == 1);
		}
	}
}
#endif

/* debug */
void rfapiMonitorCleanCheck(struct bgp *bgp)
{
	struct listnode *hnode;
	struct rfapi_descriptor *rfd;

	for (ALL_LIST_ELEMENTS_RO(&bgp->rfapi->descriptors, hnode, rfd)) {
		assert(!rfd->import_table->vpn0_queries[AFI_IP]);
		assert(!rfd->import_table->vpn0_queries[AFI_IP6]);

		struct route_node *rn;

		for (rn = route_top(rfd->import_table->imported_vpn[AFI_IP]);
		     rn; rn = route_next(rn)) {

			assert(!RFAPI_MONITOR_VPN(rn));
		}
		for (rn = route_top(rfd->import_table->imported_vpn[AFI_IP6]);
		     rn; rn = route_next(rn)) {

			assert(!RFAPI_MONITOR_VPN(rn));
		}
	}
}

/* debug */
void rfapiMonitorCheckAttachAllowed(void)
{
	struct bgp *bgp = bgp_get_default();
	assert(!(bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_CALLBACK_DISABLE));
}

void rfapiMonitorExtraFlush(safi_t safi, struct route_node *rn)
{
	struct rfapi_it_extra *hie;
	struct rfapi_monitor_vpn *v;
	struct rfapi_monitor_vpn *v_next;
	struct rfapi_monitor_encap *e = NULL;
	struct rfapi_monitor_encap *e_next = NULL;

	if (!rn)
		return;

	if (!rn->aggregate)
		return;

	hie = (struct rfapi_it_extra *)(rn->aggregate);

	switch (safi) {
	case SAFI_ENCAP:
		for (e = hie->u.encap.e; e; e = e_next) {
			e_next = e->next;
			e->next = NULL;
			XFREE(MTYPE_RFAPI_MONITOR_ENCAP, e);
			route_unlock_node(rn);
		}
		hie->u.encap.e = NULL;
		break;

	case SAFI_MPLS_VPN:
		for (v = hie->u.vpn.v; v; v = v_next) {
			v_next = v->next;
			v->next = NULL;
			XFREE(MTYPE_RFAPI_MONITOR, e);
			route_unlock_node(rn);
		}
		hie->u.vpn.v = NULL;
		if (hie->u.vpn.e.source) {
			while (!skiplist_delete_first(hie->u.vpn.e.source)) {
				route_unlock_node(rn);
			}
			skiplist_free(hie->u.vpn.e.source);
			hie->u.vpn.e.source = NULL;
			route_unlock_node(rn);
		}
		if (hie->u.vpn.idx_rd) {
			/* looping through bi->extra->vnc.import.rd is tbd */
			while (!skiplist_delete_first(hie->u.vpn.idx_rd)) {
				route_unlock_node(rn);
			}
			skiplist_free(hie->u.vpn.idx_rd);
			hie->u.vpn.idx_rd = NULL;
			route_unlock_node(rn);
		}
		if (hie->u.vpn.mon_eth) {
			while (!skiplist_delete_first(hie->u.vpn.mon_eth)) {
				route_unlock_node(rn);
			}
			skiplist_free(hie->u.vpn.mon_eth);
			hie->u.vpn.mon_eth = NULL;
			route_unlock_node(rn);
		}
		break;

	default:
		assert(0);
	}
	XFREE(MTYPE_RFAPI_IT_EXTRA, hie);
	rn->aggregate = NULL;
	route_unlock_node(rn);
}

/*
 * If the child lists are empty, release the rfapi_it_extra struct
 */
void rfapiMonitorExtraPrune(safi_t safi, struct route_node *rn)
{
	struct rfapi_it_extra *hie;

	if (!rn)
		return;

	if (!rn->aggregate)
		return;

	hie = (struct rfapi_it_extra *)(rn->aggregate);

	switch (safi) {
	case SAFI_ENCAP:
		if (hie->u.encap.e)
			return;
		break;

	case SAFI_MPLS_VPN:
		if (hie->u.vpn.v)
			return;
		if (hie->u.vpn.mon_eth) {
			if (skiplist_count(hie->u.vpn.mon_eth))
				return;
			skiplist_free(hie->u.vpn.mon_eth);
			hie->u.vpn.mon_eth = NULL;
			route_unlock_node(rn); /* uncount skiplist */
		}
		if (hie->u.vpn.e.source) {
			if (skiplist_count(hie->u.vpn.e.source))
				return;
			skiplist_free(hie->u.vpn.e.source);
			hie->u.vpn.e.source = NULL;
			route_unlock_node(rn);
		}
		if (hie->u.vpn.idx_rd) {
			if (skiplist_count(hie->u.vpn.idx_rd))
				return;
			skiplist_free(hie->u.vpn.idx_rd);
			hie->u.vpn.idx_rd = NULL;
			route_unlock_node(rn);
		}
		if (hie->u.vpn.mon_eth) {
			if (skiplist_count(hie->u.vpn.mon_eth))
				return;
			skiplist_free(hie->u.vpn.mon_eth);
			hie->u.vpn.mon_eth = NULL;
			route_unlock_node(rn);
		}
		break;

	default:
		assert(0);
	}
	XFREE(MTYPE_RFAPI_IT_EXTRA, hie);
	rn->aggregate = NULL;
	route_unlock_node(rn);
}

/*
 * returns locked node
 */
struct route_node *rfapiMonitorGetAttachNode(struct rfapi_descriptor *rfd,
					     struct prefix *p)
{
	afi_t afi;
	struct route_node *rn;

	if (RFAPI_0_PREFIX(p)) {
		assert(1);
	}

	afi = family2afi(p->family);
	assert(afi);

	/*
	 * It's possible that even though there is a route at this node,
	 * there are no routes with valid UN addresses (i.e,. with no
	 * valid tunnel routes). Check for that and walk back up the
	 * tree if necessary.
	 *
	 * When the outer loop completes, the matched node, if any, is
	 * locked (i.e., its reference count has been incremented) to
	 * account for the VPN monitor we are about to attach.
	 *
	 * if a monitor is moved to another node, there must be
	 * corresponding unlock/locks
	 */
	for (rn = route_node_match(rfd->import_table->imported_vpn[afi], p);
	     rn;) {

		struct bgp_info *bi;
		struct prefix pfx_dummy;

		/* TBD update this code to use new valid_interior_count */
		for (bi = rn->info; bi; bi = bi->next) {
			/*
			 * If there is a cached ENCAP UN address, it's a usable
			 * VPN route
			 */
			if (bi->extra && bi->extra->vnc.import.un_family) {
				break;
			}

			/*
			 * Or if there is a valid Encap Attribute tunnel subtlv
			 * address,
			 * it's a usable VPN route.
			 */
			if (!rfapiGetVncTunnelUnAddr(bi->attr, &pfx_dummy)) {
				break;
			}
		}
		if (bi)
			break;

		route_unlock_node(rn);
		if ((rn = rn->parent)) {
			route_lock_node(rn);
		}
	}

	if (!rn) {
		struct prefix pfx_default;

		memset(&pfx_default, 0, sizeof(pfx_default));
		pfx_default.family = p->family;

		/* creates default node if none exists, and increments ref count
		 */
		rn = route_node_get(rfd->import_table->imported_vpn[afi],
				    &pfx_default);
	}

	return rn;
}

/*
 * If this function happens to attach the monitor to a radix tree
 * node (as opposed to the 0-prefix list), the node pointer is
 * returned (for the benefit of caller which might like to use it
 * to generate an immediate query response).
 */
static struct route_node *rfapiMonitorAttachImport(struct rfapi_descriptor *rfd,
						   struct rfapi_monitor_vpn *m)
{
	struct route_node *rn;

	rfapiMonitorCheckAttachAllowed();

	if (RFAPI_0_PREFIX(&m->p)) {
		/*
		 * Add new monitor entry to vpn0 list
		 */
		afi_t afi;

		afi = family2afi(m->p.family);
		assert(afi);

		m->next = rfd->import_table->vpn0_queries[afi];
		rfd->import_table->vpn0_queries[afi] = m;
		vnc_zlog_debug_verbose("%s: attached monitor %p to vpn0 list",
				       __func__, m);
		return NULL;
	}

	/*
	 * Attach new monitor entry to import table node
	 */
	rn = rfapiMonitorGetAttachNode(rfd, &m->p); /* returns locked rn */
	m->node = rn;
	m->next = RFAPI_MONITOR_VPN(rn);
	RFAPI_MONITOR_VPN_W_ALLOC(rn) = m;
	RFAPI_CHECK_REFCOUNT(rn, SAFI_MPLS_VPN, 0);
	vnc_zlog_debug_verbose("%s: attached monitor %p to rn %p", __func__, m,
			       rn);
	return rn;
}


/*
 * reattach monitors for this HD to import table
 */
void rfapiMonitorAttachImportHd(struct rfapi_descriptor *rfd)
{
	struct route_node *mrn;

	if (!rfd->mon) {
		/*
		 * No monitors for this HD
		 */
		return;
	}

	for (mrn = route_top(rfd->mon); mrn; mrn = route_next(mrn)) {

		if (!mrn->info)
			continue;

		(void)rfapiMonitorAttachImport(
			rfd, (struct rfapi_monitor_vpn *)(mrn->info));
	}
}

/*
 * Adds a monitor for a query to the NVE descriptor's list
 * and, if callbacks are enabled, attaches it to the import table.
 *
 * If we happened to locate the import table radix tree attachment
 * point, return it so the caller can use it to generate a query
 * response without repeating the lookup. Note that when callbacks
 * are disabled, this function will not perform a lookup, and the
 * caller will have to do its own lookup.
 */
struct route_node *
rfapiMonitorAdd(struct bgp *bgp, struct rfapi_descriptor *rfd, struct prefix *p)
{
	struct rfapi_monitor_vpn *m;
	struct route_node *rn;

	/*
	 * Initialize nve's monitor list if needed
	 * NB use the same radix tree for IPv4 and IPv6 targets.
	 * The prefix will always have full-length mask (/32, /128)
	 * or be 0/0 so they won't get mixed up.
	 */
	if (!rfd->mon) {
		rfd->mon = route_table_init();
	}
	rn = route_node_get(rfd->mon, p);
	if (rn->info) {
		/*
		 * received this query before, no further action needed
		 */
		rfapiMonitorTimerRestart((struct rfapi_monitor_vpn *)rn->info);
		route_unlock_node(rn);
		return NULL;
	}

	/*
	 * New query for this nve, record it in the HD
	 */
	rn->info =
		XCALLOC(MTYPE_RFAPI_MONITOR, sizeof(struct rfapi_monitor_vpn));
	m = (struct rfapi_monitor_vpn *)(rn->info);
	m->rfd = rfd;
	prefix_copy(&m->p, p);

	++rfd->monitor_count;
	++bgp->rfapi->monitor_count;

	rfapiMonitorTimerRestart(m);

	if (bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_CALLBACK_DISABLE) {
		/*
		 * callbacks turned off, so don't attach monitor to import table
		 */
		return NULL;
	}


	/*
	 * attach to import table
	 */
	return rfapiMonitorAttachImport(rfd, m);
}

/*
 * returns monitor pointer if found, NULL if not
 */
static struct rfapi_monitor_vpn *
rfapiMonitorDetachImport(struct rfapi_monitor_vpn *m)
{
	struct rfapi_monitor_vpn *prev;
	struct rfapi_monitor_vpn *this = NULL;

	if (RFAPI_0_PREFIX(&m->p)) {
		afi_t afi;

		/*
		 * 0-prefix monitors are stored in a special list and not
		 * in the import VPN tree
		 */

		afi = family2afi(m->p.family);
		assert(afi);

		if (m->rfd->import_table) {
			for (prev = NULL,
			    this = m->rfd->import_table->vpn0_queries[afi];
			     this; prev = this, this = this->next) {

				if (this == m)
					break;
			}
			if (this) {
				if (!prev) {
					m->rfd->import_table
						->vpn0_queries[afi] =
						this->next;
				} else {
					prev->next = this->next;
				}
			}
		}
	} else {

		if (m->node) {
			for (prev = NULL, this = RFAPI_MONITOR_VPN(m->node);
			     this; prev = this, this = this->next) {

				if (this == m)
					break;
			}
			if (this) {
				if (prev) {
					prev->next = this->next;
				} else {
					RFAPI_MONITOR_VPN_W_ALLOC(m->node) =
						this->next;
				}
				RFAPI_CHECK_REFCOUNT(m->node, SAFI_MPLS_VPN, 1);
				route_unlock_node(m->node);
			}
			m->node = NULL;
		}
	}
	return this;
}


void rfapiMonitorDetachImportHd(struct rfapi_descriptor *rfd)
{
	struct route_node *rn;

	if (!rfd->mon)
		return;

	for (rn = route_top(rfd->mon); rn; rn = route_next(rn)) {
		if (rn->info) {
			rfapiMonitorDetachImport(
				(struct rfapi_monitor_vpn *)(rn->info));
		}
	}
}

void rfapiMonitorDel(struct bgp *bgp, struct rfapi_descriptor *rfd,
		     struct prefix *p)
{
	struct route_node *rn;
	struct rfapi_monitor_vpn *m;

	assert(rfd->mon);
	rn = route_node_get(rfd->mon, p); /* locks node */
	m = rn->info;

	assert(m);

	/*
	 * remove from import table
	 */
	if (!(bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_CALLBACK_DISABLE)) {
		rfapiMonitorDetachImport(m);
	}

	if (m->timer) {
		thread_cancel(m->timer);
		m->timer = NULL;
	}

	/*
	 * remove from rfd list
	 */
	XFREE(MTYPE_RFAPI_MONITOR, m);
	rn->info = NULL;
	route_unlock_node(rn); /* undo original lock when created */
	route_unlock_node(rn); /* undo lock in route_node_get */

	--rfd->monitor_count;
	--bgp->rfapi->monitor_count;
}

/*
 * returns count of monitors deleted
 */
int rfapiMonitorDelHd(struct rfapi_descriptor *rfd)
{
	struct route_node *rn;
	struct bgp *bgp;
	int count = 0;

	vnc_zlog_debug_verbose("%s: entry rfd=%p", __func__, rfd);

	bgp = bgp_get_default();

	if (rfd->mon) {
		for (rn = route_top(rfd->mon); rn; rn = route_next(rn)) {
			struct rfapi_monitor_vpn *m;
			if ((m = rn->info)) {
				if (!(bgp->rfapi_cfg->flags
				      & BGP_VNC_CONFIG_CALLBACK_DISABLE)) {
					rfapiMonitorDetachImport(m);
				}

				if (m->timer) {
					thread_cancel(m->timer);
					m->timer = NULL;
				}

				XFREE(MTYPE_RFAPI_MONITOR, m);
				rn->info = NULL;
				route_unlock_node(rn); /* undo original lock
							  when created */
				++count;
				--rfd->monitor_count;
				--bgp->rfapi->monitor_count;
			}
		}
		route_table_finish(rfd->mon);
		rfd->mon = NULL;
	}

	if (rfd->mon_eth) {

		struct rfapi_monitor_eth *mon_eth;

		while (!skiplist_first(rfd->mon_eth, NULL, (void **)&mon_eth)) {

			int rc;

			if (!(bgp->rfapi_cfg->flags
			      & BGP_VNC_CONFIG_CALLBACK_DISABLE)) {
				rfapiMonitorEthDetachImport(bgp, mon_eth);
			} else {
#if DEBUG_L2_EXTRA
				vnc_zlog_debug_verbose(
					"%s: callbacks disabled, not attempting to detach mon_eth %p",
					__func__, mon_eth);
#endif
			}

			if (mon_eth->timer) {
				thread_cancel(mon_eth->timer);
				mon_eth->timer = NULL;
			}

			/*
			 * remove from rfd list
			 */
			rc = skiplist_delete(rfd->mon_eth, mon_eth, mon_eth);
			assert(!rc);

			vnc_zlog_debug_verbose("%s: freeing mon_eth %p",
					       __func__, mon_eth);
			XFREE(MTYPE_RFAPI_MONITOR_ETH, mon_eth);

			++count;
			--rfd->monitor_count;
			--bgp->rfapi->monitor_count;
		}
		skiplist_free(rfd->mon_eth);
		rfd->mon_eth = NULL;
	}

	return count;
}

void rfapiMonitorResponseRemovalOff(struct bgp *bgp)
{
	if (bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_RESPONSE_REMOVAL_DISABLE) {
		return;
	}
	bgp->rfapi_cfg->flags |= BGP_VNC_CONFIG_RESPONSE_REMOVAL_DISABLE;
}

void rfapiMonitorResponseRemovalOn(struct bgp *bgp)
{
	if (!(bgp->rfapi_cfg->flags
	      & BGP_VNC_CONFIG_RESPONSE_REMOVAL_DISABLE)) {
		return;
	}
	bgp->rfapi_cfg->flags &= ~BGP_VNC_CONFIG_RESPONSE_REMOVAL_DISABLE;
}

static int rfapiMonitorTimerExpire(struct thread *t)
{
	struct rfapi_monitor_vpn *m = t->arg;

	/* forget reference to thread, it's gone */
	m->timer = NULL;

	/* delete the monitor */
	rfapiMonitorDel(bgp_get_default(), m->rfd, &m->p);

	return 0;
}

static void rfapiMonitorTimerRestart(struct rfapi_monitor_vpn *m)
{
	if (m->timer) {
		unsigned long remain = thread_timer_remain_second(m->timer);

		/* unexpected case, but avoid wraparound problems below */
		if (remain > m->rfd->response_lifetime)
			return;

		/* don't restart if we just restarted recently */
		if (m->rfd->response_lifetime - remain < 2)
			return;

		thread_cancel(m->timer);
		m->timer = NULL;
	}

	{
		char buf[BUFSIZ];

		vnc_zlog_debug_verbose(
			"%s: target %s life %u", __func__,
			rfapi_ntop(m->p.family, m->p.u.val, buf, BUFSIZ),
			m->rfd->response_lifetime);
	}
	m->timer = NULL;
	thread_add_timer(bm->master, rfapiMonitorTimerExpire, m,
			 m->rfd->response_lifetime, &m->timer);
}

/*
 * called when an updated response is sent to the NVE. Per
 * ticket 255, restart timers for any monitors that could have
 * been responsible for the response, i.e., any monitors for
 * the exact prefix or a parent of it.
 */
void rfapiMonitorTimersRestart(struct rfapi_descriptor *rfd, struct prefix *p)
{
	struct route_node *rn;

	if (AF_ETHERNET == p->family) {
		struct rfapi_monitor_eth *mon_eth;
		int rc;
		void *cursor;

		/*
		 * XXX match any LNI
		 */
		for (cursor = NULL,
		    rc = skiplist_next(rfd->mon_eth, NULL, (void **)&mon_eth,
				       &cursor);
		     rc == 0; rc = skiplist_next(rfd->mon_eth, NULL,
						 (void **)&mon_eth, &cursor)) {

			if (!memcmp(mon_eth->macaddr.octet,
				    p->u.prefix_eth.octet, ETH_ALEN)) {

				rfapiMonitorEthTimerRestart(mon_eth);
			}
		}

	} else {
		for (rn = route_top(rfd->mon); rn; rn = route_next(rn)) {
			struct rfapi_monitor_vpn *m;

			if (!((m = rn->info)))
				continue;

			/* NB order of test is significant ! */
			if (!m->node || prefix_match(&m->node->p, p)) {
				rfapiMonitorTimerRestart(m);
			}
		}
	}
}

/*
 * Find monitors at this node and all its parents. Call
 * rfapiRibUpdatePendingNode with this node and all corresponding NVEs.
 */
void rfapiMonitorItNodeChanged(
	struct rfapi_import_table *import_table, struct route_node *it_node,
	struct rfapi_monitor_vpn *monitor_list) /* for base it node, NULL=all */
{
	struct skiplist *nves_seen;
	struct route_node *rn = it_node;
	struct bgp *bgp = bgp_get_default();
	afi_t afi = family2afi(rn->p.family);
#if DEBUG_L2_EXTRA
	char buf_prefix[PREFIX_STRLEN];
#endif

	assert(bgp);
	assert(import_table);

	nves_seen = skiplist_new(0, NULL, NULL);

#if DEBUG_L2_EXTRA
	prefix2str(&it_node->p, buf_prefix, sizeof(buf_prefix));
	vnc_zlog_debug_verbose("%s: it=%p, it_node=%p, it_node->prefix=%s",
			       __func__, import_table, it_node, buf_prefix);
#endif

	if (AFI_L2VPN == afi) {
		struct rfapi_monitor_eth *m;
		struct skiplist *sl;
		void *cursor;
		int rc;

		if ((sl = RFAPI_MONITOR_ETH(rn))) {

			for (cursor = NULL,
			    rc = skiplist_next(sl, NULL, (void **)&m,
					       (void **)&cursor);
			     !rc; rc = skiplist_next(sl, NULL, (void **)&m,
						     (void **)&cursor)) {

				if (skiplist_search(nves_seen, m->rfd, NULL)) {
					/*
					 * Haven't done this NVE yet. Add to
					 * "seen" list.
					 */
					assert(!skiplist_insert(nves_seen,
								m->rfd, NULL));

					/*
					 * update its RIB
					 */
					rfapiRibUpdatePendingNode(
						bgp, m->rfd, import_table,
						it_node,
						m->rfd->response_lifetime);
				}
			}
		}

	} else {

		struct rfapi_monitor_vpn *m;

		if (monitor_list) {
			m = monitor_list;
		} else {
			m = RFAPI_MONITOR_VPN(rn);
		}

		do {
			/*
			 * If we have reached the root node (parent==NULL) and
			 * there
			 * are no routes here (info==NULL), and the IT node that
			 * changed was not the root node (it_node->parent !=
			 * NULL),
			 * then any monitors at this node are here because they
			 * had
			 * no match at all. Therefore, do not send route updates
			 * to them
			 * because we haven't sent them an initial route.
			 */
			if (!rn->parent && !rn->info && it_node->parent)
				break;

			for (; m; m = m->next) {

				if (RFAPI_0_PREFIX(&m->p)) {
					/* shouldn't happen, but be safe */
					continue;
				}
				if (skiplist_search(nves_seen, m->rfd, NULL)) {
					/*
					 * Haven't done this NVE yet. Add to
					 * "seen" list.
					 */
					assert(!skiplist_insert(nves_seen,
								m->rfd, NULL));

					char buf_attach_pfx[PREFIX_STRLEN];
					char buf_target_pfx[PREFIX_STRLEN];

					prefix2str(&m->node->p, buf_attach_pfx,
						   sizeof(buf_attach_pfx));
					prefix2str(&m->p, buf_target_pfx,
						   sizeof(buf_target_pfx));
					vnc_zlog_debug_verbose(
						"%s: update rfd %p attached to pfx %s (targ=%s)",
						__func__, m->rfd,
						buf_attach_pfx, buf_target_pfx);

					/*
					 * update its RIB
					 */
					rfapiRibUpdatePendingNode(
						bgp, m->rfd, import_table,
						it_node,
						m->rfd->response_lifetime);
				}
			}
			rn = rn->parent;
			if (rn)
				m = RFAPI_MONITOR_VPN(rn);
		} while (rn);
	}

	/*
	 * All-routes L2 monitors
	 */
	if (AFI_L2VPN == afi) {
		struct rfapi_monitor_eth *e;

#if DEBUG_L2_EXTRA
		vnc_zlog_debug_verbose("%s: checking L2 all-routes monitors",
				       __func__);
#endif

		for (e = import_table->eth0_queries; e; e = e->next) {
#if DEBUG_L2_EXTRA
			vnc_zlog_debug_verbose("%s: checking eth0 mon=%p",
					       __func__, e);
#endif
			if (skiplist_search(nves_seen, e->rfd, NULL)) {
				/*
				 * Haven't done this NVE yet. Add to "seen"
				 * list.
				 */
				assert(!skiplist_insert(nves_seen, e->rfd,
							NULL));

/*
 * update its RIB
 */
#if DEBUG_L2_EXTRA
				vnc_zlog_debug_verbose(
					"%s: found L2 all-routes monitor %p",
					__func__, e);
#endif
				rfapiRibUpdatePendingNode(
					bgp, e->rfd, import_table, it_node,
					e->rfd->response_lifetime);
			}
		}
	} else {
		struct rfapi_monitor_vpn *m;

		/*
		 * All-routes IPv4. IPv6 monitors
		 */
		for (m = import_table->vpn0_queries[afi]; m; m = m->next) {
			if (skiplist_search(nves_seen, m->rfd, NULL)) {
				/*
				 * Haven't done this NVE yet. Add to "seen"
				 * list.
				 */
				assert(!skiplist_insert(nves_seen, m->rfd,
							NULL));

				/*
				 * update its RIB
				 */
				rfapiRibUpdatePendingNode(
					bgp, m->rfd, import_table, it_node,
					m->rfd->response_lifetime);
			}
		}
	}

	skiplist_free(nves_seen);
}

/*
 * For the listed monitors, update new node and its subtree, but
 * omit old node and its subtree
 */
void rfapiMonitorMovedUp(struct rfapi_import_table *import_table,
			 struct route_node *old_node,
			 struct route_node *new_node,
			 struct rfapi_monitor_vpn *monitor_list)
{
	struct bgp *bgp = bgp_get_default();
	struct rfapi_monitor_vpn *m;

	assert(new_node);
	assert(old_node);
	assert(new_node != old_node);

	/*
	 * If new node is 0/0 and there is no route there, don't
	 * generate an update because it will not contain any
	 * routes including the target.
	 */
	if (!new_node->parent && !new_node->info) {
		vnc_zlog_debug_verbose(
			"%s: new monitor at 0/0 and no routes, no updates",
			__func__);
		return;
	}

	for (m = monitor_list; m; m = m->next) {
		rfapiRibUpdatePendingNode(bgp, m->rfd, import_table, new_node,
					  m->rfd->response_lifetime);
		rfapiRibUpdatePendingNodeSubtree(bgp, m->rfd, import_table,
						 new_node, old_node,
						 m->rfd->response_lifetime);
	}
}

static int rfapiMonitorEthTimerExpire(struct thread *t)
{
	struct rfapi_monitor_eth *m = t->arg;

	/* forget reference to thread, it's gone */
	m->timer = NULL;

	/* delete the monitor */
	rfapiMonitorEthDel(bgp_get_default(), m->rfd, &m->macaddr,
			   m->logical_net_id);

	return 0;
}

static void rfapiMonitorEthTimerRestart(struct rfapi_monitor_eth *m)
{
	if (m->timer) {
		unsigned long remain = thread_timer_remain_second(m->timer);

		/* unexpected case, but avoid wraparound problems below */
		if (remain > m->rfd->response_lifetime)
			return;

		/* don't restart if we just restarted recently */
		if (m->rfd->response_lifetime - remain < 2)
			return;

		thread_cancel(m->timer);
		m->timer = NULL;
	}

	{
		char buf[BUFSIZ];

		vnc_zlog_debug_verbose(
			"%s: target %s life %u", __func__,
			rfapiEthAddr2Str(&m->macaddr, buf, BUFSIZ),
			m->rfd->response_lifetime);
	}
	m->timer = NULL;
	thread_add_timer(bm->master, rfapiMonitorEthTimerExpire, m,
			 m->rfd->response_lifetime, &m->timer);
}

static int mon_eth_cmp(void *a, void *b)
{
	struct rfapi_monitor_eth *m1;
	struct rfapi_monitor_eth *m2;

	int i;

	m1 = (struct rfapi_monitor_eth *)a;
	m2 = (struct rfapi_monitor_eth *)b;

	/*
	 * compare ethernet addresses
	 */
	for (i = 0; i < ETH_ALEN; ++i) {
		if (m1->macaddr.octet[i] != m2->macaddr.octet[i])
			return (m1->macaddr.octet[i] - m2->macaddr.octet[i]);
	}

	/*
	 * compare LNIs
	 */
	return (m1->logical_net_id - m2->logical_net_id);
}

static void rfapiMonitorEthAttachImport(
	struct rfapi_import_table *it,
	struct route_node *rn,	 /* it node attach point if non-0 */
	struct rfapi_monitor_eth *mon) /* monitor struct to attach */
{
	struct skiplist *sl;
	int rc;

	vnc_zlog_debug_verbose("%s: it=%p", __func__, it);

	rfapiMonitorCheckAttachAllowed();

	if (RFAPI_0_ETHERADDR(&mon->macaddr)) {
		/*
		 * These go on a different list
		 */
		mon->next = it->eth0_queries;
		it->eth0_queries = mon;
#if DEBUG_L2_EXTRA
		vnc_zlog_debug_verbose("%s: attached monitor %p to eth0 list",
				       __func__, mon);
#endif
		return;
	}

	if (rn == NULL) {
#if DEBUG_L2_EXTRA
		vnc_zlog_debug_verbose("%s: rn is null!", __func__);
#endif
		return;
	}

	/*
	 * Get sl to attach to
	 */
	sl = RFAPI_MONITOR_ETH_W_ALLOC(rn);
	if (!sl) {
		sl = RFAPI_MONITOR_ETH_W_ALLOC(rn) =
			skiplist_new(0, NULL, NULL);
		route_lock_node(rn); /* count skiplist mon_eth */
	}

#if DEBUG_L2_EXTRA
	vnc_zlog_debug_verbose(
		"%s: rn=%p, rn->lock=%d, sl=%p, attaching eth mon %p", __func__,
		rn, rn->lock, sl, mon);
#endif

	rc = skiplist_insert(sl, (void *)mon, (void *)mon);
	assert(!rc);

	/* count eth monitor */
	route_lock_node(rn);
}

/*
 * reattach monitors for this HD to import table
 */
static void rfapiMonitorEthAttachImportHd(struct bgp *bgp,
					  struct rfapi_descriptor *rfd)
{
	void *cursor;
	struct rfapi_monitor_eth *mon;
	int rc;

	if (!rfd->mon_eth) {
		/*
		 * No monitors for this HD
		 */
		return;
	}

	for (cursor = NULL,
	    rc = skiplist_next(rfd->mon_eth, NULL, (void **)&mon, &cursor);
	     rc == 0;
	     rc = skiplist_next(rfd->mon_eth, NULL, (void **)&mon, &cursor)) {

		struct rfapi_import_table *it;
		struct prefix pfx_mac_buf;
		struct route_node *rn;

		it = rfapiMacImportTableGet(bgp, mon->logical_net_id);
		assert(it);

		memset((void *)&pfx_mac_buf, 0, sizeof(struct prefix));
		pfx_mac_buf.family = AF_ETHERNET;
		pfx_mac_buf.prefixlen = 48;
		pfx_mac_buf.u.prefix_eth = mon->macaddr;

		rn = route_node_get(it->imported_vpn[AFI_L2VPN], &pfx_mac_buf);
		assert(rn);

		(void)rfapiMonitorEthAttachImport(it, rn, mon);
	}
}

static void rfapiMonitorEthDetachImport(
	struct bgp *bgp,
	struct rfapi_monitor_eth *mon) /* monitor struct to detach */
{
	struct rfapi_import_table *it;
	struct prefix pfx_mac_buf;
	struct skiplist *sl;
	struct route_node *rn;
	int rc;

	it = rfapiMacImportTableGet(bgp, mon->logical_net_id);
	assert(it);

	if (RFAPI_0_ETHERADDR(&mon->macaddr)) {
		struct rfapi_monitor_eth *prev;
		struct rfapi_monitor_eth *this = NULL;

		for (prev = NULL, this = it->eth0_queries; this;
		     prev = this, this = this->next) {

			if (this == mon)
				break;
		}
		if (this) {
			if (!prev) {
				it->eth0_queries = this->next;
			} else {
				prev->next = this->next;
			}
		}
#if DEBUG_L2_EXTRA
		vnc_zlog_debug_verbose(
			"%s: it=%p, LNI=%d, detached eth0 mon %p", __func__, it,
			mon->logical_net_id, mon);
#endif
		return;
	}

	memset((void *)&pfx_mac_buf, 0, sizeof(struct prefix));
	pfx_mac_buf.family = AF_ETHERNET;
	pfx_mac_buf.prefixlen = 48;
	pfx_mac_buf.u.prefix_eth = mon->macaddr;

	rn = route_node_get(it->imported_vpn[AFI_L2VPN], &pfx_mac_buf);
	assert(rn);

#if DEBUG_L2_EXTRA
	char buf_prefix[PREFIX_STRLEN];

	prefix2str(&rn->p, buf_prefix, sizeof(buf_prefix));
#endif

	/*
	 * Get sl to detach from
	 */
	sl = RFAPI_MONITOR_ETH(rn);
#if DEBUG_L2_EXTRA
	vnc_zlog_debug_verbose(
		"%s: it=%p, rn=%p, rn->lock=%d, sl=%p, pfx=%s, LNI=%d, detaching eth mon %p",
		__func__, it, rn, rn->lock, sl, buf_prefix, mon->logical_net_id,
		mon);
#endif
	assert(sl);


	rc = skiplist_delete(sl, (void *)mon, (void *)mon);
	assert(!rc);

	/* uncount eth monitor */
	route_unlock_node(rn);
}

struct route_node *rfapiMonitorEthAdd(struct bgp *bgp,
				      struct rfapi_descriptor *rfd,
				      struct ethaddr *macaddr,
				      uint32_t logical_net_id)
{
	int rc;
	struct rfapi_monitor_eth mon_buf;
	struct rfapi_monitor_eth *val;
	struct rfapi_import_table *it;
	struct route_node *rn = NULL;
	struct prefix pfx_mac_buf;

	if (!rfd->mon_eth) {
		rfd->mon_eth = skiplist_new(0, mon_eth_cmp, NULL);
	}

	it = rfapiMacImportTableGet(bgp, logical_net_id);
	assert(it);

	/*
	 * Get route node in import table. Here is where we attach the
	 * monitor.
	 *
	 * Look it up now because we return it to caller regardless of
	 * whether we create a new monitor or not.
	 */
	memset((void *)&pfx_mac_buf, 0, sizeof(struct prefix));
	pfx_mac_buf.family = AF_ETHERNET;
	pfx_mac_buf.prefixlen = 48;
	pfx_mac_buf.u.prefix_eth = *macaddr;

	if (!RFAPI_0_ETHERADDR(macaddr)) {
		rn = route_node_get(it->imported_vpn[AFI_L2VPN], &pfx_mac_buf);
		assert(rn);
	}

	memset((void *)&mon_buf, 0, sizeof(mon_buf));
	mon_buf.rfd = rfd;
	mon_buf.macaddr = *macaddr;
	mon_buf.logical_net_id = logical_net_id;

	{
		char buf[BUFSIZ];

		vnc_zlog_debug_verbose(
			"%s: LNI=%d: rfd=%p, pfx=%s", __func__, logical_net_id,
			rfd, rfapi_ntop(pfx_mac_buf.family, pfx_mac_buf.u.val,
					buf, BUFSIZ));
	}


	/*
	 * look up query
	 */
	rc = skiplist_search(rfd->mon_eth, (void *)&mon_buf, (void **)&val);
	if (!rc) {
		/*
		 * Found monitor - we have seen this query before
		 * restart timer
		 */
		vnc_zlog_debug_verbose(
			"%s: already present in rfd->mon_eth, not adding",
			__func__);
		rfapiMonitorEthTimerRestart(val);
		return rn;
	}

	/*
	 * New query
	 */
	val = XCALLOC(MTYPE_RFAPI_MONITOR_ETH,
		      sizeof(struct rfapi_monitor_eth));
	assert(val);
	*val = mon_buf;

	++rfd->monitor_count;
	++bgp->rfapi->monitor_count;

	rc = skiplist_insert(rfd->mon_eth, val, val);

#if DEBUG_L2_EXTRA
	vnc_zlog_debug_verbose("%s: inserted rfd=%p mon_eth=%p, rc=%d",
			       __func__, rfd, val, rc);
#else
	(void)rc;
#endif

	/*
	 * start timer
	 */
	rfapiMonitorEthTimerRestart(val);

	if (bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_CALLBACK_DISABLE) {
/*
 * callbacks turned off, so don't attach monitor to import table
 */
#if DEBUG_L2_EXTRA
		vnc_zlog_debug_verbose(
			"%s: callbacks turned off, not attaching mon_eth %p to import table",
			__func__, val);
#endif
		return rn;
	}

	/*
	 * attach to import table
	 */
	rfapiMonitorEthAttachImport(it, rn, val);

	return rn;
}

void rfapiMonitorEthDel(struct bgp *bgp, struct rfapi_descriptor *rfd,
			struct ethaddr *macaddr, uint32_t logical_net_id)
{
	struct rfapi_monitor_eth *val;
	struct rfapi_monitor_eth mon_buf;
	int rc;

	vnc_zlog_debug_verbose("%s: entry rfd=%p", __func__, rfd);

	assert(rfd->mon_eth);

	memset((void *)&mon_buf, 0, sizeof(mon_buf));
	mon_buf.macaddr = *macaddr;
	mon_buf.logical_net_id = logical_net_id;

	rc = skiplist_search(rfd->mon_eth, (void *)&mon_buf, (void **)&val);
	assert(!rc);

	/*
	 * remove from import table
	 */
	if (!(bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_CALLBACK_DISABLE)) {
		rfapiMonitorEthDetachImport(bgp, val);
	}

	if (val->timer) {
		thread_cancel(val->timer);
		val->timer = NULL;
	}

	/*
	 * remove from rfd list
	 */
	rc = skiplist_delete(rfd->mon_eth, val, val);
	assert(!rc);

#if DEBUG_L2_EXTRA
	vnc_zlog_debug_verbose("%s: freeing mon_eth %p", __func__, val);
#endif
	XFREE(MTYPE_RFAPI_MONITOR_ETH, val);

	--rfd->monitor_count;
	--bgp->rfapi->monitor_count;
}


void rfapiMonitorCallbacksOff(struct bgp *bgp)
{
	struct rfapi_import_table *it;
	afi_t afi;
	struct route_table *rt;
	struct route_node *rn;
	void *cursor;
	int rc;
	struct rfapi *h = bgp->rfapi;

	if (bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_CALLBACK_DISABLE) {
		/*
		 * Already off.
		 */
		return;
	}
	bgp->rfapi_cfg->flags |= BGP_VNC_CONFIG_CALLBACK_DISABLE;

#if DEBUG_L2_EXTRA
	vnc_zlog_debug_verbose("%s: turned off callbacks", __func__);
#endif

	if (h == NULL)
		return;
	/*
	 * detach monitors from import VPN tables. The monitors
	 * will still be linked in per-nve monitor lists.
	 */
	for (it = h->imports; it; it = it->next) {
		for (afi = AFI_IP; afi < AFI_MAX; ++afi) {

			struct rfapi_monitor_vpn *m;
			struct rfapi_monitor_vpn *next;

			rt = it->imported_vpn[afi];

			for (rn = route_top(rt); rn; rn = route_next(rn)) {
				m = RFAPI_MONITOR_VPN(rn);
				if (RFAPI_MONITOR_VPN(rn))
					RFAPI_MONITOR_VPN_W_ALLOC(rn) = NULL;
				for (; m; m = next) {
					next = m->next;
					m->next =
						NULL; /* gratuitous safeness */
					m->node = NULL;
					route_unlock_node(rn); /* uncount */
				}
			}

			for (m = it->vpn0_queries[afi]; m; m = next) {
				next = m->next;
				m->next = NULL; /* gratuitous safeness */
				m->node = NULL;
			}
			it->vpn0_queries[afi] = NULL; /* detach first monitor */
		}
	}

	/*
	 * detach monitors from import Eth tables. The monitors
	 * will still be linked in per-nve monitor lists.
	 */

	/*
	 * Loop over ethernet import tables
	 */
	for (cursor = NULL,
	    rc = skiplist_next(h->import_mac, NULL, (void **)&it, &cursor);
	     !rc;
	     rc = skiplist_next(h->import_mac, NULL, (void **)&it, &cursor)) {
		struct rfapi_monitor_eth *e;
		struct rfapi_monitor_eth *enext;

		/*
		 * The actual route table
		 */
		rt = it->imported_vpn[AFI_L2VPN];

		/*
		 * Find non-0 monitors (i.e., actual addresses, not FTD
		 * monitors)
		 */
		for (rn = route_top(rt); rn; rn = route_next(rn)) {
			struct skiplist *sl;

			sl = RFAPI_MONITOR_ETH(rn);
			while (!skiplist_delete_first(sl)) {
				route_unlock_node(rn); /* uncount monitor */
			}
		}

		/*
		 * Find 0-monitors (FTD queries)
		 */
		for (e = it->eth0_queries; e; e = enext) {
#if DEBUG_L2_EXTRA
			vnc_zlog_debug_verbose("%s: detaching eth0 mon %p",
					       __func__, e);
#endif
			enext = e->next;
			e->next = NULL; /* gratuitous safeness */
		}
		it->eth0_queries = NULL; /* detach first monitor */
	}
}

void rfapiMonitorCallbacksOn(struct bgp *bgp)
{
	struct listnode *hnode;
	struct rfapi_descriptor *rfd;

	if (!(bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_CALLBACK_DISABLE)) {
		/*
		 * Already on. It's important that we don't try to reattach
		 * monitors that are already attached because, in the interest
		 * of performance, there is no checking at the lower level
		 * whether a monitor is already attached. It leads to
		 * corrupted chains (e.g., looped pointers)
		 */
		return;
	}
	bgp->rfapi_cfg->flags &= ~BGP_VNC_CONFIG_CALLBACK_DISABLE;
#if DEBUG_L2_EXTRA
	vnc_zlog_debug_verbose("%s: turned on callbacks", __func__);
#endif
	if (bgp->rfapi == NULL)
		return;

	/*
	 * reattach monitors
	 */
	for (ALL_LIST_ELEMENTS_RO(&bgp->rfapi->descriptors, hnode, rfd)) {

		rfapiMonitorAttachImportHd(rfd);
		rfapiMonitorEthAttachImportHd(bgp, rfd);
	}
}
