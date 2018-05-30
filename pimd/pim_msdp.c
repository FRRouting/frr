/*
 * IP MSDP for Quagga
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include <lib/hash.h>
#include <lib/jhash.h>
#include <lib/log.h>
#include <lib/prefix.h>
#include <lib/sockunion.h>
#include <lib/stream.h>
#include <lib/thread.h>
#include <lib/vty.h>
#include <lib/plist.h>

#include "pimd.h"
#include "pim_cmd.h"
#include "pim_memory.h"
#include "pim_iface.h"
#include "pim_rp.h"
#include "pim_str.h"
#include "pim_time.h"
#include "pim_upstream.h"
#include "pim_oil.h"

#include "pim_msdp.h"
#include "pim_msdp_packet.h"
#include "pim_msdp_socket.h"

// struct pim_msdp pim_msdp, *msdp = &pim_msdp;

static void pim_msdp_peer_listen(struct pim_msdp_peer *mp);
static void pim_msdp_peer_cr_timer_setup(struct pim_msdp_peer *mp, bool start);
static void pim_msdp_peer_ka_timer_setup(struct pim_msdp_peer *mp, bool start);
static void pim_msdp_peer_hold_timer_setup(struct pim_msdp_peer *mp,
					   bool start);
static void pim_msdp_peer_free(struct pim_msdp_peer *mp);
static void pim_msdp_enable(struct pim_instance *pim);
static void pim_msdp_sa_adv_timer_setup(struct pim_instance *pim, bool start);
static void pim_msdp_sa_deref(struct pim_msdp_sa *sa,
			      enum pim_msdp_sa_flags flags);
static int pim_msdp_mg_mbr_comp(const void *p1, const void *p2);
static void pim_msdp_mg_mbr_free(struct pim_msdp_mg_mbr *mbr);
static void pim_msdp_mg_mbr_do_del(struct pim_msdp_mg *mg,
				   struct pim_msdp_mg_mbr *mbr);

/************************ SA cache management ******************************/
static void pim_msdp_sa_timer_expiry_log(struct pim_msdp_sa *sa,
					 const char *timer_str)
{
	zlog_debug("MSDP SA %s %s timer expired", sa->sg_str, timer_str);
}

/* RFC-3618:Sec-5.1 - global active source advertisement timer */
static int pim_msdp_sa_adv_timer_cb(struct thread *t)
{
	struct pim_instance *pim = THREAD_ARG(t);

	if (PIM_DEBUG_MSDP_EVENTS) {
		zlog_debug("MSDP SA advertisment timer expired");
	}

	pim_msdp_sa_adv_timer_setup(pim, true /* start */);
	pim_msdp_pkt_sa_tx(pim);
	return 0;
}
static void pim_msdp_sa_adv_timer_setup(struct pim_instance *pim, bool start)
{
	THREAD_OFF(pim->msdp.sa_adv_timer);
	if (start) {
		thread_add_timer(pim->msdp.master, pim_msdp_sa_adv_timer_cb,
				 pim, PIM_MSDP_SA_ADVERTISMENT_TIME,
				 &pim->msdp.sa_adv_timer);
	}
}

/* RFC-3618:Sec-5.3 - SA cache state timer */
static int pim_msdp_sa_state_timer_cb(struct thread *t)
{
	struct pim_msdp_sa *sa;

	sa = THREAD_ARG(t);

	if (PIM_DEBUG_MSDP_EVENTS) {
		pim_msdp_sa_timer_expiry_log(sa, "state");
	}

	pim_msdp_sa_deref(sa, PIM_MSDP_SAF_PEER);
	return 0;
}
static void pim_msdp_sa_state_timer_setup(struct pim_msdp_sa *sa, bool start)
{
	THREAD_OFF(sa->sa_state_timer);
	if (start) {
		thread_add_timer(sa->pim->msdp.master,
				 pim_msdp_sa_state_timer_cb, sa,
				 PIM_MSDP_SA_HOLD_TIME, &sa->sa_state_timer);
	}
}

static void pim_msdp_sa_upstream_del(struct pim_msdp_sa *sa)
{
	struct pim_upstream *up = sa->up;
	if (!up) {
		return;
	}

	sa->up = NULL;
	if (PIM_UPSTREAM_FLAG_TEST_SRC_MSDP(up->flags)) {
		PIM_UPSTREAM_FLAG_UNSET_SRC_MSDP(up->flags);
		sa->flags |= PIM_MSDP_SAF_UP_DEL_IN_PROG;
		pim_upstream_del(sa->pim, up, __PRETTY_FUNCTION__);
		sa->flags &= ~PIM_MSDP_SAF_UP_DEL_IN_PROG;
	}

	if (PIM_DEBUG_MSDP_EVENTS) {
		zlog_debug("MSDP SA %s de-referenced SPT", sa->sg_str);
	}
}

static bool pim_msdp_sa_upstream_add_ok(struct pim_msdp_sa *sa,
					struct pim_upstream *xg_up)
{
	if (!(sa->flags & PIM_MSDP_SAF_PEER)) {
		/* SA should have been rxed from a peer */
		return false;
	}
	/* check if we are RP */
	if (!I_am_RP(sa->pim, sa->sg.grp)) {
		return false;
	}

	/* check if we have a (*, G) with a non-empty immediate OIL */
	if (!xg_up) {
		struct prefix_sg sg;

		memset(&sg, 0, sizeof(sg));
		sg.grp = sa->sg.grp;

		xg_up = pim_upstream_find(sa->pim, &sg);
	}
	if (!xg_up || (xg_up->join_state != PIM_UPSTREAM_JOINED)) {
		/* join desired will be true for such (*, G) entries so we will
		 * just look at join_state and let the PIM state machine do the
		 * rest of
		 * the magic */
		return false;
	}

	return true;
}

/* Upstream add evaluation needs to happen everytime -
 * 1. Peer reference is added or removed.
 * 2. The RP for a group changes.
 * 3. joinDesired for the associated (*, G) changes
 * 4. associated (*, G) is removed - this seems like a bit redundant
 *    (considering #4); but just in case an entry gets nuked without
 *    upstream state transition
 *    */
static void pim_msdp_sa_upstream_update(struct pim_msdp_sa *sa,
					struct pim_upstream *xg_up,
					const char *ctx)
{
	struct pim_upstream *up;

	if (!pim_msdp_sa_upstream_add_ok(sa, xg_up)) {
		pim_msdp_sa_upstream_del(sa);
		return;
	}

	if (sa->up) {
		/* nothing to do */
		return;
	}

	up = pim_upstream_find(sa->pim, &sa->sg);
	if (up && (PIM_UPSTREAM_FLAG_TEST_SRC_MSDP(up->flags))) {
		/* somehow we lost track of the upstream ptr? best log it */
		sa->up = up;
		if (PIM_DEBUG_MSDP_EVENTS) {
			zlog_debug("MSDP SA %s SPT reference missing",
				   sa->sg_str);
		}
		return;
	}

	/* RFC3618: "RP triggers a (S, G) join event towards the data source
	 * as if a JP message was rxed addressed to the RP itself." */
	up = pim_upstream_add(sa->pim, &sa->sg, NULL /* iif */,
			      PIM_UPSTREAM_FLAG_MASK_SRC_MSDP,
			      __PRETTY_FUNCTION__, NULL);

	sa->up = up;
	if (up) {
		/* update inherited oil */
		pim_upstream_inherited_olist(sa->pim, up);
		/* should we also start the kat in parallel? we will need it
		 * when the
		 * SA ages out */
		if (PIM_DEBUG_MSDP_EVENTS) {
			zlog_debug("MSDP SA %s referenced SPT", sa->sg_str);
		}
	} else {
		if (PIM_DEBUG_MSDP_EVENTS) {
			zlog_debug("MSDP SA %s SPT reference failed",
				   sa->sg_str);
		}
	}
}

/* release all mem associated with a sa */
static void pim_msdp_sa_free(struct pim_msdp_sa *sa)
{
	pim_msdp_sa_state_timer_setup(sa, false);

	XFREE(MTYPE_PIM_MSDP_SA, sa);
}

static struct pim_msdp_sa *pim_msdp_sa_new(struct pim_instance *pim,
					   struct prefix_sg *sg,
					   struct in_addr rp)
{
	struct pim_msdp_sa *sa;

	sa = XCALLOC(MTYPE_PIM_MSDP_SA, sizeof(*sa));
	if (!sa) {
		zlog_err("%s: PIM XCALLOC(%zu) failure", __PRETTY_FUNCTION__,
			 sizeof(*sa));
		return NULL;
	}

	sa->pim = pim;
	sa->sg = *sg;
	pim_str_sg_set(sg, sa->sg_str);
	sa->rp = rp;
	sa->uptime = pim_time_monotonic_sec();

	/* insert into misc tables for easy access */
	sa = hash_get(pim->msdp.sa_hash, sa, hash_alloc_intern);
	listnode_add_sort(pim->msdp.sa_list, sa);

	if (PIM_DEBUG_MSDP_EVENTS) {
		zlog_debug("MSDP SA %s created", sa->sg_str);
	}

	return sa;
}

static struct pim_msdp_sa *pim_msdp_sa_find(struct pim_instance *pim,
					    struct prefix_sg *sg)
{
	struct pim_msdp_sa lookup;

	lookup.sg = *sg;
	return hash_lookup(pim->msdp.sa_hash, &lookup);
}

static struct pim_msdp_sa *pim_msdp_sa_add(struct pim_instance *pim,
					   struct prefix_sg *sg,
					   struct in_addr rp)
{
	struct pim_msdp_sa *sa;

	sa = pim_msdp_sa_find(pim, sg);
	if (sa) {
		return sa;
	}

	return pim_msdp_sa_new(pim, sg, rp);
}

static void pim_msdp_sa_del(struct pim_msdp_sa *sa)
{
	/* this is somewhat redundant - still want to be careful not to leave
	 * stale upstream references */
	pim_msdp_sa_upstream_del(sa);

	/* stop timers */
	pim_msdp_sa_state_timer_setup(sa, false /* start */);

	/* remove the entry from various tables */
	listnode_delete(sa->pim->msdp.sa_list, sa);
	hash_release(sa->pim->msdp.sa_hash, sa);

	if (PIM_DEBUG_MSDP_EVENTS) {
		zlog_debug("MSDP SA %s deleted", sa->sg_str);
	}

	/* free up any associated memory */
	pim_msdp_sa_free(sa);
}

static void pim_msdp_sa_peer_ip_set(struct pim_msdp_sa *sa,
				    struct pim_msdp_peer *mp, struct in_addr rp)
{
	struct pim_msdp_peer *old_mp;

	/* optimize the "no change" case as it will happen
	 * frequently/periodically */
	if (mp && (sa->peer.s_addr == mp->peer.s_addr)) {
		return;
	}

	/* any time the peer ip changes also update the rp address */
	if (PIM_INADDR_ISNOT_ANY(sa->peer)) {
		old_mp = pim_msdp_peer_find(sa->pim, sa->peer);
		if (old_mp && old_mp->sa_cnt) {
			--old_mp->sa_cnt;
		}
	}

	if (mp) {
		++mp->sa_cnt;
		sa->peer = mp->peer;
	} else {
		sa->peer.s_addr = PIM_NET_INADDR_ANY;
	}
	sa->rp = rp;
}

/* When a local active-source is removed there is no way to withdraw the
 * source from peers. We will simply remove it from the SA cache so it will
 * not be sent in supsequent SA updates. Peers will consequently timeout the
 * SA.
 * Similarly a "peer-added" SA is never explicitly deleted. It is simply
 * aged out overtime if not seen in the SA updates from the peers.
 * XXX: should we provide a knob to drop entries learnt from a peer when the
 * peer goes down? */
static void pim_msdp_sa_deref(struct pim_msdp_sa *sa,
			      enum pim_msdp_sa_flags flags)
{
	bool update_up = false;

	if ((sa->flags & PIM_MSDP_SAF_LOCAL)) {
		if (flags & PIM_MSDP_SAF_LOCAL) {
			if (PIM_DEBUG_MSDP_EVENTS) {
				zlog_debug("MSDP SA %s local reference removed",
					   sa->sg_str);
			}
			if (sa->pim->msdp.local_cnt)
				--sa->pim->msdp.local_cnt;
		}
	}

	if ((sa->flags & PIM_MSDP_SAF_PEER)) {
		if (flags & PIM_MSDP_SAF_PEER) {
			struct in_addr rp;

			if (PIM_DEBUG_MSDP_EVENTS) {
				zlog_debug("MSDP SA %s peer reference removed",
					   sa->sg_str);
			}
			pim_msdp_sa_state_timer_setup(sa, false /* start */);
			rp.s_addr = INADDR_ANY;
			pim_msdp_sa_peer_ip_set(sa, NULL /* mp */, rp);
			/* if peer ref was removed we need to remove the msdp
			 * reference on the
			 * msdp entry */
			update_up = true;
		}
	}

	sa->flags &= ~flags;
	if (update_up) {
		pim_msdp_sa_upstream_update(sa, NULL /* xg_up */, "sa-deref");
	}

	if (!(sa->flags & PIM_MSDP_SAF_REF)) {
		pim_msdp_sa_del(sa);
	}
}

void pim_msdp_sa_ref(struct pim_instance *pim, struct pim_msdp_peer *mp,
		     struct prefix_sg *sg, struct in_addr rp)
{
	struct pim_msdp_sa *sa;

	sa = pim_msdp_sa_add(pim, sg, rp);
	if (!sa) {
		return;
	}

	/* reference it */
	if (mp) {
		if (!(sa->flags & PIM_MSDP_SAF_PEER)) {
			sa->flags |= PIM_MSDP_SAF_PEER;
			if (PIM_DEBUG_MSDP_EVENTS) {
				zlog_debug("MSDP SA %s added by peer",
					   sa->sg_str);
			}
		}
		pim_msdp_sa_peer_ip_set(sa, mp, rp);
		/* start/re-start the state timer to prevent cache expiry */
		pim_msdp_sa_state_timer_setup(sa, true /* start */);
		/* We re-evaluate SA "SPT-trigger" everytime we hear abt it from
		 * a
		 * peer. XXX: If this becomes too much of a periodic overhead we
		 * can make it event based */
		pim_msdp_sa_upstream_update(sa, NULL /* xg_up */, "peer-ref");
	} else {
		if (!(sa->flags & PIM_MSDP_SAF_LOCAL)) {
			sa->flags |= PIM_MSDP_SAF_LOCAL;
			++sa->pim->msdp.local_cnt;
			if (PIM_DEBUG_MSDP_EVENTS) {
				zlog_debug("MSDP SA %s added locally",
					   sa->sg_str);
			}
			/* send an immediate SA update to peers */
			pim_msdp_pkt_sa_tx_one(sa);
		}
		sa->flags &= ~PIM_MSDP_SAF_STALE;
	}
}

/* The following criteria must be met to originate an SA from the MSDP
 * speaker -
 * 1. KAT must be running i.e. source is active.
 * 2. We must be RP for the group.
 * 3. Source must be registrable to the RP (this is where the RFC is vague
 *    and especially ambiguous in CLOS networks; with anycast RP all sources
 *    are potentially registrable to all RPs in the domain). We assume #3 is
 *    satisfied if -
 *    a. We are also the FHR-DR for the source (OR)
 *    b. We rxed a pim register (null or data encapsulated) within the last
 *       (3 * (1.5 * register_suppression_timer))).
 */
static bool pim_msdp_sa_local_add_ok(struct pim_upstream *up)
{
	struct pim_instance *pim = up->channel_oil->pim;

	if (!(pim->msdp.flags & PIM_MSDPF_ENABLE)) {
		return false;
	}

	if (!up->t_ka_timer) {
		/* stream is not active */
		return false;
	}

	if (!I_am_RP(pim, up->sg.grp)) {
		/* we are not RP for the group */
		return false;
	}

	/* we are the FHR-DR for this stream  or we are RP and have seen
	 * registers
	 * from a FHR for this source */
	if (PIM_UPSTREAM_FLAG_TEST_FHR(up->flags) || up->t_msdp_reg_timer) {
		return true;
	}

	return false;
}

static void pim_msdp_sa_local_add(struct pim_instance *pim,
				  struct prefix_sg *sg)
{
	struct in_addr rp;
	rp.s_addr = 0;
	pim_msdp_sa_ref(pim, NULL /* mp */, sg, rp);
}

void pim_msdp_sa_local_del(struct pim_instance *pim, struct prefix_sg *sg)
{
	struct pim_msdp_sa *sa;

	sa = pim_msdp_sa_find(pim, sg);
	if (sa) {
		pim_msdp_sa_deref(sa, PIM_MSDP_SAF_LOCAL);
	}
}

/* we need to be very cautious with this API as SA del too can trigger an
 * upstream del and we will get stuck in a simple loop */
static void pim_msdp_sa_local_del_on_up_del(struct pim_instance *pim,
					    struct prefix_sg *sg)
{
	struct pim_msdp_sa *sa;

	sa = pim_msdp_sa_find(pim, sg);
	if (sa) {
		if (PIM_DEBUG_MSDP_INTERNAL) {
			zlog_debug("MSDP local sa %s del on up del",
				   sa->sg_str);
		}

		/* if there is no local reference escape */
		if (!(sa->flags & PIM_MSDP_SAF_LOCAL)) {
			if (PIM_DEBUG_MSDP_INTERNAL) {
				zlog_debug("MSDP local sa %s del; no local ref",
					   sa->sg_str);
			}
			return;
		}

		if (sa->flags & PIM_MSDP_SAF_UP_DEL_IN_PROG) {
			/* MSDP is the one that triggered the upstream del. if
			 * this happens
			 * we most certainly have a bug in the PIM upstream
			 * state machine. We
			 * will not have a local reference unless the KAT is
			 * running. And if the
			 * KAT is running there MUST be an additional
			 * source-stream reference to
			 * the flow. Accounting for such cases requires lot of
			 * changes; perhaps
			 * address this in the next release? - XXX  */
			zlog_err(
				"MSDP sa %s SPT teardown is causing the local entry to be removed",
				sa->sg_str);
			return;
		}

		/* we are dropping the sa on upstream del we should not have an
		 * upstream reference */
		if (sa->up) {
			if (PIM_DEBUG_MSDP_INTERNAL) {
				zlog_debug("MSDP local sa %s del; up non-NULL",
					   sa->sg_str);
			}
			sa->up = NULL;
		}
		pim_msdp_sa_deref(sa, PIM_MSDP_SAF_LOCAL);
	}
}

/* Local SA qualification needs to be re-evaluated when -
 * 1. KAT is started or stopped
 * 2. on RP changes
 * 3. Whenever FHR status changes for a (S,G) - XXX - currently there
 *    is no clear path to transition an entry out of "MASK_FHR" need
 *    to discuss this with Donald. May result in some strangeness if the
 *    FHR is also the RP.
 * 4. When msdp_reg timer is started or stopped
 */
void pim_msdp_sa_local_update(struct pim_upstream *up)
{
	struct pim_instance *pim = up->channel_oil->pim;

	if (pim_msdp_sa_local_add_ok(up)) {
		pim_msdp_sa_local_add(pim, &up->sg);
	} else {
		pim_msdp_sa_local_del(pim, &up->sg);
	}
}

static void pim_msdp_sa_local_setup(struct pim_instance *pim)
{
	struct pim_upstream *up;
	struct listnode *up_node;

	for (ALL_LIST_ELEMENTS_RO(pim->upstream_list, up_node, up)) {
		pim_msdp_sa_local_update(up);
	}
}

/* whenever the RP changes we need to re-evaluate the "local" SA-cache */
/* XXX: needs to be tested */
void pim_msdp_i_am_rp_changed(struct pim_instance *pim)
{
	struct listnode *sanode;
	struct listnode *nextnode;
	struct pim_msdp_sa *sa;

	if (!(pim->msdp.flags & PIM_MSDPF_ENABLE)) {
		/* if the feature is not enabled do nothing */
		return;
	}

	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP i_am_rp changed");
	}

	/* mark all local entries as stale */
	for (ALL_LIST_ELEMENTS_RO(pim->msdp.sa_list, sanode, sa)) {
		if (sa->flags & PIM_MSDP_SAF_LOCAL) {
			sa->flags |= PIM_MSDP_SAF_STALE;
		}
	}

	/* re-setup local SA entries */
	pim_msdp_sa_local_setup(pim);

	for (ALL_LIST_ELEMENTS(pim->msdp.sa_list, sanode, nextnode, sa)) {
		/* purge stale SA entries */
		if (sa->flags & PIM_MSDP_SAF_STALE) {
			/* clear the stale flag; the entry may be kept even
			 * after
			 * "local-deref" */
			sa->flags &= ~PIM_MSDP_SAF_STALE;
			/* sa_deref can end up freeing the sa; so don't access
			 * contents after */
			pim_msdp_sa_deref(sa, PIM_MSDP_SAF_LOCAL);
		} else {
			/* if the souce is still active check if we can
			 * influence SPT */
			pim_msdp_sa_upstream_update(sa, NULL /* xg_up */,
						    "rp-change");
		}
	}
}

/* We track the join state of (*, G) entries. If G has sources in the SA-cache
 * we need to setup or teardown SPT when the JoinDesired status changes for
 * (*, G) */
void pim_msdp_up_join_state_changed(struct pim_instance *pim,
				    struct pim_upstream *xg_up)
{
	struct listnode *sanode;
	struct pim_msdp_sa *sa;

	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP join state changed for %s", xg_up->sg_str);
	}

	/* If this is not really an XG entry just move on */
	if ((xg_up->sg.src.s_addr != INADDR_ANY)
	    || (xg_up->sg.grp.s_addr == INADDR_ANY)) {
		return;
	}

	/* XXX: Need to maintain SAs per-group to avoid all this unnecessary
	 * walking */
	for (ALL_LIST_ELEMENTS_RO(pim->msdp.sa_list, sanode, sa)) {
		if (sa->sg.grp.s_addr != xg_up->sg.grp.s_addr) {
			continue;
		}
		pim_msdp_sa_upstream_update(sa, xg_up, "up-jp-change");
	}
}

static void pim_msdp_up_xg_del(struct pim_instance *pim, struct prefix_sg *sg)
{
	struct listnode *sanode;
	struct pim_msdp_sa *sa;

	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP %s del", pim_str_sg_dump(sg));
	}

	/* If this is not really an XG entry just move on */
	if ((sg->src.s_addr != INADDR_ANY) || (sg->grp.s_addr == INADDR_ANY)) {
		return;
	}

	/* XXX: Need to maintain SAs per-group to avoid all this unnecessary
	 * walking */
	for (ALL_LIST_ELEMENTS_RO(pim->msdp.sa_list, sanode, sa)) {
		if (sa->sg.grp.s_addr != sg->grp.s_addr) {
			continue;
		}
		pim_msdp_sa_upstream_update(sa, NULL /* xg */, "up-jp-change");
	}
}

void pim_msdp_up_del(struct pim_instance *pim, struct prefix_sg *sg)
{
	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP up %s del", pim_str_sg_dump(sg));
	}
	if (sg->src.s_addr == INADDR_ANY) {
		pim_msdp_up_xg_del(pim, sg);
	} else {
		pim_msdp_sa_local_del_on_up_del(pim, sg);
	}
}

/* sa hash and peer list helpers */
static unsigned int pim_msdp_sa_hash_key_make(void *p)
{
	struct pim_msdp_sa *sa = p;

	return (jhash_2words(sa->sg.src.s_addr, sa->sg.grp.s_addr, 0));
}

static int pim_msdp_sa_hash_eq(const void *p1, const void *p2)
{
	const struct pim_msdp_sa *sa1 = p1;
	const struct pim_msdp_sa *sa2 = p2;

	return ((sa1->sg.src.s_addr == sa2->sg.src.s_addr)
		&& (sa1->sg.grp.s_addr == sa2->sg.grp.s_addr));
}

static int pim_msdp_sa_comp(const void *p1, const void *p2)
{
	const struct pim_msdp_sa *sa1 = p1;
	const struct pim_msdp_sa *sa2 = p2;

	if (ntohl(sa1->sg.grp.s_addr) < ntohl(sa2->sg.grp.s_addr))
		return -1;

	if (ntohl(sa1->sg.grp.s_addr) > ntohl(sa2->sg.grp.s_addr))
		return 1;

	if (ntohl(sa1->sg.src.s_addr) < ntohl(sa2->sg.src.s_addr))
		return -1;

	if (ntohl(sa1->sg.src.s_addr) > ntohl(sa2->sg.src.s_addr))
		return 1;

	return 0;
}

/* RFC-3618:Sec-10.1.3 - Peer-RPF forwarding */
/* XXX: this can use a bit of refining and extensions */
bool pim_msdp_peer_rpf_check(struct pim_msdp_peer *mp, struct in_addr rp)
{
	if (mp->peer.s_addr == rp.s_addr) {
		return true;
	}

	return false;
}

/************************ Peer session management **************************/
char *pim_msdp_state_dump(enum pim_msdp_peer_state state, char *buf,
			  int buf_size)
{
	switch (state) {
	case PIM_MSDP_DISABLED:
		snprintf(buf, buf_size, "%s", "disabled");
		break;
	case PIM_MSDP_INACTIVE:
		snprintf(buf, buf_size, "%s", "inactive");
		break;
	case PIM_MSDP_LISTEN:
		snprintf(buf, buf_size, "%s", "listen");
		break;
	case PIM_MSDP_CONNECTING:
		snprintf(buf, buf_size, "%s", "connecting");
		break;
	case PIM_MSDP_ESTABLISHED:
		snprintf(buf, buf_size, "%s", "established");
		break;
	default:
		snprintf(buf, buf_size, "unk-%d", state);
	}
	return buf;
}

char *pim_msdp_peer_key_dump(struct pim_msdp_peer *mp, char *buf, int buf_size,
			     bool long_format)
{
	char peer_str[INET_ADDRSTRLEN];
	char local_str[INET_ADDRSTRLEN];

	pim_inet4_dump("<peer?>", mp->peer, peer_str, sizeof(peer_str));
	if (long_format) {
		pim_inet4_dump("<local?>", mp->local, local_str,
			       sizeof(local_str));
		snprintf(buf, buf_size, "MSDP peer %s local %s mg %s", peer_str,
			 local_str, mp->mesh_group_name);
	} else {
		snprintf(buf, buf_size, "MSDP peer %s", peer_str);
	}

	return buf;
}

static void pim_msdp_peer_state_chg_log(struct pim_msdp_peer *mp)
{
	char state_str[PIM_MSDP_STATE_STRLEN];

	pim_msdp_state_dump(mp->state, state_str, sizeof(state_str));
	zlog_debug("MSDP peer %s state chg to %s", mp->key_str, state_str);
}

/* MSDP Connection State Machine actions (defined in RFC-3618:Sec-11.2) */
/* 11.2.A2: active peer - start connect retry timer; when the timer fires
 * a tcp connection will be made */
static void pim_msdp_peer_connect(struct pim_msdp_peer *mp)
{
	mp->state = PIM_MSDP_CONNECTING;
	if (PIM_DEBUG_MSDP_EVENTS) {
		pim_msdp_peer_state_chg_log(mp);
	}

	pim_msdp_peer_cr_timer_setup(mp, true /* start */);
}

/* 11.2.A3: passive peer - just listen for connections */
static void pim_msdp_peer_listen(struct pim_msdp_peer *mp)
{
	mp->state = PIM_MSDP_LISTEN;
	if (PIM_DEBUG_MSDP_EVENTS) {
		pim_msdp_peer_state_chg_log(mp);
	}

	/* this is interntionally asymmetric i.e. we set up listen-socket when
	* the
	* first listening peer is configured; but don't bother tearing it down
	* when
	* all the peers go down */
	pim_msdp_sock_listen(mp->pim);
}

/* 11.2.A4 and 11.2.A5: transition active or passive peer to
 * established state */
void pim_msdp_peer_established(struct pim_msdp_peer *mp)
{
	if (mp->state != PIM_MSDP_ESTABLISHED) {
		++mp->est_flaps;
	}

	mp->state = PIM_MSDP_ESTABLISHED;
	mp->uptime = pim_time_monotonic_sec();

	if (PIM_DEBUG_MSDP_EVENTS) {
		pim_msdp_peer_state_chg_log(mp);
	}

	/* stop retry timer on active peers */
	pim_msdp_peer_cr_timer_setup(mp, false /* start */);

	/* send KA; start KA and hold timers */
	pim_msdp_pkt_ka_tx(mp);
	pim_msdp_peer_ka_timer_setup(mp, true /* start */);
	pim_msdp_peer_hold_timer_setup(mp, true /* start */);

	pim_msdp_pkt_sa_tx_to_one_peer(mp);

	PIM_MSDP_PEER_WRITE_ON(mp);
	PIM_MSDP_PEER_READ_ON(mp);
}

/* 11.2.A6, 11.2.A7 and 11.2.A8: shutdown the peer tcp connection */
void pim_msdp_peer_stop_tcp_conn(struct pim_msdp_peer *mp, bool chg_state)
{
	if (chg_state) {
		if (mp->state == PIM_MSDP_ESTABLISHED) {
			++mp->est_flaps;
		}
		mp->state = PIM_MSDP_INACTIVE;
		if (PIM_DEBUG_MSDP_EVENTS) {
			pim_msdp_peer_state_chg_log(mp);
		}
	}

	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP peer %s pim_msdp_peer_stop_tcp_conn",
			   mp->key_str);
	}
	/* stop read and write threads */
	PIM_MSDP_PEER_READ_OFF(mp);
	PIM_MSDP_PEER_WRITE_OFF(mp);

	/* reset buffers */
	mp->packet_size = 0;
	if (mp->ibuf)
		stream_reset(mp->ibuf);
	if (mp->obuf)
		stream_fifo_clean(mp->obuf);

	/* stop all peer timers */
	pim_msdp_peer_ka_timer_setup(mp, false /* start */);
	pim_msdp_peer_cr_timer_setup(mp, false /* start */);
	pim_msdp_peer_hold_timer_setup(mp, false /* start */);

	/* close connection */
	if (mp->fd >= 0) {
		close(mp->fd);
		mp->fd = -1;
	}
}

/* RFC-3618:Sec-5.6 - stop the peer tcp connection and startover */
void pim_msdp_peer_reset_tcp_conn(struct pim_msdp_peer *mp, const char *rc_str)
{
	if (PIM_DEBUG_EVENTS) {
		zlog_debug("MSDP peer %s tcp reset %s", mp->key_str, rc_str);
		snprintf(mp->last_reset, sizeof(mp->last_reset), "%s", rc_str);
	}

	/* close the connection and transition to listening or connecting */
	pim_msdp_peer_stop_tcp_conn(mp, true /* chg_state */);
	if (PIM_MSDP_PEER_IS_LISTENER(mp)) {
		pim_msdp_peer_listen(mp);
	} else {
		pim_msdp_peer_connect(mp);
	}
}

static void pim_msdp_peer_timer_expiry_log(struct pim_msdp_peer *mp,
					   const char *timer_str)
{
	zlog_debug("MSDP peer %s %s timer expired", mp->key_str, timer_str);
}

/* RFC-3618:Sec-5.4 - peer hold timer */
static int pim_msdp_peer_hold_timer_cb(struct thread *t)
{
	struct pim_msdp_peer *mp;

	mp = THREAD_ARG(t);

	if (PIM_DEBUG_MSDP_EVENTS) {
		pim_msdp_peer_timer_expiry_log(mp, "hold");
	}

	if (mp->state != PIM_MSDP_ESTABLISHED) {
		return 0;
	}

	if (PIM_DEBUG_MSDP_EVENTS) {
		pim_msdp_peer_state_chg_log(mp);
	}
	pim_msdp_peer_reset_tcp_conn(mp, "ht-expired");
	return 0;
}

static void pim_msdp_peer_hold_timer_setup(struct pim_msdp_peer *mp, bool start)
{
	struct pim_instance *pim = mp->pim;
	THREAD_OFF(mp->hold_timer);
	if (start) {
		thread_add_timer(pim->msdp.master, pim_msdp_peer_hold_timer_cb,
				 mp, PIM_MSDP_PEER_HOLD_TIME, &mp->hold_timer);
	}
}


/* RFC-3618:Sec-5.5 - peer keepalive timer */
static int pim_msdp_peer_ka_timer_cb(struct thread *t)
{
	struct pim_msdp_peer *mp;

	mp = THREAD_ARG(t);

	if (PIM_DEBUG_MSDP_EVENTS) {
		pim_msdp_peer_timer_expiry_log(mp, "ka");
	}

	pim_msdp_pkt_ka_tx(mp);
	pim_msdp_peer_ka_timer_setup(mp, true /* start */);
	return 0;
}
static void pim_msdp_peer_ka_timer_setup(struct pim_msdp_peer *mp, bool start)
{
	THREAD_OFF(mp->ka_timer);
	if (start) {
		thread_add_timer(mp->pim->msdp.master,
				 pim_msdp_peer_ka_timer_cb, mp,
				 PIM_MSDP_PEER_KA_TIME, &mp->ka_timer);
	}
}

static void pim_msdp_peer_active_connect(struct pim_msdp_peer *mp)
{
	int rc;
	++mp->conn_attempts;
	rc = pim_msdp_sock_connect(mp);

	if (PIM_DEBUG_MSDP_INTERNAL) {
		zlog_debug("MSDP peer %s pim_msdp_peer_active_connect: %d",
			   mp->key_str, rc);
	}

	switch (rc) {
	case connect_error:
	case -1:
		/* connect failed restart the connect-retry timer */
		pim_msdp_peer_cr_timer_setup(mp, true /* start */);
		break;

	case connect_success:
		/* connect was sucessful move to established */
		pim_msdp_peer_established(mp);
		break;

	case connect_in_progress:
		/* for NB content we need to wait till sock is readable or
		 * writeable */
		PIM_MSDP_PEER_WRITE_ON(mp);
		PIM_MSDP_PEER_READ_ON(mp);
		/* also restart connect-retry timer to reset the socket if
		 * connect is
		 * not sucessful */
		pim_msdp_peer_cr_timer_setup(mp, true /* start */);
		break;
	}
}

/* RFC-3618:Sec-5.6 - connection retry on active peer */
static int pim_msdp_peer_cr_timer_cb(struct thread *t)
{
	struct pim_msdp_peer *mp;

	mp = THREAD_ARG(t);

	if (PIM_DEBUG_MSDP_EVENTS) {
		pim_msdp_peer_timer_expiry_log(mp, "connect-retry");
	}

	if (mp->state != PIM_MSDP_CONNECTING || PIM_MSDP_PEER_IS_LISTENER(mp)) {
		return 0;
	}

	pim_msdp_peer_active_connect(mp);
	return 0;
}
static void pim_msdp_peer_cr_timer_setup(struct pim_msdp_peer *mp, bool start)
{
	THREAD_OFF(mp->cr_timer);
	if (start) {
		thread_add_timer(
			mp->pim->msdp.master, pim_msdp_peer_cr_timer_cb, mp,
			PIM_MSDP_PEER_CONNECT_RETRY_TIME, &mp->cr_timer);
	}
}

/* if a valid packet is rxed from the peer we can restart hold timer */
void pim_msdp_peer_pkt_rxed(struct pim_msdp_peer *mp)
{
	if (mp->state == PIM_MSDP_ESTABLISHED) {
		pim_msdp_peer_hold_timer_setup(mp, true /* start */);
	}
}

/* if a valid packet is txed to the peer we can restart ka timer and avoid
 * unnecessary ka noise in the network */
void pim_msdp_peer_pkt_txed(struct pim_msdp_peer *mp)
{
	if (mp->state == PIM_MSDP_ESTABLISHED) {
		pim_msdp_peer_ka_timer_setup(mp, true /* start */);
		if (PIM_DEBUG_MSDP_INTERNAL) {
			zlog_debug("MSDP ka timer restart on pkt tx to %s",
				   mp->key_str);
		}
	}
}

static void pim_msdp_addr2su(union sockunion *su, struct in_addr addr)
{
	sockunion_init(su);
	su->sin.sin_addr = addr;
	su->sin.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	su->sin.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
}

/* 11.2.A1: create a new peer and transition state to listen or connecting */
static enum pim_msdp_err pim_msdp_peer_new(struct pim_instance *pim,
					   struct in_addr peer_addr,
					   struct in_addr local_addr,
					   const char *mesh_group_name,
					   struct pim_msdp_peer **mp_p)
{
	struct pim_msdp_peer *mp;

	pim_msdp_enable(pim);

	mp = XCALLOC(MTYPE_PIM_MSDP_PEER, sizeof(*mp));
	if (!mp) {
		zlog_err("%s: PIM XCALLOC(%zu) failure", __PRETTY_FUNCTION__,
			 sizeof(*mp));
		return PIM_MSDP_ERR_OOM;
	}

	mp->pim = pim;
	mp->peer = peer_addr;
	pim_inet4_dump("<peer?>", mp->peer, mp->key_str, sizeof(mp->key_str));
	pim_msdp_addr2su(&mp->su_peer, mp->peer);
	mp->local = local_addr;
	/* XXX: originator_id setting needs to move to the mesh group */
	pim->msdp.originator_id = local_addr;
	pim_msdp_addr2su(&mp->su_local, mp->local);
	mp->mesh_group_name = XSTRDUP(MTYPE_PIM_MSDP_MG_NAME, mesh_group_name);
	mp->state = PIM_MSDP_INACTIVE;
	mp->fd = -1;
	strcpy(mp->last_reset, "-");
	/* higher IP address is listener */
	if (ntohl(mp->local.s_addr) > ntohl(mp->peer.s_addr)) {
		mp->flags |= PIM_MSDP_PEERF_LISTENER;
	}

	/* setup packet buffers */
	mp->ibuf = stream_new(PIM_MSDP_MAX_PACKET_SIZE);
	mp->obuf = stream_fifo_new();

	/* insert into misc tables for easy access */
	mp = hash_get(pim->msdp.peer_hash, mp, hash_alloc_intern);
	listnode_add_sort(pim->msdp.peer_list, mp);

	if (PIM_DEBUG_MSDP_EVENTS) {
		zlog_debug("MSDP peer %s created", mp->key_str);

		pim_msdp_peer_state_chg_log(mp);
	}

	/* fireup the connect state machine */
	if (PIM_MSDP_PEER_IS_LISTENER(mp)) {
		pim_msdp_peer_listen(mp);
	} else {
		pim_msdp_peer_connect(mp);
	}
	if (mp_p) {
		*mp_p = mp;
	}
	return PIM_MSDP_ERR_NONE;
}

struct pim_msdp_peer *pim_msdp_peer_find(struct pim_instance *pim,
					 struct in_addr peer_addr)
{
	struct pim_msdp_peer lookup;

	lookup.peer = peer_addr;
	return hash_lookup(pim->msdp.peer_hash, &lookup);
}

/* add peer configuration if it doesn't already exist */
enum pim_msdp_err pim_msdp_peer_add(struct pim_instance *pim,
				    struct in_addr peer_addr,
				    struct in_addr local_addr,
				    const char *mesh_group_name,
				    struct pim_msdp_peer **mp_p)
{
	struct pim_msdp_peer *mp;

	if (mp_p) {
		*mp_p = NULL;
	}

	if (peer_addr.s_addr == local_addr.s_addr) {
		/* skip session setup if config is invalid */
		if (PIM_DEBUG_MSDP_EVENTS) {
			char peer_str[INET_ADDRSTRLEN];

			pim_inet4_dump("<peer?>", peer_addr, peer_str,
				       sizeof(peer_str));
			zlog_debug("%s add skipped as DIP=SIP", peer_str);
		}
		return PIM_MSDP_ERR_SIP_EQ_DIP;
	}

	mp = pim_msdp_peer_find(pim, peer_addr);
	if (mp) {
		if (mp_p) {
			*mp_p = mp;
		}
		return PIM_MSDP_ERR_PEER_EXISTS;
	}

	return pim_msdp_peer_new(pim, peer_addr, local_addr, mesh_group_name,
				 mp_p);
}

/* release all mem associated with a peer */
static void pim_msdp_peer_free(struct pim_msdp_peer *mp)
{
	/*
	 * Let's make sure we are not running when we delete
	 * the underlying data structure
	 */
	pim_msdp_peer_stop_tcp_conn(mp, false);

	if (mp->ibuf) {
		stream_free(mp->ibuf);
	}

	if (mp->obuf) {
		stream_fifo_free(mp->obuf);
	}

	if (mp->mesh_group_name) {
		XFREE(MTYPE_PIM_MSDP_MG_NAME, mp->mesh_group_name);
	}

	mp->pim = NULL;
	XFREE(MTYPE_PIM_MSDP_PEER, mp);
}

/* delete the peer config */
static enum pim_msdp_err pim_msdp_peer_do_del(struct pim_msdp_peer *mp)
{
	/* stop the tcp connection and shutdown all timers */
	pim_msdp_peer_stop_tcp_conn(mp, true /* chg_state */);

	/* remove the session from various tables */
	listnode_delete(mp->pim->msdp.peer_list, mp);
	hash_release(mp->pim->msdp.peer_hash, mp);

	if (PIM_DEBUG_MSDP_EVENTS) {
		zlog_debug("MSDP peer %s deleted", mp->key_str);
	}

	/* free up any associated memory */
	pim_msdp_peer_free(mp);

	return PIM_MSDP_ERR_NONE;
}

enum pim_msdp_err pim_msdp_peer_del(struct pim_instance *pim,
				    struct in_addr peer_addr)
{
	struct pim_msdp_peer *mp;

	mp = pim_msdp_peer_find(pim, peer_addr);
	if (!mp) {
		return PIM_MSDP_ERR_NO_PEER;
	}

	return pim_msdp_peer_do_del(mp);
}

/* peer hash and peer list helpers */
static unsigned int pim_msdp_peer_hash_key_make(void *p)
{
	struct pim_msdp_peer *mp = p;
	return (jhash_1word(mp->peer.s_addr, 0));
}

static int pim_msdp_peer_hash_eq(const void *p1, const void *p2)
{
	const struct pim_msdp_peer *mp1 = p1;
	const struct pim_msdp_peer *mp2 = p2;

	return (mp1->peer.s_addr == mp2->peer.s_addr);
}

static int pim_msdp_peer_comp(const void *p1, const void *p2)
{
	const struct pim_msdp_peer *mp1 = p1;
	const struct pim_msdp_peer *mp2 = p2;

	if (ntohl(mp1->peer.s_addr) < ntohl(mp2->peer.s_addr))
		return -1;

	if (ntohl(mp1->peer.s_addr) > ntohl(mp2->peer.s_addr))
		return 1;

	return 0;
}

/************************** Mesh group management **************************/
static void pim_msdp_mg_free(struct pim_instance *pim, struct pim_msdp_mg *mg)
{
	/* If the mesh-group has valid member or src_ip don't delete it */
	if (!mg || mg->mbr_cnt || (mg->src_ip.s_addr != INADDR_ANY)) {
		return;
	}

	if (PIM_DEBUG_MSDP_EVENTS) {
		zlog_debug("MSDP mesh-group %s deleted", mg->mesh_group_name);
	}
	if (mg->mesh_group_name)
		XFREE(MTYPE_PIM_MSDP_MG_NAME, mg->mesh_group_name);

	if (mg->mbr_list)
		list_delete_and_null(&mg->mbr_list);

	XFREE(MTYPE_PIM_MSDP_MG, mg);
	pim->msdp.mg = NULL;
}

static struct pim_msdp_mg *pim_msdp_mg_new(const char *mesh_group_name)
{
	struct pim_msdp_mg *mg;

	mg = XCALLOC(MTYPE_PIM_MSDP_MG, sizeof(*mg));
	if (!mg) {
		zlog_err("%s: PIM XCALLOC(%zu) failure", __PRETTY_FUNCTION__,
			 sizeof(*mg));
		return NULL;
	}

	mg->mesh_group_name = XSTRDUP(MTYPE_PIM_MSDP_MG_NAME, mesh_group_name);
	mg->mbr_list = list_new();
	mg->mbr_list->del = (void (*)(void *))pim_msdp_mg_mbr_free;
	mg->mbr_list->cmp = (int (*)(void *, void *))pim_msdp_mg_mbr_comp;

	if (PIM_DEBUG_MSDP_EVENTS) {
		zlog_debug("MSDP mesh-group %s created", mg->mesh_group_name);
	}
	return mg;
}

enum pim_msdp_err pim_msdp_mg_del(struct pim_instance *pim,
				  const char *mesh_group_name)
{
	struct pim_msdp_mg *mg = pim->msdp.mg;
	struct pim_msdp_mg_mbr *mbr;

	if (!mg || strcmp(mg->mesh_group_name, mesh_group_name)) {
		return PIM_MSDP_ERR_NO_MG;
	}

	/* delete all the mesh-group members */
	while (!list_isempty(mg->mbr_list)) {
		mbr = listnode_head(mg->mbr_list);
		pim_msdp_mg_mbr_do_del(mg, mbr);
	}

	/* clear src ip */
	mg->src_ip.s_addr = INADDR_ANY;

	/* free up the mesh-group */
	pim_msdp_mg_free(pim, mg);
	return PIM_MSDP_ERR_NONE;
}

static enum pim_msdp_err pim_msdp_mg_add(struct pim_instance *pim,
					 const char *mesh_group_name)
{
	if (pim->msdp.mg) {
		if (!strcmp(pim->msdp.mg->mesh_group_name, mesh_group_name)) {
			return PIM_MSDP_ERR_NONE;
		}
		/* currently only one mesh-group can exist at a time */
		return PIM_MSDP_ERR_MAX_MESH_GROUPS;
	}

	pim->msdp.mg = pim_msdp_mg_new(mesh_group_name);
	if (!pim->msdp.mg) {
		return PIM_MSDP_ERR_OOM;
	}

	return PIM_MSDP_ERR_NONE;
}

static int pim_msdp_mg_mbr_comp(const void *p1, const void *p2)
{
	const struct pim_msdp_mg_mbr *mbr1 = p1;
	const struct pim_msdp_mg_mbr *mbr2 = p2;

	if (ntohl(mbr1->mbr_ip.s_addr) < ntohl(mbr2->mbr_ip.s_addr))
		return -1;

	if (ntohl(mbr1->mbr_ip.s_addr) > ntohl(mbr2->mbr_ip.s_addr))
		return 1;

	return 0;
}

static void pim_msdp_mg_mbr_free(struct pim_msdp_mg_mbr *mbr)
{
	XFREE(MTYPE_PIM_MSDP_MG_MBR, mbr);
}

static struct pim_msdp_mg_mbr *pim_msdp_mg_mbr_find(struct pim_instance *pim,
						    struct in_addr mbr_ip)
{
	struct pim_msdp_mg_mbr *mbr;
	struct listnode *mbr_node;

	if (!pim->msdp.mg) {
		return NULL;
	}
	/* we can move this to a hash but considering that number of peers in
	 * a mesh-group that seems like bit of an overkill */
	for (ALL_LIST_ELEMENTS_RO(pim->msdp.mg->mbr_list, mbr_node, mbr)) {
		if (mbr->mbr_ip.s_addr == mbr_ip.s_addr) {
			return mbr;
		}
	}
	return mbr;
}

enum pim_msdp_err pim_msdp_mg_mbr_add(struct pim_instance *pim,
				      const char *mesh_group_name,
				      struct in_addr mbr_ip)
{
	int rc;
	struct pim_msdp_mg_mbr *mbr;
	struct pim_msdp_mg *mg;

	rc = pim_msdp_mg_add(pim, mesh_group_name);
	if (rc != PIM_MSDP_ERR_NONE) {
		return rc;
	}

	mg = pim->msdp.mg;
	mbr = pim_msdp_mg_mbr_find(pim, mbr_ip);
	if (mbr) {
		return PIM_MSDP_ERR_MG_MBR_EXISTS;
	}

	mbr = XCALLOC(MTYPE_PIM_MSDP_MG_MBR, sizeof(*mbr));
	if (!mbr) {
		zlog_err("%s: PIM XCALLOC(%zu) failure", __PRETTY_FUNCTION__,
			 sizeof(*mbr));
		/* if there are no references to the mg free it */
		pim_msdp_mg_free(pim, mg);
		return PIM_MSDP_ERR_OOM;
	}
	mbr->mbr_ip = mbr_ip;
	listnode_add_sort(mg->mbr_list, mbr);

	/* if valid SIP has been configured add peer session */
	if (mg->src_ip.s_addr != INADDR_ANY) {
		pim_msdp_peer_add(pim, mbr_ip, mg->src_ip, mesh_group_name,
				  &mbr->mp);
	}

	if (PIM_DEBUG_MSDP_EVENTS) {
		char ip_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<mbr?>", mbr->mbr_ip, ip_str, sizeof(ip_str));
		zlog_debug("MSDP mesh-group %s mbr %s created",
			   mg->mesh_group_name, ip_str);
	}
	++mg->mbr_cnt;
	return PIM_MSDP_ERR_NONE;
}

static void pim_msdp_mg_mbr_do_del(struct pim_msdp_mg *mg,
				   struct pim_msdp_mg_mbr *mbr)
{
	/* Delete active peer session if any */
	if (mbr->mp) {
		pim_msdp_peer_do_del(mbr->mp);
	}

	listnode_delete(mg->mbr_list, mbr);
	if (PIM_DEBUG_MSDP_EVENTS) {
		char ip_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<mbr?>", mbr->mbr_ip, ip_str, sizeof(ip_str));
		zlog_debug("MSDP mesh-group %s mbr %s deleted",
			   mg->mesh_group_name, ip_str);
	}
	pim_msdp_mg_mbr_free(mbr);
	if (mg->mbr_cnt) {
		--mg->mbr_cnt;
	}
}

enum pim_msdp_err pim_msdp_mg_mbr_del(struct pim_instance *pim,
				      const char *mesh_group_name,
				      struct in_addr mbr_ip)
{
	struct pim_msdp_mg_mbr *mbr;
	struct pim_msdp_mg *mg = pim->msdp.mg;

	if (!mg || strcmp(mg->mesh_group_name, mesh_group_name)) {
		return PIM_MSDP_ERR_NO_MG;
	}

	mbr = pim_msdp_mg_mbr_find(pim, mbr_ip);
	if (!mbr) {
		return PIM_MSDP_ERR_NO_MG_MBR;
	}

	pim_msdp_mg_mbr_do_del(mg, mbr);
	/* if there are no references to the mg free it */
	pim_msdp_mg_free(pim, mg);

	return PIM_MSDP_ERR_NONE;
}

static void pim_msdp_mg_src_do_del(struct pim_instance *pim)
{
	struct pim_msdp_mg_mbr *mbr;
	struct listnode *mbr_node;
	struct pim_msdp_mg *mg = pim->msdp.mg;

	/* SIP is being removed - tear down all active peer sessions */
	for (ALL_LIST_ELEMENTS_RO(mg->mbr_list, mbr_node, mbr)) {
		if (mbr->mp) {
			pim_msdp_peer_do_del(mbr->mp);
			mbr->mp = NULL;
		}
	}
	if (PIM_DEBUG_MSDP_EVENTS) {
		zlog_debug("MSDP mesh-group %s src cleared",
			   mg->mesh_group_name);
	}
}

enum pim_msdp_err pim_msdp_mg_src_del(struct pim_instance *pim,
				      const char *mesh_group_name)
{
	struct pim_msdp_mg *mg = pim->msdp.mg;

	if (!mg || strcmp(mg->mesh_group_name, mesh_group_name)) {
		return PIM_MSDP_ERR_NO_MG;
	}

	if (mg->src_ip.s_addr != INADDR_ANY) {
		mg->src_ip.s_addr = INADDR_ANY;
		pim_msdp_mg_src_do_del(pim);
		/* if there are no references to the mg free it */
		pim_msdp_mg_free(pim, mg);
	}
	return PIM_MSDP_ERR_NONE;
}

enum pim_msdp_err pim_msdp_mg_src_add(struct pim_instance *pim,
				      const char *mesh_group_name,
				      struct in_addr src_ip)
{
	int rc;
	struct pim_msdp_mg_mbr *mbr;
	struct listnode *mbr_node;
	struct pim_msdp_mg *mg;

	if (src_ip.s_addr == INADDR_ANY) {
		pim_msdp_mg_src_del(pim, mesh_group_name);
		return PIM_MSDP_ERR_NONE;
	}

	rc = pim_msdp_mg_add(pim, mesh_group_name);
	if (rc != PIM_MSDP_ERR_NONE) {
		return rc;
	}

	mg = pim->msdp.mg;
	if (mg->src_ip.s_addr != INADDR_ANY) {
		pim_msdp_mg_src_do_del(pim);
	}
	mg->src_ip = src_ip;

	for (ALL_LIST_ELEMENTS_RO(mg->mbr_list, mbr_node, mbr)) {
		pim_msdp_peer_add(pim, mbr->mbr_ip, mg->src_ip, mesh_group_name,
				  &mbr->mp);
	}

	if (PIM_DEBUG_MSDP_EVENTS) {
		char ip_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", mg->src_ip, ip_str, sizeof(ip_str));
		zlog_debug("MSDP mesh-group %s src %s set", mg->mesh_group_name,
			   ip_str);
	}
	return PIM_MSDP_ERR_NONE;
}

/*********************** MSDP feature APIs *********************************/
int pim_msdp_config_write_helper(struct pim_instance *pim, struct vty *vty,
				 const char *spaces)
{
	struct listnode *mbrnode;
	struct pim_msdp_mg_mbr *mbr;
	struct pim_msdp_mg *mg = pim->msdp.mg;
	char mbr_str[INET_ADDRSTRLEN];
	char src_str[INET_ADDRSTRLEN];
	int count = 0;

	if (!mg) {
		return count;
	}

	if (mg->src_ip.s_addr != INADDR_ANY) {
		pim_inet4_dump("<src?>", mg->src_ip, src_str, sizeof(src_str));
		vty_out(vty, "%sip msdp mesh-group %s source %s\n", spaces,
			mg->mesh_group_name, src_str);
		++count;
	}

	for (ALL_LIST_ELEMENTS_RO(mg->mbr_list, mbrnode, mbr)) {
		pim_inet4_dump("<mbr?>", mbr->mbr_ip, mbr_str, sizeof(mbr_str));
		vty_out(vty, "%sip msdp mesh-group %s member %s\n", spaces,
			mg->mesh_group_name, mbr_str);
		++count;
	}
	return count;
}

int pim_msdp_config_write(struct vty *vty)
{
	return pim_msdp_config_write_helper(pimg, vty, "");
}

/* Enable feature including active/periodic timers etc. on the first peer
 * config. Till then MSDP should just stay quiet. */
static void pim_msdp_enable(struct pim_instance *pim)
{
	if (pim->msdp.flags & PIM_MSDPF_ENABLE) {
		/* feature is already enabled */
		return;
	}
	pim->msdp.flags |= PIM_MSDPF_ENABLE;
	pim->msdp.work_obuf = stream_new(PIM_MSDP_MAX_PACKET_SIZE);
	pim_msdp_sa_adv_timer_setup(pim, true /* start */);
	/* setup sa cache based on local sources */
	pim_msdp_sa_local_setup(pim);
}

/* MSDP init */
void pim_msdp_init(struct pim_instance *pim, struct thread_master *master)
{
	pim->msdp.master = master;
	char hash_name[64];

	snprintf(hash_name, 64, "PIM %s MSDP Peer Hash", pim->vrf->name);
	pim->msdp.peer_hash = hash_create(pim_msdp_peer_hash_key_make,
					  pim_msdp_peer_hash_eq, hash_name);
	pim->msdp.peer_list = list_new();
	pim->msdp.peer_list->del = (void (*)(void *))pim_msdp_peer_free;
	pim->msdp.peer_list->cmp = (int (*)(void *, void *))pim_msdp_peer_comp;

	snprintf(hash_name, 64, "PIM %s MSDP SA Hash", pim->vrf->name);
	pim->msdp.sa_hash = hash_create(pim_msdp_sa_hash_key_make,
					pim_msdp_sa_hash_eq, hash_name);
	pim->msdp.sa_list = list_new();
	pim->msdp.sa_list->del = (void (*)(void *))pim_msdp_sa_free;
	pim->msdp.sa_list->cmp = (int (*)(void *, void *))pim_msdp_sa_comp;
}

/* counterpart to MSDP init; XXX: unused currently */
void pim_msdp_exit(struct pim_instance *pim)
{
	pim_msdp_sa_adv_timer_setup(pim, false);

	/* XXX: stop listener and delete all peer sessions */

	if (pim->msdp.peer_hash) {
		hash_free(pim->msdp.peer_hash);
		pim->msdp.peer_hash = NULL;
	}

	if (pim->msdp.peer_list) {
		list_delete_and_null(&pim->msdp.peer_list);
	}

	if (pim->msdp.sa_hash) {
		hash_free(pim->msdp.sa_hash);
		pim->msdp.sa_hash = NULL;
	}

	if (pim->msdp.sa_list) {
		list_delete_and_null(&pim->msdp.sa_list);
	}
}
