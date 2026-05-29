// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF version 2  Neighbor State Machine
 * From RFC2328 [OSPF Version 2]
 * Copyright (C) 1999, 2000 Toshiaki Takada
 */

#include <zebra.h>

#include "frrevent.h"
#include "memory.h"
#include "hash.h"
#include "linklist.h"
#include "typesafe.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "stream.h"
#include "table.h"
#include "log.h"
#include "command.h"
#include "network.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_bfd.h"
#include "ospfd/ospf_gr.h"
#include "ospfd/ospf_errors.h"
#include "ospfd/ospf_quicknbr.h"

DEFINE_HOOK(ospf_nsm_change,
	    (struct ospf_neighbor * on, int state, int oldstate),
	    (on, state, oldstate));

/* RFC4222/R5: struct ospf_neighbor is fully defined here so DECLARE_LIST
 * can access pacing_link.  Callers outside this file use the wrappers below.
 */
DECLARE_LIST(ospf_pacing_queue, struct ospf_neighbor, pacing_link);

void ospf_adj_pacing_queue_init(struct ospf_adj_pacing *p)
{
	ospf_pacing_queue_init(&p->queue);
}

void ospf_adj_pacing_queue_fini(struct ospf_adj_pacing *p)
{
	ospf_pacing_queue_fini(&p->queue);
}

void ospf_adj_pacing_queue_flush(struct ospf_interface *oi)
{
	struct ospf_neighbor *nbr;
	int count = 0;

	frr_each_safe (ospf_pacing_queue, &oi->adj_pacing.queue, nbr) {
		ospf_pacing_queue_del(&oi->adj_pacing.queue, nbr);
		if (nbr->state == NSM_TwoWay)
			OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_AdjOK);
		count++;
	}

	if (count > 0 && IS_DEBUG_OSPF(nsm, NSM_EVENTS))
		zlog_debug("R5: %s flushed %d queued neighbors (sent NSM_AdjOK)", IF_NAME(oi),
			   count);
}

static void nsm_clear_adj(struct ospf_neighbor *);

/*RFC4222/R5 changes: Track adjacency formation states for pacing*/
static bool ospf_adj_in_progress_state(int state)
{
	return state == NSM_ExStart || state == NSM_Exchange || state == NSM_Loading;
}


/*RFC422/R5 changes: check if interface pacing is enabled */
static bool ospf_adj_pacing_enabled(struct ospf_interface *oi)
{
	return oi->adj_pacing.mode != OSPF_ADJ_PACING_NONE;
}

/*RFC4222/R5 changes: Compute total unacked LSAs across all neighbors on interface */
static uint32_t ospf_adj_total_unacked(struct ospf_interface *oi)
{
	struct route_node *rn;
	uint32_t total = 0;
	uint32_t nbr_count = 0;

	for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
		struct ospf_neighbor *nbr = rn->info;

		if (nbr && nbr != oi->nbr_self) {
			total += nbr->ls_rxmt_unacked;
			nbr_count++;
		}
	}

	if (IS_DEBUG_OSPF(nsm, NSM_EVENTS) && total > 0)
		zlog_debug("R5-DYN: %s total_unacked=%u across %u neighbors", IF_NAME(oi), total,
			   nbr_count);

	return total;
}

/*RFC4222/R5 changes: Timer callback for deferred dynamic adjustment */
static void ospf_adj_dyn_adjust_timer(struct event *t)
{
	struct ospf_interface *oi = EVENT_ARG(t);
	uint64_t now_ms, elapsed_ms;
	uint32_t U, H, L;
	uint16_t limit, new_limit;

	oi->adj_pacing.t_dyn_adjust = NULL;

	if (oi->adj_pacing.mode != OSPF_ADJ_PACING_DYNAMIC)
		return;

	now_ms = ospf_now_ms();
	elapsed_ms = now_ms - oi->adj_pacing.last_adjust_ms;

	/* Rate limit: skip if adjusted too recently */
	if (elapsed_ms < OSPF_ADJ_DYN_ADJUST_INT_MS) {
		if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
			zlog_debug("R5-DYN: %s rate-limited (elapsed=%" PRIu64 "ms < %ums)",
				   IF_NAME(oi), elapsed_ms, OSPF_ADJ_DYN_ADJUST_INT_MS);
		return;
	}

	/* Compute U(t) - total unacked LSAs on this interface */
	U = ospf_adj_total_unacked(oi);

	/* Use dynamic pacing thresholds (H and L) */
	H = oi->adj_pacing.high_water;
	L = oi->adj_pacing.low_water;

	limit = oi->adj_pacing.dynamic_limit;
	new_limit = limit;

	if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
		zlog_debug("R5-DYN: %s checking: U=%u H=%u L=%u limit=%u in_progress=%u",
			   IF_NAME(oi), U, H, L, limit, oi->adj_pacing.in_progress);

	if (U > H) {
		/* Congestion: decrease limit */
		new_limit = (limit > OSPF_ADJ_DYN_FACTOR) ? (limit / OSPF_ADJ_DYN_FACTOR) : 1;
		if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
			zlog_debug("R5-DYN: %s CONGESTION detected U(%u) > H(%u), decreasing limit %u->%u",
				   IF_NAME(oi), U, H, limit, new_limit);
	} else if (U < L) {
		/* Uncongested: increase limit */
		new_limit = (limit < OSPF_ADJ_DYN_LIMIT_MAX) ? (limit + 1) : OSPF_ADJ_DYN_LIMIT_MAX;
		if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
			zlog_debug("R5-DYN: %s UNCONGESTED U(%u) < L(%u), increasing limit %u->%u",
				   IF_NAME(oi), U, L, limit, new_limit);
	} else {
		if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
			zlog_debug("R5-DYN: %s HYSTERESIS L(%u) <= U(%u) <= H(%u), no change",
				   IF_NAME(oi), L, U, H);
	}

	if (new_limit != limit) {
		oi->adj_pacing.dynamic_limit = new_limit;
		oi->adj_pacing.last_adjust_ms = now_ms;

		if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
			zlog_debug("R5-DYN: %s ADJUSTED limit %u->%u U=%u H=%u L=%u elapsed=%" PRIu64
				   "ms",
				   IF_NAME(oi), limit, new_limit, U, H, L, elapsed_ms);

		/* Limit increased: kick queue to fill newly opened slots */
		if (new_limit > limit && oi->adj_pacing.in_progress < new_limit) {
			if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
				zlog_debug("R5-DYN: %s limit increased %u->%u, kicking queued adjacencies",
					   IF_NAME(oi), limit, new_limit);
			ospf_adj_pacing_kick(oi);
		}
	}
}

/*RFC4222/R5 changes: Schedule dynamic adjustment (deferred to avoid packet processing interference) */
void ospf_adj_dyn_adjust(struct ospf_interface *oi)
{
	if (oi->adj_pacing.mode != OSPF_ADJ_PACING_DYNAMIC)
		return;

	/* Schedule if not already scheduled */
	if (!oi->adj_pacing.t_dyn_adjust) {
		event_add_timer_msec(master, ospf_adj_dyn_adjust_timer, oi, 0,
				     &oi->adj_pacing.t_dyn_adjust);
		if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
			zlog_debug("R5-DYN: %s scheduled deferred adjustment", IF_NAME(oi));
	}
}

/*RFC4222/R5 changes : Determine pacing limit for this interface (static or dynamic).*/
static uint16_t ospf_adj_pacing_limit(struct ospf_interface *oi)
{
	if (oi->adj_pacing.mode == OSPF_ADJ_PACING_STATIC)
		return oi->adj_pacing.static_limit;

	if (oi->adj_pacing.mode == OSPF_ADJ_PACING_DYNAMIC) {
		/* Recompute before returning */
		ospf_adj_dyn_adjust(oi);
		if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
			zlog_debug("R5-DYN: %s returning dynamic_limit=%u", IF_NAME(oi),
				   oi->adj_pacing.dynamic_limit);
		return oi->adj_pacing.dynamic_limit;
	}
	return 0;
}

/*RFC4222/R5 changes: can we start another adjacency on this interface? */
static bool ospf_adj_pacing_allow(struct ospf_interface *oi)
{
	/* Returns true if below the per-interface limit or pacing disabled.  */
	uint16_t limit;

	if (!ospf_adj_pacing_enabled(oi))
		return true;

	limit = ospf_adj_pacing_limit(oi);
	if (limit == 0)
		return true;

	return (oi->adj_pacing.in_progress < limit);
}

/* RFC4222/R5: Remove a neighbor from the per-interface pacing queue. */
static void ospf_adj_pacing_remove(struct ospf_neighbor *nbr)
{
	struct ospf_interface *oi = nbr->oi;

	if (ospf_pacing_queue_member(&oi->adj_pacing.queue, nbr))
		ospf_pacing_queue_del(&oi->adj_pacing.queue, nbr);
}

/* RFC4222/R5: Enqueue a neighbor to wait for an available pacing slot. */
static void ospf_adj_pacing_enqueue(struct ospf_neighbor *nbr)
{
	struct ospf_interface *oi = nbr->oi;

	if (!ospf_adj_pacing_enabled(oi))
		return;
	if (ospf_pacing_queue_member(&oi->adj_pacing.queue, nbr))
		return;

	ospf_pacing_queue_add_tail(&oi->adj_pacing.queue, nbr);
}

/* RFC4222/R5: Pop the next queued neighbor for this interface. */
static struct ospf_neighbor *ospf_adj_pacing_dequeue(struct ospf_interface *oi)
{
	struct ospf_neighbor *nbr;

	nbr = ospf_pacing_queue_first(&oi->adj_pacing.queue);
	if (!nbr)
		return NULL;

	ospf_pacing_queue_del(&oi->adj_pacing.queue, nbr);
	return nbr;
}

/*RFC4222/R5 changes: start queued adjacencies when a pacing slot opens*/
void ospf_adj_pacing_kick(struct ospf_interface *oi)
{
	struct ospf_neighbor *nbr;
	uint16_t limit, available;

	if (!ospf_adj_pacing_enabled(oi))
		return;

	limit = ospf_adj_pacing_limit(oi);
	if (limit == 0)
		return;

	/*
	 * Compute how many slots are open right now.  in_progress is only
	 * incremented inside ospf_nsm_change_state — i.e. after the scheduled
	 * NSM_AdjOK event actually fires.  If we loop on ospf_adj_pacing_allow()
	 * instead, the check always reads the pre-event value of in_progress and
	 * drains the entire queue every kick, creating O(N²) churn: all N
	 * waiters get NSM_AdjOK scheduled, then N-limit of them fail the pacing
	 * check in nsm_adj_ok and are re-enqueued, repeating on every completion.
	 */
	available = (oi->adj_pacing.in_progress < limit)
			    ? (limit - oi->adj_pacing.in_progress)
			    : 0;

	while (available > 0) {
		nbr = ospf_adj_pacing_dequeue(oi);
		if (!nbr)
			break;
		if (nbr->state != NSM_TwoWay)
			continue;
		available--;
		OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_AdjOK);
	}
}


/* OSPF NSM Timer functions. */
static void ospf_inactivity_timer(struct event *event)
{
	struct ospf_neighbor *nbr;

	nbr = EVENT_ARG(event);

	if (IS_DEBUG_OSPF(nsm, NSM_TIMERS))
		zlog_debug("NSM[%s:%pI4:%s]: Timer (Inactivity timer expire)",
			   IF_NAME(nbr->oi), &nbr->router_id,
			   ospf_get_name(nbr->oi->ospf));

	/* Dont trigger NSM_InactivityTimer event , if the current
	 * router acting as HELPER for this neighbour.
	 */
	if (!OSPF_GR_IS_ACTIVE_HELPER(nbr))
		OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_InactivityTimer);
	else {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug(
				"%s, Acting as HELPER for this neighbour, So restart the dead timer",
				__func__);
		OSPF_NSM_TIMER_ON(nbr->t_inactivity, ospf_inactivity_timer,
				  nbr->v_inactivity);
	}
}
/* RFC4222 */
void ospf_nsm_restart_inactivity_timer(struct ospf_neighbor *nbr)
{
	if (!nbr)
		return;

	/* Start or Restart Inactivity Timer. */
	event_cancel(&nbr->t_inactivity);

	OSPF_NSM_TIMER_ON(nbr->t_inactivity, ospf_inactivity_timer, nbr->v_inactivity);
}

static void ospf_db_desc_timer(struct event *event)
{
	struct ospf_neighbor *nbr;

	nbr = EVENT_ARG(event);

	if (IS_DEBUG_OSPF(nsm, NSM_TIMERS))
		zlog_debug("NSM[%s:%pI4:%s]: Timer (DD Retransmit timer expire)",
			   IF_NAME(nbr->oi), &nbr->src,
			   ospf_get_name(nbr->oi->ospf));

	/* resent last send DD packet. */
	assert(nbr->last_send);
	ospf_db_desc_resend(nbr);

	/* DD Retransmit timer set. */
	OSPF_NSM_TIMER_ON(nbr->t_db_desc, ospf_db_desc_timer, nbr->v_db_desc);
}

/* Hook function called after ospf NSM event is occurred.
 *
 * Set/clear any timers whose condition is implicit to the neighbour
 * state. There may be other timers which are set/unset according to other
 * state.
 *
 * We rely on this function to properly clear timers in lower states,
 * particularly before deleting a neighbour.
 */
static void nsm_timer_set(struct ospf_neighbor *nbr)
{
	switch (nbr->state) {
	case NSM_Deleted:
	case NSM_Down:
		event_cancel(&nbr->t_inactivity);
		event_cancel(&nbr->t_hello_reply);
		fallthrough;
	case NSM_Attempt:
	case NSM_Init:
	case NSM_TwoWay:
		event_cancel(&nbr->t_db_desc);
		event_cancel(&nbr->t_ls_rxmt);
		event_cancel(&nbr->t_ls_req);
		break;
	case NSM_ExStart:
		OSPF_NSM_TIMER_ON(nbr->t_db_desc, ospf_db_desc_timer,
				  nbr->v_db_desc);
		event_cancel(&nbr->t_ls_rxmt);
		event_cancel(&nbr->t_ls_req);
		break;
	case NSM_Exchange:
		if (!IS_SET_DD_MS(nbr->dd_flags))
			event_cancel(&nbr->t_db_desc);
		break;
	case NSM_Loading:
	case NSM_Full:
	default:
		event_cancel(&nbr->t_db_desc);
		break;
	}
}

/* 10.4 of RFC2328, indicate whether an adjacency is appropriate with
 * the given neighbour
 */
int nsm_should_adj(struct ospf_neighbor *nbr)
{
	struct ospf_interface *oi = nbr->oi;

	/* These network types must always form adjacencies. */
	if (oi->type == OSPF_IFTYPE_POINTOPOINT
	    || oi->type == OSPF_IFTYPE_POINTOMULTIPOINT
	    || oi->type == OSPF_IFTYPE_VIRTUALLINK
	    /* Router itself is the DRouter or the BDRouter. */
	    || IPV4_ADDR_SAME(&oi->address->u.prefix4, &DR(oi))
	    || IPV4_ADDR_SAME(&oi->address->u.prefix4, &BDR(oi))
	    /* Neighboring Router is the DRouter or the BDRouter. */
	    || IPV4_ADDR_SAME(&nbr->address.u.prefix4, &DR(oi))
	    || IPV4_ADDR_SAME(&nbr->address.u.prefix4, &BDR(oi)))
		return 1;

	return 0;
}

/* OSPF NSM functions. */
static int nsm_hello_received(struct ospf_neighbor *nbr)
{
	/* Start or Restart Inactivity Timer. */
	event_cancel(&nbr->t_inactivity);

	OSPF_NSM_TIMER_ON(nbr->t_inactivity, ospf_inactivity_timer,
			  nbr->v_inactivity);

	if (OSPF_IF_NON_BROADCAST(nbr->oi) && nbr->nbr_nbma != NULL)
		event_cancel(&nbr->nbr_nbma->t_poll);

	/* Send proactive ARP requests */
	if (nbr->state < NSM_Exchange)
		ospf_proactively_arp(nbr);

	return 0;
}

static int nsm_start(struct ospf_neighbor *nbr)
{
	if (nbr->nbr_nbma)
		event_cancel(&nbr->nbr_nbma->t_poll);

	event_cancel(&nbr->t_inactivity);

	OSPF_NSM_TIMER_ON(nbr->t_inactivity, ospf_inactivity_timer,
			  nbr->v_inactivity);

	/* Send proactive ARP requests */
	ospf_proactively_arp(nbr);

	return 0;
}

/*RFC4222/R5 changes: If adjacency is needed but interface pacing blocks it, queue neighbor */
static int nsm_twoway_received(struct ospf_neighbor *nbr)
{
	int adj = nsm_should_adj(nbr);

	if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
		zlog_debug("R5: TwoWay recv nbr=%pI4 adj=%d", &nbr->router_id, adj);

	if (adj && !ospf_adj_pacing_allow(nbr->oi)) {
		if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
			zlog_debug("R5: throttling nbr=%pI4", &nbr->router_id);
		ospf_adj_pacing_enqueue(nbr);
		return NSM_TwoWay;
	}
	/* if adjacency can proceed, ensure neighbor is nto left queued*/
	if (adj)
		ospf_adj_pacing_remove(nbr);

	if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
		zlog_debug("R5: TwoWay -> %s nbr=%pI4", adj ? "ExStart" : "TwoWay",
			   &nbr->router_id);

	/* Send proactive ARP requests */
	if (adj)
		ospf_proactively_arp(nbr);

	return (adj ? NSM_ExStart : NSM_TwoWay);
}

int ospf_db_summary_count(struct ospf_neighbor *nbr)
{
	return ospf_lsdb_count_all(&nbr->db_sum);
}

int ospf_db_summary_isempty(struct ospf_neighbor *nbr)
{
	return ospf_lsdb_isempty(&nbr->db_sum);
}

static int ospf_db_summary_add(struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
	switch (lsa->data->type) {
	case OSPF_OPAQUE_LINK_LSA:
		/* Exclude type-9 LSAs that does not have the same "oi" with
		 * "nbr". */
		if (lsa->oi != nbr->oi)
			return 0;
		break;
	case OSPF_OPAQUE_AREA_LSA:
		/*
		 * It is assured by the caller function "nsm_negotiation_done()"
		 * that every given LSA belongs to the same area with "nbr".
		 */
		break;
	case OSPF_OPAQUE_AS_LSA:
	default:
		break;
	}

	/* Stay away from any Local Translated Type-7 LSAs */
	if (CHECK_FLAG(lsa->flags, OSPF_LSA_LOCAL_XLT))
		return 0;

	if (IS_LSA_MAXAGE(lsa))
		ospf_ls_retransmit_add(nbr, lsa);
	else
		ospf_lsdb_add(&nbr->db_sum, lsa);

	return 0;
}

void ospf_db_summary_clear(struct ospf_neighbor *nbr)
{
	struct ospf_lsdb *lsdb;
	int i;

	lsdb = &nbr->db_sum;
	for (i = OSPF_MIN_LSA; i < OSPF_MAX_LSA; i++) {
		struct route_table *table = lsdb->type[i].db;
		struct route_node *rn;

		for (rn = route_top(table); rn; rn = route_next(rn))
			if (rn->info)
				ospf_lsdb_delete(&nbr->db_sum, rn->info);
	}
}


/* The area link state database consists of the router-LSAs,
   network-LSAs and summary-LSAs contained in the area structure,
   along with the AS-external-LSAs contained in the global structure.
   AS-external-LSAs are omitted from a virtual neighbor's Database
   summary list.  AS-external-LSAs are omitted from the Database
   summary list if the area has been configured as a stub. */
static int nsm_negotiation_done(struct ospf_neighbor *nbr)
{
	struct ospf_area *area = nbr->oi->area;
	struct ospf_lsa *lsa;
	struct route_node *rn;

	/* Send proactive ARP requests */
	ospf_proactively_arp(nbr);

	LSDB_LOOP (ROUTER_LSDB(area), rn, lsa)
		ospf_db_summary_add(nbr, lsa);
	LSDB_LOOP (NETWORK_LSDB(area), rn, lsa)
		ospf_db_summary_add(nbr, lsa);
	LSDB_LOOP (SUMMARY_LSDB(area), rn, lsa)
		ospf_db_summary_add(nbr, lsa);

	/* Process only if the neighbor is opaque capable. */
	if (CHECK_FLAG(nbr->options, OSPF_OPTION_O)) {
		LSDB_LOOP (OPAQUE_LINK_LSDB(area), rn, lsa)
			ospf_db_summary_add(nbr, lsa);
		LSDB_LOOP (OPAQUE_AREA_LSDB(area), rn, lsa)
			ospf_db_summary_add(nbr, lsa);
	}

	if (CHECK_FLAG(nbr->options, OSPF_OPTION_NP)) {
		LSDB_LOOP (NSSA_LSDB(area), rn, lsa)
			ospf_db_summary_add(nbr, lsa);
	}

	/* For Stub/NSSA area, we should not send Type-4 and Type-5 LSAs */
	if (nbr->oi->type != OSPF_IFTYPE_VIRTUALLINK
	    && area->external_routing == OSPF_AREA_DEFAULT) {
		LSDB_LOOP (ASBR_SUMMARY_LSDB(area), rn, lsa)
			ospf_db_summary_add(nbr, lsa);
		LSDB_LOOP (EXTERNAL_LSDB(nbr->oi->ospf), rn, lsa)
			ospf_db_summary_add(nbr, lsa);
	}

	if (CHECK_FLAG(nbr->options, OSPF_OPTION_O)
	    && (nbr->oi->type != OSPF_IFTYPE_VIRTUALLINK
		&& area->external_routing == OSPF_AREA_DEFAULT))
		LSDB_LOOP (OPAQUE_AS_LSDB(nbr->oi->ospf), rn, lsa)
			ospf_db_summary_add(nbr, lsa);

	return 0;
}

static int nsm_exchange_done(struct ospf_neighbor *nbr)
{
	if (ospf_ls_request_isempty(nbr))
		return NSM_Full;

	/* Send Link State Request. */
	if (!event_is_scheduled(nbr->t_ls_req))
		ospf_ls_req_send(nbr);

	return NSM_Loading;
}


/* RFC4222/R5 changes: apply per-interface pacing before moving to ExStart*/
static int nsm_adj_ok(struct ospf_neighbor *nbr)
{
	int next_state = nbr->state;
	int adj = nsm_should_adj(nbr);

	if (nbr->state == NSM_TwoWay && adj == 1) {
		if (!ospf_adj_pacing_allow(nbr->oi)) {
			if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
				zlog_debug("R5: AdjOK throttling nbr=%pI4", &nbr->router_id);
			ospf_adj_pacing_enqueue(nbr);
			return NSM_TwoWay;
		}

		next_state = NSM_ExStart;
		ospf_adj_pacing_remove(nbr);

		/* Send proactive ARP requests */
		ospf_proactively_arp(nbr);
	} else if (nbr->state >= NSM_ExStart && adj == 0)
		next_state = NSM_TwoWay;
	else if (nbr->state == NSM_TwoWay && IS_QUICKNBR(nbr) && adj == 1)
		/*
		 * Quick neighbor placeholder; only form adjacency when appropriate
		 * per RFC2328 10.4.
		 */
		next_state = NSM_ExStart;

	if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
		zlog_debug("R5: AdjOK next_state=%s nbr=%pI4",
			   lookup_msg(ospf_nsm_state_msg, next_state, NULL), &nbr->router_id);

	return next_state;
}

/* Clear adjacency related state for a neighbour, intended where nbr
 * transitions from > ExStart (i.e. a Full or forming adjacency)
 * to <= ExStart.
 */
static void nsm_clear_adj(struct ospf_neighbor *nbr)
{
	/* Clear Database Summary list. */
	if (!ospf_db_summary_isempty(nbr))
		ospf_db_summary_clear(nbr);

	/* Clear Link State Request list. */
	if (!ospf_ls_request_isempty(nbr))
		ospf_ls_request_delete_all(nbr);

	/* Clear Link State Retransmission list. */
	if (!ospf_ls_retransmit_isempty(nbr))
		ospf_ls_retransmit_clear(nbr);

	if (CHECK_FLAG(nbr->options, OSPF_OPTION_O))
		UNSET_FLAG(nbr->options, OSPF_OPTION_O);
}

/*RFC4222/R5 changes: remove neighbor from per-interface packing queue when killed*/
static int nsm_kill_nbr(struct ospf_neighbor *nbr)
{
	struct ospf_interface *oi = nbr->oi;
	struct ospf_neighbor *on;
	struct route_node *rn;

	/* R5 changes*/
	ospf_adj_pacing_remove(nbr);

	/* killing nbr_self is invalid */
	if (nbr == nbr->oi->nbr_self) {
		assert(nbr != nbr->oi->nbr_self);
		return 0;
	}

	if (OSPF_IF_NON_BROADCAST(nbr->oi) && nbr->nbr_nbma != NULL) {
		struct ospf_nbr_nbma *nbr_nbma = nbr->nbr_nbma;

		nbr_nbma->nbr = NULL;
		nbr_nbma->state_change = nbr->state_change;

		nbr->nbr_nbma = NULL;

		OSPF_POLL_TIMER_ON(nbr_nbma->t_poll, ospf_poll_timer,
				   nbr_nbma->v_poll);

		if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
			zlog_debug(
				"NSM[%s:%pI4:%s]: Down (PollIntervalTimer scheduled)",
				IF_NAME(nbr->oi),
				&nbr->address.u.prefix4,
				ospf_get_name(nbr->oi->ospf));
	}

	/*
	 * Do we have any neighbors that are also operating
	 * on this interface?
	 */
	for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
		on = rn->info;

		if (!on)
			continue;

		if (on == nbr || on == oi->nbr_self)
			continue;

		/*
		 * on is in some state where we might be
		 * sending packets on this interface
		 */
		if (on->state > NSM_Down) {
			route_unlock_node(rn);
			return 0;
		}
	}
	/*
	 * If we get here we know that this interface
	 * has no neighbors in a state where we could
	 * be sending packets.  Let's flush anything
	 * we got.
	 */
	ospf_interface_fifo_flush(oi);
	return 0;
}

/* Neighbor State Machine */
const struct {
	int (*func)(struct ospf_neighbor *);
	int next_state;
} NSM[OSPF_NSM_STATE_MAX][OSPF_NSM_EVENT_MAX] = {
	{
		/* DependUpon: dummy state. */
		{NULL, NSM_DependUpon}, /* NoEvent           */
		{NULL, NSM_DependUpon}, /* HelloReceived     */
		{NULL, NSM_DependUpon}, /* Start             */
		{NULL, NSM_DependUpon}, /* 2-WayReceived     */
		{NULL, NSM_DependUpon}, /* NegotiationDone   */
		{NULL, NSM_DependUpon}, /* ExchangeDone      */
		{NULL, NSM_DependUpon}, /* BadLSReq          */
		{NULL, NSM_DependUpon}, /* LoadingDone       */
		{NULL, NSM_DependUpon}, /* AdjOK?            */
		{NULL, NSM_DependUpon}, /* SeqNumberMismatch */
		{NULL, NSM_DependUpon}, /* 1-WayReceived     */
		{NULL, NSM_DependUpon}, /* KillNbr           */
		{NULL, NSM_DependUpon}, /* InactivityTimer   */
		{NULL, NSM_DependUpon}, /* LLDown            */
	},
	{
		/* Deleted: dummy state. */
		{NULL, NSM_Deleted}, /* NoEvent           */
		{NULL, NSM_Deleted}, /* HelloReceived     */
		{NULL, NSM_Deleted}, /* Start             */
		{NULL, NSM_Deleted}, /* 2-WayReceived     */
		{NULL, NSM_Deleted}, /* NegotiationDone   */
		{NULL, NSM_Deleted}, /* ExchangeDone      */
		{NULL, NSM_Deleted}, /* BadLSReq          */
		{NULL, NSM_Deleted}, /* LoadingDone       */
		{NULL, NSM_Deleted}, /* AdjOK?            */
		{NULL, NSM_Deleted}, /* SeqNumberMismatch */
		{NULL, NSM_Deleted}, /* 1-WayReceived     */
		{NULL, NSM_Deleted}, /* KillNbr           */
		{NULL, NSM_Deleted}, /* InactivityTimer   */
		{NULL, NSM_Deleted}, /* LLDown            */
	},
	{
		/* Down: */
		{NULL, NSM_DependUpon},		 /* NoEvent           */
		{nsm_hello_received, NSM_Init},  /* HelloReceived     */
		{nsm_start, NSM_Attempt},	 /* Start             */
		{NULL, NSM_Down},		 /* 2-WayReceived     */
		{NULL, NSM_Down},		 /* NegotiationDone   */
		{NULL, NSM_Down},		 /* ExchangeDone      */
		{NULL, NSM_Down},		 /* BadLSReq          */
		{NULL, NSM_Down},		 /* LoadingDone       */
		{NULL, NSM_Down},		 /* AdjOK?            */
		{NULL, NSM_Down},		 /* SeqNumberMismatch */
		{NULL, NSM_Down},		 /* 1-WayReceived     */
		{nsm_kill_nbr, NSM_Deleted},     /* KillNbr           */
		{nsm_kill_nbr, NSM_Deleted},     /* InactivityTimer   */
		{nsm_kill_nbr, NSM_Deleted},     /* LLDown            */
	},
	{
		/* Attempt: */
		{NULL, NSM_DependUpon},		 /* NoEvent           */
		{nsm_hello_received, NSM_Init},  /* HelloReceived     */
		{NULL, NSM_Attempt},		 /* Start             */
		{NULL, NSM_Attempt},		 /* 2-WayReceived     */
		{NULL, NSM_Attempt},		 /* NegotiationDone   */
		{NULL, NSM_Attempt},		 /* ExchangeDone      */
		{NULL, NSM_Attempt},		 /* BadLSReq          */
		{NULL, NSM_Attempt},		 /* LoadingDone       */
		{NULL, NSM_Attempt},		 /* AdjOK?            */
		{NULL, NSM_Attempt},		 /* SeqNumberMismatch */
		{NULL, NSM_Attempt},		 /* 1-WayReceived     */
		{nsm_kill_nbr, NSM_Deleted},     /* KillNbr           */
		{nsm_kill_nbr, NSM_Deleted},     /* InactivityTimer   */
		{nsm_kill_nbr, NSM_Deleted},     /* LLDown            */
	},
	{
		/* Init: */
		{NULL, NSM_DependUpon},		       /* NoEvent           */
		{nsm_hello_received, NSM_Init},        /* HelloReceived     */
		{NULL, NSM_Init},		       /* Start             */
		{nsm_twoway_received, NSM_DependUpon}, /* 2-WayReceived     */
		{NULL, NSM_Init},		       /* NegotiationDone   */
		{NULL, NSM_Init},		       /* ExchangeDone      */
		{NULL, NSM_Init},		       /* BadLSReq          */
		{NULL, NSM_Init},		       /* LoadingDone       */
		{NULL, NSM_Init},		       /* AdjOK?            */
		{NULL, NSM_Init},		       /* SeqNumberMismatch */
		{NULL, NSM_Init},		       /* 1-WayReceived     */
		{nsm_kill_nbr, NSM_Deleted},	   /* KillNbr           */
		{nsm_kill_nbr, NSM_Deleted},	   /* InactivityTimer   */
		{nsm_kill_nbr, NSM_Deleted},	   /* LLDown            */
	},
	{
		/* 2-Way: */
		{NULL, NSM_DependUpon},		   /* NoEvent           */
		{nsm_hello_received, NSM_TwoWay},  /* HelloReceived     */
		{NULL, NSM_TwoWay},		   /* Start             */
		{NULL, NSM_TwoWay},		   /* 2-WayReceived     */
		{NULL, NSM_TwoWay},		   /* NegotiationDone   */
		{NULL, NSM_TwoWay},		   /* ExchangeDone      */
		{NULL, NSM_TwoWay},		   /* BadLSReq          */
		{NULL, NSM_TwoWay},		   /* LoadingDone       */
		{nsm_adj_ok, NSM_DependUpon},      /* AdjOK?            */
		{NULL, NSM_TwoWay},		   /* SeqNumberMismatch */
		{NULL, NSM_Init},		   /* 1-WayReceived     */
		{nsm_kill_nbr, NSM_Deleted},       /* KillNbr           */
		{nsm_kill_nbr, NSM_Deleted},       /* InactivityTimer   */
		{nsm_kill_nbr, NSM_Deleted},       /* LLDown            */
	},
	{
		/* ExStart: */
		{NULL, NSM_DependUpon},		      /* NoEvent           */
		{nsm_hello_received, NSM_ExStart},    /* HelloReceived     */
		{NULL, NSM_ExStart},		      /* Start             */
		{NULL, NSM_ExStart},		      /* 2-WayReceived     */
		{nsm_negotiation_done, NSM_Exchange}, /* NegotiationDone   */
		{NULL, NSM_ExStart},		      /* ExchangeDone      */
		{NULL, NSM_ExStart},		      /* BadLSReq          */
		{NULL, NSM_ExStart},		      /* LoadingDone       */
		{nsm_adj_ok, NSM_DependUpon},	 /* AdjOK?            */
		{NULL, NSM_ExStart},		      /* SeqNumberMismatch */
		{NULL, NSM_Init},		      /* 1-WayReceived     */
		{nsm_kill_nbr, NSM_Deleted},	  /* KillNbr           */
		{nsm_kill_nbr, NSM_Deleted},	  /* InactivityTimer   */
		{nsm_kill_nbr, NSM_Deleted},	  /* LLDown            */
	},
	{
		/* Exchange: */
		{NULL, NSM_DependUpon},		     /* NoEvent           */
		{nsm_hello_received, NSM_Exchange},  /* HelloReceived     */
		{NULL, NSM_Exchange},		     /* Start             */
		{NULL, NSM_Exchange},		     /* 2-WayReceived     */
		{NULL, NSM_Exchange},		     /* NegotiationDone   */
		{nsm_exchange_done, NSM_DependUpon}, /* ExchangeDone      */
		{NULL, NSM_ExStart},		     /* BadLSReq          */
		{NULL, NSM_Exchange},		     /* LoadingDone       */
		{nsm_adj_ok, NSM_DependUpon},	/* AdjOK?            */
		{NULL, NSM_ExStart},		     /* SeqNumberMismatch */
		{NULL, NSM_Init},		     /* 1-WayReceived     */
		{nsm_kill_nbr, NSM_Deleted},	 /* KillNbr           */
		{nsm_kill_nbr, NSM_Deleted},	 /* InactivityTimer   */
		{nsm_kill_nbr, NSM_Deleted},	 /* LLDown            */
	},
	{
		/* Loading: */
		{NULL, NSM_DependUpon},		    /* NoEvent           */
		{nsm_hello_received, NSM_Loading},  /* HelloReceived     */
		{NULL, NSM_Loading},		    /* Start             */
		{NULL, NSM_Loading},		    /* 2-WayReceived     */
		{NULL, NSM_Loading},		    /* NegotiationDone   */
		{NULL, NSM_Loading},		    /* ExchangeDone      */
		{NULL, NSM_ExStart},		    /* BadLSReq          */
		{NULL, NSM_Full},		    /* LoadingDone       */
		{nsm_adj_ok, NSM_DependUpon},       /* AdjOK?            */
		{NULL, NSM_ExStart},		    /* SeqNumberMismatch */
		{NULL, NSM_Init},		    /* 1-WayReceived     */
		{nsm_kill_nbr, NSM_Deleted},	/* KillNbr           */
		{nsm_kill_nbr, NSM_Deleted},	/* InactivityTimer   */
		{nsm_kill_nbr, NSM_Deleted},	/* LLDown            */
	},
	{
		/* Full: */
		{NULL, NSM_DependUpon},		 /* NoEvent           */
		{nsm_hello_received, NSM_Full},  /* HelloReceived     */
		{NULL, NSM_Full},		 /* Start             */
		{NULL, NSM_Full},		 /* 2-WayReceived     */
		{NULL, NSM_Full},		 /* NegotiationDone   */
		{NULL, NSM_Full},		 /* ExchangeDone      */
		{NULL, NSM_ExStart},		 /* BadLSReq          */
		{NULL, NSM_Full},		 /* LoadingDone       */
		{nsm_adj_ok, NSM_DependUpon},    /* AdjOK?            */
		{NULL, NSM_ExStart},		 /* SeqNumberMismatch */
		{NULL, NSM_Init},		 /* 1-WayReceived     */
		{nsm_kill_nbr, NSM_Deleted},     /* KillNbr           */
		{nsm_kill_nbr, NSM_Deleted},     /* InactivityTimer   */
		{nsm_kill_nbr, NSM_Deleted},     /* LLDown            */
	},
};

static const char *const ospf_nsm_event_str[] = {
	"NoEvent",	   "HelloReceived",  "Start",
	"2-WayReceived",     "NegotiationDone", "ExchangeDone",
	"BadLSReq",	  "LoadingDone",     "AdjOK?",
	"SeqNumberMismatch", "1-WayReceived",   "KillNbr",
	"InactivityTimer",   "LLDown",
};

static void nsm_notice_state_change(struct ospf_neighbor *nbr, int next_state,
				    int event)
{
	/* Logging change of status. */
	if (IS_DEBUG_OSPF(nsm, NSM_STATUS))
		zlog_debug("NSM[%s:%pI4:%s]: State change %s -> %s (%s)",
			   IF_NAME(nbr->oi), &nbr->router_id,
			   ospf_get_name(nbr->oi->ospf),
			   lookup_msg(ospf_nsm_state_msg, nbr->state, NULL),
			   lookup_msg(ospf_nsm_state_msg, next_state, NULL),
			   ospf_nsm_event_str[event]);

	/* Optionally notify about adjacency changes */
	if (CHECK_FLAG(nbr->oi->ospf->config, OSPF_LOG_ADJACENCY_CHANGES)
	    && (CHECK_FLAG(nbr->oi->ospf->config, OSPF_LOG_ADJACENCY_DETAIL)
		|| (next_state == NSM_Full) || (next_state < nbr->state)))
		zlog_notice(
			"AdjChg: Nbr %pI4, NbrIP %pI4 (%s) on %s: %s -> %s (%s)",
			&nbr->router_id, &nbr->src,
			ospf_get_name(nbr->oi->ospf), IF_NAME(nbr->oi),
			lookup_msg(ospf_nsm_state_msg, nbr->state, NULL),
			lookup_msg(ospf_nsm_state_msg, next_state, NULL),
			ospf_nsm_event_str[event]);

	/* Advance in NSM */
	if (next_state > nbr->state)
		monotime(&nbr->ts_last_progress);
	else /* regression in NSM */
	{
		monotime(&nbr->ts_last_regress);
		nbr->last_regress_str = ospf_nsm_event_str[event];
	}
}

static void nsm_change_state(struct ospf_neighbor *nbr, int state)
{
	struct ospf_interface *oi = nbr->oi;
	struct ospf_area *vl_area = NULL;
	uint8_t old_state;

	/* Preserve old status. */
	old_state = nbr->state;

	/* Change to new status. */
	nbr->state = state;

	/* Statistics. */
	nbr->state_change++;

	/* R5: track per-interface in-progress adjacencies */
	if (!ospf_adj_in_progress_state(old_state) && ospf_adj_in_progress_state(state)) {
		oi->adj_pacing.in_progress++;
	} else if (ospf_adj_in_progress_state(old_state) && !ospf_adj_in_progress_state(state)) {
		if (oi->adj_pacing.in_progress > 0)
			oi->adj_pacing.in_progress--;

		if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
			zlog_debug("R5: %s in-progress=%u limit=%u", IF_NAME(oi),
				   oi->adj_pacing.in_progress, ospf_adj_pacing_limit(oi));

		/* Only kick if pacing is enabled */
		if (ospf_adj_pacing_enabled(oi))
			ospf_adj_pacing_kick(oi);
	}


	if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
		vl_area = ospf_area_lookup_by_area_id(oi->ospf,
						      oi->vl_data->vl_area_id);

	/* Generate NeighborChange ISM event.
	 *
	 * In response to NeighborChange, DR election is rerun. The information
	 * from the election process is required by the router-lsa construction.
	 *
	 * Therefore, trigger the event prior to refreshing the LSAs. */
	switch (oi->state) {
	case ISM_DROther:
	case ISM_Backup:
	case ISM_DR:
		if ((old_state < NSM_TwoWay && state >= NSM_TwoWay)
		    || (old_state >= NSM_TwoWay && state < NSM_TwoWay))
			OSPF_ISM_EVENT_EXECUTE(oi, ISM_NeighborChange);
		break;
	default:
		/* ISM_PointToPoint -> ISM_Down, ISM_Loopback -> ISM_Down, etc.
		 */
		break;
	}

	/* One of the neighboring routers changes to/from the FULL state. */
	if ((old_state != NSM_Full && state == NSM_Full)
	    || (old_state == NSM_Full && state != NSM_Full)) {
		if (state == NSM_Full) {
			oi->full_nbrs++;
			oi->area->full_nbrs++;

			ospf_check_abr_status(oi->ospf);

			if (oi->type == OSPF_IFTYPE_VIRTUALLINK && vl_area)
				if (++vl_area->full_vls == 1)
					ospf_schedule_abr_task(oi->ospf);
		} else {
			oi->full_nbrs--;
			oi->area->full_nbrs--;

			ospf_check_abr_status(oi->ospf);

			if (oi->type == OSPF_IFTYPE_VIRTUALLINK && vl_area)
				if (vl_area->full_vls > 0)
					if (--vl_area->full_vls == 0)
						ospf_schedule_abr_task(
							oi->ospf);
		}

		if (CHECK_FLAG(oi->ospf->config, OSPF_LOG_ADJACENCY_DETAIL))
			zlog_info(
				"%s:[%pI4:%s], %s -> %s): scheduling new router-LSA origination",
				__func__, &nbr->router_id,
				ospf_get_name(oi->ospf),
				lookup_msg(ospf_nsm_state_msg, old_state, NULL),
				lookup_msg(ospf_nsm_state_msg, state, NULL));

		/* Dont originate router LSA if the current
		 * router is acting as a HELPER for this neighbour.
		 */
		if (!OSPF_GR_IS_ACTIVE_HELPER(nbr))
			ospf_router_lsa_update_area(oi->area);

		if (oi->type == OSPF_IFTYPE_VIRTUALLINK) {
			vl_area = ospf_area_lookup_by_area_id(
				oi->ospf, oi->vl_data->vl_area_id);

			if (vl_area)
				ospf_router_lsa_update_area(vl_area);
		}

		/* Dont originate/flush network LSA if the current
		 * router is acting as a HELPER for this neighbour.
		 */
		if (!OSPF_GR_IS_ACTIVE_HELPER(nbr)) {
			/* Originate network-LSA. */
			if (oi->state == ISM_DR) {
				if (oi->network_lsa_self
				    && oi->full_nbrs == 0) {
					ospf_lsa_flush_area(
						oi->network_lsa_self, oi->area);
					ospf_lsa_unlock(&oi->network_lsa_self);
					oi->network_lsa_self = NULL;
				} else
					ospf_network_lsa_update(oi);
			}
		}

		if (state == NSM_Full && oi->ospf->gr_info.restart_in_progress)
			ospf_gr_check_adjs(oi->ospf);
	}

	ospf_opaque_nsm_change(nbr, old_state);

	/* State changes from > ExStart to <= ExStart should clear any Exchange
	 * or Full/LSA Update related lists and state.
	 * Potential causal events: BadLSReq, SeqNumberMismatch, AdjOK?
	 */
	if ((old_state > NSM_ExStart) && (state <= NSM_ExStart))
		nsm_clear_adj(nbr);

	/* Start DD exchange protocol */
	if (state == NSM_ExStart) {
		if (nbr->dd_seqnum == 0)
			nbr->dd_seqnum = (uint32_t)frr_weak_random();
		else
			nbr->dd_seqnum++;

		nbr->dd_flags =
			OSPF_DD_FLAG_I | OSPF_DD_FLAG_M | OSPF_DD_FLAG_MS;
		if (CHECK_FLAG(oi->ospf->config, OSPF_LOG_ADJACENCY_DETAIL))
			zlog_info(
				"%s: Initializing [DD]: %pI4 with seqnum:%x , flags:%x",
				ospf_get_name(oi->ospf), &nbr->router_id,
				nbr->dd_seqnum, nbr->dd_flags);
		ospf_db_desc_send(nbr);
	}

	/* clear cryptographic sequence number */
	if (state == NSM_Down)
		nbr->crypt_seqnum = 0;

	if (nbr->bfd_session)
		ospf_bfd_trigger_event(nbr, old_state, state);

	/* Preserve old status? */
}

/* Execute NSM event process. */
void ospf_nsm_event(struct event *e)
{
	int event;
	int next_state;
	struct ospf_neighbor *nbr;

	nbr = EVENT_ARG(e);
	event = EVENT_VAL(e);

	if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
		zlog_debug("NSM[%s:%pI4:%s]: %s (%s)", IF_NAME(nbr->oi),
			   &nbr->router_id,
			   ospf_get_name(nbr->oi->ospf),
			   lookup_msg(ospf_nsm_state_msg, nbr->state, NULL),
			   ospf_nsm_event_str[event]);

	next_state = NSM[nbr->state][event].next_state;

	/* Call function. */
	if (NSM[nbr->state][event].func != NULL) {
		int func_state = (*(NSM[nbr->state][event].func))(nbr);

		if (NSM[nbr->state][event].next_state == NSM_DependUpon)
			next_state = func_state;
		else if (func_state) {
			/* There's a mismatch between the FSM tables and what an
			 * FSM
			 * action/state-change function returned. State changes
			 * which
			 * do not have conditional/DependUpon next-states should
			 * not
			 * try set next_state.
			 */
			flog_err(
				EC_OSPF_FSM_INVALID_STATE,
				"NSM[%s:%pI4:%s]: %s (%s): Warning: action tried to change next_state to %s",
				IF_NAME(nbr->oi), &nbr->router_id,
				ospf_get_name(nbr->oi->ospf),
				lookup_msg(ospf_nsm_state_msg, nbr->state,
					   NULL),
				ospf_nsm_event_str[event],
				lookup_msg(ospf_nsm_state_msg, func_state,
					   NULL));
		}
	}

	assert(next_state != NSM_DependUpon);

	/* If state is changed. */
	if (next_state != nbr->state) {
		int old_state = nbr->state;

		nsm_notice_state_change(nbr, next_state, event);
		nsm_change_state(nbr, next_state);

		hook_call(ospf_nsm_change, nbr, next_state, old_state);
	}

	/* Make sure timer is set. */
	nsm_timer_set(nbr);

	/* When event is NSM_KillNbr, InactivityTimer or LLDown, the neighbor
	 * is deleted.
	 *
	 * Rather than encode knowledge here of which events lead to NBR
	 * delete, we take our cue from the NSM table, via the dummy
	 * 'Deleted' neighbour state.
	 */
	if (nbr->state == NSM_Deleted)
		ospf_nbr_delete(nbr);
}

/* Check loading state. */
void ospf_check_nbr_loading(struct ospf_neighbor *nbr)
{
	if (nbr->state == NSM_Loading) {
		if (ospf_ls_request_isempty(nbr))
			OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_LoadingDone);
		else if (nbr->ls_req_last == NULL)
			ospf_ls_req_event(nbr);
	}
}
