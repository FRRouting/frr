// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include "log.h"
#include "zclient.h"
#include "memory.h"
#include "frrevent.h"
#include "linklist.h"
#include "vty.h"
#include "plist.h"
#include "hash.h"
#include "jhash.h"
#include "wheel.h"
#include "network.h"

#include "pimd.h"
#include "pim_pim.h"
#include "pim_str.h"
#include "pim_time.h"
#include "pim_iface.h"
#include "pim_join.h"
#include "pim_zlookup.h"
#include "pim_upstream.h"
#include "pim_ifchannel.h"
#include "pim_neighbor.h"
#include "pim_rpf.h"
#include "pim_zebra.h"
#include "pim_oil.h"
#include "pim_macro.h"
#include "pim_rp.h"
#include "pim_register.h"
#include "pim_msdp.h"
#include "pim_jp_agg.h"
#include "pim_nht.h"
#include "pim_ssm.h"
#include "pim_vxlan.h"
#include "pim_mlag.h"

static void join_timer_stop(struct pim_upstream *up);
static void
pim_upstream_update_assert_tracking_desired(struct pim_upstream *up);
static bool pim_upstream_sg_running_proc(struct pim_upstream *up);

/*
 * A (*,G) or a (*,*) is going away
 * remove the parent pointer from
 * those pointing at us
 */
static void pim_upstream_remove_children(struct pim_instance *pim,
					 struct pim_upstream *up)
{
	struct pim_upstream *child;

	if (!up->sources)
		return;

	while (!list_isempty(up->sources)) {
		child = listnode_head(up->sources);
		listnode_delete(up->sources, child);
		if (PIM_UPSTREAM_FLAG_TEST_SRC_LHR(child->flags)) {
			PIM_UPSTREAM_FLAG_UNSET_SRC_LHR(child->flags);
			child = pim_upstream_del(pim, child, __func__);
		}
		if (child) {
			child->parent = NULL;
			if (PIM_UPSTREAM_FLAG_TEST_USE_RPT(child->flags))
				pim_upstream_mroute_iif_update(
						child->channel_oil,
						__func__);
		}
	}
	list_delete(&up->sources);
}

/*
 * A (*,G) or a (*,*) is being created
 * Find the children that would point
 * at us.
 */
static void pim_upstream_find_new_children(struct pim_instance *pim,
					   struct pim_upstream *up)
{
	struct pim_upstream *child;

	if (!pim_addr_is_any(up->sg.src) && !pim_addr_is_any(up->sg.grp))
		return;

	if (pim_addr_is_any(up->sg.src) && pim_addr_is_any(up->sg.grp))
		return;

	frr_each (rb_pim_upstream, &pim->upstream_head, child) {
		if (!pim_addr_is_any(up->sg.grp) &&
		    !pim_addr_cmp(child->sg.grp, up->sg.grp) && (child != up)) {
			child->parent = up;
			listnode_add_sort(up->sources, child);
			if (PIM_UPSTREAM_FLAG_TEST_USE_RPT(child->flags))
				pim_upstream_mroute_iif_update(
						child->channel_oil,
						__func__);
		}
	}
}

/*
 * If we have a (*,*) || (S,*) there is no parent
 * If we have a (S,G), find the (*,G)
 * If we have a (*,G), find the (*,*)
 */
static struct pim_upstream *pim_upstream_find_parent(struct pim_instance *pim,
						     struct pim_upstream *child)
{
	pim_sgaddr any = child->sg;
	struct pim_upstream *up = NULL;

	// (S,G)
	if (!pim_addr_is_any(child->sg.src) &&
	    !pim_addr_is_any(child->sg.grp)) {
		any.src = PIMADDR_ANY;
		up = pim_upstream_find(pim, &any);

		if (up)
			listnode_add(up->sources, child);

		/*
		 * In case parent is MLAG entry copy the data to child
		 */
		if (up && PIM_UPSTREAM_FLAG_TEST_MLAG_INTERFACE(up->flags)) {
			PIM_UPSTREAM_FLAG_SET_MLAG_INTERFACE(child->flags);
			if (PIM_UPSTREAM_FLAG_TEST_MLAG_NON_DF(up->flags))
				PIM_UPSTREAM_FLAG_SET_MLAG_NON_DF(child->flags);
			else
				PIM_UPSTREAM_FLAG_UNSET_MLAG_NON_DF(
					child->flags);
		}

		return up;
	}

	return NULL;
}

static void upstream_channel_oil_detach(struct pim_upstream *up)
{
	struct channel_oil *channel_oil = up->channel_oil;

	if (channel_oil) {
		/* Detaching from channel_oil, channel_oil may exist post del,
		   but upstream would not keep reference of it
		 */
		channel_oil->up = NULL;
		up->channel_oil = NULL;

		/* attempt to delete channel_oil; if channel_oil is being held
		 * because of other references cleanup info such as "Mute"
		 * inferred from the parent upstream
		 */
		pim_channel_oil_upstream_deref(channel_oil);
	}

}

static void pim_upstream_timers_stop(struct pim_upstream *up)
{
	EVENT_OFF(up->t_ka_timer);
	EVENT_OFF(up->t_rs_timer);
	EVENT_OFF(up->t_msdp_reg_timer);
	EVENT_OFF(up->t_join_timer);
}

struct pim_upstream *pim_upstream_del(struct pim_instance *pim,
				      struct pim_upstream *up, const char *name)
{
	struct listnode *node, *nnode;
	struct pim_ifchannel *ch;
	bool notify_msdp = false;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug(
			"%s(%s): Delete %s[%s] ref count: %d, flags: %d c_oil ref count %d (Pre decrement)",
			__func__, name, up->sg_str, pim->vrf->name,
			up->ref_count, up->flags,
			up->channel_oil->oil_ref_count);

	 assert(up->ref_count > 0);

	--up->ref_count;

	if (up->ref_count >= 1)
		return up;

	if (PIM_DEBUG_TRACE)
		zlog_debug("pim_upstream free vrf:%s %s flags 0x%x",
			   pim->vrf->name, up->sg_str, up->flags);

	if (pim_up_mlag_is_local(up))
		pim_mlag_up_local_del(pim, up);

	pim_upstream_timers_stop(up);

	if (up->join_state == PIM_UPSTREAM_JOINED) {
		pim_jp_agg_single_upstream_send(&up->rpf, up, 0);

		if (pim_addr_is_any(up->sg.src)) {
			/* if a (*, G) entry in the joined state is being
			 * deleted we
			 * need to notify MSDP */
			notify_msdp = true;
		}
	}

	join_timer_stop(up);
	pim_jp_agg_upstream_verification(up, false);
	up->rpf.source_nexthop.interface = NULL;

	if (!pim_addr_is_any(up->sg.src)) {
		if (pim->upstream_sg_wheel)
			wheel_remove_item(pim->upstream_sg_wheel, up);
		notify_msdp = true;
	}

	pim_mroute_del(up->channel_oil, __func__);
	upstream_channel_oil_detach(up);

	for (ALL_LIST_ELEMENTS(up->ifchannels, node, nnode, ch))
		pim_ifchannel_delete(ch);
	list_delete(&up->ifchannels);

	pim_upstream_remove_children(pim, up);
	if (up->sources)
		list_delete(&up->sources);

	if (up->parent && up->parent->sources)
		listnode_delete(up->parent->sources, up);
	up->parent = NULL;

	rb_pim_upstream_del(&pim->upstream_head, up);

	if (notify_msdp) {
		pim_msdp_up_del(pim, &up->sg);
	}

	/* When RP gets deleted, pim_rp_del() deregister addr with Zebra NHT
	 * and assign up->upstream_addr as INADDR_ANY.
	 * So before de-registering the upstream address, check if is not equal
	 * to INADDR_ANY. This is done in order to avoid de-registering for
	 * 255.255.255.255 which is maintained for some reason..
	 */
	if (!pim_addr_is_any(up->upstream_addr)) {
		/* Deregister addr with Zebra NHT */
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"%s: Deregister upstream %s addr %pPA with Zebra NHT",
				__func__, up->sg_str, &up->upstream_addr);
		pim_delete_tracked_nexthop(pim, up->upstream_addr, up, NULL);
	}

	XFREE(MTYPE_PIM_UPSTREAM, up);

	return NULL;
}

void pim_upstream_send_join(struct pim_upstream *up)
{
	if (!up->rpf.source_nexthop.interface) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: up %s RPF is not present", __func__,
				   up->sg_str);
		return;
	}

	if (PIM_DEBUG_PIM_TRACE) {
		zlog_debug("%s: RPF'%s=%pPA(%s) for Interface %s", __func__,
			   up->sg_str, &up->rpf.rpf_addr,
			   pim_upstream_state2str(up->join_state),
			   up->rpf.source_nexthop.interface->name);
		if (pim_rpf_addr_is_inaddr_any(&up->rpf)) {
			zlog_debug("%s: can't send join upstream: RPF'%s=%pPA",
				   __func__, up->sg_str, &up->rpf.rpf_addr);
			/* warning only */
		}
	}

	/* send Join(S,G) to the current upstream neighbor */
	pim_jp_agg_single_upstream_send(&up->rpf, up, 1 /* join */);
}

static void on_join_timer(struct event *t)
{
	struct pim_upstream *up;

	up = EVENT_ARG(t);

	if (!up->rpf.source_nexthop.interface) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: up %s RPF is not present", __func__,
				   up->sg_str);
		return;
	}

	/*
	 * In the case of a HFR we will not ahve anyone to send this to.
	 */
	if (PIM_UPSTREAM_FLAG_TEST_FHR(up->flags))
		return;

	/*
	 * Don't send the join if the outgoing interface is a loopback
	 * But since this might change leave the join timer running
	 */
	if (up->rpf.source_nexthop
		    .interface && !if_is_loopback(up->rpf.source_nexthop.interface))
		pim_upstream_send_join(up);

	join_timer_start(up);
}

static void join_timer_stop(struct pim_upstream *up)
{
	struct pim_neighbor *nbr = NULL;

	EVENT_OFF(up->t_join_timer);

	if (up->rpf.source_nexthop.interface)
		nbr = pim_neighbor_find(up->rpf.source_nexthop.interface,
					up->rpf.rpf_addr, true);

	if (nbr)
		pim_jp_agg_remove_group(nbr->upstream_jp_agg, up, nbr);

	pim_jp_agg_upstream_verification(up, false);
}

void join_timer_start(struct pim_upstream *up)
{
	struct pim_neighbor *nbr = NULL;

	if (up->rpf.source_nexthop.interface) {
		nbr = pim_neighbor_find(up->rpf.source_nexthop.interface,
					up->rpf.rpf_addr, true);

		if (PIM_DEBUG_PIM_EVENTS) {
			zlog_debug(
				"%s: starting %d sec timer for upstream (S,G)=%s",
				__func__, router->t_periodic, up->sg_str);
		}
	}

	if (nbr)
		pim_jp_agg_add_group(nbr->upstream_jp_agg, up, 1, nbr);
	else {
		EVENT_OFF(up->t_join_timer);
		event_add_timer(router->master, on_join_timer, up,
				router->t_periodic, &up->t_join_timer);
	}
	pim_jp_agg_upstream_verification(up, true);
}

/*
 * This is only called when we are switching the upstream
 * J/P from one neighbor to another
 *
 * As such we need to remove from the old list and
 * add to the new list.
 */
void pim_upstream_join_timer_restart(struct pim_upstream *up,
				     struct pim_rpf *old)
{
	// EVENT_OFF(up->t_join_timer);
	join_timer_start(up);
}

static void pim_upstream_join_timer_restart_msec(struct pim_upstream *up,
						 int interval_msec)
{
	if (PIM_DEBUG_PIM_EVENTS) {
		zlog_debug("%s: restarting %d msec timer for upstream (S,G)=%s",
			   __func__, interval_msec, up->sg_str);
	}

	EVENT_OFF(up->t_join_timer);
	event_add_timer_msec(router->master, on_join_timer, up, interval_msec,
			     &up->t_join_timer);
}

void pim_update_suppress_timers(uint32_t suppress_time)
{
	struct pim_instance *pim;
	struct vrf *vrf;
	unsigned int old_rp_ka_time;

	/* stash the old one so we know which values were manually configured */
	old_rp_ka_time =  (3 * router->register_suppress_time
			   + router->register_probe_time);
	router->register_suppress_time = suppress_time;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		pim = vrf->info;
		if (!pim)
			continue;

		/* Only adjust if not manually configured */
		if (pim->rp_keep_alive_time == old_rp_ka_time)
			pim->rp_keep_alive_time = PIM_RP_KEEPALIVE_PERIOD;
	}
}

void pim_upstream_join_suppress(struct pim_upstream *up, pim_addr rpf,
				int holdtime)
{
	long t_joinsuppress_msec;
	long join_timer_remain_msec = 0;
	struct pim_neighbor *nbr = NULL;

	if (!up->rpf.source_nexthop.interface) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: up %s RPF is not present", __func__,
				   up->sg_str);
		return;
	}

	t_joinsuppress_msec =
		MIN(pim_if_t_suppressed_msec(up->rpf.source_nexthop.interface),
		    1000 * holdtime);

	if (up->t_join_timer)
		join_timer_remain_msec =
			pim_time_timer_remain_msec(up->t_join_timer);
	else {
		/* Remove it from jp agg from the nbr for suppression */
		nbr = pim_neighbor_find(up->rpf.source_nexthop.interface,
					up->rpf.rpf_addr, true);

		if (nbr) {
			join_timer_remain_msec =
				pim_time_timer_remain_msec(nbr->jp_timer);
		}
	}

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug(
			"%s %s: detected Join%s to RPF'(S,G)=%pPA: join_timer=%ld msec t_joinsuppress=%ld msec",
			__FILE__, __func__, up->sg_str, &rpf,
			join_timer_remain_msec, t_joinsuppress_msec);

	if (join_timer_remain_msec < t_joinsuppress_msec) {
		if (PIM_DEBUG_PIM_TRACE) {
			zlog_debug(
				"%s %s: suppressing Join(S,G)=%s for %ld msec",
				__FILE__, __func__, up->sg_str,
				t_joinsuppress_msec);
		}

		if (nbr)
			pim_jp_agg_remove_group(nbr->upstream_jp_agg, up, nbr);

		pim_upstream_join_timer_restart_msec(up, t_joinsuppress_msec);
	}
}

void pim_upstream_join_timer_decrease_to_t_override(const char *debug_label,
						    struct pim_upstream *up)
{
	long join_timer_remain_msec;
	int t_override_msec;

	if (!up->rpf.source_nexthop.interface) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: up %s RPF is not present", __func__,
				   up->sg_str);
		return;
	}

	t_override_msec =
		pim_if_t_override_msec(up->rpf.source_nexthop.interface);

	if (up->t_join_timer) {
		join_timer_remain_msec =
			pim_time_timer_remain_msec(up->t_join_timer);
	} else {
		/* upstream join tracked with neighbor jp timer */
		struct pim_neighbor *nbr;

		nbr = pim_neighbor_find(up->rpf.source_nexthop.interface,
					up->rpf.rpf_addr, true);

		if (nbr)
			join_timer_remain_msec =
				pim_time_timer_remain_msec(nbr->jp_timer);
		else
			/* Manipulate such that override takes place */
			join_timer_remain_msec = t_override_msec + 1;
	}

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug(
			"%s: to RPF'%s=%pPA: join_timer=%ld msec t_override=%d msec",
			debug_label, up->sg_str, &up->rpf.rpf_addr,
			join_timer_remain_msec, t_override_msec);

	if (join_timer_remain_msec > t_override_msec) {
		if (PIM_DEBUG_PIM_TRACE) {
			zlog_debug(
				"%s: decreasing (S,G)=%s join timer to t_override=%d msec",
				debug_label, up->sg_str, t_override_msec);
		}

		pim_upstream_join_timer_restart_msec(up, t_override_msec);
	}
}

static void forward_on(struct pim_upstream *up)
{
	struct listnode *chnode;
	struct listnode *chnextnode;
	struct pim_ifchannel *ch = NULL;

	/* scan (S,G) state */
	for (ALL_LIST_ELEMENTS(up->ifchannels, chnode, chnextnode, ch)) {
		if (pim_macro_chisin_oiflist(ch))
			pim_forward_start(ch);

	} /* scan iface channel list */
}

static void forward_off(struct pim_upstream *up)
{
	struct listnode *chnode;
	struct listnode *chnextnode;
	struct pim_ifchannel *ch;

	/* scan per-interface (S,G) state */
	for (ALL_LIST_ELEMENTS(up->ifchannels, chnode, chnextnode, ch)) {

		pim_forward_stop(ch);

	} /* scan iface channel list */
}

int pim_upstream_could_register(struct pim_upstream *up)
{
	struct pim_interface *pim_ifp = NULL;

	/* FORCE_PIMREG is a generic flag to let an app like VxLAN-AA register
	 * a source on an upstream entry even if the source is not directly
	 * connected on the IIF.
	 */
	if (PIM_UPSTREAM_FLAG_TEST_FORCE_PIMREG(up->flags))
		return 1;

	if (up->rpf.source_nexthop.interface)
		pim_ifp = up->rpf.source_nexthop.interface->info;
	else {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: up %s RPF is not present", __func__,
				   up->sg_str);
	}

	if (pim_ifp && PIM_I_am_DR(pim_ifp)
	    && pim_if_connected_to_source(up->rpf.source_nexthop.interface,
					  up->sg.src))
		return 1;

	return 0;
}

/* Source registration is suppressed for SSM groups. When the SSM range changes
 * we re-revaluate register setup for existing upstream entries */
void pim_upstream_register_reevaluate(struct pim_instance *pim)
{
	struct pim_upstream *up;

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		/* If FHR is set CouldRegister is True. Also check if the flow
		 * is actually active; if it is not kat setup will trigger
		 * source
		 * registration whenever the flow becomes active. */
		if (!PIM_UPSTREAM_FLAG_TEST_FHR(up->flags) ||
			!pim_upstream_is_kat_running(up))
			continue;

		if (pim_is_grp_ssm(pim, up->sg.grp)) {
			/* clear the register state  for SSM groups */
			if (up->reg_state != PIM_REG_NOINFO) {
				if (PIM_DEBUG_PIM_EVENTS)
					zlog_debug(
						"Clear register for %s as G is now SSM",
						up->sg_str);
				/* remove regiface from the OIL if it is there*/
				pim_channel_del_oif(up->channel_oil,
						    pim->regiface,
						    PIM_OIF_FLAG_PROTO_PIM,
							__func__);
				up->reg_state = PIM_REG_NOINFO;
			}
		} else {
			/* register ASM sources with the RP */
			if (up->reg_state == PIM_REG_NOINFO) {
				if (PIM_DEBUG_PIM_EVENTS)
					zlog_debug(
						"Register %s as G is now ASM",
						up->sg_str);
				pim_channel_add_oif(up->channel_oil,
						    pim->regiface,
						    PIM_OIF_FLAG_PROTO_PIM,
							__func__);
				up->reg_state = PIM_REG_JOIN;
			}
		}
	}
}

/* RFC7761, Section 4.2 “Data Packet Forwarding Rules” says we should
 * forward a S -
 * 1. along the SPT if SPTbit is set
 * 2. and along the RPT if SPTbit is not set
 * If forwarding is hw accelerated i.e. control and dataplane components
 * are separate you may not be able to reliably set SPT bit on intermediate
 * routers while still forwarding on the (S,G,rpt).
 *
 * This macro is a slight deviation on the RFC and uses "traffic-agnostic"
 * criteria to decide between using the RPT vs. SPT for forwarding.
 */
void pim_upstream_update_use_rpt(struct pim_upstream *up,
			bool update_mroute)
{
	bool old_use_rpt;
	bool new_use_rpt;

	if (pim_addr_is_any(up->sg.src))
		return;

	old_use_rpt = !!PIM_UPSTREAM_FLAG_TEST_USE_RPT(up->flags);

	/* We will use the SPT (IIF=RPF_interface(S) if -
	 * 1. We have decided to join the SPT
	 * 2. We are FHR
	 * 3. Source is directly connected
	 * 4. We are RP (parent's IIF is lo or vrf-device)
	 * In all other cases the source will stay along the RPT and
	 * IIF=RPF_interface(RP).
	 */
	if (up->join_state == PIM_UPSTREAM_JOINED ||
			PIM_UPSTREAM_FLAG_TEST_FHR(up->flags) ||
			pim_if_connected_to_source(
				up->rpf.source_nexthop.interface,
				up->sg.src) ||
			/* XXX - need to switch this to a more efficient
			 * lookup API
			 */
			I_am_RP(up->pim, up->sg.grp))
		/* use SPT */
		PIM_UPSTREAM_FLAG_UNSET_USE_RPT(up->flags);
	else
		/* use RPT */
		PIM_UPSTREAM_FLAG_SET_USE_RPT(up->flags);

	new_use_rpt = !!PIM_UPSTREAM_FLAG_TEST_USE_RPT(up->flags);
	if (old_use_rpt != new_use_rpt) {
		if (PIM_DEBUG_PIM_EVENTS)
			zlog_debug("%s switched from %s to %s", up->sg_str,
				   old_use_rpt ? "RPT" : "SPT",
				   new_use_rpt ? "RPT" : "SPT");
		if (update_mroute)
			pim_upstream_mroute_add(up->channel_oil, __func__);
	}
}

/* some events like RP change require re-evaluation of SGrpt across
 * all groups
 */
void pim_upstream_reeval_use_rpt(struct pim_instance *pim)
{
	struct pim_upstream *up;

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		if (pim_addr_is_any(up->sg.src))
			continue;

		pim_upstream_update_use_rpt(up, true /*update_mroute*/);
	}
}

void pim_upstream_switch(struct pim_instance *pim, struct pim_upstream *up,
			 enum pim_upstream_state new_state)
{
	enum pim_upstream_state old_state = up->join_state;

	if (pim_addr_is_any(up->upstream_addr)) {
		if (PIM_DEBUG_PIM_EVENTS)
			zlog_debug("%s: RPF not configured for %s", __func__,
				   up->sg_str);
		return;
	}

	if (!up->rpf.source_nexthop.interface)  {
		if (PIM_DEBUG_PIM_EVENTS)
			zlog_debug("%s: RP not reachable for %s", __func__,
				   up->sg_str);
		return;
	}

	if (PIM_DEBUG_PIM_EVENTS) {
		zlog_debug("%s: PIM_UPSTREAM_%s: (S,G) old: %s new: %s",
			   __func__, up->sg_str,
			   pim_upstream_state2str(up->join_state),
			   pim_upstream_state2str(new_state));
	}

	up->join_state = new_state;
	if (old_state != new_state)
		up->state_transition = pim_time_monotonic_sec();

	pim_upstream_update_assert_tracking_desired(up);

	if (new_state == PIM_UPSTREAM_JOINED) {
		pim_upstream_inherited_olist_decide(pim, up);
		if (old_state != PIM_UPSTREAM_JOINED) {
			int old_fhr = PIM_UPSTREAM_FLAG_TEST_FHR(up->flags);

			pim_msdp_up_join_state_changed(pim, up);
			if (pim_upstream_could_register(up)) {
				PIM_UPSTREAM_FLAG_SET_FHR(up->flags);
				if (!old_fhr
				    && PIM_UPSTREAM_FLAG_TEST_SRC_STREAM(
					       up->flags)) {
					pim_upstream_keep_alive_timer_start(
						up, pim->keep_alive_time);
					pim_register_join(up);
				}
			} else {
				pim_upstream_send_join(up);
				join_timer_start(up);
			}
		}
		if (old_state != new_state)
			pim_upstream_update_use_rpt(up, true /*update_mroute*/);
	} else {
		bool old_use_rpt;
		bool new_use_rpt;
		bool send_xg_jp = false;

		forward_off(up);
		/*
		 * RFC 4601 Sec 4.5.7:
		 * JoinDesired(S,G) -> False, set SPTbit to false.
		 */
		if (!pim_addr_is_any(up->sg.src))
			up->sptbit = PIM_UPSTREAM_SPTBIT_FALSE;

		if (old_state == PIM_UPSTREAM_JOINED)
			pim_msdp_up_join_state_changed(pim, up);

		if (old_state != new_state) {
			old_use_rpt =
				!!PIM_UPSTREAM_FLAG_TEST_USE_RPT(up->flags);
			pim_upstream_update_use_rpt(up, true /*update_mroute*/);
			new_use_rpt =
				!!PIM_UPSTREAM_FLAG_TEST_USE_RPT(up->flags);
			if (new_use_rpt &&
					(new_use_rpt != old_use_rpt) &&
					up->parent)
				/* we have decided to switch from the SPT back
				 * to the RPT which means we need to cancel
				 * any previously sent SGrpt prunes immediately
				 */
				send_xg_jp = true;
		}

		/* IHR, Trigger SGRpt on *,G IIF to prune S,G from RPT towards
		   RP.
		   If I am RP for G then send S,G prune to its IIF. */
		if (pim_upstream_is_sg_rpt(up) && up->parent &&
				!I_am_RP(pim, up->sg.grp))
			send_xg_jp = true;

		pim_jp_agg_single_upstream_send(&up->rpf, up, 0 /* prune */);

		if (send_xg_jp) {
			if (PIM_DEBUG_PIM_TRACE_DETAIL)
				zlog_debug(
				  "re-join RPT; *,G IIF %s S,G IIF %s ",
				  up->parent->rpf.source_nexthop.interface ?
				  up->parent->rpf.source_nexthop.interface->name
				  : "Unknown",
				  up->rpf.source_nexthop.interface ?
				  up->rpf.source_nexthop.interface->name :
				  "Unknown");
			pim_jp_agg_single_upstream_send(&up->parent->rpf,
							up->parent,
							1 /* (W,G) Join */);
		}
		join_timer_stop(up);
	}
}

int pim_upstream_compare(const struct pim_upstream *up1,
			 const struct pim_upstream *up2)
{
	return pim_sgaddr_cmp(up1->sg, up2->sg);
}

void pim_upstream_fill_static_iif(struct pim_upstream *up,
				struct interface *incoming)
{
	up->rpf.source_nexthop.interface = incoming;

	/* reset other parameters to matched a connected incoming interface */
	up->rpf.source_nexthop.mrib_nexthop_addr = PIMADDR_ANY;
	up->rpf.source_nexthop.mrib_metric_preference =
		ZEBRA_CONNECT_DISTANCE_DEFAULT;
	up->rpf.source_nexthop.mrib_route_metric = 0;
	up->rpf.rpf_addr = PIMADDR_ANY;
}

static struct pim_upstream *pim_upstream_new(struct pim_instance *pim,
					     pim_sgaddr *sg,
					     struct interface *incoming,
					     int flags,
					     struct pim_ifchannel *ch)
{
	enum pim_rpf_result rpf_result;
	struct pim_interface *pim_ifp;
	struct pim_upstream *up;

	up = XCALLOC(MTYPE_PIM_UPSTREAM, sizeof(*up));

	up->pim = pim;
	up->sg = *sg;
	snprintfrr(up->sg_str, sizeof(up->sg_str), "%pSG", sg);
	if (ch)
		ch->upstream = up;

	rb_pim_upstream_add(&pim->upstream_head, up);
	/* Set up->upstream_addr as INADDR_ANY, if RP is not
	 * configured and retain the upstream data structure
	 */
	if (!pim_rp_set_upstream_addr(pim, &up->upstream_addr, sg->src,
				      sg->grp)) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: Received a (*,G) with no RP configured",
				   __func__);
	}

	up->parent = pim_upstream_find_parent(pim, up);
	if (pim_addr_is_any(up->sg.src)) {
		up->sources = list_new();
		up->sources->cmp =
			(int (*)(void *, void *))pim_upstream_compare;
	} else
		up->sources = NULL;

	pim_upstream_find_new_children(pim, up);
	up->flags = flags;
	up->ref_count = 1;
	up->t_join_timer = NULL;
	up->t_ka_timer = NULL;
	up->t_rs_timer = NULL;
	up->t_msdp_reg_timer = NULL;
	up->join_state = PIM_UPSTREAM_NOTJOINED;
	up->reg_state = PIM_REG_NOINFO;
	up->state_transition = pim_time_monotonic_sec();
	up->channel_oil = pim_channel_oil_add(pim, &up->sg, __func__);
	up->sptbit = PIM_UPSTREAM_SPTBIT_FALSE;

	up->rpf.source_nexthop.interface = NULL;
	up->rpf.source_nexthop.mrib_nexthop_addr = PIMADDR_ANY;
	up->rpf.source_nexthop.mrib_metric_preference =
		router->infinite_assert_metric.metric_preference;
	up->rpf.source_nexthop.mrib_route_metric =
		router->infinite_assert_metric.route_metric;
	up->rpf.rpf_addr = PIMADDR_ANY;
	up->ifchannels = list_new();
	up->ifchannels->cmp = (int (*)(void *, void *))pim_ifchannel_compare;

	if (!pim_addr_is_any(up->sg.src)) {
		wheel_add_item(pim->upstream_sg_wheel, up);

		/* Inherit the DF role from the parent (*, G) entry for
		 * VxLAN BUM groups
		 */
		if (up->parent
		    && PIM_UPSTREAM_FLAG_TEST_MLAG_VXLAN(up->parent->flags)
		    && PIM_UPSTREAM_FLAG_TEST_MLAG_NON_DF(up->parent->flags)) {
			PIM_UPSTREAM_FLAG_SET_MLAG_NON_DF(up->flags);
			if (PIM_DEBUG_VXLAN)
				zlog_debug(
					"upstream %s inherited mlag non-df flag from parent",
					up->sg_str);
		}
	}

	if (PIM_UPSTREAM_FLAG_TEST_STATIC_IIF(up->flags)
	    || PIM_UPSTREAM_FLAG_TEST_SRC_NOCACHE(up->flags)) {
		pim_upstream_fill_static_iif(up, incoming);
		pim_ifp = up->rpf.source_nexthop.interface->info;
		assert(pim_ifp);
		pim_upstream_update_use_rpt(up,
				false /*update_mroute*/);
		pim_upstream_mroute_iif_update(up->channel_oil, __func__);

		if (PIM_UPSTREAM_FLAG_TEST_SRC_NOCACHE(up->flags)) {
			/*
			 * Set the right RPF so that future changes will
			 * be right
			 */
			rpf_result = pim_rpf_update(pim, up, NULL, __func__);
			pim_upstream_keep_alive_timer_start(
				up, pim->keep_alive_time);
		}
	} else if (!pim_addr_is_any(up->upstream_addr)) {
		pim_upstream_update_use_rpt(up,
				false /*update_mroute*/);
		rpf_result = pim_rpf_update(pim, up, NULL, __func__);
		if (rpf_result == PIM_RPF_FAILURE) {
			up->channel_oil->oil_inherited_rescan = 1;
			if (PIM_DEBUG_PIM_TRACE)
				zlog_debug(
					"%s: Attempting to create upstream(%s), Unable to RPF for source",
					__func__, up->sg_str);
		}

		/* Consider a case where (S,G,rpt) prune is received and this
		 * upstream is getting created due to that, then as per RFC
		 * until prune pending time we need to behave same as NOINFO
		 * state, therefore do not install if OIF is NULL until then
		 * This is for PIM Conformance PIM-SM 16.3 fix
		 * When the prune pending timer pop, this mroute will get
		 * installed with none as OIF */
		if (up->rpf.source_nexthop.interface &&
		    !(pim_upstream_empty_inherited_olist(up) && (ch != NULL) &&
		      PIM_IF_FLAG_TEST_S_G_RPT(ch->flags))) {
			pim_upstream_mroute_iif_update(up->channel_oil,
					__func__);
		}
	}

	/* send the entry to the MLAG peer */
	/* XXX - duplicate send is possible here if pim_rpf_update
	 * successfully resolved the nexthop
	 */
	if (pim_up_mlag_is_local(up)
	    || PIM_UPSTREAM_FLAG_TEST_MLAG_INTERFACE(up->flags))
		pim_mlag_up_local_add(pim, up);

	if (PIM_DEBUG_PIM_TRACE) {
		zlog_debug(
			"%s: Created Upstream %s upstream_addr %pPAs ref count %d increment",
			__func__, up->sg_str, &up->upstream_addr,
			up->ref_count);
	}

	return up;
}

uint32_t pim_up_mlag_local_cost(struct pim_upstream *up)
{
	if (!(pim_up_mlag_is_local(up))
	    && !(up->flags & PIM_UPSTREAM_FLAG_MASK_MLAG_INTERFACE))
		return router->infinite_assert_metric.route_metric;

	if ((up->rpf.source_nexthop.interface ==
				up->pim->vxlan.peerlink_rif) &&
			(up->rpf.source_nexthop.mrib_route_metric <
			 (router->infinite_assert_metric.route_metric -
			  PIM_UPSTREAM_MLAG_PEERLINK_PLUS_METRIC)))
		return up->rpf.source_nexthop.mrib_route_metric +
			PIM_UPSTREAM_MLAG_PEERLINK_PLUS_METRIC;

	return up->rpf.source_nexthop.mrib_route_metric;
}

uint32_t pim_up_mlag_peer_cost(struct pim_upstream *up)
{
	if (!(up->flags & PIM_UPSTREAM_FLAG_MASK_MLAG_PEER))
		return router->infinite_assert_metric.route_metric;

	return up->mlag.peer_mrib_metric;
}

struct pim_upstream *pim_upstream_find(struct pim_instance *pim, pim_sgaddr *sg)
{
	struct pim_upstream lookup;
	struct pim_upstream *up = NULL;

	lookup.sg = *sg;
	up = rb_pim_upstream_find(&pim->upstream_head, &lookup);
	return up;
}

struct pim_upstream *pim_upstream_find_or_add(pim_sgaddr *sg,
					      struct interface *incoming,
					      int flags, const char *name)
{
	struct pim_interface *pim_ifp = incoming->info;

	return (pim_upstream_add(pim_ifp->pim, sg, incoming, flags, name,
				NULL));
}

void pim_upstream_ref(struct pim_upstream *up, int flags, const char *name)
{
	/* if a local MLAG reference is being created we need to send the mroute
	 * to the peer
	 */
	if (!PIM_UPSTREAM_FLAG_TEST_MLAG_VXLAN(up->flags) &&
			PIM_UPSTREAM_FLAG_TEST_MLAG_VXLAN(flags)) {
		PIM_UPSTREAM_FLAG_SET_MLAG_VXLAN(up->flags);
		pim_mlag_up_local_add(up->pim, up);
	}

	/* when we go from non-FHR to FHR we need to re-eval traffic
	 * forwarding path
	 */
	if (!PIM_UPSTREAM_FLAG_TEST_FHR(up->flags) &&
			PIM_UPSTREAM_FLAG_TEST_FHR(flags)) {
		PIM_UPSTREAM_FLAG_SET_FHR(up->flags);
		pim_upstream_update_use_rpt(up, true /*update_mroute*/);
	}

	/* re-eval joinDesired; clearing peer-msdp-sa flag can
	 * cause JD to change
	 */
	if (!PIM_UPSTREAM_FLAG_TEST_SRC_MSDP(up->flags) &&
			PIM_UPSTREAM_FLAG_TEST_SRC_MSDP(flags)) {
		PIM_UPSTREAM_FLAG_SET_SRC_MSDP(up->flags);
		pim_upstream_update_join_desired(up->pim, up);
	}

	up->flags |= flags;
	++up->ref_count;
	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("%s(%s): upstream %s ref count %d increment",
			   __func__, name, up->sg_str, up->ref_count);
}

struct pim_upstream *pim_upstream_add(struct pim_instance *pim, pim_sgaddr *sg,
				      struct interface *incoming, int flags,
				      const char *name,
				      struct pim_ifchannel *ch)
{
	struct pim_upstream *up = NULL;
	int found = 0;

	up = pim_upstream_find(pim, sg);
	if (up) {
		pim_upstream_ref(up, flags, name);
		found = 1;
	} else {
		up = pim_upstream_new(pim, sg, incoming, flags, ch);
	}

	if (PIM_DEBUG_PIM_TRACE) {
		zlog_debug(
			"%s(%s): %s, iif %pPA (%s) found: %d: ref_count: %d",
			__func__, name, up->sg_str, &up->rpf.rpf_addr,
			up->rpf.source_nexthop.interface ? up->rpf.source_nexthop
								   .interface->name
							 : "Unknown",
			found, up->ref_count);
	}

	return up;
}

/*
 * Passed in up must be the upstream for ch.  starch is NULL if no
 * information
 * This function is copied over from
 * pim_upstream_evaluate_join_desired_interface but limited to
 * parent (*,G)'s includes/joins.
 */
int pim_upstream_eval_inherit_if(struct pim_upstream *up,
						 struct pim_ifchannel *ch,
						 struct pim_ifchannel *starch)
{
	/* if there is an explicit prune for this interface we cannot
	 * add it to the OIL
	 */
	if (ch) {
		if (PIM_IF_FLAG_TEST_S_G_RPT(ch->flags))
			return 0;
	}

	/* Check if the OIF can be inherited fron the (*,G) entry
	 */
	if (starch) {
		if (!pim_macro_ch_lost_assert(starch)
		    && pim_macro_chisin_joins_or_include(starch))
			return 1;
	}

	return 0;
}

/*
 * Passed in up must be the upstream for ch.  starch is NULL if no
 * information
 */
int pim_upstream_evaluate_join_desired_interface(struct pim_upstream *up,
						 struct pim_ifchannel *ch,
						 struct pim_ifchannel *starch)
{
	if (ch) {
		if (PIM_IF_FLAG_TEST_S_G_RPT(ch->flags))
			return 0;

		if (!pim_macro_ch_lost_assert(ch)
		    && pim_macro_chisin_joins_or_include(ch))
			return 1;
	}

	/*
	 * joins (*,G)
	 */
	if (starch) {
		/* XXX: check on this with donald
		 * we are looking for PIM_IF_FLAG_MASK_S_G_RPT in
		 * upstream flags?
		 */
#if 0
		if (PIM_IF_FLAG_TEST_S_G_RPT(starch->upstream->flags))
			return 0;
#endif

		if (!pim_macro_ch_lost_assert(starch)
		    && pim_macro_chisin_joins_or_include(starch))
			return 1;
	}

	return 0;
}

/* Returns true if immediate OIL is empty and is used to evaluate
 * JoinDesired. See pim_upstream_evaluate_join_desired.
 */
static bool pim_upstream_empty_immediate_olist(struct pim_instance *pim,
				       struct pim_upstream *up)
{
	struct interface *ifp;
	struct pim_ifchannel *ch;

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		if (!ifp->info)
			continue;

		ch = pim_ifchannel_find(ifp, &up->sg);
		if (!ch)
			continue;

		/* If we have even one immediate OIF we can return with
		 * not-empty
		 */
		if (pim_upstream_evaluate_join_desired_interface(up, ch,
					    NULL /* starch */))
			return false;
	} /* scan iface channel list */

	/* immediate_oil is empty */
	return true;
}


static inline bool pim_upstream_is_msdp_peer_sa(struct pim_upstream *up)
{
	return PIM_UPSTREAM_FLAG_TEST_SRC_MSDP(up->flags);
}

/*
 *   bool JoinDesired(*,G) {
 *       if (immediate_olist(*,G) != NULL)
 *           return TRUE
 *       else
 *           return FALSE
 *   }
 *
 *   bool JoinDesired(S,G) {
 *       return( immediate_olist(S,G) != NULL
 *           OR ( KeepaliveTimer(S,G) is running
 *           AND inherited_olist(S,G) != NULL ) )
 *   }
 */
bool pim_upstream_evaluate_join_desired(struct pim_instance *pim,
				       struct pim_upstream *up)
{
	bool empty_imm_oil;
	bool empty_inh_oil;

	empty_imm_oil = pim_upstream_empty_immediate_olist(pim, up);

	/* (*,G) */
	if (pim_addr_is_any(up->sg.src))
		return !empty_imm_oil;

	/* (S,G) */
	if (!empty_imm_oil)
		return true;
	empty_inh_oil = pim_upstream_empty_inherited_olist(up);
	if (!empty_inh_oil &&
			(pim_upstream_is_kat_running(up) ||
			 pim_upstream_is_msdp_peer_sa(up)))
		return true;

	return false;
}

/*
  See also pim_upstream_evaluate_join_desired() above.
*/
void pim_upstream_update_join_desired(struct pim_instance *pim,
				      struct pim_upstream *up)
{
	int was_join_desired; /* boolean */
	int is_join_desired;  /* boolean */

	was_join_desired = PIM_UPSTREAM_FLAG_TEST_DR_JOIN_DESIRED(up->flags);

	is_join_desired = pim_upstream_evaluate_join_desired(pim, up);
	if (is_join_desired)
		PIM_UPSTREAM_FLAG_SET_DR_JOIN_DESIRED(up->flags);
	else
		PIM_UPSTREAM_FLAG_UNSET_DR_JOIN_DESIRED(up->flags);

	/* switched from false to true */
	if (is_join_desired && (up->join_state == PIM_UPSTREAM_NOTJOINED)) {
		pim_upstream_switch(pim, up, PIM_UPSTREAM_JOINED);
		return;
	}

	/* switched from true to false */
	if (!is_join_desired && was_join_desired) {
		pim_upstream_switch(pim, up, PIM_UPSTREAM_NOTJOINED);
		return;
	}
}

/*
  RFC 4601 4.5.7. Sending (S,G) Join/Prune Messages
  Transitions from Joined State
  RPF'(S,G) GenID changes

  The upstream (S,G) state machine remains in Joined state.  If the
  Join Timer is set to expire in more than t_override seconds, reset
  it so that it expires after t_override seconds.
*/
void pim_upstream_rpf_genid_changed(struct pim_instance *pim,
				    pim_addr neigh_addr)
{
	struct pim_upstream *up;

	/*
	 * Scan all (S,G) upstreams searching for RPF'(S,G)=neigh_addr
	 */
	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		pim_addr rpf_addr;

		rpf_addr = up->rpf.rpf_addr;

		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"%s: matching neigh=%pPA against upstream (S,G)=%s[%s] joined=%d rpf_addr=%pPA",
				__func__, &neigh_addr, up->sg_str,
				pim->vrf->name,
				up->join_state == PIM_UPSTREAM_JOINED,
				&rpf_addr);

		/* consider only (S,G) upstream in Joined state */
		if (up->join_state != PIM_UPSTREAM_JOINED)
			continue;

		/* match RPF'(S,G)=neigh_addr */
		if (pim_addr_cmp(rpf_addr, neigh_addr))
			continue;

		pim_upstream_join_timer_decrease_to_t_override(
			"RPF'(S,G) GenID change", up);
	}
}


void pim_upstream_rpf_interface_changed(struct pim_upstream *up,
					struct interface *old_rpf_ifp)
{
	struct listnode *chnode;
	struct listnode *chnextnode;
	struct pim_ifchannel *ch;

	/* search all ifchannels */
	for (ALL_LIST_ELEMENTS(up->ifchannels, chnode, chnextnode, ch)) {
		if (ch->ifassert_state == PIM_IFASSERT_I_AM_LOSER) {
			if (
				/* RPF_interface(S) was NOT I */
				(old_rpf_ifp == ch->interface) &&
				/* RPF_interface(S) stopped being I */
				(ch->upstream->rpf.source_nexthop
					.interface) &&
				(ch->upstream->rpf.source_nexthop
					.interface != ch->interface)) {
				assert_action_a5(ch);
			}
		} /* PIM_IFASSERT_I_AM_LOSER */

		pim_ifchannel_update_assert_tracking_desired(ch);
	}
}

void pim_upstream_update_could_assert(struct pim_upstream *up)
{
	struct listnode *chnode;
	struct listnode *chnextnode;
	struct pim_ifchannel *ch;

	/* scan per-interface (S,G) state */
	for (ALL_LIST_ELEMENTS(up->ifchannels, chnode, chnextnode, ch)) {
		pim_ifchannel_update_could_assert(ch);
	} /* scan iface channel list */
}

void pim_upstream_update_my_assert_metric(struct pim_upstream *up)
{
	struct listnode *chnode;
	struct listnode *chnextnode;
	struct pim_ifchannel *ch;

	/* scan per-interface (S,G) state */
	for (ALL_LIST_ELEMENTS(up->ifchannels, chnode, chnextnode, ch)) {
		pim_ifchannel_update_my_assert_metric(ch);

	} /* scan iface channel list */
}

static void pim_upstream_update_assert_tracking_desired(struct pim_upstream *up)
{
	struct listnode *chnode;
	struct listnode *chnextnode;
	struct pim_interface *pim_ifp;
	struct pim_ifchannel *ch;

	/* scan per-interface (S,G) state */
	for (ALL_LIST_ELEMENTS(up->ifchannels, chnode, chnextnode, ch)) {
		if (!ch->interface)
			continue;
		pim_ifp = ch->interface->info;
		if (!pim_ifp)
			continue;

		pim_ifchannel_update_assert_tracking_desired(ch);

	} /* scan iface channel list */
}

/* When kat is stopped CouldRegister goes to false so we need to
 * transition  the (S, G) on FHR to NI state and remove reg tunnel
 * from the OIL */
static void pim_upstream_fhr_kat_expiry(struct pim_instance *pim,
					struct pim_upstream *up)
{
	if (!PIM_UPSTREAM_FLAG_TEST_FHR(up->flags))
		return;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("kat expired on %s; clear fhr reg state",
			   up->sg_str);

	/* stop reg-stop timer */
	EVENT_OFF(up->t_rs_timer);
	/* remove regiface from the OIL if it is there*/
	pim_channel_del_oif(up->channel_oil, pim->regiface,
			    PIM_OIF_FLAG_PROTO_PIM, __func__);
	/* clear the register state */
	up->reg_state = PIM_REG_NOINFO;
	PIM_UPSTREAM_FLAG_UNSET_FHR(up->flags);
}

/* When kat is started CouldRegister can go to true. And if it does we
 * need to transition  the (S, G) on FHR to JOINED state and add reg tunnel
 * to the OIL */
static void pim_upstream_fhr_kat_start(struct pim_upstream *up)
{
	if (pim_upstream_could_register(up)) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"kat started on %s; set fhr reg state to joined",
				up->sg_str);

		PIM_UPSTREAM_FLAG_SET_FHR(up->flags);
		if (up->reg_state == PIM_REG_NOINFO)
			pim_register_join(up);
		pim_upstream_update_use_rpt(up, true /*update_mroute*/);
	}
}

/*
 * On an RP, the PMBR value must be cleared when the
 * Keepalive Timer expires
 * KAT expiry indicates that flow is inactive. If the flow was created or
 * maintained by activity now is the time to deref it.
 */
struct pim_upstream *pim_upstream_keep_alive_timer_proc(
		struct pim_upstream *up)
{
	struct pim_instance *pim;

	pim = up->channel_oil->pim;

	if (PIM_UPSTREAM_FLAG_TEST_DISABLE_KAT_EXPIRY(up->flags)) {
		/* if the router is a PIM vxlan encapsulator we prevent expiry
		 * of KAT as the mroute is pre-setup without any traffic
		 */
		pim_upstream_keep_alive_timer_start(up, pim->keep_alive_time);
		return up;
	}

	if (I_am_RP(pim, up->sg.grp)) {
		/*
		 * Handle Border Router
		 * We need to do more here :)
		 * But this is the start.
		 */
	}

	/* source is no longer active - pull the SA from MSDP's cache */
	pim_msdp_sa_local_del(pim, &up->sg);

	/* JoinDesired can change when KAT is started or stopped */
	pim_upstream_update_join_desired(pim, up);

	/* if entry was created because of activity we need to deref it */
	if (PIM_UPSTREAM_FLAG_TEST_SRC_STREAM(up->flags)) {
		pim_upstream_fhr_kat_expiry(pim, up);
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"kat expired on %s[%s]; remove stream reference",
				up->sg_str, pim->vrf->name);
		PIM_UPSTREAM_FLAG_UNSET_SRC_STREAM(up->flags);

		/* Return if upstream entry got deleted.*/
		if (!pim_upstream_del(pim, up, __func__))
			return NULL;
	}
	if (PIM_UPSTREAM_FLAG_TEST_SRC_NOCACHE(up->flags)) {
		PIM_UPSTREAM_FLAG_UNSET_SRC_NOCACHE(up->flags);

		if (!pim_upstream_del(pim, up, __func__))
			return NULL;
	}

	/* upstream reference would have been added to track the local
	 * membership if it is LHR. We have to clear it when KAT expires.
	 * Otherwise would result in stale entry with uncleared ref count.
	 */
	if (PIM_UPSTREAM_FLAG_TEST_SRC_LHR(up->flags)) {
		struct pim_upstream *parent = up->parent;

		PIM_UPSTREAM_FLAG_UNSET_SRC_LHR(up->flags);
		up = pim_upstream_del(pim, up, __func__);

		if (parent) {
			pim_jp_agg_single_upstream_send(&parent->rpf, parent,
							true);
		}
	}

	return up;
}
static void pim_upstream_keep_alive_timer(struct event *t)
{
	struct pim_upstream *up;

	up = EVENT_ARG(t);

	/* pull the stats and re-check */
	if (pim_upstream_sg_running_proc(up))
		/* kat was restarted because of new activity */
		return;

	pim_upstream_keep_alive_timer_proc(up);
}

void pim_upstream_keep_alive_timer_start(struct pim_upstream *up, uint32_t time)
{
	if (!PIM_UPSTREAM_FLAG_TEST_SRC_STREAM(up->flags)) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("kat start on %s with no stream reference",
				   up->sg_str);
	}
	EVENT_OFF(up->t_ka_timer);
	event_add_timer(router->master, pim_upstream_keep_alive_timer, up, time,
			&up->t_ka_timer);

	/* any time keepalive is started against a SG we will have to
	 * re-evaluate our active source database */
	pim_msdp_sa_local_update(up);
	/* JoinDesired can change when KAT is started or stopped */
	pim_upstream_update_join_desired(up->pim, up);
}

/* MSDP on RP needs to know if a source is registerable to this RP */
static void pim_upstream_msdp_reg_timer(struct event *t)
{
	struct pim_upstream *up = EVENT_ARG(t);
	struct pim_instance *pim = up->channel_oil->pim;

	/* source is no longer active - pull the SA from MSDP's cache */
	pim_msdp_sa_local_del(pim, &up->sg);
}

void pim_upstream_msdp_reg_timer_start(struct pim_upstream *up)
{
	EVENT_OFF(up->t_msdp_reg_timer);
	event_add_timer(router->master, pim_upstream_msdp_reg_timer, up,
			PIM_MSDP_REG_RXED_PERIOD, &up->t_msdp_reg_timer);

	pim_msdp_sa_local_update(up);
}

/*
 * 4.2.1 Last-Hop Switchover to the SPT
 *
 *  In Sparse-Mode PIM, last-hop routers join the shared tree towards the
 *  RP.  Once traffic from sources to joined groups arrives at a last-hop
 *  router, it has the option of switching to receive the traffic on a
 *  shortest path tree (SPT).
 *
 *  The decision for a router to switch to the SPT is controlled as
 *  follows:
 *
 *    void
 *    CheckSwitchToSpt(S,G) {
 *      if ( ( pim_include(*,G) (-) pim_exclude(S,G)
 *             (+) pim_include(S,G) != NULL )
 *           AND SwitchToSptDesired(S,G) ) {
 *             # Note: Restarting the KAT will result in the SPT switch
 *             set KeepaliveTimer(S,G) to Keepalive_Period
 *      }
 *    }
 *
 *  SwitchToSptDesired(S,G) is a policy function that is implementation
 *  defined.  An "infinite threshold" policy can be implemented by making
 *  SwitchToSptDesired(S,G) return false all the time.  A "switch on
 *  first packet" policy can be implemented by making
 *  SwitchToSptDesired(S,G) return true once a single packet has been
 *  received for the source and group.
 */
int pim_upstream_switch_to_spt_desired_on_rp(struct pim_instance *pim,
					     pim_sgaddr *sg)
{
	if (I_am_RP(pim, sg->grp))
		return 1;

	return 0;
}

int pim_upstream_is_sg_rpt(struct pim_upstream *up)
{
	struct listnode *chnode;
	struct pim_ifchannel *ch;

	for (ALL_LIST_ELEMENTS_RO(up->ifchannels, chnode, ch)) {
		if (PIM_IF_FLAG_TEST_S_G_RPT(ch->flags))
			return 1;
	}

	return 0;
}
/*
 *  After receiving a packet set SPTbit:
 *   void
 *   Update_SPTbit(S,G,iif) {
 *     if ( iif == RPF_interface(S)
 *           AND JoinDesired(S,G) == true
 *           AND ( DirectlyConnected(S) == true
 *                 OR RPF_interface(S) != RPF_interface(RP(G))
 *                 OR inherited_olist(S,G,rpt) == NULL
 *                 OR ( ( RPF'(S,G) == RPF'(*,G) ) AND
 *                      ( RPF'(S,G) != NULL ) )
 *                 OR ( I_Am_Assert_Loser(S,G,iif) ) {
 *        Set SPTbit(S,G) to true
 *     }
 *   }
 */
void pim_upstream_set_sptbit(struct pim_upstream *up,
			     struct interface *incoming)
{
	struct pim_upstream *starup = up->parent;

	// iif == RPF_interfvace(S)
	if (up->rpf.source_nexthop.interface != incoming) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"%s: Incoming Interface: %s is different than RPF_interface(S) %s",
				__func__, incoming->name,
				up->rpf.source_nexthop.interface->name);
		return;
	}

	// AND JoinDesired(S,G) == true
	if (!pim_upstream_evaluate_join_desired(up->channel_oil->pim, up)) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: %s Join is not Desired", __func__,
				   up->sg_str);
		return;
	}

	// DirectlyConnected(S) == true
	if (pim_if_connected_to_source(up->rpf.source_nexthop.interface,
				       up->sg.src)) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: %s is directly connected to the source",
				   __func__, up->sg_str);
		up->sptbit = PIM_UPSTREAM_SPTBIT_TRUE;
		return;
	}

	// OR RPF_interface(S) != RPF_interface(RP(G))
	if (!starup
	    || up->rpf.source_nexthop
			       .interface != starup->rpf.source_nexthop.interface) {
		struct pim_upstream *starup = up->parent;

		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"%s: %s RPF_interface(S) != RPF_interface(RP(G))",
				__func__, up->sg_str);
		up->sptbit = PIM_UPSTREAM_SPTBIT_TRUE;

		pim_jp_agg_single_upstream_send(&starup->rpf, starup, true);
		return;
	}

	// OR inherited_olist(S,G,rpt) == NULL
	if (pim_upstream_is_sg_rpt(up)
	    && pim_upstream_empty_inherited_olist(up)) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: %s OR inherited_olist(S,G,rpt) == NULL",
				   __func__, up->sg_str);
		up->sptbit = PIM_UPSTREAM_SPTBIT_TRUE;
		return;
	}

	// OR ( ( RPF'(S,G) == RPF'(*,G) ) AND
	//      ( RPF'(S,G) != NULL ) )
	if (up->parent && pim_rpf_is_same(&up->rpf, &up->parent->rpf)) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: %s RPF'(S,G) is the same as RPF'(*,G)",
				   __func__, up->sg_str);
		up->sptbit = PIM_UPSTREAM_SPTBIT_TRUE;
		return;
	}

	return;
}

const char *pim_upstream_state2str(enum pim_upstream_state join_state)
{
	switch (join_state) {
	case PIM_UPSTREAM_NOTJOINED:
		return "NotJoined";
	case PIM_UPSTREAM_JOINED:
		return "Joined";
	}
	return "Unknown";
}

const char *pim_reg_state2str(enum pim_reg_state reg_state, char *state_str,
			      size_t state_str_len)
{
	switch (reg_state) {
	case PIM_REG_NOINFO:
		strlcpy(state_str, "RegNoInfo", state_str_len);
		break;
	case PIM_REG_JOIN:
		strlcpy(state_str, "RegJoined", state_str_len);
		break;
	case PIM_REG_JOIN_PENDING:
		strlcpy(state_str, "RegJoinPend", state_str_len);
		break;
	case PIM_REG_PRUNE:
		strlcpy(state_str, "RegPrune", state_str_len);
		break;
	}
	return state_str;
}

static void pim_upstream_register_stop_timer(struct event *t)
{
	struct pim_interface *pim_ifp;
	struct pim_instance *pim;
	struct pim_upstream *up;
	up = EVENT_ARG(t);
	pim = up->channel_oil->pim;

	if (PIM_DEBUG_PIM_TRACE) {
		char state_str[PIM_REG_STATE_STR_LEN];
		zlog_debug("%s: (S,G)=%s[%s] upstream register stop timer %s",
			   __func__, up->sg_str, pim->vrf->name,
			   pim_reg_state2str(up->reg_state, state_str,
					     sizeof(state_str)));
	}

	switch (up->reg_state) {
	case PIM_REG_JOIN_PENDING:
		up->reg_state = PIM_REG_JOIN;
		pim_channel_add_oif(up->channel_oil, pim->regiface,
				    PIM_OIF_FLAG_PROTO_PIM,
					__func__);
		pim_vxlan_update_sg_reg_state(pim, up, true /*reg_join*/);
		break;
	case PIM_REG_JOIN:
		break;
	case PIM_REG_PRUNE:
		/* This is equalent to Couldreg -> False */
		if (!up->rpf.source_nexthop.interface) {
			if (PIM_DEBUG_PIM_TRACE)
				zlog_debug("%s: up %s RPF is not present",
					   __func__, up->sg_str);
			up->reg_state = PIM_REG_NOINFO;
			PIM_UPSTREAM_FLAG_UNSET_FHR(up->flags);
			return;
		}

		pim_ifp = up->rpf.source_nexthop.interface->info;
		if (!pim_ifp) {
			if (PIM_DEBUG_PIM_TRACE)
				zlog_debug(
					"%s: Interface: %s is not configured for pim",
					__func__,
					up->rpf.source_nexthop.interface->name);
			return;
		}
		up->reg_state = PIM_REG_JOIN_PENDING;
		pim_upstream_start_register_stop_timer(up, 1);

		if (((up->channel_oil->cc.lastused / 100)
		     > pim->keep_alive_time)
		    && (I_am_RP(pim_ifp->pim, up->sg.grp))) {
			if (PIM_DEBUG_PIM_TRACE)
				zlog_debug(
					"%s: Stop sending the register, because I am the RP and we haven't seen a packet in a while",
					__func__);
			return;
		}
		pim_null_register_send(up);
		break;
	case PIM_REG_NOINFO:
		break;
	}
}

void pim_upstream_start_register_stop_timer(struct pim_upstream *up,
					    int null_register)
{
	uint32_t time;

	EVENT_OFF(up->t_rs_timer);

	if (!null_register) {
		uint32_t lower = (0.5 * router->register_suppress_time);
		uint32_t upper = (1.5 * router->register_suppress_time);
		time = lower + (frr_weak_random() % (upper - lower + 1));
		/* Make sure we don't wrap around */
		if (time >= router->register_probe_time)
			time -= router->register_probe_time;
		else
			time = 0;
	} else
		time = router->register_probe_time;

	if (PIM_DEBUG_PIM_TRACE) {
		zlog_debug(
			"%s: (S,G)=%s Starting upstream register stop timer %d",
			__func__, up->sg_str, time);
	}
	event_add_timer(router->master, pim_upstream_register_stop_timer, up,
			time, &up->t_rs_timer);
}

int pim_upstream_inherited_olist_decide(struct pim_instance *pim,
					struct pim_upstream *up)
{
	struct interface *ifp;
	struct pim_ifchannel *ch, *starch;
	struct pim_upstream *starup = up->parent;
	int output_intf = 0;

	if (!up->rpf.source_nexthop.interface)
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: up %s RPF is not present", __func__,
				   up->sg_str);

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp;
		if (!ifp->info)
			continue;

		ch = pim_ifchannel_find(ifp, &up->sg);

		if (starup)
			starch = pim_ifchannel_find(ifp, &starup->sg);
		else
			starch = NULL;

		if (!ch && !starch)
			continue;

		pim_ifp = ifp->info;
		if (PIM_I_am_DualActive(pim_ifp)
		    && PIM_UPSTREAM_FLAG_TEST_MLAG_INTERFACE(up->flags)
		    && (PIM_UPSTREAM_FLAG_TEST_MLAG_NON_DF(up->flags)
			|| !PIM_UPSTREAM_FLAG_TEST_MLAG_PEER(up->flags)))
			continue;
		if (pim_upstream_evaluate_join_desired_interface(up, ch,
								 starch)) {
			int flag = 0;

			if (!ch)
				flag = PIM_OIF_FLAG_PROTO_STAR;
			else {
				if (PIM_IF_FLAG_TEST_PROTO_IGMP(ch->flags))
					flag = PIM_OIF_FLAG_PROTO_GM;
				if (PIM_IF_FLAG_TEST_PROTO_PIM(ch->flags))
					flag |= PIM_OIF_FLAG_PROTO_PIM;
				if (starch)
					flag |= PIM_OIF_FLAG_PROTO_STAR;
			}

			pim_channel_add_oif(up->channel_oil, ifp, flag,
					__func__);
			output_intf++;
		}
	}

	return output_intf;
}

/*
 * For a given upstream, determine the inherited_olist
 * and apply it.
 *
 * inherited_olist(S,G,rpt) =
 *           ( joins(*,*,RP(G)) (+) joins(*,G) (-) prunes(S,G,rpt) )
 *      (+) ( pim_include(*,G) (-) pim_exclude(S,G))
 *      (-) ( lost_assert(*,G) (+) lost_assert(S,G,rpt) )
 *
 *  inherited_olist(S,G) =
 *      inherited_olist(S,G,rpt) (+)
 *      joins(S,G) (+) pim_include(S,G) (-) lost_assert(S,G)
 *
 * return 1 if there are any output interfaces
 * return 0 if there are not any output interfaces
 */
int pim_upstream_inherited_olist(struct pim_instance *pim,
				 struct pim_upstream *up)
{
	int output_intf = pim_upstream_inherited_olist_decide(pim, up);

	/*
	 * If we have output_intf switch state to Join and work like normal
	 * If we don't have an output_intf that means we are probably a
	 * switch on a stick so turn on forwarding to just accept the
	 * incoming packets so we don't bother the other stuff!
	 */
	pim_upstream_update_join_desired(pim, up);

	if (!output_intf)
		forward_on(up);

	return output_intf;
}

int pim_upstream_empty_inherited_olist(struct pim_upstream *up)
{
	return pim_channel_oil_empty(up->channel_oil);
}

/*
 * When we have a new neighbor,
 * find upstreams that don't have their rpf_addr
 * set and see if the new neighbor allows
 * the join to be sent
 */
void pim_upstream_find_new_rpf(struct pim_instance *pim)
{
	struct pim_upstream *up;
	struct pim_rpf old;
	enum pim_rpf_result rpf_result;

	/*
	 * Scan all (S,G) upstreams searching for RPF'(S,G)=neigh_addr
	 */
	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		if (pim_addr_is_any(up->upstream_addr)) {
			if (PIM_DEBUG_PIM_TRACE)
				zlog_debug(
					"%s: RP not configured for Upstream %s",
					__func__, up->sg_str);
			continue;
		}

		if (pim_rpf_addr_is_inaddr_any(&up->rpf)) {
			if (PIM_DEBUG_PIM_TRACE)
				zlog_debug(
					"%s: Upstream %s without a path to send join, checking",
					__func__, up->sg_str);
			old.source_nexthop.interface =
				up->rpf.source_nexthop.interface;
			rpf_result = pim_rpf_update(pim, up, &old, __func__);
			if (rpf_result == PIM_RPF_CHANGED ||
					(rpf_result == PIM_RPF_FAILURE &&
					 old.source_nexthop.interface))
				pim_zebra_upstream_rpf_changed(pim, up, &old);
			/* update kernel multicast forwarding cache (MFC) */
			pim_upstream_mroute_iif_update(up->channel_oil,
					__func__);
		}
	}
	pim_zebra_update_all_interfaces(pim);
}

unsigned int pim_upstream_hash_key(const void *arg)
{
	const struct pim_upstream *up = arg;

	return pim_sgaddr_hash(up->sg, 0);
}

void pim_upstream_terminate(struct pim_instance *pim)
{
	struct pim_upstream *up;

	while ((up = rb_pim_upstream_first(&pim->upstream_head))) {
		if (pim_upstream_del(pim, up, __func__))
			pim_upstream_timers_stop(up);
	}

	rb_pim_upstream_fini(&pim->upstream_head);

	if (pim->upstream_sg_wheel)
		wheel_delete(pim->upstream_sg_wheel);
	pim->upstream_sg_wheel = NULL;
}

bool pim_upstream_equal(const void *arg1, const void *arg2)
{
	const struct pim_upstream *up1 = (const struct pim_upstream *)arg1;
	const struct pim_upstream *up2 = (const struct pim_upstream *)arg2;

	return !pim_sgaddr_cmp(up1->sg, up2->sg);
}

/* rfc4601:section-4.2:"Data Packet Forwarding Rules" defines
 * the cases where kat has to be restarted on rxing traffic -
 *
 * if( DirectlyConnected(S) == true AND iif == RPF_interface(S) ) {
 * set KeepaliveTimer(S,G) to Keepalive_Period
 * # Note: a register state transition or UpstreamJPState(S,G)
 * # transition may happen as a result of restarting
 * # KeepaliveTimer, and must be dealt with here.
 * }
 * if( iif == RPF_interface(S) AND UpstreamJPState(S,G) == Joined AND
 * inherited_olist(S,G) != NULL ) {
 * set KeepaliveTimer(S,G) to Keepalive_Period
 * }
 */
static bool pim_upstream_kat_start_ok(struct pim_upstream *up)
{
	struct channel_oil *c_oil = up->channel_oil;
	struct interface *ifp = up->rpf.source_nexthop.interface;
	struct pim_interface *pim_ifp;
	struct pim_instance *pim = up->channel_oil->pim;

	/* "iif == RPF_interface(S)" check is not easy to do as the info
	 * we get from the kernel/ASIC is really a "lookup/key hit".
	 * So we will do an approximate check here to avoid starting KAT
	 * because of (S,G,rpt) forwarding on a non-LHR.
	 */
	if (!ifp)
		return false;

	pim_ifp = ifp->info;
	if (pim_ifp->mroute_vif_index != *oil_incoming_vif(c_oil))
		return false;

	if (pim_if_connected_to_source(up->rpf.source_nexthop.interface,
				       up->sg.src)) {
		return true;
	}

	if ((up->join_state == PIM_UPSTREAM_JOINED)
	    && !pim_upstream_empty_inherited_olist(up)) {
		if (I_am_RP(pim, up->sg.grp))
			return true;
	}

	return false;
}

static bool pim_upstream_sg_running_proc(struct pim_upstream *up)
{
	bool rv = false;
	struct pim_instance *pim = up->pim;

	if (!up->channel_oil->installed)
		return rv;

	pim_mroute_update_counters(up->channel_oil);

	// Have we seen packets?
	if ((up->channel_oil->cc.oldpktcnt >= up->channel_oil->cc.pktcnt)
	    && (up->channel_oil->cc.lastused / 100 > 30)) {
		if (PIM_DEBUG_PIM_TRACE) {
			zlog_debug(
				"%s[%s]: %s old packet count is equal or lastused is greater than 30, (%ld,%ld,%lld)",
				__func__, up->sg_str, pim->vrf->name,
				up->channel_oil->cc.oldpktcnt,
				up->channel_oil->cc.pktcnt,
				up->channel_oil->cc.lastused / 100);
		}
		return rv;
	}

	if (pim_upstream_kat_start_ok(up)) {
		/* Add a source reference to the stream if
		 * one doesn't already exist */
		if (!PIM_UPSTREAM_FLAG_TEST_SRC_STREAM(up->flags)) {
			if (PIM_DEBUG_PIM_TRACE)
				zlog_debug(
					"source reference created on kat restart %s[%s]",
					up->sg_str, pim->vrf->name);

			pim_upstream_ref(up, PIM_UPSTREAM_FLAG_MASK_SRC_STREAM,
					 __func__);
			PIM_UPSTREAM_FLAG_SET_SRC_STREAM(up->flags);
			pim_upstream_fhr_kat_start(up);
		}
		pim_upstream_keep_alive_timer_start(up, pim->keep_alive_time);
		rv = true;
	} else if (PIM_UPSTREAM_FLAG_TEST_SRC_LHR(up->flags)) {
		pim_upstream_keep_alive_timer_start(up, pim->keep_alive_time);
		rv = true;
	}

	if ((up->sptbit != PIM_UPSTREAM_SPTBIT_TRUE) &&
	    (up->rpf.source_nexthop.interface)) {
		pim_upstream_set_sptbit(up, up->rpf.source_nexthop.interface);
		pim_upstream_update_could_assert(up);
	}

	return rv;
}

/*
 * Code to check and see if we've received packets on a S,G mroute
 * and if so to set the SPT bit appropriately
 */
static void pim_upstream_sg_running(void *arg)
{
	struct pim_upstream *up = (struct pim_upstream *)arg;
	struct pim_instance *pim = up->channel_oil->pim;

	// No packet can have arrived here if this is the case
	if (!up->channel_oil->installed) {
		if (PIM_DEBUG_TRACE)
			zlog_debug("%s: %s[%s] is not installed in mroute",
				   __func__, up->sg_str, pim->vrf->name);
		return;
	}

	/*
	 * This is a bit of a hack
	 * We've noted that we should rescan but
	 * we've missed the window for doing so in
	 * pim_zebra.c for some reason.  I am
	 * only doing this at this point in time
	 * to get us up and working for the moment
	 */
	if (up->channel_oil->oil_inherited_rescan) {
		if (PIM_DEBUG_TRACE)
			zlog_debug(
				"%s: Handling unscanned inherited_olist for %s[%s]",
				__func__, up->sg_str, pim->vrf->name);
		pim_upstream_inherited_olist_decide(pim, up);
		up->channel_oil->oil_inherited_rescan = 0;
	}

	pim_upstream_sg_running_proc(up);
}

void pim_upstream_add_lhr_star_pimreg(struct pim_instance *pim)
{
	struct pim_upstream *up;

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		if (!pim_addr_is_any(up->sg.src))
			continue;

		if (!PIM_UPSTREAM_FLAG_TEST_CAN_BE_LHR(up->flags))
			continue;

		pim_channel_add_oif(up->channel_oil, pim->regiface,
				    PIM_OIF_FLAG_PROTO_GM, __func__);
	}
}

void pim_upstream_spt_prefix_list_update(struct pim_instance *pim,
					 struct prefix_list *pl)
{
	const char *pname = prefix_list_name(pl);

	if (pim->spt.plist && strcmp(pim->spt.plist, pname) == 0) {
		pim_upstream_remove_lhr_star_pimreg(pim, pname);
	}
}

/*
 * nlist -> The new prefix list
 *
 * Per Group Application of pimreg to the OIL
 * If the prefix list tells us DENY then
 * we need to Switchover to SPT immediate
 * so add the pimreg.
 * If the prefix list tells us to ACCEPT than
 * we need to Never do the SPT so remove
 * the interface
 *
 */
void pim_upstream_remove_lhr_star_pimreg(struct pim_instance *pim,
					 const char *nlist)
{
	struct pim_upstream *up;
	struct prefix_list *np;
	struct prefix g;
	enum prefix_list_type apply_new;

	np = prefix_list_lookup(PIM_AFI, nlist);

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		if (!pim_addr_is_any(up->sg.src))
			continue;

		if (!PIM_UPSTREAM_FLAG_TEST_CAN_BE_LHR(up->flags))
			continue;

		if (!nlist) {
			pim_channel_del_oif(up->channel_oil, pim->regiface,
					    PIM_OIF_FLAG_PROTO_GM, __func__);
			continue;
		}
		pim_addr_to_prefix(&g, up->sg.grp);
		apply_new = prefix_list_apply_ext(np, NULL, &g, true);
		if (apply_new == PREFIX_DENY)
			pim_channel_add_oif(up->channel_oil, pim->regiface,
					    PIM_OIF_FLAG_PROTO_GM, __func__);
		else
			pim_channel_del_oif(up->channel_oil, pim->regiface,
					    PIM_OIF_FLAG_PROTO_GM, __func__);
	}
}

void pim_upstream_init(struct pim_instance *pim)
{
	char name[64];

	snprintf(name, sizeof(name), "PIM %s Timer Wheel", pim->vrf->name);
	pim->upstream_sg_wheel =
		wheel_init(router->master, 31000, 100, pim_upstream_hash_key,
			   pim_upstream_sg_running, name);

	rb_pim_upstream_init(&pim->upstream_head);
}
