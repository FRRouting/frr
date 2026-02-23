// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * ospf_bfd.c: OSPF BFD handling routines
 *
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
 */

#include <zebra.h>

#include "command.h"
#include "json.h"
#include "linklist.h"
#include "memory.h"
#include "prefix.h"
#include "frrevent.h"
#include "buffer.h"
#include "stream.h"
#include "zclient.h"
#include "vty.h"
#include "table.h"
#include "bfd.h"
#include "ospfd.h"
#include "ospf_asbr.h"
#include "ospf_lsa.h"
#include "ospf_lsdb.h"
#include "ospf_neighbor.h"
#include "ospf_interface.h"
#include "ospf_nsm.h"
#include "ospf_bfd.h"
#include "ospf_dump.h"
#include "ospf_vty.h"
#include "ospf_quicknbr.h"

DEFINE_MTYPE_STATIC(OSPFD, BFD_CONFIG, "BFD configuration data");
DEFINE_MTYPE_STATIC(OSPFD, OSPF_BFD_SESSION_ENTRY, "OSPF BFD session entry");

static void ospf_bfd_session_change(struct bfd_session_params *bsp,
				    const struct bfd_session_status *bss, void *arg);

struct ospf_bfd_session_entry {
	struct ospf_interface *oi;
	struct in_addr endpoint;
	/* Weak pointer to the current neighbor (may be NULL). */
	struct ospf_neighbor *nbr;
	struct bfd_session_params *bsp;
};

static void ospf_bfd_entry_key(const struct in_addr *endpoint, struct prefix *p)
{
	memset(p, 0, sizeof(*p));
	p->family = AF_INET;
	p->prefixlen = IPV4_MAX_BITLEN;
	p->u.prefix4 = *endpoint;
}

static struct ospf_bfd_session_entry *ospf_bfd_entry_lookup(struct ospf_interface *oi,
							    const struct in_addr *endpoint)
{
	struct prefix key;
	struct route_node *rn;
	struct ospf_bfd_session_entry *entry;

	if (!oi || !oi->bfd_sessions)
		return NULL;

	ospf_bfd_entry_key(endpoint, &key);
	rn = route_node_lookup(oi->bfd_sessions, &key);
	if (!rn)
		return NULL;

	entry = rn->info;
	route_unlock_node(rn);
	return entry;
}

static struct ospf_bfd_session_entry *ospf_bfd_entry_get(struct ospf_interface *oi,
							 const struct in_addr *endpoint)
{
	struct prefix key;
	struct route_node *rn;
	struct ospf_bfd_session_entry *entry;

	if (!oi->bfd_sessions)
		oi->bfd_sessions = route_table_init();

	ospf_bfd_entry_key(endpoint, &key);
	rn = route_node_get(oi->bfd_sessions, &key);

	if (rn->info) {
		route_unlock_node(rn);
		entry = rn->info;
	} else {
		entry = XCALLOC(MTYPE_OSPF_BFD_SESSION_ENTRY, sizeof(*entry));
		entry->oi = oi;
		entry->endpoint = *endpoint;
		rn->info = entry;
	}

	if (!entry->bsp)
		entry->bsp = bfd_sess_new(ospf_bfd_session_change, entry);

	return entry;
}

static void ospf_bfd_entry_del(struct ospf_interface *oi, const struct in_addr *endpoint)
{
	struct prefix key;
	struct route_node *rn;
	struct ospf_bfd_session_entry *entry;

	if (!oi || !oi->bfd_sessions)
		return;

	ospf_bfd_entry_key(endpoint, &key);
	rn = route_node_lookup(oi->bfd_sessions, &key);
	if (!rn)
		return;

	entry = rn->info;
	if (entry) {
		rn->info = NULL;
		if (entry->nbr)
			entry->nbr->bfd_session = NULL;
		bfd_sess_free(&entry->bsp);
		entry->nbr = NULL;
		XFREE(MTYPE_OSPF_BFD_SESSION_ENTRY, entry);
		/* Drop the persistent node lock held while info was set. */
		route_unlock_node(rn);
	}

	/* Drop the lookup lock. */
	route_unlock_node(rn);
}

/*
 * ospf_bfd_trigger_event - Neighbor is registered/deregistered with BFD when
 *                          neighbor state is changed to/from 2way.
 */
void ospf_bfd_trigger_event(struct ospf_neighbor *nbr, int old_state, int state)
{
	struct ospf_interface *oi = nbr->oi;
	struct ospf_if_params *oip = IF_DEF_PARAMS(oi->ifp);

	/* In quick neighbor mode, ignore the neighbor state changes. Just keep the session
	 * installed to allow quick neighbor re-add
	 */
	if (!oip->bfd_config || oip->bfd_config->quick)
		return;

	if ((old_state < NSM_TwoWay) && (state >= NSM_TwoWay))
		bfd_sess_install(nbr->bfd_session);
	else if ((old_state >= NSM_TwoWay) && (state < NSM_TwoWay))
		bfd_sess_uninstall(nbr->bfd_session);
}

static void ospf_bfd_session_change(struct bfd_session_params *bsp,
				    const struct bfd_session_status *bss,
				    void *arg)
{
	struct ospf_bfd_session_entry *entry = arg;
	struct ospf_neighbor *nbr = entry ? entry->nbr : NULL;
	struct ospf_interface *oi = entry ? entry->oi : NULL;
	struct ospf_if_params *oip = oi ? IF_DEF_PARAMS(oi->ifp) : NULL;

	/*
	 * Handle Admin Down from peer separately.
	 * When BFD receives Admin Down from peer, we should NOT tear down
	 * the OSPF neighbor. The peer is administratively shutting down BFD,
	 * but the OSPF adjacency should remain up.
	 */
	if (bss->state == BSS_ADMIN_DOWN && bss->previous_state == BSS_UP) {
		if (IS_DEBUG_OSPF(bfd, BFD_LIB)) {
			if (nbr)
				zlog_debug("%s: NSM[%s:%pI4]: BFD received Admin Down from peer - OSPF adjacency maintained",
					   __func__, IF_NAME(nbr->oi), &nbr->address.u.prefix4);
			else if (oi && entry)
				zlog_debug("%s: NSM[%s:%pI4]: BFD received Admin Down (no neighbor) - OSPF adjacency maintained",
					   __func__, IF_NAME(oi), &entry->endpoint);
		}
		/* Don't tear down OSPF neighbor, just log the event */
		return;
	}

	/* If we don't have a current neighbor pointer, try to find it by endpoint. */
	if (!nbr && oi && entry) {
		nbr = ospf_nbr_lookup_by_addr(oi->nbrs, &entry->endpoint);
		entry->nbr = nbr;
	}

	/* BFD peer went down. */
	if (bss->state == BFD_STATUS_DOWN && bss->previous_state == BFD_STATUS_UP) {
		if (nbr) {
			if (IS_DEBUG_OSPF(bfd, BFD_LIB))
				zlog_debug("%s: NSM[%s:%pI4]: BFD Down", __func__,
					   IF_NAME(nbr->oi), &nbr->address.u.prefix4);
			ospf_nbr_bring_down(nbr);
		} else if (IS_DEBUG_OSPF(bfd, BFD_LIB) && oi && entry) {
			zlog_debug("%s: NSM[%s:%pI4]: BFD Down (no neighbor)", __func__,
				   IF_NAME(oi), &entry->endpoint);
		}
	}

	/* BFD peer went up. */
	if (bss->state == BSS_UP && bss->previous_state == BSS_DOWN) {
		if (IS_DEBUG_OSPF(bfd, BFD_LIB)) {
			if (nbr)
				zlog_debug("%s: NSM[%s:%pI4]: BFD Up", __func__, IF_NAME(nbr->oi),
					   &nbr->address.u.prefix4);
			else if (oi && entry)
				zlog_debug("%s: NSM[%s:%pI4]: BFD Up (no neighbor)", __func__,
					   IF_NAME(oi), &entry->endpoint);
		}

		if (oi && entry && oip && oip->bfd_config && oip->bfd_config->quick)
			ospf_qn_add(oi, &entry->endpoint);
	}
}

void ospf_neighbor_bfd_apply(struct ospf_neighbor *nbr)
{
	struct ospf_interface *oi = nbr->oi;
	struct ospf_if_params *oip = IF_DEF_PARAMS(oi->ifp);
	struct ospf_bfd_session_entry *entry;

	/* BFD configuration was removed. */
	if (oip->bfd_config == NULL) {
		ospf_neighbor_bfd_clear(nbr);
		return;
	}

	entry = ospf_bfd_entry_get(oi, &nbr->src);
	entry->nbr = nbr;
	nbr->bfd_session = entry->bsp;

	/* Pass local interface address as source (like BGP does with su_local) */
	bfd_sess_set_ipv4_addrs(entry->bsp, oi->address ? &oi->address->u.prefix4 : NULL,
				&nbr->src);
	bfd_sess_set_interface(entry->bsp, oi->ifp->name);
	bfd_sess_set_vrf(entry->bsp, oi->ospf->vrf_id);

	/* Set new configuration. */
	bfd_sess_set_timers(entry->bsp, oip->bfd_config->detection_multiplier,
			    oip->bfd_config->min_rx, oip->bfd_config->min_tx);
	bfd_sess_set_profile(entry->bsp, oip->bfd_config->profile);

	/* Don't start sessions on down OSPF sessions.
	 * Quick neighbors can still be added in a down state though
	 */
	if (!oip->bfd_config->quick && nbr->state < NSM_TwoWay)
		return;

	bfd_sess_install(entry->bsp);
}

void ospf_neighbor_bfd_clear(struct ospf_neighbor *nbr)
{
	struct ospf_interface *oi;
	struct ospf_bfd_session_entry *entry;
	struct bfd_session_params *legacy_bsp;
	struct ospf_if_params *oip;

	if (!nbr)
		return;

	oi = nbr->oi;
	oip = (oi && oi->ifp) ? IF_DEF_PARAMS(oi->ifp) : NULL;
	legacy_bsp = nbr->bfd_session;
	nbr->bfd_session = NULL;

	/*
	 * Preferred path: session is interface-owned. If an entry exists, delete it
	 * and do NOT free legacy_bsp (it aliases entry->bsp).
	 */
	entry = (oi ? ospf_bfd_entry_lookup(oi, &nbr->src) : NULL);
	if (entry) {
		/* legacy_bsp aliases entry->bsp; avoid using a stale local pointer. */
		legacy_bsp = NULL;

		/*
		 * Quick-neighbor mode: keep the BFD session installed even if the
		 * neighbor goes away, so BFD can quickly detect it again and we can
		 * re-add via quick neighbor add.
		 *
		 * IMPORTANT: the neighbor object is being freed, so we must drop
		 * the weak pointer.
		 */
		if (oip && oip->bfd_config && oip->bfd_config->quick) {
			entry->nbr = NULL;
			if (entry->bsp)
				bfd_sess_install(entry->bsp);
			return;
		}

		ospf_bfd_entry_del(oi, &nbr->src);
		return;
	}

	/* Legacy/partial-init fallback: free whatever the neighbor owns. */
	bfd_sess_free(&legacy_bsp);
}

void ospf_bfd_if_flush(struct ospf_interface *oi)
{
	struct route_node *rn, *next;

	if (!oi || !oi->bfd_sessions)
		return;

	for (rn = route_top(oi->bfd_sessions); rn; rn = next) {
		struct ospf_bfd_session_entry *entry;

		entry = rn->info;
		next = route_next(rn);

		if (!entry)
			continue;

		rn->info = NULL;
		if (entry->nbr)
			entry->nbr->bfd_session = NULL;
		bfd_sess_free(&entry->bsp);
		entry->nbr = NULL;
		XFREE(MTYPE_OSPF_BFD_SESSION_ENTRY, entry);
		/* Drop the persistent node lock held while info was set. */
		route_unlock_node(rn);
	}
}

static void ospf_bfd_if_prune_nonquick(struct ospf_interface *oi)
{
	struct route_node *rn, *next;

	if (!oi || !oi->bfd_sessions)
		return;

	for (rn = route_top(oi->bfd_sessions); rn; rn = next) {
		struct ospf_bfd_session_entry *entry;

		entry = rn->info;
		next = route_next(rn);

		if (!entry)
			continue;

		/*
		 * Non-quick mode: only keep BFD sessions for neighbors that are
		 * currently up enough for normal OSPF BFD handling (TwoWay+).
		 *
		 * In quick mode we may keep sessions without a neighbor to allow
		 * rapid detection and re-add; once quick is disabled these "orphan"
		 * sessions must be removed.
		 */
		if (!entry->nbr || entry->nbr->state < NSM_TwoWay) {
			rn->info = NULL;
			if (entry->nbr)
				entry->nbr->bfd_session = NULL;
			bfd_sess_free(&entry->bsp);
			entry->nbr = NULL;
			XFREE(MTYPE_OSPF_BFD_SESSION_ENTRY, entry);
			/* Drop the persistent node lock held while info was set. */
			route_unlock_node(rn);
		}
	}
}

static void ospf_interface_bfd_apply(struct interface *ifp)
{
	struct ospf_interface *oi;
	struct route_table *nbrs;
	struct ospf_neighbor *nbr;
	struct route_node *irn;
	struct route_node *nrn;

	/* Iterate over all interfaces and set neighbors BFD session. */
	for (irn = route_top(IF_OIFS(ifp)); irn; irn = route_next(irn)) {
		if ((oi = irn->info) == NULL)
			continue;
		if ((nbrs = oi->nbrs) == NULL)
			continue;
		for (nrn = route_top(nbrs); nrn; nrn = route_next(nrn)) {
			if ((nbr = nrn->info) == NULL || nbr == oi->nbr_self)
				continue;

			ospf_neighbor_bfd_apply(nbr);
		}
	}
}

static void ospf_interface_enable_bfd(struct interface *ifp, bool quick)
{
	struct ospf_if_params *oip = IF_DEF_PARAMS(ifp);
	bool old_quick = false;

	if (!oip->bfd_config) {
		/* Allocate memory for configurations and set defaults. */
		oip->bfd_config = XCALLOC(MTYPE_BFD_CONFIG, sizeof(*oip->bfd_config));
		oip->bfd_config->detection_multiplier = BFD_DEF_DETECT_MULT;
		oip->bfd_config->min_rx = BFD_DEF_MIN_RX;
		oip->bfd_config->min_tx = BFD_DEF_MIN_TX;
	} else
		old_quick = oip->bfd_config->quick;

	oip->bfd_config->quick = quick;

	/* Remove any down sessions kept alive for quick mode if quick
	 * mode is being disabled.
	 */
	if (old_quick && !quick) {
		struct route_node *rn;

		for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
			struct ospf_interface *oi = rn->info;

			if (!oi)
				continue;
			ospf_bfd_if_prune_nonquick(oi);
		}

		/* Re-apply BFD configuration so non-quick gating takes effect immediately. */
		ospf_interface_bfd_apply(ifp);
	}
}

void ospf_interface_disable_bfd(struct interface *ifp,
				struct ospf_if_params *oip)
{
	XFREE(MTYPE_BFD_CONFIG, oip->bfd_config);
	ospf_interface_bfd_apply(ifp);
	/* Ensure any interface-owned entries are removed too. */
	{
		struct route_node *rn;

		for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
			struct ospf_interface *oi = rn->info;

			if (!oi)
				continue;
			ospf_bfd_if_flush(oi);
		}
	}
}

/*
 * ospf_bfd_write_config - Write the interface BFD configuration.
 */
void ospf_bfd_write_config(struct vty *vty, const struct ospf_if_params *params
			   __attribute__((unused)))
{
#if HAVE_BFDD == 0
	if (params->bfd_config->detection_multiplier != BFD_DEF_DETECT_MULT
	    || params->bfd_config->min_rx != BFD_DEF_MIN_RX
	    || params->bfd_config->min_tx != BFD_DEF_MIN_TX)
		vty_out(vty, " ip ospf bfd %d %d %d%s\n", params->bfd_config->detection_multiplier,
			params->bfd_config->min_rx, params->bfd_config->min_tx,
			(params->bfd_config->quick ? " quick" : ""));
	else
#endif /* ! HAVE_BFDD */
		vty_out(vty, " ip ospf bfd%s\n", (params->bfd_config->quick ? " quick" : ""));

	if (params->bfd_config->profile[0])
		vty_out(vty, " ip ospf bfd profile %s\n",
			params->bfd_config->profile);
}

void ospf_interface_bfd_show(struct vty *vty, const struct interface *ifp,
			     struct json_object *json)
{
	struct ospf_if_params *params = IF_DEF_PARAMS(ifp);
	struct bfd_configuration *bfd_config = params->bfd_config;
	struct json_object *json_bfd;

	if (bfd_config == NULL)
		return;

	if (json) {
		json_bfd = json_object_new_object();
		json_object_int_add(json_bfd, "detectionMultiplier",
				    bfd_config->detection_multiplier);
		json_object_int_add(json_bfd, "rxMinInterval",
				    bfd_config->min_rx);
		json_object_int_add(json_bfd, "txMinInterval",
				    bfd_config->min_tx);
		json_object_object_add(json, "peerBfdInfo", json_bfd);
	} else
		vty_out(vty,
			"  BFD: Detect Multiplier: %d, Min Rx interval: %d, Min Tx interval: %d\n",
			bfd_config->detection_multiplier, bfd_config->min_rx,
			bfd_config->min_tx);
}

DEFUN (ip_ospf_bfd,
       ip_ospf_bfd_cmd,
       "ip ospf bfd [quick]",
       "IP Information\n"
       "OSPF interface commands\n"
       "Enables BFD support\n"
       "Quick neighbor establishment mode\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	ospf_interface_enable_bfd(ifp, argc >= 4);
	ospf_interface_bfd_apply(ifp);
	return CMD_SUCCESS;
}

#if HAVE_BFDD > 0
DEFUN_HIDDEN(
#else
DEFUN(
#endif /* HAVE_BFDD */
       ip_ospf_bfd_param,
       ip_ospf_bfd_param_cmd,
       "ip ospf bfd (2-255) (50-60000) (50-60000) [quick]",
       "IP Information\n"
       "OSPF interface commands\n"
       "Enables BFD support\n"
       "Detect Multiplier\n"
       "Required min receive interval\n"
       "Desired min transmit interval\n"
       "Quick neighbor establishment mode\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 5;

	ospf_interface_enable_bfd(ifp, argc >= 7);

	params = IF_DEF_PARAMS(ifp);
	params->bfd_config->detection_multiplier =
		strtol(argv[idx_number]->arg, NULL, 10);
	params->bfd_config->min_rx = strtol(argv[idx_number_2]->arg, NULL, 10);
	params->bfd_config->min_tx = strtol(argv[idx_number_3]->arg, NULL, 10);

	ospf_interface_bfd_apply(ifp);

	return CMD_SUCCESS;
}

DEFUN (ip_ospf_bfd_prof,
       ip_ospf_bfd_prof_cmd,
       "ip ospf bfd profile BFDPROF",
       "IP Information\n"
       "OSPF interface commands\n"
       "Enables BFD support\n"
       BFD_PROFILE_STR
       BFD_PROFILE_NAME_STR)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;
	int idx_prof = 4;

	params = IF_DEF_PARAMS(ifp);
	if (!params->bfd_config) {
		vty_out(vty, "ip ospf bfd has not been set\n");
		return CMD_WARNING;
	}

	strlcpy(params->bfd_config->profile, argv[idx_prof]->arg,
		sizeof(params->bfd_config->profile));
	ospf_interface_bfd_apply(ifp);

	return CMD_SUCCESS;
}

DEFUN (no_ip_ospf_bfd_prof,
       no_ip_ospf_bfd_prof_cmd,
       "no ip ospf bfd profile [BFDPROF]",
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Enables BFD support\n"
       BFD_PROFILE_STR
       BFD_PROFILE_NAME_STR)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;

	params = IF_DEF_PARAMS(ifp);
	if (!params->bfd_config)
		return CMD_SUCCESS;

	params->bfd_config->profile[0] = 0;
	ospf_interface_bfd_apply(ifp);

	return CMD_SUCCESS;
}

DEFUN (no_ip_ospf_bfd,
       no_ip_ospf_bfd_cmd,
#if HAVE_BFDD > 0
       "no ip ospf bfd [quick]",
#else
       "no ip ospf bfd [(2-255) (50-60000) (50-60000)] [quick]",
#endif /* HAVE_BFDD */
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Disables BFD support\n"
#if HAVE_BFDD == 0
       "Detect Multiplier\n"
       "Required min receive interval\n"
       "Desired min transmit interval\n"
#endif /* !HAVE_BFDD */
       "Quick neighbor establishment mode\n"
)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	ospf_interface_disable_bfd(ifp, IF_DEF_PARAMS(ifp));
	return CMD_SUCCESS;
}

void ospf_bfd_init(struct event_loop *tm)
{
	bfd_protocol_integration_init(ospf_zclient, tm);

	/* Install BFD command */
	install_element(INTERFACE_NODE, &ip_ospf_bfd_cmd);
	install_element(INTERFACE_NODE, &ip_ospf_bfd_param_cmd);
	install_element(INTERFACE_NODE, &ip_ospf_bfd_prof_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_bfd_prof_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_bfd_cmd);
}
