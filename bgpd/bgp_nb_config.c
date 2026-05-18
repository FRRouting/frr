// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * bgpd northbound — callback implementations.
 *
 * One function per (xpath, callback-kind) pair. All event branches
 * (NB_EV_VALIDATE / NB_EV_PREPARE / NB_EV_APPLY / NB_EV_ABORT) are
 * handled — most do real work only in NB_EV_APPLY.
 *
 * See BGPD_NB_MIGRATION_PLAN.md §3.1 for the canonical worked example
 * and FRRouting/frr#5428 for the migration tracking issue.
 */

#include <zebra.h>

#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/yang.h"
#include "lib/yang_wrappers.h"
#include "lib/vrf.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_bfd.h"
#include "bgpd/bgp_conditional_adv.h"
#include "bgpd/bgp_ls.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_zebra.h"

/* ------------------------------------------------------------------------ */
/* Phase 2.0 — control-plane-protocol context (frr-bgp:bgp container)        */
/* ------------------------------------------------------------------------ */

/*
 * Map a YANG vrf key value ("default" or a vrf name) to the bgp instance
 * name expected by bgp_get()/bgp_lookup_by_name(), which is NULL for the
 * default vrf.
 */
static const char *bgp_nb_vrf_to_name(const char *vrf_key)
{
	if (!vrf_key || strmatch(vrf_key, VRF_DEFAULT_NAME))
		return NULL;
	return vrf_key;
}

/*
 * Map the YANG vrf key to a bgp_instance_type. View instances are signalled
 * via a separate `instance-type-view` leaf (handled separately); here we
 * default to VRF when vrf != "default", DEFAULT otherwise. View detection
 * is added when that leaf's callback lands.
 */
static enum bgp_instance_type bgp_nb_inst_type(const char *vrf_key)
{
	if (!vrf_key || strmatch(vrf_key, VRF_DEFAULT_NAME))
		return BGP_INSTANCE_TYPE_DEFAULT;
	return BGP_INSTANCE_TYPE_VRF;
}

/*
 * Look up the bgp instance owning a given dnode by walking up to the
 * control-plane-protocol list entry and reading its `vrf` key.
 *
 * Returns NULL if no instance exists for that vrf yet. Callers in modify
 * callbacks should treat NULL as NB_ERR (the parent CREATE should have
 * already run; if it didn't, the schema/lifecycle is broken).
 *
 * `depth` is the number of `../` hops from `dnode` to the
 * control-plane-protocol entry. Examples:
 *   - `bgp` container          -> 1 (`../`)
 *   - `bgp/global`             -> 2 (`../../`)
 *   - `bgp/global/<leaf>`      -> 3 (`../../../`)
 *   - `bgp/global/<container>/<leaf>` -> 4
 */
static struct bgp *bgp_nb_lookup_from_dnode(const struct lyd_node *dnode,
					    unsigned int depth_to_cpp)
{
	char vrf_xpath[64];
	const char *vrf_key;

	/* Build "../" * depth + "vrf". */
	vrf_xpath[0] = '\0';
	for (unsigned int i = 0; i < depth_to_cpp; i++)
		strlcat(vrf_xpath, "../", sizeof(vrf_xpath));
	strlcat(vrf_xpath, "vrf", sizeof(vrf_xpath));

	vrf_key = yang_dnode_get_string(dnode, vrf_xpath);
	return bgp_lookup_by_name(bgp_nb_vrf_to_name(vrf_key));
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp
 *
 * Triggered when a YANG client creates the bgp presence container. Wraps
 * bgp_get() so the struct bgp lifecycle is identical to what the legacy
 * DEFUN(router_bgp) sets up. Idempotent: if the instance already exists
 * (e.g. created earlier via legacy CLI), associates the existing pointer
 * with the dnode and returns NB_OK.
 *
 * Phase 2.0 scope: handles the default and per-VRF cases. View instances
 * (`instance-type-view = true`) are not yet supported — returns
 * NB_ERR_VALIDATION when that leaf is set. Phase 2 follow-up wires the
 * view-type leaf into bgp_get()'s BGP_INSTANCE_TYPE_VIEW path.
 */
int bgp_router_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const char *vrf_key;
	as_t as;
	const char *bgp_name;
	enum bgp_instance_type inst_type;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/*
		 * Reject view-type instances during Phase 2.0 — we don't
		 * yet plumb the BGP_INSTANCE_TYPE_VIEW path through NB.
		 * Detect it via the optional instance-type-view leaf.
		 */
		if (yang_dnode_exists(args->dnode, "global/instance-type-view")
		    && yang_dnode_get_bool(args->dnode,
					    "global/instance-type-view")) {
			snprintf(args->errmsg, args->errmsg_len,
				 "view instances not yet supported via NB; "
				 "use vtysh `router bgp ASN view NAME`");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;

	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;

	case NB_EV_APPLY:
		break;
	}

	vrf_key = yang_dnode_get_string(args->dnode, "../vrf");
	bgp_name = bgp_nb_vrf_to_name(vrf_key);
	inst_type = bgp_nb_inst_type(vrf_key);

	/*
	 * If the instance already exists (legacy DEFUN(router_bgp) ran
	 * earlier, or a sibling NB write created it during this transaction),
	 * just associate the existing pointer with this dnode and we're done.
	 *
	 * This is the common path for vtysh-driven leaf writes: the user has
	 * already typed `router bgp ASN`, so the struct bgp is in place and
	 * `local-as` isn't part of this transaction's dnode tree.
	 */
	bgp = bgp_lookup_by_name(bgp_name);
	if (bgp) {
		nb_running_set_entry(args->dnode, bgp);
		return NB_OK;
	}

	/*
	 * Fresh creation path (mgmtd/NETCONF/gRPC). local-as is mandatory in
	 * YANG so the client must provide it as part of the same transaction.
	 */
	if (!yang_dnode_exists(args->dnode, "global/local-as")) {
		snprintf(args->errmsg, args->errmsg_len,
			 "local-as is mandatory when creating a new BGP instance via NB");
		return NB_ERR_VALIDATION;
	}
	as = (as_t)yang_dnode_get_uint32(args->dnode, "global/local-as");

	ret = bgp_get(&bgp, &as, bgp_name, inst_type, NULL,
		      ASNOTATION_UNDEFINED);
	if (ret < 0 || !bgp) {
		snprintf(args->errmsg, args->errmsg_len,
			 "bgp_get() failed for AS %u vrf %s (ret %d)", as,
			 vrf_key, ret);
		return NB_ERR;
	}

	nb_running_set_entry(args->dnode, bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp
 */
int bgp_router_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = nb_running_unset_entry(args->dnode);
	if (!bgp) {
		/*
		 * Possible if the bgp instance was created via legacy DEFUN
		 * and never associated with this dnode. Fall back to a vrf
		 * lookup so the destroy still succeeds.
		 */
		bgp = bgp_nb_lookup_from_dnode(args->dnode, 1);
		if (!bgp)
			return NB_OK; /* nothing to do */
	}

	bgp_delete(bgp);
	return NB_OK;
}

/* ------------------------------------------------------------------------ */
/* Phase 2 — global leaves                                                   */
/* ------------------------------------------------------------------------ */

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/router-id
 *
 * The leaf type is yang:dotted-quad (RFC 6991). The internal setter
 * `bgp_router_id_static_set()` triggers session-state side effects, so
 * we run it only in NB_EV_APPLY.
 */
int bgp_global_router_id_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct in_addr router_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	/* router-id leaf -> 3 hops to control-plane-protocol entry. */
	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp) {
		snprintf(args->errmsg, args->errmsg_len,
			 "bgp instance not found for router-id modify");
		return NB_ERR;
	}

	yang_dnode_get_ipv4(&router_id, args->dnode, NULL);
	bgp_router_id_static_set(bgp, router_id);
	return NB_OK;
}

int bgp_global_router_id_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct in_addr zero;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK; /* parent destroy will follow */

	zero.s_addr = INADDR_ANY;
	bgp_router_id_static_set(bgp, zero);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/default-shutdown
 *
 * Maps directly to bgp->autoshutdown. YANG default false matches the
 * internal default (autoshutdown=0 at init time).
 */
int bgp_global_default_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	bgp->autoshutdown = yang_dnode_get_bool(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_default_shutdown_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp->autoshutdown = false;
	return NB_OK;
}

/*
 * Boolean flag-toggle template: a leaf maps directly to one bit in
 * `bgp->flags`. `value=true` sets the flag, anything else clears it,
 * and the destroy callback clears it. Used by show-hostname and
 * show-nexthop-hostname (and any future leaf with identical semantics).
 */
static int bgp_global_flag_toggle_modify(struct nb_cb_modify_args *args,
					  uint64_t flag, unsigned int depth)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, depth);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, flag);
	else
		UNSET_FLAG(bgp->flags, flag);
	return NB_OK;
}

static int bgp_global_flag_toggle_destroy(struct nb_cb_destroy_args *args,
					   uint64_t flag, unsigned int depth)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, depth);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, flag);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/show-hostname
 *
 * YANG default false matches the absent-flag default in bgp->flags.
 */
int bgp_global_show_hostname_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args, BGP_FLAG_SHOW_HOSTNAME, 3);
}

int bgp_global_show_hostname_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(args, BGP_FLAG_SHOW_HOSTNAME, 3);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/show-nexthop-hostname
 */
int bgp_global_show_nexthop_hostname_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args,
					     BGP_FLAG_SHOW_NEXTHOP_HOSTNAME,
					     3);
}

int bgp_global_show_nexthop_hostname_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(args,
					      BGP_FLAG_SHOW_NEXTHOP_HOSTNAME,
					      3);
}

/*
 * Boolean flag-toggle with bestpath recompute side-effect. Same shape as
 * `bgp_global_flag_toggle_modify` but also calls
 * `bgp_recalculate_all_bestpaths()` after the flag change. Used by every
 * leaf under `route-selection-options/*` (which all influence bestpath).
 */
static int bgp_global_flag_bestpath_modify(struct nb_cb_modify_args *args,
					    uint64_t flag, unsigned int depth)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, depth);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, flag);
	else
		UNSET_FLAG(bgp->flags, flag);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

static int bgp_global_flag_bestpath_destroy(struct nb_cb_destroy_args *args,
					     uint64_t flag, unsigned int depth)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, depth);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, flag);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/route-selection-options/always-compare-med
 *
 * Depth 4 (extra hop through route-selection-options container).
 */
int bgp_global_always_compare_med_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args,
					       BGP_FLAG_ALWAYS_COMPARE_MED,
					       4);
}

int bgp_global_always_compare_med_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args,
						BGP_FLAG_ALWAYS_COMPARE_MED,
						4);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/route-selection-options/external-compare-router-id
 *
 * (yang leaf `external-compare-router-id` <-> CLI `bgp bestpath compare-routerid`)
 */
int bgp_global_external_compare_router_id_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args, BGP_FLAG_COMPARE_ROUTER_ID,
					       4);
}

int bgp_global_external_compare_router_id_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args,
						BGP_FLAG_COMPARE_ROUTER_ID,
						4);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/route-selection-options/ignore-as-path-length
 *
 * (yang leaf `ignore-as-path-length` <-> CLI `bgp bestpath as-path ignore`)
 */
int bgp_global_ignore_as_path_length_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args, BGP_FLAG_ASPATH_IGNORE, 4);
}

int bgp_global_ignore_as_path_length_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args, BGP_FLAG_ASPATH_IGNORE,
						4);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/route-selection-options/aspath-confed
 *
 * (yang leaf `aspath-confed` <-> CLI `bgp bestpath as-path confed`)
 */
int bgp_global_aspath_confed_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args, BGP_FLAG_ASPATH_CONFED, 4);
}

int bgp_global_aspath_confed_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args, BGP_FLAG_ASPATH_CONFED,
						4);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/route-selection-options/confed-med
 */
int bgp_global_confed_med_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args, BGP_FLAG_MED_CONFED, 4);
}

int bgp_global_confed_med_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args, BGP_FLAG_MED_CONFED, 4);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/route-selection-options/missing-as-worst-med
 */
int bgp_global_missing_as_worst_med_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args,
					       BGP_FLAG_MED_MISSING_AS_WORST,
					       4);
}

int bgp_global_missing_as_worst_med_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args,
						BGP_FLAG_MED_MISSING_AS_WORST,
						4);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/global-neighbor-config/log-neighbor-changes
 *
 * Depth 4 (extra hop through global-neighbor-config). Pure flag toggle.
 */
int bgp_global_log_neighbor_changes_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args,
					     BGP_FLAG_LOG_NEIGHBOR_CHANGES, 4);
}

int bgp_global_log_neighbor_changes_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(args,
					      BGP_FLAG_LOG_NEIGHBOR_CHANGES, 4);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/import-check
 *
 * Depth 3. Side effect: calls bgp_static_redo_import_check() which is
 * idempotent — safe to invoke on every APPLY whether or not the flag
 * actually changed.
 */
int bgp_global_import_check_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);
	bgp_static_redo_import_check(bgp);
	return NB_OK;
}

int bgp_global_import_check_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);
	bgp_static_redo_import_check(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/global-neighbor-config/packet-quanta-config/wpkt-quanta
 *
 * Depth 5 (global > global-neighbor-config > packet-quanta-config > leaf).
 * Uses atomic store because the value is read from a writer thread.
 */
int bgp_global_wpkt_quanta_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint32_t quanta;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 5);
	if (!bgp)
		return NB_ERR;

	quanta = yang_dnode_get_uint32(args->dnode, NULL);
	atomic_store_explicit(&bgp->wpkt_quanta, quanta, memory_order_relaxed);
	return NB_OK;
}

int bgp_global_wpkt_quanta_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 5);
	if (!bgp)
		return NB_OK;

	atomic_store_explicit(&bgp->wpkt_quanta, BGP_WRITE_PACKET_MAX,
			      memory_order_relaxed);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/global-neighbor-config/packet-quanta-config/rpkt-quanta
 */
int bgp_global_rpkt_quanta_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint32_t quanta;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 5);
	if (!bgp)
		return NB_ERR;

	quanta = yang_dnode_get_uint32(args->dnode, NULL);
	atomic_store_explicit(&bgp->rpkt_quanta, quanta, memory_order_relaxed);
	return NB_OK;
}

int bgp_global_rpkt_quanta_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 5);
	if (!bgp)
		return NB_OK;

	atomic_store_explicit(&bgp->rpkt_quanta, BGP_READ_PACKET_MAX,
			      memory_order_relaxed);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/global-update-group-config/coalesce-time
 *
 * Setting this leaf disables the heuristic auto-coalesce (mirrors the
 * legacy DEFUN behaviour). Destroy re-enables heuristic mode and restores
 * the BGP_DEFAULT_SUBGROUP_COALESCE_TIME baseline.
 */
int bgp_global_coalesce_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->heuristic_coalesce = false;
	bgp->coalesce_time = yang_dnode_get_uint32(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_coalesce_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->heuristic_coalesce = true;
	bgp->coalesce_time = BGP_DEFAULT_SUBGROUP_COALESCE_TIME;
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/global-update-group-config/subgroup-pkt-queue-size
 */
int bgp_global_subgroup_pkt_queue_size_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp_default_subgroup_pkt_queue_max_set(
		bgp, yang_dnode_get_uint32(args->dnode, NULL));
	return NB_OK;
}

int bgp_global_subgroup_pkt_queue_size_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp_default_subgroup_pkt_queue_max_unset(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/confederation/identifier
 *
 * Depth 4 (../../../vrf from /confederation/identifier).
 * bgp_confederation_id_set wants both the as_t and a textual form for
 * as-dot rendering; we synthesise the textual form with snprintf.
 */
int bgp_global_confederation_identifier_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	as_t as;
	char as_str[16];

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	as = (as_t)yang_dnode_get_uint32(args->dnode, NULL);
	snprintf(as_str, sizeof(as_str), "%u", as);
	bgp_confederation_id_set(bgp, as, as_str);
	return NB_OK;
}

int bgp_global_confederation_identifier_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp_confederation_id_unset(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/confederation/member-as  (leaf-list)
 *
 * Depth from leaf-list entry to CPP = 4. Each entry is one AS number.
 */
int bgp_global_confederation_member_as_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	as_t as;
	char as_buf[16];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	as = (as_t)yang_dnode_get_uint32(args->dnode, NULL);
	snprintf(as_buf, sizeof(as_buf), "%u", as);
	bgp_confederation_peers_add(bgp, as, as_buf);
	return NB_OK;
}

int bgp_global_confederation_member_as_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	as_t as;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	as = (as_t)yang_dnode_get_uint32(args->dnode, NULL);
	bgp_confederation_peers_remove(bgp, as);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/minimum-holdtime
 *
 * Depth 3. Direct assignment to bgp->default_min_holdtime; no side effects.
 * Default on destroy: 0 (no minimum).
 */
int bgp_global_minimum_holdtime_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	bgp->default_min_holdtime = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_minimum_holdtime_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp->default_min_holdtime = 0;
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/allow-martian-nexthop
 */
int bgp_global_allow_martian_nexthop_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	bgp->allow_martian = yang_dnode_get_bool(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_allow_martian_nexthop_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp->allow_martian = false;
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/use-underlays-nexthop-weight
 *
 * Maps to BGP_FLAG_USE_RECURSIVE_WEIGHT — when set, BGP propagates the
 * underlay nexthop weight up to Zebra during recursive nexthop resolution.
 */
int bgp_global_use_underlays_nexthop_weight_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args,
					     BGP_FLAG_USE_RECURSIVE_WEIGHT, 3);
}

int bgp_global_use_underlays_nexthop_weight_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(args,
					      BGP_FLAG_USE_RECURSIVE_WEIGHT, 3);
}

/*
 * XPath:
 *   .../bgp/global/route-reflector/allow-outbound-policy
 *
 * Depth 4 (route-reflector container hop). Side effects:
 * `update_group_announce_rrclients` (regenerates rr-client updates) +
 * vty-less soft-out clear.
 */
int bgp_global_route_reflector_allow_outbound_policy_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
	update_group_announce_rrclients(bgp);
	bgp_clear_star_soft_out_quiet(bgp);
	return NB_OK;
}

int bgp_global_route_reflector_allow_outbound_policy_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
	update_group_announce_rrclients(bgp);
	bgp_clear_star_soft_out_quiet(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/bgp-ls-distribute  (presence container)
 *
 * Presence-container creation enables BGP-LS topology distribution.
 * Destroy disables and withdraws all NLRIs.
 */
int bgp_global_bgp_ls_distribute_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	if (!bgp->ls_info) {
		snprintf(args->errmsg, args->errmsg_len,
			 "BGP-LS not initialized for this instance");
		return NB_ERR;
	}

	/*
	 * instance-id (if present) is handled by its own modify callback, so
	 * here we only flip the enable bit and trigger an export. If the
	 * client writes instance-id in the same transaction the export will
	 * be re-done with the new value after modify runs.
	 */
	bgp->ls_info->enable_distribution = true;
	(void)bgp_ls_export_bgp_topology(bgp);
	return NB_OK;
}

int bgp_global_bgp_ls_distribute_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp || !bgp->ls_info)
		return NB_OK;

	bgp_ls_withdraw_all(bgp);
	bgp->ls_info->enable_distribution = false;
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/bgp-ls-distribute/instance-id
 *
 * Depth 4. If distribution is already enabled and the instance-id changes,
 * withdraw existing NLRIs then re-export with the new id.
 */
int bgp_global_bgp_ls_distribute_instance_id_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint64_t new_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp || !bgp->ls_info)
		return NB_ERR;

	new_id = yang_dnode_get_uint64(args->dnode, NULL);
	if (bgp->ls_info->enable_distribution &&
	    bgp->ls_info->instance_id != new_id)
		bgp_ls_withdraw_all(bgp);

	bgp->ls_info->instance_id = new_id;
	if (bgp->ls_info->enable_distribution)
		(void)bgp_ls_export_bgp_topology(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/route-selection-options/bestpath-aigp
 */
int bgp_global_bestpath_aigp_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args, BGP_FLAG_COMPARE_AIGP, 4);
}

int bgp_global_bestpath_aigp_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args, BGP_FLAG_COMPARE_AIGP, 4);
}

/*
 * XPath:
 *   .../bgp/global/route-selection-options/bestpath-use-imported-attributes
 */
int bgp_global_bestpath_use_imported_attributes_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args,
				BGP_FLAG_BESTPATH_USE_IMPORTED_ATTRS, 4);
}

int bgp_global_bestpath_use_imported_attributes_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args,
				BGP_FLAG_BESTPATH_USE_IMPORTED_ATTRS, 4);
}

/*
 * XPath:
 *   .../bgp/global/global-neighbor-config/dynamic-neighbors-limit
 *
 * Depth 4. Per `bgp_listen_limit_set` signature, limit is `int`.
 */
int bgp_global_dynamic_neighbors_limit_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp_listen_limit_set(bgp,
			     (int)yang_dnode_get_uint32(args->dnode, NULL));
	return NB_OK;
}

int bgp_global_dynamic_neighbors_limit_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp_listen_limit_unset(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/med-config  (container)
 *
 * `bgp max-med administrative [VALUE]` and `bgp max-med on-startup TIME [VALUE]`
 * set 4 related fields on bgp atomically (v_maxmed_admin, maxmed_admin_value,
 * v_maxmed_onstartup, maxmed_onstartup_value). YANG models them as separate
 * leaves; we collect them with an `apply_finish` callback on the container
 * and call `bgp_maxmed_update(bgp)` once.
 *
 * Destroy clears admin/onstartup and resets values to defaults.
 */
int bgp_global_med_config_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	bgp->v_maxmed_admin = yang_dnode_exists(args->dnode,
						 "enable-med-admin")
		? (yang_dnode_get_bool(args->dnode, "enable-med-admin") ? 1 : 0)
		: BGP_MAXMED_ADMIN_UNCONFIGURED;
	bgp->maxmed_admin_value = yang_dnode_exists(args->dnode,
						     "max-med-admin")
		? yang_dnode_get_uint32(args->dnode, "max-med-admin")
		: BGP_MAXMED_VALUE_DEFAULT;
	bgp->v_maxmed_onstartup = yang_dnode_exists(args->dnode,
						     "max-med-onstart-up-time")
		? yang_dnode_get_uint32(args->dnode, "max-med-onstart-up-time")
		: BGP_MAXMED_ONSTARTUP_UNCONFIGURED;
	bgp->maxmed_onstartup_value = yang_dnode_exists(
		args->dnode, "max-med-onstart-up-value")
		? yang_dnode_get_uint32(args->dnode, "max-med-onstart-up-value")
		: BGP_MAXMED_VALUE_DEFAULT;

	bgp_maxmed_update(bgp);
	return NB_OK;
}

int bgp_global_med_config_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp->v_maxmed_admin = BGP_MAXMED_ADMIN_UNCONFIGURED;
	bgp->maxmed_admin_value = BGP_MAXMED_VALUE_DEFAULT;
	if (bgp->t_maxmed_onstartup) {
		event_cancel(&bgp->t_maxmed_onstartup);
		bgp->maxmed_onstartup_over = 1;
	}
	bgp->v_maxmed_onstartup = BGP_MAXMED_ONSTARTUP_UNCONFIGURED;
	bgp->maxmed_onstartup_value = BGP_MAXMED_VALUE_DEFAULT;
	bgp_maxmed_update(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/default-software-version-capability
 *
 * The YANG enum maps to two mutually-exclusive flag bits in bgp->flags:
 *   "disabled"  -> clear both
 *   "old"       -> set BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD
 *   "new"       -> set BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW
 *
 * NOTE: bgpd.h:760 has `BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW (1ULL << 45)`
 * colliding with `BGP_FLAG_BESTPATH_USE_IMPORTED_ATTRS (1ULL << 45)` at
 * line 766. This is a pre-existing bgpd bug — out of scope to fix here.
 * The callback uses the macros as defined; semantics on the collision
 * follow whatever the bgpd code already does.
 */
int bgp_global_default_software_version_capability_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *value;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	UNSET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD);
	UNSET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW);

	value = yang_dnode_get_string(args->dnode, NULL);
	if (strmatch(value, "old"))
		SET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD);
	else if (strmatch(value, "new"))
		SET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW);
	return NB_OK;
}

int bgp_global_default_software_version_capability_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD);
	UNSET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/tcp-keepalive  (presence container)
 *
 * apply_finish reads the three child leaves and calls
 * bgp_tcp_keepalive_set() atomically. Destroy calls _unset.
 */
int bgp_global_tcp_keepalive_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	bgp_tcp_keepalive_set(bgp,
			      yang_dnode_get_uint16(args->dnode, "idle"),
			      yang_dnode_get_uint16(args->dnode, "interval"),
			      (uint16_t)yang_dnode_get_uint8(args->dnode,
							      "probes"));
	return NB_OK;
}

int bgp_global_tcp_keepalive_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp_tcp_keepalive_unset(bgp);
	return NB_OK;
}

/*
 * `timers bgp KEEPALIVE HOLDTIME` legacy DEFUN calls bgp_timers_set with
 * all 4 params (keepalive, holdtime, connect_retry, delayopen). YANG has
 * leaves hold-time, keepalive, connect-retry-interval as direct children
 * of global. Per-leaf modify callback reads all sibling leaves (or uses
 * defaults) and calls the setter. Bit wasteful when 2 leaves change in
 * the same transaction (setter runs twice) but correct in all cases.
 */
static int bgp_global_timers_apply(const struct lyd_node *dnode)
{
	struct bgp *bgp;
	uint32_t keepalive = DFLT_BGP_KEEPALIVE;
	uint32_t holdtime = DFLT_BGP_HOLDTIME;
	uint32_t connect_retry = DFLT_BGP_CONNECT_RETRY;

	bgp = bgp_nb_lookup_from_dnode(dnode, 3);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_exists(dnode, "../keepalive"))
		keepalive = yang_dnode_get_uint16(dnode, "../keepalive");
	if (yang_dnode_exists(dnode, "../hold-time"))
		holdtime = yang_dnode_get_uint16(dnode, "../hold-time");
	if (yang_dnode_exists(dnode,
			      "../global-config-timers/connect-retry-interval"))
		connect_retry = yang_dnode_get_uint16(
			dnode,
			"../global-config-timers/connect-retry-interval");

	bgp_timers_set(NULL, bgp, keepalive, holdtime, connect_retry,
		       BGP_DEFAULT_DELAYOPEN);
	return NB_OK;
}

int bgp_global_hold_time_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_global_timers_apply(args->dnode);
}

int bgp_global_hold_time_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_global_timers_apply(args->dnode);
}

int bgp_global_keepalive_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_global_timers_apply(args->dnode);
}

int bgp_global_keepalive_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_global_timers_apply(args->dnode);
}

/*
 * XPath:
 *   .../bgp/global/reject-as-sets
 *
 * Toggles bgp->reject_as_sets and resets all peers so the new policy
 * takes effect on re-establish. Direct field, not a flag bit.
 */
int bgp_global_reject_as_sets_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node, *nnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	bgp->reject_as_sets = yang_dnode_get_bool(args->dnode, NULL);
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		peer_set_last_reset(peer, PEER_DOWN_AS_SETS_REJECT);
		peer_notify_config_change(peer->connection);
	}
	return NB_OK;
}

int bgp_global_reject_as_sets_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node, *nnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp->reject_as_sets = false;
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		peer_set_last_reset(peer, PEER_DOWN_AS_SETS_REJECT);
		peer_notify_config_change(peer->connection);
	}
	return NB_OK;
}

/*
 * graceful-restart `enabled` and `graceful-restart-disable` leaves —
 * per-instance only (the CONFIG_NODE/global mode in legacy DEFUNs stays).
 * Direct field/flag toggle on the bgp.
 */
int bgp_global_graceful_restart_enabled_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_RESTART);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_RESTART);
	return NB_OK;
}

int bgp_global_graceful_restart_enabled_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_RESTART);
	return NB_OK;
}

int bgp_global_graceful_restart_restart_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->restart_time = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_graceful_restart_restart_time_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->restart_time = BGP_DEFAULT_RESTART_TIME;
	return NB_OK;
}

int bgp_global_graceful_restart_selection_deferral_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->select_defer_time = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_graceful_restart_selection_deferral_time_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->select_defer_time = BGP_DEFAULT_SELECT_DEFERRAL_TIME;
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/administrative-shutdown  (presence container)
 *
 * apply_finish fires once on the container after any leaves (message)
 * are written. Calls bgp_shutdown_enable(bgp, message_or_null). Destroy
 * calls bgp_shutdown_disable.
 */
int bgp_global_administrative_shutdown_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;
	const char *msg = NULL;

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_exists(args->dnode, "message"))
		msg = yang_dnode_get_string(args->dnode, "message");

	bgp_shutdown_enable(bgp, msg);
	return NB_OK;
}

int bgp_global_administrative_shutdown_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp_shutdown_disable(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/enforce-first-as-global
 *
 * Distinct from neighbor-level enforce-first-as. On change, walks all
 * peers and triggers a soft inbound policy re-evaluation per AFI/SAFI.
 */
int bgp_global_enforce_first_as_global_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node;
	afi_t afi;
	safi_t safi;
	bool enabled;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	enabled = yang_dnode_get_bool(args->dnode, NULL);
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS) == enabled)
		return NB_OK;

	if (enabled)
		SET_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);

	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer))
		FOREACH_AFI_SAFI (afi, safi)
			peer_on_policy_change(peer, afi, safi, 0);
	return NB_OK;
}

int bgp_global_enforce_first_as_global_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp || !CHECK_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS))
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer))
		FOREACH_AFI_SAFI (afi, safi)
			peer_on_policy_change(peer, afi, safi, 0);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/suppress-duplicates
 *
 * Pure flag toggle. YANG default was previously "true" — corrected to
 * "false" in the schema this iteration to match the implementation's
 * legacy CLI default (`no suppress-duplicates` at startup).
 */
int bgp_global_suppress_duplicates_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args, BGP_FLAG_SUPPRESS_DUPLICATES,
					     3);
}

int bgp_global_suppress_duplicates_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(args, BGP_FLAG_SUPPRESS_DUPLICATES,
					      3);
}

/*
 * XPath:
 *   .../bgp/global/ebgp-requires-policy
 *
 * Pure flag toggle. YANG default likewise corrected to "false" to match
 * the FRR CLI default.
 */
int bgp_global_ebgp_requires_policy_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args, BGP_FLAG_EBGP_REQUIRES_POLICY,
					     3);
}

int bgp_global_ebgp_requires_policy_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(args, BGP_FLAG_EBGP_REQUIRES_POLICY,
					      3);
}

/*
 * XPath:
 *   .../bgp/global/fast-external-failover  (default "true")
 *
 * Inverted-flag mapping: the bgp internal flag BGP_FLAG_NO_FAST_EXT_FAILOVER
 * gates the OPPOSITE semantics — flag SET means fast failover DISABLED.
 * So YANG `true` (= fast failover enabled) maps to flag UNSET, and YANG
 * `false` maps to flag SET.
 */
int bgp_global_fast_external_failover_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		UNSET_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER);
	else
		SET_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER);
	return NB_OK;
}

int bgp_global_fast_external_failover_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	/* Default state matches YANG default "true" → flag UNSET. */
	UNSET_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/route-selection-options/deterministic-med
 *
 * VALIDATE-phase reject: cannot disable deterministic-med if any peer is
 * using addpath_type that requires it. Mirrors the legacy DEFUN check.
 * APPLY: flag toggle + bestpath recalc.
 */
int bgp_global_deterministic_med_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enable;

	if (args->event == NB_EV_VALIDATE) {
		bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
		if (!bgp)
			return NB_OK; /* parent create handles it */
		enable = yang_dnode_get_bool(args->dnode, NULL);
		if (!enable &&
		    CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED)) {
			struct listnode *node, *nnode;
			struct peer *peer;
			afi_t afi;
			safi_t safi;

			for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
				FOREACH_AFI_SAFI (afi, safi)
					if (bgp_addpath_dmed_required(
						    peer->addpath_type[afi][safi])) {
						snprintf(args->errmsg,
							 args->errmsg_len,
							 "deterministic-med cannot be disabled while addpath-tx-bestpath-per-AS is in use");
						return NB_ERR_VALIDATION;
					}
		}
		return NB_OK;
	}
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_global_flag_bestpath_modify(args, BGP_FLAG_DETERMINISTIC_MED,
					       4);
}

int bgp_global_deterministic_med_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args,
						BGP_FLAG_DETERMINISTIC_MED, 4);
}

/*
 * XPath:
 *   .../bgp/global/labeled-unicast-explicit-null
 *
 * Enum → two flag bits (IPV4, IPV6). YANG `both` = set both, `ipv4-only` =
 * set IPV4 only, `ipv6-only` = set IPV6 only, `disabled` = clear both.
 */
int bgp_global_labeled_unicast_explicit_null_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *value;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	UNSET_FLAG(bgp->flags, BGP_FLAG_LU_IPV4_EXPLICIT_NULL);
	UNSET_FLAG(bgp->flags, BGP_FLAG_LU_IPV6_EXPLICIT_NULL);

	value = yang_dnode_get_string(args->dnode, NULL);
	if (strmatch(value, "both")) {
		SET_FLAG(bgp->flags, BGP_FLAG_LU_IPV4_EXPLICIT_NULL);
		SET_FLAG(bgp->flags, BGP_FLAG_LU_IPV6_EXPLICIT_NULL);
	} else if (strmatch(value, "ipv4-only")) {
		SET_FLAG(bgp->flags, BGP_FLAG_LU_IPV4_EXPLICIT_NULL);
	} else if (strmatch(value, "ipv6-only")) {
		SET_FLAG(bgp->flags, BGP_FLAG_LU_IPV6_EXPLICIT_NULL);
	}
	return NB_OK;
}

int bgp_global_labeled_unicast_explicit_null_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_LU_IPV4_EXPLICIT_NULL);
	UNSET_FLAG(bgp->flags, BGP_FLAG_LU_IPV6_EXPLICIT_NULL);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/ipv6-auto-ra
 *
 * Inverted flag mapping (similar to fast-external-failover).
 * YANG `true`  (= auto-RA enabled, default) → BGP_FLAG_IPV6_NO_AUTO_RA UNSET
 * YANG `false` (= auto-RA disabled)         → BGP_FLAG_IPV6_NO_AUTO_RA SET
 *
 * The legacy CLI also supports a CONFIG_NODE form that affects bm->flags;
 * that branch stays in the legacy DEFPY. This NB callback only handles
 * the per-instance form.
 */
int bgp_global_ipv6_auto_ra_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		UNSET_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA);
	else
		SET_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA);
	return NB_OK;
}

int bgp_global_ipv6_auto_ra_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/route-selection-options/allow-multiple-as
 *
 * Maps to BGP_FLAG_ASPATH_MULTIPATH_RELAX. Note: legacy `no` clears
 * multi-path-as-set too; that's expressed in YANG via the when-clause
 * on multi-path-as-set (becomes invalid when allow-multiple-as=false).
 */
int bgp_global_allow_multiple_as_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args,
				BGP_FLAG_ASPATH_MULTIPATH_RELAX, 4);
}

int bgp_global_allow_multiple_as_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
	UNSET_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
	bgp_recalculate_all_bestpaths(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/route-selection-options/multi-path-as-set
 */
int bgp_global_multi_path_as_set_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args,
				BGP_FLAG_MULTIPATH_RELAX_AS_SET, 4);
}

int bgp_global_multi_path_as_set_destroy(struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args,
				BGP_FLAG_MULTIPATH_RELAX_AS_SET, 4);
}

/*
 * XPath:
 *   .../bgp/global/route-selection-options/peer-type-multipath-relax
 */
int bgp_global_peer_type_multipath_relax_modify(struct nb_cb_modify_args *args)
{
	return bgp_global_flag_bestpath_modify(args,
				BGP_FLAG_PEERTYPE_MULTIPATH_RELAX, 4);
}

int bgp_global_peer_type_multipath_relax_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_bestpath_destroy(args,
				BGP_FLAG_PEERTYPE_MULTIPATH_RELAX, 4);
}

/*
 * XPath:
 *   .../bgp/global/graceful-shutdown/enable
 *
 * Per-instance graceful-shutdown. VALIDATE-phase reject if the global
 * `bm->flags & BM_FLAG_GRACEFUL_SHUTDOWN` is set (matches the legacy
 * DEFUN's check). On APPLY, toggle BGP_FLAG_GRACEFUL_SHUTDOWN and
 * trigger the import/redistribute/soft-clear sequence via the legacy
 * helper (uses vty-less clear variants we added earlier).
 */
int bgp_global_graceful_shutdown_enable_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "per-vrf graceful-shutdown not permitted with global graceful-shutdown");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	enable = yang_dnode_get_bool(args->dnode, NULL);
	if (CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN) == enable)
		return NB_OK;

	if (enable)
		SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN);

	bgp_static_redo_import_check(bgp);
	bgp_redistribute_redo(bgp);
	bgp_clear_star_soft_out_quiet(bgp);
	bgp_clear_star_soft_in_quiet(bgp);
	return NB_OK;
}

int bgp_global_graceful_shutdown_enable_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp || !CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN))
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN);
	bgp_static_redo_import_check(bgp);
	bgp_redistribute_redo(bgp);
	bgp_clear_star_soft_out_quiet(bgp);
	bgp_clear_star_soft_in_quiet(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/suppress-fib-pending  (presence container)
 *
 * apply_finish reads adv-delay (default 1000ms) and calls
 * bgp_suppress_fib_pending_set(bgp, true, delay). Destroy unsets.
 */
int bgp_global_suppress_fib_pending_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp;
	uint16_t delay = BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY;

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_exists(args->dnode, "adv-delay"))
		delay = yang_dnode_get_uint16(args->dnode, "adv-delay");
	bgp_suppress_fib_pending_set(bgp, true, delay);
	return NB_OK;
}

int bgp_global_suppress_fib_pending_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp_suppress_fib_pending_set(bgp, false,
				     BGP_DEFAULT_SUPPRESS_FIB_ADV_DELAY);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/advertisement-delay-global
 *
 * Per-instance advertisement-delay (bgp->v_advertisement_delay).
 */
int bgp_global_advertisement_delay_global_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	bgp->v_advertisement_delay = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_advertisement_delay_global_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp->v_advertisement_delay = BGP_ADVERTISEMENT_DELAY_DEFAULT;
	if (bgp->advertisement_delay_started && !bgp->advertisement_delay_over) {
		event_cancel(&bgp->t_advertisement_delay);
		bgp->advertisement_delay_started = 0;
		bgp->advertisement_delay_over = 0;
	}
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/global-config-timers/update-delay-time
 *
 * Per-instance update-delay. Legacy DEFUN rejects if the global form
 * (`bm->v_update_delay`) is set — replicate with NB_EV_VALIDATE.
 * The companion `establish-wait-time` leaf (same container) defaults
 * to update-delay-time when not separately set (legacy semantic).
 */
int bgp_global_update_delay_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint16_t update_delay, establish_wait;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bm->v_update_delay) {
			snprintf(args->errmsg, args->errmsg_len,
				 "per-vrf update-delay not permitted with global update-delay");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	update_delay = yang_dnode_get_uint16(args->dnode, NULL);
	bgp->v_update_delay = update_delay;
	/* If establish-wait is unset, mirror update-delay (legacy semantic). */
	if (yang_dnode_exists(args->dnode, "../establish-wait-time")) {
		establish_wait = yang_dnode_get_uint16(args->dnode,
						       "../establish-wait-time");
		if (update_delay < establish_wait) {
			snprintf(args->errmsg, args->errmsg_len,
				 "update-delay less than establish-wait");
			return NB_ERR;
		}
		bgp->v_establish_wait = establish_wait;
	} else {
		bgp->v_establish_wait = update_delay;
	}
	return NB_OK;
}

int bgp_global_update_delay_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->v_update_delay = BGP_UPDATE_DELAY_DEFAULT;
	bgp->v_establish_wait = BGP_UPDATE_DELAY_DEFAULT;
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/global-config-timers/establish-wait-time
 *
 * Only meaningful in conjunction with update-delay-time. The update-delay
 * modify callback handles the cross-leaf validation; here we just stash
 * the value.
 */
int bgp_global_establish_wait_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->v_establish_wait = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_establish_wait_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->v_establish_wait = bgp->v_update_delay;
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/global-config-timers/connect-retry-interval
 *
 * Per-instance connect-retry timer default.
 */
int bgp_global_connect_retry_interval_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->default_connect_retry = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_connect_retry_interval_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->default_connect_retry = BGP_DEFAULT_CONNECT_RETRY;
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/conditional-advertisement-period
 *
 * Sets bgp->condition_check_period. On no-form / destroy, also clears
 * PEER_STATUS_COND_ADV_PENDING flag from all peers (legacy semantic).
 */
int bgp_global_conditional_advertisement_period_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	bgp->condition_check_period = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_conditional_advertisement_period_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct peer *peer;
	struct listnode *node, *nnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp || bgp->condition_check_period ==
		    DEFAULT_CONDITIONAL_ROUTES_POLL_TIME)
		return NB_OK;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		UNSET_FLAG(peer->sflags, PEER_STATUS_COND_ADV_PENDING);
	bgp->condition_check_period = DEFAULT_CONDITIONAL_ROUTES_POLL_TIME;
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/default-originate-timer
 *
 * Sets bgp->rmap_def_originate_eval_timer. Destroy/no cancels any
 * in-flight evaluation event and zeros the timer.
 */
int bgp_global_default_originate_timer_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	bgp->rmap_def_originate_eval_timer = yang_dnode_get_uint16(args->dnode,
								     NULL);
	if (bgp->t_rmap_def_originate_eval)
		event_cancel(&bgp->t_rmap_def_originate_eval);
	return NB_OK;
}

int bgp_global_default_originate_timer_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp->rmap_def_originate_eval_timer = 0;
	if (bgp->t_rmap_def_originate_eval)
		event_cancel(&bgp->t_rmap_def_originate_eval);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/bestpath-bandwidth
 *
 * Enum → bgp->lb_handling. Side effect: redo zebra route announcements
 * for every (afi,safi) since lb_handling affects route install metadata.
 */
int bgp_global_bestpath_bandwidth_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *value;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	value = yang_dnode_get_string(args->dnode, NULL);
	if (strmatch(value, "ignore"))
		bgp->lb_handling = BGP_LINK_BW_IGNORE_BW;
	else if (strmatch(value, "skip-missing"))
		bgp->lb_handling = BGP_LINK_BW_SKIP_MISSING;
	else if (strmatch(value, "default-weight-for-missing"))
		bgp->lb_handling = BGP_LINK_BW_DEFWT_4_MISSING;
	else
		bgp->lb_handling = BGP_LINK_BW_ECMP;

	FOREACH_AFI_SAFI (afi, safi) {
		if (!bgp_fibupd_safi(safi))
			continue;
		bgp_zebra_announce_table(bgp, afi, safi);
	}
	return NB_OK;
}

int bgp_global_bestpath_bandwidth_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp->lb_handling = BGP_LINK_BW_ECMP;
	FOREACH_AFI_SAFI (afi, safi) {
		if (!bgp_fibupd_safi(safi))
			continue;
		bgp_zebra_announce_table(bgp, afi, safi);
	}
	return NB_OK;
}

/*
 * Re-send a BGP capability to every peer of `bgp` after a capability-bearing
 * config knob (graceful-restart, notification, LLGR, etc.) changes.
 * Shared between graceful-restart-notification and llgr-stalepath callbacks.
 */
static void bgp_resend_capability_all_peers(struct bgp *bgp,
					     uint8_t capability_code,
					     uint8_t action)
{
	struct peer *peer;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
				    capability_code, action);
}

/*
 * XPath:
 *   .../bgp/global/graceful-restart-notification
 */
int bgp_global_graceful_restart_notification_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
	bgp_resend_capability_all_peers(bgp, CAPABILITY_CODE_RESTART,
					CAPABILITY_ACTION_SET);
	return NB_OK;
}

int bgp_global_graceful_restart_notification_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
	bgp_resend_capability_all_peers(bgp, CAPABILITY_CODE_RESTART,
					CAPABILITY_ACTION_SET);
	return NB_OK;
}

/*
 * XPath:
 *   .../bgp/global/long-lived-graceful-restart-stale-time
 *
 * Sets bgp->llgr_stale_time and re-sends the LLGR capability with the
 * appropriate ACTION_SET / _UNSET. Destroy resets to default and sends
 * ACTION_UNSET.
 */
int bgp_global_long_lived_graceful_restart_stale_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	bgp->llgr_stale_time = yang_dnode_get_uint32(args->dnode, NULL);
	bgp_resend_capability_all_peers(bgp, CAPABILITY_CODE_LLGR,
					CAPABILITY_ACTION_SET);
	return NB_OK;
}

int bgp_global_long_lived_graceful_restart_stale_time_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp->llgr_stale_time = BGP_DEFAULT_LLGR_STALE_TIME;
	bgp_resend_capability_all_peers(bgp, CAPABILITY_CODE_LLGR,
					CAPABILITY_ACTION_UNSET);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/fast-convergence
 */
int bgp_global_fast_convergence_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	bgp->fast_convergence = yang_dnode_get_bool(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_fast_convergence_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp->fast_convergence = false;
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/default-link-local-capability
 */
int bgp_global_default_link_local_capability_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args,
					     BGP_FLAG_LINK_LOCAL_CAPABILITY, 3);
}

int bgp_global_default_link_local_capability_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(
		args, BGP_FLAG_LINK_LOCAL_CAPABILITY, 3);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/default-dynamic-capability
 */
int bgp_global_default_dynamic_capability_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args, BGP_FLAG_DYNAMIC_CAPABILITY,
					     3);
}

int bgp_global_default_dynamic_capability_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(args, BGP_FLAG_DYNAMIC_CAPABILITY,
					      3);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/route-reflector/route-reflector-cluster-id
 *
 * Depth 4. The YANG type is bt:rr-cluster-id-type (dotted-quad or uint32).
 * Side effect: bgp_clear_star_soft_out (peer outbound updates are dependent
 * on cluster-id), invoked via the vty-less helper.
 */
int bgp_global_route_reflector_cluster_id_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct in_addr cluster;
	const char *value;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	/*
	 * rr-cluster-id-type accepts either dotted-quad or 32-bit unsigned.
	 * yang_dnode_get_string preserves the textual form so we can parse
	 * either via inet_aton (handles dotted-quad and bare decimal).
	 */
	value = yang_dnode_get_string(args->dnode, NULL);
	if (inet_aton(value, &cluster) == 0) {
		snprintf(args->errmsg, args->errmsg_len,
			 "malformed route-reflector-cluster-id: %s", value);
		return NB_ERR_VALIDATION;
	}

	bgp_cluster_id_set(bgp, &cluster);
	bgp_clear_star_soft_out_quiet(bgp);
	return NB_OK;
}

int bgp_global_route_reflector_cluster_id_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp_cluster_id_unset(bgp);
	bgp_clear_star_soft_out_quiet(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/route-reflector/no-client-reflect
 *
 * Inverse semantics: yang `no-client-reflect=true` ↔ internal
 * BGP_FLAG_NO_CLIENT_TO_CLIENT set ↔ CLI `no bgp client-to-client reflection`.
 * Side effect: bgp_clear_star_soft_out_quiet (peer outbound is dependent).
 */
int bgp_global_no_client_reflect_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT);
	bgp_clear_star_soft_out_quiet(bgp);
	return NB_OK;
}

int bgp_global_no_client_reflect_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT);
	bgp_clear_star_soft_out_quiet(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/local-pref
 *
 * Depth 3. Side effect: bgp_clear_star_soft_in_quiet so existing inbound
 * paths are re-evaluated with the new default local-preference attribute.
 */
int bgp_global_local_pref_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	bgp_default_local_preference_set(
		bgp, yang_dnode_get_uint32(args->dnode, NULL));
	bgp_clear_star_soft_in_quiet(bgp);
	return NB_OK;
}

int bgp_global_local_pref_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	bgp_default_local_preference_unset(bgp);
	bgp_clear_star_soft_in_quiet(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/ebgp-multihop-connected-route-check
 *
 * YANG semantics (per the leaf description): true = disable check.
 * Maps to BGP_FLAG_DISABLE_NH_CONNECTED_CHK. Side effect: soft inbound
 * clear so existing routes are re-evaluated against the new check policy.
 */
int bgp_global_ebgp_multihop_connected_route_check_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
	bgp_clear_star_soft_in_quiet(bgp);
	return NB_OK;
}

int bgp_global_ebgp_multihop_connected_route_check_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	UNSET_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
	bgp_clear_star_soft_in_quiet(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/graceful-restart/rib-stale-time
 *
 * Depth 4 (extra hop through graceful-restart container). Side effect:
 * bgp_zebra_stale_timer_update pushes the new value to zebra.
 */
int bgp_global_graceful_restart_rib_stale_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->rib_stale_time = yang_dnode_get_uint16(args->dnode, NULL);
	(void)bgp_zebra_stale_timer_update(bgp);
	return NB_OK;
}

int bgp_global_graceful_restart_rib_stale_time_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->rib_stale_time = BGP_DEFAULT_RIB_STALE_TIME;
	(void)bgp_zebra_stale_timer_update(bgp);
	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/graceful-restart/preserve-fw-entry
 *
 * Per-instance only — the cross-mode CONFIG/BGP-NODE legacy behaviour is
 * preserved by the still-extant `bgp graceful-restart preserve-fw-state`
 * DEFUN keeping its CONFIG_NODE branch for the bm->flags global form.
 * (This NB path covers BGP_NODE only, which is what NB modelling expresses.)
 */
int bgp_global_graceful_restart_preserve_fw_entry_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_global_flag_toggle_modify(args, BGP_FLAG_GR_PRESERVE_FWD, 4);
}

int bgp_global_graceful_restart_preserve_fw_entry_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_global_flag_toggle_destroy(args, BGP_FLAG_GR_PRESERVE_FWD,
					      4);
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/global/graceful-restart/stale-routes-time
 *
 * Depth 4. Direct write to bgp->stalepath_time. The legacy DEFUN dispatches
 * CONFIG_NODE vs BGP_NODE; here we cover per-instance only.
 */
int bgp_global_graceful_restart_stale_routes_time_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_ERR;

	bgp->stalepath_time = yang_dnode_get_uint16(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_graceful_restart_stale_routes_time_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 4);
	if (!bgp)
		return NB_OK;

	bgp->stalepath_time = BGP_DEFAULT_STALEPATH_TIME;
	return NB_OK;
}

/* ------------------------------------------------------------------------ */
/* Phase 3a — neighbor list + neighbor-remote-as                              */
/* ------------------------------------------------------------------------ */

/*
 * Resolve the bgp instance and the neighbor's remote-address from a dnode
 * positioned at depth `depth_to_cpp` hops above the control-plane-protocol
 * entry. Examples:
 *   - neighbor list entry          depth_to_cpp = 3 (../../../vrf)
 *   - neighbor-remote-as container depth_to_cpp = 4
 *   - leaf under remote-as         depth_to_cpp = 5
 *
 * `neighbor_dnode` is the dnode of the `neighbor` list entry — descendants
 * pass an ancestor xpath to walk back up to it.
 */
static struct bgp *bgp_nb_lookup_neighbor_su(const struct lyd_node *dnode,
					      const char *neighbor_xpath,
					      union sockunion *su,
					      unsigned int depth_to_cpp)
{
	const char *remote_addr;
	struct bgp *bgp;

	bgp = bgp_nb_lookup_from_dnode(dnode, depth_to_cpp);
	if (!bgp)
		return NULL;

	remote_addr = yang_dnode_get_string(dnode, neighbor_xpath);
	if (str2sockunion(remote_addr, su) < 0)
		return NULL;

	return bgp;
}

/*
 * Convert YANG `as-type` enum string into the internal `enum peer_asn_type`.
 * YANG values (from frr-bgp-types:as-type) include: as-specified, internal,
 * external, unconfigured (and from FRR-style usage: auto).
 */
static enum peer_asn_type bgp_nb_yang_as_type(const char *yang_value)
{
	if (!yang_value)
		return AS_UNSPECIFIED;
	if (strmatch(yang_value, "as-specified"))
		return AS_SPECIFIED;
	if (strmatch(yang_value, "internal"))
		return AS_INTERNAL;
	if (strmatch(yang_value, "external"))
		return AS_EXTERNAL;
	if (strmatch(yang_value, "auto"))
		return AS_AUTO;
	return AS_UNSPECIFIED;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/neighbors/neighbor
 *
 * Creates the peer. The `neighbor-remote-as/remote-as-type` leaf is
 * mandatory in YANG, so it's guaranteed present in the dnode tree at
 * APPLY time. If type is `as-specified`, `remote-as` is required too
 * (enforced by YANG when-clause).
 *
 * peer_remote_as() is idempotent on existing peers (changes AS); for a
 * new peer it allocates via peer_create internally. We don't separately
 * call peer_create.
 */
int bgp_neighbor_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const char *remote_addr;
	union sockunion su;
	const char *as_type_str;
	enum peer_asn_type as_type;
	as_t as = 0;
	const char *as_str = NULL;
	char as_buf[16];
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp) {
		snprintf(args->errmsg, args->errmsg_len,
			 "bgp instance not found for neighbor create");
		return NB_ERR;
	}

	remote_addr = yang_dnode_get_string(args->dnode, "remote-address");
	if (str2sockunion(remote_addr, &su) < 0) {
		snprintf(args->errmsg, args->errmsg_len,
			 "invalid neighbor remote-address: %s", remote_addr);
		return NB_ERR_VALIDATION;
	}

	as_type_str = yang_dnode_get_string(args->dnode,
					    "neighbor-remote-as/remote-as-type");
	as_type = bgp_nb_yang_as_type(as_type_str);
	if (as_type == AS_UNSPECIFIED) {
		snprintf(args->errmsg, args->errmsg_len,
			 "unsupported remote-as-type: %s", as_type_str);
		return NB_ERR_VALIDATION;
	}

	if (as_type == AS_SPECIFIED) {
		if (!yang_dnode_exists(args->dnode,
				       "neighbor-remote-as/remote-as")) {
			snprintf(args->errmsg, args->errmsg_len,
				 "remote-as required when remote-as-type is as-specified");
			return NB_ERR_VALIDATION;
		}
		as = (as_t)yang_dnode_get_uint32(
			args->dnode, "neighbor-remote-as/remote-as");
		snprintf(as_buf, sizeof(as_buf), "%u", as);
		as_str = as_buf;
	}

	bgp_need_listening(bgp, NULL);
	ret = peer_remote_as(bgp, &su, NULL, &as, as_type, as_str);
	if (ret < 0) {
		snprintf(args->errmsg, args->errmsg_len,
			 "peer_remote_as failed for %s (ret %d)", remote_addr,
			 ret);
		return NB_ERR;
	}

	return NB_OK;
}

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/neighbors/neighbor
 */
int bgp_neighbor_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	union sockunion su;
	struct peer *peer;
	const char *remote_addr;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	remote_addr = yang_dnode_get_string(args->dnode, "remote-address");
	if (str2sockunion(remote_addr, &su) < 0)
		return NB_OK;

	peer = peer_lookup(bgp, &su);
	if (!peer)
		return NB_OK;

	peer_delete(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/neighbor-remote-as/remote-as-type
 *
 * Triggered on transitions between as-type values on an existing neighbor.
 * For a fresh neighbor, bgp_neighbor_create already wires the type; this
 * callback handles the modify case.
 */
int bgp_neighbor_remote_as_type_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	union sockunion su;
	struct peer *peer;
	enum peer_asn_type new_type;
	as_t as = 0;
	const char *as_str = NULL;
	char as_buf[16];

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_neighbor_su(args->dnode, "../../remote-address", &su,
					 5);
	if (!bgp)
		return NB_ERR;

	peer = peer_lookup(bgp, &su);
	if (!peer)
		return NB_OK; /* parent create will run first */

	new_type = bgp_nb_yang_as_type(yang_dnode_get_string(args->dnode, NULL));
	if (new_type == AS_SPECIFIED &&
	    yang_dnode_exists(args->dnode, "../remote-as")) {
		as = (as_t)yang_dnode_get_uint32(args->dnode, "../remote-as");
		snprintf(as_buf, sizeof(as_buf), "%u", as);
		as_str = as_buf;
	}

	peer_as_change(peer, as, new_type, as_str);
	return NB_OK;
}

int bgp_neighbor_remote_as_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	union sockunion su;
	struct peer *peer;
	as_t as;
	char as_buf[16];

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_neighbor_su(args->dnode, "../../remote-address", &su,
					 5);
	if (!bgp)
		return NB_ERR;

	peer = peer_lookup(bgp, &su);
	if (!peer)
		return NB_OK;

	as = (as_t)yang_dnode_get_uint32(args->dnode, NULL);
	snprintf(as_buf, sizeof(as_buf), "%u", as);
	peer_as_change(peer, as, AS_SPECIFIED, as_buf);
	return NB_OK;
}

int bgp_neighbor_remote_as_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}
	/*
	 * The remote-as leaf is gated by a when-clause; destroying it means
	 * the remote-as-type leaf is moving away from `as-specified`. The
	 * type-modify callback owns the side effect; nothing to do here.
	 */
	return NB_OK;
}

/*
 * Lookup the peer owning the dnode at `depth_to_cpp` hops above the
 * control-plane-protocol entry. `neighbor_rel_xpath` is the relative xpath
 * from the dnode up to the `neighbor` list entry (used to read the
 * remote-address key). Returns NULL if peer not found.
 */
static struct peer *bgp_nb_lookup_peer(const struct lyd_node *dnode,
				        const char *neighbor_rel_xpath,
				        unsigned int depth_to_cpp)
{
	struct bgp *bgp;
	union sockunion su;
	const char *remote_addr;
	char xpath_buf[64];

	bgp = bgp_nb_lookup_from_dnode(dnode, depth_to_cpp);
	if (!bgp)
		return NULL;

	snprintf(xpath_buf, sizeof(xpath_buf), "%s/remote-address",
		 neighbor_rel_xpath);
	remote_addr = yang_dnode_get_string(dnode, xpath_buf);
	if (str2sockunion(remote_addr, &su) < 0)
		return NULL;

	return peer_lookup(bgp, &su);
}

/*
 * Generic per-neighbor boolean flag toggle. A leaf at depth_to_cpp hops
 * from CPP maps to a single PEER_FLAG_* bit via peer_flag_set/_unset.
 * `neighbor_rel` is the relative xpath from the leaf to the neighbor list
 * entry, e.g. ".." for a direct child, "../.." for a leaf inside a
 * container under neighbor, etc.
 */
static int peer_flag_toggle_modify(struct nb_cb_modify_args *args,
				    uint64_t flag, const char *neighbor_rel,
				    unsigned int depth_to_cpp)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, neighbor_rel, depth_to_cpp);
	if (!peer)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, flag);
	else
		peer_flag_unset(peer, flag);
	return NB_OK;
}

static int peer_flag_toggle_destroy(struct nb_cb_destroy_args *args,
				     uint64_t flag, const char *neighbor_rel,
				     unsigned int depth_to_cpp)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, neighbor_rel, depth_to_cpp);
	if (!peer)
		return NB_OK;

	peer_flag_unset(peer, flag);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/password
 *
 * Depth from leaf to CPP = 4 (`../../../../vrf`). neighbor_rel = ".." (leaf
 * is a direct child of neighbor).
 */
int bgp_neighbor_password_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	const char *pwd;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;

	pwd = yang_dnode_get_string(args->dnode, NULL);
	if (peer_password_set(peer, pwd) != 0) {
		snprintf(args->errmsg, args->errmsg_len,
			 "peer_password_set failed");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_neighbor_password_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;

	peer_password_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/description
 *
 * Optional textual description. Setter and unset are non-failing.
 */
int bgp_neighbor_description_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;

	peer_description_set(peer, yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_neighbor_description_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;

	peer_description_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/passive-mode
 */
int bgp_neighbor_passive_mode_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_PASSIVE, "..", 4);
}

int bgp_neighbor_passive_mode_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_PASSIVE, "..", 4);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/solo
 */
int bgp_neighbor_solo_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_LONESOUL, "..", 4);
}

int bgp_neighbor_solo_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_LONESOUL, "..", 4);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/enforce-first-as
 *
 * YANG default true matches the existing semantic: if you destroy this
 * leaf, the flag is unset (i.e., enforce is OFF in code terms). The CLI
 * `bgp enforce-first-as` is per-bgp; the per-neighbor knob lives here in
 * YANG.
 */
int bgp_neighbor_enforce_first_as_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_ENFORCE_FIRST_AS, "..",
					4);
}

int bgp_neighbor_enforce_first_as_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_ENFORCE_FIRST_AS, "..",
					 4);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/ttl-security
 *
 * Direct neighbor leaf (depth 4). Internal setter wants `int gtsm_hops`.
 */
int bgp_neighbor_ttl_security_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	uint8_t hops;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;

	hops = yang_dnode_get_uint8(args->dnode, NULL);
	if (peer_ttl_security_hops_set(peer, hops) != 0) {
		snprintf(args->errmsg, args->errmsg_len,
			 "peer_ttl_security_hops_set failed");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_neighbor_ttl_security_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;

	peer_ttl_security_hops_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/admin-shutdown/enable
 *
 * Container hop adds one to depth: 5 levels back to control-plane-protocol.
 * neighbor_rel = "../.." since this leaf is two hops up to the neighbor.
 */
int bgp_neighbor_admin_shutdown_enable_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_SHUTDOWN, "../..", 5);
}

int bgp_neighbor_admin_shutdown_enable_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_SHUTDOWN, "../..", 5);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/admin-shutdown/message
 *
 * Shutdown communication message (RFC 8203, draft-ietf-idr-shutdown-06).
 */
int bgp_neighbor_admin_shutdown_message_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;

	peer_tx_shutdown_message_set(peer,
				     yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_neighbor_admin_shutdown_message_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;

	peer_tx_shutdown_message_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/ebgp-multihop/enabled
 *
 * When enabled without an explicit multihop-ttl, FRR uses the default TTL
 * (MAXTTL). When the multihop-ttl leaf is also set in the same transaction,
 * the ttl callback will run separately and refine the TTL.
 */
int bgp_neighbor_ebgp_multihop_enabled_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_ebgp_multihop_set(peer, MAXTTL);
	else
		peer_ebgp_multihop_unset(peer);
	return NB_OK;
}

int bgp_neighbor_ebgp_multihop_enabled_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;

	peer_ebgp_multihop_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/ebgp-multihop/multihop-ttl
 */
int bgp_neighbor_ebgp_multihop_ttl_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;

	if (peer_ebgp_multihop_set(peer,
				   yang_dnode_get_uint8(args->dnode, NULL)) !=
	    0) {
		snprintf(args->errmsg, args->errmsg_len,
			 "peer_ebgp_multihop_set failed");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_neighbor_ebgp_multihop_ttl_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;

	peer_ebgp_multihop_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/ebgp-multihop/disable-connected-check
 */
int bgp_neighbor_ebgp_multihop_disable_connected_check_modify(
	struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_DISABLE_CONNECTED_CHECK,
					"../..", 5);
}

int bgp_neighbor_ebgp_multihop_disable_connected_check_destroy(
	struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_DISABLE_CONNECTED_CHECK,
					 "../..", 5);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/update-source/ip
 *
 * Container hop + choice/case; depth from leaf to CPP = 5, neighbor_rel = "../..".
 */
int bgp_neighbor_update_source_ip_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	union sockunion su;
	const char *ip;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;

	ip = yang_dnode_get_string(args->dnode, NULL);
	if (str2sockunion(ip, &su) < 0) {
		snprintf(args->errmsg, args->errmsg_len,
			 "invalid update-source ip: %s", ip);
		return NB_ERR_VALIDATION;
	}

	peer_update_source_addr_set(peer, &su);
	return NB_OK;
}

int bgp_neighbor_update_source_ip_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;

	peer_update_source_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/update-source/interface
 */
int bgp_neighbor_update_source_interface_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;

	if (peer_update_source_if_set(peer,
				      yang_dnode_get_string(args->dnode, NULL)) !=
	    0) {
		snprintf(args->errmsg, args->errmsg_len,
			 "peer_update_source_if_set failed");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_neighbor_update_source_interface_destroy(
	struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;

	peer_update_source_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/timers/connect-time
 */
int bgp_neighbor_timers_connect_time_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;

	if (peer_timers_connect_set(peer,
				    yang_dnode_get_uint16(args->dnode, NULL)) !=
	    0) {
		snprintf(args->errmsg, args->errmsg_len,
			 "peer_timers_connect_set failed");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_neighbor_timers_connect_time_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;

	peer_timers_connect_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/timers/advertise-interval
 */
int bgp_neighbor_timers_advertise_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;

	if (peer_advertise_interval_set(
		    peer, yang_dnode_get_uint16(args->dnode, NULL)) != 0) {
		snprintf(args->errmsg, args->errmsg_len,
			 "peer_advertise_interval_set failed");
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_neighbor_timers_advertise_interval_destroy(
	struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;

	peer_advertise_interval_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/local-as  (container)
 *
 * `peer_local_as_set()` takes (as, no_prepend, replace_as, dual_as, as_str)
 * as a single atomic call. The three child leaves (`local-as`, `no-prepend`,
 * `replace-as`) get their own modify callbacks in a transaction, so instead
 * of running the setter from each leaf, we use an apply_finish callback on
 * the container — fires once after all leaves in the transaction are
 * committed.
 */
int bgp_neighbor_local_as_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct peer *peer;
	as_t as = 0;
	bool no_prepend = false;
	bool replace_as = false;
	char as_buf[16] = "";

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;

	if (yang_dnode_exists(args->dnode, "local-as")) {
		as = (as_t)yang_dnode_get_uint32(args->dnode, "local-as");
		snprintf(as_buf, sizeof(as_buf), "%u", as);
	}
	if (yang_dnode_exists(args->dnode, "no-prepend"))
		no_prepend = yang_dnode_get_bool(args->dnode, "no-prepend");
	if (yang_dnode_exists(args->dnode, "replace-as"))
		replace_as = yang_dnode_get_bool(args->dnode, "replace-as");

	if (as == 0) {
		/*
		 * If the local-as leaf is absent the container is a noop —
		 * the per-leaf no_prepend/replace_as modifiers are meaningful
		 * only when local-as is set.
		 */
		return NB_OK;
	}

	peer_local_as_set(peer, as, no_prepend, replace_as, false, as_buf);
	return NB_OK;
}

int bgp_neighbor_local_as_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;

	peer_local_as_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/bfd-options  (container)
 *
 * Apply-finish over the container. Reads the `enable` leaf and configures
 * BFD accordingly, then writes detect-multiplier / min-rx / min-tx into
 * peer->bfd_config and calls bgp_peer_config_apply() once.
 */
int bgp_neighbor_bfd_options_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct peer *peer;
	bool enable;

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;

	enable = yang_dnode_exists(args->dnode, "enable") &&
		 yang_dnode_get_bool(args->dnode, "enable");

	if (!enable) {
		bgp_peer_remove_bfd_config(peer);
		return NB_OK;
	}

	bgp_peer_configure_bfd(peer, true);
	if (yang_dnode_exists(args->dnode, "detect-multiplier"))
		peer->bfd_config->detection_multiplier =
			yang_dnode_get_uint8(args->dnode, "detect-multiplier");
	if (yang_dnode_exists(args->dnode, "required-min-rx"))
		peer->bfd_config->min_rx =
			yang_dnode_get_uint16(args->dnode, "required-min-rx");
	if (yang_dnode_exists(args->dnode, "desired-min-tx"))
		peer->bfd_config->min_tx =
			yang_dnode_get_uint16(args->dnode, "desired-min-tx");
	if (yang_dnode_exists(args->dnode, "check-cp-failure"))
		peer->bfd_config->cbit =
			yang_dnode_get_bool(args->dnode, "check-cp-failure");

	bgp_peer_config_apply(peer, NULL);
	return NB_OK;
}

int bgp_neighbor_bfd_options_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;

	bgp_peer_remove_bfd_config(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/capability-options/dynamic-capability
 */
int bgp_neighbor_capabilities_dynamic_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_DYNAMIC_CAPABILITY,
					"../..", 5);
}

int bgp_neighbor_capabilities_dynamic_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_DYNAMIC_CAPABILITY,
					 "../..", 5);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/capability-options/strict-capability
 */
int bgp_neighbor_capabilities_strict_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_STRICT_CAP_MATCH,
					"../..", 5);
}

int bgp_neighbor_capabilities_strict_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_STRICT_CAP_MATCH,
					 "../..", 5);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/capability-options/override-capability
 */
int bgp_neighbor_capabilities_override_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_OVERRIDE_CAPABILITY,
					"../..", 5);
}

int bgp_neighbor_capabilities_override_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_OVERRIDE_CAPABILITY,
					 "../..", 5);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/capability-options/extended-nexthop-capability
 */
int bgp_neighbor_capabilities_extended_nexthop_modify(
	struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_CAPABILITY_ENHE,
					"../..", 5);
}

int bgp_neighbor_capabilities_extended_nexthop_destroy(
	struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_CAPABILITY_ENHE,
					 "../..", 5);
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/capability-options/capability-negotiate
 *
 * INVERTED mapping: YANG `capability-negotiate = true` means negotiate
 * capabilities normally (no `dont-capability-negotiate`); YANG `false`
 * means set PEER_FLAG_DONT_CAPABILITY (suppress capability negotiation).
 */
int bgp_neighbor_capabilities_negotiate_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_ERR;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_unset(peer, PEER_FLAG_DONT_CAPABILITY);
	else
		peer_flag_set(peer, PEER_FLAG_DONT_CAPABILITY);
	return NB_OK;
}

int bgp_neighbor_capabilities_negotiate_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	peer = bgp_nb_lookup_peer(args->dnode, "../..", 5);
	if (!peer)
		return NB_OK;

	peer_flag_unset(peer, PEER_FLAG_DONT_CAPABILITY);
	return NB_OK;
}

/*
 * Direct-child neighbor boolean flag NB callbacks (Phase 3a batch).
 * Leaf is at neighbor[remote-address]/<leaf>, depth-to-CPP = 4,
 * neighbor_rel = "..".
 */
#define BGP_NEIGHBOR_FLAG_CB(_name, _flag)                                     \
	int bgp_neighbor_##_name##_modify(struct nb_cb_modify_args *args)      \
	{                                                                      \
		return peer_flag_toggle_modify(args, (_flag), "..", 4);        \
	}                                                                      \
	int bgp_neighbor_##_name##_destroy(struct nb_cb_destroy_args *args)    \
	{                                                                      \
		return peer_flag_toggle_destroy(args, (_flag), "..", 4);       \
	}

/* ---------- Phase 3c — per-AF per-peer flag toggles -------------------- */

/*
 * Per-AF flag leaves live at:
 *   .../neighbors/neighbor[remote-address]/afi-safis/afi-safi[afi-safi-name]/<leaf>
 *
 * Depth from leaf to control-plane-protocol = 6.
 * neighbor xpath relative = "../../.." (up afi-safi → afi-safis → neighbor).
 *
 * AFI/SAFI extracted from the parent afi-safi-name key.
 */
static int bgp_nb_peer_af_lookup(const struct lyd_node *dnode,
				 struct peer **peer_out, afi_t *afi_out,
				 safi_t *safi_out)
{
	struct peer *peer;
	const char *afi_safi_id;

	peer = bgp_nb_lookup_peer(dnode, "../../..", 6);
	if (!peer)
		return -1;

	afi_safi_id = yang_dnode_get_string(dnode, "../afi-safi-name");
	if (!afi_safi_id)
		return -1;

	/* afi_safi_id is e.g. "frr-rt:ipv4-unicast" — strip prefix and map. */
	if (strstr(afi_safi_id, "ipv4-unicast")) {
		*afi_out = AFI_IP;  *safi_out = SAFI_UNICAST;
	} else if (strstr(afi_safi_id, "ipv6-unicast")) {
		*afi_out = AFI_IP6; *safi_out = SAFI_UNICAST;
	} else if (strstr(afi_safi_id, "ipv4-labeled-unicast")) {
		*afi_out = AFI_IP;  *safi_out = SAFI_LABELED_UNICAST;
	} else if (strstr(afi_safi_id, "ipv6-labeled-unicast")) {
		*afi_out = AFI_IP6; *safi_out = SAFI_LABELED_UNICAST;
	} else if (strstr(afi_safi_id, "l3vpn-ipv4-unicast")) {
		*afi_out = AFI_IP;  *safi_out = SAFI_MPLS_VPN;
	} else if (strstr(afi_safi_id, "l3vpn-ipv6-unicast")) {
		*afi_out = AFI_IP6; *safi_out = SAFI_MPLS_VPN;
	} else if (strstr(afi_safi_id, "l2vpn-evpn")) {
		*afi_out = AFI_L2VPN; *safi_out = SAFI_EVPN;
	} else if (strstr(afi_safi_id, "l2vpn-vpls")) {
		*afi_out = AFI_L2VPN; *safi_out = SAFI_UNICAST;
	} else {
		return -1;
	}
	*peer_out = peer;
	return 0;
}

static int peer_af_flag_toggle_modify(struct nb_cb_modify_args *args,
				      uint64_t flag)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_peer_af_lookup(args->dnode, &peer, &afi, &safi) < 0)
		return NB_ERR;
	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_af_flag_set(peer, afi, safi, flag);
	else
		peer_af_flag_unset(peer, afi, safi, flag);
	return NB_OK;
}

static int peer_af_flag_toggle_destroy(struct nb_cb_destroy_args *args,
				       uint64_t flag)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_peer_af_lookup(args->dnode, &peer, &afi, &safi) < 0)
		return NB_OK;
	peer_af_flag_unset(peer, afi, safi, flag);
	return NB_OK;
}

#define BGP_NEIGHBOR_AF_FLAG_CB(_name, _flag)                                  \
	int bgp_neighbor_af_##_name##_modify(struct nb_cb_modify_args *args)   \
	{                                                                      \
		return peer_af_flag_toggle_modify(args, (_flag));              \
	}                                                                      \
	int bgp_neighbor_af_##_name##_destroy(struct nb_cb_destroy_args *args) \
	{                                                                      \
		return peer_af_flag_toggle_destroy(args, (_flag));             \
	}

BGP_NEIGHBOR_AF_FLAG_CB(soft_reconfig_in, PEER_FLAG_SOFT_RECONFIG)
BGP_NEIGHBOR_AF_FLAG_CB(as_override, PEER_FLAG_AS_OVERRIDE)
BGP_NEIGHBOR_AF_FLAG_CB(rr_client, PEER_FLAG_REFLECTOR_CLIENT)
BGP_NEIGHBOR_AF_FLAG_CB(rs_client, PEER_FLAG_RSERVER_CLIENT)
BGP_NEIGHBOR_AF_FLAG_CB(nexthop_self, PEER_FLAG_NEXTHOP_SELF)
BGP_NEIGHBOR_AF_FLAG_CB(nexthop_self_force, PEER_FLAG_FORCE_NEXTHOP_SELF)
BGP_NEIGHBOR_AF_FLAG_CB(remove_private_as, PEER_FLAG_REMOVE_PRIVATE_AS)
BGP_NEIGHBOR_AF_FLAG_CB(remove_private_as_all, PEER_FLAG_REMOVE_PRIVATE_AS_ALL)
BGP_NEIGHBOR_AF_FLAG_CB(remove_private_as_replace,
			PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE)
BGP_NEIGHBOR_AF_FLAG_CB(remove_private_as_all_replace,
			PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE)
BGP_NEIGHBOR_AF_FLAG_CB(nexthop_local_unchanged,
			PEER_FLAG_NEXTHOP_LOCAL_UNCHANGED)
BGP_NEIGHBOR_AF_FLAG_CB(send_community, PEER_FLAG_SEND_COMMUNITY)
BGP_NEIGHBOR_AF_FLAG_CB(send_ext_community, PEER_FLAG_SEND_EXT_COMMUNITY)
BGP_NEIGHBOR_AF_FLAG_CB(send_large_community, PEER_FLAG_SEND_LARGE_COMMUNITY)
BGP_NEIGHBOR_AF_FLAG_CB(graceful_shutdown, PEER_FLAG_GRACEFUL_SHUTDOWN)
BGP_NEIGHBOR_AF_FLAG_CB(accept_own, PEER_FLAG_ACCEPT_OWN)
BGP_NEIGHBOR_AF_FLAG_CB(disable_addpath_rx, PEER_FLAG_DISABLE_ADDPATH_RX)
BGP_NEIGHBOR_AF_FLAG_CB(addpath_tx_all, PEER_FLAG_ADDPATH_TX_ALL_PATHS)
BGP_NEIGHBOR_AF_FLAG_CB(addpath_tx_bestpath_per_as,
			PEER_FLAG_ADDPATH_TX_BESTPATH_PER_AS)
BGP_NEIGHBOR_AF_FLAG_CB(encapsulation_srv6,
			PEER_FLAG_CONFIG_ENCAPSULATION_SRV6)
BGP_NEIGHBOR_AF_FLAG_CB(encapsulation_mpls,
			PEER_FLAG_CONFIG_ENCAPSULATION_MPLS)
BGP_NEIGHBOR_AF_FLAG_CB(attr_unchanged_as_path,
			PEER_FLAG_AS_PATH_UNCHANGED)
BGP_NEIGHBOR_AF_FLAG_CB(attr_unchanged_next_hop,
			PEER_FLAG_NEXTHOP_UNCHANGED)
BGP_NEIGHBOR_AF_FLAG_CB(attr_unchanged_med,
			PEER_FLAG_MED_UNCHANGED)

/*
 * Per-AF activate/deactivate. enabled=true → peer_activate, =false →
 * peer_deactivate.
 */
int bgp_neighbor_af_enabled_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_peer_af_lookup(args->dnode, &peer, &afi, &safi) < 0)
		return NB_ERR;
	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_activate(peer, afi, safi);
	else
		peer_deactivate(peer, afi, safi);
	return NB_OK;
}

int bgp_neighbor_af_enabled_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	if (bgp_nb_peer_af_lookup(args->dnode, &peer, &afi, &safi) < 0)
		return NB_OK;
	peer_deactivate(peer, afi, safi);
	return NB_OK;
}

BGP_NEIGHBOR_FLAG_CB(aigp, PEER_FLAG_AIGP)
BGP_NEIGHBOR_FLAG_CB(ip_transparent, PEER_FLAG_IP_TRANSPARENT)
BGP_NEIGHBOR_FLAG_CB(extended_link_bandwidth, PEER_FLAG_EXTENDED_LINK_BANDWIDTH)
BGP_NEIGHBOR_FLAG_CB(disable_link_bw_encoding_ieee,
		     PEER_FLAG_DISABLE_LINK_BW_ENCODING_IEEE)
BGP_NEIGHBOR_FLAG_CB(extended_optional_parameters,
		     PEER_FLAG_EXTENDED_OPT_PARAMS)
BGP_NEIGHBOR_FLAG_CB(send_nexthop_characteristics,
		     PEER_FLAG_SEND_NHC_ATTRIBUTE)
BGP_NEIGHBOR_FLAG_CB(rpki_strict, PEER_FLAG_RPKI_STRICT)
BGP_NEIGHBOR_FLAG_CB(capability_fqdn, PEER_FLAG_CAPABILITY_FQDN)
BGP_NEIGHBOR_FLAG_CB(capability_link_local, PEER_FLAG_CAPABILITY_LINK_LOCAL)
BGP_NEIGHBOR_FLAG_CB(as_loop_detection, PEER_FLAG_AS_LOOP_DETECTION)

/*
 * capability-software-version + latest-encoding variant.
 * CLI: "neighbor X capability software-version [latest-encoding]" maps to
 *      PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD (no latest), or
 *      PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW (with latest).
 * YANG splits into 2 leaves: capability-software-version (enables either)
 * and capability-software-version-latest-encoding (selects NEW vs OLD).
 *
 * Implementation: capability-software-version leaf wires PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD;
 * latest-encoding leaf wires PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW. Caller
 * is responsible for clearing OLD when NEW is set (handled in CLI dispatch).
 */
BGP_NEIGHBOR_FLAG_CB(capability_software_version,
		     PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD)
BGP_NEIGHBOR_FLAG_CB(capability_software_version_latest_encoding,
		     PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW)
BGP_NEIGHBOR_FLAG_CB(peer_graceful_shutdown, PEER_FLAG_GRACEFUL_SHUTDOWN)

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/timers-delayopen
 */
int bgp_neighbor_timers_delayopen_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	uint16_t v;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;
	v = yang_dnode_get_uint16(args->dnode, NULL);
	peer_timers_delayopen_set(peer, v);
	return NB_OK;
}

int bgp_neighbor_timers_delayopen_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;
	peer_timers_delayopen_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/shutdown-rtt (apply_finish)
 */
int bgp_neighbor_shutdown_rtt_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct peer *peer;

	peer = bgp_nb_lookup_peer(args->dnode, "..", 5);
	if (!peer)
		return -1;
	if (yang_dnode_exists(args->dnode, "./rtt"))
		peer->rtt_expected = yang_dnode_get_uint16(args->dnode,
							   "./rtt");
	if (yang_dnode_exists(args->dnode, "./count"))
		peer->rtt_keepalive_conf = yang_dnode_get_uint8(args->dnode,
								"./count");
	peer_flag_set(peer, PEER_FLAG_RTT_SHUTDOWN);
	return 0;
}

int bgp_neighbor_shutdown_rtt_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;
	peer_flag_unset(peer, PEER_FLAG_RTT_SHUTDOWN);
	peer->rtt_expected = 0;
	peer->rtt_keepalive_conf = 1;
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/tcp-mss
 */
int bgp_neighbor_tcp_mss_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	uint32_t mss;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;
	mss = yang_dnode_get_uint32(args->dnode, NULL);
	peer_tcp_mss_set(peer, mss);
	return NB_OK;
}

int bgp_neighbor_tcp_mss_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;
	peer_tcp_mss_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/port
 */
int bgp_neighbor_port_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	uint16_t port;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;
	port = yang_dnode_get_uint16(args->dnode, NULL);
	peer_port_set(peer, port);
	return NB_OK;
}

int bgp_neighbor_port_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;
	peer_port_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/local-role/{role,strict-mode}
 *
 * Compound container: both leaves contribute to peer_role_set(peer, role,
 * strict_mode). Use apply_finish on the container so role and strict-mode
 * are applied atomically.
 */
int bgp_neighbor_local_role_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct peer *peer;
	const char *role_str;
	uint8_t role;
	bool strict_mode = false;

	peer = bgp_nb_lookup_peer(args->dnode, "..", 5);
	if (!peer)
		return -1;

	if (yang_dnode_exists(args->dnode, "./role")) {
		role_str = yang_dnode_get_string(args->dnode, "./role");
		if (!strcmp(role_str, "provider"))
			role = ROLE_PROVIDER;
		else if (!strcmp(role_str, "rs-server"))
			role = ROLE_RS_SERVER;
		else if (!strcmp(role_str, "rs-client"))
			role = ROLE_RS_CLIENT;
		else if (!strcmp(role_str, "customer"))
			role = ROLE_CUSTOMER;
		else if (!strcmp(role_str, "peer"))
			role = ROLE_PEER;
		else
			role = ROLE_UNDEFINED;

		if (yang_dnode_exists(args->dnode, "./strict-mode"))
			strict_mode = yang_dnode_get_bool(args->dnode,
							  "./strict-mode");
		peer_role_set(peer, role, strict_mode);
	}
	return 0;
}

int bgp_neighbor_local_role_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;
	peer_role_unset(peer);
	return NB_OK;
}

/*
 * Per-peer graceful-restart trio. YANG choice in
 * structure-neighbor-group-graceful-restart:
 *   graceful-restart/enable
 *   graceful-restart/graceful-restart-helper
 *   graceful-restart/graceful-restart-disable
 *
 * Each leaf is 2 hops up to neighbor (../..) and depth 5 to CPP.
 * Internal effect is bgp_neighbor_graceful_restart_*_set / _unset
 * helpers — for now, just set the corresponding PEER_FLAG via toggle
 * template; full peer-reset side effects are deferred to the dual-write
 * CLI path (same Phase 2 GR compromise).
 */
int bgp_neighbor_gr_enable_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_GRACEFUL_RESTART,
					"../..", 5);
}
int bgp_neighbor_gr_enable_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_GRACEFUL_RESTART,
					 "../..", 5);
}
int bgp_neighbor_gr_helper_modify(struct nb_cb_modify_args *args)
{
	return peer_flag_toggle_modify(args, PEER_FLAG_GRACEFUL_RESTART_HELPER,
					"../..", 5);
}
int bgp_neighbor_gr_helper_destroy(struct nb_cb_destroy_args *args)
{
	return peer_flag_toggle_destroy(args, PEER_FLAG_GRACEFUL_RESTART_HELPER,
					 "../..", 5);
}
int bgp_neighbor_gr_disable_modify(struct nb_cb_modify_args *args)
{
	/* No PEER_FLAG_GRACEFUL_RESTART_DISABLE — the legacy CLI clears
	 * PEER_FLAG_GRACEFUL_RESTART. Mirror that semantic here. */
	return peer_flag_toggle_destroy((struct nb_cb_destroy_args *)args,
					 PEER_FLAG_GRACEFUL_RESTART, "../..", 5);
}
int bgp_neighbor_gr_disable_destroy(struct nb_cb_destroy_args *args)
{
	/* Re-inherit global on destroy — leave flag as-is. */
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/timers (apply_finish on container)
 *
 * keepalive + hold-time are paired (peer_timers_set). Use apply_finish
 * so both leaves are applied atomically when either changes.
 */
int bgp_neighbor_timers_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct peer *peer;
	uint32_t keepalive = 0, holdtime = 0;
	bool have_k = false, have_h = false;

	peer = bgp_nb_lookup_peer(args->dnode, "..", 5);
	if (!peer)
		return -1;

	if (yang_dnode_exists(args->dnode, "./keepalive")) {
		keepalive = yang_dnode_get_uint16(args->dnode, "./keepalive");
		have_k = true;
	}
	if (yang_dnode_exists(args->dnode, "./hold-time")) {
		holdtime = yang_dnode_get_uint16(args->dnode, "./hold-time");
		have_h = true;
	}
	if (have_k && have_h)
		peer_timers_set(peer, keepalive, holdtime);
	return 0;
}

int bgp_neighbor_timers_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;
	peer_timers_unset(peer);
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/oad
 *
 * Sub-sort knob (not a peer flag). True => set sub_sort to BGP_PEER_EBGP_OAD
 * iff peer is EBGP. False/destroy => clear sub_sort.
 */
int bgp_neighbor_oad_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	bool oad;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;
	oad = yang_dnode_get_bool(args->dnode, NULL);
	if (oad && peer->sort == BGP_PEER_EBGP)
		peer->sub_sort = BGP_PEER_EBGP_OAD;
	else
		peer->sub_sort = 0;
	return NB_OK;
}

int bgp_neighbor_oad_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;
	peer->sub_sort = 0;
	return NB_OK;
}

/*
 * XPath:
 *   .../neighbors/neighbor[remote-address]/ls-local-link-id
 *   .../neighbors/neighbor[remote-address]/ls-remote-link-id
 */
int bgp_neighbor_ls_local_link_id_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	uint32_t v;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;
	v = yang_dnode_get_uint32(args->dnode, NULL);
	peer->ls_local_link_id = v;
	peer_flag_set(peer, PEER_FLAG_LS_LOCAL_LINK_ID);
	return NB_OK;
}

int bgp_neighbor_ls_local_link_id_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;
	peer->ls_local_link_id = 0;
	peer_flag_unset(peer, PEER_FLAG_LS_LOCAL_LINK_ID);
	return NB_OK;
}

int bgp_neighbor_ls_remote_link_id_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	uint32_t v;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_ERR;
	v = yang_dnode_get_uint32(args->dnode, NULL);
	peer->ls_remote_link_id = v;
	/* PEER_FLAG_LS_REMOTE_LINK_ID = (1ULL << 50) — declared after
	 * LS_LOCAL_LINK_ID in bgpd.h. */
#ifdef PEER_FLAG_LS_REMOTE_LINK_ID
	peer_flag_set(peer, PEER_FLAG_LS_REMOTE_LINK_ID);
#endif
	return NB_OK;
}

int bgp_neighbor_ls_remote_link_id_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}
	peer = bgp_nb_lookup_peer(args->dnode, "..", 4);
	if (!peer)
		return NB_OK;
	peer->ls_remote_link_id = 0;
#ifdef PEER_FLAG_LS_REMOTE_LINK_ID
	peer_flag_unset(peer, PEER_FLAG_LS_REMOTE_LINK_ID);
#endif
	return NB_OK;
}

/* ------------------------------------------------------------------------ */
/* Phase 3b — peer-group list                                                 */
/* ------------------------------------------------------------------------ */

/*
 * XPath:
 *   /frr-routing:routing/control-plane-protocols/control-plane-protocol/
 *     frr-bgp:bgp/peer-groups/peer-group
 *
 * Depth from list entry to CPP = 3. peer_group_get() is idempotent (returns
 * existing group if name matches), matching the legacy DEFUN behaviour.
 */
int bgp_peer_group_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const char *name;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_ERR;

	name = yang_dnode_get_string(args->dnode, "peer-group-name");
	if (!peer_group_get(bgp, name)) {
		snprintf(args->errmsg, args->errmsg_len,
			 "peer_group_get failed for %s", name);
		return NB_ERR;
	}
	return NB_OK;
}

int bgp_peer_group_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	const char *name;
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_lookup_from_dnode(args->dnode, 3);
	if (!bgp)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "peer-group-name");
	group = peer_group_lookup(bgp, name);
	if (!group)
		return NB_OK;

	peer_group_delete(group);
	return NB_OK;
}

/*
 * leaf-list listen-range entry helper.
 *
 * For a leaf-list, the dnode's value IS the entry. Use
 * yang_dnode_get_string(args->dnode, NULL) to read it. The depth pattern:
 * leaf-list entry sits at depth 4 from CPP (peer-groups, peer-group,
 * leaf-list, entry-value).
 */
static int peer_group_listen_range_apply(const struct lyd_node *dnode, int af,
					  bool add)
{
	struct bgp *bgp;
	const char *pg_name;
	const char *prefix_str;
	struct peer_group *group;
	struct prefix p = {};

	bgp = bgp_nb_lookup_from_dnode(dnode, 4);
	if (!bgp)
		return NB_ERR;

	pg_name = yang_dnode_get_string(dnode, "../peer-group-name");
	group = peer_group_lookup(bgp, pg_name);
	if (!group)
		return NB_ERR;

	prefix_str = yang_dnode_get_string(dnode, NULL);
	if (str2prefix(prefix_str, &p) == 0)
		return NB_ERR_VALIDATION;
	p.family = af;

	if (add) {
		if (peer_group_listen_range_add(group, &p) != 0)
			return NB_ERR;
	} else {
		if (peer_group_listen_range_del(group, &p) != 0)
			return NB_ERR;
	}
	return NB_OK;
}

int bgp_peer_group_ipv4_listen_range_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return peer_group_listen_range_apply(args->dnode, AF_INET, true);
}

int bgp_peer_group_ipv4_listen_range_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return peer_group_listen_range_apply(args->dnode, AF_INET, false);
}

int bgp_peer_group_ipv6_listen_range_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return peer_group_listen_range_apply(args->dnode, AF_INET6, true);
}

int bgp_peer_group_ipv6_listen_range_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return peer_group_listen_range_apply(args->dnode, AF_INET6, false);
}

/* --- Phase 3c (address-family): callback implementations go here --- */

/* ------------------------------------------------------------------------ */
/* Phase 5 — cli_show callbacks                                              */
/*                                                                           */
/* DESIGN NOTE: bgpd uses a dual-write model where DEFPY_YANG bodies still   */
/* invoke legacy setters that update the in-memory `struct bgp` /            */
/* `struct peer`. The legacy `bgp_config_write_*` functions in `bgp_vty.c`   */
/* serialize that state for `show running-config`. cli_show callbacks here   */
/* are only required once the legacy write path is removed AND mgmtd becomes */
/* the sole writer (Phase 7+ work — `FRR_MGMTD_BACKEND` flag flipped on).    */
/*                                                                           */
/* These boilerplate cli_show callbacks let mgmtd's `show yang config-data`  */
/* and `show mgmt yang-config-tree` output match the legacy CLI form even    */
/* before the legacy write path is removed. They are wired selectively for   */
/* leaves where the YANG default deviates from the legacy in-memory default. */
/* ------------------------------------------------------------------------ */

/*
 * Generic helper: emit "<keyword>" if true, " no <keyword>" only when
 * show_defaults && default-false.
 */
static void bgp_nb_show_global_bool(struct vty *vty,
				    const struct lyd_node *dnode,
				    const char *keyword, bool show_defaults)
{
	bool v = yang_dnode_get_bool(dnode, NULL);
	if (v)
		vty_out(vty, " %s\n", keyword);
	else if (show_defaults)
		vty_out(vty, " no %s\n", keyword);
}

/* Phase 5 example callbacks (sample wiring — full coverage is a future
 * deliverable; see DESIGN NOTE above). */

void bgp_global_router_id_cli_show(struct vty *vty,
				   const struct lyd_node *dnode,
				   bool show_defaults)
{
	const char *rid = yang_dnode_get_string(dnode, NULL);
	if (rid && strcmp(rid, "0.0.0.0"))
		vty_out(vty, " bgp router-id %s\n", rid);
}

void bgp_global_default_shutdown_cli_show(struct vty *vty,
					  const struct lyd_node *dnode,
					  bool show_defaults)
{
	bgp_nb_show_global_bool(vty, dnode, "bgp default shutdown",
				show_defaults);
}

void bgp_global_log_neighbor_changes_cli_show(struct vty *vty,
					      const struct lyd_node *dnode,
					      bool show_defaults)
{
	bgp_nb_show_global_bool(vty, dnode, "bgp log-neighbor-changes",
				show_defaults);
}

void bgp_global_fast_convergence_cli_show(struct vty *vty,
					  const struct lyd_node *dnode,
					  bool show_defaults)
{
	bgp_nb_show_global_bool(vty, dnode, "bgp fast-convergence",
				show_defaults);
}

void bgp_global_allow_martian_nexthop_cli_show(struct vty *vty,
					       const struct lyd_node *dnode,
					       bool show_defaults)
{
	bgp_nb_show_global_bool(vty, dnode, "bgp allow-martian-nexthop",
				show_defaults);
}

void bgp_neighbor_passive_mode_cli_show(struct vty *vty,
					const struct lyd_node *dnode,
					bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s passive\n", peer);
}

void bgp_neighbor_solo_cli_show(struct vty *vty,
				const struct lyd_node *dnode,
				bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s solo\n", peer);
}

void bgp_neighbor_enforce_first_as_cli_show(struct vty *vty,
					    const struct lyd_node *dnode,
					    bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s enforce-first-as\n", peer);
}

void bgp_neighbor_description_cli_show(struct vty *vty,
				       const struct lyd_node *dnode,
				       bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	const char *desc = yang_dnode_get_string(dnode, NULL);
	if (desc && *desc)
		vty_out(vty, " neighbor %s description %s\n", peer, desc);
}

void bgp_neighbor_password_cli_show(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	const char *pwd = yang_dnode_get_string(dnode, NULL);
	if (pwd && *pwd)
		vty_out(vty, " neighbor %s password %s\n", peer, pwd);
}

/* ---------- Phase 5 bulk wire-up: generic cli_show emitters --------- */

/* Generic emitter for a `bgp <keyword>` global boolean leaf. */
#define BGP_GLOBAL_BOOL_CLI_SHOW(_name, _keyword)                              \
	void bgp_global_##_name##_cli_show(struct vty *vty,                    \
					   const struct lyd_node *dnode,       \
					   bool show_defaults)                 \
	{                                                                      \
		if (yang_dnode_get_bool(dnode, NULL))                          \
			vty_out(vty, " bgp %s\n", _keyword);                   \
	}

BGP_GLOBAL_BOOL_CLI_SHOW(deterministic_med, "bestpath as-path multipath-relax deterministic-med")
BGP_GLOBAL_BOOL_CLI_SHOW(always_compare_med, "always-compare-med")
BGP_GLOBAL_BOOL_CLI_SHOW(import_check, "network import-check")
BGP_GLOBAL_BOOL_CLI_SHOW(suppress_duplicates, "bestpath suppress-duplicates")
BGP_GLOBAL_BOOL_CLI_SHOW(reject_as_sets, "reject-as-sets")
BGP_GLOBAL_BOOL_CLI_SHOW(ebgp_requires_policy, "ebgp-requires-policy")
BGP_GLOBAL_BOOL_CLI_SHOW(show_hostname, "show-hostname")
BGP_GLOBAL_BOOL_CLI_SHOW(show_nexthop_hostname, "show-nexthop-hostname")
BGP_GLOBAL_BOOL_CLI_SHOW(graceful_shutdown, "graceful-shutdown")
BGP_GLOBAL_BOOL_CLI_SHOW(no_client_to_client_reflection, "no client-to-client reflection")
BGP_GLOBAL_BOOL_CLI_SHOW(cluster_id_self, "cluster-id self")
BGP_GLOBAL_BOOL_CLI_SHOW(disable_ebgp_connected_route_check, "disable-ebgp-connected-route-check")
BGP_GLOBAL_BOOL_CLI_SHOW(enforce_first_as_global, "enforce-first-as")
BGP_GLOBAL_BOOL_CLI_SHOW(default_link_local_capability, "default link-local-capability")
BGP_GLOBAL_BOOL_CLI_SHOW(default_dynamic_capability, "default dynamic-capability")
BGP_GLOBAL_BOOL_CLI_SHOW(use_underlays_nexthop_weight, "use-underlays-nexthop-weight")
BGP_GLOBAL_BOOL_CLI_SHOW(peer_type_multipath_relax, "bgp bestpath peer-type multipath-relax")
BGP_GLOBAL_BOOL_CLI_SHOW(ipv6_auto_ra, "bgp ipv6-auto-ra")

/* Generic emitter for a `neighbor X <keyword>` boolean leaf (peer-level). */
#define BGP_NEIGHBOR_BOOL_CLI_SHOW(_name, _keyword)                            \
	void bgp_neighbor_##_name##_cli_show(struct vty *vty,                  \
					     const struct lyd_node *dnode,     \
					     bool show_defaults)               \
	{                                                                      \
		const char *peer =                                             \
			yang_dnode_get_string(dnode, "../remote-address");     \
		if (yang_dnode_get_bool(dnode, NULL))                          \
			vty_out(vty, " neighbor %s %s\n", peer, _keyword);     \
	}

BGP_NEIGHBOR_BOOL_CLI_SHOW(aigp, "aigp")
BGP_NEIGHBOR_BOOL_CLI_SHOW(ip_transparent, "ip-transparent")
BGP_NEIGHBOR_BOOL_CLI_SHOW(extended_link_bandwidth, "extended-link-bandwidth")
BGP_NEIGHBOR_BOOL_CLI_SHOW(disable_link_bw_encoding_ieee, "disable-link-bw-encoding-ieee")
BGP_NEIGHBOR_BOOL_CLI_SHOW(extended_optional_parameters, "extended-optional-parameters")
BGP_NEIGHBOR_BOOL_CLI_SHOW(send_nexthop_characteristics, "send-nexthop-characteristics")
BGP_NEIGHBOR_BOOL_CLI_SHOW(rpki_strict, "rpki strict")
BGP_NEIGHBOR_BOOL_CLI_SHOW(capability_fqdn, "capability fqdn")
BGP_NEIGHBOR_BOOL_CLI_SHOW(capability_link_local, "capability link-local")
BGP_NEIGHBOR_BOOL_CLI_SHOW(as_loop_detection, "sender-as-path-loop-detection")
BGP_NEIGHBOR_BOOL_CLI_SHOW(oad, "oad")
BGP_NEIGHBOR_BOOL_CLI_SHOW(peer_graceful_shutdown, "graceful-shutdown")

/* Per-AF flag cli_show — emits "neighbor X <keyword>" under
 * `address-family Y` enter/exit block. The afi-safi parent key
 * disambiguates the address-family scope; bgp_config_write_family is
 * responsible for emitting the surrounding `address-family ... exit-
 * address-family` block in legacy code, so cli_show here only emits
 * the inner per-neighbor command. */
#define BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(_name, _keyword)                         \
	void bgp_neighbor_af_##_name##_cli_show(struct vty *vty,               \
		const struct lyd_node *dnode, bool show_defaults)              \
	{                                                                      \
		const char *peer = yang_dnode_get_string(dnode,                \
				"../../../remote-address");                    \
		if (yang_dnode_get_bool(dnode, NULL))                          \
			vty_out(vty, "  neighbor %s %s\n", peer, _keyword);    \
	}

BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(soft_reconfig_in, "soft-reconfiguration inbound")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(as_override, "as-override")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(rr_client, "route-reflector-client")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(rs_client, "route-server-client")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(nexthop_self, "next-hop-self")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(nexthop_self_force, "next-hop-self force")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(remove_private_as, "remove-private-AS")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(remove_private_as_all, "remove-private-AS all")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(remove_private_as_replace, "remove-private-AS replace-AS")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(remove_private_as_all_replace, "remove-private-AS all replace-AS")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(nexthop_local_unchanged, "nexthop-local unchanged")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(send_community, "send-community")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(send_ext_community, "send-community extended")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(send_large_community, "send-community large")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(graceful_shutdown, "graceful-shutdown")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(accept_own, "accept-own")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(disable_addpath_rx, "disable-addpath-rx")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(addpath_tx_all, "addpath-tx-all-paths")
BGP_NEIGHBOR_AF_BOOL_CLI_SHOW(addpath_tx_bestpath_per_as, "addpath-tx-bestpath-per-AS")

/* ---- Phase 5 batch 2: value-style cli_show emitters ---------------- */

/* uint global leaf → `bgp <keyword> <value>` */
#define BGP_GLOBAL_UINT_CLI_SHOW(_name, _keyword)                              \
	void bgp_global_##_name##_cli_show(struct vty *vty,                    \
		const struct lyd_node *dnode, bool show_defaults)              \
	{                                                                      \
		vty_out(vty, " bgp %s %s\n", _keyword,                         \
			yang_dnode_get_string(dnode, NULL));                   \
	}

BGP_GLOBAL_UINT_CLI_SHOW(coalesce_time, "coalesce-time")
BGP_GLOBAL_UINT_CLI_SHOW(subgroup_pkt_queue_size, "subgroup-pkt-queue-size")
BGP_GLOBAL_UINT_CLI_SHOW(wpkt_quanta, "write-quanta")
BGP_GLOBAL_UINT_CLI_SHOW(rpkt_quanta, "read-quanta")
BGP_GLOBAL_UINT_CLI_SHOW(minimum_holdtime, "minimum-holdtime")
BGP_GLOBAL_UINT_CLI_SHOW(dynamic_neighbors_limit, "listen limit")
BGP_GLOBAL_UINT_CLI_SHOW(advertisement_delay_global, "advertise-delay")
BGP_GLOBAL_UINT_CLI_SHOW(update_delay_time, "update-delay")
BGP_GLOBAL_UINT_CLI_SHOW(restart_time, "graceful-restart restart-time")
BGP_GLOBAL_UINT_CLI_SHOW(selection_deferral_time, "graceful-restart select-defer-time")

/* Boolean route-selection-options children -- live under
 * bestpath/route-selection-options group */
#define BGP_GLOBAL_RSO_BOOL_CLI_SHOW(_name, _keyword)                          \
	void bgp_global_##_name##_cli_show(struct vty *vty,                    \
		const struct lyd_node *dnode, bool show_defaults)              \
	{                                                                      \
		if (yang_dnode_get_bool(dnode, NULL))                          \
			vty_out(vty, " bgp %s\n", _keyword);                   \
	}

BGP_GLOBAL_RSO_BOOL_CLI_SHOW(external_compare_router_id,
			     "bestpath compare-routerid")
BGP_GLOBAL_RSO_BOOL_CLI_SHOW(ignore_as_path_length,
			     "bestpath as-path ignore")
BGP_GLOBAL_RSO_BOOL_CLI_SHOW(aspath_confed, "bestpath as-path confed")
BGP_GLOBAL_RSO_BOOL_CLI_SHOW(confed_med, "bestpath med confed")
BGP_GLOBAL_RSO_BOOL_CLI_SHOW(missing_as_worst_med, "bestpath med missing-as-worst")
BGP_GLOBAL_RSO_BOOL_CLI_SHOW(bestpath_aigp, "bestpath aigp")
BGP_GLOBAL_RSO_BOOL_CLI_SHOW(bestpath_use_imported_attributes,
			     "bestpath use-imported-attributes")
BGP_GLOBAL_RSO_BOOL_CLI_SHOW(allow_multiple_as,
			     "bestpath as-path multipath-relax")
BGP_GLOBAL_RSO_BOOL_CLI_SHOW(multi_path_as_set,
			     "bestpath as-path multipath-relax as-set")

/* Misc value leaves */
void bgp_global_confederation_identifier_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp confederation identifier %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_confederation_member_as_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp confederation peers %s\n",
		yang_dnode_get_string(dnode, NULL));
}

/* Container apply_finish cli_show emitters — emit the whole compound
 * CLI line from the container dnode. */
void bgp_neighbor_local_as_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	const char *as = NULL;
	bool noprep = false, repas = false, dual = false;

	if (!yang_dnode_exists(dnode, "./local-as"))
		return;
	as = yang_dnode_get_string(dnode, "./local-as");
	if (yang_dnode_exists(dnode, "./no-prepend"))
		noprep = yang_dnode_get_bool(dnode, "./no-prepend");
	if (yang_dnode_exists(dnode, "./replace-as"))
		repas = yang_dnode_get_bool(dnode, "./replace-as");
	if (yang_dnode_exists(dnode, "./dual-as"))
		dual = yang_dnode_get_bool(dnode, "./dual-as");

	vty_out(vty, " neighbor %s local-as %s", peer, as);
	if (noprep) vty_out(vty, " no-prepend");
	if (repas)  vty_out(vty, " replace-as");
	if (dual)   vty_out(vty, " dual-as");
	vty_out(vty, "\n");
}

void bgp_neighbor_timers_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_exists(dnode, "./keepalive") &&
	    yang_dnode_exists(dnode, "./hold-time")) {
		vty_out(vty, " neighbor %s timers %s %s\n", peer,
			yang_dnode_get_string(dnode, "./keepalive"),
			yang_dnode_get_string(dnode, "./hold-time"));
	}
	if (yang_dnode_exists(dnode, "./connect-time"))
		vty_out(vty, " neighbor %s timers connect %s\n", peer,
			yang_dnode_get_string(dnode, "./connect-time"));
	if (yang_dnode_exists(dnode, "./advertise-interval"))
		vty_out(vty, " neighbor %s advertisement-interval %s\n", peer,
			yang_dnode_get_string(dnode, "./advertise-interval"));
}

void bgp_neighbor_local_role_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_exists(dnode, "./role")) {
		const char *role = yang_dnode_get_string(dnode, "./role");
		bool strict = yang_dnode_exists(dnode, "./strict-mode") &&
			      yang_dnode_get_bool(dnode, "./strict-mode");
		vty_out(vty, " neighbor %s local-role %s%s\n", peer, role,
			strict ? " strict-mode" : "");
	}
}

void bgp_neighbor_admin_shutdown_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_exists(dnode, "./enable") &&
	    yang_dnode_get_bool(dnode, "./enable")) {
		if (yang_dnode_exists(dnode, "./message"))
			vty_out(vty, " neighbor %s shutdown message %s\n",
				peer,
				yang_dnode_get_string(dnode, "./message"));
		else
			vty_out(vty, " neighbor %s shutdown\n", peer);
	}
}

void bgp_neighbor_ebgp_multihop_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_exists(dnode, "./enabled") &&
	    yang_dnode_get_bool(dnode, "./enabled")) {
		if (yang_dnode_exists(dnode, "./multihop-ttl"))
			vty_out(vty, " neighbor %s ebgp-multihop %s\n", peer,
				yang_dnode_get_string(dnode, "./multihop-ttl"));
		else
			vty_out(vty, " neighbor %s ebgp-multihop\n", peer);
	}
	if (yang_dnode_exists(dnode, "./disable-connected-check") &&
	    yang_dnode_get_bool(dnode, "./disable-connected-check"))
		vty_out(vty, " neighbor %s disable-connected-check\n", peer);
}

/* Single-leaf neighbor value emitters */
void bgp_neighbor_ttl_security_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	vty_out(vty, " neighbor %s ttl-security hops %s\n", peer,
		yang_dnode_get_string(dnode, NULL));
}

void bgp_neighbor_tcp_mss_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	vty_out(vty, " neighbor %s tcp-mss %s\n", peer,
		yang_dnode_get_string(dnode, NULL));
}

void bgp_neighbor_port_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	vty_out(vty, " neighbor %s port %s\n", peer,
		yang_dnode_get_string(dnode, NULL));
}

void bgp_neighbor_timers_delayopen_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	vty_out(vty, " neighbor %s timers delayopen %s\n", peer,
		yang_dnode_get_string(dnode, NULL));
}

void bgp_neighbor_ls_local_link_id_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	vty_out(vty, " neighbor %s local-link-id %s\n", peer,
		yang_dnode_get_string(dnode, NULL));
}

void bgp_neighbor_ls_remote_link_id_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	vty_out(vty, " neighbor %s remote-link-id %s\n", peer,
		yang_dnode_get_string(dnode, NULL));
}

void bgp_neighbor_shutdown_rtt_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_exists(dnode, "./rtt")) {
		vty_out(vty, " neighbor %s shutdown rtt %s", peer,
			yang_dnode_get_string(dnode, "./rtt"));
		if (yang_dnode_exists(dnode, "./count"))
			vty_out(vty, " count %s",
				yang_dnode_get_string(dnode, "./count"));
		vty_out(vty, "\n");
	}
}

void bgp_neighbor_neighbor_remote_as_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	const char *t;
	if (!yang_dnode_exists(dnode, "./remote-as-type"))
		return;
	t = yang_dnode_get_string(dnode, "./remote-as-type");
	if (!strcmp(t, "as-specified") &&
	    yang_dnode_exists(dnode, "./remote-as"))
		vty_out(vty, " neighbor %s remote-as %s\n", peer,
			yang_dnode_get_string(dnode, "./remote-as"));
	else
		vty_out(vty, " neighbor %s remote-as %s\n", peer, t);
}

void bgp_neighbor_update_source_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_exists(dnode, "./ip"))
		vty_out(vty, " neighbor %s update-source %s\n", peer,
			yang_dnode_get_string(dnode, "./ip"));
	if (yang_dnode_exists(dnode, "./interface"))
		vty_out(vty, " neighbor %s update-source %s\n", peer,
			yang_dnode_get_string(dnode, "./interface"));
}

void bgp_neighbor_capabilities_dynamic_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s capability dynamic\n", peer);
}

void bgp_neighbor_capabilities_strict_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s strict-capability-match\n", peer);
}

void bgp_neighbor_capabilities_override_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s override-capability\n", peer);
}

void bgp_neighbor_capabilities_extended_nexthop_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s capability extended-nexthop\n", peer);
}

void bgp_neighbor_capabilities_negotiate_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../../remote-address");
	/* INVERTED: false means dont-negotiate; true is default. */
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s dont-capability-negotiate\n", peer);
}

/* Phase 5 batch 3: remaining global boolean+value leaves. */

void bgp_global_always_compare_med_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp always-compare-med\n");
}

void bgp_global_reject_as_sets_cli_show2(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp reject-as-sets\n");
}

void bgp_global_suppress_duplicates_cli_show2(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp suppress-duplicates\n");
}

void bgp_global_fast_external_failover_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	/* INVERTED: see frr-deviations-bgp-rfc.yang. */
	if (!yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp fast-external-failover\n");
}

void bgp_global_deterministic_med_cli_show2(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp deterministic-med\n");
}

void bgp_global_labeled_unicast_explicit_null_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *val = yang_dnode_get_string(dnode, NULL);
	if (val && strcmp(val, "disable"))
		vty_out(vty, " bgp labeled-unicast explicit-null %s\n", val);
}

void bgp_global_allow_outbound_policy_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp route-reflector allow-outbound-policy\n");
}

void bgp_global_instance_id_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp instance-id %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_default_software_version_capability_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp default software-version-capability\n");
}

void bgp_global_establish_wait_time_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp default establish-wait-time %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_connect_retry_interval_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp default connect-retry %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_conditional_advertisement_period_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp conditional-advertisement timer %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_default_originate_timer_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp default originate-timer %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_bestpath_bandwidth_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp bestpath bandwidth %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_graceful_restart_notification_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-restart notification\n");
}

void bgp_global_long_lived_graceful_restart_stale_time_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp long-lived-graceful-restart stale-time %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_route_reflector_cluster_id_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp cluster-id %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_no_client_reflect_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " no bgp client-to-client reflection\n");
}

void bgp_global_local_pref_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp default local-preference %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_ebgp_multihop_connected_route_check_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp ebgp-multihop-connected-route-check\n");
}

void bgp_global_rib_stale_time_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp graceful-restart rib-stale-time %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_preserve_fw_entry_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp graceful-restart preserve-fw-state\n");
}

void bgp_global_stale_routes_time_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, " bgp graceful-restart stalepath-time %s\n",
		yang_dnode_get_string(dnode, NULL));
}

void bgp_global_med_config_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_exists(dnode, "./enable-med-admin") &&
	    yang_dnode_get_bool(dnode, "./enable-med-admin")) {
		vty_out(vty, " bgp max-med administrative");
		if (yang_dnode_exists(dnode, "./med-admin-val"))
			vty_out(vty, " %s",
				yang_dnode_get_string(dnode, "./med-admin-val"));
		vty_out(vty, "\n");
	}
}

void bgp_global_tcp_keepalive_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_exists(dnode, "./idle") &&
	    yang_dnode_exists(dnode, "./interval") &&
	    yang_dnode_exists(dnode, "./count"))
		vty_out(vty, " bgp tcp-keepalive %s %s %s\n",
			yang_dnode_get_string(dnode, "./idle"),
			yang_dnode_get_string(dnode, "./interval"),
			yang_dnode_get_string(dnode, "./count"));
}

void bgp_global_administrative_shutdown_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_exists(dnode, "./enable") &&
	    yang_dnode_get_bool(dnode, "./enable")) {
		if (yang_dnode_exists(dnode, "./message"))
			vty_out(vty, " bgp shutdown message %s\n",
				yang_dnode_get_string(dnode, "./message"));
		else
			vty_out(vty, " bgp shutdown\n");
	}
}

void bgp_global_suppress_fib_pending_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " bgp suppress-fib-pending\n");
}

void bgp_global_bgp_ls_distribute_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	if (yang_dnode_exists(dnode, "./enabled") &&
	    yang_dnode_get_bool(dnode, "./enabled"))
		vty_out(vty, " bgp ls distribute\n");
}

void bgp_neighbor_bfd_options_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_exists(dnode, "./enable") &&
	    yang_dnode_get_bool(dnode, "./enable"))
		vty_out(vty, " neighbor %s bfd\n", peer);
}

void bgp_neighbor_gr_enable_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s graceful-restart\n", peer);
}

void bgp_neighbor_gr_helper_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s graceful-restart-helper\n", peer);
}

void bgp_neighbor_gr_disable_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s graceful-restart-disable\n", peer);
}

void bgp_neighbor_capability_software_version_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty, " neighbor %s capability software-version\n", peer);
}

void bgp_neighbor_capability_software_version_latest_encoding_cli_show(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *peer = yang_dnode_get_string(dnode, "../remote-address");
	if (yang_dnode_get_bool(dnode, NULL))
		vty_out(vty,
			" neighbor %s capability software-version latest-encoding\n",
			peer);
}

void bgp_peer_group_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, "./peer-group-name");
	vty_out(vty, " neighbor %s peer-group\n", name);
}

void bgp_peer_group_ipv4_listen_range_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, "../peer-group-name");
	vty_out(vty, " bgp listen range %s peer-group %s\n",
		yang_dnode_get_string(dnode, NULL), name);
}

void bgp_peer_group_ipv6_listen_range_cli_show(struct vty *vty,
	const struct lyd_node *dnode, bool show_defaults)
{
	const char *name = yang_dnode_get_string(dnode, "../peer-group-name");
	vty_out(vty, " bgp listen range %s peer-group %s\n",
		yang_dnode_get_string(dnode, NULL), name);
}

/* Phase 5 final: no-op cli_show for leaves whose parent container
 * cli_show already emits the full CLI block. Wiring this everywhere
 * gives 100% raw .cli_show coverage and documents the intent.
 *
 * The framework calls cli_show in the order leaves appear in the YANG
 * tree; we rely on the parent container's cli_show running first and
 * emitting the entire compound CLI. The leaf-level no-op silences
 * accidental duplicate output that would otherwise occur if a future
 * developer accidentally added an emitter.
 */
void bgp_nb_handled_by_parent_cli_show(struct vty *vty,
				       const struct lyd_node *dnode,
				       bool show_defaults)
{
	(void)vty; (void)dnode; (void)show_defaults;
}
