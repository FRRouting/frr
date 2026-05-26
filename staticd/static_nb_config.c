// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018        Vmware
 *                           Vishal Dhingra
 */
#include <zebra.h>

#include "northbound.h"
#include "libfrr.h"
#include "log.h"
#include "lib_errors.h"
#include "prefix.h"
#include "table.h"
#include "vrf.h"
#include "nexthop.h"
#include "srcdest_table.h"

#include "static_vrf.h"
#include "static_routes.h"
#include "static_nb.h"
#include "static_zebra.h"

#include "static_srv6.h"
#include "static_debug.h"

/* Accumulator passed to path_list_ecmp_iter_cb() to count nexthops in the
 * same ECMP group (those sharing table-id, distance, and metric) and track
 * whether the group contains blackhole or non-blackhole nexthops.
 */
struct path_list_ecmp_check {
	uint32_t table_id;
	uint8_t distance;
	uint32_t metric;
	uint32_t count;
	bool has_blackhole;
	bool has_non_blackhole;
};

static int path_list_ecmp_iter_cb(const struct lyd_node *dnode, void *arg)
{
	struct path_list_ecmp_check *ec = arg;
	enum static_nh_type nh_type;

	if (yang_dnode_get_uint32(dnode, "table-id") != ec->table_id ||
	    yang_dnode_get_uint8(dnode, "distance") != ec->distance ||
	    yang_dnode_get_uint32(dnode, "metric") != ec->metric)
		return YANG_ITER_CONTINUE;

	ec->count++;
	nh_type = yang_dnode_get_enum(dnode, "nh-type");
	if (nh_type == STATIC_BLACKHOLE)
		ec->has_blackhole = true;
	else
		ec->has_non_blackhole = true;

	return YANG_ITER_CONTINUE;
}

/*
 * Validate ECMP constraints for the path-list entry at path_list_dnode.
 * Counts existing nexthops in the same ECMP group (same table-id, distance,
 * and metric) and rejects blackhole/non-blackhole mixing or exceeding the
 * ECMP limit.  Called from NB_EV_VALIDATE in path-list create,
 * distance_modify, and metric_modify.
 */
static int ecmp_path_list_validate(const struct lyd_node *path_list_dnode, char *errmsg,
				   size_t errmsg_len)
{
	struct path_list_ecmp_check ec = {
		.table_id = yang_dnode_get_uint32(path_list_dnode, "table-id"),
		.distance = yang_dnode_get_uint8(path_list_dnode, "distance"),
		.metric = yang_dnode_get_uint32(path_list_dnode, "metric"),
	};
	const struct lyd_node *route_dnode;
	enum static_nh_type nh_type;

	route_dnode = yang_dnode_get_parent(path_list_dnode, "route-list");
	yang_dnode_iterate(path_list_ecmp_iter_cb, &ec, route_dnode, "./path-list");

	nh_type = yang_dnode_get_enum(path_list_dnode, "nh-type");
	if (nh_type == STATIC_BLACKHOLE && ec.has_non_blackhole) {
		snprintf(errmsg, errmsg_len,
			 "Route cannot have blackhole and non-blackhole nexthops simultaneously");
		return NB_ERR_VALIDATION;
	}
	if (nh_type != STATIC_BLACKHOLE && ec.has_blackhole) {
		snprintf(errmsg, errmsg_len,
			 "Route cannot have blackhole and non-blackhole nexthops simultaneously");
		return NB_ERR_VALIDATION;
	}
	if (ec.count > zebra_ecmp_count) {
		snprintf(errmsg, errmsg_len, "Route cannot have more than %u ECMP nexthops",
			 zebra_ecmp_count);
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

static int static_path_list_create(struct nb_cb_create_args *args)
{
	struct route_node *rn;
	struct static_path *pn;
	struct static_nexthop *nh;
	const struct lyd_node *vrf_dnode;
	const char *vrf;
	uint8_t distance;
	uint32_t metric;
	uint32_t table_id;
	struct ipaddr ipaddr;
	enum static_nh_type nh_type;
	const char *ifname;
	const char *nh_vrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
		vrf_dnode = yang_dnode_get_parent(args->dnode,
						  "control-plane-protocol");
		vrf = yang_dnode_get_string(vrf_dnode, "vrf");
		table_id = yang_dnode_get_uint32(args->dnode, "table-id");

		/*
		 * TableId is not applicable for VRF. Consider the case of
		 * l3mdev, there is one uint32_t space to work with.
		 * A l3mdev device points at a specific table that it
		 * relates to and a set of interfaces it belongs to.
		 */
		if (table_id && (strcmp(vrf, vrf_get_default_name()) != 0)
		    && !vrf_is_backend_netns()) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"%% table param only available when running on netns-based vrfs");
			return NB_ERR_VALIDATION;
		}
		ifname = yang_dnode_get_string(args->dnode, "interface");
		if (ifname != NULL) {
			if (strcasecmp(ifname, "Null0") == 0 || strcasecmp(ifname, "reject") == 0 ||
			    strcasecmp(ifname, "blackhole") == 0) {
				snprintf(args->errmsg, args->errmsg_len,
					 "%s: Nexthop interface name can not be from reserved keywords(Null0, reject, blackhole)",
					 ifname);
				return NB_ERR_VALIDATION;
			}
		}

		return ecmp_path_list_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		rn = nb_running_get_entry(args->dnode, NULL, true);
		distance = yang_dnode_get_uint8(args->dnode, "distance");
		metric = yang_dnode_get_uint32(args->dnode, "metric");
		table_id = yang_dnode_get_uint32(args->dnode, "table-id");
		pn = static_add_path(rn, table_id, distance, metric);

		yang_dnode_get_ip(&ipaddr, args->dnode, "gateway");
		nh_type = yang_dnode_get_enum(args->dnode, "nh-type");
		ifname = yang_dnode_get_string(args->dnode, "interface");
		nh_vrf = yang_dnode_get_string(args->dnode, "vrf");

		if (strmatch(ifname, "(null)"))
			ifname = "";

		if (!static_add_nexthop_validate(nh_vrf, nh_type, &ipaddr))
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "Warning!! Local connected address is configured as Gateway IP((%s))",
				  yang_dnode_get_string(args->dnode, "./gateway"));
		nh = static_add_nexthop(pn, nh_type, &ipaddr, ifname, nh_vrf, 0);
		nb_running_set_entry(args->dnode, nh);
		break;
	}

	return NB_OK;
}

static int static_path_list_destroy(struct nb_cb_destroy_args *args)
{
	struct static_nexthop *nh;
	struct static_path *pn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_unset_entry(args->dnode);
		pn = nh->pn;
		static_delete_nexthop(nh);
		if (static_nexthop_list_count(&pn->nexthop_list) == 0)
			static_del_path(pn);
		break;
	}

	return NB_OK;
}

static int static_path_list_tag_modify(struct nb_cb_modify_args *args)
{
	struct static_nexthop *nh;
	struct static_path *pn;
	uint32_t old_tag;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(args->dnode, NULL, true);
		pn = nh->pn;

		/*
		 * Update nh->tag and recompute pn->tag (max-wins across the
		 * path's nexthops).  Skip the install when the effective path
		 * tag is unchanged — this also makes setting the same value
		 * idempotent.
		 */
		nh->tag = yang_dnode_get_uint32(args->dnode, NULL);
		old_tag = pn->tag;
		static_path_recalc_tag(pn);
		if (pn->tag == old_tag)
			break;

		/*
		 * Do not call static_install_path() here; apply_finish()
		 * fires after all per-leaf callbacks complete and performs
		 * the single install for this path-list entry.
		 *
		 * Mark the nexthop as needing reinstall so that
		 * static_nht_update_path() issues a route ADD when
		 * apply_finish() calls static_install_nexthop() via the
		 * NHT fast path (nh->state must be STATIC_START, not
		 * STATIC_INSTALLED, for the update to reach zebra).
		 */
		nh->state = STATIC_START;
		break;
	}

	return NB_OK;
}

/*
 * Move nexthop nh from its current path to the path keyed by (table_id,
 * distance, metric).  Called by distance_modify and metric_modify when
 * the value actually changes.
 *
 * Old-path: remove nh from old_pn->nexthop_list, recalculate old_pn->tag
 * if nh carried the max tag (so remaining ECMP peers get the correct tag
 * in the route-UPDATE), uninstall via static_uninstall_nexthop(), and free
 * old_pn when it is now empty.
 *
 * New-path: find or create the target static_path, attach nh, propagate the
 * tag, and mark the nexthop for install via apply_finish().
 */
static void static_nexthop_move_path(struct static_nexthop *nh, uint8_t distance, uint32_t metric)
{
	struct static_path *old_pn = nh->pn;
	struct route_node *rn = old_pn->rn;
	uint32_t table_id = old_pn->table_id;
	struct static_path *new_pn;

	/*
	 * Remove nh from old_pn before uninstalling so that
	 * static_uninstall_nexthop() sees the correct nexthop count
	 * (sends a route delete, not an update, when nh was the last
	 * nexthop on the old path).  Recalculate old_pn->tag first:
	 * if nh carried the max tag, any remaining ECMP nexthops must
	 * get the correct tag in the route-update sent to zebra.
	 */
	static_nexthop_list_del(&old_pn->nexthop_list, nh);
	if (old_pn->tag == nh->tag)
		static_path_recalc_tag(old_pn);
	static_uninstall_nexthop(nh);
	if (static_nexthop_list_count(&old_pn->nexthop_list) == 0)
		static_del_path(old_pn);

	new_pn = static_add_path(rn, table_id, distance, metric);
	nh->pn = new_pn;
	static_nexthop_list_add_tail(&new_pn->nexthop_list, nh);
	/*
	 * Propagate the tag to the new path.  tag_modify does not
	 * re-fire, so recalculate from the nexthops now on new_pn.
	 */
	static_path_recalc_tag(new_pn);
	/*
	 * static_uninstall_nexthop() does not reset nh->state, so it
	 * can remain STATIC_INSTALLED after the old path is torn down.
	 * Reset to STATIC_START so apply_finish() → static_install_nexthop()
	 * → static_nht_update_path() issues a route ADD on the new path.
	 */
	nh->state = STATIC_START;
}

static int static_path_list_distance_modify(struct nb_cb_modify_args *args)
{
	struct static_nexthop *nh;
	const struct lyd_node *pl;
	uint8_t distance;

	switch (args->event) {
	case NB_EV_VALIDATE:
		pl = yang_dnode_get_parent(args->dnode, "path-list");
		return ecmp_path_list_validate(pl, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(args->dnode, NULL, true);
		distance = yang_dnode_get_uint8(args->dnode, NULL);
		/*
		 * distance_modify fires during initial route creation as
		 * well as on explicit distance changes.  Skip the
		 * path-move when the value has not actually changed.
		 */
		if (distance != nh->pn->distance)
			static_nexthop_move_path(nh, distance, nh->pn->metric);
		break;
	}

	return NB_OK;
}

static int static_path_list_metric_modify(struct nb_cb_modify_args *args)
{
	struct static_nexthop *nh;
	const struct lyd_node *pl;
	uint32_t metric;

	switch (args->event) {
	case NB_EV_VALIDATE:
		pl = yang_dnode_get_parent(args->dnode, "path-list");
		return ecmp_path_list_validate(pl, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(args->dnode, NULL, true);
		metric = yang_dnode_get_uint32(args->dnode, NULL);
		if (metric != nh->pn->metric)
			static_nexthop_move_path(nh, nh->pn->distance, metric);
		break;
	}

	return NB_OK;
}

static int nexthop_srv6_segs_stack_entry_create(struct nb_cb_create_args *args)
{
	struct static_nexthop *nh;
	uint32_t pos;
	uint8_t index;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(args->dnode, NULL, true);
		pos = yang_get_list_pos(args->dnode);
		if (!pos) {
			flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				  "libyang returns invalid seg position");
			return NB_ERR;
		}
		/* Mapping to array = list-index -1 */
		index = pos - 1;
		memset(&nh->snh_seg.seg[index], 0, sizeof(struct in6_addr));
		nh->snh_seg.num_segs++;
		break;
	}

	return NB_OK;
}

static int nexthop_srv6_segs_stack_entry_destroy(struct nb_cb_destroy_args *args)
{
	struct static_nexthop *nh;
	uint32_t pos;
	uint8_t index;
	int old_num_segs;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(args->dnode, NULL, true);
		pos = yang_get_list_pos(args->dnode);
		if (!pos) {
			flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				  "libyang returns invalid seg position");
			return NB_ERR;
		}
		index = pos - 1;
		old_num_segs = nh->snh_seg.num_segs;
		memset(&nh->snh_seg.seg[index], 0, sizeof(struct in6_addr));
		nh->snh_seg.num_segs--;

		if (old_num_segs != nh->snh_seg.num_segs)
			nh->state = STATIC_START;
		break;
	}

	return NB_OK;
}

static int static_nexthop_srv6_segs_modify(struct nb_cb_modify_args *args)
{
	struct static_nexthop *nh;
	uint32_t pos;
	uint8_t index;
	struct in6_addr old_seg;
	struct in6_addr cli_seg;

	nh = nb_running_get_entry(args->dnode, NULL, true);
	pos = yang_get_list_pos(lyd_parent(args->dnode));
	if (!pos) {
		flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
			  "libyang returns invalid seg position");
		return NB_ERR;
	}
	/* Mapping to array = list-index -1 */
	index = pos - 1;

	old_seg = nh->snh_seg.seg[index];
	yang_dnode_get_ipv6(&cli_seg, args->dnode, NULL);

	memcpy(&nh->snh_seg.seg[index], &cli_seg, sizeof(struct in6_addr));

	if (memcmp(&old_seg, &nh->snh_seg.seg[index],
		   sizeof(struct in6_addr)) != 0)
		nh->state = STATIC_START;

	return NB_OK;
}

static int static_nexthop_srv6_encap_behavior_modify(struct nb_cb_modify_args *args)
{
	struct static_nexthop *nh;
	enum srv6_headend_behavior old_encap_behavior;
	const char *encap_behavior_str;

	switch (args->event) {
	case NB_EV_VALIDATE:
		encap_behavior_str = yang_dnode_get_string(args->dnode, NULL);
		if (!strmatch(encap_behavior_str, "ietf-srv6-types:H.Encaps") &&
		    !strmatch(encap_behavior_str, "ietf-srv6-types:H.Encaps.Red")) {
			snprintf(args->errmsg, args->errmsg_len,
				 "%% Unsupported encap behavior: %s", encap_behavior_str);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(args->dnode, NULL, true);
		old_encap_behavior = nh->snh_seg.encap_behavior;
		encap_behavior_str = yang_dnode_get_string(args->dnode, NULL);
		if (strmatch(encap_behavior_str, "ietf-srv6-types:H.Encaps"))
			nh->snh_seg.encap_behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS;
		else if (strmatch(encap_behavior_str, "ietf-srv6-types:H.Encaps.Red"))
			nh->snh_seg.encap_behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED;
		else {
			snprintf(args->errmsg, args->errmsg_len,
				 "%% Unsupported encap behavior: %s", encap_behavior_str);
			return NB_ERR;
		}

		if (old_encap_behavior != nh->snh_seg.encap_behavior)
			nh->state = STATIC_START;
		break;
	}

	return NB_OK;
}

static int static_nexthop_srv6_encap_behavior_destroy(struct nb_cb_destroy_args *args)
{
	struct static_nexthop *nh;
	enum srv6_headend_behavior old_encap_behavior;

	nh = nb_running_get_entry(args->dnode, NULL, true);
	old_encap_behavior = nh->snh_seg.encap_behavior;
	nh->snh_seg.encap_behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS;

	if (old_encap_behavior != nh->snh_seg.encap_behavior)
		nh->state = STATIC_START;

	return NB_OK;
}

static int nexthop_mpls_label_stack_entry_create(struct nb_cb_create_args *args)
{
	struct static_nexthop *nh;
	uint32_t pos;
	uint8_t index;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!mpls_enabled) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"%% MPLS not turned on in kernel ignoring static route");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(args->dnode, NULL, true);
		pos = yang_get_list_pos(args->dnode);
		if (!pos) {
			flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				  "libyang returns invalid label position");
			return NB_ERR;
		}
		/* Mapping to array = list-index -1 */
		index = pos - 1;
		nh->snh_label.label[index] = 0;
		nh->snh_label.num_labels++;
		break;
	}

	return NB_OK;
}

static int
nexthop_mpls_label_stack_entry_destroy(struct nb_cb_destroy_args *args)
{
	struct static_nexthop *nh;
	uint32_t pos;
	uint8_t index;
	uint old_num_labels;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(args->dnode, NULL, true);
		pos = yang_get_list_pos(args->dnode);
		if (!pos) {
			flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				  "libyang returns invalid label position");
			return NB_ERR;
		}
		index = pos - 1;
		old_num_labels = nh->snh_label.num_labels;
		nh->snh_label.label[index] = 0;
		nh->snh_label.num_labels--;

		if (old_num_labels != nh->snh_label.num_labels)
			nh->state = STATIC_START;
		break;
	}

	return NB_OK;
}

static int static_nexthop_mpls_label_modify(struct nb_cb_modify_args *args)
{
	struct static_nexthop *nh;
	uint32_t pos;
	uint8_t index;
	mpls_label_t old_label;

	nh = nb_running_get_entry(args->dnode, NULL, true);
	pos = yang_get_list_pos(lyd_parent(args->dnode));
	if (!pos) {
		flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
			  "libyang returns invalid label position");
		return NB_ERR;
	}
	/* Mapping to array = list-index -1 */
	index = pos - 1;

	old_label = nh->snh_label.label[index];
	nh->snh_label.label[index] = yang_dnode_get_uint32(args->dnode, NULL);

	if (old_label != nh->snh_label.label[index])
		nh->state = STATIC_START;

	return NB_OK;
}

static int static_nexthop_weight_modify(struct nb_cb_modify_args *args)
{
	struct static_nexthop *nh;
	uint16_t weight;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(args->dnode, NULL, true);
		weight = nh->weight;
		nh->weight = yang_dnode_get_uint16(args->dnode, NULL);

		if (weight != nh->weight)
			nh->state = STATIC_START;
		break;
	}

	return NB_OK;
}

static int static_nexthop_weight_destroy(struct nb_cb_destroy_args *args)
{
	struct static_nexthop *nh;
	uint16_t weight;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(args->dnode, NULL, true);
		weight = nh->weight;
		nh->weight = 0;

		if (weight != nh->weight)
			nh->state = STATIC_START;
		break;
	}

	return NB_OK;
}

static int static_nexthop_onlink_modify(struct nb_cb_modify_args *args)
{
	struct static_nexthop *nh;
	enum static_nh_type nh_type;
	bool old_onlink;

	switch (args->event) {
	case NB_EV_VALIDATE:
		nh_type = yang_dnode_get_enum(args->dnode, "../nh-type");
		if ((nh_type != STATIC_IPV4_GATEWAY_IFNAME)
		    && (nh_type != STATIC_IPV6_GATEWAY_IFNAME)) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"nexthop type is not the ipv4 or ipv6 interface type");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(args->dnode, NULL, true);
		old_onlink = nh->onlink;
		nh->onlink = yang_dnode_get_bool(args->dnode, NULL);

		if (old_onlink != nh->onlink)
			nh->state = STATIC_START;
		break;
	}

	return NB_OK;
}

static int static_nexthop_color_modify(struct nb_cb_modify_args *args)
{
	struct static_nexthop *nh;
	uint32_t old_color;

	nh = nb_running_get_entry(args->dnode, NULL, true);
	old_color = nh->color;
	nh->color = yang_dnode_get_uint32(args->dnode, NULL);

	if (old_color != nh->color)
		nh->state = STATIC_START;

	return NB_OK;
}

static int static_nexthop_color_destroy(struct nb_cb_destroy_args *args)
{
	struct static_nexthop *nh;
	uint32_t old_color;

	nh = nb_running_get_entry(args->dnode, NULL, true);
	old_color = nh->color;
	nh->color = 0;

	if (old_color != nh->color)
		nh->state = STATIC_START;

	return NB_OK;
}

static int static_nexthop_bh_type_modify(struct nb_cb_modify_args *args)
{
	struct static_nexthop *nh;
	enum static_nh_type nh_type;

	switch (args->event) {
	case NB_EV_VALIDATE:
		nh_type = yang_dnode_get_enum(args->dnode, "../nh-type");
		if (nh_type != STATIC_BLACKHOLE) {
			snprintf(args->errmsg, args->errmsg_len,
				 "nexthop type is not the blackhole type");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(args->dnode, NULL, true);
		nh->bh_type = yang_dnode_get_enum(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

void routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct static_nexthop *nh;

	nh = nb_running_get_entry(args->dnode, NULL, true);

	static_install_nexthop(nh);
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_pre_validate(
	struct nb_cb_pre_validate_args *args)
{
	const struct lyd_node *mls_dnode;
	uint32_t count;

	mls_dnode = yang_dnode_get(args->dnode, "mpls-label-stack");
	count = yang_get_list_elements_count(lyd_child(mls_dnode));

	if (count > MPLS_MAX_LABELS) {
		snprintf(args->errmsg, args->errmsg_len,
			"Too many labels, Enter %d or fewer",
			MPLS_MAX_LABELS);
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

int routing_control_plane_protocols_name_validate(
	struct nb_cb_create_args *args)
{
	const char *name;

	name = yang_dnode_get_string(args->dnode, "name");
	if (!strmatch(name, "staticd")) {
		snprintf(args->errmsg, args->errmsg_len,
			"static routing supports only one instance with name staticd");
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol
 */
int routing_control_plane_protocols_staticd_create(struct nb_cb_create_args *args)
{
	struct static_vrf *svrf;
	const char *vrf;

	vrf = yang_dnode_get_string(args->dnode, "vrf");
	svrf = static_vrf_alloc(vrf);
	nb_running_set_entry(args->dnode, svrf);

	return NB_OK;
}

int routing_control_plane_protocols_staticd_destroy(
	struct nb_cb_destroy_args *args)
{
	struct static_vrf *svrf;
	struct route_table *stable;
	struct route_node *rn;
	afi_t afi;
	safi_t safi;

	svrf = nb_running_unset_entry(args->dnode);

	FOREACH_AFI_SAFI (afi, safi) {
		stable = svrf->stable[afi][safi];
		if (!stable)
			continue;

		for (rn = route_top(stable); rn; rn = srcdest_route_next(rn))
			static_del_route(rn);
	}

	static_vrf_free(svrf);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_create(
	struct nb_cb_create_args *args)
{
	struct static_vrf *svrf;
	struct route_node *rn;
	const struct lyd_node *vrf_dnode;
	struct prefix prefix, src_prefix, *src_p;
	const char *afi_safi;
	afi_t prefix_afi;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		yang_dnode_get_prefix(&prefix, args->dnode, "prefix");
		yang_dnode_get_prefix(&src_prefix, args->dnode, "src-prefix");
		src_p = src_prefix.prefixlen ? &src_prefix : NULL;
		afi_safi = yang_dnode_get_string(args->dnode, "afi-safi");
		yang_afi_safi_identity2value(afi_safi, &afi, &safi);
		prefix_afi = family2afi(prefix.family);
		if (afi != prefix_afi) {
			flog_warn(
				EC_LIB_NB_CB_CONFIG_VALIDATE,
				"route node %s creation failed",
				yang_dnode_get_string(args->dnode, "prefix"));
			return NB_ERR_VALIDATION;
		}

		if (src_p && afi != AFI_IP6) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "invalid use of IPv6 dst-src prefix %s on %s",
				  yang_dnode_get_string(args->dnode, "src-prefix"),
				  yang_dnode_get_string(args->dnode, "prefix"));
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf_dnode = yang_dnode_get_parent(args->dnode,
						  "control-plane-protocol");
		svrf = nb_running_get_entry(vrf_dnode, NULL, true);

		yang_dnode_get_prefix(&prefix, args->dnode, "prefix");
		yang_dnode_get_prefix(&src_prefix, args->dnode, "src-prefix");
		src_p = src_prefix.prefixlen ? &src_prefix : NULL;
		afi_safi = yang_dnode_get_string(args->dnode, "afi-safi");
		yang_afi_safi_identity2value(afi_safi, &afi, &safi);

		rn = static_add_route(afi, safi, &prefix, (struct prefix_ipv6 *)src_p, svrf);
		if (!svrf->vrf || svrf->vrf->vrf_id == VRF_UNKNOWN)
			snprintf(
				args->errmsg, args->errmsg_len,
				"Static Route to %s not installed currently because dependent config not fully available",
				yang_dnode_get_string(args->dnode, "prefix"));
		nb_running_set_entry(args->dnode, rn);
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct route_node *rn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		rn = nb_running_unset_entry(args->dnode);
		static_del_route(rn);
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_create(
	struct nb_cb_create_args *args)
{
	return static_path_list_create(args);
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_destroy(
	struct nb_cb_destroy_args *args)
{
	return static_path_list_destroy(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/tag
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_tag_modify(
	struct nb_cb_modify_args *args)
{
	return static_path_list_tag_modify(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/distance
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_distance_modify(
	struct nb_cb_modify_args *args)
{
	return static_path_list_distance_modify(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/metric
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_metric_modify(
	struct nb_cb_modify_args *args)
{
	return static_path_list_metric_modify(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/bh-type
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_bh_type_modify(
	struct nb_cb_modify_args *args)
{
	return static_nexthop_bh_type_modify(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/weight
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_weight_modify(
	struct nb_cb_modify_args *args)
{
	return static_nexthop_weight_modify(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/weight
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_weight_destroy(
	struct nb_cb_destroy_args *args)
{
	return static_nexthop_weight_destroy(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/onlink
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_onlink_modify(
	struct nb_cb_modify_args *args)
{
	return static_nexthop_onlink_modify(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/srte-color
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_color_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		if (static_nexthop_color_modify(args) != NB_OK)
			return NB_ERR;

		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_color_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		if (static_nexthop_color_destroy(args) != NB_OK)
			return NB_ERR;
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/srv6-segs-stack/entry
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_srv6_segs_stack_entry_create(
	struct nb_cb_create_args *args)
{
	return nexthop_srv6_segs_stack_entry_create(args);
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_srv6_segs_stack_entry_destroy(
	struct nb_cb_destroy_args *args)
{
	return nexthop_srv6_segs_stack_entry_destroy(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/srv6-segs-stack/entry/seg
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_srv6_segs_stack_entry_seg_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		if (static_nexthop_srv6_segs_modify(args) != NB_OK)
			return NB_ERR;
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_srv6_segs_stack_entry_seg_destroy(
	struct nb_cb_destroy_args *args)
{
	/*
	 * No operation is required in this call back.
	 * nexthop_srv6_segs_stack_entry_destroy() will take care
	 * to reset the seg value.
	 */
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/srv6-segs-stack/encap-behavior
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_srv6_segs_stack_encap_behavior_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		if (static_nexthop_srv6_encap_behavior_modify(args) != NB_OK)
			return NB_ERR;
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_srv6_segs_stack_encap_behavior_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		if (static_nexthop_srv6_encap_behavior_destroy(args) != NB_OK)
			return NB_ERR;
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/mpls-label-stack/entry
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_mpls_label_stack_entry_create(
	struct nb_cb_create_args *args)
{
	return nexthop_mpls_label_stack_entry_create(args);
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_mpls_label_stack_entry_destroy(
	struct nb_cb_destroy_args *args)
{
	return nexthop_mpls_label_stack_entry_destroy(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/mpls-label-stack/entry/label
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_mpls_label_stack_entry_label_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		if (static_nexthop_mpls_label_modify(args) != NB_OK)
			return NB_ERR;
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_mpls_label_stack_entry_label_destroy(
	struct nb_cb_destroy_args *args)
{
	/*
	 * No operation is required in this call back.
	 * nexthop_mpls_label_stack_entry_destroy() will take care
	 * to reset the label value.
	 */
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/mpls-label-stack/entry/ttl
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_mpls_label_stack_entry_ttl_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_mpls_label_stack_entry_ttl_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/mpls-label-stack/entry/traffic-class
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_mpls_label_stack_entry_traffic_class_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_mpls_label_stack_entry_traffic_class_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/bfd-monitoring
 */
int route_next_hop_bfd_create(struct nb_cb_create_args *args)
{
	struct static_nexthop *sn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	sn = nb_running_get_entry(args->dnode, NULL, true);
	static_next_hop_bfd_monitor_enable(sn, args->dnode);
	return NB_OK;
}

int route_next_hop_bfd_destroy(struct nb_cb_destroy_args *args)
{
	struct static_nexthop *sn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	sn = nb_running_get_entry(args->dnode, NULL, true);
	static_next_hop_bfd_monitor_disable(sn);
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/bfd-monitoring/source
 */
int route_next_hop_bfd_source_modify(struct nb_cb_modify_args *args)
{
	struct static_nexthop *sn;
	struct ipaddr source;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	sn = nb_running_get_entry(args->dnode, NULL, true);
	yang_dnode_get_ip(&source, args->dnode, NULL);
	static_next_hop_bfd_source(sn, &source);
	return NB_OK;
}

int route_next_hop_bfd_source_destroy(struct nb_cb_destroy_args *args)
{
	struct static_nexthop *sn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	sn = nb_running_get_entry(args->dnode, NULL, true);
	static_next_hop_bfd_auto_source(sn);

	/*
	 * NHT information is needed by BFD to automatically find the source.
	 * Force zebra to resend the NHT data by unregistering and registering
	 * again.  The path-list apply_finish callback calls
	 * static_install_nexthop() which re-registers via
	 * static_zebra_nht_register(nh, true).
	 */
	static_zebra_nht_register(sn, false);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/bfd-monitoring/multi-hop
 */
int route_next_hop_bfd_multi_hop_modify(struct nb_cb_modify_args *args)
{
	struct static_nexthop *sn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	sn = nb_running_get_entry(args->dnode, NULL, true);
	static_next_hop_bfd_multi_hop(sn,
				      yang_dnode_get_bool(args->dnode, NULL));

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/bfd-monitoring/profile
 */
int route_next_hop_bfd_profile_modify(struct nb_cb_modify_args *args)
{
	struct static_nexthop *sn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	sn = nb_running_get_entry(args->dnode, NULL, true);
	static_next_hop_bfd_profile(sn,
				    yang_dnode_get_string(args->dnode, NULL));

	return NB_OK;
}

int route_next_hop_bfd_profile_destroy(struct nb_cb_destroy_args *args)
{
	struct static_nexthop *sn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	sn = nb_running_get_entry(args->dnode, NULL, true);
	static_next_hop_bfd_profile(sn, NULL);

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_create(
	struct nb_cb_create_args *args)
{
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_destroy(
	struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_create(
	struct nb_cb_create_args *args)
{
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_destroy(
	struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6/static-sids
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_create(
	struct nb_cb_create_args *args)
{
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_destroy(
	struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6/locators/locator/static-sids/sid
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_create(
	struct nb_cb_create_args *args)
{
	struct static_srv6_sid *sid;
	struct prefix_ipv6 sid_value;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv6p(&sid_value, args->dnode, "sid");
	sid = static_srv6_sid_alloc(&sid_value);
	nb_running_set_entry(args->dnode, sid);
	listnode_add(srv6_sids, sid);

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_destroy(
	struct nb_cb_destroy_args *args)
{
	struct static_srv6_sid *sid;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	sid = nb_running_unset_entry(args->dnode);
	listnode_delete(srv6_sids, sid);
	static_srv6_sid_del(sid);

	return NB_OK;
}

void routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct static_srv6_sid *sid;
	struct static_srv6_locator *locator;
	bool is_ua, has_interface, has_nexthop;

	sid = nb_running_get_entry(args->dnode, NULL, true);

	locator = static_srv6_locator_lookup(sid->locator_name);
	if (!locator) {
		DEBUGD(&static_dbg_srv6,
		       "%s: Locator %s not found, trying to get locator information from zebra",
		       __func__, sid->locator_name);
		static_zebra_srv6_manager_get_locator(sid->locator_name);
		return;
	}

	sid->locator = locator;

	/* Determine if this is a SID that requires nexthop resolution */

	/* Check if SID is uA or End.X that may require nexthop resolution */
	is_ua = (sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_X ||
		 sid->behavior == SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID);

	/* Check if interface is configured */
	has_interface = (sid->attributes.ifname[0] != '\0');

	/* Check if nexthop is configured (not all zeros) */
	has_nexthop = !IN6_IS_ADDR_UNSPECIFIED(&sid->attributes.nh6);

	if (is_ua && has_interface && !has_nexthop) {
		/* This is a uA SID with interface but no explicit nexthop - enable nexthop resolution */
		if (!CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_NEEDS_NH_RESOLUTION)) {
			DEBUGD(&static_dbg_srv6,
			       "%s: Enabling nexthop resolution for SID %pFX on interface %s",
			       __func__, &sid->addr, sid->attributes.ifname);

			/* Set nexthop resolution flag and register for neighbor notifications */
			SET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_NEEDS_NH_RESOLUTION);
			static_srv6_neigh_register_if_needed();
		}
	} else {
		/* This is a SID that does not require nexthop resolution - disable nexthop resolution */
		if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_NEEDS_NH_RESOLUTION)) {
			DEBUGD(&static_dbg_srv6, "%s: Disabling nexthop resolution for SID %pFX",
			       __func__, &sid->addr);

			/*
			 * Clear the nexthop resolution flag and unregister from neighbor notifications
			 * if there are no other SIDs requiring nexthop resolution.
			 */
			UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_NEEDS_NH_RESOLUTION);
			static_srv6_neigh_unregister_if_needed();
		}
	}

	static_zebra_request_srv6_sid(sid);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6/locators/locator/static-sids/sid/behavior
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_behavior_modify(
	struct nb_cb_modify_args *args)
{
	struct static_srv6_sid *sid;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	sid = nb_running_get_entry(args->dnode, NULL, true);

	/* Release and uninstall existing SID, if any, before requesting the new one */
	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID)) {
		static_zebra_release_srv6_sid(sid);
		UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID);
	}

	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA))
		static_zebra_srv6_sid_uninstall(sid);

	sid->behavior = yang_dnode_get_enum(args->dnode, "../behavior");

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_behavior_destroy(
	struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6/locators/locator/static-sids/sid/vrf-name
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_vrf_name_modify(
	struct nb_cb_modify_args *args)
{
	struct static_srv6_sid *sid;
	const char *vrf_name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	sid = nb_running_get_entry(args->dnode, NULL, true);

	/* Release and uninstall existing SID, if any, before requesting the new one */
	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID)) {
		static_zebra_release_srv6_sid(sid);
		UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID);
	}

	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA))
		static_zebra_srv6_sid_uninstall(sid);

	vrf_name = yang_dnode_get_string(args->dnode, "../vrf-name");
	snprintf(sid->attributes.vrf_name, sizeof(sid->attributes.vrf_name), "%s", vrf_name);

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_vrf_name_destroy(
	struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6/locators/locator/static-sids/sid/paths
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_create(
	struct nb_cb_create_args *args)
{
	/* Actual setting is done in apply_finish */
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_destroy(
	struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6/locators/locator/static-sids/sid/paths/interface
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_interface_modify(
	struct nb_cb_modify_args *args)
{
	struct static_srv6_sid *sid;
	const char *ifname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	sid = nb_running_get_entry(args->dnode, NULL, true);

	/* Release and uninstall existing SID, if any, before requesting the new one */
	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID)) {
		static_zebra_release_srv6_sid(sid);
		UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID);
	}

	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA))
		static_zebra_srv6_sid_uninstall(sid);

	ifname = yang_dnode_get_string(args->dnode, "../interface");
	snprintf(sid->attributes.ifname, sizeof(sid->attributes.ifname), "%s", ifname);

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_interface_destroy(
	struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6/locators/locator/static-sids/sid/paths/next-hop
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_next_hop_modify(
	struct nb_cb_modify_args *args)
{
	struct static_srv6_sid *sid;
	struct ipaddr nexthop;

	switch (args->event) {
	case NB_EV_VALIDATE:
		yang_dnode_get_ip(&nexthop, args->dnode, "../next-hop");
		if (!IS_IPADDR_V6(&nexthop)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "%% Nexthop must be an IPv6 address");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		sid = nb_running_get_entry(args->dnode, NULL, true);

		/* Release and uninstall existing SID, if any, before requesting the new one */
		if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID)) {
			static_zebra_release_srv6_sid(sid);
			UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID);
		}

		if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA))
			static_zebra_srv6_sid_uninstall(sid);

		yang_dnode_get_ip(&nexthop, args->dnode, "../next-hop");
		sid->attributes.nh6 = nexthop.ipaddr_v6;

		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_paths_next_hop_destroy(
	struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/segment-routing/srv6/locators/locator/static-sids/sid/vrf-name
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_locator_name_modify(
	struct nb_cb_modify_args *args)
{
	struct static_srv6_sid *sid;
	const char *loc_name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	sid = nb_running_get_entry(args->dnode, NULL, true);

	/* Release and uninstall existing SID, if any, before requesting the new one */
	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID)) {
		static_zebra_release_srv6_sid(sid);
		UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID);
	}

	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA))
		static_zebra_srv6_sid_uninstall(sid);

	loc_name = yang_dnode_get_string(args->dnode, "../locator-name");
	snprintf(sid->locator_name, sizeof(sid->locator_name), "%s", loc_name);

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_segment_routing_srv6_local_sids_sid_locator_name_destroy(
	struct nb_cb_destroy_args *args)
{
	return NB_OK;
}
