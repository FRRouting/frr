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


static int static_path_list_create(struct nb_cb_create_args *args)
{
	struct route_node *rn;
	struct static_path *pn;
	const struct lyd_node *vrf_dnode;
	const char *vrf;
	uint8_t distance;
	uint32_t table_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
		vrf_dnode = yang_dnode_get_parent(args->dnode,
						  "control-plane-protocol");
		vrf = yang_dnode_get_string(vrf_dnode, "./vrf");
		table_id = yang_dnode_get_uint32(args->dnode, "./table-id");

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
		break;
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		rn = nb_running_get_entry(args->dnode, NULL, true);
		distance = yang_dnode_get_uint8(args->dnode, "./distance");
		table_id = yang_dnode_get_uint32(args->dnode, "./table-id");
		pn = static_add_path(rn, table_id, distance);
		nb_running_set_entry(args->dnode, pn);
	}

	return NB_OK;
}

static int static_path_list_destroy(struct nb_cb_destroy_args *args)
{
	struct static_path *pn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		pn = nb_running_unset_entry(args->dnode);
		static_del_path(pn);
		break;
	}

	return NB_OK;
}

static int static_path_list_tag_modify(struct nb_cb_modify_args *args)
{
	struct static_path *pn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		pn = nb_running_get_entry(args->dnode, NULL, true);
		pn->tag = yang_dnode_get_uint32(args->dnode, NULL);
		static_install_path(pn);
		break;
	}

	return NB_OK;
}

struct nexthop_iter {
	uint32_t count;
	bool blackhole;
};

static int nexthop_iter_cb(const struct lyd_node *dnode, void *arg)
{
	struct nexthop_iter *iter = arg;
	enum static_nh_type nh_type;

	nh_type = yang_dnode_get_enum(dnode, "./nh-type");

	if (nh_type == STATIC_BLACKHOLE)
		iter->blackhole = true;

	iter->count++;

	return YANG_ITER_CONTINUE;
}

static bool static_nexthop_create(struct nb_cb_create_args *args)
{
	const struct lyd_node *pn_dnode;
	struct nexthop_iter iter;
	struct static_path *pn;
	struct ipaddr ipaddr;
	struct static_nexthop *nh;
	enum static_nh_type nh_type;
	const char *ifname;
	const char *nh_vrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifname = yang_dnode_get_string(args->dnode, "./interface");
		nh_type = yang_dnode_get_enum(args->dnode, "./nh-type");
		if (ifname != NULL && nh_type != STATIC_BLACKHOLE) {
			if (strcasecmp(ifname, "Null0") == 0
			    || strcasecmp(ifname, "reject") == 0
			    || strcasecmp(ifname, "blackhole") == 0) {
				snprintf(args->errmsg, args->errmsg_len,
					"%s: Nexthop interface name can not be from reserved keywords(Null0, reject, blackhole)",
					ifname);
				return NB_ERR_VALIDATION;
			}
		}

		iter.count = 0;
		iter.blackhole = false;

		pn_dnode = yang_dnode_get_parent(args->dnode, "path-list");
		yang_dnode_iterate(nexthop_iter_cb, &iter, pn_dnode,
				   "./frr-nexthops/nexthop");

		if (iter.blackhole && iter.count > 1) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"Route cannot have blackhole and non-blackhole nexthops simultaneously");
			return NB_ERR_VALIDATION;
		} else if (iter.count > zebra_ecmp_count) {
			snprintf(args->errmsg, args->errmsg_len,
				"Route cannot have more than %d ECMP nexthops",
				 zebra_ecmp_count);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		yang_dnode_get_ip(&ipaddr, args->dnode, "./gateway");
		nh_type = yang_dnode_get_enum(args->dnode, "./nh-type");
		ifname = yang_dnode_get_string(args->dnode, "./interface");
		nh_vrf = yang_dnode_get_string(args->dnode, "./vrf");
		pn = nb_running_get_entry(args->dnode, NULL, true);

		if (!static_add_nexthop_validate(nh_vrf, nh_type, &ipaddr))
			flog_warn(
				EC_LIB_NB_CB_CONFIG_VALIDATE,
				"Warning!! Local connected address is configured as Gateway IP((%s))",
				yang_dnode_get_string(args->dnode,
						      "./gateway"));
		nh = static_add_nexthop(pn, nh_type, &ipaddr, ifname, nh_vrf,
					0);
		nb_running_set_entry(args->dnode, nh);
		break;
	}

	return NB_OK;
}

static bool static_nexthop_destroy(struct nb_cb_destroy_args *args)
{
	struct static_nexthop *nh;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_unset_entry(args->dnode);
		static_delete_nexthop(nh);
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
	const char *nh_ifname;
	const char *nh_vrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
		nh_type = yang_dnode_get_enum(args->dnode, "../nh-type");
		nh_ifname = yang_dnode_get_string(args->dnode, "../interface");
		nh_vrf = yang_dnode_get_string(args->dnode, "../vrf");
		if (nh_ifname && nh_vrf) {
			struct vrf *vrf = vrf_lookup_by_name(nh_vrf);

			if (!vrf) {
				snprintf(args->errmsg, args->errmsg_len,
					 "nexthop vrf %s not found", nh_vrf);
				return NB_ERR_VALIDATION;
			}

			struct interface *ifp = if_lookup_by_name(nh_ifname,
								  vrf->vrf_id);

			if (ifp && (!strmatch(nh_ifname, "blackhole") ||
				    !strmatch(nh_ifname, "reject"))) {
				snprintf(args->errmsg, args->errmsg_len,
					 "nexthop interface name must be (reject, blackhole)");
				return NB_ERR_VALIDATION;
			}
		}
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

void routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct static_nexthop *nh;

	nh = nb_running_get_entry(args->dnode, NULL, true);

	static_install_nexthop(nh);
}

void routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct static_nexthop *nh;

	nh = nb_running_get_entry(args->dnode, NULL, true);

	static_install_nexthop(nh);
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_pre_validate(
	struct nb_cb_pre_validate_args *args)
{
	const struct lyd_node *mls_dnode;
	uint32_t count;

	mls_dnode = yang_dnode_get(args->dnode, "./mpls-label-stack");
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

	name = yang_dnode_get_string(args->dnode, "./name");
	if (!strmatch(name, "staticd")) {
		snprintf(args->errmsg, args->errmsg_len,
			"static routing supports only one instance with name staticd");
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}
/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_create(
	struct nb_cb_create_args *args)
{
	struct vrf *vrf;
	struct static_vrf *s_vrf;
	struct route_node *rn;
	const struct lyd_node *vrf_dnode;
	struct prefix prefix;
	const char *afi_safi;
	afi_t prefix_afi;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
		yang_dnode_get_prefix(&prefix, args->dnode, "./prefix");
		afi_safi = yang_dnode_get_string(args->dnode, "./afi-safi");
		yang_afi_safi_identity2value(afi_safi, &afi, &safi);
		prefix_afi = family2afi(prefix.family);
		if (afi != prefix_afi) {
			flog_warn(
				EC_LIB_NB_CB_CONFIG_VALIDATE,
				"route node %s creation failed",
				yang_dnode_get_string(args->dnode, "./prefix"));
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf_dnode = yang_dnode_get_parent(args->dnode,
						  "control-plane-protocol");
		vrf = nb_running_get_entry(vrf_dnode, NULL, true);
		s_vrf = vrf->info;

		yang_dnode_get_prefix(&prefix, args->dnode, "./prefix");
		afi_safi = yang_dnode_get_string(args->dnode, "./afi-safi");
		yang_afi_safi_identity2value(afi_safi, &afi, &safi);

		rn = static_add_route(afi, safi, &prefix, NULL, s_vrf);
		if (vrf->vrf_id == VRF_UNKNOWN)
			snprintf(
				args->errmsg, args->errmsg_len,
				"Static Route to %s not installed currently because dependent config not fully available",
				yang_dnode_get_string(args->dnode, "./prefix"));
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_create(
	struct nb_cb_create_args *args)
{
	return static_nexthop_create(args);
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_destroy(
	struct nb_cb_destroy_args *args)
{
	return static_nexthop_destroy(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/bh-type
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_bh_type_modify(
	struct nb_cb_modify_args *args)
{
	return static_nexthop_bh_type_modify(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/onlink
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_onlink_modify(
	struct nb_cb_modify_args *args)
{
	return static_nexthop_onlink_modify(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/srte-color
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_color_modify(
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

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_color_destroy(
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/srv6-segs-stack/entry
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_create(
	struct nb_cb_create_args *args)
{
	return nexthop_srv6_segs_stack_entry_create(args);
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_destroy(
	struct nb_cb_destroy_args *args)
{
	return nexthop_srv6_segs_stack_entry_destroy(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/srv6-segs-stack/entry/seg
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_seg_modify(
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

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_seg_destroy(
	struct nb_cb_destroy_args *args)
{
	/*
	 * No operation is required in this call back.
	 * nexthop_srv6_segs_stack_entry_destroy() will take care
	 * to reset the seg vaue.
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/mpls-label-stack/entry
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_create(
	struct nb_cb_create_args *args)
{
	return nexthop_mpls_label_stack_entry_create(args);
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_destroy(
	struct nb_cb_destroy_args *args)
{
	return nexthop_mpls_label_stack_entry_destroy(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/mpls-label-stack/entry/label
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_label_modify(
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

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_label_destroy(
	struct nb_cb_destroy_args *args)
{
	/*
	 * No operation is required in this call back.
	 * nexthop_mpls_label_stack_entry_destroy() will take care
	 * to reset the label vaue.
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/mpls-label-stack/entry/ttl
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_modify(
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

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_destroy(
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/mpls-label-stack/entry/traffic-class
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_modify(
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

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_destroy(
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_create(
	struct nb_cb_create_args *args)
{
	struct static_vrf *s_vrf;
	struct route_node *rn;
	struct route_node *src_rn;
	struct prefix_ipv6 src_prefix = {};
	struct stable_info *info;
	afi_t afi;
	safi_t safi = SAFI_UNICAST;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		rn = nb_running_get_entry(args->dnode, NULL, true);
		info = route_table_get_info(rn->table);
		s_vrf = info->svrf;
		yang_dnode_get_ipv6p(&src_prefix, args->dnode, "./src-prefix");
		afi = family2afi(src_prefix.family);
		src_rn =
			static_add_route(afi, safi, &rn->p, &src_prefix, s_vrf);
		nb_running_set_entry(args->dnode, src_rn);
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct route_node *src_rn;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		src_rn = nb_running_unset_entry(args->dnode);
		static_del_route(src_rn);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_create(
	struct nb_cb_create_args *args)
{
	return static_path_list_create(args);
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_destroy(
	struct nb_cb_destroy_args *args)
{
	return static_path_list_destroy(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/tag
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_tag_modify(
	struct nb_cb_modify_args *args)
{
	return static_path_list_tag_modify(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_create(
	struct nb_cb_create_args *args)
{
	return static_nexthop_create(args);
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_destroy(
	struct nb_cb_destroy_args *args)
{
	return static_nexthop_destroy(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/bh-type
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_bh_type_modify(
	struct nb_cb_modify_args *args)
{
	return static_nexthop_bh_type_modify(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/onlink
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_onlink_modify(
	struct nb_cb_modify_args *args)
{
	return static_nexthop_onlink_modify(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/srte-color
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_color_modify(
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


int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_color_destroy(
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/srv6-segs-stack/entry
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_create(
	struct nb_cb_create_args *args)
{
	return nexthop_srv6_segs_stack_entry_create(args);
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_destroy(
	struct nb_cb_destroy_args *args)
{
	return nexthop_srv6_segs_stack_entry_destroy(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/srv6-segs-stack/entry/seg
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_seg_modify(
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

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_srv6_segs_stack_entry_seg_destroy(
	struct nb_cb_destroy_args *args)
{
	/*
	 * No operation is required in this call back.
	 * nexthop_mpls_seg_stack_entry_destroy() will take care
	 * to reset the seg vaue.
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/mpls-label-stack/entry
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_create(
	struct nb_cb_create_args *args)
{
	return nexthop_mpls_label_stack_entry_create(args);
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_destroy(
	struct nb_cb_destroy_args *args)
{
	return nexthop_mpls_label_stack_entry_destroy(args);
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/mpls-label-stack/entry/label
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_label_modify(
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

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_label_destroy(
	struct nb_cb_destroy_args *args)
{
	/*
	 * No operation is required in this call back.
	 * nexthop_mpls_label_stack_entry_destroy() will take care
	 * to reset the label vaue.
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/mpls-label-stack/entry/ttl
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_modify(
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

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_destroy(
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/mpls-label-stack/entry/traffic-class
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_modify(
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

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_destroy(
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
