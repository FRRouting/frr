/*
 * Copyright (C) 2018        Vmware
 *                           Vishal Dhingra
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
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
	uint8_t distance;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		rn = nb_running_get_entry(args->dnode, NULL, true);
		distance = yang_dnode_get_uint8(args->dnode, "./distance");
		pn = static_add_path(rn, distance);
		nb_running_set_entry(args->dnode, pn);
	}

	return NB_OK;
}

static void static_path_list_destroy(struct nb_cb_destroy_args *args,
				     const struct lyd_node *rn_dnode,
				     struct stable_info *info)
{
	struct route_node *rn;
	struct static_path *pn;

	pn = nb_running_unset_entry(args->dnode);
	rn = nb_running_get_entry(rn_dnode, NULL, true);
	static_del_path(rn, pn, info->safi, info->svrf);
}

static void static_path_list_tag_modify(struct nb_cb_modify_args *args,
					const struct lyd_node *rn_dnode,
					struct stable_info *info)
{
	struct static_path *pn;
	struct route_node *rn;
	route_tag_t tag;

	tag = yang_dnode_get_uint32(args->dnode, NULL);
	pn = nb_running_get_entry(args->dnode, NULL, true);
	pn->tag = tag;
	rn = nb_running_get_entry(rn_dnode, NULL, true);

	static_install_path(rn, pn, info->safi, info->svrf);
}

static int static_path_list_tableid_modify(struct nb_cb_modify_args *args,
					   const struct lyd_node *rn_dnode,
					   struct stable_info *info)
{
	struct static_path *pn;
	struct route_node *rn;
	uint32_t table_id;
	const struct lyd_node *vrf_dnode;
	const char *vrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
		vrf_dnode = yang_dnode_get_parent(args->dnode,
						  "control-plane-protocol");
		vrf = yang_dnode_get_string(vrf_dnode, "./vrf");
		table_id = yang_dnode_get_uint32(args->dnode, NULL);
		if (table_id && (strcmp(vrf, vrf_get_default_name()) != 0)
		    && !vrf_is_backend_netns()) {
			snprintf(args->errmsg, args->errmsg_len,
				"%% table param only available when running on netns-based vrfs");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		table_id = yang_dnode_get_uint32(args->dnode, NULL);
		pn = nb_running_get_entry(args->dnode, NULL, true);
		pn->table_id = table_id;
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		static_install_path(rn, pn, info->safi, info->svrf);
		break;
	}

	return NB_OK;
}

static bool static_nexthop_create(struct nb_cb_create_args *args,
				  const struct lyd_node *rn_dnode,
				  struct stable_info *info)
{
	struct route_node *rn;
	struct static_path *pn;
	struct ipaddr ipaddr;
	struct static_nexthop *nh;
	int nh_type;
	const char *ifname;
	const char *nh_vrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifname = yang_dnode_get_string(args->dnode, "./interface");
		if (ifname != NULL) {
			if (strcasecmp(ifname, "Null0") == 0
			    || strcasecmp(ifname, "reject") == 0
			    || strcasecmp(ifname, "blackhole") == 0) {
				snprintf(args->errmsg, args->errmsg_len,
					"%s: Nexthop interface name can not be from reserved keywords(Null0, reject, blackhole)",
					ifname);
				return NB_ERR_VALIDATION;
			}
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
		rn = nb_running_get_entry(rn_dnode, NULL, true);

		if (!static_add_nexthop_validate(info->svrf, nh_type, &ipaddr))
			flog_warn(
				EC_LIB_NB_CB_CONFIG_VALIDATE,
				"Warning!! Local connected address is configured as Gateway IP((%s))",
				yang_dnode_get_string(args->dnode,
						      "./gateway"));
		nh = static_add_nexthop(rn, pn, info->safi, info->svrf, nh_type,
					&ipaddr, ifname, nh_vrf, 0);
		if (!nh) {
			char buf[SRCDEST2STR_BUFFER];

			flog_warn(
				EC_LIB_NB_CB_CONFIG_APPLY,
				"%s : nh [%d:%s:%s:%s] nexthop creation failed",
				srcdest_rnode2str(rn, buf, sizeof(buf)),
				nh_type, ifname,
				yang_dnode_get_string(args->dnode, "./gateway"),
				nh_vrf);
			return NB_ERR;
		}
		nb_running_set_entry(args->dnode, nh);
		break;
	}

	return NB_OK;
}

static bool static_nexthop_destroy(struct nb_cb_destroy_args *args,
				   const struct lyd_node *rn_dnode,
				   struct stable_info *info)
{
	struct route_node *rn;
	struct static_path *pn;
	const struct lyd_node *pn_dnode;
	struct static_nexthop *nh;
	int ret;

	nh = nb_running_unset_entry(args->dnode);
	pn_dnode = yang_dnode_get_parent(args->dnode, "path-list");
	pn = nb_running_get_entry(pn_dnode, NULL, true);
	rn = nb_running_get_entry(rn_dnode, NULL, true);

	ret = static_delete_nexthop(rn, pn, info->safi, info->svrf, nh);
	if (!ret) {
		char buf[SRCDEST2STR_BUFFER];

		flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
			  "%s : nh [%d:%s:%s:%s] nexthop destroy failed",
			  srcdest_rnode2str(rn, buf, sizeof(buf)),
			  yang_dnode_get_enum(args->dnode, "./nh-type"),
			  yang_dnode_get_string(args->dnode, "./interface"),
			  yang_dnode_get_string(args->dnode, "./gateway"),
			  yang_dnode_get_string(args->dnode, "./vrf"));
		return NB_ERR;
	}

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
		nh->snh_label.label[index] = 0;
		nh->snh_label.num_labels--;
		break;
	}

	return NB_OK;
}

static int static_nexthop_mpls_label_modify(struct nb_cb_modify_args *args)
{
	struct static_nexthop *nh;
	uint32_t pos;
	uint8_t index;

	nh = nb_running_get_entry(args->dnode, NULL, true);
	pos = yang_get_list_pos(args->dnode->parent);
	if (!pos) {
		flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
			  "libyang returns invalid label position");
		return NB_ERR;
	}
	/* Mapping to array = list-index -1 */
	index = pos - 1;
	nh->snh_label.label[index] = yang_dnode_get_uint32(args->dnode, NULL);

	return NB_OK;
}

static int static_nexthop_onlink_modify(struct nb_cb_modify_args *args)
{
	struct static_nexthop *nh;

	nh = nb_running_get_entry(args->dnode, NULL, true);
	nh->onlink = yang_dnode_get_bool(args->dnode, NULL);

	return NB_OK;
}

static int static_nexthop_color_modify(struct nb_cb_modify_args *args)
{
	struct static_nexthop *nh;

	nh = nb_running_get_entry(args->dnode, NULL, true);
	nh->color = yang_dnode_get_uint32(args->dnode, NULL);

	return NB_OK;
}

static int static_nexthop_color_destroy(struct nb_cb_destroy_args *args)
{
	struct static_nexthop *nh;

	nh = nb_running_unset_entry(args->dnode);
	nh->color = 0;

	return NB_OK;
}

static int static_nexthop_bh_type_modify(struct nb_cb_modify_args *args)
{
	struct static_nexthop *nh;

	nh = nb_running_get_entry(args->dnode, NULL, true);
	nh->bh_type = yang_dnode_get_enum(args->dnode, NULL);

	return NB_OK;
}


void routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct static_nexthop *nh;
	struct static_path *pn;
	struct route_node *rn;
	const struct lyd_node *pn_dnode;
	const struct lyd_node *rn_dnode;
	const char *ifname;
	const char *nh_vrf;
	struct stable_info *info;
	int nh_type;

	nh_type = yang_dnode_get_enum(args->dnode, "./nh-type");
	ifname = yang_dnode_get_string(args->dnode, "./interface");
	nh_vrf = yang_dnode_get_string(args->dnode, "./vrf");

	nh = nb_running_get_entry(args->dnode, NULL, true);

	pn_dnode = yang_dnode_get_parent(args->dnode, "path-list");
	pn = nb_running_get_entry(pn_dnode, NULL, true);

	rn_dnode = yang_dnode_get_parent(pn_dnode, "route-list");
	rn = nb_running_get_entry(rn_dnode, NULL, true);
	info = route_table_get_info(rn->table);

	static_install_nexthop(rn, pn, nh, info->safi, info->svrf, ifname,
			       nh_type, nh_vrf);
}


void routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct static_nexthop *nh;
	struct static_path *pn;
	struct route_node *rn;
	struct route_node *src_rn;
	const struct lyd_node *pn_dnode;
	const struct lyd_node *rn_dnode;
	const struct lyd_node *src_dnode;
	const char *ifname;
	const char *nh_vrf;
	struct stable_info *info;
	int nh_type;

	nh_type = yang_dnode_get_enum(args->dnode, "./nh-type");
	ifname = yang_dnode_get_string(args->dnode, "./interface");
	nh_vrf = yang_dnode_get_string(args->dnode, "./vrf");

	nh = nb_running_get_entry(args->dnode, NULL, true);

	pn_dnode = yang_dnode_get_parent(args->dnode, "path-list");
	pn = nb_running_get_entry(pn_dnode, NULL, true);

	src_dnode = yang_dnode_get_parent(pn_dnode, "src-list");
	src_rn = nb_running_get_entry(src_dnode, NULL, true);

	rn_dnode = yang_dnode_get_parent(src_dnode, "route-list");
	rn = nb_running_get_entry(rn_dnode, NULL, true);
	info = route_table_get_info(rn->table);

	static_install_nexthop(src_rn, pn, nh, info->safi, info->svrf, ifname,
			       nh_type, nh_vrf);
}
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_pre_validate(
	struct nb_cb_pre_validate_args *args)
{
	const struct lyd_node *mls_dnode;
	uint32_t count;

	mls_dnode = yang_dnode_get(args->dnode, "./mpls-label-stack");
	count = yang_get_list_elements_count(yang_dnode_get_child(mls_dnode));

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
		if (!rn) {
			flog_warn(
				EC_LIB_NB_CB_CONFIG_APPLY,
				"route node %s creation failed",
				yang_dnode_get_string(args->dnode, "./prefix"));
			return NB_ERR;
		}
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
	struct stable_info *info;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		rn = nb_running_unset_entry(args->dnode);
		info = route_table_get_info(rn->table);
		static_del_route(rn, info->safi, info->svrf);
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
	const struct lyd_node *rn_dnode;
	struct route_node *rn;
	struct stable_info *info;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		rn_dnode = yang_dnode_get_parent(args->dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);
		static_path_list_destroy(args, rn_dnode, info);
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/tag
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_tag_modify(
	struct nb_cb_modify_args *args)
{
	struct stable_info *info;
	struct route_node *rn;
	const struct lyd_node *rn_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		rn_dnode = yang_dnode_get_parent(args->dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);
		static_path_list_tag_modify(args, rn_dnode, info);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/table-id
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_table_id_modify(
	struct nb_cb_modify_args *args)
{
	struct route_node *rn;
	const struct lyd_node *rn_dnode;
	struct stable_info *info;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (static_path_list_tableid_modify(args, NULL, NULL) != NB_OK)
			return NB_ERR_VALIDATION;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		rn_dnode = yang_dnode_get_parent(args->dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);

		if (static_path_list_tableid_modify(args, rn_dnode, info)
		    != NB_OK)
			return NB_ERR_VALIDATION;
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_create(
	struct nb_cb_create_args *args)
{
	struct route_node *rn;
	const struct lyd_node *rn_dnode;
	struct stable_info *info;

	switch (args->event) {
	case NB_EV_VALIDATE:
		rn_dnode = yang_dnode_get_parent(args->dnode, "route-list");
		if (static_nexthop_create(args, rn_dnode, NULL) != NB_OK)
			return NB_ERR_VALIDATION;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		rn_dnode = yang_dnode_get_parent(args->dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);

		if (static_nexthop_create(args, rn_dnode, info) != NB_OK)
			return NB_ERR_VALIDATION;
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_destroy(
	struct nb_cb_destroy_args *args)
{
	struct route_node *rn;
	const struct lyd_node *rn_dnode;
	struct stable_info *info;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		rn_dnode = yang_dnode_get_parent(args->dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);

		if (static_nexthop_destroy(args, rn_dnode, info) != NB_OK)
			return NB_ERR;
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/bh-type
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_bh_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		if (static_nexthop_bh_type_modify(args) != NB_OK)
			return NB_ERR;
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_bh_type_destroy(
	struct nb_cb_destroy_args *args)
{
	/* blackhole type has a boolean type with default value,
	 * so no need to do any operations in destroy callback
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-nexthops/nexthop/onlink
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_onlink_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		if (static_nexthop_onlink_modify(args) != NB_OK)
			return NB_ERR;

		break;
	}
	return NB_OK;
}
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_nexthops_nexthop_onlink_destroy(
	struct nb_cb_destroy_args *args)
{
	/* onlink has a boolean type with default value,
	 * so no need to do any operations in destroy callback
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
		if (!src_rn) {
			flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				  "src rn %s creation failed",
				  yang_dnode_get_string(args->dnode,
							"./src-prefix"));
			return NB_ERR;
		}
		nb_running_set_entry(args->dnode, src_rn);
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct route_node *src_rn;
	struct route_node *rn;
	struct stable_info *info;
	const struct lyd_node *rn_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		src_rn = nb_running_unset_entry(args->dnode);
		rn_dnode = yang_dnode_get_parent(args->dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);
		static_del_route(src_rn, info->safi, info->svrf);
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
	struct route_node *rn;
	const struct lyd_node *rn_dnode;
	const struct lyd_node *srn_dnode;
	struct stable_info *info;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		srn_dnode = yang_dnode_get_parent(args->dnode, "src-list");
		rn_dnode = yang_dnode_get_parent(srn_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);
		static_path_list_destroy(args, srn_dnode, info);
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/tag
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_tag_modify(
	struct nb_cb_modify_args *args)
{
	struct stable_info *info;
	struct route_node *rn;
	const struct lyd_node *srn_dnode;
	const struct lyd_node *rn_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_ABORT:
	case NB_EV_PREPARE:
		break;
	case NB_EV_APPLY:
		srn_dnode = yang_dnode_get_parent(args->dnode, "src-list");
		rn_dnode = yang_dnode_get_parent(srn_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);
		static_path_list_tag_modify(args, srn_dnode, info);
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/table-id
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_table_id_modify(
	struct nb_cb_modify_args *args)
{
	struct route_node *rn;
	const struct lyd_node *rn_dnode;
	const struct lyd_node *src_dnode;
	struct stable_info *info;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (static_path_list_tableid_modify(args, NULL, NULL) != NB_OK)
			return NB_ERR_VALIDATION;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		src_dnode = yang_dnode_get_parent(args->dnode, "src-list");
		rn_dnode = yang_dnode_get_parent(src_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);

		if (static_path_list_tableid_modify(args, src_dnode, info)
		    != NB_OK)
			return NB_ERR_VALIDATION;

		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_create(
	struct nb_cb_create_args *args)
{
	struct route_node *rn;
	const struct lyd_node *rn_dnode;
	const struct lyd_node *src_dnode;
	struct stable_info *info;

	switch (args->event) {
	case NB_EV_VALIDATE:
		rn_dnode = yang_dnode_get_parent(args->dnode, "route-list");
		if (static_nexthop_create(args, rn_dnode, NULL) != NB_OK)
			return NB_ERR_VALIDATION;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		src_dnode = yang_dnode_get_parent(args->dnode, "src-list");
		rn_dnode = yang_dnode_get_parent(src_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);

		if (static_nexthop_create(args, src_dnode, info) != NB_OK)
			return NB_ERR_VALIDATION;

		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_destroy(
	struct nb_cb_destroy_args *args)
{
	struct route_node *rn;
	const struct lyd_node *rn_dnode;
	const struct lyd_node *src_dnode;
	struct stable_info *info;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		src_dnode = yang_dnode_get_parent(args->dnode, "src-list");
		rn_dnode = yang_dnode_get_parent(src_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);

		if (static_nexthop_destroy(args, rn_dnode, info) != NB_OK)
			return NB_ERR;
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/bh-type
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_bh_type_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		if (static_nexthop_bh_type_modify(args) != NB_OK)
			return NB_ERR;
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_bh_type_destroy(
	struct nb_cb_destroy_args *args)
{
	/* blackhole type has a boolean type with default value,
	 * so no need to do any operations in destroy callback
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
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-nexthops/nexthop/onlink
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_onlink_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		if (static_nexthop_onlink_modify(args) != NB_OK)
			return NB_ERR;

		break;
	}
	return NB_OK;
}


int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_nexthops_nexthop_onlink_destroy(
	struct nb_cb_destroy_args *args)
{
	/* onlink has a boolean type with default value,
	 * so no need to do any operations in destroy callback
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
