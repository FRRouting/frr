#include "northbound.h"
#include "libfrr.h"
#include "log.h"
#include "lib_errors.h"
#include "prefix.h"
#include "table.h"
#include "vrf.h"
#include "nexthop.h"

#include "static_vrf.h"
#include "static_routes.h"
#include "static_nb.h"
/* prototypes */
/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct vrf *vrf;
	struct static_vrf *s_vrf;
	struct route_node *rn;
	struct prefix prefix;
	char buf[PREFIX_STRLEN];
	afi_t afi;
	safi_t safi = SAFI_UNICAST;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		vrf = nb_running_get_entry(dnode, NULL, true);
		s_vrf = vrf->info;

		yang_dnode_get_prefix(&prefix, dnode, "./destination-prefix");
		afi = family2afi(prefix.family);

		if (afi == AFI_IP) {
			if (IN_MULTICAST(ntohl(prefix.u.prefix4.s_addr)))
				safi = SAFI_MULTICAST;
		} else {
			if (IN6_IS_ADDR_MULTICAST(&prefix.u.prefix6))
				safi = SAFI_MULTICAST;
		}

		rn = static_add_route(afi, safi, &prefix, NULL, s_vrf);
		if (!rn) {
			prefix2str(&prefix, buf, PREFIX_STRLEN);
			flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				  "route node %s creation failed", buf);
			return NB_ERR;
		}
		nb_running_set_entry(dnode, rn);
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{

	struct route_node *rn;
	struct stable_info *info;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		rn = nb_running_get_entry(dnode, NULL, true);
		nb_running_unset_entry(dnode);
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
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct route_node *rn;
	struct static_route_info *si;
	uint8_t distance;
	route_tag_t tag;
	uint32_t table_id;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		rn = nb_running_get_entry(dnode, NULL, true);
		distance = yang_dnode_get_uint8(dnode, "./distance");
		tag = yang_dnode_get_uint32(dnode, "./tag");
		table_id = yang_dnode_get_uint32(dnode, "./table-id");
		si = static_add_route_info(rn, distance, tag, table_id);
		nb_running_set_entry(dnode, si);
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct route_node *rn;
	const struct lyd_node *rn_dnode;
	struct static_route_info *ri;
	struct stable_info *info;
	bool ret;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		rn_dnode = yang_dnode_get_pleaf(dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		ri = nb_running_get_entry(dnode, NULL, true);
		nb_running_unset_entry(dnode);
		info = route_table_get_info(rn->table);
		ret = static_del_route_info(rn, ri, info->safi, info->svrf);
		if (!ret)
			return NB_ERR;
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct route_node *rn;
	const struct lyd_node *rn_dnode;
	struct static_route_info *ri;
	struct stable_info *info;
	struct ipaddr ipaddr;
	struct static_nexthop *nh;
	int nh_type;
	const char *ifname;
	const char *nh_vrf;

	switch (event) {
	case NB_EV_VALIDATE:
		ifname = yang_dnode_get_string(dnode, "./interface");
		if (ifname != NULL) {
			if (strcasecmp(ifname, "Null0") == 0
			    || strcasecmp(ifname, "reject") == 0
			    || strcasecmp(ifname, "blackhole") == 0) {
				rn_dnode = yang_dnode_get_pleaf(dnode,
								"route-list");
				flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
					  "%s : Nexthop interface name can not be from reserved keywords(Null0, reject, blackhole)",
					  yang_dnode_get_string(
						  rn_dnode,
						  "./destination-prefix"));
				return NB_ERR_VALIDATION;
			}
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		yang_dnode_get_ip(&ipaddr, dnode, "./gateway");
		nh_type = yang_dnode_get_enum(dnode, "./nh-type");
		ifname = yang_dnode_get_string(dnode, "./interface");
		nh_vrf = yang_dnode_get_string(dnode, "./vrf");
		ri = nb_running_get_entry(dnode, NULL, true);
		rn_dnode = yang_dnode_get_pleaf(dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);

		if (!static_add_nexthop_validate(info->svrf, nh_type, &ipaddr))
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "Warning!! Local connected address is configured as Gateway IP((%s))",
				  yang_dnode_get_string(dnode, "./gateway"));
		nh = static_add_nexthop(rn, ri, info->safi, info->svrf, nh_type,
					&ipaddr, ifname, nh_vrf);
		if (!nh) {
			flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				  "%s : nh [%d:%s:%s:%s]creation failed",
				  yang_dnode_get_string(rn_dnode,
							"./destination-prefix"),
				  nh_type, ifname,
				  yang_dnode_get_string(dnode, "./gateway"),
				  nh_vrf);
			return NB_ERR;
		}
		nb_running_set_entry(dnode, nh);
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct route_node *rn;
	const struct lyd_node *rn_dnode;
	struct static_route_info *ri;
	const struct lyd_node *ri_dnode;
	struct static_nexthop *nh;
	struct stable_info *info;
	int ret;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(dnode, NULL, true);
		ri_dnode = yang_dnode_get_pleaf(dnode, "path-list");
		ri = nb_running_get_entry(ri_dnode, NULL, true);
		rn_dnode = yang_dnode_get_pleaf(ri_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);

		nb_running_unset_entry(dnode);

		info = route_table_get_info(rn->table);

		ret = static_delete_nexthop(rn, ri, info->safi, info->svrf, nh);
		if (!ret) {
			flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				  "%s : nh [%d:%s:%s:%s]destroy failed",
				  yang_dnode_get_string(rn_dnode,
							"./destination-prefix"),
				  yang_dnode_get_enum(dnode, "./nh-type"),
				  yang_dnode_get_string(dnode, "./interface"),
				  yang_dnode_get_string(dnode, "./gateway"),
				  yang_dnode_get_string(dnode, "./vrf"));
			return NB_ERR;
		}
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/bh-type
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_bh_type_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{

	struct route_node *rn;
	struct static_route_info *ri;
	const struct lyd_node *rn_dnode;
	const struct lyd_node *ri_dnode;
	struct static_nexthop *nh;
	struct stable_info *info;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(dnode, NULL, true);

		ri_dnode = yang_dnode_get_pleaf(dnode, "path-list");
		ri = nb_running_get_entry(ri_dnode, NULL, true);

		rn_dnode = yang_dnode_get_pleaf(ri_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);

		nh->bh_type = yang_dnode_get_enum(dnode, NULL);
		info = route_table_get_info(rn->table);
		static_install_route(rn, ri, info->safi, info->svrf);
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_bh_type_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct route_node *rn;
	struct static_route_info *ri;
	const struct lyd_node *rn_dnode;
	const struct lyd_node *ri_dnode;
	struct static_nexthop *nh;
	struct stable_info *info;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(dnode, NULL, true);

		ri_dnode = yang_dnode_get_pleaf(dnode, "path-list");
		ri = nb_running_get_entry(ri_dnode, NULL, true);

		rn_dnode = yang_dnode_get_pleaf(ri_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);

		nh->bh_type = STATIC_BLACKHOLE_NULL;
		info = route_table_get_info(rn->table);
		static_install_route(rn, ri, info->safi, info->svrf);
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/onlink
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_onlink_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct route_node *rn;
	const struct lyd_node *rn_dnode;
	struct static_nexthop *nh;
	struct static_route_info *ri;
	const struct lyd_node *ri_dnode;
	struct stable_info *info;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(dnode, NULL, true);

		ri_dnode = yang_dnode_get_pleaf(dnode, "path-list");
		ri = nb_running_get_entry(ri_dnode, NULL, true);

		rn_dnode = yang_dnode_get_pleaf(ri_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		nh->onlink = yang_dnode_get_bool(dnode, NULL);
		info = route_table_get_info(rn->table);

		static_install_route(rn, ri, info->safi, info->svrf);
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_onlink_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct route_node *rn;
	struct static_route_info *ri;
	const struct lyd_node *rn_dnode;
	const struct lyd_node *ri_dnode;
	struct static_nexthop *nh;
	struct stable_info *info;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(dnode, NULL, true);

		ri_dnode = yang_dnode_get_pleaf(dnode, "path-list");
		ri = nb_running_get_entry(ri_dnode, NULL, true);

		rn_dnode = yang_dnode_get_pleaf(ri_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);
		nh->onlink = false;
		static_install_route(rn, ri, info->safi, info->svrf);
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/mpls-label-stack/entry
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	uint8_t id;

	switch (event) {
	case NB_EV_VALIDATE:
		id = yang_dnode_get_uint8(dnode, "id");
		if (id > MPLS_MAX_LABELS) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "Too many labels, Enter %d or fewer",
				  MPLS_MAX_LABELS);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/mpls-label-stack/entry/label
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_label_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct route_node *rn;
	struct static_route_info *ri;
	struct static_nexthop *nh;
	const struct lyd_node *id_dnode;
	const struct lyd_node *rn_dnode;
	const struct lyd_node *ri_dnode;
	struct stable_info *info;
	uint8_t id;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(dnode, NULL, true);
		id_dnode = yang_dnode_get_pleaf(dnode, "entry");
		id = yang_dnode_get_uint8(id_dnode, "id");
		nh->snh_label.label[id] = yang_dnode_get_uint32(dnode, NULL);
		nh->snh_label.num_labels++;

		ri_dnode = yang_dnode_get_pleaf(id_dnode, "path-list");
		ri = nb_running_get_entry(ri_dnode, NULL, true);

		rn_dnode = yang_dnode_get_pleaf(ri_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);
		static_install_route(rn, ri, info->safi, info->svrf);
		break;
	default:
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_label_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{

	struct route_node *rn;
	struct static_route_info *ri;
	struct stable_info *info;
	struct static_nexthop *nh;
	const struct lyd_node *id_dnode;
	const struct lyd_node *rn_dnode;
	const struct lyd_node *ri_dnode;
	uint8_t id;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(dnode, NULL, true);
		id_dnode = yang_dnode_get_pleaf(dnode, "entry");
		id = yang_dnode_get_uint8(id_dnode, "id");
		nh->snh_label.num_labels--;
		nh->snh_label.label[id] = 0;

		ri_dnode = yang_dnode_get_pleaf(id_dnode, "path-list");
		ri = nb_running_get_entry(ri_dnode, NULL, true);

		rn_dnode = yang_dnode_get_pleaf(ri_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);
		static_install_route(rn, ri, info->safi, info->svrf);
		break;
	default:
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/mpls-label-stack/entry/ttl
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/mpls-label-stack/entry/traffic-class
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct static_vrf *s_vrf;
	struct route_node *rn;
	struct route_node *src_rn;
	struct prefix_ipv6 src_prefix;
	struct stable_info *info;
	afi_t afi;
	safi_t safi = SAFI_UNICAST;

	switch (event) {
	case NB_EV_VALIDATE:
		memset(&src_prefix, 0, sizeof(struct prefix_ipv6));
		yang_dnode_get_ipv6p(&src_prefix, dnode, "./src-prefix");
		afi = family2afi(src_prefix.family);
		if (afi != AFI_IP6) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "src-list applicable only for IPV6 AFI");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		rn = nb_running_get_entry(dnode, NULL, true);
		info = route_table_get_info(rn->table);
		s_vrf = info->svrf;
		memset(&src_prefix, 0, sizeof(struct prefix_ipv6));
		yang_dnode_get_ipv6p(&src_prefix, dnode, "./src-prefix");
		afi = family2afi(src_prefix.family);
		src_rn =
			static_add_route(afi, safi, &rn->p, &src_prefix, s_vrf);
		if (!src_rn) {
			flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				  "rn creation failed");
			return NB_ERR;
		}
		nb_running_set_entry(dnode, src_rn);
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct route_node *src_rn;
	struct route_node *rn;
	struct stable_info *info;
	const struct lyd_node *rn_dnode;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		src_rn = nb_running_get_entry(dnode, NULL, true);
		rn_dnode = yang_dnode_get_pleaf(dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		nb_running_unset_entry(dnode);
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
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct route_node *src_rn;
	struct static_route_info *si;
	uint8_t distance;
	route_tag_t tag;
	uint32_t table_id;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		src_rn = nb_running_get_entry(dnode, NULL, true);
		distance = yang_dnode_get_uint8(dnode, "./distance");
		tag = yang_dnode_get_uint32(dnode, "./tag");
		table_id = yang_dnode_get_uint32(dnode, "./table-id");
		si = static_add_route_info(src_rn, distance, tag, table_id);
		nb_running_set_entry(dnode, si);
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct route_node *src_rn;
	struct route_node *rn;
	const struct lyd_node *rn_dnode;
	const struct lyd_node *srn_dnode;
	struct static_route_info *ri;
	struct stable_info *info;
	bool ret;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		ri = nb_running_get_entry(dnode, NULL, true);

		srn_dnode = yang_dnode_get_pleaf(dnode, "src-list");
		src_rn = nb_running_get_entry(srn_dnode, NULL, true);

		rn_dnode = yang_dnode_get_pleaf(srn_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);

		nb_running_unset_entry(dnode);

		info = route_table_get_info(rn->table);

		ret = static_del_route_info(src_rn, ri, info->safi, info->svrf);
		if (!ret)
			return NB_ERR;
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct route_node *src_rn;
	struct route_node *rn;
	struct static_route_info *ri;
	const struct lyd_node *rn_dnode;
	const struct lyd_node *src_dnode;
	struct ipaddr ipaddr;
	struct static_nexthop *nh;
	int nh_type;
	struct stable_info *info;
	const char *ifname;
	const char *nh_vrf;

	switch (event) {
	case NB_EV_VALIDATE:
		ifname = yang_dnode_get_string(dnode, "./interface");
		if (ifname != NULL) {
			if (strcasecmp(ifname, "Null0") == 0
			    || strcasecmp(ifname, "reject") == 0
			    || strcasecmp(ifname, "blackhole") == 0) {
				flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
					  "Nexthop interface name can not be from reserved keywords(Null0, reject, blackhole)");
				return NB_ERR_VALIDATION;
			}
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		yang_dnode_get_ip(&ipaddr, dnode, "./gateway");
		nh_type = yang_dnode_get_enum(dnode, "./nh-type");
		ifname = yang_dnode_get_string(dnode, "./interface");
		nh_vrf = yang_dnode_get_string(dnode, "./vrf");

		ri = nb_running_get_entry(dnode, NULL, true);

		src_dnode = yang_dnode_get_pleaf(dnode, "src-list");
		src_rn = nb_running_get_entry(src_dnode, NULL, true);

		rn_dnode = yang_dnode_get_pleaf(dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);

		if (!static_add_nexthop_validate(info->svrf, nh_type, &ipaddr))
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "Warning!! Local connected address is configured as Gateway IP");
		nh = static_add_nexthop(src_rn, ri, info->safi, info->svrf,
					nh_type, &ipaddr, ifname, nh_vrf);
		if (!nh) {
			flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				  "nh creation failed");
			return NB_ERR;
		}

		nb_running_set_entry(dnode, nh);
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct route_node *rn;
	struct route_node *src_rn;
	struct static_route_info *ri;
	const struct lyd_node *rn_dnode;
	const struct lyd_node *src_dnode;
	const struct lyd_node *ri_dnode;
	struct static_nexthop *nh;
	struct stable_info *info;
	int ret;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(dnode, NULL, true);

		ri_dnode = yang_dnode_get_pleaf(dnode, "path-list");
		ri = nb_running_get_entry(ri_dnode, NULL, true);

		src_dnode = yang_dnode_get_pleaf(ri_dnode, "src-list");
		src_rn = nb_running_get_entry(src_dnode, NULL, true);

		rn_dnode = yang_dnode_get_pleaf(src_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);

		nb_running_unset_entry(dnode);

		info = route_table_get_info(rn->table);

		ret = static_delete_nexthop(src_rn, ri, info->safi, info->svrf,
					    nh);
		if (!ret) {
			flog_warn(EC_LIB_NB_CB_CONFIG_APPLY,
				  "nh destroy failed");
			return NB_ERR;
		}
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/bh-type
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_bh_type_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct route_node *src_rn;
	struct route_node *rn;
	struct static_route_info *ri;
	const struct lyd_node *rn_dnode;
	const struct lyd_node *src_dnode;
	const struct lyd_node *ri_dnode;
	struct static_nexthop *nh;
	struct stable_info *info;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(dnode, NULL, true);

		ri_dnode = yang_dnode_get_pleaf(dnode, "path-list");
		ri = nb_running_get_entry(ri_dnode, NULL, true);

		src_dnode = yang_dnode_get_pleaf(ri_dnode, "src-list");
		src_rn = nb_running_get_entry(src_dnode, NULL, true);

		nh->bh_type = yang_dnode_get_enum(dnode, NULL);

		rn_dnode = yang_dnode_get_pleaf(src_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);
		static_install_route(src_rn, ri, info->safi, info->svrf);
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_bh_type_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct route_node *src_rn;
	struct static_route_info *ri;
	const struct lyd_node *src_dnode;
	struct route_node *rn;
	const struct lyd_node *rn_dnode;
	const struct lyd_node *ri_dnode;
	struct static_nexthop *nh;
	struct stable_info *info;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(dnode, NULL, true);

		ri_dnode = yang_dnode_get_pleaf(dnode, "path-list");
		ri = nb_running_get_entry(ri_dnode, NULL, true);

		src_dnode = yang_dnode_get_pleaf(ri_dnode, "src-list");
		src_rn = nb_running_get_entry(src_dnode, NULL, true);
		nh->bh_type = STATIC_BLACKHOLE_NULL;
		rn_dnode = yang_dnode_get_pleaf(src_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);
		static_install_route(src_rn, ri, info->safi, info->svrf);
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/onlink
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_onlink_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct route_node *src_rn;
	struct route_node *rn;
	struct static_route_info *ri;
	const struct lyd_node *rn_dnode;
	const struct lyd_node *src_dnode;
	const struct lyd_node *ri_dnode;
	struct static_nexthop *nh;
	struct stable_info *info;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(dnode, NULL, true);

		ri_dnode = yang_dnode_get_pleaf(dnode, "path-list");
		ri = nb_running_get_entry(ri_dnode, NULL, true);

		src_dnode = yang_dnode_get_pleaf(ri_dnode, "src-list");
		src_rn = nb_running_get_entry(src_dnode, NULL, true);

		nh->onlink = yang_dnode_get_bool(dnode, NULL);
		rn_dnode = yang_dnode_get_pleaf(src_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);
		static_install_route(src_rn, ri, info->safi, info->svrf);
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_onlink_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct route_node *src_rn;
	struct static_route_info *ri;
	struct route_node *rn;
	const struct lyd_node *rn_dnode;
	const struct lyd_node *src_dnode;
	const struct lyd_node *ri_dnode;
	struct static_nexthop *nh;
	struct stable_info *info;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(dnode, NULL, true);

		ri_dnode = yang_dnode_get_pleaf(dnode, "path-list");
		ri = nb_running_get_entry(ri_dnode, NULL, true);

		src_dnode = yang_dnode_get_pleaf(ri_dnode, "src-list");
		src_rn = nb_running_get_entry(src_dnode, NULL, true);
		nh->onlink = false;
		rn_dnode = yang_dnode_get_pleaf(src_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);
		static_install_route(src_rn, ri, info->safi, info->svrf);
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/mpls-label-stack/entry
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	uint8_t id;

	switch (event) {
	case NB_EV_VALIDATE:
		id = yang_dnode_get_uint8(dnode, "id");
		if (id > MPLS_MAX_LABELS) {
			flog_warn(EC_LIB_NB_CB_CONFIG_VALIDATE,
				  "Too many labels, Enter %d or fewer",
				  MPLS_MAX_LABELS);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/mpls-label-stack/entry/label
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_label_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct route_node *src_rn;
	struct static_route_info *ri;
	struct route_node *rn;
	const struct lyd_node *rn_dnode;
	struct static_nexthop *nh;
	const struct lyd_node *id_dnode;
	const struct lyd_node *src_dnode;
	const struct lyd_node *ri_dnode;
	struct stable_info *info;
	uint8_t id;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(dnode, NULL, true);
		id_dnode = yang_dnode_get_pleaf(dnode, "entry");
		id = yang_dnode_get_uint8(id_dnode, "id");
		nh->snh_label.label[id] = yang_dnode_get_uint32(dnode, NULL);
		nh->snh_label.num_labels++;

		ri_dnode = yang_dnode_get_pleaf(id_dnode, "path-list");
		ri = nb_running_get_entry(ri_dnode, NULL, true);

		src_dnode = yang_dnode_get_pleaf(ri_dnode, "src-list");
		src_rn = nb_running_get_entry(src_dnode, NULL, true);

		rn_dnode = yang_dnode_get_pleaf(src_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);
		static_install_route(src_rn, ri, info->safi, info->svrf);
		break;
	default:
		break;
	}
	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_label_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{

	struct route_node *src_rn;
	struct route_node *rn;
	struct static_route_info *ri;
	const struct lyd_node *rn_dnode;
	struct stable_info *info;
	struct static_nexthop *nh;
	const struct lyd_node *id_dnode;
	const struct lyd_node *src_dnode;
	const struct lyd_node *ri_dnode;
	uint8_t id;

	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		nh = nb_running_get_entry(dnode, NULL, true);
		id_dnode = yang_dnode_get_pleaf(dnode, "entry");
		id = yang_dnode_get_uint8(id_dnode, "id");
		nh->snh_label.num_labels--;
		nh->snh_label.label[id] = 0;

		ri_dnode = yang_dnode_get_pleaf(id_dnode, "path-list");
		ri = nb_running_get_entry(ri_dnode, NULL, true);

		src_dnode = yang_dnode_get_pleaf(ri_dnode, "src-list");
		src_rn = nb_running_get_entry(src_dnode, NULL, true);

		rn_dnode = yang_dnode_get_pleaf(src_dnode, "route-list");
		rn = nb_running_get_entry(rn_dnode, NULL, true);
		info = route_table_get_info(rn->table);
		static_install_route(src_rn, ri, info->safi, info->svrf);
		break;
	default:
		break;
	}
	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/mpls-label-stack/entry/ttl
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_ttl_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/route-list/src-list/path-list/frr-staticd-next-hop/frr-nexthops/nexthop/mpls-label-stack/entry/traffic-class
 */
int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}

int routing_control_plane_protocols_control_plane_protocol_staticd_route_list_src_list_path_list_frr_staticd_next_hop_frr_nexthops_nexthop_mpls_label_stack_entry_traffic_class_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* TODO: implement me. */
		break;
	}

	return NB_OK;
}
