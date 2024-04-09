// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 1997, 1998, 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 * Copyright (C) 2023 LabN Consulting, L.L.C.
 */

#include <zebra.h>

#include "if.h"
#include "vrf.h"
#include "log.h"
#include "prefix.h"
#include "table.h"
#include "command.h"
#include "if_rmap.h"
#include "routemap.h"
#include "northbound.h"
#include "libfrr.h"

#include "ripd/ripd.h"
#include "ripd/rip_nb.h"
#include "ripd/rip_debug.h"
#include "ripd/rip_interface.h"
#include "ripd/rip_bfd.h"

/*
 * XPath: /frr-ripd:ripd/instance
 */
int ripd_instance_create(struct nb_cb_create_args *args)
{
	struct rip *rip;
	struct vrf *vrf;
	const char *vrf_name;
	int socket;

	vrf_name = yang_dnode_get_string(args->dnode, "vrf");
	vrf = vrf_lookup_by_name(vrf_name);

	/*
	 * Try to create a RIP socket only if the VRF is enabled, otherwise
	 * create a disabled RIP instance and wait for the VRF to be enabled.
	 */
	switch (args->event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
		if (!vrf || !vrf_is_enabled(vrf))
			break;

		socket = rip_create_socket(vrf);
		if (socket < 0)
			return NB_ERR_RESOURCE;
		args->resource->fd = socket;
		break;
	case NB_EV_ABORT:
		if (!vrf || !vrf_is_enabled(vrf))
			break;

		socket = args->resource->fd;
		close(socket);
		break;
	case NB_EV_APPLY:
		if (vrf && vrf_is_enabled(vrf))
			socket = args->resource->fd;
		else
			socket = -1;

		rip = rip_create(vrf_name, vrf, socket);
		nb_running_set_entry(args->dnode, rip);
		break;
	}

	return NB_OK;
}

int ripd_instance_destroy(struct nb_cb_destroy_args *args)
{
	struct rip *rip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_unset_entry(args->dnode);
	rip_clean(rip);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/allow-ecmp
 */
int ripd_instance_allow_ecmp_modify(struct nb_cb_modify_args *args)
{
	struct rip *rip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	rip->ecmp =
		MIN(yang_dnode_get_uint8(args->dnode, NULL), zebra_ecmp_count);
	if (!rip->ecmp) {
		rip_ecmp_disable(rip);
		return NB_OK;
	}

	rip_ecmp_change(rip);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/default-information-originate
 */
int ripd_instance_default_information_originate_modify(
	struct nb_cb_modify_args *args)
{
	struct rip *rip;
	bool default_information;
	struct prefix_ipv4 p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	default_information = yang_dnode_get_bool(args->dnode, NULL);

	memset(&p, 0, sizeof(p));
	p.family = AF_INET;
	if (default_information) {
		struct nexthop nh;

		memset(&nh, 0, sizeof(nh));
		nh.type = NEXTHOP_TYPE_IPV4;
		rip_redistribute_add(rip, ZEBRA_ROUTE_RIP, RIP_ROUTE_DEFAULT,
				     &p, &nh, 0, 0, 0);
	} else {
		rip_redistribute_delete(rip, ZEBRA_ROUTE_RIP, RIP_ROUTE_DEFAULT,
					&p, 0);
	}

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/default-metric
 */
int ripd_instance_default_metric_modify(struct nb_cb_modify_args *args)
{
	struct rip *rip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	rip->default_metric = yang_dnode_get_uint8(args->dnode, NULL);
	/* rip_update_default_metric (); */

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/default
 */
int ripd_instance_distance_default_modify(struct nb_cb_modify_args *args)
{
	struct rip *rip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	rip->distance = yang_dnode_get_uint8(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/source
 */
int ripd_instance_distance_source_create(struct nb_cb_create_args *args)
{
	struct rip *rip;
	struct prefix_ipv4 prefix;
	struct route_node *rn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv4p(&prefix, args->dnode, "prefix");
	apply_mask_ipv4(&prefix);

	/* Get RIP distance node. */
	rip = nb_running_get_entry(args->dnode, NULL, true);
	rn = route_node_get(rip->distance_table, (struct prefix *)&prefix);
	rn->info = rip_distance_new();
	nb_running_set_entry(args->dnode, rn);

	return NB_OK;
}

int ripd_instance_distance_source_destroy(struct nb_cb_destroy_args *args)
{
	struct route_node *rn;
	struct rip_distance *rdistance;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rn = nb_running_unset_entry(args->dnode);
	rdistance = rn->info;
	rip_distance_free(rdistance);
	rn->info = NULL;
	route_unlock_node(rn);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/source/distance
 */
int ripd_instance_distance_source_distance_modify(
	struct nb_cb_modify_args *args)
{
	struct route_node *rn;
	uint8_t distance;
	struct rip_distance *rdistance;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Set distance value. */
	rn = nb_running_get_entry(args->dnode, NULL, true);
	distance = yang_dnode_get_uint8(args->dnode, NULL);
	rdistance = rn->info;
	rdistance->distance = distance;

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/source/access-list
 */
int ripd_instance_distance_source_access_list_modify(
	struct nb_cb_modify_args *args)
{
	const char *acl_name;
	struct route_node *rn;
	struct rip_distance *rdistance;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	acl_name = yang_dnode_get_string(args->dnode, NULL);

	/* Set access-list */
	rn = nb_running_get_entry(args->dnode, NULL, true);
	rdistance = rn->info;
	if (rdistance->access_list)
		free(rdistance->access_list);
	rdistance->access_list = strdup(acl_name);

	return NB_OK;
}

int ripd_instance_distance_source_access_list_destroy(
	struct nb_cb_destroy_args *args)
{
	struct route_node *rn;
	struct rip_distance *rdistance;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Reset access-list configuration. */
	rn = nb_running_get_entry(args->dnode, NULL, true);
	rdistance = rn->info;
	free(rdistance->access_list);
	rdistance->access_list = NULL;

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/explicit-neighbor
 */
int ripd_instance_explicit_neighbor_create(struct nb_cb_create_args *args)
{
	struct rip *rip;
	struct prefix_ipv4 p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	yang_dnode_get_ipv4(&p.prefix, args->dnode, NULL);

	return rip_neighbor_add(rip, &p);
}

int ripd_instance_explicit_neighbor_destroy(struct nb_cb_destroy_args *args)
{
	struct rip *rip;
	struct prefix_ipv4 p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	yang_dnode_get_ipv4(&p.prefix, args->dnode, NULL);

	return rip_neighbor_delete(rip, &p);
}

/*
 * XPath: /frr-ripd:ripd/instance/network
 */
int ripd_instance_network_create(struct nb_cb_create_args *args)
{
	struct rip *rip;
	struct prefix p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	yang_dnode_get_ipv4p(&p, args->dnode, NULL);
	apply_mask_ipv4((struct prefix_ipv4 *)&p);

	return rip_enable_network_add(rip, &p);
}

int ripd_instance_network_destroy(struct nb_cb_destroy_args *args)
{
	struct rip *rip;
	struct prefix p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	yang_dnode_get_ipv4p(&p, args->dnode, NULL);
	apply_mask_ipv4((struct prefix_ipv4 *)&p);

	return rip_enable_network_delete(rip, &p);
}

/*
 * XPath: /frr-ripd:ripd/instance/interface
 */
int ripd_instance_interface_create(struct nb_cb_create_args *args)
{
	struct rip *rip;
	const char *ifname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	ifname = yang_dnode_get_string(args->dnode, NULL);

	return rip_enable_if_add(rip, ifname);
}

int ripd_instance_interface_destroy(struct nb_cb_destroy_args *args)
{
	struct rip *rip;
	const char *ifname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	ifname = yang_dnode_get_string(args->dnode, NULL);

	return rip_enable_if_delete(rip, ifname);
}

/*
 * XPath: /frr-ripd:ripd/instance/offset-list
 */
int ripd_instance_offset_list_create(struct nb_cb_create_args *args)
{
	struct rip *rip;
	const char *ifname;
	struct rip_offset_list *offset;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	ifname = yang_dnode_get_string(args->dnode, "interface");

	offset = rip_offset_list_new(rip, ifname);
	nb_running_set_entry(args->dnode, offset);

	return NB_OK;
}

int ripd_instance_offset_list_destroy(struct nb_cb_destroy_args *args)
{
	int direct;
	struct rip_offset_list *offset;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	direct = yang_dnode_get_enum(args->dnode, "direction");

	offset = nb_running_unset_entry(args->dnode);
	if (offset->direct[direct].alist_name) {
		free(offset->direct[direct].alist_name);
		offset->direct[direct].alist_name = NULL;
	}
	if (offset->direct[RIP_OFFSET_LIST_IN].alist_name == NULL
	    && offset->direct[RIP_OFFSET_LIST_OUT].alist_name == NULL)
		offset_list_del(offset);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/offset-list/access-list
 */
int ripd_instance_offset_list_access_list_modify(struct nb_cb_modify_args *args)
{
	int direct;
	struct rip_offset_list *offset;
	const char *alist_name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	direct = yang_dnode_get_enum(args->dnode, "../direction");
	alist_name = yang_dnode_get_string(args->dnode, NULL);

	offset = nb_running_get_entry(args->dnode, NULL, true);
	if (offset->direct[direct].alist_name)
		free(offset->direct[direct].alist_name);
	offset->direct[direct].alist_name = strdup(alist_name);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/offset-list/metric
 */
int ripd_instance_offset_list_metric_modify(struct nb_cb_modify_args *args)
{
	int direct;
	uint8_t metric;
	struct rip_offset_list *offset;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	direct = yang_dnode_get_enum(args->dnode, "../direction");
	metric = yang_dnode_get_uint8(args->dnode, NULL);

	offset = nb_running_get_entry(args->dnode, NULL, true);
	offset->direct[direct].metric = metric;

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/passive-default
 */
int ripd_instance_passive_default_modify(struct nb_cb_modify_args *args)
{
	struct rip *rip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	rip->passive_default = yang_dnode_get_bool(args->dnode, NULL);
	rip_passive_nondefault_clean(rip);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/passive-interface
 */
int ripd_instance_passive_interface_create(struct nb_cb_create_args *args)
{
	struct rip *rip;
	const char *ifname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	ifname = yang_dnode_get_string(args->dnode, NULL);

	return rip_passive_nondefault_set(rip, ifname);
}

int ripd_instance_passive_interface_destroy(struct nb_cb_destroy_args *args)
{
	struct rip *rip;
	const char *ifname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	ifname = yang_dnode_get_string(args->dnode, NULL);

	return rip_passive_nondefault_unset(rip, ifname);
}

/*
 * XPath: /frr-ripd:ripd/instance/non-passive-interface
 */
int ripd_instance_non_passive_interface_create(struct nb_cb_create_args *args)
{
	struct rip *rip;
	const char *ifname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	ifname = yang_dnode_get_string(args->dnode, NULL);

	return rip_passive_nondefault_set(rip, ifname);
}

int ripd_instance_non_passive_interface_destroy(struct nb_cb_destroy_args *args)
{
	struct rip *rip;
	const char *ifname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	ifname = yang_dnode_get_string(args->dnode, NULL);

	return rip_passive_nondefault_unset(rip, ifname);
}


/*
 * XPath: /frr-ripd:ripd/instance/distribute-list
 */
int ripd_instance_distribute_list_create(struct nb_cb_create_args *args)
{
	struct rip *rip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	group_distribute_list_create_helper(args, rip->distribute_ctx);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/redistribute
 */
int ripd_instance_redistribute_create(struct nb_cb_create_args *args)
{
	struct rip *rip;
	int type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, "protocol");

	rip->redist[type].enabled = true;

	return NB_OK;
}

int ripd_instance_redistribute_destroy(struct nb_cb_destroy_args *args)
{
	struct rip *rip;
	int type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, "protocol");

	rip->redist[type].enabled = false;
	if (rip->redist[type].route_map.name) {
		free(rip->redist[type].route_map.name);
		rip->redist[type].route_map.name = NULL;
		rip->redist[type].route_map.map = NULL;
	}
	rip->redist[type].metric_config = false;
	rip->redist[type].metric = 0;

	if (rip->enabled)
		rip_redistribute_conf_delete(rip, type);

	return NB_OK;
}

void ripd_instance_redistribute_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct rip *rip;
	int type;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, "protocol");

	if (rip->enabled)
		rip_redistribute_conf_update(rip, type);
}

/*
 * XPath: /frr-ripd:ripd/instance/redistribute/route-map
 */
int ripd_instance_redistribute_route_map_modify(struct nb_cb_modify_args *args)
{
	struct rip *rip;
	int type;
	const char *rmap_name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, "../protocol");
	rmap_name = yang_dnode_get_string(args->dnode, NULL);

	if (rip->redist[type].route_map.name)
		free(rip->redist[type].route_map.name);
	rip->redist[type].route_map.name = strdup(rmap_name);
	rip->redist[type].route_map.map = route_map_lookup_by_name(rmap_name);

	return NB_OK;
}

int ripd_instance_redistribute_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	struct rip *rip;
	int type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, "../protocol");

	free(rip->redist[type].route_map.name);
	rip->redist[type].route_map.name = NULL;
	rip->redist[type].route_map.map = NULL;

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/redistribute/metric
 */
int ripd_instance_redistribute_metric_modify(struct nb_cb_modify_args *args)
{
	struct rip *rip;
	int type;
	uint8_t metric;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, "../protocol");
	metric = yang_dnode_get_uint8(args->dnode, NULL);

	rip->redist[type].metric_config = true;
	rip->redist[type].metric = metric;

	return NB_OK;
}

int ripd_instance_redistribute_metric_destroy(struct nb_cb_destroy_args *args)
{
	struct rip *rip;
	int type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, "../protocol");

	rip->redist[type].metric_config = false;
	rip->redist[type].metric = 0;

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/if-route-maps/if-route-map
 */
int ripd_instance_if_route_maps_if_route_map_create(
	struct nb_cb_create_args *args)
{
	/* if_rmap is created when first routemap is added */
	return NB_OK;
}

int ripd_instance_if_route_maps_if_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	struct rip *rip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/*
	 * YANG will prune edit deletes up to the most general deleted node so
	 * we need to handle deleting any existing state underneath and not
	 * count on those more specific callbacks being called individually.
	 */

	rip = nb_running_get_entry(args->dnode, NULL, true);
	if_rmap_yang_destroy_cb(rip->if_rmap_ctx, args->dnode);

	return NB_OK;
}

static void if_route_map_modify(const struct lyd_node *dnode,
				enum if_rmap_type type, bool delete)
{
	struct rip *rip = nb_running_get_entry(dnode, NULL, true);

	if_rmap_yang_modify_cb(rip->if_rmap_ctx, dnode, type, delete);
}

/*
 * XPath: /frr-ripd:ripd/instance/if-route-maps/if-route-map/in-route-map
 */
int ripd_instance_if_route_maps_if_route_map_in_route_map_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if_route_map_modify(args->dnode, IF_RMAP_IN, false);

	return NB_OK;
}

int ripd_instance_if_route_maps_if_route_map_in_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if_route_map_modify(args->dnode, IF_RMAP_IN, true);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/if-route-maps/if-route-map/out-route-map
 */
int ripd_instance_if_route_maps_if_route_map_out_route_map_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if_route_map_modify(args->dnode, IF_RMAP_OUT, false);

	return NB_OK;
}

int ripd_instance_if_route_maps_if_route_map_out_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if_route_map_modify(args->dnode, IF_RMAP_OUT, true);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/static-route
 */
int ripd_instance_static_route_create(struct nb_cb_create_args *args)
{
	struct rip *rip;
	struct nexthop nh;
	struct prefix_ipv4 p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	yang_dnode_get_ipv4p(&p, args->dnode, NULL);
	apply_mask_ipv4(&p);

	memset(&nh, 0, sizeof(nh));
	nh.type = NEXTHOP_TYPE_IPV4;
	rip_redistribute_add(rip, ZEBRA_ROUTE_RIP, RIP_ROUTE_STATIC, &p, &nh, 0,
			     0, 0);

	return NB_OK;
}

int ripd_instance_static_route_destroy(struct nb_cb_destroy_args *args)
{
	struct rip *rip;
	struct prefix_ipv4 p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	yang_dnode_get_ipv4p(&p, args->dnode, NULL);
	apply_mask_ipv4(&p);

	rip_redistribute_delete(rip, ZEBRA_ROUTE_RIP, RIP_ROUTE_STATIC, &p, 0);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/timers/
 */
void ripd_instance_timers_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct rip *rip;

	rip = nb_running_get_entry(args->dnode, NULL, true);

	/* Reset update timer thread. */
	rip_event(rip, RIP_UPDATE_EVENT, 0);
}

/*
 * XPath: /frr-ripd:ripd/instance/timers/flush-interval
 */
int ripd_instance_timers_flush_interval_modify(struct nb_cb_modify_args *args)
{
	struct rip *rip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	rip->garbage_time = yang_dnode_get_uint32(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/timers/holddown-interval
 */
int ripd_instance_timers_holddown_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct rip *rip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	rip->timeout_time = yang_dnode_get_uint32(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/timers/update-interval
 */
int ripd_instance_timers_update_interval_modify(struct nb_cb_modify_args *args)
{
	struct rip *rip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	rip->update_time = yang_dnode_get_uint32(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/version/receive
 */
int ripd_instance_version_receive_modify(struct nb_cb_modify_args *args)
{
	struct rip *rip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	rip->version_recv = yang_dnode_get_enum(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/version/send
 */
int ripd_instance_version_send_modify(struct nb_cb_modify_args *args)
{
	struct rip *rip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	rip->version_send = yang_dnode_get_enum(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/default-bfd-profile
 */
int ripd_instance_default_bfd_profile_modify(struct nb_cb_modify_args *args)
{
	struct rip *rip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	XFREE(MTYPE_RIP_BFD_PROFILE, rip->default_bfd_profile);
	rip->default_bfd_profile =
		XSTRDUP(MTYPE_RIP_BFD_PROFILE,
			yang_dnode_get_string(args->dnode, NULL));
	rip_bfd_instance_update(rip);

	return NB_OK;
}

int ripd_instance_default_bfd_profile_destroy(struct nb_cb_destroy_args *args)
{
	struct rip *rip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(args->dnode, NULL, true);
	XFREE(MTYPE_RIP_BFD_PROFILE, rip->default_bfd_profile);
	rip_bfd_instance_update(rip);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/split-horizon
 */
int lib_interface_rip_split_horizon_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	ri = ifp->info;
	ri->split_horizon = yang_dnode_get_enum(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/v2-broadcast
 */
int lib_interface_rip_v2_broadcast_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	ri = ifp->info;
	ri->v2_broadcast = yang_dnode_get_bool(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/version-receive
 */
int lib_interface_rip_version_receive_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	ri = ifp->info;
	ri->ri_receive = yang_dnode_get_enum(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/version-send
 */
int lib_interface_rip_version_send_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	ri = ifp->info;
	ri->ri_send = yang_dnode_get_enum(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/authentication-scheme/mode
 */
int lib_interface_rip_authentication_scheme_mode_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	ri = ifp->info;
	ri->auth_type = yang_dnode_get_enum(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-ripd:rip/authentication-scheme/md5-auth-length
 */
int lib_interface_rip_authentication_scheme_md5_auth_length_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	ri = ifp->info;
	ri->md5_auth_len = yang_dnode_get_enum(args->dnode, NULL);

	return NB_OK;
}

int lib_interface_rip_authentication_scheme_md5_auth_length_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	ri = ifp->info;
	ri->md5_auth_len = yang_get_default_enum(
		"%s/authentication-scheme/md5-auth-length", RIP_IFACE);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/authentication-password
 */
int lib_interface_rip_authentication_password_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	ri = ifp->info;
	XFREE(MTYPE_RIP_INTERFACE_STRING, ri->auth_str);
	ri->auth_str = XSTRDUP(MTYPE_RIP_INTERFACE_STRING,
			       yang_dnode_get_string(args->dnode, NULL));

	return NB_OK;
}

int lib_interface_rip_authentication_password_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	ri = ifp->info;
	XFREE(MTYPE_RIP_INTERFACE_STRING, ri->auth_str);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/bfd-monitoring
 */
int lib_interface_rip_bfd_create(struct nb_cb_create_args *args)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	ri = ifp->info;
	ri->bfd.enabled = yang_dnode_get_bool(args->dnode, "enable");
	XFREE(MTYPE_RIP_BFD_PROFILE, ri->bfd.profile);
	if (yang_dnode_exists(args->dnode, "profile"))
		ri->bfd.profile = XSTRDUP(
			MTYPE_RIP_BFD_PROFILE,
			yang_dnode_get_string(args->dnode, "profile"));

	rip_bfd_interface_update(ri);

	return NB_OK;
}

int lib_interface_rip_bfd_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	ri = ifp->info;
	ri->bfd.enabled = false;
	XFREE(MTYPE_RIP_BFD_PROFILE, ri->bfd.profile);
	rip_bfd_interface_update(ri);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/bfd-monitoring/enable
 */
int lib_interface_rip_bfd_enable_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	ri = ifp->info;
	ri->bfd.enabled = yang_dnode_get_bool(args->dnode, NULL);
	rip_bfd_interface_update(ri);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/bfd-monitoring/profile
 */
int lib_interface_rip_bfd_profile_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	ri = ifp->info;
	XFREE(MTYPE_RIP_BFD_PROFILE, ri->bfd.profile);
	ri->bfd.profile = XSTRDUP(MTYPE_RIP_BFD_PROFILE,
				  yang_dnode_get_string(args->dnode, NULL));
	rip_bfd_interface_update(ri);

	return NB_OK;
}

int lib_interface_rip_bfd_profile_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	ri = ifp->info;
	XFREE(MTYPE_RIP_BFD_PROFILE, ri->bfd.profile);
	rip_bfd_interface_update(ri);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/authentication-key-chain
 */
int lib_interface_rip_authentication_key_chain_modify(
	struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	ri = ifp->info;
	XFREE(MTYPE_RIP_INTERFACE_STRING, ri->key_chain);
	ri->key_chain = XSTRDUP(MTYPE_RIP_INTERFACE_STRING,
				yang_dnode_get_string(args->dnode, NULL));

	return NB_OK;
}

int lib_interface_rip_authentication_key_chain_destroy(
	struct nb_cb_destroy_args *args)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	ri = ifp->info;
	XFREE(MTYPE_RIP_INTERFACE_STRING, ri->key_chain);

	return NB_OK;
}
