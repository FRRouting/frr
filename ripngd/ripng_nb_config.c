// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 1998 Kunihiro Ishiguro
 * Copyright (C) 2018 NetDEF, Inc.
 *                    Renato Westphal
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
#include "agg_table.h"
#include "northbound.h"
#include "libfrr.h"

#include "ripngd/ripngd.h"
#include "ripngd/ripng_nb.h"
#include "ripngd/ripng_debug.h"
#include "ripngd/ripng_route.h"

/*
 * XPath: /frr-ripngd:ripngd/instance
 */
int ripngd_instance_create(struct nb_cb_create_args *args)
{
	struct ripng *ripng;
	struct vrf *vrf;
	const char *vrf_name;
	int socket;

	vrf_name = yang_dnode_get_string(args->dnode, "vrf");
	vrf = vrf_lookup_by_name(vrf_name);

	/*
	 * Try to create a RIPng socket only if the VRF is enabled, otherwise
	 * create a disabled RIPng instance and wait for the VRF to be enabled.
	 */
	switch (args->event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
		if (!vrf || !vrf_is_enabled(vrf))
			break;

		socket = ripng_make_socket(vrf);
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

		ripng = ripng_create(vrf_name, vrf, socket);
		nb_running_set_entry(args->dnode, ripng);
		break;
	}

	return NB_OK;
}

int ripngd_instance_destroy(struct nb_cb_destroy_args *args)
{
	struct ripng *ripng;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_unset_entry(args->dnode);
	ripng_clean(ripng);

	return NB_OK;
}

const void *ripngd_instance_get_next(struct nb_cb_get_next_args *args)
{
	struct ripng *ripng = (struct ripng *)args->list_entry;

	if (args->list_entry == NULL)
		ripng = RB_MIN(ripng_instance_head, &ripng_instances);
	else
		ripng = RB_NEXT(ripng_instance_head, ripng);

	return ripng;
}

int ripngd_instance_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct ripng *ripng = args->list_entry;

	args->keys->num = 1;
	strlcpy(args->keys->key[0], ripng->vrf_name,
		sizeof(args->keys->key[0]));

	return NB_OK;
}

const void *ripngd_instance_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *vrf_name = args->keys->key[0];

	return ripng_lookup_by_vrf_name(vrf_name);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/allow-ecmp
 */
int ripngd_instance_allow_ecmp_modify(struct nb_cb_modify_args *args)
{
	struct ripng *ripng;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	ripng->ecmp =
		MIN(yang_dnode_get_uint8(args->dnode, NULL), zebra_ecmp_count);
	if (!ripng->ecmp) {
		ripng_ecmp_disable(ripng);
		return NB_OK;
	}

	ripng_ecmp_change(ripng);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/default-information-originate
 */
int ripngd_instance_default_information_originate_modify(
	struct nb_cb_modify_args *args)
{
	struct ripng *ripng;
	bool default_information;
	struct prefix_ipv6 p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	default_information = yang_dnode_get_bool(args->dnode, NULL);

	(void)str2prefix_ipv6("::/0", &p);
	if (default_information) {
		ripng_redistribute_add(ripng, ZEBRA_ROUTE_RIPNG,
				       RIPNG_ROUTE_DEFAULT, &p, 0, NULL, 0);
	} else {
		ripng_redistribute_delete(ripng, ZEBRA_ROUTE_RIPNG,
					  RIPNG_ROUTE_DEFAULT, &p, 0);
	}

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/default-metric
 */
int ripngd_instance_default_metric_modify(struct nb_cb_modify_args *args)
{
	struct ripng *ripng;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	ripng->default_metric = yang_dnode_get_uint8(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/network
 */
int ripngd_instance_network_create(struct nb_cb_create_args *args)
{
	struct ripng *ripng;
	struct prefix p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	yang_dnode_get_ipv6p(&p, args->dnode, NULL);
	apply_mask_ipv6((struct prefix_ipv6 *)&p);

	return ripng_enable_network_add(ripng, &p);
}

int ripngd_instance_network_destroy(struct nb_cb_destroy_args *args)
{
	struct ripng *ripng;
	struct prefix p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	yang_dnode_get_ipv6p(&p, args->dnode, NULL);
	apply_mask_ipv6((struct prefix_ipv6 *)&p);

	return ripng_enable_network_delete(ripng, &p);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/interface
 */
int ripngd_instance_interface_create(struct nb_cb_create_args *args)
{
	struct ripng *ripng;
	const char *ifname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	ifname = yang_dnode_get_string(args->dnode, NULL);

	return ripng_enable_if_add(ripng, ifname);
}

int ripngd_instance_interface_destroy(struct nb_cb_destroy_args *args)
{
	struct ripng *ripng;
	const char *ifname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	ifname = yang_dnode_get_string(args->dnode, NULL);

	return ripng_enable_if_delete(ripng, ifname);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/offset-list
 */
int ripngd_instance_offset_list_create(struct nb_cb_create_args *args)
{
	struct ripng *ripng;
	const char *ifname;
	struct ripng_offset_list *offset;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	ifname = yang_dnode_get_string(args->dnode, "interface");

	offset = ripng_offset_list_new(ripng, ifname);
	nb_running_set_entry(args->dnode, offset);

	return NB_OK;
}

int ripngd_instance_offset_list_destroy(struct nb_cb_destroy_args *args)
{
	int direct;
	struct ripng_offset_list *offset;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	direct = yang_dnode_get_enum(args->dnode, "direction");

	offset = nb_running_unset_entry(args->dnode);
	if (offset->direct[direct].alist_name) {
		free(offset->direct[direct].alist_name);
		offset->direct[direct].alist_name = NULL;
	}
	if (offset->direct[RIPNG_OFFSET_LIST_IN].alist_name == NULL
	    && offset->direct[RIPNG_OFFSET_LIST_OUT].alist_name == NULL)
		ripng_offset_list_del(offset);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/offset-list/access-list
 */
int ripngd_instance_offset_list_access_list_modify(
	struct nb_cb_modify_args *args)
{
	int direct;
	struct ripng_offset_list *offset;
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
 * XPath: /frr-ripngd:ripngd/instance/offset-list/metric
 */
int ripngd_instance_offset_list_metric_modify(struct nb_cb_modify_args *args)
{
	int direct;
	uint8_t metric;
	struct ripng_offset_list *offset;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	direct = yang_dnode_get_enum(args->dnode, "../direction");
	metric = yang_dnode_get_uint8(args->dnode, NULL);

	offset = nb_running_get_entry(args->dnode, NULL, true);
	offset->direct[direct].metric = metric;

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/passive-interface
 */
int ripngd_instance_passive_interface_create(struct nb_cb_create_args *args)
{
	struct ripng *ripng;
	const char *ifname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	ifname = yang_dnode_get_string(args->dnode, NULL);

	return ripng_passive_interface_set(ripng, ifname);
}

int ripngd_instance_passive_interface_destroy(struct nb_cb_destroy_args *args)
{
	struct ripng *ripng;
	const char *ifname;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	ifname = yang_dnode_get_string(args->dnode, NULL);

	return ripng_passive_interface_unset(ripng, ifname);
}

/*
 * XPath: /frr-ripng:ripng/instance/distribute-list
 */
int ripngd_instance_distribute_list_create(struct nb_cb_create_args *args)
{
	struct ripng *ripng;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	group_distribute_list_create_helper(args, ripng->distribute_ctx);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/redistribute
 */
int ripngd_instance_redistribute_create(struct nb_cb_create_args *args)
{
	struct ripng *ripng;
	int type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, "protocol");

	ripng->redist[type].enabled = true;

	return NB_OK;
}

int ripngd_instance_redistribute_destroy(struct nb_cb_destroy_args *args)
{
	struct ripng *ripng;
	int type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, "protocol");

	ripng->redist[type].enabled = false;
	if (ripng->redist[type].route_map.name) {
		free(ripng->redist[type].route_map.name);
		ripng->redist[type].route_map.name = NULL;
		ripng->redist[type].route_map.map = NULL;
	}
	ripng->redist[type].metric_config = false;
	ripng->redist[type].metric = 0;

	if (ripng->enabled)
		ripng_redistribute_conf_delete(ripng, type);

	return NB_OK;
}

void ripngd_instance_redistribute_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	struct ripng *ripng;
	int type;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, "protocol");

	if (ripng->enabled)
		ripng_redistribute_conf_update(ripng, type);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/redistribute/route-map
 */
int ripngd_instance_redistribute_route_map_modify(
	struct nb_cb_modify_args *args)
{
	struct ripng *ripng;
	int type;
	const char *rmap_name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, "../protocol");
	rmap_name = yang_dnode_get_string(args->dnode, NULL);

	if (ripng->redist[type].route_map.name)
		free(ripng->redist[type].route_map.name);
	ripng->redist[type].route_map.name = strdup(rmap_name);
	ripng->redist[type].route_map.map = route_map_lookup_by_name(rmap_name);

	return NB_OK;
}

int ripngd_instance_redistribute_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	struct ripng *ripng;
	int type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, "../protocol");

	free(ripng->redist[type].route_map.name);
	ripng->redist[type].route_map.name = NULL;
	ripng->redist[type].route_map.map = NULL;

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/redistribute/metric
 */
int ripngd_instance_redistribute_metric_modify(struct nb_cb_modify_args *args)
{
	struct ripng *ripng;
	int type;
	uint8_t metric;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, "../protocol");
	metric = yang_dnode_get_uint8(args->dnode, NULL);

	ripng->redist[type].metric_config = true;
	ripng->redist[type].metric = metric;

	return NB_OK;
}

int ripngd_instance_redistribute_metric_destroy(struct nb_cb_destroy_args *args)
{
	struct ripng *ripng;
	int type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	type = yang_dnode_get_enum(args->dnode, "../protocol");

	ripng->redist[type].metric_config = false;
	ripng->redist[type].metric = 0;

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/if-route-maps/if-route-map
 */
int ripngd_instance_if_route_maps_if_route_map_create(
	struct nb_cb_create_args *args)
{
	/* if_rmap is created when first routemap is added */
	return NB_OK;
}

int ripngd_instance_if_route_maps_if_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	struct ripng *ripng;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/*
	 * YANG will prune edit deletes up to the most general deleted node so
	 * we need to handle deleting any existing state underneath and not
	 * count on those more specific callbacks being called individually.
	 */

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	if_rmap_yang_destroy_cb(ripng->if_rmap_ctx, args->dnode);

	return NB_OK;
}

static void if_route_map_modify(const struct lyd_node *dnode,
				enum if_rmap_type type, bool delete)
{
	struct ripng *ripng = nb_running_get_entry(dnode, NULL, true);

	if_rmap_yang_modify_cb(ripng->if_rmap_ctx, dnode, type, delete);
}
/*
 * XPath: /frr-ripng:ripng/instance/if-route-maps/if-route-map/in-route-map
 */
int ripngd_instance_if_route_maps_if_route_map_in_route_map_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if_route_map_modify(args->dnode, IF_RMAP_IN, false);

	return NB_OK;
}

int ripngd_instance_if_route_maps_if_route_map_in_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if_route_map_modify(args->dnode, IF_RMAP_IN, true);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/if-route-maps/if-route-map/out-route-map
 */
int ripngd_instance_if_route_maps_if_route_map_out_route_map_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if_route_map_modify(args->dnode, IF_RMAP_OUT, false);

	return NB_OK;
}

int ripngd_instance_if_route_maps_if_route_map_out_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if_route_map_modify(args->dnode, IF_RMAP_OUT, true);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/static-route
 */
int ripngd_instance_static_route_create(struct nb_cb_create_args *args)
{
	struct ripng *ripng;
	struct prefix_ipv6 p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	yang_dnode_get_ipv6p(&p, args->dnode, NULL);
	apply_mask_ipv6(&p);

	ripng_redistribute_add(ripng, ZEBRA_ROUTE_RIPNG, RIPNG_ROUTE_STATIC, &p,
			       0, NULL, 0);

	return NB_OK;
}

int ripngd_instance_static_route_destroy(struct nb_cb_destroy_args *args)
{
	struct ripng *ripng;
	struct prefix_ipv6 p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	yang_dnode_get_ipv6p(&p, args->dnode, NULL);
	apply_mask_ipv6(&p);

	ripng_redistribute_delete(ripng, ZEBRA_ROUTE_RIPNG, RIPNG_ROUTE_STATIC,
				  &p, 0);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/aggregate-address
 */
int ripngd_instance_aggregate_address_create(struct nb_cb_create_args *args)
{
	struct ripng *ripng;
	struct prefix_ipv6 p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	yang_dnode_get_ipv6p(&p, args->dnode, NULL);
	apply_mask_ipv6(&p);

	ripng_aggregate_add(ripng, (struct prefix *)&p);

	return NB_OK;
}

int ripngd_instance_aggregate_address_destroy(struct nb_cb_destroy_args *args)
{
	struct ripng *ripng;
	struct prefix_ipv6 p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	yang_dnode_get_ipv6p(&p, args->dnode, NULL);
	apply_mask_ipv6(&p);

	ripng_aggregate_delete(ripng, (struct prefix *)&p);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/timers
 */
void ripngd_instance_timers_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct ripng *ripng;

	ripng = nb_running_get_entry(args->dnode, NULL, true);

	/* Reset update timer thread. */
	ripng_event(ripng, RIPNG_UPDATE_EVENT, 0);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/timers/flush-interval
 */
int ripngd_instance_timers_flush_interval_modify(struct nb_cb_modify_args *args)
{
	struct ripng *ripng;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	ripng->garbage_time = yang_dnode_get_uint16(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/timers/holddown-interval
 */
int ripngd_instance_timers_holddown_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct ripng *ripng;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	ripng->timeout_time = yang_dnode_get_uint16(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/timers/update-interval
 */
int ripngd_instance_timers_update_interval_modify(
	struct nb_cb_modify_args *args)
{
	struct ripng *ripng;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(args->dnode, NULL, true);
	ripng->update_time = yang_dnode_get_uint16(args->dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripngd:ripng/split-horizon
 */
int lib_interface_ripng_split_horizon_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct ripng_interface *ri;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(args->dnode, NULL, true);
	ri = ifp->info;
	ri->split_horizon = yang_dnode_get_enum(args->dnode, NULL);

	return NB_OK;
}
