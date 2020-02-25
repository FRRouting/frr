/*
 * Copyright (C) 1998 Kunihiro Ishiguro
 * Copyright (C) 2018 NetDEF, Inc.
 *                    Renato Westphal
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

#include <zebra.h>

#include "if.h"
#include "vrf.h"
#include "log.h"
#include "prefix.h"
#include "table.h"
#include "command.h"
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
int ripngd_instance_create(enum nb_event event, const struct lyd_node *dnode,
			   union nb_resource *resource)
{
	struct ripng *ripng;
	struct vrf *vrf;
	const char *vrf_name;
	int socket;

	vrf_name = yang_dnode_get_string(dnode, "./vrf");
	vrf = vrf_lookup_by_name(vrf_name);

	/*
	 * Try to create a RIPng socket only if the VRF is enabled, otherwise
	 * create a disabled RIPng instance and wait for the VRF to be enabled.
	 */
	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
		if (!vrf || !vrf_is_enabled(vrf))
			break;

		socket = ripng_make_socket(vrf);
		if (socket < 0)
			return NB_ERR_RESOURCE;
		resource->fd = socket;
		break;
	case NB_EV_ABORT:
		if (!vrf || !vrf_is_enabled(vrf))
			break;

		socket = resource->fd;
		close(socket);
		break;
	case NB_EV_APPLY:
		if (vrf && vrf_is_enabled(vrf))
			socket = resource->fd;
		else
			socket = -1;

		ripng = ripng_create(vrf_name, vrf, socket);
		nb_running_set_entry(dnode, ripng);
		break;
	}

	return NB_OK;
}

int ripngd_instance_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	struct ripng *ripng;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_unset_entry(dnode);
	ripng_clean(ripng);

	return NB_OK;
}

const void *ripngd_instance_get_next(const void *parent_list_entry,
				     const void *list_entry)
{
	struct ripng *ripng = (struct ripng *)list_entry;

	if (list_entry == NULL)
		ripng = RB_MIN(ripng_instance_head, &ripng_instances);
	else
		ripng = RB_NEXT(ripng_instance_head, ripng);

	return ripng;
}

int ripngd_instance_get_keys(const void *list_entry,
			     struct yang_list_keys *keys)
{
	const struct ripng *ripng = list_entry;

	keys->num = 1;
	strlcpy(keys->key[0], ripng->vrf_name, sizeof(keys->key[0]));

	return NB_OK;
}

const void *ripngd_instance_lookup_entry(const void *parent_list_entry,
					 const struct yang_list_keys *keys)
{
	const char *vrf_name = keys->key[0];

	return ripng_lookup_by_vrf_name(vrf_name);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/allow-ecmp
 */
int ripngd_instance_allow_ecmp_modify(enum nb_event event,
				      const struct lyd_node *dnode,
				      union nb_resource *resource)
{
	struct ripng *ripng;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	ripng->ecmp = yang_dnode_get_bool(dnode, NULL);
	if (!ripng->ecmp)
		ripng_ecmp_disable(ripng);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/default-information-originate
 */
int ripngd_instance_default_information_originate_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct ripng *ripng;
	bool default_information;
	struct prefix_ipv6 p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	default_information = yang_dnode_get_bool(dnode, NULL);

	str2prefix_ipv6("::/0", &p);
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
int ripngd_instance_default_metric_modify(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource)
{
	struct ripng *ripng;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	ripng->default_metric = yang_dnode_get_uint8(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/network
 */
int ripngd_instance_network_create(enum nb_event event,
				   const struct lyd_node *dnode,
				   union nb_resource *resource)
{
	struct ripng *ripng;
	struct prefix p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	yang_dnode_get_ipv6p(&p, dnode, NULL);
	apply_mask_ipv6((struct prefix_ipv6 *)&p);

	return ripng_enable_network_add(ripng, &p);
}

int ripngd_instance_network_destroy(enum nb_event event,
				    const struct lyd_node *dnode)
{
	struct ripng *ripng;
	struct prefix p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	yang_dnode_get_ipv6p(&p, dnode, NULL);
	apply_mask_ipv6((struct prefix_ipv6 *)&p);

	return ripng_enable_network_delete(ripng, &p);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/interface
 */
int ripngd_instance_interface_create(enum nb_event event,
				     const struct lyd_node *dnode,
				     union nb_resource *resource)
{
	struct ripng *ripng;
	const char *ifname;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	ifname = yang_dnode_get_string(dnode, NULL);

	return ripng_enable_if_add(ripng, ifname);
}

int ripngd_instance_interface_destroy(enum nb_event event,
				      const struct lyd_node *dnode)
{
	struct ripng *ripng;
	const char *ifname;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	ifname = yang_dnode_get_string(dnode, NULL);

	return ripng_enable_if_delete(ripng, ifname);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/offset-list
 */
int ripngd_instance_offset_list_create(enum nb_event event,
				       const struct lyd_node *dnode,
				       union nb_resource *resource)
{
	struct ripng *ripng;
	const char *ifname;
	struct ripng_offset_list *offset;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	ifname = yang_dnode_get_string(dnode, "./interface");

	offset = ripng_offset_list_new(ripng, ifname);
	nb_running_set_entry(dnode, offset);

	return NB_OK;
}

int ripngd_instance_offset_list_destroy(enum nb_event event,
					const struct lyd_node *dnode)
{
	int direct;
	struct ripng_offset_list *offset;

	if (event != NB_EV_APPLY)
		return NB_OK;

	direct = yang_dnode_get_enum(dnode, "./direction");

	offset = nb_running_unset_entry(dnode);
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
int ripngd_instance_offset_list_access_list_modify(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	int direct;
	struct ripng_offset_list *offset;
	const char *alist_name;

	if (event != NB_EV_APPLY)
		return NB_OK;

	direct = yang_dnode_get_enum(dnode, "../direction");
	alist_name = yang_dnode_get_string(dnode, NULL);

	offset = nb_running_get_entry(dnode, NULL, true);
	if (offset->direct[direct].alist_name)
		free(offset->direct[direct].alist_name);
	offset->direct[direct].alist_name = strdup(alist_name);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/offset-list/metric
 */
int ripngd_instance_offset_list_metric_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	int direct;
	uint8_t metric;
	struct ripng_offset_list *offset;

	if (event != NB_EV_APPLY)
		return NB_OK;

	direct = yang_dnode_get_enum(dnode, "../direction");
	metric = yang_dnode_get_uint8(dnode, NULL);

	offset = nb_running_get_entry(dnode, NULL, true);
	offset->direct[direct].metric = metric;

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/passive-interface
 */
int ripngd_instance_passive_interface_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	struct ripng *ripng;
	const char *ifname;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	ifname = yang_dnode_get_string(dnode, NULL);

	return ripng_passive_interface_set(ripng, ifname);
}

int ripngd_instance_passive_interface_destroy(enum nb_event event,
					      const struct lyd_node *dnode)
{
	struct ripng *ripng;
	const char *ifname;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	ifname = yang_dnode_get_string(dnode, NULL);

	return ripng_passive_interface_unset(ripng, ifname);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/redistribute
 */
int ripngd_instance_redistribute_create(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource)
{
	struct ripng *ripng;
	int type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	type = yang_dnode_get_enum(dnode, "./protocol");

	ripng->redist[type].enabled = true;

	return NB_OK;
}

int ripngd_instance_redistribute_destroy(enum nb_event event,
					 const struct lyd_node *dnode)
{
	struct ripng *ripng;
	int type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	type = yang_dnode_get_enum(dnode, "./protocol");

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

void ripngd_instance_redistribute_apply_finish(const struct lyd_node *dnode)
{
	struct ripng *ripng;
	int type;

	ripng = nb_running_get_entry(dnode, NULL, true);
	type = yang_dnode_get_enum(dnode, "./protocol");

	if (ripng->enabled)
		ripng_redistribute_conf_update(ripng, type);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/redistribute/route-map
 */
int ripngd_instance_redistribute_route_map_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct ripng *ripng;
	int type;
	const char *rmap_name;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	type = yang_dnode_get_enum(dnode, "../protocol");
	rmap_name = yang_dnode_get_string(dnode, NULL);

	if (ripng->redist[type].route_map.name)
		free(ripng->redist[type].route_map.name);
	ripng->redist[type].route_map.name = strdup(rmap_name);
	ripng->redist[type].route_map.map = route_map_lookup_by_name(rmap_name);

	return NB_OK;
}

int ripngd_instance_redistribute_route_map_destroy(enum nb_event event,
						   const struct lyd_node *dnode)
{
	struct ripng *ripng;
	int type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	type = yang_dnode_get_enum(dnode, "../protocol");

	free(ripng->redist[type].route_map.name);
	ripng->redist[type].route_map.name = NULL;
	ripng->redist[type].route_map.map = NULL;

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/redistribute/metric
 */
int ripngd_instance_redistribute_metric_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	struct ripng *ripng;
	int type;
	uint8_t metric;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	type = yang_dnode_get_enum(dnode, "../protocol");
	metric = yang_dnode_get_uint8(dnode, NULL);

	ripng->redist[type].metric_config = true;
	ripng->redist[type].metric = metric;

	return NB_OK;
}

int ripngd_instance_redistribute_metric_destroy(enum nb_event event,
						const struct lyd_node *dnode)
{
	struct ripng *ripng;
	int type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	type = yang_dnode_get_enum(dnode, "../protocol");

	ripng->redist[type].metric_config = false;
	ripng->redist[type].metric = 0;

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/static-route
 */
int ripngd_instance_static_route_create(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource)
{
	struct ripng *ripng;
	struct prefix_ipv6 p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	yang_dnode_get_ipv6p(&p, dnode, NULL);
	apply_mask_ipv6(&p);

	ripng_redistribute_add(ripng, ZEBRA_ROUTE_RIPNG, RIPNG_ROUTE_STATIC, &p,
			       0, NULL, 0);

	return NB_OK;
}

int ripngd_instance_static_route_destroy(enum nb_event event,
					 const struct lyd_node *dnode)
{
	struct ripng *ripng;
	struct prefix_ipv6 p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	yang_dnode_get_ipv6p(&p, dnode, NULL);
	apply_mask_ipv6(&p);

	ripng_redistribute_delete(ripng, ZEBRA_ROUTE_RIPNG, RIPNG_ROUTE_STATIC,
				  &p, 0);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/aggregate-address
 */
int ripngd_instance_aggregate_address_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	struct ripng *ripng;
	struct prefix_ipv6 p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	yang_dnode_get_ipv6p(&p, dnode, NULL);
	apply_mask_ipv6(&p);

	ripng_aggregate_add(ripng, (struct prefix *)&p);

	return NB_OK;
}

int ripngd_instance_aggregate_address_destroy(enum nb_event event,
					      const struct lyd_node *dnode)
{
	struct ripng *ripng;
	struct prefix_ipv6 p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	yang_dnode_get_ipv6p(&p, dnode, NULL);
	apply_mask_ipv6(&p);

	ripng_aggregate_delete(ripng, (struct prefix *)&p);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/timers
 */
void ripngd_instance_timers_apply_finish(const struct lyd_node *dnode)
{
	struct ripng *ripng;

	ripng = nb_running_get_entry(dnode, NULL, true);

	/* Reset update timer thread. */
	ripng_event(ripng, RIPNG_UPDATE_EVENT, 0);
}

/*
 * XPath: /frr-ripngd:ripngd/instance/timers/flush-interval
 */
int ripngd_instance_timers_flush_interval_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	struct ripng *ripng;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	ripng->garbage_time = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/timers/holddown-interval
 */
int ripngd_instance_timers_holddown_interval_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct ripng *ripng;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	ripng->timeout_time = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripngd:ripngd/instance/timers/update-interval
 */
int ripngd_instance_timers_update_interval_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct ripng *ripng;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ripng = nb_running_get_entry(dnode, NULL, true);
	ripng->update_time = yang_dnode_get_uint16(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripngd:ripng/split-horizon
 */
int lib_interface_ripng_split_horizon_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	struct interface *ifp;
	struct ripng_interface *ri;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(dnode, NULL, true);
	ri = ifp->info;
	ri->split_horizon = yang_dnode_get_enum(dnode, NULL);

	return NB_OK;
}
