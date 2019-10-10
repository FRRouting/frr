/*
 * Copyright (C) 1997, 1998, 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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
#include "northbound.h"
#include "libfrr.h"

#include "ripd/ripd.h"
#include "ripd/rip_debug.h"
#include "ripd/rip_cli.h"
#include "ripd/rip_interface.h"

/*
 * XPath: /frr-ripd:ripd/instance
 */
static int ripd_instance_create(enum nb_event event,
				const struct lyd_node *dnode,
				union nb_resource *resource)
{
	struct rip *rip;
	struct vrf *vrf;
	const char *vrf_name;
	int socket;

	vrf_name = yang_dnode_get_string(dnode, "./vrf");
	vrf = vrf_lookup_by_name(vrf_name);

	/*
	 * Try to create a RIP socket only if the VRF is enabled, otherwise
	 * create a disabled RIP instance and wait for the VRF to be enabled.
	 */
	switch (event) {
	case NB_EV_VALIDATE:
		break;
	case NB_EV_PREPARE:
		if (!vrf || !vrf_is_enabled(vrf))
			break;

		socket = rip_create_socket(vrf);
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

		rip = rip_create(vrf_name, vrf, socket);
		nb_running_set_entry(dnode, rip);
		break;
	}

	return NB_OK;
}

static int ripd_instance_destroy(enum nb_event event,
				 const struct lyd_node *dnode)
{
	struct rip *rip;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_unset_entry(dnode);
	rip_clean(rip);

	return NB_OK;
}

static const void *ripd_instance_get_next(const void *parent_list_entry,
					  const void *list_entry)
{
	struct rip *rip = (struct rip *)list_entry;

	if (list_entry == NULL)
		rip = RB_MIN(rip_instance_head, &rip_instances);
	else
		rip = RB_NEXT(rip_instance_head, rip);

	return rip;
}

static int ripd_instance_get_keys(const void *list_entry,
				  struct yang_list_keys *keys)
{
	const struct rip *rip = list_entry;

	keys->num = 1;
	strlcpy(keys->key[0], rip->vrf_name, sizeof(keys->key[0]));

	return NB_OK;
}

static const void *ripd_instance_lookup_entry(const void *parent_list_entry,
					      const struct yang_list_keys *keys)
{
	const char *vrf_name = keys->key[0];

	return rip_lookup_by_vrf_name(vrf_name);
}

/*
 * XPath: /frr-ripd:ripd/instance/allow-ecmp
 */
static int ripd_instance_allow_ecmp_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	struct rip *rip;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	rip->ecmp = yang_dnode_get_bool(dnode, NULL);
	if (!rip->ecmp)
		rip_ecmp_disable(rip);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/default-information-originate
 */
static int
ripd_instance_default_information_originate_modify(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	struct rip *rip;
	bool default_information;
	struct prefix_ipv4 p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	default_information = yang_dnode_get_bool(dnode, NULL);

	memset(&p, 0, sizeof(struct prefix_ipv4));
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
static int ripd_instance_default_metric_modify(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	struct rip *rip;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	rip->default_metric = yang_dnode_get_uint8(dnode, NULL);
	/* rip_update_default_metric (); */

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/default
 */
static int ripd_instance_distance_default_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	struct rip *rip;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	rip->distance = yang_dnode_get_uint8(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/source
 */
static int ripd_instance_distance_source_create(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	struct rip *rip;
	struct prefix_ipv4 prefix;
	struct route_node *rn;

	if (event != NB_EV_APPLY)
		return NB_OK;

	yang_dnode_get_ipv4p(&prefix, dnode, "./prefix");
	apply_mask_ipv4(&prefix);

	/* Get RIP distance node. */
	rip = nb_running_get_entry(dnode, NULL, true);
	rn = route_node_get(rip->distance_table, (struct prefix *)&prefix);
	rn->info = rip_distance_new();
	nb_running_set_entry(dnode, rn);

	return NB_OK;
}

static int ripd_instance_distance_source_destroy(enum nb_event event,
						 const struct lyd_node *dnode)
{
	struct route_node *rn;
	struct rip_distance *rdistance;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rn = nb_running_unset_entry(dnode);
	rdistance = rn->info;
	rip_distance_free(rdistance);
	rn->info = NULL;
	route_unlock_node(rn);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/source/distance
 */
static int
ripd_instance_distance_source_distance_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	struct route_node *rn;
	uint8_t distance;
	struct rip_distance *rdistance;

	if (event != NB_EV_APPLY)
		return NB_OK;

	/* Set distance value. */
	rn = nb_running_get_entry(dnode, NULL, true);
	distance = yang_dnode_get_uint8(dnode, NULL);
	rdistance = rn->info;
	rdistance->distance = distance;

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/distance/source/access-list
 */
static int
ripd_instance_distance_source_access_list_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	const char *acl_name;
	struct route_node *rn;
	struct rip_distance *rdistance;

	if (event != NB_EV_APPLY)
		return NB_OK;

	acl_name = yang_dnode_get_string(dnode, NULL);

	/* Set access-list */
	rn = nb_running_get_entry(dnode, NULL, true);
	rdistance = rn->info;
	if (rdistance->access_list)
		free(rdistance->access_list);
	rdistance->access_list = strdup(acl_name);

	return NB_OK;
}

static int
ripd_instance_distance_source_access_list_destroy(enum nb_event event,
						  const struct lyd_node *dnode)
{
	struct route_node *rn;
	struct rip_distance *rdistance;

	if (event != NB_EV_APPLY)
		return NB_OK;

	/* Reset access-list configuration. */
	rn = nb_running_get_entry(dnode, NULL, true);
	rdistance = rn->info;
	free(rdistance->access_list);
	rdistance->access_list = NULL;

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/explicit-neighbor
 */
static int ripd_instance_explicit_neighbor_create(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct rip *rip;
	struct prefix_ipv4 p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	yang_dnode_get_ipv4(&p.prefix, dnode, NULL);

	return rip_neighbor_add(rip, &p);
}

static int ripd_instance_explicit_neighbor_destroy(enum nb_event event,
						   const struct lyd_node *dnode)
{
	struct rip *rip;
	struct prefix_ipv4 p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	yang_dnode_get_ipv4(&p.prefix, dnode, NULL);

	return rip_neighbor_delete(rip, &p);
}

/*
 * XPath: /frr-ripd:ripd/instance/network
 */
static int ripd_instance_network_create(enum nb_event event,
					const struct lyd_node *dnode,
					union nb_resource *resource)
{
	struct rip *rip;
	struct prefix p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	yang_dnode_get_ipv4p(&p, dnode, NULL);
	apply_mask_ipv4((struct prefix_ipv4 *)&p);

	return rip_enable_network_add(rip, &p);
}

static int ripd_instance_network_destroy(enum nb_event event,
					 const struct lyd_node *dnode)
{
	struct rip *rip;
	struct prefix p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	yang_dnode_get_ipv4p(&p, dnode, NULL);
	apply_mask_ipv4((struct prefix_ipv4 *)&p);

	return rip_enable_network_delete(rip, &p);
}

/*
 * XPath: /frr-ripd:ripd/instance/interface
 */
static int ripd_instance_interface_create(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource)
{
	struct rip *rip;
	const char *ifname;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	ifname = yang_dnode_get_string(dnode, NULL);

	return rip_enable_if_add(rip, ifname);
}

static int ripd_instance_interface_destroy(enum nb_event event,
					   const struct lyd_node *dnode)
{
	struct rip *rip;
	const char *ifname;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	ifname = yang_dnode_get_string(dnode, NULL);

	return rip_enable_if_delete(rip, ifname);
}

/*
 * XPath: /frr-ripd:ripd/instance/offset-list
 */
static int ripd_instance_offset_list_create(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	struct rip *rip;
	const char *ifname;
	struct rip_offset_list *offset;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	ifname = yang_dnode_get_string(dnode, "./interface");

	offset = rip_offset_list_new(rip, ifname);
	nb_running_set_entry(dnode, offset);

	return NB_OK;
}

static int ripd_instance_offset_list_destroy(enum nb_event event,
					     const struct lyd_node *dnode)
{
	int direct;
	struct rip_offset_list *offset;

	if (event != NB_EV_APPLY)
		return NB_OK;

	direct = yang_dnode_get_enum(dnode, "./direction");

	offset = nb_running_unset_entry(dnode);
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
static int
ripd_instance_offset_list_access_list_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	int direct;
	struct rip_offset_list *offset;
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
 * XPath: /frr-ripd:ripd/instance/offset-list/metric
 */
static int ripd_instance_offset_list_metric_modify(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	int direct;
	uint8_t metric;
	struct rip_offset_list *offset;

	if (event != NB_EV_APPLY)
		return NB_OK;

	direct = yang_dnode_get_enum(dnode, "../direction");
	metric = yang_dnode_get_uint8(dnode, NULL);

	offset = nb_running_get_entry(dnode, NULL, true);
	offset->direct[direct].metric = metric;

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/passive-default
 */
static int ripd_instance_passive_default_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	struct rip *rip;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	rip->passive_default = yang_dnode_get_bool(dnode, NULL);
	rip_passive_nondefault_clean(rip);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/passive-interface
 */
static int ripd_instance_passive_interface_create(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct rip *rip;
	const char *ifname;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	ifname = yang_dnode_get_string(dnode, NULL);

	return rip_passive_nondefault_set(rip, ifname);
}

static int ripd_instance_passive_interface_destroy(enum nb_event event,
						   const struct lyd_node *dnode)
{
	struct rip *rip;
	const char *ifname;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	ifname = yang_dnode_get_string(dnode, NULL);

	return rip_passive_nondefault_unset(rip, ifname);
}

/*
 * XPath: /frr-ripd:ripd/instance/non-passive-interface
 */
static int
ripd_instance_non_passive_interface_create(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	struct rip *rip;
	const char *ifname;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	ifname = yang_dnode_get_string(dnode, NULL);

	return rip_passive_nondefault_unset(rip, ifname);
}

static int
ripd_instance_non_passive_interface_destroy(enum nb_event event,
					    const struct lyd_node *dnode)
{
	struct rip *rip;
	const char *ifname;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	ifname = yang_dnode_get_string(dnode, NULL);

	return rip_passive_nondefault_set(rip, ifname);
}

/*
 * XPath: /frr-ripd:ripd/instance/redistribute
 */
static int ripd_instance_redistribute_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	struct rip *rip;
	int type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	type = yang_dnode_get_enum(dnode, "./protocol");

	rip->redist[type].enabled = true;

	return NB_OK;
}

static int ripd_instance_redistribute_destroy(enum nb_event event,
					      const struct lyd_node *dnode)
{
	struct rip *rip;
	int type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	type = yang_dnode_get_enum(dnode, "./protocol");

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

static void
ripd_instance_redistribute_apply_finish(const struct lyd_node *dnode)
{
	struct rip *rip;
	int type;

	rip = nb_running_get_entry(dnode, NULL, true);
	type = yang_dnode_get_enum(dnode, "./protocol");

	if (rip->enabled)
		rip_redistribute_conf_update(rip, type);
}

/*
 * XPath: /frr-ripd:ripd/instance/redistribute/route-map
 */
static int
ripd_instance_redistribute_route_map_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	struct rip *rip;
	int type;
	const char *rmap_name;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	type = yang_dnode_get_enum(dnode, "../protocol");
	rmap_name = yang_dnode_get_string(dnode, NULL);

	if (rip->redist[type].route_map.name)
		free(rip->redist[type].route_map.name);
	rip->redist[type].route_map.name = strdup(rmap_name);
	rip->redist[type].route_map.map = route_map_lookup_by_name(rmap_name);

	return NB_OK;
}

static int
ripd_instance_redistribute_route_map_destroy(enum nb_event event,
					     const struct lyd_node *dnode)
{
	struct rip *rip;
	int type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	type = yang_dnode_get_enum(dnode, "../protocol");

	free(rip->redist[type].route_map.name);
	rip->redist[type].route_map.name = NULL;
	rip->redist[type].route_map.map = NULL;

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/redistribute/metric
 */
static int
ripd_instance_redistribute_metric_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct rip *rip;
	int type;
	uint8_t metric;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	type = yang_dnode_get_enum(dnode, "../protocol");
	metric = yang_dnode_get_uint8(dnode, NULL);

	rip->redist[type].metric_config = true;
	rip->redist[type].metric = metric;

	return NB_OK;
}

static int
ripd_instance_redistribute_metric_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct rip *rip;
	int type;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	type = yang_dnode_get_enum(dnode, "../protocol");

	rip->redist[type].metric_config = false;
	rip->redist[type].metric = 0;

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/static-route
 */
static int ripd_instance_static_route_create(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	struct rip *rip;
	struct nexthop nh;
	struct prefix_ipv4 p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	yang_dnode_get_ipv4p(&p, dnode, NULL);
	apply_mask_ipv4(&p);

	memset(&nh, 0, sizeof(nh));
	nh.type = NEXTHOP_TYPE_IPV4;
	rip_redistribute_add(rip, ZEBRA_ROUTE_RIP, RIP_ROUTE_STATIC, &p, &nh, 0,
			     0, 0);

	return NB_OK;
}

static int ripd_instance_static_route_destroy(enum nb_event event,
					      const struct lyd_node *dnode)
{
	struct rip *rip;
	struct prefix_ipv4 p;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	yang_dnode_get_ipv4p(&p, dnode, NULL);
	apply_mask_ipv4(&p);

	rip_redistribute_delete(rip, ZEBRA_ROUTE_RIP, RIP_ROUTE_STATIC, &p, 0);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/timers/
 */
static void ripd_instance_timers_apply_finish(const struct lyd_node *dnode)
{
	struct rip *rip;

	rip = nb_running_get_entry(dnode, NULL, true);

	/* Reset update timer thread. */
	rip_event(rip, RIP_UPDATE_EVENT, 0);
}

/*
 * XPath: /frr-ripd:ripd/instance/timers/flush-interval
 */
static int
ripd_instance_timers_flush_interval_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	struct rip *rip;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	rip->garbage_time = yang_dnode_get_uint32(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/timers/holddown-interval
 */
static int
ripd_instance_timers_holddown_interval_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	struct rip *rip;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	rip->timeout_time = yang_dnode_get_uint32(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/timers/update-interval
 */
static int
ripd_instance_timers_update_interval_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	struct rip *rip;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	rip->update_time = yang_dnode_get_uint32(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/version/receive
 */
static int ripd_instance_version_receive_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	struct rip *rip;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	rip->version_recv = yang_dnode_get_enum(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/version/send
 */
static int ripd_instance_version_send_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	struct rip *rip;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_get_entry(dnode, NULL, true);
	rip->version_send = yang_dnode_get_enum(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/split-horizon
 */
static int lib_interface_rip_split_horizon_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(dnode, NULL, true);
	ri = ifp->info;
	ri->split_horizon = yang_dnode_get_enum(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/v2-broadcast
 */
static int lib_interface_rip_v2_broadcast_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(dnode, NULL, true);
	ri = ifp->info;
	ri->v2_broadcast = yang_dnode_get_bool(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/version-receive
 */
static int
lib_interface_rip_version_receive_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(dnode, NULL, true);
	ri = ifp->info;
	ri->ri_receive = yang_dnode_get_enum(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/version-send
 */
static int lib_interface_rip_version_send_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(dnode, NULL, true);
	ri = ifp->info;
	ri->ri_send = yang_dnode_get_enum(dnode, NULL);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/authentication-scheme/mode
 */
static int lib_interface_rip_authentication_scheme_mode_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(dnode, NULL, true);
	ri = ifp->info;
	ri->auth_type = yang_dnode_get_enum(dnode, NULL);

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-ripd:rip/authentication-scheme/md5-auth-length
 */
static int lib_interface_rip_authentication_scheme_md5_auth_length_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(dnode, NULL, true);
	ri = ifp->info;
	ri->md5_auth_len = yang_dnode_get_enum(dnode, NULL);

	return NB_OK;
}

static int lib_interface_rip_authentication_scheme_md5_auth_length_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(dnode, NULL, true);
	ri = ifp->info;
	ri->md5_auth_len = yang_get_default_enum(
		"%s/authentication-scheme/md5-auth-length", RIP_IFACE);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/authentication-password
 */
static int
lib_interface_rip_authentication_password_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(dnode, NULL, true);
	ri = ifp->info;
	XFREE(MTYPE_RIP_INTERFACE_STRING, ri->auth_str);
	ri->auth_str = XSTRDUP(MTYPE_RIP_INTERFACE_STRING,
			       yang_dnode_get_string(dnode, NULL));

	return NB_OK;
}

static int
lib_interface_rip_authentication_password_destroy(enum nb_event event,
						  const struct lyd_node *dnode)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(dnode, NULL, true);
	ri = ifp->info;
	XFREE(MTYPE_RIP_INTERFACE_STRING, ri->auth_str);

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ripd:rip/authentication-key-chain
 */
static int
lib_interface_rip_authentication_key_chain_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(dnode, NULL, true);
	ri = ifp->info;
	XFREE(MTYPE_RIP_INTERFACE_STRING, ri->key_chain);
	ri->key_chain = XSTRDUP(MTYPE_RIP_INTERFACE_STRING,
				yang_dnode_get_string(dnode, NULL));

	return NB_OK;
}

static int
lib_interface_rip_authentication_key_chain_destroy(enum nb_event event,
						   const struct lyd_node *dnode)
{
	struct interface *ifp;
	struct rip_interface *ri;

	if (event != NB_EV_APPLY)
		return NB_OK;

	ifp = nb_running_get_entry(dnode, NULL, true);
	ri = ifp->info;
	XFREE(MTYPE_RIP_INTERFACE_STRING, ri->key_chain);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/state/neighbors/neighbor
 */
static const void *
ripd_instance_state_neighbors_neighbor_get_next(const void *parent_list_entry,
						const void *list_entry)
{
	const struct rip *rip = parent_list_entry;
	struct listnode *node;

	if (list_entry == NULL)
		node = listhead(rip->peer_list);
	else
		node = listnextnode((struct listnode *)list_entry);

	return node;
}

static int
ripd_instance_state_neighbors_neighbor_get_keys(const void *list_entry,
						struct yang_list_keys *keys)
{
	const struct listnode *node = list_entry;
	const struct rip_peer *peer = listgetdata(node);

	keys->num = 1;
	(void)inet_ntop(AF_INET, &peer->addr, keys->key[0],
			sizeof(keys->key[0]));

	return NB_OK;
}

static const void *ripd_instance_state_neighbors_neighbor_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys)
{
	const struct rip *rip = parent_list_entry;
	struct in_addr address;
	struct rip_peer *peer;
	struct listnode *node;

	yang_str2ipv4(keys->key[0], &address);

	for (ALL_LIST_ELEMENTS_RO(rip->peer_list, node, peer)) {
		if (IPV4_ADDR_SAME(&peer->addr, &address))
			return node;
	}

	return NULL;
}

/*
 * XPath: /frr-ripd:ripd/instance/state/neighbors/neighbor/address
 */
static struct yang_data *
ripd_instance_state_neighbors_neighbor_address_get_elem(const char *xpath,
							const void *list_entry)
{
	const struct listnode *node = list_entry;
	const struct rip_peer *peer = listgetdata(node);

	return yang_data_new_ipv4(xpath, &peer->addr);
}

/*
 * XPath: /frr-ripd:ripd/instance/state/neighbors/neighbor/last-update
 */
static struct yang_data *
ripd_instance_state_neighbors_neighbor_last_update_get_elem(
	const char *xpath, const void *list_entry)
{
	/* TODO: yang:date-and-time is tricky */
	return NULL;
}

/*
 * XPath: /frr-ripd:ripd/instance/state/neighbors/neighbor/bad-packets-rcvd
 */
static struct yang_data *
ripd_instance_state_neighbors_neighbor_bad_packets_rcvd_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct listnode *node = list_entry;
	const struct rip_peer *peer = listgetdata(node);

	return yang_data_new_uint32(xpath, peer->recv_badpackets);
}

/*
 * XPath: /frr-ripd:ripd/instance/state/neighbors/neighbor/bad-routes-rcvd
 */
static struct yang_data *
ripd_instance_state_neighbors_neighbor_bad_routes_rcvd_get_elem(
	const char *xpath, const void *list_entry)
{
	const struct listnode *node = list_entry;
	const struct rip_peer *peer = listgetdata(node);

	return yang_data_new_uint32(xpath, peer->recv_badroutes);
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route
 */
static const void *
ripd_instance_state_routes_route_get_next(const void *parent_list_entry,
					  const void *list_entry)
{
	const struct rip *rip = parent_list_entry;
	struct route_node *rn;

	if (list_entry == NULL)
		rn = route_top(rip->table);
	else
		rn = route_next((struct route_node *)list_entry);
	while (rn && rn->info == NULL)
		rn = route_next(rn);

	return rn;
}

static int
ripd_instance_state_routes_route_get_keys(const void *list_entry,
					  struct yang_list_keys *keys)
{
	const struct route_node *rn = list_entry;

	keys->num = 1;
	(void)prefix2str(&rn->p, keys->key[0], sizeof(keys->key[0]));

	return NB_OK;
}

static const void *
ripd_instance_state_routes_route_lookup_entry(const void *parent_list_entry,
					      const struct yang_list_keys *keys)
{
	const struct rip *rip = parent_list_entry;
	struct prefix prefix;
	struct route_node *rn;

	yang_str2ipv4p(keys->key[0], &prefix);

	rn = route_node_lookup(rip->table, &prefix);
	if (!rn || !rn->info)
		return NULL;

	route_unlock_node(rn);

	return rn;
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route/prefix
 */
static struct yang_data *
ripd_instance_state_routes_route_prefix_get_elem(const char *xpath,
						 const void *list_entry)
{
	const struct route_node *rn = list_entry;
	const struct rip_info *rinfo = listnode_head(rn->info);

	return yang_data_new_ipv4p(xpath, &rinfo->rp->p);
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route/next-hop
 */
static struct yang_data *
ripd_instance_state_routes_route_next_hop_get_elem(const char *xpath,
						   const void *list_entry)
{
	const struct route_node *rn = list_entry;
	const struct rip_info *rinfo = listnode_head(rn->info);

	switch (rinfo->nh.type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		return yang_data_new_ipv4(xpath, &rinfo->nh.gate.ipv4);
	default:
		return NULL;
	}
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route/interface
 */
static struct yang_data *
ripd_instance_state_routes_route_interface_get_elem(const char *xpath,
						    const void *list_entry)
{
	const struct route_node *rn = list_entry;
	const struct rip_info *rinfo = listnode_head(rn->info);
	const struct rip *rip = rip_info_get_instance(rinfo);

	switch (rinfo->nh.type) {
	case NEXTHOP_TYPE_IFINDEX:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		return yang_data_new_string(
			xpath,
			ifindex2ifname(rinfo->nh.ifindex, rip->vrf->vrf_id));
	default:
		return NULL;
	}
}

/*
 * XPath: /frr-ripd:ripd/instance/state/routes/route/metric
 */
static struct yang_data *
ripd_instance_state_routes_route_metric_get_elem(const char *xpath,
						 const void *list_entry)
{
	const struct route_node *rn = list_entry;
	const struct rip_info *rinfo = listnode_head(rn->info);

	return yang_data_new_uint8(xpath, rinfo->metric);
}

/*
 * XPath: /frr-ripd:clear-rip-route
 */
static void clear_rip_route(struct rip *rip)
{
	struct route_node *rp;

	if (IS_RIP_DEBUG_EVENT)
		zlog_debug("Clearing all RIP routes (VRF %s)", rip->vrf_name);

	/* Clear received RIP routes */
	for (rp = route_top(rip->table); rp; rp = route_next(rp)) {
		struct list *list;
		struct listnode *listnode;
		struct rip_info *rinfo;

		list = rp->info;
		if (!list)
			continue;

		for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
			if (!rip_route_rte(rinfo))
				continue;

			if (CHECK_FLAG(rinfo->flags, RIP_RTF_FIB))
				rip_zebra_ipv4_delete(rip, rp);
			break;
		}

		if (rinfo) {
			RIP_TIMER_OFF(rinfo->t_timeout);
			RIP_TIMER_OFF(rinfo->t_garbage_collect);
			listnode_delete(list, rinfo);
			rip_info_free(rinfo);
		}

		if (list_isempty(list)) {
			list_delete(&list);
			rp->info = NULL;
			route_unlock_node(rp);
		}
	}
}

static int clear_rip_route_rpc(const char *xpath, const struct list *input,
			       struct list *output)
{
	struct rip *rip;
	struct yang_data *yang_vrf;

	yang_vrf = yang_data_list_find(input, "%s/%s", xpath, "input/vrf");
	if (yang_vrf) {
		rip = rip_lookup_by_vrf_name(yang_vrf->value);
		if (rip)
			clear_rip_route(rip);
	} else {
		struct vrf *vrf;

		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			rip = vrf->info;
			if (!rip)
				continue;

			clear_rip_route(rip);
		}
	}

	return NB_OK;
}

/*
 * XPath: /frr-ripd:authentication-type-failure
 */
void ripd_notif_send_auth_type_failure(const char *ifname)
{
	const char *xpath = "/frr-ripd:authentication-type-failure";
	struct list *arguments;
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	arguments = yang_data_list_new();

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/interface-name", xpath);
	data = yang_data_new_string(xpath_arg, ifname);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-ripd:authentication-failure
 */
void ripd_notif_send_auth_failure(const char *ifname)
{
	const char *xpath = "/frr-ripd:authentication-failure";
	struct list *arguments;
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	arguments = yang_data_list_new();

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/interface-name", xpath);
	data = yang_data_new_string(xpath_arg, ifname);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/* clang-format off */
const struct frr_yang_module_info frr_ripd_info = {
	.name = "frr-ripd",
	.nodes = {
		{
			.xpath = "/frr-ripd:ripd/instance",
			.cbs = {
				.cli_show = cli_show_router_rip,
				.create = ripd_instance_create,
				.destroy = ripd_instance_destroy,
				.get_keys = ripd_instance_get_keys,
				.get_next = ripd_instance_get_next,
				.lookup_entry = ripd_instance_lookup_entry,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/allow-ecmp",
			.cbs = {
				.cli_show = cli_show_rip_allow_ecmp,
				.modify = ripd_instance_allow_ecmp_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/default-information-originate",
			.cbs = {
				.cli_show = cli_show_rip_default_information_originate,
				.modify = ripd_instance_default_information_originate_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/default-metric",
			.cbs = {
				.cli_show = cli_show_rip_default_metric,
				.modify = ripd_instance_default_metric_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/distance/default",
			.cbs = {
				.cli_show = cli_show_rip_distance,
				.modify = ripd_instance_distance_default_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/distance/source",
			.cbs = {
				.cli_show = cli_show_rip_distance_source,
				.create = ripd_instance_distance_source_create,
				.destroy = ripd_instance_distance_source_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/distance/source/distance",
			.cbs = {
				.modify = ripd_instance_distance_source_distance_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/distance/source/access-list",
			.cbs = {
				.destroy = ripd_instance_distance_source_access_list_destroy,
				.modify = ripd_instance_distance_source_access_list_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/explicit-neighbor",
			.cbs = {
				.cli_show = cli_show_rip_neighbor,
				.create = ripd_instance_explicit_neighbor_create,
				.destroy = ripd_instance_explicit_neighbor_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/network",
			.cbs = {
				.cli_show = cli_show_rip_network_prefix,
				.create = ripd_instance_network_create,
				.destroy = ripd_instance_network_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/interface",
			.cbs = {
				.cli_show = cli_show_rip_network_interface,
				.create = ripd_instance_interface_create,
				.destroy = ripd_instance_interface_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/offset-list",
			.cbs = {
				.cli_show = cli_show_rip_offset_list,
				.create = ripd_instance_offset_list_create,
				.destroy = ripd_instance_offset_list_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/offset-list/access-list",
			.cbs = {
				.modify = ripd_instance_offset_list_access_list_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/offset-list/metric",
			.cbs = {
				.modify = ripd_instance_offset_list_metric_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/passive-default",
			.cbs = {
				.cli_show = cli_show_rip_passive_default,
				.modify = ripd_instance_passive_default_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/passive-interface",
			.cbs = {
				.cli_show = cli_show_rip_passive_interface,
				.create = ripd_instance_passive_interface_create,
				.destroy = ripd_instance_passive_interface_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/non-passive-interface",
			.cbs = {
				.cli_show = cli_show_rip_non_passive_interface,
				.create = ripd_instance_non_passive_interface_create,
				.destroy = ripd_instance_non_passive_interface_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/redistribute",
			.cbs = {
				.apply_finish = ripd_instance_redistribute_apply_finish,
				.cli_show = cli_show_rip_redistribute,
				.create = ripd_instance_redistribute_create,
				.destroy = ripd_instance_redistribute_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/redistribute/route-map",
			.cbs = {
				.destroy = ripd_instance_redistribute_route_map_destroy,
				.modify = ripd_instance_redistribute_route_map_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/redistribute/metric",
			.cbs = {
				.destroy = ripd_instance_redistribute_metric_destroy,
				.modify = ripd_instance_redistribute_metric_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/static-route",
			.cbs = {
				.cli_show = cli_show_rip_route,
				.create = ripd_instance_static_route_create,
				.destroy = ripd_instance_static_route_destroy,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/timers",
			.cbs = {
				.apply_finish = ripd_instance_timers_apply_finish,
				.cli_show = cli_show_rip_timers,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/timers/flush-interval",
			.cbs = {
				.modify = ripd_instance_timers_flush_interval_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/timers/holddown-interval",
			.cbs = {
				.modify = ripd_instance_timers_holddown_interval_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/timers/update-interval",
			.cbs = {
				.modify = ripd_instance_timers_update_interval_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/version",
			.cbs = {
				.cli_show = cli_show_rip_version,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/version/receive",
			.cbs = {
				.modify = ripd_instance_version_receive_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/version/send",
			.cbs = {
				.modify = ripd_instance_version_send_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/split-horizon",
			.cbs = {
				.cli_show = cli_show_ip_rip_split_horizon,
				.modify = lib_interface_rip_split_horizon_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/v2-broadcast",
			.cbs = {
				.cli_show = cli_show_ip_rip_v2_broadcast,
				.modify = lib_interface_rip_v2_broadcast_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/version-receive",
			.cbs = {
				.cli_show = cli_show_ip_rip_receive_version,
				.modify = lib_interface_rip_version_receive_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/version-send",
			.cbs = {
				.cli_show = cli_show_ip_rip_send_version,
				.modify = lib_interface_rip_version_send_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-scheme",
			.cbs = {
				.cli_show = cli_show_ip_rip_authentication_scheme,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-scheme/mode",
			.cbs = {
				.modify = lib_interface_rip_authentication_scheme_mode_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-scheme/md5-auth-length",
			.cbs = {
				.destroy = lib_interface_rip_authentication_scheme_md5_auth_length_destroy,
				.modify = lib_interface_rip_authentication_scheme_md5_auth_length_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-password",
			.cbs = {
				.cli_show = cli_show_ip_rip_authentication_string,
				.destroy = lib_interface_rip_authentication_password_destroy,
				.modify = lib_interface_rip_authentication_password_modify,
			},
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-ripd:rip/authentication-key-chain",
			.cbs = {
				.cli_show = cli_show_ip_rip_authentication_key_chain,
				.destroy = lib_interface_rip_authentication_key_chain_destroy,
				.modify = lib_interface_rip_authentication_key_chain_modify,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/neighbors/neighbor",
			.cbs = {
				.get_keys = ripd_instance_state_neighbors_neighbor_get_keys,
				.get_next = ripd_instance_state_neighbors_neighbor_get_next,
				.lookup_entry = ripd_instance_state_neighbors_neighbor_lookup_entry,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/neighbors/neighbor/address",
			.cbs = {
				.get_elem = ripd_instance_state_neighbors_neighbor_address_get_elem,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/neighbors/neighbor/last-update",
			.cbs = {
				.get_elem = ripd_instance_state_neighbors_neighbor_last_update_get_elem,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/neighbors/neighbor/bad-packets-rcvd",
			.cbs = {
				.get_elem = ripd_instance_state_neighbors_neighbor_bad_packets_rcvd_get_elem,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/neighbors/neighbor/bad-routes-rcvd",
			.cbs = {
				.get_elem = ripd_instance_state_neighbors_neighbor_bad_routes_rcvd_get_elem,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/routes/route",
			.cbs = {
				.get_keys = ripd_instance_state_routes_route_get_keys,
				.get_next = ripd_instance_state_routes_route_get_next,
				.lookup_entry = ripd_instance_state_routes_route_lookup_entry,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/routes/route/prefix",
			.cbs = {
				.get_elem = ripd_instance_state_routes_route_prefix_get_elem,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/routes/route/next-hop",
			.cbs = {
				.get_elem = ripd_instance_state_routes_route_next_hop_get_elem,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/routes/route/interface",
			.cbs = {
				.get_elem = ripd_instance_state_routes_route_interface_get_elem,
			},
		},
		{
			.xpath = "/frr-ripd:ripd/instance/state/routes/route/metric",
			.cbs = {
				.get_elem = ripd_instance_state_routes_route_metric_get_elem,
			},
		},
		{
			.xpath = "/frr-ripd:clear-rip-route",
			.cbs = {
				.rpc = clear_rip_route_rpc,
			},
		},
		{
			.xpath = NULL,
		},
	}
};
