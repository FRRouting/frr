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
#include "ripd/rip_nb.h"
#include "ripd/rip_debug.h"
#include "ripd/rip_interface.h"

/*
 * XPath: /frr-ripd:ripd/instance
 */
int ripd_instance_create(enum nb_event event, const struct lyd_node *dnode,
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

int ripd_instance_destroy(enum nb_event event, const struct lyd_node *dnode)
{
	struct rip *rip;

	if (event != NB_EV_APPLY)
		return NB_OK;

	rip = nb_running_unset_entry(dnode);
	rip_clean(rip);

	return NB_OK;
}

/*
 * XPath: /frr-ripd:ripd/instance/allow-ecmp
 */
int ripd_instance_allow_ecmp_modify(enum nb_event event,
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
int ripd_instance_default_information_originate_modify(
	enum nb_event event, const struct lyd_node *dnode,
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
int ripd_instance_default_metric_modify(enum nb_event event,
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
int ripd_instance_distance_default_modify(enum nb_event event,
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
int ripd_instance_distance_source_create(enum nb_event event,
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

int ripd_instance_distance_source_destroy(enum nb_event event,
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
int ripd_instance_distance_source_distance_modify(enum nb_event event,
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
int ripd_instance_distance_source_access_list_modify(
	enum nb_event event, const struct lyd_node *dnode,
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

int ripd_instance_distance_source_access_list_destroy(
	enum nb_event event, const struct lyd_node *dnode)
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
int ripd_instance_explicit_neighbor_create(enum nb_event event,
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

int ripd_instance_explicit_neighbor_destroy(enum nb_event event,
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
int ripd_instance_network_create(enum nb_event event,
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

int ripd_instance_network_destroy(enum nb_event event,
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
int ripd_instance_interface_create(enum nb_event event,
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

int ripd_instance_interface_destroy(enum nb_event event,
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
int ripd_instance_offset_list_create(enum nb_event event,
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

int ripd_instance_offset_list_destroy(enum nb_event event,
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
int ripd_instance_offset_list_access_list_modify(enum nb_event event,
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
int ripd_instance_offset_list_metric_modify(enum nb_event event,
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
int ripd_instance_passive_default_modify(enum nb_event event,
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
int ripd_instance_passive_interface_create(enum nb_event event,
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

int ripd_instance_passive_interface_destroy(enum nb_event event,
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
int ripd_instance_non_passive_interface_create(enum nb_event event,
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

int ripd_instance_non_passive_interface_destroy(enum nb_event event,
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
int ripd_instance_redistribute_create(enum nb_event event,
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

int ripd_instance_redistribute_destroy(enum nb_event event,
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

void ripd_instance_redistribute_apply_finish(const struct lyd_node *dnode)
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
int ripd_instance_redistribute_route_map_modify(enum nb_event event,
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

int ripd_instance_redistribute_route_map_destroy(enum nb_event event,
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
int ripd_instance_redistribute_metric_modify(enum nb_event event,
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

int ripd_instance_redistribute_metric_destroy(enum nb_event event,
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
int ripd_instance_static_route_create(enum nb_event event,
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

int ripd_instance_static_route_destroy(enum nb_event event,
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
void ripd_instance_timers_apply_finish(const struct lyd_node *dnode)
{
	struct rip *rip;

	rip = nb_running_get_entry(dnode, NULL, true);

	/* Reset update timer thread. */
	rip_event(rip, RIP_UPDATE_EVENT, 0);
}

/*
 * XPath: /frr-ripd:ripd/instance/timers/flush-interval
 */
int ripd_instance_timers_flush_interval_modify(enum nb_event event,
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
int ripd_instance_timers_holddown_interval_modify(enum nb_event event,
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
int ripd_instance_timers_update_interval_modify(enum nb_event event,
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
int ripd_instance_version_receive_modify(enum nb_event event,
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
int ripd_instance_version_send_modify(enum nb_event event,
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
int lib_interface_rip_split_horizon_modify(enum nb_event event,
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
int lib_interface_rip_v2_broadcast_modify(enum nb_event event,
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
int lib_interface_rip_version_receive_modify(enum nb_event event,
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
int lib_interface_rip_version_send_modify(enum nb_event event,
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
int lib_interface_rip_authentication_scheme_mode_modify(
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
int lib_interface_rip_authentication_scheme_md5_auth_length_modify(
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

int lib_interface_rip_authentication_scheme_md5_auth_length_destroy(
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
int lib_interface_rip_authentication_password_modify(
	enum nb_event event, const struct lyd_node *dnode,
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

int lib_interface_rip_authentication_password_destroy(
	enum nb_event event, const struct lyd_node *dnode)
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
int lib_interface_rip_authentication_key_chain_modify(
	enum nb_event event, const struct lyd_node *dnode,
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

int lib_interface_rip_authentication_key_chain_destroy(
	enum nb_event event, const struct lyd_node *dnode)
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
