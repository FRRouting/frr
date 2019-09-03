/*
 * EIGRP daemon northbound implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <zebra.h>

#include "lib/keychain.h"
#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/table.h"
#include "lib/vrf.h"
#include "lib/zclient.h"

#include "eigrp_structs.h"
#include "eigrpd.h"
#include "eigrp_interface.h"
#include "eigrp_network.h"
#include "eigrp_zebra.h"

/* Helper functions. */
static void redistribute_get_metrics(const struct lyd_node *dnode,
				     struct eigrp_metrics *em)
{
	memset(em, 0, sizeof(*em));

	if (yang_dnode_exists(dnode, "./bandwidth"))
		em->bandwidth = yang_dnode_get_uint32(dnode, "./bandwidth");
	if (yang_dnode_exists(dnode, "./delay"))
		em->delay = yang_dnode_get_uint32(dnode, "./delay");
#if 0 /* TODO: How does MTU work? */
	if (yang_dnode_exists(dnode, "./mtu"))
		em->mtu[0] = yang_dnode_get_uint32(dnode, "./mtu");
#endif
	if (yang_dnode_exists(dnode, "./load"))
		em->load = yang_dnode_get_uint32(dnode, "./load");
	if (yang_dnode_exists(dnode, "./reliability"))
		em->reliability = yang_dnode_get_uint32(dnode, "./reliability");
}

static struct eigrp_interface *eigrp_interface_lookup(const struct eigrp *eigrp,
						      const char *ifname)
{
	struct eigrp_interface *eif;
	struct listnode *ln;

	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, ln, eif)) {
		if (strcmp(ifname, eif->ifp->name))
			continue;

		return eif;
	}

	return NULL;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance
 */
static int eigrpd_instance_create(enum nb_event event,
				  const struct lyd_node *dnode,
				  union nb_resource *resource)
{
	struct eigrp *eigrp;
	const char *vrf;
	vrf_id_t vrfid;

	switch (event) {
	case NB_EV_VALIDATE:
		/* NOTHING */
		break;
	case NB_EV_PREPARE:
		vrf = yang_dnode_get_string(dnode, "./vrf");
		vrfid = vrf_name_to_id(vrf);

		eigrp = eigrp_get(yang_dnode_get_uint16(dnode, "./asn"), vrfid);
		resource->ptr = eigrp;
		break;
	case NB_EV_ABORT:
		eigrp_finish_final(resource->ptr);
		break;
	case NB_EV_APPLY:
		nb_running_set_entry(dnode, resource->ptr);
		break;
	}

	return NB_OK;
}

static int eigrpd_instance_destroy(enum nb_event event,
				   const struct lyd_node *dnode)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_unset_entry(dnode);
		eigrp_finish_final(eigrp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/router-id
 */
static int eigrpd_instance_router_id_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		yang_dnode_get_ipv4(&eigrp->router_id_static, dnode, NULL);
		break;
	}

	return NB_OK;
}

static int eigrpd_instance_router_id_destroy(enum nb_event event,
					     const struct lyd_node *dnode)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp->router_id_static.s_addr = 0;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/passive-interface
 */
static int
eigrpd_instance_passive_interface_create(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct eigrp_interface *eif;
	struct eigrp *eigrp;
	const char *ifname;

	switch (event) {
	case NB_EV_VALIDATE:
		eigrp = nb_running_get_entry(dnode, NULL, false);
		if (eigrp == NULL) {
			/*
			 * XXX: we can't verify if the interface exists
			 * and is active until EIGRP is up.
			 */
			break;
		}

		ifname = yang_dnode_get_string(dnode, NULL);
		eif = eigrp_interface_lookup(eigrp, ifname);
		if (eif == NULL)
			return NB_ERR_INCONSISTENCY;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		ifname = yang_dnode_get_string(dnode, NULL);
		eif = eigrp_interface_lookup(eigrp, ifname);
		if (eif == NULL)
			return NB_ERR_INCONSISTENCY;

		eif->params.passive_interface = EIGRP_IF_PASSIVE;
		break;
	}

	return NB_OK;
}

static int
eigrpd_instance_passive_interface_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct eigrp_interface *eif;
	struct eigrp *eigrp;
	const char *ifname;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		ifname = yang_dnode_get_string(dnode, NULL);
		eif = eigrp_interface_lookup(eigrp, ifname);
		if (eif == NULL)
			break;

		eif->params.passive_interface = EIGRP_IF_ACTIVE;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/active-time
 */
static int eigrpd_instance_active_time_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
		/* TODO: Not implemented. */
		return NB_ERR_INCONSISTENCY;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/variance
 */
static int eigrpd_instance_variance_modify(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp->variance = yang_dnode_get_uint8(dnode, NULL);
		break;
	}

	return NB_OK;
}

static int eigrpd_instance_variance_destroy(enum nb_event event,
					    const struct lyd_node *dnode)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp->variance = EIGRP_VARIANCE_DEFAULT;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/maximum-paths
 */
static int eigrpd_instance_maximum_paths_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp->max_paths = yang_dnode_get_uint8(dnode, NULL);
		break;
	}

	return NB_OK;
}

static int eigrpd_instance_maximum_paths_destroy(enum nb_event event,
						 const struct lyd_node *dnode)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp->max_paths = EIGRP_MAX_PATHS_DEFAULT;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K1
 */
static int
eigrpd_instance_metric_weights_K1_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp->k_values[0] = yang_dnode_get_uint8(dnode, NULL);
		break;
	}

	return NB_OK;
}

static int
eigrpd_instance_metric_weights_K1_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp->k_values[0] = EIGRP_K1_DEFAULT;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K2
 */
static int
eigrpd_instance_metric_weights_K2_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp->k_values[1] = yang_dnode_get_uint8(dnode, NULL);
		break;
	}

	return NB_OK;
}

static int
eigrpd_instance_metric_weights_K2_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp->k_values[1] = EIGRP_K2_DEFAULT;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K3
 */
static int
eigrpd_instance_metric_weights_K3_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp->k_values[2] = yang_dnode_get_uint8(dnode, NULL);
		break;
	}

	return NB_OK;
}

static int
eigrpd_instance_metric_weights_K3_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp->k_values[2] = EIGRP_K3_DEFAULT;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K4
 */
static int
eigrpd_instance_metric_weights_K4_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp->k_values[3] = yang_dnode_get_uint8(dnode, NULL);
		break;
	}

	return NB_OK;
}

static int
eigrpd_instance_metric_weights_K4_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp->k_values[3] = EIGRP_K4_DEFAULT;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K5
 */
static int
eigrpd_instance_metric_weights_K5_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp->k_values[4] = yang_dnode_get_uint8(dnode, NULL);
		break;
	}

	return NB_OK;
}

static int
eigrpd_instance_metric_weights_K5_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp->k_values[4] = EIGRP_K5_DEFAULT;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K6
 */
static int
eigrpd_instance_metric_weights_K6_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp->k_values[5] = yang_dnode_get_uint8(dnode, NULL);
		break;
	}

	return NB_OK;
}

static int
eigrpd_instance_metric_weights_K6_destroy(enum nb_event event,
					  const struct lyd_node *dnode)
{
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp->k_values[5] = EIGRP_K6_DEFAULT;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/network
 */
static int eigrpd_instance_network_create(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource)
{
	struct route_node *rnode;
	struct prefix prefix;
	struct eigrp *eigrp;
	int exists;

	yang_dnode_get_ipv4p(&prefix, dnode, NULL);

	switch (event) {
	case NB_EV_VALIDATE:
		eigrp = nb_running_get_entry(dnode, NULL, false);
		/* If entry doesn't exist it means the list is empty. */
		if (eigrp == NULL)
			break;

		rnode = route_node_get(eigrp->networks, &prefix);
		exists = (rnode->info != NULL);
		route_unlock_node(rnode);
		if (exists)
			return NB_ERR_INCONSISTENCY;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		if (eigrp_network_set(eigrp, &prefix) == 0)
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}

static int eigrpd_instance_network_destroy(enum nb_event event,
					   const struct lyd_node *dnode)
{
	struct route_node *rnode;
	struct prefix prefix;
	struct eigrp *eigrp;
	int exists = 0;

	yang_dnode_get_ipv4p(&prefix, dnode, NULL);

	switch (event) {
	case NB_EV_VALIDATE:
		eigrp = nb_running_get_entry(dnode, NULL, false);
		/* If entry doesn't exist it means the list is empty. */
		if (eigrp == NULL)
			break;

		rnode = route_node_get(eigrp->networks, &prefix);
		exists = (rnode->info != NULL);
		route_unlock_node(rnode);
		if (exists == 0)
			return NB_ERR_INCONSISTENCY;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		eigrp_network_unset(eigrp, &prefix);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/neighbor
 */
static int eigrpd_instance_neighbor_create(enum nb_event event,
					   const struct lyd_node *dnode,
					   union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
		/* TODO: Not implemented. */
		return NB_ERR_INCONSISTENCY;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

static int eigrpd_instance_neighbor_destroy(enum nb_event event,
					    const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
		/* TODO: Not implemented. */
		return NB_ERR_INCONSISTENCY;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute
 */
static int eigrpd_instance_redistribute_create(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	struct eigrp_metrics metrics;
	const char *vrfname;
	struct eigrp *eigrp;
	uint32_t proto;
	vrf_id_t vrfid;

	switch (event) {
	case NB_EV_VALIDATE:
		proto = yang_dnode_get_enum(dnode, "./protocol");
		vrfname = yang_dnode_get_string(dnode, "../vrf");
		vrfid = vrf_name_to_id(vrfname);
		if (vrf_bitmap_check(zclient->redist[AFI_IP][proto], vrfid))
			return NB_ERR_INCONSISTENCY;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		proto = yang_dnode_get_enum(dnode, "./protocol");
		redistribute_get_metrics(dnode, &metrics);
		eigrp_redistribute_set(eigrp, proto, metrics);
		break;
	}

	return NB_OK;
}

static int eigrpd_instance_redistribute_destroy(enum nb_event event,
						const struct lyd_node *dnode)
{
	struct eigrp *eigrp;
	uint32_t proto;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		proto = yang_dnode_get_enum(dnode, "./protocol");
		eigrp_redistribute_unset(eigrp, proto);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/route-map
 */
static int
eigrpd_instance_redistribute_route_map_modify(enum nb_event event,
					      const struct lyd_node *dnode,
					      union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
		/* TODO: Not implemented. */
		return NB_ERR_INCONSISTENCY;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

static int
eigrpd_instance_redistribute_route_map_destroy(enum nb_event event,
					       const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
		/* TODO: Not implemented. */
		return NB_ERR_INCONSISTENCY;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/metrics/bandwidth
 */
static int eigrpd_instance_redistribute_metrics_bandwidth_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	struct eigrp_metrics metrics;
	struct eigrp *eigrp;
	uint32_t proto;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		proto = yang_dnode_get_enum(dnode, "../../protocol");
		redistribute_get_metrics(dnode, &metrics);
		eigrp_redistribute_set(eigrp, proto, metrics);
		break;
	}

	return NB_OK;
}

static int eigrpd_instance_redistribute_metrics_bandwidth_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	struct eigrp_metrics metrics;
	struct eigrp *eigrp;
	uint32_t proto;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(dnode, NULL, true);
		proto = yang_dnode_get_enum(dnode, "../../protocol");
		redistribute_get_metrics(dnode, &metrics);
		eigrp_redistribute_set(eigrp, proto, metrics);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/metrics/delay
 */
static int
eigrpd_instance_redistribute_metrics_delay_modify(enum nb_event event,
						  const struct lyd_node *dnode,
						  union nb_resource *resource)
{
	return eigrpd_instance_redistribute_metrics_bandwidth_modify(event,
								     dnode,
								     resource);
}

static int
eigrpd_instance_redistribute_metrics_delay_destroy(enum nb_event event,
						   const struct lyd_node *dnode)
{
	return eigrpd_instance_redistribute_metrics_bandwidth_destroy(event,
								      dnode);
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/metrics/reliability
 */
static int eigrpd_instance_redistribute_metrics_reliability_modify(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	return eigrpd_instance_redistribute_metrics_bandwidth_modify(event,
								     dnode,
								     resource);
}

static int eigrpd_instance_redistribute_metrics_reliability_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	return eigrpd_instance_redistribute_metrics_bandwidth_destroy(event,
								      dnode);
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/metrics/load
 */
static int
eigrpd_instance_redistribute_metrics_load_modify(enum nb_event event,
						 const struct lyd_node *dnode,
						 union nb_resource *resource)
{
	return eigrpd_instance_redistribute_metrics_bandwidth_modify(event,
								     dnode,
								     resource);
}

static int
eigrpd_instance_redistribute_metrics_load_destroy(enum nb_event event,
						  const struct lyd_node *dnode)
{
	return eigrpd_instance_redistribute_metrics_bandwidth_destroy(event,
								      dnode);
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/metrics/mtu
 */
static int
eigrpd_instance_redistribute_metrics_mtu_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	return eigrpd_instance_redistribute_metrics_bandwidth_modify(event,
								     dnode,
								     resource);
}

static int
eigrpd_instance_redistribute_metrics_mtu_destroy(enum nb_event event,
						 const struct lyd_node *dnode)
{
	return eigrpd_instance_redistribute_metrics_bandwidth_destroy(event,
								      dnode);
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/delay
 */
static int lib_interface_eigrp_delay_modify(enum nb_event event,
					    const struct lyd_node *dnode,
					    union nb_resource *resource)
{
	struct eigrp_interface *ei;
	struct interface *ifp;

	switch (event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(dnode, NULL, false);
		if (ifp == NULL) {
			/*
			 * XXX: we can't verify if the interface exists
			 * and is active until EIGRP is up.
			 */
			break;
		}

		ei = ifp->info;
		if (ei == NULL)
			return NB_ERR_INCONSISTENCY;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		ei = ifp->info;
		if (ei == NULL)
			return NB_ERR_INCONSISTENCY;

		ei->params.delay = yang_dnode_get_uint32(dnode, NULL);
		eigrp_if_reset(ifp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/bandwidth
 */
static int lib_interface_eigrp_bandwidth_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	struct interface *ifp;
	struct eigrp_interface *ei;

	switch (event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(dnode, NULL, false);
		if (ifp == NULL) {
			/*
			 * XXX: we can't verify if the interface exists
			 * and is active until EIGRP is up.
			 */
			break;
		}

		ei = ifp->info;
		if (ei == NULL)
			return NB_ERR_INCONSISTENCY;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		ei = ifp->info;
		if (ei == NULL)
			return NB_ERR_INCONSISTENCY;

		ei->params.bandwidth = yang_dnode_get_uint32(dnode, NULL);
		eigrp_if_reset(ifp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/hello-interval
 */
static int
lib_interface_eigrp_hello_interval_modify(enum nb_event event,
					  const struct lyd_node *dnode,
					  union nb_resource *resource)
{
	struct interface *ifp;
	struct eigrp_interface *ei;

	switch (event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(dnode, NULL, false);
		if (ifp == NULL) {
			/*
			 * XXX: we can't verify if the interface exists
			 * and is active until EIGRP is up.
			 */
			break;
		}

		ei = ifp->info;
		if (ei == NULL)
			return NB_ERR_INCONSISTENCY;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		ei = ifp->info;
		if (ei == NULL)
			return NB_ERR_INCONSISTENCY;

		ei->params.v_hello = yang_dnode_get_uint16(dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/hold-time
 */
static int lib_interface_eigrp_hold_time_modify(enum nb_event event,
						const struct lyd_node *dnode,
						union nb_resource *resource)
{
	struct interface *ifp;
	struct eigrp_interface *ei;

	switch (event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(dnode, NULL, false);
		if (ifp == NULL) {
			/*
			 * XXX: we can't verify if the interface exists
			 * and is active until EIGRP is up.
			 */
			break;
		}

		ei = ifp->info;
		if (ei == NULL)
			return NB_ERR_INCONSISTENCY;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		ei = ifp->info;
		if (ei == NULL)
			return NB_ERR_INCONSISTENCY;

		ei->params.v_wait = yang_dnode_get_uint16(dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/split-horizon
 */
static int
lib_interface_eigrp_split_horizon_modify(enum nb_event event,
					 const struct lyd_node *dnode,
					 union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
		/* TODO: Not implemented. */
		return NB_ERR_INCONSISTENCY;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/instance
 */
static int lib_interface_eigrp_instance_create(enum nb_event event,
					       const struct lyd_node *dnode,
					       union nb_resource *resource)
{
	struct eigrp_interface *eif;
	struct interface *ifp;
	struct eigrp *eigrp;

	switch (event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(dnode, NULL, false);
		if (ifp == NULL) {
			/*
			 * XXX: we can't verify if the interface exists
			 * and is active until EIGRP is up.
			 */
			break;
		}

		eigrp = eigrp_get(yang_dnode_get_uint16(dnode, "./asn"),
				  ifp->vrf_id);
		eif = eigrp_interface_lookup(eigrp, ifp->name);
		if (eif == NULL)
			return NB_ERR_INCONSISTENCY;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(dnode, NULL, true);
		eigrp = eigrp_get(yang_dnode_get_uint16(dnode, "./asn"),
				  ifp->vrf_id);
		eif = eigrp_interface_lookup(eigrp, ifp->name);
		if (eif == NULL)
			return NB_ERR_INCONSISTENCY;

		nb_running_set_entry(dnode, eif);
		break;
	}

	return NB_OK;
}

static int lib_interface_eigrp_instance_destroy(enum nb_event event,
						const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		nb_running_unset_entry(dnode);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-eigrpd:eigrp/instance/summarize-addresses
 */
static int lib_interface_eigrp_instance_summarize_addresses_create(
	enum nb_event event, const struct lyd_node *dnode,
	union nb_resource *resource)
{
	switch (event) {
	case NB_EV_VALIDATE:
		/* TODO: Not implemented. */
		return NB_ERR_INCONSISTENCY;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

static int lib_interface_eigrp_instance_summarize_addresses_destroy(
	enum nb_event event, const struct lyd_node *dnode)
{
	switch (event) {
	case NB_EV_VALIDATE:
		/* TODO: Not implemented. */
		return NB_ERR_INCONSISTENCY;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/instance/authentication
 */
static int
lib_interface_eigrp_instance_authentication_modify(enum nb_event event,
						   const struct lyd_node *dnode,
						   union nb_resource *resource)
{
	struct eigrp_interface *eif;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eif = nb_running_get_entry(dnode, NULL, true);
		eif->params.auth_type = yang_dnode_get_enum(dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/instance/keychain
 */
static int
lib_interface_eigrp_instance_keychain_modify(enum nb_event event,
					     const struct lyd_node *dnode,
					     union nb_resource *resource)
{
	struct eigrp_interface *eif;
	struct keychain *keychain;

	switch (event) {
	case NB_EV_VALIDATE:
		keychain = keychain_lookup(yang_dnode_get_string(dnode, NULL));
		if (keychain == NULL)
			return NB_ERR_INCONSISTENCY;
		break;
	case NB_EV_PREPARE:
		resource->ptr = strdup(yang_dnode_get_string(dnode, NULL));
		if (resource->ptr == NULL)
			return NB_ERR_RESOURCE;
		break;
	case NB_EV_ABORT:
		free(resource->ptr);
		resource->ptr = NULL;
		break;
	case NB_EV_APPLY:
		eif = nb_running_get_entry(dnode, NULL, true);
		if (eif->params.auth_keychain)
			free(eif->params.auth_keychain);

		eif->params.auth_keychain = resource->ptr;
		break;
	}

	return NB_OK;
}

static int
lib_interface_eigrp_instance_keychain_destroy(enum nb_event event,
					      const struct lyd_node *dnode)
{
	struct eigrp_interface *eif;

	switch (event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eif = nb_running_get_entry(dnode, NULL, true);
		if (eif->params.auth_keychain)
			free(eif->params.auth_keychain);

		eif->params.auth_keychain = NULL;
		break;
	}

	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_eigrpd_info = {
	.name = "frr-eigrpd",
	.nodes = {
		{
			.xpath = "/frr-eigrpd:eigrpd/instance",
			.cbs = {
				.create = eigrpd_instance_create,
				.destroy = eigrpd_instance_destroy,
				.cli_show = eigrp_cli_show_header,
				.cli_show_end = eigrp_cli_show_end_header,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/router-id",
			.cbs = {
				.modify = eigrpd_instance_router_id_modify,
				.destroy = eigrpd_instance_router_id_destroy,
				.cli_show = eigrp_cli_show_router_id,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/passive-interface",
			.cbs = {
				.create = eigrpd_instance_passive_interface_create,
				.destroy = eigrpd_instance_passive_interface_destroy,
				.cli_show = eigrp_cli_show_passive_interface,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/active-time",
			.cbs = {
				.modify = eigrpd_instance_active_time_modify,
				.cli_show = eigrp_cli_show_active_time,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/variance",
			.cbs = {
				.modify = eigrpd_instance_variance_modify,
				.destroy = eigrpd_instance_variance_destroy,
				.cli_show = eigrp_cli_show_variance,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/maximum-paths",
			.cbs = {
				.modify = eigrpd_instance_maximum_paths_modify,
				.destroy = eigrpd_instance_maximum_paths_destroy,
				.cli_show = eigrp_cli_show_maximum_paths,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/metric-weights",
			.cbs = {
				.cli_show = eigrp_cli_show_metrics,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/metric-weights/K1",
			.cbs = {
				.modify = eigrpd_instance_metric_weights_K1_modify,
				.destroy = eigrpd_instance_metric_weights_K1_destroy,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/metric-weights/K2",
			.cbs = {
				.modify = eigrpd_instance_metric_weights_K2_modify,
				.destroy = eigrpd_instance_metric_weights_K2_destroy,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/metric-weights/K3",
			.cbs = {
				.modify = eigrpd_instance_metric_weights_K3_modify,
				.destroy = eigrpd_instance_metric_weights_K3_destroy,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/metric-weights/K4",
			.cbs = {
				.modify = eigrpd_instance_metric_weights_K4_modify,
				.destroy = eigrpd_instance_metric_weights_K4_destroy,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/metric-weights/K5",
			.cbs = {
				.modify = eigrpd_instance_metric_weights_K5_modify,
				.destroy = eigrpd_instance_metric_weights_K5_destroy,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/metric-weights/K6",
			.cbs = {
				.modify = eigrpd_instance_metric_weights_K6_modify,
				.destroy = eigrpd_instance_metric_weights_K6_destroy,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/network",
			.cbs = {
				.create = eigrpd_instance_network_create,
				.destroy = eigrpd_instance_network_destroy,
				.cli_show = eigrp_cli_show_network,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/neighbor",
			.cbs = {
				.create = eigrpd_instance_neighbor_create,
				.destroy = eigrpd_instance_neighbor_destroy,
				.cli_show = eigrp_cli_show_neighbor,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/redistribute",
			.cbs = {
				.create = eigrpd_instance_redistribute_create,
				.destroy = eigrpd_instance_redistribute_destroy,
				.cli_show = eigrp_cli_show_redistribute,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/redistribute/route-map",
			.cbs = {
				.modify = eigrpd_instance_redistribute_route_map_modify,
				.destroy = eigrpd_instance_redistribute_route_map_destroy,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/redistribute/metrics/bandwidth",
			.cbs = {
				.modify = eigrpd_instance_redistribute_metrics_bandwidth_modify,
				.destroy = eigrpd_instance_redistribute_metrics_bandwidth_destroy,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/redistribute/metrics/delay",
			.cbs = {
				.modify = eigrpd_instance_redistribute_metrics_delay_modify,
				.destroy = eigrpd_instance_redistribute_metrics_delay_destroy,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/redistribute/metrics/reliability",
			.cbs = {
				.modify = eigrpd_instance_redistribute_metrics_reliability_modify,
				.destroy = eigrpd_instance_redistribute_metrics_reliability_destroy,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/redistribute/metrics/load",
			.cbs = {
				.modify = eigrpd_instance_redistribute_metrics_load_modify,
				.destroy = eigrpd_instance_redistribute_metrics_load_destroy,
			}
		},
		{
			.xpath = "/frr-eigrpd:eigrpd/instance/redistribute/metrics/mtu",
			.cbs = {
				.modify = eigrpd_instance_redistribute_metrics_mtu_modify,
				.destroy = eigrpd_instance_redistribute_metrics_mtu_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-eigrpd:eigrp/delay",
			.cbs = {
				.modify = lib_interface_eigrp_delay_modify,
				.cli_show = eigrp_cli_show_delay,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-eigrpd:eigrp/bandwidth",
			.cbs = {
				.modify = lib_interface_eigrp_bandwidth_modify,
				.cli_show = eigrp_cli_show_bandwidth,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-eigrpd:eigrp/hello-interval",
			.cbs = {
				.modify = lib_interface_eigrp_hello_interval_modify,
				.cli_show = eigrp_cli_show_hello_interval,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-eigrpd:eigrp/hold-time",
			.cbs = {
				.modify = lib_interface_eigrp_hold_time_modify,
				.cli_show = eigrp_cli_show_hold_time,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-eigrpd:eigrp/split-horizon",
			.cbs = {
				.modify = lib_interface_eigrp_split_horizon_modify,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-eigrpd:eigrp/instance",
			.cbs = {
				.create = lib_interface_eigrp_instance_create,
				.destroy = lib_interface_eigrp_instance_destroy,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-eigrpd:eigrp/instance/summarize-addresses",
			.cbs = {
				.create = lib_interface_eigrp_instance_summarize_addresses_create,
				.destroy = lib_interface_eigrp_instance_summarize_addresses_destroy,
				.cli_show = eigrp_cli_show_summarize_address,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-eigrpd:eigrp/instance/authentication",
			.cbs = {
				.modify = lib_interface_eigrp_instance_authentication_modify,
				.cli_show = eigrp_cli_show_authentication,
			}
		},
		{
			.xpath = "/frr-interface:lib/interface/frr-eigrpd:eigrp/instance/keychain",
			.cbs = {
				.modify = lib_interface_eigrp_instance_keychain_modify,
				.destroy = lib_interface_eigrp_instance_keychain_destroy,
				.cli_show = eigrp_cli_show_keychain,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
