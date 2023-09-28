// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * EIGRP daemon northbound implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
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
#include "eigrp_cli.h"

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
static int eigrpd_instance_create(struct nb_cb_create_args *args)
{
	struct eigrp *eigrp;
	const char *vrf;
	struct vrf *pVrf;
	vrf_id_t vrfid;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/* NOTHING */
		break;
	case NB_EV_PREPARE:
		vrf = yang_dnode_get_string(args->dnode, "./vrf");

		pVrf = vrf_lookup_by_name(vrf);
		if (pVrf)
			vrfid = pVrf->vrf_id;
		else
			vrfid = VRF_DEFAULT;

		eigrp = eigrp_get(yang_dnode_get_uint16(args->dnode, "./asn"),
				  vrfid);
		args->resource->ptr = eigrp;
		break;
	case NB_EV_ABORT:
		eigrp_finish_final(args->resource->ptr);
		break;
	case NB_EV_APPLY:
		nb_running_set_entry(args->dnode, args->resource->ptr);
		break;
	}

	return NB_OK;
}

static int eigrpd_instance_destroy(struct nb_cb_destroy_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_unset_entry(args->dnode);
		eigrp_finish_final(eigrp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/router-id
 */
static int eigrpd_instance_router_id_modify(struct nb_cb_modify_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		yang_dnode_get_ipv4(&eigrp->router_id_static, args->dnode,
				    NULL);
		break;
	}

	return NB_OK;
}

static int eigrpd_instance_router_id_destroy(struct nb_cb_destroy_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp->router_id_static.s_addr = INADDR_ANY;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/passive-interface
 */
static int
eigrpd_instance_passive_interface_create(struct nb_cb_create_args *args)
{
	struct eigrp_interface *eif;
	struct eigrp *eigrp;
	const char *ifname;

	switch (args->event) {
	case NB_EV_VALIDATE:
		eigrp = nb_running_get_entry(args->dnode, NULL, false);
		if (eigrp == NULL) {
			/*
			 * XXX: we can't verify if the interface exists
			 * and is active until EIGRP is up.
			 */
			break;
		}

		ifname = yang_dnode_get_string(args->dnode, NULL);
		eif = eigrp_interface_lookup(eigrp, ifname);
		if (eif == NULL)
			return NB_ERR_INCONSISTENCY;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		ifname = yang_dnode_get_string(args->dnode, NULL);
		eif = eigrp_interface_lookup(eigrp, ifname);
		if (eif == NULL)
			return NB_ERR_INCONSISTENCY;

		eif->params.passive_interface = EIGRP_IF_PASSIVE;
		break;
	}

	return NB_OK;
}

static int
eigrpd_instance_passive_interface_destroy(struct nb_cb_destroy_args *args)
{
	struct eigrp_interface *eif;
	struct eigrp *eigrp;
	const char *ifname;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		ifname = yang_dnode_get_string(args->dnode, NULL);
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
static int eigrpd_instance_active_time_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		/* TODO: Not implemented. */
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		snprintf(args->errmsg, args->errmsg_len,
			 "active time not implemented yet");
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/variance
 */
static int eigrpd_instance_variance_modify(struct nb_cb_modify_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp->variance = yang_dnode_get_uint8(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

static int eigrpd_instance_variance_destroy(struct nb_cb_destroy_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp->variance = EIGRP_VARIANCE_DEFAULT;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/maximum-paths
 */
static int eigrpd_instance_maximum_paths_modify(struct nb_cb_modify_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp->max_paths = yang_dnode_get_uint8(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

static int
eigrpd_instance_maximum_paths_destroy(struct nb_cb_destroy_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp->max_paths = EIGRP_MAX_PATHS_DEFAULT;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K1
 */
static int
eigrpd_instance_metric_weights_K1_modify(struct nb_cb_modify_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp->k_values[0] = yang_dnode_get_uint8(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

static int
eigrpd_instance_metric_weights_K1_destroy(struct nb_cb_destroy_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp->k_values[0] = EIGRP_K1_DEFAULT;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K2
 */
static int
eigrpd_instance_metric_weights_K2_modify(struct nb_cb_modify_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp->k_values[1] = yang_dnode_get_uint8(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

static int
eigrpd_instance_metric_weights_K2_destroy(struct nb_cb_destroy_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp->k_values[1] = EIGRP_K2_DEFAULT;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K3
 */
static int
eigrpd_instance_metric_weights_K3_modify(struct nb_cb_modify_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp->k_values[2] = yang_dnode_get_uint8(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

static int
eigrpd_instance_metric_weights_K3_destroy(struct nb_cb_destroy_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp->k_values[2] = EIGRP_K3_DEFAULT;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K4
 */
static int
eigrpd_instance_metric_weights_K4_modify(struct nb_cb_modify_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp->k_values[3] = yang_dnode_get_uint8(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

static int
eigrpd_instance_metric_weights_K4_destroy(struct nb_cb_destroy_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp->k_values[3] = EIGRP_K4_DEFAULT;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K5
 */
static int
eigrpd_instance_metric_weights_K5_modify(struct nb_cb_modify_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp->k_values[4] = yang_dnode_get_uint8(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

static int
eigrpd_instance_metric_weights_K5_destroy(struct nb_cb_destroy_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp->k_values[4] = EIGRP_K5_DEFAULT;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/metric-weights/K6
 */
static int
eigrpd_instance_metric_weights_K6_modify(struct nb_cb_modify_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp->k_values[5] = yang_dnode_get_uint8(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

static int
eigrpd_instance_metric_weights_K6_destroy(struct nb_cb_destroy_args *args)
{
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp->k_values[5] = EIGRP_K6_DEFAULT;
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/network
 */
static int eigrpd_instance_network_create(struct nb_cb_create_args *args)
{
	struct route_node *rnode;
	struct prefix prefix;
	struct eigrp *eigrp;
	int exists;

	yang_dnode_get_ipv4p(&prefix, args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		eigrp = nb_running_get_entry(args->dnode, NULL, false);
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
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		if (eigrp_network_set(eigrp, &prefix) == 0)
			return NB_ERR_INCONSISTENCY;
		break;
	}

	return NB_OK;
}

static int eigrpd_instance_network_destroy(struct nb_cb_destroy_args *args)
{
	struct route_node *rnode;
	struct prefix prefix;
	struct eigrp *eigrp;
	int exists = 0;

	yang_dnode_get_ipv4p(&prefix, args->dnode, NULL);

	switch (args->event) {
	case NB_EV_VALIDATE:
		eigrp = nb_running_get_entry(args->dnode, NULL, false);
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
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp_network_unset(eigrp, &prefix);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/neighbor
 */
static int eigrpd_instance_neighbor_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		/* TODO: Not implemented. */
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		snprintf(args->errmsg, args->errmsg_len,
			 "neighbor Command is not implemented yet");
		break;
	}

	return NB_OK;
}

static int eigrpd_instance_neighbor_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		/* TODO: Not implemented. */
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		snprintf(args->errmsg, args->errmsg_len,
			 "no neighbor Command is not implemented yet");
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute
 */
static int eigrpd_instance_redistribute_create(struct nb_cb_create_args *args)
{
	struct eigrp_metrics metrics;
	const char *vrfname;
	struct eigrp *eigrp;
	uint32_t proto;
	vrf_id_t vrfid;
	struct vrf *pVrf;

	switch (args->event) {
	case NB_EV_VALIDATE:
		proto = yang_dnode_get_enum(args->dnode, "./protocol");
		vrfname = yang_dnode_get_string(args->dnode, "../vrf");

		pVrf = vrf_lookup_by_name(vrfname);
		if (pVrf)
			vrfid = pVrf->vrf_id;
		else
			vrfid = VRF_DEFAULT;

		if (vrf_bitmap_check(&zclient->redist[AFI_IP][proto], vrfid))
			return NB_ERR_INCONSISTENCY;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		proto = yang_dnode_get_enum(args->dnode, "./protocol");
		redistribute_get_metrics(args->dnode, &metrics);
		eigrp_redistribute_set(eigrp, proto, metrics);
		break;
	}

	return NB_OK;
}

static int eigrpd_instance_redistribute_destroy(struct nb_cb_destroy_args *args)
{
	struct eigrp *eigrp;
	uint32_t proto;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		proto = yang_dnode_get_enum(args->dnode, "./protocol");
		eigrp_redistribute_unset(eigrp, proto);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/route-map
 */
static int
eigrpd_instance_redistribute_route_map_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		/* TODO: Not implemented. */
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		snprintf(
			args->errmsg, args->errmsg_len,
			"'redistribute X route-map FOO' command not implemented yet");
		break;
	}

	return NB_OK;
}

static int
eigrpd_instance_redistribute_route_map_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		/* TODO: Not implemented. */
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		snprintf(
			args->errmsg, args->errmsg_len,
			"'no redistribute X route-map FOO' command not implemented yet");
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/metrics/bandwidth
 */
static int eigrpd_instance_redistribute_metrics_bandwidth_modify(
	struct nb_cb_modify_args *args)
{
	struct eigrp_metrics metrics;
	struct eigrp *eigrp;
	uint32_t proto;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		proto = yang_dnode_get_enum(args->dnode, "../../protocol");
		redistribute_get_metrics(args->dnode, &metrics);
		eigrp_redistribute_set(eigrp, proto, metrics);
		break;
	}

	return NB_OK;
}

static int eigrpd_instance_redistribute_metrics_bandwidth_destroy(
	struct nb_cb_destroy_args *args)
{
	struct eigrp_metrics metrics;
	struct eigrp *eigrp;
	uint32_t proto;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eigrp = nb_running_get_entry(args->dnode, NULL, true);
		proto = yang_dnode_get_enum(args->dnode, "../../protocol");
		redistribute_get_metrics(args->dnode, &metrics);
		eigrp_redistribute_set(eigrp, proto, metrics);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/metrics/delay
 */
static int eigrpd_instance_redistribute_metrics_delay_modify(
	struct nb_cb_modify_args *args)
{
	return eigrpd_instance_redistribute_metrics_bandwidth_modify(args);
}

static int eigrpd_instance_redistribute_metrics_delay_destroy(
	struct nb_cb_destroy_args *args)
{
	return eigrpd_instance_redistribute_metrics_bandwidth_destroy(args);
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/metrics/reliability
 */
static int eigrpd_instance_redistribute_metrics_reliability_modify(
	struct nb_cb_modify_args *args)
{
	return eigrpd_instance_redistribute_metrics_bandwidth_modify(args);
}

static int eigrpd_instance_redistribute_metrics_reliability_destroy(
	struct nb_cb_destroy_args *args)
{
	return eigrpd_instance_redistribute_metrics_bandwidth_destroy(args);
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/metrics/load
 */
static int
eigrpd_instance_redistribute_metrics_load_modify(struct nb_cb_modify_args *args)
{
	return eigrpd_instance_redistribute_metrics_bandwidth_modify(args);
}

static int eigrpd_instance_redistribute_metrics_load_destroy(
	struct nb_cb_destroy_args *args)
{
	return eigrpd_instance_redistribute_metrics_bandwidth_destroy(args);
}

/*
 * XPath: /frr-eigrpd:eigrpd/instance/redistribute/metrics/mtu
 */
static int
eigrpd_instance_redistribute_metrics_mtu_modify(struct nb_cb_modify_args *args)
{
	return eigrpd_instance_redistribute_metrics_bandwidth_modify(args);
}

static int eigrpd_instance_redistribute_metrics_mtu_destroy(
	struct nb_cb_destroy_args *args)
{
	return eigrpd_instance_redistribute_metrics_bandwidth_destroy(args);
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/delay
 */
static int lib_interface_eigrp_delay_modify(struct nb_cb_modify_args *args)
{
	struct eigrp_interface *ei;
	struct interface *ifp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(args->dnode, NULL, false);
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
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		ei = ifp->info;
		if (ei == NULL)
			return NB_ERR_INCONSISTENCY;

		ei->params.delay = yang_dnode_get_uint32(args->dnode, NULL);
		eigrp_if_reset(ifp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/bandwidth
 */
static int lib_interface_eigrp_bandwidth_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct eigrp_interface *ei;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(args->dnode, NULL, false);
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
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		ei = ifp->info;
		if (ei == NULL)
			return NB_ERR_INCONSISTENCY;

		ei->params.bandwidth = yang_dnode_get_uint32(args->dnode, NULL);
		eigrp_if_reset(ifp);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/hello-interval
 */
static int
lib_interface_eigrp_hello_interval_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct eigrp_interface *ei;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(args->dnode, NULL, false);
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
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		ei = ifp->info;
		if (ei == NULL)
			return NB_ERR_INCONSISTENCY;

		ei->params.v_hello = yang_dnode_get_uint16(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/hold-time
 */
static int lib_interface_eigrp_hold_time_modify(struct nb_cb_modify_args *args)
{
	struct interface *ifp;
	struct eigrp_interface *ei;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(args->dnode, NULL, false);
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
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		ei = ifp->info;
		if (ei == NULL)
			return NB_ERR_INCONSISTENCY;

		ei->params.v_wait = yang_dnode_get_uint16(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/split-horizon
 */
static int
lib_interface_eigrp_split_horizon_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		/* TODO: Not implemented. */
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		snprintf(args->errmsg, args->errmsg_len,
			 "split-horizon command not implemented yet");
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/instance
 */
static int lib_interface_eigrp_instance_create(struct nb_cb_create_args *args)
{
	struct eigrp_interface *eif;
	struct interface *ifp;
	struct eigrp *eigrp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		ifp = nb_running_get_entry(args->dnode, NULL, false);
		if (ifp == NULL) {
			/*
			 * XXX: we can't verify if the interface exists
			 * and is active until EIGRP is up.
			 */
			break;
		}

		eigrp = eigrp_get(yang_dnode_get_uint16(args->dnode, "./asn"),
				  ifp->vrf->vrf_id);
		eif = eigrp_interface_lookup(eigrp, ifp->name);
		if (eif == NULL)
			return NB_ERR_INCONSISTENCY;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		ifp = nb_running_get_entry(args->dnode, NULL, true);
		eigrp = eigrp_get(yang_dnode_get_uint16(args->dnode, "./asn"),
				  ifp->vrf->vrf_id);
		eif = eigrp_interface_lookup(eigrp, ifp->name);
		if (eif == NULL)
			return NB_ERR_INCONSISTENCY;

		nb_running_set_entry(args->dnode, eif);
		break;
	}

	return NB_OK;
}

static int lib_interface_eigrp_instance_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		nb_running_unset_entry(args->dnode);
		break;
	}

	return NB_OK;
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-eigrpd:eigrp/instance/summarize-addresses
 */
static int lib_interface_eigrp_instance_summarize_addresses_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		/* TODO: Not implemented. */
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		snprintf(args->errmsg, args->errmsg_len,
			 "summary command not implemented yet");
		break;
	}

	return NB_OK;
}

static int lib_interface_eigrp_instance_summarize_addresses_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		/* TODO: Not implemented. */
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		snprintf(args->errmsg, args->errmsg_len,
			 "no summary command not implemented yet");
		/* NOTHING */
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/instance/authentication
 */
static int lib_interface_eigrp_instance_authentication_modify(
	struct nb_cb_modify_args *args)
{
	struct eigrp_interface *eif;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eif = nb_running_get_entry(args->dnode, NULL, true);
		eif->params.auth_type = yang_dnode_get_enum(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

/*
 * XPath: /frr-interface:lib/interface/frr-eigrpd:eigrp/instance/keychain
 */
static int
lib_interface_eigrp_instance_keychain_modify(struct nb_cb_modify_args *args)
{
	struct eigrp_interface *eif;
	struct keychain *keychain;

	switch (args->event) {
	case NB_EV_VALIDATE:
		keychain = keychain_lookup(
			yang_dnode_get_string(args->dnode, NULL));
		if (keychain == NULL)
			return NB_ERR_INCONSISTENCY;
		break;
	case NB_EV_PREPARE:
		args->resource->ptr =
			strdup(yang_dnode_get_string(args->dnode, NULL));
		if (args->resource->ptr == NULL)
			return NB_ERR_RESOURCE;
		break;
	case NB_EV_ABORT:
		free(args->resource->ptr);
		args->resource->ptr = NULL;
		break;
	case NB_EV_APPLY:
		eif = nb_running_get_entry(args->dnode, NULL, true);
		if (eif->params.auth_keychain)
			free(eif->params.auth_keychain);

		eif->params.auth_keychain = args->resource->ptr;
		break;
	}

	return NB_OK;
}

static int
lib_interface_eigrp_instance_keychain_destroy(struct nb_cb_destroy_args *args)
{
	struct eigrp_interface *eif;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		/* NOTHING */
		break;
	case NB_EV_APPLY:
		eif = nb_running_get_entry(args->dnode, NULL, true);
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
