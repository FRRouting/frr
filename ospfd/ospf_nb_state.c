// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 21 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (C) 2023 LabN Consulting, L.L.C.
 */

#include <zebra.h>
#include "debug.h"
#include "northbound.h"
#include "table.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_opaque.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nb.h"
#include "ospfd/ospf_vty.h"


#define RNPARENT(args) ((struct route_node *)((args)->parent_list_entry))
#define RNENTRY(args) ((struct route_node *)((args)->list_entry))
#define OIPARENT(args) ((struct ospf_interface *)RNPARENT(args)->info)
#define OIENTRY(args) ((struct ospf_interface *)RNENTRY(args)->info)
#define NBRENTRY(args) ((struct ospf_neighbor *)RNENTRY(args)->info)


/*
 * XPath: /frr-interface:lib/interface/state/frr-ospfd-lite:ospf/state
 */
const void *
lib_interface_ospf_interface_get_next(struct nb_cb_get_next_args *args)
{
	struct interface *ifp = (struct interface *)args->parent_list_entry;
	struct route_node *rn = (struct route_node *)args->list_entry;

	assert(ifp);
	if (!rn)
		rn = route_top(IF_OIFS(ifp));
	else
		rn = route_next(rn);
	for (; rn && !rn->info; rn = route_next(rn))
		;
	return rn;
}

int lib_interface_ospf_interface_get_keys(struct nb_cb_get_keys_args *args)
{
	struct ospf_interface *oi = OIENTRY(args);

	args->keys->num = 1;
	if (CHECK_FLAG(oi->connected->flags, ZEBRA_IFA_UNNUMBERED))
		args->keys->key[0][0] = 0;
	else
		snprintfrr(args->keys->key[0], sizeof(args->keys->key[0]),
			   "%pI4", &oi->address->u.prefix4);
	return NB_OK;
}

const void *
lib_interface_ospf_interface_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	struct interface *ifp = (struct interface *)args->parent_list_entry;
	const char *key = args->keys->key[0];
	struct ospf_interface *oi;
	struct route_node *rn;
	struct prefix_ipv4 p;

	assert(ifp);

	/* handle unnumbered case */
	if (!key[0]) {
		for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
			oi = rn->info;
			if (oi && CHECK_FLAG(oi->connected->flags,
					     ZEBRA_IFA_UNNUMBERED))
				return rn;
		}
		return NULL;
	}

	if (!str2prefix_ipv4(key, &p)) {
		DEBUGD(&nb_dbg_cbs_state, "invalid interface address key: %s",
		       key);
		return NULL;
	}

	rn = route_node_match(IF_OIFS(ifp), &p);
	if (!rn || !rn->info)
		return NULL;
	return rn;
}

/*
 * XPath: /frr-interface:lib/interface/frr-ospfd-lite:ospf-interface/state/state
 */
struct yang_data *lib_interface_ospf_interface_state_state_get_elem(
	struct nb_cb_get_elem_args *args)
{
	return yang_data_new_enum(args->xpath, OIENTRY(args)->state);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-ospfd-lite:ospf-interface/state/hello-timer
 */
struct yang_data *lib_interface_ospf_interface_state_hello_timer_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct ospf_interface *oi = OIENTRY(args);
	uint16_t secs;

	/* TODO: update the model to support fast-hello */
	secs = OSPF_IF_PARAM(oi, fast_hello) ? 1 : OSPF_IF_PARAM(oi, v_hello);

	return yang_data_new_uint16(args->xpath, secs);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-ospfd-lite:ospf-interface/state/neighbors/neighbor
 */
const void *lib_interface_ospf_interface_state_neighbors_neighbor_get_next(
	struct nb_cb_get_next_args *args)
{
	struct route_node *rn = RNENTRY(args);

	if (rn)
		rn = route_next(rn);
	else {
		struct ospf_interface *oi = OIPARENT(args);

		assert(oi);
		rn = route_top(oi->nbrs);
	}
	for (; rn && !rn->info; rn = route_next(rn))
		;
	return rn;
}

int lib_interface_ospf_interface_state_neighbors_neighbor_get_keys(
	struct nb_cb_get_keys_args *args)
{
	struct ospf_neighbor *nbr = NBRENTRY(args);

	args->keys->num = 1;
	snprintfrr(args->keys->key[0], sizeof(args->keys->key[0]), "%pI4",
		   &nbr->router_id);
	return NB_OK;
}

const void *lib_interface_ospf_interface_state_neighbors_neighbor_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	struct ospf_interface *oi = OIPARENT(args);
	const char *key = args->keys->key[0];
	struct route_node *rn;
	struct prefix_ipv4 p;

	if (!str2prefix_ipv4(key, &p) || p.prefixlen != IPV4_MAX_BITLEN) {
		DEBUGD(&nb_dbg_cbs_state, "invalid neighbor router id key : %s",
		       key);
		return NULL;
	}

	rn = route_node_match(oi->nbrs, &p);
	if (!rn || !rn->info)
		return NULL;
	return rn;
}

struct yang_data *
lib_interface_ospf_interface_state_neighbors_neighbor_get_elem(
	struct nb_cb_get_elem_args *args)
{
	return yang_data_new_ipv4(args->xpath, &NBRENTRY(args)->router_id);
}


/*
 * XPath:
 * /frr-interface:lib/interface/frr-ospfd-lite:ospf-interface/state/neighbors/neighbor/neighbor-router-id
 */
struct yang_data *
lib_interface_ospf_interface_state_neighbors_neighbor_neighbor_router_id_get_elem(
	struct nb_cb_get_elem_args *args)
{
	return yang_data_new_ipv4(args->xpath, &NBRENTRY(args)->router_id);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-ospfd-lite:ospf-interface/state/neighbors/neighbor/address
 */
struct yang_data *
lib_interface_ospf_interface_state_neighbors_neighbor_address_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct ospf_neighbor *nbr = NBRENTRY(args);

	if (CHECK_FLAG(nbr->oi->connected->flags, ZEBRA_IFA_UNNUMBERED))
		return NULL;
	return yang_data_new_ipv4(args->xpath, &nbr->address.u.prefix4);
}

/*
 * XPath:
 * /frr-interface:lib/interface/frr-ospfd-lite:ospf-interface/state/neighbors/neighbor/state
 */
struct yang_data *
lib_interface_ospf_interface_state_neighbors_neighbor_state_get_elem(
	struct nb_cb_get_elem_args *args)
{
	return yang_data_new_enum(args->xpath, NBRENTRY(args)->state);
}

#define LNPARENT(args) ((const struct listnode *)((args)->parent_list_entry))
#define LNENTRY(args)  ((const struct listnode *)((args)->list_entry))
#define OPARENT(args)  ((struct ospf *)listgetdata(LNPARENT(args)))
#define OENTRY(args)   ((struct ospf *)listgetdata(LNENTRY(args)))

const void *ospf_instance_get_next(struct nb_cb_get_next_args *args)
{
	const struct listnode *node = LNENTRY(args);

	if (node == NULL)
		return listhead(om->ospf);
	else
		return listnextnode(node);
}

int ospf_instance_get_keys(struct nb_cb_get_keys_args *args)
{
	struct ospf *ospf = OENTRY(args);

	args->keys->num = 1;
	if (!ospf->name)
		args->keys->key[0][0] = 0;
	else
		strlcpy(args->keys->key[0], ospf->name, sizeof(args->keys->key[0]));

	return NB_OK;
}

const void *ospf_instance_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *vrf_name = args->keys->key[0];
	const struct listnode *node;
	struct ospf *ospf;

	for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf))
		if ((ospf->name == NULL && vrf_name[0]) ||
		    (ospf->name && vrf_name[0] && !strcmp(ospf->name, vrf_name)))
			return node;
	return NULL;
}

/*
 * XPath: /frr-ospfd-lite:ospf/instance/state/router-flags/router-flag
 */
struct yang_data *ospf_instance_state_router_flags_router_flag_get_elem(
	struct nb_cb_get_elem_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

const void *ospf_instance_state_router_flags_router_flag_get_next(
	struct nb_cb_get_next_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ospfd-lite:ospf/instance/state/statistics/originate-new-lsa-count
 */
struct yang_data *
ospf_instance_state_statistics_originate_new_lsa_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct ospf *ospf = OENTRY(args);

	return yang_data_new_uint32(args->xpath, ospf->lsa_originate_count);
}

/*
 * XPath: /frr-ospfd-lite:ospf/instance/state/statistics/rx-new-lsas-count
 */
struct yang_data *ospf_instance_state_statistics_rx_new_lsas_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct ospf *ospf = OENTRY(args);

	return yang_data_new_uint32(args->xpath, ospf->rx_lsa_count);
}

/*
 * XPath: /frr-ospfd-lite:ospf/instance/state/statistics/spf/timestamp
 */
struct yang_data *ospf_instance_state_statistics_spf_timestamp_get_elem(
	struct nb_cb_get_elem_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath: /frr-ospfd-lite:ospf/instance/state/statistics/spf/duration
 */
struct yang_data *ospf_instance_state_statistics_spf_duration_get_elem(
	struct nb_cb_get_elem_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

#define APARENT(args) ((struct ospf_area *)listgetdata(LNPARENT(args)))
#define AENTRY(args)  ((struct ospf_area *)listgetdata(LNENTRY(args)))

const void *ospf_instance_areas_area_get_next(struct nb_cb_get_next_args *args)
{
	struct ospf *ospf = OPARENT(args);
	const struct listnode *node = LNENTRY(args);

	if (node == NULL)
		return listhead(ospf->areas);
	else
		return listnextnode(node);
}

int ospf_instance_areas_area_get_keys(struct nb_cb_get_keys_args *args)
{
	struct ospf_area *area = AENTRY(args);

	args->keys->num = 1;
	snprintfrr(args->keys->key[0], sizeof(args->keys->key[0]), "%pI4",
		   &area->area_id);

	return NB_OK;
}

const void *
ospf_instance_areas_area_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	struct ospf *ospf = OPARENT(args);
	const char *key = args->keys->key[0];
	struct ospf_area *area;
	struct listnode *node;
	struct in_addr area_id;
	int aid_fmt;

	if (str2area_id(key, &area_id, &aid_fmt))
		/* TODO: dbg log ? */
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
		if (area->area_id.s_addr == area_id.s_addr)
			return node;
	return NULL;
}

/*
 * XPath: /frr-ospfd-lite:ospf/instance/areas/area/state/statistics/spf-runs-count
 */
struct yang_data *ospf_instance_areas_area_state_statistics_spf_runs_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct ospf_area *area = AENTRY(args);

	return yang_data_new_uint32(args->xpath, area->spf_calculation);
}

/*
 * XPath: /frr-ospfd-lite:ospf/instance/areas/area/state/statistics/abr-count
 */
struct yang_data *ospf_instance_areas_area_state_statistics_abr_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct ospf_area *area = AENTRY(args);

	return yang_data_new_uint32(args->xpath, area->abr_count);
}

/*
 * XPath: /frr-ospfd-lite:ospf/instance/areas/area/state/statistics/asbr-count
 */
struct yang_data *ospf_instance_areas_area_state_statistics_asbr_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct ospf_area *area = AENTRY(args);

	return yang_data_new_uint32(args->xpath, area->asbr_count);
}

/*
 * XPath: /frr-ospfd-lite:ospf/instance/areas/area/state/statistics/area-scope-lsa-count
 */
struct yang_data *ospf_instance_areas_area_state_statistics_area_scope_lsa_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct ospf_area *area = AENTRY(args);

	return yang_data_new_uint32(args->xpath, area->lsdb->total);
}

/*
 * XPath:
 * /frr-ospfd-lite:ospf/instance/areas/area/state/statistics/spf-timestamp
 */
struct yang_data *
ospf_instance_areas_area_state_statistics_spf_timestamp_get_elem(
	struct nb_cb_get_elem_args *args)
{
	/* TODO: implement me. */
	return NULL;
}

/*
 * XPath:
 * /frr-ospfd-lite:ospf/instance/areas/area/state/statistics/active-interfaces
 */
struct yang_data *ospf_instance_areas_area_state_statistics_active_interfaces_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct ospf_area *area = AENTRY(args);

	return yang_data_new_uint32(args->xpath, area->act_ints);
}


/*
 * XPath: /frr-ospfd-lite:ospf/instance/areas/area/state/statistics/full-nbrs
 */
struct yang_data *ospf_instance_areas_area_state_statistics_full_nbrs_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct ospf_area *area = AENTRY(args);

	return yang_data_new_uint32(args->xpath, area->full_nbrs);
}

/*
 * XPath: /frr-ospfd-lite:ospf/instance/areas/area/state/statistics/full-virtual
 */
struct yang_data *ospf_instance_areas_area_state_statistics_full_virtual_get_elem(
	struct nb_cb_get_elem_args *args)
{
	struct ospf_area *area = AENTRY(args);

	return yang_data_new_uint32(args->xpath, area->full_vls);
}
