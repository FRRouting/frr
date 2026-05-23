// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF northbound operational state.
 */

#include <zebra.h>

#include "debug.h"
#include "if.h"
#include "json.h"
#include "linklist.h"
#include "table.h"
#include "vrf.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_opaque.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospf_nb.h"
#include "ospf_vty.h"

static void ospfd_ietf_interface_key(const struct interface *ifp, char *key,
				     size_t key_len)
{
	if (vrf_is_backend_netns())
		snprintf(key, key_len, "%s:%s", ifp->vrf->name, ifp->name);
	else
		snprintf(key, key_len, "%s", ifp->name);
}

static bool ospfd_ietf_interface_key_match(const struct interface *ifp,
					   const char *key)
{
	char ifkey[XPATH_MAXLEN];

	ospfd_ietf_interface_key(ifp, ifkey, sizeof(ifkey));

	return !strcmp(ifkey, key);
}

static void *ospfd_ietf_list_next_data(struct list *list, const void *entry)
{
	struct listnode *node;
	void *data;

	if (!list)
		return NULL;

	if (!entry) {
		node = listhead(list);
		return node ? listgetdata(node) : NULL;
	}

	for (ALL_LIST_ELEMENTS_RO(list, node, data)) {
		if (data != entry)
			continue;

		node = listnextnode(node);
		return node ? listgetdata(node) : NULL;
	}

	return NULL;
}

static const char *ospfd_ietf_instance_name(const struct ospf *ospf)
{
	return ospf->name ? ospf->name : "default";
}

static uint8_t ospfd_ietf_neighbor_state(uint8_t state)
{
	switch (state) {
	case NSM_Deleted:
	case NSM_Down:
		return 1;
	case NSM_Attempt:
		return 2;
	case NSM_Init:
		return 3;
	case NSM_TwoWay:
		return 4;
	case NSM_ExStart:
		return 5;
	case NSM_Exchange:
		return 6;
	case NSM_Loading:
		return 7;
	case NSM_Full:
		return 8;
	default:
		return 1;
	}
}

static bool ospfd_ietf_interface_name_seen(const struct ospf_area *area,
					   const struct ospf_interface *end)
{
	const struct listnode *node;
	struct ospf_interface *oi;
	char endkey[XPATH_MAXLEN];

	ospfd_ietf_interface_key(end->ifp, endkey, sizeof(endkey));

	for (ALL_LIST_ELEMENTS_RO(area->oiflist, node, oi)) {
		if (oi == end)
			break;

		if (ospfd_ietf_interface_key_match(oi->ifp, endkey))
			return true;
	}

	return false;
}

static const struct ospf_interface *
ospfd_ietf_next_unique_interface(const struct ospf_area *area,
				 const struct ospf_interface *entry)
{
	const struct listnode *node;
	struct ospf_interface *oi;
	bool after_entry = entry == NULL;

	for (ALL_LIST_ELEMENTS_RO(area->oiflist, node, oi)) {
		if (!after_entry) {
			if (oi == entry)
				after_entry = true;
			continue;
		}

		if (!ospfd_ietf_interface_name_seen(area, oi))
			return oi;
	}

	return NULL;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol
 */
const void *ospfd_ietf_routing_control_plane_protocol_get_next(struct nb_cb_get_next_args *args)
{
	return ospfd_ietf_list_next_data(om->ospf, args->list_entry);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol
 */
int ospfd_ietf_routing_control_plane_protocol_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct ospf *ospf = args->list_entry;

	args->keys->num = 2;
	strlcpy(args->keys->key[0], "ietf-ospf:ospfv2", sizeof(args->keys->key[0]));
	strlcpy(args->keys->key[1], ospfd_ietf_instance_name(ospf), sizeof(args->keys->key[1]));

	return NB_OK;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol
 */
const void *
ospfd_ietf_routing_control_plane_protocol_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *type = args->keys->key[0];
	const char *name = args->keys->key[1];
	const struct listnode *node;
	struct ospf *ospf;

	if (strcmp(type, "ietf-ospf:ospfv2"))
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf))
		if (!strcmp(ospfd_ietf_instance_name(ospf), name))
			return ospf;

	return NULL;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/router-id
 */
struct yang_data *ospfd_ietf_ospf_router_id_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct ospf *ospf = args->list_entry;

	return yang_data_new_ipv4(args->xpath, &ospf->router_id);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/statistics/originate-new-lsa-count
 */
struct yang_data *
ospfd_ietf_ospf_statistics_originate_new_lsa_count_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct ospf *ospf = args->list_entry;

	return yang_data_new_uint32(args->xpath, ospf->lsa_originate_count);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/statistics/rx-new-lsas-count
 */
struct yang_data *
ospfd_ietf_ospf_statistics_rx_new_lsas_count_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct ospf *ospf = args->list_entry;

	return yang_data_new_uint32(args->xpath, ospf->rx_lsa_count);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area
 */
const void *ospfd_ietf_ospf_areas_area_get_next(struct nb_cb_get_next_args *args)
{
	const struct ospf *ospf = args->parent_list_entry;

	return ospfd_ietf_list_next_data(ospf->areas, args->list_entry);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area
 */
int ospfd_ietf_ospf_areas_area_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct ospf_area *area = args->list_entry;

	args->keys->num = 1;
	snprintfrr(args->keys->key[0], sizeof(args->keys->key[0]), "%pI4", &area->area_id);

	return NB_OK;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area
 */
const void *ospfd_ietf_ospf_areas_area_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const struct ospf *ospf = args->parent_list_entry;
	const char *key = args->keys->key[0];
	struct ospf_area *area;
	struct listnode *node;
	struct in_addr area_id;

	if (str2area_id(key, &area_id, &(int){ 0 })) {
		DEBUGD(&nb_dbg_cbs_state, "invalid OSPF area-id key: %s", key);
		return NULL;
	}

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
		if (area->area_id.s_addr == area_id.s_addr)
			return area;

	return NULL;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/statistics/spf-runs-count
 */
struct yang_data *
ospfd_ietf_ospf_areas_area_statistics_spf_runs_count_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct ospf_area *area = args->list_entry;

	return yang_data_new_uint32(args->xpath, area->spf_calculation);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/statistics/abr-count
 */
struct yang_data *
ospfd_ietf_ospf_areas_area_statistics_abr_count_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct ospf_area *area = args->list_entry;

	return yang_data_new_uint32(args->xpath, area->abr_count);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/statistics/asbr-count
 */
struct yang_data *
ospfd_ietf_ospf_areas_area_statistics_asbr_count_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct ospf_area *area = args->list_entry;

	return yang_data_new_uint32(args->xpath, area->asbr_count);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/statistics/area-scope-lsa-count
 */
struct yang_data *ospfd_ietf_ospf_areas_area_statistics_area_scope_lsa_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct ospf_area *area = args->list_entry;

	return yang_data_new_uint32(args->xpath, area->lsdb->total);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface
 */
const void *
ospfd_ietf_ospf_areas_area_interfaces_interface_get_next(struct nb_cb_get_next_args *args)
{
	const struct ospf_area *area = args->parent_list_entry;

	return ospfd_ietf_next_unique_interface(area, args->list_entry);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface
 */
int ospfd_ietf_ospf_areas_area_interfaces_interface_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct ospf_interface *oi = args->list_entry;

	args->keys->num = 1;
	ospfd_ietf_interface_key(oi->ifp, args->keys->key[0],
				 sizeof(args->keys->key[0]));

	return NB_OK;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface
 */
const void *
ospfd_ietf_ospf_areas_area_interfaces_interface_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const struct ospf_area *area = args->parent_list_entry;
	const char *name = args->keys->key[0];
	const struct listnode *node;
	struct ospf_interface *oi;

	for (ALL_LIST_ELEMENTS_RO(area->oiflist, node, oi))
		if (ospfd_ietf_interface_key_match(oi->ifp, name))
			return oi;

	return NULL;
}

static const void *ospfd_ietf_neighbor_next(struct route_table *nbrs,
					    const struct ospf_neighbor *entry)
{
	struct ospf_neighbor *nbr;
	struct route_node *rn;
	bool after_entry = entry == NULL;

	for (rn = route_top(nbrs); rn; rn = route_next(rn)) {
		nbr = rn->info;

		if (!nbr || nbr == nbr->oi->nbr_self || nbr->state == NSM_Down)
			continue;

		if (!after_entry) {
			if (nbr == entry)
				after_entry = true;
			continue;
		}

		route_unlock_node(rn);
		return nbr;
	}

	return NULL;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface/neighbors/neighbor
 */
const void *ospfd_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_get_next(
	struct nb_cb_get_next_args *args)
{
	const struct ospf_interface *oi = args->parent_list_entry;

	return ospfd_ietf_neighbor_next(oi->nbrs, args->list_entry);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface/neighbors/neighbor
 */
int ospfd_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_get_keys(
	struct nb_cb_get_keys_args *args)
{
	const struct ospf_neighbor *nbr = args->list_entry;

	args->keys->num = 1;
	snprintfrr(args->keys->key[0], sizeof(args->keys->key[0]), "%pI4", &nbr->router_id);

	return NB_OK;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface/neighbors/neighbor
 */
const void *ospfd_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	const struct ospf_interface *oi = args->parent_list_entry;
	struct in_addr router_id;
	struct ospf_neighbor *nbr;
	struct route_node *rn;

	if (inet_pton(AF_INET, args->keys->key[0], &router_id) != 1) {
		DEBUGD(&nb_dbg_cbs_state, "invalid OSPF neighbor router-id key: %s",
		       args->keys->key[0]);
		return NULL;
	}

	for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
		nbr = rn->info;

		if (!nbr || nbr == oi->nbr_self || nbr->state == NSM_Down)
			continue;

		if (nbr->router_id.s_addr == router_id.s_addr) {
			route_unlock_node(rn);
			return nbr;
		}
	}

	return NULL;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface/neighbors/neighbor/address
 */
struct yang_data *
ospfd_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_address_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct ospf_neighbor *nbr = args->list_entry;

	return yang_data_new_ipv4(args->xpath, &nbr->address.u.prefix4);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface/neighbors/neighbor/state
 */
struct yang_data *ospfd_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_state_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct ospf_neighbor *nbr = args->list_entry;

	return yang_data_new_enum(args->xpath, ospfd_ietf_neighbor_state(nbr->state));
}
