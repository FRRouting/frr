// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPFv3 northbound operational state.
 */

#include <zebra.h>

#include "debug.h"
#include "if.h"
#include "linklist.h"
#include "vrf.h"

#include "ospf6_area.h"
#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_nb.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_route.h"
#include "ospf6_top.h"

static void ospf6d_ietf_interface_key(const struct interface *ifp, char *key,
				      size_t key_len)
{
	if (vrf_is_backend_netns())
		snprintf(key, key_len, "%s:%s", ifp->vrf->name, ifp->name);
	else
		snprintf(key, key_len, "%s", ifp->name);
}

static bool ospf6d_ietf_interface_key_match(const struct interface *ifp,
					    const char *key)
{
	char ifkey[XPATH_MAXLEN];

	ospf6d_ietf_interface_key(ifp, ifkey, sizeof(ifkey));

	return !strcmp(ifkey, key);
}

static void *ospf6d_ietf_list_next_data(struct list *list, const void *entry)
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

static const char *ospf6d_ietf_instance_name(const struct ospf6 *ospf6)
{
	return ospf6->name ? ospf6->name : "default";
}

struct ospf6 *ospf6d_ietf_ospf_lookup_instance(const char *name)
{
	const struct listnode *node;
	struct ospf6 *ospf6;

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, node, ospf6))
		if (!strcmp(ospf6d_ietf_instance_name(ospf6), name))
			return ospf6;

	return NULL;
}

static uint32_t ospf6d_ietf_ospf_area_router_count(const struct ospf6_area *area,
						   uint8_t router_bit)
{
	struct ospf6_route *route;
	uint32_t count = 0;

	if (!area->ospf6->brouter_table)
		return 0;

	for (route = ospf6_route_head(area->ospf6->brouter_table); route;
	     route = ospf6_route_next(route)) {
		if (route->path.area_id != area->area_id)
			continue;

		if (CHECK_FLAG(route->path.router_bits, router_bit))
			count++;
	}

	return count;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol
 */
const void *ospf6d_ietf_routing_control_plane_protocol_get_next(struct nb_cb_get_next_args *args)
{
	return ospf6d_ietf_list_next_data(om6->ospf6, args->list_entry);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol
 */
int ospf6d_ietf_routing_control_plane_protocol_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct ospf6 *ospf6 = args->list_entry;

	args->keys->num = 2;
	strlcpy(args->keys->key[0], "ietf-ospf:ospfv3", sizeof(args->keys->key[0]));
	strlcpy(args->keys->key[1], ospf6d_ietf_instance_name(ospf6), sizeof(args->keys->key[1]));

	return NB_OK;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol
 */
const void *
ospf6d_ietf_routing_control_plane_protocol_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const char *type = args->keys->key[0];

	if (strcmp(type, "ietf-ospf:ospfv3"))
		return NULL;

	return ospf6d_ietf_ospf_lookup_instance(args->keys->key[1]);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/router-id
 */
struct yang_data *ospf6d_ietf_ospf_router_id_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct ospf6 *ospf6 = args->list_entry;
	/* ospf6d stores router IDs as network-byte-order uint32_t values. */
	struct in_addr router_id = { .s_addr = ospf6->router_id };

	return yang_data_new_ipv4(args->xpath, &router_id);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/statistics/originate-new-lsa-count
 */
struct yang_data *
ospf6d_ietf_ospf_statistics_originate_new_lsa_count_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct ospf6 *ospf6 = args->list_entry;

	return yang_data_new_uint32(args->xpath, ospf6->lsa_originate_count);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/statistics/rx-new-lsas-count
 */
struct yang_data *
ospf6d_ietf_ospf_statistics_rx_new_lsas_count_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct ospf6 *ospf6 = args->list_entry;

	return yang_data_new_uint32(args->xpath, ospf6->rx_lsa_count);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area
 */
const void *ospf6d_ietf_ospf_areas_area_get_next(struct nb_cb_get_next_args *args)
{
	const struct ospf6 *ospf6 = args->parent_list_entry;

	return ospf6d_ietf_list_next_data(ospf6->area_list, args->list_entry);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area
 */
int ospf6d_ietf_ospf_areas_area_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct ospf6_area *area = args->list_entry;

	args->keys->num = 1;
	snprintfrr(args->keys->key[0], sizeof(args->keys->key[0]), "%pI4", &area->area_id);

	return NB_OK;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area
 */
const void *ospf6d_ietf_ospf_areas_area_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const struct ospf6 *ospf6 = args->parent_list_entry;
	const char *key = args->keys->key[0];
	struct ospf6_area *area;
	struct listnode *node;
	uint32_t area_id;

	if (str2area_id(key, &area_id, &(int){ 0 })) {
		DEBUGD(&nb_dbg_cbs_state, "invalid OSPFv3 area-id key: %s", key);
		return NULL;
	}

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, area))
		if (area->area_id == area_id)
			return area;

	return NULL;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/statistics/spf-runs-count
 */
struct yang_data *
ospf6d_ietf_ospf_areas_area_statistics_spf_runs_count_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct ospf6_area *area = args->list_entry;

	return yang_data_new_uint32(args->xpath, area->spf_calculation);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/statistics/abr-count
 */
struct yang_data *
ospf6d_ietf_ospf_areas_area_statistics_abr_count_get_elem(struct nb_cb_get_elem_args *args)
{
	return yang_data_new_uint32(args->xpath,
				    ospf6d_ietf_ospf_area_router_count(args->list_entry,
								       OSPF6_ROUTER_BIT_B));
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/statistics/asbr-count
 */
struct yang_data *
ospf6d_ietf_ospf_areas_area_statistics_asbr_count_get_elem(struct nb_cb_get_elem_args *args)
{
	return yang_data_new_uint32(args->xpath,
				    ospf6d_ietf_ospf_area_router_count(args->list_entry,
								       OSPF6_ROUTER_BIT_E));
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/statistics/area-scope-lsa-count
 */
struct yang_data *ospf6d_ietf_ospf_areas_area_statistics_area_scope_lsa_count_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct ospf6_area *area = args->list_entry;

	return yang_data_new_uint32(args->xpath, area->lsdb->count);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface
 */
const void *
ospf6d_ietf_ospf_areas_area_interfaces_interface_get_next(struct nb_cb_get_next_args *args)
{
	const struct ospf6_area *area = args->parent_list_entry;

	return ospf6d_ietf_list_next_data(area->if_list, args->list_entry);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface
 */
int ospf6d_ietf_ospf_areas_area_interfaces_interface_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct ospf6_interface *oi = args->list_entry;

	args->keys->num = 1;
	ospf6d_ietf_interface_key(oi->interface, args->keys->key[0],
				  sizeof(args->keys->key[0]));

	return NB_OK;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface
 */
const void *
ospf6d_ietf_ospf_areas_area_interfaces_interface_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	const struct ospf6_area *area = args->parent_list_entry;
	const char *name = args->keys->key[0];
	const struct listnode *node;
	struct ospf6_interface *oi;

	for (ALL_LIST_ELEMENTS_RO(area->if_list, node, oi))
		if (ospf6d_ietf_interface_key_match(oi->interface, name))
			return oi;

	return NULL;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface/neighbors/neighbor
 */
const void *ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_get_next(
	struct nb_cb_get_next_args *args)
{
	const struct ospf6_interface *oi = args->parent_list_entry;

	return ospf6d_ietf_list_next_data(oi->neighbor_list, args->list_entry);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface/neighbors/neighbor
 */
int ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_get_keys(
	struct nb_cb_get_keys_args *args)
{
	const struct ospf6_neighbor *on = args->list_entry;
	/* ospf6d stores neighbor router IDs in network byte order too. */
	struct in_addr router_id = { .s_addr = on->router_id };

	args->keys->num = 1;
	snprintfrr(args->keys->key[0], sizeof(args->keys->key[0]), "%pI4", &router_id);

	return NB_OK;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface/neighbors/neighbor
 */
const void *ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_lookup_entry(
	struct nb_cb_lookup_entry_args *args)
{
	const struct ospf6_interface *oi = args->parent_list_entry;
	const char *key = args->keys->key[0];
	const struct listnode *node;
	struct ospf6_neighbor *on;
	struct in_addr router_id;

	if (inet_pton(AF_INET, key, &router_id) != 1) {
		DEBUGD(&nb_dbg_cbs_state, "invalid OSPFv3 neighbor router-id key: %s", key);
		return NULL;
	}

	for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, node, on))
		if (on->router_id == router_id.s_addr)
			return on;

	return NULL;
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface/neighbors/neighbor/address
 */
struct yang_data *
ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_address_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct ospf6_neighbor *on = args->list_entry;

	return yang_data_new_ipv6(args->xpath, &on->linklocal_addr);
}

/*
 * XPath: /ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/areas/area/interfaces/interface/neighbors/neighbor/state
 */
struct yang_data *
ospf6d_ietf_ospf_areas_area_interfaces_interface_neighbors_neighbor_state_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct ospf6_neighbor *on = args->list_entry;

	/* OSPF6_NEIGHBOR_* values 1..8 match RFC 9129's enum encoding. */
	return yang_data_new_enum(args->xpath, on->state);
}
