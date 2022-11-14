/*
 * OSPF BGP-IGP IGP metric update handling routines
 * Copyright (C) 2021 Samsung R&D Institute India - Bangalore.
 *			Madhurilatha Kuruganti
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
#include <string.h>

#include "monotime.h"
#include "memory.h"
#include "thread.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "command.h"
#include "plist.h"
#include "log.h"
#include "zclient.h"
#include <lib/json.h>
#include "defaults.h"
#include "orr_msg.h"

#include "ospfd.h"
#include "ospf_asbr.h"
#include "ospf_dump.h"
#include "ospf_lsa.h"
#include "ospf_orr.h"
#include "ospf_route.h"
#include "ospf_spf.h"
#include "ospf_te.h"

static void ospf_show_orr_root(struct orr_root *root);
static void ospf_show_orr(struct ospf *ospf, afi_t afi, safi_t safi);
static struct orr_root *ospf_orr_root_new(struct ospf *ospf, afi_t afi,
					  safi_t safi, struct prefix *p,
					  char *group_name)
{
	struct list *orr_root_list = NULL;
	struct orr_root *root = NULL;

	if (!ospf->orr_root[afi][safi])
		ospf->orr_root[afi][safi] = list_new();

	orr_root_list = ospf->orr_root[afi][safi];
	root = XCALLOC(MTYPE_OSPF_ORR_ROOT, sizeof(struct orr_root));

	listnode_add(orr_root_list, root);

	root->afi = afi;
	root->safi = safi;
	prefix_copy(&root->prefix, p);
	IPV4_ADDR_COPY(&root->router_id, &p->u.prefix4);
	strlcpy(root->group_name, group_name, sizeof(root->group_name));
	root->new_rtrs = NULL;
	root->new_table = NULL;

	ospf_orr_debug("For %s %s, ORR Group %s, created ORR Root entry %pFX.",
		       afi2str(afi), safi2str(safi), root->group_name, p);

	return root;
}

static struct orr_root *ospf_orr_root_lookup(struct ospf *ospf, afi_t afi,
					     safi_t safi, struct in_addr *rid)
{
	struct list *orr_root_list = NULL;
	struct orr_root *root = NULL;
	struct listnode *node;

	orr_root_list = ospf->orr_root[afi][safi];
	if (!orr_root_list)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(orr_root_list, node, root))
		if (IPV4_ADDR_SAME(&root->router_id, rid))
			return root;

	ospf_orr_debug("For %s %s, ORR Root '%pI4' not found.", afi2str(afi),
		       safi2str(safi), rid);

	return NULL;
}

static struct orr_root *ospf_orr_root_lookup_by_adv_rid(struct ospf *ospf,
							afi_t afi, safi_t safi,
							struct in_addr *rid)
{
	struct list *orr_root_list = NULL;
	struct orr_root *root = NULL;
	struct listnode *node;

	orr_root_list = ospf->orr_root[afi][safi];
	if (!orr_root_list)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(orr_root_list, node, root))
		if (IPV4_ADDR_SAME(&root->adv_router, rid))
			return root;

	return NULL;
}

/*
 * Lookup each area's LSDB if is there is any opaque area LSA received and
 * update the root database with the advertising router.
 */
static struct ospf_lsa *
ospf_orr_lookup_opaque_area_lsa_by_id(struct in_addr rid)
{
	struct ospf_lsa *lsa = NULL;
	struct ospf_area *area = NULL;
	struct ospf *ospf = NULL;
	struct listnode *node = NULL, *nnode = NULL;

	/* if ospf is not enabled ignore */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (!ospf)
		return NULL;

	/* Lookup for Opaque area LSA in each area. */
	for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area)) {
		lsa = ospf_lsa_lookup_by_mpls_te_rid(area, OSPF_OPAQUE_AREA_LSA,
						     rid);
		if (!lsa)
			continue;
		ospf_orr_debug("Opaque Area LSA found in area %pI4 for %pI4",
			       &area->area_id, &rid);
		return lsa;
	}
	return NULL;
}

/*
 * Lookup each area's LSDB if is there is any opaque area LSA received and
 * update the root database with the advertising router.
 */
static struct ospf_lsa *ospf_orr_lookup_router_lsa_by_id(struct in_addr rid)
{
	struct ospf_lsa *lsa = NULL;
	struct ospf_area *area = NULL;
	struct ospf *ospf = NULL;
	struct listnode *node = NULL, *nnode = NULL;

	/* if ospf is not enabled ignore */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (!ospf)
		return NULL;

	/* Lookup for Router LSA in each area. */
	for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area)) {
		lsa = ospf_lsa_lookup_by_adv_rid(area, OSPF_ROUTER_LSA, rid);
		if (!lsa)
			continue;
		ospf_orr_debug("Router LSA found in area %pI4 for %pI4",
			       &area->area_id, &rid);
		return lsa;
	}
	return NULL;
}

/*
 * BGP-IGP IGP metric msg between BGP and IGP
 */
int ospf_orr_igp_metric_register(struct orr_igp_metric_reg msg)
{
	afi_t afi;
	safi_t safi;
	struct ospf *ospf = NULL;
	struct ospf_lsa *lsa = NULL;
	struct orr_root *root = NULL;

	/* if ospf is not enabled ignore */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (!ospf)
		return -1;

	if (msg.proto != ZEBRA_ROUTE_BGP)
		return -1;

	afi = family2afi(msg.prefix.family);
	safi = msg.safi;

	ospf_orr_debug(
		"Received IGP metric %s message from BGP for ORR Group %s from location %pFX",
		msg.reg ? "Register" : "Unregister", msg.group_name,
		&msg.prefix);

	/* Get ORR Root entry for the given address-family */
	root = ospf_orr_root_lookup(ospf, afi, safi, &msg.prefix.u.prefix4);

	/* Should not hit this condition */
	if ((root && msg.reg) || (!root && !msg.reg))
		return -1;

	/* Create ORR Root entry and calculate SPF from root */
	if (!root) {
		root = ospf_orr_root_new(ospf, afi, safi, &msg.prefix,
					 msg.group_name);
		if (!root) {
			ospf_orr_debug(
				"For %s %s, Failed to create ORR Root entry %pFX.",
				afi2str(afi), safi2str(safi), &msg.prefix);
			return -1;
		}
		ospf->orr_spf_request++;

		lsa = ospf_orr_lookup_opaque_area_lsa_by_id(root->router_id);
		if (!lsa || !lsa->data)
			return -1;

		IPV4_ADDR_COPY(&root->adv_router, &lsa->data->adv_router);

		/* Lookup LSDB for Router LSA */
		if (!root->router_lsa_rcvd) {
			lsa = ospf_orr_lookup_router_lsa_by_id(
				root->adv_router);
			if (!lsa || !lsa->data)
				return -1;
			root->router_lsa_rcvd = lsa;
		}

		/* Compute SPF for all root nodes */
		ospf_orr_spf_calculate_schedule(ospf);
	}
	/* Delete ORR Root entry. SPF calculation not required. */
	else {
		listnode_delete(ospf->orr_root[afi][safi], root);
		XFREE(MTYPE_OSPF_ORR_ROOT, root);

		/* If last node is deleted in the list */
		if (!ospf->orr_root[afi][safi]->count)
			list_delete(&ospf->orr_root[afi][safi]);

		ospf->orr_spf_request--;
	}

	if (IS_DEBUG_OSPF_ORR)
		ospf_show_orr(ospf, afi, safi);

	return 0;
}

void ospf_orr_igp_metric_send_update_add(struct orr_root *root,
					 unsigned short instance)
{
	int ret;
	uint8_t count = 0;
	struct route_node *rn;
	struct ospf_route *or;
	struct orr_igp_metric_info msg;

	memset(&msg, 0, sizeof(msg));
	msg.proto = ZEBRA_ROUTE_OSPF;
	msg.safi = root->safi;
	msg.instId = instance;
	msg.add = true;
	prefix_copy(&msg.root, &root->prefix);

	/* Update prefix table from ORR Route table */
	for (rn = route_top(root->new_table); rn; rn = route_next(rn)) {
		or = rn->info;
		if (!or)
			continue;

		if (or->type != OSPF_DESTINATION_NETWORK &&
		    or->type != OSPF_DESTINATION_DISCARD)
			continue;

		if (ospf_route_match_same(root->old_table,
					  (struct prefix_ipv4 *)&rn->p, or))
			continue;

		if (count < ORR_MAX_PREFIX) {
			prefix_copy(&msg.nexthop[count].prefix,
				    (struct prefix_ipv4 *)&rn->p);
			msg.nexthop[count].metric = or->cost;
			count++;
		} else {
			msg.num_entries = count;
			ret = zclient_send_opaque(zclient,
						  ORR_IGP_METRIC_UPDATE,
						  (uint8_t *)&msg, sizeof(msg));
			if (ret != ZCLIENT_SEND_SUCCESS)
				ospf_orr_debug(
					"Failed to send message to BGP.");
			count = 0;
			prefix_copy(&msg.nexthop[count].prefix,
				    (struct prefix_ipv4 *)&rn->p);
			msg.nexthop[count].metric = or->cost;
			count++;
		}
	}
	if (count > 0 && count <= ORR_MAX_PREFIX) {
		msg.num_entries = count;
		ret = zclient_send_opaque(zclient, ORR_IGP_METRIC_UPDATE,
					  (uint8_t *)&msg, sizeof(msg));
		if (ret != ZCLIENT_SEND_SUCCESS)
			ospf_orr_debug("Failed to send message to BGP.");
	}
}

void ospf_orr_igp_metric_send_update_delete(struct orr_root *root,
					    unsigned short instance)
{
	int ret;
	uint8_t count = 0;
	struct route_node *rn;
	struct ospf_route *or;
	struct orr_igp_metric_info msg;

	if (!root->old_table)
		return;

	memset(&msg, 0, sizeof(msg));
	msg.proto = ZEBRA_ROUTE_OSPF;
	msg.instId = instance;
	msg.safi = root->safi;
	msg.add = false;
	prefix_copy(&msg.root, &root->prefix);

	/* Update prefix table from ORR Route table */
	for (rn = route_top(root->old_table); rn; rn = route_next(rn)) {
		or = rn->info;
		if (!or)
			continue;

		if (or->path_type != OSPF_PATH_INTRA_AREA &&
		    or->path_type != OSPF_PATH_INTER_AREA)
			continue;

		if (or->type != OSPF_DESTINATION_NETWORK &&
		    or->type != OSPF_DESTINATION_DISCARD)
			continue;

		if (ospf_route_exist_new_table(root->new_table,
					       (struct prefix_ipv4 *)&rn->p))
			continue;

		if (count < ORR_MAX_PREFIX) {
			prefix_copy(&msg.nexthop[count].prefix,
				    (struct prefix_ipv4 *)&rn->p);
			msg.nexthop[count].metric = or->cost;
			count++;
		} else {
			msg.num_entries = count;
			ret = zclient_send_opaque(zclient,
						  ORR_IGP_METRIC_UPDATE,
						  (uint8_t *)&msg, sizeof(msg));
			if (ret != ZCLIENT_SEND_SUCCESS)
				ospf_orr_debug(
					"Failed to send message to BGP.");
			count = 0;
			prefix_copy(&msg.nexthop[count].prefix,
				    (struct prefix_ipv4 *)&rn->p);
			msg.nexthop[count].metric = or->cost;
			count++;
		}
	}
	if (count > 0 && count <= ORR_MAX_PREFIX) {
		msg.num_entries = count;
		ret = zclient_send_opaque(zclient, ORR_IGP_METRIC_UPDATE,
					  (uint8_t *)&msg, sizeof(msg));
		if (ret != ZCLIENT_SEND_SUCCESS)
			ospf_orr_debug("Failed to send message to BGP.");
	}
}

static void ospf_show_orr_root(struct orr_root *root)
{
	if (!root)
		return;

	ospf_orr_debug("Address Family: %s %s", afi2str(root->afi),
		       safi2str(root->safi));
	ospf_orr_debug("ORR Group: %s", root->group_name);
	ospf_orr_debug("Router-Address: %pI4:", &root->router_id);
	ospf_orr_debug("Advertising Router: %pI4:", &root->adv_router);
}

static void ospf_show_orr(struct ospf *ospf, afi_t afi, safi_t safi)
{
	struct listnode *node = NULL;
	struct orr_root *orr_root = NULL;
	struct list *orr_root_list = NULL;

	FOREACH_AFI_SAFI (afi, safi) {
		orr_root_list = ospf->orr_root[afi][safi];
		if (!orr_root_list)
			return;

		for (ALL_LIST_ELEMENTS_RO(orr_root_list, node, orr_root))
			ospf_show_orr_root(orr_root);
	}
}

void ospf_orr_root_table_update(struct ospf_lsa *lsa, bool add)
{
	afi_t afi;
	safi_t safi;
	struct lsa_header *lsah = lsa->data;
	uint32_t lsid = ntohl(lsah->id.s_addr);
	uint8_t opaque_type = GET_OPAQUE_TYPE(lsid);
	uint32_t opaque_id = GET_OPAQUE_ID(lsid);
	struct tlv_header *tlvh = TLV_HDR_TOP(lsah);
	struct te_tlv_router_addr *router_addr = NULL;
	struct orr_root *root = NULL;
	struct ospf *ospf = NULL;

	/* if ospf is not enabled ignore */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (!ospf)
		return;

	if (opaque_type != OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA)
		return;

	if (!tlvh || (ntohs(tlvh->type) != TE_TLV_ROUTER_ADDR) ||
	    (ntohs(tlvh->length) != TE_LINK_SUBTLV_DEF_SIZE))
		return;

	router_addr = (struct te_tlv_router_addr *)tlvh;
	if (IS_DEBUG_OSPF_ORR) {
		zlog_debug("[OSPF-ORR]: Opaque-area LSA %s LSDB",
			   add ? "added to" : "deleted from");
		zlog_debug("[OSPF-ORR]: Opaque-Type %u (%s)", opaque_type,
			   "Traffic Engineering LSA");
		zlog_debug("[OSPF-ORR]: Opaque-ID   0x%x", opaque_id);
		zlog_debug("[OSPF-ORR]: Opaque-Info: %u octets of data%s",
			   ntohs(lsah->length) - OSPF_LSA_HEADER_SIZE,
			   VALID_OPAQUE_INFO_LEN(lsah) ? ""
						       : "(Invalid length?)");
		zlog_debug("[OSPF-ORR]: Router-Address: %pI4",
			   &router_addr->value);
		zlog_debug("[OSPF-ORR]: Advertising Router: %pI4",
			   &lsa->data->adv_router);
	}
	/*
	 * When Opaque LSA is added or removed from LSDB check if there is any
	 * change in MPLS-TE Router address and Advertising router address and
	 * update the table accordingly if there is no change in the mapping
	 * ignore update
	 *
	 * Get ORR Root entry for the given address-family
	 */
	FOREACH_AFI_SAFI (afi, safi) {
		root = ospf_orr_root_lookup(ospf, afi, safi,
					    &router_addr->value);
		if (root) {
			IPV4_ADDR_COPY(&root->adv_router,
				       &lsa->data->adv_router);
			if (IS_DEBUG_OSPF_ORR)
				ospf_show_orr(ospf, afi, safi);
			break;
		}
	}
}

void ospf_orr_root_update_rcvd_lsa(struct ospf_lsa *lsa)
{
	afi_t afi;
	safi_t safi;
	struct orr_root *root = NULL;

	if (!lsa || !lsa->area || !lsa->area->ospf)
		return;

	FOREACH_AFI_SAFI (afi, safi) {
		root = ospf_orr_root_lookup_by_adv_rid(
			lsa->area->ospf, afi, safi, &lsa->data->adv_router);
		if (root) {
			SET_FLAG(lsa->flags, OSPF_LSA_ORR);
			ospf_refresher_register_lsa(lsa->area->ospf, lsa);
			root->router_lsa_rcvd = lsa;
		}

		ospf_orr_debug("Received LSA[Type%d:%pI4]", lsa->data->type,
			       &lsa->data->adv_router);

		/* Compute SPF for all root nodes */
		ospf_orr_spf_calculate_schedule(lsa->area->ospf);
		return;
	}
}

/* Do not Install routes to root table. Just update table ponters */
void ospf_orr_route_install(struct orr_root *root, struct route_table *rt,
			    unsigned short instance)
{
	/*
	 * rt contains new routing table, new_table contains an old one.
	 * updating pointers
	 */
	if (root->old_table)
		ospf_route_table_free(root->old_table);

	root->old_table = root->new_table;
	root->new_table = rt;

	/* Send update to BGP to delete old routes. */
	ospf_orr_igp_metric_send_update_delete(root, instance);

	/* REVISIT: Skipping external route table for now */

	/* Send update to BGP to add new routes. */
	ospf_orr_igp_metric_send_update_add(root, instance);
}

void ospf_orr_spf_calculate_schedule(struct ospf *ospf)
{
	/* OSPF instance does not exist. */
	if (ospf == NULL)
		return;

	/* No roots nodes rgistered for rSPF */
	if (!ospf->orr_spf_request)
		return;

	/* ORR SPF calculation timer is already scheduled. */
	if (ospf->t_orr_calc) {
		ospf_orr_debug(
			"SPF: calculation timer is already scheduled: %p",
			(void *)ospf->t_orr_calc);
		return;
	}

	ospf->t_orr_calc = NULL;

	ospf_orr_debug("SPF: calculation timer scheduled");

	thread_add_timer(master, ospf_orr_spf_calculate_schedule_worker, ospf,
			 OSPF_ORR_CALC_INTERVAL, &ospf->t_orr_calc);
}

void ospf_orr_spf_calculate_area(struct ospf *ospf, struct ospf_area *area,
				 struct route_table *new_table,
				 struct route_table *all_rtrs,
				 struct route_table *new_rtrs,
				 struct ospf_lsa *lsa_rcvd)
{
	ospf_spf_calculate(area, lsa_rcvd, new_table, all_rtrs, new_rtrs, false,
			   true);
}

void ospf_orr_spf_calculate_areas(struct ospf *ospf,
				  struct route_table *new_table,
				  struct route_table *all_rtrs,
				  struct route_table *new_rtrs,
				  struct ospf_lsa *lsa_rcvd)
{
	struct ospf_area *area;
	struct listnode *node, *nnode;

	/* Calculate SPF for each area. */
	for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area)) {
		/*
		 * Do backbone last, so as to first discover intra-area paths
		 * for any back-bone virtual-links
		 */
		if (ospf->backbone && ospf->backbone == area)
			continue;

		ospf_orr_spf_calculate_area(ospf, area, new_table, all_rtrs,
					    new_rtrs, lsa_rcvd);
	}

	/* SPF for backbone, if required */
	if (ospf->backbone)
		ospf_orr_spf_calculate_area(ospf, ospf->backbone, new_table,
					    all_rtrs, new_rtrs, lsa_rcvd);
}
