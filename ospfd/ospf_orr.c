/*
 * OSPF BGP-IGP IGP metric update handling routines
 * Copyright (C) 2021 Samsung R&D Institute India - Bangalore.
 * 			Madhurilatha Kuruganti
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
#include "ospf_orr.h"
#include "ospf_dump.h"
#include "ospf_lsa.h"
#include "ospf_spf.h"
#include "ospf_te.h"
#include "ospf_route.h"

extern struct zclient *zclient;

static void ospf_show_orr_root(struct orr_root *root);
void ospf_show_orr(struct ospf *ospf, afi_t afi, safi_t safi);
static struct orr_root *ospf_orr_root_new(struct ospf *ospf, afi_t afi,
					  safi_t safi, struct prefix *p)
{
	struct list *orr_root_list = NULL;
	struct orr_root *root = NULL;
	char buf[PREFIX2STR_BUFFER];

	prefix2str(p, buf, sizeof(buf));

	if (!ospf->orr_root[afi][safi])
		ospf->orr_root[afi][safi] = list_new();

	orr_root_list = ospf->orr_root[afi][safi];
	root = XCALLOC(MTYPE_OSPF_ORR_ROOT, sizeof(struct orr_root));
	if (!root)
		return NULL;

	listnode_add(orr_root_list, root);

	root->afi = afi;
	root->safi = safi;
	prefix_copy(&root->prefix, p);
	IPV4_ADDR_COPY(&root->router_id, &p->u.prefix4);
	root->new_rtrs = NULL;
	root->new_table = NULL;

	ospf_orr_debug("%s: For %s %s, created ORR Root entry %s.", __func__,
		       afi2str(afi), safi2str(safi), buf);

	return root;
}

static struct orr_root *ospf_orr_root_lookup(struct ospf *ospf, afi_t afi,
					     safi_t safi, struct in_addr *rid)
{
	struct list *orr_root_list = NULL;
	struct orr_root *root = NULL;
	struct listnode *node;

	assert(ospf);

	orr_root_list = ospf->orr_root[afi][safi];
	if (!orr_root_list)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(orr_root_list, node, root))
		if (IPV4_ADDR_SAME(&root->router_id, rid))
			return root;

	ospf_orr_debug("%s: For %s %s, ORR Root '%pI4' Not Found.", __func__,
		       afi2str(afi), safi2str(safi), rid);

	return NULL;
}

static struct orr_root *ospf_orr_root_lookup_by_adv_rid(struct ospf *ospf,
							afi_t afi, safi_t safi,
							struct in_addr *rid)
{
	struct list *orr_root_list = NULL;
	struct orr_root *root = NULL;
	struct listnode *node;

	assert(ospf);

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
	if (!(ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT)))
		return NULL;

	/* Lookup for Opaque area LSA in each area. */
	for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area)) {
		lsa = ospf_lsa_lookup_by_mpls_te_rid(area, OSPF_OPAQUE_AREA_LSA,
						     rid);
		if (!lsa)
			continue;
		zlog_debug("%s: Opaque Area LSA found in area %pI4 for %pI4",
			   __func__, &area->area_id, &rid);
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
	if (!(ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT)))
		return NULL;

	/* Lookup for Router LSA in each area. */
	for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area)) {
		lsa = ospf_lsa_lookup_by_adv_rid(area, OSPF_ROUTER_LSA, rid);
		if (!lsa)
			continue;
		zlog_debug("%s: Router LSA found in area %pI4 for %pI4",
			   __func__, &area->area_id, &rid);
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
	char buf[PREFIX2STR_BUFFER];
	struct orr_root *root = NULL;

	/* if ospf is not enabled ignore */
	if (!(ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT)))
		return -1;

	if (msg.proto != ZEBRA_ROUTE_BGP)
		return -1;

	afi = family2afi(msg.prefix.family);
	safi = msg.safi;
	prefix2str(&msg.prefix, buf, sizeof(buf));

	ospf_orr_debug(
		"%s: Received IGP metric %s message from BGP for location %s",
		__func__, msg.reg ? "Register" : "Unregister", buf);

	/* Get ORR Root entry for the given address-family */
	root = ospf_orr_root_lookup(ospf, afi, safi, &msg.prefix.u.prefix4);

	/* Should not hit this condition */
	if ((root && msg.reg) || (!root && !msg.reg))
		return -1;

	/* Create ORR Root entry and calculate SPF from root */
	if (!root) {
		root = ospf_orr_root_new(ospf, afi, safi, &msg.prefix);
		if (!root) {
			ospf_orr_debug(
				"%s: For %s %s, Failed to create ORR Root entry %s.",
				__func__, afi2str(afi), safi2str(safi), buf);
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
		ospf_spf_calculate_schedule(ospf, SPF_FLAG_ORR_ROOT_CHANGE);
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
	ospf_show_orr(ospf, afi, safi);
	return 0;
}

void ospf_orr_igp_metric_send_update(struct orr_root *root,
				     unsigned short instance)
{
	int ret;
	uint8_t count = 0;
	struct route_node *rn;
	struct ospf_route * or ;
	struct orr_igp_metric_info msg;

	ospf_orr_debug("%s: Start", __func__);

	memset(&msg, 0, sizeof(msg));
	msg.proto = ZEBRA_ROUTE_OSPF;
	msg.safi = root->safi;
	msg.instId = instance;
	prefix_copy(&msg.root, &root->prefix);
	msg.num_entries = root->new_table->count;

	/* Update prefix table from ORR Route table */
	for (rn = route_top(root->new_table); rn; rn = route_next(rn)) {
		if (!(or = rn->info))
			continue;

		if (or->type != OSPF_DESTINATION_NETWORK)
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
					"%s: Failed to send message to BGP.",
					__func__);
			count = 0;
			prefix_copy(&msg.nexthop[count].prefix,
				    (struct prefix_ipv4 *)&rn->p);
			msg.nexthop[count].metric = or->cost;
			count++;
		}
	}
	if (count <= ORR_MAX_PREFIX) {
		msg.num_entries = count;
		ret = zclient_send_opaque(zclient, ORR_IGP_METRIC_UPDATE,
					  (uint8_t *)&msg, sizeof(msg));
		if (ret != ZCLIENT_SEND_SUCCESS)
			ospf_orr_debug("%s: Failed to send message to BGP.",
				       __func__);
	}

	ospf_orr_debug("%s: End", __func__);
}

static void ospf_show_orr_root(struct orr_root *root)
{
	if (!root)
		return;

	ospf_orr_debug("%s: Router-Address: %pI4:", __func__, &root->router_id);
	ospf_orr_debug("%s: \tAdvertising Router: %pI4:", __func__,
		       &root->adv_router);

	return;
}

void ospf_show_orr(struct ospf *ospf, afi_t afi, safi_t safi)
{
	struct listnode *node = NULL;
	struct orr_root *orr_root = NULL;
	struct list *orr_root_list = NULL;

	assert(ospf);

	FOREACH_AFI_SAFI (afi, safi) {
		orr_root_list = ospf->orr_root[afi][safi];
		if (!orr_root_list)
			return;

		ospf_orr_debug("%s: For Address Family %s %s:", __func__,
			       afi2str(afi), safi2str(safi));
		for (ALL_LIST_ELEMENTS_RO(orr_root_list, node, orr_root))
			ospf_show_orr_root(orr_root);
	}
	return;
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
	if (!(ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT)))
		return;

	if (opaque_type != OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA)
		return;

	if (!tlvh || (ntohs(tlvh->type) != TE_TLV_ROUTER_ADDR)
	    || (ntohs(tlvh->length) != TE_LINK_SUBTLV_DEF_SIZE))
		return;

	router_addr = (struct te_tlv_router_addr *)tlvh;
	if (IS_DEBUG_OSPF_ORR) {
		zlog_debug("[OSPF-ORR] %s: Opaque-area lsa %s lsdb", __func__,
			   add ? "added to" : "deleted from");
		zlog_debug("[OSPF-ORR] %s: \tOpaque-Type %u (%s)", __func__,
			   opaque_type, "Traffic Engineering LSA");
		zlog_debug("[OSPF-ORR] %s: \tOpaque-ID   0x%x", __func__,
			   opaque_id);
		zlog_debug("[OSPF-ORR] %s: \tOpaque-Info: %u octets of data%s",
			   __func__, ntohs(lsah->length) - OSPF_LSA_HEADER_SIZE,
			   VALID_OPAQUE_INFO_LEN(lsah) ? ""
						       : "(Invalid length?)");
		zlog_debug("[OSPF-ORR] %s: \tRouter-Address: %pI4", __func__,
			   &router_addr->value);
		zlog_debug("[OSPF-ORR] %s: \tAdvertising Router: %pI4",
			   __func__, &lsa->data->adv_router);
	}
	/* when Opaque LSA is added or removed from LSDB check if there is any
	 * change in MPLS-TE Router address and Advertising router address and
	 * update the table accordingly if there is no change in the mapping
	 * ignore update */
	/* Get ORR Root entry for the given address-family */
	FOREACH_AFI_SAFI (afi, safi) {
		root = ospf_orr_root_lookup(ospf, afi, safi,
					    &router_addr->value);
		if (root) {
			IPV4_ADDR_COPY(&root->adv_router,
				       &lsa->data->adv_router);
			ospf_show_orr(ospf, afi, safi);
			break;
		}
	}
	return;
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
		if (!root)
			continue;

		ospf_orr_debug("%s: Received LSA[Type%d:%pI4]", __func__,
			       lsa->data->type, &lsa->data->adv_router);

		root->router_lsa_rcvd = lsa;
		/* Compute SPF for all root nodes */
		ospf_spf_calculate_schedule(lsa->area->ospf,
					    SPF_FLAG_ORR_ROOT_CHANGE);
		return;
	}
}

/* Install routes to root table. */
void ospf_orr_route_install(struct orr_root *root, struct route_table *rt)
{
	struct route_node *rn;
	struct ospf_route * or ;

	/* rt contains new routing table, new_table contains an old one.
	   updating pointers */
	if (root->old_table)
		ospf_route_table_free(root->old_table);

	root->old_table = root->new_table;
	root->new_table = rt;
#if 0
        /* Delete old routes. */
        if (root->old_table)
                ospf_route_delete_uniq(root, root->old_table, rt);
#endif
	/* Install new routes. */
	for (rn = route_top(rt); rn; rn = route_next(rn))
		if ((or = rn->info) != NULL) {
			if (or->type == OSPF_DESTINATION_NETWORK) {
				if (!ospf_route_match_same(
					    root->old_table,
					    (struct prefix_ipv4 *)&rn->p, or)) {
#if 0
                                        ospf_zebra_add(
                                                ospf,
                                                (struct prefix_ipv4 *)&rn->p,
                                                or);
#endif
				}
			} else if (or->type == OSPF_DESTINATION_DISCARD)
				if (!ospf_route_match_same(
					    root->old_table,
					    (struct prefix_ipv4 *)&rn->p, or)) {
#if 0
                                        ospf_zebra_add_discard(
                                                ospf,
                                                (struct prefix_ipv4 *)&rn->p);
#endif
				}
		}
}
