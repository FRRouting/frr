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
#include "ospfd/ospf_te.h"

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

	IPV4_ADDR_COPY(&root->router_id, &p->u.prefix4);
	root->old_table = NULL;
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

/*
 * BGP-IGP IGP metric msg between BGP and IGP
 */
int ospf_orr_igp_metric_register(struct orr_igp_metric_reg msg)
{
	afi_t afi;
	safi_t safi;
	struct ospf *ospf;
	char buf[PREFIX2STR_BUFFER];
	struct orr_root *root = NULL;

	/* if ospf is not enabled ignore */
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL)
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

	if (!root) {
		/* Create ORR Root entry */
		root = ospf_orr_root_new(ospf, afi, safi, &msg.prefix);
		if (!root) {
			ospf_orr_debug(
				"%s: For %s %s, Failed to create ORR Root entry %s.",
				__func__, afi2str(afi), safi2str(safi), buf);
			return -1;
		}
	} else {
		/* Delete ORR Root entry */
		listnode_delete(ospf->orr_root[afi][safi], root);
		XFREE(MTYPE_OSPF_ORR_ROOT, root);

		/* If last node is deleted in the list*/
		if (!ospf->orr_root[afi][safi]->count)
			list_delete(&ospf->orr_root[afi][safi]);
	}

	ospf_show_orr(ospf, afi, safi);
	return 0;
}

void ospf_orr_igp_metric_send_update(struct prefix root)
{
	ospf_orr_debug("%s: send IGP metric to BGP for Root", __func__);
	/*
		memset(&update, 0, sizeof(update));
		update.proto = LDP_IGP_SYNC_IF_STATE_REQUEST;

		zclient_send_opaque(zclient, ORR_IGP_METRIC_UPDATE,
			(uint8_t *)&update, sizeof(update));
	*/
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
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL)
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
