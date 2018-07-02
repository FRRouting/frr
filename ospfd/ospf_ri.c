/*
 * This is an implementation of RFC4970 Router Information
 * with support of RFC5088 PCE Capabilites announcement
 *
 * Module name: Router Information
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 * Copyright (C) 2012 - 2017 Orange Labs http://www.orange.com/
 *
 * This file is part of GNU Quagga.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include <math.h>

#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "vty.h"
#include "stream.h"
#include "log.h"
#include "thread.h"
#include "hash.h"
#include "sockunion.h" /* for inet_aton() */
#include "mpls.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_ase.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_sr.h"
#include "ospfd/ospf_ri.h"

/* Store Router Information PCE TLV and SubTLV in network byte order. */
struct ospf_pce_info {
	bool enabled;
	struct ri_tlv_pce pce_header;
	struct ri_pce_subtlv_address pce_address;
	struct ri_pce_subtlv_path_scope pce_scope;
	struct list *pce_domain;
	struct list *pce_neighbor;
	struct ri_pce_subtlv_cap_flag pce_cap_flag;
};

/*
 * Store Router Information Segment Routing TLV and SubTLV
 * in network byte order
 */
struct ospf_ri_sr_info {
	bool enabled;
	/* Algorithms supported by the node */
	struct ri_sr_tlv_sr_algorithm algo;
	/*
	 * Segment Routing Global Block i.e. label range
	 * Only one range supported in this code
	 */
	struct ri_sr_tlv_sid_label_range range;
	/* Maximum SID Depth supported by the node */
	struct ri_sr_tlv_node_msd msd;
};

/* Following structure are internal use only. */
struct ospf_router_info {
	bool enabled;

	uint8_t registered;
	uint8_t scope;

/* Flags to manage this router information. */
#define RIFLG_LSA_ENGAGED		0x1
#define RIFLG_LSA_FORCED_REFRESH	0x2
	uint32_t flags;

	/* area pointer if flooding is Type 10 Null if flooding is AS scope */
	struct ospf_area *area;
	struct in_addr area_id;

	/* Store Router Information Capabilities LSA */
	struct ri_tlv_router_cap router_cap;

	/* Store PCE capability LSA */
	struct ospf_pce_info pce_info;

	/* Store SR capability LSA */
	struct ospf_ri_sr_info sr_info;
};

/*
 * Global variable to manage Opaque-LSA/Router Information on this node.
 * Note that all parameter values are stored in network byte order.
 */
static struct ospf_router_info OspfRI;

/*------------------------------------------------------------------------------*
 * Followings are initialize/terminate functions for Router Information
 *handling.
 *------------------------------------------------------------------------------*/

static void ospf_router_info_ism_change(struct ospf_interface *oi,
					int old_status);
static void ospf_router_info_nsm_change(struct ospf_neighbor *nbr,
					int old_status);
static void ospf_router_info_config_write_router(struct vty *vty);
static void ospf_router_info_show_info(struct vty *vty, struct ospf_lsa *lsa);
static int ospf_router_info_lsa_originate(void *arg);
static struct ospf_lsa *ospf_router_info_lsa_refresh(struct ospf_lsa *lsa);
static void ospf_router_info_lsa_schedule(enum lsa_opcode opcode);
static void ospf_router_info_register_vty(void);
static int ospf_router_info_lsa_update(struct ospf_lsa *lsa);
static void del_pce_info(void *val);

int ospf_router_info_init(void)
{

	zlog_info("RI -> Initialize Router Information");

	memset(&OspfRI, 0, sizeof(struct ospf_router_info));
	OspfRI.enabled = false;
	OspfRI.registered = 0;
	OspfRI.scope = OSPF_OPAQUE_AS_LSA;
	OspfRI.area_id.s_addr = 0;
	OspfRI.flags = 0;

	/* Initialize pce domain and neighbor list */
	OspfRI.pce_info.enabled = false;
	OspfRI.pce_info.pce_domain = list_new();
	OspfRI.pce_info.pce_domain->del = del_pce_info;
	OspfRI.pce_info.pce_neighbor = list_new();
	OspfRI.pce_info.pce_neighbor->del = del_pce_info;

	/* Initialize Segment Routing information structure */
	OspfRI.sr_info.enabled = false;

	ospf_router_info_register_vty();

	return 0;
}

static int ospf_router_info_register(uint8_t scope)
{
	int rc = 0;

	if (OspfRI.registered)
		return rc;

	zlog_info("RI -> Register Router Information with scope %s(%d)",
		  scope == OSPF_OPAQUE_AREA_LSA ? "Area" : "AS", scope);
	rc = ospf_register_opaque_functab(
		scope, OPAQUE_TYPE_ROUTER_INFORMATION_LSA,
		NULL, /* new interface */
		NULL, /* del interface */
		ospf_router_info_ism_change, ospf_router_info_nsm_change,
		ospf_router_info_config_write_router,
		NULL, /* Config. write interface */
		NULL, /* Config. write debug */
		ospf_router_info_show_info, ospf_router_info_lsa_originate,
		ospf_router_info_lsa_refresh, ospf_router_info_lsa_update,
		NULL); /* del_lsa_hook */

	if (rc != 0) {
		zlog_warn(
			"ospf_router_info_init: Failed to register functions");
		return rc;
	}

	OspfRI.registered = 1;
	OspfRI.scope = scope;
	return rc;
}

static int ospf_router_info_unregister()
{

	if ((OspfRI.scope != OSPF_OPAQUE_AS_LSA)
	    && (OspfRI.scope != OSPF_OPAQUE_AREA_LSA)) {
		zlog_warn(
			"Unable to unregister Router Info functions: Wrong scope!");
		return -1;
	}

	ospf_delete_opaque_functab(OspfRI.scope,
				   OPAQUE_TYPE_ROUTER_INFORMATION_LSA);

	OspfRI.registered = 0;
	return 0;
}

void ospf_router_info_term(void)
{

	list_delete_and_null(&OspfRI.pce_info.pce_domain);
	list_delete_and_null(&OspfRI.pce_info.pce_neighbor);

	OspfRI.enabled = false;

	ospf_router_info_unregister();

	return;
}

void ospf_router_info_finish(void)
{
	list_delete_all_node(OspfRI.pce_info.pce_domain);
	list_delete_all_node(OspfRI.pce_info.pce_neighbor);

	OspfRI.enabled = false;
}

static void del_pce_info(void *val)
{
	XFREE(MTYPE_OSPF_PCE_PARAMS, val);
	return;
}

/* Catch RI LSA flooding Scope for ospf_ext.[h,c] code */
struct scope_info ospf_router_info_get_flooding_scope(void)
{
	struct scope_info flooding_scope;

	if (OspfRI.scope == OSPF_OPAQUE_AS_LSA) {
		flooding_scope.scope = OSPF_OPAQUE_AS_LSA;
		flooding_scope.area_id.s_addr = 0;
		return flooding_scope;
	}
	flooding_scope.scope = OSPF_OPAQUE_AREA_LSA;
	flooding_scope.area_id.s_addr = OspfRI.area_id.s_addr;
	return flooding_scope;
}

/*------------------------------------------------------------------------*
 * Followings are control functions for ROUTER INFORMATION parameters
 *management.
 *------------------------------------------------------------------------*/

static void set_router_info_capabilities(struct ri_tlv_router_cap *ric,
					 uint32_t cap)
{
	ric->header.type = htons(RI_TLV_CAPABILITIES);
	ric->header.length = htons(RI_TLV_LENGTH);
	ric->value = htonl(cap);
	return;
}

static int set_pce_header(struct ospf_pce_info *pce)
{
	uint16_t length = 0;
	struct listnode *node;
	struct ri_pce_subtlv_domain *domain;
	struct ri_pce_subtlv_neighbor *neighbor;

	/* PCE Address */
	if (ntohs(pce->pce_address.header.type) != 0)
		length += TLV_SIZE(&pce->pce_address.header);

	/* PCE Path Scope */
	if (ntohs(pce->pce_scope.header.type) != 0)
		length += TLV_SIZE(&pce->pce_scope.header);

	/* PCE Domain */
	for (ALL_LIST_ELEMENTS_RO(pce->pce_domain, node, domain)) {
		if (ntohs(domain->header.type) != 0)
			length += TLV_SIZE(&domain->header);
	}

	/* PCE Neighbor */
	for (ALL_LIST_ELEMENTS_RO(pce->pce_neighbor, node, neighbor)) {
		if (ntohs(neighbor->header.type) != 0)
			length += TLV_SIZE(&neighbor->header);
	}

	/* PCE Capabilities */
	if (ntohs(pce->pce_cap_flag.header.type) != 0)
		length += TLV_SIZE(&pce->pce_cap_flag.header);

	if (length != 0) {
		pce->pce_header.header.type = htons(RI_TLV_PCE);
		pce->pce_header.header.length = htons(length);
		pce->enabled = true;
	} else {
		pce->pce_header.header.type = 0;
		pce->pce_header.header.length = 0;
		pce->enabled = false;
	}

	return length;
}

static void set_pce_address(struct in_addr ipv4, struct ospf_pce_info *pce)
{

	/* Enable PCE Info */
	pce->pce_header.header.type = htons(RI_TLV_PCE);
	/* Set PCE Address */
	pce->pce_address.header.type = htons(RI_PCE_SUBTLV_ADDRESS);
	pce->pce_address.header.length = htons(PCE_ADDRESS_LENGTH_IPV4);
	pce->pce_address.address.type = htons(PCE_ADDRESS_TYPE_IPV4);
	pce->pce_address.address.value = ipv4;

	return;
}

static void set_pce_path_scope(uint32_t scope, struct ospf_pce_info *pce)
{

	/* Set PCE Scope */
	pce->pce_scope.header.type = htons(RI_PCE_SUBTLV_PATH_SCOPE);
	pce->pce_scope.header.length = htons(RI_TLV_LENGTH);
	pce->pce_scope.value = htonl(scope);

	return;
}

static void set_pce_domain(uint16_t type, uint32_t domain,
			   struct ospf_pce_info *pce)
{

	struct ri_pce_subtlv_domain *new;

	/* Create new domain info */
	new = XCALLOC(MTYPE_OSPF_PCE_PARAMS,
		      sizeof(struct ri_pce_subtlv_domain));

	new->header.type = htons(RI_PCE_SUBTLV_DOMAIN);
	new->header.length = htons(PCE_ADDRESS_LENGTH_IPV4);
	new->type = htons(type);
	new->value = htonl(domain);

	/* Add new domain to the list */
	listnode_add(pce->pce_domain, new);

	return;
}

static void unset_pce_domain(uint16_t type, uint32_t domain,
			     struct ospf_pce_info *pce)
{
	struct listnode *node;
	struct ri_pce_subtlv_domain *old = NULL;
	int found = 0;

	/* Search the corresponding node */
	for (ALL_LIST_ELEMENTS_RO(pce->pce_domain, node, old)) {
		if ((old->type == htons(type))
		    && (old->value == htonl(domain))) {
			found = 1;
			break;
		}
	}

	/* if found remove it */
	if (found) {
		listnode_delete(pce->pce_domain, old);

		/* Avoid misjudgement in the next lookup. */
		if (listcount(pce->pce_domain) == 0)
			pce->pce_domain->head = pce->pce_domain->tail = NULL;

		/* Finally free the old domain */
		XFREE(MTYPE_OSPF_PCE_PARAMS, old);
	}
}

static void set_pce_neighbor(uint16_t type, uint32_t domain,
			     struct ospf_pce_info *pce)
{

	struct ri_pce_subtlv_neighbor *new;

	/* Create new neighbor info */
	new = XCALLOC(MTYPE_OSPF_PCE_PARAMS,
		      sizeof(struct ri_pce_subtlv_neighbor));

	new->header.type = htons(RI_PCE_SUBTLV_NEIGHBOR);
	new->header.length = htons(PCE_ADDRESS_LENGTH_IPV4);
	new->type = htons(type);
	new->value = htonl(domain);

	/* Add new domain to the list */
	listnode_add(pce->pce_neighbor, new);

	return;
}

static void unset_pce_neighbor(uint16_t type, uint32_t domain,
			       struct ospf_pce_info *pce)
{
	struct listnode *node;
	struct ri_pce_subtlv_neighbor *old = NULL;
	int found = 0;

	/* Search the corresponding node */
	for (ALL_LIST_ELEMENTS_RO(pce->pce_neighbor, node, old)) {
		if ((old->type == htons(type))
		    && (old->value == htonl(domain))) {
			found = 1;
			break;
		}
	}

	/* if found remove it */
	if (found) {
		listnode_delete(pce->pce_neighbor, old);

		/* Avoid misjudgement in the next lookup. */
		if (listcount(pce->pce_neighbor) == 0)
			pce->pce_neighbor->head = pce->pce_neighbor->tail =
				NULL;

		/* Finally free the old domain */
		XFREE(MTYPE_OSPF_PCE_PARAMS, old);
	}
}

static void set_pce_cap_flag(uint32_t cap, struct ospf_pce_info *pce)
{

	/* Set PCE Capabilities flag */
	pce->pce_cap_flag.header.type = htons(RI_PCE_SUBTLV_CAP_FLAG);
	pce->pce_cap_flag.header.length = htons(RI_TLV_LENGTH);
	pce->pce_cap_flag.value = htonl(cap);

	return;
}

/* Segment Routing TLV setter */

/* Algorithm SubTLV - section 3.1 */
static void set_sr_algorithm(uint8_t algo)
{

	OspfRI.sr_info.algo.value[0] = algo;
	for (int i = 1; i < ALGORITHM_COUNT; i++)
		OspfRI.sr_info.algo.value[i] = SR_ALGORITHM_UNSET;

	/* Set TLV type and length == only 1 Algorithm */
	TLV_TYPE(OspfRI.sr_info.algo) = htons(RI_SR_TLV_SR_ALGORITHM);
	TLV_LEN(OspfRI.sr_info.algo) = htons(sizeof(uint8_t));
}

/* unset Aglogithm SubTLV */
static void unset_sr_algorithm(uint8_t algo)
{

	for (int i = 0; i < ALGORITHM_COUNT; i++)
		OspfRI.sr_info.algo.value[i] = SR_ALGORITHM_UNSET;

	/* Unset TLV type and length */
	TLV_TYPE(OspfRI.sr_info.algo) = htons(0);
	TLV_LEN(OspfRI.sr_info.algo) = htons(0);
}

/* Segment Routing Global Block SubTLV - section 3.2 */
static void set_sr_sid_label_range(struct sr_srgb srgb)
{
	/* Set Header */
	TLV_TYPE(OspfRI.sr_info.range) = htons(RI_SR_TLV_SID_LABEL_RANGE);
	TLV_LEN(OspfRI.sr_info.range) =
		htons(SUBTLV_SID_LABEL_SIZE + sizeof(uint32_t));
	/* Set Range Size */
	OspfRI.sr_info.range.size = htonl(SET_RANGE_SIZE(srgb.range_size));
	/* Set Lower bound label SubTLV */
	TLV_TYPE(OspfRI.sr_info.range.lower) = htons(SUBTLV_SID_LABEL);
	TLV_LEN(OspfRI.sr_info.range.lower) = htons(SID_RANGE_LABEL_LENGTH);
	OspfRI.sr_info.range.lower.value = htonl(SET_LABEL(srgb.lower_bound));
}

/* Unset this SRGB SubTLV */
static void unset_sr_sid_label_range(void)
{

	TLV_TYPE(OspfRI.sr_info.range) = htons(0);
	TLV_LEN(OspfRI.sr_info.range) = htons(0);
	TLV_TYPE(OspfRI.sr_info.range.lower) = htons(0);
	TLV_LEN(OspfRI.sr_info.range.lower) = htons(0);
}

/* Set Maximum Stack Depth for this router */
static void set_sr_node_msd(uint8_t msd)
{
	TLV_TYPE(OspfRI.sr_info.msd) = htons(RI_SR_TLV_NODE_MSD);
	TLV_LEN(OspfRI.sr_info.msd) = htons(sizeof(uint32_t));
	OspfRI.sr_info.msd.value = msd;
}

/* Unset this router MSD */
static void unset_sr_node_msd(void)
{
	TLV_TYPE(OspfRI.sr_info.msd) = htons(0);
	TLV_LEN(OspfRI.sr_info.msd) = htons(0);
}

static void unset_param(void *tlv_buffer)
{
	struct tlv_header *tlv = (struct tlv_header *)tlv_buffer;

	tlv->type = 0;
	/* Fill the Value to 0 */
	memset(TLV_DATA(tlv_buffer), 0, TLV_BODY_SIZE(tlv));
	tlv->length = 0;

	return;
}

static void initialize_params(struct ospf_router_info *ori)
{
	uint32_t cap = 0;
	struct ospf *top;

	/*
	 * Initialize default Router Information Capabilities.
	 */
	cap = RI_TE_SUPPORT;

	set_router_info_capabilities(&ori->router_cap, cap);

	/* If Area address is not null and exist, retrieve corresponding
	 * structure */
	top = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	zlog_info("RI-> Initialize Router Info for %s scope within area %s",
		  OspfRI.scope == OSPF_OPAQUE_AREA_LSA ? "Area" : "AS",
		  inet_ntoa(OspfRI.area_id));

	/* Try to get the Area context at this step. Do it latter if not
	 * available */
	if ((OspfRI.scope == OSPF_OPAQUE_AREA_LSA) && (OspfRI.area == NULL))
		OspfRI.area = ospf_area_lookup_by_area_id(top, OspfRI.area_id);

	/*
	 * Initialize default PCE Information values
	 */
	/* PCE address == OSPF Router ID */
	set_pce_address(top->router_id, &ori->pce_info);

	/* PCE scope */
	cap = 7; /* Set L, R and Rd bits to one = intra & inter-area path
		    computation */
	set_pce_path_scope(cap, &ori->pce_info);

	/* PCE Capabilities */
	cap = PCE_CAP_BIDIRECTIONAL | PCE_CAP_DIVERSE_PATH | PCE_CAP_OBJECTIVES
	      | PCE_CAP_ADDITIVE | PCE_CAP_MULTIPLE_REQ;
	set_pce_cap_flag(cap, &ori->pce_info);

	return;
}

static int is_mandated_params_set(struct ospf_router_info ori)
{
	int rc = 0;

	if (ntohs(ori.router_cap.header.type) == 0)
		return rc;

	if ((ntohs(ori.pce_info.pce_header.header.type) == RI_TLV_PCE)
	    && (ntohs(ori.pce_info.pce_address.header.type) == 0)
	    && (ntohs(ori.pce_info.pce_cap_flag.header.type) == 0))
		return rc;

	if ((ori.sr_info.enabled) && (ntohs(TLV_TYPE(ori.sr_info.algo)) == 0)
	    && (ntohs(TLV_TYPE(ori.sr_info.range)) == 0))
		return rc;

	rc = 1;

	return rc;
}

/*
 * Used by Segment Routing to set new TLVs and Sub-TLVs values
 *
 * @param enable To activate or not Segment Routing router Information flooding
 * @param size   Size of Label Range i.e. SRGB size
 * @param lower  Lower bound of the Label Range i.e. SRGB first label
 * @param msd    Maximum label Stack Depth suported by the router
 *
 * @return none
 */
void ospf_router_info_update_sr(bool enable, struct sr_srgb srgb, uint8_t msd)
{

	/* First activate and initialize Router Information is necessary */
	if (!OspfRI.enabled) {
		OspfRI.enabled = true;
		initialize_params(&OspfRI);
	}

	if (IS_DEBUG_OSPF_SR)
		zlog_debug("RI-> %s Routing Information for Segment Routing",
			   enable ? "Enable" : "Disable");

	/* Unset or Set SR parameters */
	if (!enable) {
		unset_sr_algorithm(SR_ALGORITHM_SPF);
		unset_sr_sid_label_range();
		unset_sr_node_msd();
		OspfRI.sr_info.enabled = false;
	} else {
		// Only SR_ALGORITHM_SPF is supported
		set_sr_algorithm(SR_ALGORITHM_SPF);
		set_sr_sid_label_range(srgb);
		if (msd != 0)
			set_sr_node_msd(msd);
		else
			unset_sr_node_msd();
		OspfRI.sr_info.enabled = true;
	}

	/* Refresh if already engaged or originate RI LSA */
	if (CHECK_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED))
		ospf_router_info_lsa_schedule(REFRESH_THIS_LSA);
	else
		ospf_router_info_lsa_schedule(REORIGINATE_THIS_LSA);
}

/*------------------------------------------------------------------------*
 * Followings are callback functions against generic Opaque-LSAs handling.
 *------------------------------------------------------------------------*/
static void ospf_router_info_ism_change(struct ospf_interface *oi,
					int old_state)
{
	/* So far, nothing to do here. */
	return;
}

static void ospf_router_info_nsm_change(struct ospf_neighbor *nbr,
					int old_state)
{
	/* So far, nothing to do here. */
	return;
}

/*------------------------------------------------------------------------*
 * Followings are OSPF protocol processing functions for ROUTER INFORMATION
 *------------------------------------------------------------------------*/

static void build_tlv_header(struct stream *s, struct tlv_header *tlvh)
{

	stream_put(s, tlvh, sizeof(struct tlv_header));
	return;
}

static void build_tlv(struct stream *s, struct tlv_header *tlvh)
{

	if (ntohs(tlvh->type) != 0) {
		build_tlv_header(s, tlvh);
		stream_put(s, TLV_DATA(tlvh), TLV_BODY_SIZE(tlvh));
	}
	return;
}

static void ospf_router_info_lsa_body_set(struct stream *s)
{

	struct listnode *node;
	struct ri_pce_subtlv_domain *domain;
	struct ri_pce_subtlv_neighbor *neighbor;

	/* Build Router Information TLV */
	build_tlv(s, &OspfRI.router_cap.header);

	/* Build Segment Routing TLVs if enabled */
	if (OspfRI.sr_info.enabled) {
		/* Build Algorithm TLV */
		build_tlv(s, &TLV_HDR(OspfRI.sr_info.algo));
		/* Build SRGB TLV */
		build_tlv(s, &TLV_HDR(OspfRI.sr_info.range));
		/* Build MSD TLV */
		build_tlv(s, &TLV_HDR(OspfRI.sr_info.msd));
	}

	/* Add RI PCE TLV if it is set */
	if (OspfRI.pce_info.enabled) {

		/* Compute PCE Info header first */
		set_pce_header(&OspfRI.pce_info);

		/* Build PCE TLV */
		build_tlv_header(s, &OspfRI.pce_info.pce_header.header);

		/* Build PCE address sub-tlv */
		build_tlv(s, &OspfRI.pce_info.pce_address.header);

		/* Build PCE path scope sub-tlv */
		build_tlv(s, &OspfRI.pce_info.pce_scope.header);

		/* Build PCE domain sub-tlv */
		for (ALL_LIST_ELEMENTS_RO(OspfRI.pce_info.pce_domain, node,
					  domain))
			build_tlv(s, &domain->header);

		/* Build PCE neighbor sub-tlv */
		for (ALL_LIST_ELEMENTS_RO(OspfRI.pce_info.pce_neighbor, node,
					  neighbor))
			build_tlv(s, &neighbor->header);

		/* Build PCE cap flag sub-tlv */
		build_tlv(s, &OspfRI.pce_info.pce_cap_flag.header);
	}

	return;
}

/* Create new opaque-LSA. */
static struct ospf_lsa *ospf_router_info_lsa_new()
{
	struct ospf *top;
	struct stream *s;
	struct lsa_header *lsah;
	struct ospf_lsa *new = NULL;
	uint8_t options, lsa_type;
	struct in_addr lsa_id;
	uint32_t tmp;
	uint16_t length;

	/* Create a stream for LSA. */
	if ((s = stream_new(OSPF_MAX_LSA_SIZE)) == NULL) {
		zlog_warn("ospf_router_info_lsa_new: stream_new() ?");
		return NULL;
	}
	lsah = (struct lsa_header *)STREAM_DATA(s);

	options = OSPF_OPTION_E;  /* Enable AS external as we flood RI with
				     Opaque Type 11 */
	options |= OSPF_OPTION_O; /* Don't forget this :-) */

	lsa_type = OspfRI.scope;
	/* LSA ID == 0 for Router Information see RFC 4970 */
	tmp = SET_OPAQUE_LSID(OPAQUE_TYPE_ROUTER_INFORMATION_LSA, 0);
	lsa_id.s_addr = htonl(tmp);

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
		zlog_debug(
			"LSA[Type%d:%s]: Create an Opaque-LSA/ROUTER INFORMATION instance",
			lsa_type, inet_ntoa(lsa_id));

	top = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	/* Set opaque-LSA header fields. */
	lsa_header_set(s, options, lsa_type, lsa_id, top->router_id);

	/* Set opaque-LSA body fields. */
	ospf_router_info_lsa_body_set(s);

	/* Set length. */
	length = stream_get_endp(s);
	lsah->length = htons(length);

	/* Now, create an OSPF LSA instance. */
	if ((new = ospf_lsa_new()) == NULL) {
		zlog_warn("ospf_router_info_lsa_new: ospf_lsa_new() ?");
		stream_free(s);
		return NULL;
	}
	if ((new->data = ospf_lsa_data_new(length)) == NULL) {
		zlog_warn("ospf_router_info_lsa_new: ospf_lsa_data_new() ?");
		ospf_lsa_unlock(&new);
		new = NULL;
		stream_free(s);
		return new;
	}

	new->area = OspfRI.area; /* Area must be null if the Opaque type is AS
				    scope, fulfill otherwise */

	if (new->area && new->area->ospf)
		new->vrf_id = new->area->ospf->vrf_id;
	else
		new->vrf_id = VRF_DEFAULT;

	SET_FLAG(new->flags, OSPF_LSA_SELF);
	memcpy(new->data, lsah, length);
	stream_free(s);

	return new;
}

static int ospf_router_info_lsa_originate1(void *arg)
{
	struct ospf_lsa *new;
	struct ospf *top;
	struct ospf_area *area;
	int rc = -1;
	vrf_id_t vrf_id = VRF_DEFAULT;

	/* First check if the area is known if flooding scope is Area */
	if (OspfRI.scope == OSPF_OPAQUE_AREA_LSA) {
		area = (struct ospf_area *)arg;
		if (area->area_id.s_addr != OspfRI.area_id.s_addr) {
			zlog_debug(
				"RI -> This is not the Router Information Area. Stop processing");
			return rc;
		}
		OspfRI.area = area;
		if (area->ospf)
			vrf_id = area->ospf->vrf_id;
	}

	/* Create new Opaque-LSA/ROUTER INFORMATION instance. */
	if ((new = ospf_router_info_lsa_new()) == NULL) {
		zlog_warn(
			"ospf_router_info_lsa_originate1: ospf_router_info_lsa_new() ?");
		return rc;
	}
	new->vrf_id = vrf_id;

	/* Get ospf info */
	top = ospf_lookup_by_vrf_id(vrf_id);
	if (top == NULL) {
		zlog_debug("%s: ospf instance not found for vrf id %u",
			   __PRETTY_FUNCTION__, vrf_id);
		ospf_lsa_unlock(&new);
		return rc;
	}

	/* Install this LSA into LSDB. */
	if (ospf_lsa_install(top, NULL /*oi */, new) == NULL) {
		zlog_warn(
			"ospf_router_info_lsa_originate1: ospf_lsa_install() ?");
		ospf_lsa_unlock(&new);
		return rc;
	}

	/* Now this Router Info parameter entry has associated LSA. */
	SET_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED);

	/* Update new LSA origination count. */
	top->lsa_originate_count++;

	/* Flood new LSA through AS. */
	if (OspfRI.scope == OSPF_OPAQUE_AS_LSA)
		ospf_flood_through_as(top, NULL /*nbr */, new);
	else
		ospf_flood_through_area(OspfRI.area, NULL /*nbr */, new);

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE)) {
		zlog_debug(
			"LSA[Type%d:%s]: Originate Opaque-LSA/ROUTER INFORMATION",
			new->data->type, inet_ntoa(new->data->id));
		ospf_lsa_header_dump(new->data);
	}

	rc = 0;
	return rc;
}

static int ospf_router_info_lsa_originate(void *arg)
{

	int rc = -1;

	if (!OspfRI.enabled) {
		zlog_info(
			"ospf_router_info_lsa_originate: ROUTER INFORMATION is disabled now.");
		rc = 0; /* This is not an error case. */
		return rc;
	}

	/* Check if Router Information LSA is already engaged */
	if (CHECK_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED)) {
		if (CHECK_FLAG(OspfRI.flags, RIFLG_LSA_FORCED_REFRESH)) {
			UNSET_FLAG(OspfRI.flags, RIFLG_LSA_FORCED_REFRESH);
			ospf_router_info_lsa_schedule(REFRESH_THIS_LSA);
		}
	} else {
		if (!is_mandated_params_set(OspfRI))
			zlog_warn(
				"ospf_router_info_lsa_originate: lacks mandated ROUTER INFORMATION parameters");

		/* Ok, let's try to originate an LSA */
		if (ospf_router_info_lsa_originate1(arg) != 0)
			return rc;
	}

	rc = 0;
	return rc;
}

static struct ospf_lsa *ospf_router_info_lsa_refresh(struct ospf_lsa *lsa)
{
	struct ospf_lsa *new = NULL;
	struct ospf *top;

	if (!OspfRI.enabled) {
		/*
		 * This LSA must have flushed before due to ROUTER INFORMATION
		 * status change.
		 * It seems a slip among routers in the routing domain.
		 */
		zlog_info(
			"ospf_router_info_lsa_refresh: ROUTER INFORMATION is disabled now.");
		lsa->data->ls_age =
			htons(OSPF_LSA_MAXAGE); /* Flush it anyway. */
	}

	/* Verify that the Router Information ID is supported */
	if (GET_OPAQUE_ID(ntohl(lsa->data->id.s_addr)) != 0) {
		zlog_warn(
			"ospf_router_info_lsa_refresh: Unsupported Router Information ID");
		return NULL;
	}

	/* If the lsa's age reached to MaxAge, start flushing procedure. */
	if (IS_LSA_MAXAGE(lsa)) {
		UNSET_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED);
		ospf_opaque_lsa_flush_schedule(lsa);
		return NULL;
	}

	/* Create new Opaque-LSA/ROUTER INFORMATION instance. */
	if ((new = ospf_router_info_lsa_new()) == NULL) {
		zlog_warn(
			"ospf_router_info_lsa_refresh: ospf_router_info_lsa_new() ?");
		return NULL;
	}
	new->data->ls_seqnum = lsa_seqnum_increment(lsa);
	new->vrf_id = lsa->vrf_id;

	/* Install this LSA into LSDB. */
	/* Given "lsa" will be freed in the next function. */
	top = ospf_lookup_by_vrf_id(lsa->vrf_id);
	if (ospf_lsa_install(top, NULL /*oi */, new) == NULL) {
		zlog_warn("ospf_router_info_lsa_refresh: ospf_lsa_install() ?");
		ospf_lsa_unlock(&new);
		return new;
	}

	/* Flood updated LSA through AS or AREA depending of OspfRI.scope. */
	if (OspfRI.scope == OSPF_OPAQUE_AS_LSA)
		ospf_flood_through_as(top, NULL /*nbr */, new);
	else
		ospf_flood_through_area(OspfRI.area, NULL /*nbr */, new);

	/* Debug logging. */
	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE)) {
		zlog_debug(
			"LSA[Type%d:%s]: Refresh Opaque-LSA/ROUTER INFORMATION",
			new->data->type, inet_ntoa(new->data->id));
		ospf_lsa_header_dump(new->data);
	}

	return new;
}

static void ospf_router_info_lsa_schedule(enum lsa_opcode opcode)
{
	struct ospf_lsa lsa;
	struct lsa_header lsah;
	struct ospf *top;
	uint32_t tmp;

	memset(&lsa, 0, sizeof(lsa));
	memset(&lsah, 0, sizeof(lsah));

	zlog_debug("RI-> LSA schedule %s%s%s",
		   opcode == REORIGINATE_THIS_LSA ? "Re-Originate" : "",
		   opcode == REFRESH_THIS_LSA ? "Refresh" : "",
		   opcode == FLUSH_THIS_LSA ? "Flush" : "");

	/* Check LSA flags state coherence */
	if (!CHECK_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED)
	    && (opcode != REORIGINATE_THIS_LSA))
		return;

	if (CHECK_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED)
	    && (opcode == REORIGINATE_THIS_LSA))
		opcode = REFRESH_THIS_LSA;

	top = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if ((OspfRI.scope == OSPF_OPAQUE_AREA_LSA) && (OspfRI.area == NULL)) {
		zlog_warn(
			"ospf_router_info_lsa_schedule(): Router Info is Area scope flooding but area is not set");
		OspfRI.area = ospf_area_lookup_by_area_id(top, OspfRI.area_id);
	}
	lsa.area = OspfRI.area;
	lsa.data = &lsah;
	lsah.type = OspfRI.scope;

	/* LSA ID is set to 0 for the Router Information. See RFC 4970 */
	tmp = SET_OPAQUE_LSID(OPAQUE_TYPE_ROUTER_INFORMATION_LSA, 0);
	lsah.id.s_addr = htonl(tmp);

	switch (opcode) {
	case REORIGINATE_THIS_LSA:
		if (OspfRI.scope == OSPF_OPAQUE_AREA_LSA)
			ospf_opaque_lsa_reoriginate_schedule(
				(void *)OspfRI.area, OSPF_OPAQUE_AREA_LSA,
				OPAQUE_TYPE_ROUTER_INFORMATION_LSA);
		else
			ospf_opaque_lsa_reoriginate_schedule(
				(void *)top, OSPF_OPAQUE_AS_LSA,
				OPAQUE_TYPE_ROUTER_INFORMATION_LSA);
		break;
	case REFRESH_THIS_LSA:
		ospf_opaque_lsa_refresh_schedule(&lsa);
		break;
	case FLUSH_THIS_LSA:
		UNSET_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED);
		ospf_opaque_lsa_flush_schedule(&lsa);
		break;
	default:
		zlog_warn("ospf_router_info_lsa_schedule: Unknown opcode (%u)",
			  opcode);
		break;
	}

	return;
}

/* Callback to handle Segment Routing information */
static int ospf_router_info_lsa_update(struct ospf_lsa *lsa)
{

	/* Sanity Check */
	if (lsa == NULL) {
		zlog_warn("OSPF-RI (%s): Abort! LSA is NULL", __func__);
		return -1;
	}

	/* Process only Opaque LSA */
	if ((lsa->data->type != OSPF_OPAQUE_AREA_LSA)
	    && (lsa->data->type != OSPF_OPAQUE_AS_LSA))
		return 0;

	/* Process only Router Information LSA */
	if (GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr))
	    != OPAQUE_TYPE_ROUTER_INFORMATION_LSA)
		return 0;

	/* Check if it is not my LSA */
	if (IS_LSA_SELF(lsa))
		return 0;

	/* Check if Router Info & Segment Routing are enable */
	if (!OspfRI.enabled || !OspfRI.sr_info.enabled)
		return 0;

	/* Call Segment Routing LSA update or deletion */
	if (!IS_LSA_MAXAGE(lsa))
		ospf_sr_ri_lsa_update(lsa);
	else
		ospf_sr_ri_lsa_delete(lsa);

	return 0;
}

/*------------------------------------------------------------------------*
 * Followings are vty session control functions.
 *------------------------------------------------------------------------*/

static uint16_t show_vty_router_cap(struct vty *vty, struct tlv_header *tlvh)
{
	struct ri_tlv_router_cap *top = (struct ri_tlv_router_cap *)tlvh;

	if (vty != NULL)
		vty_out(vty, "  Router Capabilities: 0x%x\n",
			ntohl(top->value));
	else
		zlog_debug("    Router Capabilities: 0x%x", ntohl(top->value));

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_pce_subtlv_address(struct vty *vty,
					    struct tlv_header *tlvh)
{
	struct ri_pce_subtlv_address *top =
		(struct ri_pce_subtlv_address *)tlvh;

	if (ntohs(top->address.type) == PCE_ADDRESS_TYPE_IPV4) {
		if (vty != NULL)
			vty_out(vty, "  PCE Address: %s\n",
				inet_ntoa(top->address.value));
		else
			zlog_debug("    PCE Address: %s",
				   inet_ntoa(top->address.value));
	} else {
		/* TODO: Add support to IPv6 with inet_ntop() */
		if (vty != NULL)
			vty_out(vty, "  PCE Address: 0x%x\n",
				ntohl(top->address.value.s_addr));
		else
			zlog_debug("    PCE Address: 0x%x",
				   ntohl(top->address.value.s_addr));
	}

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_pce_subtlv_path_scope(struct vty *vty,
					       struct tlv_header *tlvh)
{
	struct ri_pce_subtlv_path_scope *top =
		(struct ri_pce_subtlv_path_scope *)tlvh;

	if (vty != NULL)
		vty_out(vty, "  PCE Path Scope: 0x%x\n", ntohl(top->value));
	else
		zlog_debug("    PCE Path Scope: 0x%x", ntohl(top->value));

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_pce_subtlv_domain(struct vty *vty,
					   struct tlv_header *tlvh)
{
	struct ri_pce_subtlv_domain *top = (struct ri_pce_subtlv_domain *)tlvh;
	struct in_addr tmp;

	if (ntohs(top->type) == PCE_DOMAIN_TYPE_AREA) {
		tmp.s_addr = top->value;
		if (vty != NULL)
			vty_out(vty, "  PCE domain Area: %s\n", inet_ntoa(tmp));
		else
			zlog_debug("    PCE domain Area: %s", inet_ntoa(tmp));
	} else {
		if (vty != NULL)
			vty_out(vty, "  PCE domain AS: %d\n",
				ntohl(top->value));
		else
			zlog_debug("    PCE domain AS: %d", ntohl(top->value));
	}
	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_pce_subtlv_neighbor(struct vty *vty,
					     struct tlv_header *tlvh)
{

	struct ri_pce_subtlv_neighbor *top =
		(struct ri_pce_subtlv_neighbor *)tlvh;
	struct in_addr tmp;

	if (ntohs(top->type) == PCE_DOMAIN_TYPE_AREA) {
		tmp.s_addr = top->value;
		if (vty != NULL)
			vty_out(vty, "  PCE neighbor Area: %s\n",
				inet_ntoa(tmp));
		else
			zlog_debug("    PCE neighbor Area: %s", inet_ntoa(tmp));
	} else {
		if (vty != NULL)
			vty_out(vty, "  PCE neighbor AS: %d\n",
				ntohl(top->value));
		else
			zlog_debug("    PCE neighbor AS: %d",
				   ntohl(top->value));
	}
	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_pce_subtlv_cap_flag(struct vty *vty,
					     struct tlv_header *tlvh)
{
	struct ri_pce_subtlv_cap_flag *top =
		(struct ri_pce_subtlv_cap_flag *)tlvh;

	if (vty != NULL)
		vty_out(vty, "  PCE Capabilities Flag: 0x%x\n",
			ntohl(top->value));
	else
		zlog_debug("    PCE Capabilities Flag: 0x%x",
			   ntohl(top->value));

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_unknown_tlv(struct vty *vty, struct tlv_header *tlvh)
{
	if (vty != NULL)
		vty_out(vty, "  Unknown TLV: [type(0x%x), length(0x%x)]\n",
			ntohs(tlvh->type), ntohs(tlvh->length));
	else
		zlog_debug("    Unknown TLV: [type(0x%x), length(0x%x)]",
			   ntohs(tlvh->type), ntohs(tlvh->length));

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_pce_info(struct vty *vty, struct tlv_header *ri,
				  uint32_t total)
{
	struct tlv_header *tlvh;
	uint16_t sum = 0;

	for (tlvh = ri; sum < total; tlvh = TLV_HDR_NEXT(tlvh)) {
		switch (ntohs(tlvh->type)) {
		case RI_PCE_SUBTLV_ADDRESS:
			sum += show_vty_pce_subtlv_address(vty, tlvh);
			break;
		case RI_PCE_SUBTLV_PATH_SCOPE:
			sum += show_vty_pce_subtlv_path_scope(vty, tlvh);
			break;
		case RI_PCE_SUBTLV_DOMAIN:
			sum += show_vty_pce_subtlv_domain(vty, tlvh);
			break;
		case RI_PCE_SUBTLV_NEIGHBOR:
			sum += show_vty_pce_subtlv_neighbor(vty, tlvh);
			break;
		case RI_PCE_SUBTLV_CAP_FLAG:
			sum += show_vty_pce_subtlv_cap_flag(vty, tlvh);
			break;
		default:
			sum += show_vty_unknown_tlv(vty, tlvh);
			break;
		}
	}
	return sum;
}

/* Display Segment Routing Algorithm TLV information */
static uint16_t show_vty_sr_algorithm(struct vty *vty, struct tlv_header *tlvh)
{
	struct ri_sr_tlv_sr_algorithm *algo =
		(struct ri_sr_tlv_sr_algorithm *)tlvh;
	int i;

	if (vty != NULL) {
		vty_out(vty, "  Segment Routing Algorithm TLV:\n");
		for (i = 0; i < ntohs(algo->header.length); i++) {
			switch (algo->value[i]) {
			case 0:
				vty_out(vty, "    Algorithm %d: SPF\n", i);
				break;
			case 1:
				vty_out(vty, "    Algorithm %d: Strict SPF\n",
					i);
				break;
			default:
				vty_out(vty,
					"  Algorithm %d: Unknown value %d\n", i,
					algo->value[i]);
				break;
			}
		}
	}

	else {
		zlog_debug("  Segment Routing Algorithm TLV:\n");
		for (i = 0; i < ntohs(algo->header.length); i++)
			switch (algo->value[i]) {
			case 0:
				zlog_debug("    Algorithm %d: SPF\n", i);
				break;
			case 1:
				zlog_debug("    Algorithm %d: Strict SPF\n", i);
				break;
			default:
				zlog_debug(
					"    Algorithm %d: Unknown value %d\n",
					i, algo->value[i]);
				break;
			}
	}

	return TLV_SIZE(tlvh);
}

/* Display Segment Routing SID/Label Range TLV information */
static uint16_t show_vty_sr_range(struct vty *vty, struct tlv_header *tlvh)
{
	struct ri_sr_tlv_sid_label_range *range =
		(struct ri_sr_tlv_sid_label_range *)tlvh;

	if (vty != NULL) {
		vty_out(vty,
			"  Segment Routing Range TLV:\n"
			"    Range Size = %d\n"
			"    SID Label = %d\n\n",
			GET_RANGE_SIZE(ntohl(range->size)),
			GET_LABEL(ntohl(range->lower.value)));
	} else {
		zlog_debug(
			"  Segment Routing Range TLV:\n"
			"    Range Size = %d\n"
			"    SID Label = %d\n\n",
			GET_RANGE_SIZE(ntohl(range->size)),
			GET_LABEL(ntohl(range->lower.value)));
	}

	return TLV_SIZE(tlvh);
}

/* Display Segment Routing Maximum Stack Depth TLV information */
static uint16_t show_vty_sr_msd(struct vty *vty, struct tlv_header *tlvh)
{
	struct ri_sr_tlv_node_msd *msd = (struct ri_sr_tlv_node_msd *)tlvh;

	if (vty != NULL) {
		vty_out(vty,
			"  Segment Routing MSD TLV:\n"
			"    Node Maximum Stack Depth = %d\n",
			msd->value);
	} else {
		zlog_debug(
			"  Segment Routing MSD TLV:\n"
			"    Node Maximum Stack Depth = %d\n",
			msd->value);
	}

	return TLV_SIZE(tlvh);
}

static void ospf_router_info_show_info(struct vty *vty, struct ospf_lsa *lsa)
{
	struct lsa_header *lsah = (struct lsa_header *)lsa->data;
	struct tlv_header *tlvh;
	uint16_t length = 0, sum = 0;

	/* Initialize TLV browsing */
	length = ntohs(lsah->length) - OSPF_LSA_HEADER_SIZE;

	for (tlvh = TLV_HDR_TOP(lsah); sum < length;
	     tlvh = TLV_HDR_NEXT(tlvh)) {
		switch (ntohs(tlvh->type)) {
		case RI_TLV_CAPABILITIES:
			sum += show_vty_router_cap(vty, tlvh);
			break;
		case RI_TLV_PCE:
			tlvh++;
			sum += TLV_HDR_SIZE;
			sum += show_vty_pce_info(vty, tlvh, length - sum);
			break;
		case RI_SR_TLV_SR_ALGORITHM:
			sum += show_vty_sr_algorithm(vty, tlvh);
			break;
		case RI_SR_TLV_SID_LABEL_RANGE:
			sum += show_vty_sr_range(vty, tlvh);
			break;
		case RI_SR_TLV_NODE_MSD:
			sum += show_vty_sr_msd(vty, tlvh);
			break;

		default:
			sum += show_vty_unknown_tlv(vty, tlvh);
			break;
		}
	}

	return;
}

static void ospf_router_info_config_write_router(struct vty *vty)
{
	struct ospf_pce_info *pce = &OspfRI.pce_info;
	struct listnode *node;
	struct ri_pce_subtlv_domain *domain;
	struct ri_pce_subtlv_neighbor *neighbor;
	struct in_addr tmp;

	if (!OspfRI.enabled)
		return;

	if (OspfRI.scope == OSPF_OPAQUE_AS_LSA)
		vty_out(vty, " router-info as\n");
	else
		vty_out(vty, " router-info area %s\n",
			inet_ntoa(OspfRI.area_id));

	if (OspfRI.pce_info.enabled) {

		if (pce->pce_address.header.type != 0)
			vty_out(vty, "  pce address %s\n",
				inet_ntoa(pce->pce_address.address.value));

		if (pce->pce_cap_flag.header.type != 0)
			vty_out(vty, "  pce flag 0x%x\n",
				ntohl(pce->pce_cap_flag.value));

		for (ALL_LIST_ELEMENTS_RO(pce->pce_domain, node, domain)) {
			if (domain->header.type != 0) {
				if (domain->type == PCE_DOMAIN_TYPE_AREA) {
					tmp.s_addr = domain->value;
					vty_out(vty, "  pce domain area %s\n",
						inet_ntoa(tmp));
				} else {
					vty_out(vty, "  pce domain as %d\n",
						ntohl(domain->value));
				}
			}
		}

		for (ALL_LIST_ELEMENTS_RO(pce->pce_neighbor, node, neighbor)) {
			if (neighbor->header.type != 0) {
				if (neighbor->type == PCE_DOMAIN_TYPE_AREA) {
					tmp.s_addr = neighbor->value;
					vty_out(vty, "  pce neighbor area %s\n",
						inet_ntoa(tmp));
				} else {
					vty_out(vty, "  pce neighbor as %d\n",
						ntohl(neighbor->value));
				}
			}
		}

		if (pce->pce_scope.header.type != 0)
			vty_out(vty, "  pce scope 0x%x\n",
				ntohl(OspfRI.pce_info.pce_scope.value));
	}
	return;
}

/*------------------------------------------------------------------------*
 * Followings are vty command functions.
 *------------------------------------------------------------------------*/

DEFUN (router_info,
       router_info_area_cmd,
       "router-info <as|area A.B.C.D>",
       OSPF_RI_STR
       "Enable the Router Information functionality with AS flooding scope\n"
       "Enable the Router Information functionality with Area flooding scope\n"
       "OSPF area ID in IP format\n")
{
	int idx_ipv4 = 2;
	char *area = (argc == 3) ? argv[idx_ipv4]->arg : NULL;

	uint8_t scope;

	if (OspfRI.enabled)
		return CMD_SUCCESS;

	/* Check and get Area value if present */
	if (area) {
		if (!inet_aton(area, &OspfRI.area_id)) {
			vty_out(vty, "%% specified Area ID %s is invalid\n",
				area);
			return CMD_WARNING_CONFIG_FAILED;
		}
		scope = OSPF_OPAQUE_AREA_LSA;
	} else {
		OspfRI.area_id.s_addr = 0;
		scope = OSPF_OPAQUE_AS_LSA;
	}

	/* First start to register Router Information callbacks */
	if ((ospf_router_info_register(scope)) != 0) {
		zlog_warn(
			"Unable to register Router Information callbacks. Abort!");
		return CMD_WARNING_CONFIG_FAILED;
	}

	OspfRI.enabled = true;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("RI-> Router Information (%s flooding): OFF -> ON",
			   OspfRI.scope == OSPF_OPAQUE_AREA_LSA ? "Area"
								: "AS");

	/*
	 * Following code is intended to handle two cases;
	 *
	 * 1) Router Information was disabled at startup time, but now become
	 * enabled.
	 * 2) Router Information was once enabled then disabled, and now enabled
	 * again.
	 */

	initialize_params(&OspfRI);

	/* Refresh RI LSA if already engaged */
	if (CHECK_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED)) {
		zlog_debug("RI-> Refresh LSA following configuration");
		ospf_router_info_lsa_schedule(REFRESH_THIS_LSA);
	} else {
		zlog_debug("RI-> Initial origination following configuration");
		ospf_router_info_lsa_schedule(REORIGINATE_THIS_LSA);
	}
	return CMD_SUCCESS;
}


DEFUN (no_router_info,
       no_router_info_cmd,
       "no router-info",
       NO_STR
       "Disable the Router Information functionality\n")
{

	if (!OspfRI.enabled)
		return CMD_SUCCESS;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("RI-> Router Information: ON -> OFF");

	if (CHECK_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED))
		ospf_router_info_lsa_schedule(FLUSH_THIS_LSA);

	OspfRI.enabled = false;

	return CMD_SUCCESS;
}

static int ospf_ri_enabled(struct vty *vty)
{
	if (OspfRI.enabled)
		return 1;

	if (vty)
		vty_out(vty, "%% OSPF RI is not turned on\n");

	return 0;
}

DEFUN (pce_address,
       pce_address_cmd,
       "pce address A.B.C.D",
       PCE_STR
       "Stable IP address of the PCE\n"
       "PCE address in IPv4 address format\n")
{
	int idx_ipv4 = 2;
	struct in_addr value;
	struct ospf_pce_info *pi = &OspfRI.pce_info;

	if (!ospf_ri_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	if (!inet_aton(argv[idx_ipv4]->arg, &value)) {
		vty_out(vty, "Please specify PCE Address by A.B.C.D\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (ntohs(pi->pce_address.header.type) == 0
	    || ntohl(pi->pce_address.address.value.s_addr)
		       != ntohl(value.s_addr)) {

		set_pce_address(value, pi);

		/* Refresh RI LSA if already engaged */
		if (CHECK_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED))
			ospf_router_info_lsa_schedule(REFRESH_THIS_LSA);
	}

	return CMD_SUCCESS;
}

DEFUN (no_pce_address,
       no_pce_address_cmd,
       "no pce address [A.B.C.D]",
       NO_STR
       PCE_STR
       "Disable PCE address\n"
       "PCE address in IPv4 address format\n")
{

	unset_param(&OspfRI.pce_info.pce_address);

	/* Refresh RI LSA if already engaged */
	if (CHECK_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED))
		ospf_router_info_lsa_schedule(REFRESH_THIS_LSA);

	return CMD_SUCCESS;
}

DEFUN (pce_path_scope,
       pce_path_scope_cmd,
       "pce scope BITPATTERN",
       PCE_STR
       "Path scope visibilities of the PCE for path computation\n"
       "32-bit Hexadecimal value\n")
{
	int idx_bitpattern = 2;
	uint32_t scope;
	struct ospf_pce_info *pi = &OspfRI.pce_info;

	if (!ospf_ri_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	if (sscanf(argv[idx_bitpattern]->arg, "0x%x", &scope) != 1) {
		vty_out(vty, "pce_path_scope: fscanf: %s\n",
			safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (ntohl(pi->pce_scope.header.type) == 0
	    || scope != pi->pce_scope.value) {
		set_pce_path_scope(scope, pi);

		/* Refresh RI LSA if already engaged */
		if (CHECK_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED))
			ospf_router_info_lsa_schedule(REFRESH_THIS_LSA);
	}

	return CMD_SUCCESS;
}

DEFUN (no_pce_path_scope,
       no_pce_path_scope_cmd,
       "no pce scope [BITPATTERN]",
       NO_STR
       PCE_STR
       "Disable PCE path scope\n"
       "32-bit Hexadecimal value\n")
{

	unset_param(&OspfRI.pce_info.pce_address);

	/* Refresh RI LSA if already engaged */
	if (CHECK_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED))
		ospf_router_info_lsa_schedule(REFRESH_THIS_LSA);

	return CMD_SUCCESS;
}

DEFUN (pce_domain,
       pce_domain_cmd,
       "pce domain as (0-65535)",
       PCE_STR
       "Configure PCE domain AS number\n"
       "AS number where the PCE as visibilities for path computation\n"
       "AS number in decimal <0-65535>\n")
{
	int idx_number = 3;

	uint32_t as;
	struct ospf_pce_info *pce = &OspfRI.pce_info;
	struct listnode *node;
	struct ri_pce_subtlv_domain *domain;

	if (!ospf_ri_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	if (sscanf(argv[idx_number]->arg, "%" SCNu32, &as) != 1) {
		vty_out(vty, "pce_domain: fscanf: %s\n", safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Check if the domain is not already in the domain list */
	for (ALL_LIST_ELEMENTS_RO(pce->pce_domain, node, domain)) {
		if (ntohl(domain->header.type) == 0 && as == domain->value)
			return CMD_SUCCESS;
	}

	/* Create new domain if not found */
	set_pce_domain(PCE_DOMAIN_TYPE_AS, as, pce);

	/* Refresh RI LSA if already engaged */
	if (CHECK_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED))
		ospf_router_info_lsa_schedule(REFRESH_THIS_LSA);

	return CMD_SUCCESS;
}

DEFUN (no_pce_domain,
       no_pce_domain_cmd,
       "no pce domain as (0-65535)",
       NO_STR
       PCE_STR
       "Disable PCE domain AS number\n"
       "AS number where the PCE as visibilities for path computation\n"
       "AS number in decimal <0-65535>\n")
{
	int idx_number = 4;

	uint32_t as;
	struct ospf_pce_info *pce = &OspfRI.pce_info;

	if (sscanf(argv[idx_number]->arg, "%" SCNu32, &as) != 1) {
		vty_out(vty, "no_pce_domain: fscanf: %s\n",
			safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Unset corresponding PCE domain */
	unset_pce_domain(PCE_DOMAIN_TYPE_AS, as, pce);

	/* Refresh RI LSA if already engaged */
	if (CHECK_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED))
		ospf_router_info_lsa_schedule(REFRESH_THIS_LSA);

	return CMD_SUCCESS;
}

DEFUN (pce_neigbhor,
       pce_neighbor_cmd,
       "pce neighbor as (0-65535)",
       PCE_STR
       "Configure PCE neighbor domain AS number\n"
       "AS number of PCE neighbors\n"
       "AS number in decimal <0-65535>\n")
{
	int idx_number = 3;

	uint32_t as;
	struct ospf_pce_info *pce = &OspfRI.pce_info;
	struct listnode *node;
	struct ri_pce_subtlv_neighbor *neighbor;

	if (!ospf_ri_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	if (sscanf(argv[idx_number]->arg, "%" SCNu32, &as) != 1) {
		vty_out(vty, "pce_neighbor: fscanf: %s\n",
			safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Check if the domain is not already in the domain list */
	for (ALL_LIST_ELEMENTS_RO(pce->pce_neighbor, node, neighbor)) {
		if (ntohl(neighbor->header.type) == 0 && as == neighbor->value)
			return CMD_SUCCESS;
	}

	/* Create new domain if not found */
	set_pce_neighbor(PCE_DOMAIN_TYPE_AS, as, pce);

	/* Refresh RI LSA if already engaged */
	if (CHECK_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED))
		ospf_router_info_lsa_schedule(REFRESH_THIS_LSA);

	return CMD_SUCCESS;
}

DEFUN (no_pce_neighbor,
       no_pce_neighbor_cmd,
       "no pce neighbor as (0-65535)",
       NO_STR
       PCE_STR
       "Disable PCE neighbor AS number\n"
       "AS number of PCE neighbor\n"
       "AS number in decimal <0-65535>\n")
{
	int idx_number = 4;

	uint32_t as;
	struct ospf_pce_info *pce = &OspfRI.pce_info;

	if (sscanf(argv[idx_number]->arg, "%" SCNu32, &as) != 1) {
		vty_out(vty, "no_pce_neighbor: fscanf: %s\n",
			safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Unset corresponding PCE domain */
	unset_pce_neighbor(PCE_DOMAIN_TYPE_AS, as, pce);

	/* Refresh RI LSA if already engaged */
	if (CHECK_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED))
		ospf_router_info_lsa_schedule(REFRESH_THIS_LSA);

	return CMD_SUCCESS;
}

DEFUN (pce_cap_flag,
       pce_cap_flag_cmd,
       "pce flag BITPATTERN",
       PCE_STR
       "Capabilities of the PCE for path computation\n"
       "32-bit Hexadecimal value\n")
{
	int idx_bitpattern = 2;

	uint32_t cap;
	struct ospf_pce_info *pce = &OspfRI.pce_info;

	if (!ospf_ri_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	if (sscanf(argv[idx_bitpattern]->arg, "0x%x", &cap) != 1) {
		vty_out(vty, "pce_cap_flag: fscanf: %s\n",
			safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (ntohl(pce->pce_cap_flag.header.type) == 0
	    || cap != pce->pce_cap_flag.value) {
		set_pce_cap_flag(cap, pce);

		/* Refresh RI LSA if already engaged */
		if (CHECK_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED))
			ospf_router_info_lsa_schedule(REFRESH_THIS_LSA);
	}

	return CMD_SUCCESS;
}

DEFUN (no_pce_cap_flag,
       no_pce_cap_flag_cmd,
       "no pce flag",
       NO_STR
       PCE_STR
       "Disable PCE capabilities\n")
{

	unset_param(&OspfRI.pce_info.pce_cap_flag);

	/* Refresh RI LSA if already engaged */
	if (CHECK_FLAG(OspfRI.flags, RIFLG_LSA_ENGAGED))
		ospf_router_info_lsa_schedule(REFRESH_THIS_LSA);

	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_router_info,
       show_ip_ospf_router_info_cmd,
       "show ip ospf router-info",
       SHOW_STR
       IP_STR
       OSPF_STR
       "Router Information\n")
{

	if (OspfRI.enabled) {
		vty_out(vty, "--- Router Information parameters ---\n");
		show_vty_router_cap(vty, &OspfRI.router_cap.header);
	} else {
		if (vty != NULL)
			vty_out(vty,
				"  Router Information is disabled on this router\n");
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_opsf_router_info_pce,
       show_ip_ospf_router_info_pce_cmd,
       "show ip ospf router-info pce",
       SHOW_STR
       IP_STR
       OSPF_STR
       "Router Information\n"
       "PCE information\n")
{

	struct ospf_pce_info *pce = &OspfRI.pce_info;
	struct listnode *node;
	struct ri_pce_subtlv_domain *domain;
	struct ri_pce_subtlv_neighbor *neighbor;

	if ((OspfRI.enabled) && (OspfRI.pce_info.enabled)) {
		vty_out(vty, "--- PCE parameters ---\n");

		if (pce->pce_address.header.type != 0)
			show_vty_pce_subtlv_address(vty,
						    &pce->pce_address.header);

		if (pce->pce_scope.header.type != 0)
			show_vty_pce_subtlv_path_scope(vty,
						       &pce->pce_scope.header);

		for (ALL_LIST_ELEMENTS_RO(pce->pce_domain, node, domain)) {
			if (domain->header.type != 0)
				show_vty_pce_subtlv_domain(vty,
							   &domain->header);
		}

		for (ALL_LIST_ELEMENTS_RO(pce->pce_neighbor, node, neighbor)) {
			if (neighbor->header.type != 0)
				show_vty_pce_subtlv_neighbor(vty,
							     &neighbor->header);
		}

		if (pce->pce_cap_flag.header.type != 0)
			show_vty_pce_subtlv_cap_flag(vty,
						     &pce->pce_cap_flag.header);

	} else {
		vty_out(vty, "  PCE info is disabled on this router\n");
	}

	return CMD_SUCCESS;
}

/* Install new CLI commands */
static void ospf_router_info_register_vty(void)
{
	install_element(VIEW_NODE, &show_ip_ospf_router_info_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_router_info_pce_cmd);

	install_element(OSPF_NODE, &router_info_area_cmd);
	install_element(OSPF_NODE, &no_router_info_cmd);
	install_element(OSPF_NODE, &pce_address_cmd);
	install_element(OSPF_NODE, &no_pce_address_cmd);
	install_element(OSPF_NODE, &pce_path_scope_cmd);
	install_element(OSPF_NODE, &no_pce_path_scope_cmd);
	install_element(OSPF_NODE, &pce_domain_cmd);
	install_element(OSPF_NODE, &no_pce_domain_cmd);
	install_element(OSPF_NODE, &pce_neighbor_cmd);
	install_element(OSPF_NODE, &no_pce_neighbor_cmd);
	install_element(OSPF_NODE, &pce_cap_flag_cmd);
	install_element(OSPF_NODE, &no_pce_cap_flag_cmd);

	return;
}
