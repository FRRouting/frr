// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This is an implementation of RFC4970 Router Information
 * with support of RFC5088 PCE Capabilites announcement
 *
 * Module name: Router Information
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 * Copyright (C) 2012 - 2017 Orange Labs http://www.orange.com/
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
#include "frrevent.h"
#include "hash.h"
#include "sockunion.h" /* for inet_aton() */
#include "mpls.h"
#include "affinitymap.h"
#include "segment_routing.h"

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
#include "ospfd/ospf_errors.h"
#ifndef VTYSH_EXTRACT_PL
#include "ospfd/ospf_ri_clippy.c"
#endif

/*
 * Global variable to manage Opaque-LSA/Router Information on this node.
 * Note that all parameter values are stored in network byte order.
 */
struct ospf_router_info OspfRI;

/*------------------------------------------------------------------------------*
 * Following are initialize/terminate functions for Router Information
 *handling.
 *------------------------------------------------------------------------------*/

static void ospf_router_info_ism_change(struct ospf_interface *oi,
					int old_status);
static void ospf_router_info_config_write_router(struct vty *vty);
static void ospf_router_info_show_info(struct vty *vty,
				       struct json_object *json,
				       struct ospf_lsa *lsa);
static int ospf_router_info_lsa_originate(void *arg);
static struct ospf_lsa *ospf_router_info_lsa_refresh(struct ospf_lsa *lsa);
static void ospf_router_info_lsa_schedule(struct ospf_ri_area_info *ai,
					  enum lsa_opcode opcode);
static void ospf_router_info_register_vty(void);
static int ospf_router_info_lsa_update(struct ospf_lsa *lsa);
static void del_area_info(void *val);
static void del_pce_info(void *val);
static void flush_ri_fad_tlvs(void);

int ospf_router_info_init(void)
{

	zlog_info("RI (%s): Initialize Router Information", __func__);

	memset(&OspfRI, 0, sizeof(OspfRI));
	OspfRI.enabled = false;
	OspfRI.registered = 0;
	OspfRI.scope = OSPF_OPAQUE_AS_LSA;
	OspfRI.as_flags = RIFLG_LSA_INACTIVE;
	OspfRI.area_info = list_new();
	OspfRI.area_info->del = del_area_info;

	/* Initialize pce domain and neighbor list */
	OspfRI.pce_info.enabled = false;
	OspfRI.pce_info.pce_domain = list_new();
	OspfRI.pce_info.pce_domain->del = del_pce_info;
	OspfRI.pce_info.pce_neighbor = list_new();
	OspfRI.pce_info.pce_neighbor->del = del_pce_info;

	/* Initialize Segment Routing information structure */
	OspfRI.sr_info.enabled = false;

	/* Initialize the Flex-Algo database */
	OspfRI.fad_info.fads = flex_algos_alloc(NULL, NULL);
	tlv_list_init(&OspfRI.fad_info.ri_fad_tlvs);

	ospf_router_info_register_vty();

	return 0;
}

static int ospf_router_info_register(uint8_t scope)
{
	int rc = 0;

	if (OspfRI.registered)
		return rc;

	zlog_info("RI (%s): Register Router Information with scope %s(%d)",
		  __func__,
		  scope == OSPF_OPAQUE_AREA_LSA ? "Area" : "AS", scope);
	rc = ospf_register_opaque_functab(
		scope, OPAQUE_TYPE_ROUTER_INFORMATION_LSA,
		NULL, /* new interface */
		NULL, /* del interface */
		ospf_router_info_ism_change,
		NULL, /* NSM change */
		ospf_router_info_config_write_router,
		NULL, /* Config. write interface */
		NULL, /* Config. write debug */
		ospf_router_info_show_info, ospf_router_info_lsa_originate,
		ospf_router_info_lsa_refresh, ospf_router_info_lsa_update,
		NULL); /* del_lsa_hook */

	if (rc != 0) {
		flog_warn(
			EC_OSPF_OPAQUE_REGISTRATION,
			"RI (%s): Failed to register functions", __func__);
		return rc;
	}

	OspfRI.registered = 1;
	OspfRI.scope = scope;
	return rc;
}

static int ospf_router_info_unregister(void)
{

	if ((OspfRI.scope != OSPF_OPAQUE_AS_LSA)
	    && (OspfRI.scope != OSPF_OPAQUE_AREA_LSA)) {
		assert("Unable to unregister Router Info functions: Wrong scope!"
		       == NULL);
		return -1;
	}

	ospf_delete_opaque_functab(OspfRI.scope,
				   OPAQUE_TYPE_ROUTER_INFORMATION_LSA);

	OspfRI.registered = 0;
	return 0;
}

void ospf_router_info_term(void)
{

	list_delete(&OspfRI.area_info);
	list_delete(&OspfRI.pce_info.pce_domain);
	list_delete(&OspfRI.pce_info.pce_neighbor);
	flush_ri_fad_tlvs();
	if (OspfRI.enabled && OspfRI.fad_info.fads) {
		flex_algos_free(OspfRI.fad_info.fads);
		OspfRI.fad_info.fads = NULL;
	}

	OspfRI.enabled = false;

	ospf_router_info_unregister();

	return;
}

void ospf_router_info_finish(void)
{
	struct listnode *node, *nnode;
	struct ospf_ri_area_info *ai;

	/* Flush Router Info LSA */
	for (ALL_LIST_ELEMENTS(OspfRI.area_info, node, nnode, ai))
		if (CHECK_FLAG(ai->flags, RIFLG_LSA_ENGAGED))
			ospf_router_info_lsa_schedule(ai, FLUSH_THIS_LSA);

	list_delete_all_node(OspfRI.pce_info.pce_domain);
	list_delete_all_node(OspfRI.pce_info.pce_neighbor);
	flush_ri_fad_tlvs();
	if (OspfRI.enabled && OspfRI.fad_info.fads) {
		flex_algos_free(OspfRI.fad_info.fads);
		OspfRI.fad_info.fads = NULL;
	}

	OspfRI.enabled = false;
}

static void del_area_info(void *val)
{
	XFREE(MTYPE_OSPF_ROUTER_INFO, val);
}

static void del_pce_info(void *val)
{
	XFREE(MTYPE_OSPF_PCE_PARAMS, val);
}

/* Catch RI LSA flooding Scope for ospf_ext.[h,c] code */
struct scope_info ospf_router_info_get_flooding_scope(void)
{
	struct scope_info flooding_scope;

	if (OspfRI.scope == OSPF_OPAQUE_AS_LSA) {
		flooding_scope.scope = OSPF_OPAQUE_AS_LSA;
		flooding_scope.areas = NULL;
		return flooding_scope;
	}
	flooding_scope.scope = OSPF_OPAQUE_AREA_LSA;
	flooding_scope.areas = OspfRI.area_info;
	return flooding_scope;
}

static struct ospf_ri_area_info *lookup_by_area(struct ospf_area *area)
{
	struct listnode *node, *nnode;
	struct ospf_ri_area_info *ai;

	for (ALL_LIST_ELEMENTS(OspfRI.area_info, node, nnode, ai))
		if (ai->area == area)
			return ai;

	return NULL;
}

/*------------------------------------------------------------------------*
 * Following are control functions for ROUTER INFORMATION parameters
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
	pce->pce_address.header.length = htons(PCE_ADDRESS_IPV4_SIZE);
	pce->pce_address.address.type = htons(PCE_ADDRESS_IPV4);
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
	new->header.length = htons(PCE_ADDRESS_IPV4_SIZE);
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
	new->header.length = htons(PCE_ADDRESS_IPV4_SIZE);
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

/* Set Segment Routing Global Block SubTLV - section 3.2 */
static void set_sr_global_label_range(struct sr_block srgb)
{
	/* Set Header */
	TLV_TYPE(OspfRI.sr_info.srgb) = htons(RI_SR_TLV_SRGB_LABEL_RANGE);
	TLV_LEN(OspfRI.sr_info.srgb) = htons(RI_SR_TLV_LABEL_RANGE_SIZE);
	/* Set Range Size */
	OspfRI.sr_info.srgb.size = htonl(SET_RANGE_SIZE(srgb.range_size));
	/* Set Lower bound label SubTLV */
	TLV_TYPE(OspfRI.sr_info.srgb.lower) = htons(SUBTLV_SID_LABEL);
	TLV_LEN(OspfRI.sr_info.srgb.lower) = htons(SID_RANGE_LABEL_LENGTH);
	OspfRI.sr_info.srgb.lower.value = htonl(SET_LABEL(srgb.lower_bound));
}

/* Unset Segment Routing Global Block SubTLV */
static void unset_sr_global_label_range(void)
{
	TLV_TYPE(OspfRI.sr_info.srgb) = htons(0);
	TLV_LEN(OspfRI.sr_info.srgb) = htons(0);
	TLV_TYPE(OspfRI.sr_info.srgb.lower) = htons(0);
	TLV_LEN(OspfRI.sr_info.srgb.lower) = htons(0);
}

/* Set Segment Routing Local Block SubTLV - section 3.2 */
static void set_sr_local_label_range(struct sr_block srlb)
{
	/* Set Header */
	TLV_TYPE(OspfRI.sr_info.srlb) = htons(RI_SR_TLV_SRLB_LABEL_RANGE);
	TLV_LEN(OspfRI.sr_info.srlb) = htons(RI_SR_TLV_LABEL_RANGE_SIZE);
	/* Set Range Size */
	OspfRI.sr_info.srlb.size = htonl(SET_RANGE_SIZE(srlb.range_size));
	/* Set Lower bound label SubTLV */
	TLV_TYPE(OspfRI.sr_info.srlb.lower) = htons(SUBTLV_SID_LABEL);
	TLV_LEN(OspfRI.sr_info.srlb.lower) = htons(SID_RANGE_LABEL_LENGTH);
	OspfRI.sr_info.srlb.lower.value = htonl(SET_LABEL(srlb.lower_bound));
}

/* Unset Segment Routing Local Block SubTLV */
static void unset_sr_local_label_range(void)
{
	TLV_TYPE(OspfRI.sr_info.srlb) = htons(0);
	TLV_LEN(OspfRI.sr_info.srlb) = htons(0);
	TLV_TYPE(OspfRI.sr_info.srlb.lower) = htons(0);
	TLV_LEN(OspfRI.sr_info.srlb.lower) = htons(0);
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
	struct listnode *node, *nnode;
	struct ospf_area *area;
	struct ospf_ri_area_info *new;

	/*
	 * Initialize default Router Information Capabilities.
	 */
	cap = RI_TE_SUPPORT;

	set_router_info_capabilities(&ori->router_cap, cap);

	/* If Area address is not null and exist, retrieve corresponding
	 * structure */
	top = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	zlog_info("RI (%s): Initialize Router Info for %s scope", __func__,
		  OspfRI.scope == OSPF_OPAQUE_AREA_LSA ? "Area" : "AS");

	/* Try to get available Area's context from ospf at this step.
	 * Do it latter if not available */
	if (OspfRI.scope == OSPF_OPAQUE_AREA_LSA) {
		if (!list_isempty(OspfRI.area_info))
			list_delete_all_node(OspfRI.area_info);
		for (ALL_LIST_ELEMENTS(top->areas, node, nnode, area)) {
			zlog_debug("RI (%s): Add area %pI4 to Router Information",
				__func__, &area->area_id);
			new = XCALLOC(MTYPE_OSPF_ROUTER_INFO,
				sizeof(struct ospf_ri_area_info));
			new->area = area;
			new->flags = RIFLG_LSA_INACTIVE;
			listnode_add(OspfRI.area_info, new);
		}
	}

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

static int is_mandated_params_set(struct ospf_router_info *ori)
{
	int rc = 0;

	if (ori == NULL)
		return rc;

	if (ntohs(ori->router_cap.header.type) == 0)
		return rc;

	if ((ntohs(ori->pce_info.pce_header.header.type) == RI_TLV_PCE)
	    && (ntohs(ori->pce_info.pce_address.header.type) == 0)
	    && (ntohs(ori->pce_info.pce_cap_flag.header.type) == 0))
		return rc;

	if ((ori->sr_info.enabled) && (ntohs(TLV_TYPE(ori->sr_info.algo)) == 0)
	    && (ntohs(TLV_TYPE(ori->sr_info.srgb)) == 0))
		return rc;

	rc = 1;

	return rc;
}

/*
 * Used by Segment Routing to set new TLVs and Sub-TLVs values
 *
 * @param enable To activate or not Segment Routing router Information flooding
 * @param srn    Self Segment Routing node
 *
 * @return none
 */
void ospf_router_info_update_sr(bool enable, struct sr_node *srn)
{
	struct listnode *node, *nnode;
	struct ospf_ri_area_info *ai;

	/* First, check if Router Information is registered or not */
	if (!OspfRI.registered)
		ospf_router_info_register(OSPF_OPAQUE_AREA_LSA);

	/* Verify that scope is AREA */
	if (OspfRI.scope != OSPF_OPAQUE_AREA_LSA) {
		zlog_err(
			"RI (%s): Router Info is %s flooding: Change scope to Area flooding for Segment Routing",
			__func__,
			OspfRI.scope == OSPF_OPAQUE_AREA_LSA ? "Area" : "AS");
		return;
	}

	/* Then, activate and initialize Router Information if necessary */
	if (!OspfRI.enabled) {
		OspfRI.enabled = true;
		initialize_params(&OspfRI);
	}

	/* Check that SR node is valid */
	if (srn == NULL)
		return;

	if (IS_DEBUG_OSPF_SR)
		zlog_debug("RI (%s): %s Routing Information for Segment Routing",
			   __func__, enable ? "Enable" : "Disable");

	/* Unset or Set SR parameters */
	if (!enable) {
		unset_sr_algorithm(SR_ALGORITHM_SPF);
		unset_sr_global_label_range();
		unset_sr_local_label_range();
		unset_sr_node_msd();
		OspfRI.sr_info.enabled = false;
	} else {
		// Only SR_ALGORITHM_SPF is supported
		set_sr_algorithm(SR_ALGORITHM_SPF);
		set_sr_global_label_range(srn->srgb);
		set_sr_local_label_range(srn->srlb);
		if (srn->msd != 0)
			set_sr_node_msd(srn->msd);
		else
			unset_sr_node_msd();
		OspfRI.sr_info.enabled = true;
	}

	/* Refresh if already engaged or originate RI LSA */
	for (ALL_LIST_ELEMENTS(OspfRI.area_info, node, nnode, ai)) {
		if (CHECK_FLAG(ai->flags, RIFLG_LSA_ENGAGED))
			ospf_router_info_lsa_schedule(ai, REFRESH_THIS_LSA);
		else
			ospf_router_info_lsa_schedule(ai,
				REORIGINATE_THIS_LSA);

	}
}

static void flush_ri_fad_subtlvs(struct ri_fad_tlv *fad_tlv)
{
	struct tlv *subtlv;

	FOREACH_TLV_IN_LIST (&fad_tlv->sub_tlvs, subtlv) {
		tlv_list_del(&fad_tlv->sub_tlvs, subtlv);

		switch (ntohs(subtlv->hdr.type)) {
		case RI_FAD_EXC_ADMINGRP_SUBTLV:
			/* SubTLV-specific cleanup */
			XFREE(MTYPE_OSPF_RI_FAD_EXC_ADMNGRP_SUBTLV, subtlv);
			break;
		case RI_FAD_INCANY_ADMINGRP_SUBTLV:
			/* SubTLV-specific cleanup */
			XFREE(MTYPE_OSPF_RI_FAD_INCANY_ADMNGRP_SUBTLV, subtlv);
			break;
		case RI_FAD_INCALL_ADMINGRP_SUBTLV:
			/* SubTLV-specific cleanup */
			XFREE(MTYPE_OSPF_RI_FAD_INCALL_ADMNGRP_SUBTLV, subtlv);
			break;
		case RI_FAD_FLAGS_SUBTLV:
			/* SubTLV-specific cleanup */
			XFREE(MTYPE_OSPF_RI_FAD_FLAGS_SUBTLV, subtlv);
			break;
		case RI_FAD_EXC_SRLG_SUBTLV:
			/* SubTLV-specific cleanup */
			XFREE(MTYPE_OSPF_RI_FAD_EXC_SRLG_SUBTLV, subtlv);
			break;
		default:
			break;
		}
	}

	tlv_list_fini(&fad_tlv->sub_tlvs);
}

static void flush_ri_fad_tlvs(void)
{
	struct tlv *tlv;
	struct ri_fad_tlv *fad_tlv;

	if (OspfRI.fad_info.num_fads) {
		FOREACH_TLV_IN_LIST (&OspfRI.fad_info.ri_fad_tlvs, tlv) {
			fad_tlv = (struct ri_fad_tlv *)&tlv->hdr;
			flush_ri_fad_subtlvs(fad_tlv);
			tlv_list_del(&OspfRI.fad_info.ri_fad_tlvs, tlv);
			XFREE(MTYPE_OSPF_RI_FAD_TLV, tlv);
		}
	}
}

static void update_ri_fad_tlv(struct flex_algo *fad)
{
	struct tlv *tlv, *subtlv;
	struct ri_fad_tlv *fad_tlv;
	struct ri_fad_exclude_admingrp_subtlv *exc_admngrp_subtlv;
	struct ri_fad_include_any_admingrp_subtlv *incany_admngrp_subtlv;
	struct ri_fad_include_all_admingrp_subtlv *incall_admngrp_subtlv;
	struct ri_fad_flags_subtlv *flags_subtlv;
	struct ri_fad_exclude_srlg_subtlv *exc_srlg_subtlv;
	uint16_t tlv_len, subtlv_len;
	size_t num_items;
	struct admin_group *ag;

	tlv = XCALLOC(MTYPE_OSPF_RI_FAD_TLV,
		      sizeof(tlv) + sizeof(struct ri_fad_tlv));
	assert(tlv);
	fad_tlv = (struct ri_fad_tlv *)&tlv->hdr;

	tlv_list_init(&fad_tlv->sub_tlvs);
	tlv_len = RI_FAD_TLV_MIN_LEN;
	fad_tlv->header.type = htons(RI_FAD_TLV);
	fad_tlv->algorithm_id = fad->algorithm;
	fad_tlv->calc_type = fad->calc_type;
	fad_tlv->metric_type = fad->metric_type;
	fad_tlv->priority = fad->priority;

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
		zlog_debug("Generate RI-FAD-TLV (type:%u, id:%u)",
			   ntohs(fad_tlv->header.type), fad_tlv->algorithm_id);

	/* Add Exclude Admin Group SubTLVs (if any) */
	num_items = admin_group_size(&fad->admin_group_exclude_any);
	if (num_items) {
		ag = &fad->admin_group_exclude_any;
		subtlv_len = (bf_word_size(ag->bitmap) * sizeof(uint32_t));
		subtlv = XCALLOC(
			MTYPE_OSPF_RI_FAD_EXC_ADMNGRP_SUBTLV,
			sizeof(tlv) +
				sizeof(struct ri_fad_exclude_admingrp_subtlv) +
				subtlv_len);
		assert(subtlv);
		exc_admngrp_subtlv =
			(struct ri_fad_exclude_admingrp_subtlv *)&subtlv->hdr;
		exc_admngrp_subtlv->header.type =
			htons(RI_FAD_EXC_ADMINGRP_SUBTLV);

		flex_algo_encode_admin_group(ag,
				(uint8_t *)exc_admngrp_subtlv->admin_groups,
				&subtlv_len);
		exc_admngrp_subtlv->header.length = htons(subtlv_len);
		tlv_len += subtlv_len + sizeof(struct tlv_header);

		tlv_list_add_tail(&fad_tlv->sub_tlvs, subtlv);

		if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
			zlog_debug(
				"Generate RI-FAD-EXC-ADMGRP-SUBTLV (type:%u/%u, "
				"len: %u/%u, num-admin-groups: %u), total_len: %u",
				ntohs(exc_admngrp_subtlv->header.type),
				ntohs(subtlv->hdr.type), subtlv_len,
				ntohs(subtlv->hdr.length), (uint32_t)num_items,
				tlv_len);
	}

	/* Add Include-Any Admin Group SubTLVs (if any) */
	num_items = admin_group_size(&fad->admin_group_include_any);
	if (num_items) {
		ag = &fad->admin_group_include_any;
		subtlv_len = (bf_word_size(ag->bitmap) * sizeof(uint32_t));
		subtlv = XCALLOC(
			MTYPE_OSPF_RI_FAD_INCANY_ADMNGRP_SUBTLV,
			sizeof(tlv) +
				sizeof(struct
				       ri_fad_include_any_admingrp_subtlv) +
				subtlv_len);
		assert(subtlv);
		incany_admngrp_subtlv =
			(struct ri_fad_include_any_admingrp_subtlv *)&subtlv
				->hdr;
		incany_admngrp_subtlv->header.type =
			htons(RI_FAD_INCANY_ADMINGRP_SUBTLV);

		flex_algo_encode_admin_group(ag,
				(uint8_t *)incany_admngrp_subtlv->admin_groups,
				&subtlv_len);
		incany_admngrp_subtlv->header.length = htons(subtlv_len);
		tlv_len += subtlv_len + sizeof(struct tlv_header);

		tlv_list_add_tail(&fad_tlv->sub_tlvs, subtlv);

		if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
			zlog_debug(
				"Generate RI-FAD-INCANY-ADMGRP-SUBTLV (type:%u, "
				"len: %u, num-admin-groups: %u), total_len: %u",
				ntohs(incany_admngrp_subtlv->header.type),
				ntohs(incany_admngrp_subtlv->header.length),
				(uint32_t)num_items, tlv_len);
	}

	/* Add Include-All Admin Group SubTLVs (if any) */
	num_items = admin_group_size(&fad->admin_group_include_all);
	if (num_items) {
		ag = &fad->admin_group_include_all;
		subtlv_len = (bf_word_size(ag->bitmap) * sizeof(uint32_t));
		subtlv = XCALLOC(
			MTYPE_OSPF_RI_FAD_INCALL_ADMNGRP_SUBTLV,
			sizeof(tlv) +
				sizeof(struct
				       ri_fad_include_all_admingrp_subtlv) +
				subtlv_len);
		assert(subtlv);
		incall_admngrp_subtlv =
			(struct ri_fad_include_all_admingrp_subtlv *)&subtlv
				->hdr;
		incall_admngrp_subtlv->header.type =
			htons(RI_FAD_INCALL_ADMINGRP_SUBTLV);

		flex_algo_encode_admin_group(ag,
				(uint8_t *)incall_admngrp_subtlv->admin_groups,
				&subtlv_len);
		incall_admngrp_subtlv->header.length = htons(subtlv_len);
		tlv_len += subtlv_len + sizeof(struct tlv_header);

		tlv_list_add_tail(&fad_tlv->sub_tlvs, subtlv);

		if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
			zlog_debug(
				"Generate RI-FAD-INCALL-ADMGRP-SUBTLV (type:%u, "
				"len: %u, num-admin-groups: %u), total_len: %u",
				ntohs(incall_admngrp_subtlv->header.type),
				ntohs(incall_admngrp_subtlv->header.length),
				(uint32_t)num_items, tlv_len);
	}

	/* Add Flags SubTLVs (if any) */
	if (fad->flags) {
		subtlv_len = ROUNDUP(sizeof(fad->flags), sizeof(uint32_t));
		subtlv = XCALLOC(MTYPE_OSPF_RI_FAD_FLAGS_SUBTLV,
				 sizeof(tlv) +
					 sizeof(struct ri_fad_flags_subtlv) +
					 subtlv_len);
		assert(subtlv);
		flags_subtlv = (struct ri_fad_flags_subtlv *)&subtlv->hdr;
		flags_subtlv->header.type = htons(RI_FAD_FLAGS_SUBTLV);
		flags_subtlv->header.length = htons(subtlv_len);
		memcpy(flags_subtlv->flags, &fad->flags, sizeof(fad->flags));
		tlv_len += subtlv_len + sizeof(struct tlv_header);

		tlv_list_add_tail(&fad_tlv->sub_tlvs, subtlv);

		if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
			zlog_debug(
				"Generate RI-FAD-FLAGS-SUBTLV (type:%u, "
				"len: %u/%u), total_len: %u",
				ntohs(flags_subtlv->header.type),
				ntohs(flags_subtlv->header.length),
				(uint32_t)subtlv_len, tlv_len);
	}

	/* Add Exclude SRLG SubTLVs (if any) */
	num_items = admin_group_size(&fad->srlgs_exclude);
	if (num_items) {
		ag = &fad->srlgs_exclude;
		subtlv_len = (bf_word_size(ag->bitmap) * sizeof(uint32_t));
		subtlv = XCALLOC(
			MTYPE_OSPF_RI_FAD_EXC_SRLG_SUBTLV,
			sizeof(tlv) +
				sizeof(struct
				       ri_fad_exclude_srlg_subtlv) +
				subtlv_len);
		assert(subtlv);
		exc_srlg_subtlv =
			(struct ri_fad_exclude_srlg_subtlv *)&subtlv
				->hdr;
		exc_srlg_subtlv->header.type =
			htons(RI_FAD_EXC_SRLG_SUBTLV);

		flex_algo_encode_admin_group(ag,
				(uint8_t *)exc_srlg_subtlv->srlgs,
				&subtlv_len);
		exc_srlg_subtlv->header.length = htons(subtlv_len);
		tlv_len += subtlv_len + sizeof(struct tlv_header);

		tlv_list_add_tail(&fad_tlv->sub_tlvs, subtlv);

		if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
			zlog_debug(
				"Generate RI-FAD-EXC-SRLG-SUBTLV (type:%u, "
				"len: %u, num-srlgs: %u), total_len: %u",
				ntohs(exc_srlg_subtlv->header.type),
				ntohs(exc_srlg_subtlv->header.length),
				(uint32_t)num_items, tlv_len);
	}

	fad_tlv->header.length = htons(tlv_len);
	tlv_list_add_tail(&OspfRI.fad_info.ri_fad_tlvs, tlv);

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
		zlog_debug("Final RI-FAD-TLV (len:%u/%u)",
			   ntohs(fad_tlv->header.length), tlv_len);
}

static void update_ri_fad_tlvs(void)
{
	struct flex_algo *fad;
	struct listnode *curr, *next;

	flush_ri_fad_tlvs();

	if (OspfRI.fad_info.fads && OspfRI.fad_info.num_fads) {
		FOREACH_FLEX_ALGO_DEFN (OspfRI.fad_info.fads, curr, next, fad) {
			update_ri_fad_tlv(fad);
		}

		if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
			zlog_debug("Added total %u RI-FAD-TLVs",
				   (uint32_t)tlv_list_count(
					   &OspfRI.fad_info.ri_fad_tlvs));
	}
}

/*------------------------------------------------------------------------*
 * Following are callback functions against generic Opaque-LSAs handling.
 *------------------------------------------------------------------------*/
static void ospf_router_info_ism_change(struct ospf_interface *oi,
					int old_state)
{

	struct ospf_ri_area_info *ai;

	/* Collect area information */
	ai = lookup_by_area(oi->area);

	/* Check if area is not yet registered */
	if (ai != NULL)
		return;

	/* Add this new area to the list */
	ai = XCALLOC(MTYPE_OSPF_ROUTER_INFO, sizeof(struct ospf_ri_area_info));
	ai->area = oi->area;
	ai->flags = RIFLG_LSA_INACTIVE;
	listnode_add(OspfRI.area_info, ai);

	return;
}

/*------------------------------------------------------------------------*
 * Following are OSPF protocol processing functions for ROUTER INFORMATION
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

static void ri_lsa_add_fad_tlvs(struct stream *s)
{
	struct tlv *tlv, *subtlv;
	struct tlv_header *tlvh, *hdr;
	struct ri_fad_tlv *fad_tlv;
	uint16_t *tlv_lenp, orig_len;
	size_t tlv_begin, tlv_end;

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
		zlog_debug(
			"Adding %d/%d Flex-Algo-Definitions",
			OspfRI.fad_info.num_fads,
			(uint32_t)tlv_list_count(&OspfRI.fad_info.ri_fad_tlvs));

	if (OspfRI.fad_info.num_fads) {
		FOREACH_TLV_IN_LIST (&OspfRI.fad_info.ri_fad_tlvs, tlv) {
			fad_tlv = (struct ri_fad_tlv *)&tlv->hdr;

			/*
			 * Prepare TLV to write it onto the stream without
			 * the sub-TLVs.
			 */
			hdr = &fad_tlv->header;
			tlv_lenp = &hdr->length;
			orig_len = ntohs(*tlv_lenp);
			if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
				zlog_debug(
					"Got %u bytes of RI-FAD-TLV (type:%u, "
					"len: %u, id:%u/%u, metric:%u/%u, calc:%u/%u, prio:%u/%u)",
					orig_len, ntohs(hdr->type),
					ntohs(hdr->length), tlv->body[0],
					fad_tlv->algorithm_id, tlv->body[1],
					fad_tlv->metric_type, tlv->body[2],
					fad_tlv->calc_type, tlv->body[3],
					fad_tlv->priority);

			/* Note the tlv header position in the stream buffer */
			tlv_begin = stream_get_endp(s);
			tlvh = (struct tlv_header *)(STREAM_DATA(s) +
						     stream_get_endp(s));

			/* Write out the tlv header in the stream buffer */
			*tlv_lenp = htons(RI_FAD_TLV_MIN_LEN);
			build_tlv(s, hdr);

			FOREACH_TLV_IN_LIST (&fad_tlv->sub_tlvs, subtlv) {
				switch (ntohs(subtlv->hdr.type)) {
				case RI_FAD_EXC_ADMINGRP_SUBTLV:
				case RI_FAD_INCANY_ADMINGRP_SUBTLV:
				case RI_FAD_INCALL_ADMINGRP_SUBTLV:
				case RI_FAD_FLAGS_SUBTLV:
				case RI_FAD_EXC_SRLG_SUBTLV:
					build_tlv(s, &subtlv->hdr);

					if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
						zlog_debug(
							"Wrote Sub-TLV (type:%u, len: %u)",
							ntohs(subtlv->hdr.type),
							ntohs(subtlv->hdr
								      .length));
					break;
				default:
					break;
				}
			}

			/* Restore the original TLV-len in the stream buffer */
			tlv_end = stream_get_endp(s);
			tlv_lenp = &tlvh->length;
			*tlv_lenp = htons(orig_len);

			if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
				zlog_debug(
					"Wrote %u/%u bytes of RI-FAD-TLV (type:%u, len: %u)",
					orig_len,
					(uint32_t)(tlv_end - tlv_begin),
					ntohs(tlvh->type), ntohs(tlvh->length));
		}
	}
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
		build_tlv(s, &TLV_HDR(OspfRI.sr_info.srgb));
		/* Build SRLB TLV */
		build_tlv(s, &TLV_HDR(OspfRI.sr_info.srlb));
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

	/* Add Flex-Algo definitions */
	update_ri_fad_tlvs();
	ri_lsa_add_fad_tlvs(s);

	return;
}

/* Create new opaque-LSA. */
static struct ospf_lsa *ospf_router_info_lsa_new(struct ospf_area *area)
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
	s = stream_new(OSPF_MAX_LSA_SIZE);

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
			"LSA[Type%d:%pI4]: Create an Opaque-LSA/ROUTER INFORMATION instance",
			lsa_type, &lsa_id);

	top = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	/* Set opaque-LSA header fields. */
	lsa_header_set(s, options, lsa_type, lsa_id, top->router_id);

	/* Set opaque-LSA body fields. */
	ospf_router_info_lsa_body_set(s);

	/* Set length. */
	length = stream_get_endp(s);
	lsah->length = htons(length);

	/* Now, create an OSPF LSA instance. */
	new = ospf_lsa_new_and_data(length);

	/* Routing Information is only supported for default VRF */
	new->vrf_id = VRF_DEFAULT;
	new->area = area;

	SET_FLAG(new->flags, OSPF_LSA_SELF);
	memcpy(new->data, lsah, length);
	stream_free(s);

	return new;
}

static int ospf_router_info_lsa_originate_as(void *arg)
{
	struct ospf_lsa *new;
	struct ospf *top;
	int rc = -1;

	/* Sanity Check */
	if (OspfRI.scope == OSPF_OPAQUE_AREA_LSA) {
		flog_warn(
			EC_OSPF_LSA_INSTALL_FAILURE,
			"RI (%s): wrong flooding scope AREA instead of AS ?",
			__func__);
		return rc;
	}

	/* Create new Opaque-LSA/ROUTER INFORMATION instance. */
	new = ospf_router_info_lsa_new(NULL);
	top = (struct ospf *)arg;

	/* Check ospf info */
	if (top == NULL) {
		zlog_debug("RI (%s): ospf instance not found for vrf id %u",
			   __func__, VRF_DEFAULT);
		ospf_lsa_unlock(&new);
		return rc;
	}

	/* Install this LSA into LSDB. */
	if (ospf_lsa_install(top, NULL /*oi */, new) == NULL) {
		flog_warn(
			EC_OSPF_LSA_INSTALL_FAILURE,
			"RI (%s): ospf_lsa_install() ?", __func__);
		ospf_lsa_unlock(&new);
		return rc;
	}

	/* Update new LSA origination count. */
	top->lsa_originate_count++;

	/* Flood new LSA through AREA or AS. */
	SET_FLAG(OspfRI.as_flags, RIFLG_LSA_ENGAGED);
	ospf_flood_through_as(top, NULL /*nbr */, new);

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE)) {
		zlog_debug(
			"LSA[Type%d:%pI4]: Originate Opaque-LSA/ROUTER INFORMATION",
			new->data->type, &new->data->id);
		ospf_lsa_header_dump(new->data);
	}

	rc = 0;
	return rc;
}

static int ospf_router_info_lsa_originate_area(void *arg)
{
	struct ospf_lsa *new;
	struct ospf *top;
	struct ospf_ri_area_info *ai = NULL;
	int rc = -1;

	/* Sanity Check */
	if (OspfRI.scope == OSPF_OPAQUE_AS_LSA) {
		flog_warn(
			EC_OSPF_LSA_INSTALL_FAILURE,
			"RI (%s): wrong flooding scope AS instead of AREA ?",
			__func__);
		return rc;
	}

	/* Create new Opaque-LSA/ROUTER INFORMATION instance. */
	ai = lookup_by_area((struct ospf_area *)arg);
	if (ai == NULL) {
		zlog_debug(
			"RI (%s): There is no context for this Router Information. Stop processing",
			__func__);
		return rc;
	}

	if (ai->area->ospf)
		top = ai->area->ospf;
	else
		top = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	new = ospf_router_info_lsa_new(ai->area);

	/* Check ospf info */
	if (top == NULL) {
		zlog_debug("RI (%s): ospf instance not found for vrf id %u",
			   __func__, VRF_DEFAULT);
		ospf_lsa_unlock(&new);
		return rc;
	}

	/* Install this LSA into LSDB. */
	if (ospf_lsa_install(top, NULL /*oi */, new) == NULL) {
		flog_warn(
			EC_OSPF_LSA_INSTALL_FAILURE,
			"RI (%s): ospf_lsa_install() ?", __func__);
		ospf_lsa_unlock(&new);
		return rc;
	}

	/* Update new LSA origination count. */
	top->lsa_originate_count++;

	/* Flood new LSA through AREA or AS. */
	SET_FLAG(ai->flags, RIFLG_LSA_ENGAGED);
	ospf_flood_through_area(ai->area, NULL /*nbr */, new);

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE)) {
		zlog_debug(
			"LSA[Type%d:%pI4]: Originate Opaque-LSA/ROUTER INFORMATION",
			new->data->type, &new->data->id);
		ospf_lsa_header_dump(new->data);
	}

	rc = 0;
	return rc;
}

static int ospf_router_info_lsa_originate(void *arg)
{

	struct ospf_ri_area_info *ai;
	int rc = -1;

	if (!OspfRI.enabled) {
		zlog_info("RI (%s): ROUTER INFORMATION is disabled now.",
			  __func__);
		rc = 0; /* This is not an error case. */
		return rc;
	}

	/* Check if Router Information LSA is already engaged */
	if (OspfRI.scope == OSPF_OPAQUE_AS_LSA) {
		if ((CHECK_FLAG(OspfRI.as_flags, RIFLG_LSA_ENGAGED))
			&& (CHECK_FLAG(OspfRI.as_flags,
				RIFLG_LSA_FORCED_REFRESH))) {
			UNSET_FLAG(OspfRI.as_flags, RIFLG_LSA_FORCED_REFRESH);
			ospf_router_info_lsa_schedule(NULL, REFRESH_THIS_LSA);
			rc = 0;
			return rc;
		}
	} else {
		ai = lookup_by_area((struct ospf_area *)arg);
		if (ai == NULL) {
			flog_warn(
				EC_OSPF_LSA,
				"RI (%s): Missing area information", __func__);
			return rc;
		}
		if ((CHECK_FLAG(ai->flags, RIFLG_LSA_ENGAGED))
			&& (CHECK_FLAG(ai->flags, RIFLG_LSA_FORCED_REFRESH))) {
			UNSET_FLAG(ai->flags, RIFLG_LSA_FORCED_REFRESH);
			ospf_router_info_lsa_schedule(ai, REFRESH_THIS_LSA);
			rc = 0;
			return rc;
		}
	}

	/* Router Information is not yet Engaged, check parameters */
	if (!is_mandated_params_set(&OspfRI))
		flog_warn(
			EC_OSPF_LSA,
			"RI (%s): lacks mandated ROUTER INFORMATION parameters",
			__func__);

	/* Ok, let's try to originate an LSA */
	if (OspfRI.scope == OSPF_OPAQUE_AS_LSA)
		rc = ospf_router_info_lsa_originate_as(arg);
	else
		rc = ospf_router_info_lsa_originate_area(arg);

	return rc;
}

static struct ospf_lsa *ospf_router_info_lsa_refresh(struct ospf_lsa *lsa)
{
	struct ospf_ri_area_info *ai = NULL;
	struct ospf_lsa *new = NULL;
	struct ospf *top;

	if (!OspfRI.enabled) {
		/*
		 * This LSA must have flushed before due to ROUTER INFORMATION
		 * status change.
		 * It seems a slip among routers in the routing domain.
		 */
		zlog_info("RI (%s): ROUTER INFORMATION is disabled now.",
			  __func__);
		lsa->data->ls_age =
			htons(OSPF_LSA_MAXAGE); /* Flush it anyway. */
	}

	/* Verify that the Router Information ID is supported */
	if (GET_OPAQUE_ID(ntohl(lsa->data->id.s_addr)) != 0) {
		flog_warn(
			EC_OSPF_LSA,
			"RI (%s): Unsupported Router Information ID",
			__func__);
		return NULL;
	}

	/* Process LSA depending of the flooding scope */
	if (OspfRI.scope == OSPF_OPAQUE_AREA_LSA) {
		/* Get context AREA context */
		ai = lookup_by_area(lsa->area);
		if (ai == NULL) {
			flog_warn(
				EC_OSPF_LSA,
				"RI (%s): No associated Area", __func__);
			return NULL;
		}
		/* Flush LSA, if the lsa's age reached to MaxAge. */
		if (IS_LSA_MAXAGE(lsa)) {
			UNSET_FLAG(ai->flags, RIFLG_LSA_ENGAGED);
			ospf_opaque_lsa_flush_schedule(lsa);
			return NULL;
		}
		/* Create new Opaque-LSA/ROUTER INFORMATION instance. */
		new = ospf_router_info_lsa_new(ai->area);
		new->data->ls_seqnum = lsa_seqnum_increment(lsa);
		/* Install this LSA into LSDB. */
		/* Given "lsa" will be freed in the next function. */
		top = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf_lsa_install(top, NULL /*oi */, new) == NULL) {
			flog_warn(EC_OSPF_LSA_INSTALL_FAILURE,
				  "RI (%s): ospf_lsa_install() ?", __func__);
			ospf_lsa_unlock(&new);
			return new;
		}
		/* Flood updated LSA through AREA */
		ospf_flood_through_area(ai->area, NULL /*nbr */, new);

	} else { /* AS Flooding scope */
		/* Flush LSA, if the lsa's age reached to MaxAge. */
		if (IS_LSA_MAXAGE(lsa)) {
			UNSET_FLAG(OspfRI.as_flags, RIFLG_LSA_ENGAGED);
			ospf_opaque_lsa_flush_schedule(lsa);
			return NULL;
		}
		/* Create new Opaque-LSA/ROUTER INFORMATION instance. */
		new = ospf_router_info_lsa_new(NULL);
		new->data->ls_seqnum = lsa_seqnum_increment(lsa);
		/* Install this LSA into LSDB. */
		/* Given "lsa" will be freed in the next function. */
		top = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf_lsa_install(top, NULL /*oi */, new) == NULL) {
			flog_warn(EC_OSPF_LSA_INSTALL_FAILURE,
				  "RI (%s): ospf_lsa_install() ?", __func__);
			ospf_lsa_unlock(&new);
			return new;
		}
		/* Flood updated LSA through AS */
		ospf_flood_through_as(top, NULL /*nbr */, new);
	}

	/* Debug logging. */
	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE)) {
		zlog_debug(
			"LSA[Type%d:%pI4]: Refresh Opaque-LSA/ROUTER INFORMATION",
			new->data->type, &new->data->id);
		ospf_lsa_header_dump(new->data);
	}

	return new;
}

static void ospf_router_info_lsa_schedule(struct ospf_ri_area_info *ai,
					  enum lsa_opcode opcode)
{
	struct ospf_lsa lsa;
	struct lsa_header lsah;
	struct ospf *top;
	uint32_t tmp;

	memset(&lsa, 0, sizeof(lsa));
	memset(&lsah, 0, sizeof(lsah));

	zlog_debug("RI (%s): LSA schedule %s%s%s", __func__,
		   opcode == REORIGINATE_THIS_LSA ? "Re-Originate" : "",
		   opcode == REFRESH_THIS_LSA ? "Refresh" : "",
		   opcode == FLUSH_THIS_LSA ? "Flush" : "");

	/* Check LSA flags state coherence and collect area information */
	if (OspfRI.scope == OSPF_OPAQUE_AREA_LSA) {
		if ((ai == NULL) || (ai->area == NULL)) {
			flog_warn(
				EC_OSPF_LSA,
				"RI (%s): Router Info is Area scope flooding but area is not set",
				__func__);
				return;
		}

		if (!CHECK_FLAG(ai->flags, RIFLG_LSA_ENGAGED)
		    && (opcode != REORIGINATE_THIS_LSA))
			return;

		if (CHECK_FLAG(ai->flags, RIFLG_LSA_ENGAGED)
		    && (opcode == REORIGINATE_THIS_LSA))
			opcode = REFRESH_THIS_LSA;

		lsa.area = ai->area;
		top = ai->area->ospf;
	} else {
		if (!CHECK_FLAG(OspfRI.as_flags, RIFLG_LSA_ENGAGED)
		    && (opcode != REORIGINATE_THIS_LSA))
			return;

		if (CHECK_FLAG(OspfRI.as_flags, RIFLG_LSA_ENGAGED)
		    && (opcode == REORIGINATE_THIS_LSA))
			opcode = REFRESH_THIS_LSA;

		top = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		lsa.area = NULL;
	}

	lsa.data = &lsah;
	lsah.type = OspfRI.scope;

	/* LSA ID is set to 0 for the Router Information. See RFC 4970 */
	tmp = SET_OPAQUE_LSID(OPAQUE_TYPE_ROUTER_INFORMATION_LSA, 0);
	lsah.id.s_addr = htonl(tmp);

	switch (opcode) {
	case REORIGINATE_THIS_LSA:
		if (OspfRI.scope == OSPF_OPAQUE_AREA_LSA)
			ospf_opaque_lsa_reoriginate_schedule(
				(void *)ai->area, OSPF_OPAQUE_AREA_LSA,
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
		if (OspfRI.scope == OSPF_OPAQUE_AREA_LSA)
			UNSET_FLAG(ai->flags, RIFLG_LSA_ENGAGED);
		else
			UNSET_FLAG(OspfRI.as_flags, RIFLG_LSA_ENGAGED);
		ospf_opaque_lsa_flush_schedule(&lsa);
		break;
	}

	return;
}

/* Callback to handle Segment Routing information */
static int ospf_router_info_lsa_update(struct ospf_lsa *lsa)
{

	/* Sanity Check */
	if (lsa == NULL) {
		flog_warn(EC_OSPF_LSA, "RI (%s): Abort! LSA is NULL",
			  __func__);
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
 * Following are vty session control functions.
 *------------------------------------------------------------------------*/

#define check_tlv_size(size, msg)                                              \
	do {                                                                   \
		if (ntohs(tlvh->length) > size) {                              \
			if (vty != NULL)                                       \
				vty_out(vty, "  Wrong %s TLV size: %d(%d)\n",  \
					msg, ntohs(tlvh->length), size);       \
			else                                                   \
				zlog_debug("    Wrong %s TLV size: %d(%d)",    \
					   msg, ntohs(tlvh->length), size);    \
			return size + TLV_HDR_SIZE;                            \
		}                                                              \
	} while (0)

#define check_tlv_min_size(size, msg)                                          \
	do {                                                                   \
		if (ntohs(tlvh->length) < size) {                              \
			if (vty != NULL)                                       \
				vty_out(vty,                                   \
					"  Insuffcient %s TLV size: %d, "      \
					"Minimum expected: %d\n",              \
					msg, ntohs(tlvh->length), size);       \
			else                                                   \
				zlog_debug(                                    \
					"   Insuffcient %s TLV size: %d,"      \
					"Minimum expected: %d",                \
					msg, ntohs(tlvh->length), size);       \
			return size + TLV_HDR_SIZE;                            \
		}                                                              \
	} while (0)

#define check_tlv_size_multiple_of(unitsize, msg)                              \
	do {                                                                   \
		if (ntohs(tlvh->length) % unitsize) {                          \
			if (vty != NULL)                                       \
				vty_out(vty,                                   \
					"  %s TLV size: %d not mutiple of"     \
					" %d bytes\n",                         \
					msg, ntohs(tlvh->length),              \
					(int)unitsize);                        \
			else                                                   \
				zlog_debug(                                    \
					"  %s TLV size: %d not mutiple of "    \
					"%d bytes",                            \
					msg, ntohs(tlvh->length),              \
					(int)unitsize);                        \
			return ntohs(tlvh->length) + TLV_HDR_SIZE;             \
		}                                                              \
	} while (0)


static uint16_t show_vty_router_cap(struct vty *vty, struct tlv_header *tlvh,
				    json_object *json)
{
	struct ri_tlv_router_cap *top = (struct ri_tlv_router_cap *)tlvh;

	check_tlv_size(RI_TLV_CAPABILITIES_SIZE, "Router Capabilities");

	if (json) {
		tlvh_get_json_values(tlvh, json, "Router Capabilities TLV");
		json_object_string_addf(json, "capabilities", "0x%x",
					ntohl(top->value));
	} else if (vty != NULL)
		vty_out(vty, "  Router Capabilities: 0x%x\n",
			ntohl(top->value));
	else
		zlog_debug("    Router Capabilities: 0x%x", ntohl(top->value));

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_pce_subtlv_address(struct vty *vty,
					    struct tlv_header *tlvh,
					    json_object *json)
{
	struct ri_pce_subtlv_address *top =
		(struct ri_pce_subtlv_address *)tlvh;

	if (ntohs(top->address.type) == PCE_ADDRESS_IPV4) {
		check_tlv_size(PCE_ADDRESS_IPV4_SIZE, "PCE Address");
		if (json) {
			tlvh_get_json_values(tlvh, json, "PCE Address SubTLV");
			json_object_string_addf(json, "pceAddress", "%pI4",
						&top->address.value);
		} else if (vty != NULL)
			vty_out(vty, "  PCE Address: %pI4\n",
				&top->address.value);
		else
			zlog_debug("    PCE Address: %pI4",
				   &top->address.value);
	} else if (ntohs(top->address.type) == PCE_ADDRESS_IPV6) {
		/* TODO: Add support to IPv6 with inet_ntop() */
		check_tlv_size(PCE_ADDRESS_IPV6_SIZE, "PCE Address");
		if (vty != NULL)
			vty_out(vty, "  PCE Address: 0x%x\n",
				ntohl(top->address.value.s_addr));
		else
			zlog_debug("    PCE Address: 0x%x",
				   ntohl(top->address.value.s_addr));
	} else {
		if (vty != NULL)
			vty_out(vty, "  Wrong PCE Address type: 0x%x\n",
				ntohl(top->address.type));
		else
			zlog_debug("    Wrong PCE Address type: 0x%x",
				   ntohl(top->address.type));
	}

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_pce_subtlv_path_scope(struct vty *vty,
					       struct tlv_header *tlvh,
					       json_object *json)
{
	struct ri_pce_subtlv_path_scope *top =
		(struct ri_pce_subtlv_path_scope *)tlvh;

	check_tlv_size(RI_PCE_SUBTLV_PATH_SCOPE_SIZE, "PCE Path Scope");

	if (json) {
		tlvh_get_json_values(tlvh, json, "PCE Path Scope SubTLV");
		json_object_int_add(json, "pcePathScope", ntohl(top->value));
	} else if (vty != NULL)
		vty_out(vty, "  PCE Path Scope: 0x%x\n", ntohl(top->value));
	else
		zlog_debug("    PCE Path Scope: 0x%x", ntohl(top->value));

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_pce_subtlv_domain(struct vty *vty,
					   struct tlv_header *tlvh,
					   json_object *json)
{
	struct ri_pce_subtlv_domain *top = (struct ri_pce_subtlv_domain *)tlvh;
	struct in_addr tmp;

	check_tlv_size(RI_PCE_SUBTLV_DOMAIN_SIZE, "PCE Domain");

	if (ntohs(top->type) == PCE_DOMAIN_TYPE_AREA) {
		tmp.s_addr = top->value;
		if (json) {
			tlvh_get_json_values(tlvh, json, "PCE Domain SubTLV");
			json_object_string_add(json, "domainType", "Area");
			json_object_string_addf(json, "domainArea", "%pI4",
						&tmp);
		} else if (vty != NULL)
			vty_out(vty, "  PCE Domain Area: %pI4\n", &tmp);
		else
			zlog_debug("    PCE Domain Area: %pI4", &tmp);
	} else if (ntohs(top->type) == PCE_DOMAIN_TYPE_AS) {
		if (json) {
			tlvh_get_json_values(tlvh, json, "PCE Domain SubTLV");
			json_object_string_add(json, "domainType", "AS");
			json_object_int_add(json, "pceDomainAS",
					    ntohl(top->value));
		} else if (vty != NULL)
			vty_out(vty, "  PCE Domain AS: %d\n",
				ntohl(top->value));
		else
			zlog_debug("    PCE Domain AS: %d", ntohl(top->value));
	} else {
		if (json) {
			tlvh_get_json_values(tlvh, json, "PCE Domain SubTLV");
			json_object_string_addf(json, "domainType",
						"Unknown (%d)",
						ntohl(top->type));
		} else if (vty != NULL)
			vty_out(vty, "  Wrong PCE Domain type: %d\n",
				ntohl(top->type));
		else
			zlog_debug("    Wrong PCE Domain type: %d",
				   ntohl(top->type));
	}

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_pce_subtlv_neighbor(struct vty *vty,
					     struct tlv_header *tlvh,
					     json_object *json)
{

	struct ri_pce_subtlv_neighbor *top =
		(struct ri_pce_subtlv_neighbor *)tlvh;
	struct in_addr tmp;

	check_tlv_size(RI_PCE_SUBTLV_NEIGHBOR_SIZE, "PCE Neighbor");

	if (ntohs(top->type) == PCE_DOMAIN_TYPE_AREA) {
		tmp.s_addr = top->value;
		if (json) {
			tlvh_get_json_values(tlvh, json, "PCE Neighbor SubTLV");
			json_object_string_add(json, "domainType", "Area");
			json_object_string_addf(json, "neighborArea", "%pI4",
						&tmp);
		} else if (vty != NULL)
			vty_out(vty, "  PCE Neighbor Area: %pI4\n", &tmp);
		else
			zlog_debug("    PCE Neighbor Area: %pI4", &tmp);
	} else if (ntohs(top->type) == PCE_DOMAIN_TYPE_AS) {
		if (json) {
			tlvh_get_json_values(tlvh, json, "PCE Neighbor SubTLV");
			json_object_string_add(json, "domainType", "AS");
			json_object_int_add(json, "neighborAS",
					    ntohl(top->value));
		} else if (vty != NULL)
			vty_out(vty, "  PCE Neighbor AS: %d\n",
				ntohl(top->value));
		else
			zlog_debug("    PCE Neighbor AS: %d",
				   ntohl(top->value));
	} else {
		if (json) {
			tlvh_get_json_values(tlvh, json, "PCE Neighbor SubTLV");
			json_object_string_addf(json, "domainType",
						"Unknown (%d)",
						ntohl(top->type));
		} else if (vty != NULL)
			vty_out(vty, "  Wrong PCE Neighbor type: %d\n",
				ntohl(top->type));
		else
			zlog_debug("    Wrong PCE Neighbor type: %d",
				   ntohl(top->type));
	}

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_pce_subtlv_cap_flag(struct vty *vty,
					     struct tlv_header *tlvh,
					     json_object *json)
{
	struct ri_pce_subtlv_cap_flag *top =
		(struct ri_pce_subtlv_cap_flag *)tlvh;

	check_tlv_size(RI_PCE_SUBTLV_CAP_FLAG_SIZE, "PCE Capabilities");

	if (json) {
		tlvh_get_json_values(tlvh, json, "PCE Capabilities SubTLV");
		json_object_string_addf(json, "flag", "0x%x",
					ntohl(top->value));
	} else if (vty != NULL)
		vty_out(vty, "  PCE Capabilities Flag: 0x%x\n",
			ntohl(top->value));
	else
		zlog_debug("    PCE Capabilities Flag: 0x%x",
			   ntohl(top->value));

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_unknown_tlv(struct vty *vty, struct tlv_header *tlvh,
				     size_t buf_size, json_object *json)
{
	if (TLV_SIZE(tlvh) > buf_size) {
		if (vty != NULL)
			vty_out(vty,
				"    TLV type %d, size %d exceeds buffer size %d. Abort!\n",
				ntohs(tlvh->length), TLV_SIZE(tlvh),
				(int)buf_size);
		else
			zlog_debug(
				"    TLV type %d, size %d exceeds buffer size %d. Abort!",
				ntohs(tlvh->length), TLV_SIZE(tlvh),
				(int)buf_size);
		return buf_size;
	}

	if (json)
		tlvh_get_json_values(tlvh, json, "Unknown");
	else if (vty != NULL)
		vty_out(vty, "  Unknown TLV: [type(0x%x), length(0x%x)]\n",
			ntohs(tlvh->type), ntohs(tlvh->length));
	else
		zlog_debug("    Unknown TLV: [type(0x%x), length(0x%x)]",
			   ntohs(tlvh->type), ntohs(tlvh->length));

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_pce_info(struct vty *vty, struct tlv_header *ri,
				  size_t buf_size, json_object *json)
{
	struct tlv_header *tlvh;
	uint16_t length = ntohs(ri->length);
	uint16_t sum = 0;
	json_object *stlvs_json = NULL;
	json_object *stlv_json = NULL;

	/* Verify that TLV length is valid against remaining buffer size */
	if (length > buf_size) {
		vty_out(vty,
			"  PCE Info TLV size %d exceeds buffer size. Abort!\n",
			length);
		return buf_size;
	}

	if (json) {
		tlvh_get_json_values(ri, json, "PCE Information TLV");
		stlvs_json = json_object_new_array();
		json_object_object_add(json, "subTLVs", stlvs_json);
	}

	for (tlvh = ri; sum < length; tlvh = TLV_HDR_NEXT(tlvh)) {
		if (stlvs_json) {
			stlv_json = json_object_new_object();
			json_object_array_add(stlvs_json, stlv_json);
		}

		switch (ntohs(tlvh->type)) {
		case RI_PCE_SUBTLV_ADDRESS:
			sum += show_vty_pce_subtlv_address(vty, tlvh,
							   stlv_json);
			break;
		case RI_PCE_SUBTLV_PATH_SCOPE:
			sum += show_vty_pce_subtlv_path_scope(vty, tlvh,
							      stlv_json);
			break;
		case RI_PCE_SUBTLV_DOMAIN:
			sum += show_vty_pce_subtlv_domain(vty, tlvh, stlv_json);
			break;
		case RI_PCE_SUBTLV_NEIGHBOR:
			sum += show_vty_pce_subtlv_neighbor(vty, tlvh,
							    stlv_json);
			break;
		case RI_PCE_SUBTLV_CAP_FLAG:
			sum += show_vty_pce_subtlv_cap_flag(vty, tlvh,
							    stlv_json);
			break;
		default:
			sum += show_vty_unknown_tlv(vty, tlvh, length - sum,
						    stlv_json);
			break;
		}
	}
	return sum;
}

/* Display Segment Routing Algorithm TLV information */
static uint16_t show_vty_sr_algorithm(struct vty *vty, struct tlv_header *tlvh,
				      json_object *json)
{
	struct ri_sr_tlv_sr_algorithm *algo =
		(struct ri_sr_tlv_sr_algorithm *)tlvh;
	int i;
	json_object *algos_json;
	json_object *algo_json;

	check_tlv_size(ALGORITHM_COUNT, "Segment Routing Algorithm");

	if (json) {
		tlvh_get_json_values(tlvh, json, "SR Algorithm TLV");
		algos_json = json_object_new_array();
		json_object_object_add(json, "algorithms", algos_json);
		for (i = 0; i < ntohs(algo->header.length); i++) {
			algo_json =
				json_object_new_int((int64_t)algo->value[i]);
			json_object_array_add(algos_json, algo_json);
		}
	} else if (vty != NULL) {
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
	} else {
		zlog_debug("  Segment Routing Algorithm TLV:");
		for (i = 0; i < ntohs(algo->header.length); i++)
			switch (algo->value[i]) {
			case 0:
				zlog_debug("    Algorithm %d: SPF", i);
				break;
			case 1:
				zlog_debug("    Algorithm %d: Strict SPF", i);
				break;
			default:
				zlog_debug("    Algorithm %d: Unknown value %d",
					   i, algo->value[i]);
				break;
			}
	}

	return TLV_SIZE(tlvh);
}

/* Display Segment Routing SID/Label Range TLV information */
static uint16_t show_vty_sr_range(struct vty *vty, struct tlv_header *tlvh,
				  json_object *json)
{
	struct ri_sr_tlv_sid_label_range *range =
		(struct ri_sr_tlv_sid_label_range *)tlvh;

	check_tlv_size(RI_SR_TLV_LABEL_RANGE_SIZE, "SR Label Range");

	if (json) {
		tlvh_get_json_values(tlvh, json,
				     ntohs(range->header.type) ==
						     RI_SR_TLV_SRGB_LABEL_RANGE
					     ? "SR Global Label Range TLV"
					     : "SR Local Label Range TLV");
		json_object_int_add(json, "rangeSize",
				    GET_RANGE_SIZE(ntohl(range->size)));
		json_object_int_add(json, "rangeStartLabel",
				    GET_LABEL(ntohl(range->lower.value)));
	} else if (vty != NULL) {
		vty_out(vty,
			"  Segment Routing %s Range TLV:\n"
			"    Range Size = %d\n"
			"    SID Label = %d\n\n",
			ntohs(range->header.type) == RI_SR_TLV_SRGB_LABEL_RANGE
				? "Global"
				: "Local",
			GET_RANGE_SIZE(ntohl(range->size)),
			GET_LABEL(ntohl(range->lower.value)));
	} else {
		zlog_debug(
			"  Segment Routing %s Range TLV:  Range Size = %d  SID Label = %d",
			ntohs(range->header.type) == RI_SR_TLV_SRGB_LABEL_RANGE
				? "Global"
				: "Local",
			GET_RANGE_SIZE(ntohl(range->size)),
			GET_LABEL(ntohl(range->lower.value)));
	}

	return TLV_SIZE(tlvh);
}

/* Display Segment Routing Maximum Stack Depth TLV information */
static uint16_t show_vty_sr_msd(struct vty *vty, struct tlv_header *tlvh,
				json_object *json)
{
	struct ri_sr_tlv_node_msd *msd = (struct ri_sr_tlv_node_msd *)tlvh;

	check_tlv_size(RI_SR_TLV_NODE_MSD_SIZE, "Node Maximum Stack Depth");

	if (json) {
		tlvh_get_json_values(tlvh, json,
				     "Node Maxomum Stack Depth TLV");
		json_object_int_add(json, "maximumStackDepth",
				    (int64_t)msd->value);
	} else if (vty != NULL) {
		vty_out(vty,
			"  Segment Routing MSD TLV:\n"
			"    Node Maximum Stack Depth = %d\n",
			msd->value);
	} else {
		zlog_debug(
			"  Segment Routing MSD TLV:  Node Maximum Stack Depth = %d",
			msd->value);
	}

	return TLV_SIZE(tlvh);
}

static void show_vty_admin_groups(struct vty *vty,
				  struct admin_group *grp,
				  json_object *admngrps_json,
				  bool map_affinity)
{
	uint16_t indx = 0;
	json_object *admngrp_json = NULL;
	uint32_t admn_grp;
	char *name = NULL;

	FOREACH_FLEX_ALGO_ADMIN_GROUP (grp, admn_grp) {
		if (map_affinity)
			name = affinity_map_name_get(admn_grp);
		if (admngrps_json) {
			if (!map_affinity) {
				admngrp_json = json_object_new_int(admn_grp);

			} else if(name) {
				admngrp_json = json_object_new_string(name);
			} else {
				admngrp_json = json_object_new_stringf(
							"unknown(%u)",
							admn_grp);
			}
			json_object_array_add(admngrps_json, admngrp_json);
		}  else if (vty != NULL) {
			if (!(indx % 16))
				vty_out(vty, "      [ ");
			else
				vty_out(vty, ", ");

			if (!map_affinity) {
				vty_out(vty, "%u", admn_grp);
			} else if (name)
				vty_out(vty, "%s", name);
			else
				vty_out(vty, "unknown(%u)", admn_grp);

			if ((indx % 16) == 15)
				vty_out(vty, " ]\n");
		}
		indx ++;
	}

	if (!admngrps_json && vty && (indx % 16))
		vty_out(vty, " ]\n");
}

static uint16_t show_vty_fad_exc_admngrp(struct vty *vty,
					 struct tlv_header *tlvh,
					 json_object *json)
{
	struct ri_fad_exclude_admingrp_subtlv *top =
		(struct ri_fad_exclude_admingrp_subtlv *)tlvh;
	json_object *admngrps_json = NULL;
	struct admin_group grp = { 0 };

	check_tlv_min_size(RI_FAD_EXC_ADMINGRP_SUBTLV_MIN_LEN,
			   "FAD Exclude Admin Groups");
	check_tlv_size_multiple_of(sizeof(uint32_t),
				   "FAD Exclude Admin Groups");

	flex_algo_decode_admin_group(&grp, (uint8_t *)top->admin_groups,
				     ntohs(tlvh->length));
	if (json) {
		tlvh_get_json_values(tlvh, json, "Exclude Admin Groups SubTLV");
		admngrps_json = json_object_new_array();
		json_object_object_add(json, "adminGroups", admngrps_json);
	} else if (vty != NULL) {
		vty_out(vty, "    FAD Exclude Admin Groups: \n");
	}

	show_vty_admin_groups(vty, &grp, admngrps_json, true);

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_fad_incany_admngrp(struct vty *vty,
					    struct tlv_header *tlvh,
					    json_object *json)
{
	struct ri_fad_include_any_admingrp_subtlv *top =
		(struct ri_fad_include_any_admingrp_subtlv *)tlvh;
	json_object *admngrps_json = NULL;
	struct admin_group grp = { 0 };

	check_tlv_min_size(RI_FAD_INCANY_ADMINGRP_SUBTLV_MIN_LEN,
			   "FAD Include Any Admin Groups");
	check_tlv_size_multiple_of(sizeof(uint32_t),
				   "FAD Include Any Admin Groups");

	flex_algo_decode_admin_group(&grp, (uint8_t *)top->admin_groups,
				     ntohs(tlvh->length));
	if (json) {
		tlvh_get_json_values(tlvh, json, "Include-Any Admin Groups SubTLV");
		admngrps_json = json_object_new_array();
		json_object_object_add(json, "adminGroups", admngrps_json);
	} else if (vty != NULL) {
		vty_out(vty, "    FAD Include-Any Admin Groups: \n");
	}

	show_vty_admin_groups(vty, &grp, admngrps_json, true);

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_fad_incall_admngrp(struct vty *vty,
					    struct tlv_header *tlvh,
					    json_object *json)
{
	struct ri_fad_include_all_admingrp_subtlv *top =
		(struct ri_fad_include_all_admingrp_subtlv *)tlvh;
	json_object *admngrps_json = NULL;
	struct admin_group grp = { 0 };

	check_tlv_min_size(RI_FAD_INCALL_ADMINGRP_SUBTLV_MIN_LEN,
			   "FAD Include All Admin Groups");
	check_tlv_size_multiple_of(sizeof(uint32_t),
				   "FAD Include All Admin Groups");

	flex_algo_decode_admin_group(&grp, (uint8_t *)top->admin_groups,
				     ntohs(tlvh->length));
	if (json) {
		tlvh_get_json_values(tlvh, json, "Include-All Admin Groups SubTLV");
		admngrps_json = json_object_new_array();
		json_object_object_add(json, "adminGroups", admngrps_json);
	} else if (vty != NULL) {
		vty_out(vty, "    FAD Include-All Admin Groups: \n");
	}

	show_vty_admin_groups(vty, &grp, admngrps_json, true);

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_fad_exc_srlg(struct vty *vty, struct tlv_header *tlvh,
				      json_object *json)
{
	struct ri_fad_exclude_srlg_subtlv *top =
		(struct ri_fad_exclude_srlg_subtlv *)tlvh;
	json_object *srlgs_json = NULL;
	struct admin_group grp = { 0 };

	check_tlv_min_size(RI_FAD_EXC_SRLG_SUBTLV_MIN_LEN, "FAD Exclude SRLGs");
	check_tlv_size_multiple_of(sizeof(uint32_t), "FAD Exclude SRLGs");

	flex_algo_decode_admin_group(&grp, (uint8_t *)top->srlgs,
				     ntohs(tlvh->length));
	if (json) {
		tlvh_get_json_values(tlvh, json, "Exclude SRLGs SubTLV");
		srlgs_json = json_object_new_array();
		json_object_object_add(json, "srlgs", srlgs_json);
	} else if (vty != NULL) {
		vty_out(vty, "    FAD Exclude SRLGs: \n");
	}

	show_vty_admin_groups(vty, &grp, srlgs_json, false);

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_fad_flags(struct vty *vty, struct tlv_header *tlvh,
				   json_object *json)
{
	struct ri_fad_flags_subtlv *top = (struct ri_fad_flags_subtlv *)tlvh;
	uint16_t num_flags = ntohs(tlvh->length) / sizeof(top->flags[0]);
	uint16_t indx;
	json_object *flags_json = NULL;
	json_object *flag_json = NULL;

	check_tlv_min_size(RI_FAD_FLAGS_SUBTLV_MIN_LEN, "FAD Flags");
	check_tlv_size_multiple_of(sizeof(uint8_t), "FAD Flags");

	if (json) {
		tlvh_get_json_values(tlvh, json, "Flexible-Algo Flags SubTLV");
		flags_json = json_object_new_array();
		json_object_object_add(json, "flags", flags_json);
		for (indx = 0; indx < num_flags; indx++) {
			flag_json = json_object_new_int64(
				(int64_t)ntohl(top->flags[indx]));
			json_object_array_add(flags_json, flag_json);
		}
	} else if (vty != NULL) {
		vty_out(vty, "    FAD Flags: \n");
		for (indx = 0; indx < num_flags; indx++) {
			if (!(indx % 16))
				vty_out(vty, "      [ 0x%02x",
					ntohl(top->flags[indx]));
			else if (!(indx % 15))
				vty_out(vty, ", 0x%02x ]\n",
					ntohl(top->flags[indx]));
			else
				vty_out(vty, ", 0x%02x",
					ntohl(top->flags[indx]));
		}
		if ((indx % 15))
			vty_out(vty, " ]\n");
	} else {
		char list_str[1024] = {0};
		char disp_str[32];

		zlog_debug("    FAD Flags:");
		for (indx = 0; indx < num_flags; indx++) {
			snprintf(disp_str, sizeof(disp_str), "0x%02x ",
				 ntohl(top->flags[indx]));
			strlcat(list_str, disp_str, sizeof(list_str));
			if (!(indx % 15)) {
				zlog_debug("      %s", list_str);
				list_str[0] = '\0';
			}
		}
		zlog_debug("      %s", list_str);
	}

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_fad_info(struct vty *vty, struct tlv_header *ri,
				  size_t buf_size, json_object *json)
{
	struct tlv_header *tlvh = ri;
	uint16_t length = ntohs(tlvh->length);
	uint16_t sum = 0;
	struct ri_fad_tlv *fad_tlv = (struct ri_fad_tlv *)tlvh;
	uint8_t *tlv_start = (uint8_t *)ri;
	json_object *stlvs_json = NULL;
	json_object *stlv_json = NULL;

	/* Verify that TLV length is valid against remaining buffer size */
	if (length > buf_size) {
		vty_out(vty, "  FAD TLV size %d exceeds buffer size. Abort!\n",
			length);
		return buf_size;
	}

	check_tlv_min_size(RI_FAD_TLV_MIN_LEN, "Flexible Algorithm Definition");

	if (json) {
		tlvh_get_json_values(tlvh, json,
				     "Flexible Algorithm Defintion TLV");
		json_object_int_add(json, "algorithmId",
				    (int64_t)fad_tlv->algorithm_id);
		json_object_int_add(json, "priority",
				    (int64_t)fad_tlv->priority);
		json_object_string_add(
			json, "metricType",
			flex_algo_metric_type2str(fad_tlv->metric_type));
		json_object_string_add(
			json, "caculationType",
			flex_algo_calc_type2str(fad_tlv->calc_type));
		stlvs_json = json_object_new_array();
		json_object_object_add(json, "subTLVs", stlvs_json);
	} else if (vty != NULL) {
		vty_out(vty,
			"  Flexible Algorithm Defintion TLV: Length: %u\n"
			"    Algorithm-Identifier = %d\n"
			"    Priority = %d\n"
			"    Metric-Type = %s\n"
			"    Calculation-Type = %s\n",
			ntohs(fad_tlv->header.length), fad_tlv->algorithm_id,
			fad_tlv->priority,
			flex_algo_metric_type2str(fad_tlv->metric_type),
			flex_algo_calc_type2str(fad_tlv->calc_type));
	} else {
		zlog_debug(
			"  Flexible Algorithm Defintion TLV: Algorithm-Identifier = %d",
			fad_tlv->algorithm_id);
		zlog_debug(
			"    Priority = %d, Metric-Type = %s, Calculation-Type = %s",
			fad_tlv->priority,
			flex_algo_metric_type2str(fad_tlv->metric_type),
			flex_algo_calc_type2str(fad_tlv->calc_type));
	}

	tlv_start += RI_FAD_TLV_MIN_LEN + TLV_HDR_SIZE;
	sum += RI_FAD_TLV_MIN_LEN;
	for (tlvh = (struct tlv_header *)tlv_start; sum < length;
	     tlvh = TLV_HDR_NEXT(tlvh)) {
		if (stlvs_json) {
			stlv_json = json_object_new_object();
			json_object_array_add(stlvs_json, stlv_json);
		}

		switch (ntohs(tlvh->type)) {
		case RI_FAD_EXC_ADMINGRP_SUBTLV:
			sum += show_vty_fad_exc_admngrp(vty, tlvh, stlv_json);
			break;
		case RI_FAD_INCANY_ADMINGRP_SUBTLV:
			sum += show_vty_fad_incany_admngrp(vty, tlvh,
							   stlv_json);
			break;
		case RI_FAD_INCALL_ADMINGRP_SUBTLV:
			sum += show_vty_fad_incall_admngrp(vty, tlvh,
							   stlv_json);
			break;
		case RI_FAD_FLAGS_SUBTLV:
			sum += show_vty_fad_flags(vty, tlvh, stlv_json);
			break;
		case RI_FAD_EXC_SRLG_SUBTLV:
			sum += show_vty_fad_exc_srlg(vty, tlvh, stlv_json);
			break;
		default:
			sum += show_vty_unknown_tlv(vty, tlvh, length - sum,
						    stlv_json);
			break;
		}
	}

	return TLV_SIZE(&fad_tlv->header);
}

static void ospf_router_info_show_info(struct vty *vty,
				       struct json_object *json,
				       struct ospf_lsa *lsa)
{
	struct lsa_header *lsah = lsa->data;
	struct tlv_header *tlvh;
	uint16_t length = 0, sum = 0;
	json_object *tlvs_json = NULL;
	json_object *tlv_json = NULL;

	if (json) {
		tlvs_json = json_object_new_array();
		json_object_object_add(json, "tlvs", tlvs_json);
	}

	/* Initialize TLV browsing */
	length = lsa->size - OSPF_LSA_HEADER_SIZE;

	for (tlvh = TLV_HDR_TOP(lsah); sum < length && tlvh;
	     tlvh = TLV_HDR_NEXT(tlvh)) {
		if (tlvs_json) {
			tlv_json = json_object_new_object();
			json_object_array_add(tlvs_json, tlv_json);
		}

		switch (ntohs(tlvh->type)) {
		case RI_TLV_CAPABILITIES:
			sum += show_vty_router_cap(vty, tlvh, tlv_json);
			break;
		case RI_TLV_PCE:
			tlvh++;
			sum += TLV_HDR_SIZE;
			sum += show_vty_pce_info(vty, tlvh, length - sum,
						 tlv_json);
			break;
		case RI_SR_TLV_SR_ALGORITHM:
			sum += show_vty_sr_algorithm(vty, tlvh, tlv_json);
			break;
		case RI_SR_TLV_SRGB_LABEL_RANGE:
		case RI_SR_TLV_SRLB_LABEL_RANGE:
			sum += show_vty_sr_range(vty, tlvh, tlv_json);
			break;
		case RI_SR_TLV_NODE_MSD:
			sum += show_vty_sr_msd(vty, tlvh, tlv_json);
			break;
		case RI_FAD_TLV:
			sum += show_vty_fad_info(vty, tlvh, length - sum,
						 tlv_json);
			break;

		default:
			sum += show_vty_unknown_tlv(vty, tlvh, length,
						    tlv_json);
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
	struct flex_algo *fad;
	struct listnode *curr, *next;
	uint32_t admin_grp, srlg;

	if (!OspfRI.enabled)
		return;

	if (OspfRI.scope == OSPF_OPAQUE_AS_LSA)
		vty_out(vty, " router-info as\n");
	else
		vty_out(vty, " router-info area\n");

	if (OspfRI.pce_info.enabled) {

		if (pce->pce_address.header.type != 0)
			vty_out(vty, "  pce address %pI4\n",
				&pce->pce_address.address.value);

		if (pce->pce_cap_flag.header.type != 0)
			vty_out(vty, "  pce flag 0x%x\n",
				ntohl(pce->pce_cap_flag.value));

		for (ALL_LIST_ELEMENTS_RO(pce->pce_domain, node, domain)) {
			if (domain->header.type != 0) {
				if (domain->type == PCE_DOMAIN_TYPE_AREA) {
					tmp.s_addr = domain->value;
					vty_out(vty, "  pce domain area %pI4\n",
						&tmp);
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
					vty_out(vty,
						"  pce neighbor area %pI4\n",
						&tmp);
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

	FOREACH_FLEX_ALGO_DEFN (OspfRI.fad_info.fads, curr, next, fad) {
		vty_out(vty, " flexible-algorithm %u\n", fad->algorithm);
		if (fad->metric_type != MT_DEFAULT)
			vty_out(vty, " flexible-algorithm %u metric-type %s\n", fad->algorithm,
				flex_algo_metric_type2str(fad->metric_type));
		if (fad->calc_type != CALC_TYPE_DEFAULT)
			vty_out(vty, " flexible-algorithm %u calculation-type %s\n",
				fad->algorithm, flex_algo_calc_type2str(fad->calc_type));
		if (fad->priority != FLEX_ALGO_PRIO_DEFAULT)
			vty_out(vty, " flexible-algorithm %u priority %u\n", fad->algorithm,
				fad->priority);
		FOREACH_FLEX_ALGO_ADMIN_GROUP (&fad->admin_group_exclude_any, admin_grp) {
			vty_out(vty,
				" flexible-algorithm %u exclude-admin-group %s\n",
				fad->algorithm, affinity_map_name_get((int)admin_grp));
		}
		FOREACH_FLEX_ALGO_ADMIN_GROUP (&fad->admin_group_include_all,
					       admin_grp) {
			vty_out(vty,
				" flexible-algorithm %u include-all-admin-group %s\n",
				fad->algorithm, affinity_map_name_get((int)admin_grp));
		}
		FOREACH_FLEX_ALGO_ADMIN_GROUP (&fad->admin_group_include_any,
					       admin_grp) {
			vty_out(vty,
				" flexible-algorithm %u include-any-admin-group %s\n",
				fad->algorithm, affinity_map_name_get((int)admin_grp));
		}
		FOREACH_FLEX_ALGO_SRLG (&fad->srlgs_exclude, srlg) {
			vty_out(vty, " flexible-algorithm %u exclude-srlg %u\n",
				fad->algorithm, srlg);
		}
		if (FLEX_ALGO_PREFIX_METRIC_SET(fad)) {
			vty_out(vty,
				" flexible-algorithm %u advertise-prefix-metric %u\n",
				fad->algorithm, fad->prefix_adv_metric);
		}
	}

	return;
}

/* 
 * Schedule RI LSA action in function of the scope
 */
void ospf_router_info_schedule(enum lsa_opcode opcode)
{
	struct listnode *node, *nnode;
	struct ospf_ri_area_info *ai;

	if (OspfRI.scope == OSPF_OPAQUE_AS_LSA) {
		if (CHECK_FLAG(OspfRI.as_flags, RIFLG_LSA_ENGAGED))
			ospf_router_info_lsa_schedule(NULL, opcode);
		else if (opcode == REORIGINATE_THIS_LSA)
			ospf_router_info_lsa_schedule(NULL, opcode);
	} else {
		for (ALL_LIST_ELEMENTS(OspfRI.area_info, node, nnode, ai)) {
			if (CHECK_FLAG(ai->flags, RIFLG_LSA_ENGAGED))
				ospf_router_info_lsa_schedule(ai, opcode);
		}
	}
}

/*------------------------------------------------------------------------*
 * Following are vty command functions.
 *------------------------------------------------------------------------*/
DEFUN (router_info,
       router_info_area_cmd,
       "router-info <as|area [A.B.C.D]>",
       OSPF_RI_STR
       "Enable the Router Information functionality with AS flooding scope\n"
       "Enable the Router Information functionality with Area flooding scope\n"
       "OSPF area ID in IP format (deprecated)\n")
{
	int idx_mode = 1;
	uint8_t scope;
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (OspfRI.enabled)
		return CMD_SUCCESS;

	/* Check that the OSPF is using default VRF */
	if (ospf->vrf_id != VRF_DEFAULT) {
		vty_out(vty,
			"Router Information is only supported in default VRF\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Check and get Area value if present */
	if (strncmp(argv[idx_mode]->arg, "as", 2) == 0)
		scope = OSPF_OPAQUE_AS_LSA;
	else
		scope = OSPF_OPAQUE_AREA_LSA;

	/* First start to register Router Information callbacks */
	if (!OspfRI.registered && (ospf_router_info_register(scope)) != 0) {
		vty_out(vty,
			"%% Unable to register Router Information callbacks.");
		flog_err(
			EC_OSPF_INIT_FAIL,
			"RI (%s): Unable to register Router Information callbacks. Abort!",
			__func__);
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

	/* Originate or Refresh RI LSA if already engaged */
	ospf_router_info_schedule(REORIGINATE_THIS_LSA);
	return CMD_SUCCESS;
}

DEFUN (no_router_info,
       no_router_info_cmd,
       "no router-info",
       NO_STR
       "Disable the Router Information functionality\n")
{
	struct flex_algo *fad;
	struct listnode *curr, *next;

	if (!OspfRI.enabled)
		return CMD_SUCCESS;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("RI-> Router Information: ON -> OFF");

	/* Remove all Flexible-Algo-Defns from DB. */
	FOREACH_FLEX_ALGO_DEFN (OspfRI.fad_info.fads, curr, next, fad) {
		flex_algo_delete(OspfRI.fad_info.fads, fad->algorithm);;
	}

	ospf_router_info_schedule(FLUSH_THIS_LSA);

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
		ospf_router_info_schedule(REFRESH_THIS_LSA);
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
	ospf_router_info_schedule(REFRESH_THIS_LSA);

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
		ospf_router_info_schedule(REFRESH_THIS_LSA);
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
	ospf_router_info_schedule(REFRESH_THIS_LSA);

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
	ospf_router_info_schedule(REFRESH_THIS_LSA);

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
	ospf_router_info_schedule(REFRESH_THIS_LSA);

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
	ospf_router_info_schedule(REFRESH_THIS_LSA);

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
	ospf_router_info_schedule(REFRESH_THIS_LSA);

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
		ospf_router_info_schedule(REFRESH_THIS_LSA);
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
	ospf_router_info_schedule(REFRESH_THIS_LSA);

	return CMD_SUCCESS;
}

DEFPY(flex_algo_defn, flex_algo_defn_cmd,
      "[no$no] flexible-algorithm (128-255)$id",
      NO_STR
      "Specify a Flexible Algorithm Definition\n"
      "Unique number assigned to the Flexible Algorithm\n")
{
	struct flex_algo *fad;
	bool update_lsa = false;

	fad = flex_algo_lookup(OspfRI.fad_info.fads, (uint8_t)id);
	if (!no && !fad) {
		fad = flex_algo_alloc(OspfRI.fad_info.fads, (uint8_t)id, NULL);
		assert(fad);
		OspfRI.fad_info.num_fads++;
		/* Refresh RI LSA if already engaged */
		update_lsa = true;
	}

	if (no && fad) {
		flex_algo_delete(OspfRI.fad_info.fads, fad->algorithm);;
		OspfRI.fad_info.num_fads--;
		/* Refresh RI LSA if already engaged */
		update_lsa = true;
	}

	/* Re-originate RI LSA if required */
	if (update_lsa)
		ospf_router_info_schedule(REFRESH_THIS_LSA);

	if (!fad)
		return CMD_ERR_NO_MATCH;


	return CMD_SUCCESS;
}

DEFPY(flex_algo_metric_type, flex_algo_metric_type_cmd,
      "[no$no] flexible-algorithm (128-255)$id metric-type [<igp>$typestr]",
      NO_STR
      "Specify a Flexible Algorithm Definition\n"
      "Unique number assigned to the new Flexible Algorithm\n"
      "Metric type to be used for the Flexible Algorithm\n"
      "IGP metric type\n")
{
	enum flex_algo_metric_type metric_type;
	struct flex_algo *fad;
	bool update_lsa = false;

	if (!ospf_ri_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	if (no)
		metric_type = MT_DEFAULT;
	else {
		if (!typestr)
			return CMD_ERR_INCOMPLETE;
		metric_type = flex_algo_str2metric_type(typestr);
		if (metric_type < MT_MIN || metric_type >= MT_MAX)
			return CMD_ERR_NO_MATCH;
	}

	fad = flex_algo_lookup(OspfRI.fad_info.fads, (uint8_t)id);
	if (!no && !fad) {
		fad = flex_algo_alloc(OspfRI.fad_info.fads, (uint8_t)id, NULL);
		assert(fad);
		OspfRI.fad_info.num_fads++;
		/* Refresh RI LSA if already engaged */
		update_lsa = true;
	}

	if (no && !fad)
		return CMD_ERR_NO_MATCH;

	if (fad->metric_type != metric_type) {
		fad->metric_type = metric_type;
		update_lsa = true;
	}

	/* Refresh/Re-originate RI LSA if already engaged */
	if (update_lsa)
		ospf_router_info_schedule(REFRESH_THIS_LSA);

	return CMD_SUCCESS;
}

DEFPY(flex_algo_calc_type, flex_algo_calc_type_cmd,
      "[no$no] flexible-algorithm (128-255)$id calculation-type [<spf>$typestr]",
      NO_STR
      "Specify a Flexible Algorithm Definition\n"
      "Unique number assigned to the new Flexible Algorithm\n"
      "Calculation type to be used for the Flexible Algorithm\n"
      "Shortest Path First\n")
{
	enum flex_algo_calc_type calc_type;
	struct flex_algo *fad;
	bool update_lsa = false;

	if (!ospf_ri_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	if (no)
		calc_type = CALC_TYPE_DEFAULT;
	else {
		if (!typestr)
			return CMD_ERR_INCOMPLETE;
		calc_type = flex_algo_str2calc_type(typestr);
		if (calc_type < CALC_TYPE_MIN ||
			calc_type < CALC_TYPE_MIN)
			return CMD_ERR_NO_MATCH;
	}

	fad = flex_algo_lookup(OspfRI.fad_info.fads, (uint8_t)id);
	if (!no && !fad) {
		fad = flex_algo_alloc(OspfRI.fad_info.fads, (uint8_t)id, NULL);
		assert(fad);
		OspfRI.fad_info.num_fads++;
		/* Refresh RI LSA if already engaged */
		update_lsa = true;
	}

	if (no && !fad)
		return CMD_ERR_NO_MATCH;

	if (fad->calc_type != calc_type) {
		fad->calc_type = calc_type;
		update_lsa = true;
	}

	/* Refresh/Re-originate RI LSA if already engaged */
	if (update_lsa)
		ospf_router_info_schedule(REFRESH_THIS_LSA);

	return CMD_SUCCESS;
}

DEFPY(flex_algo_priority, flex_algo_priority_cmd,
      "[no$no] flexible-algorithm (128-255)$id priority [(0-4294967295)$prio]",
      NO_STR
      "Specify a Flexible Algorithm Definition\n"
      "Unique number assigned to the new Flexible Algorithm\n"
      "Assign a priority to be used for the Flexible Algorithm\n"
      "Priority to be used for the Flexible Algorithm\n")
{
	struct flex_algo *fad;
	bool update_lsa = false;

	if (!ospf_ri_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	if (no)
		prio = FLEX_ALGO_PRIO_DEFAULT;
	else {
		if (prio > FLEX_ALGO_PRIO_MAX)
			return CMD_ERR_NO_MATCH;
	}

	fad = flex_algo_lookup(OspfRI.fad_info.fads, (uint8_t)id);
	if (!no && !fad) {
		fad = flex_algo_alloc(OspfRI.fad_info.fads, (uint8_t)id, NULL);
		assert(fad);
		OspfRI.fad_info.num_fads++;
		/* Refresh RI LSA if already engaged */
		update_lsa = true;
	}

	if (no && !fad)
		return CMD_ERR_NO_MATCH;

	if (fad->priority != (uint8_t)prio) {
		fad->priority = (uint8_t)prio;
		update_lsa = true;
	}

	/* Refresh/Re-originate RI LSA if already engaged */
	if (update_lsa)
		ospf_router_info_schedule(REFRESH_THIS_LSA);

	return CMD_SUCCESS;
}

static int ospf_flex_algo_admin_group_update(
	bool delete, struct admin_group *admin_group,
	const char *name, bool update_lsa)
{
	struct affinity_map *map = NULL;
	int found_ag = 0;
	uint32_t bitpos;

	if (!delete && !name) 
		return CMD_ERR_INCOMPLETE;
	
	if (name)
		map = affinity_map_get(name);
	if (name && !map) {
		zlog_err("Couldn't find any affinity by name '%s'", name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (map)
		found_ag = admin_group_get(admin_group, map->bit_position);
	if (!delete) {
		if (map && !found_ag) {
			admin_group_set(admin_group,
					map->bit_position);
			/* Refresh RI LSA if already engaged */
			update_lsa = true;
		}
	} else {
		if (!found_ag && name)
			return CMD_ERR_NO_MATCH;

		if (!name)
			FOREACH_FLEX_ALGO_ADMIN_GROUP(admin_group, bitpos)
				admin_group_unset(admin_group, bitpos);
		else if(map)
			admin_group_unset(admin_group,
					  map->bit_position);

		/* Refresh RI LSA if already engaged */
		update_lsa = true;
	}

	/* Refresh/Re-originate RI LSA if already engaged */
	if (update_lsa)
		ospf_router_info_schedule(REFRESH_THIS_LSA);

	return CMD_SUCCESS;
}

DEFPY(flex_algo_exc_admngrp, flex_algo_exc_admngrp_cmd,
      "[no$no] flexible-algorithm (128-255)$id exclude-admin-group [NAME$name]",
      NO_STR
      "Specify a Flexible Algorithm Definition\n"
      "Unique number assigned to the new Flexible Algorithm\n"
      "Add a Admin-Group to the Exclude list\n"
      "Name of the admin group to be added(or deleted)\n")
{
	struct flex_algo *fad;
	bool update_lsa = false;

	if (!ospf_ri_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	fad = flex_algo_lookup(OspfRI.fad_info.fads, (uint8_t)id);
	if (!no && !fad) {
		fad = flex_algo_alloc(OspfRI.fad_info.fads, (uint8_t)id, NULL);
		assert(fad);
		OspfRI.fad_info.num_fads++;
		/* Refresh RI LSA if already engaged */
		update_lsa = true;
	}

	if (no && !fad)
		return CMD_ERR_NO_MATCH;

	return ospf_flex_algo_admin_group_update(no ? true : false,
			&fad->admin_group_exclude_any, name, update_lsa);
}

DEFPY(flex_algo_incall_admngrp, flex_algo_incall_admngrp_cmd,
      "[no$no] flexible-algorithm (128-255)$id include-all-admin-group [NAME$name]",
      NO_STR
      "Specify a Flexible Algorithm Definition\n"
      "Unique number assigned to the new Flexible Algorithm\n"
      "Add a Admin-Group to the Include-All list\n"
      "Name of the admin group to be added(or deleted)\n")
{
	struct flex_algo *fad;
	bool update_lsa = false;

	if (!ospf_ri_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	fad = flex_algo_lookup(OspfRI.fad_info.fads, (uint8_t)id);
	if (!no && !fad) {
		fad = flex_algo_alloc(OspfRI.fad_info.fads, (uint8_t)id, NULL);
		assert(fad);
		OspfRI.fad_info.num_fads++;
		/* Refresh RI LSA if already engaged */
		update_lsa = true;
	}

	if (no && !fad)
		return CMD_ERR_NO_MATCH;

	return ospf_flex_algo_admin_group_update(no ? true : false,
			&fad->admin_group_include_all, name, update_lsa);
}

DEFPY(flex_algo_incany_admngrp, flex_algo_incany_admngrp_cmd,
      "[no$no] flexible-algorithm (128-255)$id include-any-admin-group [NAME$name]",
      NO_STR
      "Specify a Flexible Algorithm Definition\n"
      "Unique number assigned to the new Flexible Algorithm\n"
      "Add a Admin-Group to the Include-Any list\n"
      "Name of the admin group to be added (or deleted)\n")
{
	struct flex_algo *fad;
	bool update_lsa = false;

	if (!ospf_ri_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	fad = flex_algo_lookup(OspfRI.fad_info.fads, (uint8_t)id);
	if (!no && !fad) {
		fad = flex_algo_alloc(OspfRI.fad_info.fads, (uint8_t)id, NULL);
		assert(fad);
		OspfRI.fad_info.num_fads++;
		/* Refresh RI LSA if already engaged */
		update_lsa = true;
	}

	if (no && !fad)
		return CMD_ERR_NO_MATCH;

	return ospf_flex_algo_admin_group_update(no ? true : false,
			&fad->admin_group_include_any, name, update_lsa);
}

DEFPY(flex_algo_exc_srlg, flex_algo_exc_srlg_cmd,
      "[no$no] flexible-algorithm (128-255)$id exclude-srlg [(0-4294967295)$srlgval]",
      NO_STR
      "Specify a Flexible Algorithm Definition\n"
      "Unique number assigned to the new Flexible Algorithm\n"
      "Add or remove a SRLG to or from the Exclude list\n"
      "SRLG to be added or removed\n")
{
	struct flex_algo *fad;
	int found_srlg;
	uint32_t bitpos;

	bool update_lsa = false;

	if (!ospf_ri_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	fad = flex_algo_lookup(OspfRI.fad_info.fads, (uint8_t)id);
	if (!no && !fad) {
		fad = flex_algo_alloc(OspfRI.fad_info.fads, (uint8_t)id, NULL);
		assert(fad);
		OspfRI.fad_info.num_fads++;
		/* Refresh RI LSA if already engaged */
		update_lsa = true;
	}

	if (no && !fad)
		return CMD_ERR_NO_MATCH;

	bitpos = (uint32_t) srlgval;
	found_srlg = admin_group_get(&fad->srlgs_exclude, bitpos);
	if (!no) {
		if (!found_srlg) {
			admin_group_set(&fad->srlgs_exclude, bitpos);
			/* Refresh RI LSA if already engaged */
			update_lsa = true;
		}
	} else {
		if (argc < 5)
			FOREACH_FLEX_ALGO_SRLG(&fad->srlgs_exclude, bitpos)
				admin_group_unset(&fad->srlgs_exclude, bitpos);
		else {
			if (!found_srlg)
				return CMD_ERR_NO_MATCH;

			admin_group_unset(&fad->srlgs_exclude, bitpos);
		}

		/* Refresh RI LSA if already engaged */
		update_lsa = true;
	}

	/* Refresh/Re-originate RI LSA if already engaged */
	if (update_lsa)
		ospf_router_info_schedule(REFRESH_THIS_LSA);

	return CMD_SUCCESS;
}

DEFPY(flex_algo_prfx_metric, flex_algo_prfx_metric_cmd,
      "[no$no] flexible-algorithm (128-255)$id advertise-prefix-metric [(0-4294967295)$prefmetric]",
      NO_STR
      "Specify a Flexible Algorithm Definition\n"
      "Unique number assigned to the new Flexible Algorithm\n"
      "Advertise prefix metric TLV\n"
      "Specify the metric to override all individual prefix metric with\n")
{
	uint32_t metric;
	struct flex_algo *fad;
	bool update_lsa = false;

	if (!ospf_ri_enabled(vty))
		return CMD_WARNING_CONFIG_FAILED;

	fad = flex_algo_lookup(OspfRI.fad_info.fads, (uint8_t)id);
	if (!no && !fad) {
		fad = flex_algo_alloc(OspfRI.fad_info.fads, (uint8_t)id, NULL);
		assert(fad);
		OspfRI.fad_info.num_fads++;
		/* Refresh RI LSA if already engaged */
		update_lsa = true;
	}

	if (no && !fad)
		return CMD_ERR_NO_MATCH;

	if (!no) {
		metric = prefmetric ? (uint32_t)prefmetric
			: fad->prefix_adv_metric;

		if (!FLEX_ALGO_PREFIX_METRIC_SET(fad) ||
			fad->prefix_adv_metric != metric) {
			flex_algo_set_prefix_metric(fad, metric);
			update_lsa = true;
		}
	} else if (FLEX_ALGO_PREFIX_METRIC_SET(fad)) {
		flex_algo_reset_prefix_metric(fad);
		update_lsa = true;
	}

	/*
	 * Refresh/Re-originate the Router-Info LSA along with
	 * all the EXT Prefix LSAs if already engaged.
	 */
	if (update_lsa)
		ospf_router_info_schedule(REFRESH_THIS_LSA);

	return CMD_SUCCESS;
}

DEFUN(show_ip_ospf_router_info, show_ip_ospf_router_info_cmd,
      "show ip ospf router-info",
      SHOW_STR IP_STR OSPF_STR "Router Information\n")
{

	if (OspfRI.enabled) {
		vty_out(vty, "--- Router Information parameters ---\n");
		show_vty_router_cap(vty, &OspfRI.router_cap.header, NULL);
	} else {
		if (vty != NULL)
			vty_out(vty,
				"  Router Information is disabled on this router\n");
	}
	return CMD_SUCCESS;
}

DEFUN(show_ip_opsf_router_info_pce, show_ip_ospf_router_info_pce_cmd,
      "show ip ospf router-info pce",
      SHOW_STR IP_STR OSPF_STR
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
			show_vty_pce_subtlv_address(
				vty, &pce->pce_address.header, NULL);

		if (pce->pce_scope.header.type != 0)
			show_vty_pce_subtlv_path_scope(
				vty, &pce->pce_scope.header, NULL);

		for (ALL_LIST_ELEMENTS_RO(pce->pce_domain, node, domain)) {
			if (domain->header.type != 0)
				show_vty_pce_subtlv_domain(vty, &domain->header,
							   NULL);
		}

		for (ALL_LIST_ELEMENTS_RO(pce->pce_neighbor, node, neighbor)) {
			if (neighbor->header.type != 0)
				show_vty_pce_subtlv_neighbor(
					vty, &neighbor->header, NULL);
		}

		if (pce->pce_cap_flag.header.type != 0)
			show_vty_pce_subtlv_cap_flag(
				vty, &pce->pce_cap_flag.header, NULL);

	} else {
		vty_out(vty, "  PCE info is disabled on this router\n");
	}

	return CMD_SUCCESS;
}

static void show_vty_flxalg_info(struct vty *vty, struct flex_algo *fad)
{
	uint32_t admin_grp;
	uint32_t srlg;
	const char *name;

	vty_out(vty, " Flexible-Algorithm: %u\n", fad->algorithm);
	vty_out(vty, "  Metric-Type: \t%s\n",
		flex_algo_metric_type2str(fad->metric_type));
	vty_out(vty, "  Calculation-Type: \t%s\n",
		flex_algo_calc_type2str(fad->calc_type));
	vty_out(vty, "  Priority: \t%u\n", fad->priority);
	vty_out(vty, "  Flags: \t0x%02x\n", fad->flags);
	vty_out(vty, "  Advt-Prefix-Metric: \t%s\n",
		FLEX_ALGO_PREFIX_METRIC_SET(fad) ? "Y" : "N");
	if (FLEX_ALGO_PREFIX_METRIC_SET(fad))
		vty_out(vty, "    Prefix-Metric: \t%u\n",
			fad->prefix_adv_metric);

	if (admin_group_size(&fad->admin_group_exclude_any)) {
		vty_out(vty, "  Exclude-Admin-Groups: \n");
		FOREACH_FLEX_ALGO_ADMIN_GROUP(&fad->admin_group_exclude_any, admin_grp)
		{
			name = affinity_map_name_get(admin_grp);
			vty_out(vty, "  \t - %s(%u)\n", name ? name : "Unknown",
				admin_grp);
		}
	}

	if (admin_group_size(&fad->admin_group_include_any)) {
		vty_out(vty, "  Include-Any-Admin-Groups: \n");
		FOREACH_FLEX_ALGO_ADMIN_GROUP (&fad->admin_group_include_any,
					       admin_grp) {
			name = affinity_map_name_get(admin_grp);
			vty_out(vty, "  \t - %s(%u)\n", name ? name : "Unknown",
				admin_grp);
		}
	}

	if (admin_group_size(&fad->admin_group_include_all)) {
		vty_out(vty, "  Include-All-Admin-Groups: \n");
		FOREACH_FLEX_ALGO_ADMIN_GROUP (&fad->admin_group_include_all,
					       admin_grp) {
			name = affinity_map_name_get(admin_grp);
			vty_out(vty, "  \t - %s(%u)\n", name ? name : "Unknown",
				admin_grp);
		}
	}

	if (admin_group_size(&fad->srlgs_exclude)) {
		vty_out(vty, "  Exclude-SRLGs: \n");
		FOREACH_FLEX_ALGO_SRLG (&fad->srlgs_exclude, srlg) {
			vty_out(vty, "  \t - %u\n", srlg);
		}
	}
}

DEFPY(show_ip_opsf_router_info_flxalg, show_ip_ospf_router_info_flxalg_cmd,
      "show ip ospf router-info flexible-algorithms [(128-255)$id]",
      SHOW_STR IP_STR OSPF_STR
      "Router Information\n"
      "Flexible-Algorithm information\n"
      "Unique identifier assigned to the Flexible-Algorithm\n")
{
	struct flex_algo *fad;
	struct listnode *curr, *next;

	if ((OspfRI.enabled) && !flex_algos_empty(OspfRI.fad_info.fads)) {
		if (!id) {
			vty_out(vty, "--- Flexible-Algorithm parameters ---\n");

			FOREACH_FLEX_ALGO_DEFN (OspfRI.fad_info.fads, curr, next, fad) {
				show_vty_flxalg_info(vty, fad);
			}
		} else {
			if (id < FLEX_ALGO_ALGO_MIN || id > FLEX_ALGO_ALGO_MAX) {
				vty_out(vty, " Invalid algorithm identifier '%ld'!\n", id);
				return CMD_SUCCESS;
			}

			fad = flex_algo_lookup(OspfRI.fad_info.fads, (uint32_t)id);
			if (!fad) {
				vty_out(vty, "No such Flexible algorithm '%ld'!\n", id);
			} else {
				show_vty_flxalg_info(vty, fad);
			}
		}
	} else {
		vty_out(vty, "  No Flexible-Algoritthms on this router\n");
	}

	return CMD_SUCCESS;
}

/* Install new CLI commands */
static void ospf_router_info_register_vty(void)
{
	install_element(VIEW_NODE, &show_ip_ospf_router_info_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_router_info_pce_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_router_info_flxalg_cmd);

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
	install_element(OSPF_NODE, &flex_algo_defn_cmd);
	install_element(OSPF_NODE, &flex_algo_metric_type_cmd);
	install_element(OSPF_NODE, &flex_algo_calc_type_cmd);
	install_element(OSPF_NODE, &flex_algo_priority_cmd);
	install_element(OSPF_NODE, &flex_algo_exc_admngrp_cmd);
	install_element(OSPF_NODE, &flex_algo_incany_admngrp_cmd);
	install_element(OSPF_NODE, &flex_algo_incall_admngrp_cmd);
	install_element(OSPF_NODE, &flex_algo_exc_srlg_cmd);
	install_element(OSPF_NODE, &flex_algo_prfx_metric_cmd);

	return;
}
