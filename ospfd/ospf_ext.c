/*
 * This is an implementation of RFC7684 OSPFv2 Prefix/Link Attribute
 * Advertisement
 *
 * Module name: Extended Prefix/Link Opaque LSA
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 * Author: Anselme Sawadogo <anselmesawadogo@gmail.com>
 *
 * Copyright (C) 2016 - 2018 Orange Labs http://www.orange.com
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
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

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
#include "network.h"
#include "if.h"
#include "libospf.h" /* for ospf interface types */

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
#include "ospfd/ospf_ext.h"

/* Following structure are internal use only. */

/*
 * Global variable to manage Extended Prefix/Link Opaque LSA on this node.
 * Note that all parameter values are stored in network byte order.
 */
static struct ospf_ext_lp OspfEXT;

/*
 * -----------------------------------------------------------------------
 * Followings are initialize/terminate functions for Extended Prefix/Link
 * Opaque LSA handling.
 * -----------------------------------------------------------------------
 */

/* Extended Prefix Opaque LSA related callback functions */
static void ospf_ext_pref_ism_change(struct ospf_interface *oi, int old_status);
static void ospf_ext_pref_show_info(struct vty *vty, struct ospf_lsa *lsa);
static int ospf_ext_pref_lsa_originate(void *arg);
static struct ospf_lsa *ospf_ext_pref_lsa_refresh(struct ospf_lsa *lsa);
static void ospf_ext_pref_lsa_schedule(struct ext_itf *exti,
				       enum lsa_opcode opcode);
/* Extended Link Opaque LSA related callback functions */
static int ospf_ext_link_new_if(struct interface *ifp);
static int ospf_ext_link_del_if(struct interface *ifp);
static void ospf_ext_link_ism_change(struct ospf_interface *oi, int old_status);
static void ospf_ext_link_nsm_change(struct ospf_neighbor *nbr, int old_status);
static void ospf_ext_link_show_info(struct vty *vty, struct ospf_lsa *lsa);
static int ospf_ext_link_lsa_originate(void *arg);
static struct ospf_lsa *ospf_ext_link_lsa_refresh(struct ospf_lsa *lsa);
static void ospf_ext_link_lsa_schedule(struct ext_itf *exti,
				       enum lsa_opcode opcode);
static void ospf_ext_lsa_schedule(struct ext_itf *exti, enum lsa_opcode op);
static int ospf_ext_link_lsa_update(struct ospf_lsa *lsa);
static int ospf_ext_pref_lsa_update(struct ospf_lsa *lsa);
static void del_ext_info(void *val);

/*
 * Extended Link/Prefix initialization
 *
 * @param - none
 *
 * @return - 0 if OK, <> 0 otherwise
 */
int ospf_ext_init(void)
{
	int rc = 0;

	memset(&OspfEXT, 0, sizeof(struct ospf_ext_lp));
	OspfEXT.enabled = false;
	/* Only Area flooding is supported yet */
	OspfEXT.scope = OSPF_OPAQUE_AREA_LSA;
	/* Initialize interface list */
	OspfEXT.iflist = list_new();
	OspfEXT.iflist->del = del_ext_info;

	zlog_info("EXT (%s): Register Extended Link Opaque LSA", __func__);
	rc = ospf_register_opaque_functab(
		OSPF_OPAQUE_AREA_LSA, OPAQUE_TYPE_EXTENDED_LINK_LSA,
		ospf_ext_link_new_if,	/* new if */
		ospf_ext_link_del_if,	/* del if */
		ospf_ext_link_ism_change,    /* ism change */
		ospf_ext_link_nsm_change,    /* nsm change */
		NULL,			     /* Write router config. */
		NULL,			     /* Write interface conf. */
		NULL,			     /* Write debug config. */
		ospf_ext_link_show_info,     /* Show LSA info */
		ospf_ext_link_lsa_originate, /* Originate LSA */
		ospf_ext_link_lsa_refresh,   /* Refresh LSA */
		ospf_ext_link_lsa_update,    /* new_lsa_hook */
		NULL);			     /* del_lsa_hook */

	if (rc != 0) {
		zlog_warn("EXT (%s): Failed to register Extended Link LSA",
			  __func__);
		return rc;
	}

	zlog_info("EXT (%s): Register Extended Prefix Opaque LSA", __func__);
	rc = ospf_register_opaque_functab(
		OspfEXT.scope, OPAQUE_TYPE_EXTENDED_PREFIX_LSA,
		NULL,			     /* new if handle by link */
		NULL,			     /* del if handle by link */
		ospf_ext_pref_ism_change,    /* ism change */
		NULL,			     /* nsm change */
		ospf_sr_config_write_router, /* Write router config. */
		NULL,			     /* Write interface conf. */
		NULL,			     /* Write debug config. */
		ospf_ext_pref_show_info,     /* Show LSA info */
		ospf_ext_pref_lsa_originate, /* Originate LSA */
		ospf_ext_pref_lsa_refresh,   /* Refresh LSA */
		ospf_ext_pref_lsa_update,    /* new_lsa_hook */
		NULL);			     /* del_lsa_hook */
	if (rc != 0) {
		zlog_warn("EXT (%s): Failed to register Extended Prefix LSA",
			  __func__);
		return rc;
	}

	return rc;
}

/*
 * Extended Link/Prefix termination function
 *
 * @param - none
 * @return - none
 */
void ospf_ext_term(void)
{

	if ((OspfEXT.scope != OSPF_OPAQUE_AREA_LSA)
	    && (OspfEXT.scope != OSPF_OPAQUE_AS_LSA))
		zlog_warn(
			"EXT: Unable to unregister Extended Prefix "
			"Opaque LSA functions: Wrong scope!");
	else
		ospf_delete_opaque_functab(OspfEXT.scope,
					   OPAQUE_TYPE_EXTENDED_PREFIX_LSA);

	ospf_delete_opaque_functab(OSPF_OPAQUE_AREA_LSA,
				   OPAQUE_TYPE_EXTENDED_LINK_LSA);

	list_delete_and_null(&OspfEXT.iflist);
	OspfEXT.scope = 0;
	OspfEXT.enabled = false;

	return;
}

/*
 * Extended Link/Prefix finish function
 *
 * @param - none
 * @return - none
 */
void ospf_ext_finish(void)
{
	// list_delete_all_node(OspfEXT.iflist);
	OspfEXT.enabled = false;
}

/*
 * ---------------------------------------------------------------------
 * Followings are control functions for Extended Prefix/Link Opaque LSA
 * parameters management.
 * ---------------------------------------------------------------------
 */

/* Functions to free memory space */
static void del_ext_info(void *val)
{
	XFREE(MTYPE_OSPF_EXT_PARAMS, val);
}

/* Increment instance value for Extended Prefix Opaque LSAs Opaque ID field */
static uint32_t get_ext_pref_instance_value(void)
{
	static uint32_t seqno = 0;

	if (seqno < MAX_LEGAL_EXT_INSTANCE_NUM)
		seqno += 1;
	else
		seqno = 1; /* Avoid zero. */

	return seqno;
}

/* Increment instance value for Extended Link Opaque LSAs Opaque ID field */
static uint32_t get_ext_link_instance_value(void)
{
	static uint32_t seqno = 0;

	if (seqno < MAX_LEGAL_EXT_INSTANCE_NUM)
		seqno += 1;
	else
		seqno = 1; /* Avoid zero. */

	return seqno;
}

/* Lookup Extended Prefix/Links by ifp from OspfEXT struct iflist */
static struct ext_itf *lookup_ext_by_ifp(struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct ext_itf *exti;

	for (ALL_LIST_ELEMENTS(OspfEXT.iflist, node, nnode, exti))
		if (exti->ifp == ifp)
			return exti;

	return NULL;
}

/* Lookup Extended Prefix/Links by LSA ID from OspfEXT struct iflist */
static struct ext_itf *lookup_ext_by_instance(struct ospf_lsa *lsa)
{
	struct listnode *node;
	struct ext_itf *exti;
	uint32_t key = GET_OPAQUE_ID(ntohl(lsa->data->id.s_addr));
	uint8_t type = GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr));


	for (ALL_LIST_ELEMENTS_RO(OspfEXT.iflist, node, exti))
		if ((exti->instance == key) && (exti->type == type))
			return exti;

	return NULL;
}

/*
 * ----------------------------------------------------------------------
 * The underlying subsection defines setters and unsetters to create and
 * delete tlvs and subtlvs
 * ----------------------------------------------------------------------
 */

/* Extended Prefix TLV - RFC7684 section 2.1 */
static void set_ext_prefix(struct ext_itf *exti, uint8_t route_type,
			   uint8_t flags, struct prefix_ipv4 p)
{

	TLV_TYPE(exti->prefix) = htons(EXT_TLV_PREFIX);
	/* Warning: Size must be adjust depending of subTLV's */
	TLV_LEN(exti->prefix) = htons(EXT_TLV_PREFIX_SIZE);
	exti->prefix.route_type = route_type;
	exti->prefix.flags = flags;
	/* Only Address Family Ipv4 (0) is defined in RFC 7684 */
	exti->prefix.af = 0;
	exti->prefix.pref_length = p.prefixlen;
	exti->prefix.address = p.prefix;
}

/* Extended Link TLV - RFC7684 section 3.1 */
static void set_ext_link(struct ext_itf *exti, uint8_t type, struct in_addr id,
			 struct in_addr data)
{

	TLV_TYPE(exti->link) = htons(EXT_TLV_LINK);
	/* Warning: Size must be adjust depending of subTLV's */
	TLV_LEN(exti->link) = htons(EXT_TLV_LINK_SIZE);
	exti->link.link_type = type;
	exti->link.link_id = id;
	exti->link.link_data = data;
}

/* Prefix SID SubTLV - section 5 */
static void set_prefix_sid(struct ext_itf *exti, uint8_t algorithm,
			   uint32_t value, int value_type, uint8_t flags)
{

	if ((algorithm != SR_ALGORITHM_SPF)
	    && (algorithm != SR_ALGORITHM_STRICT_SPF)) {
		zlog_warn("EXT (%s): unrecognized algorithm, not SPF or S-SPF",
			  __func__);
		return;
	}

	/* Update flags according to the type of value field: label or index */
	if (value_type == SID_LABEL)
		SET_FLAG(flags, EXT_SUBTLV_PREFIX_SID_VFLG);

	/* set prefix sid subtlv for an extended prefix tlv */
	TLV_TYPE(exti->node_sid) = htons(EXT_SUBTLV_PREFIX_SID);
	exti->node_sid.algorithm = algorithm;
	exti->node_sid.flags = flags;
	exti->node_sid.mtid = 0; /* Multi-Topology is not supported */

	/* Set Label or Index value */
	if (value_type == SID_LABEL) {
		TLV_LEN(exti->node_sid) =
			htons(SID_LABEL_SIZE(EXT_SUBTLV_PREFIX_SID_SIZE));
		exti->node_sid.value = htonl(SET_LABEL(value));
	} else {
		TLV_LEN(exti->node_sid) =
			htons(SID_INDEX_SIZE(EXT_SUBTLV_PREFIX_SID_SIZE));
		exti->node_sid.value = htonl(value);
	}
}

/* Adjacency SID SubTLV - section 6.1 */
static void set_adj_sid(struct ext_itf *exti, bool backup, uint32_t value,
			int value_type)
{
	int index;
	uint8_t flags;

	/* Determine which ADJ_SID must be set: nominal or backup */
	if (backup) {
		flags = EXT_SUBTLV_LINK_ADJ_SID_BFLG;
		index = 1;
	} else {
		index = 0;
		flags = 0;
	}

	/* Set Header */
	TLV_TYPE(exti->adj_sid[index]) = htons(EXT_SUBTLV_ADJ_SID);

	/* Only Local ADJ-SID is supported for the moment */
	SET_FLAG(flags, EXT_SUBTLV_LINK_ADJ_SID_LFLG);

	exti->adj_sid[index].mtid = 0; /* Multi-Topology is not supported */

	/* Adjust Length, Flags and Value depending on the type of Label */
	if (value_type == SID_LABEL) {
		SET_FLAG(flags, EXT_SUBTLV_LINK_ADJ_SID_VFLG);
		TLV_LEN(exti->adj_sid[index]) =
			htons(SID_LABEL_SIZE(EXT_SUBTLV_ADJ_SID_SIZE));
		exti->adj_sid[index].value = htonl(SET_LABEL(value));
	} else {
		UNSET_FLAG(flags, EXT_SUBTLV_LINK_ADJ_SID_VFLG);
		TLV_LEN(exti->adj_sid[index]) =
			htons(SID_INDEX_SIZE(EXT_SUBTLV_ADJ_SID_SIZE));
		exti->adj_sid[index].value = htonl(value);
	}

	exti->adj_sid[index].flags = flags; /* Set computed flags */
	exti->adj_sid[index].mtid = 0;   /* Multi-Topology is not supported */
	exti->adj_sid[index].weight = 0; /* Load-Balancing is not supported */
}

/* LAN Adjacency SID SubTLV - section 6.2 */
static void set_lan_adj_sid(struct ext_itf *exti, bool backup, uint32_t value,
			    int value_type, struct in_addr neighbor_id)
{

	int index;
	uint8_t flags;

	/* Determine which ADJ_SID must be set: nominal or backup */
	if (backup) {
		flags = EXT_SUBTLV_LINK_ADJ_SID_BFLG;
		index = 1;
	} else {
		index = 0;
		flags = 0;
	}

	/* Set Header */
	TLV_TYPE(exti->lan_sid[index]) = htons(EXT_SUBTLV_LAN_ADJ_SID);

	/* Only Local ADJ-SID is supported for the moment */
	SET_FLAG(flags, EXT_SUBTLV_LINK_ADJ_SID_LFLG);

	/* Adjust Length, Flags and Value depending on the type of Label */
	if (value_type == SID_LABEL) {
		SET_FLAG(flags, EXT_SUBTLV_LINK_ADJ_SID_VFLG);
		TLV_LEN(exti->lan_sid[index]) =
			htons(SID_LABEL_SIZE(EXT_SUBTLV_PREFIX_RANGE_SIZE));
		exti->lan_sid[index].value = htonl(SET_LABEL(value));
	} else {
		UNSET_FLAG(flags, EXT_SUBTLV_LINK_ADJ_SID_VFLG);
		TLV_LEN(exti->lan_sid[index]) =
			htons(SID_INDEX_SIZE(EXT_SUBTLV_PREFIX_RANGE_SIZE));
		exti->lan_sid[index].value = htonl(value);
	}

	exti->lan_sid[index].flags = flags; /* Set computed flags */
	exti->lan_sid[index].mtid = 0;   /* Multi-Topology is not supported */
	exti->lan_sid[index].weight = 0; /* Load-Balancing is not supported */
	exti->lan_sid[index].neighbor_id = neighbor_id;
}

/* Experimental SubTLV from Cisco */
static void set_rmt_itf_addr(struct ext_itf *exti, struct in_addr rmtif)
{

	TLV_TYPE(exti->rmt_itf_addr) = htons(EXT_SUBTLV_RMT_ITF_ADDR);
	TLV_LEN(exti->rmt_itf_addr) = htons(sizeof(struct in_addr));
	exti->rmt_itf_addr.value = rmtif;
}

/*
 * Update Extended prefix SID index for Loopback interface type
 *
 * @param ifname - Loopback interface name
 * @param index - new value for the prefix SID of this interface
 * @param p - prefix for this interface or NULL if Extended Prefix
 * should be remove
 *
 * @return instance number if update is OK, 0 otherwise
 */
uint32_t ospf_ext_schedule_prefix_index(struct interface *ifp, uint32_t index,
					struct prefix_ipv4 *p, uint8_t flags)
{
	int rc = 0;
	struct ext_itf *exti;

	/* Find Extended Prefix interface */
	exti = lookup_ext_by_ifp(ifp);
	if (exti == NULL)
		return rc;

	if (p != NULL) {
		if (IS_DEBUG_OSPF_SR)
			zlog_debug(
				"EXT (%s): Schedule new prefix %s/%u with "
				"index %u on interface %s",
				__func__, inet_ntoa(p->prefix), p->prefixlen,
				index, ifp->name);

		/* Set first Extended Prefix then the Prefix SID information */
		set_ext_prefix(exti, OSPF_PATH_INTRA_AREA, EXT_TLV_PREF_NFLG,
			       *p);
		set_prefix_sid(exti, SR_ALGORITHM_SPF, index, SID_INDEX, flags);

		/* Try to Schedule LSA */
		SET_FLAG(exti->flags, EXT_LPFLG_LSA_ACTIVE);
		if (CHECK_FLAG(exti->flags, EXT_LPFLG_LSA_ENGAGED))
			ospf_ext_pref_lsa_schedule(exti, REFRESH_THIS_LSA);
		else
			ospf_ext_pref_lsa_schedule(exti, REORIGINATE_THIS_LSA);
	} else {
		if (IS_DEBUG_OSPF_SR)
			zlog_debug("EXT (%s): Remove prefix for interface %s",
				   __func__, ifp->name);

		if (CHECK_FLAG(exti->flags, EXT_LPFLG_LSA_ENGAGED)) {
			ospf_ext_pref_lsa_schedule(exti, FLUSH_THIS_LSA);
			UNSET_FLAG(exti->flags, EXT_LPFLG_LSA_ENGAGED);
			UNSET_FLAG(exti->flags, EXT_LPFLG_LSA_ACTIVE);
		}
	}

	return SET_OPAQUE_LSID(exti->type, exti->instance);
}

/*
 * Used by Segment Routing to activate/deactivate Extended Link/Prefix flooding
 *
 * @param enable To activate or not Segment Routing Extended LSA flooding
 *
 * @return none
 */
void ospf_ext_update_sr(bool enable)
{
	struct listnode *node;
	struct ext_itf *exti;

	if (IS_DEBUG_OSPF_SR)
		zlog_debug("EXT (%s): %s Extended LSAs for Segment Routing ",
			   __func__, enable ? "Enable" : "Disable");

	if (enable) {
		OspfEXT.enabled = true;
		/* Refresh LSAs if already engaged or originate */
		for (ALL_LIST_ELEMENTS_RO(OspfEXT.iflist, node, exti))
			if (CHECK_FLAG(exti->flags, EXT_LPFLG_LSA_ENGAGED))
				ospf_ext_lsa_schedule(exti, REFRESH_THIS_LSA);
			else
				ospf_ext_lsa_schedule(exti,
						      REORIGINATE_THIS_LSA);
	} else {
		/* Start by Flushing engaged LSAs */
		for (ALL_LIST_ELEMENTS_RO(OspfEXT.iflist, node, exti))
			if (CHECK_FLAG(exti->flags, EXT_LPFLG_LSA_ENGAGED))
				ospf_ext_lsa_schedule(exti, FLUSH_THIS_LSA);
		/* And then disable Extended Link/Prefix */
		OspfEXT.enabled = false;
	}
}
/*
 * -----------------------------------------------------------------------
 * Followings are callback functions against generic Opaque-LSAs handling
 * -----------------------------------------------------------------------
 */

/* Add new Interface in Extended Interface List */
static int ospf_ext_link_new_if(struct interface *ifp)
{
	struct ext_itf *new;
	int rc = -1;

	if (lookup_ext_by_ifp(ifp) != NULL) {
		zlog_warn("EXT (%s): interface %s is already in use", __func__,
			  ifp ? ifp->name : "-");
		rc = 0; /* Do nothing here. */
		return rc;
	}

	new = XCALLOC(MTYPE_OSPF_EXT_PARAMS, sizeof(struct ext_itf));
	if (new == NULL) {
		zlog_warn("EXT (%s): XCALLOC: %s", __func__,
			  safe_strerror(errno));
		return rc;
	}

	/* initialize new information and link back the interface */
	new->ifp = ifp;
	new->flags = EXT_LPFLG_LSA_INACTIVE;

	listnode_add(OspfEXT.iflist, new);

	rc = 0;
	return rc;
}

/* Remove existing Interface from Extended Interface List */
static int ospf_ext_link_del_if(struct interface *ifp)
{
	struct ext_itf *exti;
	int rc = -1;

	exti = lookup_ext_by_ifp(ifp);
	if (exti != NULL) {
		struct list *iflist = OspfEXT.iflist;

		/* Dequeue listnode entry from the list. */
		listnode_delete(iflist, exti);

		XFREE(MTYPE_OSPF_EXT_PARAMS, exti);

		rc = 0;
	} else {
		zlog_warn("EXT (%s): interface %s is not found", __func__,
			  ifp ? ifp->name : "-");
	}

	return rc;
}

/*
 * Determine if an Interface belongs to an Extended Link Adjacency or LAN Adj.
 * type and allocate new instance value accordingly
 */
static void ospf_ext_link_ism_change(struct ospf_interface *oi, int old_status)
{
	struct ext_itf *exti;

	/* Get interface information for Segment Routing */
	exti = lookup_ext_by_ifp(oi->ifp);
	if (exti == NULL) {
		zlog_warn("EXT (%s): Cannot get Extended info. from OI(%s)",
			  __func__, IF_NAME(oi));
		return;
	}

	/* Determine if interface is related to Adjacency or LAN Adj. SID */
	if (oi->type != OSPF_IFTYPE_LOOPBACK) {
		if (oi->state == ISM_DR)
			exti->stype = LAN_ADJ_SID;
		else
			exti->stype = ADJ_SID;

		exti->instance = get_ext_link_instance_value();
		exti->type = OPAQUE_TYPE_EXTENDED_LINK_LSA;

		zlog_debug("EXT (%s): Set %s SID to interface %s ", __func__,
			   exti->stype == ADJ_SID ? "Adj." : "LAN Adj.",
			   oi->ifp->name);
	}
}

/*
 * Determine if an Interface belongs to an Extended Prefix and
 * allocate new instance value accordingly
 */
static void ospf_ext_pref_ism_change(struct ospf_interface *oi, int old_status)
{
	struct ext_itf *exti;

	/* Get interface information for Segment Routing */
	exti = lookup_ext_by_ifp(oi->ifp);
	if (exti == NULL) {
		zlog_warn("EXT (%s): Cannot get Extended info. from OI(%s)",
			  __func__, IF_NAME(oi));
		return;
	}

	/* Determine if interface is related to a Node SID */
	if (oi->type == OSPF_IFTYPE_LOOPBACK) {
		exti->stype = PREF_SID;
		exti->instance = get_ext_pref_instance_value();
		exti->type = OPAQUE_TYPE_EXTENDED_PREFIX_LSA;

		zlog_debug("EXT (%s): Set Node SID to interface %s ", __func__,
			   oi->ifp->name);

		/* Complete SRDB if the interface belongs to a Prefix */
		if (OspfEXT.enabled)
			ospf_sr_update_prefix(oi->ifp, oi->address);
	}
}

/*
 * Finish Extended Link configuration and flood corresponding LSA
 * when OSPF adjacency on this link fire up
 */
static void ospf_ext_link_nsm_change(struct ospf_neighbor *nbr, int old_status)
{
	struct ospf_interface *oi = nbr->oi;
	struct ext_itf *exti;
	uint32_t label;

	/* Process Neighbor only when its state is NSM Full */
	if (nbr->state != NSM_Full)
		return;

	/* Get interface information for Segment Routing */
	exti = lookup_ext_by_ifp(oi->ifp);
	if (exti == NULL) {
		zlog_warn("EXT (%s): Cannot get Extended info. from OI(%s)",
			  __func__, IF_NAME(oi));
		return;
	}

	if (oi->area == NULL || oi->area->ospf == NULL) {
		zlog_warn("EXT (%s): Cannot refer to OSPF from OI(%s)",
			  __func__, IF_NAME(oi));
		return;
	}

	/* Keep Area information in combination with SR info. */
	exti->area = oi->area;
	OspfEXT.area = oi->area;

	/* Process only Adjacency/LAN SID */
	if (exti->stype == PREF_SID)
		return;

	switch (oi->state) {
	case ISM_PointToPoint:
		/* Segment ID is an Adjacency one */
		exti->stype = ADJ_SID;

		/* Set Extended Link TLV with link_id == Nbr Router ID */
		set_ext_link(exti, OSPF_IFTYPE_POINTOPOINT, nbr->router_id,
			     oi->address->u.prefix4);

		/* Set Extended Link Adjacency SubTLVs, backup first */
		label = get_ext_link_label_value();
		set_adj_sid(exti, true, label, SID_LABEL);
		label = get_ext_link_label_value();
		set_adj_sid(exti, false, label, SID_LABEL);
		/* And Remote Interface address */
		set_rmt_itf_addr(exti, nbr->address.u.prefix4);

		break;

	case ISM_DR:
		/* Segment ID is a LAN Adjacency for the DR only */
		exti->stype = LAN_ADJ_SID;

		/* Set Extended Link TLV with link_id == DR */
		set_ext_link(exti, OSPF_IFTYPE_BROADCAST, DR(oi),
			     oi->address->u.prefix4);

		/* Set Extended Link Adjacency SubTLVs, backup first */
		label = get_ext_link_label_value();
		set_lan_adj_sid(exti, true, label, SID_LABEL, nbr->router_id);
		label = get_ext_link_label_value();
		set_lan_adj_sid(exti, false, label, SID_LABEL, nbr->router_id);

		break;

	case ISM_DROther:
	case ISM_Backup:
		/* Segment ID is an Adjacency if not the DR */
		exti->stype = ADJ_SID;

		/* Set Extended Link TLV with link_id == DR */
		set_ext_link(exti, OSPF_IFTYPE_BROADCAST, DR(oi),
			     oi->address->u.prefix4);

		/* Set Extended Link Adjacency SubTLVs, backup first */
		label = get_ext_link_label_value();
		set_adj_sid(exti, true, label, SID_LABEL);
		label = get_ext_link_label_value();
		set_adj_sid(exti, false, label, SID_LABEL);

		break;

	default:
		if (CHECK_FLAG(exti->flags, EXT_LPFLG_LSA_ENGAGED)) {
			ospf_ext_link_lsa_schedule(exti, FLUSH_THIS_LSA);
			UNSET_FLAG(exti->flags, EXT_LPFLG_LSA_ENGAGED);
			UNSET_FLAG(exti->flags, EXT_LPFLG_LSA_ACTIVE);
		}
		return;
	}

	if (IS_DEBUG_OSPF_SR)
		zlog_debug("EXT (%s): Complete %s SID to interface %s ",
			   __func__,
			   exti->stype == ADJ_SID ? "Adj." : "LAN Adj.",
			   oi->ifp->name);

	/* flood this links params if everything is ok */
	SET_FLAG(exti->flags, EXT_LPFLG_LSA_ACTIVE);
	if (OspfEXT.enabled) {
		if (CHECK_FLAG(exti->flags, EXT_LPFLG_LSA_ENGAGED))
			ospf_ext_link_lsa_schedule(exti, REFRESH_THIS_LSA);
		else
			ospf_ext_link_lsa_schedule(exti, REORIGINATE_THIS_LSA);
	}
}

/* Callbacks to handle Extended Link Segment Routing LSA information */
static int ospf_ext_link_lsa_update(struct ospf_lsa *lsa)
{
	/* Sanity Check */
	if (lsa == NULL) {
		zlog_warn("EXT (%s): Abort! LSA is NULL", __func__);
		return -1;
	}

	/* Process only Opaque LSA */
	if ((lsa->data->type != OSPF_OPAQUE_AREA_LSA)
	    && (lsa->data->type != OSPF_OPAQUE_AS_LSA))
		return 0;

	/* Process only Extended Link LSA */
	if (GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr))
	    != OPAQUE_TYPE_EXTENDED_LINK_LSA)
		return 0;

	/* Check if Extended is enable */
	if (!OspfEXT.enabled)
		return 0;

	/* Call Segment Routing LSA update or deletion */
	if (!IS_LSA_MAXAGE(lsa))
		ospf_sr_ext_link_lsa_update(lsa);
	else
		ospf_sr_ext_link_lsa_delete(lsa);

	return 0;
}

/* Callbacks to handle Extended Prefix Segment Routing LSA information */
static int ospf_ext_pref_lsa_update(struct ospf_lsa *lsa)
{

	/* Sanity Check */
	if (lsa == NULL) {
		zlog_warn("EXT (%s): Abort! LSA is NULL", __func__);
		return -1;
	}

	/* Process only Opaque LSA */
	if ((lsa->data->type != OSPF_OPAQUE_AREA_LSA)
	    && (lsa->data->type != OSPF_OPAQUE_AS_LSA))
		return 0;

	/* Process only Extended Prefix LSA */
	if (GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr))
	    != OPAQUE_TYPE_EXTENDED_PREFIX_LSA)
		return 0;

	/* Check if it is not my LSA */
	if (IS_LSA_SELF(lsa))
		return 0;

	/* Check if Extended is enable */
	if (!OspfEXT.enabled)
		return 0;

	/* Call Segment Routing LSA update or deletion */
	if (!IS_LSA_MAXAGE(lsa))
		ospf_sr_ext_prefix_lsa_update(lsa);
	else
		ospf_sr_ext_prefix_lsa_delete(lsa);

	return 0;
}

/*
 * -------------------------------------------------------
 * Followings are OSPF protocol processing functions for
 * Extended Prefix/Link Opaque LSA
 * -------------------------------------------------------
 */

static void build_tlv_header(struct stream *s, struct tlv_header *tlvh)
{
	stream_put(s, tlvh, sizeof(struct tlv_header));
}

static void build_tlv(struct stream *s, struct tlv_header *tlvh)
{

	if ((tlvh != NULL) && (ntohs(tlvh->type) != 0)) {
		build_tlv_header(s, tlvh);
		stream_put(s, TLV_DATA(tlvh), TLV_BODY_SIZE(tlvh));
	}
}

/* Build an Extended Prefix Opaque LSA body for extended prefix TLV */
static void ospf_ext_pref_lsa_body_set(struct stream *s, struct ext_itf *exti)
{

	/* Sanity check */
	if ((exti == NULL) || (exti->stype != PREF_SID))
		return;

	/* Adjust Extended Prefix TLV size */
	TLV_LEN(exti->prefix) = htons(ntohs(TLV_LEN(exti->node_sid))
				      + EXT_TLV_PREFIX_SIZE + TLV_HDR_SIZE);

	/* Build LSA body for an Extended Prefix TLV */
	build_tlv_header(s, &exti->prefix.header);
	stream_put(s, TLV_DATA(&exti->prefix.header), EXT_TLV_PREFIX_SIZE);
	/* Then add Prefix SID SubTLV */
	build_tlv(s, &exti->node_sid.header);
}

/* Build an Extended Link Opaque LSA body for extended link TLV */
static void ospf_ext_link_lsa_body_set(struct stream *s, struct ext_itf *exti)
{
	size_t size;

	/* Sanity check */
	if ((exti == NULL)
	    || ((exti->stype != ADJ_SID) && (exti->stype != LAN_ADJ_SID)))
		return;

	if (exti->stype == ADJ_SID) {
		/* Adjust Extended Link TLV size for Adj. SID */
		size = EXT_TLV_LINK_SIZE + 2 * EXT_SUBTLV_ADJ_SID_SIZE
		       + 2 * TLV_HDR_SIZE;
		if (ntohs(TLV_TYPE(exti->rmt_itf_addr)) != 0)
			size = size + EXT_SUBTLV_RMT_ITF_ADDR_SIZE
			       + TLV_HDR_SIZE;
		TLV_LEN(exti->link) = htons(size);

		/* Build LSA body for an Extended Link TLV with Adj. SID */
		build_tlv_header(s, &exti->link.header);
		stream_put(s, TLV_DATA(&exti->link.header), EXT_TLV_LINK_SIZE);
		/* then add Adjacency SubTLVs */
		build_tlv(s, &exti->adj_sid[1].header);
		build_tlv(s, &exti->adj_sid[0].header);

		/* Add Cisco experimental SubTLV if interface is PtoP */
		if (ntohs(TLV_TYPE(exti->rmt_itf_addr)) != 0)
			build_tlv(s, &exti->rmt_itf_addr.header);
	} else {
		/* Adjust Extended Link TLV size for LAN SID */
		size = EXT_TLV_LINK_SIZE
		       + 2 * (EXT_SUBTLV_LAN_ADJ_SID_SIZE + TLV_HDR_SIZE);
		TLV_LEN(exti->link) = htons(size);

		/* Build LSA body for an Extended Link TLV with LAN SID */
		build_tlv_header(s, &exti->link.header);
		stream_put(s, TLV_DATA(&exti->link.header), EXT_TLV_LINK_SIZE);
		/* then add LAN-Adjacency SubTLVs */
		build_tlv(s, &exti->lan_sid[1].header);
		build_tlv(s, &exti->lan_sid[0].header);
	}
}

/* Create new Extended Prefix opaque-LSA for every extended prefix */
static struct ospf_lsa *ospf_ext_pref_lsa_new(struct ospf_area *area,
					      struct ext_itf *exti)
{
	struct stream *s;
	struct lsa_header *lsah;
	struct ospf_lsa *new = NULL;
	struct ospf *top;
	uint8_t options, lsa_type;
	struct in_addr lsa_id;
	struct in_addr router_id;
	uint32_t tmp;
	uint16_t length;

	/* Sanity Check */
	if (exti == NULL)
		return NULL;

	/* Create a stream for LSA. */
	s = stream_new(OSPF_MAX_LSA_SIZE);
	if (s == NULL) {
		zlog_warn("EXT (%s): stream_new() error", __func__);
		return NULL;
	}

	/* Prepare LSA Header */
	lsah = (struct lsa_header *)STREAM_DATA(s);

	lsa_type = OspfEXT.scope;

	/*
	 * LSA ID is a variable number identifying different instances of
	 * Extended Prefix Opaque LSA from the same router see RFC 7684
	 */
	tmp = SET_OPAQUE_LSID(OPAQUE_TYPE_EXTENDED_PREFIX_LSA, exti->instance);
	lsa_id.s_addr = htonl(tmp);

	options = OSPF_OPTION_O; /* Don't forget this :-) */

	/* Fix Options and Router ID depending of the flooding scope */
	if ((OspfEXT.scope == OSPF_OPAQUE_AS_LSA) || (area == NULL)) {
		options = OSPF_OPTION_E;
		top = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		router_id.s_addr = top ? top->router_id.s_addr : 0;
	} else {
		options |= LSA_OPTIONS_GET(area); /* Get area default option */
		options |= LSA_OPTIONS_NSSA_GET(area);
		router_id = area->ospf->router_id;
	}

	/* Set opaque-LSA header fields. */
	lsa_header_set(s, options, lsa_type, lsa_id, router_id);

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
		zlog_debug(
			"EXT (%s): LSA[Type%u:%s]: Create an Opaque-LSA "
			"Extended Prefix Opaque LSA instance",
			__func__, lsa_type, inet_ntoa(lsa_id));


	/* Set opaque-LSA body fields. */
	ospf_ext_pref_lsa_body_set(s, exti);

	/* Set length. */
	length = stream_get_endp(s);
	lsah->length = htons(length);

	/* Now, create an OSPF LSA instance. */
	new = ospf_lsa_new();
	if (new == NULL) {
		zlog_warn("EXT (%s): ospf_lsa_new() error", __func__);
		stream_free(s);
		return NULL;
	}
	new->data = ospf_lsa_data_new(length);
	if (new->data == NULL) {
		zlog_warn("EXT (%s): ospf_lsa_data_new() error", __func__);
		ospf_lsa_unlock(&new);
		new = NULL;
		stream_free(s);
		return NULL;
	}

	/* Segment Routing belongs only to default VRF */
	new->vrf_id = VRF_DEFAULT;
	new->area = area;
	SET_FLAG(new->flags, OSPF_LSA_SELF);
	memcpy(new->data, lsah, length);
	stream_free(s);

	return new;
}

/* Create new Extended Link opaque-LSA for every extended link TLV */
static struct ospf_lsa *ospf_ext_link_lsa_new(struct ospf_area *area,
					      struct ext_itf *exti)
{
	struct stream *s;
	struct lsa_header *lsah;
	struct ospf_lsa *new = NULL;
	uint8_t options, lsa_type;
	struct in_addr lsa_id;
	uint32_t tmp;
	uint16_t length;

	/* Sanity Check */
	if (exti == NULL)
		return NULL;

	/* Create a stream for LSA. */
	s = stream_new(OSPF_MAX_LSA_SIZE);
	if (s == NULL) {
		zlog_warn("EXT (%s): stream_new() error", __func__);
		return NULL;
	}
	lsah = (struct lsa_header *)STREAM_DATA(s);

	options = OSPF_OPTION_O;	  /* Don't forget this :-) */
	options |= LSA_OPTIONS_GET(area); /* Get area default option */
	options |= LSA_OPTIONS_NSSA_GET(area);
	/* Extended Link Opaque LSA are only flooded within an area */
	lsa_type = OSPF_OPAQUE_AREA_LSA;

	/*
	 * LSA ID is a variable number identifying different instances of
	 * Extended Link Opaque LSA from the same router see RFC 7684
	 */
	tmp = SET_OPAQUE_LSID(OPAQUE_TYPE_EXTENDED_LINK_LSA, exti->instance);
	lsa_id.s_addr = htonl(tmp);

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
		zlog_debug(
			"EXT (%s) LSA[Type%u:%s]: Create an Opaque-LSA "
			"Extended Link Opaque LSA instance",
			__func__, lsa_type, inet_ntoa(lsa_id));

	/* Set opaque-LSA header fields. */
	lsa_header_set(s, options, lsa_type, lsa_id, area->ospf->router_id);

	/* Set opaque-LSA body fields. */
	ospf_ext_link_lsa_body_set(s, exti);

	/* Set length. */
	length = stream_get_endp(s);
	lsah->length = htons(length);

	/* Now, create an OSPF LSA instance. */
	new = ospf_lsa_new();
	if (new == NULL) {
		zlog_warn("EXT (%s): ospf_lsa_new() error", __func__);
		stream_free(s);
		return NULL;
	}
	new->data = ospf_lsa_data_new(length);
	if (new->data == NULL) {
		zlog_warn("EXT (%s): ospf_lsa_data_new() error", __func__);
		ospf_lsa_unlock(&new);
		new = NULL;
		stream_free(s);
		return NULL;
	}

	/* Segment Routing belongs only to default VRF */
	new->vrf_id = VRF_DEFAULT;
	new->area = area;
	SET_FLAG(new->flags, OSPF_LSA_SELF);
	memcpy(new->data, lsah, length);
	stream_free(s);

	return new;
}

/*
 * Process the origination of an Extended Prefix Opaque LSA
 * for every extended prefix TLV
 */
static int ospf_ext_pref_lsa_originate1(struct ospf_area *area,
					struct ext_itf *exti)
{
	struct ospf_lsa *new;
	int rc = -1;


	/* Create new Opaque-LSA/Extended Prefix Opaque LSA instance. */
	new = ospf_ext_pref_lsa_new(area, exti);
	if (new == NULL) {
		zlog_warn("EXT (%s): ospf_ext_pref_lsa_new() error", __func__);
		return rc;
	}

	/* Install this LSA into LSDB. */
	if (ospf_lsa_install(area->ospf, NULL /*oi */, new) == NULL) {
		zlog_warn("EXT (%s): ospf_lsa_install() error", __func__);
		ospf_lsa_unlock(&new);
		return rc;
	}

	/* Now this Extended Prefix Opaque LSA info parameter entry has
	 * associated LSA.
	 */
	SET_FLAG(exti->flags, EXT_LPFLG_LSA_ENGAGED);

	/* Update new LSA origination count. */
	area->ospf->lsa_originate_count++;

	/* Flood new LSA through area. */
	ospf_flood_through_area(area, NULL /*nbr */, new);

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE)) {
		char area_id[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &area->area_id, area_id, sizeof(area_id));
		zlog_debug(
			"EXT (%s): LSA[Type%u:%s]: Originate Opaque-LSA "
			"Extended Prefix Opaque LSA: Area(%s), Link(%s)",
			__func__, new->data->type, inet_ntoa(new->data->id),
			area_id, exti->ifp->name);
		ospf_lsa_header_dump(new->data);
	}

	rc = 0;

	return rc;
}

/*
 * Process the origination of an Extended Link Opaque LSA
 * for every extended link TLV
 */
static int ospf_ext_link_lsa_originate1(struct ospf_area *area,
					struct ext_itf *exti)
{
	struct ospf_lsa *new;
	int rc = -1;

	/* Create new Opaque-LSA/Extended Link Opaque LSA instance. */
	new = ospf_ext_link_lsa_new(area, exti);
	if (new == NULL) {
		zlog_warn("EXT (%s): ospf_ext_link_lsa_new() error", __func__);
		return rc;
	}

	/* Install this LSA into LSDB. */
	if (ospf_lsa_install(area->ospf, NULL /*oi */, new) == NULL) {
		zlog_warn("EXT (%s): ospf_lsa_install() error", __func__);
		ospf_lsa_unlock(&new);
		return rc;
	}

	/* Now this link-parameter entry has associated LSA. */
	SET_FLAG(exti->flags, EXT_LPFLG_LSA_ENGAGED);

	/* Update new LSA origination count. */
	area->ospf->lsa_originate_count++;

	/* Flood new LSA through area. */
	ospf_flood_through_area(area, NULL /*nbr */, new);

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE)) {
		char area_id[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &area->area_id, area_id, sizeof(area_id));
		zlog_debug(
			"EXT (%s): LSA[Type%u:%s]: Originate Opaque-LSA "
			"Extended Link Opaque LSA: Area(%s), Link(%s)",
			__func__, new->data->type, inet_ntoa(new->data->id),
			area_id, exti->ifp->name);
		ospf_lsa_header_dump(new->data);
	}

	rc = 0;

	return rc;
}

/* Trigger the origination of Extended Prefix Opaque LSAs */
static int ospf_ext_pref_lsa_originate(void *arg)
{
	struct ospf_area *area = (struct ospf_area *)arg;
	struct listnode *node;
	struct ext_itf *exti;
	int rc = -1;

	if (!OspfEXT.enabled) {
		zlog_info(
			"EXT (%s): Segment Routing "
			"functionality is Disabled now",
			__func__);
		rc = 0; /* This is not an error case. */
		return rc;
	}
	if (IS_DEBUG_OSPF_SR)
		zlog_debug("EXT (%s): Start Originate Prefix LSA for area %s",
			   __func__, inet_ntoa(area->area_id));

	/* Check if Extended Prefix Opaque LSA is already engaged */
	for (ALL_LIST_ELEMENTS_RO(OspfEXT.iflist, node, exti)) {

		/* Process only Prefix SID */
		if (exti->stype != PREF_SID)
			continue;

		/* Process only Extended Prefix with valid Area ID */
		if ((exti->area == NULL)
		    || (!IPV4_ADDR_SAME(&exti->area->area_id, &area->area_id)))
			continue;

		if (CHECK_FLAG(exti->flags, EXT_LPFLG_LSA_ENGAGED)) {
			if (CHECK_FLAG(exti->flags,
				       EXT_LPFLG_LSA_FORCED_REFRESH)) {
				zlog_warn(
					"EXT (%s): Refresh instead of "
					"Originate",
					__func__);
				UNSET_FLAG(exti->flags,
					   EXT_LPFLG_LSA_FORCED_REFRESH);
				ospf_ext_pref_lsa_schedule(exti,
							   REFRESH_THIS_LSA);
			}
			continue;
		}

		/* Ok, let's try to originate an LSA */
		if (IS_DEBUG_OSPF_SR)
			zlog_debug(
				"EXT (%s): Let's finally reoriginate the "
				"LSA 7.0.0.%u for Itf %s",
				__func__, exti->instance,
				exti->ifp ? exti->ifp->name : "");
		ospf_ext_pref_lsa_originate1(area, exti);
	}

	rc = 0;
	return rc;
}

/* Trigger the origination of Extended Link Opaque LSAs */
static int ospf_ext_link_lsa_originate(void *arg)
{
	struct ospf_area *area = (struct ospf_area *)arg;
	struct listnode *node;
	struct ext_itf *exti;
	int rc = -1;

	if (!OspfEXT.enabled) {
		zlog_info(
			"EXT (%s): Segment Routing "
			"functionality is Disabled now",
			__func__);
		rc = 0; /* This is not an error case. */
		return rc;
	}

	/* Check if Extended Prefix Opaque LSA is already engaged */
	for (ALL_LIST_ELEMENTS_RO(OspfEXT.iflist, node, exti)) {
		/* Process only Adjacency or LAN SID */
		if (exti->stype == PREF_SID)
			continue;

		/* Process only Extended Link with valid Area ID */
		if ((exti->area == NULL)
		    || (!IPV4_ADDR_SAME(&exti->area->area_id, &area->area_id)))
			continue;

		/* Check if LSA not already engaged */
		if (CHECK_FLAG(exti->flags, EXT_LPFLG_LSA_ENGAGED)) {
			if (CHECK_FLAG(exti->flags,
				       EXT_LPFLG_LSA_FORCED_REFRESH)) {
				zlog_warn(
					"EXT (%s): Refresh instead of "
					"Originate",
					__func__);
				UNSET_FLAG(exti->flags,
					   EXT_LPFLG_LSA_FORCED_REFRESH);
				ospf_ext_link_lsa_schedule(exti,
							   REFRESH_THIS_LSA);
			}
			continue;
		}

		/* Ok, let's try to originate an LSA */
		if (IS_DEBUG_OSPF_SR)
			zlog_debug(
				"EXT (%s): Let's finally reoriginate the "
				"LSA 8.0.0.%u for Itf %s through the Area %s",
				__func__, exti->instance,
				exti->ifp ? exti->ifp->name : "-",
				inet_ntoa(area->area_id));
		ospf_ext_link_lsa_originate1(area, exti);
	}

	rc = 0;
	return rc;
}

/* Refresh an Extended Prefix Opaque LSA */
static struct ospf_lsa *ospf_ext_pref_lsa_refresh(struct ospf_lsa *lsa)
{
	struct ospf_lsa *new = NULL;
	struct ospf_area *area = lsa->area;
	struct ospf *top;
	struct ext_itf *exti;

	if (!OspfEXT.enabled) {
		/*
		 * This LSA must have flushed before due to Extended Prefix
		 * Opaque LSA status change.
		 * It seems a slip among routers in the routing domain.
		 */
		zlog_info(
			"EXT (%s): Segment Routing functionality is "
			"Disabled",
			__func__);
		/* Flush it anyway. */
		lsa->data->ls_age = htons(OSPF_LSA_MAXAGE);
	}

	/* Lookup this lsa corresponding Extended parameters */
	exti = lookup_ext_by_instance(lsa);
	if (exti == NULL) {
		zlog_warn("EXT (%s): Invalid parameter LSA ID", __func__);
		/* Flush it anyway. */
		lsa->data->ls_age = htons(OSPF_LSA_MAXAGE);
	}

	/* Check if Interface was not disable in the interval */
	if ((exti != NULL) && !CHECK_FLAG(exti->flags, EXT_LPFLG_LSA_ACTIVE)) {
		zlog_warn("EXT (%s): Interface was Disabled: Flush it!",
			  __func__);
		/* Flush it anyway. */
		lsa->data->ls_age = htons(OSPF_LSA_MAXAGE);
	}

	/* If the lsa's age reached to MaxAge, start flushing procedure. */
	if (IS_LSA_MAXAGE(lsa)) {
		if (exti)
			UNSET_FLAG(exti->flags, EXT_LPFLG_LSA_ENGAGED);
		ospf_opaque_lsa_flush_schedule(lsa);
		return NULL;
	}

	/* Create new Opaque-LSA/Extended Prefix Opaque LSA instance. */
	new = ospf_ext_pref_lsa_new(area, exti);

	if (new == NULL) {
		zlog_warn("EXT (%s): ospf_ext_pref_lsa_new() error", __func__);
		return NULL;
	}
	new->data->ls_seqnum = lsa_seqnum_increment(lsa);

	/*
	 * Install this LSA into LSDB
	 * Given "lsa" will be freed in the next function
	 * As area could be NULL i.e. when using OPAQUE_LSA_AS, we prefer to use
	 * ospf_lookup() to get ospf instance
	 */
	if (area)
		top = area->ospf;
	else
		top = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	if (ospf_lsa_install(top, NULL /*oi */, new) == NULL) {
		zlog_warn("EXT (%s): ospf_lsa_install() error", __func__);
		ospf_lsa_unlock(&new);
		return NULL;
	}

	/* Flood updated LSA through the Prefix Area according to the RFC7684 */
	ospf_flood_through_area(area, NULL /*nbr */, new);

	/* Debug logging. */
	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE)) {
		zlog_debug(
			"EXT (%s): LSA[Type%u:%s] Refresh Extended Prefix LSA",
			__func__, new->data->type, inet_ntoa(new->data->id));
		ospf_lsa_header_dump(new->data);
	}

	return new;
}

/* Refresh an Extended Link Opaque LSA */
static struct ospf_lsa *ospf_ext_link_lsa_refresh(struct ospf_lsa *lsa)
{
	struct ext_itf *exti;
	struct ospf_area *area = lsa->area;
	struct ospf *top = area->ospf;
	struct ospf_lsa *new = NULL;

	if (!OspfEXT.enabled) {
		/*
		 * This LSA must have flushed before due to OSPF-SR status
		 * change. It seems a slip among routers in the routing domain.
		 */
		zlog_info("EXT (%s): Segment Routing functionality is Disabled",
			  __func__);
		/* Flush it anyway. */
		lsa->data->ls_age = htons(OSPF_LSA_MAXAGE);
	}

	/* Lookup this LSA corresponding Extended parameters */
	exti = lookup_ext_by_instance(lsa);
	if (exti == NULL) {
		zlog_warn("EXT (%s): Invalid parameter LSA ID", __func__);
		/* Flush it anyway. */
		lsa->data->ls_age = htons(OSPF_LSA_MAXAGE);
	}

	/* Check if Interface was not disable in the interval */
	if ((exti != NULL) && !CHECK_FLAG(exti->flags, EXT_LPFLG_LSA_ACTIVE)) {
		zlog_warn("EXT (%s): Interface was Disabled: Flush it!",
			  __func__);
		lsa->data->ls_age = htons(OSPF_LSA_MAXAGE);
	}

	/* If the lsa's age reached to MaxAge, start flushing procedure */
	if (IS_LSA_MAXAGE(lsa)) {
		if (exti)
			UNSET_FLAG(exti->flags, EXT_LPFLG_LSA_ENGAGED);
		ospf_opaque_lsa_flush_schedule(lsa);
		return NULL;
	}

	/* Create new Opaque-LSA/Extended Link instance */
	new = ospf_ext_link_lsa_new(area, exti);
	if (new == NULL) {
		zlog_warn("EXT (%s): Error creating new LSA", __func__);
		return NULL;
	}
	new->data->ls_seqnum = lsa_seqnum_increment(lsa);

	/* Install this LSA into LSDB. */
	/* Given "lsa" will be freed in the next function */
	if (ospf_lsa_install(top, NULL /*oi */, new) == NULL) {
		zlog_warn("EXT (%s): Error installing new LSA", __func__);
		ospf_lsa_unlock(&new);
		return NULL;
	}

	/* Flood updated LSA through the link Area according to the RFC7684 */
	ospf_flood_through_area(area, NULL /*nbr */, new);

	/* Debug logging. */
	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE)) {
		zlog_debug(
			"EXT (%s): LSA[Type%u:%s]: Refresh Extended Link LSA",
			__func__, new->data->type, inet_ntoa(new->data->id));
		ospf_lsa_header_dump(new->data);
	}

	return new;
}

/* Schedule Extended Prefix Opaque LSA origination/refreshment/flushing */
static void ospf_ext_pref_lsa_schedule(struct ext_itf *exti,
				       enum lsa_opcode opcode)
{
	struct ospf_lsa lsa;
	struct lsa_header lsah;
	struct ospf *top;
	uint32_t tmp;

	memset(&lsa, 0, sizeof(lsa));
	memset(&lsah, 0, sizeof(lsah));

	/* Sanity Check */
	if (exti == NULL)
		return;

	/* Check if the corresponding link is ready to be flooded */
	if (!(CHECK_FLAG(exti->flags, EXT_LPFLG_LSA_ACTIVE)))
		return;

	zlog_debug("EXT (%s): Schedule %s%s%s LSA for interface %s", __func__,
		   opcode == REORIGINATE_THIS_LSA ? "Re-Originate" : "",
		   opcode == REFRESH_THIS_LSA ? "Refresh" : "",
		   opcode == FLUSH_THIS_LSA ? "Flush" : "",
		   exti->ifp ? exti->ifp->name : "-");

	/* Set LSA header information */
	if (exti->area == NULL) {
		zlog_warn(
			"EXT (%s): Flooding is Area scope but area is not yet "
			"set",
			__func__);
		if (OspfEXT.area == NULL) {
			top = ospf_lookup_by_vrf_id(VRF_DEFAULT);
			OspfEXT.area = ospf_area_lookup_by_area_id(
				top, OspfEXT.area_id);
		}
		exti->area = OspfEXT.area;
	}
	lsa.area = exti->area;
	lsa.data = &lsah;
	lsah.type = OSPF_OPAQUE_AREA_LSA;
	tmp = SET_OPAQUE_LSID(OPAQUE_TYPE_EXTENDED_PREFIX_LSA, exti->instance);
	lsah.id.s_addr = htonl(tmp);

	switch (opcode) {
	case REORIGINATE_THIS_LSA:
		ospf_opaque_lsa_reoriginate_schedule(
			(void *)exti->area, OSPF_OPAQUE_AREA_LSA,
			OPAQUE_TYPE_EXTENDED_PREFIX_LSA);
		break;
	case REFRESH_THIS_LSA:
		ospf_opaque_lsa_refresh_schedule(&lsa);
		break;
	case FLUSH_THIS_LSA:
		UNSET_FLAG(exti->flags, EXT_LPFLG_LSA_ENGAGED);
		ospf_opaque_lsa_flush_schedule(&lsa);
		break;
	default:
		zlog_warn("EXT (%s): Unknown opcode", __func__);
		break;
	}
}

/* Schedule Extended Link Opaque LSA origination/refreshment/flushing */
static void ospf_ext_link_lsa_schedule(struct ext_itf *exti,
				       enum lsa_opcode opcode)
{
	struct ospf_lsa lsa;
	struct lsa_header lsah;
	struct ospf *top;
	uint32_t tmp;

	memset(&lsa, 0, sizeof(lsa));
	memset(&lsah, 0, sizeof(lsah));

	/* Sanity Check */
	if (exti == NULL)
		return;

	/* Check if the corresponding link is ready to be flooded */
	if (!(CHECK_FLAG(exti->flags, EXT_LPFLG_LSA_ACTIVE)))
		return;

	zlog_debug("EXT (%s): Schedule %s%s%s LSA for interface %s", __func__,
		   opcode == REORIGINATE_THIS_LSA ? "Re-Originate" : "",
		   opcode == REFRESH_THIS_LSA ? "Refresh" : "",
		   opcode == FLUSH_THIS_LSA ? "Flush" : "",
		   exti->ifp ? exti->ifp->name : "-");

	/* Set LSA header information */
	if (exti->area == NULL) {
		zlog_warn(
			"EXT (%s): Flooding is Area scope but area is not "
			"yet set",
			__func__);
		if (OspfEXT.area == NULL) {
			top = ospf_lookup_by_vrf_id(VRF_DEFAULT);
			OspfEXT.area = ospf_area_lookup_by_area_id(
				top, OspfEXT.area_id);
		}
		exti->area = OspfEXT.area;
	}
	lsa.area = exti->area;
	lsa.data = &lsah;
	lsah.type = OSPF_OPAQUE_AREA_LSA;
	tmp = SET_OPAQUE_LSID(OPAQUE_TYPE_EXTENDED_LINK_LSA, exti->instance);
	lsah.id.s_addr = htonl(tmp);

	switch (opcode) {
	case REORIGINATE_THIS_LSA:
		ospf_opaque_lsa_reoriginate_schedule(
			(void *)exti->area, OSPF_OPAQUE_AREA_LSA,
			OPAQUE_TYPE_EXTENDED_LINK_LSA);
		break;
	case REFRESH_THIS_LSA:
		ospf_opaque_lsa_refresh_schedule(&lsa);
		break;
	case FLUSH_THIS_LSA:
		UNSET_FLAG(exti->flags, EXT_LPFLG_LSA_ENGAGED);
		ospf_opaque_lsa_flush_schedule(&lsa);
		break;
	default:
		zlog_warn("EXT (%s): Unknown opcode", __func__);
		break;
	}
}

/* Schedule Extended Link or Prefix depending of the Type of LSA */
static void ospf_ext_lsa_schedule(struct ext_itf *exti, enum lsa_opcode op)
{

	if (exti->stype == PREF_SID)
		ospf_ext_pref_lsa_schedule(exti, op);
	else
		ospf_ext_link_lsa_schedule(exti, op);
}

/*
 * ------------------------------------
 * Followings are vty show functions.
 * ------------------------------------
 */

/* Cisco experimental SubTLV */
static uint16_t show_vty_ext_link_rmt_itf_addr(struct vty *vty,
					       struct tlv_header *tlvh)
{
	struct ext_subtlv_rmt_itf_addr *top;

	top = (struct ext_subtlv_rmt_itf_addr *)tlvh;

	vty_out(vty,
		"  Remote Interface Address Sub-TLV: Length %u\n	"
		"Address: %s\n",
		ntohs(top->header.length), inet_ntoa(top->value));

	return TLV_SIZE(tlvh);
}

/* Adjacency SID SubTLV */
static uint16_t show_vty_ext_link_adj_sid(struct vty *vty,
					  struct tlv_header *tlvh)
{
	struct ext_subtlv_adj_sid *top = (struct ext_subtlv_adj_sid *)tlvh;

	vty_out(vty,
		"  Adj-SID Sub-TLV: Length %u\n\tFlags: "
		"0x%x\n\tMT-ID:0x%x\n\tWeight: 0x%x\n\t%s: %u\n",
		ntohs(top->header.length), top->flags, top->mtid, top->weight,
		CHECK_FLAG(top->flags, EXT_SUBTLV_LINK_ADJ_SID_VFLG) ? "Label"
								     : "Index",
		CHECK_FLAG(top->flags, EXT_SUBTLV_LINK_ADJ_SID_VFLG)
			? GET_LABEL(ntohl(top->value))
			: ntohl(top->value));

	return TLV_SIZE(tlvh);
}

/* LAN Adjacency SubTLV */
static uint16_t show_vty_ext_link_lan_adj_sid(struct vty *vty,
					      struct tlv_header *tlvh)
{
	struct ext_subtlv_lan_adj_sid *top =
		(struct ext_subtlv_lan_adj_sid *)tlvh;

	vty_out(vty,
		"  LAN-Adj-SID Sub-TLV: Length %u\n\tFlags: "
		"0x%x\n\tMT-ID:0x%x\n\tWeight: 0x%x\n\tNeighbor ID: "
		"%s\n\t%s: %u\n",
		ntohs(top->header.length), top->flags, top->mtid, top->weight,
		inet_ntoa(top->neighbor_id),
		CHECK_FLAG(top->flags, EXT_SUBTLV_LINK_ADJ_SID_VFLG) ? "Label"
								     : "Index",
		CHECK_FLAG(top->flags, EXT_SUBTLV_LINK_ADJ_SID_VFLG)
			? GET_LABEL(ntohl(top->value))
			: ntohl(top->value));

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_unknown_tlv(struct vty *vty, struct tlv_header *tlvh)
{
	vty_out(vty, "    Unknown TLV: [type(0x%x), length(0x%x)]\n",
		ntohs(tlvh->type), ntohs(tlvh->length));

	return TLV_SIZE(tlvh);
}

/* Extended Link Sub TLVs */
static uint16_t show_vty_link_info(struct vty *vty, struct tlv_header *ext)
{
	struct ext_tlv_link *top = (struct ext_tlv_link *)ext;
	struct tlv_header *tlvh;
	uint16_t length = ntohs(top->header.length) - 3 * sizeof(uint32_t);
	uint16_t sum = 0;

	vty_out(vty,
		"  Extended Link TLV: Length %u\n	Link Type: 0x%x\n"
		"	Link ID: %s\n",
		ntohs(top->header.length), top->link_type,
		inet_ntoa(top->link_id));
	vty_out(vty, "	Link data: %s\n", inet_ntoa(top->link_data));

	tlvh = (struct tlv_header *)((char *)(ext) + TLV_HDR_SIZE
				     + EXT_TLV_LINK_SIZE);
	for (; sum < length; tlvh = TLV_HDR_NEXT(tlvh)) {
		switch (ntohs(tlvh->type)) {
		case EXT_SUBTLV_ADJ_SID:
			sum += show_vty_ext_link_adj_sid(vty, tlvh);
			break;
		case EXT_SUBTLV_LAN_ADJ_SID:
			sum += show_vty_ext_link_lan_adj_sid(vty, tlvh);
			break;
		case EXT_SUBTLV_RMT_ITF_ADDR:
			sum += show_vty_ext_link_rmt_itf_addr(vty, tlvh);
			break;
		default:
			sum += show_vty_unknown_tlv(vty, tlvh);
			break;
		}
	}

	return sum + sizeof(struct ext_tlv_link);
}

/* Extended Link TLVs */
static void ospf_ext_link_show_info(struct vty *vty, struct ospf_lsa *lsa)
{
	struct lsa_header *lsah = (struct lsa_header *)lsa->data;
	struct tlv_header *tlvh;
	uint16_t length = 0, sum = 0;

	/* Initialize TLV browsing */
	length = ntohs(lsah->length) - OSPF_LSA_HEADER_SIZE;

	for (tlvh = TLV_HDR_TOP(lsah); sum < length;
	     tlvh = TLV_HDR_NEXT(tlvh)) {
		switch (ntohs(tlvh->type)) {
		case EXT_TLV_LINK:
			sum += show_vty_link_info(vty, tlvh);
			break;
		default:
			sum += show_vty_unknown_tlv(vty, tlvh);
			break;
		}
	}
}

/* Prefix SID SubTLV */
static uint16_t show_vty_ext_pref_pref_sid(struct vty *vty,
					   struct tlv_header *tlvh)
{
	struct ext_subtlv_prefix_sid *top =
		(struct ext_subtlv_prefix_sid *)tlvh;

	vty_out(vty,
		"  Prefix SID Sub-TLV: Length %u\n\tAlgorithm: "
		"%u\n\tFlags: 0x%x\n\tMT-ID:0x%x\n\t%s: %u\n",
		ntohs(top->header.length), top->algorithm, top->flags,
		top->mtid,
		CHECK_FLAG(top->flags, EXT_SUBTLV_PREFIX_SID_VFLG) ? "Label"
								   : "Index",
		CHECK_FLAG(top->flags, EXT_SUBTLV_PREFIX_SID_VFLG)
			? GET_LABEL(ntohl(top->value))
			: ntohl(top->value));

	return TLV_SIZE(tlvh);
}

/* Extended Prefix SubTLVs */
static uint16_t show_vty_pref_info(struct vty *vty, struct tlv_header *ext)
{
	struct ext_tlv_prefix *top = (struct ext_tlv_prefix *)ext;
	struct tlv_header *tlvh;
	uint16_t length = ntohs(top->header.length) - 2 * sizeof(uint32_t);
	uint16_t sum = 0;

	vty_out(vty,
		"  Extended Prefix TLV: Length %u\n\tRoute Type: %u\n"
		"\tAddress Family: 0x%x\n\tFlags: 0x%x\n\tAddress: %s/%u\n",
		ntohs(top->header.length), top->route_type, top->af, top->flags,
		inet_ntoa(top->address), top->pref_length);

	tlvh = (struct tlv_header *)((char *)(ext) + TLV_HDR_SIZE
				     + EXT_TLV_PREFIX_SIZE);
	for (; sum < length; tlvh = TLV_HDR_NEXT(tlvh)) {
		switch (ntohs(tlvh->type)) {
		case EXT_SUBTLV_PREFIX_SID:
			sum += show_vty_ext_pref_pref_sid(vty, tlvh);
			break;
		default:
			sum += show_vty_unknown_tlv(vty, tlvh);
			break;
		}
	}

	return sum + sizeof(struct ext_tlv_prefix);
}

/* Extended Prefix TLVs */
static void ospf_ext_pref_show_info(struct vty *vty, struct ospf_lsa *lsa)
{
	struct lsa_header *lsah = (struct lsa_header *)lsa->data;
	struct tlv_header *tlvh;
	uint16_t length = 0, sum = 0;

	/* Initialize TLV browsing */
	length = ntohs(lsah->length) - OSPF_LSA_HEADER_SIZE;

	for (tlvh = TLV_HDR_TOP(lsah); sum < length;
	     tlvh = TLV_HDR_NEXT(tlvh)) {
		switch (ntohs(tlvh->type)) {
		case EXT_TLV_PREFIX:
			sum += show_vty_pref_info(vty, tlvh);
			break;
		default:
			sum += show_vty_unknown_tlv(vty, tlvh);
			break;
		}
	}
}
