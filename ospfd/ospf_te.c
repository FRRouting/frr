// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This is an implementation of RFC3630
 * Copyright (C) 2001 KDD R&D Laboratories, Inc.
 * http://www.kddlabs.co.jp/
 *
 * Copyright (C) 2012 Orange Labs
 * http://www.orange.com
 */

/* Add support of RFC7471 */
/* Add support of RFC5392, RFC6827 */

#include <zebra.h>
#include <math.h>

#include "linklist.h"
#include "prefix.h"
#include "vrf.h"
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
#include "network.h"
#include "link_state.h"
#include "zclient.h"
#include "printfrr.h"
#include <lib/json.h>

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
#include "ospfd/ospf_te.h"
#include "ospfd/ospf_sr.h"
#include "ospfd/ospf_ri.h"
#include "ospfd/ospf_ext.h"
#include "ospfd/ospf_vty.h"
#include "ospfd/ospf_errors.h"

/*
 * Global variable to manage Opaque-LSA/MPLS-TE on this node.
 * Note that all parameter values are stored in network byte order.
 */
struct ospf_mpls_te OspfMplsTE;

static const char *const mode2text[] = {"Off", "AS", "Area"};


/*------------------------------------------------------------------------*
 * Following are initialize/terminate functions for MPLS-TE handling.
 *------------------------------------------------------------------------*/

static int ospf_mpls_te_new_if(struct interface *ifp);
static int ospf_mpls_te_del_if(struct interface *ifp);
static void ospf_mpls_te_ism_change(struct ospf_interface *oi, int old_status);
static void ospf_mpls_te_nsm_change(struct ospf_neighbor *nbr, int old_status);
static void ospf_mpls_te_config_write_router(struct vty *vty);
static void ospf_mpls_te_show_info(struct vty *vty, struct json_object *json,
				   struct ospf_lsa *lsa);
static int ospf_mpls_te_lsa_originate_area(void *arg);
static int ospf_mpls_te_lsa_inter_as_as(void *arg);
static int ospf_mpls_te_lsa_inter_as_area(void *arg);
static struct ospf_lsa *ospf_mpls_te_lsa_refresh(struct ospf_lsa *lsa);
static int ospf_mpls_te_lsa_update(struct ospf_lsa *lsa);
static int ospf_mpls_te_lsa_delete(struct ospf_lsa *lsa);

static void del_mpls_te_link(void *val);
static void ospf_mpls_te_register_vty(void);

int ospf_mpls_te_init(void)
{
	int rc;

	/* Register Opaque AREA LSA Type 1 for Traffic Engineering */
	rc = ospf_register_opaque_functab(
		OSPF_OPAQUE_AREA_LSA,
		OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA,
		ospf_mpls_te_new_if,
		ospf_mpls_te_del_if,
		ospf_mpls_te_ism_change,
		ospf_mpls_te_nsm_change,
		ospf_mpls_te_config_write_router,
		NULL, /* ospf_mpls_te_config_write_if */
		NULL, /* ospf_mpls_te_config_write_debug */
		ospf_mpls_te_show_info, ospf_mpls_te_lsa_originate_area,
		ospf_mpls_te_lsa_refresh,
		ospf_mpls_te_lsa_update, /* ospf_mpls_te_new_lsa_hook */
		ospf_mpls_te_lsa_delete /* ospf_mpls_te_del_lsa_hook */);
	if (rc != 0) {
		flog_warn(
			EC_OSPF_OPAQUE_REGISTRATION,
			"MPLS-TE (%s): Failed to register Traffic Engineering functions",
			__func__);
		return rc;
	}

	/*
	 * Wee need also to register Opaque LSA Type 6 i.e. Inter-AS RFC5392 for
	 * both AREA and AS at least to have the possibility to call the show()
	 * function when looking to the opaque LSA of the OSPF database.
	 */
	rc = ospf_register_opaque_functab(OSPF_OPAQUE_AREA_LSA,
					  OPAQUE_TYPE_INTER_AS_LSA, NULL,
					  NULL, NULL, NULL, NULL, NULL, NULL,
					  ospf_mpls_te_show_info,
					  ospf_mpls_te_lsa_inter_as_area,
					  ospf_mpls_te_lsa_refresh, NULL, NULL);
	if (rc != 0) {
		flog_warn(
			EC_OSPF_OPAQUE_REGISTRATION,
			"MPLS-TE (%s): Failed to register Inter-AS with Area scope",
			__func__);
		return rc;
	}

	rc = ospf_register_opaque_functab(OSPF_OPAQUE_AS_LSA,
					  OPAQUE_TYPE_INTER_AS_LSA, NULL,
					  NULL, NULL, NULL, NULL, NULL, NULL,
					  ospf_mpls_te_show_info,
					  ospf_mpls_te_lsa_inter_as_as,
					  ospf_mpls_te_lsa_refresh, NULL, NULL);
	if (rc != 0) {
		flog_warn(
			EC_OSPF_OPAQUE_REGISTRATION,
			"MPLS-TE (%s): Failed to register Inter-AS with AS scope",
			__func__);
		return rc;
	}

	memset(&OspfMplsTE, 0, sizeof(OspfMplsTE));
	OspfMplsTE.enabled = false;
	OspfMplsTE.export = false;
	OspfMplsTE.inter_as = Off;
	OspfMplsTE.iflist = list_new();
	OspfMplsTE.iflist->del = del_mpls_te_link;

	ospf_mpls_te_register_vty();

	return rc;
}

void ospf_mpls_te_term(void)
{
	list_delete(&OspfMplsTE.iflist);

	ospf_delete_opaque_functab(OSPF_OPAQUE_AREA_LSA,
				   OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA);
	ospf_delete_opaque_functab(OSPF_OPAQUE_AREA_LSA,
				   OPAQUE_TYPE_INTER_AS_LSA);
	ospf_delete_opaque_functab(OSPF_OPAQUE_AS_LSA,
				   OPAQUE_TYPE_INTER_AS_LSA);

	OspfMplsTE.enabled = false;
	OspfMplsTE.inter_as = Off;
	OspfMplsTE.export = false;

	return;
}

void ospf_mpls_te_finish(void)
{
	OspfMplsTE.enabled = false;
	OspfMplsTE.inter_as = Off;
	OspfMplsTE.export = false;
}

/*------------------------------------------------------------------------*
 * Following are control functions for MPLS-TE parameters management.
 *------------------------------------------------------------------------*/
static void del_mpls_te_link(void *val)
{
	XFREE(MTYPE_OSPF_MPLS_TE, val);
	return;
}

static uint32_t get_mpls_te_instance_value(void)
{
	static uint32_t seqno = 0;

	if (seqno < MAX_LEGAL_TE_INSTANCE_NUM)
		seqno += 1;
	else
		seqno = 1; /* Avoid zero. */

	return seqno;
}

static struct mpls_te_link *lookup_linkparams_by_ifp(struct interface *ifp)
{
	struct listnode *node, *nnode;
	struct mpls_te_link *lp;

	for (ALL_LIST_ELEMENTS(OspfMplsTE.iflist, node, nnode, lp))
		if (lp->ifp == ifp)
			return lp;

	return NULL;
}

static struct mpls_te_link *lookup_linkparams_by_instance(struct ospf_lsa *lsa)
{
	struct listnode *node;
	struct mpls_te_link *lp;
	unsigned int key = GET_OPAQUE_ID(ntohl(lsa->data->id.s_addr));

	for (ALL_LIST_ELEMENTS_RO(OspfMplsTE.iflist, node, lp))
		if (lp->instance == key)
			return lp;

	ote_debug("MPLS-TE (%s): Entry not found: key(%x)", __func__, key);
	return NULL;
}

static void ospf_mpls_te_foreach_area(
	void (*func)(struct mpls_te_link *lp, enum lsa_opcode sched_opcode),
	enum lsa_opcode sched_opcode)
{
	struct listnode *node, *nnode;
	struct listnode *node2;
	struct mpls_te_link *lp;
	struct ospf_area *area;

	for (ALL_LIST_ELEMENTS(OspfMplsTE.iflist, node, nnode, lp)) {
		/* Skip Inter-AS TEv2 Links */
		if (IS_INTER_AS(lp->type))
			continue;
		if ((area = lp->area) == NULL)
			continue;
		if (CHECK_FLAG(lp->flags, LPFLG_LOOKUP_DONE))
			continue;

		if (func != NULL)
			(*func)(lp, sched_opcode);

		for (node2 = listnextnode(node); node2;
		     node2 = listnextnode(node2))
			if ((lp = listgetdata(node2)) != NULL)
				if (lp->area != NULL)
					if (IPV4_ADDR_SAME(&lp->area->area_id,
							   &area->area_id))
						SET_FLAG(lp->flags,
							 LPFLG_LOOKUP_DONE);
	}

	for (ALL_LIST_ELEMENTS_RO(OspfMplsTE.iflist, node, lp))
		if (lp->area != NULL)
			UNSET_FLAG(lp->flags, LPFLG_LOOKUP_DONE);

	return;
}

static void set_mpls_te_router_addr(struct in_addr ipv4)
{
	OspfMplsTE.router_addr.header.type = htons(TE_TLV_ROUTER_ADDR);
	OspfMplsTE.router_addr.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	OspfMplsTE.router_addr.value = ipv4;
	return;
}

static void set_linkparams_link_header(struct mpls_te_link *lp)
{
	uint16_t length = 0;

	/* TE_LINK_SUBTLV_LINK_TYPE */
	if (ntohs(lp->link_type.header.type) != 0)
		length += TLV_SIZE(&lp->link_type.header);

	/* TE_LINK_SUBTLV_LINK_ID */
	if (ntohs(lp->link_id.header.type) != 0)
		length += TLV_SIZE(&lp->link_id.header);

	/* TE_LINK_SUBTLV_LCLIF_IPADDR */
	if (lp->lclif_ipaddr.header.type != 0)
		length += TLV_SIZE(&lp->lclif_ipaddr.header);

	/* TE_LINK_SUBTLV_RMTIF_IPADDR */
	if (lp->rmtif_ipaddr.header.type != 0)
		length += TLV_SIZE(&lp->rmtif_ipaddr.header);

	/* TE_LINK_SUBTLV_TE_METRIC */
	if (ntohs(lp->te_metric.header.type) != 0)
		length += TLV_SIZE(&lp->te_metric.header);

	/* TE_LINK_SUBTLV_MAX_BW */
	if (ntohs(lp->max_bw.header.type) != 0)
		length += TLV_SIZE(&lp->max_bw.header);

	/* TE_LINK_SUBTLV_MAX_RSV_BW */
	if (ntohs(lp->max_rsv_bw.header.type) != 0)
		length += TLV_SIZE(&lp->max_rsv_bw.header);

	/* TE_LINK_SUBTLV_UNRSV_BW */
	if (ntohs(lp->unrsv_bw.header.type) != 0)
		length += TLV_SIZE(&lp->unrsv_bw.header);

	/* TE_LINK_SUBTLV_RSC_CLSCLR */
	if (ntohs(lp->rsc_clsclr.header.type) != 0)
		length += TLV_SIZE(&lp->rsc_clsclr.header);

	/* TE_LINK_SUBTLV_LLRI */
	if (ntohs(lp->llri.header.type) != 0)
		length += TLV_SIZE(&lp->llri.header);

	/* TE_LINK_SUBTLV_RIP */
	if (ntohs(lp->rip.header.type) != 0)
		length += TLV_SIZE(&lp->rip.header);

	/* TE_LINK_SUBTLV_RAS */
	if (ntohs(lp->ras.header.type) != 0)
		length += TLV_SIZE(&lp->ras.header);

	/* TE_LINK_SUBTLV_LRRID */
	if (ntohs(lp->lrrid.header.type) != 0)
		length += TLV_SIZE(&lp->lrrid.header);

	/* TE_LINK_SUBTLV_AV_DELAY */
	if (ntohs(lp->av_delay.header.type) != 0)
		length += TLV_SIZE(&lp->av_delay.header);

	/* TE_LINK_SUBTLV_MM_DELAY */
	if (ntohs(lp->mm_delay.header.type) != 0)
		length += TLV_SIZE(&lp->mm_delay.header);

	/* TE_LINK_SUBTLV_DELAY_VAR */
	if (ntohs(lp->delay_var.header.type) != 0)
		length += TLV_SIZE(&lp->delay_var.header);

	/* TE_LINK_SUBTLV_PKT_LOSS */
	if (ntohs(lp->pkt_loss.header.type) != 0)
		length += TLV_SIZE(&lp->pkt_loss.header);

	/* TE_LINK_SUBTLV_RES_BW */
	if (ntohs(lp->res_bw.header.type) != 0)
		length += TLV_SIZE(&lp->res_bw.header);

	/* TE_LINK_SUBTLV_AVA_BW */
	if (ntohs(lp->ava_bw.header.type) != 0)
		length += TLV_SIZE(&lp->ava_bw.header);

	/* TE_LINK_SUBTLV_USE_BW */
	if (ntohs(lp->use_bw.header.type) != 0)
		length += TLV_SIZE(&lp->use_bw.header);

	lp->link_header.header.type = htons(TE_TLV_LINK);
	lp->link_header.header.length = htons(length);

	return;
}

static void set_linkparams_link_type(struct ospf_interface *oi,
				     struct mpls_te_link *lp)
{
	lp->link_type.header.type = htons(TE_LINK_SUBTLV_LINK_TYPE);
	lp->link_type.header.length = htons(TE_LINK_SUBTLV_TYPE_SIZE);

	switch (oi->type) {
	case OSPF_IFTYPE_POINTOPOINT:
		lp->link_type.link_type.value = LINK_TYPE_SUBTLV_VALUE_PTP;
		break;
	case OSPF_IFTYPE_BROADCAST:
	case OSPF_IFTYPE_NBMA:
		lp->link_type.link_type.value = LINK_TYPE_SUBTLV_VALUE_MA;
		break;
	default:
		/* Not supported yet. */ /* XXX */
		lp->link_type.header.type = htons(0);
		break;
	}
	return;
}

static void set_linkparams_link_id(struct mpls_te_link *lp,
				   struct in_addr link_id)
{

	lp->link_id.header.type = htons(TE_LINK_SUBTLV_LINK_ID);
	lp->link_id.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	lp->link_id.value = link_id;
	return;
}

static void set_linkparams_lclif_ipaddr(struct mpls_te_link *lp,
					struct in_addr lclif)
{

	lp->lclif_ipaddr.header.type = htons(TE_LINK_SUBTLV_LCLIF_IPADDR);
	lp->lclif_ipaddr.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	lp->lclif_ipaddr.value[0] = lclif;
	return;
}

static void set_linkparams_rmtif_ipaddr(struct mpls_te_link *lp,
					struct in_addr rmtif)
{

	lp->rmtif_ipaddr.header.type = htons(TE_LINK_SUBTLV_RMTIF_IPADDR);
	lp->rmtif_ipaddr.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	lp->rmtif_ipaddr.value[0] = rmtif;
	return;
}

static void set_linkparams_te_metric(struct mpls_te_link *lp,
				     uint32_t te_metric)
{
	lp->te_metric.header.type = htons(TE_LINK_SUBTLV_TE_METRIC);
	lp->te_metric.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	lp->te_metric.value = htonl(te_metric);
	return;
}

static void set_linkparams_max_bw(struct mpls_te_link *lp, float fp)
{
	lp->max_bw.header.type = htons(TE_LINK_SUBTLV_MAX_BW);
	lp->max_bw.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	lp->max_bw.value = htonf(fp);
	return;
}

static void set_linkparams_max_rsv_bw(struct mpls_te_link *lp, float fp)
{
	lp->max_rsv_bw.header.type = htons(TE_LINK_SUBTLV_MAX_RSV_BW);
	lp->max_rsv_bw.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	lp->max_rsv_bw.value = htonf(fp);
	return;
}

static void set_linkparams_unrsv_bw(struct mpls_te_link *lp, int priority,
				    float fp)
{
	/* Note that TLV-length field is the size of array. */
	lp->unrsv_bw.header.type = htons(TE_LINK_SUBTLV_UNRSV_BW);
	lp->unrsv_bw.header.length = htons(TE_LINK_SUBTLV_UNRSV_SIZE);
	lp->unrsv_bw.value[priority] = htonf(fp);
	return;
}

static void set_linkparams_rsc_clsclr(struct mpls_te_link *lp,
				      uint32_t classcolor)
{
	lp->rsc_clsclr.header.type = htons(TE_LINK_SUBTLV_RSC_CLSCLR);
	lp->rsc_clsclr.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	lp->rsc_clsclr.value = htonl(classcolor);
	return;
}

static void set_linkparams_inter_as(struct mpls_te_link *lp,
				    struct in_addr addr, uint32_t as)
{

	/* Set the Remote ASBR IP address and then the associated AS number */
	lp->rip.header.type = htons(TE_LINK_SUBTLV_RIP);
	lp->rip.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	lp->rip.value = addr;

	lp->ras.header.type = htons(TE_LINK_SUBTLV_RAS);
	lp->ras.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	lp->ras.value = htonl(as);

	/* Set Type & Flooding flag accordingly */
	lp->type = INTER_AS;
	if (OspfMplsTE.inter_as == AS)
		SET_FLAG(lp->flags, LPFLG_LSA_FLOOD_AS);
	else
		UNSET_FLAG(lp->flags, LPFLG_LSA_FLOOD_AS);
}

static void unset_linkparams_inter_as(struct mpls_te_link *lp)
{

	/* Reset the Remote ASBR IP address and then the associated AS number */
	lp->rip.header.type = htons(0);
	lp->rip.header.length = htons(0);
	lp->rip.value.s_addr = htonl(0);

	lp->ras.header.type = htons(0);
	lp->ras.header.length = htons(0);
	lp->ras.value = htonl(0);

	/* Reset Type & Flooding flag accordingly */
	lp->type = STD_TE;
	UNSET_FLAG(lp->flags, LPFLG_LSA_FLOOD_AS);
}

void set_linkparams_llri(struct mpls_te_link *lp, uint32_t local,
			 uint32_t remote)
{

	lp->llri.header.type = htons(TE_LINK_SUBTLV_LLRI);
	lp->llri.header.length = htons(TE_LINK_SUBTLV_LLRI_SIZE);
	lp->llri.local = htonl(local);
	lp->llri.remote = htonl(remote);
}

void set_linkparams_lrrid(struct mpls_te_link *lp, struct in_addr local,
			  struct in_addr remote)
{

	lp->lrrid.header.type = htons(TE_LINK_SUBTLV_LRRID);
	lp->lrrid.header.length = htons(TE_LINK_SUBTLV_LRRID_SIZE);
	lp->lrrid.local.s_addr = local.s_addr;
	lp->lrrid.remote.s_addr = remote.s_addr;
}

static void set_linkparams_av_delay(struct mpls_te_link *lp, uint32_t delay,
				    uint8_t anormal)
{
	uint32_t tmp;
	/* Note that TLV-length field is the size of array. */
	lp->av_delay.header.type = htons(TE_LINK_SUBTLV_AV_DELAY);
	lp->av_delay.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	tmp = delay & TE_EXT_MASK;
	if (anormal)
		tmp |= TE_EXT_ANORMAL;
	lp->av_delay.value = htonl(tmp);
	return;
}

static void set_linkparams_mm_delay(struct mpls_te_link *lp, uint32_t low,
				    uint32_t high, uint8_t anormal)
{
	uint32_t tmp;
	/* Note that TLV-length field is the size of array. */
	lp->mm_delay.header.type = htons(TE_LINK_SUBTLV_MM_DELAY);
	lp->mm_delay.header.length = htons(TE_LINK_SUBTLV_MM_DELAY_SIZE);
	tmp = low & TE_EXT_MASK;
	if (anormal)
		tmp |= TE_EXT_ANORMAL;
	lp->mm_delay.low = htonl(tmp);
	lp->mm_delay.high = htonl(high);
	return;
}

static void set_linkparams_delay_var(struct mpls_te_link *lp, uint32_t jitter)
{
	/* Note that TLV-length field is the size of array. */
	lp->delay_var.header.type = htons(TE_LINK_SUBTLV_DELAY_VAR);
	lp->delay_var.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	lp->delay_var.value = htonl(jitter & TE_EXT_MASK);
	return;
}

static void set_linkparams_pkt_loss(struct mpls_te_link *lp, uint32_t loss,
				    uint8_t anormal)
{
	uint32_t tmp;
	/* Note that TLV-length field is the size of array. */
	lp->pkt_loss.header.type = htons(TE_LINK_SUBTLV_PKT_LOSS);
	lp->pkt_loss.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	tmp = loss & TE_EXT_MASK;
	if (anormal)
		tmp |= TE_EXT_ANORMAL;
	lp->pkt_loss.value = htonl(tmp);
	return;
}

static void set_linkparams_res_bw(struct mpls_te_link *lp, float fp)
{
	/* Note that TLV-length field is the size of array. */
	lp->res_bw.header.type = htons(TE_LINK_SUBTLV_RES_BW);
	lp->res_bw.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	lp->res_bw.value = htonf(fp);
	return;
}

static void set_linkparams_ava_bw(struct mpls_te_link *lp, float fp)
{
	/* Note that TLV-length field is the size of array. */
	lp->ava_bw.header.type = htons(TE_LINK_SUBTLV_AVA_BW);
	lp->ava_bw.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	lp->ava_bw.value = htonf(fp);
	return;
}

static void set_linkparams_use_bw(struct mpls_te_link *lp, float fp)
{
	/* Note that TLV-length field is the size of array. */
	lp->use_bw.header.type = htons(TE_LINK_SUBTLV_USE_BW);
	lp->use_bw.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	lp->use_bw.value = htonf(fp);
	return;
}

/* Update TE parameters from Interface */
static void update_linkparams(struct mpls_te_link *lp)
{
	int i;
	struct interface *ifp;

	/* Get the Interface structure */
	if ((ifp = lp->ifp) == NULL) {
		ote_debug(
			"MPLS-TE (%s): Abort update TE parameters: no interface associated to Link Parameters",
			__func__);
		return;
	}
	if (!HAS_LINK_PARAMS(ifp)) {
		ote_debug(
			"MPLS-TE (%s): Abort update TE parameters: no Link Parameters for interface",
			__func__);
		return;
	}

	/* RFC3630 metrics */
	if (IS_PARAM_SET(ifp->link_params, LP_ADM_GRP))
		set_linkparams_rsc_clsclr(lp, ifp->link_params->admin_grp);
	else
		TLV_TYPE(lp->rsc_clsclr) = 0;

	if (IS_PARAM_SET(ifp->link_params, LP_MAX_BW))
		set_linkparams_max_bw(lp, ifp->link_params->max_bw);
	else
		TLV_TYPE(lp->max_bw) = 0;

	if (IS_PARAM_SET(ifp->link_params, LP_MAX_RSV_BW))
		set_linkparams_max_rsv_bw(lp, ifp->link_params->max_rsv_bw);
	else
		TLV_TYPE(lp->max_rsv_bw) = 0;

	if (IS_PARAM_SET(ifp->link_params, LP_UNRSV_BW))
		for (i = 0; i < MAX_CLASS_TYPE; i++)
			set_linkparams_unrsv_bw(lp, i,
						ifp->link_params->unrsv_bw[i]);
	else
		TLV_TYPE(lp->unrsv_bw) = 0;

	if (IS_PARAM_SET(ifp->link_params, LP_TE_METRIC))
		set_linkparams_te_metric(lp, ifp->link_params->te_metric);
	else
		TLV_TYPE(lp->te_metric) = 0;

	/* TE metric Extensions */
	if (IS_PARAM_SET(ifp->link_params, LP_DELAY))
		set_linkparams_av_delay(lp, ifp->link_params->av_delay, 0);
	else
		TLV_TYPE(lp->av_delay) = 0;

	if (IS_PARAM_SET(ifp->link_params, LP_MM_DELAY))
		set_linkparams_mm_delay(lp, ifp->link_params->min_delay,
					ifp->link_params->max_delay, 0);
	else
		TLV_TYPE(lp->mm_delay) = 0;

	if (IS_PARAM_SET(ifp->link_params, LP_DELAY_VAR))
		set_linkparams_delay_var(lp, ifp->link_params->delay_var);
	else
		TLV_TYPE(lp->delay_var) = 0;

	if (IS_PARAM_SET(ifp->link_params, LP_PKT_LOSS))
		set_linkparams_pkt_loss(lp, ifp->link_params->pkt_loss, 0);
	else
		TLV_TYPE(lp->pkt_loss) = 0;

	if (IS_PARAM_SET(ifp->link_params, LP_RES_BW))
		set_linkparams_res_bw(lp, ifp->link_params->res_bw);
	else
		TLV_TYPE(lp->res_bw) = 0;

	if (IS_PARAM_SET(ifp->link_params, LP_AVA_BW))
		set_linkparams_ava_bw(lp, ifp->link_params->ava_bw);
	else
		TLV_TYPE(lp->ava_bw) = 0;

	if (IS_PARAM_SET(ifp->link_params, LP_USE_BW))
		set_linkparams_use_bw(lp, ifp->link_params->use_bw);
	else
		TLV_TYPE(lp->use_bw) = 0;

	/* RFC5392 */
	if (IS_PARAM_SET(ifp->link_params, LP_RMT_AS)) {
		/* Flush LSA if it engaged and was previously a STD_TE one */
		if (IS_STD_TE(lp->type)
		    && CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED)) {
			ote_debug(
				"MPLS-TE (%s): Update IF: Switch from Standard LSA to INTER-AS for %s[%d/%d]",
				__func__, ifp->name, lp->flags, lp->type);

			ospf_mpls_te_lsa_schedule(lp, FLUSH_THIS_LSA);
			/* Then, switch it to INTER-AS */
			if (OspfMplsTE.inter_as == AS) {
				lp->type = INTER_AS;
				SET_FLAG(lp->flags, LPFLG_LSA_FLOOD_AS);
			} else {
				lp->type = INTER_AS;
				UNSET_FLAG(lp->flags, LPFLG_LSA_FLOOD_AS);
				lp->area = ospf_area_lookup_by_area_id(
					ospf_lookup_by_vrf_id(VRF_DEFAULT),
					OspfMplsTE.interas_areaid);
			}
		}
		set_linkparams_inter_as(lp, ifp->link_params->rmt_ip,
					ifp->link_params->rmt_as);
	} else {
		ote_debug(
			"MPLS-TE (%s): Update IF: Switch from INTER-AS LSA to Standard for %s[%d/%d]",
			__func__, ifp->name, lp->flags, lp->type);

		/* reset inter-as TE params */
		/* Flush LSA if it engaged and was previously an INTER_AS one */
		if (IS_INTER_AS(lp->type)
		    && CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED)) {
			ospf_mpls_te_lsa_schedule(lp, FLUSH_THIS_LSA);
			/* Then, switch it to Standard TE */
			lp->flags = STD_TE;
			UNSET_FLAG(lp->flags, LPFLG_LSA_FLOOD_AS);
		}
		unset_linkparams_inter_as(lp);
	}
}

static void initialize_linkparams(struct mpls_te_link *lp)
{
	struct interface *ifp = lp->ifp;
	struct ospf_interface *oi = NULL;
	struct route_node *rn;

	ote_debug("MPLS-TE (%s): Initialize Link Parameters for interface %s",
		  __func__, ifp->name);

	/* Search OSPF Interface parameters for this interface */
	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {

		if ((oi = rn->info) == NULL)
			continue;

		if (oi->ifp == ifp)
			break;
	}

	if ((oi == NULL) || (oi->ifp != ifp)) {
		ote_debug(
			"MPLS-TE (%s): Could not find corresponding OSPF Interface for %s",
			__func__, ifp->name);
		return;
	}

	/*
	 * Try to set initial values those can be derived from
	 * zebra-interface information.
	 */
	set_linkparams_link_type(oi, lp);

	/* Set local IP addr */
	set_linkparams_lclif_ipaddr(lp, oi->address->u.prefix4);

	/* Set Remote IP addr if Point to Point Interface */
	if (oi->type == OSPF_IFTYPE_POINTOPOINT) {
		struct prefix *pref = CONNECTED_PREFIX(oi->connected);
		if (pref != NULL)
			set_linkparams_rmtif_ipaddr(lp, pref->u.prefix4);
	}

	/* Keep Area information in combination with link parameters. */
	lp->area = oi->area;

	return;
}

static int is_mandated_params_set(struct mpls_te_link *lp)
{
	int rc = 0;

	if (ntohs(OspfMplsTE.router_addr.header.type) == 0) {
		flog_warn(EC_OSPF_TE_UNEXPECTED,
			  "MPLS-TE (%s): Missing Router Address", __func__);
		return rc;
	}

	if (ntohs(lp->link_type.header.type) == 0) {
		flog_warn(EC_OSPF_TE_UNEXPECTED,
			  "MPLS-TE (%s): Missing Link Type", __func__);
		return rc;
	}

	if (!IS_INTER_AS(lp->type) && (ntohs(lp->link_id.header.type) == 0)) {
		flog_warn(EC_OSPF_TE_UNEXPECTED, "MPLS-TE (%s) Missing Link ID",
			  __func__);
		return rc;
	}

	rc = 1;
	return rc;
}

/*------------------------------------------------------------------------*
 * Following are callback functions against generic Opaque-LSAs handling.
 *------------------------------------------------------------------------*/

static int ospf_mpls_te_new_if(struct interface *ifp)
{
	struct mpls_te_link *new;

	ote_debug("MPLS-TE (%s): Add new %s interface %s to MPLS-TE list",
		  __func__, ifp->link_params ? "Active" : "Inactive",
		  ifp->name);

	if (lookup_linkparams_by_ifp(ifp) != NULL)
		return 0;

	new = XCALLOC(MTYPE_OSPF_MPLS_TE, sizeof(struct mpls_te_link));

	new->instance = get_mpls_te_instance_value();
	new->ifp = ifp;
	/* By default TE-Link is RFC3630 compatible flooding in Area and not
	 * active */
	/* This default behavior will be adapted with call to
	 * ospf_mpls_te_update_if() */
	new->type = STD_TE;
	new->flags = LPFLG_LSA_INACTIVE;

	/* Initialize Link Parameters from Interface */
	initialize_linkparams(new);

	/* Set TE Parameters from Interface */
	update_linkparams(new);

	/* Add Link Parameters structure to the list */
	listnode_add(OspfMplsTE.iflist, new);

	ote_debug("MPLS-TE (%s): Add new LP context for %s[%d/%d]", __func__,
		  ifp->name, new->flags, new->type);

	/* Schedule Opaque-LSA refresh. */ /* XXX */
	return 0;
}

static int ospf_mpls_te_del_if(struct interface *ifp)
{
	struct mpls_te_link *lp;
	int rc = -1;

	if ((lp = lookup_linkparams_by_ifp(ifp)) != NULL) {
		struct list *iflist = OspfMplsTE.iflist;

		/* Dequeue listnode entry from the list. */
		listnode_delete(iflist, lp);

		XFREE(MTYPE_OSPF_MPLS_TE, lp);
	}

	/* Schedule Opaque-LSA refresh. */ /* XXX */

	rc = 0;
	return rc;
}

/* Main initialization / update function of the MPLS TE Link context */

/* Call when interface TE Link parameters are modified */
void ospf_mpls_te_update_if(struct interface *ifp)
{
	struct mpls_te_link *lp;

	ote_debug("MPLS-TE (%s): Update LSA parameters for interface %s [%s]",
		  __func__, ifp->name, HAS_LINK_PARAMS(ifp) ? "ON" : "OFF");

	/* Get Link context from interface */
	if ((lp = lookup_linkparams_by_ifp(ifp)) == NULL) {
		flog_warn(
			EC_OSPF_TE_UNEXPECTED,
			"MPLS-TE (%s): Did not find Link Parameters context for interface %s",
			__func__, ifp->name);
		return;
	}

	/* Fulfill MPLS-TE Link TLV from Interface TE Link parameters */
	if (HAS_LINK_PARAMS(ifp)) {
		SET_FLAG(lp->flags, LPFLG_LSA_ACTIVE);

		/* Update TE parameters */
		update_linkparams(lp);

		/* Finally Re-Originate or Refresh Opaque LSA if MPLS_TE is
		 * enabled */
		if (OspfMplsTE.enabled)
			if (lp->area != NULL) {
				if (CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED))
					ospf_mpls_te_lsa_schedule(
						lp, REFRESH_THIS_LSA);
				else
					ospf_mpls_te_lsa_schedule(
						lp, REORIGINATE_THIS_LSA);
			}
	} else {
		/* If MPLS TE is disable on this interface, flush LSA if it is
		 * already engaged */
		if (CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED))
			ospf_mpls_te_lsa_schedule(lp, FLUSH_THIS_LSA);
		else
			/* Reset Activity flag */
			lp->flags = LPFLG_LSA_INACTIVE;
	}

	return;
}

/*
 * Just add interface and set available information. Other information
 * and flooding of LSA will be done later when adjacency will be up
 * See ospf_mpls_te_nsm_change() after
 */
static void ospf_mpls_te_ism_change(struct ospf_interface *oi, int old_state)
{

	struct mpls_te_link *lp;

	lp = lookup_linkparams_by_ifp(oi->ifp);
	if (lp == NULL) {
		flog_warn(
			EC_OSPF_TE_UNEXPECTED,
			"MPLS-TE (%s): Cannot get linkparams from OI(%s)?",
			__func__, IF_NAME(oi));
		return;
	}

	if (oi->area == NULL || oi->area->ospf == NULL) {
		flog_warn(
			EC_OSPF_TE_UNEXPECTED,
			"MPLS-TE (%s): Cannot refer to OSPF from OI(%s)?",
			__func__, IF_NAME(oi));
		return;
	}

	/* Keep Area information in combination with linkparams. */
	lp->area = oi->area;

	switch (oi->state) {
	case ISM_PointToPoint:
	case ISM_DROther:
	case ISM_Backup:
	case ISM_DR:
		/* Set Link type and Local IP addr */
		set_linkparams_link_type(oi, lp);
		set_linkparams_lclif_ipaddr(lp, oi->address->u.prefix4);

		break;
	case ISM_Down:
		/* Interface goes Down: Flush LSA if engaged */
		if (CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED)) {
			ote_debug(
				"MPLS-TE (%s): Interface %s goes down: flush LSA",
				__func__, IF_NAME(oi));
			ospf_mpls_te_lsa_schedule(lp, FLUSH_THIS_LSA);
			return;
		}
		break;
	default:
		break;
	}

	ote_debug("MPLS-TE (%s): Update Link parameters for interface %s",
		  __func__, IF_NAME(oi));

	return;
}

/*
 * Complete TE info and schedule LSA flooding
 * Link-ID and Remote IP address must be set with neighbor info
 * which are only valid once NSM state is FULL
 */
static void ospf_mpls_te_nsm_change(struct ospf_neighbor *nbr, int old_state)
{
	struct ospf_interface *oi = nbr->oi;
	struct mpls_te_link *lp;

	/* Process Link only when neighbor old or new state is NSM Full */
	if (nbr->state != NSM_Full && old_state != NSM_Full)
		return;

	/* Get interface information for Traffic Engineering */
	lp = lookup_linkparams_by_ifp(oi->ifp);
	if (lp == NULL) {
		flog_warn(
			EC_OSPF_TE_UNEXPECTED,
			"MPLS-TE (%s): Cannot get linkparams from OI(%s)?",
			__func__, IF_NAME(oi));
		return;
	}

	if (oi->area == NULL || oi->area->ospf == NULL) {
		flog_warn(
			EC_OSPF_TE_UNEXPECTED,
			"MPLS-TE (%s): Cannot refer to OSPF from OI(%s)?",
			__func__, IF_NAME(oi));
		return;
	}

	/* Flush TE Opaque LSA if Neighbor State goes Down or Deleted */
	if (OspfMplsTE.enabled
	    && (nbr->state == NSM_Down || nbr->state == NSM_Deleted)) {
		if (CHECK_FLAG(lp->flags, EXT_LPFLG_LSA_ENGAGED)) {
			ote_debug(
				"MPLS-TE (%s): Interface %s goes down: flush LSA",
				__func__, IF_NAME(oi));
			ospf_mpls_te_lsa_schedule(lp, FLUSH_THIS_LSA);
		}
		return;
	}

	/* Keep Area information in combination with SR info. */
	lp->area = oi->area;

	/*
	 * The Link ID is identical to the contents of the Link ID field
	 * in the Router LSA for these link types.
	 */
	switch (oi->state) {
	case ISM_PointToPoint:
		/* Set Link ID with neighbor Router ID */
		set_linkparams_link_id(lp, nbr->router_id);
		/* Set Remote IP address */
		set_linkparams_rmtif_ipaddr(lp, nbr->address.u.prefix4);
		break;

	case ISM_DR:
	case ISM_DROther:
	case ISM_Backup:
		/* Set Link ID with the Designated Router ID */
		set_linkparams_link_id(lp, DR(oi));
		break;

	case ISM_Down:
		/* State goes Down: Flush LSA if engaged */
		if (OspfMplsTE.enabled
		    && CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED)) {
			ote_debug(
				"MPLS-TE (%s): Interface %s goes down: flush LSA",
				__func__, IF_NAME(oi));
			ospf_mpls_te_lsa_schedule(lp, FLUSH_THIS_LSA);
		}
		return;
	default:
		break;
	}

	ote_debug("MPLS-TE (%s): Add Link-ID %pI4 for interface %s ", __func__,
		  &lp->link_id.value, oi->ifp->name);

	/* Try to Schedule LSA */
	if (OspfMplsTE.enabled) {
		if (CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED))
			ospf_mpls_te_lsa_schedule(lp, REFRESH_THIS_LSA);
		else
			ospf_mpls_te_lsa_schedule(lp, REORIGINATE_THIS_LSA);
	}
	return;
}

/*------------------------------------------------------------------------*
 * Following are OSPF protocol processing functions for MPLS-TE LSA.
 *------------------------------------------------------------------------*/

static void build_tlv_header(struct stream *s, struct tlv_header *tlvh)
{
	stream_put(s, tlvh, sizeof(struct tlv_header));
	return;
}

static void build_router_tlv(struct stream *s)
{
	struct tlv_header *tlvh = &OspfMplsTE.router_addr.header;
	if (ntohs(tlvh->type) != 0) {
		build_tlv_header(s, tlvh);
		stream_put(s, TLV_DATA(tlvh), TLV_BODY_SIZE(tlvh));
	}
	return;
}

static void build_link_subtlv(struct stream *s, struct tlv_header *tlvh)
{

	if ((tlvh != NULL) && (ntohs(tlvh->type) != 0)) {
		build_tlv_header(s, tlvh);
		stream_put(s, TLV_DATA(tlvh), TLV_BODY_SIZE(tlvh));
	}
	return;
}

static void build_link_tlv(struct stream *s, struct mpls_te_link *lp)
{
	set_linkparams_link_header(lp);
	build_tlv_header(s, &lp->link_header.header);

	build_link_subtlv(s, &lp->link_type.header);
	build_link_subtlv(s, &lp->link_id.header);
	build_link_subtlv(s, &lp->lclif_ipaddr.header);
	build_link_subtlv(s, &lp->rmtif_ipaddr.header);
	build_link_subtlv(s, &lp->te_metric.header);
	build_link_subtlv(s, &lp->max_bw.header);
	build_link_subtlv(s, &lp->max_rsv_bw.header);
	build_link_subtlv(s, &lp->unrsv_bw.header);
	build_link_subtlv(s, &lp->rsc_clsclr.header);
	build_link_subtlv(s, &lp->lrrid.header);
	build_link_subtlv(s, &lp->llri.header);
	build_link_subtlv(s, &lp->rip.header);
	build_link_subtlv(s, &lp->ras.header);
	build_link_subtlv(s, &lp->av_delay.header);
	build_link_subtlv(s, &lp->mm_delay.header);
	build_link_subtlv(s, &lp->delay_var.header);
	build_link_subtlv(s, &lp->pkt_loss.header);
	build_link_subtlv(s, &lp->res_bw.header);
	build_link_subtlv(s, &lp->ava_bw.header);
	build_link_subtlv(s, &lp->use_bw.header);

	return;
}

static void ospf_mpls_te_lsa_body_set(struct stream *s, struct mpls_te_link *lp)
{
	/*
	 * The router address TLV is type 1, and ... It must appear in exactly
	 * one Traffic Engineering LSA originated by a router but not in
	 * Inter-AS TLV.
	 */
	if (!IS_INTER_AS(lp->type))
		build_router_tlv(s);

	/*
	 * Only one Link TLV shall be carried in each LSA, allowing for fine
	 * granularity changes in topology.
	 */
	build_link_tlv(s, lp);
	return;
}

/* Create new opaque-LSA. */
static struct ospf_lsa *ospf_mpls_te_lsa_new(struct ospf *ospf,
					     struct ospf_area *area,
					     struct mpls_te_link *lp)
{
	struct stream *s;
	struct lsa_header *lsah;
	struct ospf_lsa *new = NULL;
	uint8_t options, lsa_type = 0;
	struct in_addr lsa_id;
	uint32_t tmp;
	uint16_t length;

	/* Create a stream for LSA. */
	s = stream_new(OSPF_MAX_LSA_SIZE);
	lsah = (struct lsa_header *)STREAM_DATA(s);

	options = OSPF_OPTION_O; /* Don't forget this :-) */

	/* Set opaque-LSA header fields depending of the type of RFC */
	if (IS_INTER_AS(lp->type)) {
		if (IS_FLOOD_AS(lp->flags)) {
			/* Enable AS external as we flood Inter-AS with Opaque
			 * Type 11
			 */
			options |= OSPF_OPTION_E;
			lsa_type = OSPF_OPAQUE_AS_LSA;
		} else {
			options |= LSA_OPTIONS_GET(
				area); /* Get area default option */
			options |= LSA_OPTIONS_NSSA_GET(area);
			lsa_type = OSPF_OPAQUE_AREA_LSA;
		}
		tmp = SET_OPAQUE_LSID(OPAQUE_TYPE_INTER_AS_LSA, lp->instance);
		lsa_id.s_addr = htonl(tmp);

		if (!ospf) {
			stream_free(s);
			return NULL;
		}

		lsa_header_set(s, options, lsa_type, lsa_id, ospf->router_id);
	} else {
		options |= LSA_OPTIONS_GET(area); /* Get area default option */
		options |= LSA_OPTIONS_NSSA_GET(area);
		lsa_type = OSPF_OPAQUE_AREA_LSA;
		tmp = SET_OPAQUE_LSID(OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA,
				      lp->instance);
		lsa_id.s_addr = htonl(tmp);
		lsa_header_set(s, options, lsa_type, lsa_id,
			       area->ospf->router_id);
	}

	ote_debug(
		"MPLS-TE (%s): LSA[Type%d:%pI4]: Create an Opaque-LSA/MPLS-TE instance",
		__func__, lsa_type, &lsa_id);

	/* Set opaque-LSA body fields. */
	ospf_mpls_te_lsa_body_set(s, lp);

	/* Set length. */
	length = stream_get_endp(s);
	lsah->length = htons(length);

	/* Now, create an OSPF LSA instance. */
	new = ospf_lsa_new_and_data(length);

	new->area = area;
	new->vrf_id = VRF_DEFAULT;

	SET_FLAG(new->flags, OSPF_LSA_SELF);
	memcpy(new->data, lsah, length);
	stream_free(s);

	return new;
}

static int ospf_mpls_te_lsa_originate1(struct ospf_area *area,
				       struct mpls_te_link *lp)
{
	struct ospf_lsa *new = NULL;
	int rc = -1;

	/* Create new Opaque-LSA/MPLS-TE instance. */
	new = ospf_mpls_te_lsa_new(area->ospf, area, lp);
	if (new == NULL) {
		flog_warn(EC_OSPF_TE_UNEXPECTED,
			  "MPLS-TE (%s): ospf_mpls_te_lsa_new() ?", __func__);
		return rc;
	}

	/* Install this LSA into LSDB. */
	if (ospf_lsa_install(area->ospf, NULL /*oi*/, new) == NULL) {
		flog_warn(EC_OSPF_LSA_INSTALL_FAILURE,
			  "MPLS-TE (%s): ospf_lsa_install() ?", __func__);
		ospf_lsa_unlock(&new);
		return rc;
	}

	/* Now this link-parameter entry has associated LSA. */
	SET_FLAG(lp->flags, LPFLG_LSA_ENGAGED);
	/* Update new LSA origination count. */
	area->ospf->lsa_originate_count++;

	/* Flood new LSA through area. */
	ospf_flood_through_area(area, NULL /*nbr*/, new);

	ote_debug(
		"MPLS-TE (%s): LSA[Type%d:%pI4]: Originate Opaque-LSA/MPLS-TE: Area(%pI4), Link(%s)",
		__func__, new->data->type, &new->data->id, &area->area_id,
		lp->ifp->name);
	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
		ospf_lsa_header_dump(new->data);

	rc = 0;
	return rc;
}

static int ospf_mpls_te_lsa_originate_area(void *arg)
{
	struct ospf_area *area = (struct ospf_area *)arg;
	struct listnode *node, *nnode;
	struct mpls_te_link *lp;
	int rc = -1;

	if (!OspfMplsTE.enabled) {
		ote_debug("MPLS-TE (%s): MPLS-TE is disabled now.", __func__);
		rc = 0; /* This is not an error case. */
		return rc;
	}

	for (ALL_LIST_ELEMENTS(OspfMplsTE.iflist, node, nnode, lp)) {
		/* Process only enabled LSA with area scope flooding */
		if (!CHECK_FLAG(lp->flags, LPFLG_LSA_ACTIVE)
		    || IS_FLOOD_AS(lp->flags))
			continue;

		if (lp->area == NULL)
			continue;

		if (!IPV4_ADDR_SAME(&lp->area->area_id, &area->area_id))
			continue;

		if (CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED)) {
			if (CHECK_FLAG(lp->flags, LPFLG_LSA_FORCED_REFRESH)) {
				UNSET_FLAG(lp->flags, LPFLG_LSA_FORCED_REFRESH);
				ote_debug(
					"MPLS-TE (%s): Refresh instead of Originate",
					__func__);
				ospf_mpls_te_lsa_schedule(lp, REFRESH_THIS_LSA);
			}
			continue;
		}

		if (!is_mandated_params_set(lp)) {
			ote_debug(
				"MPLS-TE (%s): Link(%s) lacks some mandated MPLS-TE parameters.",
				__func__, lp->ifp ? lp->ifp->name : "?");
			continue;
		}

		/* Ok, let's try to originate an LSA for this area and Link. */
		ote_debug(
			"MPLS-TE (%s): Let's finally reoriginate the LSA %d through the Area %pI4 for Link %s",
			__func__, lp->instance, &area->area_id,
			lp->ifp ? lp->ifp->name : "?");
		if (ospf_mpls_te_lsa_originate1(area, lp) != 0)
			return rc;
	}

	rc = 0;
	return rc;
}

static int ospf_mpls_te_lsa_originate2(struct ospf *top,
				       struct mpls_te_link *lp)
{
	struct ospf_lsa *new;
	int rc = -1;

	/* Create new Opaque-LSA/Inter-AS instance. */
	new = ospf_mpls_te_lsa_new(top, NULL, lp);
	if (new == NULL) {
		flog_warn(EC_OSPF_LSA_UNEXPECTED,
			  "MPLS-TE (%s): ospf_router_info_lsa_new() ?",
			  __func__);
		return rc;
	}

	/* Install this LSA into LSDB. */
	if (ospf_lsa_install(top, NULL /*oi */, new) == NULL) {
		flog_warn(EC_OSPF_LSA_INSTALL_FAILURE,
			  "MPLS-TE (%s): ospf_lsa_install() ?", __func__);
		ospf_lsa_unlock(&new);
		return rc;
	}

	/* Now this Router Info parameter entry has associated LSA. */
	SET_FLAG(lp->flags, LPFLG_LSA_ENGAGED);
	/* Update new LSA origination count. */
	top->lsa_originate_count++;

	/* Flood new LSA through AS. */
	ospf_flood_through_as(top, NULL /*nbr */, new);

	ote_debug(
		"MPLS-TE (%s): LSA[Type%d:%pI4]: Originate Opaque-LSA/MPLS-TE Inter-AS",
		__func__, new->data->type, &new->data->id);
	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
		ospf_lsa_header_dump(new->data);


	rc = 0;
	return rc;
}

static int ospf_mpls_te_lsa_originate_as(void *arg)
{
	struct ospf *top;
	struct ospf_area *area;
	struct listnode *node, *nnode;
	struct mpls_te_link *lp;
	int rc = -1;

	if ((!OspfMplsTE.enabled) || (OspfMplsTE.inter_as == Off)) {
		ote_debug("MPLS-TE (%s): Inter-AS is disabled for now",
			  __func__);
		rc = 0; /* This is not an error case. */
		return rc;
	}

	for (ALL_LIST_ELEMENTS(OspfMplsTE.iflist, node, nnode, lp)) {
		/* Process only enabled INTER_AS Links or Pseudo-Links */
		if (!CHECK_FLAG(lp->flags, LPFLG_LSA_ACTIVE)
		    || !CHECK_FLAG(lp->flags, LPFLG_LSA_FLOOD_AS)
		    || !IS_INTER_AS(lp->type))
			continue;

		if (CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED)) {
			if (CHECK_FLAG(lp->flags, LPFLG_LSA_FORCED_REFRESH)) {
				UNSET_FLAG(lp->flags, LPFLG_LSA_FORCED_REFRESH);
				ospf_mpls_te_lsa_schedule(lp, REFRESH_THIS_LSA);
			}
			continue;
		}

		if (!is_mandated_params_set(lp)) {
			flog_warn(
				EC_OSPF_TE_UNEXPECTED,
				"MPLS-TE (%s): Link(%s) lacks some mandated MPLS-TE parameters.",
				__func__, lp->ifp ? lp->ifp->name : "?");
			continue;
		}

		/* Ok, let's try to originate an LSA for this AS and Link. */
		ote_debug(
			"MPLS-TE (%s): Let's finally re-originate the Inter-AS LSA %d through the %s for Link %s",
			__func__, lp->instance,
			IS_FLOOD_AS(lp->flags) ? "AS" : "Area",
			lp->ifp ? lp->ifp->name : "Unknown");

		if (IS_FLOOD_AS(lp->flags)) {
			top = (struct ospf *)arg;
			ospf_mpls_te_lsa_originate2(top, lp);
		} else {
			area = (struct ospf_area *)arg;
			ospf_mpls_te_lsa_originate1(area, lp);
		}
	}

	rc = 0;
	return rc;
}

/*
 * As Inter-AS LSA must be registered with both AREA and AS flooding, and
 * because all origination callback functions are call (disregarding the Opaque
 * LSA type and Flooding scope) it is necessary to determine which flooding
 * scope is associated with the LSA origination as parameter is of type void and
 * must be cast to struct *ospf for AS flooding and to struct *ospf_area for
 * Area flooding.
 */
static int ospf_mpls_te_lsa_inter_as_as(void *arg)
{
	if (OspfMplsTE.inter_as == AS)
		return ospf_mpls_te_lsa_originate_as(arg);
	else
		return 0;
}

static int ospf_mpls_te_lsa_inter_as_area(void *arg)
{
	if (OspfMplsTE.inter_as == Area)
		return ospf_mpls_te_lsa_originate_area(arg);
	else
		return 0;
}

static struct ospf_lsa *ospf_mpls_te_lsa_refresh(struct ospf_lsa *lsa)
{
	struct mpls_te_link *lp;
	struct ospf_area *area = lsa->area;
	struct ospf *top;
	struct ospf_lsa *new = NULL;

	if (!OspfMplsTE.enabled) {
		/*
		 * This LSA must have flushed before due to MPLS-TE status
		 * change.
		 * It seems a slip among routers in the routing domain.
		 */
		ote_debug("MPLS-TE (%s): MPLS-TE is disabled now", __func__);
		lsa->data->ls_age =
			htons(OSPF_LSA_MAXAGE); /* Flush it anyway. */
	}

	/* At first, resolve lsa/lp relationship. */
	if ((lp = lookup_linkparams_by_instance(lsa)) == NULL) {
		flog_warn(EC_OSPF_TE_UNEXPECTED,
			  "MPLS-TE (%s): Invalid parameter?", __func__);
		lsa->data->ls_age =
			htons(OSPF_LSA_MAXAGE); /* Flush it anyway. */
		ospf_opaque_lsa_flush_schedule(lsa);
		return NULL;
	}

	/* Check if lp was not disable in the interval */
	if (!CHECK_FLAG(lp->flags, LPFLG_LSA_ACTIVE)) {
		flog_warn(EC_OSPF_TE_UNEXPECTED,
			  "MPLS-TE (%s): lp was disabled: Flush it!", __func__);
		lsa->data->ls_age =
			htons(OSPF_LSA_MAXAGE); /* Flush it anyway. */
	}

	/* If the lsa's age reached to MaxAge, start flushing procedure. */
	if (IS_LSA_MAXAGE(lsa)) {
		UNSET_FLAG(lp->flags, LPFLG_LSA_ENGAGED);
		ospf_opaque_lsa_flush_schedule(lsa);
		return NULL;
	}
	top = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	/* Create new Opaque-LSA/MPLS-TE instance. */
	new = ospf_mpls_te_lsa_new(top, area, lp);
	if (new == NULL) {
		flog_warn(EC_OSPF_TE_UNEXPECTED,
			  "MPLS-TE (%s): ospf_mpls_te_lsa_new() ?", __func__);
		return NULL;
	}
	new->data->ls_seqnum = lsa_seqnum_increment(lsa);

	/* Install this LSA into LSDB. */
	/* Given "lsa" will be freed in the next function. */
	/* As area could be NULL i.e. when using OPAQUE_LSA_AS, we prefer to use
	 * ospf_lookup() to get ospf instance */
	if (area)
		top = area->ospf;

	if (ospf_lsa_install(top, NULL /*oi */, new) == NULL) {
		flog_warn(EC_OSPF_LSA_INSTALL_FAILURE,
			  "MPLS-TE (%s): ospf_lsa_install() ?", __func__);
		ospf_lsa_unlock(&new);
		return NULL;
	}

	/* Flood updated LSA through AS or Area depending of the RFC of the link
	 */
	if (IS_FLOOD_AS(lp->flags))
		ospf_flood_through_as(top, NULL, new);
	else
		ospf_flood_through_area(area, NULL /*nbr*/, new);

	/* Debug logging. */
	ote_debug("MPLS-TE (%s): LSA[Type%d:%pI4]: Refresh Opaque-LSA/MPLS-TE",
		  __func__, new->data->type, &new->data->id);
	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
		ospf_lsa_header_dump(new->data);

	return new;
}

void ospf_mpls_te_lsa_schedule(struct mpls_te_link *lp, enum lsa_opcode opcode)
{
	struct ospf_lsa lsa;
	struct lsa_header lsah;
	struct ospf *top;
	uint32_t tmp;

	memset(&lsa, 0, sizeof(lsa));
	memset(&lsah, 0, sizeof(lsah));
	top = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	/* Check if the pseudo link is ready to flood */
	if (!CHECK_FLAG(lp->flags, LPFLG_LSA_ACTIVE))
		return;

	ote_debug("MPLS-TE (%s): Schedule %s%s%s LSA for interface %s",
		  __func__,
		  opcode == REORIGINATE_THIS_LSA ? "Re-Originate" : "",
		  opcode == REFRESH_THIS_LSA ? "Refresh" : "",
		  opcode == FLUSH_THIS_LSA ? "Flush" : "",
		  lp->ifp ? lp->ifp->name : "-");

	lsa.area = lp->area;
	lsa.data = &lsah;
	if (IS_FLOOD_AS(lp->flags)) {
		lsah.type = OSPF_OPAQUE_AS_LSA;
		tmp = SET_OPAQUE_LSID(OPAQUE_TYPE_INTER_AS_LSA, lp->instance);
		lsah.id.s_addr = htonl(tmp);
	} else {
		lsah.type = OSPF_OPAQUE_AREA_LSA;
		if (IS_INTER_AS(lp->type)) {
			/* Set the area context if not know */
			if (lp->area == NULL)
				lp->area = ospf_area_lookup_by_area_id(
					top, OspfMplsTE.interas_areaid);
			/* Unable to set the area context. Abort! */
			if (lp->area == NULL) {
				flog_warn(
					EC_OSPF_TE_UNEXPECTED,
					"MPLS-TE (%s): Area context is null. Abort !",
					__func__);
				return;
			}
			tmp = SET_OPAQUE_LSID(OPAQUE_TYPE_INTER_AS_LSA,
					      lp->instance);
		} else
			tmp = SET_OPAQUE_LSID(
				OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA,
				lp->instance);
		lsah.id.s_addr = htonl(tmp);
	}

	switch (opcode) {
	case REORIGINATE_THIS_LSA:
		if (IS_FLOOD_AS(lp->flags)) {
			ospf_opaque_lsa_reoriginate_schedule(
				(void *)top, OSPF_OPAQUE_AS_LSA,
				OPAQUE_TYPE_INTER_AS_LSA);
		} else {
			if (IS_INTER_AS(lp->type))
				ospf_opaque_lsa_reoriginate_schedule(
					(void *)lp->area, OSPF_OPAQUE_AREA_LSA,
					OPAQUE_TYPE_INTER_AS_LSA);
			else
				ospf_opaque_lsa_reoriginate_schedule(
					(void *)lp->area, OSPF_OPAQUE_AREA_LSA,
					OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA);
		}
		break;
	case REFRESH_THIS_LSA:
		ospf_opaque_lsa_refresh_schedule(&lsa);
		break;
	case FLUSH_THIS_LSA:
		/* Reset Activity flag */
		lp->flags = LPFLG_LSA_INACTIVE;
		ospf_opaque_lsa_flush_schedule(&lsa);
		break;
	default:
		flog_warn(EC_OSPF_TE_UNEXPECTED,
			  "MPLS-TE (%s): Unknown opcode (%u)", __func__,
			  opcode);
		break;
	}
}

/**
 * ------------------------------------------------------
 * Following are Link State Data Base control functions.
 * ------------------------------------------------------
 */

/**
 * Get Vertex from TED by the router which advertised the LSA. A new Vertex and
 * associated Link State Node are created if Vertex is not found.
 *
 * @param ted	Link State Traffic Engineering Database
 * @param lsa	OSPF Link State Advertisement
 *
 * @return	Link State Vertex
 */
static struct ls_vertex *get_vertex(struct ls_ted *ted, struct ospf_lsa *lsa)
{
	struct ls_node_id lnid;
	struct ls_node *lnode;
	struct ls_vertex *vertex;

	/* Sanity Check */
	if (!ted || !lsa || !lsa->data || !lsa->area)
		return NULL;

	/* Search if a Link State Vertex already exist */
	lnid.origin = OSPFv2;
	lnid.id.ip.addr = lsa->data->adv_router;
	lnid.id.ip.area_id = lsa->area->area_id;
	vertex = ls_find_vertex_by_id(ted, lnid);

	/* Create Node & Vertex in the Link State Date Base if not found */
	if (!vertex) {
		const struct in_addr inaddr_any = {.s_addr = INADDR_ANY};

		lnode = ls_node_new(lnid, inaddr_any, in6addr_any);
		snprintfrr(lnode->name, MAX_NAME_LENGTH, "%pI4",
			   &lnid.id.ip.addr);
		vertex = ls_vertex_add(ted, lnode);
	}

	if (IS_LSA_SELF(lsa))
		ted->self = vertex;

	return vertex;
}

/**
 * Get Edge from TED by Link State Attribute ID. A new Edge and associated Link
 * State Attributes are created if not found.
 *
 * @param ted		Link State Traffic Engineering Database
 * @param adv		Link State Node ID of router which advertised Edge
 * @param link_id	Link State Attribute ID
 *
 * @return		Link State Edge
 */
static struct ls_edge *get_edge(struct ls_ted *ted, struct ls_node_id adv,
				struct in_addr link_id)
{
	struct ls_edge_key key;
	struct ls_edge *edge;
	struct ls_attributes *attr;

	/* Search Edge that corresponds to the Link ID */
	key.family = AF_INET;
	IPV4_ADDR_COPY(&key.k.addr, &link_id);
	edge = ls_find_edge_by_key(ted, key);

	/* Create new one if not exist */
	if (!edge) {
		attr = ls_attributes_new(adv, link_id, in6addr_any, 0);
		edge = ls_edge_add(ted, attr);
	}

	return edge;
}

/**
 * Export Link State information to consumer daemon through ZAPI Link State
 * Opaque Message.
 *
 * @param type		Type of Link State Element i.e. Vertex, Edge or Subnet
 * @param link_state	Pointer to Link State Vertex, Edge or Subnet
 *
 * @return		0 if success, -1 otherwise
 */
static int ospf_te_export(uint8_t type, void *link_state)
{
	struct ls_message msg = {};
	int rc = 0;

	if (!OspfMplsTE.export)
		return rc;

	switch (type) {
	case LS_MSG_TYPE_NODE:
		ls_vertex2msg(&msg, (struct ls_vertex *)link_state);
		rc = ls_send_msg(zclient, &msg, NULL);
		break;
	case LS_MSG_TYPE_ATTRIBUTES:
		ls_edge2msg(&msg, (struct ls_edge *)link_state);
		rc = ls_send_msg(zclient, &msg, NULL);
		break;
	case LS_MSG_TYPE_PREFIX:
		ls_subnet2msg(&msg, (struct ls_subnet *)link_state);
		rc = ls_send_msg(zclient, &msg, NULL);
		break;
	default:
		rc = -1;
		break;
	}

	return rc;
}

/**
 * Update Link State Edge & Attributes from the given Link State Attributes ID
 * and metric. This function is called when parsing Router LSA.
 *
 * @param ted		Link State Traffic Engineering Database
 * @param vertex	Vertex where the Edge is attached as source
 * @param link_data	Link State Edge ID
 * @param metric	Standard metric attached to this Edge
 */
static void ospf_te_update_link(struct ls_ted *ted, struct ls_vertex *vertex,
				struct in_addr link_data, uint8_t metric)
{
	struct ls_edge *edge;
	struct ls_attributes *attr;

	/* Sanity check */
	if (!ted || !vertex || !vertex->node)
		return;

	/* Get Corresponding Edge from Link State Data Base */
	edge = get_edge(ted, vertex->node->adv, link_data);
	attr = edge->attributes;

	/* re-attached edge to vertex if needed */
	if (!edge->source)
		edge->source = vertex;

	/* Check if it is just an LSA refresh */
	if ((CHECK_FLAG(attr->flags, LS_ATTR_METRIC)
	     && (attr->metric == metric))) {
		edge->status = SYNC;
		return;
	}

	/* Update metric value */
	attr->metric = metric;
	SET_FLAG(attr->flags, LS_ATTR_METRIC);
	if (edge->status != NEW)
		edge->status = UPDATE;

	ote_debug("    |- %s Edge %pI4 with metric %d",
		  edge->status == NEW ? "Add" : "Update", &attr->standard.local,
		  attr->metric);

	/* Export Link State Edge */
	ospf_te_export(LS_MSG_TYPE_ATTRIBUTES, edge);
	edge->status = SYNC;
}

/**
 * Update Link State Subnet & Prefix from the given prefix and metric. This
 * function is called when parsing Router LSA.
 *
 * @param ted		Link State Traffic Engineering Database
 * @param vertex	Vertex where the Edge is attached as source
 * @param p		Prefix associated to the Subnet
 * @param metric	Standard metric attached to this Edge
 */
static void ospf_te_update_subnet(struct ls_ted *ted, struct ls_vertex *vertex,
				  struct prefix *p, uint8_t metric)
{
	struct ls_subnet *subnet;
	struct ls_prefix *ls_pref;

	/* Search if there is a Subnet for this prefix */
	subnet = ls_find_subnet(ted, p);

	/* If found a Subnet, check if it is attached to this Vertex */
	if (subnet) {
		/* Re-attach the subnet to the vertex if necessary */
		if (subnet->vertex != vertex) {
			subnet->vertex = vertex;
			listnode_add_sort_nodup(vertex->prefixes, subnet);
		}
		/* Check if it is a simple refresh */
		ls_pref = subnet->ls_pref;
		if ((CHECK_FLAG(ls_pref->flags, LS_PREF_METRIC))
		    && (ls_pref->metric == metric)) {
			subnet->status = SYNC;
			return;
		}
		ls_pref->metric = metric;
		SET_FLAG(ls_pref->flags, LS_PREF_METRIC);
		subnet->status = UPDATE;
	} else {
		/* Create new Link State Prefix  */
		ls_pref = ls_prefix_new(vertex->node->adv, p);
		ls_pref->metric = metric;
		SET_FLAG(ls_pref->flags, LS_PREF_METRIC);
		/* and add it to the TED */
		subnet = ls_subnet_add(ted, ls_pref);
	}

	ote_debug("    |- %s subnet %pFX with metric %d",
		  subnet->status == NEW ? "Add" : "Update", &subnet->key,
		  ls_pref->metric);

	/* Export Link State Subnet */
	ospf_te_export(LS_MSG_TYPE_PREFIX, subnet);
	subnet->status = SYNC;
}

/**
 * Delete Subnet that correspond to the given IPv4 address and export deletion
 * information before removal. Prefix length is fixed to IPV4_MAX_BITLEN.
 *
 * @param ted	Links State Database
 * @param addr	IPv4 address
 */
static void ospf_te_delete_subnet(struct ls_ted *ted, struct in_addr addr)
{
	struct prefix p;
	struct ls_subnet *subnet;

	/* Search subnet that correspond to the address/32 as prefix */
	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.u.prefix4 = addr;
	ote_debug("  |- Delete Subnet info. for Prefix %pFX", &p);
	subnet = ls_find_subnet(ted, &p);

	/* Remove subnet if found */
	if (subnet) {
		subnet->status = DELETE;
		ospf_te_export(LS_MSG_TYPE_PREFIX, subnet);
		ls_subnet_del_all(ted, subnet);
	}
}

/**
 * Parse Router LSA. This function will create or update corresponding Vertex,
 * Edge and Subnet.
 *
 * @param ted	Link State Traffic Engineering Database
 * @param lsa	OSPF Link State Advertisement
 *
 * @return	0 if success, -1 otherwise
 */
static int ospf_te_parse_router_lsa(struct ls_ted *ted, struct ospf_lsa *lsa)
{
	struct router_lsa *rl;
	enum ls_node_type type;
	struct ls_vertex *vertex;
	int len, links;

	/* Sanity Check */
	if (!ted || !lsa || !lsa->data)
		return -1;

	ote_debug("MPLS-TE (%s): Parse Router LSA[%pI4] from Router[%pI4]",
		  __func__, &lsa->data->id, &lsa->data->adv_router);

	/* Get vertex from LSA Advertise Router ID */
	vertex = get_vertex(ted, lsa);

	/* Set Node type information if it has changed */
	rl = (struct router_lsa *)lsa->data;
	if (IS_ROUTER_LSA_VIRTUAL(rl))
		type = PSEUDO;
	else if (IS_ROUTER_LSA_EXTERNAL(rl))
		type = ASBR;
	else if (IS_ROUTER_LSA_BORDER(rl))
		type = ABR;
	else
		type = STANDARD;

	if (vertex->status == NEW) {
		vertex->node->type = type;
		SET_FLAG(vertex->node->flags, LS_NODE_TYPE);
	} else if (vertex->node->type != type) {
		vertex->node->type = type;
		vertex->status = UPDATE;
	}

	/* Check if Vertex has been modified */
	if (vertex->status != SYNC) {
		ote_debug("  |- %s Vertex %pI4",
			  vertex->status == NEW ? "Add" : "Update",
			  &vertex->node->router_id);

		/* Vertex is out of sync: export it */
		ospf_te_export(LS_MSG_TYPE_NODE, vertex);
		vertex->status = SYNC;
	}

	/* Then, process Link Information */
	len = lsa->size - OSPF_LSA_HEADER_SIZE - OSPF_ROUTER_LSA_MIN_SIZE;
	links = ntohs(rl->links);
	for (int i = 0; i < links && len > 0; len -= 12, i++) {
		struct prefix p;
		uint32_t metric;

		switch (rl->link[i].type) {
		case LSA_LINK_TYPE_POINTOPOINT:
			ospf_te_update_link(ted, vertex, rl->link[i].link_data,
					    ntohs(rl->link[i].metric));
			/* Add corresponding subnet */
			p.family = AF_INET;
			p.prefixlen = IPV4_MAX_BITLEN;
			p.u.prefix4 = rl->link[i].link_data;
			metric = ntohs(rl->link[i].metric);
			ospf_te_update_subnet(ted, vertex, &p, metric);
			break;
		case LSA_LINK_TYPE_STUB:
			/* Keep only /32 prefix */
			p.prefixlen = ip_masklen(rl->link[i].link_data);
			if (p.prefixlen == IPV4_MAX_BITLEN) {
				p.family = AF_INET;
				p.u.prefix4 = rl->link[i].link_id;
				metric = ntohs(rl->link[i].metric);
				ospf_te_update_subnet(ted, vertex, &p, metric);
			}
			break;
		default:
			break;
		}
	}

	return 0;
}

/**
 * Delete Vertex, Edge and Subnet associated to this Router LSA. This function
 * is called when the router received such LSA with MAX_AGE (Flush) or when the
 * router stop OSPF.
 *
 * @param ted	Link State Traffic Engineering Database
 * @param lsa	OSPF Link State Advertisement
 *
 * @return	0 if success, -1 otherwise
 */
static int ospf_te_delete_router_lsa(struct ls_ted *ted, struct ospf_lsa *lsa)
{
	struct ls_node_id lnid;
	struct ls_vertex *vertex;

	/* Sanity Check */
	if (!ted || !lsa || !lsa->data)
		return -1;

	/* Search Vertex that corresponds to this LSA */
	lnid.origin = OSPFv2;
	lnid.id.ip.addr = lsa->data->adv_router;
	lnid.id.ip.area_id = lsa->area->area_id;
	vertex = ls_find_vertex_by_id(ted, lnid);
	if (!vertex)
		return -1;

	ote_debug("MPLS-TE (%s): Delete Vertex %pI4 from Router LSA[%pI4]",
		  __func__, &vertex->node->router_id, &lsa->data->id);

	/* Export deleted vertex ... */
	vertex->status = DELETE;
	ospf_te_export(LS_MSG_TYPE_NODE, vertex);

	/* ... and remove Node & Vertex from Link State Date Base */
	ls_vertex_del_all(ted, vertex);

	return 0;
}

/**
 * Create or update Remote Vertex that corresponds to the remote ASBR of the
 * foreign network if Edge is associated to an Inter-AS LSA (Type 6).
 *
 * @param ted	Link State Traffic Engineering Database
 * @param edge	Link State Edge
 */
static void ospf_te_update_remote_asbr(struct ls_ted *ted, struct ls_edge *edge)
{
	struct ls_node_id lnid;
	struct ls_vertex *vertex;
	struct ls_node *lnode;
	struct ls_attributes *attr;
	struct prefix p;

	/* Sanity Check */
	if (!ted || !edge)
		return;

	/* Search if a Link State Vertex already exist */
	attr = edge->attributes;
	lnid.origin = OSPFv2;
	lnid.id.ip.addr = attr->standard.remote_addr;
	lnid.id.ip.area_id = attr->adv.id.ip.area_id;
	vertex = ls_find_vertex_by_id(ted, lnid);

	/* Create Node & Vertex in the Link State Date Base if not found */
	if (!vertex) {
		const struct in_addr inaddr_any = {.s_addr = INADDR_ANY};

		lnode = ls_node_new(lnid, inaddr_any, in6addr_any);
		snprintfrr(lnode->name, MAX_NAME_LENGTH, "%pI4",
			   &lnid.id.ip.addr);
		vertex = ls_vertex_add(ted, lnode);
	}

	/* Update Node information */
	lnode = vertex->node;
	if (CHECK_FLAG(lnode->flags, LS_NODE_TYPE)) {
		if (lnode->type != RMT_ASBR) {
			lnode->type = RMT_ASBR;
			if (vertex->status != NEW)
				vertex->status = UPDATE;
		}
	} else {
		lnode->type = RMT_ASBR;
		SET_FLAG(lnode->flags, LS_NODE_TYPE);
		if (vertex->status != NEW)
			vertex->status = UPDATE;
	}
	if (CHECK_FLAG(lnode->flags, LS_NODE_AS_NUMBER)) {
		if (lnode->as_number != attr->standard.remote_as) {
			lnode->as_number = attr->standard.remote_as;
			if (vertex->status != NEW)
				vertex->status = UPDATE;
		}
	} else {
		lnode->as_number = attr->standard.remote_as;
		SET_FLAG(lnode->flags, LS_NODE_AS_NUMBER);
		if (vertex->status != NEW)
			vertex->status = UPDATE;
	}

	/* Export Link State Vertex if needed */
	if (vertex->status == NEW  || vertex->status == UPDATE) {
		ote_debug("  |- %s Remote Vertex %pI4 for AS %u",
			  vertex->status == NEW ? "Add" : "Update",
			  &lnode->router_id, lnode->as_number);
		ospf_te_export(LS_MSG_TYPE_NODE, vertex);
		vertex->status = SYNC;
	}

	/* Update corresponding Subnets */
	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.u.prefix4 = attr->standard.local;
	ospf_te_update_subnet(ted, edge->source, &p, attr->standard.te_metric);

	p.family = AF_INET;
	p.prefixlen = IPV4_MAX_BITLEN;
	p.u.prefix4 = attr->standard.remote_addr;
	ospf_te_update_subnet(ted, vertex, &p, attr->standard.te_metric);

	/* Connect Edge to the remote Vertex */
	if (edge->destination == NULL) {
		edge->destination = vertex;
		listnode_add_sort_nodup(vertex->incoming_edges, edge);
	}

	/* Finally set type to ASBR the node that advertised this Edge ... */
	vertex = edge->source;
	lnode = vertex->node;
	if (CHECK_FLAG(lnode->flags, LS_NODE_TYPE)) {
		if (lnode->type != ASBR) {
			lnode->type = ASBR;
			if (vertex->status != NEW)
				vertex->status = UPDATE;
		}
	} else {
		lnode->type = ASBR;
		SET_FLAG(lnode->flags, LS_NODE_TYPE);
		if (vertex->status != NEW)
			vertex->status = UPDATE;
	}

	/* ... and Export it if needed */
	if (vertex->status == NEW  || vertex->status == UPDATE) {
		ospf_te_export(LS_MSG_TYPE_NODE, vertex);
		vertex->status = SYNC;
	}
}

/**
 * Parse Opaque Traffic Engineering LSA (Type 1) TLVs and create or update the
 * corresponding Link State Edge and Attributes. Vertex connections are also
 * updated if needed based on the remote IP address of the Edge and existing
 * reverse Edge.
 *
 * @param ted	Link State Traffic Engineering Database
 * @param lsa	OSPF Link State Advertisement
 *
 * @return	0 if success, -1 otherwise
 */
static int ospf_te_parse_te(struct ls_ted *ted, struct ospf_lsa *lsa)
{
	struct ls_edge *edge;
	struct ls_vertex *vertex;
	struct ls_attributes *old, attr = {};
	struct tlv_header *tlvh;
	void *value;
	uint16_t len, sum;
	uint8_t lsa_id;

	/* Initialize Attribute */
	attr.adv.origin = OSPFv2;
	attr.adv.id.ip.addr = lsa->data->adv_router;
	if (lsa->data->type != OSPF_OPAQUE_AS_LSA)
		attr.adv.id.ip.area_id = lsa->area->area_id;

	/* Initialize TLV browsing */
	tlvh = TLV_HDR_TOP(lsa->data);
	len = lsa->size - OSPF_LSA_HEADER_SIZE;

	/* Check if TE Router-ID TLV is present */
	if (ntohs(tlvh->type) == TE_TLV_ROUTER_ADDR) {
		/* if TE Router-ID is alone, we are done ... */
		if (len == TE_LINK_SUBTLV_DEF_SIZE)
			return 0;

		/* ... otherwise, skip it */
		len -= TE_LINK_SUBTLV_DEF_SIZE + TLV_HDR_SIZE;
		tlvh = TLV_HDR_NEXT(tlvh);
	}

	/* Check if we have a valid TE Link TLV */
	if ((len == 0) || (ntohs(tlvh->type) != TE_TLV_LINK))
		return 0;

	sum = sizeof(struct tlv_header);
	/* Browse sub-TLV and fulfill Link State Attributes */
	for (tlvh = TLV_DATA(tlvh); sum < len; tlvh = TLV_HDR_NEXT(tlvh)) {
		uint32_t val32, tab32[2];
		float valf, tabf[8];
		struct in_addr addr;

		value = TLV_DATA(tlvh);
		switch (ntohs(tlvh->type)) {
		case TE_LINK_SUBTLV_LCLIF_IPADDR:
			memcpy(&addr, value, TE_LINK_SUBTLV_DEF_SIZE);
			attr.standard.local = addr;
			SET_FLAG(attr.flags, LS_ATTR_LOCAL_ADDR);
			break;
		case TE_LINK_SUBTLV_RMTIF_IPADDR:
			memcpy(&addr, value, TE_LINK_SUBTLV_DEF_SIZE);
			attr.standard.remote = addr;
			SET_FLAG(attr.flags, LS_ATTR_NEIGH_ADDR);
			break;
		case TE_LINK_SUBTLV_TE_METRIC:
			memcpy(&val32, value, TE_LINK_SUBTLV_DEF_SIZE);
			attr.standard.te_metric = ntohl(val32);
			SET_FLAG(attr.flags, LS_ATTR_TE_METRIC);
			break;
		case TE_LINK_SUBTLV_MAX_BW:
			memcpy(&valf, value, TE_LINK_SUBTLV_DEF_SIZE);
			attr.standard.max_bw = ntohf(valf);
			SET_FLAG(attr.flags, LS_ATTR_MAX_BW);
			break;
		case TE_LINK_SUBTLV_MAX_RSV_BW:
			memcpy(&valf, value, TE_LINK_SUBTLV_DEF_SIZE);
			attr.standard.max_rsv_bw = ntohf(valf);
			SET_FLAG(attr.flags, LS_ATTR_MAX_RSV_BW);
			break;
		case TE_LINK_SUBTLV_UNRSV_BW:
			memcpy(tabf, value, TE_LINK_SUBTLV_UNRSV_SIZE);
			for (int i = 0; i < MAX_CLASS_TYPE; i++)
				attr.standard.unrsv_bw[i] = ntohf(tabf[i]);
			SET_FLAG(attr.flags, LS_ATTR_UNRSV_BW);
			break;
		case TE_LINK_SUBTLV_RSC_CLSCLR:
			memcpy(&val32, value, TE_LINK_SUBTLV_DEF_SIZE);
			attr.standard.admin_group = ntohl(val32);
			SET_FLAG(attr.flags, LS_ATTR_ADM_GRP);
			break;
		case TE_LINK_SUBTLV_LLRI:
			memcpy(tab32, value, TE_LINK_SUBTLV_LLRI_SIZE);
			attr.standard.local_id = ntohl(tab32[0]);
			attr.standard.remote_id = ntohl(tab32[1]);
			SET_FLAG(attr.flags, LS_ATTR_LOCAL_ID);
			SET_FLAG(attr.flags, LS_ATTR_NEIGH_ID);
			break;
		case TE_LINK_SUBTLV_RIP:
			memcpy(&addr, value, TE_LINK_SUBTLV_DEF_SIZE);
			attr.standard.remote_addr = addr;
			SET_FLAG(attr.flags, LS_ATTR_REMOTE_ADDR);
			break;
		case TE_LINK_SUBTLV_RAS:
			memcpy(&val32, value, TE_LINK_SUBTLV_DEF_SIZE);
			attr.standard.remote_as = ntohl(val32);
			SET_FLAG(attr.flags, LS_ATTR_REMOTE_AS);
			break;
		case TE_LINK_SUBTLV_AV_DELAY:
			memcpy(&val32, value, TE_LINK_SUBTLV_DEF_SIZE);
			attr.extended.delay = ntohl(val32);
			SET_FLAG(attr.flags, LS_ATTR_DELAY);
			break;
		case TE_LINK_SUBTLV_MM_DELAY:
			memcpy(tab32, value, TE_LINK_SUBTLV_MM_DELAY_SIZE);
			attr.extended.min_delay = ntohl(tab32[0]);
			attr.extended.max_delay = ntohl(tab32[1]);
			SET_FLAG(attr.flags, LS_ATTR_MIN_MAX_DELAY);
			break;
		case TE_LINK_SUBTLV_DELAY_VAR:
			memcpy(&val32, value, TE_LINK_SUBTLV_DEF_SIZE);
			attr.extended.jitter = ntohl(val32);
			SET_FLAG(attr.flags, LS_ATTR_JITTER);
			break;
		case TE_LINK_SUBTLV_PKT_LOSS:
			memcpy(&val32, value, TE_LINK_SUBTLV_DEF_SIZE);
			attr.extended.pkt_loss = ntohl(val32);
			SET_FLAG(attr.flags, LS_ATTR_PACKET_LOSS);
			break;
		case TE_LINK_SUBTLV_RES_BW:
			memcpy(&valf, value, TE_LINK_SUBTLV_DEF_SIZE);
			attr.extended.rsv_bw = ntohf(valf);
			SET_FLAG(attr.flags, LS_ATTR_RSV_BW);
			break;
		case TE_LINK_SUBTLV_AVA_BW:
			memcpy(&valf, value, TE_LINK_SUBTLV_DEF_SIZE);
			attr.extended.ava_bw = ntohf(valf);
			SET_FLAG(attr.flags, LS_ATTR_AVA_BW);
			break;
		case TE_LINK_SUBTLV_USE_BW:
			memcpy(&valf, value, TE_LINK_SUBTLV_DEF_SIZE);
			attr.extended.used_bw = ntohf(valf);
			SET_FLAG(attr.flags, LS_ATTR_USE_BW);
			break;
		default:
			break;
		}
		sum += TLV_SIZE(tlvh);
	}

	/* Get corresponding Edge from Link State Data Base */
	if (IPV4_NET0(attr.standard.local.s_addr) && !attr.standard.local_id) {
		ote_debug("  |- Found no TE Link local address/ID. Abort!");
		return -1;
	}
	edge = get_edge(ted, attr.adv, attr.standard.local);
	old = edge->attributes;

	ote_debug("  |- Process Traffic Engineering LSA %pI4 for Edge %pI4",
		  &lsa->data->id, &attr.standard.local);

	/* Update standard fields */
	len = sizeof(struct ls_standard);
	if ((attr.flags & 0x0FFFF) == (old->flags & 0x0FFFF)) {
		if (memcmp(&attr.standard, &old->standard, len) != 0) {
			memcpy(&old->standard, &attr.standard, len);
			if (edge->status != NEW)
				edge->status = UPDATE;
		}
	} else {
		memcpy(&old->standard, &attr.standard, len);
		old->flags |= attr.flags & 0x0FFFF;
		if (edge->status != NEW)
			edge->status = UPDATE;
	}
	/* Update extended fields */
	len = sizeof(struct ls_extended);
	if ((attr.flags & 0x0FF0000) == (old->flags & 0x0FF0000)) {
		if (memcmp(&attr.extended, &old->extended, len) != 0) {
			memcpy(&old->extended, &attr.extended, len);
			if (edge->status != NEW)
				edge->status = UPDATE;
		}
	} else {
		memcpy(&old->extended, &attr.extended, len);
		old->flags |= attr.flags & 0x0FF0000;
		if (edge->status != NEW)
			edge->status = UPDATE;
	}

	/* If LSA is an Opaque Inter-AS, Add Node and Subnet */
	lsa_id = GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr));
	if (lsa_id ==  OPAQUE_TYPE_INTER_AS_LSA)
		ospf_te_update_remote_asbr(ted, edge);

	/* Update remote Link if remote IP addr is known */
	if (CHECK_FLAG(old->flags, LS_ATTR_NEIGH_ADDR)) {
		struct ls_edge *dst;

		dst = ls_find_edge_by_destination(ted, old);
		/* Attach remote link if not set */
		if (dst && edge->source && dst->destination == NULL) {
			vertex = edge->source;
			if (vertex->incoming_edges)
				listnode_add_sort_nodup(vertex->incoming_edges,
							dst);
			dst->destination = vertex;
		}
		/* and destination vertex to this edge */
		if (dst && dst->source && edge->destination == NULL) {
			vertex = dst->source;
			if (vertex->incoming_edges)
				listnode_add_sort_nodup(vertex->incoming_edges,
							edge);
			edge->destination = vertex;
		}
	}

	/* Export Link State Edge if needed */
	if (edge->status == NEW || edge->status == UPDATE) {
		ote_debug("  |- %s TE info. for Edge %pI4",
			  edge->status == NEW ? "Add" : "Update",
			  &edge->attributes->standard.local);

		ospf_te_export(LS_MSG_TYPE_ATTRIBUTES, edge);
		edge->status = SYNC;
	}

	return 0;
}

/**
 * Delete Link State Attributes information that correspond to the Opaque
 * Traffic Engineering LSA (Type 1) TLVs. Note that the Edge is not removed.
 *
 * @param ted	Link State Traffic Engineering Database
 * @param lsa	OSPF Link State Advertisement
 *
 * @return	0 if success, -1 otherwise
 */
static int ospf_te_delete_te(struct ls_ted *ted, struct ospf_lsa *lsa)
{
	struct ls_edge *edge;
	struct ls_attributes *attr;
	struct tlv_header *tlvh;
	struct in_addr addr;
	struct ls_edge_key key = {.family = AF_UNSPEC};
	uint16_t len, sum;
	uint8_t lsa_id;

	/* Initialize TLV browsing */
	tlvh = TLV_HDR_TOP(lsa->data);
	/* Skip Router TE ID if present */
	if (ntohs(tlvh->type) == TE_TLV_ROUTER_ADDR)
		tlvh = TLV_HDR_NEXT(tlvh);
	len = TLV_BODY_SIZE(tlvh);
	sum = sizeof(struct tlv_header);

	/* Browse sub-TLV to find Link ID */
	for (tlvh = TLV_DATA(tlvh); sum < len; tlvh = TLV_HDR_NEXT(tlvh)) {
		if (ntohs(tlvh->type) == TE_LINK_SUBTLV_LCLIF_IPADDR) {
			memcpy(&addr, TLV_DATA(tlvh), TE_LINK_SUBTLV_DEF_SIZE);
			key.family = AF_INET;
			IPV4_ADDR_COPY(&key.k.addr, &addr);
			break;
		}
		sum += TLV_SIZE(tlvh);
	}
	if (key.family == AF_UNSPEC)
		return 0;

	/* Search Edge that corresponds to the Link ID */
	edge = ls_find_edge_by_key(ted, key);
	if (!edge || !edge->attributes)
		return 0;
	attr = edge->attributes;

	/* First, remove Remote ASBR and associated Edge & Subnet if any */
	lsa_id = GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr));
	if (lsa_id ==  OPAQUE_TYPE_INTER_AS_LSA) {
		ote_debug("  |- Delete remote ASBR, Edge and Subnet");

		if (edge->destination) {
			edge->destination->status = DELETE;
			ospf_te_export(LS_MSG_TYPE_NODE, edge->destination);
			ls_vertex_del_all(ted, edge->destination);
		}

		ospf_te_delete_subnet(ted, attr->standard.local);

		edge->status = DELETE;
		ospf_te_export(LS_MSG_TYPE_ATTRIBUTES, edge);
		ls_edge_del_all(ted, edge);

		return 0;
	}

	ote_debug("  |- Delete TE info. for Edge %pI4",
		  &edge->attributes->standard.local);

	/* First remove the associated Subnet */
	ospf_te_delete_subnet(ted, attr->standard.local);

	/* Then ,remove Link State Attributes TE information */
	memset(&attr->standard, 0, sizeof(struct ls_standard));
	attr->flags &= 0x0FFFF;
	memset(&attr->extended, 0, sizeof(struct ls_extended));
	attr->flags &= 0x0FF0000;
	ls_attributes_srlg_del(attr);

	/* Export Edge that has been updated */
	if (CHECK_FLAG(attr->flags, LS_ATTR_ADJ_SID)
	    || CHECK_FLAG(attr->flags, LS_ATTR_BCK_ADJ_SID)) {
		edge->status = UPDATE;
		ospf_te_export(LS_MSG_TYPE_ATTRIBUTES, edge);
		edge->status = SYNC;
	} else {
		/* Remove completely the Edge if Segment Routing is not set */
		edge->status = DELETE;
		ospf_te_export(LS_MSG_TYPE_ATTRIBUTES, edge);
		ls_edge_del_all(ted, edge);
	}

	return 0;
}

/**
 * Parse Opaque Router Information LSA (Type 4) TLVs and update the
 * corresponding Link State Vertex with these information (Segment Routing).
 *
 * @param ted	Link State Traffic Engineering Database
 * @param lsa	OSPF Link State Advertisement
 *
 * @return	0 if success, -1 otherwise
 */
static int ospf_te_parse_ri(struct ls_ted *ted, struct ospf_lsa *lsa)
{
	struct ls_vertex *vertex;
	struct ls_node *node;
	struct lsa_header *lsah = lsa->data;
	struct tlv_header *tlvh;
	uint16_t len = 0, sum = 0;

	/* Get vertex / Node from LSA Advertised Router ID */
	vertex = get_vertex(ted, lsa);
	node = vertex->node;

	ote_debug("  |- Process Router Information LSA %pI4 for Vertex %pI4",
		  &lsa->data->id, &node->router_id);

	/* Initialize TLV browsing */
	len = lsa->size - OSPF_LSA_HEADER_SIZE;
	for (tlvh = TLV_HDR_TOP(lsah); sum < len && tlvh;
	     tlvh = TLV_HDR_NEXT(tlvh)) {
		struct ri_sr_tlv_sr_algorithm *algo;
		struct ri_sr_tlv_sid_label_range *range;
		struct ri_sr_tlv_node_msd *msd;
		uint32_t size, lower;

		switch (ntohs(tlvh->type)) {
		case RI_SR_TLV_SR_ALGORITHM:
			algo = (struct ri_sr_tlv_sr_algorithm *)tlvh;

			for (int i = 0; i < ntohs(algo->header.length); i++) {
				if (CHECK_FLAG(node->flags, LS_NODE_SR)
				    && (node->algo[i] == algo->value[i]))
					continue;

				node->algo[i] = algo->value[i];
				SET_FLAG(node->flags, LS_NODE_SR);
				if (vertex->status != NEW)
					vertex->status = UPDATE;
			}

			/* Reset other Algorithms */
			for (int i = ntohs(algo->header.length); i < 2; i++) {
				if (vertex->status != NEW
				    && node->algo[i] != SR_ALGORITHM_UNSET)
					vertex->status = UPDATE;
				node->algo[i] = SR_ALGORITHM_UNSET;
			}

			break;

		case RI_SR_TLV_SRGB_LABEL_RANGE:
			range = (struct ri_sr_tlv_sid_label_range *)tlvh;
			size = GET_RANGE_SIZE(ntohl(range->size));
			lower = GET_LABEL(ntohl(range->lower.value));
			if ((CHECK_FLAG(node->flags, LS_NODE_SR))
			    && ((node->srgb.range_size == size)
				&& (node->srgb.lower_bound == lower)))
				break;

			node->srgb.range_size = size;
			node->srgb.lower_bound = lower;
			SET_FLAG(node->flags, LS_NODE_SR);
			if (vertex->status != NEW)
				vertex->status = UPDATE;

			break;

		case RI_SR_TLV_SRLB_LABEL_RANGE:
			range = (struct ri_sr_tlv_sid_label_range *)tlvh;
			size = GET_RANGE_SIZE(ntohl(range->size));
			lower = GET_LABEL(ntohl(range->lower.value));
			if ((CHECK_FLAG(node->flags, LS_NODE_SRLB))
			    && ((node->srlb.range_size == size)
				&& (node->srlb.lower_bound == lower)))
				break;

			node->srlb.range_size = size;
			node->srlb.lower_bound = lower;
			SET_FLAG(node->flags, LS_NODE_SRLB);
			if (vertex->status != NEW)
				vertex->status = UPDATE;

			break;

		case RI_SR_TLV_NODE_MSD:
			msd = (struct ri_sr_tlv_node_msd *)tlvh;
			if ((CHECK_FLAG(node->flags, LS_NODE_MSD))
			    && (node->msd == msd->value))
				break;

			node->msd = msd->value;
			SET_FLAG(node->flags, LS_NODE_MSD);
			if (vertex->status != NEW)
				vertex->status = UPDATE;

			break;

		default:
			break;
		}
		sum += TLV_SIZE(tlvh);
	}

	/* Vertex has been created or updated: export it */
	if (vertex->status == NEW || vertex->status == UPDATE) {
		ote_debug("  |- %s SR info - SRGB[%d/%d] for Vertex %pI4",
			  vertex->status == NEW ? "Add" : "Update",
			  vertex->node->srgb.lower_bound,
			  vertex->node->srgb.range_size,
			  &vertex->node->router_id);

		ospf_te_export(LS_MSG_TYPE_NODE, vertex);
		vertex->status = SYNC;
	}

	return 0;
}

/**
 * Delete Link State Node information (Segment Routing) that correspond to the
 * Opaque Router Information LSA (Type 4) TLVs. Note that the Vertex is not
 * removed.
 *
 * @param ted	Link State Traffic Engineering Database
 * @param lsa	OSPF Link State Advertisement
 *
 * @return	0 if success, -1 otherwise
 */
static int ospf_te_delete_ri(struct ls_ted *ted, struct ospf_lsa *lsa)
{
	struct ls_node_id lnid;
	struct ls_vertex *vertex;
	struct ls_node *node;

	/* Search if a Link State Vertex already exist */
	lnid.origin = OSPFv2;
	lnid.id.ip.addr = lsa->data->adv_router;
	lnid.id.ip.area_id = lsa->area->area_id;
	vertex = ls_find_vertex_by_id(ted, lnid);
	if (!vertex)
		return -1;

	/* Remove Segment Routing Information if any */
	node = vertex->node;
	UNSET_FLAG(node->flags, LS_NODE_SR);
	memset(&node->srgb, 0, sizeof(struct ls_srgb));
	node->algo[0] = SR_ALGORITHM_UNSET;
	node->algo[1] = SR_ALGORITHM_UNSET;
	UNSET_FLAG(node->flags, LS_NODE_SRLB);
	memset(&node->srlb, 0, sizeof(struct ls_srlb));
	UNSET_FLAG(node->flags, LS_NODE_MSD);
	node->msd = 0;
	vertex->status = UPDATE;

	ote_debug("  |- Delete SR info. for Vertex %pI4",
		  &vertex->node->router_id);

	/* Vertex has been updated: export it */
	ospf_te_export(LS_MSG_TYPE_NODE, vertex);
	vertex->status = SYNC;

	return 0;
}

/**
 * Parse Opaque Extended Prefix LSA (Type 7) TLVs and update the corresponding
 * Link State Subnet with these information (Segment Routing ID).
 *
 * @param ted	Link State Traffic Engineering Database
 * @param lsa	OSPF Link State Advertisement
 *
 * @return	0 if success, -1 otherwise
 */
static int ospf_te_parse_ext_pref(struct ls_ted *ted, struct ospf_lsa *lsa)
{
	struct ls_node_id lnid;
	struct ls_subnet *subnet;
	struct ls_prefix *ls_pref;
	struct prefix pref;
	struct ext_tlv_prefix *ext;
	struct ext_subtlv_prefix_sid *pref_sid;
	uint32_t label;

	/* Get corresponding Subnet from Link State Data Base */
	ext = (struct ext_tlv_prefix *)TLV_HDR_TOP(lsa->data);
	pref.family = AF_INET;
	pref.prefixlen = ext->pref_length;
	pref.u.prefix4 = ext->address;
	subnet = ls_find_subnet(ted, &pref);

	/* Create new Link State Prefix if not found */
	if (!subnet) {
		lnid.origin = OSPFv2;
		lnid.id.ip.addr = lsa->data->adv_router;
		lnid.id.ip.area_id = lsa->area->area_id;
		ls_pref = ls_prefix_new(lnid, &pref);
		/* and add it to the TED */
		subnet = ls_subnet_add(ted, ls_pref);
	}

	ote_debug("  |- Process Extended Prefix LSA %pI4 for subnet %pFX",
		  &lsa->data->id, &pref);

	/* Initialize TLV browsing */
	ls_pref = subnet->ls_pref;
	pref_sid = (struct ext_subtlv_prefix_sid *)((char *)(ext) + TLV_HDR_SIZE
						    + EXT_TLV_PREFIX_SIZE);
	label = CHECK_FLAG(pref_sid->flags, EXT_SUBTLV_PREFIX_SID_VFLG)
			? GET_LABEL(ntohl(pref_sid->value))
			: ntohl(pref_sid->value);

	/* Check if it is a simple refresh */
	if (CHECK_FLAG(ls_pref->flags, LS_PREF_SR)
	    && ls_pref->sr.algo == pref_sid->algorithm
	    && ls_pref->sr.sid_flag == pref_sid->flags
	    && ls_pref->sr.sid == label)
		return 0;

	/* Fulfill SR information */
	ls_pref->sr.algo = pref_sid->algorithm;
	ls_pref->sr.sid_flag = pref_sid->flags;
	ls_pref->sr.sid = label;
	SET_FLAG(ls_pref->flags, LS_PREF_SR);
	if (subnet->status != NEW)
		subnet->status = UPDATE;

	/* Export Subnet if needed */
	if (subnet->status == NEW || subnet->status == UPDATE) {
		ote_debug("  |- %s SID %d to subnet %pFX",
			  subnet->status == NEW ? "Add" : "Update",
			  ls_pref->sr.sid, &ls_pref->pref);

		ospf_te_export(LS_MSG_TYPE_PREFIX, subnet);
		subnet->status = SYNC;
	}

	return 0;
}

/**
 * Delete Link State Subnet information (Segment Routing ID) that correspond to
 * the Opaque Extended Prefix LSA (Type 7) TLVs. Note that the Subnet is not
 * removed.
 *
 * @param ted	Link State Traffic Engineering Database
 * @param lsa	OSPF Link State Advertisement
 *
 * @return	0 if success, -1 otherwise
 */
static int ospf_te_delete_ext_pref(struct ls_ted *ted, struct ospf_lsa *lsa)
{
	struct ls_subnet *subnet;
	struct ls_prefix *ls_pref;
	struct prefix pref;
	struct ext_tlv_prefix *ext;

	/* Get corresponding Subnet from Link State Data Base */
	ext = (struct ext_tlv_prefix *)TLV_HDR_TOP(lsa->data);
	pref.family = AF_INET;
	pref.prefixlen = ext->pref_length;
	pref.u.prefix4 = ext->address;
	subnet = ls_find_subnet(ted, &pref);

	/* Check if there is a corresponding subnet */
	if (!subnet)
		return -1;

	ote_debug("  |- Delete SID %d to subnet %pFX", subnet->ls_pref->sr.sid,
		  &subnet->ls_pref->pref);

	/* Remove Segment Routing information */
	ls_pref = subnet->ls_pref;
	UNSET_FLAG(ls_pref->flags, LS_PREF_SR);
	memset(&ls_pref->sr, 0, sizeof(struct ls_sid));
	subnet->status = UPDATE;

	/* Subnet has been updated: export it */
	ospf_te_export(LS_MSG_TYPE_PREFIX, subnet);
	subnet->status = SYNC;

	return 0;
}

/**
 * Parse Opaque Extended Link LSA (Type 8) TLVs and update the corresponding
 * Link State Edge with these information (Segment Routing Adjacency).
 *
 * @param ted	Link State Traffic Engineering Database
 * @param lsa	OSPF Link State Advertisement
 *
 * @return	0 if success, -1 otherwise
 */
static int ospf_te_parse_ext_link(struct ls_ted *ted, struct ospf_lsa *lsa)
{
	struct ls_node_id lnid;
	struct tlv_header *tlvh;
	struct ext_tlv_link *ext;
	struct ls_edge *edge;
	struct ls_attributes *atr;
	uint16_t len = 0, sum = 0, i;
	uint32_t label;

	/* Get corresponding Edge from Link State Data Base */
	lnid.origin = OSPFv2;
	lnid.id.ip.addr = lsa->data->adv_router;
	lnid.id.ip.area_id = lsa->area->area_id;
	ext = (struct ext_tlv_link *)TLV_HDR_TOP(lsa->data);
	edge = get_edge(ted, lnid, ext->link_data);
	atr = edge->attributes;

	ote_debug("  |- Process Extended Link LSA %pI4 for edge %pI4",
		  &lsa->data->id, &edge->attributes->standard.local);

	/* Initialize TLV browsing */
	len = TLV_BODY_SIZE(&ext->header) - EXT_TLV_LINK_SIZE;
	tlvh = (struct tlv_header *)((char *)(ext) + TLV_HDR_SIZE
				     + EXT_TLV_LINK_SIZE);
	for (; sum < len; tlvh = TLV_HDR_NEXT(tlvh)) {
		struct ext_subtlv_adj_sid *adj;
		struct ext_subtlv_lan_adj_sid *ladj;
		struct ext_subtlv_rmt_itf_addr *rmt;

		switch (ntohs(tlvh->type)) {
		case EXT_SUBTLV_ADJ_SID:
			adj = (struct ext_subtlv_adj_sid *)tlvh;
			label = CHECK_FLAG(adj->flags,
					   EXT_SUBTLV_LINK_ADJ_SID_VFLG)
					? GET_LABEL(ntohl(adj->value))
					: ntohl(adj->value);
			i = CHECK_FLAG(adj->flags,
				       EXT_SUBTLV_LINK_ADJ_SID_BFLG) ? 1 : 0;
			if (((i && CHECK_FLAG(atr->flags, LS_ATTR_BCK_ADJ_SID))
			     || (!i && CHECK_FLAG(atr->flags, LS_ATTR_ADJ_SID)))
			    && atr->adj_sid[i].flags == adj->flags
			    && atr->adj_sid[i].sid == label
			    && atr->adj_sid[i].weight == adj->weight)
				break;

			atr->adj_sid[i].flags = adj->flags;
			atr->adj_sid[i].sid = label;
			atr->adj_sid[i].weight = adj->weight;
			if (i == 0)
				SET_FLAG(atr->flags, LS_ATTR_ADJ_SID);
			else
				SET_FLAG(atr->flags, LS_ATTR_BCK_ADJ_SID);
			if (edge->status != NEW)
				edge->status = UPDATE;

			break;
		case EXT_SUBTLV_LAN_ADJ_SID:
			ladj = (struct ext_subtlv_lan_adj_sid *)tlvh;
			label = CHECK_FLAG(ladj->flags,
					   EXT_SUBTLV_LINK_ADJ_SID_VFLG)
					? GET_LABEL(ntohl(ladj->value))
					: ntohl(ladj->value);
			i = CHECK_FLAG(ladj->flags,
				       EXT_SUBTLV_LINK_ADJ_SID_BFLG) ? 1 : 0;
			if (((i && CHECK_FLAG(atr->flags, LS_ATTR_BCK_ADJ_SID))
			     || (!i && CHECK_FLAG(atr->flags, LS_ATTR_ADJ_SID)))
			    && atr->adj_sid[i].flags == ladj->flags
			    && atr->adj_sid[i].sid == label
			    && atr->adj_sid[i].weight == ladj->weight
			    && IPV4_ADDR_SAME(&atr->adj_sid[1].neighbor.addr,
					      &ladj->neighbor_id))
				break;

			atr->adj_sid[i].flags = ladj->flags;
			atr->adj_sid[i].sid = label;
			atr->adj_sid[i].weight = ladj->weight;
			atr->adj_sid[i].neighbor.addr = ladj->neighbor_id;
			if (i == 0)
				SET_FLAG(atr->flags, LS_ATTR_ADJ_SID);
			else
				SET_FLAG(atr->flags, LS_ATTR_BCK_ADJ_SID);
			if (edge->status != NEW)
				edge->status = UPDATE;

			break;
		case EXT_SUBTLV_RMT_ITF_ADDR:
			rmt = (struct ext_subtlv_rmt_itf_addr *)tlvh;
			if (CHECK_FLAG(atr->flags, LS_ATTR_NEIGH_ADDR)
			    && IPV4_ADDR_SAME(&atr->standard.remote,
					      &rmt->value))
				break;

			atr->standard.remote = rmt->value;
			SET_FLAG(atr->flags, LS_ATTR_NEIGH_ADDR);
			if (edge->status != NEW)
				edge->status = UPDATE;

			break;
		default:
			break;
		}
		sum += TLV_SIZE(tlvh);
	}

	/* Export Link State Edge if needed */
	if (edge->status == NEW || edge->status == UPDATE) {
		ote_debug("  |- %s Adj-SID %d & %d to edge %pI4",
			  edge->status == NEW ? "Add" : "Update",
			  edge->attributes->adj_sid[0].sid,
			  edge->attributes->adj_sid[1].sid,
			  &edge->attributes->standard.local);

		ospf_te_export(LS_MSG_TYPE_ATTRIBUTES, edge);
		edge->status = SYNC;
	}

	return 0;
}

/**
 * Delete Link State Edge information (Segment Routing Adjacency) that
 * correspond to the Opaque Extended Link LSA (Type 8) TLVs. Note that the Edge
 * is not removed.
 *
 * @param ted	Link State Traffic Engineering Database
 * @param lsa	OSPF Link State Advertisement
 *
 * @return	0 if success, -1 otherwise
 */
static int ospf_te_delete_ext_link(struct ls_ted *ted, struct ospf_lsa *lsa)
{
	struct ls_edge *edge;
	struct ls_attributes *atr;
	struct ext_tlv_link *ext;
	struct ls_edge_key key;

	/* Search for corresponding Edge from Link State Data Base */
	ext = (struct ext_tlv_link *)TLV_HDR_TOP(lsa->data);
	key.family = AF_INET;
	IPV4_ADDR_COPY(&key.k.addr, &ext->link_data);
	edge = ls_find_edge_by_key(ted, key);

	/* Check if there is a corresponding Edge */
	if (!edge)
		return -1;

	ote_debug("  |- Delete Adj-SID %d to edge %pI4",
		  edge->attributes->adj_sid[0].sid,
		  &edge->attributes->standard.local);

	/* Remove Segment Routing information */
	atr = edge->attributes;
	UNSET_FLAG(atr->flags, LS_ATTR_ADJ_SID);
	UNSET_FLAG(atr->flags, LS_ATTR_BCK_ADJ_SID);
	memset(atr->adj_sid, 0, 2 * sizeof(struct ls_sid));
	edge->status = UPDATE;

	/* Edge has been updated: export it */
	ospf_te_export(LS_MSG_TYPE_ATTRIBUTES, edge);
	edge->status = SYNC;

	return 0;
}

/**
 * Parse Opaque LSA Type and call corresponding parser.
 *
 * @param ted	Link State Traffic Engineering Database
 * @param lsa	OSPF Link State Advertisement
 *
 * @return	0 if success, -1 otherwise
 */
static int ospf_te_parse_opaque_lsa(struct ls_ted *ted, struct ospf_lsa *lsa)
{
	uint8_t key = GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr));
	int rc = -1;

	ote_debug("MPLS-TE (%s): Parse Opaque LSA[%pI4] from Router[%pI4]",
		  __func__, &lsa->data->id, &lsa->data->adv_router);

	switch (key) {
	case OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA:
	case OPAQUE_TYPE_INTER_AS_LSA:
		rc = ospf_te_parse_te(ted, lsa);
		break;
	case OPAQUE_TYPE_ROUTER_INFORMATION_LSA:
		rc = ospf_te_parse_ri(ted, lsa);
		break;
	case OPAQUE_TYPE_EXTENDED_PREFIX_LSA:
		rc = ospf_te_parse_ext_pref(ted, lsa);
		break;
	case OPAQUE_TYPE_EXTENDED_LINK_LSA:
		rc = ospf_te_parse_ext_link(ted, lsa);
		break;
	default:
		break;
	}

	return rc;
}

/**
 * Parse Opaque LSA Type and call corresponding deletion function.
 *
 * @param ted	Link State Traffic Engineering Database
 * @param lsa	OSPF Link State Advertisement
 *
 * @return	0 if success, -1 otherwise
 */
static int ospf_te_delete_opaque_lsa(struct ls_ted *ted, struct ospf_lsa *lsa)
{
	uint8_t key = GET_OPAQUE_TYPE(ntohl(lsa->data->id.s_addr));
	int rc = -1;

	ote_debug("MPLS-TE (%s): Parse Opaque LSA[%pI4] from Router[%pI4]",
		  __func__, &lsa->data->id, &lsa->data->adv_router);

	switch (key) {
	case OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA:
	case OPAQUE_TYPE_INTER_AS_LSA:
		rc = ospf_te_delete_te(ted, lsa);
		break;
	case OPAQUE_TYPE_ROUTER_INFORMATION_LSA:
		rc = ospf_te_delete_ri(ted, lsa);
		break;
	case OPAQUE_TYPE_EXTENDED_PREFIX_LSA:
		rc = ospf_te_delete_ext_pref(ted, lsa);
		break;
	case OPAQUE_TYPE_EXTENDED_LINK_LSA:
		rc = ospf_te_delete_ext_link(ted, lsa);
		break;
	default:
		break;
	}

	return rc;
}

/**
 * Update Traffic Engineering Database Elements that correspond to the received
 * OSPF LSA. If LSA age is equal to MAX_AGE, call deletion function instead.
 *
 * @param lsa	OSPF Link State Advertisement
 *
 * @return	0 if success, -1 otherwise
 */
static int ospf_mpls_te_lsa_update(struct ospf_lsa *lsa)
{

	uint8_t rc;

	/* Check that MPLS-TE is active */
	if (!OspfMplsTE.enabled || !OspfMplsTE.ted)
		return 0;

	/* Sanity Check */
	if (lsa == NULL) {
		flog_warn(EC_OSPF_LSA_NULL, "TE (%s): Abort! LSA is NULL",
			  __func__);
		return -1;
	}

	/* If LSA is MAX_AGE, remove corresponding Link State element */
	if (IS_LSA_MAXAGE(lsa)) {
		switch (lsa->data->type) {
		case OSPF_ROUTER_LSA:
			rc = ospf_te_delete_router_lsa(OspfMplsTE.ted, lsa);
			break;
		case OSPF_OPAQUE_AREA_LSA:
		case OSPF_OPAQUE_AS_LSA:
			rc = ospf_te_delete_opaque_lsa(OspfMplsTE.ted, lsa);
			break;
		default:
			rc = 0;
			break;
		}
	} else {
		/* Parse LSA to Update corresponding Link State element */
		switch (lsa->data->type) {
		case OSPF_ROUTER_LSA:
			rc = ospf_te_parse_router_lsa(OspfMplsTE.ted, lsa);
			break;
		case OSPF_OPAQUE_AREA_LSA:
		case OSPF_OPAQUE_AS_LSA:
			rc = ospf_te_parse_opaque_lsa(OspfMplsTE.ted, lsa);
			break;
		default:
			rc = 0;
			break;
		}
	}

	return rc;
}

/**
 * Delete Traffic Engineering Database element from OSPF LSA. This function
 * process only self LSA (i.e. advertised by the router) which reach MAX_AGE
 * as LSA deleted by neighbor routers are Flushed (i.e. advertised with
 * age == MAX_AGE) and processed by ospf_mpls_te_lsa_update() function.
 *
 * @param lsa	OSPF Link State Advertisement
 *
 * @return	0 if success, -1 otherwise
 */
static int ospf_mpls_te_lsa_delete(struct ospf_lsa *lsa)
{

	uint8_t rc;

	/* Check that MPLS-TE is active */
	if (!OspfMplsTE.enabled || !OspfMplsTE.ted)
		return 0;

	/* Sanity Check */
	if (lsa == NULL) {
		flog_warn(EC_OSPF_LSA_NULL, "TE (%s): Abort! LSA is NULL",
			  __func__);
		return -1;
	}

	/*
	 * Process only self LSAs that reach MAX_AGE. Indeed, when the router
	 * need to update or refresh an LSA, it first removes the old LSA from
	 * the LSDB and then insert the new one. Thus, to avoid removing
	 * corresponding Link State element and loosing some parameters
	 * instead of just updating it, only self LSAs that reach MAX_AGE are
	 * processed here. Other LSAs are processed by ospf_mpls_te_lsa_update()
	 * and eventually removed when LSA age is MAX_AGE i.e. LSA is flushed
	 * by the originator.
	 */
	if (!IS_LSA_SELF(lsa) || !IS_LSA_MAXAGE(lsa))
		return 0;

	/* Parse Link State information */
	switch (lsa->data->type) {
	case OSPF_ROUTER_LSA:
		rc = ospf_te_delete_router_lsa(OspfMplsTE.ted, lsa);
		break;
	case OSPF_OPAQUE_AREA_LSA:
	case OSPF_OPAQUE_AS_LSA:
		rc = ospf_te_delete_opaque_lsa(OspfMplsTE.ted, lsa);
		break;
	default:
		rc = 0;
		break;
	}

	return rc;
}

/**
 * Send the whole Link State Traffic Engineering Database to the consumer that
 * request it through a ZAPI Link State Synchronous Opaque Message.
 *
 * @param info	ZAPI Opaque message
 *
 * @return	0 if success, -1 otherwise
 */
int ospf_te_sync_ted(struct zapi_opaque_reg_info dst)
{
	int rc = -1;

	/* Check that MPLS-TE and TE distribution are enabled */
	if (!OspfMplsTE.enabled || !OspfMplsTE.export)
		return rc;

	rc = ls_sync_ted(OspfMplsTE.ted, zclient, &dst);

	return rc;
}

/**
 * Initialize Traffic Engineering Database from the various OSPF Link State
 * Database (LSDB).
 *
 * @param ted	Link State Traffice Engineering Database
 * @param ospf	OSPF main structure
 */
static void ospf_te_init_ted(struct ls_ted *ted, struct ospf *ospf)
{
	struct listnode *node, *nnode;
	struct route_node *rn;
	struct ospf_area *area;
	struct ospf_lsa *lsa;

	/* Iterate over all areas. */
	for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area)) {
		if (!area->lsdb)
			continue;

		/* Parse all Router LSAs from the area LSDB */
		LSDB_LOOP (ROUTER_LSDB(area), rn, lsa)
			ospf_te_parse_router_lsa(ted, lsa);

		/* Parse all Opaque LSAs from the area LSDB */
		LSDB_LOOP (OPAQUE_AREA_LSDB(area), rn, lsa)
			ospf_te_parse_opaque_lsa(ted, lsa);
	}

	/* Parse AS-external opaque LSAs from OSPF LSDB */
	if (ospf->lsdb) {
		LSDB_LOOP (OPAQUE_AS_LSDB(ospf), rn, lsa)
			ospf_te_parse_opaque_lsa(ted, lsa);
	}

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

static uint16_t show_vty_router_addr(struct vty *vty, struct tlv_header *tlvh,
				     json_object *json)
{
	struct te_tlv_router_addr *top = (struct te_tlv_router_addr *)tlvh;

	check_tlv_size(TE_LINK_SUBTLV_DEF_SIZE, "Router Address");

	if (vty != NULL)
		if (!json)
			vty_out(vty, "  Router-Address: %pI4\n", &top->value);
		else
			json_object_string_addf(json, "routerAddress", "%pI4",
						&top->value);
	else
		zlog_debug("    Router-Address: %pI4", &top->value);

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_header(struct vty *vty, struct tlv_header *tlvh,
				     size_t buf_size, json_object *json)
{
	struct te_tlv_link *top = (struct te_tlv_link *)tlvh;

	if (TLV_SIZE(tlvh) > buf_size) {
		if (vty != NULL)
			vty_out(vty,
				"    TLV size %d exceeds buffer size. Abort!",
				TLV_SIZE(tlvh));
		else
			zlog_debug(
				"    TLV size %d exceeds buffer size. Abort!",
				TLV_SIZE(tlvh));
		return buf_size;
	}

	if (vty != NULL)
		if (!json)
			vty_out(vty, "  Link: %u octets of data\n",
				ntohs(top->header.length));
		else
			json_object_int_add(json, "teLinkDataLength",
					    ntohs(top->header.length));
	else
		zlog_debug("    Link: %u octets of data",
			   ntohs(top->header.length));

	return TLV_HDR_SIZE; /* Here is special, not "TLV_SIZE". */
}

static uint16_t show_vty_link_subtlv_link_type(struct vty *vty,
					       struct tlv_header *tlvh,
					       json_object *json)
{
	struct te_link_subtlv_link_type *top;
	const char *cp = "Unknown";

	check_tlv_size(TE_LINK_SUBTLV_TYPE_SIZE, "Link Type");

	top = (struct te_link_subtlv_link_type *)tlvh;
	switch (top->link_type.value) {
	case LINK_TYPE_SUBTLV_VALUE_PTP:
		cp = "Point-to-point";
		break;
	case LINK_TYPE_SUBTLV_VALUE_MA:
		cp = "Multiaccess";
		break;
	default:
		break;
	}

	if (vty != NULL)
		if (!json)
			vty_out(vty, "  Link-Type: %s (%u)\n", cp,
				top->link_type.value);
		else
			json_object_string_add(json, "accessType", cp);
	else
		zlog_debug("    Link-Type: %s (%u)", cp, top->link_type.value);

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_link_id(struct vty *vty,
					     struct tlv_header *tlvh,
					     json_object *json)
{
	struct te_link_subtlv_link_id *top;

	check_tlv_size(TE_LINK_SUBTLV_DEF_SIZE, "Link ID");

	top = (struct te_link_subtlv_link_id *)tlvh;
	if (vty != NULL)
		if (!json)
			vty_out(vty, "  Link-ID: %pI4\n", &top->value);
		else
			json_object_string_addf(json, "linkID", "%pI4",
						&top->value);
	else
		zlog_debug("    Link-ID: %pI4", &top->value);

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_lclif_ipaddr(struct vty *vty,
						  struct tlv_header *tlvh,
						  size_t buf_size,
						  json_object *json)
{
	struct te_link_subtlv_lclif_ipaddr *top;
	json_object *json_addr, *json_obj;
	char buf[4];
	int i, n;

	if (TLV_SIZE(tlvh) > buf_size) {
		if (vty != NULL)
			vty_out(vty,
				"    TLV size %d exceeds buffer size. Abort!",
				TLV_SIZE(tlvh));
		else
			zlog_debug(
				"    TLV size %d exceeds buffer size. Abort!",
				TLV_SIZE(tlvh));
		return buf_size;
	}

	top = (struct te_link_subtlv_lclif_ipaddr *)tlvh;
	n = ntohs(tlvh->length) / sizeof(top->value[0]);

	if (vty != NULL)
		if (!json)
			vty_out(vty, "  Local Interface IP Address(es): %d\n",
				n);
		else {
			json_addr = json_object_new_array();
			json_object_object_add(json, "localIPAddresses",
					       json_addr);
		}
	else
		zlog_debug("    Local Interface IP Address(es): %d", n);

	for (i = 0; i < n; i++) {
		if (vty != NULL)
			if (!json)
				vty_out(vty, "    #%d: %pI4\n", i,
					&top->value[i]);
			else {
				json_obj = json_object_new_object();
				snprintfrr(buf, 2, "%d", i);
				json_object_string_addf(json_obj, buf, "%pI4",
							&top->value[i]);
				json_object_array_add(json_addr, json_obj);
			}
		else
			zlog_debug("      #%d: %pI4", i, &top->value[i]);
	}
	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_rmtif_ipaddr(struct vty *vty,
						  struct tlv_header *tlvh,
						  size_t buf_size,
						  json_object *json)
{
	struct te_link_subtlv_rmtif_ipaddr *top;
	json_object *json_addr, *json_obj;
	char buf[4];
	int i, n;

	if (TLV_SIZE(tlvh) > buf_size) {
		if (vty != NULL)
			vty_out(vty,
				"    TLV size %d exceeds buffer size. Abort!",
				TLV_SIZE(tlvh));
		else
			zlog_debug(
				"    TLV size %d exceeds buffer size. Abort!",
				TLV_SIZE(tlvh));
		return buf_size;
	}

	top = (struct te_link_subtlv_rmtif_ipaddr *)tlvh;
	n = ntohs(tlvh->length) / sizeof(top->value[0]);
	if (vty != NULL)
		if (!json)
			vty_out(vty, "  Remote Interface IP Address(es): %d\n",
				n);
		else {
			json_addr = json_object_new_array();
			json_object_object_add(json, "remoteIPAddresses",
					       json_addr);
		}
	else
		zlog_debug("    Remote Interface IP Address(es): %d", n);

	for (i = 0; i < n; i++) {
		if (vty != NULL)
			if (!json)
				vty_out(vty, "    #%d: %pI4\n", i,
					&top->value[i]);
			else {
				json_obj = json_object_new_object();
				snprintfrr(buf, 2, "%d", i);
				json_object_string_addf(json_obj, buf, "%pI4",
							&top->value[i]);
				json_object_array_add(json_addr, json_obj);
			}
		else
			zlog_debug("      #%d: %pI4", i, &top->value[i]);
	}
	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_te_metric(struct vty *vty,
					       struct tlv_header *tlvh,
					       json_object *json)
{
	struct te_link_subtlv_te_metric *top;

	check_tlv_size(TE_LINK_SUBTLV_DEF_SIZE, "TE Metric");

	top = (struct te_link_subtlv_te_metric *)tlvh;
	if (vty != NULL)
		if (!json)
			vty_out(vty, "  Traffic Engineering Metric: %u\n",
				(uint32_t)ntohl(top->value));
		else
			json_object_int_add(json, "teDefaultMetric",
					    (uint32_t)ntohl(top->value));
	else
		zlog_debug("    Traffic Engineering Metric: %u",
			   (uint32_t)ntohl(top->value));

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_max_bw(struct vty *vty,
					    struct tlv_header *tlvh,
					    json_object *json)
{
	struct te_link_subtlv_max_bw *top;
	float fval;

	check_tlv_size(TE_LINK_SUBTLV_DEF_SIZE, "Maximum Bandwidth");

	top = (struct te_link_subtlv_max_bw *)tlvh;
	fval = ntohf(top->value);

	if (vty != NULL)
		if (!json)
			vty_out(vty, "  Maximum Bandwidth: %g (Bytes/sec)\n",
				fval);
		else
			json_object_double_add(json, "maxLinkBandwidth", fval);
	else
		zlog_debug("    Maximum Bandwidth: %g (Bytes/sec)", fval);

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_max_rsv_bw(struct vty *vty,
						struct tlv_header *tlvh,
						json_object *json)
{
	struct te_link_subtlv_max_rsv_bw *top;
	float fval;

	check_tlv_size(TE_LINK_SUBTLV_DEF_SIZE, "Maximum Reservable Bandwidth");

	top = (struct te_link_subtlv_max_rsv_bw *)tlvh;
	fval = ntohf(top->value);

	if (vty != NULL)
		if (!json)
			vty_out(vty, "  Maximum Reservable Bandwidth: %g (Bytes/sec)\n",
				fval);
		else
			json_object_double_add(json, "maxResvLinkBandwidth",
					       fval);
	else
		zlog_debug("    Maximum Reservable Bandwidth: %g (Bytes/sec)",
			   fval);

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_unrsv_bw(struct vty *vty,
					      struct tlv_header *tlvh,
					      json_object *json)
{
	struct te_link_subtlv_unrsv_bw *top;
	json_object *json_bw, *json_obj;
	float fval1, fval2;
	char buf[16];
	int i;

	check_tlv_size(TE_LINK_SUBTLV_UNRSV_SIZE, "Unreserved Bandwidth");

	top = (struct te_link_subtlv_unrsv_bw *)tlvh;
	if (vty != NULL)
		if (!json)
			vty_out(vty,
				"  Unreserved Bandwidth per Class Type in Byte/s:\n");
		else {
			json_bw = json_object_new_array();
			json_object_object_add(json, "unreservedBandwidth",
					       json_bw);
		}
	else
		zlog_debug(
			"    Unreserved Bandwidth per Class Type in Byte/s:");
	for (i = 0; i < MAX_CLASS_TYPE; i += 2) {
		fval1 = ntohf(top->value[i]);
		fval2 = ntohf(top->value[i + 1]);

		if (vty != NULL)
			if (!json)
				vty_out(vty,
					"    [%d]: %g (Bytes/sec),\t[%d]: %g (Bytes/sec)\n",
					i, fval1, i + 1, fval2);
			else {
				json_obj = json_object_new_object();
				snprintfrr(buf, 12, "classType-%u", i);
				json_object_double_add(json_obj, buf, fval1);
				json_object_array_add(json_bw, json_obj);
				json_obj = json_object_new_object();
				snprintfrr(buf, 12, "classType-%u", i + 1);
				json_object_double_add(json_obj, buf, fval2);
				json_object_array_add(json_bw, json_obj);
			}
		else
			zlog_debug(
				"      [%d]: %g (Bytes/sec),  [%d]: %g (Bytes/sec)",
				i, fval1, i + 1, fval2);
	}

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_rsc_clsclr(struct vty *vty,
						struct tlv_header *tlvh,
						json_object *json)
{
	struct te_link_subtlv_rsc_clsclr *top;

	check_tlv_size(TE_LINK_SUBTLV_DEF_SIZE, "Resource class/color");

	top = (struct te_link_subtlv_rsc_clsclr *)tlvh;
	if (vty != NULL)
		if (!json)
			vty_out(vty, "  Resource class/color: 0x%x\n",
				(uint32_t)ntohl(top->value));
		else
			json_object_string_addf(json, "administrativeGroup",
						"0x%x",
						(uint32_t)ntohl(top->value));
	else
		zlog_debug("    Resource Class/Color: 0x%x",
			   (uint32_t)ntohl(top->value));

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_lrrid(struct vty *vty,
					   struct tlv_header *tlvh,
					   json_object *json)
{
	struct te_link_subtlv_lrrid *top;

	check_tlv_size(TE_LINK_SUBTLV_LRRID_SIZE, "Local/Remote Router ID");

	top = (struct te_link_subtlv_lrrid *)tlvh;

	if (vty != NULL) {
		if (!json) {
			vty_out(vty, "  Local  TE Router ID: %pI4\n",
				&top->local);
			vty_out(vty, "  Remote TE Router ID: %pI4\n",
				&top->remote);
		} else {
			json_object_string_addf(json, "localTeRouterID", "%pI4",
						&top->local);
			json_object_string_addf(json, "remoteTeRouterID",
						"%pI4", &top->remote);
		}
	} else {
		zlog_debug("    Local  TE Router ID: %pI4",
			   &top->local);
		zlog_debug("    Remote TE Router ID: %pI4",
			   &top->remote);
	}

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_llri(struct vty *vty,
					  struct tlv_header *tlvh,
					  json_object *json)
{
	struct te_link_subtlv_llri *top;

	check_tlv_size(TE_LINK_SUBTLV_LLRI_SIZE, "Link Local/Remote ID");

	top = (struct te_link_subtlv_llri *)tlvh;

	if (vty != NULL) {
		if (!json) {
			vty_out(vty, "  Link Local  ID: %d\n",
				(uint32_t)ntohl(top->local));
			vty_out(vty, "  Link Remote ID: %d\n",
				(uint32_t)ntohl(top->remote));
		} else {
			json_object_int_add(json, "localLinkID",
					    (uint32_t)ntohl(top->local));
			json_object_int_add(json, "remoteLinkID",
					    (uint32_t)ntohl(top->remote));
		}
	} else {
		zlog_debug("    Link Local  ID: %d",
			   (uint32_t)ntohl(top->local));
		zlog_debug("    Link Remote ID: %d",
			   (uint32_t)ntohl(top->remote));
	}

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_rip(struct vty *vty,
					 struct tlv_header *tlvh,
					 json_object *json)
{
	struct te_link_subtlv_rip *top;

	check_tlv_size(TE_LINK_SUBTLV_DEF_SIZE, "Remote ASBR Address");

	top = (struct te_link_subtlv_rip *)tlvh;

	if (vty != NULL)
		if (!json)
			vty_out(vty, "  Inter-AS TE Remote ASBR IP address: %pI4\n",
				&top->value);
		else
			json_object_string_addf(json, "remoteAsbrAddress",
						"%pI4", &top->value);
	else
		zlog_debug("    Inter-AS TE Remote ASBR IP address: %pI4",
			   &top->value);

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_ras(struct vty *vty,
					 struct tlv_header *tlvh,
					 json_object *json)
{
	struct te_link_subtlv_ras *top;

	check_tlv_size(TE_LINK_SUBTLV_DEF_SIZE, "Remote AS number");

	top = (struct te_link_subtlv_ras *)tlvh;

	if (vty != NULL)
		if (!json)
			vty_out(vty, "  Inter-AS TE Remote AS number: %u\n",
				ntohl(top->value));
		else
			json_object_int_add(json, "remoteAsbrNumber",
					    ntohl(top->value));
	else
		zlog_debug("    Inter-AS TE Remote AS number: %u",
			   ntohl(top->value));

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_av_delay(struct vty *vty,
					      struct tlv_header *tlvh,
					      json_object *json)
{
	struct te_link_subtlv_av_delay *top;
	uint32_t delay;
	uint32_t anomalous;

	check_tlv_size(TE_LINK_SUBTLV_DEF_SIZE, "Average Link Delay");

	top = (struct te_link_subtlv_av_delay *)tlvh;
	delay = (uint32_t)ntohl(top->value) & TE_EXT_MASK;
	anomalous = (uint32_t)ntohl(top->value) & TE_EXT_ANORMAL;

	if (vty != NULL)
		if (!json)
			vty_out(vty, "  %s Average Link Delay: %d (micro-sec)\n",
				anomalous ? "Anomalous" : "Normal", delay);
		else {
			json_object_int_add(json, "oneWayDelay", delay);
			json_object_string_add(json, "oneWayDelayNormality",
					       anomalous ? "abnormal"
							 : "normal");
		}
	else
		zlog_debug("    %s Average Link Delay: %d (micro-sec)",
			   anomalous ? "Anomalous" : "Normal", delay);

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_mm_delay(struct vty *vty,
					      struct tlv_header *tlvh,
					      json_object *json)
{
	struct te_link_subtlv_mm_delay *top;
	uint32_t low, high;
	uint32_t anomalous;

	check_tlv_size(TE_LINK_SUBTLV_MM_DELAY_SIZE, "Min/Max Link Delay");

	top = (struct te_link_subtlv_mm_delay *)tlvh;
	low = (uint32_t)ntohl(top->low) & TE_EXT_MASK;
	anomalous = (uint32_t)ntohl(top->low) & TE_EXT_ANORMAL;
	high = (uint32_t)ntohl(top->high);

	if (vty != NULL)
		if (!json)
			vty_out(vty,
				"  %s Min/Max Link Delay: %d/%d (micro-sec)\n",
				anomalous ? "Anomalous" : "Normal", low, high);
		else {
			json_object_int_add(json, "oneWayMinDelay", low);
			json_object_string_add(json, "oneWayMinDelayNormality",
					       anomalous ? "abnormal"
							 : "normal");
			json_object_int_add(json, "oneWayMaxDelay", high);
			json_object_string_add(json, "oneWayMaxDelayNormality",
					       anomalous ? "abnormal"
							 : "normal");
		}
	else
		zlog_debug("    %s Min/Max Link Delay: %d/%d (micro-sec)",
			   anomalous ? "Anomalous" : "Normal", low, high);

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_delay_var(struct vty *vty,
					       struct tlv_header *tlvh,
					       json_object *json)
{
	struct te_link_subtlv_delay_var *top;
	uint32_t jitter;

	check_tlv_size(TE_LINK_SUBTLV_DEF_SIZE, "Link Delay Variation");

	top = (struct te_link_subtlv_delay_var *)tlvh;
	jitter = (uint32_t)ntohl(top->value) & TE_EXT_MASK;

	if (vty != NULL)
		if (!json)
			vty_out(vty, "  Delay Variation: %d (micro-sec)\n",
				jitter);
		else
			json_object_int_add(json, "oneWayDelayVariation",
					    jitter);
	else
		zlog_debug("    Delay Variation: %d (micro-sec)", jitter);

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_pkt_loss(struct vty *vty,
					      struct tlv_header *tlvh,
					      json_object *json)
{
	struct te_link_subtlv_pkt_loss *top;
	uint32_t loss;
	uint32_t anomalous;
	float fval;

	check_tlv_size(TE_LINK_SUBTLV_DEF_SIZE, "Link Loss");

	top = (struct te_link_subtlv_pkt_loss *)tlvh;
	loss = (uint32_t)ntohl(top->value) & TE_EXT_MASK;
	fval = (float)(loss * LOSS_PRECISION);
	anomalous = (uint32_t)ntohl(top->value) & TE_EXT_ANORMAL;

	if (vty != NULL)
		if (!json)
			vty_out(vty, "  %s Link Loss: %g (%%)\n",
				anomalous ? "Anomalous" : "Normal", fval);
		else {
			json_object_double_add(json, "oneWayPacketLoss", fval);
			json_object_string_add(json,
					       "oneWayPacketLossNormality",
					       anomalous ? "abnormal"
							 : "normal");
		}
	else
		zlog_debug("    %s Link Loss: %g (%%)",
			   anomalous ? "Anomalous" : "Normal", fval);

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_res_bw(struct vty *vty,
					    struct tlv_header *tlvh,
					    json_object *json)
{
	struct te_link_subtlv_res_bw *top;
	float fval;

	check_tlv_size(TE_LINK_SUBTLV_DEF_SIZE, "Residual Bandwidth");

	top = (struct te_link_subtlv_res_bw *)tlvh;
	fval = ntohf(top->value);

	if (vty != NULL)
		if (!json)
			vty_out(vty,
				"  Unidirectional Residual Bandwidth: %g (Bytes/sec)\n",
				fval);
		else
			json_object_double_add(json, "oneWayResidualBandwidth",
					       fval);
	else
		zlog_debug(
			"    Unidirectional Residual Bandwidth: %g (Bytes/sec)",
			fval);

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_ava_bw(struct vty *vty,
					    struct tlv_header *tlvh,
					    json_object *json)
{
	struct te_link_subtlv_ava_bw *top;
	float fval;

	check_tlv_size(TE_LINK_SUBTLV_DEF_SIZE, "Available Bandwidth");

	top = (struct te_link_subtlv_ava_bw *)tlvh;
	fval = ntohf(top->value);

	if (vty != NULL)
		if (!json)
			vty_out(vty,
				"  Unidirectional Available Bandwidth: %g (Bytes/sec)\n",
				fval);
		else
			json_object_double_add(json, "oneWayAvailableBandwidth",
					       fval);
	else
		zlog_debug(
			"    Unidirectional Available Bandwidth: %g (Bytes/sec)",
			fval);

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_link_subtlv_use_bw(struct vty *vty,
					    struct tlv_header *tlvh,
					    json_object *json)
{
	struct te_link_subtlv_use_bw *top;
	float fval;

	check_tlv_size(TE_LINK_SUBTLV_DEF_SIZE, "Utilized Bandwidth");

	top = (struct te_link_subtlv_use_bw *)tlvh;
	fval = ntohf(top->value);

	if (vty != NULL)
		if (!json)
			vty_out(vty,
				"  Unidirectional Utilized Bandwidth: %g (Bytes/sec)\n",
				fval);
		else
			json_object_double_add(json, "oneWayUtilizedBandwidth",
					       fval);
	else
		zlog_debug(
			"    Unidirectional Utilized Bandwidth: %g (Bytes/sec)",
			fval);

	return TLV_SIZE(tlvh);
}

static uint16_t show_vty_unknown_tlv(struct vty *vty, struct tlv_header *tlvh,
				     size_t buf_size, json_object *json)
{
	json_object *obj;

	if (TLV_SIZE(tlvh) > buf_size) {
		if (vty != NULL)
			vty_out(vty,
				"    TLV size %d exceeds buffer size. Abort!",
				TLV_SIZE(tlvh));
		else
			zlog_debug(
				"    TLV size %d exceeds buffer size. Abort!",
				TLV_SIZE(tlvh));
		return buf_size;
	}

	if (vty != NULL)
		if (!json)
			vty_out(vty, "  Unknown TLV: [type(0x%x), length(0x%x)]\n",
				ntohs(tlvh->type), ntohs(tlvh->length));
		else {
			obj = json_object_new_object();
			json_object_string_addf(obj, "type", "0x%x",
						ntohs(tlvh->type));
			json_object_string_addf(obj, "length", "0x%x",
						ntohs(tlvh->length));
			json_object_object_add(json, "unknownTLV", obj);
		}
	else
		zlog_debug("    Unknown TLV: [type(0x%x), length(0x%x)]",
			   ntohs(tlvh->type), ntohs(tlvh->length));

	return TLV_SIZE(tlvh);
}

static uint16_t ospf_mpls_te_show_link_subtlv(struct vty *vty,
					      struct tlv_header *tlvh0,
					      uint16_t subtotal, uint16_t total,
					      json_object *json)
{
	struct tlv_header *tlvh;
	uint16_t sum = subtotal;

	for (tlvh = tlvh0; sum < total; tlvh = TLV_HDR_NEXT(tlvh)) {
		switch (ntohs(tlvh->type)) {
		case TE_LINK_SUBTLV_LINK_TYPE:
			sum += show_vty_link_subtlv_link_type(vty, tlvh, json);
			break;
		case TE_LINK_SUBTLV_LINK_ID:
			sum += show_vty_link_subtlv_link_id(vty, tlvh, json);
			break;
		case TE_LINK_SUBTLV_LCLIF_IPADDR:
			sum += show_vty_link_subtlv_lclif_ipaddr(vty, tlvh,
								 total - sum,
								 json);
			break;
		case TE_LINK_SUBTLV_RMTIF_IPADDR:
			sum += show_vty_link_subtlv_rmtif_ipaddr(vty, tlvh,
								 total - sum,
								 json);
			break;
		case TE_LINK_SUBTLV_TE_METRIC:
			sum += show_vty_link_subtlv_te_metric(vty, tlvh, json);
			break;
		case TE_LINK_SUBTLV_MAX_BW:
			sum += show_vty_link_subtlv_max_bw(vty, tlvh, json);
			break;
		case TE_LINK_SUBTLV_MAX_RSV_BW:
			sum += show_vty_link_subtlv_max_rsv_bw(vty, tlvh, json);
			break;
		case TE_LINK_SUBTLV_UNRSV_BW:
			sum += show_vty_link_subtlv_unrsv_bw(vty, tlvh, json);
			break;
		case TE_LINK_SUBTLV_RSC_CLSCLR:
			sum += show_vty_link_subtlv_rsc_clsclr(vty, tlvh, json);
			break;
		case TE_LINK_SUBTLV_LRRID:
			sum += show_vty_link_subtlv_lrrid(vty, tlvh, json);
			break;
		case TE_LINK_SUBTLV_LLRI:
			sum += show_vty_link_subtlv_llri(vty, tlvh, json);
			break;
		case TE_LINK_SUBTLV_RIP:
			sum += show_vty_link_subtlv_rip(vty, tlvh, json);
			break;
		case TE_LINK_SUBTLV_RAS:
			sum += show_vty_link_subtlv_ras(vty, tlvh, json);
			break;
		case TE_LINK_SUBTLV_AV_DELAY:
			sum += show_vty_link_subtlv_av_delay(vty, tlvh, json);
			break;
		case TE_LINK_SUBTLV_MM_DELAY:
			sum += show_vty_link_subtlv_mm_delay(vty, tlvh, json);
			break;
		case TE_LINK_SUBTLV_DELAY_VAR:
			sum += show_vty_link_subtlv_delay_var(vty, tlvh, json);
			break;
		case TE_LINK_SUBTLV_PKT_LOSS:
			sum += show_vty_link_subtlv_pkt_loss(vty, tlvh, json);
			break;
		case TE_LINK_SUBTLV_RES_BW:
			sum += show_vty_link_subtlv_res_bw(vty, tlvh, json);
			break;
		case TE_LINK_SUBTLV_AVA_BW:
			sum += show_vty_link_subtlv_ava_bw(vty, tlvh, json);
			break;
		case TE_LINK_SUBTLV_USE_BW:
			sum += show_vty_link_subtlv_use_bw(vty, tlvh, json);
			break;
		default:
			sum += show_vty_unknown_tlv(vty, tlvh, total - sum,
						    json);
			break;
		}
	}
	return sum;
}

static void ospf_mpls_te_show_info(struct vty *vty, struct json_object *json,
				   struct ospf_lsa *lsa)
{
	struct lsa_header *lsah = lsa->data;
	struct tlv_header *tlvh, *next;
	uint16_t sum, sub, total;
	uint16_t (*subfunc)(struct vty * vty, struct tlv_header * tlvh,
			    uint16_t subtotal, uint16_t total,
			    struct json_object *json) = NULL;
	json_object *jobj = NULL;

	sum = 0;
	sub = 0;
	total = lsa->size - OSPF_LSA_HEADER_SIZE;

	for (tlvh = TLV_HDR_TOP(lsah); sum < total && tlvh;
	     tlvh = (next ? next : TLV_HDR_NEXT(tlvh))) {
		if (subfunc != NULL) {
			sum = (*subfunc)(vty, tlvh, sum, total, jobj);
			next = (struct tlv_header *)((char *)tlvh + sum);
			subfunc = NULL;
			continue;
		}

		next = NULL;
		sub = total - sum;
		switch (ntohs(tlvh->type)) {
		case TE_TLV_ROUTER_ADDR:
			if (json) {
				jobj = json_object_new_object();
				json_object_object_add(json, "teRouterAddress",
						       jobj);
			}
			sum += show_vty_router_addr(vty, tlvh, jobj);
			break;
		case TE_TLV_LINK:
			if (json) {
				jobj = json_object_new_object();
				json_object_object_add(json, "teLink", jobj);
			}
			sum += show_vty_link_header(vty, tlvh, sub, jobj);
			subfunc = ospf_mpls_te_show_link_subtlv;
			next = TLV_DATA(tlvh);
			break;
		default:
			sum += show_vty_unknown_tlv(vty, tlvh, sub, json);
			break;
		}
	}
	return;
}

static void ospf_mpls_te_config_write_router(struct vty *vty)
{

	if (OspfMplsTE.enabled) {
		vty_out(vty, " mpls-te on\n");
		vty_out(vty, " mpls-te router-address %pI4\n",
			&OspfMplsTE.router_addr.value);

		if (OspfMplsTE.inter_as == AS)
			vty_out(vty, " mpls-te inter-as as\n");
		if (OspfMplsTE.inter_as == Area)
			vty_out(vty, " mpls-te inter-as area %pI4 \n",
				&OspfMplsTE.interas_areaid);
		if (OspfMplsTE.export)
			vty_out(vty, " mpls-te export\n");
	}
	return;
}

/*------------------------------------------------------------------------*
 * Following are vty command functions.
 *------------------------------------------------------------------------*/

DEFUN (ospf_mpls_te_on,
       ospf_mpls_te_on_cmd,
       "mpls-te on",
       MPLS_TE_STR
       "Enable the MPLS-TE functionality\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct listnode *node;
	struct mpls_te_link *lp;

	if (OspfMplsTE.enabled)
		return CMD_SUCCESS;

	/* Check that the OSPF is using default VRF */
	if (ospf->vrf_id != VRF_DEFAULT) {
		vty_out(vty, "MPLS TE is only supported in default VRF\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ote_debug("MPLS-TE: OFF -> ON");

	OspfMplsTE.enabled = true;

	/* Reoriginate RFC3630 & RFC6827 Links */
	ospf_mpls_te_foreach_area(ospf_mpls_te_lsa_schedule,
				  REORIGINATE_THIS_LSA);

	/* Reoriginate LSA if INTER-AS is always on */
	if (OspfMplsTE.inter_as != Off) {
		for (ALL_LIST_ELEMENTS_RO(OspfMplsTE.iflist, node, lp)) {
			if (IS_INTER_AS(lp->type)) {
				ospf_mpls_te_lsa_schedule(lp,
							  REORIGINATE_THIS_LSA);
			}
		}
	}

	/* Create TED and initialize it */
	OspfMplsTE.ted = ls_ted_new(1, "OSPF", 0);
	if (!OspfMplsTE.ted) {
		vty_out(vty, "Unable to create Link State Data Base\n");
		return CMD_WARNING;
	}
	ospf_te_init_ted(OspfMplsTE.ted, ospf);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_mpls_te,
       no_ospf_mpls_te_cmd,
       "no mpls-te [on]",
       NO_STR
       MPLS_TE_STR
       "Disable the MPLS-TE functionality\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct listnode *node, *nnode;
	struct mpls_te_link *lp;

	if (!OspfMplsTE.enabled)
		return CMD_SUCCESS;

	ote_debug("MPLS-TE: ON -> OFF");

	/* Remove TED */
	ls_ted_del_all(&OspfMplsTE.ted);
	OspfMplsTE.enabled = false;

	/* Flush all TE Opaque LSAs */
	for (ALL_LIST_ELEMENTS(OspfMplsTE.iflist, node, nnode, lp))
		if (CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED))
			ospf_mpls_te_lsa_schedule(lp, FLUSH_THIS_LSA);

	/*
	 * This resets the OspfMplsTE.inter_as to its initial state.
	 * This is to avoid having an inter-as value different from
	 * Off when mpls-te gets restarted (after being removed)
	 */
	OspfMplsTE.inter_as = Off;

	return CMD_SUCCESS;
}

DEFUN (ospf_mpls_te_router_addr,
       ospf_mpls_te_router_addr_cmd,
       "mpls-te router-address A.B.C.D",
       MPLS_TE_STR
       "Stable IP address of the advertising router\n"
       "MPLS-TE router address in IPv4 address format\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4 = 2;
	struct te_tlv_router_addr *ra = &OspfMplsTE.router_addr;
	struct in_addr value;

	if (!inet_aton(argv[idx_ipv4]->arg, &value)) {
		vty_out(vty, "Please specify Router-Addr by A.B.C.D\n");
		return CMD_WARNING;
	}

	if (ntohs(ra->header.type) == 0
	    || ntohl(ra->value.s_addr) != ntohl(value.s_addr)) {
		struct listnode *node, *nnode;
		struct mpls_te_link *lp;
		int need_to_reoriginate = 0;

		set_mpls_te_router_addr(value);

		if (!OspfMplsTE.enabled)
			return CMD_SUCCESS;

		for (ALL_LIST_ELEMENTS(OspfMplsTE.iflist, node, nnode, lp)) {
			if ((lp->area == NULL) || IS_FLOOD_AS(lp->flags))
				continue;

			if (!CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED)) {
				need_to_reoriginate = 1;
				break;
			}
		}

		for (ALL_LIST_ELEMENTS(OspfMplsTE.iflist, node, nnode, lp)) {
			if ((lp->area == NULL) || IS_FLOOD_AS(lp->flags))
				continue;

			if (need_to_reoriginate)
				SET_FLAG(lp->flags, LPFLG_LSA_FORCED_REFRESH);
			else
				ospf_mpls_te_lsa_schedule(lp, REFRESH_THIS_LSA);
		}

		if (need_to_reoriginate)
			ospf_mpls_te_foreach_area(ospf_mpls_te_lsa_schedule,
						  REORIGINATE_THIS_LSA);
	}

	return CMD_SUCCESS;
}

static int set_inter_as_mode(struct vty *vty, const char *mode_name,
			     const char *area_id)
{
	enum inter_as_mode mode;
	struct listnode *node;
	struct mpls_te_link *lp;
	int format;

	if (OspfMplsTE.enabled) {

		/* Read and Check inter_as mode */
		if (strcmp(mode_name, "as") == 0)
			mode = AS;
		else if (strcmp(mode_name, "area") == 0) {
			mode = Area;
			VTY_GET_OSPF_AREA_ID(OspfMplsTE.interas_areaid, format,
					     area_id);
		} else {
			vty_out(vty,
				"Unknown mode. Please choose between as or area\n");
			return CMD_WARNING;
		}

		ote_debug(
			"MPLS-TE (%s): Inter-AS enable with %s flooding support",
			__func__, mode2text[mode]);

		/* Enable mode and re-originate LSA if needed */
		if ((OspfMplsTE.inter_as == Off)
		    && (mode != OspfMplsTE.inter_as)) {
			OspfMplsTE.inter_as = mode;
			/* Re-originate all InterAS-TEv2 LSA */
			for (ALL_LIST_ELEMENTS_RO(OspfMplsTE.iflist, node,
						  lp)) {
				if (IS_INTER_AS(lp->type)) {
					if (mode == AS)
						SET_FLAG(lp->flags,
							 LPFLG_LSA_FLOOD_AS);
					else
						UNSET_FLAG(lp->flags,
							   LPFLG_LSA_FLOOD_AS);
					ospf_mpls_te_lsa_schedule(
						lp, REORIGINATE_THIS_LSA);
				}
			}
		} else {
			vty_out(vty,
				"Please change Inter-AS support to disable first before going to mode %s\n",
				mode2text[mode]);
			return CMD_WARNING;
		}
	} else {
		vty_out(vty, "mpls-te has not been turned on\n");
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}


DEFUN (ospf_mpls_te_inter_as_as,
       ospf_mpls_te_inter_as_cmd,
       "mpls-te inter-as as",
       MPLS_TE_STR
       "Configure MPLS-TE Inter-AS support\n"
       "AS native mode self originate INTER_AS LSA with Type 11 (as flooding scope)\n")
{
	return set_inter_as_mode(vty, "as", "");
}

DEFUN (ospf_mpls_te_inter_as_area,
       ospf_mpls_te_inter_as_area_cmd,
       "mpls-te inter-as area <A.B.C.D|(0-4294967295)>",
       MPLS_TE_STR
       "Configure MPLS-TE Inter-AS support\n"
       "AREA native mode self originate INTER_AS LSA with Type 10 (area flooding scope)\n"
       "OSPF area ID in IP format\n"
       "OSPF area ID as decimal value\n")
{
	int idx_ipv4_number = 3;
	return set_inter_as_mode(vty, "area", argv[idx_ipv4_number]->arg);
}

DEFUN (no_ospf_mpls_te_inter_as,
       no_ospf_mpls_te_inter_as_cmd,
       "no mpls-te inter-as",
       NO_STR
       MPLS_TE_STR
       "Disable MPLS-TE Inter-AS support\n")
{

	struct listnode *node, *nnode;
	struct mpls_te_link *lp;

	ote_debug("MPLS-TE: Inter-AS support OFF");

	if ((OspfMplsTE.enabled) && (OspfMplsTE.inter_as != Off)) {
		/* Flush all Inter-AS LSA */
		for (ALL_LIST_ELEMENTS(OspfMplsTE.iflist, node, nnode, lp))
			if (IS_INTER_AS(lp->type)
			    && CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED))
				ospf_mpls_te_lsa_schedule(lp, FLUSH_THIS_LSA);

		OspfMplsTE.inter_as = Off;
	}

	return CMD_SUCCESS;
}

DEFUN (ospf_mpls_te_export,
       ospf_mpls_te_export_cmd,
       "mpls-te export",
       MPLS_TE_STR
       "Export the MPLS-TE information as Link State\n")
{

	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (OspfMplsTE.enabled) {
		if (ls_register(zclient, true) != 0) {
			vty_out(vty, "Unable to register Link State\n");
			return CMD_WARNING;
		}
		OspfMplsTE.export = true;
	} else {
		vty_out(vty, "mpls-te has not been turned on\n");
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}


DEFUN (no_ospf_mpls_te_export,
       no_ospf_mpls_te_export_cmd,
       "no mpls-te export",
       NO_STR
       MPLS_TE_STR
       "Stop export of the MPLS-TE information as Link State\n")
{

	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (OspfMplsTE.export) {
		if (ls_unregister(zclient, true) != 0) {
			vty_out(vty, "Unable to unregister Link State\n");
			return CMD_WARNING;
		}
		OspfMplsTE.export = false;
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_mpls_te_router,
       show_ip_ospf_mpls_te_router_cmd,
       "show ip ospf mpls-te router",
       SHOW_STR
       IP_STR
       OSPF_STR
       "MPLS-TE information\n"
       "MPLS-TE Router parameters\n")
{
	if (OspfMplsTE.enabled) {
		vty_out(vty, "--- MPLS-TE router parameters ---\n");

		if (ntohs(OspfMplsTE.router_addr.header.type) != 0)
			show_vty_router_addr(vty,
					     &OspfMplsTE.router_addr.header,
					     NULL);
		else
			vty_out(vty, "  Router address is not set\n");
		vty_out(vty, "  Link State distribution is %s\n",
			OspfMplsTE.export ? "Active" : "Inactive");
	}
	return CMD_SUCCESS;
}

static void show_mpls_te_link_sub(struct vty *vty, struct interface *ifp,
				  json_object *json)
{
	struct mpls_te_link *lp;

	if ((OspfMplsTE.enabled) && HAS_LINK_PARAMS(ifp) && !if_is_loopback(ifp)
	    && if_is_up(ifp)
	    && ((lp = lookup_linkparams_by_ifp(ifp)) != NULL)) {
		/* Continue only if interface is not passive or support Inter-AS
		 * TEv2 */
		if (!(ospf_oi_count(ifp) > 0)) {
			if (IS_INTER_AS(lp->type)) {
				vty_out(vty,
					"-- Inter-AS TEv2 link parameters for %s --\n",
					ifp->name);
			} else {
				/* MPLS-TE is not activate on this interface */
				/* or this interface is passive and Inter-AS
				 * TEv2 is not activate */
				vty_out(vty,
					"  %s: MPLS-TE is disabled on this interface\n",
					ifp->name);
				return;
			}
		} else {
			vty_out(vty, "-- MPLS-TE link parameters for %s --\n",
				ifp->name);
		}

		if (TLV_TYPE(lp->link_type) != 0)
			show_vty_link_subtlv_link_type(vty,
						       &lp->link_type.header,
						       json);
		if (TLV_TYPE(lp->link_id) != 0)
			show_vty_link_subtlv_link_id(vty, &lp->link_id.header,
						     json);
		if (TLV_TYPE(lp->lclif_ipaddr) != 0)
			show_vty_link_subtlv_lclif_ipaddr(
				vty, &lp->lclif_ipaddr.header,
				lp->lclif_ipaddr.header.length,
				json);
		if (TLV_TYPE(lp->rmtif_ipaddr) != 0)
			show_vty_link_subtlv_rmtif_ipaddr(
				vty, &lp->rmtif_ipaddr.header,
				lp->rmtif_ipaddr.header.length,
				json);
		if (TLV_TYPE(lp->rip) != 0)
			show_vty_link_subtlv_rip(vty, &lp->rip.header, json);
		if (TLV_TYPE(lp->ras) != 0)
			show_vty_link_subtlv_ras(vty, &lp->ras.header, json);
		if (TLV_TYPE(lp->te_metric) != 0)
			show_vty_link_subtlv_te_metric(vty,
						       &lp->te_metric.header,
						       json);
		if (TLV_TYPE(lp->max_bw) != 0)
			show_vty_link_subtlv_max_bw(vty, &lp->max_bw.header,
						    json);
		if (TLV_TYPE(lp->max_rsv_bw) != 0)
			show_vty_link_subtlv_max_rsv_bw(vty,
							&lp->max_rsv_bw.header,
							json);
		if (TLV_TYPE(lp->unrsv_bw) != 0)
			show_vty_link_subtlv_unrsv_bw(vty,
						      &lp->unrsv_bw.header,
						      json);
		if (TLV_TYPE(lp->rsc_clsclr) != 0)
			show_vty_link_subtlv_rsc_clsclr(vty,
							&lp->rsc_clsclr.header,
							json);
		if (TLV_TYPE(lp->av_delay) != 0)
			show_vty_link_subtlv_av_delay(vty,
						      &lp->av_delay.header,
						      json);
		if (TLV_TYPE(lp->mm_delay) != 0)
			show_vty_link_subtlv_mm_delay(vty,
						      &lp->mm_delay.header,
						      json);
		if (TLV_TYPE(lp->delay_var) != 0)
			show_vty_link_subtlv_delay_var(vty,
						       &lp->delay_var.header,
						       json);
		if (TLV_TYPE(lp->pkt_loss) != 0)
			show_vty_link_subtlv_pkt_loss(vty,
						      &lp->pkt_loss.header,
						      json);
		if (TLV_TYPE(lp->res_bw) != 0)
			show_vty_link_subtlv_res_bw(vty, &lp->res_bw.header,
						    json);
		if (TLV_TYPE(lp->ava_bw) != 0)
			show_vty_link_subtlv_ava_bw(vty, &lp->ava_bw.header,
						    json);
		if (TLV_TYPE(lp->use_bw) != 0)
			show_vty_link_subtlv_use_bw(vty, &lp->use_bw.header,
						    json);
		vty_out(vty, "---------------\n\n");
	} else {
		vty_out(vty, "  %s: MPLS-TE is disabled on this interface\n",
			ifp->name);
	}

	return;
}

DEFUN (show_ip_ospf_mpls_te_link,
       show_ip_ospf_mpls_te_link_cmd,
       "show ip ospf mpls-te interface [INTERFACE]",
       SHOW_STR
       IP_STR
       OSPF_STR
       "MPLS-TE information\n"
       "Interface information\n"
       "Interface name\n")
{
	struct vrf *vrf;
	int idx_interface = 0;
	struct interface *ifp = NULL;
	struct ospf *ospf = NULL;

	argv_find(argv, argc, "INTERFACE", &idx_interface);
	ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	if (ospf == NULL || !ospf->oi_running)
		return CMD_SUCCESS;
	vrf = vrf_lookup_by_id(VRF_DEFAULT);
	if (!vrf)
		return CMD_SUCCESS;
	if (idx_interface) {
		ifp = if_lookup_by_name(argv[idx_interface]->arg, VRF_DEFAULT);
		if (ifp == NULL) {
			vty_out(vty, "No such interface name in vrf %s\n",
				vrf->name);
			return CMD_SUCCESS;
		}
	}
	if (!ifp) {
		FOR_ALL_INTERFACES (vrf, ifp)
			show_mpls_te_link_sub(vty, ifp, NULL);
		return CMD_SUCCESS;
	}

	show_mpls_te_link_sub(vty, ifp, NULL);
	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_mpls_te_db,
       show_ip_ospf_mpls_te_db_cmd,
       "show ip ospf mpls-te database [<vertex [<self-originate|adv-router A.B.C.D>]|edge [A.B.C.D]|subnet [A.B.C.D/M]>] [verbose|json]",
       SHOW_STR
       IP_STR
       OSPF_STR
       "MPLS-TE information\n"
       "MPLS-TE database\n"
       "MPLS-TE Vertex\n"
       "Self-originated MPLS-TE router\n"
       "Advertised MPLS-TE router\n"
       "MPLS-TE router ID (as an IP address)\n"
       "MPLS-TE Edge\n"
       "MPLS-TE Edge ID (as an IP address)\n"
       "MPLS-TE Subnet\n"
       "MPLS-TE Subnet ID (as an IP prefix)\n"
       "Verbose output\n"
       JSON_STR)
{
	int idx = 0;
	struct in_addr ip_addr;
	struct prefix pref;
	struct ls_vertex *vertex;
	struct ls_edge *edge;
	struct ls_subnet *subnet;
	uint64_t key;
	struct ls_edge_key ekey;
	bool verbose = false;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	if (!OspfMplsTE.enabled || !OspfMplsTE.ted) {
		vty_out(vty, "MPLS-TE database is not enabled\n");
		return CMD_WARNING;
	}

	if (uj)
		json = json_object_new_object();

	if (argv[argc - 1]->arg && strmatch(argv[argc - 1]->text, "verbose"))
		verbose = true;

	idx = 5;
	if (argv_find(argv, argc, "vertex", &idx)) {
		/* Show Vertex */
		if (argv_find(argv, argc, "self-originate", &idx))
			vertex = OspfMplsTE.ted->self;
		else if (argv_find(argv, argc, "adv-router", &idx)) {
			if (!inet_aton(argv[idx + 1]->arg, &ip_addr)) {
				vty_out(vty,
					"Specified Router ID %s is invalid\n",
					argv[idx + 1]->arg);
				return CMD_WARNING_CONFIG_FAILED;
			}
			/* Get the Vertex from the Link State Database */
			key = ((uint64_t)ntohl(ip_addr.s_addr)) & 0xffffffff;
			vertex = ls_find_vertex_by_key(OspfMplsTE.ted, key);
			if (!vertex) {
				vty_out(vty, "No vertex found for ID %pI4\n",
					&ip_addr);
				return CMD_WARNING;
			}
		} else
			vertex = NULL;

		if (vertex)
			ls_show_vertex(vertex, vty, json, verbose);
		else
			ls_show_vertices(OspfMplsTE.ted, vty, json, verbose);

	} else if (argv_find(argv, argc, "edge", &idx)) {
		/* Show Edge */
		if (argv_find(argv, argc, "A.B.C.D", &idx)) {
			if (!inet_aton(argv[idx]->arg, &ip_addr)) {
				vty_out(vty,
					"Specified Edge ID %s is invalid\n",
					argv[idx]->arg);
				return CMD_WARNING_CONFIG_FAILED;
			}
			/* Get the Edge from the Link State Database */
			ekey.family = AF_INET;
			IPV4_ADDR_COPY(&ekey.k.addr, &ip_addr);
			edge = ls_find_edge_by_key(OspfMplsTE.ted, ekey);
			if (!edge) {
				vty_out(vty, "No edge found for ID %pI4\n",
					&ip_addr);
				return CMD_WARNING;
			}
		} else
			edge = NULL;

		if (edge)
			ls_show_edge(edge, vty, json, verbose);
		else
			ls_show_edges(OspfMplsTE.ted, vty, json, verbose);

	} else if (argv_find(argv, argc, "subnet", &idx)) {
		/* Show Subnet */
		if (argv_find(argv, argc, "A.B.C.D/M", &idx)) {
			if (!str2prefix(argv[idx]->arg, &pref)) {
				vty_out(vty, "Invalid prefix format %s\n",
					argv[idx]->arg);
				return CMD_WARNING_CONFIG_FAILED;
			}
			/* Get the Subnet from the Link State Database */
			subnet = ls_find_subnet(OspfMplsTE.ted, &pref);
			if (!subnet) {
				vty_out(vty, "No subnet found for ID %pFX\n",
					&pref);
				return CMD_WARNING;
			}
		} else
			subnet = NULL;

		if (subnet)
			ls_show_subnet(subnet, vty, json, verbose);
		else
			ls_show_subnets(OspfMplsTE.ted, vty, json, verbose);

	} else {
		/* Show the complete TED */
		ls_show_ted(OspfMplsTE.ted, vty, json, verbose);
	}

	if (uj)
		vty_json(vty, json);
	return CMD_SUCCESS;
}

static void ospf_mpls_te_register_vty(void)
{
	install_element(VIEW_NODE, &show_ip_ospf_mpls_te_router_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_mpls_te_link_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_mpls_te_db_cmd);

	install_element(OSPF_NODE, &ospf_mpls_te_on_cmd);
	install_element(OSPF_NODE, &no_ospf_mpls_te_cmd);
	install_element(OSPF_NODE, &ospf_mpls_te_router_addr_cmd);
	install_element(OSPF_NODE, &ospf_mpls_te_inter_as_cmd);
	install_element(OSPF_NODE, &ospf_mpls_te_inter_as_area_cmd);
	install_element(OSPF_NODE, &no_ospf_mpls_te_inter_as_cmd);
	install_element(OSPF_NODE, &ospf_mpls_te_export_cmd);
	install_element(OSPF_NODE, &no_ospf_mpls_te_export_cmd);

	return;
}
