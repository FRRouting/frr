/*
 * This is an implementation of RFC3630
 * Copyright (C) 2001 KDD R&D Laboratories, Inc.
 * http://www.kddlabs.co.jp/
 *
 * Copyright (C) 2012 Orange Labs
 * http://www.orange.com
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "thread.h"
#include "hash.h"
#include "sockunion.h" /* for inet_aton() */
#include "network.h"

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
#include "ospfd/ospf_vty.h"

/*
 * Global variable to manage Opaque-LSA/MPLS-TE on this node.
 * Note that all parameter values are stored in network byte order.
 */
struct ospf_mpls_te OspfMplsTE;

const char *mode2text[] = {"Off", "AS", "Area"};

/*------------------------------------------------------------------------*
 * Followings are initialize/terminate functions for MPLS-TE handling.
 *------------------------------------------------------------------------*/

static int ospf_mpls_te_new_if(struct interface *ifp);
static int ospf_mpls_te_del_if(struct interface *ifp);
static void ospf_mpls_te_ism_change(struct ospf_interface *oi, int old_status);
static void ospf_mpls_te_nsm_change(struct ospf_neighbor *nbr, int old_status);
static void ospf_mpls_te_config_write_router(struct vty *vty);
static void ospf_mpls_te_show_info(struct vty *vty, struct ospf_lsa *lsa);
static int ospf_mpls_te_lsa_originate_area(void *arg);
static int ospf_mpls_te_lsa_originate_as(void *arg);
static struct ospf_lsa *ospf_mpls_te_lsa_refresh(struct ospf_lsa *lsa);

static void del_mpls_te_link(void *val);
static void ospf_mpls_te_register_vty(void);

int ospf_mpls_te_init(void)
{
	int rc;

	rc = ospf_register_opaque_functab(
		OSPF_OPAQUE_AREA_LSA, OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA,
		ospf_mpls_te_new_if, ospf_mpls_te_del_if,
		ospf_mpls_te_ism_change, ospf_mpls_te_nsm_change,
		ospf_mpls_te_config_write_router,
		NULL, /*ospf_mpls_te_config_write_if */
		NULL, /* ospf_mpls_te_config_write_debug */
		ospf_mpls_te_show_info, ospf_mpls_te_lsa_originate_area,
		ospf_mpls_te_lsa_refresh, NULL, /* ospf_mpls_te_new_lsa_hook */
		NULL /* ospf_mpls_te_del_lsa_hook */);
	if (rc != 0) {
		zlog_warn(
			"ospf_mpls_te_init: Failed to register Traffic Engineering functions");
		return rc;
	}

	memset(&OspfMplsTE, 0, sizeof(struct ospf_mpls_te));
	OspfMplsTE.enabled = false;
	OspfMplsTE.inter_as = Off;
	OspfMplsTE.iflist = list_new();
	OspfMplsTE.iflist->del = del_mpls_te_link;

	ospf_mpls_te_register_vty();

	return rc;
}

/* Additional register for RFC5392 support */
static int ospf_mpls_te_register(enum inter_as_mode mode)
{
	int rc = 0;
	u_int8_t scope;

	if (OspfMplsTE.inter_as != Off)
		return rc;

	if (mode == AS)
		scope = OSPF_OPAQUE_AS_LSA;
	else
		scope = OSPF_OPAQUE_AREA_LSA;

	rc = ospf_register_opaque_functab(scope, OPAQUE_TYPE_INTER_AS_LSA, NULL,
					  NULL, NULL, NULL, NULL, NULL, NULL,
					  ospf_mpls_te_show_info,
					  ospf_mpls_te_lsa_originate_as,
					  ospf_mpls_te_lsa_refresh, NULL, NULL);

	if (rc != 0) {
		zlog_warn(
			"ospf_router_info_init: Failed to register Inter-AS functions");
		return rc;
	}

	return rc;
}

static int ospf_mpls_te_unregister()
{
	u_int8_t scope;

	if (OspfMplsTE.inter_as == Off)
		return 0;

	if (OspfMplsTE.inter_as == AS)
		scope = OSPF_OPAQUE_AS_LSA;
	else
		scope = OSPF_OPAQUE_AREA_LSA;

	ospf_delete_opaque_functab(scope, OPAQUE_TYPE_INTER_AS_LSA);

	return 0;
}

void ospf_mpls_te_term(void)
{
	list_delete_and_null(&OspfMplsTE.iflist);

	ospf_delete_opaque_functab(OSPF_OPAQUE_AREA_LSA,
				   OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA);

	OspfMplsTE.enabled = false;

	ospf_mpls_te_unregister();
	OspfMplsTE.inter_as = Off;

	return;
}

void ospf_mpls_te_finish(void)
{
	// list_delete_all_node(OspfMplsTE.iflist);

	OspfMplsTE.enabled = false;
	OspfMplsTE.inter_as = Off;
}

/*------------------------------------------------------------------------*
 * Followings are control functions for MPLS-TE parameters management.
 *------------------------------------------------------------------------*/

static void del_mpls_te_link(void *val)
{
	XFREE(MTYPE_OSPF_MPLS_TE, val);
	return;
}

static u_int32_t get_mpls_te_instance_value(void)
{
	static u_int32_t seqno = 0;

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

	zlog_warn("lookup_linkparams_by_instance: Entry not found: key(%x)",
		  key);
	return NULL;
}

static void ospf_mpls_te_foreach_area(void (*func)(struct mpls_te_link *lp,
					enum lsa_opcode sched_opcode),
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
	u_int16_t length = 0;

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

static void set_linkparams_link_id(struct ospf_interface *oi,
				   struct mpls_te_link *lp)
{
	struct ospf_neighbor *nbr;
	int done = 0;

	lp->link_id.header.type = htons(TE_LINK_SUBTLV_LINK_ID);
	lp->link_id.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);

	/*
	 * The Link ID is identical to the contents of the Link ID field
	 * in the Router LSA for these link types.
	 */
	switch (oi->type) {
	case OSPF_IFTYPE_POINTOPOINT:
		/* Take the router ID of the neighbor. */
		if ((nbr = ospf_nbr_lookup_ptop(oi))
		    && nbr->state == NSM_Full) {
			lp->link_id.value = nbr->router_id;
			done = 1;
		}
		break;
	case OSPF_IFTYPE_BROADCAST:
	case OSPF_IFTYPE_NBMA:
		/* Take the interface address of the designated router. */
		if ((nbr = ospf_nbr_lookup_by_addr(oi->nbrs, &DR(oi))) == NULL)
			break;

		if (nbr->state == NSM_Full
		    || (IPV4_ADDR_SAME(&oi->address->u.prefix4, &DR(oi))
			&& ospf_nbr_count(oi, NSM_Full) > 0)) {
			lp->link_id.value = DR(oi);
			done = 1;
		}
		break;
	default:
		/* Not supported yet. */ /* XXX */
		lp->link_id.header.type = htons(0);
		break;
	}

	if (!done) {
		struct in_addr mask;
		masklen2ip(oi->address->prefixlen, &mask);
		lp->link_id.value.s_addr =
			oi->address->u.prefix4.s_addr & mask.s_addr;
	}
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
				     u_int32_t te_metric)
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
				      u_int32_t classcolor)
{
	lp->rsc_clsclr.header.type = htons(TE_LINK_SUBTLV_RSC_CLSCLR);
	lp->rsc_clsclr.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	lp->rsc_clsclr.value = htonl(classcolor);
	return;
}

static void set_linkparams_inter_as(struct mpls_te_link *lp,
				    struct in_addr addr, u_int32_t as)
{

	/* Set the Remote ASBR IP address and then the associated AS number */
	lp->rip.header.type = htons(TE_LINK_SUBTLV_RIP);
	lp->rip.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	lp->rip.value = addr;

	lp->ras.header.type = htons(TE_LINK_SUBTLV_RAS);
	lp->ras.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	lp->ras.value = htonl(as);
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
}

void set_linkparams_llri(struct mpls_te_link *lp, u_int32_t local,
			 u_int32_t remote)
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

static void set_linkparams_av_delay(struct mpls_te_link *lp, u_int32_t delay,
				    u_char anormal)
{
	u_int32_t tmp;
	/* Note that TLV-length field is the size of array. */
	lp->av_delay.header.type = htons(TE_LINK_SUBTLV_AV_DELAY);
	lp->av_delay.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	tmp = delay & TE_EXT_MASK;
	if (anormal)
		tmp |= TE_EXT_ANORMAL;
	lp->av_delay.value = htonl(tmp);
	return;
}

static void set_linkparams_mm_delay(struct mpls_te_link *lp, u_int32_t low,
				    u_int32_t high, u_char anormal)
{
	u_int32_t tmp;
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

static void set_linkparams_delay_var(struct mpls_te_link *lp, u_int32_t jitter)
{
	/* Note that TLV-length field is the size of array. */
	lp->delay_var.header.type = htons(TE_LINK_SUBTLV_DELAY_VAR);
	lp->delay_var.header.length = htons(TE_LINK_SUBTLV_DEF_SIZE);
	lp->delay_var.value = htonl(jitter & TE_EXT_MASK);
	return;
}

static void set_linkparams_pkt_loss(struct mpls_te_link *lp, u_int32_t loss,
				    u_char anormal)
{
	u_int32_t tmp;
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
		if (IS_DEBUG_OSPF_TE)
			zlog_debug(
				"OSPF MPLS-TE: Abort update TE parameters: no interface associated to Link Parameters");
		return;
	}
	if (!HAS_LINK_PARAMS(ifp)) {
		if (IS_DEBUG_OSPF_TE)
			zlog_debug(
				"OSPF MPLS-TE: Abort update TE parameters: no Link Parameters for interface");
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
			if (IS_DEBUG_OSPF_TE)
				zlog_debug(
					"OSPF MPLS-TE Update IF: Switch from Standard LSA to INTER-AS for %s[%d/%d]",
					ifp->name, lp->flags, lp->type);

			ospf_mpls_te_lsa_schedule(lp, FLUSH_THIS_LSA);
			/* Then, switch it to INTER-AS */
			if (OspfMplsTE.inter_as == AS)
				lp->flags = INTER_AS | FLOOD_AS;
			else {
				lp->flags = INTER_AS | FLOOD_AREA;
				lp->area = ospf_area_lookup_by_area_id(
					ospf_lookup_by_vrf_id(VRF_DEFAULT),
					OspfMplsTE.interas_areaid);
			}
		}
		set_linkparams_inter_as(lp, ifp->link_params->rmt_ip,
					ifp->link_params->rmt_as);
	} else {
		if (IS_DEBUG_OSPF_TE)
			zlog_debug(
				"OSPF MPLS-TE Update IF: Switch from INTER-AS LSA to Standard for %s[%d/%d]",
				ifp->name, lp->flags, lp->type);

		/* reset inter-as TE params */
		/* Flush LSA if it engaged and was previously an INTER_AS one */
		if (IS_INTER_AS(lp->type)
		    && CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED)) {
			ospf_mpls_te_lsa_schedule(lp, FLUSH_THIS_LSA);
			/* Then, switch it to Standard TE */
			lp->flags = STD_TE | FLOOD_AREA;
		}
		unset_linkparams_inter_as(lp);
	}
}

static void initialize_linkparams(struct mpls_te_link *lp)
{
	struct interface *ifp = lp->ifp;
	struct ospf_interface *oi = NULL;
	struct route_node *rn;

	if (IS_DEBUG_OSPF_TE)
		zlog_debug(
			"MPLS-TE(initialize_linkparams) Initialize Link Parameters for interface %s",
			ifp->name);

	/* Search OSPF Interface parameters for this interface */
	for (rn = route_top (IF_OIFS (ifp)); rn; rn = route_next (rn)) {

		if ((oi = rn->info) == NULL)
			continue;

		if (oi->ifp == ifp)
			break;
	}

	if ((oi == NULL) || (oi->ifp != ifp)) {
		if (IS_DEBUG_OSPF_TE)
			zlog_warn(
				"MPLS-TE(initialize_linkparams) Could not find corresponding OSPF Interface for %s",
				ifp->name);
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
		zlog_warn(
			"MPLS-TE(is_mandated_params_set) Missing Router Address");
		return rc;
	}

	if (ntohs(lp->link_type.header.type) == 0) {
		zlog_warn("MPLS-TE(is_mandated_params_set) Missing Link Type");
		return rc;
	}

	if (!IS_INTER_AS(lp->type) && (ntohs(lp->link_id.header.type) == 0)) {
		zlog_warn("MPLS-TE(is_mandated_params_set) Missing Link ID");
		return rc;
	}

	rc = 1;
	return rc;
}

/*------------------------------------------------------------------------*
 * Followings are callback functions against generic Opaque-LSAs handling.
 *------------------------------------------------------------------------*/

static int ospf_mpls_te_new_if(struct interface *ifp)
{
	struct mpls_te_link *new;
	int rc = -1;

	if (IS_DEBUG_OSPF_TE)
		zlog_debug(
			"MPLS-TE(ospf_mpls_te_new_if) Add new %s interface %s to MPLS-TE list",
			ifp->link_params ? "Active" : "Inactive", ifp->name);

	if (lookup_linkparams_by_ifp(ifp) != NULL) {
		zlog_warn("ospf_mpls_te_new_if: ifp(%p) already in use?",
			  (void *)ifp);
		rc = 0; /* Do nothing here. */
		return rc;
	}

	new = XCALLOC(MTYPE_OSPF_MPLS_TE, sizeof(struct mpls_te_link));
	if (new == NULL) {
		zlog_warn("ospf_mpls_te_new_if: XMALLOC: %s",
			  safe_strerror(errno));
		return rc;
	}

	new->instance = get_mpls_te_instance_value();
	new->ifp = ifp;
	/* By default TE-Link is RFC3630 compatible flooding in Area and not
	 * active */
	/* This default behavior will be adapted with call to
	 * ospf_mpls_te_update_if() */
	new->type = STD_TE | FLOOD_AREA;
	new->flags = LPFLG_LSA_INACTIVE;

	/* Initialize Link Parameters from Interface */
	initialize_linkparams(new);

	/* Set TE Parameters from Interface */
	update_linkparams(new);

	/* Add Link Parameters structure to the list */
	listnode_add(OspfMplsTE.iflist, new);

	if (IS_DEBUG_OSPF_TE)
		zlog_debug(
			"OSPF MPLS-TE New IF: Add new LP context for %s[%d/%d]",
			ifp->name, new->flags, new->type);

	/* Schedule Opaque-LSA refresh. */ /* XXX */

	rc = 0;
	return rc;
}

static int ospf_mpls_te_del_if(struct interface *ifp)
{
	struct mpls_te_link *lp;
	int rc = -1;

	if ((lp = lookup_linkparams_by_ifp(ifp)) != NULL) {
		struct list *iflist = OspfMplsTE.iflist;

		/* Dequeue listnode entry from the list. */
		listnode_delete(iflist, lp);

		/* Avoid misjudgement in the next lookup. */
		if (listcount(iflist) == 0)
			iflist->head = iflist->tail = NULL;

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

	if (IS_DEBUG_OSPF_TE)
		zlog_debug(
			"OSPF MPLS-TE: Update LSA parameters for interface %s [%s]",
			ifp->name, HAS_LINK_PARAMS(ifp) ? "ON" : "OFF");

	/* Get Link context from interface */
	if ((lp = lookup_linkparams_by_ifp(ifp)) == NULL) {
		zlog_warn(
			"OSPF MPLS-TE Update: Did not find Link Parameters context for interface %s",
			ifp->name);
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
					ospf_mpls_te_lsa_schedule(lp, REFRESH_THIS_LSA);
				else
					ospf_mpls_te_lsa_schedule(lp, REORIGINATE_THIS_LSA);
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

static void ospf_mpls_te_ism_change(struct ospf_interface *oi, int old_state)
{
	struct te_link_subtlv_link_type old_type;
	struct te_link_subtlv_link_id old_id;
	struct mpls_te_link *lp;

	if ((lp = lookup_linkparams_by_ifp(oi->ifp)) == NULL) {
		zlog_warn(
			"ospf_mpls_te_ism_change: Cannot get linkparams from OI(%s)?",
			IF_NAME(oi));
		return;
	}

	if (oi->area == NULL || oi->area->ospf == NULL) {
		zlog_warn(
			"ospf_mpls_te_ism_change: Cannot refer to OSPF from OI(%s)?",
			IF_NAME(oi));
		return;
	}
#ifdef notyet
	if ((lp->area != NULL
	     && !IPV4_ADDR_SAME(&lp->area->area_id, &oi->area->area_id))
	    || (lp->area != NULL && oi->area == NULL)) {
		/* How should we consider this case? */
		zlog_warn(
			"MPLS-TE: Area for OI(%s) has changed to [%s], flush previous LSAs",
			IF_NAME(oi),
			oi->area ? inet_ntoa(oi->area->area_id) : "N/A");
		ospf_mpls_te_lsa_schedule(lp, FLUSH_THIS_LSA);
	}
#endif
	/* Keep Area information in combination with linkparams. */
	lp->area = oi->area;

	/* Keep interface MPLS-TE status */
	lp->flags = HAS_LINK_PARAMS(oi->ifp);

	switch (oi->state) {
	case ISM_PointToPoint:
	case ISM_DROther:
	case ISM_Backup:
	case ISM_DR:
		old_type = lp->link_type;
		old_id = lp->link_id;

		/* Set Link type, Link ID, Local and Remote IP addr */
		set_linkparams_link_type(oi, lp);
		set_linkparams_link_id(oi, lp);
		set_linkparams_lclif_ipaddr(lp, oi->address->u.prefix4);

		if (oi->type == LINK_TYPE_SUBTLV_VALUE_PTP) {
			struct prefix *pref = CONNECTED_PREFIX(oi->connected);
			if (pref != NULL)
				set_linkparams_rmtif_ipaddr(lp,
							    pref->u.prefix4);
		}

		/* Update TE parameters */
		update_linkparams(lp);

		/* Try to Schedule LSA */
		if ((ntohs(old_type.header.type)
			     != ntohs(lp->link_type.header.type)
		     || old_type.link_type.value
				!= lp->link_type.link_type.value)
		    || (ntohs(old_id.header.type)
				!= ntohs(lp->link_id.header.type)
			|| ntohl(old_id.value.s_addr)
				   != ntohl(lp->link_id.value.s_addr))) {
			if (CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED))
				ospf_mpls_te_lsa_schedule(lp, REFRESH_THIS_LSA);
			else
				ospf_mpls_te_lsa_schedule(lp, REORIGINATE_THIS_LSA);
		}
		break;
	default:
		lp->link_type.header.type = htons(0);
		lp->link_id.header.type = htons(0);

		if (CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED))
			ospf_mpls_te_lsa_schedule(lp, FLUSH_THIS_LSA);
		break;
	}

	return;
}

static void ospf_mpls_te_nsm_change(struct ospf_neighbor *nbr, int old_state)
{
	/* Nothing to do here */
	return;
}

/*------------------------------------------------------------------------*
 * Followings are OSPF protocol processing functions for MPLS-TE.
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
	 * The router address TLV is type 1, and ...
	 *                                      It must appear in exactly one
	 * Traffic Engineering LSA originated by a router.
	 */
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
	u_char options, lsa_type = 0;
	struct in_addr lsa_id;
	u_int32_t tmp;
	u_int16_t length;

	/* Create a stream for LSA. */
	if ((s = stream_new(OSPF_MAX_LSA_SIZE)) == NULL) {
		zlog_warn("ospf_mpls_te_lsa_new: stream_new() ?");
		return NULL;
	}
	lsah = (struct lsa_header *)STREAM_DATA(s);

	options = OSPF_OPTION_O; /* Don't forget this :-) */

	/* Set opaque-LSA header fields depending of the type of RFC */
	if (IS_INTER_AS(lp->type)) {
		if
			IS_FLOOD_AS(lp->type)
			{
				options |= OSPF_OPTION_E; /* Enable AS external
							     as we flood
							     Inter-AS with
							     Opaque Type 11 */
				lsa_type = OSPF_OPAQUE_AS_LSA;
			}
		else {
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

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE))
		zlog_debug(
			"LSA[Type%d:%s]: Create an Opaque-LSA/MPLS-TE instance",
			lsa_type, inet_ntoa(lsa_id));

	/* Set opaque-LSA body fields. */
	ospf_mpls_te_lsa_body_set(s, lp);

	/* Set length. */
	length = stream_get_endp(s);
	lsah->length = htons(length);

	/* Now, create an OSPF LSA instance. */
	if ((new = ospf_lsa_new()) == NULL) {
		zlog_warn("ospf_mpls_te_lsa_new: ospf_lsa_new() ?");
		stream_free(s);
		return NULL;
	}
	if ((new->data = ospf_lsa_data_new(length)) == NULL) {
		zlog_warn("ospf_mpls_te_lsa_new: ospf_lsa_data_new() ?");
		ospf_lsa_unlock(&new);
		new = NULL;
		stream_free(s);
		return new;
	}

	new->vrf_id = ospf->vrf_id;
	if (area && area->ospf)
		new->vrf_id = area->ospf->vrf_id;
	new->area = area;
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
		zlog_warn(
			"ospf_mpls_te_lsa_originate1: ospf_mpls_te_lsa_new() ?");
		return rc;
	}

	/* Install this LSA into LSDB. */
	if (ospf_lsa_install(area->ospf, NULL /*oi*/, new) == NULL) {
		zlog_warn("ospf_mpls_te_lsa_originate1: ospf_lsa_install() ?");
		ospf_lsa_unlock(&new);
		return rc;
	}

	/* Now this link-parameter entry has associated LSA. */
	SET_FLAG(lp->flags, LPFLG_LSA_ENGAGED);
	/* Update new LSA origination count. */
	area->ospf->lsa_originate_count++;

	/* Flood new LSA through area. */
	ospf_flood_through_area(area, NULL /*nbr*/, new);

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE)) {
		char area_id[INET_ADDRSTRLEN];
		strlcpy(area_id, inet_ntoa(area->area_id), sizeof(area_id));
		zlog_debug(
			"LSA[Type%d:%s]: Originate Opaque-LSA/MPLS-TE: Area(%s), Link(%s)",
			new->data->type, inet_ntoa(new->data->id), area_id,
			lp->ifp->name);
		ospf_lsa_header_dump(new->data);
	}

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
		zlog_info(
			"ospf_mpls_te_lsa_originate_area: MPLS-TE is disabled now.");
		rc = 0; /* This is not an error case. */
		return rc;
	}

	for (ALL_LIST_ELEMENTS(OspfMplsTE.iflist, node, nnode, lp)) {
		/* Process only enabled LSA with area scope flooding */
		if (!CHECK_FLAG(lp->flags, LPFLG_LSA_ACTIVE)
		    || IS_FLOOD_AS(lp->type))
			continue;

		if (lp->area == NULL)
			continue;

		if (!IPV4_ADDR_SAME(&lp->area->area_id, &area->area_id))
			continue;

		if (CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED)) {
			if (CHECK_FLAG(lp->flags, LPFLG_LSA_FORCED_REFRESH)) {
				UNSET_FLAG(lp->flags, LPFLG_LSA_FORCED_REFRESH);
				zlog_warn(
					"OSPF MPLS-TE (ospf_mpls_te_lsa_originate_area): Refresh instead of Originate");
				ospf_mpls_te_lsa_schedule(lp, REFRESH_THIS_LSA);
			}
			continue;
		}

		if (!is_mandated_params_set(lp)) {
			zlog_warn(
				"ospf_mpls_te_lsa_originate_area: Link(%s) lacks some mandated MPLS-TE parameters.",
				lp->ifp ? lp->ifp->name : "?");
			continue;
		}

		/* Ok, let's try to originate an LSA for this area and Link. */
		if (IS_DEBUG_OSPF_TE)
			zlog_debug(
				"MPLS-TE(ospf_mpls_te_lsa_originate_area) Let's finally reoriginate the LSA %d through the Area %s for Link %s",
				lp->instance, inet_ntoa(area->area_id),
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
		zlog_warn(
			"ospf_mpls_te_lsa_originate2: ospf_router_info_lsa_new() ?");
		return rc;
	}
	new->vrf_id = top->vrf_id;

	/* Install this LSA into LSDB. */
	if (ospf_lsa_install(top, NULL /*oi */, new) == NULL) {
		zlog_warn("ospf_mpls_te_lsa_originate2: ospf_lsa_install() ?");
		ospf_lsa_unlock(&new);
		return rc;
	}

	/* Now this Router Info parameter entry has associated LSA. */
	SET_FLAG(lp->flags, LPFLG_LSA_ENGAGED);
	/* Update new LSA origination count. */
	top->lsa_originate_count++;

	/* Flood new LSA through AS. */
	ospf_flood_through_as(top, NULL /*nbr */, new);

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE)) {
		zlog_debug(
			"LSA[Type%d:%s]: Originate Opaque-LSA/MPLS-TE Inter-AS",
			new->data->type, inet_ntoa(new->data->id));
		ospf_lsa_header_dump(new->data);
	}

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

	if ((!OspfMplsTE.enabled)
	    || (OspfMplsTE.inter_as == Off)) {
		zlog_info(
			"ospf_mpls_te_lsa_originate_as: MPLS-TE Inter-AS is disabled for now.");
		rc = 0; /* This is not an error case. */
		return rc;
	}

	for (ALL_LIST_ELEMENTS(OspfMplsTE.iflist, node, nnode, lp)) {
		/* Process only enabled INTER_AS Links or Pseudo-Links */
		if (!CHECK_FLAG(lp->flags, LPFLG_LSA_ACTIVE)
		    || !IS_INTER_AS(lp->type))
			continue;

		if (CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED)) {
			if (CHECK_FLAG(lp->flags, LPFLG_LSA_FORCED_REFRESH)) {
				UNSET_FLAG(lp->flags,LPFLG_LSA_FORCED_REFRESH);
				ospf_mpls_te_lsa_schedule(lp, REFRESH_THIS_LSA);
			}
			continue;
		}

		if (!is_mandated_params_set(lp)) {
			zlog_warn(
				"ospf_mpls_te_lsa_originate_as: Link(%s) lacks some mandated MPLS-TE parameters.",
				lp->ifp ? lp->ifp->name : "?");
			continue;
		}

		/* Ok, let's try to originate an LSA for this AS and Link. */
		if (IS_DEBUG_OSPF_TE)
			zlog_debug(
				"MPLS-TE(ospf_mpls_te_lsa_originate_as) Let's finally re-originate the Inter-AS LSA %d through the %s for Link %s",
				lp->instance,
				IS_FLOOD_AS(lp->type) ? "AS" : "Area",
				lp->ifp ? lp->ifp->name : "Unknown");

		if (IS_FLOOD_AS(lp->type)) {
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
		zlog_info("ospf_mpls_te_lsa_refresh: MPLS-TE is disabled now.");
		lsa->data->ls_age =
			htons(OSPF_LSA_MAXAGE); /* Flush it anyway. */
	}

	/* At first, resolve lsa/lp relationship. */
	if ((lp = lookup_linkparams_by_instance(lsa)) == NULL) {
		zlog_warn("ospf_mpls_te_lsa_refresh: Invalid parameter?");
		lsa->data->ls_age =
			htons(OSPF_LSA_MAXAGE); /* Flush it anyway. */
	}

	/* Check if lp was not disable in the interval */
	if (!CHECK_FLAG(lp->flags, LPFLG_LSA_ACTIVE)) {
		zlog_warn(
			"ospf_mpls_te_lsa_refresh: lp was disabled: Flush it!");
		lsa->data->ls_age =
			htons(OSPF_LSA_MAXAGE); /* Flush it anyway. */
	}

	/* If the lsa's age reached to MaxAge, start flushing procedure. */
	if (IS_LSA_MAXAGE(lsa)) {
		if (lp)
			UNSET_FLAG(lp->flags, LPFLG_LSA_ENGAGED);
		ospf_opaque_lsa_flush_schedule(lsa);
		return NULL;
	}
	top = ospf_lookup_by_vrf_id(lsa->vrf_id);
	/* Create new Opaque-LSA/MPLS-TE instance. */
	new = ospf_mpls_te_lsa_new(top, area, lp);
	if (new == NULL) {
		zlog_warn("ospf_mpls_te_lsa_refresh: ospf_mpls_te_lsa_new() ?");
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
		zlog_warn("ospf_mpls_te_lsa_refresh: ospf_lsa_install() ?");
		ospf_lsa_unlock(&new);
		return NULL;
	}

	/* Flood updated LSA through AS or Area depending of the RFC of the link
	 */
	if (IS_FLOOD_AS(lp->type))
		ospf_flood_through_as(top, NULL, new);
	else
		ospf_flood_through_area(area, NULL /*nbr*/, new);

	/* Debug logging. */
	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE)) {
		zlog_debug("LSA[Type%d:%s]: Refresh Opaque-LSA/MPLS-TE",
			   new->data->type, inet_ntoa(new->data->id));
		ospf_lsa_header_dump(new->data);
	}

	return new;
}

void ospf_mpls_te_lsa_schedule(struct mpls_te_link *lp, enum lsa_opcode opcode)
{
	struct ospf_lsa lsa;
	struct lsa_header lsah;
	struct ospf *top;
	u_int32_t tmp;

	memset(&lsa, 0, sizeof(lsa));
	memset(&lsah, 0, sizeof(lsah));
	top = ospf_lookup_by_vrf_id(VRF_DEFAULT);

	/* Check if the pseudo link is ready to flood */
	if (!(CHECK_FLAG(lp->flags, LPFLG_LSA_ACTIVE))
	    || !(IS_FLOOD_AREA(lp->type) || IS_FLOOD_AS(lp->type))) {
		return;
	}

	lsa.area = lp->area;
	lsa.data = &lsah;
	if (IS_FLOOD_AS(lp->type)) {
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
				zlog_warn(
					"MPLS-TE(ospf_mpls_te_lsa_schedule) Area context is null. Abort !");
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
		if (IS_FLOOD_AS(lp->type)) {
			ospf_opaque_lsa_reoriginate_schedule(
				(void *)top, OSPF_OPAQUE_AS_LSA,
				OPAQUE_TYPE_INTER_AS_LSA);
			break;
		}

		if (IS_FLOOD_AREA(lp->type)) {
			if (IS_INTER_AS(lp->type))
				ospf_opaque_lsa_reoriginate_schedule(
					(void *)lp->area, OSPF_OPAQUE_AREA_LSA,
					OPAQUE_TYPE_INTER_AS_LSA);
			else
				ospf_opaque_lsa_reoriginate_schedule(
					(void *)lp->area, OSPF_OPAQUE_AREA_LSA,
					OPAQUE_TYPE_TRAFFIC_ENGINEERING_LSA);
			break;
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
		zlog_warn("ospf_mpls_te_lsa_schedule: Unknown opcode (%u)",
			  opcode);
		break;
	}

	return;
}


/*------------------------------------------------------------------------*
 * Followings are vty session control functions.
 *------------------------------------------------------------------------*/

static u_int16_t show_vty_router_addr(struct vty *vty,
				      struct tlv_header *tlvh)
{
	struct te_tlv_router_addr *top = (struct te_tlv_router_addr *)tlvh;

	if (vty != NULL)
		vty_out(vty, "  Router-Address: %s\n", inet_ntoa(top->value));
	else
		zlog_debug("    Router-Address: %s", inet_ntoa(top->value));

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_header(struct vty *vty,
				      struct tlv_header *tlvh)
{
	struct te_tlv_link *top = (struct te_tlv_link *)tlvh;

	if (vty != NULL)
		vty_out(vty, "  Link: %u octets of data\n",
			ntohs(top->header.length));
	else
		zlog_debug("    Link: %u octets of data",
			   ntohs(top->header.length));

	return TLV_HDR_SIZE; /* Here is special, not "TLV_SIZE". */
}

static u_int16_t show_vty_link_subtlv_link_type(struct vty *vty,
						struct tlv_header *tlvh)
{
	struct te_link_subtlv_link_type *top;
	const char *cp = "Unknown";

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
		vty_out(vty, "  Link-Type: %s (%u)\n", cp,
			top->link_type.value);
	else
		zlog_debug("    Link-Type: %s (%u)", cp, top->link_type.value);

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_link_id(struct vty *vty,
					      struct tlv_header *tlvh)
{
	struct te_link_subtlv_link_id *top;

	top = (struct te_link_subtlv_link_id *)tlvh;
	if (vty != NULL)
		vty_out(vty, "  Link-ID: %s\n", inet_ntoa(top->value));
	else
		zlog_debug("    Link-ID: %s", inet_ntoa(top->value));

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_lclif_ipaddr(struct vty *vty,
						   struct tlv_header *tlvh)
{
	struct te_link_subtlv_lclif_ipaddr *top;
	int i, n;

	top = (struct te_link_subtlv_lclif_ipaddr *)tlvh;
	n = ntohs(tlvh->length) / sizeof(top->value[0]);

	if (vty != NULL)
		vty_out(vty, "  Local Interface IP Address(es): %d\n", n);
	else
		zlog_debug("    Local Interface IP Address(es): %d", n);

	for (i = 0; i < n; i++) {
		if (vty != NULL)
			vty_out(vty, "    #%d: %s\n", i,
				inet_ntoa(top->value[i]));
		else
			zlog_debug("      #%d: %s", i,
				   inet_ntoa(top->value[i]));
	}
	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_rmtif_ipaddr(struct vty *vty,
						   struct tlv_header *tlvh)
{
	struct te_link_subtlv_rmtif_ipaddr *top;
	int i, n;

	top = (struct te_link_subtlv_rmtif_ipaddr *)tlvh;
	n = ntohs(tlvh->length) / sizeof(top->value[0]);
	if (vty != NULL)
		vty_out(vty, "  Remote Interface IP Address(es): %d\n", n);
	else
		zlog_debug("    Remote Interface IP Address(es): %d", n);

	for (i = 0; i < n; i++) {
		if (vty != NULL)
			vty_out(vty, "    #%d: %s\n", i,
				inet_ntoa(top->value[i]));
		else
			zlog_debug("      #%d: %s", i,
				   inet_ntoa(top->value[i]));
	}
	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_te_metric(struct vty *vty,
						struct tlv_header *tlvh)
{
	struct te_link_subtlv_te_metric *top;

	top = (struct te_link_subtlv_te_metric *)tlvh;
	if (vty != NULL)
		vty_out(vty, "  Traffic Engineering Metric: %u\n",
			(u_int32_t)ntohl(top->value));
	else
		zlog_debug("    Traffic Engineering Metric: %u",
			   (u_int32_t)ntohl(top->value));

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_max_bw(struct vty *vty,
					     struct tlv_header *tlvh)
{
	struct te_link_subtlv_max_bw *top;
	float fval;

	top = (struct te_link_subtlv_max_bw *)tlvh;
	fval = ntohf(top->value);

	if (vty != NULL)
		vty_out(vty, "  Maximum Bandwidth: %g (Bytes/sec)\n", fval);
	else
		zlog_debug("    Maximum Bandwidth: %g (Bytes/sec)", fval);

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_max_rsv_bw(struct vty *vty,
						 struct tlv_header *tlvh)
{
	struct te_link_subtlv_max_rsv_bw *top;
	float fval;

	top = (struct te_link_subtlv_max_rsv_bw *)tlvh;
	fval = ntohf(top->value);

	if (vty != NULL)
		vty_out(vty, "  Maximum Reservable Bandwidth: %g (Bytes/sec)\n",
			fval);
	else
		zlog_debug("    Maximum Reservable Bandwidth: %g (Bytes/sec)",
			   fval);

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_unrsv_bw(struct vty *vty,
					       struct tlv_header *tlvh)
{
	struct te_link_subtlv_unrsv_bw *top;
	float fval1, fval2;
	int i;

	top = (struct te_link_subtlv_unrsv_bw *)tlvh;
	if (vty != NULL)
		vty_out(vty,
			"  Unreserved Bandwidth per Class Type in Byte/s:\n");
	else
		zlog_debug(
			"    Unreserved Bandwidth per Class Type in Byte/s:");
	for (i = 0; i < MAX_CLASS_TYPE; i += 2) {
		fval1 = ntohf(top->value[i]);
		fval2 = ntohf(top->value[i + 1]);

		if (vty != NULL)
			vty_out(vty,
				"    [%d]: %g (Bytes/sec),\t[%d]: %g (Bytes/sec)\n",
				i, fval1, i + 1, fval2);
		else
			zlog_debug(
				"      [%d]: %g (Bytes/sec),\t[%d]: %g (Bytes/sec)",
				i, fval1, i + 1, fval2);
	}

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_rsc_clsclr(struct vty *vty,
						 struct tlv_header *tlvh)
{
	struct te_link_subtlv_rsc_clsclr *top;

	top = (struct te_link_subtlv_rsc_clsclr *)tlvh;
	if (vty != NULL)
		vty_out(vty, "  Resource class/color: 0x%x\n",
			(u_int32_t)ntohl(top->value));
	else
		zlog_debug("    Resource Class/Color: 0x%x",
			   (u_int32_t)ntohl(top->value));

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_lrrid(struct vty *vty,
					    struct tlv_header *tlvh)
{
	struct te_link_subtlv_lrrid *top;

	top = (struct te_link_subtlv_lrrid *)tlvh;

	if (vty != NULL) {
		vty_out(vty, "  Local  TE Router ID: %s\n",
			inet_ntoa(top->local));
		vty_out(vty, "  Remote TE Router ID: %s\n",
			inet_ntoa(top->remote));
	} else {
		zlog_debug("    Local  TE Router ID: %s",
			   inet_ntoa(top->local));
		zlog_debug("    Remote TE Router ID: %s",
			   inet_ntoa(top->remote));
	}

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_llri(struct vty *vty,
					   struct tlv_header *tlvh)
{
	struct te_link_subtlv_llri *top;

	top = (struct te_link_subtlv_llri *)tlvh;

	if (vty != NULL) {
		vty_out(vty, "  Link Local  ID: %d\n",
			(u_int32_t)ntohl(top->local));
		vty_out(vty, "  Link Remote ID: %d\n",
			(u_int32_t)ntohl(top->remote));
	} else {
		zlog_debug("    Link Local  ID: %d",
			   (u_int32_t)ntohl(top->local));
		zlog_debug("    Link Remote ID: %d",
			   (u_int32_t)ntohl(top->remote));
	}

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_rip(struct vty *vty,
					  struct tlv_header *tlvh)
{
	struct te_link_subtlv_rip *top;

	top = (struct te_link_subtlv_rip *)tlvh;

	if (vty != NULL)
		vty_out(vty, "  Inter-AS TE Remote ASBR IP address: %s\n",
			inet_ntoa(top->value));
	else
		zlog_debug("    Inter-AS TE Remote ASBR IP address: %s",
			   inet_ntoa(top->value));

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_ras(struct vty *vty,
					  struct tlv_header *tlvh)
{
	struct te_link_subtlv_ras *top;

	top = (struct te_link_subtlv_ras *)tlvh;

	if (vty != NULL)
		vty_out(vty, "  Inter-AS TE Remote AS number: %u\n",
			ntohl(top->value));
	else
		zlog_debug("    Inter-AS TE Remote AS number: %u",
			   ntohl(top->value));

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_av_delay(struct vty *vty,
					       struct tlv_header *tlvh)
{
	struct te_link_subtlv_av_delay *top;
	u_int32_t delay;
	u_int32_t anomalous;

	top = (struct te_link_subtlv_av_delay *)tlvh;
	delay = (u_int32_t)ntohl(top->value) & TE_EXT_MASK;
	anomalous = (u_int32_t)ntohl(top->value) & TE_EXT_ANORMAL;

	if (vty != NULL)
		vty_out(vty, "  %s Average Link Delay: %d (micro-sec)\n",
			anomalous ? "Anomalous" : "Normal", delay);
	else
		zlog_debug("    %s Average Link Delay: %d (micro-sec)",
			   anomalous ? "Anomalous" : "Normal", delay);

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_mm_delay(struct vty *vty,
					       struct tlv_header *tlvh)
{
	struct te_link_subtlv_mm_delay *top;
	u_int32_t low, high;
	u_int32_t anomalous;

	top = (struct te_link_subtlv_mm_delay *)tlvh;
	low = (u_int32_t)ntohl(top->low) & TE_EXT_MASK;
	anomalous = (u_int32_t)ntohl(top->low) & TE_EXT_ANORMAL;
	high = (u_int32_t)ntohl(top->high);

	if (vty != NULL)
		vty_out(vty, "  %s Min/Max Link Delay: %d/%d (micro-sec)\n",
			anomalous ? "Anomalous" : "Normal", low, high);
	else
		zlog_debug("    %s Min/Max Link Delay: %d/%d (micro-sec)",
			   anomalous ? "Anomalous" : "Normal", low, high);

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_delay_var(struct vty *vty,
						struct tlv_header *tlvh)
{
	struct te_link_subtlv_delay_var *top;
	u_int32_t jitter;

	top = (struct te_link_subtlv_delay_var *)tlvh;
	jitter = (u_int32_t)ntohl(top->value) & TE_EXT_MASK;

	if (vty != NULL)
		vty_out(vty, "  Delay Variation: %d (micro-sec)\n", jitter);
	else
		zlog_debug("    Delay Variation: %d (micro-sec)", jitter);

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_pkt_loss(struct vty *vty,
					       struct tlv_header *tlvh)
{
	struct te_link_subtlv_pkt_loss *top;
	u_int32_t loss;
	u_int32_t anomalous;
	float fval;

	top = (struct te_link_subtlv_pkt_loss *)tlvh;
	loss = (u_int32_t)ntohl(top->value) & TE_EXT_MASK;
	fval = (float)(loss * LOSS_PRECISION);
	anomalous = (u_int32_t)ntohl(top->value) & TE_EXT_ANORMAL;

	if (vty != NULL)
		vty_out(vty, "  %s Link Loss: %g (%%)\n",
			anomalous ? "Anomalous" : "Normal", fval);
	else
		zlog_debug("    %s Link Loss: %g (%%)",
			   anomalous ? "Anomalous" : "Normal", fval);

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_res_bw(struct vty *vty,
					     struct tlv_header *tlvh)
{
	struct te_link_subtlv_res_bw *top;
	float fval;

	top = (struct te_link_subtlv_res_bw *)tlvh;
	fval = ntohf(top->value);

	if (vty != NULL)
		vty_out(vty,
			"  Unidirectional Residual Bandwidth: %g (Bytes/sec)\n",
			fval);
	else
		zlog_debug(
			"    Unidirectional Residual Bandwidth: %g (Bytes/sec)",
			fval);

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_ava_bw(struct vty *vty,
					     struct tlv_header *tlvh)
{
	struct te_link_subtlv_ava_bw *top;
	float fval;

	top = (struct te_link_subtlv_ava_bw *)tlvh;
	fval = ntohf(top->value);

	if (vty != NULL)
		vty_out(vty,
			"  Unidirectional Available Bandwidth: %g (Bytes/sec)\n",
			fval);
	else
		zlog_debug(
			"    Unidirectional Available Bandwidth: %g (Bytes/sec)",
			fval);

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_link_subtlv_use_bw(struct vty *vty,
					     struct tlv_header *tlvh)
{
	struct te_link_subtlv_use_bw *top;
	float fval;

	top = (struct te_link_subtlv_use_bw *)tlvh;
	fval = ntohf(top->value);

	if (vty != NULL)
		vty_out(vty,
			"  Unidirectional Utilized Bandwidth: %g (Bytes/sec)\n",
			fval);
	else
		zlog_debug(
			"    Unidirectional Utilized Bandwidth: %g (Bytes/sec)",
			fval);

	return TLV_SIZE(tlvh);
}

static u_int16_t show_vty_unknown_tlv(struct vty *vty,
				      struct tlv_header *tlvh)
{
	if (vty != NULL)
		vty_out(vty, "  Unknown TLV: [type(0x%x), length(0x%x)]\n",
			ntohs(tlvh->type), ntohs(tlvh->length));
	else
		zlog_debug("    Unknown TLV: [type(0x%x), length(0x%x)]",
			   ntohs(tlvh->type), ntohs(tlvh->length));

	return TLV_SIZE(tlvh);
}

static u_int16_t ospf_mpls_te_show_link_subtlv(struct vty *vty,
					       struct tlv_header *tlvh0,
					       u_int16_t subtotal,
					       u_int16_t total)
{
	struct tlv_header *tlvh, *next;
	u_int16_t sum = subtotal;

	for (tlvh = tlvh0; sum < total;
	     tlvh = (next ? next : TLV_HDR_NEXT(tlvh))) {
		next = NULL;
		switch (ntohs(tlvh->type)) {
		case TE_LINK_SUBTLV_LINK_TYPE:
			sum += show_vty_link_subtlv_link_type(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_LINK_ID:
			sum += show_vty_link_subtlv_link_id(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_LCLIF_IPADDR:
			sum += show_vty_link_subtlv_lclif_ipaddr(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_RMTIF_IPADDR:
			sum += show_vty_link_subtlv_rmtif_ipaddr(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_TE_METRIC:
			sum += show_vty_link_subtlv_te_metric(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_MAX_BW:
			sum += show_vty_link_subtlv_max_bw(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_MAX_RSV_BW:
			sum += show_vty_link_subtlv_max_rsv_bw(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_UNRSV_BW:
			sum += show_vty_link_subtlv_unrsv_bw(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_RSC_CLSCLR:
			sum += show_vty_link_subtlv_rsc_clsclr(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_LRRID:
			sum += show_vty_link_subtlv_lrrid(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_LLRI:
			sum += show_vty_link_subtlv_llri(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_RIP:
			sum += show_vty_link_subtlv_rip(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_RAS:
			sum += show_vty_link_subtlv_ras(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_AV_DELAY:
			sum += show_vty_link_subtlv_av_delay(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_MM_DELAY:
			sum += show_vty_link_subtlv_mm_delay(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_DELAY_VAR:
			sum += show_vty_link_subtlv_delay_var(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_PKT_LOSS:
			sum += show_vty_link_subtlv_pkt_loss(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_RES_BW:
			sum += show_vty_link_subtlv_res_bw(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_AVA_BW:
			sum += show_vty_link_subtlv_ava_bw(vty, tlvh);
			break;
		case TE_LINK_SUBTLV_USE_BW:
			sum += show_vty_link_subtlv_use_bw(vty, tlvh);
			break;
		default:
			sum += show_vty_unknown_tlv(vty, tlvh);
			break;
		}
	}
	return sum;
}

static void ospf_mpls_te_show_info(struct vty *vty, struct ospf_lsa *lsa)
{
	struct lsa_header *lsah = (struct lsa_header *)lsa->data;
	struct tlv_header *tlvh, *next;
	u_int16_t sum, total;
	u_int16_t (*subfunc)(struct vty * vty, struct tlv_header * tlvh,
			     u_int16_t subtotal, u_int16_t total) = NULL;

	sum = 0;
	total = ntohs(lsah->length) - OSPF_LSA_HEADER_SIZE;

	for (tlvh = TLV_HDR_TOP(lsah); sum < total;
	     tlvh = (next ? next : TLV_HDR_NEXT(tlvh))) {
		if (subfunc != NULL) {
			sum = (*subfunc)(vty, tlvh, sum, total);
			next = (struct tlv_header *)((char *)tlvh + sum);
			subfunc = NULL;
			continue;
		}

		next = NULL;
		switch (ntohs(tlvh->type)) {
		case TE_TLV_ROUTER_ADDR:
			sum += show_vty_router_addr(vty, tlvh);
			break;
		case TE_TLV_LINK:
			sum += show_vty_link_header(vty, tlvh);
			subfunc = ospf_mpls_te_show_link_subtlv;
			next = TLV_DATA(tlvh);
			break;
		default:
			sum += show_vty_unknown_tlv(vty, tlvh);
			break;
		}
	}
	return;
}

static void ospf_mpls_te_config_write_router(struct vty *vty)
{

	if (OspfMplsTE.enabled) {
		vty_out(vty, " mpls-te on\n");
		vty_out(vty, " mpls-te router-address %s\n",
			inet_ntoa(OspfMplsTE.router_addr.value));
	}

	if (OspfMplsTE.inter_as == AS)
		vty_out(vty, "  mpls-te inter-as as\n");
	if (OspfMplsTE.inter_as == Area)
		vty_out(vty, "  mpls-te inter-as area %s \n",
			inet_ntoa(OspfMplsTE.interas_areaid));

	return;
}

/*------------------------------------------------------------------------*
 * Followings are vty command functions.
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

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("MPLS-TE: OFF -> ON");

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

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("MPLS-TE: ON -> OFF");

	OspfMplsTE.enabled = false;

	for (ALL_LIST_ELEMENTS(OspfMplsTE.iflist, node, nnode, lp))
		if (CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED))
			ospf_mpls_te_lsa_schedule(lp, FLUSH_THIS_LSA);

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
			if ((lp->area == NULL) || IS_FLOOD_AS(lp->type))
				continue;

			if (!CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED)) {
				need_to_reoriginate = 1;
				break;
			}
		}

		for (ALL_LIST_ELEMENTS(OspfMplsTE.iflist, node, nnode, lp)) {
			if ((lp->area == NULL) || IS_FLOOD_AS(lp->type))
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

		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"MPLS-TE: Inter-AS enable with %s flooding support",
				mode2text[mode]);

		/* Register new callbacks regarding the flooding scope (AS or
		 * Area) */
		if (ospf_mpls_te_register(mode) < 0) {
			vty_out(vty,
				"Internal error: Unable to register Inter-AS functions\n");
			return CMD_WARNING;
		}

		/* Enable mode and re-originate LSA if needed */
		if ((OspfMplsTE.inter_as == Off)
		    && (mode != OspfMplsTE.inter_as)) {
			OspfMplsTE.inter_as = mode;
			/* Re-originate all InterAS-TEv2 LSA */
			for (ALL_LIST_ELEMENTS_RO(OspfMplsTE.iflist, node,
						  lp)) {
				if (IS_INTER_AS(lp->type)) {
					if (mode == AS)
						lp->type |= FLOOD_AS;
					else
						lp->type |= FLOOD_AREA;
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

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("MPLS-TE: Inter-AS support OFF");

	if ((OspfMplsTE.enabled)
	    && (OspfMplsTE.inter_as != Off)) {
		OspfMplsTE.inter_as = Off;
		/* Flush all Inter-AS LSA */
		for (ALL_LIST_ELEMENTS(OspfMplsTE.iflist, node, nnode, lp))
			if (IS_INTER_AS(lp->type)
			    && CHECK_FLAG(lp->flags, LPFLG_LSA_ENGAGED))
				ospf_mpls_te_lsa_schedule(lp, FLUSH_THIS_LSA);
	}

	/* Deregister the Callbacks for Inter-AS suport */
	ospf_mpls_te_unregister();

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
					     &OspfMplsTE.router_addr.header);
		else
			vty_out(vty, "  N/A\n");
	}
	return CMD_SUCCESS;
}

static void show_mpls_te_link_sub(struct vty *vty, struct interface *ifp)
{
	struct mpls_te_link *lp;

	if ((OspfMplsTE.enabled) && HAS_LINK_PARAMS(ifp)
	    && !if_is_loopback(ifp) && if_is_up(ifp)
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
						       &lp->link_type.header);
		if (TLV_TYPE(lp->link_id) != 0)
			show_vty_link_subtlv_link_id(vty, &lp->link_id.header);
		if (TLV_TYPE(lp->lclif_ipaddr) != 0)
			show_vty_link_subtlv_lclif_ipaddr(
				vty, &lp->lclif_ipaddr.header);
		if (TLV_TYPE(lp->rmtif_ipaddr) != 0)
			show_vty_link_subtlv_rmtif_ipaddr(
				vty, &lp->rmtif_ipaddr.header);
		if (TLV_TYPE(lp->rip) != 0)
			show_vty_link_subtlv_rip(vty, &lp->rip.header);
		if (TLV_TYPE(lp->ras) != 0)
			show_vty_link_subtlv_ras(vty, &lp->ras.header);
		if (TLV_TYPE(lp->te_metric) != 0)
			show_vty_link_subtlv_te_metric(vty,
						       &lp->te_metric.header);
		if (TLV_TYPE(lp->max_bw) != 0)
			show_vty_link_subtlv_max_bw(vty, &lp->max_bw.header);
		if (TLV_TYPE(lp->max_rsv_bw) != 0)
			show_vty_link_subtlv_max_rsv_bw(vty,
							&lp->max_rsv_bw.header);
		if (TLV_TYPE(lp->unrsv_bw) != 0)
			show_vty_link_subtlv_unrsv_bw(vty,
						      &lp->unrsv_bw.header);
		if (TLV_TYPE(lp->rsc_clsclr) != 0)
			show_vty_link_subtlv_rsc_clsclr(vty,
							&lp->rsc_clsclr.header);
		if (TLV_TYPE(lp->av_delay) != 0)
			show_vty_link_subtlv_av_delay(vty,
						      &lp->av_delay.header);
		if (TLV_TYPE(lp->mm_delay) != 0)
			show_vty_link_subtlv_mm_delay(vty,
						      &lp->mm_delay.header);
		if (TLV_TYPE(lp->delay_var) != 0)
			show_vty_link_subtlv_delay_var(vty,
						       &lp->delay_var.header);
		if (TLV_TYPE(lp->pkt_loss) != 0)
			show_vty_link_subtlv_pkt_loss(vty,
						      &lp->pkt_loss.header);
		if (TLV_TYPE(lp->res_bw) != 0)
			show_vty_link_subtlv_res_bw(vty, &lp->res_bw.header);
		if (TLV_TYPE(lp->ava_bw) != 0)
			show_vty_link_subtlv_ava_bw(vty, &lp->ava_bw.header);
		if (TLV_TYPE(lp->use_bw) != 0)
			show_vty_link_subtlv_use_bw(vty, &lp->use_bw.header);
		vty_out(vty, "---------------\n\n");
	} else {
		vty_out(vty, "  %s: MPLS-TE is disabled on this interface\n",
			ifp->name);
	}

	return;
}

DEFUN (show_ip_ospf_mpls_te_link,
       show_ip_ospf_mpls_te_link_cmd,
       "show ip ospf [vrf <NAME|all>] mpls-te interface [INTERFACE]",
       SHOW_STR
       IP_STR
       OSPF_STR
       VRF_CMD_HELP_STR
       "All VRFs\n"
       "MPLS-TE information\n"
       "Interface information\n"
       "Interface name\n")
{
	struct vrf *vrf;
	int idx_interface = 5;
	struct interface *ifp;
	struct listnode *node;
	char *vrf_name = NULL;
	bool all_vrf;
	int inst = 0;
	int idx_vrf = 0;
	struct ospf *ospf = NULL;

	if (argv_find(argv, argc, "vrf", &idx_vrf)) {
		vrf_name = argv[idx_vrf + 1]->arg;
		all_vrf = strmatch(vrf_name, "all");
	}

	/* vrf input is provided could be all or specific vrf*/
	if (vrf_name) {
		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
				if (!ospf->oi_running)
					continue;
				vrf = vrf_lookup_by_id(ospf->vrf_id);
				FOR_ALL_INTERFACES (vrf, ifp)
					show_mpls_te_link_sub(vty, ifp);
			}
			return CMD_SUCCESS;
		}
		ospf = ospf_lookup_by_inst_name (inst, vrf_name);
		if (ospf == NULL || !ospf->oi_running)
			return CMD_SUCCESS;
		vrf = vrf_lookup_by_id(ospf->vrf_id);
		FOR_ALL_INTERFACES (vrf, ifp)
			show_mpls_te_link_sub(vty, ifp);
		return CMD_SUCCESS;
	}
	/* Show All Interfaces. */
	if (argc == 5) {
		for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
			if (!ospf->oi_running)
				continue;
			vrf = vrf_lookup_by_id(ospf->vrf_id);
			FOR_ALL_INTERFACES (vrf, ifp)
				show_mpls_te_link_sub(vty, ifp);
		}
	}
	/* Interface name is specified. */
	else {
		ifp = if_lookup_by_name_all_vrf(argv[idx_interface]->arg);
		if (ifp == NULL)
			vty_out(vty, "No such interface name\n");
		else
			show_mpls_te_link_sub(vty, ifp);
	}

	return CMD_SUCCESS;
}

static void ospf_mpls_te_register_vty(void)
{
	install_element(VIEW_NODE, &show_ip_ospf_mpls_te_router_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_mpls_te_link_cmd);

	install_element(OSPF_NODE, &ospf_mpls_te_on_cmd);
	install_element(OSPF_NODE, &no_ospf_mpls_te_cmd);
	install_element(OSPF_NODE, &ospf_mpls_te_router_addr_cmd);
	install_element(OSPF_NODE, &ospf_mpls_te_inter_as_cmd);
	install_element(OSPF_NODE, &ospf_mpls_te_inter_as_area_cmd);
	install_element(OSPF_NODE, &no_ospf_mpls_te_inter_as_cmd);

	return;
}
