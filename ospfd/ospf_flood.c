/*
 * OSPF Flooding -- RFC2328 Section 13.
 * Copyright (C) 1999, 2000 Toshiaki Takada
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
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

#include <zebra.h>

#include "monotime.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "command.h"
#include "table.h"
#include "thread.h"
#include "memory.h"
#include "log.h"
#include "zclient.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_packet.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_dump.h"

extern struct zclient *zclient;

/* Do the LSA acking specified in table 19, Section 13.5, row 2
 * This get called from ospf_flood_out_interface. Declared inline
 * for speed. */
static void ospf_flood_delayed_lsa_ack(struct ospf_neighbor *inbr,
				       struct ospf_lsa *lsa)
{
	/* LSA is more recent than database copy, but was not
	   flooded back out receiving interface.  Delayed
	   acknowledgment sent. If interface is in Backup state
	   delayed acknowledgment sent only if advertisement
	   received from Designated Router, otherwise do nothing See
	   RFC 2328 Section 13.5 */

	/* Whether LSA is more recent or not, and whether this is in
	   response to the LSA being sent out recieving interface has been
	   worked out previously */

	/* Deal with router as BDR */
	if (inbr->oi->state == ISM_Backup && !NBR_IS_DR(inbr))
		return;

	/* Schedule a delayed LSA Ack to be sent */
	listnode_add(inbr->oi->ls_ack,
		     ospf_lsa_lock(lsa)); /* delayed LSA Ack */
}

/* Check LSA is related to external info. */
struct external_info *ospf_external_info_check(struct ospf *ospf,
					       struct ospf_lsa *lsa)
{
	struct as_external_lsa *al;
	struct prefix_ipv4 p;
	struct route_node *rn;
	struct list *ext_list;
	struct listnode *node;
	struct ospf_external *ext;
	int type;

	al = (struct as_external_lsa *)lsa->data;

	p.family = AF_INET;
	p.prefix = lsa->data->id;
	p.prefixlen = ip_masklen(al->mask);

	for (type = 0; type < ZEBRA_ROUTE_MAX; type++) {
		int redist_on = 0;

		redist_on =
			is_prefix_default(&p)
				? vrf_bitmap_check(
					  zclient->default_information[AFI_IP],
					  ospf->vrf_id)
				: (zclient->mi_redist[AFI_IP][type].enabled
				   || vrf_bitmap_check(
					      zclient->redist[AFI_IP][type],
					      ospf->vrf_id));
		// Pending: check for MI above.
		if (redist_on) {
			ext_list = ospf->external[type];
			if (!ext_list)
				continue;

			for (ALL_LIST_ELEMENTS_RO(ext_list, node, ext)) {
				rn = NULL;
				if (ext->external_info)
					rn = route_node_lookup(
						ext->external_info,
						(struct prefix *)&p);
				if (rn) {
					route_unlock_node(rn);
					if (rn->info != NULL)
						return (struct external_info *)
							rn->info;
				}
			}
		}
	}

	if (is_prefix_default(&p) && ospf->external[DEFAULT_ROUTE]) {
		ext_list = ospf->external[DEFAULT_ROUTE];

		for (ALL_LIST_ELEMENTS_RO(ext_list, node, ext)) {
			if (!ext->external_info)
				continue;

			rn = route_node_lookup(ext->external_info,
					       (struct prefix *)&p);
			if (!rn)
				continue;
			route_unlock_node(rn);
			if (rn->info != NULL)
				return (struct external_info *)rn->info;
		}
	}
	return NULL;
}

static void ospf_process_self_originated_lsa(struct ospf *ospf,
					     struct ospf_lsa *new,
					     struct ospf_area *area)
{
	struct ospf_interface *oi;
	struct external_info *ei;
	struct listnode *node;
	struct as_external_lsa *al;
	struct prefix_ipv4 p;
	struct ospf_external_aggr_rt *aggr;

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"%s:LSA[Type%d:%pI4]: Process self-originated LSA seq 0x%x",
			ospf_get_name(ospf), new->data->type,
			&new->data->id, ntohl(new->data->ls_seqnum));

	/* If we're here, we installed a self-originated LSA that we received
	   from a neighbor, i.e. it's more recent.  We must see whether we want
	   to originate it.
	   If yes, we should use this LSA's sequence number and reoriginate
	   a new instance.
	   if not --- we must flush this LSA from the domain. */
	switch (new->data->type) {
	case OSPF_ROUTER_LSA:
		/* Originate a new instance and schedule flooding */
		if (area->router_lsa_self)
			area->router_lsa_self->data->ls_seqnum =
				new->data->ls_seqnum;
		ospf_router_lsa_update_area(area);
		return;
	case OSPF_NETWORK_LSA:
	case OSPF_OPAQUE_LINK_LSA:
		/* We must find the interface the LSA could belong to.
		   If the interface is no more a broadcast type or we are no
		   more
		   the DR, we flush the LSA otherwise -- create the new instance
		   and
		   schedule flooding. */

		/* Look through all interfaces, not just area, since interface
		   could be moved from one area to another. */
		for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi))
			/* These are sanity check. */
			if (IPV4_ADDR_SAME(&oi->address->u.prefix4,
					   &new->data->id)) {
				if (oi->area != area
				    || oi->type != OSPF_IFTYPE_BROADCAST
				    || !IPV4_ADDR_SAME(&oi->address->u.prefix4,
						       &DR(oi))) {
					ospf_schedule_lsa_flush_area(area, new);
					return;
				}

				if (new->data->type == OSPF_OPAQUE_LINK_LSA) {
					ospf_opaque_lsa_refresh(new);
					return;
				}

				if (oi->network_lsa_self)
					oi->network_lsa_self->data->ls_seqnum =
						new->data->ls_seqnum;
				/* Schedule network-LSA origination. */
				ospf_network_lsa_update(oi);
				return;
			}
		break;
	case OSPF_SUMMARY_LSA:
	case OSPF_ASBR_SUMMARY_LSA:
		ospf_schedule_abr_task(ospf);
		break;
	case OSPF_AS_EXTERNAL_LSA:
	case OSPF_AS_NSSA_LSA:
		if ((new->data->type == OSPF_AS_EXTERNAL_LSA)
		    && CHECK_FLAG(new->flags, OSPF_LSA_LOCAL_XLT)) {
			ospf_translated_nssa_refresh(ospf, NULL, new);
			return;
		}

		al = (struct as_external_lsa *)new->data;
		p.family = AF_INET;
		p.prefixlen = ip_masklen(al->mask);
		p.prefix = new->data->id;

		ei = ospf_external_info_check(ospf, new);
		if (ei) {
			if (ospf_external_aggr_match(ospf, &ei->p)) {
				if (IS_DEBUG_OSPF(lsa, EXTNL_LSA_AGGR))
					zlog_debug(
						"%s, Matching external aggregate route found for %pI4, so don't refresh it.",
						__func__,
						&ei->p.prefix);

				/* Aggregated external route shouldn't
				 * be in LSDB.
				 */
				if (!IS_LSA_MAXAGE(new))
					ospf_lsa_flush_as(ospf, new);

				return;
			}

			ospf_external_lsa_refresh(ospf, new, ei,
						  LSA_REFRESH_FORCE, false);
		} else {
			aggr = (struct ospf_external_aggr_rt *)
				ospf_extrenal_aggregator_lookup(ospf, &p);
			if (aggr) {
				struct external_info ei_aggr;

				memset(&ei_aggr, 0,
					sizeof(struct external_info));
				ei_aggr.p = aggr->p;
				ei_aggr.tag = aggr->tag;
				ei_aggr.instance = ospf->instance;
				ei_aggr.route_map_set.metric = -1;
				ei_aggr.route_map_set.metric_type = -1;

				ospf_external_lsa_refresh(ospf, new, &ei_aggr,
						  LSA_REFRESH_FORCE, true);
			} else
				ospf_lsa_flush_as(ospf, new);
		}
		break;
	case OSPF_OPAQUE_AREA_LSA:
		ospf_opaque_lsa_refresh(new);
		break;
	case OSPF_OPAQUE_AS_LSA:
		ospf_opaque_lsa_refresh(new);
		/* Reconsideration may needed. */ /* XXX */
		break;
	default:
		break;
	}
}

/* OSPF LSA flooding -- RFC2328 Section 13.(5). */

/* Now Updated for NSSA operation, as follows:


	Type-5's have no change.  Blocked to STUB or NSSA.

	Type-7's can be received, and if a DR
	they will also flood the local NSSA Area as Type-7's

	If a Self-Originated LSA (now an ASBR),
	The LSDB will be updated as Type-5's, (for continual re-fresh)

	    If an NSSA-IR it is installed/flooded as Type-7, P-bit on.
	    if an NSSA-ABR it is installed/flooded as Type-7, P-bit off.

	Later, during the ABR TASK, if the ABR is the Elected NSSA
	translator, then All Type-7s (with P-bit ON) are Translated to
	Type-5's and flooded to all non-NSSA/STUB areas.

	During ASE Calculations,
	    non-ABRs calculate external routes from Type-7's
	    ABRs calculate external routes from Type-5's and non-self Type-7s
*/
int ospf_flood(struct ospf *ospf, struct ospf_neighbor *nbr,
	       struct ospf_lsa *current, struct ospf_lsa *new)
{
	struct ospf_interface *oi;
	int lsa_ack_flag;

	/* Type-7 LSA's will be flooded throughout their native NSSA area,
	   but will also be flooded as Type-5's into ABR capable links.  */

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"%s:LSA[Flooding]: start, NBR %pI4 (%s), cur(%p), New-LSA[%s]",
			ospf_get_name(ospf), &nbr->router_id,
			lookup_msg(ospf_nsm_state_msg, nbr->state, NULL),
			(void *)current, dump_lsa_key(new));

	oi = nbr->oi;

	/* If there is already a database copy, and if the
	   database copy was received via flooding and installed less
	   than MinLSArrival seconds ago, discard the new LSA
	   (without acknowledging it). */
	if (current != NULL) /* -- endo. */
	{
		if (IS_LSA_SELF(current)
		    && (ntohs(current->data->ls_age) == 0
			&& ntohl(current->data->ls_seqnum)
				   == OSPF_INITIAL_SEQUENCE_NUMBER)) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s:LSA[Flooding]: Got a self-originated LSA, while local one is initial instance.",
					ospf_get_name(ospf));
			; /* Accept this LSA for quick LSDB resynchronization.
			     */
		} else if (monotime_since(&current->tv_recv, NULL)
			   < ospf->min_ls_arrival * 1000LL) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s:LSA[Flooding]: LSA is received recently.",
					ospf_get_name(ospf));
			return -1;
		}
	}

	/* Flood the new LSA out some subset of the router's interfaces.
	   In some cases (e.g., the state of the receiving interface is
	   DR and the LSA was received from a router other than the
	   Backup DR) the LSA will be flooded back out the receiving
	   interface. */
	lsa_ack_flag = ospf_flood_through(ospf, nbr, new);

	/* Remove the current database copy from all neighbors' Link state
	   retransmission lists.  AS_EXTERNAL and AS_EXTERNAL_OPAQUE does
					      ^^^^^^^^^^^^^^^^^^^^^^^
	   not have area ID.
	   All other (even NSSA's) do have area ID.  */
	if (current) {
		switch (current->data->type) {
		case OSPF_AS_EXTERNAL_LSA:
		case OSPF_OPAQUE_AS_LSA:
			ospf_ls_retransmit_delete_nbr_as(ospf, current);
			break;
		default:
			ospf_ls_retransmit_delete_nbr_area(oi->area, current);
			break;
		}
	}

	/* Do some internal house keeping that is needed here */
	SET_FLAG(new->flags, OSPF_LSA_RECEIVED);
	(void)ospf_lsa_is_self_originated(ospf, new); /* Let it set the flag */

	/* Received Grace LSA */
	if (IS_GRACE_LSA(new)) {

		if (IS_LSA_MAXAGE(new)) {

			/*  Handling Max age grace LSA.*/
			if (IS_DEBUG_OSPF_GR_HELPER)
				zlog_debug(
					"%s, Received a maxage GRACE-LSA from router %pI4",
					__func__, &new->data->adv_router);

			if (current) {
				ospf_process_maxage_grace_lsa(ospf, new, nbr);
			} else {
				if (IS_DEBUG_OSPF_GR_HELPER)
					zlog_debug(
						"%s, Grace LSA doesn't exist in lsdb, so discarding grace lsa",
						__func__);
				return -1;
			}
		} else {
			if (IS_DEBUG_OSPF_GR_HELPER)
				zlog_debug(
					"%s, Received a GRACE-LSA from router %pI4",
					__func__, &new->data->adv_router);

			if (ospf_process_grace_lsa(ospf, new, nbr)
			    == OSPF_GR_NOT_HELPER) {
				if (IS_DEBUG_OSPF_GR_HELPER)
					zlog_debug(
						"%s, Not moving to HELPER role, So discarding grace LSA",
						__func__);
				return -1;
			}
		}
	}

	/* Install the new LSA in the link state database
	   (replacing the current database copy).  This may cause the
	   routing table calculation to be scheduled.  In addition,
	   timestamp the new LSA with the current time.  The flooding
	   procedure cannot overwrite the newly installed LSA until
	   MinLSArrival seconds have elapsed. */

	if (!(new = ospf_lsa_install(ospf, oi, new)))
		return -1; /* unknown LSA type or any other error condition */

	/* Acknowledge the receipt of the LSA by sending a Link State
	   Acknowledgment packet back out the receiving interface. */
	if (lsa_ack_flag)
		ospf_flood_delayed_lsa_ack(nbr, new);

	/* If this new LSA indicates that it was originated by the
	   receiving router itself, the router must take special action,
	   either updating the LSA or in some cases flushing it from
	   the routing domain. */
	if (ospf_lsa_is_self_originated(ospf, new))
		ospf_process_self_originated_lsa(ospf, new, oi->area);
	else
		/* Update statistics value for OSPF-MIB. */
		ospf->rx_lsa_count++;

	return 0;
}

/* OSPF LSA flooding -- RFC2328 Section 13.3. */
static int ospf_flood_through_interface(struct ospf_interface *oi,
					struct ospf_neighbor *inbr,
					struct ospf_lsa *lsa)
{
	struct ospf_neighbor *onbr;
	struct route_node *rn;
	int retx_flag;
	char buf[PREFIX_STRLEN];

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"%s: considering int %s (%s), INBR(%s), LSA[%s] AGE %u",
			__func__, IF_NAME(oi), ospf_get_name(oi->ospf),
			inbr ? inet_ntop(AF_INET, &inbr->router_id, buf,
					 sizeof(buf))
			     : "NULL",
			dump_lsa_key(lsa), ntohs(lsa->data->ls_age));

	if (!ospf_if_is_enable(oi))
		return 0;

	/* Remember if new LSA is added to a retransmit list. */
	retx_flag = 0;

	/* Each of the neighbors attached to this interface are examined,
	   to determine whether they must receive the new LSA.  The following
	   steps are executed for each neighbor: */
	for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
		struct ospf_lsa *ls_req;

		if (rn->info == NULL)
			continue;

		onbr = rn->info;
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"%s: considering nbr %pI4 via %s (%s), state: %s",
				__func__, &onbr->router_id, IF_NAME(oi),
				ospf_get_name(oi->ospf),
				lookup_msg(ospf_nsm_state_msg, onbr->state,
					   NULL));

		/* If the neighbor is in a lesser state than Exchange, it
		   does not participate in flooding, and the next neighbor
		   should be examined. */
		if (onbr->state < NSM_Exchange)
			continue;

		/* If the adjacency is not yet full (neighbor state is
		   Exchange or Loading), examine the Link state request
		   list associated with this adjacency.  If there is an
		   instance of the new LSA on the list, it indicates that
		   the neighboring router has an instance of the LSA
		   already.  Compare the new LSA to the neighbor's copy: */
		if (onbr->state < NSM_Full) {
			if (IS_DEBUG_OSPF_EVENT)
				zlog_debug(
					"%s: adj to onbr %pI4 is not Full (%s)",
					__func__, &onbr->router_id,
					lookup_msg(ospf_nsm_state_msg,
						   onbr->state, NULL));
			ls_req = ospf_ls_request_lookup(onbr, lsa);
			if (ls_req != NULL) {
				int ret;

				ret = ospf_lsa_more_recent(ls_req, lsa);
				/* The new LSA is less recent. */
				if (ret > 0)
					continue;
				/* The two copies are the same instance, then
				   delete
				   the LSA from the Link state request list. */
				else if (ret == 0) {
					ospf_ls_request_delete(onbr, ls_req);
					ospf_check_nbr_loading(onbr);
					continue;
				}
				/* The new LSA is more recent.  Delete the LSA
				   from the Link state request list. */
				else {
					ospf_ls_request_delete(onbr, ls_req);
					ospf_check_nbr_loading(onbr);
				}
			}
		}

		if (IS_OPAQUE_LSA(lsa->data->type)) {
			if (!CHECK_FLAG(onbr->options, OSPF_OPTION_O)) {
				if (IS_DEBUG_OSPF(lsa, LSA_FLOODING))
					zlog_debug(
						"%s: Skipping neighbor %s via %pI4 -- Not Opaque-capable.",
						__func__, IF_NAME(oi),
						&onbr->router_id);
				continue;
			}
		}

 /* If the new LSA was received from this neighbor,
    examine the next neighbor. */
		if (inbr) {
			/*
			 * Triggered by LSUpd message parser "ospf_ls_upd ()".
			 * E.g., all LSAs handling here is received via network.
			 */
			if (IPV4_ADDR_SAME(&inbr->router_id,
					   &onbr->router_id)) {
				if (IS_DEBUG_OSPF(lsa, LSA_FLOODING))
					zlog_debug(
						"%s: Skipping neighbor %s via %pI4 -- inbr == onbr.",
						__func__, IF_NAME(oi),
						&inbr->router_id);
				continue;
			}
		} else {
			/*
			 * Triggered by MaxAge remover, so far.
			 * NULL "inbr" means flooding starts from this node.
			 */
			if (IPV4_ADDR_SAME(&lsa->data->adv_router,
					   &onbr->router_id)) {
				if (IS_DEBUG_OSPF(lsa, LSA_FLOODING))
					zlog_debug(
						"%s: Skipping neighbor %s via %pI4 -- lsah->adv_router == onbr.",
						__func__, IF_NAME(oi),
						&onbr->router_id);
				continue;
			}
		}

		/* Add the new LSA to the Link state retransmission list
		   for the adjacency. The LSA will be retransmitted
		   at intervals until an acknowledgment is seen from
		   the neighbor. */
		ospf_ls_retransmit_add(onbr, lsa);
		retx_flag = 1;
	}

	/* If in the previous step, the LSA was NOT added to any of
	   the Link state retransmission lists, there is no need to
	   flood the LSA out the interface. */
	if (retx_flag == 0) {
		return (inbr && inbr->oi == oi);
	}

	/* if we've received the lsa on this interface we need to perform
	   additional checking */
	if (inbr && (inbr->oi == oi)) {
		/* If the new LSA was received on this interface, and it was
		   received from either the Designated Router or the Backup
		   Designated Router, chances are that all the neighbors have
		   received the LSA already. */
		if (NBR_IS_DR(inbr) || NBR_IS_BDR(inbr)) {
			if (IS_DEBUG_OSPF_NSSA)
				zlog_debug("%s: DR/BDR NOT SEND to int %s (%s)",
					   __func__, IF_NAME(oi),
					   ospf_get_name(oi->ospf));
			return 1;
		}

		/* If the new LSA was received on this interface, and the
		   interface state is Backup, examine the next interface.  The
		   Designated Router will do the flooding on this interface.
		   However, if the Designated Router fails the router will
		   end up retransmitting the updates. */

		if (oi->state == ISM_Backup) {
			if (IS_DEBUG_OSPF_NSSA)
				zlog_debug(
					"%s: ISM_Backup NOT SEND to int %s (%s)",
					__func__, IF_NAME(oi),
					ospf_get_name(oi->ospf));
			return 1;
		}
	}

	/* The LSA must be flooded out the interface. Send a Link State
	   Update packet (including the new LSA as contents) out the
	   interface.  The LSA's LS age must be incremented by InfTransDelay
	   (which	must be	> 0) when it is copied into the outgoing Link
	   State Update packet (until the LS age field reaches the maximum
	   value of MaxAge). */
	/* XXX HASSO: Is this IS_DEBUG_OSPF_NSSA really correct? */
	if (IS_DEBUG_OSPF_NSSA)
		zlog_debug("%s: DR/BDR sending upd to int %s (%s)", __func__,
			   IF_NAME(oi), ospf_get_name(oi->ospf));

	/*  RFC2328  Section 13.3
	    On non-broadcast networks, separate	Link State Update
	    packets must be sent, as unicasts, to each adjacent	neighbor
	    (i.e., those in state Exchange or greater).	 The destination
	    IP addresses for these packets are the neighbors' IP
	    addresses.   */
	if (oi->type == OSPF_IFTYPE_NBMA) {
		struct ospf_neighbor *nbr;

		for (rn = route_top(oi->nbrs); rn; rn = route_next(rn))
			if ((nbr = rn->info) != NULL)
				if (nbr != oi->nbr_self
				    && nbr->state >= NSM_Exchange)
					ospf_ls_upd_send_lsa(
						nbr, lsa,
						OSPF_SEND_PACKET_DIRECT);
	} else
		ospf_ls_upd_send_lsa(oi->nbr_self, lsa,
				     OSPF_SEND_PACKET_INDIRECT);

	return 0;
}

int ospf_flood_through_area(struct ospf_area *area, struct ospf_neighbor *inbr,
			    struct ospf_lsa *lsa)
{
	struct listnode *node, *nnode;
	struct ospf_interface *oi;
	int lsa_ack_flag = 0;

	assert(area);
	/* All other types are specific to a single area (Area A).  The
	   eligible interfaces are all those interfaces attaching to the
	   Area A.  If Area A is the backbone, this includes all the virtual
	   links.  */
	for (ALL_LIST_ELEMENTS(area->oiflist, node, nnode, oi)) {
		if (area->area_id.s_addr != OSPF_AREA_BACKBONE
		    && oi->type == OSPF_IFTYPE_VIRTUALLINK)
			continue;

		if ((lsa->data->type == OSPF_OPAQUE_LINK_LSA)
		    && (lsa->oi != oi)) {
			/*
			 * Link local scoped Opaque-LSA should only be flooded
			 * for the link on which the LSA has received.
			 */
			if (IS_DEBUG_OSPF(lsa, LSA_FLOODING))
				zlog_debug(
					"Type-9 Opaque-LSA: lsa->oi(%p) != oi(%p)",
					(void *)lsa->oi, (void *)oi);
			continue;
		}

		if (ospf_flood_through_interface(oi, inbr, lsa))
			lsa_ack_flag = 1;
	}

	return (lsa_ack_flag);
}

int ospf_flood_through_as(struct ospf *ospf, struct ospf_neighbor *inbr,
			  struct ospf_lsa *lsa)
{
	struct listnode *node;
	struct ospf_area *area;
	int lsa_ack_flag;

	lsa_ack_flag = 0;

	/* The incoming LSA is type 5 or type 7  (AS-EXTERNAL or AS-NSSA )

	  Divert the Type-5 LSA's to all non-NSSA/STUB areas

	  Divert the Type-7 LSA's to all NSSA areas

	   AS-external-LSAs are flooded throughout the entire AS, with the
	   exception of stub areas (see Section 3.6).  The eligible
	   interfaces are all the router's interfaces, excluding virtual
	   links and those interfaces attaching to stub areas.  */

	if (CHECK_FLAG(lsa->flags, OSPF_LSA_LOCAL_XLT)) /* Translated from 7  */
		if (IS_DEBUG_OSPF_NSSA)
			zlog_debug("Flood/AS: NSSA TRANSLATED LSA");

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		int continue_flag = 0;
		struct listnode *if_node;
		struct ospf_interface *oi;

		switch (area->external_routing) {
		/* Don't send AS externals into stub areas.  Various types
		   of support for partial stub areas can be implemented
		   here.  NSSA's will receive Type-7's that have areas
		   matching the originl LSA. */
		case OSPF_AREA_NSSA: /* Sending Type 5 or 7 into NSSA area */
				     /* Type-7, flood NSSA area */
			if (lsa->data->type == OSPF_AS_NSSA_LSA
			    && area == lsa->area)
				/* We will send it. */
				continue_flag = 0;
			else
				continue_flag = 1; /* Skip this NSSA area for
						      Type-5's et al */
			break;

		case OSPF_AREA_TYPE_MAX:
		case OSPF_AREA_STUB:
			continue_flag = 1; /* Skip this area. */
			break;

		case OSPF_AREA_DEFAULT:
		default:
			/* No Type-7 into normal area */
			if (lsa->data->type == OSPF_AS_NSSA_LSA)
				continue_flag = 1; /* skip Type-7 */
			else
				continue_flag = 0; /* Do this area. */
			break;
		}

		/* Do continue for above switch.  Saves a big if then mess */
		if (continue_flag)
			continue; /* main for-loop */

		/* send to every interface in this area */

		for (ALL_LIST_ELEMENTS_RO(area->oiflist, if_node, oi)) {
			/* Skip virtual links */
			if (oi->type != OSPF_IFTYPE_VIRTUALLINK)
				if (ospf_flood_through_interface(oi, inbr,
								 lsa)) /* lsa */
					lsa_ack_flag = 1;
		}
	} /* main area for-loop */

	return (lsa_ack_flag);
}

int ospf_flood_through(struct ospf *ospf, struct ospf_neighbor *inbr,
		       struct ospf_lsa *lsa)
{
	int lsa_ack_flag = 0;

	/* Type-7 LSA's for NSSA are flooded throughout the AS here, and
	   upon return are updated in the LSDB for Type-7's.  Later,
	   re-fresh will re-send them (and also, if ABR, packet code will
	   translate to Type-5's)

	   As usual, Type-5 LSA's (if not DISCARDED because we are STUB or
	   NSSA) are flooded throughout the AS, and are updated in the
	   global table.  */
	/*
	 * At the common sub-sub-function "ospf_flood_through_interface()",
	 * a parameter "inbr" will be used to distinguish the called context
	 * whether the given LSA was received from the neighbor, or the
	 * flooding for the LSA starts from this node (e.g. the LSA was self-
	 * originated, or the LSA is going to be flushed from routing domain).
	 *
	 * So, for consistency reasons, this function "ospf_flood_through()"
	 * should also allow the usage that the given "inbr" parameter to be
	 * NULL. If we do so, corresponding AREA parameter should be referred
	 * by "lsa->area", instead of "inbr->oi->area".
	 */
	switch (lsa->data->type) {
	case OSPF_AS_EXTERNAL_LSA: /* Type-5 */
	case OSPF_OPAQUE_AS_LSA:
		lsa_ack_flag = ospf_flood_through_as(ospf, inbr, lsa);
		break;
	/* Type-7 Only received within NSSA, then flooded */
	case OSPF_AS_NSSA_LSA:
		/* Any P-bit was installed with the Type-7. */

		if (IS_DEBUG_OSPF_NSSA)
			zlog_debug(
				"ospf_flood_through: LOCAL NSSA FLOOD of Type-7.");
	/* Fallthrough */
	default:
		lsa_ack_flag = ospf_flood_through_area(lsa->area, inbr, lsa);
		break;
	}

	return (lsa_ack_flag);
}


/* Management functions for neighbor's Link State Request list. */
void ospf_ls_request_add(struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
	/*
	 * We cannot make use of the newly introduced callback function
	 * "lsdb->new_lsa_hook" to replace debug output below, just because
	 * it seems no simple and smart way to pass neighbor information to
	 * the common function "ospf_lsdb_add()" -- endo.
	 */
	if (IS_DEBUG_OSPF(lsa, LSA_FLOODING))
		zlog_debug("RqstL(%lu)++, NBR(%pI4(%s)), LSA[%s]",
			   ospf_ls_request_count(nbr),
			   &nbr->router_id,
			   ospf_get_name(nbr->oi->ospf), dump_lsa_key(lsa));

	ospf_lsdb_add(&nbr->ls_req, lsa);
}

unsigned long ospf_ls_request_count(struct ospf_neighbor *nbr)
{
	return ospf_lsdb_count_all(&nbr->ls_req);
}

int ospf_ls_request_isempty(struct ospf_neighbor *nbr)
{
	return ospf_lsdb_isempty(&nbr->ls_req);
}

/* Remove LSA from neighbor's ls-request list. */
void ospf_ls_request_delete(struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
	if (nbr->ls_req_last == lsa) {
		ospf_lsa_unlock(&nbr->ls_req_last);
		nbr->ls_req_last = NULL;
	}

	if (IS_DEBUG_OSPF(lsa, LSA_FLOODING)) /* -- endo. */
		zlog_debug("RqstL(%lu)--, NBR(%pI4(%s)), LSA[%s]",
			   ospf_ls_request_count(nbr),
			   &nbr->router_id,
			   ospf_get_name(nbr->oi->ospf), dump_lsa_key(lsa));

	ospf_lsdb_delete(&nbr->ls_req, lsa);
}

/* Remove all LSA from neighbor's ls-requenst list. */
void ospf_ls_request_delete_all(struct ospf_neighbor *nbr)
{
	ospf_lsa_unlock(&nbr->ls_req_last);
	nbr->ls_req_last = NULL;
	ospf_lsdb_delete_all(&nbr->ls_req);
}

/* Lookup LSA from neighbor's ls-request list. */
struct ospf_lsa *ospf_ls_request_lookup(struct ospf_neighbor *nbr,
					struct ospf_lsa *lsa)
{
	return ospf_lsdb_lookup(&nbr->ls_req, lsa);
}

struct ospf_lsa *ospf_ls_request_new(struct lsa_header *lsah)
{
	struct ospf_lsa *new;

	new = ospf_lsa_new_and_data(OSPF_LSA_HEADER_SIZE);
	memcpy(new->data, lsah, OSPF_LSA_HEADER_SIZE);

	return new;
}


/* Management functions for neighbor's ls-retransmit list. */
unsigned long ospf_ls_retransmit_count(struct ospf_neighbor *nbr)
{
	return ospf_lsdb_count_all(&nbr->ls_rxmt);
}

unsigned long ospf_ls_retransmit_count_self(struct ospf_neighbor *nbr,
					    int lsa_type)
{
	return ospf_lsdb_count_self(&nbr->ls_rxmt, lsa_type);
}

int ospf_ls_retransmit_isempty(struct ospf_neighbor *nbr)
{
	return ospf_lsdb_isempty(&nbr->ls_rxmt);
}

/* Add LSA to be retransmitted to neighbor's ls-retransmit list. */
void ospf_ls_retransmit_add(struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
	struct ospf_lsa *old;

	old = ospf_ls_retransmit_lookup(nbr, lsa);

	if (ospf_lsa_more_recent(old, lsa) < 0) {
		if (old) {
			old->retransmit_counter--;
			if (IS_DEBUG_OSPF(lsa, LSA_FLOODING))
				zlog_debug("RXmtL(%lu)--, NBR(%pI4(%s)), LSA[%s]",
					   ospf_ls_retransmit_count(nbr),
					   &nbr->router_id,
					   ospf_get_name(nbr->oi->ospf),
					   dump_lsa_key(old));
			ospf_lsdb_delete(&nbr->ls_rxmt, old);
		}
		lsa->retransmit_counter++;
		/*
		 * We cannot make use of the newly introduced callback function
		 * "lsdb->new_lsa_hook" to replace debug output below, just
		 * because
		 * it seems no simple and smart way to pass neighbor information
		 * to
		 * the common function "ospf_lsdb_add()" -- endo.
		 */
		if (IS_DEBUG_OSPF(lsa, LSA_FLOODING))
			zlog_debug("RXmtL(%lu)++, NBR(%pI4(%s)), LSA[%s]",
				   ospf_ls_retransmit_count(nbr),
				   &nbr->router_id,
				   ospf_get_name(nbr->oi->ospf),
				   dump_lsa_key(lsa));
		ospf_lsdb_add(&nbr->ls_rxmt, lsa);
	}
}

/* Remove LSA from neibghbor's ls-retransmit list. */
void ospf_ls_retransmit_delete(struct ospf_neighbor *nbr, struct ospf_lsa *lsa)
{
	if (ospf_ls_retransmit_lookup(nbr, lsa)) {
		lsa->retransmit_counter--;
		if (IS_DEBUG_OSPF(lsa, LSA_FLOODING)) /* -- endo. */
			zlog_debug("RXmtL(%lu)--, NBR(%pI4(%s)), LSA[%s]",
				   ospf_ls_retransmit_count(nbr),
				   &nbr->router_id,
				   ospf_get_name(nbr->oi->ospf),
				   dump_lsa_key(lsa));
		ospf_lsdb_delete(&nbr->ls_rxmt, lsa);
	}
}

/* Clear neighbor's ls-retransmit list. */
void ospf_ls_retransmit_clear(struct ospf_neighbor *nbr)
{
	struct ospf_lsdb *lsdb;
	int i;

	lsdb = &nbr->ls_rxmt;

	for (i = OSPF_MIN_LSA; i < OSPF_MAX_LSA; i++) {
		struct route_table *table = lsdb->type[i].db;
		struct route_node *rn;
		struct ospf_lsa *lsa;

		for (rn = route_top(table); rn; rn = route_next(rn))
			if ((lsa = rn->info) != NULL)
				ospf_ls_retransmit_delete(nbr, lsa);
	}

	ospf_lsa_unlock(&nbr->ls_req_last);
	nbr->ls_req_last = NULL;
}

/* Lookup LSA from neighbor's ls-retransmit list. */
struct ospf_lsa *ospf_ls_retransmit_lookup(struct ospf_neighbor *nbr,
					   struct ospf_lsa *lsa)
{
	return ospf_lsdb_lookup(&nbr->ls_rxmt, lsa);
}

static void ospf_ls_retransmit_delete_nbr_if(struct ospf_interface *oi,
					     struct ospf_lsa *lsa)
{
	struct route_node *rn;
	struct ospf_neighbor *nbr;
	struct ospf_lsa *lsr;

	if (ospf_if_is_enable(oi))
		for (rn = route_top(oi->nbrs); rn; rn = route_next(rn))
			/* If LSA find in LS-retransmit list, then remove it. */
			if ((nbr = rn->info) != NULL) {
				lsr = ospf_ls_retransmit_lookup(nbr, lsa);

				/* If LSA find in ls-retransmit list, remove it.
				 */
				if (lsr != NULL
				    && lsr->data->ls_seqnum
					       == lsa->data->ls_seqnum)
					ospf_ls_retransmit_delete(nbr, lsr);
			}
}

void ospf_ls_retransmit_delete_nbr_area(struct ospf_area *area,
					struct ospf_lsa *lsa)
{
	struct listnode *node, *nnode;
	struct ospf_interface *oi;

	for (ALL_LIST_ELEMENTS(area->oiflist, node, nnode, oi))
		ospf_ls_retransmit_delete_nbr_if(oi, lsa);
}

void ospf_ls_retransmit_delete_nbr_as(struct ospf *ospf, struct ospf_lsa *lsa)
{
	struct listnode *node, *nnode;
	struct ospf_interface *oi;

	for (ALL_LIST_ELEMENTS(ospf->oiflist, node, nnode, oi))
		ospf_ls_retransmit_delete_nbr_if(oi, lsa);
}


/* Sets ls_age to MaxAge and floods throu the area.
   When we implement ASE routing, there will be another function
   flushing an LSA from the whole domain. */
void ospf_lsa_flush_area(struct ospf_lsa *lsa, struct ospf_area *area)
{
	/* Reset the lsa origination time such that it gives
	   more time for the ACK to be received and avoid
	   retransmissions */
	lsa->data->ls_age = htons(OSPF_LSA_MAXAGE);
	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug("%s: MAXAGE set to LSA %pI4", __func__,
			   &lsa->data->id);
	monotime(&lsa->tv_recv);
	lsa->tv_orig = lsa->tv_recv;
	ospf_flood_through_area(area, NULL, lsa);
	ospf_lsa_maxage(area->ospf, lsa);
}

void ospf_lsa_flush_as(struct ospf *ospf, struct ospf_lsa *lsa)
{
	/* Reset the lsa origination time such that it gives
	   more time for the ACK to be received and avoid
	   retransmissions */
	lsa->data->ls_age = htons(OSPF_LSA_MAXAGE);
	monotime(&lsa->tv_recv);
	lsa->tv_orig = lsa->tv_recv;
	ospf_flood_through_as(ospf, NULL, lsa);
	ospf_lsa_maxage(ospf, lsa);
}

void ospf_lsa_flush(struct ospf *ospf, struct ospf_lsa *lsa)
{
	lsa->data->ls_age = htons(OSPF_LSA_MAXAGE);

	switch (lsa->data->type) {
	case OSPF_ROUTER_LSA:
	case OSPF_NETWORK_LSA:
	case OSPF_SUMMARY_LSA:
	case OSPF_ASBR_SUMMARY_LSA:
	case OSPF_AS_NSSA_LSA:
	case OSPF_OPAQUE_LINK_LSA:
	case OSPF_OPAQUE_AREA_LSA:
		ospf_lsa_flush_area(lsa, lsa->area);
		break;
	case OSPF_AS_EXTERNAL_LSA:
	case OSPF_OPAQUE_AS_LSA:
		ospf_lsa_flush_as(ospf, lsa);
		break;
	default:
		zlog_info("%s: Unknown LSA type %u", __func__, lsa->data->type);
		break;
	}
}
