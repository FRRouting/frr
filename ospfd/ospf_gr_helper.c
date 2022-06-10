/*
 * OSPF Graceful Restart helper functions.
 *
 * Copyright (C) 2020-21 Vmware, Inc.
 * Rajesh Kumar Girada
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

#include <zebra.h>

#include "thread.h"
#include "memory.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "vty.h"
#include "filter.h"
#include "log.h"
#include "jhash.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_errors.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_gr.h"

static const char * const ospf_exit_reason_desc[] = {
	"Unknown reason",
	"Helper in progress",
	"Topology Change",
	"Grace timer expiry",
	"Successful graceful restart",
};

static const char * const ospf_restart_reason_desc[] = {
	"Unknown restart",
	"Software restart",
	"Software reload/upgrade",
	"Switch to redundant control processor",
};

static const char * const ospf_rejected_reason_desc[] = {
	"Unknown reason",
	"Helper support disabled",
	"Neighbour is not in FULL state",
	"Supports only planned restart but received unplanned",
	"Topo change due to change in lsa rxmt list",
	"LSA age is more than Grace interval",
	"Router is in the process of graceful restart",
};

static void show_ospf_grace_lsa_info(struct vty *vty, struct json_object *json,
				     struct ospf_lsa *lsa);
static bool ospf_check_change_in_rxmt_list(struct ospf_neighbor *nbr);

static unsigned int ospf_enable_rtr_hash_key(const void *data)
{
	const struct advRtr *rtr = data;

	return jhash_1word(rtr->advRtrAddr.s_addr, 0);
}

static bool ospf_enable_rtr_hash_cmp(const void *d1, const void *d2)
{
	const struct advRtr *rtr1 = (struct advRtr *)d1;
	const struct advRtr *rtr2 = (struct advRtr *)d2;

	return (rtr1->advRtrAddr.s_addr == rtr2->advRtrAddr.s_addr);
}

static void *ospf_enable_rtr_hash_alloc(void *p)
{
	struct advRtr *rid;

	rid = XCALLOC(MTYPE_OSPF_GR_HELPER, sizeof(struct advRtr));
	rid->advRtrAddr.s_addr = ((struct in_addr *)p)->s_addr;

	return rid;
}

static void ospf_disable_rtr_hash_free(void *rtr)
{
	XFREE(MTYPE_OSPF_GR_HELPER, rtr);
}

static void ospf_enable_rtr_hash_destroy(struct ospf *ospf)
{
	if (ospf->enable_rtr_list == NULL)
		return;

	hash_clean(ospf->enable_rtr_list, ospf_disable_rtr_hash_free);
	hash_free(ospf->enable_rtr_list);
	ospf->enable_rtr_list = NULL;
}

/*
 * GR exit reason strings
 */
const char *ospf_exit_reason2str(unsigned int reason)
{
	if (reason < array_size(ospf_exit_reason_desc))
		return(ospf_exit_reason_desc[reason]);
	else
		return "Invalid reason";
}

/*
 * GR restart reason strings
 */
const char *ospf_restart_reason2str(unsigned int reason)
{
	if (reason < array_size(ospf_restart_reason_desc))
		return(ospf_restart_reason_desc[reason]);
	else
		return "Invalid reason";
}

/*
 * GR rejected reason strings
 */
const char *ospf_rejected_reason2str(unsigned int reason)
{
	if (reason < array_size(ospf_rejected_reason_desc))
		return(ospf_rejected_reason_desc[reason]);
	else
		return "Invalid reason";
}

/*
 * Initialize GR helper config data structures.
 *
 * OSPF
 *    OSPF pointer
 *
 * Returns:
 *    Nothing
 */
void ospf_gr_helper_instance_init(struct ospf *ospf)
{
	if (IS_DEBUG_OSPF_GR)
		zlog_debug("%s, GR Helper init.", __func__);

	ospf->is_helper_supported = OSPF_GR_FALSE;
	ospf->strict_lsa_check = OSPF_GR_TRUE;
	ospf->only_planned_restart = OSPF_GR_FALSE;
	ospf->supported_grace_time = OSPF_MAX_GRACE_INTERVAL;
	ospf->last_exit_reason = OSPF_GR_HELPER_EXIT_NONE;
	ospf->active_restarter_cnt = 0;

	ospf->enable_rtr_list =
		hash_create(ospf_enable_rtr_hash_key, ospf_enable_rtr_hash_cmp,
			    "OSPF enable router hash");
}

/*
 * De-Initialize GR helper config data structures.
 *
 * OSPF
 *    OSPF pointer
 *
 * Returns:
 *    Nothing
 */
void ospf_gr_helper_instance_stop(struct ospf *ospf)
{
	if (IS_DEBUG_OSPF_GR)
		zlog_debug("%s, GR helper deinit.", __func__);

	ospf_enable_rtr_hash_destroy(ospf);
}

/*
 * Initialize GR helper config data structures.
 *
 * Returns:
 *    Nothing
 */
void ospf_gr_helper_init(void)
{
	int rc;

	if (IS_DEBUG_OSPF_GR)
		zlog_debug("%s, GR Helper init.", __func__);

	rc = ospf_register_opaque_functab(
		OSPF_OPAQUE_LINK_LSA, OPAQUE_TYPE_GRACE_LSA, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, show_ospf_grace_lsa_info, NULL, NULL,
		NULL, NULL);
	if (rc != 0) {
		flog_warn(EC_OSPF_OPAQUE_REGISTRATION,
			  "%s: Failed to register Grace LSA functions",
				__func__);
	}
}

/*
 * De-Initialize GR helper config data structures.
 *
 * Returns:
 *    Nothing
 */
void ospf_gr_helper_stop(void)
{
	if (IS_DEBUG_OSPF_GR)
		zlog_debug("%s, GR helper deinit.", __func__);

	ospf_delete_opaque_functab(OSPF_OPAQUE_LINK_LSA, OPAQUE_TYPE_GRACE_LSA);
}

/*
 * Extracting tlv info from GRACE LSA.
 *
 * lsa
 *   ospf grace lsa
 *
 * Returns:
 * interval : grace interval.
 * addr     : RESTARTER address.
 * reason   : Restarting reason.
 */
static int ospf_extract_grace_lsa_fields(struct ospf_lsa *lsa,
					 uint32_t *interval,
					 struct in_addr *addr, uint8_t *reason)
{
	struct lsa_header *lsah = NULL;
	struct tlv_header *tlvh = NULL;
	struct grace_tlv_graceperiod *grace_period;
	struct grace_tlv_restart_reason *gr_reason;
	struct grace_tlv_restart_addr *restart_addr;
	uint16_t length = 0;
	int sum = 0;

	lsah = (struct lsa_header *)lsa->data;

	/* Check LSA len */
	if (lsa->size <= OSPF_LSA_HEADER_SIZE) {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug("%s: Malformed packet: Invalid LSA len:%d",
				   __func__, length);
		return OSPF_GR_FAILURE;
	}

	length = lsa->size - OSPF_LSA_HEADER_SIZE;

	for (tlvh = TLV_HDR_TOP(lsah); sum < length && tlvh;
	     tlvh = TLV_HDR_NEXT(tlvh)) {

		/* Check TLV len against overall LSA */
		if (sum + TLV_SIZE(tlvh) > length) {
			if (IS_DEBUG_OSPF_GR)
				zlog_debug("%s: Malformed packet: Invalid TLV len:%u",
					   __func__, TLV_SIZE(tlvh));
			return OSPF_GR_FAILURE;
		}

		switch (ntohs(tlvh->type)) {
		case GRACE_PERIOD_TYPE:
			if (TLV_SIZE(tlvh) <
			    sizeof(struct grace_tlv_graceperiod)) {
				zlog_debug("%s: Malformed packet: Invalid grace TLV len:%u",
					   __func__, TLV_SIZE(tlvh));
				return OSPF_GR_FAILURE;
			}

			grace_period = (struct grace_tlv_graceperiod *)tlvh;
			*interval = ntohl(grace_period->interval);
			sum += TLV_SIZE(tlvh);

			/* Check if grace interval is valid */
			if (*interval > OSPF_MAX_GRACE_INTERVAL
			    || *interval < OSPF_MIN_GRACE_INTERVAL)
				return OSPF_GR_FAILURE;
			break;
		case RESTART_REASON_TYPE:
			if (TLV_SIZE(tlvh) <
			    sizeof(struct grace_tlv_restart_reason)) {
				zlog_debug("%s: Malformed packet: Invalid reason TLV len:%u",
					   __func__, TLV_SIZE(tlvh));
				return OSPF_GR_FAILURE;
			}

			gr_reason = (struct grace_tlv_restart_reason *)tlvh;
			*reason = gr_reason->reason;
			sum += TLV_SIZE(tlvh);

			if (*reason >= OSPF_GR_INVALID_REASON_CODE)
				return OSPF_GR_FAILURE;
			break;
		case RESTARTER_IP_ADDR_TYPE:
			if (TLV_SIZE(tlvh) <
			    sizeof(struct grace_tlv_restart_addr)) {
				zlog_debug("%s: Malformed packet: Invalid addr TLV len:%u",
					   __func__, TLV_SIZE(tlvh));
				return OSPF_GR_FAILURE;
			}

			restart_addr = (struct grace_tlv_restart_addr *)tlvh;
			addr->s_addr = restart_addr->addr.s_addr;
			sum += TLV_SIZE(tlvh);
			break;
		default:
			if (IS_DEBUG_OSPF_GR)
				zlog_debug(
					"%s, Malformed packet.Invalid TLV type:%d",
					__func__, ntohs(tlvh->type));
			return OSPF_GR_FAILURE;
		}
	}

	return OSPF_GR_SUCCESS;
}

/*
 * Grace timer expiry handler.
 * HELPER aborts its role at grace timer expiry.
 *
 * thread
 *    thread pointer
 *
 * Returns:
 *    Nothing
 */
static void ospf_handle_grace_timer_expiry(struct thread *thread)
{
	struct ospf_neighbor *nbr = THREAD_ARG(thread);

	nbr->gr_helper_info.t_grace_timer = NULL;

	ospf_gr_helper_exit(nbr, OSPF_GR_HELPER_GRACE_TIMEOUT);
}

/*
 * Process Grace LSA.If it is eligible move to HELPER role.
 * Ref rfc3623 section 3.1
 *
 * ospf
 *    OSPF pointer.
 *
 * lsa
 *    Grace LSA received from RESTARTER.
 *
 * nbr
 *    OSPF neighbour which requests the router to act as
 *    HELPER.
 *
 * Returns:
 *    status.
 *    If supported as HELPER : OSPF_GR_HELPER_INPROGRESS
 *    If Not supported as HELPER : OSPF_GR_HELPER_NONE
 */
int ospf_process_grace_lsa(struct ospf *ospf, struct ospf_lsa *lsa,
			   struct ospf_neighbor *nbr)
{
	struct in_addr restart_addr = {0};
	uint8_t restart_reason = 0;
	uint32_t grace_interval = 0;
	uint32_t actual_grace_interval = 0;
	struct advRtr lookup;
	struct ospf_neighbor *restarter = NULL;
	struct ospf_interface *oi = nbr->oi;
	int ret;


	/* Extract the grace lsa packet fields */
	ret = ospf_extract_grace_lsa_fields(lsa, &grace_interval, &restart_addr,
					    &restart_reason);
	if (ret != OSPF_GR_SUCCESS) {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug("%s, Wrong Grace LSA packet.", __func__);
		return OSPF_GR_NOT_HELPER;
	}

	if (IS_DEBUG_OSPF_GR)
		zlog_debug(
			"%s, Grace LSA received from %pI4, grace interval:%u, restart reason:%s",
			__func__, &restart_addr, grace_interval,
			ospf_restart_reason2str(restart_reason));

	/* In case of broadcast links, if RESTARTER is DR_OTHER,
	 * grace LSA might be received from DR, so need to get
	 * actual neighbour info , here RESTARTER.
	 */
	if (oi->type != OSPF_IFTYPE_POINTOPOINT) {
		restarter = ospf_nbr_lookup_by_addr(oi->nbrs, &restart_addr);

		if (!restarter) {
			if (IS_DEBUG_OSPF_GR)
				zlog_debug(
					"%s, Restarter is not a nbr(%pI4) for this router.",
					__func__, &restart_addr);
			return OSPF_GR_NOT_HELPER;
		}
	} else
		restarter = nbr;

	/* Verify Helper enabled globally */
	if (!ospf->is_helper_supported) {
		/* Verify that Helper support is enabled for the
		 * current neighbour router-id.
		 */
		lookup.advRtrAddr.s_addr = restarter->router_id.s_addr;

		if (!hash_lookup(ospf->enable_rtr_list, &lookup)) {
			if (IS_DEBUG_OSPF_GR)
				zlog_debug(
					"%s, HELPER support is disabled, So not a HELPER",
					__func__);
			restarter->gr_helper_info.rejected_reason =
				OSPF_HELPER_SUPPORT_DISABLED;
			return OSPF_GR_NOT_HELPER;
		}
	}


	/* Check neighbour is in FULL state and
	 * became a adjacency.
	 */
	if (!IS_NBR_STATE_FULL(restarter)) {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug(
				"%s, This Neighbour %pI4 is not in FULL state.",
				__func__, &restarter->src);
		restarter->gr_helper_info.rejected_reason =
			OSPF_HELPER_NOT_A_VALID_NEIGHBOUR;
		return OSPF_GR_NOT_HELPER;
	}

	/* Based on the restart reason from grace lsa
	 * check the current router is supporting or not
	 */
	if (ospf->only_planned_restart
	    && !OSPF_GR_IS_PLANNED_RESTART(restart_reason)) {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug(
				"%s, Router supports only planned restarts but received the GRACE LSA for an unplanned restart.",
				__func__);
		restarter->gr_helper_info.rejected_reason =
			OSPF_HELPER_PLANNED_ONLY_RESTART;
		return OSPF_GR_NOT_HELPER;
	}

	/* Check the retransmission list of this
	 * neighbour, check any change in lsas.
	 */
	if (ospf->strict_lsa_check && !ospf_ls_retransmit_isempty(restarter)
	    && ospf_check_change_in_rxmt_list(restarter)) {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug(
				"%s, Changed LSA in Rxmt list. So not Helper.",
				__func__);
		restarter->gr_helper_info.rejected_reason =
			OSPF_HELPER_TOPO_CHANGE_RTXMT_LIST;
		return OSPF_GR_NOT_HELPER;
	}

	/*LSA age must be less than the grace period */
	if (ntohs(lsa->data->ls_age) >= grace_interval) {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug(
				"%s, Grace LSA age(%d) is more than the grace interval(%d)",
				__func__, lsa->data->ls_age, grace_interval);
		restarter->gr_helper_info.rejected_reason =
			OSPF_HELPER_LSA_AGE_MORE;
		return OSPF_GR_NOT_HELPER;
	}

	if (ospf->gr_info.restart_in_progress) {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug(
				"%s: router is in the process of graceful restart",
				__func__);
		restarter->gr_helper_info.rejected_reason =
			OSPF_HELPER_RESTARTING;
		return OSPF_GR_NOT_HELPER;
	}

	/* check supported grace period configured
	 * if configured, use this to start the grace
	 * timer otherwise use the interval received
	 * in grace LSA packet.
	 */
	actual_grace_interval = grace_interval;
	if (grace_interval > ospf->supported_grace_time) {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug(
				"%s, Received grace period %d is larger than supported grace %d",
				__func__, grace_interval,
				ospf->supported_grace_time);
		actual_grace_interval = ospf->supported_grace_time;
	}

	if (OSPF_GR_IS_ACTIVE_HELPER(restarter)) {
		if (restarter->gr_helper_info.t_grace_timer)
			THREAD_OFF(restarter->gr_helper_info.t_grace_timer);

		if (ospf->active_restarter_cnt > 0)
			ospf->active_restarter_cnt--;

		if (IS_DEBUG_OSPF_GR)
			zlog_debug(
				"%s, Router is already acting as a HELPER for this nbr,so restart the grace timer",
				__func__);
	} else {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug(
				"%s, This Router becomes a HELPER for the neighbour %pI4",
				__func__, &restarter->src);
	}

	/* Became a Helper to the RESTART neighbour.
	 * Change the helper status.
	 */
	restarter->gr_helper_info.gr_helper_status = OSPF_GR_ACTIVE_HELPER;
	restarter->gr_helper_info.recvd_grace_period = grace_interval;
	restarter->gr_helper_info.actual_grace_period = actual_grace_interval;
	restarter->gr_helper_info.gr_restart_reason = restart_reason;
	restarter->gr_helper_info.rejected_reason = OSPF_HELPER_REJECTED_NONE;

	/* Increment the active restarter count */
	ospf->active_restarter_cnt++;

	if (IS_DEBUG_OSPF_GR)
		zlog_debug("%s, Grace timer started.interval:%d", __func__,
			   actual_grace_interval);

	/* Start the grace timer */
	thread_add_timer(master, ospf_handle_grace_timer_expiry, restarter,
			 actual_grace_interval,
			 &restarter->gr_helper_info.t_grace_timer);

	return OSPF_GR_ACTIVE_HELPER;
}

/*
 * API to check any change in the neighbor's
 * retransmission list.
 *
 * nbr
 *    OSPF neighbor
 *
 * Returns:
 *    TRUE  - if any change in the lsa.
 *    FALSE - no change in the lsas.
 */
static bool ospf_check_change_in_rxmt_list(struct ospf_neighbor *nbr)
{
	struct route_node *rn;
	struct ospf_lsa *lsa;
	struct route_table *tbl;

	tbl = nbr->ls_rxmt.type[OSPF_ROUTER_LSA].db;
	LSDB_LOOP (tbl, rn, lsa)
		if (lsa->to_be_acknowledged)
			return OSPF_GR_TRUE;
	tbl = nbr->ls_rxmt.type[OSPF_NETWORK_LSA].db;
	LSDB_LOOP (tbl, rn, lsa)
		if (lsa->to_be_acknowledged)
			return OSPF_GR_TRUE;

	tbl = nbr->ls_rxmt.type[OSPF_SUMMARY_LSA].db;
	LSDB_LOOP (tbl, rn, lsa)
		if (lsa->to_be_acknowledged)
			return OSPF_GR_TRUE;

	tbl = nbr->ls_rxmt.type[OSPF_ASBR_SUMMARY_LSA].db;
	LSDB_LOOP (tbl, rn, lsa)
		if (lsa->to_be_acknowledged)
			return OSPF_GR_TRUE;

	tbl = nbr->ls_rxmt.type[OSPF_AS_EXTERNAL_LSA].db;
	LSDB_LOOP (tbl, rn, lsa)
		if (lsa->to_be_acknowledged)
			return OSPF_GR_TRUE;

	tbl = nbr->ls_rxmt.type[OSPF_AS_NSSA_LSA].db;
	LSDB_LOOP (tbl, rn, lsa)
		if (lsa->to_be_acknowledged)
			return OSPF_GR_TRUE;

	return OSPF_GR_FALSE;
}

/*
 * Actions to be taken  when topo change detected
 * HELPER will exit upon topo change.
 *
 * ospf
 *    ospf pointer
 * lsa
 *    topo change occurred due to this lsa type (1 to 5 and 7)
 *
 * Returns:
 *    Nothing
 */
void ospf_helper_handle_topo_chg(struct ospf *ospf, struct ospf_lsa *lsa)
{
	struct listnode *node;
	struct ospf_interface *oi;

	/* Topo change not required to be handled if strict
	 * LSA check is disabled for this router.
	 */
	if (!ospf->strict_lsa_check)
		return;

	if (IS_DEBUG_OSPF_GR)
		zlog_debug("%s: Topo change detected due to LSA[%s]", __func__,
			   dump_lsa_key(lsa));

	lsa->to_be_acknowledged = OSPF_GR_TRUE;

	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi)) {
		struct route_node *rn = NULL;

		if (ospf_interface_neighbor_count(oi) == 0)
			continue;

		/* Ref rfc3623 section 3.2.3.b
		 * If change due to external LSA and if the area is
		 * stub, then it is not a topo change. Since Type-5
		 * lsas will not be flooded in stub area.
		 */
		if ((oi->area->external_routing == OSPF_AREA_STUB)
		    && (lsa->data->type == OSPF_AS_EXTERNAL_LSA)) {
			continue;
		}

		for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
			struct ospf_neighbor *nbr = NULL;

			if (!rn->info)
				continue;

			nbr = rn->info;

			if (OSPF_GR_IS_ACTIVE_HELPER(nbr))
				ospf_gr_helper_exit(nbr,
						    OSPF_GR_HELPER_TOPO_CHG);
		}
	}
}

/*
 * Api to exit from HELPER role to take all actions
 * required at exit.
 * Ref rfc3623 section 3.2
 *
 * ospf
 *    OSPF pointer.
 *
 * nbr
 *    OSPF neighbour for which it is acting as HELPER.
 *
 * reason
 *    The reason for exiting from HELPER.
 *
 * Returns:
 *    Nothing.
 */
void ospf_gr_helper_exit(struct ospf_neighbor *nbr,
			 enum ospf_helper_exit_reason reason)
{
	struct ospf_interface *oi = nbr->oi;
	struct ospf *ospf = oi->ospf;

	if (!OSPF_GR_IS_ACTIVE_HELPER(nbr))
		return;

	if (IS_DEBUG_OSPF_GR)
		zlog_debug("%s, Exiting from HELPER support to %pI4, due to %s",
			   __func__, &nbr->src, ospf_exit_reason2str(reason));

	/* Reset helper status*/
	nbr->gr_helper_info.gr_helper_status = OSPF_GR_NOT_HELPER;
	nbr->gr_helper_info.helper_exit_reason = reason;
	nbr->gr_helper_info.actual_grace_period = 0;
	nbr->gr_helper_info.recvd_grace_period = 0;
	nbr->gr_helper_info.gr_restart_reason = 0;
	ospf->last_exit_reason = reason;

	if (ospf->active_restarter_cnt <= 0) {
		zlog_err(
			"OSPF GR-Helper: active_restarter_cnt should be greater than zero here.");
		return;
	}
	/* Decrement active Restarter count */
	ospf->active_restarter_cnt--;

	/* If the exit not triggered due to grace timer
	 * expiry, stop the grace timer.
	 */
	if (reason != OSPF_GR_HELPER_GRACE_TIMEOUT)
		THREAD_OFF(nbr->gr_helper_info.t_grace_timer);

	/* check exit triggered due to successful completion
	 * of graceful restart.
	 */
	if (reason != OSPF_GR_HELPER_COMPLETED) {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug("%s, Unsuccessful GR exit", __func__);
	}

	/*Recalculate the DR for the network segment */
	if (oi->type == OSPF_IFTYPE_BROADCAST || oi->type == OSPF_IFTYPE_NBMA)
		ospf_dr_election(oi);

	/* Originate a router LSA */
	ospf_router_lsa_update_area(oi->area);

	/* Originate network lsa if it is an DR in the LAN */
	if (oi->state == ISM_DR)
		ospf_network_lsa_update(oi);
}

/*
 * Process MaxAge Grace LSA.
 * It is a indication for successful completion of GR.
 * If router acting as HELPER, It exits from helper role.
 *
 * ospf
 *    OSPF pointer.
 *
 * lsa
 *    Grace LSA received from RESTARTER.
 *
 * nbr
 *    OSPF neighbour which requests the router to act as
 *    HELPER.
 *
 * Returns:
 *    Nothing.
 */
void ospf_process_maxage_grace_lsa(struct ospf *ospf, struct ospf_lsa *lsa,
				   struct ospf_neighbor *nbr)
{
	struct in_addr restartAddr = {0};
	uint8_t restartReason = 0;
	uint32_t graceInterval = 0;
	struct ospf_neighbor *restarter = NULL;
	struct ospf_interface *oi = nbr->oi;
	int ret;

	/* Extract the grace lsa packet fields */
	ret = ospf_extract_grace_lsa_fields(lsa, &graceInterval, &restartAddr,
					    &restartReason);
	if (ret != OSPF_GR_SUCCESS) {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug("%s, Wrong Grace LSA packet.", __func__);
		return;
	}

	if (IS_DEBUG_OSPF_GR)
		zlog_debug("%s, GraceLSA received for neighbour %pI4", __func__,
			   &restartAddr);

	/* In case of broadcast links, if RESTARTER is DR_OTHER,
	 * grace LSA might be received from DR, so fetching the
	 * actual neighbour information using restarter address.
	 */
	if (oi->type != OSPF_IFTYPE_POINTOPOINT) {
		restarter = ospf_nbr_lookup_by_addr(oi->nbrs, &restartAddr);

		if (!restarter) {
			if (IS_DEBUG_OSPF_GR)
				zlog_debug(
					"%s, Restarter is not a neighbour for this router.",
					__func__);
			return;
		}
	} else {
		restarter = nbr;
	}

	ospf_gr_helper_exit(restarter, OSPF_GR_HELPER_COMPLETED);
}

/* Configuration handlers */
/*
 * Disable/Enable HELPER support on router level.
 *
 * ospf
 *    OSPF pointer.
 *
 * status
 *    TRUE/FALSE
 *
 * Returns:
 *    Nothing.
 */
void ospf_gr_helper_support_set(struct ospf *ospf, bool support)
{
	struct ospf_interface *oi;
	struct listnode *node;
	struct advRtr lookup;

	if (ospf->is_helper_supported == support)
		return;

	ospf->is_helper_supported = support;

	/* If helper support disabled, cease HELPER role for all
	 * supporting neighbors.
	 */
	if (support == OSPF_GR_FALSE) {
		for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi)) {
			struct route_node *rn = NULL;

			if (ospf_interface_neighbor_count(oi) == 0)
				continue;

			for (rn = route_top(oi->nbrs); rn;
			     rn = route_next(rn)) {
				struct ospf_neighbor *nbr = NULL;

				if (!rn->info)
					continue;

				nbr = rn->info;

				lookup.advRtrAddr.s_addr =
					nbr->router_id.s_addr;
				/* check if helper support enabled for the
				 * corresponding routerid.If enabled, don't
				 * exit from helper role.
				 */
				if (hash_lookup(ospf->enable_rtr_list, &lookup))
					continue;

				if (OSPF_GR_IS_ACTIVE_HELPER(nbr))
					ospf_gr_helper_exit(
						nbr, OSPF_GR_HELPER_TOPO_CHG);
			}
		}
	}
}

/*
 * Enable/Disable HELPER support on a specified advertagement
 * router.
 *
 * ospf
 *    OSPF pointer.
 *
 * advRtr
 *    HELPER support for given Advertisement Router.
 *
 * support
 *    True - Enable Helper Support.
 *    False - Disable Helper Support.
 *
 * Returns:
 *    Nothing.
 */

void ospf_gr_helper_support_set_per_routerid(struct ospf *ospf,
					     struct in_addr *advrtr,
					     bool support)
{
	struct advRtr temp;
	struct advRtr *rtr;
	struct ospf_interface *oi;
	struct listnode *node;

	temp.advRtrAddr.s_addr = advrtr->s_addr;

	if (support == OSPF_GR_FALSE) {
		/*Delete the routerid from the enable router hash table */
		rtr = hash_lookup(ospf->enable_rtr_list, &temp);

		if (rtr) {
			hash_release(ospf->enable_rtr_list, rtr);
			ospf_disable_rtr_hash_free(rtr);
		}

		/* If helper support is enabled globally
		 * no action is required.
		 */
		if (ospf->is_helper_supported)
			return;

		/* Cease the HELPER role fore neighbours from the
		 * specified advertisement router.
		 */
		for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi)) {
			struct route_node *rn = NULL;

			if (ospf_interface_neighbor_count(oi) == 0)
				continue;

			for (rn = route_top(oi->nbrs); rn;
			     rn = route_next(rn)) {
				struct ospf_neighbor *nbr = NULL;

				if (!rn->info)
					continue;

				nbr = rn->info;

				if (nbr->router_id.s_addr != advrtr->s_addr)
					continue;

				if (OSPF_GR_IS_ACTIVE_HELPER(nbr))
					ospf_gr_helper_exit(
						nbr, OSPF_GR_HELPER_TOPO_CHG);
			}
		}

	} else {
		/* Add the routerid to the enable router hash table */
		(void)hash_get(ospf->enable_rtr_list, &temp,
			       ospf_enable_rtr_hash_alloc);
	}
}

/*
 * Api to enable/disable strict lsa check on the HELPER.
 *
 * ospf
 *    OSPF pointer.
 *
 * enabled
 *    True - disable the lsa check.
 *    False - enable the strict lsa check.
 *
 * Returns:
 *    Nothing.
 */
void ospf_gr_helper_lsa_check_set(struct ospf *ospf, bool enabled)
{
	if (ospf->strict_lsa_check == enabled)
		return;

	ospf->strict_lsa_check = enabled;
}

/*
 * Api to set the supported grace interval in this router.
 *
 * ospf
 *    OSPF pointer.
 *
 * interval
 *    The supported grace interval..
 *
 * Returns:
 *    Nothing.
 */
void ospf_gr_helper_supported_gracetime_set(struct ospf *ospf,
					    uint32_t interval)
{
	ospf->supported_grace_time = interval;
}

/*
 * Api to set the supported restart reason.
 *
 * ospf
 *    OSPF pointer.
 *
 * planned_only
 *    True: support only planned restart.
 *    False: support for planned/unplanned restarts.
 *
 * Returns:
 *    Nothing.
 */
void ospf_gr_helper_set_supported_planned_only_restart(struct ospf *ospf,
						      bool planned_only)
{
	ospf->only_planned_restart = planned_only;
}

/*
 * Api to display the grace LSA information.
 *
 * vty
 *    vty pointer.
 * lsa
 *    Grace LSA.
 * json
 *    json object
 *
 * Returns:
 *    Nothing.
 */
static void show_ospf_grace_lsa_info(struct vty *vty, struct json_object *json,
				     struct ospf_lsa *lsa)
{
	struct lsa_header *lsah = NULL;
	struct tlv_header *tlvh = NULL;
	struct grace_tlv_graceperiod *gracePeriod;
	struct grace_tlv_restart_reason *grReason;
	struct grace_tlv_restart_addr *restartAddr;
	uint16_t length = 0;
	int sum = 0;

	if (json)
		return;

	lsah = (struct lsa_header *)lsa->data;

	if (lsa->size <= OSPF_LSA_HEADER_SIZE) {
		if (vty)
			vty_out(vty, "%% Invalid LSA length: %d\n", length);
		else
			zlog_debug("%% Invalid LSA length: %d", length);
		return;
	}

	length = lsa->size - OSPF_LSA_HEADER_SIZE;

	if (vty)
		vty_out(vty, "  TLV info:\n");
	else
		zlog_debug("  TLV info:");

	for (tlvh = TLV_HDR_TOP(lsah); sum < length && tlvh;
	     tlvh = TLV_HDR_NEXT(tlvh)) {
		/* Check TLV len */
		if (sum + TLV_SIZE(tlvh) > length) {
			if (vty)
				vty_out(vty, "%% Invalid TLV length: %u\n",
					TLV_SIZE(tlvh));
			else
				zlog_debug("%% Invalid TLV length: %u",
					   TLV_SIZE(tlvh));
			return;
		}

		switch (ntohs(tlvh->type)) {
		case GRACE_PERIOD_TYPE:
			if (TLV_SIZE(tlvh)
			    < sizeof(struct grace_tlv_graceperiod)) {
				if (vty)
					vty_out(vty,
						"%% Invalid grace TLV length %u\n",
						TLV_SIZE(tlvh));
				else
					zlog_debug(
						"%% Invalid grace TLV length %u",
						TLV_SIZE(tlvh));
				return;
			}

			gracePeriod = (struct grace_tlv_graceperiod *)tlvh;
			sum += TLV_SIZE(tlvh);

			if (vty)
				vty_out(vty, "   Grace period:%d\n",
					ntohl(gracePeriod->interval));
			else
				zlog_debug("   Grace period:%d",
					   ntohl(gracePeriod->interval));
			break;
		case RESTART_REASON_TYPE:
			if (TLV_SIZE(tlvh)
			    < sizeof(struct grace_tlv_restart_reason)) {
				if (vty)
					vty_out(vty,
						"%% Invalid reason TLV length %u\n",
						TLV_SIZE(tlvh));
				else
					zlog_debug(
						"%% Invalid reason TLV length %u",
						TLV_SIZE(tlvh));
				return;
			}

			grReason = (struct grace_tlv_restart_reason *)tlvh;
			sum += TLV_SIZE(tlvh);

			if (vty)
				vty_out(vty, "   Restart reason:%s\n",
					ospf_restart_reason2str(
						grReason->reason));
			else
				zlog_debug("   Restart reason:%s",
					   ospf_restart_reason2str(
						   grReason->reason));
			break;
		case RESTARTER_IP_ADDR_TYPE:
			if (TLV_SIZE(tlvh)
			    < sizeof(struct grace_tlv_restart_addr)) {
				if (vty)
					vty_out(vty,
						"%% Invalid addr TLV length %u\n",
						TLV_SIZE(tlvh));
				else
					zlog_debug(
						"%% Invalid addr TLV length %u",
						TLV_SIZE(tlvh));
				return;
			}

			restartAddr = (struct grace_tlv_restart_addr *)tlvh;
			sum += TLV_SIZE(tlvh);

			if (vty)
				vty_out(vty, "   Restarter address:%pI4\n",
					&restartAddr->addr);
			else
				zlog_debug("   Restarter address:%pI4",
					   &restartAddr->addr);
			break;
		default:
			if (vty)
				vty_out(vty, "   Unknown TLV type %d\n",
					ntohs(tlvh->type));
			else
				zlog_debug("   Unknown TLV type %d",
					   ntohs(tlvh->type));

			break;
		}
	}
}
