/*
 * OSPF6 Graceful Restart helper functions.
 *
 * Copyright (C) 2021-22 Vmware, Inc.
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

#include "log.h"
#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "stream.h"
#include "zclient.h"
#include "memory.h"
#include "table.h"
#include "lib/bfd.h"
#include "lib_errors.h"
#include "jhash.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_route.h"
#include "ospf6_message.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_intra.h"
#include "ospf6d.h"
#include "ospf6_gr.h"
#include "lib/json.h"
#ifndef VTYSH_EXTRACT_PL
#include "ospf6d/ospf6_gr_helper_clippy.c"
#endif

DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_GR_HELPER, "OSPF6 Graceful restart helper");

unsigned char conf_debug_ospf6_gr;

const char *ospf6_exit_reason_desc[] = {
	"Unknown reason",     "Helper inprogress",	   "Topology Change",
	"Grace timer expiry", "Successful graceful restart",
};

const char *ospf6_restart_reason_desc[] = {
	"Unknown restart",
	"Software restart",
	"Software reload/upgrade",
	"Switch to redundant control processor",
};

const char *ospf6_rejected_reason_desc[] = {
	"Unknown reason",
	"Helper support disabled",
	"Neighbour is not in FULL state",
	"Supports only planned restart but received for unplanned",
	"Topo change due to change in lsa rxmt list",
	"LSA age is more than Grace interval",
};

static unsigned int ospf6_enable_rtr_hash_key(const void *data)
{
	const struct advRtr *rtr = data;

	return jhash_1word(rtr->advRtrAddr, 0);
}

static bool ospf6_enable_rtr_hash_cmp(const void *d1, const void *d2)
{
	const struct advRtr *rtr1 = d1;
	const struct advRtr *rtr2 = d2;

	return (rtr1->advRtrAddr == rtr2->advRtrAddr);
}

static void *ospf6_enable_rtr_hash_alloc(void *p)
{
	struct advRtr *rid;

	rid = XCALLOC(MTYPE_OSPF6_GR_HELPER, sizeof(struct advRtr));
	rid->advRtrAddr = ((struct advRtr *)p)->advRtrAddr;

	return rid;
}

static void ospf6_disable_rtr_hash_free(void *rtr)
{
	XFREE(MTYPE_OSPF6_GR_HELPER, rtr);
}

static void ospf6_enable_rtr_hash_destroy(struct ospf6 *ospf6)
{
	if (ospf6->ospf6_helper_cfg.enable_rtr_list == NULL)
		return;

	hash_clean(ospf6->ospf6_helper_cfg.enable_rtr_list,
		   ospf6_disable_rtr_hash_free);
	hash_free(ospf6->ospf6_helper_cfg.enable_rtr_list);
	ospf6->ospf6_helper_cfg.enable_rtr_list = NULL;
}

/*
 * Extracting tlv info from GRACE LSA.
 *
 * lsa
 *   ospf6 grace lsa
 *
 * Returns:
 * interval : grace interval.
 * reason   : Restarting reason.
 */
static int ospf6_extract_grace_lsa_fields(struct ospf6_lsa *lsa,
					  uint32_t *interval, uint8_t *reason)
{
	struct ospf6_lsa_header *lsah = NULL;
	struct tlv_header *tlvh = NULL;
	struct grace_tlv_graceperiod *gracePeriod;
	struct grace_tlv_restart_reason *grReason;
	uint16_t length = 0;
	int sum = 0;

	lsah = (struct ospf6_lsa_header *)lsa->header;

	length = ntohs(lsah->length) - OSPF6_LSA_HEADER_SIZE;

	for (tlvh = TLV_HDR_TOP(lsah); sum < length;
	     tlvh = TLV_HDR_NEXT(tlvh)) {
		switch (ntohs(tlvh->type)) {
		case GRACE_PERIOD_TYPE:
			gracePeriod = (struct grace_tlv_graceperiod *)tlvh;
			*interval = ntohl(gracePeriod->interval);
			sum += TLV_SIZE(tlvh);

			/* Check if grace interval is valid */
			if (*interval > OSPF6_MAX_GRACE_INTERVAL
			    || *interval < OSPF6_MIN_GRACE_INTERVAL)
				return OSPF6_FAILURE;
			break;
		case RESTART_REASON_TYPE:
			grReason = (struct grace_tlv_restart_reason *)tlvh;
			*reason = grReason->reason;
			sum += TLV_SIZE(tlvh);

			if (*reason >= OSPF6_GR_INVALID_REASON_CODE)
				return OSPF6_FAILURE;
			break;
		default:
			if (IS_DEBUG_OSPF6_GR_HELPER)
				zlog_debug(
					"%s, Ignoring unknown TLV type:%d",
					__func__, ntohs(tlvh->type));
		}
	}

	return OSPF6_SUCCESS;
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
static int ospf6_handle_grace_timer_expiry(struct thread *thread)
{
	struct ospf6_neighbor *nbr = THREAD_ARG(thread);

	nbr->gr_helper_info.t_grace_timer = NULL;

	// ospf6_gr_helper_exit(nbr, OSPF6_GR_HELPER_GRACE_TIMEOUT);
	return OSPF6_SUCCESS;
}

/*
 * API to check any change in the neighbor's
 * retransmission list.
 *
 * nbr
 *    ospf6 neighbor
 *
 * Returns:
 *    TRUE  - if any change in the lsa.
 *    FALSE - no change in the lsas.
 */
static bool ospf6_check_chg_in_rxmt_list(struct ospf6_neighbor *nbr)
{
	struct ospf6_lsa *lsa, *lsanext;

	for (ALL_LSDB(nbr->retrans_list, lsa, lsanext)) {
		struct ospf6_lsa *lsa_in_db = NULL;

		/* Fetching the same copy of LSA form LSDB to validate the
		 * topochange.
		 */
		lsa_in_db =
			ospf6_lsdb_lookup(lsa->header->type, lsa->header->id,
					  lsa->header->adv_router, lsa->lsdb);

		if (lsa_in_db && lsa_in_db->tobe_acknowledged)
			return OSPF6_TRUE;
	}

	return OSPF6_FALSE;
}

/*
 * Process Grace LSA.If it is eligible move to HELPER role.
 * Ref rfc3623 section 3.1 and rfc5187
 *
 * ospf
 *    Ospf6 pointer.
 *
 * lsa
 *    Grace LSA received from RESTARTER.
 *
 * restarter
 *    ospf6 neighbour which requests the router to act as
 *    HELPER.
 *
 * Returns:
 *    status.
 *    If supported as HELPER : OSPF_GR_HELPER_INPROGRESS
 *    If Not supported as HELPER : OSPF_GR_HELPER_NONE
 */
int ospf6_process_grace_lsa(struct ospf6 *ospf6, struct ospf6_lsa *lsa,
			    struct ospf6_neighbor *restarter)
{
	uint8_t restart_reason = 0;
	uint32_t grace_interval = 0;
	uint32_t actual_grace_interval = 0;
	struct advRtr lookup;
	int ret;

	/* Extract the grace lsa packet fields */
	ret = ospf6_extract_grace_lsa_fields(lsa, &grace_interval,
					     &restart_reason);
	if (ret != OSPF6_SUCCESS) {
		if (IS_DEBUG_OSPF6_GR_HELPER)
			zlog_debug("%s, Wrong Grace LSA packet.",
				   __func__);
		return OSPF6_GR_NOT_HELPER;
	}

	if (IS_DEBUG_OSPF6_GR_HELPER)
		zlog_debug(
			"%s, Grace LSA received from  %pI4, grace interval:%u, restart reason :%s",
			__func__, &restarter->router_id,
			grace_interval,
			ospf6_restart_reason_desc[restart_reason]);

	/* Verify Helper enabled globally */
	if (!ospf6->ospf6_helper_cfg.is_helper_supported) {
		/* Verify Helper support is enabled for the
		 * current neighbour router-id.
		 */
		lookup.advRtrAddr = restarter->router_id;

		if (!hash_lookup(ospf6->ospf6_helper_cfg.enable_rtr_list,
				 &lookup)) {
			if (IS_DEBUG_OSPF6_GR_HELPER)
				zlog_debug(
					"%s, HELPER support is disabled, So not a HELPER",
					__func__);
			restarter->gr_helper_info.rejected_reason =
				OSPF6_HELPER_SUPPORT_DISABLED;
			return OSPF6_GR_NOT_HELPER;
		}
	}

	/* Check neighbour is in FULL state and
	 * became a adjacency.
	 */
	if (!IS_NBR_STATE_FULL(restarter)) {
		if (IS_DEBUG_OSPF6_GR_HELPER)
			zlog_debug(
				"%s, This Neighbour %pI6 is not in FULL state.",
				__func__, &restarter->linklocal_addr);
		restarter->gr_helper_info.rejected_reason =
			OSPF6_HELPER_NOT_A_VALID_NEIGHBOUR;
		return OSPF6_GR_NOT_HELPER;
	}

	/* Based on the restart reason from grace lsa
	 * check the current router is supporting or not
	 */
	if (ospf6->ospf6_helper_cfg.only_planned_restart
	    && !OSPF6_GR_IS_PLANNED_RESTART(restart_reason)) {
		if (IS_DEBUG_OSPF6_GR_HELPER)
			zlog_debug(
				"%s, Router supports only planned restarts but received the GRACE LSA due a unplanned restart",
				__func__);
		restarter->gr_helper_info.rejected_reason =
			OSPF6_HELPER_PLANNED_ONLY_RESTART;
		return OSPF6_GR_NOT_HELPER;
	}

	/* Check the retransmission list of this
	 * neighbour, check any change in lsas.
	 */
	if (ospf6->ospf6_helper_cfg.strict_lsa_check
	    && restarter->retrans_list->count
	    && ospf6_check_chg_in_rxmt_list(restarter)) {
		if (IS_DEBUG_OSPF6_GR_HELPER)
			zlog_debug(
				"%s, Changed LSA in Rxmt list.So not Helper.",
				__func__);
		restarter->gr_helper_info.rejected_reason =
			OSPF6_HELPER_TOPO_CHANGE_RTXMT_LIST;
		return OSPF6_GR_NOT_HELPER;
	}

	/*LSA age must be less than the grace period */
	if (ntohs(lsa->header->age) >= grace_interval) {
		if (IS_DEBUG_OSPF6_GR_HELPER)
			zlog_debug(
				"%s, Grace LSA age(%d) is more than the grace interval(%d)",
				__func__, lsa->header->age,
				grace_interval);
		restarter->gr_helper_info.rejected_reason =
			OSPF6_HELPER_LSA_AGE_MORE;
		return OSPF6_GR_NOT_HELPER;
	}

	/* check supported grace period configured
	 * if configured, use this to start the grace
	 * timer otherwise use the interval received
	 * in grace LSA packet.
	 */
	actual_grace_interval = grace_interval;
	if (grace_interval > ospf6->ospf6_helper_cfg.supported_grace_time) {
		if (IS_DEBUG_OSPF6_GR_HELPER)
			zlog_debug(
				"%s, Received grace period %d is larger than supported grace %d",
				__func__, grace_interval,
				ospf6->ospf6_helper_cfg.supported_grace_time);
		actual_grace_interval =
			ospf6->ospf6_helper_cfg.supported_grace_time;
	}

	if (OSPF6_GR_IS_ACTIVE_HELPER(restarter)) {
		if (restarter->gr_helper_info.t_grace_timer)
			THREAD_OFF(restarter->gr_helper_info.t_grace_timer);

		if (ospf6->ospf6_helper_cfg.active_restarter_cnt > 0)
			ospf6->ospf6_helper_cfg.active_restarter_cnt--;

		if (IS_DEBUG_OSPF6_GR_HELPER)
			zlog_debug(
				"%s, Router is already acting as a HELPER for this nbr,so restart the grace timer",
				__func__);
	} else {
		if (IS_DEBUG_OSPF6_GR_HELPER)
			zlog_debug(
				"%s, This Router becomes a HELPER for the neighbour %pI6",
				__func__, &restarter->linklocal_addr);
	}

	/* Became a Helper to the RESTART neighbour.
	 * change the helper status.
	 */
	restarter->gr_helper_info.gr_helper_status = OSPF6_GR_ACTIVE_HELPER;
	restarter->gr_helper_info.recvd_grace_period = grace_interval;
	restarter->gr_helper_info.actual_grace_period = actual_grace_interval;
	restarter->gr_helper_info.gr_restart_reason = restart_reason;
	restarter->gr_helper_info.rejected_reason = OSPF6_HELPER_REJECTED_NONE;

	/* Increment the active restart nbr count */
	ospf6->ospf6_helper_cfg.active_restarter_cnt++;

	if (IS_DEBUG_OSPF6_GR_HELPER)
		zlog_debug("%s, Grace timer started.interval:%u",
			   __func__, actual_grace_interval);

	/* Start the grace timer */
	thread_add_timer(master, ospf6_handle_grace_timer_expiry, restarter,
			 actual_grace_interval,
			 &restarter->gr_helper_info.t_grace_timer);

	return OSPF6_GR_ACTIVE_HELPER;
}

/* Debug commands */
DEFPY(debug_ospf6_gr,
      debug_ospf6_gr_cmd,
      "[no$no] debug ospf6 graceful-restart",
      NO_STR
      DEBUG_STR OSPF6_STR
      "Graceful restart\n")
{
	if (!no)
		OSPF6_DEBUG_GR_HELPER_ON();
	else
		OSPF6_DEBUG_GR_HELPER_OFF();

	return CMD_SUCCESS;
}

/*
 * Initialize GR helper config data structure.
 *
 * ospf6
 *    ospf6 pointer
 *
 * Returns:
 *    Nothing
 */
void ospf6_gr_helper_init(struct ospf6 *ospf6)
{
	if (IS_DEBUG_OSPF6_GR_HELPER)
		zlog_debug("%s, GR Helper init.", __func__);

	ospf6->ospf6_helper_cfg.is_helper_supported = OSPF6_FALSE;
	ospf6->ospf6_helper_cfg.strict_lsa_check = OSPF6_TRUE;
	ospf6->ospf6_helper_cfg.only_planned_restart = OSPF6_FALSE;
	ospf6->ospf6_helper_cfg.supported_grace_time = OSPF6_MAX_GRACE_INTERVAL;
	ospf6->ospf6_helper_cfg.last_exit_reason = OSPF6_GR_HELPER_EXIT_NONE;
	ospf6->ospf6_helper_cfg.active_restarter_cnt = 0;

	ospf6->ospf6_helper_cfg.enable_rtr_list = hash_create(
		ospf6_enable_rtr_hash_key, ospf6_enable_rtr_hash_cmp,
		"Ospf6 enable router hash");
}

/*
 * De-Initilise GR helper config datastructer.
 *
 * ospf6
 *    ospf6 pointer
 *
 * Returns:
 *    Nothing
 */
void ospf6_gr_helper_deinit(struct ospf6 *ospf6)
{

	if (IS_DEBUG_OSPF6_GR_HELPER)
		zlog_debug("%s, GR helper deinit.", __func__);

	ospf6_enable_rtr_hash_destroy(ospf6);
}
