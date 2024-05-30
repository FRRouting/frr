// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * OSPF6 Graceful Restart helper functions.
 *
 * Copyright (C) 2021-22 Vmware, Inc.
 * Rajesh Kumar Girada
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
#include "ospf6d/ospf6_gr_helper_clippy.c"

DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_GR_HELPER, "OSPF6 Graceful restart helper");

unsigned char conf_debug_ospf6_gr;

static int ospf6_grace_lsa_show_info(struct vty *vty, struct ospf6_lsa *lsa,
				     json_object *json, bool use_json);

struct ospf6_lsa_handler grace_lsa_handler = {.lh_type = OSPF6_LSTYPE_GRACE_LSA,
					      .lh_name = "Grace",
					      .lh_short_name = "GR",
					      .lh_show =
						      ospf6_grace_lsa_show_info,
					      .lh_get_prefix_str = NULL,
					      .lh_debug = 0};

const char *ospf6_exit_reason_desc[] = {
	"Unknown reason",
	"Helper in progress",
	"Topology Change",
	"Grace timer expiry",
	"Successful graceful restart",
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

	hash_clean_and_free(&ospf6->ospf6_helper_cfg.enable_rtr_list,
			    ospf6_disable_rtr_hash_free);
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

	lsah = lsa->header;
	if (ntohs(lsah->length) <= OSPF6_LSA_HEADER_SIZE) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug("%s: undersized (%u B) lsa", __func__,
				   ntohs(lsah->length));
		return OSPF6_FAILURE;
	}

	length = ntohs(lsah->length) - OSPF6_LSA_HEADER_SIZE;

	for (tlvh = TLV_HDR_TOP(lsah); sum < length && tlvh;
	     tlvh = TLV_HDR_NEXT(tlvh)) {

		/* Check TLV len against overall LSA */
		if (sum + TLV_SIZE(tlvh) > length) {
			if (IS_DEBUG_OSPF6_GR)
				zlog_debug(
					"%s: Malformed packet: Invalid TLV len:%d",
					__func__, TLV_SIZE(tlvh));
			return OSPF6_FAILURE;
		}

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
			sum += TLV_SIZE(tlvh);
			if (IS_DEBUG_OSPF6_GR)
				zlog_debug("%s, Ignoring unknown TLV type:%d",
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
static void ospf6_handle_grace_timer_expiry(struct event *thread)
{
	struct ospf6_neighbor *nbr = EVENT_ARG(thread);

	ospf6_gr_helper_exit(nbr, OSPF6_GR_HELPER_GRACE_TIMEOUT);
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

		if (lsa_in_db && lsa_in_db->tobe_acknowledged) {
			ospf6_lsa_unlock(&lsa);
			if (lsanext)
				ospf6_lsa_unlock(&lsanext);

			return OSPF6_TRUE;
		}
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
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug("%s, Wrong Grace LSA packet.", __func__);
		return OSPF6_GR_NOT_HELPER;
	}

	if (IS_DEBUG_OSPF6_GR)
		zlog_debug(
			"%s, Grace LSA received from %s(%pI4), grace interval:%u, restart reason:%s",
			__func__, restarter->name, &restarter->router_id,
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
			if (IS_DEBUG_OSPF6_GR)
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
		if (IS_DEBUG_OSPF6_GR)
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
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"%s, Router supports only planned restarts but received the GRACE LSA due to an unplanned restart",
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
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"%s, Changed LSA in Rxmt list.So not Helper.",
				__func__);
		restarter->gr_helper_info.rejected_reason =
			OSPF6_HELPER_TOPO_CHANGE_RTXMT_LIST;
		return OSPF6_GR_NOT_HELPER;
	}

	/* LSA age must be less than the grace period */
	if (ntohs(lsa->header->age) >= grace_interval) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"%s, Grace LSA age(%d) is more than the grace interval(%d)",
				__func__, lsa->header->age, grace_interval);
		restarter->gr_helper_info.rejected_reason =
			OSPF6_HELPER_LSA_AGE_MORE;
		return OSPF6_GR_NOT_HELPER;
	}

	if (ospf6->gr_info.restart_in_progress) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"%s: router is in the process of graceful restart",
				__func__);
		restarter->gr_helper_info.rejected_reason =
			OSPF6_HELPER_RESTARTING;
		return OSPF6_GR_NOT_HELPER;
	}

	/* check supported grace period configured
	 * if configured, use this to start the grace
	 * timer otherwise use the interval received
	 * in grace LSA packet.
	 */
	actual_grace_interval = grace_interval;
	if (grace_interval > ospf6->ospf6_helper_cfg.supported_grace_time) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"%s, Received grace period %d is larger than supported grace %d",
				__func__, grace_interval,
				ospf6->ospf6_helper_cfg.supported_grace_time);
		actual_grace_interval =
			ospf6->ospf6_helper_cfg.supported_grace_time;
	}

	if (OSPF6_GR_IS_ACTIVE_HELPER(restarter)) {
		EVENT_OFF(restarter->gr_helper_info.t_grace_timer);

		if (ospf6->ospf6_helper_cfg.active_restarter_cnt > 0)
			ospf6->ospf6_helper_cfg.active_restarter_cnt--;

		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"%s, Router is already acting as a HELPER for this nbr,so restart the grace timer",
				__func__);
	} else {
		if (IS_DEBUG_OSPF6_GR)
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

	if (IS_DEBUG_OSPF6_GR)
		zlog_debug("%s, Grace timer started.interval:%u", __func__,
			   actual_grace_interval);

	/* Start the grace timer */
	event_add_timer(master, ospf6_handle_grace_timer_expiry, restarter,
			actual_grace_interval,
			&restarter->gr_helper_info.t_grace_timer);

	return OSPF6_GR_ACTIVE_HELPER;
}

/*
 * Api to exit from HELPER role to take all actions
 * required at exit.
 * Ref rfc3623 section 3. and rfc51872
 *
 * ospf6
 *    Ospf6 pointer.
 *
 * nbr
 *    Ospf6 neighbour for which it is acting as HELPER.
 *
 * reason
 *    The reason for exiting from HELPER.
 *
 * Returns:
 *    Nothing.
 */
void ospf6_gr_helper_exit(struct ospf6_neighbor *nbr,
			  enum ospf6_helper_exit_reason reason)
{
	struct ospf6_interface *oi = nbr->ospf6_if;
	struct ospf6 *ospf6;

	if (!oi)
		return;

	ospf6 = oi->area->ospf6;

	if (!OSPF6_GR_IS_ACTIVE_HELPER(nbr))
		return;

	if (IS_DEBUG_OSPF6_GR)
		zlog_debug("%s, Exiting from HELPER support to %pI6, due to %s",
			   __func__, &nbr->linklocal_addr,
			   ospf6_exit_reason_desc[reason]);

	/* Reset helper status*/
	nbr->gr_helper_info.gr_helper_status = OSPF6_GR_NOT_HELPER;
	nbr->gr_helper_info.helper_exit_reason = reason;
	nbr->gr_helper_info.actual_grace_period = 0;
	nbr->gr_helper_info.recvd_grace_period = 0;
	nbr->gr_helper_info.gr_restart_reason = 0;
	ospf6->ospf6_helper_cfg.last_exit_reason = reason;

	/* If the exit not triggered due to grace timer
	 * expiry, stop the grace timer.
	 */
	if (reason != OSPF6_GR_HELPER_GRACE_TIMEOUT)
		EVENT_OFF(nbr->gr_helper_info.t_grace_timer);

	if (ospf6->ospf6_helper_cfg.active_restarter_cnt <= 0) {
		zlog_err(
			"OSPF6 GR-Helper: Number of active Restarters should be greater than zero.");
		return;
	}
	/* Decrement active restarter count */
	ospf6->ospf6_helper_cfg.active_restarter_cnt--;

	/* check exit triggered due to successful completion
	 * of graceful restart.
	 */
	if (reason != OSPF6_GR_HELPER_COMPLETED) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug("%s, Unsuccessful GR exit. RESTARTER : %pI6",
				   __func__, &nbr->linklocal_addr);
	}

	/*Recalculate the DR for the network segment */
	dr_election(oi);

	/* Originate a router LSA */
	OSPF6_ROUTER_LSA_SCHEDULE(nbr->ospf6_if->area);

	/* Originate network lsa if it is an DR in the LAN */
	if (nbr->ospf6_if->state == OSPF6_INTERFACE_DR)
		OSPF6_NETWORK_LSA_SCHEDULE(nbr->ospf6_if);
}

/*
 * Process max age Grace LSA.
 * It is a indication for successful completion of GR.
 * If router acting as HELPER, It exits from helper role.
 *
 * ospf6
 *    Ospf6 pointer.
 *
 * lsa
 *    Grace LSA received from RESTARTER.
 *
 * nbr
 *    ospf6 neighbour which request the router to act as
 *    HELPER.
 *
 * Returns:
 *    Nothing.
 */
void ospf6_process_maxage_grace_lsa(struct ospf6 *ospf6, struct ospf6_lsa *lsa,
				    struct ospf6_neighbor *restarter)
{
	uint8_t restart_reason = 0;
	uint32_t grace_interval = 0;
	int ret;

	/* Extract the grace lsa packet fields */
	ret = ospf6_extract_grace_lsa_fields(lsa, &grace_interval,
					     &restart_reason);
	if (ret != OSPF6_SUCCESS) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug("%s, Wrong Grace LSA packet.", __func__);
		return;
	}

	if (IS_DEBUG_OSPF6_GR)
		zlog_debug("%s, GraceLSA received for neighbour %pI4.",
			   __func__, &restarter->router_id);

	ospf6_gr_helper_exit(restarter, OSPF6_GR_HELPER_COMPLETED);
}

/*
 * Actions to be taken  when topo change detected
 * HELPER will be exited upon a topo change.
 *
 * ospf6
 *    ospf6 pointer
 * lsa
 *    topo change occurred due to this lsa(type (1-5  and 7)
 *
 * Returns:
 *    Nothing
 */
void ospf6_helper_handle_topo_chg(struct ospf6 *ospf6, struct ospf6_lsa *lsa)
{
	struct listnode *i, *j, *k;
	struct ospf6_neighbor *nbr = NULL;
	struct ospf6_area *oa = NULL;
	struct ospf6_interface *oi = NULL;

	if (!ospf6->ospf6_helper_cfg.active_restarter_cnt)
		return;

	/* Topo change not required to be handled if strict
	 * LSA check is disabled for this router.
	 */
	if (!ospf6->ospf6_helper_cfg.strict_lsa_check)
		return;

	if (IS_DEBUG_OSPF6_GR)
		zlog_debug("%s, Topo change detected due to lsa details : %s",
			   __func__, lsa->name);

	lsa->tobe_acknowledged = OSPF6_TRUE;

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, i, oa))
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {

			/* Ref rfc3623 section 3.2.3.b and rfc5187
			 * If change due to external LSA and if the area is
			 * stub, then it is not a topo change. Since Type-5
			 * lsas will not be flooded in stub area.
			 */
			if (IS_AREA_STUB(oi->area)
			    && ((lsa->header->type == OSPF6_LSTYPE_AS_EXTERNAL)
				|| (lsa->header->type == OSPF6_LSTYPE_TYPE_7)
				|| (lsa->header->type
				    == OSPF6_LSTYPE_INTER_ROUTER))) {
				continue;
			}

			for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, k, nbr)) {

				ospf6_gr_helper_exit(nbr,
						     OSPF6_GR_HELPER_TOPO_CHG);
			}
		}
}

/* Configuration handlers */
/*
 * Disable/Enable HELPER support on router level.
 *
 * ospf6
 *    Ospf6 pointer.
 *
 * status
 *    TRUE/FALSE
 *
 * Returns:
 *    Nothing.
 */
static void ospf6_gr_helper_support_set(struct ospf6 *ospf6, bool support)
{
	struct ospf6_interface *oi;
	struct advRtr lookup;
	struct listnode *i, *j, *k;
	struct ospf6_neighbor *nbr = NULL;
	struct ospf6_area *oa = NULL;

	if (ospf6->ospf6_helper_cfg.is_helper_supported == support)
		return;

	ospf6->ospf6_helper_cfg.is_helper_supported = support;

	/* If helper support disabled, cease HELPER role for all
	 * supporting neighbors.
	 */
	if (support == OSPF6_FALSE) {
		for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, i, oa))
			for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {

				for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, k,
							  nbr)) {

					lookup.advRtrAddr = nbr->router_id;
					/* check if helper support enabled for
					 * the corresponding  routerid.
					 * If enabled,
					 * dont exit from helper role.
					 */
					if (hash_lookup(
						    ospf6->ospf6_helper_cfg
							    .enable_rtr_list,
						    &lookup))
						continue;

					ospf6_gr_helper_exit(
						nbr, OSPF6_GR_HELPER_TOPO_CHG);
				}
			}
	}
}

/*
 * Api to enable/disable strict lsa check on the HELPER.
 *
 * ospf6
 *    Ospf6 pointer.
 *
 * enabled
 *    True - disable the lsa check.
 *    False - enable the strict lsa check.
 *
 * Returns:
 *    Nothing.
 */
static void ospf6_gr_helper_lsacheck_set(struct ospf6 *ospf6, bool enabled)
{
	if (ospf6->ospf6_helper_cfg.strict_lsa_check == enabled)
		return;

	ospf6->ospf6_helper_cfg.strict_lsa_check = enabled;
}

/*
 * Api to set the supported restart reason.
 *
 * ospf6
 *    Ospf6 pointer.
 *
 * only_planned
 *    True: support only planned restart.
 *    False: support for planned/unplanned restarts.
 *
 * Returns:
 *    Nothing.
 */

static void
ospf6_gr_helper_set_supported_onlyPlanned_restart(struct ospf6 *ospf6,
						  bool only_planned)
{
	ospf6->ospf6_helper_cfg.only_planned_restart = only_planned;
}

/*
 * Api to set the supported grace interval in this router.
 *
 * ospf6
 *    Ospf6 pointer.
 *
 * interval
 *    The supported grace interval..
 *
 * Returns:
 *    Nothing.
 */
static void ospf6_gr_helper_supported_gracetime_set(struct ospf6 *ospf6,
						    uint32_t interval)
{
	ospf6->ospf6_helper_cfg.supported_grace_time = interval;
}

/* API to walk and print  all the Helper supported router ids */
static int ospf6_print_vty_helper_dis_rtr_walkcb(struct hash_bucket *bucket,
						 void *arg)
{
	struct advRtr *rtr = bucket->data;
	struct vty *vty = (struct vty *)arg;
	static unsigned int count;

	vty_out(vty, "%-6pI4,", &rtr->advRtrAddr);
	count++;

	if (count % 5 == 0)
		vty_out(vty, "\n");

	return HASHWALK_CONTINUE;
}

/* API to walk and print  all the Helper supported router ids.*/
static int ospf6_print_json_helper_dis_rtr_walkcb(struct hash_bucket *bucket,
						  void *arg)
{
	struct advRtr *rtr = bucket->data;
	struct json_object *json_rid_array = (struct json_object *)arg;
	struct json_object *json_rid;
	char router_id[16];

	inet_ntop(AF_INET, &rtr->advRtrAddr, router_id, sizeof(router_id));

	json_rid = json_object_new_object();

	json_object_string_add(json_rid, "routerId", router_id);
	json_object_array_add(json_rid_array, json_rid);

	return HASHWALK_CONTINUE;
}

/*
 * Enable/Disable HELPER support on a specified advertisement
 * router.
 *
 * ospf6
 *    Ospf6 pointer.
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
static void ospf6_gr_helper_support_set_per_routerid(struct ospf6 *ospf6,
						     struct in_addr router_id,
						     bool support)
{
	struct advRtr temp;
	struct advRtr *rtr;
	struct listnode *i, *j, *k;
	struct ospf6_interface *oi;
	struct ospf6_neighbor *nbr;
	struct ospf6_area *oa;

	temp.advRtrAddr = router_id.s_addr;

	if (support == OSPF6_FALSE) {
		/*Delete the routerid from the enable router hash table */
		rtr = hash_lookup(ospf6->ospf6_helper_cfg.enable_rtr_list,
				  &temp);

		if (rtr) {
			hash_release(ospf6->ospf6_helper_cfg.enable_rtr_list,
				     rtr);
			ospf6_disable_rtr_hash_free(rtr);
		}

		/* If helper support is enabled globally
		 * no action is required.
		 */
		if (ospf6->ospf6_helper_cfg.is_helper_supported)
			return;

		/* Cease the HELPER role fore neighbours from the
		 * specified advertisement router.
		 */
		for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, i, oa))
			for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {

				for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, k,
							  nbr)) {

					if (nbr->router_id != router_id.s_addr)
						continue;

					if (OSPF6_GR_IS_ACTIVE_HELPER(nbr))
						ospf6_gr_helper_exit(
						nbr,
						OSPF6_GR_HELPER_TOPO_CHG);
				}
			}

	} else {
		/* Add the routerid to the enable router hash table */
		(void)hash_get(ospf6->ospf6_helper_cfg.enable_rtr_list, &temp,
			       ospf6_enable_rtr_hash_alloc);
	}
}

static void show_ospfv6_gr_helper_per_nbr(struct vty *vty, json_object *json,
					  bool uj, struct ospf6_neighbor *nbr)
{
	if (!uj) {
		vty_out(vty, "   Routerid : %pI4\n", &nbr->router_id);
		vty_out(vty, "   Received Grace period : %d(in seconds).\n",
			nbr->gr_helper_info.recvd_grace_period);
		vty_out(vty, "   Actual Grace period : %d(in seconds)\n",
			nbr->gr_helper_info.actual_grace_period);
		vty_out(vty, "   Remaining GraceTime:%ld(in seconds).\n",
			event_timer_remain_second(
				nbr->gr_helper_info.t_grace_timer));
		vty_out(vty, "   Graceful Restart reason: %s.\n\n",
			ospf6_restart_reason_desc[nbr->gr_helper_info
							  .gr_restart_reason]);
	} else {
		char nbrid[16];
		json_object *json_neigh = NULL;

		inet_ntop(AF_INET, &nbr->router_id, nbrid, sizeof(nbrid));
		json_neigh = json_object_new_object();
		json_object_string_add(json_neigh, "routerid", nbrid);
		json_object_int_add(json_neigh, "recvdGraceInterval",
				    nbr->gr_helper_info.recvd_grace_period);
		json_object_int_add(json_neigh, "actualGraceInterval",
			nbr->gr_helper_info.actual_grace_period);
		json_object_int_add(json_neigh, "remainGracetime",
				    event_timer_remain_second(
					    nbr->gr_helper_info.t_grace_timer));
		json_object_string_add(json_neigh, "restartReason",
			ospf6_restart_reason_desc[
				nbr->gr_helper_info.gr_restart_reason]);
		json_object_object_add(json, nbr->name, json_neigh);
	}
}

static void show_ospf6_gr_helper_details(struct vty *vty, struct ospf6 *ospf6,
					json_object *json, bool uj, bool detail)
{
	struct ospf6_interface *oi;

	/* Show Router ID. */
	if (uj) {
		char router_id[16];

		inet_ntop(AF_INET, &ospf6->router_id, router_id,
			  sizeof(router_id));
		json_object_string_add(json, "routerId", router_id);
	} else
		vty_out(vty,
			" OSPFv3 Routing Process (0) with Router-ID %pI4\n",
			&ospf6->router_id);

	if (!uj) {

		if (ospf6->ospf6_helper_cfg.is_helper_supported)
			vty_out(vty,
				" Graceful restart helper support enabled.\n");
		else
			vty_out(vty,
				" Graceful restart helper support disabled.\n");

		if (ospf6->ospf6_helper_cfg.strict_lsa_check)
			vty_out(vty, " Strict LSA check is enabled.\n");
		else
			vty_out(vty, " Strict LSA check is disabled.\n");

		if (ospf6->ospf6_helper_cfg.only_planned_restart)
			vty_out(vty,
				" Helper supported for planned restarts only.\n");
		else
			vty_out(vty,
				" Helper supported for Planned and Unplanned Restarts.\n");

		vty_out(vty,
			" Supported Graceful restart interval: %d(in seconds).\n",
			ospf6->ospf6_helper_cfg.supported_grace_time);

		if (OSPF6_HELPER_ENABLE_RTR_COUNT(ospf)) {
			vty_out(vty, " Enable Router list:\n");
			vty_out(vty, "   ");
			hash_walk(ospf6->ospf6_helper_cfg.enable_rtr_list,
				  ospf6_print_vty_helper_dis_rtr_walkcb, vty);
			vty_out(vty, "\n\n");
		}

		if (ospf6->ospf6_helper_cfg.last_exit_reason
		    != OSPF6_GR_HELPER_EXIT_NONE) {
			vty_out(vty, " Last Helper exit Reason :%s\n",
				ospf6_exit_reason_desc
					[ospf6->ospf6_helper_cfg
						 .last_exit_reason]);

			if (ospf6->ospf6_helper_cfg.active_restarter_cnt)
				vty_out(vty,
					" Number of Active neighbours in graceful restart: %d\n",
					ospf6->ospf6_helper_cfg
						.active_restarter_cnt);
			else
				vty_out(vty, "\n");
		}


	} else {
		json_object_string_add(
			json, "helperSupport",
			(ospf6->ospf6_helper_cfg.is_helper_supported)
				? "Enabled"
				: "Disabled");
		json_object_string_add(
			json, "strictLsaCheck",
			(ospf6->ospf6_helper_cfg.strict_lsa_check)
				? "Enabled"
				: "Disabled");

		json_object_string_add(
			json, "restartSupport",
			(ospf6->ospf6_helper_cfg.only_planned_restart)
				? "Planned Restart only"
				: "Planned and Unplanned Restarts");

		json_object_int_add(
			json, "supportedGracePeriod",
			ospf6->ospf6_helper_cfg.supported_grace_time);

		if (ospf6->ospf6_helper_cfg.last_exit_reason !=
		    OSPF6_GR_HELPER_EXIT_NONE)
			json_object_string_add(
				json, "lastExitReason",
				ospf6_exit_reason_desc
					[ospf6->ospf6_helper_cfg
						 .last_exit_reason]);

		if (ospf6->ospf6_helper_cfg.active_restarter_cnt)
			json_object_int_add(
				json, "activeRestarterCnt",
				ospf6->ospf6_helper_cfg.active_restarter_cnt);

		if (OSPF6_HELPER_ENABLE_RTR_COUNT(ospf6)) {
			struct json_object *json_rid_array =
				json_object_new_array();

			json_object_object_add(json, "enabledRouterIds",
					       json_rid_array);

			hash_walk(ospf6->ospf6_helper_cfg.enable_rtr_list,
				  ospf6_print_json_helper_dis_rtr_walkcb,
				  json_rid_array);
		}
	}

	if (detail) {
		int cnt = 1;
		struct listnode *i, *j, *k;
		struct ospf6_area *oa;
		json_object *json_neighbors = NULL;

		for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, i, oa))
			for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi)) {
				struct ospf6_neighbor *nbr;

				if (uj) {
					json_object_object_get_ex(
						json, "neighbors",
						&json_neighbors);
					if (!json_neighbors) {
						json_neighbors =
						json_object_new_object();
						json_object_object_add(
							json, "neighbors",
							json_neighbors);
					}
				}

				for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, k,
							  nbr)) {

					if (!OSPF6_GR_IS_ACTIVE_HELPER(nbr))
						continue;

					if (!uj)
						vty_out(vty,
							" Neighbour %d :\n",
							cnt++);

					show_ospfv6_gr_helper_per_nbr(
						vty, json_neighbors, uj, nbr);

				}
			}
	}
}

/* Graceful Restart HELPER  config Commands */
DEFPY(ospf6_gr_helper_enable,
      ospf6_gr_helper_enable_cmd,
      "graceful-restart helper enable [A.B.C.D$rtr_id]",
      "ospf6 graceful restart\n"
      "ospf6 GR Helper\n"
      "Enable Helper support\n"
      "Advertisement Router-ID\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	if (rtr_id_str != NULL) {

		ospf6_gr_helper_support_set_per_routerid(ospf6, rtr_id,
							 OSPF6_TRUE);

		return CMD_SUCCESS;
	}

	ospf6_gr_helper_support_set(ospf6, OSPF6_TRUE);

	return CMD_SUCCESS;
}

DEFPY(ospf6_gr_helper_disable,
      ospf6_gr_helper_disable_cmd,
      "no graceful-restart helper enable [A.B.C.D$rtr_id]",
      NO_STR
      "ospf6 graceful restart\n"
      "ospf6 GR Helper\n"
      "Enable Helper support\n"
      "Advertisement Router-ID\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	if (rtr_id_str != NULL) {

		ospf6_gr_helper_support_set_per_routerid(ospf6, rtr_id,
							 OSPF6_FALSE);

		return CMD_SUCCESS;
	}

	ospf6_gr_helper_support_set(ospf6, OSPF6_FALSE);

	return CMD_SUCCESS;
}

DEFPY(ospf6_gr_helper_disable_lsacheck,
      ospf6_gr_helper_disable_lsacheck_cmd,
      "graceful-restart helper lsa-check-disable",
      "ospf6 graceful restart\n"
      "ospf6 GR Helper\n"
      "disable strict LSA check\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	ospf6_gr_helper_lsacheck_set(ospf6, OSPF6_FALSE);
	return CMD_SUCCESS;
}

DEFPY(no_ospf6_gr_helper_disable_lsacheck,
      no_ospf6_gr_helper_disable_lsacheck_cmd,
      "no graceful-restart helper lsa-check-disable",
      NO_STR
      "ospf6 graceful restart\n"
      "ospf6 GR Helper\n"
      "diasble strict LSA check\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	ospf6_gr_helper_lsacheck_set(ospf6, OSPF6_TRUE);
	return CMD_SUCCESS;
}

DEFPY(ospf6_gr_helper_planned_only,
      ospf6_gr_helper_planned_only_cmd,
      "graceful-restart helper planned-only",
      "ospf6 graceful restart\n"
      "ospf6 GR Helper\n"
      "supported only planned restart\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	ospf6_gr_helper_set_supported_onlyPlanned_restart(ospf6, OSPF6_TRUE);

	return CMD_SUCCESS;
}

DEFPY(no_ospf6_gr_helper_planned_only, no_ospf6_gr_helper_planned_only_cmd,
      "no graceful-restart helper planned-only",
      NO_STR
      "ospf6 graceful restart\n"
      "ospf6 GR Helper\n"
      "supported only for planned restart\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	ospf6_gr_helper_set_supported_onlyPlanned_restart(ospf6, OSPF6_FALSE);

	return CMD_SUCCESS;
}

DEFPY(ospf6_gr_helper_supported_grace_time,
      ospf6_gr_helper_supported_grace_time_cmd,
      "graceful-restart helper supported-grace-time (10-1800)$interval",
      "ospf6 graceful restart\n"
      "ospf6 GR Helper\n"
      "supported grace timer\n"
      "grace interval(in seconds)\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	ospf6_gr_helper_supported_gracetime_set(ospf6, interval);
	return CMD_SUCCESS;
}

DEFPY(no_ospf6_gr_helper_supported_grace_time,
      no_ospf6_gr_helper_supported_grace_time_cmd,
      "no graceful-restart helper supported-grace-time (10-1800)$interval",
      NO_STR
      "ospf6 graceful restart\n"
      "ospf6 GR Helper\n"
      "supported grace timer\n"
      "grace interval(in seconds)\n")
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf6);

	ospf6_gr_helper_supported_gracetime_set(ospf6,
						OSPF6_MAX_GRACE_INTERVAL);
	return CMD_SUCCESS;
}

/* Show commands */
DEFPY(show_ipv6_ospf6_gr_helper,
      show_ipv6_ospf6_gr_helper_cmd,
      "show ipv6 ospf6 graceful-restart helper [detail] [json]",
      SHOW_STR
      "Ipv6 Information\n"
      "OSPF6 information\n"
      "ospf6 graceful restart\n"
      "helper details in the router\n"
      "detailed information\n" JSON_STR)
{
	int idx = 0;
	bool uj = use_json(argc, argv);
	struct ospf6 *ospf6 = NULL;
	json_object *json = NULL;
	bool detail = false;

	ospf6 = ospf6_lookup_by_vrf_name(VRF_DEFAULT_NAME);
	if (ospf6 == NULL) {
		vty_out(vty, "OSPFv3 is not configured\n");
		return CMD_SUCCESS;
	}

	if (argv_find(argv, argc, "detail", &idx))
		detail = true;

	if (uj)
		json = json_object_new_object();

	show_ospf6_gr_helper_details(vty, ospf6, json, uj, detail);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/* Debug commands */
DEFPY(debug_ospf6_gr, debug_ospf6_gr_cmd,
      "[no$no] debug ospf6 graceful-restart",
      NO_STR DEBUG_STR OSPF6_STR "Graceful restart\n")
{
	if (!no)
		OSPF6_DEBUG_GR_ON();
	else
		OSPF6_DEBUG_GR_OFF();

	return CMD_SUCCESS;
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
static int ospf6_grace_lsa_show_info(struct vty *vty, struct ospf6_lsa *lsa,
				     json_object *json, bool use_json)
{
	struct ospf6_lsa_header *lsah = NULL;
	struct tlv_header *tlvh = NULL;
	struct grace_tlv_graceperiod *gracePeriod;
	struct grace_tlv_restart_reason *grReason;
	uint16_t length = 0;
	int sum = 0;

	lsah = lsa->header;
	if (ntohs(lsah->length) <= OSPF6_LSA_HEADER_SIZE) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug("%s: undersized (%u B) lsa", __func__,
				   ntohs(lsah->length));
		return OSPF6_FAILURE;
	}

	length = ntohs(lsah->length) - OSPF6_LSA_HEADER_SIZE;

	if (vty) {
		if (!use_json)
			vty_out(vty, "TLV info:\n");
	} else {
		zlog_debug("  TLV info:");
	}

	for (tlvh = TLV_HDR_TOP(lsah); sum < length && tlvh;
	     tlvh = TLV_HDR_NEXT(tlvh)) {

		/* Check TLV len */
		if (sum + TLV_SIZE(tlvh) > length) {
			if (vty)
				vty_out(vty, "%% Invalid TLV length: %d\n",
					TLV_SIZE(tlvh));
			else if (IS_DEBUG_OSPF6_GR)
				zlog_debug("%% Invalid TLV length: %d",
					   TLV_SIZE(tlvh));
			return OSPF6_FAILURE;
		}

		switch (ntohs(tlvh->type)) {
		case GRACE_PERIOD_TYPE:
			gracePeriod = (struct grace_tlv_graceperiod *)tlvh;
			sum += TLV_SIZE(tlvh);

			if (vty) {
				if (use_json)
					json_object_int_add(
						json, "gracePeriod",
						ntohl(gracePeriod->interval));
				else
					vty_out(vty, "   Grace period:%d\n",
						ntohl(gracePeriod->interval));
			} else {
				zlog_debug("    Grace period:%d",
					   ntohl(gracePeriod->interval));
			}
			break;
		case RESTART_REASON_TYPE:
			grReason = (struct grace_tlv_restart_reason *)tlvh;
			sum += TLV_SIZE(tlvh);
			if (vty) {
				if (use_json)
					json_object_string_add(
						json, "restartReason",
						ospf6_restart_reason_desc
							[grReason->reason]);
				else
					vty_out(vty, "   Restart reason:%s\n",
						ospf6_restart_reason_desc
							[grReason->reason]);
			} else {
				zlog_debug("    Restart reason:%s",
					   ospf6_restart_reason_desc
						   [grReason->reason]);
			}
			break;
		default:
			break;
		}
	}

	return 0;
}

void ospf6_gr_helper_config_init(void)
{

	ospf6_install_lsa_handler(&grace_lsa_handler);

	install_element(OSPF6_NODE, &ospf6_gr_helper_enable_cmd);
	install_element(OSPF6_NODE, &ospf6_gr_helper_disable_cmd);
	install_element(OSPF6_NODE, &ospf6_gr_helper_disable_lsacheck_cmd);
	install_element(OSPF6_NODE, &no_ospf6_gr_helper_disable_lsacheck_cmd);
	install_element(OSPF6_NODE, &ospf6_gr_helper_planned_only_cmd);
	install_element(OSPF6_NODE, &no_ospf6_gr_helper_planned_only_cmd);
	install_element(OSPF6_NODE, &ospf6_gr_helper_supported_grace_time_cmd);
	install_element(OSPF6_NODE,
			&no_ospf6_gr_helper_supported_grace_time_cmd);

	install_element(VIEW_NODE, &show_ipv6_ospf6_gr_helper_cmd);

	install_element(CONFIG_NODE, &debug_ospf6_gr_cmd);
	install_element(ENABLE_NODE, &debug_ospf6_gr_cmd);
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
	if (IS_DEBUG_OSPF6_GR)
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
 * De-initialize GR helper config data structure.
 *
 * ospf6
 *    ospf6 pointer
 *
 * Returns:
 *    Nothing
 */
void ospf6_gr_helper_deinit(struct ospf6 *ospf6)
{

	if (IS_DEBUG_OSPF6_GR)
		zlog_debug("%s, GR helper deinit.", __func__);

	ospf6_enable_rtr_hash_destroy(ospf6);
}

static int ospf6_cfg_write_helper_enable_rtr_walkcb(struct hash_bucket *backet,
						    void *arg)
{
	struct advRtr *rtr = backet->data;
	struct vty *vty = (struct vty *)arg;

	vty_out(vty, " graceful-restart helper enable %pI4\n", &rtr->advRtrAddr);
	return HASHWALK_CONTINUE;
}

int config_write_ospf6_gr_helper(struct vty *vty, struct ospf6 *ospf6)
{
	if (ospf6->ospf6_helper_cfg.is_helper_supported)
		vty_out(vty, " graceful-restart helper enable\n");

	if (!ospf6->ospf6_helper_cfg.strict_lsa_check)
		vty_out(vty, " graceful-restart helper lsa-check-disable\n");

	if (ospf6->ospf6_helper_cfg.only_planned_restart)
		vty_out(vty, " graceful-restart helper planned-only\n");

	if (ospf6->ospf6_helper_cfg.supported_grace_time
	    != OSPF6_MAX_GRACE_INTERVAL)
		vty_out(vty,
			" graceful-restart helper supported-grace-time %d\n",
			ospf6->ospf6_helper_cfg.supported_grace_time);

	if (OSPF6_HELPER_ENABLE_RTR_COUNT(ospf6)) {
		hash_walk(ospf6->ospf6_helper_cfg.enable_rtr_list,
			  ospf6_cfg_write_helper_enable_rtr_walkcb, vty);
	}

	return 0;
}

int config_write_ospf6_debug_gr_helper(struct vty *vty)
{
	if (IS_DEBUG_OSPF6_GR)
		vty_out(vty, "debug ospf6 graceful-restart\n");
	return 0;
}
