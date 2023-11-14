/*
 * This is an implementation of RFC 5187 Graceful Restart.
 *
 * Copyright 2021 NetDEF (c), All rights reserved.
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

#include "memory.h"
#include "command.h"
#include "table.h"
#include "vty.h"
#include "log.h"
#include "hook.h"
#include "printfrr.h"

#include "ospf6d/ospf6_lsa.h"
#include "ospf6d/ospf6_lsdb.h"
#include "ospf6d/ospf6_route.h"
#include "ospf6d/ospf6_area.h"
#include "ospf6d/ospf6_interface.h"
#include "ospf6d/ospf6d.h"
#include "ospf6d/ospf6_asbr.h"
#include "ospf6d/ospf6_zebra.h"
#include "ospf6d/ospf6_message.h"
#include "ospf6d/ospf6_neighbor.h"
#include "ospf6d/ospf6_flood.h"
#include "ospf6d/ospf6_intra.h"
#include "ospf6d/ospf6_spf.h"
#include "ospf6d/ospf6_gr.h"
#ifndef VTYSH_EXTRACT_PL
#include "ospf6d/ospf6_gr_clippy.c"
#endif

static void ospf6_gr_nvm_delete(struct ospf6 *ospf6);

/* Originate and install Grace-LSA for a given interface. */
static int ospf6_gr_lsa_originate(struct ospf6_interface *oi)
{
	struct ospf6_gr_info *gr_info = &oi->area->ospf6->gr_info;
	struct ospf6_lsa_header *lsa_header;
	struct ospf6_grace_lsa *grace_lsa;
	struct ospf6_lsa *lsa;
	char buffer[OSPF6_MAX_LSASIZE];

	if (IS_OSPF6_DEBUG_ORIGINATE(LINK))
		zlog_debug("Originate Link-LSA for Interface %s",
			   oi->interface->name);

	/* prepare buffer */
	memset(buffer, 0, sizeof(buffer));
	lsa_header = (struct ospf6_lsa_header *)buffer;
	grace_lsa =
		(struct ospf6_grace_lsa *)((caddr_t)lsa_header
					   + sizeof(struct ospf6_lsa_header));

	/* Put grace period. */
	grace_lsa->tlv_period.header.type = htons(GRACE_PERIOD_TYPE);
	grace_lsa->tlv_period.header.length = htons(GRACE_PERIOD_LENGTH);
	grace_lsa->tlv_period.interval = htonl(gr_info->grace_period);

	/* Put restart reason. */
	grace_lsa->tlv_reason.header.type = htons(RESTART_REASON_TYPE);
	grace_lsa->tlv_reason.header.length = htons(RESTART_REASON_LENGTH);
	if (gr_info->restart_support)
		grace_lsa->tlv_reason.reason = OSPF6_GR_SW_RESTART;
	else
		grace_lsa->tlv_reason.reason = OSPF6_GR_UNKNOWN_RESTART;

	/* Fill LSA Header */
	lsa_header->age = 0;
	lsa_header->type = htons(OSPF6_LSTYPE_GRACE_LSA);
	lsa_header->id = htonl(oi->interface->ifindex);
	lsa_header->adv_router = oi->area->ospf6->router_id;
	lsa_header->seqnum =
		ospf6_new_ls_seqnum(lsa_header->type, lsa_header->id,
				    lsa_header->adv_router, oi->lsdb);
	lsa_header->length = htons(sizeof(*lsa_header) + sizeof(*grace_lsa));

	/* LSA checksum */
	ospf6_lsa_checksum(lsa_header);

	/* create LSA */
	lsa = ospf6_lsa_create(lsa_header);

	/* Originate */
	ospf6_lsa_originate_interface(lsa, oi);

	return 0;
}

/* Flush all self-originated Grace-LSAs. */
static void ospf6_gr_flush_grace_lsas(struct ospf6 *ospf6)
{
	struct ospf6_area *area;
	struct listnode *anode;

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, anode, area)) {
		struct ospf6_lsa *lsa;
		struct ospf6_interface *oi;
		struct listnode *inode;

		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"GR: flushing self-originated Grace-LSAs [area %pI4]",
				&area->area_id);

		for (ALL_LIST_ELEMENTS_RO(area->if_list, inode, oi)) {
			lsa = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_GRACE_LSA),
						htonl(oi->interface->ifindex),
						oi->area->ospf6->router_id,
						oi->lsdb);
			if (!lsa) {
				zlog_warn(
					"%s: Grace-LSA not found [interface %s] [area %pI4]",
					__func__, oi->interface->name,
					&area->area_id);
				continue;
			}

			ospf6_lsa_purge(lsa);
		}
	}
}

/* Exit from the Graceful Restart mode. */
static void ospf6_gr_restart_exit(struct ospf6 *ospf6, const char *reason)
{
	struct ospf6_area *area;
	struct listnode *onode, *anode;

	if (IS_DEBUG_OSPF6_GR)
		zlog_debug("GR: exiting graceful restart: %s", reason);

	ospf6->gr_info.restart_in_progress = false;
	ospf6->gr_info.finishing_restart = true;
	THREAD_OFF(ospf6->gr_info.t_grace_period);

	/* Record in non-volatile memory that the restart is complete. */
	ospf6_gr_nvm_delete(ospf6);

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, onode, area)) {
		struct ospf6_interface *oi;

		/*
		 * 1) The router should reoriginate its router-LSAs for all
		 *    attached areas in order to make sure they have the correct
		 *    contents.
		 */
		OSPF6_ROUTER_LSA_EXECUTE(area);

		for (ALL_LIST_ELEMENTS_RO(area->if_list, anode, oi)) {
			OSPF6_LINK_LSA_EXECUTE(oi);

			/*
			 * 2) The router should reoriginate network-LSAs on all
			 * segments where it is the Designated Router.
			 */
			if (oi->state == OSPF6_INTERFACE_DR)
				OSPF6_NETWORK_LSA_EXECUTE(oi);
		}
	}

	/*
	 * 3) The router reruns its OSPF routing calculations, this time
	 *    installing the results into the system forwarding table, and
	 *    originating summary-LSAs, Type-7 LSAs and AS-external-LSAs as
	 *    necessary.
	 *
	 * 4) Any remnant entries in the system forwarding table that were
	 *    installed before the restart, but that are no longer valid,
	 *    should be removed.
	 */
	ospf6_spf_schedule(ospf6, OSPF6_SPF_FLAGS_GR_FINISH);

	/* 6) Any grace-LSAs that the router originated should be flushed. */
	ospf6_gr_flush_grace_lsas(ospf6);
}

#define RTR_LSA_MISSING 0
#define RTR_LSA_ADJ_FOUND 1
#define RTR_LSA_ADJ_NOT_FOUND 2

/* Check if a Router-LSA exists and if it contains a given link. */
static int ospf6_router_lsa_contains_adj(struct ospf6_area *area,
					 in_addr_t adv_router,
					 in_addr_t neighbor_router_id)
{
	uint16_t type;
	struct ospf6_lsa *lsa;
	bool empty = true;

	type = ntohs(OSPF6_LSTYPE_ROUTER);
	for (ALL_LSDB_TYPED_ADVRTR(area->lsdb, type, adv_router, lsa)) {
		struct ospf6_router_lsa *router_lsa;
		char *start, *end, *current;

		empty = false;
		router_lsa = (struct ospf6_router_lsa
				      *)((char *)lsa->header
					 + sizeof(struct ospf6_lsa_header));

		/* Iterate over all interfaces in the Router-LSA. */
		start = (char *)router_lsa + sizeof(struct ospf6_router_lsa);
		end = (char *)lsa->header + ntohs(lsa->header->length);
		for (current = start;
		     current + sizeof(struct ospf6_router_lsdesc) <= end;
		     current += sizeof(struct ospf6_router_lsdesc)) {
			struct ospf6_router_lsdesc *lsdesc;

			lsdesc = (struct ospf6_router_lsdesc *)current;
			if (lsdesc->type != OSPF6_ROUTER_LSDESC_POINTTOPOINT)
				continue;

			if (lsdesc->neighbor_router_id == neighbor_router_id)
				return RTR_LSA_ADJ_FOUND;
		}
	}

	if (empty)
		return RTR_LSA_MISSING;

	return RTR_LSA_ADJ_NOT_FOUND;
}

static bool ospf6_gr_check_router_lsa_consistency(struct ospf6 *ospf6,
						  struct ospf6_area *area,
						  struct ospf6_lsa *lsa)
{
	if (lsa->header->adv_router == ospf6->router_id) {
		struct ospf6_router_lsa *router_lsa;
		char *start, *end, *current;

		router_lsa = (struct ospf6_router_lsa
				      *)((char *)lsa->header
					 + sizeof(struct ospf6_lsa_header));

		/* Iterate over all interfaces in the Router-LSA. */
		start = (char *)router_lsa + sizeof(struct ospf6_router_lsa);
		end = (char *)lsa->header + ntohs(lsa->header->length);
		for (current = start;
		     current + sizeof(struct ospf6_router_lsdesc) <= end;
		     current += sizeof(struct ospf6_router_lsdesc)) {
			struct ospf6_router_lsdesc *lsdesc;

			lsdesc = (struct ospf6_router_lsdesc *)current;
			if (lsdesc->type != OSPF6_ROUTER_LSDESC_POINTTOPOINT)
				continue;

			if (ospf6_router_lsa_contains_adj(
				    area, lsdesc->neighbor_router_id,
				    ospf6->router_id)
			    == RTR_LSA_ADJ_NOT_FOUND)
				return false;
		}
	} else {
		int adj1, adj2;

		adj1 = ospf6_router_lsa_contains_adj(area, ospf6->router_id,
						     lsa->header->adv_router);
		adj2 = ospf6_router_lsa_contains_adj(
			area, lsa->header->adv_router, ospf6->router_id);
		if ((adj1 == RTR_LSA_ADJ_FOUND && adj2 == RTR_LSA_ADJ_NOT_FOUND)
		    || (adj1 == RTR_LSA_ADJ_NOT_FOUND
			&& adj2 == RTR_LSA_ADJ_FOUND))
			return false;
	}

	return true;
}

/*
 * Check for LSAs that are inconsistent with the pre-restart LSAs, and abort the
 * ongoing graceful restart when that's the case.
 */
void ospf6_gr_check_lsdb_consistency(struct ospf6 *ospf6,
				     struct ospf6_area *area)
{
	uint16_t type;
	struct ospf6_lsa *lsa;

	type = ntohs(OSPF6_LSTYPE_ROUTER);
	for (ALL_LSDB_TYPED(area->lsdb, type, lsa)) {
		if (!ospf6_gr_check_router_lsa_consistency(ospf6, area, lsa)) {
			char reason[256];

			snprintfrr(reason, sizeof(reason),
				   "detected inconsistent LSA %s [area %pI4]",
				   lsa->name, &area->area_id);
			ospf6_gr_restart_exit(ospf6, reason);
			return;
		}
	}
}

/* Check if there's a fully formed adjacency with the given neighbor ID. */
static bool ospf6_gr_check_adj_id(struct ospf6_area *area,
				  in_addr_t neighbor_router_id)
{
	struct ospf6_neighbor *nbr;

	nbr = ospf6_area_neighbor_lookup(area, neighbor_router_id);
	if (!nbr || nbr->state < OSPF6_NEIGHBOR_FULL) {
		if (IS_DEBUG_OSPF6_GR)
			zlog_debug("GR: missing adjacency to router %pI4",
				   &neighbor_router_id);
		return false;
	}

	return true;
}

static bool ospf6_gr_check_adjs_lsa_transit(struct ospf6_area *area,
					    in_addr_t neighbor_router_id,
					    uint32_t neighbor_interface_id)
{
	struct ospf6 *ospf6 = area->ospf6;

	/* Check if we are the DR. */
	if (neighbor_router_id == ospf6->router_id) {
		struct ospf6_lsa *lsa;
		char *start, *end, *current;
		struct ospf6_network_lsa *network_lsa;
		struct ospf6_network_lsdesc *lsdesc;

		/* Lookup Network LSA corresponding to this interface. */
		lsa = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_NETWORK),
					neighbor_interface_id,
					neighbor_router_id, area->lsdb);
		if (!lsa)
			return false;

		/* Iterate over all routers present in the network. */
		network_lsa = (struct ospf6_network_lsa
				       *)((char *)lsa->header
					  + sizeof(struct ospf6_lsa_header));
		start = (char *)network_lsa + sizeof(struct ospf6_network_lsa);
		end = (char *)lsa->header + ntohs(lsa->header->length);
		for (current = start;
		     current + sizeof(struct ospf6_network_lsdesc) <= end;
		     current += sizeof(struct ospf6_network_lsdesc)) {
			lsdesc = (struct ospf6_network_lsdesc *)current;

			/* Skip self in the pseudonode. */
			if (lsdesc->router_id == ospf6->router_id)
				continue;

			/*
			 * Check if there's a fully formed adjacency with this
			 * router.
			 */
			if (!ospf6_gr_check_adj_id(area, lsdesc->router_id))
				return false;
		}
	} else {
		struct ospf6_neighbor *nbr;

		/* Check if there's a fully formed adjacency with the DR. */
		nbr = ospf6_area_neighbor_lookup(area, neighbor_router_id);
		if (!nbr || nbr->state < OSPF6_NEIGHBOR_FULL) {
			if (IS_DEBUG_OSPF6_GR)
				zlog_debug(
					"GR: missing adjacency to DR router %pI4",
					&neighbor_router_id);
			return false;
		}
	}

	return true;
}

static bool ospf6_gr_check_adjs_lsa(struct ospf6_area *area,
				    struct ospf6_lsa *lsa)
{
	struct ospf6_router_lsa *router_lsa;
	char *start, *end, *current;

	router_lsa =
		(struct ospf6_router_lsa *)((char *)lsa->header
					    + sizeof(struct ospf6_lsa_header));

	/* Iterate over all interfaces in the Router-LSA. */
	start = (char *)router_lsa + sizeof(struct ospf6_router_lsa);
	end = (char *)lsa->header + ntohs(lsa->header->length);
	for (current = start;
	     current + sizeof(struct ospf6_router_lsdesc) <= end;
	     current += sizeof(struct ospf6_router_lsdesc)) {
		struct ospf6_router_lsdesc *lsdesc;

		lsdesc = (struct ospf6_router_lsdesc *)current;
		switch (lsdesc->type) {
		case OSPF6_ROUTER_LSDESC_POINTTOPOINT:
			if (!ospf6_gr_check_adj_id(area,
						   lsdesc->neighbor_router_id))
				return false;
			break;
		case OSPF6_ROUTER_LSDESC_TRANSIT_NETWORK:
			if (!ospf6_gr_check_adjs_lsa_transit(
				    area, lsdesc->neighbor_router_id,
				    lsdesc->neighbor_interface_id))
				return false;
			break;
		default:
			break;
		}
	}

	return true;
}

/*
 * Check if all adjacencies prior to the restart were reestablished.
 *
 * This is done using pre-restart Router LSAs and pre-restart Network LSAs
 * received from the helping neighbors.
 */
static bool ospf6_gr_check_adjs(struct ospf6 *ospf6)
{
	struct ospf6_area *area;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, area)) {
		uint16_t type;
		uint32_t router;
		struct ospf6_lsa *lsa_self;
		bool found = false;

		type = ntohs(OSPF6_LSTYPE_ROUTER);
		router = ospf6->router_id;
		for (ALL_LSDB_TYPED_ADVRTR(area->lsdb, type, router,
					   lsa_self)) {
			found = true;
			if (!ospf6_gr_check_adjs_lsa(area, lsa_self))
				return false;
		}
		if (!found)
			return false;
	}

	return true;
}

/* Handling of grace period expiry. */
static int ospf6_gr_grace_period_expired(struct thread *thread)
{
	struct ospf6 *ospf6 = THREAD_ARG(thread);

	ospf6->gr_info.t_grace_period = NULL;
	ospf6_gr_restart_exit(ospf6, "grace period has expired");

	return 0;
}

/*
 * Record in non-volatile memory that the given OSPF instance is attempting to
 * perform a graceful restart.
 */
static void ospf6_gr_nvm_update(struct ospf6 *ospf6)
{
	const char *inst_name;
	json_object *json;
	json_object *json_instances;
	json_object *json_instance;

	inst_name = ospf6->name ? ospf6->name : VRF_DEFAULT_NAME;

	json = json_object_from_file((char *)OSPF6D_GR_STATE);
	if (json == NULL)
		json = json_object_new_object();

	json_object_object_get_ex(json, "instances", &json_instances);
	if (!json_instances) {
		json_instances = json_object_new_object();
		json_object_object_add(json, "instances", json_instances);
	}

	json_object_object_get_ex(json_instances, inst_name, &json_instance);
	if (!json_instance) {
		json_instance = json_object_new_object();
		json_object_object_add(json_instances, inst_name,
				       json_instance);
	}

	/*
	 * Record not only the grace period, but also a UNIX timestamp
	 * corresponding to the end of that period. That way, once ospf6d is
	 * restarted, it will be possible to take into account the time that
	 * passed while ospf6d wasn't running.
	 */
	json_object_int_add(json_instance, "gracePeriod",
			    ospf6->gr_info.grace_period);
	json_object_int_add(json_instance, "timestamp",
			    time(NULL) + ospf6->gr_info.grace_period);

	json_object_to_file_ext((char *)OSPF6D_GR_STATE, json,
				JSON_C_TO_STRING_PRETTY);
	json_object_free(json);
}

/*
 * Delete GR status information about the given OSPF instance from non-volatile
 * memory.
 */
static void ospf6_gr_nvm_delete(struct ospf6 *ospf6)
{
	const char *inst_name;
	json_object *json;
	json_object *json_instances;

	inst_name = ospf6->name ? ospf6->name : VRF_DEFAULT_NAME;

	json = json_object_from_file((char *)OSPF6D_GR_STATE);
	if (json == NULL)
		json = json_object_new_object();

	json_object_object_get_ex(json, "instances", &json_instances);
	if (!json_instances) {
		json_instances = json_object_new_object();
		json_object_object_add(json, "instances", json_instances);
	}

	json_object_object_del(json_instances, inst_name);

	json_object_to_file_ext((char *)OSPF6D_GR_STATE, json,
				JSON_C_TO_STRING_PRETTY);
	json_object_free(json);
}

/*
 * Fetch from non-volatile memory whether the given OSPF instance is performing
 * a graceful shutdown or not.
 */
void ospf6_gr_nvm_read(struct ospf6 *ospf6)
{
	const char *inst_name;
	json_object *json;
	json_object *json_instances;
	json_object *json_instance;
	json_object *json_timestamp;
	time_t timestamp = 0;

	inst_name = ospf6->name ? ospf6->name : VRF_DEFAULT_NAME;

	json = json_object_from_file((char *)OSPF6D_GR_STATE);
	if (json == NULL)
		json = json_object_new_object();

	json_object_object_get_ex(json, "instances", &json_instances);
	if (!json_instances) {
		json_instances = json_object_new_object();
		json_object_object_add(json, "instances", json_instances);
	}

	json_object_object_get_ex(json_instances, inst_name, &json_instance);
	if (!json_instance) {
		json_instance = json_object_new_object();
		json_object_object_add(json_instances, inst_name,
				       json_instance);
	}

	json_object_object_get_ex(json_instance, "timestamp", &json_timestamp);
	if (json_timestamp) {
		time_t now;
		unsigned long remaining_time;

		/* Check if the grace period has already expired. */
		now = time(NULL);
		timestamp = json_object_get_int(json_timestamp);
		if (now > timestamp) {
			ospf6_gr_restart_exit(
				ospf6, "grace period has expired already");
		} else {
			/* Schedule grace period timeout. */
			ospf6->gr_info.restart_in_progress = true;
			remaining_time = timestamp - time(NULL);
			if (IS_DEBUG_OSPF6_GR)
				zlog_debug(
					"GR: remaining time until grace period expires: %lu(s)",
					remaining_time);
			thread_add_timer(master, ospf6_gr_grace_period_expired,
					 ospf6, remaining_time,
					 &ospf6->gr_info.t_grace_period);
		}
	}

	json_object_object_del(json_instances, inst_name);

	json_object_to_file_ext((char *)OSPF6D_GR_STATE, json,
				JSON_C_TO_STRING_PRETTY);
	json_object_free(json);
}

/* Prepare to start a Graceful Restart. */
static void ospf6_gr_prepare(void)
{
	struct ospf6 *ospf6;
	struct ospf6_interface *oi;
	struct listnode *onode, *anode, *inode;

	for (ALL_LIST_ELEMENTS_RO(om6->ospf6, onode, ospf6)) {
		struct ospf6_area *area;

		if (!ospf6->gr_info.restart_support
		    || ospf6->gr_info.prepare_in_progress)
			continue;

		if (IS_DEBUG_OSPF6_GR)
			zlog_debug(
				"GR: preparing to perform a graceful restart [period %u second(s)] [vrf %s]",
				ospf6->gr_info.grace_period,
				ospf6_vrf_id_to_name(ospf6->vrf_id));

		/* Freeze OSPF routes in the RIB. */
		if (ospf6_zebra_gr_enable(ospf6, ospf6->gr_info.grace_period)) {
			zlog_warn(
				"%s: failed to activate graceful restart: not connected to zebra",
				__func__);
			continue;
		}

		/* Send a Grace-LSA to all neighbors. */
		for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, anode, area)) {
			for (ALL_LIST_ELEMENTS_RO(area->if_list, inode, oi)) {
				if (oi->state < OSPF6_INTERFACE_POINTTOPOINT)
					continue;
				ospf6_gr_lsa_originate(oi);
			}
		}

		/* Record end of the grace period in non-volatile memory. */
		ospf6_gr_nvm_update(ospf6);

		/*
		 * Mark that a Graceful Restart preparation is in progress, to
		 * prevent ospf6d from flushing its self-originated LSAs on
		 * exit.
		 */
		ospf6->gr_info.prepare_in_progress = true;
	}
}

static int ospf6_gr_neighbor_change(struct ospf6_neighbor *on, int next_state,
				    int prev_state)
{
	struct ospf6 *ospf6 = on->ospf6_if->area->ospf6;

	if (next_state == OSPF6_NEIGHBOR_FULL
	    && ospf6->gr_info.restart_in_progress) {
		if (ospf6_gr_check_adjs(ospf6)) {
			ospf6_gr_restart_exit(
				ospf6, "all adjacencies were reestablished");
		} else {
			if (IS_DEBUG_OSPF6_GR)
				zlog_debug(
					"GR: not all adjacencies were reestablished yet");
		}
	}

	return 0;
}

int config_write_ospf6_gr(struct vty *vty, struct ospf6 *ospf6)
{
	if (!ospf6->gr_info.restart_support)
		return 0;

	if (ospf6->gr_info.grace_period == OSPF6_DFLT_GRACE_INTERVAL)
		vty_out(vty, " graceful-restart\n");
	else
		vty_out(vty, " graceful-restart grace-period %u\n",
			ospf6->gr_info.grace_period);

	return 0;
}

DEFPY(ospf6_graceful_restart_prepare, ospf6_graceful_restart_prepare_cmd,
      "graceful-restart prepare ipv6 ospf",
      "Graceful Restart commands\n"
      "Prepare upcoming graceful restart\n" IPV6_STR
      "Prepare to restart the OSPFv3 process")
{
	ospf6_gr_prepare();

	return CMD_SUCCESS;
}

DEFPY(ospf6_graceful_restart, ospf6_graceful_restart_cmd,
      "graceful-restart [grace-period (1-1800)$grace_period]",
      OSPF_GR_STR
      "Maximum length of the 'grace period'\n"
      "Maximum length of the 'grace period' in seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf6, ospf6);

	/* Check and get restart period if present. */
	if (!grace_period_str)
		grace_period = OSPF6_DFLT_GRACE_INTERVAL;

	ospf6->gr_info.restart_support = true;
	ospf6->gr_info.grace_period = grace_period;

	return CMD_SUCCESS;
}

DEFPY(ospf6_no_graceful_restart, ospf6_no_graceful_restart_cmd,
      "no graceful-restart [period (1-1800)]",
      NO_STR OSPF_GR_STR
      "Maximum length of the 'grace period'\n"
      "Maximum length of the 'grace period' in seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf6, ospf6);

	if (!ospf6->gr_info.restart_support)
		return CMD_SUCCESS;

	if (ospf6->gr_info.prepare_in_progress) {
		vty_out(vty,
			"%% Error: Graceful Restart preparation in progress\n");
		return CMD_WARNING;
	}

	ospf6->gr_info.restart_support = false;
	ospf6->gr_info.grace_period = OSPF6_DFLT_GRACE_INTERVAL;

	return CMD_SUCCESS;
}

void ospf6_gr_init(void)
{
	hook_register(ospf6_neighbor_change, ospf6_gr_neighbor_change);

	install_element(ENABLE_NODE, &ospf6_graceful_restart_prepare_cmd);
	install_element(OSPF6_NODE, &ospf6_graceful_restart_cmd);
	install_element(OSPF6_NODE, &ospf6_no_graceful_restart_cmd);
}
