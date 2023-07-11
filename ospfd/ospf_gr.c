// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This is an implementation of RFC 3623 Graceful OSPF Restart.
 *
 * Copyright 2021 NetDEF (c), All rights reserved.
 * Copyright 2020 6WIND (c), All rights reserved.
 */

#include <zebra.h>

#include "memory.h"
#include "command.h"
#include "table.h"
#include "vty.h"
#include "log.h"
#include "printfrr.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_opaque.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_gr.h"
#include "ospfd/ospf_errors.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_gr_clippy.c"

static void ospf_gr_grace_period_expired(struct event *thread);

/* Lookup self-originated Grace-LSA in the LSDB. */
static struct ospf_lsa *ospf_gr_lsa_lookup(struct ospf *ospf,
					   struct ospf_area *area)
{
	struct ospf_lsa *lsa;
	struct in_addr lsa_id;
	uint32_t lsa_id_host_byte_order;

	lsa_id_host_byte_order = SET_OPAQUE_LSID(OPAQUE_TYPE_GRACE_LSA, 0);
	lsa_id.s_addr = htonl(lsa_id_host_byte_order);
	lsa = ospf_lsa_lookup(ospf, area, OSPF_OPAQUE_LINK_LSA, lsa_id,
			      ospf->router_id);

	return lsa;
}

/* Fill in fields of the Grace-LSA that is being originated. */
static void ospf_gr_lsa_body_set(struct ospf_gr_info *gr_info,
				 struct ospf_interface *oi,
				 enum ospf_gr_restart_reason reason,
				 struct stream *s)
{
	struct grace_tlv_graceperiod tlv_period = {};
	struct grace_tlv_restart_reason tlv_reason = {};
	struct grace_tlv_restart_addr tlv_address = {};

	/* Put grace period. */
	tlv_period.header.type = htons(GRACE_PERIOD_TYPE);
	tlv_period.header.length = htons(GRACE_PERIOD_LENGTH);
	tlv_period.interval = htonl(gr_info->grace_period);
	stream_put(s, &tlv_period, sizeof(tlv_period));

	/* Put restart reason. */
	tlv_reason.header.type = htons(RESTART_REASON_TYPE);
	tlv_reason.header.length = htons(RESTART_REASON_LENGTH);
	tlv_reason.reason = reason;
	stream_put(s, &tlv_reason, sizeof(tlv_reason));

	/* Put IP address. */
	if (oi->type == OSPF_IFTYPE_BROADCAST || oi->type == OSPF_IFTYPE_NBMA
	    || oi->type == OSPF_IFTYPE_POINTOMULTIPOINT) {
		tlv_address.header.type = htons(RESTARTER_IP_ADDR_TYPE);
		tlv_address.header.length = htons(RESTARTER_IP_ADDR_LEN);
		tlv_address.addr = oi->address->u.prefix4;
		stream_put(s, &tlv_address, sizeof(tlv_address));
	}
}

/* Generate Grace-LSA for a given interface. */
static struct ospf_lsa *ospf_gr_lsa_new(struct ospf_interface *oi,
					enum ospf_gr_restart_reason reason)
{
	struct stream *s;
	struct lsa_header *lsah;
	struct ospf_lsa *new;
	uint8_t options, lsa_type;
	struct in_addr lsa_id;
	uint32_t lsa_id_host_byte_order;
	uint16_t length;

	/* Create a stream for LSA. */
	s = stream_new(OSPF_MAX_LSA_SIZE);

	lsah = (struct lsa_header *)STREAM_DATA(s);

	options = LSA_OPTIONS_GET(oi->area);
	options |= LSA_OPTIONS_NSSA_GET(oi->area);
	options |= OSPF_OPTION_O;

	lsa_type = OSPF_OPAQUE_LINK_LSA;
	lsa_id_host_byte_order = SET_OPAQUE_LSID(OPAQUE_TYPE_GRACE_LSA, 0);
	lsa_id.s_addr = htonl(lsa_id_host_byte_order);

	/* Set opaque-LSA header fields. */
	lsa_header_set(s, options, lsa_type, lsa_id, oi->ospf->router_id);

	/* Set opaque-LSA body fields. */
	ospf_gr_lsa_body_set(&oi->ospf->gr_info, oi, reason, s);

	/* Set length. */
	length = stream_get_endp(s);
	lsah->length = htons(length);

	/* Now, create an OSPF LSA instance. */
	new = ospf_lsa_new_and_data(length);

	if (IS_DEBUG_OSPF_GR)
		zlog_debug("LSA[Type%d:%pI4]: Create an Opaque-LSA/GR instance",
			   lsa_type, &lsa_id);

	new->area = oi->area;
	new->oi = oi;
	SET_FLAG(new->flags, OSPF_LSA_SELF);
	memcpy(new->data, lsah, length);
	stream_free(s);

	return new;
}

/* Originate and install Grace-LSA for a given interface. */
static void ospf_gr_lsa_originate(struct ospf_interface *oi,
				  enum ospf_gr_restart_reason reason,
				  bool maxage)
{
	struct ospf_lsa *lsa, *old;

	/* Skip originating a Grace-LSA when not necessary. */
	if (!if_is_operative(oi->ifp) || if_is_loopback(oi->ifp) ||
	    (reason != OSPF_GR_UNKNOWN_RESTART &&
	     ospf_interface_neighbor_count(oi) == 0))
		return;

	/* Create new Grace-LSA. */
	lsa = ospf_gr_lsa_new(oi, reason);
	if (!lsa) {
		zlog_warn("%s: ospf_gr_lsa_new() failed", __func__);
		return;
	}

	if (maxage)
		lsa->data->ls_age = htons(OSPF_LSA_MAXAGE);

	/* Find the old LSA and increase the seqno. */
	old = ospf_gr_lsa_lookup(oi->ospf, oi->area);
	if (old)
		lsa->data->ls_seqnum = lsa_seqnum_increment(old);

	if (!maxage && reason == OSPF_GR_UNKNOWN_RESTART) {
		struct list *update;
		struct in_addr addr;

		/*
		 * When performing an unplanned restart, send a handcrafted
		 * Grace-LSA since the interface isn't fully initialized yet.
		 */
		ospf_lsa_checksum(lsa->data);
		ospf_lsa_lock(lsa);
		update = list_new();
		listnode_add(update, lsa);
		addr.s_addr = htonl(OSPF_ALLSPFROUTERS);
		ospf_ls_upd_queue_send(oi, update, addr, true);
		list_delete(&update);
		ospf_lsa_discard(lsa);
	} else {
		/* Install this LSA into LSDB. */
		if (ospf_lsa_install(oi->ospf, oi, lsa) == NULL) {
			zlog_warn("%s: ospf_lsa_install() failed", __func__);
			ospf_lsa_unlock(&lsa);
			return;
		}

		/* Flood the LSA through out the interface */
		ospf_flood_through_interface(oi, NULL, lsa);
	}

	/* Update new LSA origination count. */
	oi->ospf->lsa_originate_count++;
}

/* Flush all self-originated Grace-LSAs. */
static void ospf_gr_flush_grace_lsas(struct ospf *ospf)
{
	struct ospf_area *area;
	struct listnode *anode;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, anode, area)) {
		struct ospf_interface *oi;
		struct listnode *inode;

		for (ALL_LIST_ELEMENTS_RO(area->oiflist, inode, oi)) {
			if (IS_DEBUG_OSPF_GR)
				zlog_debug(
					"GR: flushing self-originated Grace-LSA [area %pI4] [interface %s]",
					&area->area_id, oi->ifp->name);

			ospf_gr_lsa_originate(oi, ospf->gr_info.reason, true);
		}
	}
}

/* Exit from the Graceful Restart mode. */
static void ospf_gr_restart_exit(struct ospf *ospf, const char *reason)
{
	struct ospf_area *area;
	struct listnode *onode, *anode;

	if (IS_DEBUG_OSPF_GR)
		zlog_debug("GR: exiting graceful restart: %s", reason);

	ospf->gr_info.restart_in_progress = false;
	EVENT_OFF(ospf->gr_info.t_grace_period);

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, onode, area)) {
		struct ospf_interface *oi;

		/*
		 * 1) The router should reoriginate its router-LSAs for all
		 *    attached areas in order to make sure they have the correct
		 *    contents.
		 */
		ospf_router_lsa_update_area(area);

		for (ALL_LIST_ELEMENTS_RO(area->oiflist, anode, oi)) {
			/* Disable hello delay. */
			if (oi->gr.hello_delay.t_grace_send) {
				oi->gr.hello_delay.elapsed_seconds = 0;
				EVENT_OFF(oi->gr.hello_delay.t_grace_send);
				OSPF_ISM_TIMER_MSEC_ON(oi->t_hello,
						       ospf_hello_timer, 1);
			}

			/*
			 * 2) The router should reoriginate network-LSAs on all
			 * segments where it is the Designated Router.
			 */
			if (oi->state == ISM_DR)
				ospf_network_lsa_update(oi);
		}
	}

	/*
	 * 5) Any received self-originated LSAs that are no longer valid should
	 *    be flushed.
	 */
	ospf_schedule_abr_task(ospf);

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
	ospf->gr_info.finishing_restart = true;
	XFREE(MTYPE_TMP, ospf->gr_info.exit_reason);
	ospf->gr_info.exit_reason = XSTRDUP(MTYPE_TMP, reason);
	ospf_spf_calculate_schedule(ospf, SPF_FLAG_GR_FINISH);

	/* 6) Any grace-LSAs that the router originated should be flushed. */
	ospf_gr_flush_grace_lsas(ospf);
}

/* Enter the Graceful Restart mode. */
void ospf_gr_restart_enter(struct ospf *ospf,
			   enum ospf_gr_restart_reason reason, time_t timestamp)
{
	unsigned long remaining_time;

	ospf->gr_info.restart_in_progress = true;
	ospf->gr_info.reason = reason;

	/* Schedule grace period timeout. */
	remaining_time = timestamp - time(NULL);
	if (IS_DEBUG_OSPF_GR)
		zlog_debug(
			"GR: remaining time until grace period expires: %lu(s)",
			remaining_time);

	event_add_timer(master, ospf_gr_grace_period_expired, ospf,
			remaining_time, &ospf->gr_info.t_grace_period);
}

/* Check if a Router-LSA contains a given link. */
static bool ospf_router_lsa_contains_adj(struct ospf_lsa *lsa,
					 struct in_addr *id)
{
	struct router_lsa *rl;

	rl = (struct router_lsa *)lsa->data;
	for (int i = 0; i < ntohs(rl->links); i++) {
		struct in_addr *link_id = &rl->link[i].link_id;

		if (rl->link[i].type != LSA_LINK_TYPE_POINTOPOINT)
			continue;

		if (IPV4_ADDR_SAME(id, link_id))
			return true;
	}

	return false;
}

static bool ospf_gr_check_router_lsa_consistency(struct ospf *ospf,
						 struct ospf_area *area,
						 struct ospf_lsa *lsa)
{
	if (CHECK_FLAG(lsa->flags, OSPF_LSA_SELF)) {
		struct ospf_lsa *lsa_self = lsa;
		struct router_lsa *rl = (struct router_lsa *)lsa->data;

		for (int i = 0; i < ntohs(rl->links); i++) {
			struct in_addr *link_id = &rl->link[i].link_id;
			struct ospf_lsa *lsa_adj;

			if (rl->link[i].type != LSA_LINK_TYPE_POINTOPOINT)
				continue;

			lsa_adj = ospf_lsa_lookup_by_id(area, OSPF_ROUTER_LSA,
							*link_id);
			if (!lsa_adj)
				continue;

			if (!ospf_router_lsa_contains_adj(lsa_adj,
							  &lsa_self->data->id))
				return false;
		}
	} else {
		struct ospf_lsa *lsa_self;

		lsa_self = ospf_lsa_lookup_by_id(area, OSPF_ROUTER_LSA,
						 ospf->router_id);
		if (!lsa_self
		    || !CHECK_FLAG(lsa_self->flags, OSPF_LSA_RECEIVED))
			return true;

		if (ospf_router_lsa_contains_adj(lsa, &ospf->router_id)
		    != ospf_router_lsa_contains_adj(lsa_self, &lsa->data->id))
			return false;
	}

	return true;
}

/*
 * Check for LSAs that are inconsistent with the pre-restart LSAs, and abort the
 * ongoing graceful restart when that's the case.
 */
void ospf_gr_check_lsdb_consistency(struct ospf *ospf, struct ospf_area *area)
{
	struct route_node *rn;
	struct ospf_lsa *lsa;

	for (rn = route_top(ROUTER_LSDB(area)); rn; rn = route_next(rn)) {
		lsa = rn->info;
		if (!lsa)
			continue;

		if (!ospf_gr_check_router_lsa_consistency(ospf, area, lsa)) {
			char reason[256];

			snprintfrr(reason, sizeof(reason),
				   "detected inconsistent LSA[%s] [area %pI4]",
				   dump_lsa_key(lsa), &area->area_id);
			ospf_gr_restart_exit(ospf, reason);
			route_unlock_node(rn);
			return;
		}
	}
}

/* Lookup neighbor by address in a given OSPF area. */
static struct ospf_neighbor *
ospf_area_nbr_lookup_by_addr(struct ospf_area *area, struct in_addr *addr)
{
	struct ospf_interface *oi;
	struct ospf_neighbor *nbr;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(area->oiflist, node, oi)) {
		nbr = ospf_nbr_lookup_by_addr(oi->nbrs, addr);
		if (nbr)
			return nbr;
	}

	return NULL;
}

/* Lookup neighbor by Router ID in a given OSPF area. */
static struct ospf_neighbor *
ospf_area_nbr_lookup_by_routerid(struct ospf_area *area, struct in_addr *id)
{
	struct ospf_interface *oi;
	struct ospf_neighbor *nbr;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(area->oiflist, node, oi)) {
		nbr = ospf_nbr_lookup_by_routerid(oi->nbrs, id);
		if (nbr)
			return nbr;
	}

	return NULL;
}

/* Check if there's a fully formed adjacency with the given neighbor ID. */
static bool ospf_gr_check_adj_id(struct ospf_area *area,
				 struct in_addr *nbr_id)
{
	struct ospf_neighbor *nbr;

	nbr = ospf_area_nbr_lookup_by_routerid(area, nbr_id);
	if (!nbr || nbr->state < NSM_Full) {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug("GR: missing adjacency to router %pI4",
				   nbr_id);
		return false;
	}

	return true;
}

static bool ospf_gr_check_adjs_lsa_transit(struct ospf_area *area,
					   struct in_addr *link_id)
{
	struct ospf *ospf = area->ospf;
	struct ospf_interface *oi;

	/*
	 * Check if the transit network refers to a local interface (in which
	 * case it must be a DR for that network).
	 */
	oi = ospf_if_lookup_by_local_addr(ospf, NULL, *link_id);
	if (oi) {
		struct ospf_lsa *lsa;
		struct network_lsa *nlsa;
		size_t cnt;

		/* Lookup Network LSA corresponding to this interface. */
		lsa = ospf_lsa_lookup_by_id(area, OSPF_NETWORK_LSA, *link_id);
		if (!lsa)
			return false;

		/* Iterate over all routers present in the network. */
		nlsa = (struct network_lsa *)lsa->data;
		cnt = (lsa->size - (OSPF_LSA_HEADER_SIZE + 4)) / 4;
		for (size_t i = 0; i < cnt; i++) {
			struct in_addr *nbr_id = &nlsa->routers[i];

			/* Skip self in the pseudonode. */
			if (IPV4_ADDR_SAME(nbr_id, &ospf->router_id))
				continue;

			/*
			 * Check if there's a fully formed adjacency with this
			 * router.
			 */
			if (!ospf_gr_check_adj_id(area, nbr_id))
				return false;
		}
	} else {
		struct ospf_neighbor *nbr;

		/* Check if there's a fully formed adjacency with the DR. */
		nbr = ospf_area_nbr_lookup_by_addr(area, link_id);
		if (!nbr || nbr->state < NSM_Full) {
			if (IS_DEBUG_OSPF_GR)
				zlog_debug(
					"GR: missing adjacency to DR router %pI4",
					link_id);
			return false;
		}
	}

	return true;
}

static bool ospf_gr_check_adjs_lsa(struct ospf_area *area, struct ospf_lsa *lsa)
{
	struct router_lsa *rl = (struct router_lsa *)lsa->data;

	for (int i = 0; i < ntohs(rl->links); i++) {
		struct in_addr *link_id = &rl->link[i].link_id;

		switch (rl->link[i].type) {
		case LSA_LINK_TYPE_POINTOPOINT:
			if (!ospf_gr_check_adj_id(area, link_id))
				return false;
			break;
		case LSA_LINK_TYPE_TRANSIT:
			if (!ospf_gr_check_adjs_lsa_transit(area, link_id))
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
void ospf_gr_check_adjs(struct ospf *ospf)
{
	struct ospf_area *area;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		struct ospf_lsa *lsa_self;

		lsa_self = ospf_lsa_lookup_by_id(area, OSPF_ROUTER_LSA,
						 ospf->router_id);
		if (!lsa_self || !ospf_gr_check_adjs_lsa(area, lsa_self)) {
			if (IS_DEBUG_OSPF_GR)
				zlog_debug(
					"GR: not all adjacencies were reestablished yet [area %pI4]",
					&area->area_id);
			return;
		}
	}

	ospf_gr_restart_exit(ospf, "all adjacencies were reestablished");
}

/* Handling of grace period expiry. */
static void ospf_gr_grace_period_expired(struct event *thread)
{
	struct ospf *ospf = EVENT_ARG(thread);

	ospf->gr_info.t_grace_period = NULL;
	ospf_gr_restart_exit(ospf, "grace period has expired");
}

/*
 * Returns the path of the file (non-volatile memory) that contains GR status
 * information.
 */
static char *ospf_gr_nvm_filepath(struct ospf *ospf)
{
	static char filepath[MAXPATHLEN];
	char instance[16] = "";

	if (ospf->instance)
		snprintf(instance, sizeof(instance), "-%d", ospf->instance);
	snprintf(filepath, sizeof(filepath), OSPFD_GR_STATE, instance);
	return filepath;
}

/* Send extra Grace-LSA out the interface (unplanned outages only). */
void ospf_gr_iface_send_grace_lsa(struct event *thread)
{
	struct ospf_interface *oi = EVENT_ARG(thread);
	struct ospf_if_params *params = IF_DEF_PARAMS(oi->ifp);

	ospf_gr_lsa_originate(oi, oi->ospf->gr_info.reason, false);

	if (++oi->gr.hello_delay.elapsed_seconds < params->v_gr_hello_delay)
		event_add_timer(master, ospf_gr_iface_send_grace_lsa, oi, 1,
				&oi->gr.hello_delay.t_grace_send);
	else
		OSPF_ISM_TIMER_MSEC_ON(oi->t_hello, ospf_hello_timer, 1);
}

/*
 * Record in non-volatile memory that the given OSPF instance is attempting to
 * perform a graceful restart.
 */
static void ospf_gr_nvm_update(struct ospf *ospf, bool prepare)
{
	char *filepath;
	const char *inst_name;
	json_object *json;
	json_object *json_instances;
	json_object *json_instance;

	filepath = ospf_gr_nvm_filepath(ospf);
	inst_name = ospf_get_name(ospf);

	json = json_object_from_file(filepath);
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

	json_object_int_add(json_instance, "gracePeriod",
			    ospf->gr_info.grace_period);

	/*
	 * Record not only the grace period, but also a UNIX timestamp
	 * corresponding to the end of that period. That way, once ospfd is
	 * restarted, it will be possible to take into account the time that
	 * passed while ospfd wasn't running.
	 */
	if (prepare)
		json_object_int_add(json_instance, "timestamp",
				    time(NULL) + ospf->gr_info.grace_period);

	json_object_to_file_ext(filepath, json, JSON_C_TO_STRING_PRETTY);
	json_object_free(json);
}

/*
 * Delete GR status information about the given OSPF instance from non-volatile
 * memory.
 */
void ospf_gr_nvm_delete(struct ospf *ospf)
{
	char *filepath;
	const char *inst_name;
	json_object *json;
	json_object *json_instances;

	filepath = ospf_gr_nvm_filepath(ospf);
	inst_name = ospf_get_name(ospf);

	json = json_object_from_file(filepath);
	if (json == NULL)
		json = json_object_new_object();

	json_object_object_get_ex(json, "instances", &json_instances);
	if (!json_instances) {
		json_instances = json_object_new_object();
		json_object_object_add(json, "instances", json_instances);
	}

	json_object_object_del(json_instances, inst_name);

	json_object_to_file_ext(filepath, json, JSON_C_TO_STRING_PRETTY);
	json_object_free(json);
}

/*
 * Fetch from non-volatile memory whether the given OSPF instance is performing
 * a graceful shutdown or not.
 */
void ospf_gr_nvm_read(struct ospf *ospf)
{
	char *filepath;
	const char *inst_name;
	json_object *json;
	json_object *json_instances;
	json_object *json_instance;
	json_object *json_timestamp;
	json_object *json_grace_period;
	time_t timestamp = 0;

	filepath = ospf_gr_nvm_filepath(ospf);
	inst_name = ospf_get_name(ospf);

	json = json_object_from_file(filepath);
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

	json_object_object_get_ex(json_instance, "gracePeriod",
				  &json_grace_period);
	json_object_object_get_ex(json_instance, "timestamp", &json_timestamp);

	if (json_timestamp) {
		time_t now;

		/* Planned GR: check if the grace period has already expired. */
		now = time(NULL);
		timestamp = json_object_get_int(json_timestamp);
		if (now > timestamp) {
			ospf_gr_restart_exit(
				ospf, "grace period has expired already");
		} else
			ospf_gr_restart_enter(ospf, OSPF_GR_SW_RESTART,
					      timestamp);
	} else if (json_grace_period) {
		uint32_t grace_period;

		/*
		 * Unplanned GR: the Grace-LSAs will be sent later as soon as
		 * the interfaces are operational.
		 */
		grace_period = json_object_get_int(json_grace_period);
		ospf->gr_info.grace_period = grace_period;
		ospf_gr_restart_enter(ospf, OSPF_GR_UNKNOWN_RESTART,
				      time(NULL) + ospf->gr_info.grace_period);
	}

	json_object_object_del(json_instances, inst_name);

	json_object_to_file_ext(filepath, json, JSON_C_TO_STRING_PRETTY);
	json_object_free(json);
}

void ospf_gr_unplanned_start_interface(struct ospf_interface *oi)
{
	/* Send Grace-LSA. */
	ospf_gr_lsa_originate(oi, oi->ospf->gr_info.reason, false);

	/* Start GR hello-delay interval. */
	oi->gr.hello_delay.elapsed_seconds = 0;
	event_add_timer(master, ospf_gr_iface_send_grace_lsa, oi, 1,
			&oi->gr.hello_delay.t_grace_send);
}

/* Prepare to start a Graceful Restart. */
static void ospf_gr_prepare(void)
{
	struct ospf *ospf;
	struct ospf_interface *oi;
	struct listnode *onode;

	for (ALL_LIST_ELEMENTS_RO(om->ospf, onode, ospf)) {
		struct listnode *inode;

		if (!ospf->gr_info.restart_support
		    || ospf->gr_info.prepare_in_progress)
			continue;

		if (IS_DEBUG_OSPF_GR)
			zlog_debug(
				"GR: preparing to perform a graceful restart [period %u second(s)] [vrf %s]",
				ospf->gr_info.grace_period,
				ospf_vrf_id_to_name(ospf->vrf_id));

		if (!CHECK_FLAG(ospf->config, OSPF_OPAQUE_CAPABLE)) {
			zlog_warn(
				"%s: failed to activate graceful restart: opaque capability not enabled",
				__func__);
			continue;
		}

		/* Send a Grace-LSA to all neighbors. */
		for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, inode, oi)) {
			if (OSPF_IF_PARAM(oi, opaque_capable))
				ospf_gr_lsa_originate(oi, OSPF_GR_SW_RESTART,
						      false);
			else
				zlog_debug(
					"GR: skipping grace LSA on interface %s (%s) with opaque capability disabled",
					IF_NAME(oi), ospf_get_name(oi->ospf));
		}

		/* Record end of the grace period in non-volatile memory. */
		ospf_gr_nvm_update(ospf, true);

		/*
		 * Mark that a Graceful Restart preparation is in progress, to
		 * prevent ospfd from flushing its self-originated LSAs on exit.
		 */
		ospf->gr_info.prepare_in_progress = true;
	}
}

DEFPY(graceful_restart_prepare, graceful_restart_prepare_cmd,
      "graceful-restart prepare ip ospf",
      "Graceful Restart commands\n"
      "Prepare upcoming graceful restart\n"
      IP_STR
      "Prepare to restart the OSPF process\n")
{
	struct ospf *ospf;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
		if (!CHECK_FLAG(ospf->config, OSPF_OPAQUE_CAPABLE)) {
			vty_out(vty,
				"%% Can't start graceful restart: opaque capability not enabled (VRF %s)\n\n",
				ospf_get_name(ospf));
			return CMD_WARNING;
		}
	}

	ospf_gr_prepare();

	return CMD_SUCCESS;
}

DEFPY(graceful_restart, graceful_restart_cmd,
      "graceful-restart [grace-period (1-1800)$grace_period]",
      OSPF_GR_STR
      "Maximum length of the 'grace period'\n"
      "Maximum length of the 'grace period' in seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	/* Check and get restart period if present. */
	if (!grace_period_str)
		grace_period = OSPF_DFLT_GRACE_INTERVAL;

	ospf->gr_info.restart_support = true;
	ospf->gr_info.grace_period = grace_period;

	/* Freeze OSPF routes in the RIB. */
	(void)ospf_zebra_gr_enable(ospf, ospf->gr_info.grace_period);

	/* Record that GR is enabled in non-volatile memory. */
	ospf_gr_nvm_update(ospf, false);

	return CMD_SUCCESS;
}

DEFPY(no_graceful_restart, no_graceful_restart_cmd,
      "no graceful-restart [grace-period (1-1800)]",
      NO_STR OSPF_GR_STR
      "Maximum length of the 'grace period'\n"
      "Maximum length of the 'grace period' in seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (!ospf->gr_info.restart_support)
		return CMD_SUCCESS;

	if (ospf->gr_info.prepare_in_progress) {
		vty_out(vty,
			"%% Error: Graceful Restart preparation in progress\n");
		return CMD_WARNING;
	}

	ospf->gr_info.restart_support = false;
	ospf->gr_info.grace_period = OSPF_DFLT_GRACE_INTERVAL;
	ospf_gr_nvm_delete(ospf);
	ospf_zebra_gr_disable(ospf);

	return CMD_SUCCESS;
}

void ospf_gr_init(void)
{
	install_element(ENABLE_NODE, &graceful_restart_prepare_cmd);
	install_element(OSPF_NODE, &graceful_restart_cmd);
	install_element(OSPF_NODE, &no_graceful_restart_cmd);
}
