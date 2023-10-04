// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

#include <zebra.h>

#include "log.h"
#include "frrevent.h"
#include "linklist.h"
#include "vty.h"
#include "command.h"

#include "ospf6d.h"
#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"
#include "ospf6_route.h"
#include "ospf6_spf.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"

#include "ospf6_flood.h"
#include "ospf6_nssa.h"
#include "ospf6_gr.h"

unsigned char conf_debug_ospf6_flooding;

struct ospf6_lsdb *ospf6_get_scoped_lsdb(struct ospf6_lsa *lsa)
{
	struct ospf6_lsdb *lsdb = NULL;
	switch (OSPF6_LSA_SCOPE(lsa->header->type)) {
	case OSPF6_SCOPE_LINKLOCAL:
		lsdb = OSPF6_INTERFACE(lsa->lsdb->data)->lsdb;
		break;
	case OSPF6_SCOPE_AREA:
		lsdb = OSPF6_AREA(lsa->lsdb->data)->lsdb;
		break;
	case OSPF6_SCOPE_AS:
		lsdb = OSPF6_PROCESS(lsa->lsdb->data)->lsdb;
		break;
	default:
		assert(0);
		break;
	}
	return lsdb;
}

struct ospf6_lsdb *ospf6_get_scoped_lsdb_self(struct ospf6_lsa *lsa)
{
	struct ospf6_lsdb *lsdb_self = NULL;
	switch (OSPF6_LSA_SCOPE(lsa->header->type)) {
	case OSPF6_SCOPE_LINKLOCAL:
		lsdb_self = OSPF6_INTERFACE(lsa->lsdb->data)->lsdb_self;
		break;
	case OSPF6_SCOPE_AREA:
		lsdb_self = OSPF6_AREA(lsa->lsdb->data)->lsdb_self;
		break;
	case OSPF6_SCOPE_AS:
		lsdb_self = OSPF6_PROCESS(lsa->lsdb->data)->lsdb_self;
		break;
	default:
		assert(0);
		break;
	}
	return lsdb_self;
}

void ospf6_lsa_originate(struct ospf6 *ospf6, struct ospf6_lsa *lsa)
{
	struct ospf6_lsa *old;
	struct ospf6_lsdb *lsdb_self;

	if (lsa->header->adv_router == INADDR_ANY) {
		if (IS_OSPF6_DEBUG_ORIGINATE_TYPE(lsa->header->type))
			zlog_debug(
				"Refusing to originate LSA (zero router ID): %s",
				lsa->name);

		ospf6_lsa_delete(lsa);
		return;
	}

	/* find previous LSA */
	old = ospf6_lsdb_lookup(lsa->header->type, lsa->header->id,
				lsa->header->adv_router, lsa->lsdb);

	/* if the new LSA does not differ from previous,
	   suppress this update of the LSA */
	if (old && !OSPF6_LSA_IS_DIFFER(lsa, old)
	    && !ospf6->gr_info.finishing_restart) {
		if (IS_OSPF6_DEBUG_ORIGINATE_TYPE(lsa->header->type))
			zlog_debug("Suppress updating LSA: %s", lsa->name);
		ospf6_lsa_delete(lsa);
		return;
	}

	/* store it in the LSDB for self-originated LSAs */
	lsdb_self = ospf6_get_scoped_lsdb_self(lsa);
	ospf6_lsdb_add(ospf6_lsa_copy(lsa), lsdb_self);

	EVENT_OFF(lsa->refresh);
	event_add_timer(master, ospf6_lsa_refresh, lsa, OSPF_LS_REFRESH_TIME,
			&lsa->refresh);

	if (IS_OSPF6_DEBUG_LSA_TYPE(lsa->header->type)
	    || IS_OSPF6_DEBUG_ORIGINATE_TYPE(lsa->header->type)) {
		zlog_debug("LSA Originate:");
		ospf6_lsa_header_print(lsa);
	}

	ospf6_install_lsa(lsa);
	ospf6_flood(NULL, lsa);
}

void ospf6_lsa_originate_process(struct ospf6_lsa *lsa, struct ospf6 *process)
{
	lsa->lsdb = process->lsdb;
	ospf6_lsa_originate(process, lsa);
}

void ospf6_lsa_originate_area(struct ospf6_lsa *lsa, struct ospf6_area *oa)
{
	lsa->lsdb = oa->lsdb;
	ospf6_lsa_originate(oa->ospf6, lsa);
}

void ospf6_lsa_originate_interface(struct ospf6_lsa *lsa,
				   struct ospf6_interface *oi)
{
	lsa->lsdb = oi->lsdb;
	ospf6_lsa_originate(oi->area->ospf6, lsa);
}

void ospf6_external_lsa_purge(struct ospf6 *ospf6, struct ospf6_lsa *lsa)
{
	uint32_t id = lsa->header->id;
	struct ospf6_area *oa;
	struct listnode *lnode;

	ospf6_lsa_purge(lsa);

	/* Delete the corresponding NSSA LSA */
	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, lnode, oa)) {
		lsa = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_TYPE_7), id,
					ospf6->router_id, oa->lsdb);
		if (lsa) {
			if (IS_OSPF6_DEBUG_NSSA)
				zlog_debug("withdraw type 7 lsa, LS ID: %u",
					   htonl(id));

			ospf6_lsa_purge(lsa);
		}
	}
}

void ospf6_lsa_purge(struct ospf6_lsa *lsa)
{
	struct ospf6_lsa *self;
	struct ospf6_lsdb *lsdb_self;

	/* remove it from the LSDB for self-originated LSAs */
	lsdb_self = ospf6_get_scoped_lsdb_self(lsa);
	self = ospf6_lsdb_lookup(lsa->header->type, lsa->header->id,
				 lsa->header->adv_router, lsdb_self);
	if (self) {
		EVENT_OFF(self->expire);
		EVENT_OFF(self->refresh);
		ospf6_lsdb_remove(self, lsdb_self);
	}

	ospf6_lsa_premature_aging(lsa);
}

/* Puring Multi Link-State IDs LSAs:
 * Same Advertising Router with Multiple Link-State IDs
 * LSAs, purging require to traverse all Link-State IDs
 */
void ospf6_lsa_purge_multi_ls_id(struct ospf6_area *oa, struct ospf6_lsa *lsa)
{
	int ls_id = 0;
	struct ospf6_lsa *lsa_next;
	uint16_t type;

	type = lsa->header->type;

	ospf6_lsa_purge(lsa);

	lsa_next = ospf6_lsdb_lookup(type, htonl(++ls_id),
				     oa->ospf6->router_id, oa->lsdb);
	while (lsa_next) {
		ospf6_lsa_purge(lsa_next);
		lsa_next = ospf6_lsdb_lookup(type, htonl(++ls_id),
					     oa->ospf6->router_id, oa->lsdb);
	}
}

void ospf6_increment_retrans_count(struct ospf6_lsa *lsa)
{
	/* The LSA must be the original one (see the description
	   in ospf6_decrement_retrans_count () below) */
	lsa->retrans_count++;
}

void ospf6_decrement_retrans_count(struct ospf6_lsa *lsa)
{
	struct ospf6_lsdb *lsdb;
	struct ospf6_lsa *orig;

	/* The LSA must be on the retrans-list of a neighbor. It means
	   the "lsa" is a copied one, and we have to decrement the
	   retransmission count of the original one (instead of this "lsa"'s).
	   In order to find the original LSA, first we have to find
	   appropriate LSDB that have the original LSA. */
	lsdb = ospf6_get_scoped_lsdb(lsa);

	/* Find the original LSA of which the retrans_count should be
	 * decremented */
	orig = ospf6_lsdb_lookup(lsa->header->type, lsa->header->id,
				 lsa->header->adv_router, lsdb);
	if (orig) {
		orig->retrans_count--;
		assert(orig->retrans_count >= 0);
	}
}

/* RFC2328 section 13.2 Installing LSAs in the database */
void ospf6_install_lsa(struct ospf6_lsa *lsa)
{
	struct ospf6 *ospf6;
	struct timeval now;
	struct ospf6_lsa *old;
	struct ospf6_area *area = NULL;

	ospf6 = ospf6_get_by_lsdb(lsa);
	assert(ospf6);

	/* Remove the old instance from all neighbors' Link state
	   retransmission list (RFC2328 13.2 last paragraph) */
	old = ospf6_lsdb_lookup(lsa->header->type, lsa->header->id,
				lsa->header->adv_router, lsa->lsdb);
	if (old) {
		if (ntohs(lsa->header->type) == OSPF6_LSTYPE_TYPE_7) {
			if (IS_OSPF6_DEBUG_NSSA)
				zlog_debug("%s : old LSA %s", __func__,
					   lsa->name);
			lsa->external_lsa_id = old->external_lsa_id;
		}
		EVENT_OFF(old->expire);
		EVENT_OFF(old->refresh);
		ospf6_flood_clear(old);
	}

	monotime(&now);
	if (!OSPF6_LSA_IS_MAXAGE(lsa)) {
		event_add_timer(master, ospf6_lsa_expire, lsa,
				OSPF_LSA_MAXAGE + lsa->birth.tv_sec -
					now.tv_sec,
				&lsa->expire);
	} else
		lsa->expire = NULL;

	if (OSPF6_LSA_IS_SEQWRAP(lsa)
	    && !(CHECK_FLAG(lsa->flag, OSPF6_LSA_SEQWRAPPED)
		 && lsa->header->seqnum == htonl(OSPF_MAX_SEQUENCE_NUMBER))) {
		if (IS_OSPF6_DEBUG_EXAMIN_TYPE(lsa->header->type))
			zlog_debug("lsa install wrapping: sequence 0x%x",
				   ntohl(lsa->header->seqnum));
		SET_FLAG(lsa->flag, OSPF6_LSA_SEQWRAPPED);
		/* in lieu of premature_aging, since we do not want to recreate
		 * this lsa
		 * and/or mess with timers etc, we just want to wrap the
		 * sequence number
		 * and reflood the lsa before continuing.
		 * NOTE: Flood needs to be called right after this function
		 * call, by the
		 * caller
		 */
		lsa->header->seqnum = htonl(OSPF_MAX_SEQUENCE_NUMBER);
		lsa->header->age = htons(OSPF_LSA_MAXAGE);
		ospf6_lsa_checksum(lsa->header);
	}

	if (IS_OSPF6_DEBUG_LSA_TYPE(lsa->header->type)
	    || IS_OSPF6_DEBUG_EXAMIN_TYPE(lsa->header->type))
		zlog_debug("%s Install LSA: %s age %d seqnum %x in LSDB.",
			   __func__, lsa->name, ntohs(lsa->header->age),
			   ntohl(lsa->header->seqnum));

	/* actually install */
	lsa->installed = now;

	/* Topo change handling */
	if (CHECK_LSA_TOPO_CHG_ELIGIBLE(ntohs(lsa->header->type))
	    && !CHECK_FLAG(lsa->flag, OSPF6_LSA_DUPLICATE)) {

		/* check if it is new lsa ? or existing lsa got modified ?*/
		if (!old || OSPF6_LSA_IS_CHANGED(old, lsa))
			ospf6_helper_handle_topo_chg(ospf6, lsa);
	}

	ospf6_lsdb_add(lsa, lsa->lsdb);

	if (ntohs(lsa->header->type) == OSPF6_LSTYPE_TYPE_7
	    && lsa->header->adv_router != ospf6->router_id) {
		area = OSPF6_AREA(lsa->lsdb->data);
		ospf6_translated_nssa_refresh(area, lsa, NULL);
		ospf6_schedule_abr_task(area->ospf6);
	}

	if (ntohs(lsa->header->type) == OSPF6_LSTYPE_ROUTER) {
		area = OSPF6_AREA(lsa->lsdb->data);
		if (old == NULL) {
			if (IS_OSPF6_DEBUG_LSA_TYPE(lsa->header->type)
			    || IS_OSPF6_DEBUG_EXAMIN_TYPE(lsa->header->type))
				zlog_debug("%s: New router LSA %s", __func__,
					   lsa->name);
			ospf6_abr_nssa_check_status(area->ospf6);
		}
	}
	return;
}

/* RFC2740 section 3.5.2. Sending Link State Update packets */
/* RFC2328 section 13.3 Next step in the flooding procedure */
void ospf6_flood_interface(struct ospf6_neighbor *from, struct ospf6_lsa *lsa,
			   struct ospf6_interface *oi)
{
	struct listnode *node, *nnode;
	struct ospf6_neighbor *on;
	struct ospf6_lsa *req, *old;
	int retrans_added = 0;
	int is_debug = 0;

	if (IS_OSPF6_DEBUG_FLOODING
	    || IS_OSPF6_DEBUG_FLOOD_TYPE(lsa->header->type)) {
		is_debug++;
		zlog_debug("Flooding on %s: %s", oi->interface->name,
			   lsa->name);
	}

	/* (1) For each neighbor */
	for (ALL_LIST_ELEMENTS(oi->neighbor_list, node, nnode, on)) {
		if (is_debug)
			zlog_debug("To neighbor %s", on->name);

		/* (a) if neighbor state < Exchange, examin next */
		if (on->state < OSPF6_NEIGHBOR_EXCHANGE) {
			if (is_debug)
				zlog_debug(
					"Neighbor state less than ExChange, next neighbor");
			continue;
		}

		/* (b) if neighbor not yet Full, check request-list */
		if (on->state != OSPF6_NEIGHBOR_FULL) {
			if (is_debug)
				zlog_debug("Neighbor not yet Full");

			req = ospf6_lsdb_lookup(
				lsa->header->type, lsa->header->id,
				lsa->header->adv_router, on->request_list);
			if (req == NULL) {
				if (is_debug)
					zlog_debug(
						"Not on request-list for this neighbor");
				/* fall through */
			} else {
				/* If new LSA less recent, examin next neighbor
				 */
				if (ospf6_lsa_compare(lsa, req) > 0) {
					if (is_debug)
						zlog_debug(
							"Requesting is older, next neighbor");
					continue;
				}

				/* If the same instance, delete from
				   request-list and
				   examin next neighbor */
				if (ospf6_lsa_compare(lsa, req) == 0) {
					if (is_debug)
						zlog_debug(
							"Requesting the same, remove it, next neighbor");
					if (req == on->last_ls_req) {
						/* sanity check refcount */
						assert(req->lock >= 2);
						ospf6_lsa_unlock(&req);
						on->last_ls_req = NULL;
					}
					if (req)
						ospf6_lsdb_remove(
							req, on->request_list);
					ospf6_check_nbr_loading(on);
					continue;
				}

				/* If the new LSA is more recent, delete from
				 * request-list */
				if (ospf6_lsa_compare(lsa, req) < 0) {
					if (is_debug)
						zlog_debug(
							"Received is newer, remove requesting");
					if (req == on->last_ls_req) {
						ospf6_lsa_unlock(&req);
						on->last_ls_req = NULL;
					}
					if (req)
						ospf6_lsdb_remove(req,
							on->request_list);
					ospf6_check_nbr_loading(on);
					/* fall through */
				}
			}
		}

		/* (c) If the new LSA was received from this neighbor,
		   examin next neighbor */
		if (from == on) {
			if (is_debug)
				zlog_debug(
					"Received is from the neighbor, next neighbor");
			continue;
		}

		if ((oi->area->ospf6->inst_shutdown)
		    || CHECK_FLAG(lsa->flag, OSPF6_LSA_FLUSH)) {
			if (is_debug)
				zlog_debug(
					"%s: Send LSA %s (age %d) update now",
					__func__, lsa->name,
					ntohs(lsa->header->age));
			ospf6_lsupdate_send_neighbor_now(on, lsa);
			continue;
		} else {
			/* (d) add retrans-list, schedule retransmission */
			if (is_debug)
				zlog_debug("Add retrans-list of neighbor %s ",
					   on->name);

			/* Do not increment the retrans count if the lsa is
			 * already present in the retrans list.
			 */
			old = ospf6_lsdb_lookup(
				lsa->header->type, lsa->header->id,
				lsa->header->adv_router, on->retrans_list);
			if (!old) {
				struct ospf6_lsa *orig;
				struct ospf6_lsdb *lsdb;

				if (is_debug)
					zlog_debug(
						"Increment %s from retrans_list of %s",
						lsa->name, on->name);

				/* Increment the retrans count on the original
				 * copy of LSA if present, to maintain the
				 * counter consistency.
				 */

				lsdb = ospf6_get_scoped_lsdb(lsa);
				orig = ospf6_lsdb_lookup(
					lsa->header->type, lsa->header->id,
					lsa->header->adv_router, lsdb);
				if (orig)
					ospf6_increment_retrans_count(orig);
				else
					ospf6_increment_retrans_count(lsa);

				ospf6_lsdb_add(ospf6_lsa_copy(lsa),
					       on->retrans_list);
				event_add_timer(master,
						ospf6_lsupdate_send_neighbor,
						on, on->ospf6_if->rxmt_interval,
						&on->thread_send_lsupdate);
				retrans_added++;
			}
		}
	}

	/* (2) examin next interface if not added to retrans-list */
	if (retrans_added == 0) {
		if (is_debug)
			zlog_debug(
				"No retransmission scheduled, next interface %s",
				oi->interface->name);
		return;
	}

	/* (3) If the new LSA was received on this interface,
	   and it was from DR or BDR, examin next interface */
	if (from && from->ospf6_if == oi
	    && (from->router_id == oi->drouter
		|| from->router_id == oi->bdrouter)) {
		if (is_debug)
			zlog_debug(
				"Received is from the I/F's DR or BDR, next interface");
		return;
	}

	/* (4) If the new LSA was received on this interface,
	   and the interface state is BDR, examin next interface */
	if (from && from->ospf6_if == oi) {
		if (oi->state == OSPF6_INTERFACE_BDR) {
			if (is_debug)
				zlog_debug(
					"Received is from the I/F, itself BDR, next interface");
			return;
		}
		SET_FLAG(lsa->flag, OSPF6_LSA_FLOODBACK);
	}

	/* (5) flood the LSA out the interface. */
	if (is_debug)
		zlog_debug("Schedule flooding for the interface");
	if ((oi->type == OSPF_IFTYPE_BROADCAST)
	    || (oi->type == OSPF_IFTYPE_POINTOPOINT)) {
		ospf6_lsdb_add(ospf6_lsa_copy(lsa), oi->lsupdate_list);
		event_add_event(master, ospf6_lsupdate_send_interface, oi, 0,
				&oi->thread_send_lsupdate);
	} else {
		/* reschedule retransmissions to all neighbors */
		for (ALL_LIST_ELEMENTS(oi->neighbor_list, node, nnode, on)) {
			EVENT_OFF(on->thread_send_lsupdate);
			event_add_event(master, ospf6_lsupdate_send_neighbor,
					on, 0, &on->thread_send_lsupdate);
		}
	}
}

void ospf6_flood_area(struct ospf6_neighbor *from, struct ospf6_lsa *lsa,
		      struct ospf6_area *oa)
{
	struct listnode *node, *nnode;
	struct ospf6_interface *oi;

	for (ALL_LIST_ELEMENTS(oa->if_list, node, nnode, oi)) {
		if (OSPF6_LSA_SCOPE(lsa->header->type) == OSPF6_SCOPE_LINKLOCAL
		    && oi != OSPF6_INTERFACE(lsa->lsdb->data))
			continue;

		ospf6_flood_interface(from, lsa, oi);
	}
}

static void ospf6_flood_process(struct ospf6_neighbor *from,
				struct ospf6_lsa *lsa, struct ospf6 *process)
{
	struct listnode *node, *nnode;
	struct ospf6_area *oa;

	for (ALL_LIST_ELEMENTS(process->area_list, node, nnode, oa)) {

		/* If unknown LSA and U-bit clear, treat as link local
		 * flooding scope
		 */
		if (!OSPF6_LSA_IS_KNOWN(lsa->header->type)
		    && !(ntohs(lsa->header->type) & OSPF6_LSTYPE_UBIT_MASK)
		    && (oa != OSPF6_INTERFACE(lsa->lsdb->data)->area)) {

			if (IS_OSPF6_DEBUG_FLOODING)
				zlog_debug("Unknown LSA, do not flood");
			continue;
		}

		if (OSPF6_LSA_SCOPE(lsa->header->type) == OSPF6_SCOPE_AREA
		    && oa != OSPF6_AREA(lsa->lsdb->data))
			continue;
		if (OSPF6_LSA_SCOPE(lsa->header->type) == OSPF6_SCOPE_LINKLOCAL
		    && oa != OSPF6_INTERFACE(lsa->lsdb->data)->area)
			continue;

		if (ntohs(lsa->header->type) == OSPF6_LSTYPE_AS_EXTERNAL
		    && (IS_AREA_STUB(oa) || IS_AREA_NSSA(oa)))
			continue;

		/* Check for NSSA LSA */
		if (ntohs(lsa->header->type) == OSPF6_LSTYPE_TYPE_7
		    && !IS_AREA_NSSA(oa) && !OSPF6_LSA_IS_MAXAGE(lsa))
			continue;

		ospf6_flood_area(from, lsa, oa);
	}
}

void ospf6_flood(struct ospf6_neighbor *from, struct ospf6_lsa *lsa)
{
	struct ospf6 *ospf6;

	ospf6 = ospf6_get_by_lsdb(lsa);
	if (ospf6 == NULL)
		return;

	ospf6_flood_process(from, lsa, ospf6);
}

static void ospf6_flood_clear_interface(struct ospf6_lsa *lsa,
					struct ospf6_interface *oi)
{
	struct listnode *node, *nnode;
	struct ospf6_neighbor *on;
	struct ospf6_lsa *rem;

	for (ALL_LIST_ELEMENTS(oi->neighbor_list, node, nnode, on)) {
		rem = ospf6_lsdb_lookup(lsa->header->type, lsa->header->id,
					lsa->header->adv_router,
					on->retrans_list);
		if (rem && !ospf6_lsa_compare(rem, lsa)) {
			if (IS_OSPF6_DEBUG_FLOODING
			    || IS_OSPF6_DEBUG_FLOOD_TYPE(lsa->header->type))
				zlog_debug("Remove %s from retrans_list of %s",
					   rem->name, on->name);
			ospf6_decrement_retrans_count(rem);
			ospf6_lsdb_remove(rem, on->retrans_list);
		}
	}
}

void ospf6_flood_clear_area(struct ospf6_lsa *lsa, struct ospf6_area *oa)
{
	struct listnode *node, *nnode;
	struct ospf6_interface *oi;

	for (ALL_LIST_ELEMENTS(oa->if_list, node, nnode, oi)) {
		if (OSPF6_LSA_SCOPE(lsa->header->type) == OSPF6_SCOPE_LINKLOCAL
		    && oi != OSPF6_INTERFACE(lsa->lsdb->data))
			continue;

		ospf6_flood_clear_interface(lsa, oi);
	}
}

static void ospf6_flood_clear_process(struct ospf6_lsa *lsa,
				      struct ospf6 *process)
{
	struct listnode *node, *nnode;
	struct ospf6_area *oa;

	for (ALL_LIST_ELEMENTS(process->area_list, node, nnode, oa)) {
		if (OSPF6_LSA_SCOPE(lsa->header->type) == OSPF6_SCOPE_AREA
		    && oa != OSPF6_AREA(lsa->lsdb->data))
			continue;
		if (OSPF6_LSA_SCOPE(lsa->header->type) == OSPF6_SCOPE_LINKLOCAL
		    && oa != OSPF6_INTERFACE(lsa->lsdb->data)->area)
			continue;

		if (ntohs(lsa->header->type) == OSPF6_LSTYPE_AS_EXTERNAL
		    && (IS_AREA_STUB(oa) || (IS_AREA_NSSA(oa))))
			continue;
		/* Check for NSSA LSA */
		if (ntohs(lsa->header->type) == OSPF6_LSTYPE_TYPE_7
		    && !IS_AREA_NSSA(oa))
			continue;

		ospf6_flood_clear_area(lsa, oa);
	}
}

void ospf6_flood_clear(struct ospf6_lsa *lsa)
{
	struct ospf6 *ospf6;

	ospf6 = ospf6_get_by_lsdb(lsa);
	if (ospf6 == NULL)
		return;
	ospf6_flood_clear_process(lsa, ospf6);
}


/* RFC2328 13.5 (Table 19): Sending link state acknowledgements. */
static void ospf6_acknowledge_lsa_bdrouter(struct ospf6_lsa *lsa,
					   int ismore_recent,
					   struct ospf6_neighbor *from)
{
	struct ospf6_interface *oi;
	int is_debug = 0;

	if (IS_OSPF6_DEBUG_FLOODING
	    || IS_OSPF6_DEBUG_FLOOD_TYPE(lsa->header->type))
		is_debug++;

	assert(from && from->ospf6_if);
	oi = from->ospf6_if;

	/* LSA is more recent than database copy, but was not flooded
	   back out receiving interface. Delayed acknowledgement sent
	   if advertisement received from Designated Router,
	   otherwide do nothing. */
	if (ismore_recent < 0) {
		if (oi->drouter == from->router_id) {
			if (is_debug)
				zlog_debug(
					"Delayed acknowledgement (BDR & MoreRecent & from DR)");
			/* Delayed acknowledgement */
			ospf6_lsdb_add(ospf6_lsa_copy(lsa), oi->lsack_list);
			event_add_timer(master, ospf6_lsack_send_interface, oi,
					3, &oi->thread_send_lsack);
		} else {
			if (is_debug)
				zlog_debug(
					"No acknowledgement (BDR & MoreRecent & ! from DR)");
		}
		return;
	}

	/* LSA is a duplicate, and was treated as an implied acknowledgement.
	   Delayed acknowledgement sent if advertisement received from
	   Designated Router, otherwise do nothing */
	if (CHECK_FLAG(lsa->flag, OSPF6_LSA_DUPLICATE)
	    && CHECK_FLAG(lsa->flag, OSPF6_LSA_IMPLIEDACK)) {
		if (oi->drouter == from->router_id) {
			if (is_debug)
				zlog_debug(
					"Delayed acknowledgement (BDR & Duplicate & ImpliedAck & from DR)");
			/* Delayed acknowledgement */
			ospf6_lsdb_add(ospf6_lsa_copy(lsa), oi->lsack_list);
			event_add_timer(master, ospf6_lsack_send_interface, oi,
					3, &oi->thread_send_lsack);
		} else {
			if (is_debug)
				zlog_debug(
					"No acknowledgement (BDR & Duplicate & ImpliedAck & ! from DR)");
		}
		return;
	}

	/* LSA is a duplicate, and was not treated as an implied
	   acknowledgement.
	   Direct acknowledgement sent */
	if (CHECK_FLAG(lsa->flag, OSPF6_LSA_DUPLICATE)
	    && !CHECK_FLAG(lsa->flag, OSPF6_LSA_IMPLIEDACK)) {
		if (is_debug)
			zlog_debug("Direct acknowledgement (BDR & Duplicate)");
		ospf6_lsdb_add(ospf6_lsa_copy(lsa), from->lsack_list);
		event_add_event(master, ospf6_lsack_send_neighbor, from, 0,
				&from->thread_send_lsack);
		return;
	}

	/* LSA's LS age is equal to Maxage, and there is no current instance
	   of the LSA in the link state database, and none of router's
	   neighbors are in states Exchange or Loading */
	/* Direct acknowledgement sent, but this case is handled in
	   early of ospf6_receive_lsa () */
}

static void ospf6_acknowledge_lsa_allother(struct ospf6_lsa *lsa,
					   int ismore_recent,
					   struct ospf6_neighbor *from)
{
	struct ospf6_interface *oi;
	int is_debug = 0;

	if (IS_OSPF6_DEBUG_FLOODING
	    || IS_OSPF6_DEBUG_FLOOD_TYPE(lsa->header->type))
		is_debug++;

	assert(from && from->ospf6_if);
	oi = from->ospf6_if;

	/* LSA has been flood back out receiving interface.
	   No acknowledgement sent. */
	if (CHECK_FLAG(lsa->flag, OSPF6_LSA_FLOODBACK)) {
		if (is_debug)
			zlog_debug("No acknowledgement (AllOther & FloodBack)");
		return;
	}

	/* LSA is more recent than database copy, but was not flooded
	   back out receiving interface. Delayed acknowledgement sent. */
	if (ismore_recent < 0) {
		if (is_debug)
			zlog_debug(
				"Delayed acknowledgement (AllOther & MoreRecent)");
		/* Delayed acknowledgement */
		ospf6_lsdb_add(ospf6_lsa_copy(lsa), oi->lsack_list);
		event_add_timer(master, ospf6_lsack_send_interface, oi, 3,
				&oi->thread_send_lsack);
		return;
	}

	/* LSA is a duplicate, and was treated as an implied acknowledgement.
	   No acknowledgement sent. */
	if (CHECK_FLAG(lsa->flag, OSPF6_LSA_DUPLICATE)
	    && CHECK_FLAG(lsa->flag, OSPF6_LSA_IMPLIEDACK)) {
		if (is_debug)
			zlog_debug(
				"No acknowledgement (AllOther & Duplicate & ImpliedAck)");
		return;
	}

	/* LSA is a duplicate, and was not treated as an implied
	   acknowledgement.
	   Direct acknowledgement sent */
	if (CHECK_FLAG(lsa->flag, OSPF6_LSA_DUPLICATE)
	    && !CHECK_FLAG(lsa->flag, OSPF6_LSA_IMPLIEDACK)) {
		if (is_debug)
			zlog_debug(
				"Direct acknowledgement (AllOther & Duplicate)");
		ospf6_lsdb_add(ospf6_lsa_copy(lsa), from->lsack_list);
		event_add_event(master, ospf6_lsack_send_neighbor, from, 0,
				&from->thread_send_lsack);
		return;
	}

	/* LSA's LS age is equal to Maxage, and there is no current instance
	   of the LSA in the link state database, and none of router's
	   neighbors are in states Exchange or Loading */
	/* Direct acknowledgement sent, but this case is handled in
	   early of ospf6_receive_lsa () */
}

static void ospf6_acknowledge_lsa(struct ospf6_lsa *lsa, int ismore_recent,
				  struct ospf6_neighbor *from)
{
	struct ospf6_interface *oi;

	assert(from && from->ospf6_if);
	oi = from->ospf6_if;

	if (oi->state == OSPF6_INTERFACE_BDR)
		ospf6_acknowledge_lsa_bdrouter(lsa, ismore_recent, from);
	else
		ospf6_acknowledge_lsa_allother(lsa, ismore_recent, from);
}

/* RFC2328 section 13 (4):
   if MaxAge LSA and if we have no instance, and no neighbor
   is in states Exchange or Loading
   returns 1 if match this case, else returns 0 */
static int ospf6_is_maxage_lsa_drop(struct ospf6_lsa *lsa,
				    struct ospf6_neighbor *from)
{
	struct ospf6_neighbor *on;
	struct ospf6_interface *oi;
	struct ospf6_area *oa;
	struct ospf6 *process = NULL;
	struct listnode *i, *j, *k;
	int count = 0;

	if (!OSPF6_LSA_IS_MAXAGE(lsa))
		return 0;

	if (ospf6_lsdb_lookup(lsa->header->type, lsa->header->id,
			      lsa->header->adv_router, lsa->lsdb))
		return 0;

	process = from->ospf6_if->area->ospf6;

	for (ALL_LIST_ELEMENTS_RO(process->area_list, i, oa))
		for (ALL_LIST_ELEMENTS_RO(oa->if_list, j, oi))
			for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, k, on))
				if (on->state == OSPF6_NEIGHBOR_EXCHANGE
				    || on->state == OSPF6_NEIGHBOR_LOADING)
					count++;

	if (count == 0)
		return 1;
	return 0;
}

static bool ospf6_lsa_check_min_arrival(struct ospf6_lsa *lsa,
					struct ospf6_neighbor *from)
{
	struct timeval now, res;
	unsigned int time_delta_ms;

	monotime(&now);
	timersub(&now, &lsa->installed, &res);
	time_delta_ms = (res.tv_sec * 1000) + (int)(res.tv_usec / 1000);

	if (time_delta_ms < from->ospf6_if->area->ospf6->lsa_minarrival) {
		if (IS_OSPF6_DEBUG_FLOODING ||
		    IS_OSPF6_DEBUG_FLOOD_TYPE(lsa->header->type))
			zlog_debug(
				"LSA can't be updated within MinLSArrival, %dms < %dms, discard",
				time_delta_ms,
				from->ospf6_if->area->ospf6->lsa_minarrival);
		return true;
	}
	return false;
}

/* RFC2328 section 13 The Flooding Procedure */
void ospf6_receive_lsa(struct ospf6_neighbor *from,
		       struct ospf6_lsa_header *lsa_header)
{
	struct ospf6_lsa *new = NULL, *old = NULL, *rem = NULL;
	int ismore_recent;
	int is_debug = 0;

	ismore_recent = 1;
	assert(from);

	/* if we receive a LSA with invalid seqnum drop it */
	if (ntohl(lsa_header->seqnum) - 1 == OSPF_MAX_SEQUENCE_NUMBER) {
		if (IS_OSPF6_DEBUG_EXAMIN_TYPE(lsa_header->type)) {
			zlog_debug(
				"received lsa [%s Id:%pI4 Adv:%pI4] with invalid seqnum 0x%x, ignore",
				ospf6_lstype_name(lsa_header->type),
				&lsa_header->id, &lsa_header->adv_router,
				ntohl(lsa_header->seqnum));
		}
		return;
	}

	/* make lsa structure for received lsa */
	new = ospf6_lsa_create(lsa_header);

	if (IS_OSPF6_DEBUG_FLOODING
	    || IS_OSPF6_DEBUG_FLOOD_TYPE(new->header->type)) {
		is_debug++;
		zlog_debug("LSA Receive from %s", from->name);
		ospf6_lsa_header_print(new);
	}

	/* (1) LSA Checksum */
	if (!ospf6_lsa_checksum_valid(new->header)) {
		if (is_debug)
			zlog_debug(
				"Wrong LSA Checksum %s (Router-ID: %pI4) [Type:%s Checksum:%#06hx), discard",
				from->name, &from->router_id,
				ospf6_lstype_name(new->header->type),
				ntohs(new->header->checksum));
		ospf6_lsa_delete(new);
		return;
	}

	/* (2) Examine the LSA's LS type.
	   RFC2470 3.5.1. Receiving Link State Update packets  */
	if (IS_AREA_STUB(from->ospf6_if->area)
	    && OSPF6_LSA_SCOPE(new->header->type) == OSPF6_SCOPE_AS) {
		if (is_debug)
			zlog_debug(
				"AS-External-LSA (or AS-scope LSA) in stub area, discard");
		ospf6_lsa_delete(new);
		return;
	}

	/* (3) LSA which have reserved scope is discarded
	   RFC2470 3.5.1. Receiving Link State Update packets  */
	/* Flooding scope check. LSAs with unknown scope are discarded here.
	   Set appropriate LSDB for the LSA */
	switch (OSPF6_LSA_SCOPE(new->header->type)) {
	case OSPF6_SCOPE_LINKLOCAL:
		new->lsdb = from->ospf6_if->lsdb;
		break;
	case OSPF6_SCOPE_AREA:
		new->lsdb = from->ospf6_if->area->lsdb;
		break;
	case OSPF6_SCOPE_AS:
		new->lsdb = from->ospf6_if->area->ospf6->lsdb;
		break;
	default:
		if (is_debug)
			zlog_debug("LSA has reserved scope, discard");
		ospf6_lsa_delete(new);
		return;
	}

	/* (4) if MaxAge LSA and if we have no instance, and no neighbor
	       is in states Exchange or Loading */
	if (ospf6_is_maxage_lsa_drop(new, from)) {
		/* log */
		if (is_debug)
			zlog_debug(
				"Drop MaxAge LSA with direct acknowledgement.");

		/* a) Acknowledge back to neighbor (Direct acknowledgement,
		 * 13.5) */
		ospf6_lsdb_add(ospf6_lsa_copy(new), from->lsack_list);
		event_add_event(master, ospf6_lsack_send_neighbor, from, 0,
				&from->thread_send_lsack);

		/* b) Discard */
		ospf6_lsa_delete(new);
		return;
	}

	/* (5) */
	/* lookup the same database copy in lsdb */
	old = ospf6_lsdb_lookup(new->header->type, new->header->id,
				new->header->adv_router, new->lsdb);
	if (old) {
		ismore_recent = ospf6_lsa_compare(new, old);
		if (ntohl(new->header->seqnum) == ntohl(old->header->seqnum)) {
			if (is_debug)
				zlog_debug("Received is duplicated LSA");
			SET_FLAG(new->flag, OSPF6_LSA_DUPLICATE);
		}
	}

	/* if no database copy or received is more recent */
	if (old == NULL || ismore_recent < 0) {
		bool self_originated;

		/* in case we have no database copy */
		ismore_recent = -1;

		/* (a) MinLSArrival check */
		if (old) {
			if (ospf6_lsa_check_min_arrival(old, from)) {
				ospf6_lsa_delete(new);
				return; /* examin next lsa */
			}
		}

		monotime(&new->received);

		if (is_debug)
			zlog_debug(
				"Install, Flood, Possibly acknowledge the received LSA");

		/* Remove older copies of this LSA from retx lists */
		if (old)
			ospf6_flood_clear(old);

		self_originated = (new->header->adv_router
				   == from->ospf6_if->area->ospf6->router_id);

		/* Received non-self-originated Grace LSA. */
		if (IS_GRACE_LSA(new) && !self_originated) {
			struct ospf6 *ospf6;

			ospf6 = ospf6_get_by_lsdb(new);

			assert(ospf6);

			if (OSPF6_LSA_IS_MAXAGE(new)) {

				if (IS_DEBUG_OSPF6_GR)
					zlog_debug(
						"%s, Received a maxage GraceLSA from router %pI4",
						__func__,
						&new->header->adv_router);
				if (old) {
					ospf6_process_maxage_grace_lsa(
						ospf6, new, from);
				} else {
					if (IS_DEBUG_OSPF6_GR)
						zlog_debug(
							"%s, GraceLSA doesn't exist in lsdb, so discarding GraceLSA",
							__func__);
					ospf6_lsa_delete(new);
					return;
				}
			} else {

				if (IS_DEBUG_OSPF6_GR)
					zlog_debug(
						"%s, Received a GraceLSA from router %pI4",
						__func__,
						&new->header->adv_router);

				if (ospf6_process_grace_lsa(ospf6, new, from)
				    == OSPF6_GR_NOT_HELPER) {
					if (IS_DEBUG_OSPF6_GR)
						zlog_debug(
							"%s, Not moving to HELPER role, So dicarding GraceLSA",
							__func__);
					return;
				}
			}
		}

		/* (b) immediately flood and (c) remove from all retrans-list */
		/* Prevent self-originated LSA to be flooded. this is to make
		 * reoriginated instance of the LSA not to be rejected by other
		 * routers due to MinLSArrival.
		 */
		if (!self_originated)
			ospf6_flood(from, new);

		/* (d), installing lsdb, which may cause routing
			table calculation (replacing database copy) */
		ospf6_install_lsa(new);

		if (OSPF6_LSA_IS_MAXAGE(new))
			ospf6_maxage_remove(from->ospf6_if->area->ospf6);

		/* (e) possibly acknowledge */
		ospf6_acknowledge_lsa(new, ismore_recent, from);

		/* (f) Self Originated LSA, section 13.4 */
		if (self_originated) {
			if (from->ospf6_if->area->ospf6->gr_info
				    .restart_in_progress) {
				if (IS_DEBUG_OSPF6_GR)
					zlog_debug(
						"Graceful Restart in progress -- not flushing self-originated LSA: %s",
						new->name);
				return;
			}

			/* Self-originated LSA (newer than ours) is received
			   from
			   another router. We have to make a new instance of the
			   LSA
			   or have to flush this LSA. */
			if (is_debug) {
				zlog_debug(
					"Newer instance of the self-originated LSA");
				zlog_debug("Schedule reorigination");
			}
			event_add_event(master, ospf6_lsa_refresh, new, 0,
					&new->refresh);
		}

		/* GR: check for network topology change. */
		struct ospf6 *ospf6 = from->ospf6_if->area->ospf6;
		struct ospf6_area *area = from->ospf6_if->area;
		if (ospf6->gr_info.restart_in_progress &&
		    (new->header->type == ntohs(OSPF6_LSTYPE_ROUTER) ||
		     new->header->type == ntohs(OSPF6_LSTYPE_NETWORK)))
			ospf6_gr_check_lsdb_consistency(ospf6, area);

		return;
	}

	/* (6) if there is instance on sending neighbor's request list */
	if (ospf6_lsdb_lookup(new->header->type, new->header->id,
			      new->header->adv_router, from->request_list)) {
		/* if no database copy, should go above state (5) */
		assert(old);

		zlog_warn(
			"Received is not newer, on the neighbor %s request-list",
			from->name);
		zlog_warn(
			"BadLSReq, discard the received LSA lsa %s send badLSReq",
			new->name);

		/* BadLSReq */
		event_add_event(master, bad_lsreq, from, 0, NULL);

		ospf6_lsa_delete(new);
		return;
	}

	/* (7) if neither one is more recent */
	if (ismore_recent == 0) {
		if (is_debug)
			zlog_debug(
				"The same instance as database copy (neither recent)");

		/* (a) if on retrans-list, Treat this LSA as an Ack: Implied Ack
		 */
		rem = ospf6_lsdb_lookup(new->header->type, new->header->id,
					new->header->adv_router,
					from->retrans_list);
		if (rem) {
			if (is_debug) {
				zlog_debug(
					"It is on the neighbor's retrans-list.");
				zlog_debug(
					"Treat as an Implied acknowledgement");
			}
			SET_FLAG(new->flag, OSPF6_LSA_IMPLIEDACK);
			ospf6_decrement_retrans_count(rem);
			ospf6_lsdb_remove(rem, from->retrans_list);
		}

		if (is_debug)
			zlog_debug("Possibly acknowledge and then discard");

		/* (b) possibly acknowledge */
		ospf6_acknowledge_lsa(new, ismore_recent, from);

		ospf6_lsa_delete(new);
		return;
	}

	/* (8) previous database copy is more recent */
	{
		assert(old);

		/* If database copy is in 'Seqnumber Wrapping',
		   simply discard the received LSA */
		if (OSPF6_LSA_IS_MAXAGE(old)
		    && old->header->seqnum == htonl(OSPF_MAX_SEQUENCE_NUMBER)) {
			if (is_debug) {
				zlog_debug("The LSA is in Seqnumber Wrapping");
				zlog_debug("MaxAge & MaxSeqNum, discard");
			}
			ospf6_lsa_delete(new);
			return;
		}

		/* Otherwise, Send database copy of this LSA to this neighbor */
		{
			if (is_debug) {
				zlog_debug("Database copy is more recent.");
				zlog_debug(
					"Send back directly and then discard");
			}

			/* Neighbor router sent recent age for LSA,
			 * Router could be restarted while current copy is
			 * MAXAGEd and not removed.*/
			if (OSPF6_LSA_IS_MAXAGE(old)
			    && !OSPF6_LSA_IS_MAXAGE(new)) {
				if (new->header->adv_router
				    != from->ospf6_if->area->ospf6->router_id) {
					if (is_debug)
						zlog_debug(
							"%s: Current copy of LSA %s is MAXAGE, but new has recent age, flooding/installing.",
							__PRETTY_FUNCTION__, old->name);
					ospf6_lsa_purge(old);
					ospf6_flood(from, new);
					ospf6_install_lsa(new);
					return;
				}
				/* For self-originated LSA, only trust
				 * ourselves. Fall through and send
				 * LS Update with our current copy.
				 */
				if (is_debug)
					zlog_debug(
						"%s: Current copy of self-originated LSA %s is MAXAGE, but new has recent age, re-sending current one.",
						__PRETTY_FUNCTION__, old->name);
			}

			/* MinLSArrival check as per RFC 2328 13 (8) */
			if (ospf6_lsa_check_min_arrival(old, from)) {
				ospf6_lsa_delete(new);
				return; /* examin next lsa */
			}

			ospf6_lsdb_add(ospf6_lsa_copy(old),
				       from->lsupdate_list);
			event_add_event(master, ospf6_lsupdate_send_neighbor,
					from, 0, &from->thread_send_lsupdate);

			ospf6_lsa_delete(new);
			return;
		}
	}
}

DEFUN (debug_ospf6_flooding,
       debug_ospf6_flooding_cmd,
       "debug ospf6 flooding",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 flooding function\n"
      )
{
	OSPF6_DEBUG_FLOODING_ON();
	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_flooding,
       no_debug_ospf6_flooding_cmd,
       "no debug ospf6 flooding",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 flooding function\n"
      )
{
	OSPF6_DEBUG_FLOODING_OFF();
	return CMD_SUCCESS;
}

int config_write_ospf6_debug_flood(struct vty *vty)
{
	if (IS_OSPF6_DEBUG_FLOODING)
		vty_out(vty, "debug ospf6 flooding\n");
	return 0;
}

void install_element_ospf6_debug_flood(void)
{
	install_element(ENABLE_NODE, &debug_ospf6_flooding_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_flooding_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_flooding_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_flooding_cmd);
}
