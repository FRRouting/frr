/*
 * OSPFv3 Not So Stubby Area implementation.
 *
 * Copyright (C) 2021 Kaushik Nath
 * Copyright (C) 2021 Soman K.S
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <zebra.h>
#include "log.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "linklist.h"
#include "command.h"
#include "thread.h"
#include "plist.h"
#include "filter.h"

#include "ospf6_proto.h"
#include "ospf6_route.h"
#include "ospf6_lsa.h"
#include "ospf6_route.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"
#include "ospf6_zebra.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"

#include "ospf6_flood.h"
#include "ospf6_intra.h"
#include "ospf6_abr.h"
#include "ospf6_asbr.h"
#include "ospf6d.h"
#include "ospf6_nssa.h"

DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_LSA,         "OSPF6 LSA");
unsigned char config_debug_ospf6_nssa = 0;
/* Determine whether this router is elected translator or not for area */
static int ospf6_abr_nssa_am_elected(struct ospf6_area *oa)
{
	struct ospf6_lsa *lsa;
	struct ospf6_router_lsa *router_lsa;
	in_addr_t *best = NULL;
	uint16_t type;

	type = htons(OSPF6_LSTYPE_ROUTER);

	/* Verify all the router LSA to compare the router ID */
	for (ALL_LSDB_TYPED(oa->lsdb, type, lsa)) {

		router_lsa = (struct ospf6_router_lsa
				      *)((caddr_t)lsa->header
					 + sizeof(struct ospf6_lsa_header));

		/* ignore non-ABR routers */
		if (!CHECK_FLAG(router_lsa->bits, OSPF6_ROUTER_BIT_B))
			continue;

		/* Router has Nt flag - always translate */
		if (CHECK_FLAG(router_lsa->bits, OSPF6_ROUTER_BIT_NT)) {
			if (IS_OSPF6_DEBUG_NSSA)
				zlog_debug("%s: router %pI4 asserts Nt",
					   __func__, &lsa->header->id);
			return 1;
		}

		if (best == NULL)
			best = &lsa->header->adv_router;
		else if (IPV4_ADDR_CMP(best, &lsa->header->adv_router) < 0)
			best = &lsa->header->adv_router;
	}

	if (best == NULL) {
		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug("%s: best electable ABR not found",
				   __func__);
		return 0;
	}

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("%s: best electable ABR is: %pI4", __func__, best);

	if (IPV4_ADDR_CMP(best, &oa->ospf6->router_id) <= 0) {
		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug("%s: elected ABR is: %pI4", __func__, best);
		return 1;
	} else {
		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug("%s: not elected best %pI4, router ID %pI4",
				   __func__, best, &oa->ospf6->router_id);
		return 0;
	}
}

/* Flush the translated LSA when translation is disabled */
static void ospf6_flush_translated_lsa(struct ospf6_area *area)
{
	uint16_t type;
	struct ospf6_lsa *type7;
	struct ospf6_lsa *type5;
	struct ospf6 *ospf6 = area->ospf6;

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("%s: start area %s", __func__, area->name);

	type = htons(OSPF6_LSTYPE_TYPE_7);
	for (ALL_LSDB_TYPED_ADVRTR(area->lsdb, type, ospf6->router_id, type7)) {
		type5 = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_AS_EXTERNAL),
					  type7->external_lsa_id,
					  ospf6->router_id, ospf6->lsdb);
		if (type5 && CHECK_FLAG(type5->flag, OSPF6_LSA_LOCAL_XLT))
			ospf6_lsa_premature_aging(type5);
	}
	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("%s: finish area %s", __func__, area->name);
}

/* Check NSSA status for all nssa areas*/
void ospf6_abr_nssa_check_status(struct ospf6 *ospf6)
{
	struct ospf6_area *area;
	struct listnode *lnode, *nnode;

	for (ALL_LIST_ELEMENTS(ospf6->area_list, lnode, nnode, area)) {
		uint8_t old_state = area->NSSATranslatorState;

		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug("%s: checking area %s flag %x", __func__,
				   area->name, area->flag);

		if (!IS_AREA_NSSA(area))
			continue;

		if (!CHECK_FLAG(area->ospf6->flag, OSPF6_FLAG_ABR)) {
			if (IS_OSPF6_DEBUG_NSSA)
				zlog_debug("%s: not ABR", __func__);
			area->NSSATranslatorState =
				OSPF6_NSSA_TRANSLATE_DISABLED;
			ospf6_flush_translated_lsa(area);
		} else {
			/* Router is ABR */
			if (area->NSSATranslatorRole == OSPF6_NSSA_ROLE_ALWAYS)
				area->NSSATranslatorState =
					OSPF6_NSSA_TRANSLATE_ENABLED;
			else {
				/* We are a candidate for Translation */
				if (ospf6_abr_nssa_am_elected(area) > 0) {
					area->NSSATranslatorState =
						OSPF6_NSSA_TRANSLATE_ENABLED;
					if (IS_OSPF6_DEBUG_NSSA)
						zlog_debug(
							"%s: elected translator",
							__func__);
				} else {
					area->NSSATranslatorState =
						OSPF6_NSSA_TRANSLATE_DISABLED;
					ospf6_flush_translated_lsa(area);
					if (IS_OSPF6_DEBUG_NSSA)
						zlog_debug("%s: not elected",
							   __func__);
				}
			}
		}

		/* RFC3101, 3.1:
		 * All NSSA border routers must set the E-bit in the Type-1
		 * router-LSAs of their directly attached non-stub areas, even
		 * when they are not translating.
		 */
		if (old_state != area->NSSATranslatorState) {
			if (old_state == OSPF6_NSSA_TRANSLATE_DISABLED)
				ospf6_asbr_status_update(ospf6,
							 ++ospf6->redist_count);
			else
				ospf6_asbr_status_update(ospf6,
							 --ospf6->redist_count);
		}
	}
}

/* Mark the summary LSA's as unapproved, when ABR status changes.*/
static void ospf6_abr_unapprove_summaries(struct ospf6 *ospf6)
{
	struct listnode *node, *nnode;
	struct ospf6_area *area;
	struct ospf6_lsa *lsa;
	uint16_t type;

	if (IS_OSPF6_DEBUG_ABR)
		zlog_debug("%s : Start", __func__);

	for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, area)) {
		if (IS_OSPF6_DEBUG_ABR)
			zlog_debug("%s : considering area %pI4", __func__,
				   &area->area_id);
		/* Inter area router LSA */
		type = htons(OSPF6_LSTYPE_INTER_ROUTER);
		for (ALL_LSDB_TYPED_ADVRTR(area->lsdb, type, ospf6->router_id,
					   lsa)) {
			if (IS_OSPF6_DEBUG_ABR)
				zlog_debug(
					"%s : approved unset on summary link id %pI4",
					__func__, &lsa->header->id);
			SET_FLAG(lsa->flag, OSPF6_LSA_UNAPPROVED);
		}
		/* Inter area prefix LSA */
		type = htons(OSPF6_LSTYPE_INTER_PREFIX);
		for (ALL_LSDB_TYPED_ADVRTR(area->lsdb, type, ospf6->router_id,
					   lsa)) {
			if (IS_OSPF6_DEBUG_ABR)
				zlog_debug(
					"%s : approved unset on asbr-summary link id %pI4",
					__func__, &lsa->header->id);
			SET_FLAG(lsa->flag, OSPF6_LSA_UNAPPROVED);
		}
	}

	if (IS_OSPF6_DEBUG_ABR)
		zlog_debug("%s : Stop", __func__);
}

/* Re-advertise inter-area router LSA's */
void ospf6_asbr_prefix_readvertise(struct ospf6 *ospf6)
{
	struct ospf6_route *brouter;
	struct listnode *node, *nnode;
	struct ospf6_area *oa;

	if (IS_OSPF6_DEBUG_ABR)
		zlog_debug("Re-examining Inter-Router prefixes");


	for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, oa)) {
		for (brouter = ospf6_route_head(oa->ospf6->brouter_table);
		     brouter; brouter = ospf6_route_next(brouter))
			ospf6_abr_originate_summary_to_area(brouter, oa);
	}

	if (IS_OSPF6_DEBUG_ABR)
		zlog_debug("Finished re-examining Inter-Router prefixes");
}

/* Advertise prefixes configured using area <area-id> range command */
static void ospf6_abr_announce_aggregates(struct ospf6 *ospf6)
{
	struct ospf6_area *area;
	struct ospf6_route *range;
	struct listnode *node, *nnode;

	if (IS_OSPF6_DEBUG_ABR)
		zlog_debug("ospf6_abr_announce_aggregates(): Start");

	for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, area)) {
		for (range = ospf6_route_head(area->range_table); range;
		     range = ospf6_route_next(range))
			ospf6_abr_range_update(range, ospf6);
	}

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, area)) {
		if (IS_OSPF6_DEBUG_ABR)
			zlog_debug(
				"ospf_abr_announce_aggregates(): looking at area %pI4",
				&area->area_id);
	}

	if (IS_OSPF6_DEBUG_ABR)
		zlog_debug("ospf6_abr_announce_aggregates(): Stop");
}

/* Flush the summary LSA's which are not approved.*/
void ospf6_abr_remove_unapproved_summaries(struct ospf6 *ospf6)
{
	struct listnode *node, *nnode;
	struct ospf6_area *area;
	struct ospf6_lsa *lsa;
	uint16_t type;

	if (IS_OSPF6_DEBUG_ABR)
		zlog_debug("%s : Start", __func__);

	for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, area)) {
		if (IS_OSPF6_DEBUG_ABR)
			zlog_debug("%s : looking at area %pI4", __func__,
				   &area->area_id);

		/* Inter area router LSA */
		type = htons(OSPF6_LSTYPE_INTER_ROUTER);
		for (ALL_LSDB_TYPED_ADVRTR(area->lsdb, type, ospf6->router_id,
					   lsa)) {
			if (CHECK_FLAG(lsa->flag, OSPF6_LSA_UNAPPROVED)) {
				lsa->header->age = htons(OSPF_LSA_MAXAGE);
				THREAD_OFF(lsa->refresh);
				thread_execute(master, ospf6_lsa_expire, lsa,
					       0);
			}
		}

		/* Inter area prefix LSA */
		type = htons(OSPF6_LSTYPE_INTER_PREFIX);
		for (ALL_LSDB_TYPED_ADVRTR(area->lsdb, type, ospf6->router_id,
					   lsa)) {
			if (CHECK_FLAG(lsa->flag, OSPF6_LSA_UNAPPROVED)) {
				lsa->header->age = htons(OSPF_LSA_MAXAGE);
				THREAD_OFF(lsa->refresh);
				thread_execute(master, ospf6_lsa_expire, lsa,
					       0);
			}
		}
	}

	if (IS_OSPF6_DEBUG_ABR)
		zlog_debug("%s : Stop", __func__);
}

/*
 * This is the function taking care about ABR stuff, i.e.
 * summary-LSA origination and flooding.
 */
static void ospf6_abr_task(struct ospf6 *ospf6)
{
	if (IS_OSPF6_DEBUG_ABR)
		zlog_debug("%s : Start", __func__);

	if (ospf6->route_table == NULL || ospf6->brouter_table == NULL) {
		if (IS_OSPF6_DEBUG_ABR)
			zlog_debug("%s : Routing tables are not yet ready",
				   __func__);
		return;
	}

	ospf6_abr_unapprove_summaries(ospf6);

	if (IS_OSPF6_DEBUG_ABR)
		zlog_debug("%s : prepare aggregates", __func__);

	ospf6_abr_range_reset_cost(ospf6);

	if (IS_OSPF6_ABR(ospf6)) {
		if (IS_OSPF6_DEBUG_ABR)
			zlog_debug("%s : process network RT", __func__);
		ospf6_abr_prefix_resummarize(ospf6);

		if (IS_OSPF6_DEBUG_ABR)
			zlog_debug("%s : process router RT", __func__);
		ospf6_asbr_prefix_readvertise(ospf6);

		if (IS_OSPF6_DEBUG_ABR)
			zlog_debug("%s : announce aggregates", __func__);
		ospf6_abr_announce_aggregates(ospf6);

		if (IS_OSPF6_DEBUG_ABR)
			zlog_debug("%s : announce stub defaults", __func__);
		ospf6_abr_defaults_to_stub(ospf6);
	}

	if (IS_OSPF6_DEBUG_ABR)
		zlog_debug("%s : remove unapproved summaries", __func__);
	ospf6_abr_remove_unapproved_summaries(ospf6);

	if (IS_OSPF6_DEBUG_ABR)
		zlog_debug("%s : Stop", __func__);
}

/* For NSSA Translations
 * Mark the translated LSA's as unapproved. */
static void ospf6_abr_unapprove_translates(struct ospf6 *ospf6)
{
	struct ospf6_lsa *lsa;
	uint16_t type;
	struct ospf6_area *oa;
	struct listnode *node;

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("ospf6_abr_unapprove_translates(): Start");

	type = htons(OSPF6_LSTYPE_AS_EXTERNAL);
	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, oa)) {
		for (ALL_LSDB_TYPED(oa->lsdb, type, lsa)) {
			if (CHECK_FLAG(lsa->flag, OSPF6_LSA_LOCAL_XLT)) {
				SET_FLAG(lsa->flag, OSPF6_LSA_UNAPPROVED);
				if (IS_OSPF6_DEBUG_NSSA)
					zlog_debug(
						"%s : approved unset on link id %pI4",
						__func__, &lsa->header->id);
			}
		}
	}

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("ospf6_abr_unapprove_translates(): Stop");
}

/* Generate the translated external lsa  from NSSA lsa */
static struct ospf6_lsa *ospf6_lsa_translated_nssa_new(struct ospf6_area *area,
						       struct ospf6_lsa *type7)
{
	char *buffer;
	struct ospf6_lsa *lsa;
	struct ospf6_as_external_lsa *ext, *extnew;
	struct ospf6_lsa_header *lsa_header;
	caddr_t old_ptr, new_ptr;
	struct ospf6_as_external_lsa *nssa;
	struct prefix prefix;
	struct ospf6_route *match;
	struct ospf6 *ospf6 = area->ospf6;
	ptrdiff_t tag_offset = 0;
	route_tag_t network_order;

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("%s : Start", __func__);

	if (area->NSSATranslatorState == OSPF6_NSSA_TRANSLATE_DISABLED) {
		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug("%s: Translation disabled for area %s",
				   __func__, area->name);
		return NULL;
	}

	buffer = XCALLOC(MTYPE_OSPF6_LSA, OSPF6_MAX_LSASIZE);
	lsa_header = (struct ospf6_lsa_header *)buffer;
	extnew = (struct ospf6_as_external_lsa
			  *)((caddr_t)lsa_header
			     + sizeof(struct ospf6_lsa_header));
	ext = (struct ospf6_as_external_lsa
		       *)((caddr_t)(type7->header)
			  + sizeof(struct ospf6_lsa_header));
	old_ptr =
		(caddr_t)((caddr_t)ext + sizeof(struct ospf6_as_external_lsa));
	new_ptr = (caddr_t)((caddr_t)extnew
			    + sizeof(struct ospf6_as_external_lsa));

	memcpy(extnew, ext, sizeof(struct ospf6_as_external_lsa));

	/* find the translated Type-5 for this Type-7 */
	nssa = (struct ospf6_as_external_lsa *)OSPF6_LSA_HEADER_END(
		type7->header);

	prefix.family = AF_INET6;
	prefix.prefixlen = nssa->prefix.prefix_length;
	ospf6_prefix_in6_addr(&prefix.u.prefix6, nssa, &nssa->prefix);

	/* Find the LSA from the external route */
	match = ospf6_route_lookup(&prefix, area->route_table);
	if (match == NULL) {
		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug("%s : no matching route %pFX", __func__,
				   &prefix);
		return NULL;
	}

	/* set Prefix */
	memcpy(new_ptr, old_ptr, OSPF6_PREFIX_SPACE(ext->prefix.prefix_length));
	ospf6_prefix_apply_mask(&extnew->prefix);
	new_ptr += OSPF6_PREFIX_SPACE(extnew->prefix.prefix_length);

	tag_offset =
		sizeof(*ext) + OSPF6_PREFIX_SPACE(ext->prefix.prefix_length);

	/* Forwarding address */
	if (CHECK_FLAG(ext->bits_metric, OSPF6_ASBR_BIT_F)) {
		memcpy(new_ptr, (caddr_t)ext + tag_offset,
		       sizeof(struct in6_addr));
		new_ptr += sizeof(struct in6_addr);
		tag_offset += sizeof(struct in6_addr);
	}
	/* External Route Tag */
	if (CHECK_FLAG(ext->bits_metric, OSPF6_ASBR_BIT_T)) {
		memcpy(&network_order, (caddr_t)ext + tag_offset,
		       sizeof(network_order));
		network_order = htonl(network_order);
		memcpy(new_ptr, &network_order, sizeof(network_order));
		new_ptr += sizeof(network_order);
	}

	/* Fill LSA Header */
	lsa_header->age = 0;
	lsa_header->type = htons(OSPF6_LSTYPE_AS_EXTERNAL);
	lsa_header->id = htonl(ospf6->external_id);
	ospf6->external_id++;
	lsa_header->adv_router = ospf6->router_id;
	lsa_header->seqnum =
		ospf6_new_ls_seqnum(lsa_header->type, lsa_header->id,
				    lsa_header->adv_router, ospf6->lsdb);
	lsa_header->length = htons((caddr_t)new_ptr - (caddr_t)lsa_header);
	type7->external_lsa_id = lsa_header->id;

	/* LSA checksum */
	ospf6_lsa_checksum(lsa_header);

	/* create LSA */
	lsa = ospf6_lsa_create(lsa_header);

	SET_FLAG(lsa->flag, OSPF6_LSA_LOCAL_XLT);
	UNSET_FLAG(lsa->flag, OSPF6_LSA_UNAPPROVED);

	/* Originate */
	ospf6_lsa_originate_process(lsa, ospf6);

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("%s: Originated type5 LSA id %pI4", __func__,
			   &lsa_header->id);
	return lsa;
}

/* Delete LSA from retransmission list */
static void ospf6_ls_retransmit_delete_nbr_as(struct ospf6 *ospf6,
					      struct ospf6_lsa *lsa)
{
	struct listnode *node, *nnode;
	struct ospf6_area *area;

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("%s : start lsa %s", __func__, lsa->name);

	/*The function ospf6_flood_clear_area removes LSA from
	 * retransmit list.
	 */
	for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, area))
		ospf6_flood_clear_area(lsa, area);

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("%s : finish  lsa %s", __func__, lsa->name);
}

/* Refresh translated  AS-external-LSA. */
struct ospf6_lsa *ospf6_translated_nssa_refresh(struct ospf6_area *area,
						struct ospf6_lsa *type7,
						struct ospf6_lsa *type5)
{
	struct ospf6_lsa *new = NULL;
	struct ospf6_as_external_lsa *ext_lsa;
	struct prefix prefix;
	struct ospf6 *ospf6 = area->ospf6;

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("%s : start area %s", __func__, area->name);

	/* Sanity checks. */
	assert(type7);

	/* Find the AS external LSA */
	if (type5 == NULL) {
		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug(
				"%s: No translated Type-5 found for Type-7 with Id %pI4",
				__func__, &type7->header->id);

		/* find the translated Type-5 for this Type-7 */
		ext_lsa = (struct ospf6_as_external_lsa *)OSPF6_LSA_HEADER_END(
			type7->header);

		prefix.family = AF_INET6;
		prefix.prefixlen = ext_lsa->prefix.prefix_length;
		ospf6_prefix_in6_addr(&prefix.u.prefix6, ext_lsa,
				      &ext_lsa->prefix);

		/* Find the AS external LSA from Type-7 LSA */
		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug("%s: try to find external LSA id %d",
				   __func__, type7->external_lsa_id);
		type5 = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_AS_EXTERNAL),
					  type7->external_lsa_id,
					  ospf6->router_id, ospf6->lsdb);
	}

	if (type5) {
		if (CHECK_FLAG(type5->flag, OSPF6_LSA_LOCAL_XLT)) {
			/* Delete LSA from neighbor retransmit-list. */
			ospf6_ls_retransmit_delete_nbr_as(ospf6, type5);

			/* Flush the LSA */
			ospf6_lsa_premature_aging(type5);
		} else {
			if (IS_OSPF6_DEBUG_NSSA)
				zlog_debug("%s: Invalid translated LSA %s",
					   __func__, type5->name);
			return NULL;
		}
	}

	/* create new translated LSA */
	if (ospf6_lsa_age_current(type7) != OSPF_LSA_MAXAGE) {
		if ((new = ospf6_lsa_translated_nssa_new(area, type7))
		    == NULL) {
			if (IS_OSPF6_DEBUG_NSSA)
				zlog_debug(
					"%s: Could not translate Type-7 for %pI4",
					__func__, &type7->header->id);
			return NULL;
		}
	}

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("%s: finish", __func__);

	return new;
}

/* Originate Translated Type-5 for supplied Type-7 NSSA LSA */
struct ospf6_lsa *ospf6_translated_nssa_originate(struct ospf6_area *oa,
						  struct ospf6_lsa *type7)
{
	struct ospf6_lsa *new;

	if (ntohs(type7->header->type) != OSPF6_LSTYPE_TYPE_7)
		return NULL;

	if ((new = ospf6_lsa_translated_nssa_new(oa, type7)) == NULL) {
		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug(
				"%s : Could not translate Type-7, Id %pI4, to Type-5",
				__func__, &type7->header->id);
		return NULL;
	}

	return new;
}

int ospf6_abr_translate_nssa(struct ospf6_area *area, struct ospf6_lsa *lsa)
{
	/* Incoming Type-7 or later aggregated Type-7
	 *
	 * LSA is skipped if P-bit is off.
	 * LSA is aggregated if within range.
	 *
	 * The Type-7 is translated, Installed/Approved as a Type-5 into
	 * global LSDB, then Flooded through AS
	 *
	 *  Later, any Unapproved Translated Type-5's are flushed/discarded
	 */

	struct ospf6_lsa *old = NULL, *new = NULL;
	struct ospf6_as_external_lsa *nssa_lsa;
	struct prefix prefix;
	struct ospf6_route *match;
	struct ospf6 *ospf6;

	ospf6 = area->ospf6;
	nssa_lsa = (struct ospf6_as_external_lsa *)OSPF6_LSA_HEADER_END(
		lsa->header);

	if (!CHECK_FLAG(nssa_lsa->prefix.prefix_options,
			OSPF6_PREFIX_OPTION_P)) {
		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug(
				"%s : LSA Id %pI4, P-bit off, NO Translation",
				__func__, &lsa->header->id);
		return 1;
	}

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug(
			"%s : LSA Id %pI4 external ID %pI4, Translating type 7 to 5",
			__func__, &lsa->header->id, &lsa->external_lsa_id);

	prefix.family = AF_INET6;
	prefix.prefixlen = nssa_lsa->prefix.prefix_length;
	ospf6_prefix_in6_addr(&prefix.u.prefix6, nssa_lsa, &nssa_lsa->prefix);

	if (!CHECK_FLAG(nssa_lsa->bits_metric, OSPF6_ASBR_BIT_F)) {
		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug(
				"%s : LSA Id %pI4, Forward address is 0, NO Translation",
				__func__, &lsa->header->id);
		return 1;
	}

	/* Find the existing AS-External LSA for this prefix */
	match = ospf6_route_lookup(&prefix, ospf6->external_table);
	if (match) {
		old = ospf6_lsdb_lookup(OSPF6_LSTYPE_AS_EXTERNAL,
					match->path.origin.id, ospf6->router_id,
					ospf6->lsdb);
	}

	/* Check Type 5 LSA using the matching external ID */
	if (old == NULL) {
		old = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_AS_EXTERNAL),
					lsa->external_lsa_id, ospf6->router_id,
					ospf6->lsdb);
	}

	if (old) {
		/* Do not continue if type 5 LSA not approved */
		if (CHECK_FLAG(old->flag, OSPF6_LSA_UNAPPROVED)) {
			if (IS_OSPF6_DEBUG_NSSA)
				zlog_debug(
					"%s : LSA Id %pI4 type 5 is not approved",
					__func__, &old->header->id);
			return 1;
		}

		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug(
				"%s : found old translated LSA Id %pI4, refreshing",
				__func__, &old->header->id);

		/* refresh */
		new = ospf6_translated_nssa_refresh(area, lsa, old);
		if (!new) {
			if (IS_OSPF6_DEBUG_NSSA)
				zlog_debug(
					"%s : could not refresh translated LSA Id %pI4",
					__func__, &old->header->id);
		}
	} else {
		/* no existing external route for this LSA Id
		 * originate translated LSA
		 */

		if (ospf6_translated_nssa_originate(area, lsa) == NULL) {
			if (IS_OSPF6_DEBUG_NSSA)
				zlog_debug(
					"%s : Could not translate Type-7 for %pI4 to Type-5",
					__func__, &lsa->header->id);
			return 1;
		}
	}

	return 0;
}

static void ospf6_abr_process_nssa_translates(struct ospf6 *ospf6)
{
	/* Scan through all NSSA_LSDB records for all areas;
	 * If P-bit is on, translate all Type-7's to 5's and aggregate or\
	 * flood install as approved in Type-5 LSDB with XLATE Flag on
	 * later, do same for all aggregates...  At end, DISCARD all
	 * remaining UNAPPROVED Type-5's (Aggregate is for future ) */

	struct listnode *node;
	struct ospf6_area *oa;
	struct ospf6_lsa *lsa;
	int type;

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("%s : Start", __func__);

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, oa)) {

		/* skip if not translator */
		if (oa->NSSATranslatorState == OSPF6_NSSA_TRANSLATE_DISABLED) {
			zlog_debug("%s area %pI4 NSSATranslatorState %d",
				   __func__, &oa->area_id,
				   oa->NSSATranslatorState);
			continue;
		}

		/* skip if not Nssa Area */
		if (!IS_AREA_NSSA(oa)) {
			zlog_debug("%s area %pI4 Flag %x", __func__,
				   &oa->area_id, oa->flag);
			continue;
		}

		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug("%s : looking at area %pI4", __func__,
				   &oa->area_id);

		type = htons(OSPF6_LSTYPE_TYPE_7);
		for (ALL_LSDB_TYPED(oa->lsdb, type, lsa)) {
			zlog_debug("%s : lsa %s , id %pI4 , adv router %pI4",
				   lsa->name, __func__, &lsa->header->id,
				   &lsa->header->adv_router);
			ospf6_abr_translate_nssa(oa, lsa);
		}
	}

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("%s : Stop", __func__);
}

/* Generate translated type-5 LSA from the configured area ranges*/
static void ospf6_abr_translate_nssa_range(struct ospf6 *ospf6)
{
	struct listnode *node, *nnode;
	struct ospf6_area *oa;
	struct ospf6_route *range;
	struct ospf6_lsa *lsa;

	for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, oa)) {
		for (range = ospf6_route_head(oa->range_table); range;
		     range = ospf6_route_next(range)) {
			if (IS_OSPF6_DEBUG_NSSA)
				zlog_debug(
					"Translating range %pFX of area %pI4",
					&range->prefix, &oa->area_id);
			if (CHECK_FLAG(range->flag,
				       OSPF6_ROUTE_DO_NOT_ADVERTISE))
				continue;

			/* Find the NSSA LSA from the route */
			/* Generate and flood external LSA */
			lsa = ospf6_lsdb_lookup(OSPF6_LSTYPE_TYPE_7,
						range->path.origin.id,
						ospf6->router_id, oa->lsdb);
			if (lsa)
				ospf6_abr_translate_nssa(oa, lsa);
		}
	}
}

static void ospf6_abr_send_nssa_aggregates(struct ospf6 *ospf6)
{
	struct listnode *node;
	struct ospf6_area *area;

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("%s : Start", __func__);

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, area)) {
		if (area->NSSATranslatorState == OSPF6_NSSA_TRANSLATE_DISABLED)
			continue;

		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug("%s : looking at area %pI4", __func__,
				   &area->area_id);

		ospf6_abr_translate_nssa_range(ospf6);
	}

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("%s : Stop", __func__);
}

/*Flood max age LSA's for the unapproved LSA's */
static int ospf6_abr_remove_unapproved_translates_apply(struct ospf6_lsa *lsa)
{
	if (CHECK_FLAG(lsa->flag, OSPF6_LSA_LOCAL_XLT)
	    && CHECK_FLAG(lsa->flag, OSPF6_LSA_UNAPPROVED)) {
		zlog_debug("%s : removing unapproved translates, lsa : %s",
			   __func__, lsa->name);

		/* FLUSH THROUGHOUT AS */
		ospf6_lsa_premature_aging(lsa);
	}
	return 0;
}

static void ospf6_abr_remove_unapproved_translates(struct ospf6 *ospf6)
{
	struct ospf6_lsa *lsa;
	uint16_t type;

	/* All AREA PROCESS should have APPROVED necessary LSAs */
	/* Remove any left over and not APPROVED */
	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("ospf6_abr_remove_unapproved_translates(): Start");

	type = htons(OSPF6_LSTYPE_AS_EXTERNAL);
	for (ALL_LSDB_TYPED(ospf6->lsdb, type, lsa))
		ospf6_abr_remove_unapproved_translates_apply(lsa);

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("ospf_abr_remove_unapproved_translates(): Stop");
}

static void ospf6_abr_nssa_task(struct ospf6 *ospf6)
{
	/* called only if any_nssa */
	struct ospf6_route *range;
	struct ospf6_area *area;
	struct listnode *node, *nnode;

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("Check for NSSA-ABR Tasks():");

	if (!IS_OSPF6_ABR(ospf6)) {
		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug("%s  Not ABR", __func__);
		return;
	}

	if (!ospf6->anyNSSA) {
		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug("%s  Not NSSA", __func__);
		return;
	}

	/* Each area must confirm TranslatorRole */
	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("ospf6_abr_nssa_task(): Start");

	/* For all Global Entries flagged "local-translate", unset APPROVED */
	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("ospf6_abr_nssa_task(): unapprove translates");

	ospf6_abr_unapprove_translates(ospf6);

	/* RESET all Ranges in every Area, same as summaries */
	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("ospf6_abr_nssa_task(): NSSA initialize aggregates");
	ospf6_abr_range_reset_cost(ospf6);

	/* For all NSSAs, Type-7s, translate to 5's, INSTALL/FLOOD, or
	 *  Aggregate as Type-7
	 * Install or Approve in Type-5 Global LSDB
	 */
	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("ospf6_abr_nssa_task(): process translates");
	ospf6_abr_process_nssa_translates(ospf6);

	/* Translate/Send any "ranged" aggregates, and also 5-Install and
	 *  Approve
	 * Scan Type-7's for aggregates, translate to Type-5's,
	 *  Install/Flood/Approve
	 */
	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("ospf6_abr_nssa_task(): send NSSA aggregates");
	ospf6_abr_send_nssa_aggregates(ospf6); /*TURNED OFF FOR NOW */

	/* Flush any unapproved previous translates from Global Data Base */
	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug(
			"ospf6_abr_nssa_task(): remove unapproved translates");
	ospf6_abr_remove_unapproved_translates(ospf6);

	for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, area)) {
		for (range = ospf6_route_head(area->range_table); range;
		     range = ospf6_route_next(range)) {
			if (CHECK_FLAG(range->flag,
				       OSPF6_ROUTE_DO_NOT_ADVERTISE))
				ospf6_zebra_delete_discard(range, ospf6);
			else
				ospf6_zebra_add_discard(range, ospf6);
		}
	}

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("ospf6_abr_nssa_task(): Stop");
}

int ospf6_redistribute_check(struct ospf6 *ospf6, struct ospf6_route *route,
			     int type)
{
	route_map_result_t ret;
	struct prefix *prefix;
	struct ospf6_redist *red;

	if (!ospf6_zebra_is_redistribute(type, ospf6->vrf_id))
		return 0;

	prefix = &route->prefix;

	red = ospf6_redist_lookup(ospf6, type, 0);
	if (!red)
		return 0;

	/* Change to new redist structure */
	if (ROUTEMAP_NAME(red)) {
		if (ROUTEMAP(red) == NULL)
			ospf6_asbr_routemap_update(NULL);
		if (ROUTEMAP(red) == NULL) {
			zlog_warn(
				"route-map \"%s\" not found, suppress redistributing",
				ROUTEMAP_NAME(red));
			return 0;
		}
	}

	/*  Change to new redist structure */
	if (ROUTEMAP(red)) {
		ret = route_map_apply(ROUTEMAP(red), prefix, route);
		if (ret == RMAP_DENYMATCH) {
			if (IS_OSPF6_DEBUG_ASBR)
				zlog_debug("Denied by route-map \"%s\"",
					   ROUTEMAP_NAME(red));
			return 0;
		}
	}

	return 1;
}

static void ospf6_external_lsa_refresh_type(struct ospf6 *ospf6, uint8_t type,
					    unsigned short instance, int force)
{
	struct ospf6_route *route;
	struct ospf6_external_info *info;
	struct ospf6_lsa *lsa;

	if (type == ZEBRA_ROUTE_MAX)
		return;

	for (route = ospf6_route_head(ospf6->external_table); route;
	     route = ospf6_route_next(route)) {
		info = route->route_option;

		/* Find the external LSA in the database */
		if (!is_default_prefix(&route->prefix)) {
			lsa = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_AS_EXTERNAL),
						htonl(info->id),
						ospf6->router_id, ospf6->lsdb);

			if (lsa) {
				THREAD_OFF(lsa->refresh);

				/* LSA is maxage,  immediate refresh */
				if (OSPF6_LSA_IS_MAXAGE(lsa))
					ospf6_flood(NULL, lsa);
				else
					thread_add_timer(master,
							 ospf6_lsa_refresh, lsa,
							 OSPF_LS_REFRESH_TIME,
							 &lsa->refresh);
			} else {
				/* LSA not found in the database
				 * Verify and originate  external LSA
				 */
				if (ospf6_redistribute_check(ospf6, route,
							     type))
					ospf6_as_external_lsa_originate(route,
									ospf6);
			}
		}
	}
}

/* Refresh default route */
static void ospf6_external_lsa_refresh_default(struct ospf6 *ospf6)
{
	struct ospf6_route *route;
	struct ospf6_external_info *info;
	struct ospf6_lsa *lsa;

	for (route = ospf6_route_head(ospf6->external_table); route;
	     route = ospf6_route_next(route)) {
		if (is_default_prefix(&route->prefix)) {
			info = route->route_option;
			lsa = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_AS_EXTERNAL),
						htonl(info->id),
						ospf6->router_id, ospf6->lsdb);

			if (lsa) {
				if (IS_OSPF6_DEBUG_NSSA)
					zlog_debug(
						"LSA[Type5:0.0.0.0]: Refresh AS-external-LSA %p",
						(void *)lsa);
				if (OSPF6_LSA_IS_MAXAGE(lsa))
					ospf6_flood(NULL, lsa);
				else
					thread_add_timer(master,
							 ospf6_lsa_refresh, lsa,
							 OSPF_LS_REFRESH_TIME,
							 &lsa->refresh);
			} else if (!lsa) {
				if (IS_OSPF6_DEBUG_NSSA)
					zlog_debug(
						"LSA[Type5:0.0.0.0]: Originate AS-external-LSA");
				ospf6_as_external_lsa_originate(route, ospf6);
			}
		}
	}
}

/* If there's redistribution configured, we need to refresh external
 * LSAs in order to install Type-7 and flood to all NSSA Areas
 */
void ospf6_asbr_nssa_redist_task(struct ospf6 *ospf6)
{
	int type;
	struct ospf6_redist *red;

	for (type = 0; type < ZEBRA_ROUTE_MAX; type++) {
		red = ospf6_redist_lookup(ospf6, type, 0);
		if (!red)
			return;

		ospf6_external_lsa_refresh_type(ospf6, type, red->instance,
						LSA_REFRESH_IF_CHANGED);
	}
	ospf6_external_lsa_refresh_default(ospf6);
}

/* This function performs ABR related processing */
static int ospf6_abr_task_timer(struct thread *thread)
{
	struct ospf6 *ospf6 = THREAD_ARG(thread);

	ospf6->t_abr_task = NULL;

	if (IS_OSPF6_DEBUG_ABR)
		zlog_debug("Running ABR task on timer");

	(void)ospf6_check_and_set_router_abr(ospf6);
	ospf6_abr_nssa_check_status(ospf6);
	ospf6_abr_task(ospf6);
	/* if nssa-abr, then scan Type-7 LSDB */
	ospf6_abr_nssa_task(ospf6);
	ospf6_asbr_nssa_redist_task(ospf6);

	return 0;
}

void ospf6_schedule_abr_task(struct ospf6 *ospf6)
{
	if (ospf6->t_abr_task) {
		if (IS_OSPF6_DEBUG_ABR)
			zlog_debug("ABR task already scheduled");
		return;
	}

	if (IS_OSPF6_DEBUG_ABR)
		zlog_debug("Scheduling ABR task");

	thread_add_timer(master, ospf6_abr_task_timer, ospf6,
			 OSPF6_ABR_TASK_DELAY, &ospf6->t_abr_task);
}

/* Flush the NSSA LSAs from the area */
static void ospf6_nssa_flush_area(struct ospf6_area *area)
{
	uint16_t type;
	struct ospf6_lsa *lsa = NULL, *type5 = NULL;
	struct ospf6 *ospf6 = area->ospf6;
	const struct route_node *rt = NULL;

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("%s: area %s", __func__, area->name);

	/* Flush the NSSA LSA */
	type = htons(OSPF6_LSTYPE_TYPE_7);
	rt = ospf6_lsdb_head(area->lsdb_self, 0, type, ospf6->router_id, &lsa);
	while (lsa) {
		lsa->header->age = htons(OSPF_LSA_MAXAGE);
		SET_FLAG(lsa->flag, OSPF6_LSA_FLUSH);
		ospf6_flood(NULL, lsa);
		/* Flush the translated LSA */
		if (ospf6_check_and_set_router_abr(ospf6)) {
			type = htons(OSPF6_LSTYPE_AS_EXTERNAL);
			type5 = ospf6_lsdb_lookup(
				htons(type), lsa->external_lsa_id,
				ospf6->router_id, ospf6->lsdb);
			if (type5
			    && CHECK_FLAG(type5->flag, OSPF6_LSA_LOCAL_XLT)) {
				type5->header->age = htons(OSPF_LSA_MAXAGE);
				SET_FLAG(type5->flag, OSPF6_LSA_FLUSH);
				ospf6_flood(NULL, type5);
			}
		}
		lsa = ospf6_lsdb_next(rt, lsa);
	}
}

static void ospf6_check_and_originate_type7_lsa(struct ospf6_area *area)
{
	struct ospf6_route rt_aggr, *route;
	struct route_node *rn = NULL;
	struct ospf6_external_info ei_aggr;
	struct ospf6_external_aggr_rt *aggr;

	/* Loop through the external_table to find the LSAs originated
	 * without aggregation and originate type-7 LSAs for them.
	 */
	for (route = ospf6_route_head(
		     area->ospf6->external_table);
	     route; route = ospf6_route_next(route)) {
		/* This means the Type-5 LSA was originated for this route */
		if (route->path.origin.id != 0)
			ospf6_nssa_lsa_originate(route, area);

	}

	/* Loop through the aggregation table to originate type-7 LSAs
	 * for the aggregated type-5 LSAs
	 */
	for (rn = route_top(area->ospf6->rt_aggr_tbl); rn;
	     rn = route_next(rn)) {
		if (!rn->info)
			continue;

		aggr = rn->info;

		if (CHECK_FLAG(aggr->aggrflags,
		    OSPF6_EXTERNAL_AGGRT_ORIGINATED)) {
			/* Prepare the external_info for aggregator */
			ospf6_fill_aggr_route_details(area->ospf6, &ei_aggr,
						      &rt_aggr, aggr);
			ospf6_nssa_lsa_originate(&rt_aggr, area);
		}
	}

}

static void ospf6_area_nssa_update(struct ospf6_area *area)
{
	if (IS_AREA_NSSA(area)) {
		if (!ospf6_check_and_set_router_abr(area->ospf6))
			OSPF6_OPT_CLEAR(area->options, OSPF6_OPT_E);
		area->ospf6->anyNSSA++;
		OSPF6_OPT_SET(area->options, OSPF6_OPT_N);
		area->NSSATranslatorRole = OSPF6_NSSA_ROLE_CANDIDATE;
	} else if (IS_AREA_ENABLED(area)) {
		if (IS_OSPF6_DEBUG_ORIGINATE(ROUTER))
			zlog_debug("Normal area for if %s", area->name);
		OSPF6_OPT_CLEAR(area->options, OSPF6_OPT_N);
		if (ospf6_check_and_set_router_abr(area->ospf6))
			OSPF6_OPT_SET(area->options, OSPF6_OPT_E);
		area->ospf6->anyNSSA--;
		area->NSSATranslatorState = OSPF6_NSSA_TRANSLATE_DISABLED;
	}

	/* Refresh router LSA */
	if (IS_AREA_NSSA(area)) {
		OSPF6_ROUTER_LSA_SCHEDULE(area);

		/* Check if router is ABR */
		if (ospf6_check_and_set_router_abr(area->ospf6)) {
			if (IS_OSPF6_DEBUG_NSSA)
				zlog_debug("Router is ABR area %s", area->name);
			ospf6_schedule_abr_task(area->ospf6);
		} else {
			/* Router is not ABR */
			if (IS_OSPF6_DEBUG_NSSA)
				zlog_debug("NSSA area %s", area->name);

			/* Originate NSSA LSA */
			ospf6_check_and_originate_type7_lsa(area);
		}
	} else {
		/* Disable NSSA */
		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug("Normal area %s", area->name);
		ospf6_nssa_flush_area(area);
		ospf6_area_disable(area);
		ospf6_area_delete(area);
	}
}

int ospf6_area_nssa_set(struct ospf6 *ospf6, struct ospf6_area *area)
{

	if (!IS_AREA_NSSA(area)) {
		SET_FLAG(area->flag, OSPF6_AREA_NSSA);
		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug("area %s nssa set", area->name);
		ospf6_area_nssa_update(area);
	}

	return 1;
}

int ospf6_area_nssa_unset(struct ospf6 *ospf6, struct ospf6_area *area)
{
	if (IS_AREA_NSSA(area)) {
		UNSET_FLAG(area->flag, OSPF6_AREA_NSSA);
		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug("area %s nssa reset", area->name);
		ospf6_area_nssa_update(area);
	}

	return 1;
}

/* Find the NSSA forwarding address */
static struct in6_addr *ospf6_get_nssa_fwd_addr(struct ospf6_area *oa)
{
	struct listnode *node, *nnode;
	struct ospf6_interface *oi;

	for (ALL_LIST_ELEMENTS(oa->if_list, node, nnode, oi)) {
		if (if_is_operative(oi->interface))
			if (oi->area && IS_AREA_NSSA(oi->area))
				return ospf6_interface_get_global_address(
					oi->interface);
	}
	return NULL;
}

void ospf6_nssa_lsa_originate(struct ospf6_route *route,
			      struct ospf6_area *area)
{
	char buffer[OSPF6_MAX_LSASIZE];
	struct ospf6_lsa_header *lsa_header;
	struct ospf6_lsa *lsa;
	struct ospf6_external_info *info = route->route_option;
	struct in6_addr *fwd_addr;

	struct ospf6_as_external_lsa *as_external_lsa;
	char buf[PREFIX2STR_BUFFER];
	caddr_t p;

	if (IS_OSPF6_DEBUG_ASBR || IS_OSPF6_DEBUG_ORIGINATE(AS_EXTERNAL)) {
		prefix2str(&route->prefix, buf, sizeof(buf));
		zlog_debug("Originate AS-External-LSA for %s", buf);
	}

	/* prepare buffer */
	memset(buffer, 0, sizeof(buffer));
	lsa_header = (struct ospf6_lsa_header *)buffer;
	as_external_lsa = (struct ospf6_as_external_lsa
				   *)((caddr_t)lsa_header
				      + sizeof(struct ospf6_lsa_header));
	p = (caddr_t)((caddr_t)as_external_lsa
		      + sizeof(struct ospf6_as_external_lsa));

	/* Fill AS-External-LSA */
	/* Metric type */
	if (route->path.metric_type == OSPF6_PATH_TYPE_EXTERNAL2)
		SET_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_E);
	else
		UNSET_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_E);

	/* external route tag */
	if (info->tag)
		SET_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_T);
	else
		UNSET_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_T);

	/* Set metric */
	OSPF6_ASBR_METRIC_SET(as_external_lsa, route->path.cost);

	/* prefixlen */
	as_external_lsa->prefix.prefix_length = route->prefix.prefixlen;

	/* PrefixOptions */
	as_external_lsa->prefix.prefix_options = route->path.prefix_options;

	/* Set the P bit */
	as_external_lsa->prefix.prefix_options |= OSPF6_PREFIX_OPTION_P;

	/* don't use refer LS-type */
	as_external_lsa->prefix.prefix_refer_lstype = htons(0);

	/* set Prefix */
	memcpy(p, &route->prefix.u.prefix6,
	       OSPF6_PREFIX_SPACE(route->prefix.prefixlen));
	ospf6_prefix_apply_mask(&as_external_lsa->prefix);
	p += OSPF6_PREFIX_SPACE(route->prefix.prefixlen);

	/* Forwarding address */
	fwd_addr = ospf6_get_nssa_fwd_addr(area);
	if (fwd_addr) {
		memcpy(p, fwd_addr, sizeof(struct in6_addr));
		p += sizeof(struct in6_addr);
		SET_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_F);
	} else
		UNSET_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_F);

	/* External Route Tag */
	if (CHECK_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_T)) {
		route_tag_t network_order = htonl(info->tag);

		memcpy(p, &network_order, sizeof(network_order));
		p += sizeof(network_order);
	}

	/* Fill LSA Header */
	lsa_header->age = 0;
	lsa_header->type = htons(OSPF6_LSTYPE_TYPE_7);
	lsa_header->id = route->path.origin.id;
	lsa_header->adv_router = area->ospf6->router_id;
	lsa_header->seqnum =
		ospf6_new_ls_seqnum(lsa_header->type, lsa_header->id,
				    lsa_header->adv_router, area->ospf6->lsdb);
	lsa_header->length = htons((caddr_t)p - (caddr_t)lsa_header);

	/* LSA checksum */
	ospf6_lsa_checksum(lsa_header);
	/* create LSA */
	lsa = ospf6_lsa_create(lsa_header);

	/* Originate */
	ospf6_lsa_originate_area(lsa, area);
}

void ospf6_abr_check_translate_nssa(struct ospf6_area *area,
				    struct ospf6_lsa *lsa)
{
	struct ospf6_lsa *type5 = NULL;
	struct ospf6 *ospf6 = area->ospf6;

	if (IS_OSPF6_DEBUG_NSSA)
		zlog_debug("%s : start", __func__);

	type5 = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_AS_EXTERNAL),
				  lsa->external_lsa_id, ospf6->router_id,
				  ospf6->lsdb);

	if (ospf6_check_and_set_router_abr(ospf6) && (type5 == NULL)) {
		if (IS_OSPF6_DEBUG_NSSA)
			zlog_debug("%s : Originating type5 LSA", __func__);
		ospf6_lsa_translated_nssa_new(area, lsa);
	}
}

DEFUN(debug_ospf6_nssa, debug_ospf6_nssa_cmd,
      "debug ospf6 nssa",
      DEBUG_STR
      OSPF6_STR
      "Debug OSPFv3 NSSA function\n")
{
	OSPF6_DEBUG_NSSA_ON();
	return CMD_SUCCESS;
}

DEFUN(no_debug_ospf6_nssa, no_debug_ospf6_nssa_cmd,
      "no debug ospf6 nssa",
      NO_STR
      DEBUG_STR
      OSPF6_STR
      "Debug OSPFv3 NSSA function\n")
{
	OSPF6_DEBUG_NSSA_OFF();
	return CMD_SUCCESS;
}

void config_write_ospf6_debug_nssa(struct vty *vty)
{
	if (IS_OSPF6_DEBUG_NSSA)
		vty_out(vty, "debug ospf6 nssa\n");
}

void install_element_ospf6_debug_nssa(void)
{
	install_element(ENABLE_NODE, &debug_ospf6_nssa_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_nssa_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_nssa_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_nssa_cmd);
}
