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

                router_lsa = (struct ospf6_router_lsa *)((caddr_t)lsa->header
				+ sizeof(struct ospf6_lsa_header));

                /* ignore non-ABR routers */
                if (!CHECK_FLAG(router_lsa->bits, OSPF6_ROUTER_BIT_B))
                        continue;

                /* Router has Nt flag - always translate */
                if (CHECK_FLAG(router_lsa->bits, OSPF6_ROUTER_BIT_NT)) {
                        if (IS_OSPF6_DEBUG_NSSA)
                                zlog_debug(
                                        "ospf6_abr_nssa_am_elected: router %pI4 asserts Nt",
                                        &lsa->header->id);
                        return 1;
                }

                if (best == NULL)
                        best = &lsa->header->adv_router;
                else if (IPV4_ADDR_CMP(&best, &lsa->header->adv_router) < 0)
                        best = &lsa->header->adv_router;
        }

        if (IS_OSPF6_DEBUG_NSSA)
                zlog_debug(
                        "ospf6_abr_nssa_am_elected: best electable ABR is: %pI4",
                        (best) ? best : 0);

        if (best == NULL)
                return 0;

        if (IPV4_ADDR_CMP(&best, &oa->ospf6->router_id) < 0)
                return 1;
        else
                return 0;
}

/* Check NSSA status for all nssa areas*/
static void ospf6_abr_nssa_check_status(struct ospf6 *ospf6)
{
        struct ospf6_area *area;
        struct listnode *lnode, *nnode;
	uint8_t old_state;

        for (ALL_LIST_ELEMENTS(ospf6->area_list, lnode, nnode, area)) {
		old_state = area->NSSATranslatorState;

                if (IS_OSPF6_DEBUG_NSSA)
                        zlog_debug(
                                "ospf6_abr_nssa_check_status: checking area %pI4 flag %x", 
				&area->area_id, area->flag);

                if (!IS_AREA_NSSA(area))
                        continue;

                if (!CHECK_FLAG(area->ospf6->flag, OSPF6_FLAG_ABR)) {
			  if (IS_OSPF6_DEBUG_NSSA)
                                zlog_debug(
                                        "ospf6_abr_nssa_check_status: not ABR");
                        area->NSSATranslatorState =
                                OSPF6_NSSA_TRANSLATE_DISABLED;
                } else {
                        /* We are a candidate for Translation */
			if (ospf6_abr_nssa_am_elected(area) > 0) {
                                        area->NSSATranslatorState =
                                                OSPF6_NSSA_TRANSLATE_ENABLED;
					  if (IS_OSPF6_DEBUG_NSSA)
                                                zlog_debug(
                                                        "ospf6_abr_nssa_check_status: elected translator");
			} else {
				area->NSSATranslatorState =
						OSPF6_NSSA_TRANSLATE_DISABLED;
					  if (IS_OSPF6_DEBUG_NSSA)
                                                zlog_debug(
                                                        "ospf6_abr_nssa_check_status: not elected");
			}
		}
		/* RFC3101, 3.1:
                 * All NSSA border routers must set the E-bit in the Type-1
                 * router-LSAs
                 * of their directly attached non-stub areas, even when they are
                 * not
                 * translating.
                 */
		if (old_state != area->NSSATranslatorState) {
                        if (old_state == OSPF6_NSSA_TRANSLATE_DISABLED)
                                ospf6_asbr_status_update(ospf6, ++ospf6->redist_count);
                        else if (area->NSSATranslatorState == OSPF6_NSSA_TRANSLATE_DISABLED)
                                ospf6_asbr_status_update(ospf6, --ospf6->redist_count);
                }
	}
}

/*Mark the summary LSA's as unapproved, when ABR status changes.*/
static void ospf6_abr_unapprove_summaries(struct ospf6 *ospf6)
{
	struct listnode *node, *nnode;
        struct ospf6_area *area;
        struct ospf6_lsa *lsa;
        uint16_t type;

        if (IS_OSPF6_DEBUG_ABR)
                zlog_debug("ospf6_abr_unapprove_summaries(): Start");

        for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, area)) {
                if (IS_OSPF6_DEBUG_ABR)
                        zlog_debug(
                                "ospf6_abr_unapprove_summaries(): considering area %pI4",
                                &area->area_id);
                /* Inter area router LSA */
                type = htons(OSPF6_LSTYPE_INTER_ROUTER);
                for (ALL_LSDB_TYPED_ADVRTR(area->lsdb, type, ospf6->router_id, lsa)) {
                                if (IS_OSPF6_DEBUG_ABR)
                                        zlog_debug(
                                                "ospf_abr_unapprove_summaries(): approved unset on summary link id %pI4",
                                                &lsa->header->id);
                        SET_FLAG(lsa->flag, OSPF6_LSA_UNAPPROVED);
                }
                /* Inter area prefix LSA */
                type = htons(OSPF6_LSTYPE_INTER_PREFIX);
                for (ALL_LSDB_TYPED_ADVRTR(area->lsdb, type, ospf6->router_id, lsa)) {
                                if (IS_OSPF6_DEBUG_ABR)
                                        zlog_debug(
                                                "ospf_abr_unapprove_summaries(): approved unset on asbr-summary link id %pI4",
                                                &lsa->header->id);
                        SET_FLAG(lsa->flag, OSPF6_LSA_UNAPPROVED);
                }
        }

        if (IS_OSPF6_DEBUG_ABR)
                zlog_debug("ospf6_abr_unapprove_summaries(): Stop");

}

/*Re-advertise inter-area router LSA's */
void ospf6_asbr_prefix_readvertise(struct ospf6 *ospf6)
{
        struct ospf6_route *brouter;
        struct listnode *node, *nnode;
        struct ospf6_area *oa;

        if (IS_OSPF6_DEBUG_ABR)
                zlog_debug("Re-examining Inter-Router prefixes");


        for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, oa)) {
                for (brouter = ospf6_route_head(oa->ospf6->brouter_table); brouter;
			brouter = ospf6_route_next(brouter))
                ospf6_abr_originate_summary_to_area(brouter, oa);
	}

        if (IS_OSPF6_DEBUG_ABR)
                zlog_debug("Finished re-examining Inter-Router prefixes");
}

/*Advertise prefixes configured using area <area-id> range command */
static void ospf6_abr_announce_aggregates(struct ospf6 *ospf6)
{
        struct ospf6_area *area;
        struct ospf6_route *range;
        struct listnode *node, *nnode;

        if (IS_OSPF6_DEBUG_ABR)
                zlog_debug("ospf6_abr_announce_aggregates(): Start");

        for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, area)) {
                for (range = ospf6_route_head(area->range_table); range; range = ospf6_route_next(range))
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

/*Flush the summary LSA's which are not approved.*/
void ospf6_abr_remove_unapproved_summaries(struct ospf6 *ospf6)
{
        struct listnode *node, *nnode;
        struct ospf6_area *area;
        struct ospf6_lsa *lsa;
        uint16_t type;

        if (IS_OSPF6_DEBUG_ABR)
                zlog_debug("ospf6_abr_remove_unapproved_summaries(): Start");

        for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, area)) {
                if (IS_OSPF6_DEBUG_ABR)
                        zlog_debug(
                                "ospf6_abr_remove_unapproved_summaries(): looking at area %pI4",
                                &area->area_id);

                /* Inter area router LSA */
                type = htons(OSPF6_LSTYPE_INTER_ROUTER);
                for (ALL_LSDB_TYPED_ADVRTR(area->lsdb, type, ospf6->router_id, lsa)) {
                                if (CHECK_FLAG(lsa->flag, OSPF6_LSA_UNAPPROVED)) {
                                        lsa->header->age = htons(OSPF_LSA_MAXAGE);
					THREAD_OFF(lsa->refresh);
                                        thread_execute(master, ospf6_lsa_expire, lsa, 0);
                		}
		}

                /* Inter area prefix LSA */
                type = htons(OSPF6_LSTYPE_INTER_PREFIX);
                for (ALL_LSDB_TYPED_ADVRTR(area->lsdb, type, ospf6->router_id, lsa)) {
                                if (CHECK_FLAG(lsa->flag, OSPF6_LSA_UNAPPROVED)) {
                                        lsa->header->age = htons(OSPF_LSA_MAXAGE);
					THREAD_OFF(lsa->refresh);
                                        thread_execute(master, ospf6_lsa_expire, lsa, 0);
                                }
                }
        }

        if (IS_OSPF6_DEBUG_ABR)
                zlog_debug("ospf6_abr_remove_unapproved_summaries(): Stop");
}

/*
 * This is the function taking care about ABR stuff, i.e.
 * summary-LSA origination and flooding.
 */
static void ospf6_abr_task(struct ospf6 *ospf6)
{
        if (IS_OSPF6_DEBUG_ABR)
                zlog_debug("ospf_abr_task(): Start");

        if (ospf6->route_table == NULL || ospf6->brouter_table == NULL) {
		if (IS_OSPF6_DEBUG_ABR)
                        zlog_debug(
                                "ospf_abr_task(): Routing tables are not yet ready");
                return;
        }

	if (IS_OSPF6_DEBUG_ABR)
                zlog_debug("ospf_abr_task(): unapprove summaries");
        ospf6_abr_unapprove_summaries(ospf6);

	if (IS_OSPF6_DEBUG_ABR)
                zlog_debug("ospf_abr_task(): prepare aggregates");
	ospf6_abr_range_reset_cost(ospf6);

        if (IS_OSPF6_ABR(ospf6)) {
	       if (IS_OSPF6_DEBUG_ABR)
                       zlog_debug("ospf_abr_task(): process network RT");
		ospf6_abr_prefix_resummarize(ospf6);

	       if (IS_OSPF6_DEBUG_ABR)
                       zlog_debug("ospf_abr_task(): process router RT");
	       ospf6_asbr_prefix_readvertise(ospf6);

	       if (IS_OSPF6_DEBUG_ABR)
                       zlog_debug("ospf_abr_task(): announce aggregates");
               ospf6_abr_announce_aggregates(ospf6);

	       if (IS_OSPF6_DEBUG_ABR)
                       zlog_debug("ospf_abr_task(): announce stub defaults");
	       ospf6_abr_defaults_to_stub(ospf6);
       }

       if (IS_OSPF6_DEBUG_ABR)
               zlog_debug("ospf_abr_task(): remove unapproved summaries");
       ospf6_abr_remove_unapproved_summaries(ospf6);

       if (IS_OSPF6_DEBUG_ABR)
               zlog_debug("ospf_abr_task(): Stop");
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

        /* NSSA Translator is not checked, because it may have gone away,
          and we would want to flush any residuals anyway */

        type = htons(OSPF6_LSTYPE_AS_EXTERNAL);
	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, oa)) {
        	for (ALL_LSDB_TYPED(oa->lsdb, type, lsa)) {
                	if (CHECK_FLAG(lsa->flag, OSPF6_LSA_LOCAL_XLT)) {
				SET_FLAG(lsa->flag, OSPF6_LSA_UNAPPROVED);
                        	if (IS_OSPF6_DEBUG_NSSA)
                                	zlog_debug(
                                        	"ospf6_abr_unapprove_translates(): approved unset on link id %pI4",
                                        	&lsa->header->id);
                	}
        	}
	}

        if (IS_OSPF6_DEBUG_NSSA)
                zlog_debug("ospf6_abr_unapprove_translates(): Stop");
}

/* Generate the translated external lsa  from NSSA lsa */
struct ospf6_lsa *ospf6_lsa_translated_nssa_new(struct ospf6 *ospf6,
						       struct ospf6_lsa *type7)
{
        char *buffer;
        struct ospf6_lsa *lsa;
        struct ospf6_as_external_lsa *ext, *extnew;
        struct ospf6_lsa_header *lsa_header;
        caddr_t old_ptr, new_ptr;
	struct ospf6_as_external_lsa *nssa;
	struct ospf6_external_info *info = NULL;
	struct prefix prefix;
 	struct ospf6_route *match;

	buffer = XCALLOC(MTYPE_OSPF6_LSA, OSPF6_MAX_LSASIZE);
        lsa_header = (struct ospf6_lsa_header *)buffer;
        extnew = (struct ospf6_as_external_lsa *)((caddr_t)lsa_header + sizeof(struct ospf6_lsa_header));
        ext = (struct ospf6_as_external_lsa *)((caddr_t)(type7->header) + sizeof(struct ospf6_lsa_header));
        old_ptr = (caddr_t)((caddr_t)ext + sizeof(struct ospf6_as_external_lsa));
        new_ptr = (caddr_t)((caddr_t)extnew + sizeof(struct ospf6_as_external_lsa));

        memcpy(extnew, ext, sizeof(struct ospf6_as_external_lsa));

	/* find the translated Type-5 for this Type-7 */
        nssa = (struct ospf6_as_external_lsa *)OSPF6_LSA_HEADER_END(type7->header);

        prefix.family = AF_INET6;
        prefix.prefixlen = nssa->prefix.prefix_length;
        ospf6_prefix_in6_addr(&prefix.u.prefix6, nssa, &nssa->prefix);

        /* Find the LSA from the external route */
        match = ospf6_route_lookup(&prefix, ospf6->external_table);
	if (match)
		info = match->route_option;

        /* set Prefix */
        memcpy(new_ptr, old_ptr, OSPF6_PREFIX_SPACE(ext->prefix.prefix_length));
        ospf6_prefix_apply_mask(&extnew->prefix);
        old_ptr += OSPF6_PREFIX_SPACE(ext->prefix.prefix_length);
        new_ptr += OSPF6_PREFIX_SPACE(extnew->prefix.prefix_length);

        /* Forwarding address */
        if (CHECK_FLAG(ext->bits_metric, OSPF6_ASBR_BIT_F)) {
                memcpy(new_ptr, &info->forwarding, sizeof(struct in6_addr));
                old_ptr += sizeof(struct in6_addr);
                new_ptr += sizeof(struct in6_addr);
        }
        /* External Route Tag */
        if (CHECK_FLAG(ext->bits_metric, OSPF6_ASBR_BIT_T)) {
                route_tag_t network_order = htonl(info->tag);

                memcpy(new_ptr, &network_order, sizeof(network_order));
                old_ptr += sizeof(network_order);
                new_ptr += sizeof(network_order);
        }

        /* Fill LSA Header */
        lsa_header->age = 0;
        lsa_header->type = htons(OSPF6_LSTYPE_AS_EXTERNAL);
        lsa_header->id = ospf6->external_id++;
        lsa_header->adv_router = ospf6->router_id;
        lsa_header->seqnum =
                ospf6_new_ls_seqnum(lsa_header->type, lsa_header->id,
                                    lsa_header->adv_router, ospf6->lsdb);
        lsa_header->length = htons((caddr_t)new_ptr - (caddr_t)lsa_header);

        /* LSA checksum */
        ospf6_lsa_checksum(lsa_header);

        /* create LSA */
        lsa = ospf6_lsa_create(lsa_header);

        SET_FLAG(lsa->flag, OSPF6_LSA_LOCAL_XLT);
        UNSET_FLAG(lsa->flag, OSPF6_LSA_UNAPPROVED);

        /* Originate */
        ospf6_lsa_originate_process(lsa, ospf6);

	zlog_debug("******* %s lsa %p", __func__, lsa);
        return lsa;
}

/* Delete LSA from retransmission list */
static void ospf6_ls_retransmit_delete_nbr_as(struct ospf6 *ospf6,
					      struct ospf6_lsa *lsa)
{
        struct listnode *node, *nnode;
        struct ospf6_area *area;

	/*The function ospf6_flood_clear_area removes LSA from
	 * retransmit list.
	 */
        for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, area))
                ospf6_flood_clear_area(lsa, area);
}

/* Refresh translated  AS-external-LSA. */
struct ospf6_lsa *ospf6_translated_nssa_refresh(struct ospf6 *ospf6,
						struct ospf6_lsa *type7,
						struct ospf6_lsa *type5)
{
        struct ospf6_lsa *new = NULL;
        struct ospf6_as_external_lsa *ext_lsa;
        struct prefix prefix;
        struct ospf6_route *match;
        struct ospf6_area *oa;
        struct listnode *node, *nnode;

        /* Sanity checks. */
        assert(type7 || type5);
        if (!(type7 || type5))
                return NULL;

        assert(ospf6->anyNSSA);

        /* get required data according to what has been given */
        if (type7 && type5 == NULL) {
                /* find the translated Type-5 for this Type-7 */
                ext_lsa = (struct ospf6_as_external_lsa *)OSPF6_LSA_HEADER_END(type7->header);

                prefix.family = AF_INET6;
                prefix.prefixlen = ext_lsa->prefix.prefix_length;
                ospf6_prefix_in6_addr(&prefix.u.prefix6, ext_lsa, &ext_lsa->prefix);

                /* Find the LSA from the external route */
                match = ospf6_route_lookup(&prefix, ospf6->external_table);
                if (match) {
                        type5 = ospf6_lsdb_lookup(OSPF6_LSTYPE_AS_EXTERNAL, match->path.origin.id, ospf6->router_id,
                                                                                ospf6->lsdb);
                }
        } else if (type5 && type7 == NULL) {
                /* find the type-7 from which supplied type-5 was translated,
                 * ie find first type-7 with same LSA Id.
                 */

                ext_lsa = (struct ospf6_as_external_lsa *)OSPF6_LSA_HEADER_END(type5->header);

                prefix.family = AF_INET6;
                prefix.prefixlen = ext_lsa->prefix.prefix_length;
                ospf6_prefix_in6_addr(&prefix.u.prefix6, ext_lsa, &ext_lsa->prefix);

                match = ospf6_route_lookup(&prefix, ospf6->external_table);
                if (match) {
                        /* Find the NSSA LSA from the area */
                        for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, oa)) {
                                if (!IS_AREA_NSSA(area))
                                        continue;

                                type7 = ospf6_lsdb_lookup(OSPF6_LSTYPE_TYPE_7, match->path.origin.id, ospf6->router_id, oa->lsdb);
                                if (type7)
                                        break;
                        }
                }
        }

        /* do we have type7? */
        if (!type7) {
                if (IS_OSPF6_DEBUG_NSSA)
                        zlog_debug(
                                "ospf6_translated_nssa_refresh(): no Type-7 found for Type-5 LSA Id %pI4",
                                &type5->header->id);
                return NULL;
        }

        /* do we have valid translated type5? */
        if (type5 == NULL || !CHECK_FLAG(type5->flag, OSPF6_LSA_LOCAL_XLT)) {
                if (IS_OSPF6_DEBUG_NSSA)
                        zlog_debug(
                                "ospf6_translated_nssa_refresh(): No translated Type-5 found for Type-7 with Id %pI4",
                                &type7->header->id);
                return NULL;
        }

        /* Delete LSA from neighbor retransmit-list. */
        ospf6_ls_retransmit_delete_nbr_as(ospf6, type5);

        /* create new translated LSA */
        if ((new = ospf6_lsa_translated_nssa_new(ospf6, type7)) == NULL) {
                if (IS_OSPF6_DEBUG_NSSA)
                        zlog_debug(
                                "ospf_translated_nssa_refresh(): Could not translate Type-7 for %pI4 to Type-5",
                                &type7->header->id);
                return NULL;
        }

        return new;
}

/* Originate Translated Type-5 for supplied Type-7 NSSA LSA */
struct ospf6_lsa *ospf6_translated_nssa_originate(struct ospf6 *ospf6, struct ospf6_lsa *type7)
{
        struct ospf6_lsa *new;

	if (ntohs(type7->header->type) != OSPF6_LSTYPE_TYPE_7)
		return NULL;

        if ((new = ospf6_lsa_translated_nssa_new(ospf6, type7)) == NULL) {
                if (IS_OSPF6_DEBUG_NSSA)
                        zlog_debug(
                                "ospf6_translated_nssa_originate(): Could not translate Type-7, Id %pI4, to Type-5",
                                &type7->header->id);
                return NULL;
        }

        return new;
}

static int ospf6_abr_translate_nssa(struct ospf6_area *area, struct ospf6_lsa *lsa)
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

	nssa_lsa = (struct ospf6_as_external_lsa *)OSPF6_LSA_HEADER_END(lsa->header);
	
	if (!CHECK_FLAG(nssa_lsa->prefix.prefix_options, OSPF6_PREFIX_OPTION_P)) {
        	if (IS_OSPF6_DEBUG_NSSA)
                	zlog_debug(
                        "ospf6_abr_translate_nssa(): LSA Id %pI4, P-bit off, NO Translation",
                        &lsa->header->id);
			return 1;
	}

	if (IS_OSPF6_DEBUG_NSSA) 
                zlog_debug(
                        "ospf_abr_translate_nssa(): LSA Id %pI4, TRANSLATING 7 to 5",
                        &lsa->header->id);

        prefix.family = AF_INET6;
        prefix.prefixlen = nssa_lsa->prefix.prefix_length;
        ospf6_prefix_in6_addr(&prefix.u.prefix6, nssa_lsa, &nssa_lsa->prefix);

        if (!CHECK_FLAG(nssa_lsa->bits_metric, OSPF6_ASBR_BIT_F)) {
                if (IS_OSPF6_DEBUG_NSSA)
                        zlog_debug(
                                "ospf6_abr_translate_nssa(): LSA Id %pI4, Forward address is 0, NO Translation",
                                &lsa->header->id);
                return 1;
	}

        /* try find existing AS-External LSA for this prefix */
        match = ospf6_route_lookup(&prefix, area->ospf6->external_table);
        if (match) {
                old = ospf6_lsdb_lookup(OSPF6_LSTYPE_TYPE_7, match->path.origin.id, ospf6->router_id,
                                                                ospf6->lsdb);
        }
        if (old) {
                /* Do not continue if type 5 LSA not approved */
                if (CHECK_FLAG(old->flag, OSPF6_LSA_UNAPPROVED)) {
                        if (IS_OSPF6_DEBUG_NSSA)
                                zlog_debug(
                                        "ospf6_abr_translate_nssa(): LSA Id %pI4 type 5 is not approved",
                                        &old->header->id);
                        return 1;
                }

                if (IS_OSPF6_DEBUG_NSSA)
                        zlog_debug(
                                "ospf6_abr_translate_nssa(): found old translated LSA Id %pI4, refreshing",
                                &old->header->id);

                /* refresh */
                new = ospf6_translated_nssa_refresh(area->ospf6, lsa, old);
                if (!new) {
                        if (IS_OSPF6_DEBUG_NSSA)
                                zlog_debug(
                                        "ospf6_abr_translate_nssa(): could not refresh translated LSA Id %pI4",
                                        &old->header->id);
                }
        } else {
                /* no existing external route for this LSA Id
                 * originate translated LSA
                 */

                if (ospf6_translated_nssa_originate(area->ospf6, lsa) == NULL) {
                        if (IS_OSPF6_DEBUG_NSSA)
                                zlog_debug(
                                        "ospf6_abr_translate_nssa(): Could not translate Type-7 for %pI4 to Type-5",
                                        &lsa->header->id);
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
                zlog_debug("ospf6_abr_process_nssa_translates(): Start");

        for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, oa)) {

		/* skip if not translator */
                if (!oa->NSSATranslatorState) {
			zlog_debug("%s area %pI4 NSSATranslatorState %d", __func__, 
					&oa->area_id, oa->NSSATranslatorState);
                        continue;
		}

		/* skip if not Nssa Area */
                if (!IS_AREA_NSSA(oa)) {
			zlog_debug("%s area %pI4 Flag %x", __func__, &oa->area_id, oa->flag);
                        continue;
		}

                if (IS_OSPF6_DEBUG_NSSA)
                        zlog_debug(
                                "ospf6_abr_process_nssa_translates(): looking at area %pI4",
                                &oa->area_id);

		type = htons(OSPF6_LSTYPE_TYPE_7);
		for (ALL_LSDB_TYPED(oa->lsdb, type, lsa)) {
			zlog_debug("lsa %s , id %pI4 , adv router %pI4", lsa->name, 
					&lsa->header->id, &lsa->header->adv_router);
                        ospf6_abr_translate_nssa(oa, lsa);
		}
        }

        if (IS_OSPF6_DEBUG_NSSA)
                zlog_debug("ospf6_abr_process_nssa_translates(): Stop");
}

/* Generate translated type-5 LSA from the configured area ranges*/
static void ospf6_abr_translate_nssa_range(struct ospf6 *ospf6)
{
        struct listnode *node, *nnode;
        struct ospf6_area *oa;
        struct ospf6_route *range;
	struct ospf6_lsa *lsa;

        for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, oa)) {
                for (range = ospf6_route_head(oa->range_table); range; range = ospf6_route_next(range)) {
			if (IS_OSPF6_DEBUG_NSSA) 
				zlog_debug("Translating range %pFX of area %pI4",
                                        &range->prefix, &oa->area_id);
                        if (CHECK_FLAG(range->flag, OSPF6_ROUTE_DO_NOT_ADVERTISE))
                                continue;

                        /* Find the NSSA LSA from the route */
                        /* Generate and flood external LSA */
			lsa = ospf6_lsdb_lookup(OSPF6_LSTYPE_TYPE_7, range->path.origin.id, ospf6->router_id, oa->lsdb);
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
                zlog_debug("ospf6_abr_send_nssa_aggregates(): Start");

        for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, area)) {
                if (!area->NSSATranslatorState)
                        continue;

                if (IS_OSPF6_DEBUG_NSSA)
                        zlog_debug(
                                "ospf_abr_send_nssa_aggregates(): looking at area %pI4",
                                &area->area_id);

                ospf6_abr_translate_nssa_range(ospf6);

        }

        if (IS_OSPF6_DEBUG_NSSA)
                zlog_debug("ospf6_abr_send_nssa_aggregates(): Stop");
}

/*Flood max age LSA's for the unapproved LSA's */
static int ospf6_abr_remove_unapproved_translates_apply(struct ospf6_lsa *lsa)
{
        if (CHECK_FLAG(lsa->flag, OSPF6_LSA_LOCAL_XLT)
            && CHECK_FLAG(lsa->flag, OSPF6_LSA_UNAPPROVED)) {
                zlog_info(
                        "ospf6_abr_remove_unapproved_translates(): removing unapproved translates, ID: %pI4",
                        &lsa->header->id);

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
        	for (range = ospf6_route_head(area->range_table); range; range = ospf6_route_next(range)) {
                	if (CHECK_FLAG(range->flag, OSPF6_ROUTE_DO_NOT_ADVERTISE))
				ospf6_zebra_delete_discard(range, ospf6);
			else
				ospf6_zebra_add_discard(range, ospf6);
		}
	}

        if (IS_OSPF6_DEBUG_NSSA)
                zlog_debug("ospf6_abr_nssa_task(): Stop");
}

int ospf6_redistribute_check(struct ospf6 *ospf6, struct ospf6_route *route, int type)
{
        route_map_result_t ret;
        struct prefix *prefix;

        if (!ospf6_zebra_is_redistribute(type, ospf6->vrf_id))
                return 0;

        prefix = &route->prefix;

        /* Change to new redist structure */
        if (ospf6->rmap[type].name) {
                if (ospf6->rmap[type].map == NULL)
                        ospf6_asbr_routemap_update(NULL);
                if (ospf6->rmap[type].map == NULL) {
                        zlog_warn(
                                "route-map \"%s\" not found, suppress redistributing",
                                ospf6->rmap[type].name);
                        return 0;
                }
        }

        /*  Change to new redist structure */
        if (ospf6->rmap[type].map) {
                ret = route_map_apply(ospf6->rmap[type].map, prefix, RMAP_OSPF6, route);
                if (ret == RMAP_DENYMATCH) {
                        if (IS_OSPF6_DEBUG_ASBR)
                                zlog_debug("Denied by route-map \"%s\"",
                                           ospf6->rmap[type].name);
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

        for (route = ospf6_route_head(ospf6->external_table); route; route = ospf6_route_next(route)) {
                info = route->route_option;

                /* Fine the external LSA in the database */
                if (!is_default_prefix(&route->prefix)) {
                        lsa = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_AS_EXTERNAL), htonl(info->id), ospf6->router_id, ospf6->lsdb);

                        if (lsa) {
                                THREAD_OFF(lsa->refresh);

                                /* LSA is maxage,  immediate refresh */
                                if (OSPF6_LSA_IS_MAXAGE(lsa))
                                        ospf6_flood(NULL, lsa);
                                else
                                        thread_add_timer(master, ospf6_lsa_refresh, lsa, OSPF_LS_REFRESH_TIME, &lsa->refresh);
                        } else {
                                /* LSA not found in the database
                                 * Verify and originate  external LSA
                                 */
                                if (ospf6_redistribute_check(ospf6, route, type))
                                        ospf6_as_external_lsa_originate(route, ospf6);
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

	for (route = ospf6_route_head(ospf6->external_table); route; route = ospf6_route_next(route)) {
		if (is_default_prefix(&route->prefix)) {
        		info = route->route_option;
        		lsa = ospf6_lsdb_lookup(htons(OSPF6_LSTYPE_AS_EXTERNAL),
						htonl(info->id), ospf6->router_id, ospf6->lsdb);

        		if (lsa) {
                		if (IS_OSPF6_DEBUG_NSSA)
                        		zlog_debug("LSA[Type5:0.0.0.0]: Refresh AS-external-LSA %p",
                                		(void *)lsa);
                		if (OSPF6_LSA_IS_MAXAGE(lsa))
                        		ospf6_flood(NULL, lsa);
                		else
                        		thread_add_timer(master, ospf6_lsa_refresh,
							lsa, OSPF_LS_REFRESH_TIME, &lsa->refresh);
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
	//ToDo: Once the redist reformation PR is merged.
        for (type = 0; type < ZEBRA_ROUTE_MAX; type++) {
#if 0	
                struct list *red_list;
                struct listnode *node;
                struct ospf6_redist *red;

                red_list = ospf6->redist[type];
                if (!red_list)
                        continue;

                for (ALL_LIST_ELEMENTS_RO(red_list, node, red))
#endif
                        ospf6_external_lsa_refresh_type(
                                ospf6, type, 0, LSA_REFRESH_IF_CHANGED);
        }
         ospf6_external_lsa_refresh_default(ospf6);
}

/* This function performs ABR related processing */
static int ospf6_abr_task_timer(struct thread *thread)
{
        struct ospf6 *ospf6 = THREAD_ARG(thread);

        ospf6->t_abr_task = 0;

        if (IS_OSPF6_DEBUG_ABR)
                zlog_debug("Running ABR task on timer");

        ospf6_is_router_abr(ospf6);
        ospf6_abr_nssa_check_status(ospf6);
        ospf6_abr_task(ospf6);
	/* if nssa-abr, then scan Type-7 LSDB */
        ospf6_abr_nssa_task(ospf6); 
	ospf6_asbr_nssa_redist_task(ospf6);

        return 0;
}

void ospf6_schedule_abr_task(struct ospf6 *ospf6)
{
        if (IS_OSPF6_DEBUG_ABR)
                zlog_debug("Scheduling ABR task");

        thread_add_timer(master, ospf6_abr_task_timer, ospf6, OSPF6_ABR_TASK_DELAY,
                         &ospf6->t_abr_task);
}

static void ospf6_area_nssa_update(struct ospf6_area *area)
{
	struct ospf6_route *route;
	
        if (IS_AREA_NSSA(area)) {
            if (!ospf6_is_router_abr(area->ospf6))
                    OSPF6_OPT_CLEAR(area->options, OSPF6_OPT_E);
                area->ospf6->anyNSSA++;
                OSPF6_OPT_SET(area->options, OSPF6_OPT_N);
        } else if (IS_AREA_ENABLED(area)) {
                if (IS_OSPF6_DEBUG_ORIGINATE(ROUTER))
                        zlog_debug("Normal area for if %s", area->name);
                OSPF6_OPT_CLEAR(area->options, OSPF6_OPT_N);
                if (ospf6_is_router_abr(area->ospf6))
                    OSPF6_OPT_SET(area->options, OSPF6_OPT_E);
                area->ospf6->anyNSSA--;
        }
	
	/* Refresh router LSA */
        OSPF6_ROUTER_LSA_SCHEDULE(area);

        /* Check if router is ABR */
        if (ospf6_is_router_abr(area->ospf6)) {
		zlog_debug("Normal area for if %s", area->name);
                ospf6_schedule_abr_task(area->ospf6);
	}
        else {
                /* Router is not ABR
                 */
                if (IS_AREA_NSSA(area)) {
			zlog_debug("Normal area for if %s", area->name);
			for (route = ospf6_route_head(area->ospf6->external_table); route;
					route = ospf6_route_next(route))
				ospf6_nssa_lsa_originate(route, area);

        	}
	}
}

int ospf6_area_nssa_set(struct ospf6 *ospf6, struct ospf6_area *area)
{
	
        if (!IS_AREA_NSSA(area)) {
		SET_FLAG(area->flag, OSPF6_AREA_NSSA);
		ospf6_area_nssa_update(area);
        }

        return 1;
}

int ospf6_area_nssa_unset(struct ospf6 *ospf6, struct ospf6_area *area)
{
	if (IS_AREA_NSSA(area)) {
		UNSET_FLAG(area->flag, OSPF6_AREA_NSSA);
		ospf6_area_nssa_update(area);
	}

	return 1;
}

/* Find the NSSA forwarding address */
static struct in6_addr* ospf6_get_nssa_fwd_addr(struct ospf6_area *oa)
{
        struct listnode *node, *nnode;
        struct ospf6_interface *oi;

        for (ALL_LIST_ELEMENTS(oa->if_list, node, nnode, oi)) {
                if (if_is_operative(oi->interface))
                        if (oi->area->flag == OSPF6_AREA_NSSA)
                                return ospf6_interface_get_global_address(oi->interface);
        }
        return NULL;
}

void ospf6_nssa_lsa_originate(struct ospf6_route *route, struct ospf6_area *area)
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
        if (route->path.metric_type == 2)
                SET_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_E);
        else
                UNSET_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_E);

        /* forwarding address */
        if (!IN6_IS_ADDR_UNSPECIFIED(&info->forwarding))
                SET_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_F);
        else
                UNSET_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_F);

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
        if (CHECK_FLAG(as_external_lsa->bits_metric, OSPF6_ASBR_BIT_F)) {
                fwd_addr = ospf6_get_nssa_fwd_addr(area);
                if (fwd_addr) {
                        memcpy(p, fwd_addr, sizeof(struct in6_addr));
                        p += sizeof(struct in6_addr);
                }
        }

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

DEFUN (debug_ospf6_nssa,
       debug_ospf6_nssa_cmd,
       "debug ospf6 nssa",
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 NSSA function\n"
      )
{
        OSPF6_DEBUG_NSSA_ON();
        return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_nssa,
       no_debug_ospf6_nssa_cmd,
       "no debug ospf6 nssa",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug OSPFv3 NSSA function\n"
      )
{
        OSPF6_DEBUG_NSSA_OFF();
        return CMD_SUCCESS;
}

void install_element_ospf6_debug_nssa(void)
{
	install_element(ENABLE_NODE, &debug_ospf6_nssa_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_nssa_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_nssa_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_nssa_cmd);
}
