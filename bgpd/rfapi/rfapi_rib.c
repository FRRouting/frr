/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * File:	rfapi_rib.c
 * Purpose:	maintain per-nve ribs and generate change lists
 */

#include "lib/zebra.h"
#include "lib/prefix.h"
#include "lib/agg_table.h"
#include "lib/vty.h"
#include "lib/memory.h"
#include "lib/log.h"
#include "lib/skiplist.h"
#include "lib/workqueue.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_vnc_types.h"

#include "bgpd/rfapi/rfapi.h"
#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#include "bgpd/rfapi/rfapi_import.h"
#include "bgpd/rfapi/rfapi_private.h"
#include "bgpd/rfapi/rfapi_vty.h"
#include "bgpd/rfapi/vnc_import_bgp.h"
#include "bgpd/rfapi/rfapi_rib.h"
#include "bgpd/rfapi/rfapi_monitor.h"
#include "bgpd/rfapi/rfapi_encap_tlv.h"
#include "bgpd/rfapi/vnc_debug.h"

#define DEBUG_PROCESS_PENDING_NODE	0
#define DEBUG_PENDING_DELETE_ROUTE	0
#define DEBUG_NHL			0
#define DEBUG_RIB_SL_RD                 0

/* forward decl */
#if DEBUG_NHL
static void rfapiRibShowRibSl(void *stream, struct prefix *pfx,
			      struct skiplist *sl);
#endif

/*
 * RIB
 * ---
 * Model of the set of routes currently in the NVE's RIB.
 *
 * node->info		ptr to "struct skiplist".
 *			MUST be NULL if there are no routes.
 *			key = ptr to struct prefix {vn}
 *			val = ptr to struct rfapi_info
 *			skiplist.del = NULL
 *			skiplist.cmp = vnc_prefix_cmp
 *
 * node->aggregate	ptr to "struct skiplist".
 *			key = ptr to struct prefix {vn}
 *			val = ptr to struct rfapi_info
 *			skiplist.del = rfapi_info_free
 *			skiplist.cmp = vnc_prefix_cmp
 *
 *			This skiplist at "aggregate"
 *			contains the routes recently
 *			deleted
 *
 *
 * Pending RIB
 * -----------
 * Sparse list of prefixes that need to be updated. Each node
 * will have the complete set of routes for the prefix.
 *
 * node->info		ptr to "struct list" (lib/linklist.h)
 *			"Cost List"
 *			List of routes sorted lowest cost first.
 *			This list is how the new complete set
 *			of routes should look.
 *			Set if there are updates to the prefix;
 *			MUST be NULL if there are no updates.
 *
 *			.data = ptr to struct rfapi_info
 *			list.cmp = NULL (sorted manually)
 *			list.del = rfapi_info_free
 *
 *			Special case: if node->info is 1, it means
 *			"delete all routes at this prefix".
 *
 * node->aggregate	ptr to struct skiplist
 *			key = ptr to struct prefix {vn} (part of ri)
 *			val =  struct rfapi_info
 *			skiplist.cmp = vnc_prefix_cmp
 *			skiplist.del = NULL
 *
 *			ptlist is rewritten anew each time
 *			rfapiRibUpdatePendingNode() is called
 *
 *			THE ptlist VALUES ARE REFERENCES TO THE
 *			rfapi_info STRUCTS IN THE node->info LIST.
 */

/*
 * iterate over RIB to count responses, compare with running counters
 */
void rfapiRibCheckCounts(
	int checkstats,      /* validate rfd & global counts */
	unsigned int offset) /* number of ri's held separately */
{
	struct rfapi_descriptor *rfd;
	struct listnode *node;

	struct bgp *bgp = bgp_get_default();

	uint32_t t_pfx_active = 0;
	uint32_t t_pfx_deleted = 0;

	uint32_t t_ri_active = 0;
	uint32_t t_ri_deleted = 0;
	uint32_t t_ri_pend = 0;

	unsigned int alloc_count;

	/*
	 * loop over NVEs
	 */
	for (ALL_LIST_ELEMENTS_RO(&bgp->rfapi->descriptors, node, rfd)) {

		afi_t afi;
		uint32_t pfx_active = 0;
		uint32_t pfx_deleted = 0;

		for (afi = AFI_IP; afi < AFI_MAX; ++afi) {

			struct agg_node *rn;

			for (rn = agg_route_top(rfd->rib[afi]); rn;
			     rn = agg_route_next(rn)) {

				struct skiplist *sl = rn->info;
				struct skiplist *dsl = rn->aggregate;
				uint32_t ri_active = 0;
				uint32_t ri_deleted = 0;

				if (sl) {
					ri_active = skiplist_count(sl);
					assert(ri_active);
					t_ri_active += ri_active;
					++pfx_active;
					++t_pfx_active;
				}

				if (dsl) {
					ri_deleted = skiplist_count(dsl);
					t_ri_deleted += ri_deleted;
					++pfx_deleted;
					++t_pfx_deleted;
				}
			}
			for (rn = agg_route_top(rfd->rib_pending[afi]); rn;
			     rn = agg_route_next(rn)) {

				struct list *l = rn->info; /* sorted by cost */
				struct skiplist *sl = rn->aggregate;
				uint32_t ri_pend_cost = 0;
				uint32_t ri_pend_uniq = 0;

				if (sl) {
					ri_pend_uniq = skiplist_count(sl);
				}

				if (l && (l != (void *)1)) {
					ri_pend_cost = l->count;
					t_ri_pend += l->count;
				}

				assert(ri_pend_uniq == ri_pend_cost);
			}
		}

		if (checkstats) {
			if (pfx_active != rfd->rib_prefix_count) {
				vnc_zlog_debug_verbose(
					"%s: rfd %p actual pfx count %u != running %u",
					__func__, rfd, pfx_active,
					rfd->rib_prefix_count);
				assert(0);
			}
		}
	}

	if (checkstats && bgp->rfapi) {
		if (t_pfx_active != bgp->rfapi->rib_prefix_count_total) {
			vnc_zlog_debug_verbose(
				"%s: actual total pfx count %u != running %u",
				__func__, t_pfx_active,
				bgp->rfapi->rib_prefix_count_total);
			assert(0);
		}
	}

	/*
	 * Check against memory allocation count
	 */
	alloc_count = mtype_stats_alloc(MTYPE_RFAPI_INFO);
	assert(t_ri_active + t_ri_deleted + t_ri_pend + offset == alloc_count);
}

static struct rfapi_info *rfapi_info_new(void)
{
	return XCALLOC(MTYPE_RFAPI_INFO, sizeof(struct rfapi_info));
}

void rfapiFreeRfapiUnOptionChain(struct rfapi_un_option *p)
{
	while (p) {
		struct rfapi_un_option *next;

		next = p->next;
		XFREE(MTYPE_RFAPI_UN_OPTION, p);
		p = next;
	}
}

void rfapiFreeRfapiVnOptionChain(struct rfapi_vn_option *p)
{
	while (p) {
		struct rfapi_vn_option *next;

		next = p->next;
		XFREE(MTYPE_RFAPI_VN_OPTION, p);
		p = next;
	}
}


static void rfapi_info_free(struct rfapi_info *goner)
{
	if (goner) {
		if (goner->tea_options) {
			rfapiFreeBgpTeaOptionChain(goner->tea_options);
			goner->tea_options = NULL;
		}
		if (goner->un_options) {
			rfapiFreeRfapiUnOptionChain(goner->un_options);
			goner->un_options = NULL;
		}
		if (goner->vn_options) {
			rfapiFreeRfapiVnOptionChain(goner->vn_options);
			goner->vn_options = NULL;
		}
		if (goner->timer) {
			struct rfapi_rib_tcb *tcb;

			tcb = ((struct thread *)goner->timer)->arg;
			thread_cancel((struct thread *)goner->timer);
			XFREE(MTYPE_RFAPI_RECENT_DELETE, tcb);
			goner->timer = NULL;
		}
		XFREE(MTYPE_RFAPI_INFO, goner);
	}
}

/*
 * Timer control block for recently-deleted and expired routes
 */
struct rfapi_rib_tcb {
	struct rfapi_descriptor *rfd;
	struct skiplist *sl;
	struct rfapi_info *ri;
	struct agg_node *rn;
	int flags;
#define RFAPI_RIB_TCB_FLAG_DELETED	0x00000001
};

/*
 * remove route from rib
 */
static int rfapiRibExpireTimer(struct thread *t)
{
	struct rfapi_rib_tcb *tcb = t->arg;

	RFAPI_RIB_CHECK_COUNTS(1, 0);

	/*
	 * Forget reference to thread. Otherwise rfapi_info_free() will
	 * attempt to free thread pointer as an option chain
	 */
	tcb->ri->timer = NULL;

	/* "deleted" skiplist frees ri, "active" doesn't */
	assert(!skiplist_delete(tcb->sl, &tcb->ri->rk, NULL));
	if (!tcb->sl->del) {
		/*
		 * XXX in this case, skiplist has no delete function: we must
		 * therefore delete rfapi_info explicitly.
		 */
		rfapi_info_free(tcb->ri);
	}

	if (skiplist_empty(tcb->sl)) {
		if (CHECK_FLAG(tcb->flags, RFAPI_RIB_TCB_FLAG_DELETED))
			tcb->rn->aggregate = NULL;
		else {
			struct bgp *bgp = bgp_get_default();
			tcb->rn->info = NULL;
			RFAPI_RIB_PREFIX_COUNT_DECR(tcb->rfd, bgp->rfapi);
		}
		skiplist_free(tcb->sl);
		agg_unlock_node(tcb->rn);
	}

	XFREE(MTYPE_RFAPI_RECENT_DELETE, tcb);

	RFAPI_RIB_CHECK_COUNTS(1, 0);

	return 0;
}

static void rfapiRibStartTimer(struct rfapi_descriptor *rfd,
			       struct rfapi_info *ri,
			       struct agg_node *rn, /* route node attached to */
			       int deleted)
{
	struct thread *t = ri->timer;
	struct rfapi_rib_tcb *tcb = NULL;
	char buf_prefix[PREFIX_STRLEN];

	if (t) {
		tcb = t->arg;
		thread_cancel(t);
		ri->timer = NULL;
	} else {
		tcb = XCALLOC(MTYPE_RFAPI_RECENT_DELETE,
			      sizeof(struct rfapi_rib_tcb));
	}
	tcb->rfd = rfd;
	tcb->ri = ri;
	tcb->rn = rn;
	if (deleted) {
		tcb->sl = (struct skiplist *)rn->aggregate;
		SET_FLAG(tcb->flags, RFAPI_RIB_TCB_FLAG_DELETED);
	} else {
		tcb->sl = (struct skiplist *)rn->info;
		UNSET_FLAG(tcb->flags, RFAPI_RIB_TCB_FLAG_DELETED);
	}

	prefix2str(&rn->p, buf_prefix, sizeof(buf_prefix));
	vnc_zlog_debug_verbose("%s: rfd %p pfx %s life %u", __func__, rfd,
			       buf_prefix, ri->lifetime);
	ri->timer = NULL;
	thread_add_timer(bm->master, rfapiRibExpireTimer, tcb, ri->lifetime,
			 &ri->timer);
	assert(ri->timer);
}

extern void rfapi_rib_key_init(struct prefix *prefix, /* may be NULL */
			       struct prefix_rd *rd,  /* may be NULL */
			       struct prefix *aux,    /* may be NULL */
			       struct rfapi_rib_key *rk)

{
	memset((void *)rk, 0, sizeof(struct rfapi_rib_key));
	if (prefix)
		rk->vn = *prefix;
	if (rd)
		rk->rd = *rd;
	if (aux)
		rk->aux_prefix = *aux;
}

/*
 * Compares two <struct rfapi_rib_key>s
 */
int rfapi_rib_key_cmp(void *k1, void *k2)
{
	struct rfapi_rib_key *a = (struct rfapi_rib_key *)k1;
	struct rfapi_rib_key *b = (struct rfapi_rib_key *)k2;
	int ret;

	if (!a || !b)
		return (a - b);

	ret = vnc_prefix_cmp(&a->vn, &b->vn);
	if (ret)
		return ret;

	ret = vnc_prefix_cmp(&a->rd, &b->rd);
	if (ret)
		return ret;

	ret = vnc_prefix_cmp(&a->aux_prefix, &b->aux_prefix);

	return ret;
}


/*
 * Note: this function will claim that two option chains are
 * different unless their option items are in identical order.
 * The consequence is that RFP updated responses can be sent
 * unnecessarily, or that they might contain nexthop items
 * that are not strictly needed.
 *
 * This function could be modified to compare option chains more
 * thoroughly, but it's not clear that the extra compuation would
 * be worth it.
 */
static int bgp_tea_options_cmp(struct bgp_tea_options *a,
			       struct bgp_tea_options *b)
{
	int rc;

	if (!a || !b) {
		return (a - b);
	}

	if (a->type != b->type)
		return (a->type - b->type);
	if (a->length != b->length)
		return (a->length = b->length);
	if ((rc = memcmp(a->value, b->value, a->length)))
		return rc;
	if (!a->next != !b->next) { /* logical xor */
		return (a->next - b->next);
	}
	if (a->next)
		return bgp_tea_options_cmp(a->next, b->next);
	return 0;
}

static int rfapi_info_cmp(struct rfapi_info *a, struct rfapi_info *b)
{
	int rc;

	if (!a || !b)
		return (a - b);

	if ((rc = rfapi_rib_key_cmp(&a->rk, &b->rk)))
		return rc;

	if ((rc = vnc_prefix_cmp(&a->un, &b->un)))
		return rc;

	if (a->cost != b->cost)
		return (a->cost - b->cost);

	if (a->lifetime != b->lifetime)
		return (a->lifetime - b->lifetime);

	if ((rc = bgp_tea_options_cmp(a->tea_options, b->tea_options)))
		return rc;

	return 0;
}

void rfapiRibClear(struct rfapi_descriptor *rfd)
{
	struct bgp *bgp;
	afi_t afi;

	if (rfd->bgp)
		bgp = rfd->bgp;
	else
		bgp = bgp_get_default();
#if DEBUG_L2_EXTRA
	vnc_zlog_debug_verbose("%s: rfd=%p", __func__, rfd);
#endif

	for (afi = AFI_IP; afi < AFI_MAX; ++afi) {
		struct agg_node *pn;
		struct agg_node *rn;

		if (rfd->rib_pending[afi]) {
			for (pn = agg_route_top(rfd->rib_pending[afi]); pn;
			     pn = agg_route_next(pn)) {
				if (pn->aggregate) {
					/*
					 * free references into the rfapi_info
					 * structures before
					 * freeing the structures themselves
					 */
					skiplist_free(
						(struct skiplist
							 *)(pn->aggregate));
					pn->aggregate = NULL;
					agg_unlock_node(
						pn); /* skiplist deleted */
				}
				/*
				 * free the rfapi_info structures
				 */
				if (pn->info) {
					if (pn->info != (void *)1) {
						list_delete(
							(struct list *
								 *)(&pn->info));
					}
					pn->info = NULL;
					/* linklist or 1 deleted */
					agg_unlock_node(pn);
				}
			}
		}
		if (rfd->rib[afi]) {
			for (rn = agg_route_top(rfd->rib[afi]); rn;
			     rn = agg_route_next(rn)) {
				if (rn->info) {

					struct rfapi_info *ri;

					while (0 == skiplist_first(
							    (struct skiplist *)
								    rn->info,
							    NULL,
							    (void **)&ri)) {

						rfapi_info_free(ri);
						skiplist_delete_first(
							(struct skiplist *)
								rn->info);
					}
					skiplist_free(
						(struct skiplist *)rn->info);
					rn->info = NULL;
					agg_unlock_node(rn);
					RFAPI_RIB_PREFIX_COUNT_DECR(rfd,
								    bgp->rfapi);
				}
				if (rn->aggregate) {

					struct rfapi_info *ri_del;

					/* delete skiplist & contents */
					while (!skiplist_first(
						(struct skiplist
							 *)(rn->aggregate),
						NULL, (void **)&ri_del)) {

						/* sl->del takes care of ri_del
						 */
						skiplist_delete_first((
							struct skiplist
								*)(rn->aggregate));
					}
					skiplist_free(
						(struct skiplist
							 *)(rn->aggregate));

					rn->aggregate = NULL;
					agg_unlock_node(rn);
				}
			}
		}
	}
	if (rfd->updated_responses_queue)
		work_queue_free_and_null(&rfd->updated_responses_queue);
}

/*
 * Release all dynamically-allocated memory that is part of an HD's RIB
 */
void rfapiRibFree(struct rfapi_descriptor *rfd)
{
	afi_t afi;


	/*
	 * NB rfd is typically detached from master list, so is not included
	 * in the count performed by RFAPI_RIB_CHECK_COUNTS
	 */

	/*
	 * Free routes attached to radix trees
	 */
	rfapiRibClear(rfd);

	/* Now the uncounted rfapi_info's are freed, so the check should succeed
	 */
	RFAPI_RIB_CHECK_COUNTS(1, 0);

	/*
	 * Free radix trees
	 */
	for (afi = AFI_IP; afi < AFI_MAX; ++afi) {
		if (rfd->rib_pending[afi])
			agg_table_finish(rfd->rib_pending[afi]);
		rfd->rib_pending[afi] = NULL;

		if (rfd->rib[afi])
			agg_table_finish(rfd->rib[afi]);
		rfd->rib[afi] = NULL;

		/* NB agg_table_finish frees only prefix nodes, not chained
		 * info */
		if (rfd->rsp_times[afi])
			agg_table_finish(rfd->rsp_times[afi]);
		rfd->rib[afi] = NULL;
	}
}

/*
 * Copies struct bgp_path_info to struct rfapi_info, except for rk fields and un
 */
static void rfapiRibBi2Ri(struct bgp_path_info *bpi, struct rfapi_info *ri,
			  uint32_t lifetime)
{
	struct bgp_attr_encap_subtlv *pEncap;

	ri->cost = rfapiRfpCost(bpi->attr);
	ri->lifetime = lifetime;

	/* This loop based on rfapiRouteInfo2NextHopEntry() */
	for (pEncap = bpi->attr->vnc_subtlvs; pEncap; pEncap = pEncap->next) {
		struct bgp_tea_options *hop;

		switch (pEncap->type) {
		case BGP_VNC_SUBTLV_TYPE_LIFETIME:
			/* use configured lifetime, not attr lifetime */
			break;

		case BGP_VNC_SUBTLV_TYPE_RFPOPTION:
			hop = XCALLOC(MTYPE_BGP_TEA_OPTIONS,
				      sizeof(struct bgp_tea_options));
			assert(hop);
			hop->type = pEncap->value[0];
			hop->length = pEncap->value[1];
			hop->value = XCALLOC(MTYPE_BGP_TEA_OPTIONS_VALUE,
					     pEncap->length - 2);
			assert(hop->value);
			memcpy(hop->value, pEncap->value + 2,
			       pEncap->length - 2);
			if (hop->length > pEncap->length - 2) {
				zlog_warn(
					"%s: VNC subtlv length mismatch: "
					"RFP option says %d, attr says %d "
					"(shrinking)",
					__func__, hop->length,
					pEncap->length - 2);
				hop->length = pEncap->length - 2;
			}
			hop->next = ri->tea_options;
			ri->tea_options = hop;
			break;

		default:
			break;
		}
	}

	rfapi_un_options_free(ri->un_options); /* maybe free old version */
	ri->un_options = rfapi_encap_tlv_to_un_option(bpi->attr);

	/*
	 * VN options
	 */
	if (bpi->extra
	    && decode_rd_type(bpi->extra->vnc.import.rd.val)
		       == RD_TYPE_VNC_ETH) {
		/* ethernet route */

		struct rfapi_vn_option *vo;

		vo = XCALLOC(MTYPE_RFAPI_VN_OPTION,
			     sizeof(struct rfapi_vn_option));
		assert(vo);

		vo->type = RFAPI_VN_OPTION_TYPE_L2ADDR;

		/* copy from RD already stored in bpi, so we don't need it_node
		 */
		memcpy(&vo->v.l2addr.macaddr, bpi->extra->vnc.import.rd.val + 2,
		       ETH_ALEN);

		(void)rfapiEcommunityGetLNI(bpi->attr->ecommunity,
					    &vo->v.l2addr.logical_net_id);
		(void)rfapiEcommunityGetEthernetTag(bpi->attr->ecommunity,
						    &vo->v.l2addr.tag_id);

		/* local_nve_id comes from RD */
		vo->v.l2addr.local_nve_id = bpi->extra->vnc.import.rd.val[1];

		/* label comes from MP_REACH_NLRI label */
		vo->v.l2addr.label = decode_label(&bpi->extra->label[0]);

		rfapi_vn_options_free(
			ri->vn_options); /* maybe free old version */
		ri->vn_options = vo;
	}

	/*
	 * If there is an auxiliary IP address (L2 can have it), copy it
	 */
	if (bpi->extra && bpi->extra->vnc.import.aux_prefix.family) {
		ri->rk.aux_prefix = bpi->extra->vnc.import.aux_prefix;
	}
}

/*
 * rfapiRibPreloadBi
 *
 *	Install route into NVE RIB model so as to be consistent with
 *	caller's response to rfapi_query().
 *
 *	Also: return indication to caller whether this specific route
 *	should be included in the response to the NVE according to
 *	the following tests:
 *
 *	1. If there were prior duplicates of this route in this same
 *	   query response, don't include the route.
 *
 * RETURN VALUE:
 *
 *	0	OK to include route in response
 *	!0	do not include route in response
 */
int rfapiRibPreloadBi(
	struct agg_node *rfd_rib_node, /* NULL = don't preload or filter */
	struct prefix *pfx_vn, struct prefix *pfx_un, uint32_t lifetime,
	struct bgp_path_info *bpi)
{
	struct rfapi_descriptor *rfd;
	struct skiplist *slRibPt = NULL;
	struct rfapi_info *ori = NULL;
	struct rfapi_rib_key rk;
	struct agg_node *trn;
	afi_t afi;

	if (!rfd_rib_node)
		return 0;

	afi = family2afi(rfd_rib_node->p.family);

	rfd = agg_get_table_info(agg_get_table(rfd_rib_node));

	memset((void *)&rk, 0, sizeof(rk));
	rk.vn = *pfx_vn;
	rk.rd = bpi->extra->vnc.import.rd;

	/*
	 * If there is an auxiliary IP address (L2 can have it), copy it
	 */
	if (bpi->extra->vnc.import.aux_prefix.family) {
		rk.aux_prefix = bpi->extra->vnc.import.aux_prefix;
	}

	/*
	 * is this route already in NVE's RIB?
	 */
	slRibPt = (struct skiplist *)rfd_rib_node->info;

	if (slRibPt && !skiplist_search(slRibPt, &rk, (void **)&ori)) {

		if ((ori->rsp_counter == rfd->rsp_counter)
		    && (ori->last_sent_time == rfd->rsp_time)) {
			return -1; /* duplicate in this response */
		}

		/* found: update contents of existing route in RIB */
		ori->un = *pfx_un;
		rfapiRibBi2Ri(bpi, ori, lifetime);
	} else {
		/* not found: add new route to RIB */
		ori = rfapi_info_new();
		ori->rk = rk;
		ori->un = *pfx_un;
		rfapiRibBi2Ri(bpi, ori, lifetime);

		if (!slRibPt) {
			slRibPt = skiplist_new(0, rfapi_rib_key_cmp, NULL);
			rfd_rib_node->info = slRibPt;
			agg_lock_node(rfd_rib_node);
			RFAPI_RIB_PREFIX_COUNT_INCR(rfd, rfd->bgp->rfapi);
		}
		skiplist_insert(slRibPt, &ori->rk, ori);
	}

	ori->last_sent_time = rfapi_time(NULL);

	/*
	 * poke timer
	 */
	RFAPI_RIB_CHECK_COUNTS(0, 0);
	rfapiRibStartTimer(rfd, ori, rfd_rib_node, 0);
	RFAPI_RIB_CHECK_COUNTS(0, 0);

	/*
	 * Update last sent time for prefix
	 */
	trn = agg_node_get(rfd->rsp_times[afi],
			   &rfd_rib_node->p); /* locks trn */
	trn->info = (void *)(uintptr_t)bgp_clock();
	if (trn->lock > 1)
		agg_unlock_node(trn);

	return 0;
}

/*
 * Frees rfapi_info items at node
 *
 * Adjust 'rib' and 'rib_pending' as follows:
 *
 * If rib_pending node->info is 1 (magic value):
 *	callback: NHL = RIB NHL with lifetime = withdraw_lifetime_value
 *	RIB = remove all routes at the node
 *	DONE
 *
 * For each item at rib node:
 *  if not present in pending node, move RIB item to "delete list"
 *
 * For each item at pending rib node:
 *  if present (same vn/un) in rib node with same lifetime & options, drop
 *	matching item from pending node
 *
 * For each remaining item at pending rib node, add or replace item
 * at rib node.
 *
 * Construct NHL as concatenation of pending list + delete list
 *
 * Clear pending node
 */
static void process_pending_node(struct bgp *bgp, struct rfapi_descriptor *rfd,
				 afi_t afi,
				 struct agg_node *pn, /* pending node */
				 struct rfapi_next_hop_entry **head,
				 struct rfapi_next_hop_entry **tail)
{
	struct listnode *node = NULL;
	struct listnode *nnode = NULL;
	struct rfapi_info *ri = NULL;    /* happy valgrind */
	struct rfapi_ip_prefix hp = {0}; /* pfx to put in NHE */
	struct agg_node *rn = NULL;
	struct skiplist *slRibPt = NULL; /* rib list */
	struct skiplist *slPendPt = NULL;
	struct list *lPendCost = NULL;
	struct list *delete_list = NULL;
	int printedprefix = 0;
	char buf_prefix[PREFIX_STRLEN];
	int rib_node_started_nonempty = 0;
	int sendingsomeroutes = 0;

#if DEBUG_PROCESS_PENDING_NODE
	unsigned int count_rib_initial = 0;
	unsigned int count_pend_vn_initial = 0;
	unsigned int count_pend_cost_initial = 0;
#endif

	assert(pn);
	prefix2str(&pn->p, buf_prefix, sizeof(buf_prefix));
	vnc_zlog_debug_verbose("%s: afi=%d, %s pn->info=%p", __func__, afi,
			       buf_prefix, pn->info);

	if (AFI_L2VPN != afi) {
		rfapiQprefix2Rprefix(&pn->p, &hp);
	}

	RFAPI_RIB_CHECK_COUNTS(1, 0);

	/*
	 * Find corresponding RIB node
	 */
	rn = agg_node_get(rfd->rib[afi], &pn->p); /* locks rn */

	/*
	 * RIB skiplist has key=rfapi_addr={vn,un}, val = rfapi_info,
	 * skiplist.del = NULL
	 */
	slRibPt = (struct skiplist *)rn->info;
	if (slRibPt)
		rib_node_started_nonempty = 1;

	slPendPt = (struct skiplist *)(pn->aggregate);
	lPendCost = (struct list *)(pn->info);

#if DEBUG_PROCESS_PENDING_NODE
	/* debugging */
	if (slRibPt)
		count_rib_initial = skiplist_count(slRibPt);

	if (slPendPt)
		count_pend_vn_initial = skiplist_count(slPendPt);

	if (lPendCost && lPendCost != (struct list *)1)
		count_pend_cost_initial = lPendCost->count;
#endif


	/*
	 * Handle special case: delete all routes at prefix
	 */
	if (lPendCost == (struct list *)1) {
		vnc_zlog_debug_verbose("%s: lPendCost=1 => delete all",
				       __func__);
		if (slRibPt && !skiplist_empty(slRibPt)) {
			delete_list = list_new();
			while (0
			       == skiplist_first(slRibPt, NULL, (void **)&ri)) {

				char buf[PREFIX_STRLEN];
				char buf2[PREFIX_STRLEN];

				listnode_add(delete_list, ri);
				vnc_zlog_debug_verbose(
					"%s: after listnode_add, delete_list->count=%d",
					__func__, delete_list->count);
				rfapiFreeBgpTeaOptionChain(ri->tea_options);
				ri->tea_options = NULL;

				if (ri->timer) {
					struct rfapi_rib_tcb *tcb;

					tcb = ((struct thread *)ri->timer)->arg;
					thread_cancel(ri->timer);
					XFREE(MTYPE_RFAPI_RECENT_DELETE, tcb);
					ri->timer = NULL;
				}

				prefix2str(&ri->rk.vn, buf, sizeof(buf));
				prefix2str(&ri->un, buf2, sizeof(buf2));
				vnc_zlog_debug_verbose(
					"%s:   put dl pfx=%s vn=%s un=%s cost=%d life=%d vn_options=%p",
					__func__, buf_prefix, buf, buf2,
					ri->cost, ri->lifetime, ri->vn_options);

				skiplist_delete_first(slRibPt);
			}

			assert(skiplist_empty(slRibPt));

			skiplist_free(slRibPt);
			rn->info = slRibPt = NULL;
			agg_unlock_node(rn);

			lPendCost = pn->info = NULL;
			agg_unlock_node(pn);

			goto callback;
		}
		if (slRibPt) {
			skiplist_free(slRibPt);
			rn->info = NULL;
			agg_unlock_node(rn);
		}

		assert(!slPendPt);
		if (slPendPt) { /* TBD I think we can toss this block */
			skiplist_free(slPendPt);
			pn->aggregate = NULL;
			agg_unlock_node(pn);
		}

		pn->info = NULL;
		agg_unlock_node(pn);

		agg_unlock_node(rn); /* agg_node_get() */

		if (rib_node_started_nonempty) {
			RFAPI_RIB_PREFIX_COUNT_DECR(rfd, bgp->rfapi);
		}

		RFAPI_RIB_CHECK_COUNTS(1, 0);

		return;
	}

	vnc_zlog_debug_verbose("%s:   lPendCost->count=%d, slRibPt->count=%d",
			       __func__,
			       (lPendCost ? (int)lPendCost->count : -1),
			       (slRibPt ? (int)slRibPt->count : -1));

	/*
	 * Iterate over routes at RIB Node.
	 * If not found at Pending Node, delete from RIB Node and add to
	 * deletelist
	 * If found at Pending Node
	 *      If identical rfapi_info, delete from Pending Node
	 */
	if (slRibPt) {
		void *cursor = NULL;
		struct rfapi_info *ori;

		/*
		 * Iterate over RIB List
		 *
		 */
		while (!skiplist_next(slRibPt, NULL, (void **)&ori, &cursor)) {

			if (skiplist_search(slPendPt, &ori->rk, (void **)&ri)) {
				/*
				 * Not in Pending list, so it should be deleted
				 */
				if (!delete_list)
					delete_list = list_new();
				listnode_add(delete_list, ori);
				rfapiFreeBgpTeaOptionChain(ori->tea_options);
				ori->tea_options = NULL;
				if (ori->timer) {
					struct rfapi_rib_tcb *tcb;

					tcb = ((struct thread *)ori->timer)
						      ->arg;
					thread_cancel(ori->timer);
					XFREE(MTYPE_RFAPI_RECENT_DELETE, tcb);
					ori->timer = NULL;
				}

#if DEBUG_PROCESS_PENDING_NODE
				/* deleted from slRibPt below, after we're done
				 * iterating */
				vnc_zlog_debug_verbose(
					"%s:   slRibPt ri %p not matched in pending list, delete",
					__func__, ori);
#endif

			} else {
				/*
				 * Found in pending list. If same lifetime,
				 * cost, options,
				 * then remove from pending list because the
				 * route
				 * hasn't changed.
				 */
				if (!rfapi_info_cmp(ori, ri)) {
					skiplist_delete(slPendPt, &ri->rk,
							NULL);
					assert(lPendCost);
					if (lPendCost) {
						/* linear walk: might need
						 * optimization */
						listnode_delete(lPendCost,
								ri); /* XXX
									doesn't
									free
									data!
									bug? */
						rfapi_info_free(
							ri); /* grr... */
					}
				}
#if DEBUG_PROCESS_PENDING_NODE
				vnc_zlog_debug_verbose(
					"%s:   slRibPt ri %p matched in pending list, %s",
					__func__, ori,
					(same ? "same info"
					      : "different info"));
#endif
			}
		}
		/*
		 * Go back and delete items from RIB
		 */
		if (delete_list) {
			for (ALL_LIST_ELEMENTS_RO(delete_list, node, ri)) {
				vnc_zlog_debug_verbose(
					"%s:   deleting ri %p from slRibPt",
					__func__, ri);
				assert(!skiplist_delete(slRibPt, &ri->rk,
							NULL));
			}
			if (skiplist_empty(slRibPt)) {
				skiplist_free(slRibPt);
				slRibPt = rn->info = NULL;
				agg_unlock_node(rn);
			}
		}
	}

	RFAPI_RIB_CHECK_COUNTS(0, (delete_list ? delete_list->count : 0));

	/*
	 * Iterate over routes at Pending Node
	 *
	 * If {vn} found at RIB Node, update RIB Node route contents to match PN
	 * If {vn} NOT found at RIB Node, add copy to RIB Node
	 */
	if (lPendCost) {
		for (ALL_LIST_ELEMENTS_RO(lPendCost, node, ri)) {

			struct rfapi_info *ori;

			if (slRibPt
			    && !skiplist_search(slRibPt, &ri->rk,
						(void **)&ori)) {

				/* found: update contents of existing route in
				 * RIB */
				ori->un = ri->un;
				ori->cost = ri->cost;
				ori->lifetime = ri->lifetime;
				rfapiFreeBgpTeaOptionChain(ori->tea_options);
				ori->tea_options =
					rfapiOptionsDup(ri->tea_options);
				ori->last_sent_time = rfapi_time(NULL);

				rfapiFreeRfapiVnOptionChain(ori->vn_options);
				ori->vn_options =
					rfapiVnOptionsDup(ri->vn_options);

				rfapiFreeRfapiUnOptionChain(ori->un_options);
				ori->un_options =
					rfapiUnOptionsDup(ri->un_options);

				vnc_zlog_debug_verbose(
					"%s:   matched lPendCost item %p in slRibPt, rewrote",
					__func__, ri);

			} else {

				char buf_rd[RD_ADDRSTRLEN];

				/* not found: add new route to RIB */
				ori = rfapi_info_new();
				ori->rk = ri->rk;
				ori->un = ri->un;
				ori->cost = ri->cost;
				ori->lifetime = ri->lifetime;
				ori->tea_options =
					rfapiOptionsDup(ri->tea_options);
				ori->last_sent_time = rfapi_time(NULL);
				ori->vn_options =
					rfapiVnOptionsDup(ri->vn_options);
				ori->un_options =
					rfapiUnOptionsDup(ri->un_options);

				if (!slRibPt) {
					slRibPt = skiplist_new(
						0, rfapi_rib_key_cmp, NULL);
					rn->info = slRibPt;
					agg_lock_node(rn);
				}
				skiplist_insert(slRibPt, &ori->rk, ori);

#if DEBUG_RIB_SL_RD
				prefix_rd2str(&ori->rk.rd, buf_rd,
					      sizeof(buf_rd));
#else
				buf_rd[0] = 0;
#endif

				vnc_zlog_debug_verbose(
					"%s:   nomatch lPendCost item %p in slRibPt, added (rd=%s)",
					__func__, ri, buf_rd);
			}

			/*
			 * poke timer
			 */
			RFAPI_RIB_CHECK_COUNTS(
				0, (delete_list ? delete_list->count : 0));
			rfapiRibStartTimer(rfd, ori, rn, 0);
			RFAPI_RIB_CHECK_COUNTS(
				0, (delete_list ? delete_list->count : 0));
		}
	}


callback:
	/*
	 * Construct NHL as concatenation of pending list + delete list
	 */


	RFAPI_RIB_CHECK_COUNTS(0, (delete_list ? delete_list->count : 0));

	if (lPendCost) {

		char buf[BUFSIZ];
		char buf2[BUFSIZ];

		vnc_zlog_debug_verbose("%s: lPendCost->count now %d", __func__,
				       lPendCost->count);
		vnc_zlog_debug_verbose("%s: For prefix %s (a)", __func__,
				       buf_prefix);
		printedprefix = 1;

		for (ALL_LIST_ELEMENTS(lPendCost, node, nnode, ri)) {

			struct rfapi_next_hop_entry *new;
			struct agg_node *trn;

			new = XCALLOC(MTYPE_RFAPI_NEXTHOP,
				      sizeof(struct rfapi_next_hop_entry));
			assert(new);

			if (ri->rk.aux_prefix.family) {
				rfapiQprefix2Rprefix(&ri->rk.aux_prefix,
						     &new->prefix);
			} else {
				new->prefix = hp;
				if (AFI_L2VPN == afi) {
					/* hp is 0; need to set length to match
					 * AF of vn */
					new->prefix.length =
						(ri->rk.vn.family == AF_INET)
							? 32
							: 128;
				}
			}
			new->prefix.cost = ri->cost;
			new->lifetime = ri->lifetime;
			rfapiQprefix2Raddr(&ri->rk.vn, &new->vn_address);
			rfapiQprefix2Raddr(&ri->un, &new->un_address);
			/* free option chain from ri */
			rfapiFreeBgpTeaOptionChain(ri->tea_options);

			ri->tea_options =
				NULL; /* option chain was transferred to NHL */

			new->vn_options = ri->vn_options;
			ri->vn_options =
				NULL; /* option chain was transferred to NHL */

			new->un_options = ri->un_options;
			ri->un_options =
				NULL; /* option chain was transferred to NHL */

			if (*tail)
				(*tail)->next = new;
			*tail = new;
			if (!*head) {
				*head = new;
			}
			sendingsomeroutes = 1;

			++rfd->stat_count_nh_reachable;
			++bgp->rfapi->stat.count_updated_response_updates;

			/*
			 * update this NVE's timestamp for this prefix
			 */
			trn = agg_node_get(rfd->rsp_times[afi],
					   &pn->p); /* locks trn */
			trn->info = (void *)(uintptr_t)bgp_clock();
			if (trn->lock > 1)
				agg_unlock_node(trn);

			rfapiRfapiIpAddr2Str(&new->vn_address, buf, BUFSIZ);
			rfapiRfapiIpAddr2Str(&new->un_address, buf2, BUFSIZ);
			vnc_zlog_debug_verbose(
				"%s:   add vn=%s un=%s cost=%d life=%d",
				__func__, buf, buf2, new->prefix.cost,
				new->lifetime);
		}
	}

	RFAPI_RIB_CHECK_COUNTS(0, (delete_list ? delete_list->count : 0));

	if (delete_list) {

		char buf[BUFSIZ];
		char buf2[BUFSIZ];

		if (!printedprefix) {
			vnc_zlog_debug_verbose("%s: For prefix %s (d)",
					       __func__, buf_prefix);
		}
		vnc_zlog_debug_verbose("%s: delete_list has %d elements",
				       __func__, delete_list->count);

		RFAPI_RIB_CHECK_COUNTS(0, delete_list->count);
		if (!CHECK_FLAG(bgp->rfapi_cfg->flags,
				BGP_VNC_CONFIG_RESPONSE_REMOVAL_DISABLE)) {

			for (ALL_LIST_ELEMENTS(delete_list, node, nnode, ri)) {

				struct rfapi_next_hop_entry *new;
				struct rfapi_info *ri_del;

				RFAPI_RIB_CHECK_COUNTS(0, delete_list->count);
				new = XCALLOC(
					MTYPE_RFAPI_NEXTHOP,
					sizeof(struct rfapi_next_hop_entry));
				assert(new);

				if (ri->rk.aux_prefix.family) {
					rfapiQprefix2Rprefix(&ri->rk.aux_prefix,
							     &new->prefix);
				} else {
					new->prefix = hp;
					if (AFI_L2VPN == afi) {
						/* hp is 0; need to set length
						 * to match AF of vn */
						new->prefix.length =
							(ri->rk.vn.family
							 == AF_INET)
								? 32
								: 128;
					}
				}

				new->prefix.cost = ri->cost;
				new->lifetime = RFAPI_REMOVE_RESPONSE_LIFETIME;
				rfapiQprefix2Raddr(&ri->rk.vn,
						   &new->vn_address);
				rfapiQprefix2Raddr(&ri->un, &new->un_address);

				new->vn_options = ri->vn_options;
				ri->vn_options = NULL; /* option chain was
							  transferred to NHL */

				new->un_options = ri->un_options;
				ri->un_options = NULL; /* option chain was
							  transferred to NHL */

				if (*tail)
					(*tail)->next = new;
				*tail = new;
				if (!*head) {
					*head = new;
				}
				++rfd->stat_count_nh_removal;
				++bgp->rfapi->stat
					  .count_updated_response_deletes;

				rfapiRfapiIpAddr2Str(&new->vn_address, buf,
						     BUFSIZ);
				rfapiRfapiIpAddr2Str(&new->un_address, buf2,
						     BUFSIZ);
				vnc_zlog_debug_verbose(
					"%s:   DEL vn=%s un=%s cost=%d life=%d",
					__func__, buf, buf2, new->prefix.cost,
					new->lifetime);

				RFAPI_RIB_CHECK_COUNTS(0, delete_list->count);
				/*
				 * Update/add to list of recent deletions at
				 * this prefix
				 */
				if (!rn->aggregate) {
					rn->aggregate = skiplist_new(
						0, rfapi_rib_key_cmp,
						(void (*)(void *))
							rfapi_info_free);
					agg_lock_node(rn);
				}
				RFAPI_RIB_CHECK_COUNTS(0, delete_list->count);

				/* sanity check lifetime */
				if (ri->lifetime
				    > RFAPI_LIFETIME_INFINITE_WITHDRAW_DELAY)
					ri->lifetime =
						RFAPI_LIFETIME_INFINITE_WITHDRAW_DELAY;

				RFAPI_RIB_CHECK_COUNTS(0, delete_list->count);
				/* cancel normal expire timer */
				if (ri->timer) {
					struct rfapi_rib_tcb *tcb;

					tcb = ((struct thread *)ri->timer)->arg;
					thread_cancel(
						(struct thread *)ri->timer);
					XFREE(MTYPE_RFAPI_RECENT_DELETE, tcb);
					ri->timer = NULL;
				}
				RFAPI_RIB_CHECK_COUNTS(0, delete_list->count);

				/*
				 * Look in "recently-deleted" list
				 */
				if (skiplist_search(
					    (struct skiplist *)(rn->aggregate),
					    &ri->rk, (void **)&ri_del)) {

					int rc;

					RFAPI_RIB_CHECK_COUNTS(
						0, delete_list->count);
					/*
					 * NOT in "recently-deleted" list
					 */
					list_delete_node(
						delete_list,
						node); /* does not free ri */
					rc = skiplist_insert(
						(struct skiplist
							 *)(rn->aggregate),
						&ri->rk, ri);
					assert(!rc);

					RFAPI_RIB_CHECK_COUNTS(
						0, delete_list->count);
					rfapiRibStartTimer(rfd, ri, rn, 1);
					RFAPI_RIB_CHECK_COUNTS(
						0, delete_list->count);
					ri->last_sent_time = rfapi_time(NULL);
#if DEBUG_RIB_SL_RD
					{
						char buf_rd[RD_ADDRSTRLEN];

						vnc_zlog_debug_verbose(
							"%s: move route to recently deleted list, rd=%s",
							__func__,
							prefix_rd2str(
								&ri->rk.rd,
								buf_rd,
								sizeof(buf_rd)));
					}
#endif

				} else {
					/*
					 * IN "recently-deleted" list
					 */
					RFAPI_RIB_CHECK_COUNTS(
						0, delete_list->count);
					rfapiRibStartTimer(rfd, ri_del, rn, 1);
					RFAPI_RIB_CHECK_COUNTS(
						0, delete_list->count);
					ri->last_sent_time = rfapi_time(NULL);
				}
			}
		} else {
			vnc_zlog_debug_verbose(
				"%s: response removal disabled, omitting removals",
				__func__);
		}

		delete_list->del = (void (*)(void *))rfapi_info_free;
		list_delete(&delete_list);
	}

	RFAPI_RIB_CHECK_COUNTS(0, 0);

	/*
	 * Reset pending lists. The final agg_unlock_node() will probably
	 * cause the pending node to be released.
	 */
	if (slPendPt) {
		skiplist_free(slPendPt);
		pn->aggregate = NULL;
		agg_unlock_node(pn);
	}
	if (lPendCost) {
		list_delete(&lPendCost);
		pn->info = NULL;
		agg_unlock_node(pn);
	}
	RFAPI_RIB_CHECK_COUNTS(0, 0);

	if (rib_node_started_nonempty) {
		if (!rn->info) {
			RFAPI_RIB_PREFIX_COUNT_DECR(rfd, bgp->rfapi);
		}
	} else {
		if (rn->info) {
			RFAPI_RIB_PREFIX_COUNT_INCR(rfd, bgp->rfapi);
		}
	}

	if (sendingsomeroutes)
		rfapiMonitorTimersRestart(rfd, &pn->p);

	agg_unlock_node(rn); /* agg_node_get() */

	RFAPI_RIB_CHECK_COUNTS(1, 0);
}

/*
 * regardless of targets, construct a single callback by doing
 * only one traversal of the pending RIB
 *
 *
 * Do callback
 *
 */
static void rib_do_callback_onepass(struct rfapi_descriptor *rfd, afi_t afi)
{
	struct bgp *bgp = bgp_get_default();
	struct rfapi_next_hop_entry *head = NULL;
	struct rfapi_next_hop_entry *tail = NULL;
	struct agg_node *rn;

#if DEBUG_L2_EXTRA
	vnc_zlog_debug_verbose("%s: rfd=%p, afi=%d", __func__, rfd, afi);
#endif

	if (!rfd->rib_pending[afi])
		return;

	assert(bgp->rfapi);

	for (rn = agg_route_top(rfd->rib_pending[afi]); rn;
	     rn = agg_route_next(rn)) {
		process_pending_node(bgp, rfd, afi, rn, &head, &tail);
	}

	if (head) {
		rfapi_response_cb_t *f;

#if DEBUG_NHL
		vnc_zlog_debug_verbose("%s: response callback NHL follows:",
				       __func__);
		rfapiPrintNhl(NULL, head);
#endif

		if (rfd->response_cb)
			f = rfd->response_cb;
		else
			f = bgp->rfapi->rfp_methods.response_cb;

		bgp->rfapi->flags |= RFAPI_INCALLBACK;
		vnc_zlog_debug_verbose("%s: invoking updated response callback",
				       __func__);
		(*f)(head, rfd->cookie);
		bgp->rfapi->flags &= ~RFAPI_INCALLBACK;
		++bgp->rfapi->response_updated_count;
	}
}

static wq_item_status rfapiRibDoQueuedCallback(struct work_queue *wq,
					       void *data)
{
	struct rfapi_descriptor *rfd;
	afi_t afi;
	uint32_t queued_flag;

	RFAPI_RIB_CHECK_COUNTS(1, 0);

	rfd = ((struct rfapi_updated_responses_queue *)data)->rfd;
	afi = ((struct rfapi_updated_responses_queue *)data)->afi;

	/* Make sure the HD wasn't closed after the work item was scheduled */
	if (rfapi_check(rfd))
		return WQ_SUCCESS;

	rib_do_callback_onepass(rfd, afi);

	queued_flag = RFAPI_QUEUED_FLAG(afi);

	UNSET_FLAG(rfd->flags, queued_flag);

	RFAPI_RIB_CHECK_COUNTS(1, 0);

	return WQ_SUCCESS;
}

static void rfapiRibQueueItemDelete(struct work_queue *wq, void *data)
{
	XFREE(MTYPE_RFAPI_UPDATED_RESPONSE_QUEUE, data);
}

static void updated_responses_queue_init(struct rfapi_descriptor *rfd)
{
	if (rfd->updated_responses_queue)
		return;

	rfd->updated_responses_queue =
		work_queue_new(bm->master, "rfapi updated responses");
	assert(rfd->updated_responses_queue);

	rfd->updated_responses_queue->spec.workfunc = rfapiRibDoQueuedCallback;
	rfd->updated_responses_queue->spec.del_item_data =
		rfapiRibQueueItemDelete;
	rfd->updated_responses_queue->spec.max_retries = 0;
	rfd->updated_responses_queue->spec.hold = 1;
}

/*
 * Called when an import table node is modified. Construct a
 * new complete nexthop list, sorted by cost (lowest first),
 * based on the import table node.
 *
 * Filter out duplicate nexthops (vn address). There should be
 * only one UN address per VN address from the point of view of
 * a given import table, so we can probably ignore UN addresses
 * while filtering.
 *
 * Based on rfapiNhlAddNodeRoutes()
 */
void rfapiRibUpdatePendingNode(
	struct bgp *bgp, struct rfapi_descriptor *rfd,
	struct rfapi_import_table *it, /* needed for L2 */
	struct agg_node *it_node, uint32_t lifetime)
{
	struct prefix *prefix;
	struct bgp_path_info *bpi;
	struct agg_node *pn;
	afi_t afi;
	uint32_t queued_flag;
	int count = 0;
	char buf[PREFIX_STRLEN];

	vnc_zlog_debug_verbose("%s: entry", __func__);

	if (CHECK_FLAG(bgp->rfapi_cfg->flags, BGP_VNC_CONFIG_CALLBACK_DISABLE))
		return;

	vnc_zlog_debug_verbose("%s: callbacks are not disabled", __func__);

	RFAPI_RIB_CHECK_COUNTS(1, 0);

	prefix = &it_node->p;
	afi = family2afi(prefix->family);
	prefix2str(prefix, buf, sizeof(buf));
	vnc_zlog_debug_verbose("%s: prefix=%s", __func__, buf);

	pn = agg_node_get(rfd->rib_pending[afi], prefix);
	assert(pn);

	vnc_zlog_debug_verbose("%s: pn->info=%p, pn->aggregate=%p", __func__,
			       pn->info, pn->aggregate);

	if (pn->aggregate) {
		/*
		 * free references into the rfapi_info structures before
		 * freeing the structures themselves
		 */
		skiplist_free((struct skiplist *)(pn->aggregate));
		pn->aggregate = NULL;
		agg_unlock_node(pn); /* skiplist deleted */
	}


	/*
	 * free the rfapi_info structures
	 */
	if (pn->info) {
		if (pn->info != (void *)1) {
			list_delete((struct list **)(&pn->info));
		}
		pn->info = NULL;
		agg_unlock_node(pn); /* linklist or 1 deleted */
	}

	/*
	 * The BPIs in the import table are already sorted by cost
	 */
	for (bpi = it_node->info; bpi; bpi = bpi->next) {

		struct rfapi_info *ri;
		struct prefix pfx_nh;

		if (!bpi->extra) {
			/* shouldn't happen */
			/* TBD increment error stats counter */
			continue;
		}

		rfapiNexthop2Prefix(bpi->attr, &pfx_nh);

		/*
		 * Omit route if nexthop is self
		 */
		if (CHECK_FLAG(bgp->rfapi_cfg->flags,
			       BGP_VNC_CONFIG_FILTER_SELF_FROM_RSP)) {

			struct prefix pfx_vn;

			assert(!rfapiRaddr2Qprefix(&rfd->vn_addr, &pfx_vn));
			if (prefix_same(&pfx_vn, &pfx_nh))
				continue;
		}

		ri = rfapi_info_new();
		ri->rk.vn = pfx_nh;
		ri->rk.rd = bpi->extra->vnc.import.rd;
		/*
		 * If there is an auxiliary IP address (L2 can have it), copy it
		 */
		if (bpi->extra->vnc.import.aux_prefix.family) {
			ri->rk.aux_prefix = bpi->extra->vnc.import.aux_prefix;
		}

		if (rfapiGetUnAddrOfVpnBi(bpi, &ri->un)) {
			rfapi_info_free(ri);
			continue;
		}

		if (!pn->aggregate) {
			pn->aggregate =
				skiplist_new(0, rfapi_rib_key_cmp, NULL);
			agg_lock_node(pn);
		}

		/*
		 * If we have already added this nexthop, the insert will fail.
		 * Note that the skiplist key is a pointer INTO the rfapi_info
		 * structure which will be added to the "info" list.
		 * The skiplist entry VALUE is not used for anything but
		 * might be useful during debugging.
		 */
		if (skiplist_insert((struct skiplist *)pn->aggregate, &ri->rk,
				    ri)) {

			/*
			 * duplicate
			 */
			rfapi_info_free(ri);
			continue;
		}

		rfapiRibBi2Ri(bpi, ri, lifetime);

		if (!pn->info) {
			pn->info = list_new();
			((struct list *)(pn->info))->del =
				(void (*)(void *))rfapi_info_free;
			agg_lock_node(pn);
		}

		listnode_add((struct list *)(pn->info), ri);
	}

	if (pn->info) {
		count = ((struct list *)(pn->info))->count;
	}

	if (!count) {
		assert(!pn->info);
		assert(!pn->aggregate);
		pn->info = (void *)1; /* magic value means this node has no
					 routes */
		agg_lock_node(pn);
	}

	agg_unlock_node(pn); /* agg_node_get */

	queued_flag = RFAPI_QUEUED_FLAG(afi);

	if (!CHECK_FLAG(rfd->flags, queued_flag)) {

		struct rfapi_updated_responses_queue *urq;

		urq = XCALLOC(MTYPE_RFAPI_UPDATED_RESPONSE_QUEUE,
			      sizeof(struct rfapi_updated_responses_queue));
		assert(urq);
		if (!rfd->updated_responses_queue)
			updated_responses_queue_init(rfd);

		SET_FLAG(rfd->flags, queued_flag);
		urq->rfd = rfd;
		urq->afi = afi;
		work_queue_add(rfd->updated_responses_queue, urq);
	}
	RFAPI_RIB_CHECK_COUNTS(1, 0);
}

void rfapiRibUpdatePendingNodeSubtree(
	struct bgp *bgp, struct rfapi_descriptor *rfd,
	struct rfapi_import_table *it, struct agg_node *it_node,
	struct agg_node *omit_subtree, /* may be NULL */
	uint32_t lifetime)
{
	/* FIXME: need to find a better way here to work without sticking our
	 * hands in node->link */
	if (agg_node_left(it_node)
	    && (agg_node_left(it_node) != omit_subtree)) {
		if (agg_node_left(it_node)->info)
			rfapiRibUpdatePendingNode(
				bgp, rfd, it, agg_node_left(it_node), lifetime);
		rfapiRibUpdatePendingNodeSubtree(bgp, rfd, it,
						 agg_node_left(it_node),
						 omit_subtree, lifetime);
	}

	if (agg_node_right(it_node)
	    && (agg_node_right(it_node) != omit_subtree)) {
		if (agg_node_right(it_node)->info)
			rfapiRibUpdatePendingNode(bgp, rfd, it,
						  agg_node_right(it_node),
						  lifetime);
		rfapiRibUpdatePendingNodeSubtree(bgp, rfd, it,
						 agg_node_right(it_node),
						 omit_subtree, lifetime);
	}
}

/*
 * RETURN VALUE
 *
 *	0	allow prefix to be included in response
 *	!0	don't allow prefix to be included in response
 */
int rfapiRibFTDFilterRecentPrefix(
	struct rfapi_descriptor *rfd,
	struct agg_node *it_rn,		    /* import table node */
	struct prefix *pfx_target_original) /* query target */
{
	struct bgp *bgp = rfd->bgp;
	afi_t afi = family2afi(it_rn->p.family);
	time_t prefix_time;
	struct agg_node *trn;

	/*
	 * Not in FTD mode, so allow prefix
	 */
	if (bgp->rfapi_cfg->rfp_cfg.download_type != RFAPI_RFP_DOWNLOAD_FULL)
		return 0;

	/*
	 * TBD
	 * This matches behavior of now-obsolete rfapiRibFTDFilterRecent(),
	 * but we need to decide if that is correct.
	 */
	if (it_rn->p.family == AF_ETHERNET)
		return 0;

#if DEBUG_FTD_FILTER_RECENT
	{
		char buf_pfx[PREFIX_STRLEN];

		prefix2str(&it_rn->p, buf_pfx, sizeof(buf_pfx));
		vnc_zlog_debug_verbose("%s: prefix %s", __func__, buf_pfx);
	}
#endif

	/*
	 * prefix covers target address, so allow prefix
	 */
	if (prefix_match(&it_rn->p, pfx_target_original)) {
#if DEBUG_FTD_FILTER_RECENT
		vnc_zlog_debug_verbose("%s: prefix covers target, allowed",
				       __func__);
#endif
		return 0;
	}

	/*
	 * check this NVE's timestamp for this prefix
	 */
	trn = agg_node_get(rfd->rsp_times[afi], &it_rn->p); /* locks trn */
	prefix_time = (time_t)trn->info;
	if (trn->lock > 1)
		agg_unlock_node(trn);

#if DEBUG_FTD_FILTER_RECENT
	vnc_zlog_debug_verbose("%s: last sent time %lu, last allowed time %lu",
			       __func__, prefix_time,
			       rfd->ftd_last_allowed_time);
#endif

	/*
	 * haven't sent this prefix, which doesn't cover target address,
	 * to NVE since ftd_advertisement_interval, so OK to send now.
	 */
	if (prefix_time <= rfd->ftd_last_allowed_time)
		return 0;

	return 1;
}

/*
 * Call when rfapi returns from rfapi_query() so the RIB reflects
 * the routes sent to the NVE before the first updated response
 *
 * Also: remove duplicates from response. Caller should use returned
 * value of nexthop chain.
 */
struct rfapi_next_hop_entry *
rfapiRibPreload(struct bgp *bgp, struct rfapi_descriptor *rfd,
		struct rfapi_next_hop_entry *response, int use_eth_resolution)
{
	struct rfapi_next_hop_entry *nhp;
	struct rfapi_next_hop_entry *nhp_next;
	struct rfapi_next_hop_entry *head = NULL;
	struct rfapi_next_hop_entry *tail = NULL;
	time_t new_last_sent_time;

	vnc_zlog_debug_verbose("%s: loading response=%p, use_eth_resolution=%d",
			       __func__, response, use_eth_resolution);

	new_last_sent_time = rfapi_time(NULL);

	for (nhp = response; nhp; nhp = nhp_next) {

		struct prefix pfx;
		struct rfapi_rib_key rk;
		afi_t afi;
		struct rfapi_info *ri;
		int need_insert;
		struct agg_node *rn;
		int rib_node_started_nonempty = 0;
		struct agg_node *trn;
		int allowed = 0;

		/* save in case we delete nhp */
		nhp_next = nhp->next;

		if (nhp->lifetime == RFAPI_REMOVE_RESPONSE_LIFETIME) {
			/*
			 * weird, shouldn't happen
			 */
			vnc_zlog_debug_verbose(
				"%s: got nhp->lifetime == RFAPI_REMOVE_RESPONSE_LIFETIME",
				__func__);
			continue;
		}


		if (use_eth_resolution) {
			/* get the prefix of the ethernet address in the L2
			 * option */
			struct rfapi_l2address_option *pL2o;
			struct rfapi_vn_option *vo;

			/*
			 * Look for VN option of type
			 * RFAPI_VN_OPTION_TYPE_L2ADDR
			 */
			for (pL2o = NULL, vo = nhp->vn_options; vo;
			     vo = vo->next) {
				if (RFAPI_VN_OPTION_TYPE_L2ADDR == vo->type) {
					pL2o = &vo->v.l2addr;
					break;
				}
			}

			if (!pL2o) {
				/*
				 * not supposed to happen
				 */
				vnc_zlog_debug_verbose("%s: missing L2 info",
						       __func__);
				continue;
			}

			afi = AFI_L2VPN;
			rfapiL2o2Qprefix(pL2o, &pfx);
		} else {
			rfapiRprefix2Qprefix(&nhp->prefix, &pfx);
			afi = family2afi(pfx.family);
		}

		/*
		 * TBD for ethernet, rib must know the right way to distinguish
		 * duplicate routes
		 *
		 * Current approach: prefix is key to radix tree; then
		 * each prefix has a set of routes with unique VN addrs
		 */

		/*
		 * Look up prefix in RIB
		 */
		rn = agg_node_get(rfd->rib[afi], &pfx); /* locks rn */

		if (rn->info) {
			rib_node_started_nonempty = 1;
		} else {
			rn->info = skiplist_new(0, rfapi_rib_key_cmp, NULL);
			agg_lock_node(rn);
		}

		/*
		 * Look up route at prefix
		 */
		need_insert = 0;
		memset((void *)&rk, 0, sizeof(rk));
		assert(!rfapiRaddr2Qprefix(&nhp->vn_address, &rk.vn));

		if (use_eth_resolution) {
			/* copy what came from aux_prefix to rk.aux_prefix */
			rfapiRprefix2Qprefix(&nhp->prefix, &rk.aux_prefix);
			if (RFAPI_0_PREFIX(&rk.aux_prefix)
			    && RFAPI_HOST_PREFIX(&rk.aux_prefix)) {
				/* mark as "none" if nhp->prefix is 0/32 or
				 * 0/128 */
				rk.aux_prefix.family = 0;
			}
		}

#if DEBUG_NHL
		{
			char str_vn[PREFIX_STRLEN];
			char str_aux_prefix[PREFIX_STRLEN];

			str_vn[0] = 0;
			str_aux_prefix[0] = 0;

			prefix2str(&rk.vn, str_vn, sizeof(str_vn));
			prefix2str(&rk.aux_prefix, str_aux_prefix,
				   sizeof(str_aux_prefix));

			if (!rk.aux_prefix.family) {
			}
			vnc_zlog_debug_verbose(
				"%s:   rk.vn=%s rk.aux_prefix=%s", __func__,
				str_vn,
				(rk.aux_prefix.family ? str_aux_prefix : "-"));
		}
		vnc_zlog_debug_verbose(
			"%s: RIB skiplist for this prefix follows", __func__);
		rfapiRibShowRibSl(NULL, &rn->p, (struct skiplist *)rn->info);
#endif


		if (!skiplist_search((struct skiplist *)rn->info, &rk,
				     (void **)&ri)) {
			/*
			 * Already have this route; make values match
			 */
			rfapiFreeRfapiUnOptionChain(ri->un_options);
			ri->un_options = NULL;
			rfapiFreeRfapiVnOptionChain(ri->vn_options);
			ri->vn_options = NULL;

#if DEBUG_NHL
			vnc_zlog_debug_verbose("%s: found in RIB", __func__);
#endif

			/*
			 * Filter duplicate routes from initial response.
			 * Check timestamps to avoid wraparound problems
			 */
			if ((ri->rsp_counter != rfd->rsp_counter)
			    || (ri->last_sent_time != new_last_sent_time)) {

#if DEBUG_NHL
				vnc_zlog_debug_verbose(
					"%s: allowed due to counter/timestamp diff",
					__func__);
#endif
				allowed = 1;
			}

		} else {

#if DEBUG_NHL
			vnc_zlog_debug_verbose(
				"%s: allowed due to not yet in RIB", __func__);
#endif
			/* not found: add new route to RIB */
			ri = rfapi_info_new();
			need_insert = 1;
			allowed = 1;
		}

		ri->rk = rk;
		assert(!rfapiRaddr2Qprefix(&nhp->un_address, &ri->un));
		ri->cost = nhp->prefix.cost;
		ri->lifetime = nhp->lifetime;
		ri->vn_options = rfapiVnOptionsDup(nhp->vn_options);
		ri->rsp_counter = rfd->rsp_counter;
		ri->last_sent_time = rfapi_time(NULL);

		if (need_insert) {
			int rc;
			rc = skiplist_insert((struct skiplist *)rn->info,
					     &ri->rk, ri);
			assert(!rc);
		}

		if (!rib_node_started_nonempty) {
			RFAPI_RIB_PREFIX_COUNT_INCR(rfd, bgp->rfapi);
		}

		RFAPI_RIB_CHECK_COUNTS(0, 0);
		rfapiRibStartTimer(rfd, ri, rn, 0);
		RFAPI_RIB_CHECK_COUNTS(0, 0);

		agg_unlock_node(rn);

		/*
		 * update this NVE's timestamp for this prefix
		 */
		trn = agg_node_get(rfd->rsp_times[afi], &pfx); /* locks trn */
		trn->info = (void *)(uintptr_t)bgp_clock();
		if (trn->lock > 1)
			agg_unlock_node(trn);

		{
			char str_pfx[PREFIX_STRLEN];
			char str_pfx_vn[PREFIX_STRLEN];

			prefix2str(&pfx, str_pfx, sizeof(str_pfx));
			prefix2str(&rk.vn, str_pfx_vn, sizeof(str_pfx_vn));
			vnc_zlog_debug_verbose(
				"%s:   added pfx=%s nh[vn]=%s, cost=%u, lifetime=%u, allowed=%d",
				__func__, str_pfx, str_pfx_vn, nhp->prefix.cost,
				nhp->lifetime, allowed);
		}

		if (allowed) {
			if (tail)
				(tail)->next = nhp;
			tail = nhp;
			if (!head) {
				head = nhp;
			}
		} else {
			rfapi_un_options_free(nhp->un_options);
			nhp->un_options = NULL;
			rfapi_vn_options_free(nhp->vn_options);
			nhp->vn_options = NULL;

			XFREE(MTYPE_RFAPI_NEXTHOP, nhp);
		}
	}

	if (tail)
		tail->next = NULL;
	return head;
}

void rfapiRibPendingDeleteRoute(struct bgp *bgp, struct rfapi_import_table *it,
				afi_t afi, struct agg_node *it_node)
{
	struct rfapi_descriptor *rfd;
	struct listnode *node;
	char buf[PREFIX_STRLEN];

	prefix2str(&it_node->p, buf, sizeof(buf));
	vnc_zlog_debug_verbose("%s: entry, it=%p, afi=%d, it_node=%p, pfx=%s",
			       __func__, it, afi, it_node, buf);

	if (AFI_L2VPN == afi) {
		/*
		 * ethernet import tables are per-LNI and each ethernet monitor
		 * identifies the rfd that owns it.
		 */
		struct rfapi_monitor_eth *m;
		struct agg_node *rn;
		struct skiplist *sl;
		void *cursor;
		int rc;

		/*
		 * route-specific monitors
		 */
		if ((sl = RFAPI_MONITOR_ETH(it_node))) {

			vnc_zlog_debug_verbose(
				"%s: route-specific skiplist: %p", __func__,
				sl);

			for (cursor = NULL,
			    rc = skiplist_next(sl, NULL, (void **)&m,
					       (void **)&cursor);
			     !rc; rc = skiplist_next(sl, NULL, (void **)&m,
						     (void **)&cursor)) {

#if DEBUG_PENDING_DELETE_ROUTE
				vnc_zlog_debug_verbose("%s: eth monitor rfd=%p",
						       __func__, m->rfd);
#endif
				/*
				 * If we have already sent a route with this
				 * prefix to this
				 * NVE, it's OK to send an update with the
				 * delete
				 */
				if ((rn = agg_node_lookup(m->rfd->rib[afi],
							  &it_node->p))) {
					rfapiRibUpdatePendingNode(
						bgp, m->rfd, it, it_node,
						m->rfd->response_lifetime);
					agg_unlock_node(rn);
				}
			}
		}

		/*
		 * all-routes/FTD monitors
		 */
		for (m = it->eth0_queries; m; m = m->next) {
#if DEBUG_PENDING_DELETE_ROUTE
			vnc_zlog_debug_verbose("%s: eth0 monitor rfd=%p",
					       __func__, m->rfd);
#endif
			/*
			 * If we have already sent a route with this prefix to
			 * this
			 * NVE, it's OK to send an update with the delete
			 */
			if ((rn = agg_node_lookup(m->rfd->rib[afi],
						  &it_node->p))) {
				rfapiRibUpdatePendingNode(
					bgp, m->rfd, it, it_node,
					m->rfd->response_lifetime);
			}
		}

	} else {
		/*
		 * Find RFDs that reference this import table
		 */
		for (ALL_LIST_ELEMENTS_RO(&bgp->rfapi->descriptors, node,
					  rfd)) {

			struct agg_node *rn;

			vnc_zlog_debug_verbose(
				"%s: comparing rfd(%p)->import_table=%p to it=%p",
				__func__, rfd, rfd->import_table, it);

			if (rfd->import_table != it)
				continue;

			vnc_zlog_debug_verbose("%s: matched rfd %p", __func__,
					       rfd);

			/*
			 * If we have sent a response to this NVE with this
			 * prefix
			 * previously, we should send an updated response.
			 */
			if ((rn = agg_node_lookup(rfd->rib[afi],
						  &it_node->p))) {
				rfapiRibUpdatePendingNode(
					bgp, rfd, it, it_node,
					rfd->response_lifetime);
				agg_unlock_node(rn);
			}
		}
	}
}

void rfapiRibShowResponsesSummary(void *stream)
{
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;
	struct bgp *bgp = bgp_get_default();

	int nves = 0;
	int nves_with_nonempty_ribs = 0;
	struct rfapi_descriptor *rfd;
	struct listnode *node;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!bgp) {
		fp(out, "Unable to find default BGP instance\n");
		return;
	}

	fp(out, "%-24s ", "Responses: (Prefixes)");
	fp(out, "%-8s %-8u ", "Active:", bgp->rfapi->rib_prefix_count_total);
	fp(out, "%-8s %-8u",
	   "Maximum:", bgp->rfapi->rib_prefix_count_total_max);
	fp(out, "\n");

	fp(out, "%-24s ", "           (Updated)");
	fp(out, "%-8s %-8u ",
	   "Update:", bgp->rfapi->stat.count_updated_response_updates);
	fp(out, "%-8s %-8u",
	   "Remove:", bgp->rfapi->stat.count_updated_response_deletes);
	fp(out, "%-8s %-8u", "Total:",
	   bgp->rfapi->stat.count_updated_response_updates
		   + bgp->rfapi->stat.count_updated_response_deletes);
	fp(out, "\n");

	fp(out, "%-24s ", "           (NVEs)");
	for (ALL_LIST_ELEMENTS_RO(&bgp->rfapi->descriptors, node, rfd)) {
		++nves;
		if (rfd->rib_prefix_count)
			++nves_with_nonempty_ribs;
	}
	fp(out, "%-8s %-8u ", "Active:", nves_with_nonempty_ribs);
	fp(out, "%-8s %-8u", "Total:", nves);
	fp(out, "\n");
}

void rfapiRibShowResponsesSummaryClear(void)
{
	struct bgp *bgp = bgp_get_default();

	bgp->rfapi->rib_prefix_count_total_max =
		bgp->rfapi->rib_prefix_count_total;
}

static int print_rib_sl(int (*fp)(void *, const char *, ...), struct vty *vty,
			void *out, struct skiplist *sl, int deleted,
			char *str_pfx, int *printedprefix)
{
	struct rfapi_info *ri;
	int rc;
	void *cursor;
	int routes_displayed = 0;

	cursor = NULL;
	for (rc = skiplist_next(sl, NULL, (void **)&ri, &cursor); !rc;
	     rc = skiplist_next(sl, NULL, (void **)&ri, &cursor)) {

		char str_vn[PREFIX_STRLEN];
		char str_un[PREFIX_STRLEN];
		char str_lifetime[BUFSIZ];
		char str_age[BUFSIZ];
		char *p;
		char str_rd[RD_ADDRSTRLEN];

		++routes_displayed;

		prefix2str(&ri->rk.vn, str_vn, sizeof(str_vn));
		p = index(str_vn, '/');
		if (p)
			*p = 0;

		prefix2str(&ri->un, str_un, sizeof(str_un));
		p = index(str_un, '/');
		if (p)
			*p = 0;

		rfapiFormatSeconds(ri->lifetime, str_lifetime, BUFSIZ);
#if RFAPI_REGISTRATIONS_REPORT_AGE
		rfapiFormatAge(ri->last_sent_time, str_age, BUFSIZ);
#else
		{
			time_t now = rfapi_time(NULL);
			time_t expire =
				ri->last_sent_time + (time_t)ri->lifetime;
			/* allow for delayed/async removal */
			rfapiFormatSeconds((expire > now ? expire - now : 1),
					   str_age, BUFSIZ);
		}
#endif

		str_rd[0] = 0; /* start empty */
#if DEBUG_RIB_SL_RD
		prefix_rd2str(&ri->rk.rd, str_rd, sizeof(str_rd));
#endif

		fp(out, " %c %-20s %-15s %-15s %-4u %-8s %-8s %s\n",
		   deleted ? 'r' : ' ', *printedprefix ? "" : str_pfx, str_vn,
		   str_un, ri->cost, str_lifetime, str_age, str_rd);

		if (!*printedprefix)
			*printedprefix = 1;
	}
	return routes_displayed;
}

#if DEBUG_NHL
/*
 * This one is for debugging (set stream to NULL to send output to log)
 */
static void rfapiRibShowRibSl(void *stream, struct prefix *pfx,
			      struct skiplist *sl)
{
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	int nhs_displayed = 0;
	char str_pfx[PREFIX_STRLEN];
	int printedprefix = 0;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;

	prefix2str(pfx, str_pfx, sizeof(str_pfx));

	nhs_displayed +=
		print_rib_sl(fp, vty, out, sl, 0, str_pfx, &printedprefix);
}
#endif

void rfapiRibShowResponses(void *stream, struct prefix *pfx_match,
			   int show_removed)
{
	int (*fp)(void *, const char *, ...);
	struct vty *vty;
	void *out;
	const char *vty_newline;

	struct rfapi_descriptor *rfd;
	struct listnode *node;

	struct bgp *bgp = bgp_get_default();
	int printedheader = 0;
	int routes_total = 0;
	int nhs_total = 0;
	int prefixes_total = 0;
	int prefixes_displayed = 0;
	int nves_total = 0;
	int nves_with_routes = 0;
	int nves_displayed = 0;
	int routes_displayed = 0;
	int nhs_displayed = 0;

	if (rfapiStream2Vty(stream, &fp, &vty, &out, &vty_newline) == 0)
		return;
	if (!bgp) {
		fp(out, "Unable to find default BGP instance\n");
		return;
	}

	/*
	 * loop over NVEs
	 */
	for (ALL_LIST_ELEMENTS_RO(&bgp->rfapi->descriptors, node, rfd)) {

		int printednve = 0;
		afi_t afi;

		++nves_total;
		if (rfd->rib_prefix_count)
			++nves_with_routes;

		for (afi = AFI_IP; afi < AFI_MAX; ++afi) {

			struct agg_node *rn;

			if (!rfd->rib[afi])
				continue;

			for (rn = agg_route_top(rfd->rib[afi]); rn;
			     rn = agg_route_next(rn)) {

				struct skiplist *sl;
				char str_pfx[PREFIX_STRLEN];
				int printedprefix = 0;

				if (!show_removed)
					sl = rn->info;
				else
					sl = rn->aggregate;

				if (!sl)
					continue;

				routes_total++;
				nhs_total += skiplist_count(sl);
				++prefixes_total;

				if (pfx_match
				    && !prefix_match(pfx_match, &rn->p)
				    && !prefix_match(&rn->p, pfx_match))
					continue;

				++prefixes_displayed;

				if (!printedheader) {
					++printedheader;

					fp(out, "\n[%s]\n",
					   show_removed ? "Removed" : "Active");
					fp(out, "%-15s %-15s\n", "Querying VN",
					   "Querying UN");
					fp(out,
					   "   %-20s %-15s %-15s %4s %-8s %-8s\n",
					   "Prefix", "Registered VN",
					   "Registered UN", "Cost", "Lifetime",
#if RFAPI_REGISTRATIONS_REPORT_AGE
					   "Age"
#else
					   "Remaining"
#endif
					   );
				}
				if (!printednve) {
					char str_vn[BUFSIZ];
					char str_un[BUFSIZ];

					++printednve;
					++nves_displayed;

					fp(out, "%-15s %-15s\n",
					   rfapiRfapiIpAddr2Str(&rfd->vn_addr,
								str_vn, BUFSIZ),
					   rfapiRfapiIpAddr2Str(&rfd->un_addr,
								str_un,
								BUFSIZ));
				}
				prefix2str(&rn->p, str_pfx, sizeof(str_pfx));
				// fp(out, "  %s\n", buf);  /* prefix */

				routes_displayed++;
				nhs_displayed += print_rib_sl(
					fp, vty, out, sl, show_removed, str_pfx,
					&printedprefix);
			}
		}
	}

	if (routes_total) {
		fp(out, "\n");
		fp(out, "Displayed %u NVEs, and %u out of %u %s prefixes",
		   nves_displayed, routes_displayed, routes_total,
		   show_removed ? "removed" : "active");
		if (nhs_displayed != routes_displayed
		    || nhs_total != routes_total)
			fp(out, " with %u out of %u next hops", nhs_displayed,
			   nhs_total);
		fp(out, "\n");
	}
}
