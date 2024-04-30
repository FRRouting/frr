// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_lsp.c
 *                             LSP processing
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 * Copyright (C) 2013-2015   Christian Franke <chris@opensourcerouting.org>
 */

#include <zebra.h>

#include "linklist.h"
#include "frrevent.h"
#include "vty.h"
#include "stream.h"
#include "memory.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "hash.h"
#include "if.h"
#include "checksum.h"
#include "md5.h"
#include "table.h"
#include "srcdest_table.h"
#include "lib_errors.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_te.h"
#include "isisd/isis_sr.h"
#include "isisd/fabricd.h"
#include "isisd/isis_tx_queue.h"
#include "isisd/isis_nb.h"
#include "isisd/isis_flex_algo.h"

DEFINE_MTYPE_STATIC(ISISD, ISIS_LSP, "ISIS LSP");

static void lsp_refresh(struct event *thread);
static void lsp_l1_refresh_pseudo(struct event *thread);
static void lsp_l2_refresh_pseudo(struct event *thread);

static void lsp_destroy(struct isis_lsp *lsp);

static bool device_startup;

int lsp_id_cmp(uint8_t *id1, uint8_t *id2)
{
	return memcmp(id1, id2, ISIS_SYS_ID_LEN + 2);
}

int lspdb_compare(const struct isis_lsp *a, const struct isis_lsp *b)
{
	return memcmp(a->hdr.lsp_id, b->hdr.lsp_id, sizeof(a->hdr.lsp_id));
}

void lsp_db_init(struct lspdb_head *head)
{
	lspdb_init(head);
}

void lsp_db_fini(struct lspdb_head *head)
{
	struct isis_lsp *lsp;

	while ((lsp = lspdb_pop(head)))
		lsp_destroy(lsp);
	lspdb_fini(head);
}

struct isis_lsp *lsp_search(struct lspdb_head *head, const uint8_t *id)
{
	struct isis_lsp searchfor;
	memcpy(searchfor.hdr.lsp_id, id, sizeof(searchfor.hdr.lsp_id));

	return lspdb_find(head, &searchfor);
}

static void lsp_clear_data(struct isis_lsp *lsp)
{
	if (!lsp)
		return;

	isis_free_tlvs(lsp->tlvs);
	lsp->tlvs = NULL;
}

static void lsp_remove_frags(struct lspdb_head *head, struct list *frags);

static void lsp_destroy(struct isis_lsp *lsp)
{
	struct listnode *cnode;
	struct isis_circuit *circuit;

	if (!lsp)
		return;

	for (ALL_LIST_ELEMENTS_RO(lsp->area->circuit_list, cnode, circuit))
		isis_tx_queue_del(circuit->tx_queue, lsp);

	ISIS_FLAGS_CLEAR_ALL(lsp->SSNflags);

	isis_te_lsp_event(lsp, LSP_DEL);

	lsp_clear_data(lsp);

	if (!LSP_FRAGMENT(lsp->hdr.lsp_id)) {
		if (lsp->lspu.frags) {
			lsp_remove_frags(&lsp->area->lspdb[lsp->level - 1],
					lsp->lspu.frags);
			list_delete(&lsp->lspu.frags);
		}
	} else {
		if (lsp->lspu.zero_lsp
		    && lsp->lspu.zero_lsp->lspu.frags) {
			listnode_delete(lsp->lspu.zero_lsp->lspu.frags, lsp);
		}
	}

	isis_spf_schedule(lsp->area, lsp->level);

	if (lsp->pdu)
		stream_free(lsp->pdu);

	fabricd_lsp_free(lsp);
	XFREE(MTYPE_ISIS_LSP, lsp);
}

/*
 * Remove all the frags belonging to the given lsp
 */
static void lsp_remove_frags(struct lspdb_head *head, struct list *frags)
{
	struct listnode *lnode, *lnnode;
	struct isis_lsp *lsp;

	for (ALL_LIST_ELEMENTS(frags, lnode, lnnode, lsp)) {
		lsp = lsp_search(head, lsp->hdr.lsp_id);
		lspdb_del(head, lsp);
		lsp_destroy(lsp);
	}
}

void lsp_search_and_destroy(struct lspdb_head *head, const uint8_t *id)
{
	struct isis_lsp *lsp;

	lsp = lsp_search(head, id);
	if (lsp) {
		lspdb_del(head, lsp);
		/*
		 * If this is a zero lsp, remove all the frags now
		 */
		if (LSP_FRAGMENT(lsp->hdr.lsp_id) == 0) {
			if (lsp->lspu.frags)
				lsp_remove_frags(head, lsp->lspu.frags);
		} else {
			/*
			 * else just remove this frag, from the zero lsps' frag
			 * list
			 */
			if (lsp->lspu.zero_lsp
			    && lsp->lspu.zero_lsp->lspu.frags)
				listnode_delete(lsp->lspu.zero_lsp->lspu.frags,
						lsp);
		}
		lsp_destroy(lsp);
	}
}

/*
 * Compares a LSP to given values
 * Params are given in net order
 */
int lsp_compare(char *areatag, struct isis_lsp *lsp, uint32_t seqno,
		uint16_t checksum, uint16_t rem_lifetime)
{
	if (lsp->hdr.seqno == seqno && lsp->hdr.checksum == checksum
	    && ((lsp->hdr.rem_lifetime == 0 && rem_lifetime == 0)
		|| (lsp->hdr.rem_lifetime != 0 && rem_lifetime != 0))) {
		if (IS_DEBUG_SNP_PACKETS) {
			zlog_debug(
				"ISIS-Snp (%s): Compare LSP %pLS seq 0x%08x, cksum 0x%04hx, lifetime %hus",
				areatag, lsp->hdr.lsp_id, lsp->hdr.seqno,
				lsp->hdr.checksum, lsp->hdr.rem_lifetime);
			zlog_debug(
				"ISIS-Snp (%s):         is equal to ours seq 0x%08x, cksum 0x%04hx, lifetime %hus",
				areatag, seqno, checksum, rem_lifetime);
		}
		return LSP_EQUAL;
	}

	/*
	 * LSPs with identical checksums should only be treated as newer if:
	 * a) The current LSP has a remaining lifetime != 0 and the other LSP
	 * has a
	 *    remaining lifetime == 0. In this case, we should participate in
	 * the purge
	 *    and should not treat the current LSP with remaining lifetime == 0
	 * as older.
	 * b) The LSP has an incorrect checksum. In this case, we need to react
	 * as given
	 *    in 7.3.16.2.
	 */
	if (seqno > lsp->hdr.seqno
	    || (seqno == lsp->hdr.seqno
		&& ((lsp->hdr.rem_lifetime != 0 && rem_lifetime == 0)
		    || (lsp->hdr.checksum != checksum
			&& lsp->hdr.rem_lifetime)))) {
		if (IS_DEBUG_SNP_PACKETS) {
			zlog_debug(
				"ISIS-Snp (%s): Compare LSP %pLS seq 0x%08x, cksum 0x%04hx, lifetime %hus",
				areatag, lsp->hdr.lsp_id, seqno, checksum,
				rem_lifetime);
			zlog_debug(
				"ISIS-Snp (%s):       is newer than ours seq 0x%08x, cksum 0x%04hx, lifetime %hus",
				areatag, lsp->hdr.seqno, lsp->hdr.checksum,
				lsp->hdr.rem_lifetime);
		}
		return LSP_NEWER;
	}
	if (IS_DEBUG_SNP_PACKETS) {
		zlog_debug(
			"ISIS-Snp (%s): Compare LSP %pLS seq 0x%08x, cksum 0x%04hx, lifetime %hus",
			areatag, lsp->hdr.lsp_id, seqno, checksum,
			rem_lifetime);
		zlog_debug(
			"ISIS-Snp (%s):       is older than ours seq 0x%08x, cksum 0x%04hx, lifetime %hus",
			areatag, lsp->hdr.seqno, lsp->hdr.checksum,
			lsp->hdr.rem_lifetime);
	}

	return LSP_OLDER;
}

static void put_lsp_hdr(struct isis_lsp *lsp, size_t *len_pointer, bool keep)
{
	uint8_t pdu_type =
		(lsp->level == IS_LEVEL_1) ? L1_LINK_STATE : L2_LINK_STATE;
	struct isis_lsp_hdr *hdr = &lsp->hdr;
	struct stream *stream = lsp->pdu;
	size_t orig_getp = 0, orig_endp = 0;

	if (keep) {
		orig_getp = stream_get_getp(lsp->pdu);
		orig_endp = stream_get_endp(lsp->pdu);
	}

	stream_set_getp(lsp->pdu, 0);
	stream_set_endp(lsp->pdu, 0);

	fill_fixed_hdr(pdu_type, stream);

	if (len_pointer)
		*len_pointer = stream_get_endp(stream);
	stream_putw(stream, hdr->pdu_len);
	stream_putw(stream, hdr->rem_lifetime);
	stream_put(stream, hdr->lsp_id, sizeof(hdr->lsp_id));
	stream_putl(stream, hdr->seqno);
	stream_putw(stream, hdr->checksum);
	stream_putc(stream, hdr->lsp_bits);

	if (keep) {
		stream_set_endp(lsp->pdu, orig_endp);
		stream_set_getp(lsp->pdu, orig_getp);
	}
}

static void lsp_add_auth(struct isis_lsp *lsp)
{
	struct isis_passwd *passwd;
	passwd = (lsp->level == IS_LEVEL_1) ? &lsp->area->area_passwd
					    : &lsp->area->domain_passwd;
	isis_tlvs_add_auth(lsp->tlvs, passwd);
}

static void lsp_pack_pdu(struct isis_lsp *lsp)
{
	if (!lsp->tlvs)
		lsp->tlvs = isis_alloc_tlvs();

	lsp_add_auth(lsp);

	size_t len_pointer;
	put_lsp_hdr(lsp, &len_pointer, false);
	isis_pack_tlvs(lsp->tlvs, lsp->pdu, len_pointer, false, true);

	lsp->hdr.pdu_len = stream_get_endp(lsp->pdu);
	lsp->hdr.checksum =
		ntohs(fletcher_checksum(STREAM_DATA(lsp->pdu) + 12,
					stream_get_endp(lsp->pdu) - 12, 12));
}

void lsp_inc_seqno(struct isis_lsp *lsp, uint32_t seqno)
{
	uint32_t newseq;

	if (seqno == 0 || lsp->hdr.seqno > seqno)
		newseq = lsp->hdr.seqno + 1;
	else
		newseq = seqno + 1;

#ifndef FABRICD
	/* check for overflow */
	if (newseq < lsp->hdr.seqno) {
		/* send northbound notification */
		lsp->area->lsp_exceeded_max_counter++;
		isis_notif_lsp_exceed_max(lsp->area, lsp->hdr.lsp_id);
	}
#endif /* ifndef FABRICD */

	lsp->hdr.seqno = newseq;

	lsp_pack_pdu(lsp);
	isis_spf_schedule(lsp->area, lsp->level);
	isis_te_lsp_event(lsp, LSP_INC);
}

static void lsp_purge_add_poi(struct isis_lsp *lsp,
			      const uint8_t *sender)
{
	if (lsp->area == NULL)
		return;

	if (!lsp->area->purge_originator)
		return;

	/* add purge originator identification */
	if (!lsp->tlvs)
		lsp->tlvs = isis_alloc_tlvs();
	isis_tlvs_set_purge_originator(lsp->tlvs, lsp->area->isis->sysid,
				       sender);
	isis_tlvs_set_dynamic_hostname(lsp->tlvs, cmd_hostname_get());
}

static void lsp_purge(struct isis_lsp *lsp, int level,
		      const uint8_t *sender)
{
	/* reset stream */
	lsp_clear_data(lsp);
	stream_reset(lsp->pdu);

	/* update header */
	lsp->hdr.checksum = 0;
	lsp->hdr.rem_lifetime = 0;
	lsp->level = level;
	lsp->age_out = lsp->area->max_lsp_lifetime[level - 1];
	lsp->area->lsp_purge_count[level - 1]++;

	lsp_purge_add_poi(lsp, sender);

	lsp_pack_pdu(lsp);
	lsp_flood(lsp, NULL);
}

/*
 * Generates checksum for LSP and its frags
 */
static void lsp_seqno_update(struct isis_lsp *lsp0)
{
	struct isis_lsp *lsp;
	struct listnode *node;

	lsp_inc_seqno(lsp0, 0);

	if (!lsp0->lspu.frags)
		return;

	for (ALL_LIST_ELEMENTS_RO(lsp0->lspu.frags, node, lsp)) {
		if (lsp->tlvs)
			lsp_inc_seqno(lsp, 0);
		else if (lsp->hdr.rem_lifetime) {
			/* Purge should only be applied when the fragment has
			 * non-zero remaining lifetime.
			 */
			lsp_purge(lsp, lsp0->level, NULL);
		}
	}

	return;
}

bool isis_level2_adj_up(struct isis_area *area)
{
	struct listnode *node, *cnode;
	struct isis_circuit *circuit;
	struct list *adjdb;
	struct isis_adjacency *adj;

	if (area->is_type == IS_LEVEL_1)
		return false;

	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit)) {
		if (circuit->circ_type == CIRCUIT_T_BROADCAST) {
			adjdb = circuit->u.bc.adjdb[1];
			if (!adjdb || !adjdb->count)
				continue;

			for (ALL_LIST_ELEMENTS_RO(adjdb, node, adj)) {
				if (adj->level != ISIS_ADJ_LEVEL1
				    && adj->adj_state == ISIS_ADJ_UP)
					return true;
			}
		} else if (circuit->circ_type == CIRCUIT_T_P2P
			   && circuit->u.p2p.neighbor) {
			adj = circuit->u.p2p.neighbor;
			if (adj->level != ISIS_ADJ_LEVEL1
			    && adj->adj_state == ISIS_ADJ_UP)
				return true;
		}
	}

	return false;
}

/*
 * Unset the overload bit after the timer expires
 */
void set_overload_on_start_timer(struct event *thread)
{
	struct isis_area *area = EVENT_ARG(thread);
	assert(area);

	area->t_overload_on_startup_timer = NULL;

	/* Check if set-overload-bit is not currently configured */
	if (!area->overload_configured)
		isis_area_overload_bit_set(area, false);
}

static void isis_reset_attach_bit(struct isis_adjacency *adj)
{
	struct isis_area *area = adj->circuit->area;
	struct lspdb_head *head;
	struct isis_lsp *lsp;
	uint8_t lspid[ISIS_SYS_ID_LEN + 2];

	/*
	 * If an L2 adjacency changed its state in L-1-2 area, we have to:
	 * - set the attached bit in L1 LSPs if it's the first L2 adjacency
	 * - remove the attached bit in L1 LSPs if it's the last L2 adjacency
	 */

	if (area->is_type != IS_LEVEL_1_AND_2 || adj->level == ISIS_ADJ_LEVEL1)
		return;

	if (!area->attached_bit_send)
		return;

	head = &area->lspdb[IS_LEVEL_1 - 1];
	memset(lspid, 0, ISIS_SYS_ID_LEN + 2);
	memcpy(lspid, area->isis->sysid, ISIS_SYS_ID_LEN);

	lsp = lsp_search(head, lspid);
	if (!lsp)
		return;

	if (adj->adj_state == ISIS_ADJ_UP
	    && !(lsp->hdr.lsp_bits & LSPBIT_ATT)) {
		sched_debug("ISIS (%s): adj going up regenerate lsp-bits",
			    area->area_tag);
		lsp_regenerate_schedule(area, IS_LEVEL_1, 0);
	} else if (adj->adj_state == ISIS_ADJ_DOWN
		   && (lsp->hdr.lsp_bits & LSPBIT_ATT)
		   && !isis_level2_adj_up(area)) {
		sched_debug("ISIS (%s): adj going down regenerate lsp-bits",
			    area->area_tag);
		lsp_regenerate_schedule(area, IS_LEVEL_1, 0);
	}
}

static uint8_t lsp_bits_generate(int level, int overload_bit, int attached_bit,
				 struct isis_area *area)
{
	uint8_t lsp_bits = 0;
	if (area->is_type == IS_LEVEL_1)
		lsp_bits = IS_LEVEL_1;
	else
		lsp_bits = IS_LEVEL_1_AND_2;
	if (overload_bit)
		lsp_bits |= overload_bit;

	/* only set the attach bit if we are a level-1-2 router and this is
	 * a level-1 LSP and we have a level-2 adjacency up from another area
	 */
	if (area->is_type == IS_LEVEL_1_AND_2 && level == IS_LEVEL_1
	    && attached_bit && isis_level2_adj_up(area))
		lsp_bits |= LSPBIT_ATT;
	return lsp_bits;
}

static void lsp_update_data(struct isis_lsp *lsp, struct isis_lsp_hdr *hdr,
			    struct isis_tlvs *tlvs, struct stream *stream,
			    struct isis_area *area, int level)
{
	/* free the old lsp data */
	lsp_clear_data(lsp);

	/* copying only the relevant part of our stream */
	if (lsp->pdu != NULL)
		stream_free(lsp->pdu);
	lsp->pdu = stream_dup(stream);

	memcpy(&lsp->hdr, hdr, sizeof(lsp->hdr));
	lsp->area = area;
	lsp->level = level;
	lsp->age_out = ZERO_AGE_LIFETIME;
	lsp->installed = time(NULL);

	lsp->tlvs = tlvs;

	if (area->dynhostname && lsp->tlvs->hostname
	    && lsp->hdr.rem_lifetime) {
		isis_dynhn_insert(
			area->isis, lsp->hdr.lsp_id, lsp->tlvs->hostname,
			(lsp->hdr.lsp_bits & LSPBIT_IST) == IS_LEVEL_1_AND_2
				? IS_LEVEL_2
				: IS_LEVEL_1);
	}

	return;
}

static void lsp_link_fragment(struct isis_lsp *lsp, struct isis_lsp *lsp0)
{
	if (!LSP_FRAGMENT(lsp->hdr.lsp_id)) {
		/* zero lsp -> create list to store fragments */
		lsp->lspu.frags = list_new();
	} else {
		/* fragment -> set backpointer and add to zero lsps list */
		assert(lsp0);
		lsp->lspu.zero_lsp = lsp0;
		listnode_add(lsp0->lspu.frags, lsp);
	}
}

void lsp_update(struct isis_lsp *lsp, struct isis_lsp_hdr *hdr,
		struct isis_tlvs *tlvs, struct stream *stream,
		struct isis_area *area, int level, bool confusion)
{
	if (lsp->own_lsp) {
		flog_err(
			EC_LIB_DEVELOPMENT,
			"ISIS-Upd (%s): BUG updating LSP %pLS still marked as own LSP",
			area->area_tag, lsp->hdr.lsp_id);
		lsp_clear_data(lsp);
		lsp->own_lsp = 0;
	}

	if (confusion) {
		lsp_purge(lsp, level, NULL);
	} else {
		lsp_update_data(lsp, hdr, tlvs, stream, area, level);
	}

	if (LSP_FRAGMENT(lsp->hdr.lsp_id) && !lsp->lspu.zero_lsp) {
		uint8_t lspid[ISIS_SYS_ID_LEN + 2];
		struct isis_lsp *lsp0;

		memcpy(lspid, lsp->hdr.lsp_id, ISIS_SYS_ID_LEN + 1);
		LSP_FRAGMENT(lspid) = 0;
		lsp0 = lsp_search(&area->lspdb[level - 1], lspid);
		if (lsp0)
			lsp_link_fragment(lsp, lsp0);
	}

	if (lsp->hdr.seqno) {
		isis_spf_schedule(lsp->area, lsp->level);
		isis_te_lsp_event(lsp, LSP_UPD);
	}
}

/* creation of LSP directly from what we received */
struct isis_lsp *lsp_new_from_recv(struct isis_lsp_hdr *hdr,
				   struct isis_tlvs *tlvs,
				   struct stream *stream, struct isis_lsp *lsp0,
				   struct isis_area *area, int level)
{
	struct isis_lsp *lsp;

	lsp = XCALLOC(MTYPE_ISIS_LSP, sizeof(struct isis_lsp));
	lsp_update_data(lsp, hdr, tlvs, stream, area, level);
	lsp_link_fragment(lsp, lsp0);

	return lsp;
}

static void lsp_adjust_stream(struct isis_lsp *lsp)
{
	if (lsp->pdu) {
		if (STREAM_SIZE(lsp->pdu) == LLC_LEN + lsp->area->lsp_mtu)
			return;
		stream_free(lsp->pdu);
	}

	lsp->pdu = stream_new(LLC_LEN + lsp->area->lsp_mtu);
}

struct isis_lsp *lsp_new(struct isis_area *area, uint8_t *lsp_id,
			 uint16_t rem_lifetime, uint32_t seqno,
			 uint8_t lsp_bits, uint16_t checksum,
			 struct isis_lsp *lsp0, int level)
{
	struct isis_lsp *lsp;

	lsp = XCALLOC(MTYPE_ISIS_LSP, sizeof(struct isis_lsp));
	lsp->area = area;

	lsp_adjust_stream(lsp);

	/* Minimal LSP PDU size */
	lsp->hdr.pdu_len = ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN;
	memcpy(lsp->hdr.lsp_id, lsp_id, sizeof(lsp->hdr.lsp_id));
	lsp->hdr.checksum = checksum;
	lsp->hdr.seqno = seqno;
	lsp->hdr.rem_lifetime = rem_lifetime;
	lsp->hdr.lsp_bits = lsp_bits;
	lsp->level = level;
	lsp->age_out = ZERO_AGE_LIFETIME;
	lsp_link_fragment(lsp, lsp0);
	put_lsp_hdr(lsp, NULL, false);

	if (IS_DEBUG_EVENTS)
		zlog_debug("New LSP with ID %pLS len %d seqnum %08x", lsp_id,
			   lsp->hdr.pdu_len, lsp->hdr.seqno);

	return lsp;
}

void lsp_insert(struct lspdb_head *head, struct isis_lsp *lsp)
{
	lspdb_add(head, lsp);
	if (lsp->hdr.seqno) {
		isis_spf_schedule(lsp->area, lsp->level);
		isis_te_lsp_event(lsp, LSP_ADD);
	}
}

/*
 * Build a list of LSPs with non-zero ht and seqno bounded by start and stop ids
 */
void lsp_build_list_nonzero_ht(struct lspdb_head *head, const uint8_t *start_id,
			       const uint8_t *stop_id, struct list *list)
{
	struct isis_lsp searchfor;
	struct isis_lsp *lsp, *start;

	memcpy(&searchfor.hdr.lsp_id, start_id, sizeof(searchfor.hdr.lsp_id));

	start = lspdb_find_gteq(head, &searchfor);
	frr_each_from (lspdb, head, lsp, start) {
		if (memcmp(lsp->hdr.lsp_id, stop_id,
			   ISIS_SYS_ID_LEN + 2) > 0)
			break;

		if (lsp->hdr.rem_lifetime && lsp->hdr.seqno)
			listnode_add(list, lsp);
	}
}

static void lsp_set_time(struct isis_lsp *lsp)
{
	assert(lsp);

	if (lsp->hdr.rem_lifetime == 0) {
		if (lsp->age_out > 0)
			lsp->age_out--;
		return;
	}

	lsp->hdr.rem_lifetime--;
	if (lsp->pdu && stream_get_endp(lsp->pdu) >= 12)
		stream_putw_at(lsp->pdu, 10, lsp->hdr.rem_lifetime);
}

void lspid_print(uint8_t *lsp_id, char *dest, size_t dest_len, char dynhost,
		 char frag, struct isis *isis)
{
	struct isis_dynhn *dyn = NULL;
	char id[SYSID_STRLEN];

	if (dynhost)
		dyn = dynhn_find_by_id(isis, lsp_id);
	else
		dyn = NULL;

	if (dyn)
		snprintf(id, sizeof(id), "%.14s", dyn->hostname);
	else if (!memcmp(isis->sysid, lsp_id, ISIS_SYS_ID_LEN) && dynhost)
		snprintf(id, sizeof(id), "%.14s", cmd_hostname_get());
	else
		snprintfrr(id, sizeof(id), "%pSY", lsp_id);

	if (frag)
		snprintf(dest, dest_len, "%s.%02x-%02x", id,
			 LSP_PSEUDO_ID(lsp_id), LSP_FRAGMENT(lsp_id));
	else
		snprintf(dest, dest_len, "%s.%02x", id, LSP_PSEUDO_ID(lsp_id));
}

/* Convert the lsp attribute bits to attribute string */
static const char *lsp_bits2string(uint8_t lsp_bits, char *buf, size_t buf_size)
{
	char *pos = buf;

	if (!lsp_bits)
		return " none";

	if (buf_size < 2 * 3)
		return " error";

	/* we only focus on the default metric */
	pos += snprintf(pos, buf_size, "%d/",
			ISIS_MASK_LSP_ATT_BITS(lsp_bits) ? 1 : 0);

	pos += snprintf(pos, buf_size, "%d/",
			ISIS_MASK_LSP_PARTITION_BIT(lsp_bits) ? 1 : 0);

	snprintf(pos, buf_size, "%d", ISIS_MASK_LSP_OL_BIT(lsp_bits) ? 1 : 0);

	return buf;
}

/* this function prints the lsp on show isis database */
void lsp_print_common(struct isis_lsp *lsp, struct vty *vty, struct json_object *json,
	       char dynhost, struct isis *isis)
{
	if (json) {
		return lsp_print_json(lsp, json, dynhost, isis);
	} else {
		return lsp_print_vty(lsp, vty, dynhost, isis);
	}
}

void lsp_print_json(struct isis_lsp *lsp, struct json_object *json,
	       char dynhost, struct isis *isis)
{
	char LSPid[255];
	char age_out[8];
	char b[200];
	json_object *own_json;
	char buf[256];

	lspid_print(lsp->hdr.lsp_id, LSPid, sizeof(LSPid), dynhost, 1, isis);
	own_json = json_object_new_object();
	json_object_object_add(json, "lsp", own_json);
	json_object_string_add(own_json, "id", LSPid);
	json_object_string_add(own_json, "own", lsp->own_lsp ? "*" : " ");
	json_object_int_add(json, "pdu-len", lsp->hdr.pdu_len);
	snprintfrr(buf, sizeof(buf), "0x%08x", lsp->hdr.seqno);
	json_object_string_add(json, "seq-number", buf);
	snprintfrr(buf, sizeof(buf), "0x%04hx", lsp->hdr.checksum);
	json_object_string_add(json, "chksum", buf);
	if (lsp->hdr.rem_lifetime == 0) {
		snprintf(age_out, sizeof(age_out), "(%d)", lsp->age_out);
		age_out[7] = '\0';
		json_object_string_add(json, "holdtime", age_out);
	} else {
		json_object_int_add(json, "holdtime", lsp->hdr.rem_lifetime);
	}
	json_object_string_add(
		json, "att-p-ol", lsp_bits2string(lsp->hdr.lsp_bits, b, sizeof(b)));
}

void lsp_print_vty(struct isis_lsp *lsp, struct vty *vty,
	       char dynhost, struct isis *isis)
{
	char LSPid[255];
	char age_out[8];
	char b[200];

	lspid_print(lsp->hdr.lsp_id, LSPid, sizeof(LSPid), dynhost, 1, isis);
	vty_out(vty, "%-21s%c  ", LSPid, lsp->own_lsp ? '*' : ' ');
	vty_out(vty, "%5hu   ", lsp->hdr.pdu_len);
	vty_out(vty, "0x%08x  ", lsp->hdr.seqno);
	vty_out(vty, "0x%04hx  ", lsp->hdr.checksum);
	if (lsp->hdr.rem_lifetime == 0) {
		snprintf(age_out, sizeof(age_out), "(%d)", lsp->age_out);
		age_out[7] = '\0';
		vty_out(vty, "%7s   ", age_out);
	} else
		vty_out(vty, " %5hu    ", lsp->hdr.rem_lifetime);
	vty_out(vty, "%s\n", lsp_bits2string(lsp->hdr.lsp_bits, b, sizeof(b)));
}

void lsp_print_detail(struct isis_lsp *lsp, struct vty *vty,
			     struct json_object *json, char dynhost,
			     struct isis *isis)
{
	if (json) {
		lsp_print_json(lsp, json, dynhost, isis);
		if (lsp->tlvs) {
			isis_format_tlvs(lsp->tlvs, json);
		}
	} else {
		lsp_print_vty(lsp, vty, dynhost, isis);
		if (lsp->tlvs)
			vty_multiline(vty, "  ", "%s",
				      isis_format_tlvs(lsp->tlvs, NULL));
		vty_out(vty, "\n");
	}
}

/* print all the lsps info in the local lspdb */
int lsp_print_all(struct vty *vty, struct json_object *json,
		  struct lspdb_head *head, char detail, char dynhost,
		  struct isis *isis)
{
	struct isis_lsp *lsp;
	int lsp_count = 0;

	if (detail == ISIS_UI_LEVEL_BRIEF) {
		frr_each (lspdb, head, lsp) {
			lsp_print_common(lsp, vty, json, dynhost, isis);
			lsp_count++;
		}
	} else if (detail == ISIS_UI_LEVEL_DETAIL) {
		frr_each (lspdb, head, lsp) {
			lsp_print_detail(lsp, vty, json, dynhost, isis);
			lsp_count++;
		}
	}

	return lsp_count;
}

static uint16_t lsp_rem_lifetime(struct isis_area *area, int level)
{
	uint16_t rem_lifetime;

	/* Add jitter to configured LSP lifetime */
	rem_lifetime =
		isis_jitter(area->max_lsp_lifetime[level - 1], MAX_AGE_JITTER);

	/* No jitter if the max refresh will be less than configure gen interval
	 */
	/* N.B. this calucation is acceptable since rem_lifetime is in
	 * [332,65535] at
	 * this point */
	if (area->lsp_gen_interval[level - 1] > (rem_lifetime - 300))
		rem_lifetime = area->max_lsp_lifetime[level - 1];

	return rem_lifetime;
}

static uint16_t lsp_refresh_time(struct isis_lsp *lsp, uint16_t rem_lifetime)
{
	struct isis_area *area = lsp->area;
	int level = lsp->level;
	uint16_t refresh_time;

	/* Add jitter to LSP refresh time */
	refresh_time =
		isis_jitter(area->lsp_refresh[level - 1], MAX_LSP_GEN_JITTER);

	/* RFC 4444 : make sure the refresh time is at least less than 300
	 * of the remaining lifetime and more than gen interval */
	if (refresh_time <= area->lsp_gen_interval[level - 1]
	    || refresh_time > (rem_lifetime - 300))
		refresh_time = rem_lifetime - 300;

	/* In cornercases, refresh_time might be <= lsp_gen_interval, however
	 * we accept this violation to satisfy refresh_time <= rem_lifetime -
	 * 300 */

	return refresh_time;
}

static void lsp_build_internal_reach_ipv4(struct isis_lsp *lsp,
					  struct isis_area *area,
					  struct prefix_ipv4 *ipv4,
					  uint32_t metric)
{
	struct sr_prefix_cfg *pcfgs[SR_ALGORITHM_COUNT] = {NULL};

	if (area->oldmetric) {
		lsp_debug(
			"ISIS (%s): Adding old-style IP reachability for %pFX",
			area->area_tag, ipv4);
		isis_tlvs_add_oldstyle_ip_reach(lsp->tlvs, ipv4, metric);
	}

	if (area->newmetric) {
		lsp_debug("ISIS (%s): Adding te-style IP reachability for %pFX",
			  area->area_tag, ipv4);

		if (area->srdb.enabled)
			for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
#ifndef FABRICD
				if (flex_algo_id_valid(i) &&
				    !isis_flex_algo_elected_supported(i, area))
					continue;
#endif /* ifndef FABRICD */
				pcfgs[i] =
					isis_sr_cfg_prefix_find(area, ipv4, i);
			}

		isis_tlvs_add_extended_ip_reach(lsp->tlvs, ipv4, metric, false,
						pcfgs);
	}
}

static void lsp_build_internal_reach_ipv6(struct isis_lsp *lsp,
					  struct isis_area *area,
					  struct prefix_ipv6 *ipv6,
					  uint32_t metric)
{
	struct sr_prefix_cfg *pcfgs[SR_ALGORITHM_COUNT] = {NULL};

	lsp_debug("ISIS (%s): Adding IPv6 reachability for %pFX",
		  area->area_tag, ipv6);

	if (area->srdb.enabled)
		for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
#ifndef FABRICD
			if (flex_algo_id_valid(i) &&
			    !isis_flex_algo_elected_supported(i, area))
				continue;
#endif /* ifndef FABRICD */
			pcfgs[i] = isis_sr_cfg_prefix_find(area, ipv6, i);
		}

	isis_tlvs_add_ipv6_reach(lsp->tlvs, isis_area_ipv6_topology(area), ipv6,
				 metric, false, pcfgs);
}


static void lsp_build_ext_reach_ipv4(struct isis_lsp *lsp,
				     struct isis_area *area)
{
	struct route_table *er_table = get_ext_reach(area, AF_INET, lsp->level);
	if (!er_table)
		return;

	for (struct route_node *rn = route_top(er_table); rn;
	     rn = route_next(rn)) {
		if (!rn->info)
			continue;

		struct prefix_ipv4 *ipv4 = (struct prefix_ipv4 *)&rn->p;
		struct isis_ext_info *info = rn->info;

		uint32_t metric = info->metric;
		if (metric > MAX_WIDE_PATH_METRIC)
			metric = MAX_WIDE_PATH_METRIC;
		if (area->oldmetric && metric > 0x3f)
			metric = 0x3f;

		if (area->oldmetric)
			isis_tlvs_add_oldstyle_ip_reach(lsp->tlvs, ipv4,
							metric);
		if (area->newmetric) {
			struct sr_prefix_cfg *pcfgs[SR_ALGORITHM_COUNT] = {
				NULL};

			if (area->srdb.enabled)
				for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
#ifndef FABRICD
					if (flex_algo_id_valid(i) &&
					    !isis_flex_algo_elected_supported(
						    i, area))
						continue;
#endif /* ifndef FABRICD */
					pcfgs[i] = isis_sr_cfg_prefix_find(
						area, ipv4, i);
				}

			isis_tlvs_add_extended_ip_reach(lsp->tlvs, ipv4, metric,
							true, pcfgs);
		}
	}
}

static void lsp_build_ext_reach_ipv6(struct isis_lsp *lsp,
				     struct isis_area *area)
{
	struct route_table *er_table =
		get_ext_reach(area, AF_INET6, lsp->level);
	if (!er_table)
		return;

	for (struct route_node *rn = route_top(er_table); rn;
	     rn = srcdest_route_next(rn)) {
		if (!rn->info)
			continue;
		struct isis_ext_info *info = rn->info;
		struct prefix_ipv6 *p, *src_p;

		srcdest_rnode_prefixes(rn, (const struct prefix **)&p,
				       (const struct prefix **)&src_p);

		uint32_t metric = info->metric;
		if (info->metric > MAX_WIDE_PATH_METRIC)
			metric = MAX_WIDE_PATH_METRIC;

		if (!src_p || !src_p->prefixlen) {
			struct sr_prefix_cfg *pcfgs[SR_ALGORITHM_COUNT] = {
				NULL};

			if (area->srdb.enabled)
				for (int i = 0; i < SR_ALGORITHM_COUNT; i++) {
#ifndef FABRICD
					if (flex_algo_id_valid(i) &&
					    !isis_flex_algo_elected_supported(
						    i, area))
						continue;
#endif /* ifndef FABRICD */
					pcfgs[i] = isis_sr_cfg_prefix_find(
						area, p, i);
				}

			isis_tlvs_add_ipv6_reach(lsp->tlvs,
						 isis_area_ipv6_topology(area),
						 p, metric, true, pcfgs);
		} else if (isis_area_ipv6_dstsrc_enabled(area)) {
			isis_tlvs_add_ipv6_dstsrc_reach(lsp->tlvs,
							ISIS_MT_IPV6_DSTSRC,
							p, src_p, metric);
		}
	}
}

static void lsp_build_ext_reach(struct isis_lsp *lsp, struct isis_area *area)
{
	lsp_build_ext_reach_ipv4(lsp, area);
	lsp_build_ext_reach_ipv6(lsp, area);
}

static struct isis_lsp *lsp_next_frag(uint8_t frag_num, struct isis_lsp *lsp0,
				      struct isis_area *area, int level)
{
	struct isis_lsp *lsp;
	uint8_t frag_id[ISIS_SYS_ID_LEN + 2];

	memcpy(frag_id, lsp0->hdr.lsp_id, ISIS_SYS_ID_LEN + 1);
	LSP_FRAGMENT(frag_id) = frag_num;

	lsp = lsp_search(&area->lspdb[level - 1], frag_id);
	if (lsp) {
		lsp_clear_data(lsp);
		if (!lsp->lspu.zero_lsp)
			lsp_link_fragment(lsp, lsp0);
		return lsp;
	}

	lsp = lsp_new(area, frag_id, lsp0->hdr.rem_lifetime, 0,
		      lsp_bits_generate(level, area->overload_bit,
					area->attached_bit_send, area),
		      0, lsp0, level);
	lsp->own_lsp = 1;
	lsp_insert(&area->lspdb[level - 1], lsp);
	return lsp;
}

/*
 * Builds the LSP data part. This func creates a new frag whenever
 * area->lsp_frag_threshold is exceeded.
 */
static void lsp_build(struct isis_lsp *lsp, struct isis_area *area)
{
	int level = lsp->level;
	struct listnode *node;
	struct isis_lsp *frag;

	lsp_clear_data(lsp);
	for (ALL_LIST_ELEMENTS_RO(lsp->lspu.frags, node, frag))
		lsp_clear_data(frag);

	lsp->tlvs = isis_alloc_tlvs();
	lsp_debug("ISIS (%s): Constructing local system LSP for level %d",
		  area->area_tag, level);

	lsp->hdr.lsp_bits = lsp_bits_generate(level, area->overload_bit,
					      area->attached_bit_send, area);

	lsp_add_auth(lsp);

	isis_tlvs_add_area_addresses(lsp->tlvs, area->area_addrs);

	/* Protocols Supported */
	if (area->ip_circuits > 0 || area->ipv6_circuits > 0) {
		struct nlpids nlpids = {.count = 0};

		if (area->ip_circuits > 0) {
			lsp_debug(
				"ISIS (%s): Found IPv4 circuit, adding IPv4 to NLPIDs",
				area->area_tag);
			nlpids.nlpids[nlpids.count] = NLPID_IP;
			nlpids.count++;
		}
		if (area->ipv6_circuits > 0) {
			lsp_debug(
				"ISIS (%s): Found IPv6 circuit, adding IPv6 to NLPIDs",
				area->area_tag);
			nlpids.nlpids[nlpids.count] = NLPID_IPV6;
			nlpids.count++;
		}
		isis_tlvs_set_protocols_supported(lsp->tlvs, &nlpids);
	}

	if (area_is_mt(area)) {
		lsp_debug("ISIS (%s): Adding MT router tlv...", area->area_tag);

		struct isis_area_mt_setting **mt_settings;
		unsigned int mt_count;

		mt_settings = area_mt_settings(area, &mt_count);
		for (unsigned int i = 0; i < mt_count; i++) {
			isis_tlvs_add_mt_router_info(
				lsp->tlvs, mt_settings[i]->mtid,
				mt_settings[i]->overload, false);
			lsp_debug("ISIS (%s):   MT %s", area->area_tag,
				  isis_mtid2str(mt_settings[i]->mtid));
		}
	} else {
		lsp_debug("ISIS (%s): Not adding MT router tlv (disabled)",
			  area->area_tag);
	}
	/* Dynamic Hostname */
	if (area->dynhostname) {
		isis_tlvs_set_dynamic_hostname(lsp->tlvs, cmd_hostname_get());
		lsp_debug("ISIS (%s): Adding dynamic hostname '%s'",
			  area->area_tag, cmd_hostname_get());
	} else {
		lsp_debug("ISIS (%s): Not adding dynamic hostname (disabled)",
			  area->area_tag);
	}

	/* Add Router Capability TLV. */
	if (area->isis->router_id != 0) {
		struct isis_router_cap *rcap;
#ifndef FABRICD
		struct isis_router_cap_fad *rcap_fad;
		struct listnode *node;
		struct flex_algo *fa;
#endif /* ifndef FABRICD */

		rcap = isis_tlvs_init_router_capability(lsp->tlvs);

		rcap->router_id.s_addr = area->isis->router_id;

#ifndef FABRICD
		/* Set flex-algo definitions */
		for (ALL_LIST_ELEMENTS_RO(area->flex_algos->flex_algos, node,
					  fa)) {
			if (!fa->advertise_definition)
				continue;
			lsp_debug("ISIS (%s):   Flex-Algo Definition %u",
				  area->area_tag, fa->algorithm);
			isis_tlvs_set_router_capability_fad(lsp->tlvs, fa,
							    fa->algorithm,
							    area->isis->sysid);
		}
#endif /* ifndef FABRICD */

		/* Add SR Sub-TLVs if SR is enabled. */
		if (area->srdb.enabled) {
			struct isis_sr_db *srdb = &area->srdb;
			uint32_t range_size;

			/* SRGB first */
			range_size = srdb->config.srgb_upper_bound
				     - srdb->config.srgb_lower_bound + 1;
			rcap->srgb.flags = ISIS_SUBTLV_SRGB_FLAG_I |
					   ISIS_SUBTLV_SRGB_FLAG_V;
			rcap->srgb.range_size = range_size;
			rcap->srgb.lower_bound = srdb->config.srgb_lower_bound;
			/* Then Algorithm */
			rcap->algo[0] = SR_ALGORITHM_SPF;
			rcap->algo[1] = SR_ALGORITHM_UNSET;
#ifndef FABRICD
			for (ALL_LIST_ELEMENTS_RO(area->flex_algos->flex_algos,
						  node, fa)) {
				if (fa->advertise_definition)
					rcap_fad = rcap->fads[fa->algorithm];
				else
					rcap_fad = NULL;

				if (!isis_flex_algo_elected_supported_local_fad(
					    fa->algorithm, area, &rcap_fad)) {
					fa->state = false;
					continue;
				}
				fa->state = true;
				lsp_debug("ISIS (%s):   SR Algorithm %u",
					  area->area_tag, fa->algorithm);
				rcap->algo[fa->algorithm] = fa->algorithm;
			}
#endif /* ifndef FABRICD */
			/* SRLB */
			rcap->srlb.flags = 0;
			range_size = srdb->config.srlb_upper_bound
				     - srdb->config.srlb_lower_bound + 1;
			rcap->srlb.range_size = range_size;
			rcap->srlb.lower_bound = srdb->config.srlb_lower_bound;
			/* And finally MSD */
			rcap->msd = srdb->config.msd;
		}

		/* Add SRv6 Sub-TLVs if SRv6 is enabled */
		if (area->srv6db.config.enabled) {
			struct isis_srv6_db *srv6db = &area->srv6db;

			rcap->srv6_cap.is_srv6_capable = true;

			/* SRv6 flags */
			rcap->srv6_cap.flags = 0;

			/* And finally MSDs */
			rcap->srv6_msd.max_seg_left_msd =
				srv6db->config.max_seg_left_msd;
			rcap->srv6_msd.max_end_pop_msd =
				srv6db->config.max_end_pop_msd;
			rcap->srv6_msd.max_h_encaps_msd =
				srv6db->config.max_h_encaps_msd;
			rcap->srv6_msd.max_end_d_msd =
				srv6db->config.max_end_d_msd;
		} else {
			rcap->srv6_cap.is_srv6_capable = false;
		}
	}

	/* Add SRv6 Locator TLV. */
	if (area->srv6db.config.enabled &&
	    !list_isempty(area->srv6db.srv6_locator_chunks)) {
		struct isis_srv6_locator locator = {};
		struct srv6_locator_chunk *chunk;

		/* TODO: support more than one locator */
		chunk = (struct srv6_locator_chunk *)listgetdata(
			listhead(area->srv6db.srv6_locator_chunks));

		locator.metric = 0;
		locator.prefix = chunk->prefix;
		locator.flags = 0;
		locator.algorithm = 0;

		struct listnode *sid_node;
		struct isis_srv6_sid *sid;
		locator.srv6_sid = list_new();
		for (ALL_LIST_ELEMENTS_RO(area->srv6db.srv6_sids, sid_node,
					  sid)) {
			listnode_add(locator.srv6_sid, sid);
		}

		isis_tlvs_add_srv6_locator(lsp->tlvs, 0, &locator);
		lsp_debug("ISIS (%s): Adding SRv6 Locator information",
			  area->area_tag);

		list_delete(&locator.srv6_sid);

		isis_tlvs_add_ipv6_reach(lsp->tlvs,
					 isis_area_ipv6_topology(area),
					 &chunk->prefix, 0, false, NULL);
	}

	/* IPv4 address and TE router ID TLVs.
	 * In case of the first one we don't follow "C" vendor,
	 * but "J" vendor behavior - one IPv4 address is put
	 * into LSP. TE router ID will be the same if MPLS-TE
	 * is not activate or MPLS-TE router-id not specified
	 */
	if (area->isis->router_id != 0) {
		struct in_addr id = {.s_addr = area->isis->router_id};
		lsp_debug("ISIS (%s): Adding router ID %pI4 as IPv4 tlv.",
			  area->area_tag, &id);
		isis_tlvs_add_ipv4_address(lsp->tlvs, &id);

		/* If new style TLV's are in use, add TE router ID TLV
		 * Check if MPLS-TE is activate and mpls-te router-id set
		 * otherwise add exactly same data as for IPv4 address
		 */
		if (area->newmetric) {
			if (IS_MPLS_TE(area->mta)
			    && area->mta->router_id.s_addr != INADDR_ANY)
				id.s_addr = area->mta->router_id.s_addr;
			lsp_debug(
				"ISIS (%s): Adding router ID also as TE router ID tlv.",
				area->area_tag);
			isis_tlvs_set_te_router_id(lsp->tlvs, &id);
		}
	} else {
		lsp_debug("ISIS (%s): Router ID is unset. Not adding tlv.",
			  area->area_tag);
	}

	if (IS_MPLS_TE(area->mta)
	    && !IN6_IS_ADDR_UNSPECIFIED(&area->mta->router_id_ipv6)) {
		lsp_debug("ISIS (%s): Adding IPv6 TE Router ID tlv.",
			  area->area_tag);
		isis_tlvs_set_te_router_id_ipv6(lsp->tlvs,
						&area->mta->router_id_ipv6);
	}

	lsp_debug("ISIS (%s): Adding circuit specific information.",
		  area->area_tag);

	if (fabricd) {
		lsp_debug(
			"ISIS (%s): Adding tier %hhu spine-leaf-extension tlv.",
			area->area_tag, fabricd_tier(area));
		isis_tlvs_add_spine_leaf(lsp->tlvs, fabricd_tier(area), true,
					 false, false, false);
	}

	struct isis_circuit *circuit;
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		if (!circuit->interface)
			lsp_debug(
				"ISIS (%s): Processing %s circuit %p with unknown interface",
				area->area_tag,
				circuit_type2string(circuit->circ_type),
				circuit);
		else
			lsp_debug("ISIS (%s): Processing %s circuit %s",
				  area->area_tag,
				  circuit_type2string(circuit->circ_type),
				  circuit->interface->name);

		if (circuit->state != C_STATE_UP) {
			lsp_debug("ISIS (%s): Circuit is not up, ignoring.",
				  area->area_tag);
			continue;
		}

		if (area->advertise_passive_only && !circuit->is_passive) {
			lsp_debug(
				"ISIS (%s): Circuit is not passive, ignoring.",
				area->area_tag);
			continue;
		}

		uint32_t metric = area->oldmetric
					  ? circuit->metric[level - 1]
					  : circuit->te_metric[level - 1];

		if (circuit->ip_router && circuit->ip_addrs->count > 0) {
			lsp_debug(
				"ISIS (%s): Circuit has IPv4 active, adding respective TLVs.",
				area->area_tag);
			struct listnode *ipnode;
			struct prefix_ipv4 *ipv4;
			for (ALL_LIST_ELEMENTS_RO(circuit->ip_addrs, ipnode,
						  ipv4))
				lsp_build_internal_reach_ipv4(lsp, area, ipv4,
							      metric);
		}

		if (circuit->ipv6_router && circuit->ipv6_non_link->count > 0) {
			struct listnode *ipnode;
			struct prefix_ipv6 *ipv6;

			for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_non_link,
						  ipnode, ipv6))
				lsp_build_internal_reach_ipv6(lsp, area, ipv6,
							      metric);
		}

		switch (circuit->circ_type) {
		case CIRCUIT_T_BROADCAST:
			if (level & circuit->is_type) {
				uint8_t *ne_id =
					(level == IS_LEVEL_1)
						? circuit->u.bc.l1_desig_is
						: circuit->u.bc.l2_desig_is;

				if (LSP_PSEUDO_ID(ne_id)) {
					if (area->oldmetric) {
						lsp_debug(
							"ISIS (%s): Adding DIS %pPN as old-style neighbor",
							area->area_tag, ne_id);
						isis_tlvs_add_oldstyle_reach(
							lsp->tlvs, ne_id,
							metric);
					}
					if (area->newmetric)
						tlvs_add_mt_bcast(
							lsp->tlvs, circuit,
							level, ne_id, metric);
				}
			} else {
				lsp_debug(
					"ISIS (%s): Circuit is not active for current level. Not adding IS neighbors",
					area->area_tag);
			}
			break;
		case CIRCUIT_T_P2P: {
			struct isis_adjacency *nei = circuit->u.p2p.neighbor;
			if (nei && nei->adj_state == ISIS_ADJ_UP
			    && (level & nei->circuit_t)) {
				uint8_t ne_id[7];
				memcpy(ne_id, nei->sysid, ISIS_SYS_ID_LEN);
				LSP_PSEUDO_ID(ne_id) = 0;

				if (area->oldmetric) {
					lsp_debug(
						"ISIS (%s): Adding old-style is reach for %pSY",
						area->area_tag, ne_id);
					isis_tlvs_add_oldstyle_reach(
						lsp->tlvs, ne_id, metric);
				}
				if (area->newmetric) {
					uint32_t neighbor_metric;
					if (fabricd_tier(area) == 0) {
						neighbor_metric = 0xffe;
					} else {
						neighbor_metric = metric;
					}

					tlvs_add_mt_p2p(lsp->tlvs, circuit,
							ne_id, neighbor_metric);
				}
			} else {
				lsp_debug(
					"ISIS (%s): No adjacency for given level on this circuit. Not adding IS neighbors",
					area->area_tag);
			}
		} break;
		case CIRCUIT_T_LOOPBACK:
			break;
		default:
			zlog_warn("lsp_area_create: unknown circuit type");
		}
	}

	lsp_build_ext_reach(lsp, area);

	struct isis_tlvs *tlvs = lsp->tlvs;
	lsp->tlvs = NULL;

	lsp_adjust_stream(lsp);
	lsp_pack_pdu(lsp);
	size_t tlv_space = STREAM_WRITEABLE(lsp->pdu) - LLC_LEN;
	lsp_clear_data(lsp);

	struct list *fragments = isis_fragment_tlvs(tlvs, tlv_space);
	if (!fragments) {
		zlog_warn("BUG: could not fragment own LSP:");
		log_multiline(LOG_WARNING, "    ", "%s",
			      isis_format_tlvs(tlvs, NULL));
		isis_free_tlvs(tlvs);
		return;
	}
	isis_free_tlvs(tlvs);

	bool fragment_overflow = false;
	frag = lsp;
	for (ALL_LIST_ELEMENTS_RO(fragments, node, tlvs)) {
		if (node != listhead(fragments)) {
			if (LSP_FRAGMENT(frag->hdr.lsp_id) == 255) {
				if (!fragment_overflow) {
					fragment_overflow = true;
					zlog_warn(
						"ISIS (%s): Too much information for 256 fragments",
						area->area_tag);
				}
				isis_free_tlvs(tlvs);
				continue;
			}

			frag = lsp_next_frag(LSP_FRAGMENT(frag->hdr.lsp_id) + 1,
					     lsp, area, level);
			lsp_adjust_stream(frag);
		}
		frag->tlvs = tlvs;
	}

	list_delete(&fragments);
	lsp_debug("ISIS (%s): LSP construction is complete. Serializing...",
		  area->area_tag);
	return;
}

/*
 * 7.3.7 and 7.3.9 Generation on non-pseudonode LSPs
 */
int lsp_generate(struct isis_area *area, int level)
{
	struct isis_lsp *oldlsp, *newlsp;
	uint32_t seq_num = 0;
	uint8_t lspid[ISIS_SYS_ID_LEN + 2];
	uint16_t rem_lifetime, refresh_time;
	uint32_t overload_time;

	if ((area == NULL) || (area->is_type & level) != level)
		return ISIS_ERROR;

	/* Check if config is still being processed */
	if (event_is_scheduled(t_isis_cfg))
		return ISIS_OK;

	memset(&lspid, 0, ISIS_SYS_ID_LEN + 2);

	memcpy(&lspid, area->isis->sysid, ISIS_SYS_ID_LEN);

	/* Check if device should be overloaded on startup */
	if (device_startup) {
		overload_time = isis_restart_read_overload_time(area);
		if (overload_time > 0) {
			isis_area_overload_bit_set(area, true);
			event_add_timer(master, set_overload_on_start_timer,
					area, overload_time,
					&area->t_overload_on_startup_timer);
		}
		device_startup = false;
	}

	/* only builds the lsp if the area shares the level */
	oldlsp = lsp_search(&area->lspdb[level - 1], lspid);
	if (oldlsp) {
		/* FIXME: we should actually initiate a purge */
		seq_num = oldlsp->hdr.seqno;
		lsp_search_and_destroy(&area->lspdb[level - 1],
				       oldlsp->hdr.lsp_id);
	}
	rem_lifetime = lsp_rem_lifetime(area, level);
	newlsp = lsp_new(area, lspid, rem_lifetime, seq_num,
			 lsp_bits_generate(area->is_type, area->overload_bit,
					   area->attached_bit_send, area),
			 0, NULL, level);
	newlsp->area = area;
	newlsp->own_lsp = 1;

	lsp_insert(&area->lspdb[level - 1], newlsp);
	/* build_lsp_data (newlsp, area); */
	lsp_build(newlsp, area);
	/* time to calculate our checksum */
	lsp_seqno_update(newlsp);
	newlsp->last_generated = time(NULL);
	lsp_flood(newlsp, NULL);
	area->lsp_gen_count[level - 1]++;

	refresh_time = lsp_refresh_time(newlsp, rem_lifetime);

	EVENT_OFF(area->t_lsp_refresh[level - 1]);
	area->lsp_regenerate_pending[level - 1] = 0;
	event_add_timer(master, lsp_refresh, &area->lsp_refresh_arg[level - 1],
			refresh_time, &area->t_lsp_refresh[level - 1]);

	if (IS_DEBUG_UPDATE_PACKETS) {
		zlog_debug(
			"ISIS-Upd (%s): Building L%d LSP %pLS, len %hu, seq 0x%08x, cksum 0x%04hx, lifetime %hus refresh %hus",
			area->area_tag, level, newlsp->hdr.lsp_id,
			newlsp->hdr.pdu_len, newlsp->hdr.seqno,
			newlsp->hdr.checksum, newlsp->hdr.rem_lifetime,
			refresh_time);
	}
	sched_debug(
		"ISIS (%s): Built L%d LSP. Set triggered regenerate to non-pending.",
		area->area_tag, level);

#ifndef FABRICD
	/* send northbound notification */
	isis_notif_lsp_gen(area, newlsp->hdr.lsp_id, newlsp->hdr.seqno,
			   newlsp->last_generated);
#endif /* ifndef FABRICD */

	return ISIS_OK;
}

/*
 * Search own LSPs, update holding time and flood
 */
static int lsp_regenerate(struct isis_area *area, int level)
{
	struct lspdb_head *head;
	struct isis_lsp *lsp, *frag;
	struct listnode *node;
	uint8_t lspid[ISIS_SYS_ID_LEN + 2];
	uint16_t rem_lifetime, refresh_time;

	if ((area == NULL) || (area->is_type & level) != level)
		return ISIS_ERROR;

	head = &area->lspdb[level - 1];
	memset(lspid, 0, ISIS_SYS_ID_LEN + 2);
	memcpy(lspid, area->isis->sysid, ISIS_SYS_ID_LEN);

	lsp = lsp_search(head, lspid);

	if (!lsp) {
		flog_err(EC_LIB_DEVELOPMENT,
			 "ISIS-Upd (%s): lsp_regenerate: no L%d LSP found!",
			 area->area_tag, level);
		return ISIS_ERROR;
	}

	lsp_clear_data(lsp);
	lsp_build(lsp, area);
	rem_lifetime = lsp_rem_lifetime(area, level);
	lsp->hdr.rem_lifetime = rem_lifetime;
	lsp->last_generated = time(NULL);
	lsp_flood(lsp, NULL);
	area->lsp_gen_count[level - 1]++;
	for (ALL_LIST_ELEMENTS_RO(lsp->lspu.frags, node, frag)) {
		if (!frag->tlvs) {
			/* Updating and flooding should only affect fragments
			 * carrying data
			 */
			continue;
		}

		frag->hdr.lsp_bits =
			lsp_bits_generate(level, area->overload_bit,
					  area->attached_bit_send, area);
		/* Set the lifetime values of all the fragments to the same
		 * value,
		 * so that no fragment expires before the lsp is refreshed.
		 */
		frag->hdr.rem_lifetime = rem_lifetime;
		frag->age_out = ZERO_AGE_LIFETIME;
		lsp_flood(frag, NULL);
	}
	lsp_seqno_update(lsp);

	refresh_time = lsp_refresh_time(lsp, rem_lifetime);
	event_add_timer(master, lsp_refresh, &area->lsp_refresh_arg[level - 1],
			refresh_time, &area->t_lsp_refresh[level - 1]);
	area->lsp_regenerate_pending[level - 1] = 0;

	if (IS_DEBUG_UPDATE_PACKETS) {
		zlog_debug(
			"ISIS-Upd (%s): Refreshed our L%d LSP %pLS, len %hu, seq 0x%08x, cksum 0x%04hx, lifetime %hus refresh %hus",
			area->area_tag, level, lsp->hdr.lsp_id,
			lsp->hdr.pdu_len, lsp->hdr.seqno, lsp->hdr.checksum,
			lsp->hdr.rem_lifetime, refresh_time);
	}
	sched_debug(
		"ISIS (%s): Rebuilt L%d LSP. Set triggered regenerate to non-pending.",
		area->area_tag, level);

	return ISIS_OK;
}

/*
 * Something has changed or periodic refresh -> regenerate LSP
 */
static void lsp_refresh(struct event *thread)
{
	struct lsp_refresh_arg *arg = EVENT_ARG(thread);

	assert(arg);

	struct isis_area *area = arg->area;

	assert(area);

	int level = arg->level;

	area->t_lsp_refresh[level - 1] = NULL;
	area->lsp_regenerate_pending[level - 1] = 0;

	if ((area->is_type & level) == 0)
		return;

	/*
	 * Throttle regeneration of LSPs (but not when BFD signalled a 'down'
	 * message)
	 */
	if (monotime_since(&area->last_lsp_refresh_event[level - 1], NULL)
		    < 100000L
	    && !(area->bfd_force_spf_refresh)) {
		sched_debug("ISIS (%s): Still unstable, postpone LSP L%d refresh",
			    area->area_tag, level);
		_lsp_regenerate_schedule(area, level, 0, false,
					 __func__, __FILE__, __LINE__);
		return;
	}

	sched_debug(
		"ISIS (%s): LSP L%d refresh timer expired. Refreshing LSP...",
		area->area_tag, level);
	lsp_regenerate(area, level);
}

int _lsp_regenerate_schedule(struct isis_area *area, int level,
			     int all_pseudo, bool postpone,
			     const char *func, const char *file,
			     int line)
{
	struct isis_lsp *lsp;
	uint8_t id[ISIS_SYS_ID_LEN + 2];
	time_t now, diff;
	long timeout;
	struct listnode *cnode;
	struct isis_circuit *circuit;
	int lvl;

	if (area == NULL)
		return ISIS_ERROR;

	sched_debug(
		"ISIS (%s): Scheduling regeneration of %s LSPs, %sincluding PSNs Caller: %s %s:%d",
		area->area_tag, circuit_t2string(level),
		all_pseudo ? "" : "not ",
		func, file, line);

	memcpy(id, area->isis->sysid, ISIS_SYS_ID_LEN);
	LSP_PSEUDO_ID(id) = LSP_FRAGMENT(id) = 0;
	now = time(NULL);

	for (lvl = IS_LEVEL_1; lvl <= IS_LEVEL_2; lvl++) {
		if (!((level & lvl) && (area->is_type & lvl)))
			continue;

		if (postpone) {
			monotime(&area->last_lsp_refresh_event[lvl - 1]);
		}

		sched_debug(
			"ISIS (%s): Checking whether L%d needs to be scheduled",
			area->area_tag, lvl);

		if (area->lsp_regenerate_pending[lvl - 1]
		    && !(area->bfd_signalled_down)) {
			/*
			 * Note: in case of a BFD 'down' message the refresh is
			 * scheduled once again just to be sure
			 */
			struct timeval remain = event_timer_remain(
				area->t_lsp_refresh[lvl - 1]);
			sched_debug(
				"ISIS (%s): Regeneration is already pending, nothing todo. (Due in %lld.%03lld seconds)",
				area->area_tag, (long long)remain.tv_sec,
				(long long)remain.tv_usec / 1000);
			continue;
		}

		lsp = lsp_search(&area->lspdb[lvl - 1], id);
		if (!lsp) {
			sched_debug(
				"ISIS (%s): We do not have any LSPs to regenerate, nothing todo.",
				area->area_tag);
			continue;
		}

		/*
		 * Throttle avoidance
		 */
		sched_debug(
			"ISIS (%s): Will schedule regen timer. Last run was: %lld, Now is: %lld",
			area->area_tag, (long long)lsp->last_generated,
			(long long)now);
		EVENT_OFF(area->t_lsp_refresh[lvl - 1]);
		diff = now - lsp->last_generated;
		if (diff < area->lsp_gen_interval[lvl - 1]
		    && !(area->bfd_signalled_down)) {
			timeout =
				1000 * (area->lsp_gen_interval[lvl - 1] - diff);
			sched_debug(
				"ISIS (%s): Scheduling in %ld ms to match configured lsp_gen_interval",
				area->area_tag, timeout);
		} else {
			/*
			 * Schedule LSP refresh ASAP
			 */
			if (area->bfd_signalled_down) {
				sched_debug(
					"ISIS (%s): Scheduling immediately due to BFD 'down' message.",
					area->area_tag);
				area->bfd_signalled_down = false;
				area->bfd_force_spf_refresh = true;
				timeout = 0;
			} else {
				int64_t time_since_last = monotime_since(
					&area->last_lsp_refresh_event[lvl - 1],
					NULL);
				timeout = time_since_last < 100000L
						  ? (100000L - time_since_last)/1000
						  : 0;
				if (timeout > 0)
					sched_debug(
						"ISIS (%s): Last generation was more than lsp_gen_interval ago. Scheduling for execution in %ld ms due to the instability timer.",
						area->area_tag, timeout);
				else
					sched_debug(
						"ISIS (%s): Last generation was more than lsp_gen_interval ago. Scheduling for execution now.",
						area->area_tag);
			}
		}

		area->lsp_regenerate_pending[lvl - 1] = 1;
		event_add_timer_msec(master, lsp_refresh,
				     &area->lsp_refresh_arg[lvl - 1], timeout,
				     &area->t_lsp_refresh[lvl - 1]);
	}

	if (all_pseudo) {
		for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode, circuit))
			lsp_regenerate_schedule_pseudo(circuit, level);
	}

	return ISIS_OK;
}

/*
 * Funcs for pseudonode LSPs
 */

/*
 * 7.3.8 and 7.3.10 Generation of level 1 and 2 pseudonode LSPs
 */
static void lsp_build_pseudo(struct isis_lsp *lsp, struct isis_circuit *circuit,
			     int level)
{
	struct isis_adjacency *adj;
	struct list *adj_list;
	struct listnode *node;
	struct isis_area *area = circuit->area;
	uint16_t mtid;

	lsp_clear_data(lsp);
	lsp->tlvs = isis_alloc_tlvs();
	lsp_debug(
		"ISIS (%s): Constructing pseudo LSP %pLS for interface %s level %d",
		area->area_tag, lsp->hdr.lsp_id, circuit->interface->name,
		level);

	lsp->level = level;
	/* RFC3787  section 4 SHOULD not set overload bit in pseudo LSPs */
	lsp->hdr.lsp_bits = lsp_bits_generate(
		level, 0, circuit->area->attached_bit_send, area);

	/*
	 * add self to IS neighbours
	 */
	uint8_t ne_id[ISIS_SYS_ID_LEN + 1];

	memcpy(ne_id, area->isis->sysid, ISIS_SYS_ID_LEN);
	LSP_PSEUDO_ID(ne_id) = 0;

	if (circuit->area->oldmetric) {
		isis_tlvs_add_oldstyle_reach(lsp->tlvs, ne_id, 0);
		lsp_debug("ISIS (%s): Adding %pPN as old-style neighbor (self)",
			  area->area_tag, ne_id);
	}
	if (circuit->area->newmetric) {
		if (area_is_mt(circuit->area))
			mtid = ISIS_MT_IPV4_UNICAST;
		else
			mtid = ISIS_MT_DISABLE;
		isis_tlvs_add_extended_reach(lsp->tlvs, mtid, ne_id, 0, NULL);
		lsp_debug("ISIS (%s): Adding %pPN as te-style neighbor (self)",
			  area->area_tag, ne_id);
	}

	adj_list = list_new();
	isis_adj_build_up_list(circuit->u.bc.adjdb[level - 1], adj_list);

	for (ALL_LIST_ELEMENTS_RO(adj_list, node, adj)) {
		if (!(adj->level & level)) {
			lsp_debug(
				"ISIS (%s): Ignoring neighbor %pSY, level does not intersect",
				area->area_tag, adj->sysid);
			continue;
		}

		if (!(level == IS_LEVEL_1
		      && adj->sys_type == ISIS_SYSTYPE_L1_IS)
		    && !(level == IS_LEVEL_1
			 && adj->sys_type == ISIS_SYSTYPE_L2_IS
			 && adj->adj_usage == ISIS_ADJ_LEVEL1AND2)
		    && !(level == IS_LEVEL_2
			 && adj->sys_type == ISIS_SYSTYPE_L2_IS)) {
			lsp_debug(
				"ISIS (%s): Ignoring neighbor %pSY, level does not match",
				area->area_tag, adj->sysid);
			continue;
		}

		memcpy(ne_id, adj->sysid, ISIS_SYS_ID_LEN);
		if (circuit->area->oldmetric) {
			isis_tlvs_add_oldstyle_reach(lsp->tlvs, ne_id, 0);
			lsp_debug(
				"ISIS (%s): Adding %pPN as old-style neighbor (peer)",
				area->area_tag, ne_id);
		}
		if (circuit->area->newmetric) {
			isis_tlvs_add_extended_reach(lsp->tlvs,
						     ISIS_MT_IPV4_UNICAST,
						     ne_id, 0, NULL);
			lsp_debug(
				"ISIS (%s): Adding %pPN as te-style neighbor (peer)",
				area->area_tag, ne_id);
		}
	}
	list_delete(&adj_list);
	return;
}

int lsp_generate_pseudo(struct isis_circuit *circuit, int level)
{
	struct lspdb_head *head = &circuit->area->lspdb[level - 1];
	struct isis_lsp *lsp;
	uint8_t lsp_id[ISIS_SYS_ID_LEN + 2];
	uint16_t rem_lifetime, refresh_time;

	if ((circuit->is_type & level) != level
	    || (circuit->state != C_STATE_UP)
	    || (circuit->circ_type != CIRCUIT_T_BROADCAST)
	    || (circuit->u.bc.is_dr[level - 1] == 0))
		return ISIS_ERROR;

	memcpy(lsp_id, circuit->isis->sysid, ISIS_SYS_ID_LEN);
	LSP_FRAGMENT(lsp_id) = 0;
	LSP_PSEUDO_ID(lsp_id) = circuit->circuit_id;

	/*
	 * If for some reason have a pseudo LSP in the db already -> regenerate
	 */
	if (lsp_search(head, lsp_id))
		return lsp_regenerate_schedule_pseudo(circuit, level);

	rem_lifetime = lsp_rem_lifetime(circuit->area, level);
	/* RFC3787  section 4 SHOULD not set overload bit in pseudo LSPs */
	lsp = lsp_new(circuit->area, lsp_id, rem_lifetime, 1,
		      lsp_bits_generate(circuit->area->is_type, 0,
					circuit->area->attached_bit_send,
					circuit->area),
		      0, NULL, level);
	lsp->area = circuit->area;

	lsp_build_pseudo(lsp, circuit, level);
	lsp_pack_pdu(lsp);
	lsp->own_lsp = 1;
	lsp_insert(head, lsp);
	lsp_flood(lsp, NULL);

	refresh_time = lsp_refresh_time(lsp, rem_lifetime);
	EVENT_OFF(circuit->u.bc.t_refresh_pseudo_lsp[level - 1]);
	circuit->lsp_regenerate_pending[level - 1] = 0;
	if (level == IS_LEVEL_1)
		event_add_timer(master, lsp_l1_refresh_pseudo, circuit,
				refresh_time,
				&circuit->u.bc.t_refresh_pseudo_lsp[level - 1]);
	else if (level == IS_LEVEL_2)
		event_add_timer(master, lsp_l2_refresh_pseudo, circuit,
				refresh_time,
				&circuit->u.bc.t_refresh_pseudo_lsp[level - 1]);

	if (IS_DEBUG_UPDATE_PACKETS) {
		zlog_debug(
			"ISIS-Upd (%s): Built L%d Pseudo LSP %pLS, len %hu, seq 0x%08x, cksum 0x%04hx, lifetime %hus, refresh %hus",
			circuit->area->area_tag, level, lsp->hdr.lsp_id,
			lsp->hdr.pdu_len, lsp->hdr.seqno, lsp->hdr.checksum,
			lsp->hdr.rem_lifetime, refresh_time);
	}

	return ISIS_OK;
}

static int lsp_regenerate_pseudo(struct isis_circuit *circuit, int level)
{
	struct lspdb_head *head = &circuit->area->lspdb[level - 1];
	struct isis_lsp *lsp;
	uint8_t lsp_id[ISIS_SYS_ID_LEN + 2];
	uint16_t rem_lifetime, refresh_time;

	if ((circuit->is_type & level) != level
	    || (circuit->state != C_STATE_UP)
	    || (circuit->circ_type != CIRCUIT_T_BROADCAST)
	    || (circuit->u.bc.is_dr[level - 1] == 0))
		return ISIS_ERROR;

	memcpy(lsp_id, circuit->isis->sysid, ISIS_SYS_ID_LEN);
	LSP_PSEUDO_ID(lsp_id) = circuit->circuit_id;
	LSP_FRAGMENT(lsp_id) = 0;

	lsp = lsp_search(head, lsp_id);

	if (!lsp) {
		flog_err(EC_LIB_DEVELOPMENT,
			 "lsp_regenerate_pseudo: no l%d LSP %pLS found!", level,
			 lsp_id);
		return ISIS_ERROR;
	}

	rem_lifetime = lsp_rem_lifetime(circuit->area, level);
	lsp->hdr.rem_lifetime = rem_lifetime;
	lsp_build_pseudo(lsp, circuit, level);
	lsp_inc_seqno(lsp, 0);
	lsp->last_generated = time(NULL);
	lsp_flood(lsp, NULL);

	refresh_time = lsp_refresh_time(lsp, rem_lifetime);
	if (level == IS_LEVEL_1)
		event_add_timer(master, lsp_l1_refresh_pseudo, circuit,
				refresh_time,
				&circuit->u.bc.t_refresh_pseudo_lsp[level - 1]);
	else if (level == IS_LEVEL_2)
		event_add_timer(master, lsp_l2_refresh_pseudo, circuit,
				refresh_time,
				&circuit->u.bc.t_refresh_pseudo_lsp[level - 1]);

	if (IS_DEBUG_UPDATE_PACKETS) {
		zlog_debug(
			"ISIS-Upd (%s): Refreshed L%d Pseudo LSP %pLS, len %hu, seq 0x%08x, cksum 0x%04hx, lifetime %hus, refresh %hus",
			circuit->area->area_tag, level, lsp->hdr.lsp_id,
			lsp->hdr.pdu_len, lsp->hdr.seqno, lsp->hdr.checksum,
			lsp->hdr.rem_lifetime, refresh_time);
	}

	return ISIS_OK;
}

/*
 * Something has changed or periodic refresh -> regenerate pseudo LSP
 */
static void lsp_l1_refresh_pseudo(struct event *thread)
{
	struct isis_circuit *circuit;
	uint8_t id[ISIS_SYS_ID_LEN + 2];

	circuit = EVENT_ARG(thread);

	circuit->u.bc.t_refresh_pseudo_lsp[0] = NULL;
	circuit->lsp_regenerate_pending[0] = 0;

	if ((circuit->u.bc.is_dr[0] == 0)
	    || (circuit->is_type & IS_LEVEL_1) == 0) {
		memcpy(id, circuit->isis->sysid, ISIS_SYS_ID_LEN);
		LSP_PSEUDO_ID(id) = circuit->circuit_id;
		LSP_FRAGMENT(id) = 0;
		lsp_purge_pseudo(id, circuit, IS_LEVEL_1);
		return;
	}

	lsp_regenerate_pseudo(circuit, IS_LEVEL_1);
}

static void lsp_l2_refresh_pseudo(struct event *thread)
{
	struct isis_circuit *circuit;
	uint8_t id[ISIS_SYS_ID_LEN + 2];

	circuit = EVENT_ARG(thread);

	circuit->u.bc.t_refresh_pseudo_lsp[1] = NULL;
	circuit->lsp_regenerate_pending[1] = 0;

	if ((circuit->u.bc.is_dr[1] == 0)
	    || (circuit->is_type & IS_LEVEL_2) == 0) {
		memcpy(id, circuit->isis->sysid, ISIS_SYS_ID_LEN);
		LSP_PSEUDO_ID(id) = circuit->circuit_id;
		LSP_FRAGMENT(id) = 0;
		lsp_purge_pseudo(id, circuit, IS_LEVEL_2);
		return;
	}

	lsp_regenerate_pseudo(circuit, IS_LEVEL_2);
}

int lsp_regenerate_schedule_pseudo(struct isis_circuit *circuit, int level)
{
	struct isis_lsp *lsp;
	uint8_t lsp_id[ISIS_SYS_ID_LEN + 2];
	time_t now, diff;
	long timeout;
	int lvl;
	struct isis_area *area = circuit->area;

	if (circuit->circ_type != CIRCUIT_T_BROADCAST
	    || circuit->state != C_STATE_UP)
		return ISIS_OK;

	sched_debug(
		"ISIS (%s): Scheduling regeneration of %s pseudo LSP for interface %s",
		area->area_tag, circuit_t2string(level),
		circuit->interface->name);

	memcpy(lsp_id, area->isis->sysid, ISIS_SYS_ID_LEN);
	LSP_PSEUDO_ID(lsp_id) = circuit->circuit_id;
	LSP_FRAGMENT(lsp_id) = 0;
	now = time(NULL);

	for (lvl = IS_LEVEL_1; lvl <= IS_LEVEL_2; lvl++) {
		sched_debug(
			"ISIS (%s): Checking whether L%d pseudo LSP needs to be scheduled",
			area->area_tag, lvl);

		if (!((level & lvl) && (circuit->is_type & lvl))) {
			sched_debug("ISIS (%s): Level is not active on circuit",
				    area->area_tag);
			continue;
		}

		if (circuit->u.bc.is_dr[lvl - 1] == 0) {
			sched_debug(
				"ISIS (%s): This IS is not DR, nothing to do.",
				area->area_tag);
			continue;
		}

		if (circuit->lsp_regenerate_pending[lvl - 1]) {
			struct timeval remain = event_timer_remain(
				circuit->u.bc.t_refresh_pseudo_lsp[lvl - 1]);
			sched_debug(
				"ISIS (%s): Regenerate is already pending, nothing todo. (Due in %lld.%03lld seconds)",
				area->area_tag, (long long)remain.tv_sec,
				(long long)remain.tv_usec / 1000);
			continue;
		}

		lsp = lsp_search(&circuit->area->lspdb[lvl - 1], lsp_id);
		if (!lsp) {
			sched_debug(
				"ISIS (%s): Pseudonode LSP does not exist yet, nothing to regenerate.",
				area->area_tag);
			continue;
		}

		/*
		 * Throttle avoidance
		 */
		sched_debug(
			"ISIS (%s): Will schedule PSN regen timer. Last run was: %lld, Now is: %lld",
			area->area_tag, (long long)lsp->last_generated,
			(long long)now);
		EVENT_OFF(circuit->u.bc.t_refresh_pseudo_lsp[lvl - 1]);
		diff = now - lsp->last_generated;
		if (diff < circuit->area->lsp_gen_interval[lvl - 1]) {
			timeout =
				1000 * (circuit->area->lsp_gen_interval[lvl - 1]
					- diff);
			sched_debug(
				"ISIS (%s): Sechduling in %ld ms to match configured lsp_gen_interval",
				area->area_tag, timeout);
		} else {
			timeout = 100;
			sched_debug(
				"ISIS (%s): Last generation was more than lsp_gen_interval ago. Scheduling for execution in %ld ms.",
				area->area_tag, timeout);
		}

		circuit->lsp_regenerate_pending[lvl - 1] = 1;

		if (lvl == IS_LEVEL_1) {
			event_add_timer_msec(
				master, lsp_l1_refresh_pseudo, circuit, timeout,
				&circuit->u.bc.t_refresh_pseudo_lsp[lvl - 1]);
		} else if (lvl == IS_LEVEL_2) {
			event_add_timer_msec(
				master, lsp_l2_refresh_pseudo, circuit, timeout,
				&circuit->u.bc.t_refresh_pseudo_lsp[lvl - 1]);
		}
	}

	return ISIS_OK;
}

/*
 * Walk through LSPs for an area
 *  - set remaining lifetime
 */
void lsp_tick(struct event *thread)
{
	struct isis_area *area;
	struct isis_lsp *lsp;
	int level;
	uint16_t rem_lifetime;
	bool fabricd_sync_incomplete = false;

	area = EVENT_ARG(thread);
	assert(area);
	area->t_tick = NULL;
	event_add_timer(master, lsp_tick, area, 1, &area->t_tick);

	struct isis_circuit *fabricd_init_c = fabricd_initial_sync_circuit(area);

	/*
	 * Remove LSPs which have aged out
	 */
	for (level = 0; level < ISIS_LEVELS; level++) {
		struct isis_lsp *next = lspdb_first(&area->lspdb[level]);
		frr_each_from (lspdb, &area->lspdb[level], lsp, next) {
			/*
			 * The lsp rem_lifetime is kept at 0 for MaxAge
			 * or
			 * ZeroAgeLifetime depending on explicit purge
			 * or
			 * natural age out. So schedule spf only once
			 * when
			 * the first time rem_lifetime becomes 0.
			 */
			rem_lifetime = lsp->hdr.rem_lifetime;
			lsp_set_time(lsp);

			/*
			 * Schedule may run spf which should be done
			 * only after
			 * the lsp rem_lifetime becomes 0 for the first
			 * time.
			 * ISO 10589 - 7.3.16.4 first paragraph.
			 */
			if (rem_lifetime == 1 && lsp->hdr.seqno != 0) {
				/* 7.3.16.4 a) set SRM flags on all */
				/* 7.3.16.4 b) retain only the header */
				if (lsp->area->purge_originator)
					lsp_purge(lsp, lsp->level, NULL);
				else
					lsp_flood(lsp, NULL);
				/* 7.3.16.4 c) record the time to purge
				 * FIXME */
				isis_spf_schedule(lsp->area, lsp->level);
				isis_te_lsp_event(lsp, LSP_TICK);
			}

			if (lsp->age_out == 0) {
				zlog_debug(
					"ISIS-Upd (%s): L%u LSP %pLS seq 0x%08x aged out",
					area->area_tag, lsp->level,
					lsp->hdr.lsp_id, lsp->hdr.seqno);

				/* if we're aging out fragment 0, lsp_destroy()
				 * below will delete all other fragments too,
				 * so we need to skip over those
				 */
				if (!LSP_FRAGMENT(lsp->hdr.lsp_id))
					while (next &&
						!memcmp(next->hdr.lsp_id,
							lsp->hdr.lsp_id,
							ISIS_SYS_ID_LEN + 1))
						next = lspdb_next(
							&area->lspdb[level],
							next);

				lspdb_del(&area->lspdb[level], lsp);
				lsp_destroy(lsp);
				lsp = NULL;
			}

			if (fabricd_init_c && lsp) {
				fabricd_sync_incomplete |=
					ISIS_CHECK_FLAG(lsp->SSNflags,
							fabricd_init_c);
			}
		}
	}

	if (fabricd_init_c
	    && !fabricd_sync_incomplete
	    && !isis_tx_queue_len(fabricd_init_c->tx_queue)) {
		fabricd_initial_sync_finish(area);
	}
}

void lsp_purge_pseudo(uint8_t *id, struct isis_circuit *circuit, int level)
{
	struct isis_lsp *lsp;

	lsp = lsp_search(&circuit->area->lspdb[level - 1], id);
	if (!lsp)
		return;

	lsp_purge(lsp, level, NULL);
}

/*
 * Purge own LSP that is received and we don't have.
 * -> Do as in 7.3.16.4
 */
void lsp_purge_non_exist(int level, struct isis_lsp_hdr *hdr,
			 struct isis_area *area)
{
	struct isis_lsp *lsp;

	/*
	 * We need to create the LSP to be purged
	 */
	lsp = XCALLOC(MTYPE_ISIS_LSP, sizeof(struct isis_lsp));
	lsp->area = area;
	lsp->level = level;
	lsp_adjust_stream(lsp);
	lsp->age_out = ZERO_AGE_LIFETIME;
	lsp->area->lsp_purge_count[level - 1]++;

	memcpy(&lsp->hdr, hdr, sizeof(lsp->hdr));
	lsp->hdr.rem_lifetime = 0;

	lsp_purge_add_poi(lsp, NULL);

	lsp_pack_pdu(lsp);

	lsp_insert(&area->lspdb[lsp->level - 1], lsp);
	lsp_flood(lsp, NULL);

	return;
}

void lsp_set_all_srmflags(struct isis_lsp *lsp, bool set)
{
	struct listnode *node;
	struct isis_circuit *circuit;

	assert(lsp);

	if (!lsp->area)
		return;

	struct list *circuit_list = lsp->area->circuit_list;
	for (ALL_LIST_ELEMENTS_RO(circuit_list, node, circuit)) {
		if (set) {
			isis_tx_queue_add(circuit->tx_queue, lsp,
					  TX_LSP_NORMAL);
		} else {
			isis_tx_queue_del(circuit->tx_queue, lsp);
		}
	}
}

void _lsp_flood(struct isis_lsp *lsp, struct isis_circuit *circuit,
		const char *func, const char *file, int line)
{
	if (IS_DEBUG_FLOODING) {
		zlog_debug("Flooding LSP %pLS%s%s (From %s %s:%d)",
			   lsp->hdr.lsp_id, circuit ? " except on " : "",
			   circuit ? circuit->interface->name : "", func, file,
			   line);
	}

	if (!fabricd)
		lsp_set_all_srmflags(lsp, true);
	else
		fabricd_lsp_flood(lsp, circuit);

	if (circuit)
		isis_tx_queue_del(circuit->tx_queue, lsp);
}

static int lsp_handle_adj_state_change(struct isis_adjacency *adj)
{
	lsp_regenerate_schedule(adj->circuit->area, IS_LEVEL_1 | IS_LEVEL_2, 0);

	/* when an adjacency state changes determine if we need to
	 * change attach_bits in other area's LSPs
	 */
	isis_reset_attach_bit(adj);

	return 0;
}

/*
 * Iterate over all IP reachability TLVs in a LSP (all fragments) of the given
 * address-family and MT-ID.
 */
int isis_lsp_iterate_ip_reach(struct isis_lsp *lsp, int family, uint16_t mtid,
			      lsp_ip_reach_iter_cb cb, void *arg)
{
	bool pseudo_lsp = LSP_PSEUDO_ID(lsp->hdr.lsp_id);
	struct isis_lsp *frag;
	struct listnode *node;

	if (lsp->hdr.seqno == 0 || lsp->hdr.rem_lifetime == 0)
		return LSP_ITER_CONTINUE;

	/* Parse LSP */
	if (lsp->tlvs) {
		if (!fabricd && !pseudo_lsp && family == AF_INET
		    && mtid == ISIS_MT_IPV4_UNICAST) {
			struct isis_item_list *reachs[] = {
				&lsp->tlvs->oldstyle_ip_reach,
				&lsp->tlvs->oldstyle_ip_reach_ext};

			for (unsigned int i = 0; i < array_size(reachs); i++) {
				struct isis_oldstyle_ip_reach *r;

				for (r = (struct isis_oldstyle_ip_reach *)
						 reachs[i]
							 ->head;
				     r; r = r->next) {
					bool external = i ? true : false;

					if ((*cb)((struct prefix *)&r->prefix,
						  r->metric, external, NULL,
						  arg)
					    == LSP_ITER_STOP)
						return LSP_ITER_STOP;
				}
			}
		}

		if (!pseudo_lsp && family == AF_INET) {
			struct isis_item_list *ipv4_reachs;

			if (mtid == ISIS_MT_IPV4_UNICAST)
				ipv4_reachs = &lsp->tlvs->extended_ip_reach;
			else
				ipv4_reachs = isis_lookup_mt_items(
					&lsp->tlvs->mt_ip_reach, mtid);

			struct isis_extended_ip_reach *r;
			for (r = ipv4_reachs ? (struct isis_extended_ip_reach *)
						       ipv4_reachs->head
					     : NULL;
			     r; r = r->next) {
				if ((*cb)((struct prefix *)&r->prefix,
					  r->metric, false, r->subtlvs, arg)
				    == LSP_ITER_STOP)
					return LSP_ITER_STOP;
			}
		}

		if (!pseudo_lsp && family == AF_INET6) {
			struct isis_item_list *ipv6_reachs;
			struct isis_ipv6_reach *r;

			if (mtid == ISIS_MT_IPV4_UNICAST)
				ipv6_reachs = &lsp->tlvs->ipv6_reach;
			else
				ipv6_reachs = isis_lookup_mt_items(
					&lsp->tlvs->mt_ipv6_reach, mtid);

			for (r = ipv6_reachs ? (struct isis_ipv6_reach *)
						       ipv6_reachs->head
					     : NULL;
			     r; r = r->next) {
				if ((*cb)((struct prefix *)&r->prefix,
					  r->metric, r->external, r->subtlvs,
					  arg)
				    == LSP_ITER_STOP)
					return LSP_ITER_STOP;
			}
		}
	}

	/* Parse LSP fragments if it is not a fragment itself */
	if (!LSP_FRAGMENT(lsp->hdr.lsp_id))
		for (ALL_LIST_ELEMENTS_RO(lsp->lspu.frags, node, frag)) {
			if (!frag->tlvs)
				continue;

			if (isis_lsp_iterate_ip_reach(frag, family, mtid, cb,
						      arg)
			    == LSP_ITER_STOP)
				return LSP_ITER_STOP;
		}

	return LSP_ITER_CONTINUE;
}

/*
 * Iterate over all IS reachability TLVs in a LSP (all fragments) of the given
 * MT-ID.
 */
int isis_lsp_iterate_is_reach(struct isis_lsp *lsp, uint16_t mtid,
			      lsp_is_reach_iter_cb cb, void *arg)
{
	bool pseudo_lsp = LSP_PSEUDO_ID(lsp->hdr.lsp_id);
	struct isis_lsp *frag;
	struct listnode *node;
	struct isis_item *head;
	struct isis_item_list *te_neighs;

	if (lsp->hdr.seqno == 0 || lsp->hdr.rem_lifetime == 0)
		return LSP_ITER_CONTINUE;

	/* Parse LSP */
	if (lsp->tlvs) {
		if (pseudo_lsp || mtid == ISIS_MT_IPV4_UNICAST) {
			head = lsp->tlvs->oldstyle_reach.head;
			for (struct isis_oldstyle_reach *reach =
				     (struct isis_oldstyle_reach *)head;
			     reach; reach = reach->next) {
				if ((*cb)(reach->id, reach->metric, true, NULL,
					  arg)
				    == LSP_ITER_STOP)
					return LSP_ITER_STOP;
			}
		}

		if (pseudo_lsp || mtid == ISIS_MT_IPV4_UNICAST)
			te_neighs = &lsp->tlvs->extended_reach;
		else
			te_neighs =
				isis_get_mt_items(&lsp->tlvs->mt_reach, mtid);
		if (te_neighs) {
			head = te_neighs->head;
			for (struct isis_extended_reach *reach =
				     (struct isis_extended_reach *)head;
			     reach; reach = reach->next) {
				if ((*cb)(reach->id, reach->metric, false,
					  reach->subtlvs, arg)
				    == LSP_ITER_STOP)
					return LSP_ITER_STOP;
			}
		}
	}

	/* Parse LSP fragments if it not a fragment itself. */
	if (!LSP_FRAGMENT(lsp->hdr.lsp_id))
		for (ALL_LIST_ELEMENTS_RO(lsp->lspu.frags, node, frag)) {
			if (!frag->tlvs)
				continue;

			if (isis_lsp_iterate_is_reach(frag, mtid, cb, arg)
			    == LSP_ITER_STOP)
				return LSP_ITER_STOP;
		}

	return LSP_ITER_CONTINUE;
}

void lsp_init(void)
{
	device_startup = true;
	hook_register(isis_adj_state_change_hook,
		      lsp_handle_adj_state_change);
}
