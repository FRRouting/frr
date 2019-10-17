/*
 * IS-IS Rout(e)ing protocol - isis_lsp.c
 *                             LSP processing
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 * Copyright (C) 2013-2015   Christian Franke <chris@opensourcerouting.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "linklist.h"
#include "thread.h"
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
#include "isisd/fabricd.h"
#include "isisd/isis_tx_queue.h"
#include "isisd/isis_nb.h"

static int lsp_refresh(struct thread *thread);
static int lsp_l1_refresh_pseudo(struct thread *thread);
static int lsp_l2_refresh_pseudo(struct thread *thread);

static void lsp_destroy(struct isis_lsp *lsp);

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
		if (isis->debugs & DEBUG_SNP_PACKETS) {
			zlog_debug(
				"ISIS-Snp (%s): Compare LSP %s seq 0x%08" PRIx32
				", cksum 0x%04" PRIx16 ", lifetime %" PRIu16
				"s",
				areatag, rawlspid_print(lsp->hdr.lsp_id),
				lsp->hdr.seqno, lsp->hdr.checksum,
				lsp->hdr.rem_lifetime);
			zlog_debug(
				"ISIS-Snp (%s):         is equal to ours seq 0x%08" PRIx32
				", cksum 0x%04" PRIx16 ", lifetime %" PRIu16
				"s",
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
		if (isis->debugs & DEBUG_SNP_PACKETS) {
			zlog_debug(
				"ISIS-Snp (%s): Compare LSP %s seq 0x%08" PRIx32
				", cksum 0x%04" PRIx16 ", lifetime %" PRIu16
				"s",
				areatag, rawlspid_print(lsp->hdr.lsp_id), seqno,
				checksum, rem_lifetime);
			zlog_debug(
				"ISIS-Snp (%s):       is newer than ours seq 0x%08" PRIx32
				", cksum 0x%04" PRIx16 ", lifetime %" PRIu16
				"s",
				areatag, lsp->hdr.seqno, lsp->hdr.checksum,
				lsp->hdr.rem_lifetime);
		}
		return LSP_NEWER;
	}
	if (isis->debugs & DEBUG_SNP_PACKETS) {
		zlog_debug("ISIS-Snp (%s): Compare LSP %s seq 0x%08" PRIx32
			   ", cksum 0x%04" PRIx16 ", lifetime %" PRIu16 "s",
			   areatag, rawlspid_print(lsp->hdr.lsp_id), seqno,
			   checksum, rem_lifetime);
		zlog_debug(
			"ISIS-Snp (%s):       is older than ours seq 0x%08" PRIx32
			", cksum 0x%04" PRIx16 ", lifetime %" PRIu16 "s",
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
		isis_notif_lsp_exceed_max(lsp->area,
					  rawlspid_print(lsp->hdr.lsp_id));
	}
#endif /* ifndef FABRICD */

	lsp->hdr.seqno = newseq;

	lsp_pack_pdu(lsp);
	isis_spf_schedule(lsp->area, lsp->level);
}

static void lsp_purge_add_poi(struct isis_lsp *lsp,
			      const uint8_t *sender)
{
	if (!lsp->area->purge_originator)
		return;

	/* add purge originator identification */
	if (!lsp->tlvs)
		lsp->tlvs = isis_alloc_tlvs();
	isis_tlvs_set_purge_originator(lsp->tlvs, isis->sysid, sender);
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

static uint8_t lsp_bits_generate(int level, int overload_bit, int attached_bit)
{
	uint8_t lsp_bits = 0;
	if (level == IS_LEVEL_1)
		lsp_bits = IS_LEVEL_1;
	else
		lsp_bits = IS_LEVEL_1_AND_2;
	if (overload_bit)
		lsp_bits |= overload_bit;
	if (attached_bit)
		lsp_bits |= attached_bit;
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
		isis_dynhn_insert(lsp->hdr.lsp_id, lsp->tlvs->hostname,
				  (lsp->hdr.lsp_bits & LSPBIT_IST)
						  == IS_LEVEL_1_AND_2
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
			"ISIS-Upd (%s): BUG updating LSP %s still marked as own LSP",
			area->area_tag, rawlspid_print(lsp->hdr.lsp_id));
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

	if (lsp->hdr.seqno)
		isis_spf_schedule(lsp->area, lsp->level);
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

	if (isis->debugs & DEBUG_EVENTS)
		zlog_debug("New LSP with ID %s-%02x-%02x len %d seqnum %08x",
			   sysid_print(lsp_id), LSP_PSEUDO_ID(lsp->hdr.lsp_id),
			   LSP_FRAGMENT(lsp->hdr.lsp_id), lsp->hdr.pdu_len,
			   lsp->hdr.seqno);

	return lsp;
}

void lsp_insert(struct lspdb_head *head, struct isis_lsp *lsp)
{
	lspdb_add(head, lsp);
	if (lsp->hdr.seqno)
		isis_spf_schedule(lsp->area, lsp->level);
}

/*
 * Build a list of LSPs with non-zero ht bounded by start and stop ids
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

		if (lsp->hdr.rem_lifetime)
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

void lspid_print(uint8_t *lsp_id, char *dest, char dynhost, char frag)
{
	struct isis_dynhn *dyn = NULL;
	uint8_t id[SYSID_STRLEN];

	if (dynhost)
		dyn = dynhn_find_by_id(lsp_id);
	else
		dyn = NULL;

	if (dyn)
		sprintf((char *)id, "%.14s", dyn->hostname);
	else if (!memcmp(isis->sysid, lsp_id, ISIS_SYS_ID_LEN) && dynhost)
		sprintf((char *)id, "%.14s", cmd_hostname_get());
	else
		memcpy(id, sysid_print(lsp_id), 15);
	if (frag)
		sprintf(dest, "%s.%02x-%02x", id, LSP_PSEUDO_ID(lsp_id),
			LSP_FRAGMENT(lsp_id));
	else
		sprintf(dest, "%s.%02x", id, LSP_PSEUDO_ID(lsp_id));
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
	pos += sprintf(pos, "%d/",
		       ISIS_MASK_LSP_ATT_DEFAULT_BIT(lsp_bits) ? 1 : 0);

	pos += sprintf(pos, "%d/",
		       ISIS_MASK_LSP_PARTITION_BIT(lsp_bits) ? 1 : 0);

	sprintf(pos, "%d", ISIS_MASK_LSP_OL_BIT(lsp_bits) ? 1 : 0);

	return buf;
}

/* this function prints the lsp on show isis database */
void lsp_print(struct isis_lsp *lsp, struct vty *vty, char dynhost)
{
	char LSPid[255];
	char age_out[8];
	char b[200];

	lspid_print(lsp->hdr.lsp_id, LSPid, dynhost, 1);
	vty_out(vty, "%-21s%c  ", LSPid, lsp->own_lsp ? '*' : ' ');
	vty_out(vty, "%5" PRIu16 "   ", lsp->hdr.pdu_len);
	vty_out(vty, "0x%08" PRIx32 "  ", lsp->hdr.seqno);
	vty_out(vty, "0x%04" PRIx16 "  ", lsp->hdr.checksum);
	if (lsp->hdr.rem_lifetime == 0) {
		snprintf(age_out, 8, "(%d)", lsp->age_out);
		age_out[7] = '\0';
		vty_out(vty, "%7s   ", age_out);
	} else
		vty_out(vty, " %5" PRIu16 "    ", lsp->hdr.rem_lifetime);
	vty_out(vty, "%s\n", lsp_bits2string(lsp->hdr.lsp_bits, b, sizeof(b)));
}

void lsp_print_detail(struct isis_lsp *lsp, struct vty *vty, char dynhost)
{
	lsp_print(lsp, vty, dynhost);
	if (lsp->tlvs)
		vty_multiline(vty, "  ", "%s", isis_format_tlvs(lsp->tlvs));
	vty_out(vty, "\n");
}

/* print all the lsps info in the local lspdb */
int lsp_print_all(struct vty *vty, struct lspdb_head *head, char detail,
		  char dynhost)
{
	struct isis_lsp *lsp;
	int lsp_count = 0;

	if (detail == ISIS_UI_LEVEL_BRIEF) {
		frr_each (lspdb, head, lsp) {
			lsp_print(lsp, vty, dynhost);
			lsp_count++;
		}
	} else if (detail == ISIS_UI_LEVEL_DETAIL) {
		frr_each (lspdb, head, lsp) {
			lsp_print_detail(lsp, vty, dynhost);
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
		if (area->newmetric)
			isis_tlvs_add_extended_ip_reach(lsp->tlvs, ipv4,
							metric);
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
			isis_tlvs_add_ipv6_reach(lsp->tlvs,
						 isis_area_ipv6_topology(area),
						 p, metric);
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
					area->attached_bit),
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
	char buf[PREFIX2STR_BUFFER];
	struct listnode *node;
	struct isis_lsp *frag;

	lsp_clear_data(lsp);
	for (ALL_LIST_ELEMENTS_RO(lsp->lspu.frags, node, frag))
		lsp_clear_data(frag);

	lsp->tlvs = isis_alloc_tlvs();
	lsp_debug("ISIS (%s): Constructing local system LSP for level %d",
		  area->area_tag, level);

	lsp->hdr.lsp_bits = lsp_bits_generate(level, area->overload_bit,
					      area->attached_bit);

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

	/* IPv4 address and TE router ID TLVs.
	 * In case of the first one we don't follow "C" vendor,
	 * but "J" vendor behavior - one IPv4 address is put
	 * into LSP. TE router ID will be the same if MPLS-TE
	 * is not activate or MPLS-TE router-id not specified
	 */
	if (isis->router_id != 0) {
		struct in_addr id = {.s_addr = isis->router_id};
		inet_ntop(AF_INET, &id, buf, sizeof(buf));
		lsp_debug("ISIS (%s): Adding router ID %s as IPv4 tlv.",
			  area->area_tag, buf);
		isis_tlvs_add_ipv4_address(lsp->tlvs, &id);

		/* If new style TLV's are in use, add TE router ID TLV
		 * Check if MPLS-TE is activate and mpls-te router-id set
		 * otherwise add exactly same data as for IPv4 address
		 */
		if (area->newmetric) {
			if (IS_MPLS_TE(area->mta)
			    && area->mta->router_id.s_addr != 0)
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

	lsp_debug("ISIS (%s): Adding circuit specific information.",
		  area->area_tag);

	if (fabricd) {
		lsp_debug(
			"ISIS (%s): Adding tier %" PRIu8 " spine-leaf-extension tlv.",
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

		uint32_t metric = area->oldmetric
					  ? circuit->metric[level - 1]
					  : circuit->te_metric[level - 1];

		if (circuit->ip_router && circuit->ip_addrs
		    && circuit->ip_addrs->count > 0) {
			lsp_debug(
				"ISIS (%s): Circuit has IPv4 active, adding respective TLVs.",
				area->area_tag);
			struct listnode *ipnode;
			struct prefix_ipv4 *ipv4;
			for (ALL_LIST_ELEMENTS_RO(circuit->ip_addrs, ipnode,
						  ipv4)) {
				if (area->oldmetric) {
					lsp_debug(
						"ISIS (%s): Adding old-style IP reachability for %s",
						area->area_tag,
						prefix2str(ipv4, buf,
							   sizeof(buf)));
					isis_tlvs_add_oldstyle_ip_reach(
						lsp->tlvs, ipv4, metric);
				}

				if (area->newmetric) {
					lsp_debug(
						"ISIS (%s): Adding te-style IP reachability for %s",
						area->area_tag,
						prefix2str(ipv4, buf,
							   sizeof(buf)));
					isis_tlvs_add_extended_ip_reach(
						lsp->tlvs, ipv4, metric);
				}
			}
		}

		if (circuit->ipv6_router && circuit->ipv6_non_link
		    && circuit->ipv6_non_link->count > 0) {
			struct listnode *ipnode;
			struct prefix_ipv6 *ipv6;

			for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_non_link,
						  ipnode, ipv6)) {
				lsp_debug(
					"ISIS (%s): Adding IPv6 reachability for %s",
					area->area_tag,
					prefix2str(ipv6, buf, sizeof(buf)));
				isis_tlvs_add_ipv6_reach(
					lsp->tlvs,
					isis_area_ipv6_topology(area), ipv6,
					metric);
			}
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
							"ISIS (%s): Adding DIS %s.%02x as old-style neighbor",
							area->area_tag,
							sysid_print(ne_id),
							LSP_PSEUDO_ID(ne_id));
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
						"ISIS (%s): Adding old-style is reach for %s",
						area->area_tag,
						sysid_print(ne_id));
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
			      isis_format_tlvs(tlvs));
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

	if ((area == NULL) || (area->is_type & level) != level)
		return ISIS_ERROR;

	memset(&lspid, 0, ISIS_SYS_ID_LEN + 2);
	memcpy(&lspid, isis->sysid, ISIS_SYS_ID_LEN);

	/* only builds the lsp if the area shares the level */
	oldlsp = lsp_search(&area->lspdb[level - 1], lspid);
	if (oldlsp) {
		/* FIXME: we should actually initiate a purge */
		seq_num = oldlsp->hdr.seqno;
		lsp_search_and_destroy(&area->lspdb[level - 1],
				       oldlsp->hdr.lsp_id);
	}
	rem_lifetime = lsp_rem_lifetime(area, level);
	newlsp =
		lsp_new(area, lspid, rem_lifetime, seq_num,
			area->is_type | area->overload_bit | area->attached_bit,
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

	THREAD_TIMER_OFF(area->t_lsp_refresh[level - 1]);
	area->lsp_regenerate_pending[level - 1] = 0;
	thread_add_timer(master, lsp_refresh,
			 &area->lsp_refresh_arg[level - 1], refresh_time,
			 &area->t_lsp_refresh[level - 1]);

	if (isis->debugs & DEBUG_UPDATE_PACKETS) {
		zlog_debug("ISIS-Upd (%s): Building L%d LSP %s, len %" PRIu16
			   ", seq 0x%08" PRIx32 ", cksum 0x%04" PRIx16
			   ", lifetime %" PRIu16 "s refresh %" PRIu16 "s",
			   area->area_tag, level,
			   rawlspid_print(newlsp->hdr.lsp_id),
			   newlsp->hdr.pdu_len, newlsp->hdr.seqno,
			   newlsp->hdr.checksum, newlsp->hdr.rem_lifetime,
			   refresh_time);
	}
	sched_debug(
		"ISIS (%s): Built L%d LSP. Set triggered regenerate to non-pending.",
		area->area_tag, level);

#ifndef FABRICD
	/* send northbound notification */
	isis_notif_lsp_gen(area, rawlspid_print(newlsp->hdr.lsp_id),
			   newlsp->hdr.seqno, newlsp->last_generated);
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
	memcpy(lspid, isis->sysid, ISIS_SYS_ID_LEN);

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

		frag->hdr.lsp_bits = lsp_bits_generate(
			level, area->overload_bit, area->attached_bit);
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
	thread_add_timer(master, lsp_refresh,
			 &area->lsp_refresh_arg[level - 1], refresh_time,
			 &area->t_lsp_refresh[level - 1]);
	area->lsp_regenerate_pending[level - 1] = 0;

	if (isis->debugs & DEBUG_UPDATE_PACKETS) {
		zlog_debug(
			"ISIS-Upd (%s): Refreshed our L%d LSP %s, len %" PRIu16
			", seq 0x%08" PRIx32 ", cksum 0x%04" PRIx16
			", lifetime %" PRIu16 "s refresh %" PRIu16 "s",
			area->area_tag, level, rawlspid_print(lsp->hdr.lsp_id),
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
static int lsp_refresh(struct thread *thread)
{
	struct lsp_refresh_arg *arg = THREAD_ARG(thread);

	assert(arg);

	struct isis_area *area = arg->area;

	assert(area);

	int level = arg->level;

	area->t_lsp_refresh[level - 1] = NULL;
	area->lsp_regenerate_pending[level - 1] = 0;

	if ((area->is_type & level) == 0)
		return ISIS_ERROR;

	if (monotime_since(&area->last_lsp_refresh_event[level - 1], NULL) < 100000L) {
		sched_debug("ISIS (%s): Still unstable, postpone LSP L%d refresh",
			    area->area_tag, level);
		_lsp_regenerate_schedule(area, level, 0, false,
					 __func__, __FILE__, __LINE__);
		return 0;
	}

	sched_debug(
		"ISIS (%s): LSP L%d refresh timer expired. Refreshing LSP...",
		area->area_tag, level);
	return lsp_regenerate(area, level);
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
		"ISIS (%s): Scheduling regeneration of %s LSPs, %sincluding PSNs"
		" Caller: %s %s:%d",
		area->area_tag, circuit_t2string(level),
		all_pseudo ? "" : "not ",
		func, file, line);

	memcpy(id, isis->sysid, ISIS_SYS_ID_LEN);
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

		if (area->lsp_regenerate_pending[lvl - 1]) {
			struct timeval remain = thread_timer_remain(
				area->t_lsp_refresh[lvl - 1]);
			sched_debug(
				"ISIS (%s): Regeneration is already pending, nothing todo."
				" (Due in %lld.%03lld seconds)",
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
		THREAD_TIMER_OFF(area->t_lsp_refresh[lvl - 1]);
		diff = now - lsp->last_generated;
		if (diff < area->lsp_gen_interval[lvl - 1]) {
			timeout =
				1000 * (area->lsp_gen_interval[lvl - 1] - diff);
			sched_debug(
				"ISIS (%s): Scheduling in %ld ms to match configured lsp_gen_interval",
				area->area_tag, timeout);
		} else {
			/*
			 * lsps are not regenerated if lsp_regenerate function
			 * is called
			 * directly. However if the lsp_regenerate call is
			 * queued for
			 * later execution it works.
			 */
			timeout = 100;
			sched_debug(
				"ISIS (%s): Last generation was more than lsp_gen_interval ago."
				" Scheduling for execution in %ld ms.",
				area->area_tag, timeout);
		}

		area->lsp_regenerate_pending[lvl - 1] = 1;
		thread_add_timer_msec(master, lsp_refresh,
				      &area->lsp_refresh_arg[lvl - 1],
				      timeout,
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

	lsp_clear_data(lsp);
	lsp->tlvs = isis_alloc_tlvs();
	lsp_debug(
		"ISIS (%s): Constructing pseudo LSP %s for interface %s level %d",
		area->area_tag, rawlspid_print(lsp->hdr.lsp_id),
		circuit->interface->name, level);

	lsp->level = level;
	/* RFC3787  section 4 SHOULD not set overload bit in pseudo LSPs */
	lsp->hdr.lsp_bits =
		lsp_bits_generate(level, 0, circuit->area->attached_bit);

	/*
	 * add self to IS neighbours
	 */
	uint8_t ne_id[ISIS_SYS_ID_LEN + 1];

	memcpy(ne_id, isis->sysid, ISIS_SYS_ID_LEN);
	LSP_PSEUDO_ID(ne_id) = 0;

	if (circuit->area->oldmetric) {
		isis_tlvs_add_oldstyle_reach(lsp->tlvs, ne_id, 0);
		lsp_debug(
			"ISIS (%s): Adding %s.%02x as old-style neighbor (self)",
			area->area_tag, sysid_print(ne_id),
			LSP_PSEUDO_ID(ne_id));
	}
	if (circuit->area->newmetric) {
		isis_tlvs_add_extended_reach(lsp->tlvs, ISIS_MT_IPV4_UNICAST,
					     ne_id, 0, circuit->ext);
		lsp_debug(
			"ISIS (%s): Adding %s.%02x as te-style neighbor (self)",
			area->area_tag, sysid_print(ne_id),
			LSP_PSEUDO_ID(ne_id));
	}

	adj_list = list_new();
	isis_adj_build_up_list(circuit->u.bc.adjdb[level - 1], adj_list);

	for (ALL_LIST_ELEMENTS_RO(adj_list, node, adj)) {
		if (!(adj->level & level)) {
			lsp_debug(
				"ISIS (%s): Ignoring neighbor %s, level does not intersect",
				area->area_tag, sysid_print(adj->sysid));
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
				"ISIS (%s): Ignoring neighbor %s, level does not match",
				area->area_tag, sysid_print(adj->sysid));
			continue;
		}

		memcpy(ne_id, adj->sysid, ISIS_SYS_ID_LEN);
		if (circuit->area->oldmetric) {
			isis_tlvs_add_oldstyle_reach(lsp->tlvs, ne_id, 0);
			lsp_debug(
				"ISIS (%s): Adding %s.%02x as old-style neighbor (peer)",
				area->area_tag, sysid_print(ne_id),
				LSP_PSEUDO_ID(ne_id));
		}
		if (circuit->area->newmetric) {
			isis_tlvs_add_extended_reach(lsp->tlvs,
						     ISIS_MT_IPV4_UNICAST,
						     ne_id, 0, circuit->ext);
			lsp_debug(
				"ISIS (%s): Adding %s.%02x as te-style neighbor (peer)",
				area->area_tag, sysid_print(ne_id),
				LSP_PSEUDO_ID(ne_id));
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

	memcpy(lsp_id, isis->sysid, ISIS_SYS_ID_LEN);
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
		      circuit->area->is_type | circuit->area->attached_bit, 0,
		      NULL, level);
	lsp->area = circuit->area;

	lsp_build_pseudo(lsp, circuit, level);
	lsp_pack_pdu(lsp);
	lsp->own_lsp = 1;
	lsp_insert(head, lsp);
	lsp_flood(lsp, NULL);

	refresh_time = lsp_refresh_time(lsp, rem_lifetime);
	THREAD_TIMER_OFF(circuit->u.bc.t_refresh_pseudo_lsp[level - 1]);
	circuit->lsp_regenerate_pending[level - 1] = 0;
	if (level == IS_LEVEL_1)
		thread_add_timer(
			master, lsp_l1_refresh_pseudo, circuit, refresh_time,
			&circuit->u.bc.t_refresh_pseudo_lsp[level - 1]);
	else if (level == IS_LEVEL_2)
		thread_add_timer(
			master, lsp_l2_refresh_pseudo, circuit, refresh_time,
			&circuit->u.bc.t_refresh_pseudo_lsp[level - 1]);

	if (isis->debugs & DEBUG_UPDATE_PACKETS) {
		zlog_debug(
			"ISIS-Upd (%s): Built L%d Pseudo LSP %s, len %" PRIu16
			", seq 0x%08" PRIx32 ", cksum 0x%04" PRIx16
			", lifetime %" PRIu16 "s, refresh %" PRIu16 "s",
			circuit->area->area_tag, level,
			rawlspid_print(lsp->hdr.lsp_id), lsp->hdr.pdu_len,
			lsp->hdr.seqno, lsp->hdr.checksum,
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

	memcpy(lsp_id, isis->sysid, ISIS_SYS_ID_LEN);
	LSP_PSEUDO_ID(lsp_id) = circuit->circuit_id;
	LSP_FRAGMENT(lsp_id) = 0;

	lsp = lsp_search(head, lsp_id);

	if (!lsp) {
		flog_err(EC_LIB_DEVELOPMENT,
			 "lsp_regenerate_pseudo: no l%d LSP %s found!", level,
			 rawlspid_print(lsp_id));
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
		thread_add_timer(
			master, lsp_l1_refresh_pseudo, circuit, refresh_time,
			&circuit->u.bc.t_refresh_pseudo_lsp[level - 1]);
	else if (level == IS_LEVEL_2)
		thread_add_timer(
			master, lsp_l2_refresh_pseudo, circuit, refresh_time,
			&circuit->u.bc.t_refresh_pseudo_lsp[level - 1]);

	if (isis->debugs & DEBUG_UPDATE_PACKETS) {
		zlog_debug(
			"ISIS-Upd (%s): Refreshed L%d Pseudo LSP %s, len %" PRIu16
			", seq 0x%08" PRIx32 ", cksum 0x%04" PRIx16
			", lifetime %" PRIu16 "s, refresh %" PRIu16 "s",
			circuit->area->area_tag, level,
			rawlspid_print(lsp->hdr.lsp_id), lsp->hdr.pdu_len,
			lsp->hdr.seqno, lsp->hdr.checksum,
			lsp->hdr.rem_lifetime, refresh_time);
	}

	return ISIS_OK;
}

/*
 * Something has changed or periodic refresh -> regenerate pseudo LSP
 */
static int lsp_l1_refresh_pseudo(struct thread *thread)
{
	struct isis_circuit *circuit;
	uint8_t id[ISIS_SYS_ID_LEN + 2];

	circuit = THREAD_ARG(thread);

	circuit->u.bc.t_refresh_pseudo_lsp[0] = NULL;
	circuit->lsp_regenerate_pending[0] = 0;

	if ((circuit->u.bc.is_dr[0] == 0)
	    || (circuit->is_type & IS_LEVEL_1) == 0) {
		memcpy(id, isis->sysid, ISIS_SYS_ID_LEN);
		LSP_PSEUDO_ID(id) = circuit->circuit_id;
		LSP_FRAGMENT(id) = 0;
		lsp_purge_pseudo(id, circuit, IS_LEVEL_1);
		return ISIS_ERROR;
	}

	return lsp_regenerate_pseudo(circuit, IS_LEVEL_1);
}

static int lsp_l2_refresh_pseudo(struct thread *thread)
{
	struct isis_circuit *circuit;
	uint8_t id[ISIS_SYS_ID_LEN + 2];

	circuit = THREAD_ARG(thread);

	circuit->u.bc.t_refresh_pseudo_lsp[1] = NULL;
	circuit->lsp_regenerate_pending[1] = 0;

	if ((circuit->u.bc.is_dr[1] == 0)
	    || (circuit->is_type & IS_LEVEL_2) == 0) {
		memcpy(id, isis->sysid, ISIS_SYS_ID_LEN);
		LSP_PSEUDO_ID(id) = circuit->circuit_id;
		LSP_FRAGMENT(id) = 0;
		lsp_purge_pseudo(id, circuit, IS_LEVEL_2);
		return ISIS_ERROR;
	}

	return lsp_regenerate_pseudo(circuit, IS_LEVEL_2);
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

	memcpy(lsp_id, isis->sysid, ISIS_SYS_ID_LEN);
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
			struct timeval remain = thread_timer_remain(
				circuit->u.bc.t_refresh_pseudo_lsp[lvl - 1]);
			sched_debug(
				"ISIS (%s): Regenerate is already pending, nothing todo."
				" (Due in %lld.%03lld seconds)",
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
		THREAD_TIMER_OFF(circuit->u.bc.t_refresh_pseudo_lsp[lvl - 1]);
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
				"ISIS (%s): Last generation was more than lsp_gen_interval ago."
				" Scheduling for execution in %ld ms.",
				area->area_tag, timeout);
		}

		circuit->lsp_regenerate_pending[lvl - 1] = 1;

		if (lvl == IS_LEVEL_1) {
			thread_add_timer_msec(
				master, lsp_l1_refresh_pseudo, circuit, timeout,
				&circuit->u.bc.t_refresh_pseudo_lsp[lvl - 1]);
		} else if (lvl == IS_LEVEL_2) {
			thread_add_timer_msec(
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
int lsp_tick(struct thread *thread)
{
	struct isis_area *area;
	struct isis_lsp *lsp;
	int level;
	uint16_t rem_lifetime;
	bool fabricd_sync_incomplete = false;

	area = THREAD_ARG(thread);
	assert(area);
	area->t_tick = NULL;
	thread_add_timer(master, lsp_tick, area, 1, &area->t_tick);

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
			}

			if (lsp->age_out == 0) {
				zlog_debug(
					"ISIS-Upd (%s): L%u LSP %s seq "
					"0x%08" PRIx32 " aged out",
					area->area_tag, lsp->level,
					rawlspid_print(lsp->hdr.lsp_id),
					lsp->hdr.seqno);

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

	return ISIS_OK;
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
	if (isis->debugs & DEBUG_FLOODING) {
		zlog_debug("Flooding LSP %s%s%s (From %s %s:%d)",
			   rawlspid_print(lsp->hdr.lsp_id),
			   circuit ? " except on " : "",
			   circuit ? circuit->interface->name : "",
			   func, file, line);
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
	return 0;
}

void lsp_init(void)
{
	hook_register(isis_adj_state_change_hook,
		      lsp_handle_adj_state_change);
}
