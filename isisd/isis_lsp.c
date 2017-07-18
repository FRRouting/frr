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

#include "isisd/dict.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/isis_tlv.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_te.h"
#include "isisd/isis_mt.h"

/* staticly assigned vars for printing purposes */
char lsp_bits_string[200]; /* FIXME: enough ? */

static int lsp_l1_refresh(struct thread *thread);
static int lsp_l2_refresh(struct thread *thread);
static int lsp_l1_refresh_pseudo(struct thread *thread);
static int lsp_l2_refresh_pseudo(struct thread *thread);

int lsp_id_cmp(u_char *id1, u_char *id2)
{
	return memcmp(id1, id2, ISIS_SYS_ID_LEN + 2);
}

dict_t *lsp_db_init(void)
{
	dict_t *dict;

	dict = dict_create(DICTCOUNT_T_MAX, (dict_comp_t)lsp_id_cmp);

	return dict;
}

struct isis_lsp *lsp_search(u_char *id, dict_t *lspdb)
{
	dnode_t *node;

#ifdef EXTREME_DEBUG
	dnode_t *dn;

	zlog_debug("searching db");
	for (dn = dict_first(lspdb); dn; dn = dict_next(lspdb, dn)) {
		zlog_debug("%s\t%pX",
			   rawlspid_print((u_char *)dnode_getkey(dn)),
			   dnode_get(dn));
	}
#endif /* EXTREME DEBUG */

	node = dict_lookup(lspdb, id);

	if (node)
		return (struct isis_lsp *)dnode_get(node);

	return NULL;
}

static void lsp_clear_data(struct isis_lsp *lsp)
{
	if (!lsp)
		return;

	if (lsp->tlv_data.hostname)
		isis_dynhn_remove(lsp->lsp_header->lsp_id);

	if (lsp->own_lsp) {
		if (lsp->tlv_data.nlpids)
			XFREE(MTYPE_ISIS_TLV, lsp->tlv_data.nlpids);
		if (lsp->tlv_data.hostname)
			XFREE(MTYPE_ISIS_TLV, lsp->tlv_data.hostname);
		if (lsp->tlv_data.router_id)
			XFREE(MTYPE_ISIS_TLV, lsp->tlv_data.router_id);
	}

	free_tlvs(&lsp->tlv_data);
}

static void lsp_destroy(struct isis_lsp *lsp)
{
	struct listnode *cnode, *lnode, *lnnode;
	struct isis_lsp *lsp_in_list;
	struct isis_circuit *circuit;

	if (!lsp)
		return;

	if (lsp->area->circuit_list) {
		for (ALL_LIST_ELEMENTS_RO(lsp->area->circuit_list, cnode,
					  circuit)) {
			if (circuit->lsp_queue == NULL)
				continue;
			for (ALL_LIST_ELEMENTS(circuit->lsp_queue, lnode,
					       lnnode, lsp_in_list))
				if (lsp_in_list == lsp)
					list_delete_node(circuit->lsp_queue,
							 lnode);
		}
	}
	ISIS_FLAGS_CLEAR_ALL(lsp->SSNflags);
	ISIS_FLAGS_CLEAR_ALL(lsp->SRMflags);

	lsp_clear_data(lsp);

	if (LSP_FRAGMENT(lsp->lsp_header->lsp_id) == 0 && lsp->lspu.frags) {
		list_delete(lsp->lspu.frags);
		lsp->lspu.frags = NULL;
	}

	isis_spf_schedule(lsp->area, lsp->level);

	if (lsp->pdu)
		stream_free(lsp->pdu);
	XFREE(MTYPE_ISIS_LSP, lsp);
}

void lsp_db_destroy(dict_t *lspdb)
{
	dnode_t *dnode, *next;
	struct isis_lsp *lsp;

	dnode = dict_first(lspdb);
	while (dnode) {
		next = dict_next(lspdb, dnode);
		lsp = dnode_get(dnode);
		lsp_destroy(lsp);
		dict_delete_free(lspdb, dnode);
		dnode = next;
	}

	dict_free(lspdb);

	return;
}

/*
 * Remove all the frags belonging to the given lsp
 */
static void lsp_remove_frags(struct list *frags, dict_t *lspdb)
{
	dnode_t *dnode;
	struct listnode *lnode, *lnnode;
	struct isis_lsp *lsp;

	for (ALL_LIST_ELEMENTS(frags, lnode, lnnode, lsp)) {
		dnode = dict_lookup(lspdb, lsp->lsp_header->lsp_id);
		lsp_destroy(lsp);
		dnode_destroy(dict_delete(lspdb, dnode));
	}

	list_delete_all_node(frags);

	return;
}

void lsp_search_and_destroy(u_char *id, dict_t *lspdb)
{
	dnode_t *node;
	struct isis_lsp *lsp;

	node = dict_lookup(lspdb, id);
	if (node) {
		node = dict_delete(lspdb, node);
		lsp = dnode_get(node);
		/*
		 * If this is a zero lsp, remove all the frags now
		 */
		if (LSP_FRAGMENT(lsp->lsp_header->lsp_id) == 0) {
			if (lsp->lspu.frags)
				lsp_remove_frags(lsp->lspu.frags, lspdb);
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
		dnode_destroy(node);
	}
}

/*
 * Compares a LSP to given values
 * Params are given in net order
 */
int lsp_compare(char *areatag, struct isis_lsp *lsp, u_int32_t seq_num,
		u_int16_t checksum, u_int16_t rem_lifetime)
{
	/* no point in double ntohl on seqnum */
	if (lsp->lsp_header->seq_num == seq_num
	    && lsp->lsp_header->checksum == checksum &&
	    /*comparing with 0, no need to do ntohl */
	    ((lsp->lsp_header->rem_lifetime == 0 && rem_lifetime == 0)
	     || (lsp->lsp_header->rem_lifetime != 0 && rem_lifetime != 0))) {
		if (isis->debugs & DEBUG_SNP_PACKETS) {
			zlog_debug(
				"ISIS-Snp (%s): Compare LSP %s seq 0x%08x, cksum 0x%04x,"
				" lifetime %us",
				areatag,
				rawlspid_print(lsp->lsp_header->lsp_id),
				ntohl(lsp->lsp_header->seq_num),
				ntohs(lsp->lsp_header->checksum),
				ntohs(lsp->lsp_header->rem_lifetime));
			zlog_debug(
				"ISIS-Snp (%s):         is equal to ours seq 0x%08x,"
				" cksum 0x%04x, lifetime %us",
				areatag, ntohl(seq_num), ntohs(checksum),
				ntohs(rem_lifetime));
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
	if (ntohl(seq_num) > ntohl(lsp->lsp_header->seq_num)
	    || (ntohl(seq_num) == ntohl(lsp->lsp_header->seq_num)
		&& ((lsp->lsp_header->rem_lifetime != 0 && rem_lifetime == 0)
		    || lsp->lsp_header->checksum != checksum))) {
		if (isis->debugs & DEBUG_SNP_PACKETS) {
			zlog_debug(
				"ISIS-Snp (%s): Compare LSP %s seq 0x%08x, cksum 0x%04x,"
				" lifetime %us",
				areatag,
				rawlspid_print(lsp->lsp_header->lsp_id),
				ntohl(seq_num), ntohs(checksum),
				ntohs(rem_lifetime));
			zlog_debug(
				"ISIS-Snp (%s):       is newer than ours seq 0x%08x, "
				"cksum 0x%04x, lifetime %us",
				areatag, ntohl(lsp->lsp_header->seq_num),
				ntohs(lsp->lsp_header->checksum),
				ntohs(lsp->lsp_header->rem_lifetime));
		}
		return LSP_NEWER;
	}
	if (isis->debugs & DEBUG_SNP_PACKETS) {
		zlog_debug(
			"ISIS-Snp (%s): Compare LSP %s seq 0x%08x, cksum 0x%04x, lifetime %us",
			areatag, rawlspid_print(lsp->lsp_header->lsp_id),
			ntohl(seq_num), ntohs(checksum), ntohs(rem_lifetime));
		zlog_debug(
			"ISIS-Snp (%s):       is older than ours seq 0x%08x,"
			" cksum 0x%04x, lifetime %us",
			areatag, ntohl(lsp->lsp_header->seq_num),
			ntohs(lsp->lsp_header->checksum),
			ntohs(lsp->lsp_header->rem_lifetime));
	}

	return LSP_OLDER;
}

static void lsp_auth_add(struct isis_lsp *lsp)
{
	struct isis_passwd *passwd;
	unsigned char hmac_md5_hash[ISIS_AUTH_MD5_SIZE];

	/*
	 * Add the authentication info if its present
	 */
	(lsp->level == IS_LEVEL_1) ? (passwd = &lsp->area->area_passwd)
				   : (passwd = &lsp->area->domain_passwd);
	switch (passwd->type) {
	/* Cleartext */
	case ISIS_PASSWD_TYPE_CLEARTXT:
		memcpy(&lsp->tlv_data.auth_info, passwd,
		       sizeof(struct isis_passwd));
		tlv_add_authinfo(passwd->type, passwd->len, passwd->passwd,
				 lsp->pdu);
		break;

	/* HMAC MD5 */
	case ISIS_PASSWD_TYPE_HMAC_MD5:
		/* Remember where TLV is written so we can later
		 * overwrite the MD5 hash */
		lsp->auth_tlv_offset = stream_get_endp(lsp->pdu);
		memset(&hmac_md5_hash, 0, ISIS_AUTH_MD5_SIZE);
		lsp->tlv_data.auth_info.type = ISIS_PASSWD_TYPE_HMAC_MD5;
		lsp->tlv_data.auth_info.len = ISIS_AUTH_MD5_SIZE;
		memcpy(&lsp->tlv_data.auth_info.passwd, hmac_md5_hash,
		       ISIS_AUTH_MD5_SIZE);
		tlv_add_authinfo(passwd->type, ISIS_AUTH_MD5_SIZE,
				 hmac_md5_hash, lsp->pdu);
		break;

	default:
		break;
	}
}

static void lsp_auth_update(struct isis_lsp *lsp)
{
	struct isis_passwd *passwd;
	unsigned char hmac_md5_hash[ISIS_AUTH_MD5_SIZE];
	uint16_t checksum, rem_lifetime;

	/* For HMAC MD5 we need to recompute the md5 hash and store it */
	(lsp->level == IS_LEVEL_1) ? (passwd = &lsp->area->area_passwd)
				   : (passwd = &lsp->area->domain_passwd);
	if (passwd->type != ISIS_PASSWD_TYPE_HMAC_MD5)
		return;

	/*
	 * In transient conditions (when net is configured where authentication
	 * config and lsp regenerate schedule is not yet run), there could be
	 * an own_lsp with auth_tlv_offset set to 0. In such a case, simply
	 * return, when lsp_regenerate is run, lsp will have auth tlv.
	 */
	if (lsp->auth_tlv_offset == 0)
		return;

	/*
	 * RFC 5304 set auth value, checksum and remaining lifetime to zero
	 * before computation and reset to old values after computation.
	 */
	checksum = lsp->lsp_header->checksum;
	rem_lifetime = lsp->lsp_header->rem_lifetime;
	lsp->lsp_header->checksum = 0;
	lsp->lsp_header->rem_lifetime = 0;
	/* Set the authentication value as well to zero */
	memset(STREAM_DATA(lsp->pdu) + lsp->auth_tlv_offset + 3, 0,
	       ISIS_AUTH_MD5_SIZE);
	/* Compute autentication value */
	hmac_md5(STREAM_DATA(lsp->pdu), stream_get_endp(lsp->pdu),
		 (unsigned char *)&passwd->passwd, passwd->len,
		 (unsigned char *)&hmac_md5_hash);
	/* Copy the hash into the stream */
	memcpy(STREAM_DATA(lsp->pdu) + lsp->auth_tlv_offset + 3, hmac_md5_hash,
	       ISIS_AUTH_MD5_SIZE);
	memcpy(&lsp->tlv_data.auth_info.passwd, hmac_md5_hash,
	       ISIS_AUTH_MD5_SIZE);
	/* Copy back the checksum and remaining lifetime */
	lsp->lsp_header->checksum = checksum;
	lsp->lsp_header->rem_lifetime = rem_lifetime;
}

void lsp_inc_seqnum(struct isis_lsp *lsp, u_int32_t seq_num)
{
	u_int32_t newseq;

	if (seq_num == 0 || ntohl(lsp->lsp_header->seq_num) > seq_num)
		newseq = ntohl(lsp->lsp_header->seq_num) + 1;
	else
		newseq = seq_num + 1;

	lsp->lsp_header->seq_num = htonl(newseq);

	/* Recompute authentication and checksum information */
	lsp_auth_update(lsp);
	/* ISO 10589 - 7.3.11 Generation of the checksum
	 * The checksum shall be computed over all fields in the LSP which
	 * appear
	 * after the Remaining Lifetime field. This field (and those appearing
	 * before it) are excluded so that the LSP may be aged by systems
	 * without
	 * requiring recomputation.
	 */
	fletcher_checksum(STREAM_DATA(lsp->pdu) + 12,
			  ntohs(lsp->lsp_header->pdu_len) - 12, 12);

	isis_spf_schedule(lsp->area, lsp->level);

	return;
}

/*
 * Genetates checksum for LSP and its frags
 */
static void lsp_seqnum_update(struct isis_lsp *lsp0)
{
	struct isis_lsp *lsp;
	struct listnode *node;

	lsp_inc_seqnum(lsp0, 0);

	if (!lsp0->lspu.frags)
		return;

	for (ALL_LIST_ELEMENTS_RO(lsp0->lspu.frags, node, lsp))
		lsp_inc_seqnum(lsp, 0);

	return;
}

static u_int8_t lsp_bits_generate(int level, int overload_bit, int attached_bit)
{
	u_int8_t lsp_bits = 0;
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

static void lsp_update_data(struct isis_lsp *lsp, struct stream *stream,
			    struct isis_area *area, int level)
{
	uint32_t expected = 0, found;
	int retval;

	/* free the old lsp data */
	lsp_clear_data(lsp);

	/* copying only the relevant part of our stream */
	if (lsp->pdu != NULL)
		stream_free(lsp->pdu);
	lsp->pdu = stream_dup(stream);

	/* setting pointers to the correct place */
	lsp->isis_header = (struct isis_fixed_hdr *)(STREAM_DATA(lsp->pdu));
	lsp->lsp_header = (struct isis_link_state_hdr *)(STREAM_DATA(lsp->pdu)
							 + ISIS_FIXED_HDR_LEN);
	lsp->area = area;
	lsp->level = level;
	lsp->age_out = ZERO_AGE_LIFETIME;
	lsp->installed = time(NULL);
	/*
	 * Get LSP data i.e. TLVs
	 */
	expected |= TLVFLAG_AUTH_INFO;
	expected |= TLVFLAG_AREA_ADDRS;
	expected |= TLVFLAG_IS_NEIGHS;
	expected |= TLVFLAG_NLPID;
	if (area->dynhostname)
		expected |= TLVFLAG_DYN_HOSTNAME;
	if (area->newmetric) {
		expected |= TLVFLAG_TE_IS_NEIGHS;
		expected |= TLVFLAG_TE_IPV4_REACHABILITY;
		expected |= TLVFLAG_TE_ROUTER_ID;
	}
	expected |= TLVFLAG_MT_ROUTER_INFORMATION;
	expected |= TLVFLAG_IPV4_ADDR;
	expected |= TLVFLAG_IPV4_INT_REACHABILITY;
	expected |= TLVFLAG_IPV4_EXT_REACHABILITY;
	expected |= TLVFLAG_IPV6_ADDR;
	expected |= TLVFLAG_IPV6_REACHABILITY;

	retval = parse_tlvs(area->area_tag,
			    STREAM_DATA(lsp->pdu) + ISIS_FIXED_HDR_LEN
				    + ISIS_LSP_HDR_LEN,
			    ntohs(lsp->lsp_header->pdu_len) - ISIS_FIXED_HDR_LEN
				    - ISIS_LSP_HDR_LEN,
			    &expected, &found, &lsp->tlv_data, NULL);
	if (retval != ISIS_OK) {
		zlog_warn("Could not parse LSP");
		return;
	}

	if ((found & TLVFLAG_DYN_HOSTNAME) && (area->dynhostname)) {
		isis_dynhn_insert(lsp->lsp_header->lsp_id,
				  lsp->tlv_data.hostname,
				  (lsp->lsp_header->lsp_bits & LSPBIT_IST)
						  == IS_LEVEL_1_AND_2
					  ? IS_LEVEL_2
					  : IS_LEVEL_1);
	}

	return;
}

void lsp_update(struct isis_lsp *lsp, struct stream *stream,
		struct isis_area *area, int level)
{
	dnode_t *dnode = NULL;

	/* Remove old LSP from database. This is required since the
	 * lsp_update_data will free the lsp->pdu (which has the key, lsp_id)
	 * and will update it with the new data in the stream. */
	dnode = dict_lookup(area->lspdb[level - 1], lsp->lsp_header->lsp_id);
	if (dnode)
		dnode_destroy(dict_delete(area->lspdb[level - 1], dnode));

	if (lsp->own_lsp) {
		zlog_err(
			"ISIS-Upd (%s): BUG updating LSP %s still marked as own LSP",
			area->area_tag,
			rawlspid_print(lsp->lsp_header->lsp_id));
		lsp_clear_data(lsp);
		lsp->own_lsp = 0;
	}

	/* rebuild the lsp data */
	lsp_update_data(lsp, stream, area, level);

	/* insert the lsp back into the database */
	lsp_insert(lsp, area->lspdb[level - 1]);
}

/* creation of LSP directly from what we received */
struct isis_lsp *lsp_new_from_stream_ptr(struct stream *stream,
					 u_int16_t pdu_len,
					 struct isis_lsp *lsp0,
					 struct isis_area *area, int level)
{
	struct isis_lsp *lsp;

	lsp = XCALLOC(MTYPE_ISIS_LSP, sizeof(struct isis_lsp));
	lsp_update_data(lsp, stream, area, level);

	if (lsp0 == NULL) {
		/*
		 * zero lsp -> create the list for fragments
		 */
		lsp->lspu.frags = list_new();
	} else {
		/*
		 * a fragment -> set the backpointer and add this to zero lsps
		 * frag list
		 */
		lsp->lspu.zero_lsp = lsp0;
		listnode_add(lsp0->lspu.frags, lsp);
	}

	return lsp;
}

struct isis_lsp *lsp_new(struct isis_area *area, u_char *lsp_id,
			 u_int16_t rem_lifetime, u_int32_t seq_num,
			 u_int8_t lsp_bits, u_int16_t checksum, int level)
{
	struct isis_lsp *lsp;

	lsp = XCALLOC(MTYPE_ISIS_LSP, sizeof(struct isis_lsp));
	lsp->area = area;

	lsp->pdu = stream_new(LLC_LEN + area->lsp_mtu);
	if (LSP_FRAGMENT(lsp_id) == 0)
		lsp->lspu.frags = list_new();
	lsp->isis_header = (struct isis_fixed_hdr *)(STREAM_DATA(lsp->pdu));
	lsp->lsp_header = (struct isis_link_state_hdr *)(STREAM_DATA(lsp->pdu)
							 + ISIS_FIXED_HDR_LEN);

	/* at first we fill the FIXED HEADER */
	(level == IS_LEVEL_1) ? fill_fixed_hdr(lsp->isis_header, L1_LINK_STATE)
			      : fill_fixed_hdr(lsp->isis_header, L2_LINK_STATE);

	/* now for the LSP HEADER */
	/* Minimal LSP PDU size */
	lsp->lsp_header->pdu_len = htons(ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN);
	memcpy(lsp->lsp_header->lsp_id, lsp_id, ISIS_SYS_ID_LEN + 2);
	lsp->lsp_header->checksum = checksum; /* Provided in network order */
	lsp->lsp_header->seq_num = htonl(seq_num);
	lsp->lsp_header->rem_lifetime = htons(rem_lifetime);
	lsp->lsp_header->lsp_bits = lsp_bits;
	lsp->level = level;
	lsp->age_out = ZERO_AGE_LIFETIME;

	stream_forward_endp(lsp->pdu, ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN);

	if (isis->debugs & DEBUG_EVENTS)
		zlog_debug("New LSP with ID %s-%02x-%02x len %d seqnum %08x",
			   sysid_print(lsp_id),
			   LSP_PSEUDO_ID(lsp->lsp_header->lsp_id),
			   LSP_FRAGMENT(lsp->lsp_header->lsp_id),
			   ntohl(lsp->lsp_header->pdu_len),
			   ntohl(lsp->lsp_header->seq_num));

	return lsp;
}

void lsp_insert(struct isis_lsp *lsp, dict_t *lspdb)
{
	dict_alloc_insert(lspdb, lsp->lsp_header->lsp_id, lsp);
	if (lsp->lsp_header->seq_num != 0) {
		isis_spf_schedule(lsp->area, lsp->level);
	}
}

/*
 * Build a list of LSPs with non-zero ht bounded by start and stop ids
 */
void lsp_build_list_nonzero_ht(u_char *start_id, u_char *stop_id,
			       struct list *list, dict_t *lspdb)
{
	dnode_t *first, *last, *curr;

	first = dict_lower_bound(lspdb, start_id);
	if (!first)
		return;

	last = dict_upper_bound(lspdb, stop_id);

	curr = first;

	if (((struct isis_lsp *)(curr->dict_data))->lsp_header->rem_lifetime)
		listnode_add(list, first->dict_data);

	while (curr) {
		curr = dict_next(lspdb, curr);
		if (curr
		    && ((struct isis_lsp *)(curr->dict_data))
			       ->lsp_header->rem_lifetime)
			listnode_add(list, curr->dict_data);
		if (curr == last)
			break;
	}

	return;
}

/*
 * Build a list of num_lsps LSPs bounded by start_id and stop_id.
 */
void lsp_build_list(u_char *start_id, u_char *stop_id, u_char num_lsps,
		    struct list *list, dict_t *lspdb)
{
	u_char count;
	dnode_t *first, *last, *curr;

	first = dict_lower_bound(lspdb, start_id);
	if (!first)
		return;

	last = dict_upper_bound(lspdb, stop_id);

	curr = first;

	listnode_add(list, first->dict_data);
	count = 1;

	while (curr) {
		curr = dict_next(lspdb, curr);
		if (curr) {
			listnode_add(list, curr->dict_data);
			count++;
		}
		if (count == num_lsps || curr == last)
			break;
	}

	return;
}

/*
 * Build a list of LSPs with SSN flag set for the given circuit
 */
void lsp_build_list_ssn(struct isis_circuit *circuit, u_char num_lsps,
			struct list *list, dict_t *lspdb)
{
	dnode_t *dnode, *next;
	struct isis_lsp *lsp;
	u_char count = 0;

	dnode = dict_first(lspdb);
	while (dnode != NULL) {
		next = dict_next(lspdb, dnode);
		lsp = dnode_get(dnode);
		if (ISIS_CHECK_FLAG(lsp->SSNflags, circuit)) {
			listnode_add(list, lsp);
			++count;
		}
		if (count == num_lsps)
			break;
		dnode = next;
	}

	return;
}

static void lsp_set_time(struct isis_lsp *lsp)
{
	assert(lsp);

	if (lsp->lsp_header->rem_lifetime == 0) {
		if (lsp->age_out > 0)
			lsp->age_out--;
		return;
	}

	lsp->lsp_header->rem_lifetime =
		htons(ntohs(lsp->lsp_header->rem_lifetime) - 1);
}

static void lspid_print(u_char *lsp_id, u_char *trg, char dynhost, char frag)
{
	struct isis_dynhn *dyn = NULL;
	u_char id[SYSID_STRLEN];

	if (dynhost)
		dyn = dynhn_find_by_id(lsp_id);
	else
		dyn = NULL;

	if (dyn)
		sprintf((char *)id, "%.14s", dyn->name.name);
	else if (!memcmp(isis->sysid, lsp_id, ISIS_SYS_ID_LEN) && dynhost)
		sprintf((char *)id, "%.14s", unix_hostname());
	else
		memcpy(id, sysid_print(lsp_id), 15);
	if (frag)
		sprintf((char *)trg, "%s.%02x-%02x", id, LSP_PSEUDO_ID(lsp_id),
			LSP_FRAGMENT(lsp_id));
	else
		sprintf((char *)trg, "%s.%02x", id, LSP_PSEUDO_ID(lsp_id));
}

/* Convert the lsp attribute bits to attribute string */
const char *lsp_bits2string(u_char *lsp_bits)
{
	char *pos = lsp_bits_string;

	if (!*lsp_bits)
		return " none";

	/* we only focus on the default metric */
	pos += sprintf(pos, "%d/",
		       ISIS_MASK_LSP_ATT_DEFAULT_BIT(*lsp_bits) ? 1 : 0);

	pos += sprintf(pos, "%d/",
		       ISIS_MASK_LSP_PARTITION_BIT(*lsp_bits) ? 1 : 0);

	pos += sprintf(pos, "%d", ISIS_MASK_LSP_OL_BIT(*lsp_bits) ? 1 : 0);

	*(pos) = '\0';

	return lsp_bits_string;
}

/* this function prints the lsp on show isis database */
void lsp_print(struct isis_lsp *lsp, struct vty *vty, char dynhost)
{
	u_char LSPid[255];
	char age_out[8];

	lspid_print(lsp->lsp_header->lsp_id, LSPid, dynhost, 1);
	vty_out(vty, "%-21s%c  ", LSPid, lsp->own_lsp ? '*' : ' ');
	vty_out(vty, "%5u   ", ntohs(lsp->lsp_header->pdu_len));
	vty_out(vty, "0x%08x  ", ntohl(lsp->lsp_header->seq_num));
	vty_out(vty, "0x%04x  ", ntohs(lsp->lsp_header->checksum));
	if (ntohs(lsp->lsp_header->rem_lifetime) == 0) {
		snprintf(age_out, 8, "(%u)", lsp->age_out);
		age_out[7] = '\0';
		vty_out(vty, "%7s   ", age_out);
	} else
		vty_out(vty, " %5u    ", ntohs(lsp->lsp_header->rem_lifetime));
	vty_out(vty, "%s\n", lsp_bits2string(&lsp->lsp_header->lsp_bits));
}

static void lsp_print_mt_reach(struct list *list, struct vty *vty, char dynhost,
			       uint16_t mtid)
{
	struct listnode *node;
	struct te_is_neigh *neigh;

	for (ALL_LIST_ELEMENTS_RO(list, node, neigh)) {
		u_char lspid[255];

		lspid_print(neigh->neigh_id, lspid, dynhost, 0);
		if (mtid == ISIS_MT_IPV4_UNICAST) {
			vty_out(vty,
				"  Metric      : %-8u IS-Extended   : %s\n",
				GET_TE_METRIC(neigh), lspid);
		} else {
			vty_out(vty,
				"  Metric      : %-8u MT-Reach      : %s %s\n",
				GET_TE_METRIC(neigh), lspid,
				isis_mtid2str(mtid));
		}
		if (IS_MPLS_TE(isisMplsTE))
			mpls_te_print_detail(vty, neigh);
	}
}

static void lsp_print_mt_ipv6_reach(struct list *list, struct vty *vty,
				    uint16_t mtid)
{
	struct listnode *node;
	struct ipv6_reachability *ipv6_reach;
	struct in6_addr in6;
	u_char buff[BUFSIZ];

	for (ALL_LIST_ELEMENTS_RO(list, node, ipv6_reach)) {
		memset(&in6, 0, sizeof(in6));
		memcpy(in6.s6_addr, ipv6_reach->prefix,
		       PSIZE(ipv6_reach->prefix_len));
		inet_ntop(AF_INET6, &in6, (char *)buff, BUFSIZ);
		if (mtid == ISIS_MT_IPV4_UNICAST) {
			if ((ipv6_reach->control_info & CTRL_INFO_DISTRIBUTION)
			    == DISTRIBUTION_INTERNAL)
				vty_out(vty,
					"  Metric      : %-8" PRIu32
					" IPv6-Internal : %s/%d\n",
					ntohl(ipv6_reach->metric), buff,
					ipv6_reach->prefix_len);
			else
				vty_out(vty,
					"  Metric      : %-8" PRIu32
					" IPv6-External : %s/%d\n",
					ntohl(ipv6_reach->metric), buff,
					ipv6_reach->prefix_len);
		} else {
			if ((ipv6_reach->control_info & CTRL_INFO_DISTRIBUTION)
			    == DISTRIBUTION_INTERNAL)
				vty_out(vty,
					"  Metric      : %-8" PRIu32
					" IPv6-MT-Int   : %s/%d %s\n",
					ntohl(ipv6_reach->metric), buff,
					ipv6_reach->prefix_len,
					isis_mtid2str(mtid));
			else
				vty_out(vty,
					"  Metric      : %-8" PRIu32
					" IPv6-MT-Ext   : %s/%d %s\n",
					ntohl(ipv6_reach->metric), buff,
					ipv6_reach->prefix_len,
					isis_mtid2str(mtid));
		}
	}
}

static void lsp_print_mt_ipv4_reach(struct list *list, struct vty *vty,
				    uint16_t mtid)
{
	struct listnode *node;
	struct te_ipv4_reachability *te_ipv4_reach;

	for (ALL_LIST_ELEMENTS_RO(list, node, te_ipv4_reach)) {
		if (mtid == ISIS_MT_IPV4_UNICAST) {
			/* FIXME: There should be better way to output this
			 * stuff. */
			vty_out(vty,
				"  Metric      : %-8" PRIu32
				" IPv4-Extended : %s/%d\n",
				ntohl(te_ipv4_reach->te_metric),
				inet_ntoa(newprefix2inaddr(
					&te_ipv4_reach->prefix_start,
					te_ipv4_reach->control)),
				te_ipv4_reach->control & 0x3F);
		} else {
			/* FIXME: There should be better way to output this
			 * stuff. */
			vty_out(vty,
				"  Metric      : %-8" PRIu32
				" IPv4-MT       : %s/%d %s\n",
				ntohl(te_ipv4_reach->te_metric),
				inet_ntoa(newprefix2inaddr(
					&te_ipv4_reach->prefix_start,
					te_ipv4_reach->control)),
				te_ipv4_reach->control & 0x3F,
				isis_mtid2str(mtid));
		}
	}
}

void lsp_print_detail(struct isis_lsp *lsp, struct vty *vty, char dynhost)
{
	struct area_addr *area_addr;
	int i;
	struct listnode *lnode;
	struct is_neigh *is_neigh;
	struct ipv4_reachability *ipv4_reach;
	struct in_addr *ipv4_addr;
	struct mt_router_info *mt_router_info;
	struct tlv_mt_ipv6_reachs *mt_ipv6_reachs;
	struct tlv_mt_neighbors *mt_is_neigh;
	struct tlv_mt_ipv4_reachs *mt_ipv4_reachs;
	u_char LSPid[255];
	u_char hostname[255];
	u_char ipv4_reach_prefix[20];
	u_char ipv4_reach_mask[20];
	u_char ipv4_address[20];

	lspid_print(lsp->lsp_header->lsp_id, LSPid, dynhost, 1);
	lsp_print(lsp, vty, dynhost);

	/* for all area address */
	if (lsp->tlv_data.area_addrs)
		for (ALL_LIST_ELEMENTS_RO(lsp->tlv_data.area_addrs, lnode,
					  area_addr)) {
			vty_out(vty, "  Area Address: %s\n",
				isonet_print(area_addr->area_addr,
					     area_addr->addr_len));
		}

	/* for the nlpid tlv */
	if (lsp->tlv_data.nlpids) {
		for (i = 0; i < lsp->tlv_data.nlpids->count; i++) {
			switch (lsp->tlv_data.nlpids->nlpids[i]) {
			case NLPID_IP:
			case NLPID_IPV6:
				vty_out(vty, "  NLPID       : 0x%X\n",
					lsp->tlv_data.nlpids->nlpids[i]);
				break;
			default:
				vty_out(vty, "  NLPID       : %s\n", "unknown");
				break;
			}
		}
	}

	for (ALL_LIST_ELEMENTS_RO(lsp->tlv_data.mt_router_info, lnode,
				  mt_router_info)) {
		vty_out(vty, "  MT          : %s%s\n",
			isis_mtid2str(mt_router_info->mtid),
			mt_router_info->overload ? " (overload)" : "");
	}

	/* for the hostname tlv */
	if (lsp->tlv_data.hostname) {
		bzero(hostname, sizeof(hostname));
		memcpy(hostname, lsp->tlv_data.hostname->name,
		       lsp->tlv_data.hostname->namelen);
		vty_out(vty, "  Hostname    : %s\n", hostname);
	}

	/* authentication tlv */
	if (lsp->tlv_data.auth_info.type != ISIS_PASSWD_TYPE_UNUSED) {
		if (lsp->tlv_data.auth_info.type == ISIS_PASSWD_TYPE_HMAC_MD5)
			vty_out(vty, "  Auth type   : md5\n");
		else if (lsp->tlv_data.auth_info.type
			 == ISIS_PASSWD_TYPE_CLEARTXT)
			vty_out(vty, "  Auth type   : clear text\n");
	}

	/* TE router id */
	if (lsp->tlv_data.router_id) {
		memcpy(ipv4_address, inet_ntoa(lsp->tlv_data.router_id->id),
		       sizeof(ipv4_address));
		vty_out(vty, "  Router ID   : %s\n", ipv4_address);
	}

	if (lsp->tlv_data.ipv4_addrs)
		for (ALL_LIST_ELEMENTS_RO(lsp->tlv_data.ipv4_addrs, lnode,
					  ipv4_addr)) {
			memcpy(ipv4_address, inet_ntoa(*ipv4_addr),
			       sizeof(ipv4_address));
			vty_out(vty, "  IPv4 Address: %s\n", ipv4_address);
		}

	/* for the IS neighbor tlv */
	if (lsp->tlv_data.is_neighs)
		for (ALL_LIST_ELEMENTS_RO(lsp->tlv_data.is_neighs, lnode,
					  is_neigh)) {
			lspid_print(is_neigh->neigh_id, LSPid, dynhost, 0);
			vty_out(vty,
				"  Metric      : %-8" PRIu8
				" IS            : %s\n",
				is_neigh->metrics.metric_default, LSPid);
		}

	/* for the internal reachable tlv */
	if (lsp->tlv_data.ipv4_int_reachs)
		for (ALL_LIST_ELEMENTS_RO(lsp->tlv_data.ipv4_int_reachs, lnode,
					  ipv4_reach)) {
			memcpy(ipv4_reach_prefix, inet_ntoa(ipv4_reach->prefix),
			       sizeof(ipv4_reach_prefix));
			memcpy(ipv4_reach_mask, inet_ntoa(ipv4_reach->mask),
			       sizeof(ipv4_reach_mask));
			vty_out(vty,
				"  Metric      : %-8" PRIu8
				" IPv4-Internal : %s %s\n",
				ipv4_reach->metrics.metric_default,
				ipv4_reach_prefix, ipv4_reach_mask);
		}

	/* for the external reachable tlv */
	if (lsp->tlv_data.ipv4_ext_reachs)
		for (ALL_LIST_ELEMENTS_RO(lsp->tlv_data.ipv4_ext_reachs, lnode,
					  ipv4_reach)) {
			memcpy(ipv4_reach_prefix, inet_ntoa(ipv4_reach->prefix),
			       sizeof(ipv4_reach_prefix));
			memcpy(ipv4_reach_mask, inet_ntoa(ipv4_reach->mask),
			       sizeof(ipv4_reach_mask));
			vty_out(vty,
				"  Metric      : %-8" PRIu8
				" IPv4-External : %s %s\n",
				ipv4_reach->metrics.metric_default,
				ipv4_reach_prefix, ipv4_reach_mask);
		}

	/* IPv6 tlv */
	lsp_print_mt_ipv6_reach(lsp->tlv_data.ipv6_reachs, vty,
				ISIS_MT_IPV4_UNICAST);

	/* MT IPv6 reachability tlv */
	for (ALL_LIST_ELEMENTS_RO(lsp->tlv_data.mt_ipv6_reachs, lnode,
				  mt_ipv6_reachs))
		lsp_print_mt_ipv6_reach(mt_ipv6_reachs->list, vty,
					mt_ipv6_reachs->mtid);

	/* TE IS neighbor tlv */
	lsp_print_mt_reach(lsp->tlv_data.te_is_neighs, vty, dynhost,
			   ISIS_MT_IPV4_UNICAST);

	/* MT IS neighbor tlv */
	for (ALL_LIST_ELEMENTS_RO(lsp->tlv_data.mt_is_neighs, lnode,
				  mt_is_neigh))
		lsp_print_mt_reach(mt_is_neigh->list, vty, dynhost,
				   mt_is_neigh->mtid);

	/* TE IPv4 tlv */
	lsp_print_mt_ipv4_reach(lsp->tlv_data.te_ipv4_reachs, vty,
				ISIS_MT_IPV4_UNICAST);

	/* MT IPv4 reachability tlv */
	for (ALL_LIST_ELEMENTS_RO(lsp->tlv_data.mt_ipv4_reachs, lnode,
				  mt_ipv4_reachs))
		lsp_print_mt_ipv4_reach(mt_ipv4_reachs->list, vty,
					mt_ipv4_reachs->mtid);

	vty_out(vty, "\n");

	return;
}

/* print all the lsps info in the local lspdb */
int lsp_print_all(struct vty *vty, dict_t *lspdb, char detail, char dynhost)
{

	dnode_t *node = dict_first(lspdb), *next;
	int lsp_count = 0;

	if (detail == ISIS_UI_LEVEL_BRIEF) {
		while (node != NULL) {
			/* I think it is unnecessary, so I comment it out */
			/* dict_contains (lspdb, node); */
			next = dict_next(lspdb, node);
			lsp_print(dnode_get(node), vty, dynhost);
			node = next;
			lsp_count++;
		}
	} else if (detail == ISIS_UI_LEVEL_DETAIL) {
		while (node != NULL) {
			next = dict_next(lspdb, node);
			lsp_print_detail(dnode_get(node), vty, dynhost);
			node = next;
			lsp_count++;
		}
	}

	return lsp_count;
}

static void _lsp_tlv_fit(struct isis_lsp *lsp, struct list **from,
			 struct list **to, int frag_thold,
			 unsigned int tlv_build_func(struct list *,
						     struct stream *,
						     void *arg),
			 void *arg)
{
	while (*from && listcount(*from)) {
		unsigned int count;

		count = tlv_build_func(*from, lsp->pdu, arg);

		if (listcount(*to) != 0 || count != listcount(*from)) {
			struct listnode *node, *nnode;
			void *elem;

			for (ALL_LIST_ELEMENTS(*from, node, nnode, elem)) {
				if (!count)
					break;
				listnode_add(*to, elem);
				list_delete_node(*from, node);
				--count;
			}
		} else {
			list_free(*to);
			*to = *from;
			*from = NULL;
		}
	}
}

#define FRAG_THOLD(S, T) ((STREAM_SIZE(S) * T) / 100)

/* stream*, area->lsp_frag_threshold, increment */
#define FRAG_NEEDED(S, T, I)                                                   \
	(STREAM_SIZE(S) - STREAM_REMAIN(S) + (I) > FRAG_THOLD(S, T))

/* FIXME: It shouldn't be necessary to pass tlvsize here, TLVs can have
 * variable length (TE TLVs, sub TLVs). */
static void lsp_tlv_fit(struct isis_lsp *lsp, struct list **from,
			struct list **to, int tlvsize, int frag_thold,
			int tlv_build_func(struct list *, struct stream *))
{
	int count, i;

	/* can we fit all ? */
	if (!FRAG_NEEDED(lsp->pdu, frag_thold,
			 listcount(*from) * tlvsize + 2)) {
		tlv_build_func(*from, lsp->pdu);
		if (listcount(*to) != 0) {
			struct listnode *node, *nextnode;
			void *elem;

			for (ALL_LIST_ELEMENTS(*from, node, nextnode, elem)) {
				listnode_add(*to, elem);
				list_delete_node(*from, node);
			}
		} else {
			list_free(*to);
			*to = *from;
			*from = NULL;
		}
	} else if (!FRAG_NEEDED(lsp->pdu, frag_thold, tlvsize + 2)) {
		/* fit all we can */
		count = FRAG_THOLD(lsp->pdu, frag_thold) - 2
			- (STREAM_SIZE(lsp->pdu) - STREAM_REMAIN(lsp->pdu));
		count = count / tlvsize;
		if (count > (int)listcount(*from))
			count = listcount(*from);
		for (i = 0; i < count; i++) {
			listnode_add(*to, listgetdata(listhead(*from)));
			listnode_delete(*from, listgetdata(listhead(*from)));
		}
		tlv_build_func(*to, lsp->pdu);
	}
	lsp->lsp_header->pdu_len = htons(stream_get_endp(lsp->pdu));
	return;
}

static u_int16_t lsp_rem_lifetime(struct isis_area *area, int level)
{
	u_int16_t rem_lifetime;

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

static u_int16_t lsp_refresh_time(struct isis_lsp *lsp, u_int16_t rem_lifetime)
{
	struct isis_area *area = lsp->area;
	int level = lsp->level;
	u_int16_t refresh_time;

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

static struct isis_lsp *lsp_next_frag(u_char frag_num, struct isis_lsp *lsp0,
				      struct isis_area *area, int level)
{
	struct isis_lsp *lsp;
	u_char frag_id[ISIS_SYS_ID_LEN + 2];

	memcpy(frag_id, lsp0->lsp_header->lsp_id, ISIS_SYS_ID_LEN + 1);
	LSP_FRAGMENT(frag_id) = frag_num;
	/* FIXME add authentication TLV for fragment LSPs */
	lsp = lsp_search(frag_id, area->lspdb[level - 1]);
	if (lsp) {
		/* Clear the TLVs */
		lsp_clear_data(lsp);
		return lsp;
	}
	lsp = lsp_new(area, frag_id, ntohs(lsp0->lsp_header->rem_lifetime), 0,
		      lsp_bits_generate(level, area->overload_bit,
					area->attached_bit),
		      0, level);
	lsp->area = area;
	lsp->own_lsp = 1;
	lsp_insert(lsp, area->lspdb[level - 1]);
	listnode_add(lsp0->lspu.frags, lsp);
	lsp->lspu.zero_lsp = lsp0;
	return lsp;
}

static void lsp_build_ext_reach_ipv4(struct isis_lsp *lsp,
				     struct isis_area *area,
				     struct tlvs *tlv_data)
{
	struct route_table *er_table;
	struct route_node *rn;
	struct prefix_ipv4 *ipv4;
	struct isis_ext_info *info;
	struct ipv4_reachability *ipreach;
	struct te_ipv4_reachability *te_ipreach;

	er_table = get_ext_reach(area, AF_INET, lsp->level);
	if (!er_table)
		return;

	for (rn = route_top(er_table); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;

		ipv4 = (struct prefix_ipv4 *)&rn->p;
		info = rn->info;
		if (area->oldmetric) {
			if (tlv_data->ipv4_ext_reachs == NULL) {
				tlv_data->ipv4_ext_reachs = list_new();
				tlv_data->ipv4_ext_reachs->del = free_tlv;
			}
			ipreach = XMALLOC(MTYPE_ISIS_TLV, sizeof(*ipreach));

			ipreach->prefix.s_addr = ipv4->prefix.s_addr;
			masklen2ip(ipv4->prefixlen, &ipreach->mask);
			ipreach->prefix.s_addr &= ipreach->mask.s_addr;

			if ((info->metric & 0x3f) != info->metric)
				ipreach->metrics.metric_default = 0x3f;
			else
				ipreach->metrics.metric_default = info->metric;
			ipreach->metrics.metric_expense = METRICS_UNSUPPORTED;
			ipreach->metrics.metric_error = METRICS_UNSUPPORTED;
			ipreach->metrics.metric_delay = METRICS_UNSUPPORTED;
			listnode_add(tlv_data->ipv4_ext_reachs, ipreach);
		}
		if (area->newmetric) {
			if (tlv_data->te_ipv4_reachs == NULL) {
				tlv_data->te_ipv4_reachs = list_new();
				tlv_data->te_ipv4_reachs->del = free_tlv;
			}
			te_ipreach = XCALLOC(MTYPE_ISIS_TLV,
					     sizeof(*te_ipreach) - 1
						     + PSIZE(ipv4->prefixlen));
			if (info->metric > MAX_WIDE_PATH_METRIC)
				te_ipreach->te_metric =
					htonl(MAX_WIDE_PATH_METRIC);
			else
				te_ipreach->te_metric = htonl(info->metric);
			te_ipreach->control = ipv4->prefixlen & 0x3f;
			memcpy(&te_ipreach->prefix_start, &ipv4->prefix.s_addr,
			       PSIZE(ipv4->prefixlen));
			listnode_add(tlv_data->te_ipv4_reachs, te_ipreach);
		}
	}
}

static struct list *tlv_get_ipv6_reach_list(struct isis_area *area,
					    struct tlvs *tlv_data)
{
	uint16_t mtid = isis_area_ipv6_topology(area);
	if (mtid == ISIS_MT_IPV4_UNICAST) {
		if (!tlv_data->ipv6_reachs) {
			tlv_data->ipv6_reachs = list_new();
			tlv_data->ipv6_reachs->del = free_tlv;
		}
		return tlv_data->ipv6_reachs;
	}

	struct tlv_mt_ipv6_reachs *reachs =
		tlvs_get_mt_ipv6_reachs(tlv_data, mtid);
	return reachs->list;
}

static void lsp_build_ext_reach_ipv6(struct isis_lsp *lsp,
				     struct isis_area *area,
				     struct tlvs *tlv_data)
{
	struct route_table *er_table;
	struct route_node *rn;
	struct prefix_ipv6 *ipv6;
	struct isis_ext_info *info;
	struct ipv6_reachability *ip6reach;
	struct list *reach_list = NULL;

	er_table = get_ext_reach(area, AF_INET6, lsp->level);
	if (!er_table)
		return;

	for (rn = route_top(er_table); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;

		ipv6 = (struct prefix_ipv6 *)&rn->p;
		info = rn->info;

		if (!reach_list)
			reach_list = tlv_get_ipv6_reach_list(area, tlv_data);

		ip6reach = XCALLOC(MTYPE_ISIS_TLV, sizeof(*ip6reach));
		if (info->metric > MAX_WIDE_PATH_METRIC)
			ip6reach->metric = htonl(MAX_WIDE_PATH_METRIC);
		else
			ip6reach->metric = htonl(info->metric);
		ip6reach->control_info = DISTRIBUTION_EXTERNAL;
		ip6reach->prefix_len = ipv6->prefixlen;
		memcpy(ip6reach->prefix, ipv6->prefix.s6_addr,
		       sizeof(ip6reach->prefix));
		listnode_add(reach_list, ip6reach);
	}
}

static void lsp_build_ext_reach(struct isis_lsp *lsp, struct isis_area *area,
				struct tlvs *tlv_data)
{
	lsp_build_ext_reach_ipv4(lsp, area, tlv_data);
	lsp_build_ext_reach_ipv6(lsp, area, tlv_data);
}

/*
 * Builds the LSP data part. This func creates a new frag whenever
 * area->lsp_frag_threshold is exceeded.
 */
static void lsp_build(struct isis_lsp *lsp, struct isis_area *area)
{
	struct is_neigh *is_neigh;
	struct te_is_neigh *te_is_neigh;
	struct listnode *node, *ipnode;
	int level = lsp->level;
	struct isis_circuit *circuit;
	struct prefix_ipv4 *ipv4;
	struct ipv4_reachability *ipreach;
	struct te_ipv4_reachability *te_ipreach;
	struct isis_adjacency *nei;
	struct prefix_ipv6 *ipv6, ip6prefix;
	struct list *ipv6_reachs = NULL;
	struct ipv6_reachability *ip6reach;
	struct tlvs tlv_data;
	struct isis_lsp *lsp0 = lsp;
	struct in_addr *routerid;
	uint32_t expected = 0, found = 0;
	uint32_t metric;
	u_char zero_id[ISIS_SYS_ID_LEN + 1];
	int retval = ISIS_OK;
	char buf[BUFSIZ];

	lsp_debug("ISIS (%s): Constructing local system LSP for level %d",
		  area->area_tag, level);

	/*
	 * Building the zero lsp
	 */
	memset(zero_id, 0, ISIS_SYS_ID_LEN + 1);

	/* Reset stream endp. Stream is always there and on every LSP refresh
	 * only
	 * TLV part of it is overwritten. So we must seek past header we will
	 * not
	 * touch. */
	stream_reset(lsp->pdu);
	stream_forward_endp(lsp->pdu, ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN);

	/*
	 * Add the authentication info if its present
	 */
	lsp_auth_add(lsp);

	/*
	 * First add the tlvs related to area
	 */

	/* Area addresses */
	if (lsp->tlv_data.area_addrs == NULL)
		lsp->tlv_data.area_addrs = list_new();
	list_add_list(lsp->tlv_data.area_addrs, area->area_addrs);
	if (listcount(lsp->tlv_data.area_addrs) > 0)
		tlv_add_area_addrs(lsp->tlv_data.area_addrs, lsp->pdu);

	/* Protocols Supported */
	if (area->ip_circuits > 0 || area->ipv6_circuits > 0) {
		lsp->tlv_data.nlpids =
			XCALLOC(MTYPE_ISIS_TLV, sizeof(struct nlpids));
		lsp->tlv_data.nlpids->count = 0;
		if (area->ip_circuits > 0) {
			lsp_debug(
				"ISIS (%s): Found IPv4 circuit, adding IPv4 to NLPIDs",
				area->area_tag);
			lsp->tlv_data.nlpids->count++;
			lsp->tlv_data.nlpids->nlpids[0] = NLPID_IP;
		}
		if (area->ipv6_circuits > 0) {
			lsp_debug(
				"ISIS (%s): Found IPv6 circuit, adding IPv6 to NLPIDs",
				area->area_tag);
			lsp->tlv_data.nlpids->count++;
			lsp->tlv_data.nlpids
				->nlpids[lsp->tlv_data.nlpids->count - 1] =
				NLPID_IPV6;
		}
		tlv_add_nlpid(lsp->tlv_data.nlpids, lsp->pdu);
	}

	if (area_is_mt(area)) {
		lsp_debug("ISIS (%s): Adding MT router tlv...", area->area_tag);
		lsp->tlv_data.mt_router_info = list_new();
		lsp->tlv_data.mt_router_info->del = free_tlv;

		struct isis_area_mt_setting **mt_settings;
		unsigned int mt_count;

		mt_settings = area_mt_settings(area, &mt_count);
		for (unsigned int i = 0; i < mt_count; i++) {
			struct mt_router_info *info;

			info = XCALLOC(MTYPE_ISIS_TLV, sizeof(*info));
			info->mtid = mt_settings[i]->mtid;
			info->overload = mt_settings[i]->overload;
			listnode_add(lsp->tlv_data.mt_router_info, info);
			lsp_debug("ISIS (%s):   MT %s", area->area_tag,
				  isis_mtid2str(info->mtid));
		}
		tlv_add_mt_router_info(lsp->tlv_data.mt_router_info, lsp->pdu);
	} else {
		lsp_debug("ISIS (%s): Not adding MT router tlv (disabled)",
			  area->area_tag);
	}
	/* Dynamic Hostname */
	if (area->dynhostname) {
		const char *hostname = unix_hostname();
		size_t hostname_len = strlen(hostname);

		lsp->tlv_data.hostname =
			XMALLOC(MTYPE_ISIS_TLV, sizeof(struct hostname));

		strncpy((char *)lsp->tlv_data.hostname->name, hostname,
			sizeof(lsp->tlv_data.hostname->name));
		if (hostname_len <= MAX_TLV_LEN)
			lsp->tlv_data.hostname->namelen = hostname_len;
		else
			lsp->tlv_data.hostname->namelen = MAX_TLV_LEN;

		lsp_debug("ISIS (%s): Adding dynamic hostname '%.*s'",
			  area->area_tag, lsp->tlv_data.hostname->namelen,
			  lsp->tlv_data.hostname->name);
		tlv_add_dynamic_hostname(lsp->tlv_data.hostname, lsp->pdu);
	} else {
		lsp_debug("ISIS (%s): Not adding dynamic hostname (disabled)",
			  area->area_tag);
	}

	/* IPv4 address and TE router ID TLVs. In case of the first one we don't
	 * follow "C" vendor, but "J" vendor behavior - one IPv4 address is put
	 * into
	 * LSP and this address is same as router id. */
	if (isis->router_id != 0) {
		inet_ntop(AF_INET, &isis->router_id, buf, sizeof(buf));
		lsp_debug("ISIS (%s): Adding router ID %s as IPv4 tlv.",
			  area->area_tag, buf);
		if (lsp->tlv_data.ipv4_addrs == NULL) {
			lsp->tlv_data.ipv4_addrs = list_new();
			lsp->tlv_data.ipv4_addrs->del = free_tlv;
		}

		routerid = XMALLOC(MTYPE_ISIS_TLV, sizeof(struct in_addr));
		routerid->s_addr = isis->router_id;
		listnode_add(lsp->tlv_data.ipv4_addrs, routerid);
		tlv_add_in_addr(routerid, lsp->pdu, IPV4_ADDR);

		/* Exactly same data is put into TE router ID TLV, but only if
		 * new style
		 * TLV's are in use. */
		if (area->newmetric) {
			lsp_debug(
				"ISIS (%s): Adding router ID also as TE router ID tlv.",
				area->area_tag);
			lsp->tlv_data.router_id =
				XMALLOC(MTYPE_ISIS_TLV, sizeof(struct in_addr));
			lsp->tlv_data.router_id->id.s_addr = isis->router_id;
			tlv_add_in_addr(&lsp->tlv_data.router_id->id, lsp->pdu,
					TE_ROUTER_ID);
		}
	} else {
		lsp_debug("ISIS (%s): Router ID is unset. Not adding tlv.",
			  area->area_tag);
	}

	memset(&tlv_data, 0, sizeof(struct tlvs));

	lsp_debug("ISIS (%s): Adding circuit specific information.",
		  area->area_tag);

	/*
	 * Then build lists of tlvs related to circuits
	 */
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

		/*
		 * Add IPv4 internal reachability of this circuit
		 */
		if (circuit->ip_router && circuit->ip_addrs
		    && circuit->ip_addrs->count > 0) {
			lsp_debug(
				"ISIS (%s): Circuit has IPv4 active, adding respective TLVs.",
				area->area_tag);
			if (area->oldmetric) {
				if (tlv_data.ipv4_int_reachs == NULL) {
					tlv_data.ipv4_int_reachs = list_new();
					tlv_data.ipv4_int_reachs->del =
						free_tlv;
				}
				for (ALL_LIST_ELEMENTS_RO(circuit->ip_addrs,
							  ipnode, ipv4)) {
					ipreach = XMALLOC(
						MTYPE_ISIS_TLV,
						sizeof(struct
						       ipv4_reachability));
					ipreach->metrics.metric_default =
						circuit->metric[level - 1];
					ipreach->metrics.metric_expense =
						METRICS_UNSUPPORTED;
					ipreach->metrics.metric_error =
						METRICS_UNSUPPORTED;
					ipreach->metrics.metric_delay =
						METRICS_UNSUPPORTED;
					masklen2ip(ipv4->prefixlen,
						   &ipreach->mask);
					ipreach->prefix.s_addr =
						((ipreach->mask.s_addr)
						 & (ipv4->prefix.s_addr));
					inet_ntop(AF_INET,
						  &ipreach->prefix.s_addr, buf,
						  sizeof(buf));
					lsp_debug(
						"ISIS (%s): Adding old-style IP reachability for %s/%d",
						area->area_tag, buf,
						ipv4->prefixlen);
					listnode_add(tlv_data.ipv4_int_reachs,
						     ipreach);
				}
			}
			if (area->newmetric) {
				if (tlv_data.te_ipv4_reachs == NULL) {
					tlv_data.te_ipv4_reachs = list_new();
					tlv_data.te_ipv4_reachs->del = free_tlv;
				}
				for (ALL_LIST_ELEMENTS_RO(circuit->ip_addrs,
							  ipnode, ipv4)) {
					/* FIXME All this assumes that we have
					 * no sub TLVs. */
					te_ipreach = XCALLOC(
						MTYPE_ISIS_TLV,
						sizeof(struct
						       te_ipv4_reachability)
							+ ((ipv4->prefixlen + 7)
							   / 8)
							- 1);

					if (area->oldmetric)
						te_ipreach->te_metric = htonl(
							circuit->metric[level
									- 1]);
					else
						te_ipreach->te_metric = htonl(
							circuit->te_metric
								[level - 1]);

					te_ipreach->control =
						(ipv4->prefixlen & 0x3F);
					memcpy(&te_ipreach->prefix_start,
					       &ipv4->prefix.s_addr,
					       (ipv4->prefixlen + 7) / 8);
					inet_ntop(AF_INET, &ipv4->prefix.s_addr,
						  buf, sizeof(buf));
					lsp_debug(
						"ISIS (%s): Adding te-style IP reachability for %s/%d",
						area->area_tag, buf,
						ipv4->prefixlen);
					listnode_add(tlv_data.te_ipv4_reachs,
						     te_ipreach);
				}
			}
		}

		/*
		 * Add IPv6 reachability of this circuit
		 */
		if (circuit->ipv6_router && circuit->ipv6_non_link
		    && circuit->ipv6_non_link->count > 0) {
			if (!ipv6_reachs)
				ipv6_reachs = tlv_get_ipv6_reach_list(
					area, &tlv_data);

			for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_non_link,
						  ipnode, ipv6)) {
				ip6reach = XCALLOC(
					MTYPE_ISIS_TLV,
					sizeof(struct ipv6_reachability));

				if (area->oldmetric)
					ip6reach->metric = htonl(
						circuit->metric[level - 1]);
				else
					ip6reach->metric = htonl(
						circuit->te_metric[level - 1]);

				ip6reach->control_info = 0;
				ip6reach->prefix_len = ipv6->prefixlen;
				memcpy(&ip6prefix, ipv6, sizeof(ip6prefix));
				apply_mask_ipv6(&ip6prefix);

				inet_ntop(AF_INET6, &ip6prefix.prefix.s6_addr,
					  buf, sizeof(buf));
				lsp_debug(
					"ISIS (%s): Adding IPv6 reachability for %s/%d",
					area->area_tag, buf, ipv6->prefixlen);

				memcpy(ip6reach->prefix,
				       ip6prefix.prefix.s6_addr,
				       sizeof(ip6reach->prefix));
				listnode_add(ipv6_reachs, ip6reach);
			}
		}

		switch (circuit->circ_type) {
		case CIRCUIT_T_BROADCAST:
			if (level & circuit->is_type) {
				if (area->oldmetric) {
					if (tlv_data.is_neighs == NULL) {
						tlv_data.is_neighs = list_new();
						tlv_data.is_neighs->del =
							free_tlv;
					}
					is_neigh = XCALLOC(
						MTYPE_ISIS_TLV,
						sizeof(struct is_neigh));
					if (level == IS_LEVEL_1)
						memcpy(is_neigh->neigh_id,
						       circuit->u.bc
							       .l1_desig_is,
						       ISIS_SYS_ID_LEN + 1);
					else
						memcpy(is_neigh->neigh_id,
						       circuit->u.bc
							       .l2_desig_is,
						       ISIS_SYS_ID_LEN + 1);
					is_neigh->metrics.metric_default =
						circuit->metric[level - 1];
					is_neigh->metrics.metric_expense =
						METRICS_UNSUPPORTED;
					is_neigh->metrics.metric_error =
						METRICS_UNSUPPORTED;
					is_neigh->metrics.metric_delay =
						METRICS_UNSUPPORTED;
					if (!memcmp(is_neigh->neigh_id, zero_id,
						    ISIS_SYS_ID_LEN + 1)) {
						XFREE(MTYPE_ISIS_TLV, is_neigh);
						lsp_debug(
							"ISIS (%s): No DIS for circuit, not adding old-style IS neighbor.",
							area->area_tag);
					} else {
						listnode_add(tlv_data.is_neighs,
							     is_neigh);
						lsp_debug(
							"ISIS (%s): Adding DIS %s.%02x as old-style neighbor",
							area->area_tag,
							sysid_print(
								is_neigh->neigh_id),
							LSP_PSEUDO_ID(
								is_neigh->neigh_id));
					}
				}
				if (area->newmetric) {
					if (tlv_data.te_is_neighs == NULL) {
						tlv_data.te_is_neighs =
							list_new();
						tlv_data.te_is_neighs->del =
							free_tlv;
					}
					te_is_neigh = XCALLOC(
						MTYPE_ISIS_TLV,
						sizeof(struct te_is_neigh));
					if (level == IS_LEVEL_1)
						memcpy(te_is_neigh->neigh_id,
						       circuit->u.bc
							       .l1_desig_is,
						       ISIS_SYS_ID_LEN + 1);
					else
						memcpy(te_is_neigh->neigh_id,
						       circuit->u.bc
							       .l2_desig_is,
						       ISIS_SYS_ID_LEN + 1);
					if (area->oldmetric)
						metric = circuit->metric[level
									 - 1];
					else
						metric =
							circuit->te_metric[level
									   - 1];
					SET_TE_METRIC(te_is_neigh, metric);
					if (!memcmp(te_is_neigh->neigh_id,
						    zero_id,
						    ISIS_SYS_ID_LEN + 1)) {
						XFREE(MTYPE_ISIS_TLV,
						      te_is_neigh);
						lsp_debug(
							"ISIS (%s): No DIS for circuit, not adding te-style IS neighbor.",
							area->area_tag);
					} else {
						/* Check if MPLS_TE is activate
						 */
						if (IS_MPLS_TE(isisMplsTE)
						    && HAS_LINK_PARAMS(
							       circuit->interface))
							/* Add SubTLVs & Adjust
							 * real size of SubTLVs
							 */
							te_is_neigh
								->sub_tlvs_length = add_te_subtlvs(
								te_is_neigh
									->sub_tlvs,
								circuit->mtc);
						else
							/* Or keep only TE
							 * metric with no
							 * SubTLVs if MPLS_TE is
							 * off */
							te_is_neigh
								->sub_tlvs_length =
								0;

						tlvs_add_mt_bcast(
							&tlv_data, circuit,
							level, te_is_neigh);
						XFREE(MTYPE_ISIS_TLV,
						      te_is_neigh);
					}
				}
			} else {
				lsp_debug(
					"ISIS (%s): Circuit is not active for current level. Not adding IS neighbors",
					area->area_tag);
			}
			break;
		case CIRCUIT_T_P2P:
			nei = circuit->u.p2p.neighbor;
			if (nei && (level & nei->circuit_t)) {
				if (area->oldmetric) {
					if (tlv_data.is_neighs == NULL) {
						tlv_data.is_neighs = list_new();
						tlv_data.is_neighs->del =
							free_tlv;
					}
					is_neigh = XCALLOC(
						MTYPE_ISIS_TLV,
						sizeof(struct is_neigh));
					memcpy(is_neigh->neigh_id, nei->sysid,
					       ISIS_SYS_ID_LEN);
					is_neigh->metrics.metric_default =
						circuit->metric[level - 1];
					is_neigh->metrics.metric_expense =
						METRICS_UNSUPPORTED;
					is_neigh->metrics.metric_error =
						METRICS_UNSUPPORTED;
					is_neigh->metrics.metric_delay =
						METRICS_UNSUPPORTED;
					listnode_add(tlv_data.is_neighs,
						     is_neigh);
					lsp_debug(
						"ISIS (%s): Adding old-style is reach for %s",
						area->area_tag,
						sysid_print(
							is_neigh->neigh_id));
				}
				if (area->newmetric) {
					uint32_t metric;

					if (tlv_data.te_is_neighs == NULL) {
						tlv_data.te_is_neighs =
							list_new();
						tlv_data.te_is_neighs->del =
							free_tlv;
					}
					te_is_neigh = XCALLOC(
						MTYPE_ISIS_TLV,
						sizeof(struct te_is_neigh));
					memcpy(te_is_neigh->neigh_id,
					       nei->sysid, ISIS_SYS_ID_LEN);
					metric = circuit->te_metric[level - 1];
					SET_TE_METRIC(te_is_neigh, metric);
					/* Check if MPLS_TE is activate */
					if (IS_MPLS_TE(isisMplsTE)
					    && HAS_LINK_PARAMS(
						       circuit->interface))
						/* Update Local and Remote IP
						 * address for MPLS TE circuit
						 * parameters */
						/* NOTE sure that it is the
						 * pertinent place for that
						 * updates */
						/* Local IP address could be
						 * updated in isis_circuit.c -
						 * isis_circuit_add_addr() */
						/* But, where update remote IP
						 * address ? in isis_pdu.c -
						 * process_p2p_hello() ? */

						/* Add SubTLVs & Adjust real
						 * size of SubTLVs */
						te_is_neigh->sub_tlvs_length =
							add_te_subtlvs(
								te_is_neigh
									->sub_tlvs,
								circuit->mtc);
					else
						/* Or keep only TE metric with
						 * no SubTLVs if MPLS_TE is off
						 */
						te_is_neigh->sub_tlvs_length =
							0;

					tlvs_add_mt_p2p(&tlv_data, circuit,
							te_is_neigh);
					XFREE(MTYPE_ISIS_TLV, te_is_neigh);
				}
			} else {
				lsp_debug(
					"ISIS (%s): No adjacency for given level on this circuit. Not adding IS neighbors",
					area->area_tag);
			}
			break;
		case CIRCUIT_T_LOOPBACK:
			break;
		default:
			zlog_warn("lsp_area_create: unknown circuit type");
		}
	}

	lsp_build_ext_reach(lsp, area, &tlv_data);

	lsp_debug("ISIS (%s): LSP construction is complete. Serializing...",
		  area->area_tag);

	while (tlv_data.ipv4_int_reachs
	       && listcount(tlv_data.ipv4_int_reachs)) {
		if (lsp->tlv_data.ipv4_int_reachs == NULL)
			lsp->tlv_data.ipv4_int_reachs = list_new();
		lsp_tlv_fit(lsp, &tlv_data.ipv4_int_reachs,
			    &lsp->tlv_data.ipv4_int_reachs, IPV4_REACH_LEN,
			    area->lsp_frag_threshold, tlv_add_ipv4_int_reachs);
		if (tlv_data.ipv4_int_reachs
		    && listcount(tlv_data.ipv4_int_reachs))
			lsp = lsp_next_frag(
				LSP_FRAGMENT(lsp->lsp_header->lsp_id) + 1, lsp0,
				area, level);
	}

	while (tlv_data.ipv4_ext_reachs
	       && listcount(tlv_data.ipv4_ext_reachs)) {
		if (lsp->tlv_data.ipv4_ext_reachs == NULL)
			lsp->tlv_data.ipv4_ext_reachs = list_new();
		lsp_tlv_fit(lsp, &tlv_data.ipv4_ext_reachs,
			    &lsp->tlv_data.ipv4_ext_reachs, IPV4_REACH_LEN,
			    area->lsp_frag_threshold, tlv_add_ipv4_ext_reachs);
		if (tlv_data.ipv4_ext_reachs
		    && listcount(tlv_data.ipv4_ext_reachs))
			lsp = lsp_next_frag(
				LSP_FRAGMENT(lsp->lsp_header->lsp_id) + 1, lsp0,
				area, level);
	}

	while (tlv_data.te_ipv4_reachs && listcount(tlv_data.te_ipv4_reachs)) {
		if (lsp->tlv_data.te_ipv4_reachs == NULL)
			lsp->tlv_data.te_ipv4_reachs = list_new();
		_lsp_tlv_fit(lsp, &tlv_data.te_ipv4_reachs,
			     &lsp->tlv_data.te_ipv4_reachs,
			     area->lsp_frag_threshold, tlv_add_te_ipv4_reachs,
			     NULL);
		if (tlv_data.te_ipv4_reachs
		    && listcount(tlv_data.te_ipv4_reachs))
			lsp = lsp_next_frag(
				LSP_FRAGMENT(lsp->lsp_header->lsp_id) + 1, lsp0,
				area, level);
	}

	struct tlv_mt_ipv4_reachs *mt_ipv4_reachs;
	for (ALL_LIST_ELEMENTS_RO(tlv_data.mt_ipv4_reachs, node,
				  mt_ipv4_reachs)) {
		while (mt_ipv4_reachs->list
		       && listcount(mt_ipv4_reachs->list)) {
			struct tlv_mt_ipv4_reachs *frag_mt_ipv4_reachs;

			frag_mt_ipv4_reachs = tlvs_get_mt_ipv4_reachs(
				&lsp->tlv_data, mt_ipv4_reachs->mtid);
			_lsp_tlv_fit(lsp, &mt_ipv4_reachs->list,
				     &frag_mt_ipv4_reachs->list,
				     area->lsp_frag_threshold,
				     tlv_add_te_ipv4_reachs,
				     &mt_ipv4_reachs->mtid);
			if (mt_ipv4_reachs->list
			    && listcount(mt_ipv4_reachs->list))
				lsp = lsp_next_frag(
					LSP_FRAGMENT(lsp->lsp_header->lsp_id)
						+ 1,
					lsp0, area, level);
		}
	}

	while (tlv_data.ipv6_reachs && listcount(tlv_data.ipv6_reachs)) {
		if (lsp->tlv_data.ipv6_reachs == NULL)
			lsp->tlv_data.ipv6_reachs = list_new();
		_lsp_tlv_fit(
			lsp, &tlv_data.ipv6_reachs, &lsp->tlv_data.ipv6_reachs,
			area->lsp_frag_threshold, tlv_add_ipv6_reachs, NULL);
		if (tlv_data.ipv6_reachs && listcount(tlv_data.ipv6_reachs))
			lsp = lsp_next_frag(
				LSP_FRAGMENT(lsp->lsp_header->lsp_id) + 1, lsp0,
				area, level);
	}

	struct tlv_mt_ipv6_reachs *mt_ipv6_reachs;
	for (ALL_LIST_ELEMENTS_RO(tlv_data.mt_ipv6_reachs, node,
				  mt_ipv6_reachs)) {
		while (mt_ipv6_reachs->list
		       && listcount(mt_ipv6_reachs->list)) {
			struct tlv_mt_ipv6_reachs *frag_mt_ipv6_reachs;

			frag_mt_ipv6_reachs = tlvs_get_mt_ipv6_reachs(
				&lsp->tlv_data, mt_ipv6_reachs->mtid);
			_lsp_tlv_fit(lsp, &mt_ipv6_reachs->list,
				     &frag_mt_ipv6_reachs->list,
				     area->lsp_frag_threshold,
				     tlv_add_ipv6_reachs,
				     &mt_ipv6_reachs->mtid);
			if (mt_ipv6_reachs->list
			    && listcount(mt_ipv6_reachs->list))
				lsp = lsp_next_frag(
					LSP_FRAGMENT(lsp->lsp_header->lsp_id)
						+ 1,
					lsp0, area, level);
		}
	}

	while (tlv_data.is_neighs && listcount(tlv_data.is_neighs)) {
		if (lsp->tlv_data.is_neighs == NULL)
			lsp->tlv_data.is_neighs = list_new();
		lsp_tlv_fit(lsp, &tlv_data.is_neighs, &lsp->tlv_data.is_neighs,
			    IS_NEIGHBOURS_LEN, area->lsp_frag_threshold,
			    tlv_add_is_neighs);
		if (tlv_data.is_neighs && listcount(tlv_data.is_neighs))
			lsp = lsp_next_frag(
				LSP_FRAGMENT(lsp->lsp_header->lsp_id) + 1, lsp0,
				area, level);
	}

	while (tlv_data.te_is_neighs && listcount(tlv_data.te_is_neighs)) {
		if (lsp->tlv_data.te_is_neighs == NULL)
			lsp->tlv_data.te_is_neighs = list_new();
		_lsp_tlv_fit(lsp, &tlv_data.te_is_neighs,
			     &lsp->tlv_data.te_is_neighs,
			     area->lsp_frag_threshold, tlv_add_te_is_neighs,
			     NULL);
		if (tlv_data.te_is_neighs && listcount(tlv_data.te_is_neighs))
			lsp = lsp_next_frag(
				LSP_FRAGMENT(lsp->lsp_header->lsp_id) + 1, lsp0,
				area, level);
	}

	struct tlv_mt_neighbors *mt_neighs;
	for (ALL_LIST_ELEMENTS_RO(tlv_data.mt_is_neighs, node, mt_neighs)) {
		while (mt_neighs->list && listcount(mt_neighs->list)) {
			struct tlv_mt_neighbors *frag_mt_neighs;

			frag_mt_neighs = tlvs_get_mt_neighbors(&lsp->tlv_data,
							       mt_neighs->mtid);
			_lsp_tlv_fit(lsp, &mt_neighs->list,
				     &frag_mt_neighs->list,
				     area->lsp_frag_threshold,
				     tlv_add_te_is_neighs, &mt_neighs->mtid);
			if (mt_neighs->list && listcount(mt_neighs->list))
				lsp = lsp_next_frag(
					LSP_FRAGMENT(lsp->lsp_header->lsp_id)
						+ 1,
					lsp0, area, level);
		}
	}


	lsp->lsp_header->pdu_len = htons(stream_get_endp(lsp->pdu));

	free_tlvs(&tlv_data);

	/* Validate the LSP */
	retval = parse_tlvs(area->area_tag,
			    STREAM_DATA(lsp->pdu) + ISIS_FIXED_HDR_LEN
				    + ISIS_LSP_HDR_LEN,
			    stream_get_endp(lsp->pdu) - ISIS_FIXED_HDR_LEN
				    - ISIS_LSP_HDR_LEN,
			    &expected, &found, &tlv_data, NULL);
	assert(retval == ISIS_OK);

	return;
}

/*
 * 7.3.7 and 7.3.9 Generation on non-pseudonode LSPs
 */
int lsp_generate(struct isis_area *area, int level)
{
	struct isis_lsp *oldlsp, *newlsp;
	u_int32_t seq_num = 0;
	u_char lspid[ISIS_SYS_ID_LEN + 2];
	u_int16_t rem_lifetime, refresh_time;

	if ((area == NULL) || (area->is_type & level) != level)
		return ISIS_ERROR;

	memset(&lspid, 0, ISIS_SYS_ID_LEN + 2);
	memcpy(&lspid, isis->sysid, ISIS_SYS_ID_LEN);

	/* only builds the lsp if the area shares the level */
	oldlsp = lsp_search(lspid, area->lspdb[level - 1]);
	if (oldlsp) {
		/* FIXME: we should actually initiate a purge */
		seq_num = ntohl(oldlsp->lsp_header->seq_num);
		lsp_search_and_destroy(oldlsp->lsp_header->lsp_id,
				       area->lspdb[level - 1]);
	}
	rem_lifetime = lsp_rem_lifetime(area, level);
	newlsp =
		lsp_new(area, lspid, rem_lifetime, seq_num,
			area->is_type | area->overload_bit | area->attached_bit,
			0, level);
	newlsp->area = area;
	newlsp->own_lsp = 1;

	lsp_insert(newlsp, area->lspdb[level - 1]);
	/* build_lsp_data (newlsp, area); */
	lsp_build(newlsp, area);
	/* time to calculate our checksum */
	lsp_seqnum_update(newlsp);
	newlsp->last_generated = time(NULL);
	lsp_set_all_srmflags(newlsp);

	refresh_time = lsp_refresh_time(newlsp, rem_lifetime);

	THREAD_TIMER_OFF(area->t_lsp_refresh[level - 1]);
	area->lsp_regenerate_pending[level - 1] = 0;
	if (level == IS_LEVEL_1)
		thread_add_timer(master, lsp_l1_refresh, area, refresh_time,
				 &area->t_lsp_refresh[level - 1]);
	else if (level == IS_LEVEL_2)
		thread_add_timer(master, lsp_l2_refresh, area, refresh_time,
				 &area->t_lsp_refresh[level - 1]);

	if (isis->debugs & DEBUG_UPDATE_PACKETS) {
		zlog_debug(
			"ISIS-Upd (%s): Building L%d LSP %s, len %d, "
			"seq 0x%08x, cksum 0x%04x, lifetime %us refresh %us",
			area->area_tag, level,
			rawlspid_print(newlsp->lsp_header->lsp_id),
			ntohl(newlsp->lsp_header->pdu_len),
			ntohl(newlsp->lsp_header->seq_num),
			ntohs(newlsp->lsp_header->checksum),
			ntohs(newlsp->lsp_header->rem_lifetime), refresh_time);
	}
	sched_debug(
		"ISIS (%s): Built L%d LSP. Set triggered regenerate to non-pending.",
		area->area_tag, level);

	return ISIS_OK;
}

/*
 * Search own LSPs, update holding time and set SRM
 */
static int lsp_regenerate(struct isis_area *area, int level)
{
	dict_t *lspdb;
	struct isis_lsp *lsp, *frag;
	struct listnode *node;
	u_char lspid[ISIS_SYS_ID_LEN + 2];
	u_int16_t rem_lifetime, refresh_time;

	if ((area == NULL) || (area->is_type & level) != level)
		return ISIS_ERROR;

	lspdb = area->lspdb[level - 1];

	memset(lspid, 0, ISIS_SYS_ID_LEN + 2);
	memcpy(lspid, isis->sysid, ISIS_SYS_ID_LEN);

	lsp = lsp_search(lspid, lspdb);

	if (!lsp) {
		zlog_err("ISIS-Upd (%s): lsp_regenerate: no L%d LSP found!",
			 area->area_tag, level);
		return ISIS_ERROR;
	}

	lsp_clear_data(lsp);
	lsp_build(lsp, area);
	lsp->lsp_header->lsp_bits = lsp_bits_generate(level, area->overload_bit,
						      area->attached_bit);
	rem_lifetime = lsp_rem_lifetime(area, level);
	lsp->lsp_header->rem_lifetime = htons(rem_lifetime);
	lsp_seqnum_update(lsp);

	lsp->last_generated = time(NULL);
	lsp_set_all_srmflags(lsp);
	for (ALL_LIST_ELEMENTS_RO(lsp->lspu.frags, node, frag)) {
		frag->lsp_header->lsp_bits = lsp_bits_generate(
			level, area->overload_bit, area->attached_bit);
		/* Set the lifetime values of all the fragments to the same
		 * value,
		 * so that no fragment expires before the lsp is refreshed.
		 */
		frag->lsp_header->rem_lifetime = htons(rem_lifetime);
		lsp_set_all_srmflags(frag);
	}

	refresh_time = lsp_refresh_time(lsp, rem_lifetime);
	if (level == IS_LEVEL_1)
		thread_add_timer(master, lsp_l1_refresh, area, refresh_time,
				 &area->t_lsp_refresh[level - 1]);
	else if (level == IS_LEVEL_2)
		thread_add_timer(master, lsp_l2_refresh, area, refresh_time,
				 &area->t_lsp_refresh[level - 1]);
	area->lsp_regenerate_pending[level - 1] = 0;

	if (isis->debugs & DEBUG_UPDATE_PACKETS) {
		zlog_debug(
			"ISIS-Upd (%s): Refreshing our L%d LSP %s, len %d, "
			"seq 0x%08x, cksum 0x%04x, lifetime %us refresh %us",
			area->area_tag, level,
			rawlspid_print(lsp->lsp_header->lsp_id),
			ntohl(lsp->lsp_header->pdu_len),
			ntohl(lsp->lsp_header->seq_num),
			ntohs(lsp->lsp_header->checksum),
			ntohs(lsp->lsp_header->rem_lifetime), refresh_time);
	}
	sched_debug(
		"ISIS (%s): Rebuilt L%d LSP. Set triggered regenerate to non-pending.",
		area->area_tag, level);

	return ISIS_OK;
}

/*
 * Something has changed or periodic refresh -> regenerate LSP
 */
static int lsp_l1_refresh(struct thread *thread)
{
	struct isis_area *area;

	area = THREAD_ARG(thread);
	assert(area);

	area->t_lsp_refresh[0] = NULL;
	area->lsp_regenerate_pending[0] = 0;

	if ((area->is_type & IS_LEVEL_1) == 0)
		return ISIS_ERROR;

	sched_debug(
		"ISIS (%s): LSP L1 refresh timer expired. Refreshing LSP...",
		area->area_tag);
	return lsp_regenerate(area, IS_LEVEL_1);
}

static int lsp_l2_refresh(struct thread *thread)
{
	struct isis_area *area;

	area = THREAD_ARG(thread);
	assert(area);

	area->t_lsp_refresh[1] = NULL;
	area->lsp_regenerate_pending[1] = 0;

	if ((area->is_type & IS_LEVEL_2) == 0)
		return ISIS_ERROR;

	sched_debug(
		"ISIS (%s): LSP L2 refresh timer expired. Refreshing LSP...",
		area->area_tag);
	return lsp_regenerate(area, IS_LEVEL_2);
}

int lsp_regenerate_schedule(struct isis_area *area, int level, int all_pseudo)
{
	struct isis_lsp *lsp;
	u_char id[ISIS_SYS_ID_LEN + 2];
	time_t now, diff;
	long timeout;
	struct listnode *cnode;
	struct isis_circuit *circuit;
	int lvl;

	if (area == NULL)
		return ISIS_ERROR;

	sched_debug(
		"ISIS (%s): Scheduling regeneration of %s LSPs, %sincluding PSNs",
		area->area_tag, circuit_t2string(level),
		all_pseudo ? "" : "not ");

	memcpy(id, isis->sysid, ISIS_SYS_ID_LEN);
	LSP_PSEUDO_ID(id) = LSP_FRAGMENT(id) = 0;
	now = time(NULL);

	for (lvl = IS_LEVEL_1; lvl <= IS_LEVEL_2; lvl++) {
		if (!((level & lvl) && (area->is_type & lvl)))
			continue;

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

		lsp = lsp_search(id, area->lspdb[lvl - 1]);
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
		if (lvl == IS_LEVEL_1) {
			thread_add_timer_msec(master, lsp_l1_refresh, area,
					      timeout,
					      &area->t_lsp_refresh[lvl - 1]);
		} else if (lvl == IS_LEVEL_2) {
			thread_add_timer_msec(master, lsp_l2_refresh, area,
					      timeout,
					      &area->t_lsp_refresh[lvl - 1]);
		}
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
	struct is_neigh *is_neigh;
	struct te_is_neigh *te_is_neigh;
	struct es_neigh *es_neigh;
	struct list *adj_list;
	struct listnode *node;
	struct isis_area *area = circuit->area;

	lsp_debug(
		"ISIS (%s): Constructing pseudo LSP %s for interface %s level %d",
		area->area_tag, rawlspid_print(lsp->lsp_header->lsp_id),
		circuit->interface->name, level);

	lsp->level = level;
	/* RFC3787  section 4 SHOULD not set overload bit in pseudo LSPs */
	lsp->lsp_header->lsp_bits =
		lsp_bits_generate(level, 0, circuit->area->attached_bit);

	/*
	 * add self to IS neighbours
	 */
	if (circuit->area->oldmetric) {
		if (lsp->tlv_data.is_neighs == NULL) {
			lsp->tlv_data.is_neighs = list_new();
			lsp->tlv_data.is_neighs->del = free_tlv;
		}
		is_neigh = XCALLOC(MTYPE_ISIS_TLV, sizeof(struct is_neigh));

		memcpy(&is_neigh->neigh_id, isis->sysid, ISIS_SYS_ID_LEN);
		listnode_add(lsp->tlv_data.is_neighs, is_neigh);
		lsp_debug(
			"ISIS (%s): Adding %s.%02x as old-style neighbor (self)",
			area->area_tag, sysid_print(is_neigh->neigh_id),
			LSP_PSEUDO_ID(is_neigh->neigh_id));
	}
	if (circuit->area->newmetric) {
		if (lsp->tlv_data.te_is_neighs == NULL) {
			lsp->tlv_data.te_is_neighs = list_new();
			lsp->tlv_data.te_is_neighs->del = free_tlv;
		}
		te_is_neigh =
			XCALLOC(MTYPE_ISIS_TLV, sizeof(struct te_is_neigh));

		memcpy(&te_is_neigh->neigh_id, isis->sysid, ISIS_SYS_ID_LEN);
		listnode_add(lsp->tlv_data.te_is_neighs, te_is_neigh);
		lsp_debug(
			"ISIS (%s): Adding %s.%02x as te-style neighbor (self)",
			area->area_tag, sysid_print(te_is_neigh->neigh_id),
			LSP_PSEUDO_ID(te_is_neigh->neigh_id));
	}

	adj_list = list_new();
	isis_adj_build_up_list(circuit->u.bc.adjdb[level - 1], adj_list);

	for (ALL_LIST_ELEMENTS_RO(adj_list, node, adj)) {
		if (adj->level & level) {
			if ((level == IS_LEVEL_1
			     && adj->sys_type == ISIS_SYSTYPE_L1_IS)
			    || (level == IS_LEVEL_1
				&& adj->sys_type == ISIS_SYSTYPE_L2_IS
				&& adj->adj_usage == ISIS_ADJ_LEVEL1AND2)
			    || (level == IS_LEVEL_2
				&& adj->sys_type == ISIS_SYSTYPE_L2_IS)) {
				/* an IS neighbour -> add it */
				if (circuit->area->oldmetric) {
					is_neigh = XCALLOC(
						MTYPE_ISIS_TLV,
						sizeof(struct is_neigh));

					memcpy(&is_neigh->neigh_id, adj->sysid,
					       ISIS_SYS_ID_LEN);
					listnode_add(lsp->tlv_data.is_neighs,
						     is_neigh);
					lsp_debug(
						"ISIS (%s): Adding %s.%02x as old-style neighbor (peer)",
						area->area_tag,
						sysid_print(is_neigh->neigh_id),
						LSP_PSEUDO_ID(
							is_neigh->neigh_id));
				}
				if (circuit->area->newmetric) {
					te_is_neigh = XCALLOC(
						MTYPE_ISIS_TLV,
						sizeof(struct te_is_neigh));
					memcpy(&te_is_neigh->neigh_id,
					       adj->sysid, ISIS_SYS_ID_LEN);
					listnode_add(lsp->tlv_data.te_is_neighs,
						     te_is_neigh);
					lsp_debug(
						"ISIS (%s): Adding %s.%02x as te-style neighbor (peer)",
						area->area_tag,
						sysid_print(
							te_is_neigh->neigh_id),
						LSP_PSEUDO_ID(
							te_is_neigh->neigh_id));
				}
			} else if (level == IS_LEVEL_1
				   && adj->sys_type == ISIS_SYSTYPE_ES) {
				/* an ES neigbour add it, if we are building
				 * level 1 LSP */
				/* FIXME: the tlv-format is hard to use here */
				if (lsp->tlv_data.es_neighs == NULL) {
					lsp->tlv_data.es_neighs = list_new();
					lsp->tlv_data.es_neighs->del = free_tlv;
				}
				es_neigh = XCALLOC(MTYPE_ISIS_TLV,
						   sizeof(struct es_neigh));

				memcpy(&es_neigh->first_es_neigh, adj->sysid,
				       ISIS_SYS_ID_LEN);
				listnode_add(lsp->tlv_data.es_neighs, es_neigh);
				lsp_debug(
					"ISIS (%s): Adding %s as ES neighbor (peer)",
					area->area_tag,
					sysid_print(es_neigh->first_es_neigh));
			} else {
				lsp_debug(
					"ISIS (%s): Ignoring neighbor %s, level does not match",
					area->area_tag,
					sysid_print(adj->sysid));
			}
		} else {
			lsp_debug(
				"ISIS (%s): Ignoring neighbor %s, level does not intersect",
				area->area_tag, sysid_print(adj->sysid));
		}
	}
	list_delete(adj_list);

	lsp_debug("ISIS (%s): Pseudo LSP construction is complete.",
		  area->area_tag);

	/* Reset endp of stream to overwrite only TLV part of it. */
	stream_reset(lsp->pdu);
	stream_forward_endp(lsp->pdu, ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN);

	/*
	 * Add the authentication info if it's present
	 */
	lsp_auth_add(lsp);

	if (lsp->tlv_data.is_neighs && listcount(lsp->tlv_data.is_neighs) > 0)
		tlv_add_is_neighs(lsp->tlv_data.is_neighs, lsp->pdu);

	if (lsp->tlv_data.te_is_neighs
	    && listcount(lsp->tlv_data.te_is_neighs) > 0)
		tlv_add_te_is_neighs(lsp->tlv_data.te_is_neighs, lsp->pdu,
				     NULL);

	if (lsp->tlv_data.es_neighs && listcount(lsp->tlv_data.es_neighs) > 0)
		tlv_add_is_neighs(lsp->tlv_data.es_neighs, lsp->pdu);

	lsp->lsp_header->pdu_len = htons(stream_get_endp(lsp->pdu));

	/* Recompute authentication and checksum information */
	lsp_auth_update(lsp);
	fletcher_checksum(STREAM_DATA(lsp->pdu) + 12,
			  ntohs(lsp->lsp_header->pdu_len) - 12, 12);

	return;
}

int lsp_generate_pseudo(struct isis_circuit *circuit, int level)
{
	dict_t *lspdb = circuit->area->lspdb[level - 1];
	struct isis_lsp *lsp;
	u_char lsp_id[ISIS_SYS_ID_LEN + 2];
	u_int16_t rem_lifetime, refresh_time;

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
	if (lsp_search(lsp_id, lspdb))
		return lsp_regenerate_schedule_pseudo(circuit, level);

	rem_lifetime = lsp_rem_lifetime(circuit->area, level);
	/* RFC3787  section 4 SHOULD not set overload bit in pseudo LSPs */
	lsp = lsp_new(circuit->area, lsp_id, rem_lifetime, 1,
		      circuit->area->is_type | circuit->area->attached_bit, 0,
		      level);
	lsp->area = circuit->area;

	lsp_build_pseudo(lsp, circuit, level);

	lsp->own_lsp = 1;
	lsp_insert(lsp, lspdb);
	lsp_set_all_srmflags(lsp);

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
			"ISIS-Upd (%s): Building L%d Pseudo LSP %s, len %d, "
			"seq 0x%08x, cksum 0x%04x, lifetime %us, refresh %us",
			circuit->area->area_tag, level,
			rawlspid_print(lsp->lsp_header->lsp_id),
			ntohl(lsp->lsp_header->pdu_len),
			ntohl(lsp->lsp_header->seq_num),
			ntohs(lsp->lsp_header->checksum),
			ntohs(lsp->lsp_header->rem_lifetime), refresh_time);
	}

	return ISIS_OK;
}

static int lsp_regenerate_pseudo(struct isis_circuit *circuit, int level)
{
	dict_t *lspdb = circuit->area->lspdb[level - 1];
	struct isis_lsp *lsp;
	u_char lsp_id[ISIS_SYS_ID_LEN + 2];
	u_int16_t rem_lifetime, refresh_time;

	if ((circuit->is_type & level) != level
	    || (circuit->state != C_STATE_UP)
	    || (circuit->circ_type != CIRCUIT_T_BROADCAST)
	    || (circuit->u.bc.is_dr[level - 1] == 0))
		return ISIS_ERROR;

	memcpy(lsp_id, isis->sysid, ISIS_SYS_ID_LEN);
	LSP_PSEUDO_ID(lsp_id) = circuit->circuit_id;
	LSP_FRAGMENT(lsp_id) = 0;

	lsp = lsp_search(lsp_id, lspdb);

	if (!lsp) {
		zlog_err("lsp_regenerate_pseudo: no l%d LSP %s found!", level,
			 rawlspid_print(lsp_id));
		return ISIS_ERROR;
	}
	lsp_clear_data(lsp);

	lsp_build_pseudo(lsp, circuit, level);

	/* RFC3787  section 4 SHOULD not set overload bit in pseudo LSPs */
	lsp->lsp_header->lsp_bits =
		lsp_bits_generate(level, 0, circuit->area->attached_bit);
	rem_lifetime = lsp_rem_lifetime(circuit->area, level);
	lsp->lsp_header->rem_lifetime = htons(rem_lifetime);
	lsp_inc_seqnum(lsp, 0);
	lsp->last_generated = time(NULL);
	lsp_set_all_srmflags(lsp);

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
			"ISIS-Upd (%s): Refreshing L%d Pseudo LSP %s, len %d, "
			"seq 0x%08x, cksum 0x%04x, lifetime %us, refresh %us",
			circuit->area->area_tag, level,
			rawlspid_print(lsp->lsp_header->lsp_id),
			ntohl(lsp->lsp_header->pdu_len),
			ntohl(lsp->lsp_header->seq_num),
			ntohs(lsp->lsp_header->checksum),
			ntohs(lsp->lsp_header->rem_lifetime), refresh_time);
	}

	return ISIS_OK;
}

/*
 * Something has changed or periodic refresh -> regenerate pseudo LSP
 */
static int lsp_l1_refresh_pseudo(struct thread *thread)
{
	struct isis_circuit *circuit;
	u_char id[ISIS_SYS_ID_LEN + 2];

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
	u_char id[ISIS_SYS_ID_LEN + 2];

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
	u_char lsp_id[ISIS_SYS_ID_LEN + 2];
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

		lsp = lsp_search(lsp_id, circuit->area->lspdb[lvl - 1]);
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
			timeout = 1000
				  * (circuit->area->lsp_gen_interval[lvl - 1]
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
 *  - set LSPs with SRMflag set for sending
 */
int lsp_tick(struct thread *thread)
{
	struct isis_area *area;
	struct isis_circuit *circuit;
	struct isis_lsp *lsp;
	struct list *lsp_list;
	struct listnode *lspnode, *cnode;
	dnode_t *dnode, *dnode_next;
	int level;
	u_int16_t rem_lifetime;

	lsp_list = list_new();

	area = THREAD_ARG(thread);
	assert(area);
	area->t_tick = NULL;
	thread_add_timer(master, lsp_tick, area, 1, &area->t_tick);

	/*
	 * Build a list of LSPs with (any) SRMflag set
	 * and removed the ones that have aged out
	 */
	for (level = 0; level < ISIS_LEVELS; level++) {
		if (area->lspdb[level] && dict_count(area->lspdb[level]) > 0) {
			for (dnode = dict_first(area->lspdb[level]);
			     dnode != NULL; dnode = dnode_next) {
				dnode_next =
					dict_next(area->lspdb[level], dnode);
				lsp = dnode_get(dnode);

				/*
				 * The lsp rem_lifetime is kept at 0 for MaxAge
				 * or
				 * ZeroAgeLifetime depending on explicit purge
				 * or
				 * natural age out. So schedule spf only once
				 * when
				 * the first time rem_lifetime becomes 0.
				 */
				rem_lifetime =
					ntohs(lsp->lsp_header->rem_lifetime);
				lsp_set_time(lsp);

				/*
				 * Schedule may run spf which should be done
				 * only after
				 * the lsp rem_lifetime becomes 0 for the first
				 * time.
				 * ISO 10589 - 7.3.16.4 first paragraph.
				 */
				if (rem_lifetime == 1
				    && lsp->lsp_header->seq_num != 0) {
					/* 7.3.16.4 a) set SRM flags on all */
					lsp_set_all_srmflags(lsp);
					/* 7.3.16.4 b) retain only the header
					 * FIXME  */
					/* 7.3.16.4 c) record the time to purge
					 * FIXME */
					/* run/schedule spf */
					/* isis_spf_schedule is called inside
					 * lsp_destroy() below;
					 * so it is not needed here. */
					/* isis_spf_schedule (lsp->area,
					 * lsp->level); */
				}

				if (lsp->age_out == 0) {
					zlog_debug(
						"ISIS-Upd (%s): L%u LSP %s seq 0x%08x aged out",
						area->area_tag, lsp->level,
						rawlspid_print(
							lsp->lsp_header
								->lsp_id),
						ntohl(lsp->lsp_header
							      ->seq_num));
					lsp_destroy(lsp);
					lsp = NULL;
					dict_delete_free(area->lspdb[level],
							 dnode);
				} else if (flags_any_set(lsp->SRMflags))
					listnode_add(lsp_list, lsp);
			}

			/*
			 * Send LSPs on circuits indicated by the SRMflags
			 */
			if (listcount(lsp_list) > 0) {
				for (ALL_LIST_ELEMENTS_RO(area->circuit_list,
							  cnode, circuit)) {
					int diff =
						time(NULL)
						- circuit->lsp_queue_last_cleared;
					if (circuit->lsp_queue == NULL
					    || diff < MIN_LSP_TRANS_INTERVAL)
						continue;
					for (ALL_LIST_ELEMENTS_RO(
						     lsp_list, lspnode, lsp)) {
						if (circuit->upadjcount
							    [lsp->level - 1]
						    && ISIS_CHECK_FLAG(
							       lsp->SRMflags,
							       circuit)) {
							/* Add the lsp only if
							 * it is not already in
							 * lsp
							 * queue */
							if (!listnode_lookup(
								    circuit->lsp_queue,
								    lsp)) {
								listnode_add(
									circuit->lsp_queue,
									lsp);
								thread_add_event(
									master,
									send_lsp,
									circuit,
									0,
									NULL);
							}
						}
					}
				}
				list_delete_all_node(lsp_list);
			}
		}
	}

	list_delete(lsp_list);

	return ISIS_OK;
}

void lsp_purge_pseudo(u_char *id, struct isis_circuit *circuit, int level)
{
	struct isis_lsp *lsp;
	u_int16_t seq_num;
	u_int8_t lsp_bits;

	lsp = lsp_search(id, circuit->area->lspdb[level - 1]);
	if (!lsp)
		return;

	/* store old values */
	seq_num = lsp->lsp_header->seq_num;
	lsp_bits = lsp->lsp_header->lsp_bits;

	/* reset stream */
	lsp_clear_data(lsp);
	stream_reset(lsp->pdu);

	/* update header */
	lsp->lsp_header->pdu_len = htons(ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN);
	memcpy(lsp->lsp_header->lsp_id, id, ISIS_SYS_ID_LEN + 2);
	lsp->lsp_header->checksum = 0;
	lsp->lsp_header->seq_num = seq_num;
	lsp->lsp_header->rem_lifetime = 0;
	lsp->lsp_header->lsp_bits = lsp_bits;
	lsp->level = level;
	lsp->age_out = lsp->area->max_lsp_lifetime[level - 1];
	stream_forward_endp(lsp->pdu, ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN);

	/*
	 * Add and update the authentication info if its present
	 */
	lsp_auth_add(lsp);
	lsp->lsp_header->pdu_len = htons(stream_get_endp(lsp->pdu));
	lsp_auth_update(lsp);
	fletcher_checksum(STREAM_DATA(lsp->pdu) + 12,
			  ntohs(lsp->lsp_header->pdu_len) - 12, 12);

	lsp_set_all_srmflags(lsp);

	return;
}

/*
 * Purge own LSP that is received and we don't have.
 * -> Do as in 7.3.16.4
 */
void lsp_purge_non_exist(int level, struct isis_link_state_hdr *lsp_hdr,
			 struct isis_area *area)
{
	struct isis_lsp *lsp;

	/*
	 * We need to create the LSP to be purged
	 */
	lsp = XCALLOC(MTYPE_ISIS_LSP, sizeof(struct isis_lsp));
	lsp->area = area;
	lsp->level = level;
	lsp->pdu = stream_new(LLC_LEN + area->lsp_mtu);
	lsp->isis_header = (struct isis_fixed_hdr *)STREAM_DATA(lsp->pdu);
	fill_fixed_hdr(lsp->isis_header, (lsp->level == IS_LEVEL_1)
						 ? L1_LINK_STATE
						 : L2_LINK_STATE);
	lsp->lsp_header = (struct isis_link_state_hdr *)(STREAM_DATA(lsp->pdu)
							 + ISIS_FIXED_HDR_LEN);
	memcpy(lsp->lsp_header, lsp_hdr, ISIS_LSP_HDR_LEN);
	stream_forward_endp(lsp->pdu, ISIS_FIXED_HDR_LEN + ISIS_LSP_HDR_LEN);

	/*
	 * Set the remaining lifetime to 0
	 */
	lsp->lsp_header->rem_lifetime = 0;

	/*
	 * Add and update the authentication info if its present
	 */
	lsp_auth_add(lsp);
	lsp_auth_update(lsp);

	/*
	 * Update the PDU length to header plus any authentication TLV.
	 */
	lsp->lsp_header->pdu_len = htons(stream_get_endp(lsp->pdu));

	/*
	 * Put the lsp into LSPdb
	 */
	lsp_insert(lsp, area->lspdb[lsp->level - 1]);

	/*
	 * Send in to whole area
	 */
	lsp_set_all_srmflags(lsp);

	return;
}

void lsp_set_all_srmflags(struct isis_lsp *lsp)
{
	struct listnode *node;
	struct isis_circuit *circuit;

	assert(lsp);

	ISIS_FLAGS_CLEAR_ALL(lsp->SRMflags);

	if (lsp->area) {
		struct list *circuit_list = lsp->area->circuit_list;
		for (ALL_LIST_ELEMENTS_RO(circuit_list, node, circuit)) {
			ISIS_SET_FLAG(lsp->SRMflags, circuit);
		}
	}
}
