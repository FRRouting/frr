// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * This is an implementation of Segment Routing over IPv6 (SRv6) for IS-IS
 * as per RFC 9352
 * https://datatracker.ietf.org/doc/html/rfc9352
 *
 * Copyright (C) 2023 Carmine Scarpitta - University of Rome Tor Vergata
 */

#include <zebra.h>

#include "srv6.h"
#include "termtable.h"

#include "isisd/isisd.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_srv6.h"
#include "isisd/isis_zebra.h"

/* Local variables and functions */
DEFINE_MTYPE_STATIC(ISISD, ISIS_SRV6_SID, "ISIS SRv6 Segment ID");

/**
 * Fill in SRv6 Locator TLV with information from an SRv6 locator.
 *
 * @param loc	     SRv6 Locator configuration
 * @param loc_tlv    SRv6 Locator TLV to be updated
 */
void isis_srv6_locator2tlv(const struct isis_srv6_locator *loc,
			   struct isis_srv6_locator_tlv *loc_tlv)
{
	/* Set SRv6 Locator metric */
	loc_tlv->metric = loc->metric;

	/* Set SRv6 Locator flags */
	loc_tlv->flags = loc->flags;

	/* Set SRv6 Locator algorithm */
	loc_tlv->algorithm = loc->algorithm;

	/* Set SRv6 Locator prefix */
	loc_tlv->prefix = loc->prefix;
}

/**
 * Unset the SRv6 locator for a given IS-IS area.
 *
 * @param area	IS-IS area
 *
 * @result True on success, False otherwise
 */
bool isis_srv6_locator_unset(struct isis_area *area)
{
	int ret;
	struct listnode *node, *nnode;
	struct srv6_locator_chunk *chunk;
	struct isis_srv6_sid *sid;

	if (strncmp(area->srv6db.config.srv6_locator_name, "",
		    sizeof(area->srv6db.config.srv6_locator_name)) == 0) {
		sr_debug("SRv6 locator not set");
		return true;
	}

	/* Delete SRv6 SIDs */
	for (ALL_LIST_ELEMENTS(area->srv6db.srv6_sids, node, nnode, sid)) {
		sr_debug(
			"Deleting SRv6 SID (locator %s, sid %pI6) from IS-IS area %s",
			area->srv6db.config.srv6_locator_name, &sid->sid,
			area->area_tag);

		/* Uninstall the SRv6 SID from the forwarding plane through
		 * Zebra */
		isis_zebra_srv6_sid_uninstall(area, sid);

		listnode_delete(area->srv6db.srv6_sids, sid);
		isis_srv6_sid_free(sid);
	}

	/* Inform Zebra that we are releasing the SRv6 locator */
	ret = isis_zebra_srv6_manager_release_locator_chunk(
		area->srv6db.config.srv6_locator_name);
	if (ret < 0)
		return false;

	/* Delete chunks */
	for (ALL_LIST_ELEMENTS(area->srv6db.srv6_locator_chunks, node, nnode,
			       chunk)) {
		sr_debug(
			"Releasing chunk of locator %s (prefix %pFX) for IS-IS area %s",
			area->srv6db.config.srv6_locator_name, &chunk->prefix,
			area->area_tag);

		listnode_delete(area->srv6db.srv6_locator_chunks, chunk);
		srv6_locator_chunk_free(&chunk);
	}

	/* Clear locator name */
	memset(area->srv6db.config.srv6_locator_name, 0,
	       sizeof(area->srv6db.config.srv6_locator_name));

	/* Regenerate LSPs to advertise that the SRv6 locator no longer exists
	 */
	lsp_regenerate_schedule(area, area->is_type, 0);

	return true;
}

/**
 * Encode SID function in the SRv6 SID.
 *
 * @param sid
 * @param func
 * @param offset
 * @param len
 */
static void encode_sid_func(struct in6_addr *sid, uint32_t func, uint8_t offset,
			    uint8_t len)
{
	for (uint8_t idx = 0; idx < len; idx++) {
		uint8_t tidx = offset + idx;
		sid->s6_addr[tidx / 8] &= ~(0x1 << (7 - tidx % 8));
		if (func >> (len - 1 - idx) & 0x1)
			sid->s6_addr[tidx / 8] |= 0x1 << (7 - tidx % 8);
	}
}

static bool sid_exist(struct isis_area *area, const struct in6_addr *sid)
{
	struct listnode *node;
	struct isis_srv6_sid *s;

	for (ALL_LIST_ELEMENTS_RO(area->srv6db.srv6_sids, node, s))
		if (sid_same(&s->sid, sid))
			return true;
	return false;
}

/**
 * Request a SID from the SRv6 locator.
 *
 * @param area		IS-IS area
 * @param chunk		SRv6 locator chunk
 * @param sid_func	The FUNCTION part of the SID to be allocated (a negative
 * number will allocate the first available SID)
 *
 * @return	First available SID on success or in6addr_any if the SRv6
 * locator chunk is full
 */
static struct in6_addr
srv6_locator_request_sid(struct isis_area *area,
			 struct srv6_locator_chunk *chunk, int sid_func)
{
	struct in6_addr sid;
	uint8_t offset = 0;
	uint8_t func_len = 0;
	uint32_t func_max;
	bool allocated = false;

	if (!area || !chunk)
		return in6addr_any;

	sr_debug("ISIS-SRv6 (%s): requested new SID from locator %s",
		 area->area_tag, chunk->locator_name);

	/* Let's build the SID, step by step. A SID has the following structure
	(defined in RFC 8986): LOCATOR:FUNCTION:ARGUMENT.*/

	/* First, we encode the LOCATOR in the L most significant bits. */
	sid = chunk->prefix.prefix;

	/* The next part of the SID is the FUNCTION. Let's compute the length
	 * and the offset of the FUNCTION in the SID */
	func_len = chunk->function_bits_length;
	offset = chunk->block_bits_length + chunk->node_bits_length;

	/* Then, encode the FUNCTION */
	if (sid_func >= 0) {
		/* SID FUNCTION has been specified. We need to allocate a SID
		 * with the requested FUNCTION. */
		encode_sid_func(&sid, sid_func, offset, func_len);
		if (sid_exist(area, &sid)) {
			zlog_warn(
				"ISIS-SRv6 (%s): the requested SID %pI6 is already used",
				area->area_tag, &sid);
			return sid;
		}
		allocated = true;
	} else {
		/* SID FUNCTION not specified. We need to choose a FUNCTION that
		 * is not already used. So let's iterate through all possible
		 * functions and get the first available one. */
		func_max = (1 << func_len) - 1;
		for (uint32_t func = 1; func < func_max; func++) {
			encode_sid_func(&sid, func, offset, func_len);
			if (sid_exist(area, &sid))
				continue;
			allocated = true;
			break;
		}
	}

	if (!allocated) {
		/* We ran out of available SIDs */
		zlog_warn("ISIS-SRv6 (%s): no SIDs available in locator %s",
			  area->area_tag, chunk->locator_name);
		return in6addr_any;
	}

	sr_debug("ISIS-SRv6 (%s): allocating new SID %pI6", area->area_tag,
		 &sid);

	return sid;
}

/**
 * Allocate an SRv6 SID from an SRv6 locator.
 *
 * @param area		IS-IS area
 * @param chunk		SRv6 locator chunk
 * @param behavior	SRv6 Endpoint Behavior bound to the SID
 *
 * @result the allocated SID on success, NULL otherwise
 */
struct isis_srv6_sid *
isis_srv6_sid_alloc(struct isis_area *area, struct srv6_locator_chunk *chunk,
		    enum srv6_endpoint_behavior_codepoint behavior,
		    int sid_func)
{
	struct isis_srv6_sid *sid = NULL;

	if (!area || !chunk)
		return NULL;

	sid = XCALLOC(MTYPE_ISIS_SRV6_SID, sizeof(struct isis_srv6_sid));

	sid->sid = srv6_locator_request_sid(area, chunk, sid_func);
	if (IPV6_ADDR_SAME(&sid->sid, &in6addr_any)) {
		isis_srv6_sid_free(sid);
		return NULL;
	}

	sid->behavior = behavior;
	sid->structure.loc_block_len = chunk->block_bits_length;
	sid->structure.loc_node_len = chunk->node_bits_length;
	sid->structure.func_len = chunk->function_bits_length;
	sid->structure.arg_len = chunk->argument_bits_length;
	sid->locator = chunk;
	sid->area = area;

	return sid;
}

void isis_srv6_sid_free(struct isis_srv6_sid *sid)
{
	XFREE(MTYPE_ISIS_SRV6_SID, sid);
}

/**
 * Show Segment Routing over IPv6 (SRv6) Node.
 *
 * @param vty	VTY output
 * @param area	IS-IS area
 * @param level	IS-IS level
 */
static void show_node(struct vty *vty, struct isis_area *area, int level)
{
	struct isis_lsp *lsp;
	struct ttable *tt;

	vty_out(vty, " IS-IS %s SRv6-Nodes:\n\n", circuit_t2string(level));

	/* Prepare table. */
	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	ttable_add_row(
		tt,
		"System ID|Algorithm|SRH Max SL|SRH Max End Pop|SRH Max H.encaps|SRH Max End D");
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');

	frr_each (lspdb, &area->lspdb[level - 1], lsp) {
		struct isis_router_cap *cap;

		if (!lsp->tlvs)
			continue;
		cap = lsp->tlvs->router_cap;
		if (!cap)
			continue;

		ttable_add_row(tt, "%pSY|%s|%u|%u|%u|%u", lsp->hdr.lsp_id,
			       cap->algo[0] == SR_ALGORITHM_SPF ? "SPF"
								: "S-SPF",
			       cap->srv6_msd.max_seg_left_msd,
			       cap->srv6_msd.max_end_pop_msd,
			       cap->srv6_msd.max_h_encaps_msd,
			       cap->srv6_msd.max_end_d_msd);
	}

	/* Dump the generated table. */
	if (tt->nrows > 1) {
		char *table;

		table = ttable_dump(tt, "\n");
		vty_out(vty, "%s\n", table);
		XFREE(MTYPE_TMP, table);
	}
	ttable_del(tt);
}

DEFUN(show_srv6_node, show_srv6_node_cmd,
      "show " PROTO_NAME " segment-routing srv6 node",
      SHOW_STR
      PROTO_HELP
      "Segment-Routing\n"
      "Segment-Routing over IPv6 (SRv6)\n"
      "SRv6 node\n")
{
	struct listnode *node, *inode;
	struct isis_area *area;
	struct isis *isis;

	for (ALL_LIST_ELEMENTS_RO(im->isis, inode, isis)) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
			vty_out(vty, "Area %s:\n",
				area->area_tag ? area->area_tag : "null");
			if (!area->srv6db.config.enabled) {
				vty_out(vty, " SRv6 is disabled\n");
				continue;
			}
			for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS;
			     level++)
				show_node(vty, area, level);
		}
	}

	return CMD_SUCCESS;
}

/**
 * IS-IS SRv6 initialization for given area.
 *
 * @param area	IS-IS area
 */
void isis_srv6_area_init(struct isis_area *area)
{
	struct isis_srv6_db *srv6db;

	if (!area)
		return;

	srv6db = &area->srv6db;

	sr_debug("ISIS-SRv6 (%s): Initialize Segment Routing SRv6 DB",
		 area->area_tag);

	/* Initialize SRv6 Data Base */
	memset(srv6db, 0, sizeof(*srv6db));

	/* Pull defaults from the YANG module */
	srv6db->config.enabled = yang_get_default_bool("%s/enabled", ISIS_SRV6);

	srv6db->config.max_seg_left_msd = SRV6_MAX_SEG_LEFT;
	srv6db->config.max_end_pop_msd = SRV6_MAX_END_POP;
	srv6db->config.max_h_encaps_msd = SRV6_MAX_H_ENCAPS;
	srv6db->config.max_end_d_msd = SRV6_MAX_END_D;

	/* Initialize SRv6 Locator chunks list */
	srv6db->srv6_locator_chunks = list_new();

	/* Initialize SRv6 SIDs list */
	srv6db->srv6_sids = list_new();
	srv6db->srv6_sids->del = (void (*)(void *))isis_srv6_sid_free;
}

/**
 * Terminate IS-IS SRv6 for the given area.
 *
 * @param area	IS-IS area
 */
void isis_srv6_area_term(struct isis_area *area)
{
	struct isis_srv6_db *srv6db = &area->srv6db;
	struct listnode *node, *nnode;
	struct srv6_locator_chunk *chunk;

	sr_debug("ISIS-SRv6 (%s): Terminate SRv6", area->area_tag);

	/* Free SRv6 Locator chunks list */
	for (ALL_LIST_ELEMENTS(srv6db->srv6_locator_chunks, node, nnode, chunk))
		srv6_locator_chunk_free(&chunk);
	list_delete(&srv6db->srv6_locator_chunks);

	/* Free SRv6 SIDs list */
	list_delete(&srv6db->srv6_sids);
}

/**
 * IS-IS SRv6 global initialization.
 */
void isis_srv6_init(void)
{
	install_element(VIEW_NODE, &show_srv6_node_cmd);
}

/**
 * IS-IS SRv6 global terminate.
 */
void isis_srv6_term(void)
{
}
