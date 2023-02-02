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
