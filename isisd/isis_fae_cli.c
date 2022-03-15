/* IS-IS Flex-Algo Endpoint Registration Tracking
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include "flex_algo.h"
#include "linklist.h"
#include "lib/json.h"
#include "lib/termtable.h"
#include "isisd/isis_fae.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_route.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_spf_private.h"
#include "isisd/isis_flex_algo.h"
#include "isisd/isis_fae_cli.h"

#ifndef FABRICD
#include "isisd/isis_fae_cli_clippy.c"

static void _show_registrations(struct ttable *tt, unsigned algorithm,
				vrf_id_t vrf_id, const char *const area_tag,
				bool active, const struct fae_db_head *const db)
{
	struct fae_db_node *node;

	RB_FOREACH (node, fae_db_head, db) {
		char epstr[INET6_ADDRSTRLEN];

		ipaddr2str(&node->endpoint, epstr, sizeof(epstr));
		ttable_add_row(tt, "%u|%s|%s|%u|%s|%u", vrf_id, area_tag, epstr,
			       algorithm, active ? "Active" : "Inactive",
			       node->client[0]);
	}
}

static void _show_registrations_by_algo(struct ttable *tt, unsigned algorithm,
					vrf_id_t vrf_id,
					const struct isis_area *const area)
{
	unsigned last = SR_ALGORITHM_COUNT;

	if (algorithm)
		last = algorithm + 1;

	for (unsigned i = algorithm; i < last; i++) {
		if (!isis_flex_algo_elected_supported(i, area))
			continue;

		_show_registrations(tt, i, vrf_id, area->area_tag, true,
				    &area->fae.active[i]);
		_show_registrations(tt, i, vrf_id, area->area_tag, false,
				    &area->fae.inactive[i]);

		if (algorithm)
			break;
	}
}

static void _show_registrations_by_area(struct ttable *tt, unsigned algorithm,
					const struct isis *const isis,
					const char *const area_tag)
{
	struct isis_area *area;
	struct listnode *area_node;

	if (area_tag) {
#if 0 /* ? */
		struct zapi_fae_igp_discriminator igp_disc;

		igp_disc.vrf_id = isis->vrf_id;
		igp_disc.proto = ZF_PROTO_ISIS;
		strcpy(igp_disc.proto_data.isis.area_tag, area_tag);
		area = isis_fae_area_lookup(&igp_disc);
#endif
		area = isis_area_lookup(area_tag, isis->vrf_id);
		if (area)
			_show_registrations_by_algo(tt, algorithm, isis->vrf_id,
						    area);
	} else {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, area_node, area))
			_show_registrations_by_algo(tt, algorithm, isis->vrf_id,
						    area);
	}
}

static void _show_registrations_by_vrf(struct ttable *tt, unsigned algorithm,
				       const char *const vrf_name,
				       const char *const area_tag)
{
	struct isis *isis;
	struct listnode *isis_node;

	if (vrf_name) {
		isis = isis_lookup_by_vrfname(vrf_name);
		if (isis)
			_show_registrations_by_area(tt, algorithm, isis,
						    area_tag);
	} else {
		for (ALL_LIST_ELEMENTS_RO(im->isis, isis_node, isis)) {
			_show_registrations_by_area(tt, algorithm, isis,
						    area_tag);
		}
	}
}

DEFPY(show_isis_fae_database, show_isis_fae_database_cmd,
      "show isis fae registrations [WORD$tag]"
      " [vrf NAME$vrf_name] [algo (0-254)$algo] [json$uj]",
      SHOW_STR PROTO_HELP
      "Flex-Algo Endpoint Database\n"
      "Endpoint Registrations\n"
      "ISO Routing area tag\n" VRF_CMD_HELP_STR
      "Flex-Algo definition\n"
      "The algorithm number\n" JSON_STR)
{
	char *table;
	struct ttable *tt;
	struct json_object *json;

	tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);
	tt->style.cell.rpad = 2;
	tt->style.corner = '+';
	ttable_restyle(tt);
	ttable_rowseps(tt, 0, BOTTOM, true, '-');
	ttable_add_row(tt, "VRF|Area|Endpoint|Algorithm|Status|Client");

	_show_registrations_by_vrf(tt, algo, vrf_name, tag);

	if (uj) {
		json = ttable_json(tt, "dssdsd");
		vty_out(vty, "%s\n",
			json_object_to_json_string_ext(
				json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
		goto out;
	}

	table = ttable_dump(tt, "\n");
	vty_out(vty, "%s\n", table);
	XFREE(MTYPE_TMP, table);

out:
	ttable_del(tt);
	return CMD_SUCCESS;
}

void isis_fae_cli_init(void)
{
	install_element(VIEW_NODE, &show_isis_fae_database_cmd);
}
#endif /* !FABRICD */
