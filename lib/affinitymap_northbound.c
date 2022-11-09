/*
 * affinity map northbound implementation.
 *
 * Copyright 2022 Hiroki Shirokura, LINE Corporation
 * Copyright 2022 Masakazu Asama
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of Free Range Routing (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/log.h"
#include "lib/northbound.h"
#include "lib/affinitymap.h"

/*
 * XPath: /frr-affinity-map:lib/affinity-maps/affinity-map
 */

static int lib_affinity_map_create(struct nb_cb_create_args *args)
{
	return NB_OK;
}

static int lib_affinity_map_destroy(struct nb_cb_destroy_args *args)
{
	const char *name;

	name = yang_dnode_get_string((const struct lyd_node *)args->dnode,
				     "./name");

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!affinity_map_check_use_hook(name))
			break;
		snprintf(args->errmsg, args->errmsg_len,
			 "affinity-map %s is used", name);
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		affinity_map_unset(name);
		break;
	}
	return NB_OK;
}

/*
 * XPath: /frr-affinity-map:lib/affinity-maps/affinity-map/value
 */
static int lib_affinity_map_value_modify(struct nb_cb_modify_args *args)
{
	const char *name;
	char *map_name;
	uint16_t pos;

	name = yang_dnode_get_string(
		(const struct lyd_node *)args->dnode->parent, "./name");

	pos = yang_dnode_get_uint16(
		(const struct lyd_node *)args->dnode->parent, "./value");

	switch (args->event) {
	case NB_EV_VALIDATE:
		map_name = affinity_map_name_get(pos);
		if (map_name &&
		    strncmp(map_name, name, AFFINITY_NAME_SIZE) != 0) {
			snprintf(args->errmsg, args->errmsg_len,
				 "bit-position is used by %s.", map_name);
			return NB_ERR_VALIDATION;
		}
		if (!affinity_map_check_update_hook(name, pos)) {
			snprintf(
				args->errmsg, args->errmsg_len,
				"affinity-map new bit-position > 31 but is used with standard admin-groups");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		affinity_map_update_hook(name, pos);
		affinity_map_set(name, pos);
		break;
	}

	return NB_OK;
}

static int lib_affinity_map_value_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_affinity_map_info = {
	.name = "frr-affinity-map",
	.nodes = {
		{
			.xpath = "/frr-affinity-map:lib/affinity-maps/affinity-map",
			.cbs = {
				.create = lib_affinity_map_create,
				.destroy = lib_affinity_map_destroy,
				.cli_show = cli_show_affinity_map,
			}
		},
		{
			.xpath = "/frr-affinity-map:lib/affinity-maps/affinity-map/value",
			.cbs = {
				.modify = lib_affinity_map_value_modify,
				.destroy = lib_affinity_map_value_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
