// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Affinity map function.
 *
 * Copyright 2022 Hiroki Shirokura, LINE Corporation
 * Copyright 2022 Masakazu Asama
 * Copyright 2022 6WIND S.A.
 */

#include <zebra.h>

#include "linklist.h"
#include "memory.h"
#include "command.h"
#include "vector.h"
#include "prefix.h"
#include "vty.h"
#include "affinitymap.h"
#include "command.h"
#include "log.h"
#include "hash.h"
#include "libfrr.h"
#include "lib_errors.h"
#include "table.h"
#include "json.h"
#include "jhash.h"

DEFINE_MTYPE_STATIC(LIB, AFFINITY_MAP, "Affinity map");

DEFINE_QOBJ_TYPE(affinity_maps);
DEFINE_QOBJ_TYPE(affinity_map);

struct affinity_maps affinity_map_master = {NULL, NULL};

static void affinity_map_free(struct affinity_map *map)
{
	XFREE(MTYPE_AFFINITY_MAP, map);
}

void affinity_map_set(const char *name, int pos)
{
	struct listnode *node;
	struct affinity_map *map;

	if (!affinity_map_master.maps)
		affinity_map_master.maps = list_new();

	for (ALL_LIST_ELEMENTS_RO(affinity_map_master.maps, node, map)) {
		if (strncmp(name, map->name, AFFINITY_NAME_SIZE) != 0)
			continue;
		map->bit_position = pos;
		return;
	}

	map = XCALLOC(MTYPE_AFFINITY_MAP, sizeof(*map));
	map->bit_position = pos;
	snprintf(map->name, sizeof(map->name), "%s", name);
	listnode_add(affinity_map_master.maps, map);
}

void affinity_map_unset(const char *name)
{
	struct listnode *node, *nnode;
	struct affinity_map *map;

	if (!affinity_map_master.maps)
		return;

	for (ALL_LIST_ELEMENTS(affinity_map_master.maps, node, nnode, map)) {
		if (strncmp(name, map->name, AFFINITY_NAME_SIZE) != 0)
			continue;
		listnode_delete(affinity_map_master.maps, map);
		affinity_map_free(map);
		return;
	}
}

struct affinity_map *affinity_map_get(const char *name)
{
	struct listnode *node;
	struct affinity_map *map;

	if (!affinity_map_master.maps)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(affinity_map_master.maps, node, map))
		if (strncmp(name, map->name, AFFINITY_NAME_SIZE) == 0)
			return map;
	return NULL;
}

void affinity_map_update_hook(const char *affmap_name, uint16_t new_pos)
{
	struct affinity_map *map;

	if (!affinity_map_master.update_hook)
		return;

	map = affinity_map_get(affmap_name);

	if (!map)
		/* Affinity-map creation */
		return;

	(*affinity_map_master.update_hook)(affmap_name, map->bit_position,
					   new_pos);
}

void affinity_map_set_update_hook(void (*func)(const char *affmap_name,
					       uint16_t old_pos,
					       uint16_t new_pos))
{
	affinity_map_master.update_hook = func;
}

void affinity_map_terminate(void)
{
	struct affinity_map *map;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(affinity_map_master.maps, node, nnode, map))
		affinity_map_free(map);
}
