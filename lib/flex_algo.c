/*
 * Flexible Algorithm definitions
 * Copyright (C) 2022  Hiroki Shirokura, LINE Corporation
 * Copyright (C) 2022  Masakazu Asama
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include "zebra.h"

#include "flex_algo.h"
#include "bitfield.h"

DEFINE_MTYPE_STATIC(LIB, FLEX_ALGO, "Flex-Algo Definition");

static void affinity_map_free(void *map)
{
	struct affinity_map *map_ = map;
	XFREE(MTYPE_FLEX_ALGO, map_);
}

struct affinity_maps *affinity_maps_alloc(void)
{
	struct affinity_maps *maps;
	maps = XCALLOC(MTYPE_FLEX_ALGO, sizeof(*maps));
	maps->maps = list_new();
	maps->maps->del = affinity_map_free;
	return maps;
}

void affinity_maps_free(struct affinity_maps *maps)
{
	list_delete(&maps->maps);
	XFREE(MTYPE_FLEX_ALGO, maps);
}

void affinity_map_set(struct affinity_maps *maps, const char *name, int pos)
{
	struct listnode *node;
	struct affinity_map *map;

	for (ALL_LIST_ELEMENTS_RO(maps->maps, node, map)) {
		if (strncmp(name, map->name, AFFINITY_NAME_SIZE) != 0)
			continue;
		map->bit_position = pos;
		return;
	}

	map = XCALLOC(MTYPE_FLEX_ALGO, sizeof(*map));
	map->bit_position = pos;
	snprintf(map->name, sizeof(map->name), "%s", name);
	listnode_add(maps->maps, map);
}

void affinity_map_unset(struct affinity_maps *maps, const char *name)
{
	struct listnode *node;
	struct affinity_map *map;

	for (ALL_LIST_ELEMENTS_RO(maps->maps, node, map)) {
		if (strncmp(name, map->name, AFFINITY_NAME_SIZE) != 0)
			continue;
		map->bit_position = -1;
		return;
	}
}

struct affinity_map *affinity_map_get(const struct affinity_maps *maps,
					 const char *name)
{
	struct listnode *node;
	struct affinity_map *map;

	for (ALL_LIST_ELEMENTS_RO(maps->maps, node, map))
		if (strncmp(name, map->name, AFFINITY_NAME_SIZE) == 0)
			return map;
	return NULL;
}

/*
 * Admin Group Utilities
 */

char *admin_group_string(char *out, size_t sz, const struct admin_group *ag)
{
	size_t index = 2;

	if (sz < index)
		return out;

	if (admin_group_size(ag) == 0) {
		snprintf(out, sz, "not-set");
		return out;
	}

	snprintf(out, sz, "0x");
	bool printed = false;
	for (ssize_t i = ag->bitmap.m - 1; i >= 0; i--) {
		if (sz - index <= 0)
			break;
		if (ag->bitmap.data[i] == 0 && !printed)
			continue;
		snprintf(&out[index], sz - index, "%08x", ag->bitmap.data[i]);
		index += 8;
		printed = true;
	}
	return out;
}

void admin_group_copy(struct admin_group *dst, const struct admin_group *src)
{
	assert(bf_is_inited(src->bitmap));
	if (bf_is_inited(dst->bitmap))
		bf_free(dst->bitmap);
	dst->bitmap = bf_copy(src->bitmap);
}

void admin_group_init(struct admin_group *ag)
{
	assert(!bf_is_inited(ag->bitmap));
	bf_init(ag->bitmap, 32);
}

void admin_group_term(struct admin_group *ag)
{
	assert(bf_is_inited(ag->bitmap));
	bf_free(ag->bitmap);
}

uint32_t admin_group_get_offset(const struct admin_group *ag, size_t oct_offset)
{
	assert(bf_is_inited(ag->bitmap));
	if (ag->bitmap.m < oct_offset)
		return 0;
	return ag->bitmap.data[oct_offset];
}

void admin_group_set(struct admin_group *ag, size_t pos)
{
	bf_set_bit(ag->bitmap, pos);
}

void admin_group_unset(struct admin_group *ag, size_t pos)
{
	bf_release_index(ag->bitmap, pos);
}

void admin_group_set_offset(struct admin_group *ag, size_t pos,
			    size_t oct_offset)
{
	admin_group_set(ag, 32 * oct_offset + pos);
}

void admin_group_unset_offset(struct admin_group *ag, size_t pos,
			      size_t oct_offset)
{
	admin_group_unset(ag, 32 * oct_offset + pos);
}

void admin_group_bulk_set(struct admin_group *ag, uint32_t bitmap,
			  size_t oct_offset)
{
	for (int i = 0; i < 32; i++) {
		if ((bitmap & (0x01 << i)) == 0)
			continue;
		size_t pos = 32 * oct_offset + i;
		admin_group_set(ag, pos);
	}
}

size_t admin_group_size(const struct admin_group *ag)
{
	size_t size = 0;
	for (size_t i = 0; i < ag->bitmap.m; i++)
		if (ag->bitmap.data[i] != 0)
			size = i + 1;
	return size;
}

void admin_group_clear(struct admin_group *ag)
{
	for (size_t i = 0; i < ag->bitmap.m; i++)
		ag->bitmap.data[i] = 0;
}

bool admin_group_zero(const struct admin_group *ag)
{
	for (size_t i = 0; i < ag->bitmap.m; i++)
		if (ag->bitmap.data[i] != 0)
			return false;
	return true;
}

bool admin_group_match_any(const struct admin_group *fad_ag,
			   const struct admin_group *link_ag)
{
	assert(fad_ag);
	assert(link_ag);
	for (size_t i = 0; i < fad_ag->bitmap.m; i++) {
		if (link_ag->bitmap.m <= i)
			break;
		uint32_t fad_ag_bitmap = fad_ag->bitmap.data[i];
		uint32_t link_ag_bitmap = link_ag->bitmap.data[i];
		if (fad_ag_bitmap & link_ag_bitmap)
			return true;
	}
	return false;
}

bool admin_group_match_all(const struct admin_group *fad_ag,
			   const struct admin_group *link_ag)
{
	for (size_t i = 0; i < fad_ag->bitmap.m; i++) {
		if (fad_ag->bitmap.data[i] == 0)
			continue;
		if (link_ag->bitmap.m < i)
			return false;
		if ((fad_ag->bitmap.data[i] & link_ag->bitmap.data[i])
		    != fad_ag->bitmap.data[i])
			return false;
	}
	return true;
}

struct flex_algos *flex_algos_alloc(flex_algo_allocator_t allocator,
				    flex_algo_releaser_t releaser)
{
	struct flex_algos *flex_algos;

	flex_algos = XCALLOC(MTYPE_FLEX_ALGO, sizeof(*flex_algos));
	flex_algos->flex_algos = list_new();
	flex_algos->allocator = allocator;
	flex_algos->releaser = releaser;
	return flex_algos;
}

struct flex_algo *flex_algo_alloc(struct flex_algos *flex_algos,
				  uint8_t algorithm, void *arg)
{
	struct flex_algo *fa;

	fa = XCALLOC(MTYPE_FLEX_ALGO, sizeof(*fa));
	fa->algorithm = algorithm;
	if (flex_algos->allocator)
		fa->data = flex_algos->allocator(arg);
	admin_group_init(&fa->admin_group_exclude_any);
	admin_group_init(&fa->admin_group_include_any);
	admin_group_init(&fa->admin_group_include_all);
	listnode_add(flex_algos->flex_algos, fa);
	return fa;
}

/**
 * @brief Look up the local flex-algo object by its algorithm number.
 * @param algorithm flex-algo algorithm number
 * @param area area pointer of flex-algo
 * @return local flex-algo object if exist, else NULL
 */
struct flex_algo *flex_algo_lookup(struct flex_algos *flex_algos,
				   uint8_t algorithm)
{
	struct listnode *node;
	struct flex_algo *fa;

	for (ALL_LIST_ELEMENTS_RO(flex_algos->flex_algos, node, fa))
		if (fa->algorithm == algorithm)
			return fa;
	return NULL;
}

void flex_algo_delete(struct flex_algos *flex_algos, uint8_t algorithm)
{
	struct listnode *node, *nnode;
	struct flex_algo *fa;

	for (ALL_LIST_ELEMENTS(flex_algos->flex_algos, node, nnode, fa)) {
		if (fa->algorithm != algorithm)
			continue;
		if (flex_algos->releaser)
			flex_algos->releaser(fa->data);
		admin_group_term(&fa->admin_group_exclude_any);
		admin_group_term(&fa->admin_group_include_any);
		admin_group_term(&fa->admin_group_include_all);
		listnode_delete(flex_algos->flex_algos, fa);
		XFREE(MTYPE_FLEX_ALGO, fa);
		return;
	}
}

/**
 * Check SR Algorithm is Flex-Algo
 * according to draft-ietf-lsr-flex-algo-18#section-4
 *
 * @param algorithm SR Algorithm
 *
 * @return true if (255 >= algorithm >= 128)
 */
bool is_flex_algo(uint8_t algorithm)
{
	return algorithm >= 128;
}
