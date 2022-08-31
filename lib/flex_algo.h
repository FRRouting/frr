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

#ifndef _FRR_FLEX_ALGO_H
#define _FRR_FLEX_ALGO_H

#include "linklist.h"
#include "prefix.h"
#include "bitfield.h"
#include "segment_routing.h"

#define AFFINITY_NAME_SIZE 256
#define FLEX_ALGO_PRIO_DEFAULT 128

# define CALC_TYPE_SPF 0

/*
 * Metric Type values from draft-ietf-lsr-flex-algo-19
 */
enum flex_algo_metric_type {
	MT_IGP = 0,
	MT_MIN_UNI_LINK_DELAY = 1,
	MT_TE_DEFAULT = 2,
};

struct affinity_map {
	char name[AFFINITY_NAME_SIZE];
	uint8_t bit_position;
};

struct affinity_maps {
	struct list *maps;
};

struct admin_group {
        bitfield_t bitmap;
};

struct flex_algo {
	uint8_t algorithm;
	enum flex_algo_metric_type metric_type;
	uint8_t calc_type;
	uint8_t priority;
	bool m_flag; /* prefix-metric */

	bool advertise_definition;

	struct admin_group admin_group_exclude_any;
	struct admin_group admin_group_include_any;
    struct admin_group admin_group_include_all;

	/*
	 * This property can be freely extended among different routing
	 * protocols. Since Flex-Algo is an IGP protocol agnostic, both IS-IS
	 * and OSPF can implement Flex-Algo. The struct flex_algo thus provides
	 * the general data structure of Flex-Algo, and the value of extending
	 * it with the IGP protocol is provided by this property.
	 */
	void *data;
};

typedef void *(*flex_algo_allocator_t)(void *);
typedef void (*flex_algo_releaser_t)(void *);

struct flex_algos {
	flex_algo_allocator_t allocator;
	flex_algo_releaser_t releaser;
	struct list *flex_algos;
};

/*
 * Affinity Map Utilities
 */
struct affinity_maps *affinity_maps_alloc(void);
void affinity_maps_free(struct affinity_maps *maps);
void affinity_map_set(struct affinity_maps *maps, const char *name, int pos);
void affinity_map_unset(struct affinity_maps *maps, const char *name);
struct affinity_map *affinity_map_get(const struct affinity_maps *maps,
				      const char *name);
char *affinity_map_name_get(const struct affinity_maps *maps,
					 int pos);

/*
 * Admin Group Utilities
 */
char *admin_group_string(char *out, size_t sz, const struct admin_group *ag);
void admin_group_copy(struct admin_group *dst, const struct admin_group *src);
void admin_group_init(struct admin_group *ag);
void admin_group_term(struct admin_group *ag);
uint32_t admin_group_get_offset(const struct admin_group *ag,
				size_t oct_offset);
void admin_group_set(struct admin_group *ag, size_t pos);
void admin_group_unset(struct admin_group *ag, size_t pos);
int admin_group_get(struct admin_group *ag, size_t pos);
void admin_group_set_offset(struct admin_group *ag, size_t pos,
			    size_t oct_offset);
void admin_group_unset_offset(struct admin_group *ag, size_t pos,
			      size_t oct_offset);
void admin_group_bulk_set(struct admin_group *ag, uint32_t bitmap,
			  size_t oct_offset);
size_t admin_group_size(const struct admin_group *ag);
void admin_group_clear(struct admin_group *ag);
bool admin_group_zero(const struct admin_group *ag);
bool admin_group_match_any(const struct admin_group *fad_ag,
			   const struct admin_group *link_ag);
bool admin_group_match_all(const struct admin_group *fad_ag,
			   const struct admin_group *link_ag);

/*
 * Flex-Algo Utilities
 */
struct flex_algos *flex_algos_alloc(flex_algo_allocator_t allocator,
				    flex_algo_releaser_t releaser);
struct flex_algo *flex_algo_alloc(struct flex_algos *flex_algos,
				  uint8_t algorithm, void *arg);
struct flex_algo *flex_algo_lookup(struct flex_algos *flex_algos,
				   uint8_t algorithm);
void flex_algos_free(struct flex_algos *flex_algos);
void flex_algo_delete(struct flex_algos *flex_algos, uint8_t algorithm);
bool is_flex_algo(uint8_t algorithm);
char *flex_algo_metric_type_print(char *type_str, size_t sz, enum flex_algo_metric_type metric_type);

#endif /* _FRR_FLEX_ALGO_H */
