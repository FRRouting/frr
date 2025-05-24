// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Affinity-map function.
 *
 * Copyright 2022 Hiroki Shirokura, LINE Corporation
 * Copyright 2022 Masakazu Asama
 * Copyright 2022 6WIND S.A.
 */

#ifndef _ZEBRA_AFFINITYMAP_H
#define _ZEBRA_AFFINITYMAP_H

#include "typesafe.h"
#include "prefix.h"
#include "memory.h"
#include "qobj.h"
#include "vty.h"
#include "lib/plist.h"
#include "lib/plist_int.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AFFINITY_NAME_SIZE 32

struct affinity_map {
	char name[AFFINITY_NAME_SIZE];
	uint16_t bit_position;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(affinity_map);

struct affinity_maps {
	struct list *maps;

	void (*update_hook)(const char *affmap_name, uint16_t old_pos,
			    uint16_t new_pos);

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(affinity_maps);

extern const struct frr_yang_module_info frr_affinity_map_info;
extern const struct frr_yang_module_info frr_affinity_map_cli_info;

void affinity_map_set(const char *name, int pos);
void affinity_map_unset(const char *name);
struct affinity_map *affinity_map_get(const char *name);

void affinity_map_update_hook(const char *affmap_name, uint16_t new_pos);

void affinity_map_set_update_hook(void (*func)(const char *affmap_name,
					       uint16_t old_pos,
					       uint16_t new_pos));

void affinity_map_init(void);
void affinity_map_terminate(void);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_AFFINITYMAP_H */
