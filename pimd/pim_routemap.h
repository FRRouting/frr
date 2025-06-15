/*
 * PIM route-map definitions
 * Copyright (C) 2021  David Lamparter for NetDEF, Inc.
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

#ifndef _PIM_ROUTEMAP_H
#define _PIM_ROUTEMAP_H

#include "if.h"

struct prefix_sg;
struct route_map;

PREDECL_DLIST(pim_filter_refs);

struct pim_filter_ref {
	struct pim_filter_refs_item itm;

	char *rmapname;
	struct route_map *rmap;
};

/* pure ACL check.  shouldn't be made to modify anything if that is
 * implemented at some point in the future.  create a new function for that.
 *
 * sg is required, interface is optional
 */
extern bool pim_filter_match(const struct pim_filter_ref *ref, const struct prefix_sg *sg,
			     struct interface *interface);

extern void pim_sg_to_prefix(const pim_sgaddr *sg, struct prefix_sg *prefix);

extern void pim_filter_ref_init(struct pim_filter_ref *ref);
extern void pim_filter_ref_fini(struct pim_filter_ref *ref);
extern void pim_filter_ref_set_rmap(struct pim_filter_ref *ref, const char *rmapname);
extern void pim_filter_ref_update(void);

#endif /* _PIM_ROUTEMAP_H */
