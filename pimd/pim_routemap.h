// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM route-map definitions
 * Copyright (C) 2021  David Lamparter for NetDEF, Inc.
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

	char *alistname;
	struct access_list *alist;
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
extern void pim_filter_ref_set_alist(struct pim_filter_ref *ref, const char *alistname);
extern void pim_filter_ref_update(void);

#endif /* _PIM_ROUTEMAP_H */
