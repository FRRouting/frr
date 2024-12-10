// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * STATICd - vrf header
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#ifndef __STATIC_VRF_H__
#define __STATIC_VRF_H__

#include "openbsd-tree.h"

#ifndef HAVE_STATICD_NB
#include "static_vty.h"
#endif /* !HAVE_STATICD_NB */

#ifdef __cplusplus
extern "C" {
#endif

struct static_vrf {
	RB_ENTRY(static_vrf) entry;

	char name[VRF_NAMSIZ + 1];
	struct vrf *vrf;

	struct route_table *stable[AFI_MAX][SAFI_MAX];

#ifndef HAVE_STATICD_NB
	/* static config args list */
	struct static_route_args_list_head route_args_list;
#endif /* !HAVE_STATICD_NB */
};

#ifndef HAVE_STATICD_NB
DECLARE_DLIST(static_route_args_list, struct static_route_args, list);
#endif /* !HAVE_STATICD_NB */

RB_HEAD(svrf_name_head, static_vrf);
RB_PROTOTYPE(svrf_name_head, static_vrf, entry, svrf_name_compare)

extern struct svrf_name_head svrfs;

#ifndef HAVE_STATICD_NB
struct static_vrf *static_vrf_lookup_by_name(const char *name);
#endif /* !HAVE_STATICD_NB */
struct static_vrf *static_vrf_alloc(const char *name);
void static_vrf_free(struct static_vrf *svrf);

struct stable_info {
	struct static_vrf *svrf;
	afi_t afi;
	safi_t safi;
};

#define GET_STABLE_VRF_ID(info) info->svrf->vrf->vrf_id

void static_vrf_init(void);

struct route_table *static_vrf_static_table(afi_t afi, safi_t safi,
					    struct static_vrf *svrf);
extern void static_vrf_terminate(void);

#ifdef __cplusplus
}
#endif

#endif
