// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * STATICd - vrf header
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#ifndef __STATIC_VRF_H__
#define __STATIC_VRF_H__

<<<<<<< HEAD
=======
#include "openbsd-tree.h"

>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
#ifdef __cplusplus
extern "C" {
#endif

struct static_vrf {
<<<<<<< HEAD
=======
	RB_ENTRY(static_vrf) entry;

	char name[VRF_NAMSIZ + 1];
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
	struct vrf *vrf;

	struct route_table *stable[AFI_MAX][SAFI_MAX];
};
<<<<<<< HEAD
=======
RB_HEAD(svrf_name_head, static_vrf);
RB_PROTOTYPE(svrf_name_head, static_vrf, entry, svrf_name_compare)

extern struct svrf_name_head svrfs;

struct static_vrf *static_vrf_alloc(const char *name);
void static_vrf_free(struct static_vrf *svrf);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

struct stable_info {
	struct static_vrf *svrf;
	afi_t afi;
	safi_t safi;
};

#define GET_STABLE_VRF_ID(info) info->svrf->vrf->vrf_id

<<<<<<< HEAD
struct static_vrf *static_vrf_lookup_by_name(const char *vrf_name);

=======
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
void static_vrf_init(void);

struct route_table *static_vrf_static_table(afi_t afi, safi_t safi,
					    struct static_vrf *svrf);
extern void static_vrf_terminate(void);

#ifdef __cplusplus
}
#endif

#endif
