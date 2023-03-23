// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * STATICd - vrf header
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#ifndef __STATIC_VRF_H__
#define __STATIC_VRF_H__

#ifdef __cplusplus
extern "C" {
#endif

struct static_vrf {
	struct vrf *vrf;

	struct route_table *stable[AFI_MAX][SAFI_MAX];
};

struct stable_info {
	struct static_vrf *svrf;
	afi_t afi;
	safi_t safi;
};

#define GET_STABLE_VRF_ID(info) info->svrf->vrf->vrf_id

struct static_vrf *static_vrf_lookup_by_name(const char *vrf_name);

void static_vrf_init(void);

struct route_table *static_vrf_static_table(afi_t afi, safi_t safi,
					    struct static_vrf *svrf);
extern void static_vrf_terminate(void);

#ifdef __cplusplus
}
#endif

#endif
