/*
 * STATICd - vrf header
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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
