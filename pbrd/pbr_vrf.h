/*
 * VRF library for PBR
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *               Stephen Worley
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __PBR_VRF_H__
#define __PBR_VRF_H__

struct pbr_vrf {
	struct vrf *vrf;
};

static inline const char *pbr_vrf_name(const struct pbr_vrf *pbr_vrf)
{
	return pbr_vrf->vrf->name;
}

static inline vrf_id_t pbr_vrf_id(const struct pbr_vrf *pbr_vrf)
{
	return pbr_vrf->vrf->vrf_id;
}

extern struct pbr_vrf *pbr_vrf_lookup_by_id(vrf_id_t vrf_id);
extern struct pbr_vrf *pbr_vrf_lookup_by_name(const char *name);
extern bool pbr_vrf_is_valid(const struct pbr_vrf *pbr_vrf);
extern bool pbr_vrf_is_enabled(const struct pbr_vrf *pbr_vrf);

extern void pbr_vrf_init(void);
#endif
