// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * VRF library for PBR
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *               Stephen Worley
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

extern struct pbr_vrf *pbr_vrf_lookup_by_name(const char *name);
extern bool pbr_vrf_is_valid(const struct pbr_vrf *pbr_vrf);
extern bool pbr_vrf_is_enabled(const struct pbr_vrf *pbr_vrf);

extern void pbr_vrf_init(void);
extern void pbr_vrf_terminate(void);
#endif
