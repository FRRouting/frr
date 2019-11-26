/*
 * PBR - vrf code
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
#include <zebra.h>

#include "vrf.h"

#include "pbr_vrf.h"
#include "pbr_memory.h"
#include "pbr_map.h"
#include "pbr_debug.h"

DEFINE_MTYPE_STATIC(PBRD, PBR_MAP_VRF, "PBR Map VRF")

static struct pbr_vrf *pbr_vrf_alloc(void)
{
	struct pbr_vrf *pbr_vrf;

	pbr_vrf = XCALLOC(MTYPE_PBR_MAP_VRF, sizeof(struct pbr_vrf));

	return pbr_vrf;
}

static void pbr_vrf_free(struct pbr_vrf *pbr_vrf)
{
	XFREE(MTYPE_PBR_MAP_VRF, pbr_vrf);
}

static int pbr_vrf_new(struct vrf *vrf)
{
	struct pbr_vrf *pbr_vrf;

	DEBUGD(&pbr_dbg_event, "%s: %u (%s)", __func__, vrf->vrf_id, vrf->name);

	pbr_vrf = pbr_vrf_alloc();
	vrf->info = pbr_vrf;
	pbr_vrf->vrf = vrf;

	return 0;
}

static int pbr_vrf_enable(struct vrf *vrf)
{
	DEBUGD(&pbr_dbg_event, "%s: %u (%s)", __func__, vrf->vrf_id, vrf->name);

	pbr_map_vrf_update(vrf->info);

	return 0;
}

static int pbr_vrf_disable(struct vrf *vrf)
{
	DEBUGD(&pbr_dbg_event, "%s: %u (%s)", __func__, vrf->vrf_id, vrf->name);

	pbr_map_vrf_update(vrf->info);

	return 0;
}

static int pbr_vrf_delete(struct vrf *vrf)
{
	DEBUGD(&pbr_dbg_event, "%s: %u (%s)", __func__, vrf->vrf_id, vrf->name);

	/*
	 * Make sure vrf is always marked disabled first so we handle
	 * pbr rules using it.
	 */
	assert(!vrf_is_enabled(vrf));

	pbr_vrf_free(vrf->info);
	vrf->info = NULL;

	return 0;
}

struct pbr_vrf *pbr_vrf_lookup_by_id(vrf_id_t vrf_id)
{
	struct vrf *vrf;

	vrf = vrf_lookup_by_id(vrf_id);
	if (vrf)
		return ((struct pbr_vrf *)vrf->info);

	return NULL;
}

struct pbr_vrf *pbr_vrf_lookup_by_name(const char *name)
{
	struct vrf *vrf;

	if (!name)
		name = VRF_DEFAULT_NAME;

	vrf = vrf_lookup_by_name(name);
	if (vrf)
		return ((struct pbr_vrf *)vrf->info);

	return NULL;
}

bool pbr_vrf_is_enabled(const struct pbr_vrf *pbr_vrf)
{
	return vrf_is_enabled(pbr_vrf->vrf) ? true : false;
}

bool pbr_vrf_is_valid(const struct pbr_vrf *pbr_vrf)
{
	if (vrf_is_backend_netns())
		return false;

	if (!pbr_vrf->vrf)
		return false;

	return pbr_vrf_is_enabled(pbr_vrf);
}

void pbr_vrf_init(void)
{
	vrf_init(pbr_vrf_new, pbr_vrf_enable, pbr_vrf_disable, pbr_vrf_delete,
		 NULL);
}
