// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * STATICd - vrf code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#include <zebra.h>

#include "vrf.h"
#include "nexthop.h"
#include "table.h"
#include "srcdest_table.h"
#include "northbound_cli.h"

#include "static_vrf.h"
#include "static_routes.h"
#include "static_zebra.h"

DEFINE_MTYPE_STATIC(STATIC, STATIC_RTABLE_INFO, "Static Route Table Info");

static int svrf_name_compare(const struct static_vrf *a,
			     const struct static_vrf *b)
{
	return strcmp(a->name, b->name);
}

RB_GENERATE(svrf_name_head, static_vrf, entry, svrf_name_compare);

struct svrf_name_head svrfs = RB_INITIALIZER(&svrfs);

static struct static_vrf *static_vrf_lookup_by_name(const char *name)
{
	struct static_vrf svrf;

	strlcpy(svrf.name, name, sizeof(svrf.name));
	return RB_FIND(svrf_name_head, &svrfs, &svrf);
}

struct static_vrf *static_vrf_alloc(const char *name)
{
	struct route_table *table;
	struct static_vrf *svrf;
	struct stable_info *info;
	struct vrf *vrf;
	safi_t safi;
	afi_t afi;

	svrf = XCALLOC(MTYPE_STATIC_RTABLE_INFO, sizeof(struct static_vrf));

	strlcpy(svrf->name, name, sizeof(svrf->name));

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		for (safi = SAFI_UNICAST; safi <= SAFI_MULTICAST; safi++) {
			if (afi == AFI_IP6)
				table = srcdest_table_init();
			else
				table = route_table_init();

			info = XCALLOC(MTYPE_STATIC_RTABLE_INFO,
				       sizeof(struct stable_info));
			info->svrf = svrf;
			info->afi = afi;
			info->safi = safi;
			route_table_set_info(table, info);

			table->cleanup = zebra_stable_node_cleanup;
			svrf->stable[afi][safi] = table;
		}
	}

	RB_INSERT(svrf_name_head, &svrfs, svrf);

	vrf = vrf_lookup_by_name(name);
	if (vrf) {
		svrf->vrf = vrf;
		vrf->info = svrf;
	}

	return svrf;
}

void static_vrf_free(struct static_vrf *svrf)
{
	struct route_table *table;
	struct vrf *vrf;
	safi_t safi;
	afi_t afi;
	void *info;

	vrf = svrf->vrf;
	if (vrf) {
		vrf->info = NULL;
		svrf->vrf = NULL;
	}

	RB_REMOVE(svrf_name_head, &svrfs, svrf);

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		for (safi = SAFI_UNICAST; safi <= SAFI_MULTICAST; safi++) {
			table = svrf->stable[afi][safi];
			info = route_table_get_info(table);
			route_table_finish(table);
			XFREE(MTYPE_STATIC_RTABLE_INFO, info);
			svrf->stable[afi][safi] = NULL;
		}
	}

	XFREE(MTYPE_STATIC_RTABLE_INFO, svrf);
}

static int static_vrf_new(struct vrf *vrf)
{
	struct static_vrf *svrf;

	svrf = static_vrf_lookup_by_name(vrf->name);
	if (svrf) {
		vrf->info = svrf;
		svrf->vrf = vrf;
	}

	return 0;
}

static int static_vrf_enable(struct vrf *vrf)
{
	static_zebra_vrf_register(vrf);
	static_fixup_vrf_ids(vrf);
	return 0;
}

static int static_vrf_disable(struct vrf *vrf)
{
	static_cleanup_vrf_ids(vrf);
	static_zebra_vrf_unregister(vrf);
	return 0;
}

static int static_vrf_delete(struct vrf *vrf)
{
	struct static_vrf *svrf;

	svrf = vrf->info;
	if (svrf) {
		svrf->vrf = NULL;
		vrf->info = NULL;
	}

	return 0;
}

/* Lookup the static routing table in a VRF. */
struct route_table *static_vrf_static_table(afi_t afi, safi_t safi,
					    struct static_vrf *svrf)
{
	if (!svrf)
		return NULL;

	if (afi >= AFI_MAX || safi >= SAFI_MAX)
		return NULL;

	return svrf->stable[afi][safi];
}

void static_vrf_init(void)
{
	vrf_init(static_vrf_new, static_vrf_enable, static_vrf_disable,
		 static_vrf_delete);

	vrf_cmd_init(NULL);
}

void static_vrf_terminate(void)
{
	struct static_vrf *svrf, *svrf_next;

	RB_FOREACH_SAFE (svrf, svrf_name_head, &svrfs, svrf_next)
		static_vrf_free(svrf);

	vrf_terminate();
}
