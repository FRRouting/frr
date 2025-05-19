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
#ifdef HAVE_STATICD_NB
#include "northbound_cli.h"
#endif /* HAVE_STATICD_NB */

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

#ifdef HAVE_STATICD_NB
static
#endif
struct static_vrf *static_vrf_lookup_by_name(const char *name)
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
#ifndef HAVE_STATICD_NB
			static_route_args_list_init(&svrf->route_args_list);
#endif /* !HAVE_STATICD_NB */
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
#ifndef HAVE_STATICD_NB
	struct static_route_args *args;
#endif /* !HAVE_STATICD_NB */
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

#ifndef HAVE_STATICD_NB
	frr_each_safe(static_route_args_list, &svrf->route_args_list, args) {
		static_route_args_list_del(&svrf->route_args_list, args);
		static_args_free(args);
	}
#endif /* !HAVE_STATICD_NB */

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

#ifndef HAVE_STATICD_NB
/* Write static route configuration. */
static int static_config(struct vty *vty, struct static_vrf *svrf, afi_t afi, safi_t safi,
			 const char *cmd)
{
	struct static_route_args *args;
	char spacing[100];
	int write = 0;

	if (!svrf)
		return 0;

	snprintf(spacing, sizeof(spacing), "%s%s", (svrf->vrf->vrf_id == VRF_DEFAULT) ? "" : " ",
		 cmd);

	frr_each_safe(static_route_args_list, &svrf->route_args_list, args) {
		if (args->afi != afi || args->safi != safi)
			continue;

		if (strcmp(svrf->vrf->name, args->vrf) != 0)
			continue;

		vty_out(vty, "%s %pFX ", spacing, &args->p);
		if (args->source)
			vty_out(vty, "from %s ", args->source);
		if (args->gateway)
			vty_out(vty, "%s ", args->gateway);
		if (args->interface_name)
			vty_out(vty, "%s ", args->interface_name);
		if (args->flag)
			vty_out(vty, "%s ", args->flag);
		if (args->tag)
			vty_out(vty, "tag %s ", args->tag);
		if (args->distance)
			vty_out(vty, "%s ", args->distance);
		if (args->label)
			vty_out(vty, "label %s ", args->label);
		if (args->segs)
			vty_out(vty, "segments %s ", args->segs);
		if (args->srv6_encap_behavior && !strmatch(args->srv6_encap_behavior, "H_Encaps"))
			vty_out(vty, "encap-behavior %s", args->srv6_encap_behavior);
		if (strcmp(args->vrf, args->nexthop_vrf) != 0)
			vty_out(vty, "nexthop-vrf %s ", args->nexthop_vrf);
		if (args->table)
			vty_out(vty, "table %s ", args->table);
		if (args->onlink)
			vty_out(vty, "onlink ");
		if (args->pm)
			vty_out(vty, "pm");
		if (args->color)
			vty_out(vty, "color %s ", args->color);
		if (args->bfd) {
			if (args->bfd_multi_hop) {
				vty_out(vty, "bfd multi-hop ");
				if (args->bfd_source)
					vty_out(vty, "source %s ", args->bfd_source);
			} else if (args->bfd_auto_hop)
				vty_out(vty, "bfd auto-hop ");
			else
				vty_out(vty, "bfd ");

			if (args->bfd_profile)
				vty_out(vty, "profile %s ", args->bfd_profile);
		}
		vty_out(vty, "\n");
		write = 1;
	}

	return write;
}
#endif /*!HAVE_STATICD_MGMTD */

#ifndef HAVE_STATICD_MGMTD
#ifdef HAVE_STATICD_NB
static int static_vrf_config_write(struct vty *vty)
{
	struct lyd_node *dnode;
	int written = 0;

	dnode = yang_dnode_get(running_config->dnode, "/frr-routing:routing");
	if (dnode) {
		nb_cli_show_dnode_cmds(vty, dnode, false);
		written = 1;
	}

	return written;
}
#else
/* !HAVE_STATICD_NB */
static int static_vrf_config_write(struct vty *vty)
{
	struct vrf *vrf;
	int written = 0;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (vrf->vrf_id != VRF_DEFAULT)
			vty_frame(vty, "vrf %s\n", vrf->name);

		written += static_config(vty, vrf->info, AFI_IP, SAFI_UNICAST, "ip route");
		written += static_config(vty, vrf->info, AFI_IP, SAFI_MULTICAST, "ip mroute");
		written += static_config(vty, vrf->info, AFI_IP6, SAFI_UNICAST, "ipv6 route");

		if (vrf->vrf_id != VRF_DEFAULT)
			vty_endframe(vty, "exit-vrf\n!\n");
	}

	return written;
}
#endif /* !HAVE_STATICD_NB */
#endif /*!HAVE_STATICD_MGMTD */

void static_vrf_init(void)
{
	vrf_init(static_vrf_new, static_vrf_enable, static_vrf_disable,
		 static_vrf_delete);

#ifdef HAVE_STATICD_MGMTD
	vrf_cmd_init(NULL, true);
#else  /*HAVE_STATICD_MGMTD */
	vrf_cmd_init(static_vrf_config_write, false);
#endif /*!HAVE_STATICD_MGMTD */
}

void static_vrf_terminate(void)
{
	struct static_vrf *svrf, *svrf_next;

	RB_FOREACH_SAFE (svrf, svrf_name_head, &svrfs, svrf_next)
		static_vrf_free(svrf);

	vrf_terminate();
}
