/* zebra NS Routines
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *                    Donald Sharp
 * Copyright (C) 2017/2018 6WIND
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include "zebra.h"

#include "lib/ns.h"
#include "lib/vrf.h"
#include "lib/prefix.h"
#include "lib/memory.h"

#include "zebra_ns.h"
#include "zebra_vrf.h"
#include "zebra_memory.h"
#include "rt.h"
#include "zebra_vxlan.h"
#include "debug.h"
#include "zebra_netns_notify.h"
#include "zebra_netns_id.h"
#include "zebra_pbr.h"
#include "rib.h"
#include "table_manager.h"
#include "zebra_errors.h"

extern struct zebra_privs_t zserv_privs;

DEFINE_MTYPE(ZEBRA, ZEBRA_NS, "Zebra Name Space")

static struct zebra_ns *dzns;

static int zebra_ns_disable_internal(struct zebra_ns *zns, bool complete);

struct zebra_ns *zebra_ns_lookup(ns_id_t ns_id)
{
	if (ns_id == NS_DEFAULT)
		return dzns;
	struct zebra_ns *info = (struct zebra_ns *)ns_info_lookup(ns_id);

	return (info == NULL) ? dzns : info;
}

static struct zebra_ns *zebra_ns_alloc(void)
{
	return XCALLOC(MTYPE_ZEBRA_NS, sizeof(struct zebra_ns));
}

static int zebra_ns_new(struct ns *ns)
{
	struct zebra_ns *zns;

	if (!ns)
		return -1;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_info("ZNS %s with id %u (created)", ns->name, ns->ns_id);

	zns = zebra_ns_alloc();
	ns->info = zns;
	zns->ns = ns;
	zns->ns_id = ns->ns_id;

	/* Do any needed per-NS data structure allocation. */
	zns->if_table = route_table_init();

	return 0;
}

static int zebra_ns_delete(struct ns *ns)
{
	struct zebra_ns *zns = (struct zebra_ns *)ns->info;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_info("ZNS %s with id %u (deleted)", ns->name, ns->ns_id);
	if (!zns)
		return 0;
	XFREE(MTYPE_ZEBRA_NS, ns->info);
	return 0;
}

static int zebra_ns_enabled(struct ns *ns)
{
	struct zebra_ns *zns = ns->info;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_info("ZNS %s with id %u (enabled)", ns->name, ns->ns_id);
	if (!zns)
		return 0;
	return zebra_ns_enable(ns->ns_id, (void **)&zns);
}

int zebra_ns_disabled(struct ns *ns)
{
	struct zebra_ns *zns = ns->info;

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_info("ZNS %s with id %u (disabled)", ns->name, ns->ns_id);
	if (!zns)
		return 0;
	return zebra_ns_disable_internal(zns, true);
}

/* Do global enable actions - open sockets, read kernel config etc. */
int zebra_ns_enable(ns_id_t ns_id, void **info)
{
	struct zebra_ns *zns = (struct zebra_ns *)(*info);

	zns->ns_id = ns_id;

	kernel_init(zns);
	interface_list(zns);
	route_read(zns);

	/* Initiate Table Manager per ZNS */
	table_manager_enable(ns_id);

	return 0;
}

/* Common handler for ns disable - this can be called during ns config,
 * or during zebra shutdown.
 */
static int zebra_ns_disable_internal(struct zebra_ns *zns, bool complete)
{
	route_table_finish(zns->if_table);

	kernel_terminate(zns, complete);

	table_manager_disable(zns->ns_id);

	zns->ns_id = NS_DEFAULT;

	return 0;
}

/* During zebra shutdown, do partial cleanup while the async dataplane
 * is still running.
 */
int zebra_ns_early_shutdown(struct ns *ns)
{
	struct zebra_ns *zns = ns->info;

	if (zns == NULL)
		return 0;

	return zebra_ns_disable_internal(zns, false);
}

/* During zebra shutdown, do final cleanup
 * after all dataplane work is complete.
 */
int zebra_ns_final_shutdown(struct ns *ns)
{
	struct zebra_ns *zns = ns->info;

	if (zns == NULL)
		return 0;

	kernel_terminate(zns, true);

	return 0;
}

int zebra_ns_init(const char *optional_default_name)
{
	struct ns *default_ns;
	ns_id_t ns_id;
	ns_id_t ns_id_external;

	frr_with_privs(&zserv_privs) {
		ns_id = zebra_ns_id_get_default();
	}
	ns_id_external = ns_map_nsid_with_external(ns_id, true);
	ns_init_management(ns_id_external, ns_id);

	default_ns = ns_lookup(ns_get_default_id());
	if (!default_ns) {
		flog_err(EC_ZEBRA_NS_NO_DEFAULT,
			 "%s: failed to find default ns", __func__);
		exit(EXIT_FAILURE); /* This is non-recoverable */
	}

	/* Do any needed per-NS data structure allocation. */
	zebra_ns_new(default_ns);
	dzns = default_ns->info;

	/* Register zebra VRF callbacks, create and activate default VRF. */
	zebra_vrf_init();

	/* Default NS is activated */
	zebra_ns_enable(ns_id_external, (void **)&dzns);

	if (optional_default_name)
		vrf_set_default_name(optional_default_name,
				     true);

	if (vrf_is_backend_netns()) {
		ns_add_hook(NS_NEW_HOOK, zebra_ns_new);
		ns_add_hook(NS_ENABLE_HOOK, zebra_ns_enabled);
		ns_add_hook(NS_DISABLE_HOOK, zebra_ns_disabled);
		ns_add_hook(NS_DELETE_HOOK, zebra_ns_delete);
		zebra_ns_notify_parse();
		zebra_ns_notify_init();
	}

	return 0;
}

int zebra_ns_config_write(struct vty *vty, struct ns *ns)
{
	if (ns && ns->name != NULL)
		vty_out(vty, " netns %s\n", ns->name);
	return 0;
}
