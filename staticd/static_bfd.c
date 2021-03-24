/*
 * Static daemon BFD integration.
 *
 * Copyright (C) 2020-2022 Network Device Education Foundation, Inc. ("NetDEF")
 *                         Rafael Zalamena
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <zebra.h>

#include "lib/bfd.h"
#include "lib/printfrr.h"
#include "lib/srcdest_table.h"

#include "staticd/static_routes.h"
#include "staticd/static_zebra.h"

#include "lib/openbsd-queue.h"

/*
 * Next hop BFD monitoring settings.
 */
static void static_next_hop_bfd_change(struct static_nexthop *sn,
				       const struct bfd_session_status *bss)
{
	switch (bss->state) {
	case BSS_UNKNOWN:
		/* FALLTHROUGH: no known state yet. */
	case BSS_ADMIN_DOWN:
		/* NOTHING: we or the remote end administratively shutdown. */
		break;
	case BSS_DOWN:
		/* Peer went down, remove this next hop. */
		zlog_info("%s: next hop is down, remove it from RIB", __func__);
		sn->path_down = true;
		static_zebra_route_add(sn->pn, true);
		break;
	case BSS_UP:
		/* Peer is back up, add this next hop. */
		zlog_info("%s: next hop is up, add it to RIB", __func__);
		sn->path_down = false;
		static_zebra_route_add(sn->pn, true);
		break;
	}
}

static void static_next_hop_bfd_updatecb(
	__attribute__((unused)) struct bfd_session_params *bsp,
	const struct bfd_session_status *bss, void *arg)
{
	static_next_hop_bfd_change(arg, bss);
}

static inline int
static_next_hop_type_to_family(const struct static_nexthop *sn)
{
	switch (sn->type) {
	case STATIC_IPV4_GATEWAY_IFNAME:
	case STATIC_IPV6_GATEWAY_IFNAME:
	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV6_GATEWAY:
		if (sn->type == STATIC_IPV4_GATEWAY ||
		    sn->type == STATIC_IPV4_GATEWAY_IFNAME)
			return AF_INET;
		else
			return AF_INET6;
		break;
	case STATIC_IFNAME:
	case STATIC_BLACKHOLE:
	default:
		zlog_err("%s: invalid next hop type", __func__);
		break;
	}

	return AF_UNSPEC;
}

void static_next_hop_bfd_monitor_enable(struct static_nexthop *sn,
					const struct lyd_node *dnode)
{
	bool use_interface;
	bool use_profile;
	bool use_source;
	bool onlink;
	bool mhop;
	int family;
	struct ipaddr source;

	use_interface = false;
	use_source = yang_dnode_exists(dnode, "./source");
	use_profile = yang_dnode_exists(dnode, "./profile");
	onlink = yang_dnode_exists(dnode, "../onlink") &&
		 yang_dnode_get_bool(dnode, "../onlink");
	mhop = yang_dnode_get_bool(dnode, "./multi-hop");


	family = static_next_hop_type_to_family(sn);
	if (family == AF_UNSPEC)
		return;

	if (sn->type == STATIC_IPV4_GATEWAY_IFNAME ||
	    sn->type == STATIC_IPV6_GATEWAY_IFNAME)
		use_interface = true;

	/* Reconfigure or allocate new memory. */
	if (sn->bsp == NULL)
		sn->bsp = bfd_sess_new(static_next_hop_bfd_updatecb, sn);

	/* Configure the session. */
	if (use_source)
		yang_dnode_get_ip(&source, dnode, "./source");

	if (onlink || mhop == false)
		bfd_sess_set_auto_source(sn->bsp, false);
	else
		bfd_sess_set_auto_source(sn->bsp, !use_source);

	/* Configure the session.*/
	if (family == AF_INET)
		bfd_sess_set_ipv4_addrs(sn->bsp,
					use_source ? &source.ip._v4_addr : NULL,
					&sn->addr.ipv4);
	else if (family == AF_INET6)
		bfd_sess_set_ipv6_addrs(sn->bsp,
					use_source ? &source.ip._v6_addr : NULL,
					&sn->addr.ipv6);

	bfd_sess_set_interface(sn->bsp, use_interface ? sn->ifname : NULL);

	bfd_sess_set_profile(sn->bsp, use_profile ? yang_dnode_get_string(
							    dnode, "./profile")
						  : NULL);

	bfd_sess_set_hop_count(sn->bsp, (onlink || mhop == false) ? 1 : 254);

	/* Install or update the session. */
	bfd_sess_install(sn->bsp);

	/* Update current path status. */
	sn->path_down = (bfd_sess_status(sn->bsp) != BSS_UP);
}

void static_next_hop_bfd_monitor_disable(struct static_nexthop *sn)
{
	bfd_sess_free(&sn->bsp);

	/* Reset path status. */
	sn->path_down = false;
}

void static_next_hop_bfd_source(struct static_nexthop *sn,
				const struct ipaddr *source)
{
	int family;

	if (sn->bsp == NULL)
		return;

	family = static_next_hop_type_to_family(sn);
	if (family == AF_UNSPEC)
		return;

	bfd_sess_set_auto_source(sn->bsp, false);
	if (family == AF_INET)
		bfd_sess_set_ipv4_addrs(sn->bsp, &source->ip._v4_addr,
					&sn->addr.ipv4);
	else if (family == AF_INET6)
		bfd_sess_set_ipv6_addrs(sn->bsp, &source->ip._v6_addr,
					&sn->addr.ipv6);

	bfd_sess_install(sn->bsp);
}

void static_next_hop_bfd_auto_source(struct static_nexthop *sn)
{
	if (sn->bsp == NULL)
		return;

	bfd_sess_set_auto_source(sn->bsp, true);
	bfd_sess_install(sn->bsp);
}

void static_next_hop_bfd_multi_hop(struct static_nexthop *sn, bool mhop)
{
	if (sn->bsp == NULL)
		return;

	bfd_sess_set_hop_count(sn->bsp, mhop ? 254 : 1);
	bfd_sess_install(sn->bsp);
}

void static_next_hop_bfd_profile(struct static_nexthop *sn, const char *name)
{
	if (sn->bsp == NULL)
		return;

	bfd_sess_set_profile(sn->bsp, name);
	bfd_sess_install(sn->bsp);
}

void static_bfd_initialize(struct zclient *zc, struct thread_master *tm)
{
	/* Initialize BFD integration library. */
	bfd_protocol_integration_init(zc, tm);
}
