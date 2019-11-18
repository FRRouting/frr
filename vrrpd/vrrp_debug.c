/*
 * VRRP debugging.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 * Quentin Young
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
#include <zebra.h>

#include "lib/command.h"
#include "lib/debug.h"
#include "lib/vector.h"

#include "vrrp_debug.h"

/* clang-format off */
struct debug vrrp_dbg_arp = {0, "VRRP ARP"};
struct debug vrrp_dbg_auto = {0, "VRRP autoconfiguration events"};
struct debug vrrp_dbg_ndisc = {0, "VRRP Neighbor Discovery"};
struct debug vrrp_dbg_pkt = {0, "VRRP packets"};
struct debug vrrp_dbg_proto = {0, "VRRP protocol events"};
struct debug vrrp_dbg_sock = {0, "VRRP sockets"};
struct debug vrrp_dbg_zebra = {0, "VRRP Zebra events"};

struct debug *vrrp_debugs[] = {
	&vrrp_dbg_arp,
	&vrrp_dbg_auto,
	&vrrp_dbg_ndisc,
	&vrrp_dbg_pkt,
	&vrrp_dbg_proto,
	&vrrp_dbg_sock,
	&vrrp_dbg_zebra
};

const char *vrrp_debugs_conflines[] = {
	"debug vrrp arp",
	"debug vrrp autoconfigure",
	"debug vrrp ndisc",
	"debug vrrp packets",
	"debug vrrp protocol",
	"debug vrrp sockets",
	"debug vrrp zebra",
};
/* clang-format on */

/*
 * Set or unset flags on all debugs for vrrpd.
 *
 * flags
 *    The flags to set
 *
 * set
 *    Whether to set or unset the specified flags
 */
static void vrrp_debug_set_all(uint32_t flags, bool set)
{
	for (unsigned int i = 0; i < array_size(vrrp_debugs); i++) {
		DEBUG_FLAGS_SET(vrrp_debugs[i], flags, set);

		/* if all modes have been turned off, don't preserve options */
		if (!DEBUG_MODE_CHECK(vrrp_debugs[i], DEBUG_MODE_ALL))
			DEBUG_CLEAR(vrrp_debugs[i]);
	}
}

static int vrrp_debug_config_write_helper(struct vty *vty, bool config)
{
	uint32_t mode = DEBUG_MODE_ALL;

	if (config)
		mode = DEBUG_MODE_CONF;

	for (unsigned int i = 0; i < array_size(vrrp_debugs); i++)
		if (DEBUG_MODE_CHECK(vrrp_debugs[i], mode))
			vty_out(vty, "%s\n", vrrp_debugs_conflines[i]);

	return 0;
}

int vrrp_config_write_debug(struct vty *vty)
{
	return vrrp_debug_config_write_helper(vty, true);
}

int vrrp_debug_status_write(struct vty *vty)
{
	return vrrp_debug_config_write_helper(vty, false);
}

void vrrp_debug_set(struct interface *ifp, uint8_t vrid, int vtynode,
		    bool onoff, bool proto, bool autoconf, bool pkt, bool sock,
		    bool ndisc, bool arp, bool zebra)
{
	uint32_t mode = DEBUG_NODE2MODE(vtynode);

	if (proto)
		DEBUG_MODE_SET(&vrrp_dbg_proto, mode, onoff);
	if (autoconf)
		DEBUG_MODE_SET(&vrrp_dbg_auto, mode, onoff);
	if (pkt)
		DEBUG_MODE_SET(&vrrp_dbg_pkt, mode, onoff);
	if (sock)
		DEBUG_MODE_SET(&vrrp_dbg_sock, mode, onoff);
	if (ndisc)
		DEBUG_MODE_SET(&vrrp_dbg_ndisc, mode, onoff);
	if (arp)
		DEBUG_MODE_SET(&vrrp_dbg_arp, mode, onoff);
	if (zebra)
		DEBUG_MODE_SET(&vrrp_dbg_zebra, mode, onoff);
}

/* ------------------------------------------------------------------------- */

struct debug_callbacks vrrp_dbg_cbs = {.debug_set_all = vrrp_debug_set_all};

void vrrp_debug_init(void)
{
	debug_init(&vrrp_dbg_cbs);
}
