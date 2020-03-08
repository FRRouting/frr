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
#ifndef __VRRP_DEBUG_H__
#define __VRRP_DEBUG_H__

#include <zebra.h>

#include "lib/debug.h"

/* VRRP debugging records */
extern struct debug vrrp_dbg_arp;
extern struct debug vrrp_dbg_auto;
extern struct debug vrrp_dbg_ndisc;
extern struct debug vrrp_dbg_pkt;
extern struct debug vrrp_dbg_proto;
extern struct debug vrrp_dbg_sock;
extern struct debug vrrp_dbg_zebra;

/*
 * Initialize VRRP debugging.
 *
 * Installs VTY commands and registers callbacks.
 */
void vrrp_debug_init(void);

/*
 * Print VRRP debugging configuration.
 *
 * vty
 *    VTY to print debugging configuration to.
 */
int vrrp_config_write_debug(struct vty *vty);

/*
 * Print VRRP debugging configuration, human readable form.
 *
 * vty
 *    VTY to print debugging configuration to.
 */
int vrrp_debug_status_write(struct vty *vty);

/*
 * Set debugging status.
 *
 * ifp
 *    Interface to set status on
 *
 * vrid
 *    VRID of instance to set status on
 *
 * vtynode
 *    vty->node
 *
 * onoff
 *    Whether to turn the specified debugs on or off
 *
 * proto
 *    Turn protocol debugging on or off
 *
 * autoconf
 *    Turn autoconfiguration debugging on or off
 *
 * pkt
 *    Turn packet debugging on or off
 */
void vrrp_debug_set(struct interface *ifp, uint8_t vrid, int vtynode,
		    bool onoff, bool proto, bool autoconf, bool pkt, bool sock,
		    bool ndisc, bool arp, bool zebra);

#endif /* __VRRP_DEBUG_H__ */
