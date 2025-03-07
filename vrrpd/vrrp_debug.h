// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * VRRP debugging.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 * Quentin Young
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
