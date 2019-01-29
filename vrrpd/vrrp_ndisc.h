/*
 * VRRP Neighbor Discovery.
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
 * You should have received a copy of the GNU General Public License along with
 * this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __VRRP_NDISC_H__
#define __VRRP_NDISC_H__

#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include "vrrp.h"

/*
 * Initialize VRRP neighbor discovery.
 */
extern void vrrp_ndisc_init(void);

/*
 * Check whether VRRP Neighbor Discovery is initialized.
 *
 * Returns:
 *    True if initialized, false otherwise
 */
extern bool vrrp_ndisc_is_init(void);

/*
 * Finish VRRP Neighbor Discovery.
 */
extern void vrrp_ndisc_fini(void);

/*
 * Send VRRP Neighbor Advertisement.
 *
 * ifp
 *    Interface to transmit on
 *
 * ip
 *    IPv6 address to send Neighbor Advertisement for
 *
 * Returns:
 *    -1 on failure
 *     0 otherwise
 */
extern int vrrp_ndisc_una_send(struct vrrp_router *r, struct ipaddr *ip);

/*
 * Send VRRP Neighbor Advertisements for all virtual IPs.
 *
 * r
 *    Virtual Router to send NA's for
 *
 * Returns:
 *    -1 on failure
 *     0 otherwise
 */
extern int vrrp_ndisc_una_send_all(struct vrrp_router *r);

#endif /* __VRRP_NDISC_H__ */
