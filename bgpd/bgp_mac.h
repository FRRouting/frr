/*
 * BGPd - Mac hash header
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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
#ifndef __BGP_MAC_H__
#define __BGP_MAC_H__

void bgp_mac_init(void);
void bgp_mac_finish(void);

/*
 * Functions to add/delete the mac entry from the appropriate
 * bgp hash's.  Additionally to do some additional processing
 * to allow the win/loss to be processed.
 */
void bgp_mac_add_mac_entry(struct interface *ifp);
void bgp_mac_del_mac_entry(struct interface *ifp);

void bgp_mac_dump_table(struct vty *vty);

/*
 * Function to lookup the prefix and see if we have a matching mac
 */
bool bgp_mac_entry_exists(const struct prefix *p);
bool bgp_mac_exist(const struct ethaddr *mac);

#endif
