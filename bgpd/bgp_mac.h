// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGPd - Mac hash header
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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
