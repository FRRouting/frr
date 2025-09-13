// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DHCP gateway routes processing
 * Copyright (C) 2025 VyOS Inc.
 * Kyrylo Yatsenko
 */

#ifndef _DHCPGW_ROUTES_H
#define _DHCPGW_ROUTES_H

#include <zebra.h>

#include "lib/frrevent.h"
#include "vty.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize dhcpgw_routes
 */
void dhcpgw_routes_init(struct event_loop *m);

/*
 * Free all resources
 */
void dhcpgw_routes_close(void);

/*
 * Process new route
 *
 * no
 *      True if route should be deleted
 *
 * ifname
 *      Interface name
 *
 * af
 *      Address family: AF_INET or AF_INET6
 *
 * command_prefix
 *      Whole command string before 'dhcp-gateway'
 *
 * command_suffix
 *      Whole command string after 'dhcp-gateway'
 */
void dhcpgw_routes_process(bool no, const char *ifname, int af, const char *command_prefix,
			   const char *command_suffix);

/*
 * Process one interface update
 *
 * If IP of DHCP gateway of the interface changed
 * and there are dhcpgw routes on this interface,
 * delete/add these routes using staticd
 *
 * ifname
 *      Interface name
 */
void dhcpgw_routes_update_interface(const char *ifname);

/*
 * Show dhcpgw routes
 *
 * vty
 *      output goes to this vty
 */
void do_show_dhcpgw_routes(struct vty *vty);

#ifdef __cplusplus
}
#endif

#endif /* _DHCPGW_ROUTES_H */
