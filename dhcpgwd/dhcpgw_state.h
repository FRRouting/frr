// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DHCP gateway related functions
 * Copyright (C) 2025 VyOS Inc.
 * Kyrylo Yatsenko
 */
/*
 * dhcpgw_state.h provides functions to write/read state of
 * interfaces controlled by DHCP.
 *
 * Store format: for each interface with DHCP file DHCPGW_STATE_PATH/ifname
 * with IP address is stored. For interfaces without gateway file is removed
 *
 * Used by update-dhcp-gw called from DHCP client hooks to store updates,
 * and by dhcpgwd to read updates.
 */

#ifndef _DHCPGW_STATE_H
#define _DHCPGW_STATE_H

#include <zebra.h>

#include "lib/nexthop.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Save interface state
 *
 * Outputs errors to stderr, as it is used from update-dhcp-gw
 *
 * ifname
 *    Interface name
 *
 * up
 *    True if interface is up and has IP-address
 *
 * af
 *    address family: AF_INET or AF_INET6
 *
 * ip
 *    If up == true, must contain negotiated IP-address
 *    If up == false, ignored, can be NULL
 *
 * Returns 0 on success, negative errno on failure
 */
int dhcpgw_state_save(const char *ifname, bool up, int af, const union g_addr *ip_addr);

/*
 * Read state of interface
 *
 * ifname
 *    Interface name
 *
 * up
 *    Will be written true, if interface has IP-address.
 *    Will be written false otherwise.
 *
 * ip
 *    If up == true, IP-address will be written here.
 *
 * Returns 0 on success, negative errno on failure
 */
int dhcpgw_state_read(const char *ifname, bool *up, int *af, union g_addr *ip_addr);

#ifdef __cplusplus
}
#endif

#endif /* _DHCPGW_STATE_H */
