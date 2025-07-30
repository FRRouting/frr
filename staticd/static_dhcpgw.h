// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DHCP gateway related functions
 * Copyright (C) 2025 VyOS Inc.
 * Kyrylo Yatsenko
 */
/*
 * static_dhcpgw.h provides functionality of static routes with
 * dhcp-gateway as gateway e.g.
 * ip route 10.1.2.7 dhcp-gateway eth0
 * This command adds route to 10.1.2.7 via whatever gateway on interface eth0
 * was received by DHCP.
 *
 * Currently only dhclient is supported.
 *
 * For this to work first static_dhcpgw_init must be called
 * and for each nexthop of type
 *		STATIC_IPV4_IFNAME_DHCP_GATEWAY
 * static_dhcpgw_add_nexthop_watch must be called on creation
 * and static_dhcpgw_del_nexthop_watch on deletion
 *
 * There are two options of updates of DHCP leases: polling and by external command.
 *
 * Command
 * `static-route-dhcp-gateway update`
 * Rereads leases, it can be used in external scripts e.g. dhclient hook.
 * See staticd/sample-dhclient-hook
 *
 * If polling is desired, set polling period via
 * `static-route-dhcp-gateway poll-period PERIOD-SECONDS`
 * Setting PERIOD-SECONDS to 0 disables polling, this is default.
 *
 * You can setup lease path by options:
 * `static-route-dhcp-gateway dhclient-lease-path-prefix LEASEPREFIX`
 * `static-route-dhcp-gateway dhclient-lease-path-suffix LEASESUFFIX`
 *
 * Lease path will be LEASEPREFIX{interface}LEASESUFFIX.
 * Default prefix is "/var/run/dhclient/dhclient_", default suffix ".lease"
 */

#ifndef _STATIC_DHCP_GATEWAY_H
#define _STATIC_DHCP_GATEWAY_H

#include <zebra.h>

#include "staticd/static_routes.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Initialize static_dhcpgw
 *
 * master
 *    Needs event_loop to add reaction to events (timer)
 */
void static_dhcpgw_init(struct event_loop *master);

/*
 * Free all resources
 */
void static_dhcpgw_close(void);

/*
 * Start watching nexthop
 *
 * nh
 *      DHCP Gateway nexthop
 */
void static_dhcpgw_add_nexthop_watch(struct static_nexthop *nh);

/*
 * Stop watching nexthop
 *
 * nh
 *      DHCP Gateway nexthop
 */
void static_dhcpgw_del_nexthop_watch(struct static_nexthop *nh);

/*
 * Set poll period or disable polling
 *
 * seconds
 *      Poll period in seconds, 0 - disabled
 */
void static_dhcpgw_set_poll_period_seconds(unsigned long seconds);

/*
 * Set prefix of path to dhclient lease file
 *
 * prefix
 *      prefix
 */
void static_dhcpgw_set_lease_path_prefix(const char *prefix);

/*
 * Set suffix of path to dhclient lease file
 *
 * suffix
 *      suffix
 */
void static_dhcpgw_set_lease_path_suffix(const char *suffix);

/*
 * Check current addresses of DHCP gateways,
 * update routes accordingly
 */
void static_dhcpgw_update(void);

#ifdef __cplusplus
}
#endif

#endif /* _STATIC_DHCP_GATEWAY_H */
