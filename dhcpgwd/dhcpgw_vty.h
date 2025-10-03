// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DHCPGWd - vty header
 * Copyright (C) 2025 VyOS Inc.
 * Kyrylo Yatsenko
 */
#ifndef __DHCPGW_VTY_H__
#define __DHCPGW_VTY_H__

/* If changed, don't forget to update in dhcpgw_vty.c same macro */
#define DHCP_GATEWAY_CMD_STR "dhcp-gateway"

#ifdef __cplusplus
extern "C" {
#endif

void dhcpgw_vty_init(void);

#ifdef __cplusplus
}
#endif

#endif
