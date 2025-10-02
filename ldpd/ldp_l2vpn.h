// SPDX-License-Identifier: GPL-2.0-or-later
/* Route map function.
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#ifndef _LDP_L2VPN_H
#define _LDP_L2VPN_H

#ifdef __cplusplus
extern "C" {
#endif

extern const struct frr_yang_module_info frr_ldp_l2vpn;
extern const struct frr_yang_module_info frr_ldp_l2vpn_cli_info;

extern void ldp_l2vpn_cli_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _LDP_L2VPN_H */
