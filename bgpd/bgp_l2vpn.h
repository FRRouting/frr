/* SPDX-License-Identifier: GPL-2.0-or-later
 * L2VPN VPLS/VPWS header
 * Copyright 2026 6WIND S.A.
 */
#ifndef _FRR_BGP_L2VPN_H
#define _FRR_BGP_L2VPN_H

extern void bgp_l2vpn_init(void);
extern struct l2vpn_svc *bgp_l2vpn_vpws_evi_match(uint32_t ethtag);
extern void bgp_l2vpn_vpws_zebra_set(struct bgp *bgp, struct l2vpn_svc *l2vpn_svc, bool on);
extern void bgp_l2vpn_ifp_up(struct interface *ifp, bool up);

#endif /* _FRR_BGP_L2VPN_H */
