// SPDX-License-Identifier: GPL-2.0-or-later
/* VPN common functions to MP-BGP
 * Copyright (C) 2017 6WIND
 */

#ifndef _FRR_BGP_VPN_H
#define _FRR_BGP_VPN_H

#include <zebra.h>

extern int show_adj_route_vpn(struct vty *vty, struct peer *peer,
			      struct prefix_rd *prd, afi_t afi, safi_t safi,
			      bool use_json);

#endif /* _QUAGGA_BGP_VPN_H */
