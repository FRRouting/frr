/* VPN common functions to MP-BGP
 * Copyright (C) 2017 6WIND
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_BGP_VPN_H
#define _FRR_BGP_VPN_H

#include <zebra.h>

extern int show_adj_route_vpn(struct vty *vty, struct peer *peer,
			      struct prefix_rd *prd, afi_t afi, safi_t safi,
			      uint8_t use_json);

#endif /* _QUAGGA_BGP_VPN_H */
