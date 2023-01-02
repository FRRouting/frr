/* MPLS/BGP L3VPN MIB
 * Copyright (C) 2020 Volta Networks Inc
 *
 * This file is part of FRR.
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

void bgp_mpls_l3vpn_module_init(void);

#define MPLSL3VPNVRFRTECIDRTYPEOTHER 1
#define MPLSL3VPNVRFRTECIDRTYPEREJECT 2
#define MPLSL3VPNVRFRTECIDRTYPELOCAL 3
#define MPLSL3VPNVRFRTECIDRTYPEREMOTE 4
#define MPLSL3VPNVRFRTECIDRTYPEBLACKHOLE 5

#define MPLSVPNVRFRTTYPEIMPORT 1
#define MPLSVPNVRFRTTYPEEXPORT 2
#define MPLSVPNVRFRTTYPEBOTH 3
