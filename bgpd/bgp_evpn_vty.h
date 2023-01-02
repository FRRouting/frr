/* EVPN VTY functions to EVPN
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

#ifndef _FRR_BGP_EVPN_VTY_H
#define _FRR_BGP_EVPN_VTY_H

extern void bgp_config_write_evpn_info(struct vty *vty, struct bgp *bgp,
				       afi_t afi, safi_t safi);
extern void bgp_ethernetvpn_init(void);

#define L2VPN_HELP_STR        "Layer 2 Virtual Private Network\n"
#define EVPN_HELP_STR        "Ethernet Virtual Private Network\n"

extern int argv_find_and_parse_oly_idx(struct cmd_token **argv, int argc,
				       int *oly_idx,
				       enum overlay_index_type *oly);

/* Parse type from "type <ead|1|...>", return -1 on failure */
extern int bgp_evpn_cli_parse_type(int *type, struct cmd_token **argv,
				   int argc);

#endif /* _QUAGGA_BGP_EVPN_VTY_H */
