/*
 * PIM for Quagga
 * Copyright (C) 2015 Cumulus Networks, Inc.
 * Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */
#ifndef PIM_RP_H
#define PIM_RP_H

void pim_rp_check_rp (struct in_addr old, struct in_addr new);
int pim_rp_i_am_rp (struct in_addr group);
int pim_rp_set_upstream_addr (struct in_addr *up, struct in_addr source);
struct pim_rpf *pim_rp_g (struct in_addr group);

#define I_am_RP(G)  pim_rp_i_am_rp ((G))
#define RP(G)       pim_rp_g ((G))
#endif
