/*
 * Zebra VxLAN (EVPN)
 * Copyright (C) 2016, 2017 Cumulus Networks, Inc.
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include "if.h"
#include "zebra/debug.h"
#include "zebra/zserv.h"
#include "zebra/rib.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_l2.h"
#include "zebra/zebra_vxlan.h"

void zebra_vxlan_print_macs_vni(struct vty *vty, struct zebra_vrf *zvrf,
				vni_t vni)
{
}

void zebra_vxlan_print_macs_all_vni(struct vty *vty, struct zebra_vrf *zvrf)
{
}

void zebra_vxlan_print_macs_all_vni_vtep(struct vty *vty,
					 struct zebra_vrf *zvrf,
					 struct in_addr vtep_ip)
{
}

void zebra_vxlan_print_specific_mac_vni(struct vty *vty, struct zebra_vrf *zvrf,
					vni_t vni, struct ethaddr *mac)
{
}

void zebra_vxlan_print_macs_vni_vtep(struct vty *vty, struct zebra_vrf *zvrf,
				     vni_t vni, struct in_addr vtep_ip)
{
}

void zebra_vxlan_print_neigh_vni(struct vty *vty, struct zebra_vrf *zvrf,
				 vni_t vni)
{
}

void zebra_vxlan_print_neigh_all_vni(struct vty *vty, struct zebra_vrf *zvrf)
{
}

void zebra_vxlan_print_specific_neigh_vni(struct vty *vty,
					  struct zebra_vrf *zvrf, vni_t vni,
					  struct ipaddr *ip)
{
}

void zebra_vxlan_print_neigh_vni_vtep(struct vty *vty, struct zebra_vrf *zvrf,
				      vni_t vni, struct in_addr vtep_ip)
{
}

void zebra_vxlan_print_vni(struct vty *vty, struct zebra_vrf *zvrf, vni_t vni)
{
}

void zebra_vxlan_print_vnis(struct vty *vty, struct zebra_vrf *zvrf)
{
}

void zebra_vxlan_print_evpn(struct vty *vty, uint8_t uj)
{
}

void zebra_vxlan_print_rmacs_l3vni(struct vty *, vni_t, uint8_t)
{
}

void zebra_vxlan_print_rmacs_all_l3vni(struct vty *, uint8_t)
{
}

void zebra_vxlan_print_nh_l3vni(struct vty *, vni_t, uint8_t)
{
}

void zebra_vxlan_print_nh_all_l3vni(struct vty *, uint8_t)
{
}

void zebra_vxlan_print_l3vni(struct vty *vty, vni_t vni)
{
}

int zebra_vxlan_svi_up(struct interface *ifp, struct interface *link_if)
{
	return 0;
}

int zebra_vxlan_svi_down(struct interface *ifp, struct interface *link_if)
{
	return 0;
}

int zebra_vxlan_remote_macip_add(struct zserv *client, int sock,
				 unsigned short length, struct zebra_vrf *zvrf)
{
	return 0;
}

int zebra_vxlan_remote_macip_del(struct zserv *client, int sock,
				 unsigned short length, struct zebra_vrf *zvrf)
{
	return 0;
}

int zebra_vxlan_local_mac_add_update(struct interface *ifp,
				     struct interface *br_if,
				     struct ethaddr *mac, vlanid_t vid,
				     uint8_t sticky)
{
	return 0;
}

int zebra_vxlan_local_mac_del(struct interface *ifp, struct interface *br_if,
			      struct ethaddr *mac, vlanid_t vid)
{
	return 0;
}

int zebra_vxlan_check_readd_remote_mac(struct interface *ifp,
				       struct interface *br_if,
				       struct ethaddr *mac, vlanid_t vid)
{
	return 0;
}

int zebra_vxlan_check_del_local_mac(struct interface *ifp,
				    struct interface *br_if,
				    struct ethaddr *mac, vlanid_t vid)
{
	return 0;
}

int zebra_vxlan_if_up(struct interface *ifp)
{
	return 0;
}

int zebra_vxlan_if_down(struct interface *ifp)
{
	return 0;
}

int zebra_vxlan_if_add(struct interface *ifp)
{
	return 0;
}

int zebra_vxlan_if_update(struct interface *ifp, uint16_t chgflags)
{
	return 0;
}

int zebra_vxlan_if_del(struct interface *ifp)
{
	return 0;
}

int zebra_vxlan_remote_vtep_add(struct zserv *client, int sock,
				unsigned short length, struct zebra_vrf *zvrf)
{
	return 0;
}

int zebra_vxlan_remote_vtep_del(struct zserv *client, int sock,
				unsigned short length, struct zebra_vrf *zvrf)
{
	return 0;
}

int zebra_vxlan_advertise_all_vni(struct zserv *client, int sock,
				  unsigned short length, struct zebra_vrf *zvrf)
{
	return 0;
}

void zebra_vxlan_init_tables(struct zebra_vrf *zvrf)
{
}

void zebra_vxlan_close_tables(struct zebra_vrf *zvrf)
{
}

void zebra_vxlan_cleanup_tables(struct zebra_vrf *zvrf)
{
}
