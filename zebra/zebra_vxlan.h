/*
 * Zebra VxLAN (EVPN) Data structures and definitions
 * These are public definitions referenced by other files.
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

#ifndef _ZEBRA_VXLAN_H
#define _ZEBRA_VXLAN_H

#include <zebra.h>

#include "linklist.h"
#include "if.h"
#include "vlan.h"
#include "vxlan.h"

#include "zebra/interface.h"
#include "zebra/zebra_vrf.h"

/* Is EVPN enabled? */
#define EVPN_ENABLED(zvrf)  (zvrf)->advertise_all_vni

/* VxLAN interface change flags of interest. */
#define ZEBRA_VXLIF_LOCAL_IP_CHANGE     0x1
#define ZEBRA_VXLIF_MASTER_CHANGE       0x2
#define ZEBRA_VXLIF_VLAN_CHANGE         0x4

extern int zebra_vxlan_if_up (struct interface *ifp);
extern int zebra_vxlan_if_down (struct interface *ifp);
extern int zebra_vxlan_if_add (struct interface *ifp);
extern int zebra_vxlan_if_update (struct interface *ifp, u_int16_t chgflags);
extern int zebra_vxlan_if_del (struct interface *ifp);
extern int zebra_vxlan_remote_vtep_add (struct zserv *client, int sock,
                                        u_short length, struct zebra_vrf *zvrf);
extern int zebra_vxlan_remote_vtep_del (struct zserv *client, int sock,
                                        u_short length, struct zebra_vrf *zvrf);
extern int zebra_vxlan_advertise_all_vni (struct zserv *client, int sock,
                                          u_short length, struct zebra_vrf *zvrf);
extern void zebra_vxlan_init_tables (struct zebra_vrf *zvrf);
extern void zebra_vxlan_close_tables (struct zebra_vrf *);

#endif /* _ZEBRA_VXLAN_H */
