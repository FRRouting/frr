/*
 * Zebra VxLAN (EVPN) Data structures and definitions
 * These are public definitions referenced by other files.
 * Copyright (C) 2021 Cumulus Networks, Inc.
 * Sharath Ramamurthy
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

#ifndef _ZEBRA_VXLAN_IF_H
#define _ZEBRA_VXLAN_IF_H

#include <zebra.h>
#include <zebra/zebra_router.h>

#include "linklist.h"
#include "if.h"
#include "vlan.h"
#include "vxlan.h"

#include "lib/json.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zserv.h"
#include "zebra/zebra_dplane.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int zebra_vxlan_if_down(struct interface *ifp);
extern int zebra_vxlan_if_up(struct interface *ifp);
extern int zebra_vxlan_if_del(struct interface *ifp);
extern int zebra_vxlan_if_update(struct interface *ifp, uint16_t chgflags);
extern int zebra_vxlan_if_add(struct interface *ifp);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_VXLAN_IF_H */
