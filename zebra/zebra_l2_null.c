/*
 * Zebra Layer-2 interface Data structures and definitions
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

void zebra_l2_map_slave_to_bridge(struct zebra_l2info_brslave *br_slave)
{
}

void zebra_l2_unmap_slave_from_bridge(struct zebra_l2info_brslave *br_slave)
{
}

void zebra_l2_bridge_add_update(struct interface *ifp,
				struct zebra_l2info_bridge *bridge_info,
				int add)
{
}

void zebra_l2_bridge_del(struct interface *ifp)
{
}

void zebra_l2_vlanif_update(struct interface *ifp,
			    struct zebra_l2info_vlan *vlan_info)
{
}

void zebra_l2_vxlanif_add_update(struct interface *ifp,
				 struct zebra_l2info_vxlan *vxlan_info, int add)
{
}

void zebra_l2_vxlanif_update_access_vlan(struct interface *ifp,
					 vlanid_t access_vlan)
{
}

void zebra_l2_vxlanif_del(struct interface *ifp)
{
}

void zebra_l2if_update_bridge_slave(struct interface *ifp,
				    ifindex_t bridge_ifindex)
{
}
