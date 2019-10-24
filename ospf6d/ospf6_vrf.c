/*
 * ospf6 - vrf code
 * Copyright (C) 2019 VMware Inc.
 *               Kishore Aramalla
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "vrf.h"

#include "ospf6_route.h"
#include "ospf6_vrf.h"
#include "ospf6_zebra.h"


static int ospf6_vrf_new(struct vrf *vrf)
{
	return 0;
}

static int ospf6_vrf_enable(struct vrf *vrf)
{
	ospf6_zebra_vrf_register(vrf);
	return 0;
}

static int ospf6_vrf_disable(struct vrf *vrf)
{
	ospf6_zebra_vrf_unregister(vrf);
	return 0;
}

static int ospf6_vrf_delete(struct vrf *vrf)
{
	return 0;
}

void ospf6_vrf_init(void)
{
	vrf_init(ospf6_vrf_new, ospf6_vrf_enable, ospf6_vrf_disable,
		 ospf6_vrf_delete, NULL);
}
