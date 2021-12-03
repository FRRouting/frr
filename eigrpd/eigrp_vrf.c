/*
 * eigrp - vrf code
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *               Donald Sharp
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

#include "eigrpd/eigrp_vrf.h"

static int eigrp_vrf_new(struct vrf *vrf)
{
	return 0;
}

static int eigrp_vrf_enable(struct vrf *vrf)
{
	return 0;
}

static int eigrp_vrf_disable(struct vrf *vrf)
{
	return 0;
}

static int eigrp_vrf_delete(struct vrf *vrf)
{
	return 0;
}

void eigrp_vrf_init(void)
{
	vrf_init(eigrp_vrf_new, eigrp_vrf_enable, eigrp_vrf_disable,
		 eigrp_vrf_delete);
}
