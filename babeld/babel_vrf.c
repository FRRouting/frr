/*
 * babel - vrf code
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
#include "babel_vrf.h"
#include "babel_zebra.h"


static int babel_vrf_new(struct vrf *vrf)
{
	return 0;
}

static int babel_vrf_enable(struct vrf *vrf)
{
	babel_zebra_vrf_register(vrf);
	return 0;
}

static int babel_vrf_disable(struct vrf *vrf)
{
	babel_zebra_vrf_unregister(vrf);
	return 0;
}

static int babel_vrf_delete(struct vrf *vrf)
{
	return 0;
}

void babel_vrf_init(void)
{
	vrf_init(babel_vrf_new, babel_vrf_enable, babel_vrf_disable,
		 babel_vrf_delete, NULL);
}
