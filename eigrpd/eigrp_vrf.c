// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * eigrp - vrf code
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *               Donald Sharp
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
