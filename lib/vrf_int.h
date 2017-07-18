/*
 * VRF Internal Header
 * Copyright (C) 2017 Cumulus Networks, Inc.
 *                    Donald Sharp
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
#ifndef __LIB_VRF_PRIVATE_H__
#define __LIB_VRF_PRIVATE_H__

#include "vrf.h"

/*
 * These functions should only be called by:
 * zebra/if_netlink.c -> The interface from OS into Zebra
 * lib/zclient.c -> The interface from Zebra to each daemon
 *
 * Why you ask?  Well because these are the turn on/off
 * functions and the only place we can really turn a
 * vrf on properly is in the call up from the os -> zebra
 * and the pass through of this informatoin from zebra -> protocols
 */

/*
 * vrf_enable
 *
 * Given a newly running vrf enable it to be used
 * by interested routing protocols
 */
extern int vrf_enable(struct vrf *);

/*
 * vrf_delete
 *
 * Given a vrf that is being deleted, delete it
 * from interested parties
 */
extern void vrf_delete(struct vrf *);

#endif
