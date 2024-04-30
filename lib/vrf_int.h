// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * VRF Internal Header
 * Copyright (C) 2017 Cumulus Networks, Inc.
 *                    Donald Sharp
 */
#ifndef __LIB_VRF_PRIVATE_H__
#define __LIB_VRF_PRIVATE_H__

#include "vrf.h"

#ifdef __cplusplus
extern "C" {
#endif

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

#ifdef __cplusplus
}
#endif

#endif
