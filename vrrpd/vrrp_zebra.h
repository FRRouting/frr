// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * VRRP Zebra interfacing.
 * Copyright (C) 2018-2019 Cumulus Networks, Inc.
 * Quentin Young
 */
#ifndef __VRRP_ZEBRA_H__
#define __VRRP_ZEBRA_H__

#include <zebra.h>

#include "lib/if.h"

extern void vrrp_zebra_init(void);
extern void vrrp_zebra_radv_set(struct vrrp_router *r, bool enable);
extern void vrrp_zclient_send_interface_protodown(struct interface *ifp,
						  bool down);

extern int vrrp_ifp_create(struct interface *ifp);
extern int vrrp_ifp_up(struct interface *ifp);
extern int vrrp_ifp_down(struct interface *ifp);
extern int vrrp_ifp_destroy(struct interface *ifp);

#endif /* __VRRP_ZEBRA_H__ */
