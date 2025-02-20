// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Router ID for zebra daemon.
 *
 * Copyright (C) 2004 James R. Leu
 *
 * This file is part of Quagga routing suite.
 */

#ifndef _ROUTER_ID_H_
#define _ROUTER_ID_H_

#include <zebra.h>

#include "memory.h"
#include "prefix.h"
#include "zclient.h"
#include "if.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void router_id_add_address(struct connected *c);
extern void router_id_del_address(struct connected *c);
extern void router_id_init(struct zebra_vrf *zvrf);
extern void router_id_cmd_init(void);
extern int router_id_get(afi_t afi, struct prefix *p, struct zebra_vrf *zvrf);
extern int router_id_set(afi_t afi, struct prefix *p, struct zebra_vrf *zvrf);

#ifdef __cplusplus
}
#endif

#endif
