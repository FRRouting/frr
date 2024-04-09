// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RIP BFD integration.
 * Copyright (C) 2021-2023 Network Device Education Foundation, Inc. ("NetDEF")
 */

#ifndef _RIP_BFD_
#define _RIP_BFD_

#include "frrevent.h"

DECLARE_MTYPE(RIP_BFD_PROFILE);

struct rip;
struct rip_interface;
struct rip_peer;

void rip_bfd_session_update(struct rip_peer *rp);
void rip_bfd_interface_update(struct rip_interface *ri);
void rip_bfd_instance_update(struct rip *rip);
void rip_bfd_init(struct event_loop *tm);

#endif /* _RIP_BFD_ */
