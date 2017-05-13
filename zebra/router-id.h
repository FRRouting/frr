/*
 * Router ID for zebra daemon.
 *
 * Copyright (C) 2004 James R. Leu
 *
 * This file is part of Quagga routing suite.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ROUTER_ID_H_
#define _ROUTER_ID_H_

#include <zebra.h>

#include "memory.h"
#include "prefix.h"
#include "zclient.h"
#include "if.h"

extern void router_id_add_address(struct connected *);
extern void router_id_del_address(struct connected *);
extern void router_id_init(struct zebra_vrf *);
extern void router_id_cmd_init(void);
extern void router_id_write(struct vty *);
extern void router_id_get(struct prefix *, vrf_id_t);

#endif
