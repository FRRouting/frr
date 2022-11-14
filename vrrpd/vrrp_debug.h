/*
 * VRRP debugging.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 * Quentin Young
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
#ifndef __VRRP_DEBUG_H__
#define __VRRP_DEBUG_H__

#include <zebra.h>

#include "lib/zlog_debug.h"

DECLARE_DEBUGFLAG(VRRP_ARP);
DECLARE_DEBUGFLAG(VRRP_AUTO);
DECLARE_DEBUGFLAG(VRRP_NDISC);
DECLARE_DEBUGFLAG(VRRP_PKT);
DECLARE_DEBUGFLAG(VRRP_PROTO);
DECLARE_DEBUGFLAG(VRRP_SOCK);
DECLARE_DEBUGFLAG(VRRP_ZEBRA);

#endif /* __VRRP_DEBUG_H__ */
