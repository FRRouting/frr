/*
 * Copyright (C) 2015 Cumulus Networks, Inc.
 *
 * This file is part of Quagga.
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

#include <zebra.h>
#include <lib/prefix.h>
#include <rtadv.h>
#include <zebra_ns.h>

void zebra_interface_radv_set (struct zserv *client, int sock, u_short length,
                          struct zebra_vrf *zvrf, int enable)
{ return; }

void rtadv_init (struct zebra_ns *zns)
{ return; }

void rtadv_terminate (struct zebra_ns *zns)
{ return; }
