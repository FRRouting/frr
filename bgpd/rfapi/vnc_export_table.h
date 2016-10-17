/* 
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#ifndef _QUAGGA_VNC_VNC_EXPORT_TABLE_H_
#define _QUAGGA_VNC_VNC_EXPORT_TABLE_H_

#include "lib/table.h"
#include "lib/thread.h"
#include "lib/vty.h"

#include "bgpd/bgpd.h"

#define VNC_EXPORT_TYPE_BGP	1
#define VNC_EXPORT_TYPE_ZEBRA	2

typedef enum vnc_export_type
{
  EXPORT_TYPE_BGP,
  EXPORT_TYPE_ZEBRA
} vnc_export_type_t;

struct vnc_export_info
{
  struct vnc_export_info	*next;
  struct route_node		*node;
  struct peer			*peer;
  u_char			type;
  u_char			subtype;
  uint32_t			lifetime;
  struct thread			*timer;
};

extern struct route_node *
vnc_etn_get (
    struct bgp		*bgp,
    vnc_export_type_t	type,
    struct prefix	*p);

extern struct route_node *
vnc_etn_lookup (
    struct bgp		*bgp,
    vnc_export_type_t	type,
    struct prefix	*p);

extern struct vnc_export_info *
vnc_eti_get (
    struct bgp		*bgp,
    vnc_export_type_t	etype,
    struct prefix	*p,
    struct peer		*peer,
    uint8_t		type,
    uint8_t		subtype);

extern void
vnc_eti_delete (struct vnc_export_info *goner);

extern struct vnc_export_info *
vnc_eti_checktimer (
    struct bgp		*bgp,
    vnc_export_type_t	etype,
    struct prefix	*p,
    struct peer		*peer,
    uint8_t		type,
    uint8_t		subtype);


#endif /* _QUAGGA_VNC_VNC_EXPORT_TABLE_H_ */
