/* 
 * Copyright (C) 2006 Sun Microsystems, Inc.
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

#include "prefix.h"
#include "zebra/rtadv.h"
#include "zebra/irdp.h"
#include "zebra/interface.h"

#if defined (HAVE_RTADV)
void rtadv_config_write (struct vty *vty, struct interface *ifp) { return; }
#endif
void irdp_config_write (struct vty *vty, struct interface *ifp) { return; }
#ifdef HAVE_PROC_NET_DEV
void ifstat_update_proc (void) { return; }
#endif
#ifdef HAVE_NET_RT_IFLIST
void ifstat_update_sysctl (void) { return; }
#endif
