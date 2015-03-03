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
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>

#include "prefix.h"
#include "zebra/rtadv.h"
#include "zebra/irdp.h"
#include "zebra/interface.h"
#include "zebra/zebra_fpm.h"

void rtadv_config_write (struct vty *vty, struct interface *ifp) { return; }
void irdp_config_write (struct vty *vty, struct interface *ifp) { return; }
#ifdef HAVE_PROC_NET_DEV
void ifstat_update_proc (void) { return; }
#endif
#ifdef HAVE_NET_RT_IFLIST
void ifstat_update_sysctl (void) { return; }
#endif

void
zfpm_trigger_update (struct route_node *rn, const char *reason)
{
  return;
}
