/* zebra NS Routines
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *                    Donald Sharp
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
#include "zebra.h"

#include "lib/vrf.h"
#include "lib/prefix.h"
#include "lib/memory.h"

#include "rtadv.h"
#include "zebra_ns.h"
#include "zebra_vrf.h"

struct zebra_ns *dzns;

struct zebra_ns *
zebra_ns_lookup (ns_id_t ns_id)
{
  return dzns;
}

int
zebra_ns_enable (ns_id_t ns_id, void **info)
{
  struct zebra_ns *zns = (struct zebra_ns *) (*info);
#ifdef HAVE_NETLINK
  char nl_name[64];
#endif

#if defined (HAVE_RTADV)
  rtadv_init (zns);
#endif

#ifdef HAVE_NETLINK
  /* Initialize netlink sockets */
  snprintf (nl_name, 64, "netlink-listen (NS %u)", ns_id);
  zns->netlink.sock = -1;
  zns->netlink.name = XSTRDUP (MTYPE_NETLINK_NAME, nl_name);

  snprintf (nl_name, 64, "netlink-cmd (NS %u)", ns_id);
  zns->netlink_cmd.sock = -1;
  zns->netlink_cmd.name = XSTRDUP (MTYPE_NETLINK_NAME, nl_name);
#endif
  zns->if_table = route_table_init ();
  kernel_init (zns);
  interface_list (zns);
  route_read (zns);

  return 0;
}

int
zebra_ns_disable (ns_id_t ns_id, void **info)
{
  struct zebra_ns *zns = (struct zebra_ns *) (*info);

#if defined (HAVE_RTADV)
  rtadv_terminate (zns);
#endif

  kernel_terminate (zns);

  return 0;
}

int
zebra_ns_init (void)
{
  dzns = XCALLOC (MTYPE_ZEBRA_NS, sizeof (struct zebra_ns));

  zebra_vrf_init ();

  zebra_ns_enable (0, (void **)&dzns);

  return 0;
}
