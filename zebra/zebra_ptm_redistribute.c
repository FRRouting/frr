/**
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>
#include "prefix.h"
#include "vty.h"
#include "stream.h"
#include "zebra/zserv.h"

/* master zebra server structure */
extern struct zebra_t zebrad;

int
zsend_interface_bfd_update (int cmd, struct zserv *client,
                            struct interface *ifp, struct prefix *dp,
                            struct prefix *sp)
{
  int blen;
  struct stream *s;

  /* Check this client need interface information. */
  if (! client->ifinfo)
    return 0;

  s = client->obuf;
  stream_reset (s);

  zserv_create_header (s, cmd);
  if (ifp)
    stream_putl (s, ifp->ifindex);
  else
    stream_putl (s, 0);

  /* BFD destination prefix information. */
  stream_putc (s, dp->family);
  blen = prefix_blen (dp);
  stream_put (s, &dp->u.prefix, blen);
  stream_putc (s, dp->prefixlen);

  /* BFD source prefix information. */
  stream_putc (s, sp->family);
  blen = prefix_blen (sp);
  stream_put (s, &sp->u.prefix, blen);
  stream_putc (s, sp->prefixlen);

  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));

  client->if_bfd_cnt++;
  return zebra_server_send_message(client);
}

void
zebra_interface_bfd_update (struct interface *ifp, struct prefix *dp,
                            struct prefix *sp)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    {
      /* Supporting for OSPF and BGP */
      if (client->proto != ZEBRA_ROUTE_OSPF && client->proto != ZEBRA_ROUTE_BGP
          && client->proto != ZEBRA_ROUTE_OSPF6)
        continue;

      /* Notify to the protocol daemons. */
      zsend_interface_bfd_update (ZEBRA_INTERFACE_BFD_DEST_DOWN, client, ifp,
                                    dp, sp);
    }
}

int
zsend_bfd_peer_replay (int cmd, struct zserv *client)
{
  struct stream *s;

  s = client->obuf;
  stream_reset (s);

  zserv_create_header (s, cmd);

  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));

  client->bfd_peer_replay_cnt++;
  return zebra_server_send_message(client);
}

void
zebra_bfd_peer_replay_req (void)
{
  struct listnode *node, *nnode;
  struct zserv *client;

  for (ALL_LIST_ELEMENTS (zebrad.client_list, node, nnode, client))
    {
      /* Supporting for BGP */
      if ((client->proto != ZEBRA_ROUTE_BGP) &&
          (client->proto != ZEBRA_ROUTE_OSPF) &&
          (client->proto != ZEBRA_ROUTE_OSPF6))
        continue;

      /* Notify to the protocol daemons. */
      zsend_bfd_peer_replay (ZEBRA_BFD_DEST_REPLAY, client);
    }
}
