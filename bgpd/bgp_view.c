/*
 * $Id: bgp_view.c,v 1.2 2004/08/26 11:22:19 hasso Exp $
 *
 * Multiple view function for route server.
 * Copyright (C) 1997 Kunihiro Ishiguro
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

#include "linklist.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "table.h"
#include "log.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_aspath.h"

/* Static configuration of BGP annoucement. */
struct route_table *bgp_static_ipv4;
#ifdef HAVE_IPV6
struct route_table *bgp_static_ipv6;
#endif /* HAVE_IPV6 */

/* Static annoucement peer. */
struct peer *static_peer;

/* Default value setting flag */
#define VAL_LOCAL_PREF 0x01
#define VAL_MED        0x02
#define VAL_NEXT_HOP   0x04

DEFUN (default_attr_localpref,
       default_attr_localpref_cmd,
       "default-attr local-pref NUMBER",
       "Set default local preference value\n"
       "Set default local preference value\n"
       "Value\n")
{
  struct bgp *bgp;
  long lpref;

  bgp = (struct bgp *) vty->index;

  lpref = strtol (argv[0], NULL, 10);

  bgp->def |= VAL_LOCAL_PREF;
  bgp->localpref = lpref;

  return CMD_SUCCESS;
}

DEFUN (no_default_attr_localpref,
       no_default_attr_localpref_cmd,
       "no default-attr local-pref NUMBER",
       NO_STR
       "Unset default local preference value\n"
       "Unset default local preference value\n"
       "Value\n")
{
  struct bgp *bgp;

  bgp = (struct bgp *) vty->index;

  bgp->def &= ~DEFAULT_LOCAL_PREF;
  bgp->localpref = 0;

  return CMD_SUCCESS;
}

#ifdef HAVE_IPV6
/* Network configuration for IPv6. */
int
bgp_network_config_ipv6 (struct vty *vty, char *address_str)
{
  int ret;
  struct prefix p;
  struct route_node *node;
  struct bgp_info *bgp_info;

  ret = str2prefix_ipv6 (address_str, (struct prefix_ipv6 *) &p);
  if (!ret)
    {
      vty_out (vty, "Please specify valid address\r\n");
      return CMD_WARNING;
    }

  apply_mask_ipv6 ((struct prefix_ipv6 *) &p);
  
  node = route_node_get (bgp_static_ipv6, &p);
  if (node->info)
    {
      vty_out (vty, "There is already same static announcement.\r\n");
      route_unlock_node (node);
      return CMD_WARNING;
    }

  bgp_info = bgp_info_new ();
  bgp_info->type = ZEBRA_ROUTE_STATIC;
  bgp_info->peer = static_peer;
  bgp_info->attr = bgp_attr_make_default ();
  node->info = bgp_info;

  nlri_process (&p, bgp_info);

  return CMD_SUCCESS;
}
#endif

/* Configure static BGP network. */
DEFUN (bgp_network,
       bgp_network_cmd,
       "network PREFIX",
       "Announce network setup\n"
       "Static network for bgp announcement\n")
{
  int ret;
  struct bgp *bgp;
  struct prefix p;
  struct route_node *node;
  struct bgp_info *bgp_info;

  bgp = (struct bgp *) vty->index;

  ret = str2prefix_ipv4 (argv[0], (struct prefix_ipv4 *) &p);
  if (!ret)
    {
#ifdef HAVE_IPV6
      return bgp_network_config_ipv6 (vty, argv[0]);
#endif /* HAVE_IPV6 */

      vty_out (vty, "Please specify address by a.b.c.d/mask\r\n");
      return CMD_WARNING;
    }

  /* Make sure mask is applied. */
  apply_mask ((struct prefix_ipv4 *) &p);

  node = route_node_get (bgp_static_ipv4, &p);
  if (node->info)
    {
      vty_out (vty, "There is already same static announcement.\r\n");
      route_unlock_node (node);
      return CMD_WARNING;
    }

  bgp_info = bgp_info_new ();
  bgp_info->type = ZEBRA_ROUTE_STATIC;
  bgp_info->peer = static_peer;
  bgp_info->attr = bgp_attr_make_default ();
  node->info = bgp_info;

  nlri_process (&p, bgp_info);

  return CMD_SUCCESS;
}

DEFUN (no_bgp_network,
       no_bgp_network_cmd,
       "no network PREFIX",
       NO_STR
       "Announce network setup\n"
       "Delete static network for bgp announcement\n")
{
  int ret;
  struct bgp *bgp;
  struct route_node *np;
  struct prefix_ipv4 p;

  bgp = (struct bgp *) vty->index;

  ret = str2prefix_ipv4 (argv[0], &p);
  if (!ret)
    {
      vty_out (vty, "Please specify address by a.b.c.d/mask\r\n");
      return CMD_WARNING;
    }

  apply_mask (&p);

  np = route_node_get (bgp_static_ipv4, (struct prefix *) &p);
  if (!np->info)
    {
      vty_out (vty, "Can't find specified static route configuration.\r\n");
      route_unlock_node (np);
      return CMD_WARNING;
    }
  nlri_delete (static_peer, (struct prefix *) &p);

  /* bgp_attr_free (np->info); */
  np->info = NULL;

  route_unlock_node (np);

  return CMD_SUCCESS;
}

int
config_write_network (struct vty *vty, struct bgp *bgp)
{
  struct route_node *node;
  struct bgp_route *route;
  char buf[BUFSIZ];
  
  for (node = route_top (bgp_static_ipv4); node; node = route_next (node)) 
    for (route = node->info; route; route = route->next)
      vty_out (vty, " network %s/%d%s", 
	       inet_ntoa (node->p.u.prefix4), node->p.prefixlen, VTY_NEWLINE);
#ifdef HAVE_IPV6
  for (node = route_top (bgp_static_ipv6); node; node = route_next (node)) 
    for (route = node->info; route; route = route->next)
      vty_out (vty, " network %s/%d%s", 
	       inet_ntop (AF_INET6, &node->p.u.prefix6, buf, BUFSIZ),
	       node->p.prefixlen, VTY_NEWLINE);
#endif /* HAVE_IPV6 */

  return 0;
}

void
view_init ()
{
  bgp_static_ipv4 = route_table_init ();
#ifdef HAVE_IPV6
  bgp_static_ipv6 = route_table_init ();
#endif /* HAVE_IPV6 */

  static_peer = peer_new ();
  static_peer->host = "Static annucement";

  install_element (BGP_NODE, &bgp_network_cmd);
  install_element (BGP_NODE, &no_bgp_network_cmd);
  install_element (BGP_NODE, &default_attr_localpref_cmd);
  install_element (BGP_NODE, &no_default_attr_localpref_cmd);
}
