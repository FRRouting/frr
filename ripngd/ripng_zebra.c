/*
 * RIPngd and zebra interface.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
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

#include "command.h"
#include "prefix.h"
#include "table.h"
#include "stream.h"
#include "memory.h"
#include "routemap.h"
#include "zclient.h"
#include "log.h"

#include "ripngd/ripngd.h"
#include "ripngd/ripng_debug.h"

/* All information about zebra. */
struct zclient *zclient = NULL;

/* Send ECMP routes to zebra. */
static void
ripng_zebra_ipv6_send (struct route_node *rp, u_char cmd)
{
  static struct in6_addr **nexthops = NULL;
  static ifindex_t *ifindexes = NULL;
  static unsigned int nexthops_len = 0;

  struct list *list = (struct list *)rp->info;
  struct zapi_ipv6 api;
  struct listnode *listnode = NULL;
  struct ripng_info *rinfo = NULL;
  int count = 0;

  if (vrf_bitmap_check (zclient->redist[AFI_IP6][ZEBRA_ROUTE_RIPNG], VRF_DEFAULT))
    {
      api.vrf_id = VRF_DEFAULT;
      api.type = ZEBRA_ROUTE_RIPNG;
      api.instance = 0;
      api.flags = 0;
      api.message = 0;
      api.safi = SAFI_UNICAST;

      if (nexthops_len < listcount (list))
        {
          nexthops_len = listcount (list);
          nexthops = XREALLOC (MTYPE_TMP, nexthops,
                               nexthops_len * sizeof (struct in6_addr *));
          ifindexes = XREALLOC (MTYPE_TMP, ifindexes,
                                nexthops_len * sizeof (unsigned int));
        }

      SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);
      SET_FLAG (api.message, ZAPI_MESSAGE_IFINDEX);
      for (ALL_LIST_ELEMENTS_RO (list, listnode, rinfo))
        {
          nexthops[count] = &rinfo->nexthop;
          ifindexes[count] = rinfo->ifindex;
          count++;
          if (cmd == ZEBRA_IPV6_ROUTE_ADD)
            SET_FLAG (rinfo->flags, RIPNG_RTF_FIB);
          else
            UNSET_FLAG (rinfo->flags, RIPNG_RTF_FIB);
        }

      api.nexthop = nexthops;
      api.nexthop_num = count;
      api.ifindex = ifindexes;
      api.ifindex_num = count;

      rinfo = listgetdata (listhead (list));

      SET_FLAG (api.message, ZAPI_MESSAGE_METRIC);
      api.metric = rinfo->metric;

      zapi_ipv6_route (cmd, zclient,
                       (struct prefix_ipv6 *)&rp->p, &api);

      if (IS_RIPNG_DEBUG_ZEBRA)
        {
          if (ripng->ecmp)
            zlog_debug ("%s: %s/%d nexthops %d",
                        (cmd == ZEBRA_IPV6_ROUTE_ADD) ? \
                            "Install into zebra" : "Delete from zebra",
                        inet6_ntoa (rp->p.u.prefix6), rp->p.prefixlen, count);
          else
            zlog_debug ("%s: %s/%d",
                        (cmd == ZEBRA_IPV6_ROUTE_ADD) ? \
                            "Install into zebra" : "Delete from zebra",
                        inet6_ntoa (rp->p.u.prefix6), rp->p.prefixlen);
        }
    }
}

/* Add/update ECMP routes to zebra. */
void
ripng_zebra_ipv6_add (struct route_node *rp)
{
  ripng_zebra_ipv6_send (rp, ZEBRA_IPV6_ROUTE_ADD);
}

/* Delete ECMP routes from zebra. */
void
ripng_zebra_ipv6_delete (struct route_node *rp)
{
  ripng_zebra_ipv6_send (rp, ZEBRA_IPV6_ROUTE_DELETE);
}

/* Zebra route add and delete treatment. */
static int
ripng_zebra_read_ipv6 (int command, struct zclient *zclient,
		       zebra_size_t length, vrf_id_t vrf_id)
{
  struct stream *s;
  struct zapi_ipv6 api;
  unsigned long ifindex;
  struct in6_addr nexthop;
  struct prefix_ipv6 p;

  s = zclient->ibuf;
  ifindex = 0;
  memset (&nexthop, 0, sizeof (struct in6_addr));

  /* Type, flags, message. */
  api.type = stream_getc (s);
  api.instance = stream_getw (s);
  api.flags = stream_getc (s);
  api.message = stream_getc (s);

  /* IPv6 prefix. */
  memset (&p, 0, sizeof (struct prefix_ipv6));
  p.family = AF_INET6;
  p.prefixlen = stream_getc (s);
  stream_get (&p.prefix, s, PSIZE (p.prefixlen));

  /* Nexthop, ifindex, distance, metric. */
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    {
      api.nexthop_num = stream_getc (s);
      stream_get (&nexthop, s, 16);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_IFINDEX))
    {
      api.ifindex_num = stream_getc (s);
      ifindex = stream_getl (s);
    }
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_DISTANCE))
    api.distance = stream_getc (s);
  else
    api.distance = 0;
  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_METRIC))
    api.metric = stream_getl (s);
  else
    api.metric = 0;

  if (command == ZEBRA_REDISTRIBUTE_IPV6_ADD)
    ripng_redistribute_add (api.type, RIPNG_ROUTE_REDISTRIBUTE, &p, ifindex, &nexthop);
  else
    ripng_redistribute_delete (api.type, RIPNG_ROUTE_REDISTRIBUTE, &p, ifindex);

  return 0;
}

void
ripng_zclient_reset (void)
{
  zclient_reset (zclient);
}

static int
ripng_redistribute_unset (int type)
{

  if (! vrf_bitmap_check (zclient->redist[AFI_IP6][type], VRF_DEFAULT))
    return CMD_SUCCESS;

  vrf_bitmap_set (zclient->redist[AFI_IP6][type], VRF_DEFAULT);

  if (zclient->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE, zclient, AFI_IP6, type, 0, VRF_DEFAULT);

  ripng_redistribute_withdraw (type);
  
  return CMD_SUCCESS;
}

int
ripng_redistribute_check (int type)
{
  return vrf_bitmap_check (zclient->redist[AFI_IP6][type], VRF_DEFAULT);
}

static void
ripng_redistribute_metric_set (int type, int metric)
{
  ripng->route_map[type].metric_config = 1;
  ripng->route_map[type].metric = metric;
}

static int
ripng_redistribute_metric_unset (int type)
{
  ripng->route_map[type].metric_config = 0;
  ripng->route_map[type].metric = 0;
  return 0;
}

static void
ripng_redistribute_routemap_set (int type, const char *name)
{
  if (ripng->route_map[type].name)
    free (ripng->route_map[type].name);

  ripng->route_map[type].name = strdup (name);
  ripng->route_map[type].map = route_map_lookup_by_name (name);
}

static void
ripng_redistribute_routemap_unset (int type)
{
  if (ripng->route_map[type].name)
    free (ripng->route_map[type].name);

  ripng->route_map[type].name = NULL;
  ripng->route_map[type].map = NULL;
}

/* Redistribution types */
static struct {
  int type;
  int str_min_len;
  const char *str;
} redist_type[] = {
  {ZEBRA_ROUTE_KERNEL,  1, "kernel"},
  {ZEBRA_ROUTE_CONNECT, 1, "connected"},
  {ZEBRA_ROUTE_STATIC,  1, "static"},
  {ZEBRA_ROUTE_OSPF6,   1, "ospf6"},
  {ZEBRA_ROUTE_BGP,     2, "bgp"},
  {0, 0, NULL}
};

void
ripng_redistribute_clean ()
{
  int i;

  for (i = 0; redist_type[i].str; i++)
    {
      if (vrf_bitmap_check (zclient->redist[AFI_IP6][redist_type[i].type], VRF_DEFAULT))
        {
          if (zclient->sock > 0)
            zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE,
                                     zclient, AFI_IP6, redist_type[i].type, 0,
                                     VRF_DEFAULT);

          vrf_bitmap_unset (zclient->redist[AFI_IP6][redist_type[i].type], VRF_DEFAULT);

          /* Remove the routes from RIPng table. */
          ripng_redistribute_withdraw (redist_type[i].type);
        }
    }
}

DEFUN (router_zebra,
       router_zebra_cmd,
       "router zebra",
       "Enable a routing process\n"
       "Make connection to zebra daemon\n")
{
  vty->node = ZEBRA_NODE;
  zclient->enable = 1;
  zclient_start (zclient);
  return CMD_SUCCESS;
}

DEFUN (no_router_zebra,
       no_router_zebra_cmd,
       "no router zebra",
       NO_STR
       "Disable a routing process\n"
       "Stop connection to zebra daemon\n")
{
  zclient->enable = 0;
  zclient_stop (zclient);
  return CMD_SUCCESS;
}

DEFUN (ripng_redistribute_ripng,
       ripng_redistribute_ripng_cmd,
       "redistribute ripng",
       "Redistribute information from another routing protocol\n"
       "RIPng route\n")
{
  vrf_bitmap_set (zclient->redist[AFI_IP6][ZEBRA_ROUTE_RIPNG], VRF_DEFAULT);
  return CMD_SUCCESS;
}

DEFUN (no_ripng_redistribute_ripng,
       no_ripng_redistribute_ripng_cmd,
       "no redistribute ripng",
       NO_STR
       "Redistribute information from another routing protocol\n"
       "RIPng route\n")
{
  vrf_bitmap_unset (zclient->redist[AFI_IP6][ZEBRA_ROUTE_RIPNG], VRF_DEFAULT);
  return CMD_SUCCESS;
}

DEFUN (ripng_redistribute_type,
       ripng_redistribute_type_cmd,
       "redistribute " QUAGGA_REDIST_STR_RIPNGD,
       "Redistribute\n"
       QUAGGA_REDIST_HELP_STR_RIPNGD)
{
  int type;

  type = proto_redistnum(AFI_IP6, argv[0]);

  if (type < 0)
    {
      vty_out(vty, "Invalid type %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  zclient_redistribute (ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP6, type, 0, VRF_DEFAULT);
  return CMD_SUCCESS;
}

DEFUN (no_ripng_redistribute_type,
       no_ripng_redistribute_type_cmd,
       "no redistribute " QUAGGA_REDIST_STR_RIPNGD,
       NO_STR
       "Redistribute\n"
       QUAGGA_REDIST_HELP_STR_RIPNGD)
{
  int type;

  type = proto_redistnum(AFI_IP6, argv[0]);

  if (type < 0)
    {
      vty_out(vty, "Invalid type %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  ripng_redistribute_metric_unset (type);
  ripng_redistribute_routemap_unset (type);
  return ripng_redistribute_unset (type);
}


DEFUN (ripng_redistribute_type_metric,
       ripng_redistribute_type_metric_cmd,
       "redistribute " QUAGGA_REDIST_STR_RIPNGD " metric <0-16>",
       "Redistribute\n"
       QUAGGA_REDIST_HELP_STR_RIPNGD
       "Metric\n"
       "Metric value\n")
{
  int type;
  int metric;

  metric = atoi (argv[1]);
  type = proto_redistnum(AFI_IP6, argv[0]);

  if (type < 0)
    {
      vty_out(vty, "Invalid type %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  ripng_redistribute_metric_set (type, metric);
  zclient_redistribute (ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP6, type, 0,
                        VRF_DEFAULT);
  return CMD_SUCCESS;
}

ALIAS (no_ripng_redistribute_type,
       no_ripng_redistribute_type_metric_cmd,
       "no redistribute " QUAGGA_REDIST_STR_RIPNGD " metric <0-16>",
       NO_STR
       "Redistribute\n"
       QUAGGA_REDIST_HELP_STR_RIPNGD
       "Metric\n"
       "Metric value\n")

DEFUN (ripng_redistribute_type_routemap,
       ripng_redistribute_type_routemap_cmd,
       "redistribute " QUAGGA_REDIST_STR_RIPNGD " route-map WORD",
       "Redistribute\n"
       QUAGGA_REDIST_HELP_STR_RIPNGD
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  int type;

  type = proto_redistnum(AFI_IP6, argv[0]);

  if (type < 0)
    {
      vty_out(vty, "Invalid type %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  ripng_redistribute_routemap_set (type, argv[1]);
  zclient_redistribute (ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP6, type, 0,
                        VRF_DEFAULT);
 return CMD_SUCCESS;
}

ALIAS (no_ripng_redistribute_type,
       no_ripng_redistribute_type_routemap_cmd,
       "no redistribute " QUAGGA_REDIST_STR_RIPNGD " route-map WORD",
       NO_STR
       "Redistribute\n"
       QUAGGA_REDIST_HELP_STR_RIPNGD
       "Route map reference\n"
       "Pointer to route-map entries\n")

DEFUN (ripng_redistribute_type_metric_routemap,
       ripng_redistribute_type_metric_routemap_cmd,
       "redistribute " QUAGGA_REDIST_STR_RIPNGD " metric <0-16> route-map WORD",
       "Redistribute\n"
       QUAGGA_REDIST_HELP_STR_RIPNGD
       "Metric\n"
       "Metric value\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
  int type;
  int metric;

  type = proto_redistnum(AFI_IP6, argv[0]);
  metric = atoi (argv[1]);

  if (type < 0)
    {
      vty_out(vty, "Invalid type %s%s", argv[0], VTY_NEWLINE);
      return CMD_WARNING;
    }

  ripng_redistribute_metric_set (type, metric);
  ripng_redistribute_routemap_set (type, argv[2]);
  zclient_redistribute (ZEBRA_REDISTRIBUTE_ADD, zclient, AFI_IP6, type, 0, VRF_DEFAULT);
  return CMD_SUCCESS;
}

ALIAS (no_ripng_redistribute_type,
       no_ripng_redistribute_type_metric_routemap_cmd,
       "no redistribute " QUAGGA_REDIST_STR_RIPNGD " metric <0-16> route-map WORD",
       NO_STR
       "Redistribute\n"
       QUAGGA_REDIST_HELP_STR_RIPNGD
       "Route map reference\n"
       "Pointer to route-map entries\n")

void
ripng_redistribute_write (struct vty *vty, int config_mode)
{
  int i;

  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    if (i != zclient->redist_default &&
        vrf_bitmap_check (zclient->redist[AFI_IP6][i], VRF_DEFAULT))
      {
      if (config_mode)
	{
	  if (ripng->route_map[i].metric_config)
	    {
	      if (ripng->route_map[i].name)
		vty_out (vty, " redistribute %s metric %d route-map %s%s",
			 zebra_route_string(i), ripng->route_map[i].metric,
			ripng->route_map[i].name, VTY_NEWLINE);
	      else
		vty_out (vty, " redistribute %s metric %d%s",
			zebra_route_string(i), ripng->route_map[i].metric,
			VTY_NEWLINE);
	    }
	  else
	    {
	      if (ripng->route_map[i].name)
		vty_out (vty, " redistribute %s route-map %s%s",
			 zebra_route_string(i), ripng->route_map[i].name,
			 VTY_NEWLINE);
	      else
		vty_out (vty, " redistribute %s%s", zebra_route_string(i),
			 VTY_NEWLINE);
	    }
	}
      else
	vty_out (vty, "    %s", zebra_route_string(i));
      }
}

/* RIPng configuration write function. */
static int
zebra_config_write (struct vty *vty)
{
  if (! zclient->enable)
    {
      vty_out (vty, "no router zebra%s", VTY_NEWLINE);
      return 1;
    }
  else if (! vrf_bitmap_check (zclient->redist[AFI_IP6][ZEBRA_ROUTE_RIPNG], VRF_DEFAULT))
    {
      vty_out (vty, "router zebra%s", VTY_NEWLINE);
      vty_out (vty, " no redistribute ripng%s", VTY_NEWLINE);
      return 1;
    }
  return 0;
}

/* Zebra node structure. */
static struct cmd_node zebra_node =
{
  ZEBRA_NODE,
  "%s(config-router)# ",
};

static void
ripng_zebra_connected (struct zclient *zclient)
{
  zclient_send_reg_requests (zclient, VRF_DEFAULT);
}

/* Initialize zebra structure and it's commands. */
void
zebra_init (struct thread_master *master)
{
  /* Allocate zebra structure. */
  zclient = zclient_new(master);
  zclient_init (zclient, ZEBRA_ROUTE_RIPNG, 0);

  zclient->zebra_connected = ripng_zebra_connected;
  zclient->interface_up = ripng_interface_up;
  zclient->interface_down = ripng_interface_down;
  zclient->interface_add = ripng_interface_add;
  zclient->interface_delete = ripng_interface_delete;
  zclient->interface_address_add = ripng_interface_address_add;
  zclient->interface_address_delete = ripng_interface_address_delete;
  zclient->ipv4_route_add = NULL;
  zclient->ipv4_route_delete = NULL;
  zclient->redistribute_route_ipv4_add = NULL;
  zclient->redistribute_route_ipv4_del = NULL;
  zclient->ipv6_route_add = ripng_zebra_read_ipv6;
  zclient->ipv6_route_delete = ripng_zebra_read_ipv6;
  zclient->redistribute_route_ipv6_add = ripng_zebra_read_ipv6;
  zclient->redistribute_route_ipv6_del = ripng_zebra_read_ipv6;
  
  /* Install zebra node. */
  install_node (&zebra_node, zebra_config_write);

  /* Install command element for zebra node. */ 
  install_element (CONFIG_NODE, &router_zebra_cmd);
  install_element (CONFIG_NODE, &no_router_zebra_cmd);
  install_default (ZEBRA_NODE);
  install_element (ZEBRA_NODE, &ripng_redistribute_ripng_cmd);
  install_element (ZEBRA_NODE, &no_ripng_redistribute_ripng_cmd);

  /* Install command elements to ripng node */
  install_element (RIPNG_NODE, &ripng_redistribute_type_cmd);
  install_element (RIPNG_NODE, &ripng_redistribute_type_routemap_cmd);
  install_element (RIPNG_NODE, &ripng_redistribute_type_metric_cmd);
  install_element (RIPNG_NODE, &ripng_redistribute_type_metric_routemap_cmd);
  install_element (RIPNG_NODE, &no_ripng_redistribute_type_cmd);
  install_element (RIPNG_NODE, &no_ripng_redistribute_type_routemap_cmd);
  install_element (RIPNG_NODE, &no_ripng_redistribute_type_metric_cmd);
  install_element (RIPNG_NODE, &no_ripng_redistribute_type_metric_routemap_cmd);
}
