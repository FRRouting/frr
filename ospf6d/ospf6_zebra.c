/*
 * Copyright (C) 1999 Yasuhiro Ohara
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#include "ospf6d.h"

#include "ospf6_interface.h"
#include "ospf6_asbr.h"

#include "ospf6_linklist.h"

/* information about zebra. */
struct zclient *zclient = NULL;

/* redistribute function */
void
ospf6_zebra_redistribute (int type)
{
  int top_change = 0;

  if (zclient->redist[type])
    return;

  if (! ospf6_is_asbr (ospf6))
    top_change = 1;

  zclient->redist[type] = 1;

  if (zclient->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_ADD, zclient->sock, type);

  if (top_change)
    CALL_CHANGE_HOOK (&top_hook, ospf6);
}

void
ospf6_zebra_no_redistribute (int type)
{
  int top_change = 0;

  if (!zclient->redist[type])
    return;

  if (ospf6_is_asbr (ospf6))
    top_change = 1;

  zclient->redist[type] = 0;

  if (zclient->sock > 0)
    zebra_redistribute_send (ZEBRA_REDISTRIBUTE_DELETE, zclient->sock, type);

  if (top_change)
    CALL_CHANGE_HOOK (&top_hook, ospf6);
}

int
ospf6_zebra_is_redistribute (int type)
{
  return zclient->redist[type];
}


/* Inteface addition message from zebra. */
int
ospf6_zebra_if_add (int command, struct zclient *zclient, zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_add_read (zclient->ibuf);

  /* log */
  if (IS_OSPF6_DUMP_ZEBRA)
    zlog_info ("ZEBRA: I/F add: %s index %d mtu %d",
               ifp->name, ifp->ifindex, ifp->mtu);

  ospf6_interface_if_add (ifp);

  return 0;
}

int
ospf6_zebra_if_del (int command, struct zclient *zclient, zebra_size_t length)
{
#if 0
  struct interface *ifp = NULL;

  ifp = zebra_interface_delete_read (zclient->ibuf);

  /* log */
  if (IS_OSPF6_DUMP_ZEBRA)
    zlog_info ("ZEBRA: I/F delete: %s index %d mtu %d",
               ifp->name, ifp->ifindex, ifp->mtu);

  ospf6_interface_if_del (ifp);
#endif

  return 0;
}

int
ospf6_zebra_if_state_update (int command, struct zclient *zclient,
                             zebra_size_t length)
{
  struct interface *ifp;

  ifp = zebra_interface_state_read (zclient->ibuf);

  /* log */
  if (IS_OSPF6_DUMP_ZEBRA)
    zlog_info ("ZEBRA: I/F %s state change: index %d flags %ld metric %d mtu %d",
               ifp->name, ifp->ifindex, ifp->flags, ifp->metric, ifp->mtu);

  ospf6_interface_state_update (ifp);
  return 0;
}

int
ospf6_zebra_if_address_update_add (int command, struct zclient *zclient,
                               zebra_size_t length)
{
  struct connected *c;
  char buf[128];

  c = zebra_interface_address_add_read (zclient->ibuf);
  if (c == NULL)
    return 0;

  if (IS_OSPF6_DUMP_ZEBRA)
    zlog_info ("ZEBRA: I/F %s address add: %5s %s/%d",
               c->ifp->name, prefix_family_str (c->address),
               inet_ntop (c->address->family, &c->address->u.prefix,
                          buf, sizeof (buf)), c->address->prefixlen);

  if (c->address->family == AF_INET6)
    ospf6_interface_address_update (c->ifp);

  return 0;
}

int
ospf6_zebra_if_address_update_delete (int command, struct zclient *zclient,
                               zebra_size_t length)
{
  struct connected *c;
  char buf[128];

  c = zebra_interface_address_delete_read (zclient->ibuf);
  if (c == NULL)
    return 0;

  if (IS_OSPF6_DUMP_ZEBRA)
    zlog_info ("ZEBRA: I/F %s address del: %5s %s/%d",
               c->ifp->name, prefix_family_str (c->address),
               inet_ntop (c->address->family, &c->address->u.prefix,
                          buf, sizeof (buf)), c->address->prefixlen);

  if (c->address->family == AF_INET6)
    ospf6_interface_address_update (c->ifp);

  return 0;
}



const char *zebra_route_name[ZEBRA_ROUTE_MAX] =
{
  "System",
  "Kernel",
  "Connect",
  "Static",
  "RIP",
  "RIPng",
  "OSPF",
  "OSPF6",
  "BGP",
};

const char *zebra_route_abname[ZEBRA_ROUTE_MAX] =
  { "X", "K", "C", "S", "r", "R", "o", "O", "B" };

int
ospf6_zebra_read_ipv6 (int command, struct zclient *zclient,
                       zebra_size_t length)
{
  struct stream *s;
  struct zapi_ipv6 api;
  unsigned long ifindex;
  struct prefix_ipv6 p;
  struct in6_addr *nexthop;
  char prefixstr[128], nexthopstr[128];

  s = zclient->ibuf;
  ifindex = 0;
  nexthop = NULL;
  memset (&api, 0, sizeof (api));

  /* Type, flags, message. */
  api.type = stream_getc (s);
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
      nexthop = (struct in6_addr *)
        malloc (api.nexthop_num * sizeof (struct in6_addr));
      stream_get (nexthop, s, api.nexthop_num * sizeof (struct in6_addr));
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

  /* log */
  if (IS_OSPF6_DUMP_ZEBRA)
    {
      prefix2str ((struct prefix *)&p, prefixstr, sizeof (prefixstr));
      inet_ntop (AF_INET6, &nexthop, nexthopstr, sizeof (nexthopstr));

      if (command == ZEBRA_IPV6_ROUTE_ADD)
	zlog_info ("ZEBRA: Receive add %s route: %s nexthop:%s ifindex:%ld",
		   zebra_route_name [api.type], prefixstr,
		   nexthopstr, ifindex);
      else
	zlog_info ("ZEBRA: Receive remove %s route: %s nexthop:%s ifindex:%ld",
		   zebra_route_name [api.type], prefixstr,
		   nexthopstr, ifindex);
    }
 
  if (command == ZEBRA_IPV6_ROUTE_ADD)
    ospf6_asbr_route_add (api.type, ifindex, (struct prefix *) &p,
                          api.nexthop_num, nexthop);
  else
    ospf6_asbr_route_remove (api.type, ifindex, (struct prefix *) &p);

  if (CHECK_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP))
    free (nexthop);

  return 0;
}


DEFUN (show_zebra,
       show_zebra_cmd,
       "show zebra",
       SHOW_STR
       "Zebra information\n")
{
  int i;
  if (!zclient)
    vty_out (vty, "Not connected to zebra%s", VTY_NEWLINE);

  vty_out (vty, "Zebra Infomation%s", VTY_NEWLINE);
  vty_out (vty, "  enable: %d%s", zclient->enable, VTY_NEWLINE);
  vty_out (vty, "  fail: %d%s", zclient->fail, VTY_NEWLINE);
  vty_out (vty, "  redistribute default: %d%s", zclient->redist_default,
           VTY_NEWLINE);
  for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
    vty_out (vty, "    RouteType: %s - %s%s", zebra_route_name[i],
             zclient->redist[i] ? "redistributed" : "not redistributed",
             VTY_NEWLINE);
  return CMD_SUCCESS;
}

DEFUN (router_zebra,
       router_zebra_cmd,
       "router zebra",
       "Enable a routing process\n"
       "Make connection to zebra daemon\n")
{
  if (IS_OSPF6_DUMP_CONFIG)
    zlog_info ("Config: router zebra");

  vty->node = ZEBRA_NODE;
  zclient->enable = 1;
  zclient_start (zclient);
  return CMD_SUCCESS;
}

DEFUN (no_router_zebra,
       no_router_zebra_cmd,
       "no router zebra",
       NO_STR
       "Configure routing process\n"
       "Disable connection to zebra daemon\n")
{
  if (IS_OSPF6_DUMP_CONFIG)
    zlog_info ("no router zebra");

  zclient->enable = 0;
  zclient_stop (zclient);
  return CMD_SUCCESS;
}

/* Zebra configuration write function. */
int
ospf6_zebra_config_write (struct vty *vty)
{
  if (! zclient->enable)
    {
      vty_out (vty, "no router zebra%s", VTY_NEWLINE);
      return 1;
    }
  else if (! zclient->redist[ZEBRA_ROUTE_OSPF6])
    {
      vty_out (vty, "router zebra%s", VTY_NEWLINE);
      vty_out (vty, " no redistribute ospf6%s", VTY_NEWLINE);
      return 1;
    }
  return 0;
}

/* Zebra node structure. */
struct cmd_node zebra_node =
{
  ZEBRA_NODE,
  "%s(config-zebra)# ",
};

#define ADD    0
#define CHANGE 1
#define REMOVE 2

static void
ospf6_zebra_route_update (int type, struct ospf6_route_req *request)
{
  char buf[96], ifname[IFNAMSIZ];

  struct zapi_ipv6 api;
  struct ospf6_route_req route;
  struct linklist *nexthop_list;
  struct linklist_node node;
  struct ospf6_nexthop *nexthop = NULL;
  struct in6_addr **nexthops;
  unsigned int *ifindexes;
  struct prefix_ipv6 *p;
  int i, ret = 0;

  if (IS_OSPF6_DUMP_ZEBRA)
    {
      prefix2str (&request->route.prefix, buf, sizeof (buf));
      if (type == REMOVE)
        zlog_info ("ZEBRA: Send remove route: %s", buf);
      else
        zlog_info ("ZEBRA: Send add route: %s", buf);
    }

  if (zclient->sock < 0)
    {
      if (IS_OSPF6_DUMP_ZEBRA)
        zlog_info ("ZEBRA:   failed: not connected to zebra");
      return;
    }

  if (request->path.origin.adv_router == ospf6->router_id &&
      (request->path.type == OSPF6_PATH_TYPE_EXTERNAL1 ||
       request->path.type == OSPF6_PATH_TYPE_EXTERNAL2))
    {
      if (IS_OSPF6_DUMP_ZEBRA)
        zlog_info ("ZEBRA:   self originated external route, ignore");
      return;
    }

  /* Only the best path (i.e. the first path of the path-list
     in 'struct ospf6_route') will be sent to zebra. */
  ospf6_route_lookup (&route, &request->route.prefix, request->table);
  if (memcmp (&route.path, &request->path, sizeof (route.path)))
    {
      /* this is not preferred best route, ignore */
      if (IS_OSPF6_DUMP_ZEBRA)
        zlog_info ("ZEBRA:   not best path, ignore");
      return;
    }

  nexthop_list = linklist_create ();

  /* for each nexthop */
  for (ospf6_route_lookup (&route, &request->route.prefix, request->table);
       ! ospf6_route_end (&route); ospf6_route_next (&route))
    {
      if (memcmp (&route.path, &request->path, sizeof (route.path)))
        break;

      #define IN6_IS_ILLEGAL_NEXTHOP(a)\
        ((*(u_int32_t *)(void *)(&(a)->s6_addr[0]) == 0xffffffff) &&\
        (*(u_int32_t *)(void *)(&(a)->s6_addr[4]) == 0xffffffff) &&\
        (*(u_int32_t *)(void *)(&(a)->s6_addr[8]) == 0xffffffff) &&\
        (*(u_int32_t *)(void *)(&(a)->s6_addr[12]) == 0xffffffff))
      if (IN6_IS_ILLEGAL_NEXTHOP (&route.nexthop.address))
        {
          zlog_warn ("ZEBRA: Illegal nexthop");
          continue;
        }

      if (type == REMOVE && ! memcmp (&route.nexthop, &request->nexthop,
                                      sizeof (struct ospf6_nexthop)))
        continue;

      nexthop = XCALLOC (MTYPE_OSPF6_OTHER, sizeof (struct ospf6_nexthop));
      if (! nexthop)
        {
          zlog_warn ("ZEBRA: Can't update nexthop: malloc failed");
          continue;
        }

      memcpy (nexthop, &route.nexthop, sizeof (struct ospf6_nexthop));
      linklist_add (nexthop, nexthop_list);
    }

  if (type == REMOVE && nexthop_list->count != 0)
    type = ADD;
  else if (type == REMOVE && nexthop_list->count == 0)
    {
      if (IS_OSPF6_DUMP_ZEBRA)
        zlog_info ("ZEBRA:   all nexthop with the selected path has gone");

      if (! memcmp (&request->route, &route.route,
                    sizeof (struct ospf6_route)))
        {
          /* send 'add' of alternative route */
          struct ospf6_path seconde_path;

          if (IS_OSPF6_DUMP_ZEBRA)
            zlog_info ("ZEBRA:   found alternative path to add");

          memcpy (&seconde_path, &route.path, sizeof (struct ospf6_path));
          type = ADD;

          while (! memcmp (&seconde_path, &route.path,
                           sizeof (struct ospf6_path)))
            {
              nexthop = XCALLOC (MTYPE_OSPF6_OTHER,
                                 sizeof (struct ospf6_nexthop));
              if (! nexthop)
                zlog_warn ("ZEBRA:   Can't update nexthop: malloc failed");
              else
                {
                  memcpy (nexthop, &route.nexthop,
                          sizeof (struct ospf6_nexthop));
                  linklist_add (nexthop, nexthop_list);
                }

              ospf6_route_next (&route);
            }
        }
      else
        {
          /* there is no alternative route. send 'remove' to zebra for
             requested route */
          if (IS_OSPF6_DUMP_ZEBRA)
            zlog_info ("ZEBRA:   can't find alternative path, remove");

          if (IS_OSPF6_DUMP_ZEBRA)
            {
              zlog_info ("ZEBRA:   Debug: walk over the route ?");
              ospf6_route_log_request ("Debug route", "***", &route);
              ospf6_route_log_request ("Debug request", "***", request);
            }

          nexthop = XCALLOC (MTYPE_OSPF6_OTHER,
                             sizeof (struct ospf6_nexthop));
          if (! nexthop)
            zlog_warn ("ZEBRA:   Can't update nexthop: malloc failed");
          else
            {
              memcpy (nexthop, &request->nexthop,
                      sizeof (struct ospf6_nexthop));
              linklist_add (nexthop, nexthop_list);
            }
        }
    }

  if (nexthop_list->count == 0)
    {
      if (IS_OSPF6_DUMP_ZEBRA)
        zlog_info ("ZEBRA:   no nexthop, ignore");
      linklist_delete (nexthop_list);
      return;
    }

  /* allocate memory for nexthop_list */
  nexthops = XCALLOC (MTYPE_OSPF6_OTHER,
                      nexthop_list->count * sizeof (struct in6_addr *));
  if (! nexthops)
    {
      zlog_warn ("ZEBRA:   Can't update zebra route: malloc failed");
      for (linklist_head (nexthop_list, &node); !linklist_end (&node);
           linklist_next (&node))
        XFREE (MTYPE_OSPF6_OTHER, node.data);
      linklist_delete (nexthop_list);
      return;
    }

  /* allocate memory for ifindex_list */
  ifindexes = XCALLOC (MTYPE_OSPF6_OTHER,
                       nexthop_list->count * sizeof (unsigned int));
  if (! ifindexes)
    {
      zlog_warn ("ZEBRA: Can't update zebra route: malloc failed");
      for (linklist_head (nexthop_list, &node); !linklist_end (&node);
           linklist_next (&node))
        XFREE (MTYPE_OSPF6_OTHER, node.data);
      linklist_delete (nexthop_list);
      XFREE (MTYPE_OSPF6_OTHER, nexthops);
      return;
    }

  i = 0;
  for (linklist_head (nexthop_list, &node); ! linklist_end (&node);
       linklist_next (&node))
    {
      nexthop = node.data;
      if (IS_OSPF6_DUMP_ZEBRA)
        {
          inet_ntop (AF_INET6, &nexthop->address, buf, sizeof (buf));
          if_indextoname (nexthop->ifindex, ifname);
          zlog_info ("ZEBRA:   nexthop: %s%%%s(%d)",
                     buf, ifname, nexthop->ifindex);
        }
      nexthops[i] = &nexthop->address;
      ifindexes[i] = nexthop->ifindex;
      i++;
    }

  api.type = ZEBRA_ROUTE_OSPF6;
  api.flags = 0;
  api.message = 0;
  SET_FLAG (api.message, ZAPI_MESSAGE_NEXTHOP);
  SET_FLAG (api.message, ZAPI_MESSAGE_IFINDEX);
  api.nexthop_num = nexthop_list->count;
  api.nexthop = nexthops;
  api.ifindex_num = nexthop_list->count;
  api.ifindex = ifindexes;

  p = (struct prefix_ipv6 *) &request->route.prefix;
  if (type == REMOVE && nexthop_list->count == 1)
    ret = zapi_ipv6_delete (zclient, p, &api);
  else
    ret = zapi_ipv6_add (zclient, p, &api);

  if (ret < 0)
    zlog_err ("ZEBRA: zapi_ipv6_add () failed: %s", strerror (errno));

  for (linklist_head (nexthop_list, &node); !linklist_end (&node);
       linklist_next (&node))
    XFREE (MTYPE_OSPF6_OTHER, node.data);
  linklist_delete (nexthop_list);
  XFREE (MTYPE_OSPF6_OTHER, nexthops);
  XFREE (MTYPE_OSPF6_OTHER, ifindexes);

  return;
}

void
ospf6_zebra_route_update_add (struct ospf6_route_req *request)
{
  ospf6_zebra_route_update (ADD, request);
}

void
ospf6_zebra_route_update_remove (struct ospf6_route_req *request)
{
  ospf6_zebra_route_update (REMOVE, request);
}

static void
ospf6_zebra_redistribute_ospf6 ()
{
  struct route_node *node;

  for (node = route_top (ospf6->route_table->table); node;
       node = route_next (node))
    {
      if (! node || ! node->info)
        continue;
      ospf6_zebra_route_update_add (node->info);
    }
}

static void
ospf6_zebra_no_redistribute_ospf6 ()
{
  struct route_node *node;

  if (! ospf6)
    return;

  for (node = route_top (ospf6->route_table->table); node;
       node = route_next (node))
    {
      if (! node || ! node->info)
        continue;

      ospf6_zebra_route_update_remove (node->info);
    }
}


DEFUN (redistribute_ospf6,
       redistribute_ospf6_cmd,
       "redistribute ospf6",
       "Redistribute control\n"
       "OSPF6 route\n")
{
  /* log */
  if (IS_OSPF6_DUMP_CONFIG)
    zlog_info ("Config: redistribute ospf6");

  zclient->redist[ZEBRA_ROUTE_OSPF6] = 1;

  /* set zebra route table */
  ospf6_zebra_redistribute_ospf6 ();

  return CMD_SUCCESS;
}

DEFUN (no_redistribute_ospf6,
       no_redistribute_ospf6_cmd,
       "no redistribute ospf6",
       NO_STR
       "Redistribute control\n"
       "OSPF6 route\n")
{
  /* log */
  if (IS_OSPF6_DUMP_CONFIG)
    zlog_info ("Config: no redistribute ospf6");

  zclient->redist[ZEBRA_ROUTE_OSPF6] = 0;

  if (! ospf6)
    return CMD_SUCCESS;

  /* clean up zebra route table */
  ospf6_zebra_no_redistribute_ospf6 ();

  ospf6_route_hook_unregister (ospf6_zebra_route_update_add,
                               ospf6_zebra_route_update_add,
                               ospf6_zebra_route_update_remove,
                               ospf6->route_table);

  return CMD_SUCCESS;
}

void
ospf6_zebra_init ()
{
  /* Allocate zebra structure. */
  zclient = zclient_new ();
  zclient_init (zclient, ZEBRA_ROUTE_OSPF6);
  zclient->interface_add = ospf6_zebra_if_add;
  zclient->interface_delete = ospf6_zebra_if_del;
  zclient->interface_up = ospf6_zebra_if_state_update;
  zclient->interface_down = ospf6_zebra_if_state_update;
  zclient->interface_address_add = ospf6_zebra_if_address_update_add;
  zclient->interface_address_delete = ospf6_zebra_if_address_update_delete;
  zclient->ipv4_route_add = NULL;
  zclient->ipv4_route_delete = NULL;
  zclient->ipv6_route_add = ospf6_zebra_read_ipv6;
  zclient->ipv6_route_delete = ospf6_zebra_read_ipv6;

  /* redistribute connected route by default */
  /* ospf6_zebra_redistribute (ZEBRA_ROUTE_CONNECT); */

  /* Install zebra node. */
  install_node (&zebra_node, ospf6_zebra_config_write);

  /* Install command element for zebra node. */
  install_element (VIEW_NODE, &show_zebra_cmd);
  install_element (ENABLE_NODE, &show_zebra_cmd);
  install_element (CONFIG_NODE, &router_zebra_cmd);
  install_element (CONFIG_NODE, &no_router_zebra_cmd);
  install_default (ZEBRA_NODE);
  install_element (ZEBRA_NODE, &redistribute_ospf6_cmd);
  install_element (ZEBRA_NODE, &no_redistribute_ospf6_cmd);

#if 0
  hook.name = "ZebraRouteUpdate";
  hook.hook_add = ospf6_zebra_route_update_add;
  hook.hook_change = ospf6_zebra_route_update_add;
  hook.hook_remove = ospf6_zebra_route_update_remove;
  ospf6_hook_register (&hook, &route_hook);
#endif

  return;
}

void
ospf6_zebra_finish ()
{
  zclient_stop (zclient);
  zclient_free (zclient);
  zclient = (struct zclient *) NULL;
}

