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

#ifndef OSPF6_ROUTE_H
#define OSPF6_ROUTE_H

#include "ospf6_hook.h"
#include "ospf6_linklist.h"

struct ospf6_route_table
{
  char name[128];

  int freeze;

  /* radix tree */
  struct route_table *table;

  /* list of hooks */
  struct linklist *hook_list[3];
  void (*hook_add) (void *);
  void (*hook_change) (void *);
  void (*hook_remove) (void *);

  u_int32_t route_id;
};



struct ospf6_route
{
  /* Destination ID */
  struct prefix prefix;

  /* Destination Type */
  u_char type;
};

/* Path */
struct ls_origin
{
  u_int16_t type;
  u_int32_t id;
  u_int32_t adv_router;
};

struct ospf6_path
{
  /* Link State Origin */
  struct ls_origin origin;

  /* Router bits */
  u_char router_bits;

  /* Optional Capabilities */
  u_char capability[3];

  /* Prefix Options */
  u_char prefix_options;

  /* Associated Area */
  u_int32_t area_id;

  /* Path-type */
  u_char type;

  /* Cost */
  u_int8_t metric_type;
  u_int32_t cost;
  u_int32_t cost_e2;
};

/* Nexthop */
struct ospf6_nexthop
{
  /* Interface index */
  unsigned int ifindex;

  /* IP address, if any */
  struct in6_addr address;
};

struct ospf6_route_node
{
  struct ospf6_route_table *table;
  int count;
  u_int32_t route_id;

  struct route_node  *route_node;
  struct ospf6_route  route;
  struct linklist    *path_list;
};

struct ospf6_path_node
{
  struct ospf6_route_node *route_node;
  struct ospf6_path        path;
  struct linklist         *nexthop_list;
};

struct ospf6_nexthop_node
{
  int            flag;
  struct timeval installed;

  struct ospf6_path_node *path_node;
  struct ospf6_nexthop    nexthop;
};

struct ospf6_route_req
{
  struct ospf6_route_table *table;
  struct route_node    *route_node;
  struct linklist_node  path_lnode;
  struct linklist_node  nexthop_lnode;
  u_int32_t route_id;

  int count;
  struct ospf6_route   route;
  struct ospf6_path    path;
  struct ospf6_nexthop nexthop;
};

#define OSPF6_DEST_TYPE_NONE       0
#define OSPF6_DEST_TYPE_ROUTER     1
#define OSPF6_DEST_TYPE_NETWORK    2
#define OSPF6_DEST_TYPE_DISCARD    3
#define OSPF6_DEST_TYPE_MAX        4

#define OSPF6_PATH_TYPE_NONE       0
#define OSPF6_PATH_TYPE_INTRA      1
#define OSPF6_PATH_TYPE_INTER      2
#define OSPF6_PATH_TYPE_EXTERNAL1  3
#define OSPF6_PATH_TYPE_EXTERNAL2  4
#define OSPF6_PATH_TYPE_ZOFFSET    5
#define OSPF6_PATH_TYPE_ZSYSTEM  (OSPF6_PATH_TYPE_ZOFFSET + ZEBRA_ROUTE_SYSTEM)
#define OSPF6_PATH_TYPE_ZKERNEL  (OSPF6_PATH_TYPE_ZOFFSET + ZEBRA_ROUTE_KERNEL)
#define OSPF6_PATH_TYPE_ZCONNECT (OSPF6_PATH_TYPE_ZOFFSET + ZEBRA_ROUTE_CONNECT)
#define OSPF6_PATH_TYPE_ZSTATIC  (OSPF6_PATH_TYPE_ZOFFSET + ZEBRA_ROUTE_STATIC)
#define OSPF6_PATH_TYPE_ZRIP     (OSPF6_PATH_TYPE_ZOFFSET + ZEBRA_ROUTE_RIP)
#define OSPF6_PATH_TYPE_ZRIPNG   (OSPF6_PATH_TYPE_ZOFFSET + ZEBRA_ROUTE_RIPNG)
#define OSPF6_PATH_TYPE_ZOSPF    (OSPF6_PATH_TYPE_ZOFFSET + ZEBRA_ROUTE_OSPF)
#define OSPF6_PATH_TYPE_ZOSPF6   (OSPF6_PATH_TYPE_ZOFFSET + ZEBRA_ROUTE_OSPF6)
#define OSPF6_PATH_TYPE_ZBGP     (OSPF6_PATH_TYPE_ZOFFSET + ZEBRA_ROUTE_BGP)
#define OSPF6_PATH_TYPE_MAX      (OSPF6_PATH_TYPE_ZOFFSET + ZEBRA_ROUTE_MAX)

#define OSPF6_ROUTE_FLAG_ROUTE_CHANGE      0x01
#define OSPF6_ROUTE_FLAG_PATH_CHANGE       0x02
#define OSPF6_ROUTE_FLAG_ADD               0x04
#define OSPF6_ROUTE_FLAG_REMOVE            0x08
#define OSPF6_ROUTE_FLAG_CHANGE            0x10

int ospf6_route_lookup (struct ospf6_route_req *request,
                        struct prefix *prefix,
                        struct ospf6_route_table *table);
void ospf6_route_head  (struct ospf6_route_req *request,
                        struct ospf6_route_table *table);
int  ospf6_route_end   (struct ospf6_route_req *request);
void ospf6_route_next  (struct ospf6_route_req *request);

void ospf6_route_add (struct ospf6_route_req *, struct ospf6_route_table *);
void ospf6_route_remove (struct ospf6_route_req *, struct ospf6_route_table *);
void ospf6_route_remove_all (struct ospf6_route_table *);

struct ospf6_route_table *ospf6_route_table_create ();
void ospf6_route_table_delete (struct ospf6_route_table *);

void ospf6_route_table_freeze (struct ospf6_route_table *);
void ospf6_route_table_thaw (struct ospf6_route_table *);

void ospf6_route_log_request (char *what, char *where,
                              struct ospf6_route_req *request);

void
ospf6_route_hook_register (void (*add)    (struct ospf6_route_req *),
                           void (*change) (struct ospf6_route_req *),
                           void (*remove) (struct ospf6_route_req *),
                           struct ospf6_route_table *table);
void
ospf6_route_hook_unregister (void (*add)    (struct ospf6_route_req *),
                             void (*change) (struct ospf6_route_req *),
                             void (*remove) (struct ospf6_route_req *),
                             struct ospf6_route_table *table);

void ospf6_route_init ();

int ospf6_route_table_show (struct vty *, int, char **,
                            struct ospf6_route_table *);

#endif /* OSPF6_ROUTE_H */

