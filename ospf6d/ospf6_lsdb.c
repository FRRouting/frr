/*
 * Copyright (C) 2002 Yasuhiro Ohara
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

#include <zebra.h>

#include "memory.h"
#include "log.h"
#include "command.h"
#include "if.h"

#include "ospf6_dump.h"
#include "ospf6_lsdb.h"

#include "ospf6_interface.h"
#include "ospf6_area.h"
#include "ospf6_top.h"

#define OSPF6_LSDB_MATCH_TYPE        0x01
#define OSPF6_LSDB_MATCH_ID          0x02
#define OSPF6_LSDB_MATCH_ADV_ROUTER  0x04
#define OSPF6_LSDB_SHOW_DUMP         0x08
#define OSPF6_LSDB_SHOW_DETAIL       0x10

struct ospf6_lsdb_hook_t hooks[0x2000];
struct ospf6_lsdb_hook_t *ospf6_lsdb_hook = hooks;

struct ospf6_lsdb *
ospf6_lsdb_create ()
{
  struct ospf6_lsdb *lsdb;

  lsdb = XCALLOC (MTYPE_OSPF6_LSDB, sizeof (struct ospf6_lsdb));
  if (lsdb == NULL)
    {
      zlog_warn ("Can't malloc lsdb");
      return NULL;
    }
  memset (lsdb, 0, sizeof (struct ospf6_lsdb));

  lsdb->table = route_table_init ();
  return lsdb;
}

void
ospf6_lsdb_delete (struct ospf6_lsdb *lsdb)
{
  ospf6_lsdb_remove_all (lsdb);
  route_table_finish (lsdb->table);
  XFREE (MTYPE_OSPF6_LSDB, lsdb);
}

static void
ospf6_lsdb_set_key (struct prefix_ipv6 *key, int flag,
                    u_int16_t type, u_int32_t id, u_int32_t adv_router)
{
  int len = 0;
  memset (key, 0, sizeof (struct prefix_ipv6));

  if (CHECK_FLAG (flag, OSPF6_LSDB_MATCH_TYPE))
    {
      len += 2;
      if (CHECK_FLAG (flag, OSPF6_LSDB_MATCH_ADV_ROUTER))
        {
          len += 4;
          if (CHECK_FLAG (flag, OSPF6_LSDB_MATCH_ID))
            len += 4;
        }
    }

  if (len > 0)
    memcpy ((char *)&key->prefix, &type, 2);
  if (len > 2)
    memcpy ((char *)&key->prefix + 2, &adv_router, 4);
  if (len > 6)
    memcpy ((char *)&key->prefix + 6, &id, 4);

  key->family = AF_INET6;
  key->prefixlen = len * 8;
}

void
ospf6_lsdb_add (struct ospf6_lsa *lsa, struct ospf6_lsdb *lsdb)
{
  int flag;
  struct prefix_ipv6 key;
  struct route_node *rn;
  struct ospf6_lsa *old = NULL;

  flag = OSPF6_LSDB_MATCH_TYPE | OSPF6_LSDB_MATCH_ID |
         OSPF6_LSDB_MATCH_ADV_ROUTER;
  ospf6_lsdb_set_key (&key, flag, lsa->header->type, lsa->header->id,
                      lsa->header->adv_router);

  rn = route_node_get (lsdb->table, (struct prefix *) &key);
  if (rn->info)
    old = rn->info;
  rn->info = lsa;
  ospf6_lsa_lock (lsa);

  if (old)
    ospf6_lsa_unlock (old);
  else
    lsdb->count++;
}

void
ospf6_lsdb_remove (struct ospf6_lsa *lsa, struct ospf6_lsdb *lsdb)
{
  int flag;
  struct prefix_ipv6 key;
  struct route_node *rn;
  struct ospf6_lsa *old;

  flag = OSPF6_LSDB_MATCH_TYPE | OSPF6_LSDB_MATCH_ID |
         OSPF6_LSDB_MATCH_ADV_ROUTER;
  ospf6_lsdb_set_key (&key, flag, lsa->header->type, lsa->header->id,
                      lsa->header->adv_router);

  rn = route_node_lookup (lsdb->table, (struct prefix *) &key);
  if (! rn || ! rn->info)
    {
      zlog_warn ("LSDB: Can't remove: no such LSA: %s", lsa->str);
      return;
    }

  old = rn->info;
  if (old != lsa)
    {
      zlog_warn ("LSDB: Can't remove: different instance: %s (%p <-> %p) %s",
                 lsa->str, lsa, old, old->str);
      return;
    }

  rn->info = NULL;
  ospf6_lsa_unlock (old);
  lsdb->count--;
}

static void
ospf6_lsdb_lookup_node (struct ospf6_lsdb_node *node,
                        u_int16_t type, u_int32_t id, u_int32_t adv_router,
                        struct ospf6_lsdb *lsdb)
{
  int flag;
  struct route_node *rn;

  memset (node, 0, sizeof (struct ospf6_lsdb_node));

  flag = OSPF6_LSDB_MATCH_TYPE | OSPF6_LSDB_MATCH_ID |
         OSPF6_LSDB_MATCH_ADV_ROUTER;
  ospf6_lsdb_set_key (&node->key, flag, type, id, adv_router);

  rn = route_node_lookup (lsdb->table, (struct prefix *) &node->key);
  if (! rn || ! rn->info)
    return;

  node->node = rn;
  node->next = route_next (rn);
  node->lsa = rn->info;
  if (node->next != NULL)
    route_unlock_node (node->next);
}

struct ospf6_lsa *
ospf6_lsdb_lookup_lsdb (u_int16_t type, u_int32_t id, u_int32_t adv_router,
                        struct ospf6_lsdb *lsdb)
{
  struct ospf6_lsdb_node node;
  ospf6_lsdb_lookup_node (&node, type, id, adv_router, lsdb);
  return node.lsa;
}

/* Iteration function */
void
ospf6_lsdb_head (struct ospf6_lsdb_node *node, struct ospf6_lsdb *lsdb)
{
  struct route_node *rn;

  memset (node, 0, sizeof (struct ospf6_lsdb_node));

  rn = route_top (lsdb->table);
  if (rn == NULL)
    return;

  while (rn && rn->info == NULL)
    rn = route_next (rn);

  if (rn && rn->info)
    {
      node->node = rn;
      node->next = route_next (rn);
      node->lsa = rn->info;
      if (node->next != NULL)
        route_unlock_node (node->next);
    }
}

void
ospf6_lsdb_type (struct ospf6_lsdb_node *node, u_int16_t type,
                 struct ospf6_lsdb *lsdb)
{
  int flag;
  struct route_node *rn;

  memset (node, 0, sizeof (struct ospf6_lsdb_node));

  flag = OSPF6_LSDB_MATCH_TYPE;
  ospf6_lsdb_set_key (&node->key, flag, type, 0, 0);

  /* get the closest radix node */
  rn = route_node_get (lsdb->table, (struct prefix *) &node->key);

  /* skip to the real existing lsdb entry */
  while (rn && rn->info == NULL && rn->p.prefixlen >= node->key.prefixlen &&
         prefix_match ((struct prefix *) &node->key, &rn->p))
    rn = route_next (rn);

  if (rn && rn->info)
    {
      node->node = rn;
      node->next = route_next (rn);
      node->lsa = rn->info;
      if (node->next != NULL)
        route_unlock_node (node->next);
    }
}

void
ospf6_lsdb_type_router (struct ospf6_lsdb_node *node,
                        u_int16_t type, u_int32_t adv_router,
                        struct ospf6_lsdb *lsdb)
{
  int flag;
  struct route_node *rn;

  memset (node, 0, sizeof (struct ospf6_lsdb_node));

  flag = OSPF6_LSDB_MATCH_TYPE | OSPF6_LSDB_MATCH_ADV_ROUTER;
  ospf6_lsdb_set_key (&node->key, flag, type, 0, adv_router);

  /* get the closest radix node */
  rn = route_node_get (lsdb->table, (struct prefix *) &node->key);

  /* skip to the real existing lsdb entry */
  while (rn && rn->info == NULL && rn->p.prefixlen >= node->key.prefixlen &&
         prefix_match ((struct prefix *) &node->key, &rn->p))
    rn = route_next (rn);

  if (rn && rn->info)
    {
      node->node = rn;
      node->next = route_next (rn);
      node->lsa = rn->info;
      if (node->next != NULL)
        route_unlock_node (node->next);
    }
}

void
ospf6_lsdb_next (struct ospf6_lsdb_node *node)
{
  struct route_node *rn;

  route_lock_node (node->node);
  rn = route_next (node->node);

  /* skip to the real existing lsdb entry */
  while (rn && rn->info == NULL && rn->p.prefixlen >= node->key.prefixlen &&
         prefix_match ((struct prefix *) &node->key, &rn->p))
    rn = route_next (rn);

  if (rn && rn->info && rn->p.prefixlen >= node->key.prefixlen &&
      prefix_match ((struct prefix *) &node->key, &rn->p))
    {
      node->node = rn;
      node->next = route_next (rn);
      node->lsa = rn->info;
      if (node->next != NULL)
        route_unlock_node (node->next);
    }
  else
    {
      node->node = NULL;
      node->next = NULL;
      node->lsa = NULL;
    }
}

struct ospf6_lsa *
ospf6_lsdb_lookup (u_int16_t type, u_int32_t id, u_int32_t adv_router,
                   void *scope)
{
  struct ospf6_interface *o6i;
  struct ospf6_area *o6a;
  listnode i, j;

  if (scope == (void *) ospf6)
    return ospf6_lsdb_lookup_lsdb (type, id, adv_router, ospf6->lsdb);

  for (i = listhead (ospf6->area_list); i; nextnode (i))
    {
      o6a = getdata (i);

      if (scope == (void *) o6a)
        return ospf6_lsdb_lookup_lsdb (type, id, adv_router, o6a->lsdb);

      for (j = listhead (o6a->if_list); j; nextnode (j))
        {
          o6i = getdata (j);

          if (scope == (void *) o6i)
            return ospf6_lsdb_lookup_lsdb (type, id, adv_router, o6i->lsdb);
        }
    }

  zlog_warn ("LSDB: Can't lookup: unknown scope, type %#hx", ntohs (type));
  return NULL;
}

void
ospf6_lsdb_install (struct ospf6_lsa *new)
{
  struct ospf6_lsdb *lsdb;
  struct ospf6_lsa *old;
  int need_hook = 0;
  void (*hook) (struct ospf6_lsa *, struct ospf6_lsa *);

  struct ospf6 *as = NULL;
  struct ospf6_area *area = NULL;
  struct ospf6_interface *linklocal = NULL;
  hook = NULL;

  switch (ntohs (new->header->type) & OSPF6_LSTYPE_SCOPE_MASK)
    {
      case OSPF6_LSA_SCOPE_LINKLOCAL:
        linklocal = (struct ospf6_interface *) new->scope;
        lsdb = linklocal->lsdb;
        break;
      case OSPF6_LSA_SCOPE_AREA:
        area = (struct ospf6_area *) new->scope;
        lsdb = area->lsdb;
        break;
      case OSPF6_LSA_SCOPE_AS:
        as = (struct ospf6 *) new->scope;
        lsdb = as->lsdb;
        break;
      default:
        zlog_warn ("LSDB: Can't install: scope unknown: %s", new->str);
        return;
    }

  /* whether schedule calculation or not */
  old = ospf6_lsdb_lookup_lsdb (new->header->type, new->header->id,
                                new->header->adv_router, lsdb);

  if (! old || ospf6_lsa_differ (old, new))
    need_hook++;

  /* log */
  if (IS_OSPF6_DUMP_LSDB)
    zlog_info ("LSDB: Install: %s %s", new->str,
               ((IS_LSA_MAXAGE (new)) ? "(MaxAge)" : ""));

  if (old)
    ospf6_lsa_lock (old);

  ospf6_lsdb_add (new, lsdb);
  gettimeofday (&new->installed, NULL);

  hook = ospf6_lsdb_hook[ntohs (new->header->type) &
                         OSPF6_LSTYPE_CODE_MASK].hook;
  if (need_hook && hook)
    (*hook) (old, new);

  /* old LSA should be freed here */
  if (old)
    ospf6_lsa_unlock (old);
}

void
ospf6_lsdb_remove_all (struct ospf6_lsdb *lsdb)
{
  struct ospf6_lsdb_node node;
  for (ospf6_lsdb_head (&node, lsdb); ! ospf6_lsdb_is_end (&node);
       ospf6_lsdb_next (&node))
    ospf6_lsdb_remove (node.lsa, lsdb);
}

void
ospf6_lsdb_remove_maxage (struct ospf6_lsdb *lsdb)
{
  struct ospf6_lsdb_node node;
  struct ospf6_lsa *lsa;

  for (ospf6_lsdb_head (&node, lsdb); ! ospf6_lsdb_is_end (&node);
       ospf6_lsdb_next (&node))
    {
      lsa = node.lsa;

      /* contiue if it's not MaxAge */
      if (! IS_LSA_MAXAGE (lsa))
        continue;

      /* continue if it's referenced by some retrans-lists */
      if (lsa->lock != 1)
        continue;

      if (IS_OSPF6_DUMP_LSDB)
        zlog_info ("Remove MaxAge LSA: %s", lsa->str);

      ospf6_lsdb_remove (lsa, lsdb);
    }
}



/* vty functions */

static int
ospf6_lsdb_match (int flag, u_int16_t type, u_int32_t id,
                  u_int32_t adv_router, struct ospf6_lsa *lsa)
{
  if (CHECK_FLAG (flag, OSPF6_LSDB_MATCH_TYPE) &&
      lsa->header->type != type)
    return 0;

  if (CHECK_FLAG (flag, OSPF6_LSDB_MATCH_ID) &&
      lsa->header->id != id)
    return 0;

  if (CHECK_FLAG (flag, OSPF6_LSDB_MATCH_ADV_ROUTER) &&
      lsa->header->adv_router != adv_router)
    return 0;

  return 1;
}

int
show_ipv6_ospf6_lsdb (struct vty *vty, int argc, char **argv,
                      struct ospf6_lsdb *lsdb)
{
  u_int flag;
  u_int16_t type = 0;
  u_int32_t id, adv_router;
  int ret;
  struct ospf6_lsdb_node node;
  char invalid[32], *invalidp;
  int l_argc = argc;
  char **l_argv = argv;

  flag = 0;
  memset (invalid, 0, sizeof (invalid));
  invalidp = invalid;

  /* chop tail if the words is 'dump' or 'summary' */
  if (l_argc > 0 && ! strcmp (l_argv[l_argc - 1], "dump"))
    {
      SET_FLAG (flag, OSPF6_LSDB_SHOW_DUMP);
      l_argc --;
    }
  else if (l_argc > 0 && ! strcmp (l_argv[l_argc - 1], "detail"))
    {
      SET_FLAG (flag, OSPF6_LSDB_SHOW_DETAIL);
      l_argc --;
    }

  if (l_argc > 0)
    {
      SET_FLAG (flag, OSPF6_LSDB_MATCH_TYPE);
      if (! strncmp (l_argv[0], "r", 1))
        type = htons (OSPF6_LSA_TYPE_ROUTER);
      if (! strncmp (l_argv[0], "n", 1))
        type = htons (OSPF6_LSA_TYPE_NETWORK);
      if (! strncmp (l_argv[0], "a", 1))
        type = htons (OSPF6_LSA_TYPE_AS_EXTERNAL);
      if (! strcmp (l_argv[0], "intra-prefix"))
        type = htons (OSPF6_LSA_TYPE_INTRA_PREFIX);
      if (! strcmp (l_argv[0], "inter-router"))
        type = htons (OSPF6_LSA_TYPE_INTER_ROUTER);
      if (! strcmp (l_argv[0], "inter-prefix"))
        type = htons (OSPF6_LSA_TYPE_INTER_PREFIX);
      if (! strncmp (l_argv[0], "l", 1))
        type = htons (OSPF6_LSA_TYPE_LINK);
      if (! strncmp (l_argv[0], "0x", 2) && strlen (l_argv[0]) == 6)
        type = htons ((short) strtol (l_argv[0], (char **)NULL, 16));
      if (! strncmp (l_argv[0], "*", 1))
        UNSET_FLAG (flag, OSPF6_LSDB_MATCH_TYPE);
    }

  if (l_argc > 1)
    {
      SET_FLAG (flag, OSPF6_LSDB_MATCH_ID);
      if (! strncmp (l_argv[1], "*", 1))
        UNSET_FLAG (flag, OSPF6_LSDB_MATCH_ID);
      else
        {
          ret = inet_pton (AF_INET, l_argv[1], &id);
          if (ret != 1)
            {
              id = htonl (strtoul (l_argv[1], &invalidp, 10));
              if (invalid[0] != '\0')
                {
                  vty_out (vty, "Link State ID is not parsable: %s%s",
                           l_argv[1], VTY_NEWLINE);
                  return CMD_SUCCESS;
                }
            }
        }
    }

  if (l_argc > 2)
    {
      SET_FLAG (flag, OSPF6_LSDB_MATCH_ADV_ROUTER);
      if (! strncmp (l_argv[2], "*", 1))
        UNSET_FLAG (flag, OSPF6_LSDB_MATCH_ADV_ROUTER);
      else
        {
          ret = inet_pton (AF_INET, l_argv[2], &adv_router);
          if (ret != 1)
            {
              adv_router = htonl (strtoul (l_argv[2], &invalidp, 10));
              if (invalid[0] != '\0')
                {
                  vty_out (vty, "Advertising Router is not parsable: %s%s",
                           l_argv[2], VTY_NEWLINE);
                  return CMD_SUCCESS;
                }
            }
        }
    }

  if (! CHECK_FLAG (flag, OSPF6_LSDB_SHOW_DETAIL))
    ospf6_lsa_show_summary_header (vty);

  for (ospf6_lsdb_head (&node, lsdb); ! ospf6_lsdb_is_end (&node);
       ospf6_lsdb_next (&node))
    {
      if (! ospf6_lsdb_match (flag, type, id, adv_router, node.lsa))
        continue;

      if (CHECK_FLAG (flag, OSPF6_LSDB_SHOW_DUMP))
        ospf6_lsa_show_dump (vty, node.lsa);
      else if (CHECK_FLAG (flag, OSPF6_LSDB_SHOW_DETAIL))
        ospf6_lsa_show (vty, node.lsa);
      else
        ospf6_lsa_show_summary (vty, node.lsa);
    }

  return CMD_SUCCESS;
}

DEFUN (show_ipv6_ospf6_database,
       show_ipv6_ospf6_database_cmd,
       "show ipv6 ospf6 database",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "LSA Database\n"
       )
{
  struct ospf6_area *o6a;
  struct ospf6_interface *o6i;
  listnode i, j;

  /* call show function for each of LSAs in the LSDBs */

  for (i = listhead (ospf6->area_list); i; nextnode (i))
    {
      o6a = (struct ospf6_area *) getdata (i);

      /* LinkLocal LSDBs */
      for (j = listhead (o6a->if_list); j; nextnode (j))
        {
          o6i = (struct ospf6_interface *) getdata (j);

          vty_out (vty, "%s", VTY_NEWLINE);
          vty_out (vty, "                Interface %s (Area: %s):%s",
                   o6i->interface->name, o6a->str, VTY_NEWLINE);
          vty_out (vty, "%s", VTY_NEWLINE);
          show_ipv6_ospf6_lsdb (vty, argc, argv, o6i->lsdb);
        }

      /* Area LSDBs */
      vty_out (vty, "%s", VTY_NEWLINE);
      vty_out (vty, "                Area %s:%s", o6a->str, VTY_NEWLINE);
      vty_out (vty, "%s", VTY_NEWLINE);
      show_ipv6_ospf6_lsdb (vty, argc, argv, o6a->lsdb);
    }

  /* AS LSDBs */
  vty_out (vty, "%s", VTY_NEWLINE);
  vty_out (vty, "                AS:%s", VTY_NEWLINE);
  vty_out (vty, "%s", VTY_NEWLINE);
  show_ipv6_ospf6_lsdb (vty, argc, argv, ospf6->lsdb);

  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_database,
       show_ipv6_ospf6_database_type_cmd,
       "show ipv6 ospf6 database (router|network|as-external|intra-prefix|inter-prefix|inter-router|link|*|HEX|dump|detail)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "LSA Database\n"
       "Router-LSA\n"
       "Network-LSA\n"
       "AS-External-LSA\n"
       "Intra-Area-Prefix-LSA\n"
       "Inter-Area-Router-LSA\n"
       "Inter-Area-Prefix-LSA\n"
       "Link-LSA\n"
       "All LS Type\n"
       "Specify LS Type by Hex\n"
       "Dump raw LSA data in Hex\n"
       "show detail of LSAs\n"
       )

ALIAS (show_ipv6_ospf6_database,
       show_ipv6_ospf6_database_type_id_cmd,
       "show ipv6 ospf6 database (router|network|as-external|intra-prefix|inter-prefix|inter-router|link|*|HEX) (A.B.C.D|*|dump|detail)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "LSA Database\n"
       "Router-LSA\n"
       "Network-LSA\n"
       "AS-External-LSA\n"
       "Intra-Area-Prefix-LSA\n"
       "Inter-Area-Router-LSA\n"
       "Inter-Area-Prefix-LSA\n"
       "Link-LSA\n"
       "All LS Type\n"
       "Specify LS Type by Hex\n"
       "Link State ID\n"
       "All Link State ID\n"
       "Dump raw LSA data in Hex\n"
       "show detail of LSAs\n"
       )

ALIAS (show_ipv6_ospf6_database,
       show_ipv6_ospf6_database_type_id_adv_router_cmd,
       "show ipv6 ospf6 database (router|network|as-external|intra-prefix|inter-prefix|inter-router|link|*|HEX) (A.B.C.D|*) (A.B.C.D|*|dump|detail)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "LSA Database\n"
       "Router-LSA\n"
       "Network-LSA\n"
       "AS-External-LSA\n"
       "Intra-Area-Prefix-LSA\n"
       "Inter-Area-Router-LSA\n"
       "Inter-Area-Prefix-LSA\n"
       "Link-LSA\n"
       "All LS Type\n"
       "Specify LS Type by Hex\n"
       "Link State ID\n"
       "All Link State ID\n"
       "Advertising Router\n"
       "All Advertising Router\n"
       "Dump raw LSA data in Hex\n"
       "show detail of LSAs\n"
       )

ALIAS (show_ipv6_ospf6_database,
       show_ipv6_ospf6_database_type_id_adv_router_dump_cmd,
       "show ipv6 ospf6 database (router|network|as-external|intra-prefix|inter-prefix|inter-router|link|*|HEX) (A.B.C.D|*) (A.B.C.D|*) (dump|detail|)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "LSA Database\n"
       "Router-LSA\n"
       "Network-LSA\n"
       "AS-External-LSA\n"
       "Intra-Area-Prefix-LSA\n"
       "Inter-Area-Router-LSA\n"
       "Inter-Area-Prefix-LSA\n"
       "Link-LSA\n"
       "All LS Type\n"
       "Specify LS Type by Hex\n"
       "Link State ID\n"
       "All Link State ID\n"
       "Advertising Router\n"
       "All Advertising Router\n"
       "Dump raw LSA data in Hex\n"
       "show detail of LSAs\n"
       )

void
ospf6_lsdb_init ()
{
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_id_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_id_adv_router_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_database_type_id_adv_router_dump_cmd);

  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_id_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_id_adv_router_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_database_type_id_adv_router_dump_cmd);
}


