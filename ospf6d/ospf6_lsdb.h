/*
 * Copyright (C) 2003 Yasuhiro Ohara
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

#ifndef OSPF6_LSDB_H
#define OSPF6_LSDB_H

#include "prefix.h"
#include "table.h"

struct ospf6_lsdb
{
  struct route_table *table;
  u_int32_t count;
  void (*hook_add) (struct ospf6_lsa *);
  void (*hook_remove) (struct ospf6_lsa *);
};

#define LSDB_FOREACH_LSA(vty, func, lsdb)                             \
  do {                                                                \
    struct ospf6_lsa *lsa;                                            \
    for (lsa = ospf6_lsdb_head (lsdb); lsa;                           \
         lsa = ospf6_lsdb_next (lsa))                                 \
      {                                                               \
        (*(func)) (vty, lsa);                                         \
      }                                                               \
  } while (0)
#define LSDB_FOREACH_LSA_T(vty, func, lsdb, type)                     \
  do {                                                                \
    struct ospf6_lsa *lsa;                                            \
    for (lsa = ospf6_lsdb_type_head (type, lsdb); lsa;                \
         lsa = ospf6_lsdb_type_next (type, lsa))                      \
      {                                                               \
        (*(func)) (vty, lsa);                                         \
      }                                                               \
  } while (0)
#define LSDB_FOREACH_LSA_I(vty, func, lsdb, id)                       \
  do {                                                                \
    struct ospf6_lsa *lsa;                                            \
    for (lsa = ospf6_lsdb_head (lsdb); lsa;                           \
         lsa = ospf6_lsdb_next (lsa))                                 \
      {                                                               \
        if (lsa->header->id != id)                                    \
          continue;                                                   \
        (*(func)) (vty, lsa);                                         \
      }                                                               \
  } while (0)
#define LSDB_FOREACH_LSA_R(vty, func, lsdb, router)                   \
  do {                                                                \
    struct ospf6_lsa *lsa;                                            \
    for (lsa = ospf6_lsdb_head (lsdb); lsa;                           \
         lsa = ospf6_lsdb_next (lsa))                                 \
      {                                                               \
        if (lsa->header->adv_router != router)                        \
          continue;                                                   \
        (*(func)) (vty, lsa);                                         \
      }                                                               \
  } while (0)
#define LSDB_FOREACH_LSA_TI(vty, func, lsdb, type, id)                \
  do {                                                                \
    struct ospf6_lsa *lsa;                                            \
    for (lsa = ospf6_lsdb_type_head (type, lsdb); lsa;                \
         lsa = ospf6_lsdb_type_next (type, lsa))                      \
      {                                                               \
        if (lsa->header->id != id)                                    \
          continue;                                                   \
        (*(func)) (vty, lsa);                                         \
      }                                                               \
  } while (0)
#define LSDB_FOREACH_LSA_TR(vty, func, lsdb, type, router)            \
  do {                                                                \
    struct ospf6_lsa *lsa;                                            \
    for (lsa = ospf6_lsdb_type_router_head (type, router, lsdb); lsa; \
         lsa = ospf6_lsdb_type_router_next (type, router, lsa))       \
      {                                                               \
        (*(func)) (vty, lsa);                                         \
      }                                                               \
  } while (0)
#define LSDB_FOREACH_LSA_IR(vty, func, lsdb, id, router)              \
  do {                                                                \
    struct ospf6_lsa *lsa;                                            \
    for (lsa = ospf6_lsdb_head (lsdb); lsa;                           \
         lsa = ospf6_lsdb_next (lsa))                                 \
      {                                                               \
        if (lsa->header->adv_router != router)                        \
          continue;                                                   \
        if (lsa->header->id != id)                                    \
          continue;                                                   \
        (*(func)) (vty, lsa);                                         \
      }                                                               \
  } while (0)
#define LSDB_FOREACH_LSA_TIR(vty, func, lsdb, type, id, router)       \
  do {                                                                \
    struct ospf6_lsa *lsa;                                            \
    lsa = ospf6_lsdb_lookup (type, id, router, lsdb);                 \
    if (lsa)                                                          \
      (*(func)) (vty, lsa);                                           \
  } while (0)

#define OSPF6_LSDB_MAXAGE_REMOVER(lsdb)                                  \
  do {                                                                   \
    struct ospf6_lsa *lsa;                                               \
    for (lsa = ospf6_lsdb_head (lsdb); lsa; lsa = ospf6_lsdb_next (lsa)) \
      {                                                                  \
        if (! OSPF6_LSA_IS_MAXAGE (lsa))                                 \
          continue;                                                      \
        if (lsa->onretrans != 0)                                         \
          continue;                                                      \
        if (IS_OSPF6_DEBUG_LSA (TIMER))                                  \
          zlog_info (" remove maxage %s", lsa->name);                    \
        ospf6_lsdb_remove (lsa, lsdb);                                   \
      }                                                                  \
  } while (0)

/* Function Prototypes */
struct ospf6_lsdb *ospf6_lsdb_create ();
void ospf6_lsdb_delete (struct ospf6_lsdb *lsdb);

struct ospf6_lsa *ospf6_lsdb_lookup (u_int16_t type, u_int32_t id,
                                     u_int32_t adv_router,
                                     struct ospf6_lsdb *lsdb);

void ospf6_lsdb_add (struct ospf6_lsa *lsa, struct ospf6_lsdb *lsdb);
void ospf6_lsdb_remove (struct ospf6_lsa *lsa, struct ospf6_lsdb *lsdb);

struct ospf6_lsa *ospf6_lsdb_head (struct ospf6_lsdb *lsdb);
struct ospf6_lsa *ospf6_lsdb_next (struct ospf6_lsa *lsa);

struct ospf6_lsa *ospf6_lsdb_type_router_head (u_int16_t type,
                                               u_int32_t adv_router,
                                               struct ospf6_lsdb *lsdb);
struct ospf6_lsa *ospf6_lsdb_type_router_next (u_int16_t type,
                                               u_int32_t adv_router,
                                               struct ospf6_lsa *lsa);

struct ospf6_lsa *ospf6_lsdb_type_head (u_int16_t type,
                                        struct ospf6_lsdb *lsdb);
struct ospf6_lsa *ospf6_lsdb_type_next (u_int16_t type,
                                        struct ospf6_lsa *lsa);

void ospf6_lsdb_remove_all (struct ospf6_lsdb *lsdb);

int ospf6_lsdb_show (struct vty *vty, int argc, char **argv,
                     struct ospf6_lsdb *lsdb);

#if 0
void ospf6_lsdb_init ();
void ospf6_lsdb_remove_maxage (struct ospf6_lsdb *lsdb);
#endif

#endif /* OSPF6_LSDB_H */


