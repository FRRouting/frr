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

#include <zebra.h>

#include "log.h"
#include "thread.h"
#include "linklist.h"
#include "vty.h"

#include "ospf6d.h"
#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_message.h"
#include "ospf6_route.h"
#include "ospf6_spf.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"


void *
ospf6_get_lsa_scope (u_int16_t type, struct ospf6_neighbor *from)
{
  void *scope = NULL;

  if (from == NULL)
    return NULL;

  switch (OSPF6_LSA_SCOPE (type))
    {
      case OSPF6_LSA_SCOPE_AS:
        scope = (from)->ospf6_if->area->ospf6;
        break;
      case OSPF6_LSA_SCOPE_AREA:
        scope = (from)->ospf6_if->area;
        break;
      case OSPF6_LSA_SCOPE_LINKLOCAL:
        scope = (from)->ospf6_if;
        break;
      default:
        break;
    }

  return scope;
}

struct ospf6_lsdb *
ospf6_get_scoped_lsdb (u_int16_t type, void *scope)
{
  struct ospf6_lsdb *lsdb = NULL;

  if (scope == NULL)
    return NULL;

  switch (OSPF6_LSA_SCOPE (type))
    {
      case OSPF6_LSA_SCOPE_AS:
        lsdb = ((struct ospf6 *)(scope))->lsdb;
        break;
      case OSPF6_LSA_SCOPE_AREA:
        lsdb = ((struct ospf6_area *)(scope))->lsdb;
        break;
      case OSPF6_LSA_SCOPE_LINKLOCAL:
        lsdb = ((struct ospf6_interface *)(scope))->lsdb;
        break;
      default:
        break;
    }

  return lsdb;
}

void
ospf6_flood_clear (struct ospf6_lsa *lsa)
{
  struct ospf6_neighbor *on;
  struct ospf6_interface *oi, *ospf6_if = NULL;
  struct ospf6_area *oa, *area = NULL;
  struct ospf6 *ospf6 = NULL;
  u_int16_t scope_type;
  list scoped_interfaces;
  struct ospf6_lsa *rxmt;
  listnode i, j;

  scoped_interfaces = list_new ();
  scope_type = OSPF6_LSA_SCOPE (lsa->header->type);

  if (scope_type == OSPF6_LSA_SCOPE_LINKLOCAL)
    {
      ospf6_if = (struct ospf6_interface *) lsa->scope;
      area = ospf6_if->area;
      ospf6 = area->ospf6;
    }
  else if (scope_type == OSPF6_LSA_SCOPE_AREA)
    {
      area = (struct ospf6_area *) lsa->scope;
      ospf6 = area->ospf6;
    }
  else if (scope_type == OSPF6_LSA_SCOPE_AS)
    {
      ospf6 = (struct ospf6 *) lsa->scope;
    }
  else
    {
      zlog_warn ("Can't decide LSA scope, quit ospf6_flood_clear ()");
      return;
    }

  /* Collect eligible interfaces */
  for (i = listhead (ospf6->area_list); i; nextnode (i))
    {
      oa = (struct ospf6_area *) getdata (i);
      if (scope_type != OSPF6_LSA_SCOPE_AS && oa != area)
        continue;

      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          oi = (struct ospf6_interface *) getdata (j);
          if (scope_type != OSPF6_LSA_SCOPE_AS &&
              scope_type != OSPF6_LSA_SCOPE_AREA && oi != ospf6_if)
            continue;

          listnode_add (scoped_interfaces, oi);
        }
    }

  for (i = listhead (scoped_interfaces); i; nextnode (i))
    {
      oi = (struct ospf6_interface *) getdata (i);
      for (j = listhead (oi->neighbor_list); j; nextnode (j))
        {
          on = (struct ospf6_neighbor *) getdata (j);
          rxmt = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                                    lsa->header->adv_router, on->retrans_list);
          if (rxmt && ! ospf6_lsa_compare (rxmt, lsa))
            {
              if (IS_OSPF6_DEBUG_LSA (DATABASE))
                zlog_info ("Remove %s from retrans_list of %s",
                           rxmt->name, on->name);
              ospf6_lsdb_remove (rxmt, on->retrans_list);
            }
        }
    }

  list_delete (scoped_interfaces);
}

/* RFC2328 section 13.2 Installing LSAs in the database */
void
ospf6_install_lsa (struct ospf6_lsa *lsa, struct ospf6_lsdb *lsdb)
{
  struct ospf6_lsa *old;

  if (IS_OSPF6_DEBUG_LSA (RECV) || IS_OSPF6_DEBUG_LSA (DATABASE))
    zlog_info ("Install LSA: %s", lsa->name);

  /* Remove the old instance from all neighbors' Link state
     retransmission list (RFC2328 13.2 last paragraph) */
  old = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                           lsa->header->adv_router, lsdb);
  if (old)
    ospf6_flood_clear (old);

  /* actually install */
  gettimeofday (&lsa->installed, (struct timezone *) NULL);
  ospf6_lsdb_add (lsa, lsdb);

  return;
}

/* RFC2328 section 13.3 Next step in the flooding procedure */
void
ospf6_flood_lsa (struct ospf6_lsa *lsa, struct ospf6_neighbor *from)
{
  struct ospf6 *scope_as = NULL;
  struct ospf6_area *oa, *scope_area = NULL;
  struct ospf6_interface *oi, *scope_linklocal = NULL;
  struct ospf6_neighbor *on;
  list eligible_interfaces;
  listnode i, j;
  u_int16_t scope_type;
  struct ospf6_lsa *req;
  int retrans_added = 0;

  scope_type = OSPF6_LSA_SCOPE (lsa->header->type);
  switch (scope_type)
    {
      case OSPF6_LSA_SCOPE_AS:
        scope_as = (struct ospf6 *) lsa->scope;
        break;
      case OSPF6_LSA_SCOPE_AREA:
        scope_as = ((struct ospf6_area *) lsa->scope)->ospf6;
        scope_area = (struct ospf6_area *) lsa->scope;
        break;
      case OSPF6_LSA_SCOPE_LINKLOCAL:
        scope_as = ((struct ospf6_interface *) lsa->scope)->area->ospf6;
        scope_area = ((struct ospf6_interface *) lsa->scope)->area;
        scope_linklocal = (struct ospf6_interface *) lsa->scope;
        break;
      default:
        if (IS_OSPF6_DEBUG_LSA (SEND))
          zlog_info ("Can't decide LSA scope");
        return;
    }

  if (IS_OSPF6_DEBUG_LSA (SEND))
    zlog_info ("Flood %s", lsa->name);

  /* Collect eligible interfaces */
  eligible_interfaces = list_new ();
  for (i = listhead (scope_as->area_list); i; nextnode (i))
    {
      oa = (struct ospf6_area *) getdata (i);
      if (scope_type != OSPF6_LSA_SCOPE_AS &&
          oa != scope_area)
        continue;

      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          oi = (struct ospf6_interface *) getdata (j);
          if (scope_type != OSPF6_LSA_SCOPE_AS &&
              scope_type != OSPF6_LSA_SCOPE_AREA &&
              oi != scope_linklocal)
            continue;

          listnode_add (eligible_interfaces, oi);
        }
    }

  /* For each eligible interface: */
  for (i = listhead (eligible_interfaces); i; nextnode (i))
    {
      oi = (struct ospf6_interface *) getdata (i);

      /* (1) For each neighbor */
      for (j = listhead (oi->neighbor_list); j; nextnode (j))
        {
          on = (struct ospf6_neighbor *) getdata (j);

          /* (a) if neighbor state < Exchange, examin next */
          if (on->state < OSPF6_NEIGHBOR_EXCHANGE)
            continue;

          /* (b) if neighbor not yet Full, check request-list */
          if (on->state != OSPF6_NEIGHBOR_FULL)
            {
              req = ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                                       lsa->header->adv_router,
                                       on->request_list);
              if (req)
                {
                  /* If new LSA less recent, examin next neighbor */
                  if (ospf6_lsa_compare (lsa, req) > 0)
                    continue;

                  /* If the same instance, delete from request-list and
                     examin next neighbor */
                  if (ospf6_lsa_compare (lsa, req) == 0)
                    {
                      if (IS_OSPF6_DEBUG_LSA (SEND) || IS_OSPF6_DEBUG_LSA (DATABASE))
                        zlog_info ("Remove %s from request-list of %s: "
                                   "the same instance", req->name, on->name);
                      ospf6_lsdb_remove (req, on->request_list);
                      continue;
                    }

                  /* If the new LSA is more recent, delete from
                     request-list */
                  if (ospf6_lsa_compare (lsa, req) < 0)
                    {
                      if (IS_OSPF6_DEBUG_LSA (SEND) || IS_OSPF6_DEBUG_LSA (DATABASE))
                        zlog_info ("Remove %s from request-list of %s: "
                                   "newer instance", req->name, on->name);
                      ospf6_lsdb_remove (req, on->request_list);
                      /* fall through */
                    }
                }
            }

          /* (c) If the new LSA was received from this neighbor,
             examin next neighbor */
          if (from == on)
            continue;

          /* (d) add retrans-list, schedule retransmission */
          if (IS_OSPF6_DEBUG_LSA (SEND) || IS_OSPF6_DEBUG_LSA (DATABASE))
            zlog_info ("  Add copy of %s to retrans-list of %s",
                       lsa->name, on->name);
          ospf6_lsdb_add (ospf6_lsa_copy (lsa), on->retrans_list);
          if (on->thread_send_lsupdate == NULL)
            on->thread_send_lsupdate =
              thread_add_event (master, ospf6_lsupdate_send_neighbor,
                                on, on->ospf6_if->rxmt_interval);
          retrans_added++;
        }

      /* (2) examin next interface if not added to retrans-list */
      if (retrans_added == 0)
        continue;

      /* (3) If the new LSA was received on this interface,
         and it was from DR or BDR, examin next interface */
      if (from && from->ospf6_if == oi &&
          (from->router_id == oi->drouter || from->router_id == oi->bdrouter))
        continue;

      /* (4) If the new LSA was received on this interface,
         and the interface state is BDR, examin next interface */
      if (from && from->ospf6_if == oi && oi->state == OSPF6_INTERFACE_BDR)
        continue;

      /* (5) flood the LSA out the interface. */
      if (if_is_broadcast (oi->interface))
        {
          if (IS_OSPF6_DEBUG_LSA (SEND) || IS_OSPF6_DEBUG_LSA (DATABASE))
            zlog_info ("  Add copy of %s to lsupdate_list of %s",
                       lsa->name, oi->interface->name);
          ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsupdate_list);
          if (oi->thread_send_lsupdate == NULL)
            oi->thread_send_lsupdate =
              thread_add_event (master, ospf6_lsupdate_send_interface, oi, 0);
        }
      else
        {
          for (j = listhead (oi->neighbor_list); j; nextnode (j))
            {
              on = (struct ospf6_neighbor *) getdata (j);
              THREAD_OFF (on->thread_send_lsupdate);
              on->thread_send_lsupdate =
                thread_add_event (master, ospf6_lsupdate_send_neighbor, on, 0);
            }
        }
    }

  list_delete (eligible_interfaces);
}

/* RFC2328 13.5 (Table 19): Sending link state acknowledgements. */
static void
ospf6_acknowledge_lsa_bdrouter (struct ospf6_lsa *lsa, int ismore_recent,
                                struct ospf6_neighbor *from)
{
  struct ospf6_interface *oi;

  assert (from && from->ospf6_if);
  oi = from->ospf6_if;

  /* LSA has been flood back out receiving interface.
     No acknowledgement sent. */
  if (CHECK_FLAG (lsa->flag, OSPF6_LSA_FLOODBACK))
    {
      if (IS_OSPF6_DEBUG_LSA (RECV))
        zlog_info ("  BDR, FloodBack, No acknowledgement.");
      return;
    }

  /* LSA is more recent than database copy, but was not flooded
     back out receiving interface. Delayed acknowledgement sent
     if advertisement received from Designated Router,
     otherwide do nothing. */
  if (ismore_recent < 0)
    {
      if (IS_OSPF6_DEBUG_LSA (RECV))
        zlog_info ("  BDR, Not FloodBack, MoreRecent, ");
      if (oi->drouter == from->router_id)
        {
          if (IS_OSPF6_DEBUG_LSA (RECV))
            zlog_info ("       From DR, Delayed acknowledgement.");
          /* Delayed acknowledgement */
          if (IS_OSPF6_DEBUG_LSA (DATABASE))
            zlog_info ("  Add copy of %s to lsack_list of %s",
                       lsa->name, oi->interface->name);
          ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsack_list);
          if (oi->thread_send_lsack == NULL)
            oi->thread_send_lsack =
              thread_add_timer (master, ospf6_lsack_send_interface, oi, 3);
        }
      else
        {
          if (IS_OSPF6_DEBUG_LSA (RECV))
            zlog_info ("       Not From DR, No acknowledgement.");
        }
      return;
    }

  /* LSA is a duplicate, and was treated as an implied acknowledgement.
     Delayed acknowledgement sent if advertisement received from
     Designated Router, otherwise do nothing */
  if (CHECK_FLAG (lsa->flag, OSPF6_LSA_DUPLICATE) &&
      CHECK_FLAG (lsa->flag, OSPF6_LSA_IMPLIEDACK))
    {
      if (IS_OSPF6_DEBUG_LSA (RECV))
        zlog_info ("  BDR, Duplicate, ImpliedAck, ");
      if (oi->drouter == from->router_id)
        {
          if (IS_OSPF6_DEBUG_LSA (RECV))
            zlog_info ("       From DR, Delayed acknowledgement.");
          /* Delayed acknowledgement */
          if (IS_OSPF6_DEBUG_LSA (DATABASE))
            zlog_info ("  Add copy of %s to lsack_list of %s",
                       lsa->name, oi->interface->name);
          ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsack_list);
          if (oi->thread_send_lsack == NULL)
            oi->thread_send_lsack =
              thread_add_timer (master, ospf6_lsack_send_interface, oi, 3);
        }
      else
        {
          if (IS_OSPF6_DEBUG_LSA (RECV))
            zlog_info ("       Not From DR, No acknowledgement.");
        }
      return;
    }

  /* LSA is a duplicate, and was not treated as an implied acknowledgement.
     Direct acknowledgement sent */
  if (CHECK_FLAG (lsa->flag, OSPF6_LSA_DUPLICATE) &&
      ! CHECK_FLAG (lsa->flag, OSPF6_LSA_IMPLIEDACK))
    {
      if (IS_OSPF6_DEBUG_LSA (RECV))
        zlog_info ("  BDR, Duplicate, Not ImpliedAck, Direct acknowledgement.");
      if (IS_OSPF6_DEBUG_LSA (DATABASE))
        zlog_info ("  Add copy of %s to lsack_list of %s",
                   lsa->name, from->name);
      ospf6_lsdb_add (ospf6_lsa_copy (lsa), from->lsack_list);
      if (from->thread_send_lsack == NULL)
        from->thread_send_lsack =
          thread_add_event (master, ospf6_lsack_send_neighbor, from, 0);
      return;
    }

  /* LSA's LS age is equal to Maxage, and there is no current instance
     of the LSA in the link state database, and none of router's
     neighbors are in states Exchange or Loading */
  /* Direct acknowledgement sent, but this case is handled in
     early of ospf6_receive_lsa () */
}

static void
ospf6_acknowledge_lsa_allother (struct ospf6_lsa *lsa, int ismore_recent,
                                struct ospf6_neighbor *from)
{
  struct ospf6_interface *oi;

  assert (from && from->ospf6_if);
  oi = from->ospf6_if;

  /* LSA has been flood back out receiving interface.
     No acknowledgement sent. */
  if (CHECK_FLAG (lsa->flag, OSPF6_LSA_FLOODBACK))
    {
      if (IS_OSPF6_DEBUG_LSA (RECV))
        zlog_info ("  AllOther, FloodBack, No acknowledgement.");
      return;
    }

  /* LSA is more recent than database copy, but was not flooded
     back out receiving interface. Delayed acknowledgement sent. */
  if (ismore_recent < 0)
    {
      if (IS_OSPF6_DEBUG_LSA (RECV))
        zlog_info ("  AllOther, Not FloodBack, Delayed acknowledgement.");
      /* Delayed acknowledgement */
      if (IS_OSPF6_DEBUG_LSA (DATABASE))
        zlog_info ("  Add copy of %s to lsack_list of %s",
                   lsa->name, oi->interface->name);
      ospf6_lsdb_add (ospf6_lsa_copy (lsa), oi->lsack_list);
      if (oi->thread_send_lsack == NULL)
        oi->thread_send_lsack =
          thread_add_timer (master, ospf6_lsack_send_interface, oi, 3);
      return;
    }

  /* LSA is a duplicate, and was treated as an implied acknowledgement.
     No acknowledgement sent. */
  if (CHECK_FLAG (lsa->flag, OSPF6_LSA_DUPLICATE) &&
      CHECK_FLAG (lsa->flag, OSPF6_LSA_IMPLIEDACK))
    {
      if (IS_OSPF6_DEBUG_LSA (RECV))
        zlog_info ("  AllOther, Duplicate, ImpliedAck, No acknowledgement.");
      return;
    }

  /* LSA is a duplicate, and was not treated as an implied acknowledgement.
     Direct acknowledgement sent */
  if (CHECK_FLAG (lsa->flag, OSPF6_LSA_DUPLICATE) &&
      ! CHECK_FLAG (lsa->flag, OSPF6_LSA_IMPLIEDACK))
    {
      if (IS_OSPF6_DEBUG_LSA (RECV))
        zlog_info ("  AllOther, Duplicate, Not ImpliedAck, Direct acknowledgement.");
      if (IS_OSPF6_DEBUG_LSA (DATABASE))
        zlog_info ("  Add copy of %s to lsack_list of %s",
                   lsa->name, from->name);
      ospf6_lsdb_add (ospf6_lsa_copy (lsa), from->lsack_list);
      if (from->thread_send_lsack == NULL)
        from->thread_send_lsack =
          thread_add_event (master, ospf6_lsack_send_neighbor, from, 0);
      return;
    }

  /* LSA's LS age is equal to Maxage, and there is no current instance
     of the LSA in the link state database, and none of router's
     neighbors are in states Exchange or Loading */
  /* Direct acknowledgement sent, but this case is handled in
     early of ospf6_receive_lsa () */
}

void
ospf6_acknowledge_lsa (struct ospf6_lsa *lsa, int ismore_recent,
                       struct ospf6_neighbor *from)
{
  struct ospf6_interface *oi;

  assert (from && from->ospf6_if);
  oi = from->ospf6_if;

  if (oi->state == OSPF6_INTERFACE_BDR)
    ospf6_acknowledge_lsa_bdrouter (lsa, ismore_recent, from);
  else
    ospf6_acknowledge_lsa_allother (lsa, ismore_recent, from);
}

/* RFC2328 section 13 (4):
   if MaxAge LSA and if we have no instance, and no neighbor
   is in states Exchange or Loading
   returns 1 if match this case, else returns 0 */
static int
ospf6_is_maxage_lsa_drop (struct ospf6_lsa *lsa,
                          struct ospf6_neighbor *from)
{
  struct ospf6_lsdb *lsdb = NULL;
  struct ospf6_neighbor *on;
  struct ospf6_interface *oi, *ospf6_if = NULL;
  struct ospf6_area *oa, *area = NULL;
  struct ospf6 *ospf6 = NULL;
  u_int16_t scope_type;
  list scoped_interfaces;
  listnode i, j;
  int count = 0;

  if (! OSPF6_LSA_IS_MAXAGE (lsa))
    return 0;

  lsdb = ospf6_get_scoped_lsdb (lsa->header->type, lsa->scope);
  if (lsdb == NULL)
    {
      zlog_info ("Can't decide scoped LSDB");
      return 0;
    }

  if (ospf6_lsdb_lookup (lsa->header->type, lsa->header->id,
                         lsa->header->adv_router, lsdb))
    return 0;

  scoped_interfaces = list_new ();
  scope_type = OSPF6_LSA_SCOPE (lsa->header->type);

  if (scope_type == OSPF6_LSA_SCOPE_LINKLOCAL)
    {
      ospf6_if = (struct ospf6_interface *) lsa->scope;
      area = ospf6_if->area;
      ospf6 = area->ospf6;
    }
  else if (scope_type == OSPF6_LSA_SCOPE_AREA)
    {
      area = (struct ospf6_area *) lsa->scope;
      ospf6 = area->ospf6;
    }
  else if (scope_type == OSPF6_LSA_SCOPE_AS)
    {
      ospf6 = (struct ospf6 *) lsa->scope;
    }
  else
    {
      zlog_info ("Can't decide LSA scope");
      return 0;
    }

  /* Collect eligible interfaces */
  for (i = listhead (ospf6->area_list); i; nextnode (i))
    {
      oa = (struct ospf6_area *) getdata (i);
      if (scope_type != OSPF6_LSA_SCOPE_AS && oa != area)
        continue;

      for (j = listhead (oa->if_list); j; nextnode (j))
        {
          oi = (struct ospf6_interface *) getdata (j);
          if (scope_type != OSPF6_LSA_SCOPE_AS &&
              scope_type != OSPF6_LSA_SCOPE_AREA && oi != ospf6_if)
            continue;

          listnode_add (scoped_interfaces, oi);
        }
    }

  for (i = listhead (scoped_interfaces); i; nextnode (i))
    {
      oi = (struct ospf6_interface *) getdata (i);
      for (j = listhead (oi->neighbor_list); j; nextnode (j))
        {
          on = (struct ospf6_neighbor *) getdata (j);
          if (on->state == OSPF6_NEIGHBOR_EXCHANGE ||
              on->state == OSPF6_NEIGHBOR_LOADING)
            count ++;
        }
    }

  list_delete (scoped_interfaces);

  if (count == 0)
    return 1;

  return 0;
}

/* RFC2328 section 13 The Flooding Procedure */
void
ospf6_receive_lsa (struct ospf6_lsa_header *lsa_header,
                   struct ospf6_neighbor *from)
{
  struct ospf6_lsa *new = NULL, *old = NULL, *rem = NULL;
  int ismore_recent;
  unsigned short cksum;
  struct ospf6_lsdb *lsdb = NULL;

  ismore_recent = 1;

  /* make lsa structure for received lsa */
  new = ospf6_lsa_create (lsa_header);

  if (IS_OSPF6_DEBUG_LSA (RECV))
    {
      zlog_info ("LSA Receive from %s", from->name);
      ospf6_lsa_header_print (new);
    }

  new->scope = ospf6_get_lsa_scope (new->header->type, from);
  if (new->scope == NULL)
    {
      zlog_warn ("Can't decide LSA scope, ignore");
      ospf6_lsa_delete (new);
      return;
    }

  /* (1) LSA Checksum */
  cksum = ntohs (new->header->checksum);
  if (ntohs (ospf6_lsa_checksum (new->header)) != cksum)
    {
      if (IS_OSPF6_DEBUG_LSA (RECV))
        zlog_info ("Wrong LSA Checksum");
      ospf6_lsa_delete (new);
      return;
    }

  /* (3) Ebit Missmatch: AS-External-LSA */
  if (ntohs (new->header->type) == OSPF6_LSTYPE_AS_EXTERNAL &&
      ospf6_area_is_stub (from->ospf6_if->area))
    {
      if (IS_OSPF6_DEBUG_LSA (RECV))
        zlog_info ("AS-External-LSA in stub area");
      ospf6_lsa_delete (new);
      return;
    }

  /* (4) if MaxAge LSA and if we have no instance, and no neighbor
         is in states Exchange or Loading */
  if (ospf6_is_maxage_lsa_drop (new, from))
    {
      /* log */
      if (IS_OSPF6_DEBUG_LSA (RECV))
        zlog_info ("Drop MaxAge LSA with Direct acknowledgement.");

      /* a) Acknowledge back to neighbor (Direct acknowledgement, 13.5) */
      if (IS_OSPF6_DEBUG_LSA (DATABASE))
        zlog_info ("  Add %s to lsack_list of %s",
                   new->name, from->name);
      ospf6_lsdb_add (new, from->lsack_list);
      if (from->thread_send_lsack == NULL)
        from->thread_send_lsack =
          thread_add_event (master, ospf6_lsack_send_neighbor, from, 0);

      /* b) Discard */
      /* "new" LSA will be discarded just after the LSAck sent */
      return;
    }

  /* (5) */
  /* lookup the same database copy in lsdb */
  lsdb = ospf6_get_scoped_lsdb (new->header->type, new->scope);
  if (lsdb == NULL)
    {
      zlog_warn ("Can't decide scoped LSDB, ignore");
      ospf6_lsa_delete (new);
      return;
    }

  old = ospf6_lsdb_lookup (new->header->type, new->header->id,
                           new->header->adv_router, lsdb);
  if (old)
    {
      ismore_recent = ospf6_lsa_compare (new, old);
      if (ntohl (new->header->seqnum) == ntohl (old->header->seqnum))
        {
          if (IS_OSPF6_DEBUG_LSA (RECV))
            zlog_info ("Duplicated LSA");
          SET_FLAG (new->flag, OSPF6_LSA_DUPLICATE);
        }
    }

  /* if no database copy or received is more recent */
  if (old == NULL || ismore_recent < 0)
    {
      /* in case we have no database copy */
      ismore_recent = -1;

      /* (a) MinLSArrival check */
      if (old)
        {
          struct timeval now, res;
          gettimeofday (&now, (struct timezone *) NULL);
          timersub (&now, &old->installed, &res);
          if (res.tv_sec < MIN_LS_ARRIVAL)
            {
              if (IS_OSPF6_DEBUG_LSA (RECV) || IS_OSPF6_DEBUG_LSA (TIMER))
                zlog_info ("LSA can't be updated within MinLSArrival");
              ospf6_lsa_delete (new);
              return;   /* examin next lsa */
            }
        }

      /* (b) immediately flood and (c) remove from all retrans-list */
      ospf6_flood_lsa (new, from);

      /* (d), installing lsdb, which may cause routing
              table calculation (replacing database copy) */
      ospf6_install_lsa (new, lsdb);

      /* (e) possibly acknowledge */
      ospf6_acknowledge_lsa (new, ismore_recent, from);

      /* (f) */
      /* Self Originated LSA, section 13.4 */
      if (new->header->adv_router == from->ospf6_if->area->ospf6->router_id
          && (! old || ismore_recent < 0))
        {
          /* We have to make a new instance of the LSA
             or have to flush this LSA. */
          if (IS_OSPF6_DEBUG_LSA (RECV))
            zlog_info ("New instance of the self-originated LSA");

          SET_FLAG (new->flag, OSPF6_LSA_REFRESH);
          ospf6_lsa_re_originate (new);
        }
      return;
    }

  /* (6) if there is instance on sending neighbor's request list */
  if (ospf6_lsdb_lookup (new->header->type, new->header->id,
                         new->header->adv_router, from->request_list))
    {
      /* if no database copy, should go above state (5) */
      assert (old);

      if (IS_OSPF6_DEBUG_LSA (RECV))
        zlog_info ("LSA is not newer and on request-list of sending neighbor");

      /* BadLSReq */
      thread_add_event (master, bad_lsreq, from, 0);

      ospf6_lsa_delete (new);
      return;
    }

  /* (7) if neither one is more recent */
  if (ismore_recent == 0)
    {
      if (IS_OSPF6_DEBUG_LSA (RECV))
        zlog_info ("The same instance as database copy");

      /* (a) if on retrans-list, Treat this LSA as an Ack: Implied Ack */
      rem = ospf6_lsdb_lookup (new->header->type, new->header->id,
                               new->header->adv_router, from->retrans_list);
      if (rem)
        {
          if (IS_OSPF6_DEBUG_LSA (RECV))
            zlog_info ("Treat as an Implied acknowledgement");
          SET_FLAG (new->flag, OSPF6_LSA_IMPLIEDACK);
          if (IS_OSPF6_DEBUG_LSA (DATABASE))
            zlog_info ("Remove %s from retrans_list of %s",
                       rem->name, from->name);
          ospf6_lsdb_remove (rem, from->retrans_list);
        }

      /* (b) possibly acknowledge */
      ospf6_acknowledge_lsa (new, ismore_recent, from);

      ospf6_lsa_delete (new);
      return;
    }

  /* (8) previous database copy is more recent */
    {
      assert (old);

      /* If database copy is in 'Seqnumber Wrapping',
         simply discard the received LSA */
      if (OSPF6_LSA_IS_MAXAGE (old) &&
          old->header->seqnum == htonl (MAX_SEQUENCE_NUMBER))
        {
          if (IS_OSPF6_DEBUG_LSA (RECV))
            zlog_info ("Database copy is in Seqnumber Wrapping");
          ospf6_lsa_delete (new);
          return;
        }

      /* Otherwise, Send database copy of this LSA to this neighbor */
        {
          if (IS_OSPF6_DEBUG_LSA (RECV))
            zlog_info ("Database is more recent, send back directly");

          /* XXX, MinLSArrival check !? RFC 2328 13 (8) */

          if (IS_OSPF6_DEBUG_LSA (DATABASE))
            zlog_info ("  Add copy of %s to lsupdate_list of %s",
                       old->name, from->name);
          ospf6_lsdb_add (ospf6_lsa_copy (old), from->lsupdate_list);
          if (from->thread_send_lsupdate == NULL)
            from->thread_send_lsupdate =
              thread_add_event (master, ospf6_lsupdate_send_neighbor, from, 0);
          ospf6_lsa_delete (new);
          return;
        }
      return;
    }
}



