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

/* check validity and put lsa in reqestlist if needed. */
/* returns -1 if SeqNumMismatch required. */
int
ospf6_dbex_check_dbdesc_lsa_header (struct ospf6_lsa_header *lsa_header,
                                    struct ospf6_neighbor *from)
{
  struct ospf6_lsa *received = NULL;
  struct ospf6_lsa *have = NULL;

  received = ospf6_lsa_summary_create
    ((struct ospf6_lsa_header__ *) lsa_header);

  /* case when received is AS-External though neighbor belongs stub area */
  if (lsa_header->type == htons (OSPF6_LSA_TYPE_AS_EXTERNAL) &&
      ospf6_area_is_stub (from->ospf6_interface->area))
    {
      zlog_err ("DbDesc %s receive from %s", from->str, received->str);
      zlog_err ("    E-bit mismatch: %s", received->str);
      ospf6_lsa_delete (received);
      return -1;
    }

  /* if already have newer database copy, check next LSA */
  have = ospf6_lsdb_lookup (lsa_header->type, lsa_header->ls_id,
                            lsa_header->advrtr,
                            ospf6_lsa_get_scope (lsa_header->type,
                                                 from->ospf6_interface));
  if (! have)
    {
      /* if we don't have database copy, add request */
      if (IS_OSPF6_DUMP_DBEX)
        zlog_info ("Have no database copy, Request");
      ospf6_neighbor_request_add (received, from);
    }
  else if (have)
    {
      /* if database copy is less recent, add request */
      if (ospf6_lsa_check_recent (received, have) < 0)
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("Database copy less recent, Request");
          ospf6_neighbor_request_add (received, from);
        }
    }

  return 0;
}

/* Direct acknowledgement */
static void
ospf6_dbex_acknowledge_direct (struct ospf6_lsa *lsa,
                               struct ospf6_neighbor *o6n)
{
  struct iovec directack[MAXIOVLIST];
  assert (lsa);

  if (IS_OSPF6_DUMP_DBEX)
    zlog_info ("DBEX: [%s:%s] direct ack %s ",
               o6n->str, o6n->ospf6_interface->interface->name,
               lsa->str);

  /* clear pointers to fragments of packet for direct acknowledgement */
  iov_clear (directack, MAXIOVLIST);

  /* set pointer of LSA to send */
  OSPF6_MESSAGE_ATTACH (directack, lsa->header,
                        sizeof (struct ospf6_lsa_header));

  /* age update and add InfTransDelay */
  ospf6_lsa_age_update_to_send (lsa, o6n->ospf6_interface->transdelay);

  /* send unicast packet to neighbor's ipaddress */
  ospf6_message_send (OSPF6_MESSAGE_TYPE_LSACK, directack, &o6n->hisaddr,
                      o6n->ospf6_interface->if_id);
}

/* Delayed  acknowledgement */
void
ospf6_dbex_acknowledge_delayed (struct ospf6_lsa *lsa,
                                struct ospf6_interface *o6i)
{
  assert (o6i);

  if (IS_OSPF6_DUMP_DBEX)
    zlog_info ("DBEX: [%s] delayed ack %s", o6i->interface->name, lsa->str);

  /* attach delayed acknowledge list */
  ospf6_lsa_age_current (lsa);
  ospf6_interface_delayed_ack_add (lsa, o6i);

  /* if not yet, schedule delayed acknowledge RxmtInterval later.
     timers should be *less than* RxmtInterval
     or needless retrans will ensue */
  if (o6i->thread_send_lsack_delayed == NULL)
    o6i->thread_send_lsack_delayed
      = thread_add_timer (master, ospf6_send_lsack_delayed,
                          o6i, o6i->rxmt_interval - 1);

  return;
}

/* RFC2328 section 13 (4):
   if MaxAge LSA and if we have no instance, and no neighbor
   is in states Exchange or Loading */
/* returns 1 if match this case, else returns 0 */
static int
ospf6_dbex_is_maxage_to_be_dropped (struct ospf6_lsa *received,
                                    struct ospf6_neighbor *from)
{
  int count;

  if (! IS_LSA_MAXAGE (received))
    return 0;

  if (ospf6_lsdb_lookup (received->header->type, received->header->id,
                         received->header->adv_router,
                         ospf6_lsa_get_scope (received->header->type,
                                              from->ospf6_interface)))
    return 0;

  if (OSPF6_LSA_IS_SCOPE_LINKLOCAL (ntohs (received->header->type)))
    {
      count = 0;
      (*from->ospf6_interface->foreach_nei)
        (from->ospf6_interface, &count, NBS_EXCHANGE, ospf6_count_state);
      (*from->ospf6_interface->foreach_nei)
        (from->ospf6_interface, &count, NBS_LOADING, ospf6_count_state);
      if (count)
        return 0;
    }
  else if (OSPF6_LSA_IS_SCOPE_AREA (ntohs (received->header->type)))
    {
      count = 0;
      (*from->ospf6_interface->area->foreach_nei)
         (from->ospf6_interface->area, &count, NBS_EXCHANGE, ospf6_count_state);
      (*from->ospf6_interface->area->foreach_nei)
         (from->ospf6_interface->area, &count, NBS_LOADING, ospf6_count_state);
      if (count)
        return 0;
    }
  else if (OSPF6_LSA_IS_SCOPE_AS (ntohs (received->header->type)))
    {
      count = 0;
      (*from->ospf6_interface->area->ospf6->foreach_nei)
         (from->ospf6_interface->area->ospf6, &count, NBS_EXCHANGE,
          ospf6_count_state);
      (*from->ospf6_interface->area->ospf6->foreach_nei)
         (from->ospf6_interface->area->ospf6, &count, NBS_LOADING,
          ospf6_count_state);
      if (count)
        return 0;
    }

  return 1;
}

static void
ospf6_dbex_remove_retrans (void *arg, int val, void *obj)
{
  struct ospf6_lsa *rem;
  struct ospf6_neighbor *nei = (struct ospf6_neighbor *) obj;
  struct ospf6_lsa *lsa = (struct ospf6_lsa *) arg;

  rem = ospf6_lsdb_lookup_lsdb (lsa->header->type, lsa->header->id,
                                lsa->header->adv_router, nei->retrans_list);
  if (rem)
    {
      ospf6_neighbor_retrans_remove (rem, nei);
      ospf6_maxage_remover ();
    }
}

void
ospf6_dbex_remove_from_all_retrans_list (struct ospf6_lsa *lsa)
{
  struct ospf6_interface *o6i;
  struct ospf6_area *o6a;

  if (OSPF6_LSA_IS_SCOPE_LINKLOCAL (htons (lsa->header->type)))
    {
      o6i = lsa->scope;
      (*o6i->foreach_nei) (o6i, lsa, 0, ospf6_dbex_remove_retrans);
    }
  else if (OSPF6_LSA_IS_SCOPE_AREA (htons (lsa->header->type)))
    {
      o6a = lsa->scope;
      (*o6a->foreach_nei) (o6a, lsa, 0, ospf6_dbex_remove_retrans);
    }
  else if (OSPF6_LSA_IS_SCOPE_AS (htons (lsa->header->type)))
    {
      (*ospf6->foreach_nei) (ospf6, lsa, 0, ospf6_dbex_remove_retrans);
    }
}

/* RFC2328 section 13 */
void
ospf6_dbex_receive_lsa (struct ospf6_lsa_header *lsa_header,
                        struct ospf6_neighbor *from)
{
  struct ospf6_lsa *received, *have, *rem;
  struct timeval now;
  int ismore_recent, acktype;
  unsigned short cksum;
  struct ospf6_lsa_slot *slot;

  received = have = (struct ospf6_lsa *)NULL;
  ismore_recent = -1;
  recent_reason = "no instance";

  zlog_info ("Receive LSA (header -> %p)", lsa_header);

  /* make lsa structure for received lsa */
  received = ospf6_lsa_create (lsa_header);

  /* set LSA scope */
  if (OSPF6_LSA_IS_SCOPE_LINKLOCAL (htons (lsa_header->type)))
    received->scope = from->ospf6_interface;
  else if (OSPF6_LSA_IS_SCOPE_AREA (htons (lsa_header->type)))
    received->scope = from->ospf6_interface->area;
  else if (OSPF6_LSA_IS_SCOPE_AS (htons (lsa_header->type)))
    received->scope = from->ospf6_interface->area->ospf6;

  /* (1) LSA Checksum */
  cksum = ntohs (lsa_header->checksum);
  if (ntohs (ospf6_lsa_checksum (lsa_header)) != cksum)
    {
      if (IS_OSPF6_DUMP_DBEX)
        zlog_info ("DBEX: received %s from %s%%%s"
                   ": wrong checksum, drop",
                   received->str, from->str,
                   from->ospf6_interface->interface->name);
      ospf6_lsa_delete (received);
      return;
    }

  /* (3) Ebit Missmatch: AS-External-LSA */
  if (lsa_header->type == htons (OSPF6_LSA_TYPE_AS_EXTERNAL) &&
      ospf6_area_is_stub (from->ospf6_interface->area))
    {
      if (IS_OSPF6_DUMP_DBEX)
        zlog_info ("DBEX: received %s from %s%%%s"
                   ": E-bit mismatch, drop",
                   received->str, from->str,
                   from->ospf6_interface->interface->name);
      ospf6_lsa_delete (received);
      return;
    }

  /* (4) if MaxAge LSA and if we have no instance, and no neighbor
         is in states Exchange or Loading */
  if (ospf6_dbex_is_maxage_to_be_dropped (received, from))
    {
      /* log */
      if (IS_OSPF6_DUMP_DBEX)
        zlog_info ("DBEX: received %s from %s%%%s"
                   ": MaxAge, no instance, no neighbor exchange, drop",
                   received->str, from->str,
                   from->ospf6_interface->interface->name);

      /* a) Acknowledge back to neighbor (13.5) */
        /* Direct Acknowledgement */
      ospf6_dbex_acknowledge_direct (received, from);

      /* b) Discard */
      ospf6_lsa_delete (received);
      return;
    }

  /* (5) */
  /* lookup the same database copy in lsdb */
  have = ospf6_lsdb_lookup (lsa_header->type, lsa_header->ls_id,
                            lsa_header->advrtr,
                            ospf6_lsa_get_scope (lsa_header->type,
                                                 from->ospf6_interface));
  if (have)
    {
      ismore_recent = ospf6_lsa_check_recent (received, have);
      if (ntohl (received->header->seqnum) == ntohl (have->header->seqnum))
        SET_FLAG (received->flag, OSPF6_LSA_FLAG_DUPLICATE);
    }

  /* if no database copy or received is more recent */
  if (!have || ismore_recent < 0)
    {
      /* in case we have no database copy */
      ismore_recent = -1;

      /* (a) MinLSArrival check */
      gettimeofday (&now, (struct timezone *)NULL);
      if (have && SEC_TVDIFF (&now, &have->installed) < OSPF6_MIN_LS_ARRIVAL)
        {
          //if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("DBEX: Receive new LSA from %s: %s seq: %#x age: %d "
                       "within MinLSArrival, drop: %ld.%06ld",
                       from->str, received->str,
                       ntohl (received->header->seqnum),
                       ntohs (received->header->age),
                       now.tv_sec, now.tv_usec);

          /* this will do free this lsa */
          ospf6_lsa_delete (received);
          return;   /* examin next lsa */
        }

      //if (IS_OSPF6_DUMP_DBEX)
        zlog_info ("DBEX: Receive new LSA from %s: %s seq: %#x age: %d: "
                   "%ld.%06ld",
                   from->str, received->str,
                   ntohl (received->header->seqnum),
                   ntohs (received->header->age),
                   now.tv_sec, now.tv_usec);

      /* (b) immediately flood */
      ospf6_dbex_flood (received, from);

#if 0
      /* Because New LSDB do not permit two LSA having the same identifier
         exist in a LSDB list, above ospf6_dbex_flood() will remove
         the old instance automatically. thus bellow is not needed. */
      /* (c) remove database copy from all neighbor's retranslist */
      if (have)
        ospf6_dbex_remove_from_all_retrans_list (have);
#endif

      /* (d), installing lsdb, which may cause routing
              table calculation (replacing database copy) */
      ospf6_lsdb_install (received);

      /* (e) possibly acknowledge */
      acktype = ack_type (received, ismore_recent, from);
      if (acktype == DIRECT_ACK)
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("DBEX: Direct Ack to %s", from->str);
          ospf6_dbex_acknowledge_direct (received, from);
        }
      else if (acktype == DELAYED_ACK)
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("DBEX: Delayed Ack to %s", from->str);
          ospf6_dbex_acknowledge_delayed (received, from->ospf6_interface);
        }
      else
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("DBEX: No Ack to %s", from->str);
        }

      /* (f) */
      /* Self Originated LSA, section 13.4 */
      if (received->lsa_hdr->lsh_advrtr == ospf6->router_id
          && (! have || ismore_recent < 0))
        {
          /* we're going to make new lsa or to flush this LSA. */
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("DBEX: Self-originated LSA %s from %s:%s",
                       received->str, from->str,
                       from->ospf6_interface->interface->name);
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("DBEX: %s: Make new one/Flush", received->str);

          SET_FLAG (received->flag, OSPF6_LSA_FLAG_REFRESH);
          slot = ospf6_lsa_slot_get (received->header->type);
          if (slot && slot->func_refresh)
            {
              (*slot->func_refresh) (received);
              return;
            }

          zlog_warn ("Can't Refresh LSA: Unknown type: %#x, Flush",
                     ntohs (received->header->type));
          ospf6_lsa_premature_aging (received);
          return;
        }
    }
  else if (ospf6_lsdb_lookup_lsdb (received->header->type,
                                   received->header->id,
                                   received->header->adv_router,
                                   from->request_list))
    /* (6) if there is instance on sending neighbor's request list */
    {
      /* if no database copy, should go above state (5) */
      assert (have);

      zlog_warn ("DBEX: [%s:%s] received LSA %s is not newer,"
                 " and is on his requestlist: Generate BadLSReq",
                 from->str, from->ospf6_interface->interface->name,
                 received->str);

      /* BadLSReq */
      thread_add_event (master, bad_lsreq, from, 0);

      ospf6_lsa_delete (received);
    }
  else if (ismore_recent == 0) /* (7) if neither is more recent */
    {
      /* (a) if on retranslist, Treat this LSA as an Ack: Implied Ack */
      rem = ospf6_lsdb_lookup_lsdb (received->header->type,
                                    received->header->id,
                                    received->header->adv_router,
                                    from->retrans_list);
      if (rem)
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("DBEX: Implied Ack from %s, (remove retrans)",
                       from->str);
          SET_FLAG (received->flag, OSPF6_LSA_FLAG_IMPLIEDACK);
          ospf6_neighbor_retrans_remove (rem, from);
        }

      /* (b) possibly acknowledge */
      acktype = ack_type (received, ismore_recent, from);
      if (acktype == DIRECT_ACK)
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("DBEX: Direct Ack to %s", from->str);
          ospf6_dbex_acknowledge_direct (received, from);
        }
      else if (acktype == DELAYED_ACK)
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("DBEX: Delayed Ack to %s", from->str);
          ospf6_dbex_acknowledge_delayed (received, from->ospf6_interface);
        }
      else
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("DBEX: No Ack to %s", from->str);
        }
      ospf6_lsa_delete (received);
    }
  else /* (8) previous database copy is more recent */
    {
      /* If Seqnumber Wrapping, simply discard
         Otherwise, Send database copy of this LSA to this neighbor */
      if (! IS_LSA_MAXAGE (received) ||
          received->lsa_hdr->lsh_seqnum != MAX_SEQUENCE_NUMBER)
        {
          if (IS_OSPF6_DUMP_DBEX)
            zlog_info ("DBEX: database is more recent: send back to %s",
                       from->str);
          ospf6_send_lsupdate_direct (have, from);
        }
      ospf6_lsa_delete (received);
    }
}

/* RFC2328: Table 19: Sending link state acknowledgements. */
int 
ack_type (struct ospf6_lsa *newp, int ismore_recent,
          struct ospf6_neighbor *from)
{
  struct ospf6_interface *ospf6_interface;
  struct ospf6_lsa *have;
  int count;

  assert (from && from->ospf6_interface);
  ospf6_interface = from->ospf6_interface;

  if (CHECK_FLAG (newp->flag, OSPF6_LSA_FLAG_FLOODBACK))
    return NO_ACK;

  if (ismore_recent < 0)
    {
      if (ospf6_interface->state != IFS_BDR)
        return DELAYED_ACK;

      if (ospf6_interface->dr == from->router_id)
        return DELAYED_ACK;
      return NO_ACK;
    }

  if (CHECK_FLAG (newp->flag, OSPF6_LSA_FLAG_DUPLICATE) &&
      CHECK_FLAG (newp->flag, OSPF6_LSA_FLAG_IMPLIEDACK))
    {
      if (ospf6_interface->state != IFS_BDR)
        return NO_ACK;

      if (ospf6_interface->dr == from->router_id)
        return DELAYED_ACK;

      return NO_ACK;
    }

  if (CHECK_FLAG (newp->flag, OSPF6_LSA_FLAG_DUPLICATE) &&
      ! CHECK_FLAG (newp->flag, OSPF6_LSA_FLAG_IMPLIEDACK))
    return DIRECT_ACK;

  have = ospf6_lsdb_lookup (newp->header->type, newp->header->id,
                            newp->header->adv_router,
                            ospf6_lsa_get_scope (newp->header->type,
                                                 from->ospf6_interface));

  count = 0;
  ospf6->foreach_nei (ospf6, &count, NBS_EXCHANGE, ospf6_count_state);
  ospf6->foreach_nei (ospf6, &count, NBS_LOADING, ospf6_count_state);

  if (IS_LSA_MAXAGE (newp) && have == NULL && count == 0)
    return DIRECT_ACK;
 
  return NO_ACK;
}

static void
ospf6_dbex_flood_linklocal (struct ospf6_lsa *lsa, struct ospf6_interface *o6i,
                            struct ospf6_neighbor *from)
{
  struct ospf6_neighbor *o6n = (struct ospf6_neighbor *) NULL;
  int ismore_recent, addretrans = 0;
  listnode n;
  struct ospf6_lsa *req;

  /* (1) for each neighbor */
  for (n = listhead (o6i->neighbor_list); n; nextnode (n))
    {
      o6n = (struct ospf6_neighbor *) getdata (n);

      /* (a) */
      if (o6n->state < NBS_EXCHANGE)
        continue;  /* examin next neighbor */

      /* (b) */
      if (o6n->state == NBS_EXCHANGE
          || o6n->state == NBS_LOADING)
        {
          req = ospf6_lsdb_lookup_lsdb (lsa->header->type,
                                        lsa->header->id,
                                        lsa->header->adv_router,
                                        o6n->request_list);
          if (req)
            {
              ismore_recent = ospf6_lsa_check_recent (lsa, req);
              if (ismore_recent > 0)
                {
                  continue; /* examin next neighbor */
                }
              else if (ismore_recent == 0)
                {
                  ospf6_neighbor_request_remove (req, o6n);
                  continue; /* examin next neighbor */
                }
              else /* ismore_recent < 0 (the new LSA is more recent) */
                {
                  ospf6_neighbor_request_remove (req, o6n);
                }
            }
        }

      /* (c) */
      if (from && from->router_id == o6n->router_id)
        continue; /* examin next neighbor */

      /* (d) add retranslist */
      if (IS_OSPF6_DUMP_DBEX)
        zlog_info ("DBEX: schedule flooding [%s:%s]: %s",
                   o6n->str, o6n->ospf6_interface->interface->name,
                   lsa->str);
      ospf6_neighbor_retrans_add (lsa, o6n);
      addretrans++;
      if (o6n->send_update == (struct thread *) NULL)
        o6n->send_update =
          thread_add_timer (master, ospf6_send_lsupdate_rxmt, o6n,
                            o6n->ospf6_interface->rxmt_interval);
    }

  /* (2) */
  if (addretrans == 0)
    return; /* examin next interface */

  if (from && from->ospf6_interface == o6i)
    {
      if (IS_OSPF6_DUMP_DBEX)
        zlog_info ("DBEX: flood back %s to %s",
                   lsa->str, o6i->interface->name);
      /* note occurence of floodback */
      SET_FLAG (lsa->flag, OSPF6_LSA_FLAG_FLOODBACK);
    }

  /* (3) */
  if (from && from->ospf6_interface == o6i)
    {
      /* if from DR or BDR, don't need to flood this interface */
      if (from->router_id == from->ospf6_interface->dr ||
          from->router_id == from->ospf6_interface->bdr)
        return; /* examin next interface */
    }

  /* (4) if I'm BDR, DR will flood this interface */
  if (from && from->ospf6_interface == o6i
      && o6i->state == IFS_BDR)
    return; /* examin next interface */

  if (IS_OSPF6_DUMP_DBEX)
    zlog_info ("Flood to interface %s", o6i->interface->name);

  /* (5) send LinkState Update */
  ospf6_send_lsupdate_flood (lsa, o6i);

  return;
}

/* RFC2328 section 13.3 */
static void
ospf6_dbex_flood_area (struct ospf6_lsa *lsa, struct ospf6_area *area,
                       struct ospf6_neighbor *from)
{
  listnode n;
  struct ospf6_interface *ospf6_interface;

  assert (lsa && lsa->lsa_hdr && area);

  /* for each eligible ospf_ifs */
  for (n = listhead (area->if_list); n; nextnode (n))
    {
      ospf6_interface = (struct ospf6_interface *) getdata (n);
      ospf6_dbex_flood_linklocal (lsa, ospf6_interface, from);
    }
}

static void
ospf6_dbex_flood_as (struct ospf6_lsa *lsa, struct ospf6 *ospf6,
                     struct ospf6_neighbor *from)
{
  listnode n;
  struct ospf6_area *o6a;

  assert (lsa && lsa->lsa_hdr && ospf6);

  /* for each attached area */
  for (n = listhead (ospf6->area_list); n; nextnode (n))
    {
      o6a = (struct ospf6_area *) getdata (n);
      ospf6_dbex_flood_area (lsa, o6a, from);
    }
}

/* flood ospf6_lsa within appropriate scope */
void
ospf6_dbex_flood (struct ospf6_lsa *lsa, struct ospf6_neighbor *from)
{
  struct ospf6_area *o6a;
  struct ospf6_interface *o6i;
  struct ospf6 *o6;
  struct ospf6_lsa_header *lsa_header;

  lsa_header = (struct ospf6_lsa_header *) lsa->lsa_hdr;

  if (OSPF6_LSA_IS_SCOPE_LINKLOCAL (ntohs (lsa_header->type)))
    {
      o6i = (struct ospf6_interface *) lsa->scope;
      assert (o6i);

      if (IS_OSPF6_DUMP_DBEX)
        zlog_info ("Flood Linklocal: %s", o6i->interface->name);
      ospf6_dbex_flood_linklocal (lsa, o6i, from);
    }
  else if (OSPF6_LSA_IS_SCOPE_AREA (ntohs (lsa_header->type)))
    {
      o6a = (struct ospf6_area *) lsa->scope;
      assert (o6a);

      if (IS_OSPF6_DUMP_DBEX)
        zlog_info ("Flood Area: %s", o6a->str);
      ospf6_dbex_flood_area (lsa, o6a, from);
    }
  else if (OSPF6_LSA_IS_SCOPE_AS (ntohs (lsa_header->type)))
    {
      o6 = (struct ospf6 *) lsa->scope;
      assert (o6);

      if (IS_OSPF6_DUMP_DBEX)
        zlog_info ("Flood AS");
      ospf6_dbex_flood_as (lsa, o6, from);
    }
  else
    {
      zlog_warn ("Can't Flood %s: scope unknown", lsa->str);
    }
}


