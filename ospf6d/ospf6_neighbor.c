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

#include <zebra.h>

#include "log.h"
#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "command.h"

#include "ospf6_lsa.h"
#include "ospf6_message.h"
#include "ospf6_neighbor.h"
#include "ospf6_nsm.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"

char *ospf6_neighbor_state_string[] =
{
  "None", "Down", "Attempt", "Init", "Twoway",
  "ExStart", "ExChange", "Loading", "Full", NULL
};

int
ospf6_neighbor_last_dbdesc_release (struct thread *thread)
{
  struct ospf6_neighbor *o6n;

  o6n = (struct ospf6_neighbor *) THREAD_ARG (thread);
  assert (o6n);
  memset (&o6n->last_dd, 0, sizeof (struct ospf6_dbdesc));
  return 0;
}



void
ospf6_neighbor_thread_cancel_all (struct ospf6_neighbor *o6n)
{
  if (o6n->inactivity_timer)
    thread_cancel (o6n->inactivity_timer);
  o6n->inactivity_timer = (struct thread *) NULL;

  if (o6n->send_update)
    thread_cancel (o6n->send_update);
  o6n->send_update = (struct thread *) NULL;

  if (o6n->thread_send_dbdesc)
    thread_cancel (o6n->thread_send_dbdesc);
  o6n->thread_send_dbdesc = (struct thread *) NULL;
  if (o6n->thread_rxmt_dbdesc)
    thread_cancel (o6n->thread_rxmt_dbdesc);
  o6n->thread_rxmt_dbdesc = (struct thread *) NULL;

  if (o6n->thread_rxmt_lsreq)
    thread_cancel (o6n->thread_rxmt_lsreq);
  o6n->thread_rxmt_lsreq = (struct thread *) NULL;
}

void
ospf6_neighbor_lslist_clear (struct ospf6_neighbor *nei)
{
  ospf6_lsdb_remove_all (nei->summary_list);
  ospf6_lsdb_remove_all (nei->request_list);
  ospf6_lsdb_remove_all (nei->retrans_list);
  ospf6_lsdb_remove_all (nei->dbdesc_list);
}

void
ospf6_neighbor_summary_add (struct ospf6_lsa *lsa,
                            struct ospf6_neighbor *nei)
{
  struct ospf6_lsa *summary;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    {
      zlog_info ("Neighbor %s summary-list:", nei->str);
      zlog_info ("    Add %s", lsa->str);
    }

  ospf6_lsa_age_current (lsa);
  summary = ospf6_lsa_summary_create (lsa->header);
  ospf6_lsdb_add (summary, nei->summary_list);
}

void
ospf6_neighbor_summary_remove (struct ospf6_lsa *lsa,
                               struct ospf6_neighbor *nei)
{
  struct ospf6_lsa *summary;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    {
      zlog_info ("Neighbor %s summary-list:", nei->str);
      zlog_info ("    Remove %s", lsa->str);
    }

  summary = ospf6_lsdb_lookup_lsdb (lsa->header->type, lsa->header->id,
                                    lsa->header->adv_router, nei->summary_list);
  ospf6_lsdb_remove (summary, nei->summary_list);
}

void
ospf6_neighbor_request_add (struct ospf6_lsa *lsa,
                            struct ospf6_neighbor *nei)
{
  struct ospf6_lsa *summary;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    {
      zlog_info ("Neighbor %s request-list:", nei->str);
      zlog_info ("    Add %s", lsa->str);
    }

  ospf6_lsa_age_current (lsa);
  summary = ospf6_lsa_summary_create (lsa->header);
  ospf6_lsdb_add (summary, nei->request_list);
}

void
ospf6_neighbor_request_remove (struct ospf6_lsa *lsa,
                               struct ospf6_neighbor *nei)
{
  struct ospf6_lsa *summary;

  if (IS_OSPF6_DUMP_NEIGHBOR)
    {
      zlog_info ("Neighbor %s request-list:", nei->str);
      zlog_info ("    Remove %s", lsa->str);
    }

  summary = ospf6_lsdb_lookup_lsdb (lsa->header->type, lsa->header->id,
                                    lsa->header->adv_router, nei->request_list);
  ospf6_lsdb_remove (summary, nei->request_list);
}

void
ospf6_neighbor_retrans_add (struct ospf6_lsa *lsa,
                            struct ospf6_neighbor *nei)
{
  if (IS_OSPF6_DUMP_NEIGHBOR)
    {
      zlog_info ("Neighbor %s retrans-list:", nei->str);
      zlog_info ("    Add %s", lsa->str);
    }

  ospf6_lsdb_add (lsa, nei->retrans_list);
}

void
ospf6_neighbor_retrans_remove (struct ospf6_lsa *lsa,
                               struct ospf6_neighbor *nei)
{
  if (IS_OSPF6_DUMP_NEIGHBOR)
    {
      zlog_info ("Neighbor %s retrans-list:", nei->str);
      zlog_info ("    Remove %s", lsa->str);
    }

  ospf6_lsdb_remove (lsa, nei->retrans_list);

  if (nei->retrans_list->count == 0)
    {
      if (nei->send_update)
        thread_cancel (nei->send_update);
      nei->send_update = NULL;
    }
}

void
ospf6_neighbor_dbdesc_add (struct ospf6_lsa *lsa,
                           struct ospf6_neighbor *nei)
{
  if (IS_OSPF6_DUMP_NEIGHBOR)
    {
      zlog_info ("Neighbor %s dbdesc-list:", nei->str);
      zlog_info ("    Add %s", lsa->str);
    }

  ospf6_lsdb_add (lsa, nei->dbdesc_list);
}

void
ospf6_neighbor_dbdesc_remove (struct ospf6_lsa *lsa,
                              struct ospf6_neighbor *nei)
{
  if (IS_OSPF6_DUMP_NEIGHBOR)
    {
      zlog_info ("Neighbor %s dbdesc-list:", nei->str);
      zlog_info ("    Remove %s", lsa->str);
    }

  ospf6_lsdb_remove (lsa, nei->dbdesc_list);
}


/* prepare summary-list of his neighbor structure */
void
ospf6_neighbor_dbex_init (struct ospf6_neighbor *nei)
{
  struct ospf6_lsdb_node node;

  /* clear ls-list */
  ospf6_neighbor_lslist_clear (nei);

  /* AS scope LSAs */
  for (ospf6_lsdb_head (&node, nei->ospf6_interface->area->ospf6->lsdb);
       ! ospf6_lsdb_is_end (&node); ospf6_lsdb_next (&node))
    {
      if (IS_LSA_MAXAGE (node.lsa))
        ospf6_neighbor_retrans_add (node.lsa, nei);
      else
        ospf6_neighbor_summary_add (node.lsa, nei);
    }

  /* AREA scope LSAs */
  for (ospf6_lsdb_head (&node, nei->ospf6_interface->area->lsdb);
       ! ospf6_lsdb_is_end (&node); ospf6_lsdb_next (&node))
    {
      if (IS_LSA_MAXAGE (node.lsa))
        ospf6_neighbor_retrans_add (node.lsa, nei);
      else
        ospf6_neighbor_summary_add (node.lsa, nei);
    }

  /* INTERFACE scope LSAs */
  for (ospf6_lsdb_head (&node, nei->ospf6_interface->lsdb);
       ! ospf6_lsdb_is_end (&node); ospf6_lsdb_next (&node))
    {
      if (IS_LSA_MAXAGE (node.lsa))
        ospf6_neighbor_retrans_add (node.lsa, nei);
      else
        ospf6_neighbor_summary_add (node.lsa, nei);
    }
}

/* create ospf6_neighbor */
struct ospf6_neighbor *
ospf6_neighbor_create (u_int32_t router_id, struct ospf6_interface *o6i)
{
  struct ospf6_neighbor *new;
  char buf[32];

  new = (struct ospf6_neighbor *)
    XMALLOC (MTYPE_OSPF6_NEIGHBOR, sizeof (struct ospf6_neighbor));
  if (new == NULL)
    {
      zlog_warn ("neighbor: malloc failed");
      return NULL;
    }

  memset (new, 0, sizeof (struct ospf6_neighbor));

  new->state = OSPF6_NEIGHBOR_STATE_DOWN;

  new->router_id = router_id;
  inet_ntop (AF_INET, &router_id, buf, sizeof (buf));
  snprintf (new->str, sizeof (new->str), "%s%%%s", buf, o6i->interface->name);
  new->inactivity_timer = (struct thread *) NULL;

  new->summary_list = ospf6_lsdb_create ();
  new->request_list = ospf6_lsdb_create ();
  new->retrans_list = ospf6_lsdb_create ();
  new->dbdesc_list = ospf6_lsdb_create ();

  listnode_add (o6i->neighbor_list, new);
  new->ospf6_interface = o6i;

  CALL_ADD_HOOK (&neighbor_hook, new);

  return new;
}

void
ospf6_neighbor_delete (struct ospf6_neighbor *o6n)
{
  CALL_REMOVE_HOOK (&neighbor_hook, o6n);

  ospf6_neighbor_thread_cancel_all (o6n);
  ospf6_neighbor_lslist_clear (o6n);

  list_free (o6n->dbdesc_lsa);

  ospf6_lsdb_delete (o6n->summary_list);
  ospf6_lsdb_delete (o6n->request_list);
  ospf6_lsdb_delete (o6n->retrans_list);
  ospf6_lsdb_delete (o6n->dbdesc_list);

  XFREE (MTYPE_OSPF6_NEIGHBOR, o6n);
}

struct ospf6_neighbor *
ospf6_neighbor_lookup (u_int32_t router_id,
                       struct ospf6_interface *o6i)
{
  listnode n;
  struct ospf6_neighbor *o6n;

  for (n = listhead (o6i->neighbor_list); n; nextnode (n))
    {
      o6n = (struct ospf6_neighbor *) getdata (n);
      if (o6n->router_id == router_id)
        return o6n;
    }
  return (struct ospf6_neighbor *) NULL;
}


/* vty functions */
/* show neighbor structure */
void
ospf6_neighbor_show_summary (struct vty *vty, struct ospf6_neighbor *o6n)
{
  char router_id[16];
  char dr[16], bdr[16];
  char duration[16];
  struct timeval now, res;

/*
    vty_out (vty, "%-15s %6s/%-11s %-15s %-15s %s[%s]%s",
             "RouterID", "State", "Duration", "DR", "BDR", "I/F",
             "State", VTY_NEWLINE);
*/

  inet_ntop (AF_INET, &o6n->router_id, router_id, sizeof (router_id));
  inet_ntop (AF_INET, &o6n->dr, dr, sizeof (dr));
  inet_ntop (AF_INET, &o6n->bdr, bdr, sizeof (bdr));

  gettimeofday (&now, NULL);
  ospf6_timeval_sub (&now, &o6n->last_changed, &res);
  ospf6_timeval_string_summary (&res, duration, sizeof (duration));

  vty_out (vty, "%-15s %6s/%-11s %-15s %-15s %s[%s]%s",
           router_id, ospf6_neighbor_state_string[o6n->state],
           duration, dr, bdr, o6n->ospf6_interface->interface->name,
           ospf6_interface_state_string[o6n->ospf6_interface->state],
           VTY_NEWLINE);
}

void
ospf6_neighbor_show (struct vty *vty, struct ospf6_neighbor *o6n)
{
  char hisaddr[64], timestring[32];
  struct timeval now, res;

  inet_ntop (AF_INET6, &o6n->hisaddr, hisaddr, sizeof (hisaddr));
  vty_out (vty, " Neighbor %s, interface address %s%s",
           o6n->str, hisaddr, VTY_NEWLINE);
  vty_out (vty, "    Area %s via interface %s (ifindex %d)%s",
           o6n->ospf6_interface->area->str,
           o6n->ospf6_interface->interface->name,
           o6n->ospf6_interface->interface->ifindex,
           VTY_NEWLINE);
  vty_out (vty, "    Priority: %d, State: %s, %d state changes%s",
           o6n->priority, ospf6_neighbor_state_string[o6n->state],
           o6n->ospf6_stat_state_changed, VTY_NEWLINE);

  gettimeofday (&now, NULL);
  ospf6_timeval_sub (&now, &o6n->last_changed, &res);
  ospf6_timeval_string_summary (&res, timestring, sizeof (timestring));
  vty_out (vty, "    Last state changed: %s ago%s", timestring, VTY_NEWLINE);
}

void
ospf6_neighbor_show_detail (struct vty *vty, struct ospf6_neighbor *o6n)
{
  char hisdr[16], hisbdr[16];

  ospf6_neighbor_show (vty, o6n);

  inet_ntop (AF_INET, &o6n->dr, hisdr, sizeof (hisdr));
  inet_ntop (AF_INET, &o6n->bdr, hisbdr, sizeof (hisbdr));

  vty_out (vty, "    His Ifindex of myside: %d%s",
                o6n->ifid, VTY_NEWLINE);
  vty_out (vty, "    His DR Election: DR %s, BDR %s%s",
                hisdr, hisbdr, VTY_NEWLINE);

  vty_out (vty, "    Last received DbDesc: opt:%s"
                " ifmtu:%hu bit:%s%s%s seqnum:%ld%s",
                "xxx", ntohs (o6n->last_dd.ifmtu),
                (DD_IS_IBIT_SET (o6n->last_dd.bits) ? "I" : "-"),
                (DD_IS_MBIT_SET (o6n->last_dd.bits) ? "M" : "-"),
                (DD_IS_MSBIT_SET (o6n->last_dd.bits) ? "m" : "s"),
                (u_long)ntohl (o6n->last_dd.seqnum), VTY_NEWLINE);
  vty_out (vty, "    My DbDesc bit for this neighbor: %s%s%s%s",
           (DD_IS_IBIT_SET (o6n->dbdesc_bits) ? "I" : "-"),
           (DD_IS_MBIT_SET (o6n->dbdesc_bits) ? "M" : "-"),
           (DD_IS_MSBIT_SET (o6n->dbdesc_bits) ? "m" : "s"),
           VTY_NEWLINE);

  vty_out (vty, "    %-16s %5d times, %-16s %5d times%s",
                "SeqnumMismatch", o6n->ospf6_stat_seqnum_mismatch,
                "BadLSReq", o6n->ospf6_stat_bad_lsreq, VTY_NEWLINE);
  vty_out (vty, "    %-16s %5d times, %-16s %5d times%s",
                "OnewayReceived", o6n->ospf6_stat_oneway_received,
                "InactivityTimer", o6n->ospf6_stat_inactivity_timer,
                VTY_NEWLINE);
  vty_out (vty, "    %-16s %5d times, %-16s %5d times%s",
                "DbDescRetrans", o6n->ospf6_stat_retrans_dbdesc,
                "LSReqRetrans", o6n->ospf6_stat_retrans_lsreq,
                VTY_NEWLINE);
  vty_out (vty, "    %-16s %5d times%s",
                "LSUpdateRetrans", o6n->ospf6_stat_retrans_lsupdate,
                VTY_NEWLINE);
  vty_out (vty, "    %-16s %5d times, %-16s %5d times%s",
                "LSAReceived", o6n->ospf6_stat_received_lsa,
                "LSUpdateReceived", o6n->ospf6_stat_received_lsupdate,
                VTY_NEWLINE);

  vty_out (vty, "    %-12s %-12s %-12s%s",
           "Message", "DbDesc", "LSReq", VTY_NEWLINE);
  vty_out (vty, "    %-12s %12d %12d%s", "LSA Send",
           o6n->lsa_send[OSPF6_MESSAGE_TYPE_DBDESC],
           o6n->lsa_send[OSPF6_MESSAGE_TYPE_LSREQ], VTY_NEWLINE);
  vty_out (vty, "    %-12s %12d %12d%s", "LSA Receive",
           o6n->lsa_receive[OSPF6_MESSAGE_TYPE_DBDESC],
           o6n->lsa_receive[OSPF6_MESSAGE_TYPE_LSREQ], VTY_NEWLINE);
  vty_out (vty, "%s", VTY_NEWLINE);
}

void
ospf6_neighbor_timestamp_hello (struct ospf6_neighbor *o6n)
{
  struct timeval now, interval;
  gettimeofday (&now, (struct timezone *) NULL);
  if (o6n->tv_last_hello_received.tv_sec)
    {
      ospf6_timeval_sub (&now, &o6n->tv_last_hello_received, &interval);
      zlog_info ("Hello Interval %s : %ld msec",
                  o6n->str, interval.tv_sec * 1000 + interval.tv_usec % 1000);
    }
  o6n->tv_last_hello_received.tv_sec = now.tv_sec;
  o6n->tv_last_hello_received.tv_usec = now.tv_usec;
}

DEFUN (show_ipv6_ospf6_neighbor_routerid,
       show_ipv6_ospf6_neighbor_routerid_cmd,
       "show ipv6 ospf6 neighbor A.B.C.D",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       "OSPF6 neighbor Router ID in IP address format\n"
       )
{
  u_int32_t router_id;
  struct ospf6_neighbor *o6n;
  struct ospf6_interface *o6i;
  struct ospf6_area *o6a;
  listnode nodei, nodej, nodek;

  OSPF6_CMD_CHECK_RUNNING ();

  if (argc == 0)
    vty_out (vty, "%-15s %6s/%-11s %-15s %-15s %s[%s]%s",
             "RouterID", "State", "Duration", "DR", "BDR", "I/F",
             "State", VTY_NEWLINE);
  else if (inet_pton (AF_INET, argv[0], &router_id) != 1)
    {
      vty_out (vty, "Malformed Router-ID: %s%s", argv[0], VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  for (nodei = listhead (ospf6->area_list); nodei; nextnode (nodei))
    {
      o6a = getdata (nodei);
      for (nodej = listhead (o6a->if_list); nodej; nextnode (nodej))
        {
          o6i = getdata (nodej);
          for (nodek = listhead (o6i->neighbor_list); nodek; nextnode (nodek))
            {
              o6n = getdata (nodek);
              if (argc == 0)
                ospf6_neighbor_show_summary (vty, o6n);
              else if (o6n->router_id == router_id)
                ospf6_neighbor_show_detail (vty, o6n);
            }
        }
    }
  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_neighbor_routerid,
       show_ipv6_ospf6_neighbor_cmd,
       "show ipv6 ospf6 neighbor",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Neighbor list\n"
       )

DEFUN (show_ipv6_ospf6_neighborlist,
       show_ipv6_ospf6_neighborlist_cmd,
       "show ipv6 ospf6 (summary-list|request-list|retrans-list|dbdesc-list)",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       "Link State summary list\n"
       "Link State request list\n"
       "Link State retransmission list\n"
       "Link State Description list (Used to retrans DbDesc)\n"
       )
{
  struct ospf6_area *o6a;
  struct ospf6_interface *o6i;
  struct ospf6_neighbor *o6n;
  listnode i, j, k, l;
  struct ospf6_lsa *lsa;
  struct ospf6_lsdb *lsdb = NULL;
  char type[16], id[16], adv_router[16];
  struct ospf6_lsdb_node node;
  u_int16_t age, cksum, len;
  u_int32_t seqnum;

  OSPF6_CMD_CHECK_RUNNING ();
  i = j = k = l = NULL;

  for (i = listhead (ospf6->area_list); i; nextnode (i))
    {
      o6a = (struct ospf6_area *) getdata (i);
      for (j = listhead (o6a->if_list); j; nextnode (j))
        {
          o6i = (struct ospf6_interface *) getdata (j);
          for (k = listhead (o6i->neighbor_list); k; nextnode (k))
            {
              o6n = (struct ospf6_neighbor *) getdata (k);

              if (strncmp (argv[0], "sum", 3) == 0)
                lsdb = o6n->summary_list;
              else if (strncmp (argv[0], "req", 3) == 0)
                lsdb = o6n->request_list;
              else if (strncmp (argv[0], "ret", 3) == 0)
                lsdb = o6n->retrans_list;
              else if (strncmp (argv[0], "dbd", 3) == 0)
                lsdb = o6n->dbdesc_list;

              vty_out (vty, "neighbor %s on interface %s: %d%s", o6n->str,
                       o6i->interface->name, lsdb->count,
                       VTY_NEWLINE);
              for (ospf6_lsdb_head (&node, lsdb); ! ospf6_lsdb_is_end (&node);
                   ospf6_lsdb_next (&node))
                {
                  lsa = node.lsa;
                  ospf6_lsa_age_current (lsa);

                  ospf6_lsa_type_string (lsa->header->type, type,
                                         sizeof (type));
                  inet_ntop (AF_INET, &lsa->header->id, id, sizeof (id));
                  inet_ntop (AF_INET, &lsa->header->adv_router, adv_router,
                             sizeof (adv_router));
                  age = ntohs (lsa->header->age);
                  seqnum = ntohl (lsa->header->seqnum);
                  cksum = ntohs (lsa->header->checksum);
                  len = ntohs (lsa->header->length);

                  vty_out (vty, "  %s-LSA ID=%s Adv=%s%s",
                           type, id, adv_router, VTY_NEWLINE);
                  vty_out (vty, "  Age: %hu SeqNum: %#x Cksum: %hx Len: %hu%s",
                           age, seqnum, cksum, len, VTY_NEWLINE);
                }
            }
        }
    }

  return CMD_SUCCESS;
}

void
ospf6_neighbor_init ()
{
  install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_neighbor_routerid_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_neighborlist_cmd);

  install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_neighbor_routerid_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_neighborlist_cmd);
}


