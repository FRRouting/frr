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

#include "if.h"
#include "log.h"
#include "command.h"

#include "ospf6_lsdb.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"

char *ospf6_interface_state_string[] =
{
  "None", "Down", "Loopback", "Waiting", "PointToPoint",
  "DROther", "BDR", "DR", NULL
};

static void
ospf6_interface_foreach_neighbor (struct ospf6_interface *o6i,
                                  void *arg, int val,
                                  void (*func) (void *, int, void *))
{
  listnode node;
  struct ospf6_neighbor *nei;

  for (node = listhead (o6i->neighbor_list); node; nextnode (node))
    {
      nei = (struct ospf6_neighbor *) getdata (node);
      (*func) (arg, val, nei);
    }
}

static int
ospf6_interface_maxage_remover (struct thread *t)
{
  int count;
  struct ospf6_interface *o6i = (struct ospf6_interface *) THREAD_ARG (t);

  o6i->maxage_remover = (struct thread *) NULL;

  count = 0;
  o6i->foreach_nei (o6i, &count, NBS_EXCHANGE, ospf6_count_state);
  o6i->foreach_nei (o6i, &count, NBS_LOADING, ospf6_count_state);
  if (count != 0)
    return 0;

  ospf6_lsdb_remove_maxage (o6i->lsdb);
  return 0;
}

void
ospf6_interface_schedule_maxage_remover (void *arg, int val, void *obj)
{
  struct ospf6_interface *o6i = (struct ospf6_interface *) obj;

  if (o6i->maxage_remover != NULL)
    return;

  o6i->maxage_remover =
    thread_add_event (master, ospf6_interface_maxage_remover, o6i, 0);
}

/* Create new ospf6 interface structure */
struct ospf6_interface *
ospf6_interface_create (struct interface *ifp)
{
  struct ospf6_interface *o6i;

  o6i = (struct ospf6_interface *)
    XMALLOC (MTYPE_OSPF6_IF, sizeof (struct ospf6_interface));

  if (o6i)
    memset (o6i, 0, sizeof (struct ospf6_interface));
  else
    {
      zlog_err ("Can't malloc ospf6_interface for ifindex %d", ifp->ifindex);
      return (struct ospf6_interface *) NULL;
    }

  o6i->instance_id = 0;
  o6i->if_id = ifp->ifindex;
  o6i->lladdr = (struct in6_addr *) NULL;
  o6i->area = (struct ospf6_area *) NULL;
  o6i->state = IFS_DOWN;
  o6i->flag = 0;
  o6i->neighbor_list = list_new ();

  o6i->ack_list = ospf6_lsdb_create ();
  o6i->lsdb = ospf6_lsdb_create ();

  o6i->transdelay = 1;
  o6i->priority = 1;
  o6i->hello_interval = 10;
  o6i->dead_interval = 40;
  o6i->rxmt_interval = 5;
  o6i->cost = 1;
  o6i->ifmtu = 1280;

  o6i->foreach_nei = ospf6_interface_foreach_neighbor;

  /* link both */
  o6i->interface = ifp;
  ifp->info = o6i;

  CALL_ADD_HOOK (&interface_hook, o6i);

  /* Get the interface's link-local if any */
  ospf6_interface_address_update(ifp);

  return o6i;
}

void
ospf6_interface_delete (struct ospf6_interface *o6i)
{
  listnode n;
  struct ospf6_neighbor *o6n;

  CALL_REMOVE_HOOK (&interface_hook, o6i);

  for (n = listhead (o6i->neighbor_list); n; nextnode (n))
    {
      o6n = (struct ospf6_neighbor *) getdata (n);
      ospf6_neighbor_delete (o6n);
    }
  list_delete (o6i->neighbor_list);

  if (o6i->thread_send_hello)
    {
      thread_cancel (o6i->thread_send_hello);
      o6i->thread_send_hello = NULL;
    }
  if (o6i->thread_send_lsack_delayed)
    {
      thread_cancel (o6i->thread_send_lsack_delayed);
      o6i->thread_send_lsack_delayed = NULL;
    }

  ospf6_lsdb_delete (o6i->ack_list);
  ospf6_lsdb_remove_all (o6i->lsdb);
  ospf6_lsdb_delete (o6i->lsdb);

  /* cut link */
  o6i->interface->info = NULL;

  /* plist_name */
  if (o6i->plist_name)
    XFREE (MTYPE_PREFIX_LIST_STR, o6i->plist_name);

  XFREE (MTYPE_OSPF6_IF, o6i);
}

static struct in6_addr *
ospf6_interface_update_linklocal_address (struct interface *ifp)
{
  listnode n;
  struct connected *c;
  struct in6_addr *l = (struct in6_addr *) NULL;

  /* for each connected address */
  for (n = listhead (ifp->connected); n; nextnode (n))
    {
      c = (struct connected *) getdata (n);

      /* if family not AF_INET6, ignore */
      if (c->address->family != AF_INET6)
        continue;

      /* linklocal scope check */
      if (IN6_IS_ADDR_LINKLOCAL (&c->address->u.prefix6))
        l = &c->address->u.prefix6;
    }
  return l;
}

void
ospf6_interface_if_add (struct interface *ifp)
{
  struct ospf6_interface *o6i;

  o6i = (struct ospf6_interface *) ifp->info;
  if (!o6i)
    return;

  o6i->if_id = ifp->ifindex;

  ospf6_interface_address_update (ifp);

  /* interface start */
  if (o6i->area)
    thread_add_event (master, interface_up, o6i, 0);
}

void
ospf6_interface_if_del (struct interface *ifp)
{
  struct ospf6_interface *o6i;

  o6i = (struct ospf6_interface *) ifp->info;
  if (!o6i)
    return;

  /* interface stop */
  if (o6i->area)
    thread_execute (master, interface_down, o6i, 0);

  listnode_delete (o6i->area->if_list, o6i);
  o6i->area = (struct ospf6_area *) NULL;

  /* cut link */
  o6i->interface = NULL;
  ifp->info = NULL;

  ospf6_interface_delete (o6i);
}

void
ospf6_interface_state_update (struct interface *ifp)
{
  struct ospf6_interface *o6i;

  o6i = (struct ospf6_interface *) ifp->info;
  if (! o6i)
    return;
  if (! o6i->area)
    return;

  if (if_is_up (ifp))
    thread_add_event (master, interface_up, o6i, 0);
  else
    thread_add_event (master, interface_down, o6i, 0);

  return;
}

void
ospf6_interface_address_update (struct interface *ifp)
{
  struct ospf6_interface *o6i;

  o6i = (struct ospf6_interface *) ifp->info;
  if (! o6i)
    return;

  /* reset linklocal pointer */
  o6i->lladdr = ospf6_interface_update_linklocal_address (ifp);

  /* if area is null, can't make link-lsa */
  if (! o6i->area)
    return;

  /* create new Link-LSA */
  CALL_FOREACH_LSA_HOOK (hook_interface, hook_change, o6i);

  CALL_CHANGE_HOOK (&interface_hook, o6i);
}

struct ospf6_interface *
ospf6_interface_lookup_by_index (int ifindex)
{
  struct ospf6_interface *o6i;
  struct interface *ifp;

  ifp = if_lookup_by_index (ifindex);

  if (! ifp)
    return (struct ospf6_interface *) NULL;

  o6i = (struct ospf6_interface *) ifp->info;
  return o6i;
}

struct ospf6_interface *
ospf6_interface_lookup_by_name (char *ifname)
{
  struct ospf6_interface *o6i;
  struct interface *ifp;

  ifp = if_lookup_by_name (ifname);

  if (! ifp)
    return (struct ospf6_interface *) NULL;

  o6i = (struct ospf6_interface *) ifp->info;
  return o6i;
}

int
ospf6_interface_count_neighbor_in_state (u_char state,
                                         struct ospf6_interface *o6i)
{
  listnode n;
  struct ospf6_neighbor *o6n;
  int count = 0;

  for (n = listhead (o6i->neighbor_list); n; nextnode (n))
    {
      o6n = (struct ospf6_neighbor *) getdata (n);
      if (o6n->state == state)
        count++;
    }
  return count;
}

int
ospf6_interface_count_full_neighbor (struct ospf6_interface *o6i)
{
  listnode n;
  struct ospf6_neighbor *o6n;
  int count = 0;

  for (n = listhead (o6i->neighbor_list); n; nextnode (n))
    {
      o6n = (struct ospf6_neighbor *) getdata (n);
      if (o6n->state == NBS_FULL)
        count++;
    }
  return count;
}

int
ospf6_interface_is_enabled (unsigned int ifindex)
{
  struct ospf6_interface *o6i;

  o6i = ospf6_interface_lookup_by_index (ifindex);
  if (! o6i)
    return 0;

  if (! o6i->area)
    return 0;

  if (o6i->state <= IFS_DOWN)
    return 0;

  return 1;
}

void
ospf6_interface_delayed_ack_add (struct ospf6_lsa *lsa,
                                 struct ospf6_interface *o6i)
{
  struct ospf6_lsa *summary;
  summary = ospf6_lsa_summary_create (lsa->header);
  ospf6_lsdb_add (summary, o6i->ack_list);
}

void
ospf6_interface_delayed_ack_remove (struct ospf6_lsa *lsa,
                                    struct ospf6_interface *o6i)
{
  struct ospf6_lsa *summary;
  summary = ospf6_lsdb_lookup_lsdb (lsa->header->type, lsa->header->id,
                                    lsa->header->adv_router, o6i->ack_list);
  ospf6_lsdb_remove (summary, o6i->ack_list);
}

/* show specified interface structure */
int
ospf6_interface_show (struct vty *vty, struct interface *iface)
{
  struct ospf6_interface *ospf6_interface;
  struct connected *c;
  struct prefix *p;
  listnode i;
  char strbuf[64], dr[32], bdr[32];
  char *updown[3] = {"down", "up", NULL};
  char *type;

  /* check physical interface type */
  if (if_is_loopback (iface))
    type = "LOOPBACK";
  else if (if_is_broadcast (iface))
    type = "BROADCAST";
  else if (if_is_pointopoint (iface))
    type = "POINTOPOINT";
  else
    type = "UNKNOWN";

  vty_out (vty, "%s is %s, type %s%s",
           iface->name, updown[if_is_up (iface)], type,
	   VTY_NEWLINE);
  vty_out (vty, "  Interface ID: %d%s", iface->ifindex, VTY_NEWLINE);

  if (iface->info == NULL)
    {
      vty_out (vty, "   OSPF not enabled on this interface%s", VTY_NEWLINE);
      return 0;
    }
  else
    ospf6_interface = (struct ospf6_interface *) iface->info;

  vty_out (vty, "  Internet Address:%s", VTY_NEWLINE);
  for (i = listhead (iface->connected); i; nextnode (i))
    {
      c = (struct connected *)getdata (i);
      p = c->address;
      prefix2str (p, strbuf, sizeof (strbuf));
      switch (p->family)
        {
        case AF_INET:
          vty_out (vty, "   inet : %s%s", strbuf,
		   VTY_NEWLINE);
          break;
        case AF_INET6:
          vty_out (vty, "   inet6: %s%s", strbuf,
		   VTY_NEWLINE);
          break;
        default:
          vty_out (vty, "   ???  : %s%s", strbuf,
		   VTY_NEWLINE);
          break;
        }
    }

  if (ospf6_interface->area)
    {
      inet_ntop (AF_INET, &ospf6_interface->area->ospf6->router_id,
                 strbuf, sizeof (strbuf));
      vty_out (vty, "  Instance ID %d, Router ID %s%s",
	       ospf6_interface->instance_id, strbuf,
	       VTY_NEWLINE);
      inet_ntop (AF_INET, &ospf6_interface->area->area_id,
                 strbuf, sizeof (strbuf));
      vty_out (vty, "  Area ID %s, Cost %hu%s", strbuf,
	       ospf6_interface->cost, VTY_NEWLINE);
    }
  else
    vty_out (vty, "  Not Attached to Area%s", VTY_NEWLINE);

  vty_out (vty, "  State %s, Transmit Delay %d sec, Priority %d%s",
           ospf6_interface_state_string[ospf6_interface->state],
           ospf6_interface->transdelay,
           ospf6_interface->priority,
	   VTY_NEWLINE);
  vty_out (vty, "  Timer intervals configured:%s", VTY_NEWLINE);
  vty_out (vty, "   Hello %d, Dead %d, Retransmit %d%s",
           ospf6_interface->hello_interval,
           ospf6_interface->dead_interval,
           ospf6_interface->rxmt_interval,
	   VTY_NEWLINE);

  inet_ntop (AF_INET, &ospf6_interface->dr, dr, sizeof (dr));
  inet_ntop (AF_INET, &ospf6_interface->bdr, bdr, sizeof (bdr));
  vty_out (vty, "  DR:%s BDR:%s%s", dr, bdr, VTY_NEWLINE);

  vty_out (vty, "  Number of I/F scoped LSAs is %u%s",
                ospf6_interface->lsdb->count, VTY_NEWLINE);
  vty_out (vty, "  %-16s %5d times, %-16s %5d times%s",
                "DRElection", ospf6_interface->ospf6_stat_dr_election,
                "DelayedLSAck", ospf6_interface->ospf6_stat_delayed_lsack,
                VTY_NEWLINE);

  return 0;
}

void
ospf6_interface_statistics_show (struct vty *vty, struct ospf6_interface *o6i)
{
  struct timeval now, uptime;
  u_long recv_total, send_total;
  u_long bps_total_avg, bps_tx_avg, bps_rx_avg;
  int i;

  gettimeofday (&now, (struct timezone *) NULL);
  ospf6_timeval_sub (&now, &ospf6->starttime, &uptime);

  recv_total = send_total = 0;
  for (i = 0; i < OSPF6_MESSAGE_TYPE_MAX; i++)
    {
      recv_total += o6i->message_stat[i].recv_octet;
      send_total += o6i->message_stat[i].send_octet;
    }
  bps_total_avg = (recv_total + send_total) * 8 / uptime.tv_sec;
  bps_tx_avg = send_total * 8 / uptime.tv_sec;
  bps_rx_avg = recv_total * 8 / uptime.tv_sec;

  vty_out (vty, "     Statistics of interface %s%s",
           o6i->interface->name, VTY_NEWLINE);
  vty_out (vty, "         Number of Neighbor: %d%s",
           listcount (o6i->neighbor_list), VTY_NEWLINE);

  vty_out (vty, "         %-8s %6s %6s %8s %8s%s",
           "Type", "tx", "rx", "tx-byte", "rx-byte", VTY_NEWLINE);
  for (i = 0; i < OSPF6_MESSAGE_TYPE_MAX; i++)
    {
      vty_out (vty, "         %-8s %6d %6d %8d %8d%s",
               ospf6_message_type_string[i],
               o6i->message_stat[i].send,
               o6i->message_stat[i].recv,
               o6i->message_stat[i].send_octet,
               o6i->message_stat[i].recv_octet,
               VTY_NEWLINE);
    }

  vty_out (vty, "         Average Link bandwidth: %ldbps"
                " (Tx: %ldbps Rx: %ldbps)%s",
           bps_total_avg, bps_tx_avg, bps_rx_avg, VTY_NEWLINE);
}

/* show interface */
DEFUN (show_ipv6_ospf6_interface,
       show_ipv6_ospf6_interface_ifname_cmd,
       "show ipv6 ospf6 interface IFNAME",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       INTERFACE_STR
       IFNAME_STR
       )
{
  struct interface *ifp;
  listnode i;

  if (argc)
    {
      ifp = if_lookup_by_name (argv[0]);
      if (!ifp)
        {
          vty_out (vty, "No such Interface: %s%s", argv[0],
		   VTY_NEWLINE);
          return CMD_WARNING;
        }
      ospf6_interface_show (vty, ifp);
    }
  else
    {
      for (i = listhead (iflist); i; nextnode (i))
        {
          ifp = (struct interface *)getdata (i);
          ospf6_interface_show (vty, ifp);
        }
    }
  return CMD_SUCCESS;
}

ALIAS (show_ipv6_ospf6_interface,
       show_ipv6_ospf6_interface_cmd,
       "show ipv6 ospf6 interface",
       SHOW_STR
       IP6_STR
       OSPF6_STR
       INTERFACE_STR
       )

/* interface variable set command */
DEFUN (ipv6_ospf6_cost,
       ipv6_ospf6_cost_cmd,
       "ipv6 ospf6 cost COST",
       IP6_STR
       OSPF6_STR
       "Interface cost\n"
       "<1-65535> Cost\n"
       )
{
  struct ospf6_interface *o6i;
  struct interface *ifp;

  ifp = (struct interface *)vty->index;
  assert (ifp);

  o6i = (struct ospf6_interface *)ifp->info;
  if (!o6i)
    o6i = ospf6_interface_create (ifp);
  assert (o6i);

  if (o6i->cost == strtol (argv[0], NULL, 10))
    return CMD_SUCCESS;

  o6i->cost = strtol (argv[0], NULL, 10);

  /* execute LSA hooks */
  CALL_FOREACH_LSA_HOOK (hook_interface, hook_change, o6i);

  CALL_CHANGE_HOOK (&interface_hook, o6i);

  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_hellointerval,
       ipv6_ospf6_hellointerval_cmd,
       "ipv6 ospf6 hello-interval HELLO_INTERVAL",
       IP6_STR
       OSPF6_STR
       "Time between HELLO packets\n"
       SECONDS_STR
       )
{
  struct ospf6_interface *ospf6_interface;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  ospf6_interface = (struct ospf6_interface *) ifp->info;
  if (!ospf6_interface)
    ospf6_interface = ospf6_interface_create (ifp);
  assert (ospf6_interface);

  ospf6_interface->hello_interval = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_deadinterval,
       ipv6_ospf6_deadinterval_cmd,
       "ipv6 ospf6 dead-interval ROUTER_DEAD_INTERVAL",
       IP6_STR
       OSPF6_STR
       "Interval after which a neighbor is declared dead\n"
       SECONDS_STR
       )
{
  struct ospf6_interface *ospf6_interface;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  ospf6_interface = (struct ospf6_interface *) ifp->info;
  if (!ospf6_interface)
    ospf6_interface = ospf6_interface_create (ifp);
  assert (ospf6_interface);

  ospf6_interface->dead_interval = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_transmitdelay,
       ipv6_ospf6_transmitdelay_cmd,
       "ipv6 ospf6 transmit-delay TRANSMITDELAY",
       IP6_STR
       OSPF6_STR
       "Link state transmit delay\n"
       SECONDS_STR
       )
{
  struct ospf6_interface *ospf6_interface;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  ospf6_interface = (struct ospf6_interface *) ifp->info;
  if (!ospf6_interface)
    ospf6_interface = ospf6_interface_create (ifp);
  assert (ospf6_interface);

  ospf6_interface->transdelay = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_retransmitinterval,
       ipv6_ospf6_retransmitinterval_cmd,
       "ipv6 ospf6 retransmit-interval RXMTINTERVAL",
       IP6_STR
       OSPF6_STR
       "Time between retransmitting lost link state advertisements\n"
       SECONDS_STR
       )
{
  struct ospf6_interface *ospf6_interface;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  ospf6_interface = (struct ospf6_interface *) ifp->info;
  if (!ospf6_interface)
    ospf6_interface = ospf6_interface_create (ifp);
  assert (ospf6_interface);

  ospf6_interface->rxmt_interval = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

/* interface variable set command */
DEFUN (ipv6_ospf6_priority,
       ipv6_ospf6_priority_cmd,
       "ipv6 ospf6 priority PRIORITY",
       IP6_STR
       OSPF6_STR
       "Router priority\n"
       "<0-255> Priority\n"
       )
{
  struct ospf6_interface *ospf6_interface;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  ospf6_interface = (struct ospf6_interface *) ifp->info;
  if (!ospf6_interface)
    ospf6_interface = ospf6_interface_create (ifp);
  assert (ospf6_interface);

  ospf6_interface->priority = strtol (argv[0], NULL, 10);

  if (ospf6_interface->area)
    ifs_change (dr_election (ospf6_interface), "Priority reconfigured",
                ospf6_interface);

  return CMD_SUCCESS;
}

DEFUN (ipv6_ospf6_instance,
       ipv6_ospf6_instance_cmd,
       "ipv6 ospf6 instance-id INSTANCE",
       IP6_STR
       OSPF6_STR
       "Instance ID\n"
       "<0-255> Instance ID\n"
       )
{
  struct ospf6_interface *ospf6_interface;
  struct interface *ifp;

  ifp = (struct interface *)vty->index;
  assert (ifp);

  ospf6_interface = (struct ospf6_interface *)ifp->info;
  if (!ospf6_interface)
    ospf6_interface = ospf6_interface_create (ifp);
  assert (ospf6_interface);

  ospf6_interface->instance_id = strtol (argv[0], NULL, 10);
  return CMD_SUCCESS;
}

DEFUN (ipv6_ospf6_passive,
       ipv6_ospf6_passive_cmd,
       "ipv6 ospf6 passive",
       IP6_STR
       OSPF6_STR
       "passive interface: No Adjacency will be formed on this I/F\n"
       )
{
  struct ospf6_interface *o6i;
  struct interface *ifp;
  listnode node;
  struct ospf6_neighbor *o6n;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  o6i = (struct ospf6_interface *) ifp->info;
  if (! o6i)
    o6i = ospf6_interface_create (ifp);
  assert (o6i);

  SET_FLAG (o6i->flag, OSPF6_INTERFACE_FLAG_PASSIVE);
  if (o6i->thread_send_hello)
    {
      thread_cancel (o6i->thread_send_hello);
      o6i->thread_send_hello = (struct thread *) NULL;
    }

  for (node = listhead (o6i->neighbor_list); node; nextnode (node))
    {
      o6n = getdata (node);
      if (o6n->inactivity_timer)
        thread_cancel (o6n->inactivity_timer);
      thread_execute (master, inactivity_timer, o6n, 0);
    }

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_passive,
       no_ipv6_ospf6_passive_cmd,
       "no ipv6 ospf6 passive",
       NO_STR
       IP6_STR
       OSPF6_STR
       "passive interface: No Adjacency will be formed on this I/F\n"
       )
{
  struct ospf6_interface *o6i;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  o6i = (struct ospf6_interface *) ifp->info;
  if (! o6i)
    o6i = ospf6_interface_create (ifp);
  assert (o6i);

  UNSET_FLAG (o6i->flag, OSPF6_INTERFACE_FLAG_PASSIVE);
  if (o6i->thread_send_hello == NULL)
    thread_add_event (master, ospf6_send_hello, o6i, 0);

  return CMD_SUCCESS;
}


DEFUN (ipv6_ospf6_advertise_force_prefix,
       ipv6_ospf6_advertise_force_prefix_cmd,
       "ipv6 ospf6 advertise force-prefix",
       IP6_STR
       OSPF6_STR
       "Advertising options\n"
       "Force advertising prefix, applicable if Loopback or P-to-P\n"
       )
{
  struct ospf6_interface *o6i;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  o6i = (struct ospf6_interface *) ifp->info;
  if (! o6i)
    o6i = ospf6_interface_create (ifp);
  assert (o6i);

  if (! if_is_loopback (ifp) && ! if_is_pointopoint (ifp))
    {
      vty_out (vty, "Interface not Loopback nor PointToPoint%s",
               VTY_NEWLINE);
      return CMD_ERR_NOTHING_TODO;
    }

  SET_FLAG (o6i->flag, OSPF6_INTERFACE_FLAG_FORCE_PREFIX);

  /* execute LSA hooks */
  CALL_FOREACH_LSA_HOOK (hook_interface, hook_change, o6i);

  CALL_CHANGE_HOOK (&interface_hook, o6i);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_advertise_force_prefix,
       no_ipv6_ospf6_advertise_force_prefix_cmd,
       "no ipv6 ospf6 advertise force-prefix",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Advertising options\n"
       "Force to advertise prefix, applicable if Loopback or P-to-P\n"
       )
{
  struct ospf6_interface *o6i;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  o6i = (struct ospf6_interface *) ifp->info;
  if (! o6i)
    o6i = ospf6_interface_create (ifp);
  assert (o6i);

  UNSET_FLAG (o6i->flag, OSPF6_INTERFACE_FLAG_FORCE_PREFIX);

  /* execute LSA hooks */
  CALL_FOREACH_LSA_HOOK (hook_interface, hook_change, o6i);

  CALL_CHANGE_HOOK (&interface_hook, o6i);

  return CMD_SUCCESS;
}

DEFUN (ipv6_ospf6_advertise_prefix_list,
       ipv6_ospf6_advertise_prefix_list_cmd,
       "ipv6 ospf6 advertise prefix-list WORD",
       IP6_STR
       OSPF6_STR
       "Advertising options\n"
       "Filter prefix using prefix-list\n"
       "Prefix list name\n"
       )
{
  struct ospf6_interface *o6i;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  o6i = (struct ospf6_interface *) ifp->info;
  if (! o6i)
    o6i = ospf6_interface_create (ifp);
  assert (o6i);

  if (o6i->plist_name)
    XFREE (MTYPE_PREFIX_LIST_STR, o6i->plist_name);
  o6i->plist_name = XSTRDUP (MTYPE_PREFIX_LIST_STR, argv[0]);

  /* execute LSA hooks */
  CALL_FOREACH_LSA_HOOK (hook_interface, hook_change, o6i);

  CALL_CHANGE_HOOK (&interface_hook, o6i);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_advertise_prefix_list,
       no_ipv6_ospf6_advertise_prefix_list_cmd,
       "no ipv6 ospf6 advertise prefix-list",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Advertising options\n"
       "Filter prefix using prefix-list\n"
       )
{
  struct ospf6_interface *o6i;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);
  o6i = (struct ospf6_interface *) ifp->info;
  if (! o6i)
    o6i = ospf6_interface_create (ifp);
  assert (o6i);

  if (o6i->plist_name)
    {
      XFREE (MTYPE_PREFIX_LIST_STR, o6i->plist_name);
      o6i->plist_name = NULL;
    }

  /* execute LSA hooks */
  CALL_FOREACH_LSA_HOOK (hook_interface, hook_change, o6i);

  CALL_CHANGE_HOOK (&interface_hook, o6i);

  return CMD_SUCCESS;
}

int
ospf6_interface_config_write (struct vty *vty)
{
  listnode i;
  struct ospf6_interface *o6i;
  struct interface *ifp;

  for (i = listhead (iflist); i; nextnode (i))
    {
      ifp = (struct interface *) getdata (i);
      o6i = (struct ospf6_interface *) ifp->info;
      if (! o6i)
        continue;

      vty_out (vty, "interface %s%s",
               o6i->interface->name, VTY_NEWLINE);
      vty_out (vty, " ipv6 ospf6 cost %d%s",
               o6i->cost, VTY_NEWLINE);
      vty_out (vty, " ipv6 ospf6 hello-interval %d%s",
               o6i->hello_interval, VTY_NEWLINE);
      vty_out (vty, " ipv6 ospf6 dead-interval %d%s",
               o6i->dead_interval, VTY_NEWLINE);
      vty_out (vty, " ipv6 ospf6 retransmit-interval %d%s",
               o6i->rxmt_interval, VTY_NEWLINE);
      vty_out (vty, " ipv6 ospf6 priority %d%s",
               o6i->priority, VTY_NEWLINE);
      vty_out (vty, " ipv6 ospf6 transmit-delay %d%s",
               o6i->transdelay, VTY_NEWLINE);
      vty_out (vty, " ipv6 ospf6 instance-id %d%s",
               o6i->instance_id, VTY_NEWLINE);

      if (CHECK_FLAG (o6i->flag, OSPF6_INTERFACE_FLAG_FORCE_PREFIX))
        vty_out (vty, " ipv6 ospf6 advertise force-prefix%s", VTY_NEWLINE);
      if (o6i->plist_name)
        vty_out (vty, " ipv6 ospf6 advertise prefix-list %s%s",
                 o6i->plist_name, VTY_NEWLINE);

      if (CHECK_FLAG (o6i->flag, OSPF6_INTERFACE_FLAG_PASSIVE))
        vty_out (vty, " ipv6 ospf6 passive%s", VTY_NEWLINE);

      vty_out (vty, "!%s", VTY_NEWLINE);
    }
  return 0;
}

struct cmd_node interface_node =
{
  INTERFACE_NODE,
  "%s(config-if)# ",
};

void
ospf6_interface_init ()
{
  /* Install interface node. */
  install_node (&interface_node, ospf6_interface_config_write);

  install_element (VIEW_NODE, &show_ipv6_ospf6_interface_cmd);
  install_element (VIEW_NODE, &show_ipv6_ospf6_interface_ifname_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_cmd);
  install_element (ENABLE_NODE, &show_ipv6_ospf6_interface_ifname_cmd);

  install_default (INTERFACE_NODE);
  install_element (INTERFACE_NODE, &interface_desc_cmd);
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_cost_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_deadinterval_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_hellointerval_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_priority_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_retransmitinterval_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_transmitdelay_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_instance_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_advertise_force_prefix_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_ospf6_advertise_force_prefix_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_advertise_prefix_list_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_ospf6_advertise_prefix_list_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_passive_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_ospf6_passive_cmd);
}


