/*
 * IS-IS Rout(e)ing protocol - isis_adjacency.c   
 *                             handling of IS-IS adjacencies
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology      
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU General Public Licenseas published by the Free 
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT 
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
 * more details.

 * You should have received a copy of the GNU General Public License along 
 * with this program; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "hash.h"
#include "vty.h"
#include "linklist.h"
#include "thread.h"
#include "if.h"
#include "stream.h"

#include "isisd/dict.h"
#include "isisd/include-netbsd/iso.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isisd.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_dr.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_pdu.h"

extern struct isis *isis;

static struct isis_adjacency *
adj_alloc (u_char * id)
{
  struct isis_adjacency *adj;

  adj = XCALLOC (MTYPE_ISIS_ADJACENCY, sizeof (struct isis_adjacency));
  memcpy (adj->sysid, id, ISIS_SYS_ID_LEN);

  return adj;
}

struct isis_adjacency *
isis_new_adj (u_char * id, u_char * snpa, int level,
	      struct isis_circuit *circuit)
{
  struct isis_adjacency *adj;
  int i;

  adj = adj_alloc (id);		/* P2P kludge */

  if (adj == NULL)
    {
      zlog_err ("Out of memory!");
      return NULL;
    }

  if (snpa) {
  memcpy (adj->snpa, snpa, 6);
  } else {
      memset (adj->snpa, ' ', 6);
  }

  adj->circuit = circuit;
  adj->level = level;
  adj->flaps = 0;
  adj->last_flap = time (NULL);
  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    {
      listnode_add (circuit->u.bc.adjdb[level - 1], adj);
      adj->dischanges[level - 1] = 0;
      for (i = 0; i < DIS_RECORDS; i++)	/* clear N DIS state change records */
	{
	  adj->dis_record[(i * ISIS_LEVELS) + level - 1].dis
	    = ISIS_UNKNOWN_DIS;
	  adj->dis_record[(i * ISIS_LEVELS) + level - 1].last_dis_change
	    = time (NULL);
	}
    }

  return adj;
}

struct isis_adjacency *
isis_adj_lookup (u_char * sysid, struct list *adjdb)
{
  struct isis_adjacency *adj;
  struct listnode *node;

  for (ALL_LIST_ELEMENTS_RO (adjdb, node, adj))
    if (memcmp (adj->sysid, sysid, ISIS_SYS_ID_LEN) == 0)
      return adj;

  return NULL;
}

struct isis_adjacency *
isis_adj_lookup_snpa (u_char * ssnpa, struct list *adjdb)
{
  struct listnode *node;
  struct isis_adjacency *adj;

  for (ALL_LIST_ELEMENTS_RO (adjdb, node, adj))
    if (memcmp (adj->snpa, ssnpa, ETH_ALEN) == 0)
      return adj;

  return NULL;
}

void
isis_delete_adj (struct isis_adjacency *adj, struct list *adjdb)
{
  if (!adj)
    return;
  /* When we recieve a NULL list, we will know its p2p. */
  if (adjdb)
    listnode_delete (adjdb, adj);

  THREAD_OFF (adj->t_expire);

  if (adj->ipv4_addrs)
    list_delete (adj->ipv4_addrs);
#ifdef HAVE_IPV6
  if (adj->ipv6_addrs)
    list_delete (adj->ipv6_addrs);
#endif
  
  XFREE (MTYPE_ISIS_ADJACENCY, adj);
  return;
}

void
isis_adj_state_change (struct isis_adjacency *adj, enum isis_adj_state state,
		       const char *reason)
{
  int old_state;
  int level = adj->level;
  struct isis_circuit *circuit;

  old_state = adj->adj_state;
  adj->adj_state = state;

  circuit = adj->circuit;

  if (isis->debugs & DEBUG_ADJ_PACKETS)
    {
      zlog_debug ("ISIS-Adj (%s): Adjacency state change %d->%d: %s",
		 circuit->area->area_tag,
		 old_state, state, reason ? reason : "unspecified");
    }

  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    {
      if (state == ISIS_ADJ_UP)
	circuit->upadjcount[level - 1]++;
      if (state == ISIS_ADJ_DOWN)
	{
	  isis_delete_adj (adj, adj->circuit->u.bc.adjdb[level - 1]);
	  circuit->upadjcount[level - 1]--;
	}

      list_delete_all_node (circuit->u.bc.lan_neighs[level - 1]);
      isis_adj_build_neigh_list (circuit->u.bc.adjdb[level - 1],
				 circuit->u.bc.lan_neighs[level - 1]);
    }
  else if (state == ISIS_ADJ_UP)
    {				/* p2p interface */
      if (adj->sys_type == ISIS_SYSTYPE_UNKNOWN)
	send_hello (circuit, 1);

      /* update counter & timers for debugging purposes */
      adj->last_flap = time (NULL);
      adj->flaps++;

      /* 7.3.17 - going up on P2P -> send CSNP */
      /* FIXME: yup, I know its wrong... but i will do it! (for now) */
      send_csnp (circuit, 1);
      send_csnp (circuit, 2);
    }
  else if (state == ISIS_ADJ_DOWN)
    {				/* p2p interface */
      adj->circuit->u.p2p.neighbor = NULL;
      isis_delete_adj (adj, NULL);
    }
  return;
}


void
isis_adj_print (struct isis_adjacency *adj)
{
  struct isis_dynhn *dyn;
  struct listnode *node;
  struct in_addr *ipv4_addr;
#ifdef HAVE_IPV6
  struct in6_addr *ipv6_addr;
  u_char ip6[INET6_ADDRSTRLEN];
#endif /* HAVE_IPV6 */

  if (!adj)
    return;
  dyn = dynhn_find_by_id (adj->sysid);
  if (dyn)
    zlog_debug ("%s", dyn->name.name);

  zlog_debug ("SystemId %20s SNPA %s, level %d\nHolding Time %d",
	      adj->sysid ? sysid_print (adj->sysid) : "unknown",
	      snpa_print (adj->snpa), adj->level, adj->hold_time);
  if (adj->ipv4_addrs && listcount (adj->ipv4_addrs) > 0)
    {
      zlog_debug ("IPv4 Addresses:");

      for (ALL_LIST_ELEMENTS_RO (adj->ipv4_addrs, node, ipv4_addr))
        zlog_debug ("%s", inet_ntoa (*ipv4_addr));
    }

#ifdef HAVE_IPV6
  if (adj->ipv6_addrs && listcount (adj->ipv6_addrs) > 0)
    {
      zlog_debug ("IPv6 Addresses:");
      for (ALL_LIST_ELEMENTS_RO (adj->ipv6_addrs, node, ipv6_addr))
	{
	  inet_ntop (AF_INET6, ipv6_addr, (char *)ip6, INET6_ADDRSTRLEN);
	  zlog_debug ("%s", ip6);
	}
    }
#endif /* HAVE_IPV6 */
  zlog_debug ("Speaks: %s", nlpid2string (&adj->nlpids));

  return;
}

int
isis_adj_expire (struct thread *thread)
{
  struct isis_adjacency *adj;
  int level;

  /*
   * Get the adjacency
   */
  adj = THREAD_ARG (thread);
  assert (adj);
  level = adj->level;
  adj->t_expire = NULL;

  /* trigger the adj expire event */
  isis_adj_state_change (adj, ISIS_ADJ_DOWN, "holding time expired");

  return 0;
}

static const char *
adj_state2string (int state)
{

  switch (state)
    {
    case ISIS_ADJ_INITIALIZING:
      return "Initializing";
    case ISIS_ADJ_UP:
      return "Up";
    case ISIS_ADJ_DOWN:
      return "Down";
    default:
      return "Unknown";
    }

  return NULL;			/* not reached */
}

/*
 * show clns/isis neighbor (detail)
 */
static void
isis_adj_print_vty2 (struct isis_adjacency *adj, struct vty *vty, char detail)
{

#ifdef HAVE_IPV6
  struct in6_addr *ipv6_addr;
  u_char ip6[INET6_ADDRSTRLEN];
#endif /* HAVE_IPV6 */
  struct in_addr *ip_addr;
  time_t now;
  struct isis_dynhn *dyn;
  int level;
  struct listnode *node;

  dyn = dynhn_find_by_id (adj->sysid);
  if (dyn)
    vty_out (vty, "  %-20s", dyn->name.name);
  else if (adj->sysid)
    {
      vty_out (vty, "  %-20s", sysid_print (adj->sysid));
    }
  else
    {
      vty_out (vty, "  unknown ");
    }

  if (detail == ISIS_UI_LEVEL_BRIEF)
    {
      if (adj->circuit)
	vty_out (vty, "%-12s", adj->circuit->interface->name);
      else
	vty_out (vty, "NULL circuit!");
      vty_out (vty, "%-3u", adj->level);	/* level */
      vty_out (vty, "%-13s", adj_state2string (adj->adj_state));
      now = time (NULL);
      if (adj->last_upd)
	vty_out (vty, "%-9lu", adj->last_upd + adj->hold_time - now);
      else
	vty_out (vty, "-        ");
      vty_out (vty, "%-10s", snpa_print (adj->snpa));
      vty_out (vty, "%s", VTY_NEWLINE);
    }

  if (detail == ISIS_UI_LEVEL_DETAIL)
    {
      level = adj->level;
      if (adj->circuit)
	vty_out (vty, "%s    Interface: %s", VTY_NEWLINE, adj->circuit->interface->name);	/* interface name */
      else
	vty_out (vty, "NULL circuit!%s", VTY_NEWLINE);
      vty_out (vty, ", Level: %u", adj->level);	/* level */
      vty_out (vty, ", State: %s", adj_state2string (adj->adj_state));
      now = time (NULL);
      if (adj->last_upd)
	vty_out (vty, ", Expires in %s",
		 time2string (adj->last_upd + adj->hold_time - now));
      else
	vty_out (vty, ", Expires in %s", time2string (adj->hold_time));
      vty_out (vty, "%s    Adjacency flaps: %u", VTY_NEWLINE, adj->flaps);
      vty_out (vty, ", Last: %s ago", time2string (now - adj->last_flap));
      vty_out (vty, "%s    Circuit type: %s",
	       VTY_NEWLINE, circuit_t2string (adj->circuit_t));
      vty_out (vty, ", Speaks: %s", nlpid2string (&adj->nlpids));
      vty_out (vty, "%s    SNPA: %s", VTY_NEWLINE, snpa_print (adj->snpa));
      dyn = dynhn_find_by_id (adj->lanid);
      if (dyn)
	vty_out (vty, ", LAN id: %s.%02x",
		 dyn->name.name, adj->lanid[ISIS_SYS_ID_LEN]);
      else
	vty_out (vty, ", LAN id: %s.%02x",
		 sysid_print (adj->lanid), adj->lanid[ISIS_SYS_ID_LEN]);

      vty_out (vty, "%s    Priority: %u",
	       VTY_NEWLINE, adj->prio[adj->level - 1]);

      vty_out (vty, ", %s, DIS flaps: %u, Last: %s ago%s",
	       isis_disflag2string (adj->dis_record[ISIS_LEVELS + level - 1].
				    dis), adj->dischanges[level - 1],
	       time2string (now -
			    (adj->dis_record[ISIS_LEVELS + level - 1].
			     last_dis_change)), VTY_NEWLINE);

      if (adj->ipv4_addrs && listcount (adj->ipv4_addrs) > 0)
	{
	  vty_out (vty, "    IPv4 Addresses:%s", VTY_NEWLINE);
	  for (ALL_LIST_ELEMENTS_RO (adj->ipv4_addrs, node, ip_addr))
            vty_out (vty, "      %s%s", inet_ntoa (*ip_addr), VTY_NEWLINE);
	}
#ifdef HAVE_IPV6
      if (adj->ipv6_addrs && listcount (adj->ipv6_addrs) > 0)
	{
	  vty_out (vty, "    IPv6 Addresses:%s", VTY_NEWLINE);
	  for (ALL_LIST_ELEMENTS_RO (adj->ipv6_addrs, node, ipv6_addr))
	    {
	      inet_ntop (AF_INET6, ipv6_addr, (char *)ip6, INET6_ADDRSTRLEN);
	      vty_out (vty, "      %s%s", ip6, VTY_NEWLINE);
	    }
	}
#endif /* HAVE_IPV6 */
      vty_out (vty, "%s", VTY_NEWLINE);
    }
  return;
}

void
isis_adj_print_vty (struct isis_adjacency *adj, struct vty *vty)
{
  isis_adj_print_vty2 (adj, vty, ISIS_UI_LEVEL_BRIEF);
}

void
isis_adj_print_vty_detail (struct isis_adjacency *adj, struct vty *vty)
{
  isis_adj_print_vty2 (adj, vty, ISIS_UI_LEVEL_DETAIL);
}

void
isis_adj_print_vty_extensive (struct isis_adjacency *adj, struct vty *vty)
{
  isis_adj_print_vty2 (adj, vty, ISIS_UI_LEVEL_EXTENSIVE);
}

void
isis_adj_p2p_print_vty (struct isis_adjacency *adj, struct vty *vty)
{
  isis_adj_print_vty2 (adj, vty, ISIS_UI_LEVEL_BRIEF);
}

void
isis_adj_p2p_print_vty_detail (struct isis_adjacency *adj, struct vty *vty)
{
  isis_adj_print_vty2 (adj, vty, ISIS_UI_LEVEL_DETAIL);
}

void
isis_adj_p2p_print_vty_extensive (struct isis_adjacency *adj, struct vty *vty)
{
  isis_adj_print_vty2 (adj, vty, ISIS_UI_LEVEL_EXTENSIVE);
}

void
isis_adjdb_iterate (struct list *adjdb, void (*func) (struct isis_adjacency *,
						      void *), void *arg)
{
  struct listnode *node, *nnode;
  struct isis_adjacency *adj;

  for (ALL_LIST_ELEMENTS (adjdb, node, nnode, adj))
    (*func) (adj, arg);
}

void
isis_adj_build_neigh_list (struct list *adjdb, struct list *list)
{
  struct isis_adjacency *adj;
  struct listnode *node;

  if (!list)
    {
      zlog_warn ("isis_adj_build_neigh_list(): NULL list");
      return;
    }

  for (ALL_LIST_ELEMENTS_RO (adjdb, node, adj))
    {
      if (!adj)
	{
	  zlog_warn ("isis_adj_build_neigh_list(): NULL adj");
	  return;
	}

      if ((adj->adj_state == ISIS_ADJ_UP ||
	   adj->adj_state == ISIS_ADJ_INITIALIZING))
	listnode_add (list, adj->snpa);
    }
  return;
}

void
isis_adj_build_up_list (struct list *adjdb, struct list *list)
{
  struct isis_adjacency *adj;
  struct listnode *node;

  if (!list)
    {
      zlog_warn ("isis_adj_build_up_list(): NULL list");
      return;
    }

  for (ALL_LIST_ELEMENTS_RO (adjdb, node, adj))
    {
      if (!adj)
	{
	  zlog_warn ("isis_adj_build_up_list(): NULL adj");
	  return;
	}

      if (adj->adj_state == ISIS_ADJ_UP)
	listnode_add (list, adj);
    }

  return;
}
