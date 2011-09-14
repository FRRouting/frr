/*
 * IS-IS Rout(e)ing protocol - isis_circuit.h
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
#ifdef GNU_LINUX
#include <net/ethernet.h>
#else
#include <netinet/if_ether.h>
#endif

#ifndef ETHER_ADDR_LEN
#define	ETHER_ADDR_LEN	ETHERADDRL
#endif

#include "log.h"
#include "memory.h"
#include "if.h"
#include "linklist.h"
#include "command.h"
#include "thread.h"
#include "hash.h"
#include "prefix.h"
#include "stream.h"

#include "isisd/dict.h"
#include "isisd/include-netbsd/iso.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_tlv.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_network.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_dr.h"
#include "isisd/isis_flags.h"
#include "isisd/isisd.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_events.h"

extern struct thread_master *master;
extern struct isis *isis;

/*
 * Prototypes.
 */
void isis_circuit_down(struct isis_circuit *);
int isis_interface_config_write(struct vty *);
int isis_if_new_hook(struct interface *);
int isis_if_delete_hook(struct interface *);

struct isis_circuit *
isis_circuit_new ()
{
  struct isis_circuit *circuit;
  int i;

  circuit = XCALLOC (MTYPE_ISIS_CIRCUIT, sizeof (struct isis_circuit));
  if (circuit)
    {
      /* set default metrics for circuit */
      for (i = 0; i < 2; i++)
	{
	  circuit->metrics[i].metric_default = DEFAULT_CIRCUIT_METRICS;
	  circuit->metrics[i].metric_expense = METRICS_UNSUPPORTED;
	  circuit->metrics[i].metric_error = METRICS_UNSUPPORTED;
	  circuit->metrics[i].metric_delay = METRICS_UNSUPPORTED;
	  circuit->te_metric[i] = DEFAULT_CIRCUIT_METRICS;
	}
    }
  else
    {
      zlog_err ("Can't malloc isis circuit");
      return NULL;
    }

  return circuit;
}

void
isis_circuit_configure (struct isis_circuit *circuit, struct isis_area *area)
{
  int i;
  circuit->area = area;
  /*
   * The level for the circuit is same as for the area, unless configured
   * otherwise.
   */
  circuit->circuit_is_type = area->is_type;
  /*
   * Default values
   */
  for (i = 0; i < 2; i++)
    {
      circuit->hello_interval[i] = HELLO_INTERVAL;
      circuit->hello_multiplier[i] = HELLO_MULTIPLIER;
      circuit->csnp_interval[i] = CSNP_INTERVAL;
      circuit->psnp_interval[i] = PSNP_INTERVAL;
      circuit->u.bc.priority[i] = DEFAULT_PRIORITY;
    }
  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    {
      circuit->u.bc.adjdb[0] = list_new ();
      circuit->u.bc.adjdb[1] = list_new ();
      circuit->u.bc.pad_hellos = 1;
    }
  circuit->lsp_interval = LSP_INTERVAL;

  /*
   * Add the circuit into area
   */
  listnode_add (area->circuit_list, circuit);

  circuit->idx = flags_get_index (&area->flags);
  circuit->lsp_queue = list_new ();

  return;
}

void
isis_circuit_deconfigure (struct isis_circuit *circuit,
			  struct isis_area *area)
{

  /* destroy adjacencies */
  if (circuit->u.bc.adjdb[0])
    isis_adjdb_iterate (circuit->u.bc.adjdb[0], (void(*) (struct isis_adjacency *, void *)) isis_delete_adj, circuit->u.bc.adjdb[0]);
  if (circuit->u.bc.adjdb[1])
    isis_adjdb_iterate (circuit->u.bc.adjdb[1], (void(*) (struct isis_adjacency *, void *)) isis_delete_adj, circuit->u.bc.adjdb[1]);
  /* Remove circuit from area */
  listnode_delete (area->circuit_list, circuit);
  /* Free the index of SRM and SSN flags */
  flags_free_index (&area->flags, circuit->idx);

  return;
}

struct isis_circuit *
circuit_lookup_by_ifp (struct interface *ifp, struct list *list)
{
  struct isis_circuit *circuit = NULL;
  struct listnode *node;

  if (!list)
    return NULL;

  for (ALL_LIST_ELEMENTS_RO (list, node, circuit))
    if (circuit->interface == ifp)
      return circuit;
  
  return NULL;
}

struct isis_circuit *
circuit_scan_by_ifp (struct interface *ifp)
{
  struct isis_area *area;
  struct listnode *node;
  struct isis_circuit *circuit;

  if (!isis->area_list)
    return NULL;

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    {
      circuit = circuit_lookup_by_ifp (ifp, area->circuit_list);
      if (circuit)
	return circuit;
    }

  return circuit_lookup_by_ifp (ifp, isis->init_circ_list);
}

void
isis_circuit_del (struct isis_circuit *circuit)
{

  if (!circuit)
    return;

  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    {
      /* destroy adjacency databases */
      if (circuit->u.bc.adjdb[0])
	list_delete (circuit->u.bc.adjdb[0]);
      if (circuit->u.bc.adjdb[1])
	list_delete (circuit->u.bc.adjdb[1]);
      /* destroy neighbour lists */
      if (circuit->u.bc.lan_neighs[0])
	list_delete (circuit->u.bc.lan_neighs[0]);
      if (circuit->u.bc.lan_neighs[1])
	list_delete (circuit->u.bc.lan_neighs[1]);
      /* destroy addresses */
    }
  if (circuit->ip_addrs)
    list_delete (circuit->ip_addrs);
#ifdef HAVE_IPV6
  if (circuit->ipv6_link)
    list_delete (circuit->ipv6_link);
  if (circuit->ipv6_non_link)
    list_delete (circuit->ipv6_non_link);
#endif /* HAVE_IPV6 */

  /* and lastly the circuit itself */
  XFREE (MTYPE_ISIS_CIRCUIT, circuit);

  return;
}

void
isis_circuit_add_addr (struct isis_circuit *circuit,
		       struct connected *connected)
{
  struct prefix_ipv4 *ipv4;
  u_char buf[BUFSIZ];
#ifdef HAVE_IPV6
  struct prefix_ipv6 *ipv6;
#endif /* HAVE_IPV6 */

  if (!circuit->ip_addrs)
    circuit->ip_addrs = list_new ();
#ifdef HAVE_IPV6
  if (!circuit->ipv6_link)
    circuit->ipv6_link = list_new ();
  if (!circuit->ipv6_non_link)
    circuit->ipv6_non_link = list_new ();
#endif /* HAVE_IPV6 */

  memset (&buf, 0, BUFSIZ);
  if (connected->address->family == AF_INET)
    {
      ipv4 = prefix_ipv4_new ();
      ipv4->prefixlen = connected->address->prefixlen;
      ipv4->prefix = connected->address->u.prefix4;
      listnode_add (circuit->ip_addrs, ipv4);
      if (circuit->area)
	lsp_regenerate_schedule (circuit->area);

#ifdef EXTREME_DEBUG
      prefix2str (connected->address, buf, BUFSIZ);
      zlog_debug ("Added IP address %s to circuit %d", buf,
		 circuit->circuit_id);
#endif /* EXTREME_DEBUG */
    }
#ifdef HAVE_IPV6
  if (connected->address->family == AF_INET6)
    {
      ipv6 = prefix_ipv6_new ();
      ipv6->prefixlen = connected->address->prefixlen;
      ipv6->prefix = connected->address->u.prefix6;

      if (IN6_IS_ADDR_LINKLOCAL (&ipv6->prefix))
	listnode_add (circuit->ipv6_link, ipv6);
      else
	listnode_add (circuit->ipv6_non_link, ipv6);
      if (circuit->area)
	lsp_regenerate_schedule (circuit->area);

#ifdef EXTREME_DEBUG
      prefix2str (connected->address, buf, BUFSIZ);
      zlog_debug ("Added IPv6 address %s to circuit %d", buf,
		 circuit->circuit_id);
#endif /* EXTREME_DEBUG */
    }
#endif /* HAVE_IPV6 */
  return;
}

void
isis_circuit_del_addr (struct isis_circuit *circuit,
		       struct connected *connected)
{
  struct prefix_ipv4 *ipv4, *ip = NULL;
  struct listnode *node;
  u_char buf[BUFSIZ];
#ifdef HAVE_IPV6
  struct prefix_ipv6 *ipv6, *ip6 = NULL;
  int found = 0;
#endif /* HAVE_IPV6 */

  memset (&buf, 0, BUFSIZ);
  if (connected->address->family == AF_INET)
    {
      ipv4 = prefix_ipv4_new ();
      ipv4->prefixlen = connected->address->prefixlen;
      ipv4->prefix = connected->address->u.prefix4;

      for (ALL_LIST_ELEMENTS_RO (circuit->ip_addrs, node, ip))
        if (prefix_same ((struct prefix *) ip, (struct prefix *) &ipv4))
          break;

      if (ip)
	{
	  listnode_delete (circuit->ip_addrs, ip);
	  if (circuit->area)
	    lsp_regenerate_schedule (circuit->area);
	}
      else
	{
	  prefix2str (connected->address, (char *)buf, BUFSIZ);
	  zlog_warn("Nonexitant ip address %s removal attempt from circuit \
		     %d", buf, circuit->circuit_id);
	}
    }
#ifdef HAVE_IPV6
  if (connected->address->family == AF_INET6)
    {
      ipv6 = prefix_ipv6_new ();
      ipv6->prefixlen = connected->address->prefixlen;
      ipv6->prefix = connected->address->u.prefix6;

      if (IN6_IS_ADDR_LINKLOCAL (&ipv6->prefix))
	{
	  for (ALL_LIST_ELEMENTS_RO (circuit->ipv6_link, node, ip6))
	    {
	      if (prefix_same ((struct prefix *) ip6, (struct prefix *) ipv6))
		break;
	    }
	  if (ip6)
	    {
	      listnode_delete (circuit->ipv6_link, ip6);
	      found = 1;
	    }
	}
      else
	{
	  for (ALL_LIST_ELEMENTS_RO (circuit->ipv6_non_link, node, ip6))
	    {
	      if (prefix_same ((struct prefix *) ip6, (struct prefix *) ipv6))
		break;
	    }
	  if (ip6)
	    {
	      listnode_delete (circuit->ipv6_non_link, ip6);
	      found = 1;
	    }
	}

      if (!found)
	{
	  prefix2str (connected->address, (char *)buf, BUFSIZ);
	  zlog_warn("Nonexitant ip address %s removal attempt from \
		     circuit %d", buf, circuit->circuit_id);
	}
      else
	if (circuit->area)
	  lsp_regenerate_schedule (circuit->area);
    }
#endif /* HAVE_IPV6 */
  return;
}

void
isis_circuit_if_add (struct isis_circuit *circuit, struct interface *ifp)
{
  struct listnode *node, *nnode;
  struct connected *conn;

  circuit->interface = ifp;
  ifp->info = circuit;

  circuit->circuit_id = ifp->ifindex % 255;	/* FIXME: Why not ? */

  /*  isis_circuit_update_addrs (circuit, ifp); */

  if (if_is_broadcast (ifp))
    {
      circuit->circ_type = CIRCUIT_T_BROADCAST;
      /*
       * Get the Hardware Address
       */
#ifdef HAVE_STRUCT_SOCKADDR_DL
#ifndef SUNOS_5
      if (circuit->interface->sdl.sdl_alen != ETHER_ADDR_LEN)
	zlog_warn ("unsupported link layer");
      else
	memcpy (circuit->u.bc.snpa, LLADDR (&circuit->interface->sdl),
		ETH_ALEN);
#endif
#else
      if (circuit->interface->hw_addr_len != ETH_ALEN)
	{
	  zlog_warn ("unsupported link layer");
	}
      else
	{
	  memcpy (circuit->u.bc.snpa, circuit->interface->hw_addr, ETH_ALEN);
	}
#ifdef EXTREME_DEGUG
      zlog_debug ("isis_circuit_if_add: if_id %d, isomtu %d snpa %s",
		 circuit->interface->ifindex, ISO_MTU (circuit),
		 snpa_print (circuit->u.bc.snpa));

#endif /* EXTREME_DEBUG */
#endif /* HAVE_STRUCT_SOCKADDR_DL */
    }
  else if (if_is_pointopoint (ifp))
    {
      circuit->circ_type = CIRCUIT_T_P2P;
    }
  else
    {
      /* It's normal in case of loopback etc. */
      if (isis->debugs & DEBUG_EVENTS)
	zlog_debug ("isis_circuit_if_add: unsupported media");
    }

  for (ALL_LIST_ELEMENTS (ifp->connected, node, nnode, conn))
    isis_circuit_add_addr (circuit, conn);

  return;
}

void
isis_circuit_update_params (struct isis_circuit *circuit,
			    struct interface *ifp)
{
  assert (circuit);

  if (circuit->circuit_id != ifp->ifindex)
    {
      zlog_warn ("changing circuit_id %d->%d", circuit->circuit_id,
		 ifp->ifindex);
      circuit->circuit_id = ifp->ifindex % 255;
    }

  /* FIXME: Why is this needed? shouldn't we compare to the area's mtu */
  /* Ofer, this was here in case someone changes the mtu (e.g. with ifconfig) 
     The areas MTU is the minimum of mtu's of circuits in the area
     now we can't catch the change
     if (circuit->mtu != ifp->mtu) {
     zlog_warn ("changing circuit mtu %d->%d", circuit->mtu, 
     ifp->mtu);    
     circuit->mtu = ifp->mtu;
     }
   */
  /*
   * Get the Hardware Address
   */
#ifdef HAVE_STRUCT_SOCKADDR_DL
#ifndef SUNOS_5
  if (circuit->interface->sdl.sdl_alen != ETHER_ADDR_LEN)
    zlog_warn ("unsupported link layer");
  else
    memcpy (circuit->u.bc.snpa, LLADDR (&circuit->interface->sdl), ETH_ALEN);
#endif
#else
  if (circuit->interface->hw_addr_len != ETH_ALEN)
    {
      zlog_warn ("unsupported link layer");
    }
  else
    {
      if (memcmp (circuit->u.bc.snpa, circuit->interface->hw_addr, ETH_ALEN))
	{
	  zlog_warn ("changing circuit snpa %s->%s",
		     snpa_print (circuit->u.bc.snpa),
		     snpa_print (circuit->interface->hw_addr));
	}
    }
#endif

  if (if_is_broadcast (ifp))
    {
      circuit->circ_type = CIRCUIT_T_BROADCAST;
    }
  else if (if_is_pointopoint (ifp))
    {
      circuit->circ_type = CIRCUIT_T_P2P;
    }
  else
    {
      zlog_warn ("isis_circuit_update_params: unsupported media");
    }

  return;
}

void
isis_circuit_if_del (struct isis_circuit *circuit)
{
  circuit->interface->info = NULL;
  circuit->interface = NULL;

  return;
}

void
isis_circuit_up (struct isis_circuit *circuit)
{

  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    {
      if (circuit->area->min_bcast_mtu == 0 ||
	  ISO_MTU (circuit) < circuit->area->min_bcast_mtu)
	circuit->area->min_bcast_mtu = ISO_MTU (circuit);
      /*
       * ISO 10589 - 8.4.1 Enabling of broadcast circuits
       */

      /* initilizing the hello sending threads
       * for a broadcast IF
       */

      /* 8.4.1 a) commence sending of IIH PDUs */

      if (circuit->circuit_is_type & IS_LEVEL_1)
	{
	  thread_add_event (master, send_lan_l1_hello, circuit, 0);
	  circuit->u.bc.lan_neighs[0] = list_new ();
	}

      if (circuit->circuit_is_type & IS_LEVEL_2)
	{
	  thread_add_event (master, send_lan_l2_hello, circuit, 0);
	  circuit->u.bc.lan_neighs[1] = list_new ();
	}

      /* 8.4.1 b) FIXME: solicit ES - 8.4.6 */
      /* 8.4.1 c) FIXME: listen for ESH PDUs */

      /* 8.4.1 d) */
      /* dr election will commence in... */
      if (circuit->circuit_is_type & IS_LEVEL_1)
	THREAD_TIMER_ON (master, circuit->u.bc.t_run_dr[0], isis_run_dr_l1,
			 circuit, 2 * circuit->hello_interval[0]);
      if (circuit->circuit_is_type & IS_LEVEL_2)
	THREAD_TIMER_ON (master, circuit->u.bc.t_run_dr[1], isis_run_dr_l2,
			 circuit, 2 * circuit->hello_interval[1]);
    }
  else
    {
      /* initializing the hello send threads
       * for a ptp IF
       */
      thread_add_event (master, send_p2p_hello, circuit, 0);

    }

  /* initializing PSNP timers */
  if (circuit->circuit_is_type & IS_LEVEL_1)
    {
      THREAD_TIMER_ON (master, circuit->t_send_psnp[0], send_l1_psnp, circuit,
		       isis_jitter (circuit->psnp_interval[0], PSNP_JITTER));
    }

  if (circuit->circuit_is_type & IS_LEVEL_2)
    {
      THREAD_TIMER_ON (master, circuit->t_send_psnp[1], send_l2_psnp, circuit,
		       isis_jitter (circuit->psnp_interval[1], PSNP_JITTER));
    }

  /* initialize the circuit streams */
  if (circuit->rcv_stream == NULL)
    circuit->rcv_stream = stream_new (ISO_MTU (circuit));

  if (circuit->snd_stream == NULL)
    circuit->snd_stream = stream_new (ISO_MTU (circuit));

  /* unified init for circuits */
  isis_sock_init (circuit);

#ifdef GNU_LINUX
  THREAD_READ_ON (master, circuit->t_read, isis_receive, circuit,
		  circuit->fd);
#else
  THREAD_TIMER_ON (master, circuit->t_read, isis_receive, circuit,
		   circuit->fd);
#endif
  return;
}

void
isis_circuit_down (struct isis_circuit *circuit)
{
  /* Cancel all active threads -- FIXME: wrong place */
  /* HT: Read thread if GNU_LINUX, TIMER thread otherwise. */
  THREAD_OFF (circuit->t_read);
  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    {
      THREAD_TIMER_OFF (circuit->u.bc.t_send_lan_hello[0]);
      THREAD_TIMER_OFF (circuit->u.bc.t_send_lan_hello[1]);
      THREAD_TIMER_OFF (circuit->u.bc.t_run_dr[0]);
      THREAD_TIMER_OFF (circuit->u.bc.t_run_dr[1]);
    }
  else if (circuit->circ_type == CIRCUIT_T_P2P)
    {
      THREAD_TIMER_OFF (circuit->u.p2p.t_send_p2p_hello);
    }

  if (circuit->t_send_psnp[0]) {
    THREAD_TIMER_OFF (circuit->t_send_psnp[0]);
  }
  if (circuit->t_send_psnp[1]) {
    THREAD_TIMER_OFF (circuit->t_send_psnp[1]);
  }
  /* close the socket */
  close (circuit->fd);

  return;
}

void
circuit_update_nlpids (struct isis_circuit *circuit)
{
  circuit->nlpids.count = 0;

  if (circuit->ip_router)
    {
      circuit->nlpids.nlpids[0] = NLPID_IP;
      circuit->nlpids.count++;
    }
#ifdef HAVE_IPV6
  if (circuit->ipv6_router)
    {
      circuit->nlpids.nlpids[circuit->nlpids.count] = NLPID_IPV6;
      circuit->nlpids.count++;
    }
#endif /* HAVE_IPV6 */
  return;
}

int
isis_interface_config_write (struct vty *vty)
{

  int write = 0;
  struct listnode *node, *node2;
  struct interface *ifp;
  struct isis_area *area;
  struct isis_circuit *c;
  int i;

  for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp))
  {
    /* IF name */
    vty_out (vty, "interface %s%s", ifp->name, VTY_NEWLINE);
    write++;
    /* IF desc */
    if (ifp->desc)
      {
	vty_out (vty, " description %s%s", ifp->desc, VTY_NEWLINE);
	write++;
      }
    /* ISIS Circuit */
    for (ALL_LIST_ELEMENTS_RO (isis->area_list, node2, area))
    {
      c = circuit_lookup_by_ifp (ifp, area->circuit_list);
      if (c)
	{
	  if (c->ip_router)
	    {
	      vty_out (vty, " ip router isis %s%s", area->area_tag,
		       VTY_NEWLINE);
	      write++;
	    }
#ifdef HAVE_IPV6
	  if (c->ipv6_router)
	    {
	      vty_out (vty, " ipv6 router isis %s%s", area->area_tag,
		       VTY_NEWLINE);
	      write++;
	    }
#endif /* HAVE_IPV6 */

	  /* ISIS - circuit type */
	  if (c->circuit_is_type == IS_LEVEL_1)
	    {
	      vty_out (vty, " isis circuit-type level-1%s", VTY_NEWLINE);
	      write++;
	    }
	  else
	    {
	      if (c->circuit_is_type == IS_LEVEL_2)
		{
		  vty_out (vty, " isis circuit-type level-2-only%s",
			   VTY_NEWLINE);
		  write++;
		}
	    }

	  /* ISIS - CSNP interval - FIXME: compare to cisco */
	  if (c->csnp_interval[0] == c->csnp_interval[1])
	    {
	      if (c->csnp_interval[0] != CSNP_INTERVAL)
		{
		  vty_out (vty, " isis csnp-interval %d%s",
			   c->csnp_interval[0], VTY_NEWLINE);
		  write++;
		}
	    }
	  else
	    {
	      for (i = 0; i < 2; i++)
		{
		  if (c->csnp_interval[1] != CSNP_INTERVAL)
		    {
		      vty_out (vty, " isis csnp-interval %d level-%d%s",
			       c->csnp_interval[1], i + 1, VTY_NEWLINE);
		      write++;
		    }
		}
	    }

	  /* ISIS - Hello padding - Defaults to true so only display if false */
	  if (c->circ_type == CIRCUIT_T_BROADCAST && !c->u.bc.pad_hellos)
	    {
	      vty_out (vty, " no isis hello padding%s", VTY_NEWLINE);
	      write++;
	    }

	  /* ISIS - Hello interval - FIXME: compare to cisco */
	  if (c->hello_interval[0] == c->hello_interval[1])
	    {
	      if (c->hello_interval[0] != HELLO_INTERVAL)
		{
		  vty_out (vty, " isis hello-interval %d%s",
			   c->hello_interval[0], VTY_NEWLINE);
		  write++;
		}
	    }
	  else
	    {
	      for (i = 0; i < 2; i++)
		{
		  if (c->hello_interval[i] != HELLO_INTERVAL)
		    {
		      if (c->hello_interval[i] == HELLO_MINIMAL)
			{
			  vty_out (vty,
				   " isis hello-interval minimal level-%d%s",
				   i + 1, VTY_NEWLINE);
			}
		      else
			{
			  vty_out (vty, " isis hello-interval %d level-%d%s",
				   c->hello_interval[i], i + 1, VTY_NEWLINE);
			}
		      write++;
		    }
		}
	    }

	  /* ISIS - Hello Multiplier */
	  if (c->hello_multiplier[0] == c->hello_multiplier[1])
	    {
	      if (c->hello_multiplier[0] != HELLO_MULTIPLIER)
		{
		  vty_out (vty, " isis hello-multiplier %d%s",
			   c->hello_multiplier[0], VTY_NEWLINE);
		  write++;
		}
	    }
	  else
	    {
	      for (i = 0; i < 2; i++)
		{
		  if (c->hello_multiplier[i] != HELLO_MULTIPLIER)
		    {
		      vty_out (vty, " isis hello-multiplier %d level-%d%s",
			       c->hello_multiplier[i], i + 1, VTY_NEWLINE);
		      write++;
		    }
		}
	    }
	  /* ISIS - Priority */
	  if (c->circ_type == CIRCUIT_T_BROADCAST)
	    {
	      if (c->u.bc.priority[0] == c->u.bc.priority[1])
		{
		  if (c->u.bc.priority[0] != DEFAULT_PRIORITY)
		    {
		      vty_out (vty, " isis priority %d%s",
			       c->u.bc.priority[0], VTY_NEWLINE);
		      write++;
		    }
		}
	      else
		{
		  for (i = 0; i < 2; i++)
		    {
		      if (c->u.bc.priority[i] != DEFAULT_PRIORITY)
			{
			  vty_out (vty, " isis priority %d level-%d%s",
				   c->u.bc.priority[i], i + 1, VTY_NEWLINE);
			  write++;
			}
		    }
		}
	    }
	  /* ISIS - Metric */
	  if (c->te_metric[0] == c->te_metric[1])
	    {
	      if (c->te_metric[0] != DEFAULT_CIRCUIT_METRICS)
		{
		  vty_out (vty, " isis metric %d%s", c->te_metric[0],
			   VTY_NEWLINE);
		  write++;
		}
	    }
	  else
	    {
	      for (i = 0; i < 2; i++)
		{
		  if (c->te_metric[i] != DEFAULT_CIRCUIT_METRICS)
		    {
		      vty_out (vty, " isis metric %d level-%d%s",
			       c->te_metric[i], i + 1, VTY_NEWLINE);
		      write++;
		    }
		}
	    }

	}
    }
    vty_out (vty, "!%s", VTY_NEWLINE);
  }

  return write;
}

DEFUN (ip_router_isis,
       ip_router_isis_cmd,
       "ip router isis WORD",
       "Interface Internet Protocol config commands\n"
       "IP router interface commands\n"
       "IS-IS Routing for IP\n"
       "Routing process tag\n")
{
  struct isis_circuit *c;
  struct interface *ifp;
  struct isis_area *area;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  area = isis_area_lookup (argv[0]);

  /* Prevent more than one circuit per interface */
  if (area)
    c = circuit_lookup_by_ifp (ifp, area->circuit_list);
  else
    c = NULL;
  if (c && (ifp->info != NULL))
    {
#ifdef HAVE_IPV6
      if (c->ipv6_router == 0)
	{
#endif /* HAVE_IPV6 */
	  /* FIXME: Find the way to warn only vty users. */
	  /* vty_out (vty, "ISIS circuit is already defined%s", VTY_NEWLINE); */
	  return CMD_WARNING;
#ifdef HAVE_IPV6
	}
#endif /* HAVE_IPV6 */
    }

  /* this is here for ciscopability */
  if (!area)
    {
      /* FIXME: Find the way to warn only vty users. */
      /* vty_out (vty, "Can't find ISIS instance %s", VTY_NEWLINE); */
      return CMD_WARNING;
    }

  if (!c)
    {
      c = circuit_lookup_by_ifp (ifp, isis->init_circ_list);
      c = isis_csm_state_change (ISIS_ENABLE, c, area);
      c->interface = ifp;	/* this is automatic */
      ifp->info = c;		/* hardly related to the FSM */
    }

  if (!c)
    return CMD_WARNING;

  c->ip_router = 1;
  area->ip_circuits++;
  circuit_update_nlpids (c);

  vty->node = INTERFACE_NODE;

  return CMD_SUCCESS;
}

DEFUN (no_ip_router_isis,
       no_ip_router_isis_cmd,
       "no ip router isis WORD",
       NO_STR
       "Interface Internet Protocol config commands\n"
       "IP router interface commands\n"
       "IS-IS Routing for IP\n"
       "Routing process tag\n")
{
  struct isis_circuit *circuit = NULL;
  struct interface *ifp;
  struct isis_area *area;
  struct listnode *node;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  area = isis_area_lookup (argv[0]);
  if (!area)
    {
      vty_out (vty, "Can't find ISIS instance %s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  for (ALL_LIST_ELEMENTS_RO (area->circuit_list, node, circuit))
    if (circuit->interface == ifp)
      break;
  if (!circuit)
    {
      vty_out (vty, "Can't find ISIS interface %s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  circuit->ip_router = 0;
  area->ip_circuits--;
#ifdef HAVE_IPV6
  if (circuit->ipv6_router == 0)
#endif
    isis_csm_state_change (ISIS_DISABLE, circuit, area);

  return CMD_SUCCESS;
}

DEFUN (isis_circuit_type,
       isis_circuit_type_cmd,
       "isis circuit-type (level-1|level-1-2|level-2-only)",
       "IS-IS commands\n"
       "Configure circuit type for interface\n"
       "Level-1 only adjacencies are formed\n"
       "Level-1-2 adjacencies are formed\n"
       "Level-2 only adjacencies are formed\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;
  int circuit_t;
  int is_type;

  ifp = vty->index;
  circuit = ifp->info;
  /* UGLY - will remove l8r */
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }

  /* XXX what to do when ip_router_isis is not executed */
  if (circuit->area == NULL)
    return CMD_WARNING;

  assert (circuit);

  circuit_t = string2circuit_t (argv[0]);

  if (!circuit_t)
    {
      vty_out (vty, "Unknown circuit-type %s", VTY_NEWLINE);
      return CMD_SUCCESS;
    }

  is_type = circuit->area->is_type;
  if (is_type == IS_LEVEL_1_AND_2 || is_type == circuit_t)
    isis_event_circuit_type_change (circuit, circuit_t);
  else
    {
      vty_out (vty, "invalid circuit level for area %s.%s",
	       circuit->area->area_tag, VTY_NEWLINE);
    }

  return CMD_SUCCESS;
}

DEFUN (no_isis_circuit_type,
       no_isis_circuit_type_cmd,
       "no isis circuit-type (level-1|level-1-2|level-2-only)",
       NO_STR
       "IS-IS commands\n"
       "Configure circuit type for interface\n"
       "Level-1 only adjacencies are formed\n"
       "Level-1-2 adjacencies are formed\n"
       "Level-2 only adjacencies are formed\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }

  assert (circuit);

  /*
   * Set the circuits level to its default value which is that of the area
   */
  isis_event_circuit_type_change (circuit, circuit->area->is_type);

  return CMD_SUCCESS;
}

DEFUN (isis_passwd,
       isis_passwd_cmd,
       "isis password WORD",
       "IS-IS commands\n"
       "Configure the authentication password for interface\n"
       "Password\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;
  int len;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }

  len = strlen (argv[0]);
  if (len > 254)
    {
      vty_out (vty, "Too long circuit password (>254)%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  circuit->passwd.len = len;
  circuit->passwd.type = ISIS_PASSWD_TYPE_CLEARTXT;
  strncpy ((char *)circuit->passwd.passwd, argv[0], 255);

  return CMD_SUCCESS;
}

DEFUN (no_isis_passwd,
       no_isis_passwd_cmd,
       "no isis password",
       NO_STR
       "IS-IS commands\n"
       "Configure the authentication password for interface\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }

  memset (&circuit->passwd, 0, sizeof (struct isis_passwd));

  return CMD_SUCCESS;
}


DEFUN (isis_priority,
       isis_priority_cmd,
       "isis priority <0-127>",
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;
  int prio;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  prio = atoi (argv[0]);

  circuit->u.bc.priority[0] = prio;
  circuit->u.bc.priority[1] = prio;

  return CMD_SUCCESS;
}

DEFUN (no_isis_priority,
       no_isis_priority_cmd,
       "no isis priority",
       NO_STR
       "IS-IS commands\n"
       "Set priority for Designated Router election\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  circuit->u.bc.priority[0] = DEFAULT_PRIORITY;
  circuit->u.bc.priority[1] = DEFAULT_PRIORITY;

  return CMD_SUCCESS;
}

ALIAS (no_isis_priority,
       no_isis_priority_arg_cmd,
       "no isis priority <0-127>",
       NO_STR
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n")

DEFUN (isis_priority_l1,
       isis_priority_l1_cmd,
       "isis priority <0-127> level-1",
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n"
       "Specify priority for level-1 routing\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;
  int prio;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  prio = atoi (argv[0]);

  circuit->u.bc.priority[0] = prio;

  return CMD_SUCCESS;
}

DEFUN (no_isis_priority_l1,
       no_isis_priority_l1_cmd,
       "no isis priority level-1",
       NO_STR
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Specify priority for level-1 routing\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  circuit->u.bc.priority[0] = DEFAULT_PRIORITY;

  return CMD_SUCCESS;
}

ALIAS (no_isis_priority_l1,
       no_isis_priority_l1_arg_cmd,
       "no isis priority <0-127> level-1",
       NO_STR
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n"
       "Specify priority for level-1 routing\n")

DEFUN (isis_priority_l2,
       isis_priority_l2_cmd,
       "isis priority <0-127> level-2",
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n"
       "Specify priority for level-2 routing\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;
  int prio;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  prio = atoi (argv[0]);

  circuit->u.bc.priority[1] = prio;

  return CMD_SUCCESS;
}

DEFUN (no_isis_priority_l2,
       no_isis_priority_l2_cmd,
       "no isis priority level-2",
       NO_STR
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Specify priority for level-2 routing\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  circuit->u.bc.priority[1] = DEFAULT_PRIORITY;

  return CMD_SUCCESS;
}

ALIAS (no_isis_priority_l2,
       no_isis_priority_l2_arg_cmd,
       "no isis priority <0-127> level-2",
       NO_STR
       "IS-IS commands\n"
       "Set priority for Designated Router election\n"
       "Priority value\n"
       "Specify priority for level-2 routing\n")

/* Metric command */
  DEFUN (isis_metric,
       isis_metric_cmd,
       "isis metric <0-16777215>",
       "IS-IS commands\n"
       "Set default metric for circuit\n"
       "Default metric value\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;
  int met;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  met = atoi (argv[0]);

  circuit->te_metric[0] = met;
  circuit->te_metric[1] = met;

  if (met > 63)
    met = 63;

  circuit->metrics[0].metric_default = met;
  circuit->metrics[1].metric_default = met;

  return CMD_SUCCESS;
}

DEFUN (no_isis_metric,
       no_isis_metric_cmd,
       "no isis metric",
       NO_STR
       "IS-IS commands\n"
       "Set default metric for circuit\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  circuit->te_metric[0] = DEFAULT_CIRCUIT_METRICS;
  circuit->te_metric[1] = DEFAULT_CIRCUIT_METRICS;
  circuit->metrics[0].metric_default = DEFAULT_CIRCUIT_METRICS;
  circuit->metrics[1].metric_default = DEFAULT_CIRCUIT_METRICS;

  return CMD_SUCCESS;
}

ALIAS (no_isis_metric,
       no_isis_metric_arg_cmd,
       "no isis metric <0-16777215>",
       NO_STR
       "IS-IS commands\n"
       "Set default metric for circuit\n"
       "Default metric value\n")

/* end of metrics */
DEFUN (isis_hello_interval,
       isis_hello_interval_cmd,
       "isis hello-interval (<1-65535>|minimal)",
       "IS-IS commands\n"
       "Set Hello interval\n"
       "Hello interval value\n"
       "Holdtime 1 seconds, interval depends on multiplier\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;
  int interval;
  char c;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);
  c = *argv[0];
  if (isdigit ((int) c))
    {
      interval = atoi (argv[0]);
    }
  else
    interval = HELLO_MINIMAL;	/* FIXME: should be calculated */

  circuit->hello_interval[0] = (u_int16_t) interval;
  circuit->hello_interval[1] = (u_int16_t) interval;

  return CMD_SUCCESS;
}

DEFUN (no_isis_hello_interval,
       no_isis_hello_interval_cmd,
       "no isis hello-interval",
       NO_STR
       "IS-IS commands\n"
       "Set Hello interval\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);


  circuit->hello_interval[0] = HELLO_INTERVAL;	/* Default is 1 sec. */
  circuit->hello_interval[1] = HELLO_INTERVAL;

  return CMD_SUCCESS;
}

ALIAS (no_isis_hello_interval,
       no_isis_hello_interval_arg_cmd,
       "no isis hello-interval (<1-65535>|minimal)",
       NO_STR
       "IS-IS commands\n"
       "Set Hello interval\n"
       "Hello interval value\n"
       "Holdtime 1 second, interval depends on multiplier\n")

DEFUN (isis_hello_interval_l1,
       isis_hello_interval_l1_cmd,
       "isis hello-interval (<1-65535>|minimal) level-1",
       "IS-IS commands\n"
       "Set Hello interval\n"
       "Hello interval value\n"
       "Holdtime 1 second, interval depends on multiplier\n"
       "Specify hello-interval for level-1 IIHs\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;
  long interval;
  char c;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  c = *argv[0];
  if (isdigit ((int) c))
    {
      interval = atoi (argv[0]);
    }
  else
    interval = HELLO_MINIMAL;

  circuit->hello_interval[0] = (u_int16_t) interval;

  return CMD_SUCCESS;
}

DEFUN (no_isis_hello_interval_l1,
       no_isis_hello_interval_l1_cmd,
       "no isis hello-interval level-1",
       NO_STR
       "IS-IS commands\n"
       "Set Hello interval\n"
       "Specify hello-interval for level-1 IIHs\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);


  circuit->hello_interval[0] = HELLO_INTERVAL;	/* Default is 1 sec. */

  return CMD_SUCCESS;
}

ALIAS (no_isis_hello_interval_l1,
       no_isis_hello_interval_l1_arg_cmd,
       "no isis hello-interval (<1-65535>|minimal) level-1",
       NO_STR
       "IS-IS commands\n"
       "Set Hello interval\n"
       "Hello interval value\n"
       "Holdtime 1 second, interval depends on multiplier\n"
       "Specify hello-interval for level-1 IIHs\n")

DEFUN (isis_hello_interval_l2,
       isis_hello_interval_l2_cmd,
       "isis hello-interval (<1-65535>|minimal) level-2",
       "IS-IS commands\n"
       "Set Hello interval\n"
       "Hello interval value\n"
       "Holdtime 1 second, interval depends on multiplier\n"
       "Specify hello-interval for level-2 IIHs\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;
  long interval;
  char c;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  c = *argv[0];
  if (isdigit ((int) c))
    {
      interval = atoi (argv[0]);
    }
  else
    interval = HELLO_MINIMAL;

  circuit->hello_interval[1] = (u_int16_t) interval;

  return CMD_SUCCESS;
}

DEFUN (no_isis_hello_interval_l2,
       no_isis_hello_interval_l2_cmd,
       "no isis hello-interval level-2",
       NO_STR
       "IS-IS commands\n"
       "Set Hello interval\n"
       "Specify hello-interval for level-2 IIHs\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);


  circuit->hello_interval[1] = HELLO_INTERVAL;	/* Default is 1 sec. */

  return CMD_SUCCESS;
}

ALIAS (no_isis_hello_interval_l2,
       no_isis_hello_interval_l2_arg_cmd,
       "no isis hello-interval (<1-65535>|minimal) level-2",
       NO_STR
       "IS-IS commands\n"
       "Set Hello interval\n"
       "Hello interval value\n"
       "Holdtime 1 second, interval depends on multiplier\n"
       "Specify hello-interval for level-2 IIHs\n")

DEFUN (isis_hello_multiplier,
       isis_hello_multiplier_cmd,
       "isis hello-multiplier <3-1000>",
       "IS-IS commands\n"
       "Set multiplier for Hello holding time\n"
       "Hello multiplier value\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;
  int mult;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  mult = atoi (argv[0]);

  circuit->hello_multiplier[0] = (u_int16_t) mult;
  circuit->hello_multiplier[1] = (u_int16_t) mult;

  return CMD_SUCCESS;
}

DEFUN (no_isis_hello_multiplier,
       no_isis_hello_multiplier_cmd,
       "no isis hello-multiplier",
       NO_STR
       "IS-IS commands\n"
       "Set multiplier for Hello holding time\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  circuit->hello_multiplier[0] = HELLO_MULTIPLIER;
  circuit->hello_multiplier[1] = HELLO_MULTIPLIER;

  return CMD_SUCCESS;
}

ALIAS (no_isis_hello_multiplier,
       no_isis_hello_multiplier_arg_cmd,
       "no isis hello-multiplier <3-1000>",
       NO_STR
       "IS-IS commands\n"
       "Set multiplier for Hello holding time\n"
       "Hello multiplier value\n")

DEFUN (isis_hello_multiplier_l1,
       isis_hello_multiplier_l1_cmd,
       "isis hello-multiplier <3-1000> level-1",
       "IS-IS commands\n"
       "Set multiplier for Hello holding time\n"
       "Hello multiplier value\n"
       "Specify hello multiplier for level-1 IIHs\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;
  int mult;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  mult = atoi (argv[0]);

  circuit->hello_multiplier[0] = (u_int16_t) mult;

  return CMD_SUCCESS;
}

DEFUN (no_isis_hello_multiplier_l1,
       no_isis_hello_multiplier_l1_cmd,
       "no isis hello-multiplier level-1",
       NO_STR
       "IS-IS commands\n"
       "Set multiplier for Hello holding time\n"
       "Specify hello multiplier for level-1 IIHs\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  circuit->hello_multiplier[0] = HELLO_MULTIPLIER;

  return CMD_SUCCESS;
}

ALIAS (no_isis_hello_multiplier_l1,
       no_isis_hello_multiplier_l1_arg_cmd,
       "no isis hello-multiplier <3-1000> level-1",
       NO_STR
       "IS-IS commands\n"
       "Set multiplier for Hello holding time\n"
       "Hello multiplier value\n"
       "Specify hello multiplier for level-1 IIHs\n")

DEFUN (isis_hello_multiplier_l2,
       isis_hello_multiplier_l2_cmd,
       "isis hello-multiplier <3-1000> level-2",
       "IS-IS commands\n"
       "Set multiplier for Hello holding time\n"
       "Hello multiplier value\n"
       "Specify hello multiplier for level-2 IIHs\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;
  int mult;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  mult = atoi (argv[0]);

  circuit->hello_multiplier[1] = (u_int16_t) mult;

  return CMD_SUCCESS;
}

DEFUN (no_isis_hello_multiplier_l2,
       no_isis_hello_multiplier_l2_cmd,
       "no isis hello-multiplier level-2",
       NO_STR
       "IS-IS commands\n"
       "Set multiplier for Hello holding time\n"
       "Specify hello multiplier for level-2 IIHs\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  circuit->hello_multiplier[1] = HELLO_MULTIPLIER;

  return CMD_SUCCESS;
}

ALIAS (no_isis_hello_multiplier_l2,
       no_isis_hello_multiplier_l2_arg_cmd,
       "no isis hello-multiplier <3-1000> level-2",
       NO_STR
       "IS-IS commands\n"
       "Set multiplier for Hello holding time\n"
       "Hello multiplier value\n"
       "Specify hello multiplier for level-2 IIHs\n")

DEFUN (isis_hello,
       isis_hello_cmd,
       "isis hello padding",
       "IS-IS commands\n"
       "Add padding to IS-IS hello packets\n"
       "Pad hello packets\n"
       "<cr>\n")
{
  struct interface *ifp;
  struct isis_circuit *circuit;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  circuit->u.bc.pad_hellos = 1;

  return CMD_SUCCESS;
}

DEFUN (no_isis_hello,
       no_isis_hello_cmd,
       "no isis hello padding",
       NO_STR
       "IS-IS commands\n"
       "Add padding to IS-IS hello packets\n"
       "Pad hello packets\n"
       "<cr>\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  circuit->u.bc.pad_hellos = 0;

  return CMD_SUCCESS;
}

DEFUN (csnp_interval,
       csnp_interval_cmd,
       "isis csnp-interval <0-65535>",
       "IS-IS commands\n"
       "Set CSNP interval in seconds\n"
       "CSNP interval value\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;
  unsigned long interval;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  interval = atol (argv[0]);

  circuit->csnp_interval[0] = (u_int16_t) interval;
  circuit->csnp_interval[1] = (u_int16_t) interval;

  return CMD_SUCCESS;
}

DEFUN (no_csnp_interval,
       no_csnp_interval_cmd,
       "no isis csnp-interval",
       NO_STR
       "IS-IS commands\n"
       "Set CSNP interval in seconds\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  circuit->csnp_interval[0] = CSNP_INTERVAL;
  circuit->csnp_interval[1] = CSNP_INTERVAL;

  return CMD_SUCCESS;
}

ALIAS (no_csnp_interval,
       no_csnp_interval_arg_cmd,
       "no isis csnp-interval <0-65535>",
       NO_STR
       "IS-IS commands\n"
       "Set CSNP interval in seconds\n"
       "CSNP interval value\n")

DEFUN (csnp_interval_l1,
       csnp_interval_l1_cmd,
       "isis csnp-interval <0-65535> level-1",
       "IS-IS commands\n"
       "Set CSNP interval in seconds\n"
       "CSNP interval value\n"
       "Specify interval for level-1 CSNPs\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;
  unsigned long interval;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  interval = atol (argv[0]);

  circuit->csnp_interval[0] = (u_int16_t) interval;

  return CMD_SUCCESS;
}

DEFUN (no_csnp_interval_l1,
       no_csnp_interval_l1_cmd,
       "no isis csnp-interval level-1",
       NO_STR
       "IS-IS commands\n"
       "Set CSNP interval in seconds\n"
       "Specify interval for level-1 CSNPs\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  circuit->csnp_interval[0] = CSNP_INTERVAL;

  return CMD_SUCCESS;
}

ALIAS (no_csnp_interval_l1,
       no_csnp_interval_l1_arg_cmd,
       "no isis csnp-interval <0-65535> level-1",
       NO_STR
       "IS-IS commands\n"
       "Set CSNP interval in seconds\n"
       "CSNP interval value\n"
       "Specify interval for level-1 CSNPs\n")

DEFUN (csnp_interval_l2,
       csnp_interval_l2_cmd,
       "isis csnp-interval <0-65535> level-2",
       "IS-IS commands\n"
       "Set CSNP interval in seconds\n"
       "CSNP interval value\n"
       "Specify interval for level-2 CSNPs\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;
  unsigned long interval;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  interval = atol (argv[0]);

  circuit->csnp_interval[1] = (u_int16_t) interval;

  return CMD_SUCCESS;
}

DEFUN (no_csnp_interval_l2,
       no_csnp_interval_l2_cmd,
       "no isis csnp-interval level-2",
       NO_STR
       "IS-IS commands\n"
       "Set CSNP interval in seconds\n"
       "Specify interval for level-2 CSNPs\n")
{
  struct isis_circuit *circuit;
  struct interface *ifp;

  ifp = vty->index;
  circuit = ifp->info;
  if (circuit == NULL)
    {
      return CMD_WARNING;
    }
  assert (circuit);

  circuit->csnp_interval[1] = CSNP_INTERVAL;

  return CMD_SUCCESS;
}

ALIAS (no_csnp_interval_l2,
       no_csnp_interval_l2_arg_cmd,
       "no isis csnp-interval <0-65535> level-2",
       NO_STR
       "IS-IS commands\n"
       "Set CSNP interval in seconds\n"
       "CSNP interval value\n"
       "Specify interval for level-2 CSNPs\n")

#ifdef HAVE_IPV6
DEFUN (ipv6_router_isis,
       ipv6_router_isis_cmd,
       "ipv6 router isis WORD",
       "IPv6 interface subcommands\n"
       "IPv6 Router interface commands\n"
       "IS-IS Routing for IPv6\n"
       "Routing process tag\n")
{
  struct isis_circuit *c;
  struct interface *ifp;
  struct isis_area *area;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  area = isis_area_lookup (argv[0]);

  /* Prevent more than one circuit per interface */
  if (area)
    c = circuit_lookup_by_ifp (ifp, area->circuit_list);
  else
    c = NULL;

  if (c && (ifp->info != NULL))
    {
      if (c->ipv6_router == 1)
	{
	  vty_out (vty, "ISIS circuit is already defined for IPv6%s",
		   VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }

  /* this is here for ciscopability */
  if (!area)
    {
      vty_out (vty, "Can't find ISIS instance %s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (!c)
    {
      c = circuit_lookup_by_ifp (ifp, isis->init_circ_list);
      c = isis_csm_state_change (ISIS_ENABLE, c, area);
      c->interface = ifp;
      ifp->info = c;
    }

  if (!c)
    return CMD_WARNING;

  c->ipv6_router = 1;
  area->ipv6_circuits++;
  circuit_update_nlpids (c);

  vty->node = INTERFACE_NODE;

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_router_isis,
       no_ipv6_router_isis_cmd,
       "no ipv6 router isis WORD",
       NO_STR
       "IPv6 interface subcommands\n"
       "IPv6 Router interface commands\n"
       "IS-IS Routing for IPv6\n"
       "Routing process tag\n")
{
  struct isis_circuit *c;
  struct interface *ifp;
  struct isis_area *area;

  ifp = (struct interface *) vty->index;
  /* UGLY - will remove l8r
     if (circuit == NULL) {
     return CMD_WARNING;
     } */
  assert (ifp);

  area = isis_area_lookup (argv[0]);
  if (!area)
    {
      vty_out (vty, "Can't find ISIS instance %s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  c = circuit_lookup_by_ifp (ifp, area->circuit_list);
  if (!c)
    return CMD_WARNING;

  c->ipv6_router = 0;
  area->ipv6_circuits--;
  if (c->ip_router == 0)
    isis_csm_state_change (ISIS_DISABLE, c, area);

  return CMD_SUCCESS;
}
#endif /* HAVE_IPV6 */

static struct cmd_node interface_node = {
  INTERFACE_NODE,
  "%s(config-if)# ",
  1,
};

int
isis_if_new_hook (struct interface *ifp)
{
/* FIXME: Discuss if the circuit should be created here
  ifp->info = XMALLOC (MTYPE_ISIS_IF_INFO, sizeof (struct isis_if_info)); */
  ifp->info = NULL;
  return 0;
}

int
isis_if_delete_hook (struct interface *ifp)
{
/* FIXME: Discuss if the circuit should be created here
  XFREE (MTYPE_ISIS_IF_INFO, ifp->info);*/
  ifp->info = NULL;
  return 0;
}

void
isis_circuit_init ()
{
  /* Initialize Zebra interface data structure */
  if_init ();
  if_add_hook (IF_NEW_HOOK, isis_if_new_hook);
  if_add_hook (IF_DELETE_HOOK, isis_if_delete_hook);

  /* Install interface node */
  install_node (&interface_node, isis_interface_config_write);
  install_element (CONFIG_NODE, &interface_cmd);

  install_default (INTERFACE_NODE);
  install_element (INTERFACE_NODE, &interface_desc_cmd);
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);

  install_element (INTERFACE_NODE, &ip_router_isis_cmd);
  install_element (INTERFACE_NODE, &no_ip_router_isis_cmd);

  install_element (INTERFACE_NODE, &isis_circuit_type_cmd);
  install_element (INTERFACE_NODE, &no_isis_circuit_type_cmd);

  install_element (INTERFACE_NODE, &isis_passwd_cmd);
  install_element (INTERFACE_NODE, &no_isis_passwd_cmd);

  install_element (INTERFACE_NODE, &isis_priority_cmd);
  install_element (INTERFACE_NODE, &no_isis_priority_cmd);
  install_element (INTERFACE_NODE, &no_isis_priority_arg_cmd);
  install_element (INTERFACE_NODE, &isis_priority_l1_cmd);
  install_element (INTERFACE_NODE, &no_isis_priority_l1_cmd);
  install_element (INTERFACE_NODE, &no_isis_priority_l1_arg_cmd);
  install_element (INTERFACE_NODE, &isis_priority_l2_cmd);
  install_element (INTERFACE_NODE, &no_isis_priority_l2_cmd);
  install_element (INTERFACE_NODE, &no_isis_priority_l2_arg_cmd);

  install_element (INTERFACE_NODE, &isis_metric_cmd);
  install_element (INTERFACE_NODE, &no_isis_metric_cmd);
  install_element (INTERFACE_NODE, &no_isis_metric_arg_cmd);

  install_element (INTERFACE_NODE, &isis_hello_interval_cmd);
  install_element (INTERFACE_NODE, &no_isis_hello_interval_cmd);
  install_element (INTERFACE_NODE, &no_isis_hello_interval_arg_cmd);
  install_element (INTERFACE_NODE, &isis_hello_interval_l1_cmd);
  install_element (INTERFACE_NODE, &no_isis_hello_interval_l1_cmd);
  install_element (INTERFACE_NODE, &no_isis_hello_interval_l1_arg_cmd);
  install_element (INTERFACE_NODE, &isis_hello_interval_l2_cmd);
  install_element (INTERFACE_NODE, &no_isis_hello_interval_l2_cmd);
  install_element (INTERFACE_NODE, &no_isis_hello_interval_l2_arg_cmd);

  install_element (INTERFACE_NODE, &isis_hello_multiplier_cmd);
  install_element (INTERFACE_NODE, &no_isis_hello_multiplier_cmd);
  install_element (INTERFACE_NODE, &no_isis_hello_multiplier_arg_cmd);
  install_element (INTERFACE_NODE, &isis_hello_multiplier_l1_cmd);
  install_element (INTERFACE_NODE, &no_isis_hello_multiplier_l1_cmd);
  install_element (INTERFACE_NODE, &no_isis_hello_multiplier_l1_arg_cmd);
  install_element (INTERFACE_NODE, &isis_hello_multiplier_l2_cmd);
  install_element (INTERFACE_NODE, &no_isis_hello_multiplier_l2_cmd);
  install_element (INTERFACE_NODE, &no_isis_hello_multiplier_l2_arg_cmd);

  install_element (INTERFACE_NODE, &isis_hello_cmd);
  install_element (INTERFACE_NODE, &no_isis_hello_cmd);
  install_element (INTERFACE_NODE, &csnp_interval_cmd);
  install_element (INTERFACE_NODE, &no_csnp_interval_cmd);
  install_element (INTERFACE_NODE, &no_csnp_interval_arg_cmd);
  install_element (INTERFACE_NODE, &csnp_interval_l1_cmd);
  install_element (INTERFACE_NODE, &no_csnp_interval_l1_cmd);
  install_element (INTERFACE_NODE, &no_csnp_interval_l1_arg_cmd);
  install_element (INTERFACE_NODE, &csnp_interval_l2_cmd);
  install_element (INTERFACE_NODE, &no_csnp_interval_l2_cmd);
  install_element (INTERFACE_NODE, &no_csnp_interval_l2_arg_cmd);

#ifdef HAVE_IPV6
  install_element (INTERFACE_NODE, &ipv6_router_isis_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_router_isis_cmd);
#endif
}
