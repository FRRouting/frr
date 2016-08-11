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
#include "vrf.h"
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
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_tlv.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_network.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_dr.h"
#include "isisd/isisd.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_events.h"

/*
 * Prototypes.
 */
int isis_interface_config_write(struct vty *);
int isis_if_new_hook(struct interface *);
int isis_if_delete_hook(struct interface *);

struct isis_circuit *
isis_circuit_new ()
{
  struct isis_circuit *circuit;
  int i;

  circuit = XCALLOC (MTYPE_ISIS_CIRCUIT, sizeof (struct isis_circuit));
  if (circuit == NULL)
    {
      zlog_err ("Can't malloc isis circuit");
      return NULL;
    }

  /*
   * Default values
   */
  circuit->is_type = IS_LEVEL_1_AND_2;
  circuit->flags = 0;
  circuit->pad_hellos = 1;
  for (i = 0; i < 2; i++)
    {
      circuit->hello_interval[i] = DEFAULT_HELLO_INTERVAL;
      circuit->hello_multiplier[i] = DEFAULT_HELLO_MULTIPLIER;
      circuit->csnp_interval[i] = DEFAULT_CSNP_INTERVAL;
      circuit->psnp_interval[i] = DEFAULT_PSNP_INTERVAL;
      circuit->priority[i] = DEFAULT_PRIORITY;
      circuit->metric[i] = DEFAULT_CIRCUIT_METRIC;
      circuit->te_metric[i] = DEFAULT_CIRCUIT_METRIC;
    }

  return circuit;
}

void
isis_circuit_del (struct isis_circuit *circuit)
{
  if (!circuit)
    return;

  isis_circuit_if_unbind (circuit, circuit->interface);

  /* and lastly the circuit itself */
  XFREE (MTYPE_ISIS_CIRCUIT, circuit);

  return;
}

void
isis_circuit_configure (struct isis_circuit *circuit, struct isis_area *area)
{
  assert (area);
  circuit->area = area;

  /*
   * Whenever the is-type of an area is changed, the is-type of each circuit
   * in that area is updated to a non-empty subset of the area is-type.
   * Inversely, when configuring a new circuit, this property should be
   * ensured as well.
   */
  if (area->is_type != IS_LEVEL_1_AND_2)
    circuit->is_type = area->is_type;

  /*
   * Add the circuit into area
   */
  listnode_add (area->circuit_list, circuit);

  circuit->idx = flags_get_index (&area->flags);

  return;
}

void
isis_circuit_deconfigure (struct isis_circuit *circuit, struct isis_area *area)
{
  /* Free the index of SRM and SSN flags */
  flags_free_index (&area->flags, circuit->idx);
  circuit->idx = 0;
  /* Remove circuit from area */
  assert (circuit->area == area);
  listnode_delete (area->circuit_list, circuit);
  circuit->area = NULL;

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
      {
        assert (ifp->info == circuit);
        return circuit;
      }

  return NULL;
}

struct isis_circuit *
circuit_scan_by_ifp (struct interface *ifp)
{
  struct isis_area *area;
  struct listnode *node;
  struct isis_circuit *circuit;

  if (ifp->info)
    return (struct isis_circuit *)ifp->info;

  if (isis->area_list)
    {
      for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
        {
          circuit = circuit_lookup_by_ifp (ifp, area->circuit_list);
          if (circuit)
            return circuit;
        }
    }
  return circuit_lookup_by_ifp (ifp, isis->init_circ_list);
}

void
isis_circuit_add_addr (struct isis_circuit *circuit,
		       struct connected *connected)
{
  struct listnode *node;
  struct prefix_ipv4 *ipv4;
#if defined(EXTREME_DEBUG)
  char buf[PREFIX2STR_BUFFER];
#endif
  struct prefix_ipv6 *ipv6;

  if (connected->address->family == AF_INET)
    {
      u_int32_t addr = connected->address->u.prefix4.s_addr;
      addr = ntohl (addr);
      if (IPV4_NET0(addr) ||
          IPV4_NET127(addr) ||
          IN_CLASSD(addr) ||
          IPV4_LINKLOCAL(addr))
        return;

      for (ALL_LIST_ELEMENTS_RO (circuit->ip_addrs, node, ipv4))
        if (prefix_same ((struct prefix *) ipv4, connected->address))
          return;

      ipv4 = prefix_ipv4_new ();
      ipv4->prefixlen = connected->address->prefixlen;
      ipv4->prefix = connected->address->u.prefix4;
      listnode_add (circuit->ip_addrs, ipv4);
      if (circuit->area)
        lsp_regenerate_schedule (circuit->area, circuit->is_type, 0);

#ifdef EXTREME_DEBUG
      prefix2str (connected->address, buf, sizeof (buf));
      zlog_debug ("Added IP address %s to circuit %d", buf,
		 circuit->circuit_id);
#endif /* EXTREME_DEBUG */
    }
  if (connected->address->family == AF_INET6)
    {
      if (IN6_IS_ADDR_LOOPBACK(&connected->address->u.prefix6))
        return;

      for (ALL_LIST_ELEMENTS_RO (circuit->ipv6_link, node, ipv6))
        if (prefix_same ((struct prefix *) ipv6, connected->address))
          return;
      for (ALL_LIST_ELEMENTS_RO (circuit->ipv6_non_link, node, ipv6))
        if (prefix_same ((struct prefix *) ipv6, connected->address))
          return;

      ipv6 = prefix_ipv6_new ();
      ipv6->prefixlen = connected->address->prefixlen;
      ipv6->prefix = connected->address->u.prefix6;

      if (IN6_IS_ADDR_LINKLOCAL (&ipv6->prefix))
	listnode_add (circuit->ipv6_link, ipv6);
      else
	listnode_add (circuit->ipv6_non_link, ipv6);
      if (circuit->area)
        lsp_regenerate_schedule (circuit->area, circuit->is_type, 0);

#ifdef EXTREME_DEBUG
      prefix2str (connected->address, buf, sizeof (buf));
      zlog_debug ("Added IPv6 address %s to circuit %d", buf,
		 circuit->circuit_id);
#endif /* EXTREME_DEBUG */
    }
  return;
}

void
isis_circuit_del_addr (struct isis_circuit *circuit,
		       struct connected *connected)
{
  struct prefix_ipv4 *ipv4, *ip = NULL;
  struct listnode *node;
  char buf[PREFIX2STR_BUFFER];
#ifdef HAVE_IPV6
  struct prefix_ipv6 *ipv6, *ip6 = NULL;
  int found = 0;
#endif /* HAVE_IPV6 */

  if (connected->address->family == AF_INET)
    {
      ipv4 = prefix_ipv4_new ();
      ipv4->prefixlen = connected->address->prefixlen;
      ipv4->prefix = connected->address->u.prefix4;

      for (ALL_LIST_ELEMENTS_RO (circuit->ip_addrs, node, ip))
        if (prefix_same ((struct prefix *) ip, (struct prefix *) ipv4))
          break;

      if (ip)
	{
	  listnode_delete (circuit->ip_addrs, ip);
          if (circuit->area)
            lsp_regenerate_schedule (circuit->area, circuit->is_type, 0);
	}
      else
	{
	  prefix2str (connected->address, buf, sizeof (buf));
	  zlog_warn ("Nonexitant ip address %s removal attempt from \
                      circuit %d", buf, circuit->circuit_id);
	  zlog_warn ("Current ip addresses on %s:", circuit->interface->name);
	  for (ALL_LIST_ELEMENTS_RO(circuit->ip_addrs, node, ip))
	    {
	      prefix2str((struct prefix*)ip, (char *)buf, BUFSIZ);
	      zlog_warn("  %s", buf);
	    }
	  zlog_warn("End of addresses");
	}

      prefix_ipv4_free (ipv4);
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
	  prefix2str (connected->address, buf, sizeof (buf));
	  zlog_warn ("Nonexitant ip address %s removal attempt from \
		      circuit %d", buf, circuit->circuit_id);
	  zlog_warn ("Current ip addresses on %s:", circuit->interface->name);
	  for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_link, node, ip6))
	    {
	      prefix2str((struct prefix*)ip6, (char *)buf, BUFSIZ);
	      zlog_warn("  %s", buf);
	    }
	  zlog_warn(" -----");
	  for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_non_link, node, ip6))
	    {
	      prefix2str((struct prefix*)ip6, (char *)buf, BUFSIZ);
	      zlog_warn("  %s", buf);
	    }
	  zlog_warn("End of addresses");
	}
      else if (circuit->area)
	  lsp_regenerate_schedule (circuit->area, circuit->is_type, 0);

      prefix_ipv6_free (ipv6);
    }
#endif /* HAVE_IPV6 */
  return;
}

static u_char
isis_circuit_id_gen (struct interface *ifp)
{
  u_char id = 0;
  char ifname[16];
  unsigned int i;
  int start = -1, end = -1;

  /*
   * Get a stable circuit id from ifname. This makes
   * the ifindex from flapping when netdevs are created
   * and deleted on the fly. Note that this circuit id
   * is used in pseudo lsps so it is better to be stable.
   * The following code works on any reasonanle ifname
   * like: eth1 or trk-1.1 etc.
   */
  for (i = 0; i < strlen (ifp->name); i++)
    {
      if (isdigit((unsigned char)ifp->name[i]))
        {
          if (start < 0)
            {
              start = i;
              end = i + 1;
            }
          else
            {
              end = i + 1;
            }
        }
      else if (start >= 0)
        break;
    }

  if ((start >= 0) && (end >= start) && (end - start) < 16)
    {
      memset (ifname, 0, 16);
      strncpy (ifname, &ifp->name[start], end - start);
      id = (u_char)atoi(ifname);
    }

  /* Try to be unique. */
  if (!id)
    id = (u_char)((ifp->ifindex & 0xff) | 0x80);

  return id;
}

void
isis_circuit_if_add (struct isis_circuit *circuit, struct interface *ifp)
{
  struct listnode *node, *nnode;
  struct connected *conn;

  circuit->circuit_id = isis_circuit_id_gen (ifp);

  isis_circuit_if_bind (circuit, ifp);
  /*  isis_circuit_update_addrs (circuit, ifp); */

  if (if_is_broadcast (ifp))
    {
      if (circuit->circ_type_config == CIRCUIT_T_P2P)
        circuit->circ_type = CIRCUIT_T_P2P;
      else
        circuit->circ_type = CIRCUIT_T_BROADCAST;
    }
  else if (if_is_pointopoint (ifp))
    {
      circuit->circ_type = CIRCUIT_T_P2P;
    }
  else if (if_is_loopback (ifp))
    {
      circuit->circ_type = CIRCUIT_T_LOOPBACK;
      circuit->is_passive = 1;
    }
  else
    {
      /* It's normal in case of loopback etc. */
      if (isis->debugs & DEBUG_EVENTS)
        zlog_debug ("isis_circuit_if_add: unsupported media");
      circuit->circ_type = CIRCUIT_T_UNKNOWN;
    }

  circuit->ip_addrs = list_new ();
#ifdef HAVE_IPV6
  circuit->ipv6_link = list_new ();
  circuit->ipv6_non_link = list_new ();
#endif /* HAVE_IPV6 */

  for (ALL_LIST_ELEMENTS (ifp->connected, node, nnode, conn))
    isis_circuit_add_addr (circuit, conn);

  return;
}

void
isis_circuit_if_del (struct isis_circuit *circuit, struct interface *ifp)
{
  struct listnode *node, *nnode;
  struct connected *conn;

  assert (circuit->interface == ifp);

  /* destroy addresses */
  for (ALL_LIST_ELEMENTS (ifp->connected, node, nnode, conn))
    isis_circuit_del_addr (circuit, conn);

  if (circuit->ip_addrs)
    {
      assert (listcount(circuit->ip_addrs) == 0);
      list_delete (circuit->ip_addrs);
      circuit->ip_addrs = NULL;
    }

#ifdef HAVE_IPV6
  if (circuit->ipv6_link)
    {
      assert (listcount(circuit->ipv6_link) == 0);
      list_delete (circuit->ipv6_link);
      circuit->ipv6_link = NULL;
    }

  if (circuit->ipv6_non_link)
    {
      assert (listcount(circuit->ipv6_non_link) == 0);
      list_delete (circuit->ipv6_non_link);
      circuit->ipv6_non_link = NULL;
    }
#endif /* HAVE_IPV6 */

  circuit->circ_type = CIRCUIT_T_UNKNOWN;
  circuit->circuit_id = 0;

  return;
}

void
isis_circuit_if_bind (struct isis_circuit *circuit, struct interface *ifp)
{
  assert (circuit != NULL);
  assert (ifp != NULL);
  if (circuit->interface)
    assert (circuit->interface == ifp);
  else
    circuit->interface = ifp;
  if (ifp->info)
    assert (ifp->info == circuit);
  else
    ifp->info = circuit;
}

void
isis_circuit_if_unbind (struct isis_circuit *circuit, struct interface *ifp)
{
  assert (circuit != NULL);
  assert (ifp != NULL);
  assert (circuit->interface == ifp);
  assert (ifp->info == circuit);
  circuit->interface = NULL;
  ifp->info = NULL;
}

static void
isis_circuit_update_all_srmflags (struct isis_circuit *circuit, int is_set)
{
  struct isis_area *area;
  struct isis_lsp *lsp;
  dnode_t *dnode, *dnode_next;
  int level;

  assert (circuit);
  area = circuit->area;
  assert (area);
  for (level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++)
    {
      if (level & circuit->is_type)
        {
          if (area->lspdb[level - 1] &&
              dict_count (area->lspdb[level - 1]) > 0)
            {
              for (dnode = dict_first (area->lspdb[level - 1]);
                   dnode != NULL; dnode = dnode_next)
                {
                  dnode_next = dict_next (area->lspdb[level - 1], dnode);
                  lsp = dnode_get (dnode);
                  if (is_set)
                    {
                      ISIS_SET_FLAG (lsp->SRMflags, circuit);
                    }
                  else
                    {
                      ISIS_CLEAR_FLAG (lsp->SRMflags, circuit);
                    }
                }
            }
        }
    }
}

size_t
isis_circuit_pdu_size(struct isis_circuit *circuit)
{
  return ISO_MTU(circuit);
}

void
isis_circuit_stream(struct isis_circuit *circuit, struct stream **stream)
{
  size_t stream_size = isis_circuit_pdu_size(circuit);

  if (!*stream)
    {
      *stream = stream_new(stream_size);
    }
  else
    {
      if (STREAM_SIZE(*stream) != stream_size)
        stream_resize(*stream, stream_size);
      stream_reset(*stream);
    }
}

int
isis_circuit_up (struct isis_circuit *circuit)
{
  int retv;

  /* Set the flags for all the lsps of the circuit. */
  isis_circuit_update_all_srmflags (circuit, 1);

  if (circuit->state == C_STATE_UP)
    return ISIS_OK;

  if (circuit->is_passive)
    return ISIS_OK;

  if (circuit->area->lsp_mtu > isis_circuit_pdu_size(circuit))
    {
      zlog_err("Interface MTU %zu on %s is too low to support area lsp mtu %u!",
               isis_circuit_pdu_size(circuit), circuit->interface->name,
               circuit->area->lsp_mtu);
      isis_circuit_update_all_srmflags(circuit, 0);
      return ISIS_ERROR;
    }

  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    {
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

      circuit->u.bc.adjdb[0] = list_new ();
      circuit->u.bc.adjdb[1] = list_new ();

      /*
       * ISO 10589 - 8.4.1 Enabling of broadcast circuits
       */

      /* initilizing the hello sending threads
       * for a broadcast IF
       */

      /* 8.4.1 a) commence sending of IIH PDUs */

      if (circuit->is_type & IS_LEVEL_1)
        {
          thread_add_event (master, send_lan_l1_hello, circuit, 0);
          circuit->u.bc.lan_neighs[0] = list_new ();
        }

      if (circuit->is_type & IS_LEVEL_2)
        {
          thread_add_event (master, send_lan_l2_hello, circuit, 0);
          circuit->u.bc.lan_neighs[1] = list_new ();
        }

      /* 8.4.1 b) FIXME: solicit ES - 8.4.6 */
      /* 8.4.1 c) FIXME: listen for ESH PDUs */

      /* 8.4.1 d) */
      /* dr election will commence in... */
      if (circuit->is_type & IS_LEVEL_1)
        THREAD_TIMER_ON (master, circuit->u.bc.t_run_dr[0], isis_run_dr_l1,
            circuit, 2 * circuit->hello_interval[0]);
      if (circuit->is_type & IS_LEVEL_2)
        THREAD_TIMER_ON (master, circuit->u.bc.t_run_dr[1], isis_run_dr_l2,
            circuit, 2 * circuit->hello_interval[1]);
    }
  else
    {
      /* initializing the hello send threads
       * for a ptp IF
       */
      circuit->u.p2p.neighbor = NULL;
      thread_add_event (master, send_p2p_hello, circuit, 0);
    }

  /* initializing PSNP timers */
  if (circuit->is_type & IS_LEVEL_1)
    THREAD_TIMER_ON (master, circuit->t_send_psnp[0], send_l1_psnp, circuit,
                     isis_jitter (circuit->psnp_interval[0], PSNP_JITTER));

  if (circuit->is_type & IS_LEVEL_2)
    THREAD_TIMER_ON (master, circuit->t_send_psnp[1], send_l2_psnp, circuit,
                     isis_jitter (circuit->psnp_interval[1], PSNP_JITTER));

  /* unified init for circuits; ignore warnings below this level */
  retv = isis_sock_init (circuit);
  if (retv != ISIS_OK)
    {
      isis_circuit_down (circuit);
      return retv;
    }

  /* initialize the circuit streams after opening connection */
  isis_circuit_stream(circuit, &circuit->rcv_stream);
  isis_circuit_stream(circuit, &circuit->snd_stream);

#ifdef GNU_LINUX
  THREAD_READ_ON (master, circuit->t_read, isis_receive, circuit,
                  circuit->fd);
#else
  THREAD_TIMER_ON (master, circuit->t_read, isis_receive, circuit,
                   circuit->fd);
#endif

  circuit->lsp_queue = list_new ();
  circuit->lsp_queue_last_cleared = time (NULL);

  return ISIS_OK;
}

void
isis_circuit_down (struct isis_circuit *circuit)
{
  if (circuit->state != C_STATE_UP)
    return;

  /* Clear the flags for all the lsps of the circuit. */
  isis_circuit_update_all_srmflags (circuit, 0);

  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    {
      /* destroy neighbour lists */
      if (circuit->u.bc.lan_neighs[0])
        {
          list_delete (circuit->u.bc.lan_neighs[0]);
          circuit->u.bc.lan_neighs[0] = NULL;
        }
      if (circuit->u.bc.lan_neighs[1])
        {
          list_delete (circuit->u.bc.lan_neighs[1]);
          circuit->u.bc.lan_neighs[1] = NULL;
        }
      /* destroy adjacency databases */
      if (circuit->u.bc.adjdb[0])
        {
          circuit->u.bc.adjdb[0]->del = isis_delete_adj;
          list_delete (circuit->u.bc.adjdb[0]);
          circuit->u.bc.adjdb[0] = NULL;
        }
      if (circuit->u.bc.adjdb[1])
        {
          circuit->u.bc.adjdb[1]->del = isis_delete_adj;
          list_delete (circuit->u.bc.adjdb[1]);
          circuit->u.bc.adjdb[1] = NULL;
        }
      if (circuit->u.bc.is_dr[0])
        {
          isis_dr_resign (circuit, 1);
          circuit->u.bc.is_dr[0] = 0;
        }
      memset (circuit->u.bc.l1_desig_is, 0, ISIS_SYS_ID_LEN + 1);
      if (circuit->u.bc.is_dr[1])
        {
          isis_dr_resign (circuit, 2);
          circuit->u.bc.is_dr[1] = 0;
        }
      memset (circuit->u.bc.l2_desig_is, 0, ISIS_SYS_ID_LEN + 1);
      memset (circuit->u.bc.snpa, 0, ETH_ALEN);

      THREAD_TIMER_OFF (circuit->u.bc.t_send_lan_hello[0]);
      THREAD_TIMER_OFF (circuit->u.bc.t_send_lan_hello[1]);
      THREAD_TIMER_OFF (circuit->u.bc.t_run_dr[0]);
      THREAD_TIMER_OFF (circuit->u.bc.t_run_dr[1]);
      THREAD_TIMER_OFF (circuit->u.bc.t_refresh_pseudo_lsp[0]);
      THREAD_TIMER_OFF (circuit->u.bc.t_refresh_pseudo_lsp[1]);
      circuit->lsp_regenerate_pending[0] = 0;
      circuit->lsp_regenerate_pending[1] = 0;
    }
  else if (circuit->circ_type == CIRCUIT_T_P2P)
    {
      isis_delete_adj (circuit->u.p2p.neighbor);
      circuit->u.p2p.neighbor = NULL;
      THREAD_TIMER_OFF (circuit->u.p2p.t_send_p2p_hello);
    }

  /* Cancel all active threads */
  THREAD_TIMER_OFF (circuit->t_send_csnp[0]);
  THREAD_TIMER_OFF (circuit->t_send_csnp[1]);
  THREAD_TIMER_OFF (circuit->t_send_psnp[0]);
  THREAD_TIMER_OFF (circuit->t_send_psnp[1]);
  THREAD_OFF (circuit->t_read);

  if (circuit->lsp_queue)
    {
      circuit->lsp_queue->del = NULL;
      list_delete (circuit->lsp_queue);
      circuit->lsp_queue = NULL;
    }

  /* send one gratuitous hello to spead up convergence */
  if (circuit->is_type & IS_LEVEL_1)
    send_hello (circuit, IS_LEVEL_1);
  if (circuit->is_type & IS_LEVEL_2)
    send_hello (circuit, IS_LEVEL_2);

  circuit->upadjcount[0] = 0;
  circuit->upadjcount[1] = 0;

  /* close the socket */
  if (circuit->fd)
    {
      close (circuit->fd);
      circuit->fd = 0;
    }

  if (circuit->rcv_stream != NULL)
    {
      stream_free (circuit->rcv_stream);
      circuit->rcv_stream = NULL;
    }

  if (circuit->snd_stream != NULL)
    {
      stream_free (circuit->snd_stream);
      circuit->snd_stream = NULL;
    }

  thread_cancel_event (master, circuit);

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

void
isis_circuit_print_vty (struct isis_circuit *circuit, struct vty *vty,
                        char detail)
{
  if (detail == ISIS_UI_LEVEL_BRIEF)
    {
      vty_out (vty, "  %-12s", circuit->interface->name);
      vty_out (vty, "0x%-7x", circuit->circuit_id);
      vty_out (vty, "%-9s", circuit_state2string (circuit->state));
      vty_out (vty, "%-9s", circuit_type2string (circuit->circ_type));
      vty_out (vty, "%-9s", circuit_t2string (circuit->is_type));
      vty_out (vty, "%s", VTY_NEWLINE);
    }

  if (detail == ISIS_UI_LEVEL_DETAIL)
    {
      struct listnode *node;
      struct prefix *ip_addr;
      char buf[BUFSIZ];

      vty_out (vty, "  Interface: %s", circuit->interface->name);
      vty_out (vty, ", State: %s", circuit_state2string (circuit->state));
      if (circuit->is_passive)
        vty_out (vty, ", Passive");
      else
        vty_out (vty, ", Active");
      vty_out (vty, ", Circuit Id: 0x%x", circuit->circuit_id);
      vty_out (vty, "%s", VTY_NEWLINE);
      vty_out (vty, "    Type: %s", circuit_type2string (circuit->circ_type));
      vty_out (vty, ", Level: %s", circuit_t2string (circuit->is_type));
      if (circuit->circ_type == CIRCUIT_T_BROADCAST)
        vty_out (vty, ", SNPA: %-10s", snpa_print (circuit->u.bc.snpa));
      vty_out (vty, "%s", VTY_NEWLINE);
      if (circuit->is_type & IS_LEVEL_1)
        {
          vty_out (vty, "    Level-1 Information:%s", VTY_NEWLINE);
          if (circuit->area->newmetric)
            vty_out (vty, "      Metric: %d", circuit->te_metric[0]);
          else
            vty_out (vty, "      Metric: %d",
                     circuit->metric[0]);
          if (!circuit->is_passive)
            {
              vty_out (vty, ", Active neighbors: %u%s",
                       circuit->upadjcount[0], VTY_NEWLINE);
              vty_out (vty, "      Hello interval: %u, "
                            "Holddown count: %u %s%s",
                       circuit->hello_interval[0],
                       circuit->hello_multiplier[0],
                       (circuit->pad_hellos ? "(pad)" : "(no-pad)"),
                       VTY_NEWLINE);
              vty_out (vty, "      CNSP interval: %u, "
                            "PSNP interval: %u%s",
                       circuit->csnp_interval[0],
                       circuit->psnp_interval[0], VTY_NEWLINE);
              if (circuit->circ_type == CIRCUIT_T_BROADCAST)
                vty_out (vty, "      LAN Priority: %u, %s%s",
                         circuit->priority[0],
                         (circuit->u.bc.is_dr[0] ? \
                          "is DIS" : "is not DIS"), VTY_NEWLINE);
            }
          else
            {
              vty_out (vty, "%s", VTY_NEWLINE);
            }
        }
      if (circuit->is_type & IS_LEVEL_2)
        {
          vty_out (vty, "    Level-2 Information:%s", VTY_NEWLINE);
          if (circuit->area->newmetric)
            vty_out (vty, "      Metric: %d", circuit->te_metric[1]);
          else
            vty_out (vty, "      Metric: %d",
                     circuit->metric[1]);
          if (!circuit->is_passive)
            {
              vty_out (vty, ", Active neighbors: %u%s",
                       circuit->upadjcount[1], VTY_NEWLINE);
              vty_out (vty, "      Hello interval: %u, "
                            "Holddown count: %u %s%s",
                       circuit->hello_interval[1],
                       circuit->hello_multiplier[1],
                       (circuit->pad_hellos ? "(pad)" : "(no-pad)"),
                       VTY_NEWLINE);
              vty_out (vty, "      CNSP interval: %u, "
                            "PSNP interval: %u%s",
                       circuit->csnp_interval[1],
                       circuit->psnp_interval[1], VTY_NEWLINE);
              if (circuit->circ_type == CIRCUIT_T_BROADCAST)
                vty_out (vty, "      LAN Priority: %u, %s%s",
                         circuit->priority[1],
                         (circuit->u.bc.is_dr[1] ? \
                          "is DIS" : "is not DIS"), VTY_NEWLINE);
            }
          else
            {
              vty_out (vty, "%s", VTY_NEWLINE);
            }
        }
      if (circuit->ip_addrs && listcount (circuit->ip_addrs) > 0)
        {
          vty_out (vty, "    IP Prefix(es):%s", VTY_NEWLINE);
          for (ALL_LIST_ELEMENTS_RO (circuit->ip_addrs, node, ip_addr))
            {
              prefix2str (ip_addr, buf, sizeof (buf)),
              vty_out (vty, "      %s%s", buf, VTY_NEWLINE);
            }
        }
      if (circuit->ipv6_link && listcount(circuit->ipv6_link) > 0)
        {
          vty_out(vty, "    IPv6 Link-Locals:%s", VTY_NEWLINE);
          for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_link, node, ip_addr))
            {
              prefix2str(ip_addr, (char*)buf, BUFSIZ),
              vty_out(vty, "      %s%s", buf, VTY_NEWLINE);
            }
        }
      if (circuit->ipv6_link && listcount(circuit->ipv6_non_link) > 0)
        {
          vty_out(vty, "    IPv6 Prefixes:%s", VTY_NEWLINE);
          for (ALL_LIST_ELEMENTS_RO(circuit->ipv6_non_link, node, ip_addr))
            {
              prefix2str(ip_addr, (char*)buf, BUFSIZ),
              vty_out(vty, "      %s%s", buf, VTY_NEWLINE);
            }
        }

      vty_out (vty, "%s", VTY_NEWLINE);
    }
  return;
}

int
isis_interface_config_write (struct vty *vty)
{
  int write = 0;
  struct listnode *node, *node2;
  struct interface *ifp;
  struct isis_area *area;
  struct isis_circuit *circuit;
  int i;

  for (ALL_LIST_ELEMENTS_RO (vrf_iflist (VRF_DEFAULT), node, ifp))
    {
      if (ifp->ifindex == IFINDEX_DELETED)
        continue;

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
          circuit = circuit_lookup_by_ifp (ifp, area->circuit_list);
          if (circuit == NULL)
            continue;
          if (circuit->ip_router)
            {
              vty_out (vty, " ip router isis %s%s", area->area_tag,
                       VTY_NEWLINE);
              write++;
            }
          if (circuit->is_passive)
            {
              vty_out (vty, " isis passive%s", VTY_NEWLINE);
              write++;
            }
          if (circuit->circ_type_config == CIRCUIT_T_P2P)
            {
              vty_out (vty, " isis network point-to-point%s", VTY_NEWLINE);
              write++;
            }
#ifdef HAVE_IPV6
          if (circuit->ipv6_router)
            {
              vty_out (vty, " ipv6 router isis %s%s", area->area_tag,
                  VTY_NEWLINE);
              write++;
            }
#endif /* HAVE_IPV6 */

          /* ISIS - circuit type */
          if (circuit->is_type == IS_LEVEL_1)
            {
              vty_out (vty, " isis circuit-type level-1%s", VTY_NEWLINE);
              write++;
            }
          else
            {
              if (circuit->is_type == IS_LEVEL_2)
                {
                  vty_out (vty, " isis circuit-type level-2-only%s",
                           VTY_NEWLINE);
                  write++;
                }
            }

          /* ISIS - CSNP interval */
          if (circuit->csnp_interval[0] == circuit->csnp_interval[1])
            {
              if (circuit->csnp_interval[0] != DEFAULT_CSNP_INTERVAL)
                {
                  vty_out (vty, " isis csnp-interval %d%s",
                           circuit->csnp_interval[0], VTY_NEWLINE);
                  write++;
                }
            }
          else
          {
            for (i = 0; i < 2; i++)
              {
                if (circuit->csnp_interval[i] != DEFAULT_CSNP_INTERVAL)
                  {
                    vty_out (vty, " isis csnp-interval %d level-%d%s",
                             circuit->csnp_interval[i], i + 1, VTY_NEWLINE);
                    write++;
                  }
              }
          }

          /* ISIS - PSNP interval */
          if (circuit->psnp_interval[0] == circuit->psnp_interval[1])
            {
              if (circuit->psnp_interval[0] != DEFAULT_PSNP_INTERVAL)
                {
                  vty_out (vty, " isis psnp-interval %d%s",
                           circuit->psnp_interval[0], VTY_NEWLINE);
                  write++;
                }
            }
          else
            {
              for (i = 0; i < 2; i++)
                {
                  if (circuit->psnp_interval[i] != DEFAULT_PSNP_INTERVAL)
                  {
                    vty_out (vty, " isis psnp-interval %d level-%d%s",
                             circuit->psnp_interval[i], i + 1, VTY_NEWLINE);
                    write++;
                  }
                }
            }

          /* ISIS - Hello padding - Defaults to true so only display if false */
          if (circuit->pad_hellos == 0)
            {
              vty_out (vty, " no isis hello padding%s", VTY_NEWLINE);
              write++;
            }

          /* ISIS - Hello interval */
          if (circuit->hello_interval[0] == circuit->hello_interval[1])
            {
              if (circuit->hello_interval[0] != DEFAULT_HELLO_INTERVAL)
                {
                  vty_out (vty, " isis hello-interval %d%s",
                           circuit->hello_interval[0], VTY_NEWLINE);
                  write++;
                }
            }
          else
            {
              for (i = 0; i < 2; i++)
                {
                  if (circuit->hello_interval[i] != DEFAULT_HELLO_INTERVAL)
                    {
                      vty_out (vty, " isis hello-interval %d level-%d%s",
                               circuit->hello_interval[i], i + 1, VTY_NEWLINE);
                      write++;
                    }
                }
            }

          /* ISIS - Hello Multiplier */
          if (circuit->hello_multiplier[0] == circuit->hello_multiplier[1])
            {
              if (circuit->hello_multiplier[0] != DEFAULT_HELLO_MULTIPLIER)
                {
                  vty_out (vty, " isis hello-multiplier %d%s",
                           circuit->hello_multiplier[0], VTY_NEWLINE);
                  write++;
                }
            }
          else
            {
              for (i = 0; i < 2; i++)
                {
                  if (circuit->hello_multiplier[i] != DEFAULT_HELLO_MULTIPLIER)
                    {
                      vty_out (vty, " isis hello-multiplier %d level-%d%s",
                               circuit->hello_multiplier[i], i + 1,
                               VTY_NEWLINE);
                      write++;
                    }
                }
            }

          /* ISIS - Priority */
          if (circuit->priority[0] == circuit->priority[1])
            {
              if (circuit->priority[0] != DEFAULT_PRIORITY)
                {
                  vty_out (vty, " isis priority %d%s",
                           circuit->priority[0], VTY_NEWLINE);
                  write++;
                }
            }
          else
            {
              for (i = 0; i < 2; i++)
                {
                  if (circuit->priority[i] != DEFAULT_PRIORITY)
                    {
                      vty_out (vty, " isis priority %d level-%d%s",
                               circuit->priority[i], i + 1, VTY_NEWLINE);
                      write++;
                    }
                }
            }

          /* ISIS - Metric */
          if (circuit->te_metric[0] == circuit->te_metric[1])
            {
              if (circuit->te_metric[0] != DEFAULT_CIRCUIT_METRIC)
                {
                  vty_out (vty, " isis metric %d%s", circuit->te_metric[0],
                           VTY_NEWLINE);
                  write++;
                }
            }
          else
            {
              for (i = 0; i < 2; i++)
                {
                  if (circuit->te_metric[i] != DEFAULT_CIRCUIT_METRIC)
                    {
                      vty_out (vty, " isis metric %d level-%d%s",
                               circuit->te_metric[i], i + 1, VTY_NEWLINE);
                      write++;
                    }
                }
            }
          if (circuit->passwd.type == ISIS_PASSWD_TYPE_HMAC_MD5)
            {
              vty_out (vty, " isis password md5 %s%s", circuit->passwd.passwd,
                       VTY_NEWLINE);
              write++;
            }
          else if (circuit->passwd.type == ISIS_PASSWD_TYPE_CLEARTXT)
            {
              vty_out (vty, " isis password clear %s%s", circuit->passwd.passwd,
                       VTY_NEWLINE);
              write++;
            }
        }
      vty_out (vty, "!%s", VTY_NEWLINE);
    }

  return write;
}

struct isis_circuit *
isis_circuit_create (struct isis_area *area, struct interface *ifp)
{
  struct isis_circuit *circuit = circuit_scan_by_ifp (ifp);
  if (circuit && circuit->area)
    return NULL;
  circuit = isis_csm_state_change (ISIS_ENABLE, circuit, area);
  assert (circuit->state == C_STATE_CONF || circuit->state == C_STATE_UP);
  isis_circuit_if_bind (circuit, ifp);
  return circuit;
}

void
isis_circuit_af_set (struct isis_circuit *circuit, bool ip_router, bool ipv6_router)
{
  struct isis_area *area = circuit->area;
  bool change = circuit->ip_router != ip_router || circuit->ipv6_router != ipv6_router;
  bool was_enabled = !!circuit->area;

  area->ip_circuits   += ip_router   - circuit->ip_router;
  area->ipv6_circuits += ipv6_router - circuit->ipv6_router;
  circuit->ip_router   = ip_router;
  circuit->ipv6_router = ipv6_router;

  if (!change)
    return;

  circuit_update_nlpids (circuit);

  if (!ip_router && !ipv6_router)
    isis_csm_state_change (ISIS_DISABLE, circuit, area);
  else if (!was_enabled)
    isis_csm_state_change (ISIS_ENABLE, circuit, area);
  else
    lsp_regenerate_schedule(circuit->area, circuit->is_type, 0);
}

int
isis_circuit_passive_set (struct isis_circuit *circuit, bool passive)
{
  if (circuit->is_passive == passive)
    return 0;

  if (if_is_loopback (circuit->interface) && !passive)
    return -1;

  if (circuit->state != C_STATE_UP)
    {
      circuit->is_passive = passive;
    }
  else
    {
      struct isis_area *area = circuit->area;
      isis_csm_state_change (ISIS_DISABLE, circuit, area);
      circuit->is_passive = passive;
      isis_csm_state_change (ISIS_ENABLE, circuit, area);
    }

  return 0;
}

void
isis_circuit_is_type_set (struct isis_circuit *circuit, int circ_type)
{
  if (circuit->circ_type != circ_type)
    isis_event_circuit_type_change (circuit, circ_type);
}

int
isis_circuit_metric_set (struct isis_circuit *circuit, int level, int metric)
{
  assert (level == IS_LEVEL_1 || level == IS_LEVEL_2);
  if (metric > MAX_WIDE_LINK_METRIC)
    return -1;
  if (circuit->area && circuit->area->oldmetric
      && metric > MAX_NARROW_LINK_METRIC)
    return -1;

  circuit->te_metric[level - 1] = metric;
  circuit->metric[level - 1] = metric;

  if (circuit->area)
    lsp_regenerate_schedule (circuit->area, level, 0);
  return 0;
}

int
isis_circuit_passwd_unset (struct isis_circuit *circuit)
{
  memset(&circuit->passwd, 0, sizeof(circuit->passwd));
  return 0;
}

static int
isis_circuit_passwd_set (struct isis_circuit *circuit, u_char passwd_type, const char *passwd)
{
  int len;

  if (!passwd)
    return -1;

  len = strlen(passwd);
  if (len > 254)
    return -1;

  circuit->passwd.len = len;
  strncpy((char *)circuit->passwd.passwd, passwd, 255);
  circuit->passwd.type = passwd_type;
  return 0;
}

int
isis_circuit_passwd_cleartext_set (struct isis_circuit *circuit, const char *passwd)
{
  return isis_circuit_passwd_set (circuit, ISIS_PASSWD_TYPE_CLEARTXT, passwd);
}

int
isis_circuit_passwd_hmac_md5_set (struct isis_circuit *circuit, const char *passwd)
{
  return isis_circuit_passwd_set (circuit, ISIS_PASSWD_TYPE_HMAC_MD5, passwd);
}
struct cmd_node interface_node = {
  INTERFACE_NODE,
  "%s(config-if)# ",
  1,
};

int
isis_circuit_circ_type_set(struct isis_circuit *circuit, int circ_type)
{
  /* Changing the network type to/of loopback or unknown interfaces
   * is not supported. */
  if (circ_type == CIRCUIT_T_UNKNOWN
      || circ_type == CIRCUIT_T_LOOPBACK
      || circuit->circ_type == CIRCUIT_T_UNKNOWN
      || circuit->circ_type == CIRCUIT_T_LOOPBACK)
    {
      if (circuit->circ_type != circ_type)
        return -1;
      else
        return 0;
    }

  if (circuit->circ_type == circ_type)
    return 0;

  if (circuit->state != C_STATE_UP)
    {
      circuit->circ_type = circ_type;
      circuit->circ_type_config = circ_type;
    }
  else
    {
      struct isis_area *area = circuit->area;
      if (circ_type == CIRCUIT_T_BROADCAST
          && !if_is_broadcast(circuit->interface))
        return -1;

      isis_csm_state_change(ISIS_DISABLE, circuit, area);
      circuit->circ_type = circ_type;
      circuit->circ_type_config = circ_type;
      isis_csm_state_change(ISIS_ENABLE, circuit, area);
    }
  return 0;
}

int
isis_if_new_hook (struct interface *ifp)
{
  return 0;
}

int
isis_if_delete_hook (struct interface *ifp)
{
  struct isis_circuit *circuit;
  /* Clean up the circuit data */
  if (ifp && ifp->info)
    {
      circuit = ifp->info;
      isis_csm_state_change (IF_DOWN_FROM_Z, circuit, circuit->area);
      isis_csm_state_change (ISIS_DISABLE, circuit, circuit->area);
    }

  return 0;
}

void
isis_circuit_init ()
{
  /* Initialize Zebra interface data structure */
  if_add_hook (IF_NEW_HOOK, isis_if_new_hook);
  if_add_hook (IF_DELETE_HOOK, isis_if_delete_hook);

  /* Install interface node */
  install_node (&interface_node, isis_interface_config_write);
  install_element (CONFIG_NODE, &interface_cmd);
  install_element (CONFIG_NODE, &no_interface_cmd);

  install_default (INTERFACE_NODE);
  install_element (INTERFACE_NODE, &interface_desc_cmd);
  install_element (INTERFACE_NODE, &no_interface_desc_cmd);

  isis_vty_init ();
}
