/*
  PIM for Quagga
  Copyright (C) 2008  Everton da Silva Marques

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program; see the file COPYING; if not, write to the
  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
  MA 02110-1301 USA
*/

#include <zebra.h>

#include "zebra/rib.h"

#include "if.h"
#include "log.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"
#include "network.h"
#include "vty.h"
#include "plist.h"

#include "pimd.h"
#include "pim_pim.h"
#include "pim_zebra.h"
#include "pim_iface.h"
#include "pim_str.h"
#include "pim_oil.h"
#include "pim_rpf.h"
#include "pim_time.h"
#include "pim_join.h"
#include "pim_zlookup.h"
#include "pim_ifchannel.h"
#include "pim_rp.h"
#include "pim_igmpv3.h"
#include "pim_jp_agg.h"
#include "pim_nht.h"

#undef PIM_DEBUG_IFADDR_DUMP
#define PIM_DEBUG_IFADDR_DUMP

static struct zclient *zclient = NULL;

static int fib_lookup_if_vif_index(struct in_addr addr);

/* Router-id update message from zebra. */
static int pim_router_id_update_zebra(int command, struct zclient *zclient,
				      zebra_size_t length, vrf_id_t vrf_id)
{
  struct prefix router_id;

  zebra_router_id_update_read(zclient->ibuf, &router_id);

  return 0;
}

static int pim_zebra_if_add(int command, struct zclient *zclient,
			    zebra_size_t length, vrf_id_t vrf_id)
{
  struct interface *ifp;

  /*
    zebra api adds/dels interfaces using the same call
    interface_add_read below, see comments in lib/zclient.c
  */
  ifp = zebra_interface_add_read(zclient->ibuf, vrf_id);
  if (!ifp)
    return 0;

  if (PIM_DEBUG_ZEBRA) {
    zlog_debug("%s: %s index %d flags %ld metric %d mtu %d operative %d",
	       __PRETTY_FUNCTION__,
	       ifp->name, ifp->ifindex, (long)ifp->flags, ifp->metric,
	       ifp->mtu, if_is_operative(ifp));
  }

  if (if_is_operative(ifp))
    pim_if_addr_add_all(ifp);

  return 0;
}

static int pim_zebra_if_del(int command, struct zclient *zclient,
			    zebra_size_t length, vrf_id_t vrf_id)
{
  struct interface *ifp;

  /*
    zebra api adds/dels interfaces using the same call
    interface_add_read below, see comments in lib/zclient.c
    
    comments in lib/zclient.c seem to indicate that calling
    zebra_interface_add_read is the correct call, but that
    results in an attemted out of bounds read which causes
    pimd to assert. Other clients use zebra_interface_state_read
    and it appears to work just fine.
  */
  ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
  if (!ifp)
    return 0;

  if (PIM_DEBUG_ZEBRA) {
    zlog_debug("%s: %s index %d flags %ld metric %d mtu %d operative %d",
	       __PRETTY_FUNCTION__,
	       ifp->name, ifp->ifindex, (long)ifp->flags, ifp->metric,
	       ifp->mtu, if_is_operative(ifp));
  }

  if (!if_is_operative(ifp))
    pim_if_addr_del_all(ifp);

  return 0;
}

static int pim_zebra_if_state_up(int command, struct zclient *zclient,
				 zebra_size_t length, vrf_id_t vrf_id)
{
  struct interface *ifp;

  /*
    zebra api notifies interface up/down events by using the same call
    zebra_interface_state_read below, see comments in lib/zclient.c
  */
  ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
  if (!ifp)
    return 0;

  if (PIM_DEBUG_ZEBRA) {
    zlog_debug("%s: %s index %d flags %ld metric %d mtu %d operative %d",
	       __PRETTY_FUNCTION__,
	       ifp->name, ifp->ifindex, (long)ifp->flags, ifp->metric,
	       ifp->mtu, if_is_operative(ifp));
  }

  if (if_is_operative(ifp)) {
    /*
      pim_if_addr_add_all() suffices for bringing up both IGMP and PIM
    */
    pim_if_addr_add_all(ifp);
  }

  return 0;
}

static int pim_zebra_if_state_down(int command, struct zclient *zclient,
				   zebra_size_t length, vrf_id_t vrf_id)
{
  struct interface *ifp;

  /*
    zebra api notifies interface up/down events by using the same call
    zebra_interface_state_read below, see comments in lib/zclient.c
  */
  ifp = zebra_interface_state_read(zclient->ibuf, vrf_id);
  if (!ifp)
    return 0;

  if (PIM_DEBUG_ZEBRA) {
    zlog_debug("%s: %s index %d flags %ld metric %d mtu %d operative %d",
	       __PRETTY_FUNCTION__,
	       ifp->name, ifp->ifindex, (long)ifp->flags, ifp->metric,
	       ifp->mtu, if_is_operative(ifp));
  }

  if (!if_is_operative(ifp)) {
    pim_ifchannel_delete_all(ifp);
    /*
      pim_if_addr_del_all() suffices for shutting down IGMP,
      but not for shutting down PIM
    */
    pim_if_addr_del_all(ifp);

    /*
      pim_sock_delete() closes the socket, stops read and timer threads,
      and kills all neighbors.
    */
    if (ifp->info) {
      pim_sock_delete(ifp, "link down");
    }
  }

  if (ifp->info)
    pim_if_del_vif(ifp);

  return 0;
}

#ifdef PIM_DEBUG_IFADDR_DUMP
static void dump_if_address(struct interface *ifp)
{
  struct connected *ifc;
  struct listnode *node;

  zlog_debug("%s %s: interface %s addresses:",
	     __FILE__, __PRETTY_FUNCTION__,
	     ifp->name);
  
  for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, ifc)) {
    struct prefix *p = ifc->address;
    
    if (p->family != AF_INET)
      continue;
    
    zlog_debug("%s %s: interface %s address %s %s",
	       __FILE__, __PRETTY_FUNCTION__,
	       ifp->name,
	       inet_ntoa(p->u.prefix4),
	       CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY) ? 
	       "secondary" : "primary");
  }
}
#endif

static int pim_zebra_if_address_add(int command, struct zclient *zclient,
				    zebra_size_t length, vrf_id_t vrf_id)
{
  struct connected *c;
  struct prefix *p;
  struct pim_interface *pim_ifp;

  /*
    zebra api notifies address adds/dels events by using the same call
    interface_add_read below, see comments in lib/zclient.c

    zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_ADD, ...)
    will add address to interface list by calling
    connected_add_by_prefix()
  */
  c = zebra_interface_address_read(command, zclient->ibuf, vrf_id);
  if (!c)
    return 0;

  pim_ifp = c->ifp->info;
  p = c->address;

  if (PIM_DEBUG_ZEBRA) {
    char buf[BUFSIZ];
    prefix2str(p, buf, BUFSIZ);
    zlog_debug("%s: %s connected IP address %s flags %u %s",
	       __PRETTY_FUNCTION__,
	       c->ifp->name, buf, c->flags,
	       CHECK_FLAG(c->flags, ZEBRA_IFA_SECONDARY) ? "secondary" : "primary");
    
#ifdef PIM_DEBUG_IFADDR_DUMP
    dump_if_address(c->ifp);
#endif
  }

  if (p->family != AF_INET)
    {
      struct listnode *cnode;
      struct connected *conn;
      int v4addrs = 0;

      for (ALL_LIST_ELEMENTS_RO (c->ifp->connected, cnode, conn))
        {
          if (conn->address->family == AF_INET)
	    v4addrs++;
        }
      if (!v4addrs && pim_ifp) 
	{
	  pim_ifp->primary_address = pim_find_primary_addr (c->ifp);
	  pim_if_addr_add_all (c->ifp);
          pim_if_add_vif (c->ifp);
	}
      return 0;
    }

  if (!CHECK_FLAG(c->flags, ZEBRA_IFA_SECONDARY)) {
    /* trying to add primary address */

    struct in_addr primary_addr = pim_find_primary_addr(c->ifp);
    if (primary_addr.s_addr != p->u.prefix4.s_addr) {
      if (PIM_DEBUG_ZEBRA) {
	/* but we had a primary address already */

	char buf[BUFSIZ];

	prefix2str(p, buf, BUFSIZ);

	zlog_warn("%s: %s : forcing secondary flag on %s",
		  __PRETTY_FUNCTION__,
		  c->ifp->name, buf);
      }
      SET_FLAG(c->flags, ZEBRA_IFA_SECONDARY);
    }
  }

  pim_if_addr_add(c);
  if (pim_ifp)
    pim_rp_check_on_if_add(pim_ifp);

  if (if_is_loopback (c->ifp))
    {
      struct listnode *ifnode;
      struct interface *ifp;

      for (ALL_LIST_ELEMENTS_RO (vrf_iflist (VRF_DEFAULT), ifnode, ifp))
        {
	  if (!if_is_loopback (ifp) && if_is_operative (ifp))
	    pim_if_addr_add_all (ifp);
        }
    }

  return 0;
}

static int pim_zebra_if_address_del(int command, struct zclient *client,
				    zebra_size_t length, vrf_id_t vrf_id)
{
  struct connected *c;
  struct prefix *p;

  /*
    zebra api notifies address adds/dels events by using the same call
    interface_add_read below, see comments in lib/zclient.c

    zebra_interface_address_read(ZEBRA_INTERFACE_ADDRESS_DELETE, ...)
    will remove address from interface list by calling
    connected_delete_by_prefix()
  */
  c = zebra_interface_address_read(command, client->ibuf, vrf_id);
  if (!c)
    return 0;
  
  p = c->address;
  if (p->family == AF_INET)
    {
        if (PIM_DEBUG_ZEBRA) {
          char buf[BUFSIZ];
          prefix2str(p, buf, BUFSIZ);
          zlog_debug("%s: %s disconnected IP address %s flags %u %s",
                     __PRETTY_FUNCTION__,
                     c->ifp->name, buf, c->flags,
                     CHECK_FLAG(c->flags, ZEBRA_IFA_SECONDARY) ? "secondary" : "primary");

#ifdef PIM_DEBUG_IFADDR_DUMP
          dump_if_address(c->ifp);
#endif
        }

        pim_if_addr_del(c, 0);
        pim_rp_setup();
        pim_i_am_rp_re_evaluate();
    }

  connected_free (c);
  return 0;
}

static void scan_upstream_rpf_cache()
{
  struct listnode     *up_node;
  struct listnode     *ifnode;
  struct listnode     *up_nextnode;
  struct listnode     *node;
  struct pim_upstream *up;
  struct interface    *ifp;

  for (ALL_LIST_ELEMENTS(pim_upstream_list, up_node, up_nextnode, up)) {
    enum pim_rpf_result rpf_result;
    struct pim_rpf      old;

    old.source_nexthop.interface = up->rpf.source_nexthop.interface;
    old.source_nexthop.nbr       = up->rpf.source_nexthop.nbr;
    rpf_result = pim_rpf_update(up, &old, 0);

    if (rpf_result == PIM_RPF_FAILURE)
      continue;

    if (rpf_result == PIM_RPF_CHANGED) {
      struct pim_neighbor *nbr;

      nbr = pim_neighbor_find (old.source_nexthop.interface,
                               old.rpf_addr.u.prefix4);
      if (nbr)
        pim_jp_agg_remove_group (nbr->upstream_jp_agg, up);

      /*
       * We have detected a case where we might need to rescan
       * the inherited o_list so do it.
       */
      if (up->channel_oil->oil_inherited_rescan)
	{
	  pim_upstream_inherited_olist_decide (up);
	  up->channel_oil->oil_inherited_rescan = 0;
	}

      if (up->join_state == PIM_UPSTREAM_JOINED) {
	/*
         * If we come up real fast we can be here
	 * where the mroute has not been installed
	 * so install it.
	 */
	if (!up->channel_oil->installed)
	  pim_mroute_add (up->channel_oil, __PRETTY_FUNCTION__);

        /*
         * RFC 4601: 4.5.7.  Sending (S,G) Join/Prune Messages
         *
         * Transitions from Joined State
         *
         * RPF'(S,G) changes not due to an Assert
         *
         * The upstream (S,G) state machine remains in Joined
         * state. Send Join(S,G) to the new upstream neighbor, which is
         * the new value of RPF'(S,G).  Send Prune(S,G) to the old
         * upstream neighbor, which is the old value of RPF'(S,G).  Set
         * the Join Timer (JT) to expire after t_periodic seconds.
         */
        pim_jp_agg_switch_interface (&old, &up->rpf, up);

        pim_upstream_join_timer_restart(up, &old);
      } /* up->join_state == PIM_UPSTREAM_JOINED */

      /* FIXME can join_desired actually be changed by pim_rpf_update()
	 returning PIM_RPF_CHANGED ? */
      pim_upstream_update_join_desired(up);

    } /* PIM_RPF_CHANGED */

  } /* for (qpim_upstream_list) */

  for (ALL_LIST_ELEMENTS_RO (vrf_iflist (VRF_DEFAULT), ifnode, ifp))
    if (ifp->info)
      {
        struct pim_interface *pim_ifp = ifp->info;
        struct pim_iface_upstream_switch *us;

        for (ALL_LIST_ELEMENTS_RO(pim_ifp->upstream_switch_list, node, us))
          {
            struct pim_rpf rpf;
            rpf.source_nexthop.interface = ifp;
            rpf.rpf_addr.u.prefix4 = us->address;
            pim_joinprune_send(&rpf, us->us);
            pim_jp_agg_clear_group(us->us);
          }
      }
}

void
pim_scan_individual_oil (struct channel_oil *c_oil, int in_vif_index)
{
  struct in_addr vif_source;
  int input_iface_vif_index;
  int old_vif_index;

  if (!pim_rp_set_upstream_addr (&vif_source, c_oil->oil.mfcc_origin, c_oil->oil.mfcc_mcastgrp))
    return;

  if (in_vif_index)
    input_iface_vif_index = in_vif_index;
  else
    input_iface_vif_index = fib_lookup_if_vif_index (vif_source);
  if (input_iface_vif_index < 1)
    {
      if (PIM_DEBUG_ZEBRA)
        {
          char source_str[INET_ADDRSTRLEN];
          char group_str[INET_ADDRSTRLEN];
          pim_inet4_dump("<source?>", c_oil->oil.mfcc_origin, source_str, sizeof(source_str));
          pim_inet4_dump("<group?>", c_oil->oil.mfcc_mcastgrp, group_str, sizeof(group_str));
          zlog_debug("%s %s: could not find input interface(%d) for (S,G)=(%s,%s)",
		     __FILE__, __PRETTY_FUNCTION__, c_oil->oil.mfcc_parent,
		     source_str, group_str);
        }
      pim_mroute_del (c_oil, __PRETTY_FUNCTION__);
      return;
    }

  if (input_iface_vif_index == c_oil->oil.mfcc_parent)
    {
      if (!c_oil->installed)
        pim_mroute_add (c_oil, __PRETTY_FUNCTION__);

      /* RPF unchanged */
      return;
    }

  if (PIM_DEBUG_ZEBRA)
    {
      struct interface *old_iif = pim_if_find_by_vif_index(c_oil->oil.mfcc_parent);
      struct interface *new_iif = pim_if_find_by_vif_index(input_iface_vif_index);
      char source_str[INET_ADDRSTRLEN];
      char group_str[INET_ADDRSTRLEN];
      pim_inet4_dump("<source?>", c_oil->oil.mfcc_origin, source_str, sizeof(source_str));
      pim_inet4_dump("<group?>", c_oil->oil.mfcc_mcastgrp, group_str, sizeof(group_str));
      zlog_debug("%s %s: (S,G)=(%s,%s) input interface changed from %s vif_index=%d to %s vif_index=%d",
		 __FILE__, __PRETTY_FUNCTION__,
		 source_str, group_str,
		 old_iif->name, c_oil->oil.mfcc_parent,
		 new_iif->name, input_iface_vif_index);
    }

  /* new iif loops to existing oif ? */
  if (c_oil->oil.mfcc_ttls[input_iface_vif_index])
    {
      struct interface *new_iif = pim_if_find_by_vif_index(input_iface_vif_index);

      if (PIM_DEBUG_ZEBRA) {
	char source_str[INET_ADDRSTRLEN];
	char group_str[INET_ADDRSTRLEN];
	pim_inet4_dump("<source?>", c_oil->oil.mfcc_origin, source_str, sizeof(source_str));
	pim_inet4_dump("<group?>", c_oil->oil.mfcc_mcastgrp, group_str, sizeof(group_str));
	zlog_debug("%s %s: (S,G)=(%s,%s) new iif loops to existing oif: %s vif_index=%d",
		   __FILE__, __PRETTY_FUNCTION__,
		   source_str, group_str,
		   new_iif->name, input_iface_vif_index);
      }
    }

    /* update iif vif_index */
    old_vif_index = c_oil->oil.mfcc_parent;
    c_oil->oil.mfcc_parent = input_iface_vif_index;

    /* update kernel multicast forwarding cache (MFC) */
    if (pim_mroute_add(c_oil, __PRETTY_FUNCTION__))
      {
	if (PIM_DEBUG_MROUTE)
	  {
	    /* just log warning */
	    struct interface *old_iif = pim_if_find_by_vif_index(old_vif_index);
	    struct interface *new_iif = pim_if_find_by_vif_index(input_iface_vif_index);
	    char source_str[INET_ADDRSTRLEN];
	    char group_str[INET_ADDRSTRLEN];
	    pim_inet4_dump("<source?>", c_oil->oil.mfcc_origin, source_str, sizeof(source_str));
	    pim_inet4_dump("<group?>", c_oil->oil.mfcc_mcastgrp, group_str, sizeof(group_str));
	    zlog_debug("%s %s: (S,G)=(%s,%s) failure updating input interface from %s vif_index=%d to %s vif_index=%d",
		       __FILE__, __PRETTY_FUNCTION__,
		       source_str, group_str,
		       old_iif ? old_iif->name : "<old_iif?>", c_oil->oil.mfcc_parent,
		       new_iif ? new_iif->name : "<new_iif?>", input_iface_vif_index);
	  }
    }
}

void pim_scan_oil()
{
  struct listnode    *node;
  struct listnode    *nextnode;
  struct channel_oil *c_oil;

  qpim_scan_oil_last = pim_time_monotonic_sec();
  ++qpim_scan_oil_events;

  for (ALL_LIST_ELEMENTS(pim_channel_oil_list, node, nextnode, c_oil))
    pim_scan_individual_oil (c_oil, 0);
}

static int on_rpf_cache_refresh(struct thread *t)
{
  zassert(qpim_rpf_cache_refresher);

  qpim_rpf_cache_refresher = 0;

  /* update PIM protocol state */
  scan_upstream_rpf_cache();

  /* update kernel multicast forwarding cache (MFC) */
  pim_scan_oil();

  qpim_rpf_cache_refresh_last = pim_time_monotonic_sec();
  ++qpim_rpf_cache_refresh_events;

  pim_rp_setup ();
  return 0;
}

void sched_rpf_cache_refresh(void)
{
  ++qpim_rpf_cache_refresh_requests;

  pim_rpf_set_refresh_time ();

  if (qpim_rpf_cache_refresher) {
    /* Refresh timer is already running */
    return;
  }

  /* Start refresh timer */

  if (PIM_DEBUG_ZEBRA) {
    zlog_debug("%s: triggering %ld msec timer",
               __PRETTY_FUNCTION__,
               qpim_rpf_cache_refresh_delay_msec);
  }

  THREAD_TIMER_MSEC_ON(master, qpim_rpf_cache_refresher,
                       on_rpf_cache_refresh,
                       0, qpim_rpf_cache_refresh_delay_msec);
}

static int
pim_zebra_nexthop_update (int command, struct zclient *zclient,
                          zebra_size_t length, vrf_id_t vrf_id)
{
  pim_parse_nexthop_update (zclient, command, vrf_id);
  return 0;
}

static void
pim_zebra_connected (struct zclient *zclient)
{
  zclient_send_reg_requests (zclient, VRF_DEFAULT);
}

void pim_zebra_init(void)
{
  int i;

#ifdef HAVE_TCP_ZEBRA
  zlog_notice("zclient update contacting ZEBRA daemon at socket TCP %s,%d", "127.0.0.1", ZEBRA_PORT);
#else
  zlog_notice("zclient update contacting ZEBRA daemon at socket UNIX %s", zclient_serv_path_get());
#endif

  /* Socket for receiving updates from Zebra daemon */
  zclient = zclient_new (master);

  zclient->zebra_connected          = pim_zebra_connected;
  zclient->router_id_update         = pim_router_id_update_zebra;
  zclient->interface_add            = pim_zebra_if_add;
  zclient->interface_delete         = pim_zebra_if_del;
  zclient->interface_up             = pim_zebra_if_state_up;
  zclient->interface_down           = pim_zebra_if_state_down;
  zclient->interface_address_add    = pim_zebra_if_address_add;
  zclient->interface_address_delete = pim_zebra_if_address_del;
  zclient->nexthop_update           = pim_zebra_nexthop_update;

  zclient_init(zclient, ZEBRA_ROUTE_PIM, 0);
  if (PIM_DEBUG_PIM_TRACE) {
    zlog_info("zclient_init cleared redistribution request");
  }

  zassert(zclient->redist_default == ZEBRA_ROUTE_PIM);

  /* Request all redistribution */
  for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
    if (i == zclient->redist_default)
      continue;
    vrf_bitmap_set (zclient->redist[AFI_IP][i], VRF_DEFAULT);;
    if (PIM_DEBUG_PIM_TRACE) {
      zlog_debug("%s: requesting redistribution for %s (%i)", 
		 __PRETTY_FUNCTION__, zebra_route_string(i), i);
    }
  }

  /* Request default information */
  zclient_redistribute_default (ZEBRA_REDISTRIBUTE_DEFAULT_ADD,
				zclient, VRF_DEFAULT);
  
  if (PIM_DEBUG_PIM_TRACE) {
    zlog_info("%s: requesting default information redistribution",
	      __PRETTY_FUNCTION__);

    zlog_notice("%s: zclient update socket initialized",
		__PRETTY_FUNCTION__);
  }

  zclient_lookup_new();
}

void igmp_anysource_forward_start(struct igmp_group *group)
{
  struct igmp_source *source;
  struct in_addr src_addr = { .s_addr = 0 };
  /* Any source (*,G) is forwarded only if mode is EXCLUDE {empty} */
  zassert(group->group_filtermode_isexcl);
  zassert(listcount(group->group_source_list) < 1);

  source = source_new (group, src_addr);
  if (!source)
    {
      zlog_warn ("%s: Failure to create * source", __PRETTY_FUNCTION__);
      return;
    }

  igmp_source_forward_start (source);
}

void igmp_anysource_forward_stop(struct igmp_group *group)
{
  struct igmp_source *source;
  struct in_addr star = { .s_addr = 0 };

  source = igmp_find_source_by_addr (group, star);
  if (source)
    igmp_source_forward_stop (source);
}

static int fib_lookup_if_vif_index(struct in_addr addr)
{
  struct pim_zlookup_nexthop nexthop_tab[MULTIPATH_NUM];
  int num_ifindex;
  int vif_index;
  ifindex_t first_ifindex;

  num_ifindex = zclient_lookup_nexthop(nexthop_tab,
				       MULTIPATH_NUM, addr,
				       PIM_NEXTHOP_LOOKUP_MAX);
  if (num_ifindex < 1) {
    if (PIM_DEBUG_ZEBRA)
      {
	char addr_str[INET_ADDRSTRLEN];
	pim_inet4_dump("<addr?>", addr, addr_str, sizeof(addr_str));
	zlog_debug("%s %s: could not find nexthop ifindex for address %s",
		   __FILE__, __PRETTY_FUNCTION__,
		   addr_str);
      }
    return -1;
  }
  
  first_ifindex = nexthop_tab[0].ifindex;
  
  if (num_ifindex > 1) {
    if (PIM_DEBUG_ZEBRA)
      {
	char addr_str[INET_ADDRSTRLEN];
	pim_inet4_dump("<addr?>", addr, addr_str, sizeof(addr_str));
	zlog_debug("%s %s: FIXME ignoring multiple nexthop ifindex'es num_ifindex=%d for address %s (using only ifindex=%d)",
		   __FILE__, __PRETTY_FUNCTION__,
		   num_ifindex, addr_str, first_ifindex);
      }
    /* debug warning only, do not return */
  }
  
  if (PIM_DEBUG_ZEBRA) {
    char addr_str[INET_ADDRSTRLEN];
    pim_inet4_dump("<ifaddr?>", addr, addr_str, sizeof(addr_str));
    zlog_debug("%s %s: found nexthop ifindex=%d (interface %s) for address %s",
	       __FILE__, __PRETTY_FUNCTION__,
	       first_ifindex, ifindex2ifname(first_ifindex, VRF_DEFAULT), addr_str);
  }

  vif_index = pim_if_find_vifindex_by_ifindex(first_ifindex);

  if (vif_index < 0) {
    if (PIM_DEBUG_ZEBRA)
      {
	char addr_str[INET_ADDRSTRLEN];
	pim_inet4_dump("<addr?>", addr, addr_str, sizeof(addr_str));
	zlog_debug("%s %s: low vif_index=%d < 1 nexthop for address %s",
		   __FILE__, __PRETTY_FUNCTION__,
		   vif_index, addr_str);
      }
    return -2;
  }

  return vif_index;
}

void igmp_source_forward_start(struct igmp_source *source)
{
  struct igmp_group *group;
  struct prefix_sg sg;
  int result;

  memset (&sg, 0, sizeof (struct prefix_sg));
  sg.src = source->source_addr;
  sg.grp = source->source_group->group_addr;

  if (PIM_DEBUG_IGMP_TRACE) {
    zlog_debug("%s: (S,G)=%s igmp_sock=%d oif=%s fwd=%d",
	       __PRETTY_FUNCTION__,
 	       pim_str_sg_dump (&sg),
	       source->source_group->group_igmp_sock->fd,
	       source->source_group->group_igmp_sock->interface->name,
	       IGMP_SOURCE_TEST_FORWARDING(source->source_flags));
  }

  /* Prevent IGMP interface from installing multicast route multiple
     times */
  if (IGMP_SOURCE_TEST_FORWARDING(source->source_flags)) {
    return;
  }

  group = source->source_group;

  if (!source->source_channel_oil) {
    struct in_addr vif_source;
    struct pim_interface *pim_oif;

    if (!pim_rp_set_upstream_addr (&vif_source, source->source_addr, sg.grp))
      return;

    int input_iface_vif_index = fib_lookup_if_vif_index(vif_source);
    if (input_iface_vif_index < 1) {
      if (PIM_DEBUG_IGMP_TRACE)
	{
	  char source_str[INET_ADDRSTRLEN];
	  pim_inet4_dump("<source?>", source->source_addr, source_str, sizeof(source_str));
	  zlog_debug("%s %s: could not find input interface for source %s",
		     __FILE__, __PRETTY_FUNCTION__,
		     source_str);
	}
      return;
    }

    /*
      Protect IGMP against adding looped MFC entries created by both
      source and receiver attached to the same interface. See TODO
      T22.
    */
    pim_oif = source->source_group->group_igmp_sock->interface->info;
    if (!pim_oif) {
      if (PIM_DEBUG_IGMP_TRACE)
	{
	  zlog_debug("%s: multicast not enabled on oif=%s ?",
		     __PRETTY_FUNCTION__,
		     source->source_group->group_igmp_sock->interface->name);
	}
      return;
    }

    if (input_iface_vif_index == pim_oif->mroute_vif_index) {
      /* ignore request for looped MFC entry */
      if (PIM_DEBUG_IGMP_TRACE) {
	zlog_debug("%s: ignoring request for looped MFC entry (S,G)=%s: igmp_sock=%d oif=%s vif_index=%d",
		   __PRETTY_FUNCTION__,
		   pim_str_sg_dump (&sg),
		   source->source_group->group_igmp_sock->fd,
		   source->source_group->group_igmp_sock->interface->name,
		   input_iface_vif_index);
      }
      return;
    }

    source->source_channel_oil = pim_channel_oil_add(&sg,
						     input_iface_vif_index);
    if (!source->source_channel_oil) {
      if (PIM_DEBUG_IGMP_TRACE)
	{
	  zlog_debug("%s %s: could not create OIL for channel (S,G)=%s",
		    __FILE__, __PRETTY_FUNCTION__,
		    pim_str_sg_dump (&sg));
	}
      return;
    }
  }

  result = pim_channel_add_oif(source->source_channel_oil,
			       group->group_igmp_sock->interface,
			       PIM_OIF_FLAG_PROTO_IGMP);
  if (result) {
    if (PIM_DEBUG_MROUTE)
      {
        zlog_warn("%s: add_oif() failed with return=%d",
                  __func__, result);
      }
    return;
  }

  /*
    Feed IGMPv3-gathered local membership information into PIM
    per-interface (S,G) state.
   */
  if (!pim_ifchannel_local_membership_add(group->group_igmp_sock->interface, &sg))
    {
      if (PIM_DEBUG_MROUTE)
	zlog_warn ("%s: Failure to add local membership for %s",
		   __PRETTY_FUNCTION__, pim_str_sg_dump (&sg));
      return;
    }

  IGMP_SOURCE_DO_FORWARDING(source->source_flags);
}

/*
  igmp_source_forward_stop: stop fowarding, but keep the source
  igmp_source_delete:       stop fowarding, and delete the source
 */
void igmp_source_forward_stop(struct igmp_source *source)
{
  struct igmp_group *group;
  struct prefix_sg sg;
  int result;

  memset (&sg, 0, sizeof (struct prefix_sg));
  sg.src = source->source_addr;
  sg.grp = source->source_group->group_addr;

  if (PIM_DEBUG_IGMP_TRACE) {
    zlog_debug("%s: (S,G)=%s igmp_sock=%d oif=%s fwd=%d",
	       __PRETTY_FUNCTION__,
	       pim_str_sg_dump (&sg),
	       source->source_group->group_igmp_sock->fd,
	       source->source_group->group_igmp_sock->interface->name,
	       IGMP_SOURCE_TEST_FORWARDING(source->source_flags));
  }

  /* Prevent IGMP interface from removing multicast route multiple
     times */
  if (!IGMP_SOURCE_TEST_FORWARDING(source->source_flags)) {
    return;
  }

  group = source->source_group;

  /*
   It appears that in certain circumstances that 
   igmp_source_forward_stop is called when IGMP forwarding
   was not enabled in oif_flags for this outgoing interface.
   Possibly because of multiple calls. When that happens, we
   enter the below if statement and this function returns early
   which in turn triggers the calling function to assert.
   Making the call to pim_channel_del_oif and ignoring the return code
   fixes the issue without ill effect, similar to
   pim_forward_stop below.
  */
  result = pim_channel_del_oif(source->source_channel_oil,
                               group->group_igmp_sock->interface,
                               PIM_OIF_FLAG_PROTO_IGMP);
  if (result) {
    if (PIM_DEBUG_IGMP_TRACE)
      zlog_debug("%s: pim_channel_del_oif() failed with return=%d",
		 __func__, result);
    return;
  }

  /*
    Feed IGMPv3-gathered local membership information into PIM
    per-interface (S,G) state.
   */
  pim_ifchannel_local_membership_del(group->group_igmp_sock->interface,
				     &sg);

  IGMP_SOURCE_DONT_FORWARDING(source->source_flags);
}

void pim_forward_start(struct pim_ifchannel *ch)
{
  struct pim_upstream *up = ch->upstream;
  uint32_t mask = PIM_OIF_FLAG_PROTO_PIM;

  if (PIM_DEBUG_PIM_TRACE) {
    char source_str[INET_ADDRSTRLEN];
    char group_str[INET_ADDRSTRLEN]; 
    char upstream_str[INET_ADDRSTRLEN];

    pim_inet4_dump("<source?>", ch->sg.src, source_str, sizeof(source_str));
    pim_inet4_dump("<group?>", ch->sg.grp, group_str, sizeof(group_str));
    pim_inet4_dump("<upstream?>", up->upstream_addr, upstream_str, sizeof(upstream_str));
    zlog_debug("%s: (S,G)=(%s,%s) oif=%s(%s)",
	       __PRETTY_FUNCTION__,
	       source_str, group_str, ch->interface->name, upstream_str);
  }

  if (!up->channel_oil) {
    int input_iface_vif_index = fib_lookup_if_vif_index(up->upstream_addr);
    if (input_iface_vif_index < 1) {
      if (PIM_DEBUG_PIM_TRACE)
	{
	  char source_str[INET_ADDRSTRLEN];
	  pim_inet4_dump("<source?>", up->sg.src, source_str, sizeof(source_str));
	  zlog_debug("%s %s: could not find input interface for source %s",
		     __FILE__, __PRETTY_FUNCTION__,
		     source_str);
	}
      return;
    }

    up->channel_oil = pim_channel_oil_add(&up->sg,
					  input_iface_vif_index);
    if (!up->channel_oil) {
      if (PIM_DEBUG_PIM_TRACE)
	zlog_debug("%s %s: could not create OIL for channel (S,G)=%s",
		   __FILE__, __PRETTY_FUNCTION__,
		   up->sg_str);
      return;
    }
  }

  if (up->flags & PIM_UPSTREAM_FLAG_MASK_SRC_IGMP)
    mask = PIM_OIF_FLAG_PROTO_IGMP;

  pim_channel_add_oif(up->channel_oil, ch->interface, mask);
}

void pim_forward_stop(struct pim_ifchannel *ch)
{
  struct pim_upstream *up = ch->upstream;

  if (PIM_DEBUG_PIM_TRACE) {
    zlog_debug("%s: (S,G)=%s oif=%s",
	       __PRETTY_FUNCTION__,
	       ch->sg_str, ch->interface->name);
  }

  pim_channel_del_oif(up->channel_oil,
                      ch->interface,
                      PIM_OIF_FLAG_PROTO_PIM);
}

void
pim_zebra_zclient_update (struct vty *vty)
{
  vty_out(vty, "Zclient update socket: ");

  if (zclient) {
    vty_out(vty, "%d failures=%d%s", zclient->sock,
	    zclient->fail, VTY_NEWLINE);
  }
  else {
    vty_out(vty, "<null zclient>%s", VTY_NEWLINE);
  }
}

struct zclient *pim_zebra_zclient_get (void)
{
  if (zclient)
    return zclient;
  else
    return NULL;
}
