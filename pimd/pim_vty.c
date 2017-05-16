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

#include "if.h"
#include "linklist.h"
#include "prefix.h"
#include "vty.h"
#include "vrf.h"
#include "plist.h"

#include "pimd.h"
#include "pim_vty.h"
#include "pim_iface.h"
#include "pim_cmd.h"
#include "pim_str.h"
#include "pim_ssmpingd.h"
#include "pim_pim.h"
#include "pim_oil.h"
#include "pim_static.h"
#include "pim_rp.h"
#include "pim_msdp.h"
#include "pim_ssm.h"

int
pim_debug_config_write (struct vty *vty)
{
  int writes = 0;

  if (PIM_DEBUG_MSDP_EVENTS) {
    vty_out(vty, "debug msdp events%s", VTY_NEWLINE);
    ++writes;
  }
  if (PIM_DEBUG_MSDP_PACKETS) {
    vty_out(vty, "debug msdp packets%s", VTY_NEWLINE);
    ++writes;
  }
  if (PIM_DEBUG_MSDP_INTERNAL) {
    vty_out(vty, "debug msdp internal%s", VTY_NEWLINE);
    ++writes;
  }
  if (PIM_DEBUG_IGMP_EVENTS) {
    vty_out(vty, "debug igmp events%s", VTY_NEWLINE);
    ++writes;
  }
  if (PIM_DEBUG_IGMP_PACKETS) {
    vty_out(vty, "debug igmp packets%s", VTY_NEWLINE);
    ++writes;
  }
  if (PIM_DEBUG_IGMP_TRACE) {
    vty_out(vty, "debug igmp trace%s", VTY_NEWLINE);
    ++writes;
  }
  if (PIM_DEBUG_IGMP_TRACE_DETAIL) {
    vty_out(vty, "debug igmp trace detail%s", VTY_NEWLINE);
    ++writes;
  }

  if (PIM_DEBUG_MROUTE) {
    vty_out(vty, "debug mroute%s", VTY_NEWLINE);
    ++writes;
  }

  if (PIM_DEBUG_MROUTE_DETAIL) {
    vty_out (vty, "debug mroute detail%s", VTY_NEWLINE);
    ++writes;
  }

  if (PIM_DEBUG_PIM_EVENTS) {
    vty_out(vty, "debug pim events%s", VTY_NEWLINE);
    ++writes;
  }
  if (PIM_DEBUG_PIM_PACKETS) {
    vty_out(vty, "debug pim packets%s", VTY_NEWLINE);
    ++writes;
  }
  if (PIM_DEBUG_PIM_PACKETDUMP_SEND) {
    vty_out(vty, "debug pim packet-dump send%s", VTY_NEWLINE);
    ++writes;
  }
  if (PIM_DEBUG_PIM_PACKETDUMP_RECV) {
    vty_out(vty, "debug pim packet-dump receive%s", VTY_NEWLINE);
    ++writes;
  }

  if (PIM_DEBUG_PIM_TRACE) {
    vty_out(vty, "debug pim trace%s", VTY_NEWLINE);
    ++writes;
  }
  if (PIM_DEBUG_PIM_TRACE_DETAIL) {
    vty_out(vty, "debug pim trace detail%s", VTY_NEWLINE);
    ++writes;
  }

  if (PIM_DEBUG_ZEBRA) {
    vty_out(vty, "debug pim zebra%s", VTY_NEWLINE);
    ++writes;
  }

  if (PIM_DEBUG_SSMPINGD) {
    vty_out(vty, "debug ssmpingd%s", VTY_NEWLINE);
    ++writes;
  }

  if (PIM_DEBUG_PIM_HELLO) {
    vty_out (vty, "debug pim packets hello%s", VTY_NEWLINE);
    ++writes;
  }

  if (PIM_DEBUG_PIM_J_P) {
    vty_out (vty, "debug pim packets joins%s", VTY_NEWLINE);
    ++writes;
  }

  if (PIM_DEBUG_PIM_REG) {
    vty_out (vty, "debug pim packets register%s", VTY_NEWLINE);
    ++writes;
  }

  if (PIM_DEBUG_STATIC) {
    vty_out (vty, "debug pim static%s", VTY_NEWLINE);
    ++writes;
  }

  return writes;
}

int pim_global_config_write(struct vty *vty)
{
  int writes = 0;
  struct pim_ssm *ssm = pimg->ssm_info;

  writes += pim_msdp_config_write (vty);

  if (!pimg->send_v6_secondary)
    {
      vty_out (vty, "no ip pim send-v6-secondary%s", VTY_NEWLINE);
      ++writes;
    }

  writes += pim_rp_config_write (vty);

  if (qpim_register_suppress_time != PIM_REGISTER_SUPPRESSION_TIME_DEFAULT)
    {
      vty_out (vty, "ip pim register-suppress-time %d%s",
	       qpim_register_suppress_time, VTY_NEWLINE);
      ++writes;
    }
  if (qpim_t_periodic != PIM_DEFAULT_T_PERIODIC)
    {
      vty_out (vty, "ip pim join-prune-interval %d%s",
	       qpim_t_periodic, VTY_NEWLINE);
      ++writes;
    }
  if (qpim_keep_alive_time != PIM_KEEPALIVE_PERIOD)
    {
      vty_out (vty, "ip pim keep-alive-timer %d%s",
               qpim_keep_alive_time, VTY_NEWLINE);
      ++writes;
    }
  if (qpim_packet_process != PIM_DEFAULT_PACKET_PROCESS)
    {
      vty_out (vty, "ip pim packets %d%s",
	       qpim_packet_process, VTY_NEWLINE);
      ++writes;
    }
  if (ssm->plist_name)
    {
      vty_out (vty, "ip pim ssm prefix-list %s%s",
               ssm->plist_name, VTY_NEWLINE);
      ++writes;
    }
  if (pimg->spt.switchover == PIM_SPT_INFINITY)
    {
      if (pimg->spt.plist)
        vty_out (vty, "ip pim spt-switchover infinity-and-beyond prefix-list %s%s",
                 pimg->spt.plist, VTY_NEWLINE);
      else
        vty_out (vty, "ip pim spt-switchover infinity-and-beyond%s",
                 VTY_NEWLINE);
      ++writes;
    }
  if (qpim_ecmp_rebalance_enable)
    {
      vty_out (vty, "ip pim ecmp rebalance%s", VTY_NEWLINE);
      ++writes;
    }
  else if (qpim_ecmp_enable)
    {
      vty_out (vty, "ip pim ecmp%s", VTY_NEWLINE);
      ++writes;
    }
  if (qpim_ssmpingd_list) {
    struct listnode *node;
    struct ssmpingd_sock *ss;
    vty_out(vty, "!%s", VTY_NEWLINE);
    ++writes;
    for (ALL_LIST_ELEMENTS_RO(qpim_ssmpingd_list, node, ss)) {
      char source_str[INET_ADDRSTRLEN];
      pim_inet4_dump("<src?>", ss->source_addr, source_str, sizeof(source_str));
      vty_out(vty, "ip ssmpingd %s%s", source_str, VTY_NEWLINE);
      ++writes;
    }
  }

  return writes;
}

int pim_interface_config_write(struct vty *vty)
{
  int writes = 0;
  struct listnode *node;
  struct interface *ifp;

  for (ALL_LIST_ELEMENTS_RO (vrf_iflist (VRF_DEFAULT), node, ifp)) {

    /* IF name */
    vty_out(vty, "interface %s%s", ifp->name, VTY_NEWLINE);
    ++writes;

    if (ifp->info) {
      struct pim_interface *pim_ifp = ifp->info;

      if (PIM_IF_TEST_PIM(pim_ifp->options)) {
	vty_out(vty, " ip pim sm%s", VTY_NEWLINE);
	++writes;
      }

      /* IF ip pim drpriority */
      if (pim_ifp->pim_dr_priority != PIM_DEFAULT_DR_PRIORITY) {
	vty_out(vty, " ip pim drpriority %u%s", pim_ifp->pim_dr_priority,
		VTY_NEWLINE);
	++writes;
      }

      /* IF ip pim hello */
      if (pim_ifp->pim_hello_period != PIM_DEFAULT_HELLO_PERIOD) {
	vty_out(vty, " ip pim hello %d", pim_ifp->pim_hello_period);
	if (pim_ifp->pim_default_holdtime != -1)
	  vty_out(vty, " %d", pim_ifp->pim_default_holdtime);
	vty_out(vty, "%s", VTY_NEWLINE);
      }

      /* update source */
      if (PIM_INADDR_ISNOT_ANY(pim_ifp->update_source)) {
        char src_str[INET_ADDRSTRLEN];
        pim_inet4_dump("<src?>", pim_ifp->update_source, src_str,
            sizeof(src_str));
        vty_out(vty, " ip pim use-source %s%s", src_str, VTY_NEWLINE);
        ++writes;
      }

      /* IF ip igmp */
      if (PIM_IF_TEST_IGMP(pim_ifp->options)) {
	vty_out(vty, " ip igmp%s", VTY_NEWLINE);
	++writes;
      }

      /* ip igmp version */
      if (pim_ifp->igmp_version != IGMP_DEFAULT_VERSION)
        {
          vty_out(vty, " ip igmp version %d%s",
                  pim_ifp->igmp_version,
                  VTY_NEWLINE);
          ++writes;
        }

      /* IF ip igmp query-interval */
      if (pim_ifp->igmp_default_query_interval != IGMP_GENERAL_QUERY_INTERVAL)
	{
	  vty_out(vty, " ip igmp query-interval %d%s",
		  pim_ifp->igmp_default_query_interval,
		  VTY_NEWLINE);
	  ++writes;
	}

      /* IF ip igmp query-max-response-time */
      if (pim_ifp->igmp_query_max_response_time_dsec != IGMP_QUERY_MAX_RESPONSE_TIME_DSEC)
	{
	  vty_out(vty, " ip igmp query-max-response-time %d%s",
		  pim_ifp->igmp_query_max_response_time_dsec,
		  VTY_NEWLINE);
	  ++writes;
	}

      /* IF ip igmp join */
      if (pim_ifp->igmp_join_list) {
	struct listnode *node;
	struct igmp_join *ij;
	for (ALL_LIST_ELEMENTS_RO(pim_ifp->igmp_join_list, node, ij)) {
	  char group_str[INET_ADDRSTRLEN];
	  char source_str[INET_ADDRSTRLEN];
	  pim_inet4_dump("<grp?>", ij->group_addr, group_str, sizeof(group_str));
          inet_ntop(AF_INET, &ij->source_addr, source_str, sizeof(source_str));
	  vty_out(vty, " ip igmp join %s %s%s",
		  group_str, source_str,
		  VTY_NEWLINE);
	  ++writes;
	}
      }

	writes += pim_static_write_mroute (vty, ifp);
    }
    vty_out(vty, "!%s", VTY_NEWLINE);
    ++writes;
  }

  return writes;
}
