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
  
  $QuaggaId: $Format:%an, %ai, %h$ $
*/

#include <zebra.h>

#include "if.h"
#include "linklist.h"
#include "vrf.h"

#include "pimd.h"
#include "pim_vty.h"
#include "pim_iface.h"
#include "pim_cmd.h"
#include "pim_str.h"
#include "pim_ssmpingd.h"
#include "pim_pim.h"
#include "pim_static.h"

int pim_debug_config_write(struct vty *vty)
{
  int writes = 0;

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

  if (PIM_DEBUG_MROUTE) {
    vty_out(vty, "debug mroute%s", VTY_NEWLINE);
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

  if (PIM_DEBUG_ZEBRA) {
    vty_out(vty, "debug pim zebra%s", VTY_NEWLINE);
    ++writes;
  }

  if (PIM_DEBUG_SSMPINGD) {
    vty_out(vty, "debug ssmpingd%s", VTY_NEWLINE);
    ++writes;
  }

  return writes;
}

int pim_global_config_write(struct vty *vty)
{
  int writes = 0;
  char buffer[32];

  if (PIM_MROUTE_IS_ENABLED) {
    vty_out(vty, "%s%s", PIM_CMD_IP_MULTICAST_ROUTING, VTY_NEWLINE);
    ++writes;
  }
  if (qpim_rp.rpf_addr.s_addr != INADDR_NONE) {
    vty_out(vty, "ip pim rp %s%s", inet_ntop(AF_INET, &qpim_rp.rpf_addr, buffer, 32), VTY_NEWLINE);
    ++writes;
  }

  if (qpim_ssmpingd_list) {
    struct listnode *node;
    struct ssmpingd_sock *ss;
    vty_out(vty, "!%s", VTY_NEWLINE);
    ++writes;
    for (ALL_LIST_ELEMENTS_RO(qpim_ssmpingd_list, node, ss)) {
      char source_str[100];
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

      /* IF ip pim ssm */
      if (PIM_IF_TEST_PIM(pim_ifp->options)) {
	if (pim_ifp->itype == PIM_INTERFACE_SSM)
	  vty_out(vty, " ip pim ssm%s", VTY_NEWLINE);
	else
	  vty_out(vty, " ip pim sm%s", VTY_NEWLINE);
	++writes;
      }

      /* IF ip pim drpriority */
      if (pim_ifp->pim_dr_priority != PIM_DEFAULT_DR_PRIORITY) {
	vty_out(vty, " ip pim drpriority %d%s", pim_ifp->pim_dr_priority,
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

      /* IF ip igmp */
      if (PIM_IF_TEST_IGMP(pim_ifp->options)) {
	vty_out(vty, " ip igmp%s", VTY_NEWLINE);
	++writes;
      }

      /* IF ip igmp query-interval */
      if (pim_ifp->igmp_default_query_interval != IGMP_GENERAL_QUERY_INTERVAL)
	{
	  vty_out(vty, " %s %d%s",
		  PIM_CMD_IP_IGMP_QUERY_INTERVAL,
		  pim_ifp->igmp_default_query_interval,
		  VTY_NEWLINE);
	  ++writes;
	}

      /* IF ip igmp query-max-response-time */
      if (pim_ifp->igmp_query_max_response_time_dsec != IGMP_QUERY_MAX_RESPONSE_TIME_DSEC)
	{
	  vty_out(vty, " %s %d%s",
		  PIM_CMD_IP_IGMP_QUERY_MAX_RESPONSE_TIME_DSEC,
		  pim_ifp->igmp_query_max_response_time_dsec,
		  VTY_NEWLINE);
	  ++writes;
	}

      /* IF ip igmp join */
      if (pim_ifp->igmp_join_list) {
	struct listnode *node;
	struct igmp_join *ij;
	for (ALL_LIST_ELEMENTS_RO(pim_ifp->igmp_join_list, node, ij)) {
	  char group_str[100];
	  char source_str[100];
	  pim_inet4_dump("<grp?>", ij->group_addr, group_str, sizeof(group_str));
	  pim_inet4_dump("<src?>", ij->source_addr, source_str, sizeof(source_str));
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
