/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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
#include "pim_bfd.h"

int pim_debug_config_write(struct vty *vty)
{
	int writes = 0;

	if (PIM_DEBUG_MSDP_EVENTS) {
		vty_out(vty, "debug msdp events\n");
		++writes;
	}
	if (PIM_DEBUG_MSDP_PACKETS) {
		vty_out(vty, "debug msdp packets\n");
		++writes;
	}
	if (PIM_DEBUG_MSDP_INTERNAL) {
		vty_out(vty, "debug msdp internal\n");
		++writes;
	}
	if (PIM_DEBUG_IGMP_EVENTS) {
		vty_out(vty, "debug igmp events\n");
		++writes;
	}
	if (PIM_DEBUG_IGMP_PACKETS) {
		vty_out(vty, "debug igmp packets\n");
		++writes;
	}
	if (PIM_DEBUG_IGMP_TRACE) {
		vty_out(vty, "debug igmp trace\n");
		++writes;
	}
	if (PIM_DEBUG_IGMP_TRACE_DETAIL) {
		vty_out(vty, "debug igmp trace detail\n");
		++writes;
	}

	if (PIM_DEBUG_MROUTE) {
		vty_out(vty, "debug mroute\n");
		++writes;
	}

	if (PIM_DEBUG_MTRACE) {
		vty_out(vty, "debug mtrace\n");
		++writes;
	}

	if (PIM_DEBUG_MROUTE_DETAIL) {
		vty_out(vty, "debug mroute detail\n");
		++writes;
	}

	if (PIM_DEBUG_PIM_EVENTS) {
		vty_out(vty, "debug pim events\n");
		++writes;
	}
	if (PIM_DEBUG_PIM_PACKETS) {
		vty_out(vty, "debug pim packets\n");
		++writes;
	}
	if (PIM_DEBUG_PIM_PACKETDUMP_SEND) {
		vty_out(vty, "debug pim packet-dump send\n");
		++writes;
	}
	if (PIM_DEBUG_PIM_PACKETDUMP_RECV) {
		vty_out(vty, "debug pim packet-dump receive\n");
		++writes;
	}

	if (PIM_DEBUG_PIM_TRACE) {
		vty_out(vty, "debug pim trace\n");
		++writes;
	}
	if (PIM_DEBUG_PIM_TRACE_DETAIL) {
		vty_out(vty, "debug pim trace detail\n");
		++writes;
	}

	if (PIM_DEBUG_ZEBRA) {
		vty_out(vty, "debug pim zebra\n");
		++writes;
	}

	if (PIM_DEBUG_SSMPINGD) {
		vty_out(vty, "debug ssmpingd\n");
		++writes;
	}

	if (PIM_DEBUG_PIM_HELLO) {
		vty_out(vty, "debug pim packets hello\n");
		++writes;
	}

	if (PIM_DEBUG_PIM_J_P) {
		vty_out(vty, "debug pim packets joins\n");
		++writes;
	}

	if (PIM_DEBUG_PIM_REG) {
		vty_out(vty, "debug pim packets register\n");
		++writes;
	}

	if (PIM_DEBUG_STATIC) {
		vty_out(vty, "debug pim static\n");
		++writes;
	}

	if (PIM_DEBUG_PIM_NHT) {
		vty_out(vty, "debug pim nht\n");
		++writes;
	}

	return writes;
}

int pim_global_config_write_worker(struct pim_instance *pim, struct vty *vty)
{
	int writes = 0;
	struct pim_ssm *ssm = pim->ssm_info;
	char spaces[10];

	if (pim->vrf_id == VRF_DEFAULT)
		sprintf(spaces, "%s", "");
	else
		sprintf(spaces, "%s", " ");

	writes += pim_msdp_config_write_helper(pim, vty, spaces);

	if (!pim->send_v6_secondary) {
		vty_out(vty, "%sno ip pim send-v6-secondary\n", spaces);
		++writes;
	}

	writes += pim_rp_config_write(pim, vty, spaces);

	if (qpim_register_suppress_time
	    != PIM_REGISTER_SUPPRESSION_TIME_DEFAULT) {
		vty_out(vty, "%sip pim register-suppress-time %d\n", spaces,
			qpim_register_suppress_time);
		++writes;
	}
	if (qpim_t_periodic != PIM_DEFAULT_T_PERIODIC) {
		vty_out(vty, "%sip pim join-prune-interval %d\n", spaces,
			qpim_t_periodic);
		++writes;
	}
	if (pim->keep_alive_time != PIM_KEEPALIVE_PERIOD) {
		vty_out(vty, "%sip pim keep-alive-timer %d\n", spaces,
			pim->keep_alive_time);
		++writes;
	}
	if (pim->rp_keep_alive_time != (unsigned int)PIM_RP_KEEPALIVE_PERIOD) {
		vty_out(vty, "%sip pim rp keep-alive-timer %d\n", spaces,
			pim->rp_keep_alive_time);
		++writes;
	}
	if (qpim_packet_process != PIM_DEFAULT_PACKET_PROCESS) {
		vty_out(vty, "%sip pim packets %d\n", spaces,
			qpim_packet_process);
		++writes;
	}
	if (ssm->plist_name) {
		vty_out(vty, "%sip pim ssm prefix-list %s\n", spaces,
			ssm->plist_name);
		++writes;
	}
	if (pim->spt.switchover == PIM_SPT_INFINITY) {
		if (pim->spt.plist)
			vty_out(vty,
				"%sip pim spt-switchover infinity-and-beyond prefix-list %s\n",
				spaces, pim->spt.plist);
		else
			vty_out(vty,
				"%sip pim spt-switchover infinity-and-beyond\n",
				spaces);
		++writes;
	}
	if (pim->ecmp_rebalance_enable) {
		vty_out(vty, "%sip pim ecmp rebalance\n", spaces);
		++writes;
	} else if (pim->ecmp_enable) {
		vty_out(vty, "%sip pim ecmp\n", spaces);
		++writes;
	}
	if (pim->ssmpingd_list) {
		struct listnode *node;
		struct ssmpingd_sock *ss;
		++writes;
		for (ALL_LIST_ELEMENTS_RO(pim->ssmpingd_list, node, ss)) {
			char source_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<src?>", ss->source_addr, source_str,
				       sizeof(source_str));
			vty_out(vty, "%sip ssmpingd %s\n", spaces, source_str);
			++writes;
		}
	}

	return writes;
}

int pim_interface_config_write(struct vty *vty)
{
	struct pim_instance *pim;
	struct interface *ifp;
	struct vrf *vrf;
	int writes = 0;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		pim = vrf->info;
		if (!pim)
			continue;

		FOR_ALL_INTERFACES (pim->vrf, ifp) {
			/* IF name */
			if (vrf->vrf_id == VRF_DEFAULT)
				vty_frame(vty, "interface %s\n", ifp->name);
			else
				vty_frame(vty, "interface %s vrf %s\n",
					  ifp->name, vrf->name);
			++writes;

			if (ifp->info) {
				struct pim_interface *pim_ifp = ifp->info;

				if (PIM_IF_TEST_PIM(pim_ifp->options)) {
					vty_out(vty, " ip pim sm\n");
					++writes;
				}

				/* IF ip pim drpriority */
				if (pim_ifp->pim_dr_priority
				    != PIM_DEFAULT_DR_PRIORITY) {
					vty_out(vty, " ip pim drpriority %u\n",
						pim_ifp->pim_dr_priority);
					++writes;
				}

				/* IF ip pim hello */
				if (pim_ifp->pim_hello_period
				    != PIM_DEFAULT_HELLO_PERIOD) {
					vty_out(vty, " ip pim hello %d",
						pim_ifp->pim_hello_period);
					if (pim_ifp->pim_default_holdtime != -1)
						vty_out(vty, " %d",
							pim_ifp->pim_default_holdtime);
					vty_out(vty, "\n");
					++writes;
				}

				/* update source */
				if (PIM_INADDR_ISNOT_ANY(
					    pim_ifp->update_source)) {
					char src_str[INET_ADDRSTRLEN];
					pim_inet4_dump("<src?>",
						       pim_ifp->update_source,
						       src_str,
						       sizeof(src_str));
					vty_out(vty, " ip pim use-source %s\n",
						src_str);
					++writes;
				}

				/* IF ip igmp */
				if (PIM_IF_TEST_IGMP(pim_ifp->options)) {
					vty_out(vty, " ip igmp\n");
					++writes;
				}

				/* ip igmp version */
				if (pim_ifp->igmp_version
				    != IGMP_DEFAULT_VERSION) {
					vty_out(vty, " ip igmp version %d\n",
						pim_ifp->igmp_version);
					++writes;
				}

				/* IF ip igmp query-interval */
				if (pim_ifp->igmp_default_query_interval
				    != IGMP_GENERAL_QUERY_INTERVAL) {
					vty_out(vty,
						" ip igmp query-interval %d\n",
						pim_ifp->igmp_default_query_interval);
					++writes;
				}

				/* IF ip igmp query-max-response-time */
				if (pim_ifp->igmp_query_max_response_time_dsec
				    != IGMP_QUERY_MAX_RESPONSE_TIME_DSEC) {
					vty_out(vty,
						" ip igmp query-max-response-time %d\n",
						pim_ifp->igmp_query_max_response_time_dsec);
					++writes;
				}

				/* IF ip igmp join */
				if (pim_ifp->igmp_join_list) {
					struct listnode *node;
					struct igmp_join *ij;
					for (ALL_LIST_ELEMENTS_RO(
						     pim_ifp->igmp_join_list,
						     node, ij)) {
						char group_str[INET_ADDRSTRLEN];
						char source_str
							[INET_ADDRSTRLEN];
						pim_inet4_dump(
							"<grp?>",
							ij->group_addr,
							group_str,
							sizeof(group_str));
						inet_ntop(AF_INET,
							  &ij->source_addr,
							  source_str,
							  sizeof(source_str));
						vty_out(vty,
							" ip igmp join %s %s\n",
							group_str, source_str);
						++writes;
					}
				}

				/* boundary */
				if (pim_ifp->boundary_oil_plist) {
					vty_out(vty,
						" ip multicast boundary oil %s\n",
						pim_ifp->boundary_oil_plist);
					++writes;
				}

				writes +=
					pim_static_write_mroute(pim, vty, ifp);
				pim_bfd_write_config(vty, ifp);
			}
			vty_endframe(vty, "!\n");
			++writes;
		}
	}

	return writes;
}
