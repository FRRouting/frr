// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
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
#include "pim_str.h"
#include "pim_ssmpingd.h"
#include "pim_pim.h"
#include "pim_oil.h"
#include "pim_static.h"
#include "pim_rp.h"
#include "pim_msdp.h"
#include "pim_ssm.h"
#include "pim_bfd.h"
#include "pim_bsm.h"
#include "pim_vxlan.h"
#include "pim6_mld.h"

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
	if (PIM_DEBUG_GM_EVENTS) {
		vty_out(vty, "debug " GM_AF_DBG " events\n");
		++writes;
	}
	if (PIM_DEBUG_GM_PACKETS) {
		vty_out(vty, "debug " GM_AF_DBG " packets\n");
		++writes;
	}
	/* PIM_DEBUG_GM_TRACE catches _DETAIL too */
	if (router->debugs & PIM_MASK_GM_TRACE) {
		vty_out(vty, "debug " GM_AF_DBG " trace\n");
		++writes;
	}
	if (PIM_DEBUG_GM_TRACE_DETAIL) {
		vty_out(vty, "debug " GM_AF_DBG " trace detail\n");
		++writes;
	}

	/* PIM_DEBUG_MROUTE catches _DETAIL too */
	if (router->debugs & PIM_MASK_MROUTE) {
		vty_out(vty, "debug " PIM_MROUTE_DBG "\n");
		++writes;
	}
	if (PIM_DEBUG_MROUTE_DETAIL) {
		vty_out(vty, "debug " PIM_MROUTE_DBG " detail\n");
		++writes;
	}

	if (PIM_DEBUG_MTRACE) {
		vty_out(vty, "debug mtrace\n");
		++writes;
	}

	if (PIM_DEBUG_PIM_EVENTS) {
		vty_out(vty, "debug " PIM_AF_DBG " events\n");
		++writes;
	}
	if (PIM_DEBUG_PIM_PACKETS) {
		vty_out(vty, "debug " PIM_AF_DBG " packets\n");
		++writes;
	}
	if (PIM_DEBUG_PIM_PACKETDUMP_SEND) {
		vty_out(vty, "debug " PIM_AF_DBG " packet-dump send\n");
		++writes;
	}
	if (PIM_DEBUG_PIM_PACKETDUMP_RECV) {
		vty_out(vty, "debug " PIM_AF_DBG " packet-dump receive\n");
		++writes;
	}

	/* PIM_DEBUG_PIM_TRACE catches _DETAIL too */
	if (router->debugs & PIM_MASK_PIM_TRACE) {
		vty_out(vty, "debug " PIM_AF_DBG " trace\n");
		++writes;
	}
	if (PIM_DEBUG_PIM_TRACE_DETAIL) {
		vty_out(vty, "debug " PIM_AF_DBG " trace detail\n");
		++writes;
	}

	if (PIM_DEBUG_ZEBRA) {
		vty_out(vty, "debug " PIM_AF_DBG " zebra\n");
		++writes;
	}

        if (PIM_DEBUG_MLAG) {
                vty_out(vty, "debug pim mlag\n");
                ++writes;
        }

	if (PIM_DEBUG_BSM) {
		vty_out(vty, "debug " PIM_AF_DBG " bsm\n");
		++writes;
	}

	if (PIM_DEBUG_VXLAN) {
		vty_out(vty, "debug " PIM_AF_DBG " vxlan\n");
		++writes;
	}

	if (PIM_DEBUG_SSMPINGD) {
		vty_out(vty, "debug ssmpingd\n");
		++writes;
	}

	if (PIM_DEBUG_PIM_HELLO) {
		vty_out(vty, "debug " PIM_AF_DBG " packets hello\n");
		++writes;
	}

	if (PIM_DEBUG_PIM_J_P) {
		vty_out(vty, "debug " PIM_AF_DBG " packets joins\n");
		++writes;
	}

	if (PIM_DEBUG_PIM_REG) {
		vty_out(vty, "debug " PIM_AF_DBG " packets register\n");
		++writes;
	}

	if (PIM_DEBUG_STATIC) {
		vty_out(vty, "debug pim static\n");
		++writes;
	}

	if (PIM_DEBUG_PIM_NHT) {
		vty_out(vty, "debug " PIM_AF_DBG " nht\n");
		++writes;
	}

	if (PIM_DEBUG_PIM_NHT_RP) {
		vty_out(vty, "debug pim nht rp\n");
		++writes;
	}

	if (PIM_DEBUG_PIM_NHT_DETAIL) {
		vty_out(vty, "debug " PIM_AF_DBG " nht detail\n");
		++writes;
	}

	if (PIM_DEBUG_AUTORP) {
		vty_out(vty, "debug pim autorp\n");
		++writes;
	}

	return writes;
}

int pim_global_config_write_worker(struct pim_instance *pim, struct vty *vty)
{
	int writes = 0;
	struct pim_ssm *ssm = pim->ssm_info;

	writes += pim_msdp_peer_config_write(vty, pim);
	writes += pim_msdp_config_write(pim, vty);

	if (!pim->send_v6_secondary) {
		vty_out(vty, " no send-v6-secondary\n");
		++writes;
	}

	writes += pim_rp_config_write(pim, vty);
#if PIM_IPV == 4
	writes += pim_autorp_config_write(pim, vty);
#endif
	writes += pim_cand_config_write(pim, vty);

	if (pim->vrf->vrf_id == VRF_DEFAULT) {
		if (router->register_suppress_time
		    != PIM_REGISTER_SUPPRESSION_TIME_DEFAULT) {
			vty_out(vty, " register-suppress-time %d\n",
				router->register_suppress_time);
			++writes;
		}
		if (router->t_periodic != PIM_DEFAULT_T_PERIODIC) {
			vty_out(vty, " join-prune-interval %d\n",
				router->t_periodic);
			++writes;
		}

		if (router->packet_process != PIM_DEFAULT_PACKET_PROCESS) {
			vty_out(vty, " packets %d\n", router->packet_process);
			++writes;
		}
	}
	if (pim->keep_alive_time != PIM_KEEPALIVE_PERIOD) {
		vty_out(vty, " keep-alive-timer %d\n", pim->keep_alive_time);
		++writes;
	}
	if (pim->rp_keep_alive_time != (unsigned int)PIM_RP_KEEPALIVE_PERIOD) {
		vty_out(vty, " rp keep-alive-timer %d\n",
			pim->rp_keep_alive_time);
		++writes;
	}
	if (ssm->plist_name) {
		vty_out(vty, " ssm prefix-list %s\n", ssm->plist_name);
		++writes;
	}
	if (pim->register_plist) {
		vty_out(vty, " register-accept-list %s\n", pim->register_plist);
		++writes;
	}
	if (pim->spt.switchover == PIM_SPT_INFINITY) {
		if (pim->spt.plist)
			vty_out(vty,
				" spt-switchover infinity-and-beyond prefix-list %s\n",
				pim->spt.plist);
		else
			vty_out(vty, " spt-switchover infinity-and-beyond\n");
		++writes;
	}
	if (pim->ecmp_rebalance_enable) {
		vty_out(vty, " ecmp rebalance\n");
		++writes;
	} else if (pim->ecmp_enable) {
		vty_out(vty, " ecmp\n");
		++writes;
	}

	if (pim->ssmpingd_list) {
		struct listnode *node;
		struct ssmpingd_sock *ss;
		++writes;
		for (ALL_LIST_ELEMENTS_RO(pim->ssmpingd_list, node, ss)) {
			vty_out(vty, " ssmpingd %pPA\n", &ss->source_addr);
			++writes;
		}
	}

	if (pim->msdp.hold_time != PIM_MSDP_PEER_HOLD_TIME
	    || pim->msdp.keep_alive != PIM_MSDP_PEER_KA_TIME
	    || pim->msdp.connection_retry != PIM_MSDP_PEER_CONNECT_RETRY_TIME) {
		vty_out(vty, " msdp timers %u %u", pim->msdp.hold_time,
			pim->msdp.keep_alive);
		if (pim->msdp.connection_retry
		    != PIM_MSDP_PEER_CONNECT_RETRY_TIME)
			vty_out(vty, " %u", pim->msdp.connection_retry);
		vty_out(vty, "\n");
	}

	return writes;
}

#if PIM_IPV == 4
static int gm_config_write(struct vty *vty, int writes,
			   struct pim_interface *pim_ifp)
{
	/* IF ip igmp */
	if (pim_ifp->gm_enable) {
		vty_out(vty, " ip igmp\n");
		++writes;
	}

	if (pim_ifp->gm_proxy) {
		vty_out(vty, " ip igmp proxy\n");
		++writes;
	}

	/* ip igmp version */
	if (pim_ifp->igmp_version != IGMP_DEFAULT_VERSION) {
		vty_out(vty, " ip igmp version %d\n", pim_ifp->igmp_version);
		++writes;
	}

	/* IF ip igmp query-max-response-time */
	if (pim_ifp->gm_query_max_response_time_dsec !=
	    GM_QUERY_MAX_RESPONSE_TIME_DSEC) {
		vty_out(vty, " ip igmp query-max-response-time %d\n",
			pim_ifp->gm_query_max_response_time_dsec);
		++writes;
	}

	/* IF ip igmp query-interval */
	if (pim_ifp->gm_default_query_interval != GM_GENERAL_QUERY_INTERVAL) {
		vty_out(vty, " ip igmp query-interval %d\n",
			pim_ifp->gm_default_query_interval);
		++writes;
	}

	/* IF ip igmp last-member_query-count */
	if (pim_ifp->gm_last_member_query_count !=
	    GM_DEFAULT_ROBUSTNESS_VARIABLE) {
		vty_out(vty, " ip igmp last-member-query-count %d\n",
			pim_ifp->gm_last_member_query_count);
		++writes;
	}

	/* IF ip igmp last-member_query-interval */
	if (pim_ifp->gm_specific_query_max_response_time_dsec !=
	    GM_SPECIFIC_QUERY_MAX_RESPONSE_TIME_DSEC) {
		vty_out(vty, " ip igmp last-member-query-interval %d\n",
			pim_ifp->gm_specific_query_max_response_time_dsec);
		++writes;
	}

	/* IF ip igmp join-group */
	if (pim_ifp->gm_join_list) {
		struct listnode *node;
		struct gm_join *ij;
		for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_join_list, node, ij)) {
			if (pim_addr_is_any(ij->source_addr))
				vty_out(vty, " ip igmp join-group %pPAs\n",
					&ij->group_addr);
			else
				vty_out(vty, " ip igmp join-group %pPAs %pPAs\n",
					&ij->group_addr, &ij->source_addr);
			++writes;
		}
	}

	/* IF ip igmp static-group */
	if (pim_ifp->static_group_list) {
		struct listnode *node;
		struct static_group *stgrp;
		for (ALL_LIST_ELEMENTS_RO(pim_ifp->static_group_list, node,
					  stgrp)) {
			if (pim_addr_is_any(stgrp->source_addr))
				vty_out(vty, " ip igmp static-group %pPAs\n",
					&stgrp->group_addr);
			else
				vty_out(vty,
					" ip igmp static-group %pPAs %pPAs\n",
					&stgrp->group_addr, &stgrp->source_addr);
			++writes;
		}
	}

	return writes;
}
#else
static int gm_config_write(struct vty *vty, int writes,
			   struct pim_interface *pim_ifp)
{
	/* IF ipv6 mld */
	if (pim_ifp->gm_enable) {
		vty_out(vty, " ipv6 mld\n");
		++writes;
	}

	if (pim_ifp->mld_version != MLD_DEFAULT_VERSION)
		vty_out(vty, " ipv6 mld version %d\n", pim_ifp->mld_version);

	/* IF ipv6 mld query-max-response-time */
	if (pim_ifp->gm_query_max_response_time_dsec !=
	    GM_QUERY_MAX_RESPONSE_TIME_DSEC)
		vty_out(vty, " ipv6 mld query-max-response-time %d\n",
			pim_ifp->gm_query_max_response_time_dsec);

	if (pim_ifp->gm_default_query_interval != GM_GENERAL_QUERY_INTERVAL)
		vty_out(vty, " ipv6 mld query-interval %d\n",
			pim_ifp->gm_default_query_interval);

	/* IF ipv6 mld last-member_query-count */
	if (pim_ifp->gm_last_member_query_count !=
	    GM_DEFAULT_ROBUSTNESS_VARIABLE)
		vty_out(vty, " ipv6 mld last-member-query-count %d\n",
			pim_ifp->gm_last_member_query_count);

	/* IF ipv6 mld last-member_query-interval */
	if (pim_ifp->gm_specific_query_max_response_time_dsec !=
	    GM_SPECIFIC_QUERY_MAX_RESPONSE_TIME_DSEC)
		vty_out(vty, " ipv6 mld last-member-query-interval %d\n",
			pim_ifp->gm_specific_query_max_response_time_dsec);

	/* IF ipv6 mld join-group */
	if (pim_ifp->gm_join_list) {
		struct listnode *node;
		struct gm_join *ij;

		for (ALL_LIST_ELEMENTS_RO(pim_ifp->gm_join_list, node, ij)) {
			if (pim_addr_is_any(ij->source_addr))
				vty_out(vty, " ipv6 mld join-group %pPAs\n",
					&ij->group_addr);
			else
				vty_out(vty,
					" ipv6 mld join-group %pPAs %pPAs\n",
					&ij->group_addr, &ij->source_addr);
			++writes;
		}
	}

	/* IF ipv6 mld static-group */
	if (pim_ifp->static_group_list) {
		struct listnode *node;
		struct static_group *stgrp;

		for (ALL_LIST_ELEMENTS_RO(pim_ifp->static_group_list, node,
					  stgrp)) {
			if (pim_addr_is_any(stgrp->source_addr))
				vty_out(vty, " ipv6 mld static-group %pPAs\n",
					&stgrp->group_addr);
			else
				vty_out(vty,
					" ipv6 mld static-group %pPAs %pPAs\n",
					&stgrp->group_addr, &stgrp->source_addr);
			++writes;
		}
	}

	return writes;
}
#endif

int pim_config_write(struct vty *vty, int writes, struct interface *ifp,
		     struct pim_instance *pim)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (pim_ifp->pim_enable) {
		vty_out(vty, " " PIM_AF_NAME " pim\n");
		++writes;
	}

	/* IF ip pim drpriority */
	if (pim_ifp->pim_dr_priority != PIM_DEFAULT_DR_PRIORITY) {
		vty_out(vty, " " PIM_AF_NAME " pim drpriority %u\n",
			pim_ifp->pim_dr_priority);
		++writes;
	}

	/* IF ip pim hello */
	if (pim_ifp->pim_hello_period != PIM_DEFAULT_HELLO_PERIOD) {
		vty_out(vty, " " PIM_AF_NAME " pim hello %d", pim_ifp->pim_hello_period);
		if (pim_ifp->pim_default_holdtime != -1)
			vty_out(vty, " %d", pim_ifp->pim_default_holdtime);
		vty_out(vty, "\n");
		++writes;
	}

	writes += gm_config_write(vty, writes, pim_ifp);

	/* update source */
	if (!pim_addr_is_any(pim_ifp->update_source)) {
		vty_out(vty, " " PIM_AF_NAME " pim use-source %pPA\n",
			&pim_ifp->update_source);
		++writes;
	}

	if (pim_ifp->activeactive)
		vty_out(vty, " " PIM_AF_NAME " pim active-active\n");

	/* boundary */
	if (pim_ifp->boundary_oil_plist) {
		vty_out(vty, " " PIM_AF_NAME " multicast boundary oil %s\n",
			pim_ifp->boundary_oil_plist);
		++writes;
	}

	if (pim_ifp->pim_passive_enable) {
		vty_out(vty, " " PIM_AF_NAME " pim passive\n");
		++writes;
	}

	writes += pim_static_write_mroute(pim, vty, ifp);
	pim_bsm_write_config(vty, ifp);
	++writes;
	pim_bfd_write_config(vty, ifp);
	++writes;

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
			/* pim is enabled internally/implicitly on the vxlan
			 * termination device ipmr-lo. skip displaying that
			 * config to avoid confusion
			 */
			if (pim_vxlan_is_term_dev_cfg(pim, ifp))
				continue;

			/* IF name */
			if_vty_config_start(vty, ifp);

			++writes;

			if (ifp->desc) {
				vty_out(vty, " description %s\n", ifp->desc);
				++writes;
			}

			if (ifp->info) {
				pim_config_write(vty, writes, ifp, pim);
			}
			if_vty_config_end(vty);

			++writes;
		}
	}

	return writes;
}
