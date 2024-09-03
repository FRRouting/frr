// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_te.c
 *
 * This is an implementation of RFC5305 & RFC 7810
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 *
 * Copyright (C) 2014 - 2019 Orange Labs http://www.orange.com
 */

#include <zebra.h>
#include <math.h>

#include "linklist.h"
#include "frrevent.h"
#include "vty.h"
#include "stream.h"
#include "memory.h"
#include "log.h"
#include "prefix.h"
#include "command.h"
#include "hash.h"
#include "if.h"
#include "vrf.h"
#include "checksum.h"
#include "md5.h"
#include "sockunion.h"
#include "network.h"
#include "sbuf.h"
#include "link_state.h"
#include "lib/json.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isisd.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_tlvs.h"
#include "isisd/isis_mt.h"
#include "isisd/isis_te.h"
#include "isisd/isis_zebra.h"

DEFINE_MTYPE_STATIC(ISISD, ISIS_MPLS_TE,    "ISIS MPLS_TE parameters");

static void isis_mpls_te_circuit_ip_update(struct isis_circuit *circuit);

/*------------------------------------------------------------------------*
 * Following are control functions for MPLS-TE parameters management.
 *------------------------------------------------------------------------*/

/**
 * Create MPLS Traffic Engineering structure which belongs to given area.
 *
 * @param area	IS-IS Area
 */
void isis_mpls_te_create(struct isis_area *area)
{
	struct listnode *node;
	struct isis_circuit *circuit;

	if (!area)
		return;

	if (area->mta == NULL) {

		struct mpls_te_area *new;

		zlog_debug("ISIS-TE(%s): Initialize MPLS Traffic Engineering",
			   area->area_tag);

		new = XCALLOC(MTYPE_ISIS_MPLS_TE, sizeof(struct mpls_te_area));

		/* Initialize MPLS_TE structure */
		new->status = enable;
		new->level = 0;
		new->inter_as = off;
		new->interas_areaid.s_addr = 0;
		new->router_id.s_addr = 0;
		new->ted = ls_ted_new(1, "ISIS", 0);
		if (!new->ted)
			zlog_warn("Unable to create Link State Data Base");

		area->mta = new;
	} else {
		area->mta->status = enable;
	}

	/* Initialize Link State Database */
	if (area->mta->ted)
		isis_te_init_ted(area);

	/* Update Extended TLVs according to Interface link parameters
	 * and neighbor IP addresses
	 */
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		isis_link_params_update(circuit, circuit->interface);
		isis_mpls_te_circuit_ip_update(circuit);
	}
}

/**
 * Disable MPLS Traffic Engineering structure which belongs to given area.
 *
 * @param area	IS-IS Area
 */
void isis_mpls_te_disable(struct isis_area *area)
{
	struct listnode *node;
	struct isis_circuit *circuit;

	if (!area->mta)
		return;

	area->mta->status = disable;

	/* Remove Link State Database */
	ls_ted_clean(area->mta->ted);

	/* Disable Extended SubTLVs on all circuit */
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		if (!IS_EXT_TE(circuit->ext))
			continue;

		/* disable MPLS_TE Circuit keeping SR one's */
		if (IS_SUBTLV(circuit->ext, EXT_ADJ_SID))
			circuit->ext->status = EXT_ADJ_SID;
		else if (IS_SUBTLV(circuit->ext, EXT_LAN_ADJ_SID))
			circuit->ext->status = EXT_LAN_ADJ_SID;
		else
			circuit->ext->status = 0;
	}
}

void isis_mpls_te_term(struct isis_area *area)
{
	struct listnode *node;
	struct isis_circuit *circuit;

	if (!area->mta)
		return;

	zlog_info("TE(%s): Terminate MPLS TE", __func__);
	/* Remove Link State Database */
	ls_ted_del_all(&area->mta->ted);

	/* Remove Extended SubTLVs */
	zlog_info(" |- Remove Extended SubTLVS for all circuit");
	for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit)) {
		zlog_info("   |- Call isis_del_ext_subtlvs()");
		isis_del_ext_subtlvs(circuit->ext);
		circuit->ext = NULL;
	}

	zlog_info(" |- Free MTA structure at %p", area->mta);
	XFREE(MTYPE_ISIS_MPLS_TE, area->mta);
}

static void isis_link_params_update_asla(struct isis_circuit *circuit,
					 struct interface *ifp)
{
	struct isis_asla_subtlvs *asla;
	struct listnode *node, *nnode;
	struct isis_ext_subtlvs *ext = circuit->ext;
	int i;

	if (!ext)
		/* no extended subTLVs - nothing to update */
		return;

	if (!HAS_LINK_PARAMS(ifp)) {
		list_delete_all_node(ext->aslas);
		return;
	}

#ifndef FABRICD
	/* RFC 8919 Application Specific Link-Attributes
	 * is required by flex-algo application ISIS_SABM_FLAG_X
	 */
	if (list_isempty(circuit->area->flex_algos->flex_algos))
		isis_tlvs_free_asla(ext, ISIS_SABM_FLAG_X);
	else
		isis_tlvs_find_alloc_asla(ext, ISIS_SABM_FLAG_X);
#endif /* ifndef FABRICD */

	if (list_isempty(ext->aslas))
		return;

	for (ALL_LIST_ELEMENTS(ext->aslas, node, nnode, asla)) {
		asla->legacy = circuit->area->asla_legacy_flag;
		RESET_SUBTLV(asla);

		if (asla->legacy)
			continue;

		/* Fulfill ASLA subTLVs from interface link parameters */
		if (IS_PARAM_SET(ifp->link_params, LP_ADM_GRP)) {
			asla->admin_group = ifp->link_params->admin_grp;
			SET_SUBTLV(asla, EXT_ADM_GRP);
		} else
			UNSET_SUBTLV(asla, EXT_ADM_GRP);

		if (IS_PARAM_SET(ifp->link_params, LP_EXTEND_ADM_GRP)) {
			admin_group_copy(&asla->ext_admin_group,
					 &ifp->link_params->ext_admin_grp);
			SET_SUBTLV(asla, EXT_EXTEND_ADM_GRP);
		} else
			UNSET_SUBTLV(asla, EXT_EXTEND_ADM_GRP);

		/* Send admin-group zero for better compatibility
		 * https://www.rfc-editor.org/rfc/rfc7308#section-2.3.2
		 */
		if (circuit->area->admin_group_send_zero &&
		    !IS_SUBTLV(asla, EXT_ADM_GRP) &&
		    !IS_SUBTLV(asla, EXT_EXTEND_ADM_GRP)) {
			asla->admin_group = 0;
			SET_SUBTLV(asla, EXT_ADM_GRP);
			admin_group_clear(&asla->ext_admin_group);
			admin_group_allow_explicit_zero(&asla->ext_admin_group);
			SET_SUBTLV(asla, EXT_EXTEND_ADM_GRP);
		}

		if (IS_PARAM_SET(ifp->link_params, LP_TE_METRIC)) {
			asla->te_metric = ifp->link_params->te_metric;
			SET_SUBTLV(asla, EXT_TE_METRIC);
		} else
			UNSET_SUBTLV(asla, EXT_TE_METRIC);

		if (IS_PARAM_SET(ifp->link_params, LP_DELAY)) {
			asla->delay = ifp->link_params->av_delay;
			SET_SUBTLV(asla, EXT_DELAY);
		} else
			UNSET_SUBTLV(asla, EXT_DELAY);

		if (IS_PARAM_SET(ifp->link_params, LP_MM_DELAY)) {
			asla->min_delay = ifp->link_params->min_delay;
			asla->max_delay = ifp->link_params->max_delay;
			SET_SUBTLV(asla, EXT_MM_DELAY);
		} else {
			UNSET_SUBTLV(asla, EXT_MM_DELAY);
		}

		if (asla->standard_apps == ISIS_SABM_FLAG_X)
			/* Flex-Algo ASLA does not need the following TE
			 * sub-TLVs
			 */
			continue;

		if (IS_PARAM_SET(ifp->link_params, LP_MAX_BW)) {
			asla->max_bw = ifp->link_params->max_bw;
			SET_SUBTLV(asla, EXT_MAX_BW);
		} else
			UNSET_SUBTLV(asla, EXT_MAX_BW);

		if (IS_PARAM_SET(ifp->link_params, LP_MAX_RSV_BW)) {
			asla->max_rsv_bw = ifp->link_params->max_rsv_bw;
			SET_SUBTLV(asla, EXT_MAX_RSV_BW);
		} else
			UNSET_SUBTLV(asla, EXT_MAX_RSV_BW);

		if (IS_PARAM_SET(ifp->link_params, LP_UNRSV_BW)) {
			for (i = 0; i < MAX_CLASS_TYPE; i++)
				asla->unrsv_bw[i] =
					ifp->link_params->unrsv_bw[i];
			SET_SUBTLV(asla, EXT_UNRSV_BW);
		} else
			UNSET_SUBTLV(asla, EXT_UNRSV_BW);

		if (IS_PARAM_SET(ifp->link_params, LP_DELAY_VAR)) {
			asla->delay_var = ifp->link_params->delay_var;
			SET_SUBTLV(asla, EXT_DELAY_VAR);
		} else
			UNSET_SUBTLV(asla, EXT_DELAY_VAR);

		if (IS_PARAM_SET(ifp->link_params, LP_PKT_LOSS)) {
			asla->pkt_loss = ifp->link_params->pkt_loss;
			SET_SUBTLV(asla, EXT_PKT_LOSS);
		} else
			UNSET_SUBTLV(asla, EXT_PKT_LOSS);

		if (IS_PARAM_SET(ifp->link_params, LP_RES_BW)) {
			asla->res_bw = ifp->link_params->res_bw;
			SET_SUBTLV(asla, EXT_RES_BW);
		} else
			UNSET_SUBTLV(asla, EXT_RES_BW);

		if (IS_PARAM_SET(ifp->link_params, LP_AVA_BW)) {
			asla->ava_bw = ifp->link_params->ava_bw;
			SET_SUBTLV(asla, EXT_AVA_BW);
		} else
			UNSET_SUBTLV(asla, EXT_AVA_BW);

		if (IS_PARAM_SET(ifp->link_params, LP_USE_BW)) {
			asla->use_bw = ifp->link_params->use_bw;
			SET_SUBTLV(asla, EXT_USE_BW);
		} else
			UNSET_SUBTLV(asla, EXT_USE_BW);
	}


	for (ALL_LIST_ELEMENTS(ext->aslas, node, nnode, asla)) {
		if (!asla->legacy && NO_SUBTLV(asla) &&
		    admin_group_nb_words(&asla->ext_admin_group) == 0)
			/* remove ASLA without info from the list of ASLAs to
			 * not send void ASLA
			 */
			isis_tlvs_del_asla_flex_algo(ext, asla);
	}
}

/* Main initialization / update function of the MPLS TE Circuit context */
/* Call when interface TE Link parameters are modified */
void isis_link_params_update(struct isis_circuit *circuit,
			     struct interface *ifp)
{
	int i;
	struct prefix_ipv4 *addr;
	struct prefix_ipv6 *addr6;
	struct isis_ext_subtlvs *ext;

	/* Check if TE is enable or not */
	if (!circuit->area || !IS_MPLS_TE(circuit->area->mta))
		return;

	/* Sanity Check */
	if (ifp == NULL)
		return;

	te_debug("ISIS-TE(%s): Update circuit parameters for interface %s",
		 circuit->area->area_tag, ifp->name);

	/* Check if MPLS TE Circuit context has not been already created */
	if (circuit->ext == NULL) {
		circuit->ext = isis_alloc_ext_subtlvs();
		te_debug("  |- Allocated new Ext-subTLVs for interface %s",
			 ifp->name);
	}

	ext = circuit->ext;

	/* Fulfill Extended subTLVs from interface link parameters */
	if (HAS_LINK_PARAMS(ifp)) {
		/* STD_TE metrics */
		if (IS_PARAM_SET(ifp->link_params, LP_ADM_GRP)) {
			ext->adm_group = ifp->link_params->admin_grp;
			SET_SUBTLV(ext, EXT_ADM_GRP);
		} else
			UNSET_SUBTLV(ext, EXT_ADM_GRP);

		if (IS_PARAM_SET(ifp->link_params, LP_EXTEND_ADM_GRP)) {
			admin_group_copy(&ext->ext_admin_group,
					 &ifp->link_params->ext_admin_grp);
			SET_SUBTLV(ext, EXT_EXTEND_ADM_GRP);
		} else
			UNSET_SUBTLV(ext, EXT_EXTEND_ADM_GRP);

		/* Send admin-group zero for better compatibility
		 * https://www.rfc-editor.org/rfc/rfc7308#section-2.3.2
		 */
		if (circuit->area->admin_group_send_zero &&
		    !IS_SUBTLV(ext, EXT_ADM_GRP) &&
		    !IS_SUBTLV(ext, EXT_EXTEND_ADM_GRP)) {
			ext->adm_group = 0;
			SET_SUBTLV(ext, EXT_ADM_GRP);
			admin_group_clear(&ext->ext_admin_group);
			admin_group_allow_explicit_zero(&ext->ext_admin_group);
			SET_SUBTLV(ext, EXT_EXTEND_ADM_GRP);
		}

		/* If known, register local IPv4 addr from ip_addr list */
		if (listcount(circuit->ip_addrs) != 0) {
			addr = (struct prefix_ipv4 *)listgetdata(
				(struct listnode *)listhead(circuit->ip_addrs));
			IPV4_ADDR_COPY(&ext->local_addr, &addr->prefix);
			SET_SUBTLV(ext, EXT_LOCAL_ADDR);
		} else
			UNSET_SUBTLV(ext, EXT_LOCAL_ADDR);

		/* If known, register local IPv6 addr from ip_addr list */
		if (listcount(circuit->ipv6_non_link) != 0) {
			addr6 = (struct prefix_ipv6 *)listgetdata(
				(struct listnode *)listhead(
					circuit->ipv6_non_link));
			IPV6_ADDR_COPY(&ext->local_addr6, &addr6->prefix);
			SET_SUBTLV(ext, EXT_LOCAL_ADDR6);
		} else
			UNSET_SUBTLV(ext, EXT_LOCAL_ADDR6);

		/*
		 * Remote IPv4 and IPv6 addresses are now added in
		 * isis_mpls_te_adj_ip_enabled() to get the right IP address
		 * in particular for IPv6 to get the global IPv6 address and
		 * not the link-local IPv6 address.
		 */

		if (IS_PARAM_SET(ifp->link_params, LP_MAX_BW)) {
			ext->max_bw = ifp->link_params->max_bw;
			SET_SUBTLV(ext, EXT_MAX_BW);
		} else
			UNSET_SUBTLV(ext, EXT_MAX_BW);

		if (IS_PARAM_SET(ifp->link_params, LP_MAX_RSV_BW)) {
			ext->max_rsv_bw = ifp->link_params->max_rsv_bw;
			SET_SUBTLV(ext, EXT_MAX_RSV_BW);
		} else
			UNSET_SUBTLV(ext, EXT_MAX_RSV_BW);

		if (IS_PARAM_SET(ifp->link_params, LP_UNRSV_BW)) {
			for (i = 0; i < MAX_CLASS_TYPE; i++)
				ext->unrsv_bw[i] =
					ifp->link_params->unrsv_bw[i];
			SET_SUBTLV(ext, EXT_UNRSV_BW);
		} else
			UNSET_SUBTLV(ext, EXT_UNRSV_BW);

		if (IS_PARAM_SET(ifp->link_params, LP_TE_METRIC)) {
			ext->te_metric = ifp->link_params->te_metric;
			SET_SUBTLV(ext, EXT_TE_METRIC);
		} else
			UNSET_SUBTLV(ext, EXT_TE_METRIC);

		/* TE metric extensions */
		if (IS_PARAM_SET(ifp->link_params, LP_DELAY)) {
			ext->delay = ifp->link_params->av_delay;
			SET_SUBTLV(ext, EXT_DELAY);
		} else
			UNSET_SUBTLV(ext, EXT_DELAY);

		if (IS_PARAM_SET(ifp->link_params, LP_MM_DELAY)) {
			ext->min_delay = ifp->link_params->min_delay;
			ext->max_delay = ifp->link_params->max_delay;
			SET_SUBTLV(ext, EXT_MM_DELAY);
		} else
			UNSET_SUBTLV(ext, EXT_MM_DELAY);

		if (IS_PARAM_SET(ifp->link_params, LP_DELAY_VAR)) {
			ext->delay_var = ifp->link_params->delay_var;
			SET_SUBTLV(ext, EXT_DELAY_VAR);
		} else
			UNSET_SUBTLV(ext, EXT_DELAY_VAR);

		if (IS_PARAM_SET(ifp->link_params, LP_PKT_LOSS)) {
			ext->pkt_loss = ifp->link_params->pkt_loss;
			SET_SUBTLV(ext, EXT_PKT_LOSS);
		} else
			UNSET_SUBTLV(ext, EXT_PKT_LOSS);

		if (IS_PARAM_SET(ifp->link_params, LP_RES_BW)) {
			ext->res_bw = ifp->link_params->res_bw;
			SET_SUBTLV(ext, EXT_RES_BW);
		} else
			UNSET_SUBTLV(ext, EXT_RES_BW);

		if (IS_PARAM_SET(ifp->link_params, LP_AVA_BW)) {
			ext->ava_bw = ifp->link_params->ava_bw;
			SET_SUBTLV(ext, EXT_AVA_BW);
		} else
			UNSET_SUBTLV(ext, EXT_AVA_BW);

		if (IS_PARAM_SET(ifp->link_params, LP_USE_BW)) {
			ext->use_bw = ifp->link_params->use_bw;
			SET_SUBTLV(ext, EXT_USE_BW);
		} else
			UNSET_SUBTLV(ext, EXT_USE_BW);

		/* INTER_AS */
		if (IS_PARAM_SET(ifp->link_params, LP_RMT_AS)) {
			ext->remote_as = ifp->link_params->rmt_as;
			ext->remote_ip = ifp->link_params->rmt_ip;
			SET_SUBTLV(ext, EXT_RMT_AS);
			SET_SUBTLV(ext, EXT_RMT_IP);
		} else {
			/* reset inter-as TE params */
			UNSET_SUBTLV(ext, EXT_RMT_AS);
			UNSET_SUBTLV(ext, EXT_RMT_IP);
		}
		te_debug("  |- New MPLS-TE link parameters status 0x%x",
			 ext->status);
	} else {
		te_debug("  |- Reset Extended subTLVs status 0x%x",
			 ext->status);
		/* Reset TE subTLVs keeping SR one's */
		if (IS_SUBTLV(ext, EXT_ADJ_SID))
			ext->status = EXT_ADJ_SID;
		else if (IS_SUBTLV(ext, EXT_LAN_ADJ_SID))
			ext->status = EXT_LAN_ADJ_SID;
		else if (IS_SUBTLV(ext, EXT_SRV6_LAN_ENDX_SID))
			ext->status = EXT_SRV6_LAN_ENDX_SID;
		else if (IS_SUBTLV(ext, EXT_SRV6_ENDX_SID))
			ext->status = EXT_SRV6_ENDX_SID;
		else
			ext->status = 0;
	}

	isis_link_params_update_asla(circuit, ifp);

	return;
}

static int _isis_mpls_te_adj_ip_enabled(struct isis_adjacency *adj, int family,
					bool global)
{
	struct isis_circuit *circuit;
	struct isis_ext_subtlvs *ext;

	circuit = adj->circuit;

	/* Check that MPLS TE is enabled */
	if (!IS_MPLS_TE(circuit->area->mta) || !circuit->ext)
		return 0;

	ext = circuit->ext;

	/* Determine nexthop IP address */
	switch (family) {
	case AF_INET:
		if (!circuit->ip_router || !adj->ipv4_address_count)
			UNSET_SUBTLV(ext, EXT_NEIGH_ADDR);
		else {
			IPV4_ADDR_COPY(&ext->neigh_addr,
				       &adj->ipv4_addresses[0]);
			SET_SUBTLV(ext, EXT_NEIGH_ADDR);
		}
		break;
	case AF_INET6:
		/* Nothing to do for link-local addresses - ie. not global.
		 * https://datatracker.ietf.org/doc/html/rfc6119#section-3.1.1
		 * Because the IPv6 traffic engineering TLVs present in LSPs are
		 * propagated across networks, they MUST NOT use link-local
		 * addresses.
		 */
		if (!global)
			return 0;

		if (!circuit->ipv6_router || !adj->global_ipv6_count)
			UNSET_SUBTLV(ext, EXT_NEIGH_ADDR6);
		else {
			IPV6_ADDR_COPY(&ext->neigh_addr6,
				       &adj->global_ipv6_addrs[0]);
			SET_SUBTLV(ext, EXT_NEIGH_ADDR6);
		}
		break;
	default:
		return 0;
	}

	return 0;
}

static int isis_mpls_te_adj_ip_enabled(struct isis_adjacency *adj, int family,
				       bool global)
{
	int ret;

	/* Sanity Check */
	if (!adj || !adj->circuit)
		return 0;

	ret = _isis_mpls_te_adj_ip_enabled(adj, family, global);

	/* Update LSP */
	lsp_regenerate_schedule(adj->circuit->area, adj->circuit->is_type, 0);

	return ret;
}

static int _isis_mpls_te_adj_ip_disabled(struct isis_adjacency *adj, int family,
					 bool global)
{
	struct isis_circuit *circuit;
	struct isis_ext_subtlvs *ext;

	circuit = adj->circuit;

	/* Check that MPLS TE is enabled */
	if (!IS_MPLS_TE(circuit->area->mta) || !circuit->ext)
		return 0;

	ext = circuit->ext;

	/* Update MPLS TE IP address parameters if possible */
	if (!IS_MPLS_TE(circuit->area->mta) || !IS_EXT_TE(ext))
		return 0;

	/* Determine nexthop IP address */
	switch (family) {
	case AF_INET:
		UNSET_SUBTLV(ext, EXT_NEIGH_ADDR);
		break;
	case AF_INET6:
		if (global)
			UNSET_SUBTLV(ext, EXT_NEIGH_ADDR6);
		break;
	default:
		return 0;
	}

	return 0;
}

static int isis_mpls_te_adj_ip_disabled(struct isis_adjacency *adj, int family,
					bool global)
{
	int ret;

	/* Sanity Check */
	if (!adj || !adj->circuit || !adj->circuit->ext)
		return 0;

	ret = _isis_mpls_te_adj_ip_disabled(adj, family, global);

	/* Update LSP */
	lsp_regenerate_schedule(adj->circuit->area, adj->circuit->is_type, 0);

	return ret;
}

static void isis_mpls_te_circuit_ip_update(struct isis_circuit *circuit)
{
	struct isis_adjacency *adj;

	/* https://datatracker.ietf.org/doc/html/rfc6119#section-3.2.3
	 * This sub-TLV of the Extended IS Reachability TLV is used for point-
	 * to-point links
	 */
	if (circuit->circ_type != CIRCUIT_T_P2P)
		return;

	adj = circuit->u.p2p.neighbor;

	if (!adj)
		return;

	/* Nothing to do for link-local addresses.
	 * https://datatracker.ietf.org/doc/html/rfc6119#section-3.1.1
	 * Because the IPv6 traffic engineering TLVs present in LSPs are
	 * propagated across networks, they MUST NOT use link-local addresses.
	 */
	if (adj->ipv4_address_count > 0)
		_isis_mpls_te_adj_ip_enabled(adj, AF_INET, false);
	else
		_isis_mpls_te_adj_ip_disabled(adj, AF_INET, false);

	if (adj->global_ipv6_count > 0)
		_isis_mpls_te_adj_ip_enabled(adj, AF_INET6, true);
	else
		_isis_mpls_te_adj_ip_disabled(adj, AF_INET6, true);
}


int isis_mpls_te_update(struct interface *ifp)
{
	struct isis_circuit *circuit;
	uint8_t rc = 1;

	/* Sanity Check */
	if (ifp == NULL)
		return rc;

	/* Get circuit context from interface */
	circuit = circuit_scan_by_ifp(ifp);
	if (circuit == NULL)
		return rc;

	/* Update TE TLVs ... */
	isis_link_params_update(circuit, ifp);

	/* ... and LSP */
	if (circuit->area &&
	    (IS_MPLS_TE(circuit->area->mta)
#ifndef FABRICD
	     || !list_isempty(circuit->area->flex_algos->flex_algos)
#endif /* ifndef FABRICD */
		     ))
		lsp_regenerate_schedule(circuit->area, circuit->is_type, 0);

	rc = 0;
	return rc;
}


/**
 * Export Link State information to consumer daemon through ZAPI Link State
 * Opaque Message.
 *
 * @param type		Type of Link State Element i.e. Vertex, Edge or Subnet
 * @param link_state	Pointer to Link State Vertex, Edge or Subnet
 *
 * @return		0 if success, -1 otherwise
 */
static int isis_te_export(uint8_t type, void *link_state)
{
	struct ls_message msg = {};
	int rc = 0;

	switch (type) {
	case LS_MSG_TYPE_NODE:
		ls_vertex2msg(&msg, (struct ls_vertex *)link_state);
		rc = ls_send_msg(zclient, &msg, NULL);
		break;
	case LS_MSG_TYPE_ATTRIBUTES:
		ls_edge2msg(&msg, (struct ls_edge *)link_state);
		rc = ls_send_msg(zclient, &msg, NULL);
		break;
	case LS_MSG_TYPE_PREFIX:
		ls_subnet2msg(&msg, (struct ls_subnet *)link_state);
		rc = ls_send_msg(zclient, &msg, NULL);
		break;
	default:
		rc = -1;
		break;
	}

	return rc;
}

/**
 * Parse LSP and build corresponding vertex. If vertex doesn't exist in the
 * Link State Database it is created otherwise updated.
 *
 * @param ted	Traffic Engineering Link State Database
 * @param lsp	IS-IS Link State PDU
 *
 * @return	Link State Vertex or NULL in case of error
 */
static struct ls_vertex *lsp_to_vertex(struct ls_ted *ted, struct isis_lsp *lsp)
{
	struct ls_vertex *vertex = NULL;
	struct ls_node *old, lnode = {};
	struct isis_tlvs *tlvs;
	const struct in_addr inaddr_any = {.s_addr = INADDR_ANY};

	/* Sanity check */
	if (!ted || !lsp)
		return NULL;

	/* Compute Link State Node ID from IS-IS sysID ... */
	if (lsp->level == ISIS_LEVEL1)
		lnode.adv.origin = ISIS_L1;
	else
		lnode.adv.origin = ISIS_L2;
	memcpy(&lnode.adv.id.iso.sys_id, &lsp->hdr.lsp_id, ISIS_SYS_ID_LEN);
	lnode.adv.id.iso.level = lsp->level;
	/* ... and search the corresponding vertex */
	vertex = ls_find_vertex_by_id(ted, lnode.adv);
	/* Create a new one if not found */
	if (!vertex) {
		old = ls_node_new(lnode.adv, inaddr_any, in6addr_any);
		old->type = STANDARD;
		vertex = ls_vertex_add(ted, old);
	}
	old = vertex->node;
	te_debug("  |- %s Vertex (%" PRIu64 ") for node %s",
		 vertex->status == NEW ? "Create" : "Found", vertex->key,
		 print_sys_hostname(old->adv.id.iso.sys_id));

	/* Fulfill Link State Node information */
	tlvs = lsp->tlvs;
	if (tlvs) {
		if (tlvs->te_router_id) {
			IPV4_ADDR_COPY(&lnode.router_id, tlvs->te_router_id);
			SET_FLAG(lnode.flags, LS_NODE_ROUTER_ID);
		}
		if (tlvs->te_router_id_ipv6) {
			IPV6_ADDR_COPY(&lnode.router_id6,
				       tlvs->te_router_id_ipv6);
			SET_FLAG(lnode.flags, LS_NODE_ROUTER_ID6);
		}
		if (tlvs->hostname) {
			strlcpy(lnode.name, tlvs->hostname, MAX_NAME_LENGTH);
			SET_FLAG(lnode.flags, LS_NODE_NAME);
		}
		if (tlvs->router_cap) {
			struct isis_router_cap *cap = tlvs->router_cap;

			if (cap->srgb.lower_bound != 0
			    && cap->srgb.range_size != 0) {
				SET_FLAG(lnode.flags, LS_NODE_SR);
				lnode.srgb.flag = cap->srgb.flags;
				lnode.srgb.lower_bound = cap->srgb.lower_bound;
				lnode.srgb.range_size = cap->srgb.range_size;
				for (int i = 0; i < LIB_LS_SR_ALGO_COUNT; i++)
					lnode.algo[i] = cap->algo[i];
			}

			if (cap->srlb.lower_bound != 0
			    && cap->srlb.range_size != 0) {
				lnode.srlb.lower_bound = cap->srlb.lower_bound;
				lnode.srlb.range_size = cap->srlb.range_size;
				SET_FLAG(lnode.flags, LS_NODE_SRLB);
			}
			if (cap->msd != 0) {
				lnode.msd = cap->msd;
				SET_FLAG(lnode.flags, LS_NODE_MSD);
			}
			if (cap->srv6_cap.is_srv6_capable) {
				SET_FLAG(lnode.flags, LS_NODE_SRV6);
				lnode.srv6_cap_flags = cap->srv6_cap.flags;
				memcpy(&lnode.srv6_msd, &cap->srv6_msd,
				       sizeof(struct isis_srv6_msd));
			}
		}
	}

	/* Update Link State Node information */
	if (!ls_node_same(old, &lnode)) {
		te_debug("    |- Update Link State Node information");
		memcpy(old, &lnode, sizeof(struct ls_node));
		if (vertex->status != NEW)
			vertex->status = UPDATE;
	}

	/* Set self TED vertex if LSP corresponds to the own router */
	if (lsp->own_lsp)
		ted->self = vertex;

	return vertex;
}

/**
 * Get Link State Edge from Link State Attributes in TE Database.
 * Edge structure is dynamically allocated and fulfill with Link State
 * Attributes if not found.
 *
 * @param ted	Link State Database
 * @param attr	Link State Attributes
 *
 * @return	New Link State Edge if success, NULL otherwise
 */
static struct ls_edge *get_edge(struct ls_ted *ted, struct ls_attributes *attr)
{
	struct ls_edge *edge;
	struct ls_standard *std;
	struct ls_edge_key key;

	/* Check parameters */
	if (!ted || !attr)
		return NULL;

	std = &attr->standard;

	/* Compute keys in function of local address (IPv4/v6) or identifier */
	if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR)) {
		key.family = AF_INET;
		IPV4_ADDR_COPY(&key.k.addr, &std->local);
	} else if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ADDR6)) {
		key.family = AF_INET6;
		IPV6_ADDR_COPY(&key.k.addr6, &std->local6);
	} else if (CHECK_FLAG(attr->flags, LS_ATTR_LOCAL_ID)) {
		key.family = AF_LOCAL;
		key.k.link_id = (((uint64_t)std->local_id) & 0xffffffff) |
				((uint64_t)std->remote_id << 32);
	} else {
		key.family = AF_UNSPEC;
	}

	/* Stop here if we don't got a valid key */
	if (key.family == AF_UNSPEC)
		return NULL;

	/* Get corresponding Edge by key from Link State Data Base */
	edge = ls_find_edge_by_key(ted, key);

	/* and create new one if not exist */
	if (!edge) {
		edge = ls_edge_add(ted, attr);
		/*
		 * Edge could be Null if no local ID is found in Attributes.
		 * Stop the processing as without any local ID it is not
		 * possible to store Edge in the TED.
		 */
		if (!edge)
			return NULL;
	}

	if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_LOCAL_ADDR))
		te_debug("    |- %s Edge (%pI4) from Extended Reach. %pI4",
			 edge->status == NEW ? "Create" : "Found",
			 &edge->key.k.addr, &attr->standard.local);
	else if (CHECK_FLAG(edge->attributes->flags, LS_ATTR_LOCAL_ADDR6))
		te_debug("    |- %s Edge (%pI6) from Extended Reach. %pI6",
			 edge->status == NEW ? "Create" : "Found",
			 &edge->key.k.addr6, &attr->standard.local6);
	else
		te_debug("    |- %s Edge (%" PRIu64 ")",
			 edge->status == NEW ? "Create" : "Found",
			 edge->key.k.link_id);

	return edge;
}

/**
 * Get Link State Attributes from IS-IS Sub-TLVs. Structure is dynamically
 * allocated and should be free once not use anymore.
 *
 * @param adv	Link State Node ID
 * @param tlvs	IS-IS Sub TLVs
 *
 * @return	New Link State attributes if success, NULL otherwise
 */
static struct ls_attributes *get_attributes(struct ls_node_id adv,
					    struct isis_ext_subtlvs *tlvs)
{
	struct ls_attributes *attr;
	struct in_addr local = {.s_addr = INADDR_ANY};
	struct in6_addr local6 = in6addr_any;
	uint32_t local_id = 0;

	/* Got Local identifier */
	if (CHECK_FLAG(tlvs->status, EXT_LOCAL_ADDR))
		local.s_addr = tlvs->local_addr.s_addr;

	if (CHECK_FLAG(tlvs->status, EXT_LOCAL_ADDR6))
		memcpy(&local6, &tlvs->local_addr6, IPV6_MAX_BYTELEN);

	if (CHECK_FLAG(tlvs->status, EXT_LLRI))
		local_id = tlvs->local_llri;

	/* Create LS Attributes */
	attr = ls_attributes_new(adv, local, local6, local_id);
	if (!attr)
		return NULL;

	/* Browse sub-TLV and fulfill Link State Attributes */
	if (CHECK_FLAG(tlvs->status, EXT_ADM_GRP)) {
		attr->standard.admin_group = tlvs->adm_group;
		SET_FLAG(attr->flags, LS_ATTR_ADM_GRP);
	}
	if (CHECK_FLAG(tlvs->status, EXT_EXTEND_ADM_GRP)) {
		admin_group_copy(&attr->ext_admin_group,
				 &tlvs->ext_admin_group);
		SET_FLAG(attr->flags, LS_ATTR_EXT_ADM_GRP);
	}
	if (CHECK_FLAG(tlvs->status, EXT_LLRI)) {
		attr->standard.local_id = tlvs->local_llri;
		attr->standard.remote_id = tlvs->remote_llri;
		SET_FLAG(attr->flags, LS_ATTR_LOCAL_ID);
		SET_FLAG(attr->flags, LS_ATTR_NEIGH_ID);
	}
	if (CHECK_FLAG(tlvs->status, EXT_NEIGH_ADDR)) {
		attr->standard.remote.s_addr = tlvs->neigh_addr.s_addr;
		SET_FLAG(attr->flags, LS_ATTR_NEIGH_ADDR);
	}
	if (CHECK_FLAG(tlvs->status, EXT_NEIGH_ADDR6)) {
		memcpy(&attr->standard.remote6, &tlvs->neigh_addr6,
		       IPV6_MAX_BYTELEN);
		SET_FLAG(attr->flags, LS_ATTR_NEIGH_ADDR6);
	}
	if (CHECK_FLAG(tlvs->status, EXT_MAX_BW)) {
		attr->standard.max_bw = tlvs->max_bw;
		SET_FLAG(attr->flags, LS_ATTR_MAX_BW);
	}
	if (CHECK_FLAG(tlvs->status, EXT_MAX_RSV_BW)) {
		attr->standard.max_rsv_bw = tlvs->max_rsv_bw;
		SET_FLAG(attr->flags, LS_ATTR_MAX_RSV_BW);
	}
	if (CHECK_FLAG(tlvs->status, EXT_UNRSV_BW)) {
		memcpy(&attr->standard.unrsv_bw, tlvs->unrsv_bw,
		       ISIS_SUBTLV_UNRSV_BW_SIZE);
		SET_FLAG(attr->flags, LS_ATTR_UNRSV_BW);
	}
	if (CHECK_FLAG(tlvs->status, EXT_TE_METRIC)) {
		attr->standard.te_metric = tlvs->te_metric;
		SET_FLAG(attr->flags, LS_ATTR_TE_METRIC);
	}
	if (CHECK_FLAG(tlvs->status, EXT_RMT_AS)) {
		attr->standard.remote_as = tlvs->remote_as;
		SET_FLAG(attr->flags, LS_ATTR_REMOTE_AS);
	}
	if (CHECK_FLAG(tlvs->status, EXT_RMT_IP)) {
		attr->standard.remote_addr = tlvs->remote_ip;
		SET_FLAG(attr->flags, LS_ATTR_REMOTE_ADDR);
	}
	if (CHECK_FLAG(tlvs->status, EXT_DELAY)) {
		attr->extended.delay = tlvs->delay;
		SET_FLAG(attr->flags, LS_ATTR_DELAY);
	}
	if (CHECK_FLAG(tlvs->status, EXT_MM_DELAY)) {
		attr->extended.min_delay = tlvs->min_delay;
		attr->extended.max_delay = tlvs->max_delay;
		SET_FLAG(attr->flags, LS_ATTR_MIN_MAX_DELAY);
	}
	if (CHECK_FLAG(tlvs->status, EXT_DELAY_VAR)) {
		attr->extended.jitter = tlvs->delay_var;
		SET_FLAG(attr->flags, LS_ATTR_JITTER);
	}
	if (CHECK_FLAG(tlvs->status, EXT_PKT_LOSS)) {
		attr->extended.pkt_loss = tlvs->pkt_loss;
		SET_FLAG(attr->flags, LS_ATTR_PACKET_LOSS);
	}
	if (CHECK_FLAG(tlvs->status, EXT_AVA_BW)) {
		attr->extended.ava_bw = tlvs->ava_bw;
		SET_FLAG(attr->flags, LS_ATTR_AVA_BW);
	}
	if (CHECK_FLAG(tlvs->status, EXT_RES_BW)) {
		attr->extended.rsv_bw = tlvs->res_bw;
		SET_FLAG(attr->flags, LS_ATTR_RSV_BW);
	}
	if (CHECK_FLAG(tlvs->status, EXT_USE_BW)) {
		attr->extended.used_bw = tlvs->use_bw;
		SET_FLAG(attr->flags, LS_ATTR_USE_BW);
	}
	if (CHECK_FLAG(tlvs->status, EXT_ADJ_SID)) {
		struct isis_adj_sid *adj =
			(struct isis_adj_sid *)tlvs->adj_sid.head;
		int i;
		for (; adj; adj = adj->next) {
			i = adj->flags & EXT_SUBTLV_LINK_ADJ_SID_BFLG ? 1 : 0;
			i += adj->flags & EXT_SUBTLV_LINK_ADJ_SID_FFLG ? 2 : 0;
			attr->adj_sid[i].flags = adj->flags;
			attr->adj_sid[i].weight = adj->weight;
			attr->adj_sid[i].sid = adj->sid;
			switch (i) {
			case ADJ_PRI_IPV4:
				SET_FLAG(attr->flags, LS_ATTR_ADJ_SID);
				break;
			case ADJ_BCK_IPV4:
				SET_FLAG(attr->flags, LS_ATTR_BCK_ADJ_SID);
				break;
			case ADJ_PRI_IPV6:
				SET_FLAG(attr->flags, LS_ATTR_ADJ_SID6);
				break;
			case ADJ_BCK_IPV6:
				SET_FLAG(attr->flags, LS_ATTR_BCK_ADJ_SID6);
				break;
			}
		}
	}
	if (CHECK_FLAG(tlvs->status, EXT_LAN_ADJ_SID)) {
		struct isis_lan_adj_sid *ladj =
			(struct isis_lan_adj_sid *)tlvs->lan_sid.head;
		int i;
		for (; ladj; ladj = ladj->next) {
			i = ladj->flags & EXT_SUBTLV_LINK_ADJ_SID_BFLG ? 1 : 0;
			i += ladj->flags & EXT_SUBTLV_LINK_ADJ_SID_FFLG ? 2 : 0;
			attr->adj_sid[i].flags = ladj->flags;
			attr->adj_sid[i].weight = ladj->weight;
			attr->adj_sid[i].sid = ladj->sid;
			memcpy(&attr->adj_sid[i].neighbor.sysid,
			       &ladj->neighbor_id, ISIS_SYS_ID_LEN);
			switch (i) {
			case ADJ_PRI_IPV4:
				SET_FLAG(attr->flags, LS_ATTR_ADJ_SID);
				break;
			case ADJ_BCK_IPV4:
				SET_FLAG(attr->flags, LS_ATTR_BCK_ADJ_SID);
				break;
			case ADJ_PRI_IPV6:
				SET_FLAG(attr->flags, LS_ATTR_ADJ_SID6);
				break;
			case ADJ_BCK_IPV6:
				SET_FLAG(attr->flags, LS_ATTR_BCK_ADJ_SID6);
				break;
			}
		}
	}
	if (CHECK_FLAG(tlvs->status, EXT_SRV6_ENDX_SID)) {
		struct isis_srv6_endx_sid_subtlv *endx =
			(struct isis_srv6_endx_sid_subtlv *)
				tlvs->srv6_endx_sid.head;
		int i;

		for (; endx; endx = endx->next) {
			if (endx->flags & EXT_SUBTLV_LINK_SRV6_ENDX_SID_BFLG) {
				i = 1;
				SET_FLAG(attr->flags, LS_ATTR_BCK_ADJ_SRV6SID);
			} else {
				i = 0;
				SET_FLAG(attr->flags, LS_ATTR_ADJ_SRV6SID);
			}
			attr->adj_srv6_sid[i].flags = endx->flags;
			attr->adj_srv6_sid[i].weight = endx->weight;
			memcpy(&attr->adj_srv6_sid[i].sid, &endx->sid,
			       sizeof(struct in6_addr));
			attr->adj_srv6_sid[i].endpoint_behavior = endx->behavior;
		}
	}
	if (CHECK_FLAG(tlvs->status, EXT_SRV6_LAN_ENDX_SID)) {
		struct isis_srv6_lan_endx_sid_subtlv *lendx =
			(struct isis_srv6_lan_endx_sid_subtlv *)
				tlvs->srv6_lan_endx_sid.head;
		int i;

		for (; lendx; lendx = lendx->next) {
			if (lendx->flags & EXT_SUBTLV_LINK_SRV6_ENDX_SID_BFLG) {
				i = 1;
				SET_FLAG(attr->flags, LS_ATTR_BCK_ADJ_SRV6SID);
			} else {
				i = 0;
				SET_FLAG(attr->flags, LS_ATTR_ADJ_SRV6SID);
			}
			memcpy(&attr->adj_srv6_sid[i].neighbor.sysid,
			       &lendx->neighbor_id, ISIS_SYS_ID_LEN);
			attr->adj_srv6_sid[i].flags = lendx->flags;
			attr->adj_srv6_sid[i].weight = lendx->weight;
			memcpy(&attr->adj_srv6_sid[i].sid, &lendx->sid,
			       sizeof(struct in6_addr));
			attr->adj_srv6_sid[i].endpoint_behavior =
				lendx->behavior;
		}
	}
	return attr;
}

/**
 * Parse Extended Reachability TLVs and create or update the corresponding
 * Link State Edge and Attributes. Vertex connections are also updated if
 * needed based on the remote IP address of the Edge and existing reverse Edge.
 *
 * @param id		ID of Extended IS
 * @param metric	Metric of the link
 * @param old_metric	Boolean that indicate if it is an old metric (no TE)
 * @param tlvs		SubTlvs that contains TE information
 * @param arg		IS-IS TE argument (TED, Vertex, and export indication)
 *
 * @return		0 if success, -1 otherwise
 */
static int lsp_to_edge_cb(const uint8_t *id, uint32_t metric, bool old_metric,
			  struct isis_ext_subtlvs *tlvs, void *arg)
{
	struct isis_te_args *args = (struct isis_te_args *)arg;
	struct ls_vertex *vertex;
	struct ls_edge *edge, *dst;
	struct ls_attributes *attr;

	te_debug("  |- Process Extended IS for %pSY", id);

	/* Check parameters */
	if (old_metric || !args || !tlvs)
		return LSP_ITER_CONTINUE;

	/* Initialize Link State Attributes */
	vertex = args->vertex;
	attr = get_attributes(vertex->node->adv, tlvs);
	/*
	 * Attributes may be Null if no local ID has been found in the LSP.
	 * Stop processing here as without any local ID it is not possible to
	 * create corresponding Edge in the TED.
	 */
	if (!attr)
		return LSP_ITER_CONTINUE;

	attr->metric = metric;
	SET_FLAG(attr->flags, LS_ATTR_METRIC);

	/* Get corresponding Edge from Link State Data Base */
	edge = get_edge(args->ted, attr);
	/*
	 * Edge could be Null if no local ID has been found in Attributes.
	 * Stop processing here as without any local ID it is not possible to
	 * create corresponding Edge in the TED.
	 */
	if (!edge) {
		ls_attributes_del(attr);
		return LSP_ITER_CONTINUE;
	}

	/* Update Attribute fields if there are different */
	if (edge->status != NEW) {
		if (!ls_attributes_same(edge->attributes, attr)) {
			te_debug("    |- Update Edge Attributes information");
			ls_attributes_del(edge->attributes);
			edge->attributes = attr;
			edge->status = UPDATE;
		} else {
			if (edge->attributes != attr)
				ls_attributes_del(attr);
			edge->status = SYNC;
		}
	}

	/* Try to update remote Link from remote address or reachability ID */
	if (edge->key.family == AF_INET)
		te_debug("    |- Link Edge (%pI4) to destination vertex (%s)",
			 &edge->key.k.addr, print_sys_hostname(id));
	else if (edge->key.family == AF_INET6)
		te_debug("    |- Link Edge (%pI6) to destination vertex (%s)",
			 &edge->key.k.addr6, print_sys_hostname(id));
	else if (edge->key.family == AF_LOCAL)
		te_debug("    |- Link Edge (%" PRIu64
			 ") to destination vertex (%s)",
			 edge->key.k.link_id, print_sys_hostname(id));
	else
		te_debug(
			"    |- Link Edge (Unknown) to destination vertex (%s)",
			print_sys_hostname(id));

	dst = ls_find_edge_by_destination(args->ted, edge->attributes);
	if (dst) {
		/* Attach remote link if not set */
		if (edge->source && dst->destination == NULL) {
			vertex = edge->source;
			if (vertex->incoming_edges)
				listnode_add_sort_nodup(vertex->incoming_edges,
							dst);
			dst->destination = vertex;
		}
		/* and destination vertex to this edge if not set */
		if (dst->source && edge->destination == NULL) {
			vertex = dst->source;
			if (vertex->incoming_edges)
				listnode_add_sort_nodup(vertex->incoming_edges,
							edge);
			edge->destination = vertex;
		}
	} else {
		/* Search dst. Vertex by Extended Reach. ID if not found */
		if (edge->destination == NULL) {
			vertex = ls_find_vertex_by_key(args->ted,
						       sysid_to_key(id));
			if (vertex && vertex->incoming_edges)
				listnode_add_sort_nodup(vertex->incoming_edges,
							edge);
			edge->destination = vertex;
		}
	}

	/* Update status and Export Link State Edge if needed */
	if (edge->status != SYNC) {
		if (args->export)
			isis_te_export(LS_MSG_TYPE_ATTRIBUTES, edge);
		edge->status = SYNC;
	}

	return LSP_ITER_CONTINUE;
}

/**
 * Parse Extended IP Reachability or MT IPv6 Reachability TLVs and create or
 * update the corresponding Link State Subnet and Prefix.
 *
 * @param prefix	Prefix associated to this subnet
 * @param metric	Metric of this prefix
 * @param external	Boolean to indicate if the prefix is external
 * @param subtlvs	Subtlvs if any (mostly Segment Routing ID)
 * @param arg		IS-IS TE argument (TED, Vertex, and export indication)
 *
 * @return		0 if success, -1 otherwise
 */
static int lsp_to_subnet_cb(const struct prefix *prefix, uint32_t metric,
			    bool external, struct isis_subtlvs *subtlvs,
			    void *arg)
{
	struct isis_te_args *args = (struct isis_te_args *)arg;
	struct ls_vertex *vertex;
	struct ls_subnet *subnet;
	struct ls_prefix *ls_pref;
	struct listnode *node;
	struct ls_edge *edge;
	struct ls_standard *std = NULL;
	struct prefix p;

	/* Sanity Check */
	if (!args || !prefix)
		return LSP_ITER_CONTINUE;

	te_debug("  |- Process Extended %s Reachability %pFX",
		 prefix->family == AF_INET ? "IP" : "IPv6", prefix);

	vertex = args->vertex;

	/*
	 * Prefix with mask different from /32 or /128 are advertised by at
	 * least 2 nodes. To avoid subnet attached to undetermined vertex, and
	 * gives the possibility to send the information to client e.g. BGP for
	 * Link State advertisement, we adjust the prefix with the corresponding
	 * IP address of the belonging interface when it is available. Other
	 * prefixes are kept unchanged.
	 */
	if (prefix->family == AF_INET && prefix->prefixlen < IPV4_MAX_BITLEN) {
		std = NULL;
		for (ALL_LIST_ELEMENTS_RO(vertex->outgoing_edges, node, edge)) {
			if (!CHECK_FLAG(edge->attributes->flags,
					LS_ATTR_LOCAL_ADDR))
				continue;

			p.u.prefix4 = edge->attributes->standard.local;
			p.family = AF_INET;
			p.prefixlen = prefix->prefixlen;
			apply_mask_ipv4((struct prefix_ipv4 *)&p);
			if (IPV4_ADDR_SAME(&p.u.prefix4, &prefix->u.prefix4)) {
				std = &edge->attributes->standard;
				break;
			}
		}
		if (std)
			p.u.prefix4 = std->local;

	} else if (prefix->family == AF_INET6
		   && prefix->prefixlen < IPV6_MAX_BITLEN) {
		std = NULL;
		for (ALL_LIST_ELEMENTS_RO(vertex->outgoing_edges, node, edge)) {
			if (!CHECK_FLAG(edge->attributes->flags,
					LS_ATTR_LOCAL_ADDR6))
				continue;

			p.u.prefix6 = edge->attributes->standard.local6;
			p.family = AF_INET6;
			p.prefixlen = prefix->prefixlen;
			apply_mask_ipv6((struct prefix_ipv6 *)&p);
			if (IPV6_ADDR_SAME(&p.u.prefix6, &prefix->u.prefix6)) {
				std = &edge->attributes->standard;
				break;
			}
		}
		if (std)
			p.u.prefix6 = std->local6;
	}
	if (!std)
		prefix_copy(&p, prefix);
	else {
		/* Remove old subnet if any before prefix adjustment */
		subnet = ls_find_subnet(args->ted, prefix);
		if (subnet) {
			if (args->export) {
				subnet->status = DELETE;
				isis_te_export(LS_MSG_TYPE_PREFIX, subnet);
			}
			te_debug("   |- Remove subnet with prefix %pFX",
				 &subnet->key);
			ls_subnet_del_all(args->ted, subnet);
		}
		te_debug("   |- Adjust prefix %pFX with local address to: %pFX",
			 prefix, &p);
	}

	/* Search existing Subnet in TED ... */
	subnet = ls_find_subnet(args->ted, &p);
	/* ... and create a new Subnet if not found */
	if (!subnet) {
		ls_pref = ls_prefix_new(vertex->node->adv, &p);
		subnet = ls_subnet_add(args->ted, ls_pref);
		/* Stop processing if we are unable to create a new subnet */
		if (!subnet)
			return LSP_ITER_CONTINUE;
	}
	ls_pref = subnet->ls_pref;

	te_debug("   |- %s Subnet from prefix %pFX",
		 subnet->status == NEW ? "Create" : "Found", &p);

	/* Update Metric */
	if (!CHECK_FLAG(ls_pref->flags, LS_PREF_METRIC)
	    || (ls_pref->metric != metric)) {
		ls_pref->metric = metric;
		SET_FLAG(ls_pref->flags, LS_PREF_METRIC);
		if (subnet->status != NEW)
			subnet->status = UPDATE;
	} else {
		if (subnet->status == ORPHAN)
			subnet->status = SYNC;
	}

	/* Update Prefix SID if any */
	if (subtlvs && subtlvs->prefix_sids.count != 0) {
		struct isis_prefix_sid *psid;
		struct ls_sid sr = {};

		psid = (struct isis_prefix_sid *)subtlvs->prefix_sids.head;
		sr.algo = psid->algorithm;
		sr.sid_flag = psid->flags;
		sr.sid = psid->value;

		if (!CHECK_FLAG(ls_pref->flags, LS_PREF_SR)
		    || !memcmp(&ls_pref->sr, &sr, sizeof(struct ls_sid))) {
			memcpy(&ls_pref->sr, &sr, sizeof(struct ls_sid));
			SET_FLAG(ls_pref->flags, LS_PREF_SR);
			if (subnet->status != NEW)
				subnet->status = UPDATE;
		} else {
			if (subnet->status == ORPHAN)
				subnet->status = SYNC;
		}
	} else {
		if (CHECK_FLAG(ls_pref->flags, LS_PREF_SR)) {
			UNSET_FLAG(ls_pref->flags, LS_PREF_SR);
			if (subnet->status != NEW)
				subnet->status = UPDATE;
		} else {
			if (subnet->status == ORPHAN)
				subnet->status = SYNC;
		}
	}

	/* Update status and Export Link State Edge if needed */
	if (subnet->status != SYNC) {
		if (args->export)
			isis_te_export(LS_MSG_TYPE_PREFIX, subnet);
		subnet->status = SYNC;
	}

	return LSP_ITER_CONTINUE;
}

/**
 * Parse ISIS LSP to fulfill the Link State Database
 *
 * @param ted	Link State Database
 * @param lsp	ISIS Link State PDU
 */
static void isis_te_parse_lsp(struct mpls_te_area *mta, struct isis_lsp *lsp)
{
	struct ls_ted *ted;
	struct ls_vertex *vertex;
	struct ls_edge *edge;
	struct ls_subnet *subnet;
	struct listnode *node;
	struct isis_te_args args;

	/* Sanity Check */
	if (!IS_MPLS_TE(mta) || !mta->ted || !lsp)
		return;

	ted = mta->ted;

	te_debug("ISIS-TE(%s): Parse LSP %pSY", lsp->area->area_tag,
		 lsp->hdr.lsp_id);

	/* First parse LSP to obtain the corresponding Vertex */
	vertex = lsp_to_vertex(ted, lsp);
	if (!vertex) {
		zlog_warn("Unable to build Vertex from LSP %pSY. Abort!",
			  lsp->hdr.lsp_id);
		return;
	}

	/* Check if Vertex has been modified */
	if (vertex->status != SYNC) {
		/* Vertex is out of sync: export it if requested */
		if (IS_EXPORT_TE(mta))
			isis_te_export(LS_MSG_TYPE_NODE, vertex);
		vertex->status = SYNC;
	}

	/* Mark outgoing Edges and Subnets as ORPHAN to detect deletion */
	for (ALL_LIST_ELEMENTS_RO(vertex->outgoing_edges, node, edge))
		edge->status = ORPHAN;

	for (ALL_LIST_ELEMENTS_RO(vertex->prefixes, node, subnet))
		subnet->status = ORPHAN;

	/* Process all Extended Reachability in LSP (all fragments) */
	args.ted = ted;
	args.vertex = vertex;
	args.export = mta->export;
	isis_lsp_iterate_is_reach(lsp, ISIS_MT_IPV4_UNICAST, lsp_to_edge_cb,
				  &args);

	isis_lsp_iterate_is_reach(lsp, ISIS_MT_IPV6_UNICAST, lsp_to_edge_cb,
				  &args);

	/* Process all Extended IP (v4 & v6) in LSP (all fragments) */
	isis_lsp_iterate_ip_reach(lsp, AF_INET, ISIS_MT_IPV4_UNICAST,
				  lsp_to_subnet_cb, &args);
	isis_lsp_iterate_ip_reach(lsp, AF_INET6, ISIS_MT_IPV6_UNICAST,
				  lsp_to_subnet_cb, &args);
	isis_lsp_iterate_ip_reach(lsp, AF_INET6, ISIS_MT_IPV4_UNICAST,
				  lsp_to_subnet_cb, &args);

	/* Clean remaining Orphan Edges or Subnets */
	if (IS_EXPORT_TE(mta))
		ls_vertex_clean(ted, vertex, zclient);
	else
		ls_vertex_clean(ted, vertex, NULL);
}

/**
 * Delete Link State Database Vertex, Edge & Prefix that correspond to this
 * ISIS Link State PDU
 *
 * @param ted	Link State Database
 * @param lsp	ISIS Link State PDU
 */
static void isis_te_delete_lsp(struct mpls_te_area *mta, struct isis_lsp *lsp)
{
	struct ls_ted *ted;
	struct ls_vertex *vertex = NULL;
	struct ls_node lnode = {};
	struct ls_edge *edge;
	struct ls_subnet *subnet;
	struct listnode *nnode, *node;

	/* Sanity Check */
	if (!IS_MPLS_TE(mta) || !mta->ted || !lsp)
		return;

	te_debug("ISIS-TE(%s): Delete Link State TED objects from LSP %pSY",
		 lsp->area->area_tag, lsp->hdr.lsp_id);

	/* Compute Link State Node ID from IS-IS sysID ... */
	if (lsp->level == ISIS_LEVEL1)
		lnode.adv.origin = ISIS_L1;
	else
		lnode.adv.origin = ISIS_L2;
	memcpy(&lnode.adv.id.iso.sys_id, &lsp->hdr.lsp_id, ISIS_SYS_ID_LEN);
	lnode.adv.id.iso.level = lsp->level;
	ted = mta->ted;
	/* ... and search the corresponding vertex */
	vertex = ls_find_vertex_by_id(ted, lnode.adv);
	if (!vertex)
		return;

	te_debug("  |- Delete Vertex %s", vertex->node->name);

	/*
	 * We can't use the ls_vertex_del_all() function if export TE is set,
	 * as we must first advertise the client daemons of each removal.
	 */
	/* Remove outgoing Edges */
	for (ALL_LIST_ELEMENTS(vertex->outgoing_edges, node, nnode, edge)) {
		if (IS_EXPORT_TE(mta)) {
			edge->status = DELETE;
			isis_te_export(LS_MSG_TYPE_ATTRIBUTES, edge);
		}
		ls_edge_del_all(ted, edge);
	}

	/* Disconnect incoming Edges */
	for (ALL_LIST_ELEMENTS(vertex->incoming_edges, node, nnode, edge)) {
		ls_disconnect(vertex, edge, false);
		if (edge->source == NULL) {
			if (IS_EXPORT_TE(mta)) {
				edge->status = DELETE;
				isis_te_export(LS_MSG_TYPE_ATTRIBUTES, edge);
			}
			ls_edge_del_all(ted, edge);
		}
	}

	/* Remove subnets */
	for (ALL_LIST_ELEMENTS(vertex->prefixes, node, nnode, subnet)) {
		if (IS_EXPORT_TE(mta)) {
			subnet->status = DELETE;
			isis_te_export(LS_MSG_TYPE_PREFIX, subnet);
		}
		ls_subnet_del_all(ted, subnet);
	}

	/* Then remove Link State Node */
	if (IS_EXPORT_TE(mta)) {
		vertex->status = DELETE;
		isis_te_export(LS_MSG_TYPE_NODE, vertex);
	}
	ls_node_del(vertex->node);

	/* Finally, remove Vertex */
	ls_vertex_del(ted, vertex);
}

/**
 * Process ISIS LSP according to the event to add, update or remove
 * corresponding vertex, edge and prefix in the Link State database.
 * Since LSP could be fragmented, the function starts by searching the root LSP
 * to retrieve the complete LSP, including eventual fragment before processing
 * all of them.
 *
 * @param lsp		ISIS Link State PDU
 * @param event		LSP event: ADD, UPD, INC & DEL (TICK are ignored)
 *
 */
void isis_te_lsp_event(struct isis_lsp *lsp, enum lsp_event event)
{
	struct isis_area *area;
	struct isis_lsp *lsp0;

	/* Sanity check */
	if (!lsp || !lsp->area)
		return;

	area = lsp->area;
	if (!IS_MPLS_TE(area->mta))
		return;

	/* Adjust LSP0 in case of fragment */
	if (LSP_FRAGMENT(lsp->hdr.lsp_id))
		lsp0 = lsp->lspu.zero_lsp;
	else
		lsp0 = lsp;

	/* Then process event */
	switch (event) {
	case LSP_ADD:
	case LSP_UPD:
	case LSP_INC:
		isis_te_parse_lsp(area->mta, lsp0);
		break;
	case LSP_DEL:
		isis_te_delete_lsp(area->mta, lsp0);
		break;
	case LSP_UNKNOWN:
	case LSP_TICK:
		break;
	}
}

/**
 * Send the whole Link State Traffic Engineering Database to the consumer that
 * request it through a ZAPI Link State Synchronous Opaque Message.
 *
 * @param info	ZAPI Opaque message
 *
 * @return	0 if success, -1 otherwise
 */
int isis_te_sync_ted(struct zapi_opaque_reg_info dst)
{
	struct listnode *node, *inode;
	struct isis *isis;
	struct isis_area *area;
	struct mpls_te_area *mta;
	int rc = -1;

	te_debug("ISIS-TE(%s): Received TED synchro from client %d", __func__,
		 dst.proto);
	/*  For each area, send TED if TE distribution is enabled */
	for (ALL_LIST_ELEMENTS_RO(im->isis, inode, isis)) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
			mta = area->mta;
			if (IS_MPLS_TE(mta) && IS_EXPORT_TE(mta)) {
				te_debug("  |- Export TED from area %s",
					 area->area_tag);
				rc = ls_sync_ted(mta->ted, zclient, &dst);
				if (rc != 0)
					return rc;
			}
		}
	}

	return rc;
}

/**
 * Initialize the Link State database from the LSP already stored for this area
 *
 * @param area	ISIS area
 */
void isis_te_init_ted(struct isis_area *area)
{
	struct isis_lsp *lsp;

	/* Iterate over all lsp. */
	for (int level = ISIS_LEVEL1; level <= ISIS_LEVELS; level++)
		frr_each (lspdb, &area->lspdb[level - 1], lsp)
			isis_te_parse_lsp(area->mta, lsp);
}

/* Following are vty command functions */
#ifndef FABRICD

static void show_router_id(struct vty *vty, struct isis_area *area)
{
	bool no_match = true;

	vty_out(vty, "Area %s:\n", area->area_tag);
	if (area->mta->router_id.s_addr != 0) {
		vty_out(vty, "  MPLS-TE IPv4 Router-Address: %pI4\n",
			&area->mta->router_id);
		no_match = false;
	}
	if (!IN6_IS_ADDR_UNSPECIFIED(&area->mta->router_id_ipv6)) {
		vty_out(vty, "  MPLS-TE IPv6 Router-Address: %pI6\n",
			&area->mta->router_id_ipv6);
		no_match = false;
	}
	if (no_match)
		vty_out(vty, "  N/A\n");
}

DEFUN(show_isis_mpls_te_router,
      show_isis_mpls_te_router_cmd,
      "show " PROTO_NAME " [vrf <NAME|all>] mpls-te router",
      SHOW_STR
      PROTO_HELP
      VRF_CMD_HELP_STR "All VRFs\n"
      MPLS_TE_STR "Router information\n")
{

	struct listnode *anode, *inode;
	struct isis_area *area;
	struct isis *isis = NULL;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	int idx_vrf = 0;

	if (!im) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}
	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (all_vrf) {
		for (ALL_LIST_ELEMENTS_RO(im->isis, inode, isis)) {
			for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
				if (!IS_MPLS_TE(area->mta))
					continue;

				show_router_id(vty, area);
			}
		}
		return 0;
	}
	isis = isis_lookup_by_vrfname(vrf_name);
	if (isis != NULL) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {
			if (!IS_MPLS_TE(area->mta))
				continue;

			show_router_id(vty, area);
		}
	}

	return CMD_SUCCESS;
}

static void show_ext_sub(struct vty *vty, char *name,
			 struct isis_ext_subtlvs *ext)
{
	struct sbuf buf;
	char ibuf[PREFIX2STR_BUFFER];

	sbuf_init(&buf, NULL, 0);

	if (!ext || ext->status == EXT_DISABLE)
		return;

	vty_out(vty, "-- MPLS-TE link parameters for %s --\n", name);

	sbuf_reset(&buf);

	if (IS_SUBTLV(ext, EXT_ADM_GRP))
		sbuf_push(&buf, 4, "Administrative Group: 0x%x\n",
			ext->adm_group);
	if (IS_SUBTLV(ext, EXT_LLRI)) {
		sbuf_push(&buf, 4, "Link Local  ID: %u\n",
			  ext->local_llri);
		sbuf_push(&buf, 4, "Link Remote ID: %u\n",
			  ext->remote_llri);
	}
	if (IS_SUBTLV(ext, EXT_LOCAL_ADDR))
		sbuf_push(&buf, 4, "Local Interface IP Address(es): %pI4\n",
			  &ext->local_addr);
	if (IS_SUBTLV(ext, EXT_NEIGH_ADDR))
		sbuf_push(&buf, 4, "Remote Interface IP Address(es): %pI4\n",
			  &ext->neigh_addr);
	if (IS_SUBTLV(ext, EXT_LOCAL_ADDR6))
		sbuf_push(&buf, 4, "Local Interface IPv6 Address(es): %s\n",
			  inet_ntop(AF_INET6, &ext->local_addr6, ibuf,
				    PREFIX2STR_BUFFER));
	if (IS_SUBTLV(ext, EXT_NEIGH_ADDR6))
		sbuf_push(&buf, 4, "Remote Interface IPv6 Address(es): %s\n",
			  inet_ntop(AF_INET6, &ext->local_addr6, ibuf,
				    PREFIX2STR_BUFFER));
	if (IS_SUBTLV(ext, EXT_MAX_BW))
		sbuf_push(&buf, 4, "Maximum Bandwidth: %g (Bytes/sec)\n",
			  ext->max_bw);
	if (IS_SUBTLV(ext, EXT_MAX_RSV_BW))
		sbuf_push(&buf, 4,
			  "Maximum Reservable Bandwidth: %g (Bytes/sec)\n",
			  ext->max_rsv_bw);
	if (IS_SUBTLV(ext, EXT_UNRSV_BW)) {
		sbuf_push(&buf, 4, "Unreserved Bandwidth:\n");
		for (int j = 0; j < MAX_CLASS_TYPE; j += 2) {
			sbuf_push(&buf, 4 + 2,
				  "[%d]: %g (Bytes/sec),\t[%d]: %g (Bytes/sec)\n",
				  j, ext->unrsv_bw[j],
				  j + 1, ext->unrsv_bw[j + 1]);
		}
	}
	if (IS_SUBTLV(ext, EXT_TE_METRIC))
		sbuf_push(&buf, 4, "Traffic Engineering Metric: %u\n",
			  ext->te_metric);
	if (IS_SUBTLV(ext, EXT_RMT_AS))
		sbuf_push(&buf, 4,
			  "Inter-AS TE Remote AS number: %u\n",
			  ext->remote_as);
	if (IS_SUBTLV(ext, EXT_RMT_IP))
		sbuf_push(&buf, 4,
			  "Inter-AS TE Remote ASBR IP address: %pI4\n",
			  &ext->remote_ip);
	if (IS_SUBTLV(ext, EXT_DELAY))
		sbuf_push(&buf, 4,
			  "%s Average Link Delay: %u (micro-sec)\n",
			  IS_ANORMAL(ext->delay) ? "Anomalous" : "Normal",
			  ext->delay & TE_EXT_MASK);
	if (IS_SUBTLV(ext, EXT_MM_DELAY)) {
		sbuf_push(&buf, 4, "%s Min/Max Link Delay: %u / %u (micro-sec)\n",
			  IS_ANORMAL(ext->min_delay) ? "Anomalous" : "Normal",
			  ext->min_delay & TE_EXT_MASK,
			  ext->max_delay & TE_EXT_MASK);
	}
	if (IS_SUBTLV(ext, EXT_DELAY_VAR))
		sbuf_push(&buf, 4,
			  "Delay Variation: %u (micro-sec)\n",
			  ext->delay_var & TE_EXT_MASK);
	if (IS_SUBTLV(ext, EXT_PKT_LOSS))
		sbuf_push(&buf, 4, "%s Link Packet Loss: %g (%%)\n",
			  IS_ANORMAL(ext->pkt_loss) ? "Anomalous" : "Normal",
			  (float)((ext->pkt_loss & TE_EXT_MASK)
				  * LOSS_PRECISION));
	if (IS_SUBTLV(ext, EXT_RES_BW))
		sbuf_push(&buf, 4,
			  "Unidirectional Residual Bandwidth: %g (Bytes/sec)\n",
			  ext->res_bw);
	if (IS_SUBTLV(ext, EXT_AVA_BW))
		sbuf_push(&buf, 4,
			  "Unidirectional Available Bandwidth: %g (Bytes/sec)\n",
			  ext->ava_bw);
	if (IS_SUBTLV(ext, EXT_USE_BW))
		sbuf_push(&buf, 4,
			  "Unidirectional Utilized Bandwidth: %g (Bytes/sec)\n",
			  ext->use_bw);

	vty_multiline(vty, "", "%s", sbuf_buf(&buf));
	vty_out(vty, "---------------\n\n");

	sbuf_free(&buf);
	return;
}

DEFUN (show_isis_mpls_te_interface,
       show_isis_mpls_te_interface_cmd,
       "show " PROTO_NAME " mpls-te interface [INTERFACE]",
       SHOW_STR
       PROTO_HELP
       MPLS_TE_STR
       "Interface information\n"
       "Interface name\n")
{
	struct listnode *anode, *cnode, *inode;
	struct isis_area *area;
	struct isis_circuit *circuit;
	struct interface *ifp;
	int idx_interface = 4;
	struct isis *isis = NULL;

	if (!im) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (argc == idx_interface) {
		/* Show All Interfaces. */
		for (ALL_LIST_ELEMENTS_RO(im->isis, inode, isis)) {
			for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode,
						  area)) {

				if (!IS_MPLS_TE(area->mta))
					continue;

				vty_out(vty, "Area %s:\n", area->area_tag);

				for (ALL_LIST_ELEMENTS_RO(area->circuit_list,
							  cnode, circuit))
					show_ext_sub(vty,
						     circuit->interface->name,
						     circuit->ext);
			}
		}
	} else {
		/* Interface name is specified. */
		ifp = if_lookup_by_name(argv[idx_interface]->arg, VRF_DEFAULT);
		if (ifp == NULL)
			vty_out(vty, "No such interface name\n");
		else {
			circuit = circuit_scan_by_ifp(ifp);
			if (!circuit)
				vty_out(vty,
					"ISIS is not enabled on circuit %s\n",
					ifp->name);
			else
				show_ext_sub(vty, ifp->name, circuit->ext);
		}
	}

	return CMD_SUCCESS;
}

/**
 * Search Vertex in TED that corresponds to the given string that represent
 * the ISO system ID in the forms <systemid/hostname>[.<pseudo-id>-<framenent>]
 *
 * @param ted	Link State Database
 * @param id	ISO System ID
 * @param isis	Main reference to the isis daemon
 *
 * @return	Vertex if found, NULL otherwise
 */
static struct ls_vertex *vertex_for_arg(struct ls_ted *ted, const char *id,
					struct isis *isis)
{
	char sysid[255] = {0};
	uint8_t number[3];
	const char *pos;
	uint8_t lspid[ISIS_SYS_ID_LEN + 2] = {0};
	struct isis_dynhn *dynhn;
	uint64_t key = 0;

	if (!id)
		return NULL;

	/*
	 * extract fragment and pseudo id from the string argv
	 * in the forms:
	 * (a) <systemid/hostname>.<pseudo-id>-<framenent> or
	 * (b) <systemid/hostname>.<pseudo-id> or
	 * (c) <systemid/hostname> or
	 * Where systemid is in the form:
	 * xxxx.xxxx.xxxx
	 */
	strlcpy(sysid, id, sizeof(sysid));
	if (strlen(id) > 3) {
		pos = id + strlen(id) - 3;
		if (strncmp(pos, "-", 1) == 0) {
			memcpy(number, ++pos, 2);
			lspid[ISIS_SYS_ID_LEN + 1] =
				(uint8_t)strtol((char *)number, NULL, 16);
			pos -= 4;
			if (strncmp(pos, ".", 1) != 0)
				return NULL;
		}
		if (strncmp(pos, ".", 1) == 0) {
			memcpy(number, ++pos, 2);
			lspid[ISIS_SYS_ID_LEN] =
				(uint8_t)strtol((char *)number, NULL, 16);
			sysid[pos - id - 1] = '\0';
		}
	}

	/*
	 * Try to find the lsp-id if the argv
	 * string is in
	 * the form
	 * hostname.<pseudo-id>-<fragment>
	 */
	if (sysid2buff(lspid, sysid)) {
		key = sysid_to_key(lspid);
	} else if ((dynhn = dynhn_find_by_name(isis, sysid))) {
		memcpy(lspid, dynhn->id, ISIS_SYS_ID_LEN);
		key = sysid_to_key(lspid);
	} else if (strncmp(cmd_hostname_get(), sysid, 15) == 0) {
		memcpy(lspid, isis->sysid, ISIS_SYS_ID_LEN);
		key = sysid_to_key(lspid);
	}

	if (key == 0)
		return NULL;

	return ls_find_vertex_by_key(ted, key);
}

/**
 * Show Link State Traffic Engineering Database extracted from IS-IS LSP.
 *
 * @param vty	VTY output console
 * @param argv	Command line argument
 * @param argc	Number of command line argument
 * @param ted	Traffic Engineering Database
 * @param isis	isis Main reference to the isis daemon
 *
 * @return	Command Success if OK, Command Warning otherwise
 */
static int show_ted(struct vty *vty, struct cmd_token *argv[], int argc,
		    struct isis_area *area, struct isis *isis)
{
	int idx;
	char *id;
	struct in_addr ip_addr;
	struct in6_addr ip6_addr;
	struct prefix pref;
	struct ls_ted *ted;
	struct ls_vertex *vertex;
	struct ls_edge *edge;
	struct ls_subnet *subnet;
	struct ls_edge_key key;
	bool detail = false;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	if (!IS_MPLS_TE(area->mta) || !area->mta->ted) {
		vty_out(vty, "MPLS-TE is disabled for Area %s\n",
			area->area_tag ? area->area_tag : "null");
		return CMD_SUCCESS;
	}

	ted = area->mta->ted;

	if (uj)
		json = json_object_new_object();
	else
		vty_out(vty, "Area %s:\n",
			area->area_tag ? area->area_tag : "null");

	if (argv[argc - 1]->arg && strmatch(argv[argc - 1]->text, "detail"))
		detail = true;

	idx = 4;
	if (argv_find(argv, argc, "vertex", &idx)) {
		/* Show Vertex */
		id = argv_find(argv, argc, "WORD", &idx) ? argv[idx]->arg
							 : NULL;
		if (!id)
			vertex = NULL;
		else if (!strncmp(id, "self", 4))
			vertex = ted->self;
		else {
			vertex = vertex_for_arg(ted, id, isis);
			if (!vertex) {
				vty_out(vty, "No vertex found for ID %s\n", id);
				return CMD_WARNING;
			}
		}

		if (vertex)
			ls_show_vertex(vertex, vty, json, detail);
		else
			ls_show_vertices(ted, vty, json, detail);

	} else if (argv_find(argv, argc, "edge", &idx)) {
		/* Show Edge */
		if (argv_find(argv, argc, "A.B.C.D", &idx)) {
			if (!inet_pton(AF_INET, argv[idx]->arg, &ip_addr)) {
				vty_out(vty,
					"Specified Edge ID %s is invalid\n",
					argv[idx]->arg);
				return CMD_WARNING_CONFIG_FAILED;
			}
			/* Get the Edge from the Link State Database */
			key.family = AF_INET;
			IPV4_ADDR_COPY(&key.k.addr, &ip_addr);
			edge = ls_find_edge_by_key(ted, key);
			if (!edge) {
				vty_out(vty, "No edge found for ID %pI4\n",
					&ip_addr);
				return CMD_WARNING;
			}
		} else if (argv_find(argv, argc, "X:X::X:X", &idx)) {
			if (!inet_pton(AF_INET6, argv[idx]->arg, &ip6_addr)) {
				vty_out(vty,
					"Specified Edge ID %s is invalid\n",
					argv[idx]->arg);
				return CMD_WARNING_CONFIG_FAILED;
			}
			/* Get the Edge from the Link State Database */
			key.family = AF_INET6;
			IPV6_ADDR_COPY(&key.k.addr6, &ip6_addr);
			edge = ls_find_edge_by_key(ted, key);
			if (!edge) {
				vty_out(vty, "No edge found for ID %pI6\n",
					&ip6_addr);
				return CMD_WARNING;
			}
		} else
			edge = NULL;

		if (edge)
			ls_show_edge(edge, vty, json, detail);
		else
			ls_show_edges(ted, vty, json, detail);

	} else if (argv_find(argv, argc, "subnet", &idx)) {
		/* Show Subnet */
		if (argv_find(argv, argc, "A.B.C.D/M", &idx)) {
			if (!str2prefix(argv[idx]->arg, &pref)) {
				vty_out(vty, "Invalid prefix format %s\n",
					argv[idx]->arg);
				return CMD_WARNING_CONFIG_FAILED;
			}
			/* Get the Subnet from the Link State Database */
			subnet = ls_find_subnet(ted, &pref);
			if (!subnet) {
				vty_out(vty, "No subnet found for ID %pFX\n",
					&pref);
				return CMD_WARNING;
			}
		} else if (argv_find(argv, argc, "X:X::X:X/M", &idx)) {
			if (!str2prefix(argv[idx]->arg, &pref)) {
				vty_out(vty, "Invalid prefix format %s\n",
					argv[idx]->arg);
				return CMD_WARNING_CONFIG_FAILED;
			}
			/* Get the Subnet from the Link State Database */
			subnet = ls_find_subnet(ted, &pref);
			if (!subnet) {
				vty_out(vty, "No subnet found for ID %pFX\n",
					&pref);
				return CMD_WARNING;
			}
		} else
			subnet = NULL;

		if (subnet)
			ls_show_subnet(subnet, vty, json, detail);
		else
			ls_show_subnets(ted, vty, json, detail);

	} else {
		/* Show the complete TED */
		ls_show_ted(ted, vty, json, detail);
	}

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/**
 * Show ISIS Traffic Engineering Database
 *
 * @param vty	VTY output console
 * @param argv	Command line argument
 * @param argc	Number of command line argument
 * @param isis	isis Main reference to the isis daemon

 * @return	Command Success if OK, Command Warning otherwise
 */
static int show_isis_ted(struct vty *vty, struct cmd_token *argv[], int argc,
			 struct isis *isis)
{
	struct listnode *node;
	struct isis_area *area;
	int rc;

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area)) {
		rc = show_ted(vty, argv, argc, area, isis);
		if (rc != CMD_SUCCESS)
			return rc;
	}
	return CMD_SUCCESS;
}

DEFUN(show_isis_mpls_te_db,
      show_isis_mpls_te_db_cmd,
      "show " PROTO_NAME " [vrf <NAME|all>] mpls-te database [<vertex [WORD]|edge [A.B.C.D|X:X::X:X]|subnet [A.B.C.D/M|X:X::X:X/M]>] [detail|json]",
      SHOW_STR PROTO_HELP VRF_CMD_HELP_STR
      "All VRFs\n"
      MPLS_TE_STR
      "MPLS-TE database\n"
      "MPLS-TE Vertex\n"
      "MPLS-TE Vertex ID (as an ISO ID, hostname or \"self\")\n"
      "MPLS-TE Edge\n"
      "MPLS-TE Edge ID (as an IPv4 address)\n"
      "MPLS-TE Edge ID (as an IPv6 address)\n"
      "MPLS-TE Subnet\n"
      "MPLS-TE Subnet ID (as an IPv4 prefix)\n"
      "MPLS-TE Subnet ID (as an IPv6 prefix)\n"
      "Detailed information\n"
      JSON_STR)
{
	int idx_vrf = 0;
	const char *vrf_name = VRF_DEFAULT_NAME;
	bool all_vrf = false;
	struct listnode *node;
	struct isis *isis;
	int rc = CMD_WARNING;

	ISIS_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (all_vrf) {
		for (ALL_LIST_ELEMENTS_RO(im->isis, node, isis)) {
			rc = show_isis_ted(vty, argv, argc, isis);
			if (rc != CMD_SUCCESS)
				return rc;
		}
		return CMD_SUCCESS;
	}
	isis = isis_lookup_by_vrfname(vrf_name);
	if (isis)
		rc = show_isis_ted(vty, argv, argc, isis);

	return rc;
}

#endif /* #ifndef FRABRICD */

/* Initialize MPLS_TE */
void isis_mpls_te_init(void)
{

	/* Register Circuit and Adjacency hook */
	hook_register(isis_if_new_hook, isis_mpls_te_update);
	hook_register(isis_adj_ip_enabled_hook, isis_mpls_te_adj_ip_enabled);
	hook_register(isis_adj_ip_disabled_hook, isis_mpls_te_adj_ip_disabled);

#ifndef FABRICD
	/* Register new VTY commands */
	install_element(VIEW_NODE, &show_isis_mpls_te_router_cmd);
	install_element(VIEW_NODE, &show_isis_mpls_te_interface_cmd);
	install_element(VIEW_NODE, &show_isis_mpls_te_db_cmd);
#endif

	return;
}
