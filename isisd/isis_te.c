/*
 * IS-IS Rout(e)ing protocol - isis_te.c
 *
 * This is an implementation of RFC5305 & RFC 7810
 *
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 *
 * Copyright (C) 2014 - 2019 Orange Labs http://www.orange.com
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include <math.h>

#include "linklist.h"
#include "thread.h"
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
#include "isisd/isis_te.h"
#include "isisd/isis_zebra.h"

const char *mode2text[] = {"Disable", "Area", "AS", "Emulate"};

/*------------------------------------------------------------------------*
 * Followings are control functions for MPLS-TE parameters management.
 *------------------------------------------------------------------------*/

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
	if ((ifp == NULL) || (circuit->state != C_STATE_UP))
		return;

	zlog_debug("TE(%s): Update circuit parameters for interface %s",
		   circuit->area->area_tag, ifp->name);

	/* Check if MPLS TE Circuit context has not been already created */
	if (circuit->ext == NULL) {
		circuit->ext = isis_alloc_ext_subtlvs();
		zlog_debug("  |- Allocated new Ext-subTLVs for interface %s",
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

		/* If known, register local IPv4 addr from ip_addr list */
		if (circuit->ip_addrs != NULL
		    && listcount(circuit->ip_addrs) != 0) {
			addr = (struct prefix_ipv4 *)listgetdata(
				(struct listnode *)listhead(circuit->ip_addrs));
			IPV4_ADDR_COPY(&ext->local_addr, &addr->prefix);
			SET_SUBTLV(ext, EXT_LOCAL_ADDR);
		} else
			UNSET_SUBTLV(ext, EXT_LOCAL_ADDR);

		/* Same for Remote IPv4 address */
		if (circuit->circ_type == CIRCUIT_T_P2P) {
			struct isis_adjacency *adj = circuit->u.p2p.neighbor;

			if (adj && adj->adj_state == ISIS_ADJ_UP
			    && adj->ipv4_address_count) {
				IPV4_ADDR_COPY(&ext->neigh_addr,
					       &adj->ipv4_addresses[0]);
				SET_SUBTLV(ext, EXT_NEIGH_ADDR);
			}
		} else
			UNSET_SUBTLV(ext, EXT_NEIGH_ADDR);

		/* If known, register local IPv6 addr from ip_addr list */
		if (circuit->ipv6_non_link != NULL
		    && listcount(circuit->ipv6_non_link) != 0) {
			addr6 = (struct prefix_ipv6 *)listgetdata(
				(struct listnode *)listhead(
					circuit->ipv6_non_link));
			IPV6_ADDR_COPY(&ext->local_addr6, &addr6->prefix);
			SET_SUBTLV(ext, EXT_LOCAL_ADDR6);
		} else
			UNSET_SUBTLV(ext, EXT_LOCAL_ADDR6);

		/* Same for Remote IPv6 address */
		if (circuit->circ_type == CIRCUIT_T_P2P) {
			struct isis_adjacency *adj = circuit->u.p2p.neighbor;

			if (adj && adj->adj_state == ISIS_ADJ_UP
			    && adj->ipv6_address_count) {
				IPV6_ADDR_COPY(&ext->neigh_addr6,
					       &adj->ipv6_addresses[0]);
				SET_SUBTLV(ext, EXT_NEIGH_ADDR6);
			}
		} else
			UNSET_SUBTLV(ext, EXT_NEIGH_ADDR6);

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
		zlog_debug("  |- New MPLS-TE link parameters status 0x%x",
			   ext->status);
	} else {
		zlog_debug("  |- Reset Extended subTLVs status 0x%x",
			   ext->status);
		/* Reset TE subTLVs keeping SR one's */
		if (IS_SUBTLV(ext, EXT_ADJ_SID))
			ext->status = EXT_ADJ_SID;
		else if (IS_SUBTLV(ext, EXT_LAN_ADJ_SID))
			ext->status = EXT_LAN_ADJ_SID;
		else
			ext->status = 0;
	}

	return;
}

static int isis_link_update_adj_hook(struct isis_adjacency *adj)
{

	struct isis_circuit *circuit = adj->circuit;

	/* Update MPLS TE Remote IP address parameter if possible */
	if (!IS_MPLS_TE(circuit->area->mta) || !IS_EXT_TE(circuit->ext))
		return 0;

	/* IPv4 first */
	if (adj->ipv4_address_count > 0) {
		IPV4_ADDR_COPY(&circuit->ext->neigh_addr,
			       &adj->ipv4_addresses[0]);
		SET_SUBTLV(circuit->ext, EXT_NEIGH_ADDR);
	}

	/* and IPv6 */
	if (adj->ipv6_address_count > 0) {
		IPV6_ADDR_COPY(&circuit->ext->neigh_addr6,
			       &adj->ipv6_addresses[0]);
		SET_SUBTLV(circuit->ext, EXT_NEIGH_ADDR6);
	}

	return 0;
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
	if (circuit->area && IS_MPLS_TE(circuit->area->mta))
		lsp_regenerate_schedule(circuit->area, circuit->is_type, 0);

	rc = 0;
	return rc;
}

/* Followings are vty command functions */
#ifndef FABRICD

DEFUN (show_isis_mpls_te_router,
       show_isis_mpls_te_router_cmd,
       "show " PROTO_NAME " mpls-te router",
       SHOW_STR
       PROTO_HELP
       MPLS_TE_STR
       "Router information\n")
{

	struct listnode *anode;
	struct isis_area *area;

	if (!isis) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {

		if (!IS_MPLS_TE(area->mta))
			continue;

		vty_out(vty, "Area %s:\n", area->area_tag);
		if (ntohs(area->mta->router_id.s_addr) != 0)
			vty_out(vty, "  MPLS-TE Router-Address: %s\n",
				inet_ntoa(area->mta->router_id));
		else
			vty_out(vty, "  N/A\n");
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
		sbuf_push(&buf, 4, "Administrative Group: 0x%" PRIx32 "\n",
			ext->adm_group);
	if (IS_SUBTLV(ext, EXT_LLRI)) {
		sbuf_push(&buf, 4, "Link Local  ID: %" PRIu32 "\n",
			  ext->local_llri);
		sbuf_push(&buf, 4, "Link Remote ID: %" PRIu32 "\n",
			  ext->remote_llri);
	}
	if (IS_SUBTLV(ext, EXT_LOCAL_ADDR))
		sbuf_push(&buf, 4, "Local Interface IP Address(es): %s\n",
			  inet_ntoa(ext->local_addr));
	if (IS_SUBTLV(ext, EXT_NEIGH_ADDR))
		sbuf_push(&buf, 4, "Remote Interface IP Address(es): %s\n",
			  inet_ntoa(ext->neigh_addr));
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
			  "Inter-AS TE Remote AS number: %" PRIu32 "\n",
			  ext->remote_as);
	if (IS_SUBTLV(ext, EXT_RMT_IP))
		sbuf_push(&buf, 4,
			  "Inter-AS TE Remote ASBR IP address: %s\n",
			  inet_ntoa(ext->remote_ip));
	if (IS_SUBTLV(ext, EXT_DELAY))
		sbuf_push(&buf, 4,
			  "%s Average Link Delay: %" PRIu32 " (micro-sec)\n",
			  IS_ANORMAL(ext->delay) ? "Anomalous" : "Normal",
			  ext->delay);
	if (IS_SUBTLV(ext, EXT_MM_DELAY)) {
		sbuf_push(&buf, 4, "%s Min/Max Link Delay: %" PRIu32 " / %"
			  PRIu32 " (micro-sec)\n",
			  IS_ANORMAL(ext->min_delay) ? "Anomalous" : "Normal",
			  ext->min_delay & TE_EXT_MASK,
			  ext->max_delay & TE_EXT_MASK);
	}
	if (IS_SUBTLV(ext, EXT_DELAY_VAR))
		sbuf_push(&buf, 4,
			  "Delay Variation: %" PRIu32 " (micro-sec)\n",
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
	struct listnode *anode, *cnode;
	struct isis_area *area;
	struct isis_circuit *circuit;
	struct interface *ifp;
	int idx_interface = 4;

	if (!isis) {
		vty_out(vty, "IS-IS Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (argc == idx_interface) {
		/* Show All Interfaces. */
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, anode, area)) {

			if (!IS_MPLS_TE(area->mta))
				continue;

			vty_out(vty, "Area %s:\n", area->area_tag);

			for (ALL_LIST_ELEMENTS_RO(area->circuit_list, cnode,
						  circuit))
				show_ext_sub(vty, circuit->interface->name,
					     circuit->ext);
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
#endif

/* Initialize MPLS_TE */
void isis_mpls_te_init(void)
{

	/* Register Circuit and Adjacency hook */
	hook_register(isis_if_new_hook, isis_mpls_te_update);
	hook_register(isis_adj_state_change_hook, isis_link_update_adj_hook);


#ifndef FABRICD
	/* Register new VTY commands */
	install_element(VIEW_NODE, &show_isis_mpls_te_router_cmd);
	install_element(VIEW_NODE, &show_isis_mpls_te_interface_cmd);
#endif

	return;
}
