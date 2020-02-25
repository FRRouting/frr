/**
 * ospf_bfd.c: OSPF BFD handling routines
 *
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
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

#include "command.h"
#include "linklist.h"
#include "memory.h"
#include "prefix.h"
#include "thread.h"
#include "buffer.h"
#include "stream.h"
#include "zclient.h"
#include "vty.h"
#include "table.h"
#include "bfd.h"
#include "ospfd.h"
#include "ospf_asbr.h"
#include "ospf_lsa.h"
#include "ospf_lsdb.h"
#include "ospf_neighbor.h"
#include "ospf_interface.h"
#include "ospf_nsm.h"
#include "ospf_bfd.h"
#include "ospf_dump.h"
#include "ospf_vty.h"

extern struct zclient *zclient;

/*
 * ospf_bfd_info_free - Free BFD info structure
 */
void ospf_bfd_info_free(void **bfd_info)
{
	bfd_info_free((struct bfd_info **)bfd_info);
}

/*
 * ospf_bfd_reg_dereg_nbr - Register/Deregister a neighbor with BFD through
 *                          zebra for starting/stopping the monitoring of
 *                          the neighbor rechahability.
 */
static void ospf_bfd_reg_dereg_nbr(struct ospf_neighbor *nbr, int command)
{
	struct ospf_interface *oi = nbr->oi;
	struct interface *ifp = oi->ifp;
	struct ospf_if_params *params;
	struct bfd_info *bfd_info;
	int cbit;

	/* Check if BFD is enabled */
	params = IF_DEF_PARAMS(ifp);

	/* Check if BFD is enabled */
	if (!params->bfd_info)
		return;
	bfd_info = (struct bfd_info *)params->bfd_info;

	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
		zlog_debug("%s nbr (%s) with BFD. OSPF vrf %s",
			   bfd_get_command_dbg_str(command),
			   inet_ntoa(nbr->src),
			   ospf_vrf_id_to_name(oi->ospf->vrf_id));

	cbit = CHECK_FLAG(bfd_info->flags, BFD_FLAG_BFD_CBIT_ON);

	bfd_peer_sendmsg(zclient, bfd_info, AF_INET, &nbr->src, NULL, ifp->name,
			 0, 0, cbit, command, 0, oi->ospf->vrf_id);
}

/*
 * ospf_bfd_trigger_event - Neighbor is registered/deregistered with BFD when
 *                          neighbor state is changed to/from 2way.
 */
void ospf_bfd_trigger_event(struct ospf_neighbor *nbr, int old_state, int state)
{
	if ((old_state < NSM_TwoWay) && (state >= NSM_TwoWay))
		ospf_bfd_reg_dereg_nbr(nbr, ZEBRA_BFD_DEST_REGISTER);
	else if ((old_state >= NSM_TwoWay) && (state < NSM_TwoWay))
		ospf_bfd_reg_dereg_nbr(nbr, ZEBRA_BFD_DEST_DEREGISTER);
}

/*
 * ospf_bfd_reg_dereg_all_nbr - Register/Deregister all neighbors associated
 *                              with a interface with BFD through
 *                              zebra for starting/stopping the monitoring of
 *                              the neighbor rechahability.
 */
static int ospf_bfd_reg_dereg_all_nbr(struct interface *ifp, int command)
{
	struct ospf_interface *oi;
	struct route_table *nbrs;
	struct ospf_neighbor *nbr;
	struct route_node *irn;
	struct route_node *nrn;

	for (irn = route_top(IF_OIFS(ifp)); irn; irn = route_next(irn)) {
		if ((oi = irn->info) == NULL)
			continue;

		if ((nbrs = oi->nbrs) == NULL)
			continue;

		for (nrn = route_top(nbrs); nrn; nrn = route_next(nrn)) {
			if ((nbr = nrn->info) == NULL || nbr == oi->nbr_self)
				continue;

			if (command != ZEBRA_BFD_DEST_DEREGISTER)
				ospf_bfd_info_nbr_create(oi, nbr);
			else
				bfd_info_free(
					(struct bfd_info **)&nbr->bfd_info);

			if (nbr->state < NSM_TwoWay)
				continue;

			ospf_bfd_reg_dereg_nbr(nbr, command);
		}
	}

	return 0;
}

/*
 * ospf_bfd_nbr_replay - Replay all the neighbors that have BFD enabled
 *                       to zebra
 */
static int ospf_bfd_nbr_replay(ZAPI_CALLBACK_ARGS)
{
	struct listnode *inode, *node, *onode;
	struct ospf *ospf;
	struct ospf_interface *oi;
	struct route_table *nbrs;
	struct route_node *rn;
	struct ospf_neighbor *nbr;
	struct ospf_if_params *params;

	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE)) {
		zlog_debug("Zebra: BFD Dest replay request");
	}

	/* Send the client registration */
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER, vrf_id);

	/* Replay the neighbor, if BFD is enabled in OSPF */
	for (ALL_LIST_ELEMENTS(om->ospf, node, onode, ospf)) {
		for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, inode, oi)) {
			if ((nbrs = oi->nbrs) == NULL)
				continue;

			params = IF_DEF_PARAMS(oi->ifp);
			if (!params->bfd_info)
				continue;

			for (rn = route_top(nbrs); rn; rn = route_next(rn)) {
				if ((nbr = rn->info) == NULL
				    || nbr == oi->nbr_self)
					continue;

				if (nbr->state < NSM_TwoWay)
					continue;

				if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE))
					zlog_debug("Replaying nbr (%s) to BFD",
						   inet_ntoa(nbr->src));

				ospf_bfd_reg_dereg_nbr(nbr,
						       ZEBRA_BFD_DEST_UPDATE);
			}
		}
	}
	return 0;
}

/*
 * ospf_bfd_interface_dest_update - Find the neighbor for which the BFD status
 *                                  has changed and bring down the neighbor
 *                                  connectivity if the BFD status changed to
 *                                  down.
 */
static int ospf_bfd_interface_dest_update(ZAPI_CALLBACK_ARGS)
{
	struct interface *ifp;
	struct ospf_interface *oi;
	struct ospf_if_params *params;
	struct ospf_neighbor *nbr = NULL;
	struct route_node *node;
	struct route_node *n_node;
	struct prefix p;
	int status;
	int old_status;
	struct bfd_info *bfd_info;
	struct timeval tv;

	ifp = bfd_get_peer_info(zclient->ibuf, &p, NULL, &status,
				NULL, vrf_id);

	if ((ifp == NULL) || (p.family != AF_INET))
		return 0;

	if (IS_DEBUG_OSPF(zebra, ZEBRA_INTERFACE)) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(&p, buf, sizeof(buf));
		zlog_debug("Zebra: interface %s bfd destination %s %s",
			   ifp->name, buf, bfd_get_status_str(status));
	}

	params = IF_DEF_PARAMS(ifp);
	if (!params->bfd_info)
		return 0;

	for (node = route_top(IF_OIFS(ifp)); node; node = route_next(node)) {
		if ((oi = node->info) == NULL)
			continue;

		/* walk the neighbor list for point-to-point network */
		if (oi->type == OSPF_IFTYPE_POINTOPOINT) {
			for (n_node = route_top(oi->nbrs); n_node;
				n_node = route_next(n_node)) {
				nbr = n_node->info;
				if (nbr) {
					/* skip myself */
					if (nbr == oi->nbr_self) {
						nbr = NULL;
						continue;
					}

					/* Found the matching neighbor */
					if (nbr->src.s_addr ==
						p.u.prefix4.s_addr)
						break;
				}
			}
		} else {
			nbr = ospf_nbr_lookup_by_addr(oi->nbrs, &p.u.prefix4);
		}

		if (!nbr || !nbr->bfd_info)
			continue;

		bfd_info = (struct bfd_info *)nbr->bfd_info;
		if (bfd_info->status == status)
			continue;

		old_status = bfd_info->status;
		BFD_SET_CLIENT_STATUS(bfd_info->status, status);
		monotime(&tv);
		bfd_info->last_update = tv.tv_sec;

		if ((status == BFD_STATUS_DOWN)
		    && (old_status == BFD_STATUS_UP)) {
			if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
				zlog_debug("NSM[%s:%s]: BFD Down",
					   IF_NAME(nbr->oi),
					   inet_ntoa(nbr->address.u.prefix4));

			OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_InactivityTimer);
		}
		if ((status == BFD_STATUS_UP)
		    && (old_status == BFD_STATUS_DOWN)) {
			if (IS_DEBUG_OSPF(nsm, NSM_EVENTS))
				zlog_debug("NSM[%s:%s]: BFD Up",
					   IF_NAME(nbr->oi),
					   inet_ntoa(nbr->address.u.prefix4));
		}
	}

	return 0;
}

/*
 * ospf_bfd_info_nbr_create - Create/update BFD information for a neighbor.
 */
void ospf_bfd_info_nbr_create(struct ospf_interface *oi,
			      struct ospf_neighbor *nbr)
{
	struct bfd_info *oi_bfd_info;
	struct bfd_info *nbr_bfd_info;
	struct interface *ifp = oi->ifp;
	struct ospf_if_params *params;

	/* Check if BFD is enabled */
	params = IF_DEF_PARAMS(ifp);

	/* Check if BFD is enabled */
	if (!params->bfd_info)
		return;

	oi_bfd_info = (struct bfd_info *)params->bfd_info;
	if (!nbr->bfd_info)
		nbr->bfd_info = bfd_info_create();

	nbr_bfd_info = (struct bfd_info *)nbr->bfd_info;
	nbr_bfd_info->detect_mult = oi_bfd_info->detect_mult;
	nbr_bfd_info->desired_min_tx = oi_bfd_info->desired_min_tx;
	nbr_bfd_info->required_min_rx = oi_bfd_info->required_min_rx;
}

/*
 * ospf_bfd_write_config - Write the interface BFD configuration.
 */
void ospf_bfd_write_config(struct vty *vty, struct ospf_if_params *params)

{
#if HAVE_BFDD == 0
	struct bfd_info *bfd_info;
#endif /* ! HAVE_BFDD */

	if (!params->bfd_info)
		return;

#if HAVE_BFDD == 0
	bfd_info = (struct bfd_info *)params->bfd_info;

	if (CHECK_FLAG(bfd_info->flags, BFD_FLAG_PARAM_CFG))
		vty_out(vty, " ip ospf bfd %d %d %d\n", bfd_info->detect_mult,
			bfd_info->required_min_rx, bfd_info->desired_min_tx);
	else
#endif /* ! HAVE_BFDD */
		vty_out(vty, " ip ospf bfd\n");
}

/*
 * ospf_bfd_show_info - Show BFD info structure
 */
void ospf_bfd_show_info(struct vty *vty, void *bfd_info, json_object *json_obj,
			bool use_json, int param_only)
{
	if (param_only)
		bfd_show_param(vty, (struct bfd_info *)bfd_info, 1, 0, use_json,
			       json_obj);
	else
		bfd_show_info(vty, (struct bfd_info *)bfd_info, 0, 1, use_json,
			      json_obj);
}

/*
 * ospf_bfd_interface_show - Show the interface BFD configuration.
 */
void ospf_bfd_interface_show(struct vty *vty, struct interface *ifp,
			     json_object *json_interface_sub, bool use_json)
{
	struct ospf_if_params *params;

	params = IF_DEF_PARAMS(ifp);

	ospf_bfd_show_info(vty, params->bfd_info, json_interface_sub, use_json,
			   1);
}

/*
 * ospf_bfd_if_param_set - Set the configured BFD paramter values for
 *                         interface.
 */
static void ospf_bfd_if_param_set(struct interface *ifp, uint32_t min_rx,
				  uint32_t min_tx, uint8_t detect_mult,
				  int defaults)
{
	struct ospf_if_params *params;
	int command = 0;

	params = IF_DEF_PARAMS(ifp);

	bfd_set_param((struct bfd_info **)&(params->bfd_info), min_rx, min_tx,
		      detect_mult, defaults, &command);
	if (command)
		ospf_bfd_reg_dereg_all_nbr(ifp, command);
}

DEFUN (ip_ospf_bfd,
       ip_ospf_bfd_cmd,
       "ip ospf bfd",
       "IP Information\n"
       "OSPF interface commands\n"
       "Enables BFD support\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;
	struct bfd_info *bfd_info;

	assert(ifp);
	params = IF_DEF_PARAMS(ifp);
	bfd_info = params->bfd_info;

	if (!bfd_info || !CHECK_FLAG(bfd_info->flags, BFD_FLAG_PARAM_CFG))
		ospf_bfd_if_param_set(ifp, BFD_DEF_MIN_RX, BFD_DEF_MIN_TX,
				      BFD_DEF_DETECT_MULT, 1);

	return CMD_SUCCESS;
}

#if HAVE_BFDD > 0
DEFUN_HIDDEN(
#else
DEFUN(
#endif /* HAVE_BFDD */
       ip_ospf_bfd_param,
       ip_ospf_bfd_param_cmd,
       "ip ospf bfd (2-255) (50-60000) (50-60000)",
       "IP Information\n"
       "OSPF interface commands\n"
       "Enables BFD support\n"
       "Detect Multiplier\n"
       "Required min receive interval\n"
       "Desired min transmit interval\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 5;
	uint32_t rx_val;
	uint32_t tx_val;
	uint8_t dm_val;
	int ret;

	assert(ifp);

	if ((ret = bfd_validate_param(
		     vty, argv[idx_number]->arg, argv[idx_number_2]->arg,
		     argv[idx_number_3]->arg, &dm_val, &rx_val, &tx_val))
	    != CMD_SUCCESS)
		return ret;

	ospf_bfd_if_param_set(ifp, rx_val, tx_val, dm_val, 0);

	return CMD_SUCCESS;
}

DEFUN (no_ip_ospf_bfd,
       no_ip_ospf_bfd_cmd,
#if HAVE_BFDD > 0
       "no ip ospf bfd",
#else
       "no ip ospf bfd [(2-255) (50-60000) (50-60000)]",
#endif /* HAVE_BFDD */
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Disables BFD support\n"
#if HAVE_BFDD == 0
       "Detect Multiplier\n"
       "Required min receive interval\n"
       "Desired min transmit interval\n"
#endif /* !HAVE_BFDD */
)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;

	assert(ifp);

	params = IF_DEF_PARAMS(ifp);
	if (params->bfd_info) {
		ospf_bfd_reg_dereg_all_nbr(ifp, ZEBRA_BFD_DEST_DEREGISTER);
		bfd_info_free(&(params->bfd_info));
	}

	return CMD_SUCCESS;
}

void ospf_bfd_init(void)
{
	bfd_gbl_init();

	/* Initialize BFD client functions */
	zclient->interface_bfd_dest_update = ospf_bfd_interface_dest_update;
	zclient->bfd_dest_replay = ospf_bfd_nbr_replay;

	/* Install BFD command */
	install_element(INTERFACE_NODE, &ip_ospf_bfd_cmd);
	install_element(INTERFACE_NODE, &ip_ospf_bfd_param_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_bfd_cmd);
}
