/*
 * pim_bfd.c: PIM BFD handling routines
 *
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Chirag Shah
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
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#include <zebra.h>

#include "lib/json.h"
#include "command.h"
#include "vty.h"
#include "zclient.h"

#include "pim_instance.h"
#include "pim_cmd.h"
#include "pim_vty.h"
#include "pim_iface.h"
#include "pim_bfd.h"
#include "bfd.h"
#include "pimd.h"
#include "pim_zebra.h"

/*
 * pim_bfd_write_config - Write the interface BFD configuration.
 */
void pim_bfd_write_config(struct vty *vty, struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct bfd_info *bfd_info = NULL;

	if (!pim_ifp)
		return;

	bfd_info = (struct bfd_info *)pim_ifp->bfd_info;
	if (!bfd_info)
		return;

#if HAVE_BFDD == 0
	if (CHECK_FLAG(bfd_info->flags, BFD_FLAG_PARAM_CFG))
		vty_out(vty, " ip pim bfd %d %d %d\n", bfd_info->detect_mult,
			bfd_info->required_min_rx, bfd_info->desired_min_tx);
	else
#endif /* ! HAVE_BFDD */
		vty_out(vty, " ip pim bfd\n");
}

/*
 * pim_bfd_show_info - Show BFD info structure
 */
void pim_bfd_show_info(struct vty *vty, void *bfd_info, json_object *json_obj,
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
 * pim_bfd_info_nbr_create - Create/update BFD information for a neighbor.
 */
void pim_bfd_info_nbr_create(struct pim_interface *pim_ifp,
			     struct pim_neighbor *neigh)
{
	struct bfd_info *nbr_bfd_info = NULL;

	/* Check if Pim Interface BFD is enabled */
	if (!pim_ifp || !pim_ifp->bfd_info)
		return;

	if (!neigh->bfd_info)
		neigh->bfd_info = bfd_info_create();

	if (!neigh->bfd_info)
		return;

	nbr_bfd_info = (struct bfd_info *)neigh->bfd_info;
	nbr_bfd_info->detect_mult = pim_ifp->bfd_info->detect_mult;
	nbr_bfd_info->desired_min_tx = pim_ifp->bfd_info->desired_min_tx;
	nbr_bfd_info->required_min_rx = pim_ifp->bfd_info->required_min_rx;
}

/*
 * pim_bfd_info_free - Free BFD info structure
 */
void pim_bfd_info_free(struct bfd_info **bfd_info)
{
	bfd_info_free(bfd_info);
}

static void pim_bfd_reg_dereg_nbr(struct pim_neighbor *nbr, int command)
{
	struct pim_interface *pim_ifp = NULL;
	struct bfd_info *bfd_info = NULL;
	struct zclient *zclient = NULL;
	int cbit;

	zclient = pim_zebra_zclient_get();

	if (!nbr)
		return;
	pim_ifp = nbr->interface->info;
	bfd_info = (struct bfd_info *)pim_ifp->bfd_info;
	if (!bfd_info)
		return;
	if (PIM_DEBUG_PIM_TRACE) {
		char str[INET_ADDRSTRLEN];
		pim_inet4_dump("<bfd_nbr?>", nbr->source_addr, str,
			       sizeof(str));
		zlog_debug("%s Nbr %s %s with BFD", __PRETTY_FUNCTION__, str,
			   bfd_get_command_dbg_str(command));
	}

	cbit = CHECK_FLAG(bfd_info->flags, BFD_FLAG_BFD_CBIT_ON);

	bfd_peer_sendmsg(zclient, bfd_info, AF_INET, &nbr->source_addr, NULL,
			 nbr->interface->name, 0, 0, cbit,
			 command, 0, VRF_DEFAULT);
}

/*
 * pim_bfd_reg_dereg_all_nbr - Register/Deregister all neighbors associated
 *                              with a interface with BFD through
 *                              zebra for starting/stopping the monitoring of
 *                              the neighbor rechahability.
 */
int pim_bfd_reg_dereg_all_nbr(struct interface *ifp, int command)
{
	struct pim_interface *pim_ifp = NULL;
	struct listnode *node = NULL;
	struct pim_neighbor *neigh = NULL;

	pim_ifp = ifp->info;
	if (!pim_ifp)
		return -1;
	if (!pim_ifp->bfd_info)
		return -1;

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list, node, neigh)) {
		if (command != ZEBRA_BFD_DEST_DEREGISTER)
			pim_bfd_info_nbr_create(pim_ifp, neigh);
		else
			pim_bfd_info_free((struct bfd_info **)&neigh->bfd_info);

		pim_bfd_reg_dereg_nbr(neigh, command);
	}

	return 0;
}

/*
 * pim_bfd_trigger_event - Neighbor is registered/deregistered with BFD when
 *                          neighbor state is changed to/from 2way.
 */
void pim_bfd_trigger_event(struct pim_interface *pim_ifp,
			   struct pim_neighbor *nbr, uint8_t nbr_up)
{
	if (nbr_up) {
		pim_bfd_info_nbr_create(pim_ifp, nbr);
		pim_bfd_reg_dereg_nbr(nbr, ZEBRA_BFD_DEST_REGISTER);
	} else {
		pim_bfd_info_free(&nbr->bfd_info);
		pim_bfd_reg_dereg_nbr(nbr, ZEBRA_BFD_DEST_DEREGISTER);
	}
}

/*
 * pim_bfd_if_param_set - Set the configured BFD paramter values for
 *                         interface.
 */
void pim_bfd_if_param_set(struct interface *ifp, uint32_t min_rx,
			  uint32_t min_tx, uint8_t detect_mult, int defaults)
{
	struct pim_interface *pim_ifp = ifp->info;
	int command = 0;

	if (!pim_ifp)
		return;
	bfd_set_param((struct bfd_info **)&(pim_ifp->bfd_info), min_rx, min_tx,
		      detect_mult, defaults, &command);

	if (pim_ifp->bfd_info) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: interface %s has bfd_info",
				   __PRETTY_FUNCTION__, ifp->name);
	}
	if (command)
		pim_bfd_reg_dereg_all_nbr(ifp, command);
}


/*
 * pim_bfd_interface_dest_update - Find the neighbor for which the BFD status
 *                                  has changed and bring down the neighbor
 *                                  connectivity if the BFD status changed to
 *                                  down.
 */
static int pim_bfd_interface_dest_update(ZAPI_CALLBACK_ARGS)
{
	struct interface *ifp = NULL;
	struct pim_interface *pim_ifp = NULL;
	struct prefix p;
	int status;
	char msg[100];
	int old_status;
	struct bfd_info *bfd_info = NULL;
	struct timeval tv;
	struct listnode *neigh_node = NULL;
	struct listnode *neigh_nextnode = NULL;
	struct pim_neighbor *neigh = NULL;

	ifp = bfd_get_peer_info(zclient->ibuf, &p, NULL, &status,
				NULL, vrf_id);

	if ((ifp == NULL) || (p.family != AF_INET))
		return 0;

	pim_ifp = ifp->info;
	if (!pim_ifp)
		return 0;

	if (!pim_ifp->bfd_info) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: pim interface %s BFD is disabled ",
				   __PRETTY_FUNCTION__, ifp->name);
		return 0;
	}

	if (PIM_DEBUG_PIM_TRACE) {
		char buf[PREFIX2STR_BUFFER];
		prefix2str(&p, buf, sizeof(buf));
		zlog_debug("%s: interface %s bfd destination %s %s",
			   __PRETTY_FUNCTION__, ifp->name, buf,
			   bfd_get_status_str(status));
	}

	for (ALL_LIST_ELEMENTS(pim_ifp->pim_neighbor_list, neigh_node,
			       neigh_nextnode, neigh)) {
		/* Check neigh address matches with BFD address */
		if (neigh->source_addr.s_addr != p.u.prefix4.s_addr)
			continue;

		bfd_info = (struct bfd_info *)neigh->bfd_info;
		if (bfd_info->status == status) {
			if (PIM_DEBUG_PIM_TRACE) {
				char str[INET_ADDRSTRLEN];
				pim_inet4_dump("<nht_nbr?>", neigh->source_addr,
					       str, sizeof(str));
				zlog_debug("%s: bfd status is same for nbr %s",
					   __PRETTY_FUNCTION__, str);
			}
			continue;
		}
		old_status = bfd_info->status;
		BFD_SET_CLIENT_STATUS(bfd_info->status, status);
		monotime(&tv);
		bfd_info->last_update = tv.tv_sec;

		if (PIM_DEBUG_PIM_TRACE) {
			zlog_debug("%s: status %s old_status %s",
				   __PRETTY_FUNCTION__,
				   bfd_get_status_str(status),
				   bfd_get_status_str(old_status));
		}
		if ((status == BFD_STATUS_DOWN)
		    && (old_status == BFD_STATUS_UP)) {
			snprintf(msg, sizeof(msg), "BFD Session Expired");
			pim_neighbor_delete(ifp, neigh, msg);
		}
	}
	return 0;
}

/*
 * pim_bfd_nbr_replay - Replay all the neighbors that have BFD enabled
 *                       to zebra
 */
static int pim_bfd_nbr_replay(ZAPI_CALLBACK_ARGS)
{
	struct interface *ifp = NULL;
	struct pim_interface *pim_ifp = NULL;
	struct pim_neighbor *neigh = NULL;
	struct listnode *neigh_node;
	struct listnode *neigh_nextnode;
	struct vrf *vrf = NULL;

	/* Send the client registration */
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER, vrf_id);

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			pim_ifp = ifp->info;

			if (!pim_ifp)
				continue;

			if (pim_ifp->pim_sock_fd < 0)
				continue;

			for (ALL_LIST_ELEMENTS(pim_ifp->pim_neighbor_list,
					       neigh_node, neigh_nextnode,
					       neigh)) {
				if (!neigh->bfd_info)
					continue;
				if (PIM_DEBUG_PIM_TRACE) {
					char str[INET_ADDRSTRLEN];

					pim_inet4_dump("<bfd_nbr?>",
						       neigh->source_addr, str,
						       sizeof(str));
					zlog_debug(
						"%s: Replaying Pim Neigh %s to BFD vrf_id %u",
						__PRETTY_FUNCTION__, str,
						vrf->vrf_id);
				}
				pim_bfd_reg_dereg_nbr(neigh,
						      ZEBRA_BFD_DEST_UPDATE);
			}
		}
	}
	return 0;
}

void pim_bfd_init(void)
{
	struct zclient *zclient = NULL;

	zclient = pim_zebra_zclient_get();

	bfd_gbl_init();

	zclient->interface_bfd_dest_update = pim_bfd_interface_dest_update;
	zclient->bfd_dest_replay = pim_bfd_nbr_replay;
}
