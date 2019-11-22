/*
 * This is an implementation of PIM MLAG Functionality
 *
 * Module name: PIM MLAG
 *
 * Author: sathesh Kumar karra <sathk@cumulusnetworks.com>
 *
 * Copyright (C) 2019 Cumulus Networks http://www.cumulusnetworks.com
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "pimd.h"
#include "pim_mlag.h"

extern struct zclient *zclient;


/********************API to process PIM MLAG Data ************************/

static void pim_mlag_process_mlagd_state_change(struct mlag_status msg)
{
	char buf[MLAG_ROLE_STRSIZE];

	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: msg dump: my_role: %s, peer_state: %s",
			   __func__,
			   mlag_role2str(msg.my_role, buf, sizeof(buf)),
			   (msg.peer_state == MLAG_STATE_RUNNING ? "RUNNING"
								 : "DOWN"));
}

static void pim_mlag_process_peer_frr_state_change(struct mlag_frr_status msg)
{
	if (PIM_DEBUG_MLAG)
		zlog_debug(
			"%s: msg dump: peer_frr_state: %s", __func__,
			(msg.frr_state == MLAG_FRR_STATE_UP ? "UP" : "DOWN"));
}

static void pim_mlag_process_vxlan_update(struct mlag_vxlan *msg)
{
}

static void pim_mlag_process_mroute_add(struct mlag_mroute_add msg)
{
	if (PIM_DEBUG_MLAG) {
		zlog_debug(
			"%s: msg dump: vrf_name: %s, s.ip: 0x%x, g.ip: 0x%x cost: %u",
			__func__, msg.vrf_name, msg.source_ip, msg.group_ip,
			msg.cost_to_rp);
		zlog_debug(
			"owner_id: %d, DR: %d, Dual active: %d, vrf_id: 0x%x intf_name: %s",
			msg.owner_id, msg.am_i_dr, msg.am_i_dual_active,
			msg.vrf_id, msg.intf_name);
	}
}

static void pim_mlag_process_mroute_del(struct mlag_mroute_del msg)
{
	if (PIM_DEBUG_MLAG) {
		zlog_debug(
			"%s: msg dump: vrf_name: %s, s.ip: 0x%x, g.ip: 0x%x ",
			__func__, msg.vrf_name, msg.source_ip, msg.group_ip);
		zlog_debug("owner_id: %d, vrf_id: 0x%x intf_name: %s",
			   msg.owner_id, msg.vrf_id, msg.intf_name);
	}
}


int pim_zebra_mlag_handle_msg(struct stream *s, int len)
{
	struct mlag_msg mlag_msg;
	char buf[ZLOG_FILTER_LENGTH_MAX];
	int rc = 0;

	rc = mlag_lib_decode_mlag_hdr(s, &mlag_msg);
	if (rc)
		return (rc);

	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: Received msg type: %s length: %d, bulk_cnt: %d",
			   __func__,
			   mlag_lib_msgid_to_str(mlag_msg.msg_type, buf,
						 sizeof(buf)),
			   mlag_msg.data_len, mlag_msg.msg_cnt);

	switch (mlag_msg.msg_type) {
	case MLAG_STATUS_UPDATE: {
		struct mlag_status msg;

		rc = mlag_lib_decode_mlag_status(s, &msg);
		if (rc)
			return (rc);
		pim_mlag_process_mlagd_state_change(msg);
	} break;
	case MLAG_PEER_FRR_STATUS: {
		struct mlag_frr_status msg;

		rc = mlag_lib_decode_frr_status(s, &msg);
		if (rc)
			return (rc);
		pim_mlag_process_peer_frr_state_change(msg);
	} break;
	case MLAG_VXLAN_UPDATE: {
		struct mlag_vxlan msg;

		rc = mlag_lib_decode_vxlan_update(s, &msg);
		if (rc)
			return rc;
		pim_mlag_process_vxlan_update(&msg);
	} break;
	case MLAG_MROUTE_ADD: {
		struct mlag_mroute_add msg;

		rc = mlag_lib_decode_mroute_add(s, &msg);
		if (rc)
			return (rc);
		pim_mlag_process_mroute_add(msg);
	} break;
	case MLAG_MROUTE_DEL: {
		struct mlag_mroute_del msg;

		rc = mlag_lib_decode_mroute_del(s, &msg);
		if (rc)
			return (rc);
		pim_mlag_process_mroute_del(msg);
	} break;
	case MLAG_MROUTE_ADD_BULK: {
		struct mlag_mroute_add msg;
		int i;

		for (i = 0; i < mlag_msg.msg_cnt; i++) {

			rc = mlag_lib_decode_mroute_add(s, &msg);
			if (rc)
				return (rc);
			pim_mlag_process_mroute_add(msg);
		}
	} break;
	case MLAG_MROUTE_DEL_BULK: {
		struct mlag_mroute_del msg;
		int i;

		for (i = 0; i < mlag_msg.msg_cnt; i++) {

			rc = mlag_lib_decode_mroute_del(s, &msg);
			if (rc)
				return (rc);
			pim_mlag_process_mroute_del(msg);
		}
	} break;
	default:
		break;
	}
	return 0;
}

/****************End of PIM Mesasge processing handler********************/

int pim_zebra_mlag_process_up(void)
{
	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: Received Process-Up from Mlag", __func__);

	return 0;
}

int pim_zebra_mlag_process_down(void)
{
	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: Received Process-Down from Mlag", __func__);

	return 0;
}

static int pim_mlag_register_handler(struct thread *thread)
{
	uint32_t bit_mask = 0;

	if (!zclient)
		return -1;

	SET_FLAG(bit_mask, (1 << MLAG_STATUS_UPDATE));
	SET_FLAG(bit_mask, (1 << MLAG_MROUTE_ADD));
	SET_FLAG(bit_mask, (1 << MLAG_MROUTE_DEL));
	SET_FLAG(bit_mask, (1 << MLAG_DUMP));
	SET_FLAG(bit_mask, (1 << MLAG_MROUTE_ADD_BULK));
	SET_FLAG(bit_mask, (1 << MLAG_MROUTE_DEL_BULK));
	SET_FLAG(bit_mask, (1 << MLAG_PIM_CFG_DUMP));
	SET_FLAG(bit_mask, (1 << MLAG_VXLAN_UPDATE));
	SET_FLAG(bit_mask, (1 << MLAG_PEER_FRR_STATUS));

	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: Posting Client Register to MLAG mask: 0x%x",
			   __func__, bit_mask);

	zclient_send_mlag_register(zclient, bit_mask);
	return 0;
}

void pim_mlag_register(void)
{
	if (router->mlag_process_register)
		return;

	router->mlag_process_register = true;

	thread_add_event(router->master, pim_mlag_register_handler, NULL, 0,
			 NULL);
}

static int pim_mlag_deregister_handler(struct thread *thread)
{
	if (!zclient)
		return -1;

	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: Posting Client De-Register to MLAG from PIM",
			   __func__);
	router->connected_to_mlag = false;
	zclient_send_mlag_deregister(zclient);
	return 0;
}

void pim_mlag_deregister(void)
{
	/* if somebody still interested in the MLAG channel skip de-reg */
	if (router->pim_mlag_intf_cnt)
		return;

	/* not registered; nothing do */
	if (!router->mlag_process_register)
		return;

	router->mlag_process_register = false;

	thread_add_event(router->master, pim_mlag_deregister_handler, NULL, 0,
			 NULL);
}

void pim_if_configure_mlag_dualactive(struct pim_interface *pim_ifp)
{
	if (!pim_ifp || !pim_ifp->pim || pim_ifp->activeactive == true)
		return;

	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: Configuring active-active on Interface: %s",
			   __func__, "NULL");

	pim_ifp->activeactive = true;
	if (pim_ifp->pim)
		pim_ifp->pim->inst_mlag_intf_cnt++;

	router->pim_mlag_intf_cnt++;
	if (PIM_DEBUG_MLAG)
		zlog_debug(
			"%s: Total MLAG configured Interfaces on router: %d, Inst: %d",
			__func__, router->pim_mlag_intf_cnt,
			pim_ifp->pim->inst_mlag_intf_cnt);

	if (router->pim_mlag_intf_cnt == 1) {
		/*
		 * atleast one Interface is configured for MLAG, send register
		 * to Zebra for receiving MLAG Updates
		 */
		pim_mlag_register();
	}
}

void pim_if_unconfigure_mlag_dualactive(struct pim_interface *pim_ifp)
{
	if (!pim_ifp || !pim_ifp->pim || pim_ifp->activeactive == false)
		return;

	if (PIM_DEBUG_MLAG)
		zlog_debug("%s: UnConfiguring active-active on Interface: %s",
			   __func__, "NULL");

	pim_ifp->activeactive = false;
	pim_ifp->pim->inst_mlag_intf_cnt--;

	router->pim_mlag_intf_cnt--;
	if (PIM_DEBUG_MLAG)
		zlog_debug(
			"%s: Total MLAG configured Interfaces on router: %d, Inst: %d",
			__func__, router->pim_mlag_intf_cnt,
			pim_ifp->pim->inst_mlag_intf_cnt);

	if (router->pim_mlag_intf_cnt == 0) {
		/*
		 * all the Interfaces are MLAG un-configured, post MLAG
		 * De-register to Zebra
		 */
		pim_mlag_deregister();
	}
}


void pim_instance_mlag_init(struct pim_instance *pim)
{
	if (!pim)
		return;

	pim->inst_mlag_intf_cnt = 0;
}


void pim_instance_mlag_terminate(struct pim_instance *pim)
{
	struct interface *ifp;

	if (!pim)
		return;

	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		struct pim_interface *pim_ifp = ifp->info;

		if (!pim_ifp || pim_ifp->activeactive == false)
			continue;

		pim_if_unconfigure_mlag_dualactive(pim_ifp);
	}
	pim->inst_mlag_intf_cnt = 0;
}

void pim_mlag_init(void)
{
	router->pim_mlag_intf_cnt = 0;
	router->connected_to_mlag = false;
	router->mlag_fifo = stream_fifo_new();
	router->zpthread_mlag_write = NULL;
	router->mlag_stream = stream_new(MLAG_BUF_LIMIT);
}
