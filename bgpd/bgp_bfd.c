/**
 * bgp_bfd.c: BGP BFD handling routines
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
#include "bfd.h"
#include "lib/json.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgp_fsm.h"
#include "bgpd/bgp_bfd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_vty.h"

extern struct zclient *zclient;

/*
 * bgp_bfd_peer_group2peer_copy - Copy the BFD information from peer group
 * template
 *                                to peer.
 */
void bgp_bfd_peer_group2peer_copy(struct peer *conf, struct peer *peer)
{
	struct bfd_info *bfd_info;
	struct bfd_info *conf_bfd_info;

	if (!conf->bfd_info)
		return;

	conf_bfd_info = (struct bfd_info *)conf->bfd_info;
	if (!peer->bfd_info)
		peer->bfd_info = bfd_info_create();

	bfd_info = (struct bfd_info *)peer->bfd_info;

	/* Copy BFD parameter values */
	bfd_info->required_min_rx = conf_bfd_info->required_min_rx;
	bfd_info->desired_min_tx = conf_bfd_info->desired_min_tx;
	bfd_info->detect_mult = conf_bfd_info->detect_mult;
	bfd_info->type = conf_bfd_info->type;
}

/*
 * bgp_bfd_is_peer_multihop - returns whether BFD peer is multi-hop or single
 * hop.
 */
int bgp_bfd_is_peer_multihop(struct peer *peer)
{
	struct bfd_info *bfd_info;

	bfd_info = (struct bfd_info *)peer->bfd_info;

	if (!bfd_info)
		return 0;

	if ((bfd_info->type == BFD_TYPE_MULTIHOP)
	    || ((peer->sort == BGP_PEER_IBGP) && !peer->shared_network)
	    || is_ebgp_multihop_configured(peer))
		return 1;
	else
		return 0;
}

/*
 * bgp_bfd_peer_sendmsg - Format and send a Peer register/Unregister
 *                        command to Zebra to be forwarded to BFD
 */
static void bgp_bfd_peer_sendmsg(struct peer *peer, int command)
{
	struct bfd_info *bfd_info;
	vrf_id_t vrf_id = VRF_DEFAULT;
	int multihop;

	bfd_info = (struct bfd_info *)peer->bfd_info;

	if (peer->bgp && (peer->bgp->inst_type == BGP_INSTANCE_TYPE_VRF))
		vrf_id = peer->bgp->vrf_id;

	if (command == ZEBRA_BFD_DEST_DEREGISTER) {
		multihop =
			CHECK_FLAG(bfd_info->flags, BFD_FLAG_BFD_TYPE_MULTIHOP);
		UNSET_FLAG(bfd_info->flags, BFD_FLAG_BFD_TYPE_MULTIHOP);
	} else {
		multihop = bgp_bfd_is_peer_multihop(peer);
		if ((command == ZEBRA_BFD_DEST_REGISTER) && multihop)
			SET_FLAG(bfd_info->flags, BFD_FLAG_BFD_TYPE_MULTIHOP);
	}

	if (peer->su.sa.sa_family == AF_INET)
		bfd_peer_sendmsg(
			zclient, bfd_info, AF_INET, &peer->su.sin.sin_addr,
			(peer->su_local) ? &peer->su_local->sin.sin_addr : NULL,
			(peer->nexthop.ifp) ? peer->nexthop.ifp->name : NULL,
			peer->ttl, multihop, command, 1, vrf_id);
	else if (peer->su.sa.sa_family == AF_INET6)
		bfd_peer_sendmsg(
			zclient, bfd_info, AF_INET6, &peer->su.sin6.sin6_addr,
			(peer->su_local) ? &peer->su_local->sin6.sin6_addr
					 : NULL,
			(peer->nexthop.ifp) ? peer->nexthop.ifp->name : NULL,
			peer->ttl, multihop, command, 1, vrf_id);
}

/*
 * bgp_bfd_register_peer - register a peer with BFD through zebra
 *                         for monitoring the peer rechahability.
 */
void bgp_bfd_register_peer(struct peer *peer)
{
	struct bfd_info *bfd_info;

	if (!peer->bfd_info)
		return;
	bfd_info = (struct bfd_info *)peer->bfd_info;

	/* Check if BFD is enabled and peer has already been registered with BFD
	 */
	if (CHECK_FLAG(bfd_info->flags, BFD_FLAG_BFD_REG))
		return;

	bgp_bfd_peer_sendmsg(peer, ZEBRA_BFD_DEST_REGISTER);
}

/**
 * bgp_bfd_deregister_peer - deregister a peer with BFD through zebra
 *                           for stopping the monitoring of the peer
 *                           rechahability.
 */
void bgp_bfd_deregister_peer(struct peer *peer)
{
	struct bfd_info *bfd_info;

	if (!peer->bfd_info)
		return;
	bfd_info = (struct bfd_info *)peer->bfd_info;

	/* Check if BFD is eanbled and peer has not been registered */
	if (!CHECK_FLAG(bfd_info->flags, BFD_FLAG_BFD_REG))
		return;

	bfd_info->status = BFD_STATUS_DOWN;
	bfd_info->last_update = bgp_clock();

	bgp_bfd_peer_sendmsg(peer, ZEBRA_BFD_DEST_DEREGISTER);
}

/*
 * bgp_bfd_update_peer - update peer with BFD with new BFD paramters
 *                       through zebra.
 */
static void bgp_bfd_update_peer(struct peer *peer)
{
	struct bfd_info *bfd_info;

	if (!peer->bfd_info)
		return;
	bfd_info = (struct bfd_info *)peer->bfd_info;

	/* Check if the peer has been registered with BFD*/
	if (!CHECK_FLAG(bfd_info->flags, BFD_FLAG_BFD_REG))
		return;

	bgp_bfd_peer_sendmsg(peer, ZEBRA_BFD_DEST_UPDATE);
}

/*
 * bgp_bfd_update_type - update session type with BFD through zebra.
 */
static void bgp_bfd_update_type(struct peer *peer)
{
	struct bfd_info *bfd_info;
	int multihop;

	if (!peer->bfd_info)
		return;
	bfd_info = (struct bfd_info *)peer->bfd_info;

	/* Check if the peer has been registered with BFD*/
	if (!CHECK_FLAG(bfd_info->flags, BFD_FLAG_BFD_REG))
		return;

	if (bfd_info->type == BFD_TYPE_NOT_CONFIGURED) {
		multihop = bgp_bfd_is_peer_multihop(peer);
		if ((multihop
		     && !CHECK_FLAG(bfd_info->flags,
				    BFD_FLAG_BFD_TYPE_MULTIHOP))
		    || (!multihop && CHECK_FLAG(bfd_info->flags,
						BFD_FLAG_BFD_TYPE_MULTIHOP))) {
			bgp_bfd_peer_sendmsg(peer, ZEBRA_BFD_DEST_DEREGISTER);
			bgp_bfd_peer_sendmsg(peer, ZEBRA_BFD_DEST_REGISTER);
		}
	} else {
		if ((bfd_info->type == BFD_TYPE_MULTIHOP
		     && !CHECK_FLAG(bfd_info->flags,
				    BFD_FLAG_BFD_TYPE_MULTIHOP))
		    || (bfd_info->type == BFD_TYPE_SINGLEHOP
			&& CHECK_FLAG(bfd_info->flags,
				      BFD_FLAG_BFD_TYPE_MULTIHOP))) {
			bgp_bfd_peer_sendmsg(peer, ZEBRA_BFD_DEST_DEREGISTER);
			bgp_bfd_peer_sendmsg(peer, ZEBRA_BFD_DEST_REGISTER);
		}
	}
}

/*
 * bgp_bfd_dest_replay - Replay all the peers that have BFD enabled
 *                       to zebra
 */
static int bgp_bfd_dest_replay(int command, struct zclient *client,
			       zebra_size_t length, vrf_id_t vrf_id)
{
	struct listnode *mnode, *node, *nnode;
	struct bgp *bgp;
	struct peer *peer;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Zebra: BFD Dest replay request");

	/* Send the client registration */
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER);

	/* Replay the peer, if BFD is enabled in BGP */

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, mnode, bgp))
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			bgp_bfd_update_peer(peer);
		}

	return 0;
}

/*
 * bgp_bfd_peer_status_update - Update the BFD status if it has changed. Bring
 *                              down the peer if the BFD session went down from
 * *                              up.
 */
static void bgp_bfd_peer_status_update(struct peer *peer, int status)
{
	struct bfd_info *bfd_info;
	int old_status;

	bfd_info = (struct bfd_info *)peer->bfd_info;

	if (bfd_info->status == status)
		return;

	old_status = bfd_info->status;
	bfd_info->status = status;
	bfd_info->last_update = bgp_clock();

	if ((status == BFD_STATUS_DOWN) && (old_status == BFD_STATUS_UP)) {
		peer->last_reset = PEER_DOWN_BFD_DOWN;
		BGP_EVENT_ADD(peer, BGP_Stop);
	}
}

/*
 * bgp_bfd_dest_update - Find the peer for which the BFD status
 *                       has changed and bring down the peer
 *                       connectivity if the BFD session went down.
 */
static int bgp_bfd_dest_update(int command, struct zclient *zclient,
			       zebra_size_t length, vrf_id_t vrf_id)
{
	struct interface *ifp;
	struct prefix dp;
	struct prefix sp;
	int status;

	ifp = bfd_get_peer_info(zclient->ibuf, &dp, &sp, &status, vrf_id);

	if (BGP_DEBUG(zebra, ZEBRA)) {
		char buf[2][PREFIX2STR_BUFFER];
		prefix2str(&dp, buf[0], sizeof(buf[0]));
		if (ifp) {
			zlog_debug(
				"Zebra: vrf %u interface %s bfd destination %s %s",
				vrf_id, ifp->name, buf[0],
				bfd_get_status_str(status));
		} else {
			prefix2str(&sp, buf[1], sizeof(buf[1]));
			zlog_debug(
				"Zebra: vrf %u source %s bfd destination %s %s",
				vrf_id, buf[1], buf[0],
				bfd_get_status_str(status));
		}
	}

	/* Bring the peer down if BFD is enabled in BGP */
	{
		struct listnode *mnode, *node, *nnode;
		struct bgp *bgp;
		struct peer *peer;

		for (ALL_LIST_ELEMENTS_RO(bm->bgp, mnode, bgp))
			for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
				if (!peer->bfd_info)
					continue;

				if ((dp.family == AF_INET)
				    && (peer->su.sa.sa_family == AF_INET)) {
					if (dp.u.prefix4.s_addr
					    != peer->su.sin.sin_addr.s_addr)
						continue;
				} else if ((dp.family == AF_INET6)
					   && (peer->su.sa.sa_family
					       == AF_INET6)) {
					if (memcmp(&dp.u.prefix6,
						   &peer->su.sin6.sin6_addr,
						   sizeof(struct in6_addr)))
						continue;
				} else
					continue;

				if (ifp && (ifp == peer->nexthop.ifp)) {
					bgp_bfd_peer_status_update(peer,
								   status);
				} else {
					if (!peer->su_local)
						continue;

					if ((sp.family == AF_INET)
					    && (peer->su_local->sa.sa_family
						== AF_INET)) {
						if (sp.u.prefix4.s_addr
						    != peer->su_local->sin
							       .sin_addr.s_addr)
							continue;
					} else if ((sp.family == AF_INET6)
						   && (peer->su_local->sa
							       .sa_family
						       == AF_INET6)) {
						if (memcmp(&sp.u.prefix6,
							   &peer->su_local->sin6
								    .sin6_addr,
							   sizeof(struct
								  in6_addr)))
							continue;
					} else
						continue;

					if ((vrf_id != VRF_DEFAULT)
					    && (peer->bgp->vrf_id != vrf_id))
						continue;

					bgp_bfd_peer_status_update(peer,
								   status);
				}
			}
	}

	return 0;
}

/*
 * bgp_bfd_peer_param_set - Set the configured BFD paramter values for peer.
 */
static int bgp_bfd_peer_param_set(struct peer *peer, u_int32_t min_rx,
				  u_int32_t min_tx, u_int8_t detect_mult,
				  int defaults)
{
	struct peer_group *group;
	struct listnode *node, *nnode;
	int command = 0;

	bfd_set_param((struct bfd_info **)&(peer->bfd_info), min_rx, min_tx,
		      detect_mult, defaults, &command);

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		group = peer->group;
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			command = 0;
			bfd_set_param((struct bfd_info **)&(peer->bfd_info),
				      min_rx, min_tx, detect_mult, defaults,
				      &command);

			if ((peer->status == Established)
			    && (command == ZEBRA_BFD_DEST_REGISTER))
				bgp_bfd_register_peer(peer);
			else if (command == ZEBRA_BFD_DEST_UPDATE)
				bgp_bfd_update_peer(peer);
		}
	} else {
		if ((peer->status == Established)
		    && (command == ZEBRA_BFD_DEST_REGISTER))
			bgp_bfd_register_peer(peer);
		else if (command == ZEBRA_BFD_DEST_UPDATE)
			bgp_bfd_update_peer(peer);
	}
	return 0;
}

/*
 * bgp_bfd_peer_param_unset - Delete the configured BFD paramter values for
 * peer.
 */
static int bgp_bfd_peer_param_unset(struct peer *peer)
{
	struct peer_group *group;
	struct listnode *node, *nnode;

	if (!peer->bfd_info)
		return 0;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		bfd_info_free(&(peer->bfd_info));
		group = peer->group;
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			bgp_bfd_deregister_peer(peer);
			bfd_info_free(&(peer->bfd_info));
		}
	} else {
		bgp_bfd_deregister_peer(peer);
		bfd_info_free(&(peer->bfd_info));
	}
	return 0;
}

/*
 * bgp_bfd_peer_param_type_set - set the BFD session type (multihop or
 * singlehop)
 */
static int bgp_bfd_peer_param_type_set(struct peer *peer,
				       enum bfd_sess_type type)
{
	struct peer_group *group;
	struct listnode *node, *nnode;
	int command = 0;
	struct bfd_info *bfd_info;

	if (!peer->bfd_info)
		bfd_set_param((struct bfd_info **)&(peer->bfd_info),
			      BFD_DEF_MIN_RX, BFD_DEF_MIN_TX,
			      BFD_DEF_DETECT_MULT, 1, &command);

	bfd_info = (struct bfd_info *)peer->bfd_info;
	bfd_info->type = type;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		group = peer->group;
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			command = 0;
			if (!peer->bfd_info)
				bfd_set_param(
					(struct bfd_info **)&(peer->bfd_info),
					BFD_DEF_MIN_RX, BFD_DEF_MIN_TX,
					BFD_DEF_DETECT_MULT, 1, &command);

			bfd_info = (struct bfd_info *)peer->bfd_info;
			bfd_info->type = type;

			if (peer->status == Established) {
				if (command == ZEBRA_BFD_DEST_REGISTER)
					bgp_bfd_register_peer(peer);
				else
					bgp_bfd_update_type(peer);
			}
		}
	} else {
		if (peer->status == Established) {
			if (command == ZEBRA_BFD_DEST_REGISTER)
				bgp_bfd_register_peer(peer);
			else
				bgp_bfd_update_type(peer);
		}
	}

	return 0;
}

/*
 * bgp_bfd_peer_config_write - Write the peer BFD configuration.
 */
void bgp_bfd_peer_config_write(struct vty *vty, struct peer *peer, char *addr)
{
	struct bfd_info *bfd_info;

	if (!peer->bfd_info)
		return;

	bfd_info = (struct bfd_info *)peer->bfd_info;

	if (CHECK_FLAG(bfd_info->flags, BFD_FLAG_PARAM_CFG))
		vty_out(vty, " neighbor %s bfd %d %d %d\n", addr,
			bfd_info->detect_mult, bfd_info->required_min_rx,
			bfd_info->desired_min_tx);

	if (bfd_info->type != BFD_TYPE_NOT_CONFIGURED)
		vty_out(vty, " neighbor %s bfd %s\n", addr,
			(bfd_info->type == BFD_TYPE_MULTIHOP) ? "multihop"
							      : "singlehop");

	if (!CHECK_FLAG(bfd_info->flags, BFD_FLAG_PARAM_CFG)
	    && (bfd_info->type == BFD_TYPE_NOT_CONFIGURED))
		vty_out(vty, " neighbor %s bfd\n", addr);
}

/*
 * bgp_bfd_show_info - Show the peer BFD information.
 */
void bgp_bfd_show_info(struct vty *vty, struct peer *peer, u_char use_json,
		       json_object *json_neigh)
{
	bfd_show_info(vty, (struct bfd_info *)peer->bfd_info,
		      bgp_bfd_is_peer_multihop(peer), 0, use_json, json_neigh);
}

DEFUN (neighbor_bfd,
       neighbor_bfd_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> bfd",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enables BFD support\n")
{
	int idx_peer = 1;
	struct peer *peer;
	int ret;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = bgp_bfd_peer_param_set(peer, BFD_DEF_MIN_RX, BFD_DEF_MIN_TX,
				     BFD_DEF_DETECT_MULT, 1);
	if (ret != 0)
		return bgp_vty_return(vty, ret);

	return CMD_SUCCESS;
}

DEFUN (neighbor_bfd_param,
       neighbor_bfd_param_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> bfd (2-255) (50-60000) (50-60000)",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enables BFD support\n"
       "Detect Multiplier\n"
       "Required min receive interval\n"
       "Desired min transmit interval\n")
{
	int idx_peer = 1;
	int idx_number_1 = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 5;
	struct peer *peer;
	u_int32_t rx_val;
	u_int32_t tx_val;
	u_int8_t dm_val;
	int ret;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if ((ret = bfd_validate_param(
		     vty, argv[idx_number_1]->arg, argv[idx_number_2]->arg,
		     argv[idx_number_3]->arg, &dm_val, &rx_val, &tx_val))
	    != CMD_SUCCESS)
		return ret;

	ret = bgp_bfd_peer_param_set(peer, rx_val, tx_val, dm_val, 0);
	if (ret != 0)
		return bgp_vty_return(vty, ret);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (neighbor_bfd_type,
       neighbor_bfd_type_cmd,
       "neighbor <A.B.C.D|X:X::X:X|WORD> bfd <multihop|singlehop>",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enables BFD support\n"
       "Multihop session\n"
       "Single hop session\n")
{
	int idx_peer = 1;
	int idx_hop = 3;
	struct peer *peer;
	enum bfd_sess_type type;
	int ret;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (strmatch(argv[idx_hop]->text, "singlehop"))
		type = BFD_TYPE_SINGLEHOP;
	else if (strmatch(argv[idx_hop]->text, "multihop"))
		type = BFD_TYPE_MULTIHOP;
	else
		return CMD_WARNING_CONFIG_FAILED;

	ret = bgp_bfd_peer_param_type_set(peer, type);
	if (ret != 0)
		return bgp_vty_return(vty, ret);

	return CMD_SUCCESS;
}

DEFUN (no_neighbor_bfd,
       no_neighbor_bfd_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> bfd [(2-255) (50-60000) (50-60000)]",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disables BFD support\n"
       "Detect Multiplier\n"
       "Required min receive interval\n"
       "Desired min transmit interval\n")
{
	int idx_peer = 2;
	struct peer *peer;
	int ret;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = bgp_bfd_peer_param_unset(peer);
	if (ret != 0)
		return bgp_vty_return(vty, ret);

	return CMD_SUCCESS;
}


DEFUN_HIDDEN (no_neighbor_bfd_type,
       no_neighbor_bfd_type_cmd,
       "no neighbor <A.B.C.D|X:X::X:X|WORD> bfd <multihop|singlehop>",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disables BFD support\n"
       "Multihop session\n"
       "Singlehop session\n")
{
	int idx_peer = 2;
	struct peer *peer;
	int ret;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (!peer->bfd_info)
		return 0;

	ret = bgp_bfd_peer_param_type_set(peer, BFD_TYPE_NOT_CONFIGURED);
	if (ret != 0)
		return bgp_vty_return(vty, ret);

	return CMD_SUCCESS;
}

void bgp_bfd_init(void)
{
	bfd_gbl_init();

	/* Initialize BFD client functions */
	zclient->interface_bfd_dest_update = bgp_bfd_dest_update;
	zclient->bfd_dest_replay = bgp_bfd_dest_replay;

	/* "neighbor bfd" commands. */
	install_element(BGP_NODE, &neighbor_bfd_cmd);
	install_element(BGP_NODE, &neighbor_bfd_param_cmd);
	install_element(BGP_NODE, &neighbor_bfd_type_cmd);
	install_element(BGP_NODE, &no_neighbor_bfd_cmd);
	install_element(BGP_NODE, &no_neighbor_bfd_type_cmd);
}
