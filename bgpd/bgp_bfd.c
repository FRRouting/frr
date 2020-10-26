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
bool bgp_bfd_is_peer_multihop(struct peer *peer)
{
	struct bfd_info *bfd_info;

	bfd_info = (struct bfd_info *)peer->bfd_info;

	if (!bfd_info)
		return false;

	if ((bfd_info->type == BFD_TYPE_MULTIHOP)
	    || ((peer->sort == BGP_PEER_IBGP) && !peer->shared_network)
	    || is_ebgp_multihop_configured(peer))
		return true;
	else
		return false;
}

/*
 * bgp_bfd_peer_sendmsg - Format and send a Peer register/Unregister
 *                        command to Zebra to be forwarded to BFD
 */
static void bgp_bfd_peer_sendmsg(struct peer *peer, int command)
{
	struct bfd_session_arg arg = {};
	struct bfd_info *bfd_info;
	int multihop;
	vrf_id_t vrf_id;
	size_t addrlen;

	/*
	 * XXX: some pointers are dangling during shutdown, so instead of
	 * trying to send a message during signal handlers lets just wait BGP
	 * to terminate zebra's connection and BFD will automatically find
	 * out that we are no longer expecting notifications.
	 *
	 * The pointer that is causing a crash here is `peer->nexthop.ifp`.
	 * That happens because at this point of the shutdown all interfaces are
	 * already `free()`d.
	 */
	if (bm->terminating)
		return;

	bfd_info = (struct bfd_info *)peer->bfd_info;

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
	/* while graceful restart with fwd path preserved
	 * and bfd controlplane check not configured is not kept
	 * keep bfd independent controlplane bit set to 1
	 */
	if (!CHECK_FLAG(peer->bgp->flags, BGP_FLAG_GRACEFUL_RESTART)
	    && !CHECK_FLAG(peer->bgp->flags, BGP_FLAG_GR_PRESERVE_FWD)
	    && !CHECK_FLAG(bfd_info->flags, BFD_FLAG_BFD_CHECK_CONTROLPLANE))
		SET_FLAG(bfd_info->flags, BFD_FLAG_BFD_CBIT_ON);

	/* Set all message arguments. */
	arg.family = peer->su.sa.sa_family;
	addrlen = arg.family == AF_INET ? sizeof(struct in_addr)
					: sizeof(struct in6_addr);

	if (arg.family == AF_INET)
		memcpy(&arg.dst, &peer->su.sin.sin_addr, addrlen);
	else
		memcpy(&arg.dst, &peer->su.sin6.sin6_addr, addrlen);

	if (peer->su_local) {
		if (arg.family == AF_INET)
			memcpy(&arg.src, &peer->su_local->sin.sin_addr,
			       addrlen);
		else
			memcpy(&arg.src, &peer->su_local->sin6.sin6_addr,
			       addrlen);
	}

	if (peer->nexthop.ifp) {
		arg.ifnamelen = strlen(peer->nexthop.ifp->name);
		strlcpy(arg.ifname, peer->nexthop.ifp->name,
			sizeof(arg.ifname));
	}

	if (bfd_info->profile[0]) {
		arg.profilelen = strlen(bfd_info->profile);
		strlcpy(arg.profile, bfd_info->profile, sizeof(arg.profile));
	}

	arg.set_flag = 1;
	arg.mhop = multihop;
	arg.ttl = peer->ttl;
	arg.vrf_id = vrf_id;
	arg.command = command;
	arg.bfd_info = bfd_info;
	arg.min_tx = bfd_info->desired_min_tx;
	arg.min_rx = bfd_info->required_min_rx;
	arg.detection_multiplier = bfd_info->detect_mult;
	arg.cbit = CHECK_FLAG(bfd_info->flags, BFD_FLAG_BFD_CBIT_ON);

	/* Send message. */
	zclient_bfd_command(zclient, &arg);
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

/**
 * bgp_bfd_reset_peer - reinitialise bfd
 * ensures that bfd state machine is restarted
 * to be synced with remote bfd
 */
void bgp_bfd_reset_peer(struct peer *peer)
{
	if (!peer->bfd_info)
		return;

	bgp_bfd_peer_sendmsg(peer, ZEBRA_BFD_DEST_REGISTER);
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
static int bgp_bfd_dest_replay(ZAPI_CALLBACK_ARGS)
{
	struct listnode *mnode, *node, *nnode;
	struct bgp *bgp;
	struct peer *peer;

	if (BGP_DEBUG(zebra, ZEBRA))
		zlog_debug("Zebra: BFD Dest replay request");

	/* Send the client registration */
	bfd_client_sendmsg(zclient, ZEBRA_BFD_CLIENT_REGISTER, vrf_id);

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
static void bgp_bfd_peer_status_update(struct peer *peer, int status,
				       int remote_cbit)
{
	struct bfd_info *bfd_info;
	int old_status;

	bfd_info = (struct bfd_info *)peer->bfd_info;

	if (bfd_info->status == status)
		return;

	old_status = bfd_info->status;
	BFD_SET_CLIENT_STATUS(bfd_info->status, status);

	bfd_info->last_update = bgp_clock();

	if (status != old_status) {
		if (BGP_DEBUG(neighbor_events, NEIGHBOR_EVENTS))
			zlog_debug("[%s]: BFD %s", peer->host,
				   bfd_get_status_str(status));
	}
	if ((status == BFD_STATUS_DOWN) && (old_status == BFD_STATUS_UP)) {
		if (CHECK_FLAG(peer->sflags, PEER_STATUS_NSF_MODE) &&
		    CHECK_FLAG(bfd_info->flags, BFD_FLAG_BFD_CHECK_CONTROLPLANE) &&
		    !remote_cbit) {
			zlog_info("%s BFD DOWN message ignored in the process of graceful restart when C bit is cleared",
				  peer->host);
			return;
		}
		peer->last_reset = PEER_DOWN_BFD_DOWN;
		BGP_EVENT_ADD(peer, BGP_Stop);
	}
	if ((status == BFD_STATUS_UP) && (old_status == BFD_STATUS_DOWN)
	    && peer->status != Established) {
		if (!BGP_PEER_START_SUPPRESSED(peer)) {
			bgp_fsm_nht_update(peer, true);
			BGP_EVENT_ADD(peer, BGP_Start);
		}
	}
}

/*
 * bgp_bfd_dest_update - Find the peer for which the BFD status
 *                       has changed and bring down the peer
 *                       connectivity if the BFD session went down.
 */
static int bgp_bfd_dest_update(ZAPI_CALLBACK_ARGS)
{
	struct interface *ifp;
	struct prefix dp;
	struct prefix sp;
	int status;
	int remote_cbit;

	ifp = bfd_get_peer_info(zclient->ibuf, &dp, &sp, &status,
				&remote_cbit, vrf_id);

	if (BGP_DEBUG(zebra, ZEBRA)) {
		struct vrf *vrf;

		vrf = vrf_lookup_by_id(vrf_id);

		if (ifp)
			zlog_debug(
				"Zebra: vrf %s(%u) interface %s bfd destination %pFX %s %s",
				VRF_LOGNAME(vrf), vrf_id, ifp->name, &dp,
				bfd_get_status_str(status),
				remote_cbit ? "(cbit on)" : "");
		else
			zlog_debug(
				"Zebra: vrf %s(%u) source %pFX bfd destination %pFX %s %s",
				VRF_LOGNAME(vrf), vrf_id, &sp, &dp,
				bfd_get_status_str(status),
				remote_cbit ? "(cbit on)" : "");
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
								   status,
								   remote_cbit);
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
								   status,
								   remote_cbit);
				}
			}
	}

	return 0;
}

/*
 * bgp_bfd_peer_param_set - Set the configured BFD paramter values for peer.
 */
static int bgp_bfd_peer_param_set(struct peer *peer, uint32_t min_rx,
				  uint32_t min_tx, uint8_t detect_mult,
				  int defaults)
{
	struct bfd_info *bi;
	struct peer_group *group;
	struct listnode *node, *nnode;
	int command = 0;

	bfd_set_param((struct bfd_info **)&(peer->bfd_info), min_rx, min_tx,
		      detect_mult, NULL, defaults, &command);

	/* This command overrides profile if it was previously applied. */
	bi = peer->bfd_info;
	bi->profile[0] = 0;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		group = peer->group;
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			command = 0;
			bfd_set_param((struct bfd_info **)&(peer->bfd_info),
				      min_rx, min_tx, detect_mult, NULL,
				      defaults, &command);

			/*
			 * This command overrides profile if it was previously
			 * applied.
			 */
			bi = peer->bfd_info;
			bi->profile[0] = 0;

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
			      BFD_DEF_DETECT_MULT, NULL, 1, &command);

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
					BFD_DEF_DETECT_MULT, NULL, 1, &command);

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

#if HAVE_BFDD > 0
/**
 * Set peer BFD profile configuration.
 */
static int bgp_bfd_peer_set_profile(struct peer *peer, const char *profile)
{
	struct peer_group *group;
	struct listnode *node, *nnode;
	int command = 0;
	struct bfd_info *bfd_info;

	bfd_set_param((struct bfd_info **)&(peer->bfd_info), BFD_DEF_MIN_RX,
		      BFD_DEF_MIN_TX, BFD_DEF_DETECT_MULT, NULL, 1, &command);

	bfd_info = (struct bfd_info *)peer->bfd_info;

	/* If profile was specified, then copy string. */
	if (profile)
		strlcpy(bfd_info->profile, profile, sizeof(bfd_info->profile));
	else /* Otherwise just initialize it empty. */
		bfd_info->profile[0] = 0;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		group = peer->group;
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			command = 0;
			bfd_set_param((struct bfd_info **)&(peer->bfd_info),
				      BFD_DEF_MIN_RX, BFD_DEF_MIN_TX,
				      BFD_DEF_DETECT_MULT, NULL, 1, &command);

			bfd_info = (struct bfd_info *)peer->bfd_info;

			/* If profile was specified, then copy string. */
			if (profile)
				strlcpy(bfd_info->profile, profile,
					sizeof(bfd_info->profile));
			else /* Otherwise just initialize it empty. */
				bfd_info->profile[0] = 0;

			if (peer->status == Established
			    && command == ZEBRA_BFD_DEST_REGISTER)
				bgp_bfd_register_peer(peer);
			else if (command == ZEBRA_BFD_DEST_UPDATE)
				bgp_bfd_update_peer(peer);
		}
	} else {
		if (peer->status == Established
		    && command == ZEBRA_BFD_DEST_REGISTER)
			bgp_bfd_register_peer(peer);
		else if (command == ZEBRA_BFD_DEST_UPDATE)
			bgp_bfd_update_peer(peer);
	}

	return 0;
}
#endif

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
#if HAVE_BFDD > 0
		vty_out(vty, " neighbor %s bfd\n", addr);
#else
		vty_out(vty, " neighbor %s bfd %d %d %d\n", addr,
			bfd_info->detect_mult, bfd_info->required_min_rx,
			bfd_info->desired_min_tx);
#endif /* HAVE_BFDD */

	if (bfd_info->type != BFD_TYPE_NOT_CONFIGURED)
		vty_out(vty, " neighbor %s bfd %s\n", addr,
			(bfd_info->type == BFD_TYPE_MULTIHOP) ? "multihop"
							      : "singlehop");

	if (!CHECK_FLAG(bfd_info->flags, BFD_FLAG_PARAM_CFG)
	    && (bfd_info->type == BFD_TYPE_NOT_CONFIGURED)) {
		vty_out(vty, " neighbor %s bfd", addr);
		if (bfd_info->profile[0])
			vty_out(vty, " profile %s", bfd_info->profile);
		vty_out(vty, "\n");
	}

	if (CHECK_FLAG(bfd_info->flags, BFD_FLAG_BFD_CHECK_CONTROLPLANE))
		vty_out(vty, " neighbor %s bfd check-control-plane-failure\n", addr);
}

/*
 * bgp_bfd_show_info - Show the peer BFD information.
 */
void bgp_bfd_show_info(struct vty *vty, struct peer *peer, bool use_json,
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

#if HAVE_BFDD > 0
DEFUN_HIDDEN(
#else
DEFUN(
#endif /* HAVE_BFDD */
       neighbor_bfd_param,
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
	uint32_t rx_val;
	uint32_t tx_val;
	uint8_t dm_val;
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

static int bgp_bfd_set_check_controlplane_failure_peer(struct vty *vty, struct peer *peer,
						       const char *no)
{
	struct bfd_info *bfd_info;

	if (!peer->bfd_info) {
		if (no)
			return CMD_SUCCESS;
		vty_out(vty, "%% Specify bfd command first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	bfd_info = (struct bfd_info *)peer->bfd_info;
	if (!no) {
		if (!CHECK_FLAG(bfd_info->flags, BFD_FLAG_BFD_CHECK_CONTROLPLANE)) {
			SET_FLAG(bfd_info->flags,  BFD_FLAG_BFD_CHECK_CONTROLPLANE);
			bgp_bfd_update_peer(peer);
		}
	} else {
		if (CHECK_FLAG(bfd_info->flags, BFD_FLAG_BFD_CHECK_CONTROLPLANE)) {
			UNSET_FLAG(bfd_info->flags,  BFD_FLAG_BFD_CHECK_CONTROLPLANE);
			bgp_bfd_update_peer(peer);
		}
	}
	return CMD_SUCCESS;
}


DEFUN (neighbor_bfd_check_controlplane_failure,
       neighbor_bfd_check_controlplane_failure_cmd,
       "[no] neighbor <A.B.C.D|X:X::X:X|WORD> bfd check-control-plane-failure",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "BFD support\n"
       "Link dataplane status with BGP controlplane\n")
{
	const char *no = strmatch(argv[0]->text, "no") ? "no" : NULL;
	int idx_peer = 0;
	struct peer *peer;
	struct peer_group *group;
	struct listnode *node, *nnode;
	int ret = CMD_SUCCESS;

	if (no)
		idx_peer = 2;
	else
		idx_peer = 1;
	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer) {
		vty_out(vty, "%% Specify remote-as or peer-group commands first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (!peer->bfd_info) {
		if (no)
			return CMD_SUCCESS;
		vty_out(vty, "%% Specify bfd command first\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		group = peer->group;
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer))
			ret = bgp_bfd_set_check_controlplane_failure_peer(vty, peer, no);
	} else
		ret = bgp_bfd_set_check_controlplane_failure_peer(vty, peer, no);
	return ret;
 }

DEFUN (no_neighbor_bfd,
       no_neighbor_bfd_cmd,
#if HAVE_BFDD > 0
       "no neighbor <A.B.C.D|X:X::X:X|WORD> bfd",
#else
       "no neighbor <A.B.C.D|X:X::X:X|WORD> bfd [(2-255) (50-60000) (50-60000)]",
#endif /* HAVE_BFDD */
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disables BFD support\n"
#if HAVE_BFDD == 0
       "Detect Multiplier\n"
       "Required min receive interval\n"
       "Desired min transmit interval\n"
#endif /* !HAVE_BFDD */
)
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

#if HAVE_BFDD > 0
DEFUN(neighbor_bfd_profile, neighbor_bfd_profile_cmd,
      "neighbor <A.B.C.D|X:X::X:X|WORD> bfd profile BFDPROF",
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "BFD integration\n"
      BFD_PROFILE_STR
      BFD_PROFILE_NAME_STR)
{
	int idx_peer = 1, idx_prof = 4;
	struct peer *peer;
	int ret;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	ret = bgp_bfd_peer_set_profile(peer, argv[idx_prof]->arg);
	if (ret != 0)
		return bgp_vty_return(vty, ret);

	return CMD_SUCCESS;
}

DEFUN(no_neighbor_bfd_profile, no_neighbor_bfd_profile_cmd,
      "no neighbor <A.B.C.D|X:X::X:X|WORD> bfd profile [BFDPROF]",
      NO_STR
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "BFD integration\n"
      BFD_PROFILE_STR
      BFD_PROFILE_NAME_STR)
{
	int idx_peer = 2;
	struct peer *peer;
	int ret;

	peer = peer_and_group_lookup_vty(vty, argv[idx_peer]->arg);
	if (!peer)
		return CMD_WARNING_CONFIG_FAILED;

	if (!peer->bfd_info)
		return 0;

	ret = bgp_bfd_peer_set_profile(peer, NULL);
	if (ret != 0)
		return bgp_vty_return(vty, ret);

	return CMD_SUCCESS;
}
#endif /* HAVE_BFDD */

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
	install_element(BGP_NODE, &neighbor_bfd_check_controlplane_failure_cmd);
	install_element(BGP_NODE, &no_neighbor_bfd_cmd);
	install_element(BGP_NODE, &no_neighbor_bfd_type_cmd);

#if HAVE_BFDD > 0
	install_element(BGP_NODE, &neighbor_bfd_profile_cmd);
	install_element(BGP_NODE, &no_neighbor_bfd_profile_cmd);
#endif /* HAVE_BFDD */
}
