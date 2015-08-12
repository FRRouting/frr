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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
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
#include "bfd.h"
#include "lib/json.h"
#include "bgpd/bgpd.h"
#include "bgp_fsm.h"
#include "bgpd/bgp_bfd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_vty.h"

extern struct zclient *zclient;

/*
 * bgp_bfd_peer_group2peer_copy - Copy the BFD information from peer group template
 *                                to peer.
 */
void
bgp_bfd_peer_group2peer_copy(struct peer *conf, struct peer *peer)
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
}

/*
 * bgp_bfd_is_peer_multihop - returns whether BFD peer is multi-hop or single hop.
 */
static int
bgp_bfd_is_peer_multihop(struct peer *peer)
{
  if((peer->sort == BGP_PEER_IBGP) || is_ebgp_multihop_configured(peer))
    return 1;
  else
    return 0;
}

/*
 * bgp_bfd_peer_sendmsg - Format and send a Peer register/Unregister
 *                        command to Zebra to be forwarded to BFD
 */
static void
bgp_bfd_peer_sendmsg (struct peer *peer, int command)
{
  struct bfd_info *bfd_info;

  bfd_info = (struct bfd_info *)peer->bfd_info;

  if (peer->su.sa.sa_family == AF_INET)
    bfd_peer_sendmsg (zclient, bfd_info, AF_INET,
                      &peer->su.sin.sin_addr,
                      (peer->su_local) ? &peer->su_local->sin.sin_addr : NULL,
                      (peer->nexthop.ifp) ? peer->nexthop.ifp->name : NULL,
                      peer->ttl, bgp_bfd_is_peer_multihop(peer), command, 1);
  else if (peer->su.sa.sa_family == AF_INET6)
    bfd_peer_sendmsg (zclient, bfd_info, AF_INET6,
                      &peer->su.sin6.sin6_addr,
                      (peer->su_local) ? &peer->su_local->sin6.sin6_addr : NULL,
                      (peer->nexthop.ifp) ? peer->nexthop.ifp->name : NULL,
                      peer->ttl, bgp_bfd_is_peer_multihop(peer), command, 1);
}

/*
 * bgp_bfd_register_peer - register a peer with BFD through zebra
 *                         for monitoring the peer rechahability.
 */
void
bgp_bfd_register_peer (struct peer *peer)
{
  struct bfd_info *bfd_info;

  if (!peer->bfd_info)
    return;
  bfd_info = (struct bfd_info *)peer->bfd_info;

  /* Check if BFD is enabled and peer has already been registered with BFD */
  if (CHECK_FLAG(bfd_info->flags, BFD_FLAG_BFD_REG))
    return;

  bgp_bfd_peer_sendmsg(peer, ZEBRA_BFD_DEST_REGISTER);
}

/**
 * bgp_bfd_deregister_peer - deregister a peer with BFD through zebra
 *                           for stopping the monitoring of the peer
 *                           rechahability.
 */
void
bgp_bfd_deregister_peer (struct peer *peer)
{
  struct bfd_info *bfd_info;

  if (!peer->bfd_info)
    return;
  bfd_info = (struct bfd_info *)peer->bfd_info;

  /* Check if BFD is eanbled and peer has not been registered */
  if (!CHECK_FLAG(bfd_info->flags, BFD_FLAG_BFD_REG))
    return;

  bgp_bfd_peer_sendmsg(peer, ZEBRA_BFD_DEST_DEREGISTER);
}

/*
 * bgp_bfd_update_peer - update peer with BFD with new BFD paramters
 *                       through zebra.
 */
static void
bgp_bfd_update_peer (struct peer *peer)
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
 * bgp_bfd_dest_replay - Replay all the peers that have BFD enabled
 *                       to zebra
 */
static int
bgp_bfd_dest_replay (int command, struct zclient *client, zebra_size_t length)
{
  struct listnode *mnode, *node, *nnode;
  struct bgp *bgp;
  struct peer *peer;

  if (BGP_DEBUG (zebra, ZEBRA))
    zlog_debug("Zebra: BFD Dest replay request");

  /* Replay the peer, if BFD is enabled in BGP */

  for (ALL_LIST_ELEMENTS_RO (bm->bgp, mnode, bgp))
    for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
      {
        bgp_bfd_update_peer(peer);
      }

  return 0;
}

/*
 * bgp_interface_bfd_dest_down - Find the peer for which the BFD status
 *                               has changed and bring down the peer
 *                               connectivity.
 */
static int
bgp_interface_bfd_dest_down (int command, struct zclient *zclient,
                             zebra_size_t length)
{
  struct interface *ifp;
  struct prefix dp;
  struct prefix sp;

  ifp = bfd_get_peer_info (zclient->ibuf, &dp, &sp);

  if (BGP_DEBUG (zebra, ZEBRA))
    {
      char buf[2][128];
      prefix2str(&dp, buf[0], sizeof(buf[0]));
      if (ifp)
        {
          zlog_debug("Zebra: interface %s bfd destination %s down",
                      ifp->name, buf[0]);
        }
      else
        {
          prefix2str(&sp, buf[1], sizeof(buf[1]));
          zlog_debug("Zebra: source %s bfd destination %s down",
                      buf[1], buf[0]);
        }
    }

  /* Bring the peer down if BFD is enabled in BGP */
  {
    struct listnode *mnode, *node, *nnode;
    struct bgp *bgp;
    struct peer *peer;

    for (ALL_LIST_ELEMENTS_RO (bm->bgp, mnode, bgp))
      for (ALL_LIST_ELEMENTS (bgp->peer, node, nnode, peer))
        {
          if (!peer->bfd_info)
            continue;

          if ((dp.family == AF_INET) && (peer->su.sa.sa_family == AF_INET))
            {
              if (dp.u.prefix4.s_addr != peer->su.sin.sin_addr.s_addr)
                continue;
            }
#ifdef HAVE_IPV6
          else if ((dp.family == AF_INET6) &&
                    (peer->su.sa.sa_family == AF_INET6))
            {
              if (memcmp(&dp.u.prefix6, &peer->su.sin6.sin6_addr,
                          sizeof (struct in6_addr)))
                continue;
            }
#endif
          else
            continue;

          if (ifp && (ifp == peer->nexthop.ifp))
            {
              peer->last_reset = PEER_DOWN_BFD_DOWN;
              BGP_EVENT_ADD (peer, BGP_Stop);
            }
          else
            {
              if (!peer->su_local)
                continue;

              if ((sp.family == AF_INET) &&
                    (peer->su_local->sa.sa_family == AF_INET))
                {
                  if (sp.u.prefix4.s_addr != peer->su_local->sin.sin_addr.s_addr)
                    continue;
                }
#ifdef HAVE_IPV6
              else if ((sp.family == AF_INET6) &&
                        (peer->su_local->sa.sa_family == AF_INET6)) 
                {
                  if (memcmp(&sp.u.prefix6, &peer->su_local->sin6.sin6_addr,
                              sizeof (struct in6_addr)))
                    continue;
                }
#endif
              else
                continue;

              peer->last_reset = PEER_DOWN_BFD_DOWN;
              BGP_EVENT_ADD (peer, BGP_Stop);
            }
        }
  }

  return 0;
}

/*
 * bgp_bfd_peer_param_set - Set the configured BFD paramter values for peer.
 */
static int
bgp_bfd_peer_param_set (struct peer *peer, u_int32_t min_rx, u_int32_t min_tx,
                         u_int8_t detect_mult, int defaults)
{
  struct peer_group *group;
  struct listnode *node, *nnode;
  int command = 0;

  bfd_set_param(&(peer->bfd_info), min_rx, min_tx, detect_mult,
                defaults, &command);

  if (CHECK_FLAG (peer->sflags, PEER_STATUS_GROUP))
    {
      group = peer->group;
      for (ALL_LIST_ELEMENTS (group->peer, node, nnode, peer))
        {
          command = 0;
          bfd_set_param(&(peer->bfd_info), min_rx, min_tx, detect_mult,
                        defaults, &command);

          if ((peer->status == Established) &&
              (command == ZEBRA_BFD_DEST_REGISTER))
            bgp_bfd_register_peer(peer);
          else if (command == ZEBRA_BFD_DEST_UPDATE)
            bgp_bfd_update_peer(peer);
        }
    }
  else
    {
      if ((peer->status == Established) &&
          (command == ZEBRA_BFD_DEST_REGISTER))
        bgp_bfd_register_peer(peer);
      else if (command == ZEBRA_BFD_DEST_UPDATE)
        bgp_bfd_update_peer(peer);
    }
  return 0;
}

/*
 * bgp_bfd_peer_param_unset - Unset the configured BFD paramter values for peer.
 */
static int
bgp_bfd_peer_param_unset (struct peer *peer)
{
  struct peer_group *group;
  struct listnode *node, *nnode;

  if (!peer->bfd_info)
    return 0;

  if (CHECK_FLAG (peer->sflags, PEER_STATUS_GROUP))
    {
      bfd_info_free(&(peer->bfd_info));
      group = peer->group;
      for (ALL_LIST_ELEMENTS (group->peer, node, nnode, peer))
        {
          bgp_bfd_deregister_peer(peer);
          bfd_info_free(&(peer->bfd_info));
        }
    }
  else
    {
      bgp_bfd_deregister_peer(peer);
      bfd_info_free(&(peer->bfd_info));
    }
  return 0;
}

/*
 * bgp_bfd_peer_config_write - Write the peer BFD configuration.
 */
void
bgp_bfd_peer_config_write(struct vty *vty, struct peer *peer, char *addr)
{
  struct bfd_info *bfd_info;

  if (!peer->bfd_info)
    return;

  bfd_info = (struct bfd_info *)peer->bfd_info;

  if (CHECK_FLAG (bfd_info->flags, BFD_FLAG_PARAM_CFG))
    vty_out (vty, " neighbor %s bfd %d %d %d%s", addr,
      bfd_info->detect_mult, bfd_info->required_min_rx,
      bfd_info->desired_min_tx, VTY_NEWLINE);
  else
    vty_out (vty, " neighbor %s bfd%s", addr, VTY_NEWLINE);
}

/*
 * bgp_bfd_show_info - Show the peer BFD information.
 */
void
bgp_bfd_show_info(struct vty *vty, struct peer *peer, u_char use_json, json_object *json_neigh)
{
  struct bfd_info *bfd_info;
  json_object *json_bfd = NULL;

  if (!peer->bfd_info)
    return;

  if (use_json)
    json_bfd = json_object_new_object();

  bfd_info = (struct bfd_info *)peer->bfd_info;

  if (use_json)
    {
      if (bgp_bfd_is_peer_multihop(peer))
        json_object_string_add(json_bfd, "bfdMultiHop", "yes");
      else
        json_object_string_add(json_bfd, "bfdMultiHop", "no");
      json_object_int_add(json_bfd, "detectMultiplier", bfd_info->detect_mult);
      json_object_int_add(json_bfd, "rxMinInterval", bfd_info->required_min_rx);
      json_object_int_add(json_bfd, "txMinInterval", bfd_info->desired_min_tx);
      json_object_object_add(json_neigh, "peerBfdInfo", json_bfd);
    }
  else
    {
      vty_out (vty, "  BFD: Multi-hop: %s%s",
               (bgp_bfd_is_peer_multihop(peer)) ? "yes" : "no", VTY_NEWLINE);
      vty_out (vty, "    Detect Mul: %d, Min Rx interval: %d,"
               " Min Tx interval: %d%s",
               bfd_info->detect_mult, bfd_info->required_min_rx,
               bfd_info->desired_min_tx, VTY_NEWLINE);
      vty_out (vty, "%s", VTY_NEWLINE);
    }
}

DEFUN (neighbor_bfd,
       neighbor_bfd_cmd,
       NEIGHBOR_CMD2 "bfd",
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enables BFD support\n")
{
  struct peer *peer;
  int ret;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = bgp_bfd_peer_param_set (peer, BFD_DEF_MIN_RX, BFD_DEF_MIN_TX,
                                  BFD_DEF_DETECT_MULT, 1);
  if (ret != 0)
    return bgp_vty_return (vty, ret);

  return CMD_SUCCESS;

}

DEFUN (neighbor_bfd_param,
       neighbor_bfd_param_cmd,
       NEIGHBOR_CMD2 "bfd " BFD_CMD_DETECT_MULT_RANGE BFD_CMD_MIN_RX_RANGE BFD_CMD_MIN_TX_RANGE,
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Enables BFD support\n"
       "Detect Multiplier\n"
       "Required min receive interval\n"
       "Desired min transmit interval\n")
{
  struct peer *peer;
  u_int32_t rx_val;
  u_int32_t tx_val;
  u_int8_t dm_val;
  int ret;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (!peer)
    return CMD_WARNING;

  if ((ret = bfd_validate_param (vty, argv[1], argv[2], argv[3], &dm_val,
                                 &rx_val, &tx_val)) != CMD_SUCCESS)
    return ret;

  ret = bgp_bfd_peer_param_set (peer, rx_val, tx_val, dm_val, 0);
  if (ret != 0)
    return bgp_vty_return (vty, ret);

  return CMD_SUCCESS;

}

DEFUN (no_neighbor_bfd,
       no_neighbor_bfd_cmd,
       NO_NEIGHBOR_CMD2 "bfd",
       NO_STR
       NEIGHBOR_STR
       NEIGHBOR_ADDR_STR2
       "Disables BFD support\n")
{
  struct peer *peer;
  int ret;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  ret = bgp_bfd_peer_param_unset(peer);
  if (ret != 0)
    return bgp_vty_return (vty, ret);

  return CMD_SUCCESS;
}

void
bgp_bfd_init(void)
{
  /* Initialize BFD client functions */
  zclient->interface_bfd_dest_down = bgp_interface_bfd_dest_down;
  zclient->bfd_dest_replay = bgp_bfd_dest_replay;

  /* "neighbor bfd" commands. */
  install_element (BGP_NODE, &neighbor_bfd_cmd);
  install_element (BGP_NODE, &neighbor_bfd_param_cmd);
  install_element (BGP_NODE, &no_neighbor_bfd_cmd);
}
