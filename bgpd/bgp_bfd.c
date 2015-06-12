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
#include "bgp_fsm.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_bfd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_vty.h"

extern struct zclient *zclient;

/*
 * bgp_bfd_peer_init - Allocate and initialize the peer BFD information
 *                     with default values.
 */
void
bgp_bfd_peer_init(struct peer *peer)
{
  struct bgp_bfd_peer_info *bfd_info;

  peer->bfd_info = XCALLOC (MTYPE_BGP_PEER_BFD_INFO,
                                  sizeof (struct bgp_bfd_peer_info));

  bfd_info = (struct bgp_bfd_peer_info *)peer->bfd_info;

  /* Set default BFD parameter values */
  bfd_info->required_min_rx = BGP_BFD_DEF_MIN_RX;
  bfd_info->desired_min_tx = BGP_BFD_DEF_MIN_TX;
  bfd_info->detect_mult = BGP_BFD_DEF_DETECT_MULT;
}

/*
 * bgp_bfd_peer_free - Free the peer BFD information.
 */
void
bgp_bfd_peer_free(struct peer *peer)
{
  XFREE (MTYPE_BGP_PEER_BFD_INFO, peer->bfd_info);
}

/*
 * bgp_bfd_peer_group2peer_copy - Copy the BFD information from peer group template
 *                                to peer.
 */
void
bgp_bfd_peer_group2peer_copy(struct peer *conf, struct peer *peer)
{
  struct bgp_bfd_peer_info *bfd_info;
  struct bgp_bfd_peer_info *conf_bfd_info;

  bfd_info = (struct bgp_bfd_peer_info *)peer->bfd_info;
  conf_bfd_info = (struct bgp_bfd_peer_info *)conf->bfd_info;

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
 * sendmsg_bfd_peer - Format and send a Peer register/Unregister
 *                    command to Zebra to be forwarded to BFD
 */
static void
sendmsg_bfd_peer (struct peer *peer, int command)
{
  struct stream *s;
  int ret;
  int len;
  struct bgp_bfd_peer_info *bfd_info;

  bfd_info = (struct bgp_bfd_peer_info *)peer->bfd_info;

  /* Check socket. */
  if (!zclient || zclient->sock < 0)
    {
      zlog_debug("%s: Can't send BFD peer register, Zebra client not established",
		 __FUNCTION__);
      return;
    }

  s = zclient->obuf;
  stream_reset (s);
  zclient_create_header (s, command);

  stream_putw(s, peer->su.sa.sa_family);
  switch (peer->su.sa.sa_family)
    {
    case AF_INET:
      stream_put_in_addr (s, &peer->su.sin.sin_addr);
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      stream_put(s, &(peer->su.sin6.sin6_addr), 16);
      break;
#endif
    default:
      break;
    }

  if (command != ZEBRA_BFD_DEST_DEREGISTER)
    {
      stream_putl(s, bfd_info->required_min_rx);
      stream_putl(s, bfd_info->desired_min_tx);
      stream_putc(s, bfd_info->detect_mult);
    }

  if (bgp_bfd_is_peer_multihop(peer))
    {
      stream_putc(s, 1);
      /* Multi-hop destination send the source IP address to BFD */
      if (peer->su_local)
        {
          stream_putw(s, peer->su_local->sa.sa_family);
          switch (peer->su_local->sa.sa_family)
            {
            case AF_INET:
              stream_put_in_addr (s, &peer->su_local->sin.sin_addr);
              break;
        #ifdef HAVE_IPV6
            case AF_INET6:
              stream_put(s, &(peer->su_local->sin6.sin6_addr), 16);
              break;
        #endif
            default:
              break;
            }
        }
      stream_putc(s, peer->ttl);
    }
  else
    {
      stream_putc(s, 0);
#ifdef HAVE_IPV6
      if ((peer->su.sa.sa_family == AF_INET6) && (peer->su_local))
        {
          stream_putw(s, peer->su_local->sa.sa_family);
          stream_put(s, &(peer->su_local->sin6.sin6_addr), 16);
        }
#endif

      if (peer->nexthop.ifp)
        {
          len = strlen(peer->nexthop.ifp->name);
          stream_putc(s, len);
          stream_put(s, peer->nexthop.ifp->name, len);
        }
      else
        {
          stream_putc(s, 0);
        }
    }

  stream_putw_at (s, 0, stream_get_endp (s));

  ret = zclient_send_message(zclient);

  if (ret < 0)
    zlog_warn("sendmsg_bfd_peer: zclient_send_message() failed");

  if (command == ZEBRA_BFD_DEST_REGISTER)
    SET_FLAG(bfd_info->flags, BGP_BFD_FLAG_BFD_REG);
  else if (command == ZEBRA_BFD_DEST_DEREGISTER)
    UNSET_FLAG(bfd_info->flags, BGP_BFD_FLAG_BFD_REG);
  return;
}

/*
 * bgp_bfd_register_peer - register a peer with BFD through zebra
 *                         for monitoring the peer rechahability.
 */
void
bgp_bfd_register_peer (struct peer *peer)
{
  struct bgp_bfd_peer_info *bfd_info;

  bfd_info = (struct bgp_bfd_peer_info *)peer->bfd_info;

  /* Check if BFD is enabled and peer has already been registered with BFD */
  if (!CHECK_FLAG(peer->flags, PEER_FLAG_BFD) ||
        CHECK_FLAG(bfd_info->flags, BGP_BFD_FLAG_BFD_REG))
    return;

  sendmsg_bfd_peer(peer, ZEBRA_BFD_DEST_REGISTER);
}

/**
 * bgp_bfd_deregister_peer - deregister a peer with BFD through zebra
 *                           for stopping the monitoring of the peer
 *                           rechahability.
 */
void
bgp_bfd_deregister_peer (struct peer *peer)
{
  struct bgp_bfd_peer_info *bfd_info;

  bfd_info = (struct bgp_bfd_peer_info *)peer->bfd_info;

  /* Check if BFD is eanbled and peer has not been registered */
  if (!CHECK_FLAG(peer->flags, PEER_FLAG_BFD) ||
        !CHECK_FLAG(bfd_info->flags, BGP_BFD_FLAG_BFD_REG))
    return;

  sendmsg_bfd_peer(peer, ZEBRA_BFD_DEST_DEREGISTER);
}

/*
 * bgp_bfd_update_peer - update peer with BFD with new BFD paramters
 *                       through zebra.
 */
void
bgp_bfd_update_peer (struct peer *peer)
{
  struct bgp_bfd_peer_info *bfd_info;

  bfd_info = (struct bgp_bfd_peer_info *)peer->bfd_info;

  /* Check if the peer has been registered with BFD*/
  if (!CHECK_FLAG(bfd_info->flags, BGP_BFD_FLAG_BFD_REG))
    return;

  sendmsg_bfd_peer(peer, ZEBRA_BFD_DEST_UPDATE);
}

/*
 * bgp_bfd_dest_replay - Replay all the peers that have BFD enabled
 *                       to zebra
 */
int
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
        if (!CHECK_FLAG (peer->flags, PEER_FLAG_BFD))
          continue;

        bgp_bfd_update_peer(peer);
      }

  return 0;
}

/*
 * bgp_interface_bfd_dest_down - Find the peer for which the BFD status
 *                               has changed and bring down the peer
 *                               connectivity.
 */
int
bgp_interface_bfd_dest_down (int command, struct zclient *zclient,
                             zebra_size_t length)
{
  struct interface *ifp;
  struct prefix dp;
  struct prefix sp;

  ifp = zebra_interface_bfd_read (zclient->ibuf, &dp, &sp);

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
          if (!CHECK_FLAG (peer->flags, PEER_FLAG_BFD))
            continue;

          if (dp.family == AF_INET)
            if (dp.u.prefix4.s_addr != peer->su.sin.sin_addr.s_addr)
              continue;
#ifdef HAVE_IPV6
          else if (dp.family == AF_INET6)
            if (!memcmp(&dp.u.prefix6, &peer->su.sin6.sin6_addr,
                        sizeof (struct in6_addr)))
              continue;
#endif
          else
            continue;

          if (ifp && (ifp == peer->nexthop.ifp))
              BGP_EVENT_ADD (peer, BGP_Stop);
          else
            {
              if (!peer->su_local)
                continue;

              if (sp.family == AF_INET)
                if (sp.u.prefix4.s_addr != peer->su_local->sin.sin_addr.s_addr)
                  continue;
#ifdef HAVE_IPV6
              else if (sp.family == AF_INET6)
                if (!memcmp(&sp.u.prefix6, &peer->su_local->sin6.sin6_addr,
                            sizeof (struct in6_addr)))
                  continue;
#endif
              else
                continue;
              BGP_EVENT_ADD (peer, BGP_Stop);
            }
        }
  }

  return 0;
}

/*
 * bgp_bfd_peer_param_set - Set the configured BFD paramter values for peer.
 */
int
bgp_bfd_peer_param_set (struct peer *peer, u_int32_t min_rx, u_int32_t min_tx,
                         u_int8_t detect_mult, int reg_peer, int defaults)
{
  struct peer_group *group;
  struct listnode *node, *nnode;
  int change = 0;
  struct bgp_bfd_peer_info *bfd_info;

  bfd_info = (struct bgp_bfd_peer_info *)peer->bfd_info;

  if ((bfd_info->required_min_rx != min_rx) ||
      (bfd_info->desired_min_tx != min_tx) ||
      (bfd_info->detect_mult != detect_mult))
    change = 1;

  bfd_info->required_min_rx = min_rx;
  bfd_info->desired_min_tx = min_tx;
  bfd_info->detect_mult = detect_mult;

  if (!defaults)
    SET_FLAG (bfd_info->flags, BGP_BFD_FLAG_PARAM_CFG);
  else
    UNSET_FLAG (bfd_info->flags, BGP_BFD_FLAG_PARAM_CFG);

  if (CHECK_FLAG (peer->sflags, PEER_STATUS_GROUP))
    {
      group = peer->group;
      for (ALL_LIST_ELEMENTS (group->peer, node, nnode, peer))
        {
          bfd_info = (struct bgp_bfd_peer_info *)peer->bfd_info;
          bfd_info->required_min_rx = min_rx;
          bfd_info->desired_min_tx = min_tx;
          bfd_info->detect_mult = detect_mult;
          SET_FLAG (bfd_info->flags, BGP_BFD_FLAG_PARAM_CFG);

          if (reg_peer && (peer->status == Established))
            bgp_bfd_register_peer(peer);
          else if (change)
            bgp_bfd_update_peer(peer);
        }
    }
   else
    {
      if (reg_peer && (peer->status == Established))
        bgp_bfd_register_peer(peer);
      else if (change)
        bgp_bfd_update_peer(peer);
    }
  return 0;
}

/*
 * bgp_bfd_peer_param_unset - Unset the configured BFD paramter values for peer.
 */
int
bgp_bfd_peer_param_unset (struct peer *peer)
{
  struct peer_group *group;
  struct listnode *node, *nnode;
  struct bgp_bfd_peer_info *bfd_info;

  bfd_info = (struct bgp_bfd_peer_info *)peer->bfd_info;

  bfd_info->required_min_rx = BGP_BFD_DEF_MIN_RX;
  bfd_info->desired_min_tx = BGP_BFD_DEF_MIN_TX;
  bfd_info->detect_mult = BGP_BFD_DEF_DETECT_MULT;
  UNSET_FLAG (bfd_info->flags, BGP_BFD_FLAG_PARAM_CFG);

  if (CHECK_FLAG (peer->sflags, PEER_STATUS_GROUP))
    {
      group = peer->group;
      for (ALL_LIST_ELEMENTS (group->peer, node, nnode, peer))
        {
          bfd_info->required_min_rx = BGP_BFD_DEF_MIN_RX;
          bfd_info->desired_min_tx = BGP_BFD_DEF_MIN_TX;
          bfd_info->detect_mult = BGP_BFD_DEF_DETECT_MULT;
          UNSET_FLAG (bfd_info->flags, BGP_BFD_FLAG_PARAM_CFG);

          bgp_bfd_deregister_peer(peer);
        }
    }
  else
    bgp_bfd_deregister_peer(peer);
  return 0;
}

/*
 * bgp_bfd_peer_config_write - Write the peer BFD configuration.
 */
void
bgp_bfd_peer_config_write(struct vty *vty, struct peer *peer, char *addr)
{
  struct bgp_bfd_peer_info *bfd_info;

  bfd_info = (struct bgp_bfd_peer_info *)peer->bfd_info;

  if (CHECK_FLAG (bfd_info->flags, BGP_BFD_FLAG_PARAM_CFG))
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
bgp_bfd_show_info(struct vty *vty, struct peer *peer)
{
  struct bgp_bfd_peer_info *bfd_info;

  bfd_info = (struct bgp_bfd_peer_info *)peer->bfd_info;

  if (CHECK_FLAG(peer->flags, PEER_FLAG_BFD))
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
  int reg_peer = 0;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (! peer)
    return CMD_WARNING;

  if ( !CHECK_FLAG (peer->flags, PEER_FLAG_BFD) )
    {
      ret = peer_flag_set (peer, PEER_FLAG_BFD);
      if (ret != 0)
        return bgp_vty_return (vty, ret);

      reg_peer = 1;
    }

  ret = bgp_bfd_peer_param_set (peer, BGP_BFD_DEF_MIN_RX, BGP_BFD_DEF_MIN_TX,
                                  BGP_BFD_DEF_DETECT_MULT, reg_peer, 1);
  if (ret != 0)
    return bgp_vty_return (vty, ret);

  return CMD_SUCCESS;

}

DEFUN (neighbor_bfd_param,
       neighbor_bfd_param_cmd,
       NEIGHBOR_CMD2 "bfd <2-255> <50-60000> <50-60000>",
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
  int reg_peer = 0;

  peer = peer_and_group_lookup_vty (vty, argv[0]);
  if (!peer)
    return CMD_WARNING;

  if (!CHECK_FLAG (peer->flags, PEER_FLAG_BFD))
    {
      ret = peer_flag_set (peer, PEER_FLAG_BFD);
      if (ret != 0)
        return bgp_vty_return (vty, ret);

      reg_peer = 1;
    }

  VTY_GET_INTEGER_RANGE ("detect-mul", dm_val, argv[1], 2, 255);
  VTY_GET_INTEGER_RANGE ("min-rx", rx_val, argv[2], 50, 60000);
  VTY_GET_INTEGER_RANGE ("min-tx", tx_val, argv[3], 50, 60000);

  ret = bgp_bfd_peer_param_set (peer, rx_val, tx_val, dm_val, reg_peer, 0);
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

  /* Do nothing if there is no change in the flag */
  if ( !CHECK_FLAG (peer->flags, PEER_FLAG_BFD) )
    return CMD_SUCCESS;

  ret = bgp_bfd_peer_param_unset(peer);
  if (ret != 0)
    return bgp_vty_return (vty, ret);

  ret = peer_flag_unset (peer, PEER_FLAG_BFD);
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
