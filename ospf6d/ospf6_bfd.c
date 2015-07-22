/**
 * ospf6_bfd.c: IPv6 OSPF BFD handling routines
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
#include "table.h"
#include "bfd.h"
#include "if.h"
#include "ospf6d.h"
#include "ospf6_message.h"
#include "ospf6_neighbor.h"
#include "ospf6_interface.h"
#include "ospf6_route.h"
#include "ospf6_zebra.h"
#include "ospf6_bfd.h"

extern struct zclient *zclient;

/*
 * ospf6_bfd_reg_dereg_nbr - Register/Deregister a neighbor with BFD through
 *                           zebra for starting/stopping the monitoring of
 *                           the neighbor rechahability.
 */
static void
ospf6_bfd_reg_dereg_nbr (struct ospf6_neighbor *on, int command)
{
  struct ospf6_interface *oi = on->ospf6_if;
  struct interface *ifp = oi->interface;
  struct bfd_info *bfd_info;
  char src[64];

  if (!oi->bfd_info)
    return;
  bfd_info = (struct bfd_info *)oi->bfd_info;

  if (IS_OSPF6_DEBUG_ZEBRA(SEND))
    {
      inet_ntop (AF_INET6, &on->linklocal_addr, src, sizeof (src));
      zlog_debug ("%s nbr (%s) with BFD",
                    bfd_get_command_dbg_str(command), src);
    }

  bfd_peer_sendmsg (zclient, bfd_info, AF_INET6, &on->linklocal_addr,
                    on->ospf6_if->linklocal_addr, ifp->name,
                    0, 0, command, 0);
}

/*
 * ospf6_bfd_trigger_event - Neighbor is registered/deregistered with BFD when
 *                           neighbor state is changed to/from 2way.
 */
void
ospf6_bfd_trigger_event(struct ospf6_neighbor *on, int old_state, int state)
{
  if ((old_state < OSPF6_NEIGHBOR_TWOWAY) && (state >= OSPF6_NEIGHBOR_TWOWAY))
    ospf6_bfd_reg_dereg_nbr(on, ZEBRA_BFD_DEST_REGISTER);
  else if ((old_state >= OSPF6_NEIGHBOR_TWOWAY) &&
            (state < OSPF6_NEIGHBOR_TWOWAY))
    ospf6_bfd_reg_dereg_nbr(on, ZEBRA_BFD_DEST_DEREGISTER);
}

/*
 * ospf6_bfd_reg_dereg_all_nbr - Register/Deregister all neighbors associated
 *                               with a interface with BFD through
 *                               zebra for starting/stopping the monitoring of
 *                               the neighbor rechahability.
 */
static void
ospf6_bfd_reg_dereg_all_nbr (struct ospf6_interface *oi, int command)
{
  struct ospf6_neighbor *on;
  struct listnode *node;

  for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, node, on))
    {
      if (on->state < OSPF6_NEIGHBOR_TWOWAY)
        continue;

      ospf6_bfd_reg_dereg_nbr(on, command);
    }
}

/*
 * ospf6_bfd_nbr_replay - Replay all the neighbors that have BFD enabled
 *                        to zebra
 */
static int
ospf6_bfd_nbr_replay (int command, struct zclient *client, zebra_size_t length)
{
  struct listnode *inode, *nnode;
  struct interface *ifp;
  struct ospf6_interface *oi;
  struct ospf6_neighbor *on;
  char dst[64];

  if (IS_OSPF6_DEBUG_ZEBRA(RECV))
    zlog_debug("Zebra: BFD Dest replay request");

  /* Replay the neighbor, if BFD is enabled on the interface*/
  for (ALL_LIST_ELEMENTS_RO (iflist, inode, ifp))
    {
      oi = (struct ospf6_interface *) ifp->info;

      if (!oi || !oi->bfd_info)
        continue;

      for (ALL_LIST_ELEMENTS_RO (oi->neighbor_list, nnode, on))
        {
          if (on->state < OSPF6_NEIGHBOR_TWOWAY)
            continue;

          if (IS_OSPF6_DEBUG_ZEBRA(SEND))
            {
              inet_ntop (AF_INET6, &on->linklocal_addr, dst, sizeof (dst));
              zlog_debug ("Replaying nbr (%s) to BFD", dst);
            }

          ospf6_bfd_reg_dereg_nbr(on, ZEBRA_BFD_DEST_UPDATE);
        }
    }
  return 0;
}

/*
 * ospf6_bfd_interface_dest_down - Find the neighbor for which the BFD status
 *                                 has changed and bring down the neighbor
 *                                 connectivity.
 */
static int
ospf6_bfd_interface_dest_down (int command, struct zclient *zclient,
                              zebra_size_t length)
{
  struct interface *ifp;
  struct ospf6_interface *oi;
  struct ospf6_neighbor *on;
  struct prefix dp;
  struct prefix sp;
  struct listnode *node, *nnode;
  char dst[64];

  ifp = bfd_get_peer_info(zclient->ibuf, &dp, &sp);

  if ((ifp == NULL) || (dp.family != AF_INET6))
    return 0;

  if (IS_OSPF6_DEBUG_ZEBRA (RECV))
    {
      char buf[128];
      prefix2str(&dp, buf, sizeof(buf));
      zlog_debug("Zebra: interface %s bfd destination %s down", ifp->name, buf);
    }


  oi = (struct ospf6_interface *) ifp->info;
  if (!oi || !oi->bfd_info)
    return 0;

  for (ALL_LIST_ELEMENTS (oi->neighbor_list, node, nnode, on))
    {
      if (memcmp(&(on->linklocal_addr), &dp.u.prefix6, sizeof(struct in6_addr)))
        continue;

      if (IS_OSPF6_DEBUG_NEIGHBOR (EVENT))
        {
          inet_ntop (AF_INET6, &on->linklocal_addr, dst, sizeof (dst));
          zlog_debug ("[%s:%s]: BFD Down", ifp->name, dst);
        }

      THREAD_OFF (on->inactivity_timer);
      thread_add_event (master, inactivity_timer, on, 0);
    }

  return 0;
}

/*
 * ospf6_bfd_write_config - Write the interface BFD configuration.
 */
void
ospf6_bfd_write_config(struct vty *vty, struct ospf6_interface *oi)
{
  struct bfd_info *bfd_info;

  if (!oi->bfd_info)
    return;

  bfd_info = (struct bfd_info *)oi->bfd_info;

  if (CHECK_FLAG(bfd_info->flags, BFD_FLAG_PARAM_CFG))
    vty_out (vty, " ipv6 ospf6 bfd %d %d %d%s",
              bfd_info->detect_mult, bfd_info->required_min_rx,
              bfd_info->desired_min_tx, VTY_NEWLINE);
  else
    vty_out (vty, " ipv6 ospf6 bfd%s", VTY_NEWLINE);
}

/*
 * ospf6_bfd_if_param_set - Set the configured BFD paramter values for
 *                            interface.
 */
static void
ospf6_bfd_if_param_set (struct ospf6_interface *oi, u_int32_t min_rx,
                        u_int32_t min_tx, u_int8_t detect_mult,
                        int defaults)
{
  int command = 0;

  bfd_set_param((struct bfd_info **)&(oi->bfd_info), min_rx, min_tx, detect_mult,
                defaults, &command);
  if (command)
    ospf6_bfd_reg_dereg_all_nbr(oi, command);
}

DEFUN (ipv6_ospf6_bfd,
       ipv6_ospf6_bfd_cmd,
       "ipv6 ospf6 bfd",
       IP6_STR
       OSPF6_STR
       "Enables BFD support\n"
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  ospf6_bfd_if_param_set (oi, BFD_DEF_MIN_RX, BFD_DEF_MIN_TX,
                          BFD_DEF_DETECT_MULT, 1);
  return CMD_SUCCESS;
}

DEFUN (ipv6_ospf6_bfd_param,
       ipv6_ospf6_bfd_param_cmd,
       "ipv6 ospf6 bfd " BFD_CMD_DETECT_MULT_RANGE BFD_CMD_MIN_RX_RANGE BFD_CMD_MIN_TX_RANGE,
       IP6_STR
       OSPF6_STR
       "Enables BFD support\n"
       "Detect Multiplier\n"
       "Required min receive interval\n"
       "Desired min transmit interval\n")
{
  struct ospf6_interface *oi;
  struct interface *ifp;
  u_int32_t rx_val;
  u_int32_t tx_val;
  u_int8_t dm_val;
  int ret;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  if ((ret = bfd_validate_param (vty, argv[0], argv[1], argv[2], &dm_val,
                                 &rx_val, &tx_val)) != CMD_SUCCESS)
    return ret;

  ospf6_bfd_if_param_set (oi, rx_val, tx_val, dm_val, 0);

  return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_bfd,
       no_ipv6_ospf6_bfd_cmd,
       "no ipv6 ospf6 bfd",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Disables BFD support\n"
       )
{
  struct ospf6_interface *oi;
  struct interface *ifp;

  ifp = (struct interface *) vty->index;
  assert (ifp);

  oi = (struct ospf6_interface *) ifp->info;
  if (oi == NULL)
    oi = ospf6_interface_create (ifp);
  assert (oi);

  if (oi->bfd_info)
    {
      ospf6_bfd_reg_dereg_all_nbr(oi, ZEBRA_BFD_DEST_DEREGISTER);
      bfd_info_free(&(oi->bfd_info));
    }

  return CMD_SUCCESS;
}

void
ospf6_bfd_init(void)
{
  /* Initialize BFD client functions */
  zclient->interface_bfd_dest_down = ospf6_bfd_interface_dest_down;
  zclient->bfd_dest_replay = ospf6_bfd_nbr_replay;

  /* Install BFD command */
  install_element (INTERFACE_NODE, &ipv6_ospf6_bfd_cmd);
  install_element (INTERFACE_NODE, &ipv6_ospf6_bfd_param_cmd);
  install_element (INTERFACE_NODE, &no_ipv6_ospf6_bfd_cmd);
}
