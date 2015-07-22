/**
 * bfd.c: BFD handling routines
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
#include "memory.h"
#include "prefix.h"
#include "thread.h"
#include "stream.h"
#include "zclient.h"
#include "table.h"
#include "vty.h"
#include "bfd.h"

/*
 * bfd_info_create - Allocate the BFD information
 */
struct bfd_info *
bfd_info_create(void)
{
  struct bfd_info *bfd_info;

  bfd_info = XCALLOC (MTYPE_BFD_INFO, sizeof (struct bfd_info));
  assert(bfd_info);

  return bfd_info;
}

/*
 * bfd_info_free - Free the BFD information.
 */
void
bfd_info_free(void **bfd_info)
{
  if (*bfd_info)
    {
      XFREE (MTYPE_BFD_INFO, *bfd_info);
      *bfd_info = NULL;
    }
}

/*
 * bfd_validate_param - Validate the BFD paramter information.
 */
int
bfd_validate_param(struct vty *vty, const char *dm_str, const char *rx_str,
                    const char *tx_str, u_int8_t *dm_val, u_int32_t *rx_val,
                    u_int32_t *tx_val)
{
  VTY_GET_INTEGER_RANGE ("detect-mul", *dm_val, dm_str,
                         BFD_MIN_DETECT_MULT, BFD_MAX_DETECT_MULT);
  VTY_GET_INTEGER_RANGE ("min-rx", *rx_val, rx_str,
                         BFD_MIN_MIN_RX, BFD_MAX_MIN_RX);
  VTY_GET_INTEGER_RANGE ("min-tx", *tx_val, tx_str,
                         BFD_MIN_MIN_TX, BFD_MAX_MIN_TX);
  return CMD_SUCCESS;
}

/*
 * bfd_set_param - Set the configured BFD paramter values
 */
void
bfd_set_param (struct bfd_info **bfd_info, u_int32_t min_rx, u_int32_t min_tx,
               u_int8_t detect_mult, int defaults, int *command)
{
  if (!*bfd_info)
    {
      *bfd_info = bfd_info_create();
      *command = ZEBRA_BFD_DEST_REGISTER;
    }
  else
    {
      if (((*bfd_info)->required_min_rx != min_rx) ||
          ((*bfd_info)->desired_min_tx != min_tx) ||
          ((*bfd_info)->detect_mult != detect_mult))
        *command = ZEBRA_BFD_DEST_UPDATE;
    }

  if (*command)
    {
      (*bfd_info)->required_min_rx = min_rx;
      (*bfd_info)->desired_min_tx = min_tx;
      (*bfd_info)->detect_mult = detect_mult;
    }

  if (!defaults)
    SET_FLAG ((*bfd_info)->flags, BFD_FLAG_PARAM_CFG);
  else
    UNSET_FLAG ((*bfd_info)->flags, BFD_FLAG_PARAM_CFG);
}

/*
 * bfd_peer_sendmsg - Format and send a peer register/Unregister
 *                    command to Zebra to be forwarded to BFD
 */
void
bfd_peer_sendmsg (struct zclient *zclient, struct bfd_info *bfd_info,
                  int family, void *dst_ip, void *src_ip, char *if_name,
                  int ttl, int multihop, int command, int set_flag)
{
  struct stream *s;
  int ret;
  int len;

  /* Check socket. */
  if (!zclient || zclient->sock < 0)
    {
      zlog_debug("%s: Can't send BFD peer register, Zebra client not "
                  "established", __FUNCTION__);
      return;
    }

  s = zclient->obuf;
  stream_reset (s);
  zclient_create_header (s, command);

  stream_putw(s, family);
  switch (family)
    {
    case AF_INET:
      stream_put_in_addr (s, (struct in_addr *)dst_ip);
      break;
#ifdef HAVE_IPV6
    case AF_INET6:
      stream_put(s, dst_ip, 16);
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

  if (multihop)
    {
      stream_putc(s, 1);
      /* Multi-hop destination send the source IP address to BFD */
      if (src_ip)
        {
          stream_putw(s, family);
          switch (family)
            {
            case AF_INET:
              stream_put_in_addr (s, (struct in_addr *) src_ip);
              break;
        #ifdef HAVE_IPV6
            case AF_INET6:
              stream_put(s, src_ip, 16);
              break;
        #endif
            default:
              break;
            }
        }
      stream_putc(s, ttl);
    }
  else
    {
      stream_putc(s, 0);
#ifdef HAVE_IPV6
      if ((family == AF_INET6) && (src_ip))
        {
          stream_putw(s, family);
          stream_put(s, src_ip, 16);
        }
#endif
      if (if_name)
        {
          len = strlen(if_name);
          stream_putc(s, len);
          stream_put(s, if_name, len);
        }
      else
        {
          stream_putc(s, 0);
        }
    }

  stream_putw_at (s, 0, stream_get_endp (s));

  ret = zclient_send_message(zclient);

  if (ret < 0)
    {
      zlog_warn("bfd_peer_sendmsg: zclient_send_message() failed");
      return;
    }

  if (set_flag)
    {
      if (command == ZEBRA_BFD_DEST_REGISTER)
        SET_FLAG(bfd_info->flags, BFD_FLAG_BFD_REG);
      else if (command == ZEBRA_BFD_DEST_DEREGISTER)
        UNSET_FLAG(bfd_info->flags, BFD_FLAG_BFD_REG);
    }

  return;
}

/*
 * bfd_get_command_dbg_str - Convert command to a debug string.
 */
const char *
bfd_get_command_dbg_str(int command)
{
  switch (command)
  {
    case ZEBRA_BFD_DEST_REGISTER:
      return "Register";
    case ZEBRA_BFD_DEST_DEREGISTER:
      return "Deregister";
    case ZEBRA_BFD_DEST_UPDATE:
      return "Update";
    default:
      return "Unknown";
  }
}

/*
 * bfd_get_peer_info - Extract the Peer information for which the BFD session
 *                     went down from the message sent from Zebra to clients.
 */
struct interface *
bfd_get_peer_info (struct stream *s, struct prefix *dp, struct prefix *sp)
{
  unsigned int ifindex;
  struct interface *ifp = NULL;
  int plen;

  /* Get interface index. */
  ifindex = stream_getl (s);

  /* Lookup index. */
  if (ifindex != 0)
    {
      ifp = if_lookup_by_index (ifindex);
      if (ifp == NULL)
        {
          zlog_warn ("zebra_interface_bfd_read: "
                     "Can't find interface by ifindex: %d ", ifindex);
          return NULL;
        }
    }

  /* Fetch destination address. */
  dp->family = stream_getc (s);

  plen = prefix_blen (dp);
  stream_get (&dp->u.prefix, s, plen);
  dp->prefixlen = stream_getc (s);

  if (sp)
    {
      sp->family = stream_getc (s);

      plen = prefix_blen (sp);
      stream_get (&sp->u.prefix, s, plen);
      sp->prefixlen = stream_getc (s);
    }
  return ifp;
}
