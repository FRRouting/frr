/*
  PIM for Quagga
  Copyright (C) 2008  Everton da Silva Marques

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program; see the file COPYING; if not, write to the
  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
  MA 02110-1301 USA
*/

#include <zebra.h>

#include "if.h"
#include "log.h"
#include "prefix.h"
#include "vty.h"
#include "plist.h"

#include "pimd.h"
#include "pim_vty.h"
#include "pim_pim.h"
#include "pim_msg.h"
#include "pim_util.h"
#include "pim_str.h"
#include "pim_iface.h"
#include "pim_rp.h"
#include "pim_rpf.h"
#include "pim_register.h"

void pim_msg_build_header(uint8_t *pim_msg, size_t pim_msg_size, uint8_t pim_msg_type)
{
  struct pim_msg_header *header = (struct pim_msg_header *)pim_msg;

  /*
   * Write header
   */
  header->ver = PIM_PROTO_VERSION;
  header->type = pim_msg_type;
  header->reserved = 0;


  header->checksum = 0;
  /*
   * The checksum for Registers is done only on the first 8 bytes of the packet,
   * including the PIM header and the next 4 bytes, excluding the data packet portion
   */
  if (pim_msg_type == PIM_MSG_TYPE_REGISTER)
    header->checksum = in_cksum (pim_msg, PIM_MSG_REGISTER_LEN);
  else
    header->checksum = in_cksum (pim_msg, pim_msg_size);
}

uint8_t *pim_msg_addr_encode_ipv4_ucast(uint8_t *buf, struct in_addr addr)
{
  buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV4; /* addr family */
  buf[1] = '\0';    /* native encoding */
  memcpy(buf+2, &addr, sizeof(struct in_addr));

  return buf + PIM_ENCODED_IPV4_UCAST_SIZE;
}

uint8_t *pim_msg_addr_encode_ipv4_group(uint8_t *buf, struct in_addr addr)
{
  buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV4; /* addr family */
  buf[1] = '\0';    /* native encoding */
  buf[2] = '\0';    /* reserved */
  buf[3] = 32;      /* mask len */
  memcpy(buf+4, &addr, sizeof(struct in_addr));

  return buf + PIM_ENCODED_IPV4_GROUP_SIZE;
}

uint8_t *
pim_msg_addr_encode_ipv4_source(uint8_t *buf,
                                struct in_addr addr, uint8_t bits)
{
  buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV4; /* addr family */
  buf[1] = '\0';    /* native encoding */
  buf[2] = bits;
  buf[3] = 32;      /* mask len */
  memcpy(buf+4, &addr, sizeof(struct in_addr));

  return buf + PIM_ENCODED_IPV4_SOURCE_SIZE;
}

/*
 * J/P Message Format
 *
 * While the RFC clearly states that this is 32 bits wide, it
 * is cheating.  These fields:
 * Encoded-Unicast format   (6 bytes MIN)
 * Encoded-Group format     (8 bytes MIN)
 * Encoded-Source format    (8 bytes MIN)
 * are *not* 32 bits wide.
 *
 * Nor does the RFC explicitly call out the size for:
 * Reserved                 (1 byte)
 * Num Groups               (1 byte)
 * Holdtime                 (2 bytes)
 * Number of Joined Sources (2 bytes)
 * Number of Pruned Sources (2 bytes)
 *
 * This leads to a missleading representation from casual
 * reading and making assumptions.  Be careful!
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |PIM Ver| Type  |   Reserved    |           Checksum            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Upstream Neighbor Address (Encoded-Unicast format)     |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Reserved     | Num groups    |          Holdtime             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Multicast Group Address 1 (Encoded-Group format)      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Number of Joined Sources    |   Number of Pruned Sources    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Joined Source Address 1 (Encoded-Source format)        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                             .                                 |
 *  |                             .                                 |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Joined Source Address n (Encoded-Source format)        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Pruned Source Address 1 (Encoded-Source format)        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                             .                                 |
 *  |                             .                                 |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Pruned Source Address n (Encoded-Source format)        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |         Multicast Group Address m (Encoded-Group format)      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |   Number of Joined Sources    |   Number of Pruned Sources    |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Joined Source Address 1 (Encoded-Source format)        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                             .                                 |
 *  |                             .                                 |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Joined Source Address n (Encoded-Source format)        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Pruned Source Address 1 (Encoded-Source format)        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                             .                                 |
 *  |                             .                                 |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |        Pruned Source Address n (Encoded-Source format)        |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
int
pim_msg_join_prune_encode (uint8_t *buf, size_t buf_size, int is_join,
                           struct pim_upstream *up,
                           struct in_addr upstream, int holdtime)
{
  struct pim_jp *msg = (struct pim_jp *)buf;
  struct in_addr stosend;
  uint8_t bits;

  assert(buf_size > sizeof (struct pim_jp));

  if (!pim_msg_addr_encode_ipv4_ucast ((uint8_t *)&msg->addr, upstream)) {
    char dst_str[INET_ADDRSTRLEN];
    pim_inet4_dump("<dst?>", upstream, dst_str, sizeof(dst_str));
    zlog_warn("%s: failure encoding destination address %s",
	      __PRETTY_FUNCTION__, dst_str);
    return -3;
  }

  msg->reserved   = 0;
  msg->num_groups = 1;
  msg->holdtime   = htons(holdtime);

  if (!pim_msg_addr_encode_ipv4_group ((uint8_t *)&msg->groups[0].g, up->sg.grp)) {
    char group_str[INET_ADDRSTRLEN];
    pim_inet4_dump("<grp?>", up->sg.grp, group_str, sizeof(group_str));
    zlog_warn("%s: failure encoding group address %s",
              __PRETTY_FUNCTION__, group_str);
    return -5;
  }

  /* number of joined/pruned sources */
  msg->groups[0].joins  = htons(is_join ? 1 : 0);
  msg->groups[0].prunes = htons(is_join ? 0 : 1);

  if (up->sg.src.s_addr == INADDR_ANY)
    {
      struct pim_rpf *rpf = pim_rp_g (up->sg.grp);
      bits = PIM_ENCODE_SPARSE_BIT | PIM_ENCODE_WC_BIT | PIM_ENCODE_RPT_BIT;
      stosend = rpf->rpf_addr.u.prefix4;
    }
  else
    {
      bits = PIM_ENCODE_SPARSE_BIT;
      stosend = up->sg.src;
    }

  if (!pim_msg_addr_encode_ipv4_source ((uint8_t *)&msg->groups[0].s[0], stosend, bits)) {
    char source_str[INET_ADDRSTRLEN];
    pim_inet4_dump("<src?>", up->sg.src, source_str, sizeof(source_str));
    zlog_warn("%s: failure encoding source address %s",
              __PRETTY_FUNCTION__, source_str);
    return -7;
  }

  /*
   * This is not implemented correctly at this point in time
   * Make it stop.
   */
#if 0
  if (up->sg.src.s_addr == INADDR_ANY)
    {
      struct pim_upstream *child;
      struct listnode *up_node;
      int send_prune = 0;

      zlog_debug ("%s: Considering (%s) children for (S,G,rpt) prune",
                  __PRETTY_FUNCTION__, up->sg_str);
      for (ALL_LIST_ELEMENTS_RO (up->sources, up_node, child))
        {
          if (child->sptbit == PIM_UPSTREAM_SPTBIT_TRUE)
            {
              if (!pim_rpf_is_same(&up->rpf, &child->rpf))
                {
                  send_prune = 1;
                  if (PIM_DEBUG_PIM_PACKETS)
                    zlog_debug ("%s: SPT Bit and RPF'(%s) != RPF'(S,G): Add Prune (%s,rpt) to compound message",
                                __PRETTY_FUNCTION__, up->sg_str, child->sg_str);
                }
              else
                if (PIM_DEBUG_PIM_PACKETS)
                  zlog_debug ("%s: SPT Bit and RPF'(%s) == RPF'(S,G): Not adding Prune for (%s,rpt)",
                              __PRETTY_FUNCTION__, up->sg_str, child->sg_str);
            }
          else if (pim_upstream_is_sg_rpt (child))
            {
              if (pim_upstream_empty_inherited_olist (child))
                {
                  send_prune = 1;
                  if (PIM_DEBUG_PIM_PACKETS)
                    zlog_debug ("%s: inherited_olist(%s,rpt) is NULL, Add Prune to compound message",
                                __PRETTY_FUNCTION__, child->sg_str);
                }
              else if (!pim_rpf_is_same (&up->rpf, &child->rpf))
                {
                  send_prune = 1;
                  if (PIM_DEBUG_PIM_PACKETS)
                    zlog_debug ("%s: RPF'(%s) != RPF'(%s,rpt), Add Prune to compound message",
                                __PRETTY_FUNCTION__, up->sg_str, child->sg_str);
                }
              else
                if (PIM_DEBUG_PIM_PACKETS)
                  zlog_debug ("%s: RPF'(%s) == RPF'(%s,rpt), Do not add Prune to compound message",
                              __PRETTY_FUNCTION__, up->sg_str, child->sg_str);
            }
          else
            if (PIM_DEBUG_PIM_PACKETS)
              zlog_debug ("%s: SPT bit is not set for (%s)",
                          __PRETTY_FUNCTION__, child->sg_str);
          if (send_prune)
            {
              pim_msg_curr = pim_msg_addr_encode_ipv4_source (pim_msg_curr, remain,
                                                              child->sg.src,
                                                              PIM_ENCODE_SPARSE_BIT | PIM_ENCODE_RPT_BIT);
              remain = pim_msg_curr - pim_msg;
              *prunes = htons(ntohs(*prunes) + 1);
              send_prune = 0;
            }
        }
    }
#endif
  pim_msg_build_header (buf, sizeof (struct pim_jp), PIM_MSG_TYPE_JOIN_PRUNE);

  return sizeof (struct pim_jp);
}
