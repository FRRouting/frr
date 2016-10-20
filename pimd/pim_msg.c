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
#include "pim_rp.h"

void pim_msg_build_header(uint8_t *pim_msg, int pim_msg_size,
			  uint8_t pim_msg_type)
{
  uint16_t checksum;

  zassert(pim_msg_size >= PIM_PIM_MIN_LEN);

  /*
   * Write header
   */

  *(uint8_t *) PIM_MSG_HDR_OFFSET_VERSION(pim_msg) = (PIM_PROTO_VERSION << 4) | pim_msg_type;
  *(uint8_t *) PIM_MSG_HDR_OFFSET_RESERVED(pim_msg) = 0;

  /*
   * Compute checksum
   */

  *(uint16_t *) PIM_MSG_HDR_OFFSET_CHECKSUM(pim_msg) = 0;
  checksum = in_cksum(pim_msg, pim_msg_size);
  *(uint16_t *) PIM_MSG_HDR_OFFSET_CHECKSUM(pim_msg) = checksum;
}

uint8_t *pim_msg_addr_encode_ipv4_ucast(uint8_t *buf,
					int buf_size,
					struct in_addr addr)
{
  const int ENCODED_IPV4_UCAST_SIZE = 6;

  if (buf_size < ENCODED_IPV4_UCAST_SIZE) {
    return 0;
  }

  buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV4; /* addr family */
  buf[1] = '\0';    /* native encoding */
  memcpy(buf+2, &addr, sizeof(struct in_addr));

  return buf + ENCODED_IPV4_UCAST_SIZE;
}

uint8_t *pim_msg_addr_encode_ipv4_group(uint8_t *buf,
					int buf_size,
					struct in_addr addr)
{
  const int ENCODED_IPV4_GROUP_SIZE = 8;

  if (buf_size < ENCODED_IPV4_GROUP_SIZE) {
    return 0;
  }

  buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV4; /* addr family */
  buf[1] = '\0';    /* native encoding */
  buf[2] = '\0';    /* reserved */
  buf[3] = 32;      /* mask len */
  memcpy(buf+4, &addr, sizeof(struct in_addr));

  return buf + ENCODED_IPV4_GROUP_SIZE;
}

uint8_t *
pim_msg_addr_encode_ipv4_source(uint8_t *buf, int buf_size,
				struct in_addr addr, uint8_t bits)
{
  const int ENCODED_IPV4_SOURCE_SIZE = 8;

  if (buf_size < ENCODED_IPV4_SOURCE_SIZE) {
    return 0;
  }

  buf[0] = PIM_MSG_ADDRESS_FAMILY_IPV4; /* addr family */
  buf[1] = '\0';    /* native encoding */
  buf[2] = bits;
  buf[3] = 32;      /* mask len */
  memcpy(buf+4, &addr, sizeof(struct in_addr));

  return buf + ENCODED_IPV4_SOURCE_SIZE;
}

int
pim_msg_join_prune_encode (uint8_t *buf, int buf_size, int is_join,
			   struct in_addr source, struct in_addr group,
			   struct in_addr upstream, int holdtime)
{
  uint8_t *pim_msg = buf;
  uint8_t *pim_msg_curr = buf + PIM_MSG_HEADER_LEN;
  uint8_t *end = buf + buf_size;
  struct in_addr stosend;
  uint8_t bits;
  int remain;

  remain = end - pim_msg_curr;
  pim_msg_curr = pim_msg_addr_encode_ipv4_ucast (pim_msg_curr, buf_size - PIM_MSG_HEADER_LEN, upstream);
  if (!pim_msg_curr) {
    char dst_str[INET_ADDRSTRLEN];
    pim_inet4_dump("<dst?>", upstream, dst_str, sizeof(dst_str));
    zlog_warn("%s: failure encoding destination address %s: space left=%d",
	      __PRETTY_FUNCTION__, dst_str, remain);
    return -3;
  }

  remain = end - pim_msg_curr;
  if (remain < 4) {
    zlog_warn("%s: group will not fit: space left=%d",
	    __PRETTY_FUNCTION__, remain);
    return -4;
  }

  *pim_msg_curr = 0; /* reserved */
  ++pim_msg_curr;
  *pim_msg_curr = 1; /* number of groups */
  ++pim_msg_curr;

  *((uint16_t *) pim_msg_curr) = htons(holdtime);
  ++pim_msg_curr;
  ++pim_msg_curr;

  remain = end - pim_msg_curr;
  pim_msg_curr = pim_msg_addr_encode_ipv4_group (pim_msg_curr, remain,
						  group);
  if (!pim_msg_curr) {
    char group_str[INET_ADDRSTRLEN];
    pim_inet4_dump("<grp?>", group, group_str, sizeof(group_str));
    zlog_warn("%s: failure encoding group address %s: space left=%d",
	      __PRETTY_FUNCTION__, group_str, remain);
    return -5;
  }

  remain = end - pim_msg_curr;
  if (remain < 4) {
    zlog_warn("%s: sources will not fit: space left=%d",
	      __PRETTY_FUNCTION__, remain);
    return -6;
  }

  /* number of joined sources */
  *((uint16_t *) pim_msg_curr) = htons(is_join ? 1 : 0);
  ++pim_msg_curr;
  ++pim_msg_curr;

  /* number of pruned sources */
  *((uint16_t *) pim_msg_curr) = htons(is_join ? 0 : 1);
  ++pim_msg_curr;
  ++pim_msg_curr;

  remain = end - pim_msg_curr;
  if (source.s_addr == INADDR_ANY)
    {
      struct pim_rpf *rpf = pim_rp_g (group);
      bits = PIM_ENCODE_SPARSE_BIT | PIM_ENCODE_WC_BIT | PIM_ENCODE_RPT_BIT;
      stosend = rpf->rpf_addr.u.prefix4;
    }
  else
    {
      bits = PIM_ENCODE_SPARSE_BIT;
      stosend = source;
    }
  pim_msg_curr = pim_msg_addr_encode_ipv4_source (pim_msg_curr, remain, stosend, bits);
  if (!pim_msg_curr) {
    char source_str[INET_ADDRSTRLEN];
    pim_inet4_dump("<src?>", source, source_str, sizeof(source_str));
    zlog_warn("%s: failure encoding source address %s: space left=%d",
	      __PRETTY_FUNCTION__, source_str, remain);
    return -7;
  }

  remain = pim_msg_curr - pim_msg;
  pim_msg_build_header (pim_msg, remain, PIM_MSG_TYPE_JOIN_PRUNE);

  return remain;
}
