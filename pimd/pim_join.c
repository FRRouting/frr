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

#include "log.h"
#include "prefix.h"
#include "if.h"

#include "pimd.h"
#include "pim_str.h"
#include "pim_tlv.h"
#include "pim_msg.h"
#include "pim_pim.h"
#include "pim_join.h"
#include "pim_oil.h"
#include "pim_iface.h"
#include "pim_hello.h"
#include "pim_ifchannel.h"
#include "pim_rpf.h"
#include "pim_rp.h"

static void
on_trace (const char *label,
	  struct interface *ifp, struct in_addr src)
{
  if (PIM_DEBUG_PIM_TRACE) {
    char src_str[100];
    pim_inet4_dump("<src?>", src, src_str, sizeof(src_str));
    zlog_debug("%s: from %s on %s",
	       label, src_str, ifp->name);
  }
}

static void recv_join(struct interface *ifp,
		      struct pim_neighbor *neigh,
		      uint16_t holdtime,
		      struct in_addr upstream,
		      struct in_addr group,
		      struct in_addr source,
		      uint8_t source_flags)
{
  struct prefix_sg sg;

  memset (&sg, 0, sizeof (struct prefix_sg));
  sg.src = source;
  sg.grp = group;

  if (PIM_DEBUG_PIM_TRACE) {
    char up_str[100];
    char neigh_str[100];
    pim_inet4_dump("<upstream?>", upstream, up_str, sizeof(up_str));
    pim_inet4_dump("<neigh?>", neigh->source_addr, neigh_str, sizeof(neigh_str));
    zlog_warn("%s: join (S,G)=%s rpt=%d wc=%d upstream=%s holdtime=%d from %s on %s",
	      __PRETTY_FUNCTION__,
	      pim_str_sg_dump (&sg),
	      source_flags & PIM_RPT_BIT_MASK,
	      source_flags & PIM_WILDCARD_BIT_MASK,
	      up_str, holdtime, neigh_str, ifp->name);
  }

  /*
   * If the RPT and WC are set it's a (*,G)
   * and the source is the RP
   */
  if ((source_flags & PIM_RPT_BIT_MASK) &&
      (source_flags & PIM_WILDCARD_BIT_MASK))
    {
      struct pim_rpf *rp = RP (sg.grp);

      /*
       * If the RP sent in the message is not
       * our RP for the group, drop the message
       */
      if (sg.src.s_addr != rp->rpf_addr.s_addr)
	return;

      sg.src.s_addr = INADDR_ANY;
    }

  /* Restart join expiry timer */
  pim_ifchannel_join_add(ifp, neigh->source_addr, upstream,
			 &sg, source_flags, holdtime);

  if (sg.src.s_addr == INADDR_ANY)
    {
      struct pim_upstream *up = pim_upstream_find (&sg);
      struct pim_upstream *child;
      struct listnode *up_node;

      for (ALL_LIST_ELEMENTS_RO (qpim_upstream_list, up_node, child))
        {
          if (child->parent == up)
            {
	      char buff[100];

	      strcpy (buff, pim_str_sg_dump (&up->sg));
	      zlog_debug("%s %s: Join(S,G)=%s from %s",
		         __FILE__, __PRETTY_FUNCTION__,
		         buff, pim_str_sg_dump (&sg));

              if (pim_upstream_evaluate_join_desired (child))
                {
                  pim_channel_add_oif (child->channel_oil, ifp, PIM_OIF_FLAG_PROTO_PIM);
                  pim_upstream_switch (child, PIM_UPSTREAM_JOINED);
                }
            }
        }
    }

}

static void recv_prune(struct interface *ifp,
		       struct pim_neighbor *neigh,
		       uint16_t holdtime,
		       struct in_addr upstream,
		       struct in_addr group,
		       struct in_addr source,
		       uint8_t source_flags)
{
  struct prefix_sg sg;

  memset (&sg, 0, sizeof (struct prefix_sg));
  sg.src = source;
  sg.grp = group;

  if (PIM_DEBUG_PIM_TRACE) {
    char up_str[100];
    char neigh_str[100];
    pim_inet4_dump("<upstream?>", upstream, up_str, sizeof(up_str));
    pim_inet4_dump("<neigh?>", neigh->source_addr, neigh_str, sizeof(neigh_str));
    zlog_warn("%s: prune (S,G)=%s rpt=%d wc=%d upstream=%s holdtime=%d from %s on %s",
	      __PRETTY_FUNCTION__,
	      pim_str_sg_dump (&sg),
	      source_flags & PIM_RPT_BIT_MASK,
	      source_flags & PIM_WILDCARD_BIT_MASK,
	      up_str, holdtime, neigh_str, ifp->name);
  }

  if ((source_flags & PIM_RPT_BIT_MASK) &&
      (source_flags & PIM_WILDCARD_BIT_MASK))
    {
      struct pim_rpf *rp = RP (sg.grp);

      // Ignoring Prune *,G's at the moment.
      if (sg.src.s_addr != rp->rpf_addr.s_addr)
	return;

      sg.src.s_addr = INADDR_ANY;
    }
  
  pim_ifchannel_prune(ifp, upstream, &sg, source_flags, holdtime);

  if (sg.src.s_addr == INADDR_ANY)
    {
      struct pim_upstream *up = pim_upstream_find (&sg);
      struct pim_upstream *child;
      struct listnode *up_node;

      for (ALL_LIST_ELEMENTS_RO (qpim_upstream_list, up_node, child))
        {
          if (child->parent == up)
            {
	      char buff[100];
	      strcpy (buff, pim_str_sg_dump (&up->sg));
	      zlog_debug("%s %s: Prune(S,G)=%s from %s",
		         __FILE__, __PRETTY_FUNCTION__,
		         buff, pim_str_sg_dump (&sg));

	      if (!pim_upstream_evaluate_join_desired (child))
	        pim_channel_del_oif (child->channel_oil, ifp, PIM_OIF_FLAG_PROTO_PIM);
	    }
        }
    }

}

int pim_joinprune_recv(struct interface *ifp,
		       struct pim_neighbor *neigh,
		       struct in_addr src_addr,
		       uint8_t *tlv_buf, int tlv_buf_size)
{
  struct prefix   msg_upstream_addr;
  uint8_t         msg_num_groups;
  uint16_t        msg_holdtime;
  int             addr_offset;
  uint8_t        *buf;
  uint8_t        *pastend;
  int             remain;
  int             group;

  on_trace(__PRETTY_FUNCTION__, ifp, src_addr);

  buf     = tlv_buf;
  pastend = tlv_buf + tlv_buf_size;

  /*
    Parse ucast addr
  */
  addr_offset = pim_parse_addr_ucast (&msg_upstream_addr,
				      buf, pastend - buf);
  if (addr_offset < 1) {
    char src_str[100];
    pim_inet4_dump("<src?>", src_addr, src_str, sizeof(src_str));
    zlog_warn("%s: pim_parse_addr_ucast() failure: from %s on %s",
	      __PRETTY_FUNCTION__,
	      src_str, ifp->name);
    return -1;
  }
  buf += addr_offset;

  /*
    Check upstream address family
   */
  if (msg_upstream_addr.family != AF_INET) {
    if (PIM_DEBUG_PIM_J_P) {
      char src_str[100];
      pim_inet4_dump("<src?>", src_addr, src_str, sizeof(src_str));
      zlog_warn("%s: ignoring join/prune directed to unexpected addr family=%d from %s on %s",
		__PRETTY_FUNCTION__,
		msg_upstream_addr.family, src_str, ifp->name);
    }
    return -2;
  }

  remain = pastend - buf;
  if (remain < 4) {
    char src_str[100];
    pim_inet4_dump("<src?>", src_addr, src_str, sizeof(src_str));
    zlog_warn("%s: short join/prune message buffer for group list: size=%d minimum=%d from %s on %s",
	      __PRETTY_FUNCTION__,
	      remain, 4, src_str, ifp->name);
    return -4;
  }

  ++buf; /* skip reserved byte */
  msg_num_groups = *(const uint8_t *) buf;
  ++buf;
  msg_holdtime = ntohs(*(const uint16_t *) buf);
  ++buf;
  ++buf;

  if (PIM_DEBUG_PIM_J_P) {
    char src_str[100];
    char upstream_str[100];
    pim_inet4_dump("<src?>", src_addr, src_str, sizeof(src_str));
    pim_inet4_dump("<addr?>", msg_upstream_addr.u.prefix4,
		   upstream_str, sizeof(upstream_str));
    zlog_debug ("%s: join/prune upstream=%s groups=%d holdtime=%d from %s on %s",
		__PRETTY_FUNCTION__,
		upstream_str, msg_num_groups, msg_holdtime,
		src_str, ifp->name);
  }

  /* Scan groups */
  for (group = 0; group < msg_num_groups; ++group) {
    struct prefix msg_group_addr;
    struct prefix msg_source_addr;
    uint8_t       msg_source_flags;
    uint16_t      msg_num_joined_sources;
    uint16_t      msg_num_pruned_sources;
    int           source;

    addr_offset = pim_parse_addr_group (&msg_group_addr,
					buf, pastend - buf);
    if (addr_offset < 1) {
      return -5;
    }
    buf += addr_offset;

    remain = pastend - buf;
    if (remain < 4) {
      char src_str[100];
      pim_inet4_dump("<src?>", src_addr, src_str, sizeof(src_str));
      zlog_warn("%s: short join/prune buffer for source list: size=%d minimum=%d from %s on %s",
		__PRETTY_FUNCTION__,
		remain, 4, src_str, ifp->name);
      return -6;
    }

    msg_num_joined_sources = ntohs(*(const uint16_t *) buf);
    buf += 2;
    msg_num_pruned_sources = ntohs(*(const uint16_t *) buf);
    buf += 2;

    if (PIM_DEBUG_PIM_J_P) {
      char src_str[100];
      char upstream_str[100];
      char group_str[100];
      pim_inet4_dump("<src?>", src_addr, src_str, sizeof(src_str));
      pim_inet4_dump("<addr?>", msg_upstream_addr.u.prefix4,
		     upstream_str, sizeof(upstream_str));
      pim_inet4_dump("<grp?>", msg_group_addr.u.prefix4,
		     group_str, sizeof(group_str));
      zlog_warn("%s: join/prune upstream=%s group=%s/%d join_src=%d prune_src=%d from %s on %s",
		__PRETTY_FUNCTION__,
		upstream_str, group_str, msg_group_addr.prefixlen,
		msg_num_joined_sources, msg_num_pruned_sources,
		src_str, ifp->name);
    }

    /* Scan joined sources */
    for (source = 0; source < msg_num_joined_sources; ++source) {
      addr_offset = pim_parse_addr_source (&msg_source_addr,
					   &msg_source_flags,
					   buf, pastend - buf);
      if (addr_offset < 1) {
	return -7;
      }

      buf += addr_offset;

      recv_join(ifp, neigh, msg_holdtime,
		msg_upstream_addr.u.prefix4,
		msg_group_addr.u.prefix4,
		msg_source_addr.u.prefix4,
		msg_source_flags);
    }

    /* Scan pruned sources */
    for (source = 0; source < msg_num_pruned_sources; ++source) {
      addr_offset = pim_parse_addr_source (&msg_source_addr,
					   &msg_source_flags,
					   buf, pastend - buf);
      if (addr_offset < 1) {
	return -8;
      }

      buf += addr_offset;

      recv_prune(ifp, neigh, msg_holdtime,
		 msg_upstream_addr.u.prefix4,
		 msg_group_addr.u.prefix4,
		 msg_source_addr.u.prefix4,
		 msg_source_flags);
    }

  } /* scan groups */

  return 0;
}

int pim_joinprune_send(struct interface *ifp,
		       struct in_addr upstream_addr,
		       struct prefix_sg *sg,
		       int send_join)
{
  struct pim_interface *pim_ifp;
  uint8_t pim_msg[1000];
  int pim_msg_size;

  on_trace (__PRETTY_FUNCTION__, ifp, upstream_addr);

  zassert(ifp);

  pim_ifp = ifp->info;

  if (!pim_ifp) {
    zlog_warn("%s: multicast not enabled on interface %s",
	      __PRETTY_FUNCTION__,
	      ifp->name);
    return -1;
  }

  if (PIM_DEBUG_PIM_J_P) {
    char dst_str[100];
    pim_inet4_dump("<dst?>", upstream_addr, dst_str, sizeof(dst_str));
    zlog_debug("%s: sending %s(S,G)=%s to upstream=%s on interface %s",
	       __PRETTY_FUNCTION__,
	       send_join ? "Join" : "Prune",
	       pim_str_sg_dump (sg), dst_str, ifp->name);
  }

  if (PIM_INADDR_IS_ANY(upstream_addr)) {
    if (PIM_DEBUG_PIM_J_P) {
      char dst_str[100];
      pim_inet4_dump("<dst?>", upstream_addr, dst_str, sizeof(dst_str));
      zlog_debug("%s: %s(S,G)=%s: upstream=%s is myself on interface %s",
		 __PRETTY_FUNCTION__,
		 send_join ? "Join" : "Prune",
		 pim_str_sg_dump (sg), dst_str, ifp->name);
    }
    return 0;
  }

  /*
    RFC 4601: 4.3.1.  Sending Hello Messages

    Thus, if a router needs to send a Join/Prune or Assert message on
    an interface on which it has not yet sent a Hello message with the
    currently configured IP address, then it MUST immediately send the
    relevant Hello message without waiting for the Hello Timer to
    expire, followed by the Join/Prune or Assert message.
  */
  pim_hello_require(ifp);

  /*
    Build PIM message
  */
  pim_msg_size = pim_msg_join_prune_encode (pim_msg, 1000, send_join,
					    sg->src, sg->grp,
					    upstream_addr, PIM_JP_HOLDTIME);

  if (pim_msg_size < 0)
    return pim_msg_size;

  if (pim_msg_send(pim_ifp->pim_sock_fd,
		   qpim_all_pim_routers_addr,
		   pim_msg,
		   pim_msg_size,
		   ifp->name)) {
    zlog_warn("%s: could not send PIM message on interface %s",
	      __PRETTY_FUNCTION__, ifp->name);
    return -8;
  }

  return 0;
}
