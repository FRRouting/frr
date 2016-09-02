/*
 * PIM for Quagga
 * Copyright (C) 2015 Cumulus Networks, Inc.
 * Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#include <zebra.h>

#include "log.h"
#include "if.h"
#include "thread.h"
#include "prefix.h"

#include "pimd.h"
#include "pim_mroute.h"
#include "pim_iface.h"
#include "pim_msg.h"
#include "pim_pim.h"
#include "pim_str.h"
#include "pim_rp.h"
#include "pim_register.h"
#include "pim_upstream.h"
#include "pim_br.h"
#include "pim_rpf.h"
#include "pim_oil.h"
#include "pim_zebra.h"
#include "pim_join.h"
#include "pim_util.h"

struct thread *send_test_packet_timer = NULL;

void
pim_register_stop_send (struct interface *ifp, struct prefix_sg *sg,
			struct in_addr src, struct in_addr originator)
{
  struct pim_interface *pinfo;
  unsigned char buffer[3000];
  unsigned int b1length = 0;
  unsigned int length;
  uint8_t *b1;
  struct prefix p;

  if (PIM_DEBUG_PIM_REG)
    {
      zlog_debug ("Sending Register stop for %s to %s on %s",
		  pim_str_sg_dump (sg), inet_ntoa(originator), ifp->name);
    }

  memset (buffer, 0, 3000);
  b1 = (uint8_t *)buffer + PIM_MSG_REGISTER_STOP_LEN;

  length = pim_encode_addr_group (b1, AFI_IP, 0, 0, sg->grp);
  b1length += length;
  b1 += length;

  p.family = AF_INET;
  p.u.prefix4 = sg->src;
  p.prefixlen = 32;
  length = pim_encode_addr_ucast (b1, &p);
  b1length += length;

  pim_msg_build_header (buffer, b1length + PIM_MSG_REGISTER_STOP_LEN, PIM_MSG_TYPE_REG_STOP);

  pinfo = (struct pim_interface *)ifp->info;
  if (!pinfo)
    {
      if (PIM_DEBUG_PIM_TRACE)
        zlog_debug ("%s: No pinfo!\n", __PRETTY_FUNCTION__);
      return;
    }
  if (pim_msg_send (pinfo->pim_sock_fd, src, originator,
		    buffer, b1length + PIM_MSG_REGISTER_STOP_LEN,
		    ifp->name))
    {
      if (PIM_DEBUG_PIM_TRACE)
	{
	  zlog_debug ("%s: could not send PIM register stop message on interface %s",
		      __PRETTY_FUNCTION__, ifp->name);
	}
    }
}

int
pim_register_stop_recv (uint8_t *buf, int buf_size)
{
  struct pim_upstream *upstream = NULL;
  struct prefix source;
  struct prefix group;
  struct prefix_sg sg;
  int l;

  l = pim_parse_addr_group (&group, buf, buf_size);
  buf += l;
  buf_size -= l;
  pim_parse_addr_ucast (&source, buf, buf_size);
  memset (&sg, 0, sizeof (struct prefix_sg));
  sg.src = source.u.prefix4;
  sg.grp = group.u.prefix4;

  if (PIM_DEBUG_PIM_REG)
    {
      zlog_debug ("Received Register stop for %s",
		  pim_str_sg_dump (&sg));
    }

  upstream = pim_upstream_find (&sg);
  if (!upstream)
    {
      return 0;
    }

  switch (upstream->join_state)
    {
    case PIM_UPSTREAM_NOTJOINED:
    case PIM_UPSTREAM_PRUNE:
      return 0;
      break;
    case PIM_UPSTREAM_JOINED:
      upstream->join_state = PIM_UPSTREAM_PRUNE;
      pim_channel_del_oif (upstream->channel_oil, pim_regiface, PIM_OIF_FLAG_PROTO_PIM);
      pim_upstream_start_register_stop_timer (upstream, 0);
    case PIM_UPSTREAM_JOIN_PENDING:
      upstream->join_state = PIM_UPSTREAM_PRUNE;
      pim_upstream_start_register_stop_timer (upstream, 0);
      return 0;
      break;
    }

  return 0;
}

void
pim_register_send (const uint8_t *buf, int buf_size, struct in_addr src, struct pim_rpf *rpg, int null_register)
{
  unsigned char buffer[3000];
  unsigned char *b1;
  struct pim_interface *pinfo;
  struct interface *ifp;

  if (PIM_DEBUG_PIM_REG)
    {
       char rp_str[100];
       strcpy (rp_str, inet_ntoa (rpg->rpf_addr.u.prefix4));
       zlog_debug ("Sending %sRegister Packet to %s", null_register ? "NULL " : "", rp_str);
    }

  ifp = rpg->source_nexthop.interface;
  pinfo = (struct pim_interface *)ifp->info;
  if (!pinfo) {
    zlog_debug("%s: No pinfo!\n", __PRETTY_FUNCTION__);
    return;
  }

  memset(buffer, 0, 3000);
  b1 = buffer + PIM_MSG_HEADER_LEN;
  *b1 |= null_register << 6;
  b1 = buffer + PIM_MSG_REGISTER_LEN;

  memcpy(b1, (const unsigned char *)buf, buf_size);

  pim_msg_build_header(buffer, buf_size + PIM_MSG_REGISTER_LEN, PIM_MSG_TYPE_REGISTER);

  if (pim_msg_send(pinfo->pim_sock_fd,
		   src,
		   rpg->rpf_addr.u.prefix4,
		   buffer,
		   buf_size + PIM_MSG_REGISTER_LEN,
		   ifp->name)) {
    if (PIM_DEBUG_PIM_TRACE) {
      zlog_debug("%s: could not send PIM register message on interface %s",
		 __PRETTY_FUNCTION__, ifp->name);
    }
    return;
  }
}

/*
 * 4.4.2 Receiving Register Messages at the RP
 *
 *   When an RP receives a Register message, the course of action is
 *  decided according to the following pseudocode:
 *
 *  packet_arrives_on_rp_tunnel( pkt ) {
 *      if( outer.dst is not one of my addresses ) {
 *          drop the packet silently.
 *          # Note: this may be a spoofing attempt
 *      }
 *      if( I_am_RP(G) AND outer.dst == RP(G) ) {
 *            sentRegisterStop = FALSE;
 *            if ( register.borderbit == TRUE ) {
 *                 if ( PMBR(S,G) == unknown ) {
 *                      PMBR(S,G) = outer.src
 *                 } else if ( outer.src != PMBR(S,G) ) {
 *                      send Register-Stop(S,G) to outer.src
 *                      drop the packet silently.
 *                 }
 *            }
 *            if ( SPTbit(S,G) OR
 *             ( SwitchToSptDesired(S,G) AND
 *               ( inherited_olist(S,G) == NULL ))) {
 *              send Register-Stop(S,G) to outer.src
 *              sentRegisterStop = TRUE;
 *            }
 *            if ( SPTbit(S,G) OR SwitchToSptDesired(S,G) ) {
 *                 if ( sentRegisterStop == TRUE ) {
 *                      set KeepaliveTimer(S,G) to RP_Keepalive_Period;
 *                 } else {
 *                      set KeepaliveTimer(S,G) to Keepalive_Period;
 *                 }
 *            }
 *            if( !SPTbit(S,G) AND ! pkt.NullRegisterBit ) {
 *                 decapsulate and forward the inner packet to
 *                 inherited_olist(S,G,rpt) # Note (+)
 *            }
 *      } else {
 *          send Register-Stop(S,G) to outer.src
 *          # Note (*)
 *      }
 *  }
 */
int
pim_register_recv (struct interface *ifp,
		   struct in_addr dest_addr,
		   struct in_addr src_addr,
		   uint8_t *tlv_buf, int tlv_buf_size)
{
  int sentRegisterStop = 0;
  struct ip *ip_hdr;
  struct prefix_sg sg;
  uint32_t *bits;

#define PIM_MSG_REGISTER_BIT_RESERVED_LEN 4
  ip_hdr = (struct ip *)(tlv_buf + PIM_MSG_REGISTER_BIT_RESERVED_LEN);

  if (!pim_rp_check_is_my_ip_address (ip_hdr->ip_dst, dest_addr)) {
    if (PIM_DEBUG_PIM_REG) {
      char dest[100];

      pim_inet4_dump ("<dst?>", dest_addr, dest, sizeof(dest));
      zlog_debug ("%s: Received Register message for %s that I do not own", __func__,
		  dest);
    }
    return 0;
  }

  if (PIM_DEBUG_PIM_REG)
    {
      char src_str[100];

      pim_inet4_dump ("<src?>", src_addr, src_str, sizeof (src_str));
      zlog_debug ("Received Register message from %s on %s", src_str, ifp->name);
    }

  /*
   * Please note this is not drawn to get the correct bit/data size
   *
   * The entirety of the REGISTER packet looks like this:
   * -------------------------------------------------------------
   * | Ver  | Type | Reserved     |       Checksum               |
   * |-----------------------------------------------------------|
   * |B|N|     Reserved 2                                        |
   * |-----------------------------------------------------------|
   * | Encap  |                IP HDR                            |
   * | Mcast  |                                                  |
   * | Packet |--------------------------------------------------|
   * |        |               Mcast Data                         |
   * |        |                                                  |
   * ...
   *
   * tlv_buf when received from the caller points at the B bit
   * We need to know the inner source and dest
   */
  bits = (uint32_t *)tlv_buf;

  /*
   * tlv_buf points to the start of the |B|N|... Reserved
   * Line above.  So we need to add 4 bytes to get to the
   * start of the actual Encapsulated data.
   */
  memset (&sg, 0, sizeof (struct prefix_sg));
  sg.src = ip_hdr->ip_src;
  sg.grp = ip_hdr->ip_dst;

  if (I_am_RP (sg.grp) && (dest_addr.s_addr == ((RP (sg.grp))->rpf_addr.u.prefix4.s_addr))) {
    sentRegisterStop = 0;

    if (*bits & PIM_REGISTER_BORDER_BIT) {
      struct in_addr pimbr = pim_br_get_pmbr (&sg);
      if (PIM_DEBUG_PIM_PACKETS)
	zlog_debug("%s: Received Register message with Border bit set", __func__);

      if (pimbr.s_addr == pim_br_unknown.s_addr)
	pim_br_set_pmbr(&sg, src_addr);
      else if (src_addr.s_addr != pimbr.s_addr) {
	pim_register_stop_send (ifp, &sg, dest_addr, src_addr);
	if (PIM_DEBUG_PIM_PACKETS)
	  zlog_debug("%s: Sending register-Stop to %s and dropping mr. packet",
	    __func__, "Sender");
	/* Drop Packet Silently */
	return 1;
      }
    }

    struct pim_upstream *upstream = pim_upstream_find (&sg);
    /*
     * If we don't have a place to send ignore the packet
     */
    if (!upstream)
      {
	upstream = pim_upstream_add (&sg, ifp);
        if (!upstream)
          {
            zlog_warn ("Failure to crate upstream state");
            return 1;
          }
        upstream->upstream_register = src_addr;
	pim_rp_set_upstream_addr (&upstream->upstream_addr, sg.src, sg.grp);
	pim_nexthop_lookup (&upstream->rpf.source_nexthop,
			    upstream->upstream_addr);
	upstream->sg.src = sg.src;
	upstream->rpf.rpf_addr = upstream->rpf.source_nexthop.mrib_nexthop_addr;

	upstream->join_state = PIM_UPSTREAM_PRUNE;

      }

    if ((upstream->sptbit == PIM_UPSTREAM_SPTBIT_TRUE) ||
	((SwitchToSptDesired(&sg)) &&
	 pim_upstream_inherited_olist (upstream) == 0)) {
      //pim_scan_individual_oil (upstream->channel_oil);
      pim_register_stop_send (ifp, &sg, dest_addr, src_addr);
      sentRegisterStop = 1;
    }

    if ((upstream->sptbit == PIM_UPSTREAM_SPTBIT_TRUE) ||
	(SwitchToSptDesired(&sg))) {
      if (sentRegisterStop) {
	pim_upstream_keep_alive_timer_start (upstream, qpim_rp_keep_alive_time);
      } else {
	pim_upstream_keep_alive_timer_start (upstream, qpim_keep_alive_time);
      }
    }

    if (!(upstream->sptbit == PIM_UPSTREAM_SPTBIT_TRUE) &&
	!(*bits & PIM_REGISTER_NR_BIT))
      {
	//decapsulate and forward the iner packet to
	//inherited_olist(S,G,rpt)
	// This is taken care of by the kernel for us
      }
  } else {
    pim_register_stop_send (ifp, &sg, dest_addr, src_addr);
  }

  return 1;
}


static int
pim_register_send_test_packet (struct thread *t)
{
  uint8_t *packet;

  packet = THREAD_ARG(t);

  *packet = 4;

  return 1;
}

/*
 * pim_register_send_test_packet
 *
 * Send a test packet to the RP from source, in group and pps packets per second
 */
void
pim_register_send_test_packet_start (struct in_addr source,
				     struct in_addr group,
				     uint32_t pps)
{
  uint8_t *packet = NULL;

  THREAD_TIMER_MSEC_ON(master, send_test_packet_timer,
		       pim_register_send_test_packet, packet, 1000/pps);

  return;
}
