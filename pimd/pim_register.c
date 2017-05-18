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

struct thread *send_test_packet_timer = NULL;

/*
 * This seems stupidly expensive.  A list lookup.  Why is this
 * not a hash?
 */
static int
pim_check_is_my_ip_address (struct in_addr dest_addr)
{
  /*
   * See if we can short-cut some?
   * This might not make sense if we ever leave a static RP
   * type of configuration.
   * Note - Premature optimization might bite our patooeys' here.
   */
  if (I_am_RP(dest_addr) && (dest_addr.s_addr == qpim_rp.rpf_addr.s_addr))
    return 1;

  if (if_lookup_exact_address (&dest_addr, AF_INET))
    return 1;

  return 0;
}

static void
pim_register_stop_send (struct in_addr src)
{
  return;
}

void
pim_register_send (const struct ip *ip_hdr, struct pim_rpf *rpg)
{
  unsigned char buffer[3000];
  unsigned char *b1;
  struct pim_interface *pinfo;
  struct interface *ifp;
  uint32_t plen;

  ifp = rpg->source_nexthop.interface;
  pinfo = (struct pim_interface *)ifp->info;
  if (!pinfo) {
    zlog_debug("%s: No pinfo!\n", __PRETTY_FUNCTION__);
    return;
  }

  memset(buffer, 0, 3000);
  b1 = buffer + PIM_MSG_REGISTER_LEN;

  plen = ntohs(ip_hdr->ip_len);
  memcpy(b1, (const unsigned char *)ip_hdr, plen);

  pim_msg_build_header(buffer, plen + PIM_MSG_REGISTER_LEN, PIM_MSG_TYPE_REGISTER);

  if (pim_msg_send(pinfo->pim_sock_fd,
		   rpg->rpf_addr,
		   buffer,
		   plen + PIM_MSG_REGISTER_LEN,
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
  //size_t hlen;
  struct in_addr group = { .s_addr = 0 };
  struct in_addr source = { .s_addr = 0 };
  //uint8_t *msg;
  uint32_t *bits;

  if (!pim_check_is_my_ip_address (dest_addr)) {
    if (PIM_DEBUG_PIM_PACKETS) {
      char dest[100];

      pim_inet4_dump ("<dst?>", dest_addr, dest, sizeof(dest));
      zlog_debug ("%s: Received Register message for %s that I do not own", __func__,
		  dest);
    }
    return 0;
  }

#define inherited_olist(S,G) NULL
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
#define PIM_MSG_REGISTER_BIT_RESERVED_LEN 4
  ip_hdr = (struct ip *)(tlv_buf + PIM_MSG_REGISTER_BIT_RESERVED_LEN);
  //hlen = (ip_hdr->ip_hl << 2) | PIM_MSG_REGISTER_LEN;
  //msg = (uint8_t *)tlv_buf + hlen;
  source = ip_hdr->ip_src;
  group = ip_hdr->ip_dst;

  if (I_am_RP (group) && (dest_addr.s_addr == ((RP (group))->rpf_addr.s_addr))) {
    sentRegisterStop = 0;

    if (*bits & PIM_REGISTER_BORDER_BIT) {
      struct in_addr pimbr = pim_br_get_pmbr (source, group);
      if (PIM_DEBUG_PIM_PACKETS)
	zlog_debug("%s: Received Register message with Border bit set", __func__);

      if (pimbr.s_addr == pim_br_unknown.s_addr)
	pim_br_set_pmbr(source, group, src_addr);
      else if (src_addr.s_addr != pimbr.s_addr) {
	pim_register_stop_send(src_addr);
	if (PIM_DEBUG_PIM_PACKETS)
	  zlog_debug("%s: Sending register-Stop to %s and dropping mr. packet",
	    __func__, "Sender");
	/* Drop Packet Silently */
	return 1;
      }
    }

    struct pim_upstream *upstream = pim_upstream_find (source, group);
    /*
     * If we don't have a place to send ignore the packet
     */
    if (!upstream)
      return 1;

    if ((upstream->sptbit == PIM_UPSTREAM_SPTBIT_TRUE) ||
	((SwitchToSptDesired(source, group)) &&
	 (inherited_olist(source, group) == NULL))) {
      pim_register_stop_send(src_addr);
      sentRegisterStop = 1;
    }

    if ((upstream->sptbit == PIM_UPSTREAM_SPTBIT_TRUE) ||
	(SwitchToSptDesired(source, group))) {
      if (sentRegisterStop) {
	pim_upstream_keep_alive_timer_start (upstream, PIM_RP_KEEPALIVE_PERIOD);
      } else {
	pim_upstream_keep_alive_timer_start (upstream, PIM_KEEPALIVE_PERIOD);
      }
    }

    if (!(upstream->sptbit == PIM_UPSTREAM_SPTBIT_TRUE) &&
	!(*bits & PIM_REGISTER_NR_BIT))
      {
	pim_rp_set_upstream_addr (&upstream->upstream_addr, source);
	pim_nexthop_lookup (&upstream->rpf.source_nexthop,
			    upstream->upstream_addr, NULL);
	upstream->rpf.source_nexthop.interface = ifp;
	upstream->source_addr.s_addr = source.s_addr;
	upstream->rpf.rpf_addr.s_addr = source.s_addr;
	upstream->channel_oil->oil.mfcc_origin = source;
	pim_scan_individual_oil (upstream->channel_oil);
	pim_joinprune_send(upstream->rpf.source_nexthop.interface,
			   upstream->rpf.source_nexthop.mrib_nexthop_addr,
			   upstream->source_addr,
			   upstream->group_addr,
			   1);

	//decapsulate and forward the iner packet to
	//inherited_olist(S,G,rpt)
      }
  } else {
    pim_register_stop_send(src_addr);
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
