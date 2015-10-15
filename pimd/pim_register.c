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
#include "pim_str.h"
#include "pim_rp.h"
#include "pim_register.h"
#include "pim_br.h"

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
  if (I_am_RP(dest_addr) && (dest_addr.s_addr == qpim_rp.s_addr))
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
  //int sentRegisterStop = 0;
  struct in_addr group = { .s_addr = 0 };
  struct in_addr source = { .s_addr = 0 };
  struct in_addr outer_src = { .s_addr = 0 };
  uint32_t *bits = (uint32_t *)tlv_buf;
  //uint8_t *data = (tlv_buf + sizeof(uint32_t));
  uint32_t nrb;

  if (!pim_check_is_my_ip_address (dest_addr)) {
    if (PIM_DEBUG_PIM_PACKETS) {
      char dest[100];

      pim_inet4_dump ("<dst?>", dest_addr, dest, sizeof(dest));
      zlog_debug ("%s: Received Register message for %s that I do not own", __func__,
		  dest);
    }
    return 0;
  }

  nrb = (*bits && PIM_REGISTER_NR_BIT);
  if (I_am_RP (group) && (dest_addr.s_addr == (RP (group).s_addr))) {
    //sentRegisterStop = 0;

    if (*bits && PIM_REGISTER_BORDER_BIT) {
      struct in_addr pimbr = pim_br_get_pmbr (source, group);
      if (PIM_DEBUG_PIM_PACKETS)
	zlog_debug("%s: Received Register message with Border bit set", __func__);

      if (pimbr.s_addr == pim_br_unknown.s_addr)
	pim_br_set_pmbr(source, group, outer_src);
      else if (outer_src.s_addr != pimbr.s_addr) {
	pim_register_stop_send(outer_src);
	if (PIM_DEBUG_PIM_PACKETS)
	  zlog_debug("%s: Sending register-Stop to %s and dropping mr. packet",
	    __func__, "Sender");
      }
    }
  } else {
      nrb++;
    //pim_recv_
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
