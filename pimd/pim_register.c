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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "log.h"
#include "if.h"
#include "thread.h"
#include "prefix.h"
#include "vty.h"
#include "plist.h"

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
#include "pim_ssm.h"
#include "pim_vxlan.h"

struct thread *send_test_packet_timer = NULL;

void pim_register_join(struct pim_upstream *up)
{
	struct pim_instance *pim = up->channel_oil->pim;

	if (pim_is_grp_ssm(pim, up->sg.grp)) {
		if (PIM_DEBUG_PIM_EVENTS)
			zlog_debug("%s register setup skipped as group is SSM",
				   up->sg_str);
		return;
	}

	pim_channel_add_oif(up->channel_oil, pim->regiface,
			    PIM_OIF_FLAG_PROTO_PIM);
	up->reg_state = PIM_REG_JOIN;
	pim_vxlan_update_sg_reg_state(pim, up, true /*reg_join*/);
}

void pim_register_stop_send(struct interface *ifp, struct prefix_sg *sg,
			    struct in_addr src, struct in_addr originator)
{
	struct pim_interface *pinfo;
	unsigned char buffer[10000];
	unsigned int b1length = 0;
	unsigned int length;
	uint8_t *b1;
	struct prefix p;

	if (PIM_DEBUG_PIM_REG) {
		zlog_debug("Sending Register stop for %s to %s on %s",
			   pim_str_sg_dump(sg), inet_ntoa(originator),
			   ifp->name);
	}

	memset(buffer, 0, 10000);
	b1 = (uint8_t *)buffer + PIM_MSG_REGISTER_STOP_LEN;

	length = pim_encode_addr_group(b1, AFI_IP, 0, 0, sg->grp);
	b1length += length;
	b1 += length;

	p.family = AF_INET;
	p.u.prefix4 = sg->src;
	p.prefixlen = 32;
	length = pim_encode_addr_ucast(b1, &p);
	b1length += length;

	pim_msg_build_header(buffer, b1length + PIM_MSG_REGISTER_STOP_LEN,
			     PIM_MSG_TYPE_REG_STOP, false);

	pinfo = (struct pim_interface *)ifp->info;
	if (!pinfo) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: No pinfo!", __PRETTY_FUNCTION__);
		return;
	}
	if (pim_msg_send(pinfo->pim_sock_fd, src, originator, buffer,
			 b1length + PIM_MSG_REGISTER_STOP_LEN, ifp->name)) {
		if (PIM_DEBUG_PIM_TRACE) {
			zlog_debug(
				"%s: could not send PIM register stop message on interface %s",
				__PRETTY_FUNCTION__, ifp->name);
		}
	}
	++pinfo->pim_ifstat_reg_stop_send;
}

int pim_register_stop_recv(struct interface *ifp, uint8_t *buf, int buf_size)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct pim_instance *pim = pim_ifp->pim;
	struct pim_upstream *upstream = NULL;
	struct prefix source;
	struct prefix_sg sg;
	int l;

	memset(&sg, 0, sizeof(struct prefix_sg));
	l = pim_parse_addr_group(&sg, buf, buf_size);
	buf += l;
	buf_size -= l;
	pim_parse_addr_ucast(&source, buf, buf_size);
	sg.src = source.u.prefix4;

	upstream = pim_upstream_find(pim, &sg);
	if (!upstream) {
		return 0;
	}

	if (PIM_DEBUG_PIM_REG)
		zlog_debug("Received Register stop for %s", upstream->sg_str);

	switch (upstream->reg_state) {
	case PIM_REG_NOINFO:
	case PIM_REG_PRUNE:
		return 0;
		break;
	case PIM_REG_JOIN:
		upstream->reg_state = PIM_REG_PRUNE;
		pim_channel_del_oif(upstream->channel_oil, pim->regiface,
				    PIM_OIF_FLAG_PROTO_PIM);
		pim_upstream_start_register_stop_timer(upstream, 0);
		pim_vxlan_update_sg_reg_state(pim, upstream,
			false/*reg_join*/);
		break;
	case PIM_REG_JOIN_PENDING:
		upstream->reg_state = PIM_REG_PRUNE;
		pim_upstream_start_register_stop_timer(upstream, 0);
		return 0;
		break;
	}

	return 0;
}

void pim_register_send(const uint8_t *buf, int buf_size, struct in_addr src,
		       struct pim_rpf *rpg, int null_register,
		       struct pim_upstream *up)
{
	unsigned char buffer[10000];
	unsigned char *b1;
	struct pim_interface *pinfo;
	struct interface *ifp;

	if (PIM_DEBUG_PIM_REG) {
		zlog_debug("Sending %s %sRegister Packet to %s", up->sg_str,
			   null_register ? "NULL " : "",
			   inet_ntoa(rpg->rpf_addr.u.prefix4));
	}

	ifp = rpg->source_nexthop.interface;
	if (!ifp) {
		if (PIM_DEBUG_PIM_REG)
			zlog_debug("%s: No interface to transmit register on",
				   __PRETTY_FUNCTION__);
		return;
	}
	pinfo = (struct pim_interface *)ifp->info;
	if (!pinfo) {
		if (PIM_DEBUG_PIM_REG)
			zlog_debug(
				"%s: Interface: %s not configured for pim to trasmit on!\n",
				__PRETTY_FUNCTION__, ifp->name);
		return;
	}

	if (PIM_DEBUG_PIM_REG) {
		char rp_str[INET_ADDRSTRLEN];
		strlcpy(rp_str, inet_ntoa(rpg->rpf_addr.u.prefix4),
			sizeof(rp_str));
		zlog_debug("%s: Sending %s %sRegister Packet to %s on %s",
			   __PRETTY_FUNCTION__, up->sg_str,
			   null_register ? "NULL " : "", rp_str, ifp->name);
	}

	memset(buffer, 0, 10000);
	b1 = buffer + PIM_MSG_HEADER_LEN;
	*b1 |= null_register << 6;
	b1 = buffer + PIM_MSG_REGISTER_LEN;

	memcpy(b1, (const unsigned char *)buf, buf_size);

	pim_msg_build_header(buffer, buf_size + PIM_MSG_REGISTER_LEN,
			     PIM_MSG_TYPE_REGISTER, false);

	++pinfo->pim_ifstat_reg_send;

	if (pim_msg_send(pinfo->pim_sock_fd, src, rpg->rpf_addr.u.prefix4,
			 buffer, buf_size + PIM_MSG_REGISTER_LEN, ifp->name)) {
		if (PIM_DEBUG_PIM_TRACE) {
			zlog_debug(
				"%s: could not send PIM register message on interface %s",
				__PRETTY_FUNCTION__, ifp->name);
		}
		return;
	}
}

void pim_null_register_send(struct pim_upstream *up)
{
	struct ip ip_hdr;
	struct pim_interface *pim_ifp;
	struct pim_rpf *rpg;
	struct in_addr src;

	pim_ifp = up->rpf.source_nexthop.interface->info;
	if (!pim_ifp) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"%s: Cannot send null-register for %s no valid iif",
				__PRETTY_FUNCTION__, up->sg_str);
		return;
	}

	rpg = RP(pim_ifp->pim, up->sg.grp);
	if (!rpg) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"%s: Cannot send null-register for %s no RPF to the RP",
				__PRETTY_FUNCTION__, up->sg_str);
		return;
	}

	memset(&ip_hdr, 0, sizeof(struct ip));
	ip_hdr.ip_p = PIM_IP_PROTO_PIM;
	ip_hdr.ip_hl = 5;
	ip_hdr.ip_v = 4;
	ip_hdr.ip_src = up->sg.src;
	ip_hdr.ip_dst = up->sg.grp;
	ip_hdr.ip_len = htons(20);

	/* checksum is broken */
	src = pim_ifp->primary_address;
	if (PIM_UPSTREAM_FLAG_TEST_SRC_VXLAN_ORIG(up->flags)) {
		if (!pim_vxlan_get_register_src(pim_ifp->pim, up, &src)) {
			if (PIM_DEBUG_PIM_TRACE)
				zlog_debug(
					"%s: Cannot send null-register for %s vxlan-aa PIP unavailable",
					__PRETTY_FUNCTION__, up->sg_str);
			return;
		}
	}
	pim_register_send((uint8_t *)&ip_hdr, sizeof(struct ip),
			src, rpg, 1, up);
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
 *            sentRegisterStop = false;
 *            if ( register.borderbit == true ) {
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
 *              sentRegisterStop = true;
 *            }
 *            if ( SPTbit(S,G) OR SwitchToSptDesired(S,G) ) {
 *                 if ( sentRegisterStop == true ) {
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
int pim_register_recv(struct interface *ifp, struct in_addr dest_addr,
		      struct in_addr src_addr, uint8_t *tlv_buf,
		      int tlv_buf_size)
{
	int sentRegisterStop = 0;
	struct ip *ip_hdr;
	struct prefix_sg sg;
	uint32_t *bits;
	int i_am_rp = 0;
	struct pim_interface *pim_ifp = NULL;

	pim_ifp = ifp->info;

#define PIM_MSG_REGISTER_BIT_RESERVED_LEN 4
	ip_hdr = (struct ip *)(tlv_buf + PIM_MSG_REGISTER_BIT_RESERVED_LEN);

	if (!pim_rp_check_is_my_ip_address(pim_ifp->pim, dest_addr)) {
		if (PIM_DEBUG_PIM_REG) {
			char dest[INET_ADDRSTRLEN];

			pim_inet4_dump("<dst?>", dest_addr, dest, sizeof(dest));
			zlog_debug(
				"%s: Received Register message for destination address: %s that I do not own",
				__func__, dest);
		}
		return 0;
	}

	++pim_ifp->pim_ifstat_reg_recv;

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
	memset(&sg, 0, sizeof(struct prefix_sg));
	sg.src = ip_hdr->ip_src;
	sg.grp = ip_hdr->ip_dst;

	i_am_rp = I_am_RP(pim_ifp->pim, sg.grp);

	if (PIM_DEBUG_PIM_REG) {
		char src_str[INET_ADDRSTRLEN];

		pim_inet4_dump("<src?>", src_addr, src_str, sizeof(src_str));
		zlog_debug("Received Register message%s from %s on %s, rp: %d",
			   pim_str_sg_dump(&sg), src_str, ifp->name, i_am_rp);
	}

	if (i_am_rp
	    && (dest_addr.s_addr
		== ((RP(pim_ifp->pim, sg.grp))->rpf_addr.u.prefix4.s_addr))) {
		sentRegisterStop = 0;

		if (*bits & PIM_REGISTER_BORDER_BIT) {
			struct in_addr pimbr = pim_br_get_pmbr(&sg);
			if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug(
					"%s: Received Register message with Border bit set",
					__func__);

			if (pimbr.s_addr == pim_br_unknown.s_addr)
				pim_br_set_pmbr(&sg, src_addr);
			else if (src_addr.s_addr != pimbr.s_addr) {
				pim_register_stop_send(ifp, &sg, dest_addr,
						       src_addr);
				if (PIM_DEBUG_PIM_PACKETS)
					zlog_debug(
						"%s: Sending register-Stop to %s and dropping mr. packet",
						__func__, "Sender");
				/* Drop Packet Silently */
				return 0;
			}
		}

		struct pim_upstream *upstream =
			pim_upstream_find(pim_ifp->pim, &sg);
		/*
		 * If we don't have a place to send ignore the packet
		 */
		if (!upstream) {
			upstream = pim_upstream_add(
				pim_ifp->pim, &sg, ifp,
				PIM_UPSTREAM_FLAG_MASK_SRC_STREAM,
				__PRETTY_FUNCTION__, NULL);
			if (!upstream) {
				zlog_warn("Failure to create upstream state");
				return 1;
			}

			upstream->upstream_register = src_addr;
		} else {
			/*
			 * If the FHR has set a very very fast register timer
			 * there exists a possibility that the incoming NULL
			 * register
			 * is happening before we set the spt bit.  If so
			 * Do a quick check to update the counters and
			 * then set the spt bit as appropriate
			 */
			if (upstream->sptbit != PIM_UPSTREAM_SPTBIT_TRUE) {
				pim_mroute_update_counters(
					upstream->channel_oil);
				/*
				 * Have we seen packets?
				 */
				if (upstream->channel_oil->cc.oldpktcnt
				    < upstream->channel_oil->cc.pktcnt)
					pim_upstream_set_sptbit(
						upstream,
						upstream->rpf.source_nexthop
							.interface);
			}
		}

		if ((upstream->sptbit == PIM_UPSTREAM_SPTBIT_TRUE)
		    || ((SwitchToSptDesired(pim_ifp->pim, &sg))
			&& pim_upstream_inherited_olist(pim_ifp->pim, upstream)
				   == 0)) {
			// pim_scan_individual_oil (upstream->channel_oil);
			pim_register_stop_send(ifp, &sg, dest_addr, src_addr);
			sentRegisterStop = 1;
		} else {
			if (PIM_DEBUG_PIM_REG)
				zlog_debug("(%s) sptbit: %d", upstream->sg_str,
					   upstream->sptbit);
		}
		if ((upstream->sptbit == PIM_UPSTREAM_SPTBIT_TRUE)
		    || (SwitchToSptDesired(pim_ifp->pim, &sg))) {
			if (sentRegisterStop) {
				pim_upstream_keep_alive_timer_start(
					upstream,
					pim_ifp->pim->rp_keep_alive_time);
			} else {
				pim_upstream_keep_alive_timer_start(
					upstream,
					pim_ifp->pim->keep_alive_time);
			}
		}

		if (!(upstream->sptbit == PIM_UPSTREAM_SPTBIT_TRUE)
		    && !(*bits & PIM_REGISTER_NR_BIT)) {
			// decapsulate and forward the iner packet to
			// inherited_olist(S,G,rpt)
			// This is taken care of by the kernel for us
		}
		pim_upstream_msdp_reg_timer_start(upstream);
	} else {
		if (PIM_DEBUG_PIM_REG) {
			if (!i_am_rp)
				zlog_debug(
					"Received Register packet for %s, Rejecting packet because I am not the RP configured for group",
					pim_str_sg_dump(&sg));
			else
				zlog_debug(
					"Received Register packet for %s, Rejecting packet because the dst ip address is not the actual RP",
					pim_str_sg_dump(&sg));
		}
		pim_register_stop_send(ifp, &sg, dest_addr, src_addr);
	}

	return 0;
}
