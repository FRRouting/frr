// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2015 Cumulus Networks, Inc.
 * Donald Sharp
 */

#include <zebra.h>

#include "log.h"
#include "if.h"
#include "frrevent.h"
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
#include "pim_rpf.h"
#include "pim_oil.h"
#include "pim_zebra.h"
#include "pim_join.h"
#include "pim_util.h"
#include "pim_ssm.h"
#include "pim_vxlan.h"
#include "pim_addr.h"

struct event *send_test_packet_timer = NULL;

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
			    PIM_OIF_FLAG_PROTO_PIM, __func__);
	up->reg_state = PIM_REG_JOIN;
	pim_vxlan_update_sg_reg_state(pim, up, true);
}

void pim_register_stop_send(struct interface *ifp, pim_sgaddr *sg, pim_addr src,
			    pim_addr originator)
{
	struct pim_interface *pinfo;
	unsigned char buffer[10000];
	unsigned int b1length = 0;
	unsigned int length;
	uint8_t *b1;

	if (PIM_DEBUG_PIM_REG) {
		zlog_debug("Sending Register stop for %pSG to %pPA on %s", sg,
			   &originator, ifp->name);
	}

	memset(buffer, 0, 10000);
	b1 = (uint8_t *)buffer + PIM_MSG_REGISTER_STOP_LEN;

	length = pim_encode_addr_group(b1, AFI_IP, 0, 0, sg->grp);
	b1length += length;
	b1 += length;

	length = pim_encode_addr_ucast(b1, sg->src);
	b1length += length;

	pim_msg_build_header(src, originator, buffer,
			     b1length + PIM_MSG_REGISTER_STOP_LEN,
			     PIM_MSG_TYPE_REG_STOP, false);

	pinfo = (struct pim_interface *)ifp->info;
	if (!pinfo) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: No pinfo!", __func__);
		return;
	}
	if (pim_msg_send(pinfo->pim->reg_sock, src, originator, buffer,
			 b1length + PIM_MSG_REGISTER_STOP_LEN, ifp)) {
		if (PIM_DEBUG_PIM_TRACE) {
			zlog_debug(
				"%s: could not send PIM register stop message on interface %s",
				__func__, ifp->name);
		}
	}

	if (!pinfo->pim_passive_enable)
		++pinfo->pim_ifstat_reg_stop_send;
}

static void pim_reg_stop_upstream(struct pim_instance *pim,
				  struct pim_upstream *up)
{
	switch (up->reg_state) {
	case PIM_REG_NOINFO:
	case PIM_REG_PRUNE:
		return;
	case PIM_REG_JOIN:
		up->reg_state = PIM_REG_PRUNE;
		pim_channel_del_oif(up->channel_oil, pim->regiface,
				    PIM_OIF_FLAG_PROTO_PIM, __func__);
		pim_upstream_start_register_probe_timer(up);
		pim_vxlan_update_sg_reg_state(pim, up, false);
		break;
	case PIM_REG_JOIN_PENDING:
		up->reg_state = PIM_REG_PRUNE;
		pim_upstream_start_register_probe_timer(up);
		return;
	}
}

int pim_register_stop_recv(struct interface *ifp, uint8_t *buf, int buf_size)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct pim_instance *pim = pim_ifp->pim;
	struct pim_upstream *up = NULL;
	struct pim_rpf *rp;
	pim_sgaddr sg;
	struct listnode *up_node;
	struct pim_upstream *child;
	bool wrong_af = false;
	bool handling_star = false;
	int l;

	if (pim_ifp->pim_passive_enable) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"skip receiving PIM message on passive interface %s",
				ifp->name);
		return 0;
	}

	++pim_ifp->pim_ifstat_reg_stop_recv;

	memset(&sg, 0, sizeof(sg));
	l = pim_parse_addr_group(&sg, buf, buf_size);
	buf += l;
	buf_size -= l;
	pim_parse_addr_ucast(&sg.src, buf, buf_size, &wrong_af);

	if (wrong_af) {
		zlog_err("invalid AF in Register-Stop on %s", ifp->name);
		return -1;
	}


	if (PIM_DEBUG_PIM_REG)
		zlog_debug("Received Register stop for %pSG", &sg);

	rp = RP(pim_ifp->pim, sg.grp);
	if (rp) {
		/* As per RFC 7761, Section 4.9.4:
		 * A special wildcard value consisting of an address field of
		 * all zeros can be used to indicate any source.
		 */
		if ((pim_addr_cmp(sg.src, rp->rpf_addr) == 0) ||
		    pim_addr_is_any(sg.src)) {
			handling_star = true;
			sg.src = PIMADDR_ANY;
		}
	}

	/*
	 * RFC 7761 Sec 4.4.1
	 * Handling Register-Stop(*,G) Messages at the DR:
	 *   A Register-Stop(*,G) should be treated as a
	 *   Register-Stop(S,G) for all (S,G) Register state
	 *   machines that are not in the NoInfo state.
	 */
	up = pim_upstream_find(pim, &sg);
	if (up) {
		/*
		 * If the upstream find actually found a particular
		 * S,G then we *know* that the following for loop
		 * is not going to execute and this is ok
		 */
		for (ALL_LIST_ELEMENTS_RO(up->sources, up_node, child)) {
			if (PIM_DEBUG_PIM_REG)
				zlog_debug("Executing Reg stop for %s",
					   child->sg_str);

			pim_reg_stop_upstream(pim, child);
		}

		if (PIM_DEBUG_PIM_REG)
			zlog_debug("Executing Reg stop for %s", up->sg_str);
		pim_reg_stop_upstream(pim, up);
	} else {
		if (!handling_star)
			return 0;
		/*
		 * Unfortunately pim was unable to find a *,G
		 * but pim may still actually have individual
		 * S,G's that need to be processed.  In that
		 * case pim must do the expensive walk to find
		 * and stop
		 */
		frr_each (rb_pim_upstream, &pim->upstream_head, up) {
			if (pim_addr_cmp(up->sg.grp, sg.grp) == 0) {
				if (PIM_DEBUG_PIM_REG)
					zlog_debug("Executing Reg stop for %s",
						   up->sg_str);
				pim_reg_stop_upstream(pim, up);
			}
		}
	}

	return 0;
}

#if PIM_IPV == 6
struct in6_addr pim_register_get_unicast_v6_addr(struct pim_interface *p_ifp)
{
	struct listnode *node;
	struct listnode *nextnode;
	struct pim_secondary_addr *sec_addr;
	struct pim_interface *pim_ifp;
	struct interface *ifp;
	struct pim_instance *pim = p_ifp->pim;

	/* Trying to get the unicast address from the RPF interface first */
	for (ALL_LIST_ELEMENTS(p_ifp->sec_addr_list, node, nextnode,
			       sec_addr)) {
		if (!is_ipv6_global_unicast(&sec_addr->addr.u.prefix6))
			continue;

		return sec_addr->addr.u.prefix6;
	}

	/* Loop through all the pim interface and try to return a global
	 * unicast ipv6 address
	 */
	FOR_ALL_INTERFACES (pim->vrf, ifp) {
		pim_ifp = ifp->info;

		if (!pim_ifp)
			continue;

		for (ALL_LIST_ELEMENTS(pim_ifp->sec_addr_list, node, nextnode,
				       sec_addr)) {
			if (!is_ipv6_global_unicast(&sec_addr->addr.u.prefix6))
				continue;

			return sec_addr->addr.u.prefix6;
		}
	}

	zlog_warn("No global address found for use to send register message");
	return PIMADDR_ANY;
}
#endif

void pim_register_send(const uint8_t *buf, int buf_size, pim_addr src,
		       struct pim_rpf *rpg, int null_register,
		       struct pim_upstream *up)
{
	unsigned char buffer[10000];
	unsigned char *b1;
	struct pim_interface *pinfo;
	struct interface *ifp;

	if (PIM_DEBUG_PIM_REG) {
		zlog_debug("Sending %s %sRegister Packet to %pPA", up->sg_str,
			   null_register ? "NULL " : "", &rpg->rpf_addr);
	}

	ifp = rpg->source_nexthop.interface;
	if (!ifp) {
		if (PIM_DEBUG_PIM_REG)
			zlog_debug("%s: No interface to transmit register on",
				   __func__);
		return;
	}
	pinfo = (struct pim_interface *)ifp->info;
	if (!pinfo) {
		if (PIM_DEBUG_PIM_REG)
			zlog_debug(
				"%s: Interface: %s not configured for pim to transmit on!",
				__func__, ifp->name);
		return;
	}

	if (PIM_DEBUG_PIM_REG) {
		zlog_debug("%s: Sending %s %sRegister Packet to %pPA on %s",
			   __func__, up->sg_str, null_register ? "NULL " : "",
			   &rpg->rpf_addr, ifp->name);
	}

	memset(buffer, 0, 10000);
	b1 = buffer + PIM_MSG_HEADER_LEN;
	*b1 |= null_register << 6;
	b1 = buffer + PIM_MSG_REGISTER_LEN;

	memcpy(b1, (const unsigned char *)buf, buf_size);

#if PIM_IPV == 6
	/* While sending Register message to RP, we cannot use link-local
	 * address therefore using unicast ipv6 address here, choosing it
	 * from the RPF Interface
	 */
	src = pim_register_get_unicast_v6_addr(pinfo);
#endif
	pim_msg_build_header(src, rpg->rpf_addr, buffer,
			     buf_size + PIM_MSG_REGISTER_LEN,
			     PIM_MSG_TYPE_REGISTER, false);

	if (!pinfo->pim_passive_enable)
		++pinfo->pim_ifstat_reg_send;

	if (pim_msg_send(pinfo->pim->reg_sock, src, rpg->rpf_addr, buffer,
			 buf_size + PIM_MSG_REGISTER_LEN, ifp)) {
		if (PIM_DEBUG_PIM_TRACE) {
			zlog_debug(
				"%s: could not send PIM register message on interface %s",
				__func__, ifp->name);
		}
		return;
	}
}

#if PIM_IPV == 4
void pim_null_register_send(struct pim_upstream *up)
{
	struct ip ip_hdr;
	struct pim_interface *pim_ifp;
	struct pim_rpf *rpg;
	pim_addr src;

	pim_ifp = up->rpf.source_nexthop.interface->info;
	if (!pim_ifp) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"%s: Cannot send null-register for %s no valid iif",
				__func__, up->sg_str);
		return;
	}

	rpg = RP(pim_ifp->pim, up->sg.grp);
	if (!rpg) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"%s: Cannot send null-register for %s no RPF to the RP",
				__func__, up->sg_str);
		return;
	}

	memset(&ip_hdr, 0, sizeof(ip_hdr));
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
					__func__, up->sg_str);
			return;
		}
	}
	pim_register_send((uint8_t *)&ip_hdr, sizeof(struct ip), src, rpg, 1,
			  up);
}
#else
void pim_null_register_send(struct pim_upstream *up)
{
	struct ip6_hdr ip6_hdr;
	struct pim_msg_header pim_msg_header;
	struct pim_interface *pim_ifp;
	struct pim_rpf *rpg;
	pim_addr src;
	unsigned char buffer[sizeof(ip6_hdr) + sizeof(pim_msg_header)];
	struct ipv6_ph ph;

	pim_ifp = up->rpf.source_nexthop.interface->info;
	if (!pim_ifp) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"Cannot send null-register for %s no valid iif",
				up->sg_str);
		return;
	}

	rpg = RP(pim_ifp->pim, up->sg.grp);
	if (!rpg) {
		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug(
				"Cannot send null-register for %s no RPF to the RP",
				up->sg_str);
		return;
	}

	memset(&ip6_hdr, 0, sizeof(ip6_hdr));
	ip6_hdr.ip6_nxt = PIM_IP_PROTO_PIM;
	ip6_hdr.ip6_plen = PIM_MSG_HEADER_LEN;
	ip6_hdr.ip6_vfc = 6 << 4;
	ip6_hdr.ip6_hlim = MAXTTL;
	ip6_hdr.ip6_src = up->sg.src;
	ip6_hdr.ip6_dst = up->sg.grp;

	memset(buffer, 0, (sizeof(ip6_hdr) + sizeof(pim_msg_header)));
	memcpy(buffer, &ip6_hdr, sizeof(ip6_hdr));

	memset(&pim_msg_header, 0, sizeof(pim_msg_header));
	memset(&ph, 0, sizeof(ph));

	ph.src = up->sg.src;
	ph.dst = up->sg.grp;
	ph.ulpl = htonl(PIM_MSG_HEADER_LEN);
	ph.next_hdr = IPPROTO_PIM;
	pim_msg_header.checksum =
		in_cksum_with_ph6(&ph, &pim_msg_header, PIM_MSG_HEADER_LEN);

	memcpy(buffer + sizeof(ip6_hdr), &pim_msg_header, PIM_MSG_HEADER_LEN);


	src = pim_ifp->primary_address;
	pim_register_send((uint8_t *)buffer,
			  sizeof(ip6_hdr) + PIM_MSG_HEADER_LEN, src, rpg, 1,
			  up);
}
#endif

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
int pim_register_recv(struct interface *ifp, pim_addr dest_addr,
		      pim_addr src_addr, uint8_t *tlv_buf, int tlv_buf_size)
{
	int sentRegisterStop = 0;
	const void *ip_hdr;
	pim_sgaddr sg;
	uint32_t *bits;
	int i_am_rp = 0;
	struct pim_interface *pim_ifp = ifp->info;
	struct pim_instance *pim = pim_ifp->pim;
	pim_addr rp_addr;
	struct pim_rpf *rpg;

	if (pim_ifp->pim_passive_enable) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"skip receiving PIM message on passive interface %s",
				ifp->name);
		return 0;
	}

#define PIM_MSG_REGISTER_BIT_RESERVED_LEN 4
	ip_hdr = (tlv_buf + PIM_MSG_REGISTER_BIT_RESERVED_LEN);

	if (!if_address_is_local(&dest_addr, PIM_AF, pim->vrf->vrf_id)) {
		if (PIM_DEBUG_PIM_REG)
			zlog_debug(
				"%s: Received Register message for destination address: %pPA that I do not own",
				__func__, &dest_addr);
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
	memset(&sg, 0, sizeof(sg));
	sg = pim_sgaddr_from_iphdr(ip_hdr);

#if PIM_IPV == 6
	/*
	 * According to RFC section 4.9.3, If Dummy PIM Header is included
	 * in NULL Register as a payload there would be two PIM headers.
	 * The inner PIM Header's checksum field should also be validated
	 * in addition to the outer PIM Header's checksum. Validation of
	 * inner PIM header checksum is done here.
	 */
	if ((*bits & PIM_REGISTER_NR_BIT) &&
	    ((tlv_buf_size - PIM_MSG_REGISTER_BIT_RESERVED_LEN) >
	     (int)sizeof(struct ip6_hdr))) {
		uint16_t computed_checksum;
		uint16_t received_checksum;
		struct ipv6_ph ph;
		struct pim_msg_header *header;

		header = (struct pim_msg_header
				  *)(tlv_buf +
				     PIM_MSG_REGISTER_BIT_RESERVED_LEN +
				     sizeof(struct ip6_hdr));
		ph.src = sg.src;
		ph.dst = sg.grp;
		ph.ulpl = htonl(PIM_MSG_HEADER_LEN);
		ph.next_hdr = IPPROTO_PIM;

		received_checksum = header->checksum;

		header->checksum = 0;
		computed_checksum = in_cksum_with_ph6(
			&ph, header, htonl(PIM_MSG_HEADER_LEN));

		if (computed_checksum != received_checksum) {
			if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug(
					"Ignoring Null Register message%pSG from %pPA due to bad checksum in Encapsulated dummy PIM header",
					&sg, &src_addr);
			return 0;
		}
	}
#endif
	i_am_rp = I_am_RP(pim, sg.grp);

	if (PIM_DEBUG_PIM_REG)
		zlog_debug(
			"Received Register message%pSG from %pPA on %s, rp: %d",
			&sg, &src_addr, ifp->name, i_am_rp);

	if (pim_is_grp_ssm(pim_ifp->pim, sg.grp)) {
		if (pim_addr_is_any(sg.src)) {
			zlog_warn(
				"%s: Received Register message for Group(%pPA) is now in SSM, dropping the packet",
				__func__, &sg.grp);
			/* Drop Packet Silently */
			return 0;
		}
	}

	rpg = RP(pim, sg.grp);
	if (!rpg) {
		zlog_warn("%s: Received Register Message %pSG from %pPA on %s where the RP could not be looked up",
			  __func__, &sg, &src_addr, ifp->name);
		return 0;
	}

	rp_addr = rpg->rpf_addr;
	if (i_am_rp && (!pim_addr_cmp(dest_addr, rp_addr))) {
		sentRegisterStop = 0;

		if (pim->register_plist) {
			struct prefix_list *plist;
			struct prefix src;

			plist = prefix_list_lookup(PIM_AFI,
						   pim->register_plist);

			pim_addr_to_prefix(&src, sg.src);

			if (prefix_list_apply_ext(plist, NULL, &src, true) ==
			    PREFIX_DENY) {
				pim_register_stop_send(ifp, &sg, dest_addr,
						       src_addr);
				if (PIM_DEBUG_PIM_PACKETS)
					zlog_debug(
						"%s: Sending register-stop to %pPA for %pSG due to prefix-list denial, dropping packet",
						__func__, &src_addr, &sg);

				return 0;
			}
		}

		if (*bits & PIM_REGISTER_BORDER_BIT) {
			if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug(
					"%s: Received Register message with Border bit set, ignoring",
					__func__);

				/* Drop Packet Silently */
			return 0;
		}

		struct pim_upstream *upstream = pim_upstream_find(pim, &sg);
		/*
		 * If we don't have a place to send ignore the packet
		 */
		if (!upstream) {
			upstream = pim_upstream_add(
				pim, &sg, ifp,
				PIM_UPSTREAM_FLAG_MASK_SRC_STREAM, __func__,
				NULL);
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
		    || ((SwitchToSptDesiredOnRp(pim, &sg))
			&& pim_upstream_inherited_olist(pim, upstream) == 0)) {
			pim_register_stop_send(ifp, &sg, dest_addr, src_addr);
			sentRegisterStop = 1;
		} else {
			if (PIM_DEBUG_PIM_REG)
				zlog_debug("(%s) sptbit: %d", upstream->sg_str,
					   upstream->sptbit);
		}
		if ((upstream->sptbit == PIM_UPSTREAM_SPTBIT_TRUE)
		    || (SwitchToSptDesiredOnRp(pim, &sg))) {
			if (sentRegisterStop) {
				pim_upstream_keep_alive_timer_start(
					upstream, pim->rp_keep_alive_time);
			} else {
				pim_upstream_keep_alive_timer_start(
					upstream, pim->keep_alive_time);
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
				zlog_debug("Received Register packet for %pSG, Rejecting packet because I am not the RP configured for group",
					   &sg);
			else
				zlog_debug("Received Register packet for %pSG, Rejecting packet because the dst ip address is not the actual RP",
					   &sg);
		}
		pim_register_stop_send(ifp, &sg, dest_addr, src_addr);
	}

	return 0;
}

/*
 * This routine scan all upstream and update register state and remove pimreg
 * when couldreg becomes false.
 */
void pim_reg_del_on_couldreg_fail(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct pim_instance *pim;
	struct pim_upstream *up;

	if (!pim_ifp)
		return;

	pim = pim_ifp->pim;

	frr_each (rb_pim_upstream, &pim->upstream_head, up) {
		if (ifp != up->rpf.source_nexthop.interface)
			continue;

		if (!pim_upstream_could_register(up)
		    && (up->reg_state != PIM_REG_NOINFO)) {
			pim_channel_del_oif(up->channel_oil, pim->regiface,
					    PIM_OIF_FLAG_PROTO_PIM, __func__);
			EVENT_OFF(up->t_rs_timer);
			up->reg_state = PIM_REG_NOINFO;
			PIM_UPSTREAM_FLAG_UNSET_FHR(up->flags);
		}
	}
}
