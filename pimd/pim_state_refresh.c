// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * pim_state_refresh.c: PIM Dense Mode State Refresh
 *
 * Copyright (C) 2024 ATCorp
 * Jafar Al-Gharaibeh
 */

#include "pim_state_refresh.h"
#include "pim_iface.h"
#include "pim_oil.h"
#include "pim_msg.h"
#include "pim_neighbor.h"
#include "linklist.h"
#include "pim_instance.h"
#include "pim_int.h"
#include "pim_util.h"
#include "pim_macro.h"
#include "pim_dm.h"

static const uint8_t staterefresh_ttl = 16;

static void on_trace(const char *label, struct interface *ifp, pim_addr src)
{
	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("%s: from %pPAs on %s", label, &src, ifp->name);
}

int pim_staterefresh_recv(struct interface *ifp, pim_addr src_addr, uint8_t *buf, int buf_size)
{
	pim_sgaddr sg;
	pim_addr msg_source_addr;
	pim_addr msg_originator_addr;
	bool wrong_af = false;
	struct pim_assert_metric msg_metric;
	int offset;
	uint8_t *curr;
	int curr_size;
	struct pim_interface *pim_ifp = NULL, *pim_ifp2;
	struct pim_ifchannel *ch;
	struct listnode *neighnode;
	struct pim_neighbor *neigh;
	uint8_t pim_msg[1000];
	uint8_t p;
	int pim_msg_size;
	struct pim_upstream *up;
	struct interface *ifp2 = NULL;

	pim_ifp = ifp->info;

	on_trace(__func__, ifp, src_addr);

	curr = buf;
	curr_size = buf_size;

	/*
	 * Parse assert group addr
	 */
	memset(&sg, 0, sizeof(sg));
	offset = pim_parse_addr_group(&sg, curr, curr_size);
	if (offset < 1) {
		zlog_warn("%s: pim_parse_addr_group() failure: from %pPAs on %s", __func__,
			  &src_addr, ifp->name);
		return -1;
	}
	curr += offset;
	curr_size -= offset;

	/*
	 * Parse assert source addr
	 */
	offset = pim_parse_addr_ucast(&msg_source_addr, curr, curr_size, &wrong_af);
	if (offset < 1 || wrong_af) {
		zlog_warn("%s: pim_parse_addr_ucast() failure: from %pPAs on %s", __func__,
			  &src_addr, ifp->name);
		return -2;
	}
	curr += offset;
	curr_size -= offset;

	if (curr_size < 8) {
		zlog_warn("%s: preference/metric size is less than 8 bytes: size=%d from %pPAs on interface %s",
			  __func__, curr_size, &src_addr, ifp->name);
		return -3;
	}

	sg.src = msg_source_addr;
	up = pim_upstream_find(pim_ifp->pim, &sg);
	if (!up)
		return 0;

	/*
	 *Parse originator source addr
	 */
	offset = pim_parse_addr_ucast(&msg_originator_addr, curr, curr_size, &wrong_af);
	if (offset < 1 || wrong_af) {
		zlog_warn("%s: pim_parse_addr_ucast() failure: from %pPAs on %s", __func__,
			  &src_addr, ifp->name);
		return -2;
	}
	curr += offset;
	curr_size -= offset;

	if (curr_size < 8) {
		zlog_warn("%s: preference/metric size is less than 8 bytes: size=%d from %pPAs on interface %s",
			  __func__, curr_size, &src_addr, ifp->name);
		return -3;
	}

	/*
	 * Parse assert metric preference
	 */

	msg_metric.metric_preference = pim_read_uint32_host(curr);

	msg_metric.rpt_bit_flag = msg_metric.metric_preference & 0x80000000; /* save highest bit */
	msg_metric.metric_preference &= ~0x80000000;			     /* clear highest bit */

	curr += 4;

	/*
	 * Parse assert route metric
	 */

	msg_metric.route_metric = pim_read_uint32_host(curr);

	curr += 4;

	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("%s: from %pPAs on %s: (S,G)=(%pPAs,%pPAs) pref=%u metric=%u rpt_bit=%u",
			   __func__, &src_addr, ifp->name, &msg_source_addr, &sg.grp,
			   msg_metric.metric_preference, msg_metric.route_metric,
			   PIM_FORCE_BOOLEAN(msg_metric.rpt_bit_flag));

	msg_metric.ip_address = src_addr;

	struct pim_staterefresh_header *header = (struct pim_staterefresh_header *)curr;

	pim_ifp = ifp->info;
	assert(pim_ifp);

	if (pim_ifp->pim_passive_enable) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("skip receiving PIM message on passive interface %s", ifp->name);
		return 0;
	}

	header->ttl--;
	if (header->ttl < 1)
		return 0;
	if (up->rpf.source_nexthop.interface != ifp && (pim_addr_cmp(up->rpf.rpf_addr, src_addr)))
		return 0;

	/* TODO: condition StateRefreshRateLimit(S,G) not implemented yet!! */

	for (ALL_LIST_ELEMENTS_RO(pim_ifp->pim_neighbor_list, neighnode, neigh)) {
		if (!neigh->prefix_list)
			continue;

		pim_ifp2 = neigh->interface->info;
		if (pim_is_group_filtered(pim_ifp2, &up->sg.grp, &up->sg.src))
			continue;
		ch = pim_ifchannel_find(neigh->interface, &up->sg);
		if (!ch)
			p = 0;
		else {
			if (pim_macro_ch_lost_assert(ch))
				continue;
			p = PIM_UPSTREAM_DM_TEST_PRUNE(ch->flags);
		}

		if (p) {
			event_cancel(&ch->t_ifjoin_expiry_timer);
			event_add_timer(router->master, pim_dm_prune_iff_on_timer, ch,
					ch->prune_holdtime, &ch->t_ifjoin_expiry_timer);
		}

		pim_msg_size =
			pim_staterefresh_build_msg(pim_msg, sizeof(pim_msg), neigh->interface,
						   up->sg.grp, up->sg.src, pim_ifp2->primary_address,
						   up->rpf.source_nexthop.mrib_metric_preference,
						   up->rpf.source_nexthop.mrib_route_metric, 0,
						   IPV4_MAX_BITLEN, header->ttl, p, header->n, 1, 0,
						   pim_ifp2->pim->staterefresh_time);

		if (pim_msg_send(pim_ifp2->pim_sock_fd, pim_ifp2->primary_address,
				 neigh->source_addr, pim_msg, pim_msg_size, ifp2)) {
			zlog_warn("%s: could not send PIM message on interface %s", __func__,
				  ifp->name);
		}
	}

	return 0;
}


int pim_staterefresh_build_msg(uint8_t *pim_msg, int buf_size, struct interface *ifp,
			       pim_addr group_addr, pim_addr source_addr, pim_addr originator_addr,
			       uint32_t metric_preference, uint32_t route_metric,
			       uint32_t rpt_bit_flag, uint8_t masklen, uint8_t ttl, bool p, bool n,
			       bool o, uint8_t reserved, uint8_t interval)
{
	struct pim_interface *pim_ifp = ifp->info;
	uint8_t *buf_pastend = pim_msg + buf_size;
	uint8_t *pim_msg_curr;
	int pim_msg_size;
	int remain;

	pim_msg_curr = pim_msg + PIM_MSG_HEADER_LEN; /* skip room for pim header */

	/* Encode group */
	remain = buf_pastend - pim_msg_curr;
	// pim_msg_curr = pim_msg_addr_encode_ucast(pim_msg_curr, group_addr);
	pim_msg_curr = pim_msg_addr_encode_group(pim_msg_curr, group_addr);
	if (!pim_msg_curr) {
		zlog_warn("%s: failure encoding group address %pPA: space left=%d", __func__,
			  &group_addr, remain);
		return -1;
	}

	/* Encode source */
	remain = buf_pastend - pim_msg_curr;
	pim_msg_curr = pim_msg_addr_encode_ucast(pim_msg_curr, source_addr);
	if (!pim_msg_curr) {
		zlog_warn("%s: failure encoding source address %pPA: space left=%d", __func__,
			  &source_addr, remain);
		return -2;
	}
	/* Originator Address*/

	remain = buf_pastend - pim_msg_curr;
	pim_msg_curr = pim_msg_addr_encode_ucast(pim_msg_curr, originator_addr);
	if (!pim_msg_curr) {
		zlog_warn("%s: failure encoding source address %pPA: space left=%d", __func__,
			  &originator_addr, remain);
		return -2;
	}

	/* Metric preference */
	pim_write_uint32(pim_msg_curr,
			 rpt_bit_flag ? metric_preference | 0x80000000 : metric_preference);
	pim_msg_curr += 4;

	/* Route metric */
	pim_write_uint32(pim_msg_curr, route_metric);
	pim_msg_curr += 4;

	/* add last header */

	struct pim_staterefresh_header *header = (struct pim_staterefresh_header *)pim_msg_curr;

	header->masklen = masklen;
	header->ttl = ttl;
	header->p = p;
	header->n = n;
	header->o = o;
	header->reserved = reserved;
	header->Interval = interval;

	pim_msg_curr += 4;

	/* Add PIM header */
	pim_msg_size = pim_msg_curr - pim_msg;
	pim_msg_build_header(pim_ifp->primary_address, qpim_all_pim_routers_addr, pim_msg,
			     pim_msg_size, PIM_MSG_TYPE_STATE_REFRESH, false);

	return pim_msg_size;
}

void pim_send_staterefresh(struct pim_upstream *up)
{
	uint8_t pim_msg[1000];
	uint8_t p, n;
	int pim_msg_size;
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp, *ifp2 = NULL;
	struct pim_interface *pim_ifp2;
	struct pim_ifchannel *ch;
	struct listnode *neighnode;
	struct pim_neighbor *neigh;

	ifp = pim_if_find_by_vif_index(up->pim, *oil_incoming_vif(up->channel_oil));
	if (!ifp) {
		if (PIM_DEBUG_PIM_EVENTS)
			zlog_debug("%s: could not find input interface for oil_incoming_vif=%d",
				   __func__, *oil_incoming_vif(up->channel_oil));
		return;
	}
	if (up->pim->staterefresh_counter < 3) {
		up->pim->staterefresh_counter++;
		n = 0;

	} else {
		n = 1;
		up->pim->staterefresh_counter = 0;
	}
	FOR_ALL_INTERFACES (vrf, ifp2) {
		pim_ifp2 = ifp2->info;

		if (!pim_ifp2 || !pim_ifp2->pim_enable ||
		    pim_is_group_filtered(pim_ifp2, &up->sg.grp, &up->sg.src))
			continue;

		if (HAVE_DENSE_MODE(pim_ifp2->pim_mode) && ifp2->ifindex != ifp->ifindex) {
			ch = pim_ifchannel_find(ifp2, &up->sg);
			if (!ch)
				p = 0;
			else
				p = PIM_UPSTREAM_DM_TEST_PRUNE(ch->flags);

			pim_msg_size =
				pim_staterefresh_build_msg(pim_msg, sizeof(pim_msg), ifp2,
							   up->sg.grp, up->sg.src,
							   pim_ifp2->primary_address,
							   up->rpf.source_nexthop
								   .mrib_metric_preference,
							   up->rpf.source_nexthop.mrib_route_metric,
							   0, IPV4_MAX_BITLEN, staterefresh_ttl, p,
							   n, 1, 0,
							   pim_ifp2->pim->staterefresh_time);

			for (ALL_LIST_ELEMENTS_RO(pim_ifp2->pim_neighbor_list, neighnode, neigh)) {
				if (!neigh->prefix_list)
					continue;

				if (pim_msg_send(pim_ifp2->pim_sock_fd, pim_ifp2->primary_address,
						 neigh->source_addr, pim_msg, pim_msg_size, ifp2)) {
					zlog_warn("%s: could not send PIM message on interface %s",
						  __func__, ifp->name);
				}
			}
		}
	}
}
