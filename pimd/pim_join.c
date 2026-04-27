// SPDX-License-Identifier: GPL-2.0-or-later


/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include "log.h"
#include "prefix.h"
#include "if.h"
#include "vty.h"
#include "plist.h"

#include "pimd.h"
#include "pim_instance.h"
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
#include "pim_jp_agg.h"
#include "pim_util.h"
#include "pim_ssm.h"
#include "pim_dm.h"

static void on_trace(const char *label, struct interface *ifp, pim_addr src)
{
	if (PIM_DEBUG_PIM_TRACE)
		zlog_debug("%s: from %pPA on %s", label, &src, ifp->name);
}

static void recv_join(struct interface *ifp, struct pim_neighbor *neigh, uint16_t holdtime,
		      pim_addr upstream, pim_sgaddr *sg, uint8_t source_flags)
{
	struct pim_interface *pim_ifp = NULL;
#if PIM_IPV == 6
	pim_addr embedded_rp;
#endif /* PIM_IPV == 6 */

	if (PIM_DEBUG_PIM_J_P)
		zlog_debug(
			"%s: join (S,G)=%pSG rpt=%d wc=%d upstream=%pPAs holdtime=%d from %pPA on %s",
			__func__, sg, !!(source_flags & PIM_RPT_BIT_MASK),
			!!(source_flags & PIM_WILDCARD_BIT_MASK), &upstream,
			holdtime, &neigh->source_addr, ifp->name);

	pim_ifp = ifp->info;

#if PIM_IPV == 6
	if (pim_ifp->pim->embedded_rp.enable && pim_embedded_rp_extract(&sg->grp, &embedded_rp) &&
	    !pim_embedded_rp_filter_match(pim_ifp->pim, &sg->grp))
		pim_embedded_rp_new(pim_ifp->pim, &sg->grp, &embedded_rp);
#endif /* PIM_IPV == 6 */

	++pim_ifp->pim_ifstat_join_recv;

	/*
	 * If the RPT and WC are set it's a (*,G)
	 * and the source is the RP
	 */
	if (CHECK_FLAG(source_flags, PIM_WILDCARD_BIT_MASK)) {
		/* As per RFC 7761 Section 4.9.1:
		 * The RPT (or Rendezvous Point Tree) bit is a 1-bit value for
		 * use with PIM Join/Prune messages (see Section 4.9.5.1). If
		 * the WC bit is 1, the RPT bit MUST be 1.
		 */
		if (!CHECK_FLAG(source_flags, PIM_RPT_BIT_MASK)) {
			if (PIM_DEBUG_PIM_J_P)
				zlog_debug(
					"Discarding (*,G)=%pSG join since WC bit is set but RPT bit is unset",
					sg);

			return;
		}

		struct pim_rpf *rp = RP(pim_ifp->pim, sg->grp);
		pim_addr rpf_addr;

		if (!rp) {
			zlog_warn("%s: Lookup of RP failed for %pSG", __func__,
				  sg);
			return;
		}

		/*
		 * If the RP sent in the message is not our RP for the group,
		 * drop the message - unless the user has specified the
		 * allow-rp option, which means we skip this check and use our
		 * RP instead, provided policy allows it. This latter bit is a
		 * non-RFC-compliant option.
		 */
		rpf_addr = rp->rpf_addr;
		if (pim_addr_cmp(sg->src, rpf_addr) && !pim_is_rp_allowed(pim_ifp, &sg->src)) {
			zlog_warn(
				"%s: Specified RP(%pPAs) in join is different than our configured RP(%pPAs)",
				__func__, &sg->src, &rpf_addr);
			return;
		}

		if (pim_is_grp_ssm(pim_ifp->pim, sg->grp)) {
			zlog_warn(
				"%s: Specified Group(%pPA) in join is now in SSM, not allowed to create PIM state",
				__func__, &sg->grp);
			return;
		}

		sg->src = PIMADDR_ANY;
	}
	if (pim_iface_grp_dm(pim_ifp, sg->grp)) {
		zlog_warn("%s: Specified Group(%pPA) in join is now in DM, not allowed to create PIM state",
			  __func__, &sg->grp);
		return;
	}

	/* Restart join expiry timer */
	pim_ifchannel_join_add(ifp, neigh->source_addr, upstream, sg,
			       source_flags, holdtime);
}

static void recv_prune(struct interface *ifp, struct pim_neighbor *neigh,
		       uint16_t holdtime, pim_addr upstream, pim_sgaddr *sg,
		       uint8_t source_flags)
{
	struct pim_interface *pim_ifp = NULL;

	if (PIM_DEBUG_PIM_J_P)
		zlog_debug(
			"%s: prune (S,G)=%pSG rpt=%d wc=%d upstream=%pPAs holdtime=%d from %pPA on %s",
			__func__, sg, source_flags & PIM_RPT_BIT_MASK,
			source_flags & PIM_WILDCARD_BIT_MASK, &upstream,
			holdtime, &neigh->source_addr, ifp->name);

	pim_ifp = ifp->info;

	++pim_ifp->pim_ifstat_prune_recv;


	pim_dm_recv_prune(ifp, neigh, holdtime, upstream, sg, source_flags);

	if (CHECK_FLAG(source_flags, PIM_WILDCARD_BIT_MASK)) {
		/* As per RFC 7761 Section 4.9.1:
		 * The RPT (or Rendezvous Point Tree) bit is a 1-bit value for
		 * use with PIM Join/Prune messages (see Section 4.9.5.1). If
		 * the WC bit is 1, the RPT bit MUST be 1.
		 */
		if (!CHECK_FLAG(source_flags, PIM_RPT_BIT_MASK)) {
			if (PIM_DEBUG_PIM_J_P)
				zlog_debug(
					"Discarding (*,G)=%pSG prune since WC bit is set but RPT bit is unset",
					sg);

			return;
		}

		/*
		 * RFC 4601 Section 4.5.2:
		 * Received Prune(*,G) messages are processed even if the
		 * RP in the message does not match RP(G).
		 */
		if (PIM_DEBUG_PIM_J_P)
			zlog_debug("%s: Prune received with RP(%pPAs) for %pSG",
				   __func__, &sg->src, sg);

		sg->src = PIMADDR_ANY;
	}

	pim_ifchannel_prune(ifp, upstream, sg, source_flags, holdtime);
}

int pim_joinprune_recv(struct interface *ifp, struct pim_neighbor *neigh,
		       pim_addr src_addr, uint8_t *tlv_buf, int tlv_buf_size)
{
	pim_addr msg_upstream_addr;
	bool wrong_af = false;
	struct pim_interface *pim_ifp;
	uint8_t msg_num_groups;
	uint16_t msg_holdtime;
	int addr_offset;
	uint8_t *buf;
	uint8_t *pastend;
	int remain;
	int group;
	struct pim_ifchannel *child = NULL;
	struct listnode *ch_node, *nch_node;

	buf = tlv_buf;
	pastend = tlv_buf + tlv_buf_size;
	pim_ifp = ifp->info;

	if (pim_ifp->pim_passive_enable) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"skip receiving PIM message on passive interface %s",
				ifp->name);
		return 0;
	}

	/*
	  Parse ucast addr
	*/
	addr_offset = pim_parse_addr_ucast(&msg_upstream_addr, buf,
					   pastend - buf, &wrong_af);
	if (addr_offset < 1) {
		zlog_warn("%s: pim_parse_addr_ucast() failure: from %pPA on %s",
			  __func__, &src_addr, ifp->name);
		return -1;
	}
	buf += addr_offset;

	/*
	  Check upstream address family
	 */
	if (wrong_af) {
		zlog_warn(
			"%s: ignoring join/prune directed to unexpected addr family from %pPA on %s",
			__func__, &src_addr, ifp->name);
		return -2;
	}

	remain = pastend - buf;
	if (remain < 4) {
		zlog_warn(
			"%s: short join/prune message buffer for group list: size=%d minimum=%d from %pPA on %s",
			__func__, remain, 4, &src_addr, ifp->name);
		return -4;
	}

	++buf; /* skip reserved byte */
	msg_num_groups = *(const uint8_t *)buf;
	++buf;
	msg_holdtime = ntohs(*(const uint16_t *)buf);
	++buf;
	++buf;

	if (PIM_DEBUG_PIM_J_P)
		zlog_debug(
			"%s: join/prune upstream=%pPAs groups=%d holdtime=%d from %pPA on %s",
			__func__, &msg_upstream_addr, msg_num_groups,
			msg_holdtime, &src_addr, ifp->name);

	/* Scan groups */
	for (group = 0; group < msg_num_groups; ++group) {
		pim_sgaddr sg;
		uint8_t msg_source_flags;
		uint16_t msg_num_joined_sources;
		uint16_t msg_num_pruned_sources;
		int source;
		struct pim_ifchannel *starg_ch = NULL, *sg_ch = NULL;
		bool group_filtered = false;

		memset(&sg, 0, sizeof(sg));
		addr_offset = pim_parse_addr_group(&sg, buf, pastend - buf);
		if (addr_offset < 1) {
			return -5;
		}
		buf += addr_offset;

		remain = pastend - buf;
		if (remain < 4) {
			zlog_warn(
				"%s: short join/prune buffer for source list: size=%d minimum=%d from %pPA on %s",
				__func__, remain, 4, &src_addr, ifp->name);
			return -6;
		}

		msg_num_joined_sources = ntohs(*(const uint16_t *)buf);
		buf += 2;
		msg_num_pruned_sources = ntohs(*(const uint16_t *)buf);
		buf += 2;

		if (PIM_DEBUG_PIM_J_P)
			zlog_debug(
				"%s: join/prune upstream=%pPAs group=%pPA/32 join_src=%d prune_src=%d from %pPA on %s",
				__func__, &msg_upstream_addr, &sg.grp,
				msg_num_joined_sources, msg_num_pruned_sources,
				&src_addr, ifp->name);

		remain = (pastend - buf) / sizeof(pim_encoded_source);
		if (msg_num_joined_sources > remain) {
			zlog_warn("%s: short join buffer for source list: size=%d minimum=%d from %pPA on %s",
				  __func__, remain, msg_num_joined_sources, &src_addr, ifp->name);
			return -6;
		}
		/* boundary check */
		group_filtered = pim_is_group_filtered(pim_ifp, &sg.grp, NULL);

		/* Scan joined sources */
		for (source = 0; source < msg_num_joined_sources; ++source) {
			struct prefix_sg psg;

			addr_offset = pim_parse_addr_source(
				&sg, &msg_source_flags, buf, pastend - buf);
			if (addr_offset < 1) {
				return -7;
			}

			buf += addr_offset;

			/* if we are filtering this group or (S,G), skip the join */
			if (group_filtered || pim_is_group_filtered(pim_ifp, &sg.grp, &sg.src))
				continue;

			pim_sg_to_prefix(&sg, &psg);
			if (!pim_filter_match(&pim_ifp->pim->join_filter, &psg, ifp, ifp)) {
				if (PIM_DEBUG_PIM_TRACE)
					zlog_debug("%s: SG%pPSG on interface %s filtered due to route-map",
						   __func__, &psg, ifp->name);
				continue;
			}

			recv_join(ifp, neigh, msg_holdtime, msg_upstream_addr, &sg,
				  msg_source_flags);

			if (pim_addr_is_any(sg.src)) {
				struct pim_ifchannel *throwaway;

				pim_ifchannel_find(ifp, &sg, &starg_ch, &throwaway);
				if (starg_ch)
					pim_ifchannel_set_star_g_join_state(
						starg_ch, 0, 1);
			}
		}

		remain = (pastend - buf) / sizeof(pim_encoded_source);
		if (msg_num_pruned_sources > remain) {
			zlog_warn("%s: short prune buffer for source list: size=%d minimum=%d from %pPA on %s",
				  __func__, remain, msg_num_pruned_sources, &src_addr, ifp->name);
			return -6;
		}

		/* Scan pruned sources */
		for (source = 0; source < msg_num_pruned_sources; ++source) {
			struct pim_ifchannel *throwaway;

			addr_offset = pim_parse_addr_source(
				&sg, &msg_source_flags, buf, pastend - buf);
			if (addr_offset < 1) {
				return -8;
			}

			buf += addr_offset;

			recv_prune(ifp, neigh, msg_holdtime, msg_upstream_addr,
				   &sg, msg_source_flags);
			/*
			 * So if we are receiving a S,G,RPT prune
			 * before we have any data for that S,G
			 * We need to retrieve the sg_ch after
			 * we parse the prune.
			 */
			pim_ifchannel_find(ifp, &sg, &sg_ch, &throwaway);

			if (!sg_ch)
				continue;

			/* (*,G) prune received */
			for (ALL_LIST_ELEMENTS(sg_ch->sources, ch_node,
					       nch_node, child)) {
				if (pim_ifchannel_is_sg_rpt(child)) {
					if (child->ifjoin_state
					    == PIM_IFJOIN_PRUNE_PENDING_TMP)
						event_cancel(&
							child->t_ifjoin_prune_pending_timer);
					event_cancel(&child->t_ifjoin_expiry_timer);
					child->ifjoin_state = PIM_IFJOIN_NOINFO;
					delete_on_noinfo(child);
				}
			}

			/* Received SG-RPT Prune delete oif from specific S,G */
			if (starg_ch && (msg_source_flags & PIM_RPT_BIT_MASK)
			    && !(msg_source_flags & PIM_WILDCARD_BIT_MASK)) {
				struct pim_upstream *up = sg_ch->upstream;
				if (up) {
					if (PIM_DEBUG_PIM_TRACE)
						zlog_debug(
							"%s: SGRpt flag is set, del inherit oif from up %s",
							__func__, up->sg_str);
					pim_channel_del_inherited_oif(
						up->channel_oil,
						starg_ch->interface,
						__func__);
				}
			}
		}
		if (starg_ch && !group_filtered)
			pim_ifchannel_set_star_g_join_state(starg_ch, 1, 0);
		starg_ch = NULL;
	} /* scan groups */

	return 0;
}


int pim_graft_recv(struct interface *ifp, struct pim_neighbor *neigh, pim_addr src_addr,
		   uint8_t *tlv_buf, int tlv_buf_size, uint8_t pim_msg_type)
{
	pim_addr msg_upstream_addr;
	bool wrong_af = false;
	struct pim_interface *pim_ifp;
	uint8_t msg_num_groups;
	uint16_t msg_holdtime;
	int addr_offset;
	uint8_t *buf;
	uint8_t *pastend;
	int remain;
	int group;
	struct pim_upstream *up;

	buf = tlv_buf;
	pastend = tlv_buf + tlv_buf_size;
	pim_ifp = ifp->info;

	if (pim_ifp->pim_passive_enable) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("skip receiving PIM message on passive interface %s", ifp->name);
		return 0;
	}

	/*
	 * Parse ucast addr
	 */
	addr_offset = pim_parse_addr_ucast(&msg_upstream_addr, buf, pastend - buf, &wrong_af);
	if (addr_offset < 1) {
		zlog_warn("%s: pim_parse_addr_ucast() failure: from %pPA on %s", __func__,
			  &src_addr, ifp->name);
		return -1;
	}
	buf += addr_offset;

	/*
	 * Check upstream address family
	 */
	if (wrong_af) {
		zlog_warn("%s: ignoring join/prune directed to unexpected addr family from %pPA on %s",
			  __func__, &src_addr, ifp->name);
		return -2;
	}

	remain = pastend - buf;
	if (remain < 4) {
		zlog_warn("%s: short join/prune message buffer for group list: size=%d minimum=%d from %pPA on %s",
			  __func__, remain, 4, &src_addr, ifp->name);
		return -4;
	}

	++buf; /* skip reserved byte */
	msg_num_groups = *(const uint8_t *)buf;
	++buf;
	msg_holdtime = ntohs(*(const uint16_t *)buf);
	++buf;
	++buf;

	if (PIM_DEBUG_GRAFT)
		zlog_debug("%s: graft upstream=%pPAs groups=%d holdtime=%d from %pPA on %s",
			   __func__, &msg_upstream_addr, msg_num_groups, msg_holdtime, &src_addr,
			   ifp->name);

	/* Scan groups */
	for (group = 0; group < msg_num_groups; ++group) {
		pim_sgaddr sg;
		uint8_t msg_source_flags;
		uint16_t msg_num_joined_sources;
		uint16_t msg_num_pruned_sources;
		int source;
		bool group_filtered = false;

		memset(&sg, 0, sizeof(sg));
		addr_offset = pim_parse_addr_group(&sg, buf, pastend - buf);
		if (addr_offset < 1)
			return -5;

		buf += addr_offset;

		remain = pastend - buf;
		if (remain < 4) {
			zlog_warn("%s: short graft buffer for source list: size=%d minimum=%d from %pPA on %s",
				  __func__, remain, 4, &src_addr, ifp->name);
			return -6;
		}

		msg_num_joined_sources = ntohs(*(const uint16_t *)buf);
		buf += 2;
		msg_num_pruned_sources = ntohs(*(const uint16_t *)buf);
		buf += 2;

		if (PIM_DEBUG_GRAFT)
			zlog_debug("%s: graft upstream=%pPAs group=%pPA/32 join_src=%d prune_src=%d from %pPA on %s",
				   __func__, &msg_upstream_addr, &sg.grp, msg_num_joined_sources,
				   msg_num_pruned_sources, &src_addr, ifp->name);

		remain = (pastend - buf) / sizeof(pim_encoded_source);
		if (msg_num_joined_sources > remain) {
			zlog_warn("%s: short graft join buffer for source list: remaining=%d minimum=%d from %pPA on %s",
				  __func__, remain, msg_num_joined_sources, &src_addr, ifp->name);
			return -6;
		}

		/* sanity and boundary check */
		group_filtered = !pim_addr_is_multicast(sg.grp) ||
				 pim_is_group_filtered(pim_ifp, &sg.grp, &sg.src);

		/* Scan joined sources */
		for (source = 0; source < msg_num_joined_sources; ++source) {
			addr_offset = pim_parse_addr_source(&sg, &msg_source_flags, buf,
							    pastend - buf);
			if (addr_offset < 1)
				return -7;

			buf += addr_offset;

			/* if we are filtering this group or (S,G), skip the graft */
			if (group_filtered || pim_is_group_filtered(pim_ifp, &sg.grp, &sg.src))
				continue;

			if (pim_msg_type == PIM_MSG_TYPE_GRAFT)
				pim_dm_recv_graft(ifp, &sg);
			else if (pim_msg_type == PIM_MSG_TYPE_GRAFT_ACK) {
				up = pim_upstream_find(pim_ifp->pim, &sg);
				if (up)
					event_cancel(&up->t_graft_timer);
			}
		}

		/* Graft msg shouldn't have prune, but just in case, skip and log */
		if (msg_num_pruned_sources) {
			remain = (pastend - buf) / sizeof(pim_encoded_source);
			if (msg_num_pruned_sources > remain) {
				zlog_warn("%s: short graft prune buffer for source list: remaining=%d minimum=%d from %pPA on %s",
					  __func__, remain, msg_num_pruned_sources, &src_addr,
					  ifp->name);
				return -6;
			}

			if (PIM_DEBUG_GRAFT)
				zlog_debug("%s: ignore prune in graft msg, upstream=%pPAs group=%pPA/32 join_src=%d prune_src=%d from %pPA on %s",
					   __func__, &msg_upstream_addr, &sg.grp,
					   msg_num_joined_sources, msg_num_pruned_sources,
					   &src_addr, ifp->name);

			buf += msg_num_pruned_sources * sizeof(pim_encoded_source);
		}

	} /* scan groups */

	return 0;
}

/*
 * Auxiliary function that sets the upstream RPT prune flag on some
 * circumstances. This is meant to be used in the function
 * `pim_joinprune_send`.
 */
static void pim_jp_groups_source_set_prune(struct list *sources)
{
	struct pim_upstream *child, *upstream;
	struct pim_jp_sources *js;
	struct listnode *node;

	if (!sources)
		return;

	js = listgetdata(listhead(sources));
	if (!js || !pim_addr_is_any(js->up->sg.src) || !js->is_join)
		return;

	upstream = js->up;
	if (PIM_DEBUG_PIM_PACKETS)
		zlog_debug("%s: Considering (%s) children for (S,G,rpt) prune", __func__,
			   upstream->sg_str);

	for (ALL_LIST_ELEMENTS_RO(upstream->sources, node, child)) {
		/*
		 * PIM VXLAN is weird
		 * It auto creates the S,G and populates a bunch
		 * of flags that make it look like a SPT prune should
		 * be sent.  But this regularly scheduled join
		 * for the *,G in the VXLAN setup can happen at
		 * scheduled times *before* the null register
		 * is received by the RP to cause it to initiate
		 * the S,G joins toward the source.  Let's just
		 * assume that if this is a SRC VXLAN ORIG route
		 * and no actual ifchannels( joins ) have been
		 * created then do not send the embedded prune
		 * Why you may ask?  Well if the prune is S,G
		 * RPT Prune is received *before* the join
		 * from the RP( if it flows to this routers
		 * upstream interface ) then we'll just wisely
		 * create a mroute with an empty oil on
		 * the upstream intermediate router preventing
		 * packets from flowing to the RP
		 */
		if (PIM_UPSTREAM_FLAG_TEST_SRC_VXLAN_ORIG(child->flags) &&
		    listcount(child->ifchannels) == 0) {
			if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug("%s: %s Vxlan originated S,G route with no ifchannels, not adding prune to compound message",
					   __func__, child->sg_str);
		} else if (!PIM_UPSTREAM_FLAG_TEST_USE_RPT(child->flags)) {
			/* If we are using SPT and the SPT and RPT IIFs
			 * are different we can prune the source off
			 * of the RPT.
			 * If RPF_interface(S) is not resolved hold
			 * decision to prune as SPT may end up on the
			 * same IIF as RPF_interface(RP).
			 */
			if (child->rpf.source_nexthop.interface &&
			    !pim_rpf_is_same(&upstream->rpf, &child->rpf)) {
				PIM_UPSTREAM_FLAG_SET_SEND_SG_RPT_PRUNE(child->flags);
				if (PIM_DEBUG_PIM_PACKETS)
					zlog_debug("%s: SPT Bit and RPF'(%s) != RPF'(S,G): Add Prune (%s,rpt) to compound message",
						   __func__, upstream->sg_str, child->sg_str);
			} else if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug("%s: SPT Bit and RPF'(%s) == RPF'(S,G): Not adding Prune for (%s,rpt)",
					   __func__, upstream->sg_str, child->sg_str);
		} else if (pim_upstream_empty_inherited_olist(child)) {
			/* S is supposed to be forwarded along the RPT
			 * but it's inherited OIL is empty. So just
			 * prune it off.
			 */
			PIM_UPSTREAM_FLAG_SET_SEND_SG_RPT_PRUNE(child->flags);
			if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug("%s: inherited_olist(%s,rpt) is NULL, Add Prune to compound message",
					   __func__, child->sg_str);
		} else if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: Do not add Prune %s to compound message %s", __func__,
				   child->sg_str, upstream->sg_str);
	}
}

/* Auxiliary function to write the source child data. This is meant to be
 * used by the function `pim_jp_groups_fill`.
 *
 * Returns `true` when buffer is full otherwise `false`.
 */
static bool pim_jp_groups_source_child_fill(struct pim_jp_groups *grp, size_t *tgroups,
					    size_t *bytes_written, size_t *bytes_left,
					    struct listnode *source_node,
					    struct listnode *child_node,
					    struct listnode **last_source,
					    struct listnode **last_child)
{
	for (; child_node != NULL; child_node = listnextnode(child_node)) {
		struct pim_upstream *child = listgetdata(child_node);

		if (!PIM_UPSTREAM_FLAG_TEST_SEND_SG_RPT_PRUNE(child->flags))
			continue;

		if (*bytes_left < sizeof(pim_encoded_source)) {
			*last_source = source_node;
			*last_child = child_node;
			return true;
		}

		*bytes_written += sizeof(pim_encoded_source);
		*bytes_left -= sizeof(pim_encoded_source);

		pim_msg_addr_encode_source((uint8_t *)&grp->s[*tgroups], child->sg.src,
					   PIM_ENCODE_SPARSE_BIT | PIM_ENCODE_RPT_BIT);
		*tgroups += 1;
		PIM_UPSTREAM_FLAG_UNSET_SEND_SG_RPT_PRUNE(child->flags);
		grp->prunes++;
	}

	return false;
}

/*
 * Auxiliary function that fills packet with group information and
 * returns the amount of bytes written. This is meant to be used in
 * the function `pim_joinprune_send`.
 *
 * If the amount of sources exceed the current packet limit, then this
 * function also returns `last_source` and/or `last_child`.
 *
 * When this function returns `last_child` but not `last_source` it means we
 * finished iterating over source list but not over upstream source list.
 *
 * **NOTE** Don't forget to converge `grp->joins` and `grp->prunes` to
 * network byte order before sending.
 */
static size_t pim_jp_groups_fill(struct pim_jp_groups *grp, struct pim_jp_agg_group *sgs,
				 size_t bytes_left, struct listnode **last_source,
				 struct listnode **last_child)
{
	struct listnode *source_node, *child_node;
	struct pim_upstream *upstream = NULL;
	size_t bytes_written = 0;
	size_t tgroups = 0;
	uint8_t bits;
	pim_addr stosend;

	memset(grp, 0, sizeof(*grp));
	pim_msg_addr_encode_group((uint8_t *)&grp->g, sgs->group);

	bytes_written += sizeof(pim_encoded_group);
	bytes_written += 4; // Joined sources (2) + Pruned Sources (2)
	/*
	 * Underflow protection, tell caller we didn't write anything
	 * this should cause the current packet to be flushed.
	 *
	 * Also include at least one encoded source to avoid empty group.
	 */
	if (bytes_left < bytes_written + sizeof(pim_encoded_source))
		return 0;

	bytes_left -= bytes_written;

	/*
	 * Get pointer to last source we stopped.
	 *
	 * When group sources are done `last_child` is set, but
	 * `last_source` is NULL.
	 */
	if (*last_source != NULL || *last_child != NULL)
		source_node = *last_source;
	else
		source_node = listhead(sgs->sources);

	/* Finish previously remaining upstream child sources */
	if (*last_child != NULL) {
		child_node = *last_child;

		if (pim_jp_groups_source_child_fill(grp, &tgroups, &bytes_written, &bytes_left,
						    source_node, child_node, last_source,
						    last_child))
			return bytes_written;
	}

	for (; source_node != NULL; source_node = listnextnode(source_node)) {
		struct pim_jp_sources *source = listgetdata(source_node);

		upstream = NULL;

		if (bytes_left < sizeof(pim_encoded_source)) {
			*last_source = source_node;
			*last_child = NULL;
			return bytes_written;
		}

		bytes_written += sizeof(pim_encoded_source);
		bytes_left -= sizeof(pim_encoded_source);

		if (pim_addr_is_any(source->up->sg.src)) {
			struct pim_instance *pim = source->up->pim;
			struct pim_rpf *rpf = pim_rp_g(pim, source->up->sg.grp);

			bits = PIM_ENCODE_SPARSE_BIT | PIM_ENCODE_WC_BIT | PIM_ENCODE_RPT_BIT;
			stosend = rpf->rpf_addr;
			/* Only Send SGRpt in case of *,G Join */
			if (source->is_join)
				upstream = source->up;
		} else if (pim_is_grp_dm(source->up->pim, source->up->sg.grp)) {
			bits = 0; /* all bits should be set to 0 for DM (RFC3973 4.7.4) */
			stosend = source->up->sg.src;
		} else {
			bits = PIM_ENCODE_SPARSE_BIT;
			stosend = source->up->sg.src;
		}

		pim_msg_addr_encode_source((uint8_t *)&grp->s[tgroups], stosend, bits);
		tgroups++;

		if (source->is_join)
			grp->joins++;
		else
			grp->prunes++;

		/* We found upstream sources, start this function over */
		if (upstream && listhead(upstream->sources)) {
			child_node = listhead(upstream->sources);

			/*
			 * Pass the next source so that on overflow
			 * `*last_source` records where to resume — the
			 * current source has already been encoded.
			 */
			if (pim_jp_groups_source_child_fill(grp, &tgroups, &bytes_written,
							    &bytes_left, listnextnode(source_node),
							    child_node, last_source, last_child))
				return bytes_written;
		}
	}

	*last_source = NULL;
	*last_child = NULL;

	return bytes_written;
}

/*
 * Auxiliary function that sends a packet. This is meant to be used in
 * `pim_joinprune_send`.
 */
static void pim_jp_flush_packet(struct interface *ifp, uint8_t pim_msg_type, void *buf,
				size_t buf_size)
{
	struct pim_interface *pim_ifp = ifp->info;

	pim_msg_build_header(pim_ifp->primary_address, qpim_all_pim_routers_addr, buf, buf_size,
			     pim_msg_type, false);
	if (pim_msg_send(pim_ifp->pim_sock_fd, pim_ifp->primary_address, qpim_all_pim_routers_addr,
			 buf, buf_size, ifp))
		zlog_warn("%s: could not send PIM message on interface %s", __func__, ifp->name);
}

#define PIM_JP_HEADER_SIZE                                                                        \
	(sizeof(struct pim_msg_header) + sizeof(pim_encoded_unicast) +                            \
	 4 /* reserved (1) + groups (1) + holdtime (2) */)

/* Size of IP header plus IP Router Alert */
#if PIM_IPV == 4
#define PIM_IP_HEADER_SIZE (sizeof(struct ip) + 4)
#else
#define PIM_IP_HEADER_SIZE (sizeof(struct ip6_hdr) + 8)
#endif

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
 * This leads to a misleading representation from casual
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
static int pim_jp_send(struct pim_rpf *rpf, struct list *groups, uint8_t pim_msg_type,
		       uint16_t holdtime)
{
	struct listnode *node, *last_source, *last_child;
	struct pim_jp_agg_group *group;
	struct pim_interface *pim_ifp;
	struct pim_jp_groups *grp;
	struct pim_jp *msg;
	struct interface *ifp;
	size_t packet_left = 0;
	size_t packet_size = 0;
	size_t group_written;
	size_t packet_max_size;
	uint8_t pim_msg[10000];

	ifp = rpf->source_nexthop.interface;
	if (ifp)
		pim_ifp = rpf->source_nexthop.interface->info;
	else {
		zlog_warn("%s: RPF interface is not present", __func__);
		return -1;
	}

	on_trace(__func__, rpf->source_nexthop.interface, rpf->rpf_addr);

	if (!pim_ifp) {
		zlog_warn("%s: multicast not enabled on interface %s", __func__,
			  rpf->source_nexthop.interface->name);
		return -1;
	}

	if (pim_addr_is_any(rpf->rpf_addr)) {
		if (PIM_DEBUG_PIM_J_P)
			zlog_debug("%s: upstream=%pPA is myself on interface %s", __func__,
				   &rpf->rpf_addr, rpf->source_nexthop.interface->name);
		return 0;
	}

	/*
	 * RFC 4601: 4.3.1.  Sending Hello Messages
	 *
	 * Thus, if a router needs to send a Join/Prune or Assert message on
	 * an interface on which it has not yet sent a Hello message with the
	 * currently configured IP address, then it MUST immediately send the
	 * relevant Hello message without waiting for the Hello Timer to
	 * expire, followed by the Join/Prune or Assert message.
	 */
	pim_hello_require(ifp);

	/* Underflow protection: next instruction we do MTU - PIM_IP_HEADER_SIZE. */
	if (ifp->mtu <= PIM_IP_HEADER_SIZE) {
		zlog_warn("%s: interface %s MTU seems bogus: %d", __func__, ifp->name, ifp->mtu);
		return 0;
	}

	/*
	 * Find out the maximum packet size an interface can handle
	 * which is the MTU size minus the size of an IP header.
	 *
	 * In case the interface MTU is bigger than our stack buffer,
	 * then use the stack buffer.
	 */
	packet_max_size = MIN(ifp->mtu - PIM_IP_HEADER_SIZE, sizeof(pim_msg));
	if (packet_max_size < (PIM_IP_HEADER_SIZE + PIM_JP_HEADER_SIZE + sizeof(struct pim_jp))) {
		zlog_warn("%s: interface %s MTU is too small: %d", __func__, ifp->name, ifp->mtu);
		return 0;
	}

	msg = (struct pim_jp *)pim_msg;
	packet_left = 0;

	for (ALL_LIST_ELEMENTS_RO(groups, node, group)) {
		if (PIM_DEBUG_PIM_J_P)
			zlog_debug(
				"%s: sending (G)=%pPAs to upstream=%pPA on interface %s",
				__func__, &group->group, &rpf->rpf_addr,
				rpf->source_nexthop.interface->name);

		/* Initialize source iterators */
		last_source = NULL;
		last_child = NULL;

		/* Set RPT prune in eligible sources */
		pim_jp_groups_source_set_prune(group->sources);

pim_start_message:
		/* Write the join prune header or point to the next group */
		if (packet_left <= sizeof(struct pim_jp)) {
			memset(msg, 0, sizeof(*msg));
			pim_msg_addr_encode_ucast((uint8_t *)&msg->addr, rpf->rpf_addr);
			msg->holdtime = htons(holdtime);

			grp = (struct pim_jp_groups *)&msg->groups[0];

			packet_size = PIM_JP_HEADER_SIZE;
			packet_left = packet_max_size - packet_size;
		} else
			grp = (struct pim_jp_groups *)&pim_msg[packet_size];

		/*
		 * Write the PIM join prune group contents
		 *
		 * While there are group sources or upstream sources
		 * available keep iterating
		 *
		 * *NOTE* when `pim_jp_groups_fill` returns 0 it means
		 * nothing was written so we can't bump the
		 * `msg->num_groups`.
		 */
		group_written = pim_jp_groups_fill(grp, group, packet_left, &last_source,
						   &last_child);
		/*
		 * When `pim_jp_groups_fill` returns 0 it means there
		 * were no more space in the buffer, so flush the
		 * packet and start over.
		 */
		if (group_written == 0) {
			pim_jp_flush_packet(ifp, pim_msg_type, pim_msg, packet_size);

			packet_left = 0;
			packet_size = 0;
			goto pim_start_message;
		}

		msg->num_groups++;

		packet_size += group_written;
		packet_left -= group_written;

		if (!pim_ifp->pim_passive_enable) {
			pim_ifp->pim_ifstat_join_send += grp->joins;
			pim_ifp->pim_ifstat_prune_send += grp->prunes;
		}

		if (PIM_DEBUG_PIM_TRACE)
			zlog_debug("%s: interface %s num_joins %u num_prunes %u", __func__,
				   ifp->name, grp->joins, grp->prunes);

		grp->joins = htons(grp->joins);
		grp->prunes = htons(grp->prunes);

		/* We filled the buffer with the group, lets flush */
		if (last_source || last_child) {
			pim_jp_flush_packet(ifp, pim_msg_type, pim_msg, packet_size);

			/* Repeat loop but don't go to the next group */
			packet_left = 0;
			goto pim_start_message;
		}

		/*
		 * `last_source` and `last_child` are NULL so we
		 * exhausted all sources in this group, before we go to
		 * the next one check if we need flushing the packet.
		 *
		 * We need to flush the packet if:
		 *  1. The buffer space is too small
		 *  2. The number of groups would overflow (> 255)
		 */
		if (packet_left <= (sizeof(struct pim_jp) + sizeof(pim_encoded_source)) ||
		    msg->num_groups == 255) {
			pim_jp_flush_packet(ifp, pim_msg_type, pim_msg, packet_size);

			packet_left = 0;
			packet_size = 0;
			continue;
		}
	}

	/* Flush final packet if something was written */
	if (packet_size > 0)
		pim_jp_flush_packet(ifp, pim_msg_type, pim_msg, packet_size);

	return 0;
}

int pim_joinprune_send(struct pim_rpf *rpf, struct list *groups)
{
	struct interface *ifp = rpf->source_nexthop.interface;
	struct pim_interface *pim_ifp;

	if (ifp == NULL) {
		zlog_warn("%s: RPF interface is not present", __func__);
		return -1;
	}

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		zlog_warn("%s: multicast not enabled on interface %s", __func__,
			  rpf->source_nexthop.interface->name);
		return -1;
	}

	return pim_jp_send(rpf, groups, PIM_MSG_TYPE_JOIN_PRUNE, pim_if_jp_hold(pim_ifp));
}

int pim_graft_send(struct pim_rpf *rpf, struct list *groups)
{
	return pim_jp_send(rpf, groups, PIM_MSG_TYPE_GRAFT, 0);
}
