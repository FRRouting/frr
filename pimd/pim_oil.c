/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
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
#include "memory.h"
#include "linklist.h"
#include "if.h"
#include "hash.h"
#include "jhash.h"

#include "pimd.h"
#include "pim_oil.h"
#include "pim_str.h"
#include "pim_iface.h"
#include "pim_time.h"
#include "pim_vxlan.h"

// struct list *pim_channel_oil_list = NULL;
// struct hash *pim_channel_oil_hash = NULL;

static void pim_channel_update_mute(struct channel_oil *c_oil);

char *pim_channel_oil_dump(struct channel_oil *c_oil, char *buf, size_t size)
{
	char *out;
	struct interface *ifp;
	struct prefix_sg sg;
	int i;

	sg.src = c_oil->oil.mfcc_origin;
	sg.grp = c_oil->oil.mfcc_mcastgrp;
	ifp = pim_if_find_by_vif_index(c_oil->pim, c_oil->oil.mfcc_parent);
	snprintf(buf, size, "%s IIF: %s, OIFS: ", pim_str_sg_dump(&sg),
		 ifp ? ifp->name : "(?)");

	out = buf + strlen(buf);
	for (i = 0; i < MAXVIFS; i++) {
		if (c_oil->oil.mfcc_ttls[i] != 0) {
			ifp = pim_if_find_by_vif_index(c_oil->pim, i);
			snprintf(out, buf + size - out, "%s ",
				 ifp ? ifp->name : "(?)");
			out += strlen(out);
		}
	}

	return buf;
}

int pim_channel_oil_compare(const struct channel_oil *c1,
			    const struct channel_oil *c2)
{
	if (ntohl(c1->oil.mfcc_mcastgrp.s_addr)
	    < ntohl(c2->oil.mfcc_mcastgrp.s_addr))
		return -1;

	if (ntohl(c1->oil.mfcc_mcastgrp.s_addr)
	    > ntohl(c2->oil.mfcc_mcastgrp.s_addr))
		return 1;

	if (ntohl(c1->oil.mfcc_origin.s_addr)
	    < ntohl(c2->oil.mfcc_origin.s_addr))
		return -1;

	if (ntohl(c1->oil.mfcc_origin.s_addr)
	    > ntohl(c2->oil.mfcc_origin.s_addr))
		return 1;

	return 0;
}

void pim_oil_init(struct pim_instance *pim)
{
	rb_pim_oil_init(&pim->channel_oil_head);
}

void pim_oil_terminate(struct pim_instance *pim)
{
	struct channel_oil *c_oil;

	while ((c_oil = rb_pim_oil_pop(&pim->channel_oil_head)))
		pim_channel_oil_free(c_oil);

	rb_pim_oil_fini(&pim->channel_oil_head);
}

void pim_channel_oil_free(struct channel_oil *c_oil)
{
	XFREE(MTYPE_PIM_CHANNEL_OIL, c_oil);
}

struct channel_oil *pim_find_channel_oil(struct pim_instance *pim,
					 struct prefix_sg *sg)
{
	struct channel_oil *c_oil = NULL;
	struct channel_oil lookup;

	lookup.oil.mfcc_mcastgrp = sg->grp;
	lookup.oil.mfcc_origin = sg->src;

	c_oil = rb_pim_oil_find(&pim->channel_oil_head, &lookup);

	return c_oil;
}

struct channel_oil *pim_channel_oil_add(struct pim_instance *pim,
					struct prefix_sg *sg,
					const char *name)
{
	struct channel_oil *c_oil;

	c_oil = pim_find_channel_oil(pim, sg);
	if (c_oil) {
		++c_oil->oil_ref_count;

		if (!c_oil->up) {
			/* channel might be present prior to upstream */
			c_oil->up = pim_upstream_find(
					pim, sg);
			/* if the upstream entry is being anchored to an
			 * already existing channel OIL we need to re-evaluate
			 * the "Mute" state on AA OIFs
			 */
			pim_channel_update_mute(c_oil);
		}

		/* check if the IIF has changed
		 * XXX - is this really needed
		 */
		pim_upstream_mroute_iif_update(c_oil, __func__);

		if (PIM_DEBUG_MROUTE)
			zlog_debug(
				"%s(%s): Existing oil for %pSG4 Ref Count: %d (Post Increment)",
				__PRETTY_FUNCTION__, name, sg,
				c_oil->oil_ref_count);
		return c_oil;
	}

	c_oil = XCALLOC(MTYPE_PIM_CHANNEL_OIL, sizeof(*c_oil));

	c_oil->oil.mfcc_mcastgrp = sg->grp;
	c_oil->oil.mfcc_origin = sg->src;

	c_oil->oil.mfcc_parent = MAXVIFS;
	c_oil->oil_ref_count = 1;
	c_oil->installed = 0;
	c_oil->up = pim_upstream_find(pim, sg);
	c_oil->pim = pim;

	rb_pim_oil_add(&pim->channel_oil_head, c_oil);

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s(%s): c_oil %s add",
				__func__, name, pim_str_sg_dump(sg));

	return c_oil;
}

struct channel_oil *pim_channel_oil_del(struct channel_oil *c_oil,
		const char *name)
{
	if (PIM_DEBUG_MROUTE) {
		struct prefix_sg sg = {.src = c_oil->oil.mfcc_mcastgrp,
				       .grp = c_oil->oil.mfcc_origin};

		zlog_debug(
			"%s(%s): Del oil for %pSG4, Ref Count: %d (Predecrement)",
			__PRETTY_FUNCTION__, name, &sg, c_oil->oil_ref_count);
	}
	--c_oil->oil_ref_count;

	if (c_oil->oil_ref_count < 1) {
		/*
		 * notice that listnode_delete() can't be moved
		 * into pim_channel_oil_free() because the later is
		 * called by list_delete_all_node()
		 */
		c_oil->up = NULL;
		rb_pim_oil_del(&c_oil->pim->channel_oil_head, c_oil);

		pim_channel_oil_free(c_oil);
		return NULL;
	}

	return c_oil;
}

void pim_channel_oil_upstream_deref(struct channel_oil *c_oil)
{
	/* The upstream entry associated with a channel_oil is abt to be
	 * deleted. If the channel_oil is kept around because of other
	 * references we need to remove upstream based states out of it.
	 */
	c_oil = pim_channel_oil_del(c_oil, __func__);
	if (c_oil) {
		/* note: here we assume that c_oil->up has already been
		 * cleared
		 */
		pim_channel_update_mute(c_oil);
	}
}

int pim_channel_del_oif(struct channel_oil *channel_oil, struct interface *oif,
			uint32_t proto_mask, const char *caller)
{
	struct pim_interface *pim_ifp;

	zassert(channel_oil);
	zassert(oif);

	pim_ifp = oif->info;

	/*
	 * Don't do anything if we've been asked to remove a source
	 * that is not actually on it.
	 */
	if (!(channel_oil->oif_flags[pim_ifp->mroute_vif_index] & proto_mask)) {
		if (PIM_DEBUG_MROUTE) {
			char group_str[INET_ADDRSTRLEN];
			char source_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<group?>",
				       channel_oil->oil.mfcc_mcastgrp,
				       group_str, sizeof(group_str));
			pim_inet4_dump("<source?>",
				       channel_oil->oil.mfcc_origin, source_str,
				       sizeof(source_str));
			zlog_debug(
				"%s %s: no existing protocol mask %u(%u) for requested OIF %s (vif_index=%d, min_ttl=%d) for channel (S,G)=(%s,%s)",
				__FILE__, __PRETTY_FUNCTION__, proto_mask,
				channel_oil
					->oif_flags[pim_ifp->mroute_vif_index],
				oif->name, pim_ifp->mroute_vif_index,
				channel_oil->oil
					.mfcc_ttls[pim_ifp->mroute_vif_index],
				source_str, group_str);
		}
		return 0;
	}

	channel_oil->oif_flags[pim_ifp->mroute_vif_index] &= ~proto_mask;

	if (channel_oil->oif_flags[pim_ifp->mroute_vif_index] &
			PIM_OIF_FLAG_PROTO_ANY) {
		if (PIM_DEBUG_MROUTE) {
			char group_str[INET_ADDRSTRLEN];
			char source_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<group?>",
				       channel_oil->oil.mfcc_mcastgrp,
				       group_str, sizeof(group_str));
			pim_inet4_dump("<source?>",
				       channel_oil->oil.mfcc_origin, source_str,
				       sizeof(source_str));
			zlog_debug(
				"%s %s: other protocol masks remain for requested OIF %s (vif_index=%d, min_ttl=%d) for channel (S,G)=(%s,%s)",
				__FILE__, __PRETTY_FUNCTION__, oif->name,
				pim_ifp->mroute_vif_index,
				channel_oil->oil
					.mfcc_ttls[pim_ifp->mroute_vif_index],
				source_str, group_str);
		}
		return 0;
	}

	channel_oil->oil.mfcc_ttls[pim_ifp->mroute_vif_index] = 0;
	/* clear mute; will be re-evaluated when the OIF becomes valid again */
	channel_oil->oif_flags[pim_ifp->mroute_vif_index] &= ~PIM_OIF_FLAG_MUTE;

	if (pim_upstream_mroute_add(channel_oil, __PRETTY_FUNCTION__)) {
		if (PIM_DEBUG_MROUTE) {
			char group_str[INET_ADDRSTRLEN];
			char source_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<group?>",
				       channel_oil->oil.mfcc_mcastgrp,
				       group_str, sizeof(group_str));
			pim_inet4_dump("<source?>",
				       channel_oil->oil.mfcc_origin, source_str,
				       sizeof(source_str));
			zlog_debug(
				"%s %s: could not remove output interface %s (vif_index=%d) for channel (S,G)=(%s,%s)",
				__FILE__, __PRETTY_FUNCTION__, oif->name,
				pim_ifp->mroute_vif_index, source_str,
				group_str);
		}
		return -1;
	}

	--channel_oil->oil_size;

	if (PIM_DEBUG_MROUTE) {
		char group_str[INET_ADDRSTRLEN];
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", channel_oil->oil.mfcc_mcastgrp,
			       group_str, sizeof(group_str));
		pim_inet4_dump("<source?>", channel_oil->oil.mfcc_origin,
			       source_str, sizeof(source_str));
		zlog_debug(
			"%s(%s): (S,G)=(%s,%s): proto_mask=%u IIF:%d OIF=%s vif_index=%d",
			__PRETTY_FUNCTION__, caller, source_str, group_str,
			proto_mask, channel_oil->oil.mfcc_parent, oif->name,
			pim_ifp->mroute_vif_index);
	}

	return 0;
}

void pim_channel_del_inherited_oif(struct channel_oil *c_oil,
		struct interface *oif, const char *caller)
{
	struct pim_upstream *up = c_oil->up;

	pim_channel_del_oif(c_oil, oif, PIM_OIF_FLAG_PROTO_STAR,
			caller);

	/* if an inherited OIF is being removed join-desired can change
	 * if the inherited OIL is now empty and KAT is running
	 */
	if (up && up->sg.src.s_addr != INADDR_ANY &&
			pim_upstream_empty_inherited_olist(up))
		pim_upstream_update_join_desired(up->pim, up);
}

static bool pim_channel_eval_oif_mute(struct channel_oil *c_oil,
		struct pim_interface *pim_ifp)
{
	struct pim_interface *pim_reg_ifp;
	struct pim_interface *vxlan_ifp;
	bool do_mute = false;
	struct pim_instance *pim = c_oil->pim;

	if (!c_oil->up)
		return do_mute;

	pim_reg_ifp = pim->regiface->info;
	if (pim_ifp == pim_reg_ifp) {
		/* suppress pimreg in the OIL if the mroute is not supposed to
		 * trigger register encapsulated data
		 */
		if (PIM_UPSTREAM_FLAG_TEST_NO_PIMREG_DATA(c_oil->up->flags))
			do_mute = true;

		return do_mute;
	}

	vxlan_ifp = pim_vxlan_get_term_ifp(pim);
	if (pim_ifp == vxlan_ifp) {
		/* 1. vxlan termination device must never be added to the
		 * origination mroute (and that can actually happen because
		 * of XG inheritance from the termination mroute) otherwise
		 * traffic will end up looping.
		 * PS: This check has also been extended to non-orig mroutes
		 * that have a local SIP as such mroutes can move back and
		 * forth between orig<=>non-orig type.
		 * 2. vxlan termination device should be removed from the non-DF
		 * to prevent duplicates to the overlay rxer
		 */
		if (PIM_UPSTREAM_FLAG_TEST_SRC_VXLAN_ORIG(c_oil->up->flags) ||
			PIM_UPSTREAM_FLAG_TEST_MLAG_NON_DF(c_oil->up->flags) ||
			pim_vxlan_is_local_sip(c_oil->up))
			do_mute = true;

		return do_mute;
	}

	return do_mute;
}

void pim_channel_update_oif_mute(struct channel_oil *c_oil,
		struct pim_interface *pim_ifp)
{
	bool old_mute;
	bool new_mute;

	/* If pim_ifp is not a part of the OIL there is nothing to do */
	if (!c_oil->oil.mfcc_ttls[pim_ifp->mroute_vif_index])
		return;

	old_mute = !!(c_oil->oif_flags[pim_ifp->mroute_vif_index] &
			PIM_OIF_FLAG_MUTE);
	new_mute = pim_channel_eval_oif_mute(c_oil, pim_ifp);
	if (old_mute == new_mute)
		return;

	if (new_mute)
		c_oil->oif_flags[pim_ifp->mroute_vif_index] |=
			PIM_OIF_FLAG_MUTE;
	else
		c_oil->oif_flags[pim_ifp->mroute_vif_index] &=
			~PIM_OIF_FLAG_MUTE;

	pim_upstream_mroute_add(c_oil, __PRETTY_FUNCTION__);
}

/* pim_upstream has been set or cleared on the c_oil. re-eval mute state
 * on all existing OIFs
 */
static void pim_channel_update_mute(struct channel_oil *c_oil)
{
	struct pim_interface *pim_reg_ifp;
	struct pim_interface *vxlan_ifp;

	pim_reg_ifp = c_oil->pim->regiface->info;
	if (pim_reg_ifp)
		pim_channel_update_oif_mute(c_oil, pim_reg_ifp);
	vxlan_ifp = pim_vxlan_get_term_ifp(c_oil->pim);
	if (vxlan_ifp)
		pim_channel_update_oif_mute(c_oil, vxlan_ifp);
}

int pim_channel_add_oif(struct channel_oil *channel_oil, struct interface *oif,
			uint32_t proto_mask, const char *caller)
{
	struct pim_interface *pim_ifp;
	int old_ttl;

	/*
	 * If we've gotten here we've gone bad, but let's
	 * not take down pim
	 */
	if (!channel_oil) {
		zlog_warn("Attempt to Add OIF for non-existent channel oil");
		return -1;
	}

	pim_ifp = oif->info;

	/* Prevent single protocol from subscribing same interface to
	   channel (S,G) multiple times */
	if (channel_oil->oif_flags[pim_ifp->mroute_vif_index] & proto_mask) {
		if (PIM_DEBUG_MROUTE) {
			char group_str[INET_ADDRSTRLEN];
			char source_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<group?>",
				       channel_oil->oil.mfcc_mcastgrp,
				       group_str, sizeof(group_str));
			pim_inet4_dump("<source?>",
				       channel_oil->oil.mfcc_origin, source_str,
				       sizeof(source_str));
			zlog_debug(
				"%s %s: existing protocol mask %u requested OIF %s (vif_index=%d, min_ttl=%d) for channel (S,G)=(%s,%s)",
				__FILE__, __PRETTY_FUNCTION__, proto_mask,
				oif->name, pim_ifp->mroute_vif_index,
				channel_oil->oil
					.mfcc_ttls[pim_ifp->mroute_vif_index],
				source_str, group_str);
		}
		return -3;
	}

	/* Allow other protocol to request subscription of same interface to
	 * channel (S,G), we need to note this information
	 */
	if (channel_oil->oif_flags[pim_ifp->mroute_vif_index]
	    & PIM_OIF_FLAG_PROTO_ANY) {

		/* Updating time here is not required as this time has to
		 * indicate when the interface is added
		 */

		channel_oil->oif_flags[pim_ifp->mroute_vif_index] |= proto_mask;
		/* Check the OIF really exists before returning, and only log
		   warning otherwise */
		if (channel_oil->oil.mfcc_ttls[pim_ifp->mroute_vif_index] < 1) {
			{
				char group_str[INET_ADDRSTRLEN];
				char source_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<group?>",
					       channel_oil->oil.mfcc_mcastgrp,
					       group_str, sizeof(group_str));
				pim_inet4_dump("<source?>",
					       channel_oil->oil.mfcc_origin,
					       source_str, sizeof(source_str));
				zlog_warn(
					"%s %s: new protocol mask %u requested nonexistent OIF %s (vif_index=%d, min_ttl=%d) for channel (S,G)=(%s,%s)",
					__FILE__, __PRETTY_FUNCTION__,
					proto_mask, oif->name,
					pim_ifp->mroute_vif_index,
					channel_oil->oil.mfcc_ttls
						[pim_ifp->mroute_vif_index],
					source_str, group_str);
			}
		}

		return 0;
	}

	old_ttl = channel_oil->oil.mfcc_ttls[pim_ifp->mroute_vif_index];

	if (old_ttl > 0) {
		if (PIM_DEBUG_MROUTE) {
			char group_str[INET_ADDRSTRLEN];
			char source_str[INET_ADDRSTRLEN];
			pim_inet4_dump("<group?>",
				       channel_oil->oil.mfcc_mcastgrp,
				       group_str, sizeof(group_str));
			pim_inet4_dump("<source?>",
				       channel_oil->oil.mfcc_origin, source_str,
				       sizeof(source_str));
			zlog_debug(
				"%s %s: interface %s (vif_index=%d) is existing output for channel (S,G)=(%s,%s)",
				__FILE__, __PRETTY_FUNCTION__, oif->name,
				pim_ifp->mroute_vif_index, source_str,
				group_str);
		}
		return -4;
	}

	channel_oil->oil.mfcc_ttls[pim_ifp->mroute_vif_index] =
		PIM_MROUTE_MIN_TTL;

	/* Some OIFs are held in a muted state i.e. the PIM state machine
	 * decided to include the OIF but additional status check such as
	 * MLAG DF role prevent it from being activated for traffic
	 * forwarding.
	 */
	if (pim_channel_eval_oif_mute(channel_oil, pim_ifp))
		channel_oil->oif_flags[pim_ifp->mroute_vif_index] |=
			PIM_OIF_FLAG_MUTE;
	else
		channel_oil->oif_flags[pim_ifp->mroute_vif_index] &=
			~PIM_OIF_FLAG_MUTE;

	/* channel_oil->oil.mfcc_parent != MAXVIFS indicate this entry is not
	 * valid to get installed in kernel.
	 */
	if (channel_oil->oil.mfcc_parent != MAXVIFS) {
		if (pim_upstream_mroute_add(channel_oil, __PRETTY_FUNCTION__)) {
			if (PIM_DEBUG_MROUTE) {
				char group_str[INET_ADDRSTRLEN];
				char source_str[INET_ADDRSTRLEN];
				pim_inet4_dump("<group?>",
				      channel_oil->oil.mfcc_mcastgrp,
				      group_str, sizeof(group_str));
				pim_inet4_dump("<source?>",
				      channel_oil->oil.mfcc_origin, source_str,
				      sizeof(source_str));
				zlog_debug(
				    "%s %s: could not add output interface %s (vif_index=%d) for channel (S,G)=(%s,%s)",
				    __FILE__, __PRETTY_FUNCTION__, oif->name,
				    pim_ifp->mroute_vif_index, source_str,
				    group_str);
			}

			channel_oil->oil.mfcc_ttls[pim_ifp->mroute_vif_index]
				= old_ttl;
			return -5;
		}
	}

	channel_oil->oif_creation[pim_ifp->mroute_vif_index] =
		pim_time_monotonic_sec();
	++channel_oil->oil_size;
	channel_oil->oif_flags[pim_ifp->mroute_vif_index] |= proto_mask;

	if (PIM_DEBUG_MROUTE) {
		char group_str[INET_ADDRSTRLEN];
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<group?>", channel_oil->oil.mfcc_mcastgrp,
			       group_str, sizeof(group_str));
		pim_inet4_dump("<source?>", channel_oil->oil.mfcc_origin,
			       source_str, sizeof(source_str));
		zlog_debug(
			"%s(%s): (S,G)=(%s,%s): proto_mask=%u OIF=%s vif_index=%d: DONE",
			__PRETTY_FUNCTION__, caller, source_str, group_str,
			proto_mask, oif->name, pim_ifp->mroute_vif_index);
	}

	return 0;
}

int pim_channel_oil_empty(struct channel_oil *c_oil)
{
	static struct mfcctl null_oil;

	if (!c_oil)
		return 1;

	/* exclude pimreg from the OIL when checking if the inherited_oil is
	 * non-NULL.
	 * pimreg device (in all vrfs) uses a vifi of
	 * 0 (PIM_OIF_PIM_REGISTER_VIF) so we simply mfcc_ttls[0] */
	return !memcmp(&c_oil->oil.mfcc_ttls[1], &null_oil.mfcc_ttls[1],
		sizeof(null_oil.mfcc_ttls) - sizeof(null_oil.mfcc_ttls[0]));
}
