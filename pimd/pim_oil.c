// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
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

static void pim_channel_update_mute(struct channel_oil *c_oil);

char *pim_channel_oil_dump(struct channel_oil *c_oil, char *buf, size_t size)
{
	char *out;
	struct interface *ifp;
	pim_sgaddr sg;
	int i;

	sg.src = *oil_origin(c_oil);
	sg.grp = *oil_mcastgrp(c_oil);
	ifp = pim_if_find_by_vif_index(c_oil->pim, *oil_incoming_vif(c_oil));
	snprintfrr(buf, size, "%pSG IIF: %s, OIFS: ", &sg,
		   ifp ? ifp->name : "(?)");

	out = buf + strlen(buf);
	for (i = 0; i < MAXVIFS; i++) {
		if (oil_if_has(c_oil, i) != 0) {
			ifp = pim_if_find_by_vif_index(c_oil->pim, i);
			snprintf(out, buf + size - out, "%s ",
				 ifp ? ifp->name : "(?)");
			out += strlen(out);
		}
	}

	return buf;
}

int pim_channel_oil_compare(const struct channel_oil *cc1,
			    const struct channel_oil *cc2)
{
	struct channel_oil *c1 = (struct channel_oil *)cc1;
	struct channel_oil *c2 = (struct channel_oil *)cc2;
	int rv;

	rv = pim_addr_cmp(*oil_mcastgrp(c1), *oil_mcastgrp(c2));
	if (rv)
		return rv;
	rv = pim_addr_cmp(*oil_origin(c1), *oil_origin(c2));
	if (rv)
		return rv;
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
					 pim_sgaddr *sg)
{
	struct channel_oil *c_oil = NULL;
	struct channel_oil lookup;

	*oil_mcastgrp(&lookup) = sg->grp;
	*oil_origin(&lookup) = sg->src;

	c_oil = rb_pim_oil_find(&pim->channel_oil_head, &lookup);

	return c_oil;
}

struct channel_oil *pim_channel_oil_add(struct pim_instance *pim,
					pim_sgaddr *sg, const char *name)
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
				"%s(%s): Existing oil for %pSG Ref Count: %d (Post Increment)",
				__func__, name, sg, c_oil->oil_ref_count);
		return c_oil;
	}

	c_oil = XCALLOC(MTYPE_PIM_CHANNEL_OIL, sizeof(*c_oil));

	*oil_mcastgrp(c_oil) = sg->grp;
	*oil_origin(c_oil) = sg->src;

	*oil_incoming_vif(c_oil) = MAXVIFS;
	c_oil->oil_ref_count = 1;
	c_oil->installed = 0;
	c_oil->up = pim_upstream_find(pim, sg);
	c_oil->pim = pim;

	rb_pim_oil_add(&pim->channel_oil_head, c_oil);

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s(%s): c_oil %pSG add", __func__, name, sg);

	return c_oil;
}


/*
 * Clean up mroute and channel oil created for dropping pkts from directly
 * connected source when the interface was non DR.
 */
void pim_clear_nocache_state(struct pim_interface *pim_ifp)
{
	struct channel_oil *c_oil;

	frr_each_safe (rb_pim_oil, &pim_ifp->pim->channel_oil_head, c_oil) {

		if ((!c_oil->up) ||
		    !(PIM_UPSTREAM_FLAG_TEST_SRC_NOCACHE(c_oil->up->flags)))
			continue;

		if (*oil_incoming_vif(c_oil) != pim_ifp->mroute_vif_index)
			continue;

		EVENT_OFF(c_oil->up->t_ka_timer);
		PIM_UPSTREAM_FLAG_UNSET_SRC_NOCACHE(c_oil->up->flags);
		PIM_UPSTREAM_FLAG_UNSET_SRC_STREAM(c_oil->up->flags);
		pim_upstream_del(pim_ifp->pim, c_oil->up, __func__);
	}
}

struct channel_oil *pim_channel_oil_del(struct channel_oil *c_oil,
					const char *name)
{
	if (PIM_DEBUG_MROUTE) {
		pim_sgaddr sg = {.src = *oil_origin(c_oil),
				 .grp = *oil_mcastgrp(c_oil)};

		zlog_debug(
			"%s(%s): Del oil for %pSG, Ref Count: %d (Predecrement)",
			__func__, name, &sg, c_oil->oil_ref_count);
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

	assert(channel_oil);
	assert(oif);

	pim_ifp = oif->info;

	assertf(pim_ifp->mroute_vif_index >= 0,
		"trying to del OIF %s with VIF (%d)", oif->name,
		pim_ifp->mroute_vif_index);

	/*
	 * Don't do anything if we've been asked to remove a source
	 * that is not actually on it.
	 */
	if (!(channel_oil->oif_flags[pim_ifp->mroute_vif_index] & proto_mask)) {
		if (PIM_DEBUG_MROUTE) {
			zlog_debug(
				"%s %s: no existing protocol mask %u(%u) for requested OIF %s (vif_index=%d, min_ttl=%d) for channel (S,G)=(%pPAs,%pPAs)",
				__FILE__, __func__, proto_mask,
				channel_oil
					->oif_flags[pim_ifp->mroute_vif_index],
				oif->name, pim_ifp->mroute_vif_index,
				oil_if_has(channel_oil, pim_ifp->mroute_vif_index),
				oil_origin(channel_oil),
				oil_mcastgrp(channel_oil));
		}
		return 0;
	}

	channel_oil->oif_flags[pim_ifp->mroute_vif_index] &= ~proto_mask;

	if (channel_oil->oif_flags[pim_ifp->mroute_vif_index] &
			PIM_OIF_FLAG_PROTO_ANY) {
		if (PIM_DEBUG_MROUTE) {
			zlog_debug(
				"%s %s: other protocol masks remain for requested OIF %s (vif_index=%d, min_ttl=%d) for channel (S,G)=(%pPAs,%pPAs)",
				__FILE__, __func__, oif->name,
				pim_ifp->mroute_vif_index,
				oil_if_has(channel_oil, pim_ifp->mroute_vif_index),
				oil_origin(channel_oil),
				oil_mcastgrp(channel_oil));
		}
		return 0;
	}

	oil_if_set(channel_oil, pim_ifp->mroute_vif_index, 0);
	/* clear mute; will be re-evaluated when the OIF becomes valid again */
	channel_oil->oif_flags[pim_ifp->mroute_vif_index] &= ~PIM_OIF_FLAG_MUTE;

	if (pim_upstream_mroute_add(channel_oil, __func__)) {
		if (PIM_DEBUG_MROUTE) {
			zlog_debug(
				"%s %s: could not remove output interface %s (vif_index=%d) for channel (S,G)=(%pPAs,%pPAs)",
				__FILE__, __func__, oif->name,
				pim_ifp->mroute_vif_index,
				oil_origin(channel_oil),
				oil_mcastgrp(channel_oil));
		}
		return -1;
	}

	--channel_oil->oil_size;

	if (PIM_DEBUG_MROUTE) {
		struct interface *iifp =
			pim_if_find_by_vif_index(pim_ifp->pim,
						 *oil_incoming_vif(channel_oil));

		zlog_debug("%s(%s): (S,G)=(%pPAs,%pPAs): proto_mask=%u IIF:%s OIF=%s vif_index=%d",
			   __func__, caller, oil_origin(channel_oil),
			   oil_mcastgrp(channel_oil), proto_mask,
			   iifp ? iifp->name : "Unknown", oif->name,
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
	if (up && !pim_addr_is_any(up->sg.src) &&
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

	if (PIM_I_am_DualActive(pim_ifp)) {
		struct pim_upstream *starup = c_oil->up->parent;
		if (PIM_UPSTREAM_FLAG_TEST_MLAG_INTERFACE(c_oil->up->flags)
		    && (PIM_UPSTREAM_FLAG_TEST_MLAG_NON_DF(c_oil->up->flags)))
			do_mute = true;

		/* In case entry is (S,G), Negotiation happens at (*.G) */
		if (starup

		    && PIM_UPSTREAM_FLAG_TEST_MLAG_INTERFACE(starup->flags)
		    && (PIM_UPSTREAM_FLAG_TEST_MLAG_NON_DF(starup->flags)))
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
	if (!oil_if_has(c_oil, pim_ifp->mroute_vif_index))
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

	pim_upstream_mroute_add(c_oil, __func__);
}

/* pim_upstream has been set or cleared on the c_oil. re-eval mute state
 * on all existing OIFs
 */
static void pim_channel_update_mute(struct channel_oil *c_oil)
{
	struct pim_interface *pim_reg_ifp;
	struct pim_interface *vxlan_ifp;

	if (c_oil->pim->regiface) {
		pim_reg_ifp = c_oil->pim->regiface->info;
		if (pim_reg_ifp)
			pim_channel_update_oif_mute(c_oil, pim_reg_ifp);
	}
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

	assertf(pim_ifp->mroute_vif_index >= 0,
		"trying to add OIF %s with VIF (%d)", oif->name,
		pim_ifp->mroute_vif_index);

	/* Prevent single protocol from subscribing same interface to
	   channel (S,G) multiple times */
	if (channel_oil->oif_flags[pim_ifp->mroute_vif_index] & proto_mask) {
		channel_oil->oif_flags[pim_ifp->mroute_vif_index] |= proto_mask;

		if (PIM_DEBUG_MROUTE) {
			zlog_debug(
				"%s %s: existing protocol mask %u requested OIF %s (vif_index=%d, min_ttl=%d) for channel (S,G)=(%pPAs,%pPAs)",
				__FILE__, __func__, proto_mask, oif->name,
				pim_ifp->mroute_vif_index,
				oil_if_has(channel_oil, pim_ifp->mroute_vif_index),
				oil_origin(channel_oil),
				oil_mcastgrp(channel_oil));
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
		if (oil_if_has(channel_oil, pim_ifp->mroute_vif_index) < 1) {
			zlog_warn(
				"%s %s: new protocol mask %u requested nonexistent OIF %s (vif_index=%d, min_ttl=%d) for channel (S,G)=(%pPAs,%pPAs)",
				__FILE__, __func__, proto_mask, oif->name,
				pim_ifp->mroute_vif_index,
				oil_if_has(channel_oil, pim_ifp->mroute_vif_index),
				oil_origin(channel_oil),
				oil_mcastgrp(channel_oil));
		}

		if (PIM_DEBUG_MROUTE) {
			zlog_debug(
				"%s(%s): (S,G)=(%pPAs,%pPAs): proto_mask=%u OIF=%s vif_index=%d added to 0x%x",
				__func__, caller, oil_origin(channel_oil),
				oil_mcastgrp(channel_oil),
				proto_mask, oif->name,
				pim_ifp->mroute_vif_index,
				channel_oil
					->oif_flags[pim_ifp->mroute_vif_index]);
		}
		return 0;
	}

	old_ttl = oil_if_has(channel_oil, pim_ifp->mroute_vif_index);

	if (old_ttl > 0) {
		if (PIM_DEBUG_MROUTE) {
			zlog_debug(
				"%s %s: interface %s (vif_index=%d) is existing output for channel (S,G)=(%pPAs,%pPAs)",
				__FILE__, __func__, oif->name,
				pim_ifp->mroute_vif_index,
				oil_origin(channel_oil),
				oil_mcastgrp(channel_oil));
		}
		return -4;
	}

	oil_if_set(channel_oil, pim_ifp->mroute_vif_index, PIM_MROUTE_MIN_TTL);

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
	if (*oil_incoming_vif(channel_oil) != MAXVIFS) {
		if (pim_upstream_mroute_add(channel_oil, __func__)) {
			if (PIM_DEBUG_MROUTE) {
				zlog_debug(
					"%s %s: could not add output interface %s (vif_index=%d) for channel (S,G)=(%pPAs,%pPAs)",
					__FILE__, __func__, oif->name,
					pim_ifp->mroute_vif_index,
					oil_origin(channel_oil),
					oil_mcastgrp(channel_oil));
			}

			oil_if_set(channel_oil, pim_ifp->mroute_vif_index,
				   old_ttl);
			return -5;
		}
	}

	channel_oil->oif_creation[pim_ifp->mroute_vif_index] =
		pim_time_monotonic_sec();
	++channel_oil->oil_size;
	channel_oil->oif_flags[pim_ifp->mroute_vif_index] |= proto_mask;

	if (PIM_DEBUG_MROUTE) {
		zlog_debug(
			"%s(%s): (S,G)=(%pPAs,%pPAs): proto_mask=%u OIF=%s vif_index=%d: DONE",
			__func__, caller, oil_origin(channel_oil),
			oil_mcastgrp(channel_oil),
			proto_mask,
			oif->name, pim_ifp->mroute_vif_index);
	}

	return 0;
}

int pim_channel_oil_empty(struct channel_oil *c_oil)
{
	static struct channel_oil null_oil;

	if (!c_oil)
		return 1;

	/* exclude pimreg from the OIL when checking if the inherited_oil is
	 * non-NULL.
	 * pimreg device (in all vrfs) uses a vifi of
	 * 0 (PIM_OIF_PIM_REGISTER_VIF) so we simply mfcc_ttls[0] */
	if (oil_if_has(c_oil, 0))
		oil_if_set(&null_oil, 0, 1);
	else
		oil_if_set(&null_oil, 0, 0);

	return !oil_if_cmp(&c_oil->oil, &null_oil.oil);
}
