/*
 * This is an implementation of RFC 3623 Graceful OSPF Restart.
 *
 * Author: Sascha Kattelmann <sascha@netdef.org>
 * Copyright 2020 6WIND (c), All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "memory.h"
#include "command.h"
#include "vty.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_gr.h"
#include "ospfd/ospf_errors.h"
#include "ospfd/ospf_dump.h"


static void ospf_gr_register_vty(void);
static void ospf_gr_config_write_router(struct vty *vty, struct ospf *ospf);
static struct ospf_lsa *ospf_gr_lsa_refresh(struct ospf_lsa *lsa);

int ospf_gr_init(void)
{
	int rc;

	if (IS_DEBUG_OSPF_GR)
		zlog_debug(
			"GR (%s): Initializing nonstop forwarding (NSF) / Graceful Restart",
			__func__);

	rc = ospf_register_opaque_functab(
		OSPF_OPAQUE_LINK_LSA, OPAQUE_TYPE_GRACE_LSA,
		NULL,			     /* new interface */
		NULL,			     /* del interface */
		NULL,			     /* ISM Change */
		NULL,			     /* NSM change */
		ospf_gr_config_write_router, /* Config. write router */
		NULL,			     /* Config. write interface */
		NULL,			     /* Config. write debug */
		NULL,			     /* show info */
		NULL,			     /* LSA originate */
		ospf_gr_lsa_refresh,	 /* LSA refresh */
		NULL,			     /* LSA update */
		NULL);			     /* del_lsa_hook */

	if (rc != 0) {
		flog_warn(EC_OSPF_OPAQUE_REGISTRATION,
			  "GR (%s): Failed to register functions", __func__);
		return rc;
	}

	ospf_gr_register_vty();

	return 0;
}

void ospf_gr_term(void)
{
	ospf_delete_opaque_functab(OSPF_OPAQUE_LINK_LSA, OPAQUE_TYPE_GRACE_LSA);
}

static struct ospf_lsa *ospf_gr_lsa_lookup(struct ospf *ospf)
{
	struct ospf_lsa *lsa = NULL;
	struct in_addr lsa_id;
	uint32_t lsa_id_host_byte_order;
	struct ospf_area *area;

	area = ospf_area_get(ospf, ospf->router_id);

	lsa_id_host_byte_order = SET_OPAQUE_LSID(OPAQUE_TYPE_GRACE_LSA, 0);
	lsa_id.s_addr = htonl(lsa_id_host_byte_order);
	lsa = ospf_lsa_lookup(ospf, area, OSPF_OPAQUE_LINK_LSA, lsa_id,
			      ospf->router_id);

	return lsa;
}

static int ospf_gr_prepare_timer(struct thread *thread)
{
	struct ospf *ospf = (struct ospf *)THREAD_ARG(thread);
	struct ospf_lsa *lsa;

	if (IS_DEBUG_OSPF_GR)
		zlog_debug(
			"[GR] Prepared restart timer expired, flushing all self-originated Grace-LSAs.");

	ospf->gr_info.t_prepare = NULL;
	ospf->gr_info.prepare_running = false;

	lsa = ospf_gr_lsa_lookup(ospf);
	if (lsa)
		ospf_opaque_lsa_flush_schedule(lsa);
	else {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug(
				"[GR] no self-originated Grace-LSAs to flush!");
	}

	if (ospf->present_zebra_gr_state == ZEBRA_GR_ENABLED) {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug("[GR] Un-stalling the RIB");

		if (ospf_zebra_gr_disable(ospf))
			return CMD_WARNING;
	}

	return 0;
}

/*
 * Before each generation of Grace-LSAs, call this function to
 * initialize the restart period loaded in the period-TLV.
 */
static void ospf_gr_init_period(struct ospf_gr_info *gr_info)
{
	struct timeval prepare_left;
	uint32_t prepare_diff;

	if (gr_info->t_prepare) {
		prepare_left = thread_timer_remain(gr_info->t_prepare);
		prepare_diff = gr_info->prepare_period - prepare_left.tv_sec;
		gr_info->tlv_period.value =
			htonl(gr_info->grace_period - prepare_diff);
	} else {
		gr_info->tlv_period.value = htonl(gr_info->grace_period);
	}
}

static void ospf_gr_build_period_tlv(struct ospf_gr_info *gr_info,
				     struct stream *s)
{
	stream_put(s, &gr_info->tlv_period, sizeof(struct gr_tlv_period));
}

static void ospf_gr_build_reason_tlv(struct ospf_gr_info *gr_info,
				     struct stream *s)
{
	if (gr_info->prepare_running)
		gr_info->tlv_reason.reason = GR_REASON_RESTART;
	else
		gr_info->tlv_reason.reason = GR_REASON_UNKNOWN;

	stream_put(s, &gr_info->tlv_reason, sizeof(struct gr_tlv_reason));
}

static void ospf_gr_build_address_tlv(struct ospf_gr_info *gr_info,
				      struct stream *s,
				      struct ospf_interface *oi)
{
	gr_info->tlv_address.addr = oi->address->u.prefix4;
	stream_put(s, &gr_info->tlv_address, sizeof(struct gr_tlv_address));
}

static void ospf_gr_lsa_body_set(struct ospf_gr_info *gr_info, struct stream *s,
				 struct ospf_interface *oi)
{
	ospf_gr_build_period_tlv(gr_info, s);
	ospf_gr_build_reason_tlv(gr_info, s);
	if (oi->type == OSPF_IFTYPE_BROADCAST || oi->type == OSPF_IFTYPE_NBMA
	    || oi->type == OSPF_IFTYPE_POINTOMULTIPOINT)
		ospf_gr_build_address_tlv(gr_info, s, oi);
}

static struct ospf_lsa *ospf_gr_lsa_new(struct ospf_interface *oi)
{
	struct stream *s;
	struct lsa_header *lsah;
	struct ospf_lsa *new;
	uint8_t options, lsa_type;
	struct in_addr lsa_id;
	uint32_t lsa_id_host_byte_order;
	uint16_t length;

	/* Create a stream for LSA. */
	s = stream_new(OSPF_MAX_LSA_SIZE);
	assert(s);

	lsah = (struct lsa_header *)STREAM_DATA(s);

	options = LSA_OPTIONS_GET(oi->area);
	options |= LSA_OPTIONS_NSSA_GET(oi->area);
	options |= OSPF_OPTION_O;

	lsa_type = OSPF_OPAQUE_LINK_LSA;
	lsa_id_host_byte_order = SET_OPAQUE_LSID(OPAQUE_TYPE_GRACE_LSA, 0);
	lsa_id.s_addr = htonl(lsa_id_host_byte_order);

	/* Set opaque-LSA header fields. */
	lsa_header_set(s, options, lsa_type, lsa_id, oi->ospf->router_id);

	/* Set opaque-LSA body fields. */
	ospf_gr_lsa_body_set(&oi->ospf->gr_info, s, oi);

	/* Set length. */
	length = stream_get_endp(s);
	lsah->length = htons(length);

	/* Now, create an OSPF LSA instance. */
	new = ospf_lsa_new_and_data(length);
	assert(new);

	if (IS_DEBUG_OSPF_GR)
		zlog_debug("LSA[Type%d:%s]: Create an Opaque-LSA/GR instance",
			   lsa_type, inet_ntoa(lsa_id));

	new->area = oi->area;
	new->oi = oi;
	SET_FLAG(new->flags, OSPF_LSA_SELF);
	memcpy(new->data, lsah, length);
	stream_free(s);

	return new;
}

static struct ospf_lsa *ospf_gr_lsa_originate(struct ospf_interface *oi,
					      struct ospf_lsa *old)
{
	struct ospf_lsa *new = NULL;
	struct ospf_area *area;

	if (oi->state == ISM_Down) {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug(
				"%s:Originating Grace LSA on Down interface %s (abort)",
				__func__, IF_NAME(oi));
		goto out;
	}

	/* Create new Grace-LSA instance. */
	new = ospf_gr_lsa_new(oi);
	if (!new) {
		if (IS_DEBUG_OSPF_GR)
			zlog_warn(
				"ospf_gr_lsa_generate: ospf_gr_lsa_new() failed");
		goto out;
	}

	/* Adjust the sequence number */
	if (!old) {
		/* Find the old LSA and increase the seq. */
		area = ospf_area_get(oi->ospf, oi->ospf->router_id);
		old = ospf_lsa_lookup_by_header(area, new->data);
		if (old)
			new->data->ls_seqnum = lsa_seqnum_increment(old);
	}

	/* Install this LSA into LSDB. */
	if (ospf_lsa_install(oi->ospf, oi, new) == NULL) {
		if (IS_DEBUG_OSPF_GR)
			zlog_warn(
				"ospf_gr_lsa_generate: ospf_lsa_install() failed");
		ospf_lsa_unlock(&new);
		goto out;
	}

	/* Update new LSA origination count. */
	if (!old)
		oi->ospf->lsa_originate_count++;

	/* Flood the LSA through out the interface */
	ospf_flood_through_interface(oi, NULL, new);

out:
	return new;
}

static struct ospf_lsa *ospf_gr_lsa_refresh(struct ospf_lsa *lsa)
{
	struct ospf *ospf = lsa->oi->ospf;
	bool force_org = false;

	if (!IS_GR_LSA(lsa->data) || !CHECK_FLAG(lsa->flags, OSPF_LSA_SELF))
		return NULL;

	if (!ospf->gr_info.restart_support) {
		/* Seems to be a leftover, flush it away. */
		lsa->data->ls_age = htons(OSPF_LSA_MAXAGE);
	} else if (ospf->gr_info.prepare_running) {
		/* Prepare running, refresh this LSA */
		force_org = true;
	} else {
		lsa->data->ls_age = htons(OSPF_LSA_MAXAGE);
	}

	/* If the lsa's age reached to MaxAge, start flushing procedure. */
	if (IS_LSA_MAXAGE(lsa) && !force_org) {
		ospf_opaque_lsa_flush_schedule(lsa);
	} else {
		ospf_gr_init_period(&lsa->oi->ospf->gr_info);
		ospf_gr_lsa_originate(lsa->oi, lsa);
	}

	return NULL;
}

static void ospf_gr_prepare(struct ospf *ospf, uint32_t period)
{
	struct listnode *node = NULL;
	struct ospf_interface *oi = NULL;

	if (IS_DEBUG_OSPF_GR)
		zlog_debug("[GR] NSF PREPARE with the period %u second(s)",
			   period);

	if (!ospf->gr_info.restart_support
	    || ospf->present_zebra_gr_state != ZEBRA_GR_ENABLED) {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug(
				"[GR] The graceful restart capability is not active!");
		return;
	}

	if (ospf->gr_info.prepare_running) {
		if (IS_DEBUG_OSPF_GR)
			zlog_debug(
				"[GR] The prepared restart has already been committed!");
		return;
	}

	ospf->gr_info.prepare_running = true;

	thread_add_timer(master, ospf_gr_prepare_timer, ospf,
			 ospf->gr_info.prepare_period,
			 &ospf->gr_info.t_prepare);

	ospf_gr_init_period(&ospf->gr_info);

	/* Send a Grace-LSA to all neighbors */
	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi))
		ospf_gr_lsa_originate(oi, NULL);
}

DEFUN(graceful_restart,
      graceful_restart_cmd,
      "graceful-restart [grace-period (1-1800)]",
      OSPF_GR_STR
      "Maximum length of the 'grace period'\n"
      "Maximum length of the 'grace period' in seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx = 2;

	/* Check and get restart period if present */
	if (argc > 1)
		ospf->gr_info.grace_period =
			strtoul(argv[idx]->arg, NULL, 10);
	else
		ospf->gr_info.grace_period =
			OSPF_GR_DEFAULT_GRACE_PERIOD;

	if (!ospf->gr_info.restart_support)
		if (IS_DEBUG_OSPF_GR)
			zlog_debug("GR: OFF -> ON");

	ospf->gr_info.restart_support = true;

	return CMD_SUCCESS;
}

DEFUN(no_graceful_restart,
      no_graceful_restart_cmd,
      "no graceful-restart [period (1-1800)]",
      NO_STR
      OSPF_GR_STR
      "Maximum length of the 'grace period'\n"
      "Maximum length of the 'grace period' in seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf->gr_info.restart_support = false;

	if (IS_DEBUG_OSPF_GR)
		zlog_debug("GR: ON -> OFF");

	return CMD_SUCCESS;
}

DEFUN(graceful_restart_prepare,
      graceful_restart_prepare_cmd,
      "graceful-restart prepare [period (1-1800)]",
      OSPF_GR_STR
      "Prepare upcoming OSPF restart by sending out 'grace' LSAs and stalling the RIB\n"
      "Length of the 'prepare period' after which 'grace' LSAs are flushed and the RIB being unstalled again\n"
      "Length of the 'prepare period' in seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx = 3;

	if (!ospf->gr_info.restart_support) {
		zlog_warn(
			"GR: Graceful Restart not enabled, can't start preparation");
		return CMD_WARNING;
	}

	/* Check and get restart period if present */
	if (argc > 2)
		ospf->gr_info.prepare_period =
			strtoul(argv[idx]->arg, NULL, 10);
	else
		ospf->gr_info.prepare_period =
			OSPF_GR_DEFAULT_PREPARE_PERIOD;

	if (!ospf->gr_info.prepare_running)
		if (IS_DEBUG_OSPF_GR)
			zlog_debug("GR PREPARE: OFF -> ON with period %d",
				   ospf->gr_info.prepare_period);

	if (ospf->present_zebra_gr_state == ZEBRA_GR_ENABLED
	    && ospf->rib_stale_time != ospf->gr_info.grace_period) {
		if (ospf_zebra_gr_stale_time_update(
			    ospf, ospf->gr_info.grace_period))
			return CMD_WARNING;
	}
	if (ospf->present_zebra_gr_state == ZEBRA_GR_DISABLED) {
		if (ospf_zebra_gr_enable(ospf, ospf->gr_info.grace_period))
			return CMD_WARNING;
	}

	ospf_gr_prepare(ospf, ospf->gr_info.prepare_period);

	return CMD_SUCCESS;
}

DEFUN(no_graceful_restart_prepare,
      no_graceful_restart_prepare_cmd,
      "no graceful-restart prepare [period (1-1800)]",
      NO_STR
      OSPF_GR_STR
      "Prepare upcoming OSPF restart by sending out 'grace' LSAs and stalling the RIB\n"
      "Length of the 'prepare period' after which 'grace' LSAs are flushed and the RIB being unstalled again\n"
      "Length of the 'prepare period' in seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (ospf->present_zebra_gr_state == ZEBRA_GR_ENABLED) {
		if (ospf_zebra_gr_disable(ospf))
			return CMD_WARNING;
	}

	if (ospf->gr_info.prepare_running && IS_DEBUG_OSPF_GR)
		zlog_debug("GR PREPARE: ON -> OFF");

	ospf->gr_info.prepare_running = false;

	return CMD_SUCCESS;
}

static void ospf_gr_config_write_router(struct vty *vty, struct ospf *ospf)
{
	if (!ospf->gr_info.restart_support)
		return;

	if (ospf->gr_info.grace_period
	    == OSPF_GR_DEFAULT_GRACE_PERIOD)
		vty_out(vty, " graceful-restart\n");
	else
		vty_out(vty, " graceful-restart grace-period %d\n",
			ospf->gr_info.grace_period);
}

/* Install new CLI commands */
static void ospf_gr_register_vty(void)
{
	install_element(OSPF_NODE, &graceful_restart_cmd);
	install_element(OSPF_NODE, &no_graceful_restart_cmd);

	install_element(OSPF_NODE, &graceful_restart_prepare_cmd);
	install_element(OSPF_NODE, &no_graceful_restart_prepare_cmd);
}
