/**
 * ospf_bfd.c: OSPF BFD handling routines
 *
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "json.h"
#include "linklist.h"
#include "memory.h"
#include "prefix.h"
#include "thread.h"
#include "buffer.h"
#include "stream.h"
#include "zclient.h"
#include "vty.h"
#include "table.h"
#include "bfd.h"
#include "ospfd.h"
#include "ospf_asbr.h"
#include "ospf_lsa.h"
#include "ospf_lsdb.h"
#include "ospf_neighbor.h"
#include "ospf_interface.h"
#include "ospf_nsm.h"
#include "ospf_bfd.h"
#include "ospf_dump.h"
#include "ospf_vty.h"

DEFINE_MTYPE_STATIC(OSPFD, BFD_CONFIG, "BFD configuration data");

/*
 * ospf_bfd_trigger_event - Neighbor is registered/deregistered with BFD when
 *                          neighbor state is changed to/from 2way.
 */
void ospf_bfd_trigger_event(struct ospf_neighbor *nbr, int old_state, int state)
{
	if ((old_state < NSM_TwoWay) && (state >= NSM_TwoWay))
		bfd_sess_install(nbr->bfd_session);
	else if ((old_state >= NSM_TwoWay) && (state < NSM_TwoWay))
		bfd_sess_uninstall(nbr->bfd_session);
}

static void ospf_bfd_session_change(struct bfd_session_params *bsp,
				    const struct bfd_session_status *bss,
				    void *arg)
{
	struct ospf_neighbor *nbr = arg;

	/* BFD peer went down. */
	if (bss->state == BFD_STATUS_DOWN
	    && bss->previous_state == BFD_STATUS_UP) {
		if (IS_DEBUG_OSPF(bfd, BFD_LIB))
			zlog_debug("%s: NSM[%s:%pI4]: BFD Down", __func__,
				   IF_NAME(nbr->oi), &nbr->address.u.prefix4);

		OSPF_NSM_EVENT_SCHEDULE(nbr, NSM_InactivityTimer);
	}

	/* BFD peer went up. */
	if (bss->state == BSS_UP && bss->previous_state == BSS_DOWN)
		if (IS_DEBUG_OSPF(bfd, BFD_LIB))
			zlog_debug("%s: NSM[%s:%pI4]: BFD Up", __func__,
				   IF_NAME(nbr->oi), &nbr->address.u.prefix4);
}

void ospf_neighbor_bfd_apply(struct ospf_neighbor *nbr)
{
	struct ospf_interface *oi = nbr->oi;
	struct ospf_if_params *oip = IF_DEF_PARAMS(oi->ifp);

	/* BFD configuration was removed. */
	if (oip->bfd_config == NULL) {
		bfd_sess_free(&nbr->bfd_session);
		return;
	}

	/* New BFD session. */
	if (nbr->bfd_session == NULL) {
		nbr->bfd_session = bfd_sess_new(ospf_bfd_session_change, nbr);
		bfd_sess_set_ipv4_addrs(nbr->bfd_session, NULL, &nbr->src);
		bfd_sess_set_interface(nbr->bfd_session, oi->ifp->name);
		bfd_sess_set_vrf(nbr->bfd_session, oi->ospf->vrf_id);
	}

	/* Set new configuration. */
	bfd_sess_set_timers(nbr->bfd_session,
			    oip->bfd_config->detection_multiplier,
			    oip->bfd_config->min_rx, oip->bfd_config->min_tx);
	bfd_sess_set_profile(nbr->bfd_session, oip->bfd_config->profile);

	/* Don't start sessions on down OSPF sessions. */
	if (nbr->state < NSM_TwoWay)
		return;

	bfd_sess_install(nbr->bfd_session);
}

static void ospf_interface_bfd_apply(struct interface *ifp)
{
	struct ospf_interface *oi;
	struct route_table *nbrs;
	struct ospf_neighbor *nbr;
	struct route_node *irn;
	struct route_node *nrn;

	/* Iterate over all interfaces and set neighbors BFD session. */
	for (irn = route_top(IF_OIFS(ifp)); irn; irn = route_next(irn)) {
		if ((oi = irn->info) == NULL)
			continue;
		if ((nbrs = oi->nbrs) == NULL)
			continue;
		for (nrn = route_top(nbrs); nrn; nrn = route_next(nrn)) {
			if ((nbr = nrn->info) == NULL || nbr == oi->nbr_self)
				continue;

			ospf_neighbor_bfd_apply(nbr);
		}
	}
}

static void ospf_interface_enable_bfd(struct interface *ifp)
{
	struct ospf_if_params *oip = IF_DEF_PARAMS(ifp);

	if (oip->bfd_config)
		return;

	/* Allocate memory for configurations and set defaults. */
	oip->bfd_config = XCALLOC(MTYPE_BFD_CONFIG, sizeof(*oip->bfd_config));
	oip->bfd_config->detection_multiplier = BFD_DEF_DETECT_MULT;
	oip->bfd_config->min_rx = BFD_DEF_MIN_RX;
	oip->bfd_config->min_tx = BFD_DEF_MIN_TX;
}

void ospf_interface_disable_bfd(struct interface *ifp,
				struct ospf_if_params *oip)
{
	XFREE(MTYPE_BFD_CONFIG, oip->bfd_config);
	ospf_interface_bfd_apply(ifp);
}

/*
 * ospf_bfd_write_config - Write the interface BFD configuration.
 */
void ospf_bfd_write_config(struct vty *vty, const struct ospf_if_params *params
			   __attribute__((unused)))
{
#if HAVE_BFDD == 0
	if (params->bfd_config->detection_multiplier != BFD_DEF_DETECT_MULT
	    || params->bfd_config->min_rx != BFD_DEF_MIN_RX
	    || params->bfd_config->min_tx != BFD_DEF_MIN_TX)
		vty_out(vty, " ip ospf bfd %d %d %d\n",
			params->bfd_config->detection_multiplier,
			params->bfd_config->min_rx, params->bfd_config->min_tx);
	else
#endif /* ! HAVE_BFDD */
		vty_out(vty, " ip ospf bfd\n");

	if (params->bfd_config->profile[0])
		vty_out(vty, " ip ospf bfd profile %s\n",
			params->bfd_config->profile);
}

void ospf_interface_bfd_show(struct vty *vty, const struct interface *ifp,
			     struct json_object *json)
{
	struct ospf_if_params *params = IF_DEF_PARAMS(ifp);
	struct bfd_configuration *bfd_config = params->bfd_config;
	struct json_object *json_bfd;

	if (bfd_config == NULL)
		return;

	if (json) {
		json_bfd = json_object_new_object();
		json_object_int_add(json_bfd, "detectionMultiplier",
				    bfd_config->detection_multiplier);
		json_object_int_add(json_bfd, "rxMinInterval",
				    bfd_config->min_rx);
		json_object_int_add(json_bfd, "txMinInterval",
				    bfd_config->min_tx);
		json_object_object_add(json, "peerBfdInfo", json_bfd);
	} else
		vty_out(vty,
			"  BFD: Detect Multiplier: %d, Min Rx interval: %d, Min Tx interval: %d\n",
			bfd_config->detection_multiplier, bfd_config->min_rx,
			bfd_config->min_tx);
}

DEFUN (ip_ospf_bfd,
       ip_ospf_bfd_cmd,
       "ip ospf bfd",
       "IP Information\n"
       "OSPF interface commands\n"
       "Enables BFD support\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	ospf_interface_enable_bfd(ifp);
	ospf_interface_bfd_apply(ifp);
	return CMD_SUCCESS;
}

#if HAVE_BFDD > 0
DEFUN_HIDDEN(
#else
DEFUN(
#endif /* HAVE_BFDD */
       ip_ospf_bfd_param,
       ip_ospf_bfd_param_cmd,
       "ip ospf bfd (2-255) (50-60000) (50-60000)",
       "IP Information\n"
       "OSPF interface commands\n"
       "Enables BFD support\n"
       "Detect Multiplier\n"
       "Required min receive interval\n"
       "Desired min transmit interval\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 5;

	ospf_interface_enable_bfd(ifp);

	params = IF_DEF_PARAMS(ifp);
	params->bfd_config->detection_multiplier =
		strtol(argv[idx_number]->arg, NULL, 10);
	params->bfd_config->min_rx = strtol(argv[idx_number_2]->arg, NULL, 10);
	params->bfd_config->min_tx = strtol(argv[idx_number_3]->arg, NULL, 10);

	ospf_interface_bfd_apply(ifp);

	return CMD_SUCCESS;
}

DEFUN (ip_ospf_bfd_prof,
       ip_ospf_bfd_prof_cmd,
       "ip ospf bfd profile BFDPROF",
       "IP Information\n"
       "OSPF interface commands\n"
       "Enables BFD support\n"
       BFD_PROFILE_STR
       BFD_PROFILE_NAME_STR)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;
	int idx_prof = 4;

	params = IF_DEF_PARAMS(ifp);
	if (!params->bfd_config) {
		vty_out(vty, "ip ospf bfd has not been set\n");
		return CMD_WARNING;
	}

	strlcpy(params->bfd_config->profile, argv[idx_prof]->arg,
		sizeof(params->bfd_config->profile));
	ospf_interface_bfd_apply(ifp);

	return CMD_SUCCESS;
}

DEFUN (no_ip_ospf_bfd_prof,
       no_ip_ospf_bfd_prof_cmd,
       "no ip ospf bfd profile [BFDPROF]",
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Enables BFD support\n"
       BFD_PROFILE_STR
       BFD_PROFILE_NAME_STR)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;

	params = IF_DEF_PARAMS(ifp);
	if (!params->bfd_config)
		return CMD_SUCCESS;

	params->bfd_config->profile[0] = 0;
	ospf_interface_bfd_apply(ifp);

	return CMD_SUCCESS;
}

DEFUN (no_ip_ospf_bfd,
       no_ip_ospf_bfd_cmd,
#if HAVE_BFDD > 0
       "no ip ospf bfd",
#else
       "no ip ospf bfd [(2-255) (50-60000) (50-60000)]",
#endif /* HAVE_BFDD */
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Disables BFD support\n"
#if HAVE_BFDD == 0
       "Detect Multiplier\n"
       "Required min receive interval\n"
       "Desired min transmit interval\n"
#endif /* !HAVE_BFDD */
)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	ospf_interface_disable_bfd(ifp, IF_DEF_PARAMS(ifp));
	return CMD_SUCCESS;
}

void ospf_bfd_init(struct thread_master *tm)
{
	bfd_protocol_integration_init(zclient, tm);

	/* Install BFD command */
	install_element(INTERFACE_NODE, &ip_ospf_bfd_cmd);
	install_element(INTERFACE_NODE, &ip_ospf_bfd_param_cmd);
	install_element(INTERFACE_NODE, &ip_ospf_bfd_prof_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_bfd_prof_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_bfd_cmd);
}
