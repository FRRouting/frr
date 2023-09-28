// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * ospf6_bfd.c: IPv6 OSPF BFD handling routines
 *
 * @copyright Copyright (C) 2015 Cumulus Networks, Inc.
 */

#include <zebra.h>

#include "command.h"
#include "linklist.h"
#include "memory.h"
#include "prefix.h"
#include "frrevent.h"
#include "buffer.h"
#include "stream.h"
#include "zclient.h"
#include "vty.h"
#include "table.h"
#include "bfd.h"
#include "if.h"
#include "ospf6d.h"
#include "ospf6_message.h"
#include "ospf6_neighbor.h"
#include "ospf6_interface.h"
#include "ospf6_route.h"
#include "ospf6_zebra.h"
#include "ospf6_bfd.h"

extern struct zclient *zclient;

/*
 * ospf6_bfd_trigger_event - Neighbor is registered/deregistered with BFD when
 *                           neighbor state is changed to/from 2way.
 */
void ospf6_bfd_trigger_event(struct ospf6_neighbor *on, int old_state,
			     int state)
{
	int family;
	struct in6_addr src, dst;

	/* Skip sessions without BFD. */
	if (on->bfd_session == NULL)
		return;

	if (old_state < OSPF6_NEIGHBOR_TWOWAY
	    && state >= OSPF6_NEIGHBOR_TWOWAY) {
		/*
		 * Check if neighbor address changed.
		 *
		 * When the neighbor is configured BFD before having an existing
		 * connection, then the destination address will be set to `::`
		 * which will cause session installation failure. This piece of
		 * code updates the address in that case.
		 */
		bfd_sess_addresses(on->bfd_session, &family, &src, &dst);
		if (memcmp(&on->linklocal_addr, &dst, sizeof(dst))) {
			bfd_sess_set_ipv6_addrs(on->bfd_session, &src,
						&on->linklocal_addr);
		}

		bfd_sess_install(on->bfd_session);
	} else if (old_state >= OSPF6_NEIGHBOR_TWOWAY
		   && state < OSPF6_NEIGHBOR_TWOWAY)
		bfd_sess_uninstall(on->bfd_session);
}

/*
 * ospf6_bfd_reg_dereg_all_nbr - Register/Deregister all neighbors associated
 *                               with a interface with BFD through
 *                               zebra for starting/stopping the monitoring of
 *                               the neighbor rechahability.
 */
static void ospf6_bfd_reg_dereg_all_nbr(struct ospf6_interface *oi,
					bool install)
{
	struct ospf6_neighbor *on;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(oi->neighbor_list, node, on)) {
		/* Remove all sessions. */
		if (!install) {
			bfd_sess_free(&on->bfd_session);
			continue;
		}

		/* Always allocate session data even if not enabled. */
		ospf6_bfd_info_nbr_create(oi, on);

		/*
		 * If not connected yet, don't create any session but defer it
		 * for later. See function `ospf6_bfd_trigger_event`.
		 */
		if (on->state < OSPF6_NEIGHBOR_TWOWAY)
			continue;

		bfd_sess_install(on->bfd_session);
	}
}

static void ospf6_bfd_callback(struct bfd_session_params *bsp,
			       const struct bfd_session_status *bss, void *arg)
{
	struct ospf6_neighbor *on = arg;

	if (bss->state == BFD_STATUS_DOWN
	    && bss->previous_state == BFD_STATUS_UP) {
		EVENT_OFF(on->inactivity_timer);
		event_add_event(master, inactivity_timer, on, 0, NULL);
	}
}

/*
 * ospf6_bfd_info_nbr_create - Create/update BFD information for a neighbor.
 */
void ospf6_bfd_info_nbr_create(struct ospf6_interface *oi,
			       struct ospf6_neighbor *on)
{
	if (!oi->bfd_config.enabled)
		return;

	if (on->bfd_session == NULL)
		on->bfd_session = bfd_sess_new(ospf6_bfd_callback, on);

	bfd_sess_set_timers(on->bfd_session,
			    oi->bfd_config.detection_multiplier,
			    oi->bfd_config.min_rx, oi->bfd_config.min_tx);
	bfd_sess_set_ipv6_addrs(on->bfd_session, on->ospf6_if->linklocal_addr,
				&on->linklocal_addr);
	bfd_sess_set_interface(on->bfd_session, oi->interface->name);
	bfd_sess_set_vrf(on->bfd_session, oi->interface->vrf->vrf_id);
	bfd_sess_set_profile(on->bfd_session, oi->bfd_config.profile);
}

/*
 * ospf6_bfd_write_config - Write the interface BFD configuration.
 */
void ospf6_bfd_write_config(struct vty *vty, struct ospf6_interface *oi)
{
	if (!oi->bfd_config.enabled)
		return;

#if HAVE_BFDD == 0
	if (oi->bfd_config.detection_multiplier != BFD_DEF_DETECT_MULT
	    || oi->bfd_config.min_rx != BFD_DEF_MIN_RX
	    || oi->bfd_config.min_tx != BFD_DEF_MIN_TX)
		vty_out(vty, " ipv6 ospf6 bfd %d %d %d\n",
			oi->bfd_config.detection_multiplier,
			oi->bfd_config.min_rx, oi->bfd_config.min_tx);
	else
#endif /* ! HAVE_BFDD */
		vty_out(vty, " ipv6 ospf6 bfd\n");

	if (oi->bfd_config.profile)
		vty_out(vty, " ipv6 ospf6 bfd profile %s\n",
			oi->bfd_config.profile);
}

DEFUN(ipv6_ospf6_bfd, ipv6_ospf6_bfd_cmd,
      "ipv6 ospf6 bfd [profile BFDPROF]",
      IP6_STR OSPF6_STR
      "Enables BFD support\n"
      "BFD Profile selection\n"
      "BFD Profile name\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi;
	int prof_idx = 4;
	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	oi->bfd_config.detection_multiplier = BFD_DEF_DETECT_MULT;
	oi->bfd_config.min_rx = BFD_DEF_MIN_RX;
	oi->bfd_config.min_tx = BFD_DEF_MIN_TX;
	oi->bfd_config.enabled = true;
	if (argc > prof_idx) {
		XFREE(MTYPE_TMP, oi->bfd_config.profile);
		oi->bfd_config.profile =
			XSTRDUP(MTYPE_TMP, argv[prof_idx]->arg);
	}

	ospf6_bfd_reg_dereg_all_nbr(oi, true);

	return CMD_SUCCESS;
}

DEFUN(no_ipv6_ospf6_bfd_profile, no_ipv6_ospf6_bfd_profile_cmd,
      "no ipv6 ospf6 bfd profile [BFDPROF]",
      NO_STR IP6_STR OSPF6_STR
      "BFD support\n"
      "BFD Profile selection\n"
      "BFD Profile name\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi;
	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	/* BFD not enabled, nothing to do. */
	if (!oi->bfd_config.enabled)
		return CMD_SUCCESS;

	/* Remove profile and apply new configuration. */
	XFREE(MTYPE_TMP, oi->bfd_config.profile);
	ospf6_bfd_reg_dereg_all_nbr(oi, true);

	return CMD_SUCCESS;
}

#if HAVE_BFDD > 0
DEFUN_HIDDEN(
#else
DEFUN(
#endif /* HAVE_BFDD */
       ipv6_ospf6_bfd_param,
       ipv6_ospf6_bfd_param_cmd,
       "ipv6 ospf6 bfd (2-255) (50-60000) (50-60000)",
       IP6_STR
       OSPF6_STR
       "Enables BFD support\n"
       "Detect Multiplier\n"
       "Required min receive interval\n"
       "Desired min transmit interval\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 5;
	struct ospf6_interface *oi;

	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	oi->bfd_config.detection_multiplier =
		strtoul(argv[idx_number]->arg, NULL, 10);
	oi->bfd_config.min_rx = strtoul(argv[idx_number_2]->arg, NULL, 10);
	oi->bfd_config.min_tx = strtoul(argv[idx_number_3]->arg, NULL, 10);
	oi->bfd_config.enabled = true;

	ospf6_bfd_reg_dereg_all_nbr(oi, true);

	return CMD_SUCCESS;
}

DEFUN (no_ipv6_ospf6_bfd,
       no_ipv6_ospf6_bfd_cmd,
       "no ipv6 ospf6 bfd",
       NO_STR
       IP6_STR
       OSPF6_STR
       "Disables BFD support\n"
       )
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf6_interface *oi;
	assert(ifp);

	oi = (struct ospf6_interface *)ifp->info;
	if (oi == NULL)
		oi = ospf6_interface_create(ifp);
	assert(oi);

	oi->bfd_config.enabled = false;
	ospf6_bfd_reg_dereg_all_nbr(oi, false);

	return CMD_SUCCESS;
}

void ospf6_bfd_init(void)
{
	bfd_protocol_integration_init(zclient, master);

	/* Install BFD command */
	install_element(INTERFACE_NODE, &ipv6_ospf6_bfd_cmd);
	install_element(INTERFACE_NODE, &ipv6_ospf6_bfd_param_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_ospf6_bfd_profile_cmd);
	install_element(INTERFACE_NODE, &no_ipv6_ospf6_bfd_cmd);
}
