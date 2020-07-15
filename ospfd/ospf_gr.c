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
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_gr.h"
#include "ospfd/ospf_errors.h"


static void ospf_gr_register_vty(void);
static void ospf_gr_config_write_router(struct vty *vty, struct ospf *ospf);

int ospf_gr_init(void)
{
	int rc;

	zlog_debug(
		"GR (%s): Initializing nonstop forwarding (NSF) / Graceful Restart",
		__func__);

	rc = ospf_register_opaque_functab(OSPF_OPAQUE_LINK_LSA,
					  OPAQUE_TYPE_GRACE_LSA,
					  NULL, /* new interface */
					  NULL, /* del interface */
					  NULL, /* ISM Change */
					  NULL, /* NSM change */
					  ospf_gr_config_write_router,
					  NULL,  /* Config. write interface */
					  NULL,  /* Config. write debug */
					  NULL,  /* show info */
					  NULL,  /* LSA originate */
					  NULL,  /* LSA refresh */
					  NULL,  /* LSA update */
					  NULL); /* del_lsa_hook */

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

	return;
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
		zlog_debug("GR PREPARE: OFF -> ON with period %d",
			   ospf->gr_info.prepare_period);

	ospf->gr_info.prepare_running = true;

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

	if (ospf->gr_info.prepare_running)
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

	return;
}

/* Install new CLI commands */
static void ospf_gr_register_vty(void)
{
	install_element(OSPF_NODE, &graceful_restart_cmd);
	install_element(OSPF_NODE, &no_graceful_restart_cmd);

	install_element(OSPF_NODE, &graceful_restart_prepare_cmd);
	install_element(OSPF_NODE, &no_graceful_restart_prepare_cmd);

	return;
}
