/*
 * OSPF6 Graceful Retsart helper functions.
 *
 * Copyright (C) 2021-22 Vmware, Inc.
 * Rajesh Kumar Girada
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

#include "log.h"
#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "stream.h"
#include "zclient.h"
#include "memory.h"
#include "table.h"
#include "lib/bfd.h"
#include "lib_errors.h"
#include "jhash.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_route.h"
#include "ospf6_message.h"

#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6_neighbor.h"
#include "ospf6_intra.h"
#include "ospf6d.h"
#include "ospf6_gr_helper.h"
#include "lib/json.h"
#ifndef VTYSH_EXTRACT_PL
#include "ospf6d/ospf6_gr_helper_clippy.c"
#endif

DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_GR_HELPER, "OSPF6 Graceful restart helper");

unsigned char conf_debug_ospf6_gr = 0;

const char *ospf6_exit_reason_desc[] = {
	"Unknown reason",     "Helper inprogress",	   "Topology Change",
	"Grace timer expiry", "Successful graceful restart",
};

const char *ospf6_restart_reason_desc[] = {
	"Unknown restart",
	"Software restart",
	"Software reload/upgrade",
	"Switch to redundant control processor",
};

const char *ospf6_rejected_reason_desc[] = {
	"Unknown reason",
	"Helper support disabled",
	"Neighbour is not in FULL state",
	"Supports only planned restart but received for unplanned",
	"Topo change due to change in lsa rxmt list",
	"LSA age is more than Grace interval",
};

static unsigned int ospf6_enable_rtr_hash_key(const void *data)
{
	const struct advRtr *rtr = data;

	return jhash_1word(rtr->advRtrAddr, 0);
}

static bool ospf6_enable_rtr_hash_cmp(const void *d1, const void *d2)
{
	const struct advRtr *rtr1 = (struct advRtr *)d1;
	const struct advRtr *rtr2 = (struct advRtr *)d2;

	return (rtr1->advRtrAddr == rtr2->advRtrAddr);
}

static void *ospf6_enable_rtr_hash_alloc(void *p)
{
	struct advRtr *rid;

	rid = XCALLOC(MTYPE_OSPF6_GR_HELPER, sizeof(struct advRtr));
	rid->advRtrAddr = ((struct advRtr *)p)->advRtrAddr;

	return rid;
}

static void ospf6_disable_rtr_hash_free(void *rtr)
{
	XFREE(MTYPE_OSPF6_GR_HELPER, rtr);
}

static void ospf6_enable_rtr_hash_destroy(struct ospf6 *ospf6)
{
	if (ospf6->ospf6_helper_cfg.enable_rtr_list == NULL)
		return;

	hash_clean(ospf6->ospf6_helper_cfg.enable_rtr_list,
		   ospf6_disable_rtr_hash_free);
	hash_free(ospf6->ospf6_helper_cfg.enable_rtr_list);
	ospf6->ospf6_helper_cfg.enable_rtr_list = NULL;
}

/* Debug commands */
DEFPY(debug_ospf6_gr,
      debug_ospf6_gr_cmd,
      "[no$no] debug ospf6 gr helper",
      NO_STR
      DEBUG_STR OSPF6_STR
      "Graceful restart\n"
      "Helper Information\n")
{
	if (!no)
		OSPF6_DEBUG_GR_HELPER_ON();
	else
		OSPF6_DEBUG_GR_HELPER_OFF();

	return CMD_SUCCESS;
}

/*
 * Initilise GR helper config datastructer.
 *
 * ospf6
 *    ospf6 pointer
 *
 * Returns:
 *    Nothing
 */
void ospf6_gr_helper_init(struct ospf6 *ospf6)
{
	if (IS_DEBUG_OSPF6_GR_HELPER)
		zlog_debug("%s, GR Helper init.", __PRETTY_FUNCTION__);

	ospf6->ospf6_helper_cfg.is_helper_supported = OSPF6_FALSE;
	ospf6->ospf6_helper_cfg.strict_lsa_check = OSPF6_TRUE;
	ospf6->ospf6_helper_cfg.only_planned_restart = OSPF6_FALSE;
	ospf6->ospf6_helper_cfg.supported_grace_time = OSPF6_MAX_GRACE_INTERVAL;
	ospf6->ospf6_helper_cfg.last_exit_reason = OSPF6_GR_HELPER_EXIT_NONE;
	ospf6->ospf6_helper_cfg.active_restarter_cnt = 0;

	ospf6->ospf6_helper_cfg.enable_rtr_list = hash_create(
		ospf6_enable_rtr_hash_key, ospf6_enable_rtr_hash_cmp,
		"Ospf6 enable router hash");
}

/*
 * De-Initilise GR helper config datastructer.
 *
 * ospf6
 *    ospf6 pointer
 *
 * Returns:
 *    Nothing
 */
void ospf6_gr_helper_deinit(struct ospf6 *ospf6)
{

	if (IS_DEBUG_OSPF6_GR_HELPER)
		zlog_debug("%s, GR helper deinit.", __PRETTY_FUNCTION__);

	ospf6_enable_rtr_hash_destroy(ospf6);
}
