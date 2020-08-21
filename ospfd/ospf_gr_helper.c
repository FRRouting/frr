/*
 * OSPF Graceful Restart helper functions.
 *
 * Copyright (C) 2020-21 Vmware, Inc.
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

#include "thread.h"
#include "memory.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "vty.h"
#include "filter.h"
#include "log.h"
#include "jhash.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_errors.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_gr_helper.h"


static unsigned int ospf_enable_rtr_hash_key(const void *data)
{
	const struct advRtr *rtr = data;

	return jhash_1word(rtr->advRtrAddr.s_addr, 0);
}

static bool ospf_enable_rtr_hash_cmp(const void *d1, const void *d2)
{
	const struct advRtr *rtr1 = (struct advRtr *)d1;
	const struct advRtr *rtr2 = (struct advRtr *)d2;

	return (rtr1->advRtrAddr.s_addr == rtr2->advRtrAddr.s_addr);
}

static void *ospf_enable_rtr_hash_alloc(void *p)
{
	struct advRtr *rid;

	rid = XCALLOC(MTYPE_OSPF_GR_HELPER, sizeof(struct advRtr));
	rid->advRtrAddr.s_addr = ((struct in_addr *)p)->s_addr;

	return rid;
}

static void ospf_disable_rtr_hash_free(void *rtr)
{
	XFREE(MTYPE_OSPF_GR_HELPER, rtr);
}

static void ospf_enable_rtr_hash_destroy(struct ospf *ospf)
{
	if (ospf->enable_rtr_list == NULL)
		return;

	hash_clean(ospf->enable_rtr_list, ospf_disable_rtr_hash_free);
	hash_free(ospf->enable_rtr_list);
	ospf->enable_rtr_list = NULL;
}

/*
 * Initialize GR helper config data structures.
 *
 * OSPF
 *    OSPF pointer
 *
 * Returns:
 *    Nothing
 */
void ospf_gr_helper_init(struct ospf *ospf)
{
	if (IS_DEBUG_OSPF_GR_HELPER)
		zlog_debug("%s, GR Helper init.", __PRETTY_FUNCTION__);

	ospf->is_helper_supported = OSPF_FALSE;
	ospf->strict_lsa_check = OSPF_TRUE;
	ospf->only_planned_restart = OSPF_FALSE;
	ospf->supported_grace_time = OSPF_MAX_GRACE_INTERVAL;
	ospf->last_exit_reason = OSPF_GR_HELPER_EXIT_NONE;
	ospf->active_restarter_cnt = 0;

	ospf->enable_rtr_list =
		hash_create(ospf_enable_rtr_hash_key, ospf_enable_rtr_hash_cmp,
			    "OSPF enable router hash");
}

/*
 * De-Initialize GR helper config data structures.
 *
 * OSPF
 *    OSPF pointer
 *
 * Returns:
 *    Nothing
 */
void ospf_gr_helper_stop(struct ospf *ospf)
{

	if (IS_DEBUG_OSPF_GR_HELPER)
		zlog_debug("%s, GR helper deinit.", __PRETTY_FUNCTION__);

	ospf_enable_rtr_hash_destroy(ospf);
}
