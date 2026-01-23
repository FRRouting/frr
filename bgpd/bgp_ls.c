// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Link-State (RFC 9552) - Core Implementation
 * Copyright (C) 2025 Carmine Scarpitta
 */

#include <zebra.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ls.h"

DEFINE_MTYPE_STATIC(BGPD, BGP_LS, "BGP-LS instance");

/*
 * ===========================================================================
 * Module Initialization and Cleanup
 * ===========================================================================
 */

/*
 * Initialize BGP-LS module for a BGP instance
 * Called from bgp_create() for the default BGP instance only
 */
void bgp_ls_init(struct bgp *bgp)
{
	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
		return;

	bgp->ls_info = XCALLOC(MTYPE_BGP_LS, sizeof(struct bgp_ls));
	bgp->ls_info->bgp = bgp;

	zlog_info("BGP-LS: Module initialized for instance %s", bgp->name_pretty);
}

/*
 * Cleanup BGP-LS module for a BGP instance
 * Called from bgp_free() for the default BGP instance only
 */
void bgp_ls_cleanup(struct bgp *bgp)
{
	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
		return;

	XFREE(MTYPE_BGP_LS, bgp->ls_info);

	zlog_info("BGP-LS: Module terminated for instance %s", bgp->name_pretty);
}
