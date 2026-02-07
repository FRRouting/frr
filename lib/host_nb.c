// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 12 2025, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2025, LabN Consulting, L.L.C.
 *
 */
#include <zebra.h>
#include "northbound.h"
#include "command.h"
#include "host_nb.h"

/*
 * XPath: /frr-host:host/allow-reserved-ranges
 */
static int host_allow_reserved_ranges_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	host.allow_reserved_ranges = yang_dnode_get_bool(args->dnode, NULL);

	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_host_nb_info = {
	.name = "frr-host",
	.nodes = {
		{ .xpath = "/frr-host:host/allow-reserved-ranges",
		  .cbs.modify = host_allow_reserved_ranges_modify,
		  .priority = NB_DFLT_PRIORITY - 3,
		},
		{ .xpath = NULL },
	}
};
/* clang-format on */
