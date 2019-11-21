/*
 * Copyright (C) 2019  NetDEF, Inc.
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

#include "thread.h"
#include "log.h"
#include "lib_errors.h"
#include "if.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"
#include "linklist.h"
#include "nexthop.h"
#include "vrf.h"
#include "typesafe.h"

#include "pathd/pathd.h"

static struct zclient *zclient;

static void path_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

void path_zebra_init(struct thread_master *master)
{
	/* Initialize asynchronous zclient. */
	zclient = zclient_new(master, &zclient_options_default);
	zclient_init(zclient, ZEBRA_ROUTE_TE, 0, &pathd_privs);
	zclient->zebra_connected = path_zebra_connected;
}

void path_zebra_add_lsp(mpls_label_t binding_sid,
			struct te_segment_list *segment_list)
{
	struct zapi_srte_tunnel zt = {};
	zt.type = ZEBRA_LSP_TE;
	zt.local_label = binding_sid;
	zt.label_num = segment_list->label_num;

	int i;
	for (i = 0; i < zt.label_num; i++) {
		zt.labels[i] = segment_list->labels[i];
	}

	(void)zebra_send_srte_tunnel(zclient, ZEBRA_SR_TE_TUNNEL_SET, &zt);
}
