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

void path_zebra_add_sr_policy(struct te_sr_policy *sr_policy,
			      struct te_segment_list *segment_list)
{
	struct zapi_sr_policy zp = {};
	zp.color = sr_policy->color;
	zp.endpoint.s_addr = sr_policy->endpoint.ipaddr_v4.s_addr;
	strncpy((char *)&zp.name, sr_policy->name,
		ZEBRA_SR_POLICY_NAME_MAX_LENGTH);

	struct te_segment_list_segment *segment;
	zp.active_segment_list.type = ZEBRA_LSP_TE;
	zp.active_segment_list.local_label = sr_policy->binding_sid;
	zp.active_segment_list.label_num = 0;

	RB_FOREACH (segment, te_segment_list_segment_instance_head,
		    &segment_list->segments) {
		zp.active_segment_list
			.labels[zp.active_segment_list.label_num] =
			segment->sid_value;
		zp.active_segment_list.label_num++;
	}

	(void)zebra_send_sr_policy(zclient, ZEBRA_SR_POLICY_SET, &zp);
}

void path_zebra_delete_sr_policy(struct te_sr_policy *sr_policy)
{
	struct zapi_sr_policy zp = {};
	zp.color = sr_policy->color;
	zp.endpoint.s_addr = sr_policy->endpoint.ipaddr_v4.s_addr;
	strncpy((char *)&zp.name, sr_policy->name,
		ZEBRA_SR_POLICY_NAME_MAX_LENGTH);
	zp.active_segment_list.type = ZEBRA_LSP_TE;
	zp.active_segment_list.local_label = sr_policy->binding_sid;
	zp.active_segment_list.label_num = 0;

	(void)zebra_send_sr_policy(zclient, ZEBRA_SR_POLICY_DELETE, &zp);
}
