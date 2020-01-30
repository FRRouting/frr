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
	struct te_sr_policy *te_sr_policy;

	zclient_send_reg_requests(zclient, VRF_DEFAULT);

	RB_FOREACH (te_sr_policy, te_sr_policy_instance_head,
		    &te_sr_policy_instances) {
		struct te_candidate_path *candidate;
		struct te_segment_list *te_segment_list;

		candidate = find_candidate_path(
			te_sr_policy, te_sr_policy->best_candidate_path_key);
		if (!candidate)
			continue;

		te_segment_list =
			te_segment_list_get(candidate->segment_list_name);
		if (!te_segment_list)
			continue;

		path_zebra_add_sr_policy(te_sr_policy, te_segment_list);
	}
}

static int path_zebra_sr_policy_notify_status(ZAPI_CALLBACK_ARGS)
{
	struct zapi_sr_policy zapi_sr_policy;
	struct te_sr_policy *te_sr_policy;
	struct te_candidate_path *best_candidate_path = NULL;
	struct ipaddr endpoint;

	if (zapi_sr_policy_notify_status_decode(zclient->ibuf, &zapi_sr_policy))
		return -1;

	endpoint.ipaddr_v4.s_addr = zapi_sr_policy.endpoint.s_addr;

	te_sr_policy = te_sr_policy_get(zapi_sr_policy.color, &endpoint);

	if (!te_sr_policy)
		return -1;

	best_candidate_path = find_candidate_path(
			te_sr_policy, te_sr_policy->best_candidate_path_key);

	if (!best_candidate_path)
		return -1;

	switch (zapi_sr_policy.status) {
		case ZEBRA_SR_POLICY_DOWN:
			switch (te_sr_policy->status) {
				/* If the policy is GOING_UP, and zebra faild
				   to install it, we wait for zebra to retry */
				/* TODO: Add some timeout after which we would
					 get is back to DOWN and remove the
					 policy */
				case TE_POLICY_GOING_UP:
				case TE_POLICY_DOWN:
					return 0;
				default:
					te_sr_policy->status = TE_POLICY_DOWN;
					break;
			}
			break;
		case ZEBRA_SR_POLICY_UP:
			switch (te_sr_policy->status) {
				case TE_POLICY_UP:
					return 0;
				default:
					te_sr_policy->status = TE_POLICY_UP;
					break;
			}
			break;

	}

	pathd_candidate_updated(best_candidate_path);
	return 0;
}

void path_zebra_init(struct thread_master *master)
{
	/* Initialize asynchronous zclient. */
	zclient = zclient_new(master, &zclient_options_default);
	zclient_init(zclient, ZEBRA_ROUTE_TE, 0, &pathd_privs);
	zclient->zebra_connected = path_zebra_connected;
	zclient->sr_policy_notify_status = path_zebra_sr_policy_notify_status;
}

void path_zebra_add_sr_policy(struct te_sr_policy *sr_policy,
			      struct te_segment_list *segment_list)
{
	struct zapi_sr_policy zp = {};
	zp.color = sr_policy->color;
	zp.endpoint.s_addr = sr_policy->endpoint.ipaddr_v4.s_addr;
	strlcpy(zp.name, sr_policy->name, sizeof(zp.name));

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

	sr_policy->status = TE_POLICY_GOING_UP;

	(void)zebra_send_sr_policy(zclient, ZEBRA_SR_POLICY_SET, &zp);
}

void path_zebra_delete_sr_policy(struct te_sr_policy *sr_policy)
{
	struct zapi_sr_policy zp = {};
	zp.color = sr_policy->color;
	zp.endpoint.s_addr = sr_policy->endpoint.ipaddr_v4.s_addr;
	strlcpy(zp.name, sr_policy->name, sizeof(zp.name));
	zp.active_segment_list.type = ZEBRA_LSP_TE;
	zp.active_segment_list.local_label = sr_policy->binding_sid;
	zp.active_segment_list.label_num = 0;

	sr_policy->status = TE_POLICY_DOWN;

	(void)zebra_send_sr_policy(zclient, ZEBRA_SR_POLICY_DELETE, &zp);
}
