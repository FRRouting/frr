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
#include "network.h"
#include "stream.h"
#include "linklist.h"
#include "nexthop.h"
#include "vrf.h"
#include "typesafe.h"

#include "pathd/pathd.h"
#include "pathd/path_zebra.h"
#include "pathd/path_util.h"

static struct zclient *zclient;
static struct zclient *zclient_sync;

/* Global Variables */
struct ipaddr g_router_id = { .ipa_type = IPADDR_NONE};
pthread_mutex_t g_router_id_mtx = PTHREAD_MUTEX_INITIALIZER;

void get_router_id(struct ipaddr *router_id)
{
	assert(router_id != NULL);
	pthread_mutex_lock(&g_router_id_mtx);
	IPADDR_COPY(router_id, &g_router_id);
	pthread_mutex_unlock(&g_router_id_mtx);
}

static void path_zebra_connected(struct zclient *zclient)
{
	struct srte_policy *policy;

	zclient_send_reg_requests(zclient, VRF_DEFAULT);

	RB_FOREACH (policy, srte_policy_head, &srte_policies) {
		struct srte_candidate *candidate;
		struct srte_segment_list *segment_list;

		candidate = policy->best_candidate;
		if (!candidate)
			continue;

		segment_list = candidate->segment_list;
		if (!segment_list)
			continue;

		path_zebra_add_sr_policy(policy, segment_list);
	}
}

static int path_zebra_sr_policy_notify_status(ZAPI_CALLBACK_ARGS)
{
	struct zapi_sr_policy zapi_sr_policy;
	struct srte_policy *policy;
	struct srte_candidate *best_candidate_path;

	if (zapi_sr_policy_notify_status_decode(zclient->ibuf, &zapi_sr_policy))
		return -1;

	policy = srte_policy_find(zapi_sr_policy.color,
				  &zapi_sr_policy.endpoint);
	if (!policy)
		return -1;

	best_candidate_path = policy->best_candidate;
	if (!best_candidate_path)
		return -1;

	srte_candidate_status_update(policy, best_candidate_path,
				     zapi_sr_policy.status);

	return 0;
}

/* Router-id update message from zebra. */
static int path_zebra_router_id_update(ZAPI_CALLBACK_ARGS)
{
	struct prefix pref;
	char buf[PREFIX2STR_BUFFER];
	pthread_mutex_lock(&g_router_id_mtx);
	zebra_router_id_update_read(zclient->ibuf, &pref);
	memset(&g_router_id, 0, sizeof(struct ipaddr));
	g_router_id.ipa_type = IPADDR_NONE;
	if (pref.family == AF_INET) {
		g_router_id.ipa_type = IPADDR_V4;
		memcpy(&g_router_id.ipaddr_v4, &pref.u.prefix4,
		       sizeof(struct in_addr));
	} else if (pref.family == AF_INET6) {
		g_router_id.ipa_type = IPADDR_V6;
		memcpy(&g_router_id.ipaddr_v6, &pref.u.prefix6,
		       sizeof(struct in6_addr));
	}
	pthread_mutex_unlock(&g_router_id_mtx);
	ipaddr2str(&g_router_id, buf, sizeof(buf));
	zlog_info("Router Id updated for VRF %u: %s", vrf_id, buf);
	return 0;
}

void path_zebra_add_sr_policy(struct srte_policy *policy,
			      struct srte_segment_list *segment_list)
{
	struct zapi_sr_policy zp = {};
	struct srte_segment_entry *segment;

	zp.color = policy->color;
	zp.endpoint = policy->endpoint;
	strlcpy(zp.name, policy->name, sizeof(zp.name));
	zp.segment_list.type = ZEBRA_LSP_SRTE;
	zp.segment_list.local_label = policy->binding_sid;
	zp.segment_list.label_num = 0;
	RB_FOREACH (segment, srte_segment_entry_head, &segment_list->segments)
		zp.segment_list.labels[zp.segment_list.label_num++] =
			segment->sid_value;
	policy->status = SRTE_POLICY_STATUS_GOING_UP;

	(void)zebra_send_sr_policy(zclient, ZEBRA_SR_POLICY_SET, &zp);
}

void path_zebra_delete_sr_policy(struct srte_policy *policy)
{
	struct zapi_sr_policy zp = {};

	zp.color = policy->color;
	zp.endpoint = policy->endpoint;
	strlcpy(zp.name, policy->name, sizeof(zp.name));
	zp.segment_list.type = ZEBRA_LSP_SRTE;
	zp.segment_list.local_label = policy->binding_sid;
	zp.segment_list.label_num = 0;
	policy->status = SRTE_POLICY_STATUS_DOWN;

	(void)zebra_send_sr_policy(zclient, ZEBRA_SR_POLICY_DELETE, &zp);
}

int path_zebra_request_label(mpls_label_t label)
{
	int ret;
	uint32_t start, end;

	ret = lm_get_label_chunk(zclient_sync, 0, label, 1, &start, &end);
	if (ret < 0) {
		zlog_warn("%s: error getting label range!", __func__);
		return -1;
	}

	return 0;
}

void path_zebra_release_label(mpls_label_t label)
{
	int ret;

	ret = lm_release_label_chunk(zclient_sync, label, label);
	if (ret < 0)
		zlog_warn("%s: error releasing label range!", __func__);
}

static void path_zebra_label_manager_connect(void)
{
	/* Connect to label manager. */
	while (zclient_socket_connect(zclient_sync) < 0) {
		zlog_warn("%s: error connecting synchronous zclient!",
			  __func__);
		sleep(1);
	}
	set_nonblocking(zclient_sync->sock);

	/* Send hello to notify zebra this is a synchronous client */
	while (zclient_send_hello(zclient_sync) < 0) {
		zlog_warn("%s: Error sending hello for synchronous zclient!",
			  __func__);
		sleep(1);
	}

	while (lm_label_manager_connect(zclient_sync, 0) != 0) {
		zlog_warn("%s: error connecting to label manager!", __func__);
		sleep(1);
	}
}

void path_zebra_init(struct thread_master *master)
{
	struct zclient_options options = zclient_options_default;
	options.synchronous = true;

	/* Initialize asynchronous zclient. */
	zclient = zclient_new(master, &zclient_options_default);
	zclient_init(zclient, ZEBRA_ROUTE_SRTE, 0, &pathd_privs);
	zclient->zebra_connected = path_zebra_connected;
	zclient->sr_policy_notify_status = path_zebra_sr_policy_notify_status;
	zclient->router_id_update = path_zebra_router_id_update;

	/* Initialize special zclient for synchronous message exchanges. */
	zclient_sync = zclient_new(master, &options);
	zclient_sync->sock = -1;
	zclient_sync->redist_default = ZEBRA_ROUTE_SRTE;
	zclient_sync->instance = 1;
	zclient_sync->privs = &pathd_privs;

	/* Connect to the LM. */
	path_zebra_label_manager_connect();
}
