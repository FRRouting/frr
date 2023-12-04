// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 */

#include <zebra.h>

#include "frrevent.h"
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
#include "pathd/path_ted.h"
#include "pathd/path_zebra.h"
#include "lib/command.h"
#include "lib/link_state.h"
#include "lib/zapi_triggered_srte.h"
#include "pathd/path_flex_algo.h"
#include "pathd/path_triggered.h"
#include "pathd/path_tsrte.h"

static int path_zebra_opaque_msg_handler(ZAPI_CALLBACK_ARGS);
static void path_zebra_tsrte_opaque_register(void);

struct zclient *zclient;
static struct zclient *zclient_sync;

/* Global Variables */
bool g_has_router_id_v4 = false;
bool g_has_router_id_v6 = false;
struct in_addr g_router_id_v4;
struct in6_addr g_router_id_v6;
pthread_mutex_t g_router_id_v4_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t g_router_id_v6_mtx = PTHREAD_MUTEX_INITIALIZER;

/**
 * Gives the IPv4 router ID received from Zebra.
 *
 * @param router_id The in_addr strucure where to store the router id
 * @return true if the router ID was available, false otherwise
 */
bool get_ipv4_router_id(struct in_addr *router_id)
{
	bool retval = false;
	assert(router_id != NULL);
	pthread_mutex_lock(&g_router_id_v4_mtx);
	if (g_has_router_id_v4) {
		memcpy(router_id, &g_router_id_v4, sizeof(*router_id));
		retval = true;
	}
	pthread_mutex_unlock(&g_router_id_v4_mtx);
	return retval;
}

/**
 * Gives the IPv6 router ID received from Zebra.
 *
 * @param router_id The in6_addr strucure where to store the router id
 * @return true if the router ID was available, false otherwise
 */
bool get_ipv6_router_id(struct in6_addr *router_id)
{
	bool retval = false;
	assert(router_id != NULL);
	pthread_mutex_lock(&g_router_id_v6_mtx);
	if (g_has_router_id_v6) {
		memcpy(router_id, &g_router_id_v6, sizeof(*router_id));
		retval = true;
	}
	pthread_mutex_unlock(&g_router_id_v6_mtx);
	return retval;
}

/**
 * Request Label Range to the Label Manager.
 * This range is for dynamic MPLS label range used for policy templates
 *
 * @param base		base label of the label range to request
 * @param chunk_size	size of the label range to request
 *
 * @return 	0 on success, -1 on failure
 */
int path_zebra_request_label_range(uint32_t base, uint32_t chunk_size)
{
	int ret;
	uint32_t start, end;

	if (zclient_sync->sock < 0)
		return -1;

	ret = lm_get_label_chunk(zclient_sync, 0, base, chunk_size, &start,
				 &end);
	if (ret < 0) {
		zlog_warn("%s: error getting label range!", __func__);
		return -1;
	}

	return 0;
}

/**
 * Release Label Range to the Label Manager.
 * This range is for dynamic MPLS label range used for policy templates
 *
 * @param start		start of label range to release
 * @param end		end of label range to release
 *
 * @return		0 on success, -1 otherwise
 */
int path_zebra_release_label_range(uint32_t start, uint32_t end)
{
	int ret;

	if (zclient_sync->sock < 0)
		return -1;

	ret = lm_release_label_chunk(zclient_sync, start, end);
	if (ret < 0) {
		zlog_warn("%s: error releasing label range!", __func__);
		return -1;
	}

	return 0;
}

static void path_zebra_connected(struct zclient *zclient)
{
	struct srte_policy *policy;

	zclient_send_reg_requests(zclient, VRF_DEFAULT);
	zclient_send_router_id_update(zclient, ZEBRA_ROUTER_ID_ADD, AFI_IP6,
				      VRF_DEFAULT);

	path_zebra_fae_igp_opaque_register();
	path_zebra_tsrte_opaque_register();
	zapi_fae_client_ready_send(zclient);
	zapi_tsrte_client_ready_send(zclient,
				     srte_triggered_get_protocol_origin());

	RB_FOREACH (policy, srte_policy_head, &srte_policies) {
		struct srte_candidate *candidate;
		struct srte_segment_list *segment_list;

		candidate = policy->best_candidate;
		if (!candidate)
			continue;

		segment_list = candidate->lsp->segment_list;
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

	srte_candidate_status_update(best_candidate_path,
				     zapi_sr_policy.status);

	return 0;
}

/* Router-id update message from zebra. */
static int path_zebra_router_id_update(ZAPI_CALLBACK_ARGS)
{
	struct prefix pref;
	const char *family;
	char buf[PREFIX2STR_BUFFER];
	zebra_router_id_update_read(zclient->ibuf, &pref);
	if (pref.family == AF_INET) {
		pthread_mutex_lock(&g_router_id_v4_mtx);
		memcpy(&g_router_id_v4, &pref.u.prefix4,
		       sizeof(g_router_id_v4));
		g_has_router_id_v4 = true;
		inet_ntop(AF_INET, &g_router_id_v4, buf, sizeof(buf));
		pthread_mutex_unlock(&g_router_id_v4_mtx);
		family = "IPv4";
	} else if (pref.family == AF_INET6) {
		pthread_mutex_lock(&g_router_id_v6_mtx);
		memcpy(&g_router_id_v6, &pref.u.prefix6,
		       sizeof(g_router_id_v6));
		g_has_router_id_v6 = true;
		inet_ntop(AF_INET6, &g_router_id_v6, buf, sizeof(buf));
		pthread_mutex_unlock(&g_router_id_v6_mtx);
		family = "IPv6";
	} else {
		zlog_warn("Unexpected router ID address family for vrf %u: %u",
			  vrf_id, pref.family);
		return 0;
	}
	zlog_info("%s Router Id updated for VRF %u: %s", family, vrf_id, buf);
	return 0;
}

/**
 * Adds a segment routing policy to Zebra.
 *
 * @param policy The policy to add
 * @param segment_list The segment list for the policy
 */
void path_zebra_add_sr_policy(struct srte_policy *policy,
			      struct srte_segment_list *segment_list)
{
	struct zapi_sr_policy zp = {};
	struct srte_segment_entry *segment;

	zp.color = policy->color;
	zp.endpoint = policy->endpoint;
	strlcpy(zp.name, policy->name, sizeof(zp.name));
	segment = RB_MIN(srte_segment_entry_head, &segment_list->segments);

	if (sid_zero_ipv6(&segment->srv6_sid_value)) {
		zp.segment_list.type = ZEBRA_SR_LSP_SRTE;
		zp.segment_list.local_label = policy->binding_sid;
		zp.segment_list.label_num = 0;
		zp.segment_list.ifindex = segment_list->ifindex;
		RB_FOREACH (segment, srte_segment_entry_head,
			    &segment_list->segments)
			zp.segment_list.labels[zp.segment_list.label_num++] =
				segment->sid_value;
	} else {
		zp.segment_list.type = ZEBRA_SR_SRV6_SRTE;
		zp.segment_list.local_label = MPLS_LABEL_NONE;
		zp.segment_list.srv6_segs.num_segs = 0;
		RB_FOREACH (segment, srte_segment_entry_head,
			    &segment_list->segments)
			IPV6_ADDR_COPY(&zp.segment_list.srv6_segs
						.segs[zp.segment_list.srv6_segs
							      .num_segs++],
				       &segment->srv6_sid_value);
	}
	policy->status = SRTE_POLICY_STATUS_GOING_UP;

	(void)zebra_send_sr_policy(zclient, ZEBRA_SR_POLICY_SET, &zp);
}

/**
 * Deletes a segment policy from Zebra.
 *
 * @param policy The policy to remove
 */
void path_zebra_delete_sr_policy(struct srte_policy *policy)
{
	struct zapi_sr_policy zp = {};
	struct srte_segment_entry *segment;

	zp.color = policy->color;
	zp.endpoint = policy->endpoint;
	strlcpy(zp.name, policy->name, sizeof(zp.name));
	segment = RB_MIN(srte_segment_entry_head,
			 &policy->best_candidate->segment_list->segments);

	if (sid_zero_ipv6(&segment->srv6_sid_value)) {
		zp.segment_list.type = ZEBRA_SR_LSP_SRTE;
		zp.segment_list.local_label = policy->binding_sid;
		zp.segment_list.label_num = 0;
	} else {
		zp.segment_list.local_label = MPLS_LABEL_NONE;
		zp.segment_list.type = ZEBRA_SR_SRV6_SRTE;
		zp.segment_list.srv6_segs.num_segs = 0;
	}
	policy->status = SRTE_POLICY_STATUS_DOWN;

	(void)zebra_send_sr_policy(zclient, ZEBRA_SR_POLICY_DELETE, &zp);
}

/**
 * Allocates a label from Zebra's label manager.
 *
 * @param label the label to be allocated
 * @return 0 if the label has been allocated, -1 otherwise
 */
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

/**
 * Releases a previously allocated label from Zebra's label manager.
 *
 * @param label The label to release
 * @return 0 ifthe label has beel released, -1 otherwise
 */
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

static void path_zebra_tsrte_opaque_register(void)
{
	zclient_register_opaque(zclient, TSRTE_BGP_REGISTER);
	zclient_register_opaque(zclient, TSRTE_BGP_UNREGISTER);
}

void path_zebra_fae_igp_opaque_register(void)
{
	zclient_register_opaque(zclient, FAE_READY);
	zclient_register_opaque(zclient, FAE_NOTREADY);
	zclient_register_opaque(zclient, TSRTE_BGP_READY);

	/*
	 * Must register even to receive unicasts
	 */
	zclient_register_opaque(zclient, FAE_UPDATE);
}

static int path_zebra_opaque_msg_handler(ZAPI_CALLBACK_ARGS)
{
	int ret = 0;
	struct stream *s;
	struct zapi_opaque_msg info;

	s = zclient->ibuf;

	if (zclient_opaque_decode(s, &info) != 0)
		return -1;

	switch (info.type) {
	case LINK_STATE_UPDATE:
	case LINK_STATE_SYNC:
		/* Start receiving ls data so cancel request sync timer */
		path_ted_timer_sync_cancel();

		struct ls_message *msg = ls_parse_msg(s);

		if (msg) {
			zlog_debug("%s: [rcv ted] ls (%s) msg (%s)-(%s) !",
				   __func__,
				   info.type == LINK_STATE_UPDATE
					   ? "LINK_STATE_UPDATE"
					   : "LINK_STATE_SYNC",
				   LS_MSG_TYPE_PRINT(msg->type),
				   LS_MSG_EVENT_PRINT(msg->event));
		} else {
			zlog_err(
				"%s: [rcv ted] Could not parse LinkState stream message.",
				__func__);
			return -1;
		}

		ret = path_ted_rcvd_message(msg);
		ls_delete_msg(msg);
		/* Update local configuration after process update. */
		path_ted_segment_list_refresh();
		break;
	case FAE_READY:
		ret = path_zebra_handle_fae_ready(true, s);
		break;
	case FAE_NOTREADY:
		ret = path_zebra_handle_fae_ready(false, s);
		break;
	case FAE_UPDATE:
		ret = path_zebra_handle_fae_update(s);
		break;
	case TSRTE_BGP_READY:
		ret = path_zebra_handle_tsrte_bgp_ready(zclient, s);
		break;
	case TSRTE_BGP_REGISTER:
	case TSRTE_BGP_UNREGISTER:
		ret = path_zebra_handle_triggered_te_register(s, info.type);
		break;
	default:
		zlog_debug("%s: [rcv ted] unknown opaque event (%d) !",
			   __func__, info.type);
		break;
	}

	return ret;
}

static zclient_handler *const path_handlers[] = {
	[ZEBRA_SR_POLICY_NOTIFY_STATUS] = path_zebra_sr_policy_notify_status,
	[ZEBRA_ROUTER_ID_UPDATE] = path_zebra_router_id_update,
	[ZEBRA_OPAQUE_MESSAGE] = path_zebra_opaque_msg_handler,
};

/**
 * Initializes Zebra asynchronous connection.
 *
 * @param master The master thread
 */
void path_zebra_init(struct event_loop *master)
{
	/* Initialize asynchronous zclient. */
	zclient = zclient_new(master, &zclient_options_default, path_handlers,
			      array_size(path_handlers));
	zclient_init(zclient, ZEBRA_ROUTE_SRTE, 0, &pathd_privs);
	zclient->zebra_connected = path_zebra_connected;

	/* Initialize special zclient for synchronous message exchanges. */
	zclient_sync = zclient_new(master, &zclient_options_sync, NULL, 0);
	zclient_sync->sock = -1;
	zclient_sync->redist_default = ZEBRA_ROUTE_SRTE;
	zclient_sync->instance = 1;
	zclient_sync->privs = &pathd_privs;

	/* Connect to the LM. */
	path_zebra_label_manager_connect();
}

void path_zebra_stop(void)
{
	zclient_unregister_opaque(zclient, FAE_UPDATE);
	zclient_unregister_opaque(zclient, FAE_READY);
	zclient_unregister_opaque(zclient, FAE_NOTREADY);
	zclient_unregister_opaque(zclient, TSRTE_BGP_READY);
	zclient_unregister_opaque(zclient, TSRTE_BGP_REGISTER);
	zclient_unregister_opaque(zclient, TSRTE_BGP_UNREGISTER);

	zclient_stop(zclient);
	zclient_free(zclient);
	zclient_stop(zclient_sync);
	zclient_free(zclient_sync);
}
