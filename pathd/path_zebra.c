// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 */

#include <zebra.h>

#include "frrevent.h"
#include "frrdistance.h"
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

static int path_zebra_opaque_msg_handler(ZAPI_CALLBACK_ARGS);

struct zclient *pathd_zclient;
static struct zclient *zclient_sync;

/* Event to retry synch zapi setup for label-manager */
static struct event *t_sync_connect;

enum path_sync_level {
	PATH_SYNC_NONE = 0,
	PATH_SYNC_CONN,
	PATH_SYNC_HELLO,
	PATH_SYNC_DONE
};
static enum path_sync_level path_sync_client_level;

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
 * @param router_id The in_addr structure where to store the router id
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
 * @param router_id The in6_addr structure where to store the router id
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

static void path_zebra_connected(struct zclient *zclient)
{
	struct srte_policy *policy;

	zclient_send_reg_requests(zclient, VRF_DEFAULT);
	zclient_send_router_id_update(zclient, ZEBRA_ROUTER_ID_ADD, AFI_IP6,
				      VRF_DEFAULT);

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

		/*
		 * A zebra restart wiped the steering route; reinstall it
		 * here because the upcoming UP notification is swallowed
		 * when the policy status never left UP.
		 */
		path_zebra_update_steering_route(policy);
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
	/* The ZAPI name field is 64 bytes, pathd's is 256 so
	 * it is truncated to its first 63 characters: it is not
	 * unique beyond that and must not be used to search for a
	 * policy.  Zebra matches policies by (color, endpoint) not
	 * currently by name.
	 */
	strlcpy(zp.name, policy->name, sizeof(zp.name));
	zp.segment_list.type = ZEBRA_LSP_SRTE;
	zp.segment_list.local_label = policy->binding_sid;
	zp.segment_list.label_num = 0;
	RB_FOREACH (segment, srte_segment_entry_head, &segment_list->segments) {
		if (zp.segment_list.label_num >= MPLS_MAX_LABELS) {
			zlog_warn(
				"%s: SR-TE policy %s (color %u) segment list exceeds maximum of %d labels, aborting install",
				__func__, policy->name, policy->color,
				MPLS_MAX_LABELS);
			return;
		}
		zp.segment_list.labels[zp.segment_list.label_num++] =
			segment->sid_value;
	}
	policy->status = SRTE_POLICY_STATUS_GOING_UP;

	(void)zebra_send_sr_policy(pathd_zclient, ZEBRA_SR_POLICY_SET, &zp);
}

/**
 * Deletes a segment policy from Zebra.
 *
 * @param policy The policy to remove
 */
void path_zebra_delete_sr_policy(struct srte_policy *policy)
{
	struct zapi_sr_policy zp = {};

	zp.color = policy->color;
	zp.endpoint = policy->endpoint;
	/* Truncated at 63 characters, see path_zebra_add_sr_policy(). */
	strlcpy(zp.name, policy->name, sizeof(zp.name));
	zp.segment_list.type = ZEBRA_LSP_SRTE;
	zp.segment_list.local_label = policy->binding_sid;
	zp.segment_list.label_num = 0;
	policy->status = SRTE_POLICY_STATUS_DOWN;

	/*
	 * Withdraw the steering route before zebra tears the policy down.
	 * Otherwise the route is leaked.
	 */
	path_zebra_update_steering_route(policy);

	(void)zebra_send_sr_policy(pathd_zclient, ZEBRA_SR_POLICY_DELETE, &zp);
}


/*
 * Builds and sends the steering route for a policy's endpoint.  The
 * route carries one colored nexthop for every UP PCEP-originated policy.
 * When no such policy remains, the route is deleted.
 *
 * @param policy The policy whose endpoint identifies the route
 * @return The number of policies represented in the route
 */
static int path_zebra_send_steering_route(struct srte_policy *policy)
{
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct srte_policy *iter;
	int num = 0;

	zapi_route_init(&api);
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_SRTE;
	api.safi = SAFI_UNICAST;

	if (IS_IPADDR_V6(&policy->endpoint)) {
		api.prefix.family = AF_INET6;
		api.prefix.prefixlen = IPV6_MAX_BITLEN;
		api.prefix.u.prefix6 = policy->endpoint.ipaddr_v6;
	} else {
		api.prefix.family = AF_INET;
		api.prefix.prefixlen = IPV4_MAX_BITLEN;
		api.prefix.u.prefix4 = policy->endpoint.ipaddr_v4;
	}

	SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	SET_FLAG(api.message, ZAPI_MESSAGE_DISTANCE);
	SET_FLAG(api.message, ZAPI_MESSAGE_SRTE);
	api.distance = ZEBRA_SRTE_DISTANCE_DEFAULT;

	RB_FOREACH (iter, srte_policy_head, &srte_policies) {
		/* Only PCEP-initiated policies get automatic steering */
		if (iter->protocol_origin != SRTE_ORIGIN_PCEP)
			continue;
		/* A policy that is not up must not attract traffic */
		if (iter->status != SRTE_POLICY_STATUS_UP)
			continue;
		/* Another endpoint belongs to another steering route */
		if (!ipaddr_is_same(&iter->endpoint, &policy->endpoint))
			continue;
		/* The zapi nexthop array is full.  Traffic to the endpoint
		 * still steers through the policies already represented;
		 * only the colors beyond the multipath limit carry nothing.
		 */
		if (num == MULTIPATH_NUM) {
			zlog_warn("%s: steering route for %pIA already carries %d colored nexthops; policy color %u (and higher) not represented",
				  __func__, &policy->endpoint, MULTIPATH_NUM, iter->color);
			break;
		}

		api_nh = &api.nexthops[num];
		zapi_nexthop_init(api_nh);
		api_nh->vrf_id = VRF_DEFAULT;
		api_nh->srte_color = iter->color;
		if (IS_IPADDR_V6(&iter->endpoint)) {
			api_nh->type = NEXTHOP_TYPE_IPV6;
			api_nh->gate.ipv6 = iter->endpoint.ipaddr_v6;
		} else {
			api_nh->type = NEXTHOP_TYPE_IPV4;
			api_nh->gate.ipv4 = iter->endpoint.ipaddr_v4;
		}
		SET_FLAG(iter->flags, F_POLICY_STEERING_ROUTE);
		num++;
	}
	api.nexthop_num = num;

	(void)zclient_route_send(num > 0 ? ZEBRA_ROUTE_ADD : ZEBRA_ROUTE_DELETE, pathd_zclient,
				 &api);

	return num;
}

/*
 * Synchronizes the PCE-initiated policy with the policy's operational status.
 * Install the per-destination steering route when a PCEP-originated policy
 * comes up, and withdraw it when the policy goes down or is deleted.
 *
 * @param policy The policy whose steering route should be updated
 */
void path_zebra_update_steering_route(struct srte_policy *policy)
{
	/*
	 * Only PCEP-originated policies: local and BGP policies keep their
	 * existing steering (operator statics / BGP color).
	 */
	if (policy->protocol_origin != SRTE_ORIGIN_PCEP)
		return;

	/*
	 * A policy that is down and never contributed to a steering route
	 * has nothing to install or withdraw.
	 */
	if (policy->status != SRTE_POLICY_STATUS_UP &&
	    !CHECK_FLAG(policy->flags, F_POLICY_STEERING_ROUTE))
		return;

	/*
	 * Always resend the route while any same-endpoint policy is up:
	 * after a zebra restart the route may be gone while the flag
	 * persists, and a repeated add is a no-op.  With no policy left
	 * up for the endpoint, the send deletes the route instead.
	 */
	path_zebra_send_steering_route(policy);

	if (policy->status != SRTE_POLICY_STATUS_UP)
		UNSET_FLAG(policy->flags, F_POLICY_STEERING_ROUTE);
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

/*
 * Initialize and connect the synchronous zclient session for the
 * label-manager. This is prepared to retry on error.
 */
static void path_zebra_label_manager_connect(struct event *event)
{
	if (path_sync_client_level == PATH_SYNC_NONE) {
		/* Connect to label manager. */
		if (zclient_socket_connect(zclient_sync) < 0) {
			zlog_warn("%s: error connecting synchronous zclient!",
				  __func__);
			event_add_timer(master, path_zebra_label_manager_connect,
					NULL, 1, &t_sync_connect);
			return;
		}
		set_nonblocking(zclient_sync->sock);

		path_sync_client_level = PATH_SYNC_CONN;
	}

	/* Send hello to notify zebra this is a synchronous client */
	if (path_sync_client_level == PATH_SYNC_CONN) {
		if (zclient_send_hello(zclient_sync) == ZCLIENT_SEND_FAILURE) {
			zlog_warn("%s: Error sending hello for synchronous zclient!",
				  __func__);
			event_add_timer(master, path_zebra_label_manager_connect,
					NULL, 1, &t_sync_connect);
			return;
		}

		path_sync_client_level = PATH_SYNC_HELLO;
	}

	if (path_sync_client_level == PATH_SYNC_HELLO) {
		if (lm_label_manager_connect(zclient_sync, 0) != 0) {
			zlog_warn("%s: error connecting to label manager!",
				  __func__);
			event_add_timer(master, path_zebra_label_manager_connect,
					NULL, 1, &t_sync_connect);
			return;
		}
		path_sync_client_level = PATH_SYNC_DONE;
	}
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
void path_zebra_init(struct event_loop *loop)
{
	/* Initialize asynchronous zclient. */
	pathd_zclient = zclient_new(loop, &zclient_options_default, path_handlers,
				    array_size(path_handlers));
	zclient_init(pathd_zclient, ZEBRA_ROUTE_SRTE, 0, &pathd_privs);
	pathd_zclient->zebra_connected = path_zebra_connected;

	/* Initialize special zclient for synchronous message exchanges. */
	zclient_sync = zclient_new(master, &zclient_options_sync, NULL, 0);
	zclient_sync->sock = -1;
	zclient_sync->redist_default = ZEBRA_ROUTE_SRTE;
	zclient_sync->instance = 1;
	zclient_sync->privs = &pathd_privs;

	/* Connect to the LM. */
	t_sync_connect = NULL;
	path_zebra_label_manager_connect(NULL);
}

void path_zebra_stop(void)
{
	zclient_stop(pathd_zclient);
	zclient_free(pathd_zclient);
	event_cancel(&t_sync_connect);
	zclient_stop(zclient_sync);
	zclient_free(zclient_sync);
}
