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
#include "jhash.h"
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

struct zclient *zclient;
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

DEFINE_MTYPE_STATIC(PATHD, PATH_NHT_DATA, "Pathd Nexthop tracking data");
PREDECL_HASH(path_nht_hash);

struct path_nht_data {
	struct path_nht_hash_item itm;

	struct prefix nh;

	vrf_id_t nh_vrf_id;

	uint32_t refcount;
	uint8_t nh_num;
	struct nexthop *nexthop;
	bool registered;

	uint32_t metric;
	uint8_t distance;
};

static void
path_zebra_add_sr_policy_internal(struct srte_policy *policy,
				  struct srte_segment_list *segment_list,
				  struct path_nht_data *nhtd);

static int path_nht_data_cmp(const struct path_nht_data *nhtd1,
			     const struct path_nht_data *nhtd2)
{
	if (nhtd1->nh_vrf_id != nhtd2->nh_vrf_id)
		return numcmp(nhtd1->nh_vrf_id, nhtd2->nh_vrf_id);

	return prefix_cmp(&nhtd1->nh, &nhtd2->nh);
}

static unsigned int path_nht_data_hash(const struct path_nht_data *nhtd)
{
	unsigned int key = 0;

	key = prefix_hash_key(&nhtd->nh);
	return jhash_1word(nhtd->nh_vrf_id, key);
}

DECLARE_HASH(path_nht_hash, struct path_nht_data, itm, path_nht_data_cmp,
	     path_nht_data_hash);

static struct path_nht_hash_head path_nht_hash[1];

static struct path_nht_data *path_nht_hash_getref(const struct path_nht_data *ref)
{
	struct path_nht_data *nhtd;

	nhtd = path_nht_hash_find(path_nht_hash, ref);
	if (!nhtd) {
		nhtd = XCALLOC(MTYPE_PATH_NHT_DATA, sizeof(*nhtd));

		prefix_copy(&nhtd->nh, &ref->nh);
		nhtd->nh_vrf_id = ref->nh_vrf_id;

		path_nht_hash_add(path_nht_hash, nhtd);
	}

	nhtd->refcount++;
	return nhtd;
}

static bool path_nht_hash_decref(struct path_nht_data **nhtd_p)
{
	struct path_nht_data *nhtd = *nhtd_p;

	*nhtd_p = NULL;

	if (--nhtd->refcount > 0)
		return true;

	path_nht_hash_del(path_nht_hash, nhtd);
	XFREE(MTYPE_PATH_NHT_DATA, nhtd);
	return false;
}

static void path_nht_hash_clear(void)
{
	struct path_nht_data *nhtd;

	while ((nhtd = path_nht_hash_pop(path_nht_hash))) {
		if (nhtd->nexthop)
			nexthops_free(nhtd->nexthop);
		XFREE(MTYPE_PATH_NHT_DATA, nhtd);
	}
}

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

static bool path_zebra_segment_list_srv6(struct srte_segment_list *segment_list)
{
	struct srte_segment_entry *segment;

	segment = RB_MIN(srte_segment_entry_head, &segment_list->segments);
	if (segment && !IPV6_ADDR_SAME(&segment->srv6_sid_value, &in6addr_any))
		return true;

	return false;
}

static bool path_zebra_nht_get_srv6_prefix(struct srte_segment_list *segment_list,
					   struct prefix *nh)
{
	struct srte_segment_entry *segment;
	bool found = false;

	if (!segment_list)
		return false;

	segment = RB_MIN(srte_segment_entry_head, &segment_list->segments);
	if (segment && !IPV6_ADDR_SAME(&segment->srv6_sid_value, &in6addr_any)) {
		nh->family = AF_INET6;
		nh->prefixlen = IPV6_MAX_BITLEN;
		memcpy(&nh->u.prefix6, &segment->srv6_sid_value,
		       sizeof(struct in6_addr));
		found = true;
	}
	return found;
}

static void path_zebra_add_srv6_policy_internal(struct srte_policy *policy)
{
	struct path_nht_data *nhtd, lookup = {};
	uint32_t cmd;
	struct srte_candidate *candidate;
	struct srte_segment_list *segment_list = NULL;

	candidate = policy->best_candidate;
	if (candidate && candidate->lsp)
		segment_list = candidate->lsp->segment_list;

	if (!segment_list)
		return;

	if (!path_zebra_nht_get_srv6_prefix(segment_list, &lookup.nh))
		return;

	lookup.nh_vrf_id = VRF_DEFAULT;

	if (CHECK_FLAG(segment_list->flags, F_SEGMENT_LIST_NHT_REGISTERED)) {
		/* nh->nh_registered means we own a reference on the nhtd */
		nhtd = path_nht_hash_find(path_nht_hash, &lookup);

		assertf(nhtd, "BUG: NH %pFX registered but not in hashtable",
			&lookup.nh);
	} else {
		nhtd = path_nht_hash_getref(&lookup);

		if (nhtd->refcount > 1)
			zlog_debug("Reusing registered nexthop(%pFX) for candidate %s pref %u (num %d)",
				   &lookup.nh, candidate->name,
				   candidate->preference, nhtd->nh_num);
	}

	SET_FLAG(segment_list->flags, F_SEGMENT_LIST_NHT_REGISTERED);

	if (nhtd->nh_num) {
		path_zebra_add_sr_policy_internal(candidate->policy,
						  segment_list, nhtd);
		return;
	}
	path_zebra_delete_sr_policy(candidate->policy);

	if (nhtd->registered)
		/* have no data, but did send register */
		return;

	cmd = ZEBRA_NEXTHOP_REGISTER;
	zlog_debug("Registering nexthop(%pFX) for candidate %s pref %u",
		   &lookup.nh, candidate->name, candidate->preference);

	if (zclient_send_rnh(zclient, cmd, &lookup.nh, SAFI_UNICAST, false,
			     false, VRF_DEFAULT) == ZCLIENT_SEND_FAILURE)
		zlog_warn("%s: Failure to send nexthop %pFX for candidate %s pref %u to zebra",
			  __func__, &lookup.nh, candidate->name,
			  candidate->preference);
	else
		nhtd->registered = true;
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
		if (path_zebra_segment_list_srv6(segment_list))
			path_zebra_add_srv6_policy_internal(policy);
		else
			path_zebra_add_sr_policy_internal(policy, segment_list,
							  NULL);
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
 * Disconnect from NHT
 */
void path_nht_removed(struct srte_candidate *candidate)
{
	struct path_nht_data *nhtd, lookup;
	struct srte_segment_list *segment_list;
	bool was_zebra_registered;

	if (!candidate || !candidate->lsp)
		return;

	segment_list = candidate->lsp->segment_list;
	if (!segment_list)
		return;

	if (!CHECK_FLAG(segment_list->flags, F_SEGMENT_LIST_NHT_REGISTERED))
		return;

	if (!path_zebra_nht_get_srv6_prefix(segment_list, &lookup.nh))
		return;

	lookup.nh_vrf_id = VRF_DEFAULT;

	/* nh->nh_registered means we own a reference on the nhtd */
	nhtd = path_nht_hash_find(path_nht_hash, &lookup);

	assertf(nhtd, "BUG: NH %pFX registered but not in hashtable",
		&lookup.nh);

	was_zebra_registered = nhtd->registered;
	UNSET_FLAG(segment_list->flags, F_SEGMENT_LIST_NHT_REGISTERED);
	if (path_nht_hash_decref(&nhtd))
		/* still got references alive */
		return;

	/* NB: nhtd is now NULL. */
	if (!was_zebra_registered)
		return;

	zlog_debug("Unregistering nexthop(%pFX) for candidate %s pref %u",
		   &lookup.nh, candidate->name, candidate->preference);

	if (zclient_send_rnh(zclient, ZEBRA_NEXTHOP_UNREGISTER, &lookup.nh,
			     SAFI_UNICAST, false, false,
			     VRF_DEFAULT) == ZCLIENT_SEND_FAILURE)
		zlog_warn("%s: Failure to send nexthop %pFX for candidate %s pref %u to zebra",
			  __func__, &lookup.nh, candidate->name,
			  candidate->preference);
}

/**
 * Adds a segment routing policy to Zebra.
 *
 * @param policy The policy to add
 * @param segment_list The segment list for the policy
 */
static void
path_zebra_add_sr_policy_internal(struct srte_policy *policy,
				  struct srte_segment_list *segment_list,
				  struct path_nht_data *nhtd)
{
	struct zapi_sr_policy zp = {};
	struct srte_segment_entry *segment;
	struct zapi_nexthop *znh;
	struct nexthop *nexthop;
	int num = 0;

	zp.color = policy->color;
	zp.endpoint = policy->endpoint;
	strlcpy(zp.name, policy->name, sizeof(zp.name));

	if (!path_zebra_segment_list_srv6(segment_list)) {
		zp.segment_list.type = ZEBRA_SR_LSP_SRTE;
		zp.segment_list.local_label = policy->binding_sid;
		zp.segment_list.label_num = 0;
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

	if (nhtd && nhtd->nexthop) {
		zp.segment_list.distance = nhtd->distance;
		zp.segment_list.metric = nhtd->metric;
		for (ALL_NEXTHOPS_PTR(nhtd, nexthop)) {
			znh = &zp.segment_list.nexthop_resolved[num++];
			zapi_nexthop_from_nexthop(znh, nexthop);
		}
		zp.segment_list.nexthop_resolved_num = nhtd->nh_num;
	}

	(void)zebra_send_sr_policy(zclient, ZEBRA_SR_POLICY_SET, &zp);
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
	if (path_zebra_segment_list_srv6(segment_list))
		path_zebra_add_srv6_policy_internal(policy);
	else
		path_zebra_add_sr_policy_internal(policy, segment_list, NULL);
}

/**
 * Deletes a segment policy from Zebra.
 *
 * @param policy The policy to remove
 */
void path_zebra_delete_sr_policy(struct srte_policy *policy)
{
	struct zapi_sr_policy zp = {};
	struct srte_segment_entry *segment = NULL;

	zp.color = policy->color;
	zp.endpoint = policy->endpoint;
	strlcpy(zp.name, policy->name, sizeof(zp.name));

	if (policy->best_candidate && policy->best_candidate->segment_list)
		segment =
			RB_MIN(srte_segment_entry_head,
			       &policy->best_candidate->segment_list->segments);

	if (segment && sid_zero_ipv6(&segment->srv6_sid_value)) {
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

static void path_nht_srv6_update(struct prefix *nh, struct path_nht_data *nhtd)
{
	struct srte_policy *policy;
	struct prefix sid_srv6 = {};
	struct srte_candidate *candidate;
	struct srte_segment_list *segment_list;

	RB_FOREACH (policy, srte_policy_head, &srte_policies) {
		if (policy->endpoint.ipa_type != AF_INET6)
			continue;

		candidate = policy->best_candidate;
		if (!candidate)
			continue;
		if (!candidate->lsp)
			continue;
		segment_list = candidate->lsp->segment_list;
		if (!segment_list)
			continue;

		/* srv6 segment lists are registered */
		if (!CHECK_FLAG(segment_list->flags,
				F_SEGMENT_LIST_NHT_REGISTERED))
			continue;

		if (!path_zebra_nht_get_srv6_prefix(segment_list, &sid_srv6))
			continue;
		if (!IPV6_ADDR_SAME(&sid_srv6.u.prefix6, &nh->u.prefix6))
			continue;
		if (nhtd->nh_num)
			path_zebra_add_sr_policy_internal(policy, segment_list,
							  nhtd);
		else
			path_zebra_delete_sr_policy(policy);
	}
}

static bool path_zebra_srv6_nexthop_info_update(struct path_nht_data *nhtd,
						struct zapi_route *nhr)
{
	struct nexthop *nexthop;
	struct nexthop *nhlist_head = NULL;
	struct nexthop *nhlist_tail = NULL;
	struct nexthop *oldnh;
	bool nh_changed = false;
	int i;

	if (nhtd && nhr)
		nhtd->nh_num = nhr->nexthop_num;

	if (!nhr->nexthop_num) {
		nhtd->nh_num = nhr->nexthop_num;
		if (nhtd->nexthop)
			nexthop_free(nhtd->nexthop);
		nhtd->nexthop = NULL;
		return true;
	}

	if (nhtd->distance != nhr->distance || nhtd->metric != nhr->metric) {
		nhtd->distance = nhr->distance;
		nhtd->metric = nhr->metric;
		nh_changed = true;
	}

	for (i = 0; i < nhr->nexthop_num; i++) {
		nexthop = nexthop_from_zapi_nexthop(&nhr->nexthops[i]);

		if (nhlist_tail) {
			nhlist_tail->next = nexthop;
			nhlist_tail = nexthop;
		} else {
			nhlist_tail = nexthop;
			nhlist_head = nexthop;
		}

		for (oldnh = nhtd->nexthop; oldnh; oldnh = oldnh->next)
			if (nexthop_same(oldnh, nexthop))
				break;

		if (!oldnh)
			nh_changed = true;
	}
	if (nhtd->nexthop)
		nexthop_free(nhtd->nexthop);
	nhtd->nexthop = nhlist_head;
	nhr->nexthop_num = nhr->nexthop_num;

	return nh_changed;
}

static void path_zebra_nexthop_update(struct vrf *vrf, struct prefix *match,
				      struct zapi_route *nhr)
{
	struct path_nht_data *nhtd, lookup;

	if (match->family != AF_INET6)
		return;

	memset(&lookup, 0, sizeof(lookup));
	prefix_copy(&lookup.nh, match);
	lookup.nh_vrf_id = vrf->vrf_id;

	nhtd = path_nht_hash_find(path_nht_hash, &lookup);

	if (!nhtd)
		zlog_err("Unable to find next-hop data for the given route.");
	else if (path_zebra_srv6_nexthop_info_update(nhtd, nhr))
		path_nht_srv6_update(&nhr->prefix, nhtd);
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

	zclient->nexthop_update = path_zebra_nexthop_update;

	/* Connect to the LM. */
	t_sync_connect = NULL;
	path_zebra_label_manager_connect(NULL);

	/* Pathd nht init */
	path_nht_hash_init(path_nht_hash);
}

void path_zebra_stop(void)
{
	path_nht_hash_clear();
	path_nht_hash_fini(path_nht_hash);

	zclient_stop(zclient);
	zclient_free(zclient);
	event_cancel(&t_sync_connect);
	zclient_stop(zclient_sync);
	zclient_free(zclient_sync);
}
