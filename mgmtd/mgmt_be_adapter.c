// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Backend Client Connection Adapter
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 */

#include <zebra.h>
#include "darr.h"
#include "frrevent.h"
#include "frrstr.h"
#include "sockopt.h"
#include "network.h"
#include "libfrr.h"
#include "mgmt_msg.h"
#include "mgmt_msg_native.h"
#include "mgmt_pb.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_memory.h"
#include "mgmt_be_client.h"
#include "mgmtd/mgmt_be_adapter.h"

#define __dbg(fmt, ...)                                                        \
	DEBUGD(&mgmt_debug_be, "BE-ADAPTER: %s: " fmt, __func__, ##__VA_ARGS__)
#define __log_err(fmt, ...)                                                    \
	zlog_err("BE-ADAPTER: %s: ERROR: " fmt, __func__, ##__VA_ARGS__)

#define FOREACH_ADAPTER_IN_LIST(adapter)                                       \
	frr_each_safe (mgmt_be_adapters, &mgmt_be_adapters, (adapter))

/* ---------- */
/* Client IDs */
/* ---------- */

const char *mgmt_be_client_names[MGMTD_BE_CLIENT_ID_MAX + 1] = {
	[MGMTD_BE_CLIENT_ID_TESTC] = "mgmtd-testc", /* always first */
	[MGMTD_BE_CLIENT_ID_ZEBRA] = "zebra",
#ifdef HAVE_RIPD
	[MGMTD_BE_CLIENT_ID_RIPD] = "ripd",
#endif
#ifdef HAVE_RIPNGD
	[MGMTD_BE_CLIENT_ID_RIPNGD] = "ripngd",
#endif
#ifdef HAVE_STATICD
	[MGMTD_BE_CLIENT_ID_STATICD] = "staticd",
#endif
	[MGMTD_BE_CLIENT_ID_MAX] = "Unknown/Invalid",
};

/* ------------- */
/* XPATH MAPPING */
/* ------------- */

/*
 * Mapping of YANG XPath prefixes to their corresponding backend clients.
 */
struct mgmt_be_xpath_map {
	char *xpath_prefix;
	uint64_t clients;
};

/*
 * Each client gets their own map, but also union all the strings into the
 * above map as well.
 */

static const char *const zebra_config_xpaths[] = {
	"/frr-affinity-map:lib",
	"/frr-filter:lib",
	"/frr-route-map:lib",
	"/frr-zebra:zebra",
	"/frr-interface:lib",
	"/frr-vrf:lib",
	NULL,
};

static const char *const zebra_oper_xpaths[] = {
	"/frr-interface:lib/interface",
	"/frr-vrf:lib/vrf/frr-zebra:zebra",
	"/frr-zebra:zebra",
	NULL,
};

#if HAVE_RIPD
static const char *const ripd_config_xpaths[] = {
	"/frr-filter:lib",
	"/frr-interface:lib/interface",
	"/frr-ripd:ripd",
	"/frr-route-map:lib",
	"/frr-vrf:lib",
	"/ietf-key-chain:key-chains",
	NULL,
};
static const char *const ripd_oper_xpaths[] = {
	"/frr-ripd:ripd",
	"/ietf-key-chain:key-chains",
	NULL,
};
static const char *const ripd_rpc_xpaths[] = {
	"/frr-ripd",
	NULL,
};
#endif

#if HAVE_RIPNGD
static const char *const ripngd_config_xpaths[] = {
	"/frr-filter:lib",
	"/frr-interface:lib/interface",
	"/frr-ripngd:ripngd",
	"/frr-route-map:lib",
	"/frr-vrf:lib",
	NULL,
};
static const char *const ripngd_oper_xpaths[] = {
	"/frr-ripngd:ripngd",
	NULL,
};
static const char *const ripngd_rpc_xpaths[] = {
	"/frr-ripngd",
	NULL,
};
#endif

#if HAVE_STATICD
static const char *const staticd_config_xpaths[] = {
	"/frr-vrf:lib",
	"/frr-interface:lib",
	"/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd",
	NULL,
};
#endif

static const char *const *be_client_config_xpaths[MGMTD_BE_CLIENT_ID_MAX] = {
	[MGMTD_BE_CLIENT_ID_ZEBRA] = zebra_config_xpaths,
#ifdef HAVE_RIPD
	[MGMTD_BE_CLIENT_ID_RIPD] = ripd_config_xpaths,
#endif
#ifdef HAVE_RIPNGD
	[MGMTD_BE_CLIENT_ID_RIPNGD] = ripngd_config_xpaths,
#endif
#ifdef HAVE_STATICD
	[MGMTD_BE_CLIENT_ID_STATICD] = staticd_config_xpaths,
#endif
};

static const char *const *be_client_oper_xpaths[MGMTD_BE_CLIENT_ID_MAX] = {
#ifdef HAVE_RIPD
	[MGMTD_BE_CLIENT_ID_RIPD] = ripd_oper_xpaths,
#endif
#ifdef HAVE_RIPNGD
	[MGMTD_BE_CLIENT_ID_RIPNGD] = ripngd_oper_xpaths,
#endif
	[MGMTD_BE_CLIENT_ID_ZEBRA] = zebra_oper_xpaths,
};

static const char *const *be_client_notif_xpaths[MGMTD_BE_CLIENT_ID_MAX] = {
};

static const char *const *be_client_rpc_xpaths[MGMTD_BE_CLIENT_ID_MAX] = {
#ifdef HAVE_RIPD
	[MGMTD_BE_CLIENT_ID_RIPD] = ripd_rpc_xpaths,
#endif
#ifdef HAVE_RIPNGD
	[MGMTD_BE_CLIENT_ID_RIPNGD] = ripngd_rpc_xpaths,
#endif
};

/*
 * We would like to have a better ADT than one with O(n) comparisons
 *
 * Perhaps it's possible to sort this array in a way that allows binary search
 * to find the start, then walk until no possible match can follow? Intuition
 * says this probably involves exact match/no-match on a stem in the map array
 * or something like that.
 */

static struct mgmt_be_xpath_map *be_cfg_xpath_map;
static struct mgmt_be_xpath_map *be_oper_xpath_map;
static struct mgmt_be_xpath_map *be_notif_xpath_map;
static struct mgmt_be_xpath_map *be_rpc_xpath_map;

static struct event_loop *mgmt_loop;
static struct msg_server mgmt_be_server = {.fd = -1};

static struct mgmt_be_adapters_head mgmt_be_adapters;

static struct mgmt_be_client_adapter
	*mgmt_be_adapters_by_id[MGMTD_BE_CLIENT_ID_MAX];


/* Forward declarations */
static void
mgmt_be_adapter_sched_init_event(struct mgmt_be_client_adapter *adapter);

static bool be_is_client_interested(const char *xpath, enum mgmt_be_client_id id,
				    enum mgmt_be_xpath_subscr_type type);

const char *mgmt_be_client_id2name(enum mgmt_be_client_id id)
{
	if (id > MGMTD_BE_CLIENT_ID_MAX)
		return "invalid client id";
	return mgmt_be_client_names[id];
}

static enum mgmt_be_client_id mgmt_be_client_name2id(const char *name)
{
	enum mgmt_be_client_id id;

	FOREACH_MGMTD_BE_CLIENT_ID (id) {
		if (!strncmp(mgmt_be_client_names[id], name,
			     MGMTD_CLIENT_NAME_MAX_LEN))
			return id;
	}

	return MGMTD_BE_CLIENT_ID_MAX;
}

static struct mgmt_be_client_adapter *
mgmt_be_find_adapter_by_fd(int conn_fd)
{
	struct mgmt_be_client_adapter *adapter;

	FOREACH_ADAPTER_IN_LIST (adapter) {
		if (adapter->conn->fd == conn_fd)
			return adapter;
	}

	return NULL;
}

static struct mgmt_be_client_adapter *
mgmt_be_find_adapter_by_name(const char *name)
{
	struct mgmt_be_client_adapter *adapter;

	FOREACH_ADAPTER_IN_LIST (adapter) {
		if (!strncmp(adapter->name, name, sizeof(adapter->name)))
			return adapter;
	}

	return NULL;
}

static void mgmt_register_client_xpath(enum mgmt_be_client_id id,
				       const char *xpath,
				       enum mgmt_be_xpath_subscr_type type)
{
	struct mgmt_be_xpath_map **maps, *map;

	switch (type) {
	case MGMT_BE_XPATH_SUBSCR_TYPE_CFG:
		maps = &be_cfg_xpath_map;
		break;
	case MGMT_BE_XPATH_SUBSCR_TYPE_OPER:
		maps = &be_oper_xpath_map;
		break;
	case MGMT_BE_XPATH_SUBSCR_TYPE_NOTIF:
		maps = &be_notif_xpath_map;
		break;
	case MGMT_BE_XPATH_SUBSCR_TYPE_RPC:
		maps = &be_rpc_xpath_map;
		break;
	}

	darr_foreach_p (*maps, map) {
		if (!strcmp(xpath, map->xpath_prefix)) {
			map->clients |= (1u << id);
			return;
		}
	}
	/* we didn't find a matching entry */
	map = darr_append(*maps);
	map->xpath_prefix = XSTRDUP(MTYPE_MGMTD_XPATH, xpath);
	map->clients = (1ul << id);
}

/*
 * initial the combined maps from per client maps
 */
static void mgmt_be_xpath_map_init(void)
{
	enum mgmt_be_client_id id;
	const char *const *init;

	__dbg("Init XPath Maps");

	FOREACH_MGMTD_BE_CLIENT_ID (id) {
		/* Initialize the common config init map */
		for (init = be_client_config_xpaths[id]; init && *init; init++) {
			__dbg(" - CFG XPATH: '%s'", *init);
			mgmt_register_client_xpath(id, *init,
						   MGMT_BE_XPATH_SUBSCR_TYPE_CFG);
		}

		/* Initialize the common oper init map */
		for (init = be_client_oper_xpaths[id]; init && *init; init++) {
			__dbg(" - OPER XPATH: '%s'", *init);
			mgmt_register_client_xpath(id, *init,
						   MGMT_BE_XPATH_SUBSCR_TYPE_OPER);
		}

		/* Initialize the common NOTIF init map */
		for (init = be_client_notif_xpaths[id]; init && *init; init++) {
			__dbg(" - NOTIF XPATH: '%s'", *init);
			mgmt_register_client_xpath(id, *init,
						   MGMT_BE_XPATH_SUBSCR_TYPE_NOTIF);
		}

		/* Initialize the common RPC init map */
		for (init = be_client_rpc_xpaths[id]; init && *init; init++) {
			__dbg(" - RPC XPATH: '%s'", *init);
			mgmt_register_client_xpath(id, *init,
						   MGMT_BE_XPATH_SUBSCR_TYPE_RPC);
		}
	}

	__dbg("Total Cfg XPath Maps: %u", darr_len(be_cfg_xpath_map));
	__dbg("Total Oper XPath Maps: %u", darr_len(be_oper_xpath_map));
	__dbg("Total Noitf XPath Maps: %u", darr_len(be_notif_xpath_map));
	__dbg("Total RPC XPath Maps: %u", darr_len(be_rpc_xpath_map));
}

static void mgmt_be_xpath_map_cleanup(void)
{
	struct mgmt_be_xpath_map *map;

	darr_foreach_p (be_cfg_xpath_map, map)
		XFREE(MTYPE_MGMTD_XPATH, map->xpath_prefix);
	darr_free(be_cfg_xpath_map);

	darr_foreach_p (be_oper_xpath_map, map)
		XFREE(MTYPE_MGMTD_XPATH, map->xpath_prefix);
	darr_free(be_oper_xpath_map);

	darr_foreach_p (be_notif_xpath_map, map)
		XFREE(MTYPE_MGMTD_XPATH, map->xpath_prefix);
	darr_free(be_notif_xpath_map);

	darr_foreach_p (be_rpc_xpath_map, map)
		XFREE(MTYPE_MGMTD_XPATH, map->xpath_prefix);
	darr_free(be_rpc_xpath_map);
}


/*
 * Check if either path or xpath is a prefix of the other. Before checking the
 * xpath is converted to a regular path string (e..g, removing key value
 * specifiers).
 */
static bool mgmt_be_xpath_prefix(const char *path, const char *xpath)
{
	int xc, pc;

	while ((xc = *xpath++)) {
		if (xc == '[') {
			xpath = frrstr_skip_over_char(xpath, ']');
			if (!xpath)
				return false;
			continue;
		}
		pc = *path++;
		if (!pc)
			return true;
		if (pc != xc)
			return false;
	}
	return true;
}

static void mgmt_be_adapter_delete(struct mgmt_be_client_adapter *adapter)
{
	__dbg("deleting client adapter '%s'", adapter->name);

	/*
	 * Notify about disconnect for appropriate cleanup
	 */
	mgmt_txn_notify_be_adapter_conn(adapter, false);
	if (adapter->id < MGMTD_BE_CLIENT_ID_MAX) {
		mgmt_be_adapters_by_id[adapter->id] = NULL;
		adapter->id = MGMTD_BE_CLIENT_ID_MAX;
	}

	assert(adapter->refcount == 1);
	mgmt_be_adapter_unlock(&adapter);
}

static int mgmt_be_adapter_notify_disconnect(struct msg_conn *conn)
{
	struct mgmt_be_client_adapter *adapter = conn->user;

	__dbg("notify disconnect for client adapter '%s'", adapter->name);

	mgmt_be_adapter_delete(adapter);

	return 0;
}

static void
mgmt_be_adapter_cleanup_old_conn(struct mgmt_be_client_adapter *adapter)
{
	struct mgmt_be_client_adapter *old;

	FOREACH_ADAPTER_IN_LIST (old) {
		if (old != adapter &&
		    !strncmp(adapter->name, old->name, sizeof(adapter->name))) {
			/*
			 * We have a Zombie lingering around
			 */
			__dbg("Client '%s' (FD:%d) seems to have reconnected. Removing old connection (FD:%d)!",
			      adapter->name, adapter->conn->fd, old->conn->fd);
			/* this will/should delete old */
			msg_conn_disconnect(old->conn, false);
		}
	}
}

static int mgmt_be_adapter_send_msg(struct mgmt_be_client_adapter *adapter,
				    Mgmtd__BeMessage *be_msg)
{
	return msg_conn_send_msg(
		adapter->conn, MGMT_MSG_VERSION_PROTOBUF, be_msg,
		mgmtd__be_message__get_packed_size(be_msg),
		(size_t(*)(void *, void *))mgmtd__be_message__pack, false);
}

static int mgmt_be_send_subscr_reply(struct mgmt_be_client_adapter *adapter,
				     bool success)
{
	Mgmtd__BeMessage be_msg;
	Mgmtd__BeSubscribeReply reply;

	mgmtd__be_subscribe_reply__init(&reply);
	reply.success = success;

	mgmtd__be_message__init(&be_msg);
	be_msg.message_case = MGMTD__BE_MESSAGE__MESSAGE_SUBSCR_REPLY;
	be_msg.subscr_reply = &reply;

	__dbg("Sending SUBSCR_REPLY client: %s sucess: %u", adapter->name,
	      success);

	return mgmt_be_adapter_send_msg(adapter, &be_msg);
}

static int
mgmt_be_adapter_handle_msg(struct mgmt_be_client_adapter *adapter,
			      Mgmtd__BeMessage *be_msg)
{
	const char *xpath;
	uint i, num;

	/*
	 * protobuf-c adds a max size enum with an internal, and changing by
	 * version, name; cast to an int to avoid unhandled enum warnings
	 */
	switch ((int)be_msg->message_case) {
	case MGMTD__BE_MESSAGE__MESSAGE_SUBSCR_REQ:
		__dbg("Got SUBSCR_REQ from '%s' to register xpaths config: %zu oper: %zu notif: %zu rpc: %zu",
		      be_msg->subscr_req->client_name,
		      be_msg->subscr_req->n_config_xpaths,
		      be_msg->subscr_req->n_oper_xpaths,
		      be_msg->subscr_req->n_notif_xpaths,
		      be_msg->subscr_req->n_rpc_xpaths);

		if (strlen(be_msg->subscr_req->client_name)) {
			strlcpy(adapter->name, be_msg->subscr_req->client_name,
				sizeof(adapter->name));
			adapter->id = mgmt_be_client_name2id(adapter->name);
			if (adapter->id >= MGMTD_BE_CLIENT_ID_MAX) {
				__log_err("Unable to resolve adapter '%s' to a valid ID. Disconnecting!",
					  adapter->name);
				/* this will/should delete old */
				msg_conn_disconnect(adapter->conn, false);
				break;
			}
			mgmt_be_adapters_by_id[adapter->id] = adapter;
			mgmt_be_adapter_cleanup_old_conn(adapter);

			/* schedule INIT sequence now that it is registered */
			mgmt_be_adapter_sched_init_event(adapter);
		}

		num = be_msg->subscr_req->n_config_xpaths;
		for (i = 0; i < num; i++) {
			xpath = be_msg->subscr_req->config_xpaths[i];
			mgmt_register_client_xpath(adapter->id, xpath,
						   MGMT_BE_XPATH_SUBSCR_TYPE_CFG);
		}

		num = be_msg->subscr_req->n_oper_xpaths;
		for (i = 0; i < num; i++) {
			xpath = be_msg->subscr_req->oper_xpaths[i];
			mgmt_register_client_xpath(adapter->id, xpath,
						   MGMT_BE_XPATH_SUBSCR_TYPE_OPER);
		}

		num = be_msg->subscr_req->n_notif_xpaths;
		for (i = 0; i < num; i++) {
			xpath = be_msg->subscr_req->notif_xpaths[i];
			mgmt_register_client_xpath(adapter->id, xpath,
						   MGMT_BE_XPATH_SUBSCR_TYPE_NOTIF);
		}

		num = be_msg->subscr_req->n_rpc_xpaths;
		for (i = 0; i < num; i++) {
			xpath = be_msg->subscr_req->rpc_xpaths[i];
			mgmt_register_client_xpath(adapter->id, xpath,
						   MGMT_BE_XPATH_SUBSCR_TYPE_RPC);
		}

		mgmt_be_send_subscr_reply(adapter, true);
		break;
	case MGMTD__BE_MESSAGE__MESSAGE_TXN_REPLY:
		__dbg("Got %s TXN_REPLY from '%s' txn-id %" PRIx64 " with '%s'",
		      be_msg->txn_reply->create ? "Create" : "Delete",
		      adapter->name, be_msg->txn_reply->txn_id,
		      be_msg->txn_reply->success ? "success" : "failure");
		/*
		 * Forward the TXN_REPLY to txn module.
		 */
		mgmt_txn_notify_be_txn_reply(
			be_msg->txn_reply->txn_id,
			be_msg->txn_reply->create,
			be_msg->txn_reply->success, adapter);
		break;
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_DATA_REPLY:
		__dbg("Got CFGDATA_REPLY from '%s' txn-id %" PRIx64 " err:'%s'",
		      adapter->name, be_msg->cfg_data_reply->txn_id,
		      be_msg->cfg_data_reply->error_if_any
			      ? be_msg->cfg_data_reply->error_if_any
			      : "None");
		/*
		 * Forward the CGFData-create reply to txn module.
		 */
		mgmt_txn_notify_be_cfgdata_reply(
			be_msg->cfg_data_reply->txn_id,
			be_msg->cfg_data_reply->success,
			be_msg->cfg_data_reply->error_if_any, adapter);
		break;
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_APPLY_REPLY:
		__dbg("Got %s CFG_APPLY_REPLY from '%s' txn-id %" PRIx64
		      " err:'%s'",
		      be_msg->cfg_apply_reply->success ? "successful" : "failed",
		      adapter->name, be_msg->cfg_apply_reply->txn_id,
		      be_msg->cfg_apply_reply->error_if_any
			      ? be_msg->cfg_apply_reply->error_if_any
			      : "None");
		/*
		 * Forward the CGFData-apply reply to txn module.
		 */
		mgmt_txn_notify_be_cfg_apply_reply(
			be_msg->cfg_apply_reply->txn_id,
			be_msg->cfg_apply_reply->success,
			be_msg->cfg_apply_reply->error_if_any, adapter);
		break;
	/*
	 * NOTE: The following messages are always sent from MGMTD to
	 * Backend clients only and/or need not be handled on MGMTd.
	 */
	case MGMTD__BE_MESSAGE__MESSAGE_SUBSCR_REPLY:
	case MGMTD__BE_MESSAGE__MESSAGE_TXN_REQ:
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_DATA_REQ:
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_APPLY_REQ:
	case MGMTD__BE_MESSAGE__MESSAGE__NOT_SET:
	default:
		/*
		 * A 'default' case is being added contrary to the
		 * FRR code guidelines to take care of build
		 * failures on certain build systems (courtesy of
		 * the proto-c package).
		 */
		break;
	}

	return 0;
}

int mgmt_be_send_txn_req(struct mgmt_be_client_adapter *adapter,
			 uint64_t txn_id, bool create)
{
	Mgmtd__BeMessage be_msg;
	Mgmtd__BeTxnReq txn_req;

	mgmtd__be_txn_req__init(&txn_req);
	txn_req.create = create;
	txn_req.txn_id = txn_id;

	mgmtd__be_message__init(&be_msg);
	be_msg.message_case = MGMTD__BE_MESSAGE__MESSAGE_TXN_REQ;
	be_msg.txn_req = &txn_req;

	__dbg("Sending TXN_REQ to '%s' txn-id: %" PRIu64, adapter->name, txn_id);

	return mgmt_be_adapter_send_msg(adapter, &be_msg);
}

int mgmt_be_send_cfgdata_req(struct mgmt_be_client_adapter *adapter,
			     uint64_t txn_id,
			     Mgmtd__YangCfgDataReq **cfgdata_reqs,
			     size_t num_reqs, bool end_of_data)
{
	Mgmtd__BeMessage be_msg;
	Mgmtd__BeCfgDataCreateReq cfgdata_req;

	mgmtd__be_cfg_data_create_req__init(&cfgdata_req);
	cfgdata_req.txn_id = txn_id;
	cfgdata_req.data_req = cfgdata_reqs;
	cfgdata_req.n_data_req = num_reqs;
	cfgdata_req.end_of_data = end_of_data;

	mgmtd__be_message__init(&be_msg);
	be_msg.message_case = MGMTD__BE_MESSAGE__MESSAGE_CFG_DATA_REQ;
	be_msg.cfg_data_req = &cfgdata_req;

	__dbg("Sending CFGDATA_CREATE_REQ to '%s' txn-id: %" PRIu64 " last: %s",
	      adapter->name, txn_id, end_of_data ? "yes" : "no");

	return mgmt_be_adapter_send_msg(adapter, &be_msg);
}

int mgmt_be_send_cfgapply_req(struct mgmt_be_client_adapter *adapter,
			      uint64_t txn_id)
{
	Mgmtd__BeMessage be_msg;
	Mgmtd__BeCfgDataApplyReq apply_req;

	mgmtd__be_cfg_data_apply_req__init(&apply_req);
	apply_req.txn_id = txn_id;

	mgmtd__be_message__init(&be_msg);
	be_msg.message_case = MGMTD__BE_MESSAGE__MESSAGE_CFG_APPLY_REQ;
	be_msg.cfg_apply_req = &apply_req;

	__dbg("Sending CFG_APPLY_REQ to '%s' txn-id: %" PRIu64, adapter->name,
	      txn_id);

	return mgmt_be_adapter_send_msg(adapter, &be_msg);
}

int mgmt_be_send_native(enum mgmt_be_client_id id, void *msg)
{
	struct mgmt_be_client_adapter *adapter = mgmt_be_get_adapter_by_id(id);

	if (!adapter)
		return -1;

	return mgmt_msg_native_send_msg(adapter->conn, msg, false);
}

static void mgmt_be_adapter_send_notify(struct mgmt_msg_notify_data *msg,
					size_t msglen)
{
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_be_xpath_map *map;
	struct nb_node *nb_node;
	const char *notif;
	uint id, len;

	if (!darr_len(be_notif_xpath_map))
		return;

	notif = mgmt_msg_native_xpath_decode(msg, msglen);
	if (!notif) {
		__log_err("Corrupt notify msg");
		return;
	}

	nb_node = nb_node_find(notif);
	if (!nb_node) {
		__log_err("No schema found for notification: %s", notif);
		return;
	}

	darr_foreach_p (be_notif_xpath_map, map) {
		len = strlen(map->xpath_prefix);
		if (strncmp(map->xpath_prefix, nb_node->xpath, len) &&
		    strncmp(map->xpath_prefix, notif, len))
			continue;

		FOREACH_BE_CLIENT_BITS (id, map->clients) {
			adapter = mgmt_be_get_adapter_by_id(id);
			if (!adapter)
				continue;
			msg_conn_send_msg(adapter->conn, MGMT_MSG_VERSION_NATIVE,
					  msg, msglen, NULL, false);
		}
	}
}

/*
 * Handle a native encoded message
 */
static void be_adapter_handle_native_msg(struct mgmt_be_client_adapter *adapter,
					 struct mgmt_msg_header *msg,
					 size_t msg_len)
{
	struct mgmt_msg_notify_data *notify_msg;
	struct mgmt_msg_tree_data *tree_msg;
	struct mgmt_msg_rpc_reply *rpc_msg;
	struct mgmt_msg_error *error_msg;

	/* get the transaction */

	switch (msg->code) {
	case MGMT_MSG_CODE_ERROR:
		error_msg = (typeof(error_msg))msg;
		__dbg("Got ERROR from '%s' txn-id %" PRIx64, adapter->name,
		      msg->refer_id);

		/* Forward the reply to the txn module */
		mgmt_txn_notify_error(adapter, msg->refer_id, msg->req_id,
				      error_msg->error, error_msg->errstr);

		break;
	case MGMT_MSG_CODE_TREE_DATA:
		/* tree data from a backend client */
		tree_msg = (typeof(tree_msg))msg;
		__dbg("Got TREE_DATA from '%s' txn-id %" PRIx64, adapter->name,
		      msg->refer_id);

		/* Forward the reply to the txn module */
		mgmt_txn_notify_tree_data_reply(adapter, tree_msg, msg_len);
		break;
	case MGMT_MSG_CODE_RPC_REPLY:
		/* RPC reply from a backend client */
		rpc_msg = (typeof(rpc_msg))msg;
		__dbg("Got RPC_REPLY from '%s' txn-id %" PRIx64, adapter->name,
		      msg->refer_id);

		/* Forward the reply to the txn module */
		mgmt_txn_notify_rpc_reply(adapter, rpc_msg, msg_len);
		break;
	case MGMT_MSG_CODE_NOTIFY:
		notify_msg = (typeof(notify_msg))msg;
		__dbg("Got NOTIFY from '%s'", adapter->name);
		mgmt_be_adapter_send_notify(notify_msg, msg_len);
		mgmt_fe_adapter_send_notify(notify_msg, msg_len);
		break;
	default:
		__log_err("unknown native message txn-id %" PRIu64
			  " req-id %" PRIu64
			  " code %u from BE client for adapter %s",
			  msg->refer_id, msg->req_id, msg->code, adapter->name);
		break;
	}
}


static void mgmt_be_adapter_process_msg(uint8_t version, uint8_t *data,
					size_t len, struct msg_conn *conn)
{
	struct mgmt_be_client_adapter *adapter = conn->user;
	Mgmtd__BeMessage *be_msg;

	if (version == MGMT_MSG_VERSION_NATIVE) {
		struct mgmt_msg_header *msg = (typeof(msg))data;

		if (len >= sizeof(*msg))
			be_adapter_handle_native_msg(adapter, msg, len);
		else
			__log_err("native message to adapter %s too short %zu",
				  adapter->name, len);
		return;
	}

	be_msg = mgmtd__be_message__unpack(NULL, len, data);
	if (!be_msg) {
		__dbg("Failed to decode %zu bytes for adapter: %s", len,
		      adapter->name);
		return;
	}
	__dbg("Decoded %zu bytes of message: %u for adapter: %s", len,
	      be_msg->message_case, adapter->name);
	(void)mgmt_be_adapter_handle_msg(adapter, be_msg);
	mgmtd__be_message__free_unpacked(be_msg, NULL);
}

/*
 * Args for callback
 */
struct mgmt_be_get_adapter_config_params {
	struct mgmt_be_client_adapter *adapter;
	struct nb_config_cbs *cfg_chgs;
	uint32_t seq;
};

/*
 * Initialize a BE client over a new connection
 */
static void mgmt_be_adapter_conn_init(struct event *thread)
{
	struct mgmt_be_client_adapter *adapter;

	adapter = (struct mgmt_be_client_adapter *)EVENT_ARG(thread);
	assert(adapter && adapter->conn->fd >= 0);

	/*
	 * Notify TXN module to create a CONFIG transaction and
	 * download the CONFIGs identified for this new client.
	 * If the TXN module fails to initiate the CONFIG transaction
	 * retry a bit later. It only fails if there's an existing config
	 * transaction in progress.
	 */
	if (mgmt_txn_notify_be_adapter_conn(adapter, true) != 0) {
		zlog_err("XXX txn in progress, retry init");
		mgmt_be_adapter_sched_init_event(adapter);
		return;
	}
}

/*
 * Schedule the initialization of the BE client connection.
 */
static void
mgmt_be_adapter_sched_init_event(struct mgmt_be_client_adapter *adapter)
{
	event_add_timer_msec(mgmt_loop, mgmt_be_adapter_conn_init, adapter,
			     MGMTD_BE_CONN_INIT_DELAY_MSEC,
			     &adapter->conn_init_ev);
}

void mgmt_be_adapter_lock(struct mgmt_be_client_adapter *adapter)
{
	adapter->refcount++;
}

extern void mgmt_be_adapter_unlock(struct mgmt_be_client_adapter **adapter)
{
	struct mgmt_be_client_adapter *a = *adapter;
	assert(a && a->refcount);

	if (!--a->refcount) {
		mgmt_be_adapters_del(&mgmt_be_adapters, a);
		EVENT_OFF(a->conn_init_ev);
		msg_server_conn_delete(a->conn);
		XFREE(MTYPE_MGMTD_BE_ADPATER, a);
	}

	*adapter = NULL;
}

/*
 * Initialize the BE adapter module
 */
void mgmt_be_adapter_init(struct event_loop *tm)
{
	char server_path[MAXPATHLEN];

	assert(!mgmt_loop);
	mgmt_loop = tm;

	mgmt_be_adapters_init(&mgmt_be_adapters);
	mgmt_be_xpath_map_init();

	snprintf(server_path, sizeof(server_path), MGMTD_BE_SOCK_NAME);

	if (msg_server_init(&mgmt_be_server, server_path, tm,
			    mgmt_be_create_adapter, "backend", &mgmt_debug_be)) {
		zlog_err("cannot initialize backend server");
		exit(1);
	}
}

/*
 * Destroy the BE adapter module
 */
void mgmt_be_adapter_destroy(void)
{
	struct mgmt_be_client_adapter *adapter;

	msg_server_cleanup(&mgmt_be_server);
	FOREACH_ADAPTER_IN_LIST (adapter) {
		mgmt_be_adapter_delete(adapter);
	}
	mgmt_be_xpath_map_cleanup();
}

/*
 * The server accepted a new connection
 */
struct msg_conn *mgmt_be_create_adapter(int conn_fd, union sockunion *from)
{
	struct mgmt_be_client_adapter *adapter = NULL;

	assert(!mgmt_be_find_adapter_by_fd(conn_fd));

	adapter = XCALLOC(MTYPE_MGMTD_BE_ADPATER,
			  sizeof(struct mgmt_be_client_adapter));
	adapter->id = MGMTD_BE_CLIENT_ID_MAX;
	snprintf(adapter->name, sizeof(adapter->name), "Unknown-FD-%d",
		 conn_fd);

	mgmt_be_adapter_lock(adapter);
	mgmt_be_adapters_add_tail(&mgmt_be_adapters, adapter);
	RB_INIT(nb_config_cbs, &adapter->cfg_chgs);

	adapter->conn = msg_server_conn_create(mgmt_loop, conn_fd,
					       mgmt_be_adapter_notify_disconnect,
					       mgmt_be_adapter_process_msg,
					       MGMTD_BE_MAX_NUM_MSG_PROC,
					       MGMTD_BE_MAX_NUM_MSG_WRITE,
					       MGMTD_BE_MAX_MSG_LEN, adapter,
					       "BE-adapter");

	adapter->conn->debug = DEBUG_MODE_CHECK(&mgmt_debug_be, DEBUG_MODE_ALL);

	__dbg("Added new MGMTD Backend adapter '%s'", adapter->name);

	return adapter->conn;
}

struct mgmt_be_client_adapter *
mgmt_be_get_adapter_by_id(enum mgmt_be_client_id id)
{
	return (id < MGMTD_BE_CLIENT_ID_MAX ? mgmt_be_adapters_by_id[id] : NULL);
}

struct mgmt_be_client_adapter *
mgmt_be_get_adapter_by_name(const char *name)
{
	return mgmt_be_find_adapter_by_name(name);
}

void mgmt_be_adapter_toggle_client_debug(bool set)
{
	struct mgmt_be_client_adapter *adapter;

	FOREACH_ADAPTER_IN_LIST (adapter)
		adapter->conn->debug = set;
}

/*
 * Get a full set of changes for all the config that an adapter is subscribed to
 * receive.
 */
void mgmt_be_get_adapter_config(struct mgmt_be_client_adapter *adapter,
			       struct nb_config_cbs **changes)
{
	const struct lyd_node *root, *dnode;
	uint32_t seq = 0;
	char *xpath;

	/* We can't be in the middle of sending other chgs when here. */
	assert(RB_EMPTY(nb_config_cbs, &adapter->cfg_chgs));

	*changes = &adapter->cfg_chgs;
	LY_LIST_FOR (running_config->dnode, root) {
		LYD_TREE_DFS_BEGIN (root, dnode) {
			if (lysc_is_key(dnode->schema))
				goto walk_cont;

			xpath = lyd_path(dnode, LYD_PATH_STD, NULL, 0);
			if (be_is_client_interested(xpath, adapter->id,
						    MGMT_BE_XPATH_SUBSCR_TYPE_CFG))
				nb_config_diff_add_change(*changes, NB_CB_CREATE, &seq, dnode);
			else
				LYD_TREE_DFS_continue = 1; /* skip any subtree */
			free(xpath);
		walk_cont:
			LYD_TREE_DFS_END(root, dnode);
		}
	}
}

uint64_t mgmt_be_interested_clients(const char *xpath,
				    enum mgmt_be_xpath_subscr_type type)
{
	struct mgmt_be_xpath_map *maps = NULL, *map;
	enum mgmt_be_client_id id;
	uint64_t clients;

	switch (type) {
	case MGMT_BE_XPATH_SUBSCR_TYPE_CFG:
		maps = be_cfg_xpath_map;
		break;
	case MGMT_BE_XPATH_SUBSCR_TYPE_OPER:
		maps = be_oper_xpath_map;
		break;
	case MGMT_BE_XPATH_SUBSCR_TYPE_NOTIF:
		maps = be_notif_xpath_map;
		break;
	case MGMT_BE_XPATH_SUBSCR_TYPE_RPC:
		maps = be_rpc_xpath_map;
		break;
	}

	clients = 0;

	__dbg("XPATH: '%s'", xpath);
	darr_foreach_p (maps, map)
		if (mgmt_be_xpath_prefix(map->xpath_prefix, xpath))
			clients |= map->clients;

	if (DEBUG_MODE_CHECK(&mgmt_debug_be, DEBUG_MODE_ALL)) {
		FOREACH_BE_CLIENT_BITS (id, clients)
			__dbg("Cient: %s: subscribed",
			      mgmt_be_client_id2name(id));
	}
	return clients;
}

/**
 * Return true if `client_id` is interested in `xpath` for `config`
 * or oper (!`config`).
 *
 * Args:
 *     xpath - the xpath to check for interest.
 *     client_id - the BE client being checked for.
 *     bool - check for config (vs oper) subscription.
 *
 * Returns:
 *     Interested or not.
 */
static bool be_is_client_interested(const char *xpath, enum mgmt_be_client_id id,
				    enum mgmt_be_xpath_subscr_type type)
{
	uint64_t clients;

	assert(id < MGMTD_BE_CLIENT_ID_MAX);

	__dbg("Checking client: %s for xpath: '%s'", mgmt_be_client_id2name(id),
	      xpath);

	clients = mgmt_be_interested_clients(xpath, type);
	if (IS_IDBIT_SET(clients, id)) {
		__dbg("client: %s: interested", mgmt_be_client_id2name(id));
		return true;
	}

	__dbg("client: %s: not interested", mgmt_be_client_id2name(id));
	return false;
}

void mgmt_be_adapter_status_write(struct vty *vty)
{
	struct mgmt_be_client_adapter *adapter;

	vty_out(vty, "MGMTD Backend Adapters\n");

	FOREACH_ADAPTER_IN_LIST (adapter) {
		vty_out(vty, "  Client: \t\t\t%s\n", adapter->name);
		vty_out(vty, "    Conn-FD: \t\t\t%d\n", adapter->conn->fd);
		vty_out(vty, "    Client-Id: \t\t\t%d\n", adapter->id);
		vty_out(vty, "    Ref-Count: \t\t\t%u\n", adapter->refcount);
		vty_out(vty, "    Msg-Recvd: \t\t\t%" PRIu64 "\n",
			adapter->conn->mstate.nrxm);
		vty_out(vty, "    Bytes-Recvd: \t\t%" PRIu64 "\n",
			adapter->conn->mstate.nrxb);
		vty_out(vty, "    Msg-Sent: \t\t\t%" PRIu64 "\n",
			adapter->conn->mstate.ntxm);
		vty_out(vty, "    Bytes-Sent: \t\t%" PRIu64 "\n",
			adapter->conn->mstate.ntxb);
	}
	vty_out(vty, "  Total: %d\n",
		(int)mgmt_be_adapters_count(&mgmt_be_adapters));
}

static void be_show_xpath_register(struct vty *vty,
				   struct mgmt_be_xpath_map *map)
{
	enum mgmt_be_client_id id;
	const char *astr;

	vty_out(vty, " - xpath: '%s'\n", map->xpath_prefix);
	FOREACH_BE_CLIENT_BITS (id, map->clients) {
		astr = mgmt_be_get_adapter_by_id(id) ? "active" : "inactive";
		vty_out(vty, "   -- %s-client: '%s'\n", astr,
			mgmt_be_client_id2name(id));
	}
}
void mgmt_be_xpath_register_write(struct vty *vty)
{
	struct mgmt_be_xpath_map *map;

	vty_out(vty, "MGMTD Backend CFG XPath Registry: Count: %u\n",
		darr_len(be_oper_xpath_map));
	darr_foreach_p (be_cfg_xpath_map, map)
		be_show_xpath_register(vty, map);

	vty_out(vty, "\nMGMTD Backend OPER XPath Registry: Count: %u\n",
		darr_len(be_oper_xpath_map));
	darr_foreach_p (be_oper_xpath_map, map)
		be_show_xpath_register(vty, map);

	vty_out(vty, "\nMGMTD Backend NOTIFY XPath Registry: Count: %u\n",
		darr_len(be_notif_xpath_map));
	darr_foreach_p (be_notif_xpath_map, map)
		be_show_xpath_register(vty, map);

	vty_out(vty, "\nMGMTD Backend RPC XPath Registry: Count: %u\n",
		darr_len(be_rpc_xpath_map));
	darr_foreach_p (be_rpc_xpath_map, map)
		be_show_xpath_register(vty, map);
}

void mgmt_be_show_xpath_registries(struct vty *vty, const char *xpath)
{
	enum mgmt_be_client_id id;
	struct mgmt_be_client_adapter *adapter;
	uint64_t cclients, nclients, oclients, rclients, combined;

	cclients = mgmt_be_interested_clients(xpath,
					      MGMT_BE_XPATH_SUBSCR_TYPE_CFG);
	oclients = mgmt_be_interested_clients(xpath,
					      MGMT_BE_XPATH_SUBSCR_TYPE_OPER);
	nclients = mgmt_be_interested_clients(xpath,
					      MGMT_BE_XPATH_SUBSCR_TYPE_NOTIF);
	rclients = mgmt_be_interested_clients(xpath,
					      MGMT_BE_XPATH_SUBSCR_TYPE_RPC);
	combined = cclients | nclients | oclients | rclients;

	vty_out(vty, "XPath: '%s'\n", xpath);
	FOREACH_BE_CLIENT_BITS (id, combined) {
		vty_out(vty,
			"  -- Client: '%s'\tconfig:%d notify:%d oper:%d rpc:%d\n",
			mgmt_be_client_id2name(id), IS_IDBIT_SET(cclients, id),
			IS_IDBIT_SET(nclients, id), IS_IDBIT_SET(oclients, id),
			IS_IDBIT_SET(rclients, id));
		adapter = mgmt_be_get_adapter_by_id(id);
		if (adapter)
			vty_out(vty, "    -- Adapter: %p\n", adapter);
	}
}
