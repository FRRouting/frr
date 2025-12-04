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
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_memory.h"
#include "mgmt_be_client.h"
#include "mgmtd/mgmt_be_adapter.h"

#define _dbg(fmt, ...)	   DEBUGD(&mgmt_debug_be, "BE-ADAPTER: %s: " fmt, __func__, ##__VA_ARGS__)
#define _log_err(fmt, ...) zlog_err("BE-ADAPTER: %s: ERROR: " fmt, __func__, ##__VA_ARGS__)

#define FOREACH_ADAPTER_IN_LIST(adapter)                                       \
	frr_each_safe (mgmt_be_adapters, &mgmt_be_adapters, (adapter))

/* ---------- */
/* Client IDs */
/* ---------- */

const char *mgmt_be_client_names[MGMTD_BE_CLIENT_ID_MAX + 1] = {
	[MGMTD_BE_CLIENT_ID_TESTC] = "mgmtd-testc", /* always first */
	[MGMTD_BE_CLIENT_ID_MGMTD] = "mgmtd",	    /* loopback */
	[MGMTD_BE_CLIENT_ID_ZEBRA] = "zebra",
#ifdef HAVE_OSPFD
	[MGMTD_BE_CLIENT_ID_OSPFD] = "ospfd",
#endif
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

/* clang-format off */
static const char *const zebra_config_xpaths[] = {
	"/frr-affinity-map:lib",
	"/frr-filter:lib",
	"/frr-host:host",
	"/frr-logging:logging",
	"/frr-route-map:lib",
	"/frr-zebra:zebra",
	"/frr-interface:lib",
	"/frr-vrf:lib",
	NULL,
};

static const char *const zebra_oper_xpaths[] = {
	"/frr-backend:clients",
	"/frr-interface:lib/interface",
	"/frr-vrf:lib/vrf/frr-zebra:zebra",
	"/frr-zebra:zebra",
	NULL,
};

static const char *const zebra_rpc_xpaths[] = {
	"/frr-logging",
	NULL,
};

/*
 * MGMTD does not use config paths. Config is handled specially since it's own
 * tree is modified directly when processing changes from the front end clients
 */

static const char *const mgmtd_oper_xpaths[] = {
	"/frr-backend:clients",
	NULL,
};

static const char *const mgmtd_rpc_xpaths[] = {
	"/frr-logging",
	NULL,
};


#ifdef HAVE_MGMTD_TESTC
static const char *const mgmtd_testc_oper_xpaths[] = {
	"/frr-backend:clients",
	NULL,
};
#endif

#if HAVE_OSPFD
static const char *const ospfd_oper_xpaths[] = {
	"/frr-interface:lib/interface/state/frr-ospfd-lite:ospf/state/*",
	"/frr-ospfd-lite:ospf/instance/state/*",
	NULL,
};
#endif

#ifdef HAVE_RIPD
static const char *const ripd_config_xpaths[] = {
	"/frr-filter:lib",
	"/frr-host:host",
	"/frr-logging:logging",
	"/frr-interface:lib/interface",
	"/frr-ripd:ripd",
	"/frr-route-map:lib",
	"/frr-vrf:lib",
	"/ietf-key-chain:key-chains",
	NULL,
};
static const char *const ripd_oper_xpaths[] = {
	"/frr-backend:clients",
	"/frr-ripd:ripd",
	"/ietf-key-chain:key-chains",
	NULL,
};
static const char *const ripd_rpc_xpaths[] = {
	"/frr-ripd",
	"/frr-logging",
	NULL,
};
#endif

#ifdef HAVE_RIPNGD
static const char *const ripngd_config_xpaths[] = {
	"/frr-filter:lib",
	"/frr-host:host",
	"/frr-logging:logging",
	"/frr-interface:lib/interface",
	"/frr-ripngd:ripngd",
	"/frr-route-map:lib",
	"/frr-vrf:lib",
	NULL,
};
static const char *const ripngd_oper_xpaths[] = {
	"/frr-backend:clients",
	"/frr-ripngd:ripngd",
	NULL,
};
static const char *const ripngd_rpc_xpaths[] = {
	"/frr-ripngd",
	"/frr-logging",
	NULL,
};
#endif

#ifdef HAVE_STATICD
static const char *const staticd_config_xpaths[] = {
	"/frr-host:host",
	"/frr-logging:logging",
	"/frr-vrf:lib",
	"/frr-interface:lib",
	"/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd",
	NULL,
};
static const char *const staticd_oper_xpaths[] = {
	"/frr-backend:clients",
	NULL,
};
static const char *const staticd_rpc_xpaths[] = {
	"/frr-logging",
	NULL,
};
#endif
/* clang-format on */

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
	[MGMTD_BE_CLIENT_ID_MGMTD] = mgmtd_oper_xpaths,
#ifdef HAVE_MGMTD_TESTC
	[MGMTD_BE_CLIENT_ID_TESTC] = mgmtd_testc_oper_xpaths,
#endif
#ifdef HAVE_RIPD
	[MGMTD_BE_CLIENT_ID_RIPD] = ripd_oper_xpaths,
#endif
#ifdef HAVE_RIPNGD
	[MGMTD_BE_CLIENT_ID_RIPNGD] = ripngd_oper_xpaths,
#endif
#ifdef HAVE_STATICD
	[MGMTD_BE_CLIENT_ID_STATICD] = staticd_oper_xpaths,
#endif
	[MGMTD_BE_CLIENT_ID_ZEBRA] = zebra_oper_xpaths,
#if HAVE_OSPFD
	[MGMTD_BE_CLIENT_ID_OSPFD] = ospfd_oper_xpaths,
#endif
};

static const char *const *be_client_notif_xpaths[MGMTD_BE_CLIENT_ID_MAX] = {
};

static const char *const *be_client_rpc_xpaths[MGMTD_BE_CLIENT_ID_MAX] = {
	[MGMTD_BE_CLIENT_ID_MGMTD] = mgmtd_rpc_xpaths,
#ifdef HAVE_RIPD
	[MGMTD_BE_CLIENT_ID_RIPD] = ripd_rpc_xpaths,
#endif
#ifdef HAVE_RIPNGD
	[MGMTD_BE_CLIENT_ID_RIPNGD] = ripngd_rpc_xpaths,
#endif
#ifdef HAVE_STATICD
	[MGMTD_BE_CLIENT_ID_STATICD] = staticd_rpc_xpaths,
#endif
	[MGMTD_BE_CLIENT_ID_ZEBRA] = zebra_rpc_xpaths,
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

/*
 * Mgmtd has it's own special "interested-in" xpath maps since it's not actually
 * a backend client of itself.
 */
static const char *const mgmtd_config_xpaths[] = {
	"/frr-logging:logging",
};


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

	maps = NULL;

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

	_dbg("Init XPath Maps");

	FOREACH_MGMTD_BE_CLIENT_ID (id) {
		/* Initialize the common config init map */
		for (init = be_client_config_xpaths[id]; init && *init; init++) {
			_dbg(" - CFG XPATH: '%s'", *init);
			mgmt_register_client_xpath(id, *init,
						   MGMT_BE_XPATH_SUBSCR_TYPE_CFG);
		}

		/* Initialize the common oper init map */
		for (init = be_client_oper_xpaths[id]; init && *init; init++) {
			_dbg(" - OPER XPATH: '%s'", *init);
			mgmt_register_client_xpath(id, *init,
						   MGMT_BE_XPATH_SUBSCR_TYPE_OPER);
		}

		/* Initialize the common NOTIF init map */
		for (init = be_client_notif_xpaths[id]; init && *init; init++) {
			_dbg(" - NOTIF XPATH: '%s'", *init);
			mgmt_register_client_xpath(id, *init,
						   MGMT_BE_XPATH_SUBSCR_TYPE_NOTIF);
		}

		/* Initialize the common RPC init map */
		for (init = be_client_rpc_xpaths[id]; init && *init; init++) {
			_dbg(" - RPC XPATH: '%s'", *init);
			mgmt_register_client_xpath(id, *init,
						   MGMT_BE_XPATH_SUBSCR_TYPE_RPC);
		}
	}

	_dbg("Total Cfg XPath Maps: %u", darr_len(be_cfg_xpath_map));
	_dbg("Total Oper XPath Maps: %u", darr_len(be_oper_xpath_map));
	_dbg("Total Notif XPath Maps: %u", darr_len(be_notif_xpath_map));
	_dbg("Total RPC XPath Maps: %u", darr_len(be_rpc_xpath_map));
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
	_dbg("deleting client adapter '%s'", adapter->name);

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

	_dbg("notify disconnect for client adapter '%s'", adapter->name);

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
			_dbg("Client '%s' (FD:%d) seems to have reconnected. Removing old connection (FD:%d)!",
			     adapter->name, adapter->conn->fd, old->conn->fd);
			/* this will/should delete old */
			msg_conn_disconnect(old->conn, false);
		}
	}
}

int mgmt_be_send_txn_req(struct mgmt_be_client_adapter *adapter, uint64_t txn_id, bool create)
{
	struct mgmt_msg_txn_req *msg;
	int ret;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_txn_req, 0, MTYPE_MSG_NATIVE_TXN_REQ);
	msg->code = MGMT_MSG_CODE_TXN_REQ;
	msg->refer_id = txn_id;
	msg->create = create;

	_dbg("Sending TXN_REQ to '%s' to %s txn-id: %Lu", adapter->name,
	     create ? "create" : "delete", txn_id);

	ret = mgmt_msg_native_send_msg(adapter->conn, msg, false);
	mgmt_msg_native_free_msg(msg);
	return ret;
}

int mgmt_be_send_cfgdata_req(struct mgmt_be_client_adapter *adapter, struct mgmt_msg_cfg_req *msg)
{
	int ret;

	_dbg("Sending CFG_REQ to '%s' txn-id: %Lu req-id: %Lu", adapter->name, msg->refer_id,
	     msg->req_id);

	ret = mgmt_msg_native_send_msg(adapter->conn, msg, false);
	if (ret)
		_log_err("Could not send CFG_REQ txn-id: %Lu to client '%s", msg->refer_id,
			 adapter->name);
	return ret;
}

int mgmt_be_send_cfgapply_req(struct mgmt_be_client_adapter *adapter,
			      uint64_t txn_id)
{
	struct mgmt_msg_cfg_apply_req *msg;
	int ret;

	msg = mgmt_msg_native_alloc_msg(struct mgmt_msg_cfg_apply_req, 0,
					MTYPE_MSG_NATIVE_CFG_APPLY_REQ);
	msg->code = MGMT_MSG_CODE_CFG_APPLY_REQ;
	msg->refer_id = txn_id;

	_dbg("Sending CFG_APPLY_REQ to '%s' txn-id: %Lu", adapter->name, txn_id);

	ret = mgmt_msg_native_send_msg(adapter->conn, msg, false);
	mgmt_msg_native_free_msg(msg);
	return ret;
}

int mgmt_be_send_native(enum mgmt_be_client_id id, void *msg)
{
	struct mgmt_be_client_adapter *adapter = mgmt_be_get_adapter_by_id(id);

	if (!adapter)
		return -1;

	return mgmt_msg_native_send_msg(adapter->conn, msg, false);
}

/*
 * Send notification to back-ends that subscribed for them.
 */
static void mgmt_be_adapter_send_notify(struct mgmt_msg_notify_data *msg, size_t msglen,
					struct mgmt_be_client_adapter *from_adapter)
{
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_be_xpath_map *map;
	struct nb_node *nb_node = NULL;
	const char *notif;
	bool is_root;
	uint id, len;

	if (!darr_len(be_notif_xpath_map))
		return;

	notif = mgmt_msg_native_xpath_decode(msg, msglen);
	if (!notif) {
		_log_err("Corrupt notify msg");
		return;
	}

	is_root = !strcmp(notif, "/");
	if (!is_root) {
		nb_node = nb_node_find(notif);
		if (!nb_node) {
			_log_err("No schema found for notification: %s", notif);
			return;
		}
	}

	darr_foreach_p (be_notif_xpath_map, map) {
		if (!is_root) {
			len = strlen(map->xpath_prefix);
			if (strncmp(map->xpath_prefix, nb_node->xpath, len) &&
			    strncmp(map->xpath_prefix, notif, len))
				continue;
		}
		FOREACH_BE_CLIENT_BITS (id, map->clients) {
			adapter = mgmt_be_get_adapter_by_id(id);
			if (!adapter || adapter == from_adapter)
				continue;

			msg_conn_send_msg(adapter->conn, MGMT_MSG_VERSION_NATIVE,
					  msg, msglen, NULL, false);
		}
	}
}

static void be_adapter_handle_subscribe(struct mgmt_msg_subscribe *msg, size_t msg_len,
					struct mgmt_be_client_adapter *adapter)
{
	const char **s = NULL;
	uint i = 0;

	s = mgmt_msg_native_strings_decode(msg, msg_len, msg->strings);
	if (!s) {
		_log_err("Corrupt subscribe msg from '%s'", adapter->name);
		msg_conn_disconnect(adapter->conn, false);
		return;
	}
	if (darr_len(s) != (1u + msg->nconfig + msg->noper + msg->nnotify + msg->nrpc)) {
		_log_err("Corrupt subscribe msg from '%s': len == %u", adapter->name, darr_len(s));
		msg_conn_disconnect(adapter->conn, false);
		goto done;
	}

	_dbg("\"%s\" now known as \"%s\"", adapter->name, s[i]);

	strlcpy(adapter->name, s[i++], sizeof(adapter->name));
	adapter->id = mgmt_be_client_name2id(adapter->name);
	if (adapter->id >= MGMTD_BE_CLIENT_ID_MAX) {
		_log_err("Unable to resolve adapter '%s' to a valid ID. Disconnecting!",
			 adapter->name);
		/* this will/should delete old */
		msg_conn_disconnect(adapter->conn, false);
		goto done;
	}
	mgmt_be_adapters_by_id[adapter->id] = adapter;
	mgmt_be_adapter_cleanup_old_conn(adapter);

	/* schedule INIT sequence now that it is registered */
	mgmt_be_adapter_sched_init_event(adapter);

	for (uint j = 0; j < msg->nconfig; j++)
		mgmt_register_client_xpath(adapter->id, s[i++], MGMT_BE_XPATH_SUBSCR_TYPE_CFG);

	for (uint j = 0; j < msg->noper; j++)
		mgmt_register_client_xpath(adapter->id, s[i++], MGMT_BE_XPATH_SUBSCR_TYPE_OPER);

	for (uint j = 0; j < msg->nnotify; j++)
		mgmt_register_client_xpath(adapter->id, s[i++], MGMT_BE_XPATH_SUBSCR_TYPE_NOTIF);

	for (uint j = 0; j < msg->nrpc; j++)
		mgmt_register_client_xpath(adapter->id, s[i++], MGMT_BE_XPATH_SUBSCR_TYPE_RPC);
done:
	darr_free_free(s);
}

/*
 * Handle a native encoded message
 */
static void be_adapter_handle_native_msg(struct mgmt_be_client_adapter *adapter,
					 struct mgmt_msg_header *msg,
					 size_t msg_len)
{
	struct mgmt_msg_subscribe *subr_msg;
	struct mgmt_msg_notify_data *notify_msg;
	struct mgmt_msg_txn_reply *txn_msg;
	struct mgmt_msg_error *error_msg;

	/* get the transaction */

	switch (msg->code) {
	case MGMT_MSG_CODE_SUBSCRIBE:
		subr_msg = (typeof(subr_msg))msg;
		_dbg("Got SUBSCRIBE from '%s' to register xpaths config: %u oper: %u notif: %u rpc: %u",
		     adapter->name, subr_msg->nconfig, subr_msg->noper, subr_msg->nnotify,
		     subr_msg->nrpc);

		be_adapter_handle_subscribe(subr_msg, msg_len, adapter);
		break;

	case MGMT_MSG_CODE_TXN_REPLY:
		txn_msg = (typeof(txn_msg))msg;
		_dbg("Got TXN_REPLY from '%s' txn-id %Lu successfully '%s'", adapter->name,
		     txn_msg->refer_id, txn_msg->created ? "Created" : "Deleted");
		/*
		 * Forward the TXN_REPLY to txn module.
		 */
		mgmt_txn_notify_be_txn_reply(txn_msg->refer_id, txn_msg->created, true, adapter);
		break;
	case MGMT_MSG_CODE_CFG_REPLY:
		_dbg("Got successful CFG_REPLY from '%s' txn-id %Lu", adapter->name, msg->refer_id);
		/*
		 * Forward the CGFData-create reply to txn module.
		 */
		mgmt_txn_notify_be_cfg_reply(msg->refer_id, true, NULL, adapter);
		break;
	case MGMT_MSG_CODE_CFG_APPLY_REPLY:
		_dbg("Got successful CFG_APPLY_REPLY from '%s' txn-id %Lu", adapter->name,
		     msg->refer_id);
		/*
		 * Forward the CGFData-apply reply to txn module.
		 */
		mgmt_txn_notify_be_cfg_apply_reply(msg->refer_id, true, NULL, adapter);
		break;

	case MGMT_MSG_CODE_ERROR:
		error_msg = (typeof(error_msg))msg;
		_dbg("Got ERROR from '%s' txn-id %Lu", adapter->name, msg->refer_id);

		/* Forward the reply to the txn module */
		mgmt_txn_notify_error(adapter, msg->refer_id, msg->req_id,
				      error_msg->error, error_msg->errstr);
		/* We may have lost our connection and adapter at this point */
		break;
	case MGMT_MSG_CODE_TREE_DATA:
		/* tree data from a backend client */
		_dbg("Got TREE_DATA from '%s' txn-id %" PRIu64, adapter->name, msg->refer_id);

		/* Forward the reply to the txn module */
		mgmt_txn_notify_tree_data_reply(adapter, (struct mgmt_msg_tree_data *)msg, msg_len);
		break;
	case MGMT_MSG_CODE_RPC_REPLY:
		/* RPC reply from a backend client */
		_dbg("Got RPC_REPLY from '%s' txn-id %" PRIu64, adapter->name, msg->refer_id);

		/* Forward the reply to the txn module */
		mgmt_txn_notify_rpc_reply(adapter, (struct mgmt_msg_rpc_reply *)msg, msg_len);
		break;
	case MGMT_MSG_CODE_NOTIFY:
		/*
		 * Handle notify message from a back-end client
		 */
		notify_msg = (typeof(notify_msg))msg;
		_dbg("Got NOTIFY from '%s'", adapter->name);
		mgmt_be_adapter_send_notify(notify_msg, msg_len, adapter);
		mgmt_fe_adapter_send_notify(notify_msg, msg_len);
		break;
	default:
		_log_err("unknown native message txn-id %" PRIu64 " req-id %" PRIu64
			 " code %u from BE client for adapter %s",
			 msg->refer_id, msg->req_id, msg->code, adapter->name);
		break;
	}
}


static void mgmt_be_adapter_process_msg(uint8_t version, uint8_t *data,
					size_t len, struct msg_conn *conn)
{
	struct mgmt_be_client_adapter *adapter = conn->user;

	if (version == MGMT_MSG_VERSION_NATIVE) {
		struct mgmt_msg_header *msg = (typeof(msg))data;

		if (len >= sizeof(*msg))
			be_adapter_handle_native_msg(adapter, msg, len);
		else
			_log_err("native message to adapter %s too short %zu", adapter->name, len);
		return;
	}

	_log_err("Protobuf not supported for backend messages (adapter: %s)", adapter->name);
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
static void mgmt_be_adapter_conn_init(struct event *event)
{
	struct mgmt_be_client_adapter *adapter;

	adapter = (struct mgmt_be_client_adapter *)EVENT_ARG(event);
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
		event_cancel(&a->conn_init_ev);
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

	_dbg("Added new MGMTD Backend adapter '%s'", adapter->name);

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
	bool wild_root;

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

	_dbg("XPATH: '%s'", xpath);

	/* wild_root will select all clients that advertise op-state */
	wild_root = !strcmp(xpath, "/") || !strcmp(xpath, "/*");
	darr_foreach_p (maps, map)
		if (wild_root || mgmt_be_xpath_prefix(map->xpath_prefix, xpath))
			clients |= map->clients;

	if (DEBUG_MODE_CHECK(&mgmt_debug_be, DEBUG_MODE_ALL)) {
		FOREACH_BE_CLIENT_BITS (id, clients)
			_dbg("Cient: %s: subscribed", mgmt_be_client_id2name(id));
	}
	return clients;
}

bool mgmt_is_mgmtd_interested(const char *xpath)
{
	const char *const *match = mgmtd_config_xpaths;
	const char *const *ematch = match + array_size(mgmtd_config_xpaths);

	for (; match < ematch; match++) {
		if (mgmt_be_xpath_prefix(*match, xpath)) {
			_dbg("mgmtd: subscribed to %s", xpath);
			return true;
		}
	}
	return false;
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

	_dbg("Checking client: %s for xpath: '%s'", mgmt_be_client_id2name(id), xpath);

	clients = mgmt_be_interested_clients(xpath, type);
	if (IS_IDBIT_SET(clients, id)) {
		_dbg("client: %s: interested", mgmt_be_client_id2name(id));
		return true;
	}

	_dbg("client: %s: not interested", mgmt_be_client_id2name(id));
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
