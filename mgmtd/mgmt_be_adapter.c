// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Backend Client Connection Adapter
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 * Copyright (c) 2023-2025, LabN Consulting, L.L.C.
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
#define _log_warn(fmt, ...) zlog_warn("BE-ADAPTER: %s: WARNING: " fmt, __func__, ##__VA_ARGS__)
#define _log_err(fmt, ...) zlog_err("BE-ADAPTER: %s: ERROR: " fmt, __func__, ##__VA_ARGS__)

/* ----- */
/* Types */
/* ----- */

/*
 * Mapping of YANG XPath prefixes to their corresponding backend clients.
 */
struct mgmt_be_xpath_map {
	char *xpath_prefix;
	uint64_t clients;
};

/* ---------- */
/* Prototypes */
/* ---------- */

/* Forward declarations */
static void be_adapter_sched_init_event(struct mgmt_be_client_adapter *adapter);

static void be_adapter_delete(struct mgmt_be_client_adapter *adapter);

// clang-format off
#ifdef _FRR_ATTRIBUTE_PRINTFRR
#pragma FRR printfrr_ext "%pMBI" (mgmt_be_client_id_t *)
#pragma FRR printfrr_ext "%pMBM" (uint64_t *)
#endif
// clang-format on

/* --------- */
/* Constants */
/* --------- */

/*
 * Client IDs
 */

/* ---------------- */
/* Global Variables */
/* ---------------- */

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

LIST_HEAD(be_adapter_list_head, mgmt_be_client_adapter) be_adapters;

typedef uint mgmt_be_client_id_t;
static char **mgmt_be_client_names;
struct mgmt_be_client_adapter **mgmt_be_adapters_by_id;

/*
 * Mgmtd has it's own special "interested-in" xpath maps since it's not actually
 * a backend client of itself; it's own tree is modified directly when
 * processing changes from the front end clients
 */
static const char *const mgmtd_config_xpaths[] = {
	"/frr-logging:logging",
};


/* ---------------- */
/* Lookup Functions */
/* ---------------- */

static struct mgmt_be_client_adapter *mgmt_be_find_adapter_by_fd(int conn_fd)
{
	struct mgmt_be_client_adapter *adapter;

	LIST_FOREACH (adapter, &be_adapters, link)
		if (adapter->conn->fd == conn_fd)
			return adapter;
	return NULL;
}

struct mgmt_be_client_adapter *mgmt_be_get_adapter_by_id(mgmt_be_client_id_t id)
{
	if (id < darr_len(mgmt_be_adapters_by_id))
		return mgmt_be_adapters_by_id[id];
	return NULL;
}

printfrr_ext_autoreg_p("MBI", printfrr_be_id);
static ssize_t printfrr_be_id(struct fbuf *buf, struct printfrr_eargs *ea, const void *ptr)
{
	mgmt_be_client_id_t id = *(mgmt_be_client_id_t *)ptr;

	if (id < darr_len(mgmt_be_client_names))
		return bputs(buf, mgmt_be_client_names[id]);
	return bprintfrr(buf, "unknown-client-id-%d", id);
}

printfrr_ext_autoreg_p("MBM", printfrr_be_mask);
static ssize_t printfrr_be_mask(struct fbuf *buf, struct printfrr_eargs *ea, const void *ptr)
{
	uint64_t bits = *(const uint64_t *)ptr;
	mgmt_be_client_id_t id;
	size_t total_len = 0;
	bool first = true;

	for (id = 0; id < 64; id++) {
		if (IS_IDBIT_UNSET(bits, id))
			continue;
		if (!first)
			total_len += bputch(buf, '|');
		if (id >= darr_len(mgmt_be_client_names))
			total_len += bprintfrr(buf, "unknown-client-id-%d", id);
		else
			total_len += bputs(buf, mgmt_be_client_names[id]);
		first = false;
	}
	return total_len;
}

/* ======================= */
/* XPath Mapping Functions */
/* ======================= */

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

/*
 * Get the mask of clients interested in an xpath.
 */
uint64_t mgmt_be_interested_clients(const char *xpath, enum mgmt_be_xpath_subscr_type type)
{
	struct mgmt_be_xpath_map *maps = NULL, *map;
	uint64_t clients = 0;
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

	/* wild_root will select all clients that advertise op-state */
	wild_root = !strcmp(xpath, "/") || !strcmp(xpath, "/*");
	darr_foreach_p (maps, map)
		if (wild_root || mgmt_be_xpath_prefix(map->xpath_prefix, xpath))
			clients |= map->clients;

	_dbg("xpath: '%s' subscribed clients: %pMBM", xpath, &clients);

	return clients;
}

/*
 * Test for interest by mgmtd in xpath.
 *
 * Mgmtd handles it's own config directly vs as a backend client of
 * itself. This function supports that.
 */
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


/*
 * This function is inefficient. For each xpath it walks the global map list.
 * We should keep a separate per-client map and use that here.
 *
 * NOTE: Fix this when removing the global constant maps used for bootstrapping.
 */
static bool be_is_client_interested(const char *xpath, mgmt_be_client_id_t id,
				    enum mgmt_be_xpath_subscr_type type)
{
	uint64_t clients;

	clients = mgmt_be_interested_clients(xpath, type);
	if (IS_IDBIT_SET(clients, id)) {
		_dbg("client: %pMBI for xpath: '%s': interested", &id, xpath);
		return true;
	}
	_dbg("client: %pMBI for xpath: '%s': not interested", &id, xpath);
	return false;
}

/*
 * Get full config changes for adapter.
 *
 * Walk the entire running config building a set of create-changes to send to
 * the adapter and return a set of config changes.
 */
struct nb_config_cbs mgmt_be_adapter_get_config(struct mgmt_be_client_adapter *adapter)
{
	struct nb_config_cbs changes = { 0 };
	const struct lyd_node *root, *dnode;
	uint32_t seq = 0;
	char *xpath;

	LY_LIST_FOR (running_config->dnode, root) {
		LYD_TREE_DFS_BEGIN (root, dnode) {
			if (lysc_is_key(dnode->schema))
				goto walk_cont;

			xpath = lyd_path(dnode, LYD_PATH_STD, NULL, 0);
			if (be_is_client_interested(xpath, adapter->id,
						    MGMT_BE_XPATH_SUBSCR_TYPE_CFG))
				nb_config_diff_add_change(&changes, NB_CB_CREATE, &seq, dnode);
			else
				LYD_TREE_DFS_continue = 1; /* skip any subtree */
			free(xpath);
walk_cont:
			LYD_TREE_DFS_END(root, dnode);
		}
	}
	return changes;
}

static void be_adapter_register_client_xpath(mgmt_be_client_id_t id, const char *xpath,
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
			SET_IDBIT(map->clients, id);
			return;
		}
	}
	/* we didn't find a matching entry */
	map = darr_append(*maps);
	map->xpath_prefix = darr_strdup(xpath);
	map->clients = (1ul << id);
}

static void be_adapter_xpath_maps_init(void)
{
	be_adapter_register_client_xpath(MGMTD_BE_CLIENT_ID_MGMTD, "/frr-backend:clients",
					 MGMT_BE_XPATH_SUBSCR_TYPE_OPER);
	be_adapter_register_client_xpath(MGMTD_BE_CLIENT_ID_MGMTD, "/frr-logging",
					 MGMT_BE_XPATH_SUBSCR_TYPE_RPC);
}

/*
 * Cleanup the xpath maps.
 */
static void be_adapter_xpath_maps_cleanup(void)
{
	struct mgmt_be_xpath_map *map;

	darr_foreach_p (be_cfg_xpath_map, map)
		darr_free(map->xpath_prefix);
	darr_free(be_cfg_xpath_map);

	darr_foreach_p (be_oper_xpath_map, map)
		darr_free(map->xpath_prefix);
	darr_free(be_oper_xpath_map);

	darr_foreach_p (be_notif_xpath_map, map)
		darr_free(map->xpath_prefix);
	darr_free(be_notif_xpath_map);

	darr_foreach_p (be_rpc_xpath_map, map)
		darr_free(map->xpath_prefix);
	darr_free(be_rpc_xpath_map);
}


/* ============================== */
/* Backend Message (API) Handling */
/* ============================== */

/*
 * The TXN module is the primary producer/consumer of messages to/from backend
 * clients so that is where you will find most of the backend message handling
 * functions.
 */

int mgmt_be_adapter_send(struct mgmt_be_client_adapter *adapter, void *_msg)
{
	struct mgmt_msg_header *msg = (struct mgmt_msg_header *)_msg;
	uint64_t txn_id = msg->refer_id;
	int ret;

	_dbg("Sending %s to '%s' txn-id: %Lu", mgmt_msg_code_name(msg->code), adapter->name,
	     txn_id);

	ret = mgmt_msg_native_send_msg(adapter->conn, msg, false);
	if (ret)
		_log_err("Failed sending %s to '%s' txn-id: %Lu", mgmt_msg_code_name(msg->code),
			 adapter->name, txn_id);
	return ret;
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
	mgmt_be_client_id_t id;
	struct mgmt_be_client_adapter *old;
	const char **s = NULL;
	const char *new_name;
	uint i = 0;

	_dbg("SUBSCRIBE '%s' to register xpaths config: %u oper: %u notif: %u rpc: %u",
	     adapter->name, msg->nconfig, msg->noper, msg->nnotify, msg->nrpc);

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

	new_name = s[i++];
	_dbg("\"%s\" now known as \"%s\"", adapter->name, new_name);
	darr_in_strdup(adapter->name, new_name);

	/* Get or allocate the ID based on the name */
	for (id = 0; id < darr_len(mgmt_be_client_names); id++)
		if (!strcmp(mgmt_be_client_names[id], adapter->name))
			break;
	/* Only allow new ID if we have space in uin64_t bitmask i.e., 64 */
	if (id >= MGMTD_BE_CLIENT_ID_MAX) {
		_log_err("No available client IDs for '%s', disconnecting.", adapter->name);
		be_adapter_delete(adapter);
		goto done;
	}
	/* Allocate new ID */
	if (id == darr_len(mgmt_be_client_names))
		*darr_append(mgmt_be_client_names) = darr_strdup(adapter->name);

	adapter->id = id;
	if (id >= darr_len(mgmt_be_adapters_by_id))
		darr_ensure_i(mgmt_be_adapters_by_id, id);
	else if (mgmt_be_adapters_by_id[id]) {
		old = mgmt_be_adapters_by_id[id];
		_dbg("client: %s using fd: %d reconnected with fd: %d", old->name, old->conn->fd,
		     adapter->conn->fd);
		be_adapter_delete(old);
	}
	mgmt_be_adapters_by_id[adapter->id] = adapter;

	/* schedule INIT sequence now that it is registered */
	be_adapter_sched_init_event(adapter);

	for (uint j = 0; j < msg->nconfig; j++)
		be_adapter_register_client_xpath(adapter->id, s[i++],
						 MGMT_BE_XPATH_SUBSCR_TYPE_CFG);

	for (uint j = 0; j < msg->noper; j++)
		be_adapter_register_client_xpath(adapter->id, s[i++],
						 MGMT_BE_XPATH_SUBSCR_TYPE_OPER);

	for (uint j = 0; j < msg->nnotify; j++)
		be_adapter_register_client_xpath(adapter->id, s[i++],
						 MGMT_BE_XPATH_SUBSCR_TYPE_NOTIF);

	for (uint j = 0; j < msg->nrpc; j++)
		be_adapter_register_client_xpath(adapter->id, s[i++],
						 MGMT_BE_XPATH_SUBSCR_TYPE_RPC);

	zlog_notice("Backend daemon: %s registers with mgmtd (client-id: %u)", adapter->name,
		    adapter->id);
done:
	darr_free_free(s);
}


static void be_adapter_process_msg(uint8_t version, uint8_t *data, size_t msg_len,
				   struct msg_conn *conn)
{
	struct mgmt_be_client_adapter *adapter = conn->user;
	struct mgmt_msg_header *msg = (typeof(msg))data;
	struct mgmt_msg_notify_data *notify_msg;
	struct mgmt_msg_error *error_msg;

	if (version != MGMT_MSG_VERSION_NATIVE) {
		_log_err("Protobuf not supported for backend messages (adapter: %s)",
			 adapter->name);
		return;
	}
	if (msg_len < sizeof(*msg)) {
		_log_err("native message to adapter %s too short %zu", adapter->name, msg_len);
		return;
	}

	/*
	 * Most messages are sent to the TXN module for processing.
	 *
	 * NOTE: Handling the config messages may lead to disconnect and
	 * deletion of the adapater. So don't do with it after calling the txn
	 * function.
	 */

	_dbg("Got %s from '%s' txn-id %Lu", mgmt_msg_code_name(msg->code), adapter->name,
	     msg->refer_id);

	switch (msg->code) {
	case MGMT_MSG_CODE_SUBSCRIBE:
		be_adapter_handle_subscribe((struct mgmt_msg_subscribe *)msg, msg_len, adapter);
		return;
	case MGMT_MSG_CODE_TXN_REPLY:
		assert(0);
		return;
	case MGMT_MSG_CODE_CFG_REPLY:
		mgmt_txn_handle_cfg_reply(msg->refer_id, adapter);
		return;
	case MGMT_MSG_CODE_CFG_APPLY_REPLY:
		mgmt_txn_handle_cfg_apply_reply(msg->refer_id, adapter);
		return;
	case MGMT_MSG_CODE_ERROR:
		error_msg = (typeof(error_msg))msg;
		mgmt_txn_handle_error_reply(adapter, msg->refer_id, msg->req_id, error_msg->error,
					    error_msg->errstr);
		return;
	case MGMT_MSG_CODE_TREE_DATA:
		mgmt_txn_handle_tree_data_reply(adapter, (struct mgmt_msg_tree_data *)msg, msg_len);
		return;
	case MGMT_MSG_CODE_RPC_REPLY:
		mgmt_txn_handle_rpc_reply(adapter, (struct mgmt_msg_rpc_reply *)msg, msg_len);
		return;
	case MGMT_MSG_CODE_NOTIFY:
		/*
		 * Handle notify message from a back-end client no TXN for this.
		 */
		notify_msg = (typeof(notify_msg))msg;
		mgmt_be_adapter_send_notify(notify_msg, msg_len, adapter);
		mgmt_fe_adapter_send_notify(notify_msg, msg_len);
		return;
	default:
		_log_err("unknown native message txn-id %" PRIu64 " req-id %" PRIu64
			 " code %u from BE client for adapter %s",
			 msg->refer_id, msg->req_id, msg->code, adapter->name);
		return;
	}
}

/* =================== */
/* Backend VTY support */
/* =================== */

void mgmt_be_adapter_status_write(struct vty *vty)
{
	struct mgmt_be_client_adapter *adapter;
	uint count = 0;

	vty_out(vty, "MGMTD Backend Adapters\n");

	LIST_FOREACH (adapter, &be_adapters, link) {
		vty_out(vty, "  Client: \t\t\t%s\n", adapter->name);
		vty_out(vty, "    Conn-FD: \t\t\t%d\n", adapter->conn->fd);
		vty_out(vty, "    Client-Id: \t\t\t%d\n", adapter->id);
		vty_out(vty, "    Msg-Recvd: \t\t\t%Lu\n", adapter->conn->mstate.nrxm);
		vty_out(vty, "    Bytes-Recvd: \t\t%Lu\n", adapter->conn->mstate.nrxb);
		vty_out(vty, "    Msg-Sent: \t\t\t%Lu\n", adapter->conn->mstate.ntxm);
		vty_out(vty, "    Bytes-Sent: \t\t%Lu\n", adapter->conn->mstate.ntxb);
		count++;
	}
	vty_out(vty, "  Total: %u\n", count);
}

static void _show_xpath_map(struct vty *vty, struct mgmt_be_xpath_map *map)
{
	mgmt_be_client_id_t id;
	const char *astr;

	vty_out(vty, " - xpath: '%s'\n", map->xpath_prefix);
	FOREACH_BE_CLIENT_BITS (id, map->clients) {
		astr = mgmt_be_get_adapter_by_id(id) ? "active" : "inactive";
		vty_out(vty, "   -- %s-client: '%pMBI'\n", astr, &id);
	}
}

void mgmt_be_xpath_register_write(struct vty *vty)
{
	struct mgmt_be_xpath_map *map;

	vty_out(vty, "MGMTD Backend CFG XPath Registry: Count: %u\n", darr_len(be_oper_xpath_map));
	darr_foreach_p (be_cfg_xpath_map, map)
		_show_xpath_map(vty, map);

	vty_out(vty, "\nMGMTD Backend OPER XPath Registry: Count: %u\n",
		darr_len(be_oper_xpath_map));
	darr_foreach_p (be_oper_xpath_map, map)
		_show_xpath_map(vty, map);

	vty_out(vty, "\nMGMTD Backend NOTIFY XPath Registry: Count: %u\n",
		darr_len(be_notif_xpath_map));
	darr_foreach_p (be_notif_xpath_map, map)
		_show_xpath_map(vty, map);

	vty_out(vty, "\nMGMTD Backend RPC XPath Registry: Count: %u\n", darr_len(be_rpc_xpath_map));
	darr_foreach_p (be_rpc_xpath_map, map)
		_show_xpath_map(vty, map);
}

/*
 * Should replace this with proper YANG module
 */
void mgmt_be_adapter_show_xpath_registries(struct vty *vty, const char *xpath)
{
	mgmt_be_client_id_t id;
	struct mgmt_be_client_adapter *adapter;
	uint64_t cclients, nclients, oclients, rclients, combined;

	cclients = mgmt_be_interested_clients(xpath, MGMT_BE_XPATH_SUBSCR_TYPE_CFG);
	oclients = mgmt_be_interested_clients(xpath, MGMT_BE_XPATH_SUBSCR_TYPE_OPER);
	nclients = mgmt_be_interested_clients(xpath, MGMT_BE_XPATH_SUBSCR_TYPE_NOTIF);
	rclients = mgmt_be_interested_clients(xpath, MGMT_BE_XPATH_SUBSCR_TYPE_RPC);
	combined = cclients | nclients | oclients | rclients;

	vty_out(vty, "XPath: '%s'\n", xpath);
	FOREACH_BE_CLIENT_BITS (id, combined) {
		vty_out(vty, "  -- Client: %pMBI\tconfig:%d notify:%d oper:%d rpc:%d\n", &id,
			IS_IDBIT_SET(cclients, id), IS_IDBIT_SET(nclients, id),
			IS_IDBIT_SET(oclients, id), IS_IDBIT_SET(rclients, id));
		adapter = mgmt_be_get_adapter_by_id(id);
		if (adapter)
			vty_out(vty, "    -- Adapter: %p\n", adapter);
	}
}

/* ========================== */
/* Backend Adapter Management */
/* ========================== */

void mgmt_be_adapter_toggle_client_debug(bool set)
{
	struct mgmt_be_client_adapter *adapter;

	LIST_FOREACH (adapter, &be_adapters, link)
		adapter->conn->debug = set;
}

/*
 * Delete a BE client adapter
 */
static void be_adapter_delete(struct mgmt_be_client_adapter *adapter)
{
	_dbg("deleting client adapter '%s'", adapter->name);

	/*
	 * Notify about disconnect for appropriate cleanup
	 */
	mgmt_txn_handle_be_adapter_connect(adapter, false);
	if (adapter->id < darr_len(mgmt_be_adapters_by_id))
		mgmt_be_adapters_by_id[adapter->id] = NULL;

	LIST_REMOVE(adapter, link);
	event_cancel(&adapter->conn_init_ev);
	msg_server_conn_delete(adapter->conn);
	darr_free(adapter->name);
	XFREE(MTYPE_MGMTD_BE_ADPATER, adapter);
}

static int mgmt_be_adapter_notify_disconnect(struct msg_conn *conn)
{
	struct mgmt_be_client_adapter *adapter = conn->user;

	_dbg("notify disconnect for client adapter '%s'", adapter->name);

	be_adapter_delete(adapter);

	return 0;
}

/*
 * Initialize a BE client over a new connection
 */
static void be_adapter_conn_init(struct event *event)
{
	struct mgmt_be_client_adapter *adapter;
	mgmt_be_client_id_t id;

	adapter = (struct mgmt_be_client_adapter *)EVENT_ARG(event);
	assert(adapter && adapter->conn->fd >= 0);
	id = adapter->id;

	/*
	 * Notify TXN module to create a CONFIG transaction and
	 * download the CONFIGs identified for this new client.
	 * If the TXN module fails to initiate the CONFIG transaction
	 * retry a bit later. It only fails if there's an existing config
	 * transaction in progress.
	 */
	if (mgmt_txn_handle_be_adapter_connect(adapter, true) != 0) {
		/* Deal with a disconnect happening */
		if (id >= darr_len(mgmt_be_adapters_by_id) || !mgmt_be_adapters_by_id[id])
			return;
		_log_warn("Couldn't send initial config to adapter: %s will retry", adapter->name);
		be_adapter_sched_init_event(adapter);
	}
}

/*
 * Schedule the initialization of the BE client connection.
 */
static void be_adapter_sched_init_event(struct mgmt_be_client_adapter *adapter)
{
	event_add_timer_msec(mgmt_loop, be_adapter_conn_init, adapter,
			     MGMTD_BE_CONN_INIT_DELAY_MSEC, &adapter->conn_init_ev);
}

/*
 * The server accepted a new connection
 */
static struct msg_conn *be_adapter_create(int conn_fd, union sockunion *from)
{
	struct mgmt_be_client_adapter *adapter = NULL;

	assert(!mgmt_be_find_adapter_by_fd(conn_fd));

	adapter = XCALLOC(MTYPE_MGMTD_BE_ADPATER, sizeof(struct mgmt_be_client_adapter));
	adapter->id = MGMTD_BE_CLIENT_ID_MAX;
	adapter->name = darr_sprintf("init-client-fd-%d", conn_fd);

	LIST_INSERT_HEAD(&be_adapters, adapter, link);

	adapter->conn = msg_server_conn_create(mgmt_loop, conn_fd,
					       mgmt_be_adapter_notify_disconnect,
					       be_adapter_process_msg, MGMTD_BE_MAX_NUM_MSG_PROC,
					       MGMTD_BE_MAX_NUM_MSG_WRITE, MGMTD_BE_MAX_MSG_LEN,
					       adapter, "BE-adapter");

	adapter->conn->debug = DEBUG_MODE_CHECK(&mgmt_debug_be, DEBUG_MODE_ALL);

	_dbg("Added new MGMTD Backend adapter '%s'", adapter->name);

	return adapter->conn;
}

/*
 * Initialize the BE adapter module
 */
void mgmt_be_adapter_init(struct event_loop *tm)
{
	char server_path[MAXPATHLEN];

	assert(!mgmt_loop);
	mgmt_loop = tm;

	*darr_append(mgmt_be_client_names) = darr_strdup("mgmtd"); /* reserve ID 0 */
	be_adapter_xpath_maps_init();

	snprintf(server_path, sizeof(server_path), MGMTD_BE_SOCK_NAME);

	if (msg_server_init(&mgmt_be_server, server_path, tm, be_adapter_create, "backend",
			    &mgmt_debug_be)) {
		zlog_err("cannot initialize backend server");
		exit(1);
	}
}

/*
 * Destroy the BE adapter module
 */
void mgmt_be_adapter_destroy(void)
{
	struct mgmt_be_client_adapter *adapter, *next;

	msg_server_cleanup(&mgmt_be_server);
	LIST_FOREACH_SAFE (adapter, &be_adapters, link, next)
		be_adapter_delete(adapter);
	be_adapter_xpath_maps_cleanup();
	darr_free_free(mgmt_be_client_names);
	darr_free(mgmt_be_adapters_by_id);
}
