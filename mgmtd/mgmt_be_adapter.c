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
#include "sockopt.h"
#include "network.h"
#include "libfrr.h"
#include "mgmt_msg.h"
#include "mgmt_pb.h"
#include "mgmt_util.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_memory.h"
#include "mgmt_be_client.h"
#include "mgmtd/mgmt_be_adapter.h"
#include "mgmtd/mgmt_txn.h"

#define MGMTD_BE_ADAPTER_DBG(fmt, ...)                                         \
	DEBUGD(&mgmt_debug_be, "BE-ADAPTER: %s: " fmt, __func__, ##__VA_ARGS__)
#define MGMTD_BE_ADAPTER_ERR(fmt, ...)                                         \
	zlog_err("BE-ADAPTER: %s: ERROR: " fmt, __func__, ##__VA_ARGS__)

#define FOREACH_ADAPTER_IN_LIST(adapter)                                       \
	frr_each_safe (mgmt_be_adapters, &mgmt_be_adapters, (adapter))

/*
 * Mapping of YANG XPath regular expressions to
 * their corresponding backend clients.
 */
struct mgmt_be_xpath_map {
	char *xpath_regexp;
	uint subscr_info[MGMTD_BE_CLIENT_ID_MAX];
};

struct mgmt_be_client_xpath {
	const char *xpath;
	uint subscribed;
};

struct mgmt_be_client_xpath_map {
	struct mgmt_be_client_xpath *xpaths;
	uint nxpaths;
};

struct mgmt_be_get_adapter_config_params {
	struct mgmt_be_client_adapter *adapter;
	struct nb_config_cbs *cfg_chgs;
	uint32_t seq;
};

/*
 * Each client gets their own map, but also union all the strings into the
 * above map as well.
 */
#if HAVE_STATICD
static struct mgmt_be_client_xpath staticd_xpaths[] = {
	{
		.xpath = "/frr-vrf:lib/*",
		.subscribed = MGMT_SUBSCR_VALIDATE_CFG | MGMT_SUBSCR_NOTIFY_CFG
			      | MGMT_SUBSCR_OPER_OWN,
	},
	{
		.xpath = "/frr-interface:lib/*",
		.subscribed = MGMT_SUBSCR_VALIDATE_CFG | MGMT_SUBSCR_NOTIFY_CFG
			      | MGMT_SUBSCR_OPER_OWN,
	},
	{
		.xpath =
			"/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-staticd:staticd/*",
		.subscribed = MGMT_SUBSCR_VALIDATE_CFG | MGMT_SUBSCR_NOTIFY_CFG
			      | MGMT_SUBSCR_OPER_OWN,
	},
};
#endif

static struct mgmt_be_client_xpath_map
	mgmt_client_xpaths[MGMTD_BE_CLIENT_ID_MAX] = {
#ifdef HAVE_STATICD
		[MGMTD_BE_CLIENT_ID_STATICD] = {staticd_xpaths,
						array_size(staticd_xpaths)},
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
static struct mgmt_be_xpath_map *mgmt_xpath_map;

static struct event_loop *mgmt_loop;
static struct msg_server mgmt_be_server = {.fd = -1};

static struct mgmt_be_adapters_head mgmt_be_adapters;

static struct mgmt_be_client_adapter
	*mgmt_be_adapters_by_id[MGMTD_BE_CLIENT_ID_MAX];

/* Forward declarations */
static void
mgmt_be_adapter_sched_init_event(struct mgmt_be_client_adapter *adapter);

static uint mgmt_be_get_subscr_for_xpath_and_client(
	const char *xpath, enum mgmt_be_client_id client_id, uint subscr_mask);

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
				       const char *xpath, uint subscribed)
{
	struct mgmt_be_xpath_map *map;

	darr_foreach_p (mgmt_xpath_map, map)
		if (!strcmp(xpath, map->xpath_regexp)) {
			map->subscr_info[id] = subscribed;
			return;
		}
	/* we didn't find a matching entry */
	map = darr_append(mgmt_xpath_map);
	map->xpath_regexp = XSTRDUP(MTYPE_MGMTD_XPATH, xpath);
	map->subscr_info[id] = subscribed;
}

/*
 * Load the initial mapping from static init map
 */
static void mgmt_be_xpath_map_init(void)
{
	struct mgmt_be_client_xpath *init, *end;
	enum mgmt_be_client_id id;

	MGMTD_BE_ADAPTER_DBG("Init XPath Maps");

	FOREACH_MGMTD_BE_CLIENT_ID (id) {
		init = mgmt_client_xpaths[id].xpaths;
		end = init + mgmt_client_xpaths[id].nxpaths;
		for (; init < end; init++) {
			MGMTD_BE_ADAPTER_DBG(" - XPATH: '%s'", init->xpath);
			mgmt_register_client_xpath(id, init->xpath,
						   init->subscribed);
		}
	}

	MGMTD_BE_ADAPTER_DBG("Total XPath Maps: %u", darr_len(mgmt_xpath_map));
}

static void mgmt_be_xpath_map_cleanup(void)
{
	struct mgmt_be_xpath_map *map;

	darr_foreach_p (mgmt_xpath_map, map)
		XFREE(MTYPE_MGMTD_XPATH, map->xpath_regexp);
	darr_free(mgmt_xpath_map);
}

static void mgmt_be_adapter_delete(struct mgmt_be_client_adapter *adapter)
{
	MGMTD_BE_ADAPTER_DBG("deleting client adapter '%s'", adapter->name);

	/*
	 * Notify about disconnect for appropriate cleanup
	 */
	mgmt_txn_notify_be_adapter_conn(adapter, false);
	if (adapter->id < MGMTD_BE_CLIENT_ID_MAX) {
		mgmt_be_adapters_by_id[adapter->id] = NULL;
		adapter->id = MGMTD_BE_CLIENT_ID_MAX;
	}

	assert(adapter->refcount == 1);
	MGMTD_BE_ADAPTER_UNLOCK(&adapter);
}

static int mgmt_be_adapter_notify_disconnect(struct msg_conn *conn)
{
	struct mgmt_be_client_adapter *adapter = conn->user;

	MGMTD_BE_ADAPTER_DBG("notify disconnect for client adapter '%s'",
			     adapter->name);

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
			MGMTD_BE_ADAPTER_DBG(
				"Client '%s' (FD:%d) seems to have reconnected. Removing old connection (FD:%d)!",
				adapter->name, adapter->conn->fd,
				old->conn->fd);
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

	MGMTD_FE_CLIENT_DBG("Sending SUBSCR_REPLY client: %s sucess: %u",
			    adapter->name, success);

	return mgmt_be_adapter_send_msg(adapter, &be_msg);
}

static int
mgmt_be_adapter_handle_msg(struct mgmt_be_client_adapter *adapter,
			      Mgmtd__BeMessage *be_msg)
{
	/*
	 * protobuf-c adds a max size enum with an internal, and changing by
	 * version, name; cast to an int to avoid unhandled enum warnings
	 */
	switch ((int)be_msg->message_case) {
	case MGMTD__BE_MESSAGE__MESSAGE_SUBSCR_REQ:
		MGMTD_BE_ADAPTER_DBG(
			"Got SUBSCR_REQ from '%s' to %sregister %zu xpaths",
			be_msg->subscr_req->client_name,
			!be_msg->subscr_req->subscribe_xpaths &&
					be_msg->subscr_req->n_xpath_reg
				? "de"
				: "",
			be_msg->subscr_req->n_xpath_reg);

		if (strlen(be_msg->subscr_req->client_name)) {
			strlcpy(adapter->name, be_msg->subscr_req->client_name,
				sizeof(adapter->name));
			adapter->id = mgmt_be_client_name2id(adapter->name);
			if (adapter->id >= MGMTD_BE_CLIENT_ID_MAX) {
				MGMTD_BE_ADAPTER_ERR(
					"Unable to resolve adapter '%s' to a valid ID. Disconnecting!",
					adapter->name);
				/* this will/should delete old */
				msg_conn_disconnect(adapter->conn, false);
				zlog_err("XXX different from original code");
				break;
			}
			mgmt_be_adapters_by_id[adapter->id] = adapter;
			mgmt_be_adapter_cleanup_old_conn(adapter);

			/* schedule INIT sequence now that it is registered */
			mgmt_be_adapter_sched_init_event(adapter);
		}

		if (be_msg->subscr_req->n_xpath_reg)
			/* we aren't handling dynamic xpaths yet */
			mgmt_be_send_subscr_reply(adapter, false);
		else
			mgmt_be_send_subscr_reply(adapter, true);
		break;
	case MGMTD__BE_MESSAGE__MESSAGE_TXN_REPLY:
		MGMTD_BE_ADAPTER_DBG(
			"Got %s TXN_REPLY from '%s' txn-id %" PRIx64
			" with '%s'",
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
		MGMTD_BE_ADAPTER_DBG(
			"Got CFGDATA_REPLY from '%s' txn-id %" PRIx64
			" batch-id %" PRIu64 " err:'%s'",
			adapter->name, be_msg->cfg_data_reply->txn_id,
			be_msg->cfg_data_reply->batch_id,
			be_msg->cfg_data_reply->error_if_any
				? be_msg->cfg_data_reply->error_if_any
				: "None");
		/*
		 * Forward the CGFData-create reply to txn module.
		 */
		mgmt_txn_notify_be_cfgdata_reply(
			be_msg->cfg_data_reply->txn_id,
			be_msg->cfg_data_reply->batch_id,
			be_msg->cfg_data_reply->success,
			be_msg->cfg_data_reply->error_if_any, adapter);
		break;
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_APPLY_REPLY:
		MGMTD_BE_ADAPTER_DBG(
			"Got %s CFG_APPLY_REPLY from '%s' txn-id %" PRIx64
			" for %zu batches id %" PRIu64 "-%" PRIu64 " err:'%s'",
			be_msg->cfg_apply_reply->success ? "successful"
							 : "failed",
			adapter->name, be_msg->cfg_apply_reply->txn_id,
			be_msg->cfg_apply_reply->n_batch_ids,
			be_msg->cfg_apply_reply->batch_ids[0],
			be_msg->cfg_apply_reply->batch_ids
				[be_msg->cfg_apply_reply->n_batch_ids - 1],
			be_msg->cfg_apply_reply->error_if_any
				? be_msg->cfg_apply_reply->error_if_any
				: "None");
		/*
		 * Forward the CGFData-apply reply to txn module.
		 */
		mgmt_txn_notify_be_cfg_apply_reply(
			be_msg->cfg_apply_reply->txn_id,
			be_msg->cfg_apply_reply->success,
			(uint64_t *)be_msg->cfg_apply_reply->batch_ids,
			be_msg->cfg_apply_reply->n_batch_ids,
			be_msg->cfg_apply_reply->error_if_any, adapter);
		break;
	case MGMTD__BE_MESSAGE__MESSAGE_GET_REPLY:
		MGMTD_BE_ADAPTER_DBG(
			"Got %s GET_REPLY Msg from '%s' with %d data for Trxn-Id 0x%" PRIx64 " Batch-Id 0x%" PRIx64 " with Err:'%s'",
			be_msg->get_reply->success ? "successful" : "failed",
			adapter->name, (int)be_msg->get_reply->data->n_data,
			be_msg->get_reply->txn_id, be_msg->get_reply->batch_id,
			be_msg->get_reply->error
				? be_msg->get_reply->error
				: "None");
		/*
		 * Forward the GET_REPLY reply to txn module.
		 */
		mgmt_txn_notify_be_getdata_req_reply(
			be_msg->get_reply->txn_id,
			be_msg->get_reply->success,
			be_msg->get_reply->batch_id,
			be_msg->get_reply->data,
			be_msg->get_reply->error, adapter);
		break;
	/*
	 * NOTE: The following messages are always sent from MGMTD to
	 * Backend clients only and/or need not be handled on MGMTd.
	 */
	case MGMTD__BE_MESSAGE__MESSAGE_SUBSCR_REPLY:
	case MGMTD__BE_MESSAGE__MESSAGE_GET_REQ:
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

	MGMTD_BE_ADAPTER_DBG("Sending TXN_REQ to '%s' txn-id: %" PRIu64,
			     adapter->name, txn_id);

	return mgmt_be_adapter_send_msg(adapter, &be_msg);
}

int mgmt_be_send_cfgdata_req(struct mgmt_be_client_adapter *adapter,
			     uint64_t txn_id, uint64_t batch_id,
			     Mgmtd__YangCfgDataReq **cfgdata_reqs,
			     size_t num_reqs, bool end_of_data)
{
	Mgmtd__BeMessage be_msg;
	Mgmtd__BeCfgDataCreateReq cfgdata_req;

	mgmtd__be_cfg_data_create_req__init(&cfgdata_req);
	cfgdata_req.batch_id = batch_id;
	cfgdata_req.txn_id = txn_id;
	cfgdata_req.data_req = cfgdata_reqs;
	cfgdata_req.n_data_req = num_reqs;
	cfgdata_req.end_of_data = end_of_data;

	mgmtd__be_message__init(&be_msg);
	be_msg.message_case = MGMTD__BE_MESSAGE__MESSAGE_CFG_DATA_REQ;
	be_msg.cfg_data_req = &cfgdata_req;

	MGMTD_BE_ADAPTER_DBG(
		"Sending CFGDATA_CREATE_REQ to '%s' txn-id: %" PRIu64
		" batch-id: %" PRIu64,
		adapter->name, txn_id, batch_id);

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

	MGMTD_BE_ADAPTER_DBG("Sending CFG_APPLY_REQ to '%s' txn-id: %" PRIu64,
			     adapter->name, txn_id);

	return mgmt_be_adapter_send_msg(adapter, &be_msg);
}

/*
 * Send GET_DATA_REQ to a backend Adapter for a specific set
 * XPATHs.
 */
int mgmt_be_send_get_data_req(struct mgmt_be_client_adapter *adapter,
			      uint64_t txn_id, uint64_t batch_id,
			      struct mgmt_be_datareq *data_req)
{
	Mgmtd__BeMessage be_msg;
	Mgmtd__BeOperDataGetReq get_req;

	mgmtd__be_oper_data_get_req__init(&get_req);
	get_req.txn_id = txn_id;
	get_req.batch_id = batch_id;
	get_req.n_data = data_req->num_reqs;
	get_req.data = data_req->getdata_reqs;

	mgmtd__be_message__init(&be_msg);
	be_msg.message_case = MGMTD__BE_MESSAGE__MESSAGE_GET_REQ;
	be_msg.get_req = &get_req;

	MGMTD_BE_ADAPTER_DBG(
		"Sending GET_REQ message to Backend client '%s' for Trxn-Id 0x%" PRIx64,
		adapter->name, txn_id);

	return mgmt_be_adapter_send_msg(adapter, &be_msg);
}

static void mgmt_be_adapter_process_msg(uint8_t version, uint8_t *data,
					size_t len, struct msg_conn *conn)
{
	struct mgmt_be_client_adapter *adapter = conn->user;
	Mgmtd__BeMessage *be_msg = mgmtd__be_message__unpack(NULL, len, data);

	if (!be_msg) {
		MGMTD_BE_ADAPTER_DBG(
			"Failed to decode %zu bytes for adapter: %s", len,
			adapter->name);
		return;
	}
	MGMTD_BE_ADAPTER_DBG("Decoded %zu bytes of message: %u for adapter: %s",
			     len, be_msg->message_case, adapter->name);
	(void)mgmt_be_adapter_handle_msg(adapter, be_msg);
	mgmtd__be_message__free_unpacked(be_msg, NULL);
}

static void mgmt_be_iter_and_get_cfg(struct mgmt_ds_ctx *ds_ctx,
				     const char *xpath, struct lyd_node *node,
				     struct nb_node *nb_node, void *ctx)
{
	(void) ds_ctx;
	struct mgmt_be_get_adapter_config_params *parms = ctx;
	struct mgmt_be_client_adapter *adapter = parms->adapter;
	uint subscr;

	subscr = mgmt_be_get_subscr_for_xpath_and_client(
			xpath, adapter->id,
			MGMT_SUBSCR_VALIDATE_CFG | MGMT_SUBSCR_NOTIFY_CFG);
	if (subscr & (MGMT_SUBSCR_VALIDATE_CFG | MGMT_SUBSCR_NOTIFY_CFG))
		nb_config_diff_created(node, &parms->seq, parms->cfg_chgs);
}

/*
 * Initialize a BE client over a new connection
 */
static void mgmt_be_adapter_conn_init(struct event *thread)
{
	struct mgmt_be_client_adapter *adapter;

	adapter = (struct mgmt_be_client_adapter *)EVENT_ARG(thread);
	assert(adapter && adapter->conn->fd >= 0);

	/*
	 * Check first if the current session can run a CONFIG
	 * transaction or not. Reschedule if a CONFIG transaction
	 * from another session is already in progress.
	 */
	if (mgmt_config_txn_in_progress() != MGMTD_SESSION_ID_NONE) {
		zlog_err("XXX txn in progress, retry init");
		mgmt_be_adapter_sched_init_event(adapter);
		return;
	}

	/*
	 * Notify TXN module to create a CONFIG transaction and
	 * download the CONFIGs identified for this new client.
	 * If the TXN module fails to initiate the CONFIG transaction
	 * disconnect from the client forcing a reconnect later.
	 * That should also take care of destroying the adapter.
	 */
	if (mgmt_txn_notify_be_adapter_conn(adapter, true) != 0) {
		zlog_err("XXX notify be adapter conn fail");
		msg_conn_disconnect(adapter->conn, false);
		adapter = NULL;
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

void mgmt_be_adapter_lock(struct mgmt_be_client_adapter *adapter,
			  const char *file, int line)
{
	adapter->refcount++;
	MGMTD_BE_ADAPTER_DBG("%s:%d --> Lock BE adapter '%s' (%p) refcnt: %d",
			     file, line, adapter->name, adapter, adapter->refcount);
}

void mgmt_be_adapter_unlock(struct mgmt_be_client_adapter **adapter,
			    const char *file, int line)
{
	struct mgmt_be_client_adapter *a = *adapter;
	assert(a && a->refcount);

	a->refcount--;
	MGMTD_BE_ADAPTER_DBG("%s:%d --> Unlock BE adapter '%s' (%p) refcnt: %d",
			     file, line, (*adapter)->name, *adapter,
			     (*adapter)->refcount);
	if (!a->refcount) {
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
	assert(!mgmt_loop);
	mgmt_loop = tm;

	mgmt_be_adapters_init(&mgmt_be_adapters);
	mgmt_be_xpath_map_init();

	if (msg_server_init(&mgmt_be_server, MGMTD_BE_SERVER_PATH, tm,
			    mgmt_be_create_adapter, "backend",
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

	MGMTD_BE_ADAPTER_LOCK(adapter);
	mgmt_be_adapters_add_tail(&mgmt_be_adapters, adapter);
	RB_INIT(nb_config_cbs, &adapter->cfg_chgs);

	adapter->conn = msg_server_conn_create(
		mgmt_loop, conn_fd, mgmt_be_adapter_notify_disconnect,
		mgmt_be_adapter_process_msg, MGMTD_BE_MAX_NUM_MSG_PROC,
		MGMTD_BE_MAX_NUM_MSG_WRITE, MGMTD_BE_MSG_MAX_LEN, adapter,
		"BE-adapter");

	MGMTD_BE_ADAPTER_DBG("Added new MGMTD Backend adapter '%s'",
			     adapter->name);

	return adapter->conn;
}

struct mgmt_be_client_adapter *
mgmt_be_get_adapter_by_id(enum mgmt_be_client_id id)
{
	return (id < MGMTD_BE_CLIENT_ID_MAX ? mgmt_be_adapters_by_id[id]
					       : NULL);
}

struct mgmt_be_client_adapter *
mgmt_be_get_adapter_by_name(const char *name)
{
	return mgmt_be_find_adapter_by_name(name);
}

int mgmt_be_get_adapter_config(struct mgmt_be_client_adapter *adapter,
			       struct nb_config_cbs **cfg_chgs)
{
	struct mgmt_be_get_adapter_config_params parms;
	struct nb_config *cfg_root = mgmt_ds_get_nb_config(mm->running_ds);

	assert(cfg_chgs);

	/*
	 * TODO: we should consider making this an assertable condition and
	 * guaranteeing it be true when this function is called. B/c what is
	 * going to happen if there are some changes being sent, and we don't
	 * gather a new snapshot, what new changes that came after the previous
	 * snapshot will then be lost?
	 */
	if (RB_EMPTY(nb_config_cbs, &adapter->cfg_chgs)) {
		parms.adapter = adapter;
		parms.cfg_chgs = &adapter->cfg_chgs;
		parms.seq = 0;

		mgmt_ds_iter_data(MGMTD_DS_RUNNING, cfg_root, "",
				  mgmt_be_iter_and_get_cfg, (void *)&parms);
	}

	*cfg_chgs = &adapter->cfg_chgs;
	return 0;
}

/*
 * This function maps a YANG data Xpath to one or more
 * Backend Clients that should be contacted for various purposes.
 * Note - Caller should de-allocate xp_map uisng
 * mgmt_be_cleanup_xpath_subscr_info()
 */
int mgmt_be_get_subscr_info_for_xpath(
	const char *xpath, struct mgmt_be_client_subscr_info *subscr_info,
	bool get_full_match)
{
	int indx, indx1, match, max_match = 0, num_reg;
	struct mgmt_be_xpath_map *map;
	enum mgmt_be_client_id id;
	struct mgmt_be_xpath_map
		*reg_maps[MGMTD_BE_MAX_NUM_XPATH_MAP] = {0};
	char *xp_matches[MGMTD_BE_MAX_NUM_XPATH_MAP] = {0};
	char *xp_match = NULL;
	struct mgmt_xpath_entry *xp_map = NULL;
	bool root_xp = false;

	if (!subscr_info)
		return -1;

	num_reg = 0;
	memset(subscr_info, 0, sizeof(*subscr_info));
	FOREACH_MGMTD_BE_CLIENT_ID (id) {
		mgmt_xpaths_init(
			&subscr_info->xpath_subscr[id]
					.xpaths);
	}

	if (strlen(xpath) <= 2 && xpath[0] == '/'
		&& (!xpath[1] || xpath[1] == '*')) {
		root_xp = true;
	}

	MGMTD_BE_ADAPTER_DBG("XPATH: %s", xpath);
	darr_foreach_p (mgmt_xpath_map, map) {
		xp_match = NULL;
		/*
		 * For Xpaths: '/' and '/ *' all xpath maps should match
		 * the given xpath.
		 */
		if (!root_xp) {
			match = mgmt_xpath_eval_regexp_match(
				map->xpath_regexp, xpath,
				true, &xp_match, NULL,
				get_full_match ? false : true);
			MGMTD_BE_ADAPTER_DBG("RE: '%s' -- Match:%d, Max-match: %d, #Reg: %d",
					     map->xpath_regexp, match, max_match, num_reg);
			if (!match || match < max_match) {
				free (xp_match);
				continue;
			}

			if (match > max_match) {
				for (indx1 = 0; indx1 < num_reg; indx1++) {
					if (xp_matches[indx1]) {
						free(xp_matches[indx1]);
						xp_matches[indx1] = NULL;
					}
				}

				num_reg = 0;
				max_match = match;
			}
		} else
			xp_match = strdup(map->xpath_regexp);

		reg_maps[num_reg] = map;
		xp_matches[num_reg] = xp_match;
		xp_match = NULL;
		num_reg++;
	}

	MGMTD_BE_ADAPTER_DBG("Mapped regex to %d Map entries...", num_reg);
	for (indx = 0; indx < num_reg; indx++) {
		MGMTD_BE_ADAPTER_DBG("%d : %s", indx, reg_maps[indx]->xpath_regexp);
		FOREACH_MGMTD_BE_CLIENT_ID (id) {
			if (reg_maps[indx]->subscr_info[id]) {
				MGMTD_BE_ADAPTER_DBG(
					"Cient: %s",
					mgmt_be_client_id2name(id));
				if (!subscr_info->xpath_subscr[id].subscribed) {
					mgmt_xpaths_init(
						&subscr_info->xpath_subscr[id]
							 .xpaths);
					subscr_info->xpath_subscr[id].subscribed |=
						reg_maps[indx]->subscr_info[id];
				}

				/*
				 * Generate xp_map
				 */
				xp_map = XCALLOC(
					MTYPE_MGMTD_XPATH_MAP,
					sizeof(struct mgmt_xpath_entry));
				assert(xp_map);
				xp_map->subscribed =
					reg_maps[indx]->subscr_info[id];
				xp_map->xpath = strdup(xp_matches[indx]);
				mgmt_xpaths_add_tail(
					&subscr_info->xpath_subscr[id]
						 .xpaths,
					xp_map);
			}
		}
	}

	for (indx = 0; indx < (int)array_size(xp_matches); indx++) {
		if (xp_matches[indx]) {
			free(xp_matches[indx]);
			xp_matches[indx] = NULL;
		}
	}

	return 0;
}

/**
 * Return the subscription info bits for a given `xpath` for a given
 * `client_id`.
 *
 * Args:
 *     xpath - the xpath to check for subscription information.
 *     client_id - the BE client being checked for.
 *     subscr_mask - The subscr bits the caller is interested in seeing
 * if set.
 *
 * Returns:
 *     The subscription info bits.
 */
static uint mgmt_be_get_subscr_for_xpath_and_client(
	const char *xpath, enum mgmt_be_client_id client_id, uint subscr_mask)
{
	struct mgmt_be_client_xpath_map *map;
	uint subscr = 0;
	uint i;

	assert(client_id < MGMTD_BE_CLIENT_ID_MAX);

	MGMTD_BE_ADAPTER_DBG("Checking client: %s for xpath: '%s'",
			     mgmt_be_client_id2name(client_id), xpath);

	map = &mgmt_client_xpaths[client_id];
	for (i = 0; i < map->nxpaths; i++) {
		if (!mgmt_xpath_eval_regexp_match(map->xpaths[i].xpath, xpath,
						  false, NULL, NULL, true))
			continue;

		MGMTD_BE_ADAPTER_DBG("xpath: %s: matched: %s",
				     map->xpaths[i].xpath, xpath);
		subscr |= map->xpaths[i].subscribed;
		if ((subscr & subscr_mask) == subscr_mask)
			break;
	}
	MGMTD_BE_ADAPTER_DBG("client: %s: subscribed: 0x%x",
			     mgmt_be_client_id2name(client_id), subscr);
	return subscr;
}

/*
 * Cleanup xpath map.
 */
void mgmt_be_cleanup_xpath_subscr_info(
	struct mgmt_be_client_subscr_info *subscr)
{
	enum mgmt_be_client_id id;
	struct mgmt_xpath_entry *xp_map = NULL;

	FOREACH_MGMTD_BE_CLIENT_ID (id) {
		if (!subscr->xpath_subscr[id].subscribed)
			continue;
		FOREACH_XPATH_IN_SUBSCR_INFO (subscr, id, xp_map) {
			if (xp_map->xpath)
				free((char *)xp_map->xpath);
			mgmt_xpaths_del(
					&subscr->xpath_subscr[id].xpaths,
					xp_map);
			XFREE(MTYPE_MGMTD_XPATH_MAP, xp_map);
		}
	}
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

void mgmt_be_xpath_register_write(struct vty *vty)
{
	struct mgmt_be_xpath_map *map;
	enum mgmt_be_client_id id;
	struct mgmt_be_client_adapter *adapter;
	uint info;

	vty_out(vty, "MGMTD Backend XPath Registry\n");

	darr_foreach_p(mgmt_xpath_map, map) {
		vty_out(vty, " - XPATH: '%s'\n", map->xpath_regexp);
		FOREACH_MGMTD_BE_CLIENT_ID (id) {
			info = map->subscr_info[id];
			if (!info)
				continue;
			vty_out(vty,
				"   -- Client: '%s'\tValidate:%d, Notify:%d, Own:%d\n",
				mgmt_be_client_id2name(id),
				(info & MGMT_SUBSCR_VALIDATE_CFG) != 0,
				(info & MGMT_SUBSCR_NOTIFY_CFG) != 0,
				(info & MGMT_SUBSCR_OPER_OWN) != 0);
			adapter = mgmt_be_get_adapter_by_id(id);
			if (adapter)
				vty_out(vty, "     -- Adapter: %p\n", adapter);
		}
	}

	vty_out(vty, "Total XPath Registries: %u\n", darr_len(mgmt_xpath_map));
}

void mgmt_be_xpath_subscr_info_write(struct vty *vty, const char *xpath)
{
	struct mgmt_be_client_subscr_info subscr;
	enum mgmt_be_client_id id;
	struct mgmt_be_client_adapter *adapter;
	struct mgmt_xpath_entry *xp;
	uint info;

	mgmt_be_get_subscr_info_for_xpath(xpath, &subscr, false);

	vty_out(vty, "XPath: '%s'\n", xpath);
	FOREACH_MGMTD_BE_CLIENT_ID (id) {
		info = subscr.xpath_subscr[id].subscribed;
		if (!info)
			continue;
		vty_out(vty,
			"  -- Client: '%s'\tValidate:%d, Notify:%d, Own:%d\n",
			mgmt_be_client_id2name(id),
			(info & MGMT_SUBSCR_VALIDATE_CFG) != 0,
			(info & MGMT_SUBSCR_NOTIFY_CFG) != 0,
			(info & MGMT_SUBSCR_OPER_OWN) != 0);
		adapter = mgmt_be_get_adapter_by_id(id);
		if (adapter) {
			vty_out(vty, "    -- Adapter: %p\n", adapter);
			vty_out(vty, "    -- Matches:\n");
			FOREACH_XPATH_IN_SUBSCR_INFO (&subscr, id, xp)
				vty_out(vty, "     -- %s\n", xp->xpath);
		}
	}
}
