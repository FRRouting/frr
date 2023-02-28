// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD Backend Client Connection Adapter
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#include <zebra.h>
#include "thread.h"
#include "sockopt.h"
#include "network.h"
#include "libfrr.h"
#include "mgmt_pb.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_memory.h"
#include "mgmt_be_client.h"
#include "mgmtd/mgmt_be_adapter.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define MGMTD_BE_ADAPTER_DBG(fmt, ...)                                        \
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define MGMTD_BE_ADAPTER_ERR(fmt, ...)                                        \
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define MGMTD_BE_ADAPTER_DBG(fmt, ...)                                        \
	do {                                                                  \
		if (mgmt_debug_be)                                            \
			zlog_debug("%s: " fmt, __func__, ##__VA_ARGS__);      \
	} while (0)
#define MGMTD_BE_ADAPTER_ERR(fmt, ...)                                        \
	zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

#define FOREACH_ADAPTER_IN_LIST(adapter)                                       \
	frr_each_safe (mgmt_be_adapters, &mgmt_be_adapters, (adapter))

/*
 * Static mapping of YANG XPath regular expressions and
 * the corresponding interested backend clients.
 * NOTE: Thiis is a static mapping defined by all MGMTD
 * backend client modules (for now, till we develop a
 * more dynamic way of creating and updating this map).
 * A running map is created by MGMTD in run-time to
 * handle real-time mapping of YANG xpaths to one or
 * more interested backend client adapters.
 *
 * Please see xpath_map_reg[] in lib/mgmt_be_client.c
 * for the actual map
 */
struct mgmt_be_xpath_map_reg {
	const char *xpath_regexp; /* Longest matching regular expression */
	enum mgmt_be_client_id *be_clients; /* clients to notify */
};

struct mgmt_be_xpath_regexp_map {
	const char *xpath_regexp;
	struct mgmt_be_client_subscr_info be_subscrs;
};

struct mgmt_be_get_adapter_config_params {
	struct mgmt_be_client_adapter *adapter;
	struct nb_config_cbs *cfg_chgs;
	uint32_t seq;
};

/*
 * Static mapping of YANG XPath regular expressions and
 * the corresponding interested backend clients.
 * NOTE: Thiis is a static mapping defined by all MGMTD
 * backend client modules (for now, till we develop a
 * more dynamic way of creating and updating this map).
 * A running map is created by MGMTD in run-time to
 * handle real-time mapping of YANG xpaths to one or
 * more interested backend client adapters.
 */
static const struct mgmt_be_xpath_map_reg xpath_static_map_reg[] = {
	{.xpath_regexp = "/frr-vrf:lib/*",
	 .be_clients =
		 (enum mgmt_be_client_id[]){
#if 0
#if HAVE_STATICD
		 MGMTD_BE_CLIENT_ID_STATICD,
#endif
#endif
			 MGMTD_BE_CLIENT_ID_MAX}},
	{.xpath_regexp = "/frr-interface:lib/*",
	 .be_clients =
		 (enum mgmt_be_client_id[]){
#if 0
#if HAVE_STATICD
		 MGMTD_BE_CLIENT_ID_STATICD,
#endif
#endif
			 MGMTD_BE_CLIENT_ID_MAX}},
	{.xpath_regexp =
		 "/frr-routing:routing/control-plane-protocols/control-plane-protocol[type='frr-staticd:staticd'][name='staticd'][vrf='default']/frr-staticd:staticd/*",

	 .be_clients =
		 (enum mgmt_be_client_id[]){
#if 0
#if HAVE_STATICD
		 MGMTD_BE_CLIENT_ID_STATICD,
#endif
#endif
			 MGMTD_BE_CLIENT_ID_MAX}},
};

#define MGMTD_BE_MAX_NUM_XPATH_MAP 256
static struct mgmt_be_xpath_regexp_map
	mgmt_xpath_map[MGMTD_BE_MAX_NUM_XPATH_MAP];
static int mgmt_num_xpath_maps;

static struct thread_master *mgmt_be_adapter_tm;

static struct mgmt_be_adapters_head mgmt_be_adapters;

static struct mgmt_be_client_adapter
	*mgmt_be_adapters_by_id[MGMTD_BE_CLIENT_ID_MAX];

/* Forward declarations */
static void
mgmt_be_adapter_register_event(struct mgmt_be_client_adapter *adapter,
			       enum mgmt_be_event event);

static struct mgmt_be_client_adapter *
mgmt_be_find_adapter_by_fd(int conn_fd)
{
	struct mgmt_be_client_adapter *adapter;

	FOREACH_ADAPTER_IN_LIST (adapter) {
		if (adapter->conn_fd == conn_fd)
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

static void
mgmt_be_cleanup_adapters(void)
{
	struct mgmt_be_client_adapter *adapter;

	FOREACH_ADAPTER_IN_LIST (adapter)
		mgmt_be_adapter_unlock(&adapter);
}

static void mgmt_be_xpath_map_init(void)
{
	int indx, num_xpath_maps;
	uint16_t indx1;
	enum mgmt_be_client_id id;

	MGMTD_BE_ADAPTER_DBG("Init XPath Maps");

	num_xpath_maps = (int)array_size(xpath_static_map_reg);
	for (indx = 0; indx < num_xpath_maps; indx++) {
		MGMTD_BE_ADAPTER_DBG(" - XPATH: '%s'",
				     xpath_static_map_reg[indx].xpath_regexp);
		mgmt_xpath_map[indx].xpath_regexp =
			xpath_static_map_reg[indx].xpath_regexp;
		for (indx1 = 0;; indx1++) {
			id = xpath_static_map_reg[indx].be_clients[indx1];
			if (id == MGMTD_BE_CLIENT_ID_MAX)
				break;
			MGMTD_BE_ADAPTER_DBG("   -- Client: %s Id: %u",
					     mgmt_be_client_id2name(id),
					     id);
			if (id < MGMTD_BE_CLIENT_ID_MAX) {
				mgmt_xpath_map[indx]
					.be_subscrs.xpath_subscr[id]
					.validate_config = 1;
				mgmt_xpath_map[indx]
					.be_subscrs.xpath_subscr[id]
					.notify_config = 1;
				mgmt_xpath_map[indx]
					.be_subscrs.xpath_subscr[id]
					.own_oper_data = 1;
			}
		}
	}

	mgmt_num_xpath_maps = indx;
	MGMTD_BE_ADAPTER_DBG("Total XPath Maps: %u", mgmt_num_xpath_maps);
}

static int mgmt_be_eval_regexp_match(const char *xpath_regexp,
				     const char *xpath)
{
	int match_len = 0, re_indx = 0, xp_indx = 0;
	int rexp_len, xpath_len;
	bool match = true, re_wild = false, xp_wild = false;
	bool delim = false, enter_wild_match = false;
	char wild_delim = 0;

	rexp_len = strlen(xpath_regexp);
	xpath_len = strlen(xpath);

	/*
	 * Remove the trailing wildcard from the regexp and Xpath.
	 */
	if (rexp_len && xpath_regexp[rexp_len-1] == '*')
		rexp_len--;
	if (xpath_len && xpath[xpath_len-1] == '*')
		xpath_len--;

	if (!rexp_len || !xpath_len)
		return 0;

	for (re_indx = 0, xp_indx = 0;
	     match && re_indx < rexp_len && xp_indx < xpath_len;) {
		match = (xpath_regexp[re_indx] == xpath[xp_indx]);

		/*
		 * Check if we need to enter wildcard matching.
		 */
		if (!enter_wild_match && !match &&
			(xpath_regexp[re_indx] == '*'
			 || xpath[xp_indx] == '*')) {
			/*
			 * Found wildcard
			 */
			enter_wild_match =
				(xpath_regexp[re_indx-1] == '/'
				 || xpath_regexp[re_indx-1] == '\''
				 || xpath[xp_indx-1] == '/'
				 || xpath[xp_indx-1] == '\'');
			if (enter_wild_match) {
				if (xpath_regexp[re_indx] == '*') {
					/*
					 * Begin RE wildcard match.
					 */
					re_wild = true;
					wild_delim = xpath_regexp[re_indx-1];
				} else if (xpath[xp_indx] == '*') {
					/*
					 * Begin XP wildcard match.
					 */
					xp_wild = true;
					wild_delim = xpath[xp_indx-1];
				}
			}
		}

		/*
		 * Check if we need to exit wildcard matching.
		 */
		if (enter_wild_match) {
			if (re_wild && xpath[xp_indx] == wild_delim) {
				/*
				 * End RE wildcard matching.
				 */
				re_wild = false;
				if (re_indx < rexp_len-1)
					re_indx++;
				enter_wild_match = false;
			} else if (xp_wild
				   && xpath_regexp[re_indx] == wild_delim) {
				/*
				 * End XP wildcard matching.
				 */
				xp_wild = false;
				if (xp_indx < xpath_len-1)
					xp_indx++;
				enter_wild_match = false;
			}
		}

		match = (xp_wild || re_wild
			 || xpath_regexp[re_indx] == xpath[xp_indx]);

		/*
		 * Check if we found a delimiter in both the Xpaths
		 */
		if ((xpath_regexp[re_indx] == '/'
			&& xpath[xp_indx] == '/')
			|| (xpath_regexp[re_indx] == ']'
				&& xpath[xp_indx] == ']')
			|| (xpath_regexp[re_indx] == '['
				&& xpath[xp_indx] == '[')) {
			/*
			 * Increment the match count if we have a
			 * new delimiter.
			 */
			if (match && re_indx && xp_indx && !delim)
				match_len++;
			delim = true;
		} else {
			delim = false;
		}

		/*
		 * Proceed to the next character in the RE/XP string as
		 * necessary.
		 */
		if (!re_wild)
			re_indx++;
		if (!xp_wild)
			xp_indx++;
	}

	/*
	 * If we finished matching and the last token was a full match
	 * increment the match count appropriately.
	 */
	if (match && !delim &&
		(xpath_regexp[re_indx] == '/'
		 || xpath_regexp[re_indx] == ']'))
		match_len++;

	return match_len;
}

static void mgmt_be_adapter_disconnect(struct mgmt_be_client_adapter *adapter)
{
	if (adapter->conn_fd >= 0) {
		close(adapter->conn_fd);
		adapter->conn_fd = -1;
	}

	/*
	 * TODO: Notify about client disconnect for appropriate cleanup
	 * mgmt_txn_notify_be_adapter_conn(adapter, false);
	 */

	if (adapter->id < MGMTD_BE_CLIENT_ID_MAX) {
		mgmt_be_adapters_by_id[adapter->id] = NULL;
		adapter->id = MGMTD_BE_CLIENT_ID_MAX;
	}

	mgmt_be_adapters_del(&mgmt_be_adapters, adapter);

	mgmt_be_adapter_unlock(&adapter);
}

static void
mgmt_be_adapter_cleanup_old_conn(struct mgmt_be_client_adapter *adapter)
{
	struct mgmt_be_client_adapter *old;

	FOREACH_ADAPTER_IN_LIST (old) {
		if (old != adapter
		    && !strncmp(adapter->name, old->name, sizeof(adapter->name))) {
			/*
			 * We have a Zombie lingering around
			 */
			MGMTD_BE_ADAPTER_DBG(
				"Client '%s' (FD:%d) seems to have reconnected. Removing old connection (FD:%d)!",
				adapter->name, adapter->conn_fd, old->conn_fd);
			mgmt_be_adapter_disconnect(old);
		}
	}
}

static int
mgmt_be_adapter_handle_msg(struct mgmt_be_client_adapter *adapter,
			      Mgmtd__BeMessage *be_msg)
{
	switch (be_msg->message_case) {
	case MGMTD__BE_MESSAGE__MESSAGE_SUBSCR_REQ:
		MGMTD_BE_ADAPTER_DBG(
			"Got Subscribe Req Msg from '%s' to %sregister %u xpaths",
			be_msg->subscr_req->client_name,
			!be_msg->subscr_req->subscribe_xpaths
					&& be_msg->subscr_req->n_xpath_reg
				? "de"
				: "",
			(uint32_t)be_msg->subscr_req->n_xpath_reg);

		if (strlen(be_msg->subscr_req->client_name)) {
			strlcpy(adapter->name, be_msg->subscr_req->client_name,
				sizeof(adapter->name));
			adapter->id = mgmt_be_client_name2id(adapter->name);
			if (adapter->id >= MGMTD_BE_CLIENT_ID_MAX) {
				MGMTD_BE_ADAPTER_ERR(
					"Unable to resolve adapter '%s' to a valid ID. Disconnecting!",
					adapter->name);
				mgmt_be_adapter_disconnect(adapter);
			}
			mgmt_be_adapters_by_id[adapter->id] = adapter;
			mgmt_be_adapter_cleanup_old_conn(adapter);
		}
		break;
	case MGMTD__BE_MESSAGE__MESSAGE_TXN_REPLY:
		MGMTD_BE_ADAPTER_DBG(
			"Got %s TXN_REPLY Msg for Txn-Id 0x%llx from '%s' with '%s'",
			be_msg->txn_reply->create ? "Create" : "Delete",
			(unsigned long long)be_msg->txn_reply->txn_id,
			adapter->name,
			be_msg->txn_reply->success ? "success" : "failure");
		/*
		 * TODO: Forward the TXN_REPLY to txn module.
		 * mgmt_txn_notify_be_txn_reply(
		 *	be_msg->txn_reply->txn_id,
		 *	be_msg->txn_reply->create,
		 *	be_msg->txn_reply->success, adapter);
		 */
		break;
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_DATA_REPLY:
		MGMTD_BE_ADAPTER_DBG(
			"Got CFGDATA_REPLY Msg from '%s' for Txn-Id 0x%llx Batch-Id 0x%llx with Err:'%s'",
			adapter->name,
			(unsigned long long)be_msg->cfg_data_reply->txn_id,
			(unsigned long long)be_msg->cfg_data_reply->batch_id,
			be_msg->cfg_data_reply->error_if_any
				? be_msg->cfg_data_reply->error_if_any
				: "None");
		/*
		 * TODO: Forward the CGFData-create reply to txn module.
		 * mgmt_txn_notify_be_cfgdata_reply(
		 *	be_msg->cfg_data_reply->txn_id,
		 *	be_msg->cfg_data_reply->batch_id,
		 *	be_msg->cfg_data_reply->success,
		 *	be_msg->cfg_data_reply->error_if_any, adapter);
		 */
		break;
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_APPLY_REPLY:
		MGMTD_BE_ADAPTER_DBG(
			"Got %s CFG_APPLY_REPLY Msg from '%s' for Txn-Id 0x%llx for %d batches (Id 0x%llx-0x%llx),  Err:'%s'",
			be_msg->cfg_apply_reply->success ? "successful"
							    : "failed",
			adapter->name,
			(unsigned long long)
				be_msg->cfg_apply_reply->txn_id,
			(int)be_msg->cfg_apply_reply->n_batch_ids,
			(unsigned long long)
				be_msg->cfg_apply_reply->batch_ids[0],
			(unsigned long long)be_msg->cfg_apply_reply
				->batch_ids[be_msg->cfg_apply_reply
						    ->n_batch_ids
					    - 1],
			be_msg->cfg_apply_reply->error_if_any
				? be_msg->cfg_apply_reply->error_if_any
				: "None");
		/* TODO: Forward the CGFData-apply reply to txn module.
		 * mgmt_txn_notify_be_cfg_apply_reply(
		 *	be_msg->cfg_apply_reply->txn_id,
		 *	be_msg->cfg_apply_reply->success,
		 *	(uint64_t *)be_msg->cfg_apply_reply->batch_ids,
		 *	be_msg->cfg_apply_reply->n_batch_ids,
		 *	be_msg->cfg_apply_reply->error_if_any, adapter);
		 */
		break;
	case MGMTD__BE_MESSAGE__MESSAGE_GET_REPLY:
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_CMD_REPLY:
	case MGMTD__BE_MESSAGE__MESSAGE_SHOW_CMD_REPLY:
	case MGMTD__BE_MESSAGE__MESSAGE_NOTIFY_DATA:
		/*
		 * TODO: Add handling code in future.
		 */
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
	case MGMTD__BE_MESSAGE__MESSAGE_CFG_CMD_REQ:
	case MGMTD__BE_MESSAGE__MESSAGE_SHOW_CMD_REQ:
	case MGMTD__BE_MESSAGE__MESSAGE__NOT_SET:
#if PROTOBUF_C_VERSION_NUMBER >= 1003000
	case _MGMTD__BE_MESSAGE__MESSAGE_IS_INT_SIZE:
#endif
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

static inline void
mgmt_be_adapter_sched_msg_write(struct mgmt_be_client_adapter *adapter)
{
	if (!CHECK_FLAG(adapter->flags, MGMTD_BE_ADAPTER_FLAGS_WRITES_OFF))
		mgmt_be_adapter_register_event(adapter, MGMTD_BE_CONN_WRITE);
}

static inline void
mgmt_be_adapter_writes_on(struct mgmt_be_client_adapter *adapter)
{
	MGMTD_BE_ADAPTER_DBG("Resume writing msgs for '%s'", adapter->name);
	UNSET_FLAG(adapter->flags, MGMTD_BE_ADAPTER_FLAGS_WRITES_OFF);
	if (adapter->obuf_work || stream_fifo_count_safe(adapter->obuf_fifo))
		mgmt_be_adapter_sched_msg_write(adapter);
}

static inline void
mgmt_be_adapter_writes_off(struct mgmt_be_client_adapter *adapter)
{
	SET_FLAG(adapter->flags, MGMTD_BE_ADAPTER_FLAGS_WRITES_OFF);
	MGMTD_BE_ADAPTER_DBG("Pause writing msgs for '%s'", adapter->name);
}

static int mgmt_be_adapter_send_msg(struct mgmt_be_client_adapter *adapter,
				       Mgmtd__BeMessage *be_msg)
{
	size_t msg_size;
	uint8_t *msg_buf = adapter->msg_buf;
	struct mgmt_be_msg *msg;

	if (adapter->conn_fd < 0)
		return -1;

	msg_size = mgmtd__be_message__get_packed_size(be_msg);
	msg_size += MGMTD_BE_MSG_HDR_LEN;
	if (msg_size > MGMTD_BE_MSG_MAX_LEN) {
		MGMTD_BE_ADAPTER_ERR(
			"Message size %d more than max size'%d. Not sending!'",
			(int)msg_size, (int)MGMTD_BE_MSG_MAX_LEN);
		return -1;
	}

	msg = (struct mgmt_be_msg *)msg_buf;
	msg->hdr.marker = MGMTD_BE_MSG_MARKER;
	msg->hdr.len = (uint16_t)msg_size;
	mgmtd__be_message__pack(be_msg, msg->payload);

	if (!adapter->obuf_work)
		adapter->obuf_work = stream_new(MGMTD_BE_MSG_MAX_LEN);
	if (STREAM_WRITEABLE(adapter->obuf_work) < msg_size) {
		stream_fifo_push(adapter->obuf_fifo, adapter->obuf_work);
		adapter->obuf_work = stream_new(MGMTD_BE_MSG_MAX_LEN);
	}
	stream_write(adapter->obuf_work, (void *)msg_buf, msg_size);

	mgmt_be_adapter_sched_msg_write(adapter);
	adapter->num_msg_tx++;
	return 0;
}

static int mgmt_be_send_txn_req(struct mgmt_be_client_adapter *adapter,
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

	MGMTD_BE_ADAPTER_DBG(
		"Sending TXN_REQ message to Backend client '%s' for Txn-Id %llx",
		adapter->name, (unsigned long long)txn_id);

	return mgmt_be_adapter_send_msg(adapter, &be_msg);
}

static int
mgmt_be_send_cfgdata_create_req(struct mgmt_be_client_adapter *adapter,
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
		"Sending CFGDATA_CREATE_REQ message to Backend client '%s' for Txn-Id %llx, Batch-Id: %llx",
		adapter->name, (unsigned long long)txn_id,
		(unsigned long long)batch_id);

	return mgmt_be_adapter_send_msg(adapter, &be_msg);
}

static int mgmt_be_send_cfgapply_req(struct mgmt_be_client_adapter *adapter,
					uint64_t txn_id)
{
	Mgmtd__BeMessage be_msg;
	Mgmtd__BeCfgDataApplyReq apply_req;

	mgmtd__be_cfg_data_apply_req__init(&apply_req);
	apply_req.txn_id = txn_id;

	mgmtd__be_message__init(&be_msg);
	be_msg.message_case = MGMTD__BE_MESSAGE__MESSAGE_CFG_APPLY_REQ;
	be_msg.cfg_apply_req = &apply_req;

	MGMTD_BE_ADAPTER_DBG(
		"Sending CFG_APPLY_REQ message to Backend client '%s' for Txn-Id 0x%llx",
		adapter->name, (unsigned long long)txn_id);

	return mgmt_be_adapter_send_msg(adapter, &be_msg);
}

static uint16_t
mgmt_be_adapter_process_msg(struct mgmt_be_client_adapter *adapter,
			       uint8_t *msg_buf, uint16_t bytes_read)
{
	Mgmtd__BeMessage *be_msg;
	struct mgmt_be_msg *msg;
	uint16_t bytes_left;
	uint16_t processed = 0;

	bytes_left = bytes_read;
	for (; bytes_left > MGMTD_BE_MSG_HDR_LEN;
	     bytes_left -= msg->hdr.len, msg_buf += msg->hdr.len) {
		msg = (struct mgmt_be_msg *)msg_buf;
		if (msg->hdr.marker != MGMTD_BE_MSG_MARKER) {
			MGMTD_BE_ADAPTER_DBG(
				"Marker not found in message from MGMTD Backend adapter '%s'",
				adapter->name);
			break;
		}

		if (bytes_left < msg->hdr.len) {
			MGMTD_BE_ADAPTER_DBG(
				"Incomplete message of %d bytes (epxected: %u) from MGMTD Backend adapter '%s'",
				bytes_left, msg->hdr.len, adapter->name);
			break;
		}

		be_msg = mgmtd__be_message__unpack(
			NULL, (size_t)(msg->hdr.len - MGMTD_BE_MSG_HDR_LEN),
			msg->payload);
		if (!be_msg) {
			MGMTD_BE_ADAPTER_DBG(
				"Failed to decode %d bytes from MGMTD Backend adapter '%s'",
				msg->hdr.len, adapter->name);
			continue;
		}

		(void)mgmt_be_adapter_handle_msg(adapter, be_msg);
		mgmtd__be_message__free_unpacked(be_msg, NULL);
		processed++;
		adapter->num_msg_rx++;
	}

	return processed;
}

static void mgmt_be_adapter_proc_msgbufs(struct thread *thread)
{
	struct mgmt_be_client_adapter *adapter;
	struct stream *work;
	int processed = 0;

	adapter = (struct mgmt_be_client_adapter *)THREAD_ARG(thread);
	assert(adapter);

	if (adapter->conn_fd < 0)
		return;

	for (; processed < MGMTD_BE_MAX_NUM_MSG_PROC;) {
		work = stream_fifo_pop_safe(adapter->ibuf_fifo);
		if (!work)
			break;

		processed += mgmt_be_adapter_process_msg(
			adapter, STREAM_DATA(work), stream_get_endp(work));

		if (work != adapter->ibuf_work) {
			/* Free it up */
			stream_free(work);
		} else {
			/* Reset stream buffer for next read */
			stream_reset(work);
		}
	}

	/*
	 * If we have more to process, reschedule for processing it.
	 */
	if (stream_fifo_head(adapter->ibuf_fifo))
		mgmt_be_adapter_register_event(adapter, MGMTD_BE_PROC_MSG);
}

static void mgmt_be_adapter_read(struct thread *thread)
{
	struct mgmt_be_client_adapter *adapter;
	int bytes_read, msg_cnt;
	size_t total_bytes, bytes_left;
	struct mgmt_be_msg_hdr *msg_hdr;
	bool incomplete = false;

	adapter = (struct mgmt_be_client_adapter *)THREAD_ARG(thread);
	assert(adapter && adapter->conn_fd >= 0);

	total_bytes = 0;
	bytes_left = STREAM_SIZE(adapter->ibuf_work) -
		     stream_get_endp(adapter->ibuf_work);
	for (; bytes_left > MGMTD_BE_MSG_HDR_LEN;) {
		bytes_read = stream_read_try(adapter->ibuf_work,
					     adapter->conn_fd, bytes_left);
		MGMTD_BE_ADAPTER_DBG(
			"Got %d bytes of message from MGMTD Backend adapter '%s'",
			bytes_read, adapter->name);
		if (bytes_read <= 0) {
			if (bytes_read == -1
			    && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				mgmt_be_adapter_register_event(
					adapter, MGMTD_BE_CONN_READ);
				return;
			}

			if (!bytes_read) {
				/* Looks like connection closed */
				MGMTD_BE_ADAPTER_ERR(
					"Got error (%d) while reading from MGMTD Backend adapter '%s'. Err: '%s'",
					bytes_read, adapter->name,
					safe_strerror(errno));
				mgmt_be_adapter_disconnect(adapter);
				return;
			}
			break;
		}

		total_bytes += bytes_read;
		bytes_left -= bytes_read;
	}

	/*
	 * Check if we would have read incomplete messages or not.
	 */
	stream_set_getp(adapter->ibuf_work, 0);
	total_bytes = 0;
	msg_cnt = 0;
	bytes_left = stream_get_endp(adapter->ibuf_work);
	for (; bytes_left > MGMTD_BE_MSG_HDR_LEN;) {
		msg_hdr =
			(struct mgmt_be_msg_hdr *)(STREAM_DATA(
							      adapter->ibuf_work)
						      + total_bytes);
		if (msg_hdr->marker != MGMTD_BE_MSG_MARKER) {
			/* Corrupted buffer. Force disconnect?? */
			MGMTD_BE_ADAPTER_ERR(
				"Received corrupted buffer from MGMTD Backend client.");
			mgmt_be_adapter_disconnect(adapter);
			return;
		}
		if (msg_hdr->len > bytes_left)
			break;

		total_bytes += msg_hdr->len;
		bytes_left -= msg_hdr->len;
		msg_cnt++;
	}

	if (bytes_left > 0)
		incomplete = true;

	/*
	 * We would have read one or several messages.
	 * Schedule processing them now.
	 */
	msg_hdr = (struct mgmt_be_msg_hdr *)(STREAM_DATA(adapter->ibuf_work)
						+ total_bytes);
	stream_set_endp(adapter->ibuf_work, total_bytes);
	stream_fifo_push(adapter->ibuf_fifo, adapter->ibuf_work);
	adapter->ibuf_work = stream_new(MGMTD_BE_MSG_MAX_LEN);
	if (incomplete) {
		stream_put(adapter->ibuf_work, msg_hdr, bytes_left);
		stream_set_endp(adapter->ibuf_work, bytes_left);
	}

	if (msg_cnt)
		mgmt_be_adapter_register_event(adapter, MGMTD_BE_PROC_MSG);

	mgmt_be_adapter_register_event(adapter, MGMTD_BE_CONN_READ);
}

static void mgmt_be_adapter_write(struct thread *thread)
{
	int bytes_written = 0;
	int processed = 0;
	int msg_size = 0;
	struct stream *s = NULL;
	struct stream *free = NULL;
	struct mgmt_be_client_adapter *adapter;

	adapter = (struct mgmt_be_client_adapter *)THREAD_ARG(thread);
	assert(adapter && adapter->conn_fd >= 0);

	/* Ensure pushing any pending write buffer to FIFO */
	if (adapter->obuf_work) {
		stream_fifo_push(adapter->obuf_fifo, adapter->obuf_work);
		adapter->obuf_work = NULL;
	}

	for (s = stream_fifo_head(adapter->obuf_fifo);
	     s && processed < MGMTD_BE_MAX_NUM_MSG_WRITE;
	     s = stream_fifo_head(adapter->obuf_fifo)) {
		/* msg_size = (int)stream_get_size(s); */
		msg_size = (int)STREAM_READABLE(s);
		bytes_written = stream_flush(s, adapter->conn_fd);
		if (bytes_written == -1
		    && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			mgmt_be_adapter_register_event(adapter,
							MGMTD_BE_CONN_WRITE);
			return;
		} else if (bytes_written != msg_size) {
			MGMTD_BE_ADAPTER_ERR(
				"Could not write all %d bytes (wrote: %d) to MGMTD Backend client socket. Err: '%s'",
				msg_size, bytes_written, safe_strerror(errno));
			if (bytes_written > 0) {
				stream_forward_getp(s, (size_t)bytes_written);
				stream_pulldown(s);
				mgmt_be_adapter_register_event(
					adapter, MGMTD_BE_CONN_WRITE);
				return;
			}
			mgmt_be_adapter_disconnect(adapter);
			return;
		}

		free = stream_fifo_pop(adapter->obuf_fifo);
		stream_free(free);
		MGMTD_BE_ADAPTER_DBG(
			"Wrote %d bytes of message to MGMTD Backend client socket.'",
			bytes_written);
		processed++;
	}

	if (s) {
		mgmt_be_adapter_writes_off(adapter);
		mgmt_be_adapter_register_event(adapter,
						MGMTD_BE_CONN_WRITES_ON);
	}
}

static void mgmt_be_adapter_resume_writes(struct thread *thread)
{
	struct mgmt_be_client_adapter *adapter;

	adapter = (struct mgmt_be_client_adapter *)THREAD_ARG(thread);
	assert(adapter && adapter->conn_fd >= 0);

	mgmt_be_adapter_writes_on(adapter);
}

static void mgmt_be_iter_and_get_cfg(struct mgmt_ds_ctx *ds_ctx,
					char *xpath, struct lyd_node *node,
					struct nb_node *nb_node, void *ctx)
{
	struct mgmt_be_client_subscr_info subscr_info;
	struct mgmt_be_get_adapter_config_params *parms;
	struct mgmt_be_client_adapter *adapter;
	struct nb_config_cbs *root;
	uint32_t *seq;

	if (mgmt_be_get_subscr_info_for_xpath(xpath, &subscr_info) != 0) {
		MGMTD_BE_ADAPTER_ERR(
			"ERROR: Failed to get subscriber for '%s'", xpath);
		return;
	}

	parms = (struct mgmt_be_get_adapter_config_params *)ctx;

	adapter = parms->adapter;
	if (!subscr_info.xpath_subscr[adapter->id].subscribed)
		return;

	root = parms->cfg_chgs;
	seq = &parms->seq;
	nb_config_diff_created(node, seq, root);
}

static void mgmt_be_adapter_conn_init(struct thread *thread)
{
	struct mgmt_be_client_adapter *adapter;

	adapter = (struct mgmt_be_client_adapter *)THREAD_ARG(thread);
	assert(adapter && adapter->conn_fd >= 0);

	/*
	 * TODO: Check first if the current session can run a CONFIG
	 * transaction or not. Reschedule if a CONFIG transaction
	 * from another session is already in progress.
	if (mgmt_config_txn_in_progress() != MGMTD_SESSION_ID_NONE) {
		mgmt_be_adapter_register_event(adapter, MGMTD_BE_CONN_INIT);
		return 0;
	}
	 */

    /*
     * TODO: Notify TXN module to create a CONFIG transaction and
     * download the CONFIGs identified for this new client.
     * If the TXN module fails to initiate the CONFIG transaction
     * disconnect from the client forcing a reconnect later.
     * That should also take care of destroying the adapter.
     *
	if (mgmt_txn_notify_be_adapter_conn(adapter, true) != 0) {
		mgmt_be_adapter_disconnect(adapter);
		adapter = NULL;
	}
     */
}

static void
mgmt_be_adapter_register_event(struct mgmt_be_client_adapter *adapter,
				enum mgmt_be_event event)
{
	struct timeval tv = {0};

	switch (event) {
	case MGMTD_BE_CONN_INIT:
		thread_add_timer_msec(mgmt_be_adapter_tm,
				      mgmt_be_adapter_conn_init, adapter,
				      MGMTD_BE_CONN_INIT_DELAY_MSEC,
				      &adapter->conn_init_ev);
		assert(adapter->conn_init_ev);
		break;
	case MGMTD_BE_CONN_READ:
		thread_add_read(mgmt_be_adapter_tm, mgmt_be_adapter_read,
				adapter, adapter->conn_fd, &adapter->conn_read_ev);
		assert(adapter->conn_read_ev);
		break;
	case MGMTD_BE_CONN_WRITE:
		thread_add_write(mgmt_be_adapter_tm, mgmt_be_adapter_write,
				 adapter, adapter->conn_fd, &adapter->conn_write_ev);
		assert(adapter->conn_write_ev);
		break;
	case MGMTD_BE_PROC_MSG:
		tv.tv_usec = MGMTD_BE_MSG_PROC_DELAY_USEC;
		thread_add_timer_tv(mgmt_be_adapter_tm,
				    mgmt_be_adapter_proc_msgbufs, adapter, &tv,
				    &adapter->proc_msg_ev);
		assert(adapter->proc_msg_ev);
		break;
	case MGMTD_BE_CONN_WRITES_ON:
		thread_add_timer_msec(mgmt_be_adapter_tm,
				      mgmt_be_adapter_resume_writes, adapter,
				      MGMTD_BE_MSG_WRITE_DELAY_MSEC,
				      &adapter->conn_writes_on);
		assert(adapter->conn_writes_on);
		break;
	case MGMTD_BE_SERVER:
	case MGMTD_BE_SCHED_CFG_PREPARE:
	case MGMTD_BE_RESCHED_CFG_PREPARE:
	case MGMTD_BE_SCHED_CFG_APPLY:
	case MGMTD_BE_RESCHED_CFG_APPLY:
		assert(!"mgmt_be_adapter_post_event() called incorrectly");
		break;
	}
}

void mgmt_be_adapter_lock(struct mgmt_be_client_adapter *adapter)
{
	adapter->refcount++;
}

extern void mgmt_be_adapter_unlock(struct mgmt_be_client_adapter **adapter)
{
	assert(*adapter && (*adapter)->refcount);

	(*adapter)->refcount--;
	if (!(*adapter)->refcount) {
		mgmt_be_adapters_del(&mgmt_be_adapters, *adapter);

		stream_fifo_free((*adapter)->ibuf_fifo);
		stream_free((*adapter)->ibuf_work);
		stream_fifo_free((*adapter)->obuf_fifo);
		stream_free((*adapter)->obuf_work);

		THREAD_OFF((*adapter)->conn_init_ev);
		THREAD_OFF((*adapter)->conn_read_ev);
		THREAD_OFF((*adapter)->conn_write_ev);
		THREAD_OFF((*adapter)->conn_writes_on);
		THREAD_OFF((*adapter)->proc_msg_ev);
		XFREE(MTYPE_MGMTD_BE_ADPATER, *adapter);
	}

	*adapter = NULL;
}

int mgmt_be_adapter_init(struct thread_master *tm)
{
	if (!mgmt_be_adapter_tm) {
		mgmt_be_adapter_tm = tm;
		memset(mgmt_xpath_map, 0, sizeof(mgmt_xpath_map));
		mgmt_num_xpath_maps = 0;
		memset(mgmt_be_adapters_by_id, 0,
		       sizeof(mgmt_be_adapters_by_id));
		mgmt_be_adapters_init(&mgmt_be_adapters);
		mgmt_be_xpath_map_init();
	}

	return 0;
}

void mgmt_be_adapter_destroy(void)
{
	mgmt_be_cleanup_adapters();
}

struct mgmt_be_client_adapter *
mgmt_be_create_adapter(int conn_fd, union sockunion *from)
{
	struct mgmt_be_client_adapter *adapter = NULL;

	adapter = mgmt_be_find_adapter_by_fd(conn_fd);
	if (!adapter) {
		adapter = XCALLOC(MTYPE_MGMTD_BE_ADPATER,
				sizeof(struct mgmt_be_client_adapter));
		assert(adapter);

		adapter->conn_fd = conn_fd;
		adapter->id = MGMTD_BE_CLIENT_ID_MAX;
		memcpy(&adapter->conn_su, from, sizeof(adapter->conn_su));
		snprintf(adapter->name, sizeof(adapter->name), "Unknown-FD-%d",
			 adapter->conn_fd);
		adapter->ibuf_fifo = stream_fifo_new();
		adapter->ibuf_work = stream_new(MGMTD_BE_MSG_MAX_LEN);
		adapter->obuf_fifo = stream_fifo_new();
		/* adapter->obuf_work = stream_new(MGMTD_BE_MSG_MAX_LEN); */
		adapter->obuf_work = NULL;
		mgmt_be_adapter_lock(adapter);

		mgmt_be_adapter_register_event(adapter, MGMTD_BE_CONN_READ);
		mgmt_be_adapters_add_tail(&mgmt_be_adapters, adapter);

		RB_INIT(nb_config_cbs, &adapter->cfg_chgs);

		MGMTD_BE_ADAPTER_DBG("Added new MGMTD Backend adapter '%s'",
				      adapter->name);
	}

	/* Make client socket non-blocking.  */
	set_nonblocking(adapter->conn_fd);
	setsockopt_so_sendbuf(adapter->conn_fd, MGMTD_SOCKET_BE_SEND_BUF_SIZE);
	setsockopt_so_recvbuf(adapter->conn_fd, MGMTD_SOCKET_BE_RECV_BUF_SIZE);

	/* Trigger resync of config with the new adapter */
	mgmt_be_adapter_register_event(adapter, MGMTD_BE_CONN_INIT);

	return adapter;
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
				  struct mgmt_ds_ctx *ds_ctx,
				  struct nb_config_cbs **cfg_chgs)
{
	char base_xpath[] = "/";
	struct mgmt_be_get_adapter_config_params parms;

	assert(cfg_chgs);

	if (RB_EMPTY(nb_config_cbs, &adapter->cfg_chgs)) {
		parms.adapter = adapter;
		parms.cfg_chgs = &adapter->cfg_chgs;
		parms.seq = 0;

		mgmt_ds_iter_data(ds_ctx, base_xpath,
				  mgmt_be_iter_and_get_cfg, (void *)&parms,
				  false);
	}

	*cfg_chgs = &adapter->cfg_chgs;
	return 0;
}

int mgmt_be_create_txn(struct mgmt_be_client_adapter *adapter,
			   uint64_t txn_id)
{
	return mgmt_be_send_txn_req(adapter, txn_id, true);
}

int mgmt_be_destroy_txn(struct mgmt_be_client_adapter *adapter,
			    uint64_t txn_id)
{
	return mgmt_be_send_txn_req(adapter, txn_id, false);
}

int mgmt_be_send_cfg_data_create_req(struct mgmt_be_client_adapter *adapter,
					uint64_t txn_id, uint64_t batch_id,
					struct mgmt_be_cfgreq *cfg_req,
					bool end_of_data)
{
	return mgmt_be_send_cfgdata_create_req(
		adapter, txn_id, batch_id, cfg_req->cfgdata_reqs,
		cfg_req->num_reqs, end_of_data);
}

extern int
mgmt_be_send_cfg_apply_req(struct mgmt_be_client_adapter *adapter,
			      uint64_t txn_id)
{
	return mgmt_be_send_cfgapply_req(adapter, txn_id);
}

/*
 * This function maps a YANG dtata Xpath to one or more
 * Backend Clients that should be contacted for various purposes.
 */
int mgmt_be_get_subscr_info_for_xpath(
	const char *xpath, struct mgmt_be_client_subscr_info *subscr_info)
{
	int indx, match, max_match = 0, num_reg;
	enum mgmt_be_client_id id;
	struct mgmt_be_client_subscr_info
		*reg_maps[array_size(mgmt_xpath_map)] = {0};
	bool root_xp = false;

	if (!subscr_info)
		return -1;

	num_reg = 0;
	memset(subscr_info, 0, sizeof(*subscr_info));

	if (strlen(xpath) <= 2 && xpath[0] == '/'
		&& (!xpath[1] || xpath[1] == '*')) {
		root_xp = true;
	}

	MGMTD_BE_ADAPTER_DBG("XPATH: %s", xpath);
	for (indx = 0; indx < mgmt_num_xpath_maps; indx++) {
		/*
		 * For Xpaths: '/' and '/ *' all xpath maps should match
		 * the given xpath.
		 */
		if (!root_xp) {
			match = mgmt_be_eval_regexp_match(
				mgmt_xpath_map[indx].xpath_regexp, xpath);

			if (!match || match < max_match)
				continue;

			if (match > max_match) {
				num_reg = 0;
				max_match = match;
			}
		}

		reg_maps[num_reg] = &mgmt_xpath_map[indx].be_subscrs;
		num_reg++;
	}

	for (indx = 0; indx < num_reg; indx++) {
		FOREACH_MGMTD_BE_CLIENT_ID (id) {
			if (reg_maps[indx]->xpath_subscr[id].subscribed) {
				MGMTD_BE_ADAPTER_DBG(
					"Cient: %s",
					mgmt_be_client_id2name(id));
				memcpy(&subscr_info->xpath_subscr[id],
				       &reg_maps[indx]->xpath_subscr[id],
				       sizeof(subscr_info->xpath_subscr[id]));
			}
		}
	}

	return 0;
}

void mgmt_be_adapter_status_write(struct vty *vty)
{
	struct mgmt_be_client_adapter *adapter;

	vty_out(vty, "MGMTD Backend Adapters\n");

	FOREACH_ADAPTER_IN_LIST (adapter) {
		vty_out(vty, "  Client: \t\t\t%s\n", adapter->name);
		vty_out(vty, "    Conn-FD: \t\t\t%d\n", adapter->conn_fd);
		vty_out(vty, "    Client-Id: \t\t\t%d\n", adapter->id);
		vty_out(vty, "    Ref-Count: \t\t\t%u\n", adapter->refcount);
		vty_out(vty, "    Msg-Sent: \t\t\t%u\n", adapter->num_msg_tx);
		vty_out(vty, "    Msg-Recvd: \t\t\t%u\n", adapter->num_msg_rx);
	}
	vty_out(vty, "  Total: %d\n",
		(int)mgmt_be_adapters_count(&mgmt_be_adapters));
}

void mgmt_be_xpath_register_write(struct vty *vty)
{
	int indx;
	enum mgmt_be_client_id id;
	struct mgmt_be_client_adapter *adapter;

	vty_out(vty, "MGMTD Backend XPath Registry\n");

	for (indx = 0; indx < mgmt_num_xpath_maps; indx++) {
		vty_out(vty, " - XPATH: '%s'\n",
			mgmt_xpath_map[indx].xpath_regexp);
		FOREACH_MGMTD_BE_CLIENT_ID (id) {
			if (mgmt_xpath_map[indx]
				    .be_subscrs.xpath_subscr[id]
				    .subscribed) {
				vty_out(vty,
					"   -- Client: '%s' \t Validate:%s, Notify:%s, Own:%s\n",
					mgmt_be_client_id2name(id),
					mgmt_xpath_map[indx]
							.be_subscrs
							.xpath_subscr[id]
							.validate_config
						? "T"
						: "F",
					mgmt_xpath_map[indx]
							.be_subscrs
							.xpath_subscr[id]
							.notify_config
						? "T"
						: "F",
					mgmt_xpath_map[indx]
							.be_subscrs
							.xpath_subscr[id]
							.own_oper_data
						? "T"
						: "F");
				adapter = mgmt_be_get_adapter_by_id(id);
				if (adapter) {
					vty_out(vty, "     -- Adapter: %p\n",
						adapter);
				}
			}
		}
	}

	vty_out(vty, "Total XPath Registries: %u\n", mgmt_num_xpath_maps);
}

void mgmt_be_xpath_subscr_info_write(struct vty *vty, const char *xpath)
{
	struct mgmt_be_client_subscr_info subscr;
	enum mgmt_be_client_id id;
	struct mgmt_be_client_adapter *adapter;

	if (mgmt_be_get_subscr_info_for_xpath(xpath, &subscr) != 0) {
		vty_out(vty, "ERROR: Failed to get subscriber for '%s'\n",
			xpath);
		return;
	}

	vty_out(vty, "XPath: '%s'\n", xpath);
	FOREACH_MGMTD_BE_CLIENT_ID (id) {
		if (subscr.xpath_subscr[id].subscribed) {
			vty_out(vty,
				"  -- Client: '%s' \t Validate:%s, Notify:%s, Own:%s\n",
				mgmt_be_client_id2name(id),
				subscr.xpath_subscr[id].validate_config ? "T"
									: "F",
				subscr.xpath_subscr[id].notify_config ? "T"
								      : "F",
				subscr.xpath_subscr[id].own_oper_data ? "T"
								      : "F");
			adapter = mgmt_be_get_adapter_by_id(id);
			if (adapter)
				vty_out(vty, "    -- Adapter: %p\n", adapter);
		}
	}
}
