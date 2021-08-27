/*
 * CMGD Backend Client Connection Adapter
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
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

#include "thread.h"
#include "sockopt.h"
#include "sockunion.h"
#include "prefix.h"
#include "network.h"
#include "lib/libfrr.h"
#include "lib/thread.h"
#include "cmgd/cmgd.h"
#include "cmgd/cmgd_memory.h"
#include "lib/cmgd_bcknd_client.h"
#include "cmgd/cmgd_bcknd_adapter.h"
#include "lib/cmgd_pb.h"
#include "lib/vty.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define CMGD_BCKND_ADPTR_DBG(fmt, ...)				\
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define CMGD_BCKND_ADPTR_ERR(fmt, ...)				\
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define CMGD_BCKND_ADPTR_DBG(fmt, ...)				\
	if (cmgd_debug_bcknd)					\
		zlog_err("%s: " fmt , __func__, ##__VA_ARGS__)
#define CMGD_BCKND_ADPTR_ERR(fmt, ...)				\
	zlog_err("%s: ERROR: " fmt , __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

#define FOREACH_ADPTR_IN_LIST(adptr)						\
	for ((adptr) = cmgd_bcknd_adptr_list_first(&cmgd_bcknd_adptrs); (adptr);\
		(adptr) = cmgd_bcknd_adptr_list_next(&cmgd_bcknd_adptrs, (adptr)))

/* 
 * Static mapping of YANG XPath regular expressions and 
 * the corresponding interested backend clients. 
 * NOTE: Thiis is a static mapping defined by all CMGD 
 * backend client modules (for now, till we develop a 
 * more dynamic way of creating and updating this map).
 * A running map is created by CMGD in run-time to 
 * handle real-time mapping of YANG xpaths to one or 
 * more interested backend client adapters.
 * 
 * Please see xpath_map_reg[] in lib/cmgd_bcknd_client.c
 * for the actual map
 */
typedef struct cmgd_bcknd_xpath_map_reg_ {
	const char *xpath_regexp;  /* Longest matching regular expression */
        uint8_t num_clients;    /* Number of clients */
	const char *bcknd_clients[CMGD_BCKND_MAX_CLIENTS_PER_XPATH_REG];  /* List of clients */
} cmgd_bcknd_xpath_map_reg_t;

typedef struct cmgd_bcknd_xpath_regexp_map_ {
	const char *xpath_regexp;
	cmgd_bcknd_client_subscr_info_t bcknd_subscrs;
} cmgd_bcknd_xpath_regexp_map_t;

/* 
 * Static mapping of YANG XPath regular expressions and 
 * the corresponding interested backend clients. 
 * NOTE: Thiis is a static mapping defined by all CMGD 
 * backend client modules (for now, till we develop a 
 * more dynamic way of creating and updating this map).
 * A running map is created by CMGD in run-time to 
 * handle real-time mapping of YANG xpaths to one or 
 * more interested backend client adapters.
 */
static const cmgd_bcknd_xpath_map_reg_t xpath_static_map_reg[] = {
	{
		.xpath_regexp = "/frr-interface:lib/*",
		.num_clients = 2,
		.bcknd_clients = {
			CMGD_BCKND_CLIENT_STATICD,
			CMGD_BCKND_CLIENT_BGPD
		}
	},
	{
		.xpath_regexp = 
			"/frr-routing:routing/control-plane-protocols/"
			"control-plane-protocol[type='frr-staticd:staticd']"
			"[name='staticd'][vrf='default']/frr-staticd:staticd/*",
		.num_clients = 1,
		.bcknd_clients = {
			CMGD_BCKND_CLIENT_STATICD
		}
	},
	{
		.xpath_regexp = 
			"/frr-routing:routing/control-plane-protocols/"
			"control-plane-protocol[type='frr-bgp:bgp']"
			"[name='bgp'][vrf='default']/frr-bgp:bgp/*",
		.num_clients = 1,
		.bcknd_clients = {
			CMGD_BCKND_CLIENT_BGPD
		}
	}
};

#define CMGD_BCKND_MAX_NUM_XPATH_MAP	256
static cmgd_bcknd_xpath_regexp_map_t 
	cmgd_xpath_map[CMGD_BCKND_MAX_NUM_XPATH_MAP] = { 0 };
static int cmgd_num_xpath_maps = 0;

static struct thread_master *cmgd_bcknd_adptr_tm = NULL;

static struct cmgd_bcknd_adptr_list_head cmgd_bcknd_adptrs = {0};

static cmgd_bcknd_client_adapter_t *cmgd_bcknd_adptrs_by_id[CMGD_BCKND_CLIENT_ID_MAX] = { 0 };

/* Forward declarations */
static void cmgd_bcknd_adptr_register_event(
	cmgd_bcknd_client_adapter_t *adptr, cmgd_event_t event);

static cmgd_bcknd_client_adapter_t *cmgd_bcknd_find_adapter_by_fd(int conn_fd)
{
	cmgd_bcknd_client_adapter_t *adptr;

	FOREACH_ADPTR_IN_LIST(adptr) {
		if (adptr->conn_fd == conn_fd) 
			return adptr;
	}

	return NULL;
}

static cmgd_bcknd_client_adapter_t *cmgd_bcknd_find_adapter_by_name(const char *name)
{
	cmgd_bcknd_client_adapter_t *adptr;

	FOREACH_ADPTR_IN_LIST(adptr) {
		if (!strncmp(adptr->name, name, sizeof(adptr->name)))
			return adptr;
	}

	return NULL;
}

static void cmgd_bcknd_xpath_map_init(void)
{
        int indx, num_xpath_maps;
        uint16_t indx1;
        cmgd_bcknd_client_id_t id;

	CMGD_BCKND_ADPTR_DBG("Init XPath Maps");

	num_xpath_maps = (int) array_size(xpath_static_map_reg);
        for (indx = 0; indx < num_xpath_maps; indx++) {
		CMGD_BCKND_ADPTR_DBG(" - XPATH: '%s'",
				xpath_static_map_reg[indx].xpath_regexp);
                cmgd_xpath_map[indx].xpath_regexp = 
                        xpath_static_map_reg[indx].xpath_regexp;
                for (indx1 = 0;
                        indx1 < xpath_static_map_reg[indx].num_clients;
                        indx1++) {
                        id  = cmgd_bknd_client_name2id(
                                xpath_static_map_reg[indx].bcknd_clients[indx1]);
			CMGD_BCKND_ADPTR_DBG("   -- Client: '%s' --> Id: %u",
				xpath_static_map_reg[indx].bcknd_clients[indx1], id);
                        if (id < CMGD_BCKND_CLIENT_ID_MAX) {
                        	cmgd_xpath_map[indx].bcknd_subscrs.
			      		xpath_subscr[id].validate_config = 1;
                        	cmgd_xpath_map[indx].bcknd_subscrs.
			      		xpath_subscr[id].notify_config = 1;
                        	cmgd_xpath_map[indx].bcknd_subscrs.
			      		xpath_subscr[id].own_oper_data = 1;
                        }
                }
        }

	cmgd_num_xpath_maps = indx;
	CMGD_BCKND_ADPTR_DBG("Total XPath Maps: %u", cmgd_num_xpath_maps);
}

static int cmgd_bcknd_eval_regexp_match(
	const char *xpath_regexp, const char *xpath)
{
	int match_len = 0, re_indx = 0, xp_indx = 0;
	int rexp_len, xpath_len;
	bool match = true, re_wild = false, xp_wild = false;
	bool key = false, incr_re = false, incr_xp = false;
	// char re_str[1024], xp_str[1024];

	rexp_len = strlen(xpath_regexp);
	xpath_len = strlen(xpath);
	// memset(re_str, 0, sizeof(re_str));
	// memset(xp_str, 0, sizeof(xp_str));

	if (!rexp_len || !xpath_len)
		return 0;

	// CMGD_BCKND_ADPTR_DBG(" REGEXP: '%s'", xpath_regexp);

	for (re_indx = 0, xp_indx = 0;
	     match && re_indx < rexp_len && xp_indx < xpath_len; ) {
		incr_re = true;
		incr_xp = true;

		// re_str[re_indx] = xpath_regexp[re_indx];
		// xp_str[xp_indx] = xpath[xp_indx];
		// CMGD_BCKND_ADPTR_DBG("'%s' || '%s'", re_str, xp_str);

		if (!key && xpath_regexp[re_indx] == '\'' && xpath[xp_indx] == '\'')
			key = key ? false : true;
		if (key && xpath_regexp[re_indx] == '*' && xpath[xp_indx] != '*') {
			incr_re = false;
			re_wild = true;
		} else if (key && xpath_regexp[re_indx] != '*' && xpath[xp_indx] == '*') {
			incr_xp = false;
			xp_wild = true;
		}

		match = (xp_wild || re_wild ||
			xpath_regexp[re_indx] == xpath[xp_indx]);

		if (match && re_indx && xp_indx &&
			((xpath_regexp[re_indx-1] == '/' && xpath[xp_indx-1] == '/') ||
			(xpath_regexp[re_indx-1] == '[' && xpath[xp_indx-1] == '[') ||
			(xpath_regexp[re_indx-1] == ']' && xpath[xp_indx-1] == '[')))
			match_len++;

		if (key && re_wild && xpath[xp_indx+1] == '\'') {
			re_wild = false;
			incr_re = true;
		}
		if (key && xp_wild && xpath_regexp[re_indx+1] == '\'') {
			xp_wild = false;
			incr_xp = true;
		}

		// CMGD_BCKND_ADPTR_DBG("K:%d, RI:%d, RX:%d, RW:%d, XW:%d, M:%d, IR: %d, IX:%d",
		// 	key, re_indx, xp_indx, re_wild, xp_wild, match, incr_re, incr_xp);

		if (incr_re)
			re_indx++;
		if (incr_xp)
			xp_indx++;
	}

	if (match) {
		match_len++;
	}

	// CMGD_BCKND_ADPTR_DBG(" - REGEXP: %s, Match: %d",
	// 	xpath_regexp, match_len);
	return match_len;
}

static void cmgd_bcknd_adapter_disconnect(cmgd_bcknd_client_adapter_t *adptr)
{
	if (adptr->conn_fd) {
		close(adptr->conn_fd);
		adptr->conn_fd = 0;
	}

	/* TODO: notify about client disconnect for appropriate cleanup */
	if (adptr->id < CMGD_BCKND_CLIENT_ID_MAX) {
		cmgd_bcknd_adptrs_by_id[adptr->id] = NULL;
		adptr->id = CMGD_BCKND_CLIENT_ID_MAX;
	}

	cmgd_bcknd_adptr_list_del(&cmgd_bcknd_adptrs, adptr);

	cmgd_bcknd_adapter_unlock(&adptr);
}

static void cmgd_bcknd_adapter_cleanup_old_conn(
	cmgd_bcknd_client_adapter_t *adptr)
{
	cmgd_bcknd_client_adapter_t *old;

	FOREACH_ADPTR_IN_LIST(old) {
		if (old != adptr &&
			!strncmp(adptr->name, old->name, sizeof(adptr->name))) {
			/*
			 * We have a Zombie lingering around
			 */
			CMGD_BCKND_ADPTR_DBG(
				"Client '%s' (FD:%d) seems to have reconnected. Removing old connection (FD:%d)!",
				adptr->name, adptr->conn_fd, old->conn_fd);
			cmgd_bcknd_adapter_disconnect(old);
		}
	}
}

static int cmgd_bcknd_adapter_handle_msg(
	cmgd_bcknd_client_adapter_t *adptr, Cmgd__BckndMessage *bcknd_msg)
{

	switch(bcknd_msg->type) {
	case CMGD__BCKND_MESSAGE__TYPE__SUBSCRIBE_REQ:
		assert(bcknd_msg->message_case == CMGD__BCKND_MESSAGE__MESSAGE_SUBSCR_REQ);
		CMGD_BCKND_ADPTR_DBG(
			"Got Subscribe Req Msg from '%s' to %sregister %u xpaths", 
			bcknd_msg->subscr_req->client_name, 
			!bcknd_msg->subscr_req->subscribe_xpaths && 
			bcknd_msg->subscr_req->n_xpath_reg ? "de" : "", 
			(uint32_t)bcknd_msg->subscr_req->n_xpath_reg);

		if (strlen(bcknd_msg->subscr_req->client_name)) {
			strlcpy(adptr->name, bcknd_msg->subscr_req->client_name, 
				sizeof(adptr->name));
			adptr->id = cmgd_bknd_client_name2id(adptr->name);
			if (adptr->id >= CMGD_BCKND_CLIENT_ID_MAX) {
				CMGD_BCKND_ADPTR_ERR("Unable to resolve adapter '%s' to a valid ID. Disconnecting!",
					adptr->name);
				cmgd_bcknd_adapter_disconnect(adptr);
			}
			cmgd_bcknd_adptrs_by_id[adptr->id] = adptr;
			cmgd_bcknd_adapter_cleanup_old_conn(adptr);
		}
		break;
	case CMGD__BCKND_MESSAGE__TYPE__TRXN_REPLY:
		assert(bcknd_msg->message_case == CMGD__BCKND_MESSAGE__MESSAGE_TRXN_REPLY);
		CMGD_BCKND_ADPTR_DBG(
			"Got %s TRXN_REPLY Msg for Trxn-Id 0x%llx from '%s' with '%s'", 
			bcknd_msg->trxn_reply->create ? "Create" : "Delete", 
			bcknd_msg->trxn_reply->trxn_id, adptr->name,
			bcknd_msg->trxn_reply->success ? "success" : "failure");
		cmgd_trxn_notify_bcknd_trxn_reply(bcknd_msg->trxn_reply->trxn_id,
			bcknd_msg->trxn_reply->create,
			bcknd_msg->trxn_reply->success, adptr);
		break;
	case CMGD__BCKND_MESSAGE__TYPE__CFGDATA_CREATE_REPLY:
		assert(bcknd_msg->message_case == CMGD__BCKND_MESSAGE__MESSAGE_CFG_DATA_REPLY);
		CMGD_BCKND_ADPTR_DBG(
			"Got CFGDATA_REPLY Msg from '%s' for Trxn-Id 0x%llx Batch-Id 0x%llx with Err:'%s'", 
			adptr->name, bcknd_msg->cfg_data_reply->trxn_id,
			bcknd_msg->cfg_data_reply->batch_id,
			bcknd_msg->cfg_data_reply->error_if_any ?
				bcknd_msg->cfg_data_reply->error_if_any : "None");
		cmgd_trxn_notify_bcknd_cfgdata_reply(bcknd_msg->cfg_data_reply->trxn_id,
			bcknd_msg->cfg_data_reply->batch_id,
			bcknd_msg->cfg_data_reply->success,
			bcknd_msg->cfg_data_reply->error_if_any, adptr);
		break;
	case CMGD__BCKND_MESSAGE__TYPE__CFGDATA_VALIDATE_REPLY:
		assert(bcknd_msg->message_case == CMGD__BCKND_MESSAGE__MESSAGE_CFG_VALIDATE_REPLY);
		CMGD_BCKND_ADPTR_DBG(
			"Got %s CFG_VALIDATE_REPLY Msg from '%s' for Trxn-Id 0x%llx for %d batches (Id 0x%llx-0x%llx),  Err:'%s'", 
			bcknd_msg->cfg_validate_reply->success ?
				"successful" : "failed",
			adptr->name, bcknd_msg->cfg_validate_reply->trxn_id,
			(int) bcknd_msg->cfg_validate_reply->n_batch_ids,
			bcknd_msg->cfg_validate_reply->batch_ids[0],
			bcknd_msg->cfg_validate_reply->batch_ids
				[bcknd_msg->cfg_validate_reply->n_batch_ids-1],
			bcknd_msg->cfg_validate_reply->error_if_any ?
				bcknd_msg->cfg_validate_reply->error_if_any : "None");
		cmgd_trxn_notify_bcknd_cfg_validate_reply(bcknd_msg->cfg_validate_reply->trxn_id,
			bcknd_msg->cfg_validate_reply->success,
			(cmgd_trxn_batch_id_t *) bcknd_msg->
				cfg_validate_reply->batch_ids,
			bcknd_msg->cfg_validate_reply->n_batch_ids,
			bcknd_msg->cfg_validate_reply->error_if_any, adptr);
		break;
	case CMGD__BCKND_MESSAGE__TYPE__CFGDATA_APPLY_REPLY:
		assert(bcknd_msg->message_case == CMGD__BCKND_MESSAGE__MESSAGE_CFG_APPLY_REPLY);
		CMGD_BCKND_ADPTR_DBG(
			"Got %s CFG_APPLY_REPLY Msg from '%s' for Trxn-Id 0x%llx for %d batches (Id 0x%llx-0x%llx),  Err:'%s'", 
			bcknd_msg->cfg_apply_reply->success ?
				"successful" : "failed",
			adptr->name, bcknd_msg->cfg_apply_reply->trxn_id,
			(int) bcknd_msg->cfg_apply_reply->n_batch_ids,
			bcknd_msg->cfg_apply_reply->batch_ids[0],
			bcknd_msg->cfg_apply_reply->batch_ids
				[bcknd_msg->cfg_apply_reply->n_batch_ids-1],
			bcknd_msg->cfg_apply_reply->error_if_any ?
				bcknd_msg->cfg_apply_reply->error_if_any : "None");
		cmgd_trxn_notify_bcknd_cfg_apply_reply(bcknd_msg->cfg_apply_reply->trxn_id,
			bcknd_msg->cfg_apply_reply->success,
			(cmgd_trxn_batch_id_t *) bcknd_msg->
				cfg_apply_reply->batch_ids,
			bcknd_msg->cfg_apply_reply->n_batch_ids,
			bcknd_msg->cfg_apply_reply->error_if_any, adptr);
		break;
	default:
		break;
	}

	return 0;
}

static inline void cmgd_bcknd_adapter_sched_msg_write(cmgd_bcknd_client_adapter_t *adptr)
{
	if (!CHECK_FLAG(adptr->flags, CMGD_BCKND_ADPTR_FLAGS_WRITES_OFF))
		cmgd_bcknd_adptr_register_event(adptr, CMGD_BCKND_CONN_WRITE);
}

static inline void cmgd_bcknd_adapter_writes_on(cmgd_bcknd_client_adapter_t *adptr)
{
	CMGD_BCKND_ADPTR_DBG("Resume writing msgs for '%s'", adptr->name);
	UNSET_FLAG(adptr->flags, CMGD_BCKND_ADPTR_FLAGS_WRITES_OFF);
	if (adptr->obuf_work || stream_fifo_count_safe(adptr->obuf_fifo))
		cmgd_bcknd_adapter_sched_msg_write(adptr);
}

static inline void cmgd_bcknd_adapter_writes_off(cmgd_bcknd_client_adapter_t *adptr)
{
	SET_FLAG(adptr->flags, CMGD_BCKND_ADPTR_FLAGS_WRITES_OFF);
	CMGD_BCKND_ADPTR_DBG("Pause writing msgs for '%s'", adptr->name);
}

static int cmgd_bcknd_adapter_send_msg(cmgd_bcknd_client_adapter_t *adptr, 
	Cmgd__BckndMessage *bcknd_msg)
{
	size_t msg_size;
	uint8_t msg_buf[CMGD_BCKND_MSG_MAX_LEN];
	cmgd_bcknd_msg_t *msg;

	if (adptr->conn_fd == 0)
		return -1;

	msg_size = cmgd__bcknd_message__get_packed_size(bcknd_msg);
	msg_size += CMGD_BCKND_MSG_HDR_LEN;
	if (msg_size > sizeof(msg_buf)) {
		CMGD_BCKND_ADPTR_ERR(
			"Message size %d more than max size'%d. Not sending!'", 
			(int) msg_size, (int)sizeof(msg_buf));
		return -1;
	}
	
	msg = (cmgd_bcknd_msg_t *)msg_buf;
	msg->hdr.marker = CMGD_BCKND_MSG_MARKER;
	msg->hdr.len = (uint16_t) msg_size;
	cmgd__bcknd_message__pack(bcknd_msg, msg->payload);

#ifndef CMGD_PACK_TX_MSGS
	adptr->obuf_work = stream_new(msg_size);
	stream_write(adptr->obuf_work, (void *)msg_buf, msg_size);
	stream_fifo_push(adptr->obuf_fifo, adptr->obuf_work);
	adptr->obuf_work = NULL;
#else
	if (!adptr->obuf_work)
		adptr->obuf_work = stream_new(CMGD_BCKND_MSG_MAX_LEN);
	if (STREAM_WRITEABLE(adptr->obuf_work) < msg_size) {
		stream_fifo_push(adptr->obuf_fifo, adptr->obuf_work);
		adptr->obuf_work = stream_new(CMGD_BCKND_MSG_MAX_LEN);
	}
	stream_write(adptr->obuf_work, (void *)msg_buf, msg_size);
#endif
	cmgd_bcknd_adapter_sched_msg_write(adptr);
	adptr->num_msg_tx++;
	return 0;
}

static int cmgd_bcknd_send_trxn_req(cmgd_bcknd_client_adapter_t *adptr,
	cmgd_trxn_id_t trxn_id, bool create)
{
	Cmgd__BckndMessage bcknd_msg;
	Cmgd__BckndTrxnReq trxn_req;

	cmgd__bcknd_trxn_req__init(&trxn_req);
	trxn_req.create = create;
	trxn_req.trxn_id = trxn_id;

	cmgd__bcknd_message__init(&bcknd_msg);
	bcknd_msg.type = CMGD__BCKND_MESSAGE__TYPE__TRXN_REQ;
	bcknd_msg.message_case = CMGD__BCKND_MESSAGE__MESSAGE_TRXN_REQ;
	bcknd_msg.trxn_req = &trxn_req;

	CMGD_BCKND_ADPTR_DBG("Sending TRXN_REQ message to Backend client '%s' for Trxn-Id %lx",
		adptr->name, trxn_id);

	return cmgd_bcknd_adapter_send_msg(adptr, &bcknd_msg);
}

static int cmgd_bcknd_send_cfgdata_create_req(cmgd_bcknd_client_adapter_t *adptr,
	cmgd_trxn_id_t trxn_id, cmgd_trxn_batch_id_t batch_id,
	cmgd_yang_cfgdata_req_t **cfgdata_reqs, size_t num_reqs)
{
	Cmgd__BckndMessage bcknd_msg;
	Cmgd__BckndCfgDataCreateReq cfgdata_req;

	cmgd__bcknd_cfg_data_create_req__init(&cfgdata_req);
	cfgdata_req.batch_id = batch_id;
	cfgdata_req.trxn_id = trxn_id;
	cfgdata_req.data_req = cfgdata_reqs;
	cfgdata_req.n_data_req = num_reqs;

	cmgd__bcknd_message__init(&bcknd_msg);
	bcknd_msg.type = CMGD__BCKND_MESSAGE__TYPE__CFGDATA_CREATE_REQ;
	bcknd_msg.message_case = CMGD__BCKND_MESSAGE__MESSAGE_CFG_DATA_REQ;
	bcknd_msg.cfg_data_req = &cfgdata_req;

	CMGD_BCKND_ADPTR_DBG("Sending CFGDATA_CREATE_REQ message to Backend client '%s' for Trxn-Id %lx, Batch-Id: %lx",
		adptr->name, trxn_id, batch_id);

	return cmgd_bcknd_adapter_send_msg(adptr, &bcknd_msg);
}

static int cmgd_bcknd_send_cfgvalidate_req(cmgd_bcknd_client_adapter_t *adptr,
	cmgd_trxn_id_t trxn_id, cmgd_trxn_batch_id_t batch_ids[],
	size_t num_batch_ids)
{
	Cmgd__BckndMessage bcknd_msg;
	Cmgd__BckndCfgDataValidateReq vldt_req;

	cmgd__bcknd_cfg_data_validate_req__init(&vldt_req);
	vldt_req.trxn_id = trxn_id;
	vldt_req.batch_ids = (uint64_t *)batch_ids;
	vldt_req.n_batch_ids = num_batch_ids;

	cmgd__bcknd_message__init(&bcknd_msg);
	bcknd_msg.type = CMGD__BCKND_MESSAGE__TYPE__CFGDATA_VALIDATE_REQ;
	bcknd_msg.message_case = CMGD__BCKND_MESSAGE__MESSAGE_CFG_VALIDATE_REQ;
	bcknd_msg.cfg_validate_req = &vldt_req;

	CMGD_BCKND_ADPTR_DBG("Sending CFG_VALIDATE_REQ message to Backend client '%s' for Trxn-Id %lx, #Batches: %d [0x%lx - 0x%lx]",
		adptr->name, trxn_id, (int) num_batch_ids, batch_ids[0],
		batch_ids[num_batch_ids-1]);

	return cmgd_bcknd_adapter_send_msg(adptr, &bcknd_msg);
}

static int cmgd_bcknd_send_cfgapply_req(cmgd_bcknd_client_adapter_t *adptr,
	cmgd_trxn_id_t trxn_id, cmgd_trxn_batch_id_t batch_ids[],
	size_t num_batch_ids)
{
	Cmgd__BckndMessage bcknd_msg;
	Cmgd__BckndCfgDataApplyReq apply_req;

	cmgd__bcknd_cfg_data_apply_req__init(&apply_req);
	apply_req.trxn_id = trxn_id;
	apply_req.batch_ids = (uint64_t *)batch_ids;
	apply_req.n_batch_ids = num_batch_ids;

	cmgd__bcknd_message__init(&bcknd_msg);
	bcknd_msg.type = CMGD__BCKND_MESSAGE__TYPE__CFGDATA_APPLY_REQ;
	bcknd_msg.message_case = CMGD__BCKND_MESSAGE__MESSAGE_CFG_APPLY_REQ;
	bcknd_msg.cfg_apply_req = &apply_req;

	CMGD_BCKND_ADPTR_DBG("Sending CFG_APPLY_REQ message to Backend client '%s' for Trxn-Id %lx, #Batches: %d [0x%lx - 0x%lx]",
		adptr->name, trxn_id, (int) num_batch_ids, batch_ids[0],
		batch_ids[num_batch_ids-1]);

	return cmgd_bcknd_adapter_send_msg(adptr, &bcknd_msg);
}

static uint16_t cmgd_bcknd_adapter_process_msg(
	cmgd_bcknd_client_adapter_t *adptr, uint8_t *msg_buf, uint16_t bytes_read)
{
	Cmgd__BckndMessage *bcknd_msg;
	cmgd_bcknd_msg_t *msg;
	uint16_t bytes_left;
	uint16_t processed = 0;

	bytes_left = bytes_read;
	for ( ; bytes_left > CMGD_BCKND_MSG_HDR_LEN;
		bytes_left -= msg->hdr.len, msg_buf += msg->hdr.len) {
		msg = (cmgd_bcknd_msg_t *)msg_buf;
		if (msg->hdr.marker != CMGD_BCKND_MSG_MARKER) {
			CMGD_BCKND_ADPTR_DBG(
				"Marker not found in message from CMGD Backend adapter '%s'", 
				adptr->name);
			break;
		}

		if (bytes_left < msg->hdr.len) {
			CMGD_BCKND_ADPTR_DBG(
				"Incomplete message of %d bytes (epxected: %u) from CMGD Backend adapter '%s'", 
				bytes_left, msg->hdr.len, adptr->name);
			break;
		}

		bcknd_msg = cmgd__bcknd_message__unpack(
			NULL, (size_t) (msg->hdr.len - CMGD_BCKND_MSG_HDR_LEN), 
			msg->payload);
		if (!bcknd_msg) {
			CMGD_BCKND_ADPTR_DBG(
				"Failed to decode %d bytes from CMGD Backend adapter '%s'", 
				msg->hdr.len, adptr->name);
			continue;
		}

		(void) cmgd_bcknd_adapter_handle_msg(adptr, bcknd_msg);
		cmgd__bcknd_message__free_unpacked(bcknd_msg, NULL);
		processed++;
		adptr->num_msg_rx++;
	}

	return processed;
}

static int cmgd_bcknd_adapter_proc_msgbufs(struct thread *thread)
{
	cmgd_bcknd_client_adapter_t *adptr;
	struct stream *work;
	int processed = 0;

	adptr = (cmgd_bcknd_client_adapter_t *)THREAD_ARG(thread);
	assert(adptr);

	if (adptr->conn_fd == 0)
		return 0;

	for ( ; processed < CMGD_BCKND_MAX_NUM_MSG_PROC ; ) {
		work = stream_fifo_pop_safe(adptr->ibuf_fifo);
		if (!work) {
			break;
		}

		processed += cmgd_bcknd_adapter_process_msg(
			adptr, STREAM_DATA(work), stream_get_endp(work));

		if (work != adptr->ibuf_work) {
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
	if (stream_fifo_head(adptr->ibuf_fifo))
		cmgd_bcknd_adptr_register_event(adptr, CMGD_BCKND_PROC_MSG);
	
	return 0;
}

static int cmgd_bcknd_adapter_read(struct thread *thread)
{
	cmgd_bcknd_client_adapter_t *adptr;
	int bytes_read, msg_cnt;
	size_t total_bytes, bytes_left;
	cmgd_bcknd_msg_hdr_t *msg_hdr;
	bool incomplete = false;

	adptr = (cmgd_bcknd_client_adapter_t *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	total_bytes = 0;
	bytes_left = STREAM_SIZE(adptr->ibuf_work) - 
		stream_get_endp(adptr->ibuf_work);
	for ( ; bytes_left > CMGD_BCKND_MSG_HDR_LEN; ) {
		bytes_read = stream_read_try(
				adptr->ibuf_work, adptr->conn_fd, bytes_left);
		CMGD_BCKND_ADPTR_DBG(
			"Got %d bytes of message from CMGD Backend adapter '%s'", 
			bytes_read, adptr->name);
		if (bytes_read <= 0) {
			if (bytes_read == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
				cmgd_bcknd_adptr_register_event(adptr, CMGD_BCKND_CONN_READ);
				return 0;
			}

			if (!bytes_read) {
				/* Looks like connection closed */
				CMGD_BCKND_ADPTR_ERR(
					"Got error (%d) while reading from CMGD Backend adapter '%s'. Err: '%s'", 
					bytes_read, adptr->name, safe_strerror(errno));
				cmgd_bcknd_adapter_disconnect(adptr);
				return -1;
			}
			break;
		}

		total_bytes += bytes_read;
		bytes_left -= bytes_read;
	}

	/*
	 * Check if we would have read incomplete messages or not.
	 */
	stream_set_getp(adptr->ibuf_work, 0);
	total_bytes = 0;
	msg_cnt = 0;
	bytes_left = stream_get_endp(adptr->ibuf_work);
	for ( ; bytes_left > CMGD_BCKND_MSG_HDR_LEN; ) {
		msg_hdr = (cmgd_bcknd_msg_hdr_t *)
			(STREAM_DATA(adptr->ibuf_work) + total_bytes);
		if (msg_hdr->marker != CMGD_BCKND_MSG_MARKER) {
			/* Corrupted buffer. Force disconnect?? */
			CMGD_BCKND_ADPTR_ERR(
				"Received corrupted buffer from CMGD Backend client.");
			cmgd_bcknd_adapter_disconnect(adptr);
			return -1;
		}
		if (msg_hdr->len > bytes_left) {
			break;
		}

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
	msg_hdr = (cmgd_bcknd_msg_hdr_t *)
		(STREAM_DATA(adptr->ibuf_work) + total_bytes);
	stream_set_endp(adptr->ibuf_work, total_bytes);
	stream_fifo_push(adptr->ibuf_fifo, adptr->ibuf_work);
	adptr->ibuf_work = stream_new(CMGD_BCKND_MSG_MAX_LEN);
	if (incomplete) {
		stream_put(adptr->ibuf_work, msg_hdr, bytes_left);
		stream_set_endp(adptr->ibuf_work, bytes_left);
	}

	if (msg_cnt)
		cmgd_bcknd_adptr_register_event(adptr, CMGD_BCKND_PROC_MSG);

	cmgd_bcknd_adptr_register_event(adptr, CMGD_BCKND_CONN_READ);

	return 0;
}

static int cmgd_bcknd_adapter_write(struct thread *thread)
{
	int bytes_written = 0;
	int processed = 0;
	int msg_size = 0;
	struct stream *s = NULL;
	struct stream *free = NULL;
	cmgd_bcknd_client_adapter_t *adptr;

	adptr = (cmgd_bcknd_client_adapter_t *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	/* Ensure pushing any pending write buffer to FIFO */
	if (adptr->obuf_work) {
		stream_fifo_push(adptr->obuf_fifo, adptr->obuf_work);
		adptr->obuf_work = NULL;
	}

	for (s = stream_fifo_head(adptr->obuf_fifo);
		s && processed < CMGD_BCKND_MAX_NUM_MSG_WRITE;
		s = stream_fifo_head(adptr->obuf_fifo)) {
		// msg_size = (int)stream_get_size(s);
		msg_size = (int) STREAM_READABLE(s);
		bytes_written = stream_flush(s, adptr->conn_fd);
		if (bytes_written == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			cmgd_bcknd_adptr_register_event(adptr, CMGD_BCKND_CONN_WRITE);
			return 0;
		} else if (bytes_written != msg_size) {
			CMGD_BCKND_ADPTR_ERR(
				"Could not write all %d bytes (wrote: %d) to CMGD Backend client socket. Err: '%s'",
				msg_size, bytes_written, safe_strerror(errno));
			if (bytes_written > 0) {
				stream_forward_getp(s, (size_t)bytes_written);
				stream_pulldown(s);
				cmgd_bcknd_adptr_register_event(adptr, CMGD_BCKND_CONN_WRITE);
				return 0;
			}
			cmgd_bcknd_adapter_disconnect(adptr);
			return -1;
		}

		free = stream_fifo_pop(adptr->obuf_fifo);
		stream_free(free);
		CMGD_BCKND_ADPTR_DBG(
			"Wrote %d bytes of message to CMGD Backend client socket.'",
			bytes_written);
		processed++;
	}

	if (s) {
		cmgd_bcknd_adapter_writes_off(adptr);
		cmgd_bcknd_adptr_register_event(adptr, CMGD_BCKND_CONN_WRITES_ON);
	}

	return 0;
}

static int cmgd_bcknd_adapter_resume_writes(struct thread *thread)
{
	cmgd_bcknd_client_adapter_t *adptr;

	adptr = (cmgd_bcknd_client_adapter_t *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	cmgd_bcknd_adapter_writes_on(adptr);

	return 0;
}

static void cmgd_bcknd_adptr_register_event(
	cmgd_bcknd_client_adapter_t *adptr, cmgd_event_t event)
{
	switch (event) {
	case CMGD_BCKND_CONN_READ:
		adptr->conn_read_ev = 
			thread_add_read(cmgd_bcknd_adptr_tm,
				cmgd_bcknd_adapter_read, adptr,
				adptr->conn_fd, NULL);
		break;
	case CMGD_BCKND_CONN_WRITE:
		adptr->conn_write_ev = 
			thread_add_write(cmgd_bcknd_adptr_tm,
				cmgd_bcknd_adapter_write, adptr,
				adptr->conn_fd, NULL);
		break;
	case CMGD_BCKND_PROC_MSG:
		adptr->proc_msg_ev = 
			thread_add_timer_msec(cmgd_bcknd_adptr_tm,
				cmgd_bcknd_adapter_proc_msgbufs, adptr,
				CMGD_BCKND_MSG_PROC_DELAY_MSEC, NULL);
		break;
	case CMGD_BCKND_CONN_WRITES_ON:
		adptr->conn_writes_on =
			thread_add_timer_msec(cmgd_bcknd_adptr_tm,
				cmgd_bcknd_adapter_resume_writes, adptr,
				CMGD_BCKND_MSG_WRITE_DELAY_MSEC, NULL);
		break;
	default:
		assert(!"cmgd_bcknd_adptr_post_event() called incorrectly");
	}
}

void cmgd_bcknd_adapter_lock(cmgd_bcknd_client_adapter_t *adptr)
{
	adptr->refcount++;
}

extern void cmgd_bcknd_adapter_unlock(cmgd_bcknd_client_adapter_t **adptr)
{
	assert(*adptr && (*adptr)->refcount);

	(*adptr)->refcount--;
	if (!(*adptr)->refcount) {
		cmgd_bcknd_adptr_list_del(&cmgd_bcknd_adptrs, *adptr);

		stream_fifo_free((*adptr)->ibuf_fifo);
		stream_free((*adptr)->ibuf_work);
		stream_fifo_free((*adptr)->obuf_fifo);
		stream_free((*adptr)->obuf_work);

		XFREE(MTYPE_CMGD_BCKND_ADPATER, *adptr);
	}

	*adptr = NULL;
}

int cmgd_bcknd_adapter_init(struct thread_master *tm)
{
	if (!cmgd_bcknd_adptr_tm) {
		cmgd_bcknd_adptr_tm = tm;
		cmgd_bcknd_adptr_list_init(&cmgd_bcknd_adptrs);
		cmgd_bcknd_xpath_map_init();
	}

	return 0;
}

cmgd_bcknd_client_adapter_t *cmgd_bcknd_create_adapter(
	int conn_fd, union sockunion *from)
{
	cmgd_bcknd_client_adapter_t *adptr = NULL;

	adptr = cmgd_bcknd_find_adapter_by_fd(conn_fd);
	if (!adptr) {
		adptr = XCALLOC(MTYPE_CMGD_BCKND_ADPATER, 
				sizeof(cmgd_bcknd_client_adapter_t));
		assert(adptr);

		adptr->conn_fd = conn_fd;
		adptr->id = CMGD_BCKND_CLIENT_ID_MAX;
		memcpy(&adptr->conn_su, from, sizeof(adptr->conn_su));
		snprintf(adptr->name, sizeof(adptr->name), "Unknown-FD-%d", adptr->conn_fd);
		adptr->ibuf_fifo = stream_fifo_new();
		adptr->ibuf_work = stream_new(CMGD_BCKND_MSG_MAX_LEN);
		adptr->obuf_fifo = stream_fifo_new();
		// adptr->obuf_work = stream_new(CMGD_BCKND_MSG_MAX_LEN);
		adptr->obuf_work = NULL;
		cmgd_bcknd_adapter_lock(adptr);

		cmgd_bcknd_adptr_register_event(adptr, CMGD_BCKND_CONN_READ);
		cmgd_bcknd_adptr_list_add_tail(&cmgd_bcknd_adptrs, adptr);

		CMGD_BCKND_ADPTR_DBG(
			"Added new CMGD Backend adapter '%s'", adptr->name);
	}

	/* Make client socket non-blocking.  */
	set_nonblocking(adptr->conn_fd);
	setsockopt_so_sendbuf(adptr->conn_fd, CMGD_SOCKET_BUF_SIZE);
	setsockopt_so_recvbuf(adptr->conn_fd, CMGD_SOCKET_BUF_SIZE);

	return adptr;
}

cmgd_bcknd_client_adapter_t *cmgd_bcknd_get_adapter_by_id(
        cmgd_bcknd_client_id_t id)
{
        return (id < CMGD_BCKND_CLIENT_ID_MAX ?
		cmgd_bcknd_adptrs_by_id[id] : NULL);
}

cmgd_bcknd_client_adapter_t *cmgd_bcknd_get_adapter_by_name(const char *name)
{
	return cmgd_bcknd_find_adapter_by_name(name);
}

int cmgd_bcknd_create_trxn(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id)
{
	return cmgd_bcknd_send_trxn_req(adptr, trxn_id, true);
}

int cmgd_bcknd_destroy_trxn(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id)
{
	return cmgd_bcknd_send_trxn_req(adptr, trxn_id, false);
}

int cmgd_bcknd_send_cfg_data_create_req(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id,
        cmgd_trxn_batch_id_t batch_id, cmgd_bcknd_cfgreq_t *cfg_req)
{
	return cmgd_bcknd_send_cfgdata_create_req(adptr, trxn_id, batch_id,
			cfg_req->cfgdata_reqs, cfg_req->num_reqs);
}

extern int cmgd_bcknd_send_cfg_validate_req(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id,
        cmgd_trxn_batch_id_t batch_ids[], size_t num_batch_ids)
{
	return cmgd_bcknd_send_cfgvalidate_req(adptr, trxn_id, batch_ids, num_batch_ids);
}

extern int cmgd_bcknd_send_cfg_apply_req(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id,
        cmgd_trxn_batch_id_t batch_ids[], size_t num_batch_ids)
{
	return cmgd_bcknd_send_cfgapply_req(adptr, trxn_id, batch_ids, num_batch_ids);
}

int cmgd_bcknd_send_get_data_req(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id,
        cmgd_trxn_batch_id_t batch_id, cmgd_bcknd_datareq_t *data_req)
{
	return 0;
}

int cmgd_bcknd_send_get_next_data_req(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id,
        cmgd_trxn_batch_id_t batch_id, cmgd_bcknd_datareq_t *data_req)
{
	return 0;
}

/* 
 * This function maps a YANG dtata Xpath to one or more 
 * Backend Clients that should be contacted for various purposes.
 */
int cmgd_bcknd_get_subscr_info_for_xpath(const char *xpath, 
	cmgd_bcknd_client_subscr_info_t *subscr_info)
{
	int indx, match, max_match = 0, num_reg;
	cmgd_bcknd_client_id_t id;
	cmgd_bcknd_client_subscr_info_t *reg_maps[array_size(cmgd_xpath_map)] = { 0 };

	if (!subscr_info)
		return -1;

	num_reg = 0;
	memset(subscr_info, 0, sizeof(*subscr_info));

	CMGD_BCKND_ADPTR_DBG("XPATH: %s", xpath);
	for (indx = 0; indx < cmgd_num_xpath_maps; indx++) {
		match = cmgd_bcknd_eval_regexp_match(
			cmgd_xpath_map[indx].xpath_regexp, xpath);

		if (match < max_match)
			continue;
	
		if (match > max_match) {
			num_reg = 0;
			max_match = match;
		}

		reg_maps[num_reg] = &cmgd_xpath_map[indx].bcknd_subscrs;
		num_reg++;
	}

	for (indx = 0; indx < num_reg; indx++) {
		FOREACH_CMGD_BCKND_CLIENT_ID(id) {
			if (reg_maps[indx]->xpath_subscr[id].subscribed) {
				CMGD_BCKND_ADPTR_DBG(
					"Cient: %s", 
					cmgd_bknd_client_id2name(id));
				memcpy(&subscr_info->xpath_subscr[id],
					&reg_maps[indx]->xpath_subscr[id],
					sizeof(subscr_info->xpath_subscr[id]));
			}
		}
	}
	
	return 0;
}

void cmgd_bcknd_adapter_status_write(struct vty *vty)
{
	cmgd_bcknd_client_adapter_t *adptr;

	vty_out(vty, "CMGD Backend Adpaters\n");

	FOREACH_ADPTR_IN_LIST(adptr) {
		vty_out(vty, "  Client: \t\t\t%s\n", adptr->name);
		vty_out(vty, "    Conn-FD: \t\t\t%d\n", adptr->conn_fd);
		vty_out(vty, "    Client-Id: \t\t\t%d\n", adptr->id);
		vty_out(vty, "    Ref-Count: \t\t\t%u\n", adptr->refcount);
		vty_out(vty, "    Msg-Sent: \t\t\t%u\n", adptr->num_msg_tx);
		vty_out(vty, "    Msg-Recvd: \t\t\t%u\n", adptr->num_msg_rx);
	}
	vty_out(vty, "  Total: %d\n", 
		(int) cmgd_bcknd_adptr_list_count(&cmgd_bcknd_adptrs));
}

void cmgd_bcknd_xpath_register_write(struct vty *vty)
{
        int indx;
        cmgd_bcknd_client_id_t id;
	cmgd_bcknd_client_adapter_t *adptr;

	vty_out(vty, "CMGD Backend XPath Registry\n");

        for (indx = 0; indx < cmgd_num_xpath_maps; indx++) {
		vty_out(vty, " - XPATH: '%s'\n",
			cmgd_xpath_map[indx].xpath_regexp);
                FOREACH_CMGD_BCKND_CLIENT_ID(id) {
			if (cmgd_xpath_map[indx].bcknd_subscrs.
				xpath_subscr[id].subscribed) {
                        	vty_out(vty, "   -- Client: '%s' \t Validate:%s, Notify:%s, Own:%s\n",
					cmgd_bknd_client_id2name(id),
					cmgd_xpath_map[indx].bcknd_subscrs.
						xpath_subscr[id].validate_config ? "T" : "F",
					cmgd_xpath_map[indx].bcknd_subscrs.
						xpath_subscr[id].notify_config ? "T" : "F",
					cmgd_xpath_map[indx].bcknd_subscrs.
						xpath_subscr[id].own_oper_data ? "T" : "F");
				adptr = cmgd_bcknd_get_adapter_by_id(id);
				if (adptr) {
					vty_out(vty, "     -- Adapter: 0x%p\n", adptr);
				}
			}
                }
        }

	vty_out(vty, "Total XPath Registries: %u\n", cmgd_num_xpath_maps);
}

void cmgd_bcknd_xpath_subscr_info_write(struct vty *vty, const char *xpath)
{
	cmgd_bcknd_client_subscr_info_t subscr;
	cmgd_bcknd_client_id_t id;
	cmgd_bcknd_client_adapter_t *adptr;

	if (cmgd_bcknd_get_subscr_info_for_xpath(xpath, &subscr) != 0) {
		vty_out(vty, "ERROR: Failed to get subscriber for '%s'\n",
			xpath);
		return;
	}

	vty_out(vty, "XPath: '%s'\n", xpath);
	FOREACH_CMGD_BCKND_CLIENT_ID(id) {
		if (subscr.xpath_subscr[id].subscribed) {
			vty_out(vty, "  -- Client: '%s' \t Validate:%s, Notify:%s, Own:%s\n",
				cmgd_bknd_client_id2name(id),
				subscr.xpath_subscr[id].validate_config ? "T" : "F",
				subscr.xpath_subscr[id].notify_config ? "T" : "F",
				subscr.xpath_subscr[id].own_oper_data ? "T" : "F");
			adptr = cmgd_bcknd_get_adapter_by_id(id);
			if (adptr) {
				vty_out(vty, "    -- Adapter: 0x%p\n", adptr);
			}
		}
	}
}
