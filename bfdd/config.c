/*********************************************************************
 * Copyright 2017-2018 Network Device Education Foundation, Inc. ("NetDEF")
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
 *
 * config.c: implements the BFD daemon configuration handling.
 *
 * Authors
 * -------
 * Rafael Zalamena <rzalamena@opensourcerouting.org>
 */

#include <zebra.h>

#include <string.h>

#include "lib/json.h"

#include "bfd.h"

/*
 * Definitions
 */
enum peer_list_type {
	PLT_IPV4,
	PLT_IPV6,
	PLT_LABEL,
};


/*
 * Prototypes
 */
static int parse_config_json(struct json_object *jo, bpc_handle h, void *arg);
static int parse_list(struct json_object *jo, enum peer_list_type plt,
		      bpc_handle h, void *arg);
static int parse_peer_config(struct json_object *jo, struct bfd_peer_cfg *bpc);
static int parse_peer_label_config(struct json_object *jo,
				   struct bfd_peer_cfg *bpc);

static int config_add(struct bfd_peer_cfg *bpc, void *arg);
static int config_del(struct bfd_peer_cfg *bpc, void *arg);

static int json_object_add_peer(struct json_object *jo, struct bfd_session *bs);


/*
 * Implementation
 */
static int config_add(struct bfd_peer_cfg *bpc,
		      void *arg __attribute__((unused)))
{
	return ptm_bfd_sess_new(bpc) == NULL;
}

static int config_del(struct bfd_peer_cfg *bpc,
		      void *arg __attribute__((unused)))
{
	return ptm_bfd_ses_del(bpc) != 0;
}

static int parse_config_json(struct json_object *jo, bpc_handle h, void *arg)
{
	const char *key, *sval;
	struct json_object *jo_val;
	struct json_object_iterator joi, join;
	int error = 0;

	JSON_FOREACH (jo, joi, join) {
		key = json_object_iter_peek_name(&joi);
		jo_val = json_object_iter_peek_value(&joi);

		if (strcmp(key, "ipv4") == 0) {
			error += parse_list(jo_val, PLT_IPV4, h, arg);
		} else if (strcmp(key, "ipv6") == 0) {
			error += parse_list(jo_val, PLT_IPV6, h, arg);
		} else if (strcmp(key, "label") == 0) {
			error += parse_list(jo_val, PLT_LABEL, h, arg);
		} else {
			sval = json_object_get_string(jo_val);
			log_warning("%s:%d invalid configuration: %s", __func__,
				    __LINE__, sval);
			error++;
		}
	}

	/*
	 * Our callers never call free() on json_object and only expect
	 * the return value, so lets free() it here.
	 */
	json_object_put(jo);

	return error;
}

int parse_config(const char *fname)
{
	struct json_object *jo;

	jo = json_object_from_file(fname);
	if (jo == NULL)
		return -1;

	return parse_config_json(jo, config_add, NULL);
}

static int parse_list(struct json_object *jo, enum peer_list_type plt,
		      bpc_handle h, void *arg)
{
	struct json_object *jo_val;
	struct bfd_peer_cfg bpc;
	int allen, idx;
	int error = 0, result;

	allen = json_object_array_length(jo);
	for (idx = 0; idx < allen; idx++) {
		jo_val = json_object_array_get_idx(jo, idx);

		/* Set defaults. */
		memset(&bpc, 0, sizeof(bpc));
		bpc.bpc_detectmultiplier = BFD_DEFDETECTMULT;
		bpc.bpc_recvinterval = BFD_DEFREQUIREDMINRX;
		bpc.bpc_txinterval = BFD_DEFDESIREDMINTX;
		bpc.bpc_echointerval = BFD_DEF_REQ_MIN_ECHO;

		switch (plt) {
		case PLT_IPV4:
			log_debug("ipv4 peers %d:", allen);
			bpc.bpc_ipv4 = true;
			break;
		case PLT_IPV6:
			log_debug("ipv6 peers %d:", allen);
			bpc.bpc_ipv4 = false;
			break;
		case PLT_LABEL:
			log_debug("label peers %d:", allen);
			if (parse_peer_label_config(jo_val, &bpc) != 0) {
				error++;
				continue;
			}
			break;

		default:
			error++;
			log_error("%s:%d: unsupported peer type", __func__,
				  __LINE__);
			break;
		}

		result = parse_peer_config(jo_val, &bpc);
		error += result;
		if (result == 0)
			error += (h(&bpc, arg) != 0);
	}

	return error;
}

static int parse_peer_config(struct json_object *jo, struct bfd_peer_cfg *bpc)
{
	const char *key, *sval;
	struct json_object *jo_val;
	struct json_object_iterator joi, join;
	int family_type = (bpc->bpc_ipv4) ? AF_INET : AF_INET6;
	int error = 0;

	log_debug("\tpeer: %s", bpc->bpc_ipv4 ? "ipv4" : "ipv6");

	JSON_FOREACH (jo, joi, join) {
		key = json_object_iter_peek_name(&joi);
		jo_val = json_object_iter_peek_value(&joi);

		if (strcmp(key, "multihop") == 0) {
			bpc->bpc_mhop = json_object_get_boolean(jo_val);
			log_debug("\tmultihop: %s",
				  bpc->bpc_mhop ? "true" : "false");
		} else if (strcmp(key, "peer-address") == 0) {
			sval = json_object_get_string(jo_val);
			if (strtosa(sval, &bpc->bpc_peer) != 0
			    || bpc->bpc_peer.sa_sin.sin_family != family_type) {
				log_info(
					"%s:%d failed to parse peer-address '%s'",
					__func__, __LINE__, sval);
				error++;
			}
			log_debug("\tpeer-address: %s", sval);
		} else if (strcmp(key, "local-address") == 0) {
			sval = json_object_get_string(jo_val);
			if (strtosa(sval, &bpc->bpc_local) != 0
			    || bpc->bpc_local.sa_sin.sin_family
				       != family_type) {
				log_info(
					"%s:%d failed to parse local-address '%s'",
					__func__, __LINE__, sval);
				error++;
			}
			log_debug("\tlocal-address: %s", sval);
		} else if (strcmp(key, "local-interface") == 0) {
			bpc->bpc_has_localif = true;
			sval = json_object_get_string(jo_val);
			if (strlcpy(bpc->bpc_localif, sval,
				    sizeof(bpc->bpc_localif))
			    > sizeof(bpc->bpc_localif)) {
				log_debug("\tlocal-interface: %s (truncated)");
				error++;
			} else {
				log_debug("\tlocal-interface: %s", sval);
			}
		} else if (strcmp(key, "vrf-name") == 0) {
			bpc->bpc_has_vrfname = true;
			sval = json_object_get_string(jo_val);
			if (strlcpy(bpc->bpc_vrfname, sval,
				    sizeof(bpc->bpc_vrfname))
			    > sizeof(bpc->bpc_vrfname)) {
				log_debug("\tvrf-name: %s (truncated)", sval);
				error++;
			} else {
				log_debug("\tvrf-name: %s", sval);
			}
		} else if (strcmp(key, "detect-multiplier") == 0) {
			bpc->bpc_detectmultiplier =
				json_object_get_int64(jo_val);
			bpc->bpc_has_detectmultiplier = true;
			log_debug("\tdetect-multiplier: %llu",
				  bpc->bpc_detectmultiplier);
		} else if (strcmp(key, "receive-interval") == 0) {
			bpc->bpc_recvinterval = json_object_get_int64(jo_val);
			bpc->bpc_has_recvinterval = true;
			log_debug("\treceive-interval: %llu",
				  bpc->bpc_recvinterval);
		} else if (strcmp(key, "transmit-interval") == 0) {
			bpc->bpc_txinterval = json_object_get_int64(jo_val);
			bpc->bpc_has_txinterval = true;
			log_debug("\ttransmit-interval: %llu",
				  bpc->bpc_txinterval);
		} else if (strcmp(key, "echo-interval") == 0) {
			bpc->bpc_echointerval = json_object_get_int64(jo_val);
			bpc->bpc_has_echointerval = true;
			log_debug("\techo-interval: %llu",
				  bpc->bpc_echointerval);
		} else if (strcmp(key, "create-only") == 0) {
			bpc->bpc_createonly = json_object_get_boolean(jo_val);
			log_debug("\tcreate-only: %s",
				  bpc->bpc_createonly ? "true" : "false");
		} else if (strcmp(key, "shutdown") == 0) {
			bpc->bpc_shutdown = json_object_get_boolean(jo_val);
			log_debug("\tshutdown: %s",
				  bpc->bpc_shutdown ? "true" : "false");
		} else if (strcmp(key, "echo-mode") == 0) {
			bpc->bpc_echo = json_object_get_boolean(jo_val);
			log_debug("\techo-mode: %s",
				  bpc->bpc_echo ? "true" : "false");
		} else if (strcmp(key, "label") == 0) {
			bpc->bpc_has_label = true;
			sval = json_object_get_string(jo_val);
			if (strlcpy(bpc->bpc_label, sval,
				    sizeof(bpc->bpc_label))
			    > sizeof(bpc->bpc_label)) {
				log_debug("\tlabel: %s (truncated)", sval);
				error++;
			} else {
				log_debug("\tlabel: %s", sval);
			}
		} else {
			sval = json_object_get_string(jo_val);
			log_warning("%s:%d invalid configuration: '%s: %s'",
				    __func__, __LINE__, key, sval);
			error++;
		}
	}

	if (bpc->bpc_peer.sa_sin.sin_family == 0) {
		log_debug("%s:%d no peer address provided", __func__, __LINE__);
		error++;
	}

	return error;
}

static int parse_peer_label_config(struct json_object *jo,
				   struct bfd_peer_cfg *bpc)
{
	struct peer_label *pl;
	struct json_object *label;
	const char *sval;

	/* Get label and translate it to BFD daemon key. */
	if (!json_object_object_get_ex(jo, "label", &label))
		return 1;

	sval = json_object_get_string(label);

	pl = pl_find(sval);
	if (pl == NULL)
		return 1;

	log_debug("\tpeer-label: %s", sval);

	/* Translate the label into BFD address keys. */
	bpc->bpc_ipv4 = !BFD_CHECK_FLAG(pl->pl_bs->flags, BFD_SESS_FLAG_IPV6);
	bpc->bpc_mhop = BFD_CHECK_FLAG(pl->pl_bs->flags, BFD_SESS_FLAG_MH);
	if (bpc->bpc_mhop) {
		bpc->bpc_peer = pl->pl_bs->mhop.peer;
		bpc->bpc_local = pl->pl_bs->mhop.local;
		if (pl->pl_bs->mhop.vrfid != VRF_DEFAULT) {
			bpc->bpc_has_vrfname = true;
			strlcpy(bpc->bpc_vrfname, pl->pl_bs->vrf->name,
				sizeof(bpc->bpc_vrfname));
		}
	} else {
		bpc->bpc_peer = pl->pl_bs->shop.peer;
		if (pl->pl_bs->ifname[0]) {
			bpc->bpc_has_localif = true;
			strlcpy(bpc->bpc_localif, pl->pl_bs->ifname,
				sizeof(bpc->bpc_localif));
		}
	}

	return 0;
}


/*
 * Control socket JSON parsing.
 */
int config_request_add(const char *jsonstr)
{
	struct json_object *jo;

	jo = json_tokener_parse(jsonstr);
	if (jo == NULL)
		return -1;

	return parse_config_json(jo, config_add, NULL);
}

int config_request_del(const char *jsonstr)
{
	struct json_object *jo;

	jo = json_tokener_parse(jsonstr);
	if (jo == NULL)
		return -1;

	return parse_config_json(jo, config_del, NULL);
}

char *config_response(const char *status, const char *error)
{
	struct json_object *resp, *jo;
	char *jsonstr;

	resp = json_object_new_object();
	if (resp == NULL)
		return NULL;

	/* Add 'status' response key. */
	jo = json_object_new_string(status);
	if (jo == NULL) {
		json_object_put(resp);
		return NULL;
	}

	json_object_object_add(resp, "status", jo);

	/* Add 'error' response key. */
	if (error != NULL) {
		jo = json_object_new_string(error);
		if (jo == NULL) {
			json_object_put(resp);
			return NULL;
		}

		json_object_object_add(resp, "error", jo);
	}

	/* Generate JSON response. */
	jsonstr = XSTRDUP(
		MTYPE_BFDD_NOTIFICATION,
		json_object_to_json_string_ext(resp, BFDD_JSON_CONV_OPTIONS));
	json_object_put(resp);

	return jsonstr;
}

char *config_notify(struct bfd_session *bs)
{
	struct json_object *resp;
	char *jsonstr;
	time_t now;

	resp = json_object_new_object();
	if (resp == NULL)
		return NULL;

	json_object_string_add(resp, "op", BCM_NOTIFY_PEER_STATUS);

	json_object_add_peer(resp, bs);

	/* Add status information */
	json_object_int_add(resp, "id", bs->discrs.my_discr);
	json_object_int_add(resp, "remote-id", bs->discrs.my_discr);

	switch (bs->ses_state) {
	case PTM_BFD_UP:
		json_object_string_add(resp, "state", "up");

		now = monotime(NULL);
		json_object_int_add(resp, "uptime", now - bs->uptime.tv_sec);
		break;
	case PTM_BFD_ADM_DOWN:
		json_object_string_add(resp, "state", "adm-down");
		break;
	case PTM_BFD_DOWN:
		json_object_string_add(resp, "state", "down");

		now = monotime(NULL);
		json_object_int_add(resp, "downtime",
				    now - bs->downtime.tv_sec);
		break;
	case PTM_BFD_INIT:
		json_object_string_add(resp, "state", "init");
		break;

	default:
		json_object_string_add(resp, "state", "unknown");
		break;
	}

	json_object_int_add(resp, "diagnostics", bs->local_diag);
	json_object_int_add(resp, "remote-diagnostics", bs->remote_diag);

	/* Generate JSON response. */
	jsonstr = XSTRDUP(
		MTYPE_BFDD_NOTIFICATION,
		json_object_to_json_string_ext(resp, BFDD_JSON_CONV_OPTIONS));
	json_object_put(resp);

	return jsonstr;
}

char *config_notify_config(const char *op, struct bfd_session *bs)
{
	struct json_object *resp;
	char *jsonstr;

	resp = json_object_new_object();
	if (resp == NULL)
		return NULL;

	json_object_string_add(resp, "op", op);

	json_object_add_peer(resp, bs);

	/* On peer deletion we don't need to add any additional information. */
	if (strcmp(op, BCM_NOTIFY_CONFIG_DELETE) == 0)
		goto skip_config;

	json_object_int_add(resp, "detect-multiplier", bs->detect_mult);
	json_object_int_add(resp, "receive-interval",
			    bs->timers.required_min_rx / 1000);
	json_object_int_add(resp, "transmit-interval",
			    bs->timers.desired_min_tx / 1000);
	json_object_int_add(resp, "echo-interval",
			    bs->timers.required_min_echo / 1000);

	json_object_int_add(resp, "remote-detect-multiplier",
			    bs->remote_detect_mult);
	json_object_int_add(resp, "remote-receive-interval",
			    bs->remote_timers.required_min_rx / 1000);
	json_object_int_add(resp, "remote-transmit-interval",
			    bs->remote_timers.desired_min_tx / 1000);
	json_object_int_add(resp, "remote-echo-interval",
			    bs->remote_timers.required_min_echo / 1000);

	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO))
		json_object_boolean_true_add(resp, "echo-mode");
	else
		json_object_boolean_false_add(resp, "echo-mode");

	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN))
		json_object_boolean_true_add(resp, "shutdown");
	else
		json_object_boolean_false_add(resp, "shutdown");

skip_config:
	/* Generate JSON response. */
	jsonstr = XSTRDUP(
		MTYPE_BFDD_NOTIFICATION,
		json_object_to_json_string_ext(resp, BFDD_JSON_CONV_OPTIONS));
	json_object_put(resp);

	return jsonstr;
}

int config_notify_request(struct bfd_control_socket *bcs, const char *jsonstr,
			  bpc_handle bh)
{
	struct json_object *jo;

	jo = json_tokener_parse(jsonstr);
	if (jo == NULL)
		return -1;

	return parse_config_json(jo, bh, bcs);
}

static int json_object_add_peer(struct json_object *jo, struct bfd_session *bs)
{
	/* Add peer 'key' information. */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_IPV6))
		json_object_boolean_true_add(jo, "ipv6");
	else
		json_object_boolean_false_add(jo, "ipv6");

	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH)) {
		json_object_boolean_true_add(jo, "multihop");
		json_object_string_add(jo, "peer-address",
				       satostr(&bs->mhop.peer));
		json_object_string_add(jo, "local-address",
				       satostr(&bs->mhop.local));
		if (bs->vrfname[0])
			json_object_string_add(jo, "vrf-name", bs->vrfname);
	} else {
		json_object_boolean_false_add(jo, "multihop");
		json_object_string_add(jo, "peer-address",
				       satostr(&bs->shop.peer));
		if (bs->local_address.sa_sin.sin_family != AF_UNSPEC)
			json_object_string_add(jo, "local-address",
					       satostr(&bs->local_address));
		if (bs->ifname[0])
			json_object_string_add(jo, "local-interface",
					       bs->ifname);
	}

	if (bs->pl)
		json_object_string_add(jo, "label", bs->pl->pl_label);

	return 0;
}


/*
 * Label handling
 */
struct peer_label *pl_find(const char *label)
{
	struct peer_label *pl;

	TAILQ_FOREACH (pl, &bglobal.bg_pllist, pl_entry) {
		if (strcmp(pl->pl_label, label) != 0)
			continue;

		return pl;
	}

	return NULL;
}

struct peer_label *pl_new(const char *label, struct bfd_session *bs)
{
	struct peer_label *pl;

	pl = XCALLOC(MTYPE_BFDD_LABEL, sizeof(*pl));
	if (pl == NULL)
		return NULL;

	if (strlcpy(pl->pl_label, label, sizeof(pl->pl_label))
	    > sizeof(pl->pl_label))
		log_warning("%s:%d: label was truncated", __func__, __LINE__);

	pl->pl_bs = bs;
	bs->pl = pl;

	TAILQ_INSERT_HEAD(&bglobal.bg_pllist, pl, pl_entry);

	return pl;
}

void pl_free(struct peer_label *pl)
{
	if (pl == NULL)
		return;

	/* Remove the pointer back. */
	pl->pl_bs->pl = NULL;

	TAILQ_REMOVE(&bglobal.bg_pllist, pl, pl_entry);
	XFREE(MTYPE_BFDD_LABEL, pl);
}
