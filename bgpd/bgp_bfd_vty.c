/*
 * BFD daemon code
 * Copyright (C) 2018 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/log.h"
#include "lib/vty.h"
#include "lib/bfdd_adapter.h"

#include "bgp_vty.h"
#include "bgpd.h"
#include "bgp_fsm.h"


/*
 * Prototypes
 */
static struct bgp_peer_notification *bpn_new(struct peer *p);
static struct bgp_peer_notification *bpn_find(struct peer *p);
static void bpn_free(struct bgp_peer_notification *bpn);
static struct bgp_peer_notification *
bpn_notification_find(struct json_object *notification);

static int bfdd_receive_id(struct bfd_control_msg *bcm, bool *repeat,
			   void *arg);
static int bfdd_receive_notification(struct bfd_control_msg *bcm, bool *repeat,
				     void *arg);
static void bfdd_peer_notification(struct json_object *notification);
static int bfdd_reconfigure(int csock, void *arg);


/*
 * Definitions
 */
struct bgp_peer_notification {
	TAILQ_ENTRY(bgp_peer_notification) bpn_entry;

	struct peer *bpn_p;
};
TAILQ_HEAD(bpnlist, bgp_peer_notification);

struct bfdd_bgp_ctx {
	int bbc_csock;
	struct bpnlist bbc_bpnlist;
} bbc;

struct bfdd_adapter_ctx bac = {
	.bac_csock = -1,
	.bac_read = bfdd_receive_notification,
	.bac_read_arg = &bbc,
	.bac_reconfigure = bfdd_reconfigure,
	.bac_reconfigure_arg = &bbc,
};


/*
 * BFD messages code.
 */
static int peer2bpc(struct peer *peer, struct bfd_peer_cfg *bpc, bool multihop)
{
	memset(bpc, 0, sizeof(*bpc));

	bpc->bpc_mhop = multihop;
	if (peer->su.sin.sin_family == AF_INET) {
		bpc->bpc_ipv4 = true;
		bpc->bpc_peer.sa_sin = peer->su.sin;
	} else if (peer->su.sin.sin_family == AF_INET6) {
		bpc->bpc_ipv4 = false;
		bpc->bpc_peer.sa_sin6 = peer->su.sin6;
	} else {
		zlog_debug("%s:%d: peer family", __FUNCTION__, __LINE__);
		return -1;
	}

	if (multihop && peer->su_local == NULL) {
		zlog_debug("%s:%d: multihop but no local address", __FUNCTION__,
			   __LINE__);
		return -1;
	}

	if (peer->su_local) {
		if (bpc->bpc_ipv4
		    && peer->su_local->sin.sin_family != AF_INET) {
			zlog_debug("%s:%d: local family != AF_INET",
				   __FUNCTION__, __LINE__);
			return -1;
		} else if (!bpc->bpc_ipv4
			   && peer->su_local->sin.sin_family != AF_INET6) {
			zlog_debug("%s:%d: local family != AF_INET6",
				   __FUNCTION__, __LINE__);
			return -1;
		}

		if (peer->su_local->sin.sin_family == AF_INET) {
			bpc->bpc_local.sa_sin = peer->su_local->sin;
		} else if (peer->su_local->sin.sin_family == AF_INET6) {
			bpc->bpc_local.sa_sin6 = peer->su_local->sin6;
		}
	}

	if (peer->nexthop.ifp) {
		if (strlcpy(bpc->bpc_localif, peer->nexthop.ifp->name,
			    sizeof(bpc->bpc_localif))
		    > sizeof(bpc->bpc_localif)) {
			zlog_debug("%s:%d: nexthop if name (truncated)",
				   __FUNCTION__, __LINE__);
		}
		bpc->bpc_has_localif = true;
	}

	/* TODO: support vrf. */

	return 0;
}

static const char *bpc2str(struct bfd_peer_cfg *bpc, char *buf, size_t buflen)
{
	size_t sp;

	memset(buf, 0, buflen);

	sp = snprintf(buf, buflen, "peer %s", satostr(&bpc->bpc_peer));
	if (bpc->bpc_has_label) {
		sp += snprintf(buf + sp, buflen - sp, " label %s", bpc->bpc_label);
	}
	if (bpc->bpc_mhop) {
		sp += snprintf(buf + sp, buflen - sp, " multihop");
	}
	if (bpc->bpc_local.sa_sin.sin_family != 0) {
		sp += snprintf(buf + sp, buflen - sp, " local %s",
			       satostr(&bpc->bpc_local));
	}
	if (bpc->bpc_has_localif) {
		sp += snprintf(buf + sp, buflen - sp, " interface %s",
			       bpc->bpc_localif);
	}

	/* TODO: add support for vrf. */

	return buf;
}

static int _bfdd_unmonitor_peer(struct peer *peer)
{
	struct bgp_peer_notification *bpn;
	const char *jsonstr;
	struct json_object *msg;
	uint16_t id;

	if (peer->bpc == NULL) {
		goto save_and_return;
	}

	/* Create the message and ask to not be notified anymore. */
	msg = bfd_ctrl_new_json();
	if (msg == NULL) {
		zlog_debug("%s:%d: not enough memory", __FUNCTION__, __LINE__);
		return -1;
	}

	bfd_ctrl_add_peer_bylabel(msg, peer->bpc);
	jsonstr = json_object_to_json_string_ext(msg, BFDD_JSON_CONV_OPTIONS);

	id = bfd_control_send(bbc.bbc_csock, BMT_NOTIFY_DEL, jsonstr,
			      strlen(jsonstr));
	json_object_put(msg);

	if (id == 0) {
		zlog_debug("%s:%d: monitor delete failure: id == 0",
			   __FUNCTION__, __LINE__);
		return -1;
	}

	if (bfd_control_recv(bbc.bbc_csock, bfdd_receive_id, &id) != 0) {
		zlog_debug("%s:%d: monitor delete failure: bfd_control_recv",
			   __FUNCTION__, __LINE__);
		return -1;
	}

	/* Free and NULLify the pointer. */
	free(peer->bpc);
	peer->bpc = NULL;

save_and_return:
	/* Save notification configuration. */
	bpn = bpn_find(peer);
	if (bpn) {
		bpn_free(bpn);
	}

	return 0;
}

int bfdd_unmonitor_peer(struct peer *peer)
{
	struct bgp_peer_notification *bpn;
	struct peer_group *group;
	struct listnode *node;
	int error = 0;

	/* Save notification configuration. */
	bpn = bpn_find(peer);
	if (bpn) {
		bpn_free(bpn);
	}

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		group = peer->group;
		for (ALL_LIST_ELEMENTS_RO(group->peer, node, peer)) {
			error |= _bfdd_unmonitor_peer(peer);
		}
	} else {
		error = _bfdd_unmonitor_peer(peer);
	}

	return error;
}

static int _bfdd_monitor_peer(struct peer *peer, const char *label,
			      bool multihop)
{
	struct bgp_peer_notification *bpn;
	struct json_object *msg;
	const char *jsonstr;
	uint16_t id;

	/* Save notification configuration. */
	bpn = bpn_find(peer);
	if (bpn == NULL) {
		bpn = bpn_new(peer);
		if (bpn == NULL)
			return -1;
	}

	/* Remove previously installed monitor. */
	if (peer->bpc && bfdd_unmonitor_peer(peer) != 0) {
		return -1;
	}

	peer->bpc = calloc(1, sizeof(*peer->bpc));
	if (peer->bpc == NULL) {
		zlog_debug("%s:%d: calloc: %s", __FUNCTION__, __LINE__,
			   strerror(errno));
		return -1;
	}

	/* Translate the BGP peer to bfdd format. */
	if (peer2bpc(peer, peer->bpc, multihop) == -1) {
		free(peer->bpc);
		peer->bpc = NULL;
		return -1;
	}
	if (label) {
		strlcpy(peer->bpc->bpc_label, label,
			sizeof(peer->bpc->bpc_label));
		peer->bpc->bpc_has_label = true;
	}

	/* Create the message and ask to not be notified anymore. */
	msg = bfd_ctrl_new_json();
	if (msg == NULL) {
		free(peer->bpc);
		peer->bpc = NULL;
		return -1;
	}

	bfd_ctrl_add_peer_bylabel(msg, peer->bpc);
	jsonstr = json_object_to_json_string_ext(msg, BFDD_JSON_CONV_OPTIONS);

	id = bfd_control_send(bbc.bbc_csock, BMT_NOTIFY_ADD, jsonstr,
			      strlen(jsonstr));
	json_object_put(msg);

	if (id == 0) {
		zlog_debug("%s:%d: monitor add failure: id == 0", __FUNCTION__,
			   __LINE__);
		return -1;
	}

	if (bfd_control_recv(bbc.bbc_csock, bfdd_receive_id, &id) != 0) {
		zlog_debug("%s:%d: monitor add failure: bfd_control_recv",
			   __FUNCTION__, __LINE__);
		return -1;
	}

	return 0;
}

static int bfdd_monitor_peer(struct peer *peer, const char *label,
			     bool multihop)
{
	struct bgp_peer_notification *bpn;
	struct peer_group *group;
	struct listnode *node;
	int error = 0;

	/* Save notification configuration. */
	bpn = bpn_find(peer);
	if (bpn == NULL) {
		bpn = bpn_new(peer);
		if (bpn == NULL)
			return -1;
	}

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		group = peer->group;
		for (ALL_LIST_ELEMENTS_RO(group->peer, node, peer)) {
			error |= _bfdd_monitor_peer(peer, label, multihop);
		}
	} else {
		error = _bfdd_monitor_peer(peer, label, multihop);
	}

	return error;
}


/*
 * Commands
 */
static int use_multihop(const int argc, struct cmd_token *argv[])
{
	if (argc == 0)
		return 0;

	if (argv[argc - 1]->arg && strmatch(argv[argc - 1]->text, "multihop"))
		return 1;

	return 0;
}

DEFUN(bfd_monitor_peer, bfd_monitor_peer_cmd,
      "neighbor <A.B.C.D|X:X::X:X|WORD> bfdd [multihop]",
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Enable BFD support\n"
      "Use multihop\n")
{
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[1]->arg);
	if (peer == NULL) {
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (bfdd_monitor_peer(peer, NULL, use_multihop(argc, argv)) != 0) {
		vty_out(vty, "%% Failed to configure BFD peer notification.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN(bfd_monitor_peer_label, bfd_monitor_peer_label_cmd,
      "neighbor <A.B.C.D|X:X::X:X|WORD> bfdd label WORD",
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Enable BFD support\n"
      "Use BFD peer with label\n"
      "Peer label\n")
{
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[1]->arg);
	if (peer == NULL) {
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (bfdd_monitor_peer(peer, argv[4]->arg, false) != 0) {
		vty_out(vty, "%% Failed to configure BFD peer notification.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN(bfd_unmonitor_peer, bfd_unmonitor_peer_cmd,
      "no neighbor <A.B.C.D|X:X::X:X|WORD> bfdd",
      NO_STR
      NEIGHBOR_STR
      NEIGHBOR_ADDR_STR2
      "Configure Bidirectional Forwarding Detection\n")
{
	struct peer *peer;

	peer = peer_and_group_lookup_vty(vty, argv[2]->arg);
	if (peer == NULL) {
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (bfdd_unmonitor_peer(peer) != 0) {
		vty_out(vty, "%% Failed to configure BFD peer notification.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}


/*
 * BFD daemon adapter code.
 */
static struct bgp_peer_notification *bpn_new(struct peer *p)
{
	struct bgp_peer_notification *bpn;

	bpn = calloc(1, sizeof(*bpn));
	if (bpn == NULL) {
		return NULL;
	}

	bpn->bpn_p = p;
	TAILQ_INSERT_HEAD(&bbc.bbc_bpnlist, bpn, bpn_entry);

	return bpn;
}

static struct bgp_peer_notification *bpn_find(struct peer *p)
{
	struct bgp_peer_notification *bpn;

	TAILQ_FOREACH (bpn, &bbc.bbc_bpnlist, bpn_entry) {
		if (bpn->bpn_p != p)
			continue;

		return bpn;
	}

	return NULL;
}

static void bpn_free(struct bgp_peer_notification *bpn)
{
	TAILQ_REMOVE(&bbc.bbc_bpnlist, bpn, bpn_entry);
	free(bpn);
}

static struct bgp_peer_notification *
bpn_notification_find(struct json_object *notification)
{
	const char *key, *sval;
	struct json_object *jo_val;
	struct json_object_iterator joi, join;
	char *interface = NULL, *vrf = NULL, *label = NULL;
	struct sockaddr_any psa, lsa, *psap = NULL, *lsap = NULL;
	struct bgp_peer_notification *bpn;
	struct bfd_peer_cfg *bpc;

	/* Search for peer information in the keys */
	JSON_FOREACH (notification, joi, join) {
		key = json_object_iter_peek_name(&joi);
		jo_val = json_object_iter_peek_value(&joi);
		sval = json_object_get_string(jo_val);

		if (strcmp(key, "peer-address") == 0) {
			strtosa(sval, &psa);
			psap = &psa;
		} else if (strcmp(key, "local-address") == 0) {
			strtosa(sval, &lsa);
			lsap = &lsa;
		} else if (strcmp(key, "local-interface") == 0) {
			interface = strdup(sval);
		} else if (strcmp(key, "vrf-name") == 0) {
			vrf = strdup(sval);
		} else if (strcmp(key, "label") == 0) {
			label = strdup(sval);
		}
	}

	TAILQ_FOREACH (bpn, &bbc.bbc_bpnlist, bpn_entry) {
		bpc = bpn->bpn_p->bpc;
		if (bpc == NULL) {
			zlog_debug("%s:%d: failed to find peer bpc",
				   __FUNCTION__, __LINE__);
			continue;
		}
		if (label && bpc->bpc_has_label) {
			if (strcmp(bpc->bpc_label, label) == 0) {
				break;
			}
		}

		if (psap && sa_cmp(&psa, &bpc->bpc_peer) != 0) {
			continue;
		}
		if (lsap && sa_cmp(lsap, &bpc->bpc_local) != 0) {
			continue;
		}
		if (interface && bpc->bpc_has_localif
		    && strcmp(interface, bpc->bpc_localif) == 0) {
			continue;
		}
		if (vrf && bpc->bpc_has_vrfname
		    && strcmp(vrf, bpc->bpc_vrfname) == 0) {
			continue;
		}

		break;
	}
	free(interface);
	free(label);
	free(vrf);

	return bpn;
}

static void bfdd_peer_notify_handle(struct peer *p, enum bfd_peer_status bps)
{
	struct bfd_peer_cfg *bpc = p->bpc;
	char buf[256];

	switch (bps) {
	case BPS_DOWN:
		zlog_debug("%s:%d: %s: event down", __FUNCTION__, __LINE__,
			   bpc2str(bpc, buf, sizeof(buf)));
		BGP_EVENT_ADD(p, BGP_Stop);
		p->last_reset = PEER_DOWN_IF_DOWN;
		break;

	case BPS_UP:
		zlog_debug("%s:%d: %s: event up", __FUNCTION__, __LINE__,
			   bpc2str(bpc, buf, sizeof(buf)));
		BGP_EVENT_ADD(p, BGP_Start);
		break;

	case BPS_INIT:
	case BPS_SHUTDOWN:
	default:
		break;
	}
}

static void bfdd_peer_notification(struct json_object *notification)
{
	struct bgp_peer_notification *bpn;
	struct bfd_peer_cfg *bpc;
	const char *key, *sval;
	struct json_object *jo_val;
	struct json_object_iterator joi, join;

	bpn = bpn_notification_find(notification);
	if (bpn == NULL) {
		zlog_debug("%s:%d: unable to find notification peer",
			   __FUNCTION__, __LINE__);
		return;
	}

	bpc = bpn->bpn_p->bpc;

	/* Get the new status information. */
	JSON_FOREACH (notification, joi, join) {
		key = json_object_iter_peek_name(&joi);
		jo_val = json_object_iter_peek_value(&joi);

		if (strcmp(key, "id") == 0) {
			bpc->bpc_id = json_object_get_int64(jo_val);
		} else if (strcmp(key, "remote-id") == 0) {
			bpc->bpc_remoteid = json_object_get_int64(jo_val);
		} else if (strcmp(key, "state") == 0) {
			sval = json_object_get_string(jo_val);
			if (strcmp(sval, "up") == 0) {
				bpc->bpc_bps = BPS_UP;
			} else if (strcmp(sval, "adm-down") == 0) {
				bpc->bpc_bps = BPS_SHUTDOWN;
			} else if (strcmp(sval, "down") == 0) {
				bpc->bpc_bps = BPS_DOWN;
			} else if (strcmp(sval, "init") == 0) {
				bpc->bpc_bps = BPS_INIT;
			}
		}
	}

	bfdd_peer_notify_handle(bpn->bpn_p, bpc->bpc_bps);
}

static int bfdd_receive_id(struct bfd_control_msg *bcm, bool *repeat, void *arg)
{
	uint16_t *id = arg;
	struct bfdd_response br;

	/* This is not the response we are waiting. */
	if (*id != ntohs(bcm->bcm_id)) {
		*repeat = true;
		return 0;
	}

	if (bcm->bcm_type != BMT_RESPONSE) {
		return -1;
	}

	if (bfd_response_parse((const char *)bcm->bcm_data, &br) == 0) {
		if (br.br_status == BRS_OK) {
			return 0;
		} else {
			return -1;
		}
	}

	return 0;
}

static int bfdd_receive_notification(struct bfd_control_msg *bcm, bool *repeat,
				     void *arg)
{
	struct json_object *notification, *jo_val;
	const char *sval;

	/* Report unhandled versions */
	switch (bcm->bcm_ver) {
	case BMV_VERSION_1:
		/* NOTHING */
		break;

	default:
		zlog_debug("%s:%d: received unsupported version: %d",
			   __FUNCTION__, __LINE__, bcm->bcm_ver);
		break;
	}

	/* This is not the response we are waiting. */
	if (ntohs(bcm->bcm_id) != 0 || bcm->bcm_type != BMT_NOTIFY) {
		zlog_debug("%s:%d: received non-notification packet",
			   __FUNCTION__, __LINE__);
		return 0;
	}

	notification = json_tokener_parse((const char *)bcm->bcm_data);
	if (json_object_object_get_ex(notification, "op", &jo_val) == false) {
		zlog_debug("%s:%d: no operation described", __FUNCTION__,
			   __LINE__);
		return 0;
	}

	sval = json_object_get_string(jo_val);
	if (strcmp(sval, BCM_NOTIFY_PEER_STATUS) == 0) {
		bfdd_peer_notification(notification);
	}

	json_object_put(notification);

	return 0;
}

static int bfdd_reconfigure(int csock, void *arg)
{
	struct bfdd_bgp_ctx *bbc = (struct bfdd_bgp_ctx *)arg;
	struct bgp_peer_notification *bpn;
	char label[MAXNAMELEN];
	bool has_label, multihop;

	bbc->bbc_csock = csock;

	TAILQ_FOREACH (bpn, &bbc->bbc_bpnlist, bpn_entry) {
		if (bpn->bpn_p->bpc->bpc_has_label) {
			strlcpy(label, bpn->bpn_p->bpc->bpc_label,
				sizeof(label));
			has_label = true;
		} else {
			memset(label, 0, sizeof(label));
			has_label = false;
		}
		multihop = bpn->bpn_p->bpc->bpc_mhop;

		/* Remove previous registration left overs. */
		free(bpn->bpn_p->bpc);
		bpn->bpn_p->bpc = NULL;

		/* Install a new one. */
		_bfdd_monitor_peer(bpn->bpn_p, has_label ? label : NULL,
				   multihop);
	}

	return 0;
}

void bfdd_print_config(struct vty *vty, const char *addr, struct peer *p)
{
	if (p->bpc == NULL) {
		return;
	}

	if (p->bpc->bpc_has_label) {
		vty_out(vty, " neighbor %s bfdd label %s\n", addr,
			p->bpc->bpc_label);
	} else {
		vty_out(vty, " neighbor %s bfdd%s\n", addr,
			p->bpc->bpc_mhop ? " multihop" : "");
	}
}

/* vtysh initialization code. */
void bfdd_vty_init(struct thread_master *master)
{
	install_element(BGP_NODE, &bfd_monitor_peer_cmd);
	install_element(BGP_NODE, &bfd_monitor_peer_label_cmd);
	install_element(BGP_NODE, &bfd_unmonitor_peer_cmd);

	TAILQ_INIT(&bbc.bbc_bpnlist);
	bac.bac_master = master;
	bfd_adapter_init(&bac);
}
