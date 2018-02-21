/*
 * BFD daemon adapter code
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

#include "lib/log.h"

#include "lib/bfdd_adapter.h"
#include "bfdd_frr.h"

/*
 * Prototypes
 */
struct bpc_node *bfdd_peer_notification_find(struct json_object *notification);
void bfdd_peer_notification(struct json_object *notification);
void bfdd_config_notification(struct json_object *notification);


/*
 * Notification handlers.
 */
struct bpc_node *bfdd_peer_notification_find(struct json_object *notification)
{
	const char *key, *sval;
	struct json_object *jo_val;
	struct json_object_iterator joi, join;
	char *interface = NULL, *vrf = NULL;
	struct sockaddr_any psa, lsa, *psap = NULL, *lsap = NULL;
	struct bfd_peer_cfg bpc;

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
		}
	}

	bfd_configure_peer(&bpc, psap, lsap, interface, vrf, NULL, 0);
	free(interface);
	free(vrf);

	return bn_find(&bc.bc_bnlist, &bpc);
}

void bfdd_peer_notification(struct json_object *notification)
{
	const char *key, *sval;
	struct json_object *jo_val;
	struct json_object_iterator joi, join;
	struct bpc_node *bn;

	/* Find peer to update its status. */
	bn = bfdd_peer_notification_find(notification);
	if (bn == NULL) {
		zlog_debug("%s:%d unable to find notification peer",
			   __FUNCTION__, __LINE__);
		return;
	}

	/* Get the new status information. */
	JSON_FOREACH (notification, joi, join) {
		key = json_object_iter_peek_name(&joi);
		jo_val = json_object_iter_peek_value(&joi);

		if (strcmp(key, "id") == 0) {
			bn->bn_bpc.bpc_id = json_object_get_int64(jo_val);
		} else if (strcmp(key, "remote-id") == 0) {
			bn->bn_bpc.bpc_remoteid = json_object_get_int64(jo_val);
		} else if (strcmp(key, "state") == 0) {
			sval = json_object_get_string(jo_val);
			if (strcmp(sval, "up") == 0) {
				bn->bn_bpc.bpc_bps = BPS_UP;
			} else if (strcmp(sval, "adm-down") == 0) {
				bn->bn_bpc.bpc_bps = BPS_SHUTDOWN;
			} else if (strcmp(sval, "down") == 0) {
				bn->bn_bpc.bpc_bps = BPS_DOWN;
			} else if (strcmp(sval, "init") == 0) {
				bn->bn_bpc.bpc_bps = BPS_INIT;
			}
		}
	}
}

void bfdd_config_notification(struct json_object *notification)
{
	const char *key, *sval;
	struct json_object *jo_val;
	struct json_object_iterator joi, join;
	char *interface = NULL, *vrf = NULL;
	struct sockaddr_any psa, lsa, *psap = NULL, *lsap = NULL;
	struct bfd_peer_cfg bpc;
	struct bpc_node *bn;
	int result;

	/* Find peer or create a new one for the incoming configuration. */
	bn = bfdd_peer_notification_find(notification);
	if (bn == NULL) {
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
			}
		}

		result = bfd_configure_peer(&bpc, psap, lsap, interface, vrf,
					    NULL, 0);
		free(interface);
		free(vrf);

		if (result != 0) {
			zlog_debug("%s:%d: bfd_configure_peer: failed",
				   __FUNCTION__, __LINE__);
			return;
		}

		bn = bn_new(&bc.bc_bnlist, &bpc);
		if (bn == NULL) {
			zlog_debug("%s:%d: bn_new", __FUNCTION__, __LINE__);
			return;
		}
	}

	/* Get the new configuration information. */
	JSON_FOREACH (notification, joi, join) {
		key = json_object_iter_peek_name(&joi);
		jo_val = json_object_iter_peek_value(&joi);

		if (strcmp(key, "detect-multiplier") == 0) {
			bpc_set_detectmultiplier(&bn->bn_bpc,
						 json_object_get_int64(jo_val));
		} else if (strcmp(key, "receive-interval") == 0) {
			bpc_set_recvinterval(&bn->bn_bpc,
					     json_object_get_int64(jo_val));
		} else if (strcmp(key, "transmit-interval") == 0) {
			bpc_set_txinterval(&bn->bn_bpc,
					   json_object_get_int64(jo_val));
		} else if (strcmp(key, "shutdown") == 0) {
			bn->bn_bpc.bpc_shutdown =
				json_object_get_boolean(jo_val);
		} else if (strcmp(key, "label") == 0) {
			strlcpy(bn->bn_bpc.bpc_label,
				json_object_get_string(jo_val),
				sizeof(bn->bn_bpc.bpc_label));
			bn->bn_bpc.bpc_has_label = true;
		}
	}
}


/*
 * Socket IO
 */
void bfdd_receive_debug(struct bfd_control_msg *bcm);

void bfdd_receive_debug(struct bfd_control_msg *bcm)
{
	switch (bcm->bcm_type) {
	case BMT_RESPONSE:
		zlog_debug("%s: id: %d, type %s, length: %u, data: %s",
			   __FUNCTION__, ntohs(bcm->bcm_id), "RESPONSE",
			   ntohl(bcm->bcm_length), bcm->bcm_data);
		break;

	case BMT_NOTIFY:
		zlog_debug("%s: id: %d, type %s, length: %u, data: %s",
			   __FUNCTION__, ntohs(bcm->bcm_id), "NOTIFY",
			   ntohl(bcm->bcm_length), bcm->bcm_data);
		break;

	case BMT_NOTIFY_ADD:
	case BMT_NOTIFY_DEL:
	case BMT_REQUEST_ADD:
	case BMT_REQUEST_DEL:
	default:
		zlog_debug("%s: invalid response type (%d)\n", __FUNCTION__,
			   bcm->bcm_type);
	}
}

/* Generic BFD function to handle notification messages. */
int bfdd_receive_notification(struct bfd_control_msg *bcm, bool *repeat,
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
		bfdd_receive_debug(bcm);
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
	} else if (strcmp(sval, BCM_NOTIFY_CONFIG_ADD) == 0
		   || strcmp(sval, BCM_NOTIFY_CONFIG_DELETE) == 0
		   || strcmp(sval, BCM_NOTIFY_CONFIG_UPDATE) == 0) {
		bfdd_config_notification(notification);
	}

	return 0;
}

/* Generic BFD function to handle responses to requests.  */
int bfdd_receive_id(struct bfd_control_msg *bcm, bool *repeat, void *arg)
{
	uint16_t *id = arg;

	/* This is not the response we are waiting. */
	if (*id != ntohs(bcm->bcm_id)) {
		bfdd_receive_notification(bcm, repeat, NULL);
		*repeat = true;
		return 0;
	}

	bfdd_receive_debug(bcm);

	if (bcm->bcm_type != BMT_RESPONSE) {
		return -1;
	}

	return 0;
}


/*
 * Auxiliary functions.
 */
void prefix2sa(const struct prefix *p, struct sockaddr_any *sa)
{
	memset(sa, 0, sizeof(*sa));

	switch (p->family) {
	case AF_INET:
		sa->sa_sin.sin_family = AF_INET;
		sa->sa_sin.sin_addr = p->u.prefix4;
		break;

	case AF_INET6:
		sa->sa_sin6.sin6_family = AF_INET6;
		sa->sa_sin6.sin6_addr = p->u.prefix6;
		break;

	default:
		zlog_err("%s: translation failed\n", __FUNCTION__);
		break;
	}
}

/*
 * Configuration rules:
 *
 * Single hop:
 * peer + (optional vxlan or interface name)
 *
 * Multi hop:
 * peer + local + (optional vrf)
 *
 * Anything else is misconfiguration.
 */
int bfd_configure_peer(struct bfd_peer_cfg *bpc,
		       const struct sockaddr_any *peer,
		       const struct sockaddr_any *local, const char *ifname,
		       const char *vrfname, char *ebuf, size_t ebuflen)
{
	memset(bpc, 0, sizeof(*bpc));

	/* Defaults */
	bpc->bpc_shutdown = true;
	bpc->bpc_detectmultiplier = BPC_DEF_DETECTMULTIPLIER;
	bpc->bpc_recvinterval = BPC_DEF_RECEIVEINTERVAL;
	bpc->bpc_txinterval = BPC_DEF_TRANSMITINTERVAL;

	/* Safety check: when no error buf is provided len must be zero. */
	if (ebuf == NULL) {
		ebuflen = 0;
	}

	/* Peer is always mandatory. */
	if (peer == NULL) {
		snprintf(ebuf, ebuflen, "peer must not be empty");
		return -1;
	}

	/* Validate address families. */
	if (peer->sa_sin.sin_family == AF_INET) {
		if (local && local->sa_sin.sin_family != AF_INET) {
			snprintf(ebuf, ebuflen,
				 "local is IPv6, but peer is IPv4");
			return -1;
		}

		bpc->bpc_ipv4 = true;
	} else if (peer->sa_sin.sin_family == AF_INET6) {
		if (local && local->sa_sin.sin_family != AF_INET6) {
			snprintf(ebuf, ebuflen,
				 "local is IPv4, but peer is IPv6");
			return -1;
		}

		bpc->bpc_ipv4 = false;
	} else {
		snprintf(ebuf, ebuflen, "invalid peer address family");
		return -1;
	}

	/* Copy local and/or peer addresses. */
	if (local) {
		bpc->bpc_local = *local;
		bpc->bpc_mhop = true;
	}

	if (peer) {
		bpc->bpc_peer = *peer;
	} else {
		/* Peer configuration is mandatory. */
		snprintf(ebuf, ebuflen, "no peer configured");
		return -1;
	}

#if 0
	/* Handle VxLAN configuration. */
	if (vxlan >= 0) {
		if (vxlan > ((1 << 24) - 1)) {
			snprintf(ebuf, ebuflen, "invalid VxLAN %d", vxlan);
			return -1;
		}
		if (bpc->bpc_mhop) {
			snprintf(ebuf, ebuflen,
				 "multihop doesn't accept VxLAN");
			return -1;
		}

		bpc->bpc_vxlan = vxlan;
	}
#endif /* VxLAN */

	/* Handle interface specification configuration. */
	if (ifname) {
		if (bpc->bpc_mhop) {
			snprintf(ebuf, ebuflen,
				 "multihop doesn't accept interface names");
			return -1;
		}

		bpc->bpc_has_localif = true;
		if (strlcpy(bpc->bpc_localif, ifname, sizeof(bpc->bpc_localif))
		    > sizeof(bpc->bpc_localif)) {
			snprintf(ebuf, ebuflen, "interface name too long");
			return -1;
		}
	}

	/* Handle VRF configuration. */
	if (vrfname) {
		bpc->bpc_has_vrfname = true;
		if (strlcpy(bpc->bpc_vrfname, vrfname, sizeof(bpc->bpc_vrfname))
		    > sizeof(bpc->bpc_vrfname)) {
			snprintf(ebuf, ebuflen, "vrf name too long");
			return -1;
		}
	}

	return 0;
}

int bpc_set_detectmultiplier(struct bfd_peer_cfg *bpc, uint8_t detectmultiplier)
{
	if (detectmultiplier < 2)
		return -1;

	if (detectmultiplier == BPC_DEF_DETECTMULTIPLIER) {
		bpc->bpc_has_detectmultiplier = false;
		bpc->bpc_detectmultiplier = detectmultiplier;
		return 0;
	}

	bpc->bpc_has_detectmultiplier = true;
	bpc->bpc_detectmultiplier = detectmultiplier;
	return 0;
}

int bpc_set_recvinterval(struct bfd_peer_cfg *bpc, uint64_t recvinterval)
{
	if (recvinterval < 50 || recvinterval > 60000)
		return -1;

	if (recvinterval == BPC_DEF_RECEIVEINTERVAL) {
		bpc->bpc_has_recvinterval = false;
		bpc->bpc_recvinterval = recvinterval;
		return 0;
	}

	bpc->bpc_has_recvinterval = true;
	bpc->bpc_recvinterval = recvinterval;
	return 0;
}

int bpc_set_txinterval(struct bfd_peer_cfg *bpc, uint64_t txinterval)
{
	if (txinterval < 50 || txinterval > 60000)
		return -1;

	if (txinterval == BPC_DEF_TRANSMITINTERVAL) {
		bpc->bpc_has_txinterval = false;
		bpc->bpc_txinterval = txinterval;
		return 0;
	}

	bpc->bpc_has_txinterval = true;
	bpc->bpc_txinterval = txinterval;
	return 0;
}


/*
 * Command functions.
 */
int bfdd_add_peer(struct vty *vty, struct bfd_peer_cfg *bpc)
{
	struct bpc_node *bn;
	struct json_object *jo;
	const char *jsonstr;
	uint16_t id;

	bn = bn_find(&bc.bc_bnlist, bpc);
	if (bn != NULL) {
		VTY_PUSH_CONTEXT(BFD_PEER_NODE, bn);
		return CMD_SUCCESS;
	}

	/* Create the request data and send. */
	jo = bfd_ctrl_new_json();
	if (jo == NULL) {
		vty_out(vty, "%% Not enough memory\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bfd_ctrl_add_peer(jo, bpc);
	jsonstr = json_object_to_json_string_ext(jo, JSON_C_TO_STRING_PRETTY);
	id = bfd_control_send(bc.bc_csock, BMT_REQUEST_ADD, jsonstr,
			      strlen(jsonstr));

	/* Free the allocate memory for JSON. */
	json_object_put(jo);

	if (id == 0) {
		vty_out(vty, "%% Failed to configure peer\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (bfd_control_recv(bc.bc_csock, bfdd_receive_id, &id) != 0) {
		vty_out(vty, "%% Failed to configure peer\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bn = bn_new(&bc.bc_bnlist, bpc);
	if (bn == NULL) {
		vty_out(vty, "%% Not enough memory\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	VTY_PUSH_CONTEXT(BFD_PEER_NODE, bn);

	return CMD_SUCCESS;
}

int _bfdd_update_peer(struct vty *vty, struct bfd_peer_cfg *bpc, bool use_label)
{
	struct json_object *jo;
	const char *jsonstr;
	uint16_t id;

	/* Create the request data and send. */
	jo = bfd_ctrl_new_json();
	if (jo == NULL) {
		vty_out(vty, "%% Not enough memory\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (use_label) {
		bfd_ctrl_add_peer_bylabel(jo, bpc);
	} else {
		bfd_ctrl_add_peer(jo, bpc);
	}

	jsonstr = json_object_to_json_string_ext(jo, JSON_C_TO_STRING_PRETTY);
	id = bfd_control_send(bc.bc_csock, BMT_REQUEST_ADD, jsonstr,
			      strlen(jsonstr));

	/* Free the allocate memory for JSON. */
	json_object_put(jo);

	if (id == 0) {
		vty_out(vty, "%% Failed to update peer\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (bfd_control_recv(bc.bc_csock, bfdd_receive_id, &id) != 0) {
		vty_out(vty, "%% Failed to update peer\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

int bfdd_update_peer(struct vty *vty, struct bfd_peer_cfg *bpc)
{
	return _bfdd_update_peer(vty, bpc, true);
}


int bfdd_delete_peer(struct vty *vty, struct bfd_peer_cfg *bpc)
{
	struct json_object *jo;
	struct bpc_node *bn;
	const char *jsonstr;
	uint16_t id;

	/* Create the request data and send. */
	jo = bfd_ctrl_new_json();
	if (jo == NULL) {
		vty_out(vty, "%% Not enough memory\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bfd_ctrl_add_peer_bylabel(jo, bpc);
	jsonstr = json_object_to_json_string_ext(jo, JSON_C_TO_STRING_PRETTY);
	id = bfd_control_send(bc.bc_csock, BMT_REQUEST_DEL, jsonstr,
			      strlen(jsonstr));

	/* Free the allocate memory for JSON. */
	json_object_put(jo);

	if (id == 0) {
		vty_out(vty, "%% Failed to delete peer\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (bfd_control_recv(bc.bc_csock, bfdd_receive_id, &id) != 0) {
		vty_out(vty, "%% Failed to delete peer\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/*
	 * Find and delete the node if it hasn't already on the confirmation
	 * above.
	 */
	bn = bn_find(&bc.bc_bnlist, bpc);
	if (bn != NULL) {
		bn_free(bn, &bc.bc_bnlist);
	}

	return CMD_SUCCESS;
}


/*
 * Useful functions.
 */
struct bpc_node *bn_new(struct bnlist *bnlist, struct bfd_peer_cfg *bpc)
{
	struct bpc_node *bn;

	/* Test if it already exists. */
	if (bnlist) {
		bn = bn_find(bnlist, bpc);
		if (bn != NULL)
			return bn;
	}

	bn = calloc(1, sizeof(*bn));
	if (bn == NULL)
		return NULL;

	if (bpc != NULL)
		bn->bn_bpc = *bpc;

	if (bnlist) {
		TAILQ_INSERT_HEAD(bnlist, bn, bn_entry);
	}

	QOBJ_REG(bn, bpc_node);

	return bn;
}

void bn_free(struct bpc_node *bn, struct bnlist *bnlist)
{
	if (bnlist) {
		TAILQ_REMOVE(bnlist, bn, bn_entry);
	}

	QOBJ_UNREG(bn);
	free(bn);
}

struct bpc_node *bn_find(struct bnlist *bnlist, struct bfd_peer_cfg *bpc)
{
	struct bpc_node *bn;
	struct bfd_peer_cfg *bpcp;

	TAILQ_FOREACH (bn, bnlist, bn_entry) {
		bpcp = &bn->bn_bpc;

		/* Compare peer address. */
		if (sa_cmp(&bpc->bpc_peer, &bpcp->bpc_peer) != 0)
			continue;

		/* Compare local address. */
		if (sa_cmp(&bpc->bpc_local, &bpcp->bpc_local) != 0)
			continue;

		/* Compare VRF name. */
		if (bpcp->bpc_has_vrfname && bpc->bpc_has_vrfname) {
			if (strcmp(bpcp->bpc_vrfname, bpc->bpc_vrfname) != 0)
				continue;
		} else if (bpcp->bpc_has_vrfname != bpc->bpc_has_vrfname) {
			continue;
		}

		/* Compare interface name. */
		if (bpcp->bpc_has_localif && bpc->bpc_has_localif) {
			if (strcmp(bpcp->bpc_localif, bpc->bpc_localif) != 0)
				continue;
		} else if (bpcp->bpc_has_localif != bpc->bpc_has_localif) {
			continue;
		}

		return bn;
	}

	return NULL;
}
