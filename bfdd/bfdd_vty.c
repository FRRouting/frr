/*
 * BFD daemon code
 * Copyright (C) 2018 Network Device Education Foundation, Inc. ("NetDEF")
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
#include "lib/json.h"
#include "lib/log.h"
#include "lib/northbound_cli.h"
#include "lib/vty.h"

#include "bfd.h"

#ifndef VTYSH_EXTRACT_PL
#include "bfdd/bfdd_vty_clippy.c"
#endif

/*
 * Commands help string definitions.
 */
#define PEER_IPV4_STR "IPv4 peer address\n"
#define PEER_IPV6_STR "IPv6 peer address\n"
#define MHOP_STR "Configure multihop\n"
#define LOCAL_STR "Configure local address\n"
#define LOCAL_IPV4_STR "IPv4 local address\n"
#define LOCAL_IPV6_STR "IPv6 local address\n"
#define LOCAL_INTF_STR "Configure local interface name to use\n"

/*
 * Prototypes
 */
static int bfd_configure_peer(struct bfd_peer_cfg *bpc, bool mhop,
			      const struct sockaddr_any *peer,
			      const struct sockaddr_any *local,
			      const char *ifname, const char *vrfname,
			      char *ebuf, size_t ebuflen);

static void _display_peer_header(struct vty *vty, struct bfd_session *bs);
static struct json_object *__display_peer_json(struct bfd_session *bs);
static struct json_object *_peer_json_header(struct bfd_session *bs);
static void _display_peer_json(struct vty *vty, struct bfd_session *bs);
static void _display_peer(struct vty *vty, struct bfd_session *bs);
static void _display_all_peers(struct vty *vty, char *vrfname, bool use_json);
static void _display_peer_iter(struct hash_bucket *hb, void *arg);
static void _display_peer_json_iter(struct hash_bucket *hb, void *arg);
static void _display_peer_counter(struct vty *vty, struct bfd_session *bs);
static struct json_object *__display_peer_counters_json(struct bfd_session *bs);
static void _display_peer_counters_json(struct vty *vty, struct bfd_session *bs);
static void _display_peer_counter_iter(struct hash_bucket *hb, void *arg);
static void _display_peer_counter_json_iter(struct hash_bucket *hb, void *arg);
static void _display_peers_counter(struct vty *vty, char *vrfname, bool use_json);
static struct bfd_session *
_find_peer_or_error(struct vty *vty, int argc, struct cmd_token **argv,
		    const char *label, const char *peer_str,
		    const char *local_str, const char *ifname,
		    const char *vrfname);


/*
 * Show commands helper functions
 */
static void _display_peer_header(struct vty *vty, struct bfd_session *bs)
{
	char addr_buf[INET6_ADDRSTRLEN];

	vty_out(vty, "\tpeer %s",
		inet_ntop(bs->key.family, &bs->key.peer, addr_buf,
			  sizeof(addr_buf)));

	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH))
		vty_out(vty, " multihop");

	if (memcmp(&bs->key.local, &zero_addr, sizeof(bs->key.local)))
		vty_out(vty, " local-address %s",
			inet_ntop(bs->key.family, &bs->key.local, addr_buf,
				  sizeof(addr_buf)));

	if (bs->key.vrfname[0])
		vty_out(vty, " vrf %s", bs->key.vrfname);
	if (bs->key.ifname[0])
		vty_out(vty, " interface %s", bs->key.ifname);
	vty_out(vty, "\n");

	if (bs->pl)
		vty_out(vty, "\t\tlabel: %s\n", bs->pl->pl_label);
}

static void _display_peer(struct vty *vty, struct bfd_session *bs)
{
	char buf[256];
	time_t now;

	_display_peer_header(vty, bs);

	vty_out(vty, "\t\tID: %u\n", bs->discrs.my_discr);
	vty_out(vty, "\t\tRemote ID: %u\n", bs->discrs.remote_discr);

	vty_out(vty, "\t\tStatus: ");
	switch (bs->ses_state) {
	case PTM_BFD_ADM_DOWN:
		vty_out(vty, "shutdown\n");
		break;
	case PTM_BFD_DOWN:
		vty_out(vty, "down\n");

		now = monotime(NULL);
		integer2timestr(now - bs->downtime.tv_sec, buf, sizeof(buf));
		vty_out(vty, "\t\tDowntime: %s\n", buf);
		break;
	case PTM_BFD_INIT:
		vty_out(vty, "init\n");
		break;
	case PTM_BFD_UP:
		vty_out(vty, "up\n");

		now = monotime(NULL);
		integer2timestr(now - bs->uptime.tv_sec, buf, sizeof(buf));
		vty_out(vty, "\t\tUptime: %s\n", buf);
		break;

	default:
		vty_out(vty, "unknown\n");
		break;
	}

	vty_out(vty, "\t\tDiagnostics: %s\n", diag2str(bs->local_diag));
	vty_out(vty, "\t\tRemote diagnostics: %s\n", diag2str(bs->remote_diag));

	vty_out(vty, "\t\tLocal timers:\n");
	vty_out(vty, "\t\t\tReceive interval: %" PRIu32 "ms\n",
		bs->timers.required_min_rx / 1000);
	vty_out(vty, "\t\t\tTransmission interval: %" PRIu32 "ms\n",
		bs->timers.desired_min_tx / 1000);
	vty_out(vty, "\t\t\tEcho transmission interval: %" PRIu32 "ms\n",
		bs->timers.required_min_echo / 1000);

	vty_out(vty, "\t\tRemote timers:\n");
	vty_out(vty, "\t\t\tReceive interval: %" PRIu32 "ms\n",
		bs->remote_timers.required_min_rx / 1000);
	vty_out(vty, "\t\t\tTransmission interval: %" PRIu32 "ms\n",
		bs->remote_timers.desired_min_tx / 1000);
	vty_out(vty, "\t\t\tEcho transmission interval: %" PRIu32 "ms\n",
		bs->remote_timers.required_min_echo / 1000);

	vty_out(vty, "\n");
}

static struct json_object *_peer_json_header(struct bfd_session *bs)
{
	struct json_object *jo = json_object_new_object();
	char addr_buf[INET6_ADDRSTRLEN];

	if (bs->key.mhop)
		json_object_boolean_true_add(jo, "multihop");
	else
		json_object_boolean_false_add(jo, "multihop");

	json_object_string_add(jo, "peer",
			       inet_ntop(bs->key.family, &bs->key.peer,
					 addr_buf, sizeof(addr_buf)));
	if (memcmp(&bs->key.local, &zero_addr, sizeof(bs->key.local)))
		json_object_string_add(jo, "local",
				       inet_ntop(bs->key.family, &bs->key.local,
						 addr_buf, sizeof(addr_buf)));

	if (bs->key.vrfname[0])
		json_object_string_add(jo, "vrf", bs->key.vrfname);
	if (bs->key.ifname[0])
		json_object_string_add(jo, "interface", bs->key.ifname);

	if (bs->pl)
		json_object_string_add(jo, "label", bs->pl->pl_label);

	return jo;
}

static struct json_object *__display_peer_json(struct bfd_session *bs)
{
	struct json_object *jo = _peer_json_header(bs);

	json_object_int_add(jo, "id", bs->discrs.my_discr);
	json_object_int_add(jo, "remote-id", bs->discrs.remote_discr);

	switch (bs->ses_state) {
	case PTM_BFD_ADM_DOWN:
		json_object_string_add(jo, "status", "shutdown");
		break;
	case PTM_BFD_DOWN:
		json_object_string_add(jo, "status", "down");
		json_object_int_add(jo, "downtime",
				    monotime(NULL) - bs->downtime.tv_sec);
		break;
	case PTM_BFD_INIT:
		json_object_string_add(jo, "status", "init");
		break;
	case PTM_BFD_UP:
		json_object_string_add(jo, "status", "up");
		json_object_int_add(jo, "uptime",
				    monotime(NULL) - bs->uptime.tv_sec);
		break;

	default:
		json_object_string_add(jo, "status", "unknown");
		break;
	}

	json_object_string_add(jo, "diagnostic", diag2str(bs->local_diag));
	json_object_string_add(jo, "remote-diagnostic",
			       diag2str(bs->remote_diag));

	json_object_int_add(jo, "receive-interval",
			    bs->timers.required_min_rx / 1000);
	json_object_int_add(jo, "transmit-interval",
			    bs->timers.desired_min_tx / 1000);
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_ECHO))
		json_object_int_add(jo, "echo-interval",
				    bs->timers.required_min_echo / 1000);
	else
		json_object_int_add(jo, "echo-interval", 0);

	json_object_int_add(jo, "remote-receive-interval",
			    bs->remote_timers.required_min_rx / 1000);
	json_object_int_add(jo, "remote-transmit-interval",
			    bs->remote_timers.desired_min_tx / 1000);
	json_object_int_add(jo, "remote-echo-interval",
			    bs->remote_timers.required_min_echo / 1000);

	return jo;
}

static void _display_peer_json(struct vty *vty, struct bfd_session *bs)
{
	struct json_object *jo = __display_peer_json(bs);

	vty_out(vty, "%s\n", json_object_to_json_string_ext(jo, 0));
	json_object_free(jo);
}

struct bfd_vrf_tuple {
	char *vrfname;
	struct vty *vty;
	struct json_object *jo;
};

static void _display_peer_iter(struct hash_bucket *hb, void *arg)
{
	struct bfd_vrf_tuple *bvt = (struct bfd_vrf_tuple *)arg;
	struct vty *vty;
	struct bfd_session *bs = hb->data;

	if (!bvt)
		return;
	vty = bvt->vty;

	if (bvt->vrfname) {
		if (!bs->key.vrfname[0] ||
		    !strmatch(bs->key.vrfname, bvt->vrfname))
			return;
	}
	_display_peer(vty, bs);
}

static void _display_peer_json_iter(struct hash_bucket *hb, void *arg)
{
	struct bfd_vrf_tuple *bvt = (struct bfd_vrf_tuple *)arg;
	struct json_object *jo, *jon = NULL;
	struct bfd_session *bs = hb->data;

	if (!bvt)
		return;
	jo = bvt->jo;

	if (bvt->vrfname) {
		if (!bs->key.vrfname[0] ||
		    !strmatch(bs->key.vrfname, bvt->vrfname))
			return;
	}

	jon = __display_peer_json(bs);
	if (jon == NULL) {
		log_warning("%s: not enough memory", __func__);
		return;
	}

	json_object_array_add(jo, jon);
}

static void _display_all_peers(struct vty *vty, char *vrfname, bool use_json)
{
	struct json_object *jo;
	struct bfd_vrf_tuple bvt;

	memset(&bvt, 0, sizeof(bvt));
	bvt.vrfname = vrfname;

	if (!use_json) {
		bvt.vty = vty;
		vty_out(vty, "BFD Peers:\n");
		bfd_id_iterate(_display_peer_iter, &bvt);
		return;
	}

	jo = json_object_new_array();
	bvt.jo = jo;
	bfd_id_iterate(_display_peer_json_iter, &bvt);

	vty_out(vty, "%s\n", json_object_to_json_string_ext(jo, 0));
	json_object_free(jo);
}

static void _display_peer_counter(struct vty *vty, struct bfd_session *bs)
{
	_display_peer_header(vty, bs);

	vty_out(vty, "\t\tControl packet input: %" PRIu64 " packets\n",
		bs->stats.rx_ctrl_pkt);
	vty_out(vty, "\t\tControl packet output: %" PRIu64 " packets\n",
		bs->stats.tx_ctrl_pkt);
	vty_out(vty, "\t\tEcho packet input: %" PRIu64 " packets\n",
		bs->stats.rx_echo_pkt);
	vty_out(vty, "\t\tEcho packet output: %" PRIu64 " packets\n",
		bs->stats.tx_echo_pkt);
	vty_out(vty, "\t\tSession up events: %" PRIu64 "\n",
		bs->stats.session_up);
	vty_out(vty, "\t\tSession down events: %" PRIu64 "\n",
		bs->stats.session_down);
	vty_out(vty, "\t\tZebra notifications: %" PRIu64 "\n",
		bs->stats.znotification);
	vty_out(vty, "\n");
}

static struct json_object *__display_peer_counters_json(struct bfd_session *bs)
{
	struct json_object *jo = _peer_json_header(bs);

	json_object_int_add(jo, "control-packet-input", bs->stats.rx_ctrl_pkt);
	json_object_int_add(jo, "control-packet-output", bs->stats.tx_ctrl_pkt);
	json_object_int_add(jo, "echo-packet-input", bs->stats.rx_echo_pkt);
	json_object_int_add(jo, "echo-packet-output", bs->stats.tx_echo_pkt);
	json_object_int_add(jo, "session-up", bs->stats.session_up);
	json_object_int_add(jo, "session-down", bs->stats.session_down);
	json_object_int_add(jo, "zebra-notifications", bs->stats.znotification);

	return jo;
}

static void _display_peer_counters_json(struct vty *vty, struct bfd_session *bs)
{
	struct json_object *jo = __display_peer_counters_json(bs);

	vty_out(vty, "%s\n", json_object_to_json_string_ext(jo, 0));
	json_object_free(jo);
}

static void _display_peer_counter_iter(struct hash_bucket *hb, void *arg)
{
	struct bfd_vrf_tuple *bvt = arg;
	struct vty *vty;
	struct bfd_session *bs = hb->data;

	if (!bvt)
		return;
	vty = bvt->vty;

	if (bvt->vrfname) {
		if (!bs->key.vrfname[0] ||
		    !strmatch(bs->key.vrfname, bvt->vrfname))
			return;
	}

	_display_peer_counter(vty, bs);
}

static void _display_peer_counter_json_iter(struct hash_bucket *hb, void *arg)
{
	struct json_object *jo, *jon = NULL;
	struct bfd_session *bs = hb->data;
	struct bfd_vrf_tuple *bvt = arg;

	if (!bvt)
		return;
	jo  = bvt->jo;

	if (bvt->vrfname) {
		if (!bs->key.vrfname[0] ||
		    !strmatch(bs->key.vrfname, bvt->vrfname))
			return;
	}

	jon = __display_peer_counters_json(bs);
	if (jon == NULL) {
		log_warning("%s: not enough memory", __func__);
		return;
	}

	json_object_array_add(jo, jon);
}

static void _display_peers_counter(struct vty *vty, char *vrfname, bool use_json)
{
	struct json_object *jo;
	struct bfd_vrf_tuple bvt;

	memset(&bvt, 0, sizeof(struct bfd_vrf_tuple));
	bvt.vrfname = vrfname;
	if (!use_json) {
		bvt.vty = vty;
		vty_out(vty, "BFD Peers:\n");
		bfd_id_iterate(_display_peer_counter_iter, &bvt);
		return;
	}

	jo = json_object_new_array();
	bvt.jo = jo;
	bfd_id_iterate(_display_peer_counter_json_iter, jo);

	vty_out(vty, "%s\n", json_object_to_json_string_ext(jo, 0));
	json_object_free(jo);
}

static struct bfd_session *
_find_peer_or_error(struct vty *vty, int argc, struct cmd_token **argv,
		    const char *label, const char *peer_str,
		    const char *local_str, const char *ifname,
		    const char *vrfname)
{
	int idx;
	bool mhop;
	struct bfd_session *bs = NULL;
	struct peer_label *pl;
	struct bfd_peer_cfg bpc;
	struct sockaddr_any psa, lsa, *lsap;
	char errormsg[128];

	/* Look up the BFD peer. */
	if (label) {
		pl = pl_find(label);
		if (pl)
			bs = pl->pl_bs;
	} else {
		strtosa(peer_str, &psa);
		if (local_str) {
			strtosa(local_str, &lsa);
			lsap = &lsa;
		} else
			lsap = NULL;

		idx = 0;
		mhop = argv_find(argv, argc, "multihop", &idx);

		if (bfd_configure_peer(&bpc, mhop, &psa, lsap, ifname, vrfname,
				       errormsg, sizeof(errormsg))
		    != 0) {
			vty_out(vty, "%% Invalid peer configuration: %s\n",
				errormsg);
			return NULL;
		}

		bs = bs_peer_find(&bpc);
	}

	/* Find peer data. */
	if (bs == NULL) {
		vty_out(vty, "%% Unable to find 'peer %s",
			label ? label : peer_str);
		if (ifname)
			vty_out(vty, " interface %s", ifname);
		if (local_str)
			vty_out(vty, " local-address %s", local_str);
		if (vrfname)
			vty_out(vty, " vrf %s", vrfname);
		vty_out(vty, "'\n");

		return NULL;
	}

	return bs;
}


/*
 * Show commands.
 */
DEFPY(bfd_show_peers, bfd_show_peers_cmd, "show bfd [vrf NAME] peers [json]",
      SHOW_STR
      "Bidirection Forwarding Detection\n"
       VRF_CMD_HELP_STR
      "BFD peers status\n" JSON_STR)
{
	char *vrf_name = NULL;
	int idx_vrf = 0;

	if (argv_find(argv, argc, "vrf", &idx_vrf))
		vrf_name = argv[idx_vrf + 1]->arg;

	_display_all_peers(vty, vrf_name, use_json(argc, argv));

	return CMD_SUCCESS;
}

DEFPY(bfd_show_peer, bfd_show_peer_cmd,
      "show bfd [vrf NAME$vrf_name] peer <WORD$label|<A.B.C.D|X:X::X:X>$peer [{multihop|local-address <A.B.C.D|X:X::X:X>$local|interface IFNAME$ifname}]> [json]",
      SHOW_STR
      "Bidirection Forwarding Detection\n"
      VRF_CMD_HELP_STR
      "BFD peers status\n"
      "Peer label\n" PEER_IPV4_STR PEER_IPV6_STR MHOP_STR LOCAL_STR
	      LOCAL_IPV4_STR LOCAL_IPV6_STR INTERFACE_STR LOCAL_INTF_STR JSON_STR)
{
	struct bfd_session *bs;

	/* Look up the BFD peer. */
	bs = _find_peer_or_error(vty, argc, argv, label, peer_str, local_str,
				 ifname, vrf_name);
	if (bs == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	if (use_json(argc, argv)) {
		_display_peer_json(vty, bs);
	} else {
		vty_out(vty, "BFD Peer:\n");
		_display_peer(vty, bs);
	}

	return CMD_SUCCESS;
}

DEFPY(bfd_show_peer_counters, bfd_show_peer_counters_cmd,
      "show bfd [vrf NAME$vrf_name] peer <WORD$label|<A.B.C.D|X:X::X:X>$peer [{multihop|local-address <A.B.C.D|X:X::X:X>$local|interface IFNAME$ifname}]> counters [json]",
      SHOW_STR
      "Bidirection Forwarding Detection\n"
      VRF_CMD_HELP_STR
      "BFD peers status\n"
      "Peer label\n"
      PEER_IPV4_STR
      PEER_IPV6_STR
      MHOP_STR
      LOCAL_STR
      LOCAL_IPV4_STR
      LOCAL_IPV6_STR
      INTERFACE_STR
      LOCAL_INTF_STR
      "Show BFD peer counters information\n"
      JSON_STR)
{
	struct bfd_session *bs;

	/* Look up the BFD peer. */
	bs = _find_peer_or_error(vty, argc, argv, label, peer_str, local_str,
				 ifname, vrf_name);
	if (bs == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	if (use_json(argc, argv))
		_display_peer_counters_json(vty, bs);
	else
		_display_peer_counter(vty, bs);

	return CMD_SUCCESS;
}

DEFPY(bfd_show_peers_counters, bfd_show_peers_counters_cmd,
      "show bfd [vrf NAME] peers counters [json]",
      SHOW_STR
      "Bidirection Forwarding Detection\n"
      VRF_CMD_HELP_STR
      "BFD peers status\n"
      "Show BFD peer counters information\n"
      JSON_STR)
{
	char *vrf_name = NULL;
	int idx_vrf = 0;

	if (argv_find(argv, argc, "vrf", &idx_vrf))
		vrf_name = argv[idx_vrf + 1]->arg;

	_display_peers_counter(vty, vrf_name, use_json(argc, argv));

	return CMD_SUCCESS;
}


/*
 * Function definitions.
 */

/*
 * Configuration rules:
 *
 * Single hop:
 * peer + (interface name)
 *
 * Multi hop:
 * peer + local + (optional vrf)
 *
 * Anything else is misconfiguration.
 */
static int bfd_configure_peer(struct bfd_peer_cfg *bpc, bool mhop,
			      const struct sockaddr_any *peer,
			      const struct sockaddr_any *local,
			      const char *ifname, const char *vrfname,
			      char *ebuf, size_t ebuflen)
{
	memset(bpc, 0, sizeof(*bpc));

	/* Defaults */
	bpc->bpc_shutdown = true;
	bpc->bpc_detectmultiplier = BPC_DEF_DETECTMULTIPLIER;
	bpc->bpc_recvinterval = BPC_DEF_RECEIVEINTERVAL;
	bpc->bpc_txinterval = BPC_DEF_TRANSMITINTERVAL;
	bpc->bpc_echointerval = BPC_DEF_ECHOINTERVAL;
	bpc->bpc_lastevent = monotime(NULL);

	/* Safety check: when no error buf is provided len must be zero. */
	if (ebuf == NULL)
		ebuflen = 0;

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
	if (local)
		bpc->bpc_local = *local;

	bpc->bpc_peer = *peer;
	bpc->bpc_mhop = mhop;

	/* Handle interface specification configuration. */
	if (ifname) {
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
	} else {
		bpc->bpc_has_vrfname = true;
		strlcpy(bpc->bpc_vrfname, VRF_DEFAULT_NAME, sizeof(bpc->bpc_vrfname));
	}

	return 0;
}

DEFUN_NOSH(show_debugging_bfd,
	   show_debugging_bfd_cmd,
	   "show debugging [bfd]",
	   SHOW_STR
	   DEBUG_STR
	   "BFD daemon\n")
{
	vty_out(vty, "BFD debugging status:\n");

	return CMD_SUCCESS;
}

struct cmd_node bfd_node = {
	BFD_NODE,
	"%s(config-bfd)# ",
	1,
};

struct cmd_node bfd_peer_node = {
	BFD_PEER_NODE,
	"%s(config-bfd-peer)# ",
	1,
};

static int bfdd_write_config(struct vty *vty)
{
	struct lyd_node *dnode;
	int written = 0;

	dnode = yang_dnode_get(running_config->dnode, "/frr-bfdd:bfdd");
	if (dnode) {
		nb_cli_show_dnode_cmds(vty, dnode, false);
		written = 1;
	}

	return written;
}

void bfdd_vty_init(void)
{
	install_element(ENABLE_NODE, &bfd_show_peers_counters_cmd);
	install_element(ENABLE_NODE, &bfd_show_peer_counters_cmd);
	install_element(ENABLE_NODE, &bfd_show_peers_cmd);
	install_element(ENABLE_NODE, &bfd_show_peer_cmd);
	install_element(ENABLE_NODE, &show_debugging_bfd_cmd);

	/* Install BFD node and commands. */
	install_node(&bfd_node, bfdd_write_config);
	install_default(BFD_NODE);

	/* Install BFD peer node. */
	install_node(&bfd_peer_node, NULL);
	install_default(BFD_PEER_NODE);

	bfdd_cli_init();
}
