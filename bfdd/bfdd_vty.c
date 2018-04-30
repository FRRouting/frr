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
#include "lib/log.h"
#include "lib/vty.h"

#include "lib/bfdd_adapter.h"
#include "bfdd_frr.h"

#ifndef VTYSH_EXTRACT_PL
#include "bfdd/bfdd_vty_clippy.c"
#endif

/*
 * Commands help string definitions.
 */
#define PEER_STR "Configure peer\n"
#define INTERFACE_NAME_STR "Configure interface name to use\n"
#define PEER_IPV4_STR "IPv4 peer address\n"
#define PEER_IPV6_STR "IPv6 peer address\n"
#define MHOP_STR "Configure multihop\n"
#define LOCAL_STR "Configure local address\n"
#define LOCAL_IPV4_STR "IPv4 local address\n"
#define LOCAL_IPV6_STR "IPv6 local address\n"
#define LOCAL_INTF_STR "Configure local interface name to use\n"
#define VRF_STR "Configure VRF\n"
#define VRF_NAME_STR "Configure VRF name\n"


/*
 * Prototypes
 */
static int bfdd_write_config(struct vty *vty);
static int bfdd_peer_write_config(struct vty *vty);


/*
 * Commands definition.
 */
DEFUN_NOSH(bfd_enter, bfd_enter_cmd, "bfd", "Configure BFD peers\n")
{
	vty->node = BFD_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH(
	bfd_peer_enter, bfd_peer_enter_cmd,
	"peer <A.B.C.D|X:X::X:X> [{multihop|local-address <A.B.C.D|X:X::X:X>|interface IFNAME|vrf NAME}]",
	PEER_STR PEER_IPV4_STR PEER_IPV6_STR
	MHOP_STR
	LOCAL_STR LOCAL_IPV4_STR LOCAL_IPV6_STR
	INTERFACE_STR
	LOCAL_INTF_STR
	VRF_STR VRF_NAME_STR)
{
	bool mhop;
	int idx;
	const char *peer, *ifname, *local, *vrfname;
	struct bfd_peer_cfg bpc;
	struct sockaddr_any psa, lsa, *lsap;
	char errormsg[128];

	vrfname = peer = ifname = local = NULL;

	/* Gather all provided information. */
	peer = argv[1]->arg;

	idx = 0;
	mhop = argv_find(argv, argc, "multihop", &idx);

	idx = 0;
	if (argv_find(argv, argc, "interface", &idx))
		ifname = argv[idx + 1]->arg;

	idx = 0;
	if (argv_find(argv, argc, "local-address", &idx))
		local = argv[idx + 1]->arg;

	idx = 0;
	if (argv_find(argv, argc, "vrf", &idx))
		vrfname = argv[idx + 1]->arg;

	if (vrfname && ifname) {
		vty_out(vty, "%% VRF is not mixable with interface\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	strtosa(peer, &psa);
	if (local) {
		strtosa(local, &lsa);
		lsap = &lsa;
	} else
		lsap = NULL;

	if (bfd_configure_peer(&bpc, mhop, &psa, lsap, ifname, vrfname,
			       errormsg, sizeof(errormsg))
	    != 0) {
		vty_out(vty, "%% Invalid peer configuration: %s\n", errormsg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return bfdd_add_peer(vty, &bpc);
}

DEFPY(bfd_peer_detectmultiplier, bfd_peer_detectmultiplier_cmd,
      "detect-multiplier (2-255)$multiplier",
      "Configure peer detection multiplier\n"
      "Configure peer detection multiplier value\n")
{
	struct bpc_node *bn;

	bn = VTY_GET_CONTEXT(bpc_node);
	if (bpc_set_detectmultiplier(&bn->bn_bpc, multiplier)) {
		vty_out(vty, "%% Invalid multiplier configuration\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return bfdd_update_peer(vty, &bn->bn_bpc);
}

DEFPY(bfd_peer_recvinterval, bfd_peer_recvinterval_cmd,
      "receive-interval (10-60000)$interval",
      "Configure peer receive interval\n"
      "Configure peer receive interval value in milliseconds\n")
{
	struct bpc_node *bn;

	bn = VTY_GET_CONTEXT(bpc_node);
	if (bpc_set_recvinterval(&bn->bn_bpc, interval)) {
		vty_out(vty, "%% Invalid interval configuration\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return bfdd_update_peer(vty, &bn->bn_bpc);
}

DEFPY(bfd_peer_txinterval, bfd_peer_txinterval_cmd,
      "transmit-interval (10-60000)$interval",
      "Configure peer transmit interval\n"
      "Configure peer transmit interval value in milliseconds\n")
{
	struct bpc_node *bn;

	bn = VTY_GET_CONTEXT(bpc_node);
	if (bpc_set_txinterval(&bn->bn_bpc, interval)) {
		vty_out(vty, "%% Invalid interval configuration\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return bfdd_update_peer(vty, &bn->bn_bpc);
}

DEFPY(bfd_peer_echointerval, bfd_peer_echointerval_cmd,
      "echo-interval (10-60000)$interval",
      "Configure peer echo interval\n"
      "Configure peer echo interval value in milliseconds\n")
{
	struct bpc_node *bn;

	bn = VTY_GET_CONTEXT(bpc_node);
	if (bpc_set_echointerval(&bn->bn_bpc, interval)) {
		vty_out(vty, "%% Invalid interval configuration\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return bfdd_update_peer(vty, &bn->bn_bpc);
}

DEFPY(bfd_peer_shutdown, bfd_peer_shutdown_cmd, "[no] shutdown",
      NO_STR "Disable BFD peer")
{
	struct bpc_node *bn;

	bn = VTY_GET_CONTEXT(bpc_node);
	bn->bn_bpc.bpc_shutdown = no ? false : true;

	return bfdd_update_peer(vty, &bn->bn_bpc);
}

DEFPY(bfd_peer_echo, bfd_peer_echo_cmd, "[no] echo-mode",
      NO_STR "Configure echo mode\n")
{
	struct bpc_node *bn;

	bn = VTY_GET_CONTEXT(bpc_node);
	bn->bn_bpc.bpc_echo = no ? false : true;

	return bfdd_update_peer(vty, &bn->bn_bpc);
}

DEFPY(bfd_peer_label, bfd_peer_label_cmd, "label WORD$label",
      "Register peer label\n"
      "Register peer label identification\n")
{
	struct bpc_node *bn;
	struct bfd_peer_cfg *bpc;
	char oldlabel[MAXNAMELEN] = {0};
	int result;

	/* Validate label length. */
	if (strlen(label) > sizeof(oldlabel)) {
		vty_out(vty, "%% Label name is too long\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	bn = VTY_GET_CONTEXT(bpc_node);
	bpc = &bn->bn_bpc;

	/* Save the old label if any. */
	if (bpc->bpc_has_label)
		strlcpy(oldlabel, bpc->bpc_label, sizeof(oldlabel));

	/* Apply configuration and test. */
	bpc->bpc_has_label = true;
	strlcpy(bpc->bpc_label, label, sizeof(bpc->bpc_label));

	result = _bfdd_update_peer(vty, bpc, false);

	/* If the update failed, then we must revert the configuration. */
	if (result != CMD_SUCCESS) {
		if (oldlabel[0] != 0) {
			strlcpy(bpc->bpc_label, oldlabel,
				sizeof(bpc->bpc_label));
		} else {
			memset(bpc->bpc_label, 0, sizeof(bpc->bpc_label));
			bpc->bpc_has_label = false;
		}
	}

	return result;
}

DEFPY(bfd_no_peer, bfd_no_peer_cmd,
      "no peer <A.B.C.D|X:X::X:X>$peer [{multihop|local-address <A.B.C.D|X:X::X:X>$local|interface IFNAME$ifname|vrf NAME$vrfname}]",
      NO_STR
      PEER_STR PEER_IPV4_STR PEER_IPV6_STR
      MHOP_STR
      LOCAL_STR LOCAL_IPV4_STR LOCAL_IPV6_STR
      INTERFACE_STR
      LOCAL_INTF_STR
      VRF_STR VRF_NAME_STR)
{
	int idx;
	bool mhop;
	struct bfd_peer_cfg bpc;
	struct sockaddr_any psa, lsa, *lsap;
	char errormsg[128];

	strtosa(peer_str, &psa);
	if (local) {
		strtosa(local_str, &lsa);
		lsap = &lsa;
	} else {
		lsap = NULL;
	}

	idx = 0;
	mhop = argv_find(argv, argc, "multihop", &idx);

	if (bfd_configure_peer(&bpc, mhop, &psa, lsap, ifname, vrfname,
			       errormsg, sizeof(errormsg))
	    != 0) {
		vty_out(vty, "%% Invalid peer configuration: %s\n", errormsg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return bfdd_delete_peer(vty, &bpc);
}

static void _display_peer(struct vty *vty, struct bfd_peer_cfg *bpc)
{
	char buf[256];
	time_t now;

	vty_out(vty, "\tpeer %s", satostr(&bpc->bpc_peer));
	if (bpc->bpc_mhop)
		vty_out(vty, " multihop");
	if (bpc->bpc_has_localif)
		vty_out(vty, " interface %s", bpc->bpc_localif);
	if (bpc->bpc_local.sa_sin.sin_family != 0)
		vty_out(vty, " local-address %s", satostr(&bpc->bpc_local));
	if (bpc->bpc_has_vrfname)
		vty_out(vty, " vrf %s", bpc->bpc_vrfname);
	vty_out(vty, "\n");

	if (bpc->bpc_has_label)
		vty_out(vty, "\t\tlabel: %s\n", bpc->bpc_label);
	vty_out(vty, "\t\tID: %u\n", bpc->bpc_id);
	vty_out(vty, "\t\tRemote ID: %u\n", bpc->bpc_remoteid);

	vty_out(vty, "\t\tStatus: ");
	switch (bpc->bpc_bps) {
	case BPS_SHUTDOWN:
		vty_out(vty, "shutdown\n");
		break;
	case BPS_DOWN:
		vty_out(vty, "down\n");
		break;
	case BPS_INIT:
		vty_out(vty, "init\n");
		break;
	case BPS_UP:
		vty_out(vty, "up\n");
		break;

	default:
		vty_out(vty, "unknown\n");
		break;
	}

	if (bpc->bpc_bps == BPS_DOWN) {
		now = monotime(NULL);
		integer2timestr(now - bpc->bpc_lastevent, buf, sizeof(buf));
		vty_out(vty, "\t\tDowntime: %s\n", buf);
	}
	if (bpc->bpc_bps == BPS_UP) {
		now = monotime(NULL);
		integer2timestr(now - bpc->bpc_lastevent, buf, sizeof(buf));
		vty_out(vty, "\t\tUptime: %s\n", buf);
	}

	vty_out(vty, "\t\tDiagnostics: %s\n", diag2str(bpc->bpc_diag));
	vty_out(vty, "\t\tRemote diagnostics: %s\n",
		diag2str(bpc->bpc_remotediag));

	vty_out(vty, "\t\tLocal timers:\n");
	vty_out(vty, "\t\t\tReceive interval: %" PRIu64 "\n",
		bpc->bpc_recvinterval);
	vty_out(vty, "\t\t\tTransmission interval: %" PRIu64 "\n",
		bpc->bpc_txinterval);

	vty_out(vty, "\t\t\tEcho transmission interval: ");
	if (bpc->bpc_echo)
		vty_out(vty, "%" PRIu64 "\n", bpc->bpc_echointerval);
	else
		vty_out(vty, "disabled\n");

	vty_out(vty, "\t\tRemote timers:\n");
	vty_out(vty, "\t\t\tReceive interval: %" PRIu64 "\n",
		bpc->bpc_remote_recvinterval);
	vty_out(vty, "\t\t\tTransmission interval: %" PRIu64 "\n",
		bpc->bpc_remote_txinterval);
	vty_out(vty, "\t\t\tEcho transmission interval: %" PRIu64 "\n",
		bpc->bpc_remote_echointerval);

	vty_out(vty, "\n");
}

DEFPY(bfd_show_peers, bfd_show_peers_cmd, "show bfd peers", SHOW_STR
      "Bidirection Forwarding Detection\n"
      "BFD peers status\n")
{
	struct bpc_node *bn;
	struct bfd_peer_cfg *bpc;

	vty_out(vty, "BFD Peers:\n");
	TAILQ_FOREACH (bn, &bc.bc_bnlist, bn_entry) {
		bpc = &bn->bn_bpc;

		_display_peer(vty, bpc);
	}

	return CMD_SUCCESS;
}

DEFPY(bfd_show_peer, bfd_show_peer_cmd,
      "show bfd peer <WORD$label|<A.B.C.D|X:X::X:X>$peer [{multihop|local-address <A.B.C.D|X:X::X:X>$local|interface IFNAME$ifname|vrf NAME$vrfname}]>",
      SHOW_STR
      "Bidirection Forwarding Detection\n"
      "BFD peers status\n"
      "Peer label\n"
      PEER_IPV4_STR PEER_IPV6_STR
      MHOP_STR
      LOCAL_STR LOCAL_IPV4_STR LOCAL_IPV6_STR
      INTERFACE_STR
      LOCAL_INTF_STR
      VRF_STR VRF_NAME_STR)
{
	int idx;
	bool mhop;
	struct bpc_node *bn;
	struct bfd_peer_cfg *bpcp;
	struct bfd_peer_cfg bpc;
	struct sockaddr_any psa, lsa, *lsap;
	char errormsg[128];

	/* Look up the BFD peer. */
	if (label) {
		TAILQ_FOREACH (bn, &bc.bc_bnlist, bn_entry) {
			bpcp = &bn->bn_bpc;

			if (strcmp(bpcp->bpc_label, label) == 0)
				break;
		}
	} else {
		strtosa(peer_str, &psa);
		if (local) {
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
			return CMD_WARNING_CONFIG_FAILED;
		}

		bn = bn_find(&bc.bc_bnlist, &bpc);
	}

	/* Find peer data. */
	if (bn == NULL) {
		vty_out(vty, "%% Unable to find 'peer %s",
			label ? label : peer_str);
		if (ifname)
			vty_out(vty, " interface %s", ifname);
		if (local)
			vty_out(vty, " local-address %s", local_str);
		if (vrfname)
			vty_out(vty, " vrf %s", vrfname);
		vty_out(vty, "'\n");

		return CMD_SUCCESS;
	}

	vty_out(vty, "BFD Peer:\n");
	_display_peer(vty, &bn->bn_bpc);

	return CMD_SUCCESS;
}


/* Init function */
static int bfdd_write_config(struct vty *vty)
{
	if (TAILQ_EMPTY(&bc.bc_bnlist))
		return 0;

	vty_out(vty, "bfd\n");
	vty_out(vty, "!\n");
	return 0;
}

static int bfdd_peer_write_config(struct vty *vty)
{
	struct bpc_node *bn;
	struct bfd_peer_cfg *bpc;

	TAILQ_FOREACH (bn, &bc.bc_bnlist, bn_entry) {
		bpc = &bn->bn_bpc;

		/* Print node header. */
		vty_out(vty, " peer %s", satostr(&bpc->bpc_peer));
		if (bpc->bpc_mhop)
			vty_out(vty, " multihop");
		if (bpc->bpc_has_localif)
			vty_out(vty, " interface %s", bpc->bpc_localif);
		if (bpc->bpc_local.sa_sin.sin_family != 0)
			vty_out(vty, " local-address %s",
				satostr(&bpc->bpc_local));
		if (bpc->bpc_has_vrfname)
			vty_out(vty, " vrf %s", bpc->bpc_vrfname);
		vty_out(vty, "\n");

		if (bpc->bpc_detectmultiplier != BPC_DEF_DETECTMULTIPLIER)
			vty_out(vty, "  detect-multiplier %d\n",
				bpc->bpc_detectmultiplier);
		if (bpc->bpc_recvinterval != BPC_DEF_RECEIVEINTERVAL)
			vty_out(vty, "  receive-interval %" PRIu64 "\n",
				bpc->bpc_recvinterval);
		if (bpc->bpc_txinterval != BPC_DEF_TRANSMITINTERVAL)
			vty_out(vty, "  transmit-interval %" PRIu64 "\n",
				bpc->bpc_txinterval);
		if (bpc->bpc_echointerval != BPC_DEF_ECHOINTERVAL)
			vty_out(vty, "  echo-interval %" PRIu64 "\n",
				bpc->bpc_echointerval);
		if (bpc->bpc_has_label)
			vty_out(vty, "  label %s\n", bpc->bpc_label);
		if (bpc->bpc_echo)
			vty_out(vty, "  echo-mode\n");

		vty_out(vty, "  %sshutdown\n", bpc->bpc_shutdown ? "" : "no ");

		vty_out(vty, " !\n");
	}

	return 1;
}

struct cmd_node bfd_node = {
	BFD_NODE, "%s(config-bfd)# ", 1,
};

struct cmd_node bfd_peer_node = {
	BFD_PEER_NODE, "%s(config-bfd-peer)# ", 1,
};

void bfdd_vty_init(void)
{
	install_element(ENABLE_NODE, &bfd_show_peers_cmd);
	install_element(ENABLE_NODE, &bfd_show_peer_cmd);
	install_element(CONFIG_NODE, &bfd_enter_cmd);

	/* Install BFD node and commands. */
	install_node(&bfd_node, bfdd_write_config);
	install_default(BFD_NODE);
	install_element(BFD_NODE, &bfd_peer_enter_cmd);
	install_element(BFD_NODE, &bfd_no_peer_cmd);

	/* Install BFD peer node. */
	install_node(&bfd_peer_node, bfdd_peer_write_config);
	install_default(BFD_PEER_NODE);
	install_element(BFD_PEER_NODE, &bfd_peer_detectmultiplier_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_recvinterval_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_txinterval_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_echointerval_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_shutdown_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_echo_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_label_cmd);
}
