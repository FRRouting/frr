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
#include "bfdd_frr.h"

#ifndef VTYSH_EXTRACT_PL
#include "bfdd/bfdd_vty_clippy.c"
#endif

/*
 * Commands help string definitions.
 */
#define PEER_STR "Configure peer\n"
#define INTERFACE_NAME_STR "Configure interface name to use\n"
#define IPV4_PEER_STR "IPv4 peer address\n"
#define IPV6_PEER_STR "IPv6 peer address\n"


/*
 * Prototypes
 */
int bfdd_write_config(struct vty *vty);
int bfdd_peer_write_config(struct vty *vty);


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
	"peer <A.B.C.D|X:X::X:X> [<{interface IFNAME}|{local-address <A.B.C.D|X:X::X:X>|vrf NAME}>]",
	"Configure peer\n"
	"IPv4 peer address\n"
	"IPv6 peer address\n" INTERFACE_STR
	"Configure interface name to use\n"
	"Configure local address (enables multihop)\n"
	"IPv4 local address\n"
	"IPv6 local address\n"
	"Configure VRF\n"
	"Configure VRF name\n")
{
	int idx = 0;
	const char *peer, *ifname, *local, *vrfname;
	struct bfd_peer_cfg bpc;
	struct sockaddr_any psa, lsa, *lsap;
	char errormsg[128];

	vrfname = peer = ifname = local = NULL;

	/* Gather all provided information. */
	peer = argv[1]->arg;

	if (argv_find(argv, argc, "interface", &idx)) {
		ifname = argv[idx + 1]->arg;
	}

	if (argv_find(argv, argc, "local-address", &idx)) {
		local = argv[idx + 1]->arg;
	}

	if (argv_find(argv, argc, "vrf", &idx)) {
		vrfname = argv[idx + 1]->arg;
	}

	strtosa(peer, &psa);
	if (local) {
		strtosa(local, &lsa);
		lsap = &lsa;
	} else
		lsap = NULL;

	if (bfd_configure_peer(&bpc, &psa, lsap, ifname, vrfname, errormsg,
			       sizeof(errormsg))
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
      "receive-interval (50-60000)$interval",
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
      "transmit-interval (50-60000)$interval",
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

DEFPY(bfd_peer_shutdown, bfd_peer_shutdown_cmd,
      "[no] shutdown",
      NO_STR
      "Disable BFD peer")
{
	struct bpc_node *bn;

	bn = VTY_GET_CONTEXT(bpc_node);
	bn->bn_bpc.bpc_shutdown = no ? false : true;

	return bfdd_update_peer(vty, &bn->bn_bpc);
}

DEFPY(bfd_no_peer, bfd_no_peer_cmd,
      "no peer <A.B.C.D|X:X::X:X>$peer [<{interface IFNAME$ifname}|{local-address <A.B.C.D|X:X::X:X>$local|vrf NAME$vrfname}>]",
      NO_STR
      "Configure peer\n"
      "IPv4 peer address\n"
      "IPv6 peer address\n" INTERFACE_STR
      "Configure interface name to use\n"
      "Configure local address (enables multihop)\n"
      "IPv4 local address\n"
      "IPv6 local address\n"
      "Configure VRF\n"
      "Configure VRF name\n")
{
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

	if (bfd_configure_peer(&bpc, &psa, lsap, ifname, vrfname, errormsg,
			       sizeof(errormsg))
	    != 0) {
		vty_out(vty, "%% Invalid peer configuration: %s\n", errormsg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	return bfdd_delete_peer(vty, &bpc);
}


/* Init function */
int bfdd_write_config(struct vty *vty)
{
	if (TAILQ_EMPTY(&bc.bc_bnlist)) {
		return 1;
	}

	vty_out(vty, "bfd\n");
	vty_out(vty, "!\n");

	return 1;
}

int bfdd_peer_write_config(struct vty *vty)
{
	struct bpc_node *bn;
	struct bfd_peer_cfg *bpc;

	TAILQ_FOREACH (bn, &bc.bc_bnlist, bn_entry) {
		bpc = &bn->bn_bpc;

		/* Print node header. */
		vty_out(vty, " peer %s", satostr(&bpc->bpc_peer));
		if (bpc->bpc_has_localif) {
			vty_out(vty, " interface %s", bpc->bpc_localif);
		}
		if (bpc->bpc_local.sa_sin.sin_family != 0) {
			vty_out(vty, " local-address %s",
				satostr(&bpc->bpc_local));
		}
		if (bpc->bpc_has_vrfname) {
			vty_out(vty, " vrf %s", bpc->bpc_vrfname);
		}
		vty_out(vty, "\n");

		if (bpc->bpc_has_detectmultiplier) {
			vty_out(vty, "  detect-multiplier %d\n",
				bpc->bpc_detectmultiplier);
		}
		if (bpc->bpc_has_recvinterval) {
			vty_out(vty, "  receive-interval %lu\n",
				bpc->bpc_recvinterval);
		}
		if (bpc->bpc_has_txinterval) {
			vty_out(vty, "  transmit-interval %lu\n",
				bpc->bpc_txinterval);
		}

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
	install_element(BFD_PEER_NODE, &bfd_peer_shutdown_cmd);
}
