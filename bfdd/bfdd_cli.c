/*
 * BFD daemon CLI implementation.
 *
 * Copyright (C) 2019 Network Device Education Foundation, Inc. ("NetDEF")
 *                    Rafael Zalamena
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <zebra.h>

#include "lib/command.h"
#include "lib/log.h"
#include "lib/northbound_cli.h"

#ifndef VTYSH_EXTRACT_PL
#include "bfdd/bfdd_cli_clippy.c"
#endif /* VTYSH_EXTRACT_PL */

#include "bfd.h"
#include "bfdd_nb.h"

/*
 * Definitions.
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
 * Prototypes.
 */

/*
 * Functions.
 */
DEFPY_NOSH(
	bfd_enter, bfd_enter_cmd,
	"bfd",
	"Configure BFD peers\n")
{
	int ret;

	nb_cli_enqueue_change(vty, "/frr-bfdd:bfdd/bfd", NB_OP_CREATE, NULL);
	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(BFD_NODE, "/frr-bfdd:bfdd/bfd");

	return ret;
}

DEFUN(
	bfd_config_reset, bfd_config_reset_cmd,
	"no bfd",
	NO_STR
	"Configure BFD peers\n")
{
	nb_cli_enqueue_change(vty, "/frr-bfdd:bfdd/bfd", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_header(struct vty *vty,
			 struct lyd_node *dnode __attribute__((__unused__)),
			 bool show_defaults __attribute__((__unused__)))
{
	vty_out(vty, "!\nbfd\n");
}

void bfd_cli_show_header_end(struct vty *vty,
			     struct lyd_node *dnode __attribute__((__unused__)))
{
	vty_out(vty, "!\n");
}

DEFPY_NOSH(
	bfd_peer_enter, bfd_peer_enter_cmd,
	"peer <A.B.C.D|X:X::X:X> [{multihop$multihop|local-address <A.B.C.D|X:X::X:X>|interface IFNAME$ifname|vrf NAME}]",
	PEER_STR
	PEER_IPV4_STR
	PEER_IPV6_STR
	MHOP_STR
	LOCAL_STR
	LOCAL_IPV4_STR
	LOCAL_IPV6_STR
	INTERFACE_STR
	LOCAL_INTF_STR
	VRF_STR
	VRF_NAME_STR)
{
	int ret, slen;
	char source_str[INET6_ADDRSTRLEN];
	char xpath[XPATH_MAXLEN], xpath_srcaddr[XPATH_MAXLEN + 32];

	if (multihop)
		snprintf(source_str, sizeof(source_str), "[source-addr='%s']",
			 local_address_str);
	else
		source_str[0] = 0;

	slen = snprintf(xpath, sizeof(xpath),
			"/frr-bfdd:bfdd/bfd/sessions/%s%s[dest-addr='%s']",
			multihop ? "multi-hop" : "single-hop", source_str,
			peer_str);
	if (ifname)
		slen += snprintf(xpath + slen, sizeof(xpath) - slen,
				 "[interface='%s']", ifname);
	else
		slen += snprintf(xpath + slen, sizeof(xpath) - slen,
				 "[interface='']");
	if (vrf)
		snprintf(xpath + slen, sizeof(xpath) - slen, "[vrf='%s']", vrf);
	else
		snprintf(xpath + slen, sizeof(xpath) - slen, "[vrf='%s']",
			 VRF_DEFAULT_NAME);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	if (multihop == NULL && local_address_str != NULL) {
		snprintf(xpath_srcaddr, sizeof(xpath_srcaddr),
			 "%s/source-addr", xpath);
		nb_cli_enqueue_change(vty, xpath_srcaddr, NB_OP_MODIFY,
				      local_address_str);
	}

	/* Apply settings immediately. */
	ret = nb_cli_apply_changes(vty, NULL);
	if (ret == CMD_SUCCESS)
		VTY_PUSH_XPATH(BFD_PEER_NODE, xpath);

	return ret;
}

DEFPY(
	bfd_no_peer, bfd_no_peer_cmd,
	"no peer <A.B.C.D|X:X::X:X> [{multihop$multihop|local-address <A.B.C.D|X:X::X:X>|interface IFNAME$ifname|vrf NAME}]",
	NO_STR
	PEER_STR
	PEER_IPV4_STR
	PEER_IPV6_STR
	MHOP_STR
	LOCAL_STR
	LOCAL_IPV4_STR
	LOCAL_IPV6_STR
	INTERFACE_STR
	LOCAL_INTF_STR
	VRF_STR
	VRF_NAME_STR)
{
	int slen;
	char xpath[XPATH_MAXLEN];
	char source_str[INET6_ADDRSTRLEN];

	if (multihop)
		snprintf(source_str, sizeof(source_str), "[source-addr='%s']",
			 local_address_str);
	else
		source_str[0] = 0;

	slen = snprintf(xpath, sizeof(xpath),
			"/frr-bfdd:bfdd/bfd/sessions/%s%s[dest-addr='%s']",
			multihop ? "multi-hop" : "single-hop", source_str,
			peer_str);
	if (ifname)
		slen += snprintf(xpath + slen, sizeof(xpath) - slen,
				 "[interface='%s']", ifname);
	else
		slen += snprintf(xpath + slen, sizeof(xpath) - slen,
				 "[interface='']");
	if (vrf)
		snprintf(xpath + slen, sizeof(xpath) - slen, "[vrf='%s']", vrf);
	else
		snprintf(xpath + slen, sizeof(xpath) - slen, "[vrf='%s']",
			 VRF_DEFAULT_NAME);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	/* Apply settings immediatly. */
	return nb_cli_apply_changes(vty, NULL);
}

static void _bfd_cli_show_peer(struct vty *vty, struct lyd_node *dnode,
			       bool show_defaults __attribute__((__unused__)),
			       bool mhop)
{
	const char *vrf = yang_dnode_get_string(dnode, "./vrf");
	const char *ifname = yang_dnode_get_string(dnode, "./interface");

	vty_out(vty, " peer %s",
		yang_dnode_get_string(dnode, "./dest-addr"));

	if (mhop)
		vty_out(vty, " multihop");

	if (yang_dnode_exists(dnode, "./source-addr"))
		vty_out(vty, " local-address %s",
			yang_dnode_get_string(dnode, "./source-addr"));

	if (strcmp(vrf, VRF_DEFAULT_NAME))
		vty_out(vty, " vrf %s", vrf);

	if (ifname[0])
		vty_out(vty, " interface %s", ifname);

	vty_out(vty, "\n");
}

void bfd_cli_show_single_hop_peer(struct vty *vty,
				  struct lyd_node *dnode,
				  bool show_defaults)
{
	_bfd_cli_show_peer(vty, dnode, show_defaults, false);
}

void bfd_cli_show_multi_hop_peer(struct vty *vty,
				  struct lyd_node *dnode,
				  bool show_defaults)
{
	_bfd_cli_show_peer(vty, dnode, show_defaults, true);
}

void bfd_cli_show_peer_end(struct vty *vty,
			   struct lyd_node *dnode __attribute__((__unused__)))
{
	vty_out(vty, " !\n");
}

DEFPY(
	bfd_peer_shutdown, bfd_peer_shutdown_cmd,
	"[no] shutdown",
	NO_STR
	"Disable BFD peer\n")
{
	nb_cli_enqueue_change(vty, "./administrative-down", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_shutdown(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults)
{
	if (show_defaults)
		vty_out(vty, "  shutdown\n");
	else
		vty_out(vty, "  %sshutdown\n",
			yang_dnode_get_bool(dnode, NULL) ? "" : "no ");
}

DEFPY(
	bfd_peer_mult, bfd_peer_mult_cmd,
	"detect-multiplier (2-255)$multiplier",
	"Configure peer detection multiplier\n"
	"Configure peer detection multiplier value\n")
{
	nb_cli_enqueue_change(vty, "./detection-multiplier", NB_OP_MODIFY,
			      multiplier_str);
	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_mult(struct vty *vty, struct lyd_node *dnode,
		       bool show_defaults)
{
	if (show_defaults)
		vty_out(vty, "  detect-multiplier %d\n",
			BFD_DEFDETECTMULT);
	else
		vty_out(vty, "  detect-multiplier %s\n",
			yang_dnode_get_string(dnode, NULL));
}

DEFPY(
	bfd_peer_rx, bfd_peer_rx_cmd,
	"receive-interval (10-60000)$interval",
	"Configure peer receive interval\n"
	"Configure peer receive interval value in milliseconds\n")
{
	char value[32];

	snprintf(value, sizeof(value), "%ld", interval * 1000);
	nb_cli_enqueue_change(vty, "./required-receive-interval", NB_OP_MODIFY,
			      value);

	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_rx(struct vty *vty, struct lyd_node *dnode,
		     bool show_defaults)
{
	uint32_t value;

	if (show_defaults)
		vty_out(vty, "  receive-interval %d\n",
			BFD_DEFREQUIREDMINRX);
	else {
		value = yang_dnode_get_uint32(dnode, NULL);
		vty_out(vty, "  receive-interval %" PRIu32 "\n", value / 1000);
	}
}

DEFPY(
	bfd_peer_tx, bfd_peer_tx_cmd,
	"transmit-interval (10-60000)$interval",
	"Configure peer transmit interval\n"
	"Configure peer transmit interval value in milliseconds\n")
{
	char value[32];

	snprintf(value, sizeof(value), "%ld", interval * 1000);
	nb_cli_enqueue_change(vty, "./desired-transmission-interval",
			      NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_tx(struct vty *vty, struct lyd_node *dnode,
		     bool show_defaults)
{
	uint32_t value;

	if (show_defaults)
		vty_out(vty, "  transmit-interval %d\n",
			BFD_DEFDESIREDMINTX);
	else {
		value = yang_dnode_get_uint32(dnode, NULL);
		vty_out(vty, "  transmit-interval %" PRIu32 "\n", value / 1000);
	}
}

DEFPY(
	bfd_peer_echo, bfd_peer_echo_cmd,
	"[no] echo-mode",
	NO_STR
	"Configure echo mode\n")
{
	nb_cli_enqueue_change(vty, "./echo-mode", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_echo(struct vty *vty, struct lyd_node *dnode,
			   bool show_defaults)
{
	if (show_defaults)
		vty_out(vty, "  no echo-mode\n");
	else
		vty_out(vty, "  %secho-mode\n",
			yang_dnode_get_bool(dnode, NULL) ? "" : "no ");
}

DEFPY(
	bfd_peer_echo_interval, bfd_peer_echo_interval_cmd,
	"echo-interval (10-60000)$interval",
	"Configure peer echo interval\n"
	"Configure peer echo interval value in milliseconds\n")
{
	char value[32];

	snprintf(value, sizeof(value), "%ld", interval * 1000);
	nb_cli_enqueue_change(vty, "./desired-echo-transmission-interval",
			      NB_OP_MODIFY, value);

	return nb_cli_apply_changes(vty, NULL);
}

void bfd_cli_show_echo_interval(struct vty *vty, struct lyd_node *dnode,
				bool show_defaults)
{
	uint32_t value;

	if (show_defaults)
		vty_out(vty, "  echo-interval %d\n",
			BFD_DEF_REQ_MIN_ECHO);
	else {
		value = yang_dnode_get_uint32(dnode, NULL);
		vty_out(vty, "  echo-interval %" PRIu32 "\n", value / 1000);
	}
}

void
bfdd_cli_init(void)
{
	install_element(CONFIG_NODE, &bfd_enter_cmd);
	install_element(CONFIG_NODE, &bfd_config_reset_cmd);

	install_element(BFD_NODE, &bfd_peer_enter_cmd);
	install_element(BFD_NODE, &bfd_no_peer_cmd);

	install_element(BFD_PEER_NODE, &bfd_peer_shutdown_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_mult_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_rx_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_tx_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_echo_cmd);
	install_element(BFD_PEER_NODE, &bfd_peer_echo_interval_cmd);
}
