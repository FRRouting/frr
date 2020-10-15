/* NHRP vty handling
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include "zebra.h"
#include "command.h"
#include "zclient.h"
#include "stream.h"
#include "filter.h"
#include "json.h"

#include "nhrpd.h"
#include "netlink.h"

static int nhrp_config_write(struct vty *vty);

#ifndef VTYSH_EXTRACT_PL
#include "nhrpd/nhrp_vty_clippy.c"
#endif

static struct cmd_node zebra_node = {
	.name = "zebra",
	.node = ZEBRA_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-router)# ",
	.config_write = nhrp_config_write,
};

static int interface_config_write(struct vty *vty);
static struct cmd_node nhrp_interface_node = {
	.name = "interface",
	.node = INTERFACE_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-if)# ",
	.config_write = interface_config_write,
};

#define NHRP_DEBUG_FLAGS_CMD "<all|common|event|interface|kernel|route|vici|vrf>"

#define NHRP_DEBUG_FLAGS_STR                                                   \
	"All messages\n"                                                       \
	"Common messages (default)\n"                                          \
	"Event manager messages\n"                                             \
	"Interface messages\n"                                                 \
	"Kernel messages\n"                                                    \
	"Route messages\n"                                                     \
	"VICI messages\n"                                                      \
	"VRF messages\n"

static const struct message debug_flags_desc[] = {
	{NHRP_DEBUG_ALL, "all"},      {NHRP_DEBUG_COMMON, "common"},
	{NHRP_DEBUG_IF, "interface"}, {NHRP_DEBUG_KERNEL, "kernel"},
	{NHRP_DEBUG_ROUTE, "route"},  {NHRP_DEBUG_VICI, "vici"},
	{NHRP_DEBUG_EVENT, "event"},  {NHRP_DEBUG_VRF, "vrf"},
	{0}};

static const struct message interface_flags_desc[] = {
	{NHRP_IFF_SHORTCUT, "shortcut"},
	{NHRP_IFF_REDIRECT, "redirect"},
	{NHRP_IFF_SHORTCUT_KEEPSA, "shortcut-keep-sa"},
	{NHRP_IFF_REG_NO_UNIQUE, "registration no-unique"},
	{0}};

static int nhrp_vty_return(struct vty *vty, int ret)
{
	static const char *const errmsgs[] = {
			[NHRP_ERR_FAIL] = "Command failed",
			[NHRP_ERR_NO_MEMORY] = "Out of memory",
			[NHRP_ERR_UNSUPPORTED_INTERFACE] =
				"NHRP not supported on this interface",
			[NHRP_ERR_NHRP_NOT_ENABLED] =
				"NHRP not enabled (set 'nhrp network-id' first)",
			[NHRP_ERR_ENTRY_EXISTS] = "Entry exists already",
			[NHRP_ERR_ENTRY_NOT_FOUND] = "Entry not found",
			[NHRP_ERR_PROTOCOL_ADDRESS_MISMATCH] =
				"Protocol address family does not match command (ip/ipv6 mismatch)",
	};
	const char *str = NULL;
	char buf[256];

	if (ret == NHRP_OK)
		return CMD_SUCCESS;

	if (ret > 0 && ret <= NHRP_ERR_MAX)
		if (errmsgs[ret])
			str = errmsgs[ret];

	if (!str) {
		str = buf;
		snprintf(buf, sizeof(buf), "Unknown error %d", ret);
	}

	vty_out(vty, "%% %s\n", str);

	return CMD_WARNING_CONFIG_FAILED;
	;
}

static int toggle_flag(struct vty *vty, const struct message *flag_desc,
		       const char *name, int on_off, unsigned *flags)
{
	int i;

	for (i = 0; flag_desc[i].str != NULL; i++) {
		if (strcmp(flag_desc[i].str, name) != 0)
			continue;
		if (on_off)
			*flags |= flag_desc[i].key;
		else
			*flags &= ~flag_desc[i].key;
		return CMD_SUCCESS;
	}

	vty_out(vty, "%% Invalid value %s\n", name);
	return CMD_WARNING_CONFIG_FAILED;
	;
}

#ifndef NO_DEBUG

DEFUN_NOSH(show_debugging_nhrp, show_debugging_nhrp_cmd,
	   "show debugging [nhrp]",
	   SHOW_STR
	   "Debugging information\n"
	   "NHRP configuration\n")
{
	int i;

	vty_out(vty, "NHRP debugging status:\n");

	for (i = 0; debug_flags_desc[i].str != NULL; i++) {
		if (debug_flags_desc[i].key == NHRP_DEBUG_ALL)
			continue;
		if (!(debug_flags_desc[i].key & debug_flags))
			continue;

		vty_out(vty, "  NHRP %s debugging is on\n",
			debug_flags_desc[i].str);
	}

	return CMD_SUCCESS;
}

DEFUN(debug_nhrp, debug_nhrp_cmd,
	"debug nhrp " NHRP_DEBUG_FLAGS_CMD,
	"Enable debug messages for specific or all parts.\n"
	"NHRP information\n"
	NHRP_DEBUG_FLAGS_STR)
{
	return toggle_flag(vty, debug_flags_desc, argv[2]->text, 1,
			   &debug_flags);
}

DEFUN(no_debug_nhrp, no_debug_nhrp_cmd,
	"no debug nhrp " NHRP_DEBUG_FLAGS_CMD,
	NO_STR
	"Disable debug messages for specific or all parts.\n"
	"NHRP information\n"
	NHRP_DEBUG_FLAGS_STR)
{
	return toggle_flag(vty, debug_flags_desc, argv[3]->text, 0,
			   &debug_flags);
}

#endif /* NO_DEBUG */

int nhrp_config_write_vrf(struct vty *vty, struct nhrp_vrf *nhrp_vrf)
{
	char indent[3];

	memset(indent, 0, sizeof(indent));
	if (nhrp_vrf->vrfname)
		snprintf(indent, sizeof(indent), " ");
	if (nhrp_vrf->nhrp_event_socket_path) {
		vty_out(vty, "%snhrp event socket %s\n",
			indent,
			nhrp_vrf->nhrp_event_socket_path);
	}
	if (nhrp_vrf->netlink_nflog_group) {
		vty_out(vty, "%snhrp nflog-group %d\n",
			indent,
			nhrp_vrf->netlink_nflog_group);
	}
	if (nhrp_vrf->netlink_mcast_nflog_group)
		vty_out(vty, "%snhrp multicast-nflog-group %d\n",
			indent,
			nhrp_vrf->netlink_mcast_nflog_group);

	return 0;
}

static int nhrp_config_write(struct vty *vty)
{
	struct nhrp_vrf *nhrp_vrf;

	nhrp_vrf = find_nhrp_vrf(NULL);
#ifndef NO_DEBUG
	if (debug_flags == NHRP_DEBUG_ALL) {
		vty_out(vty, "debug nhrp all\n");
	} else {
		int i;

		for (i = 0; debug_flags_desc[i].str != NULL; i++) {
			if (debug_flags_desc[i].key == NHRP_DEBUG_ALL)
				continue;
			if (!(debug_flags & debug_flags_desc[i].key))
				continue;
			vty_out(vty, "debug nhrp %s\n",
				debug_flags_desc[i].str);
		}
	}
	vty_out(vty, "!\n");
#endif /* NO_DEBUG */
	if (!nhrp_vrf)
		return 0;
	return nhrp_config_write_vrf(vty, nhrp_vrf);
}

#define IP_STR		"IP information\n"
#define IPV6_STR	"IPv6 information\n"
#define AFI_CMD		"<ip|ipv6>"
#define AFI_STR		IP_STR IPV6_STR
#define NHRP_STR	"Next Hop Resolution Protocol functions\n"

static afi_t cmd_to_afi(const struct cmd_token *tok)
{
	return strcmp(tok->text, "ipv6") == 0 ? AFI_IP6 : AFI_IP;
}

static const char *afi_to_cmd(afi_t afi)
{
	if (afi == AFI_IP6)
		return "ipv6";
	return "ip";
}

DEFUN(nhrp_event_socket, nhrp_event_socket_cmd,
	"nhrp event socket SOCKET",
	NHRP_STR
	"Event Manager commands\n"
	"Event Manager unix socket path\n"
	"Unix path for the socket\n")
{
	struct nhrp_vrf *nhrp_vrf;

	if (vty->node == CONFIG_NODE)
		nhrp_vrf = nhrp_get_context(NULL);
	else {
		struct vrf *vrf = VTY_GET_CONTEXT(vrf);

		if (vrf->vrf_id == VRF_DEFAULT)
			nhrp_vrf = nhrp_get_context(NULL);
		else
			nhrp_vrf = nhrp_get_context(vrf->name);
	}
	if (!nhrp_vrf)
		return CMD_WARNING_CONFIG_FAILED;
	evmgr_set_socket(nhrp_vrf, argv[3]->arg);
	return CMD_SUCCESS;
}

DEFUN(no_nhrp_event_socket, no_nhrp_event_socket_cmd,
	"no nhrp event socket [SOCKET]",
	NO_STR
	NHRP_STR
	"Event Manager commands\n"
	"Event Manager unix socket path\n"
	"Unix path for the socket\n")
{
	struct nhrp_vrf *nhrp_vrf;

	if (vty->node == CONFIG_NODE)
		nhrp_vrf = nhrp_get_context(NULL);
	else {
		struct vrf *vrf = VTY_GET_CONTEXT(vrf);

		if (vrf->vrf_id == VRF_DEFAULT)
			nhrp_vrf = nhrp_get_context(NULL);
		else
			nhrp_vrf = nhrp_get_context(vrf->name);
	}
	if (!nhrp_vrf)
		return CMD_WARNING_CONFIG_FAILED;
	evmgr_set_socket(nhrp_vrf, NULL);
	return CMD_SUCCESS;
}

DEFUN(nhrp_nflog_group, nhrp_nflog_group_cmd,
	"nhrp nflog-group (1-65535)",
	NHRP_STR
	"Specify NFLOG group number\n"
	"NFLOG group number\n")
{
	struct nhrp_vrf *nhrp_vrf;

	if (vty->node == CONFIG_NODE)
		nhrp_vrf = nhrp_get_context(NULL);
	else {
		struct vrf *vrf = VTY_GET_CONTEXT(vrf);

		if (vrf->vrf_id == VRF_DEFAULT)
			nhrp_vrf = nhrp_get_context(NULL);
		else
			nhrp_vrf = nhrp_get_context(vrf->name);
	}
	if (!nhrp_vrf)
		return CMD_WARNING_CONFIG_FAILED;
	netlink_set_nflog_group(nhrp_vrf, strtoul(argv[2]->arg, NULL, 10));

	return CMD_SUCCESS;
}

DEFUN(no_nhrp_nflog_group, no_nhrp_nflog_group_cmd,
	"no nhrp nflog-group [(1-65535)]",
	NO_STR
	NHRP_STR
	"Specify NFLOG group number\n"
	"NFLOG group number\n")
{
	struct nhrp_vrf *nhrp_vrf;

	if (vty->node == CONFIG_NODE)
		nhrp_vrf = nhrp_get_context(NULL);
	else {
		struct vrf *vrf = VTY_GET_CONTEXT(vrf);

		if (vrf->vrf_id == VRF_DEFAULT)
			nhrp_vrf = nhrp_get_context(NULL);
		else
			nhrp_vrf = nhrp_get_context(vrf->name);
	}
	if (!nhrp_vrf)
		return CMD_WARNING_CONFIG_FAILED;
	netlink_set_nflog_group(nhrp_vrf, 0);
	return CMD_SUCCESS;
}

DEFUN(nhrp_multicast_nflog_group, nhrp_multicast_nflog_group_cmd,
	"nhrp multicast-nflog-group (1-65535)",
	NHRP_STR
	"Specify NFLOG group number for Multicast Packets\n"
	"NFLOG group number\n")
{
	uint32_t nfgroup;
	struct nhrp_vrf *nhrp_vrf;

	if (vty->node == CONFIG_NODE)
		nhrp_vrf = nhrp_get_context(NULL);
	else {
		struct vrf *vrf = VTY_GET_CONTEXT(vrf);

		if (vrf->vrf_id == VRF_DEFAULT)
			nhrp_vrf = nhrp_get_context(NULL);
		else
			nhrp_vrf = nhrp_get_context(vrf->name);
	}
	if (!nhrp_vrf)
		return CMD_WARNING_CONFIG_FAILED;

	nfgroup = strtoul(argv[2]->arg, NULL, 10);
	netlink_mcast_set_nflog_group(nhrp_vrf, nfgroup);

	return CMD_SUCCESS;
}

DEFUN(no_nhrp_multicast_nflog_group, no_nhrp_multicast_nflog_group_cmd,
	"no nhrp multicast-nflog-group [(1-65535)]",
	NO_STR
	NHRP_STR
	"Specify NFLOG group number\n"
	"NFLOG group number\n")
{
	struct nhrp_vrf *nhrp_vrf;

	if (vty->node == CONFIG_NODE)
		nhrp_vrf = nhrp_get_context(NULL);
	else {
		struct vrf *vrf = VTY_GET_CONTEXT(vrf);

		if (vrf->vrf_id == VRF_DEFAULT)
			nhrp_vrf = nhrp_get_context(NULL);
		else
			nhrp_vrf = nhrp_get_context(vrf->name);
	}
	if (!nhrp_vrf)
		return CMD_WARNING_CONFIG_FAILED;

	netlink_mcast_set_nflog_group(nhrp_vrf, 0);
	return CMD_SUCCESS;
}

DEFUN(tunnel_protection, tunnel_protection_cmd,
	"tunnel protection vici profile PROFILE [fallback-profile FALLBACK]",
	"NHRP/GRE integration\n"
	"IPsec protection\n"
	"VICI (StrongSwan)\n"
	"IPsec profile\n"
	"IPsec profile name\n"
	"Fallback IPsec profile\n"
	"Fallback IPsec profile name\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	nhrp_interface_set_protection(ifp, argv[4]->arg,
				      argc > 6 ? argv[6]->arg : NULL);
	return CMD_SUCCESS;
}

DEFUN(no_tunnel_protection, no_tunnel_protection_cmd,
	"no tunnel protection",
	NO_STR
	"NHRP/GRE integration\n"
	"IPsec protection\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	nhrp_interface_set_protection(ifp, NULL, NULL);
	return CMD_SUCCESS;
}

DEFUN(tunnel_source, tunnel_source_cmd,
	"tunnel source INTERFACE [vrf VRFNAME]",
	"NHRP/GRE integration\n"
	"Tunnel device binding tracking\n"
	"Interface name\n"
	VRF_CMD_HELP_STR)
{
	char *vrfname = NULL;

	VTY_DECLVAR_CONTEXT(interface, ifp);
	if (argc == 5)
		vrfname = argv[4]->arg;
	nhrp_interface_set_source(ifp, argv[2]->arg, vrfname);
	return CMD_SUCCESS;
}

DEFUN(no_tunnel_source, no_tunnel_source_cmd,
	"no tunnel source",
	"NHRP/GRE integration\n"
	"Tunnel device binding tracking\n"
	"Interface name\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	nhrp_interface_set_source(ifp, NULL, NULL);
	return CMD_SUCCESS;
}

DEFUN(if_nhrp_network_id, if_nhrp_network_id_cmd,
	AFI_CMD " nhrp network-id (1-4294967295)",
	AFI_STR
	NHRP_STR
	"Enable NHRP and specify network-id\n"
	"System local ID to specify interface group\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct nhrp_interface *nifp = ifp->info;
	afi_t afi = cmd_to_afi(argv[0]);

	nifp->afi[afi].network_id = strtoul(argv[3]->arg, NULL, 10);
	nhrp_interface_update(ifp);

	return CMD_SUCCESS;
}

DEFUN(if_no_nhrp_network_id, if_no_nhrp_network_id_cmd,
	"no " AFI_CMD " nhrp network-id [(1-4294967295)]",
	NO_STR
	AFI_STR
	NHRP_STR
	"Enable NHRP and specify network-id\n"
	"System local ID to specify interface group\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct nhrp_interface *nifp = ifp->info;
	afi_t afi = cmd_to_afi(argv[1]);

	nifp->afi[afi].network_id = 0;
	nhrp_interface_update(ifp);

	return CMD_SUCCESS;
}

DEFUN(if_nhrp_flags, if_nhrp_flags_cmd,
	AFI_CMD " nhrp <shortcut|redirect|shortcut-keep-sa>",
	AFI_STR
	NHRP_STR
	"Allow shortcut establishment\n"
	"Send redirect notifications\n"
	"Maintain Secured Connection on Shortcut, upon expiration\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct nhrp_interface *nifp = ifp->info;
	afi_t afi = cmd_to_afi(argv[0]);

	return toggle_flag(vty, interface_flags_desc, argv[2]->text, 1,
			   &nifp->afi[afi].flags);
}

DEFUN(if_no_nhrp_flags, if_no_nhrp_flags_cmd,
	"no " AFI_CMD " nhrp <shortcut|redirect|shortcut-keep-sa>",
	NO_STR
	AFI_STR
	NHRP_STR
	"Allow shortcut establishment\n"
	"Send redirect notifications\n"
	"Close Secured Connection on Shortcut, upon expiration\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct nhrp_interface *nifp = ifp->info;
	afi_t afi = cmd_to_afi(argv[1]);

	return toggle_flag(vty, interface_flags_desc, argv[3]->text, 0,
			   &nifp->afi[afi].flags);
}

DEFUN(if_nhrp_reg_flags, if_nhrp_reg_flags_cmd,
	AFI_CMD " nhrp registration no-unique",
	AFI_STR
	NHRP_STR
	"Registration configuration\n"
	"Don't set unique flag\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct nhrp_interface *nifp = ifp->info;
	afi_t afi = cmd_to_afi(argv[0]);
	char name[256];
	snprintf(name, sizeof(name), "registration %s", argv[3]->text);
	return toggle_flag(vty, interface_flags_desc, name, 1,
			   &nifp->afi[afi].flags);
}

DEFUN(if_no_nhrp_reg_flags, if_no_nhrp_reg_flags_cmd,
	"no " AFI_CMD " nhrp registration no-unique",
	NO_STR
	AFI_STR
	NHRP_STR
	"Registration configuration\n"
	"Don't set unique flag\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct nhrp_interface *nifp = ifp->info;
	afi_t afi = cmd_to_afi(argv[1]);
	char name[256];
	snprintf(name, sizeof(name), "registration %s", argv[4]->text);
	return toggle_flag(vty, interface_flags_desc, name, 0,
			   &nifp->afi[afi].flags);
}

DEFUN(if_nhrp_holdtime, if_nhrp_holdtime_cmd,
	AFI_CMD " nhrp holdtime (1-65000)",
	AFI_STR
	NHRP_STR
	"Specify NBMA address validity time\n"
	"Time in seconds that NBMA addresses are advertised valid\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct nhrp_interface *nifp = ifp->info;
	afi_t afi = cmd_to_afi(argv[0]);

	nifp->afi[afi].holdtime = strtoul(argv[3]->arg, NULL, 10);
	nhrp_interface_update(ifp);

	return CMD_SUCCESS;
}

DEFUN(if_no_nhrp_holdtime, if_no_nhrp_holdtime_cmd,
	"no " AFI_CMD " nhrp holdtime [(1-65000)]",
	NO_STR
	AFI_STR
	NHRP_STR
	"Specify NBMA address validity time\n"
	"Time in seconds that NBMA addresses are advertised valid\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct nhrp_interface *nifp = ifp->info;
	afi_t afi = cmd_to_afi(argv[1]);

	nifp->afi[afi].holdtime = NHRPD_DEFAULT_HOLDTIME;
	nhrp_interface_update(ifp);

	return CMD_SUCCESS;
}

DEFUN(if_nhrp_mtu, if_nhrp_mtu_cmd,
	"ip nhrp mtu <(576-1500)|opennhrp>",
	IP_STR
	NHRP_STR
	"Configure NHRP advertised MTU\n"
	"MTU value\n"
	"Advertise bound interface MTU similar to OpenNHRP\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct nhrp_interface *nifp = ifp->info;

	if (argv[3]->arg[0] == 'o') {
		nifp->afi[AFI_IP].configured_mtu = -1;
	} else {
		nifp->afi[AFI_IP].configured_mtu =
			strtoul(argv[3]->arg, NULL, 10);
	}
	nhrp_interface_update_mtu(ifp, AFI_IP);

	return CMD_SUCCESS;
}

DEFUN(if_no_nhrp_mtu, if_no_nhrp_mtu_cmd,
	"no ip nhrp mtu [(576-1500)|opennhrp]",
	NO_STR
	IP_STR
	NHRP_STR
	"Configure NHRP advertised MTU\n"
	"MTU value\n"
	"Advertise bound interface MTU similar to OpenNHRP\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct nhrp_interface *nifp = ifp->info;

	nifp->afi[AFI_IP].configured_mtu = 0;
	nhrp_interface_update_mtu(ifp, AFI_IP);
	return CMD_SUCCESS;
}

DEFUN(if_nhrp_map, if_nhrp_map_cmd,
	AFI_CMD " nhrp map <A.B.C.D|X:X::X:X> <A.B.C.D|local>",
	AFI_STR
	NHRP_STR
	"Nexthop Server configuration\n"
	"IPv4 protocol address\n"
	"IPv6 protocol address\n"
	"IPv4 NBMA address\n"
	"Handle protocol address locally\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	afi_t afi = cmd_to_afi(argv[0]);
	union sockunion proto_addr, nbma_addr;
	struct nhrp_cache_config *cc;
	struct nhrp_cache *c;
	enum nhrp_cache_type type;

	if (str2sockunion(argv[3]->arg, &proto_addr) < 0
	    || afi2family(afi) != sockunion_family(&proto_addr))
		return nhrp_vty_return(vty, NHRP_ERR_PROTOCOL_ADDRESS_MISMATCH);

	if (strmatch(argv[4]->text, "local"))
		type = NHRP_CACHE_LOCAL;
	else {
		if (str2sockunion(argv[4]->arg, &nbma_addr) < 0)
			return nhrp_vty_return(vty, NHRP_ERR_FAIL);
		type = NHRP_CACHE_STATIC;
	}
	cc = nhrp_cache_config_get(ifp, &proto_addr, 1);
	if (!cc)
		return nhrp_vty_return(vty, NHRP_ERR_FAIL);
	cc->nbma = nbma_addr;
	cc->type = type;
	/* gre layer not ready */
	if (ifp->ifindex == IFINDEX_INTERNAL)
		return CMD_SUCCESS;

	c = nhrp_cache_get(ifp, &proto_addr, 1);
	if (!c)
		return nhrp_vty_return(vty, NHRP_ERR_FAIL);

	c->map = 1;
	if (type == NHRP_CACHE_LOCAL)
		nhrp_cache_update_binding(c, NHRP_CACHE_LOCAL, 0, NULL, 0,
					  NULL, NULL);
	else
		nhrp_cache_update_binding(c, NHRP_CACHE_STATIC, 0,
					  nhrp_peer_get(ifp, &nbma_addr), 0,
					  NULL, NULL);
	return CMD_SUCCESS;
}

DEFUN(if_no_nhrp_map, if_no_nhrp_map_cmd,
	"no " AFI_CMD " nhrp map <A.B.C.D|X:X::X:X> [<A.B.C.D|local>]",
	NO_STR
	AFI_STR
	NHRP_STR
	"Nexthop Server configuration\n"
	"IPv4 protocol address\n"
	"IPv6 protocol address\n"
	"IPv4 NBMA address\n"
	"Handle protocol address locally\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	afi_t afi = cmd_to_afi(argv[1]);
	union sockunion proto_addr, nbma_addr;
	struct nhrp_cache_config *cc;
	struct nhrp_cache *c;

	if (str2sockunion(argv[4]->arg, &proto_addr) < 0
	    || afi2family(afi) != sockunion_family(&proto_addr))
		return nhrp_vty_return(vty, NHRP_ERR_PROTOCOL_ADDRESS_MISMATCH);

	cc = nhrp_cache_config_get(ifp, &proto_addr, 0);
	if (!cc)
		return nhrp_vty_return(vty, NHRP_ERR_FAIL);
	nhrp_cache_config_free(cc);

	c = nhrp_cache_get(ifp, &proto_addr, 0);
	/* silently return */
	if (!c || !c->map)
		return CMD_SUCCESS;

	nhrp_cache_update_binding(c, c->cur.type, -1,
				  nhrp_peer_get(ifp, &nbma_addr), 0, NULL,
				  NULL);
	return CMD_SUCCESS;
}

DEFUN(if_nhrp_map_multicast, if_nhrp_map_multicast_cmd,
	AFI_CMD " nhrp map multicast <A.B.C.D|X:X::X:X|dynamic>",
	AFI_STR
	NHRP_STR
	"Multicast NBMA Configuration\n"
	"Use this NBMA mapping for multicasts\n"
	"IPv4 NBMA address\n"
	"IPv6 NBMA address\n"
	"Dynamically learn destinations from client registrations on hub\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	afi_t afi = cmd_to_afi(argv[0]);
	union sockunion nbma_addr;
	int ret;

	if (str2sockunion(argv[4]->arg, &nbma_addr) < 0)
		sockunion_family(&nbma_addr) = AF_UNSPEC;

	ret = nhrp_multicast_add(ifp, afi, &nbma_addr);

	return nhrp_vty_return(vty, ret);
}

DEFUN(if_no_nhrp_map_multicast, if_no_nhrp_map_multicast_cmd,
	"no " AFI_CMD " nhrp map multicast <A.B.C.D|X:X::X:X|dynamic>",
	NO_STR
	AFI_STR
	NHRP_STR
	"Multicast NBMA Configuration\n"
	"Use this NBMA mapping for multicasts\n"
	"IPv4 NBMA address\n"
	"IPv6 NBMA address\n"
	"Dynamically learn destinations from client registrations on hub\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	afi_t afi = cmd_to_afi(argv[1]);
	union sockunion nbma_addr;
	int ret;

	if (str2sockunion(argv[5]->arg, &nbma_addr) < 0)
		sockunion_family(&nbma_addr) = AF_UNSPEC;

	ret = nhrp_multicast_del(ifp, afi, &nbma_addr);

	return nhrp_vty_return(vty, ret);
}

DEFUN(if_nhrp_nhs, if_nhrp_nhs_cmd,
	AFI_CMD " nhrp nhs <A.B.C.D|X:X::X:X|dynamic> nbma <A.B.C.D|FQDN>",
	AFI_STR
	NHRP_STR
	"Nexthop Server configuration\n"
	"IPv4 protocol address\n"
	"IPv6 protocol address\n"
	"Automatic detection of protocol address\n"
	"NBMA address\n"
	"IPv4 NBMA address\n"
	"Fully qualified domain name for NBMA address(es)\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	afi_t afi = cmd_to_afi(argv[0]);
	union sockunion proto_addr;
	int ret;

	if (str2sockunion(argv[3]->arg, &proto_addr) < 0)
		sockunion_family(&proto_addr) = AF_UNSPEC;

	ret = nhrp_nhs_add(ifp, afi, &proto_addr, argv[5]->arg);
	return nhrp_vty_return(vty, ret);
}

DEFUN(if_no_nhrp_nhs, if_no_nhrp_nhs_cmd,
	"no " AFI_CMD " nhrp nhs <A.B.C.D|X:X::X:X|dynamic> nbma <A.B.C.D|FQDN>",
	NO_STR
	AFI_STR
	NHRP_STR
	"Nexthop Server configuration\n"
	"IPv4 protocol address\n"
	"IPv6 protocol address\n"
	"Automatic detection of protocol address\n"
	"NBMA address\n"
	"IPv4 NBMA address\n"
	"Fully qualified domain name for NBMA address(es)\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	afi_t afi = cmd_to_afi(argv[1]);
	union sockunion proto_addr;
	int ret;

	if (str2sockunion(argv[4]->arg, &proto_addr) < 0)
		sockunion_family(&proto_addr) = AF_UNSPEC;

	ret = nhrp_nhs_del(ifp, afi, &proto_addr, argv[6]->arg);
	return nhrp_vty_return(vty, ret);
}

struct info_ctx {
	struct vty *vty;
	afi_t afi;
	int count;
	struct json_object *json;
};

static void show_ip_nhrp_cache(struct nhrp_cache *c, void *pctx)
{
	struct info_ctx *ctx = pctx;
	struct vty *vty = ctx->vty;
	char buf[3][SU_ADDRSTRLEN];
	struct json_object *json = NULL;

	if (ctx->afi != family2afi(sockunion_family(&c->remote_addr)))
		return;


	if (!ctx->count && !ctx->json) {
		vty_out(vty, "%-8s %-8s %-24s %-24s %-24s %-6s %s\n", "Iface",
			"Type", "Protocol", "NBMA", "Claimed NBMA", "Flags",
			"Identity");
	}
	ctx->count++;

	sockunion2str(&c->remote_addr, buf[0], sizeof(buf[0]));
	if (c->cur.type == NHRP_CACHE_LOCAL) {
		struct nhrp_interface *nifp = c->ifp->info;

		if (sockunion_family(&nifp->nbma) != AF_UNSPEC) {
			sockunion2str(&nifp->nbma, buf[1], sizeof(buf[1]));
			sockunion2str(&nifp->nbma, buf[2], sizeof(buf[2]));
		} else {
			snprintf(buf[1], sizeof(buf[1]), "-");
			snprintf(buf[2], sizeof(buf[2]), "-");
		}

		/* if we are behind NAT then update NBMA field */
		if (sockunion_family(&nifp->nat_nbma) != AF_UNSPEC)
			sockunion2str(&nifp->nat_nbma, buf[1], sizeof(buf[1]));
	} else {
		if (c->cur.peer)
			sockunion2str(&c->cur.peer->vc->remote.nbma,
				      buf[1], sizeof(buf[1]));
		else
			snprintf(buf[1], sizeof(buf[1]), "-");

		if (c->cur.peer
		    && sockunion_family(&c->cur.remote_nbma_claimed)
		    != AF_UNSPEC)
			sockunion2str(&c->cur.remote_nbma_claimed,
				      buf[2], sizeof(buf[2]));
		else
			snprintf(buf[2], sizeof(buf[2]), "-");
	}

	if (ctx->json) {
		json = json_object_new_object();
		json_object_string_add(json, "interface", c->ifp->name);
		json_object_string_add(json, "type",
				       nhrp_cache_type_str[c->cur.type]);
		json_object_string_add(json, "protocol", buf[0]);
		json_object_string_add(json, "nbma", buf[1]);
		json_object_string_add(json, "claimed_nbma", buf[2]);

		if (c->used)
			json_object_boolean_true_add(json, "used");
		else
			json_object_boolean_false_add(json, "used");

		if (c->t_timeout)
			json_object_boolean_true_add(json, "timeout");
		else
			json_object_boolean_false_add(json, "timeout");

		if (c->t_auth)
			json_object_boolean_true_add(json, "auth");
		else
			json_object_boolean_false_add(json, "auth");

		if (c->cur.peer)
			json_object_string_add(json, "identity",
					       c->cur.peer->vc->remote.id);
		else
			json_object_string_add(json, "identity", "-");

		json_object_array_add(ctx->json, json);
		return;
	}
	vty_out(ctx->vty, "%-8s %-8s %-24s %-24s %-24s %c%c%c    %s\n",
		c->ifp->name,
		nhrp_cache_type_str[c->cur.type],
		buf[0], buf[1], buf[2],
		c->used ? 'U' : ' ', c->t_timeout ? 'T' : ' ',
		c->t_auth ? 'A' : ' ',
		c->cur.peer ? c->cur.peer->vc->remote.id : "-");
}

static void show_ip_nhrp_nhs(struct nhrp_nhs *n, struct nhrp_registration *reg,
			     void *pctx)
{
	struct info_ctx *ctx = pctx;
	struct vty *vty = ctx->vty;
	char buf[2][SU_ADDRSTRLEN];
	struct json_object *json = NULL;

	if (!ctx->count && !ctx->json) {
		vty_out(vty, "%-8s %-24s %-16s %-16s\n", "Iface", "FQDN",
			"NBMA", "Protocol");
	}
	ctx->count++;

	if (reg && reg->peer)
		sockunion2str(&reg->peer->vc->remote.nbma, buf[0],
			      sizeof(buf[0]));
	else
		snprintf(buf[0], sizeof(buf[0]), "-");
	sockunion2str(reg ? &reg->proto_addr : &n->proto_addr, buf[1],
		      sizeof(buf[1]));

	if (ctx->json) {
		json = json_object_new_object();
		json_object_string_add(json, "interface", n->ifp->name);
		json_object_string_add(json, "fqdn", n->nbma_fqdn);
		json_object_string_add(json, "nbma", buf[0]);
		json_object_string_add(json, "protocol", buf[1]);

		json_object_array_add(ctx->json, json);
		return;
	}

	vty_out(vty, "%-8s %-24s %-16s %-16s\n", n->ifp->name, n->nbma_fqdn,
		buf[0], buf[1]);
}

static void show_ip_nhrp_shortcut(struct nhrp_shortcut *s, void *pctx)
{
	struct info_ctx *ctx = pctx;
	struct nhrp_cache *c;
	struct vty *vty = ctx->vty;
	char buf1[PREFIX_STRLEN], buf2[SU_ADDRSTRLEN];
	struct json_object *json = NULL;

	if (!ctx->count) {
		vty_out(vty, "%-8s %-24s %-24s %s\n", "Type", "Prefix", "Via",
			"Identity");
	}
	ctx->count++;

	c = s->cache;
	if (c)
		sockunion2str(&c->remote_addr, buf2, sizeof(buf2));
	else
		buf2[0] = '\0';
	prefix2str(s->p, buf1, sizeof(buf1));

	if (ctx->json) {
		json = json_object_new_object();
		json_object_string_add(json, "type",
				       nhrp_cache_type_str[s->type]);
		json_object_string_add(json, "prefix", buf1);

		if (c)
			json_object_string_add(json, "via", buf2);

		if (c && c->cur.peer)
			json_object_string_add(json, "identity",
					       c->cur.peer->vc->remote.id);
		else
			json_object_string_add(json, "identity", "");

		json_object_array_add(ctx->json, json);
		return;
	}

	vty_out(ctx->vty, "%-8s %-24s %-24s %s\n",
		nhrp_cache_type_str[s->type],
		buf1, buf2,
		(c && c->cur.peer) ? c->cur.peer->vc->remote.id : "");
}

static void show_ip_opennhrp_cache(struct nhrp_cache *c, void *pctx)
{
	struct info_ctx *ctx = pctx;
	char buf[3][SU_ADDRSTRLEN];
	struct json_object *json = NULL;


	if (ctx->afi != family2afi(sockunion_family(&c->remote_addr)))
		return;

	if (ctx->count)
		vty_out(ctx->vty, "\n");
	ctx->count++;

	sockunion2str(&c->remote_addr, buf[0], sizeof(buf[0]));
	if (c->cur.peer)
		sockunion2str(&c->cur.peer->vc->remote.nbma, buf[1],
			      sizeof(buf[1]));
	if (sockunion_family(&c->cur.remote_nbma_natoa) != AF_UNSPEC)
		sockunion2str(&c->cur.remote_nbma_natoa, buf[2],
			      sizeof(buf[2]));
	if (ctx->json) {
		json = json_object_new_object();
		json_object_string_add(json, "type",
				       nhrp_cache_type_str[c->cur.type]);

		if (c->cur.peer && c->cur.peer->online)
			json_object_boolean_true_add(json, "up");
		else
			json_object_boolean_false_add(json, "up");

		if (c->used)
			json_object_boolean_true_add(json, "used");
		else
			json_object_boolean_false_add(json, "used");

		json_object_string_add(json, "protocolAddress", buf[0]);
		json_object_int_add(json, "protocolAddressSize",
				    8 * family2addrsize(sockunion_family
							(&c->remote_addr)));

		if (c->cur.peer)
			json_object_string_add(json, "nbmaAddress", buf[1]);

		if (sockunion_family(&c->cur.remote_nbma_natoa) != AF_UNSPEC)
			json_object_string_add(json, "nbmaNatOaAddress",
					       buf[2]);

		json_object_array_add(ctx->json, json);
		return;
	}
	vty_out(ctx->vty,
		"Type: %s\n"
		"Flags:%s%s\n"
		"Protocol-Address: %s/%zu\n",
		nhrp_cache_type_str[c->cur.type],
		(c->cur.peer && c->cur.peer->online) ? " up" : "",
		c->used ? " used" : "",
		buf[0],
		8 * family2addrsize(sockunion_family(&c->remote_addr)));

	if (c->cur.peer)
		vty_out(ctx->vty, "NBMA-Address: %s\n", buf[1]);

	if (sockunion_family(&c->cur.remote_nbma_natoa) != AF_UNSPEC)
		vty_out(ctx->vty, "NBMA-NAT-OA-Address: %s\n", buf[2]);
}

DEFPY(show_ip_nhrp, show_ip_nhrp_cmd,
	"show <ip$ip|ipv6$ipv6> nhrp [cache$cache|nhs$nhs|shortcut$shcut|opennhrp$open] [vrf <NAME$vrf_name|all$vrf_all>] [json$uj]",
	SHOW_STR
	AFI_STR
	"NHRP information\n"
	"Forwarding cache information\n"
	"Next hop server information\n"
	"Shortcut information\n"
	"opennhrpctl style cache dump\n"
	VRF_FULL_CMD_HELP_STR
	JSON_STR)
{
	struct vrf *vrf;
	struct interface *ifp;
	struct info_ctx ctx = {
		.vty = vty, .json = NULL
	};
	struct json_object *json_path = NULL, *json_all_path = NULL;
	struct json_object *json_vrf = NULL, *json_vrf_path = NULL;
	int ret = CMD_SUCCESS;
	struct nhrp_vrf *nhrp_vrf = NULL, *nhrp_vrf2;
	struct listnode *nhrp_vrf_node;
	bool lf = false;

	if (ip)
		ctx.afi = AFI_IP;
	else
		ctx.afi = AFI_IP6;
	if (vrf_name) {
		nhrp_vrf = find_nhrp_vrf(vrf_name);
		if (!nhrp_vrf)
		    return CMD_SUCCESS;
	} else if (!vrf_all)
		nhrp_vrf = find_nhrp_vrf(NULL);

	if (uj)
		json_all_path = json_object_new_object();
	for (ALL_LIST_ELEMENTS_RO(nhrp_vrf_list, nhrp_vrf_node, nhrp_vrf2)) {
		if (nhrp_vrf && nhrp_vrf != nhrp_vrf2)
			continue;
		vrf = vrf_lookup_by_id(nhrp_vrf2->vrf_id);
		if (!vrf)
			continue;
		if (uj) {
			json_vrf = json_object_new_object();
			json_vrf_path = json_object_new_object();
			json_object_string_add(json_vrf, "vrf", vrf->name);
			json_path = json_object_new_array();
			ctx.json = json_path;
		} else {
			if (vrf_all && lf)
				vty_out(vty, "\n\n");
			lf = true;
			if (vrf_all || vrf->vrf_id != VRF_DEFAULT)
				vty_out(vty, "VRF %s:\n", vrf->name);
		}
		if (cache) {
			FOR_ALL_INTERFACES (vrf, ifp)
				nhrp_cache_foreach(ifp, show_ip_nhrp_cache, &ctx);
		} else if (nhs) {
			FOR_ALL_INTERFACES (vrf, ifp)
				nhrp_nhs_foreach(ifp, ctx.afi,
						 show_ip_nhrp_nhs, &ctx);
		} else if (shcut) {
			nhrp_shortcut_foreach(ctx.afi, show_ip_nhrp_shortcut, &ctx,
					      nhrp_vrf2);
		} else {
			if (ctx.json)
				json_object_string_add(json_vrf, "status", "ok");
			ctx.count++;
			FOR_ALL_INTERFACES (vrf, ifp)
				nhrp_cache_foreach(ifp, show_ip_opennhrp_cache,
						   &ctx);
		}
		if (uj)
			json_object_int_add(json_vrf, "entriesCount", ctx.count);
		if (!ctx.count) {
			if (!ctx.json)
				vty_out(vty, "%% No entries\n");
			ret = CMD_WARNING;
		}
		if (uj) {
			json_object_object_add(json_vrf_path, "attr", json_vrf);
			json_object_object_add(json_vrf_path, "table", ctx.json);
			json_object_object_add(json_all_path, vrf->name, json_vrf_path);
		}
	}
	if (uj) {
		vty_out(vty, "%s",
			json_object_to_json_string_ext(
			       json_all_path, JSON_C_TO_STRING_PRETTY));
		json_object_free(json_all_path);
	}
	return ret;
}

struct dmvpn_cfg {
	struct vty *vty;
	struct json_object *json;
};

static void show_dmvpn_entry(struct nhrp_vc *vc, void *ctx)
{
	struct dmvpn_cfg *ctxt = ctx;
	struct vty *vty;
	char buf[2][SU_ADDRSTRLEN];
	struct json_object *json = NULL;

	if (!ctxt || !ctxt->vty)
		return;
	vty = ctxt->vty;
	sockunion2str(&vc->local.nbma, buf[0], sizeof(buf[0]));
	sockunion2str(&vc->remote.nbma, buf[1], sizeof(buf[1]));
	if (ctxt->json) {
		json = json_object_new_object();
		json_object_string_add(json, "src", buf[0]);
		json_object_string_add(json, "dst", buf[1]);

		if (notifier_active(&vc->notifier_list))
			json_object_boolean_true_add(json, "notifierActive");
		else
			json_object_boolean_false_add(json, "notifierActive");

		json_object_int_add(json, "sas", vc->ipsec);
		json_object_string_add(json, "identity", vc->remote.id);
		json_object_array_add(ctxt->json, json);
	} else {
		vty_out(vty, "%-24s %-24s %c      %-4d %-24s\n",
			buf[0], buf[1], notifier_active(&vc->notifier_list) ?
			'n' : ' ', vc->ipsec, vc->remote.id);
	}
}

DEFPY(show_dmvpn, show_dmvpn_cmd,
	"show dmvpn [vrf <NAME$vrf_name|all$vrf_all>] [json$uj]",
	SHOW_STR
	"DMVPN information\n"
	VRF_FULL_CMD_HELP_STR
	JSON_STR)
{
	bool lf = false;
	struct dmvpn_cfg ctxt;
	struct json_object *json_path = NULL;
	struct nhrp_vrf *nhrp_vrf = NULL, *nhrp_vrf2;
	struct listnode *nhrp_vrf_node;
	struct json_object *json_vrf = NULL;
	struct vrf *vrf;

	if (vrf_name) {
		nhrp_vrf = find_nhrp_vrf(vrf_name);
		if (!nhrp_vrf)
			return CMD_SUCCESS;
	} else if (!vrf_all)
		nhrp_vrf = find_nhrp_vrf(NULL);
	if (uj)
		json_vrf = json_object_new_object();
	for (ALL_LIST_ELEMENTS_RO(nhrp_vrf_list, nhrp_vrf_node, nhrp_vrf2)) {
		if (nhrp_vrf && nhrp_vrf != nhrp_vrf2)
			continue;
		vrf = vrf_lookup_by_id(nhrp_vrf2->vrf_id);
		if (!vrf)
			continue;
		ctxt.vty = vty;
		if (!uj) {
			ctxt.json = NULL;
			if (vrf_all && lf)
				vty_out(vty, "\n\n");
			lf = true;
			if (vrf_all && nhrp_vrf2->vrf_id != VRF_DEFAULT)
				vty_out(vty, "VRF %s:\n", vrf->name);
			if (nhrp_vc_count(nhrp_vrf2))
				vty_out(vty, "%-24s %-24s %-6s %-4s %-24s\n",
					"Src", "Dst", "Flags", "SAs", "Identity");
			else
				vty_out(vty, "%% VRF %s: No entries\n", vrf->name);
		} else {
			json_path = json_object_new_array();
			ctxt.json = json_path;
		}
		nhrp_vc_foreach(show_dmvpn_entry, &ctxt, nhrp_vrf);
		if (uj)
			json_object_object_add(json_vrf, vrf->name, ctxt.json);
	}
	if (uj) {
		vty_out(vty, "%s",
			json_object_to_json_string_ext(
			       json_vrf, JSON_C_TO_STRING_PRETTY));
			json_object_free(json_vrf);
	}
	return CMD_SUCCESS;
}

static void clear_nhrp_cache(struct nhrp_cache *c, void *data)
{
	struct info_ctx *ctx = data;
	if (c->cur.type <= NHRP_CACHE_DYNAMIC) {
		nhrp_cache_update_binding(c, c->cur.type, -1, NULL, 0, NULL,
					  NULL);
		ctx->count++;
	}
}

static void clear_nhrp_shortcut(struct nhrp_shortcut *s, void *data)
{
	struct info_ctx *ctx = data;
	nhrp_shortcut_purge(s, 1);
	ctx->count++;
}

DEFPY(clear_nhrp, clear_nhrp_cmd,
	"clear  <ip$ipv4|ipv6$ipv6> nhrp <cache$cache|shortcut$shortcut> [vrf <NAME$vrf_name|all$vrf_all>]",
	CLEAR_STR
	AFI_STR
	NHRP_STR
	"Dynamic cache entries\n"
	"Shortcut entries\n"
	VRF_FULL_CMD_HELP_STR)
{
	struct vrf *vrf;
	struct interface *ifp;
	struct info_ctx ctx = {
		.vty = vty, .afi = cmd_to_afi(argv[1]), .count = 0,
	};
	struct nhrp_vrf *nhrp_vrf = NULL, *nhrp_vrf2;
	struct listnode *nhrp_vrf_node;

	if (vrf_name) {
		nhrp_vrf = find_nhrp_vrf(vrf_name);
		if (!nhrp_vrf)
			return CMD_SUCCESS;
	} else if (!vrf_all)
		nhrp_vrf = find_nhrp_vrf(NULL);

	for (ALL_LIST_ELEMENTS_RO(nhrp_vrf_list, nhrp_vrf_node, nhrp_vrf2)) {
		if (nhrp_vrf && nhrp_vrf != nhrp_vrf2)
			continue;
		vrf = vrf_lookup_by_id(nhrp_vrf2->vrf_id);
		if (!vrf)
			continue;
		if (cache) {
			FOR_ALL_INTERFACES (vrf, ifp)
				nhrp_cache_foreach(ifp, clear_nhrp_cache, &ctx);
		} else {
			nhrp_shortcut_foreach(ctx.afi, clear_nhrp_shortcut, &ctx,
					      nhrp_vrf2);
		}

		if (!ctx.count) {
			vty_out(vty, "%% No entries\n");
			return CMD_WARNING;
		}
		vty_out(vty, "%% %d entries cleared\n", ctx.count);
	}

	return CMD_SUCCESS;
}

struct write_map_ctx {
	struct vty *vty;
	int family;
	const char *aficmd;
};

static void interface_config_write_nhrp_map(struct nhrp_cache_config *c,
					    void *data)
{
	struct write_map_ctx *ctx = data;
	struct vty *vty = ctx->vty;

	if (sockunion_family(&c->remote_addr) != ctx->family)
		return;

	vty_out(vty, " %s nhrp map %pSU ", ctx->aficmd, &c->remote_addr);
	if (c->type == NHRP_CACHE_LOCAL)
		vty_out(vty, "local\n");
	else
		vty_out(vty, "%pSU\n", &c->nbma);
}

static void interface_vrf_config_write(struct vty *vty, struct vrf *vrf)
{
	struct write_map_ctx mapctx;
	struct interface *ifp;
	struct nhrp_interface *nifp;
	struct nhrp_nhs *nhs;
	struct nhrp_multicast *mcast;
	const char *aficmd;
	afi_t afi;
	int i;

	FOR_ALL_INTERFACES (vrf, ifp) {
		vty_frame(vty, "interface %s%s%s\n",
			  ifp->name,
			  vrf->vrf_id != VRF_DEFAULT ? " vrf " : "",
			  vrf->vrf_id != VRF_DEFAULT ? vrf->name : "");
		if (ifp->desc)
			vty_out(vty, " description %s\n", ifp->desc);

		nifp = ifp->info;
		if (nifp->ipsec_profile) {
			vty_out(vty, " tunnel protection vici profile %s",
				nifp->ipsec_profile);
			if (nifp->ipsec_fallback_profile)
				vty_out(vty, " fallback-profile %s",
					nifp->ipsec_fallback_profile);
			vty_out(vty, "\n");
		}
		if (nifp->source) {
			vty_out(vty, " tunnel source %s", nifp->source);
			if (nifp->vrfname)
				vty_out(vty, " vrf %s", nifp->vrfname);
			vty_out(vty, "\n");
		}
		for (afi = 0; afi < AFI_MAX; afi++) {
			struct nhrp_afi_data *ad = &nifp->afi[afi];

			aficmd = afi_to_cmd(afi);

			if (ad->network_id)
				vty_out(vty, " %s nhrp network-id %u\n", aficmd,
					ad->network_id);

			if (ad->holdtime != NHRPD_DEFAULT_HOLDTIME)
				vty_out(vty, " %s nhrp holdtime %u\n", aficmd,
					ad->holdtime);

			if (ad->configured_mtu < 0)
				vty_out(vty, " %s nhrp mtu opennhrp\n", aficmd);
			else if (ad->configured_mtu)
				vty_out(vty, " %s nhrp mtu %u\n", aficmd,
					ad->configured_mtu);

			for (i = 0; interface_flags_desc[i].str != NULL; i++) {
				if (!(ad->flags & interface_flags_desc[i].key))
					continue;
				vty_out(vty, " %s nhrp %s\n", aficmd,
					interface_flags_desc[i].str);
			}

			mapctx = (struct write_map_ctx){
				.vty = vty,
				.family = afi2family(afi),
				.aficmd = aficmd,
			};
			nhrp_cache_config_foreach(
				ifp, interface_config_write_nhrp_map, &mapctx);

			list_for_each_entry(nhs, &ad->nhslist_head,
					    nhslist_entry)
			{
				vty_out(vty, " %s nhrp nhs ", aficmd);
				if (sockunion_family(&nhs->proto_addr)
				   == AF_UNSPEC)
					vty_out(vty, "dynamic");
				else
					vty_out(vty, "%pSU", &nhs->proto_addr);
				vty_out(vty, " nbma %s\n", nhs->nbma_fqdn);
			}

			list_for_each_entry(mcast, &ad->mcastlist_head,
					    list_entry)
			{
				vty_out(vty, " %s nhrp map multicast ", aficmd);
				if (sockunion_family(&mcast->nbma_addr)
				   == AF_UNSPEC)
					vty_out(vty, "dynamic\n");
				else
					vty_out(vty, "%pSU\n",
						&mcast->nbma_addr);
			}
		}

		vty_endframe(vty, "!\n");
	}
}

static int interface_config_write(struct vty *vty)
{
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name)
		interface_vrf_config_write(vty, vrf);
	return 0;
}

void nhrp_config_init(void)
{
	install_node(&zebra_node);
	install_default(ZEBRA_NODE);

	/* access-list commands */
	access_list_init();

	/* global commands */
	install_element(VIEW_NODE, &show_ip_nhrp_cmd);
	install_element(VIEW_NODE, &show_dmvpn_cmd);
	install_element(ENABLE_NODE, &clear_nhrp_cmd);

	install_element(ENABLE_NODE, &show_debugging_nhrp_cmd);

	install_element(ENABLE_NODE, &debug_nhrp_cmd);
	install_element(ENABLE_NODE, &no_debug_nhrp_cmd);

	install_element(CONFIG_NODE, &debug_nhrp_cmd);
	install_element(CONFIG_NODE, &no_debug_nhrp_cmd);

	install_element(CONFIG_NODE, &nhrp_event_socket_cmd);
	install_element(CONFIG_NODE, &no_nhrp_event_socket_cmd);
	install_element(CONFIG_NODE, &nhrp_nflog_group_cmd);
	install_element(CONFIG_NODE, &no_nhrp_nflog_group_cmd);
	install_element(CONFIG_NODE, &nhrp_multicast_nflog_group_cmd);
	install_element(CONFIG_NODE, &no_nhrp_multicast_nflog_group_cmd);

	install_element(VRF_NODE, &nhrp_event_socket_cmd);
	install_element(VRF_NODE, &no_nhrp_event_socket_cmd);
	install_element(VRF_NODE, &nhrp_nflog_group_cmd);
	install_element(VRF_NODE, &no_nhrp_nflog_group_cmd);
	install_element(VRF_NODE, &nhrp_multicast_nflog_group_cmd);
	install_element(VRF_NODE, &no_nhrp_multicast_nflog_group_cmd);

	/* interface specific commands */
	install_node(&nhrp_interface_node);

	if_cmd_init();
	install_element(INTERFACE_NODE, &tunnel_protection_cmd);
	install_element(INTERFACE_NODE, &no_tunnel_protection_cmd);
	install_element(INTERFACE_NODE, &tunnel_source_cmd);
	install_element(INTERFACE_NODE, &no_tunnel_source_cmd);
	install_element(INTERFACE_NODE, &if_nhrp_network_id_cmd);
	install_element(INTERFACE_NODE, &if_no_nhrp_network_id_cmd);
	install_element(INTERFACE_NODE, &if_nhrp_holdtime_cmd);
	install_element(INTERFACE_NODE, &if_no_nhrp_holdtime_cmd);
	install_element(INTERFACE_NODE, &if_nhrp_mtu_cmd);
	install_element(INTERFACE_NODE, &if_no_nhrp_mtu_cmd);
	install_element(INTERFACE_NODE, &if_nhrp_flags_cmd);
	install_element(INTERFACE_NODE, &if_no_nhrp_flags_cmd);
	install_element(INTERFACE_NODE, &if_nhrp_reg_flags_cmd);
	install_element(INTERFACE_NODE, &if_no_nhrp_reg_flags_cmd);
	install_element(INTERFACE_NODE, &if_nhrp_map_cmd);
	install_element(INTERFACE_NODE, &if_no_nhrp_map_cmd);
	install_element(INTERFACE_NODE, &if_nhrp_map_multicast_cmd);
	install_element(INTERFACE_NODE, &if_no_nhrp_map_multicast_cmd);
	install_element(INTERFACE_NODE, &if_nhrp_nhs_cmd);
	install_element(INTERFACE_NODE, &if_no_nhrp_nhs_cmd);
}
