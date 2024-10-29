// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP vty handling
 * Copyright (c) 2014-2015 Timo Teräs
 */

#include "zebra.h"
#include "command.h"
#include "zclient.h"
#include "stream.h"
#include "filter.h"
#include "json.h"

#include "nhrpd.h"
#include "netlink.h"
#include "nhrp_protocol.h"

#include "nhrpd/nhrp_vty_clippy.c"

static int nhrp_config_write(struct vty *vty);
static struct cmd_node zebra_node = {
	.name = "zebra",
	.node = ZEBRA_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-router)# ",
	.config_write = nhrp_config_write,
};

#define NHRP_DEBUG_FLAGS_CMD "<all|common|event|interface|kernel|route|vici>"

#define NHRP_DEBUG_FLAGS_STR                                                   \
	"All messages\n"                                                       \
	"Common messages (default)\n"                                          \
	"Event manager messages\n"                                             \
	"Interface messages\n"                                                 \
	"Kernel messages\n"                                                    \
	"Route messages\n"                                                     \
	"VICI messages\n"

static const struct message debug_flags_desc[] = {
	{NHRP_DEBUG_ALL, "all"},      {NHRP_DEBUG_COMMON, "common"},
	{NHRP_DEBUG_IF, "interface"}, {NHRP_DEBUG_KERNEL, "kernel"},
	{NHRP_DEBUG_ROUTE, "route"},  {NHRP_DEBUG_VICI, "vici"},
	{NHRP_DEBUG_EVENT, "event"},  {0}};

static const struct message interface_flags_desc[] = {
	{NHRP_IFF_SHORTCUT, "shortcut"},
	{NHRP_IFF_REDIRECT, "redirect"},
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

	cmd_show_lib_debugs(vty);

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

static int nhrp_config_write(struct vty *vty)
{
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

	if (nhrp_event_socket_path) {
		vty_out(vty, "nhrp event socket %s\n", nhrp_event_socket_path);
	}
	if (netlink_nflog_group) {
		vty_out(vty, "nhrp nflog-group %d\n", netlink_nflog_group);
	}
	if (netlink_mcast_nflog_group)
		vty_out(vty, "nhrp multicast-nflog-group %d\n",
			netlink_mcast_nflog_group);

	return 0;
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
	evmgr_set_socket(argv[3]->arg);
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
	evmgr_set_socket(NULL);
	return CMD_SUCCESS;
}

DEFUN(nhrp_nflog_group, nhrp_nflog_group_cmd,
	"nhrp nflog-group (1-65535)",
	NHRP_STR
	"Specify NFLOG group number\n"
	"NFLOG group number\n")
{
	uint32_t nfgroup;

	nfgroup = strtoul(argv[2]->arg, NULL, 10);
	netlink_set_nflog_group(nfgroup);

	return CMD_SUCCESS;
}

DEFUN(no_nhrp_nflog_group, no_nhrp_nflog_group_cmd,
	"no nhrp nflog-group [(1-65535)]",
	NO_STR
	NHRP_STR
	"Specify NFLOG group number\n"
	"NFLOG group number\n")
{
	netlink_set_nflog_group(0);
	return CMD_SUCCESS;
}

DEFUN(nhrp_multicast_nflog_group, nhrp_multicast_nflog_group_cmd,
	"nhrp multicast-nflog-group (1-65535)",
	NHRP_STR
	"Specify NFLOG group number for Multicast Packets\n"
	"NFLOG group number\n")
{
	uint32_t nfgroup;

	nfgroup = strtoul(argv[2]->arg, NULL, 10);
	netlink_mcast_set_nflog_group(nfgroup);

	return CMD_SUCCESS;
}

DEFUN(no_nhrp_multicast_nflog_group, no_nhrp_multicast_nflog_group_cmd,
	"no nhrp multicast-nflog-group [(1-65535)]",
	NO_STR
	NHRP_STR
	"Specify NFLOG group number\n"
	"NFLOG group number\n")
{
	netlink_mcast_set_nflog_group(0);
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
	"no tunnel protection [vici profile PROFILE [fallback-profile FALLBACK]]",
	NO_STR
	"NHRP/GRE integration\n"
	"IPsec protection\n"
	"VICI (StrongSwan)\n"
	"IPsec profile\n"
	"IPsec profile name\n"
	"Fallback IPsec profile\n"
	"Fallback IPsec profile name\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	nhrp_interface_set_protection(ifp, NULL, NULL);
	return CMD_SUCCESS;
}

DEFUN(tunnel_source, tunnel_source_cmd,
	"tunnel source INTERFACE",
	"NHRP/GRE integration\n"
	"Tunnel device binding tracking\n"
	"Interface name\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	nhrp_interface_set_source(ifp, argv[2]->arg);
	return CMD_SUCCESS;
}

DEFUN(no_tunnel_source, no_tunnel_source_cmd,
	"no tunnel source",
	"NHRP/GRE integration\n"
	"Tunnel device binding tracking\n"
	"Interface name\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	nhrp_interface_set_source(ifp, NULL);
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
	AFI_CMD " nhrp <shortcut|redirect>",
	AFI_STR
	NHRP_STR
	"Allow shortcut establishment\n"
	"Send redirect notifications\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct nhrp_interface *nifp = ifp->info;
	afi_t afi = cmd_to_afi(argv[0]);

	return toggle_flag(vty, interface_flags_desc, argv[2]->text, 1,
			   &nifp->afi[afi].flags);
}

DEFUN(if_no_nhrp_flags, if_no_nhrp_flags_cmd,
	"no " AFI_CMD " nhrp <shortcut|redirect>",
	NO_STR
	AFI_STR
	NHRP_STR
	"Allow shortcut establishment\n"
	"Send redirect notifications\n")
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

DEFPY(if_nhrp_authentication, if_nhrp_authentication_cmd,
      AFI_CMD "nhrp authentication PASSWORD$password",
      AFI_STR
      NHRP_STR
      "Specify plain text password used for authenticantion\n"
      "Password, plain text, limited to 8 characters\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct nhrp_cisco_authentication_extension *auth;
	struct nhrp_interface *nifp = ifp->info;
	int pass_len = strlen(password);

	if (pass_len > NHRP_CISCO_PASS_LEN) {
		vty_out(vty, "Password size limit exceeded (%d>%d)\n",
			pass_len, NHRP_CISCO_PASS_LEN);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (nifp->auth_token) {
		zbuf_free(nifp->auth_token);
		nifp->auth_token = NULL;
	}

	nifp->auth_token = zbuf_alloc(pass_len + sizeof(uint32_t));
	auth = (struct nhrp_cisco_authentication_extension *)
		       nifp->auth_token->buf;
	auth->type = htonl(NHRP_AUTHENTICATION_PLAINTEXT);
	memcpy(auth->secret, password, pass_len);

	return CMD_SUCCESS;
}


DEFPY(if_no_nhrp_authentication, if_no_nhrp_authentication_cmd,
      "no " AFI_CMD "nhrp authentication PASSWORD$password",
      NO_STR
      AFI_STR
      NHRP_STR
      "Specify plain text password used for authenticantion\n"
	  "Password, plain text, limited to 8 characters\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct nhrp_interface *nifp = ifp->info;

	if (nifp->auth_token) {
		zbuf_free(nifp->auth_token);
		nifp->auth_token = NULL;
	}
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

	if (!ctx->count && !ctx->json) {
		vty_out(vty, "%-8s %-24s %-24s %s\n", "Type", "Prefix", "Via",
			"Identity");
	}
	ctx->count++;

	c = s->cache;
	buf2[0] = '\0';
	if (c)
		sockunion2str(&c->remote_addr, buf2, sizeof(buf2));
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

	vty_out(ctx->vty, "\n\n");
}

DEFUN(show_ip_nhrp, show_ip_nhrp_cmd,
	"show " AFI_CMD " nhrp [cache|nhs|shortcut|opennhrp] [json]",
	SHOW_STR
	AFI_STR
	"NHRP information\n"
	"Forwarding cache information\n"
	"Next hop server information\n"
	"Shortcut information\n"
	"opennhrpctl style cache dump\n"
	JSON_STR)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;
	struct info_ctx ctx = {
		.vty = vty, .afi = cmd_to_afi(argv[1]), .json = NULL
	};
	bool uj = use_json(argc, argv);
	struct json_object *json_path = NULL;
	struct json_object *json_vrf = NULL, *json_vrf_path = NULL;
	int ret = CMD_SUCCESS;

	if (uj) {
		json_vrf = json_object_new_object();
		json_vrf_path = json_object_new_object();
		json_path = json_object_new_array();
		ctx.json = json_path;
	}
	if (argc <= 3 || argv[3]->text[0] == 'c') {
		FOR_ALL_INTERFACES (vrf, ifp)
			nhrp_cache_foreach(ifp, show_ip_nhrp_cache, &ctx);
	} else if (argv[3]->text[0] == 'n') {
		FOR_ALL_INTERFACES (vrf, ifp)
			nhrp_nhs_foreach(ifp, ctx.afi, show_ip_nhrp_nhs, &ctx);
	} else if (argv[3]->text[0] == 's') {
		nhrp_shortcut_foreach(ctx.afi, show_ip_nhrp_shortcut, &ctx);
	} else {
		if (!ctx.json)
			vty_out(vty, "Status: ok\n\n");
		else
			json_object_string_add(json_vrf, "status", "ok");

		ctx.count++;
		FOR_ALL_INTERFACES (vrf, ifp)
			nhrp_cache_foreach(ifp, show_ip_opennhrp_cache, &ctx);
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
		vty_json(vty, json_vrf_path);
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
	struct json_object *json = NULL;

	if (!ctxt || !ctxt->vty)
		return;
	vty = ctxt->vty;
	if (ctxt->json) {
		json = json_object_new_object();
		json_object_string_addf(json, "src", "%pSU", &vc->local.nbma);
		json_object_string_addf(json, "dst", "%pSU", &vc->remote.nbma);

		if (notifier_active(&vc->notifier_list))
			json_object_boolean_true_add(json, "notifierActive");
		else
			json_object_boolean_false_add(json, "notifierActive");

		json_object_int_add(json, "sas", vc->ipsec);
		json_object_string_add(json, "identity", vc->remote.id);
		json_object_array_add(ctxt->json, json);
	} else {
		vty_out(vty, "%-24pSU %-24pSU %c      %-4d %-24s\n",
			&vc->local.nbma, &vc->remote.nbma,
			notifier_active(&vc->notifier_list) ? 'n' : ' ',
			vc->ipsec, vc->remote.id);
	}
}

DEFUN(show_dmvpn, show_dmvpn_cmd,
	"show dmvpn [json]",
	SHOW_STR
	"DMVPN information\n"
	JSON_STR)
{
	bool uj = use_json(argc, argv);
	struct dmvpn_cfg ctxt;
	struct json_object *json_path = NULL;

	ctxt.vty = vty;
	if (!uj) {
		ctxt.json = NULL;
		vty_out(vty, "%-24s %-24s %-6s %-4s %-24s\n",
			"Src", "Dst", "Flags", "SAs", "Identity");
	} else {
		json_path = json_object_new_array();
		ctxt.json = json_path;
	}
	nhrp_vc_foreach(show_dmvpn_entry, &ctxt);
	if (uj)
		vty_json(vty, json_path);
	return CMD_SUCCESS;
}

static void clear_nhrp_cache(struct nhrp_cache *c, void *data)
{
	struct info_ctx *ctx = data;

	if (c->cur.type <= NHRP_CACHE_DYNAMIC) {
		nhrp_cache_update_binding(c, c->cur.type, -1, NULL, 0, NULL,
					  NULL);
		if (ctx)
			ctx->count++;
	}
}

static void clear_nhrp_shortcut(struct nhrp_shortcut *s, void *data)
{
	struct info_ctx *ctx = data;
	nhrp_shortcut_purge(s, 1);
	ctx->count++;
}

DEFUN(clear_nhrp, clear_nhrp_cmd,
	"clear " AFI_CMD " nhrp <cache|shortcut>",
	CLEAR_STR
	AFI_STR
	NHRP_STR
	"Dynamic cache entries\n"
	"Shortcut entries\n")
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;
	struct info_ctx ctx = {
		.vty = vty, .afi = cmd_to_afi(argv[1]), .count = 0,
	};

	if (argc <= 3 || argv[3]->text[0] == 'c') {
		FOR_ALL_INTERFACES (vrf, ifp)
			nhrp_cache_foreach(ifp, clear_nhrp_cache, &ctx);
	} else {
		nhrp_shortcut_foreach(ctx.afi, clear_nhrp_shortcut, &ctx);
		/* Clear cache also because when a shortcut is cleared then its
		 * cache entry should be cleared as well (otherwise traffic
		 * continues via the shortcut path)
		 */
		FOR_ALL_INTERFACES (vrf, ifp)
			nhrp_cache_foreach(ifp, clear_nhrp_cache, NULL);
	}

	if (!ctx.count) {
		vty_out(vty, "%% No entries\n");
		return CMD_WARNING;
	}

	vty_out(vty, "%% %d entries cleared\n", ctx.count);
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

static int interface_config_write(struct vty *vty)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct nhrp_cisco_authentication_extension *auth;
	struct write_map_ctx mapctx;
	struct interface *ifp;
	struct nhrp_interface *nifp;
	struct nhrp_nhs *nhs;
	struct nhrp_multicast *mcast;
	const char *aficmd;
	afi_t afi;
	int i;

	FOR_ALL_INTERFACES (vrf, ifp) {
		if_vty_config_start(vty, ifp);
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
		if (nifp->source)
			vty_out(vty, " tunnel source %s\n", nifp->source);

		if (nifp->auth_token) {
			auth = (struct nhrp_cisco_authentication_extension *)
				       nifp->auth_token->buf;
			vty_out(vty, " ip nhrp authentication %s\n", auth->secret);
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

			frr_each (nhrp_nhslist, &ad->nhslist_head, nhs) {
				vty_out(vty, " %s nhrp nhs ", aficmd);
				if (sockunion_family(&nhs->proto_addr)
				   == AF_UNSPEC)
					vty_out(vty, "dynamic");
				else
					vty_out(vty, "%pSU", &nhs->proto_addr);
				vty_out(vty, " nbma %s\n", nhs->nbma_fqdn);
			}

			frr_each (nhrp_mcastlist, &ad->mcastlist_head, mcast) {
				vty_out(vty, " %s nhrp map multicast ", aficmd);
				if (sockunion_family(&mcast->nbma_addr)
				   == AF_UNSPEC)
					vty_out(vty, "dynamic\n");
				else
					vty_out(vty, "%pSU\n",
						&mcast->nbma_addr);
			}
		}

		if_vty_config_end(vty);
	}

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

	vrf_cmd_init(NULL);

	/* interface specific commands */
	if_cmd_init(interface_config_write);
	install_element(INTERFACE_NODE, &tunnel_protection_cmd);
	install_element(INTERFACE_NODE, &no_tunnel_protection_cmd);
	install_element(INTERFACE_NODE, &tunnel_source_cmd);
	install_element(INTERFACE_NODE, &no_tunnel_source_cmd);
	install_element(INTERFACE_NODE, &if_nhrp_network_id_cmd);
	install_element(INTERFACE_NODE, &if_no_nhrp_network_id_cmd);
	install_element(INTERFACE_NODE, &if_nhrp_holdtime_cmd);
	install_element(INTERFACE_NODE, &if_no_nhrp_holdtime_cmd);
	install_element(INTERFACE_NODE, &if_nhrp_authentication_cmd);
	install_element(INTERFACE_NODE, &if_no_nhrp_authentication_cmd);
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
