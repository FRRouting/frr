// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra configuration command interface routine
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_COMMAND_H
#define _ZEBRA_COMMAND_H

#include "vector.h"
#include "vty.h"
#include "lib/route_types.h"
#include "graph.h"
#include "memory.h"
#include "hash.h"
#include "command_graph.h"

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MTYPE(COMPLETION);

/*
 * From RFC 1123 (Requirements for Internet Hosts), Section 2.1 on hostnames:
 * One aspect of host name syntax is hereby changed: the restriction on
 * the first character is relaxed to allow either a letter or a digit.
 * Host software MUST support this more liberal syntax.
 *
 * Host software MUST handle host names of up to 63 characters and
 * SHOULD handle host names of up to 255 characters.
 */
#define HOSTNAME_LEN   255

/* Host configuration variable */
struct host {
	/* Host name of this router. */
	char *name;

	/* Domainname of this router */
	char *domainname;

	/*
	 * Some extra system data that is useful
	 */
	char *system;
	char *release;
	char *version;

	/* Password for vty interface. */
	char *password;
	char *password_encrypt;

	/* Enable password */
	char *enable;
	char *enable_encrypt;

	/* System wide terminal lines. */
	int lines;

	/* config file name of this host */
	char *config;
	int noconfig;

	/* Flags for services */
	int advanced;
	int encrypt;

	/* Banner configuration. */
	char *motd;
	char *motdfile;

	/* Allow using IPv4 (Class E) reserved IP space */
	bool allow_reserved_ranges;
};

/* List of CLI nodes. Please remember to update the name array in command.c. */
/* clang-format off */
enum node_type {
	AUTH_NODE,		 /* Authentication mode of vty interface. */
	VIEW_NODE,		 /* View node. Default mode of vty interface. */
	AUTH_ENABLE_NODE,	/* Authentication mode for change enable. */
	ENABLE_NODE,		 /* Enable node. */
	CONFIG_NODE,		 /* Config node. Default mode of config file. */
	PREFIX_NODE, /* ip prefix-list node. */
	PREFIX_IPV6_NODE, /* ipv6 prefix-list node. */
	RMAP_NODE, /* Route map node. */
	LIB_DEBUG_NODE,		 /* frrlib debug node. */
	DEBUG_NODE,		 /* Debug node. */
	VRF_DEBUG_NODE,		 /* Vrf Debug node. */
	DEBUG_VNC_NODE,		 /* Debug VNC node. */
	RMAP_DEBUG_NODE,         /* Route-map debug node */
	RESOLVER_DEBUG_NODE,	 /* Resolver debug node */
	AAA_NODE,		 /* AAA node. */
	EXTLOG_NODE,		 /* RFC5424 & co. extended syslog */
	KEYCHAIN_NODE,		 /* Key-chain node. */
	KEYCHAIN_KEY_NODE,       /* Key-chain key node. */
	AFFMAP_NODE,		 /* Affinity map node. */
	IP_NODE,		 /* Static ip route node. */
	VRF_NODE,		 /* VRF mode node. */
	INTERFACE_NODE,		 /* Interface mode node. */
	NH_GROUP_NODE,		 /* Nexthop-Group mode node. */
	ZEBRA_NODE,		 /* zebra connection node. */
	RIP_NODE,		 /* RIP protocol mode node. */
	RIPNG_NODE,		 /* RIPng protocol mode node. */
	BABEL_NODE,		 /* BABEL protocol mode node. */
	EIGRP_NODE,		 /* EIGRP protocol mode node. */
	BGP_NODE,		 /* BGP protocol mode which includes BGP4+ */
	BGP_VPNV4_NODE,		 /* BGP MPLS-VPN PE exchange. */
	BGP_VPNV6_NODE,		 /* BGP MPLS-VPN PE exchange. */
	BGP_IPV4_NODE,		 /* BGP IPv4 unicast address family.  */
	BGP_IPV4M_NODE,		 /* BGP IPv4 multicast address family.  */
	BGP_IPV4L_NODE,		 /* BGP IPv4 labeled unicast address family.  */
	BGP_IPV6_NODE,		 /* BGP IPv6 address family */
	BGP_IPV6M_NODE,		 /* BGP IPv6 multicast address family. */
	BGP_IPV6L_NODE,		 /* BGP IPv6 labeled unicast address family. */
	BGP_VRF_POLICY_NODE,     /* BGP VRF policy */
	BGP_VNC_DEFAULTS_NODE,   /* BGP VNC nve defaults */
	BGP_VNC_NVE_GROUP_NODE,  /* BGP VNC nve group */
	BGP_VNC_L2_GROUP_NODE,   /* BGP VNC L2 group */
	BGP_EVPN_NODE,		 /* BGP EVPN node. */
	BGP_SRV6_NODE,		 /* BGP SRv6 node. */
	OSPF_NODE,		 /* OSPF protocol mode */
	OSPF6_NODE,		 /* OSPF protocol for IPv6 mode */
	LDP_NODE,		 /* LDP protocol mode */
	LDP_IPV4_NODE,		 /* LDP IPv4 address family */
	LDP_IPV6_NODE,		 /* LDP IPv6 address family */
	LDP_IPV4_IFACE_NODE,     /* LDP IPv4 Interface */
	LDP_IPV6_IFACE_NODE,     /* LDP IPv6 Interface */
	LDP_L2VPN_NODE,		 /* LDP L2VPN node */
	LDP_PSEUDOWIRE_NODE,     /* LDP Pseudowire node */
	ISIS_NODE,		 /* ISIS protocol mode */
	ISIS_FLEX_ALGO_NODE,    /* ISIS Flex Algo mode */
	ACCESS_NODE,		 /* Access list node. */
	ACCESS_IPV6_NODE,	/* Access list node. */
	ACCESS_MAC_NODE,	 /* MAC access list node*/
	AS_LIST_NODE,		 /* AS list node. */
	COMMUNITY_LIST_NODE,     /* Community list node. */
	COMMUNITY_ALIAS_NODE, /* Community alias node. */
	PBRMAP_NODE,		 /* PBR map node. */
	SMUX_NODE,		 /* SNMP configuration node. */
	DUMP_NODE,		 /* Packet dump node. */
	FORWARDING_NODE,	 /* IP forwarding node. */
	PROTOCOL_NODE,		 /* protocol filtering node */
	MPLS_NODE,		 /* MPLS config node */
	PW_NODE,		 /* Pseudowire config node */
	SEGMENT_ROUTING_NODE,	 /* Segment routing root node */
	SR_TRAFFIC_ENG_NODE,	 /* SR Traffic Engineering node */
	SR_SEGMENT_LIST_NODE,	 /* SR segment list config node */
	SR_POLICY_NODE,		 /* SR policy config node */
	SR_CANDIDATE_DYN_NODE,	 /* SR dynamic candidate path config node */
	PCEP_NODE,	 	 /* PCEP node */
	PCEP_PCE_CONFIG_NODE,	 /* PCE shared configuration node */
	PCEP_PCE_NODE,		 /* PCE configuration node */
	PCEP_PCC_NODE,		 /* PCC configuration node */
	SRV6_NODE,		 /* SRv6 node */
	SRV6_LOCS_NODE,		 /* SRv6 locators node */
	SRV6_LOC_NODE,		 /* SRv6 locator node */
	SRV6_PREFIX_NODE,		 /* SRv6 locator prefix node */
	SRV6_ENCAP_NODE,		 /* SRv6 encapsulation node */
	SRV6_SID_FORMATS_NODE,		 /* SRv6 SID formats config node */
	SRV6_SID_FORMAT_USID_F3216_NODE,		 /* SRv6 uSID f3216 format config node */
	SRV6_SID_FORMAT_UNCOMPRESSED_F4024_NODE,		 /* SRv6 uncompressed f4024 format config node */
	VTY_NODE,		 /* Vty node. */
	FPM_NODE,		 /* Dataplane FPM node. */
	LINK_PARAMS_NODE,	/* Link-parameters node */
	BGP_EVPN_VNI_NODE,       /* BGP EVPN VNI */
	RPKI_NODE,     /* RPKI node for configuration of RPKI cache server
			  connections.*/
	BGP_FLOWSPECV4_NODE,	/* BGP IPv4 FLOWSPEC Address-Family */
	BGP_FLOWSPECV6_NODE,	/* BGP IPv6 FLOWSPEC Address-Family */
	BFD_NODE,		 /* BFD protocol mode. */
	BFD_PEER_NODE,		 /* BFD peer configuration mode. */
	BFD_PROFILE_NODE,	 /* BFD profile configuration mode. */
	OPENFABRIC_NODE,	/* OpenFabric router configuration node */
	VRRP_NODE,		 /* VRRP node */
	BMP_NODE,		/* BMP config under router bgp */
	ISIS_SRV6_NODE,    /* ISIS SRv6 node */
	ISIS_SRV6_NODE_MSD_NODE,    /* ISIS SRv6 Node MSDs node */
	MGMTD_NODE,		 /* MGMTD node. */
	RPKI_VRF_NODE,  /* RPKI node for VRF */
	PIM_NODE,		 /* PIM protocol mode */
	PIM6_NODE,		 /* PIM protocol for IPv6 mode */
	NODE_TYPE_MAX, /* maximum */
};
/* clang-format on */

extern vector cmdvec;
extern const struct message tokennames[];

/* for external users depending on struct layout */
#define FRR_CMD_NODE_20200416

/* Node which has some commands and prompt string and configuration
   function pointer . */
struct cmd_node {
	const char *name;

	/* Node index. */
	enum node_type node;
	enum node_type parent_node;

	/* Prompt character at vty interface. */
	const char *prompt;

	/* Node's configuration write function */
	int (*config_write)(struct vty *);

	/* called when leaving the node on a VTY session.
	 * return 1 if normal exit processing should happen, 0 to suppress
	 */
	int (*node_exit)(struct vty *);

	/* Node's command graph */
	struct graph *cmdgraph;

	/* Vector of this node's command list. */
	vector cmd_vector;

	/* Hashed index of command node list, for de-dupping primarily */
	struct hash *cmd_hash;

	/* set as soon as any command is in cmdgraph */
	bool graph_built;

	/* don't decrement vty->xpath_index on leaving this node */
	bool no_xpath;
};

/* Return value of the commands. */
#define CMD_SUCCESS              0
#define CMD_WARNING              1
#define CMD_ERR_NO_MATCH         2
#define CMD_ERR_AMBIGUOUS        3
#define CMD_ERR_INCOMPLETE       4
#define CMD_ERR_EXEED_ARGC_MAX   5
#define CMD_ERR_NOTHING_TODO     6
#define CMD_COMPLETE_FULL_MATCH  7
#define CMD_COMPLETE_MATCH       8
#define CMD_COMPLETE_LIST_MATCH  9
#define CMD_SUCCESS_DAEMON      10
#define CMD_ERR_NO_FILE         11
#define CMD_SUSPEND             12
#define CMD_WARNING_CONFIG_FAILED 13
#define CMD_NOT_MY_INSTANCE	14
#define CMD_NO_LEVEL_UP 15
#define CMD_ERR_NO_DAEMON 16

/* Argc max counts. */
#define CMD_ARGC_MAX   256

/* clang-format off */

/* helper defines for end-user DEFUN* macros */
#define DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, attrs, dnum)     \
	const struct cmd_element cmdname = {                                   \
		.string = cmdstr,                                              \
		.func = funcname,                                              \
		.doc = helpstr,                                                \
		.attr = attrs,                                                 \
		.daemon = dnum,                                                \
		.name = #cmdname,                                              \
		.xref = XREF_INIT(XREFT_DEFUN, NULL, #funcname),               \
	};                                                                     \
	XREF_LINK(cmdname.xref);                                               \
	/* end */


#define DEFUN_CMD_FUNC_DECL(funcname)                                          \
	static int funcname(const struct cmd_element *, struct vty *, int,     \
			    struct cmd_token *[]);

#define DEFUN_CMD_FUNC_TEXT(funcname)                                          \
	static int funcname(const struct cmd_element *self                     \
			    __attribute__((unused)),                           \
			    struct vty *vty __attribute__((unused)),           \
			    int argc __attribute__((unused)),                  \
			    struct cmd_token *argv[] __attribute__((unused)))

/* DEFPY variants */

#define DEFPY_ATTR(funcname, cmdname, cmdstr, helpstr, attr)                   \
	static DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, attr, 0)  \
	funcdecl_##funcname

#define DEFPY(funcname, cmdname, cmdstr, helpstr)                              \
	DEFPY_ATTR(funcname, cmdname, cmdstr, helpstr, 0)

#define DEFPY_NOSH(funcname, cmdname, cmdstr, helpstr)                         \
	DEFPY_ATTR(funcname, cmdname, cmdstr, helpstr, CMD_ATTR_NOSH)

#define DEFPY_HIDDEN(funcname, cmdname, cmdstr, helpstr)                       \
	DEFPY_ATTR(funcname, cmdname, cmdstr, helpstr, CMD_ATTR_HIDDEN)

#define DEFPY_YANG(funcname, cmdname, cmdstr, helpstr)                         \
	DEFPY_ATTR(funcname, cmdname, cmdstr, helpstr, CMD_ATTR_YANG)

#define DEFPY_YANG_HIDDEN(funcname, cmdname, cmdstr, helpstr)                  \
	DEFPY_ATTR(funcname, cmdname, cmdstr, helpstr,                         \
		   CMD_ATTR_YANG | CMD_ATTR_HIDDEN)

#define DEFPY_YANG_NOSH(funcname, cmdname, cmdstr, helpstr)                    \
	DEFPY_ATTR(funcname, cmdname, cmdstr, helpstr,                         \
		   CMD_ATTR_YANG | CMD_ATTR_NOSH)

/* DEFUN variants */

#define DEFUN_ATTR(funcname, cmdname, cmdstr, helpstr, attr)                   \
	DEFUN_CMD_FUNC_DECL(funcname)                                          \
	static DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, attr, 0)  \
	DEFUN_CMD_FUNC_TEXT(funcname)

#define DEFUN(funcname, cmdname, cmdstr, helpstr)                              \
	DEFUN_ATTR(funcname, cmdname, cmdstr, helpstr, 0)

#define DEFUN_HIDDEN(funcname, cmdname, cmdstr, helpstr)                       \
	DEFUN_ATTR(funcname, cmdname, cmdstr, helpstr, CMD_ATTR_HIDDEN)

#define DEFUN_YANG(funcname, cmdname, cmdstr, helpstr)                         \
	DEFUN_ATTR(funcname, cmdname, cmdstr, helpstr, CMD_ATTR_YANG)

/* DEFUN_NOSH for commands that vtysh should ignore */
#define DEFUN_NOSH(funcname, cmdname, cmdstr, helpstr)                         \
	DEFUN_ATTR(funcname, cmdname, cmdstr, helpstr, CMD_ATTR_NOSH)

#define DEFUN_YANG_HIDDEN(funcname, cmdname, cmdstr, helpstr)                  \
	DEFUN_ATTR(funcname, cmdname, cmdstr, helpstr,                         \
		   CMD_ATTR_YANG | CMD_ATTR_HIDDEN)

#define DEFUN_YANG_NOSH(funcname, cmdname, cmdstr, helpstr)                    \
	DEFUN_ATTR(funcname, cmdname, cmdstr, helpstr,                         \
		   CMD_ATTR_YANG | CMD_ATTR_NOSH)

/* DEFSH for vtysh. */
#define DEFSH_ATTR(daemon, cmdname, cmdstr, helpstr, attr)                     \
	DEFUN_CMD_ELEMENT(NULL, cmdname, cmdstr, helpstr, attr, daemon)

#define DEFSH(daemon, cmdname, cmdstr, helpstr)                                \
	DEFSH_ATTR(daemon, cmdname, cmdstr, helpstr, 0)

#define DEFSH_HIDDEN(daemon, cmdname, cmdstr, helpstr)                         \
	DEFSH_ATTR(daemon, cmdname, cmdstr, helpstr, CMD_ATTR_HIDDEN)

/* DEFUN + DEFSH */
#define DEFUNSH_ATTR(daemon, funcname, cmdname, cmdstr, helpstr, attr)         \
	DEFUN_CMD_FUNC_DECL(funcname)                                          \
	static DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, attr,     \
				 daemon)                                       \
	DEFUN_CMD_FUNC_TEXT(funcname)

#define DEFUNSH(daemon, funcname, cmdname, cmdstr, helpstr)                    \
	DEFUNSH_ATTR(daemon, funcname, cmdname, cmdstr, helpstr, 0)

#define DEFUNSH_HIDDEN(daemon, funcname, cmdname, cmdstr, helpstr)             \
	DEFUNSH_ATTR(daemon, funcname, cmdname, cmdstr, helpstr,               \
		     CMD_ATTR_HIDDEN)

/* ALIAS macro which define existing command's alias. */
#define ALIAS_ATTR(funcname, cmdname, cmdstr, helpstr, attr)                   \
	static DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, attr, 0)

#define ALIAS(funcname, cmdname, cmdstr, helpstr)                              \
	ALIAS_ATTR(funcname, cmdname, cmdstr, helpstr, 0)

#define ALIAS_HIDDEN(funcname, cmdname, cmdstr, helpstr)                       \
	ALIAS_ATTR(funcname, cmdname, cmdstr, helpstr, CMD_ATTR_HIDDEN)

/* note: DEPRECATED implies HIDDEN, and other than that there is currently no
 * difference.  It's purely for expressing intent in the source code - a
 * DEPRECATED command is supposed to go away, a HIDDEN one is likely to stay.
 */
#define ALIAS_DEPRECATED(funcname, cmdname, cmdstr, helpstr)                   \
	ALIAS_ATTR(funcname, cmdname, cmdstr, helpstr,                         \
		   CMD_ATTR_DEPRECATED | CMD_ATTR_HIDDEN)

#define ALIAS_YANG(funcname, cmdname, cmdstr, helpstr)                         \
	ALIAS_ATTR(funcname, cmdname, cmdstr, helpstr, CMD_ATTR_YANG)

/* clang-format on */

/* Some macroes */

/*
 * Sometimes #defines create maximum values that
 * need to have strings created from them that
 * allow the parser to match against them.
 * These macros allow that.
 */
#define CMD_CREATE_STR(s)  CMD_CREATE_STR_HELPER(s)
#define CMD_CREATE_STR_HELPER(s) #s
#define CMD_RANGE_STR(a,s) "(" CMD_CREATE_STR(a) "-" CMD_CREATE_STR(s) ")"

/* Common descriptions. */
#define SHOW_STR "Show running system information\n"
#define IP_STR "IP information\n"
#define IPV6_STR "IPv6 information\n"
#define IP_ADDR_STR "IPv4 Address\n"
#define IP6_ADDR_STR "IPv6 Address\n"
#define SRTE_STR "SR-TE information\n"
#define SRTE_COLOR_STR "SR-TE Color information\n"
#define NO_STR "Negate a command or set its defaults\n"
#define IGNORED_IN_NO_STR "Ignored value in no form\n"
#define REDIST_STR "Redistribute information from another routing protocol\n"
#define CLEAR_STR "Reset functions\n"
#define RIP_STR "RIP information\n"
#define EIGRP_STR "EIGRP information\n"
#define BGP_STR "BGP information\n"
#define BGP_SOFT_STR "Soft reconfig inbound and outbound updates\n"
#define BGP_SOFT_IN_STR "Send route-refresh unless using 'soft-reconfiguration inbound'\n"
#define BGP_SOFT_OUT_STR "Resend all outbound updates\n"
#define BGP_SOFT_RSCLIENT_RIB_STR "Soft reconfig for rsclient RIB\n"
#define OSPF_STR "OSPF information\n"
#define NEIGHBOR_STR "Specify neighbor router\n"
#define DEBUG_STR "Debugging functions\n"
#define UNDEBUG_STR "Disable debugging functions (see also 'debug')\n"
#define ROUTER_STR "Enable a routing process\n"
#define AS_STR                                                                 \
	"AS number in plain  <1-4294967295> or dotted <0-65535>.<0-65535> format\n"
#define MAC_STR "MAC address\n"
#define MBGP_STR "MBGP information\n"
#define MATCH_STR "Match values from routing table\n"
#define SET_STR "Set values in destination routing protocol\n"
#define OUT_STR "Filter outgoing routing updates\n"
#define IN_STR  "Filter incoming routing updates\n"
#define V4NOTATION_STR "specify by IPv4 address notation(e.g. 0.0.0.0)\n"
#define OSPF6_NUMBER_STR "Specify by number\n"
#define INTERFACE_STR "Interface information\n"
#define IFNAME_STR "Interface name(e.g. ep0)\n"
#define IP6_STR "IPv6 Information\n"
#define OSPF6_STR "Open Shortest Path First (OSPF) for IPv6\n"
#define OSPF6_INSTANCE_STR "(1-65535) Instance ID\n"
#define SECONDS_STR "Seconds\n"
#define ROUTE_STR "Routing Table\n"
#define PREFIX_LIST_STR "Build a prefix list\n"
#define OSPF6_DUMP_TYPE_LIST                                                   \
	"<neighbor|interface|area|lsa|zebra|config|dbex|spf|route|lsdb|redistribute|hook|asbr|prefix|abr>"
#define AREA_TAG_STR "[area tag]\n"
#define COMMUNITY_AANN_STR "Community number where AA and NN are (0-65535)\n"
#define COMMUNITY_VAL_STR                                                      \
	"Community number in AA:NN format (where AA and NN are (0-65535)) or local-AS|no-advertise|no-export|internet|graceful-shutdown|accept-own-nexthop|accept-own|route-filter-translated-v4|route-filter-v4|route-filter-translated-v6|route-filter-v6|llgr-stale|no-llgr|blackhole|no-peer or additive\n"
#define EXTCOMM_LIST_CMD_STR "<(1-99)|(100-500)|EXTCOMMUNITY_LIST_NAME>"
#define EXTCOMM_STD_LIST_NUM_STR "Extended community-list number (standard)\n"
#define EXTCOMM_EXP_LIST_NUM_STR "Extended community-list number (expanded)\n"
#define EXTCOMM_LIST_NAME_STR "Extended community-list name\n"
#define MPLS_TE_STR "MPLS-TE specific commands\n"
#define LINK_PARAMS_STR "Configure interface link parameters\n"
#define OSPF_RI_STR "OSPF Router Information specific commands\n"
#define PCE_STR "PCE Router Information specific commands\n"
#define MPLS_STR "MPLS information\n"
#define SR_STR "Segment-Routing specific commands\n"
#define WATCHFRR_STR "watchfrr information\n"
#define ZEBRA_STR "Zebra information\n"
#define FILTER_LOG_STR "Filter Logs\n"
#define BFD_PROFILE_STR "BFD profile.\n"
#define BFD_PROFILE_NAME_STR "BFD profile name.\n"
#define SHARP_STR "Sharp Routing Protocol\n"
#define OSPF_GR_STR                                                            \
	"OSPF non-stop forwarding (NSF) also known as OSPF Graceful Restart\n"
#define MGMTD_STR "Management Daemon (MGMTD) information\n"
#define MGMTD_BE_ADAPTER_STR "MGMTD Backend Adapter information\n"
#define MGMTD_FE_ADAPTER_STR "MGMTD Frontend Adapter information\n"
#define MGMTD_TXN_STR "MGMTD Transaction information\n"
#define MGMTD_DS_STR "MGMTD Datastore information\n"

#define CMD_VNI_RANGE "(1-16777215)"
#define CONF_BACKUP_EXT ".sav"
#define MPLS_LDP_SYNC_STR "Enable MPLS LDP-SYNC\n"
#define NO_MPLS_LDP_SYNC_STR "Disable MPLS LDP-SYNC\n"
#define MPLS_LDP_SYNC_HOLDDOWN_STR                                             \
	"Time to wait for LDP-SYNC to occur before restoring if cost\n"
#define NO_MPLS_LDP_SYNC_HOLDDOWN_STR "holddown timer disable\n"
#define BGP_AF_STR "Address Family\n"
#define BGP_AF_MODIFIER_STR "Address Family modifier\n"

/* Command warnings. */
#define NO_PASSWD_CMD_WARNING                                                  \
	"Please be aware that removing the password is a security risk and you should think twice about this command.\n"

/* IPv4 only machine should not accept IPv6 address for peer's IP
   address.  So we replace VTY command string like below. */
#define NEIGHBOR_ADDR_STR  "Neighbor address\nIPv6 address\n"
#define NEIGHBOR_ADDR_STR2 "Neighbor address\nNeighbor IPv6 address\nInterface name or neighbor tag\n"
#define NEIGHBOR_ADDR_STR3 "Neighbor address\nIPv6 address\nInterface name\n"

/* Graceful Restart cli help strings */
#define GR_CMD "Global Graceful Restart command\n"
#define NO_GR_CMD "Undo Global Graceful Restart command\n"
#define GR "Global Graceful Restart - GR Mode\n"
#define GR_DISABLE "Global Graceful Restart - Disable Mode\n"
#define NO_GR_DISABLE "Undo Global Graceful Restart - Disable Mode\n"
#define GR_DEBUG "Graceful Restart - Enable Debug Logs\n"
#define GR_SHOW "Graceful Restart - Show command for Global and all neighbor mode\n"
#define GR_NEIGHBOR_CMD "Graceful Restart command for a neighbor\n"
#define NO_GR_NEIGHBOR_CMD "Undo Graceful Restart command for a neighbor\n"
#define GR_NEIGHBOR_DISABLE_CMD "Graceful Restart Disable command for a neighbor\n"
#define NO_GR_NEIGHBOR_DISABLE_CMD "Undo Graceful Restart Disable command for a neighbor\n"
#define GR_NEIGHBOR_HELPER_CMD "Graceful Restart Helper command for a neighbor\n"
#define NO_GR_NEIGHBOR_HELPER_CMD "Undo Graceful Restart Helper command for a neighbor\n"

/* EVPN help Strings */
#define EVPN_RT_HELP_STR "EVPN route information\n"
#define EVPN_RT_DIST_HELP_STR "Route Distinguisher\n"
#define EVPN_ASN_IP_HELP_STR "ASN:XX or A.B.C.D:XX\n"
#define EVPN_TYPE_HELP_STR "Specify Route type\n"
#define EVPN_TYPE_1_HELP_STR "EAD (Type-1) route\n"
#define EVPN_TYPE_2_HELP_STR "MAC-IP (Type-2) route\n"
#define EVPN_TYPE_3_HELP_STR "Multicast (Type-3) route\n"
#define EVPN_TYPE_4_HELP_STR "Ethernet Segment (Type-4) route\n"
#define EVPN_TYPE_5_HELP_STR "Prefix (Type-5) route\n"
#define EVPN_TYPE_ALL_LIST "<ead|1|macip|2|multicast|3|es|4|prefix|5>"
#define EVPN_TYPE_ALL_LIST_HELP_STR                                            \
	EVPN_TYPE_1_HELP_STR EVPN_TYPE_1_HELP_STR                              \
	EVPN_TYPE_2_HELP_STR EVPN_TYPE_2_HELP_STR                              \
	EVPN_TYPE_3_HELP_STR EVPN_TYPE_3_HELP_STR                              \
	EVPN_TYPE_4_HELP_STR EVPN_TYPE_4_HELP_STR                              \
	EVPN_TYPE_5_HELP_STR EVPN_TYPE_5_HELP_STR

/* Describing roles */
#define ROLE_STR                                                               \
	"Providing transit\nRoute server\nRS client\nUsing transit\nPublic/private peering\n"

/* BFD protocol integration strings. */
#define BFD_INTEGRATION_STR "BFD monitoring\n"
#define BFD_INTEGRATION_MULTI_HOP_STR "Use BFD multi hop session\n"
#define BFD_INTEGRATION_SOURCE_STR "Use source for BFD session\n"
#define BFD_INTEGRATION_SOURCEV4_STR "Use IPv4 source for BFD session\n"
#define BFD_INTEGRATION_SOURCEV6_STR "Use IPv4 source for BFD session\n"

/* Prototypes. */
extern void install_node(struct cmd_node *node);
extern void install_default(enum node_type);

struct xref_install_element {
	struct xref xref;

	const struct cmd_element *cmd_element;
	enum node_type node_type;
};

#define install_element(node_type_, cmd_element_) do {                         \
		static const struct xref_install_element _xref                 \
				__attribute__((used)) = {                      \
			.xref = XREF_INIT(XREFT_INSTALL_ELEMENT, NULL,         \
					  __func__),                           \
			.cmd_element = cmd_element_,                           \
			.node_type = node_type_,                               \
		};                                                             \
		XREF_LINK(_xref.xref);                                         \
		_install_element(node_type_, cmd_element_);                    \
	} while (0)

extern void _install_element(enum node_type, const struct cmd_element *);

/* known issue with uninstall_element:  changes to cmd_token->attr (i.e.
 * deprecated/hidden) are not reversed. */
extern void uninstall_element(enum node_type, const struct cmd_element *);

/* construct CLI tree only when entering nodes */
extern void cmd_defer_tree(bool val);

/* finish CLI tree for node when above is true (noop otherwise) */
extern void cmd_finalize_node(struct cmd_node *node);

/* Concatenates argv[shift] through argv[argc-1] into a single NUL-terminated
   string with a space between each element (allocated using
   XMALLOC(MTYPE_TMP)).  Returns NULL if shift >= argc. */
extern char *argv_concat(struct cmd_token **argv, int argc, int shift);

/*
 * It is preferred that you set the index initial value
 * to a 0.  This way in the future if you modify the
 * cli then there is no need to modify the initial
 * value of the index
 */
extern int argv_find(struct cmd_token **argv, int argc, const char *text,
		     int *index);

extern vector cmd_make_strvec(const char *);
extern void cmd_free_strvec(vector);
extern vector cmd_describe_command(vector, struct vty *, int *status);
extern char **cmd_complete_command(vector, struct vty *, int *status);
extern const char *cmd_prompt(enum node_type);
extern int command_config_read_one_line(struct vty *vty,
					const struct cmd_element **,
					uint32_t line_num, int use_config_node);
extern int config_from_file(struct vty *, FILE *, unsigned int *line_num);
extern enum node_type node_parent(enum node_type);
/*
 * Execute command under the given vty context.
 *
 * vty
 *    The vty context to execute under.
 *
 * cmd
 *    The command string to execute.
 *
 * matched
 *    If non-null and a match was found, the address of the matched command is
 *    stored here. No action otherwise.
 *
 * vtysh
 *    Whether or not this is being called from vtysh. If this is nonzero,
 *    XXX: then what?
 *
 * Returns:
 *    XXX: what does it return
 */
extern int cmd_execute(struct vty *vty, const char *cmd,
		       const struct cmd_element **matched, int vtysh);
extern int cmd_execute_command(vector, struct vty *,
			       const struct cmd_element **, int);
extern int cmd_execute_command_strict(vector, struct vty *,
				      const struct cmd_element **);
extern void cmd_init(int terminal);
extern void cmd_init_config_callbacks(void (*start_config_cb)(void),
				      void (*end_config_cb)(void));
extern void cmd_terminate(void);
extern void cmd_exit(struct vty *vty);
extern int cmd_list_cmds(struct vty *vty, int do_permute);
extern int cmd_find_cmds(struct vty *vty, struct cmd_token **argv, int argc);

extern int cmd_domainname_set(const char *domainname);
extern int cmd_hostname_set(const char *hostname);
extern const char *cmd_hostname_get(void);
extern const char *cmd_domainname_get(void);
extern const char *cmd_system_get(void);
extern const char *cmd_release_get(void);
extern const char *cmd_version_get(void);
extern const char *cmd_software_version_get(void);
extern bool cmd_allow_reserved_ranges_get(void);

/* NOT safe for general use; call this only if DEV_BUILD! */
extern void grammar_sandbox_init(void);

extern vector completions_to_vec(struct list *completions);

/* Export typical functions. */
extern const char *host_config_get(void);
extern void host_config_set(const char *);

extern void print_version(const char *);

extern int cmd_banner_motd_file(const char *);
extern void cmd_banner_motd_line(const char *line);

struct cmd_variable_handler {
	const char *tokenname, *varname;
	const char *xpath;	/* fill comps from set of values at xpath */
	void (*completions)(vector out, struct cmd_token *token);
};

extern void cmd_variable_complete(struct cmd_token *token, const char *arg,
				  vector comps);
extern void
cmd_variable_handler_register(const struct cmd_variable_handler *cvh);
extern char *cmd_variable_comp2str(vector comps, unsigned short cols);

extern void command_setup_early_logging(const char *dest, const char *level);

/*
 * Allow a mechanism for `debug XXX` commands that live
 * under the lib directory to output their debug status
 */
extern void cmd_show_lib_debugs(struct vty *vty);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_COMMAND_H */
