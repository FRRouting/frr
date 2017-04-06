/*
 * Zebra configuration command interface routine
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#ifndef _ZEBRA_COMMAND_H
#define _ZEBRA_COMMAND_H

#include "vector.h"
#include "vty.h"
#include "lib/route_types.h"
#include "graph.h"
#include "memory.h"
#include "hash.h"

DECLARE_MTYPE(HOST)
DECLARE_MTYPE(CMD_ARG)

/* for test-commands.c */
DECLARE_MTYPE(STRVEC)

/* Host configuration variable */
struct host
{
  /* Host name of this router. */
  char *name;

  /* Password for vty interface. */
  char *password;
  char *password_encrypt;

  /* Enable password */
  char *enable;
  char *enable_encrypt;

  /* System wide terminal lines. */
  int lines;

  /* Log filename. */
  char *logfile;

  /* config file name of this host */
  char *config;
  int noconfig;

  /* Flags for services */
  int advanced;
  int encrypt;

  /* Banner configuration. */
  const char *motd;
  char *motdfile;
};

/* There are some command levels which called from command node. */
enum node_type
{
  AUTH_NODE,                    /* Authentication mode of vty interface. */
  VIEW_NODE,                    /* View node. Default mode of vty interface. */
  AUTH_ENABLE_NODE,             /* Authentication mode for change enable. */
  ENABLE_NODE,                  /* Enable node. */
  CONFIG_NODE,                  /* Config node. Default mode of config file. */
  SERVICE_NODE,                 /* Service node. */
  DEBUG_NODE,                   /* Debug node. */
  VRF_DEBUG_NODE,               /* Vrf Debug node. */
  DEBUG_VNC_NODE,		/* Debug VNC node. */
  AAA_NODE,                     /* AAA node. */
  KEYCHAIN_NODE,                /* Key-chain node. */
  KEYCHAIN_KEY_NODE,            /* Key-chain key node. */
  NS_NODE,                      /* Logical-Router node. */
  VRF_NODE,                     /* VRF mode node. */
  INTERFACE_NODE,               /* Interface mode node. */
  ZEBRA_NODE,                   /* zebra connection node. */
  TABLE_NODE,                   /* rtm_table selection node. */
  RIP_NODE,                     /* RIP protocol mode node. */
  RIPNG_NODE,                   /* RIPng protocol mode node. */
  BGP_NODE,                     /* BGP protocol mode which includes BGP4+ */
  BGP_VPNV4_NODE,               /* BGP MPLS-VPN PE exchange. */
  BGP_VPNV6_NODE,               /* BGP MPLS-VPN PE exchange. */
  BGP_IPV4_NODE,                /* BGP IPv4 unicast address family.  */
  BGP_IPV4M_NODE,               /* BGP IPv4 multicast address family.  */
  BGP_IPV4L_NODE,               /* BGP IPv4 labeled unicast address family.  */
  BGP_IPV6_NODE,                /* BGP IPv6 address family */
  BGP_IPV6M_NODE,               /* BGP IPv6 multicast address family. */
  BGP_IPV6L_NODE,               /* BGP IPv6 labeled unicast address family. */
  BGP_ENCAP_NODE,               /* BGP ENCAP SAFI */
  BGP_ENCAPV6_NODE,             /* BGP ENCAP SAFI */
  BGP_VRF_POLICY_NODE,          /* BGP VRF policy */
  BGP_VNC_DEFAULTS_NODE,	/* BGP VNC nve defaults */
  BGP_VNC_NVE_GROUP_NODE,	/* BGP VNC nve group */
  BGP_VNC_L2_GROUP_NODE,	/* BGP VNC L2 group */
  RFP_DEFAULTS_NODE,	/* RFP defaults node */
  BGP_EVPN_NODE,	        /* BGP EVPN node. */
  OSPF_NODE,                    /* OSPF protocol mode */
  OSPF6_NODE,                   /* OSPF protocol for IPv6 mode */
  LDP_NODE,			/* LDP protocol mode */
  LDP_IPV4_NODE,		/* LDP IPv4 address family */
  LDP_IPV6_NODE,		/* LDP IPv6 address family */
  LDP_IPV4_IFACE_NODE,		/* LDP IPv4 Interface */
  LDP_IPV6_IFACE_NODE,		/* LDP IPv6 Interface */
  LDP_L2VPN_NODE,		/* LDP L2VPN node */
  LDP_PSEUDOWIRE_NODE,		/* LDP Pseudowire node */
  ISIS_NODE,                    /* ISIS protocol mode */
  PIM_NODE,                     /* PIM protocol mode */
  MASC_NODE,                    /* MASC for multicast.  */
  IRDP_NODE,                    /* ICMP Router Discovery Protocol mode. */
  IP_NODE,                      /* Static ip route node. */
  ACCESS_NODE,                  /* Access list node. */
  PREFIX_NODE,                  /* Prefix list node. */
  ACCESS_IPV6_NODE,             /* Access list node. */
  PREFIX_IPV6_NODE,             /* Prefix list node. */
  AS_LIST_NODE,                 /* AS list node. */
  COMMUNITY_LIST_NODE,          /* Community list node. */
  RMAP_NODE,                    /* Route map node. */
  SMUX_NODE,                    /* SNMP configuration node. */
  DUMP_NODE,                    /* Packet dump node. */
  FORWARDING_NODE,              /* IP forwarding node. */
  PROTOCOL_NODE,                /* protocol filtering node */
  MPLS_NODE,                    /* MPLS config node */
  VTY_NODE,                     /* Vty node. */
  LINK_PARAMS_NODE,             /* Link-parameters node */
  UNDEFINED_NODE
};

/* Node which has some commands and prompt string and configuration
   function pointer . */
struct cmd_node
{
  /* Node index. */
  enum node_type node;

  /* Prompt character at vty interface. */
  const char *prompt;

  /* Is this node's configuration goes to vtysh ? */
  int vtysh;

  /* Node's configuration write function */
  int (*func) (struct vty *);

  /* Node's command graph */
  struct graph *cmdgraph;

  /* Vector of this node's command list. */
  vector cmd_vector;

  /* Hashed index of command node list, for de-dupping primarily */
  struct hash *cmd_hash;
};

/**
 * Types for tokens.
 *
 * The type determines what kind of data the token can match (in the
 * matching use case) or hold (in the argv use case).
 */
enum cmd_token_type
{
  WORD_TKN,         // words
  VARIABLE_TKN,     // almost anything
  RANGE_TKN,        // integer range
  IPV4_TKN,         // IPV4 addresses
  IPV4_PREFIX_TKN,  // IPV4 network prefixes
  IPV6_TKN,         // IPV6 prefixes
  IPV6_PREFIX_TKN,  // IPV6 network prefixes

  /* plumbing types */
  FORK_TKN,         // marks subgraph beginning
  JOIN_TKN,         // marks subgraph end
  START_TKN,        // first token in line
  END_TKN,          // last token in line

  SPECIAL_TKN = FORK_TKN,
};

/* Command attributes */
enum
{
  CMD_ATTR_NORMAL,
  CMD_ATTR_DEPRECATED,
  CMD_ATTR_HIDDEN,
};

/* Comamand token struct. */
struct cmd_token
{
  enum cmd_token_type type;     // token type
  u_char attr;                  // token attributes
  bool allowrepeat;             // matcher allowed to match token repetively?
  uint32_t refcnt;

  char *text;                   // token text
  char *desc;                   // token description
  long long min, max;           // for ranges
  char *arg;                    // user input that matches this token

  struct graph_node *forkjoin;  // paired FORK/JOIN for JOIN/FORK
};

/* Structure of command element. */
struct cmd_element
{
  const char *string;           /* Command specification by string. */
  const char *doc;              /* Documentation of this command. */
  int daemon;                   /* Daemon to which this command belong. */
  u_char attr;                  /* Command attributes */

  /* handler function for command */
  int (*func) (const struct cmd_element *, struct vty *, int, struct cmd_token *[]);

  const char *name;             /* symbol name for debugging */
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

/* Argc max counts. */
#define CMD_ARGC_MAX   25

/* Turn off these macros when uisng cpp with extract.pl */
#ifndef VTYSH_EXTRACT_PL

/* helper defines for end-user DEFUN* macros */
#define DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, attrs, dnum) \
  static struct cmd_element cmdname = \
  { \
    .string = cmdstr, \
    .func = funcname, \
    .doc = helpstr, \
    .attr = attrs, \
    .daemon = dnum, \
    .name = #cmdname, \
  };

#define DEFUN_CMD_FUNC_DECL(funcname) \
  static int funcname (const struct cmd_element *, struct vty *, int, struct cmd_token *[]);

#define DEFUN_CMD_FUNC_TEXT(funcname) \
  static int funcname \
    (const struct cmd_element *self __attribute__ ((unused)), \
     struct vty *vty __attribute__ ((unused)), \
     int argc __attribute__ ((unused)), \
     struct cmd_token *argv[] __attribute__ ((unused)) )

#define DEFUN(funcname, cmdname, cmdstr, helpstr) \
  DEFUN_CMD_FUNC_DECL(funcname) \
  DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, 0, 0) \
  DEFUN_CMD_FUNC_TEXT(funcname)

#define DEFUN_ATTR(funcname, cmdname, cmdstr, helpstr, attr) \
  DEFUN_CMD_FUNC_DECL(funcname) \
  DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, attr, 0) \
  DEFUN_CMD_FUNC_TEXT(funcname)

#define DEFUN_HIDDEN(funcname, cmdname, cmdstr, helpstr) \
  DEFUN_ATTR (funcname, cmdname, cmdstr, helpstr, CMD_ATTR_HIDDEN)

#define DEFUN_DEPRECATED(funcname, cmdname, cmdstr, helpstr) \
  DEFUN_ATTR (funcname, cmdname, cmdstr, helpstr, CMD_ATTR_DEPRECATED) \

/* DEFUN_NOSH for commands that vtysh should ignore */
#define DEFUN_NOSH(funcname, cmdname, cmdstr, helpstr) \
  DEFUN(funcname, cmdname, cmdstr, helpstr)

/* DEFSH for vtysh. */
#define DEFSH(daemon, cmdname, cmdstr, helpstr) \
  DEFUN_CMD_ELEMENT(NULL, cmdname, cmdstr, helpstr, 0, daemon) \

#define DEFSH_HIDDEN(daemon, cmdname, cmdstr, helpstr) \
  DEFUN_CMD_ELEMENT(NULL, cmdname, cmdstr, helpstr, CMD_ATTR_HIDDEN, daemon) \

/* DEFUN + DEFSH */
#define DEFUNSH(daemon, funcname, cmdname, cmdstr, helpstr) \
  DEFUN_CMD_FUNC_DECL(funcname) \
  DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, 0, daemon) \
  DEFUN_CMD_FUNC_TEXT(funcname)

/* DEFUN + DEFSH with attributes */
#define DEFUNSH_ATTR(daemon, funcname, cmdname, cmdstr, helpstr, attr) \
  DEFUN_CMD_FUNC_DECL(funcname) \
  DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, attr, daemon) \
  DEFUN_CMD_FUNC_TEXT(funcname)

#define DEFUNSH_HIDDEN(daemon, funcname, cmdname, cmdstr, helpstr) \
  DEFUNSH_ATTR (daemon, funcname, cmdname, cmdstr, helpstr, CMD_ATTR_HIDDEN)

#define DEFUNSH_DEPRECATED(daemon, funcname, cmdname, cmdstr, helpstr) \
  DEFUNSH_ATTR (daemon, funcname, cmdname, cmdstr, helpstr, CMD_ATTR_DEPRECATED)

/* ALIAS macro which define existing command's alias. */
#define ALIAS(funcname, cmdname, cmdstr, helpstr) \
  DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, 0, 0)

#define ALIAS_ATTR(funcname, cmdname, cmdstr, helpstr, attr) \
  DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, attr, 0)

#define ALIAS_HIDDEN(funcname, cmdname, cmdstr, helpstr) \
  DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, CMD_ATTR_HIDDEN, 0)

#define ALIAS_DEPRECATED(funcname, cmdname, cmdstr, helpstr) \
  DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, CMD_ATTR_DEPRECATED, 0)

#define ALIAS_SH(daemon, funcname, cmdname, cmdstr, helpstr) \
  DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, 0, daemon)

#define ALIAS_SH_HIDDEN(daemon, funcname, cmdname, cmdstr, helpstr) \
  DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, CMD_ATTR_HIDDEN, daemon)

#define ALIAS_SH_DEPRECATED(daemon, funcname, cmdname, cmdstr, helpstr) \
  DEFUN_CMD_ELEMENT(funcname, cmdname, cmdstr, helpstr, CMD_ATTR_DEPRECATED, daemon)

#endif /* VTYSH_EXTRACT_PL */

/* Some macroes */

/*
 * Sometimes #defines create maximum values that
 * need to have strings created from them that
 * allow the parser to match against them.
 * These macros allow that.
 */
#define CMD_CREATE_STR(s)  CMD_CREATE_STR_HELPER(s)
#define CMD_CREATE_STR_HELPER(s) #s

/* Common descriptions. */
#define SHOW_STR "Show running system information\n"
#define IP_STR "IP information\n"
#define IPV6_STR "IPv6 information\n"
#define NO_STR "Negate a command or set its defaults\n"
#define REDIST_STR "Redistribute information from another routing protocol\n"
#define CLEAR_STR "Reset functions\n"
#define RIP_STR "RIP information\n"
#define BGP_STR "BGP information\n"
#define BGP_SOFT_STR "Soft reconfig inbound and outbound updates\n"
#define BGP_SOFT_IN_STR "Send route-refresh unless using 'soft-reconfiguration inbound'\n"
#define BGP_SOFT_OUT_STR "Resend all outbound updates\n"
#define BGP_SOFT_RSCLIENT_RIB_STR "Soft reconfig for rsclient RIB\n"
#define OSPF_STR "OSPF information\n"
#define NEIGHBOR_STR "Specify neighbor router\n"
#define DEBUG_STR "Debugging functions (see also 'undebug')\n"
#define UNDEBUG_STR "Disable debugging functions (see also 'debug')\n"
#define ROUTER_STR "Enable a routing process\n"
#define AS_STR "AS number\n"
#define MBGP_STR "MBGP information\n"
#define MATCH_STR "Match values from routing table\n"
#define SET_STR "Set values in destination routing protocol\n"
#define OUT_STR "Filter outgoing routing updates\n"
#define IN_STR  "Filter incoming routing updates\n"
#define V4NOTATION_STR "specify by IPv4 address notation(e.g. 0.0.0.0)\n"
#define OSPF6_NUMBER_STR "Specify by number\n"
#define INTERFACE_STR "Interface infomation\n"
#define IFNAME_STR "Interface name(e.g. ep0)\n"
#define IP6_STR "IPv6 Information\n"
#define OSPF6_STR "Open Shortest Path First (OSPF) for IPv6\n"
#define OSPF6_INSTANCE_STR "(1-65535) Instance ID\n"
#define SECONDS_STR "Seconds\n"
#define ROUTE_STR "Routing Table\n"
#define PREFIX_LIST_STR "Build a prefix list\n"
#define OSPF6_DUMP_TYPE_LIST \
"<neighbor|interface|area|lsa|zebra|config|dbex|spf|route|lsdb|redistribute|hook|asbr|prefix|abr>"
#define ISIS_STR "IS-IS information\n"
#define AREA_TAG_STR "[area tag]\n"
#define COMMUNITY_AANN_STR "Community number where AA and NN are (0-65535)\n"
#define COMMUNITY_VAL_STR  "Community number in AA:NN format (where AA and NN are (0-65535)) or local-AS|no-advertise|no-export|internet or additive\n"
#define MPLS_TE_STR "MPLS-TE specific commands\n"
#define LINK_PARAMS_STR "Configure interface link parameters\n"
#define OSPF_RI_STR "OSPF Router Information specific commands\n"
#define PCE_STR "PCE Router Information specific commands\n"
#define MPLS_STR "MPLS information\n"

#define CONF_BACKUP_EXT ".sav"

/* IPv4 only machine should not accept IPv6 address for peer's IP
   address.  So we replace VTY command string like below. */
#define NEIGHBOR_ADDR_STR  "Neighbor address\nIPv6 address\n"
#define NEIGHBOR_ADDR_STR2 "Neighbor address\nNeighbor IPv6 address\nInterface name or neighbor tag\n"
#define NEIGHBOR_ADDR_STR3 "Neighbor address\nIPv6 address\nInterface name\n"

/* Prototypes. */
extern void install_node (struct cmd_node *, int (*) (struct vty *));
extern void install_default (enum node_type);
extern void install_element (enum node_type, struct cmd_element *);

/* known issue with uninstall_element:  changes to cmd_token->attr (i.e.
 * deprecated/hidden) are not reversed. */
extern void uninstall_element (enum node_type, struct cmd_element *);

/* Concatenates argv[shift] through argv[argc-1] into a single NUL-terminated
   string with a space between each element (allocated using
   XMALLOC(MTYPE_TMP)).  Returns NULL if shift >= argc. */
extern char *argv_concat (struct cmd_token **argv, int argc, int shift);
extern int argv_find (struct cmd_token **argv, int argc, const char *text, int *index);

extern vector cmd_make_strvec (const char *);
extern void cmd_free_strvec (vector);
extern vector cmd_describe_command (vector, struct vty *, int *status);
extern char **cmd_complete_command (vector, struct vty *, int *status);
extern const char *cmd_prompt (enum node_type);
extern int command_config_read_one_line (struct vty *vty, const struct cmd_element **, int use_config_node);
extern int config_from_file (struct vty *, FILE *, unsigned int *line_num);
extern enum node_type node_parent (enum node_type);
extern int cmd_execute_command (vector, struct vty *, const struct cmd_element **, int);
extern int cmd_execute_command_strict (vector, struct vty *, const struct cmd_element **);
extern void cmd_init (int);
extern void cmd_terminate (void);
extern void cmd_exit (struct vty *vty);
extern int cmd_list_cmds (struct vty *vty, int do_permute);

extern int cmd_hostname_set (const char *hostname);

/* NOT safe for general use; call this only if DEV_BUILD! */
extern void grammar_sandbox_init (void);

/* memory management for cmd_token */
extern struct cmd_token *new_cmd_token (enum cmd_token_type, u_char attr,
                                        const char *text, const char *desc);
extern void del_cmd_token (struct cmd_token *);
extern struct cmd_token *copy_cmd_token (struct cmd_token *);

extern vector completions_to_vec (struct list *completions);
extern void cmd_merge_graphs (struct graph *old, struct graph *new, int direction);
extern void command_parse_format (struct graph *graph, struct cmd_element *cmd);

/* Export typical functions. */
extern const char *host_config_get (void);
extern void host_config_set (const char *);

extern void print_version (const char *);

extern int cmd_banner_motd_file (const char *);

/* struct host global, ick */
extern struct host host;

/* text for <cr> command */
#define CMD_CR_TEXT "<cr>"

#endif /* _ZEBRA_COMMAND_H */
