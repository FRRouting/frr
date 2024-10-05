// SPDX-License-Identifier: GPL-2.0-or-later
/* Route map function.
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_ROUTEMAP_H
#define _ZEBRA_ROUTEMAP_H

#include "typesafe.h"
#include "prefix.h"
#include "memory.h"
#include "qobj.h"
#include "vty.h"
#include "lib/plist.h"
#include "lib/plist_int.h"

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MTYPE(ROUTE_MAP_NAME);
DECLARE_MTYPE(ROUTE_MAP_RULE);
DECLARE_MTYPE(ROUTE_MAP_COMPILED);

#define DEBUG_ROUTEMAP 0x01
#define DEBUG_ROUTEMAP_DETAIL 0x02
extern uint32_t rmap_debug;

/* Route map's type. */
enum route_map_type { RMAP_PERMIT, RMAP_DENY, RMAP_ANY };

typedef enum {
	RMAP_DENYMATCH,
	RMAP_PERMITMATCH
} route_map_result_t;

/*
 * Route-map match or set result "Eg: match evpn vni xx"
 * route-map match cmd always returns match/nomatch/noop
 *    match--> found a match
 *    nomatch--> didnt find a match
 *    noop--> not applicable
 * route-map set retuns okay/error
 *    okay --> set was successful
 *    error --> set was not successful
 */
enum route_map_cmd_result_t {
	/*
	 * route-map match cmd results
	 */
	RMAP_MATCH,
	RMAP_NOMATCH,
	RMAP_NOOP,
	/*
	 * route-map set cmd results
	 */
	RMAP_OKAY,
	RMAP_ERROR
};

typedef enum { RMAP_EXIT, RMAP_GOTO, RMAP_NEXT } route_map_end_t;

typedef enum {
	RMAP_EVENT_SET_ADDED,
	RMAP_EVENT_SET_DELETED,
	RMAP_EVENT_SET_REPLACED,
	RMAP_EVENT_MATCH_ADDED,
	RMAP_EVENT_MATCH_DELETED,
	RMAP_EVENT_MATCH_REPLACED,
	RMAP_EVENT_INDEX_ADDED,
	RMAP_EVENT_INDEX_DELETED,
	RMAP_EVENT_CALL_ADDED, /* call to another routemap added */
	RMAP_EVENT_CALL_DELETED,
	RMAP_EVENT_PLIST_ADDED,
	RMAP_EVENT_PLIST_DELETED,
	RMAP_EVENT_CLIST_ADDED,
	RMAP_EVENT_CLIST_DELETED,
	RMAP_EVENT_ECLIST_ADDED,
	RMAP_EVENT_ECLIST_DELETED,
	RMAP_EVENT_LLIST_ADDED,
	RMAP_EVENT_LLIST_DELETED,
	RMAP_EVENT_ASLIST_ADDED,
	RMAP_EVENT_ASLIST_DELETED,
	RMAP_EVENT_FILTER_ADDED,
	RMAP_EVENT_FILTER_DELETED,
} route_map_event_t;

/* Depth limit in RMAP recursion using RMAP_CALL. */
#define RMAP_RECURSION_LIMIT      10

/* Route map rule structure for matching and setting. */
struct route_map_rule_cmd {
	/* Route map rule name (e.g. as-path, metric) */
	const char *str;

	/* Function for value set or match. */
	enum route_map_cmd_result_t (*func_apply)(void *rule,
						  const struct prefix *prefix,
						  void *object);

	/* Compile argument and return result as void *. */
	void *(*func_compile)(const char *);

	/* Free allocated value by func_compile (). */
	void (*func_free)(void *);

	/** To get the rule key after Compilation **/
	void *(*func_get_rmap_rule_key)(void *val);
};

/* Route map apply error. */
enum rmap_compile_rets {
	RMAP_COMPILE_SUCCESS,

	/* Route map rule is missing. */
	RMAP_RULE_MISSING,

	/* Route map rule can't compile */
	RMAP_COMPILE_ERROR,

};

/* Route map rule. This rule has both `match' rule and `set' rule. */
struct route_map_rule {
	/* Rule type. */
	const struct route_map_rule_cmd *cmd;

	/* For pretty printing. */
	char *rule_str;

	/* Pre-compiled match rule. */
	void *value;

	/* Linked list. */
	struct route_map_rule *next;
	struct route_map_rule *prev;
};

/* Route map rule list. */
struct route_map_rule_list {
	struct route_map_rule *head;
	struct route_map_rule *tail;
};

/* Forward struct declaration: the complete can be found later this file. */
struct routemap_hook_context;

/* Route map index structure. */
struct route_map_index {
	struct route_map *map;
	char *description;

	/* Preference of this route map rule. */
	int pref;

	/* Route map type permit or deny. */
	enum route_map_type type;

	/* Do we follow old rules, or hop forward? */
	route_map_end_t exitpolicy;

	/* If we're using "GOTO", to where do we go? */
	int nextpref;

	/* If we're using "CALL", to which route-map do ew go? */
	char *nextrm;

	/* Matching rule list. */
	struct route_map_rule_list match_list;
	struct route_map_rule_list set_list;

	/* Make linked list. */
	struct route_map_index *next;
	struct route_map_index *prev;

	/* Keep track how many times we've try to apply */
	uint64_t applied;
	uint64_t applied_clear;

	/* List of match/sets contexts. */
	TAILQ_HEAD(, routemap_hook_context) rhclist;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(route_map_index);

/* route map maximum length. Not strictly the maximum xpath length but cannot be
 * greater
 */
#define RMAP_NAME_MAXLEN XPATH_MAXLEN

/* Route map list structure. */
struct route_map {
	/* Name of route map. */
	char *name;

	/* Route map's rule. */
	struct route_map_index *head;
	struct route_map_index *tail;

	/* Make linked list. */
	struct route_map *next;
	struct route_map *prev;

	/* Maintain update info */
	bool to_be_processed; /* True if modification isn't acted on yet */
	bool deleted;         /* If 1, then this node will be deleted */
	bool optimization_disabled;

	/* How many times have we applied this route-map */
	uint64_t applied;
	uint64_t applied_clear;

	/* Counter to track active usage of this route-map */
	uint16_t use_count;

	/* Tables to maintain IPv4 and IPv6 prefixes from
	 * the prefix-list match clause.
	 */
	struct route_table *ipv4_prefix_table;
	struct route_table *ipv6_prefix_table;

	QOBJ_FIELDS;
};
DECLARE_QOBJ_TYPE(route_map);

/* Route-map match conditions */
#define IS_MATCH_INTERFACE(C)                                                  \
	(strmatch(C, "frr-route-map:interface"))
#define IS_MATCH_IPv4_ADDRESS_LIST(C)                                          \
	(strmatch(C, "frr-route-map:ipv4-address-list"))
#define IS_MATCH_IPv6_ADDRESS_LIST(C)                                          \
	(strmatch(C, "frr-route-map:ipv6-address-list"))
#define IS_MATCH_IPv4_NEXTHOP_LIST(C)                                          \
	(strmatch(C, "frr-route-map:ipv4-next-hop-list"))
#define IS_MATCH_IPv6_NEXTHOP_LIST(C)                                          \
	(strmatch(C, "frr-route-map:ipv6-next-hop-list"))
#define IS_MATCH_IPv4_PREFIX_LIST(C)                                           \
	(strmatch(C, "frr-route-map:ipv4-prefix-list"))
#define IS_MATCH_IPv6_PREFIX_LIST(C)                                           \
	(strmatch(C, "frr-route-map:ipv6-prefix-list"))
#define IS_MATCH_IPv4_NEXTHOP_PREFIX_LIST(C)                                   \
	(strmatch(C, "frr-route-map:ipv4-next-hop-prefix-list"))
#define IS_MATCH_IPv6_NEXTHOP_PREFIX_LIST(C)                                   \
	(strmatch(C, "frr-route-map:ipv6-next-hop-prefix-list"))
#define IS_MATCH_IPv4_NEXTHOP_TYPE(C)                                          \
	(strmatch(C, "frr-route-map:ipv4-next-hop-type"))
#define IS_MATCH_IPv6_NEXTHOP_TYPE(C)                                          \
	(strmatch(C, "frr-route-map:ipv6-next-hop-type"))
#define IS_MATCH_METRIC(C)                                                     \
	(strmatch(C, "frr-route-map:match-metric"))
#define IS_MATCH_TAG(C) (strmatch(C, "frr-route-map:match-tag"))
/* Zebra route-map match conditions */
#define IS_MATCH_IPv4_PREFIX_LEN(C)                                            \
	(strmatch(C, "frr-zebra-route-map:ipv4-prefix-length"))
#define IS_MATCH_IPv6_PREFIX_LEN(C)                                            \
	(strmatch(C, "frr-zebra-route-map:ipv6-prefix-length"))
#define IS_MATCH_IPv4_NH_PREFIX_LEN(C)                                         \
	(strmatch(C, "frr-zebra-route-map:ipv4-next-hop-prefix-length"))
#define IS_MATCH_SRC_PROTO(C)                                                  \
	(strmatch(C, "frr-zebra-route-map:source-protocol"))
#define IS_MATCH_BGP_SRC_PROTO(C)                                              \
	(strmatch(C, "frr-bgp-route-map:source-protocol"))
#define IS_MATCH_SRC_INSTANCE(C)                                               \
	(strmatch(C, "frr-zebra-route-map:source-instance"))
/* BGP route-map match conditions */
#define IS_MATCH_LOCAL_PREF(C)                                                 \
	(strmatch(C, "frr-bgp-route-map:match-local-preference"))
#define IS_MATCH_ALIAS(C) (strmatch(C, "frr-bgp-route-map:match-alias"))
#define IS_MATCH_SCRIPT(C) (strmatch(C, "frr-bgp-route-map:match-script"))
#define IS_MATCH_ORIGIN(C)                                                     \
	(strmatch(C, "frr-bgp-route-map:match-origin"))
#define IS_MATCH_RPKI(C) (strmatch(C, "frr-bgp-route-map:rpki"))
#define IS_MATCH_RPKI_EXTCOMMUNITY(C)                                          \
	(strmatch(C, "frr-bgp-route-map:rpki-extcommunity"))
#define IS_MATCH_PROBABILITY(C)                                                \
	(strmatch(C, "frr-bgp-route-map:probability"))
#define IS_MATCH_SRC_VRF(C)                                                    \
	(strmatch(C, "frr-bgp-route-map:source-vrf"))
#define IS_MATCH_PEER(C) (strmatch(C, "frr-bgp-route-map:peer"))
#define IS_MATCH_AS_LIST(C)                                                    \
	(strmatch(C, "frr-bgp-route-map:as-path-list"))
#define IS_MATCH_MAC_LIST(C)                                                   \
	(strmatch(C, "frr-bgp-route-map:mac-address-list"))
#define IS_MATCH_EVPN_ROUTE_TYPE(C)                                            \
	(strmatch(C, "frr-bgp-route-map:evpn-route-type"))
#define IS_MATCH_EVPN_DEFAULT_ROUTE(C)                                         \
	(strmatch(C, "frr-bgp-route-map:evpn-default-route"))
#define IS_MATCH_EVPN_VNI(C)                                                   \
	(strmatch(C, "frr-bgp-route-map:evpn-vni"))
#define IS_MATCH_EVPN_DEFAULT_ROUTE(C)                                         \
	(strmatch(C, "frr-bgp-route-map:evpn-default-route"))
#define IS_MATCH_EVPN_RD(C)                                                    \
	(strmatch(C, "frr-bgp-route-map:evpn-rd"))
#define IS_MATCH_ROUTE_SRC(C)                                                  \
	(strmatch(C, "frr-bgp-route-map:ip-route-source"))
#define IS_MATCH_ROUTE_SRC_PL(C)                                               \
	(strmatch(C, "frr-bgp-route-map:ip-route-source-prefix-list"))
#define IS_MATCH_COMMUNITY(C)                                                  \
	(strmatch(C, "frr-bgp-route-map:match-community"))
#define IS_MATCH_LCOMMUNITY(C)                                                 \
	(strmatch(C, "frr-bgp-route-map:match-large-community"))
#define IS_MATCH_EXTCOMMUNITY(C)                                               \
	(strmatch(C, "frr-bgp-route-map:match-extcommunity"))
#define IS_MATCH_IPV4_NH(C)                                                    \
	(strmatch(C, "frr-bgp-route-map:ipv4-nexthop"))
#define IS_MATCH_IPV6_NH(C)                                                    \
	(strmatch(C, "frr-bgp-route-map:ipv6-nexthop"))

/* Route-map set actions */
#define IS_SET_IPv4_NH(A)                                                      \
	(strmatch(A, "frr-route-map:ipv4-next-hop"))
#define IS_SET_IPv6_NH(A)                                                      \
	(strmatch(A, "frr-route-map:ipv6-next-hop"))
#define IS_SET_METRIC(A)                                                       \
	(strmatch(A, "frr-route-map:set-metric"))
#define IS_SET_MIN_METRIC(A) (strmatch(A, "frr-route-map:set-min-metric"))
#define IS_SET_MAX_METRIC(A) (strmatch(A, "frr-route-map:set-max-metric"))
#define IS_SET_TAG(A) (strmatch(A, "frr-route-map:set-tag"))
#define IS_SET_SR_TE_COLOR(A)                                                  \
	(strmatch(A, "frr-route-map:set-sr-te-color"))
/* Zebra route-map set actions */
#define IS_SET_SRC(A)                                                          \
	(strmatch(A, "frr-zebra-route-map:src-address"))
/* OSPF route-map set actions */
#define IS_SET_METRIC_TYPE(A)                                                  \
	(strmatch(A, "frr-ospf-route-map:metric-type"))
#define IS_SET_FORWARDING_ADDR(A)                                              \
	(strmatch(A, "frr-ospf6-route-map:forwarding-address"))
/* BGP route-map_set actions */
#define IS_SET_WEIGHT(A)                                                       \
	(strmatch(A, "frr-bgp-route-map:weight"))
#define IS_SET_TABLE(A) (strmatch(A, "frr-bgp-route-map:table"))
#define IS_SET_LOCAL_PREF(A)                                                   \
	(strmatch(A, "frr-bgp-route-map:set-local-preference"))
#define IS_SET_LABEL_INDEX(A)                                                  \
	(strmatch(A, "frr-bgp-route-map:label-index"))
#define IS_SET_DISTANCE(A)                                                     \
	(strmatch(A, "frr-bgp-route-map:distance"))
#define IS_SET_ORIGIN(A)                                                       \
	(strmatch(A, "frr-bgp-route-map:set-origin"))
#define IS_SET_ATOMIC_AGGREGATE(A)                                             \
	(strmatch(A, "frr-bgp-route-map:atomic-aggregate"))
#define IS_SET_AIGP_METRIC(A) (strmatch(A, "frr-bgp-route-map:aigp-metric"))
#define IS_SET_ORIGINATOR_ID(A)                                                \
	(strmatch(A, "frr-bgp-route-map:originator-id"))
#define IS_SET_COMM_LIST_DEL(A)                                                \
	(strmatch(A, "frr-bgp-route-map:comm-list-delete"))
#define IS_SET_LCOMM_LIST_DEL(A)                                               \
	(strmatch(A, "frr-bgp-route-map:large-comm-list-delete"))
#define IS_SET_EXTCOMM_LIST_DEL(A)                                                \
	(strmatch(A, "frr-bgp-route-map:extended-comm-list-delete"))
#define IS_SET_LCOMMUNITY(A)                                                   \
	(strmatch(A, "frr-bgp-route-map:set-large-community"))
#define IS_SET_COMMUNITY(A)                                                    \
	(strmatch(A, "frr-bgp-route-map:set-community"))
#define IS_SET_EXTCOMMUNITY_NONE(A)                                            \
	(strmatch(A, "frr-bgp-route-map:set-extcommunity-none"))
#define IS_SET_EXTCOMMUNITY_RT(A)                                              \
	(strmatch(A, "frr-bgp-route-map:set-extcommunity-rt"))
#define IS_SET_EXTCOMMUNITY_NT(A)                                              \
	(strmatch(A, "frr-bgp-route-map:set-extcommunity-nt"))
#define IS_SET_EXTCOMMUNITY_SOO(A)                                             \
	(strmatch(A, "frr-bgp-route-map:set-extcommunity-soo"))
#define IS_SET_EXTCOMMUNITY_LB(A)                                              \
	(strmatch(A, "frr-bgp-route-map:set-extcommunity-lb"))
#define IS_SET_EXTCOMMUNITY_COLOR(A)                                           \
	(strmatch(A, "frr-bgp-route-map:set-extcommunity-color"))

#define IS_SET_AGGREGATOR(A)                                                   \
	(strmatch(A, "frr-bgp-route-map:aggregator"))
#define IS_SET_AS_PREPEND(A)                                                   \
	(strmatch(A, "frr-bgp-route-map:as-path-prepend"))
#define IS_SET_AS_EXCLUDE(A)                                                   \
	(strmatch(A, "frr-bgp-route-map:as-path-exclude"))
#define IS_SET_AS_REPLACE(A) (strmatch(A, "frr-bgp-route-map:as-path-replace"))
#define IS_SET_IPV6_NH_GLOBAL(A)                                               \
	(strmatch(A, "frr-bgp-route-map:ipv6-nexthop-global"))
#define IS_SET_IPV6_VPN_NH(A)                                                  \
	(strmatch(A, "frr-bgp-route-map:ipv6-vpn-address"))
#define IS_SET_IPV6_PEER_ADDR(A)                                               \
	(strmatch(A, "frr-bgp-route-map:ipv6-peer-address"))
#define IS_SET_IPV6_PREFER_GLOBAL(A)                                           \
	(strmatch(A, "frr-bgp-route-map:ipv6-prefer-global"))
#define IS_SET_IPV4_VPN_NH(A)                                                  \
	(strmatch(A, "frr-bgp-route-map:ipv4-vpn-address"))
#define IS_SET_BGP_IPV4_NH(A)                                                  \
	(strmatch(A, "frr-bgp-route-map:set-ipv4-nexthop"))
#define IS_SET_BGP_EVPN_GATEWAY_IP_IPV4(A)                                     \
	(strmatch(A, "frr-bgp-route-map:set-evpn-gateway-ip-ipv4"))
#define IS_SET_BGP_EVPN_GATEWAY_IP_IPV6(A)                                     \
	(strmatch(A, "frr-bgp-route-map:set-evpn-gateway-ip-ipv6"))
#define IS_SET_BGP_L3VPN_NEXTHOP_ENCAPSULATION(A)                              \
	(strmatch(A, "frr-bgp-route-map:set-l3vpn-nexthop-encapsulation"))

enum ecommunity_lb_type {
	EXPLICIT_BANDWIDTH,
	CUMULATIVE_BANDWIDTH,
	COMPUTED_BANDWIDTH
};

/* Prototypes. */
extern void route_map_init(void);
extern void route_map_init_new(bool in_backend);

/*
 * This should only be called on shutdown
 * Additionally this function sets the hooks to NULL
 * before any processing is done.
 */
extern void route_map_finish(void);

/* Add match statement to route map. */
extern enum rmap_compile_rets route_map_add_match(struct route_map_index *index,
						  const char *match_name,
						  const char *match_arg,
						  route_map_event_t type);

/* Delete specified route match rule. */
extern enum rmap_compile_rets
route_map_delete_match(struct route_map_index *index,
		       const char *match_name, const char *match_arg,
		       route_map_event_t type);

extern const char *route_map_get_match_arg(struct route_map_index *index,
					   const char *match_name);

/* Add route-map set statement to the route map. */
extern enum rmap_compile_rets route_map_add_set(struct route_map_index *index,
						const char *set_name,
						const char *set_arg);

/* Delete route map set rule. */
extern enum rmap_compile_rets
route_map_delete_set(struct route_map_index *index,
		     const char *set_name, const char *set_arg);

/* struct route_map_rule_cmd is kept const in order to not have writable
 * function pointers (which is a security benefit.)  Hence, below struct is
 * used as proxy for hashing these for by-name lookup.
 */

PREDECL_HASH(rmap_cmd_name);

struct route_map_rule_cmd_proxy {
	struct rmap_cmd_name_item itm;
	const struct route_map_rule_cmd *cmd;
};

/* ... and just automatically create a proxy struct for each call location
 * to route_map_install_{match,set} to avoid unnecessarily added boilerplate
 * for each route-map user
 */

#define route_map_install_match(c)                                             \
	do {                                                                   \
		static struct route_map_rule_cmd_proxy proxy = {.cmd = c};     \
		_route_map_install_match(&proxy);                              \
	} while (0)

#define route_map_install_set(c)                                               \
	do {                                                                   \
		static struct route_map_rule_cmd_proxy proxy = {.cmd = c};     \
		_route_map_install_set(&proxy);                                \
	} while (0)

/* Install rule command to the match list. */
extern void _route_map_install_match(struct route_map_rule_cmd_proxy *proxy);

/*
 * Install rule command to the set list.
 *
 * When installing a particular item, Allow a difference of handling
 * of bad cli inputted(return NULL) -vs- this particular daemon cannot use
 * this form of the command(return a pointer and handle it appropriately
 * in the apply command).  See 'set metric' command
 * as it is handled in ripd/ripngd and ospfd.
 */
extern void _route_map_install_set(struct route_map_rule_cmd_proxy *proxy);

/* Lookup route map by name. */
extern struct route_map *route_map_lookup_by_name(const char *name);

/* Simple helper to warn if route-map does not exist. */
struct route_map *route_map_lookup_warn_noexist(struct vty *vty, const char *name);

/* Apply route map to the object. */
extern route_map_result_t route_map_apply_ext(struct route_map *map,
					      const struct prefix *prefix,
					      void *match_object,
					      void *set_object, int *pref);
#define route_map_apply(map, prefix, object)                                   \
	route_map_apply_ext(map, prefix, object, object, NULL)

extern void route_map_add_hook(void (*func)(const char *));
extern void route_map_delete_hook(void (*func)(const char *));

/*
 * This is the callback for when something has changed about a
 * route-map.  The interested parties can register to receive
 * this data.
 *
 * name - Is the name of the changed route-map
 */
extern void route_map_event_hook(void (*func)(const char *name));
extern int route_map_mark_updated(const char *name);
extern void route_map_walk_update_list(void (*update_fn)(char *name));
extern void route_map_upd8_dependency(route_map_event_t type, const char *arg,
				      const char *rmap_name);
extern void route_map_notify_dependencies(const char *affected_name,
					  route_map_event_t event);
extern void
route_map_notify_pentry_dependencies(const char *affected_name,
				     struct prefix_list_entry *pentry,
				     route_map_event_t event);
extern int generic_match_add(struct route_map_index *index,
			     const char *command, const char *arg,
			     route_map_event_t type,
			     char *errmsg, size_t errmsg_len);
extern int generic_match_delete(struct route_map_index *index,
				const char *command, const char *arg,
				route_map_event_t type,
				char *errmsg, size_t errmsg_len);

extern int generic_set_add(struct route_map_index *index,
			   const char *command, const char *arg,
			   char *errmsg, size_t errmsg_len);
extern int generic_set_delete(struct route_map_index *index,
			      const char *command, const char *arg,
			      char *errmsg, size_t errmsg_len);


/* match interface */
extern void route_map_match_interface_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* no match interface */
extern void route_map_no_match_interface_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* match ip address */
extern void route_map_match_ip_address_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* no match ip address */
extern void route_map_no_match_ip_address_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* match ip address prefix list */
extern void route_map_match_ip_address_prefix_list_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* no match ip address prefix list */
extern void route_map_no_match_ip_address_prefix_list_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* match ip next hop */
extern void route_map_match_ip_next_hop_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* no match ip next hop */
extern void route_map_no_match_ip_next_hop_hook(int (*func)(
	struct route_map_index *index, const char *command, const char *arg,
	route_map_event_t type, char *errmsg, size_t errmsg_len));
/* match ipv6 next hop */
extern void route_map_match_ipv6_next_hop_hook(int (*func)(
	struct route_map_index *index, const char *command, const char *arg,
	route_map_event_t type, char *errmsg, size_t errmsg_len));
/* no match ipv6 next hop */
extern void route_map_no_match_ipv6_next_hop_hook(int (*func)(
	struct route_map_index *index, const char *command, const char *arg,
	route_map_event_t type, char *errmsg, size_t errmsg_len));
/* match ip next hop prefix list */
extern void route_map_match_ip_next_hop_prefix_list_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* no match ip next hop prefix list */
extern void route_map_no_match_ip_next_hop_prefix_list_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* match ip next hop type */
extern void route_map_match_ip_next_hop_type_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* no match ip next hop type */
extern void route_map_no_match_ip_next_hop_type_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* match ipv6 address */
extern void route_map_match_ipv6_address_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* no match ipv6 address */
extern void route_map_no_match_ipv6_address_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* match ipv6 address prefix list */
extern void route_map_match_ipv6_address_prefix_list_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* no match ipv6 address prefix list */
extern void route_map_no_match_ipv6_address_prefix_list_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* match ipv6 next-hop type */
extern void route_map_match_ipv6_next_hop_type_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* no match ipv6 next-hop type */
extern void route_map_no_match_ipv6_next_hop_type_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* match ipv6 next-hop prefix-list */
extern void route_map_match_ipv6_next_hop_prefix_list_hook(int (*func)(
	struct route_map_index *index, const char *command, const char *arg,
	route_map_event_t type, char *errmsg, size_t errmsg_len));
/* no match ipv6 next-hop prefix-list */
extern void route_map_no_match_ipv6_next_hop_prefix_list_hook(int (*func)(
	struct route_map_index *index, const char *command, const char *arg,
	route_map_event_t type, char *errmsg, size_t errmsg_len));
/* match metric */
extern void route_map_match_metric_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* no match metric */
extern void route_map_no_match_metric_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* match tag */
extern void route_map_match_tag_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* no match tag */
extern void route_map_no_match_tag_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len));
/* set sr-te color */
extern void route_map_set_srte_color_hook(
	int (*func)(struct route_map_index *index,
		    const char *command, const char *arg,
		    char *errmsg, size_t errmsg_len));
/* no set sr-te color */
extern void route_map_no_set_srte_color_hook(
	int (*func)(struct route_map_index *index,
		    const char *command, const char *arg,
		    char *errmsg, size_t errmsg_len));
/* set ip nexthop */
extern void route_map_set_ip_nexthop_hook(
	int (*func)(struct route_map_index *index,
		    const char *command, const char *arg,
		    char *errmsg, size_t errmsg_len));
/* no set ip nexthop */
extern void route_map_no_set_ip_nexthop_hook(
	int (*func)(struct route_map_index *index,
		    const char *command, const char *arg,
		    char *errmsg, size_t errmsg_len));
/* set ipv6 nexthop local */
extern void route_map_set_ipv6_nexthop_local_hook(
	int (*func)(struct route_map_index *index,
		    const char *command, const char *arg,
		    char *errmsg, size_t errmsg_len));
/* no set ipv6 nexthop local */
extern void route_map_no_set_ipv6_nexthop_local_hook(
	int (*func)(struct route_map_index *index,
		    const char *command, const char *arg,
		    char *errmsg, size_t errmsg_len));
/* set metric */
extern void route_map_set_metric_hook(int (*func)(struct route_map_index *index,
						  const char *command,
						  const char *arg,
						  char *errmsg,
						  size_t errmsg_len));
/* no set metric */
extern void route_map_no_set_metric_hook(
	int (*func)(struct route_map_index *index,
		    const char *command, const char *arg,
		    char *errmsg, size_t errmsg_len));
/* set metric */
extern void route_map_set_max_metric_hook(
	int (*func)(struct route_map_index *index, const char *command,
		    const char *arg, char *errmsg, size_t errmsg_len));
/* no set metric */
extern void route_map_no_set_max_metric_hook(
	int (*func)(struct route_map_index *index, const char *command,
		    const char *arg, char *errmsg, size_t errmsg_len));
/* set metric */
extern void route_map_set_min_metric_hook(
	int (*func)(struct route_map_index *index, const char *command,
		    const char *arg, char *errmsg, size_t errmsg_len));
/* no set metric */
extern void route_map_no_set_min_metric_hook(
	int (*func)(struct route_map_index *index, const char *command,
		    const char *arg, char *errmsg, size_t errmsg_len));
/* set tag */
extern void route_map_set_tag_hook(int (*func)(struct route_map_index *index,
					       const char *command,
					       const char *arg,
					       char *errmsg,
					       size_t errmsg_len));
/* no set tag */
extern void route_map_no_set_tag_hook(int (*func)(struct route_map_index *index,
						  const char *command,
						  const char *arg,
						  char *errmsg,
						  size_t errmsg_len));

extern void *route_map_rule_tag_compile(const char *arg);
extern void route_map_rule_tag_free(void *rule);

/* Increment the route-map used counter */
extern void route_map_counter_increment(struct route_map *map);

/* Decrement the route-map used counter */
extern void route_map_counter_decrement(struct route_map *map);

/* Route map hooks data structure. */
struct route_map_match_set_hooks {
	/* match interface */
	int (*match_interface)(struct route_map_index *index,
			       const char *command, const char *arg,
			       route_map_event_t type,
			       char *errmsg, size_t errmsg_len);

	/* no match interface */
	int (*no_match_interface)(struct route_map_index *index,
				  const char *command, const char *arg,
				  route_map_event_t type,
				  char *errmsg, size_t errmsg_len);

	/* match ip address */
	int (*match_ip_address)(struct route_map_index *index,
				const char *command, const char *arg,
				route_map_event_t type,
				char *errmsg, size_t errmsg_len);

	/* no match ip address */
	int (*no_match_ip_address)(struct route_map_index *index,
				   const char *command, const char *arg,
				   route_map_event_t type,
				   char *errmsg, size_t errmsg_len);

	/* match ip address prefix list */
	int (*match_ip_address_prefix_list)(struct route_map_index *index,
					    const char *command,
					    const char *arg,
					    route_map_event_t type,
					    char *errmsg, size_t errmsg_len);

	/* no match ip address prefix list */
	int (*no_match_ip_address_prefix_list)(struct route_map_index *index,
					       const char *command,
					       const char *arg,
					       route_map_event_t type,
					       char *errmsg, size_t errmsg_len);

	/* match ip next hop */
	int (*match_ip_next_hop)(struct route_map_index *index,
				 const char *command, const char *arg,
				 route_map_event_t type,
				 char *errmsg, size_t errmsg_len);

	/* no match ip next hop */
	int (*no_match_ip_next_hop)(struct route_map_index *index,
				    const char *command, const char *arg,
				    route_map_event_t type,
				    char *errmsg, size_t errmsg_len);

	/* match ipv6 next hop */
	int (*match_ipv6_next_hop)(struct route_map_index *index,
				   const char *command, const char *arg,
				   route_map_event_t type, char *errmsg,
				   size_t errmsg_len);

	/* no match ipv6 next hop */
	int (*no_match_ipv6_next_hop)(struct route_map_index *index,
				      const char *command, const char *arg,
				      route_map_event_t type, char *errmsg,
				      size_t errmsg_len);

	/* match ipv6 next hop prefix-list */
	int (*match_ipv6_next_hop_prefix_list)(struct route_map_index *index,
					       const char *command,
					       const char *arg,
					       route_map_event_t type,
					       char *errmsg, size_t errmsg_len);

	/* no match ipv6 next-hop prefix-list */
	int (*no_match_ipv6_next_hop_prefix_list)(struct route_map_index *index,
						  const char *command,
						  const char *arg,
						  route_map_event_t type,
						  char *errmsg,
						  size_t errmsg_len);

	/* match ip next hop prefix list */
	int (*match_ip_next_hop_prefix_list)(struct route_map_index *index,
					     const char *command,
					     const char *arg,
					     route_map_event_t type,
					     char *errmsg, size_t errmsg_len);

	/* no match ip next hop prefix list */
	int (*no_match_ip_next_hop_prefix_list)(struct route_map_index *index,
						const char *command,
						const char *arg,
						route_map_event_t type,
						char *errmsg,
						size_t errmsg_len);

	/* match ip next-hop type */
	int (*match_ip_next_hop_type)(struct route_map_index *index,
				      const char *command,
				      const char *arg,
				      route_map_event_t type,
				      char *errmsg,
				      size_t errmsg_len);

	/* no match ip next-hop type */
	int (*no_match_ip_next_hop_type)(struct route_map_index *index,
					 const char *command,
					 const char *arg,
					 route_map_event_t type,
					 char *errmsg,
					 size_t errmsg_len);

	/* match ipv6 address */
	int (*match_ipv6_address)(struct route_map_index *index,
				  const char *command, const char *arg,
				  route_map_event_t type,
				  char *errmsg, size_t errmsg_len);

	/* no match ipv6 address */
	int (*no_match_ipv6_address)(struct route_map_index *index,
				     const char *command, const char *arg,
				     route_map_event_t type,
				     char *errmsg, size_t errmsg_len);


	/* match ipv6 address prefix list */
	int (*match_ipv6_address_prefix_list)(struct route_map_index *index,
					      const char *command,
					      const char *arg,
					      route_map_event_t type,
					      char *errmsg, size_t errmsg_len);

	/* no match ipv6 address prefix list */
	int (*no_match_ipv6_address_prefix_list)(struct route_map_index *index,
						 const char *command,
						 const char *arg,
						 route_map_event_t type,
						 char *errmsg,
						 size_t errmsg_len);

	/* match ipv6 next-hop type */
	int (*match_ipv6_next_hop_type)(struct route_map_index *index,
					      const char *command,
					      const char *arg,
					      route_map_event_t type,
					      char *errmsg, size_t errmsg_len);

	/* no match ipv6 next-hop type */
	int (*no_match_ipv6_next_hop_type)(struct route_map_index *index,
					   const char *command, const char *arg,
					   route_map_event_t type,
					   char *errmsg, size_t errmsg_len);

	/* match metric */
	int (*match_metric)(struct route_map_index *index,
			    const char *command, const char *arg,
			    route_map_event_t type,
			    char *errmsg, size_t errmsg_len);

	/* no match metric */
	int (*no_match_metric)(struct route_map_index *index,
			       const char *command, const char *arg,
			       route_map_event_t type,
			       char *errmsg, size_t errmsg_len);

	/* match tag */
	int (*match_tag)(struct route_map_index *index,
			 const char *command, const char *arg,
			 route_map_event_t type,
			 char *errmsg, size_t errmsg_len);

	/* no match tag */
	int (*no_match_tag)(struct route_map_index *index,
			    const char *command, const char *arg,
			    route_map_event_t type,
			    char *errmsg, size_t errmsg_len);

	/* set sr-te color */
	int (*set_srte_color)(struct route_map_index *index,
			      const char *command, const char *arg,
			      char *errmsg, size_t errmsg_len);

	/* no set sr-te color */
	int (*no_set_srte_color)(struct route_map_index *index,
				 const char *command, const char *arg,
				 char *errmsg, size_t errmsg_len);

	/* set ip nexthop */
	int (*set_ip_nexthop)(struct route_map_index *index,
			      const char *command, const char *arg,
			      char *errmsg, size_t errmsg_len);

	/* no set ip nexthop */
	int (*no_set_ip_nexthop)(struct route_map_index *index,
				 const char *command, const char *arg,
				 char *errmsg, size_t errmsg_len);

	/* set ipv6 nexthop local */
	int (*set_ipv6_nexthop_local)(struct route_map_index *index,
				      const char *command, const char *arg,
				      char *errmsg, size_t errmsg_len);

	/* no set ipv6 nexthop local */
	int (*no_set_ipv6_nexthop_local)(struct route_map_index *index,
					 const char *command, const char *arg,
					 char *errmsg, size_t errmsg_len);

	/* set metric */
	int (*set_metric)(struct route_map_index *index,
			  const char *command, const char *arg,
			  char *errmsg, size_t errmsg_len);

	/* no set metric */
	int (*no_set_metric)(struct route_map_index *index,
			     const char *command, const char *arg,
			     char *errmsg, size_t errmsg_len);
	/* set min-metric */
	int (*set_min_metric)(struct route_map_index *index,
			      const char *command, const char *arg,
			      char *errmsg, size_t errmsg_len);

	/* no set min-metric */
	int (*no_set_min_metric)(struct route_map_index *index,
				 const char *command, const char *arg,
				 char *errmsg, size_t errmsg_len);

	/* set max-metric */
	int (*set_max_metric)(struct route_map_index *index,
			      const char *command, const char *arg,
			      char *errmsg, size_t errmsg_len);

	/* no set max-metric */
	int (*no_set_max_metric)(struct route_map_index *index,
				 const char *command, const char *arg,
				 char *errmsg, size_t errmsg_len);

	/* set tag */
	int (*set_tag)(struct route_map_index *index,
		       const char *command, const char *arg,
		       char *errmsg, size_t errmsg_len);

	/* no set tag */
	int (*no_set_tag)(struct route_map_index *index,
			  const char *command, const char *arg,
			  char *errmsg, size_t errmsg_len);
};

extern struct route_map_match_set_hooks rmap_match_set_hook;

/* Making route map list. */
struct route_map_list {
	struct route_map *head;
	struct route_map *tail;

	void (*add_hook)(const char *);
	void (*delete_hook)(const char *);
	void (*event_hook)(const char *);
};

extern struct route_map_list route_map_master;

extern struct route_map *route_map_get(const char *name);
extern void route_map_delete(struct route_map *map);
extern struct route_map_index *route_map_index_get(struct route_map *map,
						   enum route_map_type type,
						   int pref);
extern void route_map_index_delete(struct route_map_index *index, int notify);

/* routemap_northbound.c */
typedef int (*routemap_match_hook_fun)(struct route_map_index *rmi,
				       const char *command, const char *arg,
				       route_map_event_t event,
				       char *errmsg, size_t errmsg_len);
typedef int (*routemap_set_hook_fun)(struct route_map_index *rmi,
				     const char *command, const char *arg,
				     char *errmsg, size_t errmsg_len);
struct routemap_hook_context {
	struct route_map_index *rhc_rmi;
	const char *rhc_rule;
	route_map_event_t rhc_event;
	routemap_set_hook_fun rhc_shook;
	routemap_match_hook_fun rhc_mhook;
	TAILQ_ENTRY(routemap_hook_context) rhc_entry;
};

int lib_route_map_entry_match_destroy(struct nb_cb_destroy_args *args);
int lib_route_map_entry_set_destroy(struct nb_cb_destroy_args *args);

struct routemap_hook_context *
routemap_hook_context_insert(struct route_map_index *rmi);
void routemap_hook_context_free(struct routemap_hook_context *rhc);

extern const struct frr_yang_module_info frr_route_map_info;
extern const struct frr_yang_module_info frr_route_map_cli_info;

/* routemap_cli.c */
extern int route_map_instance_cmp(const struct lyd_node *dnode1,
				  const struct lyd_node *dnode2);
extern void route_map_instance_show(struct vty *vty,
				    const struct lyd_node *dnode,
				    bool show_defaults);
extern void route_map_instance_show_end(struct vty *vty,
					const struct lyd_node *dnode);
extern void route_map_condition_show(struct vty *vty,
				     const struct lyd_node *dnode,
				     bool show_defaults);
extern void route_map_action_show(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);
extern void route_map_exit_policy_show(struct vty *vty,
				       const struct lyd_node *dnode,
				       bool show_defaults);
extern void route_map_call_show(struct vty *vty, const struct lyd_node *dnode,
				bool show_defaults);
extern void route_map_description_show(struct vty *vty,
				       const struct lyd_node *dnode,
				       bool show_defaults);
extern void route_map_optimization_disabled_show(struct vty *vty,
						 const struct lyd_node *dnode,
						 bool show_defaults);
extern void route_map_cli_init(void);

extern void route_map_show_debug(struct vty *vty);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_ROUTEMAP_H */
