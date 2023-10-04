// SPDX-License-Identifier: GPL-2.0-or-later
/* Route map function of bgpd.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "prefix.h"
#include "filter.h"
#include "routemap.h"
#include "command.h"
#include "linklist.h"
#include "plist.h"
#include "memory.h"
#include "log.h"
#include "frrlua.h"
#include "frrscript.h"
#ifdef HAVE_LIBPCRE2_POSIX
#ifndef _FRR_PCRE2_POSIX
#define _FRR_PCRE2_POSIX
#include <pcre2posix.h>
#endif /* _FRR_PCRE2_POSIX */
#elif defined(HAVE_LIBPCREPOSIX)
#include <pcreposix.h>
#else
#include <regex.h>
#endif /* HAVE_LIBPCRE2_POSIX */
#include "buffer.h"
#include "sockunion.h"
#include "hash.h"
#include "queue.h"
#include "frrstr.h"
#include "network.h"
#include "lib/northbound_cli.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_community_alias.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_vty.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_pbr.h"
#include "bgpd/bgp_flowspec_util.h"
#include "bgpd/bgp_encap_types.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_script.h"

#ifdef ENABLE_BGP_VNC
#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#endif

#include "bgpd/bgp_routemap_clippy.c"

/* Memo of route-map commands.

o Cisco route-map

 match as-path          :  Done
       community        :  Done
       interface        :  Done
       ip address       :  Done
       ip next-hop      :  Done
       ip route-source  :  Done
       ip prefix-list   :  Done
       ipv6 address     :  Done
       ipv6 next-hop    :  Done
       ipv6 route-source:  (This will not be implemented by bgpd)
       ipv6 prefix-list :  Done
       length           :  (This will not be implemented by bgpd)
       metric           :  Done
       route-type       :  (This will not be implemented by bgpd)
       tag              :  Done
       local-preference :  Done

 set  as-path prepend   :  Done
      as-path tag       :  Not yet
      automatic-tag     :  (This will not be implemented by bgpd)
      community         :  Done
      large-community   :  Done
      large-comm-list   :  Done
      comm-list         :  Not yet
      dampning          :  Not yet
      default           :  (This will not be implemented by bgpd)
      interface         :  (This will not be implemented by bgpd)
      ip default        :  (This will not be implemented by bgpd)
      ip next-hop       :  Done
      ip precedence     :  (This will not be implemented by bgpd)
      ip tos            :  (This will not be implemented by bgpd)
      level             :  (This will not be implemented by bgpd)
      local-preference  :  Done
      metric            :  Done
      metric-type       :  Not yet
      origin            :  Done
      tag               :  Done
      weight            :  Done
      table             :  Done

o Local extensions

  set ipv6 next-hop global: Done
  set ipv6 next-hop prefer-global: Done
  set ipv6 next-hop local : Done
  set as-path exclude     : Done

*/

/* generic value manipulation to be shared in multiple rules */

#define RMAP_VALUE_SET 0
#define RMAP_VALUE_ADD 1
#define RMAP_VALUE_SUB 2

struct rmap_value {
	uint8_t action;
	uint8_t variable;
	uint32_t value;
};

static int route_value_match(struct rmap_value *rv, uint32_t value)
{
	if (rv->variable == 0 && value == rv->value)
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

static uint32_t route_value_adjust(struct rmap_value *rv, uint32_t current,
				   struct peer *peer)
{
	uint32_t value;

	switch (rv->variable) {
	case 1:
		value = peer->rtt;
		break;
	default:
		value = rv->value;
		break;
	}

	switch (rv->action) {
	case RMAP_VALUE_ADD:
		if (current > UINT32_MAX - value)
			return UINT32_MAX;
		return current + value;
	case RMAP_VALUE_SUB:
		if (current <= value)
			return 0;
		return current - value;
	default:
		return value;
	}
}

static void *route_value_compile(const char *arg)
{
	uint8_t action = RMAP_VALUE_SET, var = 0;
	unsigned long larg = 0;
	char *endptr = NULL;
	struct rmap_value *rv;

	if (arg[0] == '+') {
		action = RMAP_VALUE_ADD;
		arg++;
	} else if (arg[0] == '-') {
		action = RMAP_VALUE_SUB;
		arg++;
	}

	if (all_digit(arg)) {
		errno = 0;
		larg = strtoul(arg, &endptr, 10);
		if (*arg == 0 || *endptr != 0 || errno || larg > UINT32_MAX)
			return NULL;
	} else {
		if (strcmp(arg, "rtt") == 0)
			var = 1;
		else
			return NULL;
	}

	rv = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct rmap_value));

	rv->action = action;
	rv->variable = var;
	rv->value = larg;
	return rv;
}

static void route_value_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* generic as path object to be shared in multiple rules */

static void *route_aspath_compile(const char *arg)
{
	struct aspath *aspath;

	aspath = aspath_str2aspath(arg, bgp_get_asnotation(NULL));
	if (!aspath)
		return NULL;
	return aspath;
}

static void route_aspath_free(void *rule)
{
	struct aspath *aspath = rule;
	aspath_free(aspath);
}

struct bgp_match_peer_compiled {
	char *interface;
	union sockunion su;
};

/* 'match peer (A.B.C.D|X:X::X:X|WORD)' */

/* Compares the peer specified in the 'match peer' clause with the peer
    received in bgp_path_info->peer. If it is the same, or if the peer structure
    received is a peer_group containing it, returns RMAP_MATCH. */
static enum route_map_cmd_result_t
route_match_peer(void *rule, const struct prefix *prefix, void *object)
{
	struct bgp_match_peer_compiled *pc;
	union sockunion *su;
	union sockunion su_def = {
		.sin = {.sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY}};
	struct peer_group *group;
	struct peer *peer;
	struct listnode *node, *nnode;

	pc = rule;
	su = &pc->su;
	peer = ((struct bgp_path_info *)object)->peer;

	if (pc->interface) {
		if (!peer->conf_if || !peer->group)
			return RMAP_NOMATCH;

		if (peer->conf_if && strcmp(peer->conf_if, pc->interface) == 0)
			return RMAP_MATCH;

		if (peer->group &&
		    strcmp(peer->group->name, pc->interface) == 0)
			return RMAP_MATCH;

		return RMAP_NOMATCH;
	}

	/* If su='0.0.0.0' (command 'match peer local'), and it's a
	   NETWORK,
	   REDISTRIBUTE, AGGREGATE-ADDRESS or DEFAULT_GENERATED route
	   => return RMAP_MATCH
	*/
	if (sockunion_same(su, &su_def)) {
		int ret;
		if (CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_NETWORK)
		    || CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_REDISTRIBUTE)
		    || CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_AGGREGATE)
		    || CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_DEFAULT))
			ret = RMAP_MATCH;
		else
			ret = RMAP_NOMATCH;
		return ret;
	}

	if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		if (sockunion_same(su, &peer->connection->su))
			return RMAP_MATCH;

		return RMAP_NOMATCH;
	} else {
		group = peer->group;
		for (ALL_LIST_ELEMENTS(group->peer, node, nnode, peer)) {
			if (sockunion_same(su, &peer->connection->su))
				return RMAP_MATCH;
		}
		return RMAP_NOMATCH;
	}

	return RMAP_NOMATCH;
}

static void *route_match_peer_compile(const char *arg)
{
	struct bgp_match_peer_compiled *pc;
	int ret;

	pc = XCALLOC(MTYPE_ROUTE_MAP_COMPILED,
		     sizeof(struct bgp_match_peer_compiled));

	ret = str2sockunion(strcmp(arg, "local") ? arg : "0.0.0.0", &pc->su);
	if (ret < 0) {
		pc->interface = XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
		return pc;
	}

	return pc;
}

/* Free route map's compiled `ip address' value. */
static void route_match_peer_free(void *rule)
{
	struct bgp_match_peer_compiled *pc = rule;

	XFREE(MTYPE_ROUTE_MAP_COMPILED, pc->interface);

	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip address matching. */
static const struct route_map_rule_cmd route_match_peer_cmd = {
	"peer",
	route_match_peer,
	route_match_peer_compile,
	route_match_peer_free
};

#ifdef HAVE_SCRIPTING

enum frrlua_rm_status {
	/*
	 * Script function run failure.  This will translate into a deny
	 */
	LUA_RM_FAILURE = 0,
	/*
	 * No Match was found for the route map function
	 */
	LUA_RM_NOMATCH,
	/*
	 * Match was found but no changes were made to the incoming data.
	 */
	LUA_RM_MATCH,
	/*
	 * Match was found and data was modified, so figure out what changed
	 */
	LUA_RM_MATCH_AND_CHANGE,
};

static enum route_map_cmd_result_t
route_match_script(void *rule, const struct prefix *prefix, void *object)
{
	const char *scriptname = rule;
	const char *routematch_function = "route_match";
	struct bgp_path_info *path = (struct bgp_path_info *)object;

	struct frrscript *fs = frrscript_new(scriptname);

	if (frrscript_load(fs, routematch_function, NULL)) {
		zlog_err(
			"Issue loading script or function; defaulting to no match");
		return RMAP_NOMATCH;
	}

	struct attr newattr = *path->attr;

	int result = frrscript_call(
		fs, routematch_function, ("prefix", prefix),
		("attributes", &newattr), ("peer", path->peer),
		("RM_FAILURE", LUA_RM_FAILURE), ("RM_NOMATCH", LUA_RM_NOMATCH),
		("RM_MATCH", LUA_RM_MATCH),
		("RM_MATCH_AND_CHANGE", LUA_RM_MATCH_AND_CHANGE));

	if (result) {
		zlog_err("Issue running script rule; defaulting to no match");
		return RMAP_NOMATCH;
	}

	long long *action = frrscript_get_result(fs, routematch_function,
						 "action", lua_tointegerp);

	int status = RMAP_NOMATCH;

	switch (*action) {
	case LUA_RM_FAILURE:
		zlog_err(
			"Executing route-map match script '%s' failed; defaulting to no match",
			scriptname);
		status = RMAP_NOMATCH;
		break;
	case LUA_RM_NOMATCH:
		status = RMAP_NOMATCH;
		break;
	case LUA_RM_MATCH_AND_CHANGE:
		status = RMAP_MATCH;
		zlog_debug("Updating attribute based on script's values");

		uint32_t locpref = 0;

		path->attr->med = newattr.med;

		if (path->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
			locpref = path->attr->local_pref;
		if (locpref != newattr.local_pref) {
			SET_FLAG(path->attr->flag,
				 ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF));
			path->attr->local_pref = newattr.local_pref;
		}
		break;
	case LUA_RM_MATCH:
		status = RMAP_MATCH;
		break;
	}

	XFREE(MTYPE_SCRIPT_RES, action);

	frrscript_delete(fs);

	return status;
}

static void *route_match_script_compile(const char *arg)
{
	char *scriptname;

	scriptname = XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);

	return scriptname;
}

static void route_match_script_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd route_match_script_cmd = {
	"script",
	route_match_script,
	route_match_script_compile,
	route_match_script_free
};

#endif /* HAVE_SCRIPTING */

/* `match ip address IP_ACCESS_LIST' */

/* Match function should return 1 if match is success else return
   zero. */
static enum route_map_cmd_result_t
route_match_ip_address(void *rule, const struct prefix *prefix, void *object)
{
	struct access_list *alist;

	if (prefix->family == AF_INET) {
		alist = access_list_lookup(AFI_IP, (char *)rule);
		if (alist == NULL) {
			if (unlikely(CHECK_FLAG(rmap_debug,
						DEBUG_ROUTEMAP_DETAIL)))
				zlog_debug(
					"%s: Access-List Specified: %s does not exist defaulting to NO_MATCH",
					__func__, (char *)rule);
			return RMAP_NOMATCH;
		}

		return (access_list_apply(alist, prefix) == FILTER_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
}

/* Route map `ip address' match statement.  `arg' should be
   access-list name. */
static void *route_match_ip_address_compile(const char *arg)
{
	struct access_list *alist;

	alist = access_list_lookup(AFI_IP, arg);
	if (!alist)
		zlog_warn(
			"Access List specified %s does not exist yet, default will be NO_MATCH until it is created",
			arg);
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `ip address' value. */
static void route_match_ip_address_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip address matching. */
static const struct route_map_rule_cmd route_match_ip_address_cmd = {
	"ip address",
	route_match_ip_address,
	route_match_ip_address_compile,
	route_match_ip_address_free
};

/* `match ip next-hop <IP_ADDRESS_ACCESS_LIST_NAME>' */

/* Match function return 1 if match is success else return zero. */
static enum route_map_cmd_result_t
route_match_ip_next_hop(void *rule, const struct prefix *prefix, void *object)
{
	struct access_list *alist;
	struct bgp_path_info *path;
	struct prefix_ipv4 p;

	if (prefix->family == AF_INET) {
		path = object;
		p.family = AF_INET;
		p.prefix = path->attr->nexthop;
		p.prefixlen = IPV4_MAX_BITLEN;

		alist = access_list_lookup(AFI_IP, (char *)rule);
		if (alist == NULL) {
			if (unlikely(CHECK_FLAG(rmap_debug,
						DEBUG_ROUTEMAP_DETAIL)))
				zlog_debug(
					"%s: Access-List Specified: %s does not exist defaulting to NO_MATCH",
					__func__, (char *)rule);

			return RMAP_NOMATCH;
		}

		return (access_list_apply(alist, &p) == FILTER_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
}

/* Route map `ip next-hop' match statement. `arg' is
   access-list name. */
static void *route_match_ip_next_hop_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `ip address' value. */
static void route_match_ip_next_hop_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip next-hop matching. */
static const struct route_map_rule_cmd route_match_ip_next_hop_cmd = {
	"ip next-hop",
	route_match_ip_next_hop,
	route_match_ip_next_hop_compile,
	route_match_ip_next_hop_free
};

/* `match ip route-source ACCESS-LIST' */

/* Match function return 1 if match is success else return zero. */
static enum route_map_cmd_result_t
route_match_ip_route_source(void *rule, const struct prefix *pfx, void *object)
{
	struct access_list *alist;
	struct bgp_path_info *path;
	struct peer *peer;
	struct prefix_ipv4 p;

	if (pfx->family == AF_INET) {
		path = object;
		peer = path->peer;

		if (!peer || sockunion_family(&peer->connection->su) != AF_INET)
			return RMAP_NOMATCH;

		p.family = AF_INET;
		p.prefix = peer->connection->su.sin.sin_addr;
		p.prefixlen = IPV4_MAX_BITLEN;

		alist = access_list_lookup(AFI_IP, (char *)rule);
		if (alist == NULL) {
			if (unlikely(CHECK_FLAG(rmap_debug,
						DEBUG_ROUTEMAP_DETAIL)))
				zlog_debug(
					"%s: Access-List Specified: %s does not exist defaulting to NO_MATCH",
					__func__, (char *)rule);

			return RMAP_NOMATCH;
		}

		return (access_list_apply(alist, &p) == FILTER_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
}

/* Route map `ip route-source' match statement. `arg' is
   access-list name. */
static void *route_match_ip_route_source_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `ip address' value. */
static void route_match_ip_route_source_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip route-source matching. */
static const struct route_map_rule_cmd route_match_ip_route_source_cmd = {
	"ip route-source",
	route_match_ip_route_source,
	route_match_ip_route_source_compile,
	route_match_ip_route_source_free
};

static enum route_map_cmd_result_t
route_match_prefix_list_flowspec(afi_t afi, struct prefix_list *plist,
				 const struct prefix *p)
{
	int ret;
	struct bgp_pbr_entry_main api;

	memset(&api, 0, sizeof(api));

	if (family2afi(p->u.prefix_flowspec.family) != afi)
		return RMAP_NOMATCH;

	/* extract match from flowspec entries */
	ret = bgp_flowspec_match_rules_fill(
					    (uint8_t *)p->u.prefix_flowspec.ptr,
					    p->u.prefix_flowspec.prefixlen, &api,
					    afi);
	if (ret < 0)
		return RMAP_NOMATCH;
	if (api.match_bitmask & PREFIX_DST_PRESENT ||
	    api.match_bitmask_iprule & PREFIX_DST_PRESENT) {
		if (family2afi((&api.dst_prefix)->family) != afi)
			return RMAP_NOMATCH;
		return prefix_list_apply(plist, &api.dst_prefix) == PREFIX_DENY
			? RMAP_NOMATCH
			: RMAP_MATCH;
	} else if (api.match_bitmask & PREFIX_SRC_PRESENT ||
		   api.match_bitmask_iprule & PREFIX_SRC_PRESENT) {
		if (family2afi((&api.src_prefix)->family) != afi)
			return RMAP_NOMATCH;
		return (prefix_list_apply(plist, &api.src_prefix) == PREFIX_DENY
			? RMAP_NOMATCH
			: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
}

static enum route_map_cmd_result_t
route_match_prefix_list_evpn(afi_t afi, struct prefix_list *plist,
			     const struct prefix *p)
{
	/* Convert to match a general plist */
	struct prefix new;

	if (evpn_prefix2prefix(p, &new))
		return RMAP_NOMATCH;

	return (prefix_list_apply(plist, &new) == PREFIX_DENY ? RMAP_NOMATCH
							      : RMAP_MATCH);
}

static enum route_map_cmd_result_t
route_match_address_prefix_list(void *rule, afi_t afi,
				const struct prefix *prefix, void *object)
{
	struct prefix_list *plist;

	plist = prefix_list_lookup(afi, (char *)rule);
	if (plist == NULL) {
		if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP_DETAIL)))
			zlog_debug(
				"%s: Prefix List %s specified does not exist defaulting to NO_MATCH",
				__func__, (char *)rule);
		return RMAP_NOMATCH;
	}

	if (prefix->family == AF_FLOWSPEC)
		return route_match_prefix_list_flowspec(afi, plist,
							prefix);

	else if (prefix->family == AF_EVPN)
		return route_match_prefix_list_evpn(afi, plist, prefix);

	return (prefix_list_apply(plist, prefix) == PREFIX_DENY ? RMAP_NOMATCH
								: RMAP_MATCH);
}

static enum route_map_cmd_result_t
route_match_ip_address_prefix_list(void *rule, const struct prefix *prefix,
				   void *object)
{
	return route_match_address_prefix_list(rule, AFI_IP, prefix, object);
}

static void *route_match_ip_address_prefix_list_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ip_address_prefix_list_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd
		route_match_ip_address_prefix_list_cmd = {
	"ip address prefix-list",
	route_match_ip_address_prefix_list,
	route_match_ip_address_prefix_list_compile,
	route_match_ip_address_prefix_list_free
};

/* `match ip next-hop prefix-list PREFIX_LIST' */

static enum route_map_cmd_result_t
route_match_ip_next_hop_prefix_list(void *rule, const struct prefix *prefix,
				    void *object)
{
	struct prefix_list *plist;
	struct bgp_path_info *path;
	struct prefix_ipv4 p;

	if (prefix->family == AF_INET) {
		path = object;
		p.family = AF_INET;
		p.prefix = path->attr->nexthop;
		p.prefixlen = IPV4_MAX_BITLEN;

		plist = prefix_list_lookup(AFI_IP, (char *)rule);
		if (plist == NULL) {
			if (unlikely(CHECK_FLAG(rmap_debug,
						DEBUG_ROUTEMAP_DETAIL)))
				zlog_debug(
					"%s: Prefix List %s specified does not exist defaulting to NO_MATCH",
					__func__, (char *)rule);
			return RMAP_NOMATCH;
		}

		return (prefix_list_apply(plist, &p) == PREFIX_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
}

static void *route_match_ip_next_hop_prefix_list_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ip_next_hop_prefix_list_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd
		route_match_ip_next_hop_prefix_list_cmd = {
	"ip next-hop prefix-list",
	route_match_ip_next_hop_prefix_list,
	route_match_ip_next_hop_prefix_list_compile,
	route_match_ip_next_hop_prefix_list_free
};

/* `match ipv6 next-hop prefix-list PREFIXLIST_NAME' */
static enum route_map_cmd_result_t
route_match_ipv6_next_hop_prefix_list(void *rule, const struct prefix *prefix,
				      void *object)
{
	struct prefix_list *plist;
	struct bgp_path_info *path;
	struct prefix_ipv6 p;

	if (prefix->family == AF_INET6) {
		path = object;
		p.family = AF_INET6;
		p.prefix = path->attr->mp_nexthop_global;
		p.prefixlen = IPV6_MAX_BITLEN;

		plist = prefix_list_lookup(AFI_IP6, (char *)rule);
		if (!plist) {
			if (unlikely(CHECK_FLAG(rmap_debug,
						DEBUG_ROUTEMAP_DETAIL)))
				zlog_debug(
					"%s: Prefix List %s specified does not exist defaulting to NO_MATCH",
					__func__, (char *)rule);
			return RMAP_NOMATCH;
		}

		if (prefix_list_apply(plist, &p) == PREFIX_PERMIT)
			return RMAP_MATCH;

		if (path->attr->mp_nexthop_len
		    == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL) {
			p.prefix = path->attr->mp_nexthop_local;
			if (prefix_list_apply(plist, &p) == PREFIX_PERMIT)
				return RMAP_MATCH;
		}
	}

	return RMAP_NOMATCH;
}

static void *route_match_ipv6_next_hop_prefix_list_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ipv6_next_hop_prefix_list_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd
		route_match_ipv6_next_hop_prefix_list_cmd = {
	"ipv6 next-hop prefix-list",
	route_match_ipv6_next_hop_prefix_list,
	route_match_ipv6_next_hop_prefix_list_compile,
	route_match_ipv6_next_hop_prefix_list_free
};

/* `match ip next-hop type <blackhole>' */

static enum route_map_cmd_result_t
route_match_ip_next_hop_type(void *rule, const struct prefix *prefix,
			     void *object)
{
	struct bgp_path_info *path;

	if (prefix->family == AF_INET) {
		path = (struct bgp_path_info *)object;
		if (!path)
			return RMAP_NOMATCH;

		/* If nexthop interface's index can't be resolved and nexthop is
		   set to any address then mark it as type `blackhole`.
		   This logic works for matching kernel/static routes like:
		   `ip route add blackhole 10.0.0.1`. */
		if (path->attr->nexthop.s_addr == INADDR_ANY
		    && !path->attr->nh_ifindex)
			return RMAP_MATCH;
	}
	return RMAP_NOMATCH;
}

static void *route_match_ip_next_hop_type_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ip_next_hop_type_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd
		route_match_ip_next_hop_type_cmd = {
	"ip next-hop type",
	route_match_ip_next_hop_type,
	route_match_ip_next_hop_type_compile,
	route_match_ip_next_hop_type_free
};

/* `match source-protocol` */
static enum route_map_cmd_result_t
route_match_source_protocol(void *rule, const struct prefix *prefix,
			    void *object)
{
	struct bgp_path_info *path = object;
	int *protocol = rule;

	if (!path)
		return RMAP_NOMATCH;

	if (path->type == *protocol)
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

static void *route_match_source_protocol_compile(const char *arg)
{
	int *protocol;

	protocol = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(*protocol));
	*protocol = proto_name2num(arg);

	return protocol;
}

static void route_match_source_protocol_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd route_match_source_protocol_cmd = {
	"source-protocol",
	route_match_source_protocol,
	route_match_source_protocol_compile,
	route_match_source_protocol_free
};


/* `match ip route-source prefix-list PREFIX_LIST' */

static enum route_map_cmd_result_t
route_match_ip_route_source_prefix_list(void *rule, const struct prefix *prefix,
					void *object)
{
	struct prefix_list *plist;
	struct bgp_path_info *path;
	struct peer *peer;
	struct prefix_ipv4 p;

	if (prefix->family == AF_INET) {
		path = object;
		peer = path->peer;

		if (!peer || sockunion_family(&peer->connection->su) != AF_INET)
			return RMAP_NOMATCH;

		p.family = AF_INET;
		p.prefix = peer->connection->su.sin.sin_addr;
		p.prefixlen = IPV4_MAX_BITLEN;

		plist = prefix_list_lookup(AFI_IP, (char *)rule);
		if (plist == NULL) {
			if (unlikely(CHECK_FLAG(rmap_debug,
						DEBUG_ROUTEMAP_DETAIL)))
				zlog_debug(
					"%s: Prefix List %s specified does not exist defaulting to NO_MATCH",
					__func__, (char *)rule);
			return RMAP_NOMATCH;
		}

		return (prefix_list_apply(plist, &p) == PREFIX_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
}

static void *route_match_ip_route_source_prefix_list_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ip_route_source_prefix_list_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd
		route_match_ip_route_source_prefix_list_cmd = {
	"ip route-source prefix-list",
	route_match_ip_route_source_prefix_list,
	route_match_ip_route_source_prefix_list_compile,
	route_match_ip_route_source_prefix_list_free
};

/* `match evpn default-route' */

/* Match function should return 1 if match is success else 0 */
static enum route_map_cmd_result_t
route_match_evpn_default_route(void *rule, const struct prefix *p, void *object)
{
	if (is_evpn_prefix_default(p))
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

/* Route map commands for default-route matching. */
static const struct route_map_rule_cmd
		route_match_evpn_default_route_cmd = {
	"evpn default-route",
	route_match_evpn_default_route,
	NULL,
	NULL
};

/* `match mac address MAC_ACCESS_LIST' */

/* Match function should return 1 if match is success else return
   zero. */
static enum route_map_cmd_result_t
route_match_mac_address(void *rule, const struct prefix *prefix, void *object)
{
	struct access_list *alist;
	struct prefix p;

	alist = access_list_lookup(AFI_L2VPN, (char *)rule);
	if (alist == NULL) {
		if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP_DETAIL)))
			zlog_debug(
				"%s: Access-List Specified: %s does not exist defaulting to NO_MATCH",
				__func__, (char *)rule);

		return RMAP_NOMATCH;
	}
	if (prefix->u.prefix_evpn.route_type != BGP_EVPN_MAC_IP_ROUTE) {
		if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP_DETAIL)))
			zlog_debug(
				"%s: Prefix %pFX is not a EVPN MAC IP ROUTE defaulting to NO_MATCH",
				__func__, prefix);
		return RMAP_NOMATCH;
	}

	p.family = AF_ETHERNET;
	p.prefixlen = ETH_ALEN * 8;
	p.u.prefix_eth = prefix->u.prefix_evpn.macip_addr.mac;

	return (access_list_apply(alist, &p) == FILTER_DENY ? RMAP_NOMATCH
							    : RMAP_MATCH);
}

/* Route map `mac address' match statement.  `arg' should be
   access-list name. */
static void *route_match_mac_address_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `ip address' value. */
static void route_match_mac_address_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for mac address matching. */
static const struct route_map_rule_cmd route_match_mac_address_cmd = {
	"mac address",
	route_match_mac_address,
	route_match_mac_address_compile,
	route_match_mac_address_free
};

/*
 * Match function returns:
 * ...RMAP_MATCH if match is found.
 * ...RMAP_NOMATCH if match is not found.
 * ...RMAP_NOOP to ignore this match check.
 */
static enum route_map_cmd_result_t
route_match_vni(void *rule, const struct prefix *prefix, void *object)
{
	vni_t vni = 0;
	unsigned int label_cnt = 0;
	struct bgp_path_info *path = NULL;
	struct prefix_evpn *evp = (struct prefix_evpn *) prefix;

	vni = *((vni_t *)rule);
	path = (struct bgp_path_info *)object;

	/*
	 * This rmap filter is valid for vxlan tunnel type only.
	 * For any other tunnel type, return noop to ignore
	 * this check.
	 */
	if (path->attr->encap_tunneltype != BGP_ENCAP_TYPE_VXLAN)
		return RMAP_NOOP;

	/*
	 * Apply filter to type 1, 2, 5 routes only.
	 * Other route types do not have vni label.
	 */
	if (evp
	    && (evp->prefix.route_type != BGP_EVPN_AD_ROUTE
		&& evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE
		&& evp->prefix.route_type != BGP_EVPN_IP_PREFIX_ROUTE))
		return RMAP_NOOP;

	if (path->extra == NULL)
		return RMAP_NOMATCH;

	for (;
	     label_cnt < BGP_MAX_LABELS && label_cnt < path->extra->num_labels;
	     label_cnt++) {
		if (vni == label2vni(&path->extra->label[label_cnt]))
			return RMAP_MATCH;
	}

	return RMAP_NOMATCH;
}

/* Route map `vni' match statement. */
static void *route_match_vni_compile(const char *arg)
{
	vni_t *vni = NULL;
	char *end = NULL;

	vni = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(vni_t));

	*vni = strtoul(arg, &end, 10);
	if (*end != '\0') {
		XFREE(MTYPE_ROUTE_MAP_COMPILED, vni);
		return NULL;
	}

	return vni;
}

/* Free route map's compiled `vni' value. */
static void route_match_vni_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for vni matching. */
static const struct route_map_rule_cmd route_match_evpn_vni_cmd = {
	"evpn vni",
	route_match_vni,
	route_match_vni_compile,
	route_match_vni_free
};

/* `match evpn route-type' */

/* Match function should return 1 if match is success else return
   zero. */
static enum route_map_cmd_result_t
route_match_evpn_route_type(void *rule, const struct prefix *pfx, void *object)
{
	uint8_t route_type = 0;

	route_type = *((uint8_t *)rule);

	if (route_type == pfx->u.prefix_evpn.route_type)
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

/* Route map `route-type' match statement. */
static void *route_match_evpn_route_type_compile(const char *arg)
{
	uint8_t *route_type = NULL;

	route_type = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(uint8_t));

	if (strncmp(arg, "ea", 2) == 0)
		*route_type = BGP_EVPN_AD_ROUTE;
	else if (strncmp(arg, "ma", 2) == 0)
		*route_type = BGP_EVPN_MAC_IP_ROUTE;
	else if (strncmp(arg, "mu", 2) == 0)
		*route_type = BGP_EVPN_IMET_ROUTE;
	else if (strncmp(arg, "es", 2) == 0)
		*route_type = BGP_EVPN_ES_ROUTE;
	else
		*route_type = BGP_EVPN_IP_PREFIX_ROUTE;

	return route_type;
}

/* Free route map's compiled `route-type' value. */
static void route_match_evpn_route_type_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for evpn route-type  matching. */
static const struct route_map_rule_cmd route_match_evpn_route_type_cmd = {
	"evpn route-type",
	route_match_evpn_route_type,
	route_match_evpn_route_type_compile,
	route_match_evpn_route_type_free
};

/* `match rd' */

/* Match function should return 1 if match is success else return zero. */
static enum route_map_cmd_result_t
route_match_rd(void *rule, const struct prefix *prefix, void *object)
{
	struct prefix_rd *prd_rule = NULL;
	const struct prefix_rd *prd_route = NULL;
	struct bgp_path_info *path = NULL;

	if (prefix->family != AF_EVPN)
		return RMAP_NOMATCH;

	prd_rule = (struct prefix_rd *)rule;
	path = (struct bgp_path_info *)object;

	if (path->net == NULL || path->net->pdest == NULL)
		return RMAP_NOMATCH;

	prd_route = (struct prefix_rd *)bgp_dest_get_prefix(path->net->pdest);
	if (memcmp(prd_route->val, prd_rule->val, ECOMMUNITY_SIZE) == 0)
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

/* Route map `rd' match statement. */
static void *route_match_rd_compile(const char *arg)
{
	struct prefix_rd *prd;
	int ret;

	prd = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct prefix_rd));

	ret = str2prefix_rd(arg, prd);
	if (!ret) {
		XFREE(MTYPE_ROUTE_MAP_COMPILED, prd);
		return NULL;
	}

	return prd;
}

/* Free route map's compiled `rd' value. */
static void route_match_rd_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for rd matching. */
static const struct route_map_rule_cmd route_match_evpn_rd_cmd = {
	"evpn rd",
	route_match_rd,
	route_match_rd_compile,
	route_match_rd_free
};

static enum route_map_cmd_result_t
route_set_evpn_gateway_ip(void *rule, const struct prefix *prefix, void *object)
{
	struct ipaddr *gw_ip = rule;
	struct bgp_path_info *path;
	struct prefix_evpn *evp;

	if (prefix->family != AF_EVPN)
		return RMAP_OKAY;

	evp = (struct prefix_evpn *)prefix;
	if (evp->prefix.route_type != BGP_EVPN_IP_PREFIX_ROUTE)
		return RMAP_OKAY;

	if ((is_evpn_prefix_ipaddr_v4(evp) && IPADDRSZ(gw_ip) != 4)
	    || (is_evpn_prefix_ipaddr_v6(evp) && IPADDRSZ(gw_ip) != 16))
		return RMAP_OKAY;

	path = object;

	/* Set gateway-ip value. */
	path->attr->evpn_overlay.type = OVERLAY_INDEX_GATEWAY_IP;
	memcpy(&path->attr->evpn_overlay.gw_ip, &gw_ip->ip.addr,
	       IPADDRSZ(gw_ip));

	return RMAP_OKAY;
}

/*
 * Route map `evpn gateway-ip' compile function.
 * Given string is converted to struct ipaddr structure
 */
static void *route_set_evpn_gateway_ip_compile(const char *arg)
{
	struct ipaddr *gw_ip = NULL;
	int ret;

	gw_ip = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct ipaddr));

	ret = str2ipaddr(arg, gw_ip);
	if (ret < 0) {
		XFREE(MTYPE_ROUTE_MAP_COMPILED, gw_ip);
		return NULL;
	}
	return gw_ip;
}

/* Free route map's compiled `evpn gateway_ip' value. */
static void route_set_evpn_gateway_ip_free(void *rule)
{
	struct ipaddr *gw_ip = rule;

	XFREE(MTYPE_ROUTE_MAP_COMPILED, gw_ip);
}

/* Route map commands for set evpn gateway-ip ipv4. */
struct route_map_rule_cmd route_set_evpn_gateway_ip_ipv4_cmd = {
	"evpn gateway-ip ipv4", route_set_evpn_gateway_ip,
	route_set_evpn_gateway_ip_compile, route_set_evpn_gateway_ip_free};

/* Route map commands for set evpn gateway-ip ipv6. */
struct route_map_rule_cmd route_set_evpn_gateway_ip_ipv6_cmd = {
	"evpn gateway-ip ipv6", route_set_evpn_gateway_ip,
	route_set_evpn_gateway_ip_compile, route_set_evpn_gateway_ip_free};

/* Route map commands for VRF route leak with source vrf matching */
static enum route_map_cmd_result_t
route_match_vrl_source_vrf(void *rule, const struct prefix *prefix,
			   void *object)
{
	struct bgp_path_info *path;
	char *vrf_name;

	vrf_name = rule;
	path = (struct bgp_path_info *)object;

	if (strncmp(vrf_name, "n/a", VRF_NAMSIZ) == 0)
		return RMAP_NOMATCH;

	if (path->extra == NULL || path->extra->vrfleak == NULL ||
	    path->extra->vrfleak->bgp_orig == NULL)
		return RMAP_NOMATCH;

	if (strncmp(vrf_name,
		    vrf_id_to_name(path->extra->vrfleak->bgp_orig->vrf_id),
		    VRF_NAMSIZ) == 0)
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

static void *route_match_vrl_source_vrf_compile(const char *arg)
{
	uint8_t *vrf_name = NULL;

	vrf_name = XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);

	return vrf_name;
}

/* Free route map's compiled `route-type' value. */
static void route_match_vrl_source_vrf_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd route_match_vrl_source_vrf_cmd = {
	"source-vrf",
	route_match_vrl_source_vrf,
	route_match_vrl_source_vrf_compile,
	route_match_vrl_source_vrf_free
};

/* `match alias` */
static enum route_map_cmd_result_t
route_match_alias(void *rule, const struct prefix *prefix, void *object)
{
	char *alias = rule;
	struct bgp_path_info *path = object;
	char **communities;
	int num;
	bool found;

	if (bgp_attr_get_community(path->attr)) {
		found = false;
		frrstr_split(bgp_attr_get_community(path->attr)->str, " ",
			     &communities, &num);
		for (int i = 0; i < num; i++) {
			const char *com2alias =
				bgp_community2alias(communities[i]);
			if (!found && strcmp(alias, com2alias) == 0)
				found = true;
			XFREE(MTYPE_TMP, communities[i]);
		}
		XFREE(MTYPE_TMP, communities);
		if (found)
			return RMAP_MATCH;
	}

	if (bgp_attr_get_lcommunity(path->attr)) {
		found = false;
		frrstr_split(bgp_attr_get_lcommunity(path->attr)->str, " ",
			     &communities, &num);
		for (int i = 0; i < num; i++) {
			const char *com2alias =
				bgp_community2alias(communities[i]);
			if (!found && strcmp(alias, com2alias) == 0)
				found = true;
			XFREE(MTYPE_TMP, communities[i]);
		}
		XFREE(MTYPE_TMP, communities);
		if (found)
			return RMAP_MATCH;
	}

	return RMAP_NOMATCH;
}

static void *route_match_alias_compile(const char *arg)
{

	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_alias_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd route_match_alias_cmd = {
	"alias", route_match_alias, route_match_alias_compile,
	route_match_alias_free};

/* `match local-preference LOCAL-PREF' */

/* Match function return 1 if match is success else return zero. */
static enum route_map_cmd_result_t
route_match_local_pref(void *rule, const struct prefix *prefix, void *object)
{
	uint32_t *local_pref;
	struct bgp_path_info *path;

	local_pref = rule;
	path = object;

	if (path->attr->local_pref == *local_pref)
		return RMAP_MATCH;
	else
		return RMAP_NOMATCH;
}

/*
 * Route map `match local-preference' match statement.
 * `arg' is local-pref value
 */
static void *route_match_local_pref_compile(const char *arg)
{
	uint32_t *local_pref;
	char *endptr = NULL;
	unsigned long tmpval;

	errno = 0;
	tmpval = strtoul(arg, &endptr, 10);
	if (*endptr != '\0' || errno || tmpval > UINT32_MAX)
		return NULL;

	local_pref = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(uint32_t));

	*local_pref = tmpval;
	return local_pref;
}

/* Free route map's compiled `match local-preference' value. */
static void route_match_local_pref_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for metric matching. */
static const struct route_map_rule_cmd route_match_local_pref_cmd = {
	"local-preference",
	route_match_local_pref,
	route_match_local_pref_compile,
	route_match_local_pref_free
};

/* `match metric METRIC' */

/* Match function return 1 if match is success else return zero. */
static enum route_map_cmd_result_t
route_match_metric(void *rule, const struct prefix *prefix, void *object)
{
	struct rmap_value *rv;
	struct bgp_path_info *path;

	rv = rule;
	path = object;
	return route_value_match(rv, path->attr->med);
}

/* Route map commands for metric matching. */
static const struct route_map_rule_cmd route_match_metric_cmd = {
	"metric",
	route_match_metric,
	route_value_compile,
	route_value_free,
};

/* `match as-path ASPATH' */

/* Match function for as-path match.  I assume given object is */
static enum route_map_cmd_result_t
route_match_aspath(void *rule, const struct prefix *prefix, void *object)
{

	struct as_list *as_list;
	struct bgp_path_info *path;

	as_list = as_list_lookup((char *)rule);
	if (as_list == NULL)
		return RMAP_NOMATCH;

	path = object;

	/* Perform match. */
	return ((as_list_apply(as_list, path->attr->aspath) == AS_FILTER_DENY)
			? RMAP_NOMATCH
			: RMAP_MATCH);
}

/* Compile function for as-path match. */
static void *route_match_aspath_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Compile function for as-path match. */
static void route_match_aspath_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for aspath matching. */
static const struct route_map_rule_cmd route_match_aspath_cmd = {
	"as-path",
	route_match_aspath,
	route_match_aspath_compile,
	route_match_aspath_free
};

/* `match community COMMUNIY' */
struct rmap_community {
	char *name;
	uint32_t name_hash;
	bool exact;
	bool any;
};

/* Match function for community match. */
static enum route_map_cmd_result_t
route_match_community(void *rule, const struct prefix *prefix, void *object)
{
	struct community_list *list;
	struct bgp_path_info *path;
	struct rmap_community *rcom = rule;

	path = object;
	rcom = rule;

	list = community_list_lookup(bgp_clist, rcom->name, rcom->name_hash,
				     COMMUNITY_LIST_MASTER);
	if (!list)
		return RMAP_NOMATCH;

	if (rcom->exact) {
		if (community_list_exact_match(
			    bgp_attr_get_community(path->attr), list))
			return RMAP_MATCH;
	} else if (rcom->any) {
		if (!bgp_attr_get_community(path->attr))
			return RMAP_OKAY;
		if (community_list_any_match(bgp_attr_get_community(path->attr),
					     list))
			return RMAP_MATCH;
	} else {
		if (community_list_match(bgp_attr_get_community(path->attr),
					 list))
			return RMAP_MATCH;
	}

	return RMAP_NOMATCH;
}

/* Compile function for community match. */
static void *route_match_community_compile(const char *arg)
{
	struct rmap_community *rcom;
	int len;
	char *p;

	rcom = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct rmap_community));

	p = strchr(arg, ' ');
	if (p) {
		len = p - arg;
		rcom->name = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, len + 1);
		memcpy(rcom->name, arg, len);
		p++;
		if (*p == 'e')
			rcom->exact = true;
		else
			rcom->any = true;
	} else {
		rcom->name = XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
		rcom->exact = false;
		rcom->any = false;
	}

	rcom->name_hash = bgp_clist_hash_key(rcom->name);
	return rcom;
}

/* Compile function for community match. */
static void route_match_community_free(void *rule)
{
	struct rmap_community *rcom = rule;

	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcom->name);
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcom);
}

/*
 * In routemap processing there is a need to add the
 * name as a rule_key in the dependency table. Routemap
 * lib is unaware of rule_key when exact-match clause
 * is in use. routemap lib uses the compiled output to
 * get the rule_key value.
 */
static void *route_match_get_community_key(void *rule)
{
	struct rmap_community *rcom;

	rcom = rule;
	return rcom->name;
}


/* Route map commands for community matching. */
static const struct route_map_rule_cmd route_match_community_cmd = {
	"community",
	route_match_community,
	route_match_community_compile,
	route_match_community_free,
	route_match_get_community_key
};

/* Match function for lcommunity match. */
static enum route_map_cmd_result_t
route_match_lcommunity(void *rule, const struct prefix *prefix, void *object)
{
	struct community_list *list;
	struct bgp_path_info *path;
	struct rmap_community *rcom = rule;

	path = object;

	list = community_list_lookup(bgp_clist, rcom->name, rcom->name_hash,
				     LARGE_COMMUNITY_LIST_MASTER);
	if (!list)
		return RMAP_NOMATCH;

	if (rcom->exact) {
		if (lcommunity_list_exact_match(
			    bgp_attr_get_lcommunity(path->attr), list))
			return RMAP_MATCH;
	} else if (rcom->any) {
		if (!bgp_attr_get_lcommunity(path->attr))
			return RMAP_OKAY;
		if (lcommunity_list_any_match(bgp_attr_get_lcommunity(path->attr),
					      list))
			return RMAP_MATCH;
	} else {
		if (lcommunity_list_match(bgp_attr_get_lcommunity(path->attr),
					  list))
			return RMAP_MATCH;
	}

	return RMAP_NOMATCH;
}

/* Compile function for community match. */
static void *route_match_lcommunity_compile(const char *arg)
{
	struct rmap_community *rcom;
	int len;
	char *p;

	rcom = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct rmap_community));

	p = strchr(arg, ' ');
	if (p) {
		len = p - arg;
		rcom->name = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, len + 1);
		memcpy(rcom->name, arg, len);
		p++;
		if (*p == 'e')
			rcom->exact = true;
		else
			rcom->any = true;
	} else {
		rcom->name = XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
		rcom->exact = false;
		rcom->any = false;
	}

	rcom->name_hash = bgp_clist_hash_key(rcom->name);
	return rcom;
}

/* Compile function for community match. */
static void route_match_lcommunity_free(void *rule)
{
	struct rmap_community *rcom = rule;

	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcom->name);
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcom);
}

/* Route map commands for community matching. */
static const struct route_map_rule_cmd route_match_lcommunity_cmd = {
	"large-community",
	route_match_lcommunity,
	route_match_lcommunity_compile,
	route_match_lcommunity_free,
	route_match_get_community_key
};


/* Match function for extcommunity match. */
static enum route_map_cmd_result_t
route_match_ecommunity(void *rule, const struct prefix *prefix, void *object)
{
	struct community_list *list;
	struct bgp_path_info *path;
	struct rmap_community *rcom = rule;

	path = object;

	list = community_list_lookup(bgp_clist, rcom->name, rcom->name_hash,
				     EXTCOMMUNITY_LIST_MASTER);
	if (!list)
		return RMAP_NOMATCH;

	if (ecommunity_list_match(bgp_attr_get_ecommunity(path->attr), list))
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

/* Compile function for extcommunity match. */
static void *route_match_ecommunity_compile(const char *arg)
{
	struct rmap_community *rcom;

	rcom = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct rmap_community));
	rcom->name = XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
	rcom->name_hash = bgp_clist_hash_key(rcom->name);

	return rcom;
}

/* Compile function for extcommunity match. */
static void route_match_ecommunity_free(void *rule)
{
	struct rmap_community *rcom = rule;

	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcom->name);
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcom);
}

/* Route map commands for community matching. */
static const struct route_map_rule_cmd route_match_ecommunity_cmd = {
	"extcommunity",
	route_match_ecommunity,
	route_match_ecommunity_compile,
	route_match_ecommunity_free
};

/* `match nlri` and `set nlri` are replaced by `address-family ipv4`
   and `address-family vpnv4'.  */

/* `match origin' */
static enum route_map_cmd_result_t
route_match_origin(void *rule, const struct prefix *prefix, void *object)
{
	uint8_t *origin;
	struct bgp_path_info *path;

	origin = rule;
	path = object;

	if (path->attr->origin == *origin)
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

static void *route_match_origin_compile(const char *arg)
{
	uint8_t *origin;

	origin = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(uint8_t));

	if (strcmp(arg, "igp") == 0)
		*origin = 0;
	else if (strcmp(arg, "egp") == 0)
		*origin = 1;
	else
		*origin = 2;

	return origin;
}

/* Free route map's compiled `ip address' value. */
static void route_match_origin_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for origin matching. */
static const struct route_map_rule_cmd route_match_origin_cmd = {
	"origin",
	route_match_origin,
	route_match_origin_compile,
	route_match_origin_free
};

/* match probability  { */

static enum route_map_cmd_result_t
route_match_probability(void *rule, const struct prefix *prefix, void *object)
{
	long r = frr_weak_random();

	switch (*(long *)rule) {
	case 0:
		break;
	case RAND_MAX:
		return RMAP_MATCH;
	default:
		if (r < *(long *)rule) {
			return RMAP_MATCH;
		}
	}

	return RMAP_NOMATCH;
}

static void *route_match_probability_compile(const char *arg)
{
	long *lobule;
	unsigned perc;

	perc = atoi(arg);
	lobule = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(long));

	switch (perc) {
	case 0:
		*lobule = 0;
		break;
	case 100:
		*lobule = RAND_MAX;
		break;
	default:
		*lobule = RAND_MAX / 100 * perc;
	}

	return lobule;
}

static void route_match_probability_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd route_match_probability_cmd = {
	"probability",
	route_match_probability,
	route_match_probability_compile,
	route_match_probability_free
};

/* `match interface IFNAME' */
/* Match function should return 1 if match is success else return
   zero. */
static enum route_map_cmd_result_t
route_match_interface(void *rule, const struct prefix *prefix, void *object)
{
	struct interface *ifp;
	struct bgp_path_info *path;

	path = object;

	if (!path || !path->peer || !path->peer->bgp)
		return RMAP_NOMATCH;

	ifp = if_lookup_by_name((char *)rule, path->peer->bgp->vrf_id);

	if (ifp == NULL || ifp->ifindex != path->attr->nh_ifindex)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

/* Route map `interface' match statement.  `arg' should be
   interface name. */
static void *route_match_interface_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `interface' value. */
static void route_match_interface_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip address matching. */
static const struct route_map_rule_cmd route_match_interface_cmd = {
	"interface",
	route_match_interface,
	route_match_interface_compile,
	route_match_interface_free
};

/* } */

/* `set ip next-hop IP_ADDRESS' */

/* Match function return 1 if match is success else return zero. */
static enum route_map_cmd_result_t
route_match_tag(void *rule, const struct prefix *prefix, void *object)
{
	route_tag_t *tag;
	struct bgp_path_info *path;

	tag = rule;
	path = object;

	return ((path->attr->tag == *tag) ? RMAP_MATCH : RMAP_NOMATCH);
}


/* Route map commands for tag matching. */
static const struct route_map_rule_cmd route_match_tag_cmd = {
	"tag",
	route_match_tag,
	route_map_rule_tag_compile,
	route_map_rule_tag_free,
};

static enum route_map_cmd_result_t
route_set_srte_color(void *rule, const struct prefix *prefix, void *object)
{
	uint32_t *srte_color = rule;
	struct bgp_path_info *path;

	path = object;

	path->attr->srte_color = *srte_color;
	path->attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_SRTE_COLOR);

	return RMAP_OKAY;
}

/* Route map `sr-te color' compile function */
static void *route_set_srte_color_compile(const char *arg)
{
	uint32_t *color;

	color = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(uint32_t));
	*color = atoi(arg);

	return color;
}

/* Free route map's compiled `sr-te color' value. */
static void route_set_srte_color_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for sr-te color set. */
struct route_map_rule_cmd route_set_srte_color_cmd = {
	"sr-te color", route_set_srte_color, route_set_srte_color_compile,
	route_set_srte_color_free};

/* Set nexthop to object.  object must be pointer to struct attr. */
struct rmap_ip_nexthop_set {
	struct in_addr *address;
	int peer_address;
	int unchanged;
};

static enum route_map_cmd_result_t
route_set_ip_nexthop(void *rule, const struct prefix *prefix, void *object)
{
	struct rmap_ip_nexthop_set *rins = rule;
	struct bgp_path_info *path;
	struct peer *peer;

	if (prefix->family == AF_INET6)
		return RMAP_OKAY;

	path = object;
	peer = path->peer;

	if (rins->unchanged) {
		SET_FLAG(path->attr->rmap_change_flags,
			 BATTR_RMAP_NEXTHOP_UNCHANGED);
	} else if (rins->peer_address) {
		if ((CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_IN)
		     || CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_IMPORT))
		    && peer->su_remote
		    && sockunion_family(peer->su_remote) == AF_INET) {
			path->attr->nexthop.s_addr =
				sockunion2ip(peer->su_remote);
			path->attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);
		} else if (CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_OUT)) {
			/* The next hop value will be set as part of
			 * packet rewrite.  Set the flags here to indicate
			 * that rewrite needs to be done.
			 * Also, clear the value.
			 */
			SET_FLAG(path->attr->rmap_change_flags,
				 BATTR_RMAP_NEXTHOP_PEER_ADDRESS);
			path->attr->nexthop.s_addr = INADDR_ANY;
		}
	} else {
		/* Set next hop value. */
		path->attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);
		path->attr->nexthop = *rins->address;
		SET_FLAG(path->attr->rmap_change_flags,
			 BATTR_RMAP_IPV4_NHOP_CHANGED);
		/* case for MP-BGP : MPLS VPN */
		path->attr->mp_nexthop_global_in = *rins->address;
		path->attr->mp_nexthop_len = sizeof(*rins->address);
	}

	return RMAP_OKAY;
}

/* Route map `ip nexthop' compile function.  Given string is converted
   to struct in_addr structure. */
static void *route_set_ip_nexthop_compile(const char *arg)
{
	struct rmap_ip_nexthop_set *rins;
	struct in_addr *address = NULL;
	int peer_address = 0;
	int unchanged = 0;
	int ret;

	if (strcmp(arg, "peer-address") == 0)
		peer_address = 1;
	else if (strcmp(arg, "unchanged") == 0)
		unchanged = 1;
	else {
		address = XMALLOC(MTYPE_ROUTE_MAP_COMPILED,
				  sizeof(struct in_addr));
		ret = inet_aton(arg, address);

		if (ret == 0) {
			XFREE(MTYPE_ROUTE_MAP_COMPILED, address);
			return NULL;
		}
	}

	rins = XCALLOC(MTYPE_ROUTE_MAP_COMPILED,
		       sizeof(struct rmap_ip_nexthop_set));

	rins->address = address;
	rins->peer_address = peer_address;
	rins->unchanged = unchanged;

	return rins;
}

/* Free route map's compiled `ip nexthop' value. */
static void route_set_ip_nexthop_free(void *rule)
{
	struct rmap_ip_nexthop_set *rins = rule;

	XFREE(MTYPE_ROUTE_MAP_COMPILED, rins->address);

	XFREE(MTYPE_ROUTE_MAP_COMPILED, rins);
}

/* Route map commands for ip nexthop set. */
static const struct route_map_rule_cmd route_set_ip_nexthop_cmd = {
	"ip next-hop",
	route_set_ip_nexthop,
	route_set_ip_nexthop_compile,
	route_set_ip_nexthop_free
};

/* `set l3vpn next-hop encapsulation l3vpn gre' */

/* Set nexthop to object */
struct rmap_l3vpn_nexthop_encapsulation_set {
	uint8_t protocol;
};

static enum route_map_cmd_result_t
route_set_l3vpn_nexthop_encapsulation(void *rule, const struct prefix *prefix,
				      void *object)
{
	struct rmap_l3vpn_nexthop_encapsulation_set *rins = rule;
	struct bgp_path_info *path;

	path = object;

	if (rins->protocol != IPPROTO_GRE)
		return RMAP_OKAY;

	SET_FLAG(path->attr->rmap_change_flags, BATTR_RMAP_L3VPN_ACCEPT_GRE);
	return RMAP_OKAY;
}

/* Route map `l3vpn nexthop encapsulation' compile function. */
static void *route_set_l3vpn_nexthop_encapsulation_compile(const char *arg)
{
	struct rmap_l3vpn_nexthop_encapsulation_set *rins;

	rins = XCALLOC(MTYPE_ROUTE_MAP_COMPILED,
		       sizeof(struct rmap_l3vpn_nexthop_encapsulation_set));

	/* XXX ALL GRE modes are accepted for now: gre or ip6gre */
	rins->protocol = IPPROTO_GRE;

	return rins;
}

/* Free route map's compiled `ip nexthop' value. */
static void route_set_l3vpn_nexthop_encapsulation_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for l3vpn next-hop encapsulation set. */
static const struct route_map_rule_cmd
	route_set_l3vpn_nexthop_encapsulation_cmd = {
		"l3vpn next-hop encapsulation",
		route_set_l3vpn_nexthop_encapsulation,
		route_set_l3vpn_nexthop_encapsulation_compile,
		route_set_l3vpn_nexthop_encapsulation_free};

/* `set local-preference LOCAL_PREF' */

/* Set local preference. */
static enum route_map_cmd_result_t
route_set_local_pref(void *rule, const struct prefix *prefix, void *object)
{
	struct rmap_value *rv;
	struct bgp_path_info *path;
	uint32_t locpref = 0;

	/* Fetch routemap's rule information. */
	rv = rule;
	path = object;

	/* Set local preference value. */
	if (path->attr->local_pref)
		locpref = path->attr->local_pref;

	path->attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF);
	path->attr->local_pref = route_value_adjust(rv, locpref, path->peer);

	return RMAP_OKAY;
}

/* Set local preference rule structure. */
static const struct route_map_rule_cmd route_set_local_pref_cmd = {
	"local-preference",
	route_set_local_pref,
	route_value_compile,
	route_value_free,
};

/* `set weight WEIGHT' */

/* Set weight. */
static enum route_map_cmd_result_t
route_set_weight(void *rule, const struct prefix *prefix, void *object)
{
	struct rmap_value *rv;
	struct bgp_path_info *path;

	/* Fetch routemap's rule information. */
	rv = rule;
	path = object;

	/* Set weight value. */
	path->attr->weight = route_value_adjust(rv, 0, path->peer);

	return RMAP_OKAY;
}

/* Set local preference rule structure. */
static const struct route_map_rule_cmd route_set_weight_cmd = {
	"weight",
	route_set_weight,
	route_value_compile,
	route_value_free,
};

/* `set distance DISTANCE */
static enum route_map_cmd_result_t
route_set_distance(void *rule, const struct prefix *prefix, void *object)
{
	struct bgp_path_info *path = object;
	struct rmap_value *rv = rule;

	path->attr->distance = rv->value;

	return RMAP_OKAY;
}

/* set distance rule structure */
static const struct route_map_rule_cmd route_set_distance_cmd = {
	"distance",
	route_set_distance,
	route_value_compile,
	route_value_free,
};

/* `set metric METRIC' */

/* Set metric to attribute. */
static enum route_map_cmd_result_t
route_set_metric(void *rule, const struct prefix *prefix, void *object)
{
	struct rmap_value *rv;
	struct bgp_path_info *path;
	uint32_t med = 0;

	/* Fetch routemap's rule information. */
	rv = rule;
	path = object;

	if (path->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))
		med = path->attr->med;

	path->attr->med = route_value_adjust(rv, med, path->peer);
	path->attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC);

	return RMAP_OKAY;
}

/* Set metric rule structure. */
static const struct route_map_rule_cmd route_set_metric_cmd = {
	"metric",
	route_set_metric,
	route_value_compile,
	route_value_free,
};

/* `set table (1-4294967295)' */

static enum route_map_cmd_result_t
route_set_table_id(void *rule, const struct prefix *prefix,

		   void *object)
{
	struct rmap_value *rv;
	struct bgp_path_info *path;

	/* Fetch routemap's rule information. */
	rv = rule;
	path = object;

	path->attr->rmap_table_id = rv->value;

	return RMAP_OKAY;
}

/* Set table_id rule structure. */
static const struct route_map_rule_cmd route_set_table_id_cmd = {
	"table",
	route_set_table_id,
	route_value_compile,
	route_value_free
};

/* `set as-path prepend ASPATH' */

/* For AS path prepend mechanism. */
static enum route_map_cmd_result_t
route_set_aspath_prepend(void *rule, const struct prefix *prefix, void *object)
{
	struct aspath *aspath;
	struct aspath *new;
	struct bgp_path_info *path;

	path = object;

	if (path->attr->aspath->refcnt)
		new = aspath_dup(path->attr->aspath);
	else
		new = path->attr->aspath;

	if ((uintptr_t)rule > 10) {
		aspath = rule;
		aspath_prepend(aspath, new);
	} else {
		as_t as = aspath_leftmost(new);
		if (as)
			new = aspath_add_seq_n(new, as, (uintptr_t)rule);
	}

	path->attr->aspath = new;

	return RMAP_OKAY;
}

static void *route_set_aspath_prepend_compile(const char *arg)
{
	unsigned int num;

	if (sscanf(arg, "last-as %u", &num) == 1 && num > 0 && num <= 10)
		return (void *)(uintptr_t)num;

	return route_aspath_compile(arg);
}

static void route_set_aspath_prepend_free(void *rule)
{
	if ((uintptr_t)rule > 10)
		route_aspath_free(rule);
}


/* Set as-path prepend rule structure. */
static const struct route_map_rule_cmd route_set_aspath_prepend_cmd = {
	"as-path prepend",
	route_set_aspath_prepend,
	route_set_aspath_prepend_compile,
	route_set_aspath_prepend_free,
};

/* `set as-path exclude ASn' */
struct aspath_exclude {
	struct aspath *aspath;
	bool exclude_all;
	char *exclude_aspath_acl_name;
	struct as_list *exclude_aspath_acl;
};

static void *route_aspath_exclude_compile(const char *arg)
{
	struct aspath_exclude *ase;
	const char *str = arg;
	static const char asp_acl[] = "as-path-access-list";

	ase = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct aspath_exclude));
	if (strmatch(str, "all"))
		ase->exclude_all = true;
	else if (!strncmp(str, asp_acl, strlen(asp_acl))) {
		str += strlen(asp_acl);
		while (*str == ' ')
			str++;
		ase->exclude_aspath_acl_name = XSTRDUP(MTYPE_TMP, str);
		ase->exclude_aspath_acl = as_list_lookup(str);
	} else
		ase->aspath = aspath_str2aspath(str, bgp_get_asnotation(NULL));
	return ase;
}

static void route_aspath_exclude_free(void *rule)
{
	struct aspath_exclude *ase = rule;

	aspath_free(ase->aspath);
	if (ase->exclude_aspath_acl_name)
		XFREE(MTYPE_TMP, ase->exclude_aspath_acl_name);
	XFREE(MTYPE_ROUTE_MAP_COMPILED, ase);
}

/* For ASN exclude mechanism.
 * Iterate over ASns requested and filter them from the given AS_PATH one by
 * one.
 * Make a deep copy of existing AS_PATH, but for the first ASn only.
 */
static enum route_map_cmd_result_t
route_set_aspath_exclude(void *rule, const struct prefix *dummy, void *object)
{
	struct aspath *new_path;
	struct bgp_path_info *path;
	struct aspath_exclude *ase = rule;

	path = object;

	if (path->peer->sort != BGP_PEER_EBGP) {
		zlog_warn(
			"`set as-path exclude` is supported only for EBGP peers");
		return RMAP_NOOP;
	}

	if (path->attr->aspath->refcnt)
		new_path = aspath_dup(path->attr->aspath);
	else
		new_path = path->attr->aspath;

	if (ase->aspath)
		path->attr->aspath =
			aspath_filter_exclude(new_path, ase->aspath);
	else if (ase->exclude_all)
		path->attr->aspath = aspath_filter_exclude_all(new_path);

	else if (ase->exclude_aspath_acl_name) {
		if (!ase->exclude_aspath_acl)
			ase->exclude_aspath_acl =
				as_list_lookup(ase->exclude_aspath_acl_name);
		if (ase->exclude_aspath_acl)
			path->attr->aspath =
				aspath_filter_exclude_acl(new_path,
							  ase->exclude_aspath_acl);
	}

	return RMAP_OKAY;
}

/* Set ASn exclude rule structure. */
static const struct route_map_rule_cmd route_set_aspath_exclude_cmd = {
	"as-path exclude",
	route_set_aspath_exclude,
	route_aspath_exclude_compile,
	route_aspath_exclude_free,
};

/* `set as-path replace AS-PATH` */
static void *route_aspath_replace_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_aspath_replace_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static enum route_map_cmd_result_t
route_set_aspath_replace(void *rule, const struct prefix *dummy, void *object)
{
	struct aspath *aspath_new;
	const char *replace = rule;
	struct bgp_path_info *path = object;
	as_t replace_asn = 0;
	as_t configured_asn;
	char *buf;
	char src_asn[ASN_STRING_MAX_SIZE];
	char *acl_list_name = NULL;
	uint32_t acl_list_name_len = 0;
	char *buf_acl_name = NULL;
	static const char asp_acl[] = "as-path-access-list";
	struct as_list *aspath_acl = NULL;

	if (path->peer->sort != BGP_PEER_EBGP) {
		zlog_warn(
			"`set as-path replace` is supported only for EBGP peers");
		goto end_ko;
	}

	buf = strchr(replace, ' ');
	if (!buf) {
		configured_asn = path->peer->change_local_as
					 ? path->peer->change_local_as
					 : path->peer->local_as;
	} else if (!strncmp(replace, asp_acl, strlen(asp_acl))) {
		/* its as-path-acl-list command get the access list name */
		while (*buf == ' ')
			buf++;
		buf_acl_name = buf;
		buf = strchr(buf_acl_name, ' ');
		if (buf)
			acl_list_name_len = buf - buf_acl_name;
		else
			acl_list_name_len = strlen(buf_acl_name);

		buf_acl_name[acl_list_name_len] = 0;
		/* get the acl-list */
		aspath_acl = as_list_lookup(buf_acl_name);
		if (!aspath_acl) {
			zlog_warn("`set as-path replace`, invalid as-path-access-list name: %s",
				  buf_acl_name);
			goto end_ko;
		}
		acl_list_name = XSTRDUP(MTYPE_TMP, buf_acl_name);
		buf_acl_name[acl_list_name_len] = ' ';

		if (!buf) {
			configured_asn = path->peer->change_local_as
						 ? path->peer->change_local_as
						 : path->peer->local_as;
		} else {
			while (*buf == ' ')
				buf++;
			/* get the configured asn */
			if (!asn_str2asn(buf, &configured_asn)) {
				zlog_warn(
					"`set as-path replace`, invalid configured AS %s",
					buf);
				goto end_ko;
			}
		}

		replace = buf;

	} else {
		memcpy(src_asn, replace, (size_t)(buf - replace));
		src_asn[(size_t)(buf - replace)] = '\0';
		replace = src_asn;
		buf++;
		if (!asn_str2asn(buf, &configured_asn)) {
			zlog_warn(
				"`set as-path replace`, invalid configured AS %s",
				buf);
			goto end_ko;
		}
	}

	if (replace && !strmatch(replace, "any") &&
	    !asn_str2asn(replace, &replace_asn)) {
		zlog_warn("`set as-path replace`, invalid AS %s", replace);
		goto end_ko;
	}

	if (path->attr->aspath->refcnt)
		aspath_new = aspath_dup(path->attr->aspath);
	else
		aspath_new = path->attr->aspath;

	if (aspath_acl) {
		path->attr->aspath = aspath_replace_regex_asn(aspath_new,
							      aspath_acl,
							      configured_asn);
	} else if (strmatch(replace, "any")) {
		path->attr->aspath =
			aspath_replace_all_asn(aspath_new, configured_asn);
	} else {
		path->attr->aspath = aspath_replace_specific_asn(
			aspath_new, replace_asn, configured_asn);
	}
	aspath_free(aspath_new);


	if (acl_list_name)
		XFREE(MTYPE_TMP, acl_list_name);
	return RMAP_OKAY;

end_ko:
	if (acl_list_name)
		XFREE(MTYPE_TMP, acl_list_name);
	return RMAP_NOOP;

}

static const struct route_map_rule_cmd route_set_aspath_replace_cmd = {
	"as-path replace",
	route_set_aspath_replace,
	route_aspath_replace_compile,
	route_aspath_replace_free,
};

/* `set community COMMUNITY' */
struct rmap_com_set {
	struct community *com;
	int additive;
	int none;
};

/* For community set mechanism. */
static enum route_map_cmd_result_t
route_set_community(void *rule, const struct prefix *prefix, void *object)
{
	struct rmap_com_set *rcs;
	struct bgp_path_info *path;
	struct attr *attr;
	struct community *new = NULL;
	struct community *old;
	struct community *merge;

	rcs = rule;
	path = object;
	attr = path->attr;
	old = bgp_attr_get_community(attr);

	/* "none" case.  */
	if (rcs->none) {
		bgp_attr_set_community(attr, NULL);
		/* See the longer comment down below. */
		if (old && old->refcnt == 0)
			community_free(&old);
		return RMAP_OKAY;
	}

	/* "additive" case.  */
	if (rcs->additive && old) {
		merge = community_merge(community_dup(old), rcs->com);

		new = community_uniq_sort(merge);
		community_free(&merge);
	} else
		new = community_dup(rcs->com);

	/* HACK: if the old community is not intern'd,
	 * we should free it here, or all reference to it may be
	 * lost.
	 * Really need to cleanup attribute caching sometime.
	 */
	if (old && old->refcnt == 0)
		community_free(&old);

	/* will be interned by caller if required */
	bgp_attr_set_community(attr, new);

	return RMAP_OKAY;
}

/* Compile function for set community. */
static void *route_set_community_compile(const char *arg)
{
	struct rmap_com_set *rcs;
	struct community *com = NULL;
	char *sp;
	int additive = 0;
	int none = 0;

	if (strcmp(arg, "none") == 0)
		none = 1;
	else {
		sp = strstr(arg, "additive");

		if (sp && sp > arg) {
			/* "additive" keyword is included.  */
			additive = 1;
			*(sp - 1) = '\0';
		}

		com = community_str2com(arg);

		if (additive)
			*(sp - 1) = ' ';

		if (!com)
			return NULL;
	}

	rcs = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct rmap_com_set));
	rcs->com = com;
	rcs->additive = additive;
	rcs->none = none;

	return rcs;
}

/* Free function for set community. */
static void route_set_community_free(void *rule)
{
	struct rmap_com_set *rcs = rule;

	if (rcs->com)
		community_free(&rcs->com);
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcs);
}

/* Set community rule structure. */
static const struct route_map_rule_cmd route_set_community_cmd = {
	"community",
	route_set_community,
	route_set_community_compile,
	route_set_community_free,
};

/* `set community COMMUNITY' */
struct rmap_lcom_set {
	struct lcommunity *lcom;
	int additive;
	int none;
};


/* For lcommunity set mechanism. */
static enum route_map_cmd_result_t
route_set_lcommunity(void *rule, const struct prefix *prefix, void *object)
{
	struct rmap_lcom_set *rcs;
	struct bgp_path_info *path;
	struct attr *attr;
	struct lcommunity *new = NULL;
	struct lcommunity *old;
	struct lcommunity *merge;

	rcs = rule;
	path = object;
	attr = path->attr;
	old = bgp_attr_get_lcommunity(attr);

	/* "none" case.  */
	if (rcs->none) {
		bgp_attr_set_lcommunity(attr, NULL);

		/* See the longer comment down below. */
		if (old && old->refcnt == 0)
			lcommunity_free(&old);
		return RMAP_OKAY;
	}

	if (rcs->additive && old) {
		merge = lcommunity_merge(lcommunity_dup(old), rcs->lcom);

		new = lcommunity_uniq_sort(merge);
		lcommunity_free(&merge);
	} else
		new = lcommunity_dup(rcs->lcom);

	/* HACK: if the old large-community is not intern'd,
	 * we should free it here, or all reference to it may be
	 * lost.
	 * Really need to cleanup attribute caching sometime.
	 */
	if (old && old->refcnt == 0)
		lcommunity_free(&old);

	/* will be intern()'d or attr_flush()'d by bgp_update_main() */
	bgp_attr_set_lcommunity(attr, new);

	return RMAP_OKAY;
}

/* Compile function for set community. */
static void *route_set_lcommunity_compile(const char *arg)
{
	struct rmap_lcom_set *rcs;
	struct lcommunity *lcom = NULL;
	char *sp;
	int additive = 0;
	int none = 0;

	if (strcmp(arg, "none") == 0)
		none = 1;
	else {
		sp = strstr(arg, "additive");

		if (sp && sp > arg) {
			/* "additive" keyworkd is included.  */
			additive = 1;
			*(sp - 1) = '\0';
		}

		lcom = lcommunity_str2com(arg);

		if (additive)
			*(sp - 1) = ' ';

		if (!lcom)
			return NULL;
	}

	rcs = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct rmap_com_set));
	rcs->lcom = lcom;
	rcs->additive = additive;
	rcs->none = none;

	return rcs;
}

/* Free function for set lcommunity. */
static void route_set_lcommunity_free(void *rule)
{
	struct rmap_lcom_set *rcs = rule;

	if (rcs->lcom) {
		lcommunity_free(&rcs->lcom);
	}
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcs);
}

/* Set community rule structure. */
static const struct route_map_rule_cmd route_set_lcommunity_cmd = {
	"large-community",
	route_set_lcommunity,
	route_set_lcommunity_compile,
	route_set_lcommunity_free,
};

/* `set large-comm-list (<1-99>|<100-500>|WORD) delete' */

/* For large community set mechanism. */
static enum route_map_cmd_result_t
route_set_lcommunity_delete(void *rule, const struct prefix *pfx, void *object)
{
	struct community_list *list;
	struct lcommunity *merge;
	struct lcommunity *new;
	struct lcommunity *old;
	struct bgp_path_info *path;
	struct rmap_community *rcom = rule;

	if (!rcom)
		return RMAP_OKAY;

	path = object;
	list = community_list_lookup(bgp_clist, rcom->name, rcom->name_hash,
				     LARGE_COMMUNITY_LIST_MASTER);
	old = bgp_attr_get_lcommunity(path->attr);

	if (list && old) {
		merge = lcommunity_list_match_delete(lcommunity_dup(old), list);
		new = lcommunity_uniq_sort(merge);
		lcommunity_free(&merge);

		/* HACK: if the old community is not intern'd,
		 * we should free it here, or all reference to it may be
		 * lost.
		 * Really need to cleanup attribute caching sometime.
		 */
		if (old->refcnt == 0)
			lcommunity_free(&old);

		if (new->size == 0) {
			bgp_attr_set_lcommunity(path->attr, NULL);
			lcommunity_free(&new);
		} else {
			bgp_attr_set_lcommunity(path->attr, new);
		}
	}

	return RMAP_OKAY;
}

/* Compile function for set lcommunity. */
static void *route_set_lcommunity_delete_compile(const char *arg)
{
	struct rmap_community *rcom;
	char **splits;
	int num;

	frrstr_split(arg, " ", &splits, &num);

	rcom = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct rmap_community));
	rcom->name = XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, splits[0]);
	rcom->name_hash = bgp_clist_hash_key(rcom->name);

	for (int i = 0; i < num; i++)
		XFREE(MTYPE_TMP, splits[i]);
	XFREE(MTYPE_TMP, splits);

	return rcom;
}

/* Free function for set lcommunity. */
static void route_set_lcommunity_delete_free(void *rule)
{
	struct rmap_community *rcom = rule;

	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcom->name);
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcom);
}

/* Set lcommunity rule structure. */
static const struct route_map_rule_cmd route_set_lcommunity_delete_cmd = {
	"large-comm-list",
	route_set_lcommunity_delete,
	route_set_lcommunity_delete_compile,
	route_set_lcommunity_delete_free,
};


/* `set comm-list (<1-99>|<100-500>|WORD) delete' */

/* For community set mechanism. */
static enum route_map_cmd_result_t
route_set_community_delete(void *rule, const struct prefix *prefix,
			   void *object)
{
	struct community_list *list;
	struct community *merge;
	struct community *new;
	struct community *old;
	struct bgp_path_info *path;
	struct rmap_community *rcom = rule;

	if (!rcom)
		return RMAP_OKAY;

	path = object;
	list = community_list_lookup(bgp_clist, rcom->name, rcom->name_hash,
				     COMMUNITY_LIST_MASTER);
	old = bgp_attr_get_community(path->attr);

	if (list && old) {
		merge = community_list_match_delete(community_dup(old), list);
		new = community_uniq_sort(merge);
		community_free(&merge);

		/* HACK: if the old community is not intern'd,
		 * we should free it here, or all reference to it may be
		 * lost.
		 * Really need to cleanup attribute caching sometime.
		 */
		if (old->refcnt == 0)
			community_free(&old);

		if (new->size == 0) {
			bgp_attr_set_community(path->attr, NULL);
			community_free(&new);
		} else {
			bgp_attr_set_community(path->attr, new);
		}
	}

	return RMAP_OKAY;
}

/* Compile function for set community. */
static void *route_set_community_delete_compile(const char *arg)
{
	struct rmap_community *rcom;
	char **splits;
	int num;

	frrstr_split(arg, " ", &splits, &num);

	rcom = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct rmap_community));
	rcom->name = XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, splits[0]);
	rcom->name_hash = bgp_clist_hash_key(rcom->name);

	for (int i = 0; i < num; i++)
		XFREE(MTYPE_TMP, splits[i]);
	XFREE(MTYPE_TMP, splits);

	return rcom;
}

/* Free function for set community. */
static void route_set_community_delete_free(void *rule)
{
	struct rmap_community *rcom = rule;

	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcom->name);
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcom);
}

/* Set community rule structure. */
static const struct route_map_rule_cmd route_set_community_delete_cmd = {
	"comm-list",
	route_set_community_delete,
	route_set_community_delete_compile,
	route_set_community_delete_free,
};

/* `set extcomm-list (<1-99>|<100-500>|WORD) delete' */
static enum route_map_cmd_result_t
route_set_ecommunity_delete(void *rule, const struct prefix *prefix,
			   void *object)
{
	struct community_list *list;
	struct ecommunity *merge;
	struct ecommunity *new;
	struct ecommunity *old;
	struct bgp_path_info *path;
	struct rmap_community *rcom = rule;

	if (!rcom)
		return RMAP_OKAY;

	path = object;
	list = community_list_lookup(bgp_clist, rcom->name, rcom->name_hash,
				     EXTCOMMUNITY_LIST_MASTER);
	old = bgp_attr_get_ecommunity(path->attr);
	if (list && old) {
		merge = ecommunity_list_match_delete(ecommunity_dup(old), list);
		new = ecommunity_uniq_sort(merge);
		ecommunity_free(&merge);

		/* HACK: if the old community is not intern'd,
		 * we should free it here, or all reference to it may be
		 * lost.
		 * Really need to cleanup attribute caching sometime.
		 */
		if (old->refcnt == 0)
			ecommunity_free(&old);

		if (new->size == 0) {
			bgp_attr_set_ecommunity(path->attr, NULL);
			ecommunity_free(&new);
		} else {
			bgp_attr_set_ecommunity(path->attr, new);
		}
	}

	return RMAP_OKAY;
}

static void *route_set_ecommunity_delete_compile(const char *arg)
{
	struct rmap_community *rcom;
	char **splits;
	int num;

	frrstr_split(arg, " ", &splits, &num);

	rcom = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct rmap_community));
	rcom->name = XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, splits[0]);
	rcom->name_hash = bgp_clist_hash_key(rcom->name);

	for (int i = 0; i < num; i++)
		XFREE(MTYPE_TMP, splits[i]);
	XFREE(MTYPE_TMP, splits);

	return rcom;
}

static void route_set_ecommunity_delete_free(void *rule)
{
	struct rmap_community *rcom = rule;

	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcom->name);
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcom);
}

static const struct route_map_rule_cmd route_set_ecommunity_delete_cmd = {
	"extended-comm-list",
	route_set_ecommunity_delete,
	route_set_ecommunity_delete_compile,
	route_set_ecommunity_delete_free,
};

/* `set extcommunity rt COMMUNITY' */

struct rmap_ecom_set {
	struct ecommunity *ecom;
	bool none;
};

/* For community set mechanism.  Used by _rt and _soo. */
static enum route_map_cmd_result_t
route_set_ecommunity(void *rule, const struct prefix *prefix, void *object)
{
	struct rmap_ecom_set *rcs;
	struct ecommunity *new_ecom;
	struct ecommunity *old_ecom;
	struct bgp_path_info *path;
	struct attr *attr;

	rcs = rule;
	path = object;
	attr = path->attr;

	if (rcs->none) {
		bgp_attr_set_ecommunity(attr, NULL);
		return RMAP_OKAY;
	}

	if (!rcs->ecom)
		return RMAP_OKAY;

	/* We assume additive for Extended Community. */
	old_ecom = bgp_attr_get_ecommunity(path->attr);

	if (old_ecom) {
		new_ecom =
			ecommunity_merge(ecommunity_dup(old_ecom), rcs->ecom);

		/* old_ecom->refcnt = 1 => owned elsewhere, e.g.
		 * bgp_update_receive()
		 *         ->refcnt = 0 => set by a previous route-map
		 * statement */
		if (!old_ecom->refcnt)
			ecommunity_free(&old_ecom);
	} else
		new_ecom = ecommunity_dup(rcs->ecom);

	/* will be intern()'d or attr_flush()'d by bgp_update_main() */
	bgp_attr_set_ecommunity(path->attr, new_ecom);

	return RMAP_OKAY;
}

static void *route_set_ecommunity_none_compile(const char *arg)
{
	struct rmap_ecom_set *rcs;
	bool none = false;

	if (strncmp(arg, "none", 4) == 0)
		none = true;

	rcs = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct rmap_ecom_set));
	rcs->ecom = NULL;
	rcs->none = none;

	return rcs;
}

static void *route_set_ecommunity_rt_compile(const char *arg)
{
	struct rmap_ecom_set *rcs;
	struct ecommunity *ecom;

	ecom = ecommunity_str2com(arg, ECOMMUNITY_ROUTE_TARGET, 0);
	if (!ecom)
		return NULL;

	rcs = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct rmap_ecom_set));
	rcs->ecom = ecommunity_intern(ecom);
	rcs->none = false;

	return rcs;
}

/* Free function for set community.  Used by _rt and _soo */
static void route_set_ecommunity_free(void *rule)
{
	struct rmap_ecom_set *rcs = rule;

	if (rcs->ecom)
		ecommunity_unintern(&rcs->ecom);

	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcs);
}

static const struct route_map_rule_cmd route_set_ecommunity_none_cmd = {
	"extcommunity",
	route_set_ecommunity,
	route_set_ecommunity_none_compile,
	route_set_ecommunity_free,
};

/* Set community rule structure. */
static const struct route_map_rule_cmd route_set_ecommunity_rt_cmd = {
	"extcommunity rt",
	route_set_ecommunity,
	route_set_ecommunity_rt_compile,
	route_set_ecommunity_free,
};

/* `set extcommunity soo COMMUNITY' */

/* Compile function for set community. */
static void *route_set_ecommunity_soo_compile(const char *arg)
{
	struct rmap_ecom_set *rcs;
	struct ecommunity *ecom;

	ecom = ecommunity_str2com(arg, ECOMMUNITY_SITE_ORIGIN, 0);
	if (!ecom)
		return NULL;

	rcs = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct rmap_ecom_set));
	rcs->ecom = ecommunity_intern(ecom);
	rcs->none = false;

	return rcs;
}

/* Set community rule structure. */
static const struct route_map_rule_cmd route_set_ecommunity_soo_cmd = {
	"extcommunity soo",
	route_set_ecommunity,
	route_set_ecommunity_soo_compile,
	route_set_ecommunity_free,
};

static void *route_set_ecommunity_nt_compile(const char *arg)
{
	struct rmap_ecom_set *rcs;
	struct ecommunity *ecom;

	ecom = ecommunity_str2com(arg, ECOMMUNITY_NODE_TARGET, 0);
	if (!ecom)
		return NULL;

	rcs = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct rmap_ecom_set));
	rcs->ecom = ecommunity_intern(ecom);
	rcs->none = false;

	return rcs;
}

static const struct route_map_rule_cmd route_set_ecommunity_nt_cmd = {
	"extcommunity nt",
	route_set_ecommunity,
	route_set_ecommunity_nt_compile,
	route_set_ecommunity_free,
};

/* `set extcommunity bandwidth' */

struct rmap_ecomm_lb_set {
	uint8_t lb_type;
#define RMAP_ECOMM_LB_SET_VALUE 1
#define RMAP_ECOMM_LB_SET_CUMUL 2
#define RMAP_ECOMM_LB_SET_NUM_MPATH 3
	bool non_trans;
	uint32_t bw;
};

static enum route_map_cmd_result_t
route_set_ecommunity_lb(void *rule, const struct prefix *prefix, void *object)
{
	struct rmap_ecomm_lb_set *rels = rule;
	struct bgp_path_info *path;
	struct peer *peer;
	struct ecommunity ecom_lb = {0};
	struct ecommunity_val lb_eval;
	uint32_t bw_bytes = 0;
	uint16_t mpath_count = 0;
	struct ecommunity *new_ecom;
	struct ecommunity *old_ecom;
	as_t as;

	path = object;
	peer = path->peer;
	if (!peer || !peer->bgp)
		return RMAP_ERROR;

	/* Build link bandwidth extended community */
	as = (peer->bgp->as > BGP_AS_MAX) ? BGP_AS_TRANS : peer->bgp->as;
	if (rels->lb_type == RMAP_ECOMM_LB_SET_VALUE) {
		bw_bytes = ((uint64_t)rels->bw * 1000 * 1000) / 8;
	} else if (rels->lb_type == RMAP_ECOMM_LB_SET_CUMUL) {
		/* process this only for the best path. */
		if (!CHECK_FLAG(path->flags, BGP_PATH_SELECTED))
			return RMAP_OKAY;

		bw_bytes = (uint32_t)bgp_path_info_mpath_cumbw(path);
		if (!bw_bytes)
			return RMAP_OKAY;

	} else if (rels->lb_type == RMAP_ECOMM_LB_SET_NUM_MPATH) {

		/* process this only for the best path. */
		if (!CHECK_FLAG(path->flags, BGP_PATH_SELECTED))
			return RMAP_OKAY;

		bw_bytes = ((uint64_t)peer->bgp->lb_ref_bw * 1000 * 1000) / 8;
		mpath_count = bgp_path_info_mpath_count(path) + 1;
		bw_bytes *= mpath_count;
	}

	encode_lb_extcomm(as, bw_bytes, rels->non_trans, &lb_eval,
			  CHECK_FLAG(peer->flags,
				     PEER_FLAG_DISABLE_LINK_BW_ENCODING_IEEE));

	/* add to route or merge with existing */
	old_ecom = bgp_attr_get_ecommunity(path->attr);
	if (old_ecom) {
		new_ecom = ecommunity_dup(old_ecom);
		ecommunity_add_val(new_ecom, &lb_eval, true, true);
		if (!old_ecom->refcnt)
			ecommunity_free(&old_ecom);
	} else {
		ecom_lb.size = 1;
		ecom_lb.unit_size = ECOMMUNITY_SIZE;
		ecom_lb.val = (uint8_t *)lb_eval.val;
		new_ecom = ecommunity_dup(&ecom_lb);
	}

	/* new_ecom will be intern()'d or attr_flush()'d in call stack */
	bgp_attr_set_ecommunity(path->attr, new_ecom);

	/* Mark that route-map has set link bandwidth; used in attribute
	 * setting decisions.
	 */
	SET_FLAG(path->attr->rmap_change_flags, BATTR_RMAP_LINK_BW_SET);

	return RMAP_OKAY;
}

static void *route_set_ecommunity_lb_compile(const char *arg)
{
	struct rmap_ecomm_lb_set *rels;
	uint8_t lb_type;
	uint32_t bw = 0;
	char bw_str[40] = {0};
	char *p, *str;
	bool non_trans = false;

	str = (char *)arg;
	p = strchr(arg, ' ');
	if (p) {
		int len;

		len = p - arg;
		memcpy(bw_str, arg, len);
		non_trans = true;
		str = bw_str;
	}

	if (strcmp(str, "cumulative") == 0)
		lb_type = RMAP_ECOMM_LB_SET_CUMUL;
	else if (strcmp(str, "num-multipaths") == 0)
		lb_type = RMAP_ECOMM_LB_SET_NUM_MPATH;
	else {
		char *end = NULL;

		bw = strtoul(str, &end, 10);
		if (*end != '\0')
			return NULL;
		lb_type = RMAP_ECOMM_LB_SET_VALUE;
	}

	rels = XCALLOC(MTYPE_ROUTE_MAP_COMPILED,
		       sizeof(struct rmap_ecomm_lb_set));
	rels->lb_type = lb_type;
	rels->bw = bw;
	rels->non_trans = non_trans;

	return rels;
}

static enum route_map_cmd_result_t
route_set_ecommunity_color(void *rule, const struct prefix *prefix,
			   void *object)
{
	struct bgp_path_info *path;

	path = object;

	route_set_ecommunity(rule, prefix, object);

	path->attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_SRTE_COLOR);
	return RMAP_OKAY;
}

static void *route_set_ecommunity_color_compile(const char *arg)
{
	struct rmap_ecom_set *rcs;
	struct ecommunity *ecom;

	ecom = ecommunity_str2com(arg, ECOMMUNITY_COLOR, 0);
	if (!ecom)
		return NULL;

	rcs = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct rmap_ecom_set));
	rcs->ecom = ecommunity_intern(ecom);
	rcs->none = false;

	return rcs;
}

static const struct route_map_rule_cmd route_set_ecommunity_color_cmd = {
	"extcommunity color",
	route_set_ecommunity_color,
	route_set_ecommunity_color_compile,
	route_set_ecommunity_free,
};


static void route_set_ecommunity_lb_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set community rule structure. */
struct route_map_rule_cmd route_set_ecommunity_lb_cmd = {
	"extcommunity bandwidth",
	route_set_ecommunity_lb,
	route_set_ecommunity_lb_compile,
	route_set_ecommunity_lb_free,
};

/* `set origin ORIGIN' */

/* For origin set. */
static enum route_map_cmd_result_t
route_set_origin(void *rule, const struct prefix *prefix, void *object)
{
	uint8_t *origin;
	struct bgp_path_info *path;

	origin = rule;
	path = object;

	path->attr->origin = *origin;

	return RMAP_OKAY;
}

/* Compile function for origin set. */
static void *route_set_origin_compile(const char *arg)
{
	uint8_t *origin;

	origin = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(uint8_t));

	if (strcmp(arg, "igp") == 0)
		*origin = BGP_ORIGIN_IGP;
	else if (strcmp(arg, "egp") == 0)
		*origin = BGP_ORIGIN_EGP;
	else
		*origin = BGP_ORIGIN_INCOMPLETE;

	return origin;
}

/* Compile function for origin set. */
static void route_set_origin_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set origin rule structure. */
static const struct route_map_rule_cmd route_set_origin_cmd = {
	"origin",
	route_set_origin,
	route_set_origin_compile,
	route_set_origin_free,
};

/* `set atomic-aggregate' */

/* For atomic aggregate set. */
static enum route_map_cmd_result_t
route_set_atomic_aggregate(void *rule, const struct prefix *pfx, void *object)
{
	struct bgp_path_info *path;

	path = object;
	path->attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE);

	return RMAP_OKAY;
}

/* Compile function for atomic aggregate. */
static void *route_set_atomic_aggregate_compile(const char *arg)
{
	return (void *)1;
}

/* Compile function for atomic aggregate. */
static void route_set_atomic_aggregate_free(void *rule)
{
	return;
}

/* Set atomic aggregate rule structure. */
static const struct route_map_rule_cmd route_set_atomic_aggregate_cmd = {
	"atomic-aggregate",
	route_set_atomic_aggregate,
	route_set_atomic_aggregate_compile,
	route_set_atomic_aggregate_free,
};

/* AIGP TLV Metric */
static enum route_map_cmd_result_t
route_set_aigp_metric(void *rule, const struct prefix *pfx, void *object)
{
	const char *aigp_metric = rule;
	struct bgp_path_info *path = object;
	uint32_t aigp = 0;

	if (strmatch(aigp_metric, "igp-metric")) {
		if (!path->nexthop)
			return RMAP_NOMATCH;

		bgp_attr_set_aigp_metric(path->attr, path->nexthop->metric);
	} else {
		aigp = atoi(aigp_metric);
		bgp_attr_set_aigp_metric(path->attr, aigp);
	}

	path->attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_AIGP);

	return RMAP_OKAY;
}

static void *route_set_aigp_metric_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_set_aigp_metric_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd route_set_aigp_metric_cmd = {
	"aigp-metric",
	route_set_aigp_metric,
	route_set_aigp_metric_compile,
	route_set_aigp_metric_free,
};

/* `set aggregator as AS A.B.C.D' */
struct aggregator {
	as_t as;
	struct in_addr address;
};

static enum route_map_cmd_result_t
route_set_aggregator_as(void *rule, const struct prefix *prefix, void *object)
{
	struct bgp_path_info *path;
	struct aggregator *aggregator;

	path = object;
	aggregator = rule;

	path->attr->aggregator_as = aggregator->as;
	path->attr->aggregator_addr = aggregator->address;
	path->attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR);

	return RMAP_OKAY;
}

static void *route_set_aggregator_as_compile(const char *arg)
{
	struct aggregator *aggregator;
	char as[10];
	char address[20];
	int ret;

	aggregator =
		XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct aggregator));
	if (sscanf(arg, "%s %s", as, address) != 2) {
		XFREE(MTYPE_ROUTE_MAP_COMPILED, aggregator);
		return NULL;
	}

	aggregator->as = strtoul(as, NULL, 10);
	ret = inet_aton(address, &aggregator->address);
	if (ret == 0) {
		XFREE(MTYPE_ROUTE_MAP_COMPILED, aggregator);
		return NULL;
	}
	return aggregator;
}

static void route_set_aggregator_as_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd route_set_aggregator_as_cmd = {
	"aggregator as",
	route_set_aggregator_as,
	route_set_aggregator_as_compile,
	route_set_aggregator_as_free,
};

/* Set tag to object. object must be pointer to struct bgp_path_info */
static enum route_map_cmd_result_t
route_set_tag(void *rule, const struct prefix *prefix, void *object)
{
	route_tag_t *tag;
	struct bgp_path_info *path;

	tag = rule;
	path = object;

	/* Set tag value */
	path->attr->tag = *tag;

	return RMAP_OKAY;
}

/* Route map commands for tag set. */
static const struct route_map_rule_cmd route_set_tag_cmd = {
	"tag",
	route_set_tag,
	route_map_rule_tag_compile,
	route_map_rule_tag_free,
};

/* Set label-index to object. object must be pointer to struct bgp_path_info */
static enum route_map_cmd_result_t
route_set_label_index(void *rule, const struct prefix *prefix, void *object)
{
	struct rmap_value *rv;
	struct bgp_path_info *path;
	uint32_t label_index;

	/* Fetch routemap's rule information. */
	rv = rule;
	path = object;

	/* Set label-index value. */
	label_index = rv->value;
	if (label_index) {
		path->attr->label_index = label_index;
		path->attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID);
	}

	return RMAP_OKAY;
}

/* Route map commands for label-index set. */
static const struct route_map_rule_cmd route_set_label_index_cmd = {
	"label-index",
	route_set_label_index,
	route_value_compile,
	route_value_free,
};

/* `match ipv6 address IP_ACCESS_LIST' */

static enum route_map_cmd_result_t
route_match_ipv6_address(void *rule, const struct prefix *prefix, void *object)
{
	struct access_list *alist;

	if (prefix->family == AF_INET6) {
		alist = access_list_lookup(AFI_IP6, (char *)rule);
		if (alist == NULL) {
			if (unlikely(CHECK_FLAG(rmap_debug,
						DEBUG_ROUTEMAP_DETAIL)))
				zlog_debug(
					"%s: Access-List Specified: %s does not exist defaulting to NO_MATCH",
					__func__, (char *)rule);

			return RMAP_NOMATCH;
		}

		return (access_list_apply(alist, prefix) == FILTER_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
}

static void *route_match_ipv6_address_compile(const char *arg)
{
	struct access_list *alist;

	alist = access_list_lookup(AFI_IP6, arg);
	if (!alist)
		zlog_warn(
			"Access List specified %s does not exist yet, default will be NO_MATCH until it is created",
			arg);

	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ipv6_address_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip address matching. */
static const struct route_map_rule_cmd route_match_ipv6_address_cmd = {
	"ipv6 address",
	route_match_ipv6_address,
	route_match_ipv6_address_compile,
	route_match_ipv6_address_free
};

/* `match ipv6 next-hop ACCESSLIST6_NAME' */
static enum route_map_cmd_result_t
route_match_ipv6_next_hop(void *rule, const struct prefix *prefix, void *object)
{
	struct bgp_path_info *path;
	struct access_list *alist;
	struct prefix_ipv6 p;

	if (prefix->family == AF_INET6) {
		path = object;
		p.family = AF_INET6;
		p.prefix = path->attr->mp_nexthop_global;
		p.prefixlen = IPV6_MAX_BITLEN;

		alist = access_list_lookup(AFI_IP6, (char *)rule);
		if (!alist) {
			if (unlikely(CHECK_FLAG(rmap_debug,
						DEBUG_ROUTEMAP_DETAIL)))
				zlog_debug(
					"%s: Access-List Specified: %s does not exist defaulting to NO_MATCH",
					__func__, (char *)rule);

			return RMAP_NOMATCH;
		}

		if (access_list_apply(alist, &p) == FILTER_PERMIT)
			return RMAP_MATCH;

		if (path->attr->mp_nexthop_len
		    == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL) {
			p.prefix = path->attr->mp_nexthop_local;
			if (access_list_apply(alist, &p) == FILTER_PERMIT)
				return RMAP_MATCH;
		}
	}

	return RMAP_NOMATCH;
}

static void *route_match_ipv6_next_hop_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ipv6_next_hop_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd route_match_ipv6_next_hop_cmd = {
	"ipv6 next-hop",
	route_match_ipv6_next_hop,
	route_match_ipv6_next_hop_compile,
	route_match_ipv6_next_hop_free
};

/* `match ipv6 next-hop IP_ADDRESS' */

static enum route_map_cmd_result_t
route_match_ipv6_next_hop_address(void *rule, const struct prefix *prefix,
				  void *object)
{
	struct in6_addr *addr = rule;
	struct bgp_path_info *path;

	path = object;

	if (IPV6_ADDR_SAME(&path->attr->mp_nexthop_global, addr))
		return RMAP_MATCH;

	if (path->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL
	    && IPV6_ADDR_SAME(&path->attr->mp_nexthop_local, rule))
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

static void *route_match_ipv6_next_hop_address_compile(const char *arg)
{
	struct in6_addr *address;
	int ret;

	address = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct in6_addr));

	ret = inet_pton(AF_INET6, arg, address);
	if (!ret) {
		XFREE(MTYPE_ROUTE_MAP_COMPILED, address);
		return NULL;
	}

	return address;
}

static void route_match_ipv6_next_hop_address_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd route_match_ipv6_next_hop_address_cmd = {
	"ipv6 next-hop address",
	route_match_ipv6_next_hop_address,
	route_match_ipv6_next_hop_address_compile,
	route_match_ipv6_next_hop_address_free
};

/* `match ip next-hop address IP_ADDRESS' */

static enum route_map_cmd_result_t
route_match_ipv4_next_hop(void *rule, const struct prefix *prefix, void *object)
{
	struct in_addr *addr = rule;
	struct bgp_path_info *path;

	path = object;

	if (path->attr->nexthop.s_addr == addr->s_addr
	    || (path->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV4
		&& IPV4_ADDR_SAME(&path->attr->mp_nexthop_global_in, addr)))
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

static void *route_match_ipv4_next_hop_compile(const char *arg)
{
	struct in_addr *address;
	int ret;

	address = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct in_addr));

	ret = inet_pton(AF_INET, arg, address);
	if (!ret) {
		XFREE(MTYPE_ROUTE_MAP_COMPILED, address);
		return NULL;
	}

	return address;
}

static void route_match_ipv4_next_hop_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd route_match_ipv4_next_hop_cmd = {
	"ip next-hop address",
	route_match_ipv4_next_hop,
	route_match_ipv4_next_hop_compile,
	route_match_ipv4_next_hop_free
};

/* `match ipv6 address prefix-list PREFIX_LIST' */

static enum route_map_cmd_result_t
route_match_ipv6_address_prefix_list(void *rule, const struct prefix *prefix,
				     void *object)
{
	return route_match_address_prefix_list(rule, AFI_IP6, prefix, object);
}

static void *route_match_ipv6_address_prefix_list_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ipv6_address_prefix_list_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd
		route_match_ipv6_address_prefix_list_cmd = {
	"ipv6 address prefix-list",
	route_match_ipv6_address_prefix_list,
	route_match_ipv6_address_prefix_list_compile,
	route_match_ipv6_address_prefix_list_free
};

/* `match ipv6 next-hop type <TYPE>' */

static enum route_map_cmd_result_t
route_match_ipv6_next_hop_type(void *rule, const struct prefix *prefix,
			       void *object)
{
	struct bgp_path_info *path;
	struct in6_addr *addr = rule;

	if (prefix->family == AF_INET6) {
		path = (struct bgp_path_info *)object;
		if (!path)
			return RMAP_NOMATCH;

		if (IPV6_ADDR_SAME(&path->attr->mp_nexthop_global, addr)
		    && !path->attr->nh_ifindex)
			return RMAP_MATCH;
	}

	return RMAP_NOMATCH;
}

static void *route_match_ipv6_next_hop_type_compile(const char *arg)
{
	struct in6_addr *address;
	int ret;

	address = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct in6_addr));

	ret = inet_pton(AF_INET6, "::0", address);
	if (!ret) {
		XFREE(MTYPE_ROUTE_MAP_COMPILED, address);
		return NULL;
	}

	return address;
}

static void route_match_ipv6_next_hop_type_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd
		route_match_ipv6_next_hop_type_cmd = {
	"ipv6 next-hop type",
	route_match_ipv6_next_hop_type,
	route_match_ipv6_next_hop_type_compile,
	route_match_ipv6_next_hop_type_free
};

/* `set ipv6 nexthop global IP_ADDRESS' */

/* Set nexthop to object.  object must be pointer to struct attr. */
static enum route_map_cmd_result_t
route_set_ipv6_nexthop_global(void *rule, const struct prefix *p, void *object)
{
	struct in6_addr *address;
	struct bgp_path_info *path;

	/* Fetch routemap's rule information. */
	address = rule;
	path = object;

	/* Set next hop value. */
	path->attr->mp_nexthop_global = *address;

	/* Set nexthop length. */
	if (path->attr->mp_nexthop_len == 0)
		path->attr->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;

	SET_FLAG(path->attr->rmap_change_flags,
		 BATTR_RMAP_IPV6_GLOBAL_NHOP_CHANGED);

	return RMAP_OKAY;
}

/* Route map `ip next-hop' compile function.  Given string is converted
   to struct in_addr structure. */
static void *route_set_ipv6_nexthop_global_compile(const char *arg)
{
	int ret;
	struct in6_addr *address;

	address = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct in6_addr));

	ret = inet_pton(AF_INET6, arg, address);

	if (ret == 0) {
		XFREE(MTYPE_ROUTE_MAP_COMPILED, address);
		return NULL;
	}

	return address;
}

/* Free route map's compiled `ip next-hop' value. */
static void route_set_ipv6_nexthop_global_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip nexthop set. */
static const struct route_map_rule_cmd
		route_set_ipv6_nexthop_global_cmd = {
	"ipv6 next-hop global",
	route_set_ipv6_nexthop_global,
	route_set_ipv6_nexthop_global_compile,
	route_set_ipv6_nexthop_global_free
};

/* Set next-hop preference value. */
static enum route_map_cmd_result_t
route_set_ipv6_nexthop_prefer_global(void *rule, const struct prefix *prefix,
				     void *object)
{
	struct bgp_path_info *path;
	struct peer *peer;

	/* Fetch routemap's rule information. */
	path = object;
	peer = path->peer;

	if (CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_IN)
	    || CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_IMPORT)) {
		/* Set next hop preference to global */
		path->attr->mp_nexthop_prefer_global = true;
		SET_FLAG(path->attr->rmap_change_flags,
			 BATTR_RMAP_IPV6_PREFER_GLOBAL_CHANGED);
	} else {
		path->attr->mp_nexthop_prefer_global = false;
		SET_FLAG(path->attr->rmap_change_flags,
			 BATTR_RMAP_IPV6_PREFER_GLOBAL_CHANGED);
	}

	return RMAP_OKAY;
}

static void *route_set_ipv6_nexthop_prefer_global_compile(const char *arg)
{
	int *rins = NULL;

	rins = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(int));
	*rins = 1;

	return rins;
}

/* Free route map's compiled `ip next-hop' value. */
static void route_set_ipv6_nexthop_prefer_global_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip nexthop set preferred. */
static const struct route_map_rule_cmd
		route_set_ipv6_nexthop_prefer_global_cmd = {
	"ipv6 next-hop prefer-global",
	route_set_ipv6_nexthop_prefer_global,
	route_set_ipv6_nexthop_prefer_global_compile,
	route_set_ipv6_nexthop_prefer_global_free
};

/* `set ipv6 nexthop local IP_ADDRESS' */

/* Set nexthop to object.  object must be pointer to struct attr. */
static enum route_map_cmd_result_t
route_set_ipv6_nexthop_local(void *rule, const struct prefix *p, void *object)
{
	struct in6_addr *address;
	struct bgp_path_info *path;
	struct bgp_dest *dest;
	struct bgp_table *table = NULL;

	/* Fetch routemap's rule information. */
	address = rule;
	path = object;
	dest = path->net;

	if (!dest)
		return RMAP_OKAY;

	table = bgp_dest_table(dest);
	if (!table)
		return RMAP_OKAY;

	/* Set next hop value. */
	path->attr->mp_nexthop_local = *address;

	/* Set nexthop length. */
	if (table->safi == SAFI_MPLS_VPN || table->safi == SAFI_ENCAP ||
	    table->safi == SAFI_EVPN)
		path->attr->mp_nexthop_len = BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL;
	else
		path->attr->mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL;

	SET_FLAG(path->attr->rmap_change_flags,
		 BATTR_RMAP_IPV6_LL_NHOP_CHANGED);

	return RMAP_OKAY;
}

/* Route map `ip nexthop' compile function.  Given string is converted
   to struct in_addr structure. */
static void *route_set_ipv6_nexthop_local_compile(const char *arg)
{
	int ret;
	struct in6_addr *address;

	address = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct in6_addr));

	ret = inet_pton(AF_INET6, arg, address);

	if (ret == 0) {
		XFREE(MTYPE_ROUTE_MAP_COMPILED, address);
		return NULL;
	}

	return address;
}

/* Free route map's compiled `ip nexthop' value. */
static void route_set_ipv6_nexthop_local_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip nexthop set. */
static const struct route_map_rule_cmd
		route_set_ipv6_nexthop_local_cmd = {
	"ipv6 next-hop local",
	route_set_ipv6_nexthop_local,
	route_set_ipv6_nexthop_local_compile,
	route_set_ipv6_nexthop_local_free
};

/* `set ipv6 nexthop peer-address' */

/* Set nexthop to object.  object must be pointer to struct attr. */
static enum route_map_cmd_result_t
route_set_ipv6_nexthop_peer(void *rule, const struct prefix *pfx, void *object)
{
	struct in6_addr peer_address;
	struct bgp_path_info *path;
	struct peer *peer;

	/* Fetch routemap's rule information. */
	path = object;
	peer = path->peer;

	if ((CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_IN)
	     || CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_IMPORT))
	    && peer->su_remote
	    && sockunion_family(peer->su_remote) == AF_INET6) {
		peer_address = peer->su_remote->sin6.sin6_addr;
		/* Set next hop value and length in attribute. */
		if (IN6_IS_ADDR_LINKLOCAL(&peer_address)) {
			path->attr->mp_nexthop_local = peer_address;
			if (path->attr->mp_nexthop_len
			    != BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
				path->attr->mp_nexthop_len =
					BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL;
		} else {
			path->attr->mp_nexthop_global = peer_address;
			if (path->attr->mp_nexthop_len == 0)
				path->attr->mp_nexthop_len =
					BGP_ATTR_NHLEN_IPV6_GLOBAL;
		}

	} else if (CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_OUT)) {
		/* The next hop value will be set as part of packet
		 * rewrite.
		 * Set the flags here to indicate that rewrite needs to
		 * be done.
		 * Also, clear the value - we clear both global and
		 * link-local
		 * nexthops, whether we send one or both is determined
		 * elsewhere.
		 */
		SET_FLAG(path->attr->rmap_change_flags,
			 BATTR_RMAP_NEXTHOP_PEER_ADDRESS);
		/* clear next hop value. */
		memset(&(path->attr->mp_nexthop_global), 0,
		       sizeof(struct in6_addr));
		memset(&(path->attr->mp_nexthop_local), 0,
		       sizeof(struct in6_addr));
	}

	return RMAP_OKAY;
}

/* Route map `ip next-hop' compile function.  Given string is converted
   to struct in_addr structure. */
static void *route_set_ipv6_nexthop_peer_compile(const char *arg)
{
	int *rins = NULL;

	rins = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(int));
	*rins = 1;

	return rins;
}

/* Free route map's compiled `ip next-hop' value. */
static void route_set_ipv6_nexthop_peer_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip nexthop set. */
static const struct route_map_rule_cmd route_set_ipv6_nexthop_peer_cmd = {
	"ipv6 next-hop peer-address",
	route_set_ipv6_nexthop_peer,
	route_set_ipv6_nexthop_peer_compile,
	route_set_ipv6_nexthop_peer_free
};

/* `set ipv4 vpn next-hop A.B.C.D' */

static enum route_map_cmd_result_t
route_set_vpnv4_nexthop(void *rule, const struct prefix *prefix, void *object)
{
	struct in_addr *address;
	struct bgp_path_info *path;

	/* Fetch routemap's rule information. */
	address = rule;
	path = object;

	/* Set next hop value. */
	path->attr->mp_nexthop_global_in = *address;
	path->attr->mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;

	SET_FLAG(path->attr->rmap_change_flags, BATTR_RMAP_VPNV4_NHOP_CHANGED);

	return RMAP_OKAY;
}

static void *route_set_vpnv4_nexthop_compile(const char *arg)
{
	int ret;
	struct in_addr *address;

	address = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct in_addr));

	ret = inet_aton(arg, address);

	if (ret == 0) {
		XFREE(MTYPE_ROUTE_MAP_COMPILED, address);
		return NULL;
	}

	return address;
}

/* `set ipv6 vpn next-hop A.B.C.D' */

static enum route_map_cmd_result_t
route_set_vpnv6_nexthop(void *rule, const struct prefix *prefix, void *object)
{
	struct in6_addr *address;
	struct bgp_path_info *path;

	/* Fetch routemap's rule information. */
	address = rule;
	path = object;

	/* Set next hop value. */
	memcpy(&path->attr->mp_nexthop_global, address,
	       sizeof(struct in6_addr));
	path->attr->mp_nexthop_len = BGP_ATTR_NHLEN_VPNV6_GLOBAL;

	SET_FLAG(path->attr->rmap_change_flags,
		 BATTR_RMAP_VPNV6_GLOBAL_NHOP_CHANGED);

	return RMAP_OKAY;
}

static void *route_set_vpnv6_nexthop_compile(const char *arg)
{
	int ret;
	struct in6_addr *address;

	address = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct in6_addr));
	ret = inet_pton(AF_INET6, arg, address);

	if (ret == 0) {
		XFREE(MTYPE_ROUTE_MAP_COMPILED, address);
		return NULL;
	}

	return address;
}

static void route_set_vpn_nexthop_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ipv4 next-hop set. */
static const struct route_map_rule_cmd route_set_vpnv4_nexthop_cmd = {
	"ipv4 vpn next-hop",
	route_set_vpnv4_nexthop,
	route_set_vpnv4_nexthop_compile,
	route_set_vpn_nexthop_free
};

/* Route map commands for ipv6 next-hop set. */
static const struct route_map_rule_cmd route_set_vpnv6_nexthop_cmd = {
	"ipv6 vpn next-hop",
	route_set_vpnv6_nexthop,
	route_set_vpnv6_nexthop_compile,
	route_set_vpn_nexthop_free
};

/* `set originator-id' */

/* For origin set. */
static enum route_map_cmd_result_t
route_set_originator_id(void *rule, const struct prefix *prefix, void *object)
{
	struct in_addr *address;
	struct bgp_path_info *path;

	address = rule;
	path = object;

	path->attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID);
	path->attr->originator_id = *address;

	return RMAP_OKAY;
}

/* Compile function for originator-id set. */
static void *route_set_originator_id_compile(const char *arg)
{
	int ret;
	struct in_addr *address;

	address = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct in_addr));

	ret = inet_aton(arg, address);

	if (ret == 0) {
		XFREE(MTYPE_ROUTE_MAP_COMPILED, address);
		return NULL;
	}

	return address;
}

/* Compile function for originator_id set. */
static void route_set_originator_id_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set originator-id rule structure. */
static const struct route_map_rule_cmd route_set_originator_id_cmd = {
	"originator-id",
	route_set_originator_id,
	route_set_originator_id_compile,
	route_set_originator_id_free,
};

static enum route_map_cmd_result_t
route_match_rpki_extcommunity(void *rule, const struct prefix *prefix,
			      void *object)
{
	struct bgp_path_info *path;
	struct ecommunity *ecomm;
	struct ecommunity_val *ecomm_val;
	enum rpki_states *rpki_status = rule;
	enum rpki_states ecomm_rpki_status = RPKI_NOT_BEING_USED;

	path = object;

	ecomm = bgp_attr_get_ecommunity(path->attr);
	if (!ecomm)
		return RMAP_NOMATCH;

	ecomm_val = ecommunity_lookup(ecomm, ECOMMUNITY_ENCODE_OPAQUE_NON_TRANS,
				      ECOMMUNITY_ORIGIN_VALIDATION_STATE);
	if (!ecomm_val)
		return RMAP_NOMATCH;

	/* The Origin Validation State is encoded in the last octet of
	 * the extended community.
	 */
	switch (ecomm_val->val[7]) {
	case ECOMMUNITY_ORIGIN_VALIDATION_STATE_VALID:
		ecomm_rpki_status = RPKI_VALID;
		break;
	case ECOMMUNITY_ORIGIN_VALIDATION_STATE_NOTFOUND:
		ecomm_rpki_status = RPKI_NOTFOUND;
		break;
	case ECOMMUNITY_ORIGIN_VALIDATION_STATE_INVALID:
		ecomm_rpki_status = RPKI_INVALID;
		break;
	case ECOMMUNITY_ORIGIN_VALIDATION_STATE_NOTUSED:
		break;
	}

	if (ecomm_rpki_status == *rpki_status)
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

static void *route_match_extcommunity_compile(const char *arg)
{
	int *rpki_status;

	rpki_status = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(int));

	if (strcmp(arg, "valid") == 0)
		*rpki_status = RPKI_VALID;
	else if (strcmp(arg, "invalid") == 0)
		*rpki_status = RPKI_INVALID;
	else
		*rpki_status = RPKI_NOTFOUND;

	return rpki_status;
}

static const struct route_map_rule_cmd route_match_rpki_extcommunity_cmd = {
	"rpki-extcommunity",
	route_match_rpki_extcommunity,
	route_match_extcommunity_compile,
	route_value_free
};

/*
 * This is the workhorse routine for processing in/out routemap
 * modifications.
 */
static void bgp_route_map_process_peer(const char *rmap_name,
				       struct route_map *map, struct peer *peer,
				       int afi, int safi, int route_update)
{
	struct bgp_filter *filter;

	if (!peer || !rmap_name)
		return;

	filter = &peer->filter[afi][safi];
	/*
	 * in is for non-route-server clients,
	 * out is for all peers
	 */
	if (filter->map[RMAP_IN].name
	    && (strcmp(rmap_name, filter->map[RMAP_IN].name) == 0)) {
		filter->map[RMAP_IN].map = map;

		if (route_update && peer_established(peer->connection)) {
			if (CHECK_FLAG(peer->af_flags[afi][safi],
				       PEER_FLAG_SOFT_RECONFIG)) {
				if (bgp_debug_update(peer, NULL, NULL, 1))
					zlog_debug(
						"Processing route_map %s(%s:%s) update on peer %s (inbound, soft-reconfig)",
						rmap_name, afi2str(afi),
						safi2str(safi), peer->host);

				bgp_soft_reconfig_in(peer, afi, safi);
			} else if (CHECK_FLAG(peer->cap, PEER_CAP_REFRESH_RCV)) {
				if (bgp_debug_update(peer, NULL, NULL, 1))
					zlog_debug(
						"Processing route_map %s(%s:%s) update on peer %s (inbound, route-refresh)",
						rmap_name, afi2str(afi),
						safi2str(safi), peer->host);
				bgp_route_refresh_send(
					peer, afi, safi, 0, 0, 0,
					BGP_ROUTE_REFRESH_NORMAL);
			}
		}
	}

	/*
	 * For outbound, unsuppress and default-originate map change (content or
	 * map created), merely update the "config" here, the actual route
	 * announcement happens at the group level.
	 */
	if (filter->map[RMAP_OUT].name
	    && (strcmp(rmap_name, filter->map[RMAP_OUT].name) == 0))
		filter->map[RMAP_OUT].map = map;

	if (filter->usmap.name && (strcmp(rmap_name, filter->usmap.name) == 0))
		filter->usmap.map = map;

	if (filter->advmap.aname
	    && (strcmp(rmap_name, filter->advmap.aname) == 0)) {
		filter->advmap.amap = map;
	}

	if (filter->advmap.cname
	    && (strcmp(rmap_name, filter->advmap.cname) == 0)) {
		filter->advmap.cmap = map;
	}

	if (peer->default_rmap[afi][safi].name
	    && (strcmp(rmap_name, peer->default_rmap[afi][safi].name) == 0))
		peer->default_rmap[afi][safi].map = map;

	/* Notify BGP conditional advertisement scanner percess */
	peer->advmap_config_change[afi][safi] = true;
}

static void bgp_route_map_update_peer_group(const char *rmap_name,
					    struct route_map *map,
					    struct bgp *bgp)
{
	struct peer_group *group;
	struct listnode *node, *nnode;
	struct bgp_filter *filter;
	int afi, safi;
	int direct;

	if (!bgp)
		return;

	/* All the peers have been updated correctly already. This is
	 * just updating the placeholder data. No real update required.
	 */
	for (ALL_LIST_ELEMENTS(bgp->group, node, nnode, group)) {
		FOREACH_AFI_SAFI (afi, safi) {
			filter = &group->conf->filter[afi][safi];

			for (direct = RMAP_IN; direct < RMAP_MAX; direct++) {
				if ((filter->map[direct].name)
				    && (strcmp(rmap_name,
					       filter->map[direct].name)
					== 0))
					filter->map[direct].map = map;
			}

			if (filter->usmap.name
			    && (strcmp(rmap_name, filter->usmap.name) == 0))
				filter->usmap.map = map;

			if (filter->advmap.aname &&
			    (strcmp(rmap_name, filter->advmap.aname) == 0))
				filter->advmap.amap = map;

			if (filter->advmap.cname &&
			    (strcmp(rmap_name, filter->advmap.cname) == 0))
				filter->advmap.cmap = map;
		}
	}
}

/*
 * Note that if an extreme number (tens of thousands) of route-maps are in use
 * and if bgp has an extreme number of peers, network statements, etc then this
 * function can consume a lot of cycles. This is due to this function being
 * called for each route-map and within this function we walk the list of peers,
 * network statements, etc looking to see if they use this route-map.
 */
static void bgp_route_map_process_update(struct bgp *bgp, const char *rmap_name,
					 bool route_update)
{
	int i;
	bool matched;
	afi_t afi;
	safi_t safi;
	struct peer *peer;
	struct bgp_dest *bn;
	struct bgp_static *bgp_static;
	struct bgp_aggregate *aggregate;
	struct listnode *node, *nnode;
	struct route_map *map;
	char buf[INET6_ADDRSTRLEN];

	map = route_map_lookup_by_name(rmap_name);

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {

		/* Ignore dummy peer-group structure */
		if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
			continue;

		FOREACH_AFI_SAFI (afi, safi) {
			/* process in/out/import/export/default-orig
			 * route-maps */
			bgp_route_map_process_peer(rmap_name, map, peer, afi,
						   safi, route_update);
		}
	}

	/* for outbound/default-orig route-maps, process for groups */
	update_group_policy_update(bgp, BGP_POLICY_ROUTE_MAP, rmap_name,
				   route_update, 0);

	/* update peer-group config (template) */
	bgp_route_map_update_peer_group(rmap_name, map, bgp);

	FOREACH_AFI_SAFI (afi, safi) {
		/* For table route-map updates. */
		if (!bgp_fibupd_safi(safi))
			continue;

		if (bgp->table_map[afi][safi].name
		    && (strcmp(rmap_name, bgp->table_map[afi][safi].name)
			== 0)) {

			/* bgp->table_map[afi][safi].map  is NULL.
			 * i.e Route map creation event.
			 * So update applied_counter.
			 * If it is not NULL, i.e It may be routemap updation or
			 * deletion. so no need to update the counter.
			 */
			if (!bgp->table_map[afi][safi].map)
				route_map_counter_increment(map);
			bgp->table_map[afi][safi].map = map;

			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug(
					"Processing route_map %s(%s:%s) update on table map",
					rmap_name, afi2str(afi),
					safi2str(safi));
			if (route_update)
				bgp_zebra_announce_table(bgp, afi, safi);
		}

		/* For network route-map updates. */
		for (bn = bgp_table_top(bgp->route[afi][safi]); bn;
		     bn = bgp_route_next(bn)) {
			bgp_static = bgp_dest_get_bgp_static_info(bn);
			if (!bgp_static)
				continue;

			if (!bgp_static->rmap.name
			    || (strcmp(rmap_name, bgp_static->rmap.name) != 0))
				continue;

			if (!bgp_static->rmap.map)
				route_map_counter_increment(map);

			bgp_static->rmap.map = map;

			if (route_update && !bgp_static->backdoor) {
				const struct prefix *bn_p =
					bgp_dest_get_prefix(bn);

				if (bgp_debug_zebra(bn_p))
					zlog_debug(
						"Processing route_map %s(%s:%s) update on static route %s",
						rmap_name, afi2str(afi),
						safi2str(safi),
						inet_ntop(bn_p->family,
							  &bn_p->u.prefix, buf,
							  sizeof(buf)));
				bgp_static_update(bgp, bn_p, bgp_static, afi,
						  safi);
			}
		}

		/* For aggregate-address route-map updates. */
		for (bn = bgp_table_top(bgp->aggregate[afi][safi]); bn;
		     bn = bgp_route_next(bn)) {
			aggregate = bgp_dest_get_bgp_aggregate_info(bn);
			if (!aggregate)
				continue;

			matched = false;

			/* Update suppress map pointer. */
			if (aggregate->suppress_map_name
			    && strmatch(aggregate->suppress_map_name,
					rmap_name)) {
				if (aggregate->rmap.map == NULL)
					route_map_counter_increment(map);

				aggregate->suppress_map = map;

				bgp_aggregate_toggle_suppressed(
					aggregate, bgp, bgp_dest_get_prefix(bn),
					afi, safi, false);

				matched = true;
			}

			if (aggregate->rmap.name
			    && strmatch(rmap_name, aggregate->rmap.name)) {
				if (aggregate->rmap.map == NULL)
					route_map_counter_increment(map);

				aggregate->rmap.map = map;

				matched = true;
			}

			if (matched && route_update) {
				const struct prefix *bn_p =
					bgp_dest_get_prefix(bn);

				if (bgp_debug_zebra(bn_p))
					zlog_debug(
						"Processing route_map %s(%s:%s) update on aggregate-address route %s",
						rmap_name, afi2str(afi),
						safi2str(safi),
						inet_ntop(bn_p->family,
							  &bn_p->u.prefix, buf,
							  sizeof(buf)));
				(void)bgp_aggregate_route(bgp, bn_p, afi, safi,
							  aggregate);
			}
		}
	}

	/* For redistribute route-map updates. */
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
			struct list *red_list;
			struct bgp_redist *red;

			red_list = bgp->redist[afi][i];
			if (!red_list)
				continue;

			for (ALL_LIST_ELEMENTS_RO(red_list, node, red)) {
				if (!red->rmap.name
				    || (strcmp(rmap_name, red->rmap.name) != 0))
					continue;

				if (!red->rmap.map)
					route_map_counter_increment(map);

				red->rmap.map = map;

				if (!route_update)
					continue;

				if (BGP_DEBUG(zebra, ZEBRA))
					zlog_debug(
						"Processing route_map %s(%s:%s) update on redistributed routes",
						rmap_name, afi2str(afi),
						safi2str(safi));

				bgp_redistribute_resend(bgp, afi, i,
							red->instance);
			}
		}

	/* for type5 command route-maps */
	FOREACH_AFI_SAFI (afi, safi) {
		if (!bgp->adv_cmd_rmap[afi][safi].name
		    || strcmp(rmap_name, bgp->adv_cmd_rmap[afi][safi].name)
			       != 0)
			continue;

		/* Make sure the route-map is populated here if not already done */
		bgp->adv_cmd_rmap[afi][safi].map = map;

		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"Processing route_map %s(%s:%s) update on advertise type5 route command",
				rmap_name, afi2str(afi), safi2str(safi));

		if (route_update && advertise_type5_routes(bgp, afi)) {
			bgp_evpn_withdraw_type5_routes(bgp, afi, safi);
			bgp_evpn_advertise_type5_routes(bgp, afi, safi);
		}
	}
}

static void bgp_route_map_process_update_cb(char *rmap_name)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp_route_map_process_update(bgp, rmap_name, true);

#ifdef ENABLE_BGP_VNC
		vnc_routemap_update(bgp, __func__);
#endif
	}

	vpn_policy_routemap_event(rmap_name);
}

void bgp_route_map_update_timer(struct event *thread)
{
	route_map_walk_update_list(bgp_route_map_process_update_cb);
}

static void bgp_route_map_mark_update(const char *rmap_name)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	/* If new update is received before the current timer timed out,
	 * turn it off and start a new timer.
	 */
	EVENT_OFF(bm->t_rmap_update);

	/* rmap_update_timer of 0 means don't do route updates */
	if (bm->rmap_update_timer) {
		event_add_timer(bm->master, bgp_route_map_update_timer, NULL,
				bm->rmap_update_timer, &bm->t_rmap_update);

		/* Signal the groups that a route-map update event has
		 * started */
		for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
			update_group_policy_update(bgp, BGP_POLICY_ROUTE_MAP,
						   rmap_name, true, 1);
	} else {
		for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
			bgp_route_map_process_update(bgp, rmap_name, false);
#ifdef ENABLE_BGP_VNC
			vnc_routemap_update(bgp, __func__);
#endif
		}

		vpn_policy_routemap_event(rmap_name);
	}
}

static void bgp_route_map_add(const char *rmap_name)
{
	if (route_map_mark_updated(rmap_name) == 0)
		bgp_route_map_mark_update(rmap_name);

	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_ADDED);
}

static void bgp_route_map_delete(const char *rmap_name)
{
	if (route_map_mark_updated(rmap_name) == 0)
		bgp_route_map_mark_update(rmap_name);

	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_DELETED);
}

static void bgp_route_map_event(const char *rmap_name)
{
	if (route_map_mark_updated(rmap_name) == 0)
		bgp_route_map_mark_update(rmap_name);

	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_ADDED);
}

DEFUN_YANG (match_mac_address,
	    match_mac_address_cmd,
	    "match mac address ACCESSLIST_MAC_NAME",
	    MATCH_STR
	    "mac address\n"
	    "Match address of route\n"
	    "MAC Access-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:mac-address-list']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[3]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_mac_address,
	    no_match_mac_address_cmd,
	    "no match mac address ACCESSLIST_MAC_NAME",
	    NO_STR
	    MATCH_STR
	    "mac\n"
	    "Match address of route\n"
	    "MAC acess-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:mac-address-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/*
 * Helper to handle the case of the user passing in a number or type string
 */
static const char *parse_evpn_rt_type(const char *num_rt_type)
{
	switch (num_rt_type[0]) {
	case '1':
		return "ead";
	case '2':
		return "macip";
	case '3':
		return "multicast";
	case '4':
		return "es";
	case '5':
		return "prefix";
	default:
		break;
	}

	/* Was already full type string */
	return num_rt_type;
}

DEFUN_YANG (match_evpn_route_type,
	    match_evpn_route_type_cmd,
	    "match evpn route-type <ead|1|macip|2|multicast|3|es|4|prefix|5>",
	    MATCH_STR
	    EVPN_HELP_STR
	    EVPN_TYPE_HELP_STR
	    EVPN_TYPE_1_HELP_STR
	    EVPN_TYPE_1_HELP_STR
	    EVPN_TYPE_2_HELP_STR
	    EVPN_TYPE_2_HELP_STR
	    EVPN_TYPE_3_HELP_STR
	    EVPN_TYPE_3_HELP_STR
	    EVPN_TYPE_4_HELP_STR
	    EVPN_TYPE_4_HELP_STR
	    EVPN_TYPE_5_HELP_STR
	    EVPN_TYPE_5_HELP_STR)
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:evpn-route-type']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:evpn-route-type",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      parse_evpn_rt_type(argv[3]->arg));

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_evpn_route_type,
	    no_match_evpn_route_type_cmd,
	    "no match evpn route-type <ead|1|macip|2|multicast|3|es|4|prefix|5>",
	    NO_STR
	    MATCH_STR
	    EVPN_HELP_STR
	    EVPN_TYPE_HELP_STR
	    EVPN_TYPE_1_HELP_STR
	    EVPN_TYPE_1_HELP_STR
	    EVPN_TYPE_2_HELP_STR
	    EVPN_TYPE_2_HELP_STR
	    EVPN_TYPE_3_HELP_STR
	    EVPN_TYPE_3_HELP_STR
	    EVPN_TYPE_4_HELP_STR
	    EVPN_TYPE_4_HELP_STR
	    EVPN_TYPE_5_HELP_STR
	    EVPN_TYPE_5_HELP_STR)
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:evpn-route-type']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (match_evpn_vni,
	    match_evpn_vni_cmd,
	    "match evpn vni " CMD_VNI_RANGE,
	    MATCH_STR
	    EVPN_HELP_STR
	    "Match VNI\n"
	    "VNI ID\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:evpn-vni']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:evpn-vni", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[3]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_evpn_vni,
	    no_match_evpn_vni_cmd,
	    "no match evpn vni " CMD_VNI_RANGE,
	    NO_STR
	    MATCH_STR
	    EVPN_HELP_STR
	    "Match VNI\n"
	    "VNI ID\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:evpn-vni']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:evpn-vni", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_DESTROY, argv[3]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (match_evpn_default_route,
	    match_evpn_default_route_cmd,
	    "match evpn default-route",
	    MATCH_STR
	    EVPN_HELP_STR
	    "default EVPN type-5 route\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:evpn-default-route']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:evpn-default-route",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_evpn_default_route,
	    no_match_evpn_default_route_cmd,
	    "no match evpn default-route",
	    NO_STR
	    MATCH_STR
	    EVPN_HELP_STR
	    "default EVPN type-5 route\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:evpn-default-route']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (match_evpn_rd,
	    match_evpn_rd_cmd,
	    "match evpn rd ASN:NN_OR_IP-ADDRESS:NN",
	    MATCH_STR
	    EVPN_HELP_STR
	    "Route Distinguisher\n"
	    "ASN:XX or A.B.C.D:XX\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:evpn-rd']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(
		xpath_value, sizeof(xpath_value),
		"%s/rmap-match-condition/frr-bgp-route-map:route-distinguisher",
		xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[3]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_evpn_rd,
	    no_match_evpn_rd_cmd,
	    "no match evpn rd ASN:NN_OR_IP-ADDRESS:NN",
	    NO_STR
	    MATCH_STR
	    EVPN_HELP_STR
	    "Route Distinguisher\n"
	    "ASN:XX or A.B.C.D:XX\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:evpn-rd']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_evpn_gw_ip_ipv4,
	    set_evpn_gw_ip_ipv4_cmd,
	    "set evpn gateway-ip ipv4 A.B.C.D",
	    SET_STR
	    EVPN_HELP_STR
	    "Set gateway IP for prefix advertisement route\n"
	    "IPv4 address\n"
	    "Gateway IP address in IPv4 format\n")
{
	int ret;
	union sockunion su;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-evpn-gateway-ip-ipv4']";
	char xpath_value[XPATH_MAXLEN];

	ret = str2sockunion(argv[4]->arg, &su);
	if (ret < 0) {
		vty_out(vty, "%% Malformed gateway IP\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (su.sin.sin_addr.s_addr == 0 ||
	    !ipv4_unicast_valid(&su.sin.sin_addr)) {
		vty_out(vty,
			"%% Gateway IP cannot be 0.0.0.0, multicast or reserved\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:evpn-gateway-ip-ipv4",
		 xpath);

	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[4]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_evpn_gw_ip_ipv4,
	    no_set_evpn_gw_ip_ipv4_cmd,
	    "no set evpn gateway-ip ipv4 A.B.C.D",
	    NO_STR
	    SET_STR
	    EVPN_HELP_STR
	    "Set gateway IP for prefix advertisement route\n"
	    "IPv4 address\n"
	    "Gateway IP address in IPv4 format\n")
{
	int ret;
	union sockunion su;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-evpn-gateway-ip-ipv4']";

	ret = str2sockunion(argv[5]->arg, &su);
	if (ret < 0) {
		vty_out(vty, "%% Malformed gateway IP\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (su.sin.sin_addr.s_addr == 0 ||
	    !ipv4_unicast_valid(&su.sin.sin_addr)) {
		vty_out(vty,
			"%% Gateway IP cannot be 0.0.0.0, multicast or reserved\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_evpn_gw_ip_ipv6,
	    set_evpn_gw_ip_ipv6_cmd,
	    "set evpn gateway-ip ipv6 X:X::X:X",
	    SET_STR
	    EVPN_HELP_STR
	    "Set gateway IP for prefix advertisement route\n"
	    "IPv6 address\n"
	    "Gateway IP address in IPv6 format\n")
{
	int ret;
	union sockunion su;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-evpn-gateway-ip-ipv6']";
	char xpath_value[XPATH_MAXLEN];

	ret = str2sockunion(argv[4]->arg, &su);
	if (ret < 0) {
		vty_out(vty, "%% Malformed gateway IP\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (IN6_IS_ADDR_LINKLOCAL(&su.sin6.sin6_addr)
	    || IN6_IS_ADDR_MULTICAST(&su.sin6.sin6_addr)) {
		vty_out(vty,
			"%% Gateway IP cannot be a linklocal or multicast address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:evpn-gateway-ip-ipv6",
		 xpath);

	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[4]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_evpn_gw_ip_ipv6,
	    no_set_evpn_gw_ip_ipv6_cmd,
	    "no set evpn gateway-ip ipv6 X:X::X:X",
	    NO_STR
	    SET_STR
	    EVPN_HELP_STR
	    "Set gateway IP for prefix advertisement route\n"
	    "IPv4 address\n"
	    "Gateway IP address in IPv4 format\n")
{
	int ret;
	union sockunion su;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-evpn-gateway-ip-ipv6']";

	ret = str2sockunion(argv[5]->arg, &su);
	if (ret < 0) {
		vty_out(vty, "%% Malformed gateway IP\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (IN6_IS_ADDR_LINKLOCAL(&su.sin6.sin6_addr)
	    || IN6_IS_ADDR_MULTICAST(&su.sin6.sin6_addr)) {
		vty_out(vty,
			"%% Gateway IP cannot be a linklocal or multicast address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(match_vrl_source_vrf,
      match_vrl_source_vrf_cmd,
      "match source-vrf NAME$vrf_name",
      MATCH_STR
      "source vrf\n"
      "The VRF name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:source-vrf']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:source-vrf", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, vrf_name);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_match_vrl_source_vrf,
      no_match_vrl_source_vrf_cmd,
      "no match source-vrf NAME$vrf_name",
      NO_STR MATCH_STR
      "source vrf\n"
      "The VRF name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:source-vrf']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (match_peer,
       match_peer_cmd,
       "match peer <A.B.C.D$addrv4|X:X::X:X$addrv6|WORD$intf>",
       MATCH_STR
       "Match peer address\n"
       "IP address of peer\n"
       "IPv6 address of peer\n"
       "Interface name of peer or peer group name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:peer']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	if (addrv4_str) {
		snprintf(
			xpath_value, sizeof(xpath_value),
			"%s/rmap-match-condition/frr-bgp-route-map:peer-ipv4-address",
			xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
				      addrv4_str);
	} else if (addrv6_str) {
		snprintf(
			xpath_value, sizeof(xpath_value),
			"%s/rmap-match-condition/frr-bgp-route-map:peer-ipv6-address",
			xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
				      addrv6_str);
	} else {
		snprintf(
			xpath_value, sizeof(xpath_value),
			"%s/rmap-match-condition/frr-bgp-route-map:peer-interface",
			xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, intf);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (match_peer_local,
	    match_peer_local_cmd,
	    "match peer local",
	    MATCH_STR
	    "Match peer address\n"
	    "Static or Redistributed routes\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:peer']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:peer-local", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_peer,
	    no_match_peer_cmd,
	    "no match peer [<local|A.B.C.D|X:X::X:X|WORD>]",
	    NO_STR
	    MATCH_STR
	    "Match peer address\n"
	    "Static or Redistributed routes\n"
	    "IP address of peer\n"
	    "IPv6 address of peer\n"
	    "Interface name of peer\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:peer']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

#ifdef HAVE_SCRIPTING
DEFUN_YANG (match_script,
	    match_script_cmd,
	    "[no] match script WORD",
	    NO_STR
	    MATCH_STR
	    "Execute script to determine match\n"
	    "The script name to run, without .lua; e.g. 'myroutemap' to run myroutemap.lua\n")
{
	bool no = strmatch(argv[0]->text, "no");
	int i = 0;
	argv_find(argv, argc, "WORD", &i);
	const char *script = argv[i]->arg;
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-script']";
	char xpath_value[XPATH_MAXLEN];

	if (no) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-match-condition/frr-bgp-route-map:script",
			 xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_DESTROY,
				      script);

		return nb_cli_apply_changes(vty, NULL);
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
			"%s/rmap-match-condition/frr-bgp-route-map:script",
			xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			script);

	return nb_cli_apply_changes(vty, NULL);
}
#endif /* HAVE_SCRIPTING */

/* match probability */
DEFUN_YANG (match_probability,
	    match_probability_cmd,
	    "match probability (0-100)",
	    MATCH_STR
	    "Match portion of routes defined by percentage value\n"
	    "Percentage of routes\n")
{
	int idx_number = 2;

	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:probability']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:probability",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_number]->arg);

	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (no_match_probability,
	    no_match_probability_cmd,
	    "no match probability [(1-99)]",
	    NO_STR
	    MATCH_STR
	    "Match portion of routes defined by percentage value\n"
	    "Percentage of routes\n")
{
	int idx_number = 3;
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:probability']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	if (argc <= idx_number)
		return nb_cli_apply_changes(vty, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:probability",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_DESTROY,
			      argv[idx_number]->arg);

	return nb_cli_apply_changes(vty, NULL);
}


DEFPY_YANG (match_ip_route_source,
       match_ip_route_source_cmd,
       "match ip route-source ACCESSLIST4_NAME",
       MATCH_STR
       IP_STR
       "Match advertising source address of route\n"
       "IP Access-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:ip-route-source']";
	char xpath_value[XPATH_MAXLEN + 32];
	int idx_acl = 3;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
			"%s/rmap-match-condition/frr-bgp-route-map:list-name",
			xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_acl]->arg);

	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (no_match_ip_route_source,
	    no_match_ip_route_source_cmd,
	    "no match ip route-source [ACCESSLIST4_NAME]",
	    NO_STR
	    MATCH_STR
	    IP_STR
	    "Match advertising source address of route\n"
	    "IP Access-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:ip-route-source']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (match_ip_route_source_prefix_list,
	    match_ip_route_source_prefix_list_cmd,
	    "match ip route-source prefix-list PREFIXLIST_NAME",
	    MATCH_STR
	    IP_STR
	    "Match advertising source address of route\n"
	    "Match entries of prefix-lists\n"
	    "IP prefix-list name\n")
{
	int idx_word = 4;
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:ip-route-source-prefix-list']";
	char xpath_value[XPATH_MAXLEN + 32];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_word]->arg);

	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (no_match_ip_route_source_prefix_list,
	    no_match_ip_route_source_prefix_list_cmd,
	    "no match ip route-source prefix-list [PREFIXLIST_NAME]",
	    NO_STR
	    MATCH_STR
	    IP_STR
	    "Match advertising source address of route\n"
	    "Match entries of prefix-lists\n"
	    "IP prefix-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:ip-route-source-prefix-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (match_local_pref,
	    match_local_pref_cmd,
	    "match local-preference (0-4294967295)",
	    MATCH_STR
	    "Match local-preference of route\n"
	    "Metric value\n")
{
	int idx_number = 2;

	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-local-preference']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:local-preference",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_number]->arg);

	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (no_match_local_pref,
	    no_match_local_pref_cmd,
	    "no match local-preference [(0-4294967295)]",
	    NO_STR
	    MATCH_STR
	    "Match local preference of route\n"
	    "Local preference value\n")
{
	int idx_localpref = 3;
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-local-preference']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	if (argc <= idx_localpref)
		return nb_cli_apply_changes(vty, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:local-preference",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_DESTROY,
			      argv[idx_localpref]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(match_alias, match_alias_cmd, "match alias ALIAS_NAME",
	   MATCH_STR
	   "Match BGP community alias name\n"
	   "BGP community alias name\n")
{
	const char *alias = argv[2]->arg;
	struct community_alias ca1;
	struct community_alias *lookup_alias;

	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-alias']";
	char xpath_value[XPATH_MAXLEN];

	memset(&ca1, 0, sizeof(ca1));
	strlcpy(ca1.alias, alias, sizeof(ca1.alias));
	lookup_alias = bgp_ca_alias_lookup(&ca1);
	if (!lookup_alias) {
		vty_out(vty, "%% BGP alias name '%s' does not exist\n", alias);
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:alias", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, alias);

	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG(no_match_alias, no_match_alias_cmd, "no match alias [ALIAS_NAME]",
	   NO_STR MATCH_STR
	   "Match BGP community alias name\n"
	   "BGP community alias name\n")
{
	int idx_alias = 3;
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-alias']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	if (argc <= idx_alias)
		return nb_cli_apply_changes(vty, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:alias", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_DESTROY,
			      argv[idx_alias]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_community, match_community_cmd,
	"match community <(1-99)|(100-500)|COMMUNITY_LIST_NAME> [<exact-match$exact|any$any>]",
	MATCH_STR "Match BGP community list\n"
		  "Community-list number (standard)\n"
		  "Community-list number (expanded)\n"
		  "Community-list name\n"
		  "Do exact matching of communities\n"
		  "Do matching of any community\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-community']";
	char xpath_value[XPATH_MAXLEN];
	char xpath_match[XPATH_MAXLEN];
	int idx_comm_list = 2;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(
		xpath_value, sizeof(xpath_value),
		"%s/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name",
		xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[idx_comm_list]->arg);

	snprintf(xpath_match, sizeof(xpath_match),
		 "%s/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-exact-match",
		 xpath);
	if (exact)
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY,
				"true");
	else
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY, "false");

	snprintf(xpath_match, sizeof(xpath_match),
		 "%s/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-any",
		 xpath);
	if (any)
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY, "false");

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(
	no_match_community, no_match_community_cmd,
	"no match community [<(1-99)|(100-500)|COMMUNITY_LIST_NAME> [<exact-match$exact|any$any>]]",
	NO_STR MATCH_STR "Match BGP community list\n"
			 "Community-list number (standard)\n"
			 "Community-list number (expanded)\n"
			 "Community-list name\n"
			 "Do exact matching of communities\n"
			 "Do matching of any community\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-community']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	match_lcommunity, match_lcommunity_cmd,
	"match large-community <(1-99)|(100-500)|LCOMMUNITY_LIST_NAME> [<exact-match$exact|any$any>]",
	MATCH_STR "Match BGP large community list\n"
		  "Large Community-list number (standard)\n"
		  "Large Community-list number (expanded)\n"
		  "Large Community-list name\n"
		  "Do exact matching of communities\n"
		  "Do matching of any community\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-large-community']";
	char xpath_value[XPATH_MAXLEN];
	char xpath_match[XPATH_MAXLEN];
	int idx_lcomm_list = 2;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(
		xpath_value, sizeof(xpath_value),
		"%s/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name",
		xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[idx_lcomm_list]->arg);

	snprintf(xpath_match, sizeof(xpath_match),
		 "%s/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-exact-match",
		 xpath);
	if (exact)
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY,
				"true");
	else
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY, "false");

	snprintf(xpath_match, sizeof(xpath_match),
		 "%s/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name-any",
		 xpath);
	if (any)
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY, "true");
	else
		nb_cli_enqueue_change(vty, xpath_match, NB_OP_MODIFY, "false");

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(
	no_match_lcommunity, no_match_lcommunity_cmd,
	"no match large-community [<(1-99)|(100-500)|LCOMMUNITY_LIST_NAME> [<exact-match|any>]]",
	NO_STR MATCH_STR "Match BGP large community list\n"
			 "Large Community-list number (standard)\n"
			 "Large Community-list number (expanded)\n"
			 "Large Community-list name\n"
			 "Do exact matching of communities\n"
			 "Do matching of any community\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-large-community']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (match_ecommunity,
	    match_ecommunity_cmd,
            "match extcommunity <(1-99)|(100-500)|EXTCOMMUNITY_LIST_NAME>",
	    MATCH_STR
	    "Match BGP/VPN extended community list\n"
	    "Extended community-list number (standard)\n"
	    "Extended community-list number (expanded)\n"
	    "Extended community-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-extcommunity']";
	char xpath_value[XPATH_MAXLEN];
	int idx_comm_list = 2;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(
		xpath_value, sizeof(xpath_value),
		"%s/rmap-match-condition/frr-bgp-route-map:comm-list/comm-list-name",
		xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[idx_comm_list]->arg);

	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (no_match_ecommunity,
	    no_match_ecommunity_cmd,
	    "no match extcommunity [<(1-99)|(100-500)|EXTCOMMUNITY_LIST_NAME>]",
	    NO_STR
	    MATCH_STR
	    "Match BGP/VPN extended community list\n"
	    "Extended community-list number (standard)\n"
	    "Extended community-list number (expanded)\n"
	    "Extended community-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-extcommunity']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}


DEFPY_YANG (set_ecommunity_delete,
	    set_ecommunity_delete_cmd,
            "set extended-comm-list " EXTCOMM_LIST_CMD_STR " delete",
	    SET_STR
	    "set BGP extended community list (for deletion)\n"
	    EXTCOMM_STD_LIST_NUM_STR
	    EXTCOMM_EXP_LIST_NUM_STR
	    EXTCOMM_LIST_NAME_STR
            "Delete matching extended communities\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:extended-comm-list-delete']";
	char xpath_value[XPATH_MAXLEN];
	int idx_comm_list = 2;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:comm-list-name",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			argv[idx_comm_list]->arg);
	return nb_cli_apply_changes(vty, NULL);
}


DEFPY_YANG (no_set_ecommunity_delete,
	    no_set_ecommunity_delete_cmd,
            "no set extended-comm-list [" EXTCOMM_LIST_CMD_STR "] delete",
	    NO_STR
	    SET_STR
	    "set BGP extended community list (for deletion)\n"
	    EXTCOMM_STD_LIST_NUM_STR
	    EXTCOMM_EXP_LIST_NUM_STR
	    EXTCOMM_LIST_NAME_STR
            "Delete matching extended communities\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:extended-comm-list-delete']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (match_aspath,
	    match_aspath_cmd,
	    "match as-path AS_PATH_FILTER_NAME",
	    MATCH_STR
	    "Match BGP AS path list\n"
	    "AS path access-list name\n")
{
	int idx_word = 2;

	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:as-path-list']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_word]->arg);

	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (no_match_aspath,
	    no_match_aspath_cmd,
	    "no match as-path [AS_PATH_FILTER_NAME]",
	    NO_STR
	    MATCH_STR
	    "Match BGP AS path list\n"
	    "AS path access-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:as-path-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (match_origin,
	    match_origin_cmd,
	    "match origin <egp|igp|incomplete>",
	    MATCH_STR
	    "BGP origin code\n"
	    "remote EGP\n"
	    "local IGP\n"
	     "unknown heritage\n")
{
	int idx_origin = 2;
	const char *origin_type;
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-origin']";
	char xpath_value[XPATH_MAXLEN];

	if (strncmp(argv[idx_origin]->arg, "igp", 2) == 0)
		origin_type = "igp";
	else if (strncmp(argv[idx_origin]->arg, "egp", 1) == 0)
		origin_type = "egp";
	else if (strncmp(argv[idx_origin]->arg, "incomplete", 2) == 0)
		origin_type = "incomplete";
	else {
		vty_out(vty, "%% Invalid match origin type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:origin", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, origin_type);

	return nb_cli_apply_changes(vty, NULL);
}


DEFUN_YANG (no_match_origin,
	    no_match_origin_cmd,
	    "no match origin [<egp|igp|incomplete>]",
	    NO_STR
	    MATCH_STR
	    "BGP origin code\n"
	    "remote EGP\n"
	    "local IGP\n"
	    "unknown heritage\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:match-origin']";
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_table_id,
	    set_table_id_cmd,
	    "set table (1-4294967295)",
	    SET_STR
	    "export route to non-main kernel table\n"
	    "Kernel routing table id\n")
{
	int idx_number = 2;
	const char *xpath = "./set-action[action='frr-bgp-route-map:table']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:table", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_number]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_table_id,
	    no_set_table_id_cmd,
	    "no set table",
	    NO_STR
	    SET_STR
	    "export route to non-main kernel table\n")
{
	const char *xpath = "./set-action[action='frr-bgp-route-map:table']";
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_ip_nexthop_peer,
	    set_ip_nexthop_peer_cmd,
	    "[no] set ip next-hop peer-address",
	    NO_STR
	    SET_STR
	    IP_STR
	    "Next hop address\n"
	    "Use peer address (for BGP only)\n")
{
	char xpath_value[XPATH_MAXLEN];
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-ipv4-nexthop']";

	if (strmatch(argv[0]->text, "no"))
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-set-action/frr-bgp-route-map:ipv4-nexthop",
			 xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
				      "peer-address");
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_ip_nexthop_unchanged,
	    set_ip_nexthop_unchanged_cmd,
	    "[no] set ip next-hop unchanged",
	    NO_STR
	    SET_STR
	    IP_STR
	    "Next hop address\n"
	    "Don't modify existing Next hop address\n")
{
	char xpath_value[XPATH_MAXLEN];
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-ipv4-nexthop']";

	if (strmatch(argv[0]->text, "no"))
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-set-action/frr-bgp-route-map:ipv4-nexthop",
			 xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
				      "unchanged");
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_distance,
	    set_distance_cmd,
	    "set distance (1-255)",
	    SET_STR
	    "BGP Administrative Distance to use\n"
	    "Distance value\n")
{
	int idx_number = 2;
	const char *xpath = "./set-action[action='frr-bgp-route-map:distance']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:distance", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_number]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_distance,
	    no_set_distance_cmd,
	    "no set distance [(1-255)]",
	    NO_STR SET_STR
	    "BGP Administrative Distance to use\n"
	    "Distance value\n")
{
	const char *xpath = "./set-action[action='frr-bgp-route-map:distance']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(set_l3vpn_nexthop_encapsulation, set_l3vpn_nexthop_encapsulation_cmd,
	   "[no] set l3vpn next-hop encapsulation gre",
	   NO_STR SET_STR
	   "L3VPN operations\n"
	   "Next hop Information\n"
	   "Encapsulation options (for BGP only)\n"
	   "Accept L3VPN traffic over GRE encapsulation\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-l3vpn-nexthop-encapsulation']";
	const char *xpath_value =
		"./set-action[action='frr-bgp-route-map:set-l3vpn-nexthop-encapsulation']/rmap-set-action/frr-bgp-route-map:l3vpn-nexthop-encapsulation";
	enum nb_operation operation;

	if (no)
		operation = NB_OP_DESTROY;
	else
		operation = NB_OP_CREATE;

	nb_cli_enqueue_change(vty, xpath, operation, NULL);
	if (operation == NB_OP_DESTROY)
		return nb_cli_apply_changes(vty, NULL);

	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, "gre");

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_local_pref,
	    set_local_pref_cmd,
	    "set local-preference WORD",
	    SET_STR
	    "BGP local preference path attribute\n"
	    "Preference value (0-4294967295)\n")
{
	int idx_number = 2;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-local-preference']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:local-pref", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_number]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_local_pref,
	    no_set_local_pref_cmd,
	    "no set local-preference [WORD]",
	    NO_STR
	    SET_STR
	    "BGP local preference path attribute\n"
	    "Preference value (0-4294967295)\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-local-preference']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_weight,
	    set_weight_cmd,
	    "set weight (0-4294967295)",
	    SET_STR
	    "BGP weight for routing table\n"
	    "Weight value\n")
{
	int idx_number = 2;
	const char *xpath = "./set-action[action='frr-bgp-route-map:weight']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:weight", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_number]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_weight,
	    no_set_weight_cmd,
	    "no set weight [(0-4294967295)]",
	    NO_STR
	    SET_STR
	    "BGP weight for routing table\n"
	    "Weight value\n")
{
	const char *xpath = "./set-action[action='frr-bgp-route-map:weight']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_label_index,
	    set_label_index_cmd,
	    "set label-index (0-1048560)",
	    SET_STR
	    "Label index to associate with the prefix\n"
	    "Label index value\n")
{
	int idx_number = 2;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:label-index']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:label-index", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_number]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_label_index,
	    no_set_label_index_cmd,
	    "no set label-index [(0-1048560)]",
	    NO_STR
	    SET_STR
	    "Label index to associate with the prefix\n"
	    "Label index value\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:label-index']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_aspath_prepend_asn,
	    set_aspath_prepend_asn_cmd,
	    "set as-path prepend ASNUM...",
	    SET_STR
	    "Transform BGP AS_PATH attribute\n"
	    "Prepend to the as-path\n"
	    AS_STR)
{
	int idx_asn = 3;
	int ret;
	char *str;
	struct aspath *aspath;

	str = argv_concat(argv, argc, idx_asn);

	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-prepend']";
	char xpath_value[XPATH_MAXLEN];

	aspath = route_aspath_compile(str);
	if (!aspath) {
		vty_out(vty, "%% Invalid AS path value %s\n", str);
		return CMD_WARNING_CONFIG_FAILED;
	}
	route_aspath_free(aspath);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:prepend-as-path", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, str);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, str);
	return ret;
}

DEFUN_YANG (set_aspath_prepend_lastas,
	    set_aspath_prepend_lastas_cmd,
	    "set as-path prepend last-as (1-10)",
	    SET_STR
	    "Transform BGP AS_PATH attribute\n"
	    "Prepend to the as-path\n"
	    "Use the last AS-number in the as-path\n"
	    "Number of times to insert\n")
{
	int idx_num = 4;

	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-prepend']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:last-as", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_num]->arg);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(set_aspath_replace_asn, set_aspath_replace_asn_cmd,
	   "set as-path replace <any|ASNUM>$replace [<ASNUM>$configured_asn]",
	   SET_STR
	   "Transform BGP AS_PATH attribute\n"
	   "Replace AS number to local or configured AS number\n"
	   "Replace any AS number to local or configured AS number\n"
	   "Replace a specific AS number to local or configured AS number\n"
	   "Define the configured AS number\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-replace']";
	char xpath_value[XPATH_MAXLEN];
	as_t as_value, as_configured_value;
	char replace_value[ASN_STRING_MAX_SIZE * 2];

	if (!strmatch(replace, "any") && !asn_str2asn(replace, &as_value)) {
		vty_out(vty, "%% Invalid AS value %s\n", replace);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (configured_asn_str &&
	    !asn_str2asn(configured_asn_str, &as_configured_value)) {
		vty_out(vty, "%% Invalid AS configured value %s\n",
			configured_asn_str);
		return CMD_WARNING_CONFIG_FAILED;
	}
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:replace-as-path", xpath);
	snprintf(replace_value, sizeof(replace_value), "%s%s%s", replace,
		 configured_asn_str ? " " : "",
		 configured_asn_str ? configured_asn_str : "");
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, replace_value);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_set_aspath_replace_asn, no_set_aspath_replace_asn_cmd,
	   "no set as-path replace [<any|ASNUM>] [<ASNUM>$configured_asn]",
	   NO_STR SET_STR
	   "Transform BGP AS_PATH attribute\n"
	   "Replace AS number to local or configured AS number\n"
	   "Replace any AS number to local or configured AS number\n"
	   "Replace a specific AS number to local or configured AS number\n"
	   "Define the configured AS number\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-replace']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	set_aspath_replace_access_list, set_aspath_replace_access_list_cmd,
	"set as-path replace as-path-access-list AS_PATH_FILTER_NAME$aspath_filter_name [<ASNUM>$configured_asn]",
	SET_STR
	"Transform BGP AS-path attribute\n"
	"Replace AS number to local or configured AS number\n"
	"Specify an as path access list name\n"
	"AS path access list name\n"
	"Define the configured AS number\n")
{
	char *str;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-replace']";
	char xpath_value[XPATH_MAXLEN];
	as_t as_configured_value;
	char replace_value[ASN_STRING_MAX_SIZE * 2];
	int ret;

	if (configured_asn_str &&
	    !asn_str2asn(configured_asn_str, &as_configured_value)) {
		vty_out(vty, "%% Invalid AS configured value %s\n",
			configured_asn_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	str = argv_concat(argv, argc, 3);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(replace_value, sizeof(replace_value), "%s %s", aspath_filter_name, str);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:replace-as-path", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, str);

	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, str);
	return ret;
}

DEFPY_YANG(
	no_set_aspath_replace_access_list, no_set_aspath_replace_access_list_cmd,
	"no set as-path replace as-path-access-list [AS_PATH_FILTER_NAME] [<ASNUM>$configured_asn]",
	NO_STR
	SET_STR
	"Transform BGP AS_PATH attribute\n"
	"Replace AS number to local or configured AS number\n"
	"Specify an as path access list name\n"
	"AS path access list name\n"
	"Define the configured AS number\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-replace']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_aspath_prepend,
	    no_set_aspath_prepend_cmd,
	    "no set as-path prepend [ASNUM] [last-as [(1-10)]]",
	    NO_STR
	    SET_STR
	    "Transform BGP AS_PATH attribute\n"
	    "Prepend to the as-path\n"
	    AS_STR
	    "Use the peers AS-number\n"
	    "Number of times to insert\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-prepend']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_aspath_exclude,
	    set_aspath_exclude_cmd,
	    "set as-path exclude ASNUM...",
	    SET_STR
	    "Transform BGP AS-path attribute\n"
	    "Exclude from the as-path\n"
	    AS_STR)
{
	int idx_asn = 3;
	int ret;
	char *str;
	struct aspath *aspath;

	str = argv_concat(argv, argc, idx_asn);

	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-exclude']";
	char xpath_value[XPATH_MAXLEN];

	aspath = route_aspath_compile(str);
	if (!aspath) {
		vty_out(vty, "%% Invalid AS path value %s\n", str);
		return CMD_WARNING_CONFIG_FAILED;
	}
	route_aspath_free(aspath);
	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:exclude-as-path", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, str);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, str);
	return ret;
}

DEFPY_YANG(set_aspath_exclude_all, set_aspath_exclude_all_cmd,
	   "[no$no] set as-path exclude all$all",
	   NO_STR SET_STR
	   "Transform BGP AS-path attribute\n"
	   "Exclude from the as-path\n"
	   "Exclude all AS numbers from the as-path\n")
{
	int ret;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-exclude']";
	char xpath_value[XPATH_MAXLEN];

	if (no)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		snprintf(xpath_value, sizeof(xpath_value),
			 "%s/rmap-set-action/frr-bgp-route-map:exclude-as-path",
			 xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, all);
	}
	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFUN_YANG (no_set_aspath_exclude,
	    no_set_aspath_exclude_cmd,
	    "no set as-path exclude ASNUM...",
	    NO_STR
	    SET_STR
	    "Transform BGP AS_PATH attribute\n"
	    "Exclude from the as-path\n"
	    "AS number\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-exclude']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(set_aspath_exclude_access_list, set_aspath_exclude_access_list_cmd,
	   "set as-path exclude as-path-access-list AS_PATH_FILTER_NAME",
	   SET_STR
	   "Transform BGP AS-path attribute\n"
	   "Exclude from the as-path\n"
	   "Specify an as path access list name\n"
	   "AS path access list name\n")
{
	char *str;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-exclude']";
	char xpath_value[XPATH_MAXLEN];
	int ret;

	str = argv_concat(argv, argc, 3);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:exclude-as-path", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, str);

	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, str);
	return ret;
}

DEFPY_YANG(no_set_aspath_exclude_access_list, no_set_aspath_exclude_access_list_cmd,
	   "no set as-path exclude as-path-access-list [AS_PATH_FILTER_NAME]",
	   NO_STR
	   SET_STR
	   "Transform BGP AS_PATH attribute\n"
	   "Exclude from the as-path\n"
	   "Specify an as path access list name\n"
	   "AS path access list name\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:as-path-exclude']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (no_set_aspath_exclude, no_set_aspath_exclude_all_cmd,
            "no set as-path exclude",
            NO_STR SET_STR
            "Transform BGP AS_PATH attribute\n"
            "Exclude from the as-path\n")

DEFUN_YANG (set_community,
	    set_community_cmd,
	    "set community AA:NN...",
	    SET_STR
	    "BGP community attribute\n"
	    COMMUNITY_VAL_STR)
{
	int idx_aa_nn = 2;
	int i;
	int first = 0;
	int additive = 0;
	struct buffer *b;
	struct community *com = NULL;
	char *str;
	char *argstr = NULL;
	int ret;

	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-community']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:community-string",
		 xpath);

	b = buffer_new(1024);

	for (i = idx_aa_nn; i < argc; i++) {
		if (strncmp(argv[i]->arg, "additive", strlen(argv[i]->arg))
		    == 0) {
			additive = 1;
			continue;
		}

		if (first)
			buffer_putc(b, ' ');
		else
			first = 1;

		if (strncmp(argv[i]->arg, "local-AS", strlen(argv[i]->arg))
		    == 0) {
			buffer_putstr(b, "local-AS");
			continue;
		}
		if (strncmp(argv[i]->arg, "no-a", strlen("no-a")) == 0
		    && strncmp(argv[i]->arg, "no-advertise",
			       strlen(argv[i]->arg))
			       == 0) {
			buffer_putstr(b, "no-advertise");
			continue;
		}
		if (strncmp(argv[i]->arg, "no-e", strlen("no-e")) == 0
		    && strncmp(argv[i]->arg, "no-export", strlen(argv[i]->arg))
			       == 0) {
			buffer_putstr(b, "no-export");
			continue;
		}
		if (strncmp(argv[i]->arg, "blackhole", strlen(argv[i]->arg))
		    == 0) {
			buffer_putstr(b, "blackhole");
			continue;
		}
		if (strncmp(argv[i]->arg, "graceful-shutdown",
			    strlen(argv[i]->arg))
		    == 0) {
			buffer_putstr(b, "graceful-shutdown");
			continue;
		}
		buffer_putstr(b, argv[i]->arg);
	}
	buffer_putc(b, '\0');

	/* Fetch result string then compile it to communities attribute.  */
	str = buffer_getstr(b);
	buffer_free(b);

	if (str)
		com = community_str2com(str);

	/* Can't compile user input into communities attribute.  */
	if (!com) {
		vty_out(vty, "%% Malformed communities attribute '%s'\n", str);
		XFREE(MTYPE_TMP, str);
		return CMD_WARNING_CONFIG_FAILED;
	}
	XFREE(MTYPE_TMP, str);

	/* Set communites attribute string.  */
	str = community_str(com, false, false);

	if (additive) {
		size_t argstr_sz = strlen(str) + strlen(" additive") + 1;
		argstr = XCALLOC(MTYPE_TMP, argstr_sz);
		strlcpy(argstr, str, argstr_sz);
		strlcat(argstr, " additive", argstr_sz);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argstr);
	} else
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, str);

	ret = nb_cli_apply_changes(vty, NULL);

	if (argstr)
		XFREE(MTYPE_TMP, argstr);
	community_free(&com);

	return ret;
}

DEFUN_YANG (set_community_none,
	    set_community_none_cmd,
	    "set community none",
	    SET_STR
	    "BGP community attribute\n"
	    "No community attribute\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-community']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:community-none", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_community,
	    no_set_community_cmd,
	    "no set community AA:NN...",
	    NO_STR
	    SET_STR
	    "BGP community attribute\n"
	    COMMUNITY_VAL_STR)
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-community']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (no_set_community,
            no_set_community_short_cmd,
            "no set community",
            NO_STR
            SET_STR
            "BGP community attribute\n")

DEFPY_YANG (set_community_delete,
       set_community_delete_cmd,
       "set comm-list <(1-99)|(100-500)|COMMUNITY_LIST_NAME> delete",
       SET_STR
       "set BGP community list (for deletion)\n"
       "Community-list number (standard)\n"
       "Community-list number (expanded)\n"
       "Community-list name\n"
       "Delete matching communities\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:comm-list-delete']";
	char xpath_value[XPATH_MAXLEN];
	int idx_comm_list = 2;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:comm-list-name",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			argv[idx_comm_list]->arg);

	return nb_cli_apply_changes(vty, NULL);

}

DEFUN_YANG (no_set_community_delete,
	    no_set_community_delete_cmd,
	    "no set comm-list [<(1-99)|(100-500)|COMMUNITY_LIST_NAME> delete]",
	    NO_STR
	    SET_STR
	    "set BGP community list (for deletion)\n"
	    "Community-list number (standard)\n"
	    "Community-list number (expanded)\n"
	    "Community-list name\n"
	    "Delete matching communities\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:comm-list-delete']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_lcommunity,
	    set_lcommunity_cmd,
	    "set large-community AA:BB:CC...",
	    SET_STR
	    "BGP large community attribute\n"
	    "Large Community number in aa:bb:cc format or additive\n")
{
	char *str;
	int ret;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-large-community']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:large-community-string",
		 xpath);
	str = argv_concat(argv, argc, 2);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, str);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, str);
	return ret;
}

DEFUN_YANG (set_lcommunity_none,
	    set_lcommunity_none_cmd,
	    "set large-community none",
	    SET_STR
	    "BGP large community attribute\n"
	    "No large community attribute\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-large-community']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:large-community-none",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_lcommunity,
	    no_set_lcommunity_cmd,
	    "no set large-community none",
	    NO_STR
	    SET_STR
	    "BGP large community attribute\n"
	    "No community attribute\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-large-community']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_lcommunity1,
	    no_set_lcommunity1_cmd,
	    "no set large-community AA:BB:CC...",
	    NO_STR
	    SET_STR
	    "BGP large community attribute\n"
	    "Large community in AA:BB:CC... format or additive\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-large-community']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (no_set_lcommunity1,
            no_set_lcommunity1_short_cmd,
            "no set large-community",
            NO_STR
            SET_STR
            "BGP large community attribute\n")

DEFPY_YANG (set_lcommunity_delete,
       set_lcommunity_delete_cmd,
       "set large-comm-list <(1-99)|(100-500)|LCOMMUNITY_LIST_NAME> delete",
       SET_STR
       "set BGP large community list (for deletion)\n"
       "Large Community-list number (standard)\n"
       "Large Communitly-list number (expanded)\n"
       "Large Community-list name\n"
       "Delete matching large communities\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:large-comm-list-delete']";
	char xpath_value[XPATH_MAXLEN];
	int idx_lcomm_list = 2;

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
			"%s/rmap-set-action/frr-bgp-route-map:comm-list-name",
			xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			argv[idx_lcomm_list]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_lcommunity_delete,
	    no_set_lcommunity_delete_cmd,
	    "no set large-comm-list <(1-99)|(100-500)|LCOMMUNITY_LIST_NAME> [delete]",
	    NO_STR
	    SET_STR
	    "set BGP large community list (for deletion)\n"
	    "Large Community-list number (standard)\n"
	    "Large Communitly-list number (expanded)\n"
	    "Large Community-list name\n"
	    "Delete matching large communities\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:large-comm-list-delete']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (no_set_lcommunity_delete,
            no_set_lcommunity_delete_short_cmd,
            "no set large-comm-list",
            NO_STR
            SET_STR
            "set BGP large community list (for deletion)\n")

DEFUN_YANG (set_ecommunity_rt,
	    set_ecommunity_rt_cmd,
	    "set extcommunity rt ASN:NN_OR_IP-ADDRESS:NN...",
	    SET_STR
	    "BGP extended community attribute\n"
	    "Route Target extended community\n"
	    "VPN extended community\n")
{
	int idx_asn_nn = 3;
	char *str;
	int ret;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-rt']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:extcommunity-rt", xpath);
	str = argv_concat(argv, argc, idx_asn_nn);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, str);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, str);
	return ret;
}

DEFUN_YANG (no_set_ecommunity_rt,
	    no_set_ecommunity_rt_cmd,
	    "no set extcommunity rt ASN:NN_OR_IP-ADDRESS:NN...",
	    NO_STR
	    SET_STR
	    "BGP extended community attribute\n"
	    "Route Target extended community\n"
	    "VPN extended community\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-rt']";
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (no_set_ecommunity_rt,
            no_set_ecommunity_rt_short_cmd,
            "no set extcommunity rt",
            NO_STR
            SET_STR
            "BGP extended community attribute\n"
            "Route Target extended community\n")

DEFUN_YANG (set_ecommunity_soo,
	    set_ecommunity_soo_cmd,
	    "set extcommunity soo ASN:NN_OR_IP-ADDRESS:NN...",
	    SET_STR
	   "BGP extended community attribute\n"
	   "Site-of-Origin extended community\n"
	   "VPN extended community\n")
{
	int idx_asn_nn = 3;
	char *str;
	int ret;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-soo']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:extcommunity-soo",
		 xpath);
	str = argv_concat(argv, argc, idx_asn_nn);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, str);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, str);
	return ret;
}

DEFUN_YANG (no_set_ecommunity_soo,
	    no_set_ecommunity_soo_cmd,
	    "no set extcommunity soo ASN:NN_OR_IP-ADDRESS:NN...",
	    NO_STR
	    SET_STR
	    "BGP extended community attribute\n"
	    "Site-of-Origin extended community\n"
	    "VPN extended community\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-soo']";
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (no_set_ecommunity_soo,
            no_set_ecommunity_soo_short_cmd,
            "no set extcommunity soo",
            NO_STR
            SET_STR
            "GP extended community attribute\n"
            "Site-of-Origin extended community\n")

DEFUN_YANG(set_ecommunity_none, set_ecommunity_none_cmd,
	   "set extcommunity none",
	   SET_STR
	   "BGP extended community attribute\n"
	   "No extended community attribute\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-none']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:extcommunity-none",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG(no_set_ecommunity_none, no_set_ecommunity_none_cmd,
	   "no set extcommunity none",
	   NO_STR SET_STR
	   "BGP extended community attribute\n"
	   "No extended community attribute\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-none']";
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_ecommunity_lb,
	    set_ecommunity_lb_cmd,
	    "set extcommunity bandwidth <(1-25600)|cumulative|num-multipaths> [non-transitive]",
	    SET_STR
	    "BGP extended community attribute\n"
	    "Link bandwidth extended community\n"
	    "Bandwidth value in Mbps\n"
	    "Cumulative bandwidth of all multipaths (outbound-only)\n"
	    "Internally computed bandwidth based on number of multipaths (outbound-only)\n"
	    "Attribute is set as non-transitive\n")
{
	int idx_lb = 3;
	int idx_non_transitive = 0;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-lb']";
	char xpath_lb_type[XPATH_MAXLEN];
	char xpath_bandwidth[XPATH_MAXLEN];
	char xpath_non_transitive[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_lb_type, sizeof(xpath_lb_type),
		 "%s/rmap-set-action/frr-bgp-route-map:extcommunity-lb/lb-type",
		 xpath);
	snprintf(xpath_bandwidth, sizeof(xpath_bandwidth),
		 "%s/rmap-set-action/frr-bgp-route-map:extcommunity-lb/bandwidth",
		 xpath);
	snprintf(xpath_non_transitive, sizeof(xpath_non_transitive),
		 "%s/rmap-set-action/frr-bgp-route-map:extcommunity-lb/two-octet-as-specific",
		 xpath);

	if ((strcmp(argv[idx_lb]->arg, "cumulative")) == 0)
		nb_cli_enqueue_change(vty, xpath_lb_type, NB_OP_MODIFY,
				      "cumulative-bandwidth");
	else if ((strcmp(argv[idx_lb]->arg, "num-multipaths")) == 0)
		nb_cli_enqueue_change(vty, xpath_lb_type, NB_OP_MODIFY,
				      "computed-bandwidth");
	else {
		nb_cli_enqueue_change(vty, xpath_lb_type, NB_OP_MODIFY,
				      "explicit-bandwidth");
		nb_cli_enqueue_change(vty, xpath_bandwidth, NB_OP_MODIFY,
				      argv[idx_lb]->arg);
	}

	if (argv_find(argv, argc, "non-transitive", &idx_non_transitive))
		nb_cli_enqueue_change(vty, xpath_non_transitive, NB_OP_MODIFY,
				      "true");
	else
		nb_cli_enqueue_change(vty, xpath_non_transitive, NB_OP_MODIFY,
				      "false");

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_ecommunity_lb,
	    no_set_ecommunity_lb_cmd,
	    "no set extcommunity bandwidth <(1-25600)|cumulative|num-multipaths> [non-transitive]",
	    NO_STR
	    SET_STR
	    "BGP extended community attribute\n"
	    "Link bandwidth extended community\n"
	    "Bandwidth value in Mbps\n"
	    "Cumulative bandwidth of all multipaths (outbound-only)\n"
	    "Internally computed bandwidth based on number of multipaths (outbound-only)\n"
	    "Attribute is set as non-transitive\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-lb']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (no_set_ecommunity_lb,
            no_set_ecommunity_lb_short_cmd,
            "no set extcommunity bandwidth",
            NO_STR
            SET_STR
            "BGP extended community attribute\n"
            "Link bandwidth extended community\n")

DEFPY_YANG (set_ecommunity_nt,
	    set_ecommunity_nt_cmd,
	    "set extcommunity nt RTLIST...",
	    SET_STR
	    "BGP extended community attribute\n"
	    "Node Target extended community\n"
	    "Node Target ID\n")
{
	int idx_nt = 3;
	char *str;
	int ret;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-nt']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:extcommunity-nt", xpath);
	str = argv_concat(argv, argc, idx_nt);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, str);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, str);
	return ret;
}

DEFPY_YANG (no_set_ecommunity_nt,
	    no_set_ecommunity_nt_cmd,
	    "no set extcommunity nt RTLIST...",
	    NO_STR
	    SET_STR
	    "BGP extended community attribute\n"
	    "Node Target extended community\n"
	    "Node Target ID\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-nt']";
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(set_ecommunity_color, set_ecommunity_color_cmd,
	   "set extcommunity color RTLIST...",
	   SET_STR
	   "BGP extended community attribute\n"
	   "Color extended community\n"
	   "Color ID\n")
{
	int idx_color = 3;
	char *str;
	int ret;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-color']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:extcommunity-color",
		 xpath);
	str = argv_concat(argv, argc, idx_color);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, str);
	ret = nb_cli_apply_changes(vty, NULL);
	XFREE(MTYPE_TMP, str);
	return ret;
}

DEFPY_YANG(no_set_ecommunity_color_all, no_set_ecommunity_color_all_cmd,
	   "no set extcommunity color",
	   NO_STR SET_STR
	   "BGP extended community attribute\n"
	   "Color extended community\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-color']";
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_set_ecommunity_color, no_set_ecommunity_color_cmd,
	   "no set extcommunity color RTLIST...",
	   NO_STR SET_STR
	   "BGP extended community attribute\n"
	   "Color extended community\n"
	   "Color ID\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-extcommunity-color']";
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_YANG (no_set_ecommunity_nt,
            no_set_ecommunity_nt_short_cmd,
            "no set extcommunity nt",
            NO_STR
            SET_STR
            "BGP extended community attribute\n"
            "Node Target extended community\n")

DEFUN_YANG (set_origin,
	    set_origin_cmd,
	    "set origin <egp|igp|incomplete>",
	    SET_STR
	    "BGP origin code\n"
	    "remote EGP\n"
	    "local IGP\n"
	    "unknown heritage\n")
{
	int idx_origin = 2;
	const char *origin_type;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-origin']";
	char xpath_value[XPATH_MAXLEN];

	if (strncmp(argv[idx_origin]->arg, "igp", 2) == 0)
		origin_type = "igp";
	else if (strncmp(argv[idx_origin]->arg, "egp", 1) == 0)
		origin_type = "egp";
	else if (strncmp(argv[idx_origin]->arg, "incomplete", 2) == 0)
		origin_type = "incomplete";
	else {
		vty_out(vty, "%% Invalid match origin type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:origin", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, origin_type);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_origin,
	    no_set_origin_cmd,
	    "no set origin [<egp|igp|incomplete>]",
	    NO_STR
	    SET_STR
	    "BGP origin code\n"
	    "remote EGP\n"
	    "local IGP\n"
	    "unknown heritage\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:set-origin']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_atomic_aggregate,
	    set_atomic_aggregate_cmd,
	    "set atomic-aggregate",
	    SET_STR
	    "BGP atomic aggregate attribute\n" )
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:atomic-aggregate']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:atomic-aggregate",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_atomic_aggregate,
	    no_set_atomic_aggregate_cmd,
	    "no set atomic-aggregate",
	    NO_STR
	    SET_STR
	    "BGP atomic aggregate attribute\n" )
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:atomic-aggregate']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (set_aigp_metric,
	    set_aigp_metric_cmd,
	    "set aigp-metric <igp-metric|(1-4294967295)>$aigp_metric",
	    SET_STR
	    "BGP AIGP attribute (AIGP Metric TLV)\n"
	    "AIGP Metric value from IGP protocol\n"
	    "Manual AIGP Metric value\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:aigp-metric']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:aigp-metric", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, aigp_metric);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_set_aigp_metric,
	    no_set_aigp_metric_cmd,
	    "no set aigp-metric [<igp-metric|(1-4294967295)>]",
	    NO_STR
	    SET_STR
	    "BGP AIGP attribute (AIGP Metric TLV)\n"
	    "AIGP Metric value from IGP protocol\n"
	    "Manual AIGP Metric value\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:aigp-metric']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_aggregator_as,
	    set_aggregator_as_cmd,
	    "set aggregator as ASNUM A.B.C.D",
	    SET_STR
	    "BGP aggregator attribute\n"
	    "AS number of aggregator\n"
	    AS_STR
	    "IP address of aggregator\n")
{
	int idx_number = 3;
	int idx_ipv4 = 4;
	char xpath_asn[XPATH_MAXLEN];
	char xpath_addr[XPATH_MAXLEN];
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:aggregator']";
	as_t as_value;

	if (!asn_str2asn(argv[idx_number]->arg, &as_value)) {
		vty_out(vty, "%% Invalid AS value %s\n", argv[idx_number]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(
		xpath_asn, sizeof(xpath_asn),
		"%s/rmap-set-action/frr-bgp-route-map:aggregator/aggregator-asn",
		xpath);
	nb_cli_enqueue_change(vty, xpath_asn, NB_OP_MODIFY,
			      argv[idx_number]->arg);

	snprintf(
		xpath_addr, sizeof(xpath_addr),
		"%s/rmap-set-action/frr-bgp-route-map:aggregator/aggregator-address",
		xpath);
	nb_cli_enqueue_change(vty, xpath_addr, NB_OP_MODIFY,
			      argv[idx_ipv4]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_aggregator_as,
	    no_set_aggregator_as_cmd,
	    "no set aggregator as [ASNUM A.B.C.D]",
	    NO_STR
	    SET_STR
	    "BGP aggregator attribute\n"
	    "AS number of aggregator\n"
	    AS_STR
	    "IP address of aggregator\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:aggregator']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (match_ipv6_next_hop,
	    match_ipv6_next_hop_cmd,
	    "match ipv6 next-hop ACCESSLIST6_NAME",
	    MATCH_STR
	    IPV6_STR
	    "Match IPv6 next-hop address of route\n"
	    "IPv6 access-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv6-next-hop-list']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[argc - 1]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_ipv6_next_hop,
	    no_match_ipv6_next_hop_cmd,
	    "no match ipv6 next-hop [ACCESSLIST6_NAME]",
	    NO_STR
	    MATCH_STR
	    IPV6_STR
	    "Match IPv6 next-hop address of route\n"
	    "IPv6 access-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv6-next-hop-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (match_ipv6_next_hop_address,
	    match_ipv6_next_hop_address_cmd,
	    "match ipv6 next-hop address X:X::X:X",
	    MATCH_STR
	    IPV6_STR
	    "Match IPv6 next-hop address of route\n"
	    "IPv6 address\n"
	    "IPv6 address of next hop\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:ipv6-nexthop']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:ipv6-address",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[argc - 1]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_ipv6_next_hop_address,
	    no_match_ipv6_next_hop_address_cmd,
	    "no match ipv6 next-hop address X:X::X:X",
	    NO_STR
	    MATCH_STR
	    IPV6_STR
	    "Match IPv6 next-hop address of route\n"
	    "IPv6 address\n"
	    "IPv6 address of next hop\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:ipv6-nexthop']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

ALIAS_HIDDEN (match_ipv6_next_hop_address,
	      match_ipv6_next_hop_old_cmd,
	      "match ipv6 next-hop X:X::X:X",
	      MATCH_STR
	      IPV6_STR
	      "Match IPv6 next-hop address of route\n"
	      "IPv6 address of next hop\n")

ALIAS_HIDDEN (no_match_ipv6_next_hop_address,
	      no_match_ipv6_next_hop_old_cmd,
	      "no match ipv6 next-hop X:X::X:X",
	      NO_STR
	      MATCH_STR
	      IPV6_STR
	      "Match IPv6 next-hop address of route\n"
	      "IPv6 address of next hop\n")

DEFUN_YANG (match_ipv6_next_hop_prefix_list,
	    match_ipv6_next_hop_prefix_list_cmd,
	    "match ipv6 next-hop prefix-list PREFIXLIST_NAME",
	    MATCH_STR
	    IPV6_STR
	    "Match IPv6 next-hop address of route\n"
	    "Match entries by prefix-list\n"
	    "IPv6 prefix-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv6-next-hop-prefix-list']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/list-name", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[argc - 1]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_match_ipv6_next_hop_prefix_list,
	    no_match_ipv6_next_hop_prefix_list_cmd,
	    "no match ipv6 next-hop prefix-list [PREFIXLIST_NAME]",
	    NO_STR
	    MATCH_STR
	    IPV6_STR
	    "Match IPv6 next-hop address of route\n"
	    "Match entries by prefix-list\n"
	    "IPv6 prefix-list name\n")
{
	const char *xpath =
		"./match-condition[condition='frr-route-map:ipv6-next-hop-prefix-list']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (match_ipv4_next_hop,
       match_ipv4_next_hop_cmd,
       "match ip next-hop address A.B.C.D",
       MATCH_STR
       IP_STR
       "Match IP next-hop address of route\n"
       "IP address\n"
       "IP address of next-hop\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:ipv4-nexthop']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:ipv4-address",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, argv[4]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_match_ipv4_next_hop,
       no_match_ipv4_next_hop_cmd,
       "no match ip next-hop address [A.B.C.D]",
       NO_STR
       MATCH_STR
       IP_STR
       "Match IP next-hop address of route\n"
       "IP address\n"
       "IP address of next-hop\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:ipv4-nexthop']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_ipv6_nexthop_peer,
	    set_ipv6_nexthop_peer_cmd,
	    "set ipv6 next-hop peer-address",
	    SET_STR
	    IPV6_STR
	    "Next hop address\n"
	    "Use peer address (for BGP only)\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:ipv6-peer-address']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:preference", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_ipv6_nexthop_peer,
	    no_set_ipv6_nexthop_peer_cmd,
	    "no set ipv6 next-hop peer-address",
	    NO_STR
	    SET_STR
	    IPV6_STR
	    "IPv6 next-hop address\n"
	    "Use peer address (for BGP only)\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:ipv6-peer-address']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_ipv6_nexthop_prefer_global,
	    set_ipv6_nexthop_prefer_global_cmd,
	    "set ipv6 next-hop prefer-global",
	    SET_STR
	    IPV6_STR
	    "IPv6 next-hop address\n"
	    "Prefer global over link-local if both exist\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:ipv6-prefer-global']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:preference", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, "true");

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_ipv6_nexthop_prefer_global,
	    no_set_ipv6_nexthop_prefer_global_cmd,
	    "no set ipv6 next-hop prefer-global",
	    NO_STR
	    SET_STR
	    IPV6_STR
	    "IPv6 next-hop address\n"
	    "Prefer global over link-local if both exist\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:ipv6-prefer-global']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (set_ipv6_nexthop_global,
	    set_ipv6_nexthop_global_cmd,
	    "set ipv6 next-hop global X:X::X:X",
	    SET_STR
	    IPV6_STR
	    "IPv6 next-hop address\n"
	    "IPv6 global address\n"
	    "IPv6 address of next hop\n")
{
	int idx_ipv6 = 4;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:ipv6-nexthop-global']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:ipv6-address", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_ipv6]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_ipv6_nexthop_global,
	    no_set_ipv6_nexthop_global_cmd,
	    "no set ipv6 next-hop global X:X::X:X",
	    NO_STR
	    SET_STR
	    IPV6_STR
	    "IPv6 next-hop address\n"
	    "IPv6 global address\n"
	    "IPv6 address of next hop\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:ipv6-nexthop-global']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

#ifdef KEEP_OLD_VPN_COMMANDS
DEFUN_YANG (set_vpn_nexthop,
	    set_vpn_nexthop_cmd,
	    "set <vpnv4 next-hop A.B.C.D|vpnv6 next-hop X:X::X:X>",
	    SET_STR
	    "VPNv4 information\n"
	    "VPN next-hop address\n"
	    "IP address of next hop\n"
	    "VPNv6 information\n"
	    "VPN next-hop address\n"
	    "IPv6 address of next hop\n")
{
	int idx_ip = 3;
	afi_t afi;
	int idx = 0;
	char xpath_value[XPATH_MAXLEN];

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
		if (afi == AFI_IP) {
			const char *xpath =
				"./set-action[action='frr-bgp-route-map:ipv4-vpn-address']";

			nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
			snprintf(
				xpath_value, sizeof(xpath_value),
				"%s/rmap-set-action/frr-bgp-route-map:ipv4-address",
				xpath);
		} else {
			const char *xpath =
				"./set-action[action='frr-bgp-route-map:ipv6-vpn-address']";

			nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
			snprintf(
				xpath_value, sizeof(xpath_value),
				"%s/rmap-set-action/frr-bgp-route-map:ipv6-address",
				xpath);
		}

		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
				argv[idx_ip]->arg);

		return nb_cli_apply_changes(vty, NULL);
	}

	return CMD_SUCCESS;
}

DEFUN_YANG (no_set_vpn_nexthop,
	   no_set_vpn_nexthop_cmd,
	   "no set <vpnv4 next-hop A.B.C.D|vpnv6 next-hop X:X::X:X>",
	   NO_STR
	   SET_STR
	   "VPNv4 information\n"
	   "VPN next-hop address\n"
	   "IP address of next hop\n"
	   "VPNv6 information\n"
	   "VPN next-hop address\n"
	   "IPv6 address of next hop\n")
{
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
		if (afi == AFI_IP) {
			const char *xpath =
				"./set-action[action='frr-bgp-route-map:ipv4-vpn-address']";
			nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		} else {
			const char *xpath =
				"./set-action[action='frr-bgp-route-map:ipv6-vpn-address']";
			nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		}
		return nb_cli_apply_changes(vty, NULL);
	}
	return CMD_SUCCESS;
}
#endif /* KEEP_OLD_VPN_COMMANDS */

DEFPY_YANG (set_ipx_vpn_nexthop,
	    set_ipx_vpn_nexthop_cmd,
	    "set <ipv4|ipv6> vpn next-hop <A.B.C.D$addrv4|X:X::X:X$addrv6>",
	    SET_STR
	    "IPv4 information\n"
	    "IPv6 information\n"
	    "VPN information\n"
	    "VPN next-hop address\n"
	    "IP address of next hop\n"
	    "IPv6 address of next hop\n")
{
	int idx_ip = 4;
	afi_t afi;
	int idx = 0;
	char xpath_value[XPATH_MAXLEN];

	if (argv_find_and_parse_afi(argv, argc, &idx, &afi)) {
		if (afi == AFI_IP) {
			if (addrv6_str) {
				vty_out(vty, "%% IPv4 next-hop expected\n");
				return CMD_WARNING_CONFIG_FAILED;
			}

			const char *xpath =
				"./set-action[action='frr-bgp-route-map:ipv4-vpn-address']";

			nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
			snprintf(
				xpath_value, sizeof(xpath_value),
				"%s/rmap-set-action/frr-bgp-route-map:ipv4-address",
				xpath);
		} else {
			if (addrv4_str) {
				vty_out(vty, "%% IPv6 next-hop expected\n");
				return CMD_WARNING_CONFIG_FAILED;
			}

			const char *xpath =
				"./set-action[action='frr-bgp-route-map:ipv6-vpn-address']";

			nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
			snprintf(
				xpath_value, sizeof(xpath_value),
				"%s/rmap-set-action/frr-bgp-route-map:ipv6-address",
				xpath);
		}
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
				      argv[idx_ip]->arg);
		return nb_cli_apply_changes(vty, NULL);
	}
	return CMD_SUCCESS;
}

DEFUN_YANG (no_set_ipx_vpn_nexthop,
	    no_set_ipx_vpn_nexthop_cmd,
	    "no set <ipv4|ipv6> vpn next-hop [<A.B.C.D|X:X::X:X>]",
	    NO_STR
	    SET_STR
	    "IPv4 information\n"
	    "IPv6 information\n"
	    "VPN information\n"
	    "VPN next-hop address\n"
	    "IP address of next hop\n"
	    "IPv6 address of next hop\n")
{
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_afi(argv, argc, &idx, &afi)) {
		if (afi == AFI_IP) {
			const char *xpath =
				"./set-action[action='frr-bgp-route-map:ipv4-vpn-address']";
			nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		} else {
			const char *xpath =
				"./set-action[action='frr-bgp-route-map:ipv6-vpn-address']";
			nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
		}
		return nb_cli_apply_changes(vty, NULL);
	}
	return CMD_SUCCESS;
}

DEFUN_YANG (set_originator_id,
	    set_originator_id_cmd,
	    "set originator-id A.B.C.D",
	    SET_STR
	   "BGP originator ID attribute\n"
	   "IP address of originator\n")
{
	int idx_ipv4 = 2;
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:originator-id']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-bgp-route-map:originator-id", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
			      argv[idx_ipv4]->arg);

	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_originator_id,
	    no_set_originator_id_cmd,
	    "no set originator-id [A.B.C.D]",
	    NO_STR
	    SET_STR
	    "BGP originator ID attribute\n"
	    "IP address of originator\n")
{
	const char *xpath =
		"./set-action[action='frr-bgp-route-map:originator-id']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (match_rpki_extcommunity,
       match_rpki_extcommunity_cmd,
       "[no$no] match rpki-extcommunity <valid|invalid|notfound>",
       NO_STR
       MATCH_STR
       "BGP RPKI (Origin Validation State) extended community attribute\n"
       "Valid prefix\n"
       "Invalid prefix\n"
       "Prefix not found\n")
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:rpki-extcommunity']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	if (!no) {
		snprintf(
			xpath_value, sizeof(xpath_value),
			"%s/rmap-match-condition/frr-bgp-route-map:rpki-extcommunity",
			xpath);
		nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY,
				      argv[2]->arg);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (match_source_protocol,
            match_source_protocol_cmd,
	    "match source-protocol " FRR_REDIST_STR_ZEBRA "$proto",
	    MATCH_STR
	    "Match protocol via which the route was learnt\n"
	    FRR_REDIST_HELP_STR_ZEBRA)
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:source-protocol']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-match-condition/frr-bgp-route-map:source-protocol",
		 xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, proto);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_match_source_protocol,
            no_match_source_protocol_cmd,
	    "no match source-protocol [" FRR_REDIST_STR_ZEBRA "]",
	    NO_STR
	    MATCH_STR
	    "Match protocol via which the route was learnt\n"
	    FRR_REDIST_HELP_STR_ZEBRA)
{
	const char *xpath =
		"./match-condition[condition='frr-bgp-route-map:source-protocol']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/* Initialization of route map. */
void bgp_route_map_init(void)
{
	route_map_init();

	route_map_add_hook(bgp_route_map_add);
	route_map_delete_hook(bgp_route_map_delete);
	route_map_event_hook(bgp_route_map_event);

	route_map_match_interface_hook(generic_match_add);
	route_map_no_match_interface_hook(generic_match_delete);

	route_map_match_ip_address_hook(generic_match_add);
	route_map_no_match_ip_address_hook(generic_match_delete);

	route_map_match_ip_address_prefix_list_hook(generic_match_add);
	route_map_no_match_ip_address_prefix_list_hook(generic_match_delete);

	route_map_match_ip_next_hop_hook(generic_match_add);
	route_map_no_match_ip_next_hop_hook(generic_match_delete);

	route_map_match_ipv6_next_hop_hook(generic_match_add);
	route_map_no_match_ipv6_next_hop_hook(generic_match_delete);

	route_map_match_ip_next_hop_prefix_list_hook(generic_match_add);
	route_map_no_match_ip_next_hop_prefix_list_hook(generic_match_delete);

	route_map_match_ip_next_hop_type_hook(generic_match_add);
	route_map_no_match_ip_next_hop_type_hook(generic_match_delete);

	route_map_match_ipv6_address_hook(generic_match_add);
	route_map_no_match_ipv6_address_hook(generic_match_delete);

	route_map_match_ipv6_address_prefix_list_hook(generic_match_add);
	route_map_no_match_ipv6_address_prefix_list_hook(generic_match_delete);

	route_map_match_ipv6_next_hop_type_hook(generic_match_add);
	route_map_no_match_ipv6_next_hop_type_hook(generic_match_delete);

	route_map_match_ipv6_next_hop_prefix_list_hook(generic_match_add);
	route_map_no_match_ipv6_next_hop_prefix_list_hook(generic_match_delete);

	route_map_match_metric_hook(generic_match_add);
	route_map_no_match_metric_hook(generic_match_delete);

	route_map_match_tag_hook(generic_match_add);
	route_map_no_match_tag_hook(generic_match_delete);

	route_map_set_srte_color_hook(generic_set_add);
	route_map_no_set_srte_color_hook(generic_set_delete);

	route_map_set_ip_nexthop_hook(generic_set_add);
	route_map_no_set_ip_nexthop_hook(generic_set_delete);

	route_map_set_ipv6_nexthop_local_hook(generic_set_add);
	route_map_no_set_ipv6_nexthop_local_hook(generic_set_delete);

	route_map_set_metric_hook(generic_set_add);
	route_map_no_set_metric_hook(generic_set_delete);

	route_map_set_tag_hook(generic_set_add);
	route_map_no_set_tag_hook(generic_set_delete);

	route_map_install_match(&route_match_peer_cmd);
	route_map_install_match(&route_match_alias_cmd);
	route_map_install_match(&route_match_local_pref_cmd);
#ifdef HAVE_SCRIPTING
	route_map_install_match(&route_match_script_cmd);
#endif
	route_map_install_match(&route_match_ip_address_cmd);
	route_map_install_match(&route_match_ip_next_hop_cmd);
	route_map_install_match(&route_match_ip_route_source_cmd);
	route_map_install_match(&route_match_ip_address_prefix_list_cmd);
	route_map_install_match(&route_match_ip_next_hop_prefix_list_cmd);
	route_map_install_match(&route_match_ip_next_hop_type_cmd);
	route_map_install_match(&route_match_source_protocol_cmd);
	route_map_install_match(&route_match_ip_route_source_prefix_list_cmd);
	route_map_install_match(&route_match_aspath_cmd);
	route_map_install_match(&route_match_community_cmd);
	route_map_install_match(&route_match_lcommunity_cmd);
	route_map_install_match(&route_match_ecommunity_cmd);
	route_map_install_match(&route_match_local_pref_cmd);
	route_map_install_match(&route_match_metric_cmd);
	route_map_install_match(&route_match_origin_cmd);
	route_map_install_match(&route_match_probability_cmd);
	route_map_install_match(&route_match_interface_cmd);
	route_map_install_match(&route_match_tag_cmd);
	route_map_install_match(&route_match_mac_address_cmd);
	route_map_install_match(&route_match_evpn_vni_cmd);
	route_map_install_match(&route_match_evpn_route_type_cmd);
	route_map_install_match(&route_match_evpn_rd_cmd);
	route_map_install_match(&route_match_evpn_default_route_cmd);
	route_map_install_match(&route_match_vrl_source_vrf_cmd);

	route_map_install_set(&route_set_evpn_gateway_ip_ipv4_cmd);
	route_map_install_set(&route_set_evpn_gateway_ip_ipv6_cmd);
	route_map_install_set(&route_set_table_id_cmd);
	route_map_install_set(&route_set_srte_color_cmd);
	route_map_install_set(&route_set_ip_nexthop_cmd);
	route_map_install_set(&route_set_local_pref_cmd);
	route_map_install_set(&route_set_weight_cmd);
	route_map_install_set(&route_set_label_index_cmd);
	route_map_install_set(&route_set_metric_cmd);
	route_map_install_set(&route_set_distance_cmd);
	route_map_install_set(&route_set_aspath_prepend_cmd);
	route_map_install_set(&route_set_aspath_exclude_cmd);
	route_map_install_set(&route_set_aspath_replace_cmd);
	route_map_install_set(&route_set_origin_cmd);
	route_map_install_set(&route_set_atomic_aggregate_cmd);
	route_map_install_set(&route_set_aigp_metric_cmd);
	route_map_install_set(&route_set_aggregator_as_cmd);
	route_map_install_set(&route_set_community_cmd);
	route_map_install_set(&route_set_community_delete_cmd);
	route_map_install_set(&route_set_ecommunity_delete_cmd);
	route_map_install_set(&route_set_lcommunity_cmd);
	route_map_install_set(&route_set_lcommunity_delete_cmd);
	route_map_install_set(&route_set_vpnv4_nexthop_cmd);
	route_map_install_set(&route_set_vpnv6_nexthop_cmd);
	route_map_install_set(&route_set_originator_id_cmd);
	route_map_install_set(&route_set_ecommunity_rt_cmd);
	route_map_install_set(&route_set_ecommunity_nt_cmd);
	route_map_install_set(&route_set_ecommunity_soo_cmd);
	route_map_install_set(&route_set_ecommunity_lb_cmd);
	route_map_install_set(&route_set_ecommunity_color_cmd);
	route_map_install_set(&route_set_ecommunity_none_cmd);
	route_map_install_set(&route_set_tag_cmd);
	route_map_install_set(&route_set_label_index_cmd);
	route_map_install_set(&route_set_l3vpn_nexthop_encapsulation_cmd);

	install_element(RMAP_NODE, &match_peer_cmd);
	install_element(RMAP_NODE, &match_peer_local_cmd);
	install_element(RMAP_NODE, &no_match_peer_cmd);
	install_element(RMAP_NODE, &match_ip_route_source_cmd);
	install_element(RMAP_NODE, &no_match_ip_route_source_cmd);
	install_element(RMAP_NODE, &match_ip_route_source_prefix_list_cmd);
	install_element(RMAP_NODE, &no_match_ip_route_source_prefix_list_cmd);
	install_element(RMAP_NODE, &match_mac_address_cmd);
	install_element(RMAP_NODE, &no_match_mac_address_cmd);
	install_element(RMAP_NODE, &match_evpn_vni_cmd);
	install_element(RMAP_NODE, &no_match_evpn_vni_cmd);
	install_element(RMAP_NODE, &match_evpn_route_type_cmd);
	install_element(RMAP_NODE, &no_match_evpn_route_type_cmd);
	install_element(RMAP_NODE, &match_evpn_rd_cmd);
	install_element(RMAP_NODE, &no_match_evpn_rd_cmd);
	install_element(RMAP_NODE, &match_evpn_default_route_cmd);
	install_element(RMAP_NODE, &no_match_evpn_default_route_cmd);
	install_element(RMAP_NODE, &set_evpn_gw_ip_ipv4_cmd);
	install_element(RMAP_NODE, &no_set_evpn_gw_ip_ipv4_cmd);
	install_element(RMAP_NODE, &set_evpn_gw_ip_ipv6_cmd);
	install_element(RMAP_NODE, &no_set_evpn_gw_ip_ipv6_cmd);
	install_element(RMAP_NODE, &match_vrl_source_vrf_cmd);
	install_element(RMAP_NODE, &no_match_vrl_source_vrf_cmd);

	install_element(RMAP_NODE, &match_aspath_cmd);
	install_element(RMAP_NODE, &no_match_aspath_cmd);
	install_element(RMAP_NODE, &match_local_pref_cmd);
	install_element(RMAP_NODE, &no_match_local_pref_cmd);
	install_element(RMAP_NODE, &match_alias_cmd);
	install_element(RMAP_NODE, &no_match_alias_cmd);
	install_element(RMAP_NODE, &match_community_cmd);
	install_element(RMAP_NODE, &no_match_community_cmd);
	install_element(RMAP_NODE, &match_lcommunity_cmd);
	install_element(RMAP_NODE, &no_match_lcommunity_cmd);
	install_element(RMAP_NODE, &match_ecommunity_cmd);
	install_element(RMAP_NODE, &no_match_ecommunity_cmd);
	install_element(RMAP_NODE, &match_origin_cmd);
	install_element(RMAP_NODE, &no_match_origin_cmd);
	install_element(RMAP_NODE, &match_probability_cmd);
	install_element(RMAP_NODE, &no_match_probability_cmd);

	install_element(RMAP_NODE, &no_set_table_id_cmd);
	install_element(RMAP_NODE, &set_table_id_cmd);
	install_element(RMAP_NODE, &set_ip_nexthop_peer_cmd);
	install_element(RMAP_NODE, &set_ip_nexthop_unchanged_cmd);
	install_element(RMAP_NODE, &set_local_pref_cmd);
	install_element(RMAP_NODE, &set_distance_cmd);
	install_element(RMAP_NODE, &no_set_distance_cmd);
	install_element(RMAP_NODE, &no_set_local_pref_cmd);
	install_element(RMAP_NODE, &set_weight_cmd);
	install_element(RMAP_NODE, &set_label_index_cmd);
	install_element(RMAP_NODE, &no_set_weight_cmd);
	install_element(RMAP_NODE, &no_set_label_index_cmd);
	install_element(RMAP_NODE, &set_aspath_prepend_asn_cmd);
	install_element(RMAP_NODE, &set_aspath_prepend_lastas_cmd);
	install_element(RMAP_NODE, &set_aspath_exclude_cmd);
	install_element(RMAP_NODE, &set_aspath_exclude_all_cmd);
	install_element(RMAP_NODE, &set_aspath_exclude_access_list_cmd);
	install_element(RMAP_NODE, &set_aspath_replace_asn_cmd);
	install_element(RMAP_NODE, &set_aspath_replace_access_list_cmd);
	install_element(RMAP_NODE, &no_set_aspath_prepend_cmd);
	install_element(RMAP_NODE, &no_set_aspath_exclude_cmd);
	install_element(RMAP_NODE, &no_set_aspath_exclude_all_cmd);
	install_element(RMAP_NODE, &no_set_aspath_exclude_access_list_cmd);
	install_element(RMAP_NODE, &no_set_aspath_replace_asn_cmd);
	install_element(RMAP_NODE, &no_set_aspath_replace_access_list_cmd);
	install_element(RMAP_NODE, &set_origin_cmd);
	install_element(RMAP_NODE, &no_set_origin_cmd);
	install_element(RMAP_NODE, &set_atomic_aggregate_cmd);
	install_element(RMAP_NODE, &no_set_atomic_aggregate_cmd);
	install_element(RMAP_NODE, &set_aigp_metric_cmd);
	install_element(RMAP_NODE, &no_set_aigp_metric_cmd);
	install_element(RMAP_NODE, &set_aggregator_as_cmd);
	install_element(RMAP_NODE, &no_set_aggregator_as_cmd);
	install_element(RMAP_NODE, &set_community_cmd);
	install_element(RMAP_NODE, &set_community_none_cmd);
	install_element(RMAP_NODE, &no_set_community_cmd);
	install_element(RMAP_NODE, &no_set_community_short_cmd);
	install_element(RMAP_NODE, &set_community_delete_cmd);
	install_element(RMAP_NODE, &no_set_community_delete_cmd);
	install_element(RMAP_NODE, &set_lcommunity_cmd);
	install_element(RMAP_NODE, &set_lcommunity_none_cmd);
	install_element(RMAP_NODE, &no_set_lcommunity_cmd);
	install_element(RMAP_NODE, &no_set_lcommunity1_cmd);
	install_element(RMAP_NODE, &no_set_lcommunity1_short_cmd);
	install_element(RMAP_NODE, &set_lcommunity_delete_cmd);
	install_element(RMAP_NODE, &no_set_lcommunity_delete_cmd);
	install_element(RMAP_NODE, &no_set_lcommunity_delete_short_cmd);
	install_element(RMAP_NODE, &set_ecommunity_rt_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_rt_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_rt_short_cmd);
	install_element(RMAP_NODE, &set_ecommunity_soo_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_soo_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_soo_short_cmd);
	install_element(RMAP_NODE, &set_ecommunity_lb_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_lb_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_lb_short_cmd);
	install_element(RMAP_NODE, &set_ecommunity_none_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_none_cmd);
	install_element(RMAP_NODE, &set_ecommunity_nt_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_nt_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_nt_short_cmd);
	install_element(RMAP_NODE, &set_ecommunity_color_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_color_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_color_all_cmd);
	install_element(RMAP_NODE, &set_ecommunity_delete_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_delete_cmd);
#ifdef KEEP_OLD_VPN_COMMANDS
	install_element(RMAP_NODE, &set_vpn_nexthop_cmd);
	install_element(RMAP_NODE, &no_set_vpn_nexthop_cmd);
#endif /* KEEP_OLD_VPN_COMMANDS */
	install_element(RMAP_NODE, &set_ipx_vpn_nexthop_cmd);
	install_element(RMAP_NODE, &no_set_ipx_vpn_nexthop_cmd);
	install_element(RMAP_NODE, &set_originator_id_cmd);
	install_element(RMAP_NODE, &no_set_originator_id_cmd);
	install_element(RMAP_NODE, &set_l3vpn_nexthop_encapsulation_cmd);

	route_map_install_match(&route_match_ipv6_address_cmd);
	route_map_install_match(&route_match_ipv6_next_hop_cmd);
	route_map_install_match(&route_match_ipv6_next_hop_address_cmd);
	route_map_install_match(&route_match_ipv6_next_hop_prefix_list_cmd);
	route_map_install_match(&route_match_ipv4_next_hop_cmd);
	route_map_install_match(&route_match_ipv6_address_prefix_list_cmd);
	route_map_install_match(&route_match_ipv6_next_hop_type_cmd);
	route_map_install_set(&route_set_ipv6_nexthop_global_cmd);
	route_map_install_set(&route_set_ipv6_nexthop_prefer_global_cmd);
	route_map_install_set(&route_set_ipv6_nexthop_local_cmd);
	route_map_install_set(&route_set_ipv6_nexthop_peer_cmd);
	route_map_install_match(&route_match_rpki_extcommunity_cmd);

	install_element(RMAP_NODE, &match_ipv6_next_hop_cmd);
	install_element(RMAP_NODE, &match_ipv6_next_hop_address_cmd);
	install_element(RMAP_NODE, &match_ipv6_next_hop_prefix_list_cmd);
	install_element(RMAP_NODE, &no_match_ipv6_next_hop_cmd);
	install_element(RMAP_NODE, &no_match_ipv6_next_hop_address_cmd);
	install_element(RMAP_NODE, &no_match_ipv6_next_hop_prefix_list_cmd);
	install_element(RMAP_NODE, &match_ipv6_next_hop_old_cmd);
	install_element(RMAP_NODE, &no_match_ipv6_next_hop_old_cmd);
	install_element(RMAP_NODE, &match_ipv4_next_hop_cmd);
	install_element(RMAP_NODE, &no_match_ipv4_next_hop_cmd);
	install_element(RMAP_NODE, &set_ipv6_nexthop_global_cmd);
	install_element(RMAP_NODE, &no_set_ipv6_nexthop_global_cmd);
	install_element(RMAP_NODE, &set_ipv6_nexthop_prefer_global_cmd);
	install_element(RMAP_NODE, &no_set_ipv6_nexthop_prefer_global_cmd);
	install_element(RMAP_NODE, &set_ipv6_nexthop_peer_cmd);
	install_element(RMAP_NODE, &no_set_ipv6_nexthop_peer_cmd);
	install_element(RMAP_NODE, &match_rpki_extcommunity_cmd);
	install_element(RMAP_NODE, &match_source_protocol_cmd);
	install_element(RMAP_NODE, &no_match_source_protocol_cmd);
#ifdef HAVE_SCRIPTING
	install_element(RMAP_NODE, &match_script_cmd);
#endif
}

void bgp_route_map_terminate(void)
{
	/* ToDo: Cleanup all the used memory */
	route_map_finish();
}
