/* Route map function of bgpd.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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
#ifdef HAVE_LIBPCREPOSIX
#include <pcreposix.h>
#else
#include <regex.h>
#endif /* HAVE_LIBPCREPOSIX */
#include "buffer.h"
#include "sockunion.h"
#include "hash.h"
#include "queue.h"
#include "frrstr.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_community.h"
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

#if ENABLE_BGP_VNC
#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#endif

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
	if (!rv)
		return NULL;

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

	aspath = aspath_str2aspath(arg);
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
    received in bgp_info->peer. If it is the same, or if the peer structure
    received is a peer_group containing it, returns RMAP_MATCH. */
static route_map_result_t route_match_peer(void *rule, struct prefix *prefix,
					   route_map_object_t type,
					   void *object)
{
	struct bgp_match_peer_compiled *pc;
	union sockunion *su;
	union sockunion su_def = {
		.sin = {.sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY}};
	struct peer_group *group;
	struct peer *peer;
	struct listnode *node, *nnode;

	if (type == RMAP_BGP) {
		pc = rule;
		su = &pc->su;
		peer = ((struct bgp_info *)object)->peer;

		if (pc->interface) {
			if (!peer->conf_if)
				return RMAP_NOMATCH;

			if (strcmp(peer->conf_if, pc->interface) == 0)
				return RMAP_MATCH;

			return RMAP_NOMATCH;
		}

		/* If su='0.0.0.0' (command 'match peer local'), and it's a
		   NETWORK,
		    REDISTRIBUTE or DEFAULT_GENERATED route => return RMAP_MATCH
		   */
		if (sockunion_same(su, &su_def)) {
			int ret;
			if (CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_NETWORK)
			    || CHECK_FLAG(peer->rmap_type,
					  PEER_RMAP_TYPE_REDISTRIBUTE)
			    || CHECK_FLAG(peer->rmap_type,
					  PEER_RMAP_TYPE_DEFAULT))
				ret = RMAP_MATCH;
			else
				ret = RMAP_NOMATCH;
			return ret;
		}

		if (!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
			if (sockunion_same(su, &peer->su))
				return RMAP_MATCH;

			return RMAP_NOMATCH;
		} else {
			group = peer->group;
			for (ALL_LIST_ELEMENTS(group->peer, node, nnode,
					       peer)) {
				if (sockunion_same(su, &peer->su))
					return RMAP_MATCH;
			}
			return RMAP_NOMATCH;
		}
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

	if (pc->interface)
		XFREE(MTYPE_ROUTE_MAP_COMPILED, pc->interface);

	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip address matching. */
struct route_map_rule_cmd route_match_peer_cmd = {"peer", route_match_peer,
						  route_match_peer_compile,
						  route_match_peer_free};

/* `match ip address IP_ACCESS_LIST' */

/* Match function should return 1 if match is success else return
   zero. */
static route_map_result_t route_match_ip_address(void *rule,
						 struct prefix *prefix,
						 route_map_object_t type,
						 void *object)
{
	struct access_list *alist;

	if (type == RMAP_BGP && prefix->family == AF_INET) {
		alist = access_list_lookup(AFI_IP, (char *)rule);
		if (alist == NULL)
			return RMAP_NOMATCH;

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
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `ip address' value. */
static void route_match_ip_address_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip address matching. */
struct route_map_rule_cmd route_match_ip_address_cmd = {
	"ip address", route_match_ip_address, route_match_ip_address_compile,
	route_match_ip_address_free};

/* `match ip next-hop IP_ADDRESS' */

/* Match function return 1 if match is success else return zero. */
static route_map_result_t route_match_ip_next_hop(void *rule,
						  struct prefix *prefix,
						  route_map_object_t type,
						  void *object)
{
	struct access_list *alist;
	struct bgp_info *bgp_info;
	struct prefix_ipv4 p;

	if (type == RMAP_BGP && prefix->family == AF_INET) {
		bgp_info = object;
		p.family = AF_INET;
		p.prefix = bgp_info->attr->nexthop;
		p.prefixlen = IPV4_MAX_BITLEN;

		alist = access_list_lookup(AFI_IP, (char *)rule);
		if (alist == NULL)
			return RMAP_NOMATCH;

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
struct route_map_rule_cmd route_match_ip_next_hop_cmd = {
	"ip next-hop", route_match_ip_next_hop, route_match_ip_next_hop_compile,
	route_match_ip_next_hop_free};

/* `match ip route-source ACCESS-LIST' */

/* Match function return 1 if match is success else return zero. */
static route_map_result_t route_match_ip_route_source(void *rule,
						      struct prefix *prefix,
						      route_map_object_t type,
						      void *object)
{
	struct access_list *alist;
	struct bgp_info *bgp_info;
	struct peer *peer;
	struct prefix_ipv4 p;

	if (type == RMAP_BGP && prefix->family == AF_INET) {
		bgp_info = object;
		peer = bgp_info->peer;

		if (!peer || sockunion_family(&peer->su) != AF_INET)
			return RMAP_NOMATCH;

		p.family = AF_INET;
		p.prefix = peer->su.sin.sin_addr;
		p.prefixlen = IPV4_MAX_BITLEN;

		alist = access_list_lookup(AFI_IP, (char *)rule);
		if (alist == NULL)
			return RMAP_NOMATCH;

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
struct route_map_rule_cmd route_match_ip_route_source_cmd = {
	"ip route-source", route_match_ip_route_source,
	route_match_ip_route_source_compile, route_match_ip_route_source_free};

/* `match ip address prefix-list PREFIX_LIST' */

static route_map_result_t
route_match_ip_address_prefix_list(void *rule, struct prefix *prefix,
				   route_map_object_t type, void *object)
{
	struct prefix_list *plist;

	if (type == RMAP_BGP && prefix->family == AF_INET) {
		plist = prefix_list_lookup(AFI_IP, (char *)rule);
		if (plist == NULL)
			return RMAP_NOMATCH;

		return (prefix_list_apply(plist, prefix) == PREFIX_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
}

static void *route_match_ip_address_prefix_list_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ip_address_prefix_list_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd route_match_ip_address_prefix_list_cmd = {
	"ip address prefix-list", route_match_ip_address_prefix_list,
	route_match_ip_address_prefix_list_compile,
	route_match_ip_address_prefix_list_free};

/* `match ip next-hop prefix-list PREFIX_LIST' */

static route_map_result_t
route_match_ip_next_hop_prefix_list(void *rule, struct prefix *prefix,
				    route_map_object_t type, void *object)
{
	struct prefix_list *plist;
	struct bgp_info *bgp_info;
	struct prefix_ipv4 p;

	if (type == RMAP_BGP && prefix->family == AF_INET) {
		bgp_info = object;
		p.family = AF_INET;
		p.prefix = bgp_info->attr->nexthop;
		p.prefixlen = IPV4_MAX_BITLEN;

		plist = prefix_list_lookup(AFI_IP, (char *)rule);
		if (plist == NULL)
			return RMAP_NOMATCH;

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

struct route_map_rule_cmd route_match_ip_next_hop_prefix_list_cmd = {
	"ip next-hop prefix-list", route_match_ip_next_hop_prefix_list,
	route_match_ip_next_hop_prefix_list_compile,
	route_match_ip_next_hop_prefix_list_free};

/* `match ip route-source prefix-list PREFIX_LIST' */

static route_map_result_t
route_match_ip_route_source_prefix_list(void *rule, struct prefix *prefix,
					route_map_object_t type, void *object)
{
	struct prefix_list *plist;
	struct bgp_info *bgp_info;
	struct peer *peer;
	struct prefix_ipv4 p;

	if (type == RMAP_BGP && prefix->family == AF_INET) {
		bgp_info = object;
		peer = bgp_info->peer;

		if (!peer || sockunion_family(&peer->su) != AF_INET)
			return RMAP_NOMATCH;

		p.family = AF_INET;
		p.prefix = peer->su.sin.sin_addr;
		p.prefixlen = IPV4_MAX_BITLEN;

		plist = prefix_list_lookup(AFI_IP, (char *)rule);
		if (plist == NULL)
			return RMAP_NOMATCH;

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

struct route_map_rule_cmd route_match_ip_route_source_prefix_list_cmd = {
	"ip route-source prefix-list", route_match_ip_route_source_prefix_list,
	route_match_ip_route_source_prefix_list_compile,
	route_match_ip_route_source_prefix_list_free};

/* `match evpn default-route' */

/* Match function should return 1 if match is success else 0 */
static route_map_result_t route_match_evpn_default_route(void *rule,
							 struct prefix *p,
							 route_map_object_t
							 type, void *object)
{
	if (type == RMAP_BGP && is_evpn_prefix_default(p))
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

/* Route map commands for default-route matching. */
struct route_map_rule_cmd route_match_evpn_default_route_cmd = {
	"evpn default-route", route_match_evpn_default_route, NULL, NULL};

/* `match mac address MAC_ACCESS_LIST' */

/* Match function should return 1 if match is success else return
   zero. */
static route_map_result_t route_match_mac_address(void *rule,
						  struct prefix *prefix,
						  route_map_object_t type,
						  void *object)
{
	struct access_list *alist;
	struct prefix p;

	if (type == RMAP_BGP) {
		alist = access_list_lookup(AFI_L2VPN, (char *)rule);
		if (alist == NULL)
			return RMAP_NOMATCH;

		if (prefix->u.prefix_evpn.route_type != BGP_EVPN_MAC_IP_ROUTE)
			return RMAP_NOMATCH;

		p.family = AF_ETHERNET;
		p.prefixlen = ETH_ALEN * 8;
		p.u.prefix_eth = prefix->u.prefix_evpn.macip_addr.mac;

		return (access_list_apply(alist, &p) == FILTER_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}

	return RMAP_NOMATCH;
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
struct route_map_rule_cmd route_match_mac_address_cmd = {
	"mac address", route_match_mac_address, route_match_mac_address_compile,
	route_match_mac_address_free};

/* `match vni' */

/* Match function should return 1 if match is success else return
   zero. */
static route_map_result_t route_match_vni(void *rule, struct prefix *prefix,
					  route_map_object_t type, void *object)
{
	vni_t vni = 0;
	struct bgp_info *bgp_info = NULL;

	if (type == RMAP_BGP) {
		vni = *((vni_t *)rule);
		bgp_info = (struct bgp_info *)object;

		if (bgp_info->extra == NULL)
			return RMAP_NOMATCH;

		if (vni == label2vni(&bgp_info->extra->label[0]))
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
	if (!vni)
		return NULL;

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
struct route_map_rule_cmd route_match_evpn_vni_cmd = {
	"evpn vni", route_match_vni, route_match_vni_compile,
	route_match_vni_free};

/* `match evpn route-type' */

/* Match function should return 1 if match is success else return
   zero. */
static route_map_result_t route_match_evpn_route_type(void *rule,
						      struct prefix *prefix,
						      route_map_object_t type,
						      void *object)
{
	uint8_t route_type = 0;

	if (type == RMAP_BGP) {
		route_type = *((uint8_t *)rule);

		if (route_type == prefix->u.prefix_evpn.route_type)
			return RMAP_MATCH;
	}

	return RMAP_NOMATCH;
}

/* Route map `route-type' match statement. */
static void *route_match_evpn_route_type_compile(const char *arg)
{
	uint8_t *route_type = NULL;

	route_type = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(uint8_t));

	if (strncmp(arg, "ma", 2) == 0)
		*route_type = BGP_EVPN_MAC_IP_ROUTE;
	else if (strncmp(arg, "mu", 2) == 0)
		*route_type = BGP_EVPN_IMET_ROUTE;
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
struct route_map_rule_cmd route_match_evpn_route_type_cmd = {
	"evpn route-type", route_match_evpn_route_type,
	route_match_evpn_route_type_compile, route_match_evpn_route_type_free};

/* `match local-preference LOCAL-PREF' */

/* Match function return 1 if match is success else return zero. */
static route_map_result_t route_match_local_pref(void *rule,
						 struct prefix *prefix,
						 route_map_object_t type,
						 void *object)
{
	uint32_t *local_pref;
	struct bgp_info *bgp_info;

	if (type == RMAP_BGP) {
		local_pref = rule;
		bgp_info = object;

		if (bgp_info->attr->local_pref == *local_pref)
			return RMAP_MATCH;
		else
			return RMAP_NOMATCH;
	}
	return RMAP_NOMATCH;
}

/* Route map `match local-preference' match statement.
   `arg' is local-pref value */
static void *route_match_local_pref_compile(const char *arg)
{
	uint32_t *local_pref;
	char *endptr = NULL;
	unsigned long tmpval;

	/* Locpref value shoud be integer. */
	if (!all_digit(arg))
		return NULL;

	errno = 0;
	tmpval = strtoul(arg, &endptr, 10);
	if (*endptr != '\0' || errno || tmpval > UINT32_MAX)
		return NULL;

	local_pref = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(uint32_t));

	if (!local_pref)
		return local_pref;

	*local_pref = tmpval;
	return local_pref;
}

/* Free route map's compiled `match local-preference' value. */
static void route_match_local_pref_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for metric matching. */
struct route_map_rule_cmd route_match_local_pref_cmd = {
	"local-preference", route_match_local_pref,
	route_match_local_pref_compile, route_match_local_pref_free};

/* `match metric METRIC' */

/* Match function return 1 if match is success else return zero. */
static route_map_result_t route_match_metric(void *rule, struct prefix *prefix,
					     route_map_object_t type,
					     void *object)
{
	struct rmap_value *rv;
	struct bgp_info *bgp_info;

	if (type == RMAP_BGP) {
		rv = rule;
		bgp_info = object;
		return route_value_match(rv, bgp_info->attr->med);
	}
	return RMAP_NOMATCH;
}

/* Route map commands for metric matching. */
struct route_map_rule_cmd route_match_metric_cmd = {
	"metric", route_match_metric, route_value_compile, route_value_free,
};

/* `match as-path ASPATH' */

/* Match function for as-path match.  I assume given object is */
static route_map_result_t route_match_aspath(void *rule, struct prefix *prefix,
					     route_map_object_t type,
					     void *object)
{

	struct as_list *as_list;
	struct bgp_info *bgp_info;

	if (type == RMAP_BGP) {
		as_list = as_list_lookup((char *)rule);
		if (as_list == NULL)
			return RMAP_NOMATCH;

		bgp_info = object;

		/* Perform match. */
		return ((as_list_apply(as_list, bgp_info->attr->aspath)
			 == AS_FILTER_DENY)
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
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
struct route_map_rule_cmd route_match_aspath_cmd = {
	"as-path", route_match_aspath, route_match_aspath_compile,
	route_match_aspath_free};

/* `match community COMMUNIY' */
struct rmap_community {
	char *name;
	int exact;
};

/* Match function for community match. */
static route_map_result_t route_match_community(void *rule,
						struct prefix *prefix,
						route_map_object_t type,
						void *object)
{
	struct community_list *list;
	struct bgp_info *bgp_info;
	struct rmap_community *rcom;

	if (type == RMAP_BGP) {
		bgp_info = object;
		rcom = rule;

		list = community_list_lookup(bgp_clist, rcom->name,
					     COMMUNITY_LIST_MASTER);
		if (!list)
			return RMAP_NOMATCH;

		if (rcom->exact) {
			if (community_list_exact_match(
				    bgp_info->attr->community, list))
				return RMAP_MATCH;
		} else {
			if (community_list_match(bgp_info->attr->community,
						 list))
				return RMAP_MATCH;
		}
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
		rcom->exact = 1;
	} else {
		rcom->name = XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
		rcom->exact = 0;
	}
	return rcom;
}

/* Compile function for community match. */
static void route_match_community_free(void *rule)
{
	struct rmap_community *rcom = rule;

	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcom->name);
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcom);
}

/* Route map commands for community matching. */
struct route_map_rule_cmd route_match_community_cmd = {
	"community", route_match_community, route_match_community_compile,
	route_match_community_free};

/* Match function for lcommunity match. */
static route_map_result_t route_match_lcommunity(void *rule,
						 struct prefix *prefix,
						 route_map_object_t type,
						 void *object)
{
	struct community_list *list;
	struct bgp_info *bgp_info;
	struct rmap_community *rcom;

	if (type == RMAP_BGP) {
		bgp_info = object;
		rcom = rule;

		list = community_list_lookup(bgp_clist, rcom->name,
					     LARGE_COMMUNITY_LIST_MASTER);
		if (!list)
			return RMAP_NOMATCH;

		if (lcommunity_list_match(bgp_info->attr->lcommunity, list))
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
	} else {
		rcom->name = XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
		rcom->exact = 0;
	}
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
struct route_map_rule_cmd route_match_lcommunity_cmd = {
	"large-community", route_match_lcommunity,
	route_match_lcommunity_compile, route_match_lcommunity_free};


/* Match function for extcommunity match. */
static route_map_result_t route_match_ecommunity(void *rule,
						 struct prefix *prefix,
						 route_map_object_t type,
						 void *object)
{
	struct community_list *list;
	struct bgp_info *bgp_info;

	if (type == RMAP_BGP) {
		bgp_info = object;

		list = community_list_lookup(bgp_clist, (char *)rule,
					     EXTCOMMUNITY_LIST_MASTER);
		if (!list)
			return RMAP_NOMATCH;

		if (ecommunity_list_match(bgp_info->attr->ecommunity, list))
			return RMAP_MATCH;
	}
	return RMAP_NOMATCH;
}

/* Compile function for extcommunity match. */
static void *route_match_ecommunity_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Compile function for extcommunity match. */
static void route_match_ecommunity_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for community matching. */
struct route_map_rule_cmd route_match_ecommunity_cmd = {
	"extcommunity", route_match_ecommunity, route_match_ecommunity_compile,
	route_match_ecommunity_free};

/* `match nlri` and `set nlri` are replaced by `address-family ipv4`
   and `address-family vpnv4'.  */

/* `match origin' */
static route_map_result_t route_match_origin(void *rule, struct prefix *prefix,
					     route_map_object_t type,
					     void *object)
{
	uint8_t *origin;
	struct bgp_info *bgp_info;

	if (type == RMAP_BGP) {
		origin = rule;
		bgp_info = object;

		if (bgp_info->attr->origin == *origin)
			return RMAP_MATCH;
	}

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
struct route_map_rule_cmd route_match_origin_cmd = {
	"origin", route_match_origin, route_match_origin_compile,
	route_match_origin_free};

/* match probability  { */

static route_map_result_t route_match_probability(void *rule,
						  struct prefix *prefix,
						  route_map_object_t type,
						  void *object)
{
	long r = random();

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

struct route_map_rule_cmd route_match_probability_cmd = {
	"probability", route_match_probability, route_match_probability_compile,
	route_match_probability_free};

/* `match interface IFNAME' */
/* Match function should return 1 if match is success else return
   zero. */
static route_map_result_t route_match_interface(void *rule,
						struct prefix *prefix,
						route_map_object_t type,
						void *object)
{
	struct interface *ifp;
	struct bgp_info *info;

	if (type == RMAP_BGP) {
		info = object;

		if (!info || !info->attr)
			return RMAP_NOMATCH;

		ifp = if_lookup_by_name_all_vrf((char *)rule);

		if (ifp == NULL || ifp->ifindex != info->attr->nh_ifindex)
			return RMAP_NOMATCH;

		return RMAP_MATCH;
	}
	return RMAP_NOMATCH;
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
struct route_map_rule_cmd route_match_interface_cmd = {
	"interface", route_match_interface, route_match_interface_compile,
	route_match_interface_free};

/* } */

/* `set ip next-hop IP_ADDRESS' */

/* Match function return 1 if match is success else return zero. */
static route_map_result_t route_match_tag(void *rule, struct prefix *prefix,
					  route_map_object_t type, void *object)
{
	route_tag_t *tag;
	struct bgp_info *bgp_info;

	if (type == RMAP_BGP) {
		tag = rule;
		bgp_info = object;

		return ((bgp_info->attr->tag == *tag) ? RMAP_MATCH
						      : RMAP_NOMATCH);
	}

	return RMAP_NOMATCH;
}


/* Route map commands for tag matching. */
static struct route_map_rule_cmd route_match_tag_cmd = {
	"tag", route_match_tag, route_map_rule_tag_compile,
	route_map_rule_tag_free,
};


/* Set nexthop to object.  ojbect must be pointer to struct attr. */
struct rmap_ip_nexthop_set {
	struct in_addr *address;
	int peer_address;
	int unchanged;
};

static route_map_result_t route_set_ip_nexthop(void *rule,
					       struct prefix *prefix,
					       route_map_object_t type,
					       void *object)
{
	struct rmap_ip_nexthop_set *rins = rule;
	struct bgp_info *bgp_info;
	struct peer *peer;

	if (type == RMAP_BGP) {
		bgp_info = object;
		peer = bgp_info->peer;

		if (rins->unchanged) {
			SET_FLAG(bgp_info->attr->rmap_change_flags,
				 BATTR_RMAP_NEXTHOP_UNCHANGED);
		} else if (rins->peer_address) {
			if ((CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_IN)
			     || CHECK_FLAG(peer->rmap_type,
					   PEER_RMAP_TYPE_IMPORT))
			    && peer->su_remote
			    && sockunion_family(peer->su_remote) == AF_INET) {
				bgp_info->attr->nexthop.s_addr =
					sockunion2ip(peer->su_remote);
				bgp_info->attr->flag |=
					ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);
			} else if (CHECK_FLAG(peer->rmap_type,
					      PEER_RMAP_TYPE_OUT)) {
				/* The next hop value will be set as part of
				 * packet rewrite.
				 * Set the flags here to indicate that rewrite
				 * needs to be done.
				 * Also, clear the value.
				 */
				SET_FLAG(bgp_info->attr->rmap_change_flags,
					 BATTR_RMAP_NEXTHOP_PEER_ADDRESS);
				bgp_info->attr->nexthop.s_addr = 0;
			}
		} else {
			/* Set next hop value. */
			bgp_info->attr->flag |=
				ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);
			bgp_info->attr->nexthop = *rins->address;
			SET_FLAG(bgp_info->attr->rmap_change_flags,
				 BATTR_RMAP_IPV4_NHOP_CHANGED);
		}
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

	if (rins->address)
		XFREE(MTYPE_ROUTE_MAP_COMPILED, rins->address);

	XFREE(MTYPE_ROUTE_MAP_COMPILED, rins);
}

/* Route map commands for ip nexthop set. */
struct route_map_rule_cmd route_set_ip_nexthop_cmd = {
	"ip next-hop", route_set_ip_nexthop, route_set_ip_nexthop_compile,
	route_set_ip_nexthop_free};

/* `set local-preference LOCAL_PREF' */

/* Set local preference. */
static route_map_result_t route_set_local_pref(void *rule,
					       struct prefix *prefix,
					       route_map_object_t type,
					       void *object)
{
	struct rmap_value *rv;
	struct bgp_info *bgp_info;
	uint32_t locpref = 0;

	if (type == RMAP_BGP) {
		/* Fetch routemap's rule information. */
		rv = rule;
		bgp_info = object;

		/* Set local preference value. */
		if (bgp_info->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))
			locpref = bgp_info->attr->local_pref;

		bgp_info->attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF);
		bgp_info->attr->local_pref =
			route_value_adjust(rv, locpref, bgp_info->peer);
	}

	return RMAP_OKAY;
}

/* Set local preference rule structure. */
struct route_map_rule_cmd route_set_local_pref_cmd = {
	"local-preference", route_set_local_pref, route_value_compile,
	route_value_free,
};

/* `set weight WEIGHT' */

/* Set weight. */
static route_map_result_t route_set_weight(void *rule, struct prefix *prefix,
					   route_map_object_t type,
					   void *object)
{
	struct rmap_value *rv;
	struct bgp_info *bgp_info;

	if (type == RMAP_BGP) {
		/* Fetch routemap's rule information. */
		rv = rule;
		bgp_info = object;

		/* Set weight value. */
		bgp_info->attr->weight =
			route_value_adjust(rv, 0, bgp_info->peer);
	}

	return RMAP_OKAY;
}

/* Set local preference rule structure. */
struct route_map_rule_cmd route_set_weight_cmd = {
	"weight", route_set_weight, route_value_compile, route_value_free,
};

/* `set metric METRIC' */

/* Set metric to attribute. */
static route_map_result_t route_set_metric(void *rule, struct prefix *prefix,
					   route_map_object_t type,
					   void *object)
{
	struct rmap_value *rv;
	struct bgp_info *bgp_info;
	uint32_t med = 0;

	if (type == RMAP_BGP) {
		/* Fetch routemap's rule information. */
		rv = rule;
		bgp_info = object;

		if (bgp_info->attr->flag
		    & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))
			med = bgp_info->attr->med;

		bgp_info->attr->med =
			route_value_adjust(rv, med, bgp_info->peer);
		bgp_info->attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC);
	}
	return RMAP_OKAY;
}

/* Set metric rule structure. */
struct route_map_rule_cmd route_set_metric_cmd = {
	"metric", route_set_metric, route_value_compile, route_value_free,
};

/* `set as-path prepend ASPATH' */

/* For AS path prepend mechanism. */
static route_map_result_t route_set_aspath_prepend(void *rule,
						   struct prefix *prefix,
						   route_map_object_t type,
						   void *object)
{
	struct aspath *aspath;
	struct aspath *new;
	struct bgp_info *binfo;

	if (type == RMAP_BGP) {
		binfo = object;

		if (binfo->attr->aspath->refcnt)
			new = aspath_dup(binfo->attr->aspath);
		else
			new = binfo->attr->aspath;

		if ((uintptr_t)rule > 10) {
			aspath = rule;
			aspath_prepend(aspath, new);
		} else {
			as_t as = aspath_leftmost(new);
			if (!as)
				as = binfo->peer->as;
			new = aspath_add_seq_n(new, as, (uintptr_t)rule);
		}

		binfo->attr->aspath = new;
	}

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
struct route_map_rule_cmd route_set_aspath_prepend_cmd = {
	"as-path prepend", route_set_aspath_prepend,
	route_set_aspath_prepend_compile, route_set_aspath_prepend_free,
};

/* `set as-path exclude ASn' */

/* For ASN exclude mechanism.
 * Iterate over ASns requested and filter them from the given AS_PATH one by
 * one.
 * Make a deep copy of existing AS_PATH, but for the first ASn only.
 */
static route_map_result_t route_set_aspath_exclude(void *rule,
						   struct prefix *dummy,
						   route_map_object_t type,
						   void *object)
{
	struct aspath *new_path, *exclude_path;
	struct bgp_info *binfo;

	if (type == RMAP_BGP) {
		exclude_path = rule;
		binfo = object;
		if (binfo->attr->aspath->refcnt)
			new_path = aspath_dup(binfo->attr->aspath);
		else
			new_path = binfo->attr->aspath;
		binfo->attr->aspath =
			aspath_filter_exclude(new_path, exclude_path);
	}
	return RMAP_OKAY;
}

/* Set ASn exlude rule structure. */
struct route_map_rule_cmd route_set_aspath_exclude_cmd = {
	"as-path exclude", route_set_aspath_exclude, route_aspath_compile,
	route_aspath_free,
};

/* `set community COMMUNITY' */
struct rmap_com_set {
	struct community *com;
	int additive;
	int none;
};

/* For community set mechanism. */
static route_map_result_t route_set_community(void *rule, struct prefix *prefix,
					      route_map_object_t type,
					      void *object)
{
	struct rmap_com_set *rcs;
	struct bgp_info *binfo;
	struct attr *attr;
	struct community *new = NULL;
	struct community *old;
	struct community *merge;

	if (type == RMAP_BGP) {
		rcs = rule;
		binfo = object;
		attr = binfo->attr;
		old = attr->community;

		/* "none" case.  */
		if (rcs->none) {
			attr->flag &= ~(ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES));
			attr->community = NULL;
			/* See the longer comment down below. */
			if (old && old->refcnt == 0)
				community_free(old);
			return RMAP_OKAY;
		}

		/* "additive" case.  */
		if (rcs->additive && old) {
			merge = community_merge(community_dup(old), rcs->com);

			new = community_uniq_sort(merge);
			community_free(merge);
		} else
			new = community_dup(rcs->com);

		/* HACK: if the old community is not intern'd,
		 * we should free it here, or all reference to it may be
		 * lost.
		 * Really need to cleanup attribute caching sometime.
		 */
		if (old && old->refcnt == 0)
			community_free(old);

		/* will be interned by caller if required */
		attr->community = new;

		attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES);
	}

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
		community_free(rcs->com);
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rcs);
}

/* Set community rule structure. */
struct route_map_rule_cmd route_set_community_cmd = {
	"community", route_set_community, route_set_community_compile,
	route_set_community_free,
};

/* `set community COMMUNITY' */
struct rmap_lcom_set {
	struct lcommunity *lcom;
	int additive;
	int none;
};


/* For lcommunity set mechanism. */
static route_map_result_t route_set_lcommunity(void *rule,
					       struct prefix *prefix,
					       route_map_object_t type,
					       void *object)
{
	struct rmap_lcom_set *rcs;
	struct bgp_info *binfo;
	struct attr *attr;
	struct lcommunity *new = NULL;
	struct lcommunity *old;
	struct lcommunity *merge;

	if (type == RMAP_BGP) {
		rcs = rule;
		binfo = object;
		attr = binfo->attr;
		old = attr->lcommunity;

		/* "none" case.  */
		if (rcs->none) {
			attr->flag &=
				~(ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES));
			attr->lcommunity = NULL;

			/* See the longer comment down below. */
			if (old && old->refcnt == 0)
				lcommunity_free(&old);
			return RMAP_OKAY;
		}

		if (rcs->additive && old) {
			merge = lcommunity_merge(lcommunity_dup(old),
						 rcs->lcom);

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
		attr->lcommunity = new;

		attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_LARGE_COMMUNITIES);
	}

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
struct route_map_rule_cmd route_set_lcommunity_cmd = {
	"large-community", route_set_lcommunity, route_set_lcommunity_compile,
	route_set_lcommunity_free,
};

/* `set large-comm-list (<1-99>|<100-500>|WORD) delete' */

/* For large community set mechanism. */
static route_map_result_t route_set_lcommunity_delete(void *rule,
						      struct prefix *prefix,
						      route_map_object_t type,
						      void *object)
{
	struct community_list *list;
	struct lcommunity *merge;
	struct lcommunity *new;
	struct lcommunity *old;
	struct bgp_info *binfo;

	if (type == RMAP_BGP) {
		if (!rule)
			return RMAP_OKAY;

		binfo = object;
		list = community_list_lookup(bgp_clist, rule,
					     LARGE_COMMUNITY_LIST_MASTER);
		old = binfo->attr->lcommunity;

		if (list && old) {
			merge = lcommunity_list_match_delete(
				lcommunity_dup(old), list);
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
				binfo->attr->lcommunity = NULL;
				binfo->attr->flag &= ~ATTR_FLAG_BIT(
					BGP_ATTR_LARGE_COMMUNITIES);
				lcommunity_free(&new);
			} else {
				binfo->attr->lcommunity = new;
				binfo->attr->flag |= ATTR_FLAG_BIT(
					BGP_ATTR_LARGE_COMMUNITIES);
			}
		}
	}

	return RMAP_OKAY;
}

/* Compile function for set lcommunity. */
static void *route_set_lcommunity_delete_compile(const char *arg)
{
	char *p;
	char *str;
	int len;

	p = strchr(arg, ' ');
	if (p) {
		len = p - arg;
		str = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, len + 1);
		memcpy(str, arg, len);
	} else
		str = NULL;

	return str;
}

/* Free function for set lcommunity. */
static void route_set_lcommunity_delete_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set lcommunity rule structure. */
struct route_map_rule_cmd route_set_lcommunity_delete_cmd = {
	"large-comm-list", route_set_lcommunity_delete,
	route_set_lcommunity_delete_compile, route_set_lcommunity_delete_free,
};


/* `set comm-list (<1-99>|<100-500>|WORD) delete' */

/* For community set mechanism. */
static route_map_result_t route_set_community_delete(void *rule,
						     struct prefix *prefix,
						     route_map_object_t type,
						     void *object)
{
	struct community_list *list;
	struct community *merge;
	struct community *new;
	struct community *old;
	struct bgp_info *binfo;

	if (type == RMAP_BGP) {
		if (!rule)
			return RMAP_OKAY;

		binfo = object;
		list = community_list_lookup(bgp_clist, rule,
					     COMMUNITY_LIST_MASTER);
		old = binfo->attr->community;

		if (list && old) {
			merge = community_list_match_delete(community_dup(old),
							    list);
			new = community_uniq_sort(merge);
			community_free(merge);

			/* HACK: if the old community is not intern'd,
			 * we should free it here, or all reference to it may be
			 * lost.
			 * Really need to cleanup attribute caching sometime.
			 */
			if (old->refcnt == 0)
				community_free(old);

			if (new->size == 0) {
				binfo->attr->community = NULL;
				binfo->attr->flag &=
					~ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES);
				community_free(new);
			} else {
				binfo->attr->community = new;
				binfo->attr->flag |=
					ATTR_FLAG_BIT(BGP_ATTR_COMMUNITIES);
			}
		}
	}

	return RMAP_OKAY;
}

/* Compile function for set community. */
static void *route_set_community_delete_compile(const char *arg)
{
	char *p;
	char *str;
	int len;

	p = strchr(arg, ' ');
	if (p) {
		len = p - arg;
		str = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, len + 1);
		memcpy(str, arg, len);
	} else
		str = NULL;

	return str;
}

/* Free function for set community. */
static void route_set_community_delete_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set community rule structure. */
struct route_map_rule_cmd route_set_community_delete_cmd = {
	"comm-list", route_set_community_delete,
	route_set_community_delete_compile, route_set_community_delete_free,
};

/* `set extcommunity rt COMMUNITY' */

/* For community set mechanism.  Used by _rt and _soo. */
static route_map_result_t route_set_ecommunity(void *rule,
					       struct prefix *prefix,
					       route_map_object_t type,
					       void *object)
{
	struct ecommunity *ecom;
	struct ecommunity *new_ecom;
	struct ecommunity *old_ecom;
	struct bgp_info *bgp_info;

	if (type == RMAP_BGP) {
		ecom = rule;
		bgp_info = object;

		if (!ecom)
			return RMAP_OKAY;

		/* We assume additive for Extended Community. */
		old_ecom = bgp_info->attr->ecommunity;

		if (old_ecom) {
			new_ecom = ecommunity_merge(ecommunity_dup(old_ecom),
						    ecom);

			/* old_ecom->refcnt = 1 => owned elsewhere, e.g.
			 * bgp_update_receive()
			 *         ->refcnt = 0 => set by a previous route-map
			 * statement */
			if (!old_ecom->refcnt)
				ecommunity_free(&old_ecom);
		} else
			new_ecom = ecommunity_dup(ecom);

		/* will be intern()'d or attr_flush()'d by bgp_update_main() */
		bgp_info->attr->ecommunity = new_ecom;

		bgp_info->attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES);
	}
	return RMAP_OKAY;
}

/* Compile function for set community. */
static void *route_set_ecommunity_rt_compile(const char *arg)
{
	struct ecommunity *ecom;

	ecom = ecommunity_str2com(arg, ECOMMUNITY_ROUTE_TARGET, 0);
	if (!ecom)
		return NULL;
	return ecommunity_intern(ecom);
}

/* Free function for set community.  Used by _rt and _soo */
static void route_set_ecommunity_free(void *rule)
{
	struct ecommunity *ecom = rule;
	ecommunity_unintern(&ecom);
}

/* Set community rule structure. */
struct route_map_rule_cmd route_set_ecommunity_rt_cmd = {
	"extcommunity rt", route_set_ecommunity,
	route_set_ecommunity_rt_compile, route_set_ecommunity_free,
};

/* `set extcommunity soo COMMUNITY' */

/* Compile function for set community. */
static void *route_set_ecommunity_soo_compile(const char *arg)
{
	struct ecommunity *ecom;

	ecom = ecommunity_str2com(arg, ECOMMUNITY_SITE_ORIGIN, 0);
	if (!ecom)
		return NULL;

	return ecommunity_intern(ecom);
}

/* Set community rule structure. */
struct route_map_rule_cmd route_set_ecommunity_soo_cmd = {
	"extcommunity soo", route_set_ecommunity,
	route_set_ecommunity_soo_compile, route_set_ecommunity_free,
};

/* `set origin ORIGIN' */

/* For origin set. */
static route_map_result_t route_set_origin(void *rule, struct prefix *prefix,
					   route_map_object_t type,
					   void *object)
{
	uint8_t *origin;
	struct bgp_info *bgp_info;

	if (type == RMAP_BGP) {
		origin = rule;
		bgp_info = object;

		bgp_info->attr->origin = *origin;
	}

	return RMAP_OKAY;
}

/* Compile function for origin set. */
static void *route_set_origin_compile(const char *arg)
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

/* Compile function for origin set. */
static void route_set_origin_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set origin rule structure. */
struct route_map_rule_cmd route_set_origin_cmd = {
	"origin", route_set_origin, route_set_origin_compile,
	route_set_origin_free,
};

/* `set atomic-aggregate' */

/* For atomic aggregate set. */
static route_map_result_t route_set_atomic_aggregate(void *rule,
						     struct prefix *prefix,
						     route_map_object_t type,
						     void *object)
{
	struct bgp_info *bgp_info;

	if (type == RMAP_BGP) {
		bgp_info = object;
		bgp_info->attr->flag |=
			ATTR_FLAG_BIT(BGP_ATTR_ATOMIC_AGGREGATE);
	}

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
struct route_map_rule_cmd route_set_atomic_aggregate_cmd = {
	"atomic-aggregate", route_set_atomic_aggregate,
	route_set_atomic_aggregate_compile, route_set_atomic_aggregate_free,
};

/* `set aggregator as AS A.B.C.D' */
struct aggregator {
	as_t as;
	struct in_addr address;
};

static route_map_result_t route_set_aggregator_as(void *rule,
						  struct prefix *prefix,
						  route_map_object_t type,
						  void *object)
{
	struct bgp_info *bgp_info;
	struct aggregator *aggregator;

	if (type == RMAP_BGP) {
		bgp_info = object;
		aggregator = rule;

		bgp_info->attr->aggregator_as = aggregator->as;
		bgp_info->attr->aggregator_addr = aggregator->address;
		bgp_info->attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_AGGREGATOR);
	}

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

struct route_map_rule_cmd route_set_aggregator_as_cmd = {
	"aggregator as", route_set_aggregator_as,
	route_set_aggregator_as_compile, route_set_aggregator_as_free,
};

/* Set tag to object. object must be pointer to struct bgp_info */
static route_map_result_t route_set_tag(void *rule, struct prefix *prefix,
					route_map_object_t type, void *object)
{
	route_tag_t *tag;
	struct bgp_info *bgp_info;

	if (type == RMAP_BGP) {
		tag = rule;
		bgp_info = object;

		/* Set tag value */
		bgp_info->attr->tag = *tag;
	}

	return RMAP_OKAY;
}

/* Route map commands for tag set. */
static struct route_map_rule_cmd route_set_tag_cmd = {
	"tag", route_set_tag, route_map_rule_tag_compile,
	route_map_rule_tag_free,
};

/* Set label-index to object. object must be pointer to struct bgp_info */
static route_map_result_t route_set_label_index(void *rule,
						struct prefix *prefix,
						route_map_object_t type,
						void *object)
{
	struct rmap_value *rv;
	struct bgp_info *bgp_info;
	uint32_t label_index;

	if (type == RMAP_BGP) {
		/* Fetch routemap's rule information. */
		rv = rule;
		bgp_info = object;

		/* Set label-index value. */
		label_index = rv->value;
		if (label_index) {
			bgp_info->attr->label_index = label_index;
			bgp_info->attr->flag |=
				ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID);
		}
	}

	return RMAP_OKAY;
}

/* Route map commands for label-index set. */
static struct route_map_rule_cmd route_set_label_index_cmd = {
	"label-index", route_set_label_index, route_value_compile,
	route_value_free,
};

/* `match ipv6 address IP_ACCESS_LIST' */

static route_map_result_t route_match_ipv6_address(void *rule,
						   struct prefix *prefix,
						   route_map_object_t type,
						   void *object)
{
	struct access_list *alist;

	if (type == RMAP_BGP && prefix->family == AF_INET6) {
		alist = access_list_lookup(AFI_IP6, (char *)rule);
		if (alist == NULL)
			return RMAP_NOMATCH;

		return (access_list_apply(alist, prefix) == FILTER_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
}

static void *route_match_ipv6_address_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ipv6_address_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip address matching. */
struct route_map_rule_cmd route_match_ipv6_address_cmd = {
	"ipv6 address", route_match_ipv6_address,
	route_match_ipv6_address_compile, route_match_ipv6_address_free};

/* `match ipv6 next-hop IP_ADDRESS' */

static route_map_result_t route_match_ipv6_next_hop(void *rule,
						    struct prefix *prefix,
						    route_map_object_t type,
						    void *object)
{
	struct in6_addr *addr = rule;
	struct bgp_info *bgp_info;

	if (type == RMAP_BGP) {
		bgp_info = object;

		if (IPV6_ADDR_SAME(&bgp_info->attr->mp_nexthop_global, addr))
			return RMAP_MATCH;

		if (bgp_info->attr->mp_nexthop_len
			    == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL
		    && IPV6_ADDR_SAME(&bgp_info->attr->mp_nexthop_local, rule))
			return RMAP_MATCH;

		return RMAP_NOMATCH;
	}

	return RMAP_NOMATCH;
}

static void *route_match_ipv6_next_hop_compile(const char *arg)
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

static void route_match_ipv6_next_hop_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd route_match_ipv6_next_hop_cmd = {
	"ipv6 next-hop", route_match_ipv6_next_hop,
	route_match_ipv6_next_hop_compile, route_match_ipv6_next_hop_free};

/* `match ipv6 address prefix-list PREFIX_LIST' */

static route_map_result_t
route_match_ipv6_address_prefix_list(void *rule, struct prefix *prefix,
				     route_map_object_t type, void *object)
{
	struct prefix_list *plist;

	if (type == RMAP_BGP && prefix->family == AF_INET6) {
		plist = prefix_list_lookup(AFI_IP6, (char *)rule);
		if (plist == NULL)
			return RMAP_NOMATCH;

		return (prefix_list_apply(plist, prefix) == PREFIX_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
}

static void *route_match_ipv6_address_prefix_list_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ipv6_address_prefix_list_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd route_match_ipv6_address_prefix_list_cmd = {
	"ipv6 address prefix-list", route_match_ipv6_address_prefix_list,
	route_match_ipv6_address_prefix_list_compile,
	route_match_ipv6_address_prefix_list_free};

/* `set ipv6 nexthop global IP_ADDRESS' */

/* Set nexthop to object.  ojbect must be pointer to struct attr. */
static route_map_result_t route_set_ipv6_nexthop_global(void *rule,
							struct prefix *prefix,
							route_map_object_t type,
							void *object)
{
	struct in6_addr *address;
	struct bgp_info *bgp_info;

	if (type == RMAP_BGP) {
		/* Fetch routemap's rule information. */
		address = rule;
		bgp_info = object;

		/* Set next hop value. */
		bgp_info->attr->mp_nexthop_global = *address;

		/* Set nexthop length. */
		if (bgp_info->attr->mp_nexthop_len == 0)
			bgp_info->attr->mp_nexthop_len =
				BGP_ATTR_NHLEN_IPV6_GLOBAL;

		SET_FLAG(bgp_info->attr->rmap_change_flags,
			 BATTR_RMAP_IPV6_GLOBAL_NHOP_CHANGED);
	}

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
struct route_map_rule_cmd route_set_ipv6_nexthop_global_cmd = {
	"ipv6 next-hop global", route_set_ipv6_nexthop_global,
	route_set_ipv6_nexthop_global_compile,
	route_set_ipv6_nexthop_global_free};

/* Set next-hop preference value. */
static route_map_result_t
route_set_ipv6_nexthop_prefer_global(void *rule, struct prefix *prefix,
				     route_map_object_t type, void *object)
{
	struct bgp_info *bgp_info;
	struct peer *peer;

	if (type == RMAP_BGP) {
		/* Fetch routemap's rule information. */
		bgp_info = object;
		peer = bgp_info->peer;

		if ((CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_IN)
		     || CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_IMPORT))
		    && peer->su_remote
		    && sockunion_family(peer->su_remote) == AF_INET6) {
			/* Set next hop preference to global */
			bgp_info->attr->mp_nexthop_prefer_global = TRUE;
			SET_FLAG(bgp_info->attr->rmap_change_flags,
				 BATTR_RMAP_IPV6_PREFER_GLOBAL_CHANGED);
		} else {
			bgp_info->attr->mp_nexthop_prefer_global = FALSE;
			SET_FLAG(bgp_info->attr->rmap_change_flags,
				 BATTR_RMAP_IPV6_PREFER_GLOBAL_CHANGED);
		}
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
struct route_map_rule_cmd route_set_ipv6_nexthop_prefer_global_cmd = {
	"ipv6 next-hop prefer-global", route_set_ipv6_nexthop_prefer_global,
	route_set_ipv6_nexthop_prefer_global_compile,
	route_set_ipv6_nexthop_prefer_global_free};

/* `set ipv6 nexthop local IP_ADDRESS' */

/* Set nexthop to object.  ojbect must be pointer to struct attr. */
static route_map_result_t route_set_ipv6_nexthop_local(void *rule,
						       struct prefix *prefix,
						       route_map_object_t type,
						       void *object)
{
	struct in6_addr *address;
	struct bgp_info *bgp_info;

	if (type == RMAP_BGP) {
		/* Fetch routemap's rule information. */
		address = rule;
		bgp_info = object;

		/* Set next hop value. */
		bgp_info->attr->mp_nexthop_local = *address;

		/* Set nexthop length. */
		if (bgp_info->attr->mp_nexthop_len
		    != BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL)
			bgp_info->attr->mp_nexthop_len =
				BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL;

		SET_FLAG(bgp_info->attr->rmap_change_flags,
			 BATTR_RMAP_IPV6_LL_NHOP_CHANGED);
	}

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
struct route_map_rule_cmd route_set_ipv6_nexthop_local_cmd = {
	"ipv6 next-hop local", route_set_ipv6_nexthop_local,
	route_set_ipv6_nexthop_local_compile,
	route_set_ipv6_nexthop_local_free};

/* `set ipv6 nexthop peer-address' */

/* Set nexthop to object.  ojbect must be pointer to struct attr. */
static route_map_result_t route_set_ipv6_nexthop_peer(void *rule,
						      struct prefix *prefix,
						      route_map_object_t type,
						      void *object)
{
	struct in6_addr peer_address;
	struct bgp_info *bgp_info;
	struct peer *peer;

	if (type == RMAP_BGP) {
		/* Fetch routemap's rule information. */
		bgp_info = object;
		peer = bgp_info->peer;

		if ((CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_IN)
		     || CHECK_FLAG(peer->rmap_type, PEER_RMAP_TYPE_IMPORT))
		    && peer->su_remote
		    && sockunion_family(peer->su_remote) == AF_INET6) {
			peer_address = peer->su_remote->sin6.sin6_addr;
			/* Set next hop value and length in attribute. */
			if (IN6_IS_ADDR_LINKLOCAL(&peer_address)) {
				bgp_info->attr->mp_nexthop_local = peer_address;
				if (bgp_info->attr->mp_nexthop_len != 32)
					bgp_info->attr->mp_nexthop_len = 32;
			} else {
				bgp_info->attr->mp_nexthop_global =
					peer_address;
				if (bgp_info->attr->mp_nexthop_len == 0)
					bgp_info->attr->mp_nexthop_len = 16;
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
			SET_FLAG(bgp_info->attr->rmap_change_flags,
				 BATTR_RMAP_NEXTHOP_PEER_ADDRESS);
			/* clear next hop value. */
			memset(&(bgp_info->attr->mp_nexthop_global), 0,
			       sizeof(struct in6_addr));
			memset(&(bgp_info->attr->mp_nexthop_local), 0,
			       sizeof(struct in6_addr));
		}
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
struct route_map_rule_cmd route_set_ipv6_nexthop_peer_cmd = {
	"ipv6 next-hop peer-address", route_set_ipv6_nexthop_peer,
	route_set_ipv6_nexthop_peer_compile, route_set_ipv6_nexthop_peer_free};

/* `set ipv4 vpn next-hop A.B.C.D' */

static route_map_result_t route_set_vpnv4_nexthop(void *rule,
						  struct prefix *prefix,
						  route_map_object_t type,
						  void *object)
{
	struct in_addr *address;
	struct bgp_info *bgp_info;

	if (type == RMAP_BGP) {
		/* Fetch routemap's rule information. */
		address = rule;
		bgp_info = object;

		/* Set next hop value. */
		bgp_info->attr->mp_nexthop_global_in = *address;
		bgp_info->attr->mp_nexthop_len = 4;
	}

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

static route_map_result_t route_set_vpnv6_nexthop(void *rule,
						  struct prefix *prefix,
						  route_map_object_t type,
						  void *object)
{
	struct in6_addr *address;
	struct bgp_info *bgp_info;

	if (type == RMAP_BGP) {
		/* Fetch routemap's rule information. */
		address = rule;
		bgp_info = object;

		/* Set next hop value. */
		memcpy(&bgp_info->attr->mp_nexthop_global, address,
		       sizeof(struct in6_addr));
		bgp_info->attr->mp_nexthop_len = BGP_ATTR_NHLEN_VPNV6_GLOBAL;
	}

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
struct route_map_rule_cmd route_set_vpnv4_nexthop_cmd = {
	"ipv4 vpn next-hop", route_set_vpnv4_nexthop,
	route_set_vpnv4_nexthop_compile, route_set_vpn_nexthop_free};

/* Route map commands for ipv6 next-hop set. */
struct route_map_rule_cmd route_set_vpnv6_nexthop_cmd = {
	"ipv6 vpn next-hop", route_set_vpnv6_nexthop,
	route_set_vpnv6_nexthop_compile, route_set_vpn_nexthop_free};

/* `set originator-id' */

/* For origin set. */
static route_map_result_t route_set_originator_id(void *rule,
						  struct prefix *prefix,
						  route_map_object_t type,
						  void *object)
{
	struct in_addr *address;
	struct bgp_info *bgp_info;

	if (type == RMAP_BGP) {
		address = rule;
		bgp_info = object;

		bgp_info->attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID);
		bgp_info->attr->originator_id = *address;
	}

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
struct route_map_rule_cmd route_set_originator_id_cmd = {
	"originator-id", route_set_originator_id,
	route_set_originator_id_compile, route_set_originator_id_free,
};

/* Add bgp route map rule. */
static int bgp_route_match_add(struct vty *vty, const char *command,
			       const char *arg, route_map_event_t type)
{
	VTY_DECLVAR_CONTEXT(route_map_index, index);
	int retval = CMD_SUCCESS;
	int ret;

	ret = route_map_add_match(index, command, arg);
	switch (ret) {
	case RMAP_RULE_MISSING:
		vty_out(vty, "%% BGP Can't find rule.\n");
		retval = CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_ERROR:
		vty_out(vty, "%% BGP Argument is malformed.\n");
		retval = CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_SUCCESS:
		if (type != RMAP_EVENT_MATCH_ADDED) {
			route_map_upd8_dependency(type, arg, index->map->name);
		}
		break;
	}

	return retval;
}

/* Delete bgp route map rule. */
static int bgp_route_match_delete(struct vty *vty, const char *command,
				  const char *arg, route_map_event_t type)
{
	VTY_DECLVAR_CONTEXT(route_map_index, index);
	int ret;
	int retval = CMD_SUCCESS;
	char *dep_name = NULL;
	const char *tmpstr;
	char *rmap_name = NULL;

	if (type != RMAP_EVENT_MATCH_DELETED) {
		/* ignore the mundane, the types without any dependency */
		if (arg == NULL) {
			if ((tmpstr = route_map_get_match_arg(index, command))
			    != NULL)
				dep_name =
					XSTRDUP(MTYPE_ROUTE_MAP_RULE, tmpstr);
		} else {
			dep_name = XSTRDUP(MTYPE_ROUTE_MAP_RULE, arg);
		}
		rmap_name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, index->map->name);
	}

	ret = route_map_delete_match(index, command, dep_name);
	switch (ret) {
	case RMAP_RULE_MISSING:
		vty_out(vty, "%% BGP Can't find rule.\n");
		retval = CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_ERROR:
		vty_out(vty, "%% BGP Argument is malformed.\n");
		retval = CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_SUCCESS:
		if (type != RMAP_EVENT_MATCH_DELETED && dep_name)
			route_map_upd8_dependency(type, dep_name, rmap_name);
		break;
	}

	if (dep_name)
		XFREE(MTYPE_ROUTE_MAP_RULE, dep_name);
	if (rmap_name)
		XFREE(MTYPE_ROUTE_MAP_NAME, rmap_name);

	return retval;
}

/*
 * This is the workhorse routine for processing in/out routemap
 * modifications.
 */
static void bgp_route_map_process_peer(const char *rmap_name,
				       struct route_map *map, struct peer *peer,
				       int afi, int safi, int route_update)
{

	int update;
	struct bgp_filter *filter;

	if (!peer || !rmap_name)
		return;

	filter = &peer->filter[afi][safi];
	/*
	 * in is for non-route-server clients,
	 * out is for all peers
	 */
	if (!CHECK_FLAG(peer->flags, PEER_FLAG_RSERVER_CLIENT)) {
		if (filter->map[RMAP_IN].name
		    && (strcmp(rmap_name, filter->map[RMAP_IN].name) == 0)) {
			filter->map[RMAP_IN].map = map;

			if (route_update && peer->status == Established) {
				if (CHECK_FLAG(peer->af_flags[afi][safi],
					       PEER_FLAG_SOFT_RECONFIG)) {
					if (bgp_debug_update(peer, NULL, NULL,
							     1))
						zlog_debug(
							"Processing route_map %s update on "
							"peer %s (inbound, soft-reconfig)",
							rmap_name, peer->host);

					bgp_soft_reconfig_in(peer, afi, safi);
				} else if (
					CHECK_FLAG(peer->cap,
						   PEER_CAP_REFRESH_OLD_RCV)
					|| CHECK_FLAG(
						   peer->cap,
						   PEER_CAP_REFRESH_NEW_RCV)) {

					if (bgp_debug_update(peer, NULL, NULL,
							     1))
						zlog_debug(
							"Processing route_map %s update on "
							"peer %s (inbound, route-refresh)",
							rmap_name, peer->host);
					bgp_route_refresh_send(peer, afi, safi,
							       0, 0, 0);
				}
			}
		}
	}

	if (CHECK_FLAG(peer->flags, PEER_FLAG_RSERVER_CLIENT)) {
		update = 0;

		if (update && route_update && peer->status == Established) {
			if (CHECK_FLAG(peer->af_flags[afi][safi],
				       PEER_FLAG_SOFT_RECONFIG)) {
				if (bgp_debug_update(peer, NULL, NULL, 1))
					zlog_debug(
						"Processing route_map %s update on "
						"peer %s (import, soft-reconfig)",
						rmap_name, peer->host);

				bgp_soft_reconfig_in(peer, afi, safi);
			} else if (CHECK_FLAG(peer->cap,
					      PEER_CAP_REFRESH_OLD_RCV)
				   || CHECK_FLAG(peer->cap,
						 PEER_CAP_REFRESH_NEW_RCV)) {
				if (bgp_debug_update(peer, NULL, NULL, 1))
					zlog_debug(
						"Processing route_map %s update on "
						"peer %s (import, route-refresh)",
						rmap_name, peer->host);
				bgp_route_refresh_send(peer, afi, safi, 0, 0,
						       0);
			}
			/* DD: Else, what else do we do ? Reset peer ? */
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

	if (peer->default_rmap[afi][safi].name
	    && (strcmp(rmap_name, peer->default_rmap[afi][safi].name) == 0))
		peer->default_rmap[afi][safi].map = map;
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
					 int route_update)
{
	int i;
	afi_t afi;
	safi_t safi;
	struct peer *peer;
	struct bgp_node *bn;
	struct bgp_static *bgp_static;
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
			bgp->table_map[afi][safi].map = map;

			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug(
					"Processing route_map %s update on "
					"table map",
					rmap_name);
			if (route_update)
				bgp_zebra_announce_table(bgp, afi, safi);
		}

		/* For network route-map updates. */
		for (bn = bgp_table_top(bgp->route[afi][safi]); bn;
		     bn = bgp_route_next(bn))
			if ((bgp_static = bn->info) != NULL) {
				if (bgp_static->rmap.name
				    && (strcmp(rmap_name, bgp_static->rmap.name)
					== 0)) {
					bgp_static->rmap.map = map;

					if (route_update)
						if (!bgp_static->backdoor) {
							if (bgp_debug_zebra(
								    &bn->p))
								zlog_debug(
									"Processing route_map %s update on "
									"static route %s",
									rmap_name,
									inet_ntop(
										bn->p.family,
										&bn->p.u.prefix,
										buf,
										INET6_ADDRSTRLEN));
							bgp_static_update(
								bgp, &bn->p,
								bgp_static, afi,
								safi);
						}
				}
			}
	}

	/* For redistribute route-map updates. */
	for (afi = AFI_IP; afi < AFI_MAX; afi++)
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
			struct list *red_list;
			struct listnode *node;
			struct bgp_redist *red;

			red_list = bgp->redist[afi][i];
			if (!red_list)
				continue;

			for (ALL_LIST_ELEMENTS_RO(red_list, node, red)) {
				if (red->rmap.name
				    && (strcmp(rmap_name, red->rmap.name)
					== 0)) {
					red->rmap.map = map;

					if (route_update) {
						if (BGP_DEBUG(zebra, ZEBRA))
							zlog_debug(
								"Processing route_map %s update on "
								"redistributed routes",
								rmap_name);

						bgp_redistribute_resend(
							bgp, afi, i,
							red->instance);
					}
				}
			}
		}

	/* for type5 command route-maps */
	FOREACH_AFI_SAFI (afi, safi) {
		if (bgp->adv_cmd_rmap[afi][safi].name
		    && strcmp(rmap_name, bgp->adv_cmd_rmap[afi][safi].name)
			       == 0) {
			if (BGP_DEBUG(zebra, ZEBRA))
				zlog_debug(
					"Processing route_map %s update on advertise type5 route command",
					rmap_name);
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
		bgp_route_map_process_update(bgp, rmap_name, 1);

#if ENABLE_BGP_VNC
		/* zlog_debug("%s: calling vnc_routemap_update", __func__); */
		vnc_routemap_update(bgp, __func__);
#endif
	}

	vpn_policy_routemap_event(rmap_name);
}

int bgp_route_map_update_timer(struct thread *thread)
{
	bm->t_rmap_update = NULL;

	route_map_walk_update_list(bgp_route_map_process_update_cb);

	return (0);
}

static void bgp_route_map_mark_update(const char *rmap_name)
{
	if (bm->t_rmap_update == NULL) {
		struct listnode *node, *nnode;
		struct bgp *bgp;

		/* rmap_update_timer of 0 means don't do route updates */
		if (bm->rmap_update_timer) {
			bm->t_rmap_update = NULL;
			thread_add_timer(bm->master, bgp_route_map_update_timer,
					 NULL, bm->rmap_update_timer,
					 &bm->t_rmap_update);

			/* Signal the groups that a route-map update event has
			 * started */
			for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
				update_group_policy_update(bgp,
							   BGP_POLICY_ROUTE_MAP,
							   rmap_name, 1, 1);
		} else {
			for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
				bgp_route_map_process_update(bgp, rmap_name, 0);
#if ENABLE_BGP_VNC
			zlog_debug("%s: calling vnc_routemap_update", __func__);
			vnc_routemap_update(bgp, __func__);
#endif
		}
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

static void bgp_route_map_event(route_map_event_t event, const char *rmap_name)
{
	if (route_map_mark_updated(rmap_name) == 0)
		bgp_route_map_mark_update(rmap_name);

	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_ADDED);
}

DEFUN (match_mac_address,
       match_mac_address_cmd,
       "match mac address WORD",
       MATCH_STR
       "mac address\n"
       "Match address of route\n"
       "MAC Access-list name\n")
{
	return bgp_route_match_add(vty, "mac address", argv[3]->arg,
				   RMAP_EVENT_FILTER_ADDED);
}

DEFUN (no_match_mac_address,
       no_match_mac_address_cmd,
       "no match mac address WORD",
       NO_STR
       MATCH_STR
       "mac\n"
       "Match address of route\n"
       "MAC acess-list name\n")
{
	return bgp_route_match_delete(vty, "mac address", argv[4]->arg,
				      RMAP_EVENT_FILTER_DELETED);
}

DEFUN (match_evpn_route_type,
       match_evpn_route_type_cmd,
       "match evpn route-type <macip | multicast | prefix>",
       MATCH_STR
       EVPN_HELP_STR
       "Match route-type\n"
       "mac-ip route\n"
       "IMET route\n"
       "prefix route\n")
{
	return bgp_route_match_add(vty, "evpn route-type", argv[3]->arg,
				   RMAP_EVENT_MATCH_ADDED);
}

DEFUN (no_match_evpn_route_type,
       no_match_evpn_route_type_cmd,
       "no match evpn route-type <macip | multicast | prefix>",
       NO_STR
       MATCH_STR
       EVPN_HELP_STR
       "Match route-type\n"
       "mac-ip route\n"
       "IMET route\n"
       "prefix route\n")
{
	return bgp_route_match_delete(vty, "evpn route-type", argv[4]->arg,
				      RMAP_EVENT_MATCH_DELETED);
}


DEFUN (match_evpn_vni,
       match_evpn_vni_cmd,
       "match evpn vni (1-16777215)",
       MATCH_STR
       EVPN_HELP_STR
       "Match VNI\n"
       "VNI ID\n")
{
	return bgp_route_match_add(vty, "evpn vni", argv[3]->arg,
				   RMAP_EVENT_MATCH_ADDED);
}

DEFUN (no_match_evpn_vni,
       no_match_evpn_vni_cmd,
       "no match evpn vni (1-16777215)",
       NO_STR
       MATCH_STR
       EVPN_HELP_STR
       "Match VNI\n"
       "VNI ID\n")
{
	return bgp_route_match_delete(vty, "evpn vni", argv[4]->arg,
				      RMAP_EVENT_MATCH_DELETED);
}

DEFUN (match_evpn_default_route,
       match_evpn_default_route_cmd,
       "match evpn default-route",
       MATCH_STR
       EVPN_HELP_STR
       "default EVPN type-5 route\n")
{
	return bgp_route_match_add(vty, "evpn default-route", NULL,
				   RMAP_EVENT_MATCH_ADDED);
}

DEFUN (no_match_evpn_default_route,
       no_match_evpn_default_route_cmd,
       "no match evpn default-route",
       NO_STR
       MATCH_STR
       EVPN_HELP_STR
       "default EVPN type-5 route\n")
{
	return bgp_route_match_delete(vty, "evpn default-route", NULL,
				      RMAP_EVENT_MATCH_DELETED);
}

DEFUN (match_peer,
       match_peer_cmd,
       "match peer <A.B.C.D|X:X::X:X|WORD>",
       MATCH_STR
       "Match peer address\n"
       "IP address of peer\n"
       "IPv6 address of peer\n"
       "Interface name of peer\n")
{
	int idx_ip = 2;
	return bgp_route_match_add(vty, "peer", argv[idx_ip]->arg,
				   RMAP_EVENT_MATCH_ADDED);
}

DEFUN (match_peer_local,
       match_peer_local_cmd,
        "match peer local",
        MATCH_STR
        "Match peer address\n"
        "Static or Redistributed routes\n")
{
	return bgp_route_match_add(vty, "peer", "local",
				   RMAP_EVENT_MATCH_DELETED);
}

DEFUN (no_match_peer,
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
	int idx_peer = 3;

	if (argc <= idx_peer)
		return bgp_route_match_delete(vty, "peer", NULL,
					      RMAP_EVENT_MATCH_DELETED);
	return bgp_route_match_delete(vty, "peer", argv[idx_peer]->arg,
				      RMAP_EVENT_MATCH_DELETED);
}


/* match probability */
DEFUN (match_probability,
       match_probability_cmd,
       "match probability (0-100)",
       MATCH_STR
       "Match portion of routes defined by percentage value\n"
       "Percentage of routes\n")
{
	int idx_number = 2;
	return bgp_route_match_add(vty, "probability", argv[idx_number]->arg,
				   RMAP_EVENT_MATCH_ADDED);
}


DEFUN (no_match_probability,
       no_match_probability_cmd,
       "no match probability [(1-99)]",
       NO_STR
       MATCH_STR
       "Match portion of routes defined by percentage value\n"
       "Percentage of routes\n")
{
	int idx_number = 3;
	if (argc <= idx_number)
		return bgp_route_match_delete(vty, "probability", NULL,
					      RMAP_EVENT_MATCH_DELETED);
	return bgp_route_match_delete(vty, "probability", argv[idx_number]->arg,
				      RMAP_EVENT_MATCH_DELETED);
}


DEFUN (match_ip_route_source,
       match_ip_route_source_cmd,
       "match ip route-source <(1-199)|(1300-2699)|WORD>",
       MATCH_STR
       IP_STR
       "Match advertising source address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP standard access-list name\n")
{
	int idx_acl = 3;
	return bgp_route_match_add(vty, "ip route-source", argv[idx_acl]->arg,
				   RMAP_EVENT_FILTER_ADDED);
}


DEFUN (no_match_ip_route_source,
       no_match_ip_route_source_cmd,
       "no match ip route-source [<(1-199)|(1300-2699)|WORD>]",
       NO_STR
       MATCH_STR
       IP_STR
       "Match advertising source address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP standard access-list name\n")
{
	int idx_number = 4;
	if (argc <= idx_number)
		return bgp_route_match_delete(vty, "ip route-source", NULL,
					      RMAP_EVENT_FILTER_DELETED);
	return bgp_route_match_delete(vty, "ip route-source",
				      argv[idx_number]->arg,
				      RMAP_EVENT_FILTER_DELETED);
}


DEFUN (match_ip_route_source_prefix_list,
       match_ip_route_source_prefix_list_cmd,
       "match ip route-source prefix-list WORD",
       MATCH_STR
       IP_STR
       "Match advertising source address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
	int idx_word = 4;
	return bgp_route_match_add(vty, "ip route-source prefix-list",
				   argv[idx_word]->arg, RMAP_EVENT_PLIST_ADDED);
}


DEFUN (no_match_ip_route_source_prefix_list,
       no_match_ip_route_source_prefix_list_cmd,
       "no match ip route-source prefix-list [WORD]",
       NO_STR
       MATCH_STR
       IP_STR
       "Match advertising source address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
	int idx_word = 5;
	if (argc <= idx_word)
		return bgp_route_match_delete(vty,
					      "ip route-source prefix-list",
					      NULL, RMAP_EVENT_PLIST_DELETED);
	return bgp_route_match_delete(vty, "ip route-source prefix-list",
				      argv[idx_word]->arg,
				      RMAP_EVENT_PLIST_DELETED);
}


DEFUN (match_local_pref,
       match_local_pref_cmd,
       "match local-preference (0-4294967295)",
       MATCH_STR
       "Match local-preference of route\n"
       "Metric value\n")
{
	int idx_number = 2;
	return bgp_route_match_add(vty, "local-preference",
				   argv[idx_number]->arg,
				   RMAP_EVENT_MATCH_ADDED);
}


DEFUN (no_match_local_pref,
       no_match_local_pref_cmd,
       "no match local-preference [(0-4294967295)]",
       NO_STR
       MATCH_STR
       "Match local preference of route\n"
       "Local preference value\n")
{
	int idx_localpref = 3;
	if (argc <= idx_localpref)
		return bgp_route_match_delete(vty, "local-preference", NULL,
					      RMAP_EVENT_MATCH_DELETED);
	return bgp_route_match_delete(vty, "local-preference",
				      argv[idx_localpref]->arg,
				      RMAP_EVENT_MATCH_DELETED);
}


DEFUN (match_community,
       match_community_cmd,
       "match community <(1-99)|(100-500)|WORD> [exact-match]",
       MATCH_STR
       "Match BGP community list\n"
       "Community-list number (standard)\n"
       "Community-list number (expanded)\n"
       "Community-list name\n"
       "Do exact matching of communities\n")
{
	int idx_comm_list = 2;
	int ret;
	char *argstr;

	if (argc == 4) {
		argstr = XMALLOC(MTYPE_ROUTE_MAP_COMPILED,
				 strlen(argv[idx_comm_list]->arg)
					 + strlen("exact-match") + 2);

		sprintf(argstr, "%s exact-match", argv[idx_comm_list]->arg);
	} else
		argstr = argv[idx_comm_list]->arg;

	ret = bgp_route_match_add(vty, "community", argstr,
				  RMAP_EVENT_CLIST_ADDED);

	if (argstr != argv[idx_comm_list]->arg)
		XFREE(MTYPE_ROUTE_MAP_COMPILED, argstr);

	return ret;
}

DEFUN (no_match_community,
       no_match_community_cmd,
       "no match community [<(1-99)|(100-500)|WORD> [exact-match]]",
       NO_STR
       MATCH_STR
       "Match BGP community list\n"
       "Community-list number (standard)\n"
       "Community-list number (expanded)\n"
       "Community-list name\n"
       "Do exact matching of communities\n")
{
	return bgp_route_match_delete(vty, "community", NULL,
				      RMAP_EVENT_CLIST_DELETED);
}

DEFUN (match_lcommunity,
       match_lcommunity_cmd,
       "match large-community <(1-99)|(100-500)|WORD>",
       MATCH_STR
       "Match BGP large community list\n"
       "Large Community-list number (standard)\n"
       "Large Community-list number (expanded)\n"
       "Large Community-list name\n")
{
	return bgp_route_match_add(vty, "large-community", argv[2]->arg,
				   RMAP_EVENT_LLIST_ADDED);
}

DEFUN (no_match_lcommunity,
       no_match_lcommunity_cmd,
       "no match large-community [<(1-99)|(100-500)|WORD>]",
       NO_STR
       MATCH_STR
       "Match BGP large community list\n"
       "Large Community-list number (standard)\n"
       "Large Community-list number (expanded)\n"
       "Large Community-list name\n")
{
	return bgp_route_match_delete(vty, "large-community", NULL,
				      RMAP_EVENT_LLIST_DELETED);
}

DEFUN (match_ecommunity,
       match_ecommunity_cmd,
       "match extcommunity <(1-99)|(100-500)|WORD>",
       MATCH_STR
       "Match BGP/VPN extended community list\n"
       "Extended community-list number (standard)\n"
       "Extended community-list number (expanded)\n"
       "Extended community-list name\n")
{
	int idx_comm_list = 2;
	return bgp_route_match_add(vty, "extcommunity",
				   argv[idx_comm_list]->arg,
				   RMAP_EVENT_ECLIST_ADDED);
}


DEFUN (no_match_ecommunity,
       no_match_ecommunity_cmd,
       "no match extcommunity [<(1-99)|(100-500)|WORD>]",
       NO_STR
       MATCH_STR
       "Match BGP/VPN extended community list\n"
       "Extended community-list number (standard)\n"
       "Extended community-list number (expanded)\n"
       "Extended community-list name\n")
{
	return bgp_route_match_delete(vty, "extcommunity", NULL,
				      RMAP_EVENT_ECLIST_DELETED);
}


DEFUN (match_aspath,
       match_aspath_cmd,
       "match as-path WORD",
       MATCH_STR
       "Match BGP AS path list\n"
       "AS path access-list name\n")
{
	int idx_word = 2;
	return bgp_route_match_add(vty, "as-path", argv[idx_word]->arg,
				   RMAP_EVENT_ASLIST_ADDED);
}


DEFUN (no_match_aspath,
       no_match_aspath_cmd,
       "no match as-path [WORD]",
       NO_STR
       MATCH_STR
       "Match BGP AS path list\n"
       "AS path access-list name\n")
{
	return bgp_route_match_delete(vty, "as-path", NULL,
				      RMAP_EVENT_ASLIST_DELETED);
}


DEFUN (match_origin,
       match_origin_cmd,
       "match origin <egp|igp|incomplete>",
       MATCH_STR
       "BGP origin code\n"
       "remote EGP\n"
       "local IGP\n"
       "unknown heritage\n")
{
	int idx_origin = 2;
	if (strncmp(argv[idx_origin]->arg, "igp", 2) == 0)
		return bgp_route_match_add(vty, "origin", "igp",
					   RMAP_EVENT_MATCH_ADDED);
	if (strncmp(argv[idx_origin]->arg, "egp", 1) == 0)
		return bgp_route_match_add(vty, "origin", "egp",
					   RMAP_EVENT_MATCH_ADDED);
	if (strncmp(argv[idx_origin]->arg, "incomplete", 2) == 0)
		return bgp_route_match_add(vty, "origin", "incomplete",
					   RMAP_EVENT_MATCH_ADDED);

	vty_out(vty, "%% Invalid match origin type\n");
	return CMD_WARNING_CONFIG_FAILED;
}


DEFUN (no_match_origin,
       no_match_origin_cmd,
       "no match origin [<egp|igp|incomplete>]",
       NO_STR
       MATCH_STR
       "BGP origin code\n"
       "remote EGP\n"
       "local IGP\n"
       "unknown heritage\n")
{
	return bgp_route_match_delete(vty, "origin", NULL,
				      RMAP_EVENT_MATCH_DELETED);
}

DEFUN (set_ip_nexthop_peer,
       set_ip_nexthop_peer_cmd,
       "[no] set ip next-hop peer-address",
       NO_STR
       SET_STR
       IP_STR
       "Next hop address\n"
       "Use peer address (for BGP only)\n")
{
	int (*func)(struct vty *, struct route_map_index *, const char *,
		    const char *) = strmatch(argv[0]->text, "no")
					    ? generic_set_delete
					    : generic_set_add;

	return func(vty, VTY_GET_CONTEXT(route_map_index), "ip next-hop",
		    "peer-address");
}

DEFUN (set_ip_nexthop_unchanged,
       set_ip_nexthop_unchanged_cmd,
       "[no] set ip next-hop unchanged",
       NO_STR
       SET_STR
       IP_STR
       "Next hop address\n"
       "Don't modify existing Next hop address\n")
{
	int (*func)(struct vty *, struct route_map_index *, const char *,
		    const char *) = strmatch(argv[0]->text, "no")
					    ? generic_set_delete
					    : generic_set_add;

	return func(vty, VTY_GET_CONTEXT(route_map_index), "ip next-hop",
		    "unchanged");
}


DEFUN (set_local_pref,
       set_local_pref_cmd,
       "set local-preference (0-4294967295)",
       SET_STR
       "BGP local preference path attribute\n"
       "Preference value\n")
{
	int idx_number = 2;
	return generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
			       "local-preference", argv[idx_number]->arg);
}


DEFUN (no_set_local_pref,
       no_set_local_pref_cmd,
       "no set local-preference [(0-4294967295)]",
       NO_STR
       SET_STR
       "BGP local preference path attribute\n"
       "Preference value\n")
{
	int idx_localpref = 3;
	if (argc <= idx_localpref)
		return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
					  "local-preference", NULL);
	return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				  "local-preference", argv[idx_localpref]->arg);
}


DEFUN (set_weight,
       set_weight_cmd,
       "set weight (0-4294967295)",
       SET_STR
       "BGP weight for routing table\n"
       "Weight value\n")
{
	int idx_number = 2;
	return generic_set_add(vty, VTY_GET_CONTEXT(route_map_index), "weight",
			       argv[idx_number]->arg);
}


DEFUN (no_set_weight,
       no_set_weight_cmd,
       "no set weight [(0-4294967295)]",
       NO_STR
       SET_STR
       "BGP weight for routing table\n"
       "Weight value\n")
{
	int idx_weight = 3;
	if (argc <= idx_weight)
		return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
					  "weight", NULL);
	return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				  "weight", argv[idx_weight]->arg);
}

DEFUN (set_label_index,
       set_label_index_cmd,
       "set label-index (0-1048560)",
       SET_STR
       "Label index to associate with the prefix\n"
       "Label index value\n")
{
	int idx_number = 2;
	return generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
			       "label-index", argv[idx_number]->arg);
}

DEFUN (no_set_label_index,
       no_set_label_index_cmd,
       "no set label-index [(0-1048560)]",
       NO_STR
       SET_STR
       "Label index to associate with the prefix\n"
       "Label index value\n")
{
	int idx_label_index = 3;
	if (argc <= idx_label_index)
		return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
					  "label-index", NULL);
	return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				  "label-index", argv[idx_label_index]->arg);
}

DEFUN (set_aspath_prepend_asn,
       set_aspath_prepend_asn_cmd,
       "set as-path prepend (1-4294967295)...",
       SET_STR
       "Transform BGP AS_PATH attribute\n"
       "Prepend to the as-path\n"
       "AS number\n")
{
	int idx_asn = 3;
	int ret;
	char *str;

	str = argv_concat(argv, argc, idx_asn);
	ret = generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
			      "as-path prepend", str);
	XFREE(MTYPE_TMP, str);

	return ret;
}

DEFUN (set_aspath_prepend_lastas,
       set_aspath_prepend_lastas_cmd,
       "set as-path prepend last-as (1-10)",
       SET_STR
       "Transform BGP AS_PATH attribute\n"
       "Prepend to the as-path\n"
       "Use the peer's AS-number\n"
       "Number of times to insert\n")
{
	return set_aspath_prepend_asn(self, vty, argc, argv);
}

DEFUN (no_set_aspath_prepend,
       no_set_aspath_prepend_cmd,
       "no set as-path prepend [(1-4294967295)]",
       NO_STR
       SET_STR
       "Transform BGP AS_PATH attribute\n"
       "Prepend to the as-path\n"
       "AS number\n")
{
	int idx_asn = 4;
	int ret;
	char *str;

	str = argv_concat(argv, argc, idx_asn);
	ret = generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				 "as-path prepend", str);
	XFREE(MTYPE_TMP, str);
	return ret;
}


DEFUN (set_aspath_exclude,
       set_aspath_exclude_cmd,
       "set as-path exclude (1-4294967295)...",
       SET_STR
       "Transform BGP AS-path attribute\n"
       "Exclude from the as-path\n"
       "AS number\n")
{
	int idx_asn = 3;
	int ret;
	char *str;

	str = argv_concat(argv, argc, idx_asn);
	ret = generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
			      "as-path exclude", str);
	XFREE(MTYPE_TMP, str);
	return ret;
}

DEFUN (no_set_aspath_exclude,
       no_set_aspath_exclude_cmd,
       "no set as-path exclude (1-4294967295)...",
       NO_STR
       SET_STR
       "Transform BGP AS_PATH attribute\n"
       "Exclude from the as-path\n"
       "AS number\n")
{
	int idx_asn = 4;
	int ret;
	char *str;

	str = argv_concat(argv, argc, idx_asn);
	ret = generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				 "as-path exclude", str);
	XFREE(MTYPE_TMP, str);
	return ret;
}


DEFUN (set_community,
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
	char *argstr;
	int ret;

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

		if (strncmp(argv[i]->arg, "internet", strlen(argv[i]->arg))
		    == 0) {
			buffer_putstr(b, "internet");
			continue;
		}
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

	if (str) {
		com = community_str2com(str);
		XFREE(MTYPE_TMP, str);
	}

	/* Can't compile user input into communities attribute.  */
	if (!com) {
		vty_out(vty, "%% Malformed communities attribute\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Set communites attribute string.  */
	str = community_str(com, false);

	if (additive) {
		argstr = XCALLOC(MTYPE_TMP,
				 strlen(str) + strlen(" additive") + 1);
		strcpy(argstr, str);
		strcpy(argstr + strlen(str), " additive");
		ret = generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
				      "community", argstr);
		XFREE(MTYPE_TMP, argstr);
	} else
		ret = generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
				      "community", str);

	community_free(com);

	return ret;
}

DEFUN (set_community_none,
       set_community_none_cmd,
       "set community none",
       SET_STR
       "BGP community attribute\n"
       "No community attribute\n")
{
	return generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
			       "community", "none");
}

DEFUN (no_set_community,
       no_set_community_cmd,
       "no set community AA:NN...",
       NO_STR
       SET_STR
       "BGP community attribute\n"
       COMMUNITY_VAL_STR)
{
	return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				  "community", NULL);
}


DEFUN (set_community_delete,
       set_community_delete_cmd,
       "set comm-list <(1-99)|(100-500)|WORD> delete",
       SET_STR
       "set BGP community list (for deletion)\n"
       "Community-list number (standard)\n"
       "Community-list number (expanded)\n"
       "Community-list name\n"
       "Delete matching communities\n")
{
	int idx_comm_list = 2;
	char *str;

	str = XCALLOC(MTYPE_TMP,
		      strlen(argv[idx_comm_list]->arg) + strlen(" delete") + 1);
	strcpy(str, argv[idx_comm_list]->arg);
	strcpy(str + strlen(argv[idx_comm_list]->arg), " delete");

	generic_set_add(vty, VTY_GET_CONTEXT(route_map_index), "comm-list",
			str);

	XFREE(MTYPE_TMP, str);
	return CMD_SUCCESS;
}

DEFUN (no_set_community_delete,
       no_set_community_delete_cmd,
       "no set comm-list [<(1-99)|(100-500)|WORD> delete]",
       NO_STR
       SET_STR
       "set BGP community list (for deletion)\n"
       "Community-list number (standard)\n"
       "Community-list number (expanded)\n"
       "Community-list name\n"
       "Delete matching communities\n")
{
	return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				  "comm-list", NULL);
}

DEFUN (set_lcommunity,
       set_lcommunity_cmd,
       "set large-community AA:BB:CC...",
       SET_STR
       "BGP large community attribute\n"
       "Large Community number in aa:bb:cc format or additive\n")
{
	int ret;
	char *str;

	str = argv_concat(argv, argc, 2);
	ret = generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
			      "large-community", str);
	XFREE(MTYPE_TMP, str);

	return ret;
}

DEFUN (set_lcommunity_none,
       set_lcommunity_none_cmd,
       "set large-community none",
       SET_STR
       "BGP large community attribute\n"
       "No large community attribute\n")
{
	return generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
			       "large-community", "none");
}

DEFUN (no_set_lcommunity,
       no_set_lcommunity_cmd,
       "no set large-community none",
       NO_STR
       SET_STR
       "BGP large community attribute\n"
       "No community attribute\n")
{
	return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				  "large-community", NULL);
}

DEFUN (no_set_lcommunity1,
       no_set_lcommunity1_cmd,
       "no set large-community AA:BB:CC...",
       NO_STR
       SET_STR
       "BGP large community attribute\n"
       "Large community in AA:BB:CC... format or additive\n")
{
	return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				  "large-community", NULL);
}

DEFUN (set_lcommunity_delete,
       set_lcommunity_delete_cmd,
       "set large-comm-list <(1-99)|(100-500)|WORD> delete",
       SET_STR
       "set BGP large community list (for deletion)\n"
       "Large Community-list number (standard)\n"
       "Large Communitly-list number (expanded)\n"
       "Large Community-list name\n"
       "Delete matching large communities\n")
{
	char *str;

	str = XCALLOC(MTYPE_TMP, strlen(argv[2]->arg) + strlen(" delete") + 1);
	strcpy(str, argv[2]->arg);
	strcpy(str + strlen(argv[2]->arg), " delete");

	generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
			"large-comm-list", str);

	XFREE(MTYPE_TMP, str);
	return CMD_SUCCESS;
}

DEFUN (no_set_lcommunity_delete,
       no_set_lcommunity_delete_cmd,
       "no set large-comm-list <(1-99)|(100-500)|WORD> [delete]",
       NO_STR
       SET_STR
       "set BGP large community list (for deletion)\n"
       "Large Community-list number (standard)\n"
       "Large Communitly-list number (expanded)\n"
       "Large Community-list name\n"
       "Delete matching large communities\n")
{
	return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				  "large-comm-list", NULL);
}

DEFUN (set_ecommunity_rt,
       set_ecommunity_rt_cmd,
       "set extcommunity rt ASN:NN_OR_IP-ADDRESS:NN...",
       SET_STR
       "BGP extended community attribute\n"
       "Route Target extended community\n"
       "VPN extended community\n")
{
	int idx_asn_nn = 3;
	int ret;
	char *str;

	str = argv_concat(argv, argc, idx_asn_nn);
	ret = generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
			      "extcommunity rt", str);
	XFREE(MTYPE_TMP, str);

	return ret;
}

DEFUN (no_set_ecommunity_rt,
       no_set_ecommunity_rt_cmd,
       "no set extcommunity rt ASN:NN_OR_IP-ADDRESS:NN...",
       NO_STR
       SET_STR
       "BGP extended community attribute\n"
       "Route Target extended community\n"
       "VPN extended community\n")
{
	return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				  "extcommunity rt", NULL);
}


DEFUN (set_ecommunity_soo,
       set_ecommunity_soo_cmd,
       "set extcommunity soo ASN:NN_OR_IP-ADDRESS:NN...",
       SET_STR
       "BGP extended community attribute\n"
       "Site-of-Origin extended community\n"
       "VPN extended community\n")
{
	int idx_asn_nn = 3;
	int ret;
	char *str;

	str = argv_concat(argv, argc, idx_asn_nn);
	ret = generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
			      "extcommunity soo", str);
	XFREE(MTYPE_TMP, str);
	return ret;
}


DEFUN (no_set_ecommunity_soo,
       no_set_ecommunity_soo_cmd,
       "no set extcommunity soo ASN:NN_OR_IP-ADDRESS:NN...",
       NO_STR
       SET_STR
       "BGP extended community attribute\n"
       "Site-of-Origin extended community\n"
       "VPN extended community\n")
{
	return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				  "extcommunity soo", NULL);
}


DEFUN (set_origin,
       set_origin_cmd,
       "set origin <egp|igp|incomplete>",
       SET_STR
       "BGP origin code\n"
       "remote EGP\n"
       "local IGP\n"
       "unknown heritage\n")
{
	int idx_origin = 2;
	if (strncmp(argv[idx_origin]->arg, "igp", 2) == 0)
		return generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
				       "origin", "igp");
	if (strncmp(argv[idx_origin]->arg, "egp", 1) == 0)
		return generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
				       "origin", "egp");
	if (strncmp(argv[idx_origin]->arg, "incomplete", 2) == 0)
		return generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
				       "origin", "incomplete");

	vty_out(vty, "%% Invalid set origin type\n");
	return CMD_WARNING_CONFIG_FAILED;
}


DEFUN (no_set_origin,
       no_set_origin_cmd,
       "no set origin [<egp|igp|incomplete>]",
       NO_STR
       SET_STR
       "BGP origin code\n"
       "remote EGP\n"
       "local IGP\n"
       "unknown heritage\n")
{
	return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				  "origin", NULL);
}


DEFUN (set_atomic_aggregate,
       set_atomic_aggregate_cmd,
       "set atomic-aggregate",
       SET_STR
       "BGP atomic aggregate attribute\n" )
{
	return generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
			       "atomic-aggregate", NULL);
}

DEFUN (no_set_atomic_aggregate,
       no_set_atomic_aggregate_cmd,
       "no set atomic-aggregate",
       NO_STR
       SET_STR
       "BGP atomic aggregate attribute\n" )
{
	return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				  "atomic-aggregate", NULL);
}

DEFUN (set_aggregator_as,
       set_aggregator_as_cmd,
       "set aggregator as (1-4294967295) A.B.C.D",
       SET_STR
       "BGP aggregator attribute\n"
       "AS number of aggregator\n"
       "AS number\n"
       "IP address of aggregator\n")
{
	int idx_number = 3;
	int idx_ipv4 = 4;
	int ret;
	struct in_addr address;
	char *argstr;

	ret = inet_aton(argv[idx_ipv4]->arg, &address);
	if (ret == 0) {
		vty_out(vty, "Aggregator IP address is invalid\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	argstr = XMALLOC(MTYPE_ROUTE_MAP_COMPILED,
			 strlen(argv[idx_number]->arg)
				 + strlen(argv[idx_ipv4]->arg) + 2);

	sprintf(argstr, "%s %s", argv[idx_number]->arg, argv[idx_ipv4]->arg);

	ret = generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
			      "aggregator as", argstr);

	XFREE(MTYPE_ROUTE_MAP_COMPILED, argstr);

	return ret;
}


DEFUN (no_set_aggregator_as,
       no_set_aggregator_as_cmd,
       "no set aggregator as [(1-4294967295) A.B.C.D]",
       NO_STR
       SET_STR
       "BGP aggregator attribute\n"
       "AS number of aggregator\n"
       "AS number\n"
       "IP address of aggregator\n")
{
	int idx_asn = 4;
	int idx_ip = 5;
	int ret;
	struct in_addr address;
	char *argstr;

	if (argc <= idx_asn)
		return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
					  "aggregator as", NULL);

	ret = inet_aton(argv[idx_ip]->arg, &address);
	if (ret == 0) {
		vty_out(vty, "Aggregator IP address is invalid\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	argstr = XMALLOC(MTYPE_ROUTE_MAP_COMPILED,
			 strlen(argv[idx_asn]->arg) + strlen(argv[idx_ip]->arg)
				 + 2);

	sprintf(argstr, "%s %s", argv[idx_asn]->arg, argv[idx_ip]->arg);

	ret = generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				 "aggregator as", argstr);

	XFREE(MTYPE_ROUTE_MAP_COMPILED, argstr);

	return ret;
}

DEFUN (match_ipv6_next_hop,
       match_ipv6_next_hop_cmd,
       "match ipv6 next-hop X:X::X:X",
       MATCH_STR
       IPV6_STR
       "Match IPv6 next-hop address of route\n"
       "IPv6 address of next hop\n")
{
	int idx_ipv6 = 3;
	return bgp_route_match_add(vty, "ipv6 next-hop", argv[idx_ipv6]->arg,
				   RMAP_EVENT_MATCH_ADDED);
}

DEFUN (no_match_ipv6_next_hop,
       no_match_ipv6_next_hop_cmd,
       "no match ipv6 next-hop X:X::X:X",
       NO_STR
       MATCH_STR
       IPV6_STR
       "Match IPv6 next-hop address of route\n"
       "IPv6 address of next hop\n")
{
	int idx_ipv6 = 4;
	return bgp_route_match_delete(vty, "ipv6 next-hop", argv[idx_ipv6]->arg,
				      RMAP_EVENT_MATCH_DELETED);
}


DEFUN (set_ipv6_nexthop_peer,
       set_ipv6_nexthop_peer_cmd,
       "set ipv6 next-hop peer-address",
       SET_STR
       IPV6_STR
       "Next hop address\n"
       "Use peer address (for BGP only)\n")
{
	return generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
			       "ipv6 next-hop peer-address", NULL);
}

DEFUN (no_set_ipv6_nexthop_peer,
       no_set_ipv6_nexthop_peer_cmd,
       "no set ipv6 next-hop peer-address",
       NO_STR
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "Use peer address (for BGP only)\n")
{
	return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				  "ipv6 next-hop peer-address", NULL);
}

DEFUN (set_ipv6_nexthop_prefer_global,
       set_ipv6_nexthop_prefer_global_cmd,
       "set ipv6 next-hop prefer-global",
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "Prefer global over link-local if both exist\n")
{
	return generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
			       "ipv6 next-hop prefer-global", NULL);
	;
}

DEFUN (no_set_ipv6_nexthop_prefer_global,
       no_set_ipv6_nexthop_prefer_global_cmd,
       "no set ipv6 next-hop prefer-global",
       NO_STR
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "Prefer global over link-local if both exist\n")
{
	return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				  "ipv6 next-hop prefer-global", NULL);
}

DEFUN (set_ipv6_nexthop_global,
       set_ipv6_nexthop_global_cmd,
       "set ipv6 next-hop global X:X::X:X",
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 global address\n"
       "IPv6 address of next hop\n")
{
	int idx_ipv6 = 4;
	struct in6_addr addr;
	int ret;

	ret = inet_pton(AF_INET6, argv[idx_ipv6]->arg, &addr);
	if (!ret) {
		vty_out(vty, "%% Malformed nexthop address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (IN6_IS_ADDR_UNSPECIFIED(&addr) || IN6_IS_ADDR_LOOPBACK(&addr)
	    || IN6_IS_ADDR_MULTICAST(&addr) || IN6_IS_ADDR_LINKLOCAL(&addr)) {
		vty_out(vty, "%% Invalid global nexthop address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
			       "ipv6 next-hop global", argv[idx_ipv6]->arg);
}


DEFUN (no_set_ipv6_nexthop_global,
       no_set_ipv6_nexthop_global_cmd,
       "no set ipv6 next-hop global X:X::X:X",
       NO_STR
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 global address\n"
       "IPv6 address of next hop\n")
{
	int idx_ipv6 = 5;
	if (argc <= idx_ipv6)
		return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
					  "ipv6 next-hop global", NULL);
	return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				  "ipv6 next-hop global", argv[idx_ipv6]->arg);
}

#ifdef KEEP_OLD_VPN_COMMANDS
DEFUN (set_vpn_nexthop,
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

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
		if (afi == AFI_IP)
			return generic_set_add(
				vty, VTY_GET_CONTEXT(route_map_index),
				"ipv4 vpn next-hop", argv[idx_ip]->arg);
		else
			return generic_set_add(
				vty, VTY_GET_CONTEXT(route_map_index),
				"ipv6 vpn next-hop", argv[idx_ip]->arg);
	}
	return CMD_SUCCESS;
}

DEFUN (no_set_vpn_nexthop,
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
	int idx_ip = 4;
	char *arg;
	afi_t afi;
	int idx = 0;

	if (argc <= idx_ip)
		arg = NULL;
	else
		arg = argv[idx_ip]->arg;
	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
		if (afi == AFI_IP)
			return generic_set_delete(
				vty, VTY_GET_CONTEXT(route_map_index),
				"ipv4 vpn next-hop", arg);
		else
			return generic_set_delete(
				vty, VTY_GET_CONTEXT(route_map_index),
				"ipv6 vpn next-hop", argv[idx_ip]->arg);
	}
	return CMD_SUCCESS;
}
#endif /* KEEP_OLD_VPN_COMMANDS */

DEFUN (set_ipx_vpn_nexthop,
       set_ipx_vpn_nexthop_cmd,
       "set <ipv4|ipv6> vpn next-hop <A.B.C.D|X:X::X:X>",
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

	if (argv_find_and_parse_afi(argv, argc, &idx, &afi)) {
		if (afi == AFI_IP)
			return generic_set_add(
				vty, VTY_GET_CONTEXT(route_map_index),
				"ipv4 vpn next-hop", argv[idx_ip]->arg);
		else
			return generic_set_add(
				vty, VTY_GET_CONTEXT(route_map_index),
				"ipv6 vpn next-hop", argv[idx_ip]->arg);
	}
	return CMD_SUCCESS;
}

DEFUN (no_set_ipx_vpn_nexthop,
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
	int idx_ip = 5;
	char *arg;
	afi_t afi;
	int idx = 0;

	if (argc <= idx_ip)
		arg = NULL;
	else
		arg = argv[idx_ip]->arg;
	if (argv_find_and_parse_afi(argv, argc, &idx, &afi)) {
		if (afi == AFI_IP)
			return generic_set_delete(
				vty, VTY_GET_CONTEXT(route_map_index),
				"ipv4 vpn next-hop", arg);
		else
			return generic_set_delete(
				vty, VTY_GET_CONTEXT(route_map_index),
				"ipv6 vpn next-hop", arg);
	}
	return CMD_SUCCESS;
}

DEFUN (set_originator_id,
       set_originator_id_cmd,
       "set originator-id A.B.C.D",
       SET_STR
       "BGP originator ID attribute\n"
       "IP address of originator\n")
{
	int idx_ipv4 = 2;
	return generic_set_add(vty, VTY_GET_CONTEXT(route_map_index),
			       "originator-id", argv[idx_ipv4]->arg);
}


DEFUN (no_set_originator_id,
       no_set_originator_id_cmd,
       "no set originator-id [A.B.C.D]",
       NO_STR
       SET_STR
       "BGP originator ID attribute\n"
       "IP address of originator\n")
{
	int idx = 0;
	char *arg =
		argv_find(argv, argc, "A.B.C.D", &idx) ? argv[idx]->arg : NULL;

	return generic_set_delete(vty, VTY_GET_CONTEXT(route_map_index),
				  "originator-id", arg);
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

	route_map_match_ip_next_hop_prefix_list_hook(generic_match_add);
	route_map_no_match_ip_next_hop_prefix_list_hook(generic_match_delete);

	route_map_match_ipv6_address_hook(generic_match_add);
	route_map_no_match_ipv6_address_hook(generic_match_delete);

	route_map_match_ipv6_address_prefix_list_hook(generic_match_add);
	route_map_no_match_ipv6_address_prefix_list_hook(generic_match_delete);

	route_map_match_metric_hook(generic_match_add);
	route_map_no_match_metric_hook(generic_match_delete);

	route_map_match_tag_hook(generic_match_add);
	route_map_no_match_tag_hook(generic_match_delete);

	route_map_set_ip_nexthop_hook(generic_set_add);
	route_map_no_set_ip_nexthop_hook(generic_set_delete);

	route_map_set_ipv6_nexthop_local_hook(generic_set_add);
	route_map_no_set_ipv6_nexthop_local_hook(generic_set_delete);

	route_map_set_metric_hook(generic_set_add);
	route_map_no_set_metric_hook(generic_set_delete);

	route_map_set_tag_hook(generic_set_add);
	route_map_no_set_tag_hook(generic_set_delete);

	route_map_install_match(&route_match_peer_cmd);
	route_map_install_match(&route_match_local_pref_cmd);
	route_map_install_match(&route_match_ip_address_cmd);
	route_map_install_match(&route_match_ip_next_hop_cmd);
	route_map_install_match(&route_match_ip_route_source_cmd);
	route_map_install_match(&route_match_ip_address_prefix_list_cmd);
	route_map_install_match(&route_match_ip_next_hop_prefix_list_cmd);
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
	route_map_install_match(&route_match_evpn_default_route_cmd);

	route_map_install_set(&route_set_ip_nexthop_cmd);
	route_map_install_set(&route_set_local_pref_cmd);
	route_map_install_set(&route_set_weight_cmd);
	route_map_install_set(&route_set_label_index_cmd);
	route_map_install_set(&route_set_metric_cmd);
	route_map_install_set(&route_set_aspath_prepend_cmd);
	route_map_install_set(&route_set_aspath_exclude_cmd);
	route_map_install_set(&route_set_origin_cmd);
	route_map_install_set(&route_set_atomic_aggregate_cmd);
	route_map_install_set(&route_set_aggregator_as_cmd);
	route_map_install_set(&route_set_community_cmd);
	route_map_install_set(&route_set_community_delete_cmd);
	route_map_install_set(&route_set_lcommunity_cmd);
	route_map_install_set(&route_set_lcommunity_delete_cmd);
	route_map_install_set(&route_set_vpnv4_nexthop_cmd);
	route_map_install_set(&route_set_vpnv6_nexthop_cmd);
	route_map_install_set(&route_set_originator_id_cmd);
	route_map_install_set(&route_set_ecommunity_rt_cmd);
	route_map_install_set(&route_set_ecommunity_soo_cmd);
	route_map_install_set(&route_set_tag_cmd);
	route_map_install_set(&route_set_label_index_cmd);

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
	install_element(RMAP_NODE, &match_evpn_default_route_cmd);
	install_element(RMAP_NODE, &no_match_evpn_default_route_cmd);

	install_element(RMAP_NODE, &match_aspath_cmd);
	install_element(RMAP_NODE, &no_match_aspath_cmd);
	install_element(RMAP_NODE, &match_local_pref_cmd);
	install_element(RMAP_NODE, &no_match_local_pref_cmd);
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

	install_element(RMAP_NODE, &set_ip_nexthop_peer_cmd);
	install_element(RMAP_NODE, &set_ip_nexthop_unchanged_cmd);
	install_element(RMAP_NODE, &set_local_pref_cmd);
	install_element(RMAP_NODE, &no_set_local_pref_cmd);
	install_element(RMAP_NODE, &set_weight_cmd);
	install_element(RMAP_NODE, &set_label_index_cmd);
	install_element(RMAP_NODE, &no_set_weight_cmd);
	install_element(RMAP_NODE, &no_set_label_index_cmd);
	install_element(RMAP_NODE, &set_aspath_prepend_asn_cmd);
	install_element(RMAP_NODE, &set_aspath_prepend_lastas_cmd);
	install_element(RMAP_NODE, &set_aspath_exclude_cmd);
	install_element(RMAP_NODE, &no_set_aspath_prepend_cmd);
	install_element(RMAP_NODE, &no_set_aspath_exclude_cmd);
	install_element(RMAP_NODE, &set_origin_cmd);
	install_element(RMAP_NODE, &no_set_origin_cmd);
	install_element(RMAP_NODE, &set_atomic_aggregate_cmd);
	install_element(RMAP_NODE, &no_set_atomic_aggregate_cmd);
	install_element(RMAP_NODE, &set_aggregator_as_cmd);
	install_element(RMAP_NODE, &no_set_aggregator_as_cmd);
	install_element(RMAP_NODE, &set_community_cmd);
	install_element(RMAP_NODE, &set_community_none_cmd);
	install_element(RMAP_NODE, &no_set_community_cmd);
	install_element(RMAP_NODE, &set_community_delete_cmd);
	install_element(RMAP_NODE, &no_set_community_delete_cmd);
	install_element(RMAP_NODE, &set_lcommunity_cmd);
	install_element(RMAP_NODE, &set_lcommunity_none_cmd);
	install_element(RMAP_NODE, &no_set_lcommunity_cmd);
	install_element(RMAP_NODE, &no_set_lcommunity1_cmd);
	install_element(RMAP_NODE, &set_lcommunity_delete_cmd);
	install_element(RMAP_NODE, &no_set_lcommunity_delete_cmd);
	install_element(RMAP_NODE, &set_ecommunity_rt_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_rt_cmd);
	install_element(RMAP_NODE, &set_ecommunity_soo_cmd);
	install_element(RMAP_NODE, &no_set_ecommunity_soo_cmd);
#ifdef KEEP_OLD_VPN_COMMANDS
	install_element(RMAP_NODE, &set_vpn_nexthop_cmd);
	install_element(RMAP_NODE, &no_set_vpn_nexthop_cmd);
#endif /* KEEP_OLD_VPN_COMMANDS */
	install_element(RMAP_NODE, &set_ipx_vpn_nexthop_cmd);
	install_element(RMAP_NODE, &no_set_ipx_vpn_nexthop_cmd);
	install_element(RMAP_NODE, &set_originator_id_cmd);
	install_element(RMAP_NODE, &no_set_originator_id_cmd);

	route_map_install_match(&route_match_ipv6_address_cmd);
	route_map_install_match(&route_match_ipv6_next_hop_cmd);
	route_map_install_match(&route_match_ipv6_address_prefix_list_cmd);
	route_map_install_set(&route_set_ipv6_nexthop_global_cmd);
	route_map_install_set(&route_set_ipv6_nexthop_prefer_global_cmd);
	route_map_install_set(&route_set_ipv6_nexthop_local_cmd);
	route_map_install_set(&route_set_ipv6_nexthop_peer_cmd);

	install_element(RMAP_NODE, &match_ipv6_next_hop_cmd);
	install_element(RMAP_NODE, &no_match_ipv6_next_hop_cmd);
	install_element(RMAP_NODE, &set_ipv6_nexthop_global_cmd);
	install_element(RMAP_NODE, &no_set_ipv6_nexthop_global_cmd);
	install_element(RMAP_NODE, &set_ipv6_nexthop_prefer_global_cmd);
	install_element(RMAP_NODE, &no_set_ipv6_nexthop_prefer_global_cmd);
	install_element(RMAP_NODE, &set_ipv6_nexthop_peer_cmd);
	install_element(RMAP_NODE, &no_set_ipv6_nexthop_peer_cmd);
}

void bgp_route_map_terminate(void)
{
	/* ToDo: Cleanup all the used memory */

	route_map_add_hook(NULL);
	route_map_delete_hook(NULL);
	route_map_event_hook(NULL);
	route_map_finish();
}
