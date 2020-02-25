/*
 * BGP Peer Attribute Unit Tests
 * Copyright (C) 2018  Pascal Mathis
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "memory.h"
#include "plist.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_clist.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_network.h"

#ifdef ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_backend.h"
#endif

#define OUT_SYMBOL_INFO "\u25ba"
#define OUT_SYMBOL_OK "\u2714"
#define OUT_SYMBOL_NOK "\u2716"

#define TEST_ASSERT(T, C)                                                      \
	do {                                                                   \
		if ((T)->state != TEST_SUCCESS || (C))                         \
			break;                                                 \
		(T)->state = TEST_ASSERT_ERROR;                                \
		(T)->error = str_printf("assertion failed: %s (%s:%d)", (#C),  \
					__FILE__, __LINE__);                   \
	} while (0)

#define TEST_ASSERT_EQ(T, A, B)                                                \
	do {                                                                   \
		if ((T)->state != TEST_SUCCESS || ((A) == (B)))                \
			break;                                                 \
		(T)->state = TEST_ASSERT_ERROR;                                \
		(T)->error = str_printf(                                       \
			"assertion failed: %s[%d] == [%d]%s (%s:%d)", (#A),    \
			(A), (B), (#B), __FILE__, __LINE__);                   \
	} while (0)

#define TEST_HANDLER_MAX 5
#define TEST_HANDLER(name) _test_handler_##name
#define TEST_HANDLER_DECL(name)                                                \
	static void _test_handler_##name(                                      \
		struct test *test, struct test_peer_attr *pa,                  \
		struct peer *peer, struct peer *group, bool peer_set,          \
		bool group_set)

#define TEST_ATTR_HANDLER_DECL(name, attr, pval, gval)                         \
	TEST_HANDLER_DECL(name)                                                \
	{                                                                      \
		if (peer_set)                                                  \
			TEST_ASSERT_EQ(test, peer->attr, (pval));              \
		else if (peer_group_active(peer) && group_set)                 \
			TEST_ASSERT_EQ(test, peer->attr, (gval));              \
		if (group_set)                                                 \
			TEST_ASSERT_EQ(test, group->attr, (gval));             \
	}                                                                      \
	TEST_HANDLER_DECL(name)

#define TEST_STR_ATTR_HANDLER_DECL(name, attr, pval, gval)                     \
	TEST_HANDLER_DECL(name)                                                \
	{                                                                      \
		if (peer_set) {                                                \
			TEST_ASSERT(test, peer->attr != NULL);                 \
			TEST_ASSERT(test, !strcmp(peer->attr, (pval)));        \
		} else if (peer_group_active(peer) && group_set) {             \
			TEST_ASSERT(test, peer->attr != NULL);                 \
			TEST_ASSERT(test, !strcmp(peer->attr, (gval)));        \
		}                                                              \
		if (group_set) {                                               \
			TEST_ASSERT(test, group->attr != NULL);                \
			TEST_ASSERT(test, !strcmp(group->attr, (gval)));       \
		}                                                              \
	}                                                                      \
	TEST_HANDLER_DECL(name)

#define TEST_SU_ATTR_HANDLER_DECL(name, attr, pval, gval)                      \
	TEST_HANDLER_DECL(name)                                                \
	{                                                                      \
		union sockunion su;                                            \
		if (peer_set) {                                                \
			str2sockunion(pval, &su);                              \
			TEST_ASSERT(test, !sockunion_cmp(peer->attr, &su));    \
		} else if (peer_group_active(peer) && group_set) {             \
			str2sockunion(gval, &su);                              \
			TEST_ASSERT(test, !sockunion_cmp(group->attr, &su));   \
		}                                                              \
		if (group_set) {                                               \
			str2sockunion(gval, &su);                              \
			TEST_ASSERT(test, !sockunion_cmp(group->attr, &su));   \
		}                                                              \
	}                                                                      \
	TEST_HANDLER_DECL(name)

/* Required variables to link in libbgp */
struct zebra_privs_t bgpd_privs = {0};
struct thread_master *master;

enum test_state {
	TEST_SUCCESS,
	TEST_SKIPPING,
	TEST_COMMAND_ERROR,
	TEST_CONFIG_ERROR,
	TEST_ASSERT_ERROR,
	TEST_CUSTOM_ERROR,
	TEST_INTERNAL_ERROR,
};

enum test_peer_attr_type {
	PEER_AT_AF_FLAG = 0,
	PEER_AT_AF_FILTER = 1,
	PEER_AT_AF_CUSTOM = 2,
	PEER_AT_GLOBAL_FLAG = 3,
	PEER_AT_GLOBAL_CUSTOM = 4
};

struct test {
	enum test_state state;
	char *desc;
	char *error;
	struct list *log;

	struct vty *vty;
	struct bgp *bgp;
	struct peer *peer;
	struct peer_group *group;

	struct {
		bool use_ibgp;
		bool use_iface_peer;
	} o;
};

struct test_config {
	int local_asn;
	int peer_asn;
	const char *peer_address;
	const char *peer_interface;
	const char *peer_group;
};

struct test_peer_family {
	afi_t afi;
	safi_t safi;
};

struct test_peer_attr {
	const char *cmd;
	const char *peer_cmd;
	const char *group_cmd;

	enum test_peer_attr_type type;
	union {
		uint32_t flag;
		struct {
			uint32_t flag;
			size_t direct;
		} filter;
	} u;
	struct {
		bool invert_peer;
		bool invert_group;
		bool use_ibgp;
		bool use_iface_peer;
		bool skip_xfer_cases;
	} o;

	afi_t afi;
	safi_t safi;
	struct test_peer_family families[AFI_MAX * SAFI_MAX];

	void (*handlers[TEST_HANDLER_MAX])(struct test *test,
					   struct test_peer_attr *pa,
					   struct peer *peer,
					   struct peer *group, bool peer_set,
					   bool group_set);
};

static struct test_config cfg = {
	.local_asn = 100,
	.peer_asn = 200,
	.peer_address = "1.1.1.1",
	.peer_interface = "IP-TEST",
	.peer_group = "PG-TEST",
};

static struct test_peer_family test_default_families[] = {
	{.afi = AFI_IP, .safi = SAFI_UNICAST},
	{.afi = AFI_IP, .safi = SAFI_MULTICAST},
	{.afi = AFI_IP6, .safi = SAFI_UNICAST},
	{.afi = AFI_IP6, .safi = SAFI_MULTICAST},
};

static char *str_vprintf(const char *fmt, va_list ap)
{
	int ret;
	int buf_size = 0;
	char *buf = NULL;
	va_list apc;

	while (1) {
		va_copy(apc, ap);
		ret = vsnprintf(buf, buf_size, fmt, apc);
		va_end(apc);

		if (ret >= 0 && ret < buf_size)
			break;

		if (ret >= 0)
			buf_size = ret + 1;
		else
			buf_size *= 2;

		buf = XREALLOC(MTYPE_TMP, buf, buf_size);
	}

	return buf;
}

static char *str_printf(const char *fmt, ...)
{
	char *buf;
	va_list ap;

	va_start(ap, fmt);
	buf = str_vprintf(fmt, ap);
	va_end(ap);

	return buf;
}

TEST_ATTR_HANDLER_DECL(advertisement_interval, v_routeadv, 10, 20);
TEST_STR_ATTR_HANDLER_DECL(password, password, "FRR-Peer", "FRR-Group");
TEST_ATTR_HANDLER_DECL(local_as, change_local_as, 1, 2);
TEST_ATTR_HANDLER_DECL(timers_1, keepalive, 10, 20);
TEST_ATTR_HANDLER_DECL(timers_2, holdtime, 30, 60);
TEST_ATTR_HANDLER_DECL(addpath_types, addpath_type[pa->afi][pa->safi],
		       BGP_ADDPATH_ALL, BGP_ADDPATH_BEST_PER_AS);
TEST_SU_ATTR_HANDLER_DECL(update_source_su, update_source, "255.255.255.1",
			  "255.255.255.2");
TEST_STR_ATTR_HANDLER_DECL(update_source_if, update_if, "IF-PEER", "IF-GROUP");

TEST_ATTR_HANDLER_DECL(allowas_in, allowas_in[pa->afi][pa->safi], 1, 2);
TEST_STR_ATTR_HANDLER_DECL(default_originate_route_map,
			   default_rmap[pa->afi][pa->safi].name, "RM-PEER",
			   "RM-GROUP");
TEST_STR_ATTR_HANDLER_DECL(
	distribute_list,
	filter[pa->afi][pa->safi].dlist[pa->u.filter.direct].name, "DL-PEER",
	"DL-GROUP");
TEST_STR_ATTR_HANDLER_DECL(
	filter_list, filter[pa->afi][pa->safi].aslist[pa->u.filter.direct].name,
	"FL-PEER", "FL-GROUP");
TEST_ATTR_HANDLER_DECL(maximum_prefix, pmax[pa->afi][pa->safi], 10, 20);
TEST_ATTR_HANDLER_DECL(maximum_prefix_threshold,
		       pmax_threshold[pa->afi][pa->safi], 1, 2);
TEST_ATTR_HANDLER_DECL(maximum_prefix_restart, pmax_restart[pa->afi][pa->safi],
		       100, 200);
TEST_STR_ATTR_HANDLER_DECL(
	prefix_list, filter[pa->afi][pa->safi].plist[pa->u.filter.direct].name,
	"PL-PEER", "PL-GROUP");
TEST_STR_ATTR_HANDLER_DECL(
	route_map, filter[pa->afi][pa->safi].map[pa->u.filter.direct].name,
	"RM-PEER", "RM-GROUP");
TEST_STR_ATTR_HANDLER_DECL(unsuppress_map, filter[pa->afi][pa->safi].usmap.name,
			   "UM-PEER", "UM-GROUP");
TEST_ATTR_HANDLER_DECL(weight, weight[pa->afi][pa->safi], 100, 200);

/* clang-format off */
static struct test_peer_attr test_peer_attrs[] = {
	/* Peer Attributes */
	{
		.cmd = "advertisement-interval",
		.peer_cmd = "advertisement-interval 10",
		.group_cmd = "advertisement-interval 20",
		.u.flag = PEER_FLAG_ROUTEADV,
		.type = PEER_AT_GLOBAL_FLAG,
		.handlers[0] = TEST_HANDLER(advertisement_interval),
	},
	{
		.cmd = "capability dynamic",
		.u.flag = PEER_FLAG_DYNAMIC_CAPABILITY,
		.type = PEER_AT_GLOBAL_FLAG,
	},
	{
		.cmd = "capability extended-nexthop",
		.u.flag = PEER_FLAG_CAPABILITY_ENHE,
		.type = PEER_AT_GLOBAL_FLAG,
	},
	{
		.cmd = "capability extended-nexthop",
		.u.flag = PEER_FLAG_CAPABILITY_ENHE,
		.type = PEER_AT_GLOBAL_FLAG,
		.o.invert_peer = true,
		.o.use_iface_peer = true,
	},
	{
		.cmd = "description",
		.peer_cmd = "description FRR Peer",
		.group_cmd = "description FRR Group",
		.type = PEER_AT_GLOBAL_CUSTOM,
	},
	{
		.cmd = "disable-connected-check",
		.u.flag = PEER_FLAG_DISABLE_CONNECTED_CHECK,
		.type = PEER_AT_GLOBAL_FLAG,
	},
	{
		.cmd = "dont-capability-negotiate",
		.u.flag = PEER_FLAG_DONT_CAPABILITY,
		.type = PEER_AT_GLOBAL_FLAG,
	},
	{
		.cmd = "enforce-first-as",
		.u.flag = PEER_FLAG_ENFORCE_FIRST_AS,
		.type = PEER_AT_GLOBAL_FLAG,
	},
	{
		.cmd = "local-as",
		.peer_cmd = "local-as 1",
		.group_cmd = "local-as 2",
		.u.flag = PEER_FLAG_LOCAL_AS,
		.type = PEER_AT_GLOBAL_FLAG,
		.handlers[0] = TEST_HANDLER(local_as),
	},
	{
		.cmd = "local-as 1 no-prepend",
		.u.flag = PEER_FLAG_LOCAL_AS | PEER_FLAG_LOCAL_AS_NO_PREPEND,
		.type = PEER_AT_GLOBAL_FLAG,
	},
	{
		.cmd = "local-as 1 no-prepend replace-as",
		.u.flag = PEER_FLAG_LOCAL_AS | PEER_FLAG_LOCAL_AS_REPLACE_AS,
		.type = PEER_AT_GLOBAL_FLAG,
	},
	{
		.cmd = "override-capability",
		.u.flag = PEER_FLAG_OVERRIDE_CAPABILITY,
		.type = PEER_AT_GLOBAL_FLAG,
	},
	{
		.cmd = "passive",
		.u.flag = PEER_FLAG_PASSIVE,
		.type = PEER_AT_GLOBAL_FLAG,
	},
	{
		.cmd = "password",
		.peer_cmd = "password FRR-Peer",
		.group_cmd = "password FRR-Group",
		.u.flag = PEER_FLAG_PASSWORD,
		.type = PEER_AT_GLOBAL_FLAG,
		.handlers[0] = TEST_HANDLER(password),
	},
	{
		.cmd = "shutdown",
		.u.flag = PEER_FLAG_SHUTDOWN,
		.type = PEER_AT_GLOBAL_FLAG,
	},
	{
		.cmd = "strict-capability-match",
		.u.flag = PEER_FLAG_STRICT_CAP_MATCH,
		.type = PEER_AT_GLOBAL_FLAG,
	},
	{
		.cmd = "timers",
		.peer_cmd = "timers 10 30",
		.group_cmd = "timers 20 60",
		.u.flag = PEER_FLAG_TIMER,
		.type = PEER_AT_GLOBAL_FLAG,
		.handlers[0] = TEST_HANDLER(timers_1),
		.handlers[1] = TEST_HANDLER(timers_2),
	},
	{
		.cmd = "timers connect",
		.peer_cmd = "timers connect 10",
		.group_cmd = "timers connect 20",
		.u.flag = PEER_FLAG_TIMER_CONNECT,
		.type = PEER_AT_GLOBAL_FLAG,
	},
	{
		.cmd = "update-source",
		.peer_cmd = "update-source 255.255.255.1",
		.group_cmd = "update-source 255.255.255.2",
		.u.flag = PEER_FLAG_UPDATE_SOURCE,
		.type = PEER_AT_GLOBAL_FLAG,
		.handlers[0] = TEST_HANDLER(update_source_su),
	},
	{
		.cmd = "update-source",
		.peer_cmd = "update-source IF-PEER",
		.group_cmd = "update-source IF-GROUP",
		.u.flag = PEER_FLAG_UPDATE_SOURCE,
		.type = PEER_AT_GLOBAL_FLAG,
		.handlers[0] = TEST_HANDLER(update_source_if),
	},

	/* Address Family Attributes */
	{
		.cmd = "addpath",
		.peer_cmd = "addpath-tx-all-paths",
		.group_cmd = "addpath-tx-bestpath-per-AS",
		.type = PEER_AT_AF_CUSTOM,
		.handlers[0] = TEST_HANDLER(addpath_types),
	},
	{
		.cmd = "allowas-in",
		.peer_cmd = "allowas-in 1",
		.group_cmd = "allowas-in 2",
		.u.flag = PEER_FLAG_ALLOWAS_IN,
		.handlers[0] = TEST_HANDLER(allowas_in),
	},
	{
		.cmd = "allowas-in origin",
		.u.flag = PEER_FLAG_ALLOWAS_IN_ORIGIN,
	},
	{
		.cmd = "as-override",
		.u.flag = PEER_FLAG_AS_OVERRIDE,
	},
	{
		.cmd = "attribute-unchanged as-path",
		.u.flag = PEER_FLAG_AS_PATH_UNCHANGED,
	},
	{
		.cmd = "attribute-unchanged next-hop",
		.u.flag = PEER_FLAG_NEXTHOP_UNCHANGED,
	},
	{
		.cmd = "attribute-unchanged med",
		.u.flag = PEER_FLAG_MED_UNCHANGED,
	},
	{
		.cmd = "attribute-unchanged as-path next-hop",
		.u.flag = PEER_FLAG_AS_PATH_UNCHANGED
			| PEER_FLAG_NEXTHOP_UNCHANGED,
	},
	{
		.cmd = "attribute-unchanged as-path med",
		.u.flag = PEER_FLAG_AS_PATH_UNCHANGED
			| PEER_FLAG_MED_UNCHANGED,
	},
	{
		.cmd = "attribute-unchanged as-path next-hop med",
		.u.flag = PEER_FLAG_AS_PATH_UNCHANGED
			| PEER_FLAG_NEXTHOP_UNCHANGED
			| PEER_FLAG_MED_UNCHANGED,
	},
	{
		.cmd = "capability orf prefix-list send",
		.u.flag = PEER_FLAG_ORF_PREFIX_SM,
	},
	{
		.cmd = "capability orf prefix-list receive",
		.u.flag = PEER_FLAG_ORF_PREFIX_RM,
	},
	{
		.cmd = "capability orf prefix-list both",
		.u.flag = PEER_FLAG_ORF_PREFIX_SM | PEER_FLAG_ORF_PREFIX_RM,
	},
	{
		.cmd = "default-originate",
		.u.flag = PEER_FLAG_DEFAULT_ORIGINATE,
	},
	{
		.cmd = "default-originate route-map",
		.peer_cmd = "default-originate route-map RM-PEER",
		.group_cmd = "default-originate route-map RM-GROUP",
		.u.flag = PEER_FLAG_DEFAULT_ORIGINATE,
		.handlers[0] = TEST_HANDLER(default_originate_route_map),
	},
	{
		.cmd = "distribute-list",
		.peer_cmd = "distribute-list DL-PEER in",
		.group_cmd = "distribute-list DL-GROUP in",
		.type = PEER_AT_AF_FILTER,
		.u.filter.flag = PEER_FT_DISTRIBUTE_LIST,
		.u.filter.direct = FILTER_IN,
		.handlers[0] = TEST_HANDLER(distribute_list),
	},
	{
		.cmd = "distribute-list",
		.peer_cmd = "distribute-list DL-PEER out",
		.group_cmd = "distribute-list DL-GROUP out",
		.type = PEER_AT_AF_FILTER,
		.u.filter.flag = PEER_FT_DISTRIBUTE_LIST,
		.u.filter.direct = FILTER_OUT,
		.handlers[0] = TEST_HANDLER(distribute_list),
	},
	{
		.cmd = "filter-list",
		.peer_cmd = "filter-list FL-PEER in",
		.group_cmd = "filter-list FL-GROUP in",
		.type = PEER_AT_AF_FILTER,
		.u.filter.flag = PEER_FT_FILTER_LIST,
		.u.filter.direct = FILTER_IN,
		.handlers[0] = TEST_HANDLER(filter_list),
	},
	{
		.cmd = "filter-list",
		.peer_cmd = "filter-list FL-PEER out",
		.group_cmd = "filter-list FL-GROUP out",
		.type = PEER_AT_AF_FILTER,
		.u.filter.flag = PEER_FT_FILTER_LIST,
		.u.filter.direct = FILTER_OUT,
		.handlers[0] = TEST_HANDLER(filter_list),
	},
	{
		.cmd = "maximum-prefix",
		.peer_cmd = "maximum-prefix 10",
		.group_cmd = "maximum-prefix 20",
		.u.flag = PEER_FLAG_MAX_PREFIX,
		.handlers[0] = TEST_HANDLER(maximum_prefix),
	},
	{
		.cmd = "maximum-prefix",
		.peer_cmd = "maximum-prefix 10 restart 100",
		.group_cmd = "maximum-prefix 20 restart 200",
		.u.flag = PEER_FLAG_MAX_PREFIX,
		.handlers[0] = TEST_HANDLER(maximum_prefix),
		.handlers[1] = TEST_HANDLER(maximum_prefix_restart),
	},
	{
		.cmd = "maximum-prefix",
		.peer_cmd = "maximum-prefix 10 1 restart 100",
		.group_cmd = "maximum-prefix 20 2 restart 200",
		.u.flag = PEER_FLAG_MAX_PREFIX,
		.handlers[0] = TEST_HANDLER(maximum_prefix),
		.handlers[1] = TEST_HANDLER(maximum_prefix_threshold),
		.handlers[2] = TEST_HANDLER(maximum_prefix_restart),
	},
	{
		.cmd = "maximum-prefix",
		.peer_cmd = "maximum-prefix 10 warning-only",
		.group_cmd = "maximum-prefix 20 warning-only",
		.u.flag = PEER_FLAG_MAX_PREFIX | PEER_FLAG_MAX_PREFIX_WARNING,
		.handlers[0] = TEST_HANDLER(maximum_prefix),
	},
	{
		.cmd = "maximum-prefix",
		.peer_cmd = "maximum-prefix 10 1 warning-only",
		.group_cmd = "maximum-prefix 20 2 warning-only",
		.u.flag = PEER_FLAG_MAX_PREFIX | PEER_FLAG_MAX_PREFIX_WARNING,
		.handlers[0] = TEST_HANDLER(maximum_prefix),
		.handlers[1] = TEST_HANDLER(maximum_prefix_threshold),
	},
	{
		.cmd = "next-hop-self",
		.u.flag = PEER_FLAG_NEXTHOP_SELF,
	},
	{
		.cmd = "next-hop-self force",
		.u.flag = PEER_FLAG_FORCE_NEXTHOP_SELF,
	},
	{
		.cmd = "prefix-list",
		.peer_cmd = "prefix-list PL-PEER in",
		.group_cmd = "prefix-list PL-GROUP in",
		.type = PEER_AT_AF_FILTER,
		.u.filter.flag = PEER_FT_PREFIX_LIST,
		.u.filter.direct = FILTER_IN,
		.handlers[0] = TEST_HANDLER(prefix_list),
	},
	{
		.cmd = "prefix-list",
		.peer_cmd = "prefix-list PL-PEER out",
		.group_cmd = "prefix-list PL-GROUP out",
		.type = PEER_AT_AF_FILTER,
		.u.filter.flag = PEER_FT_PREFIX_LIST,
		.u.filter.direct = FILTER_OUT,
		.handlers[0] = TEST_HANDLER(prefix_list),
	},
	{
		.cmd = "remove-private-AS",
		.u.flag = PEER_FLAG_REMOVE_PRIVATE_AS,
	},
	{
		.cmd = "remove-private-AS all",
		.u.flag = PEER_FLAG_REMOVE_PRIVATE_AS
			| PEER_FLAG_REMOVE_PRIVATE_AS_ALL,
	},
	{
		.cmd = "remove-private-AS replace-AS",
		.u.flag = PEER_FLAG_REMOVE_PRIVATE_AS
			| PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE,
	},
	{
		.cmd = "remove-private-AS all replace-AS",
		.u.flag = PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE,
	},
	{
		.cmd = "route-map",
		.peer_cmd = "route-map RM-PEER in",
		.group_cmd = "route-map RM-GROUP in",
		.type = PEER_AT_AF_FILTER,
		.u.filter.flag = PEER_FT_ROUTE_MAP,
		.u.filter.direct = FILTER_IN,
		.handlers[0] = TEST_HANDLER(route_map),
	},
	{
		.cmd = "route-map",
		.peer_cmd = "route-map RM-PEER out",
		.group_cmd = "route-map RM-GROUP out",
		.type = PEER_AT_AF_FILTER,
		.u.filter.flag = PEER_FT_ROUTE_MAP,
		.u.filter.direct = FILTER_OUT,
		.handlers[0] = TEST_HANDLER(route_map),
	},
	{
		.cmd = "route-reflector-client",
		.u.flag = PEER_FLAG_REFLECTOR_CLIENT,
		.o.use_ibgp = true,
		.o.skip_xfer_cases = true,
	},
	{
		.cmd = "route-server-client",
		.u.flag = PEER_FLAG_RSERVER_CLIENT,
	},
	{
		.cmd = "send-community",
		.u.flag = PEER_FLAG_SEND_COMMUNITY,
		.o.invert_peer = true,
		.o.invert_group = true,
	},
	{
		.cmd = "send-community extended",
		.u.flag = PEER_FLAG_SEND_EXT_COMMUNITY,
		.o.invert_peer = true,
		.o.invert_group = true,
	},
	{
		.cmd = "send-community large",
		.u.flag = PEER_FLAG_SEND_LARGE_COMMUNITY,
		.o.invert_peer = true,
		.o.invert_group = true,
	},
	{
		.cmd = "soft-reconfiguration inbound",
		.u.flag = PEER_FLAG_SOFT_RECONFIG,
	},
	{
		.cmd = "unsuppress-map",
		.peer_cmd = "unsuppress-map UM-PEER",
		.group_cmd = "unsuppress-map UM-GROUP",
		.type = PEER_AT_AF_FILTER,
		.u.filter.flag = PEER_FT_UNSUPPRESS_MAP,
		.u.filter.direct = 0,
		.handlers[0] = TEST_HANDLER(unsuppress_map),
	},
	{
		.cmd = "weight",
		.peer_cmd = "weight 100",
		.group_cmd = "weight 200",
		.u.flag = PEER_FLAG_WEIGHT,
		.handlers[0] = TEST_HANDLER(weight),
	},
	{NULL}
};
/* clang-format on */

static const char *str_from_afi(afi_t afi)
{
	switch (afi) {
	case AFI_IP:
		return "ipv4";
	case AFI_IP6:
		return "ipv6";
	default:
		return "<unknown AFI>";
	}
}

static const char *str_from_safi(safi_t safi)
{
	switch (safi) {
	case SAFI_UNICAST:
		return "unicast";
	case SAFI_MULTICAST:
		return "multicast";
	default:
		return "<unknown SAFI>";
	}
}

static const char *str_from_attr_type(enum test_peer_attr_type at)
{
	switch (at) {
	case PEER_AT_GLOBAL_FLAG:
		return "peer-flag";
	case PEER_AT_AF_FLAG:
		return "af-flag";
	case PEER_AT_AF_FILTER:
		return "af-filter";
	case PEER_AT_GLOBAL_CUSTOM:
	case PEER_AT_AF_CUSTOM:
		return "custom";
	default:
		return NULL;
	}
}

static bool is_attr_type_global(enum test_peer_attr_type at)
{
	return at == PEER_AT_GLOBAL_FLAG || at == PEER_AT_GLOBAL_CUSTOM;
}

static void test_log(struct test *test, const char *fmt, ...)
{
	va_list ap;

	/* Skip logging if test instance has previously failed. */
	if (test->state != TEST_SUCCESS)
		return;

	/* Store formatted log message. */
	va_start(ap, fmt);
	listnode_add(test->log, str_vprintf(fmt, ap));
	va_end(ap);
}

static void test_execute(struct test *test, const char *fmt, ...)
{
	int ret;
	char *cmd;
	va_list ap;
	vector vline;

	/* Skip execution if test instance has previously failed. */
	if (test->state != TEST_SUCCESS)
		return;

	/* Format command string with variadic arguments. */
	va_start(ap, fmt);
	cmd = str_vprintf(fmt, ap);
	va_end(ap);
	if (!cmd) {
		test->state = TEST_INTERNAL_ERROR;
		test->error =
			str_printf("could not format command string [%s]", fmt);
		return;
	}

	/* Tokenize formatted command string. */
	vline = cmd_make_strvec(cmd);
	if (vline == NULL) {
		test->state = TEST_INTERNAL_ERROR;
		test->error = str_printf(
			"tokenizing command string [%s] returned empty result",
			cmd);
		XFREE(MTYPE_TMP, cmd);

		return;
	}

	/* Execute command (non-strict). */
	ret = cmd_execute_command(vline, test->vty, NULL, 0);
	if (ret != CMD_SUCCESS) {
		test->state = TEST_COMMAND_ERROR;
		test->error = str_printf(
			"execution of command [%s] has failed with code [%d]",
			cmd, ret);
	}

	/* Free memory. */
	cmd_free_strvec(vline);
	XFREE(MTYPE_TMP, cmd);
}

static void test_config(struct test *test, const char *fmt, bool invert,
			va_list ap)
{
	char *matcher;
	char *config;
	bool matched;
	va_list apc;

	/* Skip execution if test instance has previously failed. */
	if (test->state != TEST_SUCCESS)
		return;

	/* Format matcher string with variadic arguments. */
	va_copy(apc, ap);
	matcher = str_vprintf(fmt, apc);
	va_end(apc);
	if (!matcher) {
		test->state = TEST_INTERNAL_ERROR;
		test->error =
			str_printf("could not format matcher string [%s]", fmt);
		return;
	}

	/* Fetch BGP configuration into buffer. */
	bgp_config_write(test->vty);
	config = buffer_getstr(test->vty->obuf);
	buffer_reset(test->vty->obuf);

	/* Match config against matcher. */
	matched = !!strstr(config, matcher);
	if (!matched && !invert) {
		test->state = TEST_CONFIG_ERROR;
		test->error = str_printf("expected config [%s] to be present",
					 matcher);
	} else if (matched && invert) {
		test->state = TEST_CONFIG_ERROR;
		test->error = str_printf("expected config [%s] to be absent",
					 matcher);
	}

	/* Free memory and return. */
	XFREE(MTYPE_TMP, matcher);
	XFREE(MTYPE_TMP, config);
}

static void test_config_present(struct test *test, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	test_config(test, fmt, false, ap);
	va_end(ap);
}

static void test_config_absent(struct test *test, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	test_config(test, fmt, true, ap);
	va_end(ap);
}

static void test_initialize(struct test *test)
{
	union sockunion su;

	/* Skip execution if test instance has previously failed. */
	if (test->state != TEST_SUCCESS)
		return;

	/* Log message about (re)-initialization */
	test_log(test, "prepare: %sinitialize bgp test environment",
		 test->bgp ? "re-" : "");

	/* Attempt gracefully to purge previous BGP configuration. */
	test_execute(test, "no router bgp");
	test->state = TEST_SUCCESS;

	/* Initialize BGP test environment. */
	test_execute(test, "router bgp %d", cfg.local_asn);
	test_execute(test, "no bgp default ipv4-unicast");
	test_execute(test, "neighbor %s peer-group", cfg.peer_group);
	if (test->o.use_iface_peer) {
		test_execute(test, "neighbor %s interface", cfg.peer_interface);
		test_execute(test, "neighbor %s remote-as %d",
			     cfg.peer_interface,
			     test->o.use_ibgp ? cfg.local_asn : cfg.peer_asn);
	} else {
		test_execute(test, "neighbor %s remote-as %d", cfg.peer_address,
			     test->o.use_ibgp ? cfg.local_asn : cfg.peer_asn);
	}

	if (test->state != TEST_SUCCESS)
		return;

	/* Fetch default BGP instance. */
	test->bgp = bgp_get_default();
	if (!test->bgp) {
		test->state = TEST_INTERNAL_ERROR;
		test->error =
			str_printf("could not retrieve default bgp instance");
		return;
	}

	/* Fetch peer instance. */
	if (test->o.use_iface_peer) {
		test->peer =
			peer_lookup_by_conf_if(test->bgp, cfg.peer_interface);
	} else {
		str2sockunion(cfg.peer_address, &su);
		test->peer = peer_lookup(test->bgp, &su);
	}
	if (!test->peer) {
		test->state = TEST_INTERNAL_ERROR;
		test->error = str_printf(
			"could not retrieve instance of bgp peer [%s]",
			cfg.peer_address);
		return;
	}

	/* Fetch peer-group instance. */
	test->group = peer_group_lookup(test->bgp, cfg.peer_group);
	if (!test->group) {
		test->state = TEST_INTERNAL_ERROR;
		test->error = str_printf(
			"could not retrieve instance of bgp peer-group [%s]",
			cfg.peer_group);
		return;
	}
}

static struct test *test_new(const char *desc, bool use_ibgp,
			     bool use_iface_peer)
{
	struct test *test;

	test = XCALLOC(MTYPE_TMP, sizeof(struct test));
	test->state = TEST_SUCCESS;
	test->desc = XSTRDUP(MTYPE_TMP, desc);
	test->log = list_new();
	test->o.use_ibgp = use_ibgp;
	test->o.use_iface_peer = use_iface_peer;

	test->vty = vty_new();
	test->vty->type = VTY_TERM;
	test->vty->node = CONFIG_NODE;

	test_initialize(test);

	return test;
};

static void test_finish(struct test *test)
{
	char *msg;
	struct listnode *node, *nnode;

	/* Print test output header. */
	printf("%s [test] %s\n",
	       (test->state == TEST_SUCCESS) ? OUT_SYMBOL_OK : OUT_SYMBOL_NOK,
	       test->desc);

	/* Print test log messages. */
	for (ALL_LIST_ELEMENTS(test->log, node, nnode, msg)) {
		printf("%s %s\n", OUT_SYMBOL_INFO, msg);
		XFREE(MTYPE_TMP, msg);
	}

	/* Print test error message if available. */
	if (test->state != TEST_SUCCESS && test->error)
		printf("%s error: %s\n", OUT_SYMBOL_INFO, test->error);

	/* Print machine-readable result of test. */
	printf("%s\n", test->state == TEST_SUCCESS ? "OK" : "failed");

	/* Cleanup allocated memory. */
	if (test->vty) {
		vty_close(test->vty);
		test->vty = NULL;
	}
	if (test->log)
		list_delete(&test->log);
	if (test->desc)
		XFREE(MTYPE_TMP, test->desc);
	if (test->error)
		XFREE(MTYPE_TMP, test->error);
	XFREE(MTYPE_TMP, test);
}

static void test_peer_flags(struct test *test, struct test_peer_attr *pa,
			    struct peer *peer, bool exp_val, bool exp_ovrd)
{
	bool exp_inv, cur_val, cur_ovrd, cur_inv;

	/* Skip execution if test instance has previously failed. */
	if (test->state != TEST_SUCCESS)
		return;

	/* Detect if flag is meant to be inverted. */
	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
		exp_inv = pa->o.invert_group;
	else
		exp_inv = pa->o.invert_peer;

	/* Flip expected value if flag is inverted. */
	exp_val ^= exp_inv;

	/* Fetch current state of value, override and invert flags. */
	if (pa->type == PEER_AT_GLOBAL_FLAG) {
		cur_val = !!CHECK_FLAG(peer->flags, pa->u.flag);
		cur_ovrd = !!CHECK_FLAG(peer->flags_override, pa->u.flag);
		cur_inv = !!CHECK_FLAG(peer->flags_invert, pa->u.flag);
	} else /* if (pa->type == PEER_AT_AF_FLAG) */ {
		cur_val = !!CHECK_FLAG(peer->af_flags[pa->afi][pa->safi],
				       pa->u.flag);
		cur_ovrd = !!CHECK_FLAG(
			peer->af_flags_override[pa->afi][pa->safi], pa->u.flag);
		cur_inv = !!CHECK_FLAG(peer->af_flags_invert[pa->afi][pa->safi],
				       pa->u.flag);
	}

	/* Assert expected flag states. */
	TEST_ASSERT_EQ(test, cur_val, exp_val);
	TEST_ASSERT_EQ(test, cur_ovrd, exp_ovrd);
	TEST_ASSERT_EQ(test, cur_inv, exp_inv);
}

static void test_af_filter(struct test *test, struct test_peer_attr *pa,
			   struct peer *peer, bool exp_state, bool exp_ovrd)
{
	bool cur_ovrd;
	struct bgp_filter *filter;

	/* Skip execution if test instance has previously failed. */
	if (test->state != TEST_SUCCESS)
		return;

	/* Fetch and assert current state of override flag. */
	cur_ovrd = !!CHECK_FLAG(
		peer->filter_override[pa->afi][pa->safi][pa->u.filter.direct],
		pa->u.filter.flag);

	TEST_ASSERT_EQ(test, cur_ovrd, exp_ovrd);

	/* Assert that map/list matches expected state (set/unset). */
	filter = &peer->filter[pa->afi][pa->safi];

	switch (pa->u.filter.flag) {
	case PEER_FT_DISTRIBUTE_LIST:
		TEST_ASSERT_EQ(test,
			       !!(filter->dlist[pa->u.filter.direct].name),
			       exp_state);
		break;
	case PEER_FT_FILTER_LIST:
		TEST_ASSERT_EQ(test,
			       !!(filter->aslist[pa->u.filter.direct].name),
			       exp_state);
		break;
	case PEER_FT_PREFIX_LIST:
		TEST_ASSERT_EQ(test,
			       !!(filter->plist[pa->u.filter.direct].name),
			       exp_state);
		break;
	case PEER_FT_ROUTE_MAP:
		TEST_ASSERT_EQ(test, !!(filter->map[pa->u.filter.direct].name),
			       exp_state);
		break;
	case PEER_FT_UNSUPPRESS_MAP:
		TEST_ASSERT_EQ(test, !!(filter->usmap.name), exp_state);
		break;
	}
}

static void test_custom(struct test *test, struct test_peer_attr *pa,
			struct peer *peer, struct peer *group, bool peer_set,
			bool group_set)
{
	int i;
	char *handler_error;

	for (i = 0; i < TEST_HANDLER_MAX; i++) {
		/* Skip execution if test instance has previously failed. */
		if (test->state != TEST_SUCCESS)
			return;

		/* Skip further execution if handler is undefined. */
		if (!pa->handlers[i])
			return;

		/* Execute custom handler. */
		pa->handlers[i](test, pa, peer, group, peer_set, group_set);
		if (test->state != TEST_SUCCESS) {
			test->state = TEST_CUSTOM_ERROR;
			handler_error = test->error;
			test->error = str_printf("custom handler failed: %s",
						 handler_error);
			XFREE(MTYPE_TMP, handler_error);
		}
	}
}


static void test_process(struct test *test, struct test_peer_attr *pa,
			 struct peer *peer, struct peer *group, bool peer_set,
			 bool group_set)
{
	switch (pa->type) {
	case PEER_AT_GLOBAL_FLAG:
	case PEER_AT_AF_FLAG:
		test_peer_flags(
			test, pa, peer,
			peer_set || (peer_group_active(peer) && group_set),
			peer_set);
		test_peer_flags(test, pa, group, group_set, false);
		break;

	case PEER_AT_AF_FILTER:
		test_af_filter(
			test, pa, peer,
			peer_set || (peer_group_active(peer) && group_set),
			peer_set);
		test_af_filter(test, pa, group, group_set, false);
		break;

	case PEER_AT_GLOBAL_CUSTOM:
	case PEER_AT_AF_CUSTOM:
		/*
		 * Do nothing here - a custom handler can be executed, but this
		 * is not required. This will allow defining peer attributes
		 * which shall not be checked for flag/filter/other internal
		 * states.
		 */
		break;

	default:
		test->state = TEST_INTERNAL_ERROR;
		test->error =
			str_printf("invalid attribute type: %d", pa->type);
		break;
	}

	/* Attempt to call a custom handler if set for further processing. */
	test_custom(test, pa, peer, group, peer_set, group_set);
}

static void test_peer_attr(struct test *test, struct test_peer_attr *pa)
{
	int tc = 1;
	const char *type;
	const char *ecp = pa->o.invert_peer ? "no " : "";
	const char *dcp = pa->o.invert_peer ? "" : "no ";
	const char *ecg = pa->o.invert_group ? "no " : "";
	const char *dcg = pa->o.invert_group ? "" : "no ";
	const char *peer_cmd = pa->peer_cmd ?: pa->cmd;
	const char *group_cmd = pa->group_cmd ?: pa->cmd;
	struct peer *p = test->peer;
	struct peer_group *g = test->group;

	/* Determine type and if test is address-family relevant */
	type = str_from_attr_type(pa->type);
	if (!type) {
		test->state = TEST_INTERNAL_ERROR;
		test->error =
			str_printf("invalid attribute type: %d", pa->type);
		return;
	}

	/*
	 * =====================================================================
	 * Test Case Suite 1: Config persistence after adding peer to group
	 *
	 * Example: If a peer attribute has value [1] and a group attribute has
	 * value [2], the peer attribute value should be persisted when the peer
	 * gets added to the peer-group.
	 *
	 * This test suite is meant to test the group2peer functions which can
	 * be found inside bgpd/bgpd.c, which are related to initial peer-group
	 * inheritance.
	 * =====================================================================
	 */

	/* Test Preparation: Switch and activate address-family. */
	if (!is_attr_type_global(pa->type)) {
		test_log(test, "prepare: switch address-family to [%s]",
			 get_afi_safi_str(pa->afi, pa->safi, false));
		test_execute(test, "address-family %s %s",
			     str_from_afi(pa->afi), str_from_safi(pa->safi));
		test_execute(test, "neighbor %s activate", g->name);
		test_execute(test, "neighbor %s activate", p->host);
	}

	/* Skip peer-group to peer transfer test cases if requested. */
	if (pa->o.skip_xfer_cases && test->state == TEST_SUCCESS)
		test->state = TEST_SKIPPING;

	/* Test Case: Set flag on BGP peer. */
	test_log(test, "case %02d: set %s [%s] on [%s]", tc++, type, peer_cmd,
		 p->host);
	test_execute(test, "%sneighbor %s %s", ecp, p->host, peer_cmd);
	test_config_present(test, "%sneighbor %s %s", ecp, p->host, peer_cmd);
	test_config_absent(test, "neighbor %s %s", g->name, pa->cmd);
	test_process(test, pa, p, g->conf, true, false);

	/* Test Case: Set flag on BGP peer-group. */
	test_log(test, "case %02d: set %s [%s] on [%s]", tc++, type, group_cmd,
		 g->name);
	test_execute(test, "%sneighbor %s %s", ecg, g->name, group_cmd);
	test_config_present(test, "%sneighbor %s %s", ecp, p->host, peer_cmd);
	test_config_present(test, "%sneighbor %s %s", ecg, g->name, group_cmd);
	test_process(test, pa, p, g->conf, true, true);

	/* Test Case: Add BGP peer to peer-group. */
	test_log(test, "case %02d: add peer [%s] to group [%s]", tc++, p->host,
		 g->name);
	test_execute(test, "neighbor %s peer-group %s", p->host, g->name);
	test_config_present(test, "neighbor %s %speer-group %s", p->host,
			    p->conf_if ? "interface " : "", g->name);
	test_config_present(test, "%sneighbor %s %s", ecp, p->host, peer_cmd);
	test_config_present(test, "%sneighbor %s %s", ecg, g->name, group_cmd);
	test_process(test, pa, p, g->conf, true, true);

	/* Test Case: Unset flag on BGP peer-group. */
	test_log(test, "case %02d: unset %s [%s] on [%s]", tc++, type,
		 group_cmd, g->name);
	test_execute(test, "%sneighbor %s %s", dcg, g->name, group_cmd);
	test_config_present(test, "%sneighbor %s %s", ecp, p->host, peer_cmd);
	test_config_absent(test, "neighbor %s %s", g->name, pa->cmd);
	test_process(test, pa, p, g->conf, true, false);

	/*
	 * =====================================================================
	 * Test Case Suite 2: Config inheritance after adding peer to group
	 *
	 * Example: If a peer attribute has not been set and a group attribute
	 * has a value of [2], the group attribute should be inherited to the
	 * peer without flagging the newly set value as overridden.
	 *
	 * This test suite is meant to test the group2peer functions which can
	 * be found inside bgpd/bgpd.c, which are related to initial peer-group
	 * inheritance.
	 * =====================================================================
	 */

	/* Test Preparation: Re-initialize test environment. */
	test_initialize(test);
	p = test->peer;
	g = test->group;

	/* Test Preparation: Switch and activate address-family. */
	if (!is_attr_type_global(pa->type)) {
		test_log(test, "prepare: switch address-family to [%s]",
			 get_afi_safi_str(pa->afi, pa->safi, false));
		test_execute(test, "address-family %s %s",
			     str_from_afi(pa->afi), str_from_safi(pa->safi));
		test_execute(test, "neighbor %s activate", g->name);
		test_execute(test, "neighbor %s activate", p->host);
	}

	/* Test Case: Set flag on BGP peer-group. */
	test_log(test, "case %02d: set %s [%s] on [%s]", tc++, type, group_cmd,
		 g->name);
	test_execute(test, "%sneighbor %s %s", ecg, g->name, group_cmd);
	test_config_absent(test, "neighbor %s %s", p->host, pa->cmd);
	test_config_present(test, "%sneighbor %s %s", ecg, g->name, group_cmd);
	test_process(test, pa, p, g->conf, false, true);

	/* Test Case: Add BGP peer to peer-group. */
	test_log(test, "case %02d: add peer [%s] to group [%s]", tc++, p->host,
		 g->name);
	test_execute(test, "neighbor %s peer-group %s", p->host, g->name);
	test_config_present(test, "neighbor %s %speer-group %s", p->host,
			    p->conf_if ? "interface " : "", g->name);
	test_config_absent(test, "neighbor %s %s", p->host, pa->cmd);
	test_config_present(test, "%sneighbor %s %s", ecg, g->name, group_cmd);
	test_process(test, pa, p, g->conf, false, true);

	/* Stop skipping test cases if previously enabled. */
	if (pa->o.skip_xfer_cases && test->state == TEST_SKIPPING)
		test->state = TEST_SUCCESS;

	/*
	 * =====================================================================
	 * Test Case Suite 3: Miscellaneous flag checks
	 *
	 * This test suite does not focus on initial peer-group inheritance and
	 * instead executes various different commands to set/unset attributes
	 * on both peer- and group-level. These checks should always be executed
	 * and must pass.
	 * =====================================================================
	 */

	/* Test Preparation: Re-initialize test environment. */
	test_initialize(test);
	p = test->peer;
	g = test->group;

	/* Test Preparation: Switch and activate address-family. */
	if (!is_attr_type_global(pa->type)) {
		test_log(test, "prepare: switch address-family to [%s]",
			 get_afi_safi_str(pa->afi, pa->safi, false));
		test_execute(test, "address-family %s %s",
			     str_from_afi(pa->afi), str_from_safi(pa->safi));
		test_execute(test, "neighbor %s activate", g->name);
		test_execute(test, "neighbor %s activate", p->host);
	}

	/* Test Case: Set flag on BGP peer. */
	test_log(test, "case %02d: set %s [%s] on [%s]", tc++, type, peer_cmd,
		 p->host);
	test_execute(test, "%sneighbor %s %s", ecp, p->host, peer_cmd);
	test_config_present(test, "%sneighbor %s %s", ecp, p->host, peer_cmd);
	test_config_absent(test, "neighbor %s %s", g->name, pa->cmd);
	test_process(test, pa, p, g->conf, true, false);

	/* Test Case: Add BGP peer to peer-group. */
	test_log(test, "case %02d: add peer [%s] to group [%s]", tc++, p->host,
		 g->name);
	test_execute(test, "neighbor %s peer-group %s", p->host, g->name);
	test_config_present(test, "neighbor %s %speer-group %s", p->host,
			    p->conf_if ? "interface " : "", g->name);
	test_config_present(test, "%sneighbor %s %s", ecp, p->host, peer_cmd);
	test_config_absent(test, "neighbor %s %s", g->name, pa->cmd);
	test_process(test, pa, p, g->conf, true, false);

	/* Test Case: Re-add BGP peer to peer-group. */
	test_log(test, "case %02d: re-add peer [%s] to group [%s]", tc++,
		 p->host, g->name);
	test_execute(test, "neighbor %s peer-group %s", p->host, g->name);
	test_config_present(test, "neighbor %s %speer-group %s", p->host,
			    p->conf_if ? "interface " : "", g->name);
	test_config_present(test, "%sneighbor %s %s", ecp, p->host, peer_cmd);
	test_config_absent(test, "neighbor %s %s", g->name, pa->cmd);
	test_process(test, pa, p, g->conf, true, false);

	/* Test Case: Set flag on BGP peer-group. */
	test_log(test, "case %02d: set %s [%s] on [%s]", tc++, type, group_cmd,
		 g->name);
	test_execute(test, "%sneighbor %s %s", ecg, g->name, group_cmd);
	test_config_present(test, "%sneighbor %s %s", ecp, p->host, peer_cmd);
	test_config_present(test, "%sneighbor %s %s", ecg, g->name, group_cmd);
	test_process(test, pa, p, g->conf, true, true);

	/* Test Case: Unset flag on BGP peer-group. */
	test_log(test, "case %02d: unset %s [%s] on [%s]", tc++, type,
		 group_cmd, g->name);
	test_execute(test, "%sneighbor %s %s", dcg, g->name, group_cmd);
	test_config_present(test, "%sneighbor %s %s", ecp, p->host, peer_cmd);
	test_config_absent(test, "neighbor %s %s", g->name, pa->cmd);
	test_process(test, pa, p, g->conf, true, false);

	/* Test Case: Set flag on BGP peer-group. */
	test_log(test, "case %02d: set %s [%s] on [%s]", tc++, type, group_cmd,
		 g->name);
	test_execute(test, "%sneighbor %s %s", ecg, g->name, group_cmd);
	test_config_present(test, "%sneighbor %s %s", ecp, p->host, peer_cmd);
	test_config_present(test, "%sneighbor %s %s", ecg, g->name, group_cmd);
	test_process(test, pa, p, g->conf, true, true);

	/* Test Case: Re-set flag on BGP peer. */
	test_log(test, "case %02d: re-set %s [%s] on [%s]", tc++, type,
		 peer_cmd, p->host);
	test_execute(test, "%sneighbor %s %s", ecp, p->host, peer_cmd);
	test_config_present(test, "%sneighbor %s %s", ecp, p->host, peer_cmd);
	test_config_present(test, "%sneighbor %s %s", ecg, g->name, group_cmd);
	test_process(test, pa, p, g->conf, true, true);

	/* Test Case: Unset flag on BGP peer. */
	test_log(test, "case %02d: unset %s [%s] on [%s]", tc++, type, peer_cmd,
		 p->host);
	test_execute(test, "%sneighbor %s %s", dcp, p->host, peer_cmd);
	test_config_absent(test, "neighbor %s %s", p->host, pa->cmd);
	test_config_present(test, "%sneighbor %s %s", ecg, g->name, group_cmd);
	test_process(test, pa, p, g->conf, false, true);

	/* Test Case: Unset flag on BGP peer-group. */
	test_log(test, "case %02d: unset %s [%s] on [%s]", tc++, type,
		 group_cmd, g->name);
	test_execute(test, "%sneighbor %s %s", dcg, g->name, group_cmd);
	test_config_absent(test, "neighbor %s %s", p->host, pa->cmd);
	test_config_absent(test, "neighbor %s %s", g->name, pa->cmd);
	test_process(test, pa, p, g->conf, false, false);

	/* Test Case: Set flag on BGP peer. */
	test_log(test, "case %02d: set %s [%s] on [%s]", tc++, type, peer_cmd,
		 p->host);
	test_execute(test, "%sneighbor %s %s", ecp, p->host, peer_cmd);
	test_config_present(test, "%sneighbor %s %s", ecp, p->host, peer_cmd);
	test_config_absent(test, "neighbor %s %s", g->name, pa->cmd);
	test_process(test, pa, p, g->conf, true, false);
}

static void bgp_startup(void)
{
	cmd_init(1);
	openzlog("testbgpd", "NONE", 0, LOG_CONS | LOG_NDELAY | LOG_PID,
		 LOG_DAEMON);
	zprivs_preinit(&bgpd_privs);
	zprivs_init(&bgpd_privs);

	master = thread_master_create(NULL);
	yang_init();
	nb_init(master, NULL, 0);
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE);
	bgp_option_set(BGP_OPT_NO_LISTEN);
	vrf_init(NULL, NULL, NULL, NULL, NULL);
	frr_pthread_init();
	bgp_init(0);
	bgp_pthreads_run();
}

static void bgp_shutdown(void)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;

	bgp_terminate();
	bgp_close();
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp_delete(bgp);
	bgp_dump_finish();
	bgp_route_finish();
	bgp_route_map_terminate();
	bgp_attr_finish();
	bgp_pthreads_finish();
	access_list_add_hook(NULL);
	access_list_delete_hook(NULL);
	access_list_reset();
	as_list_add_hook(NULL);
	as_list_delete_hook(NULL);
	bgp_filter_reset();
	prefix_list_add_hook(NULL);
	prefix_list_delete_hook(NULL);
	prefix_list_reset();
	community_list_terminate(bgp_clist);
	vrf_terminate();
#ifdef ENABLE_BGP_VNC
	vnc_zebra_destroy();
#endif
	bgp_zebra_destroy();

	bf_free(bm->rd_idspace);
	list_delete(&bm->bgp);
	memset(bm, 0, sizeof(*bm));

	vty_terminate();
	cmd_terminate();
	nb_terminate();
	yang_terminate();
	zprivs_terminate(&bgpd_privs);
	thread_master_free(master);
	master = NULL;
	closezlog();
}

int main(void)
{
	int i, ii;
	struct list *pa_list;
	struct test_peer_attr *pa, *pac;
	struct listnode *node, *nnode;

	bgp_startup();

	pa_list = list_new();
	i = 0;
	while (test_peer_attrs[i].cmd) {
		pa = &test_peer_attrs[i++];

		/* Just copy the peer attribute structure for global flags. */
		if (is_attr_type_global(pa->type)) {
			pac = XMALLOC(MTYPE_TMP, sizeof(struct test_peer_attr));
			memcpy(pac, pa, sizeof(struct test_peer_attr));
			listnode_add(pa_list, pac);
			continue;
		}

		/* Fallback to default families if not specified. */
		if (!pa->families[0].afi && !pa->families[0].safi)
			memcpy(&pa->families, test_default_families,
			       sizeof(test_default_families));

		/* Add peer attribute definition for each address family. */
		ii = 0;
		while (pa->families[ii].afi && pa->families[ii].safi) {
			pac = XMALLOC(MTYPE_TMP, sizeof(struct test_peer_attr));
			memcpy(pac, pa, sizeof(struct test_peer_attr));

			pac->afi = pa->families[ii].afi;
			pac->safi = pa->families[ii].safi;
			listnode_add(pa_list, pac);

			ii++;
		}
	}

	for (ALL_LIST_ELEMENTS(pa_list, node, nnode, pa)) {
		char *desc;
		struct test *test;

		/* Build test description string. */
		if (pa->afi && pa->safi)
			desc = str_printf("peer\\%s-%s\\%s",
					  str_from_afi(pa->afi),
					  str_from_safi(pa->safi), pa->cmd);
		else
			desc = str_printf("peer\\%s", pa->cmd);

		/* Initialize new test instance. */
		test = test_new(desc, pa->o.use_ibgp, pa->o.use_iface_peer);
		XFREE(MTYPE_TMP, desc);

		/* Execute tests and finish test instance. */
		test_peer_attr(test, pa);
		test_finish(test);

		/* Print empty line as spacer. */
		printf("\n");

		/* Free memory used for peer-attr declaration. */
		XFREE(MTYPE_TMP, pa);
	}

	list_delete(&pa_list);
	bgp_shutdown();

	return 0;
}
