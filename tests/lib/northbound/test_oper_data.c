/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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

#include "thread.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "memory_vty.h"
#include "log.h"
#include "northbound.h"

static struct thread_master *master;

struct troute {
	struct prefix_ipv4 prefix;
	struct in_addr nexthop;
	char ifname[IFNAMSIZ];
	uint8_t metric;
	bool active;
};

struct tvrf {
	char name[32];
	struct list *interfaces;
	struct list *routes;
};

static struct list *vrfs;

/*
 * XPath: /frr-test-module:frr-test-module/vrfs/vrf
 */
static const void *
frr_test_module_vrfs_vrf_get_next(const void *parent_list_entry,
				  const void *list_entry)
{
	struct listnode *node;

	if (list_entry == NULL)
		node = listhead(vrfs);
	else
		node = listnextnode((struct listnode *)list_entry);

	return node;
}

static int frr_test_module_vrfs_vrf_get_keys(const void *list_entry,
					     struct yang_list_keys *keys)
{
	const struct tvrf *vrf;

	vrf = listgetdata((struct listnode *)list_entry);

	keys->num = 1;
	strlcpy(keys->key[0], vrf->name, sizeof(keys->key[0]));

	return NB_OK;
}

static const void *
frr_test_module_vrfs_vrf_lookup_entry(const void *parent_list_entry,
				      const struct yang_list_keys *keys)
{
	struct listnode *node;
	struct tvrf *vrf;
	const char *vrfname;

	vrfname = keys->key[0];

	for (ALL_LIST_ELEMENTS_RO(vrfs, node, vrf)) {
		if (strmatch(vrf->name, vrfname))
			return node;
	}

	return NULL;
}

/*
 * XPath: /frr-test-module:frr-test-module/vrfs/vrf/name
 */
static struct yang_data *
frr_test_module_vrfs_vrf_name_get_elem(const char *xpath,
				       const void *list_entry)
{
	const struct tvrf *vrf;

	vrf = listgetdata((struct listnode *)list_entry);
	return yang_data_new_string(xpath, vrf->name);
}

/*
 * XPath: /frr-test-module:frr-test-module/vrfs/vrf/interfaces/interface
 */
static struct yang_data *
frr_test_module_vrfs_vrf_interfaces_interface_get_elem(const char *xpath,
						       const void *list_entry)
{
	const char *interface;

	interface = listgetdata((struct listnode *)list_entry);
	return yang_data_new_string(xpath, interface);
}

static const void *frr_test_module_vrfs_vrf_interfaces_interface_get_next(
	const void *parent_list_entry, const void *list_entry)
{
	const struct tvrf *vrf;
	struct listnode *node;

	vrf = listgetdata((struct listnode *)parent_list_entry);
	if (list_entry == NULL)
		node = listhead(vrf->interfaces);
	else
		node = listnextnode((struct listnode *)list_entry);

	return node;
}

/*
 * XPath: /frr-test-module:frr-test-module/vrfs/vrf/routes/route
 */
static const void *
frr_test_module_vrfs_vrf_routes_route_get_next(const void *parent_list_entry,
					       const void *list_entry)
{
	const struct tvrf *vrf;
	struct listnode *node;

	vrf = listgetdata((struct listnode *)parent_list_entry);
	if (list_entry == NULL)
		node = listhead(vrf->routes);
	else
		node = listnextnode((struct listnode *)list_entry);

	return node;
}

static int
frr_test_module_vrfs_vrf_routes_route_get_keys(const void *list_entry,
					       struct yang_list_keys *keys)
{
	const struct troute *route;

	route = listgetdata((struct listnode *)list_entry);

	keys->num = 1;
	(void)prefix2str(&route->prefix, keys->key[0], sizeof(keys->key[0]));

	return NB_OK;
}

static const void *frr_test_module_vrfs_vrf_routes_route_lookup_entry(
	const void *parent_list_entry, const struct yang_list_keys *keys)
{
	const struct tvrf *vrf;
	const struct troute *route;
	struct listnode *node;
	struct prefix prefix;

	yang_str2ipv4p(keys->key[0], &prefix);

	vrf = listgetdata((struct listnode *)parent_list_entry);
	for (ALL_LIST_ELEMENTS_RO(vrf->routes, node, route)) {
		if (prefix_same((struct prefix *)&route->prefix, &prefix))
			return node;
	}

	return NULL;
}

/*
 * XPath: /frr-test-module:frr-test-module/vrfs/vrf/routes/route/prefix
 */
static struct yang_data *
frr_test_module_vrfs_vrf_routes_route_prefix_get_elem(const char *xpath,
						      const void *list_entry)
{
	const struct troute *route;

	route = listgetdata((struct listnode *)list_entry);
	return yang_data_new_ipv4p(xpath, &route->prefix);
}

/*
 * XPath: /frr-test-module:frr-test-module/vrfs/vrf/routes/route/next-hop
 */
static struct yang_data *
frr_test_module_vrfs_vrf_routes_route_next_hop_get_elem(const char *xpath,
							const void *list_entry)
{
	const struct troute *route;

	route = listgetdata((struct listnode *)list_entry);
	return yang_data_new_ipv4(xpath, &route->nexthop);
}

/*
 * XPath: /frr-test-module:frr-test-module/vrfs/vrf/routes/route/interface
 */
static struct yang_data *
frr_test_module_vrfs_vrf_routes_route_interface_get_elem(const char *xpath,
							 const void *list_entry)
{
	const struct troute *route;

	route = listgetdata((struct listnode *)list_entry);
	return yang_data_new_string(xpath, route->ifname);
}

/*
 * XPath: /frr-test-module:frr-test-module/vrfs/vrf/routes/route/metric
 */
static struct yang_data *
frr_test_module_vrfs_vrf_routes_route_metric_get_elem(const char *xpath,
						      const void *list_entry)
{
	const struct troute *route;

	route = listgetdata((struct listnode *)list_entry);
	return yang_data_new_uint8(xpath, route->metric);
}

/*
 * XPath: /frr-test-module:frr-test-module/vrfs/vrf/routes/route/active
 */
static struct yang_data *
frr_test_module_vrfs_vrf_routes_route_active_get_elem(const char *xpath,
						      const void *list_entry)
{
	const struct troute *route;

	route = listgetdata((struct listnode *)list_entry);
	if (route->active)
		return yang_data_new(xpath, NULL);

	return NULL;
}

/* clang-format off */
const struct frr_yang_module_info frr_test_module_info = {
	.name = "frr-test-module",
	.nodes = {
		{
			.xpath = "/frr-test-module:frr-test-module/vrfs/vrf",
			.cbs.get_next = frr_test_module_vrfs_vrf_get_next,
			.cbs.get_keys = frr_test_module_vrfs_vrf_get_keys,
			.cbs.lookup_entry = frr_test_module_vrfs_vrf_lookup_entry,
		},
		{
			.xpath = "/frr-test-module:frr-test-module/vrfs/vrf/name",
			.cbs.get_elem = frr_test_module_vrfs_vrf_name_get_elem,
		},
		{
			.xpath = "/frr-test-module:frr-test-module/vrfs/vrf/interfaces/interface",
			.cbs.get_elem = frr_test_module_vrfs_vrf_interfaces_interface_get_elem,
			.cbs.get_next = frr_test_module_vrfs_vrf_interfaces_interface_get_next,
		},
		{
			.xpath = "/frr-test-module:frr-test-module/vrfs/vrf/routes/route",
			.cbs.get_next = frr_test_module_vrfs_vrf_routes_route_get_next,
			.cbs.get_keys = frr_test_module_vrfs_vrf_routes_route_get_keys,
			.cbs.lookup_entry = frr_test_module_vrfs_vrf_routes_route_lookup_entry,
		},
		{
			.xpath = "/frr-test-module:frr-test-module/vrfs/vrf/routes/route/prefix",
			.cbs.get_elem = frr_test_module_vrfs_vrf_routes_route_prefix_get_elem,
		},
		{
			.xpath = "/frr-test-module:frr-test-module/vrfs/vrf/routes/route/next-hop",
			.cbs.get_elem = frr_test_module_vrfs_vrf_routes_route_next_hop_get_elem,
		},
		{
			.xpath = "/frr-test-module:frr-test-module/vrfs/vrf/routes/route/interface",
			.cbs.get_elem = frr_test_module_vrfs_vrf_routes_route_interface_get_elem,
		},
		{
			.xpath = "/frr-test-module:frr-test-module/vrfs/vrf/routes/route/metric",
			.cbs.get_elem = frr_test_module_vrfs_vrf_routes_route_metric_get_elem,
		},
		{
			.xpath = "/frr-test-module:frr-test-module/vrfs/vrf/routes/route/active",
			.cbs.get_elem = frr_test_module_vrfs_vrf_routes_route_active_get_elem,
		},
		{
			.xpath = NULL,
		},
	}
};
/* clang-format on */

static const struct frr_yang_module_info *modules[] = {
	&frr_test_module_info,
};

static void create_data(unsigned int num_vrfs, unsigned int num_interfaces,
			unsigned int num_routes)
{
	struct prefix_ipv4 base_prefix;
	struct in_addr base_nexthop;

	(void)str2prefix_ipv4("10.0.0.0/32", &base_prefix);
	(void)inet_pton(AF_INET, "172.16.0.0", &base_nexthop);

	vrfs = list_new();

	/* Create VRFs. */
	for (unsigned int i = 0; i < num_vrfs; i++) {
		struct tvrf *vrf;

		vrf = XCALLOC(MTYPE_TMP, sizeof(*vrf));
		snprintf(vrf->name, sizeof(vrf->name), "vrf%u", i);
		vrf->interfaces = list_new();
		vrf->routes = list_new();

		/* Create interfaces. */
		for (unsigned int j = 0; j < num_interfaces; j++) {
			char ifname[32];
			char *interface;

			snprintf(ifname, sizeof(ifname), "eth%u", j);
			interface = XSTRDUP(MTYPE_TMP, ifname);
			listnode_add(vrf->interfaces, interface);
		}

		/* Create routes. */
		for (unsigned int j = 0; j < num_routes; j++) {
			struct troute *route;

			route = XCALLOC(MTYPE_TMP, sizeof(*route));

			memcpy(&route->prefix, &base_prefix,
			       sizeof(route->prefix));
			route->prefix.prefix.s_addr =
				htonl(ntohl(route->prefix.prefix.s_addr) + j);

			memcpy(&route->nexthop, &base_nexthop,
			       sizeof(route->nexthop));
			route->nexthop.s_addr =
				htonl(ntohl(route->nexthop.s_addr) + j);

			snprintf(route->ifname, sizeof(route->ifname), "eth%u",
				 j);
			route->metric = j % 256;
			route->active = (j % 2 == 0);
			listnode_add(vrf->routes, route);
		}

		listnode_add(vrfs, vrf);
	}
}

static void interface_delete(void *ptr)
{
	char *interface = ptr;

	XFREE(MTYPE_TMP, interface);
}

static void route_delete(void *ptr)
{
	struct troute *route = ptr;

	XFREE(MTYPE_TMP, route);
}

static void vrf_delete(void *ptr)
{
	struct tvrf *vrf = ptr;

	vrf->interfaces->del = interface_delete;
	list_delete(&vrf->interfaces);
	vrf->routes->del = route_delete;
	list_delete(&vrf->routes);
	XFREE(MTYPE_TMP, vrf);
}

static void delete_data(void)
{
	vrfs->del = vrf_delete;
	list_delete(&vrfs);
}

static void vty_do_exit(int isexit)
{
	printf("\nend.\n");

	delete_data();

	cmd_terminate();
	vty_terminate();
	nb_terminate();
	yang_terminate();
	thread_master_free(master);
	closezlog();

	log_memstats(stderr, "test-nb-oper-data");
	if (!isexit)
		exit(0);
}

/* main routine. */
int main(int argc, char **argv)
{
	struct thread thread;
	unsigned int num_vrfs = 2;
	unsigned int num_interfaces = 4;
	unsigned int num_routes = 6;

	if (argc > 1)
		num_vrfs = atoi(argv[1]);
	if (argc > 2)
		num_interfaces = atoi(argv[2]);
	if (argc > 3)
		num_routes = atoi(argv[3]);

	/* Set umask before anything for security */
	umask(0027);

	/* master init. */
	master = thread_master_create(NULL);

	openzlog("test-nb-oper-data", "NONE", 0,
		 LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);
	zlog_set_level(ZLOG_DEST_SYSLOG, ZLOG_DISABLED);
	zlog_set_level(ZLOG_DEST_STDOUT, ZLOG_DISABLED);
	zlog_set_level(ZLOG_DEST_MONITOR, LOG_DEBUG);

	/* Library inits. */
	cmd_init(1);
	cmd_hostname_set("test");
	vty_init(master);
	memory_init();
	yang_init();
	nb_init(modules, array_size(modules));

	/* Create artificial data. */
	create_data(num_vrfs, num_interfaces, num_routes);

	/* Read input from .in file. */
	vty_stdio(vty_do_exit);

	/* Fetch next active thread. */
	while (thread_fetch(master, &thread))
		thread_call(&thread);

	/* Not reached. */
	exit(0);
}
