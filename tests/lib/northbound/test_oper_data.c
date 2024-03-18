// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 */

#include <zebra.h>
#include <sys/stat.h>

#include "frrevent.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "lib_vty.h"
#include "log.h"
#include "northbound.h"
#include "northbound_cli.h"

static struct event_loop *master;

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
frr_test_module_vrfs_vrf_get_next(struct nb_cb_get_next_args *args)
{
	struct listnode *node;

	if (args->list_entry == NULL)
		node = listhead(vrfs);
	else
		node = listnextnode((struct listnode *)args->list_entry);

	return node;
}

static int frr_test_module_vrfs_vrf_get_keys(struct nb_cb_get_keys_args *args)
{
	const struct tvrf *vrf;

	vrf = listgetdata((struct listnode *)args->list_entry);

	args->keys->num = 1;
	strlcpy(args->keys->key[0], vrf->name, sizeof(args->keys->key[0]));

	return NB_OK;
}

static const void *
frr_test_module_vrfs_vrf_lookup_entry(struct nb_cb_lookup_entry_args *args)
{
	struct listnode *node;
	struct tvrf *vrf;
	const char *vrfname;

	vrfname = args->keys->key[0];

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
frr_test_module_vrfs_vrf_name_get_elem(struct nb_cb_get_elem_args *args)
{
	const struct tvrf *vrf;

	vrf = listgetdata((struct listnode *)args->list_entry);
	return yang_data_new_string(args->xpath, vrf->name);
}

/*
 * XPath: /frr-test-module:frr-test-module/vrfs/vrf/interfaces/interface
 */
static struct yang_data *frr_test_module_vrfs_vrf_interfaces_interface_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const char *interface;

	interface = listgetdata((struct listnode *)args->list_entry);
	return yang_data_new_string(args->xpath, interface);
}

static const void *frr_test_module_vrfs_vrf_interfaces_interface_get_next(
	struct nb_cb_get_next_args *args)
{
	const struct tvrf *vrf;
	struct listnode *node;

	vrf = listgetdata((struct listnode *)args->parent_list_entry);
	if (args->list_entry == NULL)
		node = listhead(vrf->interfaces);
	else
		node = listnextnode((struct listnode *)args->list_entry);

	return node;
}

/*
 * XPath: /frr-test-module:frr-test-module/vrfs/vrf/routes/route
 */
static const void *
frr_test_module_vrfs_vrf_routes_route_get_next(struct nb_cb_get_next_args *args)
{
	const struct tvrf *vrf;
	struct listnode *node;

	vrf = listgetdata((struct listnode *)args->parent_list_entry);
	if (args->list_entry == NULL)
		node = listhead(vrf->routes);
	else
		node = listnextnode((struct listnode *)args->list_entry);

	return node;
}

/*
 * XPath: /frr-test-module:frr-test-module/vrfs/vrf/routes/route/prefix
 */
static struct yang_data *frr_test_module_vrfs_vrf_routes_route_prefix_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct troute *route;

	route = listgetdata((struct listnode *)args->list_entry);
	return yang_data_new_ipv4p(args->xpath, &route->prefix);
}

/*
 * XPath: /frr-test-module:frr-test-module/vrfs/vrf/routes/route/next-hop
 */
static struct yang_data *
frr_test_module_vrfs_vrf_routes_route_next_hop_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct troute *route;

	route = listgetdata((struct listnode *)args->list_entry);
	return yang_data_new_ipv4(args->xpath, &route->nexthop);
}

/*
 * XPath: /frr-test-module:frr-test-module/vrfs/vrf/routes/route/interface
 */
static struct yang_data *
frr_test_module_vrfs_vrf_routes_route_interface_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct troute *route;

	route = listgetdata((struct listnode *)args->list_entry);
	return yang_data_new_string(args->xpath, route->ifname);
}

/*
 * XPath: /frr-test-module:frr-test-module/vrfs/vrf/routes/route/metric
 */
static struct yang_data *frr_test_module_vrfs_vrf_routes_route_metric_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct troute *route;

	route = listgetdata((struct listnode *)args->list_entry);
	return yang_data_new_uint8(args->xpath, route->metric);
}

/*
 * XPath: /frr-test-module:frr-test-module/vrfs/vrf/routes/route/active
 */
static struct yang_data *frr_test_module_vrfs_vrf_routes_route_active_get_elem(
	struct nb_cb_get_elem_args *args)
{
	const struct troute *route;

	route = listgetdata((struct listnode *)args->list_entry);
	if (route->active)
		return yang_data_new(args->xpath, NULL);

	return NULL;
}

/*
 * XPath: /frr-test-module:frr-test-module/vrfs/vrf/ping
 */
static int frr_test_module_vrfs_vrf_ping(struct nb_cb_rpc_args *args)
{
	const char *vrf = yang_dnode_get_string(args->input, "../name");
	const char *data = yang_dnode_get_string(args->input, "data");

	yang_dnode_rpc_output_add(args->output, "vrf", vrf);
	yang_dnode_rpc_output_add(args->output, "data-out", data);

	return NB_OK;
}

/*
 * XPath: /frr-test-module:frr-test-module/c1value
 */
static struct yang_data *
frr_test_module_c1value_get_elem(struct nb_cb_get_elem_args *args)
{
	return yang_data_new_uint8(args->xpath, 21);
}

/*
 * XPath: /frr-test-module:frr-test-module/c2cont/c2value
 */
static struct yang_data *
frr_test_module_c2cont_c2value_get_elem(struct nb_cb_get_elem_args *args)
{
	return yang_data_new_uint32(args->xpath, 0xAB010203);
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
			.xpath = "/frr-test-module:frr-test-module/vrfs/vrf/ping",
			.cbs.rpc = frr_test_module_vrfs_vrf_ping,
		},
		{
			.xpath = "/frr-test-module:frr-test-module/c1value",
			.cbs.get_elem = frr_test_module_c1value_get_elem,
		},
		{
			.xpath = "/frr-test-module:frr-test-module/c2cont/c2value",
			.cbs.get_elem = frr_test_module_c2cont_c2value_get_elem,
		},
		{
			.xpath = NULL,
		},
	}
};
/* clang-format on */

DEFUN(test_rpc, test_rpc_cmd, "test rpc",
      "Test\n"
      "RPC\n")
{
	struct lyd_node *output = NULL;
	char xpath[XPATH_MAXLEN];
	int ret;

	snprintf(xpath, sizeof(xpath),
		 "/frr-test-module:frr-test-module/vrfs/vrf[name='testname']/ping");

	nb_cli_rpc_enqueue(vty, "data", "testdata");

	ret = nb_cli_rpc(vty, xpath, &output);
	if (ret != CMD_SUCCESS) {
		vty_out(vty, "RPC failed\n");
		return ret;
	}

	vty_out(vty, "vrf %s data %s\n", yang_dnode_get_string(output, "vrf"),
		yang_dnode_get_string(output, "data-out"));

	yang_dnode_free(output);

	return CMD_SUCCESS;
}

static const struct frr_yang_module_info *const modules[] = {
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
	event_master_free(master);

	log_memstats(stderr, "test-nb-oper-data");
	if (!isexit)
		exit(0);
}

/* main routine. */
int main(int argc, char **argv)
{
	struct event thread;
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
	master = event_master_create(NULL);

	zlog_aux_init("NONE: ", ZLOG_DISABLED);

	/* Library inits. */
	cmd_init(1);
	cmd_hostname_set("test");
	vty_init(master, false);
	lib_cmd_init();
	nb_init(master, modules, array_size(modules), false);

	install_element(ENABLE_NODE, &test_rpc_cmd);

	/* Create artificial data. */
	create_data(num_vrfs, num_interfaces, num_routes);

	/* Read input from .in file. */
	vty_stdio(vty_do_exit);

	/* Fetch next active thread. */
	while (event_fetch(master, &thread))
		event_call(&thread);

	/* Not reached. */
	exit(0);
}
