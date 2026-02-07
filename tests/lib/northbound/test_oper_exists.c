// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 * Copyright (C) 2025 LabN Consulting, L.L.C.
 */

#include <zebra.h>
#include <sys/stat.h>

#include "debug.h"
#include "frrevent.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "lib_vty.h"
#include "log.h"
#include "northbound.h"
#include "northbound_cli.h"

static struct event_loop *master;
static struct lyd_node *data_tree;
static uint data_tree_lock;

const char *data_json = "\n"
	"{\n"
	"  \"frr-test-module:frr-test-module\": {\n"
	"    \"vrfs\": {\n"
	"      \"vrf\": [\n"
	"	 {\n"
	"	   \"name\": \"vrf0\",\n"
	"	   \"interfaces\": {\n"
	"	     \"interface\": [\n"
	"		\"eth0\",\n"
	"		\"eth1\",\n"
	"		\"eth2\",\n"
	"		\"eth3\"\n"
	"	     ],\n"
	"	     \"interface-new\": [\n"
	"		\"eth0\",\n"
	"		\"eth1\",\n"
	"		\"eth2\",\n"
	"		\"eth3\"\n"
	"	     ]\n"
	"	   },\n"
	"	   \"routes\": {\n"
	"	     \"route\": [\n"
	"		{\n"
	"		  \"prefix\": \"10.0.0.0/32\",\n"
	"		  \"next-hop\": \"172.16.0.0\",\n"
	"		  \"interface\": \"eth0\",\n"
	"		  \"metric\": 0,\n"
	"		  \"active\": [null]\n"
	"		},\n"
	"		{\n"
	"		  \"prefix\": \"10.0.0.1/32\",\n"
	"		  \"next-hop\": \"172.16.0.1\",\n"
	"		  \"interface\": \"eth1\",\n"
	"		  \"metric\": 1\n"
	"		},\n"
	"		{\n"
	"		  \"prefix\": \"10.0.0.2/32\",\n"
	"		  \"next-hop\": \"172.16.0.2\",\n"
	"		  \"interface\": \"eth2\",\n"
	"		  \"metric\": 2,\n"
	"		  \"active\": [null]\n"
	"		},\n"
	"		{\n"
	"		  \"prefix\": \"10.0.0.3/32\",\n"
	"		  \"next-hop\": \"172.16.0.3\",\n"
	"		  \"interface\": \"eth3\",\n"
	"		  \"metric\": 3\n"
	"		},\n"
	"		{\n"
	"		  \"prefix\": \"10.0.0.4/32\",\n"
	"		  \"next-hop\": \"172.16.0.4\",\n"
	"		  \"interface\": \"eth4\",\n"
	"		  \"metric\": 4,\n"
	"		  \"active\": [null]\n"
	"		},\n"
	"		{\n"
	"		  \"prefix\": \"10.0.0.5/32\",\n"
	"		  \"next-hop\": \"172.16.0.5\",\n"
	"		  \"interface\": \"eth5\",\n"
	"		  \"metric\": 5\n"
	"		}\n"
	"	     ]\n"
	"	   }\n"
	"	 },\n"
	"	 {\n"
	"	   \"name\": \"vrf1\",\n"
	"	   \"interfaces\": {\n"
	"	     \"interface\": [\n"
	"		\"eth0\",\n"
	"		\"eth1\",\n"
	"		\"eth2\",\n"
	"		\"eth3\"\n"
	"	     ],\n"
	"	     \"interface-new\": [\n"
	"		\"eth0\",\n"
	"		\"eth1\",\n"
	"		\"eth2\",\n"
	"		\"eth3\"\n"
	"	     ]\n"
	"	   },\n"
	"	   \"routes\": {\n"
	"	     \"route\": [\n"
	"		{\n"
	"		  \"prefix\": \"10.0.0.0/32\",\n"
	"		  \"next-hop\": \"172.16.0.0\",\n"
	"		  \"interface\": \"eth0\",\n"
	"		  \"metric\": 0,\n"
	"		  \"active\": [null]\n"
	"		},\n"
	"		{\n"
	"		  \"prefix\": \"10.0.0.1/32\",\n"
	"		  \"next-hop\": \"172.16.0.1\",\n"
	"		  \"interface\": \"eth1\",\n"
	"		  \"metric\": 1\n"
	"		},\n"
	"		{\n"
	"		  \"prefix\": \"10.0.0.2/32\",\n"
	"		  \"next-hop\": \"172.16.0.2\",\n"
	"		  \"interface\": \"eth2\",\n"
	"		  \"metric\": 2,\n"
	"		  \"active\": [null]\n"
	"		},\n"
	"		{\n"
	"		  \"prefix\": \"10.0.0.3/32\",\n"
	"		  \"next-hop\": \"172.16.0.3\",\n"
	"		  \"interface\": \"eth3\",\n"
	"		  \"metric\": 3\n"
	"		},\n"
	"		{\n"
	"		  \"prefix\": \"10.0.0.4/32\",\n"
	"		  \"next-hop\": \"172.16.0.4\",\n"
	"		  \"interface\": \"eth4\",\n"
	"		  \"metric\": 4,\n"
	"		  \"active\": [null]\n"
	"		},\n"
	"		{\n"
	"		  \"prefix\": \"10.0.0.5/32\",\n"
	"		  \"next-hop\": \"172.16.0.5\",\n"
	"		  \"interface\": \"eth5\",\n"
	"		  \"metric\": 5\n"
	"		}\n"
	"	     ]\n"
	"	   }\n"
	"	 }\n"
	"      ]\n"
	"    },\n"
	"    \"c2cont\": {\n"
	"      \"c2value\": 2868969987\n"
	"    },\n"
	"    \"c3value\": 21\n"
	"  }\n"
	"}\n";


static const struct lyd_node *test_oper_get_tree_locked(const char *xpath __attribute__((unused)),
							void **lock __attribute__((unused)))
{
	++data_tree_lock;
	return data_tree;
}

static void test_oper_unlock_tree(const struct lyd_node *tree __attribute__((unused)),
				  void *lock __attribute__((unused)))
{
	data_tree_lock--;
}

static int __rpc_return_ok(struct nb_cb_rpc_args *args)
{
	return NB_OK;
}

/* clang-format off */
const struct frr_yang_module_info frr_test_module_info = {
	.name = "frr-test-module",
	.get_tree_locked = test_oper_get_tree_locked,
	.unlock_tree = test_oper_unlock_tree,
	.nodes = {
		{
			.xpath = "/frr-test-module:frr-test-module/vrfs/vrf/ping",
			.cbs.rpc = __rpc_return_ok,
		},
		{
			.xpath = "/frr-test-module:rpc-no-args",
			.cbs.rpc = __rpc_return_ok,
		},
		{
			.xpath = "/frr-test-module:rpc-both-args",
			.cbs.rpc = __rpc_return_ok,
		},
		{
			.xpath = NULL,
		},
	}
};
/* clang-format on */

static const struct frr_yang_module_info *const modules[] = {
	&frr_test_module_info,
};

static void vty_do_exit(int isexit)
{
	printf("\nend.\n");

	lyd_free_all(data_tree);

	cmd_terminate();
	vty_terminate();
	nb_terminate();
	yang_terminate();
	event_master_free(master);

	log_memstats(NULL, true);
	if (!isexit)
		exit(0);
}


static struct lyd_node *load_data(void)
{
	struct ly_in *in = NULL;
	struct lyd_node *tree = NULL;
	LY_ERR err;

	err = ly_in_new_memory(data_json, &in);
	if (!err)
		err = lyd_parse_data(ly_native_ctx, NULL, in, LYD_JSON, LYD_PARSE_STRICT, LYD_VALIDATE_OPERATIONAL, &tree);
	ly_in_free(in, 0);
	if (err) {
		fprintf(stderr, "LYERR: %s\n", getcwd(NULL, 0));
		fprintf(stderr, "LYERR: %s\n", ly_last_errmsg());
		exit(1);
	}
	return tree;
}

/* main routine. */
int main(int argc, char **argv)
{
	struct event thread;

	/* Set umask before anything for security */
	umask(0027);

	/* master init. */
	master = event_master_create(NULL);

	// zlog_aux_init("NONE: ", ZLOG_DISABLED);

	/* Library inits. */
	cmd_init(1);
	cmd_hostname_set("test");
	vty_init(master, false);
	lib_cmd_init();
	debug_init();
	nb_init(master, modules, array_size(modules), false, false);

	/* Create artificial data. */
	data_tree = load_data();

	/* Read input from .in file. */
	vty_stdio(vty_do_exit);

	/* Fetch next active thread. */
	while (event_fetch(master, &thread))
		event_call(&thread);

	/* Not reached. */
	exit(0);
}
