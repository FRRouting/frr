/*
 * Copyright (C) 2020  NetDEF, Inc.
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

#include <lib/version.h>
#include "getopt.h"
#include "thread.h"
#include "vty.h"
#include "command.h"
#include "log.h"
#include "vrf.h"
#include "yang.h"

#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_spf_private.h"

#include "test_common.h"

enum test_type {
	TEST_SPF = 1,
};

#define F_DISPLAY_LSPDB 0x01
#define F_IPV4_ONLY 0x02
#define F_IPV6_ONLY 0x04
#define F_LEVEL1_ONLY 0x08
#define F_LEVEL2_ONLY 0x10

static struct isis *isis;

static void test_run_spf(struct vty *vty, const struct isis_topology *topology,
			 const struct isis_test_node *root,
			 struct isis_area *area, struct lspdb_head *lspdb,
			 int level, int tree)
{
	struct isis_spftree *spftree;

	/* Run SPF. */
	spftree = isis_spftree_new(area, lspdb, root->sysid, level, tree,
				   F_SPFTREE_NO_ADJACENCIES);
	isis_run_spf(spftree);

	/* Print the SPT and the corresponding routing table. */
	isis_print_spftree(vty, spftree);
	isis_print_routes(vty, spftree);

	/* Cleanup SPF tree. */
	isis_spftree_del(spftree);
}

static int test_run(struct vty *vty, const struct isis_topology *topology,
		    const struct isis_test_node *root, enum test_type test_type,
		    uint8_t flags)
{
	struct isis_area *area;

	/* Init topology. */
	memcpy(isis->sysid, root->sysid, sizeof(isis->sysid));
	area = isis_area_create("1", NULL);
	area->is_type = IS_LEVEL_1_AND_2;
	area->srdb.enabled = true;
	if (test_topology_load(topology, area, area->lspdb) != 0) {
		vty_out(vty, "%% Failed to load topology\n");
		return CMD_WARNING;
	}

	for (int level = IS_LEVEL_1; level <= IS_LEVEL_2; level++) {
		if (level == IS_LEVEL_1 && CHECK_FLAG(flags, F_LEVEL2_ONLY))
			continue;
		if (level == IS_LEVEL_2 && CHECK_FLAG(flags, F_LEVEL1_ONLY))
			continue;
		if ((root->level & level) == 0)
			continue;

		/* Print the LDPDB. */
		if (CHECK_FLAG(flags, F_DISPLAY_LSPDB))
			show_isis_database_lspdb(vty, area, level - 1,
						 &area->lspdb[level - 1], NULL,
						 ISIS_UI_LEVEL_DETAIL);

		for (int tree = SPFTREE_IPV4; tree <= SPFTREE_IPV6; tree++) {
			if (tree == SPFTREE_IPV4
			    && CHECK_FLAG(flags, F_IPV6_ONLY))
				continue;
			if (tree == SPFTREE_IPV6
			    && CHECK_FLAG(flags, F_IPV4_ONLY))
				continue;

			switch (test_type) {
			case TEST_SPF:
				test_run_spf(vty, topology, root, area,
					     &area->lspdb[level - 1], level,
					     tree);
				break;
			}
		}
	}

	/* Cleanup IS-IS area. */
	isis_area_destroy(area);

	/* Cleanup hostnames. */
	dyn_cache_cleanup_all();

	return CMD_SUCCESS;
}

DEFUN(test_isis, test_isis_cmd,
      "test isis topology (1-13) root HOSTNAME spf\
	 [display-lspdb] [<ipv4-only|ipv6-only>] [<level-1-only|level-2-only>]",
      "Test command\n"
      "IS-IS routing protocol\n"
      "Test topology\n"
      "Test topology number\n"
      "SPF root\n"
      "SPF root hostname\n"
      "Normal Shortest Path First\n"
      "Display the LSPDB\n"
      "Do IPv4 processing only\n"
      "Do IPv6 processing only\n"
      "Skip L2 LSPs\n"
      "Skip L1 LSPs\n")
{
	uint16_t topology_number;
	const struct isis_topology *topology;
	const struct isis_test_node *root;
	uint8_t flags = 0;
	int idx = 0;

	/* Load topology. */
	argv_find(argv, argc, "topology", &idx);
	topology_number = atoi(argv[idx + 1]->arg);
	topology = test_topology_find(test_topologies, topology_number);
	if (!topology) {
		vty_out(vty, "%% Topology \"%s\" not found\n",
			argv[idx + 1]->arg);
		return CMD_WARNING;
	}

	/* Find root node. */
	argv_find(argv, argc, "root", &idx);
	root = test_topology_find_node(topology, argv[idx + 1]->arg, 0);
	if (!root) {
		vty_out(vty, "%% Node \"%s\" not found\n", argv[idx + 1]->arg);
		return CMD_WARNING;
	}

	/* Parse control flags. */
	if (argv_find(argv, argc, "display-lspdb", &idx))
		SET_FLAG(flags, F_DISPLAY_LSPDB);
	if (argv_find(argv, argc, "ipv4-only", &idx))
		SET_FLAG(flags, F_IPV4_ONLY);
	else if (argv_find(argv, argc, "ipv6-only", &idx))
		SET_FLAG(flags, F_IPV6_ONLY);
	if (argv_find(argv, argc, "level-1-only", &idx))
		SET_FLAG(flags, F_LEVEL1_ONLY);
	else if (argv_find(argv, argc, "level-2-only", &idx))
		SET_FLAG(flags, F_LEVEL2_ONLY);

	return test_run(vty, topology, root, TEST_SPF, flags);
}

static void vty_do_exit(int isexit)
{
	printf("\nend.\n");

	isis_finish(isis);
	cmd_terminate();
	vty_terminate();
	yang_terminate();
	thread_master_free(master);

	log_memstats(stderr, "test-isis-spf");
	if (!isexit)
		exit(0);
}

struct option longopts[] = {{"help", no_argument, NULL, 'h'},
			    {"debug", no_argument, NULL, 'd'},
			    {0}};

/* Help information display. */
static void usage(char *progname, int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			progname);
	else {
		printf("Usage : %s [OPTION...]\n\
isisd SPF test program.\n\n\
-u, --debug        Enable debugging\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n",
		       progname, FRR_BUG_ADDRESS);
	}
	exit(status);
}

int main(int argc, char **argv)
{
	char *p;
	char *progname;
	struct thread thread;
	bool debug = false;

	/* Set umask before anything for security */
	umask(0027);

	/* get program name */
	progname = ((p = strrchr(argv[0], '/')) ? ++p : argv[0]);

	while (1) {
		int opt;

		opt = getopt_long(argc, argv, "hd", longopts, 0);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		case 'd':
			debug = true;
			break;
		case 'h':
			usage(progname, 0);
			break;
		default:
			usage(progname, 1);
			break;
		}
	}

	/* master init. */
	master = thread_master_create(NULL);
	isis_master_init(master);

	/* Library inits. */
	cmd_init(1);
	cmd_hostname_set("test");
	vty_init(master, false);
	yang_init(true);
	if (debug)
		zlog_aux_init("NONE: ", LOG_DEBUG);
	else
		zlog_aux_init("NONE: ", ZLOG_DISABLED);

	/* IS-IS inits. */
	yang_module_load("frr-isisd");
	isis = isis_new(VRF_DEFAULT);
	listnode_add(im->isis, isis);
	SET_FLAG(im->options, F_ISIS_UNIT_TEST);
	debug_spf_events |= DEBUG_SPF_EVENTS;
	debug_events |= DEBUG_EVENTS;
	debug_rte_events |= DEBUG_RTE_EVENTS;

	/* Install test command. */
	install_element(VIEW_NODE, &test_isis_cmd);

	/* Read input from .in file. */
	vty_stdio(vty_do_exit);

	/* Fetch next active thread. */
	while (thread_fetch(master, &thread))
		thread_call(&thread);

	/* Not reached. */
	exit(0);
}
