// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 *                     Renato Westphal
 */

#include <zebra.h>
#include <sys/stat.h>

#include <lib/version.h>
#include "getopt.h"
#include "frrevent.h"
#include "vty.h"
#include "command.h"
#include "log.h"
#include "vrf.h"
#include "yang.h"

#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_route.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_spf_private.h"

#include "test_common.h"

enum test_type {
	TEST_SPF = 1,
	TEST_REVERSE_SPF,
	TEST_LFA,
	TEST_RLFA,
	TEST_TI_LFA,
};

#define F_DISPLAY_LSPDB 0x01
#define F_IPV4_ONLY 0x02
#define F_IPV6_ONLY 0x04
#define F_LEVEL1_ONLY 0x08
#define F_LEVEL2_ONLY 0x10

static void test_run_spf(struct vty *vty, const struct isis_topology *topology,
			 const struct isis_test_node *root,
			 struct isis_area *area, struct lspdb_head *lspdb,
			 int level, int tree, bool reverse)
{
	struct isis_spftree *spftree;
	enum spf_type spf_type;

	/* Run SPF. */
	spf_type = reverse ? SPF_TYPE_REVERSE : SPF_TYPE_FORWARD;
	spftree = isis_spftree_new(area, lspdb, root->sysid, level, tree,
				   spf_type, F_SPFTREE_NO_ADJACENCIES,
				   SR_ALGORITHM_SPF);
	isis_run_spf(spftree);

	/* Print the SPT and the corresponding routing table. */
	isis_print_spftree(vty, spftree);
	isis_print_routes(vty, spftree, NULL, false, false);

	/* Cleanup SPF tree. */
	isis_spftree_del(spftree);
}

static void test_run_lfa(struct vty *vty, const struct isis_topology *topology,
			 const struct isis_test_node *root,
			 struct isis_area *area, struct lspdb_head *lspdb,
			 int level, int tree,
			 struct lfa_protected_resource *protected_resource)
{
	struct isis_spftree *spftree_self;
	uint8_t flags;

	/* Run forward SPF in the root node. */
	flags = F_SPFTREE_NO_ADJACENCIES;
	spftree_self =
		isis_spftree_new(area, lspdb, root->sysid, level, tree,
				 SPF_TYPE_FORWARD, flags, SR_ALGORITHM_SPF);
	isis_run_spf(spftree_self);

	/* Run forward SPF on all adjacent routers. */
	isis_spf_run_neighbors(spftree_self);

	/* Compute the LFA repair paths. */
	isis_lfa_compute(area, NULL, spftree_self, protected_resource);

	/* Print the SPT and the corresponding main/backup routing tables. */
	isis_print_spftree(vty, spftree_self);
	vty_out(vty, "Main:\n");
	isis_print_routes(vty, spftree_self, NULL, false, false);
	vty_out(vty, "Backup:\n");
	isis_print_routes(vty, spftree_self, NULL, false, true);

	/* Cleanup everything. */
	isis_spftree_del(spftree_self);
}

static void test_run_rlfa(struct vty *vty, const struct isis_topology *topology,
			  const struct isis_test_node *root,
			  struct isis_area *area, struct lspdb_head *lspdb,
			  int level, int tree,
			  struct lfa_protected_resource *protected_resource)
{
	struct isis_spftree *spftree_self;
	struct isis_spftree *spftree_reverse;
	struct isis_spftree *spftree_pc;
	struct isis_spf_node *spf_node, *node;
	struct rlfa *rlfa;
	uint8_t flags;

	/* Run forward SPF in the root node. */
	flags = F_SPFTREE_NO_ADJACENCIES;
	spftree_self =
		isis_spftree_new(area, lspdb, root->sysid, level, tree,
				 SPF_TYPE_FORWARD, flags, SR_ALGORITHM_SPF);
	isis_run_spf(spftree_self);

	/* Run reverse SPF in the root node. */
	spftree_reverse = isis_spf_reverse_run(spftree_self);

	/* Run forward SPF on all adjacent routers. */
	isis_spf_run_neighbors(spftree_self);

	/* Compute the local LFA repair paths. */
	isis_lfa_compute(area, NULL, spftree_self, protected_resource);

	/* Compute the remote LFA repair paths. */
	spftree_pc = isis_rlfa_compute(area, spftree_self, spftree_reverse, 0,
				       protected_resource);

	/* Print the extended P-space and Q-space. */
	vty_out(vty, "P-space (self):\n");
	RB_FOREACH (node, isis_spf_nodes, &spftree_pc->lfa.p_space)
		vty_out(vty, " %s\n", print_sys_hostname(node->sysid));
	vty_out(vty, "\n");
	RB_FOREACH (spf_node, isis_spf_nodes, &spftree_self->adj_nodes) {
		if (RB_EMPTY(isis_spf_nodes, &spf_node->lfa.p_space))
			continue;
		vty_out(vty, "P-space (%s):\n",
			print_sys_hostname(spf_node->sysid));
		RB_FOREACH (node, isis_spf_nodes, &spf_node->lfa.p_space)
			vty_out(vty, " %s\n", print_sys_hostname(node->sysid));
		vty_out(vty, "\n");
	}
	vty_out(vty, "Q-space:\n");
	RB_FOREACH (node, isis_spf_nodes, &spftree_pc->lfa.q_space)
		vty_out(vty, " %s\n", print_sys_hostname(node->sysid));
	vty_out(vty, "\n");

	/* Print the post-convergence SPT. */
	isis_print_spftree(vty, spftree_pc);

	/*
	 * Activate the computed RLFAs (if any) using artificial LDP labels for
	 * the PQ nodes.
	 */
	frr_each_safe (rlfa_tree, &spftree_self->lfa.remote.rlfas, rlfa) {
		struct zapi_rlfa_response response = {};

		response.pq_label = test_topology_node_ldp_label(
			topology, rlfa->pq_address);
		assert(response.pq_label != MPLS_INVALID_LABEL);
		isis_rlfa_activate(spftree_self, rlfa, &response);
	}

	/* Print the SPT and the corresponding main/backup routing tables. */
	isis_print_spftree(vty, spftree_self);
	vty_out(vty, "Main:\n");
	isis_print_routes(vty, spftree_self, NULL, false, false);
	vty_out(vty, "Backup:\n");
	isis_print_routes(vty, spftree_self, NULL, false, true);

	/* Cleanup everything. */
	isis_spftree_del(spftree_self);
	isis_spftree_del(spftree_reverse);
	isis_spftree_del(spftree_pc);
}

static void test_run_ti_lfa(struct vty *vty,
			    const struct isis_topology *topology,
			    const struct isis_test_node *root,
			    struct isis_area *area, struct lspdb_head *lspdb,
			    int level, int tree,
			    struct lfa_protected_resource *protected_resource)
{
	struct isis_spftree *spftree_self;
	struct isis_spftree *spftree_reverse;
	struct isis_spftree *spftree_pc;
	struct isis_spf_node *spf_node, *node;
	uint8_t flags;

	/* Run forward SPF in the root node. */
	flags = F_SPFTREE_NO_ADJACENCIES;
	spftree_self =
		isis_spftree_new(area, lspdb, root->sysid, level, tree,
				 SPF_TYPE_FORWARD, flags, SR_ALGORITHM_SPF);
	isis_run_spf(spftree_self);

	/* Run reverse SPF in the root node. */
	spftree_reverse = isis_spf_reverse_run(spftree_self);

	/* Run forward SPF on all adjacent routers. */
	isis_spf_run_neighbors(spftree_self);

	/* Compute the TI-LFA repair paths. */
	spftree_pc = isis_tilfa_compute(area, spftree_self, spftree_reverse,
					protected_resource);

	/* Print the extended P-space and Q-space. */
	vty_out(vty, "P-space (self):\n");
	RB_FOREACH (node, isis_spf_nodes, &spftree_pc->lfa.p_space)
		vty_out(vty, " %s\n", print_sys_hostname(node->sysid));
	vty_out(vty, "\n");
	RB_FOREACH (spf_node, isis_spf_nodes, &spftree_self->adj_nodes) {
		if (RB_EMPTY(isis_spf_nodes, &spf_node->lfa.p_space))
			continue;
		vty_out(vty, "P-space (%s):\n",
			print_sys_hostname(spf_node->sysid));
		RB_FOREACH (node, isis_spf_nodes, &spf_node->lfa.p_space)
			vty_out(vty, " %s\n", print_sys_hostname(node->sysid));
		vty_out(vty, "\n");
	}
	vty_out(vty, "Q-space:\n");
	RB_FOREACH (node, isis_spf_nodes, &spftree_pc->lfa.q_space)
		vty_out(vty, " %s\n", print_sys_hostname(node->sysid));
	vty_out(vty, "\n");

	/*
	 * Print the post-convergence SPT and the corresponding routing table.
	 */
	isis_print_spftree(vty, spftree_pc);
	isis_print_routes(vty, spftree_self, NULL, false, true);

	/* Cleanup everything. */
	isis_spftree_del(spftree_self);
	isis_spftree_del(spftree_reverse);
	isis_spftree_del(spftree_pc);
}

static int test_run(struct vty *vty, const struct isis_topology *topology,
		    const struct isis_test_node *root, enum test_type test_type,
		    uint8_t flags, enum lfa_protection_type protection_type,
		    const char *fail_sysid_str, uint8_t fail_pseudonode_id)
{
	struct isis_area *area;
	struct lfa_protected_resource protected_resource = {};
	uint8_t fail_id[ISIS_SYS_ID_LEN] = {};

	/* Init topology. */
	area = isis_area_create("1", NULL);
	memcpy(area->isis->sysid, root->sysid, sizeof(area->isis->sysid));
	area->is_type = IS_LEVEL_1_AND_2;
	area->srdb.enabled = true;
	if (test_topology_load(topology, area, area->lspdb) != 0) {
		vty_out(vty, "%% Failed to load topology\n");
		return CMD_WARNING;
	}

	/* Parse failed link/node. */
	if (fail_sysid_str) {
		if (sysid2buff(fail_id, fail_sysid_str) == 0) {
			struct isis_dynhn *dynhn;

			dynhn = dynhn_find_by_name(area->isis, fail_sysid_str);
			if (dynhn == NULL) {
				vty_out(vty, "Invalid system id %s\n",
					fail_sysid_str);
				return CMD_WARNING;
			}
			memcpy(fail_id, dynhn->id, ISIS_SYS_ID_LEN);
		}

		protected_resource.type = protection_type;
		memcpy(protected_resource.adjacency, fail_id, ISIS_SYS_ID_LEN);
		LSP_PSEUDO_ID(protected_resource.adjacency) =
			fail_pseudonode_id;
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
			show_isis_database_lspdb_vty(vty, area, level - 1,
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
					     tree, false);
				break;
			case TEST_REVERSE_SPF:
				test_run_spf(vty, topology, root, area,
					     &area->lspdb[level - 1], level,
					     tree, true);
				break;
			case TEST_LFA:
				test_run_lfa(vty, topology, root, area,
					     &area->lspdb[level - 1], level,
					     tree, &protected_resource);
				break;
			case TEST_RLFA:
				test_run_rlfa(vty, topology, root, area,
					      &area->lspdb[level - 1], level,
					      tree, &protected_resource);
				break;
			case TEST_TI_LFA:
				test_run_ti_lfa(vty, topology, root, area,
						&area->lspdb[level - 1], level,
						tree, &protected_resource);
				break;
			}
		}
	}

	/* Cleanup IS-IS area. */
	isis_area_destroy(area);

	return CMD_SUCCESS;
}

DEFUN(test_isis, test_isis_cmd,
      "test isis topology (1-14) root HOSTNAME\
         <\
	   spf\
	   |reverse-spf\
	   |lfa system-id WORD [pseudonode-id <1-255>]\
	   |remote-lfa system-id WORD [pseudonode-id <1-255>]\
	   |ti-lfa system-id WORD [pseudonode-id <1-255>] [node-protection]\
	 >\
	 [display-lspdb] [<ipv4-only|ipv6-only>] [<level-1-only|level-2-only>]",
      "Test command\n"
      "IS-IS routing protocol\n"
      "Test topology\n"
      "Test topology number\n"
      "SPF root\n"
      "SPF root hostname\n"
      "Normal Shortest Path First\n"
      "Reverse Shortest Path First\n"
      "Classic LFA\n"
      "System ID\n"
      "System ID\n"
      "Pseudonode-ID\n"
      "Pseudonode-ID\n"
      "Remote LFA\n"
      "System ID\n"
      "System ID\n"
      "Pseudonode-ID\n"
      "Pseudonode-ID\n"
      "Topology Independent LFA\n"
      "System ID\n"
      "System ID\n"
      "Pseudonode-ID\n"
      "Pseudonode-ID\n"
      "Node protection\n"
      "Display the LSPDB\n"
      "Do IPv4 processing only\n"
      "Do IPv6 processing only\n"
      "Skip L2 LSPs\n"
      "Skip L1 LSPs\n")
{
	uint16_t topology_number;
	const struct isis_topology *topology;
	const struct isis_test_node *root;
	enum test_type test_type;
	enum lfa_protection_type protection_type = 0;
	const char *fail_sysid_str = NULL;
	uint8_t fail_pseudonode_id = 0;
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

	/* Parse test information. */
	if (argv_find(argv, argc, "spf", &idx))
		test_type = TEST_SPF;
	else if (argv_find(argv, argc, "reverse-spf", &idx))
		test_type = TEST_REVERSE_SPF;
	else if (argv_find(argv, argc, "lfa", &idx)) {
		test_type = TEST_LFA;

		fail_sysid_str = argv[idx + 2]->arg;
		if (argv_find(argv, argc, "pseudonode-id", &idx))
			fail_pseudonode_id =
				strtoul(argv[idx + 1]->arg, NULL, 10);
		protection_type = LFA_LINK_PROTECTION;
	} else if (argv_find(argv, argc, "remote-lfa", &idx)) {
		test_type = TEST_RLFA;

		fail_sysid_str = argv[idx + 2]->arg;
		if (argv_find(argv, argc, "pseudonode-id", &idx))
			fail_pseudonode_id =
				strtoul(argv[idx + 1]->arg, NULL, 10);
		protection_type = LFA_LINK_PROTECTION;
	} else if (argv_find(argv, argc, "ti-lfa", &idx)) {
		test_type = TEST_TI_LFA;

		fail_sysid_str = argv[idx + 2]->arg;
		if (argv_find(argv, argc, "pseudonode-id", &idx))
			fail_pseudonode_id =
				strtoul(argv[idx + 1]->arg, NULL, 10);
		if (argv_find(argv, argc, "node-protection", &idx))
			protection_type = LFA_NODE_PROTECTION;
		else
			protection_type = LFA_LINK_PROTECTION;
	} else
		return CMD_WARNING;

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

	return test_run(vty, topology, root, test_type, flags, protection_type,
			fail_sysid_str, fail_pseudonode_id);
}

static void vty_do_exit(int isexit)
{
	printf("\nend.\n");

	cmd_terminate();
	vty_terminate();
	yang_terminate();
	event_master_free(master);

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
	struct event thread;
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
	master = event_master_create(NULL);
	isis_master_init(master);

	/* Library inits. */
	cmd_init(1);
	cmd_hostname_set("test");
	vty_init(master, false);
	yang_init(true, false);
	if (debug)
		zlog_aux_init("NONE: ", LOG_DEBUG);
	else
		zlog_aux_init("NONE: ", ZLOG_DISABLED);

	/* IS-IS inits. */
	yang_module_load("frr-isisd", NULL);
	SET_FLAG(im->options, F_ISIS_UNIT_TEST);
	debug_spf_events |= DEBUG_SPF_EVENTS;
	debug_lfa |= DEBUG_LFA;
	debug_events |= DEBUG_EVENTS;
	debug_rte_events |= DEBUG_RTE_EVENTS;

	/* Install test command. */
	install_element(VIEW_NODE, &test_isis_cmd);

	/* Read input from .in file. */
	vty_stdio(vty_do_exit);

	/* Fetch next active thread. */
	while (event_fetch(master, &thread))
		event_call(&thread);

	/* Not reached. */
	exit(0);
}
