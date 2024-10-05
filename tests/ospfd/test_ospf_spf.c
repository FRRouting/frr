#include <zebra.h>
#include <sys/stat.h>

#include "getopt.h"
#include "frrevent.h"
#include <lib/version.h>
#include "vty.h"
#include "command.h"
#include "log.h"
#include "vrf.h"
#include "table.h"
#include "mpls.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_ti_lfa.h"
#include "ospfd/ospf_vty.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_sr.h"

#include "common.h"

DECLARE_RBTREE_UNIQ(p_spaces, struct p_space, p_spaces_item,
		    p_spaces_compare_func);
DECLARE_RBTREE_UNIQ(q_spaces, struct q_space, q_spaces_item,
		    q_spaces_compare_func);

static struct ospf *test_init(struct ospf_test_node *root)
{
	struct ospf *ospf;
	struct ospf_area *area;
	struct in_addr area_id;
	struct in_addr router_id;

	ospf = ospf_new_alloc(0, VRF_DEFAULT_NAME);

	area_id.s_addr = OSPF_AREA_BACKBONE;
	area = ospf_area_new(ospf, area_id);
	listnode_add_sort(ospf->areas, area);

	inet_aton(root->router_id, &router_id);
	ospf->router_id = router_id;
	ospf->router_id_static = router_id;
	ospf->ti_lfa_enabled = true;

	return ospf;
}

static void test_run_spf(struct vty *vty, struct ospf *ospf,
			 enum protection_type protection_type, bool verbose)
{
	struct route_table *new_table, *new_rtrs;
	struct route_table *all_rtrs = NULL;
	struct ospf_area *area;
	struct p_space *p_space;
	struct q_space *q_space;
	char label_buf[MPLS_LABEL_STRLEN];
	char res_buf[PROTECTED_RESOURCE_STRLEN];

	/* Just use the backbone for testing */
	area = ospf->backbone;

	new_table = route_table_init();
	new_rtrs = route_table_init();
	all_rtrs = route_table_init();

	/* dryrun true, root_node false */
	ospf_spf_calculate(area, area->router_lsa_self, new_table, all_rtrs,
			   new_rtrs, true, false);

	if (verbose) {
		vty_out(vty, "SPF Tree without TI-LFA backup paths:\n\n");
		ospf_spf_print(vty, area->spf, 0);

		vty_out(vty,
			"\nRouting Table without TI-LFA backup paths:\n\n");
		print_route_table(vty, new_table);
	}

	if (verbose)
		vty_out(vty, "\n... generating TI-LFA backup paths ...\n");

	/* TI-LFA testrun */
	ospf_ti_lfa_generate_p_spaces(area, protection_type);
	ospf_ti_lfa_insert_backup_paths(area, new_table);

	/* Print P/Q space information */
	if (verbose) {
		vty_out(vty, "\nP and Q space info:\n");
		frr_each (p_spaces, area->p_spaces, p_space) {
			ospf_print_protected_resource(
				p_space->protected_resource, res_buf);
			vty_out(vty, "\nP Space for root %pI4 and %s\n",
				&p_space->root->id, res_buf);
			ospf_spf_print(vty, p_space->root, 0);

			frr_each (q_spaces, p_space->q_spaces, q_space) {
				vty_out(vty,
					"\nQ Space for destination %pI4:\n",
					&q_space->root->id);
				ospf_spf_print(vty, q_space->root, 0);
				if (q_space->label_stack) {
					mpls_label2str(
						q_space->label_stack
							->num_labels,
						q_space->label_stack->label,
						label_buf, MPLS_LABEL_STRLEN,
						ZEBRA_LSP_NONE, true);
					vty_out(vty, "\nLabel stack: %s\n",
						label_buf);
				} else {
					vty_out(vty,
						"\nLabel stack not generated!\n");
				}
			}

			vty_out(vty, "\nPost-convergence SPF Tree:\n");
			ospf_spf_print(vty, p_space->pc_spf, 0);
		}
	}

	/* Cleanup */
	ospf_ti_lfa_free_p_spaces(area);
	ospf_spf_cleanup(area->spf, area->spf_vertex_list);

	/*
	 * Print the new routing table which is augmented with TI-LFA backup
	 * paths (label stacks).
	 */
	if (verbose)
		vty_out(vty,
			"\n\nFinal Routing Table including backup paths:\n\n");

	print_route_table(vty, new_table);
}

static int test_run(struct vty *vty, struct ospf_topology *topology,
		    struct ospf_test_node *root,
		    enum protection_type protection_type, bool verbose)
{
	struct ospf *ospf;

	ospf = test_init(root);

	/* Inject LSAs into the OSPF backbone according to the topology */
	if (topology_load(vty, topology, root, ospf)) {
		vty_out(vty, "%% Failed to load topology\n");
		return CMD_WARNING;
	}

	if (verbose) {
		vty_out(vty, "\n");
		show_ip_ospf_database_summary(vty, ospf, 0, NULL);
	}

	test_run_spf(vty, ospf, protection_type, verbose);

	return 0;
}

DEFUN(test_ospf, test_ospf_cmd,
      "test ospf topology WORD root HOSTNAME ti-lfa [node-protection] [verbose]",
      "Test mode\n"
      "Choose OSPF for SPF testing\n"
      "Network topology to choose\n"
      "Name of the network topology to choose\n"
      "Root node to choose\n"
      "Hostname of the root node to choose\n"
      "Use Topology-Independent LFA\n"
      "Use node protection (default is link protection)\n"
      "Verbose output\n")
{
	struct ospf_topology *topology;
	struct ospf_test_node *root;
	enum protection_type protection_type = OSPF_TI_LFA_LINK_PROTECTION;
	int idx = 0;
	bool verbose = false;

	/* Parse topology. */
	argv_find(argv, argc, "topology", &idx);
	topology = test_find_topology(argv[idx + 1]->arg);
	if (!topology) {
		vty_out(vty, "%% Topology not found\n");
		return CMD_WARNING;
	}

	argv_find(argv, argc, "root", &idx);
	root = test_find_node(topology, argv[idx + 1]->arg);
	if (!root) {
		vty_out(vty, "%% Root not found\n");
		return CMD_WARNING;
	}

	if (argv_find(argv, argc, "node-protection", &idx))
		protection_type = OSPF_TI_LFA_NODE_PROTECTION;

	if (argv_find(argv, argc, "verbose", &idx))
		verbose = true;

	return test_run(vty, topology, root, protection_type, verbose);
}

static void vty_do_exit(int isexit)
{
	printf("\nend.\n");

	cmd_terminate();
	vty_terminate();
	event_master_free(master);

	if (!isexit)
		exit(0);
}

struct option longopts[] = {{"help", no_argument, NULL, 'h'},
			    {"debug", no_argument, NULL, 'd'},
			    {0} };

/* Help information display. */
static void usage(char *progname, int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			progname);
	else {
		printf("Usage : %s [OPTION...]\n\
ospfd SPF test program.\n\n\
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

	/* Library inits. */
	cmd_init(1);
	cmd_hostname_set("test");
	vty_init(master, false);
	if (debug)
		zlog_aux_init("NONE: ", LOG_DEBUG);
	else
		zlog_aux_init("NONE: ", ZLOG_DISABLED);

	/* Install test command. */
	install_element(VIEW_NODE, &test_ospf_cmd);

	/* needed for SR DB init */
	ospf_vty_init();
	ospf_sr_init();

	term_debug_ospf_ti_lfa = 1;

	/* Read input from .in file. */
	vty_stdio(vty_do_exit);

	/* Fetch next active thread. */
	while (event_fetch(master, &thread))
		event_call(&thread);

	/* Not reached. */
	exit(0);
}
