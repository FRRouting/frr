// SPDX-License-Identifier: GPL-2.0-or-later
/*
 */

#include <zebra.h>
#include <sys/stat.h>

#include <lib/version.h>
#include "getopt.h"
#include "frrevent.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "lib_vty.h"

extern void test_init(void);

struct event_loop *master;

struct option longopts[] = {{"daemon", no_argument, NULL, 'd'},
			    {"config_file", required_argument, NULL, 'f'},
			    {"help", no_argument, NULL, 'h'},
			    {"vty_addr", required_argument, NULL, 'A'},
			    {"vty_port", required_argument, NULL, 'P'},
			    {"version", no_argument, NULL, 'v'},
			    {0}};

DEFUN (daemon_exit,
       daemon_exit_cmd,
       "daemon-exit",
       "Make the daemon exit\n")
{
	exit(0);
}

static int timer_count;
static void test_timer(struct event *thread)
{
	int *count = EVENT_ARG(thread);

	printf("run %d of timer\n", (*count)++);
	event_add_timer(master, test_timer, count, 5, NULL);
}

static void test_timer_init(void)
{
	event_add_timer(master, test_timer, &timer_count, 10, NULL);
}

static void test_vty_init(void)
{
	install_element(VIEW_NODE, &daemon_exit_cmd);
}

/* Help information display. */
static void usage(char *progname, int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			progname);
	else {
		printf("Usage : %s [OPTION...]\n\
Daemon which does 'slow' things.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-A, --vty_addr     Set vty's bind address\n\
-P, --vty_port     Set vty's port number\n\
-v, --version      Print program version\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n",
		       progname, FRR_BUG_ADDRESS);
	}
	exit(status);
}


/* main routine. */
int main(int argc, char **argv)
{
	char *p;
	char *vty_addr = NULL;
	int vty_port = 4000;
	int daemon_mode = 0;
	char *progname;
	struct event thread;
	char *config_file = NULL;

	/* Set umask before anything for security */
	umask(0027);

	/* get program name */
	progname = ((p = strrchr(argv[0], '/')) ? ++p : argv[0]);

	/* master init. */
	master = event_master_create(NULL);

	while (1) {
		int opt;

		opt = getopt_long(argc, argv, "dhf:A:P:v", longopts, 0);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		case 'f':
			config_file = optarg;
			break;
		case 'd':
			daemon_mode = 1;
			break;
		case 'A':
			vty_addr = optarg;
			break;
		case 'P':
			/* Deal with atoi() returning 0 on failure */
			if (strcmp(optarg, "0") == 0) {
				vty_port = 0;
				break;
			}
			vty_port = atoi(optarg);
			vty_port = (vty_port ? vty_port : 4000);
			break;
		case 'v':
			print_version(progname);
			exit(0);
			break;
		case 'h':
			usage(progname, 0);
			break;
		default:
			usage(progname, 1);
			break;
		}
	}

	/* Library inits. */
	cmd_init(1);
	vty_init(master, false);
	lib_cmd_init();
	nb_init(master, NULL, 0, false);

	/* OSPF vty inits. */
	test_vty_init();

	/* Change to the daemon program. */
	if (daemon_mode && daemon(0, 0) < 0) {
		fprintf(stderr, "daemon failed: %s", strerror(errno));
		exit(1);
	}

	/* Create VTY socket */
	vty_serv_start(vty_addr, vty_port, "/tmp/.heavy.sock");

	/* Configuration file read*/
	if (!config_file)
		usage(progname, 1);
	vty_read_config(NULL, config_file, NULL);

	test_timer_init();

	test_init();

	/* Fetch next active thread. */
	while (event_fetch(master, &thread))
		event_call(&thread);

	/* Not reached. */
	exit(0);
}
