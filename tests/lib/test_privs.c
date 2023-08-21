// SPDX-License-Identifier: GPL-2.0-or-later
/*
 */

#include <zebra.h>

#include <lib/version.h>
#include "getopt.h"
#include "privs.h"
#include "memory.h"
#include "lib_vty.h"

zebra_capabilities_t _caps_p[] = {
	ZCAP_NET_RAW, ZCAP_BIND, ZCAP_NET_ADMIN, ZCAP_DAC_OVERRIDE,
};

struct zebra_privs_t test_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
	.user = FRR_USER,
	.group = FRR_GROUP,
#endif
#if defined(VTY_GROUP)
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0};

struct option longopts[] = {{"help", no_argument, NULL, 'h'},
			    {"user", required_argument, NULL, 'u'},
			    {"group", required_argument, NULL, 'g'},
			    {0}};

/* Help information display. */
static void usage(char *progname, int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			progname);
	else {
		printf("Usage : %s [OPTION...]\n\
Daemon which does 'slow' things.\n\n\
-u, --user         User to run as\n\
-g, --group        Group to run as\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n",
		       progname, FRR_BUG_ADDRESS);
	}
	exit(status);
}

struct event_loop *master;
/* main routine. */
int main(int argc, char **argv)
{
	char *p;
	char *progname;
	struct zprivs_ids_t ids;

	/* Set umask before anything for security */
	umask(0027);

	/* get program name */
	progname = ((p = strrchr(argv[0], '/')) ? ++p : argv[0]);

	while (1) {
		int opt;

		opt = getopt_long(argc, argv, "hu:g:", longopts, 0);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		case 'u':
			test_privs.user = optarg;
			break;
		case 'g':
			test_privs.group = optarg;
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
	lib_cmd_init();
	zprivs_preinit(&test_privs);
	zprivs_init(&test_privs);

#define PRIV_STATE()                                                           \
	((test_privs.current_state() == ZPRIVS_RAISED) ? "Raised" : "Lowered")

	printf("%s\n", PRIV_STATE());
	frr_with_privs(&test_privs) {
		printf("%s\n", PRIV_STATE());
	}

	printf("%s\n", PRIV_STATE());
	zprivs_get_ids(&ids);

	/* terminate privileges */
	zprivs_terminate(&test_privs);

	/* but these should continue to work... */
	printf("%s\n", PRIV_STATE());
	frr_with_privs(&test_privs) {
		printf("%s\n", PRIV_STATE());
	}

	printf("%s\n", PRIV_STATE());
	zprivs_get_ids(&ids);

	printf("terminating\n");
	return 0;
}
