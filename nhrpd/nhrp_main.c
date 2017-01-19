/* NHRP daemon main functions
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include <unistd.h>

#include "zebra.h"
#include "privs.h"
#include "getopt.h"
#include "thread.h"
#include "sigevent.h"
#include "version.h"
#include "log.h"
#include "memory.h"
#include "command.h"

#include "nhrpd.h"
#include "netlink.h"

unsigned int debug_flags = 0;

struct thread_master *master;
struct timeval current_time;
static const char *pid_file = PATH_NHRPD_PID;
static char config_default[] = SYSCONFDIR NHRP_DEFAULT_CONFIG;
static char *config_file = NULL;
static char *vty_addr = NULL;
static int vty_port = NHRP_VTY_PORT;
static int do_daemonise = 0;

/* nhrpd options. */
struct option longopts[] = {
	{ "daemon",      no_argument,       NULL, 'd'},
	{ "config_file", required_argument, NULL, 'f'},
	{ "pid_file",    required_argument, NULL, 'i'},
	{ "socket",      required_argument, NULL, 'z'},
	{ "help",        no_argument,       NULL, 'h'},
	{ "vty_addr",    required_argument, NULL, 'A'},
	{ "vty_port",    required_argument, NULL, 'P'},
	{ "user",        required_argument, NULL, 'u'},
	{ "group",       required_argument, NULL, 'g'},
	{ "version",     no_argument,       NULL, 'v'},
	{ 0 }
};

/* nhrpd privileges */
static zebra_capabilities_t _caps_p [] = {
	ZCAP_NET_RAW,
	ZCAP_NET_ADMIN,
	ZCAP_DAC_OVERRIDE,	/* for now needed to write to /proc/sys/net/ipv4/<if>/send_redirect */
};

static struct zebra_privs_t nhrpd_privs = {
#ifdef QUAGGA_USER
	.user = QUAGGA_USER,
#endif
#ifdef QUAGGA_GROUP
	.group = QUAGGA_GROUP,
#endif
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = ZEBRA_NUM_OF(_caps_p),
};

static void usage(const char *progname, int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n", progname);
	else
		printf(
"Usage : %s [OPTION...]\n\
Daemon which manages NHRP protocol.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-i, --pid_file     Set process identifier file name\n\
-z, --socket       Set path of zebra socket\n\
-A, --vty_addr     Set vty's bind address\n\
-P, --vty_port     Set vty's port number\n\
-u, --user         User to run as\n\
-g, --group        Group to run as\n\
-v, --version      Print program version\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n", progname, ZEBRA_BUG_ADDRESS);

	exit(status);
}

static void parse_arguments(const char *progname, int argc, char **argv)
{
	int opt;

	while (1) {
		opt = getopt_long(argc, argv, "df:i:z:hA:P:u:g:v", longopts, 0);
		if(opt < 0) break;

		switch (opt) {
		case 0:
			break;
		case 'd':
			do_daemonise = -1;
			break;
		case 'f':
			config_file = optarg;
			break;
		case 'i':
			pid_file = optarg;
			break;
		case 'z':
			zclient_serv_path_set(optarg);
			break;
		case 'A':
			vty_addr = optarg;
			break;
		case 'P':
			vty_port = atoi (optarg);
			if (vty_port <= 0 || vty_port > 0xffff)
				vty_port = NHRP_VTY_PORT;
			break;
		case 'u':
			nhrpd_privs.user = optarg;
			break;
		case 'g':
			nhrpd_privs.group = optarg;
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
}

static void nhrp_sigusr1(void)
{
	zlog_rotate(NULL);
}

static void nhrp_request_stop(void)
{
	debugf(NHRP_DEBUG_COMMON, "Exiting...");

	nhrp_shortcut_terminate();
	nhrp_nhs_terminate();
	nhrp_zebra_terminate();
	vici_terminate();
	evmgr_terminate();
	nhrp_vc_terminate();
	vrf_terminate();
	/* memory_terminate(); */
	/* vty_terminate(); */
	cmd_terminate();
	/* signal_terminate(); */
	zprivs_terminate(&nhrpd_privs);

	debugf(NHRP_DEBUG_COMMON, "Remove pid file.");
	if (pid_file) unlink(pid_file);
	debugf(NHRP_DEBUG_COMMON, "Done.");

	closezlog(zlog_default);

	exit(0);
}

static struct quagga_signal_t sighandlers[] = {
	{ .signal = SIGUSR1, .handler = &nhrp_sigusr1, },
	{ .signal = SIGINT,  .handler = &nhrp_request_stop, },
	{ .signal = SIGTERM, .handler = &nhrp_request_stop, },
};

int main(int argc, char **argv)
{
	struct thread thread;
	const char *progname;

	/* Set umask before anything for security */
	umask(0027);
	progname = basename(argv[0]);
	zlog_default = openzlog(progname, ZLOG_NHRP, LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);
	zlog_set_level(NULL, ZLOG_DEST_STDOUT, LOG_WARNING);

	parse_arguments(progname, argc, argv);

	/* Library inits. */
	master = thread_master_create();
	zprivs_init(&nhrpd_privs);
	signal_init(master, array_size(sighandlers), sighandlers);
	cmd_init(1);
	vty_init(master);
	memory_init();
	nhrp_interface_init();
	vrf_init();
	resolver_init();

	/* Run with elevated capabilities, as for all netlink activity
	 * we need privileges anyway. */
	nhrpd_privs.change(ZPRIVS_RAISE);

	netlink_init();
	evmgr_init();
	nhrp_vc_init();
	nhrp_packet_init();
	vici_init();
	nhrp_zebra_init();
	nhrp_shortcut_init();

	nhrp_config_init();

	/* Get zebra configuration file. */
	zlog_set_level(NULL, ZLOG_DEST_STDOUT, do_daemonise ? ZLOG_DISABLED : LOG_DEBUG);
	vty_read_config(config_file, config_default);

	if (do_daemonise && daemon(0, 0) < 0) {
		zlog_err("daemonise: %s", safe_strerror(errno));
		exit (1);
	}

	/* write pid file */
	if (pid_output(pid_file) < 0) {
		zlog_err("error while writing pidfile");
		exit (1);
	}

	/* Create VTY socket */
	vty_serv_sock(vty_addr, vty_port, NHRP_VTYSH_PATH);
	zlog_notice("nhrpd starting: vty@%d", vty_port);

	/* Main loop */
	while (thread_fetch(master, &thread))
		thread_call(&thread);

	return 0;
}
