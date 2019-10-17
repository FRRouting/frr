/*
 * BFD daemon code
 * Copyright (C) 2018 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include "filter.h"

#include "bfd.h"
#include "bfdd_nb.h"
#include "lib/version.h"


/*
 * FRR related code.
 */
DEFINE_MGROUP(BFDD, "Bidirectional Forwarding Detection Daemon")
DEFINE_MTYPE(BFDD, BFDD_CONTROL, "long-lived control socket memory")
DEFINE_MTYPE(BFDD, BFDD_NOTIFICATION, "short-lived control notification data")

/* Master of threads. */
struct thread_master *master;

/* BFDd privileges */
static zebra_capabilities_t _caps_p[] = {ZCAP_BIND, ZCAP_SYS_ADMIN, ZCAP_NET_RAW};

/* BFD daemon information. */
static struct frr_daemon_info bfdd_di;

void socket_close(int *s)
{
	if (*s <= 0)
		return;

	if (close(*s) != 0)
		log_error("%s: close(%d): (%d) %s", __func__, *s, errno,
			  strerror(errno));

	*s = -1;
}

static void sigusr1_handler(void)
{
	zlog_rotate();
}

static void sigterm_handler(void)
{
	/* Signalize shutdown. */
	frr_early_fini();

	/* Stop receiving message from zebra. */
	bfdd_zclient_stop();

	/* Shutdown controller to avoid receiving anymore commands. */
	control_shutdown();

	/* Shutdown and free all protocol related memory. */
	bfd_shutdown();

	bfd_vrf_terminate();

	/* Terminate and free() FRR related memory. */
	frr_fini();

	exit(0);
}

static void sighup_handler(void)
{
	zlog_info("SIGHUP received");

	/* Reload config file. */
	vty_read_config(NULL, bfdd_di.config_file, config_default);
}

static struct quagga_signal_t bfd_signals[] = {
	{
		.signal = SIGUSR1,
		.handler = &sigusr1_handler,
	},
	{
		.signal = SIGTERM,
		.handler = &sigterm_handler,
	},
	{
		.signal = SIGINT,
		.handler = &sigterm_handler,
	},
	{
		.signal = SIGHUP,
		.handler = &sighup_handler,
	},
};

static const struct frr_yang_module_info *bfdd_yang_modules[] = {
	&frr_interface_info,
	&frr_bfdd_info,
};

FRR_DAEMON_INFO(bfdd, BFD, .vty_port = 2617,
		.proghelp = "Implementation of the BFD protocol.",
		.signals = bfd_signals, .n_signals = array_size(bfd_signals),
		.privs = &bglobal.bfdd_privs,
		.yang_modules = bfdd_yang_modules,
		.n_yang_modules = array_size(bfdd_yang_modules))

#define OPTION_CTLSOCK 1001
static struct option longopts[] = {
	{"bfdctl", required_argument, NULL, OPTION_CTLSOCK},
	{0}
};


/*
 * BFD daemon related code.
 */
struct bfd_global bglobal;

struct bfd_diag_str_list diag_list[] = {
	{.str = "control-expired", .type = BD_CONTROL_EXPIRED},
	{.str = "echo-failed", .type = BD_ECHO_FAILED},
	{.str = "neighbor-down", .type = BD_NEIGHBOR_DOWN},
	{.str = "forwarding-reset", .type = BD_FORWARDING_RESET},
	{.str = "path-down", .type = BD_PATH_DOWN},
	{.str = "concatenated-path-down", .type = BD_CONCATPATH_DOWN},
	{.str = "administratively-down", .type = BD_ADMIN_DOWN},
	{.str = "reverse-concat-path-down", .type = BD_REVCONCATPATH_DOWN},
	{.str = NULL},
};

struct bfd_state_str_list state_list[] = {
	{.str = "admin-down", .type = PTM_BFD_ADM_DOWN},
	{.str = "down", .type = PTM_BFD_DOWN},
	{.str = "init", .type = PTM_BFD_INIT},
	{.str = "up", .type = PTM_BFD_UP},
	{.str = NULL},
};


static void bg_init(void)
{
	struct zebra_privs_t bfdd_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
		.user = FRR_USER,
		.group = FRR_GROUP,
#endif
#if defined(VTY_GROUP)
		.vty_group = VTY_GROUP,
#endif
		.caps_p = _caps_p,
		.cap_num_p = array_size(_caps_p),
		.cap_num_i = 0,
	};

	TAILQ_INIT(&bglobal.bg_bcslist);
	TAILQ_INIT(&bglobal.bg_obslist);

	memcpy(&bglobal.bfdd_privs, &bfdd_privs,
	       sizeof(bfdd_privs));
}

int main(int argc, char *argv[])
{
	char ctl_path[512];
	bool ctlsockused = false;
	int opt;

	/* Initialize system sockets. */
	bg_init();

	frr_preinit(&bfdd_di, argc, argv);
	frr_opt_add("", longopts,
		    "      --bfdctl       Specify bfdd control socket\n");

	snprintf(ctl_path, sizeof(ctl_path), BFDD_CONTROL_SOCKET,
		 "", "");
	while (true) {
		opt = frr_getopt(argc, argv, NULL);
		if (opt == EOF)
			break;

		switch (opt) {
		case OPTION_CTLSOCK:
			strlcpy(ctl_path, optarg, sizeof(ctl_path));
			ctlsockused = true;
			break;

		default:
			frr_help_exit(1);
			break;
		}
	}

	if (bfdd_di.pathspace && !ctlsockused)
		snprintf(ctl_path, sizeof(ctl_path), BFDD_CONTROL_SOCKET,
			 "/", bfdd_di.pathspace);

#if 0 /* TODO add support for JSON configuration files. */
	parse_config(conf);
#endif

	/* Initialize logging API. */
	log_init(1, BLOG_DEBUG, &bfdd_di);

	/* Initialize control socket. */
	control_init(ctl_path);

	/* Initialize FRR infrastructure. */
	master = frr_init();

	/* Initialize BFD data structures. */
	bfd_initialize();

	bfd_vrf_init();

	access_list_init();

	/* Initialize zebra connection. */
	bfdd_zclient_init(&bglobal.bfdd_privs);

	thread_add_read(master, control_accept, NULL, bglobal.bg_csock,
			&bglobal.bg_csockev);

	/* Install commands. */
	bfdd_vty_init();

	/* read configuration file and daemonize  */
	frr_config_fork();

	frr_run(master);
	/* NOTREACHED */

	return 0;
}
