/*
 * libfrr overall management functions
 *
 * Copyright (C) 2016  David Lamparter for NetDEF, Inc.
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

#include "libfrr.h"
#include "getopt.h"
#include "vty.h"
#include "command.h"
#include "version.h"
#include "memory_vty.h"
#include "zclient.h"
#include "log_int.h"
#include "module.h"

DEFINE_HOOK(frr_late_init, (struct thread_master *tm), (tm))

#define FRR_INTEGRATED_CONFIG "frr.conf"

char frr_protoname[256] = "NONE";
char frr_protonameinst[256] = "NONE";

/* Global configuration values. Initialized in preinit. */
struct frr frr;

/* Daemon-specific default configuration values */
static char pidfile_default[MAXPATHLEN];
static char vtypath_default[MAXPATHLEN];

static char comb_optstr[256];
static struct option comb_lo[64];
static struct option *comb_next_lo = &comb_lo[0];
static char comb_helpstr[4096];

struct optspec {
	const char *optstr;
	const char *helpstr;
	const struct option *longopts;
};

static void opt_extend(const struct optspec *os)
{
	const struct option *lo;

	strcat(comb_optstr, os->optstr);
	strcat(comb_helpstr, os->helpstr);
	for (lo = os->longopts; lo->name; lo++)
		memcpy(comb_next_lo++, lo, sizeof(*lo));
}


#define OPTION_VTYSOCK   1000
#define OPTION_MODULEDIR 1002

static const struct option lo_always[] = {
	{ "help",        no_argument,       NULL, 'h' },
	{ "version",     no_argument,       NULL, 'v' },
	{ "daemon",      no_argument,       NULL, 'd' },
	{ "module",      no_argument,       NULL, 'M' },
	{ "vty_socket",  required_argument, NULL, OPTION_VTYSOCK },
	{ "moduledir",   required_argument, NULL, OPTION_MODULEDIR },
	{ NULL }
};
static const struct optspec os_always = {
	"hvdM:",
	"  -h, --help         Display this help and exit\n"
	"  -v, --version      Print program version\n"
	"  -d, --daemon       Runs in daemon mode\n"
	"  -M, --module       Load specified module\n"
	"      --vty_socket   Override vty socket path\n"
	"      --moduledir    Override modules directory\n",
	lo_always
};


static const struct option lo_cfg_pid_dry[] = {
	{ "pid_file",    required_argument, NULL, 'i' },
	{ "config_file", required_argument, NULL, 'f' },
	{ "dryrun",      no_argument,       NULL, 'C' },
	{ NULL }
};
static const struct optspec os_cfg_pid_dry = {
	"f:i:C",
	"  -f, --config_file  Set configuration file name\n"
	"  -i, --pid_file     Set process identifier file name\n"
	"  -C, --dryrun       Check configuration for validity and exit\n",
	lo_cfg_pid_dry
};


static const struct option lo_zclient[] = {
	{ "socket", required_argument, NULL, 'z' },
	{ NULL }
};
static const struct optspec os_zclient = {
	"z:",
	"  -z, --socket       Set path of zebra socket\n",
	lo_zclient
};


static const struct option lo_vty[] = {
	{ "vty_addr",   required_argument, NULL, 'A'},
	{ "vty_port",   required_argument, NULL, 'P'},
	{ NULL }
};
static const struct optspec os_vty = {
	"A:P:",
	"  -A, --vty_addr     Set vty's bind address\n"
	"  -P, --vty_port     Set vty's port number\n",
	lo_vty
};


static const struct option lo_user[] = {
	{ "user",  required_argument, NULL, 'u'},
	{ "group", required_argument, NULL, 'g'},
	{ NULL }
};
static const struct optspec os_user = {
	"u:g:",
	"  -u, --user         User to run as\n"
	"  -g, --group        Group to run as\n",
	lo_user
};

/**
 * Updates the base configuration directory.
 *
 * @param base configuration directory without trailing slash
 */
void frr_update_confdir(const char *new)
{
  snprintf(frr.config.dir, sizeof(frr.config.dir), "%s", new);
}

/**
 * Prints the path to the integrated config into the provided buffer.
 *
 * @param buf the buffer to print into
 * @param len the size of the buffer
 */
void frr_integrated_conf(char *buf, size_t len)
{
  snprintf(buf, len, "%s/%s", frr.config.dir, frr.config.integrated);
}

/**
 * Prints the path to the default daemon config into the provided buffer.
 *
 * @param buf the buffer to print into
 * @param len the size of the buffer
 */
void frr_daemon_conf(char *buf, size_t len)
{
  snprintf(buf, len, "%s/%s.conf", frr.config.dir, frr.daemon->name);
}

void frr_preinit(struct frr_daemon_info *daemon, const char *name)
{
	frr.daemon = daemon;

	/* basename(), opencoded. */
	char *p = strrchr(name, '/');
	frr.daemon->progname = p ? p + 1 : name;

	umask(0027);

	opt_extend(&os_always);
	if (!(frr.daemon->flags & FRR_NO_CFG_PID_DRY))
		opt_extend(&os_cfg_pid_dry);
	if (!(frr.daemon->flags & FRR_NO_PRIVSEP))
		opt_extend(&os_user);
	if (!(frr.daemon->flags & FRR_NO_ZCLIENT))
		opt_extend(&os_zclient);
	if (!(frr.daemon->flags & FRR_NO_TCPVTY))
		opt_extend(&os_vty);

	/* Set global paths */
	frr_update_confdir(SYSCONFDIR);
	snprintf(frr.vtydir, sizeof(frr.vtydir), "%s", DAEMON_VTY_DIR);
	snprintf(frr.moduledir, sizeof(frr.moduledir), "%s", MODULE_PATH);
	snprintf(frr.config.integrated, sizeof(frr.config.integrated),
		 "%s", FRR_INTEGRATED_CONFIG);

        /* Set daemon-specific default configuration paths */
	snprintf(pidfile_default, sizeof(pidfile_default), "%s/%s.pid",
		 frr.vtydir, frr.daemon->name);

	/* Set protocol names */
	strlcpy(frr_protoname, frr.daemon->logname, sizeof(frr_protoname));
	strlcpy(frr_protonameinst, frr.daemon->logname, sizeof(frr_protonameinst));
}

void frr_opt_add(const char *optstr, const struct option *longopts,
		const char *helpstr)
{
	const struct optspec main_opts = { optstr, helpstr, longopts };
	opt_extend(&main_opts);
}

void frr_help_exit(int status)
{
	FILE *target = status ? stderr : stdout;

	if (status != 0)
		fprintf(stderr, "Invalid options.\n\n");

	if (frr.daemon->printhelp)
		frr.daemon->printhelp(target);
	else
		fprintf(target, "Usage: %s [OPTION...]\n\n%s%s%s\n\n%s",
				frr.daemon->progname,
				frr.daemon->proghelp,
				frr.daemon->copyright ? "\n\n" : "",
				frr.daemon->copyright ? frr.daemon->copyright : "",
				comb_helpstr);
	fprintf(target, "\nReport bugs to %s\n", FRR_BUG_ADDRESS);
	exit(status);
}

struct option_chain {
	struct option_chain *next;
	const char *arg;
};

static struct option_chain *modules = NULL, **modnext = &modules;
static int errors = 0;

static int frr_opt(int opt)
{
	static int vty_port_set = 0;
	static int vty_addr_set = 0;
	struct option_chain *oc;
	char *err;

	switch (opt) {
	case 'h':
		frr_help_exit(0);
		break;
	case 'v':
		print_version(frr.daemon->progname);
		exit(0);
		break;
	case 'd':
		frr.daemon->daemon_mode = 1;
		break;
	case 'M':
		oc = XMALLOC(MTYPE_TMP, sizeof(*oc));
		oc->arg = optarg;
		oc->next = NULL;
		*modnext = oc;
		modnext = &oc->next;
		break;
	case 'i':
		if (frr.daemon->flags & FRR_NO_CFG_PID_DRY)
			return 1;
		frr.daemon->pid_file = optarg;
		break;
	case 'f':
		if (frr.daemon->flags & FRR_NO_CFG_PID_DRY)
			return 1;
		frr.daemon->config_file = optarg;
		break;
	case 'C':
		if (frr.daemon->flags & FRR_NO_CFG_PID_DRY)
			return 1;
		frr.daemon->dryrun = 1;
		break;
	case 'z':
		if (frr.daemon->flags & FRR_NO_ZCLIENT)
			return 1;
		zclient_serv_path_set(optarg);
		break;
	case 'A':
		if (frr.daemon->flags & FRR_NO_TCPVTY)
			return 1;
		if (vty_addr_set) {
			fprintf(stderr, "-A option specified more than once!\n");
			errors++;
			break;
		}
		vty_addr_set = 1;
		frr.daemon->vty_addr = optarg;
		break;
	case 'P':
		if (frr.daemon->flags & FRR_NO_TCPVTY)
			return 1;
		if (vty_port_set) {
			fprintf(stderr, "-P option specified more than once!\n");
			errors++;
			break;
		}
		vty_port_set = 1;
		frr.daemon->vty_port = strtoul(optarg, &err, 0);
		if (*err || !*optarg) {
			fprintf(stderr, "invalid port number \"%s\" for -P option\n",
					optarg);
			errors++;
			break;
		}
		break;
	case OPTION_VTYSOCK:
		if (frr.daemon->vty_sock_path) {
			fprintf(stderr, "--vty_socket option specified more than once!\n");
			errors++;
			break;
		}
		frr.daemon->vty_sock_path = optarg;
		break;
	case OPTION_MODULEDIR:
		if (frr.daemon->module_path) {
			fprintf(stderr, "----moduledir option specified more than once!\n");
			errors++;
			break;
		}
		frr.daemon->module_path = optarg;
		break;
	case 'u':
		if (frr.daemon->flags & FRR_NO_PRIVSEP)
			return 1;
		frr.daemon->privs->user = optarg;
		break;
	case 'g':
		if (frr.daemon->flags & FRR_NO_PRIVSEP)
			return 1;
		frr.daemon->privs->group = optarg;
		break;
	default:
		return 1;
	}
	return 0;
}

int frr_getopt(int argc, char * const argv[], int *longindex)
{
	int opt;
	int lidx;

	comb_next_lo->name = NULL;

	do {
		opt = getopt_long(argc, argv, comb_optstr, comb_lo, &lidx);
		if (frr_opt(opt))
			break;
	} while (opt != -1);

	if (opt == -1 && errors)
		frr_help_exit(1);
	if (longindex)
		*longindex = lidx;
	return opt;
}


static struct thread_master *master;
struct thread_master *frr_init(void)
{
	struct option_chain *oc;
	struct frrmod_runtime *module;
	char moderr[256];
	const char *dir;
	dir = frr.daemon->module_path ? frr.daemon->module_path : frr.moduledir;

	srandom(time(NULL));

	if (frr.daemon->instance)
		snprintf(frr_protonameinst, sizeof(frr_protonameinst),
				"%s[%u]", frr.daemon->logname, frr.daemon->instance);

	openzlog (frr.daemon->progname, frr.daemon->logname, frr.daemon->instance,
			LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON);
#if defined(HAVE_CUMULUS)
	zlog_set_level (ZLOG_DEST_SYSLOG, zlog_default->default_lvl);
#endif

	frrmod_init(frr.daemon->module);
	while (modules) {
		modules = (oc = modules)->next;
		module = frrmod_load(oc->arg, dir, moderr, sizeof(moderr));
		if (!module) {
			fprintf(stderr, "%s\n", moderr);
			exit(1);
		}
		XFREE(MTYPE_TMP, oc);
	}

	zprivs_init(frr.daemon->privs);

	master = thread_master_create(NULL);
	signal_init(master, frr.daemon->n_signals, frr.daemon->signals);

	if (frr.daemon->flags & FRR_LIMITED_CLI)
		cmd_init(-1);
	else
		cmd_init(1);
	vty_init(master);
	memory_init();

	return master;
}

void frr_config_fork(void)
{
	hook_call(frr_late_init, master);

	char defaultconf[MAXPATHLEN];
	frr_daemon_conf(defaultconf, sizeof(defaultconf));

	if (frr.daemon->instance) {
		snprintf(defaultconf, sizeof(defaultconf), "%s/%s-%d.conf",
			 frr.config.dir, frr.daemon->name, frr.daemon->instance);
		snprintf(pidfile_default, sizeof(pidfile_default), "%s/%s-%d.pid",
			 frr.vtydir, frr.daemon->name, frr.daemon->instance);
	}

	vty_read_config(frr.daemon->config_file, defaultconf);

	/* Don't start execution if we are in dry-run mode */
	if (frr.daemon->dryrun)
		exit(0);

	/* Daemonize. */
	if (frr.daemon->daemon_mode && daemon (0, 0) < 0) {
		zlog_err("Zebra daemon failed: %s", strerror(errno));
		exit(1);
	}

	if (!frr.daemon->pid_file)
		frr.daemon->pid_file = pidfile_default;
	pid_output (frr.daemon->pid_file);
}

void frr_vty_serv(void)
{
	/* allow explicit override of vty_path in the future 
	 * (not currently set anywhere) */
	if (!frr.daemon->vty_path) {
		const char *dir;
		dir = frr.daemon->vty_sock_path ? frr.daemon->vty_sock_path : frr.vtydir;

		if (frr.daemon->instance)
			snprintf(vtypath_default, sizeof(vtypath_default),
					"%s/%s-%d.vty",
					dir, frr.daemon->name, frr.daemon->instance);
		else
			snprintf(vtypath_default, sizeof(vtypath_default),
					"%s/%s.vty", dir, frr.daemon->name);

		frr.daemon->vty_path = vtypath_default;
	}

	vty_serv_sock(frr.daemon->vty_addr, frr.daemon->vty_port, frr.daemon->vty_path);
}

void frr_run(struct thread_master *master)
{
	char instanceinfo[64] = "";

	frr_vty_serv();

	if (frr.daemon->instance)
		snprintf(instanceinfo, sizeof(instanceinfo), "instance %u ",
				frr.daemon->instance);

	zlog_notice("%s %s starting: %svty@%d%s",
			frr.daemon->name,
			FRR_VERSION,
			instanceinfo,
			frr.daemon->vty_port,
			frr.daemon->startinfo);

	struct thread thread;
	while (thread_fetch(master, &thread))
		thread_call(&thread);
}
