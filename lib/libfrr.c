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
#include <sys/un.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "libfrr.h"
#include "getopt.h"
#include "privs.h"
#include "vty.h"
#include "command.h"
#include "version.h"
#include "lib_vty.h"
#include "log_vty.h"
#include "zclient.h"
#include "module.h"
#include "network.h"
#include "lib_errors.h"
#include "db.h"
#include "northbound_cli.h"
#include "northbound_db.h"
#include "debug.h"
#include "frrcu.h"
#include "frr_pthread.h"
#include "defaults.h"

DEFINE_HOOK(frr_late_init, (struct thread_master * tm), (tm))
DEFINE_HOOK(frr_very_late_init, (struct thread_master * tm), (tm))
DEFINE_KOOH(frr_early_fini, (), ())
DEFINE_KOOH(frr_fini, (), ())

const char frr_sysconfdir[] = SYSCONFDIR;
char frr_vtydir[256];
#ifdef HAVE_SQLITE3
const char frr_dbdir[] = DAEMON_DB_DIR;
#endif
const char frr_moduledir[] = MODULE_PATH;

char frr_protoname[256] = "NONE";
char frr_protonameinst[256] = "NONE";

char config_default[512];
char frr_zclientpath[256];
static char pidfile_default[1024];
#ifdef HAVE_SQLITE3
static char dbfile_default[512];
#endif
static char vtypath_default[512];

bool debug_memstats_at_exit = false;
static bool nodetach_term, nodetach_daemon;

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

	strlcat(comb_optstr, os->optstr, sizeof(comb_optstr));
	strlcat(comb_helpstr, os->helpstr, sizeof(comb_helpstr));
	for (lo = os->longopts; lo->name; lo++)
		memcpy(comb_next_lo++, lo, sizeof(*lo));
}


#define OPTION_VTYSOCK   1000
#define OPTION_MODULEDIR 1002
#define OPTION_LOG       1003
#define OPTION_LOGLEVEL  1004
#define OPTION_TCLI      1005
#define OPTION_DB_FILE   1006
#define OPTION_LOGGING   1007
#define OPTION_LIMIT_FDS 1008

static const struct option lo_always[] = {
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{"daemon", no_argument, NULL, 'd'},
	{"module", no_argument, NULL, 'M'},
	{"profile", required_argument, NULL, 'F'},
	{"pathspace", required_argument, NULL, 'N'},
	{"vty_socket", required_argument, NULL, OPTION_VTYSOCK},
	{"moduledir", required_argument, NULL, OPTION_MODULEDIR},
	{"log", required_argument, NULL, OPTION_LOG},
	{"log-level", required_argument, NULL, OPTION_LOGLEVEL},
	{"tcli", no_argument, NULL, OPTION_TCLI},
	{"command-log-always", no_argument, NULL, OPTION_LOGGING},
	{"limit-fds", required_argument, NULL, OPTION_LIMIT_FDS},
	{NULL}};
static const struct optspec os_always = {
	"hvdM:F:N:",
	"  -h, --help         Display this help and exit\n"
	"  -v, --version      Print program version\n"
	"  -d, --daemon       Runs in daemon mode\n"
	"  -M, --module       Load specified module\n"
	"  -F, --profile      Use specified configuration profile\n"
	"  -N, --pathspace    Insert prefix into config & socket paths\n"
	"      --vty_socket   Override vty socket path\n"
	"      --moduledir    Override modules directory\n"
	"      --log          Set Logging to stdout, syslog, or file:<name>\n"
	"      --log-level    Set Logging Level to use, debug, info, warn, etc\n"
	"      --tcli         Use transaction-based CLI\n"
	"      --limit-fds    Limit number of fds supported\n",
	lo_always};


static const struct option lo_cfg_pid_dry[] = {
	{"pid_file", required_argument, NULL, 'i'},
	{"config_file", required_argument, NULL, 'f'},
#ifdef HAVE_SQLITE3
	{"db_file", required_argument, NULL, OPTION_DB_FILE},
#endif
	{"dryrun", no_argument, NULL, 'C'},
	{"terminal", no_argument, NULL, 't'},
	{NULL}};
static const struct optspec os_cfg_pid_dry = {
	"f:i:Ct",
	"  -f, --config_file  Set configuration file name\n"
	"  -i, --pid_file     Set process identifier file name\n"
#ifdef HAVE_SQLITE3
	"      --db_file      Set database file name\n"
#endif
	"  -C, --dryrun       Check configuration for validity and exit\n"
	"  -t, --terminal     Open terminal session on stdio\n"
	"  -d -t              Daemonize after terminal session ends\n",
	lo_cfg_pid_dry};


static const struct option lo_zclient[] = {
	{"socket", required_argument, NULL, 'z'},
	{NULL}};
static const struct optspec os_zclient = {
	"z:", "  -z, --socket       Set path of zebra socket\n", lo_zclient};


static const struct option lo_vty[] = {
	{"vty_addr", required_argument, NULL, 'A'},
	{"vty_port", required_argument, NULL, 'P'},
	{NULL}};
static const struct optspec os_vty = {
	"A:P:",
	"  -A, --vty_addr     Set vty's bind address\n"
	"  -P, --vty_port     Set vty's port number\n",
	lo_vty};


static const struct option lo_user[] = {{"user", required_argument, NULL, 'u'},
					{"group", required_argument, NULL, 'g'},
					{NULL}};
static const struct optspec os_user = {"u:g:",
				       "  -u, --user         User to run as\n"
				       "  -g, --group        Group to run as\n",
				       lo_user};

bool frr_zclient_addr(struct sockaddr_storage *sa, socklen_t *sa_len,
		      const char *path)
{
	memset(sa, 0, sizeof(*sa));

	if (!path)
		path = frr_zclientpath;

	if (!strncmp(path, ZAPI_TCP_PATHNAME, strlen(ZAPI_TCP_PATHNAME))) {
		/* note: this functionality is disabled at bottom */
		int af;
		int port = ZEBRA_PORT;
		char *err = NULL;
		struct sockaddr_in *sin = NULL;
		struct sockaddr_in6 *sin6 = NULL;

		path += strlen(ZAPI_TCP_PATHNAME);

		switch (path[0]) {
		case '4':
			path++;
			af = AF_INET;
			break;
		case '6':
			path++;
		/* fallthrough */
		default:
			af = AF_INET6;
			break;
		}

		switch (path[0]) {
		case '\0':
			break;
		case ':':
			path++;
			port = strtoul(path, &err, 10);
			if (*err || !*path)
				return false;
			break;
		default:
			return false;
		}

		sa->ss_family = af;
		switch (af) {
		case AF_INET:
			sin = (struct sockaddr_in *)sa;
			sin->sin_port = htons(port);
			sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			*sa_len = sizeof(struct sockaddr_in);
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
			sin->sin_len = *sa_len;
#endif
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)sa;
			sin6->sin6_port = htons(port);
			inet_pton(AF_INET6, "::1", &sin6->sin6_addr);
			*sa_len = sizeof(struct sockaddr_in6);
#ifdef SIN6_LEN
			sin6->sin6_len = *sa_len;
#endif
			break;
		}

#if 1
		/* force-disable this path, because tcp-zebra is a
		 * SECURITY ISSUE.  there are no checks at all against
		 * untrusted users on the local system connecting on TCP
		 * and injecting bogus routing data into the entire routing
		 * domain.
		 *
		 * The functionality is only left here because it may be
		 * useful during development, in order to be able to get
		 * tcpdump or wireshark watching ZAPI as TCP.  If you want
		 * to do that, flip the #if 1 above to #if 0. */
		memset(sa, 0, sizeof(*sa));
		return false;
#endif
	} else {
		/* "sun" is a #define on solaris */
		struct sockaddr_un *suna = (struct sockaddr_un *)sa;

		suna->sun_family = AF_UNIX;
		strlcpy(suna->sun_path, path, sizeof(suna->sun_path));
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
		*sa_len = suna->sun_len = SUN_LEN(suna);
#else
		*sa_len = sizeof(suna->sun_family) + strlen(suna->sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */
#if 0
		/* this is left here for future reference;  Linux abstract
		 * socket namespace support can be enabled by replacing
		 * above #if 0 with #ifdef GNU_LINUX.
		 *
		 * THIS IS A SECURITY ISSUE, the abstract socket namespace
		 * does not have user/group permission control on sockets.
		 * we'd need to implement SCM_CREDENTIALS support first to
		 * check that only proper users can connect to abstract
		 * sockets. (same problem as tcp-zebra, except there is a
		 * fix with SCM_CREDENTIALS.  tcp-zebra has no such fix.)
		 */
		if (suna->sun_path[0] == '@')
			suna->sun_path[0] = '\0';
#endif
	}
	return true;
}

static struct frr_daemon_info *di = NULL;

void frr_init_vtydir(void)
{
	snprintf(frr_vtydir, sizeof(frr_vtydir), DAEMON_VTY_DIR, "", "");
}

void frr_preinit(struct frr_daemon_info *daemon, int argc, char **argv)
{
	di = daemon;

	/* basename(), opencoded. */
	char *p = strrchr(argv[0], '/');
	di->progname = p ? p + 1 : argv[0];

	umask(0027);

	opt_extend(&os_always);
	if (!(di->flags & FRR_NO_CFG_PID_DRY))
		opt_extend(&os_cfg_pid_dry);
	if (!(di->flags & FRR_NO_PRIVSEP))
		opt_extend(&os_user);
	if (!(di->flags & FRR_NO_ZCLIENT))
		opt_extend(&os_zclient);
	if (!(di->flags & FRR_NO_TCPVTY))
		opt_extend(&os_vty);
	if (di->flags & FRR_DETACH_LATER)
		nodetach_daemon = true;

	frr_init_vtydir();
	snprintf(config_default, sizeof(config_default), "%s/%s.conf",
		 frr_sysconfdir, di->name);
	snprintf(pidfile_default, sizeof(pidfile_default), "%s/%s.pid",
		 frr_vtydir, di->name);
	snprintf(frr_zclientpath, sizeof(frr_zclientpath),
		 ZEBRA_SERV_PATH, "", "");
#ifdef HAVE_SQLITE3
	snprintf(dbfile_default, sizeof(dbfile_default), "%s/%s.db",
		 frr_dbdir, di->name);
#endif

	strlcpy(frr_protoname, di->logname, sizeof(frr_protoname));
	strlcpy(frr_protonameinst, di->logname, sizeof(frr_protonameinst));

	di->cli_mode = FRR_CLI_CLASSIC;
}

void frr_opt_add(const char *optstr, const struct option *longopts,
		 const char *helpstr)
{
	const struct optspec main_opts = {optstr, helpstr, longopts};
	opt_extend(&main_opts);
}

void frr_help_exit(int status)
{
	FILE *target = status ? stderr : stdout;

	if (status != 0)
		fprintf(stderr, "Invalid options.\n\n");

	if (di->printhelp)
		di->printhelp(target);
	else
		fprintf(target, "Usage: %s [OPTION...]\n\n%s%s%s\n\n%s",
			di->progname, di->proghelp, di->copyright ? "\n\n" : "",
			di->copyright ? di->copyright : "", comb_helpstr);
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
		print_version(di->progname);
		exit(0);
		break;
	case 'd':
		di->daemon_mode = true;
		break;
	case 'M':
		oc = XMALLOC(MTYPE_TMP, sizeof(*oc));
		oc->arg = optarg;
		oc->next = NULL;
		*modnext = oc;
		modnext = &oc->next;
		break;
	case 'F':
		if (!frr_defaults_profile_valid(optarg)) {
			const char **p;
			FILE *ofd = stderr;

			if (!strcmp(optarg, "help"))
				ofd = stdout;
			else
				fprintf(stderr,
					"The \"%s\" configuration profile is not valid for this FRR version.\n",
					optarg);

			fprintf(ofd, "Available profiles are:\n");
			for (p = frr_defaults_profiles; *p; p++)
				fprintf(ofd, "%s%s\n",
					strcmp(*p, DFLT_NAME) ? "   " : " * ",
					*p);

			if (ofd == stdout)
				exit(0);
			fprintf(ofd, "\n");
			errors++;
			break;
		}
		frr_defaults_profile_set(optarg);
		break;
	case 'i':
		if (di->flags & FRR_NO_CFG_PID_DRY)
			return 1;
		di->pid_file = optarg;
		break;
	case 'f':
		if (di->flags & FRR_NO_CFG_PID_DRY)
			return 1;
		di->config_file = optarg;
		break;
	case 'N':
		if (di->pathspace) {
			fprintf(stderr,
				"-N/--pathspace option specified more than once!\n");
			errors++;
			break;
		}
		if (di->zpathspace)
			fprintf(stderr,
				"-N option overridden by -z for zebra named socket path\n");

		if (strchr(optarg, '/') || strchr(optarg, '.')) {
			fprintf(stderr,
				"slashes or dots are not permitted in the --pathspace option.\n");
			errors++;
			break;
		}
		di->pathspace = optarg;

		if (!di->zpathspace)
			snprintf(frr_zclientpath, sizeof(frr_zclientpath),
				 ZEBRA_SERV_PATH, "/", di->pathspace);
		snprintf(frr_vtydir, sizeof(frr_vtydir), DAEMON_VTY_DIR, "/",
			 di->pathspace);
		snprintf(pidfile_default, sizeof(pidfile_default), "%s/%s.pid",
			 frr_vtydir, di->name);
		break;
#ifdef HAVE_SQLITE3
	case OPTION_DB_FILE:
		if (di->flags & FRR_NO_CFG_PID_DRY)
			return 1;
		di->db_file = optarg;
		break;
#endif
	case 'C':
		if (di->flags & FRR_NO_CFG_PID_DRY)
			return 1;
		di->dryrun = true;
		break;
	case 't':
		if (di->flags & FRR_NO_CFG_PID_DRY)
			return 1;
		di->terminal = true;
		break;
	case 'z':
		di->zpathspace = true;
		if (di->pathspace)
			fprintf(stderr,
				"-z option overrides -N option for zebra named socket path\n");
		if (di->flags & FRR_NO_ZCLIENT)
			return 1;
		strlcpy(frr_zclientpath, optarg, sizeof(frr_zclientpath));
		break;
	case 'A':
		if (di->flags & FRR_NO_TCPVTY)
			return 1;
		if (vty_addr_set) {
			fprintf(stderr,
				"-A option specified more than once!\n");
			errors++;
			break;
		}
		vty_addr_set = 1;
		di->vty_addr = optarg;
		break;
	case 'P':
		if (di->flags & FRR_NO_TCPVTY)
			return 1;
		if (vty_port_set) {
			fprintf(stderr,
				"-P option specified more than once!\n");
			errors++;
			break;
		}
		vty_port_set = 1;
		di->vty_port = strtoul(optarg, &err, 0);
		if (*err || !*optarg) {
			fprintf(stderr,
				"invalid port number \"%s\" for -P option\n",
				optarg);
			errors++;
			break;
		}
		break;
	case OPTION_VTYSOCK:
		if (di->vty_sock_path) {
			fprintf(stderr,
				"--vty_socket option specified more than once!\n");
			errors++;
			break;
		}
		di->vty_sock_path = optarg;
		break;
	case OPTION_MODULEDIR:
		if (di->module_path) {
			fprintf(stderr,
				"----moduledir option specified more than once!\n");
			errors++;
			break;
		}
		di->module_path = optarg;
		break;
	case OPTION_TCLI:
		di->cli_mode = FRR_CLI_TRANSACTIONAL;
		break;
	case 'u':
		if (di->flags & FRR_NO_PRIVSEP)
			return 1;
		di->privs->user = optarg;
		break;
	case 'g':
		if (di->flags & FRR_NO_PRIVSEP)
			return 1;
		di->privs->group = optarg;
		break;
	case OPTION_LOG:
		di->early_logging = optarg;
		break;
	case OPTION_LOGLEVEL:
		di->early_loglevel = optarg;
		break;
	case OPTION_LOGGING:
		di->log_always = true;
		break;
	case OPTION_LIMIT_FDS:
		di->limit_fds = strtoul(optarg, &err, 0);
		break;
	default:
		return 1;
	}
	return 0;
}

int frr_getopt(int argc, char *const argv[], int *longindex)
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

static void frr_mkdir(const char *path, bool strip)
{
	char buf[256];
	mode_t prev;
	int ret;
	struct zprivs_ids_t ids;

	if (strip) {
		char *slash = strrchr(path, '/');
		size_t plen;
		if (!slash)
			return;
		plen = slash - path;
		if (plen > sizeof(buf) - 1)
			return;
		memcpy(buf, path, plen);
		buf[plen] = '\0';
		path = buf;
	}

	/* o+rx (..5) is needed for the frrvty group to work properly;
	 * without it, users in the frrvty group can't access the vty sockets.
	 */
	prev = umask(0022);
	ret = mkdir(path, 0755);
	umask(prev);

	if (ret != 0) {
		/* if EEXIST, return without touching the permissions,
		 * so user-set custom permissions are left in place
		 */
		if (errno == EEXIST)
			return;

		flog_err(EC_LIB_SYSTEM_CALL, "failed to mkdir \"%s\": %s", path,
			 strerror(errno));
		return;
	}

	zprivs_get_ids(&ids);
	if (chown(path, ids.uid_normal, ids.gid_normal))
		flog_err(EC_LIB_SYSTEM_CALL, "failed to chown \"%s\": %s", path,
			 strerror(errno));
}

static struct thread_master *master;
struct thread_master *frr_init(void)
{
	struct option_chain *oc;
	struct frrmod_runtime *module;
	struct zprivs_ids_t ids;
	char moderr[256];
	char p_instance[16] = "", p_pathspace[256] = "";
	const char *dir;
	dir = di->module_path ? di->module_path : frr_moduledir;

	srandom(time(NULL));
	frr_defaults_apply();

	if (di->instance) {
		snprintf(frr_protonameinst, sizeof(frr_protonameinst), "%s[%u]",
			 di->logname, di->instance);
		snprintf(p_instance, sizeof(p_instance), "-%d", di->instance);
	}
	if (di->pathspace)
		snprintf(p_pathspace, sizeof(p_pathspace), "%s/",
			 di->pathspace);

	snprintf(config_default, sizeof(config_default), "%s%s%s%s.conf",
		 frr_sysconfdir, p_pathspace, di->name, p_instance);
	snprintf(pidfile_default, sizeof(pidfile_default), "%s/%s%s.pid",
		 frr_vtydir, di->name, p_instance);
#ifdef HAVE_SQLITE3
	snprintf(dbfile_default, sizeof(dbfile_default), "%s/%s%s%s.db",
		 frr_dbdir, p_pathspace, di->name, p_instance);
#endif

	zprivs_preinit(di->privs);
	zprivs_get_ids(&ids);

	zlog_init(di->progname, di->logname, di->instance,
		  ids.uid_normal, ids.gid_normal);

	command_setup_early_logging(di->early_logging, di->early_loglevel);

	if (!frr_zclient_addr(&zclient_addr, &zclient_addr_len,
			      frr_zclientpath)) {
		fprintf(stderr, "Invalid zserv socket path: %s\n",
			frr_zclientpath);
		exit(1);
	}

	/* don't mkdir these as root... */
	if (!(di->flags & FRR_NO_PRIVSEP)) {
		if (!di->pid_file || !di->vty_path)
			frr_mkdir(frr_vtydir, false);
		if (di->pid_file)
			frr_mkdir(di->pid_file, true);
		if (di->vty_path)
			frr_mkdir(di->vty_path, true);
	}

	frrmod_init(di->module);
	while (modules) {
		modules = (oc = modules)->next;
		module = frrmod_load(oc->arg, dir, moderr, sizeof(moderr));
		if (!module) {
			fprintf(stderr, "%s\n", moderr);
			exit(1);
		}
		XFREE(MTYPE_TMP, oc);
	}

	zprivs_init(di->privs);

	master = thread_master_create(NULL);
	signal_init(master, di->n_signals, di->signals);

#ifdef HAVE_SQLITE3
	if (!di->db_file)
		di->db_file = dbfile_default;
	db_init(di->db_file);
#endif

	if (di->flags & FRR_LIMITED_CLI)
		cmd_init(-1);
	else
		cmd_init(1);

	vty_init(master, di->log_always);
	lib_cmd_init();

	frr_pthread_init();

	log_ref_init();
	log_ref_vty_init();
	lib_error_init();

	yang_init(true);

	debug_init_cli();

	nb_init(master, di->yang_modules, di->n_yang_modules, true);
	if (nb_db_init() != NB_OK)
		flog_warn(EC_LIB_NB_DATABASE,
			  "%s: failed to initialize northbound database",
			  __func__);

	return master;
}

const char *frr_get_progname(void)
{
	return di ? di->progname : NULL;
}

enum frr_cli_mode frr_get_cli_mode(void)
{
	return di ? di->cli_mode : FRR_CLI_CLASSIC;
}

uint32_t frr_get_fd_limit(void)
{
	return di ? di->limit_fds : 0;
}

static int rcvd_signal = 0;

static void rcv_signal(int signum)
{
	rcvd_signal = signum;
	/* poll() is interrupted by the signal; handled below */
}

static void frr_daemon_wait(int fd)
{
	struct pollfd pfd[1];
	int ret;
	pid_t exitpid;
	int exitstat;
	sigset_t sigs, prevsigs;

	sigemptyset(&sigs);
	sigaddset(&sigs, SIGTSTP);
	sigaddset(&sigs, SIGQUIT);
	sigaddset(&sigs, SIGINT);
	sigprocmask(SIG_BLOCK, &sigs, &prevsigs);

	struct sigaction sa = {
		.sa_handler = rcv_signal, .sa_flags = SA_RESETHAND,
	};
	sigemptyset(&sa.sa_mask);
	sigaction(SIGTSTP, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	do {
		char buf[1];
		ssize_t nrecv;

		pfd[0].fd = fd;
		pfd[0].events = POLLIN;

		rcvd_signal = 0;

#if defined(HAVE_PPOLL)
		ret = ppoll(pfd, 1, NULL, &prevsigs);
#elif defined(HAVE_POLLTS)
		ret = pollts(pfd, 1, NULL, &prevsigs);
#else
		/* racy -- only used on FreeBSD 9 */
		sigset_t tmpsigs;
		sigprocmask(SIG_SETMASK, &prevsigs, &tmpsigs);
		ret = poll(pfd, 1, -1);
		sigprocmask(SIG_SETMASK, &tmpsigs, NULL);
#endif
		if (ret < 0 && errno != EINTR && errno != EAGAIN) {
			perror("poll()");
			exit(1);
		}
		switch (rcvd_signal) {
		case SIGTSTP:
			send(fd, "S", 1, 0);
			do {
				nrecv = recv(fd, buf, sizeof(buf), 0);
			} while (nrecv == -1
				 && (errno == EINTR || errno == EAGAIN));

			raise(SIGTSTP);
			sigaction(SIGTSTP, &sa, NULL);
			send(fd, "R", 1, 0);
			break;
		case SIGINT:
			send(fd, "I", 1, 0);
			break;
		case SIGQUIT:
			send(fd, "Q", 1, 0);
			break;
		}
	} while (ret <= 0);

	exitpid = waitpid(-1, &exitstat, WNOHANG);
	if (exitpid == 0)
		/* child successfully went to main loop & closed socket */
		exit(0);

	/* child failed one way or another ... */
	if (WIFEXITED(exitstat) && WEXITSTATUS(exitstat) == 0)
		/* can happen in --terminal case if exit is fast enough */
		(void)0;
	else if (WIFEXITED(exitstat))
		fprintf(stderr, "%s failed to start, exited %d\n", di->name,
			WEXITSTATUS(exitstat));
	else if (WIFSIGNALED(exitstat))
		fprintf(stderr, "%s crashed in startup, signal %d\n", di->name,
			WTERMSIG(exitstat));
	else
		fprintf(stderr, "%s failed to start, unknown problem\n",
			di->name);
	exit(1);
}

static int daemon_ctl_sock = -1;

static void frr_daemonize(void)
{
	int fds[2];
	pid_t pid;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) {
		perror("socketpair() for daemon control");
		exit(1);
	}
	set_cloexec(fds[0]);
	set_cloexec(fds[1]);

	pid = fork();
	if (pid < 0) {
		perror("fork()");
		exit(1);
	}
	if (pid == 0) {
		/* child */
		close(fds[0]);
		if (setsid() < 0) {
			perror("setsid()");
			exit(1);
		}

		daemon_ctl_sock = fds[1];
		return;
	}

	close(fds[1]);
	frr_daemon_wait(fds[0]);
}

/*
 * Why is this a thread?
 *
 * The read in of config for integrated config happens *after*
 * thread execution starts( because it is passed in via a vtysh -b -n )
 * While if you are not using integrated config we want the ability
 * to read the config in after thread execution starts, so that
 * we can match this behavior.
 */
static int frr_config_read_in(struct thread *t)
{
	if (!vty_read_config(vty_shared_candidate_config, di->config_file,
			     config_default)
	    && di->backup_config_file) {
		char *orig = XSTRDUP(MTYPE_TMP, host_config_get());

		zlog_info("Attempting to read backup config file: %s specified",
			  di->backup_config_file);
		vty_read_config(vty_shared_candidate_config,
				di->backup_config_file, config_default);

		host_config_set(orig);
		XFREE(MTYPE_TMP, orig);
	}

	/*
	 * Automatically commit the candidate configuration after
	 * reading the configuration file.
	 */
	if (frr_get_cli_mode() == FRR_CLI_TRANSACTIONAL) {
		struct nb_context context = {};
		char errmsg[BUFSIZ] = {0};
		int ret;

		context.client = NB_CLIENT_CLI;
		ret = nb_candidate_commit(&context, vty_shared_candidate_config,
					  true, "Read configuration file", NULL,
					  errmsg, sizeof(errmsg));
		if (ret != NB_OK && ret != NB_ERR_NO_CHANGES)
			zlog_err(
				"%s: failed to read configuration file: %s (%s)",
				__func__, nb_err_name(ret), errmsg);
	}

	hook_call(frr_very_late_init, master);

	return 0;
}

void frr_config_fork(void)
{
	hook_call(frr_late_init, master);

	if (!(di->flags & FRR_NO_CFG_PID_DRY)) {
		/* Don't start execution if we are in dry-run mode */
		if (di->dryrun) {
			frr_config_read_in(NULL);
			exit(0);
		}

		thread_add_event(master, frr_config_read_in, NULL, 0,
				 &di->read_in);
	}

	if (di->daemon_mode || di->terminal)
		frr_daemonize();

	if (!di->pid_file)
		di->pid_file = pidfile_default;
	pid_output(di->pid_file);
	zlog_tls_buffer_init();
}

static void frr_vty_serv(void)
{
	/* allow explicit override of vty_path in the future
	 * (not currently set anywhere) */
	if (!di->vty_path) {
		const char *dir;
		char defvtydir[256];

		snprintf(defvtydir, sizeof(defvtydir), "%s", frr_vtydir);

		dir = di->vty_sock_path ? di->vty_sock_path : defvtydir;

		if (di->instance)
			snprintf(vtypath_default, sizeof(vtypath_default),
				 "%s/%s-%d.vty", dir, di->name, di->instance);
		else
			snprintf(vtypath_default, sizeof(vtypath_default),
				 "%s/%s.vty", dir, di->name);

		di->vty_path = vtypath_default;
	}

	vty_serv_sock(di->vty_addr, di->vty_port, di->vty_path);
}

static void frr_check_detach(void)
{
	if (nodetach_term || nodetach_daemon)
		return;

	if (daemon_ctl_sock != -1)
		close(daemon_ctl_sock);
	daemon_ctl_sock = -1;
}

static void frr_terminal_close(int isexit)
{
	int nullfd;

	nodetach_term = false;
	frr_check_detach();

	if (!di->daemon_mode || isexit) {
		printf("\n%s exiting\n", di->name);
		if (!isexit)
			raise(SIGINT);
		return;
	} else {
		printf("\n%s daemonizing\n", di->name);
		fflush(stdout);
	}

	nullfd = open("/dev/null", O_RDONLY | O_NOCTTY);
	if (nullfd == -1) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "%s: failed to open /dev/null: %s", __func__,
			     safe_strerror(errno));
	} else {
		dup2(nullfd, 0);
		dup2(nullfd, 1);
		dup2(nullfd, 2);
		close(nullfd);
	}
}

static struct thread *daemon_ctl_thread = NULL;

static int frr_daemon_ctl(struct thread *t)
{
	char buf[1];
	ssize_t nr;

	nr = recv(daemon_ctl_sock, buf, sizeof(buf), 0);
	if (nr < 0 && (errno == EINTR || errno == EAGAIN))
		goto out;
	if (nr <= 0)
		return 0;

	switch (buf[0]) {
	case 'S': /* SIGTSTP */
		vty_stdio_suspend();
		if (send(daemon_ctl_sock, "s", 1, 0) < 0)
			zlog_err("%s send(\"s\") error (SIGTSTP propagation)",
				 (di && di->name ? di->name : ""));
		break;
	case 'R': /* SIGTCNT [implicit] */
		vty_stdio_resume();
		break;
	case 'I': /* SIGINT */
		di->daemon_mode = false;
		raise(SIGINT);
		break;
	case 'Q': /* SIGQUIT */
		di->daemon_mode = true;
		vty_stdio_close();
		break;
	}

out:
	thread_add_read(master, frr_daemon_ctl, NULL, daemon_ctl_sock,
			&daemon_ctl_thread);
	return 0;
}

void frr_detach(void)
{
	nodetach_daemon = false;
	frr_check_detach();
}

void frr_run(struct thread_master *master)
{
	char instanceinfo[64] = "";

	frr_vty_serv();

	if (di->instance)
		snprintf(instanceinfo, sizeof(instanceinfo), "instance %u ",
			 di->instance);

	zlog_notice("%s %s starting: %svty@%d%s", di->name, FRR_VERSION,
		    instanceinfo, di->vty_port, di->startinfo);

	if (di->terminal) {
		nodetach_term = true;

		vty_stdio(frr_terminal_close);
		if (daemon_ctl_sock != -1) {
			set_nonblocking(daemon_ctl_sock);
			thread_add_read(master, frr_daemon_ctl, NULL,
					daemon_ctl_sock, &daemon_ctl_thread);
		}
	} else if (di->daemon_mode) {
		int nullfd = open("/dev/null", O_RDONLY | O_NOCTTY);
		if (nullfd == -1) {
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "%s: failed to open /dev/null: %s",
				     __func__, safe_strerror(errno));
		} else {
			dup2(nullfd, 0);
			dup2(nullfd, 1);
			dup2(nullfd, 2);
			close(nullfd);
		}

		frr_check_detach();
	}

	/* end fixed stderr startup logging */
	zlog_startup_end();

	struct thread thread;
	while (thread_fetch(master, &thread))
		thread_call(&thread);
}

void frr_early_fini(void)
{
	hook_call(frr_early_fini);
}

void frr_fini(void)
{
	FILE *fp;
	char filename[128];
	int have_leftovers;

	hook_call(frr_fini);

	vty_terminate();
	cmd_terminate();
	nb_terminate();
	yang_terminate();
#ifdef HAVE_SQLITE3
	db_close();
#endif
	log_ref_fini();
	frr_pthread_finish();
	zprivs_terminate(di->privs);
	/* signal_init -> nothing needed */
	thread_master_free(master);
	master = NULL;
	zlog_tls_buffer_fini();
	zlog_fini();
	/* frrmod_init -> nothing needed / hooks */
	rcu_shutdown();

	if (!debug_memstats_at_exit)
		return;

	have_leftovers = log_memstats(stderr, di->name);

	/* in case we decide at runtime that we want exit-memstats for
	 * a daemon, but it has no stderr because it's daemonized
	 * (only do this if we actually have something to print though)
	 */
	if (!have_leftovers)
		return;

	snprintf(filename, sizeof(filename), "/tmp/frr-memstats-%s-%llu-%llu",
		 di->name, (unsigned long long)getpid(),
		 (unsigned long long)time(NULL));

	fp = fopen(filename, "w");
	if (fp) {
		log_memstats(fp, di->name);
		fclose(fp);
	}
}

#ifdef INTERP
static const char interp[]
	__attribute__((section(".interp"), used)) = INTERP;
#endif
/*
 * executable entry point for libfrr.so
 *
 * note that libc initialization is skipped for this so the set of functions
 * that can be called is rather limited
 */
extern void _libfrr_version(void)
	__attribute__((visibility("hidden"), noreturn));
void _libfrr_version(void)
{
	const char banner[] =
		FRR_FULL_NAME " " FRR_VERSION ".\n"
		FRR_COPYRIGHT GIT_INFO "\n"
		"configured with:\n    " FRR_CONFIG_ARGS "\n";
	write(1, banner, sizeof(banner) - 1);
	_exit(0);
}
