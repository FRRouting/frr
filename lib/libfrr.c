// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * libfrr overall management functions
 *
 * Copyright (C) 2016  David Lamparter for NetDEF, Inc.
 */

#include <zebra.h>

#include <signal.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/wait.h>

#include "libfrr.h"
#include "getopt.h"
#include "privs.h"
#include "vty.h"
#include "command.h"
#include "lib/version.h"
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
#include "frrscript.h"
#include "systemd.h"

#include "lib/config_paths.h"

DEFINE_HOOK(frr_early_init, (struct event_loop * tm), (tm));
DEFINE_HOOK(frr_late_init, (struct event_loop * tm), (tm));
DEFINE_HOOK(frr_config_pre, (struct event_loop * tm), (tm));
DEFINE_HOOK(frr_config_post, (struct event_loop * tm), (tm));
DEFINE_KOOH(frr_early_fini, (), ());
DEFINE_KOOH(frr_fini, (), ());

const char frr_sysconfdir[] = SYSCONFDIR;
char frr_runstatedir[256] = FRR_RUNSTATE_PATH;
char frr_libstatedir[256] = FRR_LIBSTATE_PATH;
const char frr_moduledir[] = MODULE_PATH;
const char frr_scriptdir[] = SCRIPT_PATH;

char frr_protoname[256] = "NONE";
char frr_protonameinst[256] = "NONE";

char config_default[512];
char frr_zclientpath[512];
static char pidfile_default[1024];
#ifdef HAVE_SQLITE3
static char dbfile_default[1024];
#endif
static char vtypath_default[512];

/* cleared in frr_preinit(), then re-set after daemonizing */
bool frr_is_after_fork = true;
bool debug_memstats_at_exit = false;
static bool nodetach_term, nodetach_daemon;
static uint64_t startup_fds;

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
#define OPTION_SCRIPTDIR 1009

static const struct option lo_always[] = {
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{"daemon", no_argument, NULL, 'd'},
	{"module", no_argument, NULL, 'M'},
	{"profile", required_argument, NULL, 'F'},
	{"pathspace", required_argument, NULL, 'N'},
	{"vrfdefaultname", required_argument, NULL, 'o'},
	{"vty_socket", required_argument, NULL, OPTION_VTYSOCK},
	{"moduledir", required_argument, NULL, OPTION_MODULEDIR},
	{"scriptdir", required_argument, NULL, OPTION_SCRIPTDIR},
	{"log", required_argument, NULL, OPTION_LOG},
	{"log-level", required_argument, NULL, OPTION_LOGLEVEL},
	{"command-log-always", no_argument, NULL, OPTION_LOGGING},
	{"limit-fds", required_argument, NULL, OPTION_LIMIT_FDS},
	{NULL}};
static const struct optspec os_always = {
	"hvdM:F:N:o:",
	"  -h, --help         Display this help and exit\n"
	"  -v, --version      Print program version\n"
	"  -d, --daemon       Runs in daemon mode\n"
	"  -M, --module       Load specified module\n"
	"  -F, --profile      Use specified configuration profile\n"
	"  -N, --pathspace    Insert prefix into config & socket paths\n"
	"  -o, --vrfdefaultname     Set default VRF name.\n"
	"      --vty_socket   Override vty socket path\n"
	"      --moduledir    Override modules directory\n"
	"      --scriptdir    Override scripts directory\n"
	"      --log          Set Logging to stdout, syslog, or file:<name>\n"
	"      --log-level    Set Logging Level to use, debug, info, warn, etc\n"
	"      --limit-fds    Limit number of fds supported\n",
	lo_always};

static bool logging_to_stdout = false; /* set when --log stdout specified */

static const struct option lo_cfg[] = {
	{"config_file", required_argument, NULL, 'f'},
	{"dryrun", no_argument, NULL, 'C'},
	{NULL}};
static const struct optspec os_cfg = {
	"f:C",
	"  -f, --config_file  Set configuration file name\n"
	"  -C, --dryrun       Check configuration for validity and exit\n",
	lo_cfg};


static const struct option lo_fullcli[] = {
	{"terminal", no_argument, NULL, 't'},
	{"tcli", no_argument, NULL, OPTION_TCLI},
#ifdef HAVE_SQLITE3
	{"db_file", required_argument, NULL, OPTION_DB_FILE},
#endif
	{NULL}};
static const struct optspec os_fullcli = {
	"t",
	"      --tcli         Use transaction-based CLI\n"
	"  -t, --terminal     Open terminal session on stdio\n"
	"  -d -t              Daemonize after terminal session ends\n",
	lo_fullcli};


static const struct option lo_pid[] = {
	{"pid_file", required_argument, NULL, 'i'},
	{NULL}};
static const struct optspec os_pid = {
	"i:",
	"  -i, --pid_file     Set process identifier file name\n",
	lo_pid};


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
		int port = ZEBRA_TCP_PORT;
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
			af = AF_INET6;
			break;
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

void frr_preinit(struct frr_daemon_info *daemon, int argc, char **argv)
{
	di = daemon;
	frr_is_after_fork = false;

	/* basename(), opencoded. */
	char *p = strrchr(argv[0], '/');
	di->progname = p ? p + 1 : argv[0];

	if (!getenv("GCOV_PREFIX"))
		umask(0027);
	else {
		/* If we are profiling use a more generous umask */
		umask(0002);
	}

	log_args_init(daemon->early_logging);

	opt_extend(&os_always);
	if (!(di->flags & FRR_NO_SPLIT_CONFIG))
		opt_extend(&os_cfg);
	if (!(di->flags & FRR_LIMITED_CLI))
		opt_extend(&os_fullcli);
	if (!(di->flags & FRR_NO_PID))
		opt_extend(&os_pid);
	if (!(di->flags & FRR_NO_PRIVSEP))
		opt_extend(&os_user);
	if (!(di->flags & FRR_NO_ZCLIENT))
		opt_extend(&os_zclient);
	if (!(di->flags & FRR_NO_TCPVTY))
		opt_extend(&os_vty);
	if (di->flags & FRR_DETACH_LATER)
		nodetach_daemon = true;

	snprintf(config_default, sizeof(config_default), "%s/%s.conf",
		 frr_sysconfdir, di->name);
	snprintf(pidfile_default, sizeof(pidfile_default), "%s/%s.pid",
		 frr_runstatedir, di->name);
	snprintf(frr_zclientpath, sizeof(frr_zclientpath), ZAPI_SOCK_NAME);
#ifdef HAVE_SQLITE3
	snprintf(dbfile_default, sizeof(dbfile_default), "%s/%s.db",
		 frr_libstatedir, di->name);
#endif

	strlcpy(frr_protoname, di->logname, sizeof(frr_protoname));
	strlcpy(frr_protonameinst, di->logname, sizeof(frr_protonameinst));

	di->cli_mode = FRR_CLI_CLASSIC;

	/* we may be starting with extra FDs open for whatever purpose,
	 * e.g. logging, some module, etc.  Recording them here allows later
	 * checking whether an fd is valid for such extension purposes,
	 * without this we could end up e.g. logging to a BGP session fd.
	 */
	startup_fds = 0;
	for (int i = 0; i < 64; i++) {
		struct stat st;

		if (fstat(i, &st))
			continue;
		if (S_ISDIR(st.st_mode) || S_ISBLK(st.st_mode))
			continue;

		startup_fds |= UINT64_C(0x1) << (uint64_t)i;
	}

	/* note this doesn't do anything, it just grabs state, so doing it
	 * early in _preinit is perfect.
	 */
	systemd_init_env();
}

bool frr_is_startup_fd(int fd)
{
	return !!(startup_fds & (UINT64_C(0x1) << (uint64_t)fd));
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
	struct log_arg *log_arg;
	size_t arg_len;
	char *err;

	switch (opt) {
	case 'h':
		frr_help_exit(0);
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
		if (di->flags & FRR_NO_PID)
			return 1;
		di->pid_file = optarg;
		break;
	case 'f':
		if (di->flags & FRR_NO_SPLIT_CONFIG)
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

		snprintf(frr_runstatedir, sizeof(frr_runstatedir),
			 FRR_RUNSTATE_PATH "/%s", di->pathspace);
		snprintf(frr_libstatedir, sizeof(frr_libstatedir),
			 FRR_LIBSTATE_PATH "/%s", di->pathspace);
		snprintf(pidfile_default, sizeof(pidfile_default), "%s/%s.pid",
			 frr_runstatedir, di->name);
		if (!di->zpathspace)
			snprintf(frr_zclientpath, sizeof(frr_zclientpath),
				 ZAPI_SOCK_NAME);
		break;
	case 'o':
		vrf_set_default_name(optarg);
		break;
#ifdef HAVE_SQLITE3
	case OPTION_DB_FILE:
		if (di->flags & FRR_NO_PID)
			return 1;
		di->db_file = optarg;
		break;
#endif
	case 'C':
		if (di->flags & FRR_NO_SPLIT_CONFIG)
			return 1;
		di->dryrun = true;
		break;
	case 't':
		if (di->flags & FRR_LIMITED_CLI)
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
	case OPTION_SCRIPTDIR:
		if (di->script_path) {
			fprintf(stderr, "--scriptdir option specified more than once!\n");
			errors++;
			break;
		}
		di->script_path = optarg;
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
		arg_len = strlen(optarg) + 1;
		log_arg = XCALLOC(MTYPE_TMP, sizeof(*log_arg) + arg_len);
		memcpy(log_arg->target, optarg, arg_len);
		log_args_add_tail(di->early_logging, log_arg);
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

static void _err_print(const void *cookie, const char *errstr)
{
	const char *prefix = (const char *)cookie;

	fprintf(stderr, "%s: %s\n", prefix, errstr);
}

static struct event_loop *master;
struct event_loop *frr_init(void)
{
	struct option_chain *oc;
	struct log_arg *log_arg;
	struct frrmod_runtime *module;
	struct zprivs_ids_t ids;
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
		 frr_runstatedir, di->name, p_instance);
#ifdef HAVE_SQLITE3
	snprintf(dbfile_default, sizeof(dbfile_default), "%s/%s%s%s.db",
		 frr_libstatedir, p_pathspace, di->name, p_instance);
#endif

	zprivs_preinit(di->privs);
	zprivs_get_ids(&ids);

	zlog_init(di->progname, di->logname, di->instance,
		  ids.uid_normal, ids.gid_normal);

	while ((log_arg = log_args_pop(di->early_logging))) {
		command_setup_early_logging(log_arg->target,
					    di->early_loglevel);
		/* this is a bit of a hack,
		   but need to notice when
		   the target is stdout */
		if (strcmp(log_arg->target, "stdout") == 0)
			logging_to_stdout = true;
		XFREE(MTYPE_TMP, log_arg);
	}

	if (!frr_zclient_addr(&zclient_addr, &zclient_addr_len,
			      frr_zclientpath)) {
		fprintf(stderr, "Invalid zserv socket path: %s\n",
			frr_zclientpath);
		exit(1);
	}

	/* don't mkdir these as root... */
	if (!(di->flags & FRR_NO_PRIVSEP)) {
		frr_mkdir(frr_libstatedir, false);
		if (!di->pid_file || !di->vty_path)
			frr_mkdir(frr_runstatedir, false);
		if (di->pid_file)
			frr_mkdir(di->pid_file, true);
		if (di->vty_path)
			frr_mkdir(di->vty_path, true);
	}

	frrmod_init(di->module);
	while (modules) {
		modules = (oc = modules)->next;
		module = frrmod_load(oc->arg, dir, _err_print, __func__);
		if (!module)
			exit(1);
		XFREE(MTYPE_TMP, oc);
	}

	zprivs_init(di->privs);

	master = event_master_create(NULL);
	signal_init(master, di->n_signals, di->signals);
	hook_call(frr_early_init, master);

#ifdef HAVE_SQLITE3
	if (!di->db_file)
		di->db_file = dbfile_default;
	db_init("%s", di->db_file);
#endif

	if (di->flags & FRR_LIMITED_CLI)
		cmd_init(-1);
	else
		cmd_init(1);

	vty_init(master, di->log_always);
	lib_cmd_init();

	frr_pthread_init();
#ifdef HAVE_SCRIPTING
	frrscript_init(di->script_path ? di->script_path : frr_scriptdir);
#endif

	log_ref_init();
	log_ref_vty_init();
	lib_error_init();

	nb_init(master, di->yang_modules, di->n_yang_modules, true);
	if (nb_db_init() != NB_OK)
		flog_warn(EC_LIB_NB_DATABASE,
			  "%s: failed to initialize northbound database",
			  __func__);

	debug_init_cli();

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
static void frr_config_read_in(struct event *t)
{
	hook_call(frr_config_pre, master);

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
		ret = nb_candidate_commit(context, vty_shared_candidate_config,
					  true, "Read configuration file", NULL,
					  errmsg, sizeof(errmsg));
		if (ret != NB_OK && ret != NB_ERR_NO_CHANGES)
			zlog_err(
				"%s: failed to read configuration file: %s (%s)",
				__func__, nb_err_name(ret), errmsg);
	}

	hook_call(frr_config_post, master);
}

void frr_config_fork(void)
{
	hook_call(frr_late_init, master);

	if (!(di->flags & FRR_NO_SPLIT_CONFIG)) {
		/* Don't start execution if we are in dry-run mode */
		if (di->dryrun) {
			frr_config_read_in(NULL);
			exit(0);
		}

		event_add_event(master, frr_config_read_in, NULL, 0,
				&di->read_in);
	}

	if (di->daemon_mode || di->terminal)
		frr_daemonize();

	frr_is_after_fork = true;

	if (!di->pid_file)
		di->pid_file = pidfile_default;
	pid_output(di->pid_file);
	zlog_tls_buffer_init();
}

void frr_vty_serv_start(void)
{
	/* allow explicit override of vty_path in the future
	 * (not currently set anywhere) */
	if (!di->vty_path) {
		const char *dir;
		char defvtydir[256];

		snprintf(defvtydir, sizeof(defvtydir), "%s", frr_runstatedir);

		dir = di->vty_sock_path ? di->vty_sock_path : defvtydir;

		if (di->instance)
			snprintf(vtypath_default, sizeof(vtypath_default),
				 "%s/%s-%d.vty", dir, di->name, di->instance);
		else
			snprintf(vtypath_default, sizeof(vtypath_default),
				 "%s/%s.vty", dir, di->name);

		di->vty_path = vtypath_default;
	}

	vty_serv_start(di->vty_addr, di->vty_port, di->vty_path);
}

void frr_vty_serv_stop(void)
{
	vty_serv_stop();

	if (di->vty_path)
		unlink(di->vty_path);
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
		int fd;
		/*
		 * only redirect stdin, stdout, stderr to null when a tty also
		 * don't redirect when stdout is set with --log stdout
		 */
		for (fd = 2; fd >= 0; fd--)
			if (isatty(fd) &&
			    (fd != STDOUT_FILENO || !logging_to_stdout))
				dup2(nullfd, fd);
		close(nullfd);
	}
}

static struct event *daemon_ctl_thread = NULL;

static void frr_daemon_ctl(struct event *t)
{
	char buf[1];
	ssize_t nr;

	nr = recv(daemon_ctl_sock, buf, sizeof(buf), 0);
	if (nr < 0 && (errno == EINTR || errno == EAGAIN))
		goto out;
	if (nr <= 0)
		return;

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
	event_add_read(master, frr_daemon_ctl, NULL, daemon_ctl_sock,
		       &daemon_ctl_thread);
}

void frr_detach(void)
{
	nodetach_daemon = false;
	frr_check_detach();
}

void frr_run(struct event_loop *master)
{
	char instanceinfo[64] = "";

	if (!(di->flags & FRR_MANUAL_VTY_START))
		frr_vty_serv_start();

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
			event_add_read(master, frr_daemon_ctl, NULL,
				       daemon_ctl_sock, &daemon_ctl_thread);
		}
	} else if (di->daemon_mode) {
		int nullfd = open("/dev/null", O_RDONLY | O_NOCTTY);
		if (nullfd == -1) {
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "%s: failed to open /dev/null: %s",
				     __func__, safe_strerror(errno));
		} else {
			int fd;
			/*
			 * only redirect stdin, stdout, stderr to null when a
			 * tty also don't redirect when stdout is set with --log
			 * stdout
			 */
			for (fd = 2; fd >= 0; fd--)
				if (isatty(fd) &&
				    (fd != STDOUT_FILENO || !logging_to_stdout))
					dup2(nullfd, fd);
			close(nullfd);
		}

		frr_check_detach();
	}

	/* end fixed stderr startup logging */
	zlog_startup_end();

	struct event thread;
	while (event_fetch(master, &thread))
		event_call(&thread);
}

void frr_early_fini(void)
{
	hook_call(frr_early_fini);
}

void frr_fini(void)
{
	FILE *fp;
	char filename[128];
	int have_leftovers = 0;

	hook_call(frr_fini);

	vty_terminate();
	cmd_terminate();
	nb_terminate();
	yang_terminate();
#ifdef HAVE_SQLITE3
	db_close();
#endif
	log_ref_fini();

#ifdef HAVE_SCRIPTING
	frrscript_fini();
#endif
	frr_pthread_finish();
	zprivs_terminate(di->privs);
	/* signal_init -> nothing needed */
	event_master_free(master);
	master = NULL;
	zlog_tls_buffer_fini();
	zlog_fini();
	/* frrmod_init -> nothing needed / hooks */
	rcu_shutdown();

	/* also log memstats to stderr when stderr goes to a file*/
	if (debug_memstats_at_exit || !isatty(STDERR_FILENO))
		have_leftovers = log_memstats(stderr, di->name);

	/* in case we decide at runtime that we want exit-memstats for
	 * a daemon
	 * (only do this if we actually have something to print though)
	 */
	if (!debug_memstats_at_exit || !have_leftovers)
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

struct json_object *frr_daemon_state_load(void)
{
	struct json_object *state;
	char **state_path;

	assertf(di->state_paths,
		"CODE BUG: daemon trying to load state, but no state path in frr_daemon_info");

	for (state_path = di->state_paths; *state_path; state_path++) {
		state = json_object_from_file(*state_path);
		if (state)
			return state;
	}

	return json_object_new_object();
}

/* cross-reference file_write_config() in command.c
 * the code there is similar but not identical (configs use a unique temporary
 * name for writing and keep a backup of the previous config.)
 */
void frr_daemon_state_save(struct json_object **statep)
{
	struct json_object *state = *statep;
	char *state_path, *slash, *temp_name, **other;
	size_t name_len, json_len;
	const char *json_str;
	int dirfd, fd;

	assertf(di->state_paths,
		"CODE BUG: daemon trying to save state, but no state path in frr_daemon_info");

	state_path = di->state_paths[0];
	json_str = json_object_to_json_string_ext(state,
						  JSON_C_TO_STRING_PRETTY);
	json_len = strlen(json_str);

	/* To correctly fsync() and ensure we have either consistent old state
	 * or consistent new state but no fs-damage garbage inbetween, we need
	 * to work with a directory fd.  If we need that anyway we might as
	 * well use the dirfd with openat() & co in fd-relative operations.
	 */

	slash = strrchr(state_path, '/');
	if (slash) {
		char *state_dir;

		state_dir = XSTRDUP(MTYPE_TMP, state_path);
		state_dir[slash - state_path] = '\0';
		dirfd = open(state_dir, O_DIRECTORY | O_RDONLY);
		XFREE(MTYPE_TMP, state_dir);

		if (dirfd < 0) {
			zlog_err("failed to open directory %pSQq for saving daemon state: %m",
				 state_dir);
			return;
		}

		/* skip to file name */
		slash++;
	} else {
		dirfd = open(".", O_DIRECTORY | O_RDONLY);
		if (dirfd < 0) {
			zlog_err(
				"failed to open current directory for saving daemon state: %m");
			return;
		}

		/* file name = path */
		slash = state_path;
	}

	/* unlike saving configs, a temporary unique filename is unhelpful
	 * here as it might litter files on limited write-heavy storage
	 * (think switch with small NOR flash for frequently written data.)
	 *
	 * => always use filename with .sav suffix, worst case it litters one
	 * file.
	 */
	name_len = strlen(slash);
	temp_name = XMALLOC(MTYPE_TMP, name_len + 5);
	memcpy(temp_name, slash, name_len);
	memcpy(temp_name + name_len, ".sav", 5);

	/* state file is always 0600, it's by and for FRR itself only */
	fd = openat(dirfd, temp_name, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		zlog_err("failed to open temporary daemon state save file for %pSQq: %m",
			 state_path);
		goto out_closedir_free;
	}

	while (json_len) {
		ssize_t nwr = write(fd, json_str, json_len);

		if (nwr <= 0) {
			zlog_err("failed to write temporary daemon state to %pSQq: %m",
				 state_path);

			close(fd);
			unlinkat(dirfd, temp_name, 0);
			goto out_closedir_free;
		}

		json_str += nwr;
		json_len -= nwr;
	}

	/* fsync is theoretically implicit in close(), but... */
	if (fsync(fd) < 0)
		zlog_warn("fsync for daemon state %pSQq failed: %m", state_path);
	close(fd);

	/* this is the *actual* fsync that ensures we're consistent.  The
	 * file fsync only syncs the inode, but not the directory entry
	 * referring to it.
	 */
	if (fsync(dirfd) < 0)
		zlog_warn("directory fsync for daemon state %pSQq failed: %m",
			  state_path);

	/* atomic, hopefully. */
	if (renameat(dirfd, temp_name, dirfd, slash) < 0) {
		zlog_err("renaming daemon state %pSQq to %pSQq failed: %m",
			 temp_name, state_path);
		/* no unlink here, give the user a chance to investigate */
		goto out_closedir_free;
	}

	/* and the rename needs to be synced too */
	if (fsync(dirfd) < 0)
		zlog_warn("directory fsync for daemon state %pSQq failed after rename: %m",
			  state_path);

	/* daemon may specify other deprecated paths to load from; since we
	 * just saved successfully we should delete those.
	 */
	for (other = di->state_paths + 1; *other; other++) {
		if (unlink(*other) == 0)
			continue;
		if (errno == ENOENT || errno == ENOTDIR)
			continue;

		zlog_warn("failed to remove deprecated daemon state file %pSQq: %m",
			  *other);
	}

out_closedir_free:
	XFREE(MTYPE_TMP, temp_name);
	close(dirfd);

	json_object_free(state);
	*statep = NULL;
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

/* Render simple version tuple to string */
const char *frr_vers2str(uint32_t version, char *buf, int buflen)
{
	snprintf(buf, buflen, "%d.%d.%d", MAJOR_FRRVERSION(version),
		 MINOR_FRRVERSION(version), SUB_FRRVERSION(version));

	return buf;
}
