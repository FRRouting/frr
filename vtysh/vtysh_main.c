// SPDX-License-Identifier: GPL-2.0-or-later
/* Virtual terminal interface shell.
 * Copyright (C) 2000 Kunihiro Ishiguro
 */

#include <zebra.h>

#include <sys/un.h>
#include <setjmp.h>
#include <pwd.h>
#include <sys/file.h>
#include <unistd.h>

/* readline carries some ancient definitions around */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#include <readline/readline.h>
#include <readline/history.h>
#pragma GCC diagnostic pop

/*
 * The append_history function only appears in newer versions
 * of the readline library it appears like.  Since we don't
 * need this just silently ignore the code on these
 * ancient platforms.
 */
#if !defined HAVE_APPEND_HISTORY
#define append_history(A, B)
#endif

#include <lib/version.h>
#include "getopt.h"
#include "command.h"
#include "memory.h"
#include "linklist.h"
#include "libfrr.h"
#include "ferr.h"
#include "lib_errors.h"

#include "vtysh/vtysh.h"
#include "vtysh/vtysh_user.h"

/* VTY shell program name. */
char *progname;

/* SUID mode */
static uid_t elevuid, realuid;
static gid_t elevgid, realgid;

#define VTYSH_CONFIG_NAME "vtysh.conf"
#define FRR_CONFIG_NAME "frr.conf"

/* Configuration file name and directory. */
static char vtysh_config[MAXPATHLEN * 3];
char frr_config[MAXPATHLEN * 3];
char vtydir[MAXPATHLEN];
static char history_file[MAXPATHLEN];

/* Flag for indicate executing child command. */
int execute_flag = 0;

/* Flag to indicate if in user/unprivileged mode. */
int user_mode;

/* Master of threads. */
struct event_loop *master;

/* Command logging */
FILE *logfile;

static void vtysh_rl_callback(char *line_read)
{
	HIST_ENTRY *last;

	rl_callback_handler_remove();

	if (!line_read) {
		vtysh_loop_exited = true;
		return;
	}

	/* If the line has any text in it, save it on the history. But only if
	 * last command in history isn't the same one.
	 */
	if (*line_read) {
		using_history();
		last = previous_history();
		if (!last || strcmp(last->line, line_read) != 0) {
			add_history(line_read);
			append_history(1, history_file);
		}
	}

	vtysh_execute(line_read);

	if (!vtysh_loop_exited)
		rl_callback_handler_install(vtysh_prompt(), vtysh_rl_callback);

	free(line_read);
}

/* SIGTSTP handler.  This function care user's ^Z input. */
static void sigtstp(int sig)
{
	rl_callback_handler_remove();

	/* Execute "end" command. */
	vtysh_execute("end");

	if (!vtysh_loop_exited)
		rl_callback_handler_install(vtysh_prompt(), vtysh_rl_callback);

	/* Initialize readline. */
	rl_initialize();
	printf("\n");
	rl_forced_update_display();
}

/* SIGINT handler.  This function care user's ^Z input.  */
static void sigint(int sig)
{
	/* Check this process is not child process. */
	if (!execute_flag) {
		rl_initialize();
		printf("\n");
		rl_forced_update_display();
	}
}

/* Signale wrapper for vtysh. We don't use sigevent because
 * vtysh doesn't use threads. TODO */
static void vtysh_signal_set(int signo, void (*func)(int))
{
	struct sigaction sig;
	struct sigaction osig;

	sig.sa_handler = func;
	sigemptyset(&sig.sa_mask);
	sig.sa_flags = 0;
#ifdef SA_RESTART
	sig.sa_flags |= SA_RESTART;
#endif /* SA_RESTART */

	sigaction(signo, &sig, &osig);
}

/* Initialization of signal handles. */
static void vtysh_signal_init(void)
{
	vtysh_signal_set(SIGINT, sigint);
	vtysh_signal_set(SIGTSTP, sigtstp);
	vtysh_signal_set(SIGPIPE, SIG_IGN);
}

/* Help information display. */
static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			progname);
	else
		printf("Usage : %s [OPTION...]\n\n"
		       "Integrated shell for FRR (version " FRR_VERSION
		       "). \n"
		       "Configured with:\n    " FRR_CONFIG_ARGS
		       "\n\n"
		       "-b, --boot               Execute boot startup configuration\n"
		       "-c, --command            Execute argument as command\n"
		       "-d, --daemon             Connect only to the specified daemon\n"
		       "-f, --inputfile          Execute commands from specific file and exit\n"
		       "-E, --echo               Echo prompt and command in -c mode\n"
		       "-C, --dryrun             Check configuration for validity and exit\n"
		       "-m, --markfile           Mark input file with context end\n"
		       "    --vty_socket         Override vty socket path\n"
		       "    --config_dir         Override config directory path\n"
		       "-N  --pathspace          Insert prefix into config & socket paths\n"
		       "-u  --user               Run as an unprivileged user\n"
		       "-w, --writeconfig        Write integrated config (frr.conf) and exit\n"
		       "-H, --histfile           Override history file\n"
		       "-t, --timestamp          Print a timestamp before going to shell or reading the configuration\n"
		       "    --no-fork            Don't fork clients to handle daemons (slower for large configs)\n"
		       "-h, --help               Display this help and exit\n\n"
		       "Note that multiple commands may be executed from the command\n"
		       "line by passing multiple -c args, or by embedding linefeed\n"
		       "characters in one or more of the commands.\n\n"
		       "Report bugs to %s\n",
		       progname, FRR_BUG_ADDRESS);

	exit(status);
}

/* VTY shell options, we use GNU getopt library. */
#define OPTION_VTYSOCK 1000
#define OPTION_CONFDIR 1001
#define OPTION_NOFORK 1002
struct option longopts[] = {
	{"boot", no_argument, NULL, 'b'},
	/* For compatibility with older zebra/quagga versions */
	{"eval", required_argument, NULL, 'e'},
	{"command", required_argument, NULL, 'c'},
	{"daemon", required_argument, NULL, 'd'},
	{"vty_socket", required_argument, NULL, OPTION_VTYSOCK},
	{"config_dir", required_argument, NULL, OPTION_CONFDIR},
	{"inputfile", required_argument, NULL, 'f'},
	{"histfile", required_argument, NULL, 'H'},
	{"echo", no_argument, NULL, 'E'},
	{"dryrun", no_argument, NULL, 'C'},
	{"help", no_argument, NULL, 'h'},
	{"noerror", no_argument, NULL, 'n'},
	{"mark", no_argument, NULL, 'm'},
	{"writeconfig", no_argument, NULL, 'w'},
	{"pathspace", required_argument, NULL, 'N'},
	{"user", no_argument, NULL, 'u'},
	{"timestamp", no_argument, NULL, 't'},
	{"no-fork", no_argument, NULL, OPTION_NOFORK},
	{0}};

bool vtysh_loop_exited;

static struct event *vtysh_rl_read_thread;

static void vtysh_rl_read(struct event *thread)
{
	event_add_read(master, vtysh_rl_read, NULL, STDIN_FILENO,
		       &vtysh_rl_read_thread);
	rl_callback_read_char();
}

/* Read a string, and return a pointer to it.  Returns NULL on EOF. */
static void vtysh_rl_run(void)
{
	struct event thread;

	master = event_master_create(NULL);

	rl_callback_handler_install(vtysh_prompt(), vtysh_rl_callback);
	event_add_read(master, vtysh_rl_read, NULL, STDIN_FILENO,
		       &vtysh_rl_read_thread);

	while (!vtysh_loop_exited && event_fetch(master, &thread))
		event_call(&thread);

	if (!vtysh_loop_exited)
		rl_callback_handler_remove();

	event_master_free(master);
}

static void log_it(const char *line)
{
	time_t t = time(NULL);
	struct tm tmp;
	const char *user = getenv("USER");
	char tod[64];

	localtime_r(&t, &tmp);
	if (!user)
		user = "boot";

	strftime(tod, sizeof(tod), "%Y%m%d-%H:%M.%S", &tmp);

	fprintf(logfile, "%s:%s %s\n", tod, user, line);
}

static int flock_fd;

static void vtysh_flock_config(const char *flock_file)
{
	int count = 0;

	flock_fd = open(flock_file, O_RDONLY, 0644);
	if (flock_fd < 0) {
		fprintf(stderr, "Unable to create lock file: %s, %s\n",
			flock_file, safe_strerror(errno));
		return;
	}

	while (count < 400 && (flock(flock_fd, LOCK_EX | LOCK_NB) < 0)) {
		count++;
		usleep(500000);
	}

	if (count >= 400)
		fprintf(stderr,
			"Flock of %s failed, continuing this may cause issues\n",
			flock_file);
}

static void vtysh_unflock_config(void)
{
	flock(flock_fd, LOCK_UN);
	close(flock_fd);
}

void suid_on(void)
{
	if (elevuid != realuid && seteuid(elevuid)) {
		perror("seteuid(on)");
		exit(1);
	}
	if (elevgid != realgid && setegid(elevgid)) {
		perror("setegid(on)");
		exit(1);
	}
}

void suid_off(void)
{
	if (elevuid != realuid && seteuid(realuid)) {
		perror("seteuid(off)");
		exit(1);
	}
	if (elevgid != realgid && setegid(realgid)) {
		perror("setegid(off)");
		exit(1);
	}
}

/* VTY shell main routine. */
int main(int argc, char **argv, char **env)
{
	char *p;
	int opt;
	int dryrun = 0;
	int boot_flag = 0;
	bool ts_flag = false;
	bool no_fork = false;
	const char *daemon_name = NULL;
	const char *inputfile = NULL;
	struct cmd_rec {
		char *line;
		struct cmd_rec *next;
	} *cmd = NULL;
	struct cmd_rec *tail = NULL;
	int echo_command = 0;
	int no_error = 0;
	int markfile = 0;
	int writeconfig = 0;
	int ret = 0;
	char *homedir = NULL;
	int ditch_suid = 0;
	char sysconfdir[MAXPATHLEN];
	const char *pathspace_arg = NULL;
	char pathspace[MAXPATHLEN] = "";
	const char *histfile = NULL;
	const char *histfile_env = getenv("VTYSH_HISTFILE");

	/* SUID: drop down to calling user & go back up when needed */
	elevuid = geteuid();
	elevgid = getegid();
	realuid = getuid();
	realgid = getgid();
	suid_off();

	user_mode = 0;		/* may be set in options processing */

	/* Preserve name of myself. */
	progname = ((p = strrchr(argv[0], '/')) ? ++p : argv[0]);

	strlcpy(sysconfdir, frr_sysconfdir, sizeof(sysconfdir));

	frr_init_vtydir();
	strlcpy(vtydir, frr_vtydir, sizeof(vtydir));

	/* Option handling. */
	while (1) {
		opt = getopt_long(argc, argv, "be:c:d:nf:H:mEhCwN:ut", longopts,
				  0);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		case 'b':
			boot_flag = 1;
			break;
		case 'e':
		case 'c': {
			struct cmd_rec *cr;
			cr = XMALLOC(MTYPE_TMP, sizeof(*cr));
			cr->line = optarg;
			cr->next = NULL;
			if (tail)
				tail->next = cr;
			else
				cmd = cr;
			tail = cr;
		} break;
		case OPTION_VTYSOCK:
			ditch_suid = 1; /* option disables SUID */
			strlcpy(vtydir, optarg, sizeof(vtydir));
			break;
		case OPTION_CONFDIR:
			ditch_suid = 1; /* option disables SUID */
			snprintf(sysconfdir, sizeof(sysconfdir), "%s/", optarg);
			break;
		case OPTION_NOFORK:
			no_fork = true;
			break;
		case 'N':
			if (strchr(optarg, '/') || strchr(optarg, '.')) {
				fprintf(stderr,
					"slashes or dots are not permitted in the --pathspace option.\n");
				exit(1);
			}
			pathspace_arg = optarg;
			snprintf(pathspace, sizeof(pathspace), "%s/", optarg);
			break;
		case 'd':
			daemon_name = optarg;
			break;
		case 'f':
			inputfile = optarg;
			break;
		case 'm':
			markfile = 1;
			break;
		case 'n':
			no_error = 1;
			break;
		case 'E':
			echo_command = 1;
			break;
		case 'C':
			dryrun = 1;
			break;
		case 'u':
			user_mode = 1;
			break;
		case 't':
			ts_flag = true;
			break;
		case 'w':
			writeconfig = 1;
			break;
		case 'h':
			usage(0);
			break;
		case 'H':
			histfile = optarg;
			break;
		default:
			usage(1);
			break;
		}
	}

	/* No need for forks if we're talking to 1 daemon */
	if (daemon_name)
		no_fork = true;

	if (ditch_suid) {
		elevuid = realuid;
		elevgid = realgid;
	}

	if (markfile + writeconfig + dryrun + boot_flag > 1) {
		fprintf(stderr,
			"Invalid combination of arguments.  Please specify at most one of:\n\t-b, -C, -m, -w\n");
		return 1;
	}
	if (inputfile && (writeconfig || boot_flag)) {
		fprintf(stderr,
			"WARNING: Combining the -f option with -b or -w is NOT SUPPORTED since its\nresults are inconsistent!\n");
	}

	snprintf(vtysh_config, sizeof(vtysh_config), "%s%s%s", sysconfdir,
		 pathspace, VTYSH_CONFIG_NAME);
	snprintf(frr_config, sizeof(frr_config), "%s%s%s", sysconfdir,
		 pathspace, FRR_CONFIG_NAME);

	if (pathspace_arg) {
		strlcat(vtydir, "/", sizeof(vtydir));
		strlcat(vtydir, pathspace_arg, sizeof(vtydir));
	}

	/* Initialize user input buffer. */
	setlinebuf(stdout);

	/* Signal and others. */
	vtysh_signal_init();

	/* Make vty structure and register commands. */
	vtysh_init_vty();
	vtysh_init_cmd();
	vtysh_user_init();
	vtysh_config_init();

	vty_init_vtysh();

	if (!user_mode) {
		/* Read vtysh configuration file before connecting to daemons.
		 * (file may not be readable to calling user in SUID mode) */
		suid_on();
		vtysh_apply_config(vtysh_config, dryrun, false);
		suid_off();
	}
	/* Error code library system */
	log_ref_init();
	lib_error_init();

	if (markfile) {
		if (!inputfile) {
			fprintf(stderr,
				"-f option MUST be specified with -m option\n");
			return 1;
		}
		return (vtysh_mark_file(inputfile));
	}

	/* Start execution only if not in dry-run mode */
	if (dryrun && !cmd) {
		if (inputfile) {
			ret = vtysh_apply_config(inputfile, dryrun, false);
		} else {
			ret = vtysh_apply_config(frr_config, dryrun, false);
		}

		exit(ret);
	}

	if (dryrun && cmd && cmd->line) {
		if (!user_mode)
			vtysh_execute("enable");
		while (cmd) {
			struct cmd_rec *cr;
			char *cmdnow = cmd->line, *next;
			do {
				next = strchr(cmdnow, '\n');
				if (next)
					*next++ = '\0';

				if (echo_command)
					printf("%s%s\n", vtysh_prompt(),
					       cmdnow);

				ret = vtysh_execute_no_pager(cmdnow);
				if (!no_error
				    && !(ret == CMD_SUCCESS
					 || ret == CMD_SUCCESS_DAEMON
					 || ret == CMD_WARNING))
					exit(1);
			} while ((cmdnow = next) != NULL);

			cr = cmd;
			cmd = cmd->next;
			XFREE(MTYPE_TMP, cr);
		}
		exit(ret);
	}

	/* Ignore error messages */
	if (no_error) {
		if (freopen("/dev/null", "w", stdout) == NULL) {
			fprintf(stderr,
				"Exiting: Failed to duplicate stdout with -n option");
			exit(1);
		}
	}

	/* SUID: go back up elevated privs */
	suid_on();

	/* Make sure we pass authentication before proceeding. */
	vtysh_auth();

	/* Do not connect until we have passed authentication. */
	if (vtysh_connect_all(daemon_name) <= 0) {
		fprintf(stderr, "Exiting: failed to connect to any daemons.\n");
		if (geteuid() != 0)
			fprintf(stderr,
				"Hint: if this seems wrong, try running me as a privileged user!\n");
		if (no_error)
			exit(0);
		else
			exit(1);
	}

	/* SUID: back down, don't need privs further on */
	suid_off();

	if (writeconfig) {
		if (user_mode) {
			fprintf(stderr,
				"writeconfig cannot be used when running as an unprivileged user.\n");
			if (no_error)
				exit(0);
			else
				exit(1);
		}
		vtysh_execute("enable");
		return vtysh_write_config_integrated();
	}

	if (boot_flag)
		inputfile = frr_config;

	if (inputfile || boot_flag) {
		vtysh_flock_config(inputfile);
		ret = vtysh_apply_config(inputfile, dryrun, !no_fork);
		vtysh_unflock_config();

		if (no_error)
			ret = 0;

		exit(ret);
	}

	/*
	 * Setup history file for use by both -c and regular input
	 * If we can't find the home directory, then don't store
	 * the history information.
	 * VTYSH_HISTFILE is preferred over command line
	 * argument (-H/--histfile).
	 */
	if (histfile_env) {
		strlcpy(history_file, histfile_env, sizeof(history_file));
	} else if (histfile) {
		strlcpy(history_file, histfile, sizeof(history_file));
	} else {
		homedir = vtysh_get_home();
		if (homedir)
			snprintf(history_file, sizeof(history_file),
				 "%s/.history_frr", homedir);
	}

	if (strlen(history_file) > 0) {
		if (read_history(history_file) != 0) {
			int fp;

			fp = open(history_file, O_CREAT | O_EXCL,
				  S_IRUSR | S_IWUSR);
			if (fp != -1)
				close(fp);

			read_history(history_file);
		}
	}

	if (getenv("VTYSH_LOG")) {
		const char *logpath = getenv("VTYSH_LOG");

		logfile = fopen(logpath, "a");
		if (!logfile) {
			fprintf(stderr, "Failed to open logfile (%s): %s\n",
				logpath, strerror(errno));
			exit(1);
		}
	}

	/* If eval mode. */
	if (cmd && cmd->line) {
		/* Enter into enable node. */
		if (!user_mode)
			vtysh_execute("enable");

		vtysh_add_timestamp = ts_flag;

		while (cmd != NULL) {
			char *eol;

			while ((eol = strchr(cmd->line, '\n')) != NULL) {
				*eol = '\0';

				add_history(cmd->line);
				append_history(1, history_file);

				if (echo_command)
					printf("%s%s\n", vtysh_prompt(),
					       cmd->line);

				if (logfile)
					log_it(cmd->line);

				ret = vtysh_execute_no_pager(cmd->line);
				if (!no_error
				    && !(ret == CMD_SUCCESS
					 || ret == CMD_SUCCESS_DAEMON
					 || ret == CMD_WARNING))
					exit(1);

				cmd->line = eol + 1;
			}

			add_history(cmd->line);
			append_history(1, history_file);

			if (echo_command)
				printf("%s%s\n", vtysh_prompt(), cmd->line);

			if (logfile)
				log_it(cmd->line);

			/*
			 * Parsing logic for regular commands will be different
			 * than for those commands requiring further
			 * processing, such as cli instructions terminating
			 * with question-mark character.
			 */
			if (!vtysh_execute_command_questionmark(cmd->line))
				ret = CMD_SUCCESS;
			else
				ret = vtysh_execute_no_pager(cmd->line);

			if (!no_error
			    && !(ret == CMD_SUCCESS || ret == CMD_SUCCESS_DAEMON
				 || ret == CMD_WARNING))
				exit(1);

			{
				struct cmd_rec *cr;
				cr = cmd;
				cmd = cmd->next;
				XFREE(MTYPE_TMP, cr);
			}
		}

		history_truncate_file(history_file, 1000);
		exit(0);
	}

	vtysh_readline_init();

	vty_hello(vty);

	/* Enter into enable node. */
	if (!user_mode)
		vtysh_execute("enable");

	vtysh_add_timestamp = ts_flag;

	/* Main command loop. */
	vtysh_rl_run();

	vtysh_uninit();

	history_truncate_file(history_file, 1000);
	printf("\n");

	/* Rest in peace. */
	exit(0);
}
