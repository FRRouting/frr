// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Monitor status of frr daemons and restart if necessary.
 *
 * Copyright (C) 2004  Andrew J. Schorr
 */

#include <zebra.h>
#include "frrevent.h"
#include <log.h>
#include <network.h>
#include <sigevent.h>
#include <lib/version.h>
#include "command.h"
#include "libfrr.h"
#include "lib_errors.h"
#include "zlog_targets.h"
#include "network.h"
#include "printfrr.h"

#include <getopt.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <memory.h>
#include <systemd.h>

#include "watchfrr.h"
#include "watchfrr_errors.h"

#ifndef MIN
#define MIN(X,Y) (((X) <= (Y)) ? (X) : (Y))
#endif

/* Macros to help randomize timers. */
#define JITTER(X) ((frr_weak_random() % ((X)+1))-((X)/2))
#define FUZZY(X) ((X)+JITTER((X)/20))

#define DEFAULT_PERIOD		5
#define DEFAULT_TIMEOUT		90
#define DEFAULT_RESTART_TIMEOUT	20
#define DEFAULT_LOGLEVEL	LOG_INFO
#define DEFAULT_MIN_RESTART	60
#define DEFAULT_MAX_RESTART	600
#define DEFAULT_OPERATIONAL_TIMEOUT 60

#define DEFAULT_RESTART_CMD	WATCHFRR_SH_PATH " restart %s"
#define DEFAULT_START_CMD	WATCHFRR_SH_PATH " start %s"
#define DEFAULT_STOP_CMD	WATCHFRR_SH_PATH " stop %s"

#define PING_TOKEN	"PING"

DEFINE_MGROUP(WATCHFRR, "watchfrr");
DEFINE_MTYPE_STATIC(WATCHFRR, WATCHFRR_DAEMON, "watchfrr daemon entry");

/* Needs to be global, referenced somewhere inside libfrr. */
struct event_loop *master;

static bool watch_only = false;
const char *pathspace;

enum restart_phase {
	PHASE_NONE = 0,
	PHASE_INIT,
	PHASE_STOPS_PENDING,
	PHASE_WAITING_DOWN,
	PHASE_ZEBRA_RESTART_PENDING,
	PHASE_WAITING_ZEBRA_UP
};

static const char *const phase_str[] = {
	"Idle",
	"Startup",
	"Stop jobs running",
	"Waiting for other daemons to come down",
	"Zebra restart job running",
	"Waiting for zebra to come up",
	"Start jobs running",
};

#define PHASE_TIMEOUT (3*gs.restart_timeout)
#define STARTUP_TIMEOUT	55 * 1000

struct restart_info {
	const char *name;
	const char *what;
	pid_t pid;
	struct timeval time;
	long interval;
	struct event *t_kill;
	int kills;
};

static struct global_state {
	enum restart_phase phase;
	struct event *t_phase_hanging;
	struct event *t_startup_timeout;
	struct event *t_operational;
	const char *vtydir;
	long period;
	long timeout;
	long restart_timeout;
	bool reading_configuration;
	long min_restart_interval;
	long max_restart_interval;
	long operational_timeout;
	struct daemon *daemons;
	const char *restart_command;
	const char *start_command;
	const char *stop_command;
	struct restart_info restart;
	int loglevel;
	struct daemon *special; /* points to zebra when doing phased restart */
	int numdaemons;
	int numpids;
	int numdown; /* # of daemons that are not UP or UNRESPONSIVE */
} gs = {
	.phase = PHASE_INIT,
	.vtydir = frr_vtydir,
	.period = 1000 * DEFAULT_PERIOD,
	.timeout = DEFAULT_TIMEOUT,
	.restart_timeout = DEFAULT_RESTART_TIMEOUT,
	.loglevel = DEFAULT_LOGLEVEL,
	.min_restart_interval = DEFAULT_MIN_RESTART,
	.max_restart_interval = DEFAULT_MAX_RESTART,
	.operational_timeout = DEFAULT_OPERATIONAL_TIMEOUT,
	.restart_command = DEFAULT_RESTART_CMD,
	.start_command = DEFAULT_START_CMD,
	.stop_command = DEFAULT_STOP_CMD,
};

enum daemon_state {
	DAEMON_INIT,
	DAEMON_DOWN,
	DAEMON_CONNECTING,
	DAEMON_UP,
	DAEMON_UNRESPONSIVE
};

#define IS_UP(DMN)                                                             \
	(((DMN)->state == DAEMON_UP) || ((DMN)->state == DAEMON_UNRESPONSIVE))

static const char *const state_str[] = {
	"Init", "Down", "Connecting", "Up", "Unresponsive",
};

struct daemon {
	const char *name;
	enum daemon_state state;
	int fd;
	struct timeval echo_sent;
	unsigned int connect_tries;
	struct event *t_wakeup;
	struct event *t_read;
	struct event *t_write;
	struct daemon *next;
	struct restart_info restart;

	/*
	 * For a given daemon, if we've turned on ignore timeouts
	 * ignore the timeout value and assume everything is ok
	 * This is for daemon debugging w/ gdb after we have started
	 * FRR and realize we have something that needs to be looked
	 * at
	 */
	bool ignore_timeout;
};

#define OPTION_MINRESTART 2000
#define OPTION_MAXRESTART 2001
#define OPTION_DRY        2002
#define OPTION_NETNS      2003
#define OPTION_MAXOPERATIONAL 2004

static const struct option longopts[] = {
	{"daemon", no_argument, NULL, 'd'},
	{"statedir", required_argument, NULL, 'S'},
	{"loglevel", required_argument, NULL, 'l'},
	{"interval", required_argument, NULL, 'i'},
	{"timeout", required_argument, NULL, 't'},
	{"restart-timeout", required_argument, NULL, 'T'},
	{"restart", required_argument, NULL, 'r'},
	{"start-command", required_argument, NULL, 's'},
	{"kill-command", required_argument, NULL, 'k'},
	{"dry", no_argument, NULL, OPTION_DRY},
	{"min-restart-interval", required_argument, NULL, OPTION_MINRESTART},
	{"max-restart-interval", required_argument, NULL, OPTION_MAXRESTART},
	{"operational-timeout", required_argument, NULL, OPTION_MAXOPERATIONAL},
	{"pid-file", required_argument, NULL, 'p'},
	{"blank-string", required_argument, NULL, 'b'},
#ifdef GNU_LINUX
	{"netns", optional_argument, NULL, OPTION_NETNS},
#endif
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{NULL, 0, NULL, 0}};

static int try_connect(struct daemon *dmn);
static void wakeup_send_echo(struct event *t_wakeup);
static void try_restart(struct daemon *dmn);
static void phase_check(void);
static void restart_done(struct daemon *dmn);

static const char *progname;

void watchfrr_set_ignore_daemon(struct vty *vty, const char *dname, bool ignore)
{
	struct daemon *dmn;

	for (dmn = gs.daemons; dmn; dmn = dmn->next) {
		if (strncmp(dmn->name, dname, strlen(dmn->name)) == 0)
			break;
	}

	if (dmn) {
		dmn->ignore_timeout = ignore;
		vty_out(vty, "%s switching to %s\n", dmn->name,
			ignore ? "ignore" : "watch");
	} else
		vty_out(vty, "%s is not configured for running at the moment",
			dname);
}

static void printhelp(FILE *target)
{
	fprintf(target,
		"Usage : %s [OPTION...] <daemon name> ...\n\n\
Watchdog program to monitor status of frr daemons and try to restart\n\
them if they are down or unresponsive.  It determines whether a daemon is\n\
up based on whether it can connect to the daemon's vty unix stream socket.\n\
It then repeatedly sends echo commands over that socket to determine whether\n\
the daemon is responsive.  If the daemon crashes, we will receive an EOF\n\
on the socket connection and know immediately that the daemon is down.\n\n\
The daemons to be monitored should be listed on the command line.\n\n\
In order to avoid attempting to restart the daemons in a fast loop,\n\
the -m and -M options allow you to control the minimum delay between\n\
restart commands.  The minimum restart delay is recalculated each time\n\
a restart is attempted: if the time since the last restart attempt exceeds\n\
twice the -M value, then the restart delay is set to the -m value.\n\
Otherwise, the interval is doubled (but capped at the -M value).\n\n",
		progname);

	fprintf(target,
		"Options:\n\
-d, --daemon	Run in daemon mode.  In this mode, error messages are sent\n\
		to syslog instead of stdout.\n\
-S, --statedir	Set the vty socket directory (default is %s)\n\
-N, --pathspace	Insert prefix into config & socket paths\n"
#ifdef GNU_LINUX
"    --netns	Create and/or use Linux network namespace.  If no name is\n"
"		given, uses the value from `-N`.\n"
#endif
"-l, --loglevel	Set the logging level (default is %d).\n\
		The value should range from %d (LOG_EMERG) to %d (LOG_DEBUG),\n\
		but it can be set higher than %d if extra-verbose debugging\n\
		messages are desired.\n\
    --min-restart-interval\n\
		Set the minimum seconds to wait between invocations of daemon\n\
		restart commands (default is %d).\n\
    --max-restart-interval\n\
		Set the maximum seconds to wait between invocations of daemon\n\
		restart commands (default is %d).\n\
    --operational-timeout\n\
                Set the time before systemd is notified that we are considered\n\
                operational again after a daemon restart (default is %d).\n\
-i, --interval	Set the status polling interval in seconds (default is %d)\n\
-t, --timeout	Set the unresponsiveness timeout in seconds (default is %d)\n\
-T, --restart-timeout\n\
		Set the restart (kill) timeout in seconds (default is %d).\n\
		If any background jobs are still running after this much\n\
		time has elapsed, they will be killed.\n\
-r, --restart	Supply a Bourne shell command to use to restart a single\n\
		daemon.  The command string should include '%%s' where the\n\
		name of the daemon should be substituted.\n\
		(default: '%s')\n\
-s, --start-command\n\
		Supply a Bourne shell to command to use to start a single\n\
		daemon.  The command string should include '%%s' where the\n\
		name of the daemon should be substituted.\n\
		(default: '%s')\n\
-k, --kill-command\n\
		Supply a Bourne shell to command to use to stop a single\n\
		daemon.  The command string should include '%%s' where the\n\
		name of the daemon should be substituted.\n\
		(default: '%s')\n\
    --dry	Do not start or restart anything, just log.\n\
-p, --pid-file	Set process identifier file name\n\
		(default is %s/watchfrr.pid).\n\
-b, --blank-string\n\
		When the supplied argument string is found in any of the\n\
		various shell command arguments (-r, -s, or -k), replace\n\
		it with a space.  This is an ugly hack to circumvent problems\n\
		passing command-line arguments with embedded spaces.\n\
-v, --version	Print program version\n\
-h, --help	Display this help and exit\n",
		frr_vtydir, DEFAULT_LOGLEVEL, LOG_EMERG, LOG_DEBUG, LOG_DEBUG,
		DEFAULT_MIN_RESTART, DEFAULT_MAX_RESTART,
		DEFAULT_OPERATIONAL_TIMEOUT, DEFAULT_PERIOD, DEFAULT_TIMEOUT,
		DEFAULT_RESTART_TIMEOUT, DEFAULT_RESTART_CMD, DEFAULT_START_CMD,
		DEFAULT_STOP_CMD, frr_vtydir);
}

static pid_t run_background(char *shell_cmd)
{
	pid_t child;

	switch (child = fork()) {
	case -1:
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "fork failed, cannot run command [%s]: %s",
			     shell_cmd, safe_strerror(errno));
		return -1;
	case 0:
		/* Child process. */
		/* Use separate process group so child processes can be killed
		 * easily. */
		if (setpgid(0, 0) < 0)
			zlog_warn("setpgid(0,0) failed: %s",
				  safe_strerror(errno));
		{
			char shell[] = "sh";
			char dashc[] = "-c";
			char *const argv[4] = {shell, dashc, shell_cmd, NULL};
			execv("/bin/sh", argv);
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "execv(/bin/sh -c '%s') failed: %s",
				     shell_cmd, safe_strerror(errno));
			_exit(127);
		}
	default:
		/* Parent process: we will reap the child later. */
		zlog_info("Forked background command [pid %d]: %s", (int)child,
			  shell_cmd);
		return child;
	}
}

static struct timeval *time_elapsed(struct timeval *result,
				    const struct timeval *start_time)
{
	gettimeofday(result, NULL);
	result->tv_sec -= start_time->tv_sec;
	result->tv_usec -= start_time->tv_usec;
	while (result->tv_usec < 0) {
		result->tv_usec += 1000000L;
		result->tv_sec--;
	}
	return result;
}

static void restart_kill(struct event *t_kill)
{
	struct restart_info *restart = EVENT_ARG(t_kill);
	struct timeval delay;

	time_elapsed(&delay, &restart->time);

	if (gs.reading_configuration) {
		zlog_err(
			"%s %s child process appears to still be reading configuration, delaying for another %lu time",
			restart->what, restart->name, gs.restart_timeout);
		event_add_timer(master, restart_kill, restart,
				gs.restart_timeout, &restart->t_kill);
		return;
	}

	zlog_warn(
		"%s %s child process %d still running after %ld seconds, sending signal %d",
		restart->what, restart->name, (int)restart->pid,
		(long)delay.tv_sec, (restart->kills ? SIGKILL : SIGTERM));
	kill(-restart->pid, (restart->kills ? SIGKILL : SIGTERM));
	restart->kills++;
	event_add_timer(master, restart_kill, restart, gs.restart_timeout,
			&restart->t_kill);
}

static struct restart_info *find_child(pid_t child)
{
	struct daemon *dmn;
	if (gs.restart.pid == child)
		return &gs.restart;

	for (dmn = gs.daemons; dmn; dmn = dmn->next) {
		if (dmn->restart.pid == child)
			return &dmn->restart;
	}
	return NULL;
}

static void sigchild(void)
{
	pid_t child;
	int status;
	const char *name;
	const char *what;
	struct restart_info *restart;
	struct daemon *dmn;

	switch (child = waitpid(-1, &status, WNOHANG)) {
	case -1:
		flog_err_sys(EC_LIB_SYSTEM_CALL, "waitpid failed: %s",
			     safe_strerror(errno));
		return;
	case 0:
		zlog_warn("SIGCHLD received, but waitpid did not reap a child");
		return;
	}

	if (child == integrated_write_pid) {
		integrated_write_sigchld(status);
		return;
	}

	if ((restart = find_child(child)) != NULL) {
		name = restart->name;
		what = restart->what;
		restart->pid = 0;
		gs.numpids--;
		event_cancel(&restart->t_kill);

		/* Update restart time to reflect the time the command
		 * completed. */
		gettimeofday(&restart->time, NULL);
	} else {
		flog_err_sys(
			EC_LIB_SYSTEM_CALL,
			"waitpid returned status for an unknown child process %d",
			(int)child);
		name = "(unknown)";
		what = "background";
	}
	if (WIFSTOPPED(status))
		zlog_warn("%s %s process %d is stopped", what, name,
			  (int)child);
	else if (WIFSIGNALED(status))
		zlog_warn("%s %s process %d terminated due to signal %d", what,
			  name, (int)child, WTERMSIG(status));
	else if (WIFEXITED(status)) {
		if (WEXITSTATUS(status) != 0)
			zlog_warn(
				"%s %s process %d exited with non-zero status %d",
				what, name, (int)child, WEXITSTATUS(status));
		else {
			zlog_debug("%s %s process %d exited normally", what,
				   name, (int)child);

			if (restart && restart != &gs.restart) {
				dmn = container_of(restart, struct daemon,
						   restart);
				restart_done(dmn);
			} else if (restart)
				for (dmn = gs.daemons; dmn; dmn = dmn->next)
					restart_done(dmn);
		}
	} else
		flog_err_sys(
			EC_LIB_SYSTEM_CALL,
			"cannot interpret %s %s process %d wait status 0x%x",
			what, name, (int)child, status);
	phase_check();
}

static int run_job(struct restart_info *restart, const char *cmdtype,
		   const char *command, int force, int update_interval)
{
	struct timeval delay;

	if (gs.loglevel > LOG_DEBUG + 1)
		zlog_debug("attempting to %s %s", cmdtype, restart->name);

	if (restart->pid) {
		if (gs.loglevel > LOG_DEBUG + 1)
			zlog_debug(
				"cannot %s %s, previous pid %d still running",
				cmdtype, restart->name, (int)restart->pid);
		return -1;
	}

	char buffer[512];

	snprintf(buffer, sizeof(buffer), "restarting %s", restart->name);
	systemd_send_status(buffer);

	/* Note: time_elapsed test must come before the force test, since we
	   need
	   to make sure that delay is initialized for use below in updating the
	   restart interval. */
	if ((time_elapsed(&delay, &restart->time)->tv_sec < restart->interval)
	    && !force) {

		if (gs.loglevel > LOG_DEBUG + 1)
			zlog_debug(
				"postponing %s %s: elapsed time %ld < retry interval %ld",
				cmdtype, restart->name, (long)delay.tv_sec,
				restart->interval);
		return -1;
	}

	gettimeofday(&restart->time, NULL);
	restart->kills = 0;
	{
		char cmd[strlen(command) + strlen(restart->name) + 1];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
		/* user supplied command string has a %s for the daemon name */
		snprintf(cmd, sizeof(cmd), command, restart->name);
#pragma GCC diagnostic pop
		if ((restart->pid = run_background(cmd)) > 0) {
			event_add_timer(master, restart_kill, restart,
					gs.restart_timeout, &restart->t_kill);
			restart->what = cmdtype;
			gs.numpids++;
		} else
			restart->pid = 0;
	}

	/* Calculate the new restart interval. */
	if (update_interval) {
		if (delay.tv_sec > 2 * gs.max_restart_interval)
			restart->interval = gs.min_restart_interval;
		else if ((restart->interval *= 2) > gs.max_restart_interval)
			restart->interval = gs.max_restart_interval;
		if (gs.loglevel > LOG_DEBUG + 1)
			zlog_debug("restart %s interval is now %ld",
				   restart->name, restart->interval);
	}
	return restart->pid;
}

#define SET_READ_HANDLER(DMN)                                                  \
	do {                                                                   \
		(DMN)->t_read = NULL;                                          \
		event_add_read(master, handle_read, (DMN), (DMN)->fd,          \
			       &(DMN)->t_read);                                \
	} while (0);

#define SET_WAKEUP_DOWN(DMN)                                                   \
	do {                                                                   \
		(DMN)->t_wakeup = NULL;                                        \
		event_add_timer_msec(master, wakeup_down, (DMN),               \
				     FUZZY(gs.period), &(DMN)->t_wakeup);      \
	} while (0);

#define SET_WAKEUP_UNRESPONSIVE(DMN)                                           \
	do {                                                                   \
		(DMN)->t_wakeup = NULL;                                        \
		event_add_timer_msec(master, wakeup_unresponsive, (DMN),       \
				     FUZZY(gs.period), &(DMN)->t_wakeup);      \
	} while (0);

#define SET_WAKEUP_ECHO(DMN)                                                   \
	do {                                                                   \
		(DMN)->t_wakeup = NULL;                                        \
		event_add_timer_msec(master, wakeup_send_echo, (DMN),          \
				     FUZZY(gs.period), &(DMN)->t_wakeup);      \
	} while (0);

static void wakeup_down(struct event *t_wakeup)
{
	struct daemon *dmn = EVENT_ARG(t_wakeup);

	dmn->t_wakeup = NULL;
	if (try_connect(dmn) < 0)
		SET_WAKEUP_DOWN(dmn);
	if ((dmn->connect_tries > 1) && (dmn->state != DAEMON_UP))
		try_restart(dmn);
}

static void wakeup_init(struct event *t_wakeup)
{
	struct daemon *dmn = EVENT_ARG(t_wakeup);

	dmn->t_wakeup = NULL;
	if (try_connect(dmn) < 0) {
		zlog_info(
			"%s state -> down : initial connection attempt failed",
			dmn->name);
		dmn->state = DAEMON_DOWN;
	}
	phase_check();
}

static void restart_done(struct daemon *dmn)
{
	if (dmn->state != DAEMON_DOWN) {
		zlog_warn(
			"Daemon: %s: is in %s state but expected it to be in DAEMON_DOWN state",
			dmn->name, state_str[dmn->state]);
		return;
	}
	EVENT_OFF(dmn->t_wakeup);

	if (try_connect(dmn) < 0)
		SET_WAKEUP_DOWN(dmn);
}

static void daemon_restarting_operational(struct event *thread)
{
	systemd_send_status("FRR Operational");
}

static void daemon_down(struct daemon *dmn, const char *why)
{
	if (IS_UP(dmn) || (dmn->state == DAEMON_INIT))
		flog_err(EC_WATCHFRR_CONNECTION, "%s state -> down : %s",
			 dmn->name, why);
	else if (gs.loglevel > LOG_DEBUG)
		zlog_debug("%s still down : %s", dmn->name, why);
	if (IS_UP(dmn))
		gs.numdown++;
	dmn->state = DAEMON_DOWN;
	if (dmn->fd >= 0) {
		close(dmn->fd);
		dmn->fd = -1;
	}
	EVENT_OFF(dmn->t_read);
	EVENT_OFF(dmn->t_write);
	EVENT_OFF(dmn->t_wakeup);
	if (try_connect(dmn) < 0)
		SET_WAKEUP_DOWN(dmn);

	systemd_send_status("FRR partially operational");
	phase_check();
}

static void handle_read(struct event *t_read)
{
	struct daemon *dmn = EVENT_ARG(t_read);
	static const char resp[sizeof(PING_TOKEN) + 4] = PING_TOKEN "\n";
	char buf[sizeof(resp) + 100];
	ssize_t rc;
	struct timeval delay;

	dmn->t_read = NULL;
	if ((rc = read(dmn->fd, buf, sizeof(buf))) < 0) {
		char why[100];

		if (ERRNO_IO_RETRY(errno)) {
			/* Pretend it never happened. */
			SET_READ_HANDLER(dmn);
			return;
		}
		snprintf(why, sizeof(why), "unexpected read error: %s",
			 safe_strerror(errno));
		daemon_down(dmn, why);
		return;
	}
	if (rc == 0) {
		daemon_down(dmn, "read returned EOF");
		return;
	}
	if (!dmn->echo_sent.tv_sec) {
		char why[sizeof(buf) + 100];
		snprintf(why, sizeof(why),
			 "unexpected read returns %d bytes: %.*s", (int)rc,
			 (int)rc, buf);
		daemon_down(dmn, why);
		return;
	}

	/* We are expecting an echo response: is there any chance that the
	   response would not be returned entirely in the first read?  That
	   seems inconceivable... */
	if ((rc != sizeof(resp)) || memcmp(buf, resp, sizeof(resp))) {
		char why[100 + sizeof(buf)];
		snprintf(why, sizeof(why),
			 "read returned bad echo response of %d bytes (expecting %u): %.*s",
			 (int)rc, (unsigned int)sizeof(resp), (int)rc, buf);
		daemon_down(dmn, why);
		return;
	}

	time_elapsed(&delay, &dmn->echo_sent);
	dmn->echo_sent.tv_sec = 0;
	if (dmn->state == DAEMON_UNRESPONSIVE) {
		if (delay.tv_sec < gs.timeout) {
			dmn->state = DAEMON_UP;
			zlog_warn(
				"%s state -> up : echo response received after %ld.%06ld seconds",
				dmn->name, (long)delay.tv_sec,
				(long)delay.tv_usec);
		} else
			zlog_warn(
				"%s: slow echo response finally received after %ld.%06ld seconds",
				dmn->name, (long)delay.tv_sec,
				(long)delay.tv_usec);
	} else if (gs.loglevel > LOG_DEBUG + 1)
		zlog_debug("%s: echo response received after %ld.%06ld seconds",
			   dmn->name, (long)delay.tv_sec, (long)delay.tv_usec);

	SET_READ_HANDLER(dmn);
	event_cancel(&dmn->t_wakeup);
	SET_WAKEUP_ECHO(dmn);
}

/*
 * Wait till we notice that all daemons are ready before
 * we send we are ready to systemd
 */
static void daemon_send_ready(int exitcode)
{
	FILE *fp;
	static int sent = 0;
	char started[1024];

	if (sent)
		return;

	if (exitcode == 0)
		zlog_notice("all daemons up, doing startup-complete notify");
	else if (gs.numdown < gs.numdaemons)
		flog_err(EC_WATCHFRR_CONNECTION,
			 "startup did not complete within timeout (%d/%d daemons running)",
			 gs.numdaemons - gs.numdown, gs.numdaemons);
	else {
		flog_err(EC_WATCHFRR_CONNECTION,
			 "all configured daemons failed to start -- exiting watchfrr");
		exit(exitcode);

	}

	frr_detach();

	snprintf(started, sizeof(started), "%s/%s", frr_vtydir,
		 "watchfrr.started");
	fp = fopen(started, "w");
	if (fp)
		fclose(fp);

	systemd_send_started(master);
	systemd_send_status("FRR Operational");
	sent = 1;
}

static void daemon_up(struct daemon *dmn, const char *why)
{
	dmn->state = DAEMON_UP;
	gs.numdown--;
	dmn->connect_tries = 0;
	zlog_notice("%s state -> up : %s", dmn->name, why);
	if (gs.numdown == 0) {
		daemon_send_ready(0);

		EVENT_OFF(gs.t_operational);

		event_add_timer(master, daemon_restarting_operational, NULL,
				gs.operational_timeout, &gs.t_operational);
	}

	SET_WAKEUP_ECHO(dmn);
	phase_check();
}

static void check_connect(struct event *t_write)
{
	struct daemon *dmn = EVENT_ARG(t_write);
	int sockerr;
	socklen_t reslen = sizeof(sockerr);

	dmn->t_write = NULL;
	if (getsockopt(dmn->fd, SOL_SOCKET, SO_ERROR, (char *)&sockerr, &reslen)
	    < 0) {
		zlog_warn("%s: check_connect: getsockopt failed: %s", dmn->name,
			  safe_strerror(errno));
		daemon_down(dmn,
			    "getsockopt failed checking connection success");
		return;
	}
	if ((reslen == sizeof(sockerr)) && sockerr) {
		char why[100];
		snprintf(
			why, sizeof(why),
			"getsockopt reports that connection attempt failed: %s",
			safe_strerror(sockerr));
		daemon_down(dmn, why);
		return;
	}

	daemon_up(dmn, "delayed connect succeeded");
}

static void wakeup_connect_hanging(struct event *t_wakeup)
{
	struct daemon *dmn = EVENT_ARG(t_wakeup);
	char why[100];

	dmn->t_wakeup = NULL;
	snprintf(why, sizeof(why),
		 "connection attempt timed out after %ld seconds", gs.timeout);
	daemon_down(dmn, why);
}

/* Making connection to protocol daemon. */
static int try_connect(struct daemon *dmn)
{
	int sock;
	struct sockaddr_un addr;
	socklen_t len;

	if (gs.loglevel > LOG_DEBUG + 1)
		zlog_debug("%s: attempting to connect", dmn->name);
	dmn->connect_tries++;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/%s.vty", gs.vtydir,
		 dmn->name);
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = sizeof(addr.sun_family) + strlen(addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

	/* Quick check to see if we might succeed before we go to the trouble
	   of creating a socket. */
	if (access(addr.sun_path, W_OK) < 0) {
		if (errno != ENOENT)
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "%s: access to socket %s denied: %s",
				     dmn->name, addr.sun_path,
				     safe_strerror(errno));
		return -1;
	}

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		flog_err_sys(EC_LIB_SOCKET, "%s(%s): cannot make socket: %s",
			     __func__, addr.sun_path, safe_strerror(errno));
		return -1;
	}

	if (set_nonblocking(sock) < 0 || set_cloexec(sock) < 0) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "%s(%s): set_nonblocking/cloexec(%d) failed",
			     __func__, addr.sun_path, sock);
		close(sock);
		return -1;
	}

	if (connect(sock, (struct sockaddr *)&addr, len) < 0) {
		if ((errno != EINPROGRESS) && (errno != EWOULDBLOCK)) {
			if (gs.loglevel > LOG_DEBUG)
				zlog_debug("%s(%s): connect failed: %s",
					   __func__, addr.sun_path,
					   safe_strerror(errno));
			close(sock);
			return -1;
		}
		if (gs.loglevel > LOG_DEBUG)
			zlog_debug("%s: connection in progress", dmn->name);
		dmn->state = DAEMON_CONNECTING;
		dmn->fd = sock;
		event_add_write(master, check_connect, dmn, dmn->fd,
				&dmn->t_write);
		event_add_timer(master, wakeup_connect_hanging, dmn, gs.timeout,
				&dmn->t_wakeup);
		SET_READ_HANDLER(dmn);
		return 0;
	}

	dmn->fd = sock;
	SET_READ_HANDLER(dmn);
	daemon_up(dmn, "connect succeeded");
	return 1;
}

static void phase_hanging(struct event *t_hanging)
{
	gs.t_phase_hanging = NULL;
	flog_err(EC_WATCHFRR_CONNECTION,
		 "Phase [%s] hanging for %ld seconds, aborting phased restart",
		 phase_str[gs.phase], PHASE_TIMEOUT);
	gs.phase = PHASE_NONE;
}

static void set_phase(enum restart_phase new_phase)
{
	gs.phase = new_phase;
	event_cancel(&gs.t_phase_hanging);

	event_add_timer(master, phase_hanging, NULL, PHASE_TIMEOUT,
			&gs.t_phase_hanging);
}

static void phase_check(void)
{
	struct daemon *dmn;

	switch (gs.phase) {
	case PHASE_NONE:
		break;

	case PHASE_INIT:
		for (dmn = gs.daemons; dmn; dmn = dmn->next)
			if (dmn->state == DAEMON_INIT)
				return;

		/* startup complete, everything out of INIT */
		gs.phase = PHASE_NONE;
		for (dmn = gs.daemons; dmn; dmn = dmn->next)
			if (dmn->state == DAEMON_DOWN) {
				SET_WAKEUP_DOWN(dmn);
				try_restart(dmn);
			}
		break;
	case PHASE_STOPS_PENDING:
		if (gs.numpids)
			break;
		zlog_info(
			"Phased restart: all routing daemon stop jobs have completed.");
		set_phase(PHASE_WAITING_DOWN);

	/*FALLTHRU*/
	case PHASE_WAITING_DOWN:
		if (gs.numdown + IS_UP(gs.special) < gs.numdaemons)
			break;
		systemd_send_status("Phased Restart");
		zlog_info("Phased restart: all routing daemons now down.");
		run_job(&gs.special->restart, "restart", gs.restart_command, 1,
			1);
		set_phase(PHASE_ZEBRA_RESTART_PENDING);

	/*FALLTHRU*/
	case PHASE_ZEBRA_RESTART_PENDING:
		if (gs.special->restart.pid)
			break;
		systemd_send_status("Zebra Restarting");
		zlog_info("Phased restart: %s restart job completed.",
			  gs.special->name);
		set_phase(PHASE_WAITING_ZEBRA_UP);

	/*FALLTHRU*/
	case PHASE_WAITING_ZEBRA_UP:
		if (!IS_UP(gs.special))
			break;
		zlog_info("Phased restart: %s is now up.", gs.special->name);
		for (dmn = gs.daemons; dmn; dmn = dmn->next) {
			if (dmn != gs.special)
				run_job(&dmn->restart, "start",
					gs.start_command, 1, 0);
		}
		gs.phase = PHASE_NONE;
		EVENT_OFF(gs.t_phase_hanging);
		zlog_notice("Phased global restart has completed.");
		break;
	}
}

static void try_restart(struct daemon *dmn)
{
	if (watch_only)
		return;

	if (dmn != gs.special) {
		if ((gs.special->state == DAEMON_UP)
		    && (gs.phase == PHASE_NONE))
			run_job(&dmn->restart, "restart", gs.restart_command, 0,
				1);
		else
			zlog_debug(
				"%s: postponing restart attempt because master %s daemon not up [%s], or phased restart in progress",
				dmn->name, gs.special->name,
				state_str[gs.special->state]);
		return;
	}

	if ((gs.phase != PHASE_NONE) || gs.numpids) {
		if (gs.loglevel > LOG_DEBUG + 1)
			zlog_debug(
				"postponing phased global restart: restart already in progress [%s], or outstanding child processes [%d]",
				phase_str[gs.phase], gs.numpids);
		return;
	}
	/* Is it too soon for a restart? */
	{
		struct timeval delay;
		if (time_elapsed(&delay, &gs.special->restart.time)->tv_sec
		    < gs.special->restart.interval) {
			if (gs.loglevel > LOG_DEBUG + 1)
				zlog_debug(
					"postponing phased global restart: elapsed time %ld < retry interval %ld",
					(long)delay.tv_sec,
					gs.special->restart.interval);
			return;
		}
	}
	run_job(&gs.restart, "restart", gs.restart_command, 0, 1);
}

static void wakeup_unresponsive(struct event *t_wakeup)
{
	struct daemon *dmn = EVENT_ARG(t_wakeup);

	dmn->t_wakeup = NULL;
	if (dmn->state != DAEMON_UNRESPONSIVE)
		flog_err(EC_WATCHFRR_CONNECTION,
			 "%s: no longer unresponsive (now %s), wakeup should have been cancelled!",
			 dmn->name, state_str[dmn->state]);
	else {
		SET_WAKEUP_UNRESPONSIVE(dmn);
		try_restart(dmn);
	}
}

static void wakeup_no_answer(struct event *t_wakeup)
{
	struct daemon *dmn = EVENT_ARG(t_wakeup);

	dmn->t_wakeup = NULL;
	dmn->state = DAEMON_UNRESPONSIVE;
	if (dmn->ignore_timeout)
		return;
	flog_err(EC_WATCHFRR_CONNECTION,
		 "%s state -> unresponsive : no response yet to ping sent %ld seconds ago",
		 dmn->name, gs.timeout);
	SET_WAKEUP_UNRESPONSIVE(dmn);
	try_restart(dmn);
}

static void wakeup_send_echo(struct event *t_wakeup)
{
	static const char echocmd[] = "echo " PING_TOKEN;
	ssize_t rc;
	struct daemon *dmn = EVENT_ARG(t_wakeup);

	dmn->t_wakeup = NULL;
	if (((rc = write(dmn->fd, echocmd, sizeof(echocmd))) < 0)
	    || ((size_t)rc != sizeof(echocmd))) {
		char why[100 + sizeof(echocmd)];
		snprintf(why, sizeof(why),
			 "write '%s' returned %d instead of %u", echocmd,
			 (int)rc, (unsigned int)sizeof(echocmd));
		daemon_down(dmn, why);
	} else {
		gettimeofday(&dmn->echo_sent, NULL);
		event_add_timer(master, wakeup_no_answer, dmn, gs.timeout,
				&dmn->t_wakeup);
	}
}

bool check_all_up(void)
{
	struct daemon *dmn;

	for (dmn = gs.daemons; dmn; dmn = dmn->next)
		if (dmn->state != DAEMON_UP)
			return false;
	return true;
}

void watchfrr_status(struct vty *vty)
{
	struct daemon *dmn;
	struct timeval delay;

	vty_out(vty, "watchfrr global phase: %s\n", phase_str[gs.phase]);
	vty_out(vty, " Restart Command: %pSQq\n", gs.restart_command);
	vty_out(vty, " Start Command: %pSQq\n", gs.start_command);
	vty_out(vty, " Stop Command: %pSQq\n", gs.stop_command);
	vty_out(vty, " Min Restart Interval: %ld\n", gs.min_restart_interval);
	vty_out(vty, " Max Restart Interval: %ld\n", gs.max_restart_interval);
	vty_out(vty, " Restart Timeout: %ld\n", gs.restart_timeout);
	vty_out(vty, " Reading Configuration: %s\n",
		gs.reading_configuration ? "yes" : "no");
	if (gs.restart.pid)
		vty_out(vty, "    global restart running, pid %ld\n",
			(long)gs.restart.pid);

	for (dmn = gs.daemons; dmn; dmn = dmn->next) {
		vty_out(vty, "  %-20s %s%s", dmn->name, state_str[dmn->state],
			dmn->ignore_timeout ? "/Ignoring Timeout\n" : "\n");
		if (dmn->restart.pid)
			vty_out(vty, "      restart running, pid %ld\n",
				(long)dmn->restart.pid);
		else if (dmn->state == DAEMON_DOWN &&
			time_elapsed(&delay, &dmn->restart.time)->tv_sec
				< dmn->restart.interval)
			vty_out(vty, "      restarting in %jd seconds (%jds backoff interval)\n",
				(intmax_t)dmn->restart.interval
					- (intmax_t)delay.tv_sec,
				(intmax_t)dmn->restart.interval);
	}
}

static void sigint(void)
{
	zlog_notice("Terminating on signal");
	systemd_send_stopping();
	exit(0);
}

static int valid_command(const char *cmd)
{
	char *p;

	if (cmd == NULL)
		return 0;

	return ((p = strchr(cmd, '%')) != NULL) && (*(p + 1) == 's')
	       && !strchr(p + 1, '%');
}

/* This is an ugly hack to circumvent problems with passing command-line
   arguments that contain spaces.  The fix is to use a configuration file. */
static char *translate_blanks(const char *cmd, const char *blankstr)
{
	char *res;
	char *p;
	size_t bslen = strlen(blankstr);

	if (!(res = strdup(cmd))) {
		perror("strdup");
		exit(1);
	}
	while ((p = strstr(res, blankstr)) != NULL) {
		*p = ' ';
		if (bslen != 1)
			memmove(p + 1, p + bslen, strlen(p + bslen) + 1);
	}
	return res;
}

static void startup_timeout(struct event *t_wakeup)
{
	daemon_send_ready(1);
}

#ifdef GNU_LINUX

#include <sys/mount.h>
#include <sched.h>

#define NETNS_RUN_DIR "/var/run/netns"

static void netns_create(int dirfd, const char *nsname)
{
	/* make /var/run/netns shared between mount namespaces
	 * just like iproute2 sets it up
	 */
	if (mount("", NETNS_RUN_DIR, "none", MS_SHARED | MS_REC, NULL)) {
		if (errno != EINVAL) {
			perror("mount");
			exit(1);
		}

		if (mount(NETNS_RUN_DIR, NETNS_RUN_DIR, "none",
			  MS_BIND | MS_REC, NULL)) {
			perror("mount");
			exit(1);
		}

		if (mount("", NETNS_RUN_DIR, "none", MS_SHARED | MS_REC,
			  NULL)) {
			perror("mount");
			exit(1);
		}
	}

	/* need an empty file to mount on top of */
	int nsfd = openat(dirfd, nsname, O_CREAT | O_RDONLY | O_EXCL, 0);

	if (nsfd < 0) {
		fprintf(stderr, "failed to create \"%s/%s\": %s\n",
			NETNS_RUN_DIR, nsname, strerror(errno));
		exit(1);
	}
	close(nsfd);

	if (unshare(CLONE_NEWNET)) {
		perror("unshare");
		unlinkat(dirfd, nsname, 0);
		exit(1);
	}

	char *dstpath = asprintfrr(MTYPE_TMP, "%s/%s", NETNS_RUN_DIR, nsname);

	/* bind-mount so the namespace has a name and is persistent */
	if (mount("/proc/self/ns/net", dstpath, "none", MS_BIND, NULL) < 0) {
		fprintf(stderr, "failed to bind-mount netns to \"%s\": %s\n",
			dstpath, strerror(errno));
		unlinkat(dirfd, nsname, 0);
		exit(1);
	}

	XFREE(MTYPE_TMP, dstpath);
}

static void netns_setup(const char *nsname)
{
	int dirfd, nsfd;

	dirfd = open(NETNS_RUN_DIR, O_DIRECTORY | O_RDONLY);
	if (dirfd < 0) {
		if (errno == ENOTDIR) {
			fprintf(stderr, "error: \"%s\" is not a directory!\n",
				NETNS_RUN_DIR);
			exit(1);
		} else if (errno == ENOENT) {
			if (mkdir(NETNS_RUN_DIR, 0755)) {
				fprintf(stderr, "error: \"%s\": mkdir: %s\n",
					NETNS_RUN_DIR, strerror(errno));
				exit(1);
			}
			dirfd = open(NETNS_RUN_DIR, O_DIRECTORY | O_RDONLY);
			if (dirfd < 0) {
				fprintf(stderr, "error: \"%s\": opendir: %s\n",
					NETNS_RUN_DIR, strerror(errno));
				exit(1);
			}
		} else {
			fprintf(stderr, "error: \"%s\": %s\n",
				NETNS_RUN_DIR, strerror(errno));
			exit(1);
		}
	}

	nsfd = openat(dirfd, nsname, O_RDONLY);
	if (nsfd < 0 && errno != ENOENT) {
		fprintf(stderr, "error: \"%s/%s\": %s\n",
			NETNS_RUN_DIR, nsname, strerror(errno));
		exit(1);
	}
	if (nsfd < 0)
		netns_create(dirfd, nsname);
	else {
		if (setns(nsfd, CLONE_NEWNET)) {
			perror("setns");
			exit(1);
		}
		close(nsfd);
	}
	close(dirfd);

	/* make sure loopback is up... weird things happen otherwise.
	 * ioctl is perfectly fine for this, don't need netlink...
	 */
	int sockfd;
	struct ifreq ifr = { };

	strlcpy(ifr.ifr_name, "lo", sizeof(ifr.ifr_name));

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		perror("socket");
		exit(1);
	}
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr)) {
		perror("ioctl(SIOCGIFFLAGS, \"lo\")");
		exit(1);
	}
	if (!(ifr.ifr_flags & IFF_UP)) {
		ifr.ifr_flags |= IFF_UP;
		if (ioctl(sockfd, SIOCSIFFLAGS, &ifr)) {
			perror("ioctl(SIOCSIFFLAGS, \"lo\")");
			exit(1);
		}
	}
	close(sockfd);
}

#else /* !GNU_LINUX */

static void netns_setup(const char *nsname)
{
	fprintf(stderr, "network namespaces are only available on Linux\n");
	exit(1);
}
#endif

static void watchfrr_start_config(void)
{
	gs.reading_configuration = true;
}

static void watchfrr_end_config(void)
{
	gs.reading_configuration = false;
}

static void watchfrr_init(int argc, char **argv)
{
	const char *special = "zebra";
	int i;
	struct daemon *dmn, **add = &gs.daemons;
	char alldaemons[512] = "", *p = alldaemons;

	event_add_timer_msec(master, startup_timeout, NULL, STARTUP_TIMEOUT,
			     &gs.t_startup_timeout);

	for (i = optind; i < argc; i++) {
		dmn = XCALLOC(MTYPE_WATCHFRR_DAEMON, sizeof(*dmn));

		dmn->name = dmn->restart.name = argv[i];
		dmn->state = DAEMON_INIT;
		gs.numdaemons++;
		gs.numdown++;
		dmn->fd = -1;
		event_add_timer_msec(master, wakeup_init, dmn, 0,
				     &dmn->t_wakeup);
		dmn->restart.interval = gs.min_restart_interval;
		*add = dmn;
		add = &dmn->next;

		if (!strcmp(dmn->name, special))
			gs.special = dmn;
	}

	if (!gs.daemons) {
		fprintf(stderr,
			"Must specify one or more daemons to monitor.\n\n");
		frr_help_exit(1);
	}
	if (!watch_only && !gs.special) {
		fprintf(stderr, "\"%s\" daemon must be in daemon lists\n\n",
			special);
		frr_help_exit(1);
	}

	for (dmn = gs.daemons; dmn; dmn = dmn->next) {
		snprintf(p, alldaemons + sizeof(alldaemons) - p, "%s%s",
			 (p == alldaemons) ? "" : " ", dmn->name);
		p += strlen(p);
	}
	zlog_notice("%s %s watching [%s]%s", progname, FRR_VERSION, alldaemons,
		    watch_only ? ", monitor mode" : "");
}

struct zebra_privs_t watchfrr_privs = {
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
};

static struct frr_signal_t watchfrr_signals[] = {
	{
		.signal = SIGINT,
		.handler = sigint,
	},
	{
		.signal = SIGTERM,
		.handler = sigint,
	},
	{
		.signal = SIGCHLD,
		.handler = sigchild,
	},
};

FRR_DAEMON_INFO(watchfrr, WATCHFRR,
		.flags = FRR_NO_PRIVSEP | FRR_NO_TCPVTY | FRR_LIMITED_CLI
			 | FRR_NO_CFG_PID_DRY | FRR_NO_ZCLIENT
			 | FRR_DETACH_LATER,

		.printhelp = printhelp,
		.copyright = "Copyright 2004 Andrew J. Schorr",

		.signals = watchfrr_signals,
		.n_signals = array_size(watchfrr_signals),

		.privs = &watchfrr_privs,
);

#define DEPRECATED_OPTIONS "aAezR:"

int main(int argc, char **argv)
{
	int opt;
	const char *blankstr = NULL;
	const char *netns = NULL;
	bool netns_en = false;

	frr_preinit(&watchfrr_di, argc, argv);
	progname = watchfrr_di.progname;

	frr_opt_add("b:di:k:l:N:p:r:S:s:t:T:" DEPRECATED_OPTIONS, longopts, "");

	gs.restart.name = "all";
	while ((opt = frr_getopt(argc, argv, NULL)) != EOF) {
		if (opt && opt < 128 && strchr(DEPRECATED_OPTIONS, opt)) {
			fprintf(stderr,
				"The -%c option no longer exists.\n"
				"Please refer to the watchfrr(8) man page.\n",
				opt);
			exit(1);
		}

		switch (opt) {
		case 0:
			break;
		case 'b':
			blankstr = optarg;
			break;
		case OPTION_DRY:
			watch_only = true;
			break;
		case 'k':
			if (!valid_command(optarg)) {
				fprintf(stderr,
					"Invalid kill command, must contain '%%s': %s\n",
					optarg);
				frr_help_exit(1);
			}
			gs.stop_command = optarg;
			break;
		case 'l': {
			char garbage[3];
			if ((sscanf(optarg, "%d%1s", &gs.loglevel, garbage)
			     != 1)
			    || (gs.loglevel < LOG_EMERG)) {
				fprintf(stderr,
					"Invalid loglevel argument: %s\n",
					optarg);
				frr_help_exit(1);
			}
		} break;
		case OPTION_MINRESTART: {
			char garbage[3];
			if ((sscanf(optarg, "%ld%1s", &gs.min_restart_interval,
				    garbage)
			     != 1)
			    || (gs.min_restart_interval < 0)) {
				fprintf(stderr,
					"Invalid min_restart_interval argument: %s\n",
					optarg);
				frr_help_exit(1);
			}
		} break;
		case OPTION_MAXRESTART: {
			char garbage[3];
			if ((sscanf(optarg, "%ld%1s", &gs.max_restart_interval,
				    garbage)
			     != 1)
			    || (gs.max_restart_interval < 0)) {
				fprintf(stderr,
					"Invalid max_restart_interval argument: %s\n",
					optarg);
				frr_help_exit(1);
			}
		} break;
		case OPTION_MAXOPERATIONAL: {
			char garbage[3];

			if ((sscanf(optarg, "%ld%1s", &gs.operational_timeout,
				    garbage) != 1) ||
			    (gs.operational_timeout < 0)) {
				fprintf(stderr,
					"Invalid Operational_timeout argument: %s\n",
					optarg);
				frr_help_exit(1);
			}
		} break;
		case OPTION_NETNS:
			netns_en = true;
			if (optarg && strchr(optarg, '/')) {
				fprintf(stderr,
					"invalid network namespace name \"%s\" (may not contain slashes)\n",
					optarg);
				frr_help_exit(1);
			}
			netns = optarg;
			break;
		case 'i': {
			char garbage[3];
			int period;
			if ((sscanf(optarg, "%d%1s", &period, garbage) != 1)
			    || (gs.period < 1)) {
				fprintf(stderr,
					"Invalid interval argument: %s\n",
					optarg);
				frr_help_exit(1);
			}
			gs.period = 1000 * period;
		} break;
		case 'p':
			watchfrr_di.pid_file = optarg;
			break;
		case 'r':
			if (!valid_command(optarg)) {
				fprintf(stderr,
					"Invalid restart command, must contain '%%s': %s\n",
					optarg);
				frr_help_exit(1);
			}
			gs.restart_command = optarg;
			break;
		case 's':
			if (!valid_command(optarg)) {
				fprintf(stderr,
					"Invalid start command, must contain '%%s': %s\n",
					optarg);
				frr_help_exit(1);
			}
			gs.start_command = optarg;
			break;
		case 'S':
			gs.vtydir = optarg;
			break;
		case 't': {
			char garbage[3];
			if ((sscanf(optarg, "%ld%1s", &gs.timeout, garbage)
			     != 1)
			    || (gs.timeout < 1)) {
				fprintf(stderr,
					"Invalid timeout argument: %s\n",
					optarg);
				frr_help_exit(1);
			}
		} break;
		case 'T': {
			char garbage[3];
			if ((sscanf(optarg, "%ld%1s", &gs.restart_timeout,
				    garbage)
			     != 1)
			    || (gs.restart_timeout < 1)) {
				fprintf(stderr,
					"Invalid restart timeout argument: %s\n",
					optarg);
				frr_help_exit(1);
			}
		} break;
		default:
			fputs("Invalid option.\n", stderr);
			frr_help_exit(1);
		}
	}

	if (watch_only
	    && (gs.start_command || gs.stop_command || gs.restart_command)) {
		fputs("Options -r/-s/-k are not used when --dry is active.\n",
		      stderr);
	}
	if (!watch_only
	    && (!gs.restart_command || !gs.start_command || !gs.stop_command)) {
		fprintf(stderr,
			"Options -s (start), -k (kill), and -r (restart) are required.\n");
		frr_help_exit(1);
	}

	if (blankstr) {
		if (gs.restart_command)
			gs.restart_command =
				translate_blanks(gs.restart_command, blankstr);
		if (gs.start_command)
			gs.start_command =
				translate_blanks(gs.start_command, blankstr);
		if (gs.stop_command)
			gs.stop_command =
				translate_blanks(gs.stop_command, blankstr);
	}

	gs.restart.interval = gs.min_restart_interval;

	/* env variable for the processes that we start */
	if (watchfrr_di.pathspace)
		setenv("FRR_PATHSPACE", watchfrr_di.pathspace, 1);
	else
		unsetenv("FRR_PATHSPACE");

	/*
	 * when watchfrr_di.pathspace is read, if it is not specified
	 * pathspace is NULL as expected
	 */
	pathspace = watchfrr_di.pathspace;

	if (netns_en && !netns)
		netns = watchfrr_di.pathspace;

	if (netns_en && netns && netns[0])
		netns_setup(netns);

	master = frr_init();
	watchfrr_error_init();
	watchfrr_init(argc, argv);
	cmd_init_config_callbacks(watchfrr_start_config, watchfrr_end_config);
	watchfrr_vty_init();

	frr_config_fork();

	if (watchfrr_di.daemon_mode)
		zlog_syslog_set_prio_min(MIN(gs.loglevel, LOG_DEBUG));
	else
		zlog_aux_init(NULL, MIN(gs.loglevel, LOG_DEBUG));

	frr_run(master);

	systemd_send_stopping();
	/* Not reached. */
	return 0;
}
