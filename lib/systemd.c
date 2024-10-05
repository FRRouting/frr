// SPDX-License-Identifier: GPL-2.0-or-later
/* lib/systemd Code
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Donald Sharp
 */

#include <zebra.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "frrevent.h"
#include "systemd.h"
#include "lib_errors.h"

/* these are cleared from env so they don't "leak" into things we fork(),
 * particularly for watchfrr starting individual daemons
 *
 * watchdog_pid is currently not used since watchfrr starts forking.
 * (TODO: handle that better, somehow?)
 */
static pid_t watchdog_pid = -1;
static intmax_t watchdog_msec;

/* not used yet, but can trigger auto-switch to journald logging */
bool sd_stdout_is_journal;
bool sd_stderr_is_journal;

static char *notify_socket;

/* talk to whatever entity claims to be systemd ;)
 *
 * refer to sd_notify docs for messages systemd accepts over this socket.
 * This function should be functionally equivalent to sd_notify().
 */
static void systemd_send_information(const char *info)
{
	int sock;
	struct sockaddr_un sun;

	if (!notify_socket)
		return;

	sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sock < 0)
		return;

	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, notify_socket, sizeof(sun.sun_path));

	/* linux abstract unix socket namespace */
	if (sun.sun_path[0] == '@')
		sun.sun_path[0] = '\0';

	/* nothing we can do if this errors out... */
	(void)sendto(sock, info, strlen(info), 0, (struct sockaddr *)&sun,
		     sizeof(sun));

	close(sock);
}

void systemd_send_stopping(void)
{
	systemd_send_information("STATUS=");
	systemd_send_information("STOPPING=1");
}

static struct event_loop *systemd_master = NULL;

static void systemd_send_watchdog(struct event *t)
{
	systemd_send_information("WATCHDOG=1");

	assert(watchdog_msec > 0);
	event_add_timer_msec(systemd_master, systemd_send_watchdog, NULL,
			     watchdog_msec, NULL);
}

void systemd_send_started(struct event_loop *m)
{
	assert(m != NULL);

	systemd_master = m;

	systemd_send_information("READY=1");
	if (watchdog_msec > 0)
		systemd_send_watchdog(NULL);
}

void systemd_send_status(const char *status)
{
	char buffer[1024];

	snprintf(buffer, sizeof(buffer), "STATUS=%s", status);
	systemd_send_information(buffer);
}

static intmax_t getenv_int(const char *varname, intmax_t dflt)
{
	char *val, *err;
	intmax_t intval;

	val = getenv(varname);
	if (!val)
		return dflt;

	intval = strtoimax(val, &err, 0);
	if (*err || !*val)
		return dflt;
	return intval;
}

void systemd_init_env(void)
{
	char *tmp;
	uintmax_t dev, ino;
	int len;
	struct stat st;

	notify_socket = getenv("NOTIFY_SOCKET");

	/* no point in setting up watchdog w/o notify socket */
	if (notify_socket) {
		intmax_t watchdog_usec;

		watchdog_pid = getenv_int("WATCHDOG_PID", -1);
		if (watchdog_pid <= 0)
			watchdog_pid = -1;

		/* note this is the deadline, hence the divide by 3 */
		watchdog_usec = getenv_int("WATCHDOG_USEC", 0);
		if (watchdog_usec >= 3000)
			watchdog_msec = watchdog_usec / 3000;
		else {
			if (watchdog_usec != 0)
				flog_err(
					EC_LIB_UNAVAILABLE,
					"systemd expects a %jd microsecond watchdog timer, but FRR only supports millisecond resolution!",
					watchdog_usec);
			watchdog_msec = 0;
		}
	}

	tmp = getenv("JOURNAL_STREAM");
	if (tmp && sscanf(tmp, "%ju:%ju%n", &dev, &ino, &len) == 2
	    && (size_t)len == strlen(tmp)) {
		if (fstat(1, &st) == 0 && st.st_dev == (dev_t)dev
		    && st.st_ino == (ino_t)ino)
			sd_stdout_is_journal = true;
		if (fstat(2, &st) == 0 && st.st_dev == (dev_t)dev
		    && st.st_ino == (ino_t)ino)
			sd_stderr_is_journal = true;
	}

	/* these should *not* be passed to any other process we start */
	unsetenv("WATCHDOG_PID");
	unsetenv("WATCHDOG_USEC");
}
