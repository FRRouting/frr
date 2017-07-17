/* lib/systemd Code
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Donald Sharp
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "thread.h"
#include "systemd.h"

#if defined HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

/*
 * Wrapper this silliness if we
 * don't have systemd
 */
void systemd_send_information(const char *info)
{
#if defined HAVE_SYSTEMD
	sd_notify(0, info);
#else
	return;
#endif
}

/*
 * A return of 0 means that we are not watchdoged
 */
static int systemd_get_watchdog_time(int the_process)
{
#if defined HAVE_SYSTEMD
	uint64_t usec;
	char *watchdog = NULL;
	int ret;

	ret = sd_watchdog_enabled(0, &usec);

	/*
	 * If return is 0 -> we don't want watchdog
	 * if return is < 0, some sort of failure occurred
	 */
	if (ret < 0)
		return 0;

	/*
	 * systemd can return that this process
	 * is not the expected sender of the watchdog timer
	 * If we set the_process = 0 then we expect to
	 * be able to send the watchdog to systemd
	 * irrelevant of the pid of this process.
	 */
	if (ret == 0 && the_process)
		return 0;

	if (ret == 0 && !the_process) {
		watchdog = getenv("WATCHDOG_USEC");
		if (!watchdog)
			return 0;

		usec = atol(watchdog);
	}

	return (usec / 1000000) / 3;
#else
	return 0;
#endif
}

void systemd_send_stopping(void)
{
	systemd_send_information("STOPPING=1");
}

/*
 * How many seconds should we wait between watchdog sends
 */
int wsecs = 0;
struct thread_master *systemd_master = NULL;

static int systemd_send_watchdog(struct thread *t)
{
	systemd_send_information("WATCHDOG=1");

	thread_add_timer(systemd_master, systemd_send_watchdog, NULL, wsecs,
			 NULL);

	return 1;
}

void systemd_send_started(struct thread_master *m, int the_process)
{
	assert(m != NULL);

	wsecs = systemd_get_watchdog_time(the_process);
	systemd_master = m;

	systemd_send_information("READY=1");
	if (wsecs != 0)
		thread_add_timer(m, systemd_send_watchdog, m, wsecs, NULL);
}
