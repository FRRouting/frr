/*
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
#include <sigevent.h>
#include "lib/log.h"
#include "lib/memory.h"

static void sighup(void)
{
	printf("processed hup\n");
}

static void sigusr1(void)
{
	printf("processed usr1\n");
}

static void sigusr2(void)
{
	printf("processed usr2\n");
}

struct quagga_signal_t sigs[] = {{
					 .signal = SIGHUP,
					 .handler = &sighup,
				 },
				 {
					 .signal = SIGUSR1,
					 .handler = &sigusr1,
				 },
				 {
					 .signal = SIGUSR2,
					 .handler = &sigusr2,
				 }};

struct thread_master *master;
struct thread t;

int main(void)
{
	master = thread_master_create(NULL);
	signal_init(master, array_size(sigs), sigs);

	openzlog("testsig", "NONE", 0, LOG_CONS | LOG_NDELAY | LOG_PID,
		 LOG_DAEMON);
	zlog_set_level(ZLOG_DEST_SYSLOG, ZLOG_DISABLED);
	zlog_set_level(ZLOG_DEST_STDOUT, LOG_DEBUG);
	zlog_set_level(ZLOG_DEST_MONITOR, ZLOG_DISABLED);

	while (thread_fetch(master, &t))
		thread_call(&t);

	exit(0);
}
