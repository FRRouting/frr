/*
 * zlog fuzzer target.
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

#include "log.h"
#include "zlog_5424.h"
#include "command.h"

struct input_opts {
	uint16_t out1_debug;
	uint16_t out2_debug;
	uint16_t out3_warn;
	uint8_t fmt;
	uint8_t dst;
};

static char buffer[65536];

int main(int argc, char **argv)
{
	struct input_opts io;
	int fd;
	int pair[2] = {-1, -1};

	if (read(0, &io, sizeof(io)) != sizeof(io))
		return 1;
	if (io.fmt > ZLOG_FMT_LAST)
		return 1;

	switch (io.dst) {
	case 0:
		fd = 1;
		break;
	case 1:
		socketpair(AF_UNIX, SOCK_STREAM, 0, pair);
		fd = pair[0];
		break;
	case 2:
		socketpair(AF_UNIX, SOCK_SEQPACKET, 0, pair);
		fd = pair[0];
		break;
	case 3:
		socketpair(AF_UNIX, SOCK_DGRAM, 0, pair);
		fd = pair[0];
		break;
	default:
		return 1;
	}

	pid_t child = -1;

	if (pair[1] != -1) {
		child = fork();

		if (child == 0) {
			char buf[4096];

			close(pair[0]);

			while (read(pair[1], buf, sizeof(buf)) > 0)
				;
			exit(0);
		} else if (child == -1) {
			perror("fork");
			return 1;
		}
		close(pair[1]);
	}

	for (size_t i = 0; i < sizeof(buffer); i++)
		buffer[i] = (i | 0x20) & 0x7f;

	zlog_aux_init("FUZZBALL: ", LOG_DEBUG);
	zlog_tls_buffer_init();

	struct zlog_cfg_5424 cfg[1] = {};

	zlog_5424_init(cfg);

	cfg->facility = LOG_DAEMON;
	cfg->prio_min = LOG_DEBUG;
	cfg->kw_version = true;
	cfg->kw_location = true;
	cfg->kw_uid = true;
	cfg->kw_ec = true;
	cfg->kw_args = true;

	cfg->ts_flags = 9;
	cfg->fmt = io.fmt;
	cfg->dst = ZLOG_5424_DST_FD;
	cfg->fd = fd;

	cmd_hostname_set("TEST");
	cfg->master = thread_master_create("TEST");

	zlog_5424_apply_dst(cfg);

	zlog_debug("test #1 %.*s", (int)io.out1_debug, buffer);
	zlog_debug("test #2 %.*s", (int)io.out2_debug, buffer);
	zlog_warn("test #1 %.*s", (int)io.out3_warn, buffer);

	zlog_tls_buffer_flush();
	zlog_tls_buffer_fini();

	/* AFL++ seems to do some weird stuff with its fuzzing target, make
	 * sure the fork() child is zapped here rather than creating hordes
	 * of it.
	 */
	close(fd);
	if (child != -1)
		kill(child, SIGTERM);

	return 0;
}
