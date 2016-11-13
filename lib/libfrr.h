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
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _ZEBRA_FRR_H
#define _ZEBRA_FRR_H

#include "sigevent.h"
#include "privs.h"
#include "thread.h"
#include "log.h"
#include "getopt.h"

#define FRR_NO_PRIVSEP		(1 << 0)
#define FRR_NO_TCPVTY		(1 << 1)

struct frr_daemon_info {
	unsigned flags;

	const char *progname;
	zlog_proto_t log_id;
	unsigned short instance;

	char *vty_addr;
	int vty_port;
	char *vty_sock_path;

	const char *proghelp;
	void (*printhelp)(FILE *target);
	const char *copyright;

	struct quagga_signal_t *signals;
	size_t n_signals;

	struct zebra_privs_t *privs;
};

/* execname is the daemon's executable (and pidfile and configfile) name,
 * i.e. "zebra" or "bgpd"
 * constname is the daemons source-level name, primarily for the logging ID,
 * i.e. "ZEBRA" or "BGP"
 *
 * note that this macro is also a latch-on point for other changes (e.g.
 * upcoming plugin support) that need to place some per-daemon things.  Each
 * daemon should have one of these.
 */
#define FRR_DAEMON_INFO(execname, constname, ...) \
	static struct frr_daemon_info execname ##_di = { \
		.log_id = ZLOG_ ## constname, \
		__VA_ARGS__ \
	};

extern void frr_preinit(struct frr_daemon_info *daemon,
		int argc, char **argv);
extern void frr_opt_add(const char *optstr,
		const struct option *longopts, const char *helpstr);
extern int frr_getopt(int argc, char * const argv[], int *longindex);
extern void frr_help_exit(int status);

extern struct thread_master *frr_init(void);

extern void frr_vty_serv(const char *path);

#endif /* _ZEBRA_FRR_H */
