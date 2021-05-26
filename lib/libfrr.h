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

#ifndef _ZEBRA_FRR_H
#define _ZEBRA_FRR_H

#include "sigevent.h"
#include "privs.h"
#include "thread.h"
#include "log.h"
#include "getopt.h"
#include "module.h"
#include "hook.h"
#include "northbound.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The following options disable specific command line options that
 * are not applicable for a particular daemon.
 */
#define FRR_NO_PRIVSEP		(1 << 0)
#define FRR_NO_TCPVTY		(1 << 1)
#define FRR_LIMITED_CLI		(1 << 2)
#define FRR_NO_CFG_PID_DRY	(1 << 3)
#define FRR_NO_ZCLIENT		(1 << 4)
/* If FRR_DETACH_LATER is used, the daemon will keep its parent running
 * until frr_detach() is called.  Normally "somedaemon -d" returns once the
 * main event loop is reached in the daemon;  use this for extra startup bits.
 *
 * Does nothing if -d isn't used.
 */
#define FRR_DETACH_LATER	(1 << 5)

enum frr_cli_mode {
	FRR_CLI_CLASSIC = 0,
	FRR_CLI_TRANSACTIONAL,
};

struct frr_daemon_info {
	unsigned flags;

	const char *progname;
	const char *name;
	const char *logname;
	unsigned short instance;
	struct frrmod_runtime *module;

	char *vty_addr;
	int vty_port;
	char *vty_sock_path;
	bool dryrun;
	bool daemon_mode;
	bool terminal;
	enum frr_cli_mode cli_mode;

	struct thread *read_in;
	const char *config_file;
	const char *backup_config_file;
	const char *pid_file;
#ifdef HAVE_SQLITE3
	const char *db_file;
#endif
	const char *vty_path;
	const char *module_path;
	const char *script_path;

	const char *pathspace;
	bool zpathspace;

	const char *early_logging;
	const char *early_loglevel;

	const char *proghelp;
	void (*printhelp)(FILE *target);
	const char *copyright;
	char startinfo[128];

	struct quagga_signal_t *signals;
	size_t n_signals;

	struct zebra_privs_t *privs;

	const struct frr_yang_module_info *const *yang_modules;
	size_t n_yang_modules;

	bool log_always;

	/* Optional upper limit on the number of fds used in select/poll */
	uint32_t limit_fds;
};

/* execname is the daemon's executable (and pidfile and configfile) name,
 * i.e. "zebra" or "bgpd"
 * constname is the daemons source-level name, primarily for the logging ID,
 * i.e. "ZEBRA" or "BGP"
 *
 * note that this macro is also a latch-on point for other changes (e.g.
 * upcoming module support) that need to place some per-daemon things.  Each
 * daemon should have one of these.
 */
#define FRR_DAEMON_INFO(execname, constname, ...)                              \
	static struct frr_daemon_info execname##_di = {.name = #execname,      \
						       .logname = #constname,  \
						       .module = THIS_MODULE,  \
						       __VA_ARGS__};           \
	FRR_COREMOD_SETUP(.name = #execname,                                   \
			  .description = #execname " daemon",                  \
			  .version = FRR_VERSION, );                           \
	MACRO_REQUIRE_SEMICOLON() /* end */

extern void frr_init_vtydir(void);
extern void frr_preinit(struct frr_daemon_info *daemon, int argc, char **argv);
extern void frr_opt_add(const char *optstr, const struct option *longopts,
			const char *helpstr);
extern int frr_getopt(int argc, char *const argv[], int *longindex);

extern __attribute__((__noreturn__)) void frr_help_exit(int status);

extern struct thread_master *frr_init(void);
extern const char *frr_get_progname(void);
extern enum frr_cli_mode frr_get_cli_mode(void);
extern uint32_t frr_get_fd_limit(void);
extern bool frr_is_startup_fd(int fd);

/* call order of these hooks is as ordered here */
DECLARE_HOOK(frr_late_init, (struct thread_master * tm), (tm));
/* fork() happens between late_init and config_pre */
DECLARE_HOOK(frr_config_pre, (struct thread_master * tm), (tm));
DECLARE_HOOK(frr_config_post, (struct thread_master * tm), (tm));

extern void frr_config_fork(void);

extern void frr_run(struct thread_master *master);
extern void frr_detach(void);

extern bool frr_zclient_addr(struct sockaddr_storage *sa, socklen_t *sa_len,
			     const char *path);

/* these two are before the protocol daemon does its own shutdown
 * it's named this way being the counterpart to frr_late_init */
DECLARE_KOOH(frr_early_fini, (), ());
extern void frr_early_fini(void);
/* and these two are after the daemon did its own cleanup */
DECLARE_KOOH(frr_fini, (), ());
extern void frr_fini(void);

extern char config_default[512];
extern char frr_zclientpath[256];
extern const char frr_sysconfdir[];
extern char frr_vtydir[256];
extern const char frr_moduledir[];
extern const char frr_scriptdir[];

extern char frr_protoname[];
extern char frr_protonameinst[];
/* always set in the spot where we *would* fork even if we don't do so */
extern bool frr_is_after_fork;

extern bool debug_memstats_at_exit;

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_FRR_H */
