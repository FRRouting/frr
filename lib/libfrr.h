// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * libfrr overall management functions
 *
 * Copyright (C) 2016  David Lamparter for NetDEF, Inc.
 */

#ifndef _ZEBRA_FRR_H
#define _ZEBRA_FRR_H

#include "typesafe.h"
#include "sigevent.h"
#include "privs.h"
#include "frrevent.h"
#include "log.h"
#include "getopt.h"
#include "module.h"
#include "hook.h"
#include "northbound.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ZAPI_SOCK_NAME "%s/zserv.api", frr_runstatedir

/* The following options disable specific command line options that
 * are not applicable for a particular daemon.
 */
#define FRR_NO_PRIVSEP		(1 << 0)
#define FRR_NO_TCPVTY		(1 << 1)
#define FRR_LIMITED_CLI		(1 << 2)
#define FRR_NO_SPLIT_CONFIG	(1 << 3)
#define FRR_NO_PID		(1 << 4)
#define FRR_NO_CFG_PID_DRY	(FRR_NO_PID | FRR_NO_SPLIT_CONFIG)
#define FRR_NO_ZCLIENT		(1 << 5)
/* If FRR_DETACH_LATER is used, the daemon will keep its parent running
 * until frr_detach() is called.  Normally "somedaemon -d" returns once the
 * main event loop is reached in the daemon;  use this for extra startup bits.
 *
 * Does nothing if -d isn't used.
 */
#define FRR_DETACH_LATER	(1 << 6)
/* If FRR_MANUAL_VTY_START is used, frr_run() will not automatically start
 * listening on for vty connection (either TCP or Unix socket based). The daemon
 * is responsible for calling frr_vty_serv() itself.
 */
#define FRR_MANUAL_VTY_START (1 << 7)

PREDECL_DLIST(log_args);
struct log_arg {
	struct log_args_item itm;

	char target[0];
};
DECLARE_DLIST(log_args, struct log_arg, itm);

/* Registry of daemons' port defaults. Many of these are VTY ports; some
 * daemons have default ports for other features such as ospfapi, or zebra's
 * FPM.
 */

/* default zebra TCP port for zapi; this is currently disabled for security
 * reasons.
 */
#define ZEBRA_TCP_PORT 2600

#define ZEBRA_VTY_PORT 2601
#define RIP_VTY_PORT 2602
#define RIPNG_VTY_PORT 2603
#define OSPF_VTY_PORT 2604
#define BGP_VTY_PORT 2605
#define OSPF6_VTY_PORT 2606

/* Default API server port to accept connection request from client-side.
 * This value could be overridden by "ospfapi" entry in "/etc/services".
 */
#define OSPF_API_SYNC_PORT 2607

#define ISISD_VTY_PORT 2608
#define BABEL_VTY_PORT 2609
#define NHRP_VTY_PORT 2610
#define PIMD_VTY_PORT 2611
#define LDP_VTY_PORT 2612
#define EIGRP_VTY_PORT 2613
#define SHARP_VTY_PORT 2614
#define PBR_VTY_PORT 2615
#define STATIC_VTY_PORT 2616
#define BFDD_VTY_PORT 2617
#define FABRICD_VTY_PORT 2618
#define VRRP_VTY_PORT 2619

/* default port for FPM connections */
#define FPM_DEFAULT_PORT 2620

#define PATH_VTY_PORT 2621
#define PIM6D_VTY_PORT 2622
#define MGMTD_VTY_PORT 2623
/* Registry of daemons' port defaults */

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

	struct event *read_in;
	const char *config_file;
	const char *backup_config_file;
	const char *pid_file;
#ifdef HAVE_SQLITE3
	const char *db_file;
#endif
	const char *vty_path;
	const char *module_path;
	const char *script_path;
	char **state_paths;

	const char *pathspace;
	bool zpathspace;

	struct log_args_head early_logging[1];
	const char *early_loglevel;

	const char *proghelp;
	void (*printhelp)(FILE *target);
	const char *copyright;
	char startinfo[128];

	struct frr_signal_t *signals;
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

extern void frr_preinit(struct frr_daemon_info *daemon, int argc, char **argv);
extern void frr_opt_add(const char *optstr, const struct option *longopts,
			const char *helpstr);
extern int frr_getopt(int argc, char *const argv[], int *longindex);

extern __attribute__((__noreturn__)) void frr_help_exit(int status);

extern struct event_loop *frr_init(void);
extern const char *frr_get_progname(void);
extern enum frr_cli_mode frr_get_cli_mode(void);
extern uint32_t frr_get_fd_limit(void);
extern bool frr_is_startup_fd(int fd);

/* call order of these hooks is as ordered here */
DECLARE_HOOK(frr_early_init, (struct event_loop * tm), (tm));
DECLARE_HOOK(frr_late_init, (struct event_loop * tm), (tm));
/* fork() happens between late_init and config_pre */
DECLARE_HOOK(frr_config_pre, (struct event_loop * tm), (tm));
DECLARE_HOOK(frr_config_post, (struct event_loop * tm), (tm));

extern void frr_config_fork(void);

extern void frr_run(struct event_loop *master);
extern void frr_detach(void);
extern void frr_vty_serv_start(bool check_detach);
extern void frr_vty_serv_stop(void);

extern bool frr_zclient_addr(struct sockaddr_storage *sa, socklen_t *sa_len,
			     const char *path);

struct json_object;
extern struct json_object *frr_daemon_state_load(void);
extern void frr_daemon_state_save(struct json_object **statep);

/* these two are before the protocol daemon does its own shutdown
 * it's named this way being the counterpart to frr_late_init */
DECLARE_KOOH(frr_early_fini, (), ());
extern void frr_early_fini(void);
/* and these two are after the daemon did its own cleanup */
DECLARE_KOOH(frr_fini, (), ());
extern void frr_fini(void);

extern char config_default[512];
extern char frr_zclientpath[512];
extern const char frr_sysconfdir[];
extern char frr_runstatedir[256];
extern char frr_libstatedir[256];
extern const char frr_moduledir[];
extern const char frr_scriptdir[];

extern char frr_protoname[];
extern char frr_protonameinst[];
/* always set in the spot where we *would* fork even if we don't do so */
extern bool frr_is_after_fork;

extern bool debug_memstats_at_exit;

/*
 * Version numbering: MAJOR (8) | MINOR (16) | SUB (8)
 */
#define MAKE_FRRVERSION(maj, min, sub)                                         \
	((((maj) & 0xff) << 24) | (((min) & 0xffff) << 8) | ((sub) & 0xff))
#define MAJOR_FRRVERSION(v) (((v) >> 24) & 0xff)
#define MINOR_FRRVERSION(v) (((v) >> 8) & 0xffff)
#define SUB_FRRVERSION(v)  ((v) & 0xff)

const char *frr_vers2str(uint32_t version, char *buf, int buflen);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_FRR_H */
