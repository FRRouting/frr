// SPDX-License-Identifier: ISC
/*	$OpenBSD$ */

/*
 * Copyright (c) 2013, 2016 Renato Westphal <renato@openbsd.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004, 2008 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 */

#include <zebra.h>

#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>

#include "ldpd.h"
#include "ldpe.h"
#include "lde.h"
#include "log.h"
#include "ldp_vty.h"
#include "ldp_debug.h"

#include <lib/version.h>
#include <lib/log.h>
#include "getopt.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "vrf.h"
#include "filter.h"
#include "qobj.h"
#include "libfrr.h"
#include "lib_errors.h"
#include "zlog_recirculate.h"
#include "libagentx.h"

static void		 ldpd_shutdown(void);
static pid_t		 start_child(enum ldpd_process, char *, int, int, int);
static void main_dispatch_ldpe(struct event *thread);
static void main_dispatch_lde(struct event *thread);
static int		 main_imsg_send_ipc_sockets(struct imsgbuf *,
			    struct imsgbuf *);
static void		 main_imsg_send_net_sockets(int);
static void		 main_imsg_send_net_socket(int, enum socket_type);
static int		 main_imsg_send_config(struct ldpd_conf *);
static void		 ldp_config_normalize(struct ldpd_conf *);
static void		 ldp_config_reset(struct ldpd_conf *);
static void		 ldp_config_reset_main(struct ldpd_conf *);
static void		 ldp_config_reset_af(struct ldpd_conf *, int);
static void		 ldp_config_reset_l2vpns(struct ldpd_conf *);
static void		 merge_global(struct ldpd_conf *, struct ldpd_conf *);
static void		 merge_af(int, struct ldpd_af_conf *,
			    struct ldpd_af_conf *);
static void		 merge_ifaces(struct ldpd_conf *, struct ldpd_conf *);
static void		 merge_iface_af(struct iface_af *, struct iface_af *);
static void		 merge_tnbrs(struct ldpd_conf *, struct ldpd_conf *);
static void		 merge_nbrps(struct ldpd_conf *, struct ldpd_conf *);
static void		 merge_l2vpns(struct ldpd_conf *, struct ldpd_conf *);
static void		 merge_l2vpn(struct ldpd_conf *, struct l2vpn *,
			    struct l2vpn *);

DEFINE_QOBJ_TYPE(iface);
DEFINE_QOBJ_TYPE(tnbr);
DEFINE_QOBJ_TYPE(nbr_params);
DEFINE_QOBJ_TYPE(l2vpn_if);
DEFINE_QOBJ_TYPE(l2vpn_pw);
DEFINE_QOBJ_TYPE(l2vpn);
DEFINE_QOBJ_TYPE(ldpd_conf);

const char		*log_procname;

struct ldpd_global	 global;
struct ldpd_init	 init;
struct ldpd_conf	*ldpd_conf, *vty_conf;

static struct imsgev	*iev_ldpe, *iev_ldpe_sync;
static struct imsgev	*iev_lde, *iev_lde_sync;
static pid_t		 ldpe_pid;
static pid_t		 lde_pid;

static struct frr_daemon_info ldpd_di;

DEFINE_HOOK(ldp_register_mib, (struct event_loop * tm), (tm));

static void ldp_load_module(const char *name)
{
	const char *dir;
	dir = ldpd_di.module_path ? ldpd_di.module_path : frr_moduledir;
	struct frrmod_runtime *module;

	module = frrmod_load(name, dir, NULL,NULL);
	if (!module) {
		fprintf(stderr, "%s: failed to load %s", __func__, name);
		log_warnx("%s: failed to load %s", __func__, name);
	}
}

void ldp_agentx_enabled(void)
{
	ldp_load_module("snmp");
	hook_call(ldp_register_mib, master);
}

enum ldpd_process ldpd_process;

#define LDP_DEFAULT_CONFIG	"ldpd.conf"

/* Master of threads. */
struct event_loop *master;

/* ldpd privileges */
static zebra_capabilities_t _caps_p [] =
{
	ZCAP_BIND,
	ZCAP_NET_ADMIN
};

struct zebra_privs_t ldpd_privs =
{
#if defined(FRR_USER) && defined(FRR_GROUP)
	.user = FRR_USER,
	.group = FRR_GROUP,
#endif
#if defined(VTY_GROUP)
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0
};

/* CTL Socket path */
char ctl_sock_path[MAXPATHLEN];

/* LDPd options. */
#define OPTION_CTLSOCK 1001
static const struct option longopts[] =
{
	{ "ctl_socket",  required_argument, NULL, OPTION_CTLSOCK},
	{ "instance",    required_argument, NULL, 'n'},
	{ 0 }
};

/* SIGHUP handler. */
static void
sighup(void)
{
	log_info("SIGHUP received");

	/*
	 * Do a full configuration reload. In other words, reset vty_conf
	 * and build a new configuartion from scratch.
	 */
	ldp_config_reset(vty_conf);
	vty_read_config(NULL, ldpd_di.config_file, config_default);
	ldp_config_apply(NULL, vty_conf);
}

/* SIGINT / SIGTERM handler. */
static void
sigint(void)
{
	log_info("SIGINT received");
	ldpd_shutdown();
}

/* SIGUSR1 handler. */
static void
sigusr1(void)
{
	zlog_rotate();
}

static struct frr_signal_t ldp_signals[] =
{
	{
		.signal = SIGHUP,
		.handler = &sighup,
	},
	{
		.signal = SIGINT,
		.handler = &sigint,
	},
	{
		.signal = SIGTERM,
		.handler = &sigint,
	},
	{
		.signal = SIGUSR1,
		.handler = &sigusr1,
	}
};

static const struct frr_yang_module_info *const ldpd_yang_modules[] = {
	&frr_filter_info,
	&frr_vrf_info,
};

/* clang-format off */
FRR_DAEMON_INFO(ldpd, LDP,
	.vty_port = LDP_VTY_PORT,

	.proghelp = "Implementation of the LDP protocol.",

	.signals = ldp_signals,
	.n_signals = array_size(ldp_signals),

	.privs = &ldpd_privs,

	.yang_modules = ldpd_yang_modules,
	.n_yang_modules = array_size(ldpd_yang_modules),
);
/* clang-format on */

static void ldp_config_fork_apply(struct event *t)
{
	/*
	 * So the frr_config_fork() function schedules
	 * the read of the vty config( if there is a
	 * non-integrated config ) to be after the
	 * end of startup and we are starting the
	 * main process loop.  We need to schedule
	 * the application of this if necessary
	 * after the read in of the config.
	 */
	ldp_config_apply(NULL, vty_conf);
}

int
main(int argc, char *argv[])
{
	char			*saved_argv0;
	int			 lflag = 0, eflag = 0;
	int			 pipe_parent2ldpe[2];
	int			 pipe_parent2ldpe_sync[2];
	int			 pipe_ldpe_log[2];
	int			 pipe_parent2lde[2];
	int			 pipe_parent2lde_sync[2];
	int			 pipe_lde_log[2];
	bool                    ctl_sock_used = false;

	ldpd_process = PROC_MAIN;
	log_procname = log_procnames[ldpd_process];

	saved_argv0 = argv[0];
	if (saved_argv0 == NULL)
		saved_argv0 = (char *)"ldpd";

	frr_preinit(&ldpd_di, argc, argv);
	frr_opt_add("LEn:", longopts,
		"      --ctl_socket   Override ctl socket path\n"
		"  -n, --instance     Instance id\n");

	while (1) {
		int opt;

		opt = frr_getopt(argc, argv, NULL);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		case OPTION_CTLSOCK:
			ctl_sock_used = true;
			snprintf(ctl_sock_path, sizeof(ctl_sock_path),
				 "%s/" LDPD_SOCK_NAME, optarg);
			break;
		case 'n':
			init.instance = atoi(optarg);
			if (init.instance < 1)
				exit(0);
			break;
		case 'L':
			lflag = 1;
			break;
		case 'E':
			eflag = 1;
			break;
		default:
			frr_help_exit(1);
		}
	}

	if (!ctl_sock_used)
		snprintf(ctl_sock_path, sizeof(ctl_sock_path),
			 "%s/" LDPD_SOCK_NAME, frr_runstatedir);

	strlcpy(init.user, ldpd_privs.user, sizeof(init.user));
	strlcpy(init.group, ldpd_privs.group, sizeof(init.group));
	strlcpy(init.ctl_sock_path, ctl_sock_path, sizeof(init.ctl_sock_path));
	strlcpy(init.zclient_serv_path, frr_zclientpath,
	    sizeof(init.zclient_serv_path));

	argc -= optind;
	if (argc > 0 || (lflag && eflag))
		frr_help_exit(1);

	/* check for root privileges  */
	if (geteuid() != 0) {
		errno = EPERM;
		perror(ldpd_di.progname);
		exit(1);
	}

	if (lflag)
		lde();
	else if (eflag)
		ldpe();

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pipe_parent2ldpe) == -1)
		fatal("socketpair");

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC,
	    pipe_parent2ldpe_sync) == -1)
		fatal("socketpair");

	if (socketpair(AF_UNIX, SOCK_DGRAM, PF_UNSPEC, pipe_ldpe_log) == -1)
		fatal("socketpair");

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pipe_parent2lde) == -1)
		fatal("socketpair");

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC,
	    pipe_parent2lde_sync) == -1)
		fatal("socketpair");

	if (socketpair(AF_UNIX, SOCK_DGRAM, PF_UNSPEC, pipe_lde_log) == -1)
		fatal("socketpair");

	sock_set_nonblock(pipe_parent2ldpe[0]);
	sock_set_cloexec(pipe_parent2ldpe[0]);
	sock_set_nonblock(pipe_parent2ldpe[1]);
	sock_set_cloexec(pipe_parent2ldpe[1]);
	sock_set_nonblock(pipe_parent2ldpe_sync[0]);
	sock_set_cloexec(pipe_parent2ldpe_sync[0]);
	sock_set_cloexec(pipe_parent2ldpe_sync[1]);
	sock_set_nonblock(pipe_ldpe_log[0]);
	sock_set_cloexec(pipe_ldpe_log[0]);
	sock_set_nonblock(pipe_ldpe_log[1]);
	sock_set_cloexec(pipe_ldpe_log[1]);

	sock_set_nonblock(pipe_parent2lde[0]);
	sock_set_cloexec(pipe_parent2lde[0]);
	sock_set_nonblock(pipe_parent2lde[1]);
	sock_set_cloexec(pipe_parent2lde[1]);
	sock_set_nonblock(pipe_parent2lde_sync[0]);
	sock_set_cloexec(pipe_parent2lde_sync[0]);
	sock_set_cloexec(pipe_parent2lde_sync[1]);
	sock_set_nonblock(pipe_lde_log[0]);
	sock_set_cloexec(pipe_lde_log[0]);
	sock_set_nonblock(pipe_lde_log[1]);
	sock_set_cloexec(pipe_lde_log[1]);

	/* start children */
	lde_pid = start_child(PROC_LDE_ENGINE, saved_argv0,
	    pipe_parent2lde[1], pipe_parent2lde_sync[1], pipe_lde_log[1]);
	ldpe_pid = start_child(PROC_LDP_ENGINE, saved_argv0,
	    pipe_parent2ldpe[1], pipe_parent2ldpe_sync[1], pipe_ldpe_log[1]);

	master = frr_init();
	/* The two child processes use the zlog_live backend to send their
	 * messages here, where the actual logging config is then applied.
	 * Look for zlog_live_open_fd() to find the other end of this.
	 */
	zlog_recirculate_subscribe(master, pipe_lde_log[0]);
	zlog_recirculate_subscribe(master, pipe_ldpe_log[0]);

	libagentx_init();
	vrf_init(NULL, NULL, NULL, NULL);
	access_list_init();
	ldp_vty_init();
	ldp_zebra_init(master);

	/*
	 * Create base configuration with sane defaults. All configuration
	 * requests (e.g. CLI) act on vty_conf and then call ldp_config_apply()
	 * to merge the changes into ldpd_conf, which contains the actual
	 * running configuration.
	 */
	ldpd_conf = config_new_empty();
	vty_conf = config_new_empty();
	QOBJ_REG(vty_conf, ldpd_conf);

	/* read configuration file and daemonize  */
	frr_config_fork();

	/* apply configuration */
	event_add_event(master, ldp_config_fork_apply, NULL, 0, NULL);

	/* setup pipes to children */
	if ((iev_ldpe = calloc(1, sizeof(struct imsgev))) == NULL ||
	    (iev_ldpe_sync = calloc(1, sizeof(struct imsgev))) == NULL ||
	    (iev_lde = calloc(1, sizeof(struct imsgev))) == NULL ||
	    (iev_lde_sync = calloc(1, sizeof(struct imsgev))) == NULL)
		fatal(NULL);

	imsg_init(&iev_ldpe->ibuf, pipe_parent2ldpe[0]);
	iev_ldpe->handler_read = main_dispatch_ldpe;
	event_add_read(master, iev_ldpe->handler_read, iev_ldpe,
		       iev_ldpe->ibuf.fd, &iev_ldpe->ev_read);
	iev_ldpe->handler_write = ldp_write_handler;

	imsg_init(&iev_ldpe_sync->ibuf, pipe_parent2ldpe_sync[0]);
	iev_ldpe_sync->handler_read = main_dispatch_ldpe;
	event_add_read(master, iev_ldpe_sync->handler_read, iev_ldpe_sync,
		       iev_ldpe_sync->ibuf.fd, &iev_ldpe_sync->ev_read);
	iev_ldpe_sync->handler_write = ldp_write_handler;

	imsg_init(&iev_lde->ibuf, pipe_parent2lde[0]);
	iev_lde->handler_read = main_dispatch_lde;
	event_add_read(master, iev_lde->handler_read, iev_lde, iev_lde->ibuf.fd,
		       &iev_lde->ev_read);
	iev_lde->handler_write = ldp_write_handler;

	imsg_init(&iev_lde_sync->ibuf, pipe_parent2lde_sync[0]);
	iev_lde_sync->handler_read = main_dispatch_lde;
	event_add_read(master, iev_lde_sync->handler_read, iev_lde_sync,
		       iev_lde_sync->ibuf.fd, &iev_lde_sync->ev_read);
	iev_lde_sync->handler_write = ldp_write_handler;

	if (main_imsg_send_ipc_sockets(&iev_ldpe->ibuf, &iev_lde->ibuf))
		fatal("could not establish imsg links");

	main_imsg_compose_both(IMSG_DEBUG_UPDATE, &ldp_debug, sizeof(ldp_debug));
	main_imsg_compose_both(IMSG_INIT, &init, sizeof(init));
	main_imsg_send_config(ldpd_conf);

	if (CHECK_FLAG(ldpd_conf->ipv4.flags, F_LDPD_AF_ENABLED))
		main_imsg_send_net_sockets(AF_INET);

	if (CHECK_FLAG(ldpd_conf->ipv6.flags, F_LDPD_AF_ENABLED))
		main_imsg_send_net_sockets(AF_INET6);

	frr_run(master);

	/* NOTREACHED */
	return (0);
}

static void
ldpd_shutdown(void)
{
	pid_t		 pid;
	int		 status;

	frr_early_fini();

	/* close pipes */
	msgbuf_clear(&iev_ldpe->ibuf.w);
	close(iev_ldpe->ibuf.fd);
	msgbuf_clear(&iev_lde->ibuf.w);
	close(iev_lde->ibuf.fd);

	config_clear(ldpd_conf);

	ldp_config_reset(vty_conf);
	QOBJ_UNREG(vty_conf);
	free(vty_conf);

	log_debug("waiting for children to terminate");

	while (true) {
		/* Wait for child process. */
		pid = wait(&status);
		if (pid == -1) {
			/* We got interrupted, try again. */
			if (errno == EINTR)
				continue;
			/* No more processes were found. */
			if (errno == ECHILD)
				break;

			/* Unhandled errno condition. */
			fatal("wait");
			/* UNREACHABLE */
		}

		/* We found something, lets announce it. */
		if (WIFSIGNALED(status))
			log_warnx("%s terminated; signal %d",
				  (pid == lde_pid ? "label decision engine"
						  : "ldp engine"),
				  WTERMSIG(status));

		/* Repeat until there are no more child processes. */
	}

	free(iev_ldpe);
	free(iev_lde);

	log_info("terminating");

	vrf_terminate();
	access_list_reset();
	ldp_zebra_destroy();

	frr_fini();
	exit(0);
}

static pid_t
start_child(enum ldpd_process p, char *argv0, int fd_async, int fd_sync,
	    int fd_log)
{
	char	*argv[7];
	int	 argc = 0, nullfd;
	pid_t	 pid;

	pid = fork();
	switch (pid) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		close(fd_async);
		close(fd_sync);
		close(fd_log);
		return (pid);
	}

	nullfd = open("/dev/null", O_RDONLY | O_NOCTTY);
	if (nullfd == -1) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "%s: failed to open /dev/null: %s", __func__,
			     safe_strerror(errno));
	} else {
		dup2(nullfd, 0);
		dup2(nullfd, 1);
		dup2(nullfd, 2);
		close(nullfd);
	}

	if (dup2(fd_async, LDPD_FD_ASYNC) == -1)
		fatal("cannot setup imsg async fd");

	if (dup2(fd_sync, LDPD_FD_SYNC) == -1)
		fatal("cannot setup imsg sync fd");

	if (dup2(fd_log, LDPD_FD_LOG) == -1)
		fatal("cannot setup zlog fd");

	argv[argc++] = argv0;
	switch (p) {
	case PROC_MAIN:
		fatalx("Can not start main process");
	case PROC_LDE_ENGINE:
		argv[argc++] = (char *)"-L";
		break;
	case PROC_LDP_ENGINE:
		argv[argc++] = (char *)"-E";
		break;
	}

	argv[argc++] = (char *)"-u";
	argv[argc++] = (char *)ldpd_privs.user;
	argv[argc++] = (char *)"-g";
	argv[argc++] = (char *)ldpd_privs.group;
	argv[argc++] = NULL;

	execvp(argv0, argv);
	fatal("execvp");
}

/* imsg handling */
/* ARGSUSED */
static void main_dispatch_ldpe(struct event *thread)
{
	struct imsgev *iev = EVENT_ARG(thread);
	struct imsgbuf		*ibuf = &iev->ibuf;
	struct imsg		 imsg;
	int			 af;
	ssize_t			 n;
	int			 shut = 0;

	iev->ev_read = NULL;

	if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
		fatal("imsg_read error");

	if (n == 0)	/* connection closed */
		shut = 1;

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("imsg_get");

		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_REQUEST_SOCKETS:
			af = imsg.hdr.pid;
			main_imsg_send_net_sockets(af);
			break;
		case IMSG_ACL_CHECK:
			if (imsg.hdr.len != IMSG_HEADER_SIZE +
			    sizeof(struct acl_check))
				fatalx("IMSG_ACL_CHECK imsg with wrong len");
			ldp_acl_reply(iev, (struct acl_check *)imsg.data);
			break;
		case IMSG_LDP_SYNC_IF_STATE_UPDATE:
			if (imsg.hdr.len != IMSG_HEADER_SIZE +
			    sizeof(struct ldp_igp_sync_if_state))
				fatalx("IMSG_LDP_SYNC_IF_STATE_UPDATE imsg with wrong len");

			ldp_sync_zebra_send_state_update((struct ldp_igp_sync_if_state *)imsg.data);
			break;
		default:
			log_debug("%s: error handling imsg %d", __func__,
			    imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}
	if (!shut)
		imsg_event_add(iev);
	else {
		/* this pipe is dead, so remove the event handlers and exit */
		EVENT_OFF(iev->ev_read);
		EVENT_OFF(iev->ev_write);
		ldpe_pid = 0;

		if (lde_pid == 0)
			ldpd_shutdown();
		else
			kill(lde_pid, SIGTERM);
	}
}

/* ARGSUSED */
static void main_dispatch_lde(struct event *thread)
{
	struct imsgev *iev = EVENT_ARG(thread);
	struct imsgbuf	*ibuf = &iev->ibuf;
	struct imsg	 imsg;
	ssize_t		 n;
	int		 shut = 0;
	struct zapi_rlfa_response *rlfa_labels;

	iev->ev_read = NULL;

	if ((n = imsg_read(ibuf)) == -1 && errno != EAGAIN)
		fatal("imsg_read error");

	if (n == 0)	/* connection closed */
		shut = 1;

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1)
			fatal("imsg_get");

		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_KLABEL_CHANGE:
			if (imsg.hdr.len - IMSG_HEADER_SIZE !=
			    sizeof(struct kroute))
				fatalx("invalid size of IMSG_KLABEL_CHANGE");
			if (kr_change(imsg.data))
				log_warnx("%s: error changing route", __func__);
			break;
		case IMSG_KLABEL_DELETE:
			if (imsg.hdr.len - IMSG_HEADER_SIZE !=
			    sizeof(struct kroute))
				fatalx("invalid size of IMSG_KLABEL_DELETE");
			if (kr_delete(imsg.data))
				log_warnx("%s: error deleting route", __func__);
			break;
		case IMSG_KPW_ADD:
		case IMSG_KPW_DELETE:
		case IMSG_KPW_SET:
		case IMSG_KPW_UNSET:
			if (imsg.hdr.len - IMSG_HEADER_SIZE !=
			    sizeof(struct zapi_pw))
				fatalx("invalid size of IMSG_KPWLABEL_CHANGE");

			switch (imsg.hdr.type) {
			case IMSG_KPW_ADD:
				if (kmpw_add(imsg.data))
					log_warnx("%s: error adding pseudowire", __func__);
				break;
			case IMSG_KPW_DELETE:
				if (kmpw_del(imsg.data))
					log_warnx("%s: error deleting pseudowire", __func__);
				break;
			case IMSG_KPW_SET:
				if (kmpw_set(imsg.data))
					log_warnx("%s: error setting pseudowire", __func__);
				break;
			case IMSG_KPW_UNSET:
				if (kmpw_unset(imsg.data))
					log_warnx("%s: error unsetting pseudowire", __func__);
				break;
			}
			break;
		case IMSG_ACL_CHECK:
			if (imsg.hdr.len != IMSG_HEADER_SIZE +
			    sizeof(struct acl_check))
				fatalx("IMSG_ACL_CHECK imsg with wrong len");
			ldp_acl_reply(iev, (struct acl_check *)imsg.data);
			break;
		case IMSG_RLFA_LABELS:
			if (imsg.hdr.len != IMSG_HEADER_SIZE +
			    sizeof(struct zapi_rlfa_response)) {
				log_warnx("%s: wrong imsg len", __func__);
				break;
			}
			rlfa_labels = imsg.data;
			ldp_zebra_send_rlfa_labels(rlfa_labels);
			break;
		default:
			log_debug("%s: error handling imsg %d", __func__,
			    imsg.hdr.type);
			break;
		}

		imsg_free(&imsg);
	}

	if (!shut)
		imsg_event_add(iev);
	else {
		/* this pipe is dead, so remove the event handlers and exit */
		EVENT_OFF(iev->ev_read);
		EVENT_OFF(iev->ev_write);
		lde_pid = 0;
		if (ldpe_pid == 0)
			ldpd_shutdown();
		else
			kill(ldpe_pid, SIGTERM);
	}
}

/* ARGSUSED */
void ldp_write_handler(struct event *thread)
{
	struct imsgev *iev = EVENT_ARG(thread);
	struct imsgbuf	*ibuf = &iev->ibuf;
	ssize_t		 n;

	iev->ev_write = NULL;

	if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
		fatal("msgbuf_write");
	if (n == 0) {
		/* this pipe is dead, so remove the event handlers */
		EVENT_OFF(iev->ev_read);
		EVENT_OFF(iev->ev_write);
		return;
	}

	imsg_event_add(iev);
}

void
main_imsg_compose_ldpe(int type, pid_t pid, void *data, uint16_t datalen)
{
	if (iev_ldpe == NULL)
		return;

	imsg_compose_event(iev_ldpe, type, 0, pid, -1, data, datalen);
}

void
main_imsg_compose_lde(int type, pid_t pid, void *data, uint16_t datalen)
{
	imsg_compose_event(iev_lde, type, 0, pid, -1, data, datalen);
}

int
main_imsg_compose_both(enum imsg_type type, void *buf, uint16_t len)
{
	if (iev_ldpe == NULL || iev_lde == NULL)
		return (0);

	if (imsg_compose_event(iev_ldpe, type, 0, 0, -1, buf, len) == -1)
		return (-1);

	if (imsg_compose_event(iev_lde, type, 0, 0, -1, buf, len) == -1)
		return (-1);

	return (0);
}

void
imsg_event_add(struct imsgev *iev)
{
	if (iev->handler_read)
		event_add_read(master, iev->handler_read, iev, iev->ibuf.fd,
			       &iev->ev_read);

	if (iev->handler_write && iev->ibuf.w.queued)
		event_add_write(master, iev->handler_write, iev, iev->ibuf.fd,
				&iev->ev_write);
}

int
imsg_compose_event(struct imsgev *iev, uint16_t type, uint32_t peerid,
    pid_t pid, int fd, void *data, uint16_t datalen)
{
	int	ret;

	if ((ret = imsg_compose(&iev->ibuf, type, peerid,
	    pid, fd, data, datalen)) != -1)
		imsg_event_add(iev);

	return (ret);
}

void
evbuf_enqueue(struct evbuf *eb, struct ibuf *buf)
{
	ibuf_close(&eb->wbuf, buf);
	evbuf_event_add(eb);
}

void
evbuf_event_add(struct evbuf *eb)
{
	if (eb->wbuf.queued)
		event_add_write(master, eb->handler, eb->arg, eb->wbuf.fd,
				&eb->ev);
}

void evbuf_init(struct evbuf *eb, int fd, void (*handler)(struct event *),
		void *arg)
{
	msgbuf_init(&eb->wbuf);
	eb->wbuf.fd = fd;
	eb->handler = handler;
	eb->arg = arg;
}

void
evbuf_clear(struct evbuf *eb)
{
	EVENT_OFF(eb->ev);
	msgbuf_clear(&eb->wbuf);
	eb->wbuf.fd = -1;
}

static int
main_imsg_send_ipc_sockets(struct imsgbuf *ldpe_buf, struct imsgbuf *lde_buf)
{
	int pipe_ldpe2lde[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pipe_ldpe2lde) == -1)
		return (-1);
	sock_set_nonblock(pipe_ldpe2lde[0]);
	sock_set_nonblock(pipe_ldpe2lde[1]);

	if (imsg_compose(ldpe_buf, IMSG_SOCKET_IPC, 0, 0, pipe_ldpe2lde[0],
	    NULL, 0) == -1)
		return (-1);

	if (imsg_compose(lde_buf, IMSG_SOCKET_IPC, 0, 0, pipe_ldpe2lde[1],
	    NULL, 0) == -1)
		return (-1);

	return (0);
}

static void
main_imsg_send_net_sockets(int af)
{
	if (!ldp_addrisset(af, &(ldp_af_conf_get(ldpd_conf, af))->trans_addr))
		return;

	main_imsg_send_net_socket(af, LDP_SOCKET_DISC);
	main_imsg_send_net_socket(af, LDP_SOCKET_EDISC);
	main_imsg_send_net_socket(af, LDP_SOCKET_SESSION);
	imsg_compose_event(iev_ldpe, IMSG_SETUP_SOCKETS, af, 0, -1, NULL, 0);
}

static void
main_imsg_send_net_socket(int af, enum socket_type type)
{
	int			 fd;

	fd = ldp_create_socket(af, type);
	if (fd == -1) {
		log_warnx("%s: failed to create %s socket for address-family %s", __func__, socket_name(type), af_name(af));
		return;
	}

	imsg_compose_event(iev_ldpe, IMSG_SOCKET_NET, af, 0, fd, &type,
	    sizeof(type));
}

int
ldp_acl_request(struct imsgev *iev, char *acl_name, int af,
    union ldpd_addr *addr, uint8_t prefixlen)
{
	struct imsg	 imsg;
	struct acl_check acl_check;

	if (acl_name[0] == '\0')
		return FILTER_PERMIT;

	/* build request */
	strlcpy(acl_check.acl, acl_name, sizeof(acl_check.acl));
	acl_check.af = af;
	acl_check.addr = *addr;
	acl_check.prefixlen = prefixlen;

	/* send (blocking) */
	imsg_compose_event(iev, IMSG_ACL_CHECK, 0, 0, -1, &acl_check,
	    sizeof(acl_check));
	imsg_flush(&iev->ibuf);

	/* receive (blocking) and parse result */
	if (imsg_read(&iev->ibuf) == -1)
		fatal("imsg_read error");

	if (imsg_get(&iev->ibuf, &imsg) == -1)
		fatal("imsg_get");

	if (imsg.hdr.type != IMSG_ACL_CHECK ||
	    imsg.hdr.len != IMSG_HEADER_SIZE + sizeof(int))
		fatalx("ldp_acl_request: invalid response");

	return (*((int *)imsg.data));
}

void
ldp_acl_reply(struct imsgev *iev, struct acl_check *acl_check)
{
	struct access_list	*alist;
	struct prefix		 prefix;
	int			 result;

	alist = access_list_lookup(family2afi(acl_check->af), acl_check->acl);
	if (alist == NULL)
		result = FILTER_DENY;
	else {
		prefix.family = acl_check->af;
		switch (prefix.family) {
		case AF_INET:
			prefix.u.prefix4 = acl_check->addr.v4;
			break;
		case AF_INET6:
			prefix.u.prefix6 = acl_check->addr.v6;
			break;
		default:
			fatalx("ldp_acl_reply: unknown af");
		}
		prefix.prefixlen = acl_check->prefixlen;
		result = access_list_apply(alist, &prefix);
	}

	imsg_compose_event(iev, IMSG_ACL_CHECK, 0, 0, -1, &result,
	    sizeof(result));
}

struct ldpd_af_conf *
ldp_af_conf_get(struct ldpd_conf *xconf, int af)
{
	switch (af) {
	case AF_INET:
		return (&xconf->ipv4);
	case AF_INET6:
		return (&xconf->ipv6);
	default:
		fatalx("ldp_af_conf_get: unknown af");
	}
}

struct ldpd_af_global *
ldp_af_global_get(struct ldpd_global *xglobal, int af)
{
	switch (af) {
	case AF_INET:
		return (&xglobal->ipv4);
	case AF_INET6:
		return (&xglobal->ipv6);
	default:
		fatalx("ldp_af_global_get: unknown af");
	}
}

int
ldp_is_dual_stack(struct ldpd_conf *xconf)
{
	return (CHECK_FLAG(xconf->ipv4.flags, F_LDPD_AF_ENABLED) 
            && CHECK_FLAG(xconf->ipv6.flags, F_LDPD_AF_ENABLED));
}

in_addr_t
ldp_rtr_id_get(struct ldpd_conf *xconf)
{
	if (xconf->rtr_id.s_addr != INADDR_ANY)
		return (xconf->rtr_id.s_addr);
	else
		return (global.rtr_id.s_addr);
}

static int
main_imsg_send_config(struct ldpd_conf *xconf)
{
	struct iface		*iface;
	struct tnbr		*tnbr;
	struct nbr_params	*nbrp;
	struct l2vpn		*l2vpn;
	struct l2vpn_if		*lif;
	struct l2vpn_pw		*pw;

	if (main_imsg_compose_both(IMSG_RECONF_CONF, xconf,
	    sizeof(*xconf)) == -1)
		return (-1);

	RB_FOREACH(iface, iface_head, &xconf->iface_tree) {
		if (main_imsg_compose_both(IMSG_RECONF_IFACE, iface,
		    sizeof(*iface)) == -1)
			return (-1);
	}

	RB_FOREACH(tnbr, tnbr_head, &xconf->tnbr_tree) {
		if (main_imsg_compose_both(IMSG_RECONF_TNBR, tnbr,
		    sizeof(*tnbr)) == -1)
			return (-1);
	}

	RB_FOREACH(nbrp, nbrp_head, &xconf->nbrp_tree) {
		if (main_imsg_compose_both(IMSG_RECONF_NBRP, nbrp,
		    sizeof(*nbrp)) == -1)
			return (-1);
	}

	RB_FOREACH(l2vpn, l2vpn_head, &xconf->l2vpn_tree) {
		if (main_imsg_compose_both(IMSG_RECONF_L2VPN, l2vpn,
		    sizeof(*l2vpn)) == -1)
			return (-1);

		RB_FOREACH(lif, l2vpn_if_head, &l2vpn->if_tree) {
			if (main_imsg_compose_both(IMSG_RECONF_L2VPN_IF, lif,
			    sizeof(*lif)) == -1)
				return (-1);
		}

		RB_FOREACH(pw, l2vpn_pw_head, &l2vpn->pw_tree) {
			if (main_imsg_compose_both(IMSG_RECONF_L2VPN_PW, pw,
			    sizeof(*pw)) == -1)
				return (-1);
		}

		RB_FOREACH(pw, l2vpn_pw_head, &l2vpn->pw_inactive_tree) {
			if (main_imsg_compose_both(IMSG_RECONF_L2VPN_IPW, pw,
			    sizeof(*pw)) == -1)
				return (-1);
		}
	}

	if (main_imsg_compose_both(IMSG_RECONF_END, NULL, 0) == -1)
		return (-1);

	return (0);
}

int
ldp_config_apply(struct vty *vty, struct ldpd_conf *xconf)
{
	/*
	 * When reading from a configuration file (startup and sighup), we
	 * call merge_config() only once after the whole config has been read.
	 * This is the optimal and least disruptive way to update the running
	 * configuration.
	 */
	if (vty && vty->type == VTY_FILE)
		return (0);

	ldp_config_normalize(xconf);

	if (main_imsg_send_config(xconf) == -1)
		return (-1);

	merge_config(ldpd_conf, xconf);

	return (0);
}

static void
ldp_config_normalize(struct ldpd_conf *xconf)
{
	struct iface		*iface, *itmp;
	struct nbr_params	*nbrp, *ntmp;
	struct l2vpn		*l2vpn;
	struct l2vpn_pw		*pw, *ptmp;

	if (!CHECK_FLAG(xconf->flags, F_LDPD_ENABLED))
		ldp_config_reset_main(xconf);
	else {
		if (!CHECK_FLAG(xconf->ipv4.flags, F_LDPD_AF_ENABLED))
			ldp_config_reset_af(xconf, AF_INET);
		if (!CHECK_FLAG(xconf->ipv6.flags, F_LDPD_AF_ENABLED))
			ldp_config_reset_af(xconf, AF_INET6);

		RB_FOREACH_SAFE(iface, iface_head, &xconf->iface_tree, itmp) {
			if (iface->ipv4.enabled || iface->ipv6.enabled)
				continue;

			QOBJ_UNREG(iface);
			RB_REMOVE(iface_head, &vty_conf->iface_tree, iface);
			free(iface);
		}

		RB_FOREACH_SAFE(nbrp, nbrp_head, &xconf->nbrp_tree, ntmp) {
			if (CHECK_FLAG(nbrp->flags, (F_NBRP_KEEPALIVE|F_NBRP_GTSM)))
				continue;
			if (nbrp->auth.method != AUTH_NONE)
				continue;

			QOBJ_UNREG(nbrp);
			RB_REMOVE(nbrp_head, &vty_conf->nbrp_tree, nbrp);
			free(nbrp);
		}
	}

	RB_FOREACH(l2vpn, l2vpn_head, &xconf->l2vpn_tree) {
		RB_FOREACH_SAFE(pw, l2vpn_pw_head, &l2vpn->pw_tree, ptmp) {
			if (!CHECK_FLAG(pw->flags, F_PW_STATIC_NBR_ADDR)) {
				pw->af = AF_INET;
				pw->addr.v4 = pw->lsr_id;
			}

			if (pw->lsr_id.s_addr != INADDR_ANY && pw->pwid != 0)
				continue;
			RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_tree, pw);
			RB_INSERT(l2vpn_pw_head, &l2vpn->pw_inactive_tree, pw);
		}

		RB_FOREACH_SAFE(pw, l2vpn_pw_head, &l2vpn->pw_inactive_tree,
		    ptmp) {
			if (!CHECK_FLAG(pw->flags, F_PW_STATIC_NBR_ADDR)) {
				pw->af = AF_INET;
				pw->addr.v4 = pw->lsr_id;
			}

			if (pw->lsr_id.s_addr == INADDR_ANY || pw->pwid == 0)
				continue;
			RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_inactive_tree, pw);
			RB_INSERT(l2vpn_pw_head, &l2vpn->pw_tree, pw);
		}
	}
}

static void
ldp_config_reset(struct ldpd_conf *conf)
{
	ldp_config_reset_main(conf);
	ldp_config_reset_l2vpns(conf);
}

static void
ldp_config_reset_main(struct ldpd_conf *conf)
{
	struct iface		*iface;
	struct nbr_params	*nbrp;

	while (!RB_EMPTY(iface_head, &conf->iface_tree)) {
		iface = RB_ROOT(iface_head, &conf->iface_tree);

		QOBJ_UNREG(iface);
		RB_REMOVE(iface_head, &conf->iface_tree, iface);
		free(iface);
	}

	while (!RB_EMPTY(nbrp_head, &conf->nbrp_tree)) {
		nbrp = RB_ROOT(nbrp_head, &conf->nbrp_tree);

		QOBJ_UNREG(nbrp);
		RB_REMOVE(nbrp_head, &conf->nbrp_tree, nbrp);
		free(nbrp);
	}

	conf->rtr_id.s_addr = INADDR_ANY;
	ldp_config_reset_af(conf, AF_INET);
	ldp_config_reset_af(conf, AF_INET6);
	conf->lhello_holdtime = LINK_DFLT_HOLDTIME;
	conf->lhello_interval = DEFAULT_HELLO_INTERVAL;
	conf->thello_holdtime = TARGETED_DFLT_HOLDTIME;
	conf->thello_interval = DEFAULT_HELLO_INTERVAL;
	conf->wait_for_sync_interval = DFLT_WAIT_FOR_SYNC;
	conf->trans_pref = DUAL_STACK_LDPOV6;
	conf->flags = 0;
}

static void
ldp_config_reset_af(struct ldpd_conf *conf, int af)
{
	struct ldpd_af_conf	*af_conf;
	struct iface		*iface;
	struct iface_af		*ia;
	struct tnbr		*tnbr, *ttmp;

	RB_FOREACH(iface, iface_head, &conf->iface_tree) {
		ia = iface_af_get(iface, af);
		ia->enabled = 0;
	}

	RB_FOREACH_SAFE(tnbr, tnbr_head, &conf->tnbr_tree, ttmp) {
		if (tnbr->af != af)
			continue;

		QOBJ_UNREG(tnbr);
		RB_REMOVE(tnbr_head, &conf->tnbr_tree, tnbr);
		free(tnbr);
	}

	af_conf = ldp_af_conf_get(conf, af);
	af_conf->keepalive = 180;
	af_conf->lhello_holdtime = 0;
	af_conf->lhello_interval = 0;
	af_conf->thello_holdtime = 0;
	af_conf->thello_interval = 0;
	memset(&af_conf->trans_addr, 0, sizeof(af_conf->trans_addr));
	af_conf->flags = 0;
}

static void
ldp_config_reset_l2vpns(struct ldpd_conf *conf)
{
	struct l2vpn		*l2vpn;
	struct l2vpn_if		*lif;
	struct l2vpn_pw		*pw;

	while (!RB_EMPTY(l2vpn_head, &conf->l2vpn_tree)) {
		l2vpn = RB_ROOT(l2vpn_head, &conf->l2vpn_tree);
		while (!RB_EMPTY(l2vpn_if_head, &l2vpn->if_tree)) {
			lif = RB_ROOT(l2vpn_if_head, &l2vpn->if_tree);

			QOBJ_UNREG(lif);
			RB_REMOVE(l2vpn_if_head, &l2vpn->if_tree, lif);
			free(lif);
		}

		while (!RB_EMPTY(l2vpn_pw_head, &l2vpn->pw_tree)) {
			pw = RB_ROOT(l2vpn_pw_head, &l2vpn->pw_tree);

			QOBJ_UNREG(pw);
			RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_tree, pw);
			free(pw);
		}

		while (!RB_EMPTY(l2vpn_pw_head, &l2vpn->pw_inactive_tree)) {
			pw = RB_ROOT(l2vpn_pw_head, &l2vpn->pw_inactive_tree);

			QOBJ_UNREG(pw);
			RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_inactive_tree, pw);
			free(pw);
		}

		QOBJ_UNREG(l2vpn);
		RB_REMOVE(l2vpn_head, &conf->l2vpn_tree, l2vpn);
		free(l2vpn);
	}
}

void
ldp_clear_config(struct ldpd_conf *xconf)
{
	struct iface		*iface;
	struct tnbr		*tnbr;
	struct nbr_params	*nbrp;
	struct l2vpn		*l2vpn;

	while (!RB_EMPTY(iface_head, &xconf->iface_tree)) {
		iface = RB_ROOT(iface_head, &xconf->iface_tree);

		RB_REMOVE(iface_head, &xconf->iface_tree, iface);
		free(iface);
	}

	while (!RB_EMPTY(tnbr_head, &xconf->tnbr_tree)) {
		tnbr = RB_ROOT(tnbr_head, &xconf->tnbr_tree);

		RB_REMOVE(tnbr_head, &xconf->tnbr_tree, tnbr);
		free(tnbr);
	}

	while (!RB_EMPTY(nbrp_head, &xconf->nbrp_tree)) {
		nbrp = RB_ROOT(nbrp_head, &xconf->nbrp_tree);

		RB_REMOVE(nbrp_head, &xconf->nbrp_tree, nbrp);
		free(nbrp);
	}

	while (!RB_EMPTY(l2vpn_head, &xconf->l2vpn_tree)) {
		l2vpn = RB_ROOT(l2vpn_head, &xconf->l2vpn_tree);

		RB_REMOVE(l2vpn_head, &xconf->l2vpn_tree, l2vpn);
		l2vpn_del(l2vpn);
	}

	free(xconf);
}

#define COPY(a, b) do { \
		a = malloc(sizeof(*a)); \
		if (a == NULL) \
			fatal(__func__); \
		*a = *b; \
	} while (0)

void
merge_config(struct ldpd_conf *conf, struct ldpd_conf *xconf)
{
	merge_global(conf, xconf);
	merge_af(AF_INET, &conf->ipv4, &xconf->ipv4);
	merge_af(AF_INET6, &conf->ipv6, &xconf->ipv6);
	merge_ifaces(conf, xconf);
	merge_tnbrs(conf, xconf);
	merge_nbrps(conf, xconf);
	merge_l2vpns(conf, xconf);
}

static void
merge_global(struct ldpd_conf *conf, struct ldpd_conf *xconf)
{
	/* Removing global LDP config requires resetting LDP IGP Sync FSM */
	if (CHECK_FLAG(conf->flags, F_LDPD_ENABLED) 
        && (!CHECK_FLAG(xconf->flags, F_LDPD_ENABLED)))
	{
		if (ldpd_process == PROC_LDP_ENGINE)
			ldp_sync_fsm_reset_all();
	}

	/* change of router-id requires resetting all neighborships */
	if (conf->rtr_id.s_addr != xconf->rtr_id.s_addr) {
		if (ldpd_process == PROC_LDP_ENGINE) {
			ldpe_reset_nbrs(AF_UNSPEC);
			if (conf->rtr_id.s_addr == INADDR_ANY ||
			    xconf->rtr_id.s_addr == INADDR_ANY) {
				if_update_all(AF_UNSPEC);
				tnbr_update_all(AF_UNSPEC);
			}
		}
		conf->rtr_id = xconf->rtr_id;
	}

	/*
	 * Configuration of ordered-control or independent-control
	 * requires resetting all neighborships.
	 */
	if (CHECK_FLAG(conf->flags, F_LDPD_ORDERED_CONTROL) !=
	    CHECK_FLAG(xconf->flags, F_LDPD_ORDERED_CONTROL))
		ldpe_reset_nbrs(AF_UNSPEC);

	conf->lhello_holdtime = xconf->lhello_holdtime;
	conf->lhello_interval = xconf->lhello_interval;
	conf->thello_holdtime = xconf->thello_holdtime;
	conf->thello_interval = xconf->thello_interval;
	conf->wait_for_sync_interval = xconf->wait_for_sync_interval;

	if (conf->trans_pref != xconf->trans_pref) {
		if (ldpd_process == PROC_LDP_ENGINE)
			ldpe_reset_ds_nbrs();
		conf->trans_pref = xconf->trans_pref;
	}

	if (CHECK_FLAG(conf->flags, F_LDPD_DS_CISCO_INTEROP) !=
	    CHECK_FLAG(xconf->flags, F_LDPD_DS_CISCO_INTEROP)) {
		if (ldpd_process == PROC_LDP_ENGINE)
			ldpe_reset_ds_nbrs();
	}

	/*
	 * Configuration of allow-broken-lsp requires reprograming all
	 * labeled routes
	 */
	if (CHECK_FLAG(conf->flags, F_LDPD_ALLOW_BROKEN_LSP) !=
	    CHECK_FLAG(xconf->flags, F_LDPD_ALLOW_BROKEN_LSP)) {
		if (ldpd_process == PROC_LDE_ENGINE)
			lde_allow_broken_lsp_update(xconf->flags);
	}

	if (ldpd_process == PROC_LDP_ENGINE)
		ldpe_set_config_change_time();

	conf->flags = xconf->flags;
}

static void
merge_af(int af, struct ldpd_af_conf *af_conf, struct ldpd_af_conf *xa)
{
	int		 stop_init_backoff = 0;
	int 		 remove_dynamic_tnbrs = 0;
	int		 change_egress_label = 0;
	int		 change_host_label = 0;
	int		 reset_nbrs_ipv4 = 0;
	int		 reset_nbrs = 0;
	int		 update_sockets = 0;
	int		 change_ldp_disabled = 0;

	/* update timers */
	if (af_conf->keepalive != xa->keepalive) {
		af_conf->keepalive = xa->keepalive;
		stop_init_backoff = 1;
	}

	af_conf->lhello_holdtime = xa->lhello_holdtime;
	af_conf->lhello_interval = xa->lhello_interval;
	af_conf->thello_holdtime = xa->thello_holdtime;
	af_conf->thello_interval = xa->thello_interval;

	/* update flags */
	if (CHECK_FLAG(af_conf->flags, F_LDPD_AF_THELLO_ACCEPT) &&
	    !CHECK_FLAG(xa->flags, F_LDPD_AF_THELLO_ACCEPT))
		remove_dynamic_tnbrs = 1;

	if (CHECK_FLAG(af_conf->flags, F_LDPD_AF_NO_GTSM) !=
	    CHECK_FLAG(xa->flags, F_LDPD_AF_NO_GTSM)) {
		if (af == AF_INET6)
			/* need to set/unset IPV6_MINHOPCOUNT */
			update_sockets = 1;
		else
			/* for LDPv4 just resetting the neighbors is enough */
			reset_nbrs_ipv4 = 1;
	}
	if (CHECK_FLAG(af_conf->flags, F_LDPD_AF_EXPNULL) !=
	    CHECK_FLAG(xa->flags, F_LDPD_AF_EXPNULL))
		change_egress_label = 1;

	/* changing config of host only fec filtering */
	if (CHECK_FLAG(af_conf->flags, F_LDPD_AF_ALLOCHOSTONLY)
	    != CHECK_FLAG(xa->flags, F_LDPD_AF_ALLOCHOSTONLY))
		change_host_label = 1;

	/* disabling LDP for address family */
	if (CHECK_FLAG(af_conf->flags, F_LDPD_AF_ENABLED) &&
	    !CHECK_FLAG(xa->flags, F_LDPD_AF_ENABLED))
		change_ldp_disabled = 1;

	af_conf->flags = xa->flags;

	/* update the transport address */
	if (ldp_addrcmp(af, &af_conf->trans_addr, &xa->trans_addr)) {
		af_conf->trans_addr = xa->trans_addr;
		update_sockets = 1;
	}

	/* update ACLs */
	if (strcmp(af_conf->acl_label_allocate_for, xa->acl_label_allocate_for))
		change_host_label = 1;

	if (strcmp(af_conf->acl_label_advertise_to, xa->acl_label_advertise_to) ||
	    strcmp(af_conf->acl_label_advertise_for, xa->acl_label_advertise_for) ||
	    strcmp(af_conf->acl_label_accept_from, xa->acl_label_accept_from) ||
	    strcmp(af_conf->acl_label_accept_for, xa->acl_label_accept_for))
		reset_nbrs = 1;

	if (strcmp(af_conf->acl_thello_accept_from, xa->acl_thello_accept_from))
		remove_dynamic_tnbrs = 1;

	if (strcmp(af_conf->acl_label_expnull_for, xa->acl_label_expnull_for))
		change_egress_label = 1;

	strlcpy(af_conf->acl_thello_accept_from, xa->acl_thello_accept_from,
	    sizeof(af_conf->acl_thello_accept_from));

	strlcpy(af_conf->acl_label_allocate_for, xa->acl_label_allocate_for,
	    sizeof(af_conf->acl_label_allocate_for));

	strlcpy(af_conf->acl_label_advertise_to, xa->acl_label_advertise_to,
	    sizeof(af_conf->acl_label_advertise_to));

	strlcpy(af_conf->acl_label_advertise_for, xa->acl_label_advertise_for,
	    sizeof(af_conf->acl_label_advertise_for));

	strlcpy(af_conf->acl_label_accept_from, xa->acl_label_accept_from,
	    sizeof(af_conf->acl_label_accept_from));

	strlcpy(af_conf->acl_label_accept_for, xa->acl_label_accept_for,
	    sizeof(af_conf->acl_label_accept_for));

	strlcpy(af_conf->acl_label_expnull_for, xa->acl_label_expnull_for,
	    sizeof(af_conf->acl_label_expnull_for));

	/* apply the new configuration */
	switch (ldpd_process) {
	case PROC_LDE_ENGINE:
		if (change_egress_label)
			lde_change_egress_label(af);

		if (change_host_label)
			lde_change_allocate_filter(af);

		if (change_ldp_disabled)
			lde_route_update_release_all(af);

		break;
	case PROC_LDP_ENGINE:
		if (stop_init_backoff)
			ldpe_stop_init_backoff(af);
		if (remove_dynamic_tnbrs)
			ldpe_remove_dynamic_tnbrs(af);
		if (reset_nbrs)
			ldpe_reset_nbrs(AF_UNSPEC);
		else if (reset_nbrs_ipv4)
			ldpe_reset_nbrs(AF_INET);
		break;
	case PROC_MAIN:
		if (update_sockets && iev_ldpe)
			imsg_compose_event(iev_ldpe, IMSG_CLOSE_SOCKETS, af,
			    0, -1, NULL, 0);
		break;
	}
}

static void
merge_ifaces(struct ldpd_conf *conf, struct ldpd_conf *xconf)
{
	struct iface		*iface, *itmp, *xi;

	RB_FOREACH_SAFE(iface, iface_head, &conf->iface_tree, itmp) {
		/* find deleted interfaces, which occurs when LDP is removed
		 * for all address families
		 */
		if (if_lookup_name(xconf, iface->name) == NULL) {
			switch (ldpd_process) {
			case PROC_LDP_ENGINE:
				ldpe_if_exit(iface);
				break;
			case PROC_LDE_ENGINE:
				if (iface->ipv4.enabled)
					lde_route_update_release(iface,
					    AF_INET);
				if (iface->ipv6.enabled)
					lde_route_update_release(iface,
					    AF_INET6);
				break;
			case PROC_MAIN:
				break;
			}
			RB_REMOVE(iface_head, &conf->iface_tree, iface);
			free(iface);
		}
	}
	RB_FOREACH_SAFE(xi, iface_head, &xconf->iface_tree, itmp) {
		/* find new interfaces */
		if ((iface = if_lookup_name(conf, xi->name)) == NULL) {
			COPY(iface, xi);
			RB_INSERT(iface_head, &conf->iface_tree, iface);

			switch (ldpd_process) {
			case PROC_LDP_ENGINE:
				ldpe_if_init(iface);
				break;
			case PROC_LDE_ENGINE:
				break;
			case PROC_MAIN:
				/* resend addresses to activate new interfaces */
				kif_redistribute(iface->name);
				break;
			}
			continue;
		}

		/* update labels when adding or removing ldp on an
		 * interface
		 */
		if (ldpd_process == PROC_LDE_ENGINE) {
			/* if we are removing lpd config for an address
			 * family on an interface then advertise routes
			 * learned over this interface as if they were
			 * connected routes
			 */
			if (iface->ipv4.enabled && !xi->ipv4.enabled)
				lde_route_update_release(iface, AF_INET);

			if (iface->ipv6.enabled && !xi->ipv6.enabled)
				lde_route_update_release(iface, AF_INET6);

			/* if we are adding lpd config for an address
			 * family on an interface then add proper labels
			 */
			if (!iface->ipv4.enabled && xi->ipv4.enabled)
				lde_route_update(iface, AF_INET);

			if (!iface->ipv6.enabled && xi->ipv6.enabled)
				lde_route_update(iface, AF_INET6);
		}

		/* update existing interfaces */
		merge_iface_af(&iface->ipv4, &xi->ipv4);
		merge_iface_af(&iface->ipv6, &xi->ipv6);
	}
}

static void
merge_iface_af(struct iface_af *ia, struct iface_af *xi)
{
	if (ia->enabled != xi->enabled) {
		ia->enabled = xi->enabled;
		if (ldpd_process == PROC_LDP_ENGINE)
			ldp_if_update(ia->iface, ia->af);
	}
	ia->hello_holdtime = xi->hello_holdtime;
	ia->hello_interval = xi->hello_interval;
}

static void
merge_tnbrs(struct ldpd_conf *conf, struct ldpd_conf *xconf)
{
	struct tnbr		*tnbr, *ttmp, *xt;

	RB_FOREACH_SAFE(tnbr, tnbr_head, &conf->tnbr_tree, ttmp) {
		if (!CHECK_FLAG(tnbr->flags, F_TNBR_CONFIGURED))
			continue;

		/* find deleted tnbrs */
		if (tnbr_find(xconf, tnbr->af, &tnbr->addr) == NULL) {
			switch (ldpd_process) {
			case PROC_LDP_ENGINE:
				UNSET_FLAG(tnbr->flags, F_TNBR_CONFIGURED);
				tnbr_check(conf, tnbr);
				break;
			case PROC_LDE_ENGINE:
			case PROC_MAIN:
				RB_REMOVE(tnbr_head, &conf->tnbr_tree, tnbr);
				free(tnbr);
				break;
			}
		}
	}
	RB_FOREACH_SAFE(xt, tnbr_head, &xconf->tnbr_tree, ttmp) {
		/* find new tnbrs */
		if ((tnbr = tnbr_find(conf, xt->af, &xt->addr)) == NULL) {
			COPY(tnbr, xt);
			RB_INSERT(tnbr_head, &conf->tnbr_tree, tnbr);

			switch (ldpd_process) {
			case PROC_LDP_ENGINE:
				tnbr_update(tnbr);
				break;
			case PROC_LDE_ENGINE:
			case PROC_MAIN:
				break;
			}
			continue;
		}

		/* update existing tnbrs */
		if (!CHECK_FLAG(tnbr->flags, F_TNBR_CONFIGURED))
			SET_FLAG(tnbr->flags, F_TNBR_CONFIGURED);
	}
}

static void
merge_nbrps(struct ldpd_conf *conf, struct ldpd_conf *xconf)
{
	struct nbr_params	*nbrp, *ntmp, *xn;
	struct nbr		*nbr;
	int			 nbrp_changed;

	RB_FOREACH_SAFE(nbrp, nbrp_head, &conf->nbrp_tree, ntmp) {
		/* find deleted nbrps */
		if (nbr_params_find(xconf, nbrp->lsr_id) != NULL)
			continue;

		switch (ldpd_process) {
		case PROC_LDP_ENGINE:
			nbr = nbr_find_ldpid(nbrp->lsr_id.s_addr);
			if (nbr) {
				session_shutdown(nbr, S_SHUTDOWN, 0, 0);
#ifdef __OpenBSD__
				pfkey_remove(nbr);
#else
				sock_set_md5sig(
					(ldp_af_global_get(&global, nbr->af))
						->ldp_session_socket,
					nbr->af, &nbr->raddr, NULL);
#endif
				nbr->auth.method = AUTH_NONE;
				if (nbr_session_active_role(nbr))
					nbr_establish_connection(nbr);
			}
			break;
		case PROC_LDE_ENGINE:
		case PROC_MAIN:
			break;
		}
		RB_REMOVE(nbrp_head, &conf->nbrp_tree, nbrp);
		free(nbrp);
	}

	RB_FOREACH_SAFE(xn, nbrp_head, &xconf->nbrp_tree, ntmp) {
		/* find new nbrps */
		if ((nbrp = nbr_params_find(conf, xn->lsr_id)) == NULL) {
			COPY(nbrp, xn);
			RB_INSERT(nbrp_head, &conf->nbrp_tree, nbrp);

			switch (ldpd_process) {
			case PROC_LDP_ENGINE:
				nbr = nbr_find_ldpid(nbrp->lsr_id.s_addr);
				if (nbr) {
					session_shutdown(nbr, S_SHUTDOWN, 0, 0);
					nbr->auth.method = nbrp->auth.method;
#ifdef __OpenBSD__
					if (pfkey_establish(nbr, nbrp) == -1)
						fatalx("pfkey setup failed");
#else
					sock_set_md5sig(
					    (ldp_af_global_get(&global,
					    nbr->af))->ldp_session_socket,
					    nbr->af, &nbr->raddr,
					    nbrp->auth.md5key);
#endif
					if (nbr_session_active_role(nbr))
						nbr_establish_connection(nbr);
				}
				break;
			case PROC_LDE_ENGINE:
			case PROC_MAIN:
				break;
			}
			continue;
		}

		/* update existing nbrps */
		if (nbrp->flags != xn->flags ||
		    nbrp->keepalive != xn->keepalive ||
		    nbrp->gtsm_enabled != xn->gtsm_enabled ||
		    nbrp->gtsm_hops != xn->gtsm_hops ||
		    nbrp->auth.method != xn->auth.method ||
		    strcmp(nbrp->auth.md5key, xn->auth.md5key) != 0)
			nbrp_changed = 1;
		else
			nbrp_changed = 0;

		nbrp->keepalive = xn->keepalive;
		nbrp->gtsm_enabled = xn->gtsm_enabled;
		nbrp->gtsm_hops = xn->gtsm_hops;
		nbrp->auth.method = xn->auth.method;
		strlcpy(nbrp->auth.md5key, xn->auth.md5key,
		    sizeof(nbrp->auth.md5key));
		nbrp->auth.md5key_len = xn->auth.md5key_len;
		nbrp->flags = xn->flags;

		if (ldpd_process == PROC_LDP_ENGINE) {
			nbr = nbr_find_ldpid(nbrp->lsr_id.s_addr);
			if (nbr && nbrp_changed) {
				session_shutdown(nbr, S_SHUTDOWN, 0, 0);
#ifdef __OpenBSD__
				pfkey_remove(nbr);
				nbr->auth.method = nbrp->auth.method;
				if (pfkey_establish(nbr, nbrp) == -1)
					fatalx("pfkey setup failed");
#else
				nbr->auth.method = nbrp->auth.method;
				sock_set_md5sig((ldp_af_global_get(&global,
				    nbr->af))->ldp_session_socket, nbr->af,
				    &nbr->raddr, nbrp->auth.md5key);
#endif
				if (nbr_session_active_role(nbr))
					nbr_establish_connection(nbr);
			}
		}
	}
}

static void
merge_l2vpns(struct ldpd_conf *conf, struct ldpd_conf *xconf)
{
	struct l2vpn		*l2vpn, *ltmp, *xl;

	RB_FOREACH_SAFE(l2vpn, l2vpn_head, &conf->l2vpn_tree, ltmp) {
		/* find deleted l2vpns */
		if (l2vpn_find(xconf, l2vpn->name) == NULL) {
			switch (ldpd_process) {
			case PROC_LDE_ENGINE:
				l2vpn_exit(l2vpn);
				break;
			case PROC_LDP_ENGINE:
				ldpe_l2vpn_exit(l2vpn);
				break;
			case PROC_MAIN:
				break;
			}
			RB_REMOVE(l2vpn_head, &conf->l2vpn_tree, l2vpn);
			l2vpn_del(l2vpn);
		}
	}
	RB_FOREACH_SAFE(xl, l2vpn_head, &xconf->l2vpn_tree, ltmp) {
		/* find new l2vpns */
		if ((l2vpn = l2vpn_find(conf, xl->name)) == NULL) {
			COPY(l2vpn, xl);
			RB_INSERT(l2vpn_head, &conf->l2vpn_tree, l2vpn);
			RB_INIT(l2vpn_if_head, &l2vpn->if_tree);
			RB_INIT(l2vpn_pw_head, &l2vpn->pw_tree);
			RB_INIT(l2vpn_pw_head, &l2vpn->pw_inactive_tree);

			switch (ldpd_process) {
			case PROC_LDE_ENGINE:
				l2vpn_init(l2vpn);
				break;
			case PROC_LDP_ENGINE:
				ldpe_l2vpn_init(l2vpn);
				break;
			case PROC_MAIN:
				break;
			}
		}

		/* update existing l2vpns */
		merge_l2vpn(conf, l2vpn, xl);
	}
}

static void
merge_l2vpn(struct ldpd_conf *xconf, struct l2vpn *l2vpn, struct l2vpn *xl)
{
	struct l2vpn_if		*lif, *ftmp, *xf;
	struct l2vpn_pw		*pw, *ptmp, *xp;
	struct nbr		*nbr;
	int			 reset_nbr, reinstall_pwfec, reinstall_tnbr;
	int			 previous_pw_type, previous_mtu;

	previous_pw_type = l2vpn->pw_type;
	previous_mtu = l2vpn->mtu;

	/* merge interfaces */
	RB_FOREACH_SAFE(lif, l2vpn_if_head, &l2vpn->if_tree, ftmp) {
		/* find deleted interfaces */
		if (l2vpn_if_find(xl, lif->ifname) == NULL) {
			RB_REMOVE(l2vpn_if_head, &l2vpn->if_tree, lif);
			free(lif);
		}
	}
	RB_FOREACH_SAFE(xf, l2vpn_if_head, &xl->if_tree, ftmp) {
		/* find new interfaces */
		if (l2vpn_if_find(l2vpn, xf->ifname) == NULL) {
			COPY(lif, xf);
			RB_INSERT(l2vpn_if_head, &l2vpn->if_tree, lif);
			lif->l2vpn = l2vpn;

			switch (ldpd_process) {
			case PROC_LDP_ENGINE:
			case PROC_LDE_ENGINE:
				break;
			case PROC_MAIN:
				kif_redistribute(lif->ifname);
				break;
			}
		}
	}

	/* merge active pseudowires */
	RB_FOREACH_SAFE(pw, l2vpn_pw_head, &l2vpn->pw_tree, ptmp) {
		/* find deleted active pseudowires */
		if (l2vpn_pw_find_active(xl, pw->ifname) == NULL) {
			switch (ldpd_process) {
			case PROC_LDE_ENGINE:
				l2vpn_pw_exit(pw);
				break;
			case PROC_LDP_ENGINE:
				ldpe_l2vpn_pw_exit(pw);
				break;
			case PROC_MAIN:
				break;
			}

			RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_tree, pw);
			free(pw);
		}
	}
	RB_FOREACH_SAFE(xp, l2vpn_pw_head, &xl->pw_tree, ptmp) {
		/* find new active pseudowires */
		if ((pw = l2vpn_pw_find_active(l2vpn, xp->ifname)) == NULL) {
			COPY(pw, xp);
			RB_INSERT(l2vpn_pw_head, &l2vpn->pw_tree, pw);
			pw->l2vpn = l2vpn;

			switch (ldpd_process) {
			case PROC_LDE_ENGINE:
				l2vpn_pw_init(pw);
				break;
			case PROC_LDP_ENGINE:
				ldpe_l2vpn_pw_init(pw);
				break;
			case PROC_MAIN:
				kif_redistribute(pw->ifname);
				break;
			}
			continue;
		}

		/* update existing active pseudowire */
    		if (pw->af != xp->af ||
		    ldp_addrcmp(pw->af, &pw->addr, &xp->addr))
			reinstall_tnbr = 1;
		else
			reinstall_tnbr = 0;

		/* changes that require a session restart */
		if (CHECK_FLAG(pw->flags, (F_PW_STATUSTLV_CONF|F_PW_CWORD_CONF)) !=
		    CHECK_FLAG(xp->flags, (F_PW_STATUSTLV_CONF|F_PW_CWORD_CONF)))
			reset_nbr = 1;
		else
			reset_nbr = 0;

		if (l2vpn->pw_type != xl->pw_type || l2vpn->mtu != xl->mtu ||
		    pw->pwid != xp->pwid || reinstall_tnbr || reset_nbr ||
		    pw->lsr_id.s_addr != xp->lsr_id.s_addr)
			reinstall_pwfec = 1;
		else
			reinstall_pwfec = 0;

		if (ldpd_process == PROC_LDP_ENGINE) {
			if (reinstall_tnbr)
				ldpe_l2vpn_pw_exit(pw);
			if (reset_nbr) {
				nbr = nbr_find_ldpid(pw->lsr_id.s_addr);
				if (nbr && nbr->state == NBR_STA_OPER)
					session_shutdown(nbr, S_SHUTDOWN, 0, 0);
			}
		}
		if (ldpd_process == PROC_LDE_ENGINE && reinstall_pwfec)
			l2vpn_pw_exit(pw);
		pw->lsr_id = xp->lsr_id;
		pw->af = xp->af;
		pw->addr = xp->addr;
		pw->pwid = xp->pwid;
		strlcpy(pw->ifname, xp->ifname, sizeof(pw->ifname));
		pw->ifindex = xp->ifindex;
		if (CHECK_FLAG(xp->flags, F_PW_CWORD_CONF))
			SET_FLAG(pw->flags, F_PW_CWORD_CONF);
		else
			UNSET_FLAG(pw->flags, F_PW_CWORD_CONF);

		if (CHECK_FLAG(xp->flags, F_PW_STATUSTLV_CONF))
			SET_FLAG(pw->flags, F_PW_STATUSTLV_CONF);
		else
			UNSET_FLAG(pw->flags, F_PW_STATUSTLV_CONF);

		if (CHECK_FLAG(xp->flags, F_PW_STATIC_NBR_ADDR))
			SET_FLAG(pw->flags, F_PW_STATIC_NBR_ADDR);
		else
			UNSET_FLAG(pw->flags, F_PW_STATIC_NBR_ADDR);

		if (ldpd_process == PROC_LDP_ENGINE && reinstall_tnbr)
			ldpe_l2vpn_pw_init(pw);

		if (ldpd_process == PROC_LDE_ENGINE && reinstall_pwfec) {
			l2vpn->pw_type = xl->pw_type;
			l2vpn->mtu = xl->mtu;
			l2vpn_pw_init(pw);
			l2vpn->pw_type = previous_pw_type;
			l2vpn->mtu = previous_mtu;
		}
	}

	/* merge inactive pseudowires */
	RB_FOREACH_SAFE(pw, l2vpn_pw_head, &l2vpn->pw_inactive_tree, ptmp) {
		/* find deleted inactive pseudowires */
		if (l2vpn_pw_find_inactive(xl, pw->ifname) == NULL) {
			RB_REMOVE(l2vpn_pw_head, &l2vpn->pw_inactive_tree, pw);
			free(pw);
		}
	}
	RB_FOREACH_SAFE(xp, l2vpn_pw_head, &xl->pw_inactive_tree, ptmp) {
		/* find new inactive pseudowires */
		if ((pw = l2vpn_pw_find_inactive(l2vpn, xp->ifname)) == NULL) {
			COPY(pw, xp);
			RB_INSERT(l2vpn_pw_head, &l2vpn->pw_inactive_tree, pw);
			pw->l2vpn = l2vpn;

			switch (ldpd_process) {
			case PROC_LDE_ENGINE:
			case PROC_LDP_ENGINE:
				break;
			case PROC_MAIN:
				kif_redistribute(pw->ifname);
				break;
			}
			continue;
		}

		/* update existing inactive pseudowire */
		pw->lsr_id.s_addr = xp->lsr_id.s_addr;
		pw->af = xp->af;
		pw->addr = xp->addr;
		pw->pwid = xp->pwid;
		strlcpy(pw->ifname, xp->ifname, sizeof(pw->ifname));
		pw->ifindex = xp->ifindex;
		pw->flags = xp->flags;
	}

	l2vpn->pw_type = xl->pw_type;
	l2vpn->mtu = xl->mtu;
	strlcpy(l2vpn->br_ifname, xl->br_ifname, sizeof(l2vpn->br_ifname));
	l2vpn->br_ifindex = xl->br_ifindex;
}

struct ldpd_conf *
config_new_empty(void)
{
	struct ldpd_conf	*xconf;

	xconf = calloc(1, sizeof(*xconf));
	if (xconf == NULL)
		fatal(NULL);

	RB_INIT(iface_head, &xconf->iface_tree);
	RB_INIT(tnbr_head, &xconf->tnbr_tree);
	RB_INIT(nbrp_head, &xconf->nbrp_tree);
	RB_INIT(l2vpn_head, &xconf->l2vpn_tree);

	/* set default values */
	ldp_config_reset(xconf);

	return (xconf);
}

void
config_clear(struct ldpd_conf *conf)
{
	struct ldpd_conf	*xconf;

	/*
	 * Merge current config with an empty config, this will deactivate
	 * and deallocate all the interfaces, pseudowires and so on. Before
	 * merging, copy the router-id and other variables to avoid some
	 * unnecessary operations, like trying to reset the neighborships.
	 */
	xconf = config_new_empty();
	xconf->ipv4 = conf->ipv4;
	xconf->ipv6 = conf->ipv6;
	xconf->rtr_id = conf->rtr_id;
	xconf->trans_pref = conf->trans_pref;
	xconf->flags = conf->flags;
	merge_config(conf, xconf);
	free(xconf);
	free(conf);
}
