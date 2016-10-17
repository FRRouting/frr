/*	$OpenBSD$ */

/*
 * Copyright (c) 2013, 2016 Renato Westphal <renato@openbsd.org>
 * Copyright (c) 2005 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2004, 2008 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <zebra.h>
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
#include "qobj.h"

static void		 ldpd_shutdown(void);
static pid_t		 start_child(enum ldpd_process, char *, int,
			    const char *, const char *);
static int		 main_dispatch_ldpe(struct thread *);
static int		 main_dispatch_lde(struct thread *);
static int		 main_imsg_send_ipc_sockets(struct imsgbuf *,
			    struct imsgbuf *);
static void		 main_imsg_send_net_sockets(int);
static void		 main_imsg_send_net_socket(int, enum socket_type);
static int		 main_imsg_send_config(struct ldpd_conf *);
static void		 ldp_config_normalize(struct ldpd_conf *, void **);
static void		 ldp_config_reset_main(struct ldpd_conf *, void **);
static void		 ldp_config_reset_af(struct ldpd_conf *, int, void **);
static void		 merge_config_ref(struct ldpd_conf *, struct ldpd_conf *, void **);
static void		 merge_global(struct ldpd_conf *, struct ldpd_conf *);
static void		 merge_af(int, struct ldpd_af_conf *,
			    struct ldpd_af_conf *);
static void		 merge_ifaces(struct ldpd_conf *, struct ldpd_conf *, void **);
static void		 merge_iface_af(struct iface_af *, struct iface_af *);
static void		 merge_tnbrs(struct ldpd_conf *, struct ldpd_conf *, void **);
static void		 merge_nbrps(struct ldpd_conf *, struct ldpd_conf *, void **);
static void		 merge_l2vpns(struct ldpd_conf *, struct ldpd_conf *, void **);
static void		 merge_l2vpn(struct ldpd_conf *, struct l2vpn *,
			    struct l2vpn *, void **);

DEFINE_QOBJ_TYPE(iface)
DEFINE_QOBJ_TYPE(tnbr)
DEFINE_QOBJ_TYPE(nbr_params)
DEFINE_QOBJ_TYPE(l2vpn_if)
DEFINE_QOBJ_TYPE(l2vpn_pw)
DEFINE_QOBJ_TYPE(l2vpn)
DEFINE_QOBJ_TYPE(ldpd_conf)

struct ldpd_global	 global;
struct ldpd_conf	*ldpd_conf;

static struct imsgev	*iev_ldpe;
static struct imsgev	*iev_lde;
static pid_t		 ldpe_pid;
static pid_t		 lde_pid;

#define LDP_DEFAULT_CONFIG	"ldpd.conf"
#define LDP_VTY_PORT		2612

/* Master of threads. */
struct thread_master *master;

/* Process ID saved for use by init system */
static const char *pid_file = PATH_LDPD_PID;

/* Configuration filename and directory. */
static char config_default[] = SYSCONFDIR LDP_DEFAULT_CONFIG;

/* ldpd privileges */
static zebra_capabilities_t _caps_p [] =
{
	ZCAP_BIND,
	ZCAP_NET_ADMIN
};

struct zebra_privs_t ldpd_privs =
{
#if defined(QUAGGA_USER) && defined(QUAGGA_GROUP)
	.user = QUAGGA_USER,
	.group = QUAGGA_GROUP,
#endif
#if defined(VTY_GROUP)
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0
};

/* LDPd options. */
static struct option longopts[] =
{
	{ "daemon",      no_argument,       NULL, 'd'},
	{ "config_file", required_argument, NULL, 'f'},
	{ "pid_file",    required_argument, NULL, 'i'},
	{ "socket",      required_argument, NULL, 'z'},
	{ "dryrun",      no_argument,       NULL, 'C'},
	{ "help",        no_argument,       NULL, 'h'},
	{ "vty_addr",    required_argument, NULL, 'A'},
	{ "vty_port",    required_argument, NULL, 'P'},
	{ "user",        required_argument, NULL, 'u'},
	{ "group",       required_argument, NULL, 'g'},
	{ "version",     no_argument,       NULL, 'v'},
	{ 0 }
};

/* Help information display. */
static void __attribute__ ((noreturn))
usage(char *progname, int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n",
		    progname);
	else {
		printf("Usage : %s [OPTION...]\n\
Daemon which manages LDP.\n\n\
-d, --daemon       Runs in daemon mode\n\
-f, --config_file  Set configuration file name\n\
-i, --pid_file     Set process identifier file name\n\
-z, --socket       Set path of zebra socket\n\
-A, --vty_addr     Set vty's bind address\n\
-P, --vty_port     Set vty's port number\n\
-u, --user         User to run as\n\
-g, --group        Group to run as\n\
-v, --version      Print program version\n\
-C, --dryrun       Check configuration for validity and exit\n\
-h, --help         Display this help and exit\n\
\n\
Report bugs to %s\n", progname, ZEBRA_BUG_ADDRESS);
	}

	exit(status);
}

/* SIGHUP handler. */
static void
sighup(void)
{
	log_info("SIGHUP received");
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
	zlog_rotate(NULL);
}

static struct quagga_signal_t ldp_signals[] =
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

int
main(int argc, char *argv[])
{
	char			*saved_argv0;
	int			 lflag = 0, eflag = 0;
	int			 pipe_parent2ldpe[2];
	int			 pipe_parent2lde[2];
	char			*p;
	char			*vty_addr = NULL;
	int			 vty_port = LDP_VTY_PORT;
	int			 daemon_mode = 0;
	const char		*user = NULL;
	const char		*group = NULL;
	char			*config_file = NULL;
	char			*progname;
	struct thread		 thread;
	int			 dryrun = 0;

	ldpd_process = PROC_MAIN;

	/* Set umask before anything for security */
	umask(0027);

	/* get program name */
	progname = ((p = strrchr(argv[0], '/')) ? ++p : argv[0]);

	saved_argv0 = argv[0];
	if (saved_argv0 == NULL)
		saved_argv0 = (char *)"ldpd";

	while (1) {
		int opt;

		opt = getopt_long(argc, argv, "df:i:z:hA:P:u:g:vCLE",
		    longopts, 0);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		case 'd':
			daemon_mode = 1;
			break;
		case 'f':
			config_file = optarg;
			break;
		case 'A':
			vty_addr = optarg;
			break;
		case 'i':
			pid_file = optarg;
			break;
		case 'z':
			zclient_serv_path_set(optarg);
			break;
		case 'P':
			/*
			 * Deal with atoi() returning 0 on failure, and ldpd
			 * not listening on ldpd port.
			 */
			if (strcmp(optarg, "0") == 0) {
				vty_port = 0;
				break;
			}
			vty_port = atoi(optarg);
			if (vty_port <= 0 || vty_port > 0xffff)
				vty_port = LDP_VTY_PORT;
			break;
		case 'u':
			user = optarg;
			break;
		case 'g':
			group = optarg;
			break;
		case 'v':
			print_version(progname);
			exit(0);
			break;
		case 'C':
			dryrun = 1;
			break;
		case 'h':
			usage(progname, 0);
			break;
		case 'L':
			lflag = 1;
			break;
		case 'E':
			eflag = 1;
			break;
		default:
			usage(progname, 1);
			break;
		}
	}

	argc -= optind;
	argv += optind;
	if (argc > 0 || (lflag && eflag))
		usage(progname, 1);

	/* check for root privileges  */
	if (geteuid() != 0) {
		errno = EPERM;
		perror(progname);
		exit(1);
	}

	zlog_default = openzlog(progname, ZLOG_LDP, 0,
	    LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);

	if (lflag)
		lde(user, group);
	else if (eflag)
		ldpe(user, group);

  	master = thread_master_create();

	cmd_init(1);
	vty_config_lockless ();
	vty_init(master);
	vrf_init();
	ldp_vty_init();
	ldp_vty_if_init();

	/* Get configuration file. */
	ldpd_conf = config_new_empty();
	ldp_config_reset_main(ldpd_conf, NULL);
	vty_read_config(config_file, config_default);

	/* Start execution only if not in dry-run mode */
	if (dryrun)
		exit(0);

	QOBJ_REG (ldpd_conf, ldpd_conf);

	if (daemon_mode && daemon(0, 0) < 0) {
		log_warn("LDPd daemon failed");
		exit(1);
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pipe_parent2ldpe) == -1)
		fatal("socketpair");
	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, pipe_parent2lde) == -1)
		fatal("socketpair");
	sock_set_nonblock(pipe_parent2ldpe[0]);
	sock_set_cloexec(pipe_parent2ldpe[0]);
	sock_set_nonblock(pipe_parent2ldpe[1]);
	sock_set_cloexec(pipe_parent2ldpe[1]);
	sock_set_nonblock(pipe_parent2lde[0]);
	sock_set_cloexec(pipe_parent2lde[0]);
	sock_set_nonblock(pipe_parent2lde[1]);
	sock_set_cloexec(pipe_parent2lde[1]);

	/* start children */
	lde_pid = start_child(PROC_LDE_ENGINE, saved_argv0,
	    pipe_parent2lde[1], user, group);
	ldpe_pid = start_child(PROC_LDP_ENGINE, saved_argv0,
	    pipe_parent2ldpe[1], user, group);

	/* drop privileges */
	if (user)
		ldpd_privs.user = user;
	if (group)
		ldpd_privs.group = group;
	zprivs_init(&ldpd_privs);

	/* setup signal handler */
	signal_init(master, array_size(ldp_signals), ldp_signals);

	/* library inits */
	ldp_zebra_init(master);

	/* setup pipes to children */
	if ((iev_ldpe = malloc(sizeof(struct imsgev))) == NULL ||
	    (iev_lde = malloc(sizeof(struct imsgev))) == NULL)
		fatal(NULL);
	imsg_init(&iev_ldpe->ibuf, pipe_parent2ldpe[0]);
	iev_ldpe->handler_read = main_dispatch_ldpe;
	iev_ldpe->ev_read = thread_add_read(master, iev_ldpe->handler_read,
	    iev_ldpe, iev_ldpe->ibuf.fd);
	iev_ldpe->handler_write = ldp_write_handler;
	iev_ldpe->ev_write = NULL;

	imsg_init(&iev_lde->ibuf, pipe_parent2lde[0]);
	iev_lde->handler_read = main_dispatch_lde;
	iev_lde->ev_read = thread_add_read(master, iev_lde->handler_read,
	    iev_lde, iev_lde->ibuf.fd);
	iev_lde->handler_write = ldp_write_handler;
	iev_lde->ev_write = NULL;

	if (main_imsg_send_ipc_sockets(&iev_ldpe->ibuf, &iev_lde->ibuf))
		fatal("could not establish imsg links");
	main_imsg_compose_both(IMSG_DEBUG_UPDATE, &ldp_debug,
	    sizeof(ldp_debug));
	main_imsg_send_config(ldpd_conf);

	if (ldpd_conf->ipv4.flags & F_LDPD_AF_ENABLED)
		main_imsg_send_net_sockets(AF_INET);
	if (ldpd_conf->ipv6.flags & F_LDPD_AF_ENABLED)
		main_imsg_send_net_sockets(AF_INET6);

	/* Process id file create. */
	pid_output(pid_file);

	/* Create VTY socket */
	vty_serv_sock(vty_addr, vty_port, LDP_VTYSH_PATH);

	/* Print banner. */
	log_notice("LDPd %s starting: vty@%d", QUAGGA_VERSION, vty_port);

	/* Fetch next active thread. */
	while (thread_fetch(master, &thread))
		thread_call(&thread);

	/* NOTREACHED */
	return (0);
}

static void
ldpd_shutdown(void)
{
	pid_t		 pid;
	int		 status;

	/* close pipes */
	msgbuf_clear(&iev_ldpe->ibuf.w);
	close(iev_ldpe->ibuf.fd);
	msgbuf_clear(&iev_lde->ibuf.w);
	close(iev_lde->ibuf.fd);

	config_clear(ldpd_conf);

	log_debug("waiting for children to terminate");
	do {
		pid = wait(&status);
		if (pid == -1) {
			if (errno != EINTR && errno != ECHILD)
				fatal("wait");
		} else if (WIFSIGNALED(status))
			log_warnx("%s terminated; signal %d",
			    (pid == lde_pid) ? "label decision engine" :
			    "ldp engine", WTERMSIG(status));
	} while (pid != -1 || (pid == -1 && errno == EINTR));

	free(iev_ldpe);
	free(iev_lde);

	log_info("terminating");
	exit(0);
}

static pid_t
start_child(enum ldpd_process p, char *argv0, int fd, const char *user,
    const char *group)
{
	char	*argv[7];
	int	 argc = 0;
	pid_t	 pid;

	switch (pid = fork()) {
	case -1:
		fatal("cannot fork");
	case 0:
		break;
	default:
		close(fd);
		return (pid);
	}

	if (dup2(fd, 3) == -1)
		fatal("cannot setup imsg fd");

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
	if (user) {
		argv[argc++] = (char *)"-u";
		argv[argc++] = (char *)user;
	}
	if (group) {
		argv[argc++] = (char *)"-g";
		argv[argc++] = (char *)group;
	}
	argv[argc++] = NULL;

	execvp(argv0, argv);
	fatal("execvp");
}

/* imsg handling */
/* ARGSUSED */
static int
main_dispatch_ldpe(struct thread *thread)
{
	struct imsgev		*iev = THREAD_ARG(thread);
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
		case IMSG_LOG:
			logit(imsg.hdr.pid, "%s", (const char *)imsg.data);
			break;
		case IMSG_REQUEST_SOCKETS:
			af = imsg.hdr.pid;
			main_imsg_send_net_sockets(af);
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
		THREAD_READ_OFF(iev->ev_read);
		THREAD_WRITE_OFF(iev->ev_write);
		ldpe_pid = 0;
		if (lde_pid == 0)
			ldpd_shutdown();
		else
			kill(lde_pid, SIGTERM);
	}

	return (0);
}

/* ARGSUSED */
static int
main_dispatch_lde(struct thread *thread)
{
	struct imsgev	*iev = THREAD_ARG(thread);
	struct imsgbuf	*ibuf = &iev->ibuf;
	struct imsg	 imsg;
	ssize_t		 n;
	int		 shut = 0;

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
		case IMSG_LOG:
			logit(imsg.hdr.pid, "%s", (const char *)imsg.data);
			break;
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
		case IMSG_KPWLABEL_CHANGE:
			if (imsg.hdr.len - IMSG_HEADER_SIZE !=
			    sizeof(struct kpw))
				fatalx("invalid size of IMSG_KPWLABEL_CHANGE");
			if (kmpw_set(imsg.data))
				log_warnx("%s: error changing pseudowire",
				    __func__);
			break;
		case IMSG_KPWLABEL_DELETE:
			if (imsg.hdr.len - IMSG_HEADER_SIZE !=
			    sizeof(struct kpw))
				fatalx("invalid size of IMSG_KPWLABEL_DELETE");
			if (kmpw_unset(imsg.data))
				log_warnx("%s: error unsetting pseudowire",
				    __func__);
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
		THREAD_READ_OFF(iev->ev_read);
		THREAD_WRITE_OFF(iev->ev_write);
		lde_pid = 0;
		if (ldpe_pid == 0)
			ldpd_shutdown();
		else
			kill(ldpe_pid, SIGTERM);
	}

	return (0);
}

/* ARGSUSED */
int
ldp_write_handler(struct thread *thread)
{
	struct imsgev	*iev = THREAD_ARG(thread);
	struct imsgbuf	*ibuf = &iev->ibuf;
	ssize_t		 n;

	iev->ev_write = NULL;

	if ((n = msgbuf_write(&ibuf->w)) == -1 && errno != EAGAIN)
		fatal("msgbuf_write");
	if (n == 0) {
		/* this pipe is dead, so remove the event handlers */
		THREAD_READ_OFF(iev->ev_read);
		THREAD_WRITE_OFF(iev->ev_write);
		return (0);
	}

	imsg_event_add(iev);

	return (0);
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
	THREAD_READ_ON(master, iev->ev_read, iev->handler_read, iev,
	    iev->ibuf.fd);

	if (iev->ibuf.w.queued)
		THREAD_WRITE_ON(master, iev->ev_write, iev->handler_write, iev,
		    iev->ibuf.fd);
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
		THREAD_WRITE_ON(master, eb->ev, eb->handler, eb->arg,
		    eb->wbuf.fd);
}

void
evbuf_init(struct evbuf *eb, int fd, int (*handler)(struct thread *),
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
	THREAD_WRITE_OFF(eb->ev);
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
		log_warnx("%s: failed to create %s socket for address-family "
		    "%s", __func__, socket_name(type), af_name(af));
		return;
	}

	imsg_compose_event(iev_ldpe, IMSG_SOCKET_NET, af, 0, fd, &type,
	    sizeof(type));
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
	return ((xconf->ipv4.flags & F_LDPD_AF_ENABLED) &&
	    (xconf->ipv6.flags & F_LDPD_AF_ENABLED));
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

	LIST_FOREACH(iface, &xconf->iface_list, entry) {
		if (main_imsg_compose_both(IMSG_RECONF_IFACE, iface,
		    sizeof(*iface)) == -1)
			return (-1);
	}

	LIST_FOREACH(tnbr, &xconf->tnbr_list, entry) {
		if (main_imsg_compose_both(IMSG_RECONF_TNBR, tnbr,
		    sizeof(*tnbr)) == -1)
			return (-1);
	}

	LIST_FOREACH(nbrp, &xconf->nbrp_list, entry) {
		if (main_imsg_compose_both(IMSG_RECONF_NBRP, nbrp,
		    sizeof(*nbrp)) == -1)
			return (-1);
	}

	LIST_FOREACH(l2vpn, &xconf->l2vpn_list, entry) {
		if (main_imsg_compose_both(IMSG_RECONF_L2VPN, l2vpn,
		    sizeof(*l2vpn)) == -1)
			return (-1);

		LIST_FOREACH(lif, &l2vpn->if_list, entry) {
			if (main_imsg_compose_both(IMSG_RECONF_L2VPN_IF, lif,
			    sizeof(*lif)) == -1)
				return (-1);
		}
		LIST_FOREACH(pw, &l2vpn->pw_list, entry) {
			if (main_imsg_compose_both(IMSG_RECONF_L2VPN_PW, pw,
			    sizeof(*pw)) == -1)
				return (-1);
		}
		LIST_FOREACH(pw, &l2vpn->pw_inactive_list, entry) {
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
ldp_reload_ref(struct ldpd_conf *xconf, void **ref)
{
	ldp_config_normalize(xconf, ref);

	if (main_imsg_send_config(xconf) == -1)
		return (-1);

	merge_config_ref(ldpd_conf, xconf, ref);

	return (0);
}

int
ldp_reload(struct ldpd_conf *xconf)
{
	return ldp_reload_ref(xconf, NULL);
}

static void
ldp_config_normalize(struct ldpd_conf *xconf, void **ref)
{
	struct l2vpn		*l2vpn;
	struct l2vpn_pw		*pw;

	if (!(xconf->flags & F_LDPD_ENABLED))
		ldp_config_reset_main(xconf, ref);
	else {
		if (!(xconf->ipv4.flags & F_LDPD_AF_ENABLED))
			ldp_config_reset_af(xconf, AF_INET, ref);
		if (!(xconf->ipv6.flags & F_LDPD_AF_ENABLED))
			ldp_config_reset_af(xconf, AF_INET6, ref);
	}

	LIST_FOREACH(l2vpn, &xconf->l2vpn_list, entry) {
		LIST_FOREACH(pw, &l2vpn->pw_list, entry) {
			if (pw->flags & F_PW_STATIC_NBR_ADDR)
				continue;

			pw->af = AF_INET;
			pw->addr.v4 = pw->lsr_id;
		}
		LIST_FOREACH(pw, &l2vpn->pw_inactive_list, entry) {
			if (pw->flags & F_PW_STATIC_NBR_ADDR)
				continue;

			pw->af = AF_INET;
			pw->addr.v4 = pw->lsr_id;
		}
	}
}

static void
ldp_config_reset_main(struct ldpd_conf *conf, void **ref)
{
	struct iface		*iface;
	struct nbr_params	*nbrp;

	while ((iface = LIST_FIRST(&conf->iface_list)) != NULL) {
		if (ref && *ref == iface)
			*ref = NULL;
		LIST_REMOVE(iface, entry);
		free(iface);
	}

	while ((nbrp = LIST_FIRST(&conf->nbrp_list)) != NULL) {
		if (ref && *ref == nbrp)
			*ref = NULL;
		LIST_REMOVE(nbrp, entry);
		free(nbrp);
	}

	conf->rtr_id.s_addr = INADDR_ANY;
	ldp_config_reset_af(conf, AF_INET, ref);
	ldp_config_reset_af(conf, AF_INET6, ref);
	conf->lhello_holdtime = LINK_DFLT_HOLDTIME;
	conf->lhello_interval = DEFAULT_HELLO_INTERVAL;
	conf->thello_holdtime = TARGETED_DFLT_HOLDTIME;
	conf->thello_interval = DEFAULT_HELLO_INTERVAL;
	conf->trans_pref = DUAL_STACK_LDPOV6;
	conf->flags = 0;
}

static void
ldp_config_reset_af(struct ldpd_conf *conf, int af, void **ref)
{
	struct ldpd_af_conf	*af_conf;
	struct iface		*iface;
	struct iface_af		*ia;
	struct tnbr		*tnbr, *ttmp;

	LIST_FOREACH(iface, &conf->iface_list, entry) {
		ia = iface_af_get(iface, af);
		ia->enabled = 0;
	}

	LIST_FOREACH_SAFE(tnbr, &conf->tnbr_list, entry, ttmp) {
		if (tnbr->af != af)
			continue;

		if (ref && *ref == tnbr)
			*ref = NULL;
		LIST_REMOVE(tnbr, entry);
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

struct ldpd_conf *
ldp_dup_config_ref(struct ldpd_conf *conf, void **ref)
{
	struct ldpd_conf	*xconf;
	struct iface		*iface, *xi;
	struct tnbr		*tnbr, *xt;
	struct nbr_params	*nbrp, *xn;
	struct l2vpn		*l2vpn, *xl;
	struct l2vpn_if		*lif, *xf;
	struct l2vpn_pw		*pw, *xp;

#define COPY(a, b) do { \
		a = calloc(1, sizeof(*a)); \
		if (a == NULL) \
			fatal(__func__); \
		*a = *b; \
		if (ref && *ref == b) *ref = a; \
	} while (0)

	COPY(xconf, conf);
	LIST_INIT(&xconf->iface_list);
	LIST_INIT(&xconf->tnbr_list);
	LIST_INIT(&xconf->nbrp_list);
	LIST_INIT(&xconf->l2vpn_list);

	LIST_FOREACH(iface, &conf->iface_list, entry) {
		COPY(xi, iface);
		xi->ipv4.iface = xi;
		xi->ipv6.iface = xi;
		LIST_INSERT_HEAD(&xconf->iface_list, xi, entry);
	}
	LIST_FOREACH(tnbr, &conf->tnbr_list, entry) {
		COPY(xt, tnbr);
		LIST_INSERT_HEAD(&xconf->tnbr_list, xt, entry);
	}
	LIST_FOREACH(nbrp, &conf->nbrp_list, entry) {
		COPY(xn, nbrp);
		LIST_INSERT_HEAD(&xconf->nbrp_list, xn, entry);
	}
	LIST_FOREACH(l2vpn, &conf->l2vpn_list, entry) {
		COPY(xl, l2vpn);
		LIST_INIT(&xl->if_list);
		LIST_INIT(&xl->pw_list);
		LIST_INIT(&xl->pw_inactive_list);
		LIST_INSERT_HEAD(&xconf->l2vpn_list, xl, entry);

		LIST_FOREACH(lif, &l2vpn->if_list, entry) {
			COPY(xf, lif);
			xf->l2vpn = xl;
			LIST_INSERT_HEAD(&xl->if_list, xf, entry);
		}
		LIST_FOREACH(pw, &l2vpn->pw_list, entry) {
			COPY(xp, pw);
			xp->l2vpn = xl;
			LIST_INSERT_HEAD(&xl->pw_list, xp, entry);
		}
		LIST_FOREACH(pw, &l2vpn->pw_inactive_list, entry) {
			COPY(xp, pw);
			xp->l2vpn = xl;
			LIST_INSERT_HEAD(&xl->pw_inactive_list, xp, entry);
		}
	}
#undef COPY

	return (xconf);
}

struct ldpd_conf *
ldp_dup_config(struct ldpd_conf *conf)
{
	return ldp_dup_config_ref(conf, NULL);
}

void
ldp_clear_config(struct ldpd_conf *xconf)
{
	struct iface		*iface;
	struct tnbr		*tnbr;
	struct nbr_params	*nbrp;
	struct l2vpn		*l2vpn;

	while ((iface = LIST_FIRST(&xconf->iface_list)) != NULL) {
		LIST_REMOVE(iface, entry);
		free(iface);
	}
	while ((tnbr = LIST_FIRST(&xconf->tnbr_list)) != NULL) {
		LIST_REMOVE(tnbr, entry);
		free(tnbr);
	}
	while ((nbrp = LIST_FIRST(&xconf->nbrp_list)) != NULL) {
		LIST_REMOVE(nbrp, entry);
		free(nbrp);
	}
	while ((l2vpn = LIST_FIRST(&xconf->l2vpn_list)) != NULL) {
		LIST_REMOVE(l2vpn, entry);
		l2vpn_del(l2vpn);
	}

	free(xconf);
}

static void
merge_config_ref(struct ldpd_conf *conf, struct ldpd_conf *xconf, void **ref)
{
	merge_global(conf, xconf);
	merge_af(AF_INET, &conf->ipv4, &xconf->ipv4);
	merge_af(AF_INET6, &conf->ipv6, &xconf->ipv6);
	merge_ifaces(conf, xconf, ref);
	merge_tnbrs(conf, xconf, ref);
	merge_nbrps(conf, xconf, ref);
	merge_l2vpns(conf, xconf, ref);
	if (ref && *ref == xconf)
		*ref = conf;
	free(xconf);
}

void
merge_config(struct ldpd_conf *conf, struct ldpd_conf *xconf)
{
	merge_config_ref(conf, xconf, NULL);
}

static void
merge_global(struct ldpd_conf *conf, struct ldpd_conf *xconf)
{
	/* change of router-id requires resetting all neighborships */
	if (conf->rtr_id.s_addr != xconf->rtr_id.s_addr) {
		if (ldpd_process == PROC_LDP_ENGINE) {
			ldpe_reset_nbrs(AF_INET);
			ldpe_reset_nbrs(AF_INET6);
			if (conf->rtr_id.s_addr == INADDR_ANY ||
			    xconf->rtr_id.s_addr == INADDR_ANY) {
				if_update_all(AF_UNSPEC);
				tnbr_update_all(AF_UNSPEC);
			}
		}
		conf->rtr_id = xconf->rtr_id;
	}

	conf->lhello_holdtime = xconf->lhello_holdtime;
	conf->lhello_interval = xconf->lhello_interval;
	conf->thello_holdtime = xconf->thello_holdtime;
	conf->thello_interval = xconf->thello_interval;

	if (conf->trans_pref != xconf->trans_pref) {
		if (ldpd_process == PROC_LDP_ENGINE)
			ldpe_reset_ds_nbrs();
		conf->trans_pref = xconf->trans_pref;
	}

	if ((conf->flags & F_LDPD_DS_CISCO_INTEROP) !=
	    (xconf->flags & F_LDPD_DS_CISCO_INTEROP)) {
		if (ldpd_process == PROC_LDP_ENGINE)
			ldpe_reset_ds_nbrs();
	}

	conf->flags = xconf->flags;
}

static void
merge_af(int af, struct ldpd_af_conf *af_conf, struct ldpd_af_conf *xa)
{
	int			 egress_label_changed = 0;
	int			 update_sockets = 0;

	if (af_conf->keepalive != xa->keepalive) {
		af_conf->keepalive = xa->keepalive;
		if (ldpd_process == PROC_LDP_ENGINE)
			ldpe_stop_init_backoff(af);
	}

	af_conf->lhello_holdtime = xa->lhello_holdtime;
	af_conf->lhello_interval = xa->lhello_interval;
	af_conf->thello_holdtime = xa->thello_holdtime;
	af_conf->thello_interval = xa->thello_interval;

	/* update flags */
	if (ldpd_process == PROC_LDP_ENGINE &&
	    (af_conf->flags & F_LDPD_AF_THELLO_ACCEPT) &&
	    !(xa->flags & F_LDPD_AF_THELLO_ACCEPT))
		ldpe_remove_dynamic_tnbrs(af);

	if ((af_conf->flags & F_LDPD_AF_NO_GTSM) !=
	    (xa->flags & F_LDPD_AF_NO_GTSM)) {
		if (af == AF_INET6)
			/* need to set/unset IPV6_MINHOPCOUNT */
			update_sockets = 1;
		else if (ldpd_process == PROC_LDP_ENGINE)
			/* for LDPv4 just resetting the neighbors is enough */
			ldpe_reset_nbrs(af);
	}

	if ((af_conf->flags & F_LDPD_AF_EXPNULL) !=
	    (xa->flags & F_LDPD_AF_EXPNULL))
		egress_label_changed = 1;

	af_conf->flags = xa->flags;

	if (egress_label_changed) {
		switch (ldpd_process) {
		case PROC_LDE_ENGINE:
			lde_change_egress_label(af, af_conf->flags &
			    F_LDPD_AF_EXPNULL);
			break;
		default:
			break;
		}
	}

	if (ldp_addrcmp(af, &af_conf->trans_addr, &xa->trans_addr)) {
		af_conf->trans_addr = xa->trans_addr;
		update_sockets = 1;
	}

	if (ldpd_process == PROC_MAIN && iev_ldpe && update_sockets)
		imsg_compose_event(iev_ldpe, IMSG_CLOSE_SOCKETS, af, 0, -1,
		    NULL, 0);
}

static void
merge_ifaces(struct ldpd_conf *conf, struct ldpd_conf *xconf, void **ref)
{
	struct iface		*iface, *itmp, *xi;

	LIST_FOREACH_SAFE(iface, &conf->iface_list, entry, itmp) {
		/* find deleted interfaces */
		if ((xi = if_lookup_name(xconf, iface->name)) == NULL) {
			LIST_REMOVE(iface, entry);

			switch (ldpd_process) {
			case PROC_LDE_ENGINE:
				break;
			case PROC_LDP_ENGINE:
				if_exit(iface);
				break;
			case PROC_MAIN:
				QOBJ_UNREG (iface);
				break;
			}
			free(iface);
		}
	}
	LIST_FOREACH_SAFE(xi, &xconf->iface_list, entry, itmp) {
		/* find new interfaces */
		if ((iface = if_lookup_name(conf, xi->name)) == NULL) {
			LIST_REMOVE(xi, entry);
			LIST_INSERT_HEAD(&conf->iface_list, xi, entry);

			if (ldpd_process == PROC_MAIN) {
				QOBJ_REG (xi, iface);
				/* resend addresses to activate new interfaces */
				kif_redistribute(xi->name);
			}
			continue;
		}

		/* update existing interfaces */
		merge_iface_af(&iface->ipv4, &xi->ipv4);
		merge_iface_af(&iface->ipv6, &xi->ipv6);
		LIST_REMOVE(xi, entry);
		if (ref && *ref == xi)
			*ref = iface;
		free(xi);
	}
}

static void
merge_iface_af(struct iface_af *ia, struct iface_af *xi)
{
	if (ia->enabled != xi->enabled) {
		ia->enabled = xi->enabled;
		if (ldpd_process == PROC_LDP_ENGINE)
			if_update(ia->iface, ia->af);
	}
	ia->hello_holdtime = xi->hello_holdtime;
	ia->hello_interval = xi->hello_interval;
}

static void
merge_tnbrs(struct ldpd_conf *conf, struct ldpd_conf *xconf, void **ref)
{
	struct tnbr		*tnbr, *ttmp, *xt;

	LIST_FOREACH_SAFE(tnbr, &conf->tnbr_list, entry, ttmp) {
		if (!(tnbr->flags & F_TNBR_CONFIGURED))
			continue;

		/* find deleted tnbrs */
		if ((xt = tnbr_find(xconf, tnbr->af, &tnbr->addr)) == NULL) {
			switch (ldpd_process) {
			case PROC_LDE_ENGINE:
				LIST_REMOVE(tnbr, entry);
				free(tnbr);
				break;
			case PROC_LDP_ENGINE:
				tnbr->flags &= ~F_TNBR_CONFIGURED;
				tnbr_check(tnbr);
				break;
			case PROC_MAIN:
				LIST_REMOVE(tnbr, entry);
				QOBJ_UNREG (tnbr);
				free(tnbr);
				break;
			}
		}
	}
	LIST_FOREACH_SAFE(xt, &xconf->tnbr_list, entry, ttmp) {
		/* find new tnbrs */
		if ((tnbr = tnbr_find(conf, xt->af, &xt->addr)) == NULL) {
			LIST_REMOVE(xt, entry);
			LIST_INSERT_HEAD(&conf->tnbr_list, xt, entry);

			switch (ldpd_process) {
			case PROC_LDE_ENGINE:
				break;
			case PROC_LDP_ENGINE:
				tnbr_update(xt);
				break;
			case PROC_MAIN:
				QOBJ_REG (xt, tnbr);
				break;
			}
			continue;
		}

		/* update existing tnbrs */
		if (!(tnbr->flags & F_TNBR_CONFIGURED))
			tnbr->flags |= F_TNBR_CONFIGURED;
		LIST_REMOVE(xt, entry);
		if (ref && *ref == xt)
			*ref = tnbr;
		free(xt);
	}
}

static void
merge_nbrps(struct ldpd_conf *conf, struct ldpd_conf *xconf, void **ref)
{
	struct nbr_params	*nbrp, *ntmp, *xn;
	struct nbr		*nbr;
	int			 nbrp_changed;

	LIST_FOREACH_SAFE(nbrp, &conf->nbrp_list, entry, ntmp) {
		/* find deleted nbrps */
		if ((xn = nbr_params_find(xconf, nbrp->lsr_id)) == NULL) {
			switch (ldpd_process) {
			case PROC_LDE_ENGINE:
				break;
			case PROC_LDP_ENGINE:
				nbr = nbr_find_ldpid(nbrp->lsr_id.s_addr);
				if (nbr) {
					session_shutdown(nbr, S_SHUTDOWN, 0, 0);
#ifdef __OpenBSD__
					pfkey_remove(nbr);
#else
					sock_set_md5sig(
					    (ldp_af_global_get(&global,
					    nbr->af))->ldp_session_socket,
					    nbr->af, &nbr->raddr, NULL);
#endif
					if (nbr_session_active_role(nbr))
						nbr_establish_connection(nbr);
				}
				break;
			case PROC_MAIN:
				QOBJ_UNREG (nbrp);
				break;
			}
			LIST_REMOVE(nbrp, entry);
			free(nbrp);
		}
	}
	LIST_FOREACH_SAFE(xn, &xconf->nbrp_list, entry, ntmp) {
		/* find new nbrps */
		if ((nbrp = nbr_params_find(conf, xn->lsr_id)) == NULL) {
			LIST_REMOVE(xn, entry);
			LIST_INSERT_HEAD(&conf->nbrp_list, xn, entry);

			switch (ldpd_process) {
			case PROC_LDE_ENGINE:
				break;
			case PROC_LDP_ENGINE:
				nbr = nbr_find_ldpid(xn->lsr_id.s_addr);
				if (nbr) {
					session_shutdown(nbr, S_SHUTDOWN, 0, 0);
#ifdef __OpenBSD__
					if (pfkey_establish(nbr, xn) == -1)
						fatalx("pfkey setup failed");
#else
					sock_set_md5sig(
					    (ldp_af_global_get(&global,
					    nbr->af))->ldp_session_socket,
					    nbr->af, &nbr->raddr,
					    xn->auth.md5key);
#endif
					if (nbr_session_active_role(nbr))
						nbr_establish_connection(nbr);
				}
				break;
			case PROC_MAIN:
				QOBJ_REG (xn, nbr_params);
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
				if (pfkey_establish(nbr, nbrp) == -1)
					fatalx("pfkey setup failed");
#else
				sock_set_md5sig((ldp_af_global_get(&global,
				    nbr->af))->ldp_session_socket, nbr->af,
				    &nbr->raddr, nbrp->auth.md5key);
#endif
				if (nbr_session_active_role(nbr))
					nbr_establish_connection(nbr);
			}
		}
		LIST_REMOVE(xn, entry);
		if (ref && *ref == xn)
			*ref = nbrp;
		free(xn);
	}
}

static void
merge_l2vpns(struct ldpd_conf *conf, struct ldpd_conf *xconf, void **ref)
{
	struct l2vpn		*l2vpn, *ltmp, *xl;
	struct l2vpn_if		*lif;
	struct l2vpn_pw		*pw;

	LIST_FOREACH_SAFE(l2vpn, &conf->l2vpn_list, entry, ltmp) {
		/* find deleted l2vpns */
		if ((xl = l2vpn_find(xconf, l2vpn->name)) == NULL) {
			LIST_REMOVE(l2vpn, entry);

			switch (ldpd_process) {
			case PROC_LDE_ENGINE:
				l2vpn_exit(l2vpn);
				break;
			case PROC_LDP_ENGINE:
				ldpe_l2vpn_exit(l2vpn);
				break;
			case PROC_MAIN:
				LIST_FOREACH(lif, &l2vpn->if_list, entry)
					QOBJ_UNREG (lif);
				LIST_FOREACH(pw, &l2vpn->pw_list, entry)
					QOBJ_UNREG (pw);
				LIST_FOREACH(pw, &l2vpn->pw_inactive_list, entry)
					QOBJ_UNREG (pw);
				QOBJ_UNREG (l2vpn);
				break;
			}
			l2vpn_del(l2vpn);
		}
	}
	LIST_FOREACH_SAFE(xl, &xconf->l2vpn_list, entry, ltmp) {
		/* find new l2vpns */
		if ((l2vpn = l2vpn_find(conf, xl->name)) == NULL) {
			LIST_REMOVE(xl, entry);
			LIST_INSERT_HEAD(&conf->l2vpn_list, xl, entry);

			switch (ldpd_process) {
			case PROC_LDE_ENGINE:
				l2vpn_init(xl);
				break;
			case PROC_LDP_ENGINE:
				ldpe_l2vpn_init(xl);
				break;
			case PROC_MAIN:
				QOBJ_REG (xl, l2vpn);
				break;
			}
			continue;
		}

		/* update existing l2vpns */
		merge_l2vpn(conf, l2vpn, xl, ref);
		LIST_REMOVE(xl, entry);
		if (ref && *ref == xl)
			*ref = l2vpn;
		free(xl);
	}
}

static void
merge_l2vpn(struct ldpd_conf *xconf, struct l2vpn *l2vpn, struct l2vpn *xl, void **ref)
{
	struct l2vpn_if		*lif, *ftmp, *xf;
	struct l2vpn_pw		*pw, *ptmp, *xp;
	struct nbr		*nbr;
	int			 reset_nbr, reinstall_pwfec, reinstall_tnbr;
	LIST_HEAD(, l2vpn_pw)	 pw_aux_list;
	int			 previous_pw_type, previous_mtu;

	previous_pw_type = l2vpn->pw_type;
	previous_mtu = l2vpn->mtu;

	/* merge intefaces */
	LIST_FOREACH_SAFE(lif, &l2vpn->if_list, entry, ftmp) {
		/* find deleted interfaces */
		if ((xf = l2vpn_if_find_name(xl, lif->ifname)) == NULL) {
			if (ldpd_process == PROC_MAIN)
				QOBJ_UNREG (lif);
			LIST_REMOVE(lif, entry);
			free(lif);
		}
	}
	LIST_FOREACH_SAFE(xf, &xl->if_list, entry, ftmp) {
		/* find new interfaces */
		if ((lif = l2vpn_if_find_name(l2vpn, xf->ifname)) == NULL) {
			LIST_REMOVE(xf, entry);
			LIST_INSERT_HEAD(&l2vpn->if_list, xf, entry);
			xf->l2vpn = l2vpn;
			if (ldpd_process == PROC_MAIN)
				QOBJ_REG (xf, l2vpn_if);
			continue;
		}

		LIST_REMOVE(xf, entry);
		if (ref && *ref == xf)
			*ref = lif;
		free(xf);
	}

	/* merge active pseudowires */
	LIST_INIT(&pw_aux_list);
	LIST_FOREACH_SAFE(pw, &l2vpn->pw_list, entry, ptmp) {
		/* find deleted active pseudowires */
		if ((xp = l2vpn_pw_find_name(xl, pw->ifname)) == NULL) {
			switch (ldpd_process) {
			case PROC_LDE_ENGINE:
				l2vpn_pw_exit(pw);
				break;
			case PROC_LDP_ENGINE:
				ldpe_l2vpn_pw_exit(pw);
				break;
			case PROC_MAIN:
				QOBJ_UNREG (pw);
				break;
			}

			LIST_REMOVE(pw, entry);
			free(pw);
		}
	}
	LIST_FOREACH_SAFE(xp, &xl->pw_list, entry, ptmp) {
		/* find new active pseudowires */
		if ((pw = l2vpn_pw_find_name(l2vpn, xp->ifname)) == NULL) {
			LIST_REMOVE(xp, entry);
			LIST_INSERT_HEAD(&l2vpn->pw_list, xp, entry);
			xp->l2vpn = l2vpn;

			switch (ldpd_process) {
			case PROC_LDE_ENGINE:
				l2vpn_pw_init(xp);
				break;
			case PROC_LDP_ENGINE:
				ldpe_l2vpn_pw_init(xp);
				break;
			case PROC_MAIN:
				QOBJ_REG (xp, l2vpn_pw);
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
		if ((pw->flags & (F_PW_STATUSTLV_CONF|F_PW_CWORD_CONF)) !=
		    (xp->flags & (F_PW_STATUSTLV_CONF|F_PW_CWORD_CONF)))
			reset_nbr = 1;
		else
			reset_nbr = 0;

		if (l2vpn->pw_type != xl->pw_type || l2vpn->mtu != xl->mtu ||
		    pw->pwid != xp->pwid || reinstall_tnbr || reset_nbr ||
		    pw->lsr_id.s_addr != xp->lsr_id.s_addr)
			reinstall_pwfec = 1;
		else
			reinstall_pwfec = 0;

		/* check if the pseudowire should be disabled */
		if (xp->lsr_id.s_addr == INADDR_ANY || xp->pwid == 0) {
			reinstall_tnbr = 0;
			reset_nbr = 0;
			reinstall_pwfec = 0;

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

			/* remove from active list */
			LIST_REMOVE(pw, entry);
			LIST_INSERT_HEAD(&pw_aux_list, pw, entry);
		}

		if (ldpd_process == PROC_LDP_ENGINE) {
			if (reinstall_tnbr)
				ldpe_l2vpn_pw_exit(pw);
			if (reset_nbr) {
				nbr = nbr_find_ldpid(pw->lsr_id.s_addr);
				if (nbr && nbr->state == NBR_STA_OPER)
					session_shutdown(nbr, S_SHUTDOWN, 0, 0);
			}
		}
		if (ldpd_process == PROC_LDE_ENGINE &&
		    !reset_nbr && reinstall_pwfec)
			l2vpn_pw_exit(pw);
		pw->lsr_id = xp->lsr_id;
		pw->af = xp->af;
		pw->addr = xp->addr;
		pw->pwid = xp->pwid;
		strlcpy(pw->ifname, xp->ifname, sizeof(pw->ifname));
		pw->ifindex = xp->ifindex;
		if (xp->flags & F_PW_CWORD_CONF)
			pw->flags |= F_PW_CWORD_CONF;
		else
			pw->flags &= ~F_PW_CWORD_CONF;
		if (xp->flags & F_PW_STATUSTLV_CONF)
			pw->flags |= F_PW_STATUSTLV_CONF;
		else
			pw->flags &= ~F_PW_STATUSTLV_CONF;
		if (xp->flags & F_PW_STATIC_NBR_ADDR)
			pw->flags |= F_PW_STATIC_NBR_ADDR;
		else
			pw->flags &= ~F_PW_STATIC_NBR_ADDR;
		if (ldpd_process == PROC_LDP_ENGINE && reinstall_tnbr)
			ldpe_l2vpn_pw_init(pw);
		if (ldpd_process == PROC_LDE_ENGINE &&
		    !reset_nbr && reinstall_pwfec) {
			l2vpn->pw_type = xl->pw_type;
			l2vpn->mtu = xl->mtu;
			l2vpn_pw_init(pw);
			l2vpn->pw_type = previous_pw_type;
			l2vpn->mtu = previous_mtu;
		}

		LIST_REMOVE(xp, entry);
		if (ref && *ref == xp)
			*ref = pw;
		free(xp);
	}

	/* merge inactive pseudowires */
	LIST_FOREACH_SAFE(pw, &l2vpn->pw_inactive_list, entry, ptmp) {
		/* find deleted inactive pseudowires */
		if ((xp = l2vpn_pw_find_name(xl, pw->ifname)) == NULL) {
			LIST_REMOVE(pw, entry);
			if (ldpd_process == PROC_MAIN)
				QOBJ_UNREG (pw);
			free(pw);
		}
	}
	LIST_FOREACH_SAFE(xp, &xl->pw_inactive_list, entry, ptmp) {
		/* find new inactive pseudowires */
		if ((pw = l2vpn_pw_find_name(l2vpn, xp->ifname)) == NULL) {
			LIST_REMOVE(xp, entry);
			LIST_INSERT_HEAD(&l2vpn->pw_inactive_list, xp, entry);
			xp->l2vpn = l2vpn;
			if (ldpd_process == PROC_MAIN)
				QOBJ_REG (xp, l2vpn_pw);
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

		/* check if the pseudowire should be activated */
		if (pw->lsr_id.s_addr != INADDR_ANY && pw->pwid != 0) {
			/* remove from inactive list */
			LIST_REMOVE(pw, entry);
			LIST_INSERT_HEAD(&l2vpn->pw_list, pw, entry);

			switch (ldpd_process) {
			case PROC_LDE_ENGINE:
				l2vpn_pw_init(pw);
				break;
			case PROC_LDP_ENGINE:
				ldpe_l2vpn_pw_init(pw);
				break;
			case PROC_MAIN:
				break;
			}
		}

		LIST_REMOVE(xp, entry);
		if (ref && *ref == xp)
			*ref = pw;
		free(xp);
	}

	/* insert pseudowires that were disabled in the inactive list */
	LIST_FOREACH_SAFE(pw, &pw_aux_list, entry, ptmp) {
		LIST_REMOVE(pw, entry);
		LIST_INSERT_HEAD(&l2vpn->pw_inactive_list, pw, entry);
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

	LIST_INIT(&xconf->iface_list);
	LIST_INIT(&xconf->tnbr_list);
	LIST_INIT(&xconf->nbrp_list);
	LIST_INIT(&xconf->l2vpn_list);

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
	if (ldpd_process == PROC_MAIN)
		QOBJ_UNREG (conf);
	free(conf);
}
