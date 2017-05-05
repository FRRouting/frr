/*	$OpenBSD$ */

/*
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
#include <sys/un.h>

#include "ldpd.h"
#include "ldpe.h"
#include "log.h"
#include "control.h"

#define	CONTROL_BACKLOG	5

static int		 control_accept(struct thread *);
static struct ctl_conn	*control_connbyfd(int);
static struct ctl_conn	*control_connbypid(pid_t);
static void		 control_close(int);
static int		 control_dispatch_imsg(struct thread *);

struct ctl_conns	 ctl_conns;

static int		 control_fd;

int
control_init(char *path)
{
	struct sockaddr_un	 s_un;
	int			 fd;
	mode_t			 old_umask;

	if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		log_warn("%s: socket", __func__);
		return (-1);
	}
	sock_set_nonblock(fd);

	memset(&s_un, 0, sizeof(s_un));
	s_un.sun_family = AF_UNIX;
	strlcpy(s_un.sun_path, path, sizeof(s_un.sun_path));

	if (unlink(path) == -1)
		if (errno != ENOENT) {
			log_warn("%s: unlink %s", __func__, path);
			close(fd);
			return (-1);
		}

	old_umask = umask(S_IXUSR|S_IXGRP|S_IWOTH|S_IROTH|S_IXOTH);
	if (bind(fd, (struct sockaddr *)&s_un, sizeof(s_un)) == -1) {
		log_warn("%s: bind: %s", __func__, path);
		close(fd);
		umask(old_umask);
		return (-1);
	}
	umask(old_umask);

	if (chmod(path, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP) == -1) {
		log_warn("%s: chmod", __func__);
		close(fd);
		(void)unlink(path);
		return (-1);
	}

	control_fd = fd;

	return (0);
}

int
control_listen(void)
{
	if (listen(control_fd, CONTROL_BACKLOG) == -1) {
		log_warn("%s: listen", __func__);
		return (-1);
	}

	return (accept_add(control_fd, control_accept, NULL));
}

void
control_cleanup(char *path)
{
	accept_del(control_fd);
	close(control_fd);
	unlink(path);
}

/* ARGSUSED */
static int
control_accept(struct thread *thread)
{
	int			 connfd;
	socklen_t		 len;
	struct sockaddr_un	 s_un;
	struct ctl_conn		*c;

	len = sizeof(s_un);
	if ((connfd = accept(THREAD_FD(thread), (struct sockaddr *)&s_un,
	    &len)) == -1) {
		/*
		 * Pause accept if we are out of file descriptors, or
		 * libevent will haunt us here too.
		 */
		if (errno == ENFILE || errno == EMFILE)
			accept_pause();
		else if (errno != EWOULDBLOCK && errno != EINTR &&
		    errno != ECONNABORTED)
			log_warn("%s: accept", __func__);
		return (0);
	}
	sock_set_nonblock(connfd);

	if ((c = calloc(1, sizeof(struct ctl_conn))) == NULL) {
		log_warn(__func__);
		close(connfd);
		return (0);
	}

	imsg_init(&c->iev.ibuf, connfd);
	c->iev.handler_read = control_dispatch_imsg;
	c->iev.ev_read = NULL;
	thread_add_read(master, c->iev.handler_read, &c->iev, c->iev.ibuf.fd,
			&c->iev.ev_read);
	c->iev.handler_write = ldp_write_handler;
	c->iev.ev_write = NULL;

	TAILQ_INSERT_TAIL(&ctl_conns, c, entry);

	return (0);
}

static struct ctl_conn *
control_connbyfd(int fd)
{
	struct ctl_conn	*c;

	TAILQ_FOREACH(c, &ctl_conns, entry) {
		if (c->iev.ibuf.fd == fd)
			break;
	}

	return (c);
}

static struct ctl_conn *
control_connbypid(pid_t pid)
{
	struct ctl_conn	*c;

	TAILQ_FOREACH(c, &ctl_conns, entry) {
		if (c->iev.ibuf.pid == pid)
			break;
	}

	return (c);
}

static void
control_close(int fd)
{
	struct ctl_conn	*c;

	if ((c = control_connbyfd(fd)) == NULL) {
		log_warnx("%s: fd %d: not found", __func__, fd);
		return;
	}

	msgbuf_clear(&c->iev.ibuf.w);
	TAILQ_REMOVE(&ctl_conns, c, entry);

	THREAD_READ_OFF(c->iev.ev_read);
	THREAD_WRITE_OFF(c->iev.ev_write);
	close(c->iev.ibuf.fd);
	accept_unpause();
	free(c);
}

/* ARGSUSED */
static int
control_dispatch_imsg(struct thread *thread)
{
	int		 fd = THREAD_FD(thread);
	struct ctl_conn	*c;
	struct imsg	 imsg;
	ssize_t		 n;
	unsigned int	 ifidx;

	if ((c = control_connbyfd(fd)) == NULL) {
		log_warnx("%s: fd %d: not found", __func__, fd);
		return (0);
	}

	c->iev.ev_read = NULL;

	if (((n = imsg_read(&c->iev.ibuf)) == -1 && errno != EAGAIN) ||
	    n == 0) {
		control_close(fd);
		return (0);
	}

	for (;;) {
		if ((n = imsg_get(&c->iev.ibuf, &imsg)) == -1) {
			control_close(fd);
			return (0);
		}

		if (n == 0)
			break;

		switch (imsg.hdr.type) {
		case IMSG_CTL_FIB_COUPLE:
		case IMSG_CTL_FIB_DECOUPLE:
		case IMSG_CTL_RELOAD:
		case IMSG_CTL_KROUTE:
		case IMSG_CTL_KROUTE_ADDR:
		case IMSG_CTL_IFINFO:
			/* ignore */
			break;
		case IMSG_CTL_SHOW_INTERFACE:
			if (imsg.hdr.len == IMSG_HEADER_SIZE +
			    sizeof(ifidx)) {
				memcpy(&ifidx, imsg.data, sizeof(ifidx));
				ldpe_iface_ctl(c, ifidx);
				imsg_compose_event(&c->iev, IMSG_CTL_END, 0,
				    0, -1, NULL, 0);
			}
			break;
		case IMSG_CTL_SHOW_DISCOVERY:
			ldpe_adj_ctl(c);
			break;
		case IMSG_CTL_SHOW_DISCOVERY_DTL:
			ldpe_adj_detail_ctl(c);
			break;
		case IMSG_CTL_SHOW_LIB:
		case IMSG_CTL_SHOW_L2VPN_PW:
		case IMSG_CTL_SHOW_L2VPN_BINDING:
			c->iev.ibuf.pid = imsg.hdr.pid;
			ldpe_imsg_compose_lde(imsg.hdr.type, 0, imsg.hdr.pid,
			    imsg.data, imsg.hdr.len - IMSG_HEADER_SIZE);
			break;
		case IMSG_CTL_SHOW_NBR:
			ldpe_nbr_ctl(c);
			break;
		case IMSG_CTL_CLEAR_NBR:
			if (imsg.hdr.len != IMSG_HEADER_SIZE +
			    sizeof(struct ctl_nbr))
				break;

			nbr_clear_ctl(imsg.data);
			break;
		case IMSG_CTL_LOG_VERBOSE:
			/* ignore */
			break;
		default:
			log_debug("%s: error handling imsg %d", __func__,
			    imsg.hdr.type);
			break;
		}
		imsg_free(&imsg);
	}

	imsg_event_add(&c->iev);

	return (0);
}

int
control_imsg_relay(struct imsg *imsg)
{
	struct ctl_conn	*c;

	if ((c = control_connbypid(imsg->hdr.pid)) == NULL)
		return (0);

	return (imsg_compose_event(&c->iev, imsg->hdr.type, 0, imsg->hdr.pid,
	    -1, imsg->data, imsg->hdr.len - IMSG_HEADER_SIZE));
}
