// SPDX-License-Identifier: ISC
/*	$OpenBSD$	*/

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 */

#include <zebra.h>

#include "memory.h"
#include "queue.h"
#include "imsg.h"

static int imsg_fd_overhead = 0;

static int imsg_get_fd(struct imsgbuf *);

#ifndef __OpenBSD__
/*
 * The original code calls getdtablecount() which is OpenBSD specific. Use
 * available_fds() from OpenSMTPD instead.
 */
static int available_fds(unsigned int n)
{
	unsigned int i;
	int ret, fds[256];

	if (n > (unsigned int)array_size(fds))
		return 1;

	ret = 0;
	for (i = 0; i < n; i++) {
		fds[i] = -1;
		if ((fds[i] = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
			if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT)
				fds[i] = socket(AF_INET6, SOCK_DGRAM, 0);
			if (fds[i] < 0) {
				ret = 1;
				break;
			}
		}
	}

	for (i = 0; i < n && fds[i] >= 0; i++)
		close(fds[i]);

	return (ret);
}
#endif

void imsg_init(struct imsgbuf *ibuf, int fd)
{
	msgbuf_init(&ibuf->w);
	memset(&ibuf->r, 0, sizeof(ibuf->r));
	ibuf->fd = fd;
	ibuf->w.fd = fd;
	ibuf->pid = getpid();
	TAILQ_INIT(&ibuf->fds);
}

ssize_t imsg_read(struct imsgbuf *ibuf)
{
	struct msghdr msg;
	struct cmsghdr *cmsg;
	union {
		struct cmsghdr hdr;
		char buf[CMSG_SPACE(sizeof(int) * 1)];
	} cmsgbuf;
	struct iovec iov;
	ssize_t n;
	int fd;
	struct imsg_fd *ifd;

	memset(&msg, 0, sizeof(msg));
	memset(&cmsgbuf, 0, sizeof(cmsgbuf));

	iov.iov_base = ibuf->r.buf + ibuf->r.wpos;
	iov.iov_len = sizeof(ibuf->r.buf) - ibuf->r.wpos;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	if ((ifd = calloc(1, sizeof(struct imsg_fd))) == NULL)
		return -1;

again:
#ifdef __OpenBSD__
	if (getdtablecount() + imsg_fd_overhead
		    + (int)((CMSG_SPACE(sizeof(int)) - CMSG_SPACE(0))
			    / sizeof(int))
	    >= getdtablesize()) {
#else
	if (available_fds(imsg_fd_overhead
			  + (CMSG_SPACE(sizeof(int)) - CMSG_SPACE(0))
				    / sizeof(int))) {
#endif
		errno = EAGAIN;
		free(ifd);
		return -1;
	}

	n = recvmsg(ibuf->fd, &msg, 0);
	if (n == -1) {
		if (errno == EINTR)
			goto again;
		goto fail;
	}

	ibuf->r.wpos += n;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET
		    && cmsg->cmsg_type == SCM_RIGHTS) {
			int i;
			int j;

			/*
			 * We only accept one file descriptor.  Due to C
			 * padding rules, our control buffer might contain
			 * more than one fd, and we must close them.
			 */
			j = ((char *)cmsg + cmsg->cmsg_len
			     - (char *)CMSG_DATA(cmsg))
			    / sizeof(int);
			for (i = 0; i < j; i++) {
				fd = ((int *)CMSG_DATA(cmsg))[i];
				if (ifd != NULL) {
					ifd->fd = fd;
					TAILQ_INSERT_TAIL(&ibuf->fds, ifd,
							  entry);
					ifd = NULL;
				} else
					close(fd);
			}
		}
		/* we do not handle other ctl data level */
	}

fail:
	free(ifd);
	return (n);
}

ssize_t imsg_get(struct imsgbuf *ibuf, struct imsg *imsg)
{
	size_t av, left, datalen;

	av = ibuf->r.wpos;

	if (IMSG_HEADER_SIZE > av)
		return 0;

	memcpy(&imsg->hdr, ibuf->r.buf, sizeof(imsg->hdr));
	if (imsg->hdr.len < IMSG_HEADER_SIZE || imsg->hdr.len > MAX_IMSGSIZE) {
		errno = ERANGE;
		return -1;
	}
	if (imsg->hdr.len > av)
		return 0;
	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	ibuf->r.rptr = ibuf->r.buf + IMSG_HEADER_SIZE;
	if (datalen == 0)
		imsg->data = NULL;
	else if ((imsg->data = malloc(datalen)) == NULL)
		return -1;

	if (imsg->hdr.flags & IMSGF_HASFD)
		imsg->fd = imsg_get_fd(ibuf);
	else
		imsg->fd = -1;

	if (imsg->data)
		memcpy(imsg->data, ibuf->r.rptr, datalen);

	if (imsg->hdr.len < av) {
		left = av - imsg->hdr.len;
		memmove(&ibuf->r.buf, ibuf->r.buf + imsg->hdr.len, left);
		ibuf->r.wpos = left;
	} else
		ibuf->r.wpos = 0;

	return (datalen + IMSG_HEADER_SIZE);
}

int imsg_compose(struct imsgbuf *ibuf, uint32_t type, uint32_t peerid,
		 pid_t pid, int fd, const void *data, uint16_t datalen)
{
	struct ibuf *wbuf;

	if ((wbuf = imsg_create(ibuf, type, peerid, pid, datalen)) == NULL)
		return -1;

	if (imsg_add(wbuf, data, datalen) == -1)
		return -1;

	wbuf->fd = fd;

	imsg_close(ibuf, wbuf);

	return 1;
}

int imsg_composev(struct imsgbuf *ibuf, uint32_t type, uint32_t peerid,
		  pid_t pid, int fd, const struct iovec *iov, int iovcnt)
{
	struct ibuf *wbuf;
	int i, datalen = 0;

	for (i = 0; i < iovcnt; i++)
		datalen += iov[i].iov_len;

	if ((wbuf = imsg_create(ibuf, type, peerid, pid, datalen)) == NULL)
		return -1;

	for (i = 0; i < iovcnt; i++)
		if (imsg_add(wbuf, iov[i].iov_base, iov[i].iov_len) == -1)
			return -1;

	wbuf->fd = fd;

	imsg_close(ibuf, wbuf);

	return 1;
}

/* ARGSUSED */
struct ibuf *imsg_create(struct imsgbuf *ibuf, uint32_t type, uint32_t peerid,
			 pid_t pid, uint16_t datalen)
{
	struct ibuf *wbuf;
	struct imsg_hdr hdr;

	memset(&hdr, 0x00, IMSG_HEADER_SIZE);

	datalen += IMSG_HEADER_SIZE;
	if (datalen > MAX_IMSGSIZE) {
		errno = ERANGE;
		return NULL;
	}

	hdr.type = type;
	hdr.flags = 0;
	hdr.peerid = peerid;
	if ((hdr.pid = pid) == 0)
		hdr.pid = ibuf->pid;
	if ((wbuf = ibuf_dynamic(datalen, MAX_IMSGSIZE)) == NULL) {
		return NULL;
	}
	if (imsg_add(wbuf, &hdr, sizeof(hdr)) == -1)
		return NULL;

	return (wbuf);
}

int imsg_add(struct ibuf *msg, const void *data, uint16_t datalen)
{
	if (datalen)
		if (ibuf_add(msg, data, datalen) == -1) {
			ibuf_free(msg);
			return -1;
		}
	return (datalen);
}

void imsg_close(struct imsgbuf *ibuf, struct ibuf *msg)
{
	struct imsg_hdr *hdr;

	hdr = (struct imsg_hdr *)msg->buf;

	hdr->flags &= ~IMSGF_HASFD;
	if (msg->fd != -1)
		hdr->flags |= IMSGF_HASFD;

	hdr->len = (uint16_t)msg->wpos;

	ibuf_close(&ibuf->w, msg);
}

void imsg_free(struct imsg *imsg)
{
	free(imsg->data);
}

int imsg_get_fd(struct imsgbuf *ibuf)
{
	int fd;
	struct imsg_fd *ifd;

	if ((ifd = TAILQ_POP_FIRST(&ibuf->fds, entry)) == NULL)
		return -1;

	fd = ifd->fd;
	free(ifd);

	return (fd);
}

int imsg_flush(struct imsgbuf *ibuf)
{
	while (ibuf->w.queued)
		if (msgbuf_write(&ibuf->w) <= 0)
			return -1;
	return 0;
}

void imsg_clear(struct imsgbuf *ibuf)
{
	int fd;

	msgbuf_clear(&ibuf->w);
	while ((fd = imsg_get_fd(ibuf)) != -1)
		close(fd);
}
