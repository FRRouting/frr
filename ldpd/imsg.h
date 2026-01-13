// SPDX-License-Identifier: ISC
/*	$OpenBSD$	*/

/*
 * Copyright (c) 2006, 2007 Pierre-Yves Ritschard <pyr@openbsd.org>
 * Copyright (c) 2006, 2007, 2008 Reyk Floeter <reyk@openbsd.org>
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 */

#ifndef _IMSG_H_
#define _IMSG_H_

#ifdef __cplusplus
extern "C" {
#endif

#define IBUF_READ_SIZE		65535
#define IMSG_HEADER_SIZE	sizeof(struct imsg_hdr)
#define MAX_IMSGSIZE		16384

struct ibuf {
	TAILQ_ENTRY(ibuf) entry;
	uint8_t *buf;
	size_t size;
	size_t max;
	size_t wpos;
	size_t rpos;
	int fd;
};

struct msgbuf {
	TAILQ_HEAD(, ibuf) bufs;
	uint32_t queued;
	int fd;
};

struct ibuf_read {
	uint8_t buf[IBUF_READ_SIZE];
	uint8_t *rptr;
	size_t wpos;
};

struct imsg_fd {
	TAILQ_ENTRY(imsg_fd) entry;
	int fd;
};

struct imsgbuf {
	TAILQ_HEAD(, imsg_fd) fds;
	struct ibuf_read r;
	struct msgbuf w;
	int fd;
	pid_t pid;
};

#define IMSGF_HASFD	1

struct imsg_hdr {
	uint32_t type;
	uint16_t len;
	uint16_t flags;
	uint32_t peerid;
	uint32_t pid;
};

struct imsg {
	struct imsg_hdr hdr;
	int fd;
	void *data;
};


/* buffer.c */
struct ibuf *ibuf_open(size_t size);
struct ibuf *ibuf_dynamic(size_t len, size_t max);
int ibuf_add(struct ibuf *buf, const void *data, size_t len);
void *ibuf_reserve(struct ibuf *buf, size_t len);
void *ibuf_seek(struct ibuf *buf, size_t pos, size_t len);
size_t ibuf_size(struct ibuf *buf);
size_t ibuf_left(struct ibuf *buf);
void ibuf_close(struct msgbuf *msgbuf, struct ibuf *buf);
int ibuf_write(struct msgbuf *msgbuf);
void ibuf_free(struct ibuf *buf);
void msgbuf_init(struct msgbuf *msgbuf);
void msgbuf_clear(struct msgbuf *msgbuf);
int msgbuf_write(struct msgbuf *msgbuf);
void msgbuf_drain(struct msgbuf *msgbuf, size_t n);

/* imsg.c */
void imsg_init(struct imsgbuf *ibuf, int fd);
ssize_t imsg_read(struct imsgbuf *ibuf);
ssize_t imsg_get(struct imsgbuf *ibuf, struct imsg *imsg);
int imsg_compose(struct imsgbuf *ibuf, uint32_t type, uint32_t peerid, pid_t pid, int fd,
		 const void *data, uint16_t datalen);
int imsg_composev(struct imsgbuf *ibuf, uint32_t type, uint32_t peerid, pid_t pid, int fd,
		  const struct iovec *iov, int iovcnt);
struct ibuf *imsg_create(struct imsgbuf *ibuf, uint32_t type, uint32_t peerid, pid_t pid,
			 uint16_t datalen);
int imsg_add(struct ibuf *msg, const void *data, uint16_t datalen);
void imsg_close(struct imsgbuf *ibuf, struct ibuf *msg);
void imsg_free(struct imsg *imsg);
int imsg_flush(struct imsgbuf *ibuf);
void imsg_clear(struct imsgbuf *ibuf);

#ifdef __cplusplus
}
#endif

#endif
