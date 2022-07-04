/* Stream/packet buffer API implementation
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include "zbuf.h"
#include "memory.h"
#include "nhrpd.h"

#define ERRNO_IO_RETRY(EN) (((EN) == EAGAIN) || ((EN) == EWOULDBLOCK) || ((EN) == EINTR))

DEFINE_MTYPE_STATIC(NHRPD, ZBUF_DATA, "NHRPD zbuf data");

struct zbuf *zbuf_alloc(size_t size)
{
	struct zbuf *zb;

	zb = XCALLOC(MTYPE_ZBUF_DATA, sizeof(*zb) + size);

	zbuf_init(zb, zb + 1, size, 0);
	zb->allocated = 1;

	return zb;
}

void zbuf_init(struct zbuf *zb, void *buf, size_t len, size_t datalen)
{
	*zb = (struct zbuf){
		.buf = buf,
		.end = (uint8_t *)buf + len,
		.head = buf,
		.tail = (uint8_t *)buf + datalen,
	};
}

void zbuf_free(struct zbuf *zb)
{
	if (zb->allocated)
		XFREE(MTYPE_ZBUF_DATA, zb);
}

void zbuf_reset(struct zbuf *zb)
{
	zb->head = zb->tail = zb->buf;
	zb->error = 0;
}

void zbuf_reset_head(struct zbuf *zb, void *ptr)
{
	assert((void *)zb->buf <= ptr && ptr <= (void *)zb->tail);
	zb->head = ptr;
}

static void zbuf_remove_headroom(struct zbuf *zb)
{
	ssize_t headroom = zbuf_headroom(zb);
	if (!headroom)
		return;
	memmove(zb->buf, zb->head, zbuf_used(zb));
	zb->head -= headroom;
	zb->tail -= headroom;
}

ssize_t zbuf_read(struct zbuf *zb, int fd, size_t maxlen)
{
	ssize_t r;

	if (zb->error)
		return -3;

	zbuf_remove_headroom(zb);
	if (maxlen > zbuf_tailroom(zb))
		maxlen = zbuf_tailroom(zb);

	r = read(fd, zb->tail, maxlen);
	if (r > 0)
		zb->tail += r;
	else if (r == 0)
		r = -2;
	else if (ERRNO_IO_RETRY(errno))
		r = 0;

	return r;
}

ssize_t zbuf_write(struct zbuf *zb, int fd)
{
	ssize_t r;

	if (zb->error)
		return -3;

	r = write(fd, zb->head, zbuf_used(zb));
	if (r > 0) {
		zb->head += r;
		if (zb->head == zb->tail)
			zbuf_reset(zb);
	} else if (r == 0)
		r = -2;
	else if (ERRNO_IO_RETRY(errno))
		r = 0;

	return r;
}

ssize_t zbuf_recv(struct zbuf *zb, int fd)
{
	ssize_t r;

	if (zb->error)
		return -3;

	zbuf_remove_headroom(zb);
	r = recv(fd, zb->tail, zbuf_tailroom(zb), 0);
	if (r > 0)
		zb->tail += r;
	else if (r == 0)
		r = -2;
	else if (ERRNO_IO_RETRY(errno))
		r = 0;
	return r;
}

ssize_t zbuf_send(struct zbuf *zb, int fd)
{
	ssize_t r;

	if (zb->error)
		return -3;

	r = send(fd, zb->head, zbuf_used(zb), 0);
	if (r >= 0)
		zbuf_reset(zb);

	return r;
}

void *zbuf_may_pull_until(struct zbuf *zb, const char *sep, struct zbuf *msg)
{
	size_t seplen = strlen(sep), len;
	uint8_t *ptr;

	ptr = memmem(zb->head, zbuf_used(zb), sep, seplen);
	if (!ptr)
		return NULL;

	len = ptr - zb->head + seplen;
	zbuf_init(msg, zbuf_pulln(zb, len), len, len);
	return msg->head;
}

void zbufq_init(struct zbuf_queue *zbq)
{
	*zbq = (struct zbuf_queue){
		.queue_head = INIT_DLIST(zbq->queue_head),
	};
}

void zbufq_reset(struct zbuf_queue *zbq)
{
	struct zbuf *buf;

	frr_each_safe (zbuf_queue, &zbq->queue_head, buf) {
		zbuf_queue_del(&zbq->queue_head, buf);
		zbuf_free(buf);
	}
}

void zbufq_queue(struct zbuf_queue *zbq, struct zbuf *zb)
{
	zbuf_queue_add_tail(&zbq->queue_head, zb);
}

int zbufq_write(struct zbuf_queue *zbq, int fd)
{
	struct iovec iov[16];
	struct zbuf *zb;
	ssize_t r;
	size_t iovcnt = 0;

	frr_each_safe (zbuf_queue, &zbq->queue_head, zb) {
		iov[iovcnt++] = (struct iovec){
			.iov_base = zb->head, .iov_len = zbuf_used(zb),
		};
		if (iovcnt >= array_size(iov))
			break;
	}

	r = writev(fd, iov, iovcnt);
	if (r < 0)
		return r;

	frr_each_safe (zbuf_queue, &zbq->queue_head, zb) {
		if (r < (ssize_t)zbuf_used(zb)) {
			zb->head += r;
			return 1;
		}

		r -= zbuf_used(zb);
		zbuf_queue_del(&zbq->queue_head, zb);
		zbuf_free(zb);
	}

	return 0;
}

void zbuf_copy(struct zbuf *zdst, struct zbuf *zsrc, size_t len)
{
	const void *src;
	void *dst;

	dst = zbuf_pushn(zdst, len);
	src = zbuf_pulln(zsrc, len);
	if (!dst || !src)
		return;
	memcpy(dst, src, len);
}

void zbuf_copy_peek(struct zbuf *zdst, struct zbuf *zsrc, size_t len)
{
	const void *src;
	void *dst;

	dst = zbuf_pushn(zdst, len);
	src = zbuf_pulln(zsrc, 0);
	if (!dst || !src)
		return;
	memcpy(dst, src, len);
}
