/* NHRP event manager
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "thread.h"
#include "zbuf.h"
#include "log.h"
#include "nhrpd.h"

const char *nhrp_event_socket_path;
struct nhrp_reqid_pool nhrp_event_reqid;

struct event_manager {
	struct thread *t_reconnect, *t_read, *t_write;
	struct zbuf ibuf;
	struct zbuf_queue obuf;
	int fd;
	uint8_t ibuf_data[4 * 1024];
};

static int evmgr_reconnect(struct thread *t);

static void evmgr_connection_error(struct event_manager *evmgr)
{
	THREAD_OFF(evmgr->t_read);
	THREAD_OFF(evmgr->t_write);
	zbuf_reset(&evmgr->ibuf);
	zbufq_reset(&evmgr->obuf);

	if (evmgr->fd >= 0)
		close(evmgr->fd);
	evmgr->fd = -1;
	if (nhrp_event_socket_path)
		thread_add_timer_msec(master, evmgr_reconnect, evmgr, 10,
				      &evmgr->t_reconnect);
}

static void evmgr_recv_message(struct event_manager *evmgr, struct zbuf *zb)
{
	struct zbuf zl;
	uint32_t eventid = 0;
	size_t len;
	char buf[256], result[64] = "";

	while (zbuf_may_pull_until(zb, "\n", &zl)) {
		len = zbuf_used(&zl) - 1;
		if (len >= sizeof(buf) - 1)
			continue;
		memcpy(buf, zbuf_pulln(&zl, len), len);
		buf[len] = 0;

		debugf(NHRP_DEBUG_EVENT, "evmgr: msg: %s", buf);
		if (sscanf(buf, "eventid=%" SCNu32, &eventid) != 1)
			continue;
		if (sscanf(buf, "result=%63s", result) != 1)
			continue;
	}
	debugf(NHRP_DEBUG_EVENT, "evmgr: received: eventid=%d result=%s",
	       eventid, result);
	if (eventid && result[0]) {
		struct nhrp_reqid *r =
			nhrp_reqid_lookup(&nhrp_event_reqid, eventid);
		if (r)
			r->cb(r, result);
	}
}

static int evmgr_read(struct thread *t)
{
	struct event_manager *evmgr = THREAD_ARG(t);
	struct zbuf *ibuf = &evmgr->ibuf;
	struct zbuf msg;

	evmgr->t_read = NULL;
	if (zbuf_read(ibuf, evmgr->fd, (size_t)-1) < 0) {
		evmgr_connection_error(evmgr);
		return 0;
	}

	/* Process all messages in buffer */
	while (zbuf_may_pull_until(ibuf, "\n\n", &msg))
		evmgr_recv_message(evmgr, &msg);

	thread_add_read(master, evmgr_read, evmgr, evmgr->fd, &evmgr->t_read);
	return 0;
}

static int evmgr_write(struct thread *t)
{
	struct event_manager *evmgr = THREAD_ARG(t);
	int r;

	evmgr->t_write = NULL;
	r = zbufq_write(&evmgr->obuf, evmgr->fd);
	if (r > 0) {
		thread_add_write(master, evmgr_write, evmgr, evmgr->fd,
				 &evmgr->t_write);
	} else if (r < 0) {
		evmgr_connection_error(evmgr);
	}

	return 0;
}

static void evmgr_hexdump(struct zbuf *zb, const uint8_t *val, size_t vallen)
{
	static const char xd[] = "0123456789abcdef";
	size_t i;
	char *ptr;

	ptr = zbuf_pushn(zb, 2 * vallen);
	if (!ptr)
		return;

	for (i = 0; i < vallen; i++) {
		uint8_t b = val[i];
		*(ptr++) = xd[b >> 4];
		*(ptr++) = xd[b & 0xf];
	}
}

static void evmgr_put(struct zbuf *zb, const char *fmt, ...)
{
	const char *pos, *nxt, *str;
	const uint8_t *bin;
	const union sockunion *su;
	int len;
	va_list va;

	va_start(va, fmt);
	for (pos = fmt; (nxt = strchr(pos, '%')) != NULL; pos = nxt + 2) {
		zbuf_put(zb, pos, nxt - pos);
		switch (nxt[1]) {
		case '%':
			zbuf_put8(zb, '%');
			break;
		case 'u':
			zb->tail +=
				snprintf((char *)zb->tail, zbuf_tailroom(zb),
					 "%u", va_arg(va, uint32_t));
			break;
		case 's':
			str = va_arg(va, const char *);
			zbuf_put(zb, str, strlen(str));
			break;
		case 'U':
			su = va_arg(va, const union sockunion *);
			if (sockunion2str(su, (char *)zb->tail,
					  zbuf_tailroom(zb)))
				zb->tail += strlen((char *)zb->tail);
			else
				zbuf_set_werror(zb);
			break;
		case 'H':
			bin = va_arg(va, const uint8_t *);
			len = va_arg(va, int);
			evmgr_hexdump(zb, bin, len);
			break;
		}
	}
	va_end(va);
	zbuf_put(zb, pos, strlen(pos));
}

static void evmgr_submit(struct event_manager *evmgr, struct zbuf *obuf)
{
	if (obuf->error) {
		zbuf_free(obuf);
		return;
	}
	zbuf_put(obuf, "\n", 1);
	zbufq_queue(&evmgr->obuf, obuf);
	if (evmgr->fd >= 0)
		thread_add_write(master, evmgr_write, evmgr, evmgr->fd,
				 &evmgr->t_write);
}

static int evmgr_reconnect(struct thread *t)
{
	struct event_manager *evmgr = THREAD_ARG(t);
	int fd;

	evmgr->t_reconnect = NULL;
	if (evmgr->fd >= 0 || !nhrp_event_socket_path)
		return 0;

	fd = sock_open_unix(nhrp_event_socket_path);
	if (fd < 0) {
		zlog_warn("%s: failure connecting nhrp-event socket: %s",
			  __PRETTY_FUNCTION__, strerror(errno));
		zbufq_reset(&evmgr->obuf);
		thread_add_timer(master, evmgr_reconnect, evmgr, 10,
				 &evmgr->t_reconnect);
		return 0;
	}

	zlog_info("Connected to Event Manager");
	evmgr->fd = fd;
	thread_add_read(master, evmgr_read, evmgr, evmgr->fd, &evmgr->t_read);

	return 0;
}

static struct event_manager evmgr_connection;

void evmgr_init(void)
{
	struct event_manager *evmgr = &evmgr_connection;

	evmgr->fd = -1;
	zbuf_init(&evmgr->ibuf, evmgr->ibuf_data, sizeof(evmgr->ibuf_data), 0);
	zbufq_init(&evmgr->obuf);
	thread_add_timer_msec(master, evmgr_reconnect, evmgr, 10,
			      &evmgr->t_reconnect);
}

void evmgr_set_socket(const char *socket)
{
	if (nhrp_event_socket_path) {
		free((char *)nhrp_event_socket_path);
		nhrp_event_socket_path = NULL;
	}
	if (socket)
		nhrp_event_socket_path = strdup(socket);
	evmgr_connection_error(&evmgr_connection);
}

void evmgr_terminate(void)
{
}

void evmgr_notify(const char *name, struct nhrp_cache *c,
		  void (*cb)(struct nhrp_reqid *, void *))
{
	struct event_manager *evmgr = &evmgr_connection;
	struct nhrp_vc *vc;
	struct nhrp_interface *nifp = c->ifp->info;
	struct zbuf *zb;
	afi_t afi = family2afi(sockunion_family(&c->remote_addr));

	if (!nhrp_event_socket_path) {
		cb(&c->eventid, (void *)"accept");
		return;
	}

	debugf(NHRP_DEBUG_EVENT, "evmgr: sending event %s", name);

	vc = c->new.peer ? c->new.peer->vc : NULL;
	zb = zbuf_alloc(
		1024 + (vc ? (vc->local.certlen + vc->remote.certlen) * 2 : 0));

	if (cb) {
		nhrp_reqid_free(&nhrp_event_reqid, &c->eventid);
		evmgr_put(zb, "eventid=%u\n",
			  nhrp_reqid_alloc(&nhrp_event_reqid, &c->eventid, cb));
	}

	evmgr_put(zb,
		  "event=%s\n"
		  "type=%s\n"
		  "old_type=%s\n"
		  "num_nhs=%u\n"
		  "interface=%s\n"
		  "local_addr=%U\n",
		  name, nhrp_cache_type_str[c->new.type],
		  nhrp_cache_type_str[c->cur.type],
		  (unsigned int)nhrp_cache_counts[NHRP_CACHE_NHS], c->ifp->name,
		  &nifp->afi[afi].addr);

	if (vc) {
		evmgr_put(zb,
			  "vc_initiated=%s\n"
			  "local_nbma=%U\n"
			  "local_cert=%H\n"
			  "remote_addr=%U\n"
			  "remote_nbma=%U\n"
			  "remote_cert=%H\n",
			  c->new.peer->requested ? "yes" : "no",
			  &vc->local.nbma, vc->local.cert, vc->local.certlen,
			  &c->remote_addr, &vc->remote.nbma, vc->remote.cert,
			  vc->remote.certlen);
	}

	evmgr_submit(evmgr, zb);
}
