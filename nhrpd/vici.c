/* strongSwan VICI protocol implementation for NHRP
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

#include "vici.h"

#define ERRNO_IO_RETRY(EN) (((EN) == EAGAIN) || ((EN) == EWOULDBLOCK) || ((EN) == EINTR))

struct blob {
	char *ptr;
	int len;
};

static int blob_equal(const struct blob *b, const char *str)
{
	if (!b || b->len != (int)strlen(str))
		return 0;
	return memcmp(b->ptr, str, b->len) == 0;
}

static int blob2buf(const struct blob *b, char *buf, size_t n)
{
	if (!b || b->len >= (int)n)
		return 0;
	memcpy(buf, b->ptr, b->len);
	buf[b->len] = 0;
	return 1;
}

struct vici_conn {
	struct thread *t_reconnect, *t_read, *t_write;
	struct zbuf ibuf;
	struct zbuf_queue obuf;
	int fd;
	uint8_t ibuf_data[VICI_MAX_MSGLEN];
};

struct vici_message_ctx {
	const char *sections[8];
	int nsections;
};

static int vici_reconnect(struct thread *t);
static void vici_submit_request(struct vici_conn *vici, const char *name, ...);

static void vici_zbuf_puts(struct zbuf *obuf, const char *str)
{
	size_t len = strlen(str);
	zbuf_put8(obuf, len);
	zbuf_put(obuf, str, len);
}

static void vici_connection_error(struct vici_conn *vici)
{
	nhrp_vc_reset();

	THREAD_OFF(vici->t_read);
	THREAD_OFF(vici->t_write);
	zbuf_reset(&vici->ibuf);
	zbufq_reset(&vici->obuf);

	close(vici->fd);
	vici->fd = -1;
	thread_add_timer(master, vici_reconnect, vici, 2, &vici->t_reconnect);
}

static void vici_parse_message(struct vici_conn *vici, struct zbuf *msg,
			       void (*parser)(struct vici_message_ctx *ctx,
					      enum vici_type_t msgtype,
					      const struct blob *key,
					      const struct blob *val),
			       struct vici_message_ctx *ctx)
{
	uint8_t *type;
	struct blob key = {0};
	struct blob val = {0};

	while ((type = zbuf_may_pull(msg, uint8_t)) != NULL) {
		switch (*type) {
		case VICI_SECTION_START:
			key.len = zbuf_get8(msg);
			key.ptr = zbuf_pulln(msg, key.len);
			debugf(NHRP_DEBUG_VICI, "VICI: Section start '%.*s'",
			       key.len, key.ptr);
			parser(ctx, *type, &key, NULL);
			ctx->nsections++;
			break;
		case VICI_SECTION_END:
			debugf(NHRP_DEBUG_VICI, "VICI: Section end");
			parser(ctx, *type, NULL, NULL);
			ctx->nsections--;
			break;
		case VICI_KEY_VALUE:
			key.len = zbuf_get8(msg);
			key.ptr = zbuf_pulln(msg, key.len);
			val.len = zbuf_get_be16(msg);
			val.ptr = zbuf_pulln(msg, val.len);
			debugf(NHRP_DEBUG_VICI, "VICI: Key '%.*s'='%.*s'",
			       key.len, key.ptr, val.len, val.ptr);
			parser(ctx, *type, &key, &val);
			break;
		case VICI_LIST_START:
			key.len = zbuf_get8(msg);
			key.ptr = zbuf_pulln(msg, key.len);
			debugf(NHRP_DEBUG_VICI, "VICI: List start '%.*s'",
			       key.len, key.ptr);
			break;
		case VICI_LIST_ITEM:
			val.len = zbuf_get_be16(msg);
			val.ptr = zbuf_pulln(msg, val.len);
			debugf(NHRP_DEBUG_VICI, "VICI: List item: '%.*s'",
			       val.len, val.ptr);
			parser(ctx, *type, &key, &val);
			break;
		case VICI_LIST_END:
			debugf(NHRP_DEBUG_VICI, "VICI: List end");
			break;
		default:
			debugf(NHRP_DEBUG_VICI,
			       "VICI: Unsupported message component type %d",
			       *type);
			return;
		}
	}
}

struct handle_sa_ctx {
	struct vici_message_ctx msgctx;
	int event;
	int child_ok;
	int kill_ikesa;
	uint32_t child_uniqueid, ike_uniqueid;
	struct {
		union sockunion host;
		struct blob id, cert;
	} local, remote;
};

static void parse_sa_message(struct vici_message_ctx *ctx,
			     enum vici_type_t msgtype, const struct blob *key,
			     const struct blob *val)
{
	struct handle_sa_ctx *sactx =
		container_of(ctx, struct handle_sa_ctx, msgctx);
	struct nhrp_vc *vc;
	char buf[512];

	switch (msgtype) {
	case VICI_SECTION_START:
		if (ctx->nsections == 3) {
			/* Begin of child-sa section, reset child vars */
			sactx->child_uniqueid = 0;
			sactx->child_ok = 0;
		}
		break;
	case VICI_SECTION_END:
		if (ctx->nsections == 3) {
			/* End of child-sa section, update nhrp_vc */
			int up = sactx->child_ok || sactx->event == 1;
			if (up) {
				vc = nhrp_vc_get(&sactx->local.host,
						 &sactx->remote.host, up);
				if (vc) {
					blob2buf(&sactx->local.id, vc->local.id,
						 sizeof(vc->local.id));
					if (blob2buf(&sactx->local.cert,
						     (char *)vc->local.cert,
						     sizeof(vc->local.cert)))
						vc->local.certlen =
							sactx->local.cert.len;
					blob2buf(&sactx->remote.id,
						 vc->remote.id,
						 sizeof(vc->remote.id));
					if (blob2buf(&sactx->remote.cert,
						     (char *)vc->remote.cert,
						     sizeof(vc->remote.cert)))
						vc->remote.certlen =
							sactx->remote.cert.len;
					sactx->kill_ikesa |=
						nhrp_vc_ipsec_updown(
							sactx->child_uniqueid,
							vc);
				}
			} else {
				nhrp_vc_ipsec_updown(sactx->child_uniqueid, 0);
			}
		}
		break;
	default:
		if (!key)
			break;

		switch (key->ptr[0]) {
		case 'l':
			if (blob_equal(key, "local-host")
			    && ctx->nsections == 1) {
				if (blob2buf(val, buf, sizeof(buf)))
					if (str2sockunion(buf,
							  &sactx->local.host)
					    < 0)
						zlog_err(
							"VICI: bad strongSwan local-host: %s",
							buf);
			} else if (blob_equal(key, "local-id")
				   && ctx->nsections == 1) {
				sactx->local.id = *val;
			} else if (blob_equal(key, "local-cert-data")
				   && ctx->nsections == 1) {
				sactx->local.cert = *val;
			}
			break;
		case 'r':
			if (blob_equal(key, "remote-host")
			    && ctx->nsections == 1) {
				if (blob2buf(val, buf, sizeof(buf)))
					if (str2sockunion(buf,
							  &sactx->remote.host)
					    < 0)
						zlog_err(
							"VICI: bad strongSwan remote-host: %s",
							buf);
			} else if (blob_equal(key, "remote-id")
				   && ctx->nsections == 1) {
				sactx->remote.id = *val;
			} else if (blob_equal(key, "remote-cert-data")
				   && ctx->nsections == 1) {
				sactx->remote.cert = *val;
			}
			break;
		case 'u':
			if (blob_equal(key, "uniqueid")
			    && blob2buf(val, buf, sizeof(buf))) {
				if (ctx->nsections == 3)
					sactx->child_uniqueid =
						strtoul(buf, NULL, 0);
				else if (ctx->nsections == 1)
					sactx->ike_uniqueid =
						strtoul(buf, NULL, 0);
			}
			break;
		case 's':
			if (blob_equal(key, "state") && ctx->nsections == 3) {
				sactx->child_ok =
					(sactx->event == 0
					 && (blob_equal(val, "INSTALLED")
					     || blob_equal(val, "REKEYED")));
			}
			break;
		}
		break;
	}
}

static void parse_cmd_response(struct vici_message_ctx *ctx,
			       enum vici_type_t msgtype, const struct blob *key,
			       const struct blob *val)
{
	char buf[512];

	switch (msgtype) {
	case VICI_KEY_VALUE:
		if (blob_equal(key, "errmsg")
		    && blob2buf(val, buf, sizeof(buf)))
			zlog_err("VICI: strongSwan: %s", buf);
		break;
	default:
		break;
	}
}

static void vici_recv_sa(struct vici_conn *vici, struct zbuf *msg, int event)
{
	char buf[32];
	struct handle_sa_ctx ctx = {
		.event = event,
		.msgctx.nsections = 0
	};

	vici_parse_message(vici, msg, parse_sa_message, &ctx.msgctx);

	if (ctx.kill_ikesa && ctx.ike_uniqueid) {
		debugf(NHRP_DEBUG_COMMON, "VICI: Deleting IKE_SA %u",
		       ctx.ike_uniqueid);
		snprintf(buf, sizeof buf, "%u", ctx.ike_uniqueid);
		vici_submit_request(vici, "terminate", VICI_KEY_VALUE, "ike-id",
				    strlen(buf), buf, VICI_END);
	}
}

static void vici_recv_message(struct vici_conn *vici, struct zbuf *msg)
{
	uint32_t msglen;
	uint8_t msgtype;
	struct blob name;
	struct vici_message_ctx ctx = { .nsections = 0 };

	msglen = zbuf_get_be32(msg);
	msgtype = zbuf_get8(msg);
	debugf(NHRP_DEBUG_VICI, "VICI: Message %d, %d bytes", msgtype, msglen);

	switch (msgtype) {
	case VICI_EVENT:
		name.len = zbuf_get8(msg);
		name.ptr = zbuf_pulln(msg, name.len);

		debugf(NHRP_DEBUG_VICI, "VICI: Event '%.*s'", name.len,
		       name.ptr);
		if (blob_equal(&name, "list-sa")
		    || blob_equal(&name, "child-updown")
		    || blob_equal(&name, "child-rekey"))
			vici_recv_sa(vici, msg, 0);
		else if (blob_equal(&name, "child-state-installed")
			 || blob_equal(&name, "child-state-rekeyed"))
			vici_recv_sa(vici, msg, 1);
		else if (blob_equal(&name, "child-state-destroying"))
			vici_recv_sa(vici, msg, 2);
		break;
	case VICI_CMD_RESPONSE:
		vici_parse_message(vici, msg, parse_cmd_response, &ctx);
		break;
	case VICI_EVENT_UNKNOWN:
	case VICI_CMD_UNKNOWN:
		zlog_err(
			"VICI: StrongSwan does not support mandatory events (unpatched?)");
		break;
	case VICI_EVENT_CONFIRM:
		break;
	default:
		zlog_notice("VICI: Unrecognized message type %d", msgtype);
		break;
	}
}

static int vici_read(struct thread *t)
{
	struct vici_conn *vici = THREAD_ARG(t);
	struct zbuf *ibuf = &vici->ibuf;
	struct zbuf pktbuf;

	vici->t_read = NULL;
	if (zbuf_read(ibuf, vici->fd, (size_t)-1) < 0) {
		vici_connection_error(vici);
		return 0;
	}

	/* Process all messages in buffer */
	do {
		uint32_t *hdrlen = zbuf_may_pull(ibuf, uint32_t);
		if (!hdrlen)
			break;
		if (!zbuf_may_pulln(ibuf, ntohl(*hdrlen))) {
			zbuf_reset_head(ibuf, hdrlen);
			break;
		}

		/* Handle packet */
		zbuf_init(&pktbuf, hdrlen, htonl(*hdrlen) + 4,
			  htonl(*hdrlen) + 4);
		vici_recv_message(vici, &pktbuf);
	} while (1);

	thread_add_read(master, vici_read, vici, vici->fd, &vici->t_read);
	return 0;
}

static int vici_write(struct thread *t)
{
	struct vici_conn *vici = THREAD_ARG(t);
	int r;

	vici->t_write = NULL;
	r = zbufq_write(&vici->obuf, vici->fd);
	if (r > 0) {
		thread_add_write(master, vici_write, vici, vici->fd,
				 &vici->t_write);
	} else if (r < 0) {
		vici_connection_error(vici);
	}

	return 0;
}

static void vici_submit(struct vici_conn *vici, struct zbuf *obuf)
{
	if (vici->fd < 0) {
		zbuf_free(obuf);
		return;
	}

	zbufq_queue(&vici->obuf, obuf);
	thread_add_write(master, vici_write, vici, vici->fd, &vici->t_write);
}

static void vici_submit_request(struct vici_conn *vici, const char *name, ...)
{
	struct zbuf *obuf;
	uint32_t *hdrlen;
	va_list va;
	size_t len;
	int type;

	obuf = zbuf_alloc(256);
	if (!obuf)
		return;

	hdrlen = zbuf_push(obuf, uint32_t);
	zbuf_put8(obuf, VICI_CMD_REQUEST);
	vici_zbuf_puts(obuf, name);

	va_start(va, name);
	for (type = va_arg(va, int); type != VICI_END; type = va_arg(va, int)) {
		zbuf_put8(obuf, type);
		switch (type) {
		case VICI_KEY_VALUE:
			vici_zbuf_puts(obuf, va_arg(va, const char *));
			len = va_arg(va, size_t);
			zbuf_put_be16(obuf, len);
			zbuf_put(obuf, va_arg(va, void *), len);
			break;
		default:
			break;
		}
	}
	va_end(va);
	*hdrlen = htonl(zbuf_used(obuf) - 4);
	vici_submit(vici, obuf);
}

static void vici_register_event(struct vici_conn *vici, const char *name)
{
	struct zbuf *obuf;
	uint32_t *hdrlen;
	uint8_t namelen;

	namelen = strlen(name);
	obuf = zbuf_alloc(4 + 1 + 1 + namelen);
	if (!obuf)
		return;

	hdrlen = zbuf_push(obuf, uint32_t);
	zbuf_put8(obuf, VICI_EVENT_REGISTER);
	zbuf_put8(obuf, namelen);
	zbuf_put(obuf, name, namelen);
	*hdrlen = htonl(zbuf_used(obuf) - 4);

	vici_submit(vici, obuf);
}

static int vici_reconnect(struct thread *t)
{
	struct vici_conn *vici = THREAD_ARG(t);
	int fd;

	vici->t_reconnect = NULL;
	if (vici->fd >= 0)
		return 0;

	fd = sock_open_unix("/var/run/charon.vici");
	if (fd < 0) {
		debugf(NHRP_DEBUG_VICI,
		       "%s: failure connecting VICI socket: %s",
		       __PRETTY_FUNCTION__, strerror(errno));
		thread_add_timer(master, vici_reconnect, vici, 2,
				 &vici->t_reconnect);
		return 0;
	}

	debugf(NHRP_DEBUG_COMMON, "VICI: Connected");
	vici->fd = fd;
	thread_add_read(master, vici_read, vici, vici->fd, &vici->t_read);

	/* Send event subscribtions */
	// vici_register_event(vici, "child-updown");
	// vici_register_event(vici, "child-rekey");
	vici_register_event(vici, "child-state-installed");
	vici_register_event(vici, "child-state-rekeyed");
	vici_register_event(vici, "child-state-destroying");
	vici_register_event(vici, "list-sa");
	vici_submit_request(vici, "list-sas", VICI_END);

	return 0;
}

static struct vici_conn vici_connection;

void vici_init(void)
{
	struct vici_conn *vici = &vici_connection;

	vici->fd = -1;
	zbuf_init(&vici->ibuf, vici->ibuf_data, sizeof(vici->ibuf_data), 0);
	zbufq_init(&vici->obuf);
	thread_add_timer_msec(master, vici_reconnect, vici, 10,
			      &vici->t_reconnect);
}

void vici_terminate(void)
{
}

void vici_request_vc(const char *profile, union sockunion *src,
		     union sockunion *dst, int prio)
{
	struct vici_conn *vici = &vici_connection;
	char buf[2][SU_ADDRSTRLEN];

	sockunion2str(src, buf[0], sizeof buf[0]);
	sockunion2str(dst, buf[1], sizeof buf[1]);

	vici_submit_request(vici, "initiate", VICI_KEY_VALUE, "child",
			    strlen(profile), profile, VICI_KEY_VALUE, "timeout",
			    (size_t)2, "-1", VICI_KEY_VALUE, "async", (size_t)1,
			    "1", VICI_KEY_VALUE, "init-limits", (size_t)1,
			    prio ? "0" : "1", VICI_KEY_VALUE, "my-host",
			    strlen(buf[0]), buf[0], VICI_KEY_VALUE,
			    "other-host", strlen(buf[1]), buf[1], VICI_END);
}

int sock_open_unix(const char *path)
{
	int ret, fd;
	struct sockaddr_un addr;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

	ret = connect(fd, (struct sockaddr *)&addr,
		      sizeof(addr.sun_family) + strlen(addr.sun_path));
	if (ret < 0) {
		close(fd);
		return -1;
	}

	ret = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
	if (ret < 0) {
		close(fd);
		return -1;
	}

	return fd;
}
