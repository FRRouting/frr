/* Netlink helpers for zbuf
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

#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "znl.h"

#define ZNL_ALIGN(len)		(((len)+3) & ~3)

extern struct zebra_privs_t zserv_privs;

void *znl_push(struct zbuf *zb, size_t n)
{
	return zbuf_pushn(zb, ZNL_ALIGN(n));
}

void *znl_pull(struct zbuf *zb, size_t n)
{
	return zbuf_pulln(zb, ZNL_ALIGN(n));
}

struct nlmsghdr *znl_nlmsg_push(struct zbuf *zb, uint16_t type, uint16_t flags)
{
	struct nlmsghdr *n;

	n = znl_push(zb, sizeof(*n));
	if (!n)
		return NULL;

	*n = (struct nlmsghdr){
		.nlmsg_type = type, .nlmsg_flags = flags,
	};
	return n;
}

void znl_nlmsg_complete(struct zbuf *zb, struct nlmsghdr *n)
{
	n->nlmsg_len = zb->tail - (uint8_t *)n;
}

struct nlmsghdr *znl_nlmsg_pull(struct zbuf *zb, struct zbuf *payload)
{
	struct nlmsghdr *n;
	size_t plen;

	n = znl_pull(zb, sizeof(*n));
	if (!n)
		return NULL;

	plen = n->nlmsg_len - sizeof(*n);
	zbuf_init(payload, znl_pull(zb, plen), plen, plen);
	zbuf_may_pulln(zb, ZNL_ALIGN(plen) - plen);

	return n;
}

struct rtattr *znl_rta_push(struct zbuf *zb, uint16_t type, const void *val,
			    size_t len)
{
	struct rtattr *rta;
	uint8_t *dst;

	rta = znl_push(zb, ZNL_ALIGN(sizeof(*rta)) + ZNL_ALIGN(len));
	if (!rta)
		return NULL;

	*rta = (struct rtattr){
		.rta_type = type, .rta_len = ZNL_ALIGN(sizeof(*rta)) + len,
	};

	dst = (uint8_t *)(rta + 1);
	memcpy(dst, val, len);
	memset(dst + len, 0, ZNL_ALIGN(len) - len);

	return rta;
}

struct rtattr *znl_rta_push_u32(struct zbuf *zb, uint16_t type, uint32_t val)
{
	return znl_rta_push(zb, type, &val, sizeof(val));
}

struct rtattr *znl_rta_nested_push(struct zbuf *zb, uint16_t type)
{
	struct rtattr *rta;

	rta = znl_push(zb, sizeof(*rta));
	if (!rta)
		return NULL;

	*rta = (struct rtattr){
		.rta_type = type,
	};
	return rta;
}

void znl_rta_nested_complete(struct zbuf *zb, struct rtattr *rta)
{
	size_t len = zb->tail - (uint8_t *)rta;
	size_t align = ZNL_ALIGN(len) - len;

	if (align) {
		void *dst = zbuf_pushn(zb, align);
		if (dst)
			memset(dst, 0, align);
	}
	rta->rta_len = len;
}

struct rtattr *znl_rta_pull(struct zbuf *zb, struct zbuf *payload)
{
	struct rtattr *rta;
	size_t plen;

	rta = znl_pull(zb, sizeof(*rta));
	if (!rta)
		return NULL;

	if (rta->rta_len > sizeof(*rta)) {
		plen = rta->rta_len - sizeof(*rta);
		zbuf_init(payload, znl_pull(zb, plen), plen, plen);
	} else {
		zbuf_init(payload, NULL, 0, 0);
	}

	return rta;
}

int znl_open(int protocol, int groups, struct ns *ns)
{
	int fd;
	struct sockaddr_nl snl;
	ns_id_t ns_id = NS_DEFAULT;
	struct ns *ns_local = ns;
	int ret;

	if (ns_local)
		ns_id = ns->ns_id;
	else
		ns_local = ns_get_default();
	frr_with_privs(&zserv_privs) {
		fd = ns_socket(AF_NETLINK, SOCK_RAW, protocol, ns_id);
	}
	if (fd < 0) {
		zlog_err("Can't open socket %d ( err %s)", protocol,
			 safe_strerror(errno));
		return -1;
	}

	memset(&snl, 0, sizeof snl);
	snl.nl_family = AF_NETLINK;
	snl.nl_groups = groups;

	frr_with_privs(&zserv_privs) {
		ns_switch_to_netns(ns_local->name);
		/* Bind the socket to the netlink structure for anything. */
		bind(fd, (struct sockaddr *)&snl, sizeof snl);
		ns_switchback_to_initial();
	}

	if (fd < 0)
		return -1;

	frr_with_privs(&zserv_privs) {
		int val;

		ns_switch_to_netns(ns_local->name);
		val =  fcntl(fd, F_GETFL, 0);
		ret = fcntl(fd, F_SETFL, val | O_NONBLOCK);
		ns_switchback_to_initial();
	}
	if (ret < 0)
		goto error;
	frr_with_privs(&zserv_privs) {
		ns_switch_to_netns(ns_local->name);
		ret = fcntl(fd, F_SETFD, FD_CLOEXEC);
		ns_switchback_to_initial();
	}
	if (ret < 0)
		goto error;

	return fd;
error:
	close(fd);
	return -1;
}
