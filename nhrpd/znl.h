// SPDX-License-Identifier: GPL-2.0-or-later
/* Netlink helpers for zbuf
 * Copyright (c) 2014-2015 Timo Teräs
 */

#include "zbuf.h"

#define ZNL_BUFFER_SIZE		8192

void *znl_push(struct zbuf *zb, size_t n);
void *znl_pull(struct zbuf *zb, size_t n);

struct nlmsghdr *znl_nlmsg_push(struct zbuf *zb, uint16_t type, uint16_t flags);
void znl_nlmsg_complete(struct zbuf *zb, struct nlmsghdr *n);
struct nlmsghdr *znl_nlmsg_pull(struct zbuf *zb, struct zbuf *payload);

struct rtattr *znl_rta_push(struct zbuf *zb, uint16_t type, const void *val,
			    size_t len);
struct rtattr *znl_rta_push_u32(struct zbuf *zb, uint16_t type, uint32_t val);
struct rtattr *znl_rta_nested_push(struct zbuf *zb, uint16_t type);
void znl_rta_nested_complete(struct zbuf *zb, struct rtattr *rta);

struct rtattr *znl_rta_pull(struct zbuf *zb, struct zbuf *payload);

int znl_open(int protocol, int groups);
