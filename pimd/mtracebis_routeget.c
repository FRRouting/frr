/*
 * Multicast Traceroute for FRRouting
 * Copyright (C) 2018  Mladen Sablic
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifdef __linux__

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>

#include "mtracebis_netlink.h"
#include "mtracebis_routeget.h"

static int find_dst(struct nlmsghdr *n, struct in_addr *src, struct in_addr *gw)
{
	struct rtmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *tb[RTA_MAX + 1];

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	parse_rtattr(tb, RTA_MAX, RTM_RTA(r), len);
	if (tb[RTA_PREFSRC])
		src->s_addr = *(uint32_t *)RTA_DATA(tb[RTA_PREFSRC]);
	if (tb[RTA_GATEWAY])
		gw->s_addr = *(uint32_t *)RTA_DATA(tb[RTA_GATEWAY]);
	if (tb[RTA_OIF])
		return *(int *)RTA_DATA(tb[RTA_OIF]);
	return 0;
}

int routeget(struct in_addr dst, struct in_addr *src, struct in_addr *gw)
{
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[1024];
	} req;
	int ret;
	struct rtnl_handle rth = {.fd = -1};

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_GETROUTE;
	req.r.rtm_family = AF_INET;
	req.r.rtm_table = 0;
	req.r.rtm_protocol = 0;
	req.r.rtm_scope = 0;
	req.r.rtm_type = 0;
	req.r.rtm_src_len = 0;
	req.r.rtm_dst_len = 0;
	req.r.rtm_tos = 0;

	addattr_l(&req.n, sizeof(req), RTA_DST, &dst.s_addr, 4);
	req.r.rtm_dst_len = 32;

	ret = rtnl_open(&rth, 0);

	if (ret < 0 || rth.fd <= 0)
		return ret;

	if (rtnl_talk(&rth, &req.n, 0, 0, &req.n, NULL, NULL) < 0) {
		ret = -1;
		goto close_rth;
	}

	ret = find_dst(&req.n, src, gw);
close_rth:
	rtnl_close(&rth);
	return ret;
}

#endif /* __linux__ */
