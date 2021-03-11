/* NHRP netlink/GRE tunnel configuration code
 * Copyright (c) 2014-2016 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/in.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_tunnel.h>

#include "debug.h"
#include "netlink.h"
#include "znl.h"

static int __netlink_gre_get_data(struct zbuf *zb, struct zbuf *data,
				  int ifindex)
{
	struct nlmsghdr *n;
	struct ifinfomsg *ifi;
	struct zbuf payload, rtapayload;
	struct rtattr *rta;

	debugf(NHRP_DEBUG_KERNEL, "netlink-link-gre: get-info %u", ifindex);

	n = znl_nlmsg_push(zb, RTM_GETLINK, NLM_F_REQUEST);
	ifi = znl_push(zb, sizeof(*ifi));
	*ifi = (struct ifinfomsg){
		.ifi_index = ifindex,
	};
	znl_nlmsg_complete(zb, n);

	if (zbuf_send(zb, netlink_req_fd) < 0
	    || zbuf_recv(zb, netlink_req_fd) < 0)
		return -1;

	n = znl_nlmsg_pull(zb, &payload);
	if (!n)
		return -1;

	if (n->nlmsg_type != RTM_NEWLINK)
		return -1;

	ifi = znl_pull(&payload, sizeof(struct ifinfomsg));
	if (!ifi)
		return -1;

	debugf(NHRP_DEBUG_KERNEL,
	       "netlink-link-gre: ifindex %u, receive msg_type %u, msg_flags %u",
	       ifi->ifi_index, n->nlmsg_type, n->nlmsg_flags);

	if (ifi->ifi_index != ifindex)
		return -1;

	while ((rta = znl_rta_pull(&payload, &rtapayload)) != NULL)
		if (rta->rta_type == IFLA_LINKINFO)
			break;
	if (!rta)
		return -1;

	payload = rtapayload;
	while ((rta = znl_rta_pull(&payload, &rtapayload)) != NULL)
		if (rta->rta_type == IFLA_INFO_DATA)
			break;
	if (!rta)
		return -1;

	*data = rtapayload;
	return 0;
}

static int netlink_gre_get_mtu(struct zbuf *zb, int ifindex, unsigned int *mtu)
{
	struct nlmsghdr *n;
	struct ifinfomsg *ifi;
	struct zbuf payload, rtapayload;
	struct rtattr *rta;
	unsigned int *pmtu;

	n = znl_nlmsg_push(zb, RTM_GETLINK, NLM_F_REQUEST);
	ifi = znl_push(zb, sizeof(*ifi));
	*ifi = (struct ifinfomsg){
		.ifi_index = ifindex,
	};
	znl_nlmsg_complete(zb, n);

	if (zbuf_send(zb, netlink_req_fd) < 0
	    || zbuf_recv(zb, netlink_req_fd) < 0)
		return -1;

	n = znl_nlmsg_pull(zb, &payload);
	if (!n)
		return -2;

	if (n->nlmsg_type != RTM_NEWLINK)
		return -3;

	ifi = znl_pull(&payload, sizeof(struct ifinfomsg));
	if (!ifi)
		return -4;

	if (ifi->ifi_index != ifindex)
		return -5;

	while ((rta = znl_rta_pull(&payload, &rtapayload)) != NULL)
		if (rta->rta_type == IFLA_MTU)
			break;
	if (!rta)
		return -6;

	pmtu = znl_pull(&rtapayload, sizeof(unsigned int));
	if (!pmtu)
		return -7;

	*mtu = *pmtu;

	debugf(NHRP_DEBUG_KERNEL, "netlink_gre_get_mtu: %d (ifindex=%u)", *mtu,
	       ifindex);

	return 0;
}

void netlink_gre_get_info(unsigned int ifindex, uint32_t *gre_key,
			  unsigned int *link_index, struct in_addr *saddr)
{
	struct zbuf *zb = zbuf_alloc(8192), data, rtapl;
	struct rtattr *rta;

	*link_index = 0;
	*gre_key = 0;
	saddr->s_addr = 0;

	if (__netlink_gre_get_data(zb, &data, ifindex) < 0)
		goto err;

	while ((rta = znl_rta_pull(&data, &rtapl)) != NULL) {
		switch (rta->rta_type) {
		case IFLA_GRE_LINK:
			*link_index = zbuf_get32(&rtapl);
			break;
		case IFLA_GRE_IKEY:
		case IFLA_GRE_OKEY:
			*gre_key = zbuf_get32(&rtapl);
			break;
		case IFLA_GRE_LOCAL:
			saddr->s_addr = zbuf_get32(&rtapl);
			break;
		}
	}
err:
	zbuf_free(zb);
}

void netlink_gre_set_link(unsigned int ifindex, unsigned int link_index)
{
	struct nlmsghdr *n;
	struct ifinfomsg *ifi;
	struct rtattr *rta_info, *rta_data, *rta;
	struct zbuf *zr = zbuf_alloc(8192), data, rtapl;
	struct zbuf *zb = zbuf_alloc(8192);
	size_t len;
	unsigned int mtu = 0;
	int ret;

	if (__netlink_gre_get_data(zr, &data, ifindex) < 0)
		goto err;

	ret = netlink_gre_get_mtu(zb, ifindex, &mtu);
	if (ret < 0) {
		debugf(NHRP_DEBUG_KERNEL, "netlink_gre_get_mtu failed (%d)",
		       ret);
	}

	n = znl_nlmsg_push(zb, RTM_NEWLINK, NLM_F_REQUEST);
	ifi = znl_push(zb, sizeof(*ifi));
	*ifi = (struct ifinfomsg){
		.ifi_index = ifindex,
	};

	/* LTE-1921: Preserve MTU */
	if (mtu)
		znl_rta_push_u32(zb, IFLA_MTU, mtu);

	rta_info = znl_rta_nested_push(zb, IFLA_LINKINFO);
	znl_rta_push(zb, IFLA_INFO_KIND, "gre", 3);
	rta_data = znl_rta_nested_push(zb, IFLA_INFO_DATA);

	znl_rta_push_u32(zb, IFLA_GRE_LINK, link_index);
	while ((rta = znl_rta_pull(&data, &rtapl)) != NULL) {
		if (rta->rta_type == IFLA_GRE_LINK)
			continue;
		len = zbuf_used(&rtapl);
		znl_rta_push(zb, rta->rta_type, zbuf_pulln(&rtapl, len), len);
	}

	znl_rta_nested_complete(zb, rta_data);
	znl_rta_nested_complete(zb, rta_info);

	znl_nlmsg_complete(zb, n);
	zbuf_send(zb, netlink_req_fd);
	zbuf_recv(zb, netlink_req_fd);
err:
	zbuf_free(zb);
	zbuf_free(zr);
}
