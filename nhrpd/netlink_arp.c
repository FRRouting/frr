/* NHRP netlink/neighbor table arpd code
 * Copyright (c) 2014-2016 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include <fcntl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <linux/netlink.h>
#include <linux/neighbour.h>
#include <linux/netfilter/nfnetlink_log.h>

#include "thread.h"
#include "nhrpd.h"
#include "netlink.h"
#include "znl.h"

int netlink_req_fd = -1;
int netlink_nflog_group;
static int netlink_log_fd = -1;
static struct thread *netlink_log_thread;
static int netlink_listen_fd = -1;

typedef void (*netlink_dispatch_f)(struct nlmsghdr *msg, struct zbuf *zb);

void netlink_update_binding(struct interface *ifp, union sockunion *proto,
			    union sockunion *nbma)
{
	struct nlmsghdr *n;
	struct ndmsg *ndm;
	struct zbuf *zb = zbuf_alloc(512);

	n = znl_nlmsg_push(zb, nbma ? RTM_NEWNEIGH : RTM_DELNEIGH,
			   NLM_F_REQUEST | NLM_F_REPLACE | NLM_F_CREATE);
	ndm = znl_push(zb, sizeof(*ndm));
	*ndm = (struct ndmsg){
		.ndm_family = sockunion_family(proto),
		.ndm_ifindex = ifp->ifindex,
		.ndm_type = RTN_UNICAST,
		.ndm_state = nbma ? NUD_REACHABLE : NUD_FAILED,
	};
	znl_rta_push(zb, NDA_DST, sockunion_get_addr(proto),
		     family2addrsize(sockunion_family(proto)));
	if (nbma)
		znl_rta_push(zb, NDA_LLADDR, sockunion_get_addr(nbma),
			     family2addrsize(sockunion_family(nbma)));
	znl_nlmsg_complete(zb, n);
	zbuf_send(zb, netlink_req_fd);
	zbuf_recv(zb, netlink_req_fd);
	zbuf_free(zb);
}

static void netlink_neigh_msg(struct nlmsghdr *msg, struct zbuf *zb)
{
	struct ndmsg *ndm;
	struct rtattr *rta;
	struct nhrp_cache *c;
	struct interface *ifp;
	struct zbuf payload;
	union sockunion addr;
	size_t len;
	char buf[SU_ADDRSTRLEN];
	int state;

	ndm = znl_pull(zb, sizeof(*ndm));
	if (!ndm)
		return;

	sockunion_family(&addr) = AF_UNSPEC;
	while ((rta = znl_rta_pull(zb, &payload)) != NULL) {
		len = zbuf_used(&payload);
		switch (rta->rta_type) {
		case NDA_DST:
			sockunion_set(&addr, ndm->ndm_family,
				      zbuf_pulln(&payload, len), len);
			break;
		}
	}

	ifp = if_lookup_by_index(ndm->ndm_ifindex, VRF_DEFAULT);
	if (!ifp || sockunion_family(&addr) == AF_UNSPEC)
		return;

	c = nhrp_cache_get(ifp, &addr, 0);
	if (!c)
		return;

	if (msg->nlmsg_type == RTM_GETNEIGH) {
		debugf(NHRP_DEBUG_KERNEL, "Netlink: who-has %s dev %s",
		       sockunion2str(&addr, buf, sizeof buf), ifp->name);

		if (c->cur.type >= NHRP_CACHE_CACHED) {
			nhrp_cache_set_used(c, 1);
			netlink_update_binding(ifp, &addr,
					       &c->cur.peer->vc->remote.nbma);
		}
	} else {
		debugf(NHRP_DEBUG_KERNEL, "Netlink: update %s dev %s nud %x",
		       sockunion2str(&addr, buf, sizeof buf), ifp->name,
		       ndm->ndm_state);

		state = (msg->nlmsg_type == RTM_NEWNEIGH) ? ndm->ndm_state
							  : NUD_FAILED;
		nhrp_cache_set_used(c, state == NUD_REACHABLE);
	}
}

static int netlink_route_recv(struct thread *t)
{
	uint8_t buf[ZNL_BUFFER_SIZE];
	int fd = THREAD_FD(t);
	struct zbuf payload, zb;
	struct nlmsghdr *n;

	zbuf_init(&zb, buf, sizeof(buf), 0);
	while (zbuf_recv(&zb, fd) > 0) {
		while ((n = znl_nlmsg_pull(&zb, &payload)) != 0) {
			debugf(NHRP_DEBUG_KERNEL,
			       "Netlink: Received msg_type %u, msg_flags %u",
			       n->nlmsg_type, n->nlmsg_flags);
			switch (n->nlmsg_type) {
			case RTM_GETNEIGH:
			case RTM_NEWNEIGH:
			case RTM_DELNEIGH:
				netlink_neigh_msg(n, &payload);
				break;
			}
		}
	}

	thread_add_read(master, netlink_route_recv, 0, fd, NULL);

	return 0;
}

static void netlink_log_register(int fd, int group)
{
	struct nlmsghdr *n;
	struct nfgenmsg *nf;
	struct nfulnl_msg_config_cmd cmd;
	struct zbuf *zb = zbuf_alloc(512);

	n = znl_nlmsg_push(zb, (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG,
			   NLM_F_REQUEST | NLM_F_ACK);
	nf = znl_push(zb, sizeof(*nf));
	*nf = (struct nfgenmsg){
		.nfgen_family = AF_UNSPEC,
		.version = NFNETLINK_V0,
		.res_id = htons(group),
	};
	cmd.command = NFULNL_CFG_CMD_BIND;
	znl_rta_push(zb, NFULA_CFG_CMD, &cmd, sizeof(cmd));
	znl_nlmsg_complete(zb, n);

	zbuf_send(zb, fd);
	zbuf_free(zb);
}

static void netlink_log_indication(struct nlmsghdr *msg, struct zbuf *zb)
{
	struct nfgenmsg *nf;
	struct rtattr *rta;
	struct zbuf rtapl, pktpl;
	struct interface *ifp;
	struct nfulnl_msg_packet_hdr *pkthdr = NULL;
	uint32_t *in_ndx = NULL;

	nf = znl_pull(zb, sizeof(*nf));
	if (!nf)
		return;

	memset(&pktpl, 0, sizeof(pktpl));
	while ((rta = znl_rta_pull(zb, &rtapl)) != NULL) {
		switch (rta->rta_type) {
		case NFULA_PACKET_HDR:
			pkthdr = znl_pull(&rtapl, sizeof(*pkthdr));
			break;
		case NFULA_IFINDEX_INDEV:
			in_ndx = znl_pull(&rtapl, sizeof(*in_ndx));
			break;
		case NFULA_PAYLOAD:
			pktpl = rtapl;
			break;
			/* NFULA_HWHDR exists and is supposed to contain source
			 * hardware address. However, for ip_gre it seems to be
			 * the nexthop destination address if the packet matches
			 * route. */
		}
	}

	if (!pkthdr || !in_ndx || !zbuf_used(&pktpl))
		return;

	ifp = if_lookup_by_index(htonl(*in_ndx), VRF_DEFAULT);
	if (!ifp)
		return;

	nhrp_peer_send_indication(ifp, htons(pkthdr->hw_protocol), &pktpl);
}

static int netlink_log_recv(struct thread *t)
{
	uint8_t buf[ZNL_BUFFER_SIZE];
	int fd = THREAD_FD(t);
	struct zbuf payload, zb;
	struct nlmsghdr *n;

	netlink_log_thread = NULL;

	zbuf_init(&zb, buf, sizeof(buf), 0);
	while (zbuf_recv(&zb, fd) > 0) {
		while ((n = znl_nlmsg_pull(&zb, &payload)) != 0) {
			debugf(NHRP_DEBUG_KERNEL,
			       "Netlink-log: Received msg_type %u, msg_flags %u",
			       n->nlmsg_type, n->nlmsg_flags);
			switch (n->nlmsg_type) {
			case (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET:
				netlink_log_indication(n, &payload);
				break;
			}
		}
	}

	thread_add_read(master, netlink_log_recv, 0, netlink_log_fd,
			&netlink_log_thread);

	return 0;
}

void netlink_set_nflog_group(int nlgroup)
{
	if (netlink_log_fd >= 0) {
		THREAD_OFF(netlink_log_thread);
		close(netlink_log_fd);
		netlink_log_fd = -1;
	}
	netlink_nflog_group = nlgroup;
	if (nlgroup) {
		netlink_log_fd = znl_open(NETLINK_NETFILTER, 0);
		if (netlink_log_fd < 0)
			return;

		netlink_log_register(netlink_log_fd, nlgroup);
		thread_add_read(master, netlink_log_recv, 0, netlink_log_fd,
				&netlink_log_thread);
	}
}

void netlink_init(void)
{
	netlink_req_fd = znl_open(NETLINK_ROUTE, 0);
	if (netlink_req_fd < 0)
		return;

	netlink_listen_fd = znl_open(NETLINK_ROUTE, RTMGRP_NEIGH);
	if (netlink_listen_fd < 0)
		return;

	thread_add_read(master, netlink_route_recv, 0, netlink_listen_fd, NULL);
}

int netlink_configure_arp(unsigned int ifindex, int pf)
{
	struct nlmsghdr *n;
	struct ndtmsg *ndtm;
	struct rtattr *rta;
	struct zbuf *zb = zbuf_alloc(512);
	int r;

	n = znl_nlmsg_push(zb, RTM_SETNEIGHTBL, NLM_F_REQUEST | NLM_F_REPLACE);
	ndtm = znl_push(zb, sizeof(*ndtm));
	*ndtm = (struct ndtmsg){
		.ndtm_family = pf,
	};

	znl_rta_push(zb, NDTA_NAME, pf == AF_INET ? "arp_cache" : "ndisc_cache",
		     10);

	rta = znl_rta_nested_push(zb, NDTA_PARMS);
	znl_rta_push_u32(zb, NDTPA_IFINDEX, ifindex);
	znl_rta_push_u32(zb, NDTPA_APP_PROBES, 1);
	znl_rta_push_u32(zb, NDTPA_MCAST_PROBES, 0);
	znl_rta_push_u32(zb, NDTPA_UCAST_PROBES, 0);
	znl_rta_nested_complete(zb, rta);

	znl_nlmsg_complete(zb, n);
	r = zbuf_send(zb, netlink_req_fd);
	zbuf_recv(zb, netlink_req_fd);
	zbuf_free(zb);

	return r;
}
