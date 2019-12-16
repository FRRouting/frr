/* NHRP netlink/neighbor table arpd code
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

#include <fcntl.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <linux/netlink.h>
#include <linux/neighbour.h>
#include <linux/netfilter/nfnetlink_log.h>

#include "thread.h"
#include "stream.h"
#include "prefix.h"
#include "nhrpd.h"
#include "netlink.h"
#include "znl.h"

int netlink_req_fd = -1;
int netlink_nflog_group;
static int netlink_log_fd = -1;
static struct thread *netlink_log_thread;
typedef void (*netlink_dispatch_f)(struct nlmsghdr *msg, struct zbuf *zb);

void netlink_update_binding(struct interface *ifp, union sockunion *proto,
			    union sockunion *nbma)
{
	nhrp_send_zebra_nbr(proto, nbma, ifp);
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
		while ((n = znl_nlmsg_pull(&zb, &payload)) != NULL) {
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
		thread_cancel(&netlink_log_thread);
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

void nhrp_neighbor_operation(ZAPI_CALLBACK_ARGS)
{
	union sockunion addr = {}, lladdr = {};
	struct interface *ifp;
	ifindex_t idx;
	struct ethaddr mac;
	int state, ndm_state;
	struct nhrp_cache *c;
	unsigned short l2_len;

	STREAM_GETL(zclient->ibuf, idx);
	ifp = if_lookup_by_index(idx, vrf_id);
	STREAM_GETW(zclient->ibuf, addr.sa.sa_family);
	if (addr.sa.sa_family == AF_INET) {
		STREAM_GET(&addr.sin.sin_addr.s_addr,
			   zclient->ibuf, IPV4_MAX_BYTELEN);
	} else {
		STREAM_GET(&addr.sin6.sin6_addr.s6_addr,
			   zclient->ibuf, IPV6_MAX_BYTELEN);
	}
	STREAM_GETL(zclient->ibuf, ndm_state);

	STREAM_GETL(zclient->ibuf, l2_len);
	if (l2_len) {
		STREAM_GET(&mac, zclient->ibuf, l2_len);
		if (l2_len == IPV4_MAX_BYTELEN)
			sockunion_set(&lladdr, AF_INET, (const uint8_t *)&mac,
				      l2_len);
	}
	if (!ifp)
		return;
	c = nhrp_cache_get(ifp, &addr, 0);
	if (!c)
		return;
	debugf(NHRP_DEBUG_KERNEL,
	       "Netlink: %s %pSU dev %s lladdr %pSU nud 0x%x cache used %u type %u",
	       (cmd == ZEBRA_NHRP_NEIGH_GET)
	       ? "who-has"
	       : (cmd == ZEBRA_NHRP_NEIGH_ADDED) ? "new-neigh"
	       : "del-neigh",
	       &addr, ifp->name, &lladdr, ndm_state, c->used, c->cur.type);
	if (cmd == ZEBRA_NHRP_NEIGH_GET) {
		if (c->cur.type >= NHRP_CACHE_CACHED) {
			nhrp_cache_set_used(c, 1);
			debugf(NHRP_DEBUG_KERNEL,
			       "Netlink: update binding for %pSU dev %s from c %pSU peer.vc.nbma %pSU to lladdr %pSU",
			       &addr, ifp->name, &c->cur.remote_nbma_natoa,
			       &c->cur.peer->vc->remote.nbma, &lladdr);
			/* In case of shortcuts, nbma is given by lladdr, not
			 * vc->remote.nbma.
			 */
			netlink_update_binding(ifp, &addr, &lladdr);
		}
	} else {
		state = (cmd == ZEBRA_NHRP_NEIGH_ADDED) ? ndm_state
			: NUD_FAILED;
		nhrp_cache_set_used(c, state == NUD_REACHABLE);
	}
	return;
 stream_failure:
	return;
}

void netlink_init(void)
{
	netlink_req_fd = znl_open(NETLINK_ROUTE, 0);
	if (netlink_req_fd < 0)
		return;
}
