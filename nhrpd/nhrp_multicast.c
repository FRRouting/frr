// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP Multicast Support
 * Copyright (c) 2020-2021 4RF Limited
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef GNU_LINUX
#include <linux/rtnetlink.h>
#endif

#include <fcntl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <linux/netlink.h>
#include <linux/neighbour.h>
#include <linux/netfilter/nfnetlink_log.h>
#include <linux/if_packet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "frrevent.h"
#include "nhrpd.h"
#include "netlink.h"
#include "znl.h"
#include "os.h"

DEFINE_MTYPE_STATIC(NHRPD, NHRP_MULTICAST, "NHRP Multicast");

int netlink_mcast_nflog_group;
static int netlink_mcast_log_fd = -1;
static struct event *netlink_mcast_log_thread;

struct mcast_ctx {
	struct interface *ifp;
	struct zbuf *pkt;
};

static void nhrp_multicast_send(struct nhrp_peer *p, struct zbuf *zb)
{
	size_t addrlen;
	int ret;

	addrlen = sockunion_get_addrlen(&p->vc->remote.nbma);
	ret = os_sendmsg(zb->head, zbuf_used(zb), p->ifp->ifindex,
			 sockunion_get_addr(&p->vc->remote.nbma), addrlen,
			 addrlen == 4 ? ETH_P_IP : ETH_P_IPV6);

	debugf(NHRP_DEBUG_COMMON,
	       "Multicast Packet: %pSU -> %pSU, ret = %d, size = %zu, addrlen = %zu",
	       &p->vc->local.nbma, &p->vc->remote.nbma, ret, zbuf_used(zb),
	       addrlen);
}

static void nhrp_multicast_forward_nbma(union sockunion *nbma_addr,
					struct interface *ifp, struct zbuf *pkt)
{
	struct nhrp_peer *p = nhrp_peer_get(ifp, nbma_addr);

	if (p && p->online) {
		/* Send packet */
		nhrp_multicast_send(p, pkt);
	}
	nhrp_peer_unref(p);
}

static void nhrp_multicast_forward_cache(struct nhrp_cache *c, void *pctx)
{
	struct mcast_ctx *ctx = (struct mcast_ctx *)pctx;

	if (c->cur.type == NHRP_CACHE_DYNAMIC && c->cur.peer)
		nhrp_multicast_forward_nbma(&c->cur.peer->vc->remote.nbma,
					    ctx->ifp, ctx->pkt);
}

static void nhrp_multicast_forward(struct nhrp_multicast *mcast, void *pctx)
{
	struct mcast_ctx *ctx = (struct mcast_ctx *)pctx;
	struct nhrp_interface *nifp = ctx->ifp->info;

	if (!nifp->enabled)
		return;

	/* dynamic */
	if (sockunion_family(&mcast->nbma_addr) == AF_UNSPEC) {
		nhrp_cache_foreach(ctx->ifp, nhrp_multicast_forward_cache,
				   pctx);
		return;
	}

	/* Fixed IP Address */
	nhrp_multicast_forward_nbma(&mcast->nbma_addr, ctx->ifp, ctx->pkt);
}

static void netlink_mcast_log_handler(struct nlmsghdr *msg, struct zbuf *zb)
{
	struct nfgenmsg *nf;
	struct rtattr *rta;
	struct zbuf rtapl;
	uint32_t *out_ndx = NULL;
	afi_t afi;
	struct mcast_ctx ctx;

	nf = znl_pull(zb, sizeof(*nf));
	if (!nf)
		return;

	ctx.pkt = NULL;
	while ((rta = znl_rta_pull(zb, &rtapl)) != NULL) {
		switch (rta->rta_type) {
		case NFULA_IFINDEX_OUTDEV:
			out_ndx = znl_pull(&rtapl, sizeof(*out_ndx));
			break;
		case NFULA_PAYLOAD:
			ctx.pkt = &rtapl;
			break;
			/* NFULA_HWHDR exists and is supposed to contain source
			 * hardware address. However, for ip_gre it seems to be
			 * the nexthop destination address if the packet matches
			 * route.
			 */
		}
	}

	if (!out_ndx || !ctx.pkt)
		return;

	ctx.ifp = if_lookup_by_index(htonl(*out_ndx), VRF_DEFAULT);
	if (!ctx.ifp)
		return;

	debugf(NHRP_DEBUG_COMMON,
	       "Intercepted multicast packet leaving %s len %zu",
	       ctx.ifp->name, zbuf_used(ctx.pkt));

	for (afi = 0; afi < AFI_MAX; afi++) {
		nhrp_multicast_foreach(ctx.ifp, afi, nhrp_multicast_forward,
				       (void *)&ctx);
	}
}

static void netlink_mcast_log_recv(struct event *t)
{
	uint8_t buf[65535]; /* Max OSPF Packet size */
	int fd = EVENT_FD(t);
	struct zbuf payload, zb;
	struct nlmsghdr *n;


	zbuf_init(&zb, buf, sizeof(buf), 0);
	while (zbuf_recv(&zb, fd) > 0) {
		while ((n = znl_nlmsg_pull(&zb, &payload)) != NULL) {
			debugf(NHRP_DEBUG_COMMON,
			       "Netlink-mcast-log: Received msg_type %u, msg_flags %u",
			       n->nlmsg_type, n->nlmsg_flags);
			switch (n->nlmsg_type) {
			case (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET:
				netlink_mcast_log_handler(n, &payload);
				break;
			}
		}
	}

	event_add_read(master, netlink_mcast_log_recv, 0, netlink_mcast_log_fd,
		       &netlink_mcast_log_thread);
}

static void netlink_mcast_log_register(int fd, int group)
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

void netlink_mcast_set_nflog_group(int nlgroup)
{
	if (netlink_mcast_log_fd >= 0) {
		EVENT_OFF(netlink_mcast_log_thread);
		close(netlink_mcast_log_fd);
		netlink_mcast_log_fd = -1;
		debugf(NHRP_DEBUG_COMMON, "De-register nflog group");
	}
	netlink_mcast_nflog_group = nlgroup;
	if (nlgroup) {
		netlink_mcast_log_fd = znl_open(NETLINK_NETFILTER, 0);
		if (netlink_mcast_log_fd < 0)
			return;

		netlink_mcast_log_register(netlink_mcast_log_fd, nlgroup);
		event_add_read(master, netlink_mcast_log_recv, 0,
			       netlink_mcast_log_fd, &netlink_mcast_log_thread);
		debugf(NHRP_DEBUG_COMMON, "Register nflog group: %d",
		       netlink_mcast_nflog_group);
	}
}

static int nhrp_multicast_free(struct interface *ifp,
			       struct nhrp_multicast *mcast)
{
	struct nhrp_interface *nifp = ifp->info;

	nhrp_mcastlist_del(&nifp->afi[mcast->afi].mcastlist_head, mcast);
	XFREE(MTYPE_NHRP_MULTICAST, mcast);
	return 0;
}

int nhrp_multicast_add(struct interface *ifp, afi_t afi,
		       union sockunion *nbma_addr)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_multicast *mcast;

	frr_each (nhrp_mcastlist, &nifp->afi[afi].mcastlist_head, mcast) {
		if (sockunion_same(&mcast->nbma_addr, nbma_addr))
			return NHRP_ERR_ENTRY_EXISTS;
	}

	mcast = XMALLOC(MTYPE_NHRP_MULTICAST, sizeof(struct nhrp_multicast));

	*mcast = (struct nhrp_multicast){
		.afi = afi, .ifp = ifp, .nbma_addr = *nbma_addr,
	};
	nhrp_mcastlist_add_tail(&nifp->afi[afi].mcastlist_head, mcast);

	debugf(NHRP_DEBUG_COMMON, "Adding multicast entry (%pSU)", nbma_addr);

	return NHRP_OK;
}

int nhrp_multicast_del(struct interface *ifp, afi_t afi,
		       union sockunion *nbma_addr)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_multicast *mcast;

	frr_each_safe (nhrp_mcastlist, &nifp->afi[afi].mcastlist_head, mcast) {
		if (!sockunion_same(&mcast->nbma_addr, nbma_addr))
			continue;

		debugf(NHRP_DEBUG_COMMON, "Deleting multicast entry (%pSU)",
		       nbma_addr);

		nhrp_multicast_free(ifp, mcast);

		return NHRP_OK;
	}

	return NHRP_ERR_ENTRY_NOT_FOUND;
}

void nhrp_multicast_interface_del(struct interface *ifp)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_multicast *mcast;
	afi_t afi;

	for (afi = 0; afi < AFI_MAX; afi++) {
		debugf(NHRP_DEBUG_COMMON, "Cleaning up multicast entries (%zu)",
		       nhrp_mcastlist_count(&nifp->afi[afi].mcastlist_head));

		frr_each_safe (nhrp_mcastlist, &nifp->afi[afi].mcastlist_head,
			       mcast) {
			nhrp_multicast_free(ifp, mcast);
		}
	}
}

void nhrp_multicast_foreach(struct interface *ifp, afi_t afi,
			    void (*cb)(struct nhrp_multicast *, void *),
			    void *ctx)
{
	struct nhrp_interface *nifp = ifp->info;
	struct nhrp_multicast *mcast;

	frr_each (nhrp_mcastlist, &nifp->afi[afi].mcastlist_head, mcast) {
		cb(mcast, ctx);
	}
}
