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
#include "nhrp_mcast_oil.h"

DEFINE_MTYPE_STATIC(NHRPD, NHRP_MULTICAST, "NHRP Multicast");

int netlink_mcast_nflog_group;
static int netlink_mcast_log_fd = -1;
static struct event *netlink_mcast_log_thread;

/* Inner IP decoded from an NFLOG payload; passed through the
 * replication walk so every per-NBMA decision uses the same parse.
 */
struct mcast_ctx {
	struct interface *ifp;
	struct zbuf *pkt;
	/* Parsed inner IPv4 header -- populated once per NFLOG message. */
	bool parsed;
	bool is_pim;	  /* protocol == 103 */
	union sockunion inner_src;
	union sockunion inner_dst;
	uint8_t inner_proto;
	uint8_t inner_ihl_bytes;
};

/* Parse the inner IPv4 header from an NFLOG payload. Sets ctx->parsed
 * true iff the header was structurally valid. The zbuf cursor is not
 * advanced -- callers may still read the full payload.
 */
static void parse_inner_ipv4(struct mcast_ctx *ctx)
{
	const uint8_t *p;
	size_t n;

	ctx->parsed = false;
	ctx->is_pim = false;
	memset(&ctx->inner_src, 0, sizeof(ctx->inner_src));
	memset(&ctx->inner_dst, 0, sizeof(ctx->inner_dst));

	if (!ctx->pkt)
		return;
	n = zbuf_used(ctx->pkt);
	if (n < 20)
		return;
	p = ctx->pkt->head;

	/* Version 4? */
	if ((p[0] >> 4) != 4)
		return;
	ctx->inner_ihl_bytes = (p[0] & 0x0f) * 4;
	if (ctx->inner_ihl_bytes < 20 || ctx->inner_ihl_bytes > n)
		return;

	ctx->inner_proto = p[9];
	ctx->is_pim = (ctx->inner_proto == 103);

	ctx->inner_src.sa.sa_family = AF_INET;
	memcpy(&ctx->inner_src.sin.sin_addr, p + 12, 4);
	ctx->inner_dst.sa.sa_family = AF_INET;
	memcpy(&ctx->inner_dst.sin.sin_addr, p + 16, 4);

	ctx->parsed = true;
}

/* PIM Join/Prune snoop. RFC 7761 sect.4.9.5.1 encoding:
 *   0               1               2               3
 *   0..7            8..15           16..23          24..31
 *   | PIM ver/type=3 | reserved     | checksum (16b)             |
 *   | Upstream Nbr Encoded-Unicast-Address                       |
 *   | reserved (8) | num groups (8) | holdtime (16b)             |
 *   per group:
 *     | Encoded-Group-Address                                     |
 *     | num joined sources (16) | num pruned sources (16)         |
 *     | per-source: Encoded-Source-Address                         |
 *
 * We parse enough to extract (group, [sources], holdtime, sender tunnel_ip).
 */
static void snoop_pim_joinprune(struct mcast_ctx *ctx);

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
	union sockunion *peer_nbma;

	if (c->cur.type != NHRP_CACHE_DYNAMIC || !c->cur.peer)
		return;

	peer_nbma = &c->cur.peer->vc->remote.nbma;

	/* PIM-SM OIL filter. Only apply when we have a parsed IPv4 inner
	 * packet destined at user-data multicast (not 224.0.0.0/24). If
	 * there is no OIL entry at all for this (S, G, iface), we fall
	 * back to fanout to preserve compatibility with interfaces that
	 * haven't been migrated to NBMA-mode.
	 *
	 * An operator opts into strict filtering by enabling `ip pim nbma`
	 * on the interface (see 0001). When that flag is true, we drop
	 * instead of fanning out on a missing OIL -- matching Cisco's
	 * "nothing delivered without a Join" semantics.
	 */
	if (ctx->parsed && !nhrp_mcast_is_linklocal(&ctx->inner_dst)) {
		bool default_fanout = true;
		struct nhrp_interface *nifp = ctx->ifp->info;

		if (nifp && nifp->nbma_mode_enabled)
			default_fanout = false;

		if (!nhrp_mcast_oil_contains(ctx->ifp, &ctx->inner_src,
					     &ctx->inner_dst, peer_nbma,
					     default_fanout)) {
			debugf(NHRP_DEBUG_COMMON,
			       "mcast-oil: drop (S=%pSU,G=%pSU) to %pSU -- not in OIL",
			       &ctx->inner_src, &ctx->inner_dst, peer_nbma);
			return;
		}
	}

	nhrp_multicast_forward_nbma(peer_nbma, ctx->ifp, ctx->pkt);
}

/* RFC 1071 Internet checksum over `buf`, returning 1 iff the buffer's
 * embedded checksum field (already part of `buf`) verifies. We sum all
 * 16-bit big-endian words including the stored checksum; a valid PIM
 * message folds to 0xffff (whose ones-complement is 0).
 */
static bool pim_checksum_valid(const uint8_t *buf, size_t len)
{
	uint32_t sum = 0;
	size_t i;

	for (i = 0; i + 1 < len; i += 2)
		sum += ((uint32_t)buf[i] << 8) | buf[i + 1];
	if (i < len)
		sum += (uint32_t)buf[i] << 8;
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return sum == 0xffff;
}

/* PIM Join/Prune snoop body. Parses enough of a PIM v2 Join/Prune
 * message to build the per-NBMA OIL. Called only when the inner IP
 * protocol is 103 (PIM). Sender's tunnel IP is the inner_src -- on a
 * DMVPN this is the spoke's overlay address (e.g. 192.168.200.3),
 * which nhrpd's cache maps to the NBMA.
 */
static void snoop_pim_joinprune(struct mcast_ctx *ctx)
{
	const uint8_t *pim;
	size_t pim_len, payload_off;
	uint8_t type;
	uint16_t holdtime;
	uint8_t num_groups;
	size_t off;
	int g, i;
	int num_joins, num_prunes;
	union sockunion grp, src;

	if (!ctx->parsed || !ctx->is_pim || !ctx->pkt)
		return;

	payload_off = ctx->inner_ihl_bytes;
	if (zbuf_used(ctx->pkt) < payload_off + 10)
		return;
	pim = (const uint8_t *)ctx->pkt->head + payload_off;
	pim_len = zbuf_used(ctx->pkt) - payload_off;

	/* PIM common header: [ver(4b)|type(4b)] [reserved] [checksum] */
	if ((pim[0] >> 4) != 2)
		return;
	type = pim[0] & 0x0f;
	if (type != 3)	/* Join/Prune */
		return;

	/* RFC 7761 sect.4.9.2: verify the PIM checksum before populating OIL.
	 * Spoofed/corrupt PIM on the tunnel must not be allowed to inject
	 * NBMA entries -- we only trust messages whose checksum verifies.
	 */
	if (!pim_checksum_valid(pim, pim_len)) {
		debugf(NHRP_DEBUG_COMMON, "%s: drop, bad PIM checksum (len=%zu)", __func__,
		       pim_len);
		return;
	}

	/* Upstream Nbr Encoded-Unicast-Address: [family(1)][enctype(1)][addr(N)] */
	off = 4;
	if (off + 2 > pim_len)
		return;
	uint8_t ufam = pim[off];

	if (ufam != 1)	/* AF_INET */
		return;
	off += 2;
	if (off + 4 > pim_len)
		return;
	/* skip upstream-nbr addr (4 bytes for AF_INET) */
	off += 4;

	/* reserved(1) num-groups(1) holdtime(2) */
	if (off + 4 > pim_len)
		return;
	off += 1;
	num_groups = pim[off++];
	holdtime = (pim[off] << 8) | pim[off + 1];
	off += 2;

	for (g = 0; g < num_groups; g++) {
		/* Encoded-Group-Address: family(1) enctype(1) reserved(1)
		 * mask-len(1) group-addr(4 for v4). Total 8 bytes.
		 */
		if (off + 8 > pim_len)
			return;
		if (pim[off] != 1)
			return;
		memset(&grp, 0, sizeof(grp));
		grp.sa.sa_family = AF_INET;
		memcpy(&grp.sin.sin_addr, pim + off + 4, 4);
		off += 8;

		/* num-joined-srcs(2) num-pruned-srcs(2) */
		if (off + 4 > pim_len)
			return;
		num_joins = (pim[off] << 8) | pim[off + 1];
		off += 2;
		num_prunes = (pim[off] << 8) | pim[off + 1];
		off += 2;

		/* Each Encoded-Source-Address: family(1) enctype(1) flags(1)
		 * mask-len(1) src-addr(4 for v4). Total 8 bytes. The flags
		 * byte carries S/W/R bits; W=1 plus all-zeros src means the
		 * source is the RP (i.e. this is a (*,G) join).
		 */
		for (i = 0; i < num_joins; i++) {
			uint8_t flags;
			bool wc;

			if (off + 8 > pim_len)
				return;
			flags = pim[off + 2];
			wc = (flags & 0x02) != 0;  /* W bit */
			memset(&src, 0, sizeof(src));
			src.sa.sa_family = AF_INET;
			memcpy(&src.sin.sin_addr, pim + off + 4, 4);
			off += 8;

			nhrp_mcast_oil_join(ctx->ifp, &src, &grp,
					    &ctx->inner_src, holdtime, wc);
		}
		for (i = 0; i < num_prunes; i++) {
			uint8_t pflags;
			bool pwc, prpt;

			if (off + 8 > pim_len)
				return;
			pflags = pim[off + 2];
			pwc  = (pflags & 0x02) != 0;  /* W bit */
			prpt = (pflags & 0x01) != 0;  /* R bit */
			memset(&src, 0, sizeof(src));
			src.sa.sa_family = AF_INET;
			memcpy(&src.sin.sin_addr, pim + off + 4, 4);
			off += 8;

			/* (W=1,R=1)   = (*,G)     Prune    -> drop (*,G)
			 * (W=0,R=0)   = (S,G)     Prune    -> drop (S,G)
			 * (W=0,R=1)   = (S,G,rpt) Prune    -> SPT switchover;
			 *                                    don't touch
			 *                                    (*,G) or (S,G).
			 *                                    We don't track
			 *                                    (S,G,rpt) state
			 *                                    separately, so no-op.
			 */
			nhrp_mcast_oil_prune(ctx->ifp, &src, &grp,
					     &ctx->inner_src, pwc, prpt);
		}
	}
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
	uint32_t *in_ndx = NULL;
	afi_t afi;
	struct mcast_ctx ctx;

	memset(&ctx, 0, sizeof(ctx));

	nf = znl_pull(zb, sizeof(*nf));
	if (!nf)
		return;

	while ((rta = znl_rta_pull(zb, &rtapl)) != NULL) {
		switch (rta->rta_type) {
		case NFULA_IFINDEX_OUTDEV:
			out_ndx = znl_pull(&rtapl, sizeof(*out_ndx));
			break;
		case NFULA_IFINDEX_INDEV:
			in_ndx = znl_pull(&rtapl, sizeof(*in_ndx));
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

	if (!ctx.pkt)
		return;

	/* Parse inner IP once; both the PIM snoop (input direction) and
	 * the replication filter (output direction) read the same data.
	 */
	parse_inner_ipv4(&ctx);

	/* Direction dispatch:
	 *  - OUT (NFULA_IFINDEX_OUTDEV set): replicate to peers, subject
	 *    to the OIL filter inside nhrp_multicast_forward_cache.
	 *  - IN  (NFULA_IFINDEX_INDEV set):  if this is a PIM Join/Prune,
	 *    record the sender's NBMA in the OIL cache. No replication.
	 */
	if (out_ndx) {
		ctx.ifp = if_lookup_by_index(ntohl(*out_ndx), VRF_DEFAULT);
		if (!ctx.ifp)
			return;

		debugf(NHRP_DEBUG_COMMON,
		       "Intercepted multicast packet leaving %s len %zu",
		       ctx.ifp->name, zbuf_used(ctx.pkt));

		for (afi = 0; afi < AFI_MAX; afi++) {
			nhrp_multicast_foreach(ctx.ifp, afi,
					       nhrp_multicast_forward,
					       (void *)&ctx);
		}
	} else if (in_ndx) {
		ctx.ifp = if_lookup_by_index(ntohl(*in_ndx), VRF_DEFAULT);
		if (!ctx.ifp)
			return;

		if (ctx.is_pim) {
			debugf(NHRP_DEBUG_COMMON,
			       "Intercepted PIM packet arriving on %s len %zu",
			       ctx.ifp->name, zbuf_used(ctx.pkt));
			snoop_pim_joinprune(&ctx);
		}
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
		event_cancel(&netlink_mcast_log_thread);
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
