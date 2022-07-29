/*
 * Zebra Traffic Control (TC) interaction with the kernel using netlink.
 *
 * Copyright (C) 2022 Shichu Yang
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#ifdef HAVE_NETLINK

#include <linux/if_ether.h>
#include <sys/socket.h>

#include "if.h"
#include "prefix.h"
#include "vrf.h"

#include <linux/fib_rules.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rt.h"
#include "zebra/interface.h"
#include "zebra/debug.h"
#include "zebra/rtadv.h"
#include "zebra/kernel_netlink.h"
#include "zebra/tc_netlink.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_trace.h"

/* TODO: move these bitflags to zebra_tc.h */
#define TC_FILTER_SRC_IP (1 << 0)
#define TC_FILTER_DST_IP (1 << 1)
#define TC_FILTER_IP_PROTOCOL (1 << 9)

#define TC_FREQ_DEFAULT (100)

#define TC_MAJOR_BASE (0x1000u)
#define TC_MINOR_NOCLASS (0xffffu)

#define TC_FILTER_MASK (0x8000u)

#define TIME_UNITS_PER_SEC (1000000)
#define xmittime(r, s) (TIME_UNITS_PER_SEC * ((double)(s) / (double)(r)))

static uint32_t tc_get_freq(void)
{
	int freq = 0;
	FILE *fp = fopen("/proc/net/psched", "r");

	if (fp) {
		uint32_t nom, denom;

		if (fscanf(fp, "%*08x%*08x%08x%08x", &nom, &denom) == 2) {
			if (nom == 1000000)
				freq = denom;
		}
		fclose(fp);
	}

	return freq == 0 ? TC_FREQ_DEFAULT : freq;
}

static inline uint32_t tc_make_handle(uint16_t major, uint16_t minor)
{
	return (major) << 16 | (minor);
}

static inline uint32_t tc_get_handle(struct zebra_dplane_ctx *ctx,
				     uint16_t minor)
{
	uint16_t major = TC_MAJOR_BASE + (uint16_t)dplane_ctx_get_ifindex(ctx);

	return tc_make_handle(major, minor);
}

static void tc_calc_rate_table(struct tc_ratespec *ratespec, uint32_t *table,
			       uint32_t mtu)
{
	if (mtu == 0)
		mtu = 2047;

	int cell_log = -1;

	if (cell_log < 0) {
		cell_log = 0;
		while ((mtu >> cell_log) > 255)
			cell_log++;
	}

	for (int i = 0; i < 256; i++)
		table[i] = xmittime(ratespec->rate, (i + 1) << cell_log);

	ratespec->cell_align = -1;
	ratespec->cell_log = cell_log;
	ratespec->linklayer = TC_LINKLAYER_ETHERNET;
}

static int tc_flower_get_inet_prefix(const struct prefix *prefix,
				     struct inet_prefix *addr)
{
	addr->family = prefix->family;

	if (addr->family == AF_INET) {
		addr->bytelen = 4;
		addr->bitlen = prefix->prefixlen;
		addr->flags = 0;
		addr->flags |= PREFIXLEN_SPECIFIED;
		addr->flags |= ADDRTYPE_INET;
		memcpy(addr->data, prefix->u.val32, sizeof(prefix->u.val32));
	} else if (addr->family == AF_INET6) {
		addr->bytelen = 16;
		addr->bitlen = prefix->prefixlen;
		addr->flags = 0;
		addr->flags |= PREFIXLEN_SPECIFIED;
		addr->flags |= ADDRTYPE_INET;
		memcpy(addr->data, prefix->u.val, sizeof(prefix->u.val));
	} else {
		return -1;
	}

	return 0;
}

static int tc_flower_get_inet_mask(const struct prefix *prefix,
				   struct inet_prefix *addr)
{
	addr->family = prefix->family;

	if (addr->family == AF_INET) {
		addr->bytelen = 4;
		addr->bitlen = prefix->prefixlen;
		addr->flags = 0;
		addr->flags |= PREFIXLEN_SPECIFIED;
		addr->flags |= ADDRTYPE_INET;
	} else if (addr->family == AF_INET6) {
		addr->bytelen = 16;
		addr->bitlen = prefix->prefixlen;
		addr->flags = 0;
		addr->flags |= PREFIXLEN_SPECIFIED;
		addr->flags |= ADDRTYPE_INET;
	} else {
		return -1;
	}

	memset(addr->data, 0xff, addr->bytelen);

	int rest = prefix->prefixlen;

	for (int i = 0; i < addr->bytelen / 4; i++) {
		if (!rest) {
			addr->data[i] = 0;
		} else if (rest / 32 >= 1) {
			rest -= 32;
		} else {
			addr->data[i] <<= 32 - rest;
			addr->data[i] = htonl(addr->data[i]);
			rest = 0;
		}
	}

	return 0;
}

/*
 * Traffic control queue discipline encoding (only "htb" supported)
 */
static ssize_t netlink_qdisc_msg_encode(int cmd, struct zebra_dplane_ctx *ctx,
					void *data, size_t datalen)
{
	struct nlsock *nl;

	const char *kind = "htb";

	struct tc_htb_glob htb_glob = {
		.rate2quantum = 10, .version = 3, .defcls = TC_MINOR_NOCLASS};

	struct rtattr *nest;

	struct {
		struct nlmsghdr n;
		struct tcmsg t;
		char buf[0];
	} *req = (void *)data;

	if (datalen < sizeof(*req))
		return 0;

	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	req->n.nlmsg_flags |= NLM_F_REPLACE;

	req->n.nlmsg_type = cmd;

	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->t.tcm_family = AF_UNSPEC;
	req->t.tcm_ifindex = dplane_ctx_get_ifindex(ctx);
	req->t.tcm_handle = tc_get_handle(ctx, 0);
	req->t.tcm_parent = TC_H_ROOT;

	nl_attr_put(&req->n, datalen, TCA_KIND, kind, strlen(kind) + 1);

	nest = nl_attr_nest(&req->n, datalen, TCA_OPTIONS);

	nl_attr_put(&req->n, datalen, TCA_HTB_INIT, &htb_glob,
		    sizeof(htb_glob));
	nl_attr_nest_end(&req->n, nest);

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

/*
 * Traffic control class encoding
 */
static ssize_t netlink_tclass_msg_encode(int cmd, struct zebra_dplane_ctx *ctx,
					 void *data, size_t datalen)
{
	struct nlsock *nl;
	struct tc_htb_opt htb_opt = {};

	uint64_t rate, ceil;
	uint64_t buffer, cbuffer;

	/* TODO: fetch mtu from interface */
	uint32_t mtu = 0;

	uint32_t rtab[256];
	uint32_t ctab[256];

	struct rtattr *nest;

	struct {
		struct nlmsghdr n;
		struct tcmsg t;
		char buf[0];
	} *req = (void *)data;

	if (datalen < sizeof(*req))
		return 0;

	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	req->n.nlmsg_type = cmd;

	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->t.tcm_family = AF_UNSPEC;
	req->t.tcm_ifindex = dplane_ctx_get_ifindex(ctx);
	req->t.tcm_handle = tc_get_handle(ctx, 1);
	req->t.tcm_parent = tc_get_handle(ctx, 0);

	rate = dplane_ctx_tc_get_rate(ctx);
	ceil = dplane_ctx_tc_get_ceil(ctx);

	ceil = ceil < rate ? rate : ceil;

	htb_opt.rate.rate = (rate >> 32 != 0) ? ~0U : rate;
	htb_opt.ceil.rate = (ceil >> 32 != 0) ? ~0U : ceil;

	buffer = rate / tc_get_freq(), cbuffer = ceil / tc_get_freq();

	htb_opt.buffer = buffer;
	htb_opt.cbuffer = cbuffer;

	tc_calc_rate_table(&htb_opt.rate, rtab, mtu);
	tc_calc_rate_table(&htb_opt.ceil, rtab, mtu);

	htb_opt.ceil.mpu = htb_opt.rate.mpu = 0;
	htb_opt.ceil.overhead = htb_opt.rate.overhead = 0;

	nest = nl_attr_nest(&req->n, datalen, TCA_OPTIONS);

	if (rate >> 32 != 0) {
		nl_attr_put(&req->n, datalen, TCA_HTB_CEIL64, &rate,
			    sizeof(rate));
	}

	if (ceil >> 32 != 0) {
		nl_attr_put(&req->n, datalen, TCA_HTB_CEIL64, &ceil,
			    sizeof(ceil));
	}

	nl_attr_put(&req->n, datalen, TCA_HTB_PARMS, &htb_opt, sizeof(htb_opt));

	nl_attr_put(&req->n, datalen, TCA_HTB_RTAB, rtab, sizeof(rtab));
	nl_attr_put(&req->n, datalen, TCA_HTB_CTAB, ctab, sizeof(ctab));
	nl_attr_nest_end(&req->n, nest);

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

/*
 * Traffic control filter encoding (only "flower" supported)
 */
static ssize_t netlink_tfilter_msg_encode(int cmd, struct zebra_dplane_ctx *ctx,
					  void *data, size_t datalen)
{
	struct nlsock *nl;
	struct rtattr *nest;

	const char *kind = "flower";

	uint16_t priority;
	uint16_t protocol;
	uint32_t classid;
	uint32_t filter_bm;
	uint32_t flags = 0;

	struct inet_prefix addr;

	struct {
		struct nlmsghdr n;
		struct tcmsg t;
		char buf[0];
	} *req = (void *)data;

	if (datalen < sizeof(*req))
		return 0;

	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	req->n.nlmsg_flags |= NLM_F_EXCL;

	req->n.nlmsg_type = cmd;

	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->t.tcm_family = AF_UNSPEC;
	req->t.tcm_ifindex = dplane_ctx_get_ifindex(ctx);

	/* TODO: priority and layer-3 protocol support */
	priority = 0;
	protocol = htons(ETH_P_IP);
	classid = tc_get_handle(ctx, 1);
	filter_bm = dplane_ctx_tc_get_filter_bm(ctx);

	req->t.tcm_info = tc_make_handle(priority, protocol);

	req->t.tcm_handle = 1;
	req->t.tcm_parent = tc_get_handle(ctx, 0);

	nl_attr_put(&req->n, datalen, TCA_KIND, kind, strlen(kind) + 1);
	nest = nl_attr_nest(&req->n, datalen, TCA_OPTIONS);

	nl_attr_put(&req->n, datalen, TCA_FLOWER_CLASSID, &classid,
		    sizeof(classid));

	if (filter_bm & TC_FILTER_SRC_IP) {
		const struct prefix *src_p = dplane_ctx_tc_get_src_ip(ctx);

		if (tc_flower_get_inet_prefix(src_p, &addr) != 0)
			return 0;

		nl_attr_put(&req->n, datalen,
			    (addr.family == AF_INET) ? TCA_FLOWER_KEY_IPV4_SRC
						     : TCA_FLOWER_KEY_IPV6_SRC,
			    addr.data, addr.bytelen);

		if (tc_flower_get_inet_mask(src_p, &addr) != 0)
			return 0;

		nl_attr_put(&req->n, datalen,
			    (addr.family == AF_INET)
				    ? TCA_FLOWER_KEY_IPV4_SRC_MASK
				    : TCA_FLOWER_KEY_IPV6_SRC_MASK,
			    addr.data, addr.bytelen);
	}

	if (filter_bm & TC_FILTER_DST_IP) {
		const struct prefix *dst_p = dplane_ctx_tc_get_dst_ip(ctx);

		if (tc_flower_get_inet_prefix(dst_p, &addr) != 0)
			return 0;

		nl_attr_put(&req->n, datalen,
			    (addr.family == AF_INET) ? TCA_FLOWER_KEY_IPV4_DST
						     : TCA_FLOWER_KEY_IPV6_DST,
			    addr.data, addr.bytelen);

		if (tc_flower_get_inet_mask(dst_p, &addr) != 0)
			return 0;

		nl_attr_put(&req->n, datalen,
			    (addr.family == AF_INET)
				    ? TCA_FLOWER_KEY_IPV4_DST_MASK
				    : TCA_FLOWER_KEY_IPV6_DST_MASK,
			    addr.data, addr.bytelen);
	}

	if (filter_bm & TC_FILTER_IP_PROTOCOL) {
		nl_attr_put8(&req->n, datalen, TCA_FLOWER_KEY_IP_PROTO,
			     dplane_ctx_tc_get_ip_proto(ctx));
	}

	nl_attr_put32(&req->n, datalen, TCA_FLOWER_FLAGS, flags);

	nl_attr_put16(&req->n, datalen, TCA_FLOWER_KEY_ETH_TYPE, protocol);
	nl_attr_nest_end(&req->n, nest);

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

static ssize_t netlink_newqdisc_msg_encoder(struct zebra_dplane_ctx *ctx,
					    void *buf, size_t buflen)
{
	return netlink_qdisc_msg_encode(RTM_NEWQDISC, ctx, buf, buflen);
}

static ssize_t netlink_newtclass_msg_encoder(struct zebra_dplane_ctx *ctx,
					     void *buf, size_t buflen)
{
	return netlink_tclass_msg_encode(RTM_NEWTCLASS, ctx, buf, buflen);
}

static ssize_t netlink_newtfilter_msg_encoder(struct zebra_dplane_ctx *ctx,
					      void *buf, size_t buflen)
{
	return netlink_tfilter_msg_encode(RTM_NEWTFILTER, ctx, buf, buflen);
}

enum netlink_msg_status netlink_put_tc_update_msg(struct nl_batch *bth,
						  struct zebra_dplane_ctx *ctx)
{
	/* TODO: error handling and other actions (delete, replace, ...) */

	netlink_batch_add_msg(bth, ctx, netlink_newqdisc_msg_encoder, false);
	netlink_batch_add_msg(bth, ctx, netlink_newtclass_msg_encoder, false);
	return netlink_batch_add_msg(bth, ctx, netlink_newtfilter_msg_encoder,
				     false);
}

#endif /* HAVE_NETLINK */
