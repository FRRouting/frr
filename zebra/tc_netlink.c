// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Traffic Control (TC) interaction with the kernel using netlink.
 *
 * Copyright (C) 2022 Shichu Yang
 */

#include <zebra.h>

#ifdef HAVE_NETLINK

#include <linux/rtnetlink.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/tc_act/tc_skbedit.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>

#include "if.h"
#include "prefix.h"
#include "vrf.h"

#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/rt.h"
#include "zebra/interface.h"
#include "zebra/debug.h"
#include "zebra/kernel_netlink.h"
#include "zebra/tc_netlink.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_tc.h"
#include "zebra/zebra_trace.h"
#include "lib/netlink_parser.h"
#include "lib/darr.h"

#define TC_FREQ_DEFAULT (100)

/* some magic number */
#define TC_MINOR_NOCLASS (0xffffu)

#ifndef TC_H_CLSACT
#define TC_H_CLSACT TC_H_INGRESS
#endif
#ifndef TC_H_MIN_INGRESS
#define TC_H_MIN_INGRESS 0xFFF2U
#endif
#ifndef TC_H_MIN_EGRESS
#define TC_H_MIN_EGRESS 0xFFF3U
#endif

/* tcm_parent for a filter attached at @attach */
static uint32_t tc_filter_parent(enum tc_filter_attach attach)
{
	switch (attach) {
	case TC_ATTACH_INGRESS:
		return TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS);
	case TC_ATTACH_EGRESS:
		return TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
	case TC_ATTACH_ROOT:
		break;
	}

	return TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA, 0);
}

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
	const char *kind_str = NULL;

	struct rtattr *nest;

	struct {
		struct nlmsghdr n;
		struct tcmsg t;
		char buf[0];
	} *req = data;

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
	req->t.tcm_info = 0;
	req->t.tcm_handle = 0;
	req->t.tcm_parent = TC_H_ROOT;

	/*
	 * clsact: fixed parent and handle, no options.  Never replace a clsact
	 * that is already there: it may hold someone else's filters.
	 */
	if (dplane_ctx_tc_qdisc_get_kind(ctx) == TC_QDISC_CLSACT) {
		req->t.tcm_parent = TC_H_CLSACT;
		req->t.tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);

		if (cmd == RTM_NEWQDISC) {
			req->n.nlmsg_flags |= NLM_F_EXCL;
			kind_str = dplane_ctx_tc_qdisc_get_kind_str(ctx);
			if (!nl_attr_put(&req->n, datalen, TCA_KIND, kind_str,
					 strlen(kind_str) + 1))
				return 0;
		}

		return NLMSG_ALIGN(req->n.nlmsg_len);
	}

	req->n.nlmsg_flags |= NLM_F_REPLACE;

	if (cmd == RTM_NEWQDISC) {
		req->t.tcm_handle = TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA, 0);

		kind_str = dplane_ctx_tc_qdisc_get_kind_str(ctx);

		if (!nl_attr_put(&req->n, datalen, TCA_KIND, kind_str, strlen(kind_str) + 1))
			return 0;

		nest = nl_attr_nest(&req->n, datalen, TCA_OPTIONS);

		if (!nest)
			return 0;

		switch (dplane_ctx_tc_qdisc_get_kind(ctx)) {
		case TC_QDISC_HTB: {
			struct tc_htb_glob htb_glob = {
				.rate2quantum = 10,
				.version = 3,
				.defcls = TC_MINOR_NOCLASS};
			if (!nl_attr_put(&req->n, datalen, TCA_HTB_INIT, &htb_glob,
					 sizeof(htb_glob))) {
				return 0;
			}
			break;
		}
		case TC_QDISC_NOQUEUE:
			break;
		default:
			break;
			/* not implemented */
		}

		nl_attr_nest_end(&req->n, nest);
	} else {
		/* ifindex are enough for del/get qdisc */
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

/*
 * Traffic control class encoding
 */
static ssize_t netlink_tclass_msg_encode(int cmd, struct zebra_dplane_ctx *ctx,
					 void *data, size_t datalen)
{
	enum dplane_op_e op = dplane_ctx_get_op(ctx);

	struct nlsock *nl;
	const char *kind_str = NULL;

	struct rtattr *nest;

	struct {
		struct nlmsghdr n;
		struct tcmsg t;
		char buf[0];
	} *req = data;

	if (datalen < sizeof(*req))
		return 0;

	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	if (op == DPLANE_OP_TC_CLASS_UPDATE)
		req->n.nlmsg_flags |= NLM_F_REPLACE;

	req->n.nlmsg_type = cmd;

	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->t.tcm_family = AF_UNSPEC;
	req->t.tcm_ifindex = dplane_ctx_get_ifindex(ctx);

	req->t.tcm_handle = TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA,
				      dplane_ctx_tc_class_get_handle(ctx));
	req->t.tcm_parent = TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA, 0);
	req->t.tcm_info = 0;

	kind_str = dplane_ctx_tc_class_get_kind_str(ctx);

	if (op == DPLANE_OP_TC_CLASS_ADD || op == DPLANE_OP_TC_CLASS_UPDATE) {
		zlog_debug("netlink tclass encoder: op: %s kind: %s handle: %u",
			   op == DPLANE_OP_TC_CLASS_UPDATE ? "update" : "add",
			   kind_str, dplane_ctx_tc_class_get_handle(ctx));

		if (!nl_attr_put(&req->n, datalen, TCA_KIND, kind_str, strlen(kind_str) + 1))
			return 0;

		nest = nl_attr_nest(&req->n, datalen, TCA_OPTIONS);
		if (!nest)
			return 0;

		switch (dplane_ctx_tc_class_get_kind(ctx)) {
		case TC_QDISC_HTB: {
			struct tc_htb_opt htb_opt = {};

			uint64_t rate = dplane_ctx_tc_class_get_rate(ctx),
				 ceil = dplane_ctx_tc_class_get_ceil(ctx);

			uint64_t buffer, cbuffer;

			/* TODO: fetch mtu from interface */
			uint32_t mtu = 1500;

			uint32_t rtab[256];
			uint32_t ctab[256];

			ceil = MAX(rate, ceil);

			htb_opt.rate.rate = (rate >> 32 != 0) ? ~0U : rate;
			htb_opt.ceil.rate = (ceil >> 32 != 0) ? ~0U : ceil;

			buffer = rate / tc_get_freq() + mtu;
			cbuffer = ceil / tc_get_freq() + mtu;

			htb_opt.buffer = buffer;
			htb_opt.cbuffer = cbuffer;

			tc_calc_rate_table(&htb_opt.rate, rtab, mtu);
			tc_calc_rate_table(&htb_opt.ceil, ctab, mtu);

			htb_opt.ceil.mpu = htb_opt.rate.mpu = 0;
			htb_opt.ceil.overhead = htb_opt.rate.overhead = 0;

			if (rate >> 32 != 0) {
				if (!nl_attr_put(&req->n, datalen, TCA_HTB_RATE64, &rate,
						 sizeof(rate)))
					return 0;
			}

			if (ceil >> 32 != 0) {
				if (!nl_attr_put(&req->n, datalen, TCA_HTB_CEIL64, &ceil,
						 sizeof(ceil)))
					return 0;
			}

			if (!nl_attr_put(&req->n, datalen, TCA_HTB_PARMS, &htb_opt,
					 sizeof(htb_opt)))
				return 0;

			if (!nl_attr_put(&req->n, datalen, TCA_HTB_RTAB, rtab, sizeof(rtab)))
				return 0;
			if (!nl_attr_put(&req->n, datalen, TCA_HTB_CTAB, ctab, sizeof(ctab)))
				return 0;
			break;
		}
		default:
			break;
		}

		nl_attr_nest_end(&req->n, nest);
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

static int netlink_tfilter_flower_port_type(uint8_t ip_proto, bool src)
{
	if (ip_proto == IPPROTO_TCP)
		return src ? TCA_FLOWER_KEY_TCP_SRC : TCA_FLOWER_KEY_TCP_DST;
	else if (ip_proto == IPPROTO_UDP)
		return src ? TCA_FLOWER_KEY_UDP_SRC : TCA_FLOWER_KEY_UDP_DST;
	else if (ip_proto == IPPROTO_SCTP)
		return src ? TCA_FLOWER_KEY_SCTP_SRC : TCA_FLOWER_KEY_SCTP_DST;
	else
		return -1;
}

/*
 * Encode a TCA_FLOWER_ACT list holding one skbedit action:
 *   priority (skb->priority) and/or masked mark, then continue (pipe).
 * The action carries ZEBRA_TC_ACT_COOKIE so that zebra can recognise its
 * own filters in the kernel at startup.
 */
static int netlink_tfilter_put_skbedit(struct nlmsghdr *n, size_t datalen,
				       struct zebra_dplane_ctx *ctx)
{
	const struct tc_action_skbedit *se = dplane_ctx_tc_filter_get_skbedit(ctx);
	struct tc_skbedit parms = {};
	struct rtattr *acts, *act, *opts;

	acts = nl_attr_nest(n, datalen, TCA_FLOWER_ACT);
	if (!acts)
		return 0;

	/* actions are numbered from 1 */
	act = nl_attr_nest(n, datalen, 1);
	if (!act)
		return 0;

	if (!nl_attr_put(n, datalen, TCA_ACT_KIND, "skbedit", strlen("skbedit") + 1))
		return 0;

	if (!nl_attr_put(n, datalen, TCA_ACT_COOKIE, ZEBRA_TC_ACT_COOKIE, ZEBRA_TC_ACT_COOKIE_LEN))
		return 0;

	opts = nl_attr_nest(n, datalen, TCA_ACT_OPTIONS);
	if (!opts)
		return 0;

	parms.action = TC_ACT_PIPE;
	if (!nl_attr_put(n, datalen, TCA_SKBEDIT_PARMS, &parms, sizeof(parms)))
		return 0;

	if (se->set_priority && !nl_attr_put32(n, datalen, TCA_SKBEDIT_PRIORITY, se->priority))
		return 0;

	if (se->set_mark) {
		if (!nl_attr_put32(n, datalen, TCA_SKBEDIT_MARK, se->mark))
			return 0;
		if (!nl_attr_put32(n, datalen, TCA_SKBEDIT_MASK, se->mark_mask))
			return 0;
	}

	nl_attr_nest_end(n, opts);
	nl_attr_nest_end(n, act);
	nl_attr_nest_end(n, acts);

	return 1;
}

static int netlink_tfilter_flower_put_options(struct nlmsghdr *n, size_t datalen,
					      struct zebra_dplane_ctx *ctx)
{
	struct inet_prefix addr;
	uint32_t flags = 0, classid;
	uint16_t protocol = htons(dplane_ctx_tc_filter_get_eth_proto(ctx));
	uint32_t filter_bm = dplane_ctx_tc_filter_get_filter_bm(ctx);

	if (filter_bm & TC_FLOWER_SRC_IP) {
		const struct prefix *src_p =
			dplane_ctx_tc_filter_get_src_ip(ctx);

		if (tc_flower_get_inet_prefix(src_p, &addr) != 0)
			return -1;

		if (!nl_attr_put(n, datalen,
				 (addr.family == AF_INET) ? TCA_FLOWER_KEY_IPV4_SRC
							  : TCA_FLOWER_KEY_IPV6_SRC,
				 addr.data, addr.bytelen))
			return 0;

		if (tc_flower_get_inet_mask(src_p, &addr) != 0)
			return -1;

		if (!nl_attr_put(n, datalen,
				 (addr.family == AF_INET) ? TCA_FLOWER_KEY_IPV4_SRC_MASK
							  : TCA_FLOWER_KEY_IPV6_SRC_MASK,
				 addr.data, addr.bytelen))
			return 0;
	}

	if (filter_bm & TC_FLOWER_DST_IP) {
		const struct prefix *dst_p =
			dplane_ctx_tc_filter_get_dst_ip(ctx);

		if (tc_flower_get_inet_prefix(dst_p, &addr) != 0)
			return -1;

		if (!nl_attr_put(n, datalen,
				 (addr.family == AF_INET) ? TCA_FLOWER_KEY_IPV4_DST
							  : TCA_FLOWER_KEY_IPV6_DST,
				 addr.data, addr.bytelen))
			return 0;

		if (tc_flower_get_inet_mask(dst_p, &addr) != 0)
			return -1;

		if (!nl_attr_put(n, datalen,
				 (addr.family == AF_INET) ? TCA_FLOWER_KEY_IPV4_DST_MASK
							  : TCA_FLOWER_KEY_IPV6_DST_MASK,
				 addr.data, addr.bytelen))
			return 0;
	}

	if (filter_bm & TC_FLOWER_IP_PROTOCOL) {
		if (!nl_attr_put8(n, datalen, TCA_FLOWER_KEY_IP_PROTO,
				  dplane_ctx_tc_filter_get_ip_proto(ctx)))
			return 0;
	}

	if (filter_bm & TC_FLOWER_SRC_PORT) {
		uint16_t min, max;

		min = dplane_ctx_tc_filter_get_src_port_min(ctx);
		max = dplane_ctx_tc_filter_get_src_port_max(ctx);

		if (max > min) {
			if (!nl_attr_put16(n, datalen, TCA_FLOWER_KEY_PORT_SRC_MIN, htons(min)))
				return 0;
			if (!nl_attr_put16(n, datalen, TCA_FLOWER_KEY_PORT_SRC_MAX, htons(max)))
				return 0;
		} else {
			int type = netlink_tfilter_flower_port_type(
				dplane_ctx_tc_filter_get_ip_proto(ctx), true);

			if (type < 0)
				return -1;

			if (!nl_attr_put16(n, datalen, type, htons(min)))
				return 0;
		}
	}

	if (filter_bm & TC_FLOWER_DST_PORT) {
		uint16_t min = dplane_ctx_tc_filter_get_dst_port_min(ctx),
			 max = dplane_ctx_tc_filter_get_dst_port_max(ctx);

		if (max > min) {
			if (!nl_attr_put16(n, datalen, TCA_FLOWER_KEY_PORT_DST_MIN, htons(min)))
				return 0;

			if (!nl_attr_put16(n, datalen, TCA_FLOWER_KEY_PORT_DST_MAX, htons(max)))
				return 0;
		} else {
			int type = netlink_tfilter_flower_port_type(
				dplane_ctx_tc_filter_get_ip_proto(ctx), false);

			if (type < 0)
				return -1;

			if (!nl_attr_put16(n, datalen, type, htons(min)))
				return 0;
		}
	}

	if (filter_bm & TC_FLOWER_DSFIELD) {
		if (!nl_attr_put8(n, datalen, TCA_FLOWER_KEY_IP_TOS,
				  dplane_ctx_tc_filter_get_dsfield(ctx)))
			return 0;
		if (!nl_attr_put8(n, datalen, TCA_FLOWER_KEY_IP_TOS_MASK,
				  dplane_ctx_tc_filter_get_dsfield_mask(ctx)))
			return 0;
	}

	if (filter_bm & TC_FLOWER_VLAN_ID) {
		if (!nl_attr_put16(n, datalen, TCA_FLOWER_KEY_VLAN_ID,
				   dplane_ctx_tc_filter_get_vlan_id(ctx)))
			return 0;
	}

	if (filter_bm & TC_FLOWER_VLAN_PRIO) {
		if (!nl_attr_put8(n, datalen, TCA_FLOWER_KEY_VLAN_PRIO,
				  dplane_ctx_tc_filter_get_vlan_prio(ctx)))
			return 0;
	}

	if (filter_bm & TC_FLOWER_VLAN_ETH_TYPE) {
		if (!nl_attr_put16(n, datalen, TCA_FLOWER_KEY_VLAN_ETH_TYPE,
				   htons(dplane_ctx_tc_filter_get_vlan_eth_type(ctx))))
			return 0;
	}

	if (dplane_ctx_tc_filter_has_action(ctx)) {
		if (netlink_tfilter_put_skbedit(n, datalen, ctx) <= 0)
			return 0;
	} else {
		classid = TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA, dplane_ctx_tc_filter_get_classid(ctx));
		if (!nl_attr_put32(n, datalen, TCA_FLOWER_CLASSID, classid))
			return 0;
	}

	if (!nl_attr_put32(n, datalen, TCA_FLOWER_FLAGS, flags))
		return 0;

	/* ETH_P_ALL: match any ethertype, so no key */
	if (dplane_ctx_tc_filter_get_eth_proto(ctx) != ETH_P_ALL &&
	    !nl_attr_put16(n, datalen, TCA_FLOWER_KEY_ETH_TYPE, protocol))
		return 0;

	return 1;
}

/*
 * Traffic control filter encoding
 */
static ssize_t netlink_tfilter_msg_encode(int cmd, struct zebra_dplane_ctx *ctx,
					  void *data, size_t datalen)
{
	enum dplane_op_e op = dplane_ctx_get_op(ctx);

	struct nlsock *nl;
	const char *kind_str = NULL;

	struct rtattr *nest;

	uint16_t priority;
	uint16_t protocol;

	struct {
		struct nlmsghdr n;
		struct tcmsg t;
		char buf[0];
	} *req = data;

	ssize_t ret = 0;

	if (datalen < sizeof(*req))
		return 0;

	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req->n.nlmsg_flags = NLM_F_CREATE | NLM_F_REQUEST;

	if (op == DPLANE_OP_TC_FILTER_UPDATE)
		req->n.nlmsg_flags |= NLM_F_REPLACE;

	req->n.nlmsg_type = cmd;

	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->t.tcm_family = AF_UNSPEC;
	req->t.tcm_ifindex = dplane_ctx_get_ifindex(ctx);

	priority = dplane_ctx_tc_filter_get_priority(ctx);
	protocol = htons(dplane_ctx_tc_filter_get_eth_proto(ctx));

	req->t.tcm_info = TC_H_MAKE(priority << 16, protocol);
	req->t.tcm_handle = dplane_ctx_tc_filter_get_handle(ctx);
	req->t.tcm_parent = tc_filter_parent(dplane_ctx_tc_filter_get_attach(ctx));

	kind_str = dplane_ctx_tc_filter_get_kind_str(ctx);

	if (op == DPLANE_OP_TC_FILTER_ADD || op == DPLANE_OP_TC_FILTER_UPDATE) {
		if (!nl_attr_put(&req->n, datalen, TCA_KIND, kind_str, strlen(kind_str) + 1))
			return 0;

		zlog_debug(
			"netlink tfilter encoder: op: %s priority: %u protocol: %u kind: %s handle: %u filter_bm: %u ip_proto: %u",
			op == DPLANE_OP_TC_FILTER_UPDATE ? "update" : "add",
			priority, protocol, kind_str,
			dplane_ctx_tc_filter_get_handle(ctx),
			dplane_ctx_tc_filter_get_filter_bm(ctx),
			dplane_ctx_tc_filter_get_ip_proto(ctx));

		nest = nl_attr_nest(&req->n, datalen, TCA_OPTIONS);
		if (!nest)
			return 0;

		switch (dplane_ctx_tc_filter_get_kind(ctx)) {
		case TC_FILTER_FLOWER: {
			ret = netlink_tfilter_flower_put_options(&req->n, datalen, ctx);
			if (ret <= 0)
				return 0;
			break;
		}
		default:
			break;
		}
		nl_attr_nest_end(&req->n, nest);
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

static ssize_t netlink_newqdisc_msg_encoder(struct zebra_dplane_ctx *ctx,
					    void *buf, size_t buflen)
{
	return netlink_qdisc_msg_encode(RTM_NEWQDISC, ctx, buf, buflen);
}

static ssize_t netlink_delqdisc_msg_encoder(struct zebra_dplane_ctx *ctx,
					    void *buf, size_t buflen)
{
	return netlink_qdisc_msg_encode(RTM_DELQDISC, ctx, buf, buflen);
}

static ssize_t netlink_newtclass_msg_encoder(struct zebra_dplane_ctx *ctx,
					     void *buf, size_t buflen)
{
	return netlink_tclass_msg_encode(RTM_NEWTCLASS, ctx, buf, buflen);
}

static ssize_t netlink_deltclass_msg_encoder(struct zebra_dplane_ctx *ctx,
					     void *buf, size_t buflen)
{
	return netlink_tclass_msg_encode(RTM_DELTCLASS, ctx, buf, buflen);
}

static ssize_t netlink_newtfilter_msg_encoder(struct zebra_dplane_ctx *ctx,
					      void *buf, size_t buflen)
{
	return netlink_tfilter_msg_encode(RTM_NEWTFILTER, ctx, buf, buflen);
}

static ssize_t netlink_deltfilter_msg_encoder(struct zebra_dplane_ctx *ctx,
					      void *buf, size_t buflen)
{
	return netlink_tfilter_msg_encode(RTM_DELTFILTER, ctx, buf, buflen);
}

enum netlink_msg_status
netlink_put_tc_qdisc_update_msg(struct nl_batch *bth,
				struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op;
	enum netlink_msg_status ret;

	op = dplane_ctx_get_op(ctx);

	if (op == DPLANE_OP_TC_QDISC_INSTALL) {
		ret = netlink_batch_add_msg(
			bth, ctx, netlink_newqdisc_msg_encoder, false);
	} else if (op == DPLANE_OP_TC_QDISC_UNINSTALL) {
		ret = netlink_batch_add_msg(
			bth, ctx, netlink_delqdisc_msg_encoder, false);
	} else {
		return FRR_NETLINK_ERROR;
	}

	return ret;
}

enum netlink_msg_status
netlink_put_tc_class_update_msg(struct nl_batch *bth,
				struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op;
	enum netlink_msg_status ret;

	op = dplane_ctx_get_op(ctx);

	if (op == DPLANE_OP_TC_CLASS_ADD || op == DPLANE_OP_TC_CLASS_UPDATE) {
		ret = netlink_batch_add_msg(
			bth, ctx, netlink_newtclass_msg_encoder, false);
	} else if (op == DPLANE_OP_TC_CLASS_DELETE) {
		ret = netlink_batch_add_msg(
			bth, ctx, netlink_deltclass_msg_encoder, false);
	} else {
		return FRR_NETLINK_ERROR;
	}

	return ret;
}

enum netlink_msg_status
netlink_put_tc_filter_update_msg(struct nl_batch *bth,
				 struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op;
	enum netlink_msg_status ret;

	op = dplane_ctx_get_op(ctx);

	if (op == DPLANE_OP_TC_FILTER_ADD) {
		ret = netlink_batch_add_msg(
			bth, ctx, netlink_newtfilter_msg_encoder, false);
	} else if (op == DPLANE_OP_TC_FILTER_UPDATE) {
		/*
		 * Replace will fail if either filter type or the number of
		 * filter options is changed, so DEL then NEW
		 *
		 * TFILTER may have refs to TCLASS.
		 */

		(void)netlink_batch_add_msg(bth, ctx, netlink_deltfilter_msg_encoder, true);
		ret = netlink_batch_add_msg(
			bth, ctx, netlink_newtfilter_msg_encoder, false);
	} else if (op == DPLANE_OP_TC_FILTER_DELETE) {
		ret = netlink_batch_add_msg(
			bth, ctx, netlink_deltfilter_msg_encoder, false);
	} else {
		return FRR_NETLINK_ERROR;
	}

	return ret;
}

/*
 * Request queue discipline from the kernel
 */
static int netlink_request_qdiscs(struct nlsock *nl, int family, int type)
{
	struct {
		struct nlmsghdr n;
		struct tcmsg tc;
	} req;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_type = type;
	req.n.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
	req.tc.tcm_family = family;

	return netlink_request(nl, &req);
}

/*
 * Startup cleanup of filters left behind by a previous zebra.
 *
 * zebra-derived filters (PBR traffic-class) live on clsact hooks, whose
 * qdisc handle is fixed, so ownership is recognised per filter: the
 * handle has TC_FILTER_HANDLE_ZEBRA set and the action carries
 * ZEBRA_TC_ACT_COOKIE.  The qdisc dump collects the clsact interfaces,
 * each clsact hook is then dumped and matching filters are deleted.  This
 * runs in the dataplane pthread before any client can add filters.
 * Both collections grow as needed (darr), so nothing is left behind on
 * systems with many ports or classifiers.
 */

struct tc_startup_filter {
	ifindex_t ifindex;
	uint32_t parent;
	uint32_t info;
	uint32_t handle;
};

struct tc_startup_scan {
	ifindex_t *clsact_ifs;		  /* darr */
	struct tc_startup_filter *filters; /* darr */
};

static void tc_startup_note_clsact(void *arg, ifindex_t ifindex)
{
	struct tc_startup_scan *scan = arg;

	darr_push(scan->clsact_ifs, ifindex);
}

static bool tc_filter_has_zebra_cookie(struct rtattr *options)
{
	struct rtattr *fopts[TCA_FLOWER_MAX + 1];
	struct rtattr *acts[TCA_ACT_MAX_PRIO + 1];

	netlink_parse_rtattr_nested(fopts, TCA_FLOWER_MAX, options);
	if (!fopts[TCA_FLOWER_ACT])
		return false;

	netlink_parse_rtattr_nested(acts, TCA_ACT_MAX_PRIO, fopts[TCA_FLOWER_ACT]);
	for (int i = 1; i <= TCA_ACT_MAX_PRIO; i++) {
		struct rtattr *act[TCA_ACT_MAX + 1];

		if (!acts[i])
			continue;

		netlink_parse_rtattr_nested(act, TCA_ACT_MAX, acts[i]);
		if (act[TCA_ACT_COOKIE] &&
		    RTA_PAYLOAD(act[TCA_ACT_COOKIE]) == ZEBRA_TC_ACT_COOKIE_LEN &&
		    memcmp(RTA_DATA(act[TCA_ACT_COOKIE]), ZEBRA_TC_ACT_COOKIE,
			   ZEBRA_TC_ACT_COOKIE_LEN) == 0)
			return true;
	}

	return false;
}

static int tc_startup_filter_cb(struct nlmsghdr *h, ns_id_t ns_id, int startup, void *arg)
{
	struct tc_startup_scan *scan = arg;
	struct tc_startup_filter f;
	struct rtattr *tb[TCA_MAX + 1];
	struct tcmsg *tcm;
	int len;

	if (h->nlmsg_type != RTM_NEWTFILTER)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct tcmsg));
	if (len < 0)
		return -1;

	tcm = NLMSG_DATA(h);
	netlink_parse_rtattr(tb, TCA_MAX, TCA_RTA(tcm), len);

	/* handle 0 is the classifier instance itself, not a filter */
	if (!(tcm->tcm_handle & TC_FILTER_HANDLE_ZEBRA))
		return 0;
	if (!tb[TCA_KIND] || strcmp(RTA_DATA(tb[TCA_KIND]), "flower") != 0)
		return 0;
	if (!tb[TCA_OPTIONS] || !tc_filter_has_zebra_cookie(tb[TCA_OPTIONS]))
		return 0;

	f.ifindex = tcm->tcm_ifindex;
	f.parent = tcm->tcm_parent;
	f.info = tcm->tcm_info;
	f.handle = tcm->tcm_handle;
	darr_push(scan->filters, f);

	return 0;
}

static void tc_startup_flush_filters(struct nlsock *nl, const struct zebra_dplane_info *dp_info,
				     struct tc_startup_scan *scan)
{
	static const uint32_t hooks[] = {
		TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_INGRESS),
		TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS),
	};
	struct {
		struct nlmsghdr n;
		struct tcmsg t;
		char buf[64];
	} req;

	for (unsigned int i = 0; i < darr_len(scan->clsact_ifs); i++) {
		for (unsigned int j = 0; j < array_size(hooks); j++) {
			memset(&req, 0, sizeof(req));
			req.n.nlmsg_type = RTM_GETTFILTER;
			req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
			req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
			req.t.tcm_family = AF_UNSPEC;
			req.t.tcm_ifindex = scan->clsact_ifs[i];
			req.t.tcm_parent = hooks[j];

			if (netlink_request(nl, &req) < 0)
				continue;
			netlink_parse_info(tc_startup_filter_cb, nl, dp_info, 0, true, scan, NULL);
		}
	}

	for (unsigned int i = 0; i < darr_len(scan->filters); i++) {
		struct tc_startup_filter *f = &scan->filters[i];

		if (IS_ZEBRA_DEBUG_KERNEL || IS_ZEBRA_DEBUG_TC)
			zlog_debug("%s: removing leftover zebra tc filter ifindex %d parent %x pref %u handle 0x%08x",
				   __func__, f->ifindex, f->parent, TC_H_MAJ(f->info) >> 16,
				   f->handle);

		memset(&req, 0, sizeof(req));
		req.n.nlmsg_type = RTM_DELTFILTER;
		req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
		req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg));
		req.t.tcm_family = AF_UNSPEC;
		req.t.tcm_ifindex = f->ifindex;
		req.t.tcm_parent = f->parent;
		req.t.tcm_info = f->info;
		req.t.tcm_handle = f->handle;
		nl_attr_put(&req.n, sizeof(req), TCA_KIND, "flower", strlen("flower") + 1);

		if (netlink_request(nl, &req) < 0)
			continue;
		netlink_parse_info(netlink_talk_filter, nl, dp_info, 0, true, NULL, NULL);
	}

	darr_free(scan->filters);
}

int netlink_qdisc_change(struct nlmsghdr *h, ns_id_t ns_id, int startup, void *arg)
{
	struct tcmsg *tcm;
	enum tc_qdisc_kind kind = TC_QDISC_UNSPEC;

	int len;
	struct rtattr *tb[TCA_MAX + 1];

	frrtrace(3, frr_zebra, netlink_tc_qdisc_change, h, ns_id, startup);

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct tcmsg));

	if (len < 0) {
		flog_err(EC_ZEBRA_NETLINK_LENGTH_ERROR,
			 "%s: Message received from netlink is of a broken size %d %zu", __func__,
			 h->nlmsg_len, (size_t)NLMSG_LENGTH(sizeof(struct tcmsg)));
		return -1;
	}

	tcm = NLMSG_DATA(h);
	netlink_parse_rtattr(tb, TCA_MAX, TCA_RTA(tcm), len);

	if (RTA_DATA(tb[TCA_KIND]))
		kind = tc_qdisc_str2kind((const char *)RTA_DATA(tb[TCA_KIND]));

	/* Startup read: remember interfaces with a clsact qdisc (see below) */
	if (arg && startup && kind == TC_QDISC_CLSACT && h->nlmsg_type == RTM_NEWQDISC)
		tc_startup_note_clsact(arg, tcm->tcm_ifindex);

	enum dplane_tc_qdisc_notify_e notify_type = (h->nlmsg_type == RTM_NEWQDISC)
							    ? DPLANE_TC_QDISC_NOTIFY_NEW
							    : DPLANE_TC_QDISC_NOTIFY_DEL;

	/*
	 * Hand the decoded fields off to the zebra master pthread.
	 * The dplane thread is purely a decoder here -- the policy
	 * (e.g. cleaning up a leftover zebra-owned qdisc at startup)
	 * is decided by zebra_tc_qdisc_handle_notify() in the master
	 * thread.
	 */
	dplane_tc_qdisc_notify_enqueue(ns_id, notify_type, !!startup, kind, tcm->tcm_ifindex,
				       TC_H_MAJ(tcm->tcm_handle));

	return 0;
}

int netlink_tclass_change(struct nlmsghdr *h, ns_id_t ns_id, int startup, void *arg)
{
	struct tcmsg *tcm;

	int len;
	struct rtattr *tb[TCA_MAX + 1];

	frrtrace(3, frr_zebra, netlink_tc_class_change, h, ns_id, startup);

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct tcmsg));

	if (len < 0) {
		flog_err(EC_ZEBRA_NETLINK_LENGTH_ERROR,
			 "%s: Message received from netlink is of a broken size %d %zu", __func__,
			 h->nlmsg_len, (size_t)NLMSG_LENGTH(sizeof(struct tcmsg)));
		return -1;
	}

	tcm = NLMSG_DATA(h);
	netlink_parse_rtattr(tb, TCA_MAX, TCA_RTA(tcm), len);


	if (tb[TCA_OPTIONS] != NULL) {
		struct rtattr *options[TCA_HTB_MAX + 1];

		netlink_parse_rtattr_nested(options, TCA_HTB_MAX,
					    tb[TCA_OPTIONS]);

		/* TODO: more details */
		/* struct tc_htb_opt *opt = RTA_DATA(options[TCA_HTB_PARMS]); */
	}

	return 0;
}

int netlink_tfilter_change(struct nlmsghdr *h, ns_id_t ns_id, int startup, void *arg)
{
	struct tcmsg *tcm;

	int len;
	struct rtattr *tb[TCA_MAX + 1];

	frrtrace(3, frr_zebra, netlink_tc_filter_change, h, ns_id, startup);

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct tcmsg));

	if (len < 0) {
		flog_err(EC_ZEBRA_NETLINK_LENGTH_ERROR,
			 "%s: Message received from netlink is of a broken size %d %zu", __func__,
			 h->nlmsg_len, (size_t)NLMSG_LENGTH(sizeof(struct tcmsg)));
		return -1;
	}

	tcm = NLMSG_DATA(h);
	netlink_parse_rtattr(tb, TCA_MAX, TCA_RTA(tcm), len);

	return 0;
}

void kernel_read_tc_qdisc(struct zebra_dplane_ctx *ctx)
{
	const struct zebra_dplane_info *dp_info = dplane_ctx_get_ns(ctx);
	struct nlsock *nl;
	int ret;

	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));
	if (!nl) {
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_FAILURE);
		zebra_dplane_startup_stage(dplane_ctx_get_ns_id(ctx),
					   ZEBRA_DPLANE_FINISHED_READING);
		return;
	}

	ret = netlink_request_qdiscs(nl, AF_UNSPEC, RTM_GETQDISC);
	if (ret >= 0) {
		struct tc_startup_scan *scan = XCALLOC(MTYPE_TMP, sizeof(*scan));

		netlink_parse_info(netlink_qdisc_change, nl, dp_info, 0, true, scan, NULL);
		if (darr_len(scan->clsact_ifs))
			tc_startup_flush_filters(nl, dp_info, scan);
		darr_free(scan->clsact_ifs);
		XFREE(MTYPE_TMP, scan);
	}

	dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);

	/*
	 * Signal that startup reads are finished. Any platform-specific
	 * implementation of this function must do the same once it has
	 * finished reading all TC data, so that zebra can advance from
	 * ZEBRA_DPLANE_ADDRESSES_READ to ZEBRA_DPLANE_FINISHED_READING.
	 */
	zebra_dplane_startup_stage(dplane_ctx_get_ns_id(ctx),
				   ZEBRA_DPLANE_FINISHED_READING);
}

#endif /* HAVE_NETLINK */
