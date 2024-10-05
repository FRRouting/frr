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

#define TC_FREQ_DEFAULT (100)

/* some magic number */
#define TC_QDISC_MAJOR_ZEBRA (0xbeef0000u)
#define TC_MINOR_NOCLASS (0xffffu)

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

	req->n.nlmsg_flags |= NLM_F_REPLACE;

	req->n.nlmsg_type = cmd;

	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->t.tcm_family = AF_UNSPEC;
	req->t.tcm_ifindex = dplane_ctx_get_ifindex(ctx);
	req->t.tcm_info = 0;
	req->t.tcm_handle = 0;
	req->t.tcm_parent = TC_H_ROOT;

	if (cmd == RTM_NEWQDISC) {
		req->t.tcm_handle = TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA, 0);

		kind_str = dplane_ctx_tc_qdisc_get_kind_str(ctx);

		nl_attr_put(&req->n, datalen, TCA_KIND, kind_str,
			    strlen(kind_str) + 1);

		nest = nl_attr_nest(&req->n, datalen, TCA_OPTIONS);

		switch (dplane_ctx_tc_qdisc_get_kind(ctx)) {
		case TC_QDISC_HTB: {
			struct tc_htb_glob htb_glob = {
				.rate2quantum = 10,
				.version = 3,
				.defcls = TC_MINOR_NOCLASS};
			nl_attr_put(&req->n, datalen, TCA_HTB_INIT, &htb_glob,
				    sizeof(htb_glob));
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

		nl_attr_put(&req->n, datalen, TCA_KIND, kind_str,
			    strlen(kind_str) + 1);

		nest = nl_attr_nest(&req->n, datalen, TCA_OPTIONS);

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
				nl_attr_put(&req->n, datalen, TCA_HTB_RATE64,
					    &rate, sizeof(rate));
			}

			if (ceil >> 32 != 0) {
				nl_attr_put(&req->n, datalen, TCA_HTB_CEIL64,
					    &ceil, sizeof(ceil));
			}

			nl_attr_put(&req->n, datalen, TCA_HTB_PARMS, &htb_opt,
				    sizeof(htb_opt));

			nl_attr_put(&req->n, datalen, TCA_HTB_RTAB, rtab,
				    sizeof(rtab));
			nl_attr_put(&req->n, datalen, TCA_HTB_CTAB, ctab,
				    sizeof(ctab));
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

static void netlink_tfilter_flower_put_options(struct nlmsghdr *n,
					       size_t datalen,
					       struct zebra_dplane_ctx *ctx)
{
	struct inet_prefix addr;
	uint32_t flags = 0, classid;
	uint8_t protocol = htons(dplane_ctx_tc_filter_get_eth_proto(ctx));
	uint32_t filter_bm = dplane_ctx_tc_filter_get_filter_bm(ctx);

	if (filter_bm & TC_FLOWER_SRC_IP) {
		const struct prefix *src_p =
			dplane_ctx_tc_filter_get_src_ip(ctx);

		if (tc_flower_get_inet_prefix(src_p, &addr) != 0)
			return;

		nl_attr_put(n, datalen,
			    (addr.family == AF_INET) ? TCA_FLOWER_KEY_IPV4_SRC
						     : TCA_FLOWER_KEY_IPV6_SRC,
			    addr.data, addr.bytelen);

		if (tc_flower_get_inet_mask(src_p, &addr) != 0)
			return;

		nl_attr_put(n, datalen,
			    (addr.family == AF_INET)
				    ? TCA_FLOWER_KEY_IPV4_SRC_MASK
				    : TCA_FLOWER_KEY_IPV6_SRC_MASK,
			    addr.data, addr.bytelen);
	}

	if (filter_bm & TC_FLOWER_DST_IP) {
		const struct prefix *dst_p =
			dplane_ctx_tc_filter_get_dst_ip(ctx);

		if (tc_flower_get_inet_prefix(dst_p, &addr) != 0)
			return;

		nl_attr_put(n, datalen,
			    (addr.family == AF_INET) ? TCA_FLOWER_KEY_IPV4_DST
						     : TCA_FLOWER_KEY_IPV6_DST,
			    addr.data, addr.bytelen);

		if (tc_flower_get_inet_mask(dst_p, &addr) != 0)
			return;

		nl_attr_put(n, datalen,
			    (addr.family == AF_INET)
				    ? TCA_FLOWER_KEY_IPV4_DST_MASK
				    : TCA_FLOWER_KEY_IPV6_DST_MASK,
			    addr.data, addr.bytelen);
	}

	if (filter_bm & TC_FLOWER_IP_PROTOCOL) {
		nl_attr_put8(n, datalen, TCA_FLOWER_KEY_IP_PROTO,
			     dplane_ctx_tc_filter_get_ip_proto(ctx));
	}

	if (filter_bm & TC_FLOWER_SRC_PORT) {
		uint16_t min, max;

		min = dplane_ctx_tc_filter_get_src_port_min(ctx);
		max = dplane_ctx_tc_filter_get_src_port_max(ctx);

		if (max > min) {
			nl_attr_put16(n, datalen, TCA_FLOWER_KEY_PORT_SRC_MIN,
				      htons(min));

			nl_attr_put16(n, datalen, TCA_FLOWER_KEY_PORT_SRC_MAX,
				      htons(max));
		} else {
			int type = netlink_tfilter_flower_port_type(
				dplane_ctx_tc_filter_get_ip_proto(ctx), true);

			if (type < 0)
				return;

			nl_attr_put16(n, datalen, type, htons(min));
		}
	}

	if (filter_bm & TC_FLOWER_DST_PORT) {
		uint16_t min = dplane_ctx_tc_filter_get_dst_port_min(ctx),
			 max = dplane_ctx_tc_filter_get_dst_port_max(ctx);

		if (max > min) {
			nl_attr_put16(n, datalen, TCA_FLOWER_KEY_PORT_DST_MIN,
				      htons(min));

			nl_attr_put16(n, datalen, TCA_FLOWER_KEY_PORT_DST_MAX,
				      htons(max));
		} else {
			int type = netlink_tfilter_flower_port_type(
				dplane_ctx_tc_filter_get_ip_proto(ctx), false);

			if (type < 0)
				return;

			nl_attr_put16(n, datalen, type, htons(min));
		}
	}

	if (filter_bm & TC_FLOWER_DSFIELD) {
		nl_attr_put8(n, datalen, TCA_FLOWER_KEY_IP_TOS,
			     dplane_ctx_tc_filter_get_dsfield(ctx));
		nl_attr_put8(n, datalen, TCA_FLOWER_KEY_IP_TOS_MASK,
			     dplane_ctx_tc_filter_get_dsfield_mask(ctx));
	}

	classid = TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA,
			    dplane_ctx_tc_filter_get_classid(ctx));
	nl_attr_put32(n, datalen, TCA_FLOWER_CLASSID, classid);

	nl_attr_put32(n, datalen, TCA_FLOWER_FLAGS, flags);

	nl_attr_put16(n, datalen, TCA_FLOWER_KEY_ETH_TYPE, protocol);
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
	req->t.tcm_parent = TC_H_MAKE(TC_QDISC_MAJOR_ZEBRA, 0);

	kind_str = dplane_ctx_tc_filter_get_kind_str(ctx);

	if (op == DPLANE_OP_TC_FILTER_ADD || op == DPLANE_OP_TC_FILTER_UPDATE) {
		nl_attr_put(&req->n, datalen, TCA_KIND, kind_str,
			    strlen(kind_str) + 1);

		zlog_debug(
			"netlink tfilter encoder: op: %s priority: %u protocol: %u kind: %s handle: %u filter_bm: %u ip_proto: %u",
			op == DPLANE_OP_TC_FILTER_UPDATE ? "update" : "add",
			priority, protocol, kind_str,
			dplane_ctx_tc_filter_get_handle(ctx),
			dplane_ctx_tc_filter_get_filter_bm(ctx),
			dplane_ctx_tc_filter_get_ip_proto(ctx));

		nest = nl_attr_nest(&req->n, datalen, TCA_OPTIONS);
		switch (dplane_ctx_tc_filter_get_kind(ctx)) {
		case TC_FILTER_FLOWER: {
			netlink_tfilter_flower_put_options(&req->n, datalen,
							   ctx);
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

		(void)netlink_batch_add_msg(
			bth, ctx, netlink_deltfilter_msg_encoder, false);
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
 * Request filters from the kernel
 */
static int netlink_request_filters(struct zebra_ns *zns, int family, int type,
				   ifindex_t ifindex)
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
	req.tc.tcm_ifindex = ifindex;

	return netlink_request(&zns->netlink_cmd, &req);
}

/*
 * Request queue discipline from the kernel
 */
static int netlink_request_qdiscs(struct zebra_ns *zns, int family, int type)
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

	return netlink_request(&zns->netlink_cmd, &req);
}

int netlink_qdisc_change(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	struct tcmsg *tcm;
	struct zebra_tc_qdisc qdisc = {};
	enum tc_qdisc_kind kind = TC_QDISC_UNSPEC;
	const char *kind_str = "Unknown";

	int len;
	struct rtattr *tb[TCA_MAX + 1];

	frrtrace(3, frr_zebra, netlink_tc_qdisc_change, h, ns_id, startup);

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct tcmsg));

	if (len < 0) {
		zlog_err(
			"%s: Message received from netlink is of a broken size %d %zu",
			__func__, h->nlmsg_len,
			(size_t)NLMSG_LENGTH(sizeof(struct tcmsg)));
		return -1;
	}

	tcm = NLMSG_DATA(h);
	netlink_parse_rtattr(tb, TCA_MAX, TCA_RTA(tcm), len);

	if (RTA_DATA(tb[TCA_KIND])) {
		kind_str = (const char *)RTA_DATA(tb[TCA_KIND]);

		kind = tc_qdisc_str2kind(kind_str);
	}

	qdisc.qdisc.ifindex = tcm->tcm_ifindex;

	switch (kind) {
	case TC_QDISC_NOQUEUE:
		/* "noqueue" is the default qdisc */
		break;
	case TC_QDISC_HTB:
	case TC_QDISC_UNSPEC:
		break;
	}

	if (tb[TCA_OPTIONS] != NULL) {
		struct rtattr *options[TCA_HTB_MAX + 1];

		netlink_parse_rtattr_nested(options, TCA_HTB_MAX,
					    tb[TCA_OPTIONS]);

		/* TODO: more details */
		/* struct tc_htb_glob *glob = RTA_DATA(options[TCA_HTB_INIT]);
		 */
	}

	if (h->nlmsg_type == RTM_NEWQDISC) {
		if (startup &&
		    TC_H_MAJ(tcm->tcm_handle) == TC_QDISC_MAJOR_ZEBRA) {
			enum zebra_dplane_result ret;

			ret = dplane_tc_qdisc_uninstall(&qdisc);

			zlog_debug("%s: %s leftover qdisc: ifindex %d kind %s",
				   __func__,
				   ((ret == ZEBRA_DPLANE_REQUEST_FAILURE)
					    ? "Failed to remove"
					    : "Removed"),
				   qdisc.qdisc.ifindex, kind_str);
		}
	}

	return 0;
}

int netlink_tclass_change(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	struct tcmsg *tcm;

	int len;
	struct rtattr *tb[TCA_MAX + 1];

	frrtrace(3, frr_zebra, netlink_tc_class_change, h, ns_id, startup);

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct tcmsg));

	if (len < 0) {
		zlog_err(
			"%s: Message received from netlink is of a broken size %d %zu",
			__func__, h->nlmsg_len,
			(size_t)NLMSG_LENGTH(sizeof(struct tcmsg)));
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

int netlink_tfilter_change(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	struct tcmsg *tcm;

	int len;
	struct rtattr *tb[TCA_MAX + 1];

	frrtrace(3, frr_zebra, netlink_tc_filter_change, h, ns_id, startup);

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct tcmsg));

	if (len < 0) {
		zlog_err(
			"%s: Message received from netlink is of a broken size %d %zu",
			__func__, h->nlmsg_len,
			(size_t)NLMSG_LENGTH(sizeof(struct tcmsg)));
		return -1;
	}

	tcm = NLMSG_DATA(h);
	netlink_parse_rtattr(tb, TCA_MAX, TCA_RTA(tcm), len);

	return 0;
}

int netlink_qdisc_read(struct zebra_ns *zns)
{
	int ret;
	struct zebra_dplane_info dp_info;

	zebra_dplane_info_from_zns(&dp_info, zns, true);

	ret = netlink_request_qdiscs(zns, AF_UNSPEC, RTM_GETQDISC);
	if (ret < 0)
		return ret;

	ret = netlink_parse_info(netlink_qdisc_change, &zns->netlink_cmd,
				 &dp_info, 0, true);
	if (ret < 0)
		return ret;

	return 0;
}

int netlink_tfilter_read_for_interface(struct zebra_ns *zns, ifindex_t ifindex)
{
	int ret;
	struct zebra_dplane_info dp_info;

	zebra_dplane_info_from_zns(&dp_info, zns, true);

	ret = netlink_request_filters(zns, AF_UNSPEC, RTM_GETTFILTER, ifindex);
	if (ret < 0)
		return ret;

	ret = netlink_parse_info(netlink_tfilter_change, &zns->netlink_cmd,
				 &dp_info, 0, true);
	if (ret < 0)
		return ret;

	return 0;
}

#endif /* HAVE_NETLINK */
