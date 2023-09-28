// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Policy Based Routing (PBR) interaction with the kernel using
 * netlink.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 */

#include <zebra.h>

#ifdef HAVE_NETLINK

#include "if.h"
#include "prefix.h"
#include "vrf.h"

#include <linux/fib_rules.h>
#include "zebra/zserv.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rt.h"
#include "zebra/interface.h"
#include "zebra/debug.h"
#include "zebra/rtadv.h"
#include "zebra/kernel_netlink.h"
#include "zebra/rule_netlink.h"
#include "zebra/zebra_pbr.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_dplane.h"
#include "zebra/zebra_trace.h"

/* definitions */

/* static function declarations */

/* Private functions */


/*
 * netlink_rule_msg_encode
 *
 * Encodes netlink RTM_ADDRULE/RTM_DELRULE message to buffer buf of size buflen.
 *
 * Returns -1 on failure, 0 when the msg doesn't fit entirely in the buffer
 * or the number of bytes written to buf.
 */
static ssize_t netlink_rule_msg_encode(
	int cmd, const struct zebra_dplane_ctx *ctx, uint32_t filter_bm,
	uint32_t priority, uint32_t table, const struct prefix *src_ip,
	const struct prefix *dst_ip, uint32_t fwmark, uint8_t dsfield,
	uint8_t ip_protocol, void *buf, size_t buflen)
{
	uint8_t protocol = RTPROT_ZEBRA;
	int family;
	int bytelen;
	struct {
		struct nlmsghdr n;
		struct fib_rule_hdr frh;
		char buf[];
	} *req = buf;

	const char *ifname = dplane_ctx_rule_get_ifname(ctx);

	if (buflen < sizeof(*req))
		return 0;
	memset(req, 0, sizeof(*req));

	/* Assume ipv4 if no src/dst set, we only support ipv4/ipv6 */
	if (PREFIX_FAMILY(src_ip))
		family = PREFIX_FAMILY(src_ip);
	else if (PREFIX_FAMILY(dst_ip))
		family = PREFIX_FAMILY(dst_ip);
	else
		family = AF_INET;

	bytelen = (family == AF_INET ? 4 : 16);

	req->n.nlmsg_type = cmd;
	req->n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req->n.nlmsg_flags = NLM_F_REQUEST;

	req->frh.family = family;
	req->frh.action = FR_ACT_TO_TBL;

	if (!nl_attr_put(&req->n, buflen, FRA_PROTOCOL, &protocol,
			 sizeof(protocol)))
		return 0;

	/* rule's pref # */
	if (!nl_attr_put32(&req->n, buflen, FRA_PRIORITY, priority))
		return 0;

	/* interface on which applied */
	if (!nl_attr_put(&req->n, buflen, FRA_IFNAME, ifname,
			 strlen(ifname) + 1))
		return 0;

	/* source IP, if specified */
	if (filter_bm & PBR_FILTER_SRC_IP) {
		req->frh.src_len = src_ip->prefixlen;
		if (!nl_attr_put(&req->n, buflen, FRA_SRC, &src_ip->u.prefix,
				 bytelen))
			return 0;
	}

	/* destination IP, if specified */
	if (filter_bm & PBR_FILTER_DST_IP) {
		req->frh.dst_len = dst_ip->prefixlen;
		if (!nl_attr_put(&req->n, buflen, FRA_DST, &dst_ip->u.prefix,
				 bytelen))
			return 0;
	}

	/* fwmark, if specified */
	if (filter_bm & PBR_FILTER_FWMARK) {
		if (!nl_attr_put32(&req->n, buflen, FRA_FWMARK, fwmark))
			return 0;
	}

	/* dsfield, if specified; mask off the ECN bits */
	if (filter_bm & PBR_FILTER_DSCP)
		req->frh.tos = dsfield & PBR_DSFIELD_DSCP;

	/* protocol to match on */
	if (filter_bm & PBR_FILTER_IP_PROTOCOL)
		nl_attr_put8(&req->n, buflen, FRA_IP_PROTO, ip_protocol);

	/* Route table to use to forward, if filter criteria matches. */
	if (table < 256)
		req->frh.table = table;
	else {
		req->frh.table = RT_TABLE_UNSPEC;
		if (!nl_attr_put32(&req->n, buflen, FRA_TABLE, table))
			return 0;
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug(
			"Tx %s family %s IF %s Pref %u Fwmark %u Src %pFX Dst %pFX Table %u",
			nl_msg_type_to_str(cmd), nl_family_to_str(family),
			ifname, priority, fwmark, src_ip, dst_ip, table);

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

static ssize_t netlink_rule_msg_encoder(struct zebra_dplane_ctx *ctx, void *buf,
					size_t buflen)
{
	int cmd = RTM_NEWRULE;

	if (dplane_ctx_get_op(ctx) == DPLANE_OP_RULE_DELETE)
		cmd = RTM_DELRULE;

	return netlink_rule_msg_encode(
		cmd, ctx, dplane_ctx_rule_get_filter_bm(ctx),
		dplane_ctx_rule_get_priority(ctx),
		dplane_ctx_rule_get_table(ctx), dplane_ctx_rule_get_src_ip(ctx),
		dplane_ctx_rule_get_dst_ip(ctx),
		dplane_ctx_rule_get_fwmark(ctx),
		dplane_ctx_rule_get_dsfield(ctx),
		dplane_ctx_rule_get_ipproto(ctx), buf, buflen);
}

static ssize_t netlink_oldrule_msg_encoder(struct zebra_dplane_ctx *ctx,
					   void *buf, size_t buflen)
{
	return netlink_rule_msg_encode(
		RTM_DELRULE, ctx, dplane_ctx_rule_get_old_filter_bm(ctx),
		dplane_ctx_rule_get_old_priority(ctx),
		dplane_ctx_rule_get_old_table(ctx),
		dplane_ctx_rule_get_old_src_ip(ctx),
		dplane_ctx_rule_get_old_dst_ip(ctx),
		dplane_ctx_rule_get_old_fwmark(ctx),
		dplane_ctx_rule_get_old_dsfield(ctx),
		dplane_ctx_rule_get_old_ipproto(ctx), buf, buflen);
}

/*
 * Identify valid rule actions for netlink - other actions can't be installed
 */
static bool nl_rule_valid_action(uint32_t action)
{
	if (action == PBR_ACTION_TABLE)
		return true;
	else
		return false;
}

/* Public functions */

enum netlink_msg_status
netlink_put_rule_update_msg(struct nl_batch *bth, struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op;
	enum netlink_msg_status ret;
	struct pbr_rule rule = {};

	op = dplane_ctx_get_op(ctx);
	if (!(op == DPLANE_OP_RULE_ADD || op == DPLANE_OP_RULE_UPDATE
	      || op == DPLANE_OP_RULE_DELETE)) {
		flog_err(
			EC_ZEBRA_PBR_RULE_UPDATE,
			"Context received for kernel rule update with incorrect OP code (%u)",
			op);
		return FRR_NETLINK_ERROR;
	}

	/* TODO -- special handling for rules that include actions that
	 * netlink cannot install. Some of the rule attributes are not
	 * available in netlink: only try to install valid actions.
	 */
	dplane_ctx_rule_get(ctx, &rule, NULL);
	if (!nl_rule_valid_action(rule.action.flags)) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: skip invalid action %#x", __func__,
				   rule.action.flags);
		return 0;
	}

	ret = netlink_batch_add_msg(bth, ctx, netlink_rule_msg_encoder, false);

	/**
	 * Delete the old one.
	 *
	 * Don't care about this result right?
	 */
	if (op == DPLANE_OP_RULE_UPDATE)
		netlink_batch_add_msg(bth, ctx, netlink_oldrule_msg_encoder,
				      true);

	return ret;
}

/*
 * Handle netlink notification informing a rule add or delete.
 * Handling of an ADD is TBD.
 * DELs are notified up, if other attributes indicate it may be a
 * notification of interest. The expectation is that if this corresponds
 * to a PBR rule added by FRR, it will be readded.
 *
 * If startup and we see a rule we created, delete it as its leftover
 * from a previous instance and should have been removed on shutdown.
 *
 */
int netlink_rule_change(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	struct zebra_ns *zns;
	struct fib_rule_hdr *frh;
	struct rtattr *tb[FRA_MAX + 1];
	int len;
	char *ifname;
	struct zebra_pbr_rule rule = {};
	uint8_t proto = 0;
	uint8_t ip_proto = 0;

	frrtrace(3, frr_zebra, netlink_rule_change, h, ns_id, startup);

	/* Basic validation followed by extracting attributes. */
	if (h->nlmsg_type != RTM_NEWRULE && h->nlmsg_type != RTM_DELRULE)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct fib_rule_hdr));
	if (len < 0) {
		zlog_err(
			"%s: Message received from netlink is of a broken size: %d %zu",
			__func__, h->nlmsg_len,
			(size_t)NLMSG_LENGTH(sizeof(struct fib_rule_hdr)));
		return -1;
	}

	frh = NLMSG_DATA(h);

	if (frh->family != AF_INET && frh->family != AF_INET6) {
		if (frh->family == RTNL_FAMILY_IPMR
		    || frh->family == RTNL_FAMILY_IP6MR) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"Received rule netlink that we are ignoring for family %u, rule change: %u",
					frh->family, h->nlmsg_type);
			return 0;
		}
		flog_warn(
			EC_ZEBRA_NETLINK_INVALID_AF,
			"Invalid address family: %u received from kernel rule change: %u",
			frh->family, h->nlmsg_type);
		return 0;
	}
	if (frh->action != FR_ACT_TO_TBL)
		return 0;

	memset(tb, 0, sizeof(tb));
	netlink_parse_rtattr(tb, FRA_MAX, RTM_RTA(frh), len);

	if (tb[FRA_PRIORITY])
		rule.rule.priority = *(uint32_t *)RTA_DATA(tb[FRA_PRIORITY]);

	if (tb[FRA_SRC]) {
		if (frh->family == AF_INET)
			memcpy(&rule.rule.filter.src_ip.u.prefix4,
			       RTA_DATA(tb[FRA_SRC]), 4);
		else
			memcpy(&rule.rule.filter.src_ip.u.prefix6,
			       RTA_DATA(tb[FRA_SRC]), 16);
		rule.rule.filter.src_ip.prefixlen = frh->src_len;
		rule.rule.filter.src_ip.family = frh->family;
		rule.rule.filter.filter_bm |= PBR_FILTER_SRC_IP;
	}

	if (tb[FRA_DST]) {
		if (frh->family == AF_INET)
			memcpy(&rule.rule.filter.dst_ip.u.prefix4,
			       RTA_DATA(tb[FRA_DST]), 4);
		else
			memcpy(&rule.rule.filter.dst_ip.u.prefix6,
			       RTA_DATA(tb[FRA_DST]), 16);
		rule.rule.filter.dst_ip.prefixlen = frh->dst_len;
		rule.rule.filter.dst_ip.family = frh->family;
		rule.rule.filter.filter_bm |= PBR_FILTER_DST_IP;
	}

	if (tb[FRA_TABLE])
		rule.rule.action.table = *(uint32_t *)RTA_DATA(tb[FRA_TABLE]);
	else
		rule.rule.action.table = frh->table;

	/* TBD: We don't care about rules not specifying an IIF. */
	if (tb[FRA_IFNAME] == NULL)
		return 0;

	if (tb[FRA_PROTOCOL])
		proto = *(uint8_t *)RTA_DATA(tb[FRA_PROTOCOL]);

	if (tb[FRA_IP_PROTO])
		ip_proto = *(uint8_t *)RTA_DATA(tb[FRA_IP_PROTO]);

	ifname = (char *)RTA_DATA(tb[FRA_IFNAME]);
	strlcpy(rule.ifname, ifname, sizeof(rule.ifname));

	if (h->nlmsg_type == RTM_NEWRULE) {
		/*
		 * If we see a rule at startup we created, delete it now.
		 * It should have been flushed on a previous shutdown.
		 */
		if (startup && proto == RTPROT_ZEBRA) {
			enum zebra_dplane_result ret;

			ret = dplane_pbr_rule_delete(&rule);

			zlog_debug(
				"%s: %s leftover rule: family %s IF %s Pref %u Src %pFX Dst %pFX Table %u ip-proto: %u",
				__func__,
				((ret == ZEBRA_DPLANE_REQUEST_FAILURE)
					 ? "Failed to remove"
					 : "Removed"),
				nl_family_to_str(frh->family), rule.ifname,
				rule.rule.priority, &rule.rule.filter.src_ip,
				&rule.rule.filter.dst_ip,
				rule.rule.action.table, ip_proto);
		}

		/* TBD */
		return 0;
	}

	zns = zebra_ns_lookup(ns_id);

	/* If we don't know the interface, we don't care. */
	if (!if_lookup_by_name_per_ns(zns, ifname))
		return 0;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug(
			"Rx %s family %s IF %s Pref %u Src %pFX Dst %pFX Table %u ip-proto: %u",
			nl_msg_type_to_str(h->nlmsg_type),
			nl_family_to_str(frh->family), rule.ifname,
			rule.rule.priority, &rule.rule.filter.src_ip,
			&rule.rule.filter.dst_ip, rule.rule.action.table,
			ip_proto);

	return kernel_pbr_rule_del(&rule);
}

/*
 * Request rules from the kernel
 */
static int netlink_request_rules(struct zebra_ns *zns, int family, int type)
{
	struct {
		struct nlmsghdr n;
		struct fib_rule_hdr frh;
		char buf[NL_PKT_BUF_SIZE];
	} req;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_type = type;
	req.n.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct fib_rule_hdr));
	req.frh.family = family;

	return netlink_request(&zns->netlink_cmd, &req);
}

/*
 * Get to know existing PBR rules in the kernel - typically called at startup.
 */
int netlink_rules_read(struct zebra_ns *zns)
{
	int ret;
	struct zebra_dplane_info dp_info;

	zebra_dplane_info_from_zns(&dp_info, zns, true);

	ret = netlink_request_rules(zns, AF_INET, RTM_GETRULE);
	if (ret < 0)
		return ret;

	ret = netlink_parse_info(netlink_rule_change, &zns->netlink_cmd,
				 &dp_info, 0, true);
	if (ret < 0)
		return ret;

	ret = netlink_request_rules(zns, AF_INET6, RTM_GETRULE);
	if (ret < 0)
		return ret;

	ret = netlink_parse_info(netlink_rule_change, &zns->netlink_cmd,
				 &dp_info, 0, true);

	return ret;
}

#endif /* HAVE_NETLINK */
