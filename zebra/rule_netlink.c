/*
 * Zebra Policy Based Routing (PBR) interaction with the kernel using
 * netlink.
 * Copyright (C) 2018  Cumulus Networks, Inc.
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

/* definitions */

/* static function declarations */

/* Private functions */

/* Install or uninstall specified rule for a specific interface.
 * Form netlink message and ship it. Currently, notify status after
 * waiting for netlink status.
 */
static int netlink_rule_update(int cmd, struct zebra_pbr_rule *rule)
{
	uint8_t protocol = RTPROT_ZEBRA;
	int family;
	int bytelen;
	struct {
		struct nlmsghdr n;
		struct fib_rule_hdr frh;
		char buf[NL_PKT_BUF_SIZE];
	} req;
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);
	struct sockaddr_nl snl;
	char buf1[PREFIX_STRLEN];
	char buf2[PREFIX_STRLEN];

	memset(&req, 0, sizeof(req) - NL_PKT_BUF_SIZE);
	family = PREFIX_FAMILY(&rule->rule.filter.src_ip);
	bytelen = (family == AF_INET ? 4 : 16);

	req.n.nlmsg_type = cmd;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_pid = zns->netlink_cmd.snl.nl_pid;

	req.frh.family = family;
	req.frh.action = FR_ACT_TO_TBL;

	addattr_l(&req.n, sizeof(req),
		  FRA_PROTOCOL, &protocol, sizeof(protocol));

	/* rule's pref # */
	addattr32(&req.n, sizeof(req), FRA_PRIORITY, rule->rule.priority);

	/* interface on which applied */
	addattr_l(&req.n, sizeof(req), FRA_IFNAME, rule->ifname,
		  strlen(rule->ifname) + 1);

	/* source IP, if specified */
	if (IS_RULE_FILTERING_ON_SRC_IP(rule)) {
		req.frh.src_len = rule->rule.filter.src_ip.prefixlen;
		addattr_l(&req.n, sizeof(req), FRA_SRC,
			  &rule->rule.filter.src_ip.u.prefix, bytelen);
	}
	/* destination IP, if specified */
	if (IS_RULE_FILTERING_ON_DST_IP(rule)) {
		req.frh.dst_len = rule->rule.filter.dst_ip.prefixlen;
		addattr_l(&req.n, sizeof(req), FRA_DST,
			  &rule->rule.filter.dst_ip.u.prefix, bytelen);
	}

	/* fwmark, if specified */
	if (IS_RULE_FILTERING_ON_FWMARK(rule)) {
		addattr32(&req.n, sizeof(req), FRA_FWMARK,
			  rule->rule.filter.fwmark);
	}

	/* Route table to use to forward, if filter criteria matches. */
	if (rule->rule.action.table < 256)
		req.frh.table = rule->rule.action.table;
	else {
		req.frh.table = RT_TABLE_UNSPEC;
		addattr32(&req.n, sizeof(req), FRA_TABLE,
			  rule->rule.action.table);
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug(
			"Tx %s family %s IF %s(%u) Pref %u Fwmark %u Src %s Dst %s Table %u",
			nl_msg_type_to_str(cmd), nl_family_to_str(family),
			rule->ifname, rule->rule.ifindex, rule->rule.priority,
			rule->rule.filter.fwmark,
			prefix2str(&rule->rule.filter.src_ip, buf1,
				   sizeof(buf1)),
			prefix2str(&rule->rule.filter.dst_ip, buf2,
				   sizeof(buf2)),
			rule->rule.action.table);

	/* Ship off the message.
	 * Note: Currently, netlink_talk() is a blocking call which returns
	 * back the status.
	 */
	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;
	return netlink_talk(netlink_talk_filter, &req.n,
			    &zns->netlink_cmd, zns, 0);
}


/* Public functions */
/*
 * Install specified rule for a specific interface. The preference is what
 * goes in the rule to denote relative ordering; it may or may not be the
 * same as the rule's user-defined sequence number.
 */
enum zebra_dplane_result kernel_add_pbr_rule(struct zebra_pbr_rule *rule)
{
	int ret = 0;

	ret = netlink_rule_update(RTM_NEWRULE, rule);
	kernel_pbr_rule_add_del_status(rule,
				       (!ret) ? ZEBRA_DPLANE_INSTALL_SUCCESS
					      : ZEBRA_DPLANE_INSTALL_FAILURE);

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

/*
 * Uninstall specified rule for a specific interface.
 */
enum zebra_dplane_result kernel_del_pbr_rule(struct zebra_pbr_rule *rule)
{
	int ret = 0;

	ret = netlink_rule_update(RTM_DELRULE, rule);
	kernel_pbr_rule_add_del_status(rule,
				       (!ret) ? ZEBRA_DPLANE_DELETE_SUCCESS
					      : ZEBRA_DPLANE_DELETE_FAILURE);

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

/*
 * Update specified rule for a specific interface.
 */
enum zebra_dplane_result kernel_update_pbr_rule(struct zebra_pbr_rule *old_rule,
						struct zebra_pbr_rule *new_rule)
{
	int ret = 0;

	/* Add the new, updated one */
	ret = netlink_rule_update(RTM_NEWRULE, new_rule);

	/**
	 * Delete the old one.
	 *
	 * Don't care about this result right?
	 */
	netlink_rule_update(RTM_DELRULE, old_rule);

	kernel_pbr_rule_add_del_status(new_rule,
				       (!ret) ? ZEBRA_DPLANE_INSTALL_SUCCESS
					      : ZEBRA_DPLANE_INSTALL_FAILURE);

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
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
	char buf1[PREFIX_STRLEN];
	char buf2[PREFIX_STRLEN];
	uint8_t proto = 0;

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

	ifname = (char *)RTA_DATA(tb[FRA_IFNAME]);
	strlcpy(rule.ifname, ifname, sizeof(rule.ifname));

	if (h->nlmsg_type == RTM_NEWRULE) {
		/*
		 * If we see a rule at startup we created, delete it now.
		 * It should have been flushed on a previous shutdown.
		 */
		if (startup && proto == RTPROT_ZEBRA) {
			int ret;

			ret = netlink_rule_update(RTM_DELRULE, &rule);

			zlog_debug(
				"%s: %s leftover rule: family %s IF %s(%u) Pref %u Src %s Dst %s Table %u",
				__func__,
				((ret == 0) ? "Removed" : "Failed to remove"),
				nl_family_to_str(frh->family), rule.ifname,
				rule.rule.ifindex, rule.rule.priority,
				prefix2str(&rule.rule.filter.src_ip, buf1,
					   sizeof(buf1)),
				prefix2str(&rule.rule.filter.dst_ip, buf2,
					   sizeof(buf2)),
				rule.rule.action.table);
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
			"Rx %s family %s IF %s(%u) Pref %u Src %s Dst %s Table %u",
			nl_msg_type_to_str(h->nlmsg_type),
			nl_family_to_str(frh->family), rule.ifname,
			rule.rule.ifindex, rule.rule.priority,
			prefix2str(&rule.rule.filter.src_ip, buf1,
				   sizeof(buf1)),
			prefix2str(&rule.rule.filter.dst_ip, buf2,
				   sizeof(buf2)),
			rule.rule.action.table);

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
				 &dp_info, 0, 1);
	if (ret < 0)
		return ret;

	ret = netlink_request_rules(zns, AF_INET6, RTM_GETRULE);
	if (ret < 0)
		return ret;

	ret = netlink_parse_info(netlink_rule_change, &zns->netlink_cmd,
				 &dp_info, 0, 1);
	return ret;
}

#endif /* HAVE_NETLINK */
