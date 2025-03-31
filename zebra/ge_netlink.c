// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Generic Netlink functions.
 * Copyright (C) 2022, Carmine Scarpitta
 */

#include <zebra.h>

#ifdef HAVE_NETLINK

/* The following definition is to workaround an issue in the Linux kernel
 * header files with redefinition of 'struct in6_addr' in both
 * netinet/in.h and linux/in6.h.
 * Reference - https://sourceware.org/ml/libc-alpha/2013-01/msg00599.html
 */
#define _LINUX_IN6_H

#include <linux/genetlink.h>
#include <linux/rtnetlink.h>
#include <linux/seg6_genl.h>

#include "lib/ns.h"
#include "zebra/ge_netlink.h"
#include "zebra/debug.h"
#include "zebra/kernel_netlink.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_srv6.h"


/**
 * This file provides an implementation of the functionality exposed by the
 * kernel through the Generic Netlink mechanism.
 *
 * Supported features include the ability to configure the source address used
 * for SRv6 encapsulation ('sr tunsrc' in kernel terminology).
 *
 * At the time of writing this code, the kernel does not send us any asynchronous
 * notifications when someone changes the 'sr tunsrc' under us. As a result, we
 * are currently unable to detect when the source address changes and update the
 * SRv6 encapsulation source address configured in zebra.
 *
 * In the future, when the kernel supports async notifications, the implementation
 * can be improved by listening on the Generic Netlink socket and adding a handler
 * to process/parse incoming 'sr tunsrc' change messages and update the SRv6 zebra
 * configuration with the new encap source address.
 */


/*
 * Numeric family identifier used to configure SRv6 internal parameters through Generic Netlink.
 */
static int16_t seg6_genl_family = -1;

static int genl_parse_getfamily(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	int len;
	struct rtattr *tb[CTRL_ATTR_MAX + 1];
	struct genlmsghdr *ghdr = NLMSG_DATA(h);
	struct rtattr *attrs;
	const char *family;

	if (h->nlmsg_type != GENL_ID_CTRL) {
		zlog_err(
			"Not a controller message, nlmsg_len=%d nlmsg_type=0x%x",
			h->nlmsg_len, h->nlmsg_type);
		return 0;
	}

	len = h->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0) {
		zlog_err(
			"Message received from netlink is of a broken size %d %zu",
			h->nlmsg_len, (size_t)NLMSG_LENGTH(GENL_HDRLEN));
		return -1;
	}

	if (ghdr->cmd != CTRL_CMD_NEWFAMILY) {
		zlog_err("Unknown controller command %d", ghdr->cmd);
		return -1;
	}

	attrs = (struct rtattr *)((char *)ghdr + GENL_HDRLEN);
	netlink_parse_rtattr(tb, CTRL_ATTR_MAX, attrs, len);

	if (tb[CTRL_ATTR_FAMILY_ID] == NULL) {
		zlog_err("Missing family id TLV");
		return -1;
	}

	if (tb[CTRL_ATTR_FAMILY_NAME] == NULL) {
		zlog_err("Missing family name TLV");
		return -1;
	}

	family = (char *)RTA_DATA(tb[CTRL_ATTR_FAMILY_NAME]);

	if (strmatch(family, "SEG6"))
		seg6_genl_family =
			*(int16_t *)RTA_DATA(tb[CTRL_ATTR_FAMILY_ID]);
	else {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_err("Unsupported Generic Netlink family '%s'",
				 family);
		return -1;
	}

	return 0;
}

int genl_resolve_family(const char *family)
{
	struct zebra_ns *zns;
	struct genl_request req;

	memset(&req, 0, sizeof(req));

	zns = zebra_ns_lookup(NS_DEFAULT);

	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = GENL_ID_CTRL;

	req.n.nlmsg_pid = zns->ge_netlink_cmd.snl.nl_pid;

	req.g.cmd = CTRL_CMD_GETFAMILY;
	req.g.version = 0;

	if (!nl_attr_put(&req.n, sizeof(req), CTRL_ATTR_FAMILY_NAME, family,
			 strlen(family) + 1))
		return -1;

	return ge_netlink_talk(genl_parse_getfamily, &req.n, zns, false);
}

/*
 * sr tunsrc change via netlink interface, using a dataplane context object
 *
 * Returns -1 on failure, 0 when the msg doesn't fit entirely in the buffer
 * otherwise the number of bytes written to buf.
 */
ssize_t netlink_sr_tunsrc_set_msg_encode(int cmd, struct zebra_dplane_ctx *ctx,
					 void *buf, size_t buflen)
{
	struct nlsock *nl;
	const struct in6_addr *tunsrc_addr;
	struct genl_request *req = buf;

	if (seg6_genl_family < 0) {
		zlog_err(
			"Failed to set SRv6 source address: kernel does not support 'SEG6' Generic Netlink family.");
		return -1;
	}

	tunsrc_addr = dplane_ctx_get_srv6_encap_srcaddr(ctx);
	if (!tunsrc_addr)
		return -1;

	if (buflen < sizeof(*req))
		return 0;

	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	memset(req, 0, sizeof(*req));

	req->n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req->n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;

	/* Prepare Netlink request to set tunsrc addr */
	req->n.nlmsg_type = seg6_genl_family;
	req->n.nlmsg_pid = nl->snl.nl_pid;

	req->g.cmd = cmd;
	req->g.version = SEG6_GENL_VERSION;

	switch (cmd) {
	case SEG6_CMD_SET_TUNSRC:
		if (!nl_attr_put(&req->n, buflen, SEG6_ATTR_DST, tunsrc_addr,
				 sizeof(struct in6_addr)))
			return 0;
		break;
	default:
		zlog_err("Unsupported command (%u)", cmd);
		return -1;
	}

	return NLMSG_ALIGN(req->n.nlmsg_len);
}

ssize_t netlink_sr_tunsrc_set_msg_encoder(struct zebra_dplane_ctx *ctx,
					  void *buf, size_t buflen)
{
	enum dplane_op_e op;
	int cmd = 0;

	op = dplane_ctx_get_op(ctx);

	/* Call to netlink layer based on type of operation */
	if (op == DPLANE_OP_SRV6_ENCAP_SRCADDR_SET) {
		/* Validate */
		if (dplane_ctx_get_srv6_encap_srcaddr(ctx) == NULL) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"sr tunsrc set failed: SRv6 encap source address not set");
			return -1;
		}

		cmd = SEG6_CMD_SET_TUNSRC;
	} else {
		/* Invalid op */
		zlog_err("Context received for kernel sr tunsrc update with incorrect OP code (%u)",
			 op);
		return -1;
	}

	return netlink_sr_tunsrc_set_msg_encode(cmd, ctx, buf, buflen);
}

enum netlink_msg_status
netlink_put_sr_tunsrc_set_msg(struct nl_batch *bth, struct zebra_dplane_ctx *ctx)
{
	enum dplane_op_e op;
	struct zebra_ns *zns;
	struct genl_request req;

	op = dplane_ctx_get_op(ctx);
	assert(op == DPLANE_OP_SRV6_ENCAP_SRCADDR_SET);

	netlink_sr_tunsrc_set_msg_encoder(ctx, &req, sizeof(req));

	zns = zebra_ns_lookup(dplane_ctx_get_ns_sock(ctx));

	return ge_netlink_talk(netlink_talk_filter, &req.n, zns, false);
}

/**
 * netlink_sr_tunsrc_reply_read() - Read in SR tunsrc reply from the kernel
 *
 * @h:			Netlink message header
 * @ns_id:		Namspace id
 * @startup:	Are we reading under startup conditions?
 *
 * Return:	Result status
 */
int netlink_sr_tunsrc_reply_read(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	int len;
	struct genlmsghdr *ghdr;
	struct rtattr *tb[SEG6_ATTR_MAX + 1] = {};
	struct rtattr *attrs;

	if (h->nlmsg_type != seg6_genl_family)
		return 0;

	len = h->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0) {
		zlog_warn("%s: Message received from netlink is of a broken size %d %zu",
			  __func__, h->nlmsg_len,
			  (size_t)NLMSG_LENGTH(GENL_HDRLEN));
		return -1;
	}

	ghdr = NLMSG_DATA(h);

	if (ghdr->cmd != SEG6_CMD_GET_TUNSRC)
		return 0;

	attrs = (struct rtattr *)((char *)ghdr + GENL_HDRLEN);
	netlink_parse_rtattr(tb, SEG6_ATTR_MAX, attrs, len);

	if (tb[SEG6_ATTR_DST] == NULL) {
		zlog_err("Missing tunsrc addr");
		return -1;
	}

	zebra_srv6_encap_src_addr_set(
		(struct in6_addr *)RTA_DATA(tb[SEG6_ATTR_DST]));

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: SRv6 encap source address received from kernel: '%pI6'",
			   __func__,
			   (struct in6_addr *)RTA_DATA(tb[SEG6_ATTR_DST]));

	return 0;
}

/**
 * netlink_request_sr_tunsrc() - Request SR tunsrc from the kernel
 * @zns:	Zebra namespace
 *
 * Return:	Result status
 */
static int netlink_request_sr_tunsrc(struct zebra_ns *zns)
{
	struct genl_request req;

	if (zns->ge_netlink_cmd.sock < 0)
		return -1;

	if (seg6_genl_family < 0) {
		zlog_err(
			"Failed to get SRv6 encap source address: kernel does not support 'SEG6' Generic Netlink family.");
		return -1;
	}

	/* Form the request, specifying filter (rtattr) if needed. */
	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = seg6_genl_family;
	req.g.cmd = SEG6_CMD_GET_TUNSRC;
	req.g.version = SEG6_GENL_VERSION;

	return netlink_request(&zns->ge_netlink_cmd, &req);
}

/**
 * SR tunsrc read function using netlink interface. Only called
 * on bootstrap time.
 */
int netlink_sr_tunsrc_read(struct zebra_ns *zns)
{
	int ret;
	struct zebra_dplane_info dp_info;

	if (zns->ge_netlink_cmd.sock < 0)
		return -1;

	/* Capture info in intermediate info struct */
	dp_info.ns_id = zns->ns_id;
	dp_info.is_cmd = true;
	dp_info.sock = zns->ge_netlink_cmd.sock;
	dp_info.seq = zns->ge_netlink_cmd.seq;

	/* Get SR tunsrc. */
	ret = netlink_request_sr_tunsrc(zns);
	if (ret < 0)
		return ret;
	ret = netlink_parse_info(netlink_sr_tunsrc_reply_read,
				 &zns->ge_netlink_cmd, &dp_info, 0, true);
	if (ret < 0)
		return ret;

	return 0;
}

void ge_netlink_init(struct zebra_ns *zns)
{
	if (zns->ge_netlink_cmd.sock < 0)
		return;

	/*
	 * Resolves the 'seg6' Generic Netlink family name to the corresponding numeric family identifier.
	 * This will give us the numeric family identifier required to send 'seg6' commands to the kernel
	 * over the Generic Netlink socket. 'seg6' commands are used to configure SRv6 internal parameters
	 * such as the address to use as source for encapsulated packets.
	 */
	if (genl_resolve_family("SEG6"))
		zlog_warn(
			"Kernel does not support 'SEG6' Generic Netlink family. Any attempt to set the encapsulation parameters under the SRv6 configuration will fail");

	/**
	 * Retrieve the actual SRv6 encap source address from the kernel
	 * (default namespace) and save it to zebra SRv6 config
	 */
	if (zns->ns_id == NS_DEFAULT)
		netlink_sr_tunsrc_read(zns);
}

#endif /* HAVE_NETLINK */
