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
}

#endif /* HAVE_NETLINK */
