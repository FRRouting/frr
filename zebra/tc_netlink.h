// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Traffic Control (TC) interaction with the kernel using netlink.
 *
 * Copyright (C) 2022 Shichu Yang
 */

#ifndef _ZEBRA_TC_NETLINK_H
#define _ZEBRA_TC_NETLINK_H

#ifdef HAVE_NETLINK

#ifdef __cplusplus
extern "C" {
#endif

/* Represent a prefixed address in flower filter */

struct inet_prefix {
	uint16_t flags;
	uint16_t bytelen;
	uint16_t bitlen;
	uint16_t family;
	uint32_t data[64];
};

enum {
	PREFIXLEN_SPECIFIED = (1 << 0),
	ADDRTYPE_INET = (1 << 1),
	ADDRTYPE_UNSPEC = (1 << 2),
	ADDRTYPE_MULTI = (1 << 3),

	ADDRTYPE_INET_UNSPEC = ADDRTYPE_INET | ADDRTYPE_UNSPEC,
	ADDRTYPE_INET_MULTI = ADDRTYPE_INET | ADDRTYPE_MULTI
};

extern enum netlink_msg_status
netlink_put_tc_qdisc_update_msg(struct nl_batch *bth,
				struct zebra_dplane_ctx *ctx);
extern enum netlink_msg_status
netlink_put_tc_class_update_msg(struct nl_batch *bth,
				struct zebra_dplane_ctx *ctx);
extern enum netlink_msg_status
netlink_put_tc_filter_update_msg(struct nl_batch *bth,
				 struct zebra_dplane_ctx *ctx);

/**
 * "filter" & "class" in the following become "tfilter" & "tclass" for
 * the sake of consistency with kernel message types (RTM_NEWTFILTER etc.)
 */

extern int netlink_qdisc_read(struct zebra_ns *zns);

extern int netlink_tfilter_change(struct nlmsghdr *h, ns_id_t ns_id,
				  int startup);
extern int netlink_tclass_change(struct nlmsghdr *h, ns_id_t ns_id,
				 int startup);
extern int netlink_qdisc_change(struct nlmsghdr *h, ns_id_t ns_id, int startup);


#ifdef __cplusplus
}
#endif

#endif /* HAVE_NETLINK */

#endif /* _ZEBRA_TC_NETLINK_H */
