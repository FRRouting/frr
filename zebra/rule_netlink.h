// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra Policy Based Routing (PBR) interaction with the kernel using
 * netlink - public definitions and function declarations.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 */

#ifndef _ZEBRA_RULE_NETLINK_H
#define _ZEBRA_RULE_NETLINK_H

#ifdef HAVE_NETLINK

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Handle netlink notification informing a rule add or delete.
 */
extern int netlink_rule_change(struct nlmsghdr *h, ns_id_t ns_id, int startup);

/*
 * Get to know existing PBR rules in the kernel - typically called at startup.
 */
extern int netlink_rules_read(struct zebra_ns *zns);

extern enum netlink_msg_status
netlink_put_rule_update_msg(struct nl_batch *bth, struct zebra_dplane_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* HAVE_NETLINK */

#endif /* _ZEBRA_RULE_NETLINK_H */
