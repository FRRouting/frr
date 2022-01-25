/* Header file exported by if_netlink.c to zebra.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_IF_NETLINK_H
#define _ZEBRA_IF_NETLINK_H

#ifdef HAVE_NETLINK

#ifdef __cplusplus
extern "C" {
#endif

extern int netlink_interface_addr(struct nlmsghdr *h, ns_id_t ns_id,
				  int startup);

/*
 * Parse an incoming interface address change message, generate a dplane
 * context object for processing.
 */
int netlink_interface_addr_dplane(struct nlmsghdr *h, ns_id_t ns_id,
				  int startup);

extern int netlink_link_change(struct nlmsghdr *h, ns_id_t ns_id, int startup);
extern int interface_lookup_netlink(struct zebra_ns *zns);

extern ssize_t netlink_intf_msg_encode(uint16_t cmd,
				       const struct zebra_dplane_ctx *ctx,
				       void *buf, size_t buflen);
extern enum netlink_msg_status
netlink_put_gre_set_msg(struct nl_batch *bth, struct zebra_dplane_ctx *ctx);

extern enum netlink_msg_status
netlink_put_address_update_msg(struct nl_batch *bth,
			       struct zebra_dplane_ctx *ctx);

extern int netlink_tunneldump_read(struct zebra_ns *zns);
extern enum netlink_msg_status
netlink_put_intf_update_msg(struct nl_batch *bth, struct zebra_dplane_ctx *ctx);

#define FRR_PROTODOWN_REASON_DEFAULT_BIT 7
/* Protodown bit setter/getter
 *
 * Allow users to change the bit if it conflicts with another
 * on their system.
 */
extern void if_netlink_set_frr_protodown_r_bit(uint8_t bit);
extern void if_netlink_unset_frr_protodown_r_bit(void);
extern bool if_netlink_frr_protodown_r_bit_is_set(void);
extern uint8_t if_netlink_get_frr_protodown_r_bit(void);

#ifdef __cplusplus
}
#endif

#endif /* HAVE_NETLINK */

#endif /* _ZEBRA_IF_NETLINK_H */
