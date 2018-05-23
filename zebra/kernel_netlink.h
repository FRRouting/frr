/* Declarations and definitions for kernel interaction over netlink
 * Copyright (C) 2016 Cumulus Networks, Inc.
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

#ifndef _ZEBRA_KERNEL_NETLINK_H
#define _ZEBRA_KERNEL_NETLINK_H

#ifdef HAVE_NETLINK

#define NL_RCV_PKT_BUF_SIZE     32768
#define NL_PKT_BUF_SIZE         8192

extern void netlink_parse_rtattr(struct rtattr **tb, int max,
				 struct rtattr *rta, int len);
extern int addattr_l(struct nlmsghdr *n, unsigned int maxlen, int type,
		     void *data, unsigned int alen);
extern int rta_addattr_l(struct rtattr *rta, unsigned int maxlen, int type,
			 void *data, unsigned int alen);
extern int addattr16(struct nlmsghdr *n, unsigned int maxlen, int type,
		     uint16_t data);
extern int addattr32(struct nlmsghdr *n, unsigned int maxlen, int type,
		     int data);
extern struct rtattr *addattr_nest(struct nlmsghdr *n, int maxlen, int type);
extern int addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest);
extern struct rtattr *rta_nest(struct rtattr *rta, int maxlen, int type);
extern int rta_nest_end(struct rtattr *rta, struct rtattr *nest);
extern const char *nl_msg_type_to_str(uint16_t msg_type);
extern const char *nl_rtproto_to_str(uint8_t rtproto);
extern const char *nl_family_to_str(uint8_t family);
extern const char *nl_rttype_to_str(uint8_t rttype);

extern int netlink_parse_info(int (*filter)(struct nlmsghdr *, ns_id_t, int),
			      struct nlsock *nl, struct zebra_ns *zns,
			      int count, int startup);
extern int netlink_talk_filter(struct nlmsghdr *h, ns_id_t ns, int startup);
extern int netlink_talk(int (*filter)(struct nlmsghdr *, ns_id_t, int startup),
			struct nlmsghdr *n, struct nlsock *nl,
			struct zebra_ns *zns, int startup);
extern int netlink_request(struct nlsock *nl, struct nlmsghdr *n);

#endif /* HAVE_NETLINK */

#endif /* _ZEBRA_KERNEL_NETLINK_H */
