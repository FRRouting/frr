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

#ifdef __cplusplus
extern "C" {
#endif

#ifdef HAVE_NETLINK

#define NL_RCV_PKT_BUF_SIZE     32768
#define NL_PKT_BUF_SIZE         8192

/*
 * nl_attr_put - add an attribute to the Netlink message.
 *
 * Returns true if the attribute could be added to the message (fits into the
 * buffer), otherwise false is returned.
 */
extern bool nl_attr_put(struct nlmsghdr *n, unsigned int maxlen, int type,
			const void *data, unsigned int alen);
extern bool nl_attr_put16(struct nlmsghdr *n, unsigned int maxlen, int type,
			  uint16_t data);
extern bool nl_attr_put32(struct nlmsghdr *n, unsigned int maxlen, int type,
			  uint32_t data);

/*
 * nl_attr_nest - start an attribute nest.
 *
 * Returns a valid pointer to the beginning of the nest if the attribute
 * describing the nest could be added to the message (fits into the buffer),
 * otherwise NULL is returned.
 */
extern struct rtattr *nl_attr_nest(struct nlmsghdr *n, unsigned int maxlen,
				   int type);

/*
 * nl_attr_nest_end - finalize nesting of attributes.
 *
 * Updates the length field of the attribute header to include the appeneded
 * attributes. Returns a total length of the Netlink message.
 */
extern int nl_attr_nest_end(struct nlmsghdr *n, struct rtattr *nest);

/*
 * nl_attr_rtnh - append a rtnexthop record to the Netlink message.
 *
 * Returns a valid pointer to the rtnexthop struct if it could be added to
 * the message (fits into the buffer), otherwise NULL is returned.
 */
extern struct rtnexthop *nl_attr_rtnh(struct nlmsghdr *n, unsigned int maxlen);

/*
 * nl_attr_rtnh_end - finalize adding a rtnexthop record.
 *
 * Updates the length field of the rtnexthop to include the appeneded
 * attributes.
 */
extern void nl_attr_rtnh_end(struct nlmsghdr *n, struct rtnexthop *rtnh);

extern void netlink_parse_rtattr(struct rtattr **tb, int max,
				 struct rtattr *rta, int len);
extern void netlink_parse_rtattr_nested(struct rtattr **tb, int max,
					struct rtattr *rta);
extern const char *nl_msg_type_to_str(uint16_t msg_type);
extern const char *nl_rtproto_to_str(uint8_t rtproto);
extern const char *nl_family_to_str(uint8_t family);
extern const char *nl_rttype_to_str(uint8_t rttype);

#if defined(HANDLE_NETLINK_FUZZING)
extern bool netlink_read;
extern void netlink_read_init(const char *fname);
#endif /* HANDLE_NETLINK_FUZZING */
extern int netlink_parse_info(int (*filter)(struct nlmsghdr *, ns_id_t, int),
			      const struct nlsock *nl,
			      const struct zebra_dplane_info *dp_info,
			      int count, int startup);
extern int netlink_talk_filter(struct nlmsghdr *h, ns_id_t ns, int startup);
extern int netlink_talk(int (*filter)(struct nlmsghdr *, ns_id_t, int startup),
			struct nlmsghdr *n, struct nlsock *nl,
			struct zebra_ns *zns, int startup);
/* Version with 'info' struct only */
int netlink_talk_info(int (*filter)(struct nlmsghdr *, ns_id_t, int startup),
		      struct nlmsghdr *n,
		      const struct zebra_dplane_info *dp_info, int startup);

extern int netlink_request(struct nlsock *nl, void *req);

#endif /* HAVE_NETLINK */

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_KERNEL_NETLINK_H */
