// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Stub netlink parser library module
 * Copyright (c) 2024 Cisco Systems Inc.
 */

#ifndef LIB_NETLINK_PARSER_H
#define LIB_NETLINK_PARSER_H 1

#include "lib/zebra.h"

/* Only used with netlink, for now */
#ifdef HAVE_NETLINK

#include "linux/netlink.h"
#include "linux/rtnetlink.h"

#define RTM_NHA(h)                                                             \
	((struct rtattr *)(((char *)(h)) + NLMSG_ALIGN(sizeof(struct nhmsg))))

#ifndef NLMSG_TAIL
#define NLMSG_TAIL(nmsg)                                                       \
	((struct rtattr *)(((uint8_t *)(nmsg))                                 \
			   + NLMSG_ALIGN((nmsg)->nlmsg_len)))
#endif

#ifndef RTA_TAIL
#define RTA_TAIL(rta)                                                          \
	((struct rtattr *)(((uint8_t *)(rta)) + RTA_ALIGN((rta)->rta_len)))
#endif

#define NLA_DATA(nla) ((struct nlattr *)(((char *)(nla)) + NLA_LENGTH(0)))

#define ERR_NLA(err, inner_len)                                                \
	((struct nlattr *)(((char *)(err))                                     \
			   + NLMSG_ALIGN(sizeof(struct nlmsgerr))              \
			   + NLMSG_ALIGN((inner_len))))

#define NLA_LENGTH(len) (NLA_ALIGN(sizeof(struct nlattr)) + (len))

/* Init nl message in-place in a buffer */
struct nlmsghdr *nl_msg_init(int type, int flags, int seq, int pid, uint8_t *buf,
			     uint32_t buflen);
struct nlmsghdr *netlink_parse_buf(struct rtattr **tb, int max, void *buf, size_t len);
void nl_msg_get_data(const struct nlmsghdr *n, uint16_t *ptype, uint32_t *plen,
		     uint16_t *pflags);
void netlink_parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta, int len);
void netlink_parse_rtattr_nested(struct rtattr **tb, int max, struct rtattr *rta);

void netlink_parse_nlattr(struct nlattr **tb, int max, struct nlattr *nla, int len);

/*
 * nl_attr_nest - start an attribute nest.
 *
 * Returns a valid pointer to the beginning of the nest if the attribute
 * describing the nest could be added to the message (fits into the buffer),
 * otherwise NULL is returned.
 */
struct rtattr *nl_attr_nest(struct nlmsghdr *n, unsigned int maxlen, int type);

/*
 * nl_attr_nest_end - finalize nesting of attributes.
 *
 * Updates the length field of the attribute header to include the appeneded
 * attributes. Returns a total length of the Netlink message.
 */
int nl_attr_nest_end(struct nlmsghdr *n, struct rtattr *nest);

/*
 * nl_attr_put - add an attribute to the Netlink message.
 *
 * Returns true if the attribute could be added to the message (fits into the
 * buffer), otherwise false is returned.
 */
bool nl_attr_put(struct nlmsghdr *n, unsigned int maxlen, int type, const void *data,
		 unsigned int alen);
bool nl_attr_put8(struct nlmsghdr *n, unsigned int maxlen, int type, uint8_t data);
bool nl_attr_put16(struct nlmsghdr *n, unsigned int maxlen, int type, uint16_t data);
bool nl_attr_put32(struct nlmsghdr *n, unsigned int maxlen, int type, uint32_t data);
bool nl_attr_put64(struct nlmsghdr *n, unsigned int maxlen, int type, uint64_t data);

/*
 * nl_rta_put - add an additional optional attribute(rtattr) to the
 * Netlink message buffer.
 *
 * Returns true if the attribute could be added to the message (fits into the
 * buffer), otherwise false is returned.
 */
bool nl_rta_put(struct rtattr *rta, unsigned int maxlen, int type, const void *data,
		int alen);
bool nl_rta_put16(struct rtattr *rta, unsigned int maxlen, int type, uint16_t data);
bool nl_rta_put64(struct rtattr *rta, unsigned int maxlen, int type, uint64_t data);


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

/*
 * nl_addraw_l copies raw form the netlink message buffer into netlink
 * message header pointer. It ensures the aligned data buffer does not
 * override past max length.
 * return value is 0 if its successful
 */
extern bool nl_addraw_l(struct nlmsghdr *n, unsigned int maxlen, const void *data,
			unsigned int len);
/*
 * nl_rta_nest - start an additional optional attribute (rtattr) nest.
 *
 * Returns a valid pointer to the beginning of the nest if the attribute
 * describing the nest could be added to the message (fits into the buffer),
 * otherwise NULL is returned.
 */
extern struct rtattr *nl_rta_nest(struct rtattr *rta, unsigned int maxlen, int type);
/*
 * nl_rta_nest_end - finalize nesting of an aditionl optionl attributes.
 *
 * Updates the length field of the attribute header to include the appeneded
 * attributes. Returns a total length of the Netlink message.
 */
extern int nl_rta_nest_end(struct rtattr *rta, struct rtattr *nest);

#endif /* HAVE_NETLINK */

#endif /* LIB_NETLINK_PARSER_H */
