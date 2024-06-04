// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Stub netlink parser library module
 * Copyright (c) 2023 Cisco Systems Inc.
 *
 */

#include "config.h"
#include "xref.h"

XREF_SETUP();

/* Only used with netlink, for now */
#ifdef HAVE_NETLINK

#ifndef FRR_KERNEL_NETLINK

/* Need some things to build this code as standalone, outside zebra. */

#include "zebra.h"
#include "linux/netlink.h"
#include "linux/rtnetlink.h"

/* Forward decl */
struct zebra_dplane_info;

#include "zebra_ns.h"
#include "kernel_netlink.h"

void vzlogx(const struct xref_logmsg *xref, int prio, const char *fmt,
	    va_list ap)
{
}

#endif	/* FRR_KERNEL_NETLINK */

void netlink_parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta,
			  int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		/*
		 * The type may be &'ed with NLA_F_NESTED
		 * which puts data in the upper 8 bits of the
		 * rta_type.  Mask it off and save the actual
		 * underlying value to be placed into the array.
		 * This way we don't accidently crash in the future
		 * when the kernel sends us new data and we try
		 * to write well beyond the end of the array.
		 */
		uint16_t type = rta->rta_type & NLA_TYPE_MASK;

		if (type <= max)
			tb[type] = rta;
		rta = RTA_NEXT(rta, len);
	}
}

/**
 * netlink_parse_rtattr_nested() - Parses a nested route attribute
 * @tb:         Pointer to array for storing rtattr in.
 * @max:        Max number to store.
 * @rta:        Pointer to rtattr to look for nested items in.
 */
void netlink_parse_rtattr_nested(struct rtattr **tb, int max,
				 struct rtattr *rta)
{
	netlink_parse_rtattr(tb, max, RTA_DATA(rta), RTA_PAYLOAD(rta));
}

bool nl_addraw_l(struct nlmsghdr *n, unsigned int maxlen, const void *data,
		 unsigned int len)
{
	if (NLMSG_ALIGN(n->nlmsg_len) + NLMSG_ALIGN(len) > maxlen) {
		zlog_err("ERROR message exceeded bound of %d", maxlen);
		return false;
	}

	memcpy(NLMSG_TAIL(n), data, len);
	memset((uint8_t *)NLMSG_TAIL(n) + len, 0, NLMSG_ALIGN(len) - len);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + NLMSG_ALIGN(len);

	return true;
}

bool nl_attr_put(struct nlmsghdr *n, unsigned int maxlen, int type,
		 const void *data, unsigned int alen)
{
	int len;
	struct rtattr *rta;

	len = RTA_LENGTH(alen);

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen)
		return false;

	rta = (struct rtattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = len;

	if (data)
		memcpy(RTA_DATA(rta), data, alen);
	else
		assert(alen == 0);

	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

	return true;
}

bool nl_attr_put8(struct nlmsghdr *n, unsigned int maxlen, int type,
		  uint8_t data)
{
	return nl_attr_put(n, maxlen, type, &data, sizeof(uint8_t));
}

bool nl_attr_put16(struct nlmsghdr *n, unsigned int maxlen, int type,
		   uint16_t data)
{
	return nl_attr_put(n, maxlen, type, &data, sizeof(uint16_t));
}

bool nl_attr_put32(struct nlmsghdr *n, unsigned int maxlen, int type,
		   uint32_t data)
{
	return nl_attr_put(n, maxlen, type, &data, sizeof(uint32_t));
}

bool nl_attr_put64(struct nlmsghdr *n, unsigned int maxlen, int type,
		   uint64_t data)
{
	return nl_attr_put(n, maxlen, type, &data, sizeof(uint64_t));
}

struct rtattr *nl_attr_nest(struct nlmsghdr *n, unsigned int maxlen, int type)
{
	struct rtattr *nest = NLMSG_TAIL(n);

	if (!nl_attr_put(n, maxlen, type, NULL, 0))
		return NULL;

	nest->rta_type |= NLA_F_NESTED;
	return nest;
}

int nl_attr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (uint8_t *)NLMSG_TAIL(n) - (uint8_t *)nest;
	return n->nlmsg_len;
}

struct rtnexthop *nl_attr_rtnh(struct nlmsghdr *n, unsigned int maxlen)
{
	struct rtnexthop *rtnh = (struct rtnexthop *)NLMSG_TAIL(n);

	if (NLMSG_ALIGN(n->nlmsg_len) + RTNH_ALIGN(sizeof(struct rtnexthop))
	    > maxlen)
		return NULL;

	memset(rtnh, 0, sizeof(struct rtnexthop));
	n->nlmsg_len =
		NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(sizeof(struct rtnexthop));

	return rtnh;
}

void nl_attr_rtnh_end(struct nlmsghdr *n, struct rtnexthop *rtnh)
{
	rtnh->rtnh_len = (uint8_t *)NLMSG_TAIL(n) - (uint8_t *)rtnh;
}

bool nl_rta_put(struct rtattr *rta, unsigned int maxlen, int type,
		const void *data, int alen)
{
	struct rtattr *subrta;
	int len = RTA_LENGTH(alen);

	if (RTA_ALIGN(rta->rta_len) + RTA_ALIGN(len) > maxlen) {
		zlog_err("ERROR max allowed bound %d exceeded for rtattr",
			 maxlen);
		return false;
	}
	subrta = (struct rtattr *)(((char *)rta) + RTA_ALIGN(rta->rta_len));
	subrta->rta_type = type;
	subrta->rta_len = len;
	if (alen)
		memcpy(RTA_DATA(subrta), data, alen);
	rta->rta_len = NLMSG_ALIGN(rta->rta_len) + RTA_ALIGN(len);

	return true;
}

bool nl_rta_put16(struct rtattr *rta, unsigned int maxlen, int type,
		  uint16_t data)
{
	return nl_rta_put(rta, maxlen, type, &data, sizeof(uint16_t));
}

bool nl_rta_put64(struct rtattr *rta, unsigned int maxlen, int type,
		  uint64_t data)
{
	return nl_rta_put(rta, maxlen, type, &data, sizeof(uint64_t));
}

struct rtattr *nl_rta_nest(struct rtattr *rta, unsigned int maxlen, int type)
{
	struct rtattr *nest = RTA_TAIL(rta);

	if (nl_rta_put(rta, maxlen, type, NULL, 0))
		return NULL;

	nest->rta_type |= NLA_F_NESTED;

	return nest;
}

int nl_rta_nest_end(struct rtattr *rta, struct rtattr *nest)
{
	nest->rta_len = (uint8_t *)RTA_TAIL(rta) - (uint8_t *)nest;

	return rta->rta_len;
}

#define NLA_OK(nla, len)                                                       \
	((len) >= (int)sizeof(struct nlattr)                                   \
	 && (nla)->nla_len >= sizeof(struct nlattr)                            \
	 && (nla)->nla_len <= (len))
#define NLA_NEXT(nla, attrlen)                                                 \
	((attrlen) -= NLA_ALIGN((nla)->nla_len),                               \
	 (struct nlattr *)(((char *)(nla)) + NLA_ALIGN((nla)->nla_len)))
#define NLA_LENGTH(len) (NLA_ALIGN(sizeof(struct nlattr)) + (len))
#define NLA_DATA(nla) ((struct nlattr *)(((char *)(nla)) + NLA_LENGTH(0)))

#define ERR_NLA(err, inner_len)                                                \
	((struct nlattr *)(((char *)(err))                                     \
			   + NLMSG_ALIGN(sizeof(struct nlmsgerr))              \
			   + NLMSG_ALIGN((inner_len))))

void netlink_parse_nlattr(struct nlattr **tb, int max, struct nlattr *nla,
			  int len)
{
	while (NLA_OK(nla, len)) {
		if (nla->nla_type <= max)
			tb[nla->nla_type] = nla;
		nla = NLA_NEXT(nla, len);
	}
}

#endif	/* HAVE_NETLINK */
