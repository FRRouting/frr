// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include "log.h"
#include "prefix.h"
#include "plist.h"
#include "plist_int.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_util.h"

/*
  RFC 3376: 4.1.7. QQIC (Querier's Query Interval Code)

  If QQIC < 128,  QQI = QQIC
  If QQIC >= 128, QQI = (mant | 0x10) << (exp + 3)

  0 1 2 3 4 5 6 7
  +-+-+-+-+-+-+-+-+
  |1| exp | mant  |
  +-+-+-+-+-+-+-+-+

  Since exp=0..7 then (exp+3)=3..10, then QQI has
  one of the following bit patterns:

  exp=0: QQI = 0000.0000.1MMM.M000
  exp=1: QQI = 0000.0001.MMMM.0000
  ...
  exp=6: QQI = 001M.MMM0.0000.0000
  exp=7: QQI = 01MM.MM00.0000.0000
  --------- ---------
  0x4  0x0  0x0  0x0
*/
uint8_t igmp_msg_encode16to8(uint16_t value)
{
	uint8_t code;

	if (value < 128) {
		code = value;
	} else {
		uint16_t mask = 0x4000;
		uint8_t exp;
		uint16_t mant;
		for (exp = 7; exp > 0; --exp) {
			if (mask & value)
				break;
			mask >>= 1;
		}
		mant = 0x000F & (value >> (exp + 3));
		code = ((uint8_t)1 << 7) | ((uint8_t)exp << 4) | (uint8_t)mant;
	}

	return code;
}

/*
  RFC 3376: 4.1.7. QQIC (Querier's Query Interval Code)

  If QQIC < 128,  QQI = QQIC
  If QQIC >= 128, QQI = (mant | 0x10) << (exp + 3)

  0 1 2 3 4 5 6 7
  +-+-+-+-+-+-+-+-+
  |1| exp | mant  |
  +-+-+-+-+-+-+-+-+
*/
uint16_t igmp_msg_decode8to16(uint8_t code)
{
	uint16_t value;

	if (code < 128) {
		value = code;
	} else {
		uint16_t mant = (code & 0x0F);
		uint8_t exp = (code & 0x70) >> 4;
		value = (mant | 0x10) << (exp + 3);
	}

	return value;
}

void pim_pkt_dump(const char *label, const uint8_t *buf, int size)
{
	zlog_debug("%s: pkt dump size=%d", label, size);
	zlog_hexdump(buf, size);
}

int pim_is_group_224_0_0_0_24(struct in_addr group_addr)
{
	static int first = 1;
	static struct prefix group_224;
	struct prefix group;

	if (first) {
		if (!str2prefix("224.0.0.0/24", &group_224))
			return 0;
		first = 0;
	}

	group.family = AF_INET;
	group.u.prefix4 = group_addr;
	group.prefixlen = IPV4_MAX_BITLEN;

	return prefix_match(&group_224, &group);
}

int pim_is_group_224_4(struct in_addr group_addr)
{
	static int first = 1;
	static struct prefix group_all;
	struct prefix group;

	if (first) {
		if (!str2prefix("224.0.0.0/4", &group_all))
			return 0;
		first = 0;
	}

	group.family = AF_INET;
	group.u.prefix4 = group_addr;
	group.prefixlen = IPV4_MAX_BITLEN;

	return prefix_match(&group_all, &group);
}

bool pim_is_group_ff00_8(struct in6_addr group_address)
{
	struct prefix group_all = { .family = AF_INET6,
				    .prefixlen = 8,
				    .u.prefix6.s6_addr = { 0xFF } };
	struct prefix group;

	group.family = AF_INET6;
	group.u.prefix6 = group_address;
	group.prefixlen = IPV6_MAX_BITLEN;

	return prefix_match(&group_all, &group);
}

static bool pim_cisco_match(const struct filter *filter, const struct in_addr *source,
			    const struct in_addr *group)
{
	const struct filter_cisco *cfilter = &filter->u.cfilter;
	uint32_t source_addr;
	uint32_t group_addr;

	group_addr = group->s_addr & ~cfilter->mask_mask.s_addr;

	if (cfilter->extended) {
		source_addr = source->s_addr & ~cfilter->addr_mask.s_addr;
		if (group_addr == cfilter->mask.s_addr && source_addr == cfilter->addr.s_addr)
			return true;
	} else if (group_addr == cfilter->addr.s_addr)
		return true;

	return false;
}

enum filter_type pim_access_list_apply(struct access_list *access, const struct in_addr *source,
				       const struct in_addr *group)
{
	struct filter *filter;
	struct prefix group_prefix = {};

	if (access == NULL)
		return FILTER_DENY;

	for (filter = access->head; filter; filter = filter->next) {
		if (filter->cisco) {
			if (pim_cisco_match(filter, source, group))
				return filter->type;
		}
	}

	group_prefix.family = AF_INET;
	group_prefix.prefixlen = IPV4_MAX_BITLEN;
	group_prefix.u.prefix4.s_addr = group->s_addr;
	return access_list_apply(access, &group_prefix);
}

bool pim_is_group_filtered(struct pim_interface *pim_ifp, pim_addr *grp, pim_addr *src)
{
	bool is_filtered = false;
#if PIM_IPV == 4
	struct prefix grp_pfx = {};
	pim_addr any_src = PIMADDR_ANY;

	if (!pim_ifp->boundary_oil_plist && !pim_ifp->boundary_acl)
		return false;

	pim_addr_to_prefix(&grp_pfx, *grp);

	/* Filter if either group or (S,G) are denied */
	if (pim_ifp->boundary_oil_plist) {
		is_filtered = prefix_list_apply_ext(pim_ifp->boundary_oil_plist, NULL, &grp_pfx,
						    true) == PREFIX_DENY;
		if (is_filtered && PIM_DEBUG_EVENTS) {
			zlog_debug("Filtering group %pI4 per prefix-list %s", grp,
				   pim_ifp->boundary_oil_plist->name);
		}
	}
	if (!is_filtered && pim_ifp->boundary_acl) {
		/* If src not provided, set to "any" (*)? */
		if (!src)
			src = &any_src;
		/* S,G filtering using extended access-list syntax */
		is_filtered = pim_access_list_apply(pim_ifp->boundary_acl, src, grp) == FILTER_DENY;
		if (is_filtered && PIM_DEBUG_EVENTS) {
			if (pim_addr_is_any(*src)) {
				zlog_debug("Filtering (S,G)=(*, %pI4) per access-list %s", grp,
					   pim_ifp->boundary_acl->name);
			} else {
				zlog_debug("Filtering (S,G)=(%pI4, %pI4) per access-list %s", src,
					   grp, pim_ifp->boundary_acl->name);
			}
		}
	}
#endif
	return is_filtered;
}


/* This function returns all multicast group */
void pim_get_all_mcast_group(struct prefix *prefix)
{
	memset(prefix, 0, sizeof(*prefix));

#if PIM_IPV == 4
	/* Precomputed version of: `str2prefix("224.0.0.0/4", prefix);` */
	prefix->family = AF_INET;
	prefix->prefixlen = 4;
	prefix->u.prefix4.s_addr = htonl(0xe0000000);
#else
	/* Precomputed version of: `str2prefix("FF00::0/8", prefix)` */
	prefix->family = AF_INET6;
	prefix->prefixlen = 8;
	prefix->u.prefix6.s6_addr[0] = 0xff;
#endif
}

bool pim_addr_is_multicast(pim_addr addr)
{
#if PIM_IPV == 4
	if (IN_MULTICAST(ntohl(addr.s_addr)))
		return true;
#else
	if (IN6_IS_ADDR_MULTICAST(&addr))
		return true;
#endif
	return false;
}
