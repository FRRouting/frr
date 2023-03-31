// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include "log.h"
#include "prefix.h"
#include "plist.h"

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

bool pim_is_group_filtered(struct pim_interface *pim_ifp, pim_addr *grp)
{
	struct prefix grp_pfx;
	struct prefix_list *pl;

	if (!pim_ifp->boundary_oil_plist)
		return false;

	pim_addr_to_prefix(&grp_pfx, *grp);

	pl = prefix_list_lookup(PIM_AFI, pim_ifp->boundary_oil_plist);
	return pl ? prefix_list_apply_ext(pl, NULL, &grp_pfx, true) ==
			       PREFIX_DENY
		  : false;
}


/* This function returns all multicast group */
int pim_get_all_mcast_group(struct prefix *prefix)
{
#if PIM_IPV == 4
	if (!str2prefix("224.0.0.0/4", prefix))
		return 0;
#else
	if (!str2prefix("FF00::0/8", prefix))
		return 0;
#endif
	return 1;
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
