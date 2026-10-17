// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (c) 2026 Qipeng Ding */
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <zebra.h>
#include "privs.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_route.h"

struct zebra_privs_t bgpd_privs = {};
struct event_loop *master;

int main(void)
{
	static const uint8_t lengths[] = { 0, 4, 12, 16, 24, 32, 48 };
	struct attr owner = {};

	bgp_attr_set_aigp_metric(&owner, 17);

	for (unsigned int i = 0; i < array_size(lengths); i++) {
		struct attr parsed = {};
		struct attr original;
		struct attr classic;
		struct in6_addr zero = {};

		assert(inet_pton(AF_INET, "192.0.2.13", &parsed.nexthop) == 1);
		assert(inet_pton(AF_INET, "192.0.2.14", &parsed.mp_nexthop_global_in) == 1);
		assert(inet_pton(AF_INET6, "2001:db8:1::13", &parsed.mp_nexthop_global) == 1);
		assert(inet_pton(AF_INET6, "fe80::13", &parsed.mp_nexthop_local) == 1);
		parsed.mp_nexthop_len = lengths[i];
		parsed.nh_lla_ifindex = 7;
		parsed.local_pref = 200;
		parsed.med = 30;
		parsed.extra = owner.extra;
		bgp_attr_set(&parsed, BGP_ATTR_NEXT_HOP);
		bgp_attr_set(&parsed, BGP_ATTR_AIGP);
		bgp_attr_set(&parsed, BGP_ATTR_MP_REACH_NLRI);
		bgp_attr_set(&parsed, BGP_ATTR_MP_UNREACH_NLRI);
		memcpy(&original, &parsed, sizeof(parsed));
		bgp_attr_classic_nlri(&classic, &parsed);
		assert(classic.nexthop.s_addr == original.nexthop.s_addr);
		assert(bgp_attr_exists(&classic, BGP_ATTR_NEXT_HOP));
		assert(!bgp_attr_exists(&classic, BGP_ATTR_MP_REACH_NLRI));
		assert(!bgp_attr_exists(&classic, BGP_ATTR_MP_UNREACH_NLRI));
		assert(!BGP_ATTR_MP_NEXTHOP_LEN_IP6(&classic));
		assert(classic.mp_nexthop_len == 0 && classic.mp_nexthop_global_in.s_addr == 0);
		assert(memcmp(&classic.mp_nexthop_global, &zero, sizeof(zero)) == 0);
		assert(memcmp(&classic.mp_nexthop_local, &zero, sizeof(zero)) == 0);
		assert(classic.nh_lla_ifindex == 0);
		assert(classic.local_pref == 200 && classic.med == 30 &&
		       classic.extra == owner.extra);
		assert(bgp_attr_exists(&classic, BGP_ATTR_AIGP) &&
		       bgp_attr_get_aigp_metric(&classic) == 17);
		assert(memcmp(&parsed, &original, sizeof(parsed)) == 0);
	}
	bgp_attr_unset_aigp_metric(&owner);
	puts("Classic NLRI next-hop context and original MP attributes preserved.");
	puts("OK");

	return 0;
}
