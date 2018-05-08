/*
 * Copyright (C) 2008 Sun Microsystems, Inc.
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "qobj.h"
#include "vty.h"
#include "stream.h"
#include "privs.h"
#include "memory.h"
#include "queue.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_vty.h"

#define VT100_RESET "\x1b[0m"
#define VT100_RED "\x1b[31m"
#define VT100_GREEN "\x1b[32m"
#define VT100_YELLOW "\x1b[33m"

#define CAPABILITY 0
#define DYNCAP     1
#define OPT_PARAM  2

/* need these to link in libbgp */
struct zebra_privs_t *bgpd_privs = NULL;
struct thread_master *master = NULL;

static int failed = 0;
static int tty = 0;

/* test segments to parse and validate, and use for other tests */
static struct test_segment {
	const char *name;
	const char *desc;
	const uint8_t data[1024];
	int len;
#define SHOULD_PARSE	0
#define SHOULD_ERR	-1
	int parses; /* whether it should parse or not */
} mp_reach_segments[] = {
	{
		"IPv6",
		"IPV6 MP Reach, global nexthop, 1 NLRI",
		{
			/* AFI / SAFI */ 0x0,
			AFI_IP6,
			SAFI_UNICAST,
			/* nexthop bytes */ 16,
			/* Nexthop (global) */ 0xff,
			0xfe,
			0x1,
			0x2,
			0xaa,
			0xbb,
			0xcc,
			0xdd,
			0x3,
			0x4,
			0x5,
			0x6,
			0xa1,
			0xa2,
			0xa3,
			0xa4,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 32,
			0xff,
			0xfe,
			0x1,
			0x2, /* fffe:102::/32 */
		},
		(4 + 16 + 1 + 5),
		SHOULD_PARSE,
	},
	{
		"IPv6-2",
		"IPV6 MP Reach, global nexthop, 2 NLRIs",
		{
			/* AFI / SAFI */ 0x0,
			AFI_IP6,
			SAFI_UNICAST,
			/* nexthop bytes */ 16,
			/* Nexthop (global) */ 0xff,
			0xfe,
			0x1,
			0x2, /* ffee:102:... */
			0xaa,
			0xbb,
			0xcc,
			0xdd,
			0x3,
			0x4,
			0x5,
			0x6,
			0xa1,
			0xa2,
			0xa3,
			0xa4,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 32,
			0xff,
			0xfe,
			0x1,
			0x2, /* fffe:102::/32 */
			64,
			0xff,
			0xfe,
			0x0,
			0x1, /* fffe:1:2:3::/64 */
			0x0,
			0x2,
			0x0,
			0x3,
		},
		(4 + 16 + 1 + 5 + 9),
		SHOULD_PARSE,
	},
	{
		"IPv6-default",
		"IPV6 MP Reach, global nexthop, 2 NLRIs + default",
		{
			/* AFI / SAFI */ 0x0,
			AFI_IP6,
			SAFI_UNICAST,
			/* nexthop bytes */ 16,
			/* Nexthop (global) */ 0xff,
			0xfe,
			0x1,
			0x2,
			0xaa,
			0xbb,
			0xcc,
			0xdd,
			0x3,
			0x4,
			0x5,
			0x6,
			0xa1,
			0xa2,
			0xa3,
			0xa4,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 32,
			0xff,
			0xfe,
			0x1,
			0x2, /* fffe:102::/32 */
			64,
			0xff,
			0xfe,
			0x0,
			0x1, /* fffe:1:2:3::/64 */
			0x0,
			0x2,
			0x0,
			0x3,
			0x0, /* ::/0 */
		},
		(4 + 16 + 1 + 5 + 9 + 1),
		SHOULD_PARSE,
	},
	{
		"IPv6-lnh",
		"IPV6 MP Reach, global+local nexthops, 2 NLRIs + default",
		{
			/* AFI / SAFI */ 0x0,
			AFI_IP6,
			SAFI_UNICAST,
			/* nexthop bytes */ 32,
			/* Nexthop (global) */ 0xff,
			0xfe,
			0x1,
			0x2, /* fffe:102:... */
			0xaa,
			0xbb,
			0xcc,
			0xdd,
			0x3,
			0x4,
			0x5,
			0x6,
			0xa1,
			0xa2,
			0xa3,
			0xa4,
			/* Nexthop (local) */ 0xfe,
			0x80,
			0x0,
			0x0, /* fe80::210:2ff:.. */
			0x0,
			0x0,
			0x0,
			0x0,
			0x2,
			0x10,
			0x2,
			0xff,
			0x1,
			0x2,
			0x3,
			0x4,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 32,
			0xff,
			0xfe,
			0x1,
			0x2, /* fffe:102::/32 */
			64,
			0xff,
			0xfe,
			0x0,
			0x1, /* fffe:1:2:3::/64 */
			0x0,
			0x2,
			0x0,
			0x3,
			0x0, /* ::/0 */
		},
		(4 + 32 + 1 + 5 + 9 + 1),
		SHOULD_PARSE,
	},
	{
		"IPv6-nhlen",
		"IPV6 MP Reach, inappropriate nexthop length",
		{
			/* AFI / SAFI */ 0x0,
			AFI_IP6,
			SAFI_UNICAST,
			/* nexthop bytes */ 4,
			/* Nexthop (global) */ 0xff,
			0xfe,
			0x1,
			0x2, /* fffe:102:... */
			0xaa,
			0xbb,
			0xcc,
			0xdd,
			0x3,
			0x4,
			0x5,
			0x6,
			0xa1,
			0xa2,
			0xa3,
			0xa4,
			/* Nexthop (local) */ 0xfe,
			0x80,
			0x0,
			0x0, /* fe80::210:2ff:.. */
			0x0,
			0x0,
			0x0,
			0x0,
			0x2,
			0x10,
			0x2,
			0xff,
			0x1,
			0x2,
			0x3,
			0x4,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 32,
			0xff,
			0xfe,
			0x1,
			0x2, /* fffe:102::/32 */
			64,
			0xff,
			0xfe,
			0x0,
			0x1, /* fffe:1:2:3::/64 */
			0x0,
			0x2,
			0x0,
			0x3,
			0x0, /* ::/0 */
		},
		(4 + 32 + 1 + 5 + 9 + 1),
		SHOULD_ERR,
	},
	{
		"IPv6-nhlen2",
		"IPV6 MP Reach, invalid nexthop length",
		{
			/* AFI / SAFI */ 0x0,
			AFI_IP6,
			SAFI_UNICAST,
			/* nexthop bytes */ 5,
			/* Nexthop (global) */ 0xff,
			0xfe,
			0x1,
			0x2, /* fffe:102:... */
			0xaa,
			0xbb,
			0xcc,
			0xdd,
			0x3,
			0x4,
			0x5,
			0x6,
			0xa1,
			0xa2,
			0xa3,
			0xa4,
			/* Nexthop (local) */ 0xfe,
			0x80,
			0x0,
			0x0, /* fe80::210:2ff:.. */
			0x0,
			0x0,
			0x0,
			0x0,
			0x2,
			0x10,
			0x2,
			0xff,
			0x1,
			0x2,
			0x3,
			0x4,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 32,
			0xff,
			0xfe,
			0x1,
			0x2, /* fffe:102::/32 */
			64,
			0xff,
			0xfe,
			0x0,
			0x1, /* fffe:1:2:3::/64 */
			0x0,
			0x2,
			0x0,
			0x3,
			0x0, /* ::/0 */
		},
		(4 + 32 + 1 + 5 + 9 + 1),
		SHOULD_ERR,
	},
	{
		"IPv6-nhlen3",
		"IPV6 MP Reach, nexthop length overflow",
		{
			/* AFI / SAFI */ 0x0,
			AFI_IP6,
			SAFI_UNICAST,
			/* nexthop bytes */ 32,
			/* Nexthop (global) */ 0xff,
			0xfe,
			0x1,
			0x2, /* fffe:102:... */
			0xaa,
			0xbb,
			0xcc,
			0xdd,
			0x3,
			0x4,
			0x5,
			0x6,
			0xa1,
			0xa2,
			0xa3,
			0xa4,
		},
		(4 + 16),
		SHOULD_ERR,
	},
	{
		"IPv6-nhlen4",
		"IPV6 MP Reach, nexthop length short",
		{
			/* AFI / SAFI */ 0x0,
			AFI_IP6,
			SAFI_UNICAST,
			/* nexthop bytes */ 16,
			/* Nexthop (global) */ 0xff,
			0xfe,
			0x1,
			0x2, /* fffe:102:... */
			0xaa,
			0xbb,
			0xcc,
			0xdd,
			0x3,
			0x4,
			0x5,
			0x6,
			0xa1,
			0xa2,
			0xa3,
			0xa4,
			/* Nexthop (local) */ 0xfe,
			0x80,
			0x0,
			0x0, /* fe80::210:2ff:.. */
			0x0,
			0x0,
			0x0,
			0x0,
			0x2,
			0x10,
			0x2,
			0xff,
			0x1,
			0x2,
			0x3,
			0x4,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 32,
			0xff,
			0xfe,
			0x1,
			0x2, /* fffe:102::/32 */
			64,
			0xff,
			0xfe,
			0x0,
			0x1, /* fffe:1:2:3::/64 */
			0x0,
			0x2,
			0x0,
			0x3,
			0x0, /* ::/0 */
		},
		(4 + 32 + 1 + 5 + 9 + 1),
		SHOULD_ERR,
	},
	{
		"IPv6-nlri",
		"IPV6 MP Reach, NLRI bitlen overflow",
		{
			/* AFI / SAFI */ 0x0,
			AFI_IP6,
			SAFI_UNICAST,
			/* nexthop bytes */ 32,
			/* Nexthop (global) */ 0xff,
			0xfe,
			0x1,
			0x2, /* fffe:102:... */
			0xaa,
			0xbb,
			0xcc,
			0xdd,
			0x3,
			0x4,
			0x5,
			0x6,
			0xa1,
			0xa2,
			0xa3,
			0xa4,
			/* Nexthop (local) */ 0xfe,
			0x80,
			0x0,
			0x0, /* fe80::210:2ff:.. */
			0x0,
			0x0,
			0x0,
			0x0,
			0x2,
			0x10,
			0x2,
			0xff,
			0x1,
			0x2,
			0x3,
			0x4,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 120,
			0xff,
			0xfe,
			0x1,
			0x2, /* fffe:102::/32 */
			64,
			0xff,
			0xfe,
			0x0,
			0x1, /* fffe:1:2:3::/64 */
			0x0,
			0x2,
			0x0,
			0x3,
			0, /* ::/0 */
		},
		(4 + 32 + 1 + 5 + 9 + 1),
		SHOULD_ERR,
	},
	{
		"IPv4",
		"IPv4 MP Reach, 2 NLRIs + default",
		{
			/* AFI / SAFI */ 0x0, AFI_IP, SAFI_UNICAST,
			/* nexthop bytes */ 4,
			/* Nexthop */ 192, 168, 0, 1,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 16, 10, 1, /* 10.1/16 */
			17, 10, 2, 3,		     /* 10.2.3/17 */
			0,			     /* 0/0 */
		},
		(4 + 4 + 1 + 3 + 4 + 1),
		SHOULD_PARSE,
	},
	{
		"IPv4-nhlen",
		"IPv4 MP Reach, nexthop lenth overflow",
		{
			/* AFI / SAFI */ 0x0, AFI_IP, SAFI_UNICAST,
			/* nexthop bytes */ 32,
			/* Nexthop */ 192, 168, 0, 1,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 16, 10, 1, /* 10.1/16 */
			17, 10, 2, 3,		     /* 10.2.3/17 */
			0,			     /* 0/0 */
		},
		(4 + 4 + 1 + 3 + 4 + 1),
		SHOULD_ERR,
	},
	{
		"IPv4-nlrilen",
		"IPv4 MP Reach, nlri lenth overflow",
		{
			/* AFI / SAFI */ 0x0, AFI_IP, SAFI_UNICAST,
			/* nexthop bytes */ 4,
			/* Nexthop */ 192, 168, 0, 1,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 16, 10, 1, /* 10.1/16 */
			30, 10, 0,		     /* 0/0 */
		},
		(4 + 4 + 1 + 3 + 2 + 1),
		SHOULD_ERR,
	},
	{
		"IPv4-VPNv4",
		"IPv4/VPNv4 MP Reach, RD, Nexthop, 2 NLRIs",
		{
			/* AFI / SAFI */ 0x0, AFI_IP, IANA_SAFI_MPLS_VPN,
			/* nexthop bytes */ 12,
			/* RD */ 0, 0, 0, 0, /* RD defined to be 0 */
			0, 0, 0, 0,
			/* Nexthop */ 192, 168, 0, 1,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 88 + 16, 0, 1, 2, /* tag */
							    /* rd, 8 octets */
			0, 0,				    /* RD_TYPE_AS */
			0, 2, 0, 0xff, 3, 4,		    /* AS(2):val(4) */
			10, 1,				    /* 10.1/16 */
			88 + 17, 0xff, 0, 0,		    /* tag */
							    /* rd, 8 octets */
			0, 0,				    /* RD_TYPE_IP */
			192, 168, 0, 1,			    /* IPv4 */
			10, 2, 3,			    /* 10.2.3/17 */
		},
		(4 + 12 + 1 + (1 + 3 + 8 + 2) + (1 + 3 + 8 + 3)),
		SHOULD_PARSE,
	},
	{
		"IPv4-VPNv4-bogus-plen",
		"IPv4/MPLS-labeled VPN MP Reach, RD, Nexthop, NLRI / bogus p'len",
		{
			/* AFI / SAFI */ 0x0,
			AFI_IP,
			IANA_SAFI_MPLS_VPN,
			/* nexthop bytes */ 12,
			/* RD */ 0,
			0,
			1,
			2,
			0,
			0xff,
			3,
			4,
			/* Nexthop */ 192,
			168,
			0,
			1,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 16,
			10,
			1, /* 10.1/16 */
			17,
			10,
			2,
			3, /* 10.2.3/17 */
			0, /* 0/0 */
		},
		(3 + 1 + 3 * 4 + 1 + 3 + 4 + 1),
		SHOULD_ERR,
	},
	{
		"IPv4-VPNv4-plen1-short",
		"IPv4/VPNv4 MP Reach, RD, Nexthop, 2 NLRIs, 1st plen short",
		{
			/* AFI / SAFI */ 0x0, AFI_IP, IANA_SAFI_MPLS_VPN,
			/* nexthop bytes */ 12,
			/* RD */ 0, 0, 0, 0, /* RD defined to be 0 */
			0, 0, 0, 0,
			/* Nexthop */ 192, 168, 0, 1,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 88 + 1, 0, 1, 2, /* tag */
							   /* rd, 8 octets */
			0, 0,				   /* RD_TYPE_AS */
			0, 2, 0, 0xff, 3, 4,		   /* AS(2):val(4) */
			10, 1,				   /* 10.1/16 */
			88 + 17, 0xff, 0, 0,		   /* tag */
							   /* rd, 8 octets */
			0, 0,				   /* RD_TYPE_IP */
			192, 168, 0, 1,			   /* IPv4 */
			10, 2, 3,			   /* 10.2.3/17 */
		},
		(4 + 12 + 1 + (1 + 3 + 8 + 2) + (1 + 3 + 8 + 3)),
		SHOULD_ERR,
	},
	{
		"IPv4-VPNv4-plen1-long",
		"IPv4/VPNv4 MP Reach, RD, Nexthop, 2 NLRIs, 1st plen long",
		{
			/* AFI / SAFI */ 0x0, AFI_IP, IANA_SAFI_MPLS_VPN,
			/* nexthop bytes */ 12,
			/* RD */ 0, 0, 0, 0, /* RD defined to be 0 */
			0, 0, 0, 0,
			/* Nexthop */ 192, 168, 0, 1,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 88 + 32, 0, 1, 2, /* tag */
							    /* rd, 8 octets */
			0, 0,				    /* RD_TYPE_AS */
			0, 2, 0, 0xff, 3, 4,		    /* AS(2):val(4) */
			10, 1,				    /* 10.1/16 */
			88 + 17, 0xff, 0, 0,		    /* tag */
							    /* rd, 8 octets */
			0, 0,				    /* RD_TYPE_IP */
			192, 168, 0, 1,			    /* IPv4 */
			10, 2, 3,			    /* 10.2.3/17 */
		},
		(4 + 12 + 1 + (1 + 3 + 8 + 2) + (1 + 3 + 8 + 3)),
		SHOULD_ERR,
	},
	{
		"IPv4-VPNv4-plenn-long",
		"IPv4/VPNv4 MP Reach, RD, Nexthop, 3 NLRIs, last plen long",
		{
			/* AFI / SAFI */ 0x0, AFI_IP, IANA_SAFI_MPLS_VPN,
			/* nexthop bytes */ 12,
			/* RD */ 0, 0, 0, 0, /* RD defined to be 0 */
			0, 0, 0, 0,
			/* Nexthop */ 192, 168, 0, 1,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 88 + 16, 0, 1, 2, /* tag */
							    /* rd, 8 octets */
			0, 0,				    /* RD_TYPE_AS */
			0, 2, 0, 0xff, 3, 4,		    /* AS(2):val(4) */
			10, 1,				    /* 10.1/16 */
			88 + 17, 0xff, 0, 0,		    /* tag */
							    /* rd, 8 octets */
			0, 0,				    /* RD_TYPE_IP */
			192, 168, 0, 1,			    /* IPv4 */
			10, 2, 3,			    /* 10.2.3/17 */
			88 + 1,				    /* bogus */
		},
		(4 + 12 + 1 + (1 + 3 + 8 + 2) + (1 + 3 + 8 + 3) + 1),
		SHOULD_ERR,
	},
	{
		"IPv4-VPNv4-plenn-short",
		"IPv4/VPNv4 MP Reach, RD, Nexthop, 2 NLRIs, last plen short",
		{
			/* AFI / SAFI */ 0x0, AFI_IP, IANA_SAFI_MPLS_VPN,
			/* nexthop bytes */ 12,
			/* RD */ 0, 0, 0, 0, /* RD defined to be 0 */
			0, 0, 0, 0,
			/* Nexthop */ 192, 168, 0, 1,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 88 + 16, 0, 1, 2, /* tag */
							    /* rd, 8 octets */
			0, 0,				    /* RD_TYPE_AS */
			0, 2, 0, 0xff, 3, 4,		    /* AS(2):val(4) */
			10, 1,				    /* 10.1/16 */
			88 + 2, 0xff, 0, 0,		    /* tag */
							    /* rd, 8 octets */
			0, 0,				    /* RD_TYPE_IP */
			192, 168, 0, 1,			    /* IPv4 */
			10, 2, 3,			    /* 10.2.3/17 */
		},
		(4 + 12 + 1 + (1 + 3 + 8 + 2) + (1 + 3 + 8 + 3)),
		SHOULD_ERR,
	},
	{
		"IPv4-VPNv4-bogus-rd-type",
		"IPv4/VPNv4 MP Reach, RD, NH, 2 NLRI, unknown RD in 1st (log, but parse)",
		{
			/* AFI / SAFI */ 0x0, AFI_IP, IANA_SAFI_MPLS_VPN,
			/* nexthop bytes */ 12,
			/* RD */ 0, 0, 0, 0, /* RD defined to be 0 */
			0, 0, 0, 0,
			/* Nexthop */ 192, 168, 0, 1,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 88 + 16, 0, 1, 2, /* tag */
							    /* rd, 8 octets */
			0xff, 0,			    /* Bogus RD */
			0, 2, 0, 0xff, 3, 4,		    /* AS(2):val(4) */
			10, 1,				    /* 10.1/16 */
			88 + 17, 0xff, 0, 0,		    /* tag */
							    /* rd, 8 octets */
			0, 0,				    /* RD_TYPE_IP */
			192, 168, 0, 1,			    /* IPv4 */
			10, 2, 3,			    /* 10.2.3/17 */
		},
		(4 + 12 + 1 + (1 + 3 + 8 + 2) + (1 + 3 + 8 + 3)),
		SHOULD_PARSE,
	},
	{
		"IPv4-VPNv4-0-nlri",
		"IPv4/VPNv4 MP Reach, RD, Nexthop, 3 NLRI, 3rd 0 bogus",
		{
			/* AFI / SAFI */ 0x0, AFI_IP, IANA_SAFI_MPLS_VPN,
			/* nexthop bytes */ 12,
			/* RD */ 0, 0, 0, 0, /* RD defined to be 0 */
			0, 0, 0, 0,
			/* Nexthop */ 192, 168, 0, 1,
			/* SNPA (defunct, MBZ) */ 0x0,
			/* NLRI tuples */ 88 + 16, 0, 1, 2, /* tag */
							    /* rd, 8 octets */
			0, 0,				    /* RD_TYPE_AS */
			0, 2, 0, 0xff, 3, 4,		    /* AS(2):val(4) */
			10, 1,				    /* 10.1/16 */
			88 + 17, 0xff, 0, 0,		    /* tag */
							    /* rd, 8 octets */
			0, 0,				    /* RD_TYPE_IP */
			192, 168, 0, 1,			    /* IPv4 */
			10, 2, 3,			    /* 10.2.3/17 */
			0 /* 0/0, bogus for vpnv4 ?? */
		},
		(4 + 12 + 1 + (1 + 3 + 8 + 2) + (1 + 3 + 8 + 3) + 1),
		SHOULD_ERR,
	},

	/* From bug #385 */
	{
		"IPv6-bug",
		"IPv6, global nexthop, 1 default NLRI",
		{
			/* AFI / SAFI */ 0x0,
			0x2,
			0x1,
			/* nexthop bytes */ 0x20,
			/* Nexthop (global) */ 0x20,
			0x01,
			0x04,
			0x70,
			0x00,
			0x01,
			0x00,
			0x06,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x01,
			/* Nexthop (local) */ 0xfe,
			0x80,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x00,
			0x02,
			0x0c,
			0xdb,
			0xff,
			0xfe,
			0xfe,
			0xeb,
			0x00,
			/* SNPA (defunct, MBZ) */ 0,
			/* NLRI tuples */ /* Should have 0 here for ::/0, but
					     dont */
		},
		37,
		SHOULD_ERR,
	},
	{
		.name = "IPv4",
		.desc = "IPV4 MP Reach, flowspec, 1 NLRI",
		.data = {
			/* AFI / SAFI */ 0x0,
			AFI_IP,
			IANA_SAFI_FLOWSPEC,
			0x00, /* no NH */
			0x00,
			0x06, /* FS Length */
			0x01, /* FS dest prefix ID */
			0x1e, /* IP */
			0x1e,
			0x28,
			0x28,
			0x0
		},
		.len = 12,
		.parses = SHOULD_PARSE,
	},
	{NULL, NULL, {0}, 0, 0}};

/* MP_UNREACH_NLRI tests */
static struct test_segment mp_unreach_segments[] = {
	{
		"IPv6-unreach",
		"IPV6 MP Unreach, 1 NLRI",
		{
			/* AFI / SAFI */ 0x0, AFI_IP6, SAFI_UNICAST,
			/* NLRI tuples */ 32, 0xff, 0xfe, 0x1,
			0x2, /* fffe:102::/32 */
		},
		(3 + 5),
		SHOULD_PARSE,
	},
	{
		"IPv6-unreach2",
		"IPV6 MP Unreach, 2 NLRIs",
		{
			/* AFI / SAFI */ 0x0, AFI_IP6, SAFI_UNICAST,
			/* NLRI tuples */ 32, 0xff, 0xfe, 0x1,
			0x2,			  /* fffe:102::/32 */
			64, 0xff, 0xfe, 0x0, 0x1, /* fffe:1:2:3::/64 */
			0x0, 0x2, 0x0, 0x3,
		},
		(3 + 5 + 9),
		SHOULD_PARSE,
	},
	{
		"IPv6-unreach-default",
		"IPV6 MP Unreach, 2 NLRIs + default",
		{
			/* AFI / SAFI */ 0x0, AFI_IP6, SAFI_UNICAST,
			/* NLRI tuples */ 32, 0xff, 0xfe, 0x1,
			0x2,			  /* fffe:102::/32 */
			64, 0xff, 0xfe, 0x0, 0x1, /* fffe:1:2:3::/64 */
			0x0, 0x2, 0x0, 0x3, 0x0,  /* ::/0 */
		},
		(3 + 5 + 9 + 1),
		SHOULD_PARSE,
	},
	{
		"IPv6-unreach-nlri",
		"IPV6 MP Unreach, NLRI bitlen overflow",
		{
			/* AFI / SAFI */ 0x0, AFI_IP6, SAFI_UNICAST,
			/* NLRI tuples */ 120, 0xff, 0xfe, 0x1,
			0x2,			  /* fffe:102::/32 */
			64, 0xff, 0xfe, 0x0, 0x1, /* fffe:1:2:3::/64 */
			0x0, 0x2, 0x0, 0x3, 0,    /* ::/0 */
		},
		(3 + 5 + 9 + 1),
		SHOULD_ERR,
	},
	{
		"IPv4-unreach",
		"IPv4 MP Unreach, 2 NLRIs + default",
		{
			/* AFI / SAFI */ 0x0, AFI_IP, SAFI_UNICAST,
			/* NLRI tuples */ 16, 10, 1, /* 10.1/16 */
			17, 10, 2, 3,		     /* 10.2.3/17 */
			0,			     /* 0/0 */
		},
		(3 + 3 + 4 + 1),
		SHOULD_PARSE,
	},
	{
		"IPv4-unreach-nlrilen",
		"IPv4 MP Unreach, nlri length overflow",
		{
			/* AFI / SAFI */ 0x0, AFI_IP, SAFI_UNICAST,
			/* NLRI tuples */ 16, 10, 1, /* 10.1/16 */
			30, 10, 0,		     /* 0/0 */
		},
		(3 + 3 + 2 + 1),
		SHOULD_ERR,
	},
	{
		"IPv4-unreach-VPNv4",
		"IPv4/MPLS-labeled VPN MP Unreach, RD, 3 NLRIs",
		{
			/* AFI / SAFI */ 0x0, AFI_IP, IANA_SAFI_MPLS_VPN,
			/* NLRI tuples */ 88 + 16, 0, 1, 2, /* tag */
							    /* rd, 8 octets */
			0, 0,				    /* RD_TYPE_AS */
			0, 2, 0, 0xff, 3, 4,		    /* AS(2):val(4) */
			10, 1,				    /* 10.1/16 */
			88 + 17, 0xff, 0, 0,		    /* tag */
							    /* rd, 8 octets */
			0, 0,				    /* RD_TYPE_IP */
			192, 168, 0, 1,			    /* IPv4 */
			10, 2, 3,			    /* 10.2.3/17 */
		},
		(3 + (1 + 3 + 8 + 2) + (1 + 3 + 8 + 3)),
		SHOULD_PARSE,
	},
	{
		.name = "IPv4",
		.desc = "IPV4 MP Unreach, flowspec, 1 NLRI",
		.data = {
			/* AFI / SAFI */ 0x0,
			AFI_IP,
			IANA_SAFI_FLOWSPEC,
			0x06, /* FS Length */
			0x01, /* FS dest prefix ID */
			0x1e, /* IP */
			0x1e,
			0x28,
			0x28,
			0x0
		},
		.len = 10,
		.parses = SHOULD_PARSE,
	},
	{NULL, NULL, {0}, 0, 0}};

static struct test_segment mp_prefix_sid[] = {
	{
		"PREFIX-SID",
		"PREFIX-SID Test 1",
		{
			0x01, 0x00, 0x07,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x02,
			0x03, 0x00, 0x08, 0x00,
			0x00, 0x0a, 0x1b, 0xfe,
			0x00, 0x00, 0x0a
		},
		.len = 21,
		.parses = SHOULD_PARSE,
	},
	{NULL, NULL, { 0 }, 0, 0},
};

/* nlri_parse indicates 0 on successful parse, and -1 otherwise.
 * attr_parse indicates BGP_ATTR_PARSE_PROCEED/0 on success,
 * and BGP_ATTR_PARSE_ERROR/-1 or lower negative ret on err.
 */
static void handle_result(struct peer *peer, struct test_segment *t,
			  int parse_ret, int nlri_ret)
{
	int oldfailed = failed;

	printf("mp attr parsed?: %s\n", parse_ret ? "no" : "yes");
	if (!parse_ret)
		printf("nrli parsed?:  %s\n", nlri_ret ? "no" : "yes");
	printf("should parse?:  %s\n", t->parses ? "no" : "yes");

	if ((parse_ret != 0 || nlri_ret != 0) != (t->parses != 0))
		failed++;


	if (tty)
		printf("%s",
		       (failed > oldfailed) ? VT100_RED "failed!" VT100_RESET
					    : VT100_GREEN "OK" VT100_RESET);
	else
		printf("%s", (failed > oldfailed) ? "failed!" : "OK");

	if (failed)
		printf(" (%u)", failed);

	printf("\n\n");
}

/* basic parsing test */
static void parse_test(struct peer *peer, struct test_segment *t, int type)
{
	int parse_ret = 0, nlri_ret = 0;
	struct attr attr = {};
	struct bgp_nlri nlri = {};
	struct bgp_attr_parser_args attr_args = {
		.peer = peer,
		.length = t->len,
		.total = 1,
		.attr = &attr,
		.type = type,
		.flags = BGP_ATTR_FLAG_OPTIONAL,
		.startp = BGP_INPUT_PNT(peer),
	};
#define RANDOM_FUZZ 35
	stream_reset(peer->curr);
	stream_put(peer->curr, NULL, RANDOM_FUZZ);
	stream_set_getp(peer->curr, RANDOM_FUZZ);

	stream_write(peer->curr, t->data, t->len);

	printf("%s: %s\n", t->name, t->desc);

	switch (type) {
	case BGP_ATTR_MP_REACH_NLRI:
		parse_ret = bgp_mp_reach_parse(&attr_args, &nlri);
		break;
	case BGP_ATTR_MP_UNREACH_NLRI:
		parse_ret = bgp_mp_unreach_parse(&attr_args, &nlri);
		break;
	case BGP_ATTR_PREFIX_SID:
		parse_ret = bgp_attr_prefix_sid(t->len, &attr_args, &nlri);
		break;
	default:
		printf("unknown type");
		return;
	}
	if (!parse_ret) {
		iana_afi_t pkt_afi;
		iana_safi_t pkt_safi;

		/* Convert AFI, SAFI to internal values, check. */
		if (bgp_map_afi_safi_int2iana(nlri.afi, nlri.safi, &pkt_afi,
					      &pkt_safi))
			assert(0);

		printf("MP: %u(%u)/%u(%u): recv %u, nego %u\n", nlri.afi,
		       pkt_afi, nlri.safi, pkt_safi,
		       peer->afc_recv[nlri.afi][nlri.safi],
		       peer->afc_nego[nlri.afi][nlri.safi]);
	}

	if (!parse_ret) {
		if (type == BGP_ATTR_MP_REACH_NLRI)
			nlri_ret = bgp_nlri_parse(peer, &attr, &nlri, 0);
		else if (type == BGP_ATTR_MP_UNREACH_NLRI)
			nlri_ret = bgp_nlri_parse(peer, &attr, &nlri, 1);
	}
	handle_result(peer, t, parse_ret, nlri_ret);
}

static struct bgp *bgp;
static as_t asn = 100;

int main(void)
{
	struct interface ifp;
	struct peer *peer;
	int i, j;

	conf_bgp_debug_neighbor_events = -1UL;
	conf_bgp_debug_packet = -1UL;
	conf_bgp_debug_as4 = -1UL;
	conf_bgp_debug_flowspec = -1UL;
	term_bgp_debug_neighbor_events = -1UL;
	term_bgp_debug_packet = -1UL;
	term_bgp_debug_as4 = -1UL;
	term_bgp_debug_flowspec = -1UL;

	qobj_init();
	cmd_init(0);
	bgp_vty_init();
	master = thread_master_create("test mp attr");
	bgp_master_init(master);
	vrf_init(NULL, NULL, NULL, NULL);
	bgp_option_set(BGP_OPT_NO_LISTEN);
	bgp_attr_init();

	if (fileno(stdout) >= 0)
		tty = isatty(fileno(stdout));

	if (bgp_get(&bgp, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT))
		return -1;

	peer = peer_create_accept(bgp);
	peer->host = (char *)"foo";
	peer->status = Established;
	peer->curr = stream_new(BGP_MAX_PACKET_SIZE);

	ifp.ifindex = 0;
	peer->nexthop.ifp = &ifp;

	for (i = AFI_IP; i < AFI_MAX; i++)
		for (j = SAFI_UNICAST; j < SAFI_MAX; j++) {
			peer->afc[i][j] = 1;
			peer->afc_adv[i][j] = 1;
		}

	i = 0;
	while (mp_reach_segments[i].name)
		parse_test(peer, &mp_reach_segments[i++],
			   BGP_ATTR_MP_REACH_NLRI);

	i = 0;
	while (mp_unreach_segments[i].name)
		parse_test(peer, &mp_unreach_segments[i++],
			   BGP_ATTR_MP_UNREACH_NLRI);

	i = 0;
	while (mp_prefix_sid[i].name)
		parse_test(peer, &mp_prefix_sid[i++],
			   BGP_ATTR_PREFIX_SID);
	printf("failures: %d\n", failed);
	return failed;
}
