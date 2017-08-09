/*
 * Defines and structures common to OSPFv2 and OSPFv3
 * Copyright (C) 1998, 99, 2000 Kunihiro Ishiguro, Toshiaki Takada
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

#ifndef _LIBOSPFD_H
#define _LIBOSPFD_H

/* IP precedence. */
#ifndef IPTOS_PREC_INTERNETCONTROL
#define IPTOS_PREC_INTERNETCONTROL	0xC0
#endif /* IPTOS_PREC_INTERNETCONTROL */

/* Default protocol, port number. */
#ifndef IPPROTO_OSPFIGP
#define IPPROTO_OSPFIGP         89
#endif /* IPPROTO_OSPFIGP */

/* Architectual Constants */
#ifdef DEBUG
#define OSPF_LS_REFRESH_TIME                   120
#else
#define OSPF_LS_REFRESH_TIME                  1800
#endif
#define OSPF_MIN_LS_INTERVAL                  5000     /* msec */
#define OSPF_MIN_LS_ARRIVAL                   1000     /* in milliseconds */
#define OSPF_LSA_INITIAL_AGE                     0	/* useful for debug */
#define OSPF_LSA_MAXAGE                       3600
#define OSPF_CHECK_AGE                         300
#define OSPF_LSA_MAXAGE_DIFF                   900
#define OSPF_LS_INFINITY                  0xffffff
#define OSPF_DEFAULT_DESTINATION        0x00000000      /* 0.0.0.0 */
#define OSPF_INITIAL_SEQUENCE_NUMBER    0x80000001U
#define OSPF_MAX_SEQUENCE_NUMBER        0x7fffffffU

/* OSPF Interface Types */
#define OSPF_IFTYPE_NONE		0
#define OSPF_IFTYPE_POINTOPOINT		1
#define OSPF_IFTYPE_BROADCAST		2
#define OSPF_IFTYPE_NBMA		3
#define OSPF_IFTYPE_POINTOMULTIPOINT	4
#define OSPF_IFTYPE_VIRTUALLINK		5
#define OSPF_IFTYPE_LOOPBACK            6
#define OSPF_IFTYPE_MAX			7

/* OSPF interface default values. */
#define OSPF_OUTPUT_COST_DEFAULT           10
#define OSPF_OUTPUT_COST_INFINITE	   UINT16_MAX
#define OSPF_ROUTER_DEAD_INTERVAL_DEFAULT  40
#define OSPF_ROUTER_DEAD_INTERVAL_MINIMAL   1
#define OSPF_HELLO_INTERVAL_DEFAULT        10
#define OSPF_ROUTER_PRIORITY_DEFAULT        1
#define OSPF_RETRANSMIT_INTERVAL_DEFAULT    5
#define OSPF_TRANSMIT_DELAY_DEFAULT         1
#define OSPF_DEFAULT_BANDWIDTH		 10000	/* Mbps */

#define OSPF_DEFAULT_REF_BANDWIDTH	100000  /* Mbps */

#define OSPF_POLL_INTERVAL_DEFAULT         60
#define OSPF_NEIGHBOR_PRIORITY_DEFAULT      0

#define OSPF_MTU_IGNORE_DEFAULT             0
#define OSPF_FAST_HELLO_DEFAULT             0

#define OSPF_AREA_BACKBONE              0x00000000      /* 0.0.0.0 */
#define OSPF_AREA_RANGE_COST_UNSPEC	-1U

#define OSPF_AREA_DEFAULT       0
#define OSPF_AREA_STUB          1
#define OSPF_AREA_NSSA          2
#define OSPF_AREA_TYPE_MAX	3

/* SPF Throttling timer values. */
#define OSPF_SPF_DELAY_DEFAULT              0
#define OSPF_SPF_HOLDTIME_DEFAULT           50
#define OSPF_SPF_MAX_HOLDTIME_DEFAULT	    5000

#define OSPF_LSA_MAXAGE_CHECK_INTERVAL		30
#define OSPF_LSA_MAXAGE_REMOVE_DELAY_DEFAULT	60

#endif /* _LIBOSPFD_H */
