/* BGP open message handling
 * Copyright (C) 1999 Kunihiro Ishiguro
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

#ifndef _QUAGGA_BGP_OPEN_H
#define _QUAGGA_BGP_OPEN_H

/* Standard header for capability TLV */
struct capability_header {
	uint8_t code;
	uint8_t length;
};

/* Generic MP capability data */
struct capability_mp_data {
	uint16_t afi; /* iana_afi_t */
	uint8_t reserved;
	uint8_t safi; /* iana_safi_t */
};

struct capability_as4 {
	uint32_t as4;
};

struct graceful_restart_af {
	afi_t afi;
	safi_t safi;
	uint8_t flag;
};

struct capability_gr {
	uint16_t restart_flag_time;
	struct graceful_restart_af gr[];
};

/* Capability Code */
#define CAPABILITY_CODE_MP              1 /* Multiprotocol Extensions */
#define CAPABILITY_CODE_REFRESH         2 /* Route Refresh Capability */
#define CAPABILITY_CODE_ORF             3 /* Cooperative Route Filtering Capability */
#define CAPABILITY_CODE_RESTART        64 /* Graceful Restart Capability */
#define CAPABILITY_CODE_AS4            65 /* 4-octet AS number Capability */
#define CAPABILITY_CODE_DYNAMIC_OLD    66 /* Dynamic Capability, deprecated since 2003 */
#define CAPABILITY_CODE_DYNAMIC        67 /* Dynamic Capability */
#define CAPABILITY_CODE_ADDPATH        69 /* Addpath Capability */
#define CAPABILITY_CODE_FQDN           73 /* Advertise hostname capabilty */
#define CAPABILITY_CODE_ENHE            5 /* Extended Next Hop Encoding */
#define CAPABILITY_CODE_REFRESH_OLD   128 /* Route Refresh Capability(cisco) */
#define CAPABILITY_CODE_ORF_OLD       130 /* Cooperative Route Filtering Capability(cisco) */

/* Capability Length */
#define CAPABILITY_CODE_MP_LEN          4
#define CAPABILITY_CODE_REFRESH_LEN     0
#define CAPABILITY_CODE_DYNAMIC_LEN     0
#define CAPABILITY_CODE_RESTART_LEN     2 /* Receiving only case */
#define CAPABILITY_CODE_AS4_LEN         4
#define CAPABILITY_CODE_ADDPATH_LEN     4
#define CAPABILITY_CODE_ENHE_LEN        6 /* NRLI AFI = 2, SAFI = 2, Nexthop AFI = 2 */
#define CAPABILITY_CODE_MIN_FQDN_LEN    2
#define CAPABILITY_CODE_ORF_LEN         5

/* Cooperative Route Filtering Capability.  */

/* ORF Type */
#define ORF_TYPE_PREFIX                64 
#define ORF_TYPE_PREFIX_OLD           128

/* ORF Mode */
#define ORF_MODE_RECEIVE                1 
#define ORF_MODE_SEND                   2 
#define ORF_MODE_BOTH                   3 

/* Capability Message Action.  */
#define CAPABILITY_ACTION_SET           0
#define CAPABILITY_ACTION_UNSET         1

/* Graceful Restart */
#define RESTART_R_BIT              0x8000
#define RESTART_F_BIT              0x80

extern int bgp_open_option_parse(struct peer *, uint8_t, int *);
extern void bgp_open_capability(struct stream *, struct peer *);
extern void bgp_capability_vty_out(struct vty *, struct peer *, uint8_t,
				   json_object *);
extern as_t peek_for_as4_capability(struct peer *, uint8_t);

#endif /* _QUAGGA_BGP_OPEN_H */
