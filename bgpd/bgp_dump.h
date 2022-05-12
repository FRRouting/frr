/* BGP dump routine.
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

#ifndef _QUAGGA_BGP_DUMP_H
#define _QUAGGA_BGP_DUMP_H

/* MRT compatible packet dump values.  */
/* type value */
#define MSG_PROTOCOL_BGP4MP    16
#define MSG_PROTOCOL_BGP4MP_ET 17

/* subtype value */
#define BGP4MP_STATE_CHANGE 0
#define BGP4MP_MESSAGE 1
#define BGP4MP_ENTRY 2
#define BGP4MP_SNAPSHOT 3
#define BGP4MP_MESSAGE_AS4 4
#define BGP4MP_STATE_CHANGE_AS4 5
#define BGP4MP_MESSAGE_ADDPATH 8
#define BGP4MP_MESSAGE_AS4_ADDPATH 9
#define BGP4MP_MESSAGE_LOCAL_ADDPATH 10
#define BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH 11

#define BGP_DUMP_HEADER_SIZE 12
#define BGP_DUMP_MSG_HEADER  40

#define TABLE_DUMP_V2_PEER_INDEX_TABLE 1
#define TABLE_DUMP_V2_RIB_IPV4_UNICAST 2
#define TABLE_DUMP_V2_RIB_IPV4_MULTICAST 3
#define TABLE_DUMP_V2_RIB_IPV6_UNICAST 4
#define TABLE_DUMP_V2_RIB_IPV6_MULTICAST 5
#define TABLE_DUMP_V2_RIB_IPV4_UNICAST_ADDPATH 8
#define TABLE_DUMP_V2_RIB_IPV4_MULTICAST_ADDPATH 9
#define TABLE_DUMP_V2_RIB_IPV6_UNICAST_ADDPATH 10
#define TABLE_DUMP_V2_RIB_IPV6_MULTICAST_ADDPATH 11
#define TABLE_DUMP_V2_RIB_GENERIC_ADDPATH 12

#define TABLE_DUMP_V2_PEER_INDEX_TABLE_IP  0
#define TABLE_DUMP_V2_PEER_INDEX_TABLE_IP6 1
#define TABLE_DUMP_V2_PEER_INDEX_TABLE_AS2 0
#define TABLE_DUMP_V2_PEER_INDEX_TABLE_AS4 2

extern void bgp_dump_init(void);
extern void bgp_dump_finish(void);
extern int bgp_dump_state(struct peer *peer);

#endif /* _QUAGGA_BGP_DUMP_H */
