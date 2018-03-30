/* BGP Flowspec header . private structs and defines
 * Copyright (C) 2018 6WIND
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_BGP_FLOWSPEC_PRIVATE_H
#define _FRR_BGP_FLOWSPEC_PRIVATE_H

#define FLOWSPEC_NLRI_SIZELIMIT			240

/* Flowspec raffic action bit*/
#define FLOWSPEC_TRAFFIC_ACTION_TERMINAL	1
#define FLOWSPEC_TRAFFIC_ACTION_SAMPLE		0
#define FLOWSPEC_TRAFFIC_ACTION_DISTRIBUTE	1

/* Flow Spec Component Types */
#define NUM_OF_FLOWSPEC_MATCH_TYPES		12
#define FLOWSPEC_DEST_PREFIX		1
#define FLOWSPEC_SRC_PREFIX		2
#define FLOWSPEC_IP_PROTOCOL		3
#define FLOWSPEC_PORT			4
#define FLOWSPEC_DEST_PORT		5
#define FLOWSPEC_SRC_PORT		6
#define FLOWSPEC_ICMP_TYPE		7
#define FLOWSPEC_ICMP_CODE		8
#define FLOWSPEC_TCP_FLAGS		9
#define FLOWSPEC_PKT_LEN		10
#define FLOWSPEC_DSCP			11
#define FLOWSPEC_FRAGMENT		12

#endif /* _FRR_BGP_FLOWSPEC_PRIVATE_H */
