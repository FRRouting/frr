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

#endif /* _FRR_BGP_FLOWSPEC_PRIVATE_H */
