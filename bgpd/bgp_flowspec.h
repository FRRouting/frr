/* BGP Flowspec header for packet handling
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

#ifndef _FRR_BGP_FLOWSPEC_H
#define _FRR_BGP_FLOWSPEC_H

extern int bgp_nlri_parse_flowspec(struct peer *peer, struct attr *attr,
				   struct bgp_nlri *packet, int withdraw);

extern void bgp_flowspec_vty_init(void);

#endif /* _FRR_BGP_FLOWSPEC_H */
