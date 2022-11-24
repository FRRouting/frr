/* BGP Tracker
 *
 * Copyright 2022 6WIND S.A.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef BGPD_BGP_TRACKER_H_
#define BGPD_BGP_TRACKER_H_

struct tracker *bgp_tracker_get(char *name);
void bgp_tracker_set(char *name, bool status);
struct tracker *bgp_tracker_new(char *name);
void bgp_tracker_free(char *name);
void bgp_tracker_terminate(void);
void bgp_tracker_init(void);

#endif /* BGPD_BGP_TRACKER_H_ */
