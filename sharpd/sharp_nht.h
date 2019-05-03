/*
 * SHARP - code to track nexthops
 * Copyright (C) Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __SHARP_NHT_H__
#define __SHARP_NHT_H__

struct sharp_nh_tracker {
	/* What are we watching */
	struct prefix p;

	/* Number of valid nexthops */
	uint32_t nhop_num;

	uint32_t updates;
};

extern struct sharp_nh_tracker *sharp_nh_tracker_get(struct prefix *p);

extern void sharp_nh_tracker_dump(struct vty *vty);
#endif
