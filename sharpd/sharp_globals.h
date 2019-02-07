/*
 * SHARP - code to track globals
 * Copyright (C) 2019 Cumulus Networks, Inc.
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
#ifndef __SHARP_GLOBAL_H__
#define __SHARP_GLOBAL_H__

DECLARE_MGROUP(SHARPD)

struct sharp_routes {
	/* The original prefix for route installation */
	struct prefix orig_prefix;

	/* The nexthop group we are using for installation */
	struct nexthop nhop;
	struct nexthop_group nhop_group;

	uint32_t total_routes;
	uint32_t installed_routes;
	uint32_t removed_routes;
	int32_t repeat;

	uint8_t inst;

	struct timeval t_start;
	struct timeval t_end;
};

struct sharp_global {
	/* Global data about route install/deletions */
	struct sharp_routes r;

	/* The list of nexthops that we are watching and data about them */
	struct list *nhs;
};

extern struct sharp_global sg;
#endif
