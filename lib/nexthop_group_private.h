/*
 * Nexthop Group Private Functions.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Stephen Worley
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

/**
 * These functions should only be used internally for nexthop groups
 * and in certain special cases. Please use `lib/nexthop_group.h` for
 * any general nexthop_group api needs.
 */

#ifndef __NEXTHOP_GROUP_PRIVATE__
#define __NEXTHOP_GROUP_PRIVATE__

#include <nexthop_group.h>

#ifdef __cplusplus
extern "C" {
#endif

void _nexthop_add(struct nexthop **target, struct nexthop *nexthop);
void _nexthop_del(struct nexthop_group *nhg, struct nexthop *nexthop);

#ifdef __cplusplus
}
#endif

#endif /* __NEXTHOP_GROUP_PRIVATE__ */
