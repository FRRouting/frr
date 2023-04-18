// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Nexthop Group Private Functions.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Stephen Worley
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
