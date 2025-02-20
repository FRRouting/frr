// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Nexthop Group Support
 * Copyright (C) 2023 NVIDIA Corporation
 * Copyright (C) 2023 6WIND
 */

#ifndef _BGP_NHG_H
#define _BGP_NHG_H

#include "nexthop_group.h"

/* APIs for setting up and allocating L3 nexthop group ids */
extern uint32_t bgp_nhg_id_alloc(void);
extern void bgp_nhg_id_free(uint32_t nhg_id);
extern void bgp_nhg_init(void);
void bgp_nhg_finish(void);

#endif /* _BGP_NHG_H */
