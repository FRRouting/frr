/*
 * Zebra affinity-map header
 *
 * Copyright 2022 6WIND S.A.
 *
 * This file is part of Free Range Routing (FRR).
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

#ifndef __ZEBRA_AFFINITYMAP_H__
#define __ZEBRA_AFFINITYMAP_H__

#include "lib/affinitymap.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void zebra_affinity_map_init(void);

#ifdef __cplusplus
}
#endif

#endif
