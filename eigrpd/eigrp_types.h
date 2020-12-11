/*
 * EIGRP Definition of Data Types
 * Copyright (C) 2018
 * Authors:
 *   Donnie Savage
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

#ifndef _ZEBRA_EIGRP_TYPES_H_
#define _ZEBRA_EIGRP_TYPES_H_

typedef uint64_t eigrp_bandwidth_t;
typedef uint64_t eigrp_delay_t;
typedef uint64_t eigrp_metric_t;
typedef uint32_t eigrp_scaled_t;

typedef uint32_t eigrp_system_metric_t;
typedef uint32_t eigrp_system_delay_t;
typedef uint32_t eigrp_system_bandwidth_t;

#endif /* _ZEBRA_EIGRP_TYPES_H_ */
