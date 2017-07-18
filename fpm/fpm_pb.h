/*
 * fpm_pb.h
 *
 * @copyright Copyright (C) 2016 Sproute Networks, Inc.
 *
 * @author Avneesh Sachdev <avneesh@sproute.com>
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * Public header file for fpm protobuf definitions.
 */

#ifndef _FPM_PB_H
#define _FPM_PB_H

#include "route_types.h"
#include "qpb/qpb.h"

#include "fpm/fpm.pb-c.h"

/*
 * fpm__route_key__create
 */
#define fpm_route_key_create fpm__route_key__create
static inline Fpm__RouteKey *fpm__route_key__create(qpb_allocator_t *allocator,
						    struct prefix *prefix)
{
	Fpm__RouteKey *key;

	key = QPB_ALLOC(allocator, typeof(*key));
	if (!key) {
		return NULL;
	}
	fpm__route_key__init(key);

	key->prefix = qpb__l3_prefix__create(allocator, prefix);
	if (!key->prefix) {
		return NULL;
	}

	return key;
}

#endif
