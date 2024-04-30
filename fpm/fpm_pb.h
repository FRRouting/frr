// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * fpm_pb.h
 *
 * @copyright Copyright (C) 2016 Sproute Networks, Inc.
 *
 * @author Avneesh Sachdev <avneesh@sproute.com>
 */

/*
 * Public header file for fpm protobuf definitions.
 */

#ifndef _FPM_PB_H
#define _FPM_PB_H

#include "lib/route_types.h"
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
