// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * qpb_allocator.c
 *
 * @copyright Copyright (C) 2016 Sproute Networks, Inc.
 *
 * @author Avneesh Sachdev <avneesh@sproute.com>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "linear_allocator.h"

#include "qpb_allocator.h"

/*
 * _qpb_alloc
 */
static void *_qpb_alloc(void *allocator_data, size_t size)
{
	return linear_allocator_alloc(allocator_data, size);
}

/*
 * _qpb_free
 */
static void _qpb_free(void *allocator_data, void *ptr)
{
	linear_allocator_free(allocator_data, ptr);
}

static ProtobufCAllocator allocator_template = {_qpb_alloc, _qpb_free, NULL};

/*
 * qpb_allocator_init_linear
 *
 * Initialize qpb_allocator_t with the given linear allocator.
 */
void qpb_allocator_init_linear(qpb_allocator_t *allocator,
			       linear_allocator_t *linear_allocator)
{
	*allocator = allocator_template;
	allocator->allocator_data = linear_allocator;
}
