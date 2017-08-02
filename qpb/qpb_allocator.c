/*
 * qpb_allocator.c
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
