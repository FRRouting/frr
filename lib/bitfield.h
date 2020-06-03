/* Bitfields
 * Copyright (C) 2016 Cumulus Networks, Inc.
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
/**
 * A simple bit array implementation to allocate and free IDs. An example
 * of its usage is in allocating link state IDs for OSPFv3 as OSPFv3 has
 * removed all address semantics from LS ID. Another usage can be in
 * allocating IDs for BGP neighbors (and dynamic update groups) for
 * efficient storage of adj-rib-out.
 *
 * An example:
 * #include "bitfield.h"
 *
 * bitfield_t bitfield;
 *
 * bf_init(bitfield, 32);
 * ...
 * bf_assign_index(bitfield, id1);
 * bf_assign_index(bitfield, id2);
 * ...
 * bf_release_index(bitfield, id1);
 */

#ifndef _BITFIELD_H
#define _BITFIELD_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int word_t;
#define WORD_MAX 0xFFFFFFFF
#define WORD_SIZE (sizeof(word_t) * 8)

/**
 * The bitfield structure.
 * @data: the bits to manage.
 * @n: The current word number that is being used.
 * @m: total number of words in 'data'
 */
typedef struct {word_t *data; size_t n, m; } bitfield_t;

/**
 * Initialize the bits.
 * @v: an instance of bitfield_t struct.
 * @N: number of bits to start with, which equates to how many
 *     IDs can be allocated.
 */
#define bf_init(v, N)                                                          \
	do {                                                                   \
		(v).n = 0;                                                     \
		(v).m = ((N) / WORD_SIZE + 1);                                 \
		(v).data = calloc(1, ((v).m * sizeof(word_t)));                \
	} while (0)

/**
 * allocate and assign an id from bitfield v.
 */
#define bf_assign_index(v, id)                                                 \
	do {                                                                   \
		bf_find_bit(v, id);                                            \
		bf_set_bit(v, id);                                             \
	} while (0)

/*
 * allocate and assign 0th bit in the bitfiled.
 */
#define bf_assign_zero_index(v)                                                \
	do {                                                                   \
		int id = 0;                                                    \
		bf_assign_index(v, id);                                        \
	} while (0)

/*
 * return an id to bitfield v
 */
#define bf_release_index(v, id)                                                \
	(v).data[bf_index(id)] &= ~(1 << (bf_offset(id)))

/* check if an id is in use */
#define bf_test_index(v, id)                                                \
	((v).data[bf_index(id)] & (1 << (bf_offset(id))))

/* check if the bit field has been setup */
#define bf_is_inited(v) ((v).data)

/* compare two bitmaps of the same length */
#define bf_cmp(v1, v2) (memcmp((v1).data, (v2).data, ((v1).m * sizeof(word_t))))

/*
 * return 0th index back to bitfield
 */
#define bf_release_zero_index(v) bf_release_index(v, 0)

#define bf_index(b) ((b) / WORD_SIZE)
#define bf_offset(b) ((b) % WORD_SIZE)

/**
 * Set a bit in the array. If it fills up that word and we are
 * out of words, extend it by one more word.
 */
#define bf_set_bit(v, b)                                                       \
	do {                                                                   \
		size_t w = bf_index(b);                                        \
		(v).data[w] |= 1 << (bf_offset(b));                            \
		(v).n += ((v).data[w] == WORD_MAX);                            \
		if ((v).n == (v).m) {                                          \
			(v).m = (v).m + 1;                                     \
			(v).data = realloc((v).data, (v).m * sizeof(word_t));  \
		}                                                              \
	} while (0)

/* Find a clear bit in v and assign it to b. */
#define bf_find_bit(v, b)                                                      \
	do {                                                                   \
		word_t word = 0;                                               \
		unsigned int w, sh;                                            \
		for (w = 0; w <= (v).n; w++) {                                 \
			if ((word = (v).data[w]) != WORD_MAX)                  \
				break;                                         \
		}                                                              \
		(b) = ((word & 0xFFFF) == 0xFFFF) << 4;                        \
		word >>= (b);                                                  \
		sh = ((word & 0xFF) == 0xFF) << 3;                             \
		word >>= sh;                                                   \
		(b) |= sh;                                                     \
		sh = ((word & 0xF) == 0xF) << 2;                               \
		word >>= sh;                                                   \
		(b) |= sh;                                                     \
		sh = ((word & 0x3) == 0x3) << 1;                               \
		word >>= sh;                                                   \
		(b) |= sh;                                                     \
		sh = ((word & 0x1) == 0x1) << 0;                               \
		word >>= sh;                                                   \
		(b) |= sh;                                                     \
		(b) += (w * WORD_SIZE);                                        \
	} while (0)

static inline unsigned int bf_find_next_set_bit(bitfield_t v,
		word_t start_index)
{
	int start_bit;
	unsigned long i, offset;

	start_bit = start_index & (WORD_SIZE - 1);

	for (i = bf_index(start_index); i < v.m; ++i) {
		if (v.data[i] == 0) {
			/* if the whole word is empty move to the next */
			start_bit = 0;
			continue;
		}
		/* scan one word for set bits */
		for (offset = start_bit; offset < WORD_SIZE; ++offset) {
			if ((v.data[i] >> offset) & 1)
				return ((i * WORD_SIZE) + offset);
		}
		/* move to the next word */
		start_bit = 0;
	}
	return WORD_MAX;
}

/* iterate through all the set bits */
#define bf_for_each_set_bit(v, b, max)                 \
	for ((b) = bf_find_next_set_bit((v), 0);           \
			(b) < max;                                 \
			(b) = bf_find_next_set_bit((v), (b) + 1))

/*
 * Free the allocated memory for data
 * @v: an instance of bitfield_t struct.
 */
#define bf_free(v)                                                             \
	do {                                                                   \
		free((v).data);                                                \
		(v).data = NULL;                                               \
	} while (0)

#ifdef __cplusplus
}
#endif

#endif
