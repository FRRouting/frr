// SPDX-License-Identifier: GPL-2.0-or-later
/* Bitfields
 * Copyright (C) 2016 Cumulus Networks, Inc.
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

DECLARE_MTYPE(BITFIELD);

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
		(v).data = (word_t *)XCALLOC(MTYPE_BITFIELD,                   \
					     ((v).m * sizeof(word_t)));        \
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
			(v).data = XREALLOC(MTYPE_BITFIELD, (v).data,          \
					    (v).m * sizeof(word_t));           \
			(v).data[(v).m - 1] = 0;                               \
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

/*
 * Find a clear bit in v and return it
 * Start looking in the word containing bit position start_index.
 * If necessary, wrap around after bit position max_index.
 */
static inline unsigned int
bf_find_next_clear_bit_wrap(bitfield_t *v, word_t start_index, word_t max_index)
{
	int start_bit;
	unsigned long i, offset, scanbits, wordcount_max, index_max;

	if (start_index > max_index)
		start_index = 0;

	start_bit = start_index & (WORD_SIZE - 1);
	wordcount_max = bf_index(max_index) + 1;

	scanbits = WORD_SIZE;
	for (i = bf_index(start_index); i < v->m; ++i) {
		if (v->data[i] == WORD_MAX) {
			/* if the whole word is full move to the next */
			start_bit = 0;
			continue;
		}
		/* scan one word for clear bits */
		if ((i == v->m - 1) && (v->m >= wordcount_max))
			/* max index could be only part of word */
			scanbits = (max_index % WORD_SIZE) + 1;
		for (offset = start_bit; offset < scanbits; ++offset) {
			if (!((v->data[i] >> offset) & 1))
				return ((i * WORD_SIZE) + offset);
		}
		/* move to the next word */
		start_bit = 0;
	}

	if (v->m < wordcount_max) {
		/*
		 * We can expand bitfield, so no need to wrap.
		 * Return the index of the first bit of the next word.
		 * Assumption is that caller will call bf_set_bit which
		 * will allocate additional space.
		 */
		v->m += 1;
		v->data = (word_t *)XREALLOC(MTYPE_BITFIELD, v->data,
					     v->m * sizeof(word_t));
		v->data[v->m - 1] = 0;
		return v->m * WORD_SIZE;
	}

	/*
	 * start looking for a clear bit at the start of the bitfield and
	 * stop when we reach start_index
	 */
	scanbits = WORD_SIZE;
	index_max = bf_index(start_index - 1);
	for (i = 0; i <= index_max; ++i) {
		if (i == index_max)
			scanbits = ((start_index - 1) % WORD_SIZE) + 1;
		for (offset = start_bit; offset < scanbits; ++offset) {
			if (!((v->data[i] >> offset) & 1))
				return ((i * WORD_SIZE) + offset);
		}
		/* move to the next word */
		start_bit = 0;
	}

	return WORD_MAX;
}

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
		XFREE(MTYPE_BITFIELD, (v).data);                               \
		(v).data = NULL;                                               \
	} while (0)

static inline bitfield_t bf_copy(bitfield_t src)
{
	bitfield_t dst;

	assert(bf_is_inited(src));
	bf_init(dst, WORD_SIZE * (src.m - 1));
	for (size_t i = 0; i < src.m; i++)
		dst.data[i] = src.data[i];
	dst.n = src.n;
	return dst;
}


#ifdef __cplusplus
}
#endif

#endif
