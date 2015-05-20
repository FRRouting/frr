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

typedef unsigned int word_t;
#define WORD_MAX 0xFFFFFFFF
#define WORD_SIZE (sizeof(word_t) * 8)

/**
 * The bitfield structure.
 * @data: the bits to manage.
 * @n: The current word number that is being used.
 * @m: total number of words in 'data'
 */
#define bitfield_t struct { word_t *data; size_t n, m; }

/**
 * Initialize the bits.
 * @v: an instance of bitfield_t struct.
 * @N: number of bits to start with, which equates to how many
 *     IDs can be allocated.
 */
#define bf_init(v, N)				    \
  do {						    \
    (v).n = 0;					    \
    (v).m = ((N) / WORD_SIZE + 1);		    \
    (v).data = calloc(1, ((v).m * sizeof(word_t))); \
  } while (0)

/**
 * allocate and assign an id from bitfield v.
 */
#define bf_assign_index(v, id)				\
  do {							\
    bf_find_bit(v, id);					\
    bf_set_bit(v, id);					\
  } while (0)

/**
 * return an id to bitfield v
 */
#define bf_release_index(v, id)			\
  (v).data[bf_index(id)] &= ~(1 << (bf_offset(id)))

#define bf_index(b) ((b) / WORD_SIZE)
#define bf_offset(b) ((b) % WORD_SIZE)

/**
 * Set a bit in the array. If it fills up that word and we are
 * out of words, extend it by one more word.
 */
#define bf_set_bit(v, b)					\
  do {								\
    size_t w = bf_index(b);					\
    (v).data[w] |= 1 << (bf_offset(b));				\
    (v).n += ((v).data[w] == WORD_MAX);				\
    if ((v).n == (v).m) {					\
      (v).m = (v).m + 1;					\
      (v).data = realloc((v).data, (v).m * sizeof(word_t));	\
    }								\
  } while (0)

/* Find a clear bit in v and assign it to b. */
#define bf_find_bit(v, b)					\
  do {								\
    word_t word;						\
    unsigned int w, sh;						\
    for (w = 0; w <= (v).n; w++) {				\
      if ((word = (v).data[w]) != WORD_MAX) break;		\
    }								\
    (b) = ((word & 0xFFFF) == 0xFFFF) << 4; word >>= (b);	\
    sh = ((word & 0xFF) == 0xFF) << 3; word >>= sh; (b) |= sh;	\
    sh = ((word & 0xF) == 0xF) << 2; word >>= sh; (b) |= sh;	\
    sh = ((word & 0x3) == 0x3) << 1; word >>= sh; (b) |= sh;	\
    sh = ((word & 0x1) == 0x1) << 0; word >>= sh; (b) |= sh;	\
    (b) += (w * WORD_SIZE);					\
  } while (0)

#endif
