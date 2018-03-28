/* jhash.h: Jenkins hash support.
 *
 * Copyright (C) 1996 Bob Jenkins (bob_jenkins@burtleburtle.net)
 *
 * http://burtleburtle.net/bob/hash/
 *
 * These are the credits from Bob's sources:
 *
 * lookup2.c, by Bob Jenkins, December 1996, Public Domain.
 * hash(), hash2(), hash3, and mix() are externally useful functions.
 * Routines to test the hash are included if SELF_TEST is defined.
 * You can use this free for any purpose.  It has no warranty.
 *
 * Copyright (C) 2003 David S. Miller (davem@redhat.com)
 *
 * I've modified Bob's hash to be useful in the Linux kernel, and
 * any bugs present are surely my fault.  -DaveM
 */

#ifndef _QUAGGA_JHASH_H
#define _QUAGGA_JHASH_H

/* The most generic version, hashes an arbitrary sequence
 * of bytes.  No alignment or length assumptions are made about
 * the input key.
 */
extern uint32_t jhash(const void *key, uint32_t length, uint32_t initval);

/* A special optimized version that handles 1 or more of uint32_ts.
 * The length parameter here is the number of uint32_ts in the key.
 */
extern uint32_t jhash2(const uint32_t *k, uint32_t length, uint32_t initval);

/* A special ultra-optimized versions that knows they are hashing exactly
 * 3, 2 or 1 word(s).
 *
 * NOTE: In partilar the "c += length; __jhash_mix(a,b,c);" normally
 *       done at the end is not done here.
 */
extern uint32_t jhash_3words(uint32_t a, uint32_t b, uint32_t c,
			     uint32_t initval);
extern uint32_t jhash_2words(uint32_t a, uint32_t b, uint32_t initval);
extern uint32_t jhash_1word(uint32_t a, uint32_t initval);

#endif /* _QUAGGA_JHASH_H */
