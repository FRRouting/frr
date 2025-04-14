#ifndef _ZEBRA_MEMPOOL_H
#define _ZEBRA_MEMPOOL_H


/* includes */
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "memory.h"

/* Structures */

/*
 * A block has a management part and a flat memory area between
 * start and end addresses.
 *
 * This area is split into contiguous chunks.
 * A chunk has a header and a data area.
 *
 * Every block has at least 3 chunks:
 * - One empty starting chunk
 * - One empty ending chunk
 * - And at least one chunk (free or used) between the first and last
 */


struct mpblock {
	struct mpblock *next;

	struct mmemptype *bphead; /* Reserved for future use */

	bool blockfull; /* Reserved for future use */

	size_t size;	     /* Reserved for future use */
	size_t totalused;    /* used size in the block only data */
	size_t totalfree;    /* free size in the block for data and headers*/
	size_t totalmgm;     /* Size used by chunk headers */
	size_t totalmaxsize; /* totalused + totalfree + totalmgm */

	uint32_t n_alloc_chunk;
	uint32_t n_free_chunk;

	/*
	 * Doubly-linked list of free chunks
	 * only meaningful for free chunks
	 */
	struct mpchunk *firstfreechunk;
	struct mpchunk *lastfreechunk;

	/* Flat memory area */
	char *start;
	char *end;
};

/*
 * Structure used to manage a memory pool.
 *
 * A memory pool is composed of several blocks.
 * One block is initially allocated and remains for the pool's lifetime.
 * Other blocks are allocated/freed as needed.
 * Blocks contain a flat memory area of default_blk_size bytes.
 * All blocks are referenced in a singly linked list.
 */
struct memptype {
	struct memtype stat;
	size_t totalsize;    /* Reserved for future use */
	size_t totalmaxsize; /* Reserved for future use */

	size_t n_blocks;
	struct mpblock *blocks_list;

	size_t default_block_size;
};


/*
 * Chunks are the basic elements of the memory pool.
 * They are placed contiguously in the flat memory area.
 * Every chunk has a header and a data section.
 *
 * A chunk is either free or used.
 * Chunks are doubly linked using 'size' and 'prev_size'.
 *
 * - chunk + SZ(size) gives the next chunk
 * - chunk - SZ(prev_size) gives the previous chunk
 * - SZ(size) gives the total size of the current chunk
 * - SZ(prev_size) gives the total size of the previous chunk
 *
 * Free chunks are doubly linked via fd and bk fields.
 * These fields are only meaningful for free chunks.
 */

struct mpchunk {
	size_t prev_size; /* Lower 3 bits used as flags */
	size_t size;	  /* Lower 3 bits used as flags */
	/*
	 * Double linked list (only for free chunks)
	 */
	struct mpchunk *fd;
	struct mpchunk *bk;

	/* Data area (size - sizeof(mpchunk) bytes) */
};


/* external functions */


extern void mpfree(struct memptype *mt, void *ptr);
extern void *mpalloc(struct memptype *mt, size_t size);
extern struct memptype *mphead_create(size_t default_size);
extern void mphead_delete(struct memptype **mt);
extern uint32_t mp_nb_blocks(struct memptype *mt);


#endif /* _ZEBRA_MEMPOOL_H */
