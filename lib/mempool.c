#include <zebra.h>
#include "mempool.h"

/*  Internal Chunk Status Flags */
#define CUR_IN_USE  0x000000002 /* Current chunk is in use */
#define PREV_IN_USE 0x000000001 /* Previous chunk is in use */

/* Alignment and Size Macros */
#define ALIGN 3				/* Alignment shift (8-byte alignment) */
#define SZ(x) (((x) >> ALIGN) << ALIGN) /* Truncate to aligned size */

/* Chunk Status Setters */
#define SET_CUR_INUSE(a)  ((a)->size |= CUR_IN_USE)
#define SET_CUR_FREE(a)	  ((a)->size &= ~CUR_IN_USE)
#define SET_PREV_INUSE(a) ((a)->prev_size |= PREV_IN_USE)
#define SET_PREV_FREE(a)  ((a)->prev_size &= ~PREV_IN_USE)

/* Chunk Status Checkers */
#define IS_IN_USE(a)	  (((a)->size & CUR_IN_USE) == CUR_IN_USE)
#define IS_FREE(a)	  (((a)->size & CUR_IN_USE) == 0)
#define IS_PREV_IN_USE(a) ((a)->prev_size & PREV_IN_USE)
#define IS_PREV_FREE(a)	  (((a)->prev_size) & PREV_IN_USE) == 0)

/* Chunk Metadata Access */
#define PREV_CHUNK(a) ((struct mpchunk *)((char *)(a)-SZ((a)->prev_size)))
#define NEXT_CHUNK(a) ((struct mpchunk *)((char *)(a) + SZ((a)->size)))
#define SIZE(a)	      SZ((a)->size)
#define PREV_SIZE(a)  SZ((a)->prev_size)

#define CHUNK_HDR_SIZE sizeof(struct mpchunk)

/* Chunk Validity */
#define IS_CHUNK_VALID(a)                                                                          \
	((SIZE(a) == PREV_SIZE(NEXT_CHUNK(a))) && (PREV_SIZE(a) == SIZE(PREV_CHUNK(a))))

/* Block Utility Macros */
#define IS_FULL(b)	  ((b)->blockfull)
#define IS_IN_BLOCK(a, b) (((b)->start <= (char *)(a)) && ((char *)(a) <= (b)->end))


/* Internal Use Macro */


/*external vars */

/* Internal vars */
extern struct memgroup **mg_insert;

struct memgroup mem_pool_grp = {
	.name = "mempool",
	.types = NULL,
	.next = NULL,
	.insert = NULL,
	.ref = NULL
};


/*
 * get real size used for ptr (inlude chunk)
 * only valid for a in use pointer
 */
static inline size_t mpalloc_usable_size(void *ptr)
{
	struct mpchunk *chunk;

	chunk = (struct mpchunk *)(((char *)ptr) - CHUNK_HDR_SIZE);

	return SZ(chunk->size);
}


static inline void mt_count_alloc(struct memtype *mt, size_t size, void *ptr)
{
	size_t current;
	size_t oldsize;

	current = 1 + atomic_fetch_add_explicit(&mt->n_alloc, 1,
						memory_order_relaxed);

	oldsize = atomic_load_explicit(&mt->n_max, memory_order_relaxed);
	if (current > oldsize)
		/* note that this may fail, but approximation is sufficient */
		atomic_compare_exchange_weak_explicit(&mt->n_max, &oldsize,
						      current,
						      memory_order_relaxed,
						      memory_order_relaxed);

	oldsize = atomic_load_explicit(&mt->size, memory_order_relaxed);
	if (oldsize == 0)
		oldsize = atomic_exchange_explicit(&mt->size, size,
						   memory_order_relaxed);
	if (oldsize != 0 && oldsize != size && oldsize != SIZE_VAR)
		atomic_store_explicit(&mt->size, SIZE_VAR,
				      memory_order_relaxed);

	size_t mallocsz = mpalloc_usable_size(ptr);

	current = mallocsz + atomic_fetch_add_explicit(&mt->total, mallocsz,
						       memory_order_relaxed);
	oldsize = atomic_load_explicit(&mt->max_size, memory_order_relaxed);
	if (current > oldsize)
		/* note that this may fail, but approximation is sufficient */
		atomic_compare_exchange_weak_explicit(&mt->max_size, &oldsize,
						      current,
						      memory_order_relaxed,
						      memory_order_relaxed);
}


static inline void mt_count_free(struct memtype *mt, void *ptr)
{

	assert(mt->n_alloc);
	atomic_fetch_sub_explicit(&mt->n_alloc, 1, memory_order_relaxed);

	size_t mallocsz = mpalloc_usable_size(ptr);

	atomic_fetch_sub_explicit(&mt->total, mallocsz, memory_order_relaxed);

}





/*
 * turning an allocated chunk to free
 * previous chunk is assumed allocated or First free chunk
 * next chunk is assumed allocated or Last free chunk
 * current is allocated
 * no size change
 * status and linking change
 */
static void freemidchunk(struct mpblock *block, struct mpchunk *chunk, struct mpchunk *prevfreechunk)
{
	struct mpchunk *next_chunk;
	char *ptr = (char *)chunk;

	next_chunk = (struct mpchunk *)(ptr + SZ(chunk->size));

	/* manage status */
	SET_CUR_FREE(chunk);
	SET_PREV_FREE(next_chunk);

	/* manage linked list */
	chunk->bk = prevfreechunk;
	chunk->fd = prevfreechunk->fd;
	prevfreechunk->fd->bk = chunk;
	prevfreechunk->fd = chunk;

	/*
	 * update block counters
	 * 1 chunks allocated->free
	 * header remains
	 */
	block->totalused -= SZ(chunk->size) - CHUNK_HDR_SIZE;
	block->totalfree += SZ(chunk->size) - CHUNK_HDR_SIZE;

	return;
}

/*
 * turning an allocated chunk to free
 * chunk is merged with previous one
 * previous chunk is assumed free and not First chunk
 * current is allocated
 * only sizes will change
 */
static void mpchunkmergewithprev(struct mpblock *block, struct mpchunk *prev_chunk,
				 struct mpchunk *chunk)
{
	struct mpchunk *next_chunk;
	char *ptr = (char *)chunk;

	next_chunk = (struct mpchunk *)(ptr + SZ(chunk->size));

	/* we merge with an allocated one */
	next_chunk->prev_size += SZ(prev_chunk->size);
	prev_chunk->size += SZ(chunk->size);

	/* set status */
	SET_PREV_FREE(next_chunk);

	/*
	 * update block counters
	 * 1 chunks removed
	 * allocated chunk freed, header also free for use
	 */
	block->totalused -= SZ(chunk->size) - CHUNK_HDR_SIZE;
	block->totalfree += SZ(chunk->size);
	block->totalmgm -= CHUNK_HDR_SIZE;
	return;
}

/*
 * turning an allocated chunk to free
 * chunk is merged with the next one
 * current chunk is assumed allocated
 * next chunk is free and not Last one
 */
static void mpchunkmergewithnext(struct mpblock *block, struct mpchunk *chunk,
				 struct mpchunk *next_chunk)
{
	struct mpchunk *next_next_chunk;
	char *ptr = (char *)next_chunk;

	next_next_chunk = (struct mpchunk *)(ptr + SZ(next_chunk->size));

	/* we merge with an allocated one */
	chunk->size += SZ(next_chunk->size);
	next_next_chunk->prev_size = SZ(chunk->size);

	/* set status */
	SET_CUR_FREE(chunk);

	/* manage linked list */
	next_chunk->bk->fd = chunk;
	chunk->bk = next_chunk->bk;
	chunk->fd = next_chunk->fd;
	chunk->fd->bk = chunk;

	/*
	 * update block counters
	 * 1 chunks removed
	 * allocated chunk freed, header also free for use
	 */
	block->totalused -= SZ(chunk->size) - CHUNK_HDR_SIZE;
	block->totalfree += SZ(chunk->size);
	block->totalmgm -= CHUNK_HDR_SIZE;

	return;
}


/*
 * turning an allocated chunk to free
 * chunk is merged with previous and next one
 * previous chunk is assumed free and not First one
 * next chunk is assumed free and not Last one
 * current is Allocated
 */

static void mpchunkmergeprevnextfree(struct mpblock *block, struct mpchunk *chunk,
				     struct mpchunk *prev_chunk, struct mpchunk *next_chunk)
{

	struct mpchunk *nextnext_chunk;
	char *ptr = (char *)next_chunk;

	/* this chunk may be the last */
	nextnext_chunk = (struct mpchunk *)(ptr + SZ(next_chunk->size));

	/* merge with two other free chunks */
	nextnext_chunk->prev_size += SZ(prev_chunk->size) + SZ(chunk->size);
	prev_chunk->size += SZ(chunk->size) + SZ(next_chunk->size);

	/* set status */
	SET_CUR_FREE(prev_chunk);

	/* manage linked list */
	prev_chunk->fd = next_chunk->fd;
	next_chunk->fd->bk = prev_chunk;

	/*
	 * update block counters
	 * 1 chunks removed
	 * allocated chunk freed, header also free for use
	 */
	block->totalused -= SZ(chunk->size) - CHUNK_HDR_SIZE;
	block->totalfree += SZ(chunk->size) + CHUNK_HDR_SIZE;
	block->totalmgm -= 2 * CHUNK_HDR_SIZE;

	return;
}

/*
 * freeing a allocated chunk
 */
static uint32_t freempchunk(struct mpblock *block, struct mpchunk *chunk)
{
	char *ptr = (char *)chunk;
	struct mpchunk *next_chunk, *prev_chunk, *cur_chunk;
	struct mpchunk *prev_free_chunk = NULL;
	assert(IS_CHUNK_VALID(chunk));
	assert(IS_IN_USE(chunk));

	prev_chunk = (struct mpchunk *)(ptr - SZ(chunk->prev_size));
	next_chunk = (struct mpchunk *)(ptr + SZ(chunk->size));

	/*
	 * four possibilities
	 * 1) previous and next chunk are free
	 * 2) only previous chunk is free
	 * 3) only next chunk is free
	 * 4) previous and next chunk are alocated
	 */
	if (IS_FREE(prev_chunk) && IS_FREE(next_chunk) &&
	    (prev_chunk != block->firstfreechunk) &&
	    (next_chunk != block->lastfreechunk)) {
		/*
		 * merge chunk with previous and next chunk
		 * resulting chunk will take place of previous one
		 */
		assert(IS_CHUNK_VALID(prev_chunk));
		assert(IS_CHUNK_VALID(next_chunk));
		mpchunkmergeprevnextfree(block, chunk, prev_chunk, next_chunk);
		assert(IS_CHUNK_VALID(prev_chunk));

	} else if (IS_FREE(prev_chunk) &&
		   (prev_chunk != block->firstfreechunk)) {
		assert(IS_CHUNK_VALID(prev_chunk));
		/*
		 * merge chunk with previous one
		 * resultant chunk will be the previous one
		 */
		mpchunkmergewithprev(block, prev_chunk, chunk);
		assert(IS_CHUNK_VALID(prev_chunk));

	} else if (IS_FREE(next_chunk) && (next_chunk != block->lastfreechunk)) {
		assert(IS_CHUNK_VALID(next_chunk));
		/* chunk will absorb next_chunk */
		mpchunkmergewithnext(block, chunk, next_chunk);
		assert(IS_CHUNK_VALID(chunk));

	} else {
		/* search for previous free chunk */

		cur_chunk = block->firstfreechunk;
		while (cur_chunk) {
			if ((char *)cur_chunk >= (char *)chunk)
				break;
			prev_free_chunk = cur_chunk;
			cur_chunk = cur_chunk->fd;
		}

		assert(prev_free_chunk);
		assert(prev_free_chunk->fd != chunk);

		freemidchunk(block, chunk, prev_free_chunk);
		assert(IS_IN_BLOCK(chunk->fd, block));
		assert(IS_IN_BLOCK(chunk->bk, block));
		assert(IS_CHUNK_VALID(chunk));
		/*
		 * update block counters one used chunk set free
		 * correction
		 */

		block->n_free_chunk++;
		assert(IS_FREE(chunk->bk));
	}

	/* update block counters */
	block->n_alloc_chunk--;

	return 0;
}

/*
 * get a free chunk with enougth free memory in on block
 *
 */
static struct mpchunk *mpgetfreesizechunk(struct mpblock *block, size_t size)
{
	size_t needed_size = (((size >> ALIGN) + 1) << ALIGN);
	uint32_t i = 0;


	if (block->totalfree < needed_size)
		return NULL;

	struct mpchunk *cur_chunk = block->firstfreechunk;

	while (cur_chunk) {
		if ((IS_FREE(cur_chunk) && SZ(cur_chunk->size) >= needed_size))
			break;
		cur_chunk = cur_chunk->fd;
		i++;
		assert(i <= block->n_free_chunk);
	}

	return cur_chunk;
}


/*
 * creation of one chunk in block
 * this is made from a free chunk
 * update block counters
 */
static void *mpallocinblock(struct mpblock *block, struct mpchunk *chunk, size_t size)
{
	struct mpchunk *next_chunk = NULL, *new_chunk = NULL;
	char *ptr = (char *)chunk;
	/* Size + align + header */
	size_t needed_size = (((size >> ALIGN) + 1) << ALIGN) + CHUNK_HDR_SIZE;

	next_chunk = (struct mpchunk *)(ptr + SZ(chunk->size));

	assert(IS_CHUNK_VALID(chunk));
	/*
	 * chunk is great enought for 2 * sizes allocation
	 * thus to avoid
	 */
	if (SZ(chunk->size) > needed_size * 2) {
		/*
		 * split the current chunk
		 * current chunk will be  allocated
		 * needed_size
		 * new_chunk will be free
		 * old_size - needed_size - alloc header size
		 */

		new_chunk = (struct mpchunk *)(ptr + needed_size);
		assert(IS_IN_BLOCK(new_chunk, block));
		new_chunk->prev_size = needed_size;
		new_chunk->size = SZ(chunk->size) - needed_size;

		chunk->size = needed_size;
		next_chunk->prev_size = new_chunk->size;


		/* apply status */
		SET_PREV_INUSE(new_chunk);
		SET_CUR_INUSE(chunk);

		/*
		 * manage double linked list
		 * possible de optimize
		 */
		assert(IS_IN_BLOCK(chunk->bk, block));
		assert(IS_IN_BLOCK(chunk->fd, block));
		new_chunk->bk = chunk->bk;
		new_chunk->fd = chunk->fd;
		chunk->bk->fd = new_chunk;
		chunk->fd->bk = new_chunk;

		/* previous free has not changed */
		assert(IS_CHUNK_VALID(chunk));
		assert(IS_CHUNK_VALID(new_chunk));
		assert(chunk != chunk->fd);
		assert(new_chunk != new_chunk->fd);
		assert(IS_FREE(new_chunk->bk));
		block->totalmgm += CHUNK_HDR_SIZE;

	} else {
		/* transform current free chunk into allocated one */

		SET_CUR_INUSE(chunk);
		SET_PREV_INUSE(next_chunk);
		/* manage double linked list */
		assert(IS_IN_BLOCK(chunk->bk, block));
		assert(IS_IN_BLOCK(chunk->fd, block));
		chunk->bk->fd = chunk->fd;
		chunk->fd->bk = chunk->bk;
		block->n_free_chunk--;
		block->totalfree += CHUNK_HDR_SIZE;
		assert(IS_CHUNK_VALID(chunk));
		assert(chunk != chunk->fd);
	}

	block->n_alloc_chunk++;
	block->totalfree -= SZ(chunk->size);
	block->totalused += SZ(chunk->size) - CHUNK_HDR_SIZE;

	/* return the address of data area */
	return (void *)(ptr + CHUNK_HDR_SIZE);
}


/*
 * Initializes a memory block with the specified size.
 * Parameters:
 *   size - size of the block to initialize
 * Returns:
 *   Pointer to the initialized memory block
 */
static struct mpblock *mp_new_block(size_t size)
{
	struct mpchunk *first_chunk, *main_chunk, *last_chunk;
	struct mpblock *new_block;

	void *allocated_mem;


	new_block = (struct mpblock *)malloc(sizeof(struct mpblock));
	memset(new_block, 0, sizeof(struct mpblock));
	allocated_mem = malloc(size);

	new_block->start = (char *)allocated_mem;
	new_block->end = (char *)allocated_mem + size;

	/* block has 3 basic chunks
	 * First chunk free and size 0
	 * main chunk free that will be transformed into allocated chunks
	 * Last chunk free and size 0
	 */

	first_chunk = (struct mpchunk *)new_block->start;
	main_chunk = (struct mpchunk *)(new_block->start + CHUNK_HDR_SIZE);
	last_chunk = (struct mpchunk *)(new_block->end - CHUNK_HDR_SIZE);

	first_chunk->size = 32;
	first_chunk->prev_size = 0;
	first_chunk->bk = NULL;
	first_chunk->fd = main_chunk;
	main_chunk->size = size - (2 * CHUNK_HDR_SIZE);
	main_chunk->prev_size = 32;
	main_chunk->bk = first_chunk;
	main_chunk->fd = last_chunk;
	last_chunk->size = 32;
	last_chunk->prev_size = size - (2 * CHUNK_HDR_SIZE);
	last_chunk->bk = main_chunk;
	last_chunk->fd = NULL;

	/* init block counters */
	new_block->totalmaxsize = size;
	new_block->totalused = 0;
	new_block->totalfree = size - (3 * CHUNK_HDR_SIZE);
	new_block->totalmgm = 3 * CHUNK_HDR_SIZE;
	new_block->n_free_chunk = 3;
	new_block->firstfreechunk = first_chunk;
	new_block->lastfreechunk = last_chunk;
	return new_block;
}

/*
 * Frees the memory associated with the given block.
 * Parameters:
 *   block - pointer to the block to free
 */
static void mp_free_block(struct mpblock **block)
{
	free((*block)->start);
	free(*block);
	*block = NULL;
	return;
}

/*
 * mempool creation
 *
 */
struct memptype *mphead_create(size_t default_size)
{
	struct memptype *new_pool;
	new_pool = (struct memptype *)malloc(sizeof(struct memptype));
	memset(new_pool, 0, sizeof(struct memptype));

	new_pool->default_block_size = SZ(default_size);

	new_pool->blocks_list = mp_new_block(new_pool->default_block_size);
	new_pool->totalsize = 0;
	new_pool->totalmaxsize = SZ(default_size);
	new_pool->n_blocks = 1;

	/* stats see memory.h */
	mem_pool_grp.ref = mg_insert;
	*mg_insert =  &mem_pool_grp;
	mg_insert = &mem_pool_grp.next;

	mem_pool_grp.insert = &mem_pool_grp.types;
	new_pool->stat.name = "redistribute stream";
	new_pool->stat.ref = mem_pool_grp.insert;
	*mem_pool_grp.insert =  &new_pool->stat;
	mem_pool_grp.insert = &new_pool->stat.next;
	return new_pool;
}

/*
 * mempool deletion
 *
 */
void mphead_delete(struct memptype **mt)
{
	struct mpblock *cur_block, *next_block;


	cur_block = (*mt)->blocks_list;
	while (cur_block) {
		next_block = cur_block->next;
		mp_free_block(&cur_block);
		cur_block = next_block;
	}

	/* stats see memory.h */
	if (mem_pool_grp.next)
		mem_pool_grp.next->ref = mem_pool_grp.ref;

	*mem_pool_grp.ref = mem_pool_grp.next;

	free(*mt);
	*mt = NULL;
}

/*
 * Allocates a memory chunk of the specified size from the given block.
 * Parameters:
 *   block - memory block to allocate from
 *   size - requested size of the chunk
 * Returns:
 *   Pointer to the allocated memory chunk or NULL if allocation fails
 */
void *mpalloc(struct memptype *mt, size_t size)
{
	struct mpblock *cur_block;
	struct mpblock *new_block;
	struct mpchunk *cur_chunk;
	void *cur_ptr = NULL;
	uint32_t i = 0;

	/* search for a block with enough free size */
	cur_block = mt->blocks_list;
	while (cur_block) {
		cur_chunk = mpgetfreesizechunk(cur_block, size);
		if (cur_chunk) {
			/* changes chunks in block */
			cur_ptr = mpallocinblock(cur_block, cur_chunk, size);
			mt_count_alloc(&mt->stat, size, cur_ptr);
			return cur_ptr;
		} else
			cur_block = cur_block->next;
		i++;
		assert(i <= mt->n_blocks);
	}

	/* no block with enougth free size */
	new_block = mp_new_block(mt->default_block_size);
	new_block->next = mt->blocks_list;
	mt->blocks_list = new_block;
	mt->n_blocks++;
	mt->totalmaxsize += mt->default_block_size;

	cur_chunk = new_block->firstfreechunk->fd;
	cur_ptr = mpallocinblock(new_block, cur_chunk, size);
	/* updates counters */
	mt_count_alloc(&mt->stat, size, cur_ptr);

	return cur_ptr;
}

/*
 * Frees a previously allocated memory chunk.
 * Parameters:
 *   block - the block containing the chunk
 *   ptr - pointer to the chunk to free
 */
void mpfree(struct memptype *mt, void *ptr)
{
	struct mpblock *cur_block;
	struct mpblock *prev_block = NULL;
	struct mpchunk *chunk;


	/* search the block */
	cur_block = mt->blocks_list;
	while (cur_block) {
		if ((ptr > (void *)cur_block->start) && (ptr < (void *)cur_block->end))
			break;
		prev_block = cur_block;
		cur_block = cur_block->next;
	}

	assert(cur_block);

	/* update  pool counters */
	mt_count_free(&mt->stat, ptr);

	chunk = (struct mpchunk *)((char *)ptr - CHUNK_HDR_SIZE);
	assert(IS_IN_USE(chunk));
	freempchunk(cur_block, chunk);

	/* remove block if it is empty and not the first one in list */
	if (!cur_block->n_alloc_chunk && cur_block != mt->blocks_list) {
		prev_block->next = cur_block->next;
		mp_free_block(&cur_block);
		mt->n_blocks--;
		mt->totalmaxsize -= mt->default_block_size;
	}

}

uint32_t mp_nb_blocks(struct memptype *mt)
{
	return mt->n_blocks;
}
