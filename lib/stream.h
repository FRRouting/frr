// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Packet interface
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_STREAM_H
#define _ZEBRA_STREAM_H

#include <pthread.h>

#include "frratomic.h"
#include "mpls.h"
#include "prefix.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A stream is an arbitrary buffer, whose contents generally are assumed to
 * be in network order.
 *
 * A stream has the following attributes associated with it:
 *
 * - size: the allocated, invariant size of the buffer.
 *
 * - getp: the get position marker, denoting the offset in the stream where
 *         the next read (or 'get') will be from. This getp marker is
 *         automatically adjusted when data is read from the stream, the
 *         user may also manipulate this offset as they wish, within limits
 *         (see below)
 *
 * - endp: the end position marker, denoting the offset in the stream where
 *         valid data ends, and if the user attempted to write (or
 *         'put') data where that data would be written (or 'put') to.
 *
 * These attributes are all size_t values.
 *
 * Constraints:
 *
 * 1. getp can never exceed endp
 *
 * - hence if getp is equal to endp, there is no more valid data that can be
 *   gotten from the stream (though, the user may reposition getp to earlier in
 *   the stream, if they wish).
 *
 * 2. endp can never exceed size
 *
 * - hence, if endp is equal to size, then the stream is full, and no more
 *   data can be written to the stream.
 *
 * In other words the following must always be true, and the stream
 * abstraction is allowed internally to assert that the following property
 * holds true for a stream, as and when it wishes:
 *
 *        getp <= endp <= size
 *
 * It is the users responsibility to ensure this property is never violated.
 *
 * A stream therefore can be thought of like this:
 *
 * 	---------------------------------------------------
 * 	|XXXXXXXXXXXXXXXXXXXXXXXX                         |
 * 	---------------------------------------------------
 *               ^               ^                        ^
 *               getp            endp                     size
 *
 * This shows a stream containing data (shown as 'X') up to the endp offset.
 * The stream is empty from endp to size. Without adjusting getp, there are
 * still endp-getp bytes of valid data to be read from the stream.
 *
 * Methods are provided to get and put to/from the stream, as well as
 * retrieve the values of the 3 markers and manipulate the getp marker.
 *
 * Note:
 * At the moment, newly allocated streams are zero filled. Hence, one can
 * use stream_forward_endp() to effectively create arbitrary zero-fill
 * padding. However, note that stream_reset() does *not* zero-out the
 * stream. This property should **not** be relied upon.
 *
 * Best practice is to use stream_put (<stream *>, NULL, <size>) to zero out
 * any part of a stream which isn't otherwise written to.
 */

/* Stream buffer. */
struct stream {
	struct stream *next;

	/*
	 * Remainder is ***private*** to stream
	 * direct access is frowned upon!
	 * Use the appropriate functions/macros
	 */
	size_t getp;	       /* next get position */
	size_t endp;	       /* last valid data position */
	size_t size;	       /* size of data segment */
	unsigned char data[];  /* data pointer */
};

/* First in first out queue structure. */
struct stream_fifo {
	/* lock for mt-safe operations */
	pthread_mutex_t mtx;

	/* number of streams in this fifo */
	atomic_size_t count;
	atomic_size_t max_count;

	struct stream *head;
	struct stream *tail;
};

/* Utility macros. */
#define STREAM_SIZE(S)  ((S)->size)
/* number of bytes which can still be written */
#define STREAM_WRITEABLE(S) ((S)->size - (S)->endp)
/* number of bytes still to be read */
#define STREAM_READABLE(S) ((S)->endp - (S)->getp)

#define STREAM_CONCAT_REMAIN(S1, S2, size) ((size) - (S1)->endp - (S2)->endp)

/* this macro is deprecated, but not slated for removal anytime soon */
#define STREAM_DATA(S)  ((S)->data)

/* Stream prototypes.
 * For stream_{put,get}S, the S suffix mean:
 *
 * c: character (unsigned byte)
 * w: word (two bytes)
 * l: long (two words)
 * q: quad (four words)
 */
extern struct stream *stream_new(size_t);
extern void stream_free(struct stream *);
/* Copy 'src' into 'dest', returns 'dest' */
extern struct stream *stream_copy(struct stream *dest,
				  const struct stream *src);
extern struct stream *stream_dup(const struct stream *s);

extern size_t stream_resize_inplace(struct stream **sptr, size_t newsize);

extern size_t stream_get_getp(const struct stream *s);
extern size_t stream_get_endp(const struct stream *s);
extern size_t stream_get_size(const struct stream *s);

/**
 * Create a new stream structure; copy offset bytes from s1 to the new
 * stream; copy s2 data to the new stream; copy rest of s1 data to the
 * new stream.
 */
extern struct stream *stream_dupcat(const struct stream *s1,
				    const struct stream *s2, size_t offset);

extern void stream_set_getp(struct stream *, size_t);
extern void stream_set_endp(struct stream *, size_t);
extern void stream_forward_getp(struct stream *, size_t);
extern bool stream_forward_getp2(struct stream *, size_t);
extern void stream_rewind_getp(struct stream *s, size_t size);
extern bool stream_rewind_getp2(struct stream *s, size_t size);
extern void stream_forward_endp(struct stream *, size_t);
extern bool stream_forward_endp2(struct stream *, size_t);

/* steam_put: NULL source zeroes out size_t bytes of stream */
extern void stream_put(struct stream *, const void *, size_t);
extern int stream_putc(struct stream *, uint8_t);
extern int stream_putc_at(struct stream *, size_t, uint8_t);
extern int stream_putw(struct stream *, uint16_t);
extern int stream_putw_at(struct stream *, size_t, uint16_t);
extern int stream_put3(struct stream *, uint32_t);
extern int stream_put3_at(struct stream *, size_t, uint32_t);
extern int stream_putl(struct stream *, uint32_t);
extern int stream_putl_at(struct stream *, size_t, uint32_t);
extern int stream_putq(struct stream *, uint64_t);
extern int stream_putq_at(struct stream *, size_t, uint64_t);
extern int stream_put_ipv4(struct stream *, uint32_t);
extern int stream_put_in_addr(struct stream *s, const struct in_addr *addr);
extern bool stream_put_ipaddr(struct stream *s, const struct ipaddr *ip);
extern int stream_put_in_addr_at(struct stream *s, size_t putp,
				 const struct in_addr *addr);
extern int stream_put_in6_addr_at(struct stream *s, size_t putp,
				  const struct in6_addr *addr);
extern int stream_put_prefix_addpath(struct stream *s, const struct prefix *p,
				     bool addpath_capable,
				     uint32_t addpath_tx_id);
extern int stream_put_prefix(struct stream *s, const struct prefix *p);
extern int stream_put_labeled_prefix(struct stream *, const struct prefix *,
				     mpls_label_t *, bool addpath_capable,
				     uint32_t addpath_tx_id);
extern void stream_get(void *, struct stream *, size_t);
extern bool stream_get2(void *data, struct stream *s, size_t size);
extern void stream_get_from(void *, struct stream *, size_t, size_t);
extern uint8_t stream_getc(struct stream *);
extern bool stream_getc2(struct stream *s, uint8_t *byte);
extern uint8_t stream_getc_from(struct stream *, size_t);
extern uint16_t stream_getw(struct stream *);
extern bool stream_getw2(struct stream *s, uint16_t *word);
extern uint16_t stream_getw_from(struct stream *, size_t);
extern uint32_t stream_get3(struct stream *);
extern uint32_t stream_get3_from(struct stream *, size_t);
extern uint32_t stream_getl(struct stream *);
extern bool stream_getl2(struct stream *s, uint32_t *l);
extern uint32_t stream_getl_from(struct stream *, size_t);
extern uint64_t stream_getq(struct stream *);
extern uint64_t stream_getq_from(struct stream *, size_t);
bool stream_getq2(struct stream *s, uint64_t *q);
extern uint32_t stream_get_ipv4(struct stream *);
extern bool stream_get_ipaddr(struct stream *s, struct ipaddr *ip);

/* IEEE-754 floats */
extern float stream_getf(struct stream *);
extern double stream_getd(struct stream *);
extern int stream_putf(struct stream *, float);
extern int stream_putd(struct stream *, double);

#undef stream_read
#undef stream_write

/* Deprecated: assumes blocking I/O.  Will be removed.
   Use stream_read_try instead.  */
extern int stream_read(struct stream *, int, size_t);

/* Read up to size bytes into the stream.
   Return code:
     >0: number of bytes read
     0: end-of-file
     -1: fatal error
     -2: transient error, should retry later (i.e. EAGAIN or EINTR)
   This is suitable for use with non-blocking file descriptors.
 */
extern ssize_t stream_read_try(struct stream *s, int fd, size_t size);

extern ssize_t stream_recvmsg(struct stream *s, int fd, struct msghdr *,
			      int flags, size_t size);
extern ssize_t stream_recvfrom(struct stream *s, int fd, size_t len, int flags,
			       struct sockaddr *from, socklen_t *fromlen);
extern size_t stream_write(struct stream *, const void *, size_t);

/* reset the stream. See Note above */
extern void stream_reset(struct stream *);
extern int stream_flush(struct stream *, int);
extern int stream_empty(struct stream *); /* is the stream empty? */

/* debugging */
extern void stream_hexdump(const struct stream *s);

/**
 * Reorganize the buffer data so it can fit more. This function is normally
 * called right after stream data is consumed so we can read more data
 * (the functions that consume data start with `stream_get*()` and macros
 * `STREAM_GET*()`).
 *
 * \param s stream pointer.
 */
extern void stream_pulldown(struct stream *s);

/* deprecated */
extern uint8_t *stream_pnt(struct stream *);

/*
 * Operations on struct stream_fifo.
 *
 * Each function has a safe variant, which ensures that the operation performed
 * is atomic with respect to the operations performed by all other safe
 * variants. In other words, the safe variants lock the stream_fifo's mutex
 * before performing their action. These are provided for convenience when
 * using stream_fifo in a multithreaded context, to alleviate the need for the
 * caller to implement their own synchronization around the stream_fifo.
 *
 * The following functions do not have safe variants. The caller must ensure
 * that these operations are performed safely in a multithreaded context:
 * - stream_fifo_new
 * - stream_fifo_free
 */

/*
 * Create a new stream_fifo.
 *
 * Returns:
 *    newly created stream_fifo
 */
extern struct stream_fifo *stream_fifo_new(void);

/*
 * Init or re-init an on-stack fifo. This allows use of a fifo struct without
 * requiring a malloc/free cycle.
 * Note well that the fifo must be de-inited with the 'fifo_deinit' api.
 */
void stream_fifo_init(struct stream_fifo *fifo);

/*
 * Deinit an on-stack fifo.
 */
void stream_fifo_deinit(struct stream_fifo *fifo);

/*
 * Push a stream onto a stream_fifo.
 *
 * fifo
 *    the stream_fifo to push onto
 *
 * s
 *    the stream to push onto the stream_fifo
 */
extern void stream_fifo_push(struct stream_fifo *fifo, struct stream *s);
extern void stream_fifo_push_safe(struct stream_fifo *fifo, struct stream *s);

/*
 * Pop a stream off a stream_fifo.
 *
 * fifo
 *    the stream_fifo to pop from
 *
 * Returns:
 *    the next stream in the stream_fifo
 */
extern struct stream *stream_fifo_pop(struct stream_fifo *fifo);
extern struct stream *stream_fifo_pop_safe(struct stream_fifo *fifo);

/*
 * Retrieve the next stream from a stream_fifo without popping it.
 *
 * fifo
 *    the stream_fifo to operate on
 *
 * Returns:
 *    the next stream that would be returned from stream_fifo_pop
 */
extern struct stream *stream_fifo_head(struct stream_fifo *fifo);
extern struct stream *stream_fifo_head_safe(struct stream_fifo *fifo);

/*
 * Remove all streams from a stream_fifo.
 *
 * fifo
 *    the stream_fifo to clean
 */
extern void stream_fifo_clean(struct stream_fifo *fifo);
extern void stream_fifo_clean_safe(struct stream_fifo *fifo);

/*
 * Retrieve number of streams on a stream_fifo.
 *
 * fifo
 *    the stream_fifo to retrieve the count for
 *
 * Returns:
 *    the number of streams on the stream_fifo
 */
extern size_t stream_fifo_count_safe(struct stream_fifo *fifo);

/*
 * Free a stream_fifo.
 *
 * Calls stream_fifo_clean, then deinitializes the stream_fifo and frees it.
 *
 * fifo
 *    the stream_fifo to free
 */
extern void stream_fifo_free(struct stream_fifo *fifo);

/* This is here because "<< 24" is particularly problematic in C.
 * This is because the left operand of << is integer-promoted, which means
 * an uint8_t gets converted into a *signed* int.  Shifting into the sign
 * bit of a signed int is theoretically undefined behaviour, so - the left
 * operand needs to be cast to unsigned.
 *
 * This is not a problem for 16- or 8-bit values (they don't reach the sign
 * bit), for 64-bit values (you need to cast them anyway), and neither for
 * encoding (because it's downcasted.)
 */
static inline const uint8_t *ptr_get_be64(const uint8_t *ptr, uint64_t *out)
{
	uint32_t tmp1, tmp2;

	memcpy(&tmp1, ptr, sizeof(tmp1));
	memcpy(&tmp2, ptr + sizeof(tmp1), sizeof(tmp1));

	*out = (((uint64_t)ntohl(tmp1)) << 32) | ntohl(tmp2);

	return ptr + 8;
}

static inline const uint8_t *ptr_get_be32(const uint8_t *ptr, uint32_t *out)
{
	uint32_t tmp;

	memcpy(&tmp, ptr, sizeof(tmp));
	*out = ntohl(tmp);
	return ptr + 4;
}

static inline uint8_t *ptr_get_be16(uint8_t *ptr, uint16_t *out)
{
	uint16_t tmp;

	memcpy(&tmp, ptr, sizeof(tmp));
	*out = ntohs(tmp);

	return ptr + 2;
}

/*
 * so Normal stream_getX functions assert.  Which is anathema
 * to keeping a daemon up and running when something goes south
 * Provide a stream_getX2 functions that do not assert.
 * In addition provide these macro's that upon failure
 * goto stream_failure.  This is modeled upon some NL_XX
 * macros in the linux kernel.
 *
 * This change allows for proper memory freeing
 * after we've detected an error.
 *
 * In the future we will be removing the assert in
 * the stream functions but we need a transition
 * plan.
 */
#define STREAM_GETC(S, P)                                                      \
	do {                                                                   \
		uint8_t _pval;                                                 \
		if (!stream_getc2((S), &_pval))                                \
			goto stream_failure;                                   \
		(P) = _pval;                                                   \
	} while (0)

#define STREAM_GETW(S, P)                                                      \
	do {                                                                   \
		uint16_t _pval;                                                \
		if (!stream_getw2((S), &_pval))                                \
			goto stream_failure;                                   \
		(P) = _pval;                                                   \
	} while (0)

#define STREAM_GETL(S, P)                                                      \
	do {                                                                   \
		uint32_t _pval;                                                \
		if (!stream_getl2((S), &_pval))                                \
			goto stream_failure;                                   \
		(P) = _pval;                                                   \
	} while (0)

#define STREAM_GETF(S, P)                                                      \
	do {                                                                   \
		union {                                                        \
			float r;                                               \
			uint32_t d;                                            \
		} _pval;                                                       \
		if (!stream_getl2((S), &_pval.d))                              \
			goto stream_failure;                                   \
		(P) = _pval.r;                                                 \
	} while (0)

#define STREAM_GETQ(S, P)                                                      \
	do {                                                                   \
		uint64_t _pval;                                                \
		if (!stream_getq2((S), &_pval))                                \
			goto stream_failure;                                   \
		(P) = _pval;                                                   \
	} while (0)

#define STREAM_GET_IPADDR(S, P)                                                \
	do {                                                                   \
		if (!stream_get_ipaddr((S), (P)))                              \
			goto stream_failure;                                   \
	} while (0)

#define STREAM_GET(P, STR, SIZE)                                               \
	do {                                                                   \
		if (!stream_get2((P), (STR), (SIZE)))                          \
			goto stream_failure;                                   \
	} while (0)

#define STREAM_FORWARD_GETP(STR, SIZE)                                         \
	do {                                                                   \
		if (!stream_forward_getp2((STR), (SIZE)))                      \
			goto stream_failure;                                   \
	} while (0)

#define STREAM_REWIND_GETP(STR, SIZE)                                          \
	do {                                                                   \
		if (!stream_rewind_getp2((STR), (SIZE)))                       \
			goto stream_failure;                                   \
	} while (0)

#define STREAM_FORWARD_ENDP(STR, SIZE)                                         \
	do {                                                                   \
		if (!stream_forward_endp2((STR), (SIZE)))                      \
			goto stream_failure;                                   \
	} while (0)

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_STREAM_H */
