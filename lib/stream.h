/*
 * Packet interface
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef _ZEBRA_STREAM_H
#define _ZEBRA_STREAM_H

#include "prefix.h"

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
 * A Good stream user should ensure it writes all bytes. (the zero-fill
 * guarantee may be removed in future, however, the zero-filling may
 * possibly be moved to stream_forward_endp() instead, maybe..)
 */

/* Stream buffer. */
struct stream
{
  struct stream *next;

  /* Remainder is ***private*** to stream
   * direct access is frowned upon!
   * Use the appropriate functions/macros 
   */
  size_t getp; 		/* next get position */
  size_t endp;		/* last valid data position */
  size_t size;		/* size of data segment */
  unsigned char data[0]; /* data pointer */
};

/* First in first out queue structure. */
struct stream_fifo
{
  size_t count;

  struct stream *head;
  struct stream *tail;
};

/* Utility macros. */
#define STREAM_SIZE(S)  ((S)->size)
  /* number of bytes which can still be written */
#define STREAM_WRITEABLE(S) ((S)->size - (S)->endp)
  /* number of bytes still to be read */
#define STREAM_READABLE(S) ((S)->endp - (S)->getp)

/* deprecated macros - do not use in new code */
#define STREAM_PNT(S)   stream_pnt((S))
#define STREAM_DATA(S)  ((S)->data)
#define STREAM_REMAIN(S) STREAM_WRITEABLE((S))

/* Stream prototypes. */
struct stream *stream_new (size_t);
void stream_free (struct stream *);
struct stream * stream_copy (struct stream *new, struct stream *src);
struct stream *stream_dup (struct stream *);

size_t stream_get_getp (struct stream *);
size_t stream_get_endp (struct stream *);
size_t stream_get_size (struct stream *);
u_char *stream_get_data (struct stream *);

void stream_set_getp (struct stream *, size_t);
void stream_forward_getp (struct stream *, size_t);
void stream_forward_endp (struct stream *, size_t);

void stream_put (struct stream *, void *, size_t);
int stream_putc (struct stream *, u_char);
int stream_putc_at (struct stream *, size_t, u_char);
int stream_putw (struct stream *, u_int16_t);
int stream_putw_at (struct stream *, size_t, u_int16_t);
int stream_putl (struct stream *, u_int32_t);
int stream_putl_at (struct stream *, size_t, u_int32_t);
int stream_put_ipv4 (struct stream *, u_int32_t);
int stream_put_in_addr (struct stream *, struct in_addr *);
int stream_put_prefix (struct stream *, struct prefix *);

void stream_get (void *, struct stream *, size_t);
u_char stream_getc (struct stream *);
u_char stream_getc_from (struct stream *, size_t);
u_int16_t stream_getw (struct stream *);
u_int16_t stream_getw_from (struct stream *, size_t);
u_int32_t stream_getl (struct stream *);
u_int32_t stream_getl_from (struct stream *, size_t);
u_int32_t stream_get_ipv4 (struct stream *);

#undef stream_read
#undef stream_write

/* Deprecated: assumes blocking I/O.  Will be removed. 
   Use stream_read_try instead.  */
int stream_read (struct stream *, int, size_t);

/* Deprecated: all file descriptors should already be non-blocking.
   Will be removed.  Use stream_read_try instead. */
int stream_read_unblock (struct stream *, int, size_t);

/* Read up to size bytes into the stream.
   Return code:
     >0: number of bytes read
     0: end-of-file
     -1: fatal error
     -2: transient error, should retry later (i.e. EAGAIN or EINTR)
   This is suitable for use with non-blocking file descriptors.
 */
extern ssize_t stream_read_try(struct stream *s, int fd, size_t size);

int stream_recvmsg (struct stream *s, int fd, struct msghdr *,
                    int flags, size_t size);
int stream_write (struct stream *, u_char *, size_t);

void stream_reset (struct stream *); /* reset the stream. See Note above */
int stream_flush (struct stream *, int);
int stream_empty (struct stream *); /* is the stream empty? */

/* deprecated */
u_char *stream_pnt (struct stream *);

/* Stream fifo. */
struct stream_fifo *stream_fifo_new ();
void stream_fifo_push (struct stream_fifo *fifo, struct stream *s);
struct stream *stream_fifo_pop (struct stream_fifo *fifo);
struct stream *stream_fifo_head (struct stream_fifo *fifo);
void stream_fifo_clean (struct stream_fifo *fifo);
void stream_fifo_free (struct stream_fifo *fifo);

#endif /* _ZEBRA_STREAM_H */
