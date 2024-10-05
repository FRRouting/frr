// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Buffering to output and input.
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#ifndef _ZEBRA_BUFFER_H
#define _ZEBRA_BUFFER_H

#ifdef __cplusplus
extern "C" {
#endif

/* Create a new buffer.  Memory will be allocated in chunks of the given
   size.  If the argument is 0, the library will supply a reasonable
   default size suitable for buffering socket I/O. */
extern struct buffer *buffer_new(size_t size);

/* Free all data in the buffer. */
extern void buffer_reset(struct buffer *b);

/* This function first calls buffer_reset to release all buffered data.
   Then it frees the struct buffer itself. */
extern void buffer_free(struct buffer *b);

/* Add the given data to the end of the buffer. */
extern void buffer_put(struct buffer *b, const void *p, size_t size);
/* Add a single character to the end of the buffer. */
extern void buffer_putc(struct buffer *b, uint8_t c);
/* Add a NUL-terminated string to the end of the buffer. */
extern void buffer_putstr(struct buffer *b, const char *str);
/* Add given data, inline-expanding \n to \r\n */
extern void buffer_put_crlf(struct buffer *b, const void *p, size_t size);

/* Combine all accumulated (and unflushed) data inside the buffer into a
   single NUL-terminated string allocated using XMALLOC(MTYPE_TMP).  Note
   that this function does not alter the state of the buffer, so the data
   is still inside waiting to be flushed. */
char *buffer_getstr(struct buffer *b);

/* Returns 1 if there is no pending data in the buffer.  Otherwise returns 0. */
int buffer_empty(struct buffer *b);

typedef enum {
	/* An I/O error occurred.  The buffer should be destroyed and the
	   file descriptor should be closed. */
	BUFFER_ERROR = -1,

	/* The data was written successfully, and the buffer is now empty
	   (there is no pending data waiting to be flushed). */
	BUFFER_EMPTY = 0,

	/* There is pending data in the buffer waiting to be flushed.  Please
	   try flushing the buffer when select indicates that the file
	   descriptor
	   is writeable. */
	BUFFER_PENDING = 1
} buffer_status_t;

/* Try to write this data to the file descriptor.  Any data that cannot
   be written immediately is added to the buffer queue. */
extern buffer_status_t buffer_write(struct buffer *b, int fd, const void *p,
				    size_t size);

/* This function attempts to flush some (but perhaps not all) of
   the queued data to the given file descriptor. */
extern buffer_status_t buffer_flush_available(struct buffer *b, int fd);

/* The following 2 functions (buffer_flush_all and buffer_flush_window)
   are for use in lib/vty.c only.  They should not be used elsewhere. */

/* Call buffer_flush_available repeatedly until either all data has been
   flushed, or an I/O error has been encountered, or the operation would
   block. */
extern buffer_status_t buffer_flush_all(struct buffer *b, int fd);

/* Attempt to write enough data to the given fd to fill a window of the
   given width and height (and remove the data written from the buffer).

   If !no_more, then a message saying " --More-- " is appended.
   If erase is true, then first overwrite the previous " --More-- " message
   with spaces.

   Any write error (including EAGAIN or EINTR) will cause this function
   to return -1 (because the logic for handling the erase and more features
   is too complicated to retry the write later).
*/
extern buffer_status_t buffer_flush_window(struct buffer *b, int fd, int width,
					   int height, int erase, int no_more);

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_BUFFER_H */
