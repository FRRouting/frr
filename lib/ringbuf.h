// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Circular buffer implementation.
 * Copyright (C) 2017 Cumulus Networks
 * Quentin Young
 */
#ifndef _FRR_RINGBUF_H_
#define _FRR_RINGBUF_H_

#include <zebra.h>
#include <stdint.h>

#include "memory.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ringbuf {
	size_t size;
	ssize_t start;
	ssize_t end;
	bool empty;
	uint8_t *data;
};

/*
 * Creates a new ring buffer.
 *
 * @param size	buffer size, in bytes
 * @return the newly created buffer
 */
struct ringbuf *ringbuf_new(size_t size);

/*
 * Deletes a ring buffer and frees all associated resources.
 *
 * @param buf	the ring buffer to destroy
 */
void ringbuf_del(struct ringbuf *buf);

/*
 * Get amount of data left to read from the buffer.
 *
 * @return number of readable bytes
 */
size_t ringbuf_remain(struct ringbuf *buf);

/*
 * Get amount of space left to write to the buffer
 *
 * @return number of writeable bytes
 */
size_t ringbuf_space(struct ringbuf *buf);


/*
 * Put data into the ring buffer.
 *
 * @param data	the data to put in the buffer
 * @param size	how much of data to put in
 * @return number of bytes written; will be less than size if there was not
 * enough space
 */
size_t ringbuf_put(struct ringbuf *buf, const void *data, size_t size);

/*
 * Get data from the ring buffer.
 *
 * @param data	where to put the data
 * @param size	how much of data to get
 * @return number of bytes read into data; will be less than size if there was
 * not enough data to read
 */
size_t ringbuf_get(struct ringbuf *buf, void *data, size_t size);

/*
 * Peek data from the ring buffer.
 *
 * @param offset	where to get the data from, in bytes offset from the
 *			start of the data
 * @param data		where to put the data
 * @param size		how much data to get
 * @return		number of bytes read into data; will be less than size
 *			if there was not enough data to read; will be -1 if the
 *			offset exceeds the amount of data left in the ring
 *			buffer
 */
size_t ringbuf_peek(struct ringbuf *buf, size_t offset, void *data,
		    size_t size);

/*
 * Copy data from one ringbuf to another.
 *
 * @param to	destination ringbuf
 * @param from	source ringbuf
 * @param size	how much data to copy
 * @return amount of data copied
 */
size_t ringbuf_copy(struct ringbuf *to, struct ringbuf *from, size_t size);

/*
 * Reset buffer. Does not wipe.
 *
 * @param buf
 */
void ringbuf_reset(struct ringbuf *buf);

/*
 * Reset buffer. Wipes.
 *
 * @param buf
 */
void ringbuf_wipe(struct ringbuf *buf);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_RINGBUF_H_ */
