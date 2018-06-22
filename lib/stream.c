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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include <stddef.h>
#include <pthread.h>

#include "stream.h"
#include "memory.h"
#include "network.h"
#include "prefix.h"
#include "log.h"

DEFINE_MTYPE_STATIC(LIB, STREAM, "Stream")
DEFINE_MTYPE_STATIC(LIB, STREAM_DATA, "Stream data")
DEFINE_MTYPE_STATIC(LIB, STREAM_FIFO, "Stream FIFO")

/* Tests whether a position is valid */
#define GETP_VALID(S, G) ((G) <= (S)->endp)
#define PUT_AT_VALID(S,G) GETP_VALID(S,G)
#define ENDP_VALID(S, E) ((E) <= (S)->size)

/* asserting sanity checks. Following must be true before
 * stream functions are called:
 *
 * Following must always be true of stream elements
 * before and after calls to stream functions:
 *
 * getp <= endp <= size
 *
 * Note that after a stream function is called following may be true:
 * if (getp == endp) then stream is no longer readable
 * if (endp == size) then stream is no longer writeable
 *
 * It is valid to put to anywhere within the size of the stream, but only
 * using stream_put..._at() functions.
 */
#define STREAM_WARN_OFFSETS(S)                                                 \
	zlog_warn("&(struct stream): %p, size: %lu, getp: %lu, endp: %lu\n",   \
		  (void *)(S), (unsigned long)(S)->size,                       \
		  (unsigned long)(S)->getp, (unsigned long)(S)->endp)

#define STREAM_VERIFY_SANE(S)                                                  \
	do {                                                                   \
		if (!(GETP_VALID(S, (S)->getp) && ENDP_VALID(S, (S)->endp)))   \
			STREAM_WARN_OFFSETS(S);                                \
		assert(GETP_VALID(S, (S)->getp));                              \
		assert(ENDP_VALID(S, (S)->endp));                              \
	} while (0)

#define STREAM_BOUND_WARN(S, WHAT)                                             \
	do {                                                                   \
		zlog_warn("%s: Attempt to %s out of bounds", __func__,         \
			  (WHAT));                                             \
		STREAM_WARN_OFFSETS(S);                                        \
		assert(0);                                                     \
	} while (0)

#define STREAM_BOUND_WARN2(S, WHAT)                                            \
	do {                                                                   \
		zlog_warn("%s: Attempt to %s out of bounds", __func__,         \
			  (WHAT));                                             \
		STREAM_WARN_OFFSETS(S);                                        \
	} while (0)

/* XXX: Deprecated macro: do not use */
#define CHECK_SIZE(S, Z)                                                       \
	do {                                                                   \
		if (((S)->endp + (Z)) > (S)->size) {                           \
			zlog_warn(                                             \
				"CHECK_SIZE: truncating requested size %lu\n", \
				(unsigned long)(Z));                           \
			STREAM_WARN_OFFSETS(S);                                \
			(Z) = (S)->size - (S)->endp;                           \
		}                                                              \
	} while (0);

/* Make stream buffer. */
struct stream *stream_new(size_t size)
{
	struct stream *s;

	assert(size > 0);

	s = XCALLOC(MTYPE_STREAM, sizeof(struct stream));

	if (s == NULL)
		return s;

	if ((s->data = XMALLOC(MTYPE_STREAM_DATA, size)) == NULL) {
		XFREE(MTYPE_STREAM, s);
		return NULL;
	}

	s->size = size;
	return s;
}

/* Free it now. */
void stream_free(struct stream *s)
{
	if (!s)
		return;

	XFREE(MTYPE_STREAM_DATA, s->data);
	XFREE(MTYPE_STREAM, s);
}

struct stream *stream_copy(struct stream *new, struct stream *src)
{
	STREAM_VERIFY_SANE(src);

	assert(new != NULL);
	assert(STREAM_SIZE(new) >= src->endp);

	new->endp = src->endp;
	new->getp = src->getp;

	memcpy(new->data, src->data, src->endp);

	return new;
}

struct stream *stream_dup(struct stream *s)
{
	struct stream *new;

	STREAM_VERIFY_SANE(s);

	if ((new = stream_new(s->endp)) == NULL)
		return NULL;

	return (stream_copy(new, s));
}

struct stream *stream_dupcat(struct stream *s1, struct stream *s2,
			     size_t offset)
{
	struct stream *new;

	STREAM_VERIFY_SANE(s1);
	STREAM_VERIFY_SANE(s2);

	if ((new = stream_new(s1->endp + s2->endp)) == NULL)
		return NULL;

	memcpy(new->data, s1->data, offset);
	memcpy(new->data + offset, s2->data, s2->endp);
	memcpy(new->data + offset + s2->endp, s1->data + offset,
	       (s1->endp - offset));
	new->endp = s1->endp + s2->endp;
	return new;
}

size_t stream_resize(struct stream *s, size_t newsize)
{
	uint8_t *newdata;
	STREAM_VERIFY_SANE(s);

	newdata = XREALLOC(MTYPE_STREAM_DATA, s->data, newsize);

	if (newdata == NULL)
		return s->size;

	s->data = newdata;
	s->size = newsize;

	if (s->endp > s->size)
		s->endp = s->size;
	if (s->getp > s->endp)
		s->getp = s->endp;

	STREAM_VERIFY_SANE(s);

	return s->size;
}

size_t stream_get_getp(struct stream *s)
{
	STREAM_VERIFY_SANE(s);
	return s->getp;
}

size_t stream_get_endp(struct stream *s)
{
	STREAM_VERIFY_SANE(s);
	return s->endp;
}

size_t stream_get_size(struct stream *s)
{
	STREAM_VERIFY_SANE(s);
	return s->size;
}

/* Stream structre' stream pointer related functions.  */
void stream_set_getp(struct stream *s, size_t pos)
{
	STREAM_VERIFY_SANE(s);

	if (!GETP_VALID(s, pos)) {
		STREAM_BOUND_WARN(s, "set getp");
		pos = s->endp;
	}

	s->getp = pos;
}

void stream_set_endp(struct stream *s, size_t pos)
{
	STREAM_VERIFY_SANE(s);

	if (!ENDP_VALID(s, pos)) {
		STREAM_BOUND_WARN(s, "set endp");
		return;
	}

	/*
	 * Make sure the current read pointer is not beyond the new endp.
	 */
	if (s->getp > pos) {
		STREAM_BOUND_WARN(s, "set endp");
		return;
	}

	s->endp = pos;
	STREAM_VERIFY_SANE(s);
}

/* Forward pointer. */
void stream_forward_getp(struct stream *s, size_t size)
{
	STREAM_VERIFY_SANE(s);

	if (!GETP_VALID(s, s->getp + size)) {
		STREAM_BOUND_WARN(s, "seek getp");
		return;
	}

	s->getp += size;
}

void stream_forward_endp(struct stream *s, size_t size)
{
	STREAM_VERIFY_SANE(s);

	if (!ENDP_VALID(s, s->endp + size)) {
		STREAM_BOUND_WARN(s, "seek endp");
		return;
	}

	s->endp += size;
}

/* Copy from stream to destination. */
inline bool stream_get2(void *dst, struct stream *s, size_t size)
{
	STREAM_VERIFY_SANE(s);

	if (STREAM_READABLE(s) < size) {
		STREAM_BOUND_WARN2(s, "get");
		return false;
	}

	memcpy(dst, s->data + s->getp, size);
	s->getp += size;

	return true;
}

void stream_get(void *dst, struct stream *s, size_t size)
{
	STREAM_VERIFY_SANE(s);

	if (STREAM_READABLE(s) < size) {
		STREAM_BOUND_WARN(s, "get");
		return;
	}

	memcpy(dst, s->data + s->getp, size);
	s->getp += size;
}

/* Get next character from the stream. */
inline bool stream_getc2(struct stream *s, uint8_t *byte)
{
	STREAM_VERIFY_SANE(s);

	if (STREAM_READABLE(s) < sizeof(uint8_t)) {
		STREAM_BOUND_WARN2(s, "get char");
		return false;
	}
	*byte = s->data[s->getp++];

	return true;
}

uint8_t stream_getc(struct stream *s)
{
	uint8_t c;

	STREAM_VERIFY_SANE(s);

	if (STREAM_READABLE(s) < sizeof(uint8_t)) {
		STREAM_BOUND_WARN(s, "get char");
		return 0;
	}
	c = s->data[s->getp++];

	return c;
}

/* Get next character from the stream. */
uint8_t stream_getc_from(struct stream *s, size_t from)
{
	uint8_t c;

	STREAM_VERIFY_SANE(s);

	if (!GETP_VALID(s, from + sizeof(uint8_t))) {
		STREAM_BOUND_WARN(s, "get char");
		return 0;
	}

	c = s->data[from];

	return c;
}

inline bool stream_getw2(struct stream *s, uint16_t *word)
{
	STREAM_VERIFY_SANE(s);

	if (STREAM_READABLE(s) < sizeof(uint16_t)) {
		STREAM_BOUND_WARN2(s, "get ");
		return false;
	}

	*word = s->data[s->getp++] << 8;
	*word |= s->data[s->getp++];

	return true;
}

/* Get next word from the stream. */
uint16_t stream_getw(struct stream *s)
{
	uint16_t w;

	STREAM_VERIFY_SANE(s);

	if (STREAM_READABLE(s) < sizeof(uint16_t)) {
		STREAM_BOUND_WARN(s, "get ");
		return 0;
	}

	w = s->data[s->getp++] << 8;
	w |= s->data[s->getp++];

	return w;
}

/* Get next word from the stream. */
uint16_t stream_getw_from(struct stream *s, size_t from)
{
	uint16_t w;

	STREAM_VERIFY_SANE(s);

	if (!GETP_VALID(s, from + sizeof(uint16_t))) {
		STREAM_BOUND_WARN(s, "get ");
		return 0;
	}

	w = s->data[from++] << 8;
	w |= s->data[from];

	return w;
}

/* Get next 3-byte from the stream. */
uint32_t stream_get3_from(struct stream *s, size_t from)
{
	uint32_t l;

	STREAM_VERIFY_SANE(s);

	if (!GETP_VALID(s, from + 3)) {
		STREAM_BOUND_WARN(s, "get 3byte");
		return 0;
	}

	l = s->data[from++] << 16;
	l |= s->data[from++] << 8;
	l |= s->data[from];

	return l;
}

uint32_t stream_get3(struct stream *s)
{
	uint32_t l;

	STREAM_VERIFY_SANE(s);

	if (STREAM_READABLE(s) < 3) {
		STREAM_BOUND_WARN(s, "get 3byte");
		return 0;
	}

	l = s->data[s->getp++] << 16;
	l |= s->data[s->getp++] << 8;
	l |= s->data[s->getp++];

	return l;
}

/* Get next long word from the stream. */
uint32_t stream_getl_from(struct stream *s, size_t from)
{
	uint32_t l;

	STREAM_VERIFY_SANE(s);

	if (!GETP_VALID(s, from + sizeof(uint32_t))) {
		STREAM_BOUND_WARN(s, "get long");
		return 0;
	}

	l = (unsigned)(s->data[from++]) << 24;
	l |= s->data[from++] << 16;
	l |= s->data[from++] << 8;
	l |= s->data[from];

	return l;
}

/* Copy from stream at specific location to destination. */
void stream_get_from(void *dst, struct stream *s, size_t from, size_t size)
{
	STREAM_VERIFY_SANE(s);

	if (!GETP_VALID(s, from + size)) {
		STREAM_BOUND_WARN(s, "get from");
		return;
	}

	memcpy(dst, s->data + from, size);
}

inline bool stream_getl2(struct stream *s, uint32_t *l)
{
	STREAM_VERIFY_SANE(s);

	if (STREAM_READABLE(s) < sizeof(uint32_t)) {
		STREAM_BOUND_WARN2(s, "get long");
		return false;
	}

	*l = (unsigned int)(s->data[s->getp++]) << 24;
	*l |= s->data[s->getp++] << 16;
	*l |= s->data[s->getp++] << 8;
	*l |= s->data[s->getp++];

	return true;
}

uint32_t stream_getl(struct stream *s)
{
	uint32_t l;

	STREAM_VERIFY_SANE(s);

	if (STREAM_READABLE(s) < sizeof(uint32_t)) {
		STREAM_BOUND_WARN(s, "get long");
		return 0;
	}

	l = (unsigned)(s->data[s->getp++]) << 24;
	l |= s->data[s->getp++] << 16;
	l |= s->data[s->getp++] << 8;
	l |= s->data[s->getp++];

	return l;
}

/* Get next quad word from the stream. */
uint64_t stream_getq_from(struct stream *s, size_t from)
{
	uint64_t q;

	STREAM_VERIFY_SANE(s);

	if (!GETP_VALID(s, from + sizeof(uint64_t))) {
		STREAM_BOUND_WARN(s, "get quad");
		return 0;
	}

	q = ((uint64_t)s->data[from++]) << 56;
	q |= ((uint64_t)s->data[from++]) << 48;
	q |= ((uint64_t)s->data[from++]) << 40;
	q |= ((uint64_t)s->data[from++]) << 32;
	q |= ((uint64_t)s->data[from++]) << 24;
	q |= ((uint64_t)s->data[from++]) << 16;
	q |= ((uint64_t)s->data[from++]) << 8;
	q |= ((uint64_t)s->data[from++]);

	return q;
}

uint64_t stream_getq(struct stream *s)
{
	uint64_t q;

	STREAM_VERIFY_SANE(s);

	if (STREAM_READABLE(s) < sizeof(uint64_t)) {
		STREAM_BOUND_WARN(s, "get quad");
		return 0;
	}

	q = ((uint64_t)s->data[s->getp++]) << 56;
	q |= ((uint64_t)s->data[s->getp++]) << 48;
	q |= ((uint64_t)s->data[s->getp++]) << 40;
	q |= ((uint64_t)s->data[s->getp++]) << 32;
	q |= ((uint64_t)s->data[s->getp++]) << 24;
	q |= ((uint64_t)s->data[s->getp++]) << 16;
	q |= ((uint64_t)s->data[s->getp++]) << 8;
	q |= ((uint64_t)s->data[s->getp++]);

	return q;
}

/* Get next long word from the stream. */
uint32_t stream_get_ipv4(struct stream *s)
{
	uint32_t l;

	STREAM_VERIFY_SANE(s);

	if (STREAM_READABLE(s) < sizeof(uint32_t)) {
		STREAM_BOUND_WARN(s, "get ipv4");
		return 0;
	}

	memcpy(&l, s->data + s->getp, sizeof(uint32_t));
	s->getp += sizeof(uint32_t);

	return l;
}

float stream_getf(struct stream *s)
{
	union {
		float r;
		uint32_t d;
	} u;
	u.d = stream_getl(s);
	return u.r;
}

double stream_getd(struct stream *s)
{
	union {
		double r;
		uint64_t d;
	} u;
	u.d = stream_getq(s);
	return u.r;
}

/* Copy to source to stream.
 *
 * XXX: This uses CHECK_SIZE and hence has funny semantics -> Size will wrap
 * around. This should be fixed once the stream updates are working.
 *
 * stream_write() is saner
 */
void stream_put(struct stream *s, const void *src, size_t size)
{

	/* XXX: CHECK_SIZE has strange semantics. It should be deprecated */
	CHECK_SIZE(s, size);

	STREAM_VERIFY_SANE(s);

	if (STREAM_WRITEABLE(s) < size) {
		STREAM_BOUND_WARN(s, "put");
		return;
	}

	if (src)
		memcpy(s->data + s->endp, src, size);
	else
		memset(s->data + s->endp, 0, size);

	s->endp += size;
}

/* Put character to the stream. */
int stream_putc(struct stream *s, uint8_t c)
{
	STREAM_VERIFY_SANE(s);

	if (STREAM_WRITEABLE(s) < sizeof(uint8_t)) {
		STREAM_BOUND_WARN(s, "put");
		return 0;
	}

	s->data[s->endp++] = c;
	return sizeof(uint8_t);
}

/* Put word to the stream. */
int stream_putw(struct stream *s, uint16_t w)
{
	STREAM_VERIFY_SANE(s);

	if (STREAM_WRITEABLE(s) < sizeof(uint16_t)) {
		STREAM_BOUND_WARN(s, "put");
		return 0;
	}

	s->data[s->endp++] = (uint8_t)(w >> 8);
	s->data[s->endp++] = (uint8_t)w;

	return 2;
}

/* Put long word to the stream. */
int stream_put3(struct stream *s, uint32_t l)
{
	STREAM_VERIFY_SANE(s);

	if (STREAM_WRITEABLE(s) < 3) {
		STREAM_BOUND_WARN(s, "put");
		return 0;
	}

	s->data[s->endp++] = (uint8_t)(l >> 16);
	s->data[s->endp++] = (uint8_t)(l >> 8);
	s->data[s->endp++] = (uint8_t)l;

	return 3;
}

/* Put long word to the stream. */
int stream_putl(struct stream *s, uint32_t l)
{
	STREAM_VERIFY_SANE(s);

	if (STREAM_WRITEABLE(s) < sizeof(uint32_t)) {
		STREAM_BOUND_WARN(s, "put");
		return 0;
	}

	s->data[s->endp++] = (uint8_t)(l >> 24);
	s->data[s->endp++] = (uint8_t)(l >> 16);
	s->data[s->endp++] = (uint8_t)(l >> 8);
	s->data[s->endp++] = (uint8_t)l;

	return 4;
}

/* Put quad word to the stream. */
int stream_putq(struct stream *s, uint64_t q)
{
	STREAM_VERIFY_SANE(s);

	if (STREAM_WRITEABLE(s) < sizeof(uint64_t)) {
		STREAM_BOUND_WARN(s, "put quad");
		return 0;
	}

	s->data[s->endp++] = (uint8_t)(q >> 56);
	s->data[s->endp++] = (uint8_t)(q >> 48);
	s->data[s->endp++] = (uint8_t)(q >> 40);
	s->data[s->endp++] = (uint8_t)(q >> 32);
	s->data[s->endp++] = (uint8_t)(q >> 24);
	s->data[s->endp++] = (uint8_t)(q >> 16);
	s->data[s->endp++] = (uint8_t)(q >> 8);
	s->data[s->endp++] = (uint8_t)q;

	return 8;
}

int stream_putf(struct stream *s, float f)
{
	union {
		float i;
		uint32_t o;
	} u;
	u.i = f;
	return stream_putl(s, u.o);
}

int stream_putd(struct stream *s, double d)
{
	union {
		double i;
		uint64_t o;
	} u;
	u.i = d;
	return stream_putq(s, u.o);
}

int stream_putc_at(struct stream *s, size_t putp, uint8_t c)
{
	STREAM_VERIFY_SANE(s);

	if (!PUT_AT_VALID(s, putp + sizeof(uint8_t))) {
		STREAM_BOUND_WARN(s, "put");
		return 0;
	}

	s->data[putp] = c;

	return 1;
}

int stream_putw_at(struct stream *s, size_t putp, uint16_t w)
{
	STREAM_VERIFY_SANE(s);

	if (!PUT_AT_VALID(s, putp + sizeof(uint16_t))) {
		STREAM_BOUND_WARN(s, "put");
		return 0;
	}

	s->data[putp] = (uint8_t)(w >> 8);
	s->data[putp + 1] = (uint8_t)w;

	return 2;
}

int stream_put3_at(struct stream *s, size_t putp, uint32_t l)
{
	STREAM_VERIFY_SANE(s);

	if (!PUT_AT_VALID(s, putp + 3)) {
		STREAM_BOUND_WARN(s, "put");
		return 0;
	}
	s->data[putp] = (uint8_t)(l >> 16);
	s->data[putp + 1] = (uint8_t)(l >> 8);
	s->data[putp + 2] = (uint8_t)l;

	return 3;
}

int stream_putl_at(struct stream *s, size_t putp, uint32_t l)
{
	STREAM_VERIFY_SANE(s);

	if (!PUT_AT_VALID(s, putp + sizeof(uint32_t))) {
		STREAM_BOUND_WARN(s, "put");
		return 0;
	}
	s->data[putp] = (uint8_t)(l >> 24);
	s->data[putp + 1] = (uint8_t)(l >> 16);
	s->data[putp + 2] = (uint8_t)(l >> 8);
	s->data[putp + 3] = (uint8_t)l;

	return 4;
}

int stream_putq_at(struct stream *s, size_t putp, uint64_t q)
{
	STREAM_VERIFY_SANE(s);

	if (!PUT_AT_VALID(s, putp + sizeof(uint64_t))) {
		STREAM_BOUND_WARN(s, "put");
		return 0;
	}
	s->data[putp] = (uint8_t)(q >> 56);
	s->data[putp + 1] = (uint8_t)(q >> 48);
	s->data[putp + 2] = (uint8_t)(q >> 40);
	s->data[putp + 3] = (uint8_t)(q >> 32);
	s->data[putp + 4] = (uint8_t)(q >> 24);
	s->data[putp + 5] = (uint8_t)(q >> 16);
	s->data[putp + 6] = (uint8_t)(q >> 8);
	s->data[putp + 7] = (uint8_t)q;

	return 8;
}

/* Put long word to the stream. */
int stream_put_ipv4(struct stream *s, uint32_t l)
{
	STREAM_VERIFY_SANE(s);

	if (STREAM_WRITEABLE(s) < sizeof(uint32_t)) {
		STREAM_BOUND_WARN(s, "put");
		return 0;
	}
	memcpy(s->data + s->endp, &l, sizeof(uint32_t));
	s->endp += sizeof(uint32_t);

	return sizeof(uint32_t);
}

/* Put long word to the stream. */
int stream_put_in_addr(struct stream *s, struct in_addr *addr)
{
	STREAM_VERIFY_SANE(s);

	if (STREAM_WRITEABLE(s) < sizeof(uint32_t)) {
		STREAM_BOUND_WARN(s, "put");
		return 0;
	}

	memcpy(s->data + s->endp, addr, sizeof(uint32_t));
	s->endp += sizeof(uint32_t);

	return sizeof(uint32_t);
}

/* Put in_addr at location in the stream. */
int stream_put_in_addr_at(struct stream *s, size_t putp, struct in_addr *addr)
{
	STREAM_VERIFY_SANE(s);

	if (!PUT_AT_VALID(s, putp + 4)) {
		STREAM_BOUND_WARN(s, "put");
		return 0;
	}

	memcpy(&s->data[putp], addr, 4);
	return 4;
}

/* Put in6_addr at location in the stream. */
int stream_put_in6_addr_at(struct stream *s, size_t putp, struct in6_addr *addr)
{
	STREAM_VERIFY_SANE(s);

	if (!PUT_AT_VALID(s, putp + 16)) {
		STREAM_BOUND_WARN(s, "put");
		return 0;
	}

	memcpy(&s->data[putp], addr, 16);
	return 16;
}

/* Put prefix by nlri type format. */
int stream_put_prefix_addpath(struct stream *s, struct prefix *p,
			      int addpath_encode, uint32_t addpath_tx_id)
{
	size_t psize;
	size_t psize_with_addpath;

	STREAM_VERIFY_SANE(s);

	psize = PSIZE(p->prefixlen);

	if (addpath_encode)
		psize_with_addpath = psize + 4;
	else
		psize_with_addpath = psize;

	if (STREAM_WRITEABLE(s) < (psize_with_addpath + sizeof(uint8_t))) {
		STREAM_BOUND_WARN(s, "put");
		return 0;
	}

	if (addpath_encode) {
		s->data[s->endp++] = (uint8_t)(addpath_tx_id >> 24);
		s->data[s->endp++] = (uint8_t)(addpath_tx_id >> 16);
		s->data[s->endp++] = (uint8_t)(addpath_tx_id >> 8);
		s->data[s->endp++] = (uint8_t)addpath_tx_id;
	}

	s->data[s->endp++] = p->prefixlen;
	memcpy(s->data + s->endp, &p->u.prefix, psize);
	s->endp += psize;

	return psize;
}

int stream_put_prefix(struct stream *s, struct prefix *p)
{
	return stream_put_prefix_addpath(s, p, 0, 0);
}

/* Put NLRI with label */
int stream_put_labeled_prefix(struct stream *s, struct prefix *p,
			      mpls_label_t *label)
{
	size_t psize;
	uint8_t *label_pnt = (uint8_t *)label;

	STREAM_VERIFY_SANE(s);

	psize = PSIZE(p->prefixlen);

	if (STREAM_WRITEABLE(s) < (psize + 3)) {
		STREAM_BOUND_WARN(s, "put");
		return 0;
	}

	stream_putc(s, (p->prefixlen + 24));
	stream_putc(s, label_pnt[0]);
	stream_putc(s, label_pnt[1]);
	stream_putc(s, label_pnt[2]);
	memcpy(s->data + s->endp, &p->u.prefix, psize);
	s->endp += psize;

	return (psize + 3);
}

/* Read size from fd. */
int stream_read(struct stream *s, int fd, size_t size)
{
	int nbytes;

	STREAM_VERIFY_SANE(s);

	if (STREAM_WRITEABLE(s) < size) {
		STREAM_BOUND_WARN(s, "put");
		return 0;
	}

	nbytes = readn(fd, s->data + s->endp, size);

	if (nbytes > 0)
		s->endp += nbytes;

	return nbytes;
}

ssize_t stream_read_try(struct stream *s, int fd, size_t size)
{
	ssize_t nbytes;

	STREAM_VERIFY_SANE(s);

	if (STREAM_WRITEABLE(s) < size) {
		STREAM_BOUND_WARN(s, "put");
		/* Fatal (not transient) error, since retrying will not help
		   (stream is too small to contain the desired data). */
		return -1;
	}

	if ((nbytes = read(fd, s->data + s->endp, size)) >= 0) {
		s->endp += nbytes;
		return nbytes;
	}
	/* Error: was it transient (return -2) or fatal (return -1)? */
	if (ERRNO_IO_RETRY(errno))
		return -2;
	zlog_warn("%s: read failed on fd %d: %s", __func__, fd,
		  safe_strerror(errno));
	return -1;
}

/* Read up to size bytes into the stream from the fd, using recvmsgfrom
 * whose arguments match the remaining arguments to this function
 */
ssize_t stream_recvfrom(struct stream *s, int fd, size_t size, int flags,
			struct sockaddr *from, socklen_t *fromlen)
{
	ssize_t nbytes;

	STREAM_VERIFY_SANE(s);

	if (STREAM_WRITEABLE(s) < size) {
		STREAM_BOUND_WARN(s, "put");
		/* Fatal (not transient) error, since retrying will not help
		   (stream is too small to contain the desired data). */
		return -1;
	}

	if ((nbytes = recvfrom(fd, s->data + s->endp, size, flags, from,
			       fromlen))
	    >= 0) {
		s->endp += nbytes;
		return nbytes;
	}
	/* Error: was it transient (return -2) or fatal (return -1)? */
	if (ERRNO_IO_RETRY(errno))
		return -2;
	zlog_warn("%s: read failed on fd %d: %s", __func__, fd,
		  safe_strerror(errno));
	return -1;
}

/* Read up to smaller of size or SIZE_REMAIN() bytes to the stream, starting
 * from endp.
 * First iovec will be used to receive the data.
 * Stream need not be empty.
 */
ssize_t stream_recvmsg(struct stream *s, int fd, struct msghdr *msgh, int flags,
		       size_t size)
{
	int nbytes;
	struct iovec *iov;

	STREAM_VERIFY_SANE(s);
	assert(msgh->msg_iovlen > 0);

	if (STREAM_WRITEABLE(s) < size) {
		STREAM_BOUND_WARN(s, "put");
		/* This is a logic error in the calling code: the stream is too
		   small
		   to hold the desired data! */
		return -1;
	}

	iov = &(msgh->msg_iov[0]);
	iov->iov_base = (s->data + s->endp);
	iov->iov_len = size;

	nbytes = recvmsg(fd, msgh, flags);

	if (nbytes > 0)
		s->endp += nbytes;

	return nbytes;
}

/* Write data to buffer. */
size_t stream_write(struct stream *s, const void *ptr, size_t size)
{

	CHECK_SIZE(s, size);

	STREAM_VERIFY_SANE(s);

	if (STREAM_WRITEABLE(s) < size) {
		STREAM_BOUND_WARN(s, "put");
		return 0;
	}

	memcpy(s->data + s->endp, ptr, size);
	s->endp += size;

	return size;
}

/* Return current read pointer.
 * DEPRECATED!
 * Use stream_get_pnt_to if you must, but decoding streams properly
 * is preferred
 */
uint8_t *stream_pnt(struct stream *s)
{
	STREAM_VERIFY_SANE(s);
	return s->data + s->getp;
}

/* Check does this stream empty? */
int stream_empty(struct stream *s)
{
	STREAM_VERIFY_SANE(s);

	return (s->endp == 0);
}

/* Reset stream. */
void stream_reset(struct stream *s)
{
	STREAM_VERIFY_SANE(s);

	s->getp = s->endp = 0;
}

/* Write stream contens to the file discriptor. */
int stream_flush(struct stream *s, int fd)
{
	int nbytes;

	STREAM_VERIFY_SANE(s);

	nbytes = write(fd, s->data + s->getp, s->endp - s->getp);

	return nbytes;
}

/* Stream first in first out queue. */

struct stream_fifo *stream_fifo_new(void)
{
	struct stream_fifo *new;

	new = XCALLOC(MTYPE_STREAM_FIFO, sizeof(struct stream_fifo));
	pthread_mutex_init(&new->mtx, NULL);
	return new;
}

/* Add new stream to fifo. */
void stream_fifo_push(struct stream_fifo *fifo, struct stream *s)
{
#if defined DEV_BUILD
	size_t max, curmax;
#endif

	if (fifo->tail)
		fifo->tail->next = s;
	else
		fifo->head = s;

	fifo->tail = s;
	fifo->tail->next = NULL;
#if !defined DEV_BUILD
	atomic_fetch_add_explicit(&fifo->count, 1, memory_order_release);
#else
	max = atomic_fetch_add_explicit(&fifo->count, 1, memory_order_release);
	curmax = atomic_load_explicit(&fifo->max_count, memory_order_relaxed);
	if (max > curmax)
		atomic_store_explicit(&fifo->max_count, max,
				      memory_order_relaxed);
#endif
}

void stream_fifo_push_safe(struct stream_fifo *fifo, struct stream *s)
{
	pthread_mutex_lock(&fifo->mtx);
	{
		stream_fifo_push(fifo, s);
	}
	pthread_mutex_unlock(&fifo->mtx);
}

/* Delete first stream from fifo. */
struct stream *stream_fifo_pop(struct stream_fifo *fifo)
{
	struct stream *s;

	s = fifo->head;

	if (s) {
		fifo->head = s->next;

		if (fifo->head == NULL)
			fifo->tail = NULL;

		atomic_fetch_sub_explicit(&fifo->count, 1,
					  memory_order_release);

		/* ensure stream is scrubbed of references to this fifo */
		s->next = NULL;
	}

	return s;
}

struct stream *stream_fifo_pop_safe(struct stream_fifo *fifo)
{
	struct stream *ret;

	pthread_mutex_lock(&fifo->mtx);
	{
		ret = stream_fifo_pop(fifo);
	}
	pthread_mutex_unlock(&fifo->mtx);

	return ret;
}

struct stream *stream_fifo_head(struct stream_fifo *fifo)
{
	return fifo->head;
}

struct stream *stream_fifo_head_safe(struct stream_fifo *fifo)
{
	struct stream *ret;

	pthread_mutex_lock(&fifo->mtx);
	{
		ret = stream_fifo_head(fifo);
	}
	pthread_mutex_unlock(&fifo->mtx);

	return ret;
}

void stream_fifo_clean(struct stream_fifo *fifo)
{
	struct stream *s;
	struct stream *next;

	for (s = fifo->head; s; s = next) {
		next = s->next;
		stream_free(s);
	}
	fifo->head = fifo->tail = NULL;
	atomic_store_explicit(&fifo->count, 0, memory_order_release);
}

void stream_fifo_clean_safe(struct stream_fifo *fifo)
{
	pthread_mutex_lock(&fifo->mtx);
	{
		stream_fifo_clean(fifo);
	}
	pthread_mutex_unlock(&fifo->mtx);
}

size_t stream_fifo_count_safe(struct stream_fifo *fifo)
{
	return atomic_load_explicit(&fifo->count, memory_order_acquire);
}

void stream_fifo_free(struct stream_fifo *fifo)
{
	stream_fifo_clean(fifo);
	pthread_mutex_destroy(&fifo->mtx);
	XFREE(MTYPE_STREAM_FIFO, fifo);
}
