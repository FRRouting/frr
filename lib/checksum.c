// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Checksum routine for Internet Protocol family headers (C Version).
 *
 * Refer to "Computing the Internet Checksum" by R. Braden, D. Borman and
 * C. Partridge, Computer Communication Review, Vol. 19, No. 2, April 1989,
 * pp. 86-101, for additional details on computing this checksum.
 */

#include <zebra.h>
#include "checksum.h"

#define add_carry(dst, add)                                                    \
	do {                                                                   \
		typeof(dst) _add = (add);                                      \
		dst += _add;                                                   \
		if (dst < _add)                                                \
			dst++;                                                 \
	} while (0)

uint16_t in_cksumv(const struct iovec *iov, size_t iov_len)
{
	const struct iovec *iov_end;
	uint32_t sum = 0;

	union {
		uint8_t bytes[2];
		uint16_t word;
	} wordbuf;
	bool have_oddbyte = false;

	/*
	 * Our algorithm is simple, using a 32-bit accumulator (sum),
	 * we add sequential 16-bit words to it, and at the end, fold back
	 * all the carry bits from the top 16 bits into the lower 16 bits.
	 */

	for (iov_end = iov + iov_len; iov < iov_end; iov++) {
		const uint8_t *ptr, *end;

		ptr = (const uint8_t *)iov->iov_base;
		end = ptr + iov->iov_len;
		if (ptr == end)
			continue;

		if (have_oddbyte) {
			have_oddbyte = false;
			wordbuf.bytes[1] = *ptr++;

			add_carry(sum, wordbuf.word);
		}

		while (ptr + 8 <= end) {
			add_carry(sum, *(const uint32_t *)(ptr + 0));
			add_carry(sum, *(const uint32_t *)(ptr + 4));
			ptr += 8;
		}

		while (ptr + 2 <= end) {
			add_carry(sum, *(const uint16_t *)ptr);
			ptr += 2;
		}

		if (ptr + 1 <= end) {
			wordbuf.bytes[0] = *ptr++;
			have_oddbyte = true;
		}
	}

	/* mop up an odd byte, if necessary */
	if (have_oddbyte) {
		wordbuf.bytes[1] = 0;
		add_carry(sum, wordbuf.word);
	}

	/*
	 * Add back carry outs from top 16 bits to low 16 bits.
	 */

	sum = (sum >> 16) + (sum & 0xffff); /* add high-16 to low-16 */
	sum += (sum >> 16);		    /* add carry */
	return ~sum;
}

/* Fletcher Checksum -- Refer to RFC1008. */
#define MODX                 4102U   /* 5802 should be fine */

/* To be consistent, offset is 0-based index, rather than the 1-based
   index required in the specification ISO 8473, Annex C.1 */
/* calling with offset == FLETCHER_CHECKSUM_VALIDATE will validate the checksum
   without modifying the buffer; a valid checksum returns 0 */
uint16_t fletcher_checksum(uint8_t *buffer, const size_t len,
			   const uint16_t offset)
{
	uint8_t *p;
	int x, y, c0, c1;
	uint16_t checksum = 0;
	uint16_t *csum;
	size_t partial_len, i, left = len;

	if (offset != FLETCHER_CHECKSUM_VALIDATE)
	/* Zero the csum in the packet. */
	{
		assert(offset
		       < (len - 1)); /* account for two bytes of checksum */
		csum = (uint16_t *)(buffer + offset);
		*(csum) = 0;
	}

	p = buffer;
	c0 = 0;
	c1 = 0;

	while (left != 0) {
		partial_len = MIN(left, MODX);

		for (i = 0; i < partial_len; i++) {
			c0 = c0 + *(p++);
			c1 += c0;
		}

		c0 = c0 % 255;
		c1 = c1 % 255;

		left -= partial_len;
	}

	/* The cast is important, to ensure the mod is taken as a signed value.
	 */
	x = (int)((len - offset - 1) * c0 - c1) % 255;

	if (x <= 0)
		x += 255;
	y = 510 - c0 - x;
	if (y > 255)
		y -= 255;

	if (offset == FLETCHER_CHECKSUM_VALIDATE) {
		checksum = (c1 << 8) + c0;
	} else {
		/*
		 * Now we write this to the packet.
		 * We could skip this step too, since the checksum returned
		 * would
		 * be stored into the checksum field by the caller.
		 */
		buffer[offset] = x;
		buffer[offset + 1] = y;

		/* Take care of the endian issue */
		checksum = htons((x << 8) | (y & 0xFF));
	}

	return checksum;
}
