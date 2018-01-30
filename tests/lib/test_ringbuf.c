/*
 * Circular buffer tests.
 * Copyright (C) 2017  Cumulus Networks
 * Quentin Young
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>
#include <memory.h>
#include "ringbuf.h"

static void validate_state(struct ringbuf *buf, size_t size, size_t contains)
{
	assert(buf->size == size);
	assert(ringbuf_remain(buf) == contains);
	assert(ringbuf_space(buf) == buf->size - contains);
	assert(buf->empty != (bool)contains);
}

int main(int argc, char **argv)
{
	struct ringbuf *soil = ringbuf_new(BUFSIZ);

	validate_state(soil, BUFSIZ, 0);

	/* verify reset functionality on clean buffer */
	printf("Validating reset on empty buffer...\n");
	ringbuf_reset(soil);

	validate_state(soil, BUFSIZ, 0);

	/* put one byte */
	printf("Validating write...\n");
	uint8_t walnut = 47;
	assert(ringbuf_put(soil, &walnut, sizeof(walnut)) == 1);

	validate_state(soil, BUFSIZ, 1);

	/* validate read limitations */
	printf("Validating read limits...\n");
	uint8_t nuts[2];
	assert(ringbuf_get(soil, &nuts, sizeof(nuts)) == 1);

	/* reset */
	printf("Validating reset on full buffer...\n");
	ringbuf_reset(soil);
	validate_state(soil, BUFSIZ, 0);

	/* copy stack garbage to buffer */
	printf("Validating big write...\n");
	uint8_t compost[BUFSIZ];
	assert(ringbuf_put(soil, &compost, sizeof(compost)) == BUFSIZ);

	validate_state(soil, BUFSIZ, BUFSIZ);
	assert(soil->start == 0);
	assert(soil->end == 0);

	/* read 15 bytes of garbage */
	printf("Validating read...\n");
	assert(ringbuf_get(soil, &compost, 15) == 15);

	validate_state(soil, BUFSIZ, BUFSIZ - 15);
	assert(soil->start == 15);
	assert(soil->end == 0);

	/* put another 10 bytes and validate wraparound */
	printf("Validating wraparound...\n");
	assert(ringbuf_put(soil, &compost[BUFSIZ/2], 10) == 10);

	validate_state(soil, BUFSIZ, BUFSIZ - 15 + 10);
	assert(soil->start == 15);
	assert(soil->end == 10);

	/* put another 15 bytes and validate state */
	printf("Validating size limits...\n");
	assert(ringbuf_put(soil, &compost, 15) == 5);
	validate_state(soil, BUFSIZ, BUFSIZ);

	/* read entire buffer */
	printf("Validating big read...\n");
	assert(ringbuf_get(soil, &compost, BUFSIZ) == BUFSIZ);

	validate_state(soil, BUFSIZ, 0);
	assert(soil->empty = true);
	assert(soil->start == soil->end);
	assert(soil->start == 15);

	/* read empty buffer */
	printf("Validating empty read...\n");
	assert(ringbuf_get(soil, &compost, 1) == 0);
	validate_state(soil, BUFSIZ, 0);

	/* reset, validate state */
	printf("Validating reset...\n");
	ringbuf_reset(soil);
	validate_state(soil, BUFSIZ, 0);
	assert(soil->start == 0);
	assert(soil->end == 0);

	/* wipe, validate state */
	printf("Validating wipe...\n");
	memset(&compost, 0x00, sizeof(compost));
	ringbuf_wipe(soil);
	assert(memcmp(&compost, soil->data, sizeof(compost)) == 0);

	/* validate maximum write */
	printf("Validating very big write...\n");
	const char flower[BUFSIZ * 2];
	assert(ringbuf_put(soil, &flower, sizeof(flower)) == BUFSIZ);

	validate_state(soil, BUFSIZ, BUFSIZ);

	/* wipe, validate state */
	printf("Validating wipe...\n");
	memset(&compost, 0x00, sizeof(compost));
	ringbuf_wipe(soil);
	assert(memcmp(&compost, soil->data, sizeof(compost)) == 0);

	/* validate simple data encode / decode */
	const char *organ = "seed";
	printf("Encoding: '%s'\n", organ);
	assert(ringbuf_put(soil, organ, strlen(organ)) == 4);
	char water[strlen(organ) + 1];
	assert(ringbuf_get(soil, &water, strlen(organ)) == 4);
	water[strlen(organ)] = '\0';
	printf("Retrieved: '%s'\n", water);

	validate_state(soil, BUFSIZ, 0);

	/* validate simple data encode / decode across ring boundary */
	soil->start = soil->size - 2;
	soil->end = soil->start;
	const char *phloem = "root";
	printf("Encoding: '%s'\n", phloem);
	assert(ringbuf_put(soil, phloem, strlen(phloem)) == 4);
	char xylem[strlen(phloem) + 1];
	assert(ringbuf_get(soil, &xylem, 100) == 4);
	xylem[strlen(phloem)] = '\0';
	printf("Retrieved: '%s'\n", xylem);

	ringbuf_wipe(soil);

	/* validate simple data peek across ring boundary */
	soil->start = soil->size - 2;
	soil->end = soil->start;
	const char *cytoplasm = "tree";
	printf("Encoding: '%s'\n", cytoplasm);
	assert(ringbuf_put(soil, cytoplasm, strlen(cytoplasm)) == 4);
	char chloroplast[strlen(cytoplasm) + 1];
	assert(ringbuf_peek(soil, 2, &chloroplast[0], 100) == 2);
	assert(ringbuf_peek(soil, 0, &chloroplast[2], 2) == 2);
	chloroplast[strlen(cytoplasm)] = '\0';
	assert(!strcmp(chloroplast, "eetr"));
	printf("Retrieved: '%s'\n", chloroplast);

	printf("Deleting...\n");
	ringbuf_del(soil);

	printf("Creating new buffer...\n");
	soil = ringbuf_new(15);
	soil->start = soil->end = 7;

	/* validate data encode of excessive data */
	const char *twenty = "vascular plants----";
	char sixteen[16];
	printf("Encoding: %s\n", twenty);
	assert(ringbuf_put(soil, twenty, strlen(twenty)) == 15);
	assert(ringbuf_get(soil, sixteen, 20));
	sixteen[15] = '\0';
	printf("Retrieved: %s\n", sixteen);
	assert(!strcmp(sixteen, "vascular plants"));

	printf("Deleting...\n");
	ringbuf_del(soil);

	printf("Done.\n");
	return 0;
}
