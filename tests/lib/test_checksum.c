// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2008 Sun Microsystems, Inc.
 */

#include <zebra.h>
#include <stdlib.h>
#include <time.h>

#include "checksum.h"
#include "network.h"
#include "prng.h"

struct event_loop *master;

struct acc_vals {
	int c0;
	int c1;
};

struct csum_vals {
	struct acc_vals a;
	int x;
	int y;
};

static struct csum_vals ospfd_vals, isisd_vals;

typedef size_t testsz_t;
typedef uint16_t testoff_t;

/* Fletcher Checksum -- Refer to RFC1008. */
#define MODX                 4102U

/* The final reduction phase.
 * This one should be the original ospfd version
 */
static uint16_t reduce_ospfd(struct csum_vals *vals, testsz_t len,
			     testoff_t off)
{
#define x vals->x
#define y vals->y
#define c0 vals->a.c0
#define c1 vals->a.c1

	x = ((len - off - 1) * c0 - c1) % 255;

	if (x <= 0)
		x += 255;
	y = 510 - c0 - x;
	if (y > 255)
		y -= 255;

	/* take care endian issue. */
	return htons((x << 8) + y);
#undef x
#undef y
#undef c0
#undef c1
}

/* slightly different concatenation */
static uint16_t reduce_ospfd1(struct csum_vals *vals, testsz_t len,
			      testoff_t off)
{
#define x vals->x
#define y vals->y
#define c0 vals->a.c0
#define c1 vals->a.c1

	x = ((len - off - 1) * c0 - c1) % 255;
	if (x <= 0)
		x += 255;
	y = 510 - c0 - x;
	if (y > 255)
		y -= 255;

	/* take care endian issue. */
	return htons((x << 8) | (y & 0xff));
#undef x
#undef y
#undef c0
#undef c1
}

/* original isisd version */
static uint16_t reduce_isisd(struct csum_vals *vals, testsz_t len,
			     testoff_t off)
{
#define x vals->x
#define y vals->y
#define c0 vals->a.c0
#define c1 vals->a.c1
	uint32_t mul;

	mul = (len - off) * (c0);
	x = mul - c0 - c1;
	y = c1 - mul - 1;

	if (y > 0)
		y++;
	if (x < 0)
		x--;

	x %= 255;
	y %= 255;

	if (x == 0)
		x = 255;
	if (y == 0)
		y = 1;

	return htons((x << 8) | (y & 0xff));

#undef x
#undef y
#undef c0
#undef c1
}

/* Is the -1 in y wrong perhaps? */
static uint16_t reduce_isisd_yfix(struct csum_vals *vals, testsz_t len,
				  testoff_t off)
{
#define x vals->x
#define y vals->y
#define c0 vals->a.c0
#define c1 vals->a.c1
	uint32_t mul;

	mul = (len - off) * (c0);
	x = mul - c0 - c1;
	y = c1 - mul;

	if (y > 0)
		y++;
	if (x < 0)
		x--;

	x %= 255;
	y %= 255;

	if (x == 0)
		x = 255;
	if (y == 0)
		y = 1;

	return htons((x << 8) | (y & 0xff));

#undef x
#undef y
#undef c0
#undef c1
}

/* Move the mods yp */
static uint16_t reduce_isisd_mod(struct csum_vals *vals, testsz_t len,
				 testoff_t off)
{
#define x vals->x
#define y vals->y
#define c0 vals->a.c0
#define c1 vals->a.c1
	uint32_t mul;

	mul = (len - off) * (c0);
	x = mul - c1 - c0;
	y = c1 - mul - 1;

	x %= 255;
	y %= 255;

	if (y > 0)
		y++;
	if (x < 0)
		x--;

	if (x == 0)
		x = 255;
	if (y == 0)
		y = 1;

	return htons((x << 8) | (y & 0xff));

#undef x
#undef y
#undef c0
#undef c1
}

/* Move the mods up + fix y */
static uint16_t reduce_isisd_mody(struct csum_vals *vals, testsz_t len,
				  testoff_t off)
{
#define x vals->x
#define y vals->y
#define c0 vals->a.c0
#define c1 vals->a.c1
	uint32_t mul;

	mul = (len - off) * (c0);
	x = mul - c0 - c1;
	y = c1 - mul;

	x %= 255;
	y %= 255;

	if (y > 0)
		y++;
	if (x < 0)
		x--;

	if (x == 0)
		x = 255;
	if (y == 0)
		y = 1;

	return htons((x << 8) | (y & 0xff));

#undef x
#undef y
#undef c0
#undef c1
}

struct reductions_t {
	const char *name;
	uint16_t (*f)(struct csum_vals *, testsz_t, testoff_t);
} reducts[] = {
	{.name = "ospfd", .f = reduce_ospfd},
	{.name = "ospfd-1", .f = reduce_ospfd1},
	{.name = "isisd", .f = reduce_isisd},
	{.name = "isisd-yfix", .f = reduce_isisd_yfix},
	{.name = "isisd-mod", .f = reduce_isisd_mod},
	{.name = "isisd-mody", .f = reduce_isisd_mody},
	{NULL, NULL},
};

/* The original ospfd checksum */
static uint16_t ospfd_checksum(uint8_t *buffer, testsz_t len, testoff_t off)
{
	uint8_t *sp, *ep, *p, *q;
	int c0 = 0, c1 = 0;
	int x, y;
	uint16_t checksum, *csum;

	csum = (uint16_t *)(buffer + off);
	*(csum) = 0;

	sp = buffer;

	for (ep = sp + len; sp < ep; sp = q) {
		q = sp + MODX;
		if (q > ep)
			q = ep;
		for (p = sp; p < q; p++) {
			c0 += *p;
			c1 += c0;
		}
		c0 %= 255;
		c1 %= 255;
	}

	ospfd_vals.a.c0 = c0;
	ospfd_vals.a.c1 = c1;

	// printf ("%s: len %u, off %u, c0 %d, c1 %d\n",
	//        __func__, len, off, c0, c1);

	x = ((int)(len - off - 1) * (int)c0 - (int)c1) % 255;

	if (x <= 0)
		x += 255;
	y = 510 - c0 - x;
	if (y > 255)
		y -= 255;

	ospfd_vals.x = x;
	ospfd_vals.y = y;

	buffer[off] = x;
	buffer[off + 1] = y;

	/* take care endian issue. */
	checksum = htons((x << 8) | (y & 0xff));

	return (checksum);
}

/* the original, broken isisd checksum */
static uint16_t iso_csum_create(uint8_t *buffer, testsz_t len, testoff_t off)
{

	uint8_t *p;
	int x;
	int y;
	uint32_t mul;
	uint32_t c0;
	uint32_t c1;
	uint16_t checksum, *csum;
	int i, init_len, partial_len;

	checksum = 0;

	csum = (uint16_t *)(buffer + off);
	*(csum) = checksum;

	p = buffer;
	c0 = 0;
	c1 = 0;
	init_len = len;

	while (len != 0) {
		partial_len = MIN(len, MODX);

		for (i = 0; i < partial_len; i++) {
			c0 = c0 + *(p++);
			c1 += c0;
		}

		c0 = c0 % 255;
		c1 = c1 % 255;

		len -= partial_len;
	}

	isisd_vals.a.c0 = c0;
	isisd_vals.a.c1 = c1;

	mul = (init_len - off) * c0;

	x = mul - c1 - c0;
	y = c1 - mul - 1;

	if (y > 0)
		y++;
	if (x < 0)
		x--;

	x %= 255;
	y %= 255;

	if (x == 0)
		x = 255;
	if (y == 0)
		y = 1;

	isisd_vals.x = x;
	isisd_vals.y = y;

	checksum = htons((x << 8) | (y & 0xFF));

	*(csum) = checksum;

	/* return the checksum for user usage */
	return checksum;
}

static int verify(uint8_t *buffer, testsz_t len)
{
	uint8_t *p;
	uint32_t c0;
	uint32_t c1;
	int i, partial_len;

	p = buffer;

	c0 = 0;
	c1 = 0;

	while (len) {
		partial_len = MIN(len, 5803U);

		for (i = 0; i < partial_len; i++) {
			c0 = c0 + *(p++);
			c1 += c0;
		}
		c0 = c0 % 255;
		c1 = c1 % 255;

		len -= partial_len;
	}

	if (c0 == 0 && c1 == 0)
		return 0;

	return 1;
}

static int /* return checksum in low-order 16 bits */
	in_cksum_optimized(void *parg, int nbytes)
{
	unsigned short *ptr = parg;
	register long sum;       /* assumes long == 32 bits */
	register unsigned short answer; /* assumes unsigned short == 16 bits */
	register int count;
	/*
	 * Our algorithm is simple, using a 32-bit accumulator (sum),
	 * we add sequential 16-bit words to it, and at the end, fold back
	 * all the carry bits from the top 16 bits into the lower 16 bits.
	 */

	sum = 0;
	count = nbytes >> 1; /* div by 2 */
	for (ptr--; count; --count)
		sum += *++ptr;

	if (nbytes & 1)			   /* Odd */
		sum += *(uint8_t *)(++ptr); /* one byte only */

	/*
	 * Add back carry outs from top 16 bits to low 16 bits.
	 */

	sum = (sum >> 16) + (sum & 0xffff); /* add high-16 to low-16 */
	sum += (sum >> 16);		    /* add carry */
	answer = ~sum; /* ones-complement, then truncate to 16 bits */
	return (answer);
}


static int /* return checksum in low-order 16 bits */
	in_cksum_rfc(void *parg, int count)
/* from RFC 1071 */
{
	unsigned short *addr = parg;
	/* Compute Internet Checksum for "count" bytes
	 *         beginning at location "addr".
	 */
	register long sum = 0;

	while (count > 1) {
		/*  This is the inner loop */
		sum += *addr++;
		count -= 2;
	}
	/*  Add left-over byte, if any */
	if (count > 0) {
		sum += *(uint8_t *)addr;
	}

	/*  Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}


int main(int argc, char **argv)
{
/* 60017 65629 702179 */
#define MAXDATALEN 60017
#define BUFSIZE MAXDATALEN + sizeof(uint16_t)
	uint8_t buffer[BUFSIZE];
	int exercise = 0;
#define EXERCISESTEP 257
	struct prng *prng = prng_new(0);

	while (1) {
		uint16_t ospfd, isisd, lib, in_csum, in_csum_res, in_csum_rfc;
		int i;

		exercise += EXERCISESTEP;
		exercise %= MAXDATALEN;

		printf("\rexercising length %d\033[K", exercise);

		for (i = 0; i < exercise; i++)
			buffer[i] = prng_rand(prng);

		in_csum = in_cksum(buffer, exercise);
		in_csum_res = in_cksum_optimized(buffer, exercise);
		in_csum_rfc = in_cksum_rfc(buffer, exercise);
		if (in_csum_res != in_csum || in_csum != in_csum_rfc)
			printf("\nverify: in_chksum failed in_csum:%x, in_csum_res:%x,in_csum_rfc %x, len:%d\n",
			       in_csum, in_csum_res, in_csum_rfc, exercise);

		struct iovec iov[3];
		uint16_t in_csum_iov;

		iov[0].iov_base = buffer;
		iov[0].iov_len = exercise / 2;
		iov[1].iov_base = buffer + iov[0].iov_len;
		iov[1].iov_len = exercise - iov[0].iov_len;

		in_csum_iov = in_cksumv(iov, 2);
		if (in_csum_iov != in_csum)
			printf("\nverify: in_cksumv failed, lens: %zu+%zu\n",
			       iov[0].iov_len, iov[1].iov_len);

		if (exercise >= 6) {
			/* force split with byte leftover */
			iov[0].iov_base = buffer;
			iov[0].iov_len = (exercise / 2) | 1;
			iov[1].iov_base = buffer + iov[0].iov_len;
			iov[1].iov_len = 2;
			iov[2].iov_base = buffer + iov[0].iov_len + 2;
			iov[2].iov_len = exercise - iov[0].iov_len - 2;

			in_csum_iov = in_cksumv(iov, 3);
			if (in_csum_iov != in_csum)
				printf("\nverify: in_cksumv failed, lens: %zu+%zu+%zu, got %04x, expected %04x\n",
				       iov[0].iov_len, iov[1].iov_len,
				       iov[2].iov_len, in_csum_iov, in_csum);

			/* force split without byte leftover */
			iov[0].iov_base = buffer;
			iov[0].iov_len = (exercise / 2) & ~1UL;
			iov[1].iov_base = buffer + iov[0].iov_len;
			iov[1].iov_len = 2;
			iov[2].iov_base = buffer + iov[0].iov_len + 2;
			iov[2].iov_len = exercise - iov[0].iov_len - 2;

			in_csum_iov = in_cksumv(iov, 3);
			if (in_csum_iov != in_csum)
				printf("\nverify: in_cksumv failed, lens: %zu+%zu+%zu, got %04x, expected %04x\n",
				       iov[0].iov_len, iov[1].iov_len,
				       iov[2].iov_len, in_csum_iov, in_csum);
		}

		if (exercise >= FLETCHER_CHECKSUM_VALIDATE)
			continue;

		ospfd = ospfd_checksum(buffer, exercise + sizeof(uint16_t),
				       exercise);
		if (verify(buffer, exercise + sizeof(uint16_t)))
			printf("\nverify: ospfd failed\n");
		isisd = iso_csum_create(buffer, exercise + sizeof(uint16_t),
					exercise);
		if (verify(buffer, exercise + sizeof(uint16_t)))
			printf("\nverify: isisd failed\n");
		lib = fletcher_checksum(buffer, exercise + sizeof(uint16_t),
					exercise);
		if (verify(buffer, exercise + sizeof(uint16_t)))
			printf("\nverify: lib failed\n");

		if (ospfd != lib) {
			printf("\nMismatch in values at size %d\n"
			       "ospfd: 0x%04x\tc0: %d\tc1: %d\tx: %d\ty: %d\n"
			       "isisd: 0x%04x\tc0: %d\tc1: %d\tx: %d\ty: %d\n"
			       "lib: 0x%04x\n",
			       exercise, ospfd, ospfd_vals.a.c0,
			       ospfd_vals.a.c1, ospfd_vals.x, ospfd_vals.y,
			       isisd, isisd_vals.a.c0, isisd_vals.a.c1,
			       isisd_vals.x, isisd_vals.y, lib);

			/* Investigate reduction phase discrepencies */
			if (ospfd_vals.a.c0 == isisd_vals.a.c0
			    && ospfd_vals.a.c1 == isisd_vals.a.c1) {
				printf("\n");
				for (i = 0; reducts[i].name != NULL; i++) {
					ospfd = reducts[i].f(
						&ospfd_vals,
						exercise + sizeof(uint16_t),
						exercise);
					printf("%20s: x: %02x, y %02x, checksum 0x%04x\n",
					       reducts[i].name,
					       ospfd_vals.x & 0xff,
					       ospfd_vals.y & 0xff, ospfd);
				}
			}

			printf("\n  uint8_t testdata [] = {\n  ");
			for (i = 0; i < exercise; i++) {
				printf("0x%02x,%s", buffer[i],
				       (i + 1) % 8 ? " " : "\n  ");
			}
			printf("\n}\n");
			exit(1);
		}
	}
}
