// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 23 2023, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 *
 */
#include <zebra.h>
#include "darr.h"

/*
 * Public functions to test:
 * [x] - darr_append
 * [x] - darr_append_n
 * [x] - darr_append_nz
 * [x] - darr_cap
 * [-] - darr_ensure_cap
 * [x] - darr_ensure_i
 * [x] - darr_foreach_i
 * [x] - darr_foreach_p
 * [x] - darr_free
 * [x] - darr_insert
 * [ ] - darr_insertz
 * [x] - darr_insert_n
 * [x] - darr_insert_nz
 * [x] - darr_maxi
 * [x] - darr_pop
 * [x] - darr_push
 * [ ] - darr_pushz
 * [x] - darr_remove
 * [x] - darr_remove_n
 * [x] - darr_reset
 * [x] - darr_setlen
 */

static void test_int(void)
{
	int z105[105] = {0};
	int a1[] = {0, 1, 2, 3, 4};
	int a2[] = {4, 3, 2, 1, 0};
	int *da1 = NULL;
	int *da2 = NULL;
	int *dap;
	uint i;

	darr_ensure_i(da1, 0);
	da1[0] = 0;
	assert(darr_len(da1) == 1);
	assert(darr_cap(da1) == 1);

	*darr_ensure_i(da1, 1) = 1;
	assert(darr_len(da1) == 2);
	assert(darr_cap(da1) == 2);

	darr_ensure_i(da1, 4);
	darr_foreach_i (da1, i)
		da1[i] = i;

	assert(darr_len(da1) == 5);
	/* minimum non-pow2 array size for long long and smaller */
	assert(darr_cap(da1) == 8);
	assert(!memcmp(da1, a1, sizeof(a1)));

	/* reverse the numbers */
	darr_foreach_p (da1, dap)
		*dap = darr_end(da1) - dap - 1;
	assert(!memcmp(da1, a2, sizeof(a2)));

	darr_append_n(da1, 100);
	darr_foreach_p (da1, dap)
		*dap = darr_end(da1) - dap - 1;

	darr_pop_n(da1, 100);
	darr_append_nz(da1, 100);
	assert(!memcmp(&da1[5], z105, _darr_esize(da1) * 100));

	assert(darr_len(da1) == 105);
	assert(darr_maxi(da1) == 127);
	assert(darr_cap(da1) == 128);

	darr_setlen(da1, 102);
	assert(darr_len(da1) == 102);
	assert(darr_maxi(da1) == 127);

	int a3[] = { 0xdeadbeaf, 0x12345678 };

	da1[0] = a3[0];
	da1[101] = a3[1];
	darr_remove_n(da1, 1, 100);
	assert(darr_len(da1) == array_size(a3));
	assert(!memcmp(da1, a3, sizeof(a3)));

	da1[0] = a3[1];
	da1[1] = a3[0];

	darr_insert_n(da1, 1, 100);
	assert(darr_len(da1) == 102);
	assert(da1[0] == a3[1]);
	assert(da1[101] == a3[0]);

	darr_reset(da1);
	assert(darr_len(da1) == 0);
	assert(darr_maxi(da1) == 127);
	assert(darr_cap(da1) == 128);

	/* we touch the length field of the freed block here somehow */
	darr_insert_n(da1, 100, 300);
	assert(darr_len(da1) == 400);
	assert(darr_cap(da1) == 512);

	da1[400 - 1] = 0x0BAD;
	*darr_insert(da1, 0) = 0xF00D;
	assert(da1[0] == 0xF00D);
	assert(da1[400] == 0x0BAD);
	assert(darr_len(da1) == 401);
	assert(darr_cap(da1) == 512);

	darr_free(da1);
	assert(da1 == NULL);
	assert(darr_len(da1) == 0);
	darr_setlen(da1, 0);
	darr_reset(da1);
	darr_free(da1);

	*darr_append(da2) = 0;
	*darr_append(da2) = 1;
	darr_push(da2, 2);
	darr_push(da2, 3);
	darr_push(da2, 4);

	assert(!memcmp(da2, a1, sizeof(a1)));

	assert(darr_pop(da2) == 4);
	assert(darr_pop(da2) == 3);
	assert(darr_pop(da2) == 2);
	assert(darr_len(da2) == 2);
	assert(darr_pop(da2) == 1);
	assert(darr_pop(da2) == 0);
	assert(darr_len(da2) == 0);

	darr_free(da2);
}

static void test_struct(void)
{
	/*
	 *uwould like to use different sizes with padding but memcmp can't be
	 *used then.
	 */
	struct st {
		long long a;
		long long b;
	};
	struct st z102[102] = {{0, 0}};
	struct st *da1 = NULL;
	struct st *da2 = NULL;
	struct st a1[] = {
		{0, 0}, {1, 1}, {2, 2}, {3, 3}, {4, 4},
	};
	uint i;

	darr_ensure_i(da1, 0);
	da1[0].a = 0;
	da1[0].b = 0;
	assert(darr_len(da1) == 1);
	assert(darr_cap(da1) == 1);

	darr_ensure_i(da1, 1)->a = 1;
	darr_ensure_i(da1, 1)->b = 1;
	assert(darr_len(da1) == 2);
	assert(darr_cap(da1) == 2);

	darr_ensure_i(da1, 4);
	da1[2].a = 2;
	da1[2].b = 2;

	da1[3].a = 3;
	da1[3].b = 3;

	da1[4].a = 4;
	da1[4].b = 4;

	assert(darr_len(da1) == 5);
	/* minimum non-pow2 array size for long long and smaller */
	assert(darr_cap(da1) == 8);
	assert(!memcmp(da1, a1, sizeof(a1)));

	darr_append_n(da1, 100);

	assert(darr_len(da1) == 105);
	assert(darr_maxi(da1) == 127);
	assert(darr_cap(da1) == 128);

	darr_setlen(da1, 102);
	assert(darr_len(da1) == 102);
	assert(darr_maxi(da1) == 127);

	struct st a2[] = {
		{0xdeadbeaf, 0xdeadbeaf},
		{0x12345678, 0x12345678},
	};
	da1[0] = a2[0];
	da1[101] = a2[1];
	darr_remove_n(da1, 1, 100);
	assert(darr_len(da1) == array_size(a2));
	assert(!memcmp(da1, a2, sizeof(a2)));

	da1[0] = a2[1];
	da1[1] = a2[0];

	darr_insert_n(da1, 1, 100);
	assert(darr_len(da1) == 102);
	darr_foreach_i (da1, i) {
		da1[i].a = i;
		da1[i].b = i;
	}
	darr_remove_n(da1, 1, 100);
	assert(darr_len(da1) == 2);
	darr_insert_nz(da1, 1, 100);
	assert(!memcmp(&da1[1], z102, 100 * sizeof(da1[0])));
	/* assert(da1[0] == a2[1]); */
	/* assert(da1[101] == a2[0]); */

	darr_reset(da1);
	assert(darr_len(da1) == 0);
	assert(darr_maxi(da1) == 127);
	assert(darr_cap(da1) == 128);

	/* we touch the length field of the freed block here somehow */
	darr_insert_n(da1, 100, 300);

	assert(darr_len(da1) == 400);
	assert(darr_cap(da1) == 512);

	darr_free(da1);
	assert(da1 == NULL);

	assert(darr_len(da1) == 0);
	darr_setlen(da1, 0);
	darr_reset(da1);

	darr_free(da1);

	struct st i0 = {0, 0};
	struct st i1 = {1, 1};
	struct st i2 = {2, 2};
	struct st i3 = {3, 3};
	struct st i4 = {4, 4};

	*darr_append(da2) = i0;
	*darr_append(da2) = i1;
	darr_push(da2, i2);
	darr_push(da2, i3);
	darr_push(da2, i4);

	assert(!memcmp(da2, a1, sizeof(a1)));

	struct st p0, p1, p2, p3, p4;

	p4 = darr_pop(da2);
	p3 = darr_pop(da2);
	p2 = darr_pop(da2);
	p1 = darr_pop(da2);
	p0 = darr_pop(da2);
	assert(darr_len(da2) == 0);
	assert(p4.a == i4.a && p4.b == i4.b);
	assert(p3.a == i3.a && p3.b == i3.b);
	assert(p2.a == i2.a && p2.b == i2.b);
	assert(p1.a == i1.a && p1.b == i1.b);
	assert(p0.a == i0.a && p0.b == i0.b);

	darr_free(da2);
}

int main(int argc, char **argv)
{
	test_int();
	test_struct();
}
