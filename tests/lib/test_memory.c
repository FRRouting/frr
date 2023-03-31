// SPDX-License-Identifier: GPL-2.0-or-later
/*
 */

#include <zebra.h>
#include <memory.h>

DEFINE_MGROUP(TEST_MEMORY, "memory test");
DEFINE_MTYPE_STATIC(TEST_MEMORY, TEST, "generic test mtype");

/* Memory torture tests
 *
 * Tests below are generic but comments are focused on interaction with
 * Paul's proposed memory 'quick' cache, which may never be included in
 * CVS
 */

struct event_loop *master;

#if 0 /* set to 1 to use system alloc directly */
#undef XMALLOC
#undef XCALLOC
#undef XREALLOC
#undef XFREE
#define XMALLOC(T,S) malloc((S))
#define XCALLOC(T,S) calloc(1, (S))
#define XREALLOC(T,P,S) realloc((P),(S))
#define XFREE(T,P) free((P))
#endif

#define TIMES 10

int main(int argc, char **argv)
{
	void *a[10];
	int i;

	printf("malloc x, malloc x, free, malloc x, free free\n\n");
	/* simple case, test cache */
	for (i = 0; i < TIMES; i++) {
		a[0] = XMALLOC(MTYPE_TEST, 1024);
		memset(a[0], 1, 1024);
		a[1] = XMALLOC(MTYPE_TEST, 1024);
		memset(a[1], 1, 1024);
		XFREE(MTYPE_TEST, a[0]); /* should go to cache */
		a[0] = XMALLOC(MTYPE_TEST,
			       1024); /* should be satisfied from cache */
		XFREE(MTYPE_TEST, a[0]);
		XFREE(MTYPE_TEST, a[1]);
	}

	printf("malloc x, malloc y, free x, malloc y, free free\n\n");
	/* cache should go invalid, valid, invalid, etc.. */
	for (i = 0; i < TIMES; i++) {
		a[0] = XMALLOC(MTYPE_TEST, 512);
		memset(a[0], 1, 512);
		a[1] = XMALLOC(MTYPE_TEST, 1024); /* invalidate cache */
		memset(a[1], 1, 1024);
		XFREE(MTYPE_TEST, a[0]);
		a[0] = XMALLOC(MTYPE_TEST, 1024);
		XFREE(MTYPE_TEST, a[0]);
		XFREE(MTYPE_TEST, a[1]);
		/* cache should become valid again on next request */
	}

	printf("calloc\n\n");
	/* test calloc */
	for (i = 0; i < TIMES; i++) {
		a[0] = XCALLOC(MTYPE_TEST, 1024);
		memset(a[0], 1, 1024);
		a[1] = XCALLOC(MTYPE_TEST, 512); /* invalidate cache */
		memset(a[1], 1, 512);
		XFREE(MTYPE_TEST, a[1]);
		XFREE(MTYPE_TEST, a[0]);
		/* alloc == 0, cache can become valid again on next request */
	}

	printf("calloc and realloc\n\n");
	/* check calloc + realloc */
	for (i = 0; i < TIMES; i++) {
		printf("calloc a0 1024\n");
		a[0] = XCALLOC(MTYPE_TEST, 1024);
		memset(a[0], 1, 1024 / 2);

		printf("calloc 1 1024\n");
		a[1] = XCALLOC(MTYPE_TEST, 1024);
		memset(a[1], 1, 1024 / 2);

		printf("realloc 0 1024\n");
		a[3] = XREALLOC(MTYPE_TEST, a[0], 2048); /* invalidate cache */
		if (a[3] != NULL)
			a[0] = a[3];
		memset(a[0], 1, 1024);

		printf("calloc 2 512\n");
		a[2] = XCALLOC(MTYPE_TEST, 512);
		memset(a[2], 1, 512);

		printf("free 1 0 2\n");
		XFREE(MTYPE_TEST, a[1]);
		XFREE(MTYPE_TEST, a[0]);
		XFREE(MTYPE_TEST, a[2]);
		/* alloc == 0, cache valid next request */
	}
	return 0;
}
