// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2021, LabN Consulting, L.L.C
 */

#include <zebra.h>
#include <skiplist.h>

static void sl_debug(struct skiplist *l)
{
	int i;

	if (!l)
		return;

	printf("Skiplist %p has max level %d\n", l, l->level);
	for (i = l->level; i >= 0; --i)
		printf("  @%d: %d\n", i, l->level_stats[i]);
}

static void *scramble(int i)
{
	uintptr_t result;

	result = (uintptr_t)(i & 0xff) << 24;
	result |= (uintptr_t)i >> 8;

	return (void *)result;
}
#define sampleSize 65536
static int sl_test(void)
{
	struct skiplist *l;
	register int i, k;
	void *keys[sampleSize];
	void *v = NULL;
	int errors = 0;

	l = skiplist_new(SKIPLIST_FLAG_ALLOW_DUPLICATES, NULL, NULL);

	printf("%s: skiplist_new returned %p\n", __func__, l);

	for (i = 0; i < 4; i++) {

		for (k = 0; k < sampleSize; k++) {
			if (!(k % 10000))
				printf("%s: (%d:%d)\n", __func__, i, k);
			/* keys[k] = (void *)random(); */
			keys[k] = scramble(k);
			if (skiplist_insert(l, keys[k], keys[k])) {
				++errors;
				printf("error in insert #%d,#%d\n", i, k);
			}
		}

		printf("%s: inserts done\n", __func__);
		sl_debug(l);

		for (k = 0; k < sampleSize; k++) {

			if (!(k % 10000))
				printf("[%d:%d]\n", i, k);
			/* keys[k] = (void *)random(); */
			if (skiplist_search(l, keys[k], &v)) {
				++errors;
				printf("error in search #%d,#%d\n", i, k);
			}

			if (v != keys[k]) {
				++errors;
				printf("search returned wrong value\n");
			}
		}
		printf("%s: searches done\n", __func__);


		for (k = 0; k < sampleSize; k++) {

			if (!(k % 10000))
				printf("<%d:%d>\n", i, k);
			/* keys[k] = (void *)random(); */
			if (skiplist_delete(l, keys[k], keys[k])) {
				++errors;
				printf("error in delete\n");
			}
			keys[k] = scramble(k ^ 0xf0f0f0f0);
			if (skiplist_insert(l, keys[k], keys[k])) {
				++errors;
				printf("error in insert #%d,#%d\n", i, k);
			}
		}

		printf("%s: del+inserts done\n", __func__);
		sl_debug(l);

		for (k = 0; k < sampleSize; k++) {

			if (!(k % 10000))
				printf("{%d:%d}\n", i, k);
			/* keys[k] = (void *)random(); */
			if (skiplist_delete_first(l)) {
				++errors;
				printf("error in delete_first\n");
			}
		}
	}

	sl_debug(l);

	skiplist_free(l);

	return errors;
}

int main(int argc, char **argv)
{
	int errors = sl_test();

	if (errors)
		return 1;
	return 0;
}
